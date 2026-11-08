const REPO = 'lederg001/lederg-proxy';
const BRANCH = 'main';
const PROBE_TIMEOUT_MS = 5000;
const STATE_KEY = 'scanner-state-v1';
const FEED_TTL_MS = 9 * 60 * 1000;
const FEED_RETRY_COOLDOWN_MS = 5 * 60 * 1000;
const MAX_SOURCE_BYTES = 768 * 1024;
const MAX_POOL_ENDPOINTS = 300;
const MAX_CONFIGS_PER_FEED = 120;
const CHECKS_PER_RUN = 20;
const PROBE_CONCURRENCY = 6;
const ACTIVE_TTL_MS = 35 * 60 * 1000;
const REMOVE_AFTER_FAILURES = 2;
const REQUEST_TIMEOUT_MS = 12000;

export function calculateSweepMinutes(totalEndpoints, batchSize = CHECKS_PER_RUN) {
  if (!Number.isInteger(totalEndpoints) || totalEndpoints < 0) {
    throw new Error('totalEndpoints must be a non-negative integer');
  }
  if (!Number.isInteger(batchSize) || batchSize < 1) {
    throw new Error('batchSize must be a positive integer');
  }
  return totalEndpoints === 0 ? 0 : Math.ceil(totalEndpoints / batchSize);
}

export const FEEDS = [
  { id: 'nomorewalls', name: 'peasoft/NoMoreWalls', url: 'https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt', country: null, priority: 0 },
  { id: 'ts-sf-fly', name: 'ts-sf/fly', url: 'https://raw.githubusercontent.com/ts-sf/fly/main/v2', country: null, priority: 1 },
  { id: 'morpheusadam-lite', name: 'morpheusadam/v2ray-config — lite', url: 'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt', country: null, priority: 2 },
  { id: 'alirewa-config', name: 'Alirewa/V2ray-Configs', url: 'https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt', country: null, priority: 3 },
  { id: 'chaishpish-tfmtproto', name: 'chaishpish/free_server_v2ray', url: 'https://raw.githubusercontent.com/chaishpish/free_server_v2ray/main/%40TFMTProto', country: null, priority: 4 },
];

const COUNTRY_HINTS = [
  ['NL', /🇳🇱|netherlands|nederland|holland|荷兰/i],
  ['DE', /🇩🇪|germany|deutschland|allemagne/i],
  ['FR', /🇫🇷|france|法国/i],
  ['GB', /🇬🇧|united kingdom|great britain|britain|england|uk\b/i],
  ['US', /🇺🇸|united states|\busa\b|\bus\b|america/i],
  ['FI', /🇫🇮|finland|suomi/i],
  ['SE', /🇸🇪|sweden|sverige/i],
  ['CH', /🇨🇭|switzerland|schweiz/i],
  ['PL', /🇵🇱|poland|polska/i],
  ['IT', /🇮🇹|italy|italia/i],
  ['SG', /🇸🇬|singapore/i],
  ['CA', /🇨🇦|canada/i],
  ['JP', /🇯🇵|japan|日本/i],
  ['AT', /🇦🇹|austria|österreich/i],
  ['LT', /🇱🇹|lithuania|lietuva/i],
  ['RU', /🇷🇺|russia|россия/i],
  ['BE', /🇧🇪|belgium/i],
  ['CZ', /🇨🇿|czech/i],
  ['ES', /🇪🇸|spain|españa/i],
  ['NO', /🇳🇴|norway|norge/i],
  ['TR', /🇹🇷|turkey|türkiye/i],
];

const COUNTRY_NAMES = {
  NL: 'Netherlands', DE: 'Germany', FR: 'France', GB: 'United Kingdom',
  US: 'United States', FI: 'Finland', SE: 'Sweden', CH: 'Switzerland',
  PL: 'Poland', IT: 'Italy', SG: 'Singapore', CA: 'Canada', JP: 'Japan',
  AT: 'Austria', LT: 'Lithuania', RU: 'Russia', BE: 'Belgium', CZ: 'Czechia',
  ES: 'Spain', NO: 'Norway', TR: 'Türkiye', UN: 'Unknown',
};

const DEFAULT_PORTS = {
  vless: 443, vmess: 443, trojan: 443, ss: 8388,
  socks: 1080, socks5: 1080, hysteria2: 443, hy2: 443,
};

function decodeBase64Utf8(value) {
  const normalized = String(value).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  if (!normalized || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) return null;
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

export function decodeMaybeBase64(input) {
  const text = String(input ?? '').replace(/^\uFEFF/, '');
  const trimmed = text.trim();
  if (!trimmed) return '';
  if (/(?:vless|vmess|trojan|ss|socks5?|hysteria2|hy2):\/\//i.test(trimmed)) return text;
  const compact = trimmed.replace(/\s+/g, '');
  if (compact.length < 20 || compact.length > MAX_SOURCE_BYTES || !/^[A-Za-z0-9+/_=-]+$/.test(compact)) return text;
  const decoded = decodeBase64Utf8(compact);
  return decoded && /(?:vless|vmess|trojan|ss|socks5?|hysteria2|hy2):\/\//i.test(decoded) ? decoded : text;
}

export function extractUris(input) {
  const matches = String(input ?? '').match(/(?:vless|vmess|trojan|ss|socks5?|hysteria2|hy2):\/\/[^\s"'<>]+/gi) || [];
  const seen = new Set();
  const result = [];
  for (const raw of matches) {
    const uri = raw.replace(/[\]),;]+$/g, '').replace(/[.]$/, '').trim();
    if (!uri || seen.has(uri)) continue;
    seen.add(uri);
    result.push(uri);
  }
  return result;
}

export function detectCountry(label) {
  const text = String(label ?? '');
  for (const [code, pattern] of COUNTRY_HINTS) {
    if (pattern.test(text)) return code;
  }
  return 'UN';
}

function normalizeHost(host) {
  return String(host ?? '').trim().replace(/^\[/, '').replace(/\]$/, '').replace(/\.$/, '').toLowerCase();
}

function isPrivateIpv4(host) {
  const parts = host.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return false;
  const nums = parts.map(Number);
  if (nums.some((part) => part < 0 || part > 255)) return true;
  const [a, b, c] = nums;
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && c <= 2) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function isPublicHost(host) {
  const value = normalizeHost(host);
  if (!value || value.length > 253) return false;
  if (value === 'localhost' || value.endsWith('.localhost') || value.endsWith('.local') ||
      value.endsWith('.internal') || value.endsWith('.test') || value.endsWith('.invalid') ||
      value.endsWith('.example')) return false;
  if (isPrivateIpv4(value)) return false;
  if (value.includes(':')) {
    const ipv6 = value.toLowerCase();
    // Only global-unicast 2000::/3 addresses are useful as public proxy endpoints.
    if (!/^[23][0-9a-f]{0,3}:/i.test(ipv6) || ipv6.startsWith('2001:db8:')) return false;
    if (ipv6.includes('.') || ipv6.split(':').length > 8) return false;
    return true;
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return true;
  if (!value.includes('.')) return false;
  if (!/^[a-z0-9.-]+$/.test(value)) return false;
  return value.split('.').every((part) => part.length > 0 && part.length <= 63 && !part.startsWith('-') && !part.endsWith('-'));
}

function splitHostPort(value, fallbackPort) {
  const text = String(value ?? '').trim();
  if (!text) return null;
  let host = '';
  let port = fallbackPort;
  if (text.startsWith('[')) {
    const close = text.indexOf(']');
    if (close < 0) return null;
    host = text.slice(1, close);
    const remainder = text.slice(close + 1);
    if (remainder.startsWith(':')) port = Number(remainder.slice(1));
  } else {
    const lastColon = text.lastIndexOf(':');
    if (lastColon > 0 && /^\d+$/.test(text.slice(lastColon + 1))) {
      host = text.slice(0, lastColon);
      port = Number(text.slice(lastColon + 1));
    } else {
      host = text;
    }
  }
  host = normalizeHost(host);
  if (!isPublicHost(host) || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

function parseVmess(uri) {
  const payload = uri.slice('vmess://'.length).split('#')[0].split('?')[0];
  const decoded = decodeBase64Utf8(payload);
  if (!decoded) return null;
  let config;
  try { config = JSON.parse(decoded); } catch { return null; }
  const host = normalizeHost(config.add || config.address || config.host);
  const port = Number(config.port || 443);
  if (!isPublicHost(host) || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port, name: String(config.ps || config.name || '') };
}

function parseShadowsocks(uri) {
  let value = uri.slice('ss://'.length);
  const fragment = value.indexOf('#');
  if (fragment >= 0) value = value.slice(0, fragment);
  const query = value.indexOf('?');
  if (query >= 0) value = value.slice(0, query);
  if (!value.includes('@')) {
    const decoded = decodeBase64Utf8(value);
    if (!decoded) return null;
    value = decoded;
  } else {
    const at = value.lastIndexOf('@');
    const auth = value.slice(0, at);
    if (!auth.includes(':')) {
      const decodedAuth = decodeBase64Utf8(auth);
      if (decodedAuth?.includes(':')) value = `${decodedAuth}@${value.slice(at + 1)}`;
    }
  }
  const at = value.lastIndexOf('@');
  if (at < 0) return null;
  const server = splitHostPort(value.slice(at + 1), DEFAULT_PORTS.ss);
  if (!server) return null;
  let auth = value.slice(0, at);
  try { auth = decodeURIComponent(auth); } catch { /* keep raw auth */ }
  const separator = auth.indexOf(':');
  if (separator < 1) return null;
  let method = auth.slice(0, separator);
  let password = auth.slice(separator + 1);
  try { password = decodeURIComponent(password); } catch { /* keep raw password */ }
  if (!/^[a-z0-9][a-z0-9-]*$/i.test(method) || !password) return null;
  return { ...server, method, password, name: '' };
}

export function parseProxyUri(uri, sourceId = 'unknown', forcedCountry = null) {
  const raw = String(uri ?? '').trim();
  const schemeMatch = raw.match(/^([a-z0-9]+):\/\//i);
  if (!schemeMatch) return null;
  const protocol = schemeMatch[1].toLowerCase();
  if (!Object.hasOwn(DEFAULT_PORTS, protocol)) return null;

  let endpoint = null;
  let name = '';
  if (protocol === 'vmess') {
    endpoint = parseVmess(raw);
    name = endpoint?.name || '';
  } else if (protocol === 'ss') {
    endpoint = parseShadowsocks(raw);
  } else {
    try {
      const parsed = new URL(raw);
      endpoint = splitHostPort(parsed.hostname + (parsed.port ? `:${parsed.port}` : ''), DEFAULT_PORTS[protocol]);
      name = decodeURIComponent(parsed.hash.replace(/^#/, '')).slice(0, 80);
    } catch {
      return null;
    }
  }
  if (!endpoint) return null;
  const source = FEEDS.find((feed) => feed.id === sourceId);
  const inferred = detectCountry(`${name} ${raw.split('#')[1] || ''}`);
  const country = forcedCountry || source?.country || inferred;
  const countrySource = forcedCountry || source?.country ? 'source-country-feed' : inferred !== 'UN' ? 'node-label' : 'unknown';
  return {
    uri: raw,
    protocol,
    host: endpoint.host,
    port: endpoint.port,
    name: name || `${COUNTRY_NAMES[country] || 'Proxy'} ${protocol.toUpperCase()}`,
    country,
    country_name: COUNTRY_NAMES[country] || 'Unknown',
    country_source: countrySource,
    source: sourceId,
  };
}

async function readLimitedText(response, limitBytes) {
  if (!response.body) return '';
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared > limitBytes) throw new Error(`source too large (${declared} bytes)`);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limitBytes) {
        await reader.cancel('source limit exceeded');
        throw new Error(`source exceeds ${limitBytes} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

async function fetchFeed(feed) {
  const response = await fetch(feed.url, {
    headers: { accept: 'text/plain, application/octet-stream;q=0.9, */*;q=0.5', 'user-agent': 'LEDERG-Proxy-Scanner/1.0' },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`feed HTTP ${response.status}`);
  const body = await readLimitedText(response, MAX_SOURCE_BYTES);
  const decoded = decodeMaybeBase64(body);
  const uris = extractUris(decoded);
  const configs = [];
  const seen = new Set();
  for (const uri of uris) {
    const parsed = parseProxyUri(uri, feed.id, feed.country);
    if (!parsed) continue;
    if (seen.has(parsed.uri)) continue;
    seen.add(parsed.uri);
    configs.push(parsed);
    if (configs.length >= MAX_CONFIGS_PER_FEED) break;
  }
  return { id: feed.id, fetched_at: Date.now(), count: configs.length, configs };
}

async function loadFeedCaches(env) {
  const entries = await Promise.all(FEEDS.map(async (feed) => {
    const cache = await env.STATE.get(`feed:${feed.id}`, 'json');
    return { feed, cache };
  }));
  return entries;
}

export function selectStaleFeed(entries, attempts = {}, now = Date.now()) {
  const stale = entries
    .filter(({ cache }) => !cache || !Number.isFinite(cache.fetched_at) || now - cache.fetched_at > FEED_TTL_MS)
    .filter(({ feed }) => {
      const attemptedAt = Number(attempts?.[feed.id]?.attempted_at || 0);
      return !Number.isFinite(attemptedAt) || attemptedAt <= 0 || now - attemptedAt >= FEED_RETRY_COOLDOWN_MS;
    })
    .sort((a, b) => (a.cache?.fetched_at || 0) - (b.cache?.fetched_at || 0));
  return stale[0]?.feed || null;
}

async function refreshOneStaleFeed(env, entries, now) {
  const attempts = await Promise.all(entries.map(async ({ feed }) => [
    feed.id,
    await env.STATE.get(`feed-attempt:${feed.id}`, 'json'),
  ]));
  const feed = selectStaleFeed(entries, Object.fromEntries(attempts), now);
  if (!feed) return { refreshed: null, error: null };

  // Record the attempt before the network call so a broken/rate-limited feed
  // cannot monopolize every scheduled run and starve the remaining sources.
  await env.STATE.put(`feed-attempt:${feed.id}`, JSON.stringify({ attempted_at: now }), { expirationTtl: 24 * 60 * 60 });
  try {
    const value = await fetchFeed(feed);
    await env.STATE.put(`feed:${feed.id}`, JSON.stringify(value), { expirationTtl: 24 * 60 * 60 });
    return { refreshed: feed.id, error: null };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(JSON.stringify({ message: 'feed refresh failed', feed: feed.id, error: message }));
    return { refreshed: null, error: `${feed.id}: ${message}` };
  }
}

function createEndpointPool(entries) {
  const grouped = new Map();
  for (const { feed, cache } of entries) {
    if (!cache || !Array.isArray(cache.configs)) continue;
    for (const config of cache.configs) {
      const key = `${config.host}:${config.port}`;
      if (!grouped.has(key)) grouped.set(key, { key, host: config.host, port: config.port, priority: feed.priority, configs: [] });
      const group = grouped.get(key);
      group.priority = Math.min(group.priority, feed.priority);
      if (!group.configs.some((item) => item.uri === config.uri)) group.configs.push(config);
    }
  }
  return Array.from(grouped.values())
    .sort((a, b) => a.priority - b.priority || a.key.localeCompare(b.key))
    .slice(0, MAX_POOL_ENDPOINTS);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function probeTcpSocket(endpoint, connectFn, timeoutMs = PROBE_TIMEOUT_MS) {
  if (typeof connectFn !== 'function') return { ok: false, error: 'Cloudflare TCP socket connector is unavailable' };
  if (!endpoint?.host || !Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535) {
    return { ok: false, error: 'Invalid TCP endpoint' };
  }
  const startedAt = performance.now();
  let socket;
  let timeoutId;
  try {
    socket = connectFn({ hostname: endpoint.host, port: endpoint.port }, { secureTransport: 'off', allowHalfOpen: false });
    if (!socket?.opened || typeof socket.close !== 'function') throw new Error('TCP socket did not expose opened/close');
    const opened = await Promise.race([
      socket.opened,
      new Promise((_, reject) => { timeoutId = setTimeout(() => reject(new Error('TCP connect timeout')), timeoutMs); }),
    ]);
    const latencyMs = Math.max(1, Math.round(performance.now() - startedAt));
    try { socket.close(); } catch { /* handshake already succeeded */ }
    return { ok: true, latency_ms: latencyMs, address: opened?.remoteAddress || null };
  } catch (error) {
    try { socket?.close?.(); } catch { /* ignore close errors */ }
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

async function mapLimit(items, limit, mapper) {
  const output = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      try { output[index] = await mapper(items[index], index); }
      catch (error) { output[index] = { pending: true, error: error instanceof Error ? error.message : String(error) }; }
    }
  });
  await Promise.all(workers);
  return output;
}

function applyProbeResult(state, endpoint, result, now) {
  const previous = state.endpoints[endpoint.key] || { success_count: 0, fail_count: 0, latency_ms: null };
  const updated = { ...previous, last_checked_at: new Date(now).toISOString() };
  if (result?.ok) {
    const newLatency = result.latency_ms;
    const oldLatency = Number(previous.latency_ms);
    const materiallyDifferent = !Number.isFinite(oldLatency) || Math.abs(newLatency - oldLatency) >= Math.max(25, oldLatency * 0.15);
    updated.latency_ms = materiallyDifferent ? newLatency : previous.latency_ms;
    updated.success_count = Math.min(99, (previous.success_count || 0) + 1);
    updated.fail_count = 0;
    updated.pending_count = 0;
    updated.last_success_at = new Date(now).toISOString();
    updated.address = result.address || previous.address || null;
    updated.last_probe_error = null;
    updated.available = true;
  } else if (result?.pending) {
    updated.pending_count = Math.min(99, (previous.pending_count || 0) + 1);
    updated.last_probe_error = result.error || 'TCP handshake is still pending';
  } else {
    updated.fail_count = (previous.fail_count || 0) + 1;
    updated.last_probe_error = result?.error || 'TCP probe failed';
    if (updated.fail_count >= REMOVE_AFTER_FAILURES) updated.available = false;
  }
  state.endpoints[endpoint.key] = updated;
}

function getActiveNodes(pool, state, now) {
  const nodes = [];
  for (const endpoint of pool) {
    const status = state.endpoints[endpoint.key];
    if (!status?.available || !Number.isFinite(Number(status.latency_ms))) continue;
    const lastSuccess = Date.parse(status.last_success_at || '');
    if (!Number.isFinite(lastSuccess) || now - lastSuccess > ACTIVE_TTL_MS) continue;
    const stableChecks = Math.min(3, status.success_count || 1);
    for (const config of endpoint.configs) {
      nodes.push({
        ...config,
        ping_ms: Number(status.latency_ms),
        stable_checks: stableChecks,
        endpoint: endpoint.key,
      });
    }
  }
  const unique = new Map();
  for (const node of nodes) if (!unique.has(node.uri)) unique.set(node.uri, node);
  return Array.from(unique.values()).sort((a, b) => a.ping_ms - b.ping_ms || a.country.localeCompare(b.country)).slice(0, 500);
}

export function renderHappSubscription(nodes) {
  const uris = (Array.isArray(nodes) ? nodes : [])
    .filter((node) => typeof node?.uri === 'string' && /^(vless|vmess|ss|trojan|socks5?|hysteria2|hy2):\/\//i.test(node.uri))
    .sort((a, b) => Number(a.ping_ms || 999999) - Number(b.ping_ms || 999999))
    .map((node) => node.uri.trim());
  return [
    '#profile-title: LEDERG PROXY',
    '#subscriptions-sort-type: ping',
    '#subscription-auto-update-open-enable: 1',
    ...uris,
    '',
  ].join('\n');
}

function truthyParam(value) {
  return ['1', 'true', 'yes'].includes(String(value ?? '').toLowerCase());
}

function buildXrayStreamSettings(network, security, values, fallbackHost) {
  const stream = { network: network || 'tcp', security: security || 'none' };
  const sni = values.sni || values.serverName || values.host || fallbackHost;
  const fingerprint = values.fp || values.fingerprint || 'chrome';
  if (stream.security === 'tls') {
    const tlsSettings = { serverName: sni, fingerprint };
    const alpn = String(values.alpn || '').split(',').map((item) => item.trim()).filter(Boolean);
    if (alpn.length) tlsSettings.alpn = alpn;
    if (truthyParam(values.allowInsecure || values.insecure)) tlsSettings.allowInsecure = true;
    stream.tlsSettings = tlsSettings;
  } else if (stream.security === 'reality') {
    const realitySettings = { serverName: sni, fingerprint };
    const publicKey = values.pbk || values.publicKey;
    const shortId = values.sid || values.shortId;
    const spiderX = values.spx || values.spiderX;
    if (publicKey) realitySettings.publicKey = publicKey;
    if (shortId) realitySettings.shortId = shortId;
    if (spiderX) realitySettings.spiderX = spiderX;
    stream.realitySettings = realitySettings;
  }
  if (stream.network === 'ws') {
    const headers = {};
    const wsHost = values.host || values.wsHost;
    if (wsHost) headers.Host = wsHost;
    stream.wsSettings = { path: values.path || values.wsPath || '/', headers };
  } else if (stream.network === 'grpc') {
    stream.grpcSettings = {
      serviceName: values.serviceName || values.path || '',
      ...(truthyParam(values.multiMode) ? { multiMode: true } : {}),
    };
  } else if (stream.network === 'httpupgrade') {
    stream.httpupgradeSettings = { path: values.path || '/', host: values.host || sni };
  } else if (stream.network === 'xhttp') {
    stream.xhttpSettings = { path: values.path || '/', host: values.host || sni, mode: values.mode || 'auto' };
  }
  return stream;
}

function parseVmessConfig(uri) {
  const payload = String(uri).slice('vmess://'.length).split('#')[0].split('?')[0];
  const decoded = decodeBase64Utf8(payload);
  if (!decoded) return null;
  try { return JSON.parse(decoded); } catch { return null; }
}

function createXrayOutbound(node) {
  const protocol = String(node.protocol || '').toLowerCase();
  const uri = String(node.uri || '');
  if (protocol === 'vless') {
    const url = new URL(uri);
    const id = decodeURIComponent(url.username);
    if (!id) return null;
    const params = url.searchParams;
    const security = params.get('security') || 'none';
    const network = params.get('type') || params.get('network') || 'tcp';
    const user = { id, encryption: params.get('encryption') || 'none' };
    const flow = params.get('flow');
    if (flow) user.flow = flow;
    return {
      tag: 'proxy', protocol: 'vless',
      settings: { vnext: [{ address: node.host, port: node.port, users: [user] }] },
      streamSettings: buildXrayStreamSettings(network, security, Object.fromEntries(params.entries()), node.host),
    };
  }
  if (protocol === 'vmess') {
    const config = parseVmessConfig(uri);
    if (!config?.id) return null;
    const network = String(config.net || 'tcp').toLowerCase();
    const security = String(config.tls || '').toLowerCase() === 'tls' ? 'tls' : 'none';
    const user = { id: String(config.id), alterId: Number(config.aid || 0), security: String(config.scy || 'auto') };
    return {
      tag: 'proxy', protocol: 'vmess',
      settings: { vnext: [{ address: node.host, port: node.port, users: [user] }] },
      streamSettings: buildXrayStreamSettings(network, security, {
        sni: config.sni, fp: config.fp, host: config.host, path: config.path,
        serviceName: config.serviceName, mode: config.mode,
      }, node.host),
    };
  }
  if (protocol === 'ss') {
    const parsed = parseShadowsocks(uri);
    if (!parsed) return null;
    return {
      tag: 'proxy', protocol: 'shadowsocks',
      settings: { servers: [{ address: node.host, port: node.port, method: parsed.method, password: parsed.password }] },
    };
  }
  if (protocol === 'trojan') {
    const url = new URL(uri);
    const password = decodeURIComponent(url.username);
    if (!password) return null;
    const params = url.searchParams;
    const security = params.get('security') || 'tls';
    const network = params.get('type') || params.get('network') || 'tcp';
    return {
      tag: 'proxy', protocol: 'trojan',
      settings: { servers: [{ address: node.host, port: node.port, password }] },
      streamSettings: buildXrayStreamSettings(network, security, Object.fromEntries(params.entries()), node.host),
    };
  }
  if (protocol === 'socks' || protocol === 'socks5') {
    const url = new URL(uri);
    let user = decodeURIComponent(url.username || '');
    let pass = decodeURIComponent(url.password || '');
    if (user && !pass && !user.includes(':')) {
      const decoded = decodeBase64Utf8(user);
      if (decoded?.includes(':')) [user, pass] = decoded.split(/:(.*)/s, 2);
    }
    const server = { address: node.host, port: node.port };
    if (user) server.users = [{ user, pass }];
    return { tag: 'proxy', protocol: 'socks', settings: { servers: [server] } };
  }
  // Hysteria2 is valid in HAPP's URI subscriptions, but is not represented as an Xray outbound.
  return null;
}

export function buildHappJsonConfigs(nodes) {
  const profiles = [];
  const sorted = (Array.isArray(nodes) ? nodes : [])
    .slice()
    .sort((a, b) => Number(a.ping_ms || 999999) - Number(b.ping_ms || 999999));
  for (const node of sorted) {
    try {
      const proxy = createXrayOutbound(node);
      if (!proxy) continue;
      const location = node.country_name || COUNTRY_NAMES[node.country] || 'Unknown';
      profiles.push({
        remarks: `${location} | ${String(node.protocol).toUpperCase()} | ${Math.round(Number(node.ping_ms) || 0)}ms`,
        log: { loglevel: 'warning' },
        dns: { servers: ['1.1.1.1', '1.0.0.1'], queryStrategy: 'UseIP' },
        inbounds: [{
          tag: 'socks-in', port: 10808, listen: '127.0.0.1', protocol: 'socks',
          settings: { auth: 'noauth', udp: true },
          sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: false },
        }],
        outbounds: [proxy, { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
        routing: {
          domainStrategy: 'AsIs',
          rules: [
            { type: 'field', outboundTag: 'direct', ip: ['geoip:private'] },
            { type: 'field', outboundTag: 'proxy', network: 'tcp,udp' },
          ],
        },
        meta: { serverDescription: `${node.source || 'public source'}; Cloudflare edge TCP ${Math.round(Number(node.ping_ms) || 0)}ms` },
      });
      if (profiles.length >= 150) break;
    } catch {
      // Skip malformed or unsupported shared links rather than publishing invalid profiles.
    }
  }
  return profiles;
}

export function buildManifest({ now = new Date().toISOString(), candidates = 0, checked = 0, nodes = [] } = {}) {
  const byCountry = {};
  const endpoints = new Set();
  for (const node of nodes) {
    const country = node.country || 'UN';
    byCountry[country] = (byCountry[country] || 0) + 1;
    endpoints.add(node.endpoint || `${node.host}:${node.port}`);
  }
  const sorted = [...nodes].sort((a, b) => Number(a.ping_ms || 999999) - Number(b.ping_ms || 999999));
  return {
    schema: 'lederg-proxy-feed/v1',
    updated_at: now,
    probe: {
      provider: 'Cloudflare Workers TCP sockets',
      location: 'Cloudflare edge (not a fixed city)',
      method: 'TCP handshake',
      meaning: 'TCP port reachability and handshake time from the Cloudflare Worker edge; this is not a full VPN-tunnel or exit-IP test.',
    },
    stats: {
      candidate_endpoints: candidates,
      checked_this_run: checked,
      active_endpoints: endpoints.size,
      active_configs: sorted.length,
      estimated_sweep_minutes: calculateSweepMinutes(candidates),
      by_country: byCountry,
    },
    sources: FEEDS.map(({ id, name, url, country }) => ({ id, name, url, country_filter: country })),
    nodes: sorted.map((node) => ({
      name: node.name,
      protocol: node.protocol,
      server: node.host,
      port: node.port,
      country: node.country || 'UN',
      country_name: node.country_name || COUNTRY_NAMES[node.country] || 'Unknown',
      country_basis: node.country_source || 'unknown',
      source: node.source,
      ping_ms: Number(node.ping_ms),
      stable_checks: Number(node.stable_checks || 1),
      uri: node.uri,
    })),
  };
}

async function persistState(env, state) {
  await env.STATE.put(STATE_KEY, JSON.stringify(state), { expirationTtl: 30 * 24 * 60 * 60 });
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function runScanner(env, scheduledTime = Date.now(), tcpConnect = env.TCP_CONNECT) {
  if (!env.STATE) throw new Error('STATE KV binding is missing');
  const now = Number(scheduledTime) || Date.now();
  const state = await env.STATE.get(STATE_KEY, 'json') || { cursor: 0, endpoints: {}, source_errors: {}, last_run: null };
  if (!state.endpoints || typeof state.endpoints !== 'object') state.endpoints = {};
  const entries = await loadFeedCaches(env);
  const refresh = await refreshOneStaleFeed(env, entries, now);
  const refreshedEntries = await loadFeedCaches(env);
  const pool = createEndpointPool(refreshedEntries);
  if (!pool.length) {
    state.last_run = { at: new Date(now).toISOString(), candidate_endpoints: 0, checked: 0, active_configs: 0, estimated_sweep_minutes: 0, error: refresh.error || 'No valid proxy endpoints found in sources' };
    await persistState(env, state);
    return state.last_run;
  }

  const start = Math.max(0, Number(state.cursor) || 0) % pool.length;
  const batch = [];
  for (let i = 0; i < Math.min(CHECKS_PER_RUN, pool.length); i += 1) batch.push(pool[(start + i) % pool.length]);
  const results = await mapLimit(batch, PROBE_CONCURRENCY, (endpoint) => probeTcpSocket(endpoint, tcpConnect));
  results.forEach((result, index) => applyProbeResult(state, batch[index], result, now));
  state.cursor = (start + batch.length) % pool.length;

  const poolKeys = new Set(pool.map((item) => item.key));
  for (const [key, status] of Object.entries(state.endpoints)) {
    const last = Date.parse(status.last_checked_at || status.last_success_at || '');
    if (!poolKeys.has(key) || (Number.isFinite(last) && now - last > 14 * 24 * 60 * 60 * 1000)) delete state.endpoints[key];
  }

  const activeNodes = getActiveNodes(pool, state, now);
  const subscriptionText = renderHappSubscription(activeNodes);
  const happProfiles = buildHappJsonConfigs(activeNodes);
  const happJsonText = `${JSON.stringify(happProfiles, null, 2)}\n`;
  const fingerprintPayload = buildManifest({ now: '', candidates: pool.length, checked: batch.length, nodes: activeNodes });
  const contentFingerprint = await sha256Hex(`${JSON.stringify(fingerprintPayload)}\n${subscriptionText}\n${happJsonText}`);
  const contentChanged = contentFingerprint !== state.last_content_fingerprint;
  const publishedAt = contentChanged ? new Date(now).toISOString() : (state.last_published_at || new Date(now).toISOString());
  const stablePayload = buildManifest({ now: publishedAt, candidates: pool.length, checked: batch.length, nodes: activeNodes });
  const manifestText = `${JSON.stringify(stablePayload, null, 2)}\n`;
  const publish = { skipped: true, reason: 'Outputs are stored in Cloudflare KV; GitHub is used only as a public source' };
  state.last_content_fingerprint = contentFingerprint;
  await env.STATE.put('last-manifest', manifestText, { expirationTtl: 30 * 24 * 60 * 60 });
  await env.STATE.put('last-happ-json', happJsonText, { expirationTtl: 30 * 24 * 60 * 60 });
  await env.STATE.put('last-happ-subscription', subscriptionText, { expirationTtl: 30 * 24 * 60 * 60 });
  delete state.last_error;
  state.last_run = {
    at: new Date(now).toISOString(),
    candidate_endpoints: pool.length,
    checked: batch.length,
    tcp_ok: results.filter((result) => result?.ok).length,
    pending_or_errors: results.filter((result) => !result?.ok).length,
    estimated_sweep_minutes: calculateSweepMinutes(pool.length),
    probe_results: results.map((result, index) => ({
      endpoint: batch[index].key,
      status: result?.ok ? 'ok' : result?.pending ? 'pending' : 'failed',
      latency_ms: result?.latency_ms ?? null,
      error: result?.error || null,
    })),
    active_configs: activeNodes.length,
    active_endpoints: new Set(activeNodes.map((node) => node.endpoint)).size,
    refreshed_feed: refresh.refreshed,
    feed_refresh_error: refresh.error,
    output_storage: 'Cloudflare KV',
  };
  await persistState(env, state);
  console.log(JSON.stringify({ message: 'proxy scan completed', ...state.last_run }));
  return state.last_run;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== 'GET') return new Response('Method Not Allowed', { status: 405 });
    if (url.pathname === '/health' || url.pathname === '/') {
      const state = await env.STATE?.get(STATE_KEY, 'json') || {};
      return Response.json({
        service: 'LEDERG PROXY SCANNER',
        status: 'online',
        repository: REPO,
        branch: BRANCH,
        output_files: ['json', 'happ.txt', 'manifest.json'],
        probe: { provider: 'Cloudflare Workers TCP sockets', location: 'Cloudflare edge', method: 'TCP handshake' },
        schedule: '* * * * * UTC; 20 TCP probes per minute; up to 300 endpoints per 15-minute sweep',
        estimated_full_pool_cycle_minutes: calculateSweepMinutes(MAX_POOL_ENDPOINTS),
        last_run: state.last_run || null,
      }, { headers: { 'cache-control': 'no-store' } });
    }
    if (url.pathname === '/json') {
      const value = await env.STATE?.get('last-happ-json');
      return value
        ? new Response(value, { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } })
        : Response.json([], { status: 503 });
    }
    if (url.pathname === '/manifest') {
      const value = await env.STATE?.get('last-manifest');
      return value
        ? new Response(value, { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } })
        : Response.json({ status: 'not_ready', message: 'The first scheduled scan has not completed yet.' }, { status: 503 });
    }
    if (url.pathname === '/happ') {
      const value = await env.STATE?.get('last-happ-subscription');
      return value
        ? new Response(value, { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } })
        : new Response('The first scheduled scan has not completed yet.', { status: 503 });
    }
    return Response.json({ error: 'Not found' }, { status: 404 });
  },

  async scheduled(controller, env, tcpConnect) {
    try {
      await runScanner(env, controller.scheduledTime, tcpConnect);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(JSON.stringify({ message: 'scheduled scan failed', error: message }));
      const state = await env.STATE?.get(STATE_KEY, 'json') || { cursor: 0, endpoints: {} };
      state.last_error = { at: new Date(controller.scheduledTime || Date.now()).toISOString(), message };
      await persistState(env, state);
      throw error;
    }
  },
};
