import { getVlessProbeSupport, PROXY_VERIFY_LIMITS, verifyVlessProxy, verifyVlessServices } from './proxy-verifier.mjs';

const REPO = 'lederg001/lederg-proxy';
const BRANCH = 'main';
const GLOBALPING_API = 'https://api.globalping.io/v1';
const GLOBALPING_REQUEST_TIMEOUT_MS = 9000;
const GLOBALPING_POLL_ATTEMPTS = 40;
const GLOBALPING_POLL_DELAY_MS = 500;
const HISTORY_SIZE = 5;
const MOSCOW_CITY = 'Moscow';
const MOSCOW_COUNTRY = 'RU';
const TCP_PROXY_PROTOCOLS = new Set(['vless', 'vmess', 'trojan', 'ss', 'socks', 'socks5']);
const STATE_KEY = 'scanner-state-v1';
const FEED_TTL_MS = 9 * 60 * 1000;
const FEED_RETRY_COOLDOWN_MS = 5 * 60 * 1000;
const MAX_SOURCE_BYTES = 768 * 1024;
const MAX_POOL_ENDPOINTS = 30;
const MAX_CONFIGS_PER_FEED = 120;
const SCHEDULE_INTERVAL_MINUTES = 15;
const CHECKS_PER_RUN = MAX_POOL_ENDPOINTS;
const PROBE_CONCURRENCY = 6;
const VERIFIER_CONCURRENCY = 8;
const ACTIVE_TTL_MS = 35 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 12000;

export function calculateSweepMinutes(totalEndpoints, batchSize = CHECKS_PER_RUN) {
  if (!Number.isInteger(totalEndpoints) || totalEndpoints < 0) {
    throw new Error('totalEndpoints must be a non-negative integer');
  }
  if (!Number.isInteger(batchSize) || batchSize < 1) {
    throw new Error('batchSize must be a positive integer');
  }
  return totalEndpoints === 0 ? 0 : Math.ceil(totalEndpoints / batchSize) * SCHEDULE_INTERVAL_MINUTES;
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
      // Only publish protocols whose server port can be tested with a TCP ping.
      if (!TCP_PROXY_PROTOCOLS.has(String(config.protocol || '').toLowerCase())) continue;
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

export function parseGlobalpingTcpResult(payload) {
  if (payload?.status === 'in-progress') {
    return { pending: true, error: 'Moscow measurement is still in progress' };
  }

  const entries = Array.isArray(payload?.results) ? payload.results : [];
  const moscowEntry = entries.find(({ probe }) => {
    const location = probe?.location || probe || {};
    return String(location.city || '').toLowerCase() === MOSCOW_CITY.toLowerCase() &&
      String(location.country || '').toUpperCase() === MOSCOW_COUNTRY;
  });

  if (!moscowEntry) {
    return { ok: false, error: 'Globalping returned no probe in Moscow, RU' };
  }

  const location = moscowEntry.probe?.location || moscowEntry.probe || {};
  const result = moscowEntry.result || {};
  if (result.status === 'in-progress') {
    return { pending: true, error: 'Moscow probe is still running' };
  }
  if (result.status !== 'finished') {
    return {
      ok: false,
      error: result.error || result.rawOutput || 'Moscow TCP measurement did not finish successfully',
      probe_location: 'Moscow',
      network: location.network || null,
      asn: location.asn || null,
    };
  }

  const stats = result.stats || {};
  const total = Math.max(0, Number(stats.total) || 0);
  const received = Math.max(0, Number(stats.rcv) || 0);
  const latency = Number(stats.avg);
  const minLatency = Number(stats.min);
  const maxLatency = Number(stats.max);
  const lossPct = Number.isFinite(Number(stats.loss))
    ? Number(stats.loss)
    : (total > 0 ? ((total - received) / total) * 100 : 100);

  if (!Number.isFinite(latency) || received === 0) {
    return {
      ok: false,
      error: result.rawOutput || result.error || 'Moscow TCP ping received no replies',
      received,
      total,
      loss_pct: Math.max(0, Math.min(100, Math.round(lossPct * 10) / 10)),
      probe_location: 'Moscow',
      network: location.network || null,
      asn: location.asn || null,
    };
  }

  const normalizedLoss = Math.max(0, Math.min(100, Math.round(lossPct * 10) / 10));
  const jitter = Number.isFinite(minLatency) && Number.isFinite(maxLatency)
    ? Math.max(0, maxLatency - minLatency)
    : 0;
  const ok = received >= Math.ceil(Math.max(1, total) * (2 / 3)) && normalizedLoss <= 33.4;

  return {
    ok,
    latency_ms: Math.max(1, Math.round(latency)),
    jitter_ms: Math.round(jitter),
    loss_pct: normalizedLoss,
    received,
    total,
    probe_location: 'Moscow',
    network: location.network || null,
    asn: location.asn || null,
    error: ok ? null : 'Moscow TCP ping had excessive packet loss',
  };
}

function findMoscowMeasurementEntry(payload) {
  if (payload?.pending === true) return payload;
  if (payload?.status === 'in-progress') return { pending: true, error: 'Moscow measurement is still in progress' };
  const entries = Array.isArray(payload?.results) ? payload.results : [];
  const entry = entries.find(({ probe }) => {
    const location = probe?.location || probe || {};
    return String(location.city || '').toLowerCase() === MOSCOW_CITY.toLowerCase() &&
      String(location.country || '').toUpperCase() === MOSCOW_COUNTRY;
  });
  return entry || null;
}

export function parseGlobalpingMtrResult(payload, targetHost = '') {
  const entry = findMoscowMeasurementEntry(payload);
  if (entry?.pending) return entry;
  if (!entry) return { ok: false, error: 'Globalping returned no MTR probe in Moscow, RU' };
  const location = entry.probe?.location || entry.probe || {};
  const result = entry.result || {};
  if (result.status === 'in-progress') return { pending: true, error: 'Moscow TCP MTR is still running' };
  if (result.status !== 'finished') {
    return { ok: false, error: result.error || result.rawOutput || 'Moscow TCP MTR did not finish', probe_location: 'Moscow' };
  }

  const hops = Array.isArray(result.hops) ? result.hops : [];
  const normalizeMtrAddress = (value) => String(value || '').replace(/^\\[|\\]$/g, '').toLowerCase();
  const resolvedAddress = normalizeMtrAddress(result.resolvedAddress);
  const finalHop = [...hops].reverse().find((hop) =>
    resolvedAddress && normalizeMtrAddress(hop?.resolvedAddress) === resolvedAddress
  );
  if (!finalHop) {
    return {
      ok: false,
      error: 'MTR route did not reach the resolved proxy endpoint',
      probe_location: 'Moscow',
      network: location.network || null,
      asn: location.asn || null,
      hops: hops.length,
    };
  }

  const stats = finalHop.stats || {};
  const total = Math.max(0, Number(stats.total) || 0);
  const received = Math.max(0, Number(stats.rcv) || 0);
  const latency = stats.avg == null ? Number.NaN : Number(stats.avg);
  const lossPct = stats.loss != null && Number.isFinite(Number(stats.loss))
    ? Number(stats.loss)
    : (total > 0 ? ((total - received) / total) * 100 : 100);
  const jitterValue = stats.jAvg ?? stats.jMax ?? stats.stDev;
  const jitter = jitterValue == null ? 0 : Number(jitterValue);
  const normalizedLoss = Math.max(0, Math.min(100, Math.round(lossPct * 10) / 10));
  const latencyMs = Number.isFinite(latency) ? Math.round(latency) : null;
  const jitterMs = Number.isFinite(jitter) ? Math.round(jitter) : 0;
  const ok = received >= Math.ceil(Math.max(1, total) * 0.8) &&
    normalizedLoss <= 20 &&
    Number.isFinite(latency) &&
    latency <= 450;

  return {
    ok,
    latency_ms: latencyMs,
    jitter_ms: jitterMs,
    loss_pct: normalizedLoss,
    received,
    total,
    hops: hops.length,
    target: resolvedAddress || targetHost,
    probe_location: 'Moscow',
    network: location.network || null,
    asn: location.asn || null,
    error: ok ? null : 'MTR target hop is unstable: packet loss, latency or missing replies exceed limits',
  };
}

export function parseGlobalpingDnsResult(payload, queryHost = '') {
  const entry = findMoscowMeasurementEntry(payload);
  if (entry?.pending) return entry;
  if (!entry) return { ok: false, error: 'Globalping returned no DNS probe in Moscow, RU' };
  const location = entry.probe?.location || entry.probe || {};
  const result = entry.result || {};
  if (result.status === 'in-progress') return { pending: true, error: 'Moscow DNS query is still running' };
  if (result.status !== 'finished') {
    return { ok: false, error: result.error || result.rawOutput || 'Moscow DNS query did not finish', probe_location: 'Moscow' };
  }
  const answers = Array.isArray(result.answers) ? result.answers : [];
  const statusCode = Number(result.statusCode);
  const queryMs = result.timings?.total == null ? Number.NaN : Number(result.timings.total);
  const ok = statusCode === 0 && answers.length > 0 && Number.isFinite(queryMs);
  return {
    ok,
    query_ms: Number.isFinite(queryMs) ? Math.round(queryMs) : null,
    answer_count: answers.length,
    answers: answers.slice(0, 4).map((answer) => ({
      type: String(answer.type || '').slice(0, 12),
      value: String(answer.value || '').slice(0, 100),
    })),
    resolver: result.resolver || '77.88.8.8',
    provider: 'Yandex DNS (77.88.8.8)',
    query_host: queryHost,
    dns_status: Number.isFinite(statusCode) ? statusCode : null,
    probe_location: 'Moscow',
    network: location.network || null,
    error: ok ? null : (statusCode !== 0
      ? `Yandex DNS returned ${result.statusCodeName || `RCODE ${statusCode}`}`
      : 'Yandex DNS returned no usable A record for the proxy endpoint'),
  };
}

export function parseGlobalpingDohTransportResult(payload) {
  const entry = findMoscowMeasurementEntry(payload);
  if (entry?.pending) return entry;
  if (!entry) return { ok: false, error: 'Globalping returned no Yandex DoH TLS probe in Moscow, RU' };
  const location = entry.probe?.location || entry.probe || {};
  const result = entry.result || {};
  if (result.status === 'in-progress') return { pending: true, error: 'Yandex DoH TLS test is still running' };
  if (result.status !== 'finished') {
    return { ok: false, error: result.error || result.rawOutput || 'Yandex DoH TLS test did not finish', probe_location: 'Moscow' };
  }
  const timings = result.timings || {};
  const tlsAuthorized = result.tls?.authorized === true;
  const tcpMs = timings.tcp == null ? Number.NaN : Number(timings.tcp);
  const tlsMs = timings.tls == null ? Number.NaN : Number(timings.tls);
  const ok = tlsAuthorized && Number.isFinite(tcpMs) && Number.isFinite(tlsMs);
  return {
    ok,
    tls_authorized: tlsAuthorized,
    tls_protocol: result.tls?.protocol || null,
    connect_ms: Number.isFinite(tcpMs) ? Math.round(tcpMs) : null,
    tls_ms: Number.isFinite(tlsMs) ? Math.round(tlsMs) : null,
    total_ms: timings.total == null ? null : Math.round(Number(timings.total)),
    http_status: Number(result.statusCode) || null,
    provider: 'Yandex DoH',
    host: 'common.dot.dns.yandex.net',
    probe_location: 'Moscow',
    network: location.network || null,
    error: ok ? null : (!tlsAuthorized
      ? 'Yandex DoH TLS certificate validation failed from Moscow'
      : 'Yandex DoH TCP/TLS timing is incomplete'),
  };
}

async function requestGlobalpingMeasurement(target, type, measurementOptions, fetchFn) {
  const headers = {
    accept: 'application/json',
    'content-type': 'application/json',
    'user-agent': 'LEDERG-Proxy-Scanner/3.0',
  };
  let dispatch;
  try {
    const response = await fetchFn(`${GLOBALPING_API}/measurements`, {
      method: 'POST',
      headers,
      signal: AbortSignal.timeout(GLOBALPING_REQUEST_TIMEOUT_MS),
      body: JSON.stringify({
        target,
        type,
        locations: [{ city: MOSCOW_CITY, country: MOSCOW_COUNTRY, limit: 1 }],
        timeout: 10,
        measurementOptions,
      }),
    });
    if (response.status === 429) return { pending: true, error: 'Globalping rate limit reached' };
    if (!response.ok) return { pending: true, error: `Globalping dispatch HTTP ${response.status}` };
    dispatch = await response.json();
  } catch (error) {
    return { pending: true, error: error instanceof Error ? error.message : String(error) };
  }

  if (!dispatch?.id) return { pending: true, error: dispatch?.error?.message || 'Globalping did not return a measurement ID' };
  for (let attempt = 0; attempt < GLOBALPING_POLL_ATTEMPTS; attempt += 1) {
    await sleep(GLOBALPING_POLL_DELAY_MS);
    try {
      const response = await fetchFn(`${GLOBALPING_API}/measurements/${encodeURIComponent(dispatch.id)}`, {
        headers,
        signal: AbortSignal.timeout(GLOBALPING_REQUEST_TIMEOUT_MS),
      });
      if (response.status === 429) return { pending: true, error: 'Globalping result rate limit reached' };
      if (!response.ok) return { pending: true, error: `Globalping result HTTP ${response.status}` };
      const measurement = await response.json();
      if (measurement.status === 'in-progress') continue;
      return measurement;
    } catch (error) {
      return { pending: true, error: error instanceof Error ? error.message : String(error) };
    }
  }
  return { pending: true, error: `Moscow ${type.toUpperCase()} measurement did not finish within the polling window` };
}

export async function probeMoscow(endpoint, kind = 'mtr', fetchFn = fetch) {
  if (!endpoint?.host || !Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535) {
    return { ok: false, error: 'Invalid TCP endpoint' };
  }
  if (kind === 'dns') {
    const queryHost = endpoint.host.includes(':') || /^\\d+(?:\\.\\d+){3}$/.test(endpoint.host)
      ? 'ya.ru'
      : endpoint.host;
    const measurement = await requestGlobalpingMeasurement(
      queryHost,
      'dns',
      {
        query: { type: 'A' },
        resolver: '77.88.8.8',
        protocol: 'UDP',
        port: 53,
        trace: false,
      },
      fetchFn,
    );
    return parseGlobalpingDnsResult(measurement, queryHost);
  }

  const measurement = await requestGlobalpingMeasurement(
    endpoint.host,
    'mtr',
    { protocol: 'TCP', port: endpoint.port, packets: 5 },
    fetchFn,
  );
  return parseGlobalpingMtrResult(measurement, endpoint.host);
}

export async function probeMoscowDohTransport(fetchFn = fetch) {
  const measurement = await requestGlobalpingMeasurement(
    'common.dot.dns.yandex.net',
    'http',
    {
      resolver: '77.88.8.8',
      protocol: 'HTTPS',
      port: 443,
      request: {
        method: 'HEAD',
        path: '/dns-query',
        headers: { accept: 'application/dns-message' },
      },
    },
    fetchFn,
  );
  return parseGlobalpingDohTransportResult(measurement);
}

export async function probeMoscowPair(endpoint, probeFn = probeMoscow) {
  // One TCP MTR to the proxy port plus one Yandex UDP DNS A-record lookup per Moscow endpoint.
  // A separate HTTPS/TLS reachability test to the Yandex DoH host runs once per scan.
  // 30 endpoints x 2 measurements x 4 scans/hour + 4 DoH checks = 244 tests/hour.
  const [mtr, dns] = await Promise.all([
    probeFn(endpoint, 'mtr'),
    probeFn(endpoint, 'dns'),
  ]);
  const checks = [mtr, dns];
  const completed = checks.filter((check) => check && !check.pending);
  const allCompleted = completed.length === 2;
  const ok = allCompleted && mtr.ok === true && dns.ok === true;
  const sample = allCompleted ? {
    at: new Date().toISOString(),
    ok,
    ...(mtr.ok && Number.isFinite(Number(mtr.latency_ms)) ? {
      latency_ms: Number(mtr.latency_ms),
      jitter_ms: Number(mtr.jitter_ms) || 0,
      loss_pct: Number(mtr.loss_pct) || 0,
      network: mtr.network || null,
    } : {}),
    error: ok ? null : [mtr.error, dns.error].filter(Boolean).join('; ') || 'Moscow MTR and DoH checks must both pass',
  } : null;

  return {
    ok,
    pending: !allCompleted,
    samples: sample ? [sample] : [],
    measurements_completed: completed.length,
    measurements_requested: 2,
    latency_ms: mtr.latency_ms ?? null,
    jitter_ms: mtr.jitter_ms ?? null,
    loss_pct: mtr.loss_pct ?? null,
    network: mtr.network || dns.network || null,
    probe_location: 'Moscow',
    mtr,
    dns,
    error: ok ? null : (!allCompleted
      ? checks.find((check) => check?.pending)?.error || 'Moscow diagnostics are still pending'
      : sample?.error || 'Moscow diagnostics failed'),
  };
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

export function evaluateMoscowHistory(samples) {
  const history = (Array.isArray(samples) ? samples : []).slice(-HISTORY_SIZE);
  const successful = history.filter((sample) => sample?.ok && Number.isFinite(Number(sample.latency_ms)));
  const latencies = successful.map((sample) => Number(sample.latency_ms)).sort((a, b) => a - b);
  const jitterValues = successful.map((sample) => Number(sample.jitter_ms) || 0).sort((a, b) => a - b);
  const lossValues = successful.map((sample) => Number(sample.loss_pct) || 0);
  const median = (values) => {
    if (!values.length) return null;
    const middle = Math.floor(values.length / 2);
    return values.length % 2 ? values[middle] : (values[middle - 1] + values[middle]) / 2;
  };
  const successCount = successful.length;
  const reliability = history.length ? Math.round((successCount / history.length) * 100) : 0;
  let consecutiveSuccesses = 0;
  let consecutiveFailures = 0;
  for (let index = history.length - 1; index >= 0; index -= 1) {
    if (history[index]?.ok) {
      if (consecutiveFailures > 0) break;
      consecutiveSuccesses += 1;
    } else {
      if (consecutiveSuccesses > 0) break;
      consecutiveFailures += 1;
    }
  }
  const latency = median(latencies);
  const jitter = median(jitterValues);
  const loss = lossValues.length ? lossValues.reduce((sum, value) => sum + value, 0) / lossValues.length : null;
  const score = latency == null ? null : Math.round(latency + jitter * 0.5 + (loss || 0) * 2.5);
  return {
    latency_ms: latency == null ? null : Math.round(latency),
    jitter_ms: jitter == null ? 0 : Math.round(jitter),
    loss_pct: loss == null ? null : Math.round(loss * 10) / 10,
    reliability_pct: reliability,
    consecutive_successes: consecutiveSuccesses,
    consecutive_failures: consecutiveFailures,
    score,
    available: successCount >= 2 && reliability >= 80 && consecutiveSuccesses >= 2 && consecutiveFailures < 2,
  };
}

export function applyProbeResult(state, endpoint, result, now) {
  const existing = state.endpoints[endpoint.key] || {};
  const previous = existing.probe_location === 'Moscow'
    ? existing
    : { recent_samples: [], pending_count: 0 };
  const updated = {
    ...previous,
    probe_location: 'Moscow',
    last_checked_at: new Date(now).toISOString(),
    last_pair_checked_at: new Date(now).toISOString(),
    last_pair_ok: Boolean(result && !result.pending && result.ok),
    mtr: result?.mtr ? {
      ok: Boolean(result.mtr.ok),
      latency_ms: result.mtr.latency_ms ?? null,
      jitter_ms: result.mtr.jitter_ms ?? null,
      loss_pct: result.mtr.loss_pct ?? null,
      hops: result.mtr.hops ?? null,
      probe_location: result.mtr.probe_location || 'Moscow',
      network: result.mtr.network || null,
      error: result.mtr.error || null,
    } : previous.mtr || null,
    dns: result?.dns ? {
      ok: Boolean(result.dns.ok),
      provider: result.dns.provider || 'Yandex DNS (77.88.8.8)',
      query_ms: result.dns.query_ms ?? null,
      answer_count: result.dns.answer_count ?? 0,
      dns_status: result.dns.dns_status ?? null,
      query_host: result.dns.query_host || null,
      probe_location: result.dns.probe_location || 'Moscow',
      error: result.dns.error || null,
    } : previous.dns || null,
  };

  const incomingSamples = Array.isArray(result?.samples)
    ? result.samples.filter((sample) => sample && !sample.pending)
    : (result?.pending ? [] : [result]);
  const normalizedSamples = incomingSamples.map((sample) => sample.ok
    ? {
        at: new Date(now).toISOString(),
        ok: true,
        latency_ms: Number(sample.latency_ms),
        jitter_ms: Number(sample.jitter_ms) || 0,
        loss_pct: Number(sample.loss_pct) || 0,
        network: sample.network || result.network || null,
      }
    : {
        at: new Date(now).toISOString(),
        ok: false,
        error: sample.error || result?.error || 'Moscow TCP probe failed',
      });

  if (normalizedSamples.length) {
    updated.recent_samples = [...(previous.recent_samples || []), ...normalizedSamples].slice(-HISTORY_SIZE);
    const quality = evaluateMoscowHistory(updated.recent_samples);
    Object.assign(updated, quality);

    const latestSuccess = [...normalizedSamples].reverse().find((sample) => sample.ok);
    if (latestSuccess) {
      updated.last_success_at = new Date(now).toISOString();
      updated.network = latestSuccess.network || previous.network || null;
      updated.asn = result.asn || previous.asn || null;
    }

    const latestFailure = [...normalizedSamples].reverse().find((sample) => !sample.ok);
    updated.last_probe_error = latestFailure?.error || result?.error || null;
  }

  if (result?.pending) {
    updated.pending_count = Math.min(9, (previous.pending_count || 0) + 1);
    updated.last_probe_error = result.error || 'Moscow TCP test is still pending';
  } else {
    updated.pending_count = 0;
  }

  state.endpoints[endpoint.key] = updated;
  return updated;
}

export function selectVerifiableConfigs(configs, limit = 3) {
  if (!Array.isArray(configs) || !Number.isInteger(limit) || limit < 1) return [];
  return configs.filter((config) => getVlessProbeSupport(config).supported).slice(0, limit);
}

export function applyProxyVerificationResult(state, endpoint, config, result, now) {
  const status = state.endpoints[endpoint.key] || {};
  if (!status.verified_configs || typeof status.verified_configs !== 'object') status.verified_configs = {};
  const services = result?.services || null;
  const servicesOk = services?.youtube?.ok === true && services?.discord?.ok === true;
  const verificationOk = Boolean(result?.ok && result?.supported !== false && servicesOk);
  const verification = {
    ok: verificationOk,
    supported: result?.supported !== false,
    services,
    verified_at: new Date(now).toISOString(),
    verifier: result?.verifier || 'VLESS protocol + HTTP egress',
    probe_location: result?.probe_location || 'Cloudflare Worker egress (not Moscow)',
    connect_ms: Number.isFinite(Number(result?.connect_ms)) ? Number(result.connect_ms) : null,
    tunnel_ms: Number.isFinite(Number(result?.tunnel_ms)) ? Number(result.tunnel_ms) : null,
    download_ms: Number.isFinite(Number(result?.download_ms)) ? Number(result.download_ms) : null,
    download_bytes: Number(result?.download_bytes) || 0,
    download_mbps: Number(result?.download_mbps) || 0,
    http_status: Number(result?.http_status) || null,
    target: result?.target || null,
    error: verificationOk ? null : (
      result?.error || services?.error ||
      (!services ? 'YouTube and Discord HTTPS checks were not completed' : 'YouTube or Discord is unreachable through the proxy')
    ),
  };
  status.verified_configs[config.uri] = verification;
  state.endpoints[endpoint.key] = status;
  return verification;
}

function getActiveNodes(pool, state, now) {
  const nodes = [];
  for (const endpoint of pool) {
    const status = state.endpoints[endpoint.key];
    if (status?.probe_location !== 'Moscow' || status.last_pair_ok !== true || status.mtr?.ok !== true || status.dns?.ok !== true || !status.available || !Number.isFinite(Number(status.latency_ms))) continue;
    const lastSuccess = Date.parse(status.last_success_at || '');
    if (!Number.isFinite(lastSuccess) || now - lastSuccess > ACTIVE_TTL_MS) continue;
    for (const config of endpoint.configs) {
      const functionalProbe = status.verified_configs?.[config.uri];
      const functionalAt = Date.parse(functionalProbe?.verified_at || '');
      if (!functionalProbe?.ok || !Number.isFinite(functionalAt) || now - functionalAt > ACTIVE_TTL_MS) continue;
      nodes.push({
        ...config,
        ping_ms: Number(status.latency_ms),
        jitter_ms: Number(status.jitter_ms) || 0,
        loss_pct: Number(status.loss_pct) || 0,
        reliability_pct: Number(status.reliability_pct) || 0,
        score: Number(status.score) || Number(status.latency_ms),
        stable_checks: Number(status.consecutive_successes) || 0,
        endpoint: endpoint.key,
        probe_location: 'Moscow',
        probe_network: status.network || null,
        moscow_mtr: status.mtr,
        moscow_dns: status.dns,
        functional_probe: functionalProbe,
      });
    }
  }
  const unique = new Map();
  for (const node of nodes) if (!unique.has(node.uri)) unique.set(node.uri, node);
  return Array.from(unique.values())
    .sort((a, b) => Number(a.score) - Number(b.score) || a.ping_ms - b.ping_ms)
    .slice(0, 500);
}

export function renderHappSubscription(nodes) {
  const uris = (Array.isArray(nodes) ? nodes : [])
    .filter((node) => node?.functional_probe?.ok === true)
    .filter((node) => typeof node?.uri === 'string' && /^(vless|vmess|ss|trojan|socks5?|hysteria2|hy2):\/\//i.test(node.uri))
    .sort((a, b) => Number(a.score ?? a.ping_ms ?? 999999) - Number(b.score ?? b.ping_ms ?? 999999))
    .map((node) => node.uri.trim());
  return [
    '#profile-title: LEDERG PROXY',
    '#profile-update-interval: 1',
    ...uris,
    '',
  ].join('\n');
}

function truthyParam(value) {
  return ['1', 'true', 'yes'].includes(String(value ?? '').toLowerCase());
}

export const MOSCOW_DNS_SERVERS = [
  'https://common.dot.dns.yandex.net/dns-query',
  'https://unfiltered.adguard-dns.com/dns-query',
  'https://dns10.quad9.net/dns-query',
  'https://dns.google/dns-query',
];

export function buildMoscowDnsConfig() {
  return {
    hosts: {
      'common.dot.dns.yandex.net': ['77.88.8.8', '77.88.8.1'],
      'dns.google': ['8.8.8.8', '8.8.4.4'],
      'unfiltered.adguard-dns.com': ['94.140.14.140', '94.140.14.141'],
      'dns10.quad9.net': ['9.9.9.10', '149.112.112.10'],
    },
    servers: [...MOSCOW_DNS_SERVERS],
    queryStrategy: 'UseIP',
    disableCache: false,
    disableFallback: false,
    disableFallbackIfMatch: false,
    enableParallelQuery: false,
  };
}

export function buildXrayStreamSettings(network, security, values, fallbackHost) {
  const stream = { network: network || 'tcp', security: security || 'none' };
  const configuredSni = values.sni || values.serverName || values.host || values.server_name;
  const sni = configuredSni || fallbackHost;
  const fingerprint = values.fp || values.fingerprint || 'chrome';

  if (stream.security === 'tls') {
    const tlsSettings = { serverName: sni, fingerprint };
    const alpn = String(values.alpn || '').split(',').map((item) => item.trim()).filter(Boolean);
    if (alpn.length) tlsSettings.alpn = alpn;
    if (truthyParam(values.allowInsecure || values.insecure)) tlsSettings.allowInsecure = true;
    const echConfigList = values.echConfigList || values.ech;
    if (echConfigList) tlsSettings.echConfigList = echConfigList;
    stream.tlsSettings = tlsSettings;
  } else if (stream.security === 'reality') {
    const realitySettings = { fingerprint };
    if (configuredSni) realitySettings.serverName = configuredSni;
    const publicKey = values.pbk || values.password || values.publicKey;
    const shortId = values.sid || values.shortId;
    const spiderX = values.spx || values.spiderX;
    if (publicKey) realitySettings.password = publicKey;
    if (shortId) realitySettings.shortId = shortId;
    if (spiderX) realitySettings.spiderX = spiderX;
    const mldsa65Verify = values.mldsa65Verify || values.mldsa65_verify;
    if (mldsa65Verify) realitySettings.mldsa65Verify = mldsa65Verify;
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

function isRealityCompatibleTransport(network) {
  return ['tcp', 'raw', 'xhttp', 'grpc'].includes(String(network || 'tcp').toLowerCase());
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
    if (security === 'reality' && !isRealityCompatibleTransport(network)) return null;
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
    if (security === 'reality' && !isRealityCompatibleTransport(network)) return null;
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
    .sort((a, b) => Number(a.score ?? a.ping_ms ?? 999999) - Number(b.score ?? b.ping_ms ?? 999999));
  for (const node of sorted) {
    try {
      if (node?.functional_probe?.ok !== true) continue;
      const proxy = createXrayOutbound(node);
      if (!proxy) continue;
      const location = node.country_name || COUNTRY_NAMES[node.country] || 'Unknown';
      profiles.push({
        remarks: `${location} | ${String(node.protocol).toUpperCase()} | Moscow ${Math.round(Number(node.ping_ms) || 0)}ms | YT ${node.functional_probe.services?.youtube?.response_ms ?? '—'}ms | DC ${node.functional_probe.services?.discord?.response_ms ?? '—'}ms | DL ${Number(node.functional_probe.download_mbps).toFixed(2)} Mbps`,
        log: { loglevel: 'warning' },
        dns: buildMoscowDnsConfig(),
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
        meta: {
          serverDescription: `${node.source || 'public source'}; Moscow TCP ${Math.round(Number(node.ping_ms) || 0)}ms; RTT spread ${Math.round(Number(node.jitter_ms) || 0)}ms; loss ${Number(node.loss_pct) || 0}%`,
          moscowProbe: { city: 'Moscow', country: 'RU', network: node.probe_network || null },
          tlsCamouflage: proxy.streamSettings?.security === 'reality'
            ? `REALITY + uTLS ${proxy.streamSettings.realitySettings?.fingerprint || 'source fingerprint'}`
            : proxy.streamSettings?.security === 'tls'
              ? `TLS + uTLS ${proxy.streamSettings.tlsSettings?.fingerprint || 'source fingerprint'}`
              : 'Native protocol settings from source link',
          dnsProviders: ['Yandex DoH', 'AdGuard DoH', 'Quad9 DoH', 'Google DoH'],
          proxyVerification: {
            level: node.functional_probe.verifier,
            status: 'passed',
            tested_at: node.functional_probe.verified_at,
            probe_location: node.functional_probe.probe_location,
            connect_ms: node.functional_probe.connect_ms,
            tunnel_ms: node.functional_probe.tunnel_ms,
            download_ms: node.functional_probe.download_ms,
            download_bytes: node.functional_probe.download_bytes,
            download_mbps: node.functional_probe.download_mbps,
            http_status: node.functional_probe.http_status,
            target: node.functional_probe.target,
            services: node.functional_probe.services,
            required_services: ['YouTube HTTPS /generate_204', 'Discord HTTPS /api/v10/gateway'],
            note: 'Moscow reachability is measured separately by Globalping. VLESS authentication, download and YouTube/Discord HTTPS checks run through the proxy from Cloudflare Worker egress, not Moscow.',
          },
        },
      });
      if (profiles.length >= 150) break;
    } catch {
      // Skip malformed or unsupported shared links rather than publishing invalid profiles.
    }
  }
  return profiles;
}

export function buildManifest({ now = new Date().toISOString(), candidates = 0, checked = 0, measurements = 0, nodes = [] } = {}) {
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
      provider: 'Globalping community probes',
      city: MOSCOW_CITY,
      country: MOSCOW_COUNTRY,
      method: 'Globalping TCP MTR (5 packets/hop) to the proxy port and Yandex DNS A-record lookup (77.88.8.8/UDP) per Moscow proxy probe; a separate HTTPS/TLS reachability check to the Yandex DoH hostname each scan; full VLESS tunnel and download from Cloudflare Worker egress',
      meaning: 'Moscow MTR must reach the proxy endpoint with at least 80% replies, no more than 20% loss and RTT <=450ms. Yandex DNS must return an A-record for the proxy hostname. A separate Moscow HTTPS test validates the Yandex DoH TLS endpoint. Full VLESS authentication, HTTP 200 and download speed are additionally verified from Cloudflare Worker egress, not Moscow.',
      functional_verification: {
        protocol: 'VLESS',
        transports: ['TCP', 'RAW', 'WebSocket'],
        security: ['none', 'TLS with source SNI'],
        min_download_bytes: PROXY_VERIFY_LIMITS.min_download_bytes,
        min_download_mbps: PROXY_VERIFY_LIMITS.min_download_mbps,
        required_services: ['YouTube HTTPS /generate_204', 'Discord HTTPS /api/v10/gateway'],
        service_policy: 'Both target TLS certificates must validate and both HTTP status codes must match expected success codes',
        probe_location: 'Cloudflare Worker egress through VLESS tunnel, not Moscow',
      },
    },
    stats: {
      candidate_endpoints: candidates,
      checked_this_run: checked,
      checked_endpoints_this_run: checked,
      measurements_this_run: measurements,
      active_endpoints: endpoints.size,
      active_configs: sorted.length,
      fully_verified_configs: sorted.length,
      average_download_mbps: sorted.length ? Number((sorted.reduce((sum, node) => sum + (Number(node.functional_probe?.download_mbps) || 0), 0) / sorted.length).toFixed(3)) : 0,
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
      score: Number(node.score),
      jitter_ms: Number(node.jitter_ms) || 0,
      loss_pct: Number(node.loss_pct) || 0,
      reliability_pct: Number(node.reliability_pct) || 0,
      probe_location: node.probe_location || 'Moscow',
      probe_network: node.probe_network || null,
      stable_checks: Number(node.stable_checks || 1),
      protocol_verified: node.functional_probe?.ok === true,
      verifier: node.functional_probe?.verifier || null,
      verification_location: node.functional_probe?.probe_location || null,
      proxy_connect_ms: node.functional_probe?.connect_ms ?? null,
      proxy_tunnel_ms: node.functional_probe?.tunnel_ms ?? null,
      speed_test_bytes: node.functional_probe?.download_bytes ?? 0,
      download_mbps: node.functional_probe?.download_mbps ?? 0,
      verification_http_status: node.functional_probe?.http_status ?? null,
      youtube: node.functional_probe?.services?.youtube || { ok: false, error: 'not checked' },
      discord: node.functional_probe?.services?.discord || { ok: false, error: 'not checked' },
      verification_tested_at: node.functional_probe?.verified_at || null,
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

async function runScanner(env, scheduledTime = Date.now()) {
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
  const [results, dohTransport] = await Promise.all([
    mapLimit(batch, PROBE_CONCURRENCY, (endpoint) => probeMoscowPair(endpoint)),
    probeMoscowDohTransport(),
  ]);
  results.forEach((result, index) => applyProbeResult(state, batch[index], result, now));

  const verificationJobs = [];
  for (let index = 0; index < batch.length; index += 1) {
    const endpoint = batch[index];
    const moscowResult = results[index];
    const selected = moscowResult?.ok ? selectVerifiableConfigs(endpoint.configs, 3) : [];
    const selectedUris = new Set(selected.map((config) => config.uri));
    for (const config of endpoint.configs) {
      if (selectedUris.has(config.uri)) {
        verificationJobs.push({ endpoint, config });
      } else {
        applyProxyVerificationResult(state, endpoint, config, {
          ok: false,
          supported: false,
          error: moscowResult?.ok
            ? 'Not selected for this scan cycle (per-endpoint verification cap)'
            : (moscowResult?.error || 'Moscow TCP pair did not pass'),
        }, now);
      }
    }
  }
  const verificationResults = await mapLimit(
    verificationJobs,
    VERIFIER_CONCURRENCY,
    async ({ config }) => {
      const proxyCheck = await verifyVlessProxy(config);
      if (!proxyCheck?.ok) {
        const skipped = {
          youtube: { ok: false, service: 'youtube', error: proxyCheck?.error || 'Base proxy verification failed' },
          discord: { ok: false, service: 'discord', error: proxyCheck?.error || 'Base proxy verification failed' },
        };
        return { ...proxyCheck, services: skipped, verifier: 'VLESS + download; service checks skipped after base failure' };
      }
      const services = await verifyVlessServices(config);
      return {
        ...proxyCheck,
        ok: services.ok === true,
        services: { youtube: services.youtube, discord: services.discord },
        verifier: 'VLESS + download + YouTube HTTPS + Discord HTTPS',
        error: services.ok ? null : services.error,
      };
    },
  );
  verificationResults.forEach((result, index) => {
    const job = verificationJobs[index];
    applyProxyVerificationResult(state, job.endpoint, job.config, result, now);
  });
  const protocolPassed = verificationResults.filter((result) => result?.ok).length;
  const protocolUnsupported = verificationResults.filter((result) => result?.supported === false).length;
  const youtubePassed = verificationResults.filter((result) => result?.services?.youtube?.ok === true).length;
  const discordPassed = verificationResults.filter((result) => result?.services?.discord?.ok === true).length;
  const serviceChecks = verificationResults.filter((result) => result?.services).length;
  const speedSamples = verificationResults.filter((result) => result?.ok && Number.isFinite(Number(result.download_mbps)));
  const averageDownloadMbps = speedSamples.length
    ? Number((speedSamples.reduce((sum, result) => sum + Number(result.download_mbps), 0) / speedSamples.length).toFixed(3))
    : 0;
  const downloadBytes = speedSamples.reduce((sum, result) => sum + (Number(result.download_bytes) || 0), 0);
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
  const measurementCount = batch.length * 2 + 1;
  const fingerprintPayload = buildManifest({ now: '', candidates: pool.length, checked: batch.length, measurements: measurementCount, nodes: activeNodes });
  const contentFingerprint = await sha256Hex(`${JSON.stringify(fingerprintPayload)}\n${subscriptionText}\n${happJsonText}`);
  const contentChanged = contentFingerprint !== state.last_content_fingerprint;
  const publishedAt = contentChanged ? new Date(now).toISOString() : (state.last_published_at || new Date(now).toISOString());
  state.last_published_at = publishedAt;
  const stablePayload = buildManifest({ now: publishedAt, candidates: pool.length, checked: batch.length, measurements: measurementCount, nodes: activeNodes });
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
    moscow_pairs_ok: results.filter((result) => result?.ok).length,
    moscow_measurements: results.reduce((sum, result) => sum + (Number(result?.measurements_completed) || 0), 0) + Number(dohTransport && !dohTransport.pending),
    yandex_doh_transport: dohTransport,
    pending_or_errors: results.filter((result) => !result?.ok).length,
    estimated_sweep_minutes: calculateSweepMinutes(pool.length),
    protocol_checks: verificationResults.length,
    protocol_passed: protocolPassed,
    protocol_unsupported: protocolUnsupported,
    service_checks: serviceChecks,
    youtube_passed: youtubePassed,
    discord_passed: discordPassed,
    services_fully_passed: verificationResults.filter((result) => result?.services?.youtube?.ok === true && result?.services?.discord?.ok === true).length,
    speed_test_bytes: downloadBytes,
    average_download_mbps: averageDownloadMbps,
    probe_results: results.map((result, index) => ({
      endpoint: batch[index].key,
      status: result?.ok ? 'ok' : result?.pending ? 'pending' : 'failed',
      measurements_completed: Number(result?.measurements_completed) || 0,
      measurement_successes: Number(Boolean(result?.mtr?.ok)) + Number(Boolean(result?.dns?.ok)),
      mtr: result?.mtr || null,
      dns: result?.dns || null,
      latency_ms: result?.latency_ms ?? null,
      jitter_ms: result?.jitter_ms ?? null,
      loss_pct: result?.loss_pct ?? null,
      probe_location: result?.probe_location || 'Moscow',
      network: result?.network || null,
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
        probe: { provider: 'Globalping community probes', city: MOSCOW_CITY, country: MOSCOW_COUNTRY, method: 'TCP MTR + Yandex DNS from Moscow; VLESS authentication, download and HTTPS requests to YouTube and Discord through each proxy from Cloudflare Worker egress' },
        schedule: '15-minute scan; up to 30 endpoints; 2 Globalping measurements per endpoint + 1 Yandex DoH TLS check per scan; 244 measurements/hour max; VLESS auth + 256 KiB download + YouTube HTTPS + Discord HTTPS through proxy',
        max_tests_per_hour: 240,
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

  async scheduled(controller, env) {
    try {
      await runScanner(env, controller.scheduledTime);
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
