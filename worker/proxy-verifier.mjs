const TEXT = new TextEncoder();
const TEST_HOST = 'ipv4.download.thinkbroadband.com';
const TEST_PATH = '/1MB.zip';
const MIN_DOWNLOAD_BYTES = 256 * 1024;
const MIN_DOWNLOAD_MBPS = 1;
const SOCKET_TIMEOUT_MS = 9000;
const DOWNLOAD_TIMEOUT_MS = 10000;

function concatBytes(...parts) {
  const arrays = parts.filter(Boolean).map((part) => part instanceof Uint8Array ? part : new Uint8Array(part));
  const out = new Uint8Array(arrays.reduce((sum, item) => sum + item.length, 0));
  let offset = 0;
  for (const item of arrays) { out.set(item, offset); offset += item.length; }
  return out;
}

function bytesToHex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function base64(value) {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function normalizedHost(value) {
  return String(value || '').replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
}

function timeout(promise, ms, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), ms); }),
  ]).finally(() => clearTimeout(timer));
}

export function getVlessProbeSupport(node) {
  try {
    if (String(node?.protocol || '').toLowerCase() !== 'vless') {
      return { supported: false, reason: 'Full protocol verifier currently supports VLESS only' };
    }
    const url = new URL(node.uri);
    const params = url.searchParams;
    const network = String(params.get('type') || params.get('network') || 'tcp').toLowerCase();
    const security = String(params.get('security') || 'none').toLowerCase();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(decodeURIComponent(url.username))) {
      return { supported: false, reason: 'Invalid VLESS UUID' };
    }
    if (params.get('flow')) return { supported: false, reason: 'VLESS flow requires Xray-compatible client verification' };
    if (!['tcp', 'raw', 'ws'].includes(network)) return { supported: false, reason: `Transport ${network} is not verified by this checker` };
    if (!['none', 'tls'].includes(security)) return { supported: false, reason: `Security mode ${security} requires a dedicated verifier` };
    const sni = params.get('sni') || params.get('servername') || params.get('serverName') || node.host;
    if (security === 'tls' && normalizedHost(sni) !== normalizedHost(node.host)) {
      return { supported: false, reason: 'Worker TCP sockets cannot set a separate TLS SNI; endpoint SNI differs from host' };
    }
    const wsHost = params.get('host') || node.host;
    if (network === 'ws' && !wsHost) return { supported: false, reason: 'WebSocket Host header is missing' };
    return {
      supported: true,
      network,
      security,
      path: params.get('path') || '/',
      wsHost,
      sni,
    };
  } catch {
    return { supported: false, reason: 'Malformed VLESS configuration' };
  }
}

export function buildVlessProbeRequest(uri, targetHost = TEST_HOST, targetPort = 80, targetPath = TEST_PATH) {
  const url = new URL(uri);
  const uuid = decodeURIComponent(url.username).replace(/-/g, '');
  if (!/^[0-9a-f]{32}$/i.test(uuid)) throw new Error('Invalid VLESS UUID');
  const uuidBytes = Uint8Array.from(uuid.match(/.{2}/g), (pair) => Number.parseInt(pair, 16));
  const hostBytes = TEXT.encode(targetHost);
  if (hostBytes.length > 255) throw new Error('Target host is too long');
  const port = Number(targetPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid target port');
  const header = new Uint8Array(1 + 16 + 1 + 1 + 2 + 1 + 1 + hostBytes.length);
  let offset = 0;
  header[offset++] = 0;
  header.set(uuidBytes, offset); offset += 16;
  header[offset++] = 0; // no protobuf addons
  header[offset++] = 1; // TCP CONNECT
  header[offset++] = (port >> 8) & 0xff;
  header[offset++] = port & 0xff;
  header[offset++] = 2; // domain address
  header[offset++] = hostBytes.length;
  header.set(hostBytes, offset);
  const http = TEXT.encode(`GET ${targetPath} HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: LEDERG-Proxy-Health/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
  return concatBytes(header, http);
}

class ByteQueue {
  constructor(nextChunk, writeChunk) {
    this.nextChunk = nextChunk;
    this.writeChunk = writeChunk;
    this.buffer = new Uint8Array(0);
  }
  async fill(ms = SOCKET_TIMEOUT_MS) {
    const value = await timeout(this.nextChunk(), ms, 'Timed out waiting for proxy response');
    if (!value || value.length === 0) throw new Error('Proxy closed the connection');
    this.buffer = concatBytes(this.buffer, value);
  }
  async readExactly(length, ms = SOCKET_TIMEOUT_MS) {
    while (this.buffer.length < length) await this.fill(ms);
    const out = this.buffer.slice(0, length);
    this.buffer = this.buffer.slice(length);
    return out;
  }
  async readUntil(delimiter, maxBytes = 16384, ms = SOCKET_TIMEOUT_MS) {
    const marker = delimiter instanceof Uint8Array ? delimiter : TEXT.encode(delimiter);
    while (true) {
      outer: for (let i = 0; i <= this.buffer.length - marker.length; i += 1) {
        for (let j = 0; j < marker.length; j += 1) if (this.buffer[i + j] !== marker[j]) continue outer;
        const end = i + marker.length;
        if (end > maxBytes) throw new Error('Proxy response header exceeded the size limit');
        const out = this.buffer.slice(0, end);
        this.buffer = this.buffer.slice(end);
        return out;
      }
      if (this.buffer.length > maxBytes) throw new Error('Proxy response header exceeded the size limit');
      await this.fill(ms);
    }
  }
  async readSome(ms = DOWNLOAD_TIMEOUT_MS) {
    if (this.buffer.length) {
      const out = this.buffer;
      this.buffer = new Uint8Array(0);
      return out;
    }
    return timeout(this.nextChunk(), ms, 'Download stalled through proxy');
  }
  write(bytes) { return this.writeChunk(bytes); }
}

function makeWebSocketFrame(payload, opcode = 2) {
  const data = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  const mask = crypto.getRandomValues(new Uint8Array(4));
  let header;
  if (data.length < 126) {
    header = new Uint8Array([0x80 | opcode, 0x80 | data.length]);
  } else if (data.length <= 65535) {
    header = new Uint8Array([0x80 | opcode, 0x80 | 126, data.length >> 8, data.length & 255]);
  } else {
    throw new Error('WebSocket probe frame is too large');
  }
  const masked = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 1) masked[i] = data[i] ^ mask[i % 4];
  return concatBytes(header, mask, masked);
}

async function readWebSocketMessage(raw, rawWriter) {
  const chunks = [];
  let total = 0;
  let expectedOpcode = 0;
  while (true) {
    const first = await raw.readExactly(2);
    const fin = Boolean(first[0] & 0x80);
    const opcode = first[0] & 0x0f;
    const masked = Boolean(first[1] & 0x80);
    let length = first[1] & 0x7f;
    if (length === 126) length = new DataView((await raw.readExactly(2)).buffer).getUint16(0);
    else if (length === 127) throw new Error('WebSocket 64-bit frame is not supported by the health probe');
    if (length > 1024 * 1024) throw new Error('WebSocket response frame is too large');
    const mask = masked ? await raw.readExactly(4) : null;
    const payload = await raw.readExactly(length);
    if (mask) for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
    if (opcode === 8) throw new Error('Proxy closed the WebSocket tunnel');
    if (opcode === 9) {
      await rawWriter(makeWebSocketFrame(payload, 10));
      continue;
    }
    if (opcode === 10) continue;
    if (opcode === 2) expectedOpcode = 2;
    else if (opcode !== 0) throw new Error('Proxy returned a non-binary WebSocket message');
    chunks.push(payload);
    total += payload.length;
    if (total > 1024 * 1024) throw new Error('WebSocket message exceeded the size limit');
    if (fin) {
      if (expectedOpcode !== 2) throw new Error('Invalid WebSocket continuation sequence');
      return concatBytes(...chunks);
    }
  }
}

async function createTunnel(socket, node, support) {
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  const raw = new ByteQueue(
    async () => {
      const result = await reader.read();
      if (result.done) throw new Error('Proxy closed the TCP socket');
      return result.value;
    },
    (bytes) => writer.write(bytes),
  );
  if (support.network !== 'ws') return raw;

  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const key = base64(nonce);
  const request = [
    `GET ${support.path} HTTP/1.1`,
    `Host: ${support.wsHost}`,
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Key: ${key}`,
    'Sec-WebSocket-Version: 13',
    'User-Agent: LEDERG-Proxy-Health/1.0',
    '',
    '',
  ].join('\r\n');
  await raw.write(TEXT.encode(request));
  const handshake = new TextDecoder().decode(await raw.readUntil('\r\n\r\n'));
  if (!/^HTTP\/1\.[01] 101\b/i.test(handshake)) throw new Error(`WebSocket upgrade rejected: ${handshake.split('\r\n')[0] || 'no status'}`);
  const accept = handshake.match(/^sec-websocket-accept:\s*(.+)$/im)?.[1]?.trim();
  const digest = await crypto.subtle.digest('SHA-1', TEXT.encode(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'));
  if (accept !== base64(new Uint8Array(digest))) throw new Error('Invalid WebSocket Sec-WebSocket-Accept');
  return new ByteQueue(
    () => readWebSocketMessage(raw, (bytes) => raw.write(bytes)),
    (bytes) => raw.write(makeWebSocketFrame(bytes)),
  );
}

async function readHttpHeaders(tunnel) {
  const headerBytes = await tunnel.readUntil('\r\n\r\n', 32768);
  const headerText = new TextDecoder().decode(headerBytes);
  const lines = headerText.split('\r\n');
  const match = lines[0]?.match(/^HTTP\/1\.[01]\s+(\d{3})/i);
  if (!match) throw new Error('The upstream proxy tunnel did not return a valid HTTP response');
  const headers = {};
  for (const line of lines.slice(1)) {
    const at = line.indexOf(':');
    if (at > 0) headers[line.slice(0, at).trim().toLowerCase()] = line.slice(at + 1).trim();
  }
  return { status: Number(match[1]), headers };
}

export async function verifyVlessProxy(node, connectFn) {
  const support = getVlessProbeSupport(node);
  if (!support.supported) return { ok: false, supported: false, error: support.reason };
  let socket;
  const startedAt = performance.now();
  try {
    let connector = connectFn;
    if (!connector) {
      const sockets = await import('cloudflare:sockets');
      connector = sockets.connect;
    }
    socket = connector(
      { hostname: node.host, port: node.port },
      { secureTransport: support.security === 'tls' ? 'on' : 'off', allowHalfOpen: true },
    );
    await timeout(socket.opened, SOCKET_TIMEOUT_MS, 'TCP/TLS connection to the proxy timed out');
    const connectedAt = performance.now();
    const tunnel = await createTunnel(socket, node, support);
    const request = buildVlessProbeRequest(node.uri);
    await tunnel.write(request);
    const vlessHeader = await tunnel.readExactly(2);
    if (vlessHeader[0] !== 0) throw new Error('The proxy did not return a valid VLESS response header');
    const addonLength = vlessHeader[1];
    if (addonLength > 0) await tunnel.readExactly(addonLength);
    const http = await readHttpHeaders(tunnel);
    if (http.status !== 200) throw new Error(`Proxy tunnel HTTP test returned status ${http.status}`);
    const declaredLength = Number(http.headers['content-length'] || 0);
    if (declaredLength > 0 && declaredLength < MIN_DOWNLOAD_BYTES) {
      throw new Error('The upstream speed-test response is too small');
    }

    let bytes = 0;
    let firstByteAt = 0;
    const downloadStartedAt = performance.now();
    while (bytes < MIN_DOWNLOAD_BYTES && performance.now() - downloadStartedAt < DOWNLOAD_TIMEOUT_MS) {
      const chunk = await tunnel.readSome(Math.max(1000, DOWNLOAD_TIMEOUT_MS - (performance.now() - downloadStartedAt)));
      if (!chunk?.length) break;
      if (!firstByteAt) firstByteAt = performance.now();
      bytes += chunk.length;
    }
    const finishedAt = performance.now();
    const transferMs = Math.max(1, finishedAt - (firstByteAt || downloadStartedAt));
    const downloadMbps = Number(((bytes * 8) / (transferMs / 1000) / 1_000_000).toFixed(3));
    if (bytes < MIN_DOWNLOAD_BYTES) throw new Error(`Proxy tunnel delivered only ${bytes} bytes; minimum is ${MIN_DOWNLOAD_BYTES}`);
    if (downloadMbps < MIN_DOWNLOAD_MBPS) {
      throw new Error(`Proxy download speed ${downloadMbps} Mbps is below the ${MIN_DOWNLOAD_MBPS} Mbps minimum`);
    }
    return {
      ok: true,
      supported: true,
      verifier: 'VLESS protocol response + HTTP 200 egress + download sample',
      probe_location: 'Cloudflare Worker egress (not Moscow)',
      connect_ms: Math.round(connectedAt - startedAt),
      tunnel_ms: Math.round(finishedAt - startedAt),
      download_ms: Math.round(transferMs),
      download_bytes: bytes,
      download_mbps: downloadMbps,
      http_status: http.status,
      target: `${TEST_HOST}${TEST_PATH}`,
    };
  } catch (error) {
    return {
      ok: false,
      supported: true,
      error: error instanceof Error ? error.message : String(error),
      probe_location: 'Cloudflare Worker egress (not Moscow)',
    };
  } finally {
    try { await socket?.close(); } catch { /* close errors do not change the test result */ }
  }
}

export const PROXY_VERIFY_LIMITS = Object.freeze({
  min_download_bytes: MIN_DOWNLOAD_BYTES,
  min_download_mbps: MIN_DOWNLOAD_MBPS,
  socket_timeout_ms: SOCKET_TIMEOUT_MS,
  download_timeout_ms: DOWNLOAD_TIMEOUT_MS,
  supported_protocols: ['VLESS'],
  supported_transports: ['TCP', 'RAW', 'WebSocket'],
  supported_security: ['none', 'TLS (when SNI equals endpoint hostname)'],
});
