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

export async function verifyVlessProxy(node, dependencies = {}) {
  const support = getVlessProbeSupport(node);
  if (!support.supported) return { ok: false, supported: false, error: support.reason };
  let tunnel;
  let reader;
  const startedAt = performance.now();
  try {
    tunnel = dependencies.openTunnel
      ? await dependencies.openTunnel(node, TEST_HOST, 80)
      : await openVlessTunnel(node, TEST_HOST, 80, dependencies);
    const request = TEXT.encode(
      `GET ${TEST_PATH} HTTP/1.1\\r\\nHost: ${TEST_HOST}\\r\\nUser-Agent: LEDERG-Proxy-Health/1.0\\r\\nAccept: */*\\r\\nConnection: close\\r\\n\\r\\n`,
    );
    const responseStartedAt = performance.now();
    await writeSocket(tunnel.socket, request);
    reader = new SocketByteReader(tunnel.socket);
    const headerBytes = await timeout(
      reader.readUntil(),
      SOCKET_TIMEOUT_MS,
      'Timed out waiting for the proxy speed-test response',
    );
    const http = parseHttpResponseHead(headerBytes);
    if (http.status !== 200) throw new Error(`Proxy tunnel HTTP test returned status ${http.status}`);
    const declaredLength = Number(http.headers['content-length'] || 0);
    if (declaredLength > 0 && declaredLength < MIN_DOWNLOAD_BYTES) {
      throw new Error('The upstream speed-test response is too small');
    }

    let bytes = 0;
    let firstByteAt = 0;
    const downloadStartedAt = performance.now();
    while (bytes < MIN_DOWNLOAD_BYTES && performance.now() - downloadStartedAt < DOWNLOAD_TIMEOUT_MS) {
      const chunk = await timeout(
        reader.readSome(),
        Math.max(1000, DOWNLOAD_TIMEOUT_MS - (performance.now() - downloadStartedAt)),
        'Download stalled through proxy',
      );
      if (!chunk?.length) break;
      if (!firstByteAt) firstByteAt = performance.now();
      bytes += chunk.length;
    }
    const finishedAt = performance.now();
    const transferMs = Math.max(1, finishedAt - (firstByteAt || downloadStartedAt));
    const downloadMbps = Number(((bytes * 8) / (transferMs / 1000) / 1_000_000).toFixed(3));
    if (bytes < MIN_DOWNLOAD_BYTES) {
      throw new Error(`Proxy tunnel delivered only ${bytes} bytes; minimum is ${MIN_DOWNLOAD_BYTES}`);
    }
    if (downloadMbps < MIN_DOWNLOAD_MBPS) {
      throw new Error(`Proxy download speed ${downloadMbps} Mbps is below the ${MIN_DOWNLOAD_MBPS} Mbps minimum`);
    }
    return {
      ok: true,
      supported: true,
      verifier: 'VLESS auth + HTTP 200 egress + download sample',
      probe_location: 'Cloudflare Worker egress through VLESS tunnel (not Moscow)',
      connect_ms: Number.isFinite(Number(tunnel.connect_ms))
        ? Number(tunnel.connect_ms)
        : Math.round((tunnel.connectedAt || startedAt) - startedAt),
      tunnel_ms: Math.round(finishedAt - startedAt),
      download_ms: Math.round(transferMs),
      download_bytes: bytes,
      download_mbps: downloadMbps,
      http_status: http.status,
      target: `${TEST_HOST}${TEST_PATH}`,
      speed_test_response_ms: Math.round(finishedAt - responseStartedAt),
    };
  } catch (error) {
    return {
      ok: false,
      supported: true,
      error: error instanceof Error ? error.message : String(error),
      probe_location: 'Cloudflare Worker egress through VLESS tunnel (not Moscow)',
    };
  } finally {
    try { reader?.detach(); } catch { /* best-effort cleanup */ }
    try { tunnel?.close?.(); } catch { /* best-effort cleanup */ }
  }
}

export const VLESS_SERVICE_PROBES = Object.freeze([
  Object.freeze({
    id: 'youtube',
    hostname: 'www.youtube.com',
    port: 443,
    path: '/generate_204',
    acceptedStatuses: [200, 204],
  }),
  Object.freeze({
    id: 'discord',
    hostname: 'discord.com',
    port: 443,
    path: '/api/v10/gateway',
    acceptedStatuses: [200],
  }),
]);

const SERVICE_TIMEOUT_MS = 9000;
const SERVICE_HEADER_LIMIT = 32768;

function appendUint8(left, right) {
  const a = left || new Uint8Array(0);
  const b = right instanceof Uint8Array ? right : new Uint8Array(right);
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

class SocketByteReader {
  constructor(socket) {
    this.socket = socket;
    this.buffer = new Uint8Array(0);
    this.failure = null;
    this.waiters = [];
    this.onData = (chunk) => {
      this.buffer = appendUint8(this.buffer, chunk);
      for (const waiter of this.waiters.splice(0)) waiter.resolve();
    };
    this.onError = (error) => {
      this.failure = error instanceof Error ? error : new Error(String(error));
      for (const waiter of this.waiters.splice(0)) waiter.reject(this.failure);
    };
    this.onEnd = () => {
      this.failure = new Error('Proxy tunnel closed before the response was complete');
      for (const waiter of this.waiters.splice(0)) waiter.reject(this.failure);
    };
    socket.on('data', this.onData);
    socket.on('error', this.onError);
    socket.on('end', this.onEnd);
    socket.resume?.();
  }

  async waitForData() {
    if (this.failure) throw this.failure;
    await new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
    if (this.failure) throw this.failure;
  }

  async readExactly(length) {
    if (!Number.isInteger(length) || length < 0 || length > SERVICE_HEADER_LIMIT) {
      throw new Error('Invalid proxy response read length');
    }
    while (this.buffer.length < length) await this.waitForData();
    const result = this.buffer.slice(0, length);
    this.buffer = this.buffer.slice(length);
    return result;
  }

  async readSome() {
    if (this.buffer.length) {
      const result = this.buffer;
      this.buffer = new Uint8Array(0);
      return result;
    }
    await this.waitForData();
    const result = this.buffer;
    this.buffer = new Uint8Array(0);
    return result;
  }

  async readUntil(delimiter = '\r\n\r\n', maxBytes = SERVICE_HEADER_LIMIT) {
    const marker = TEXT.encode(delimiter);
    while (true) {
      outer: for (let i = 0; i <= this.buffer.length - marker.length; i += 1) {
        for (let j = 0; j < marker.length; j += 1) {
          if (this.buffer[i + j] !== marker[j]) continue outer;
        }
        const end = i + marker.length;
        if (end > maxBytes) throw new Error('Upstream HTTP response headers exceeded the size limit');
        const result = this.buffer.slice(0, end);
        this.buffer = this.buffer.slice(end);
        return result;
      }
      if (this.buffer.length > maxBytes) throw new Error('Upstream HTTP response headers exceeded the size limit');
      await this.waitForData();
    }
  }

  detach() {
    this.socket.pause?.();
    this.socket.removeListener('data', this.onData);
    this.socket.removeListener('error', this.onError);
    this.socket.removeListener('end', this.onEnd);
    if (this.buffer.length) {
      this.socket.unshift?.(this.buffer);
      this.buffer = new Uint8Array(0);
    }
  }
}

function waitForSocketEvent(socket, eventName, timeoutMs, timeoutMessage) {
  return new Promise((resolve, reject) => {
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener(eventName, onSuccess);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
    };
    const onSuccess = (...args) => { cleanup(); resolve(args[0]); };
    const onError = (error) => { cleanup(); reject(error instanceof Error ? error : new Error(String(error))); };
    const onClose = () => { cleanup(); reject(new Error('Socket closed before ' + eventName)); };
    socket.once(eventName, onSuccess);
    socket.once('error', onError);
    socket.once('close', onClose);
    timer = setTimeout(() => { cleanup(); reject(new Error(timeoutMessage)); }, timeoutMs);
  });
}

function writeSocket(socket, bytes) {
  return new Promise((resolve, reject) => {
    socket.write(bytes, (error) => error ? reject(error) : resolve());
  });
}

function parseHttpResponseHead(bytes) {
  const text = new TextDecoder().decode(bytes);
  const lines = text.split('\r\n');
  const firstLine = lines.shift() || '';
  const match = firstLine.match(/^HTTP\/1\.[01]\s+(\d{3})\b/i);
  if (!match) throw new Error('Target service did not return a valid HTTP response');
  const headers = {};
  for (const line of lines) {
    const index = line.indexOf(':');
    if (index > 0) headers[line.slice(0, index).trim().toLowerCase()] = line.slice(index + 1).trim();
  }
  return { status: Number(match[1]), headers };
}

function isIpLiteral(host) {
  const value = normalizedHost(host);
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(':');
}

function buildVlessConnectHeader(uri, targetHost, targetPort = 443) {
  const url = new URL(uri);
  const uuid = decodeURIComponent(url.username).replace(/-/g, '');
  if (!/^[0-9a-f]{32}$/i.test(uuid)) throw new Error('Invalid VLESS UUID');
  const uuidBytes = Uint8Array.from(uuid.match(/.{2}/g), (pair) => Number.parseInt(pair, 16));
  const hostBytes = TEXT.encode(targetHost);
  if (hostBytes.length < 1 || hostBytes.length > 255) throw new Error('Invalid target hostname length');
  const port = Number(targetPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid target port');
  return concatBytes(
    new Uint8Array([0]),
    uuidBytes,
    new Uint8Array([0, 1, (port >> 8) & 0xff, port & 0xff, 2, hostBytes.length]),
    hostBytes,
  );
}

function buildWebSocketRequest(support, port) {
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const key = base64(nonce);
  const request = [
    `GET ${support.path} HTTP/1.1`,
    `Host: ${support.wsHost}${port === 443 || port === 80 ? '' : `:${port}`}`,
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Key: ${key}`,
    'Sec-WebSocket-Version: 13',
    'User-Agent: LEDERG-Proxy-Health/1.0',
    '',
    '',
  ].join('\r\n');
  return { request: TEXT.encode(request), key };
}

async function validateWebSocketUpgrade(socket, support, port) {
  const { request, key } = buildWebSocketRequest(support, port);
  await writeSocket(socket, request);
  const reader = new SocketByteReader(socket);
  const headerBytes = await timeout(
    reader.readUntil(),
    SERVICE_TIMEOUT_MS,
    'WebSocket upgrade timed out',
  );
  reader.detach();
  const header = new TextDecoder().decode(headerBytes);
  if (!/^HTTP\/1\.[01] 101\b/im.test(header)) {
    throw new Error(`VLESS WebSocket upgrade rejected: ${header.split('\r\n')[0] || 'no HTTP status'}`);
  }
  const accept = header.match(/^sec-websocket-accept:\s*(.+)$/im)?.[1]?.trim();
  const digest = await crypto.subtle.digest(
    'SHA-1',
    TEXT.encode(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'),
  );
  if (accept !== base64(new Uint8Array(digest))) throw new Error('Invalid WebSocket Sec-WebSocket-Accept');
}

function createWebSocketDuplex(socket, Duplex) {
  let incoming = new Uint8Array(0);
  let closed = false;
  let stream;
  const onData = (chunk) => {
    incoming = appendUint8(incoming, chunk);
    parseFrames();
  };
  const onError = (error) => stream?.destroy(error);
  const onEnd = () => {
    if (!closed) {
      closed = true;
      stream?.push(null);
    }
  };
  const parseFrames = () => {
    while (incoming.length >= 2 && !closed) {
      const first = incoming[0];
      const second = incoming[1];
      const opcode = first & 0x0f;
      const masked = Boolean(second & 0x80);
      let length = second & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (incoming.length < 4) return;
        length = (incoming[2] << 8) | incoming[3];
        offset = 4;
      } else if (length === 127) {
        if (incoming.length < 10) return;
        const high = new DataView(incoming.buffer, incoming.byteOffset + 2, 8).getUint32(0);
        const low = new DataView(incoming.buffer, incoming.byteOffset + 2, 8).getUint32(4);
        if (high !== 0 || low > 1024 * 1024) {
          stream.destroy(new Error('WebSocket frame exceeds the TLS probe limit'));
          return;
        }
        length = low;
        offset = 10;
      }
      const maskLength = masked ? 4 : 0;
      if (length > 1024 * 1024 || incoming.length < offset + maskLength + length) return;
      const mask = masked ? incoming.slice(offset, offset + 4) : null;
      const payloadStart = offset + maskLength;
      const payload = incoming.slice(payloadStart, payloadStart + length);
      incoming = incoming.slice(payloadStart + length);
      if (mask) for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
      if (opcode === 8) {
        closed = true;
        stream.push(null);
        return;
      }
      if (opcode === 9) {
        socket.write(makeWebSocketFrame(payload, 10));
        continue;
      }
      if (opcode === 10) continue;
      if (opcode === 1 || opcode === 2 || opcode === 0) {
        if (!stream.push(payload)) return;
      }
    }
  };
  stream = new Duplex({
    read() { parseFrames(); },
    write(chunk, _encoding, callback) {
      socket.write(makeWebSocketFrame(new Uint8Array(chunk)), callback);
    },
    final(callback) { callback(); },
    destroy(error, callback) {
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('end', onEnd);
      callback(error);
    },
  });
  socket.on('data', onData);
  socket.on('error', onError);
  socket.on('end', onEnd);
  socket.resume?.();
  return stream;
}


async function openVlessTunnel(node, targetHost, targetPort, dependencies = {}) {
  const support = getVlessProbeSupport(node);
  if (!support.supported) throw new Error(support.reason);
  const netModule = dependencies.net || await import('node:net');
  const tlsModule = dependencies.tls || await import('node:tls');
  const streamModule = dependencies.stream || await import('node:stream');
  const connect = dependencies.connect || netModule.connect;
  const tlsConnect = dependencies.tlsConnect || tlsModule.connect;
  const Duplex = dependencies.Duplex || streamModule.Duplex;
  const rawSocket = connect({ host: node.host, port: node.port });
  let proxySocket = rawSocket;
  let websocketStream = null;
  try {
    await timeout(
      waitForSocketEvent(rawSocket, 'connect', SERVICE_TIMEOUT_MS, 'TCP connection to the VLESS server timed out'),
      SERVICE_TIMEOUT_MS + 100,
      'TCP connection to the VLESS server timed out',
    );
    const connectedAt = performance.now();

    if (support.security === 'tls') {
      const servername = support.sni && !isIpLiteral(support.sni) ? support.sni : undefined;
      proxySocket = tlsConnect({
        socket: rawSocket,
        host: support.sni || node.host,
        ...(servername ? { servername } : {}),
        rejectUnauthorized: true,
        ALPNProtocols: ['http/1.1'],
      });
      await timeout(
        waitForSocketEvent(proxySocket, 'secureConnect', SERVICE_TIMEOUT_MS, 'TLS to the VLESS server timed out'),
        SERVICE_TIMEOUT_MS + 100,
        'TLS to the VLESS server timed out',
      );
      if (proxySocket.authorized !== true) {
        throw new Error(`TLS certificate for VLESS server is not trusted: ${proxySocket.authorizationError || 'unknown error'}`);
      }
    }

    let tunnelSocket = proxySocket;
    if (support.network === 'ws') {
      await validateWebSocketUpgrade(proxySocket, support, node.port);
      websocketStream = createWebSocketDuplex(proxySocket, Duplex);
      tunnelSocket = websocketStream;
    }

    await writeSocket(tunnelSocket, buildVlessConnectHeader(node.uri, targetHost, targetPort));
    const reader = new SocketByteReader(tunnelSocket);
    const header = await timeout(
      reader.readExactly(2),
      SERVICE_TIMEOUT_MS,
      `VLESS connection to ${targetHost} timed out`,
    );
    if (header[0] !== 0) throw new Error('The proxy did not return a valid VLESS response');
    if (header[1] > 0) {
      await timeout(reader.readExactly(header[1]), SERVICE_TIMEOUT_MS, 'VLESS response addons timed out');
    }
    reader.detach();

    return {
      socket: tunnelSocket,
      connectedAt,
      connect_ms: Math.round(connectedAt - (rawSocket.connecting ? connectedAt : (rawSocket._connectStart || connectedAt))),
      close() {
        try { websocketStream?.destroy(); } catch { /* best-effort cleanup */ }
        try { proxySocket?.destroy(); } catch { /* best-effort cleanup */ }
        if (rawSocket !== proxySocket) {
          try { rawSocket?.destroy(); } catch { /* best-effort cleanup */ }
        }
      },
    };
  } catch (error) {
    try { websocketStream?.destroy(); } catch { /* best-effort cleanup */ }
    try { proxySocket?.destroy(); } catch { /* best-effort cleanup */ }
    if (rawSocket !== proxySocket) {
      try { rawSocket?.destroy(); } catch { /* best-effort cleanup */ }
    }
    throw error;
  }
}

async function verifyVlessService(node, service, dependencies = {}) {
  let tunnel;
  let serviceTls;
  let reader;
  const startedAt = performance.now();
  try {
    const support = getVlessProbeSupport(node);
    if (!support.supported) return { ok: false, service: service.id, error: support.reason };
    const tlsModule = dependencies.tls || await import('node:tls');
    const tlsConnect = dependencies.tlsConnect || tlsModule.connect;
    tunnel = dependencies.openTunnel
      ? await dependencies.openTunnel(node, service.hostname, service.port)
      : await openVlessTunnel(node, service.hostname, service.port, dependencies);

    const tlsStartedAt = performance.now();
    serviceTls = tlsConnect({
      socket: tunnel.socket,
      host: service.hostname,
      servername: service.hostname,
      rejectUnauthorized: true,
      ALPNProtocols: ['http/1.1'],
    });
    await timeout(
      waitForSocketEvent(serviceTls, 'secureConnect', SERVICE_TIMEOUT_MS, `TLS to ${service.id} timed out through proxy`),
      SERVICE_TIMEOUT_MS + 100,
      `TLS to ${service.id} timed out through proxy`,
    );
    const tlsFinishedAt = performance.now();
    if (serviceTls.authorized !== true) {
      throw new Error(`TLS certificate for ${service.id} was not trusted: ${serviceTls.authorizationError || 'unknown error'}`);
    }

    const request = [
      `GET ${service.path} HTTP/1.1`,
      `Host: ${service.hostname}`,
      'User-Agent: LEDERG-Proxy-Health/1.0',
      'Accept: */*',
      'Connection: close',
      '',
      '',
    ].join('\\r\\n');
    const responseStartedAt = performance.now();
    await writeSocket(serviceTls, TEXT.encode(request));
    reader = new SocketByteReader(serviceTls);
    const responseBytes = await timeout(
      reader.readUntil(),
      SERVICE_TIMEOUT_MS,
      `HTTP response from ${service.id} timed out through proxy`,
    );
    const response = parseHttpResponseHead(responseBytes);
    const completedAt = performance.now();
    const ok = service.acceptedStatuses.includes(response.status);
    return {
      ok,
      service: service.id,
      probe_location: 'Cloudflare Worker egress through VLESS tunnel (not Moscow)',
      connect_ms: tunnel.connect_ms ?? Math.round(tunnel.connectedAt - startedAt),
      tls_ms: Math.round(tlsFinishedAt - tlsStartedAt),
      response_ms: Math.round(completedAt - responseStartedAt),
      total_ms: Math.round(completedAt - startedAt),
      http_status: response.status,
      tls_authorized: serviceTls.authorized === true,
      tls_protocol: serviceTls.getProtocol?.() || null,
      alpn: serviceTls.alpnProtocol || null,
      target: `https://${service.hostname}${service.path}`,
      error: ok ? null : `${service.id} returned HTTP ${response.status}`,
    };
  } catch (error) {
    return {
      ok: false,
      service: service.id,
      probe_location: 'Cloudflare Worker egress through VLESS tunnel (not Moscow)',
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    try { reader?.detach(); } catch { /* best-effort cleanup */ }
    try { serviceTls?.destroy(); } catch { /* best-effort cleanup */ }
    try { tunnel?.close?.(); } catch { /* best-effort cleanup */ }
  }
}

export async function verifyVlessServices(node, probeService = verifyVlessService) {
  const results = await Promise.all(
    VLESS_SERVICE_PROBES.map((service) => probeService(node, service)),
  );
  const indexed = Object.fromEntries(results.map((result, index) => [VLESS_SERVICE_PROBES[index].id, result]));
  const ok = VLESS_SERVICE_PROBES.every((service) => indexed[service.id]?.ok === true);
  const failed = VLESS_SERVICE_PROBES.filter((service) => indexed[service.id]?.ok !== true);
  return {
    ok,
    youtube: indexed.youtube || { ok: false, error: 'YouTube probe did not return a result' },
    discord: indexed.discord || { ok: false, error: 'Discord probe did not return a result' },
    error: ok ? null : failed.map((service) => indexed[service.id]?.error || `${service.id} check failed`).join('; '),
  };
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
