import test from 'node:test';
import assert from 'node:assert/strict';
import { Duplex } from 'node:stream';
import {
  applyProbeResult,
  applyProxyVerificationResult,
  buildHappJsonConfigs,
  buildMoscowDnsConfig,
  buildXrayStreamSettings,
  calculateSweepMinutes,
  decodeMaybeBase64,
  evaluateMoscowHistory,
  parseGlobalpingTcpResult,
  parseGlobalpingMtrResult,
  parseGlobalpingDnsResult,
  parseGlobalpingDohTransportResult,
  probeMoscowPair,
  renderHappSubscription,
  parseProxyUri,
  selectVerifiableConfigs,
} from './worker.mjs';
import {
  buildVlessProbeRequest,
  getVlessProbeSupport,
  verifyVlessProxy,
  verifyVlessServices,
  VLESS_SERVICE_PROBES,
  PROXY_VERIFY_LIMITS,
} from './proxy-verifier.mjs';

test('accepts a TCP ping from a Moscow, RU probe using Globalping measurement response shape', () => {
  const parsed = parseGlobalpingTcpResult({
    status: 'finished',
    results: [{
      probe: {
        city: 'Moscow',
        country: 'RU',
        network: 'Example ISP',
        asn: 12345,
      },
      result: {
        status: 'finished',
        stats: { min: 42, avg: 45, max: 50, total: 3, rcv: 3, drop: 0, loss: 0 },
      },
    }],
  });

  assert.equal(parsed.ok, true);
  assert.equal(parsed.latency_ms, 45);
  assert.equal(parsed.jitter_ms, 8);
  assert.equal(parsed.loss_pct, 0);
  assert.equal(parsed.probe_location, 'Moscow');
  assert.equal(parsed.network, 'Example ISP');
  assert.equal(parsed.asn, 12345);
});

test('accepts the location-wrapped form used by the online-probes inventory', () => {
  const parsed = parseGlobalpingTcpResult({
    status: 'finished',
    results: [{
      probe: { location: { city: 'Moscow', country: 'RU', network: 'Moscow ISP' } },
      result: {
        status: 'finished',
        stats: { min: 22, avg: 25, max: 31, total: 3, rcv: 3, drop: 0, loss: 0 },
      },
    }],
  });

  assert.equal(parsed.ok, true);
  assert.equal(parsed.latency_ms, 25);
  assert.equal(parsed.network, 'Moscow ISP');
});

test('never accepts a successful probe from a non-Moscow location', () => {
  const parsed = parseGlobalpingTcpResult({
    status: 'finished',
    results: [{
      probe: { city: 'Amsterdam', country: 'NL' },
      result: {
        status: 'finished',
        stats: { min: 4, avg: 5, max: 6, total: 3, rcv: 3, loss: 0 },
      },
    }],
  });

  assert.equal(parsed.ok, false);
  assert.match(parsed.error, /Moscow/i);
});

test('keeps unfinished Moscow measurements pending rather than marking them offline', () => {
  assert.deepEqual(parseGlobalpingTcpResult({ status: 'in-progress', results: [] }), {
    pending: true,
    error: 'Moscow measurement is still in progress',
  });
});

test('rejects a Moscow TCP test with severe packet loss', () => {
  const parsed = parseGlobalpingTcpResult({
    status: 'finished',
    results: [{
      probe: { city: 'Moscow', country: 'RU' },
      result: {
        status: 'finished',
        stats: { min: 80, avg: 120, max: 200, total: 3, rcv: 1, drop: 2, loss: 66.7 },
      },
    }],
  });

  assert.equal(parsed.ok, false);
  assert.equal(parsed.loss_pct, 66.7);
});

test('scores Moscow samples by median latency, jitter, and reliability', () => {
  const quality = evaluateMoscowHistory([
    { ok: true, latency_ms: 80, jitter_ms: 10, loss_pct: 0 },
    { ok: true, latency_ms: 100, jitter_ms: 20, loss_pct: 0 },
    { ok: false, error: 'timeout' },
    { ok: true, latency_ms: 90, jitter_ms: 15, loss_pct: 0 },
    { ok: true, latency_ms: 95, jitter_ms: 15, loss_pct: 0 },
  ]);

  assert.equal(quality.latency_ms, 93);
  assert.equal(quality.jitter_ms, 15);
  assert.equal(quality.reliability_pct, 80);
  assert.equal(quality.consecutive_successes, 2);
  assert.equal(quality.available, true);
  assert.equal(Number.isFinite(quality.score), true);
});

test('does not publish a new proxy after only one Moscow success', () => {
  const quality = evaluateMoscowHistory([
    { ok: true, latency_ms: 40, jitter_ms: 5, loss_pct: 0 },
  ]);

  assert.equal(quality.available, false);
});

test('marks a Moscow endpoint unavailable after two consecutive failed checks', () => {
  const quality = evaluateMoscowHistory([
    { ok: true, latency_ms: 40, jitter_ms: 5, loss_pct: 0 },
    { ok: false, error: 'timeout' },
    { ok: false, error: 'connection refused' },
  ]);

  assert.equal(quality.available, false);
  assert.equal(quality.consecutive_failures, 2);
});

test('uses only non-Cloudflare DoH resolvers and bootstraps their hostnames', () => {
  const dns = buildMoscowDnsConfig();

  assert.deepEqual(dns.servers, [
    'https://common.dot.dns.yandex.net/dns-query',
    'https://unfiltered.adguard-dns.com/dns-query',
    'https://dns10.quad9.net/dns-query',
    'https://dns.google/dns-query',
  ]);
  assert.deepEqual(dns.hosts['common.dot.dns.yandex.net'], ['77.88.8.8', '77.88.8.1']);
  assert.deepEqual(dns.hosts['dns.google'], ['8.8.8.8', '8.8.4.4']);
  assert.deepEqual(dns.hosts['unfiltered.adguard-dns.com'], ['94.140.14.140', '94.140.14.141']);
  assert.deepEqual(dns.hosts['dns10.quad9.net'], ['9.9.9.10', '149.112.112.10']);
  assert.equal(dns.enableParallelQuery, false);
  assert.equal(JSON.stringify(dns).includes('1.1.1.1'), false);
});

test('uses Chrome uTLS fingerprint and the configured SNI for ordinary TLS', () => {
  const settings = buildXrayStreamSettings('tcp', 'tls', {
    sni: 'cdn.example.net',
    alpn: 'h2,http/1.1',
  }, 'origin.example.net');

  assert.deepEqual(settings, {
    network: 'tcp',
    security: 'tls',
    tlsSettings: {
      serverName: 'cdn.example.net',
      fingerprint: 'chrome',
      alpn: ['h2', 'http/1.1'],
    },
  });
});

test('keeps REALITY server-provided public key, SNI, short ID and spider path', () => {
  const settings = buildXrayStreamSettings('tcp', 'reality', {
    sni: 'www.example.net',
    fp: 'chrome',
    pbk: 'source-provided-public-key',
    sid: '0123456789abcdef',
    spx: '/gateway',
  }, 'origin.example.net');

  assert.deepEqual(settings.realitySettings, {
    fingerprint: 'chrome',
    serverName: 'www.example.net',
    password: 'source-provided-public-key',
    shortId: '0123456789abcdef',
    spiderX: '/gateway',
  });
});

test('decodes base64 GitHub subscription source files', () => {
  const encoded = 'dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAcHJveHkuZXhhbXBsZTo0NDM=';
  assert.match(decodeMaybeBase64(encoded), /^vless:\/\//);
});

test('parses a public VLESS config and rejects a private endpoint', () => {
  const valid = parseProxyUri('vless://11111111-1111-4111-8111-111111111111@proxy.example.net:443?security=tls&type=tcp#DE', 'nomorewalls');
  const invalid = parseProxyUri('vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443?security=tls&type=tcp', 'nomorewalls');

  assert.equal(valid?.protocol, 'vless');
  assert.equal(valid?.host, 'proxy.example.net');
  assert.equal(invalid, null);
});

test('checks all 30 candidates every 15 minutes and stays below the Globalping hourly limit', () => {
  assert.equal(calculateSweepMinutes(30, 30), 15);
  assert.equal(30 * 2 * (60 / 15), 240);
  assert.equal(240 < 250, true);
  assert.equal(calculateSweepMinutes(31, 30), 30);
  assert.equal(calculateSweepMinutes(0, 30), 0);
});


test('runs a Moscow TCP MTR and a real HTTPS DNS-over-HTTPS check for each candidate', async () => {
  const calls = [];
  const paired = await probeMoscowPair(
    { host: 'proxy.example.net', port: 443 },
    async (_endpoint, type) => {
      calls.push(type);
      return type === 'mtr'
        ? { ok: true, latency_ms: 50, jitter_ms: 4, loss_pct: 0, hops: 9, network: 'Moscow ISP', probe_location: 'Moscow' }
        : { ok: true, query_ms: 18, answer_count: 2, tls_authorized: true, provider: 'Yandex UDP DNS', probe_location: 'Moscow' };
    },
  );

  assert.deepEqual(calls.sort(), ['dns', 'mtr']);
  assert.equal(paired.ok, true);
  assert.equal(paired.measurements_completed, 2);
  assert.equal(paired.samples.length, 1);
  assert.equal(paired.samples[0].latency_ms, 50);
  assert.equal(paired.mtr.hops, 9);
  assert.equal(paired.dns.answer_count, 2);
});

test('publishes a candidate after two independent successful Moscow samples', () => {
  const state = { endpoints: {} };
  applyProbeResult(
    state,
    { key: 'proxy.example.net:443' },
    {
      ok: true,
      samples: [
        { ok: true, latency_ms: 50, jitter_ms: 5, loss_pct: 0, network: 'Moscow ISP' },
        { ok: true, latency_ms: 60, jitter_ms: 7, loss_pct: 0, network: 'Moscow ISP' },
      ],
    },
    Date.parse('2026-11-09T00:20:00.000Z'),
  );

  const status = state.endpoints['proxy.example.net:443'];
  assert.equal(status.available, true);
  assert.equal(status.reliability_pct, 100);
  assert.equal(status.consecutive_successes, 2);
  assert.equal(status.recent_samples.length, 2);
  assert.equal(status.latency_ms, 55);
});

test('does not publish a candidate if only one of two Moscow samples succeeds', () => {
  const state = { endpoints: {} };
  applyProbeResult(
    state,
    { key: 'proxy.example.net:443' },
    {
      ok: false,
      samples: [
        { ok: true, latency_ms: 50, jitter_ms: 5, loss_pct: 0 },
        { ok: false, error: 'connection refused' },
      ],
    },
    Date.parse('2026-11-09T00:20:00.000Z'),
  );

  assert.equal(state.endpoints['proxy.example.net:443'].available, false);
  assert.equal(state.endpoints['proxy.example.net:443'].reliability_pct, 50);
});


test('reports the actual TLS fingerprint used by the generated HAPP profile', () => {
  const profiles = buildHappJsonConfigs([{
    uri: 'vless://11111111-1111-4111-8111-111111111111@node.example.net:443?security=tls&type=tcp&sni=cdn.example.net&fp=firefox',
    protocol: 'vless',
    host: 'node.example.net',
    port: 443,
    ping_ms: 42,
    score: 42,
    country: 'FR',
    source: 'test',
    functional_probe: { ok: true, verifier: 'test', verified_at: '2026-11-09T00:00:00.000Z', probe_location: 'test', connect_ms: 10, tunnel_ms: 20, download_ms: 30, download_bytes: 65536, download_mbps: 5, http_status: 200, target: 'test' },
  }]);

  assert.equal(profiles.length, 1);
  assert.equal(profiles[0].outbounds[0].streamSettings.tlsSettings.fingerprint, 'firefox');
  assert.equal(profiles[0].meta.tlsCamouflage, 'TLS + uTLS firefox');
  assert.equal(profiles[0].dns.servers[0], 'https://common.dot.dns.yandex.net/dns-query');
});


function fakeProxySocket(responseBytes) {
  const writes = [];
  let sent = false;
  const socket = new Duplex({
    read() {},
    write(chunk, _encoding, callback) {
      writes.push(new Uint8Array(chunk));
      if (!sent) {
        sent = true;
        queueMicrotask(() => socket.push(responseBytes));
      }
      callback();
    },
  });
  return { socket, writes, close: () => socket.destroy() };
}

test('supports only VLESS transports the verifier can actually negotiate', () => {
  const base = {
    protocol: 'vless',
    host: 'proxy.example.net',
    port: 443,
    uri: 'vless://11111111-1111-4111-8111-111111111111@proxy.example.net:443?type=ws&security=none&path=%2Fedge',
  };
  assert.deepEqual(getVlessProbeSupport(base), {
    supported: true,
    network: 'ws',
    security: 'none',
    path: '/edge',
    wsHost: 'proxy.example.net',
    sni: 'proxy.example.net',
  });
  assert.equal(getVlessProbeSupport({ ...base, protocol: 'vmess' }).supported, false);
  assert.equal(getVlessProbeSupport({
    ...base,
    uri: base.uri.replace('type=ws', 'type=grpc'),
  }).supported, false);
  assert.equal(getVlessProbeSupport({
    ...base,
    uri: base.uri.replace('security=none', 'security=reality'),
  }).supported, false);
});

test('supports a separate source-provided TLS SNI for proxy endpoints', () => {
  const result = getVlessProbeSupport({
    protocol: 'vless',
    host: '203.0.113.10',
    port: 443,
    uri: 'vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?type=tcp&security=tls&sni=cdn.example.net',
  });
  assert.equal(result.supported, true);
  assert.equal(result.sni, 'cdn.example.net');
});

test('defines direct HTTPS health checks for YouTube and Discord', () => {
  assert.deepEqual(VLESS_SERVICE_PROBES.map((item) => ({
    id: item.id,
    hostname: item.hostname,
    path: item.path,
    acceptedStatuses: item.acceptedStatuses,
  })), [
    { id: 'youtube', hostname: 'www.youtube.com', path: '/generate_204', acceptedStatuses: [200, 204] },
    { id: 'discord', hostname: 'discord.com', path: '/api/v10/gateway', acceptedStatuses: [200] },
  ]);
});

test('requires both YouTube and Discord HTTPS requests to succeed through VLESS', async () => {
  const seen = [];
  const result = await verifyVlessServices(
    { protocol: 'vless', uri: 'vless://11111111-1111-4111-8111-111111111111@proxy.example.net:443?type=tcp', host: 'proxy.example.net', port: 443 },
    async (_node, service) => {
      seen.push(service.id);
      return {
        ok: true,
        service: service.id,
        probe_location: 'Cloudflare Worker egress (not Moscow)',
        connect_ms: 30,
        tls_ms: 45,
        response_ms: 70,
        http_status: service.id === 'youtube' ? 204 : 200,
        tls_authorized: true,
        tls_protocol: 'TLSv1.3',
      };
    },
  );

  assert.deepEqual(seen.sort(), ['discord', 'youtube']);
  assert.equal(result.ok, true);
  assert.equal(result.youtube.ok, true);
  assert.equal(result.youtube.http_status, 204);
  assert.equal(result.discord.ok, true);
  assert.equal(result.discord.http_status, 200);
});

test('rejects a proxy from HAPP when Discord is blocked even if YouTube works', async () => {
  const result = await verifyVlessServices(
    { protocol: 'vless', uri: 'vless://11111111-1111-4111-8111-111111111111@proxy.example.net:443?type=tcp', host: 'proxy.example.net', port: 443 },
    async (_node, service) => ({
      ok: service.id === 'youtube',
      service: service.id,
      http_status: service.id === 'youtube' ? 204 : 403,
      tls_authorized: true,
      error: service.id === 'discord' ? 'Discord returned HTTP 403' : null,
    }),
  );

  assert.equal(result.ok, false);
  assert.equal(result.youtube.ok, true);
  assert.equal(result.discord.ok, false);
  assert.match(result.error, /discord/i);
});

test('does not mark a VLESS profile verified if the YouTube or Discord egress check failed', () => {
  const state = { endpoints: {} };
  const node = { uri: 'vless://11111111-1111-4111-8111-111111111111@proxy.example.net:443?type=tcp' };
  const result = applyProxyVerificationResult(
    state,
    { key: 'proxy.example.net:443' },
    node,
    {
      ok: true,
      supported: true,
      http_status: 200,
      download_bytes: 262144,
      download_mbps: 5,
      services: {
        youtube: { ok: true, http_status: 204, response_ms: 50 },
        discord: { ok: false, http_status: 403, error: 'blocked' },
      },
    },
    Date.parse('2026-11-09T12:00:00.000Z'),
  );

  assert.equal(result.ok, false);
  assert.equal(result.services.youtube.ok, true);
  assert.equal(result.services.discord.ok, false);
});

test('keeps the source-provided TLS SNI when checking the target services through VLESS', () => {
  const result = getVlessProbeSupport({
    protocol: 'vless',
    host: '203.0.113.10',
    port: 443,
    uri: 'vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?type=tcp&security=tls&sni=cdn.example.net',
  });

  assert.equal(result.supported, true);
  assert.equal(result.sni, 'cdn.example.net');
});

test('builds a VLESS TCP CONNECT request with a real UUID and HTTP probe payload', () => {
  const bytes = buildVlessProbeRequest(
    'vless://11111111-1111-4111-8111-111111111111@proxy.example.net:443?type=tcp',
    'probe.example.net',
    80,
    '/check.bin',
  );
  assert.equal(bytes[0], 0);
  assert.deepEqual([...bytes.slice(1, 17)], [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11,
    0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  ]);
  assert.equal(new TextDecoder().decode(bytes).includes('GET /check.bin HTTP/1.1'), true);
});

test('requires an authenticated VLESS tunnel, upstream HTTP 200 and a real download sample', async () => {
  const body = new Uint8Array(256 * 1024).fill(0x61);
  const header = new TextEncoder().encode('HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n');
  const response = new Uint8Array(header.length + body.length);
  response.set(header, 0);
  response.set(body, header.length);
  const fake = fakeProxySocket(response);
  let target;
  const result = await verifyVlessProxy({
    protocol: 'vless',
    host: 'proxy.example.net',
    port: 443,
    uri: 'vless://11111111-1111-4111-8111-111111111111@proxy.example.net:443?type=tcp&security=none',
  }, {
    openTunnel: async (_node, hostname, port) => {
      target = { hostname, port };
      return { socket: fake.socket, connectedAt: performance.now() - 5, close: fake.close };
    },
  });

  assert.equal(result.ok, true, result.error);
  assert.equal(result.supported, true);
  assert.equal(result.http_status, 200);
  assert.equal(result.download_bytes, 256 * 1024);
  assert.equal(result.probe_location, 'Cloudflare Worker egress through VLESS tunnel (not Moscow)');
  assert.deepEqual(target, { hostname: 'ipv4.download.thinkbroadband.com', port: 80 });
  const sent = new TextDecoder().decode(fake.writes[0]);
  assert.equal(sent.includes('GET /1MB.zip HTTP/1.1'), true);
});

test('never accepts an open VLESS socket when tunneled HTTP returns an error', async () => {
  const errorResponse = new TextEncoder().encode(
    'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n',
  );
  const response = new Uint8Array(2 + errorResponse.length);
  response.set([0, 0]);
  response.set(errorResponse, 2);
  const fake = fakeProxySocket(response);
  const result = await verifyVlessProxy({
    protocol: 'vless',
    host: 'proxy.example.net',
    port: 443,
    uri: 'vless://11111111-1111-4111-8111-111111111111@proxy.example.net:443?type=tcp&security=none',
  }, {
    openTunnel: async () => ({ socket: fake.socket, connectedAt: performance.now() - 2, close: fake.close }),
  });
  assert.equal(result.ok, false);
  assert.match(result.error, /status 403/i);
});


test('selects only VLESS configs with a supported full-verification transport', () => {
  const configs = [
    { protocol: 'vmess', uri: 'vmess://not-verified', host: 'proxy.example.net', port: 443 },
    { protocol: 'vless', uri: 'vless://11111111-1111-4111-8111-111111111111@proxy.example.net:443?type=grpc', host: 'proxy.example.net', port: 443 },
    { protocol: 'vless', uri: 'vless://11111111-1111-4111-8111-111111111111@proxy.example.net:443?type=tcp&security=none', host: 'proxy.example.net', port: 443 },
    { protocol: 'trojan', uri: 'trojan://password@proxy.example.net:443', host: 'proxy.example.net', port: 443 },
  ];
  assert.deepEqual(selectVerifiableConfigs(configs, 3), [configs[2]]);
});


test('requires a meaningful end-to-end download sample and minimum speed', () => {
  assert.equal(PROXY_VERIFY_LIMITS.min_download_bytes, 256 * 1024);
  assert.equal(PROXY_VERIFY_LIMITS.min_download_mbps, 1);
  assert.equal(PROXY_VERIFY_LIMITS.supported_protocols.includes('VLESS'), true);
});


test('accepts a completed Moscow TCP MTR only when the final proxy hop responds without material loss', () => {
  const parsed = parseGlobalpingMtrResult({
    status: 'finished',
    results: [{
      probe: { city: 'Moscow', country: 'RU', network: 'Example Moscow ISP', asn: 12345 },
      result: {
        status: 'finished',
        resolvedAddress: '198.51.100.10',
        hops: [
          { resolvedAddress: '10.0.0.1', stats: { avg: 3, jAvg: 1, total: 5, rcv: 5, drop: 0, loss: 0 } },
          { resolvedAddress: '198.51.100.10', stats: { min: 41, avg: 45, max: 49, jAvg: 3, total: 5, rcv: 5, drop: 0, loss: 0 } },
        ],
      },
    }],
  }, 'proxy.example.net');

  assert.equal(parsed.ok, true);
  assert.equal(parsed.latency_ms, 45);
  assert.equal(parsed.jitter_ms, 3);
  assert.equal(parsed.loss_pct, 0);
  assert.equal(parsed.hops, 2);
  assert.equal(parsed.network, 'Example Moscow ISP');
});

test('rejects Moscow MTR when the route never reaches the proxy endpoint', () => {
  const parsed = parseGlobalpingMtrResult({
    status: 'finished',
    results: [{
      probe: { city: 'Moscow', country: 'RU' },
      result: {
        status: 'finished',
        resolvedAddress: '198.51.100.10',
        hops: [{ resolvedAddress: null, stats: { avg: null, jAvg: null, total: 5, rcv: 0, drop: 5, loss: 100 } }],
      },
    }],
  }, 'proxy.example.net');

  assert.equal(parsed.ok, false);
  assert.match(parsed.error, /endpoint|hop|loss/i);
});

test('requires a positive Yandex DNS A response from a Moscow probe', () => {
  const parsed = parseGlobalpingDnsResult({
    status: 'finished',
    results: [{
      probe: { city: 'Moscow', country: 'RU', network: 'Example Moscow ISP' },
      result: {
        status: 'finished',
        statusCode: 0,
        statusCodeName: 'NOERROR',
        resolver: '77.88.8.8',
        answers: [{ type: 'A', value: '198.51.100.10' }],
        timings: { total: 18 },
      },
    }],
  }, 'proxy.example.net');

  assert.equal(parsed.ok, true);
  assert.equal(parsed.query_ms, 18);
  assert.equal(parsed.answer_count, 1);
  assert.equal(parsed.provider, 'Yandex DNS (77.88.8.8)');
});

test('rejects Moscow DNS lookup if Yandex returns no usable A record', () => {
  const parsed = parseGlobalpingDnsResult({
    status: 'finished',
    results: [{
      probe: { city: 'Moscow', country: 'RU' },
      result: {
        status: 'finished',
        statusCode: 2,
        statusCodeName: 'SERVFAIL',
        resolver: '77.88.8.8',
        answers: [],
        timings: { total: 88 },
      },
    }],
  }, 'proxy.example.net');

  assert.equal(parsed.ok, false);
  assert.match(parsed.error, /DNS|record/i);
});

test('validates TLS transport to the Yandex DoH endpoint from Moscow separately', () => {
  const parsed = parseGlobalpingDohTransportResult({
    status: 'finished',
    results: [{
      probe: { city: 'Moscow', country: 'RU', network: 'Example Moscow ISP' },
      result: {
        status: 'finished',
        statusCode: 400,
        tls: { authorized: true, protocol: 'TLSv1.3' },
        timings: { total: 55, dns: 4, tcp: 12, tls: 20, firstByte: 15, download: 4 },
      },
    }],
  });

  assert.equal(parsed.ok, true);
  assert.equal(parsed.tls_authorized, true);
  assert.equal(parsed.tls_protocol, 'TLSv1.3');
  assert.equal(parsed.connect_ms, 12);
  assert.equal(parsed.tls_ms, 20);
});

test('rejects the Yandex DoH path when the Moscow TLS handshake is not trusted', () => {
  const parsed = parseGlobalpingDohTransportResult({
    status: 'finished',
    results: [{
      probe: { city: 'Moscow', country: 'RU' },
      result: {
        status: 'finished',
        statusCode: 400,
        tls: { authorized: false },
        timings: { total: 55, tcp: 12, tls: 20 },
      },
    }],
  });

  assert.equal(parsed.ok, false);
  assert.match(parsed.error, /TLS/i);
});

test('preserves a running Globalping check as pending instead of converting it to no-probe failure', () => {
  const parsed = parseGlobalpingMtrResult({
    pending: true,
    error: 'Moscow MTR measurement did not finish within the polling window',
  }, 'proxy.example.net');
  assert.equal(parsed.pending, true);
  assert.match(parsed.error, /did not finish/i);
});

test('does not record an incomplete MTR and DNS pair as a completed failure sample', async () => {
  const paired = await probeMoscowPair(
    { host: 'proxy.example.net', port: 443 },
    async (_endpoint, type) => type === 'mtr'
      ? { pending: true, error: 'MTR still running' }
      : { ok: true, query_ms: 20, answer_count: 1, provider: 'Yandex DNS (77.88.8.8)' },
  );
  assert.equal(paired.pending, true);
  assert.equal(paired.measurements_completed, 1);
  assert.equal(paired.samples.length, 0);
});

test('publishes a HAPP subscription with supported standard profile settings only', () => {
  const subscription = renderHappSubscription([{
    uri: 'vless://11111111-1111-4111-8111-111111111111@proxy.example.net:443?type=tcp',
    score: 40,
    ping_ms: 40,
    functional_probe: { ok: true },
  }]);

  assert.match(subscription, /#profile-title: LEDERG PROXY/);
  assert.match(subscription, /#profile-update-interval: 1/);
  assert.doesNotMatch(subscription, /#subscriptions-sort-type/);
  assert.doesNotMatch(subscription, /#subscription-auto-update-open-enable/);
});
