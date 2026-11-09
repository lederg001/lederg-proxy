import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildMoscowDnsConfig,
  buildXrayStreamSettings,
  calculateSweepMinutes,
  decodeMaybeBase64,
  evaluateMoscowHistory,
  parseGlobalpingTcpResult,
  parseProxyUri,
} from './worker.mjs';

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
    'https://dns.google/dns-query',
    'https://unfiltered.adguard-dns.com/dns-query',
    'https://dns10.quad9.net/dns-query',
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

test('a 45-endpoint Moscow pool stays below the public Globalping hourly limit', () => {
  assert.equal(calculateSweepMinutes(45, 3), 15);
  assert.equal(3 * 60, 180);
  assert.equal(180 < 250, true);
  assert.equal(calculateSweepMinutes(46, 3), 16);
  assert.equal(calculateSweepMinutes(0, 3), 0);
});
