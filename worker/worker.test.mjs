import test from 'node:test';
import assert from 'node:assert/strict';
import {
  calculateSweepMinutes,
  decodeMaybeBase64,
  evaluateMoscowHistory,
  parseGlobalpingTcpResult,
  parseProxyUri,
} from './worker.mjs';

test('accepts a TCP ping only when the reporting probe is in Moscow, Russia', () => {
  const parsed = parseGlobalpingTcpResult({
    status: 'finished',
    results: [{
      probe: { city: 'Moscow', country: 'RU', network: 'Example ISP', asn: 12345 },
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
});

test('never accepts a successful probe from a non-Moscow location', () => {
  const parsed = parseGlobalpingTcpResult({
    status: 'finished',
    results: [{
      probe: { city: 'Amsterdam', country: 'NL' },
      result: { status: 'finished', stats: { min: 4, avg: 5, max: 6, total: 3, rcv: 3, loss: 0 } },
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
  ]);

  assert.equal(quality.latency_ms, 90);
  assert.equal(quality.jitter_ms, 15);
  assert.equal(quality.reliability_pct, 67);
  assert.equal(quality.available, true);
  assert.equal(Number.isFinite(quality.score), true);
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

test('keeps a 60-endpoint Moscow scan within 15 minutes and 240 checks per hour', () => {
  assert.equal(calculateSweepMinutes(60, 4), 15);
  assert.equal(calculateSweepMinutes(61, 4), 16);
  assert.equal(calculateSweepMinutes(0, 4), 0);
});
