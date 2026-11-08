import test from 'node:test';
import assert from 'node:assert/strict';
import {
  calculateSweepMinutes,
  decodeMaybeBase64,
  parseProxyUri,
  probeTcpSocket,
} from './worker.mjs';

test('probes a reachable TCP endpoint and closes the socket', async () => {
  let closed = false;
  const result = await probeTcpSocket(
    { host: 'proxy.example.net', port: 443 },
    (address, options) => {
      assert.deepEqual(address, { hostname: 'proxy.example.net', port: 443 });
      assert.deepEqual(options, { secureTransport: 'off', allowHalfOpen: false });
      return {
        opened: Promise.resolve({ remoteAddress: '203.0.113.10' }),
        close() { closed = true; },
      };
    },
  );
  assert.equal(result.ok, true);
  assert.equal(Number.isFinite(result.latency_ms), true);
  assert.equal(result.address, '203.0.113.10');
  assert.equal(closed, true);
});

test('reports TCP connect errors and closes failed sockets', async () => {
  let closed = false;
  const result = await probeTcpSocket(
    { host: 'proxy.example.net', port: 443 },
    () => ({
      opened: Promise.reject(new Error('Connection refused')),
      close() { closed = true; },
    }),
  );
  assert.deepEqual(result, { ok: false, error: 'Connection refused' });
  assert.equal(closed, true);
});

test('times out a stalled TCP handshake', async () => {
  let closed = false;
  const result = await probeTcpSocket(
    { host: 'proxy.example.net', port: 443 },
    () => ({
      opened: new Promise(() => {}),
      close() { closed = true; },
    }),
    5,
  );
  assert.deepEqual(result, { ok: false, error: 'TCP connect timeout' });
  assert.equal(closed, true);
});

test('does not claim success when the runtime socket connector is missing', async () => {
  assert.deepEqual(
    await probeTcpSocket({ host: 'proxy.example.net', port: 443 }, null),
    { ok: false, error: 'Cloudflare TCP socket connector is unavailable' },
  );
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

test('a 300-endpoint pool is fully pinged within a 15-minute rotation', () => {
  assert.equal(calculateSweepMinutes(300, 20), 15);
  assert.equal(calculateSweepMinutes(301, 20), 16);
  assert.equal(calculateSweepMinutes(0, 20), 0);
});
