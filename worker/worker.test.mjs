import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCheckHostTarget,
  calculateSweepMinutes,
  parseCheckHostTcpResult,
} from './worker.mjs';

test('formats IPv4 probe targets as HTTPS URLs with the requested port', () => {
  assert.equal(buildCheckHostTarget('8.8.8.8', 443), 'https://8.8.8.8:443');
});

test('formats IPv6 probe targets with brackets', () => {
  assert.equal(
    buildCheckHostTarget('2606:4700:4700::1111', 8443),
    'https://[2606:4700:4700::1111]:8443',
  );
});

test('rejects invalid TCP ports', () => {
  assert.throws(() => buildCheckHostTarget('8.8.8.8', 0), /port/i);
  assert.throws(() => buildCheckHostTarget('8.8.8.8', 65536), /port/i);
});

test('parses the documented Check-Host TCP success shape', () => {
  assert.deepEqual(
    parseCheckHostTcpResult({
      'ru1.node.check-host.net': [{ time: 0.1234, address: '8.8.8.8' }],
    }),
    { ok: true, latency_ms: 123, address: '8.8.8.8' },
  );
});

test('parses a TCP connection error', () => {
  assert.deepEqual(
    parseCheckHostTcpResult({
      'ru1.node.check-host.net': [{ error: 'Connection timed out' }],
    }),
    { ok: false, error: 'Connection timed out' },
  );
});

test('leaves an unfinished Check-Host request pending', () => {
  assert.equal(parseCheckHostTcpResult({ 'ru1.node.check-host.net': null }), null);
});

test('rotates a 300-endpoint pool in 15 one-minute scan batches', () => {
  assert.equal(calculateSweepMinutes(300, 20), 15);
});

test('rounds partial scan batches up and handles an empty pool', () => {
  assert.equal(calculateSweepMinutes(21, 20), 2);
  assert.equal(calculateSweepMinutes(0, 20), 0);
});
