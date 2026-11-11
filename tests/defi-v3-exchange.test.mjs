// Offline tests of the file-exchange client under the unchanged createV3BridgeSession (no Simulator, SDK or network).
//
// The app side is simulated in-process: it publishes a grant, reads the request record's exact bytes and writes one
// result record signed with an ephemeral Node software key (test double only; the real path never has a Node signer).
// Verified: zero requests on connect, one verified result from the original candidate, and refusal of stale runs,
// mutated identity, tampered bytes, cancellation, a second request and a second result.
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { bytesToHex, hexToBytes, keccak } from '../defi-v3.js';
import { BRIDGE_ORIGIN, CHAIN, METHODS, SIGN_METHOD, candidateFromWire } from '../defi-v3-session.js';
import { P256, multiply } from '../defi-v3-result.js';
import {
  ExchangeError, FILES, buildSafeTxWire, createExchangeClient, runExchange, sha256, topicFor, writeOnce, writeRun,
} from './support/defi-v3-exchange-client.mjs';

const SAFE = '0x' + '11'.repeat(20);
const SIGNER = '0xa11ce0000000000000000000000000000000a11c';
const utf8 = (text) => new TextEncoder().encode(text);
const big = (bytes) => BigInt(bytesToHex(bytes));
const word = (v) => hexToBytes('0x' + v.toString(16).padStart(64, '0'));

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function softwareKey() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = privateKey.export({ format: 'jwk' });
  const b = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
  const point = concat(Uint8Array.of(4), b(jwk.x), b(jwk.y));
  return { d: big(b(jwk.d)), point, keyId: bytesToHex(sha256(point)).slice(2) };
}

function invert(a, m) {
  let [r0, r1, s0, s1] = [((a % m) + m) % m, m, 1n, 0n];
  while (r1) { const q = r0 / r1; [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1]; }
  return ((s0 % m) + m) % m;
}

function signDigest(key, h) {
  const { N, G, HALF_N } = P256;
  for (;;) {
    const k = big(randomBytes(32)) % N;
    if (k === 0n) continue;
    const r = multiply(k, G).x % N;
    let s = (invert(k, N) * (big(h) + r * key.d)) % N;
    if (r === 0n || s === 0n) continue;
    if (s > HALF_N) s = N - s;
    return { r, s };
  }
}

/** The closed eleven-field result text for a candidate (the app's SafeDeFiResultCodec stands in here). */
function resultText(key, candidate) {
  const { r, s } = signDigest(key, sha256(hexToBytes(candidate.signedDigest)));
  const raw = concat(word(r), word(s));
  const fields = [['v', candidate.v], ['purpose', candidate.purpose], ['requestId', candidate.requestId],
    ['keyId', candidate.keyId], ['codecId', candidate.codecId], ['binding', candidate.binding],
    ['commitment', candidate.commitment], ['signedDigest', candidate.signedDigest],
    ['publicPoint', bytesToHex(key.point)], ['rawSignature', bytesToHex(raw)],
    ['signerSignature', bytesToHex(concat(keccak(utf8(candidate.keyId)), raw))]];
  return '{' + fields.map(([k, v]) => `"${k}":"${v}"`).join(',') + '}';
}

function workspace(t) {
  const dir = mkdtempSync(join(tmpdir(), 'p256-defi-exchange-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const run = randomUUID();
  writeRun(dir, run);
  return { dir, run, topic: topicFor(run) };
}

/** In-process stand-in for the app composition/port: grant after permission, one result at the explicit return. */
function phone({ dir, run, topic }, key, { grantRun = run, grantTopic = topic, mutate = (r) => r, cancel = false } = {}) {
  const binding = bytesToHex(randomBytes(32));
  const signs = { count: 0 };
  writeOnce(dir, FILES.app, { run, stage: 'composed' });
  writeOnce(dir, FILES.grant, {
    run: grantRun,
    session: { topic: grantTopic, expiry: Math.floor(Date.now() / 1000) + 3600, peer: { metadata: { url: BRIDGE_ORIGIN } },
      namespaces: { eip155: { accounts: [`${CHAIN}:${SIGNER}`], methods: [...METHODS], events: [], chains: [CHAIN] } } },
    grant: { safe: SAFE, signer: SIGNER, keyId: key.keyId, binding, chainId: '137' },
  });
  const explicitReturn = async () => {
    while (!existsSync(join(dir, FILES.request))) await new Promise((r) => setTimeout(r, 20));
    const request = JSON.parse(readFileSync(join(dir, FILES.request), 'utf8'));
    assert.equal(request.run, run);
    assert.equal(request.topic, topic);
    const outer = JSON.parse(request.raw);
    const identity = { run, topic, id: { t: 'integer', v: String(outer.id) }, method: outer.method, chain: CHAIN,
      params: JSON.stringify(outer.params) };
    if (cancel) return writeOnce(dir, FILES.result, mutate({ ...identity, error: { code: 4001, message: 'user rejected' } }));
    const candidate = candidateFromWire(utf8(JSON.stringify(outer.params[0])), sha256);
    signs.count += 1;
    const result = resultText(key, candidate);
    const record = mutate({ ...identity, result, resultSha256: bytesToHex(sha256(utf8(result))).slice(2) });
    return writeOnce(dir, FILES.result, record);
  };
  return { signs, binding, explicitReturn };
}

test('explicit return completes the Web request with the app bytes verified independently', async (t) => {
  const ws = workspace(t);
  const key = softwareKey();
  const app = phone(ws, key);
  const client = createExchangeClient({ dir: ws.dir, run: ws.run, timeoutMs: 5_000, pollMs: 20 });
  const grant = await client.peekGrant();
  assert.equal(grant.binding, app.binding);
  assert.equal(client.calls.length, 0, 'reading the grant requests nothing');
  const returning = app.explicitReturn();
  const verdict = await runExchange({ dir: ws.dir, run: ws.run, safe: SAFE, timeoutMs: 5_000, pollMs: 20 });
  await returning;
  assert.equal(verdict.status, 'verified', JSON.stringify(verdict));
  assert.equal(app.signs.count, 1);
  assert.deepEqual(verdict.counts, { connects: 1, requests: 1, verified: 1 });
  assert.equal(verdict.account, `${CHAIN}:${SIGNER}`);
  assert.equal(verdict.keyId, key.keyId);
  const request = JSON.parse(readFileSync(join(ws.dir, FILES.request), 'utf8'));
  assert.deepEqual(request.id, { t: 'integer', v: '1' });
  assert.equal(request.method, SIGN_METHOD);
  assert.equal(request.chain, CHAIN);
  const envelope = JSON.parse(request.raw).params[0];
  assert.equal(envelope.binding, app.binding);
  assert.equal(envelope.id, verdict.requestId);
  const result = JSON.parse(readFileSync(join(ws.dir, FILES.result), 'utf8'));
  assert.equal(verdict.resultSha256, result.resultSha256);
  const text = JSON.stringify(verdict);
  assert.ok(!text.includes(ws.topic) && !text.includes(app.binding.slice(2)) && !text.includes(result.result),
    'verdict carries no topic, binding or result bytes');
  // A second result record for the same run can never be created.
  assert.throws(() => writeOnce(ws.dir, FILES.result, result), { code: `EXISTS:${FILES.result}` });
  // A second request on the settled exchange is refused before anything is written.
  assert.throws(() => writeOnce(ws.dir, FILES.request, request), { code: `EXISTS:${FILES.request}` });
});

test('connect never requests; a grant of another run or topic is refused', async (t) => {
  const key = softwareKey();
  for (const override of [{ grantRun: randomUUID() }, { grantTopic: topicFor(randomUUID()) }]) {
    const ws = workspace(t);
    phone(ws, key, override);
    const verdict = await runExchange({ dir: ws.dir, run: ws.run, safe: SAFE, timeoutMs: 1_000, pollMs: 20 });
    assert.equal(verdict.status, 'failed');
    assert.equal(verdict.code, 'GRANT_MISMATCH');
    assert.equal(verdict.counts.requests, 0);
    assert.ok(!existsSync(join(ws.dir, FILES.request)));
  }
  const ws = workspace(t);
  const client = createExchangeClient({ dir: ws.dir, run: ws.run, timeoutMs: 200, pollMs: 20 });
  await assert.rejects(client.peekGrant(), { code: `TIMEOUT:${FILES.grant}` });
});

test('stale run, mutated identity, tampered bytes and cancellation never verify', async (t) => {
  const key = softwareKey();
  const cases = [
    ['stale run', (r) => ({ ...r, run: randomUUID() }), 'DELIVERY_UNKNOWN', 'unknown'],
    ['other topic', (r) => ({ ...r, topic: topicFor(randomUUID()) }), 'DELIVERY_UNKNOWN', 'unknown'],
    ['typed id', (r) => ({ ...r, id: { t: 'string', v: '1' } }), 'DELIVERY_UNKNOWN', 'unknown'],
    ['other id', (r) => ({ ...r, id: { t: 'integer', v: '2' } }), 'DELIVERY_UNKNOWN', 'unknown'],
    ['method', (r) => ({ ...r, method: 'p256_getSafeRequestResultV3' }), 'DELIVERY_UNKNOWN', 'unknown'],
    ['chain', (r) => ({ ...r, chain: 'eip155:1' }), 'DELIVERY_UNKNOWN', 'unknown'],
    ['params', (r) => ({ ...r, params: r.params.replace('"v":"3"', '"v":"2"') }), 'DELIVERY_UNKNOWN', 'unknown'],
    ['digest', (r) => ({ ...r, resultSha256: 'ab'.repeat(32) }), 'DELIVERY_UNKNOWN', 'unknown'],
    ['tampered signature', (r) => {
      const text = r.result.replace(/"rawSignature":"0x([0-9a-f]{2})/, (_, b) => `"rawSignature":"0x${b === '00' ? '01' : '00'}`);
      return { ...r, result: text, resultSha256: bytesToHex(sha256(utf8(text))).slice(2) };
    }, 'SIGNATURE_MISMATCH', 'pending'],
    ['tampered binding', (r) => {
      const text = r.result.replace(/"binding":"0x[0-9a-f]{64}"/, `"binding":"0x${'ef'.repeat(32)}"`);
      return { ...r, result: text, resultSha256: bytesToHex(sha256(utf8(text))).slice(2) };
    }, 'METADATA_MISMATCH:binding', 'pending'],
    ['error and result together', (r) => ({ ...r, error: { code: 4001, message: 'x' } }), 'DELIVERY_UNKNOWN', 'unknown'],
  ];
  for (const [name, mutate, code, outcome] of cases) {
    const ws = workspace(t);
    const app = phone(ws, key, { mutate });
    const returning = app.explicitReturn();
    const verdict = await runExchange({ dir: ws.dir, run: ws.run, safe: SAFE, timeoutMs: 2_000, pollMs: 20 });
    await returning;
    assert.equal(verdict.status, 'failed', name);
    assert.equal(verdict.code, code, name);
    assert.equal(verdict.counts.verified, 0, name);
    assert.deepEqual(Object.values(verdict.outcomes), [outcome], name);
  }
  const ws = workspace(t);
  const app = phone(ws, key, { cancel: true });
  const returning = app.explicitReturn();
  const verdict = await runExchange({ dir: ws.dir, run: ws.run, safe: SAFE, timeoutMs: 2_000, pollMs: 20 });
  await returning;
  assert.equal(verdict.status, 'failed');
  assert.equal(verdict.code, 'RPC_4001');
  assert.equal(app.signs.count, 0);
  assert.deepEqual(Object.values(verdict.outcomes), ['rejected']);
});

test('the Web candidate is bound to the grant and refused for another Safe or chain by the session', async (t) => {
  const ws = workspace(t);
  const key = softwareKey();
  const app = phone(ws, key);
  // Web's expected Safe or Signer differing from the published grant never reaches the exchange.
  for (const expectation of [{ safe: '0x' + '22'.repeat(20) }, { safe: SAFE, signer: '0x' + '22'.repeat(20) }]) {
    const verdict = await runExchange({ dir: ws.dir, run: ws.run, timeoutMs: 1_000, pollMs: 20, ...expectation });
    assert.equal(verdict.status, 'failed');
    assert.equal(verdict.code, 'GRANT_MISMATCH');
    assert.equal(verdict.counts.requests, 0);
    assert.ok(!existsSync(join(ws.dir, FILES.request)));
    assert.equal(app.signs.count, 0);
  }
  const wire = buildSafeTxWire({ safe: SAFE, signer: SIGNER, keyId: key.keyId, binding: app.binding, issuedAt: 1_700_000_000 });
  const candidate = candidateFromWire(wire, sha256);
  assert.equal(candidate.chainId, '137');
  assert.equal(candidate.binding, app.binding);
  assert.throws(() => buildSafeTxWire({ safe: SAFE, signer: SIGNER, keyId: key.keyId, binding: 'cd'.repeat(32),
    issuedAt: 1 }), ExchangeError);
});
