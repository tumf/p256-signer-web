// Offline contract of the Web side against the pinned Swift SDK's response re-serialization (docs/mvp2-sdk-local-transport.md).
//
// The app hands the exact closed eleven-field result bytes to the SDK port; the pinned reown-swift SDK decodes them
// into AnyCodable (a dictionary), builds RPCResponse(id, result) and JSONEncoder-encodes it before encryption, so the
// result text the browser SDK decrypts has the SDK's key order and escaping (Darwin escapes "/" as "\/"), not the
// app's bytes. These tests pin what the unchanged browser side therefore relies on: the structured SDK result is
// verified field by field by the independent validator (order-insensitive, value-exact), the typed id and the closed
// errors survive, and a late reply for another request never verifies. Node software key only; no SDK, relay, UI,
// network or production manifest. Nothing here is live SDK delivery evidence.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign as nodeSign } from 'node:crypto';
import { test } from 'node:test';
import { bytesToHex, hexToBytes, keccak } from '../defi-v3.js';
import { BRIDGE_ORIGIN, CHAIN, METHODS, SIGN_METHOD, candidateFromWire, createSessionConfig, createV3BridgeSession }
  from '../defi-v3-session.js';
import { P256, RESULT_FIELDS, V3ResultError, copyResult, verifyV3Result } from '../defi-v3-result.js';
import { buildSafeTxWire } from './support/defi-v3-exchange-client.mjs';

const sha256 = (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest());
const utf8 = (text) => new TextEncoder().encode(text);
const big = (bytes) => BigInt(bytesToHex(bytes));
const word = (v) => hexToBytes('0x' + v.toString(16).padStart(64, '0'));
const SAFE = '0x' + '11'.repeat(20);
const SIGNER = '0x' + '22'.repeat(20);
const TOPIC = 'ab'.repeat(32);
const BINDING = '0x' + 'cd'.repeat(32);
const NOW = 1_700_000_000;

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
  return { privateKey, point, keyId: bytesToHex(sha256(point)).slice(2) };
}

/** The app codec's shape: P-256 over the message H (ECDSA hashes it with SHA-256), low-S, r||s. */
function appResult(key, candidate) {
  const h = hexToBytes(candidate.signedDigest);
  const ieee = nodeSign('sha256', h, { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  const r = big(ieee.subarray(0, 32));
  let s = big(ieee.subarray(32));
  if (s > P256.HALF_N) s = P256.N - s;
  const raw = concat(word(r), word(s));
  const values = {
    v: candidate.v, purpose: candidate.purpose, requestId: candidate.requestId, keyId: candidate.keyId,
    codecId: candidate.codecId, binding: candidate.binding, commitment: candidate.commitment,
    signedDigest: candidate.signedDigest, publicPoint: bytesToHex(key.point), rawSignature: bytesToHex(raw),
    signerSignature: bytesToHex(concat(keccak(utf8(candidate.keyId)), raw)),
  };
  // SafeDeFiResultCodec.encode: canonical field order, compact, strings only.
  const text = '{' + RESULT_FIELDS.map((k) => `"${k}":"${values[k]}"`).join(',') + '}';
  return { values, text };
}

/** What the pinned Swift SDK encrypts: AnyCodable dictionary order (arbitrary; reversed here) and escaped slashes. */
function swiftSDKPlaintext(id, values) {
  const escape = (text) => text.replaceAll('/', '\\/');
  const members = [...RESULT_FIELDS].reverse().map((k) => `"${k}":"${escape(values[k])}"`);
  return `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{${members.join(',')}}}`;
}

function swiftSDKErrorPlaintext(id, code, message, data) {
  const error = { code, message, ...(data === undefined ? {} : { data }) };
  return `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"error":${JSON.stringify(error)}}`;
}

function candidateFor(key, { variant = 1 } = {}) {
  const wire = buildSafeTxWire({ safe: SAFE, signer: SIGNER, keyId: key.keyId, binding: BINDING, issuedAt: NOW, variant });
  return { wire, candidate: candidateFromWire(wire, sha256) };
}

/** Fake browser SDK client: `request()` resolves with the structured object the SDK decoded from `plaintext`. */
function fakeClient(plaintextFor) {
  const calls = [];
  const session = { topic: TOPIC, expiry: 2_000_000_000, peer: { metadata: { url: BRIDGE_ORIGIN } },
    namespaces: { eip155: { accounts: [`${CHAIN}:${SIGNER}`], methods: [...METHODS], events: [] } } };
  return {
    calls,
    session: { get: () => session }, on() {}, off() {},
    connect: async (args) => { calls.push(['connect', args]); return { approval: async () => session }; },
    disconnect: async (args) => { calls.push(['disconnect', args]); },
    request: async (args) => {
      calls.push(['request', args]);
      const response = JSON.parse(plaintextFor(args));
      if (response.error) {
        const error = new Error(response.error.message);
        error.code = response.error.code;
        error.data = response.error.data;
        throw error;
      }
      return response.result;
    },
  };
}

test('the structured SDK result verifies field by field regardless of SDK key order and escaping', () => {
  const key = softwareKey();
  const { candidate } = candidateFor(key);
  const { values, text } = appResult(key, candidate);
  const plaintext = swiftSDKPlaintext(1, values);
  assert.notEqual(plaintext.includes(text), true, 'the SDK plaintext does not carry the app bytes verbatim');
  assert.ok(plaintext.includes('\\/'), 'slashes in codecId/purpose are escaped by the Swift encoder');
  const response = JSON.parse(plaintext);
  assert.equal(response.id, 1, 'integer typed id survives as a JSON number');
  assert.notDeepEqual(Object.keys(response.result), RESULT_FIELDS, 'SDK order differs from the canonical order');
  // The browser SDK hands the structured object to the unchanged validator: value-exact, order-insensitive.
  const verified = verifyV3Result(response.result, candidate, { sha256 });
  assert.deepEqual(Object.keys(verified), RESULT_FIELDS, 'the frozen copy is canonical');
  for (const field of RESULT_FIELDS) assert.equal(verified[field], values[field]);
  // The SDK plaintext's result text (escaped, reordered) is also accepted as text by the strict parser, and
  // re-emitting the verified values in canonical order reproduces the app's exact bytes.
  const sdkText = plaintext.slice(plaintext.indexOf('"result":') + '"result":'.length, -1);
  assert.notEqual(sdkText, text);
  assert.deepEqual(copyResult(sdkText), verified);
  assert.equal('{' + RESULT_FIELDS.map((k) => `"${k}":"${verified[k]}"`).join(',') + '}', text);
  // The contract is the values: changing any one of them after re-serialization is caught.
  const tampered = { ...response.result, rawSignature: '0x' + '00'.repeat(64) };
  assert.throws(() => verifyV3Result(tampered, candidate, { sha256 }), V3ResultError);
});

test('the unchanged session accepts the reordered structured result and reports it verified', async () => {
  const key = softwareKey();
  const { wire, candidate } = candidateFor(key);
  const { values } = appResult(key, candidate);
  const client = fakeClient(() => swiftSDKPlaintext(1, values));
  const bridge = createV3BridgeSession({ client, config: createSessionConfig({ signer: SIGNER, safe: SAFE }), sha256,
    clock: () => NOW });
  await bridge.connect();
  assert.equal(client.calls.filter(([name]) => name === 'request').length, 0, 'connect never requests');
  const result = await bridge.request(wire);
  assert.equal(result.rawSignature, values.rawSignature);
  assert.equal(result.commitment, candidate.commitment);
  assert.equal(bridge.inspect().outcomes[candidate.requestId], 'verified');
  const [, sent] = client.calls.find(([name]) => name === 'request');
  assert.equal(sent.topic, TOPIC);
  assert.equal(sent.request.method, SIGN_METHOD);
  assert.equal(JSON.stringify(sent.request.params[0]), new TextDecoder().decode(wire), 'the original envelope is sent');
  await bridge.dispose();
});

test('a late reply for another request, a cancelled request and an unavailable result never verify', async () => {
  const key = softwareKey();
  const first = candidateFor(key, { variant: 1 });
  const second = candidateFor(key, { variant: 2 });
  // Old-session reply: the app's result for the first request answers the second one's id (never admitted twice).
  const stale = appResult(key, first.candidate);
  assert.throws(() => verifyV3Result(JSON.parse(swiftSDKPlaintext(2, stale.values)).result, second.candidate, { sha256 }),
    { code: 'METADATA_MISMATCH:requestId' });
  assert.throws(() => verifyV3Result(JSON.parse(swiftSDKPlaintext(2, stale.values)).result, second.candidate, { sha256 }),
    (error) => error instanceof V3ResultError);
  // Cancellation and unavailability: the closed errors the app maps (4001 without data, -32000 with classification).
  const plaintexts = [
    [swiftSDKErrorPlaintext(1, 4001, 'user rejected'), 'RPC_4001'],
    [swiftSDKErrorPlaintext(1, -32000, 'result unavailable', { classification: 'RESULT_UNAVAILABLE' }), 'RPC_-32000'],
  ];
  for (const [plaintext, code] of plaintexts) {
    const decoded = JSON.parse(plaintext);
    assert.equal(decoded.result, undefined);
    const client = fakeClient(() => plaintext);
    const bridge = createV3BridgeSession({ client, config: createSessionConfig({ signer: SIGNER, safe: SAFE }), sha256,
      clock: () => NOW });
    await bridge.connect();
    await assert.rejects(bridge.request(first.wire), { code });
    assert.equal(bridge.inspect().outcomes[first.candidate.requestId], 'rejected');
    assert.equal(client.calls.filter(([name]) => name === 'request').length, 1, 'no automatic retry');
    await bridge.dispose();
  }
  // String typed ids are JSON strings on the wire and never equal the integer form.
  assert.equal(JSON.parse(swiftSDKErrorPlaintext('req-1', 4001, 'user rejected')).id, 'req-1');
  assert.notEqual(JSON.parse(swiftSDKErrorPlaintext('1', 4001, 'user rejected')).id, 1);
});
