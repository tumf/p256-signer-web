// Offline tests of the browser v3 bridge session and the independent result validator.
//
// Fake SDK client and ephemeral Node software keys only: no relay, network, WalletConnect, Keychain or production
// manifest. P-256 verification is cross-checked against Node's OpenSSL signer before it judges any result.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign as nodeSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { bytesToHex, hexToBytes, keccak } from '../defi-v3.js';
import {
  BRIDGE_ORIGIN, CHAIN, METHODS, RESULT_METHOD, SIGN_METHOD, candidateFromWire, createSessionConfig,
  createV3BridgeSession, requiredNamespaces,
} from '../defi-v3-session.js';
import { P256, RESULT_FIELDS, V3ResultError, multiply, verifyP256, verifyV3Result } from '../defi-v3-result.js';

const sha256 = (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest());
const utf8 = (text) => new TextEncoder().encode(text);
const hexOf = (text) => bytesToHex(utf8(text));
const SAFE = '0x1111111111111111111111111111111111111111';
const SIGNER = '0x2222222222222222222222222222222222222222';
const TOPIC = 'ab'.repeat(32);
const BINDING = '0x' + 'cd'.repeat(32);
const CODEC = 'hybrid-delegator-1.3.0/raw-p256-msg/v1';

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const word = (v) => hexToBytes('0x' + v.toString(16).padStart(64, '0'));
const big = (bytes) => BigInt(bytesToHex(bytes));

function softwareKey() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = privateKey.export({ format: 'jwk' });
  const b = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
  const point = concat(Uint8Array.of(4), b(jwk.x), b(jwk.y));
  return { privateKey, d: big(b(jwk.d)), point, keyId: bytesToHex(sha256(point)).slice(2) };
}

function invert(a, m) {
  let [r0, r1, s0, s1] = [((a % m) + m) % m, m, 1n, 0n];
  while (r1) { const q = r0 / r1; [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1]; }
  return ((s0 % m) + m) % m;
}

/** Test-only ECDSA over H as e (random nonce). `high` forces the high-S twin. */
function signDigest(key, h, { high = false } = {}) {
  const { N, G, HALF_N } = P256;
  for (;;) {
    const k = big(randomBytes(32)) % N;
    if (k === 0n) continue;
    const r = multiply(k, G).x % N;
    let s = (invert(k, N) * (big(h) + r * key.d)) % N;
    if (r === 0n || s === 0n) continue;
    if ((s > HALF_N) !== high) s = N - s;
    return { r, s };
  }
}

function typedJson(amount) {
  return '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],'
    + '"Amount":[{"name":"value","type":"uint256"}]},"primaryType":"Amount",'
    + `"domain":{"name":"Demo","chainId":137},"message":{"value":${amount}}}`;
}

function wire(key, { kind = 'personal', id = randomUUID(), signer = SIGNER, safe = SAFE, amount = '1' } = {}) {
  let method; let params; let body; let purpose;
  if (kind === 'typed') {
    const typed = typedJson(amount);
    purpose = 'safe-message-v1.5.0/eip712-v1';
    method = 'eth_signTypedData_v4';
    params = JSON.stringify([safe, typed]);
    body = `{"typedDataJson":"${hexOf(typed)}"}`;
  } else {
    const message = hexOf(`hello ${id}`);
    purpose = 'safe-message-v1.5.0/personal-v1';
    method = 'personal_sign';
    params = JSON.stringify([message, safe]);
    body = `{"encodingProfile":"hex-v1","input":"${message}","bytes":"${message}"}`;
  }
  const payload = `{"chainId":"137","safe":"${safe}","source":{"method":"${method}","idJson":"${hexOf('1')}",`
    + `"paramsJson":"${hexOf(params)}","origin":"https://app.example","chainRef":"eip155:137"},"body":${body}}`;
  const fields = [['v', '3'], ['purpose', purpose], ['codecId', CODEC], ['id', id], ['keyId', key.keyId],
    ['binding', BINDING], ['signer', signer], ['issuedAt', '1700000000'], ['expiresAt', '1700000060'],
    ['payloadJson', hexOf(payload)]];
  return utf8('{' + fields.map(([k, v]) => `"${k}":"${v}"`).join(',') + '}');
}

function resultFor(key, candidate, { high = false, rawDigest = false } = {}) {
  const h = hexToBytes(candidate.signedDigest);
  const { r, s } = signDigest(key, rawDigest ? h : sha256(h), { high });
  const raw = concat(word(r), word(s));
  return {
    v: candidate.v, purpose: candidate.purpose, requestId: candidate.requestId, keyId: candidate.keyId,
    codecId: candidate.codecId, binding: candidate.binding, commitment: candidate.commitment,
    signedDigest: candidate.signedDigest, publicPoint: bytesToHex(key.point), rawSignature: bytesToHex(raw),
    signerSignature: bytesToHex(concat(keccak(utf8(candidate.keyId)), raw)),
  };
}

function session(overrides = {}) {
  return {
    topic: TOPIC, expiry: 2_000_000_000, peer: { metadata: { url: BRIDGE_ORIGIN } },
    namespaces: { eip155: { accounts: [`${CHAIN}:${SIGNER}`], methods: [...METHODS], events: [] } }, ...overrides,
  };
}

/** Fake SDK client simulating the phone: signs only when asked through an explicit request. */
function fakeClient(key, { connectWith = session(), respond } = {}) {
  const calls = [];
  const wires = new Map();
  const client = {
    calls,
    wires,
    session: { get: () => connectWith }, on() {}, off() {},
    connect: async (args) => { calls.push(['connect', args]); return { approval: async () => connectWith }; },
    disconnect: async (args) => { calls.push(['disconnect', args]); },
    request: async (args) => {
      calls.push(['request', structuredClone(args)]);
      if (respond) return respond(args);
      const params = args.request.params[0];
      const id = args.request.method === SIGN_METHOD ? params.id : params.id;
      return resultFor(key, wires.get(id));
    },
  };
  return client;
}

function register(client, bytes) {
  const candidate = candidateFromWire(bytes, sha256);
  client.wires.set(candidate.requestId, candidate);
  return candidate;
}

const config = () => createSessionConfig({ signer: SIGNER, safe: SAFE });

test('explicit permission does not sign', async () => {
  const key = softwareKey();
  const client = fakeClient(key);
  const bridge = createV3BridgeSession({ client, config: config(), sha256 });
  assert.equal(bridge.inspect().connected, false);
  await assert.rejects(bridge.request(wire(key)), { code: 'NOT_CONNECTED' });
  const view = await bridge.connect();
  assert.equal(view.connected, true);
  assert.equal(view.account, `${CHAIN}:${SIGNER}`);
  assert.deepEqual(client.calls.map(([name]) => name), ['connect'], 'connecting requests no signature');
  // Lifecycle events on another topic or foreground-like inspection never request anything.
  bridge.handleEvent('session_update', { topic: 'ef'.repeat(32) });
  bridge.inspect();
  assert.deepEqual(client.calls.map(([name]) => name), ['connect']);
  // A session update ends the session; nothing reconnects or signs.
  bridge.handleEvent('session_update', { topic: TOPIC });
  assert.equal(bridge.inspect().connected, false);
  assert.deepEqual(client.calls.map(([name]) => name), ['connect', 'disconnect']);
  await assert.rejects(bridge.request(wire(key)), { code: 'NOT_CONNECTED' });
});

test('normal local config validates addresses and rejects forged config before SDK access', () => {
  const trusted = config();
  assert.deepEqual(trusted, { bridgeOrigin: BRIDGE_ORIGIN, chain: CHAIN, signer: SIGNER, safe: SAFE });
  assert.ok(Object.isFrozen(trusted));
  for (const options of [undefined, null, {}, { signer: SIGNER }, { signer: SAFE, safe: SAFE },
    { signer: '0x1234', safe: SAFE }, { signer: SIGNER, safe: 'not-an-address' },
    { signer: { toString: () => SIGNER }, safe: SAFE }, { signer: SIGNER, safe: [SAFE] },
    { signer: '0x' + 'AA'.repeat(20), safe: SAFE }]) {
    assert.throws(() => createSessionConfig(options), { code: 'INVALID_CONFIG' });
  }
  const client = fakeClient();
  for (const forged of [undefined, null, { ...trusted }, JSON.parse(JSON.stringify(trusted)),
    Object.freeze({ ...trusted, fixtureOnly: true }), new Proxy(trusted, {})]) {
    assert.throws(() => createV3BridgeSession({ client, config: forged, sha256 }), { code: 'INVALID_CONFIG' });
  }
  assert.deepEqual(client.calls, []);
});

test('normal local config connects and requests only the exact namespace and configured account', async () => {
  const key = softwareKey();
  assert.deepEqual(requiredNamespaces(), {
    eip155: { chains: ['eip155:137'], methods: ['p256_signSafeRequestV3', 'p256_getSafeRequestResultV3'], events: [] },
  });
  const variants = [
    session({ peer: { metadata: { url: 'https://app.example' } } }),
    session({ peer: { metadata: { url: BRIDGE_ORIGIN + '/' } } }),
    session({ namespaces: { eip155: { accounts: [`${CHAIN}:${SIGNER}`], methods: [...METHODS, 'eth_sign'], events: [] } } }),
    session({ namespaces: { eip155: { accounts: [`${CHAIN}:${SIGNER}`], methods: ['p256_signSafeRequest', 'p256_getSessionContext'], events: [] } } }),
    session({ namespaces: { eip155: { accounts: [`eip155:1:${SIGNER}`], methods: [...METHODS], events: [] } } }),
    session({ namespaces: { eip155: { accounts: [`${CHAIN}:${SAFE}`], methods: [...METHODS], events: [] } } }),
    session({ namespaces: { eip155: { accounts: [`${CHAIN}:${SIGNER}`, `${CHAIN}:${SAFE}`], methods: [...METHODS], events: [] } } }),
    session({ namespaces: { eip155: { accounts: [`${CHAIN}:${SIGNER}`], methods: [...METHODS], events: ['chainChanged'] } } }),
    session({ namespaces: { eip155: { accounts: [`${CHAIN}:${SIGNER}`], chains: ['eip155:1'], methods: [...METHODS], events: [] } } }),
  ];
  for (const connectWith of variants) {
    const client = fakeClient(key, { connectWith });
    const bridge = createV3BridgeSession({ client, config: config(), sha256 });
    await assert.rejects(bridge.connect(), { code: 'NAMESPACE_MISMATCH' });
    assert.equal(bridge.inspect().connected, false);
    assert.deepEqual(client.calls.map(([name]) => name), ['connect', 'disconnect']);
  }
  // Wrong account or chain in the request never reaches the client.
  const client = fakeClient(key);
  const bridge = createV3BridgeSession({ client, config: config(), sha256 });
  await bridge.connect();
  await assert.rejects(bridge.request(wire(key, { signer: '0x' + '33'.repeat(20) })), { code: 'ACCOUNT_MISMATCH' });
  assert.equal(client.calls.filter(([name]) => name === 'request').length, 0);
  // The same signer/chain may authorize multiple Safes; the configured Safe is not interchangeable.
  const requestId = randomUUID();
  await assert.rejects(bridge.request(wire(key, { id: requestId, safe: '0x' + '33'.repeat(20) })),
    { code: 'ACCOUNT_MISMATCH' });
  assert.equal(client.calls.filter(([name]) => name === 'request').length, 0);
  const allowed = wire(key, { id: requestId });
  register(client, allowed);
  assert.equal((await bridge.request(allowed)).requestId, requestId);
  assert.equal(client.calls.filter(([name]) => name === 'request').length, 1);
});

test('lossless envelope and strict result verification', async () => {
  const key = softwareKey();
  // The verifier agrees with OpenSSL on a Node-made signature over H = SHA-256(m), used directly as e.
  const m = randomBytes(40);
  const der = nodeSign('sha256', m, { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  const r = big(der.subarray(0, 32));
  let s = big(der.subarray(32));
  if (s > P256.HALF_N) s = P256.N - s;
  assert.equal(verifyP256(key.point, sha256(m), r, s), true);
  assert.throws(() => verifyP256(key.point, sha256(m), r, P256.N - s), { code: 'HIGH_S' });
  assert.throws(() => verifyP256(key.point, sha256(randomBytes(8)), r, s), { code: 'INVALID_SIGNATURE' });
  // A SHA-256 over H is not the signed message.
  const h = sha256(m);
  assert.throws(() => verifyP256(key.point, sha256(h), r, s), { code: 'INVALID_SIGNATURE' });

  const client = fakeClient(key);
  const bridge = createV3BridgeSession({ client, config: config(), sha256 });
  await bridge.connect();
  const amount = '123456789012345678901234567890123456789';
  const bytes = wire(key, { kind: 'typed', amount });
  const candidate = register(client, bytes);
  const result = await bridge.request(bytes);
  const [, sent] = client.calls.find(([name]) => name === 'request');
  assert.equal(sent.topic, TOPIC);
  assert.equal(sent.chainId, CHAIN);
  assert.equal(sent.request.method, SIGN_METHOD);
  assert.equal(sent.request.params.length, 1);
  // The envelope object re-serializes to the exact original wire; payloadJson keeps the raw number token.
  assert.equal(JSON.stringify(sent.request.params[0]), new TextDecoder().decode(bytes));
  const payload = new TextDecoder().decode(hexToBytes(sent.request.params[0].payloadJson));
  const typed = new TextDecoder().decode(hexToBytes(JSON.parse(payload).body.typedDataJson));
  assert.ok(typed.includes(`"value":${amount}`));
  assert.ok(Object.isFrozen(result));
  assert.equal(Object.getPrototypeOf(result), null);
  assert.deepEqual(Object.keys(result), RESULT_FIELDS);
  assert.equal(result.commitment, candidate.commitment);
  assert.equal(bridge.inspect().outcomes[candidate.requestId], 'verified');
  // JSON text results are parsed strictly too.
  assert.ok(verifyV3Result(JSON.stringify(resultFor(key, candidate)), candidate, { sha256 }));
  assert.throws(() => verifyV3Result('{"v":"3","v":"3"}', candidate, { sha256 }), V3ResultError);
});

test('stale session and unknown send never retry', async () => {
  const key = softwareKey();
  // Session ended while the request is in flight: the late result is discarded.
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const slow = fakeClient(key, { respond: async (args) => { await gate; return resultFor(key, slow.wires.get(args.request.params[0].id)); } });
  const bridge = createV3BridgeSession({ client: slow, config: config(), sha256 });
  await bridge.connect();
  const bytes = wire(key);
  register(slow, bytes);
  const pending = bridge.request(bytes);
  bridge.handleEvent('session_delete', { topic: TOPIC });
  release();
  await assert.rejects(pending, { code: 'STALE_SESSION' });
  assert.equal(bridge.inspect().connected, false);

  // Unknown delivery: exactly one request, no automatic retry; explicit retrieve uses the closed recovery params.
  let first = true;
  const flaky = fakeClient(key, {
    respond: async (args) => {
      if (first) { first = false; throw new Error('socket closed'); }
      return resultFor(key, flaky.wires.get(args.request.params[0].id));
    },
  });
  const second = createV3BridgeSession({ client: flaky, config: config(), sha256 });
  await second.connect();
  const unknownWire = wire(key);
  const candidate = register(flaky, unknownWire);
  await assert.rejects(second.request(unknownWire), { code: 'DELIVERY_UNKNOWN' });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(flaky.calls.filter(([name]) => name === 'request').length, 1, 'never retried automatically');
  assert.equal(second.inspect().outcomes[candidate.requestId], 'unknown');
  await assert.rejects(second.request(unknownWire), { code: 'DUPLICATE_REQUEST' });
  const recovered = await second.retrieve(candidate.requestId);
  const [, retrieval] = flaky.calls.filter(([name]) => name === 'request')[1];
  assert.equal(retrieval.request.method, RESULT_METHOD);
  assert.deepEqual(retrieval.request.params, [{ id: candidate.requestId, commitment: candidate.commitment,
    binding: candidate.binding }]);
  assert.equal(recovered.requestId, candidate.requestId);
  // A closed RPC error is surfaced as its fixed code, without retry.
  const rejecting = fakeClient(key, { respond: async () => { throw Object.assign(new Error('x'), { code: 4001 }); } });
  const third = createV3BridgeSession({ client: rejecting, config: config(), sha256 });
  await third.connect();
  const rejected = wire(key);
  await assert.rejects(third.request(rejected), { code: 'RPC_4001' });
  assert.equal(rejecting.calls.filter(([name]) => name === 'request').length, 1);
  await assert.rejects(second.retrieve(randomUUID()), { code: 'UNKNOWN_REQUEST' });
});

test('SDK store changes during a signed reply suppress late success without an event', async () => {
  for (const mutate of [s => { s.expiry = 0; }, s => { s.namespaces.eip155.accounts = [`${CHAIN}:${SAFE}`]; }]) {
    const key = softwareKey(), granted = session();
    const client = fakeClient(key, { connectWith: granted, respond: async args => {
      mutate(granted);
      return resultFor(key, client.wires.get(args.request.params[0].id));
    } });
    const bridge = createV3BridgeSession({ client, config: config(), sha256 });
    await bridge.connect();
    const bytes = wire(key); register(client, bytes);
    await assert.rejects(bridge.request(bytes), { code: 'STALE_SESSION' });
    assert.equal(bridge.inspect().connected, false);
    assert.deepEqual(Object.keys(bridge.inspect().outcomes), []);
    assert.equal(client.calls.filter(([name]) => name === 'request').length, 1);
  }
});

test('independent result rejects extra fields high-S keyIDHash mismatch', () => {
  const key = softwareKey();
  const candidate = candidateFromWire(wire(key), sha256);
  const good = resultFor(key, candidate);
  assert.ok(verifyV3Result(good, candidate, { sha256 }));
  const reject = (value, code, against = candidate) => {
    assert.throws(() => verifyV3Result(value, against, { sha256 }), (error) => {
      assert.ok(error instanceof V3ResultError);
      assert.equal(error.code, code);
      assert.ok(!error.message.includes(good.rawSignature.slice(2, 18)), 'no signature bytes in errors');
      return true;
    });
  };
  reject({ ...good, extra: 'x' }, 'UNKNOWN_FIELD');
  const missing = { ...good };
  delete missing.signerSignature;
  reject(missing, 'MISSING_FIELD');
  reject({ ...good, v: 3 }, 'NON_STRING_FIELD');
  reject(Object.defineProperty({ ...good }, 'binding', { get: () => good.binding, enumerable: true }), 'NON_STRING_FIELD');
  reject(Object.assign(Object.create({ inherited: 1 }), good), 'MALFORMED');
  reject([good], 'MALFORMED');
  reject(resultFor(key, candidate, { high: true }), 'HIGH_S');
  reject(resultFor(key, candidate, { rawDigest: true }), 'INVALID_SIGNATURE');
  const raw = hexToBytes(good.rawSignature);
  reject({ ...good, signerSignature: bytesToHex(concat(keccak(hexToBytes('0x' + candidate.keyId)), raw)) },
    'KEY_ID_HASH_MISMATCH');
  reject({ ...good, signerSignature: bytesToHex(concat(new Uint8Array(32), raw)) }, 'KEY_ID_HASH_MISMATCH');
  const other = resultFor(key, candidate);
  reject({ ...good, signerSignature: other.signerSignature }, 'SIGNATURE_MISMATCH');
  reject({ ...good, rawSignature: good.rawSignature.toUpperCase().replace('0X', '0x') }, 'INVALID_ENCODING:rawSignature');
  reject({ ...good, binding: '0x' + 'ab'.repeat(32) }, 'METADATA_MISMATCH:binding');
  reject({ ...good, commitment: '0x' + '00'.repeat(32) }, 'METADATA_MISMATCH:commitment');
  // A changed candidate binding (another request) rejects the same result.
  reject(good, 'METADATA_MISMATCH:requestId', candidateFromWire(wire(key), sha256));
  reject(good, 'METADATA_MISMATCH:binding', { ...candidate, binding: '0x' + 'ef'.repeat(32) });
  // Another key's point under this keyId.
  const stranger = softwareKey();
  reject({ ...good, publicPoint: bytesToHex(stranger.point) }, 'IDENTITY_MISMATCH');
  // A signature by another key over the same H fails verification.
  const foreign = resultFor({ ...stranger, keyId: candidate.keyId }, candidate);
  reject({ ...good, rawSignature: foreign.rawSignature, signerSignature: foreign.signerSignature }, 'INVALID_SIGNATURE');
});

test('no topic or URI persistence or logging', async () => {
  for (const name of ['../defi-v3-session.js', '../defi-v3-result.js']) {
    const text = readFileSync(new URL(name, import.meta.url), 'utf8');
    assert.doesNotMatch(text, /\b(?:console\s*\.|localStorage\b|sessionStorage\b|indexedDB\b|document\s*\.\s*cookie\b)/);
    assert.doesNotMatch(text, /\b(?:fetch|XMLHttpRequest|WebSocket|eval|Function)\s*\(/);
  }
  const key = softwareKey();
  const client = fakeClient(key, { respond: async () => { throw new Error(`relay wc:${TOPIC}@2?symKey=00`); } });
  const bridge = createV3BridgeSession({ client, config: config(), sha256 });
  const view = await bridge.connect();
  const serialized = JSON.stringify(view) + JSON.stringify(bridge.inspect()) + Object.keys(bridge).join(',');
  assert.ok(!serialized.includes(TOPIC), 'inspection never exposes the topic');
  assert.ok(!serialized.includes('wc:'));
  const error = await bridge.request(wire(key)).catch((e) => e);
  assert.equal(error.code, 'DELIVERY_UNKNOWN');
  assert.ok(!String(error.message).includes(TOPIC), 'errors carry fixed codes only');
  assert.ok(!JSON.stringify(bridge.inspect()).includes(TOPIC));
});
