import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildRequest, expectedFrom, issuedAtFor, transaction, validateContext, verifyResult } from '../safe-request-model.js';
import { VECTOR_CLOCK, contextFor, envelope, expected, freshSigner, resultFor, v } from './support/safe-fixtures.mjs';

const c = v.context.result;
const context = () => validateContext(structuredClone(c), expected);
const request = () => buildRequest(context(), expected, envelope.id, issuedAtFor(VECTOR_CLOCK));

test('Swift frozen context, Hybrid v2 envelope, hash, commitment preimage and signature agree', async () => {
  const r = request();
  assert.equal(r.envelope, v.request.envelope);
  assert.equal(r.safeTxHash, v.request.safeTxHash);
  assert.equal(transaction(expected).safeTxHash, v.request.safeTxHash);
  assert.equal(r.commitmentPreimage, v.request.commitmentPreimage);
  assert.equal(r.commitment, v.request.commitment);
  assert.equal(await verifyResult(v.result.result, r, context(), expected, v.request.now), v.result.result.signerSignature);
});

test('envelope addresses are lowercase hex even when context and inputs are EIP-55', () => {
  const e = JSON.parse(request().envelope);
  assert.match(c.signer, /[A-F]/);
  for (const value of [e.signer, e.body.safe, e.body.tx.to]) assert.match(value, /^0x[0-9a-f]{40}$/);
});

test('issuedAt is backdated 30 s and expiresAt stays issuedAt + 120', () => {
  assert.equal(issuedAtFor(1700000030), 1700000000);
  assert.equal(issuedAtFor(10), 0);
  const r = buildRequest(context(), expected, envelope.id, issuedAtFor(1700000100));
  assert.equal(r.issuedAt, 1700000070);
  assert.equal(r.expiresAt, 1700000190);
  const e = JSON.parse(r.envelope);
  assert.equal(e.issuedAt, '1700000070');
  assert.equal(e.expiresAt, '1700000190');
});

test('closed context rejects changed identity, policy, origin, limits, missing and extra keys', () => {
  for (const [key, value] of Object.entries({ origin: c.origin + '/', chainId: '1', version: '1',
    safe: expected.recipient, signer: expected.recipient, keyId: '00'.repeat(32), publicKey: '0x04' + '00'.repeat(64),
    binding: '0x00', codecId: 'other', purpose: 'other', maxValiditySeconds: 121, maxEnvelopeBytes: 65536, extra: true })) {
    assert.throws(() => validateContext({ ...c, [key]: value }, expected), key);
  }
  for (const key of Object.keys(c)) {
    const missing = { ...c };
    delete missing[key];
    assert.throws(() => validateContext(missing, expected), key);
  }
  assert.throws(() => validateContext(c, { ...expected, origin: 'https://example.com' }));
});

test('typed transfer rejects invalid amounts, nonce, addresses, IDs and time', () => {
  for (const patch of [{ value: '-1' }, { value: '01' }, { value: '1.0' }, { value: String(1n << 256n) },
    { nonce: 0 }, { nonce: '-1' }, { recipient: '0x' + '00'.repeat(20) }, { recipient: 'wrong' }]) {
    assert.throws(() => buildRequest(context(), { ...expected, ...patch }, envelope.id, 1700000000));
  }
  assert.throws(() => buildRequest(context(), expected, 'not-uuid', 1700000000));
  assert.throws(() => buildRequest(context(), expected, envelope.id.toUpperCase(), 1700000000));
  assert.throws(() => buildRequest(context(), expected, envelope.id, -1));
});

test('expected authority comes from the verified handoff plus independent canonical inputs', async () => {
  const key = await freshSigner();
  const input = { safe: ` ${c.safe.toLowerCase()} `, recipient: expected.recipient, value: '1000000000000000000', nonce: '7' };
  const e = expectedFrom(key.handoff, input);
  assert.deepEqual(e, { origin: 'https://p256-signer.tumf.dev', safe: c.safe, signer: key.handoff.expectedAddress,
    publicKey: key.publicKey, keyId: key.keyID, recipient: v.policy.recipient,
    value: '1000000000000000000', nonce: '7' });
  assert.ok(Object.isFrozen(e));
  for (const [field, patch] of [['safe', { safe: '0x' + '00'.repeat(20) }], ['safe', { safe: c.safe.replace('a', 'A') }],
    ['recipient', { recipient: '' }], ['value', { value: '1.5' }], ['value', { value: '00' }], ['value', { value: '0x1' }],
    ['nonce', { nonce: '-0' }], ['same', { safe: key.handoff.expectedAddress }]]) {
    assert.throws(() => expectedFrom(key.handoff, { ...input, ...patch }), (error) => error.field === field && error.message.length > 0);
  }
});

test('genuine fresh-key WebCrypto signature verifies; high-S, other key and wrong hash are rejected', async () => {
  const key = await freshSigner(), other = await freshSigner('0x' + '22'.repeat(32));
  const e = expectedFrom(key.handoff, { safe: c.safe, recipient: expected.recipient, value: '5', nonce: '3' });
  const ctx = validateContext(contextFor(e), e);
  const r = buildRequest(ctx, e, crypto.randomUUID(), issuedAtFor(1800000000));
  const now = 1800000000;
  const good = resultFor(r, ctx, await key.sign(r.safeTxHash));
  assert.equal(await verifyResult(good, r, ctx, e, now), good.signerSignature);
  const variants = {
    highS: resultFor(r, ctx, await key.sign(r.safeTxHash, { highS: true })),
    otherKey: resultFor(r, ctx, await other.sign(r.safeTxHash)),
    otherHash: resultFor(r, ctx, await key.sign(r.commitment)),
    doubleHashed: resultFor(r, ctx, await key.sign(new Uint8Array(await crypto.subtle.digest('SHA-256', Buffer.from(r.safeTxHash.slice(2), 'hex'))))),
  };
  for (const [name, result] of Object.entries(variants)) await assert.rejects(verifyResult(result, r, ctx, e, now), name);
});

test('result rejects every tampered field, missing or extra field, and stale or retargeted request', async () => {
  for (const [key, value] of Object.entries({ version: '1', requestId: '00000000-0000-0000-0000-000000000000',
    keyId: '00'.repeat(32), codecId: 'other', safeTxHash: '0x' + '00'.repeat(32), commitment: '0x' + '00'.repeat(32),
    binding: '0x' + '00'.repeat(32), publicPoint: '0x04' + '00'.repeat(64), rawSignature: '0x' + '00'.repeat(64),
    signerSignature: '0x' + '00'.repeat(96), extra: true })) {
    await assert.rejects(verifyResult({ ...v.result.result, [key]: value }, request(), context(), expected, v.request.now), key);
  }
  for (const key of Object.keys(v.result.result)) {
    const missing = { ...v.result.result };
    delete missing[key];
    await assert.rejects(verifyResult(missing, request(), context(), expected, v.request.now), key);
  }
  await assert.rejects(verifyResult(null, request(), context(), expected, v.request.now));
  await assert.rejects(verifyResult([v.result.result], request(), context(), expected, v.request.now));
  const raw = '0x17' + v.result.result.rawSignature.slice(4);
  // Valid-size raw and Hybrid encoding that agree with each other still must pass actual P-256 verification.
  const forged = { ...v.result.result, rawSignature: raw, signerSignature: v.result.result.signerSignature.slice(0, 66) + raw.slice(2) };
  await assert.rejects(verifyResult(forged, request(), context(), expected, v.request.now));
  for (const now of [1699999999, 1700000120]) await assert.rejects(verifyResult(v.result.result, request(), context(), expected, now));
  await assert.rejects(verifyResult(v.result.result, { ...request(), envelope: '{}' }, context(), expected, v.request.now));
  // Mutated key, binding or transaction after the request was built: the same signature no longer matches.
  for (const patch of [{ value: '2' }, { nonce: '1' }, { recipient: c.safe }]) {
    await assert.rejects(verifyResult(v.result.result, request(), context(), { ...expected, ...patch }, v.request.now));
  }
  const rebound = validateContext({ ...c, binding: '0x' + '01'.repeat(32) }, expected);
  await assert.rejects(verifyResult(v.result.result, request(), rebound, expected, v.request.now));
});
