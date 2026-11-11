// Unit tests of key-model.js: closed native anchors, real P-256 point checks, the exact compiler self-call, H,
// userOpHash, commitment and envelope against frozen Swift vectors, closed native context/result with real WebCrypto
// verification, exact fee/cost arithmetic and the closed raw attempt v1/v2 schemas of key-attempt-store.js (pure
// parser/serializer). Pure functions with software keys; no network, storage or clock.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import ethers from '../vendor/ethers.js';
import * as M from '../key-model.js';
import { DB_VERSION, KeyAttemptStore, MAX_RECORD_BYTES, parseAttempt, serializeAttempt } from '../key-attempt-store.js';
import { K1, K2, anchorText, bareKeyText, contextWire, nativeSign, highS, signRaw, softwareKey } from './support/key-fixtures.mjs';

const U = ethers.utils;
const vectors = JSON.parse(readFileSync(new URL('./fixtures/key-swift-vectors.json', import.meta.url)));
const k1 = softwareKey(K1), k2 = softwareKey(K2);
const SIGNER = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const signerLower = SIGNER.toLowerCase();
const dec = (h) => BigInt(h).toString();
const opOf = (v) => ({ sender: v.sender, nonce: dec(v.nonce), initCode: v.initCode, callData: v.callData,
  accountGasLimits: v.accountGasLimits, preVerificationGas: dec(v.preVerificationGas), gasFees: v.gasFees,
  paymasterAndData: v.paymasterAndData, signature: '0x' });
const code = (fn) => { try { fn(); } catch (e) { return e.code; } return 'accepted'; };

test('authority and bare-key anchors: exact native spelling accepted, every deviation refused', () => {
  const a = M.parseAuthority(anchorText(SIGNER, k1));
  assert.deepEqual({ ...a }, { kind: 'authority', signer: SIGNER, signerAddress: signerLower, publicKey: k1.publicKey,
    keyId: k1.keyId });
  assert.equal(M.parseBareKey(bareKeyText(k2)).keyId, k2.keyId);
  const base = JSON.parse(anchorText(SIGNER, k1));
  const text = (o) => JSON.stringify(o);
  const cases = {
    kind: text({ ...base, kind: 'p256-public-key' }),
    fields: text({ ...base, extra: 'x' }),
    missing: text(Object.fromEntries(Object.entries(base).filter(([k]) => k !== 'keyId'))),
    version: text({ ...base, v: '2' }),
    versionNumber: text({ ...base, v: 1 }).replace('"v":1', '"v":1'),
    // enable-multichain-operations: 1, 8453 and 84532 are closed chains now; an unlisted or noncanonical ID is refused.
    chain: text({ ...base, chainId: '10' }),
    chainPadded: text({ ...base, chainId: '0137' }),
    chainHex: text({ ...base, chainId: '0x89' }),
    lowerSigner: text({ ...base, signer: signerLower }),
    badChecksum: text({ ...base, signer: SIGNER.replace('a', 'A') }),
    zeroSigner: text({ ...base, signer: '0x0000000000000000000000000000000000000000' }),
    upperPoint: text({ ...base, publicKey: base.publicKey.toUpperCase().replace('0X', '0x') }),
    noPrefix: text({ ...base, publicKey: base.publicKey.slice(2) }),
    offCurve: text({ ...base, publicKey: base.publicKey.slice(0, -1) + (base.publicKey.at(-1) === '0' ? '1' : '0') }),
    fieldBound: text({ ...base, publicKey: '0x04' + 'ff'.repeat(64) }),
    keyIdMismatch: text({ ...base, keyId: k2.keyId }),
    keyIdPrefix: text({ ...base, keyId: '0x' + base.keyId }),
    duplicate: text(base).replace('}', `,"keyId":"${base.keyId}"}`),
    escapedDuplicate: text(base).replace('}', `,"key\\u0049d":"${base.keyId}"}`),
    nested: text({ ...base, chainId: { v: '137' } }),
    array: `[${text(base)}]`,
    trailing: text(base) + 'x',
    deployment: text({ chainId: 137, expectedAddress: SIGNER, keyID: k1.keyId, publicKey: k1.publicKey,
      recipe: 'polygon-137/hybrid-delegator-1.3.0/erc1967-create2/v1', salt: '0x' + '00'.repeat(32), version: 1 }),
    oversize: text({ ...base, kind: base.kind }).padEnd(4097, ' '),
    loneSurrogate: text(base).replace('"v":"1"', '"v":"1\\ud800"'),
  };
  const results = Object.fromEntries(Object.entries(cases).map(([k, t]) => [k, code(() => M.parseAuthority(t))]));
  for (const [name, result] of Object.entries(results)) assert.notEqual(result, 'accepted', name);
  assert.equal(results.duplicate, 'duplicate');
  assert.equal(results.escapedDuplicate, 'duplicate');
  assert.equal(results.kind, 'kind');
  assert.equal(results.deployment, 'type');
  // Opposite kinds are never normalized into each other.
  assert.equal(code(() => M.parseBareKey(anchorText(SIGNER, k1))), 'kind');
  assert.equal(code(() => M.parseAuthority(bareKeyText(k1))), 'kind');
  assert.equal(code(() => M.parseBareKey(bareKeyText(k1).replace('}', ',"chainId":"137"}'))), 'fields');
});

test('P-256 points: on-curve, below the field prime, uncompressed lowercase only', () => {
  assert.equal(M.isPoint(k1.publicKey), true);
  const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const x = BigInt('0x' + k1.publicKey.slice(4, 68));
  assert.equal(M.isPoint('0x04' + (x + p).toString(16).padStart(64, '0').slice(-64) + k1.publicKey.slice(68)), false);
  assert.equal(M.isPoint('0x02' + k1.publicKey.slice(4, 68)), false);
  assert.equal(M.isPoint('0x04' + '00'.repeat(64)), false);
});

test('compiler self-call, H and native gas fields match frozen Swift HybridKeyChangeCompiler vectors', () => {
  assert.ok(vectors.compiler.length >= 4);
  for (const v of vectors.compiler) {
    const point = '0x04' + v.x.slice(2) + v.y.slice(2);
    const inner = v.action === 'add' ? M.addKeyCall(point, v.keyID) : M.removeKeyCall(v.keyID);
    assert.equal(M.executeCall(v.sender, inner), v.callData, v.name);
    const op = opOf(v);
    assert.equal(M.typedDataHash(op), v.typedDataHash, v.name);
    assert.notEqual(M.userOpHash(op), v.typedDataHash, v.name);
    assert.equal(M.checkOperation(op), op);
  }
  assert.equal(M.SELECTORS.execute, '0x5c1c6dcd');
  assert.equal(M.SELECTORS.addKey, '0xc8561e73');
});

/** The same preimage with keyID as 32 decoded bytes instead of 64 ASCII bytes (the rejected encoding). */
function decodedKeyIdCommitment({ id, keyId, binding, issuedAt, expiresAt, operation, typedHash }, ascii = false) {
  const w = (v, n = 32) => U.arrayify(M.word(v, n));
  const fields = [U.toUtf8Bytes('1'), U.toUtf8Bytes(M.PURPOSE), U.toUtf8Bytes(M.CODEC_ID),
    U.arrayify('0x' + id.replaceAll('-', '')), ascii ? U.toUtf8Bytes(keyId) : U.arrayify('0x' + keyId), U.arrayify(binding), w(issuedAt, 8),
    w(expiresAt, 8), w(137), U.arrayify(M.ENTRYPOINT), U.arrayify(operation.sender), U.arrayify(operation.sender),
    w(operation.nonce), U.arrayify('0x'), U.arrayify(operation.callData), U.arrayify(operation.accountGasLimits),
    w(operation.preVerificationGas), U.arrayify(operation.gasFees), U.arrayify('0x'), U.arrayify('0x'),
    U.arrayify(typedHash)];
  return U.sha256(U.concat([U.toUtf8Bytes(M.COMMITMENT_DOMAIN), ...fields.flatMap((f) => [w(f.length, 4), f])]));
}

test('commitment matches frozen Swift ledger rows; keyID is ASCII, not decoded hex', () => {
  const f = vectors.approvalFixture;
  for (const r of vectors.approval) {
    const op = opOf(r), h = M.typedDataHash(op);
    assert.equal(h, r.typedDataHash);
    const args = { id: r.requestID, keyId: r.keyID, binding: f.binding, issuedAt: f.issuedAt, expiresAt: f.expiresAt,
      operation: op, typedHash: h };
    assert.equal(M.commitment(args), r.commitment, r.name);
    // Negative control: a hex-decoded keyID, a shifted time or another H must not reproduce Swift.
    assert.notEqual(decodedKeyIdCommitment(args), r.commitment);
    assert.equal(decodedKeyIdCommitment(args, true), r.commitment, 'control preimage is otherwise identical');
    assert.notEqual(M.commitment({ ...args, expiresAt: f.expiresAt + 1 }), r.commitment);
    assert.notEqual(M.commitment({ ...args, typedHash: M.userOpHash(op) }), r.commitment);
  }
});

test('planChange: add/remove maps, duplicate by ID or point, 64-key limit, final key, unknown key', () => {
  const fees = { maxFee: 10n ** 9n, priorityFee: 10n ** 9n };
  const keys = [k1];
  const add = M.planChange({ signer: signerLower, nonce: 3n, keys, change: { kind: 'add', key: k2 }, fees });
  assert.deepEqual(add.after.map((k) => k.keyId), [k1.keyId, k2.keyId].sort());
  assert.equal(add.operation.nonce, '3');
  assert.equal(add.operation.accountGasLimits, M.packHigh(700000n, 300000n));
  assert.equal(add.operation.preVerificationGas, '60000');
  assert.equal(add.operation.gasFees, M.packHigh(fees.priorityFee, fees.maxFee));
  const remove = M.planChange({ signer: signerLower, nonce: 4n, keys: add.after, change: { kind: 'remove', keyId: k1.keyId }, fees });
  assert.deepEqual(remove.after.map((k) => k.keyId), [k2.keyId]);
  const plan = (k, change) => code(() => M.planChange({ signer: signerLower, nonce: 0n, keys: k, change, fees }));
  assert.equal(plan(keys, { kind: 'add', key: k1 }), 'duplicate');
  assert.equal(plan(keys, { kind: 'add', key: { keyId: k2.keyId, publicKey: k1.publicKey } }), 'curve');
  assert.equal(plan(keys, { kind: 'remove', keyId: k1.keyId }), 'last');
  assert.equal(plan(keys, { kind: 'remove', keyId: k2.keyId }), 'unknown');
  const many = Array.from({ length: 64 }, (_, i) => softwareKey(BigInt(i + 1000)));
  assert.equal(plan(many, { kind: 'add', key: k2 }), 'limit');
  assert.equal(plan([...many.slice(0, 63)], { kind: 'add', key: k2 }), 'accepted');
});

test('fees: Gwei syntax, exact wei, uint120 AA94 bound, priority <= max, native cap; no outer fee helper', () => {
  assert.equal(M.parseGwei('1'), 10n ** 9n);
  assert.equal(M.parseGwei('0.000000001'), 1n);
  assert.equal(M.parseGwei('12.5'), 12500000000n);
  for (const [text, expected] of [['', 'blank'], ['01', 'format'], ['1.', 'format'], ['.5', 'format'],
    ['1e9', 'format'], ['-1', 'format'], ['1,000', 'format'], ['1.0000000001', 'format'], [' 1', 'format'],
    ['１', 'format']]) assert.equal(code(() => M.parseGwei(text)), expected, text);
  const maxGwei = (M.UINT120_MAX / M.GWEI).toString();
  assert.equal(code(() => M.innerFees(maxGwei, '0')), 'accepted');
  assert.equal(code(() => M.innerFees((M.UINT120_MAX / M.GWEI + 1n).toString(), '0')), 'bounds');
  assert.equal(code(() => M.innerFees('0', '0')), 'bounds');
  assert.equal(code(() => M.innerFees('1', '2')), 'bounds');
  assert.equal(code(() => M.innerFees('2', '1', 10n ** 9n)), 'bounds');
  assert.equal(code(() => M.innerFees('', '1')), 'blank');
  // The wallet owns outer gas/fees: the model has no outer fee parser, maximum or balance comparison.
  assert.equal(M.outerFees, undefined);
  assert.equal(M.outerMaximum, undefined);
  const p = M.prefund(10n ** 9n, 10n ** 15n);
  assert.equal(p.required, 1060000n * 10n ** 9n);
  assert.equal(p.shortfall, p.required - 10n ** 15n);
  assert.equal(M.prefund(10n ** 9n, p.required).shortfall, 0n);
  assert.equal(code(() => M.prefund(M.UINT256_MAX, 0n)), 'overflow');
  assert.equal(M.formatPol(1500000000000000000n), '1.5');
});

async function signedFixture() {
  const binding = '0x' + 'ab'.repeat(32);
  const wire = contextWire({ signer: signerLower, key: k1, binding, chain: { keys: [k1], nonce: 7n, blockNumber: 100n,
    blockHash: '0x' + '12'.repeat(32) } });
  const anchor = M.parseAuthority(anchorText(SIGNER, k1));
  const context = M.validateNativeContext(wire, anchor);
  const plan = M.planChange({ signer: signerLower, nonce: 7n, keys: context.keys, change: { kind: 'add', key: k2 },
    fees: { maxFee: 10n ** 9n, priorityFee: 1n } });
  const request = M.buildRequest({ context, operation: plan.operation, id: crypto.randomUUID(), issuedAt: M.issuedAtFor(1800000000) });
  const result = await nativeSign({ envelope: request.envelope, key: k1, binding });
  return { wire, anchor, context, request, result, binding };
}

test('closed native context: exact fields and types, pinned constants, sorted complete keys with the anchor', async () => {
  const { wire, anchor } = await signedFixture();
  const mutations = {
    extra: (c) => { c.note = 'x'; }, missing: (c) => { delete c.owner; }, versionString: (c) => { c.version = '1'; },
    origin: (c) => { c.origin = 'https://evil.example'; }, owner: (c) => { c.owner = '0x' + '11'.repeat(20); },
    implementation: (c) => { c.implementation = '0x' + '22'.repeat(20); }, entryPoint: (c) => { c.entryPoint = M.ZERO_ADDRESS; },
    codeHash: (c) => { c.implementationCodeHash = '0x' + '00'.repeat(32); }, zeroBinding: (c) => { c.binding = '0x' + '00'.repeat(32); },
    signer: (c) => { c.signer = '0x' + '33'.repeat(20); }, keyId: (c) => { c.keyId = k2.keyId; },
    keysMissingAnchor: (c) => { c.keys = [{ keyId: k2.keyId, publicKey: k2.publicKey }]; },
    keysExtraField: (c) => { c.keys[0].note = 'x'; }, maxValidity: (c) => { c.maxValiditySeconds = 60; },
    nonceNumber: (c) => { c.nonce = 7; }, nonceLeadingZero: (c) => { c.nonce = '07'; },
    unsorted: (c) => { c.keys = [{ keyId: k2.keyId, publicKey: k2.publicKey }, ...c.keys].reverse(); },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const c = structuredClone(wire);
    mutate(c);
    if (name === 'unsorted') c.keys.sort((a, b) => (a.keyId < b.keyId ? 1 : -1));
    assert.notEqual(code(() => M.validateNativeContext(c, anchor)), 'accepted', name);
  }
  const ok = M.validateNativeContext(wire, anchor);
  assert.equal(ok.nonce, 7n);
  const web = { signer: signerLower, keys: ok.keys, nonce: 7n, block: { number: 110n } };
  assert.equal(M.agree(ok, web), true);
  assert.equal(code(() => M.agree(ok, { ...web, block: { number: 131n } })), 'changed');
  assert.equal(code(() => M.agree(ok, { ...web, nonce: 8n })), 'changed');
  assert.equal(code(() => M.agree({ ...ok, maxGasUnits: 1059999n }, web)), 'policy');
});

test('result verification: real WebCrypto over raw H, closed fields, low-S, keyID prefix and expiry', async () => {
  const { context, request, result } = await signedFixture();
  const now = request.issuedAt + 10;
  assert.equal(await M.verifyResult(result, request, context, now), result.signerSignature);
  const reject = async (r, at = now) => {
    try { await M.verifyResult(r, request, context, at); return 'accepted'; } catch (e) { return e.code; }
  };
  const doubleHashed = await signRaw(k1, U.sha256(request.typedDataHash));
  const wrongKey = await signRaw(k2, request.typedDataHash);
  const cases = {
    highS: { ...result, rawSignature: highS(result.rawSignature), signerSignature: U.hexConcat([M.keyIdHash(k1.keyId), highS(result.rawSignature)]) },
    doubleHashed: { ...result, rawSignature: doubleHashed, signerSignature: U.hexConcat([M.keyIdHash(k1.keyId), doubleHashed]) },
    wrongKey: { ...result, rawSignature: wrongKey, signerSignature: U.hexConcat([M.keyIdHash(k1.keyId), wrongKey]) },
    prefix: { ...result, signerSignature: U.hexConcat([M.keyIdHash(k2.keyId), result.rawSignature]) },
    commitment: { ...result, commitment: '0x' + '00'.repeat(32) },
    h: { ...result, typedDataHash: request.userOpHash }, nonce: { ...result, nonce: '8' },
    binding: { ...result, binding: '0x' + 'cd'.repeat(32) }, extra: { ...result, note: 'x' },
    version: { ...result, version: '1' }, requestId: { ...result, requestId: crypto.randomUUID() },
    zeroR: { ...result, rawSignature: '0x' + '00'.repeat(32) + result.rawSignature.slice(66) },
  };
  for (const [name, r] of Object.entries(cases)) assert.notEqual(await reject(r), 'accepted', name);
  assert.equal(await reject(result, request.expiresAt), 'expired');
  assert.equal(await reject(result, request.issuedAt - 1), 'expired');
  // The envelope is the exact native closed schema with string-valued v.
  const e = JSON.parse(request.envelope);
  assert.deepEqual(Object.keys(e), ['v', 'id', 'purpose', 'codecId', 'keyId', 'binding', 'issuedAt', 'expiresAt',
    'chainId', 'entryPoint', 'signer', 'body']);
  assert.equal(e.v, '1');
  assert.deepEqual(Object.keys(e.body), M.BODY_KEYS);
  assert.equal(Number(e.expiresAt) - Number(e.issuedAt), 120);
  assert.equal(M.issuedAtFor(10), 1);
});

test('handleOps calldata encodes exactly one signed operation and the beneficiary', async () => {
  const { request, result } = await signedFixture();
  const data = M.handleOpsCall(request.operation, result.signerSignature, '0x' + '44'.repeat(20));
  const iface = new U.Interface(['function handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)']);
  const [ops, beneficiary] = iface.decodeFunctionData('handleOps', data);
  assert.equal(ops.length, 1);
  assert.equal(ops[0][8], result.signerSignature);
  assert.equal(beneficiary.toLowerCase(), '0x' + '44'.repeat(20));
  assert.equal(data.slice(0, 10), M.SELECTORS.handleOps);
});

// ---------------------------------------------------------------------------------------------------------------
// Closed raw attempt v1/v2 schemas

const V1 = JSON.parse(readFileSync(new URL('./fixtures/key-attempt-v1.json', import.meta.url))).records;
const CEILINGS = ['outerGasLimit', 'outerMaxFeePerGas', 'outerMaxPriorityFeePerGas'];
const corrupt = (raw) => { try { parseAttempt(raw); return 'accepted'; } catch (e) { return e.code; } };
/** A v2 record from a v1 one: exactly the three ceilings deleted and integer version 2 (never a production path). */
const asV2 = (raw) => {
  const r = JSON.parse(raw);
  for (const key of CEILINGS) delete r[key];
  return { ...r, version: 2 };
};
const P_ONE_GWEI = 1060000n * 10n ** 9n;

test('attempt v1 compatibility: frozen base bytes round-trip exactly; base rejections stay rejected', () => {
  assert.ok(Object.keys(V1).length >= 7);
  for (const [name, raw] of Object.entries(V1)) {
    const record = parseAttempt(raw);
    assert.equal(record.version, 1, name);
    assert.equal(serializeAttempt(JSON.parse(raw)), raw, name);
    assert.deepEqual(Object.keys(record).slice(17, 20), CEILINGS, name);
  }
  const raw = V1.succeeded;
  const cases = {
    floor: raw.replace('"outerGasLimit":"2200000"', '"outerGasLimit":"1199999"'),
    tipAboveMax: raw.replace('"outerMaxPriorityFeePerGas":"1000000000"', '"outerMaxPriorityFeePerGas":"1000000001"'),
    zeroMax: raw.replace('"outerMaxFeePerGas":"1000000000"', '"outerMaxFeePerGas":"0"'),
    missingCeiling: raw.replace('"outerGasLimit":"2200000",', ''),
    stringVersion: raw.replace('"version":1', '"version":"1"'),
    floatVersion: raw.replace('"version":1', '"version":1.0'),
    extra: raw.replace('"version":1,', '"version":1,"note":"x",'),
    leadingZero: raw.replace('"outerGasLimit":"2200000"', '"outerGasLimit":"02200000"'),
  };
  for (const [name, bytes] of Object.entries(cases)) {
    assert.notEqual(bytes, raw, name);
    assert.equal(corrupt(bytes), 'corrupt', name);
  }
  // v2-only stricter evidence never retroactively changes v1: an over-P inner cost is unchanged legacy data.
  const over = JSON.parse(V1.succeeded);
  over.outcome.actualGasCostWei = (P_ONE_GWEI + 1n).toString();
  assert.equal(parseAttempt(serializeAttempt(over)).version, 1);
});

test('attempt v2 closed schema: exact order, no outer ceilings, required pending hint, mixed/unknown versions refused', () => {
  for (const [name, raw] of Object.entries(V1)) {
    const text = serializeAttempt(asV2(raw));
    const record = parseAttempt(text);
    assert.equal(record.version, 2, name);
    assert.equal(serializeAttempt(JSON.parse(text)), text, name);
    assert.deepEqual(Object.keys(record).slice(0, 18), ['version', 'attemptId', 'status', 'chainId', 'entryPoint',
      'signer', 'signerNonce', 'authorizerKeyId', 'typedDataHash', 'userOpHash', 'calldataSHA256', 'operation',
      'beforeKeys', 'expectedAfterKeys', 'walletAccount', 'beneficiary', 'walletPendingNonce', 'sendStartedAt'], name);
    for (const key of CEILINGS) assert.ok(!text.includes(key), `${name} ${key}`);
  }
  const base = serializeAttempt(asV2(V1.succeeded));
  const v2 = JSON.parse(base);
  const reject = (label, value) => assert.equal(code(() => serializeAttempt(value)), 'corrupt', label);
  for (const key of CEILINGS) {
    reject(`mixed ${key}`, { ...v2, [key]: '2200000' });
    assert.equal(corrupt(base.replace('"sendStartedAt"', `"${key}":"2200000","sendStartedAt"`)), 'corrupt', key);
  }
  for (const version of [3, 0, '2', null, 2.5, undefined]) {
    const r = { ...v2, version };
    if (version === undefined) delete r.version;
    reject(`version ${version}`, r);
  }
  assert.equal(corrupt(base.replace('"version":2', '"version":"2"')), 'corrupt');
  assert.equal(corrupt(base.replace('"version":2,', '')), 'corrupt');
  // Required non-null pending hint; no gas/nonce/estimate substitute member.
  const { walletPendingNonce: _hint, ...noHint } = v2;
  reject('missing pending hint', noHint);
  reject('null pending hint', { ...v2, walletPendingNonce: null });
  reject('pending hint overflow', { ...v2, walletPendingNonce: (M.UINT256_MAX + 1n).toString() });
  reject('pending hint leading zero', { ...v2, walletPendingNonce: '00' });
  assert.equal(parseAttempt(serializeAttempt({ ...v2, walletPendingNonce: '0' })).walletPendingNonce, '0');
  for (const extra of ['gas', 'nonce', 'estimatedCost', 'outerMaxFee']) reject(`substitute ${extra}`, { ...v2, [extra]: '1' });
  // Canonical bytes: duplicate decoded names, reordering, nested extras, nulls, overflow and size.
  const status = `"status":"${v2.status}"`;
  assert.equal(corrupt(base.replace(status, `${status},${status}`)), 'corrupt', 'duplicate');
  assert.equal(corrupt(base.replace(`"attemptId":"${v2.attemptId}",${status}`, `${status},"attemptId":"${v2.attemptId}"`)),
    'corrupt', 'reordered');
  assert.equal(corrupt(base.replace('"initCode":"0x"', '"initCode":"0x","note":"x"')), 'corrupt', 'nested operation');
  reject('receipt extra', { ...v2, receipt: { ...v2.receipt, logs: [] } });
  reject('outcome extra', { ...v2, outcome: { ...v2.outcome, net: '1' } });
  reject('key extra', { ...v2, beforeKeys: [{ ...v2.beforeKeys[0], note: 'x' }] });
  reject('null transactionHash', { ...v2, transactionHash: null });
  reject('null actualWalletNonce', { ...v2, actualWalletNonce: null });
  reject('actual nonce overflow', { ...v2, actualWalletNonce: (M.UINT256_MAX + 1n).toString() });
  reject('null receipt', { ...v2, receipt: null });
  assert.equal(corrupt(base + ' '.repeat(MAX_RECORD_BYTES)), 'corrupt', 'oversize');
  // Unchanged common operation/key-map/hash relationships.
  reject('typedDataHash', { ...v2, typedDataHash: '0x' + '00'.repeat(32) });
  reject('userOpHash', { ...v2, userOpHash: v2.typedDataHash });
  reject('callData', { ...v2, operation: { ...v2.operation, callData: v2.operation.callData.slice(0, -2) + '01' } });
  reject('signature stored', { ...v2, operation: { ...v2.operation, signature: '0x' + '11'.repeat(96) } });
  reject('after keys', { ...v2, expectedAfterKeys: v2.beforeKeys });
  reject('beneficiary', { ...v2, beneficiary: '0x' + '44'.repeat(20) });
  // Outcome shape and the signed-inner cost bound P = 1060000 x inner maxFee.
  const { actualGasCostWei: _cost, ...noInner } = v2.outcome;
  reject('succeeded without inner cost', { ...v2, outcome: noInner });
  reject('status/outcome mismatch', { ...v2, status: 'innerFailed' });
  const atP = { ...v2, outcome: { ...v2.outcome, actualGasCostWei: P_ONE_GWEI.toString() } };
  assert.equal(parseAttempt(serializeAttempt(atP)).outcome.actualGasCostWei, P_ONE_GWEI.toString());
  reject('above signed inner P', { ...v2, outcome: { ...v2.outcome, actualGasCostWei: (P_ONE_GWEI + 1n).toString() } });
  reject('reserved with hash', { ...asV2(V1.reserved), transactionHash: v2.transactionHash });
});

test('attempt wrapper stays database version 1 for both raw versions; no upgrade path', () => {
  assert.equal(DB_VERSION, 1);
  const store = new KeyAttemptStore({ indexedDB: null });
  const v2 = serializeAttempt(asV2(V1.hashKnown));
  for (const raw of [V1.hashKnown, v2]) {
    assert.deepEqual({ ...store.check({ version: 1, revision: 3, raw }) }, { version: 1, revision: 3, raw });
    assert.equal(code(() => store.check({ version: 2, revision: 3, raw })), 'corrupt');
  }
  assert.equal(code(() => store.check({ version: 1, revision: 3, raw: v2.replace('"version":2', '"version":3') })), 'corrupt');
});

// add-signer-chain-qr-authorizer-ui: the iPhone 「署名者を追加」 handoff (Swift vector KeyChangeHandoffTests).
const SWIFT_KEY_CHANGE_FRAGMENT = '#key-change=eyJ2IjoiMSIsImtpbmQiOiJoeWJyaWQta2V5LWF1dGhvcml0eSIsImNoYWluSWQiOiIxMzciLCJzaWduZXIiOiIweEExMWNlMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMGExMWMiLCJwdWJsaWNLZXkiOiIweDA0NmIxN2QxZjJlMTJjNDI0N2Y4YmNlNmU1NjNhNDQwZjI3NzAzN2Q4MTJkZWIzM2EwZjRhMTM5NDVkODk4YzI5NjRmZTM0MmUyZmUxYTdmOWI4ZWU3ZWI0YTdjMGY5ZTE2MmJjZTMzNTc2YjMxNWVjZWNiYjY0MDY4MzdiZjUxZjUiLCJrZXlJZCI6IjY5OGJlYTYzZGM0NGEzNDQ2NjNmZjE0MjlhZWExMDg0MmRmMjdiNmI5OTFlZjI1ODY2YjJjNmMwMmNkY2M1YmUifQp7InYiOiIxIiwia2luZCI6InAyNTYtcHVibGljLWtleSIsInB1YmxpY0tleSI6IjB4MDQ3Y2YyN2IxODhkMDM0ZjdlOGE1MjM4MDMwNGI1MWFjM2MwODk2OWUyNzdmMjFiMzVhNjBiNDhmYzQ3NjY5OTc4MDc3NzU1MTBkYjhlZDA0MDI5M2Q5YWM2OWY3NDMwZGJiYTdkYWRlNjNjZTk4MjI5OWUwNGI3OWQyMjc4NzNkMSIsImtleUlkIjoiYTlmMzAwZWI1OTYwZTg5MTMzYWY3MzYyMDExYTFlMjZmMGUyZWEyZTM2ZGM0MDJhMDRhZjZjMTkyYjg5MWE4YyJ9';

test('key-change fragment: the Swift vector prefills both public texts; every deviation refused', () => {
  const prefill = M.parseKeyChangeFragment(SWIFT_KEY_CHANGE_FRAGMENT);
  assert.equal(prefill.authority.signer, '0xA11ce0000000000000000000000000000000a11c');
  assert.equal(prefill.authority.keyId, '698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be');
  assert.equal(prefill.key.keyId, 'a9f300eb5960e89133af7362011a1e26f0e2ea2e36dc402a04af6c192b891a8c');
  assert.equal(M.parseAuthority(prefill.authorityText).signer, prefill.authority.signer);
  assert.equal(M.parseBareKey(prefill.keyText).keyId, prefill.key.keyId);
  const b64 = (text) => Buffer.from(text, 'utf8').toString('base64url');
  const [authority, key] = [prefill.authorityText, prefill.keyText];
  for (const bad of [SWIFT_KEY_CHANGE_FRAGMENT.slice(1), '#registration=' + b64(authority + '\n' + key),
    '#key-change=', '#key-change=' + b64(authority), '#key-change=' + b64(authority + '\n' + key + '\n'),
    '#key-change=' + b64(key + '\n' + authority), '#key-change=' + b64(authority + '\n' + authority),
    '#key-change=' + b64(authority + '\r\n' + key), '#key-change=' + b64(authority + '\n' + key) + '=',
    '#key-change=' + b64(authority + '\n' + key) + '&x=1',
    // enable-multichain-operations: a Base anchor is valid now (its own chain); an unlisted chain still is not.
    '#key-change=' + b64(authority.replace('"137"', '"10"') + '\n' + key),
    '#key-change=' + b64(authority + '\n' + key.replace('p256-public-key', 'hybrid-key-authority')),
    '#key-change=' + 'A'.repeat(6000)]) {
    assert.equal(code(() => M.parseKeyChangeFragment(bad)) === 'accepted', false, bad.slice(0, 60));
  }
  const base = M.parseKeyChangeFragment('#key-change=' + b64(authority.replace('"137"', '"8453"') + '\n' + key));
  assert.equal(M.anchorChain(base.authority).id, 8453, 'the prefilled anchor names its own closed chain');
  // The authority's own key is never offered as the key to add.
  const own = JSON.stringify({ v: '1', kind: 'p256-public-key', publicKey: prefill.authority.publicKey,
    keyId: prefill.authority.keyId });
  assert.notEqual(code(() => M.parseKeyChangeFragment('#key-change=' + b64(authority + '\n' + own))), 'accepted');
});
