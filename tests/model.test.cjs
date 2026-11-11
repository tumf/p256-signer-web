'use strict';
// Production model.js against the independent oracle (tests/support/oracle.cjs), the ethers 5.4.0 vectors
// in tests/fixtures/registry-vectors.json and fresh Swift RegistrationHandoff output.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const oracle = require('./support/oracle.cjs');
const { FakeChain, PROXY, GWEI } = require('./support/fake-chain.cjs');

const root = path.resolve(__dirname, '..');
const vectors = JSON.parse(fs.readFileSync(path.join(root, 'tests/fixtures/registry-vectors.json'), 'utf8'));
const load = () => import('../model.js');

function handoffFor(row) {
  return { version: 1, recipe: vectors.recipe, chainId: 137, publicKey: row.publicPoint, keyID: row.keyID,
    salt: row.salt, expectedAddress: row.address };
}
const canonical = (h) => JSON.stringify(Object.fromEntries(Object.keys(h).sort().map((k) => [k, h[k]])));
const b64 = (text) => Buffer.from(text).toString('base64url');
const pattern = vectors.vectors.find((row) => row.name === 'd1-pattern');

test('every oracle vector round-trips to exact initializer, creation, address and deploy calldata', async () => {
  const m = await load();
  for (const row of vectors.vectors) {
    const plan = m.buildPlan(m.parseHandoff(canonical(handoffFor(row))));
    assert.equal(plan.address, row.address, row.name);
    assert.equal(plan.initializer, row.initializer);
    assert.equal(plan.creation, row.creation);
    assert.equal(plan.creationHash, row.creationHash);
    const independent = oracle.derive(row.publicPoint, row.salt, PROXY);
    assert.equal(plan.transaction.data, independent.calldata);
    const decoded = oracle.decodeDeploy(plan.transaction.data, PROXY);
    assert.ok(decoded.exact);
    assert.equal(decoded.salt, row.salt);
    assert.equal(decoded.owner, '0x' + '00'.repeat(20));
    assert.equal(decoded.keyCount, 1);
    assert.equal(decoded.keyID, row.keyID);
    assert.equal(decoded.implementation, m.IMPLEMENTATION);
    assert.deepEqual(plan.transaction, { to: m.FACTORY, data: plan.transaction.data, value: '0x0' });
  }
});

test('fresh Swift RegistrationHandoff output decodes to the same real calldata and address', async (t) => {
  const capture = process.env.REGISTRATION_HANDOFF_CAPTURE;
  if (!capture) return t.skip('REGISTRATION_HANDOFF_CAPTURE not provided (the registration-web gate always sets it)');
  const m = await load();
  const output = JSON.parse(fs.readFileSync(capture, 'utf8'));
  assert.equal(output.source, 'RegistrationHandoffTests');
  assert.equal(output.rows.length, 2);
  let nonzero = 0;
  for (const row of output.rows) {
    const url = new URL(row.url);
    assert.equal(url.origin + url.pathname, 'https://p256-signer.tumf.dev/');
    assert.equal(url.search, '');
    const fromFragment = m.parseFragment(url.hash);
    const fromJSON = m.parseHandoff(row.json);
    assert.deepEqual(fromFragment, fromJSON);
    assert.equal(canonical(fromJSON), row.json, 'Swift emits compact sorted-key JSON');
    const plan = m.buildPlan(fromJSON);
    const independent = oracle.derive(fromJSON.publicKey, fromJSON.salt, PROXY);
    assert.equal(plan.address, fromJSON.expectedAddress);
    assert.equal(independent.address, fromJSON.expectedAddress);
    assert.equal(plan.transaction.data, independent.calldata);
    if (/[1-9a-f]/.test(fromJSON.salt.slice(2))) nonzero++;
  }
  assert.equal(nonzero, 1, 'the persisted random-salt row is exported with its own salt');
});

test('fragment import: canonical base64url only, bounded before decoding', async () => {
  const m = await load();
  const json = canonical(handoffFor(pattern));
  assert.equal(m.parseFragment('#registration=' + b64(json)).salt, pattern.salt);
  const cases = {
    padded: ['#registration=' + b64(json) + '=', 'fragment'],
    standardAlphabet: ['#registration=' + Buffer.from(json + '??>').toString('base64'), 'encoding'],
    alphabet: ['#registration=' + b64(json) + '+', 'encoding'],
    extraParam: ['#registration=' + b64(json) + '&x=1', 'fragment'],
    otherName: ['#deploy=' + b64(json), 'fragment'],
    oversize: ['#registration=' + 'A'.repeat(5463), 'oversize'],
    invalidUTF8: ['#registration=' + Buffer.from([0x7b, 0xff, 0x7d]).toString('base64url'), 'encoding'],
    lengthMod1: ['#registration=A', 'encoding'],
  };
  for (const [name, [hash, code]] of Object.entries(cases)) {
    assert.throws(() => m.parseFragment(hash), (e) => e.code === code, name);
  }
  // Nonzero trailing bits: payload lengths 1 and 2 mod 3 leave 4 and 2 unused bits in the final character.
  // A lenient decoder ignores them and yields identical bytes, so only canonical re-encoding rejects these.
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  for (const payload of [json + ' ', json + '  ']) {
    assert.notEqual(Buffer.byteLength(payload) % 3, 0);
    const encoded = b64(payload);
    const unusedBits = Buffer.byteLength(payload) % 3 === 1 ? 4 : 2;
    const last = ALPHABET.indexOf(encoded.at(-1));
    assert.equal(last & ((1 << unusedBits) - 1), 0, 'canonical encoding has zero trailing bits');
    const tampered = encoded.slice(0, -1) + ALPHABET[last | 1];
    assert.deepEqual(Buffer.from(tampered, 'base64url'), Buffer.from(payload), 'same bytes under lenient decoding');
    assert.equal(m.parseFragment('#registration=' + encoded).salt, pattern.salt, 'canonical form is accepted');
    assert.throws(() => m.parseFragment('#registration=' + tampered), (e) => e.code === 'encoding',
      `trailing bits (${unusedBits})`);
  }
});

test('manual JSON import rejects every malformed, extra, duplicate or authority-bearing form', async () => {
  const m = await load();
  const base = handoffFor(pattern);
  const json = canonical(base);
  const swap = (key, value) => canonical({ ...base, [key]: value });
  const offCurve = '0x04' + '00'.repeat(32) + '01'.repeat(32);
  const cases = {
    duplicate: [json.replace('{', '{"version":1,'), 'duplicate'],
    unknown: [canonical({ ...base, rpc: 'https://evil.example' }), 'fields'],
    missing: [canonical({ ...base, salt: undefined }), 'fields'],
    nested: [json.replace('"version":1', '"version":{"v":1}'), 'type'],
    float: [json.replace('"version":1', '"version":1.0'), 'type'],
    exponent: [json.replace('"chainId":137', '"chainId":1.37e2'), 'type'],
    boolean: [json.replace('"version":1', '"version":true'), 'type'],
    stringNumber: [json.replace('"chainId":137', '"chainId":"137"'), 'type'],
    trailing: [json + 'x', 'json'],
    twoObjects: [json + json, 'json'],
    controlChar: [json.replace('"salt"', '"sa\u0001lt"'), 'json'],
    loneSurrogate: [json.replace('"salt"', '"salt\\ud800"'), 'encoding'],
    badEscape: [json.replace('"salt"', '"sa\\qlt"'), 'json'],
    oversize: [json.replace('}', ',' + '"' + 'p'.repeat(4100) + '":1}'), 'oversize'],
    version: [swap('version', 2), 'version'],
    recipe: [swap('recipe', 'polygon-137/hybrid-delegator-1.3.0/erc1967-create2/v2'), 'recipe'],
    chain: [swap('chainId', 1), 'chain'],
    upperKey: [swap('publicKey', base.publicKey.toUpperCase().replace('0X', '0x')), 'publicKey'],
    shortKey: [swap('publicKey', base.publicKey.slice(0, -2)), 'publicKey'],
    offCurve: [canonical({ ...base, publicKey: offCurve, keyID: require('node:crypto').createHash('sha256')
      .update(Buffer.from(offCurve.slice(2), 'hex')).digest('hex') }), 'curve'],
    keyID: [swap('keyID', 'a'.repeat(64)), 'keyID'],
    salt: [swap('salt', base.salt.toUpperCase().replace('0X', '0x')), 'salt'],
    lowerAddress: [swap('expectedAddress', base.expectedAddress.toLowerCase()), 'address'],
    otherRowAddress: [swap('expectedAddress', vectors.vectors[0].address), 'binding'],
    zeroSaltShortcut: [swap('salt', '0x' + '00'.repeat(32)), 'binding'],
    barePoint: [pattern.publicPoint, 'not-v1'],
    pointArray: [JSON.stringify([pattern.publicPoint]), 'not-v1'],
    url: ['https://p256-signer.tumf.dev/#registration=' + b64(json), 'not-v1'],
    empty: ['', 'json'],
  };
  for (const [name, [text, code]] of Object.entries(cases)) {
    assert.throws(() => m.parseHandoff(text), (e) => e.code === code && e.message.length < 120
      && !e.message.includes(base.publicKey), name);
  }
  // Whitespace-tolerant but complete-token JSON is accepted.
  assert.equal(m.parseHandoff(' ' + JSON.stringify(base, null, 2) + '\n').expectedAddress, base.expectedAddress);
});

test('block-bound inspection: undeployed, already deployed and every fail-closed authority case', async () => {
  const m = await load();
  const plan = m.buildPlan(handoffFor(pattern));
  const fresh = () => new FakeChain();
  let chain = fresh();
  const undeployed = await m.inspect((method, params) => chain.rpc(method, params), plan);
  assert.equal(undeployed.kind, 'undeployed');
  assert.deepEqual(Object.keys(undeployed).sort(), ['block', 'kind'], 'identity and block only: no estimate or fees');
  assert.ok(chain.calls.filter((c) => ['eth_getCode', 'eth_call', 'eth_getStorageAt'].includes(c.method))
    .every((c) => c.params[c.params.length - 1] === '0x' + undeployed.block.number.toString(16)));
  const FEE_METHODS = ['eth_estimateGas', 'eth_maxPriorityFeePerGas', 'eth_gasPrice', 'eth_feeHistory',
    'eth_getTransactionCount'];
  assert.equal(chain.calls.some((c) => FEE_METHODS.includes(c.method)), false, 'no gas/fee/nonce RPC dependency');

  chain = fresh();
  chain.preDeploy(plan);
  const deployed = await m.inspect((a, b) => chain.rpc(a, b), plan);
  assert.equal(deployed.kind, 'deployed');

  // Missing gas-estimate, base-fee or priority-fee support never blocks a valid operation.
  for (const faults of [{ estimate: true }, { noBaseFee: true }, { noTip: true },
    { estimate: true, noBaseFee: true, noTip: true }]) {
    chain = new FakeChain({ faults });
    assert.equal((await m.inspect((a, b) => chain.rpc(a, b), plan)).kind, 'undeployed', JSON.stringify(faults));
  }

  const failures = {
    offline: (c) => { c.faults.offline = true; },
    chain: (c) => { c.chainHex = '0x1'; },
    code: (c) => { c.faults.factoryCode = true; },
    prediction: (c) => { c.faults.prediction = true; },
    keyset: (c) => c.preDeploy(plan, { keys: [{ id: plan.keyID, x: plan.x, y: plan.y }, { id: 'b'.repeat(64),
      x: plan.x, y: plan.y }] }),
    'keyset-owner': (c) => c.preDeploy(plan, { owner: '0x' + '22'.repeat(20) }),
    'keyset-coordinates': (c) => c.preDeploy(plan, { keys: [{ id: plan.keyID, x: plan.y, y: plan.x }] }),
    'keyset-implementation': (c) => c.preDeploy(plan, { implementation: '0x' + '33'.repeat(20) }),
    block: (c) => { c.faults.blockFlip = true; },
  };
  for (const [name, mutate] of Object.entries(failures)) {
    chain = fresh();
    mutate(chain);
    await assert.rejects(m.inspect((a, b) => chain.rpc(a, b), plan),
      (e) => e.code === name.split('-')[0] || (name === 'keyset-implementation' && e.code === 'keyset'), name);
  }
});

test('v2 wallet-selected evidence: canonical EIP-1559 or legacy gasPrice; partial or inconsistent fields rejected', async () => {
  const m = await load();
  const base = { nonce: '0x3', gas: '0x75300' };
  assert.deepEqual(m.walletObserved({ ...base, maxFeePerGas: '0x10', maxPriorityFeePerGas: '0x2', gasPrice: '0xc' }),
    { nonce: 3n, gas: 480000n, maxFeePerGas: 16n, maxPriorityFeePerGas: 2n });
  assert.deepEqual(m.walletObserved({ ...base, gasPrice: '0x9' }),
    { nonce: 3n, gas: 480000n, maxFeePerGas: 9n, maxPriorityFeePerGas: 9n }, 'legacy gasPrice maps to both');
  assert.deepEqual(m.walletObserved({ ...base, maxFeePerGas: '0x0', maxPriorityFeePerGas: '0x0' }).maxFeePerGas, 0n,
    'zero fees are bounded nonnegative quantities');
  for (const [name, tx] of Object.entries({
    'zero-gas': { ...base, gas: '0x0', gasPrice: '0x1' },
    'gas-above-uint256': { ...base, gas: '0x1' + '0'.repeat(64), gasPrice: '0x1' },
    'priority-above-max': { ...base, maxFeePerGas: '0x1', maxPriorityFeePerGas: '0x2' },
    'partial-max-only': { ...base, maxFeePerGas: '0x1' },
    'partial-priority-only': { ...base, maxPriorityFeePerGas: '0x1', gasPrice: '0x1' },
    'no-fee-fields': { ...base },
    'malformed-fee': { ...base, maxFeePerGas: '16', maxPriorityFeePerGas: '0x1' },
    'leading-zero': { ...base, gasPrice: '0x01' },
    'malformed-gasprice-beside-1559': { ...base, maxFeePerGas: '0x2', maxPriorityFeePerGas: '0x1', gasPrice: 'x' },
    'missing-nonce': { gas: '0x1', gasPrice: '0x1' },
  })) {
    assert.throws(() => m.walletObserved(tx), (e) => e.code === 'rpc', name);
  }
  // A v2 attempt is never classified against an app ceiling, however high the wallet-selected values are.
  const huge = { ...base, gas: '0x' + (10n ** 9n).toString(16), maxFeePerGas: '0x' + (10n ** 15n).toString(16),
    maxPriorityFeePerGas: '0x' + (10n ** 15n).toString(16) };
  assert.equal(m.observe(huge, { version: 2 }).override, false);
});

test('v2 settlement: receipt must agree with the fetched transaction; wallet fee choices never override', async () => {
  const m = await load();
  const plan = m.buildPlan(handoffFor(pattern));
  const from = '0x1111111111111111111111111111111111111111';
  const attempt = { version: 2, from, transaction: { chainId: '0x89', value: '0x0', nonce: '0x0' } };
  const settle = async ({ legacy = false, fees = {}, tamperTx = null, tamperReceipt = null, revert = false } = {}) => {
    const chain = new FakeChain();
    const choice = { ...chain.walletChoice(from, { legacy }), ...fees };
    const hash = chain.submit({ from, ...plan.transaction, ...choice });
    chain.mine({ revert });
    chain.mine();
    const rpc = async (method, params) => {
      const value = await chain.rpc(method, params);
      if (method === 'eth_getTransactionByHash' && tamperTx) return tamperTx(value);
      if (method === 'eth_getTransactionReceipt' && tamperReceipt) return tamperReceipt(value);
      return value;
    };
    return m.verifySettlement(rpc, plan, attempt, hash);
  };
  const higher = { maxFeePerGas: '0x' + (500n * GWEI).toString(16), maxPriorityFeePerGas: '0x' + (50n * GWEI).toString(16) };
  for (const [name, spec, state] of [
    ['wallet-default', {}, 'success'],
    ['wallet-fee-higher', { fees: higher }, 'success'],
    ['wallet-gas-higher', { fees: { gas: '0x' + (5_000_000n).toString(16) } }, 'success'],
    ['wallet-fee-lower', { fees: { maxFeePerGas: '0x' + (31n * GWEI).toString(16), maxPriorityFeePerGas: '0x1' } }, 'success'],
    ['legacy-gasprice', { legacy: true }, 'success'],
    ['wallet-nonce', { fees: { nonce: '0x7' } }, 'success'],
    ['reverted', { revert: true, fees: higher }, 'failed'],
    ['gas-used-above-gas', { tamperReceipt: (r) => ({ ...r, gasUsed: '0x' + (10n ** 7n).toString(16) }) }, 'unknown'],
    ['price-above-max', { tamperReceipt: (r) => ({ ...r, effectiveGasPrice: '0x' + (10n ** 12n).toString(16) }) }, 'unknown'],
    ['inclusion-block-differs', { tamperTx: (t) => ({ ...t, blockNumber: '0x1' }) }, 'unknown'],
    ['inclusion-hash-differs', { tamperTx: (t) => ({ ...t, blockHash: '0x' + 'ab'.repeat(32) }) }, 'unknown'],
    ['tx-not-included', { tamperTx: (t) => ({ ...t, blockNumber: null, blockHash: null }) }, 'unknown'],
    ['partial-fee-evidence', { tamperTx: (t) => ({ ...t, maxPriorityFeePerGas: undefined }) }, 'unknown'],
  ]) {
    const result = await settle(spec);
    assert.equal(result.state, state, name);
    assert.notEqual(result.state, 'walletOverride', `${name}: never walletOverride`);
    if (state === 'unknown') assert.ok(['receipt', 'evidence'].includes(result.reason), `${name}: ${result.reason}`);
    if (state === 'success') assert.equal(result.readback, 'deployed');
  }
});

test('historical v1 integer fee policy and strict POL cap parsing (v1 records/tests only)', async () => {
  const m = await load();
  const limits = m.ceilings({ estimate: 400001n, baseFee: 30n * GWEI, tip: 2n * GWEI });
  assert.equal(limits.gasLimit, 480002n, 'ceil(estimate*120/100)');
  assert.equal(limits.maxFeePerGas, 62n * GWEI);
  assert.equal(limits.maxPriorityFeePerGas, 2n * GWEI);
  assert.equal(limits.maxTotal, 480002n * 62n * GWEI);
  assert.throws(() => m.ceilings({ estimate: 0n, baseFee: 1n, tip: 0n }));
  assert.equal(m.parsePol('0.05'), 50_000_000_000_000_000n);
  assert.equal(m.parsePol('1'), 10n ** 18n);
  assert.equal(m.parsePol('0.000000000000000001'), 1n);
  for (const [text, code] of [['', 'invalid'], ['0', 'zero'], ['0.0', 'zero'], ['-1', 'invalid'], ['1e-3', 'invalid'],
    ['NaN', 'invalid'], [' 1', 'invalid'], ['01', 'invalid'], ['1.', 'invalid'], ['.5', 'invalid'],
    ['0.0000000000000000001', 'invalid'], ['+1', 'invalid'], ['9'.repeat(80), 'large']]) {
    assert.throws(() => m.parsePol(text), (e) => e.code === code, JSON.stringify(text));
  }
  assert.equal(m.formatPol(50_000_000_000_000_000n), '0.05');
  assert.equal(m.formatPol(10n ** 18n), '1');
});
