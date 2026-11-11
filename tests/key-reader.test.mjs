// key-reader.js against the fixture-controlled chain (tests/support/key-chain.mjs): the full block-bound reader
// algorithm, freshness, pinned identity, complete key enumeration/storage/getter agreement, nonce and coherence,
// historical post-state mode, bounded concurrency and deadlines, the bounded pending wallet-nonce lookup and the v2
// actual outer fee coherence check (strict wire fixtures). Fixture RPC responses only: NOT EVM execution.
import assert from 'node:assert/strict';
import { mock, test } from 'node:test';
import ethers from '../vendor/ethers.js';
import { ENTRYPOINT, IMPLEMENTATION_SLOT, SELECTORS, UINT256_MAX, UINT64_MAX, word } from '../key-model.js';
import {
  MAX_CONCURRENT_READS, ReadError, coherentFees, pendingNonce, readContext, receipt, transaction,
} from '../key-reader.js';
import { createChain } from './support/key-chain.mjs';
import { K1, K2, softwareKey } from './support/key-fixtures.mjs';

const U = ethers.utils;
const k1 = softwareKey(K1), k2 = softwareKey(K2);
const SIGNER = '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed';
const now = () => Math.floor(Date.now() / 1000);
const world = (opts = {}) => createChain({ signer: SIGNER, keys: [k1, k2], nonce: 5n, deposit: 10n ** 18n, now, ...opts });
const read = (chain, opts = {}) => readContext(chain.rpc, { signer: SIGNER, authorizer: k1, now, ...opts });
async function failure(chain, opts) {
  try { await read(chain, opts); return 'accepted'; } catch (e) { assert.ok(e instanceof ReadError); return e.code; }
}

test('coherent acquisition: complete sorted keys, nonce, deposit and executor balance, every read at B', async () => {
  const chain = world({ balances: { ['0x' + '77'.repeat(20)]: 5n } });
  const context = await read(chain, { executor: '0x' + '77'.repeat(20) });
  assert.deepEqual(context.keys.map((k) => k.keyId), [k1.keyId, k2.keyId].sort());
  assert.equal(context.nonce, 5n);
  assert.equal(context.deposit, 10n ** 18n);
  assert.equal(context.executorBalance, 5n);
  assert.equal(context.owner, '0x' + '00'.repeat(20));
  const b = '0x' + context.block.number.toString(16);
  const blockBound = chain.calls.filter(([m]) => ['eth_getCode', 'eth_getStorageAt', 'eth_call', 'eth_getBalance'].includes(m));
  assert.ok(blockBound.length >= 12);
  for (const [, params] of blockBound) assert.equal(params.at(-1), b);
  const blocks = chain.calls.filter(([m]) => m === 'eth_getBlockByNumber').map(([, p]) => p[0]);
  assert.deepEqual(blocks, ['latest', b]);
  assert.equal(chain.calls.filter(([m]) => m === 'eth_chainId').length, 2);
  for (const [method] of chain.calls) assert.ok(!/send|sign|estimate/i.test(method), method);
});

test('freshness: older than 60s or more than 5s ahead is stale; historical mode skips only freshness', async () => {
  const chain = world();
  chain.head().timestamp = BigInt(now() - 61);
  assert.equal(await failure(chain), 'stale');
  chain.head().timestamp = BigInt(now() + 6);
  assert.equal(await failure(chain), 'stale');
  chain.head().timestamp = BigInt(now() - 3600);
  const head = chain.head();
  const historical = await read(chain, { historical: { number: head.number, hash: head.hash }, authorizer: null });
  assert.equal(historical.block.hash, head.hash);
  assert.equal(await failure(chain, { historical: { number: head.number, hash: '0x' + '99'.repeat(32) } }), 'mismatch');
});

test('pinned identity and complete key-set negatives are refused', async () => {
  const cases = {
    chain: (c) => { c.state.chainId = 1n; },
    proxyCode: (c) => { c.state.proxyCode += '00'; },
    implementationSlot: (c) => { c.state.implementation = '0x' + '12'.repeat(20); },
    implementationCode: (c) => { c.state.implementationCode = '0x6080'; },
    owner: (c) => { c.state.owner = '0x' + '34'.repeat(20); },
    entryPoint: (c) => { c.state.entryPoint = '0x' + '56'.repeat(20); },
    authorizerMissing: (c) => { c.state.keys = [k2]; },
    noKeys: (c) => { c.state.keys = []; },
    tooMany: (c) => { c.state.keys = Array.from({ length: 65 }, (_, i) => softwareKey(BigInt(i + 50))); },
    countMismatch: (c) => { c.override = (m, p, v) => (m === 'eth_call' && p[0].data === '0x1c03010a' ? word(3) : v); },
    duplicateHash: (c) => { c.override = (m, p, v) => (m === 'eth_call' && p[0].data === '0x2ffeaad6'
      ? v.slice(0, 2 + 128 + 64) + v.slice(2 + 128, 2 + 128 + 64) : v); },
    offCurveStorage: (c) => { c.override = (m, p, v) => (m === 'eth_getStorageAt' && p[1] !== IMPLEMENTATION_SLOT
      && v !== word(0) ? word(BigInt(v) ^ 1n) : v); },
    getterDisagrees: (c) => { c.override = (m, p, v) => (m === 'eth_call' && p[0].data.startsWith('0xd37aec92')
      ? word(1) + word(2).slice(2) : v); },
    nonceKeyBits: (c) => { c.override = (m, p, v) => (m === 'eth_call' && p[0].data.startsWith(SELECTORS.getNonce)
      ? word((1n << 64n) + 5n) : v); },
    shortWord: (c) => { c.override = (m, p, v) => (m === 'eth_call' && p[0].data === '0x8da5cb5b' ? '0x00' : v); },
    upperHex: (c) => { c.override = (m, p, v) => (m === 'eth_call' && p[0].data === '0xb0d691fe' ? v.toUpperCase().replace('0X', '0x') : v); },
    blockMoved: (c) => {
      let n = 0;
      c.override = (m, p, v) => (m === 'eth_getBlockByNumber' && p[0] !== 'latest' && ++n === 1 ? { ...v, hash: '0x' + 'ee'.repeat(32) } : v);
    },
    nonCanonicalQuantity: (c) => { c.override = (m, p, v) => (m === 'eth_chainId' ? '0x089' : v); },
    nullBlock: (c) => { c.override = (m, p, v) => (m === 'eth_getBlockByNumber' ? null : v); },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const chain = world();
    mutate(chain);
    assert.notEqual(await failure(chain), 'accepted', name);
  }
  const unavailable = world();
  unavailable.fail = (m) => m === 'eth_getStorageAt';
  assert.equal(await failure(unavailable), 'unavailable');
  await assert.rejects(readContext(world().rpc, { signer: '0x' + '00'.repeat(20), now }), (e) => e.code === 'input');
});

test('block recheck rejects a changed number, hash or timestamp in live and historical reads', async () => {
  for (const historical of [false, true]) {
    for (const field of ['number', 'hash', 'timestamp']) {
      const chain = world();
      let blocks = 0;
      chain.override = (m, p, v) => m === 'eth_getBlockByNumber' && ++blocks === 2
        ? { ...v, [field]: field === 'hash' ? '0x' + 'ee'.repeat(32) : '0x1' } : v;
      const head = chain.head();
      assert.equal(await failure(chain, historical ? { historical: { number: head.number, hash: head.hash } } : {}),
        'mismatch', `${historical ? 'historical' : 'live'} ${field}`);
    }
  }
});

test('64 keys are read with at most 8 concurrent per-key reads, all agreeing', async () => {
  const keys = Array.from({ length: 64 }, (_, i) => softwareKey(BigInt(i + 200)));
  const chain = createChain({ signer: SIGNER, keys, now });
  let active = 0, peak = 0;
  const rpc = chain.rpc;
  chain.rpc = async (m, p) => {
    if (m !== 'eth_getStorageAt' || p[1] === IMPLEMENTATION_SLOT) return rpc(m, p);
    active++; peak = Math.max(peak, active);
    await new Promise((r) => setTimeout(r, 1));
    try { return await rpc(m, p); } finally { active--; }
  };
  const context = await readContext(chain.rpc, { signer: SIGNER, authorizer: keys[0], now });
  assert.equal(context.keys.length, 64);
  assert.ok(peak <= MAX_CONCURRENT_READS && peak > 1, `peak ${peak}`);
});

test('per-request 10s and total 60s deadlines end the acquisition as unavailable', async () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    const chain = world();
    chain.rpc = () => new Promise(() => {});
    const pending = read(chain).then(() => 'accepted', (e) => e.code);
    mock.timers.tick(10_000);
    assert.equal(await pending, 'unavailable');
    const slow = world();
    const rpc = slow.rpc;
    slow.rpc = (m, p) => new Promise((resolve) => setTimeout(() => resolve(rpc(m, p)), 9_000));
    const total = read(slow).then(() => 'accepted', (e) => e.code);
    for (let i = 0; i < 8; i++) { mock.timers.tick(9_000); await new Promise((r) => setImmediate(r)); }
    assert.equal(await total, 'unavailable');
  } finally { mock.timers.reset(); }
});

test('receipt logs require canonical inclusion fields matching their receipt and removed false', async (t) => {
  const hash = '0x' + 'ab'.repeat(32), blockHash = '0x' + 'cd'.repeat(32);
  // Ethereum JSON-RPC log shape; unrelated standard fields must remain compatible.
  const log = { address: ENTRYPOINT, topics: [word(0)], data: '0x', transactionHash: hash,
    blockHash, blockNumber: '0x10', removed: false, logIndex: '0x0', transactionIndex: '0x0' };
  const raw = { transactionHash: hash, blockHash, blockNumber: '0x10', status: '0x1',
    from: SIGNER, to: ENTRYPOINT, gasUsed: '0x5208', effectiveGasPrice: '0x1', logs: [log] };
  const parse = (value) => receipt(async () => ({ ...raw, logs: [value] }), hash);
  await t.test('Ethereum log shape', async () => {
    const parsed = await parse(log);
    assert.equal(parsed.logs[0].blockNumber, 16n);
    assert.equal(parsed.logs[0].removed, false);
  });
  for (const field of ['transactionHash', 'blockHash', 'blockNumber', 'removed']) {
    const invalid = { ...log };
    delete invalid[field];
    await t.test(`requires ${field}`, async () => {
      await assert.rejects(parse(invalid), (e) => e.code === 'malformed');
    });
  }
  for (const [field, values] of Object.entries({
    transactionHash: [undefined, null, '0x1234', '0x' + 'ef'.repeat(32), hash + '\n'],
    blockHash: [undefined, null, '0x1234', '0x' + 'ef'.repeat(32), blockHash + '\n'],
    blockNumber: [undefined, null, '0x010', '0x11', '0x10\n', 16],
    removed: [undefined, null, true, 0, 'false', {}],
  })) {
    for (const value of values) {
      const invalid = { ...log, [field]: value };
      if (value === undefined) delete invalid[field];
      await t.test(`${field}: ${JSON.stringify(value)}`, async () => {
        await assert.rejects(parse(invalid), (e) => e.code === 'malformed');
      });
    }
  }
});

test('strict transaction and receipt parsing: exact hash, canonical fields, bounded logs', async () => {
  const chain = world();
  const hash = chain.submit({ from: '0x' + '77'.repeat(20), to: ENTRYPOINT, value: '0x0', gas: '0x2191c0',
    maxFeePerGas: '0x3b9aca00', maxPriorityFeePerGas: '0x3b9aca00', chainId: '0x89',
    data: new U.Interface(['function handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)'])
      .encodeFunctionData('handleOps', [[[SIGNER, 5, '0x', '0x5c1c6dcd', word(0), 60000, word(0), '0x', '0x']], '0x' + '77'.repeat(20)]) },
  { innerSuccess: false });
  const tx = await transaction(chain.rpc, hash);
  assert.equal(tx.to, ENTRYPOINT);
  assert.equal(tx.chainId, 137n);
  const rc = await receipt(chain.rpc, hash);
  assert.equal(rc.status, '0x1');
  assert.equal(rc.logs.length, 1);
  assert.equal(await transaction(chain.rpc, '0x' + '00'.repeat(32)), null);
  chain.override = (m, p, v) => (m === 'eth_getTransactionReceipt' ? { ...v, transactionHash: '0x' + '11'.repeat(32) } : v);
  await assert.rejects(receipt(chain.rpc, hash), (e) => e.code === 'malformed');
  chain.override = (m, p, v) => (m === 'eth_getTransactionReceipt' ? { ...v, status: '0x2' } : v);
  await assert.rejects(receipt(chain.rpc, hash), (e) => e.code === 'malformed');
  chain.override = (m, p, v) => (m === 'eth_getTransactionByHash' ? { ...v, hash: '0x' + '11'.repeat(32) } : v);
  await assert.rejects(transaction(chain.rpc, hash), (e) => e.code === 'malformed');
});

test('pending wallet nonce: one bounded read-only lookup, canonical uint256 including 0x0, everything else refused', async () => {
  const account = '0x' + '7e'.repeat(20);
  const calls = [];
  const answer = (value) => async (method, params) => { calls.push([method, params]); return value; };
  assert.equal(await pendingNonce(answer('0x0'), account), 0n);
  assert.equal(await pendingNonce(answer('0x2a'), account), 42n);
  assert.equal(await pendingNonce(answer('0x' + 'f'.repeat(64)), account), UINT256_MAX);
  assert.deepEqual(calls[0], ['eth_getTransactionCount', [account, 'pending']]);
  for (const bad of ['0x00', '0x', '2a', '0x2A', ' 0x1', '0x' + '1'.repeat(65), null, undefined, 7, {}, ['0x1']]) {
    await assert.rejects(pendingNonce(answer(bad), account), (e) => e instanceof ReadError && e.code === 'malformed',
      JSON.stringify(bad));
  }
  await assert.rejects(pendingNonce(async () => { throw new TypeError('relay'); }, account),
    (e) => e instanceof ReadError && e.code === 'unavailable');
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    const pending = pendingNonce(() => new Promise(() => {}), account).then(() => 'accepted', (e) => e.code);
    mock.timers.tick(10_000);
    assert.equal(await pending, 'unavailable');
  } finally { mock.timers.reset(); }
});

test('raw fee mode leaves actual gas/fee members to the v2 coherence check; legacy mode is unchanged', async () => {
  const hash = '0x' + 'ab'.repeat(32), blockHash = '0x' + 'cd'.repeat(32);
  const tx = { hash, from: SIGNER, to: ENTRYPOINT, value: '0x0', input: '0x', nonce: '0x1', chainId: '0x89',
    blockNumber: '0x10', blockHash, gas: '0x2191c0', maxFeePerGas: '0x01' };
  const rc = { transactionHash: hash, blockHash, blockNumber: '0x10', status: '0x1', from: SIGNER, to: ENTRYPOINT,
    gasUsed: 'bad', logs: [] };
  await assert.rejects(transaction(async () => tx, hash), (e) => e.code === 'malformed');
  await assert.rejects(receipt(async () => rc, hash), (e) => e.code === 'malformed');
  const raw = await transaction(async () => tx, hash, { fees: 'raw' });
  assert.deepEqual({ ...raw.feeFields }, { gas: '0x2191c0', maxFeePerGas: '0x01', maxPriorityFeePerGas: null, gasPrice: null });
  assert.equal(raw.gas, undefined);
  assert.equal(raw.nonce, 1n);
  const r = await receipt(async () => rc, hash, { fees: 'raw' });
  assert.deepEqual({ ...r.feeFields }, { gasUsed: 'bad', effectiveGasPrice: null });
  // Transport identity is still strict in raw mode.
  await assert.rejects(transaction(async () => ({ ...tx, nonce: '0x01' }), hash, { fees: 'raw' }), (e) => e.code === 'malformed');
});

test('v2 actual fee coherence: dynamic and legacy shapes, gasPrice agreement, partial/invalid/contradictory evidence', () => {
  const G = 10n ** 9n, h = (n) => '0x' + BigInt(n).toString(16);
  const dyn = { gas: h(2200000), maxFeePerGas: h(30n * G), maxPriorityFeePerGas: h(2n * G), gasPrice: null };
  const leg = { gas: h(2200000), maxFeePerGas: null, maxPriorityFeePerGas: null, gasPrice: h(5n * G) };
  const rcOf = (used, price) => ({ gasUsed: h(used), effectiveGasPrice: h(price) });
  const ok = coherentFees(dyn, rcOf(400000, 12n * G));
  assert.equal(ok.outerCost, 400000n * 12n * G);
  assert.equal(coherentFees({ ...dyn, gasPrice: h(12n * G) }, rcOf(400000, 12n * G)).effectiveGasPrice, 12n * G);
  assert.equal(coherentFees(dyn, rcOf(2200000, 2n * G)).gasUsed, 2200000n);
  assert.equal(coherentFees(dyn, rcOf(1, 30n * G)).outerCost, 30n * G);
  assert.equal(coherentFees(leg, rcOf(400000, 5n * G)).outerCost, 400000n * 5n * G);
  // Wallet fee choices far above or below any former application ceiling are internally coherent evidence.
  assert.ok(coherentFees({ ...dyn, maxFeePerGas: h(10n ** 30n), maxPriorityFeePerGas: h(10n ** 29n) }, rcOf(400000, 10n ** 29n)));
  assert.ok(coherentFees({ ...leg, gasPrice: '0x1' }, rcOf(21000, 1)));
  const fees = (t, r) => { try { coherentFees(t, r); return 'accepted'; } catch (e) { assert.ok(e instanceof ReadError); return e.code; } };
  const cases = {
    noFees: [{ ...leg, gasPrice: null }, rcOf(1, 1)],
    partialMax: [{ ...dyn, maxPriorityFeePerGas: null }, rcOf(400000, 2n * G)],
    partialPriority: [{ ...dyn, maxFeePerGas: null }, rcOf(400000, 2n * G)],
    partialWithGasPrice: [{ ...dyn, maxPriorityFeePerGas: null, gasPrice: h(2n * G) }, rcOf(400000, 2n * G)],
    priorityAboveMax: [{ ...dyn, maxPriorityFeePerGas: h(31n * G) }, rcOf(400000, 30n * G)],
    zeroMax: [{ ...dyn, maxFeePerGas: '0x0', maxPriorityFeePerGas: '0x0' }, rcOf(400000, 0)],
    zeroLegacy: [{ ...leg, gasPrice: '0x0' }, rcOf(400000, 0)],
    zeroGas: [{ ...dyn, gas: '0x0' }, rcOf(0, 2n * G)],
    missingGas: [{ ...dyn, gas: null }, rcOf(1, 2n * G)],
    gasOverUint64: [{ ...dyn, gas: h(UINT64_MAX + 1n) }, rcOf(1, 2n * G)],
    leadingZero: [{ ...dyn, maxFeePerGas: '0x01bf08eb000' }, rcOf(1, 2n * G)],
    upperHex: [{ ...dyn, maxFeePerGas: dyn.maxFeePerGas.toUpperCase().replace('0X', '0x') }, rcOf(1, 2n * G)],
    decimal: [{ ...dyn, maxFeePerGas: '30000000000' }, rcOf(1, 2n * G)],
    number: [{ ...dyn, maxPriorityFeePerGas: 2 }, rcOf(1, 2)],
    feeOverUint256: [{ ...dyn, maxFeePerGas: '0x1' + '0'.repeat(64) }, rcOf(1, 2n * G)],
    gasUsedAboveGas: [dyn, rcOf(2200001, 2n * G)],
    gasUsedMissing: [dyn, { gasUsed: null, effectiveGasPrice: h(2n * G) }],
    effectiveMissing: [dyn, { gasUsed: h(1), effectiveGasPrice: null }],
    effectiveAboveMax: [dyn, rcOf(400000, 30n * G + 1n)],
    effectiveBelowPriority: [dyn, rcOf(400000, 2n * G - 1n)],
    minedGasPriceDisagrees: [{ ...dyn, gasPrice: h(13n * G) }, rcOf(400000, 12n * G)],
    malformedGasPrice: [{ ...dyn, gasPrice: '0x00' }, rcOf(400000, 12n * G)],
    legacyEffectiveDiffers: [leg, rcOf(400000, 5n * G - 1n)],
    overflow: [{ ...dyn, maxFeePerGas: h(UINT256_MAX), maxPriorityFeePerGas: '0x0' }, rcOf(2, UINT256_MAX)],
  };
  for (const [name, [tx, rc]] of Object.entries(cases)) assert.equal(fees(tx, rc), 'fees', name);
});
