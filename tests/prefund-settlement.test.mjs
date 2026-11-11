// Production prefund settlement (PrefundController.reconcile/newFunding) over scripted FIXTURE receipts: the exact saved
// tuple, canonical receipt/block identity with two confirmations, the pinned EntryPoint runtime at the receipt block
// and exactly one matching Deposited event; coherent actual costs; status0 failures; cumulative totalDeposit; current
// readiness reported separately from the verified transaction; non-fabricated refusals that never unlock new funding;
// and the version policy: v2 accepts the wallet's actual nonce and fees, literal v1 records keep their saved bounds.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ENTRYPOINT } from '../key-model.js';
import {
  BOR_LOG_FEE_TRANSFER, BOR_LOG_TRANSFER, BOR_PROTOCOL_ADDRESS, DEPOSITED_EVENT, addressTopic, depositCall,
  parseFundingAttempt,
} from '../prefund-model.js';
import { DB_NAME } from '../prefund-attempt-store.js';
import { LEGACY_MESSAGES, MESSAGES } from '../prefund-controller.js';
import { memoryIndexedDB } from './support/memory-idb.mjs';
import { FUNDER, P1, SIGNER, k2, mine, reviewed, world } from './support/prefund-world.mjs';
import v1Fixture from './fixtures/prefund-attempt-v1.json' with { type: 'json' };

const signer = SIGNER.toLowerCase();
const show = (v) => JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? x.toString() : x));

/** Sends one reviewed funding with `submit` scripting, mines `confirmations - 1` more blocks, runs `after`, reconciles. */
async function settled({ submit = {}, deposit = 0n, after = null, confirmations = 2, w = world({ deposit }) } = {}) {
  await reviewed(w);
  w.wallet.submit = submit;
  await w.controller.send();
  mine(w, confirmations - 1);
  if (after) await after(w);
  await w.controller.reconcile();
  return w;
}
const hashOf = (w) => w.controller.view().attempt.record.transactionHash;
const tx = (w) => w.chain.state.txs.get(hashOf(w));
const rc = (w) => w.chain.state.receipts.get(hashOf(w));
const status = async (w) => parseFundingAttempt((await w.store.read()).raw).status;

test('exact funding success: one cumulative Deposited event, canonical receipt at two confirmations, separate readiness', async () => {
  const w = await settled({ deposit: 7n });
  const view = w.controller.view();
  assert.equal(view.row, 'PF19-success-ready', show(view.attempt.outcome));
  const record = view.attempt.record;
  assert.equal(record.status, 'succeeded');
  assert.equal(record.outcome.totalDeposit, P1.toString());
  assert.equal(record.amount, (P1 - 7n).toString());
  // Actual costs are proved and persisted internally from the wallet's own execution (fixture default 2 Gwei).
  assert.equal(view.attempt.outcome.costs.gasCost, 45000n * 2n * 10n ** 9n);
  assert.equal(record.outcome.actualGasCost, (45000n * 2n * 10n ** 9n).toString());
  assert.equal(record.outcome.walletNonce, record.walletPendingNonce);
  assert.equal(view.attempt.outcome.current.shortage, 0n);
  assert.equal(view.actions.newFunding, true);
  w.stop();
});

test('cumulative event: another deposit preceded this one; totalDeposit exceeds D+Q and is never used as amount', async () => {
  const w = await settled({ after: (x) => {
    // Rewrite the event to a higher cumulative total, as if another deposit landed earlier in the block.
    const r = rc(x);
    r.logs[0].data = '0x' + (P1 * 3n).toString(16).padStart(64, '0');
  } });
  const view = w.controller.view();
  assert.equal(view.row, 'PF19-success-ready');
  assert.equal(view.attempt.outcome.costs.totalDeposit, P1 * 3n);
  assert.equal(view.attempt.outcome.costs.amount, P1);
  w.stop();
});

test('deposit consumed after funding, current read failure and changed authority keep the transaction proof', async () => {
  const consumed = await settled({ after: (x) => { x.chain.state.deposit = 10n; x.chain.mine(); } });
  let view = consumed.controller.view();
  assert.equal(view.row, 'PF20-consumed');
  assert.equal(view.attempt.record.status, 'succeeded');
  assert.equal(view.attempt.outcome.current.shortage, P1 - 10n);
  consumed.stop();
  const failed = await settled({ after: (x) => { x.chain.fail = (m) => m === 'eth_getStorageAt'; } });
  view = failed.controller.view();
  assert.equal(view.row, 'PF20-read-failed');
  assert.equal(view.attempt.record.status, 'succeeded');
  failed.stop();
  const changed = await settled({ after: (x) => { x.chain.state.keys = [k2]; x.chain.mine(); } });
  view = changed.controller.view();
  assert.equal(view.row, 'PF20-authority-changed');
  assert.equal(view.attempt.record.status, 'succeeded');
  assert.equal(view.actions.newFunding, true);
  changed.stop();
});

test('current-read deadline retains this pass verified deposit proof and costs; late readiness is ignored', async (t) => {
  const w = world();
  t.after(() => w.stop());
  await reviewed(w);
  await w.controller.send();
  mine(w);
  let release, reached;
  const held = new Promise((resolve) => { release = resolve; });
  const reading = new Promise((resolve) => { reached = resolve; });
  const rpc = w.controller.rpc;
  w.controller.rpc = async (method, params) => {
    if (method === 'eth_getStorageAt') { reached(); await held; }
    return rpc(method, params);
  };
  let expire;
  const setTimer = w.controller.setTimer;
  w.controller.setTimer = (fn, ms) => ms === 60000 ? (expire = fn, null) : setTimer(fn, ms);
  const pending = w.controller.reconcile();
  // Never hang if verification refuses before the current read: the assertions below then fail instead.
  await Promise.race([reading, pending]);
  expire?.();
  await pending;
  const view = w.controller.view();
  release();
  assert.equal(view.attempt.record.status, 'succeeded');
  assert.equal(view.row, 'PF20-read-failed');
  assert.equal(view.attempt.outcome.costs.amount, P1);
  assert.equal(view.attempt.outcome.costs.gasCost, 45000n * 2n * 10n ** 9n);
  assert.equal(view.attempt.outcome.current.reason, 'read-failed');
  assert.equal(view.actions.send, false);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(w.controller.view().row, 'PF20-read-failed');
});

test('matching canonical status0 is outerFailed with no deposit; new funding requires reverification', async () => {
  const w = await settled({ submit: { status: '0x0', gasUsed: 30000n } });
  const view = w.controller.view();
  assert.equal(view.row, 'PF17-outer-failed');
  assert.equal(view.message, '取引は失敗しました。入金はされていません。');
  assert.equal(view.attempt.record.status, 'outerFailed');
  assert.equal(view.attempt.outcome.costs.gasCost, 30000n * 2n * 10n ** 9n);
  assert.equal(view.attempt.outcome.costs.amount, undefined);
  assert.equal(w.chain.state.deposit, 0n);
  // A reorg discovered at the explicit new-funding reverification refuses the rollover.
  w.chain.reorg(BigInt(rc(w).blockNumber));
  await w.controller.newFunding();
  assert.equal(w.controller.view().rollover, false);
  assert.equal(w.controller.view().row, 'PF18-reorg');
  assert.equal(await status(w), 'uncertain');
  assert.equal(w.controller.view().actions.newFunding, false);
  w.stop();
});

// Polygon-shaped receipts: Bor appends LogTransfer (native value) and LogFeeTransfer (fee) from 0x…1010; the fixture
// stamps receipt membership (blockHash/blockNumber/transactionHash, removed=false) on every scripted log.
const WORDS = (n) => '0x' + '00'.repeat(32 * n);
const borLog = (topic0, from, to) => ({ address: BOR_PROTOCOL_ADDRESS,
  topics: [topic0, addressTopic(BOR_PROTOCOL_ADDRESS), addressTopic(from), addressTopic(to)], data: WORDS(5) });
const VALIDATOR = '0x' + '55'.repeat(20);

test('Polygon receipt: LogTransfer + matching Deposited + LogFeeTransfer settles as success and allows new funding', async () => {
  const w = await settled({ submit: { logs: (d) => [borLog(BOR_LOG_TRANSFER, FUNDER, ENTRYPOINT), d[0],
    borLog(BOR_LOG_FEE_TRANSFER, FUNDER, VALIDATOR)] } });
  assert.equal(rc(w).logs.length, 3);
  const view = w.controller.view();
  assert.equal(view.row, 'PF19-success-ready', show(view.attempt.outcome));
  assert.equal(await status(w), 'succeeded');
  assert.equal(view.attempt.record.outcome.totalDeposit, P1.toString());
  assert.equal(view.actions.newFunding, true);
  await w.controller.newFunding();
  assert.equal(w.controller.view().rollover, true);
  w.stop();
});

test('Polygon receipt: status0 with only LogFeeTransfer settles as outerFailed with no deposit', async () => {
  const w = await settled({ submit: { status: '0x0', gasUsed: 30000n,
    logs: () => [borLog(BOR_LOG_FEE_TRANSFER, FUNDER, VALIDATOR)] } });
  assert.equal(rc(w).logs.length, 1);
  const view = w.controller.view();
  assert.equal(view.row, 'PF17-outer-failed', show(view.attempt.outcome));
  assert.equal(await status(w), 'outerFailed');
  assert.equal(view.attempt.outcome.costs.gasCost, 30000n * 2n * 10n ** 9n);
  assert.equal(view.actions.newFunding, true);
  w.stop();
});

test('confirmation loss during final chain reads cannot persist a terminal outcome', async (t) => {
  for (const boundary of ['runtime', 'receipt-block']) for (const status of ['0x1', '0x0']) {
    const w = world();
    t.after(() => w.stop());
    await reviewed(w);
    w.wallet.submit = { status };
    await w.controller.send();
    mine(w);
    let removed = false, receiptReads = 0;
    w.chain.extraOverride = (method, params, value) => {
      if (method === 'eth_getBlockByNumber' && params[0] === rc(w).blockNumber) receiptReads++;
      if (!removed && (boundary === 'runtime' ? method === 'eth_getCode' && params[0] === ENTRYPOINT
        : method === 'eth_getBlockByNumber' && params[0] === rc(w).blockNumber && receiptReads === 2)) {
        w.chain.state.blocks.pop();
        removed = true;
      }
      return value;
    };
    await w.controller.reconcile();
    assert.equal(removed, true);
    assert.equal(w.chain.head().number, BigInt(rc(w).blockNumber));
    assert.equal(w.controller.view().row, 'PF16-one-confirmation', status);
    assert.equal(w.controller.view().attempt.record.status, 'confirming', status);
    assert.equal(w.controller.view().attempt.record.outcome, undefined, status);
    assert.equal(w.controller.view().actions.newFunding, false, status);
  }
});

test('receipt-block reorg during final head read cannot authorize success or rollover', async (t) => {
  for (const atHead of [2, 3]) for (const action of ['reconcile', 'newFunding']) {
    const w = world();
    t.after(() => w.stop());
    await reviewed(w); await w.controller.send(); mine(w);
    if (action === 'newFunding') await w.controller.reconcile();
    const hash = w.controller.view().attempt.record.transactionHash;
    const receipt = w.chain.state.receipts.get(hash);
    const rpc = w.controller.rpc;
    let heads = 0;
    w.controller.rpc = async (method, params) => {
      if (method === 'eth_getBlockByNumber' && params[0] === 'latest' && ++heads === atHead) {
        w.chain.reorg(BigInt(receipt.blockNumber));
        w.chain.reorg(w.chain.head().number);
        w.chain.state.deposit = 0n;
        w.chain.state.txs.delete(hash); w.chain.state.receipts.delete(hash);
      }
      return rpc(method, params);
    };
    await w.controller[action]();
    assert.equal(w.controller.view().row, 'PF18-reorg', action);
    assert.equal(w.controller.view().rollover, false, action);
    assert.equal(await status(w), 'uncertain', action);
  }
});

test('pending, one confirmation and absent receipts are not success', async () => {
  const pending = await settled({ submit: { mineBlock: false } });
  assert.equal(pending.controller.view().row, 'PF16-hash-no-receipt');
  assert.equal(await status(pending), 'hashKnown');
  pending.stop();
  const one = await settled({ confirmations: 1 });
  assert.equal(one.controller.view().row, 'PF16-one-confirmation');
  assert.equal(await status(one), 'confirming');
  assert.equal(one.controller.view().actions.newFunding, false);
  one.stop();
});

const plus1 = (hex) => '0x' + (BigInt(hex) + 1n).toString(16);
const REFUSALS = {
  'PF18-foreign-tuple': { after: (w) => { tx(w).value = '0x1'; } },
  // v2 has no saved ceiling, so cost refusals are actual incoherence between the transaction and its receipt.
  'PF18-wrong-cost': { after: (w) => { tx(w).maxPriorityFeePerGas = plus1(tx(w).maxFeePerGas); } },
  'gas-used-over-limit': { row: 'PF18-wrong-cost', after: (w) => { rc(w).gasUsed = plus1(tx(w).gas); } },
  'price-over-max': { row: 'PF18-wrong-cost', after: (w) => { rc(w).effectiveGasPrice = plus1(tx(w).maxFeePerGas); } },
  'legacy-price-over-gas-price': { row: 'PF18-wrong-cost', execution: { gasPrice: '0x3b9aca00' },
    after: (w) => { rc(w).effectiveGasPrice = plus1(tx(w).gasPrice); } },
  'PF18-reorg': { after: (w) => { w.chain.reorg(BigInt(rc(w).blockNumber)); } },
  'receipt-block': { row: 'PF18-reorg', after: (w) => { rc(w).blockHash = '0x' + '12'.repeat(32); rc(w).logs.forEach((l) => { l.blockHash = rc(w).blockHash; }); } },
  'PF18-runtime': { after: (w) => { w.chain.historicalCode.set(BigInt(rc(w).blockNumber), '0x00'); } },
  'PF18-absent-event': { submit: { logs: () => [] } },
  'PF18-duplicate-event': { submit: { logs: (d) => [d[0], { ...d[0] }] } },
  'PF18-foreign-log': { submit: { logs: (d) => [{ ...d[0], topics: [DEPOSITED_EVENT, addressTopic('0x' + '22'.repeat(20))] }] } },
  'other-contract-log': { row: 'PF18-foreign-log', submit: { logs: (d) => [d[0], { address: '0x' + '33'.repeat(20), topics: [], data: '0x' }] } },
  'status0-with-log': { row: 'PF18-foreign-log', submit: { status: '0x0', logs: () => [{ address: ENTRYPOINT,
    topics: [DEPOSITED_EVENT, addressTopic(signer)], data: '0x' + P1.toString(16).padStart(64, '0') }] } },
  'polygon-with-other-log': { row: 'PF18-foreign-log', submit: { logs: (d) => [borLog(BOR_LOG_TRANSFER, VALIDATOR, ENTRYPOINT),
    d[0], { address: '0x' + '33'.repeat(20), topics: [], data: '0x' }, borLog(BOR_LOG_FEE_TRANSFER, VALIDATOR, VALIDATOR)] } },
  'protocol-address-unknown-topic': { row: 'PF18-foreign-log', submit: { logs: (d) => [d[0],
    { ...borLog(BOR_LOG_FEE_TRANSFER, VALIDATOR, VALIDATOR), topics: [DEPOSITED_EVENT] }] } },
  'status0-fee-and-other-log': { row: 'PF18-foreign-log', submit: { status: '0x0', logs: () => [
    borLog(BOR_LOG_FEE_TRANSFER, VALIDATOR, VALIDATOR), { address: '0x' + '33'.repeat(20), topics: [], data: '0x' }] } },
  'status0-log-transfer': { row: 'PF18-foreign-log', submit: { status: '0x0', logs: () => [
    borLog(BOR_LOG_TRANSFER, VALIDATOR, ENTRYPOINT), borLog(BOR_LOG_FEE_TRANSFER, VALIDATOR, VALIDATOR)] } },
  'status0-deposited-with-fee': { row: 'PF18-foreign-log', submit: { status: '0x0', logs: () => [{ address: ENTRYPOINT,
    topics: [DEPOSITED_EVENT, addressTopic(signer)], data: '0x' + P1.toString(16).padStart(64, '0') },
    borLog(BOR_LOG_FEE_TRANSFER, VALIDATOR, VALIDATOR)] } },
  'event-value-below-amount': { row: 'PF18-foreign-log', submit: { logs: (d) => [{ ...d[0], data: '0x' + '00'.repeat(31) + '01' }] } },
};

test('reorg, foreign tuple/event/log, nonce, cost and runtime mismatches are uncertain and never unlock new funding', async () => {
  for (const [name, { row = name, submit = {}, after = null, execution = {} }] of Object.entries(REFUSALS)) {
    const w = world();
    w.wallet.execution = execution;
    await settled({ submit, after, w });
    const view = w.controller.view();
    assert.equal(view.row, row, `${name}: ${show(view.attempt.outcome)}`);
    assert.equal(view.error, true, name);
    assert.equal(view.message, MESSAGES[row], name);
    assert.equal(await status(w), 'uncertain', name);
    assert.equal(view.actions.newFunding, false, name);
    assert.equal(view.actions.send, false, name);
    await w.controller.newFunding();
    assert.equal(w.controller.view().rollover, false, name);
    assert.equal(w.wallet.sends.length, 1, name);
    w.stop();
  }
});

test('a wrong wallet tuple supplied by hash for an unknown attempt is refused and never attached', async () => {
  const w = world();
  await reviewed(w);
  w.wallet.mode = 'reject';
  await w.controller.send();
  // Some other transaction (a different account depositing a different value) is not this attempt.
  const foreign = w.chain.submitDeposit({ from: '0x' + '44'.repeat(20), to: ENTRYPOINT, value: '0x5',
    data: '0xb760faf9' + '00'.repeat(12) + signer.slice(2), gas: '0xea60', maxFeePerGas: '0x3b9aca00',
    maxPriorityFeePerGas: '0x3b9aca00' });
  mine(w);
  w.controller.setLookupHash(foreign);
  await w.controller.reconcile();
  const view = w.controller.view();
  assert.equal(view.row, 'PF18-foreign-tuple');
  assert.equal(await status(w), 'unknown');
  assert.equal(view.attempt.record.transactionHash, undefined);
  assert.equal(view.actions.newFunding, false);
  w.stop();
});

test('stale-tab terminal successor: unchanged outcome must validate durable revision before success or rollover', async (t) => {
  for (const action of ['reconcile', 'newFunding']) {
    const shared = memoryIndexedDB();
    const first = await settled({ w: world({ indexedDB: shared }) });
    const second = world({ indexedDB: shared, chain: first.chain });
    t.after(() => { first.stop(); second.stop(); });
    await second.controller.start();
    await second.controller.newFunding();
    first.chain.state.deposit = 0n;
    first.chain.mine();
    await reviewed(second);
    await second.controller.send();
    mine(second);
    await second.controller.reconcile();
    assert.equal(second.controller.view().row, 'PF19-success-ready');
    const successor = await second.store.read();
    assert.notEqual(first.controller.view().attempt.revision, successor.revision);
    await first.controller[action]();
    const view = first.controller.view();
    assert.equal(view.row, 'PF21-conflict', action);
    assert.equal(view.attempt.revision, successor.revision, action);
    assert.equal(view.attempt.record.attemptId, parseFundingAttempt(successor.raw).attemptId, action);
    assert.equal(view.attempt.outcome, null, action);
    assert.equal(view.rollover, false, action);
    assert.equal(view.actions.newFunding, false, action);
    assert.deepEqual(await first.store.read(), successor);
    assert.equal(first.wallet.sends.length + second.wallet.sends.length, 2);
  }
});

test('successor committed during current-read cannot inherit the previous pass proof', async (t) => {
  const shared = memoryIndexedDB();
  const first = await settled({ w: world({ indexedDB: shared }) });
  const second = world({ indexedDB: shared, chain: first.chain });
  t.after(() => { first.stop(); second.stop(); });
  await second.controller.start();
  let release, reached;
  const held = new Promise((resolve) => { release = resolve; });
  const reading = new Promise((resolve) => { reached = resolve; });
  const rpc = first.controller.rpc;
  first.controller.rpc = async (method, params) => {
    if (method === 'eth_getStorageAt') { reached(); await held; }
    return rpc(method, params);
  };
  const pending = first.controller.reconcile();
  await Promise.race([reading, pending]);
  await second.controller.newFunding();
  first.chain.state.deposit = 0n;
  first.chain.mine();
  await reviewed(second);
  await second.controller.send();
  mine(second);
  await second.controller.reconcile();
  const successor = await second.store.read();
  release();
  await pending;
  const view = first.controller.view();
  assert.equal(view.row, 'PF21-conflict');
  assert.equal(view.attempt.revision, successor.revision);
  assert.equal(view.attempt.outcome, null);
  assert.equal(view.rollover, false);
  assert.deepEqual(await first.store.read(), successor);
});

test('stale-tab settlement: an old tab cannot write over or display success of a newer attempt', async () => {
  const shared = memoryIndexedDB();
  const first = await settled({ w: world({ indexedDB: shared }) });
  assert.equal(first.controller.view().row, 'PF19-success-ready');
  const second = world({ indexedDB: shared, chain: first.chain });
  await second.controller.start();
  await second.controller.newFunding();
  first.chain.state.deposit = 0n;
  first.chain.mine();
  await reviewed(second);
  second.wallet.submit = { mineBlock: false };
  await second.controller.send();
  const successor = await second.store.read();
  // The first tab still holds the old snapshot; its reconcile and new funding refuse to write.
  await first.controller.reconcile();
  await first.controller.newFunding();
  assert.deepEqual(await first.store.read(), successor);
  assert.equal(first.wallet.sends.length + second.wallet.sends.length, 2);
  assert.notEqual(first.controller.view().row, 'PF19-success-ready');
  first.stop(); second.stop();
});

test('wallet choices and pending nonce are not v2 approval bounds: actual nonce and coherent fees above old caps succeed', async () => {
  // The wallet picks another nonce than the pending hint and fees above every old fixture cap (60000 gas, 1 Gwei).
  const w = world();
  w.wallet.execution = { gas: '0x493e0', maxFeePerGas: '0xba43b7400', maxPriorityFeePerGas: '0x77359400' };
  const v = await settled({ submit: { nonce: 9, gasUsed: 150000n }, w });
  let view = v.controller.view();
  assert.equal(view.row, 'PF19-success-ready', show(view.attempt.outcome));
  const record = view.attempt.record;
  assert.deepEqual([record.version, record.walletPendingNonce, record.outcome.walletNonce], [2, '0', '9']);
  assert.equal(record.outcome.effectiveGasPrice, (50n * 10n ** 9n).toString());
  assert.equal(record.outcome.actualGasCost, (150000n * 50n * 10n ** 9n).toString());
  assert.equal(view.actions.newFunding, true);
  w.stop();
  // A legacy gasPrice transaction is normalized by the shared reader and accepted when coherent.
  const legacy = world();
  legacy.wallet.execution = { gasPrice: '0x6fc23ac00' };
  await settled({ w: legacy });
  view = legacy.controller.view();
  assert.equal(view.row, 'PF19-success-ready', show(view.attempt.outcome));
  assert.equal(view.attempt.record.outcome.effectiveGasPrice, (30n * 10n ** 9n).toString());
  legacy.stop();
  // A user-supplied hash for an unknown v2 attempt follows the same policy: nonce 4 is attached with full proof.
  const unknown = world();
  await reviewed(unknown);
  unknown.wallet.mode = 'send-then-fail';
  unknown.wallet.submit = { nonce: 4 };
  await unknown.controller.send();
  mine(unknown);
  unknown.controller.setLookupHash(unknown.chain.deposits[0].hash);
  await unknown.controller.reconcile();
  view = unknown.controller.view();
  assert.equal(view.row, 'PF19-success-ready', show(view.attempt.outcome));
  assert.deepEqual([view.attempt.record.walletPendingNonce, view.attempt.record.outcome.walletNonce], ['0', '4']);
  assert.equal(unknown.wallet.sends.length, 1);
  unknown.stop();
});

/** A world whose dedicated store holds the literal frozen v1 bytes `raw` (never synthesized from a v2 record). */
async function legacyWorld(raw) {
  const shared = memoryIndexedDB();
  const seed = world({ indexedDB: shared });
  await seed.controller.start();
  seed.stop();
  shared.databases.get(DB_NAME).stores.get('state').set('current', { version: 1, revision: 3, raw });
  const w = world({ indexedDB: shared });
  await w.controller.start();
  return w;
}
const V1_HASH = parseFundingAttempt(v1Fixture.valid.hashKnown).transactionHash;
/** The historical v1 wallet's own transaction for the literal record: its saved caps and pending nonce 0. */
const legacySubmit = (w, { tx: fields = {}, ...options } = {}) => w.chain.submitDeposit({ from: FUNDER, to: ENTRYPOINT,
  value: '0x' + P1.toString(16), data: depositCall(SIGNER.toLowerCase()), gas: '0xea60', maxFeePerGas: '0x3b9aca00',
  maxPriorityFeePerGas: '0x3b9aca00', chainId: '0x89', ...fields }, { hash: V1_HASH, nonce: 0, ...options });

test('literal v1 recovery keeps saved nonce and approved caps; reconciliation CAS-updates it as v1 and never resends', async () => {
  const w = await legacyWorld(v1Fixture.valid.hashKnown);
  let view = w.controller.view();
  assert.deepEqual([view.row, view.legacy, view.actions.send, view.actions.reconcile], ['PF22-hashKnown', true, false, true]);
  legacySubmit(w);
  mine(w);
  await w.controller.reconcile();
  view = w.controller.view();
  assert.equal(view.row, 'PF19-success-ready', show(view.attempt.outcome));
  const stored = parseFundingAttempt((await w.store.read()).raw);
  assert.deepEqual([stored.version, stored.status, stored.outerGasLimit, stored.outcome.walletNonce], [1, 'succeeded', '60000', '0']);
  assert.equal((await w.store.read()).revision, 4);
  assert.equal(w.wallet.sends.length, 0);
  // Only explicit new funding after this chain proof opens a fresh review, which can reserve only a new v2.
  await w.controller.newFunding();
  assert.equal(w.controller.view().row, 'PF23-new-attempt');
  w.chain.state.deposit = 0n;
  w.chain.mine();
  await reviewed(w);
  await w.controller.send();
  const next = await w.store.read();
  assert.deepEqual([parseFundingAttempt(next.raw).version, next.revision, w.wallet.sends.length], [2, 6, 1]);
  w.stop();

  const cases = {
    'PF18-nonce': { tx: { }, nonce: 5 },
    'PF18-wrong-cost': { tx: { gas: '0xea61' } },
    'gas-used-over-cap': { row: 'PF18-wrong-cost', tx: { gas: '0xea60' }, gasUsed: 60001n },
    'fee-over-cap': { row: 'PF18-wrong-cost', tx: { maxFeePerGas: '0x3b9aca01', maxPriorityFeePerGas: '0x3b9aca00' } },
  };
  for (const [name, { row = name, tx: fields, ...options }] of Object.entries(cases)) {
    const x = await legacyWorld(v1Fixture.valid.hashKnown);
    legacySubmit(x, { tx: fields, ...options });
    mine(x);
    await x.controller.reconcile();
    view = x.controller.view();
    assert.equal(view.row, row, `${name}: ${show(view.attempt.outcome)}`);
    assert.equal(view.message, LEGACY_MESSAGES[row] || MESSAGES[row], name);
    assert.equal(await status(x), 'uncertain', name);
    assert.equal(parseFundingAttempt((await x.store.read()).raw).version, 1, name);
    assert.deepEqual([view.actions.newFunding, view.actions.send, x.wallet.sends.length], [false, false, 0], name);
    x.stop();
  }
  assert.equal(LEGACY_MESSAGES['PF18-wrong-cost'], '取引の費用が承認した上限と一致しません。結果を採用しません。');
  assert.equal(MESSAGES['PF18-wrong-cost'], '取引と受領記録の費用情報が一致しません。結果を採用しません。');
});

test('literal v1 outer failure re-proves its status0 history with the legacy wording; terminal v1 restores read-only', async () => {
  const w = await legacyWorld(v1Fixture.valid.hashKnown);
  legacySubmit(w, { status: '0x0', gasUsed: 30000n });
  mine(w);
  await w.controller.reconcile();
  const view = w.controller.view();
  assert.equal(view.row, 'PF17-outer-failed', show(view.attempt.outcome));
  assert.equal(view.message, '取引は失敗しました。入金はされていません。ガス代は発生しています。');
  assert.equal(view.attempt.outcome.costs.gasCost, 30000n * 10n ** 9n);
  assert.equal(parseFundingAttempt((await w.store.read()).raw).version, 1);
  w.stop();
  for (const [kind, row] of [['reserved', 'PF22-reserved'], ['unknown', 'PF22-reserved'], ['hashKnown', 'PF22-hashKnown'],
    ['confirming', 'PF22-hashKnown'], ['uncertain', 'PF22-terminal'], ['succeeded', 'PF22-terminal'],
    ['outerFailed', 'PF22-terminal']]) {
    const x = await legacyWorld(v1Fixture.valid[kind]);
    const v = x.controller.view();
    assert.deepEqual([v.row, v.legacy, v.actions.send, v.actions.inspect], [row, true, false, false], kind);
    assert.equal((await x.store.read()).raw, v1Fixture.valid[kind], kind);
    assert.equal(x.wallet.sends.length + x.chain.calls.length, 0, kind);
    x.stop();
  }
});
