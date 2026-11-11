// Semantic settlement through the production controller over FIXTURE-scripted transactions/receipts/blocks (parsing
// and negative paths only; tests/key-evm.test.mjs owns real execution). Success requires the exact tuple, canonical
// receipt/block identity, two confirmations, exactly one matching EntryPoint UserOperationEvent and the complete
// expected key map and old nonce + 1; everything else is failed or uncertain and never retried. New (v2) attempts
// require internally coherent actual wallet fees and an event within the signed inner budget; legacy v1 fixtures keep
// their outer-ceiling (KW26-cap) behavior unchanged.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ENTRYPOINT, word } from '../key-model.js';
import { approve, k1, k2, k3, seedLegacy, world } from './support/key-world.mjs';

const G = 10n ** 9n;
const hex = (n) => '0x' + BigInt(n).toString(16);
const P = 1060000n * G;

async function sent({ submit = {}, change, key = k1, keys, mine = true, fees, legacy } = {}) {
  const w = world({ keys: keys || [k1] });
  await w.controller.loadAttempt();
  await approve(w, change ? { key, change } : { key });
  w.wallet.submit = submit;
  if (fees) w.wallet.fees = fees;
  await w.controller.send();
  if (legacy) await seedLegacy(w, legacy);
  if (mine) w.chain.mine();
  return w;
}
async function settled(options, script) {
  const w = await sent(options);
  if (script) await script(w);
  await w.controller.reconcile();
  return { w, v: w.controller.view() };
}
const hashOf = (w) => w.controller.view().attempt.record.transactionHash;

test('exact success: matching event, full expected keys and nonce + 1, with distinct costs', async () => {
  const { v } = await settled();
  assert.equal(v.row, 'KW27');
  assert.equal(v.attempt.record.status, 'succeeded');
  assert.equal(v.costs.actualGasCost, 123456789n);
  assert.equal(v.costs.outerCost, 400000n * 10n ** 9n);
  assert.equal(v.costs.net, v.costs.outerCost - v.costs.actualGasCost);
  assert.equal(v.attempt.record.outcome.kind, 'succeeded');
});

test('pending and one confirmation are never success', async () => {
  const w = await sent({ submit: { mineBlock: false }, mine: false });
  await w.controller.reconcile();
  assert.equal(w.controller.view().row, 'KW23-pending');
  w.chain.include(hashOf(w));
  await w.controller.reconcile();
  assert.equal(w.controller.view().row, 'KW23-one');
  assert.equal(w.controller.view().attempt.record.status, 'confirming');
  w.chain.mine();
  await w.controller.reconcile();
  assert.equal(w.controller.view().row, 'KW27');
});

test('outer-only success, wrong, duplicate, foreign-emitter and malformed events stay uncertain', async () => {
  const scripts = {
    missing: { dropEvent: true },
    wrongHash: { eventOverride: (e) => ({ ...e, topics: [e.topics[0], word(1), e.topics[2], e.topics[3]] }) },
    otherEmitter: { eventOverride: (e) => ({ ...e, address: '0x' + '99'.repeat(20) }) },
    sender: { eventOverride: (e) => ({ ...e, topics: [e.topics[0], e.topics[1], word(5), e.topics[3]] }) },
    paymaster: { eventOverride: (e) => ({ ...e, topics: [e.topics[0], e.topics[1], e.topics[2], word(7)] }) },
    nonce: { eventOverride: (e) => ({ ...e, data: word(9) + e.data.slice(66) }) },
    successWord: { eventOverride: (e) => ({ ...e, data: e.data.slice(0, 66) + word(2).slice(2) + e.data.slice(130) }) },
    shortData: { eventOverride: (e) => ({ ...e, data: e.data.slice(0, -64) }) },
  };
  for (const [name, submit] of Object.entries(scripts)) {
    const { v } = await settled({ submit });
    assert.equal(v.row, 'KW26-event', name);
    assert.equal(v.attempt.record.status, 'uncertain', name);
  }
  const { v } = await settled({}, async (w) => {
    const rc = w.chain.state.receipts.get(hashOf(w));
    rc.logs.push({ ...rc.logs[0] });
  });
  assert.equal(v.row, 'KW26-event', 'duplicate');
});

test('inner failure and outer failure are distinguished, with incurred costs', async () => {
  const inner = await settled({ submit: { innerSuccess: false } });
  assert.equal(inner.v.row, 'KW24');
  assert.equal(inner.v.attempt.record.status, 'innerFailed');
  assert.ok(inner.v.costs.actualGasCost > 0n);
  const outer = await settled({ submit: { outerStatus: '0x0' } });
  assert.equal(outer.v.row, 'KW25');
  assert.equal(outer.v.attempt.record.status, 'outerFailed');
  assert.ok(outer.v.costs.outerCost > 0n);
});

test('reorg, altered tuple and v1 raised caps are not success; v2 wallet fee choices are not cap overrides', async () => {
  const reorg = await settled({}, async (w) => w.chain.reorg(BigInt(w.chain.state.receipts.get(hashOf(w)).blockNumber)));
  assert.equal(reorg.v.row, 'KW26-reorg');
  const tuples = {
    from: (tx) => { tx.from = '0x' + '55'.repeat(20); }, to: (tx) => { tx.to = '0x' + '56'.repeat(20); },
    value: (tx) => { tx.value = '0x1'; }, input: (tx) => { tx.input = tx.input.slice(0, -2) + '01'; },
    chain: (tx) => { tx.chainId = '0x1'; },
  };
  for (const [name, mutate] of Object.entries(tuples)) {
    const { v } = await settled({}, async (w) => mutate(w.chain.state.txs.get(hashOf(w))));
    assert.equal(v.row, 'KW26-foreign', name);
    assert.notEqual(v.attempt.record.status, 'succeeded', name);
  }
  // Legacy v1 (frozen ceilings gas 2200000, 1 gwei): any wallet value above a stored ceiling keeps KW26-cap.
  const ceilings = { gas: '2200000', maxFee: String(G), priority: String(G) };
  for (const [field, raised] of [['gas', { gas: hex(2200001n) }], ['maxFeePerGas', { maxFeePerGas: hex(2n * G) }],
    ['maxPriorityFeePerGas', { maxFeePerGas: hex(G), maxPriorityFeePerGas: hex(G + 1n) }]]) {
    const { v } = await settled({ legacy: ceilings, fees: { gas: hex(2200000n), maxFeePerGas: hex(G),
      maxPriorityFeePerGas: hex(G), ...raised } });
    assert.equal(v.attempt.record.version, 1, field);
    assert.equal(v.row, 'KW26-cap', field);
    assert.equal(v.attempt.record.status, 'uncertain', field);
    assert.equal(v.attempt.record.outerGasLimit, '2200000', field);
  }
  // A lower wallet-chosen fee is within the v1 ceilings.
  const lower = await settled({ legacy: ceilings, fees: { gas: hex(2200000n), maxFeePerGas: hex(G),
    maxPriorityFeePerGas: '0x1' } });
  assert.equal(lower.v.row, 'KW27');
  assert.equal(lower.v.attempt.record.version, 1);
  // v2: the same higher and lower wallet choices (and ones far beyond any former ceiling or floor) are accepted
  // when coherent; they never change the signed inner bytes, H, budget or deposit.
  for (const [name, fees] of Object.entries({
    higherGas: { gas: hex(9000000n), maxFeePerGas: hex(G), maxPriorityFeePerGas: hex(G) },
    lowerGas: { gas: hex(500000n), maxFeePerGas: hex(G), maxPriorityFeePerGas: hex(G) },
    higherFees: { gas: hex(2200000n), maxFeePerGas: hex(500n * G), maxPriorityFeePerGas: hex(300n * G) },
    lowerFees: { gas: hex(2200000n), maxFeePerGas: hex(2n), maxPriorityFeePerGas: '0x1' },
    legacyShape: { gas: hex(2200000n), gasPrice: hex(40n * G) },
  })) {
    const { w, v } = await settled({ fees });
    assert.equal(v.row, 'KW27', name);
    assert.equal(v.attempt.record.version, 2, name);
    assert.equal(v.attempt.record.status, 'succeeded', name);
    const price = name === 'legacyShape' ? 40n * G : BigInt(fees.maxPriorityFeePerGas);
    assert.equal(v.costs.outerCost, 400000n * price, name);
    assert.equal(v.attempt.record.operation.gasFees, w.controller.view().attempt.record.operation.gasFees, name);
    assert.equal(BigInt('0x' + v.attempt.record.operation.gasFees.slice(34)), G, `${name}: signed inner maxFee`);
    w.stop();
  }
});

test('foreign or removed receipt logs never establish product success', async () => {
  for (const [field, value] of [
    ['transactionHash', word(123)], ['blockHash', word(456)], ['blockNumber', '0x1'], ['removed', true],
  ]) {
    const w = await sent();
    try {
      w.chain.state.receipts.get(hashOf(w)).logs[0][field] = value;
      await w.controller.reconcile();
      const v = w.controller.view();
      assert.equal(v.row, 'KW26-rpc', field);
      assert.notEqual(v.attempt.record.status, 'succeeded', field);
      assert.equal(w.wallet.sends.length, 1, field);
    } finally { w.stop(); }
  }
});

test('receipt costs inconsistent with the actual transaction never establish success or costs', async () => {
  // Legacy v1: the original classification (KW26-rpc). v2: the fee-evidence classification KW26-fees.
  for (const [field, legacy] of [['gasUsed', true], ['effectiveGasPrice', true], ['gasUsed', false],
    ['effectiveGasPrice', false]]) {
    const w = await sent(legacy ? { legacy: { gas: '2200000' } } : {});
    try {
      const hash = hashOf(w), tx = w.chain.state.txs.get(hash);
      const receipt = w.chain.state.receipts.get(hash);
      receipt[field] = '0x' + (BigInt(tx[field === 'gasUsed' ? 'gas' : 'maxFeePerGas']) + 1n).toString(16);
      await w.controller.reconcile();
      const v = w.controller.view();
      assert.equal(v.row, legacy ? 'KW26-rpc' : 'KW26-fees', field);
      assert.notEqual(v.attempt.record.status, 'succeeded', field);
      assert.equal(v.costs, null, field);
      assert.equal(w.wallet.sends.length, 1, field);
    } finally { w.stop(); }
  }
});

test('v2 wallet fee evidence: incoherent actual transaction/receipt fees stay uncertain, stale success invalidated', async () => {
  const tamper = {
    partialPair: (tx) => { delete tx.maxPriorityFeePerGas; },
    priorityAboveMax: (tx) => { tx.maxPriorityFeePerGas = hex(BigInt(tx.maxFeePerGas) + 1n); },
    missingFees: (tx) => { delete tx.maxFeePerGas; delete tx.maxPriorityFeePerGas; delete tx.gasPrice; },
    nonCanonical: (tx) => { tx.maxFeePerGas = '0x0' + tx.maxFeePerGas.slice(2); },
    zeroGas: (tx) => { tx.gas = '0x0'; },
    gasUsedAboveGas: (tx, rc) => { rc.gasUsed = hex(BigInt(tx.gas) + 1n); },
    effectiveContradiction: (tx, rc) => { rc.effectiveGasPrice = hex(BigInt(tx.maxFeePerGas) + 1n); },
    minedGasPrice: (tx) => { tx.gasPrice = hex(BigInt(tx.gasPrice) + 1n); },
    overflow: (tx, rc) => {
      Object.assign(tx, { gas: hex(2n ** 63n), maxFeePerGas: hex(2n ** 255n), maxPriorityFeePerGas: '0x0', gasPrice: hex(2n ** 255n) });
      Object.assign(rc, { gasUsed: hex(2n ** 62n), effectiveGasPrice: hex(2n ** 255n) });
    },
  };
  for (const [name, mutate] of Object.entries(tamper)) {
    const { w, v } = await settled({}, async (x) => {
      const hash = hashOf(x);
      mutate(x.chain.state.txs.get(hash), x.chain.state.receipts.get(hash));
    });
    assert.equal(v.row, 'KW26-fees', name);
    assert.equal(v.attempt.record.status, 'uncertain', name);
    assert.equal(v.attempt.record.outcome, undefined, name);
    assert.equal(v.costs, null, name);
    assert.equal(v.actions.send, false, name);
    assert.equal(w.wallet.sends.length, 1, name);
    w.stop();
  }
  // A saved success is rechecked at every inspection: later incoherent evidence removes the stale outcome by CAS.
  const { w, v } = await settled();
  assert.equal(v.row, 'KW27');
  w.chain.state.receipts.get(hashOf(w)).effectiveGasPrice = '0x0';
  await w.controller.reconcile();
  const again = w.controller.view();
  assert.equal(again.row, 'KW26-fees');
  assert.equal(again.attempt.record.status, 'uncertain');
  assert.equal(again.attempt.record.outcome, undefined);
  w.stop();
});

test('v2 signed-inner budget: an event above P or actualGasUsed x inner maxFee is not reimbursement or success', async () => {
  const event = (cost, used) => ({ eventOverride: (e) => ({ ...e, data: e.data.slice(0, 130) + word(cost).slice(2)
    + word(used).slice(2) }) });
  for (const [name, submit] of Object.entries({
    aboveP: event(P + 1n, 2000000n),
    aboveUsedTimesFee: event(400000n * G + 1n, 400000n),
    usedOverflow: event(1n, 2n ** 255n),
  })) {
    const { w, v } = await settled({ submit });
    assert.equal(v.row, 'KW26-event', name);
    assert.equal(v.attempt.record.status, 'uncertain', name);
    assert.equal(v.attempt.record.outcome, undefined, name);
    assert.equal(v.costs.actualGasCost, undefined, name);
    w.stop();
  }
  // Exactly at the bound is valid evidence; an outer cost far above P is never capped by it.
  const { w, v } = await settled({ submit: event(P, 1060000n), fees: { gas: hex(9000000n), maxFeePerGas: hex(900n * G),
    maxPriorityFeePerGas: hex(900n * G) } });
  assert.equal(v.row, 'KW27');
  assert.equal(v.costs.actualGasCost, P);
  assert.ok(v.costs.outerCost > P);
  assert.equal(v.costs.net, v.costs.outerCost - P);
  w.stop();
  // The same over-budget event on a legacy v1 record keeps the unchanged v1 outcome.
  const legacy = await settled({ submit: event(P + 1n, 2000000n), legacy: { gas: '2200000' } });
  assert.equal(legacy.v.row, 'KW27');
  assert.equal(legacy.v.attempt.record.version, 1);
  legacy.w.stop();
  // An over-budget innerFailed event is equally not an inner-cost claim.
  const inner = await settled({ submit: { innerSuccess: false, ...event(P + 1n, 2000000n) } });
  assert.equal(inner.v.row, 'KW26-event');
  inner.w.stop();
});

test('post-state mismatch, same-block conflict and RPC loss are uncertain subtypes', async () => {
  const state = await settled({}, async (w) => { w.chain.state.keys.push({ ...k3 }); });
  assert.equal(state.v.row, 'KW26-state');
  const same = await settled({}, async (w) => { w.chain.state.nonce += 1n; });
  assert.equal(same.v.row, 'KW26-same-block');
  assert.equal(same.v.attempt.record.outcome.kind, 'sameBlockConflict');
  assert.notEqual(same.v.attempt.record.status, 'succeeded');
  const rpc = await settled({}, async (w) => { w.chain.fail = (m) => m === 'eth_getStorageAt'; });
  assert.equal(rpc.v.row, 'KW26-rpc');
  const receipts = await settled({}, async (w) => { w.chain.fail = (m) => m === 'eth_getTransactionReceipt'; });
  assert.equal(receipts.v.row, 'KW26-rpc');
});

test('self-removal settles without requiring the removed authorizer to remain registered', async () => {
  const { v } = await settled({ keys: [k1, k2], change: { mode: 'remove', removeKeyId: k1.keyId } });
  assert.equal(v.row, 'KW28');
  assert.deepEqual(v.attempt.outcome.keys.map((k) => k.keyId), [k2.keyId]);
});

test('hash input: only a verified matching transaction is attached; a foreign hash attaches nothing', async () => {
  const w = await sent({ submit: {} });
  const real = hashOf(w);
  // An unknown outcome (no stored hash) whose hash the user supplies later.
  await w.controller.update((r) => { const { transactionHash: _t, actualWalletNonce: _n, ...rest } = r; return { ...rest, status: 'unknown' }; });
  const foreign = w.chain.submit({ from: '0x' + '44'.repeat(20), to: ENTRYPOINT, value: '0x0', gas: '0x1',
    maxFeePerGas: '0x1', maxPriorityFeePerGas: '0x1', data: w.wallet.sends[0].data });
  w.chain.mine();
  await w.controller.reconcile(foreign);
  assert.equal(w.controller.view().row, 'KW26-foreign');
  assert.equal(w.controller.view().attempt.record.transactionHash, undefined);
  await w.controller.reconcile('not-a-hash');
  assert.equal(w.controller.view().attempt.record.transactionHash, undefined);
  await w.controller.reconcile(real);
  assert.equal(w.controller.view().attempt.record.transactionHash, real);
  assert.equal(w.controller.view().row, 'KW27');
});
