// Production PrefundController and FundingAttemptStore over the prefund fixture chain (FIXTURE RPC, not EVM evidence)
// and the in-memory IndexedDB double: review invalidation, coherent inspection with the pinned EntryPoint runtime at
// B, the explicit send click as the only app-side approval (an internal armed review), every awaited pre-send boundary
// paused to inject edited inner fees, wallet loss, authority edits and concurrent-tab replacement, a new v2 CAS
// reservation before exactly one five-key wallet invocation, amount-only W<Q refusal, unknown outcomes, late completion
// isolation, restore reconcile-only and explicit terminal rollover.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ENTRYPOINT } from '../key-model.js';
import { DEPOSIT_TO_SELECTOR, depositCall, parseFundingAttempt } from '../prefund-model.js';
import { DB_NAME } from '../prefund-attempt-store.js';
import { memoryIndexedDB } from './support/memory-idb.mjs';
import { FUNDER, P1, SIGNER, anchorText, k1, k2, mine, reviewed, world } from './support/prefund-world.mjs';

const RELAY_METHODS = new Set(['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_getStorageAt', 'eth_call',
  'eth_getBalance', 'eth_getTransactionCount', 'eth_getTransactionByHash', 'eth_getTransactionReceipt']);
const signer = SIGNER.toLowerCase();
const rowOf = (w) => w.controller.view().row;
const show = (v) => JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? x.toString() : x));
const stored = async (w) => w.store.read();

test('inspection: malformed authority makes no RPC call; EntryPoint code is read at B and B is rechecked after it', async () => {
  const w = world();
  await w.controller.start();
  for (const [text, row] of [['{"v":"1"', 'PF02-json'], [anchorText(SIGNER, k1).replace(k1.publicKey.slice(4, 8), '0000'), 'PF02-point'],
    [anchorText(SIGNER, k1).replace(k1.keyId, 'c'.repeat(64)), 'PF02-id'], [SIGNER, 'PF02-json']]) {
    w.controller.setAuthorityText(text);
    await w.controller.inspect();
    assert.equal(rowOf(w), row);
  }
  assert.equal(w.chain.calls.length, 0);
  w.controller.setAuthorityText(anchorText(SIGNER, k1));
  await w.controller.inspect();
  assert.equal(rowOf(w), 'PF05-blank-fee');
  const calls = w.chain.calls.map(([m, p]) => `${m}:${JSON.stringify(p)}`);
  const b = w.chain.head().number;
  const codeAt = calls.indexOf(`eth_getCode:${JSON.stringify([ENTRYPOINT, '0x' + b.toString(16)])}`);
  assert.ok(codeAt > 0, 'EntryPoint code read at B');
  assert.ok(calls.slice(codeAt + 1).some((c) => c.startsWith(`eth_getBlockByNumber:["0x${b.toString(16)}"`)), 'B rechecked');
  assert.ok(calls.slice(codeAt + 1).includes('eth_chainId:[]'), 'chain rechecked');
  assert.ok(w.chain.calls.every(([m]) => RELAY_METHODS.has(m)));
  assert.equal(w.controller.view().context.entryPointCodeHash, '0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58');
  w.stop();
});

test('inspection failures are fixed read-only rows with no funding: rpc, chain, runtimes, undeployed, membership, stale', async () => {
  const cases = {
    'PF04-rpc': (c) => { c.fail = () => true; },
    'PF04-mismatch': (c) => { c.state.chainId = 1n; },
    'PF04-ep-runtime': (c) => { c.entryPointCode = c.entryPointCode.slice(0, -2) + '00'; },
    undeployed: (c) => { c.state.proxyCode = '0x'; },
    membership: (c) => { c.state.keys = [k2]; },
    'PF04-stale': (c) => { c.state.blocks.at(-1).timestamp -= 1000n; },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const w = world();
    await w.controller.start();
    mutate(w.chain);
    w.controller.setAuthorityText(anchorText(SIGNER, k1));
    await w.controller.inspect();
    const view = w.controller.view();
    assert.equal(view.row, name.startsWith('PF04') ? name : 'PF04-mismatch', name);
    assert.equal(view.error, true);
    assert.equal(view.actions.inspect, true);
    assert.equal(view.actions.walletChoose, false);
    assert.equal(view.actions.send, false);
    w.stop();
  }
});

test('cancelled inspection ignores its late result', async () => {
  const w = world();
  await w.controller.start();
  w.chain.delay = 30;
  w.controller.setAuthorityText(anchorText(SIGNER, k1));
  const pending = w.controller.inspect();
  assert.equal(rowOf(w), 'PF03-reading');
  assert.equal(w.controller.view().busy, true);
  w.controller.cancelInspect();
  await pending;
  assert.equal(rowOf(w), 'PF03-cancelled-late');
  assert.equal(w.controller.view().context, null);
  w.stop();
});

test('P/D/Q review: zero shortage has no funding; exact shortage tuple, no explicit nonce, CAS before the one wallet call', async () => {
  const sufficient = world({ deposit: P1 });
  let view = await reviewed(sufficient);
  assert.equal(view.row, 'PF06-sufficient');
  assert.equal(view.actions.send, false);
  assert.equal(view.actions.walletChoose, false);
  await sufficient.controller.send();
  assert.equal(sufficient.wallet.sends.length, 0);
  sufficient.stop();

  const w = world({ deposit: 123n });
  view = await reviewed(w);
  assert.equal(view.row, 'PF12-ready');
  assert.equal(view.plan.amount, P1 - 123n);
  assert.equal(view.actions.send, true);
  assert.equal((await w.store.read()).raw, null);
  let atSend = null;
  const request = w.wallet.request.bind(w.wallet);
  w.wallet.request = async (method, params) => {
    if (method === 'eth_sendTransaction') atSend = await w.store.read();
    return request(method, params);
  };
  await w.controller.send();
  assert.equal(w.wallet.sends.length, 1);
  // Exactly five keys: the wallet, not the app, owns gas, fees, nonce and transaction type.
  assert.equal(Object.keys(w.wallet.sends[0]).sort().join(), 'chainId,data,from,to,value');
  assert.deepEqual(w.wallet.sends[0], { from: FUNDER, to: ENTRYPOINT, value: '0x' + (P1 - 123n).toString(16),
    data: depositCall(signer), chainId: '0x89' });
  assert.ok(w.wallet.sends[0].data.startsWith(DEPOSIT_TO_SELECTOR));
  assert.equal(atSend.revision, 1);
  const reserved = parseFundingAttempt(atSend.raw);
  assert.equal(reserved.status, 'reserved');
  assert.equal(reserved.version, 2);
  assert.ok(!/outerGasLimit|outerMaxFeePerGas|outerMaxPriorityFeePerGas/.test(atSend.raw));
  assert.equal(reserved.amount, (P1 - 123n).toString());
  assert.equal(reserved.observedDeposit, '123');
  assert.equal(reserved.walletPendingNonce, '0');
  assert.ok(!/signature|binding|topic|symKey|wc:/.test(atSend.raw));
  assert.equal(rowOf(w), 'PF16-hash-no-receipt');
  // A second explicit send is impossible while the attempt governs the page.
  assert.equal(w.controller.view().actions.send, false);
  await w.controller.send();
  assert.equal(w.wallet.sends.length, 1);
  assert.ok(w.chain.calls.every(([m]) => RELAY_METHODS.has(m)));
  assert.deepEqual([...w.indexedDB.databases.keys()], [DB_NAME]);
  w.stop();
});

/**
 * Pauses the send at one awaited boundary, runs `inject`, releases it and returns the world. Boundaries: the fresh
 * EntryPoint code read (reading), the pending-nonce read, the CAS commit and the post-reservation wallet chain check.
 */
async function paused(boundary, inject, { shared = null } = {}) {
  const w = world({ indexedDB: shared || memoryIndexedDB() });
  await reviewed(w);
  let release, reached;
  const hit = new Promise((resolve) => { reached = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const rpc = w.controller.rpc;
  w.controller.rpc = async (method, params) => {
    const phase = w.controller.s.attempt.sendPhase;
    const value = await rpc(method, params);
    if ((boundary === 'reading' && phase === 'reading' && method === 'eth_getCode')
        || (boundary === 'nonce' && method === 'eth_getTransactionCount')) { reached(); await gate; }
    return value;
  };
  if (boundary === 'cas') {
    const cas = w.store.compareAndSet.bind(w.store);
    w.store.compareAndSet = async (...args) => { reached(); await gate; return cas(...args); };
  }
  if (boundary === 'chain') w.wallet.hold = async () => { reached(); await gate; };
  const sending = w.controller.send();
  await hit;
  try { await inject(w); } finally { release(); }
  await sending;
  return w;
}

const INJECTIONS = {
  'fee-changed': (w) => w.controller.setFee('2'),
  'fee-retyped': (w) => { w.controller.setFee(''); w.controller.setFee('1'); },
  'wallet-lost': (w) => { w.wallet.change({ status: 'disconnected', account: null }); w.controller.walletChanged(); },
  'account-changed': (w) => { w.wallet.change({ account: '0x' + '9a'.repeat(20) }); w.controller.walletChanged(); },
  'authority-edited': (w) => w.controller.setAuthorityText(anchorText(SIGNER, k2)),
};

test('every pre-reservation boundary: changed inner fee, wallet loss or authority edit disarms the send and invokes no wallet', async () => {
  for (const boundary of ['reading', 'nonce', 'cas']) {
    for (const [name, inject] of Object.entries(INJECTIONS)) {
      const w = await paused(boundary, inject);
      const snapshot = await stored(w);
      assert.equal(w.wallet.sends.length, 0, `${boundary}/${name}`);
      if (boundary === 'cas') {
        // The change lands while the atomic commit is in flight: the reservation exists, stays preserved and becomes
        // reconcile-only unknown with no wallet call (the intended conservative availability ceiling).
        assert.equal(snapshot.revision, 2, `${boundary}/${name}`);
        assert.equal(parseFundingAttempt(snapshot.raw).status, 'unknown', `${boundary}/${name}`);
        assert.equal(w.controller.view().row, 'PF15-error');
        w.stop();
        continue;
      }
      assert.deepEqual([snapshot.revision, snapshot.raw], [0, null], `${boundary}/${name}`);
      const view = w.controller.view();
      assert.equal(view.attempt.sending, false);
      assert.equal(w.controller.s.armed, null, `${boundary}/${name}`);
      if (name === 'wallet-lost') assert.equal(view.row, 'PF13-wallet-lost');
      if (name.startsWith('fee-')) assert.equal(view.row, 'PF13-fee-changed');
      if (name.startsWith('fee-')) {
        // The aborted review is not silently re-sendable: a fresh inner fee edit makes it ready for an explicit click.
        assert.deepEqual([view.actions.editFee, view.actions.send], [true, false], `${boundary}/${name}`);
        w.controller.setFee('5');
        assert.deepEqual([w.controller.view().row, w.controller.view().actions.send, w.wallet.sends.length],
          ['PF12-ready', true, 0], `${boundary}/${name}`);
      }
      if (name === 'wallet-lost') {
        assert.equal(view.actions.send, false);
        w.wallet.change({ status: 'connected', account: FUNDER });
        w.controller.walletChanged();
        assert.deepEqual([w.controller.view().row, w.controller.view().actions.send, w.wallet.sends.length],
          ['PF12-ready', true, 0], boundary);
      }
      w.stop();
    }
  }
});

test('after the durable reservation: authority loss at the final wallet check keeps it unknown with zero invocations', async () => {
  for (const [name, inject] of Object.entries(INJECTIONS)) {
    const w = await paused('chain', inject);
    const snapshot = await stored(w);
    const record = parseFundingAttempt(snapshot.raw);
    assert.equal(w.wallet.sends.length, 0, name);
    assert.equal(snapshot.revision, 2, name);
    assert.equal(record.status, 'unknown', name);
    assert.equal(rowOf(w), 'PF15-error', name);
    assert.equal(w.controller.view().actions.send, false);
    assert.equal(w.controller.view().actions.newFunding, false);
    w.stop();
  }
  // A wallet that reports another chain at the final check is never asked to send.
  const w = await paused('chain', (x) => { x.wallet.chainId = '0x1'; });
  assert.equal(w.wallet.sends.length, 0);
  assert.equal(parseFundingAttempt((await stored(w)).raw).status, 'unknown');
  w.stop();
});

test('post-reservation wallet chain lookup is bounded; late reply never invokes send', async (t) => {
  const w = world();
  t.after(() => w.stop());
  await reviewed(w);
  let release, reached;
  const held = new Promise((resolve) => { release = resolve; });
  const hit = new Promise((resolve) => { reached = resolve; });
  w.wallet.hold = () => { reached(); return held; };
  const setTimer = w.controller.setTimer;
  const durations = [];
  w.controller.setTimer = (fn, ms) => { durations.push(ms); return setTimer(fn, 10); };
  const sending = w.controller.send();
  // The held wallet reply never settles before release: the send may only finish through its own bounded deadline.
  await hit;
  await Promise.race([sending, new Promise((resolve) => setTimeout(resolve, 2000))]);
  const view = w.controller.view();
  // Always release the peer, including on RED, so the fixture leaves no dangling operation.
  release();
  await sending;
  assert.ok(durations.length > 0, 'wallet chain lookup must register a deadline');
  assert.equal(view.busy, false);
  assert.equal(view.attempt.record.status, 'unknown');
  assert.equal(w.wallet.sends.length, 0);
  assert.equal(w.controller.view().actions.send, false);
});

test('stale inspection after nonce, CAS or final wallet chain wait never invokes send', async (t) => {
  for (const boundary of ['nonce', 'cas', 'chain']) {
    const w = await paused(boundary, (x) => { x.clock.offset += 120; });
    t.after(() => w.stop());
    assert.equal(w.wallet.sends.length, 0, boundary);
    assert.equal(w.controller.view().actions.send, false, boundary);
    if (boundary === 'nonce') assert.equal((await stored(w)).raw, null);
    else assert.equal(parseFundingAttempt((await stored(w)).raw).status, 'unknown');
  }
});

test('concurrent-tab replacement at every boundary: the losing tab invokes no wallet and keeps the winner bytes', async () => {
  for (const boundary of ['reading', 'nonce', 'cas', 'chain']) {
    const shared = memoryIndexedDB();
    let other;
    const w = await paused(boundary, async (first) => {
      other = world({ indexedDB: shared, chain: first.chain });
      // The winner's deposit stays pending, so the loser's fresh read still sees the reviewed deposit and reaches CAS.
      other.wallet.submit = { mineBlock: false };
      await reviewed(other);
      await other.controller.send();
    }, { shared });
    const snapshot = await stored(w);
    if (boundary === 'chain') {
      // The first tab already holds the durable reservation: the second tab restores it read-only and never sends.
      assert.equal(other.wallet.sends.length, 0, boundary);
      assert.equal(other.controller.view().row, 'PF22-reserved', boundary);
      assert.equal(w.wallet.sends.length, 1, boundary);
    } else {
      assert.equal(other.wallet.sends.length, 1, boundary);
      assert.equal(w.wallet.sends.length, 0, boundary);
      assert.equal(w.controller.view().row, 'PF21-conflict', boundary);
      assert.equal(snapshot.raw, (await other.store.read()).raw);
      assert.equal(w.controller.view().attempt.outcome, null);
    }
    w.stop(); other.stop();
  }
});

test('fresh pre-send read: a changed deposit redraws Q and requires a new explicit send; W<Q refuses, W=Q reaches the wallet', async () => {
  const w = world({ deposit: 0n });
  await reviewed(w);
  w.chain.state.deposit = 5n;
  w.chain.mine();
  await w.controller.send();
  assert.equal(w.wallet.sends.length, 0);
  let view = w.controller.view();
  assert.equal(view.plan.amount, P1 - 5n);
  assert.equal(w.controller.s.armed, null);
  assert.equal(view.row, 'PF12-ready');
  assert.equal((await stored(w)).raw, null);
  // The redrawn review is not sent by itself; only another explicit click sends the new exact Q.
  await w.controller.send();
  assert.equal(w.wallet.sends.length, 1);
  assert.equal(w.wallet.sends[0].value, '0x' + (P1 - 5n).toString(16));
  w.stop();

  // Amount-only affordability: W < Q refuses before any reservation, focusing the wallet error.
  const poor = world({ balance: P1 - 1n });
  await reviewed(poor);
  await poor.controller.send();
  view = poor.controller.view();
  assert.equal(view.row, 'PF11-balance-short');
  assert.equal(view.message, 'ウォレット残高が入金額に足りません。');
  assert.deepEqual([view.actions.send, poor.controller.s.armed], [false, null]);
  assert.equal(poor.wallet.sends.length, 0);
  assert.equal((await stored(poor)).raw, null);
  // A fresh review (here a wallet change, then a top-up and a new inspection) may recover; nothing auto-sends.
  poor.chain.state.balances[FUNDER] = P1;
  poor.wallet.change({});
  poor.controller.walletChanged();
  await poor.controller.inspect();
  assert.equal(poor.controller.view().row, 'PF12-ready');
  assert.equal(poor.wallet.sends.length, 0);
  poor.stop();

  // W = Q is not refused by the app: the wallet decides whether value plus its own fees is affordable.
  const exact = world({ balance: P1 });
  await reviewed(exact);
  exact.wallet.mode = 'reject';
  await exact.controller.send();
  assert.equal(exact.wallet.sends.length, 1);
  assert.equal(exact.wallet.sends[0].value, '0x' + P1.toString(16));
  assert.equal(exact.controller.view().row, 'PF15-rejected');
  exact.stop();
});

test('explicit send click is the sole app-side approval: armed once, consumed by the wallet call, never a UI action', async () => {
  const w = world();
  await reviewed(w);
  const view = w.controller.view();
  for (const removed of ['setConsent', 'setOuterFees', 'outer']) assert.equal(typeof w.controller[removed], 'undefined', removed);
  for (const key of ['consent', 'outer', 'outerText']) assert.ok(!(key in view), key);
  assert.deepEqual(Object.keys(view.actions).filter((k) => /consent|outer|arm/i.test(k)), []);
  assert.equal(w.controller.s.armed, null);
  assert.equal(view.actions.send, true);
  // Wallet fee choices are the wallet's: higher fees and a legacy gasPrice do not invalidate the review.
  w.wallet.execution = { gasPrice: '0xba43b7400' };
  let armedAtCas = null;
  const cas = w.store.compareAndSet.bind(w.store);
  w.store.compareAndSet = async (...args) => { armedAtCas ??= w.controller.s.armed; return cas(...args); };
  const first = w.controller.send();
  // A repeated click while sending cannot rearm or invoke again.
  await w.controller.send();
  await first;
  assert.ok(armedAtCas && armedAtCas.reviewGen >= 0, 'armed during the awaited pre-send boundaries');
  assert.equal(w.controller.s.armed, null);
  assert.equal(w.wallet.sends.length, 1);
  assert.deepEqual(Object.keys(w.wallet.sends[0]).sort(), ['chainId', 'data', 'from', 'to', 'value']);
  assert.equal(w.wallet.executed[0].gasPrice, '0xba43b7400');
  // Departure drops the ephemeral review and armed authority, never the durable record.
  const before = await stored(w);
  w.controller.destroy();
  assert.deepEqual([w.controller.s.armed, w.controller.s.inspection.phase], [null, 'idle']);
  assert.deepEqual(await w.indexedDB.databases.get(DB_NAME).stores.get('state').get('current'), before);
  w.stop();
});

test('retained review shell: a disconnect after valid review keeps PF12-ready with send disabled and reconnect never auto-sends', async () => {
  const initial = world();
  await initial.controller.start();
  initial.wallet.change({ status: 'disconnected', account: null });
  initial.controller.walletChanged();
  await reviewed(initial);
  // No prior valid review: the disconnected state is the PF07 wallet choice.
  assert.equal(initial.controller.view().row, 'PF07-shortage');
  assert.equal(initial.controller.view().review, null);
  initial.stop();

  const w = world();
  await reviewed(w);
  assert.equal(w.controller.view().row, 'PF12-ready');
  w.wallet.change({ status: 'disconnected', account: null });
  w.controller.walletChanged();
  let view = w.controller.view();
  assert.equal(view.row, 'PF12-ready');
  assert.equal(view.message, '入金内容を確認し、表示した入金を1回だけ送信してください。');
  assert.equal(view.review.account, FUNDER);
  assert.deepEqual([view.actions.send, view.actions.walletChoose, view.actions.walletConnect, w.controller.reviewReady()],
    [false, true, true, false]);
  await w.controller.send();
  assert.equal(w.wallet.sends.length, 0);
  assert.equal((await stored(w)).raw, null);
  // Reconnecting rechecks every guard; the send still needs an explicit click.
  w.wallet.change({ status: 'connected', account: FUNDER });
  w.controller.walletChanged();
  view = w.controller.view();
  assert.deepEqual([view.row, view.actions.send, w.wallet.sends.length], ['PF12-ready', true, 0]);
  // An inner fee edit ends the retained shell: a later disconnect falls back to PF07.
  w.controller.setFee('2');
  w.wallet.change({ status: 'disconnected', account: null });
  w.controller.walletChanged();
  assert.equal(w.controller.view().row, 'PF12-ready', 'the edited review was valid before the disconnect');
  w.controller.setFee('3');
  assert.equal(w.controller.view().row, 'PF07-shortage');
  w.stop();
});

test('rejected, error, malformed and timed-out wallet responses keep the reservation; nothing is resent', async () => {
  for (const [mode, row] of [['reject', 'PF15-rejected'], ['error', 'PF15-error'], ['malformed', 'PF15-malformed-hash']]) {
    const w = world();
    await reviewed(w);
    w.wallet.mode = mode;
    await w.controller.send();
    assert.equal(rowOf(w), row, mode);
    assert.equal(parseFundingAttempt((await stored(w)).raw).status, 'unknown');
    await w.controller.send();
    await w.controller.reconcile();
    assert.equal(w.wallet.sends.length, 1, mode);
    const view = w.controller.view();
    assert.deepEqual([view.actions.send, view.actions.newFunding, view.actions.reconcile, view.actions.hashInput],
      [false, false, false, true]);
    w.stop();
  }
  // Timeout, then the late hash attaches to the ORIGINAL reservation only.
  const w = world();
  await reviewed(w);
  w.wallet.mode = 'hang';
  const set = w.controller.setTimer;
  w.controller.setTimer = (fn, ms) => set(fn, ms === 300000 ? 20 : ms);
  await w.controller.send();
  assert.equal(rowOf(w), 'PF15-timeout');
  const attemptId = w.controller.view().attempt.record.attemptId;
  w.wallet.release();
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(rowOf(w), 'PF15-late-hash');
  const record = parseFundingAttempt((await stored(w)).raw);
  assert.deepEqual([record.attemptId, record.status], [attemptId, 'hashKnown']);
  assert.equal(w.wallet.sends.length, 1);
  w.stop();
});

test('wallet hash released in the timeout callback survives the unknown write race', async (t) => {
  const w = world();
  t.after(() => w.stop());
  await reviewed(w);
  w.wallet.mode = 'hang';
  let completed;
  const handled = new Promise((resolve) => { completed = resolve; });
  const lateHash = w.controller.lateHash.bind(w.controller);
  w.controller.lateHash = async (...args) => { try { await lateHash(...args); } finally { completed(); } };
  const setTimer = w.controller.setTimer;
  w.controller.setTimer = (fn, ms) => setTimer(ms === 300000 ? () => { fn(); w.wallet.release(); } : fn,
    ms === 300000 ? 10 : ms);
  await w.controller.send();
  await handled;
  const record = parseFundingAttempt((await stored(w)).raw);
  assert.equal(record.status, 'hashKnown');
  assert.equal(record.transactionHash, w.chain.deposits[0].hash);
  assert.equal(rowOf(w), 'PF15-late-hash');
  assert.equal(w.wallet.sends.length, 1);
  assert.equal(w.controller.view().actions.send, false);
});

test('late completion isolation: a late hash for a replaced attempt never mutates the newer attempt', async () => {
  const w = world();
  await reviewed(w);
  const first = w.controller.view();
  w.wallet.mode = 'reject';
  await w.controller.send();
  const old = w.controller.view().attempt.record.attemptId;
  await w.controller.lateHash('00000000-0000-4000-8000-000000000000', '0x' + 'ab'.repeat(32));
  await w.controller.lateHash(old, 'not-a-hash');
  assert.equal(parseFundingAttempt((await stored(w)).raw).status, 'unknown');
  assert.ok(first);
  w.stop();
});

test('unknown outcome: nonce advance, deposit change, timeout or reload never permit a second deposit', async () => {
  const shared = memoryIndexedDB();
  const w = world({ indexedDB: shared });
  await reviewed(w);
  w.wallet.mode = 'send-then-fail';
  await w.controller.send();
  assert.equal(rowOf(w), 'PF15-error');
  mine(w, 3);
  w.clock.offset += 400;
  w.chain.mine();
  const reload = world({ indexedDB: shared, chain: w.chain });
  reload.clock.offset = w.clock.offset;
  await reload.controller.start();
  let view = reload.controller.view();
  assert.equal(view.row, 'PF22-reserved');
  assert.deepEqual([view.actions.send, view.actions.newFunding, view.actions.inspect, view.actions.walletChoose],
    [false, false, false, false]);
  reload.controller.setAuthorityText(anchorText(SIGNER, k1));
  await reload.controller.inspect();
  await reload.controller.send();
  await reload.controller.newFunding();
  assert.equal(reload.wallet.sends.length, 0);
  assert.equal(reload.chain.state.walletNonces[FUNDER.toLowerCase()], 1);
  // Only the exact public hash and read-only reconciliation proceed.
  reload.controller.setLookupHash('0x' + 'zz'.repeat(32));
  assert.equal(reload.controller.view().actions.reconcile, false);
  reload.controller.setLookupHash(w.chain.deposits[0].hash.toUpperCase().replace('0X', '0x'));
  await reload.controller.reconcile();
  view = reload.controller.view();
  assert.equal(view.row, 'PF19-success-ready', show(view.attempt.outcome));
  assert.equal(view.attempt.record.transactionHash, w.chain.deposits[0].hash);
  assert.equal(reload.wallet.sends.length + w.wallet.sends.length, 1);
  w.stop(); reload.stop();
});

test('restore is reconcile-only for reserved, hash-known and terminal attempts', async () => {
  const shared = memoryIndexedDB();
  const w = world({ indexedDB: shared });
  await reviewed(w);
  w.wallet.submit = { mineBlock: false };
  await w.controller.send();
  let reload = world({ indexedDB: shared, chain: w.chain });
  await reload.controller.start();
  assert.equal(reload.controller.view().row, 'PF22-hashKnown');
  assert.equal(reload.controller.view().actions.reconcile, true);
  w.chain.includeDeposit(w.chain.deposits[0].hash);
  mine(w);
  await reload.controller.reconcile();
  assert.equal(reload.controller.view().row, 'PF19-success-ready');
  const again = world({ indexedDB: shared, chain: w.chain });
  await again.controller.start();
  assert.equal(again.controller.view().row, 'PF22-terminal');
  assert.equal(again.controller.view().actions.newFunding, true);
  assert.equal(again.controller.view().actions.send, false);
  assert.equal(again.wallet.sends.length + reload.wallet.sends.length, 0);
  w.stop(); reload.stop(); again.stop();
  reload = null;
});

test('explicit new funding: only after reverified terminal proof; CAS replaces that exact revision with a fresh review', async () => {
  const w = world();
  await reviewed(w);
  await w.controller.send();
  // Not terminal yet: no rollover.
  await w.controller.newFunding();
  assert.equal(w.controller.view().rollover, false);
  mine(w);
  await w.controller.reconcile();
  assert.equal(rowOf(w), 'PF19-success-ready');
  const prior = await stored(w);
  await w.controller.newFunding();
  let view = w.controller.view();
  assert.equal(view.row, 'PF23-new-attempt');
  assert.deepEqual([view.authorityText, view.fee, w.controller.s.armed, view.attempt.outcome, view.actions.send],
    ['', '', null, null, false]);
  assert.deepEqual(await stored(w), prior);
  w.chain.state.deposit = 0n;
  w.chain.mine();
  view = await reviewed(w, { fee: '1' });
  assert.equal(view.row, 'PF12-ready');
  await w.controller.send();
  const next = await stored(w);
  assert.equal(parseFundingAttempt(next.raw).version, 2);
  // The reservation replaced exactly the prior revision (+1); the returned hash is the next write (+2).
  assert.equal(next.revision, prior.revision + 2);
  assert.equal(parseFundingAttempt(next.raw).status, 'hashKnown');
  assert.notEqual(parseFundingAttempt(next.raw).attemptId, parseFundingAttempt(prior.raw).attemptId);
  assert.equal(w.wallet.sends.length, 2);
  w.stop();
});

test('storage: unavailable, blocked and corrupt refuse sending; corrupt bytes are preserved without overwrite', async () => {
  const unavailable = world({ indexedDB: { open() { throw new Error('denied'); } } });
  await reviewed(unavailable);
  assert.equal(rowOf(unavailable), 'PF21-unavailable');
  await unavailable.controller.send();
  assert.equal(unavailable.wallet.sends.length, 0);
  unavailable.stop();
  const blocked = world({ indexedDB: { open() { const r = {}; setTimeout(() => r.onblocked?.(), 0); return r; } } });
  await reviewed(blocked);
  assert.equal(rowOf(blocked), 'PF21-blocked');
  blocked.stop();
  const shared = memoryIndexedDB();
  const seed = world({ indexedDB: shared });
  await seed.controller.start();
  const bad = { version: 1, revision: 4, raw: '{"version":1,"status":"reserved"}' };
  shared.databases.get(DB_NAME).stores.get('state').set('current', bad);
  const w = world({ indexedDB: shared });
  await reviewed(w);
  assert.equal(rowOf(w), 'PF21-corrupt');
  await w.controller.send();
  await w.controller.reloadAttempt();
  assert.equal(w.wallet.sends.length, 0);
  assert.deepEqual(shared.databases.get(DB_NAME).stores.get('state').get('current'), bad);
  seed.stop(); w.stop();
});
