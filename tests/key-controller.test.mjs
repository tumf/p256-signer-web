// Production KeyChangeController state, generation, reservation and one-shot wallet wiring over the fixture chain,
// a software native peer, a scripted wallet and the actual KeyAttemptStore on an in-memory IndexedDB double (Node
// adapter evidence; cross-tab/durability evidence is tests/key-storage.test.mjs in real Chromium). Fixture RPC only.
import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { DB_NAME, STORE_NAME, SINGLETON_KEY, serializeAttempt } from '../key-attempt-store.js';
import { WALLET_TIMEOUT_MS } from '../key-controller.js';
import { STORE_TIMEOUT_MS } from '../key-attempt-store.js';
import { ACQUISITION_DEADLINE_MS } from '../key-reader.js';
import { ENTRYPOINT, handleOpsCall } from '../key-model.js';
import { REQUEST_KEYS } from './support/key-chain.mjs';
import { memoryIndexedDB } from './support/memory-idb.mjs';
import { EXECUTOR, approve, bareKeyText, k1, k2, k3, seedLegacy, world as createWorld } from './support/key-world.mjs';

const worlds = [];
const world = (...args) => { const w = createWorld(...args); worlds.push(w); return w; };
afterEach(() => { for (const w of worlds.splice(0)) w.stop(); });

const tick = () => new Promise((r) => setTimeout(r, 10));
const nativeConnects = (w) => w.native.client.calls.filter(([k]) => k === 'connect').length;

test('initial state: inspect is the only forward action; nothing connects, signs or sends', async () => {
  const w = world();
  await w.controller.loadAttempt();
  const v = w.controller.view();
  assert.equal(v.row, 'KW01');
  assert.equal(v.actions.inspect, true);
  for (const action of ['connectNative', 'previewNative', 'requestSignature', 'send', 'reconcile']) {
    assert.equal(v.actions[action], false, action);
  }
  assert.equal(nativeConnects(w), 0);
  assert.equal(w.wallet.sends.length, 0);
});

test('invalid anchor, stale inspection, cancel and late completion are never adopted', async () => {
  const w = world();
  await w.controller.loadAttempt();
  w.controller.setAnchorText('{"v":"1"}');
  await w.controller.inspect();
  assert.equal(w.controller.view().row, 'KW02');
  w.chain.delay = 20;
  w.controller.setAnchorText(`{"v":"1","kind":"hybrid-key-authority","chainId":"137","signer":"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed","publicKey":"${k1.publicKey}","keyId":"${k1.keyId}"}`);
  const reading = w.controller.inspect();
  assert.equal(w.controller.view().row, 'KW03');
  assert.equal(w.controller.view().actions.cancelInspect, true);
  w.controller.cancelInspect();
  await reading;
  assert.equal(w.controller.view().inspection, 'idle');
  const again = w.controller.inspect();
  w.controller.setAnchorText(w.controller.s.anchorText + ' ');
  await again;
  assert.equal(w.controller.view().inspection, 'idle');
  w.chain.delay = 0;
  w.chain.fail = () => true;
  await w.controller.inspect();
  assert.equal(w.controller.view().row, 'KW04');
  w.chain.fail = null;
  await w.controller.inspect();
  assert.equal(w.controller.view().row, 'KW05');
});

test('change and fee problems map to their rows and keep connect disabled', async () => {
  const w = world({ keys: [k1] });
  await w.controller.loadAttempt();
  w.controller.setAnchorText(`{"v":"1","kind":"hybrid-key-authority","chainId":"137","signer":"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed","publicKey":"${k1.publicKey}","keyId":"${k1.keyId}"}`);
  await w.controller.inspect();
  const row = (change) => { w.controller.setChange(change); return w.controller.view(); };
  assert.equal(row({ mode: 'add', bareText: bareKeyText(k1), feeMax: '1', feePriority: '1' }).row, 'KW07-duplicate');
  assert.equal(row({ bareText: bareKeyText(k2).replace(k2.publicKey.slice(-4), '0000') }).row, 'KW07-curve');
  assert.equal(row({ mode: 'remove', removeKeyId: k1.keyId }).row, 'KW07-last');
  assert.equal(row({ mode: 'add', bareText: bareKeyText(k2), feeMax: '' }).row, 'KW08-blank');
  assert.equal(row({ feeMax: '1.0000000001' }).row, 'KW08-format');
  assert.equal(row({ feeMax: '1', feePriority: '2' }).row, 'KW08-bounds');
  const ok = row({ feePriority: '1' });
  assert.equal(ok.row, 'KW05');
  assert.equal(ok.actions.connectNative, true);
  w.chain.state.deposit = 0n;
  await w.controller.inspect();
  const short = w.controller.view();
  assert.equal(short.row, 'KW09');
  assert.equal(short.actions.connectNative, false);
  assert.equal(short.cost.shortfall, short.cost.required);
});

test('explicit native sequence: connect requests nothing; preview reads context; request signs once', async () => {
  const w = world();
  await w.controller.loadAttempt();
  const v = await approve(w);
  assert.equal(v.native.phase, 'verified');
  // The wallet double is already connected, so the next row is the explicit send review KW20, not KW15.
  assert.equal(v.row, 'KW20');
  assert.equal(w.peer.signs, 1);
  assert.deepEqual(w.native.client.calls.filter(([k]) => k === 'request').map(([, m]) => m),
    ['p256_getKeyChangeContext', 'p256_getKeyChangeContext', 'p256_signKeyChangeRequest']);
  assert.match(v.signed.signerSignature, /^0x[0-9a-f]{192}$/);
  // The verified signature is not execution: only the explicit send action invokes the wallet. There is no outer
  // input or payment checkbox to complete first.
  assert.equal(v.actions.send, true);
  assert.equal(v.actions.consent, undefined);
  assert.equal(v.outer, undefined);
  assert.equal(w.wallet.sends.length, 0);
  w.stop();
});

test('native failures: refusal, loss event, changed authority and browser expiry each give their row', async () => {
  let w = world();
  await w.controller.loadAttempt();
  w.peer.mode = 'reject';
  assert.equal((await approve(w)).row, 'KW16-rejected');
  w = world();
  await w.controller.loadAttempt();
  w.controller.setAnchorText(`{"v":"1","kind":"hybrid-key-authority","chainId":"137","signer":"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed","publicKey":"${k1.publicKey}","keyId":"${k1.keyId}"}`);
  await w.controller.inspect();
  w.controller.setChange({ mode: 'add', bareText: bareKeyText(k2), feeMax: '1', feePriority: '1' });
  await w.controller.connectNative();
  w.native.client.emit('session_delete', w.native.client.topic);
  await tick();
  assert.equal(w.controller.view().row, 'KW16-lost');
  w = world();
  await w.controller.loadAttempt();
  w.controller.setAnchorText(`{"v":"1","kind":"hybrid-key-authority","chainId":"137","signer":"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed","publicKey":"${k1.publicKey}","keyId":"${k1.keyId}"}`);
  await w.controller.inspect();
  w.controller.setChange({ mode: 'add', bareText: bareKeyText(k2), feeMax: '1', feePriority: '1' });
  await w.controller.connectNative();
  await w.controller.previewNative();
  w.peer.binding = '0x' + 'c2'.repeat(32);
  await w.controller.requestSignature();
  assert.equal(w.controller.view().row, 'KW16-changed');
  assert.equal(w.peer.signs, 0);
  // Expiry discards the browser's permission to submit; it does not claim onchain revocation.
  w = world();
  await w.controller.loadAttempt();
  await approve(w);
  w.clock.offset = 200;
  w.controller.armExpiry(w.controller.view().signed.request.expiresAt - 200);
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(w.controller.view().row, 'KW16-expired');
  assert.equal(w.controller.view().signed, null);
  await w.controller.send();
  assert.equal(w.wallet.sends.length, 0);
  w.stop();
});

test('persist-before-send: the exact reservation exists when the wallet is invoked, exactly once', async () => {
  const w = world();
  await w.controller.loadAttempt();
  await approve(w);
  assert.equal(w.controller.view().row, 'KW20');
  let stored = null;
  w.wallet.observed = () => { stored = w.controller.view().attempt.record; };
  await w.controller.send();
  assert.equal(w.wallet.sends.length, 1);
  assert.equal(stored.status, 'reserved');
  assert.equal(stored.beneficiary, EXECUTOR);
  assert.equal(w.controller.view().attempt.record.status, 'hashKnown');
  assert.equal(w.controller.view().signed, null);
  await w.controller.send();
  assert.equal(w.wallet.sends.length, 1);
  const tx = w.wallet.sends[0];
  assert.deepEqual(Object.keys(tx).sort(), ['chainId', 'data', 'from', 'to', 'value']);
  assert.equal(tx.value, '0x0');
  assert.equal(tx.chainId, '0x89');
  w.stop();
});

test('exact five-field wallet request and v2 reservation with the fresh pending nonce hint', async () => {
  for (const hint of [0, 5]) {
    const w = world();
    try {
      await w.controller.loadAttempt(); await approve(w);
      w.chain.state.walletNonces[EXECUTOR] = hint;
      const signed = w.controller.view().signed;
      let reservedAtSend = null;
      w.wallet.observed = () => { reservedAtSend = w.controller.view().attempt.record; };
      const before = w.chain.calls.length;
      await w.controller.send();
      assert.equal(w.wallet.sends.length, 1);
      const request = w.wallet.sends[0];
      assert.deepEqual(Object.keys(request).sort(), REQUEST_KEYS);
      assert.deepEqual(request, { from: EXECUTOR, to: ENTRYPOINT,
        data: handleOpsCall(signed.request.operation, signed.signerSignature, EXECUTOR), value: '0x0', chainId: '0x89' });
      for (const field of ['gas', 'gasLimit', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce', 'type',
        'accessList']) assert.equal(field in request, false, field);
      // The record reserved before the single invocation is exact raw v2 with the latest lookup value.
      assert.equal(reservedAtSend.version, 2);
      assert.equal(reservedAtSend.status, 'reserved');
      assert.equal(reservedAtSend.walletPendingNonce, String(hint));
      for (const key of ['outerGasLimit', 'outerMaxFeePerGas', 'outerMaxPriorityFeePerGas']) {
        assert.equal(key in reservedAtSend, false, key);
      }
      // The lookup is the last read before the reservation; the executor balance is never read.
      const reads = w.chain.calls.slice(before).map(([m]) => m);
      assert.equal(reads.at(-1), 'eth_getTransactionCount');
      assert.deepEqual(w.chain.calls.slice(before).at(-1)[1], [EXECUTOR, 'pending']);
      assert.equal(reads.includes('eth_getBalance'), false);
      assert.equal(w.controller.view().attempt.record.walletPendingNonce, String(hint));
    } finally { w.stop(); }
  }
});

test('pending nonce lookup failure, malformed value, timeout and late completion: no CAS, no send, explicit retry', async () => {
  const scripts = {
    unavailable: (w) => { w.chain.fail = (m) => m === 'eth_getTransactionCount'; },
    malformed: (w) => { w.chain.override = (m, _p, v) => (m === 'eth_getTransactionCount' ? '0x00' : v); },
    nullValue: (w) => { w.chain.override = (m, _p, v) => (m === 'eth_getTransactionCount' ? null : v); },
    overflow: (w) => { w.chain.override = (m, _p, v) => (m === 'eth_getTransactionCount' ? '0x1' + '0'.repeat(64) : v); },
    timeout: (w) => {
      // The lookup hangs; the 60s send-preflight deadline fires; the lookup then completes late.
      w.timers = [];
      const set = w.controller.setTimer;
      w.controller.setTimer = (fn, ms) => { if (ms === ACQUISITION_DEADLINE_MS) { w.timers.push(fn); return -1; } return set(fn, ms); };
      const rpc = w.controller.rpc;
      w.controller.rpc = (m, p) => (m === 'eth_getTransactionCount'
        ? new Promise((resolve) => { w.late = () => resolve('0x0'); }) : rpc(m, p));
    },
  };
  for (const [name, script] of Object.entries(scripts)) {
    const w = world();
    try {
      await w.controller.loadAttempt(); await approve(w);
      script(w);
      let cas = 0;
      const compare = w.store.compareAndSet.bind(w.store);
      w.store.compareAndSet = (...args) => { cas++; return compare(...args); };
      const sending = w.controller.send();
      assert.equal(w.controller.view().row, 'KW20-checking', name);
      assert.equal(w.controller.view().actions.send, false, name);
      if (name === 'timeout') {
        for (let i = 0; i < 100 && !w.late; i++) await tick();
        w.timers[0]();
      }
      await sending;
      if (name === 'timeout') { w.late(); await tick(); }
      const v = w.controller.view();
      assert.equal(v.row, 'KW20-nonce', name);
      assert.equal(v.error, true, name);
      assert.equal(cas, 0, name);
      assert.equal(w.wallet.sends.length, 0, name);
      assert.equal((await w.store.read()).raw, null, name);
      // The still-valid verified signature remains in memory; only another explicit send repeats the preflight.
      assert.equal(v.native.phase, 'verified', name);
      assert.notEqual(v.signed, null, name);
      assert.equal(v.actions.send, true, name);
      w.chain.fail = null; w.chain.override = null;
      if (name === 'timeout') {
        w.controller.rpc = w.chain.rpc;
        w.controller.setTimer = (fn, ms) => setTimeout(fn, ms);
      }
      w.chain.state.walletNonces[EXECUTOR] = 9;
      await w.controller.send();
      assert.equal(w.wallet.sends.length, 1, name);
      assert.equal(cas, 2, name); // the reservation, then the hash observation
      assert.equal(w.controller.view().attempt.record.walletPendingNonce, '9', name);
    } finally { w.stop(); }
  }
});

test('altered unsigned inner bytes, H or signed budget at send never reserve or invoke the wallet', async () => {
  for (const alter of ['fees', 'typedDataHash', 'nonce']) {
    const w = world();
    try {
      await w.controller.loadAttempt(); await approve(w);
      const signed = w.controller.s.native.signed;
      if (alter === 'fees') w.controller.s.native.signed = { ...signed, fees: { ...signed.fees, maxFee: signed.fees.maxFee * 2n } };
      if (alter === 'typedDataHash') {
        w.controller.s.native.signed = { ...signed, request: { ...signed.request, typedDataHash: signed.request.userOpHash } };
      }
      if (alter === 'nonce') w.chain.state.nonce += 1n;
      await w.controller.send();
      assert.equal(w.wallet.sends.length, 0, alter);
      assert.equal((await w.store.read()).raw, null, alter);
      assert.equal(w.controller.view().row, 'KW16-changed', alter);
    } finally { w.stop(); }
  }
});

test('refusal, malformed hash and timeout keep the reservation: unknown, reconcile only, no retry', async () => {
  for (const mode of ['reject', 'malformed', 'timeout', 'nohash']) {
    const w = world();
    await w.controller.loadAttempt();
    await approve(w);

    w.wallet.mode = mode;
    await w.controller.send();
    const v = w.controller.view();
    assert.equal(v.attempt.record.status, 'unknown', mode);
    assert.equal(v.row, 'KW22-no-hash', mode);
    assert.equal(v.actions.send, false);
    assert.equal(v.actions.connectNative, false);
    assert.equal(v.actions.reconcile, true);
    assert.equal(v.actions.newChange, false);
    // Unchanged nonce: an explicit new change is refused (4001 never permits rollover).
    await w.controller.newChange();
    assert.equal(w.controller.view().rollover, null, mode);
    assert.equal(w.wallet.sends.length, 1, mode);
    w.stop();
  }
});

test('wallet timeout then late hash: attached to the original reservation, shown as late hash', async () => {
  const w = world();
  await w.controller.loadAttempt();
  await approve(w);

  w.wallet.mode = 'hang';
  const timers = [];
  w.controller.setTimer = (fn, ms) => { timers.push([fn, ms]); return timers.length; };
  w.controller.clearTimer = () => {};
  const sending = w.controller.send();
  for (let i = 0; i < 100 && !w.wallet.release; i++) await tick();
  timers.find(([, ms]) => ms === WALLET_TIMEOUT_MS)[0]();
  await sending;
  assert.equal(w.controller.view().row, 'KW22-no-hash');
  w.wallet.release();
  for (let i = 0; i < 50 && !w.controller.view().attempt.record.transactionHash; i++) await tick();
  const v = w.controller.view();
  assert.equal(v.row, 'KW22-late-hash');
  assert.equal(v.attempt.record.status, 'hashKnown');
  assert.equal(w.wallet.sends.length, 1);
});

test('fresh-block prechecks: nonce/key drift and deposit drop invoke no wallet; executor balance is no gate', async () => {
  for (const drift of ['nonce', 'keys', 'deposit', 'balance']) {
    const w = world();
    await w.controller.loadAttempt();
    await approve(w);

    if (drift === 'nonce') w.chain.state.nonce += 1n;
    if (drift === 'deposit') w.chain.state.deposit = 0n;
    if (drift === 'keys') w.chain.state.keys = [k1, k3];
    // A wallet balance is never compared with an application outer maximum: the wallet approves its own payment.
    if (drift === 'balance') w.chain.state.balances[EXECUTOR] = 0n;
    await w.controller.send();
    if (drift === 'balance') {
      assert.equal(w.wallet.sends.length, 1, drift);
      assert.equal(w.controller.view().attempt.record.status, 'hashKnown', drift);
    } else {
      assert.equal(w.wallet.sends.length, 0, drift);
      assert.equal(w.controller.view().attempt.record, null, drift);
      assert.equal(w.controller.view().row, 'KW16-changed', drift);
    }
    w.stop();
  }
});

test('wallet generation change during prechecks invokes no wallet', async () => {
  const w = world();
  await w.controller.loadAttempt();
  await approve(w);

  w.chain.delay = 5;
  const sending = w.controller.send();
  w.wallet.generation++;
  w.controller.walletChanged();
  await sending;
  assert.equal(w.wallet.sends.length, 0);
  assert.equal(w.controller.view().attempt.record, null);
  w.stop();
});

test('stale-tab settlement preserves a newer attempt exactly after a CAS conflict', async () => {
  const a = world(); let b;
  try {
    await a.controller.loadAttempt();
    await approve(a); await a.controller.send();
    a.chain.mine();
    b = world({ indexedDB: a.indexedDB, chain: a.chain });
    await b.controller.loadAttempt();
    await b.controller.reconcile(); await b.controller.newChange();
    await approve(b, { change: { mode: 'add', bareText: bareKeyText(k3) } });

    b.wallet.request = async () => '0x' + '43'.repeat(32);
    await b.controller.send();
    const successor = await b.store.read();
    assert.equal(JSON.parse(successor.raw).status, 'hashKnown');
    await a.controller.reconcile();
    assert.deepEqual(await a.store.read(), successor);
    assert.equal(a.controller.view().row, 'KW29-conflict');
    assert.equal(a.controller.view().attempt.outcome, null);
  } finally { a.stop(); b?.stop(); }
});

test('native loss at the final nonce read or durable reservation prevents wallet invocation', async () => {
  for (const boundary of ['pending-nonce', 'reservation']) {
    const w = world();
    try {
      await w.controller.loadAttempt(); await approve(w);
      const lose = () => w.native.client.emit('session_delete', w.native.client.topic);
      if (boundary === 'pending-nonce') {
        w.chain.override = (method, _params, value) => { if (method === 'eth_getTransactionCount') lose(); return value; };
      } else {
        const cas = w.store.compareAndSet.bind(w.store);
        w.store.compareAndSet = async (...args) => { const result = await cas(...args); lose(); return result; };
      }
      await w.controller.send();
      assert.equal(w.wallet.sends.length, 0, boundary);
      const saved = await w.store.read();
      assert.equal(saved.raw === null, boundary === 'pending-nonce', boundary);
      if (saved.raw) assert.equal(JSON.parse(saved.raw).status, 'reserved');
      assert.equal(w.controller.view().signed, null, boundary);
      assert.equal(w.controller.view().actions.send, false, boundary);
    } finally { w.stop(); }
  }
});

test('account, chain, provider, session or expiry change at either send await invalidates the send', async () => {
  for (const boundary of ['pending-nonce', 'reservation']) {
    for (const change of ['account', 'chain', 'provider', 'account-and-restore', 'session', 'expiry']) {
      const w = world();
      try {
        await w.controller.loadAttempt(); await approve(w);
        const edit = () => {
          if (change.startsWith('account')) { w.wallet.account = '0x' + '55'.repeat(20); w.controller.walletChanged(); }
          if (change === 'account-and-restore') { w.wallet.account = EXECUTOR; w.controller.walletChanged(); }
          if (change === 'chain') { w.wallet.chainId = '0x1'; w.controller.walletChanged(); }
          if (change === 'provider') { w.wallet.generation++; w.controller.walletChanged(); }
          if (change === 'session') w.native.client.emit('session_delete', w.native.client.topic);
          if (change === 'expiry') w.clock.offset = 1000;
        };
        if (boundary === 'pending-nonce') {
          w.chain.override = (method, _params, value) => { if (method === 'eth_getTransactionCount') edit(); return value; };
        } else {
          const cas = w.store.compareAndSet.bind(w.store);
          w.store.compareAndSet = async (...args) => { const result = await cas(...args); edit(); return result; };
        }
        await w.controller.send();
        assert.equal(w.wallet.sends.length, 0, `${boundary}/${change}`);
        const saved = await w.store.read();
        assert.equal(saved.raw === null, boundary === 'pending-nonce');
        // A reservation that lost its authority stays durable and reconcile-only: the lock is never released.
        if (saved.raw) {
          assert.equal(JSON.parse(saved.raw).status, 'reserved');
          assert.equal(JSON.parse(saved.raw).version, 2);
          assert.equal(w.controller.view().actions.send, false);
          await w.controller.send();
          assert.equal(w.wallet.sends.length, 0, `${boundary}/${change} again`);
        }
      } finally { w.stop(); }
    }
  }
});

test('storage: unavailable, corrupt and CAS conflict refuse sending and keep the old bytes', async () => {
  const broken = world({ indexedDB: { open() { throw new Error('denied'); } } });
  await broken.controller.loadAttempt();
  assert.equal(broken.controller.view().row, 'KW29-unavailable');
  await approve(broken);
  assert.equal(broken.controller.view().actions.connectNative, false);
  assert.equal(broken.peer.signs, 0);

  const idb = memoryIndexedDB();
  const first = world({ indexedDB: idb });
  await first.controller.loadAttempt();
  const db = idb.databases.get(DB_NAME).stores.get(STORE_NAME);
  db.set(SINGLETON_KEY, { version: 1, revision: 3, raw: '{"version":1}' });
  const corrupt = world({ indexedDB: idb });
  await corrupt.controller.loadAttempt();
  assert.equal(corrupt.controller.view().row, 'KW29-corrupt');
  assert.equal(corrupt.controller.view().actions.reconcile, false);
  assert.deepEqual(db.get(SINGLETON_KEY), { version: 1, revision: 3, raw: '{"version":1}' });

  const shared = memoryIndexedDB();
  const a = world({ indexedDB: shared }), b = world({ indexedDB: shared });
  await a.controller.loadAttempt();
  await b.controller.loadAttempt();
  await approve(a);
  await approve(b);
  await a.controller.send();
  await b.controller.send();
  assert.equal(a.wallet.sends.length, 1);
  assert.equal(b.wallet.sends.length, 0);
  assert.equal(b.controller.view().row, 'KW29-conflict');
  a.stop(); b.stop();

  const lax = world({ indexedDB: memoryIndexedDB({ durability: 'relaxed' }) });
  await lax.controller.loadAttempt();
  await approve(lax);
  await lax.controller.send();
  assert.equal(lax.wallet.sends.length, 0);
  assert.equal(lax.controller.view().row, 'KW29-unavailable');
  lax.stop();
});

test('storage: a hung (deadline) or aborted reservation transaction refuses sending and keeps the old row', async () => {
  for (const script of ['hang', 'abort', 'error']) {
    const idb = memoryIndexedDB();
    const w = world({ indexedDB: idb });
    await w.controller.loadAttempt();
    await approve(w);

    const row = idb.databases.get(DB_NAME).stores.get(STORE_NAME);
    const before = structuredClone(row.get(SINGLETON_KEY));
    idb.control.readwrite = script;
    const started = Date.now();
    await w.controller.send();
    if (script === 'hang') assert.ok(Date.now() - started >= STORE_TIMEOUT_MS - 50, 'only the store deadline ends it');
    const v = w.controller.view();
    assert.equal(w.wallet.sends.length, 0, script);
    assert.equal(v.row, 'KW29-unavailable', script);
    assert.equal(v.actions.send, false, script);
    assert.equal(v.attempt.record, null, script);
    assert.deepEqual(row.get(SINGLETON_KEY), before, script);
    // A second press while storage is refused still invokes no wallet.
    await w.controller.send();
    assert.equal(w.wallet.sends.length, 0, script);
    w.stop();
  }
});

test('reload restores the attempt only: no session, signature or grant; reconcile-only', async () => {
  const idb = memoryIndexedDB();
  const w = world({ indexedDB: idb });
  await w.controller.loadAttempt();
  await approve(w);

  w.wallet.mode = 'reject';
  await w.controller.send();
  const reloaded = world({ indexedDB: idb });
  await reloaded.controller.loadAttempt();
  const v = reloaded.controller.view();
  assert.equal(v.row, 'KW30-v2-reserved');
  assert.equal(v.attempt.record.version, 2);
  assert.equal(v.signed, null);
  assert.equal(v.actions.connectNative, false);
  assert.equal(v.actions.send, false);
  assert.equal(v.actions.hashInput, true);
  const raw = idb.databases.get(DB_NAME).stores.get(STORE_NAME).get(SINGLETON_KEY).raw;
  for (const secret of ['signerSignature', 'rawSignature', 'binding', 'topic', w.binding.slice(2)]) {
    assert.ok(!raw.includes(secret), secret);
  }
  assert.equal(serializeAttempt(JSON.parse(raw)), raw);
  w.stop();
});

test('a pending successor never inherits the prior attempt success display', async () => {
  const w = world();
  try {
    await w.controller.loadAttempt(); await approve(w);
    await w.controller.send(); w.chain.mine(); await w.controller.reconcile();
    assert.equal(w.controller.view().row, 'KW27');
    await w.controller.newChange();
    await approve(w, { change: { mode: 'add', bareText: bareKeyText(k3) } });

    w.wallet.submit = { mineBlock: false };
    await w.controller.send();
    const v = w.controller.view();
    assert.equal(v.attempt.record.status, 'hashKnown');
    assert.equal(v.attempt.outcome, null);
    assert.equal(v.row, 'KW23-pending');
  } finally { w.stop(); }
});

test('rollover (b): canonical outer failure with unchanged nonce needs the acknowledgement', async () => {
  const w = world();
  await w.controller.loadAttempt();
  await approve(w);

  w.wallet.submit = { outerStatus: '0x0' };
  await w.controller.send();
  w.chain.mine();
  await w.controller.reconcile();
  assert.equal(w.controller.view().row, 'KW25');
  assert.equal(w.controller.view().actions.newChange, true);
  await w.controller.newChange();
  const v = w.controller.view();
  assert.deepEqual(v.rollover, { needsAck: true, ack: false });
  await approve(w, { change: { mode: 'add', bareText: bareKeyText(k3) } });
  assert.equal(w.peer.signs, 1, 'no new native signing before the acknowledgement');
  w.controller.setRolloverAck(true);
  await approve(w, { change: { mode: 'add', bareText: bareKeyText(k3) } });
  assert.equal(w.controller.view().native.phase, 'verified');
  assert.equal(w.peer.signs, 2);
  w.stop();
});

/** A sent attempt whose outer transaction failed with status 0x0 at two confirmations, verified by reconcile. */
async function outerFailed(idb = memoryIndexedDB()) {
  const w = world({ indexedDB: idb });
  await w.controller.loadAttempt();
  await approve(w);

  w.wallet.submit = { outerStatus: '0x0' };
  await w.controller.send();
  w.chain.mine();
  await w.controller.reconcile();
  assert.equal(w.controller.view().row, 'KW25');
  return w;
}

test('rollover warning withdrawal at either send await prevents a successor wallet call', async () => {
  for (const boundary of ['pending-nonce', 'reservation']) {
    for (const restore of [false, true]) {
      const w = await outerFailed();
      try {
        await w.controller.newChange(); w.controller.setRolloverAck(true);
        await approve(w, { change: { mode: 'add', bareText: bareKeyText(k3) } });

        const withdraw = () => {
          w.controller.setRolloverAck(false);
          if (restore) w.controller.setRolloverAck(true);
        };
        if (boundary === 'pending-nonce') {
          w.chain.override = (method, _params, value) => { if (method === 'eth_getTransactionCount') withdraw(); return value; };
        } else {
          const cas = w.store.compareAndSet.bind(w.store);
          w.store.compareAndSet = async (...args) => { const result = await cas(...args); withdraw(); return result; };
        }
        await w.controller.send();
        assert.equal(w.wallet.sends.length, 1, `${boundary}/${restore}`);
      } finally { w.stop(); }
    }
  }
});

const staleReceipt = {
  reorged: (w, hash) => w.chain.reorg(BigInt(w.chain.state.receipts.get(hash).blockNumber)),
  removed: (w, hash) => w.chain.state.receipts.delete(hash),
  pending: (w, hash) => {
    w.chain.state.receipts.delete(hash);
    Object.assign(w.chain.state.txs.get(hash), { blockNumber: null, blockHash: null });
  },
  dropped: (w, hash) => { w.chain.state.receipts.delete(hash); w.chain.state.txs.delete(hash); },
};

test('rollover (b) is re-verified: a stale outer failure (reorged/removed/pending) never grants rollover', async () => {
  for (const [name, mutate] of Object.entries(staleReceipt)) {
    for (const path of ['reconcile', 'reload', 'direct']) {
      const idb = memoryIndexedDB();
      const sent = await outerFailed(idb);
      const hash = sent.controller.view().attempt.record.transactionHash;
      const label = `${name}/${path}`;
      mutate(sent, hash);
      let w = sent;
      if (path === 'reload') {
        w = world({ indexedDB: idb, chain: sent.chain });
        await w.controller.loadAttempt();
        assert.equal(w.controller.view().row, 'KW30-v2-terminal', label);
      }
      if (path !== 'direct') {
        await w.controller.reconcile();
        const v = w.controller.view();
        assert.equal(v.attempt.record.status, 'hashKnown', label);
        assert.equal(v.attempt.record.receipt, undefined, label);
        assert.equal(v.attempt.record.outcome, undefined, label);
        assert.equal(v.actions.newChange, false, label);
        assert.equal(v.actions.reconcile, true, label);
      }
      const signs = w.peer.signs, connects = nativeConnects(w);
      await w.controller.newChange();
      assert.equal(w.controller.view().rollover, null, label);
      assert.notEqual(w.controller.view().row, 'KW25', label);
      assert.equal(w.controller.view().actions.newChange, false, label);
      w.controller.setRolloverAck(true);
      await approve(w, { change: { mode: 'add', bareText: bareKeyText(k3) } });
      assert.equal(w.peer.signs, signs, label);
      assert.equal(nativeConnects(w), connects, label);
      assert.equal(w.controller.view().native.phase, 'idle', label);
      assert.equal(sent.wallet.sends.length, 1, label);
      sent.stop(); w.stop();
    }
  }
});

test('rollover (b) after reload re-verifies the still-canonical failed receipt before the acknowledgement', async () => {
  const idb = memoryIndexedDB();
  const sent = await outerFailed(idb);
  const w = world({ indexedDB: idb, chain: sent.chain });
  await w.controller.loadAttempt();
  assert.equal(w.controller.view().row, 'KW30-v2-terminal');
  const reads = w.chain.calls.length;
  await w.controller.newChange();
  const methods = w.chain.calls.slice(reads).map(([m]) => m);
  for (const m of ['eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getBlockByNumber']) {
    assert.ok(methods.includes(m), m);
  }
  assert.deepEqual(w.controller.view().rollover, { needsAck: true, ack: false });
  assert.equal(w.peer.signs, 0);
  sent.stop(); w.stop();
});

test('rollover (c): hashless unknown with independently advanced nonce resolves state, never execution', async () => {
  for (const exact of [true, false]) {
    const w = world();
    await w.controller.loadAttempt();
    await approve(w);

    w.wallet.mode = 'reject';
    await w.controller.send();
    w.chain.state.nonce += 1n;
    w.chain.state.keys = exact ? [k1, k2] : [k1, k3];
    w.chain.mine();
    await w.controller.reconcile();
    const v = w.controller.view();
    assert.equal(v.row, exact ? 'KW26-state-resolved' : 'KW26-state-advanced');
    assert.equal(v.attempt.record.status, exact ? 'stateResolved' : 'uncertain');
    assert.notEqual(v.row, 'KW27');
    await w.controller.newChange();
    assert.deepEqual(w.controller.view().rollover, { needsAck: false, ack: false });
    w.stop();
  }
});

test('hash-known pending attempts expose explicit rollover only after fresh independent nonce advance', async () => {
  for (const exact of [true, false]) {
    const w = world();
    try {
      await w.controller.loadAttempt(); await approve(w);
      w.wallet.submit = { mineBlock: false };
      await w.controller.send();
      assert.equal(w.chain.state.nonce, 0n, 'pending submission is not a confirmed operation');
      await w.controller.reconcile();
      assert.equal(w.controller.view().row, 'KW23-pending');
      assert.equal(w.controller.view().actions.newChange, false);
      w.chain.state.nonce = 1n;
      w.chain.state.keys = exact ? [k1, k2] : [k1, k3];
      w.chain.mine();
      await w.controller.reconcile();
      assert.equal(w.controller.view().row, exact ? 'KW26-state-resolved' : 'KW26-state-advanced');
      assert.equal(w.controller.view().actions.newChange, true);
      assert.notEqual(w.controller.view().attempt.record.status, 'succeeded');
      await w.controller.newChange();
      assert.deepEqual(w.controller.view().rollover, { needsAck: false, ack: false });
      assert.equal(w.wallet.sends.length, 1);
    } finally { w.stop(); }
  }
});

test('two sequential distinct changes in one database, including a fresh authorizer after self-removal', async () => {
  const idb = memoryIndexedDB();
  const w = world({ indexedDB: idb, keys: [k1] });
  await w.controller.loadAttempt();
  await approve(w);

  await w.controller.send();
  w.chain.mine();
  await w.controller.reconcile();
  assert.equal(w.controller.view().row, 'KW27');
  await w.controller.newChange();
  await approve(w, { key: k1, change: { mode: 'remove', removeKeyId: k1.keyId } });
  assert.equal(w.controller.view().selfRemoval, true);

  await w.controller.send();
  w.chain.mine();
  await w.controller.reconcile();
  assert.equal(w.controller.view().row, 'KW28');
  await w.controller.newChange();
  await approve(w, { key: k2, change: { mode: 'add', bareText: bareKeyText(k3) } });

  await w.controller.send();
  w.chain.mine();
  await w.controller.reconcile();
  assert.equal(w.controller.view().row, 'KW27');
  assert.equal(w.wallet.sends.length, 3);
  const ids = new Set();
  w.wallet.sends.forEach((tx) => ids.add(tx.data));
  assert.equal(ids.size, 3);
  assert.ok(idb.databases.get(DB_NAME).stores.get(STORE_NAME).get(SINGLETON_KEY).revision >= 9);
  assert.deepEqual(w.chain.state.keys.map((k) => k.keyId).sort(), [k2.keyId, k3.keyId].sort());
  w.stop();
});

test('delayed original hash never attaches to a successor attempt', async () => {
  const w = world();
  try {
    await w.controller.loadAttempt(); await approve(w);
    w.wallet.mode = 'hang';
    const timers = [];
    const set = w.controller.setTimer;
    w.controller.setTimer = (fn, ms) => (ms === WALLET_TIMEOUT_MS ? (timers.push(fn), -1) : set(fn, ms));
    const sending = w.controller.send();
    for (let i = 0; i < 100 && !w.wallet.release; i++) await tick();
    const release = w.wallet.release;
    timers[0]();
    await sending;
    const original = w.controller.view().attempt.record;
    assert.equal(original.status, 'unknown');
    // The signer nonce independently advances (keys as planned): explicit rollover (c), then a new request.
    w.chain.state.nonce += 1n; w.chain.state.keys = [k1, k2]; w.chain.mine();
    await w.controller.reconcile();
    await w.controller.newChange();
    w.wallet.mode = 'ok';
    w.controller.setTimer = set;
    await approve(w, { change: { mode: 'add', bareText: bareKeyText(k3) } });
    w.wallet.submit = { mineBlock: false };
    await w.controller.send();
    const successor = w.controller.view().attempt.record;
    assert.notEqual(successor.attemptId, original.attemptId);
    const raw = (await w.store.read()).raw;
    release();
    for (let i = 0; i < 20; i++) await tick();
    assert.equal((await w.store.read()).raw, raw);
    assert.equal(w.controller.view().attempt.record.transactionHash, successor.transactionHash);
    assert.notEqual(w.controller.view().row, 'KW22-late-hash');
    assert.equal(w.wallet.sends.length, 2);
  } finally { w.stop(); }
});

test('actual wallet nonce differing from the pending hint only updates actualWalletNonce; no resend', async () => {
  const w = world();
  try {
    await w.controller.loadAttempt(); await approve(w);
    w.chain.state.walletNonces[EXECUTOR] = 3;
    // The wallet itself picks a later nonce (another of its transactions intervened).
    w.wallet.observed = () => { w.chain.state.walletNonces[EXECUTOR] = 7; };
    await w.controller.send();
    w.chain.mine();
    await w.controller.reconcile();
    const v = w.controller.view();
    assert.equal(v.row, 'KW27');
    assert.equal(v.attempt.record.walletPendingNonce, '3');
    assert.equal(v.attempt.record.actualWalletNonce, '7');
    assert.equal(v.attempt.record.signerNonce, '0');
    assert.equal(v.actions.send, false);
    assert.equal(w.wallet.sends.length, 1);
  } finally { w.stop(); }
});

test('legacy v1 records: exact bytes on load, reload without signing capability, v1 reconciliation, v2 only at the new reservation', async () => {
  const idb = memoryIndexedDB();
  const w = world({ indexedDB: idb });
  let reloaded;
  try {
    await w.controller.loadAttempt(); await approve(w);
    await w.controller.send();
    const legacy = await seedLegacy(w);
    assert.equal(legacy.version, 1);
    const legacyRaw = (await w.store.read()).raw;
    reloaded = world({ indexedDB: idb, chain: w.chain });
    await reloaded.controller.loadAttempt();
    let v = reloaded.controller.view();
    assert.equal(v.row, 'KW30-hash');
    assert.equal(v.signed, null);
    assert.equal(v.actions.send, false);
    assert.equal(v.actions.connectNative, false);
    assert.equal((await reloaded.store.read()).raw, legacyRaw, 'loading never rewrites v1 bytes');
    w.chain.mine();
    await reloaded.controller.reconcile();
    v = reloaded.controller.view();
    assert.equal(v.row, 'KW27');
    const settledRaw = (await reloaded.store.read()).raw;
    const settled = JSON.parse(settledRaw);
    assert.equal(settled.version, 1);
    assert.equal(settled.outerGasLimit, '2200000');
    assert.equal(settled.status, 'succeeded');
    await reloaded.controller.newChange();
    assert.ok(reloaded.controller.view().rollover);
    assert.equal((await reloaded.store.read()).raw, settledRaw, 'rollover alone rewrites nothing');
    await approve(reloaded, { change: { mode: 'add', bareText: bareKeyText(k3) } });
    let expected = null;
    const cas = reloaded.store.compareAndSet.bind(reloaded.store);
    reloaded.store.compareAndSet = (prior, next) => { expected ??= prior; return cas(prior, next); };
    await reloaded.controller.send();
    assert.equal(expected.raw, settledRaw);
    const successor = JSON.parse((await reloaded.store.read()).raw);
    assert.equal(successor.version, 2);
    assert.equal('outerGasLimit' in successor, false);
    assert.equal(reloaded.wallet.sends.length, 1);
  } finally { w.stop(); reloaded?.stop(); }
});
