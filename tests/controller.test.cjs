'use strict';
// Production controller.js + wallet.js + model.js with a fake EIP-1193 wallet (send capture) and an
// independent read-only chain double. Every negative path asserts the captured send count directly.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const oracle = require('./support/oracle.cjs');
const { FakeChain, FakeWallet, PROXY, GWEI, legacyAttempt } = require('./support/fake-chain.cjs');

const root = path.resolve(__dirname, '..');
const vectors = JSON.parse(fs.readFileSync(path.join(root, 'tests/fixtures/registry-vectors.json'), 'utf8'));
const row = vectors.vectors.find((item) => item.name === 'd1-pattern');
const handoffText = JSON.stringify({ chainId: 137, expectedAddress: row.address, keyID: row.keyID,
  publicKey: row.publicPoint, recipe: vectors.recipe, salt: row.salt, version: 1 });
const ACCOUNT = '0x1111111111111111111111111111111111111111';
const OTHER = '0x2222222222222222222222222222222222222222';

// Unit double, not native storage evidence: one shared in-memory row with the production store's revision/raw
// compare-and-set, tombstone, conflict and abort semantics (microtask-async; `hold()` is a bounded barrier).
// Native IndexedDB transactions are proved separately by check-attempt-store.cjs in Chromium.
class MemoryAttemptDB {
  constructor() {
    this.row = { version: 1, revision: 0, raw: null, legacyRaw: null };
    this.mode = 'ok';
    this.legacy = null;
    this.gates = [];
    this.writes = 0;
  }
  get raw() { return this.row.raw; }
  get revision() { return this.row.revision; }
  /** Another page commits `raw` (null = explicit clear tombstone) at revision+1. */
  put(raw) { this.row = { ...this.row, revision: this.row.revision + 1, raw }; }
  /** The next compareAndSet waits until the returned release() is called. */
  hold() {
    let release;
    this.gates.push(new Promise((resolve) => { release = resolve; }));
    return release;
  }
}

class MemoryStore {
  constructor(db, validateRecord, StorageError) {
    Object.assign(this, { db, validateRecord, StorageError });
  }
  current() {
    if (this.db.mode === 'unavailable') throw new this.StorageError('unavailable');
    const row = this.db.row;
    if (row.raw !== null && !this.validateRecord(row.raw)) throw new this.StorageError('corrupt');
    return Object.freeze({ ...row });
  }
  async load() {
    await null;
    const snapshot = this.current();
    return { snapshot, legacyConflict: this.db.legacy !== null && this.db.legacy !== snapshot.legacyRaw };
  }
  async read() {
    await null;
    return this.current();
  }
  async compareAndSet(expected, nextRaw) {
    if (nextRaw !== null && !this.validateRecord(nextRaw)) throw new this.StorageError('invalid');
    const gate = this.db.gates.shift();
    if (gate) await gate;
    await null;
    // Compare and write in one synchronous step (the transaction).
    const current = this.current();
    if (current.revision !== expected.revision || current.raw !== expected.raw) return { committed: false, snapshot: current };
    if (this.db.mode !== 'ok') throw new this.StorageError('aborted');
    this.db.row = { ...current, revision: current.revision + 1, raw: nextRaw };
    this.db.writes++;
    return { committed: true, snapshot: Object.freeze({ ...this.db.row }) };
  }
}

class Clock {
  constructor() { this.t = 0; this.timers = new Map(); this.id = 0; }
  now() { return this.t; }
  setTimeout(fn, ms) { const id = ++this.id; this.timers.set(id, { at: this.t + ms, fn }); return id; }
  clearTimeout(id) { this.timers.delete(id); }
  async advance(ms) {
    const end = this.t + ms;
    for (;;) {
      const next = [...this.timers.entries()].filter(([, v]) => v.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      this.timers.delete(next[0]);
      this.t = next[1].at;
      await next[1].fn();
      await flush();
    }
    this.t = end;
  }
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

/** Unit double of the per-tab sessionStorage plan copy (a Map shared between "reloads" of the same tab). */
function memoryPlanStore(map = new Map()) {
  return { map, read: () => (map.has('plan') ? map.get('plan') : null), write: (t) => map.set('plan', t),
    remove: () => map.delete('plan') };
}

async function setup({ db = new MemoryAttemptDB(), chain = new FakeChain(), wallet, clock = new Clock(),
  accounts = [ACCOUNT], load = true, tab = 0, planStore } = {}) {
  const [{ RegistrationController, validateRecord }, { WalletManager }, model, { StorageError }] = await Promise.all([
    import('../controller.js'), import('../wallet.js'), import('../model.js'), import('../attempt-store.js')]);
  wallet = wallet || new FakeWallet(chain, { accounts });
  const win = Object.assign(new EventTarget(), { Event, ethereum: wallet });
  const views = [];
  let controller;
  const manager = new WalletManager({ win, config: { walletConnectProjectId: null, allowedDeploymentOrigin:
    model.ORIGIN }, origin: 'http://127.0.0.1:18763', loadWalletConnect: () => { throw new Error('no WC'); },
  onChange: (event) => controller && controller.walletChanged(event) });
  let n = 0;
  const store = new MemoryStore(db, validateRecord, StorageError);
  controller = new RegistrationController({ rpc: (m, p) => chain.rpc(m, p), wallet: manager, store, clock, planStore,
    uuid: () => `00000000-0000-4000-8000-${String(tab).padStart(4, '0')}${String(++n).padStart(8, '0')}`, onState: (v) => views.push(v) });
  manager.start();
  if (load) await controller.loadAttempt();
  return { controller, manager, wallet, chain, db, store, clock, views, model };
}

/** Import, connect and inspect: a coherent undeployed review is directly ready for the explicit action. */
async function ready(env) {
  const { controller } = env;
  if (controller.initializing) await controller.loadAttempt();
  controller.prepare(handoffText);
  controller.selectWallet('legacy');
  await controller.connect();
  await controller.inspect();
  assert.equal(controller.phase(), 'ready', 'fixture reaches ready');
}

const EXACT_REQUEST_KEYS = ['chainId', 'data', 'from', 'to', 'value'];
const planOf = (model) => model.buildPlan(model.parseHandoff(handoffText));

/**
 * A byte-preserved historical v1 attempt (frozen ceilings, user cap 1 POL) whose wallet transaction carried
 * `override`, seeded in storage and resumed read-only by a fresh controller (v1 attempts can no longer be created).
 */
async function resumeLegacy({ override = null, mine = 2, revert = false, chain = new FakeChain(), db = new MemoryAttemptDB(),
  submit = true } = {}) {
  const model = await import('../model.js');
  const legacy = legacyAttempt(chain, planOf(model), { override, submit });
  db.put(legacy.raw);
  if (mine) chain.mine({ revert });
  for (let i = 1; i < mine; i++) chain.mine();
  const env = await setup({ db, chain, load: false });
  await env.controller.loadAttempt();
  for (let i = 0; i < 6; i++) await flush();
  return { ...env, legacy };
}



test('numeric Polygon chain IDs survive send-time revalidation without weakening drift protection', async () => {
  for (const drift of [false, true]) {
    const env = await setup();
    env.wallet.chainId = 137;
    await ready(env);
    assert.equal(env.wallet.sends.length, 0, 'connecting and reviewing never send');
    if (drift) env.wallet.chainId = 1; // No event: the fresh read still has to catch the change.
    await env.controller.send();
    await flush();
    assert.equal(env.wallet.sends.length, drift ? 0 : 1);
    if (!drift) assert.equal(env.wallet.sends[0].chainId, '0x89');
  }
});

test('late numeric chain responses cannot revive readiness after disconnect or provider reselection', { timeout: 5000 }, async () => {
  for (const action of ['disconnect', 'reselect']) for (const timing of ['pending', 'resolved']) {
    const env = await setup();
    await ready(env);
    const next = new FakeWallet(env.chain, { accounts: [ACCOUNT], chainId: 137 });
    env.manager.announce({ info: { uuid: 'next', name: 'Next' }, provider: next });
    const before = { ...env.db.row };
    const original = env.wallet.request.bind(env.wallet);
    let release, entered;
    const chainResponse = new Promise((resolve) => { release = resolve; });
    const chainRequested = new Promise((resolve) => { entered = resolve; });
    env.wallet.request = (request) => {
      if (request.method !== 'eth_chainId') return original(request);
      entered();
      return chainResponse;
    };
    const pending = env.controller.send();
    await chainRequested;
    assert.equal(env.controller.sendLock, true);
    const viewStart = env.views.length;
    if (timing === 'resolved') release(137); // normalChain's reaction is queued but has not run.
    if (action === 'disconnect') await env.controller.disconnect();
    else {
      env.controller.selectWallet('eip6963:next');
      await env.controller.connect();
      assert.equal(env.manager.provider, next);
      assert.equal(env.manager.status, 'connected');
    }
    release(137);
    assert.equal(await pending, false, `${action}/${timing}: stale send refused`);
    await flush();
    assert.equal(env.controller.review, null);
    assert.equal(env.controller.canSend(), false);
    assert.ok(env.views.slice(viewStart).every((view) => !view.canSend && !view.review));
    assert.equal(env.wallet.sends.length + next.sends.length, 0);
    assert.deepEqual(env.db.row, before, 'no attempt admitted or replaced');
    assert.equal(env.db.writes, 0);
    await env.controller.disconnect();
  }
});

test('invalid or rejected pre-send chain responses invalidate readiness without admission or sends', async () => {
  const { MESSAGES } = await import('../controller.js');
  for (const value of [NaN, Number.MAX_SAFE_INTEGER + 1, null, new Error('chain request rejected')]) {
    const env = await setup();
    await ready(env);
    const before = { ...env.db.row };
    const original = env.wallet.request.bind(env.wallet);
    let reads = 0;
    env.wallet.request = (request) => {
      if (request.method !== 'eth_chainId') return original(request);
      reads++;
      return value instanceof Error ? Promise.reject(value) : Promise.resolve(value);
    };
    assert.equal(await env.controller.send(), false);
    assert.equal(reads, 1, 'refusal reached the fresh wallet chain read');
    assert.equal(env.controller.sendNotice, MESSAGES.drift);
    assert.equal(env.controller.review, null);
    assert.equal(env.controller.canSend(), false);
    assert.equal(env.wallet.sends.length, 0);
    assert.deepEqual(env.db.row, before);
    assert.equal(env.db.writes, 0);
    await env.controller.disconnect();
  }
});

test('explicit flow sends exactly one identity-only transaction decoding to the selected nonzero-salt row', async () => {
  const env = await setup();
  const { controller, wallet, chain } = env;
  assert.equal(controller.phase(), 'empty');
  controller.prepare(handoffText);
  assert.equal(controller.phase(), 'disconnected');
  assert.deepEqual(wallet.requests, [], 'import/discovery makes no wallet request');
  controller.selectWallet('legacy');
  await controller.connect();
  assert.equal(controller.phase(), 'connected');
  await controller.inspect();
  // No cap, fee consent or checkbox: a coherent operation review is directly ready for the explicit action.
  assert.equal(controller.phase(), 'ready');
  const view = controller.view();
  assert.deepEqual(Object.keys(view.review).sort(), ['block', 'from'], 'review is operation identity only');
  for (const key of ['cap', 'consent']) assert.equal(key in view, false, `no ${key} in the view`);
  for (const key of ['setCap', 'setConsent']) assert.equal(typeof controller[key], 'undefined', `no ${key} command`);
  assert.equal(chain.calls.some((c) => ['eth_estimateGas', 'eth_maxPriorityFeePerGas'].includes(c.method)), false,
    'readiness has no gas/fee RPC dependency');
  assert.equal(wallet.sends.length, 0, 'inspection never sends');
  // Rapid repeated clicks: one request total.
  const sends = [controller.send(), controller.send(), controller.send()];
  await Promise.all(sends);
  await flush();
  assert.equal(wallet.sends.length, 1);
  const tx = wallet.sends[0];
  assert.deepEqual(Object.keys(tx).sort(), EXACT_REQUEST_KEYS, 'exactly from/to/data/value/chainId');
  for (const key of ['nonce', 'gas', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas']) {
    assert.equal(key in tx, false, `${key} is the wallet's choice, never requested`);
  }
  assert.equal(tx.chainId, '0x89');
  assert.equal(tx.value, '0x0');
  assert.equal(tx.to, env.model.FACTORY);
  assert.equal(tx.from, ACCOUNT);
  const decoded = oracle.decodeDeploy(tx.data, PROXY);
  assert.ok(decoded.exact);
  assert.equal(decoded.salt, row.salt, 'the selected saved salt, not zero');
  assert.equal(decoded.keyID, row.keyID);
  assert.equal(decoded.owner, '0x' + '00'.repeat(20));
  assert.equal(oracle.derive(row.publicPoint, row.salt, PROXY).calldata, tx.data);
  // The admitted record is the closed v2 schema with the pending-nonce hint, never caps or fee requests.
  const record = JSON.parse(env.db.raw);
  assert.equal(record.version, 2);
  assert.deepEqual(Object.keys(record).sort(), ['address', 'chainId', 'dataHash', 'effectiveNonce', 'from', 'hash', 'id',
    'manifest', 'observed', 'reason', 'replacementHash', 'salt', 'sendEntered', 'state', 'submission', 'to',
    'transaction', 'version']);
  assert.deepEqual(record.transaction, { chainId: '0x89', value: '0x0', nonce: '0x0' });
  assert.equal(controller.phase(), 'txPending');
  await controller.send();
  assert.equal(wallet.sends.length, 1, 'locked while unresolved');
  // Pending → confirmed success after two confirmations and readback.
  chain.mine();
  await controller.refresh();
  assert.equal(controller.phase(), 'txPending', 'one confirmation is not success');
  chain.mine();
  await controller.refresh();
  assert.equal(controller.phase(), 'success');
  assert.equal(controller.view().settlement.readback, 'deployed');
  assert.equal(chain.writes, 1, 'refresh paths never submit');
  // Explicit clear with cancel then confirm.
  controller.requestClear();
  controller.cancelClear();
  assert.ok(env.db.raw, 'cancel retains bytes');
  controller.requestClear();
  await controller.confirmClear();
  assert.equal(env.db.raw, null);
  assert.equal(controller.phase(), 'connected', 'returns to the public plan; fresh inspection required');
  await controller.inspect();
  assert.equal(controller.phase(), 'deployed', 'already-deployed readback offers no send');
  assert.equal(controller.canSend(), false);
});

test('connect, switch and inspect never send; account/chain/input/provider/disconnect invalidate readiness', async () => {
  const env = await setup();
  const { controller, wallet, chain } = env;
  wallet.chainId = '0x1';
  controller.prepare(handoffText);
  controller.selectWallet('legacy');
  await controller.connect();
  assert.equal(controller.phase(), 'wrongChain');
  wallet.behavior.switch = '4902';
  await controller.switchPolygon();
  assert.equal(controller.view().wallet.error.code, 'switchUnsupported');
  wallet.behavior.switch = 'reject';
  await controller.switchPolygon();
  assert.equal(controller.view().wallet.error.code, 'switchRejected');
  wallet.behavior.switch = 'ok';
  await controller.switchPolygon();
  assert.equal(controller.phase(), 'connected');
  assert.deepEqual(wallet.requests.filter((r) => r.method === 'wallet_switchEthereumChain').map((r) => r.params),
    [[{ chainId: '0x89' }], [{ chainId: '0x89' }], [{ chainId: '0x89' }]], 'only 0x89, never add-chain');
  await controller.inspect();
  const next = new FakeWallet(chain, { accounts: [ACCOUNT] });
  env.manager.announce({ info: { uuid: 'next', name: 'Next' }, provider: next });
  for (const [name, change] of Object.entries({
    account: () => wallet.emitAccounts([OTHER]),
    chain: () => wallet.emitChain('0x1'),
    input: () => controller.inputEdited(),
    provider: () => controller.selectWallet('eip6963:next'),
    disconnect: () => wallet.emit('disconnect'),
  })) {
    if (controller.phase() !== 'ready') {
      if (!controller.plan) controller.prepare(handoffText);
      if (controller.wallet.provider !== wallet) controller.selectWallet('legacy');
      if (controller.wallet.status !== 'connected') {
        wallet.chainId = '0x89';
        wallet.accounts = [ACCOUNT];
        await controller.connect();
      }
      if (!controller.review) await controller.inspect();
    }
    assert.equal(controller.phase(), 'ready', `before ${name}`);
    change();
    assert.equal(controller.canSend(), false, `${name} invalidates readiness`);
    assert.equal(controller.review, null, `${name} clears the review`);
    await controller.send();
  }
  assert.equal(wallet.sends.length + next.sends.length, 0);
  assert.equal(chain.writes, 0);
});

test('a late inspection result after a generation change cannot restore readiness', async () => {
  const env = await setup();
  const { controller, wallet, chain } = env;
  controller.prepare(handoffText);
  controller.selectWallet('legacy');
  await controller.connect();
  const original = chain.rpc.bind(chain);
  let release;
  chain.rpc = async (m, p) => { if (m === 'eth_call') await new Promise((r) => { release = r; }); return original(m, p); };
  const pending = controller.inspect();
  await flush();
  assert.equal(controller.phase(), 'inspecting');
  wallet.emitAccounts([OTHER]);
  release();
  await pending;
  assert.equal(controller.review, null);
  assert.equal(controller.inspection.status, 'idle');
  assert.equal(wallet.sends.length, 0);
});

test('pre-send drift, nonce lookup failure and storage failure yield zero sends and require fresh review', async () => {
  const { MESSAGES } = await import('../controller.js');
  const drifts = {
    deployedNow: (env) => { env.chain.preDeploy(planOf(env.model)); },
    walletAccount: (env) => { env.wallet.accounts = [OTHER]; },
    walletChain: (env) => { env.wallet.chainId = '0x1'; },
    code: (env) => { env.chain.faults.factoryCode = true; },
    block: (env) => { env.chain.faults.blockFlip = true; },
    pendingNonceUnavailable: (env) => { env.chain.faults.pendingNonce = true; },
    pendingNonceMalformed: (env) => {
      const original = env.chain.rpc.bind(env.chain);
      env.chain.rpc = async (m, p) => (m === 'eth_getTransactionCount' ? '0x01' : original(m, p));
    },
    storage: (env) => { env.db.mode = 'full'; },
  };
  for (const [name, mutate] of Object.entries(drifts)) {
    const env = await setup();
    await ready(env);
    mutate(env);
    assert.equal(await env.controller.send(), false, name);
    assert.equal(env.wallet.sends.length, 0, `${name}: zero sends`);
    assert.equal(env.controller.canSend(), false, `${name}: readiness invalidated`);
    if (name !== 'storage') assert.equal(env.db.raw, null, `${name}: nothing admitted`);
    if (name === 'storage') assert.equal(env.controller.phase(), 'storageError');
    if (name === 'deployedNow') assert.equal(env.controller.phase(), 'deployed');
    if (name.startsWith('pendingNonce')) {
      assert.equal(env.controller.sendNotice, MESSAGES.nonce, `${name}: no invented nonce`);
      assert.equal(env.db.writes, 0);
    }
  }
});

test('nonce and fee changes since review are wallet authority: the fresh pending nonce is saved as a hint only', async () => {
  for (const [name, mutate, hint] of [
    ['nonce-changed', (env) => { env.chain.faults.pendingNonceBump = 3; }, '0x3'],
    ['estimate-changed', (env) => { env.chain.estimate = 900_000n; }, '0x0'],
    ['tip-changed', (env) => { env.chain.tip = 50n * GWEI; }, '0x0'],
    ['base-fee-changed', (env) => { env.chain.baseFee = 300n * GWEI; }, '0x0'],
    ['fee-rpc-unavailable', (env) => Object.assign(env.chain.faults, { estimate: true, noTip: true, noBaseFee: true }), '0x0'],
  ]) {
    const env = await setup();
    await ready(env);
    mutate(env);
    assert.equal(await env.controller.send(), true, name);
    await flush();
    assert.equal(env.wallet.sends.length, 1, `${name}: one send`);
    assert.deepEqual(Object.keys(env.wallet.sends[0]).sort(), EXACT_REQUEST_KEYS, `${name}: identity-only request`);
    const record = JSON.parse(env.db.raw);
    assert.equal(record.transaction.nonce, hint, `${name}: freshest pending nonce is the stored hint`);
    assert.equal(env.controller.phase(), 'txPending');
  }
});

test('account, chain or disconnect at every send-path await boundary yields zero sends and no retained admission', async () => {
  const points = {
    'wallet-accounts': { wallet: 'eth_accounts' },
    'wallet-chain': { wallet: 'eth_chainId' },
    'inspection-read': { rpc: 'eth_getCode' },
    'pending-nonce-read': { rpc: 'eth_getTransactionCount' },
  };
  const events = {
    account: (env) => env.wallet.emitAccounts([OTHER]),
    chain: (env) => env.wallet.emitChain('0x1'),
    disconnect: (env) => env.wallet.emit('disconnect'),
  };
  for (const [point, where] of Object.entries(points)) for (const [name, fire] of Object.entries(events)) {
    const env = await setup();
    await ready(env);
    let fired = false;
    const once = () => { if (!fired) { fired = true; fire(env); } };
    if (where.wallet) {
      const original = env.wallet.request.bind(env.wallet);
      env.wallet.request = async (request) => {
        if (request.method === where.wallet) once();
        return original(request);
      };
    } else {
      const original = env.chain.rpc.bind(env.chain);
      env.chain.rpc = async (m, p) => {
        if (m === where.rpc) once();
        return original(m, p);
      };
    }
    assert.equal(await env.controller.send(), false, `${point}/${name}`);
    await flush();
    assert.ok(fired, `${point}/${name}: the boundary was reached`);
    assert.equal(env.wallet.sends.length, 0, `${point}/${name}: zero sends`);
    assert.equal(env.db.raw, null, `${point}/${name}: nothing admitted`);
    assert.equal(env.controller.canSend(), false, `${point}/${name}: readiness invalidated`);
  }
});

test('an event during revalidation (before the request) yields zero sends', async () => {
  const env = await setup();
  await ready(env);
  const original = env.chain.rpc.bind(env.chain);
  env.chain.rpc = async (m, p) => {
    if (m === 'eth_getTransactionCount') env.wallet.emitChain('0x1');
    return original(m, p);
  };
  assert.equal(await env.controller.send(), false);
  assert.equal(env.wallet.sends.length, 0);
  assert.equal(env.db.raw, null);
});

test('rejection, transport error, malformed hash, timeout and late hash outcomes', async () => {
  for (const [mode, expected] of [['reject', 'rejected'], ['error', 'unknown'], ['malformed', 'unknown']]) {
    const env = await setup();
    await ready(env);
    env.wallet.behavior.send = mode;
    await env.controller.send();
    await flush();
    assert.equal(env.controller.phase(), expected, mode);
    assert.equal(env.wallet.sends.length, 1);
    assert.equal(env.controller.view().clearable, expected === 'rejected', `${mode} clearability`);
    await env.controller.send();
    assert.equal(env.wallet.sends.length, 1, `${mode}: no automatic retry`);
  }
  // Timeout then a late hash after account and chain events: the original attempt tracks it.
  const env = await setup();
  await ready(env);
  env.wallet.behavior.send = 'deferred';
  await env.controller.send();
  assert.equal(env.controller.phase(), 'walletPending');
  env.wallet.emitAccounts([OTHER]);
  env.wallet.emitChain('0x1');
  assert.equal(env.controller.phase(), 'walletPending', 'events cannot discard the attempt');
  await env.clock.advance(60_000);
  assert.equal(env.controller.phase(), 'unknown');
  assert.equal(env.controller.view().attempt.reason, 'send-timeout');
  env.controller.requestClear();
  assert.equal(env.controller.view().clearPending, false, 'unknown cannot be cleared');
  env.wallet.releaseSend();
  await flush();
  assert.equal(env.controller.phase(), 'txPending', 'late hash becomes pending on the frozen attempt');
  assert.equal(env.wallet.sends.length, 1);
  assert.equal(JSON.parse(env.db.raw).hash, env.controller.attempt.hash);
});

test('v2 settlement: wallet-selected nonce/gas/fees settle normally; identity, readback and reorg stay unresolved', async () => {
  const HIGH_FEE = '0x' + (500n * GWEI).toString(16);
  const cases = {
    'wallet-nonce': { override: { nonce: '0x5' }, expect: 'success', effectiveNonce: '0x5' },
    'wallet-gas-higher': { override: { gas: '0x' + (5_000_000n).toString(16) }, expect: 'success' },
    'wallet-fee-higher': { override: { maxFeePerGas: HIGH_FEE, maxPriorityFeePerGas: '0x' + (60n * GWEI).toString(16) },
      expect: 'success' },
    'wallet-fee-lower': { override: { maxFeePerGas: '0x' + (31n * GWEI).toString(16), maxPriorityFeePerGas: '0x1' },
      expect: 'success' },
    'wallet-legacy-gasprice': { feeMode: 'legacy', expect: 'success' },
    'wallet-fee-higher-reverted': { override: { maxFeePerGas: HIGH_FEE }, revert: true, expect: 'failed' },
    'wallet-fee-higher-reorg': { override: { maxFeePerGas: HIGH_FEE }, reorgAfter: true, expect: 'txPending' },
    reverted: { revert: true, expect: 'failed' },
    'readback-mismatch': { faults: { deployWrongKey: true }, expect: 'unknown' },
    'identity-mismatch': { override: { data: '0x4af63f02' + '00'.repeat(64) }, expect: 'unknown' },
    reorg: { reorgAfter: true, expect: 'txPending' },
  };
  for (const [name, spec] of Object.entries(cases)) {
    const env = await setup();
    await ready(env);
    Object.assign(env.chain.faults, spec.faults || {});
    env.wallet.override = spec.override || null;
    if (spec.feeMode) env.wallet.feeMode = spec.feeMode;
    await env.controller.send();
    await flush();
    await env.controller.refresh();
    env.chain.mine({ revert: spec.revert });
    env.chain.mine();
    await env.controller.refresh();
    if (spec.reorgAfter) {
      env.chain.reorg(2);
      await env.controller.refresh();
    }
    const view = env.controller.view();
    assert.equal(view.phase, spec.expect, name);
    assert.notEqual(view.phase, 'walletOverride', `${name}: wallet fee choices never create walletOverride`);
    if (spec.effectiveNonce) assert.equal(view.attempt.effectiveNonce, spec.effectiveNonce, 'effective nonce from hash');
    if (spec.expect === 'success') {
      assert.equal(view.clearable, true, `${name}: resolved success is clearable`);
      assert.ok(view.attempt.observed, `${name}: verified observations are kept internally`);
    }
    if (spec.expect === 'failed') assert.equal(view.clearable, true, `${name}: canonical failure is clearable`);
    if (spec.expect === 'unknown') assert.equal(view.clearable, false, `${name}: unknown stays locked`);
    assert.equal(env.wallet.sends.length, 1, `${name}: one send`);
    assert.equal(env.chain.writes, 1, `${name}: refresh never submits`);
    const record = JSON.parse(env.db.raw);
    assert.equal(record.version, 2);
    assert.deepEqual(record.transaction, { chainId: '0x89', value: '0x0', nonce: '0x0' }, `${name}: request hint immutable`);
  }
});

test('v2 receipt that contradicts the fetched transaction stays UNKNOWN and locked', async () => {
  for (const [name, tamper] of Object.entries({
    'gas-used-above-gas': (m, v) => (m === 'eth_getTransactionReceipt' && v ? { ...v, gasUsed: '0x' + (10n ** 8n).toString(16) } : v),
    'price-above-max': (m, v) => (m === 'eth_getTransactionReceipt' && v
      ? { ...v, effectiveGasPrice: '0x' + (10n ** 13n).toString(16) } : v),
    'inclusion-differs': (m, v) => (m === 'eth_getTransactionByHash' && v ? { ...v, blockHash: '0x' + 'ab'.repeat(32) } : v),
    'partial-fees': (m, v) => (m === 'eth_getTransactionByHash' && v ? { ...v, maxFeePerGas: null } : v),
  })) {
    const env = await setup();
    await ready(env);
    await env.controller.send();
    await flush();
    env.chain.mine();
    env.chain.mine();
    const original = env.chain.rpc.bind(env.chain);
    env.chain.rpc = async (m, p) => tamper(m, await original(m, p));
    await env.controller.refresh();
    const view = env.controller.view();
    assert.equal(view.phase, 'unknown', name);
    assert.ok(['receipt', 'evidence'].includes(view.attempt.reason), `${name}: ${view.attempt.reason}`);
    assert.equal(view.clearable, false, `${name}: not a clearable failure`);
    assert.equal(env.controller.locked(), true);
    assert.equal(env.wallet.sends.length, 1, `${name}: no retry`);
  }
});

test('historical v1 records keep frozen-ceiling classification: within-limit success, overrides locked', async () => {
  const BIGFEE = '0x' + (100n * GWEI).toString(16);
  const BIG = '0x' + (900_000n).toString(16);
  const cases = {
    'nonce-overridden': { override: { nonce: '0x5' }, expect: 'success', differs: true },
    'gas-overridden-within-limits': { override: { gas: '0x61a80' }, expect: 'success', differs: true },
    'fee-overridden-deployed': { override: { maxFeePerGas: BIGFEE }, expect: 'walletOverride', readback: 'deployed' },
    'gas-overridden-deployed': { override: { gas: BIG }, expect: 'walletOverride', readback: 'deployed' },
    'fee-overridden-not-deployed': { override: { maxFeePerGas: BIGFEE }, revert: true, expect: 'walletOverride',
      readback: 'not-deployed' },
    'gas-overridden-unknown': { override: { gas: BIG }, reorgAfter: true, expect: 'walletOverride', readback: 'unknown' },
    reverted: { revert: true, expect: 'failed' },
  };
  for (const [name, spec] of Object.entries(cases)) {
    const env = await resumeLegacy({ override: spec.override, revert: spec.revert });
    if (spec.reorgAfter) {
      env.chain.reorg(2);
      await env.controller.refresh();
    }
    const view = env.controller.view();
    assert.equal(view.phase, spec.expect, name);
    if (spec.readback) assert.equal(view.settlement.readback, spec.readback, `${name} readback`);
    if (spec.differs) assert.equal(view.settlement.observed.differs, true, `${name} shows requested/observed`);
    if (spec.expect === 'walletOverride') {
      assert.equal(view.clearable, false, `${name} cannot clear`);
      assert.ok(view.attempt.observed, `${name} records observed values`);
      env.controller.requestClear();
      assert.equal(env.controller.view().clearPending, false);
    }
    if (spec.expect === 'failed') assert.ok(view.settlement.paidFee > 0n, 'v1 status0 paid gas evidence kept');
    assert.equal(env.wallet.sends.length, 0, `${name}: resume never sends`);
    assert.equal(env.chain.writes, 1, `${name}: refresh never submits`);
    const record = JSON.parse(env.db.raw);
    assert.equal(record.version, 1, `${name}: never converted`);
    assert.equal(record.transaction.gas, '0x75300', `${name}: frozen request immutable`);
    assert.equal(record.capWei, env.legacy.record.capWei, `${name}: cap retained`);
  }
});

test('replacement scan: identical replacement, proved cancellation, no candidate, unverified nonce', async () => {
  async function dropAndReplace(env, kind, verify = true) {
    await env.controller.send();
    await flush();
    if (verify) await env.controller.refresh(); // records the effective nonce from the returned hash
    const original = env.chain.mempool.pop();
    env.chain.txs.delete(original.hash);
    if (kind === 'replacement') {
      env.chain.submit({ from: original.from, to: original.to, data: original.input, value: '0x0', nonce: original.nonce,
        gas: original.gas, maxFeePerGas: original.maxFeePerGas, maxPriorityFeePerGas: original.maxPriorityFeePerGas });
    } else if (kind === 'cancelled') {
      env.chain.submit({ from: original.from, to: original.from, data: '0x', value: '0x0', nonce: original.nonce,
        gas: '0x5208', maxFeePerGas: original.maxFeePerGas, maxPriorityFeePerGas: original.maxPriorityFeePerGas });
    } else {
      env.chain.nonces.set(original.from.toLowerCase(), BigInt(original.nonce) + 1n);
    }
    env.chain.mine();
    env.chain.mine();
    await env.controller.refresh();
    return env.controller.view();
  }
  let env = await setup();
  await ready(env);
  let view = await dropAndReplace(env, 'replacement');
  assert.equal(view.phase, 'success');
  assert.ok(view.attempt.replacementHash && view.attempt.replacementHash !== view.attempt.hash, 'lineage kept');
  env = await setup();
  await ready(env);
  view = await dropAndReplace(env, 'cancelled');
  assert.equal(view.phase, 'failed');
  assert.equal(view.attempt.reason, 'cancelled');
  env = await setup();
  await ready(env);
  view = await dropAndReplace(env, 'none');
  assert.equal(view.phase, 'unknown');
  env = await setup();
  await ready(env);
  view = await dropAndReplace(env, 'cancelled', false);
  assert.equal(view.phase, 'unknown', 'requested nonce alone is not cancellation proof');
  assert.equal(env.wallet.sends.length, 1);
});

test('v2 replacement scan never uses the nonce hint: an unverified hash disappearance stays unresolved', async () => {
  const cases = {
    'hint-nonce success, wallet chose the hint': { walletNonce: null, revert: false },
    'hint-nonce revert, wallet chose another nonce': { walletNonce: '0x1', revert: true },
    'hint-nonce success, wallet chose another nonce': { walletNonce: '0x1', revert: false },
  };
  for (const [name, spec] of Object.entries(cases)) {
    const env = await setup();
    await ready(env);
    if (spec.walletNonce) env.wallet.override = { nonce: spec.walletNonce };
    await env.controller.send();
    await flush();
    const hash = env.controller.attempt.hash;
    assert.ok(hash, `${name}: wallet hash recorded`);
    assert.equal(env.controller.attempt.transaction.nonce, '0x0', `${name}: pending-nonce hint`);
    // Our own hash vanishes before any refresh verified its effective nonce.
    const original = env.chain.mempool.pop();
    env.chain.txs.delete(original.hash);
    const other = env.chain.submit({ from: original.from, to: original.to, data: original.input, value: '0x0',
      nonce: '0x0', gas: original.gas, maxFeePerGas: original.maxFeePerGas,
      maxPriorityFeePerGas: original.maxPriorityFeePerGas });
    env.chain.mine({ revert: spec.revert });
    env.chain.mine();
    env.chain.mine();
    await env.controller.refresh();
    const view = env.controller.view();
    assert.equal(view.phase, 'unknown', `${name}: unresolved`);
    assert.equal(view.attempt.reason, 'unverified-nonce', name);
    assert.equal(view.attempt.replacementHash, null, `${name}: no replacement lineage`);
    assert.equal(view.attempt.effectiveNonce, null, `${name}: no effective nonce`);
    assert.equal(view.clearable, false, `${name}: not clearable`);
    env.controller.requestClear();
    assert.equal(env.controller.view().clearPending, false);
    const stored = JSON.parse(env.db.raw);
    assert.equal(stored.state, 'unknown', `${name}: stored unknown`);
    assert.equal(stored.hash, hash);
    assert.equal(stored.replacementHash, null);
    assert.notEqual(stored.hash, other);
    assert.ok(!env.chain.calls.some((c) => c.method === 'eth_getBlockByNumber' && c.params[1] === true),
      `${name}: no replacement scan`);
    assert.equal(env.wallet.sends.length, 1, `${name}: zero further wallet sends`);
  }
  // Not sticky: once our own hash is readable again, ordinary settlement resumes from that hash.
  const env = await setup();
  await ready(env);
  await env.controller.send();
  await flush();
  const own = env.chain.txs.get(env.controller.attempt.hash);
  env.chain.txs.delete(own.hash);
  await env.controller.refresh();
  assert.equal(env.controller.phase(), 'unknown', 'not yet readable: unresolved');
  env.chain.txs.set(own.hash, own);
  await env.controller.refresh();
  assert.equal(env.controller.phase(), 'txPending', 'readable again: pending on its own hash');
  env.chain.mine();
  env.chain.mine();
  await env.controller.refresh();
  assert.equal(env.controller.phase(), 'success');
  assert.equal(env.controller.attempt.replacementHash, null);
  assert.equal(env.wallet.sends.length, 1);
});

test('reload resume: pending/override/unknown stay locked; tampered and unavailable storage fail closed', async () => {
  // Pending record reloads before any send UI, read-only, with the wallet disconnected.
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  let env = await setup({ db, chain });
  await ready(env);
  await env.controller.send();
  await flush();
  const saved = db.raw;
  env = await setup({ db, chain, load: false });
  await env.controller.loadAttempt();
  assert.equal(env.controller.phase(), 'resuming', 'no stored outcome before the first read-only refresh');
  await flush();
  assert.equal(env.controller.phase(), 'txPending');
  assert.equal(env.wallet.requests.length, 0, 'no reconnect or wallet use on resume');
  chain.mine();
  chain.mine();
  await env.controller.refresh();
  assert.equal(env.controller.phase(), 'success');
  assert.equal(chain.writes, 1);

  // walletPending at reload (send entered, no hash) is UNKNOWN; manual hash only reconciles reads.
  const record = JSON.parse(saved);
  const hashless = { ...record, hash: null, state: 'walletPending' };
  const store2 = new MemoryAttemptDB();
  store2.put(JSON.stringify(hashless));
  env = await setup({ db: store2, chain, load: false });
  await env.controller.loadAttempt();
  assert.equal(env.controller.phase(), 'unknown');
  await env.controller.enterHash('0x' + 'ab'.repeat(32));
  assert.ok(env.controller.view().manualHashError);
  await env.controller.enterHash(record.hash);
  assert.equal(env.controller.phase(), 'success');
  assert.equal(env.wallet.sends.length, 0);

  // Tampered records: error, zero send, bytes untouched.
  const tamper = {
    address: { ...record, address: vectors.vectors[0].address },
    dataHash: { ...record, dataHash: '0x' + '00'.repeat(32) },
    cap: { ...record, capWei: '0x1' },
    mixedV1Fields: { ...record, capWei: '0xde0b6b3a7640000', maxTotal: '0x1' },
    txGas: { ...record, transaction: { ...record.transaction, gas: '0x75300' } },
    txNonceMissing: { ...record, transaction: { chainId: '0x89', value: '0x0' } },
    v2Override: { ...record, state: 'walletOverride' },
    v2ObservedPriorityAboveMax: { ...record, observed: { nonce: '0x0', gas: '0x1', maxFeePerGas: '0x1',
      maxPriorityFeePerGas: '0x2' } },
    v2ObservedZeroGas: { ...record, observed: { nonce: '0x0', gas: '0x0', maxFeePerGas: '0x1',
      maxPriorityFeePerGas: '0x1' } },
    unknownVersion: { ...record, version: 3 },
    v1WithoutCaps: { ...record, version: 1 },
    extra: { ...record, extra: true },
    manifest: { ...record, manifest: { ...record.manifest, salt: '0x' + '00'.repeat(32) } },
    pendingWithoutHash: { ...record, hash: null, state: 'pending' },
    hashlessEffectiveNonce: { ...record, hash: null, state: 'unknown', reason: 'reload', effectiveNonce: '0x0' },
    cancelWithoutLineage: { ...record, state: 'failed', reason: 'cancelled', effectiveNonce: '0x0' },
  };
  for (const [name, value] of Object.entries(tamper)) {
    const store = new MemoryAttemptDB();
    const text = JSON.stringify(value);
    store.put(text);
    const t = await setup({ db: store, load: false });
    await t.controller.loadAttempt();
    assert.equal(t.controller.phase(), 'resumeError', name);
    assert.equal(t.controller.view().resumeError.message, '保存情報を検証できません');
    t.controller.prepare(handoffText);
    t.controller.selectWallet('legacy');
    await t.controller.connect();
    await t.controller.inspect();
    assert.equal(t.controller.canSend(), false, `${name}: no send`);
    t.controller.requestClear();
    await t.controller.confirmClear();
    assert.equal(store.raw, text, `${name}: never silently deleted or rewritten`);
    assert.equal(store.writes, 0, `${name}: no write`);
  }

  // Storage unavailable: storageError and no send.
  const blocked = new MemoryAttemptDB();
  blocked.mode = 'unavailable';
  const t = await setup({ db: blocked, load: false });
  await t.controller.loadAttempt();
  assert.equal(t.controller.phase(), 'storageError');

  // A historical v1 walletOverride reloads locked even when deployed; its bytes are never converted.
  const o = await resumeLegacy({ override: { maxFeePerGas: '0x' + (100n * GWEI).toString(16) } });
  assert.equal(o.controller.phase(), 'walletOverride');
  const overrideBytes = o.db.raw;
  const reloaded = await setup({ db: o.db, chain: o.chain, load: false });
  await reloaded.controller.loadAttempt();
  await flush();
  await flush();
  assert.equal(reloaded.controller.phase(), 'walletOverride');
  assert.equal(reloaded.controller.view().settlement.readback, 'deployed');
  reloaded.controller.requestClear();
  assert.equal(reloaded.controller.view().clearPending, false);
  assert.equal(reloaded.wallet.sends.length + o.wallet.sends.length, 0);
  assert.equal(JSON.parse(o.db.raw).version, 1);
  assert.equal(JSON.parse(o.db.raw).state, 'walletOverride');
  assert.equal(o.db.raw, overrideBytes, 'reload revalidates read-only without rewriting');
});

test('v1 and v2 records coexist in the unchanged wrapper: exact discrimination, version-aware identity', async () => {
  const { validateRecord, identityOf } = await import('../controller.js');
  const model = await import('../model.js');
  const chain = new FakeChain();
  const v1 = legacyAttempt(chain, planOf(model), { submit: false });
  assert.ok(validateRecord(v1.raw), 'byte-preserved v1 validates');
  // The v1 identity string is unchanged: same keys, same order, caps included.
  const keysV1 = ['id', 'version', 'manifest', 'chainId', 'from', 'to', 'dataHash', 'salt', 'address', 'transaction',
    'capWei', 'maxTotal', 'submission', 'sendEntered'];
  const canonical = (value) => (Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
    : value && typeof value === 'object' ? `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`
      : JSON.stringify(value));
  assert.equal(identityOf(v1.record), canonical(keysV1.map((k) => v1.record[k])), 'v1 identity byte-compatible');
  const { capWei, maxTotal, ...rest } = v1.record;
  const v2 = { ...rest, version: 2, transaction: { chainId: '0x89', value: '0x0', nonce: v1.record.transaction.nonce } };
  assert.ok(validateRecord(JSON.stringify(v2)), 'closed v2 validates');
  const identity = identityOf(v2);
  assert.equal(identity.includes('undefined'), false, 'absent caps omitted, never serialized as undefined');
  assert.ok(identity.startsWith(`[${JSON.stringify(v2.id)},2,`), 'version is part of identity');
  assert.notEqual(identityOf({ ...v2, version: 1 }), identity);
  // Mixed or unknown shapes fail closed.
  for (const [name, value] of Object.entries({
    v2WithCap: { ...v2, capWei },
    v2WithMaxTotal: { ...v2, maxTotal },
    v2WithV1Transaction: { ...v2, transaction: v1.record.transaction },
    v1WithV2Transaction: { ...v1.record, transaction: v2.transaction },
    v1WithoutCaps: { ...v2, version: 1 },
    version0: { ...v2, version: 0 },
    versionString: { ...v2, version: '2' },
  })) {
    assert.equal(validateRecord(JSON.stringify(value)), null, name);
  }
});

test('polling is bounded to 50 polls / 10 minutes and never sends', async () => {
  const env = await setup();
  await ready(env);
  await env.controller.send();
  await flush();
  const before = env.chain.calls.filter((c) => c.method === 'eth_getTransactionByHash').length;
  await env.clock.advance(12_000 * 60);
  const polls = env.chain.calls.filter((c) => c.method === 'eth_getTransactionByHash').length - before;
  assert.ok(polls <= 50, `bounded polls (${polls})`);
  assert.equal(env.controller.view().pollExpired, true);
  assert.equal(env.controller.phase(), 'txPending');
  assert.equal(env.wallet.sends.length, 1);
});

// ---------------------------------------------------------------------------------------------
// Acceptance repair cases (multi-tab, resume, settlement evidence, clear race, manual/late hashes)

const OWNER_SELECTOR = '0x8da5cb5b';

/** Wraps chain.rpc so calls matching `match` wait for `release()`. */
function gate(chain, match) {
  const original = chain.rpc.bind(chain);
  const waiting = [];
  chain.rpc = async (m, p) => {
    if (match(m, p)) await new Promise((resolve) => waiting.push(resolve));
    return original(m, p);
  };
  return { release: () => { while (waiting.length) waiting.shift()(); }, restore: () => { chain.rpc = original; },
    get waiting() { return waiting.length; } };
}

async function confirmedSuccess(env) {
  await ready(env);
  await env.controller.send();
  await flush();
  env.chain.mine();
  env.chain.mine();
  await env.controller.refresh();
  assert.equal(env.controller.phase(), 'success');
}

test('a second tab never overwrites an unresolved stored attempt and makes zero wallet requests', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const a = await setup({ db, chain });
  const b = await setup({ db, chain });
  await ready(a);
  await ready(b);
  a.wallet.behavior.send = 'deferred';
  await a.controller.send();
  assert.equal(a.controller.phase(), 'walletPending');
  const stored = db.raw;
  assert.ok(stored);
  assert.equal(b.controller.phase(), 'ready', 'tab B still shows its own stale readiness');
  assert.equal(await b.controller.send(), false);
  assert.equal(b.wallet.sends.length, 0, 'zero eth_sendTransaction from tab B');
  assert.equal(b.wallet.requests.filter((r) => r.method === 'eth_sendTransaction').length, 0);
  assert.equal(db.raw, stored, 'stored bytes unchanged');
  assert.equal(b.controller.locked(), true);
  assert.equal(b.controller.attempt.id, JSON.parse(stored).id, 'B is locked on the stored attempt');
  assert.equal(b.controller.phase(), 'unknown');
  assert.equal(b.controller.view().attempt.reason, 'other-tab');
  assert.equal(b.controller.view().clearable, false);
  // A's own attempt keeps tracking its late hash.
  a.wallet.releaseSend();
  await flush();
  assert.equal(a.controller.phase(), 'txPending');
  assert.equal(a.wallet.sends.length, 1);
  // A tampered/foreign stored value also blocks and is kept byte-for-byte.
  const c = await setup({ db: new MemoryAttemptDB(), chain });
  await ready(c);
  c.db.put('{"foreign":true}');
  assert.equal(await c.controller.send(), false);
  assert.equal(c.wallet.sends.length, 0);
  assert.equal(c.controller.phase(), 'resumeError');
  assert.equal(c.db.raw, '{"foreign":true}');
});

test('a stale tab never clears or refreshes over another tab\'s newer unresolved attempt', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const a = await setup({ db, chain });
  // Resolved record X: a reverted (failed) deployment, so the address stays undeployed for attempt Y.
  await ready(a);
  await a.controller.send();
  await flush();
  chain.mine({ revert: true });
  chain.mine();
  await a.controller.refresh();
  assert.equal(a.controller.phase(), 'failed');
  const resolved = db.raw;
  const resolvedId = JSON.parse(resolved).id;
  // Stale tabs B and C load and verify the same resolved record X.
  const b = await setup({ db, chain, load: false });
  const c = await setup({ db, chain, load: false });
  for (const tab of [b, c]) {
    await tab.controller.loadAttempt();
    await flush();
    await tab.controller.refresh();
    assert.equal(tab.controller.phase(), 'failed');
    assert.equal(tab.controller.attempt.id, resolvedId);
  }
  b.controller.requestClear();
  assert.equal(b.controller.view().clearPending, true);
  // Tab A clears X and sends a new deferred attempt Y.
  a.controller.requestClear();
  await a.controller.confirmClear();
  assert.equal(db.raw, null);
  await ready(a);
  a.wallet.behavior.send = 'deferred';
  await a.controller.send();
  assert.equal(a.controller.phase(), 'walletPending');
  const newer = db.raw;
  const newerId = JSON.parse(newer).id;
  assert.notEqual(newerId, resolvedId);
  const sends = () => [a, b, c].reduce((n, tab) => n + tab.wallet.sends.length, 0);
  const sendsBefore = sends();
  // B's stale confirmClear removes nothing; B adopts Y read-only.
  await b.controller.confirmClear();
  assert.equal(db.raw, newer, 'stale confirmClear leaves stored bytes unchanged');
  assert.equal(b.controller.attempt.id, newerId, 'B is locked on A\'s attempt');
  assert.equal(b.controller.locked(), true);
  assert.equal(b.controller.view().clearable, false);
  // C's stale refresh does not write X back over Y; C adopts Y read-only.
  await c.controller.refresh();
  await flush();
  assert.equal(db.raw, newer, 'stale refresh leaves stored bytes unchanged');
  assert.equal(c.controller.attempt.id, newerId, 'C is locked on A\'s attempt');
  assert.equal(c.controller.locked(), true);
  // Neither stale tab can send, and a freshly loaded controller is locked on Y.
  assert.equal(await b.controller.send(), false);
  assert.equal(await c.controller.send(), false);
  const d = await setup({ db, chain, load: false });
  await d.controller.loadAttempt();
  await flush();
  assert.equal(d.controller.attempt.id, newerId);
  assert.equal(d.controller.locked(), true);
  assert.equal(sends() + d.wallet.sends.length, sendsBefore, 'no further eth_sendTransaction');
  assert.equal(db.raw, newer);
  // A stale tab whose record another tab cleared adopts the empty state without writing.
  const e = await setup({ db: new MemoryAttemptDB(), chain, load: false });
  e.db.put(resolved);
  await e.controller.loadAttempt();
  await flush();
  await e.controller.refresh();
  e.db.put(null); // another page's explicit clear (tombstone)
  await e.controller.refresh();
  assert.equal(e.db.raw, null, 'a cleared record is not resurrected');
  assert.equal(e.controller.attempt, null);
  // A's own attempt keeps tracking its late hash.
  a.wallet.releaseSend();
  await flush();
  assert.equal(a.controller.phase(), 'txPending');
  assert.equal(JSON.parse(db.raw).id, newerId);
});

test('stale rejected, manual-hash and emptied-storage tabs never remove, overwrite or unlock another attempt', async () => {
  // (a) B adopts A's rejected record through the yield path; A clears it and sends again while B's clear
  // confirmation is open. B's confirmClear removes nothing and B cannot send.
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const a = await setup({ db, chain });
  const b = await setup({ db, chain });
  await ready(a);
  await ready(b);
  a.wallet.behavior.send = 'reject';
  await a.controller.send();
  await flush();
  assert.equal(a.controller.phase(), 'rejected');
  assert.equal(await b.controller.send(), false);
  assert.equal(b.controller.phase(), 'rejected');
  b.controller.requestClear();
  assert.equal(b.controller.view().clearPending, true);
  a.controller.requestClear();
  await a.controller.confirmClear();
  await ready(a);
  a.wallet.behavior.send = 'deferred';
  await a.controller.send();
  const newer = db.raw;
  const newerId = JSON.parse(newer).id;
  const sendsBefore = a.wallet.sends.length + b.wallet.sends.length;
  await b.controller.confirmClear();
  assert.equal(db.raw, newer, 'stale rejected clear leaves stored bytes unchanged');
  assert.equal(b.controller.attempt.id, newerId);
  assert.equal(b.controller.locked(), true);
  assert.equal(await b.controller.send(), false);
  assert.equal(a.wallet.sends.length + b.wallet.sends.length, sendsBefore, 'no further eth_sendTransaction');
  // (b) A stale tab's manual hash is not written over another attempt's stored bytes.
  const c = await setup({ chain: new FakeChain() });
  await ready(c);
  c.wallet.behavior.send = 'deferred';
  await c.controller.send();
  await c.clock.advance(60_000);
  const hashless = c.db.raw;
  const stale = await setup({ db: c.db, chain: c.chain, load: false });
  await stale.controller.loadAttempt();
  assert.equal(stale.controller.phase(), 'unknown');
  const other = JSON.stringify({ ...JSON.parse(hashless), id: '00000000-0000-4000-8000-00000000abcd' });
  c.db.put(other);
  const planned = c.model.buildPlan(c.model.parseHandoff(handoffText));
  const manual = c.chain.submit({ from: ACCOUNT, to: c.model.FACTORY, data: planned.transaction.data, value: '0x0',
    nonce: '0x0', gas: '0x75300', maxFeePerGas: '0x' + (62n * GWEI).toString(16),
    maxPriorityFeePerGas: '0x' + (2n * GWEI).toString(16) });
  await stale.controller.enterHash(manual);
  await flush();
  assert.equal(c.db.raw, other, 'stale manual hash leaves stored bytes unchanged');
  assert.equal(stale.controller.attempt.id, JSON.parse(other).id, 'the stale tab is locked on the stored attempt');
  assert.equal(stale.controller.locked(), true);
  // (c) Empty storage under an attempt still unresolved here proves no clear: it stays locked, unwritten.
  const d = await setup();
  await ready(d);
  await d.controller.send();
  await flush();
  assert.equal(d.controller.phase(), 'txPending');
  d.db.put(null);
  await d.controller.refresh();
  assert.equal(d.db.raw, null, 'nothing is written into emptied storage');
  assert.equal(d.controller.phase(), 'txPending');
  assert.equal(d.controller.locked(), true);
  assert.equal(await d.controller.send(), false);
  assert.equal(d.wallet.sends.length, 1);
  // Once this tab sees the attempt resolved, the empty storage is a legitimate clear and is adopted.
  d.chain.mine();
  d.chain.mine();
  await d.controller.refresh();
  assert.equal(d.db.raw, null);
  assert.equal(d.controller.attempt, null);
});

test('disconnect while eth_sendTransaction is pending keeps the attempt and tracks the late hash', async () => {
  const env = await setup();
  await ready(env);
  env.wallet.behavior.send = 'deferred';
  await env.controller.send();
  assert.equal(env.controller.phase(), 'walletPending');
  env.wallet.emit('disconnect');
  assert.equal(env.manager.status, 'disconnected');
  assert.equal(env.controller.phase(), 'walletPending', 'disconnect cannot discard the attempt');
  assert.ok(env.db.raw);
  assert.equal(await env.controller.send(), false);
  env.wallet.releaseSend();
  await flush();
  assert.equal(env.controller.phase(), 'txPending', 'late hash tracked after disconnect');
  assert.equal(JSON.parse(env.db.raw).hash, env.controller.attempt.hash);
  assert.equal(env.wallet.sends.length, 1);
});

test('reload treats a stored effective nonce as a hint: no cancellation proof from storage', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const env = await setup({ db, chain });
  await ready(env);
  await env.controller.send();
  await flush();
  // The returned hash becomes unknown to RPC and an unrelated transaction consumes nonce 0.
  const original = chain.mempool.pop();
  chain.txs.delete(original.hash);
  chain.submit({ from: original.from, to: original.from, data: '0x', value: '0x0', nonce: original.nonce,
    gas: '0x5208', maxFeePerGas: original.maxFeePerGas, maxPriorityFeePerGas: original.maxPriorityFeePerGas });
  chain.mine();
  chain.mine();
  const record = JSON.parse(db.raw);
  assert.equal(record.effectiveNonce, null);
  const edited = JSON.stringify({ ...record, effectiveNonce: original.nonce });
  db.put(edited);
  const reloaded = await setup({ db, chain, load: false });
  await reloaded.controller.loadAttempt();
  await flush();
  await flush();
  assert.equal(reloaded.controller.phase(), 'unknown', 'stays unknown, not failed');
  assert.equal(reloaded.controller.view().attempt.reason, 'unverified-nonce');
  assert.equal(reloaded.controller.view().clearable, false);
  assert.equal(reloaded.controller.locked(), true);
  assert.equal(reloaded.wallet.sends.length, 0);
});

test('proved cancellation keeps the consuming hash and paid fee across reload and stays failed', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const env = await setup({ db, chain });
  await ready(env);
  await env.controller.send();
  await flush();
  await env.controller.refresh(); // verifies the effective nonce from the returned hash this session
  const original = chain.mempool.pop();
  chain.txs.delete(original.hash);
  const consuming = chain.submit({ from: original.from, to: original.from, data: '0x', value: '0x0',
    nonce: original.nonce, gas: '0x5208', maxFeePerGas: original.maxFeePerGas,
    maxPriorityFeePerGas: original.maxPriorityFeePerGas });
  chain.mine();
  chain.mine();
  await env.controller.refresh();
  let view = env.controller.view();
  assert.equal(view.phase, 'failed');
  assert.equal(view.attempt.reason, 'cancelled');
  assert.equal(view.attempt.replacementHash, consuming, 'consuming hash kept with the original lineage');
  const receipt = chain.receipts.get(consuming);
  const fee = BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice);
  assert.equal(view.settlement.paidFee, fee, 'paid fee from the consuming canonical receipt');
  assert.equal(JSON.parse(db.raw).replacementHash, consuming);
  const reloaded = await setup({ db, chain, load: false });
  await reloaded.controller.loadAttempt();
  assert.equal(reloaded.controller.phase(), 'resuming');
  await flush();
  await flush();
  view = reloaded.controller.view();
  assert.equal(view.phase, 'failed', 'not re-judged as an identity mismatch');
  assert.equal(view.attempt.replacementHash, consuming);
  assert.equal(view.settlement.paidFee, fee);
  assert.equal(view.clearable, true);
  assert.equal(reloaded.wallet.sends.length, 0);
  assert.equal(chain.writes, 2, 'original plus the external consuming transaction only');
});

test('settlement exposes paid fee/receipt only from a twice-verified canonical receipt block', async () => {
  for (const [name, spec] of Object.entries({
    'recheck-reorg': { flip: 'second', expect: 'pending' },
    'rpc-after-receipt': { fail: 'eth_blockNumber', expect: 'unknown' },
    'override-rpc-after-receipt': { fail: 'eth_blockNumber', override: true, expect: 'walletOverride' },
    'override-recheck-reorg': { flip: 'second', override: true, expect: 'walletOverride' },
  })) {
    let env;
    if (spec.override) {
      // Ceiling overrides exist only for historical v1 records.
      env = await resumeLegacy({ override: { maxFeePerGas: '0x' + (100n * GWEI).toString(16) }, mine: 0 });
    } else {
      env = await setup();
      await ready(env);
      await env.controller.send();
      await flush();
    }
    env.chain.mine();
    env.chain.mine();
    const record = JSON.parse(env.db.raw);
    const plan = env.model.buildPlan(env.model.parseHandoff(handoffText));
    const receiptBlock = env.chain.receipts.get(record.hash).blockNumber;
    let reads = 0;
    const rpc = async (m, p) => {
      if (m === spec.fail) throw Object.assign(new Error('limit'), { code: -32005 });
      const value = await env.chain.rpc(m, p);
      if (spec.flip && m === 'eth_getBlockByNumber' && p[0] === receiptBlock && ++reads === 2) {
        return { ...value, hash: '0x' + 'ee'.repeat(32) };
      }
      return value;
    };
    const result = await env.model.verifySettlement(rpc, plan, record, record.hash);
    assert.equal(result.state, spec.expect, name);
    assert.equal(result.paidFee, null, `${name}: paid fee unknown`);
    assert.equal(result.receipt, null, `${name}: no receipt exposed`);
    assert.equal(result.confirmations, 0n, `${name}: no confirmations exposed`);
    assert.equal(result.readback, 'unknown', `${name}: readback unknown`);
  }
});

test('an unavailable readback eth_call is unknown/rpc, never a key-set mismatch', async () => {
  // Historical v1 walletOverride settlement: readback unknown.
  const env = await resumeLegacy({ override: { maxFeePerGas: '0x' + (100n * GWEI).toString(16) }, mine: 0 });
  env.chain.mine();
  env.chain.mine();
  const original = env.chain.rpc.bind(env.chain);
  env.chain.rpc = async (m, p) => {
    if (m === 'eth_call' && p[0].data.startsWith(OWNER_SELECTOR)) {
      throw Object.assign(new Error('limit exceeded'), { code: -32005 });
    }
    return original(m, p);
  };
  await env.controller.refresh();
  assert.equal(env.controller.phase(), 'walletOverride');
  assert.equal(env.controller.view().settlement.readback, 'unknown');
  assert.equal(env.controller.view().settlement.paidFee, null);
  // Inspection of a deployed target: an RPC inspection error, not keyset.
  const t = await setup();
  t.chain.preDeploy(t.model.buildPlan(t.model.parseHandoff(handoffText)));
  const raw = t.chain.rpc.bind(t.chain);
  t.chain.rpc = async (m, p) => {
    if (m === 'eth_call' && p[0].data.startsWith(OWNER_SELECTOR)) {
      throw Object.assign(new Error('limit exceeded'), { code: -32005 });
    }
    return raw(m, p);
  };
  t.controller.prepare(handoffText);
  t.controller.selectWallet('legacy');
  await t.controller.connect();
  await t.controller.inspect();
  assert.equal(t.controller.phase(), 'inspectionError');
  assert.equal(t.controller.view().inspection.error.code, 'rpc');
  t.chain.rpc = raw;
  await t.controller.inspect();
  assert.equal(t.controller.phase(), 'deployed', 'a decoded matching readback is still deployed');
  assert.equal(t.wallet.sends.length, 0);
});

test('reload shows no stored success before the first refresh, then reflects fetched data', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const env = await setup({ db, chain });
  await confirmedSuccess(env);
  // Same chain: fetched data confirms success.
  let r = await setup({ db, chain, load: false });
  let held = gate(chain, () => true);
  await r.controller.loadAttempt();
  assert.equal(r.controller.phase(), 'resuming');
  assert.equal(r.controller.view().clearable, false);
  r.controller.requestClear();
  assert.equal(r.controller.view().clearPending, false);
  held.release();
  held.restore();
  await flush();
  await flush();
  assert.equal(r.controller.phase(), 'success');
  // Reorged out: the stored success is never shown; fetched data yields pending.
  chain.reorg(3);
  r = await setup({ db, chain, load: false });
  held = gate(chain, () => true);
  await r.controller.loadAttempt();
  assert.notEqual(r.controller.phase(), 'success');
  held.release();
  held.restore();
  await flush();
  await flush();
  assert.equal(r.controller.phase(), 'txPending');
  assert.equal(r.wallet.sends.length, 0);
});

test('clear during an in-flight refresh stays cleared; a revoked success drops the clear confirmation', async () => {
  const env = await setup();
  await confirmedSuccess(env);
  const held = gate(env.chain, (m) => m === 'eth_getTransactionByHash');
  const refreshing = env.controller.refresh();
  await flush();
  env.controller.requestClear();
  await env.controller.confirmClear();
  assert.equal(env.db.raw, null);
  held.release();
  held.restore();
  await refreshing;
  await flush();
  assert.equal(env.db.raw, null, 'the in-flight refresh does not resurrect the record');
  assert.equal(env.controller.attempt, null);
  // Revocation: success, 記録を消去, then a refresh that detects a reorg.
  const env2 = await setup();
  await confirmedSuccess(env2);
  env2.controller.requestClear();
  assert.equal(env2.controller.view().clearPending, true);
  env2.chain.reorg(3);
  await env2.controller.refresh();
  assert.equal(env2.controller.phase(), 'txPending');
  assert.equal(env2.controller.view().clearPending, false, 'confirmation hidden once not clearable');
  const bytes = env2.db.raw;
  await env2.controller.confirmClear();
  assert.equal(env2.db.raw, bytes, 'confirmClear stays inert');
  assert.equal(env2.wallet.sends.length, 1);
});

test('the wallet hash is never discarded for a manual hash; pre-submission transactions are rejected', async () => {
  const plan = (env) => env.model.buildPlan(env.model.parseHandoff(handoffText));
  const sameIdentity = (env, nonce) => env.chain.submit({ from: ACCOUNT, to: env.model.FACTORY,
    data: plan(env).transaction.data, value: '0x0', nonce, gas: '0x75300',
    maxFeePerGas: '0x' + (62n * GWEI).toString(16), maxPriorityFeePerGas: '0x' + (2n * GWEI).toString(16) });
  async function timedOut(env) {
    await ready(env);
    env.wallet.behavior.send = 'deferred';
    await env.controller.send();
    await env.clock.advance(60_000);
    assert.equal(env.controller.phase(), 'unknown');
  }
  // (a) The wallet hash arrives while a manual entry is being verified.
  let env = await setup();
  await timedOut(env);
  const manual = sameIdentity(env, '0x0');
  let held = gate(env.chain, (m, p) => m === 'eth_getTransactionByHash' && p[0] === manual);
  const entering = env.controller.enterHash(manual);
  await flush();
  env.wallet.releaseSend();
  await flush();
  const walletHash = env.controller.attempt.hash;
  assert.ok(walletHash && walletHash !== manual);
  held.release();
  held.restore();
  await entering;
  assert.equal(env.controller.attempt.hash, walletHash, 'manual entry dropped after the wallet hash');
  assert.equal(JSON.parse(env.db.raw).hash, walletHash);
  // (b) The wallet hash arrives after a manual hash was accepted: it is persisted and tracked.
  env = await setup();
  await timedOut(env);
  const manual2 = sameIdentity(env, '0x0');
  await env.controller.enterHash(manual2);
  assert.equal(env.controller.attempt.hash, manual2);
  env.wallet.releaseSend();
  await flush();
  const tracked = env.controller.attempt.hash;
  assert.notEqual(tracked, manual2, 'wallet hash replaces the manual reconciliation');
  assert.equal(env.controller.phase(), 'txPending');
  assert.equal(JSON.parse(env.db.raw).hash, tracked);
  assert.equal(env.wallet.sends.length, 1);
  // (b2) Superseded expectation: a wallet hash used to erase an already confirmed manual success. Stored success
  // now wins: its bytes/lineage are retained, the conflicting wallet hash is a visible notice only, no new send.
  env = await setup();
  await timedOut(env);
  const manual3 = sameIdentity(env, '0x0');
  env.chain.mine();
  env.chain.mine();
  await env.controller.enterHash(manual3);
  assert.equal(env.controller.phase(), 'success');
  held = gate(env.chain, (m, p) => m === 'eth_getTransactionByHash' && p[0] === manual3);
  const stale = env.controller.refresh();
  await flush();
  const confirmed = env.db.raw;
  env.wallet.releaseSend();
  await flush();
  const conflicting = env.wallet.sends.length === 1 && env.chain.mempool.length
    ? env.chain.mempool[env.chain.mempool.length - 1].hash : null;
  held.release();
  held.restore();
  await stale;
  await flush();
  assert.equal(env.controller.attempt.hash, manual3, 'stored success hash retained');
  assert.equal(env.controller.phase(), 'success');
  assert.equal(JSON.parse(env.db.raw).state, 'success');
  assert.equal(JSON.parse(env.db.raw).hash, manual3);
  assert.equal(env.db.raw, confirmed, 'confirmed success bytes unchanged by the late wallet hash');
  assert.ok(env.controller.view().notices.lateHash, 'conflicting wallet hash visible as a notice');
  assert.notEqual(env.controller.view().notices.lateHash, manual3);
  if (conflicting) assert.equal(env.controller.view().notices.lateHash, conflicting);
  assert.equal(env.wallet.sends.length, 1, 'zero new sends');
  // (c) A same-identity transaction mined before the submission block is not this attempt's hash.
  env = await setup();
  const old = sameIdentity(env, '0x0');
  env.chain.mine({ revert: true });
  env.chain.mine();
  await timedOut(env);
  await env.controller.enterHash(old);
  assert.equal(env.controller.view().manualHashError, 'このハッシュの取引は今回の送信より前のブロックで確定しています。この送信の取引ではありません。');
  assert.equal(env.controller.attempt.hash, null);
  assert.equal(env.controller.phase(), 'unknown');
  assert.equal(env.controller.view().clearable, false);
  assert.equal(env.wallet.sends.length, 1);
});

test('a relay failure on the send-time pending-nonce read blocks admission with Japanese copy', async () => {
  const { MESSAGES } = await import('../controller.js');
  for (const error of [new TypeError('fetch failed'), Object.assign(new Error('limit'), { code: -32005 })]) {
    const env = await setup();
    await ready(env);
    const inspected = env.chain.calls.filter((c) => c.method === 'eth_getTransactionCount').length;
    assert.equal(inspected, 0, 'inspection reads no nonce');
    const original = env.chain.rpc.bind(env.chain);
    env.chain.rpc = async (m, p) => {
      if (m === 'eth_getTransactionCount' && p[1] === 'pending') throw error;
      return original(m, p);
    };
    assert.equal(await env.controller.send(), false);
    assert.equal(env.controller.view().sendNotice, MESSAGES.nonce);
    assert.ok(/[぀-ヿ一-鿿]/.test(MESSAGES.nonce), 'Japanese copy');
    assert.equal(env.wallet.sends.length, 0, 'nothing sent without a real nonce hint');
    assert.equal(env.db.raw, null, 'nothing admitted');
    assert.equal(env.controller.canSend(), false, 'a fresh explicit action after re-inspection is required');
  }
});

// ---------------------------------------------------------------------------------------------
// Transactional attempt storage (unit: the shared in-memory double above). The first three cases retain the RED
// assertions of test commit 1e504e87 (same-attempt cross-tab recovery loss), adapted to the store.

const BIGGAS = '0xdbba0';

test('v2 manual hash: inconsistent or malformed read evidence never binds an older same-identity transaction', async () => {
  const model = await import('../model.js');
  const plan = planOf(model);
  const tampers = {
    pendingView: (tx) => ({ ...tx, blockNumber: null, blockHash: null }),
    laterBlock: (tx) => ({ ...tx, blockNumber: '0xffff' }),
    malformedBlock: (tx) => ({ ...tx, blockNumber: '0x0001' }),
    missingPriorityFee: (tx) => { const { maxPriorityFeePerGas, ...rest } = tx; return rest; },
  };
  for (const [name, tamper] of Object.entries(tampers)) {
    const chain = new FakeChain();
    // An older reverted transaction with the deployment identity, mined before the attempt's submission block.
    const old = chain.submit({ from: ACCOUNT, to: plan.transaction.to, data: plan.transaction.data, value: '0x0',
      nonce: '0x0', gas: '0x75300', maxFeePerGas: '0x' + (62n * GWEI).toString(16),
      maxPriorityFeePerGas: '0x' + (2n * GWEI).toString(16) });
    chain.mine({ revert: true });
    chain.mine();
    const { capWei, maxTotal, ...rest } = legacyAttempt(chain, plan, { submit: false }).record;
    const hashless = { ...rest, version: 2, state: 'unknown',
      transaction: { chainId: '0x89', value: '0x0', nonce: rest.transaction.nonce } };
    const db = new MemoryAttemptDB();
    db.put(JSON.stringify(hashless));
    const env = await setup({ db, chain, load: false });
    await env.controller.loadAttempt();
    assert.equal(env.controller.phase(), 'unknown', `${name}: hashless v2 is unknown`);
    const original = chain.rpc.bind(chain);
    let tampered = 0;
    chain.rpc = async (m, p) => {
      const value = await original(m, p);
      if (m === 'eth_getTransactionByHash' && p[0] === old && !tampered++) return tamper(value);
      return value;
    };
    await env.controller.enterHash(old);
    assert.equal(tampered, 1, `${name}: tampered read served`);
    assert.equal(env.controller.view().manualHashError, '取引ハッシュを読取りRPCで確認できませんでした。', name);
    assert.equal(env.controller.attempt.hash, null, `${name}: hash not bound`);
    assert.equal(JSON.parse(env.db.raw).hash, null, `${name}: stored hash not bound`);
    // A later consistent read still cannot resolve the attempt: the hash predates this send.
    await env.controller.refresh();
    await env.controller.enterHash(old);
    assert.equal(env.controller.view().manualHashError,
      'このハッシュの取引は今回の送信より前のブロックで確定しています。この送信の取引ではありません。', name);
    const view = env.controller.view();
    assert.equal(view.phase, 'unknown', `${name}: still unknown`);
    assert.equal(view.clearable, false, `${name}: not clearable`);
    env.controller.requestClear();
    assert.equal(env.controller.view().clearPending, false, `${name}: no clear confirmation`);
    const stored = JSON.parse(env.db.raw);
    assert.equal(stored.state, 'unknown', `${name}: stored unknown`);
    assert.equal(stored.hash, null);
    assert.equal(stored.version, 2);
    assert.equal(env.wallet.sends.length, 0, `${name}: zero wallet sends`);
  }
});

test('a sending tab timeout never erases the same attempt hash recovered by another tab', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const a = await setup({ db, chain });
  await ready(a);
  a.wallet.behavior.send = 'deferred';
  await a.controller.send();
  const b = await setup({ db, chain });
  assert.equal(b.controller.phase(), 'unknown');
  assert.equal(b.controller.attempt.id, a.controller.attempt.id);
  // The wallet submitted (with its own higher gas) but its response to A has not arrived; B reconciles read-only.
  const hash = chain.submit({ ...a.wallet.built[0], gas: BIGGAS });
  await b.controller.enterHash(hash);
  assert.equal(b.controller.phase(), 'txPending', 'a v2 wallet gas choice is not an override');
  const recovered = db.raw;
  assert.equal(JSON.parse(recovered).hash, hash);
  await a.clock.advance(60_000);
  await flush();
  assert.equal(db.raw, recovered, 'timeout must not erase the recovered hash evidence');
  assert.equal(a.controller.attempt.hash, hash, 'A adopts the newer same-attempt evidence read-only');
  assert.equal(a.controller.view().notices.newer, true);
  assert.equal(a.wallet.sends.length + b.wallet.sends.length, 1, 'no recovery send');
});

test('malformed or rejected wallet responses cannot erase a same-attempt hash recovered by another tab', async (t) => {
  for (const outcome of ['malformed', 'rejected']) await t.test(outcome, async () => {
    const db = new MemoryAttemptDB();
    const chain = new FakeChain();
    const a = await setup({ db, chain });
    await ready(a);
    a.wallet.behavior.send = 'deferred';
    await a.controller.send();
    const b = await setup({ db, chain });
    const hash = chain.submit(a.wallet.built[0]);
    await b.controller.enterHash(hash);
    const recovered = db.raw;
    if (outcome === 'malformed') a.wallet.pendingSends[0].resolve('not-a-hash');
    else a.wallet.pendingSends[0].reject(Object.assign(new Error('rejected'), { code: 4001 }));
    await flush();
    assert.equal(db.raw, recovered, 'known hash is not a hashless failure');
    assert.notEqual(a.controller.phase(), 'rejected');
    assert.equal(a.wallet.sends.length + b.wallet.sends.length, 1);
  });
});

test('a same-ID stale refresh cannot erase the newer wallet hash', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const a = await setup({ db, chain });
  await ready(a);
  a.wallet.behavior.send = 'deferred';
  await a.controller.send();
  const b = await setup({ db, chain });
  const manual = chain.submit(a.wallet.built[0]);
  await b.controller.enterHash(manual);
  // B's older hash is valid, but the sending tab receives a different authoritative hash (wallet-chosen gas).
  a.wallet.pendingSends[0].tx.gas = BIGGAS;
  a.wallet.releaseSend();
  await flush();
  await a.controller.refresh();
  const newer = db.raw;
  assert.equal(JSON.parse(newer).state, 'pending');
  assert.notEqual(JSON.parse(newer).hash, manual);
  assert.equal(JSON.parse(newer).observed.gas, BIGGAS, 'verified wallet gas retained internally');
  await b.controller.refresh();
  await flush();
  assert.equal(db.raw, newer, 'same-ID refresh cannot restore obsolete evidence');
  assert.equal(b.controller.attempt.hash, JSON.parse(newer).hash, 'B adopts the newer row read-only');
  assert.equal(b.wallet.sends.length, 0);
});

test('storage initialization admits nothing; corrupt, unavailable and legacy-conflict loads fail closed', async () => {
  const pending = await setup({ load: false });
  assert.equal(pending.controller.phase(), 'initializing');
  pending.controller.prepare(handoffText);
  pending.controller.selectWallet('legacy');
  await pending.controller.connect();
  assert.equal(pending.controller.canInspect(), false, 'no inspection before storage settles');
  assert.equal(await pending.controller.send(), false);
  assert.equal(pending.controller.view().initializing, true);
  for (const [name, mutate, phase] of [
    ['corrupt', (db) => db.put('{"foreign":true}'), 'resumeError'],
    ['unavailable', (db) => { db.mode = 'unavailable'; }, 'storageError'],
    ['legacy-conflict', (db) => { db.legacy = '{"changed":true}'; }, 'storageError'],
  ]) {
    const db = new MemoryAttemptDB();
    mutate(db);
    const env = await setup({ db });
    assert.equal(env.controller.phase(), phase, name);
    if (name === 'legacy-conflict') assert.equal(env.controller.view().storageError.code, 'legacy-conflict');
    env.controller.prepare(handoffText);
    env.controller.selectWallet('legacy');
    await env.controller.connect();
    await env.controller.inspect();
    assert.equal(env.controller.canSend(), false, `${name}: no send`);
    assert.equal(db.writes, 0, `${name}: nothing repaired or written`);
    assert.equal(env.wallet.sends.length, 0);
  }
});

test('two pages with different accounts competing from the same empty revision admit exactly one send', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const a = await setup({ db, chain });
  const b = await setup({ db, chain, accounts: [OTHER] });
  await ready(a);
  await ready(b);
  assert.equal(a.controller.snapshot.revision, b.controller.snapshot.revision, 'both read the same empty revision');
  const [sentA, sentB] = await Promise.all([a.controller.send(), b.controller.send()]);
  await flush();
  assert.equal(a.wallet.sends.length + b.wallet.sends.length, 1, 'exactly one wallet invocation');
  assert.equal([sentA, sentB].filter(Boolean).length, 1);
  const loser = sentA ? b : a;
  const winner = sentA ? a : b;
  assert.equal(db.revision, winner.controller.snapshot.revision);
  assert.equal(JSON.parse(db.raw).from.toLowerCase(), winner.wallet.sends[0].from.toLowerCase());
  assert.equal(loser.controller.attempt.id, JSON.parse(db.raw).id, 'loser adopts the retained attempt read-only');
  assert.equal(loser.controller.locked(), true);
  assert.equal(await loser.controller.send(), false);
  // Reopening the losing page still cannot send.
  const reopened = await setup({ db, chain, accounts: [loser.wallet.accounts[0]] });
  assert.equal(reopened.controller.locked(), true);
  assert.equal(a.wallet.sends.length + b.wallet.sends.length + reopened.wallet.sends.length, 1);
});

test('conflict adoption revalidates without saving; a later explicit refresh can save', async (t) => {
  for (const path of ['admission', 'same-ID', 'different-ID']) await t.test(path, async () => {
    const db = new MemoryAttemptDB();
    const chain = new FakeChain();
    const a = await setup({ db, chain });
    const b = await setup({ db, chain, accounts: [OTHER], tab: 1 });
    await ready(a);
    await ready(b);
    await a.controller.send();
    await flush();
    const saved = db.raw;
    const revision = db.revision;
    assert.equal(revision, 2, 'admission and wallet hash saved before the losing operation');
    assert.equal(JSON.parse(saved).observed, null);
    if (path === 'admission') {
      assert.equal(await b.controller.send(), false);
    } else {
      if (path === 'same-ID') b.controller.adopt(JSON.parse(saved), a.controller.attemptPlan);
      else b.controller.adopt({ ...JSON.parse(saved), id: '00000000-0000-4000-8000-000000009999' }, a.controller.attemptPlan);
      b.controller.adoptLatest(a.store.current());
    }
    await flush();
    assert.equal(b.controller.refreshing, false, 'read-only revalidation finished');
    assert.ok(b.controller.attempt.observed, 'chain observations are still revalidated and displayed');
    assert.equal(db.raw, saved, 'adopting a conflict leaves exact stored bytes unchanged');
    assert.equal(db.revision, revision, 'adopting a conflict does not advance the revision');
    assert.equal(a.wallet.sends.length, 1);
    assert.equal(b.wallet.sends.length, 0);
    assert.equal(await b.controller.send(), false);
    await b.controller.refresh();
    assert.equal(db.revision, revision + 1, 'explicit refresh retains its captured-revision commit');
    assert.ok(JSON.parse(db.raw).observed);
    assert.equal(JSON.parse(db.raw).hash, JSON.parse(saved).hash);
    assert.equal(b.wallet.sends.length, 0);
  });
});

test('read-only adoption of a newly resolved attempt can be explicitly cleared', async (t) => {
  for (const state of ['success', 'failed']) await t.test(state, async () => {
    const db = new MemoryAttemptDB(), chain = new FakeChain();
    const a = await setup({ db, chain }), b = await setup({ db, chain, accounts: [OTHER], tab: 1 });
    await ready(a); await ready(b);
    let release, waiting = false;
    const barrier = new Promise((resolve) => { release = resolve; });
    const cas = b.store.compareAndSet.bind(b.store);
    b.store.compareAndSet = async (...args) => { waiting = true; await barrier; return cas(...args); };
    const losingSend = b.controller.send();
    await until(() => waiting);
    await a.controller.send(); await settleAll();
    a.controller.stopTracking();
    chain.mine({ revert: state === 'failed' }); chain.mine();
    const raw = db.raw, revision = db.revision;
    release(); assert.equal(await losingSend, false);
    await settleAll();
    assert.equal(b.controller.phase(), state);
    assert.equal(b.controller.clearable(), true);
    assert.equal(db.raw, raw, 'adoption is still read-only');
    b.controller.requestClear(); await b.controller.confirmClear();
    assert.equal(db.raw, null, 'explicit clear consumes the verified snapshot, not an unsaved state label');
    assert.equal(db.revision, revision + 1, 'only the requested tombstone commits');
    assert.equal(a.wallet.sends.length + b.wallet.sends.length, 1);
  });
});

test('changed same-ID lineage cannot use an earlier settlement to clear before revalidation', async () => {
  const env = await setup(); await confirmedSuccess(env);
  const original = JSON.parse(env.db.raw);
  const replacementHash = env.chain.submit(env.wallet.built[0]);
  env.db.put(JSON.stringify({ ...original, replacementHash }));
  const raw = env.db.raw;
  const hold = gate(env.chain, (m, p) => m === 'eth_getTransactionByHash' && p[0] === replacementHash);
  try {
    env.controller.adoptLatest(env.store.current());
    await until(() => hold.waiting > 0);
    assert.equal(env.controller.clearable(), false, 'old success does not verify the new lineage');
    env.controller.requestClear(); await env.controller.confirmClear();
    assert.equal(env.db.raw, raw);
  } finally { hold.restore(); hold.release(); }
  await settleAll();
  assert.equal(env.controller.phase(), 'txPending');
  assert.equal(env.controller.clearable(), false);
  assert.equal(env.db.raw, raw, 'new lineage is only revalidated, not saved by adoption');
});

test('first hash adopted for the same attempt starts bounded polling without resetting an existing window', async () => {
  const db = new MemoryAttemptDB(), chain = new FakeChain();
  const a = await setup({ db, chain }); await ready(a);
  a.wallet.behavior.send = 'deferred'; await a.controller.send();
  const b = await setup({ db, chain, tab: 1 }); await settleAll();
  assert.equal(b.controller.pollStarted, null);
  const hash = chain.submit(a.wallet.built[0]);
  await b.controller.enterHash(hash);
  a.controller.adoptLatest(a.store.current()); await settleAll();
  assert.notEqual(a.controller.pollTimer, null, 'adopted first hash is automatically followed');
  const started = a.controller.pollStarted;
  const polls = a.controller.polls;
  a.controller.adoptLatest(a.store.current()); await settleAll();
  assert.equal(a.controller.pollStarted, started);
  assert.equal(a.controller.polls, polls);
  chain.mine(); chain.mine();
  await a.clock.advance(12_000);
  assert.equal(a.controller.phase(), 'success');
  assert.equal(a.wallet.sends.length + b.wallet.sends.length, 1);
});

test('an unsaved wallet hash remains visibly separate when a stale clear adopts another hash', async () => {
  const db = new MemoryAttemptDB(), chain = new FakeChain();
  const a = await setup({ db, chain }); await ready(a);
  a.wallet.behavior.send = 'deferred'; await a.controller.send(); await a.clock.advance(60_000);
  const manual = chain.submit(a.wallet.built[0]); chain.mine({ revert: true }); chain.mine();
  await a.controller.enterHash(manual);
  const b = await setup({ db, chain, tab: 1 }); await settleAll();
  a.controller.requestClear(); const release = db.hold(), clearing = a.controller.confirmClear();
  chain.reorg(2); await b.controller.refresh();
  db.mode = 'full'; a.wallet.releaseSend(); await settleAll();
  const hash = a.controller.unsaved.outcome.hash;
  assert.notEqual(hash, manual);
  const retained = db.raw, revision = db.revision;
  db.mode = 'ok'; release(); await clearing; await settleAll();
  const view = a.controller.view();
  assert.equal(view.attempt.hash, manual, 'stored adoption and unsaved response are different evidence');
  assert.equal(view.notices.unsaved, true);
  assert.ok(view.sendNotice && view.sendNotice.includes(hash), 'unsaved wallet hash remains in the rendered notice');
  assert.ok(view.sendNotice.includes('未保存'));
  assert.equal(db.raw, retained);
  assert.equal(db.revision, revision, 'adoption never auto-retries the held write');
  await a.controller.refresh(); await settleAll();
  assert.equal(JSON.parse(db.raw).hash, hash);
  assert.equal(a.controller.view().notices.unsaved, false);
  assert.equal(a.wallet.sends.length + b.wallet.sends.length, 1);
});

test('an older timeout suspended before storage cannot replace a newer unsaved wallet hash', async () => {
  const env = await setup(); await ready(env);
  env.wallet.behavior.send = 'deferred'; await env.controller.send();
  let release, waiting = false;
  const barrier = new Promise((resolve) => { release = resolve; });
  const read = env.store.read.bind(env.store);
  env.store.read = async () => {
    if (!waiting) { waiting = true; await barrier; }
    return read();
  };
  await env.clock.advance(60_000);
  assert.equal(waiting, true);
  env.db.mode = 'full'; env.wallet.releaseSend(); await settleAll();
  const held = env.controller.unsaved;
  assert.equal(held.outcome.kind, 'hash');
  release(); await settleAll();
  assert.deepEqual(env.controller.unsaved, held, 'weaker deferred failure cannot discard the known hash');
  assert.ok(JSON.stringify(env.controller.view(), (_, v) => typeof v === 'bigint' ? v.toString() : v)
    .includes(held.outcome.hash));
  assert.equal(JSON.parse(env.db.raw).hash, null);
  env.db.mode = 'ok'; await env.controller.refresh(); await settleAll();
  assert.equal(JSON.parse(env.db.raw).hash, held.outcome.hash);
  assert.equal(env.wallet.sends.length, 1);
});

test('a successful clear retains a wallet hash received while its tombstone was pending', async () => {
  const env = await setup(); await ready(env);
  env.wallet.behavior.send = 'deferred'; await env.controller.send(); await env.clock.advance(60_000);
  const manual = env.chain.submit(env.wallet.built[0]); await env.controller.enterHash(manual);
  env.controller.stopTracking(); env.chain.mine({ revert: true }); env.chain.mine();
  env.controller.adoptLatest(env.store.current()); await settleAll();
  assert.equal(env.controller.phase(), 'failed');
  assert.equal(JSON.parse(env.db.raw).state, 'pending');
  const release = env.db.hold();
  env.controller.requestClear(); const clearing = env.controller.confirmClear();
  assert.equal(env.db.gates.length, 0, 'clear reached the CAS boundary');
  env.db.mode = 'full'; env.wallet.releaseSend(); await settleAll();
  const held = env.controller.unsaved;
  assert.equal(held.outcome.kind, 'hash');
  assert.notEqual(held.outcome.hash, manual);
  env.db.mode = 'ok'; release(); await clearing; await settleAll();
  assert.equal(env.db.raw, null, 'the completed clear is not undone');
  const view = env.controller.view();
  assert.equal(view.notices.staleHash, held.outcome.hash, 'received evidence survives as a cleared-attempt notice');
  assert.equal(env.controller.clearedIdentity, held.identity);
  assert.ok(view.sendNotice.includes(held.outcome.hash));
  assert.equal(view.notices.reloadRequired, true);
  assert.equal(view.locked, true);
  assert.equal(await env.controller.send(), false);
  await env.controller.refresh();
  assert.equal(env.db.raw, null, 'retry cannot resurrect the cleared attempt');
  assert.equal(env.wallet.sends.length, 1);
});

test('admission abort, post-commit drift and a synchronous provider throw never double-send', async () => {
  // Drift between transaction completion and the wallet call: only this admission is tombstoned, zero sends.
  const env = await setup();
  await ready(env);
  const release = env.db.hold();
  const sending = env.controller.send();
  await flush();
  env.wallet.emitChain('0x1');
  release();
  assert.equal(await sending, false);
  await flush();
  assert.equal(env.wallet.sends.length, 0, 'zero sends after post-commit drift');
  assert.equal(env.db.raw, null, 'the just-created admission is conditionally cleared');
  assert.equal(env.db.revision, 2, 'admission then tombstone, both conditional');
  assert.equal(env.controller.canSend(), false, 'fresh review required');
  // Storage aborts the admission: zero sends, storage error.
  const aborted = await setup();
  await ready(aborted);
  aborted.db.mode = 'full';
  assert.equal(await aborted.controller.send(), false);
  assert.equal(aborted.wallet.sends.length, 0);
  assert.equal(aborted.controller.phase(), 'storageError');
  // A synchronous provider throw is the same uncertain path as a rejected promise: unknown, locked, no retry.
  const sync = await setup();
  await ready(sync);
  sync.wallet.request = function (args) {
    if (args.method === 'eth_sendTransaction') throw Object.assign(new Error('boom'), { code: -32603 });
    return FakeWallet.prototype.request.call(this, args);
  };
  assert.equal(await sync.controller.send(), true);
  await flush();
  assert.equal(sync.controller.phase(), 'unknown');
  assert.equal(JSON.parse(sync.db.raw).reason, 'send-error');
  assert.equal(sync.controller.view().sendCount, 1);
  assert.equal(await sync.controller.send(), false);
});

test('late wallet hash precedence: cancellation lineage wins; ordinary or wallet-fee observed manual is replaced', async () => {
  async function manualThenRelease(mutateStored) {
    const db = new MemoryAttemptDB();
    const chain = new FakeChain();
    const a = await setup({ db, chain });
    await ready(a);
    a.wallet.behavior.send = 'deferred';
    await a.controller.send();
    const b = await setup({ db, chain });
    const manual = chain.submit(a.wallet.built[0]);
    await b.controller.enterHash(manual);
    if (mutateStored) db.put(JSON.stringify(mutateStored(JSON.parse(db.raw))));
    const before = db.raw;
    a.wallet.releaseSend();
    await flush();
    await flush();
    return { a, b, db, before, manual };
  }
  // Ordinary pending manual hash with observations: replaceable by the wallet hash.
  let r = await manualThenRelease(null);
  assert.equal(JSON.parse(r.before).state, 'pending');
  assert.notEqual(JSON.parse(r.before).observed, null, 'observed !== null is not an override');
  assert.notEqual(JSON.parse(r.db.raw).hash, r.manual, 'wallet hash replaces the ordinary manual hash');
  assert.equal(JSON.parse(r.db.raw).state, 'pending');
  assert.equal(r.a.controller.view().notices.lateHash, null);
  // v2 wallet-selected gas far above any old ceiling is still no override: the wallet hash replaces it.
  r = await manualThenRelease((rec) => ({ ...rec, observed: { ...rec.observed, gas: BIGGAS } }));
  assert.notEqual(JSON.parse(r.db.raw).hash, r.manual, 'v2 wallet gas never protects the manual hash');
  assert.equal(r.a.controller.view().notices.lateHash, null);
  // Cancellation lineage.
  r = await manualThenRelease((rec) => ({ ...rec, state: 'unknown', reason: 'cancel-unverified',
    replacementHash: '0x' + 'cd'.repeat(32), effectiveNonce: '0x0' }));
  // The late hash is notice-only; a later read-only recheck may still re-judge the lineage from chain data.
  assert.equal(JSON.parse(r.db.raw).hash, r.manual, 'cancellation lineage keeps the stored hash');
  assert.ok(r.a.controller.view().notices.lateHash);
  assert.equal(r.a.wallet.sends.length + r.b.wallet.sends.length, 1);
});

test('historical v1 outcome precedence is unchanged: observed or sticky ceiling overrides keep the stored hash', async () => {
  const { decideOutcome, identityOf, validateRecord } = await import('../controller.js');
  const model = await import('../model.js');
  const chain = new FakeChain();
  const legacy = legacyAttempt(chain, planOf(model));
  const identity = identityOf(legacy.record);
  const observed = { nonce: '0x0', gas: '0x75300', maxFeePerGas: legacy.record.transaction.maxFeePerGas,
    maxPriorityFeePerGas: legacy.record.transaction.maxPriorityFeePerGas };
  const other = '0x' + 'ef'.repeat(32);
  const within = JSON.stringify({ ...legacy.record, observed });
  assert.ok(validateRecord(within));
  assert.equal(decideOutcome(within, identity, { kind: 'hash', hash: other }).kind, 'write', 'within-limit is replaceable');
  for (const [name, record] of Object.entries({
    'observed-gas-override': { ...legacy.record, observed: { ...observed, gas: BIGGAS } },
    'observed-fee-override': { ...legacy.record, observed: { ...observed, maxFeePerGas: '0x' + (100n * GWEI).toString(16) } },
    'sticky-override': { ...legacy.record, state: 'walletOverride' },
  })) {
    const raw = JSON.stringify(record);
    assert.ok(validateRecord(raw), name);
    assert.equal(decideOutcome(raw, identity, { kind: 'hash', hash: other }).kind, 'notice', `${name}: hash is notice-only`);
    for (const outcome of [{ kind: 'timeout' }, { kind: 'malformed' }, { kind: 'error', code: 4001 }]) {
      assert.equal(decideOutcome(raw, identity, outcome).kind, 'unchanged', `${name}/${outcome.kind}: never erased`);
    }
  }
  // A v1 identity never matches a v2 record with the same id (version-aware identity).
  const { capWei, maxTotal, ...rest } = legacy.record;
  const v2 = JSON.stringify({ ...rest, version: 2, transaction: { chainId: '0x89', value: '0x0', nonce: '0x0' } });
  assert.equal(decideOutcome(v2, identity, { kind: 'hash', hash: other }).kind, 'foreign');
});

test('an unsaved wallet hash stays visible and the explicit refresh retries only that outcome', async () => {
  const env = await setup();
  await ready(env);
  env.wallet.behavior.send = 'deferred';
  await env.controller.send();
  const stored = env.db.raw;
  env.db.mode = 'full';
  env.wallet.releaseSend();
  await flush();
  const view = env.controller.view();
  assert.equal(view.notices.unsaved, true);
  assert.ok(view.attempt.hash, 'returned public hash kept in memory');
  assert.equal(env.db.raw, stored, 'stored bytes unchanged');
  assert.equal(JSON.parse(env.db.raw).hash, null);
  assert.equal(view.clearable, false);
  // A failed retry keeps the outcome; a later successful retry commits exactly that hash, never a send.
  await env.controller.refresh();
  assert.equal(env.controller.view().notices.unsaved, true);
  env.db.mode = 'ok';
  await env.controller.refresh();
  await flush();
  assert.equal(env.controller.view().notices.unsaved, false);
  assert.equal(JSON.parse(env.db.raw).hash, view.attempt.hash);
  assert.equal(env.controller.phase(), 'txPending');
  assert.equal(env.wallet.sends.length, 1);
});

test('a terminal callback after another page cleared never resurrects; ABA bytes at an old revision are refused', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const a = await setup({ db, chain });
  await ready(a);
  a.wallet.behavior.send = 'deferred';
  await a.controller.send();
  const b = await setup({ db, chain });
  const manual = chain.submit(a.wallet.built[0]);
  chain.mine();
  chain.mine();
  await b.controller.enterHash(manual);
  assert.equal(b.controller.phase(), 'success');
  b.controller.requestClear();
  await b.controller.confirmClear();
  assert.equal(db.raw, null, 'explicit clear writes a tombstone');
  const revision = db.revision;
  a.wallet.releaseSend();
  await flush();
  await flush();
  assert.equal(db.raw, null, 'late callback does not resurrect the cleared attempt');
  assert.equal(db.revision, revision);
  assert.ok(a.controller.view().notices.staleHash, 'returned hash preserved as a notice');
  assert.ok(a.controller.view().sendNotice.includes(a.controller.view().notices.staleHash), 'notice visible');
  assert.equal(await a.controller.send(), false, 'send disabled until an explicit reload');
  assert.equal(a.controller.locked(), true);
  // ABA: identical bytes return at a newer revision; a writer holding the old revision cannot commit.
  const db2 = new MemoryAttemptDB();
  const c = await setup({ db: db2, chain: new FakeChain() });
  await ready(c);
  c.wallet.behavior.send = 'deferred';
  await c.controller.send();
  const x = db2.raw;
  const d = await setup({ db: db2, chain: c.chain });
  const old = d.controller.snapshot;
  db2.put(JSON.stringify({ ...JSON.parse(x), state: 'unknown', reason: 'send-timeout' }));
  db2.put(x);
  assert.equal(db2.raw, old.raw, 'same bytes');
  const result = await d.store.compareAndSet(old, null);
  assert.equal(result.committed, false, 'old revision refused despite identical bytes');
  assert.equal(db2.raw, x);
  assert.equal(a.wallet.sends.length + b.wallet.sends.length + c.wallet.sends.length + d.wallet.sends.length, 2);
});

const LATE = '0x' + 'ab'.repeat(32);
const rejection = () => Object.assign(new Error('rejected'), { code: 4001 });
const settleAll = async (n = 4) => { for (let i = 0; i < n; i++) await flush(); };

test('a 4001 after an unsaved send timeout stays unknown; a held outcome is never dropped by a weaker one', async () => {
  const { identityOf } = await import('../controller.js');
  async function unsavedTimeout() {
    const env = await setup();
    await ready(env);
    env.wallet.behavior.send = 'deferred';
    await env.controller.send();
    env.db.mode = 'full';
    await env.clock.advance(60_000);
    await settleAll();
    assert.equal(JSON.parse(env.db.raw).state, 'walletPending', 'the timeout was not saved');
    assert.equal(env.controller.view().notices.unsaved, true);
    return env;
  }
  // Storage recovers before the late 4001: the saved row is unknown, never a clearable rejection.
  let env = await unsavedTimeout();
  env.db.mode = 'ok';
  env.wallet.pendingSends[0].reject(rejection());
  await settleAll();
  let saved = JSON.parse(env.db.raw);
  assert.equal(saved.state, 'unknown');
  assert.notEqual(saved.reason, 'user-rejected');
  assert.equal(env.controller.phase(), 'unknown');
  assert.equal(env.controller.clearable(), false);
  assert.equal(env.controller.view().notices.unsaved, false);
  assert.equal(env.wallet.sends.length, 1, 'no extra send');
  // The 4001 save fails too: the held outcome is merged, and the explicit retry saves unknown, never rejected.
  env = await unsavedTimeout();
  env.wallet.pendingSends[0].reject(rejection());
  await settleAll();
  assert.equal(JSON.parse(env.db.raw).state, 'walletPending');
  assert.equal(env.controller.phase(), 'unknown');
  assert.equal(env.controller.view().notices.unsaved, true);
  env.db.mode = 'ok';
  await env.controller.refresh();
  await settleAll();
  saved = JSON.parse(env.db.raw);
  assert.equal(saved.state, 'unknown');
  assert.notEqual(saved.reason, 'user-rejected');
  assert.equal(env.controller.clearable(), false);
  assert.equal(env.controller.view().notices.unsaved, false);
  assert.equal(env.wallet.sends.length, 1);
  // A held unsaved hash survives a later timeout or error outcome of the same identity: the hash is what commits.
  for (const weaker of [{ kind: 'timeout' }, { kind: 'error', code: 4001 }, { kind: 'malformed' }]) {
    env = await setup();
    await ready(env);
    env.wallet.behavior.send = 'deferred';
    await env.controller.send();
    const identity = identityOf(JSON.parse(env.db.raw));
    env.db.mode = 'full';
    env.wallet.releaseSend();
    await settleAll();
    const held = env.controller.attempt.hash;
    assert.ok(held && env.controller.view().notices.unsaved, `${weaker.kind}: hash held unsaved`);
    await env.controller.reconcileOutcome(identity, weaker);
    assert.equal(env.controller.view().notices.unsaved, true, `${weaker.kind}: failed save keeps the held hash`);
    assert.equal(env.controller.attempt.hash, held);
    env.db.mode = 'ok';
    await env.controller.reconcileOutcome(identity, weaker);
    await settleAll();
    assert.equal(JSON.parse(env.db.raw).hash, held, `${weaker.kind}: the held hash is saved, not dropped`);
    assert.equal(env.controller.view().notices.unsaved, false);
    assert.equal(env.wallet.sends.length, 1);
  }
});

/** One tab: X times out, a reverted manual hash resolves it as failed, X is cleared; X's wallet call is still open. */
async function clearedWhilePending() {
  const env = await setup();
  await ready(env);
  env.wallet.behavior.send = 'deferred';
  await env.controller.send();
  await env.clock.advance(60_000);
  const manual = env.chain.submit({ ...env.wallet.built[0] });
  env.chain.mine({ revert: true });
  env.chain.mine();
  await env.controller.enterHash(manual);
  assert.equal(env.controller.phase(), 'failed');
  env.controller.requestClear();
  await env.controller.confirmClear();
  assert.equal(env.db.raw, null);
  assert.equal(env.controller.locked(), false, 'nothing locks before the stale callback');
  env.wallet.behavior.send = 'ok';
  return env;
}

async function until(predicate) {
  for (let i = 0; i < 50 && !predicate(); i++) await flush();
  assert.ok(predicate(), 'bounded barrier reached');
}

test('a stale callback of a cleared attempt locks sending until reload, whatever is displayed', async (t) => {
  await t.test('late hash while another attempt Y is displayed', async () => {
    const env = await clearedWhilePending();
    await ready(env);
    await env.controller.send();
    await settleAll();
    const y = env.controller.attempt;
    assert.ok(y && y.hash, 'Y sent and displayed');
    env.wallet.pendingSends[0].resolve(LATE);
    await settleAll();
    let view = env.controller.view();
    assert.equal(view.locked, true);
    assert.equal(view.notices.reloadRequired, true);
    assert.equal(view.notices.staleHash, LATE);
    assert.ok(view.sendNotice.includes(LATE) && view.sendNotice.includes('再読み込み'), 'reload reason and hash');
    assert.equal(view.notices.lateHash, null, 'not attributed to Y');
    assert.equal(view.notices.cleared, false, 'Y is not told it was cleared');
    assert.equal(view.attempt.id, y.id);
    assert.equal(JSON.parse(env.db.raw).id, y.id, 'Y row untouched');
    // Resolving and clearing Y keeps the lock and the notice.
    env.chain.mine();
    env.chain.mine();
    await env.controller.refresh();
    assert.equal(env.controller.phase(), 'success');
    env.controller.requestClear();
    await env.controller.confirmClear();
    view = env.controller.view();
    assert.equal(view.locked, true);
    assert.equal(view.notices.staleHash, LATE);
    assert.ok(view.sendNotice.includes(LATE));
    env.controller.prepare(handoffText);
    await env.controller.inspect();
    assert.equal(await env.controller.send(), false);
    assert.equal(env.wallet.sends.length, 2, 'X and Y only');
  });
  for (const kind of ['transport', 'malformed', '4001']) await t.test(`late ${kind} after the clear`, async () => {
    const env = await clearedWhilePending();
    const pending = env.wallet.pendingSends[0];
    if (kind === 'malformed') pending.resolve('not-a-hash');
    else pending.reject(kind === '4001' ? rejection() : Object.assign(new Error('transport'), { code: -32603 }));
    await settleAll();
    assert.equal(env.db.raw, null, 'no write');
    const view = env.controller.view();
    assert.equal(view.locked, true);
    assert.equal(view.notices.reloadRequired, true);
    assert.ok(view.sendNotice, 'reload reason visible');
    env.controller.prepare(handoffText);
    await env.controller.inspect();
    assert.equal(env.controller.canSend(), false);
    assert.equal(await env.controller.send(), false);
    assert.equal(env.wallet.sends.length, 1);
  });
  await t.test('late hash during Y revalidation', async () => {
    const env = await clearedWhilePending();
    await ready(env);
    const held = gate(env.chain, (m) => m === 'eth_getTransactionCount');
    const sending = env.controller.send();
    await until(() => held.waiting > 0);
    env.wallet.pendingSends[0].resolve(LATE);
    await settleAll();
    held.release();
    held.restore();
    assert.equal(await sending, false);
    assert.equal(env.wallet.sends.length, 1, 'zero wallet calls for Y');
    assert.equal(env.db.raw, null, 'Y never admitted');
    assert.equal(env.controller.locked(), true);
  });
  await t.test('late hash during Y admission', async () => {
    const env = await clearedWhilePending();
    await ready(env);
    const release = env.db.hold();
    const sending = env.controller.send();
    await until(() => env.db.gates.length === 0);
    env.wallet.pendingSends[0].resolve(LATE);
    await settleAll();
    release();
    assert.equal(await sending, false);
    await settleAll();
    assert.equal(env.wallet.sends.length, 1, 'zero wallet calls for Y');
    assert.equal(env.db.raw, null, 'the just-committed admission is withdrawn');
    assert.equal(env.controller.locked(), true);
    assert.equal(env.controller.view().notices.staleHash, LATE);
  });
});

test('another tab clears X and sends Y: A\'s X timeout adopts Y without attributing the clear to Y', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const a = await setup({ db, chain, tab: 1 });
  await ready(a);
  a.wallet.behavior.send = 'deferred';
  await a.controller.send();
  const x = a.controller.attempt;
  const b = await setup({ db, chain, tab: 2 });
  const manual = chain.submit({ ...a.wallet.built[0] });
  chain.mine({ revert: true });
  chain.mine();
  await b.controller.enterHash(manual);
  assert.equal(b.controller.phase(), 'failed');
  b.controller.requestClear();
  await b.controller.confirmClear();
  assert.equal(db.raw, null);
  await ready(b);
  await b.controller.send();
  await settleAll();
  const y = JSON.parse(db.raw);
  assert.notEqual(y.id, x.id, 'distinct attempts');
  await a.clock.advance(60_000);
  await settleAll();
  const view = a.controller.view();
  assert.equal(view.attempt.id, y.id, 'A adopts Y read-only');
  assert.equal(view.locked, true, 'X was sent here: locked until reload');
  assert.equal(view.notices.reloadRequired, true);
  assert.ok(view.sendNotice && view.sendNotice.includes('再読み込み'), 'reload reason visible');
  assert.equal(view.notices.cleared, false, 'Y is not told it was cleared');
  assert.equal(await a.controller.send(), false);
  assert.equal(a.wallet.sends.length, 1);
});

test('a displayed attempt that another tab cleared still carries the cleared notice', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const a = await setup({ db, chain, tab: 1 });
  await ready(a);
  a.wallet.behavior.send = 'deferred';
  await a.controller.send();
  const x = a.controller.attempt;
  const b = await setup({ db, chain, tab: 2 });
  const manual = chain.submit({ ...a.wallet.built[0] });
  chain.mine();
  chain.mine();
  await b.controller.enterHash(manual);
  assert.equal(b.controller.phase(), 'success');
  b.controller.requestClear();
  await b.controller.confirmClear();
  assert.equal(db.raw, null);
  await a.clock.advance(60_000);
  await settleAll();
  const view = a.controller.view();
  assert.equal(view.attempt && view.attempt.id, x.id, 'X stays displayed, never recreated');
  assert.equal(db.raw, null);
  assert.equal(view.locked, true);
  assert.equal(view.notices.cleared, true, 'X itself was cleared elsewhere');
});

test('a late hash for an attempt another tab cleared stays visible after release and wallet events', async () => {
  const db = new MemoryAttemptDB();
  const chain = new FakeChain();
  const a = await setup({ db, chain });
  await ready(a);
  a.wallet.behavior.send = 'deferred';
  await a.controller.send();
  const b = await setup({ db, chain });
  const manual = chain.submit(a.wallet.built[0]);
  chain.mine();
  chain.mine();
  await b.controller.enterHash(manual);
  assert.equal(b.controller.phase(), 'success');
  // A's timeout adopts the resolved row read-only and revalidates it.
  await a.clock.advance(60_000);
  await settleAll();
  assert.equal(a.controller.phase(), 'success');
  b.controller.requestClear();
  await b.controller.confirmClear();
  assert.equal(db.raw, null);
  a.wallet.releaseSend();
  await settleAll();
  const check = (label) => {
    const view = a.controller.view();
    assert.equal(view.attempt, null, `${label}: resolved attempt released`);
    assert.ok(view.notices.staleHash && view.notices.staleHash !== manual, `${label}: returned hash kept`);
    assert.ok(view.sendNotice.includes(view.notices.staleHash), `${label}: hash visible`);
    assert.ok(view.sendNotice.includes('再読み込み'), `${label}: reload reason`);
    assert.equal(view.notices.reloadRequired, true);
    assert.equal(view.locked, true);
  };
  check('after release');
  a.wallet.emitAccounts([OTHER]);
  check('account');
  a.wallet.emitChain('0x1');
  check('chain');
  a.wallet.emit('disconnect');
  check('disconnect');
  assert.equal(await a.controller.send(), false);
  assert.equal(db.raw, null);
  assert.equal(a.wallet.sends.length + b.wallet.sends.length, 1);
});

test('a background poll retrying an unsaved wallet hash never moves focus', async () => {
  const env = await setup();
  await ready(env);
  env.wallet.behavior.send = 'deferred';
  await env.controller.send();
  await env.clock.advance(60_000);
  const manual = env.chain.submit({ ...env.wallet.built[0] });
  await env.controller.enterHash(manual);
  assert.equal(env.controller.attempt.hash, manual, 'manual hash polled');
  env.db.mode = 'full';
  env.wallet.releaseSend();
  await settleAll();
  const walletHash = env.controller.attempt.hash;
  assert.ok(walletHash && walletHash !== manual && env.controller.view().notices.unsaved);
  const seq = env.controller.view().focus.seq;
  // Two failing polls, then one after storage recovers.
  await env.clock.advance(12_000);
  await settleAll();
  await env.clock.advance(12_000);
  await settleAll();
  assert.equal(env.controller.view().notices.unsaved, true);
  assert.equal(env.controller.view().focus.seq, seq, 'failed background retries keep focus');
  env.db.mode = 'ok';
  await env.clock.advance(12_000);
  await settleAll();
  assert.equal(env.controller.view().notices.unsaved, false);
  assert.equal(JSON.parse(env.db.raw).hash, walletHash, 'hash saved by the background retry');
  assert.equal(env.controller.view().focus.seq, seq, 'a successful background retry keeps focus');
  assert.equal(env.wallet.sends.length, 1, 'zero extra sends');
});

// -------------------------------------------------------------------------------------------------
// The single explicit action ウォレットで配備 (deploy): one activation continues from connect through the Polygon
// switch and the strict inspection to the existing single-flight send. Every negative path asserts zero sends.

const methods = (wallet) => wallet.requests.map((r) => r.method);
/** Gates the next chain RPC call matching `method`; returns release(). */
function gateChain(chain, method) {
  const original = chain.rpc.bind(chain);
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let armed = true;
  chain.rpc = async (m, p) => {
    if (armed && m === method) { armed = false; await gate; }
    return original(m, p);
  };
  return release;
}

test('one explicit activation continues from connect through switch and inspection to exactly one send', async () => {
  const env = await setup();
  const { controller, wallet, chain } = env;
  wallet.chainId = '0x1';
  assert.equal(controller.nextStage(), null, 'no plan: nothing to do');
  assert.equal(await controller.deploy(), false);
  controller.prepare(handoffText);
  assert.equal(controller.nextStage(), 'connect', 'the sole provider is selected without connecting');
  assert.equal(wallet.requests.length, 0, 'selection never requests accounts');
  controller.selectWallet('legacy');
  assert.equal(controller.nextStage(), 'connect');
  const sent = await controller.deploy();
  assert.equal(sent, true, 'the activation reached the send');
  assert.equal(wallet.sends.length, 1, 'exactly one eth_sendTransaction');
  assert.deepEqual(Object.keys(wallet.sends[0]).sort(), EXACT_REQUEST_KEYS);
  assert.equal(wallet.sends[0].from, ACCOUNT);
  const m = methods(wallet);
  assert.equal(m[0], 'eth_requestAccounts', 'connect is the first wallet request');
  assert.deepEqual(wallet.requests.filter((r) => r.method === 'wallet_switchEthereumChain').map((r) => r.params),
    [[{ chainId: '0x89' }]], 'exactly one explicit 0x89 switch');
  assert.ok(m.indexOf('wallet_switchEthereumChain') < m.indexOf('eth_sendTransaction'));
  assert.ok(m.filter((x) => x === 'eth_sendTransaction').length === 1);
  // The send stage itself kept its fresh revalidation: wallet account/chain reread after the inspection.
  const afterSwitch = m.slice(m.indexOf('wallet_switchEthereumChain') + 1);
  assert.ok(afterSwitch.includes('eth_accounts') && afterSwitch.includes('eth_chainId'), 'send-time rechecks');
  assert.ok(chain.calls.some((c) => c.method === 'eth_getTransactionCount'), 'pending nonce lookup before admission');
  await flush();
  assert.equal(controller.phase(), 'txPending');
  assert.equal(controller.operation, null);
  assert.equal(controller.nextStage(), null, 'a stored attempt locks the action');
  assert.equal(await controller.deploy(), false);
  assert.equal(wallet.sends.length, 1);
  assert.equal(chain.writes, 1, 'one admission');
});

test('repeated activation performs one operation and at most one send', async () => {
  const env = await setup();
  const { controller, wallet } = env;
  controller.prepare(handoffText);
  controller.selectWallet('legacy');
  wallet.behavior.connect = 'deferred';
  const first = controller.deploy();
  const second = controller.deploy();
  const third = controller.deploy();
  assert.equal(controller.view().operation, 'connect');
  assert.equal(controller.view().stage, null, 'nothing is offered while the operation runs');
  assert.equal(await second, false);
  assert.equal(await third, false);
  await flush();
  assert.equal(wallet.requests.filter((r) => r.method === 'eth_requestAccounts').length, 1, 'one connect request');
  wallet.behavior.send = 'deferred';
  wallet.releaseConnect();
  assert.equal(await first, true);
  assert.equal(wallet.sends.length, 1, 'the one activation sent once');
  assert.equal(controller.phase(), 'walletPending');
  assert.equal(await controller.deploy(), false, 'no activation while the wallet approval is pending');
  assert.equal(wallet.sends.length, 1);
  wallet.releaseSend();
  await flush();
  assert.equal(controller.phase(), 'txPending');
  // From a ready review (individual controls), rapid activation still sends exactly once.
  const other = await setup();
  await ready(other);
  other.wallet.behavior.send = 'deferred';
  const sends = [other.controller.deploy(), other.controller.deploy(), other.controller.deploy()];
  await flush();
  assert.equal(other.wallet.sends.length, 1, 'exactly one send request for repeated clicks');
  other.wallet.releaseSend();
  assert.deepEqual(await Promise.all(sends), [true, false, false]);
  assert.equal(other.wallet.sends.length, 1);
});

test('a rejected connection or switch ends the activation with zero sends; the next activation starts afresh', async () => {
  const { MESSAGES } = await import('../controller.js');
  const env = await setup();
  const { controller, wallet } = env;
  controller.prepare(handoffText);
  controller.selectWallet('legacy');
  wallet.behavior.connect = 'reject';
  assert.equal(await controller.deploy(), false);
  assert.equal(controller.phase(), 'disconnected');
  assert.equal(controller.view().wallet.error.code, 'rejected');
  assert.equal(controller.sendNotice, null, 'a wallet rejection is the wallet\'s message, not drift');
  assert.equal(controller.nextStage(), 'connect', 'the next activation retries the connection');
  assert.equal(wallet.sends.length, 0);
  wallet.behavior.connect = 'unavailable';
  assert.equal(await controller.deploy(), false);
  assert.equal(controller.view().wallet.error.code, 'unavailable');
  wallet.behavior.connect = 'ok';
  wallet.chainId = '0x1';
  for (const [mode, code] of [['reject', 'switchRejected'], ['4902', 'switchUnsupported']]) {
    wallet.behavior.switch = mode;
    assert.equal(await controller.deploy(), false);
    assert.equal(controller.phase(), 'wrongChain', `${mode}: the activation ends at the switch`);
    assert.equal(controller.view().wallet.error.code, code);
    assert.equal(controller.nextStage(), 'switch');
    assert.equal(controller.review, null, 'no inspection off Polygon');
    assert.equal(wallet.sends.length, 0);
  }
  const switches = wallet.requests.filter((r) => r.method === 'wallet_switchEthereumChain');
  assert.equal(switches.length, 2);
  assert.ok(switches.every((r) => r.params[0].chainId === '0x89'), 'only 0x89, never add-chain');
  assert.equal(wallet.requests.filter((r) => r.method === 'eth_requestAccounts').length, 3, 'connect is not repeated');
  wallet.behavior.switch = 'ok';
  assert.equal(await controller.deploy(), true, 'the approved switch continues to the send');
  assert.equal(wallet.sends.length, 1);
  assert.notEqual(MESSAGES.interrupted, undefined);
});

test('drift before an activation leaves no stale send; a new activation inspects the current target afresh', async () => {
  const env = await setup();
  const { controller, wallet, manager, chain } = env;
  const next = new FakeWallet(chain, { accounts: [OTHER] });
  manager.announce({ info: { uuid: 'next', name: 'Next' }, provider: next });
  await ready(env);
  const from = controller.review.from;
  // Each kind of drift removes the send stage; no event alone ever sends.
  wallet.emitAccounts([OTHER]);
  assert.equal(controller.phase(), 'connected');
  assert.equal(controller.nextStage(), 'inspect');
  await controller.inspect();
  assert.equal(controller.phase(), 'ready');
  wallet.emitChain('0x1');
  assert.equal(controller.nextStage(), 'switch');
  wallet.emitChain('0x89');
  assert.equal(controller.nextStage(), 'inspect');
  await controller.inspect();
  controller.inputEdited();
  assert.equal(controller.nextStage(), null);
  assert.equal(await controller.deploy(), false);
  controller.prepare(handoffText);
  await controller.inspect();
  assert.equal(controller.phase(), 'ready');
  wallet.emit('disconnect');
  assert.equal(controller.nextStage(), 'connect');
  await controller.connect();
  await controller.inspect();
  assert.equal(controller.phase(), 'ready');
  controller.selectWallet('eip6963:next');
  assert.equal(controller.nextStage(), 'connect');
  assert.equal(wallet.sends.length + next.sends.length, 0, 'drift never sends');
  // The activation after drift binds the current provider/account, never the earlier review's identity.
  assert.equal(await controller.deploy(), true);
  assert.equal(next.sends.length, 1);
  assert.equal(wallet.sends.length, 0, 'the earlier provider receives nothing');
  assert.equal(next.sends[0].from, OTHER);
  assert.notEqual(next.sends[0].from, from);
});

test('drift during an await cancels the activation before its next stage with zero sends', async () => {
  const { MESSAGES } = await import('../controller.js');
  // During the wallet connection (deferred approval): the plan is edited or re-confirmed.
  for (const edit of [(c) => c.inputEdited(), (c) => c.prepare(handoffText)]) {
    const env = await setup();
    const { controller, wallet } = env;
    controller.prepare(handoffText);
    controller.selectWallet('legacy');
    wallet.behavior.connect = 'deferred';
    const pending = controller.deploy();
    await flush();
    edit(controller);
    wallet.releaseConnect();
    assert.equal(await pending, false);
    await flush();
    assert.equal(wallet.sends.length, 0);
    assert.equal(controller.review, null, 'no inspection for a plan the activation was not started for');
    assert.equal(controller.inspection.status, 'idle');
    assert.ok(!wallet.requests.some((r) => r.method === 'wallet_switchEthereumChain' || r.method === 'eth_sendTransaction'));
    assert.equal(controller.sendNotice, MESSAGES.interrupted);
    assert.equal(controller.operation, null);
  }
  // During the read-only inspection: provider reselection, account change, chain change, disconnect.
  const drifts = {
    provider: (env) => env.controller.selectWallet('eip6963:next'),
    account: (env) => env.wallet.emitAccounts([OTHER]),
    chain: (env) => env.wallet.emitChain('0x1'),
    disconnectEvent: (env) => env.wallet.emit('disconnect'),
    disconnectCommand: (env) => env.controller.disconnect(),
    input: (env) => env.controller.inputEdited(),
  };
  for (const [name, drift] of Object.entries(drifts)) {
    const env = await setup();
    const { controller, wallet, manager, chain } = env;
    const next = new FakeWallet(chain, { accounts: [OTHER] });
    manager.announce({ info: { uuid: 'next', name: 'Next' }, provider: next });
    controller.prepare(handoffText);
    controller.selectWallet('legacy');
    const release = gateChain(chain, 'eth_getBlockByNumber');
    const pending = controller.deploy();
    for (let i = 0; i < 4; i++) await flush();
    assert.equal(controller.view().operation, 'inspect', `${name}: the activation is inspecting`);
    await drift(env);
    release();
    assert.equal(await pending, false, `${name}: cancelled`);
    await flush();
    assert.equal(wallet.sends.length + next.sends.length, 0, `${name}: zero sends`);
    assert.equal(controller.review, null, `${name}: no review survives`);
    assert.equal(controller.canSend(), false);
    assert.equal(controller.operation, null);
    assert.ok(!wallet.requests.some((r) => r.method === 'eth_sendTransaction'));
    assert.equal(chain.writes, 0, `${name}: nothing admitted`);
    if (name !== 'input') assert.ok(controller.sendNotice === MESSAGES.interrupted || controller.sendNotice === null);
  }
  // During the send stage's own revalidation the existing drift check refuses the send (no admission).
  const env = await setup();
  const { controller, wallet, chain } = env;
  controller.prepare(handoffText);
  controller.selectWallet('legacy');
  const release = gateChain(chain, 'eth_getTransactionCount');
  const pending = controller.deploy();
  for (let i = 0; i < 12; i++) await flush();
  assert.equal(controller.view().operation, 'send');
  wallet.emitAccounts([OTHER]);
  release();
  assert.equal(await pending, false);
  assert.equal(wallet.sends.length, 0);
  assert.equal(chain.writes, 0, 'drift before admission never writes');
  assert.equal(controller.sendNotice, MESSAGES.drift);
  assert.equal(controller.nextStage(), 'inspect', 'the next activation inspects the current account afresh');
});

test('an already deployed target completes the activation with zero sends', async () => {
  const env = await setup();
  const { controller, wallet, chain, model } = env;
  chain.preDeploy(planOf(model));
  controller.prepare(handoffText);
  controller.selectWallet('legacy');
  assert.equal(await controller.deploy(), false);
  assert.equal(controller.phase(), 'deployed');
  assert.equal(controller.nextStage(), null, 'nothing to do');
  assert.equal(wallet.sends.length, 0);
  assert.equal(chain.writes, 0);
  assert.equal(controller.attempt, null, 'no record is invented for a deployment this page did not send');
  // Deployed between the review and the activation: the send stage's fresh inspection stops it (existing path).
  const late = await setup();
  await ready(late);
  late.chain.preDeploy(planOf(late.model));
  assert.equal(await late.controller.deploy(), false);
  assert.equal(late.controller.phase(), 'deployed');
  assert.equal(late.wallet.sends.length, 0);
  assert.equal(late.chain.writes, 0);
});

test('page load, plan restore and plain wallet events never send', async () => {
  const planStore = memoryPlanStore();
  const env = await setup({ planStore });
  const { controller, wallet, chain, model } = env;
  controller.prepare(handoffText);
  assert.equal(planStore.read(), JSON.stringify(planOf(model).handoff), 'the validated manifest is remembered');
  controller.selectWallet('legacy');
  await controller.connect();
  wallet.emitChain('0x1');
  await controller.switchPolygon();
  wallet.emitAccounts([OTHER]);
  wallet.emitAccounts([ACCOUNT]);
  await controller.inspect();
  assert.equal(controller.phase(), 'ready', 'a ready review alone is not a send');
  assert.equal(wallet.sends.length, 0);
  // "Reload": a fresh controller over the same tab store restores the plan with zero wallet or chain activity.
  const reloaded = await setup({ planStore: memoryPlanStore(planStore.map), chain, db: env.db });
  const calls = chain.calls.length;
  assert.equal(reloaded.controller.restorePlan(), true);
  assert.equal(reloaded.controller.phase(), 'disconnected');
  assert.equal(reloaded.controller.plan.address, planOf(model).address);
  assert.equal(reloaded.controller.nextStage(), 'connect', 'sole provider selected, connection still explicit');
  assert.equal(reloaded.wallet.requests.length, 0);
  assert.equal(chain.calls.length, calls, 'restore reads nothing from the chain');
  assert.equal(reloaded.wallet.sends.length, 0);
  assert.equal(reloaded.controller.restorePlan(), false, 'a loaded plan is never replaced by the copy');
  // Editing the input drops the copy; a failed confirmation leaves none.
  reloaded.controller.inputEdited();
  assert.equal(planStore.read(), null);
  reloaded.controller.prepare('{"version":1,');
  assert.equal(planStore.read(), null);
  assert.equal(reloaded.controller.phase(), 'inputError');
});

test('a remembered plan is validated like input, loses to a fragment and never outranks a stored attempt', async () => {
  const bad = ['x'.repeat(5000), '{"version":1,', JSON.stringify({ ...JSON.parse(handoffText), expectedAddress: OTHER }),
    '[]', 'https://example.invalid', ''];
  for (const text of bad) {
    const planStore = memoryPlanStore();
    planStore.write(text);
    const env = await setup({ planStore });
    assert.equal(env.controller.restorePlan(), false, `rejected: ${text.slice(0, 16)}`);
    assert.equal(env.controller.phase(), 'empty');
    assert.equal(env.controller.inputError, null, 'a broken copy is dropped, not echoed');
    assert.equal(planStore.read(), text === '' ? '' : null, 'a broken copy is removed');
  }
  const throwing = { read: () => { throw new Error('denied'); }, write: () => { throw new Error('denied'); },
    remove: () => { throw new Error('denied'); } };
  const denied = await setup({ planStore: throwing });
  assert.equal(denied.controller.restorePlan(), false);
  denied.controller.prepare(handoffText);
  assert.equal(denied.controller.phase(), 'disconnected', 'a denied copy never blocks the plan');
  // A fragment wins: valid replaces the copy, invalid shows the fragment error and leaves no copy.
  const other = JSON.stringify({ ...JSON.parse(handoffText) });
  const planStore = memoryPlanStore();
  planStore.write(other);
  const env = await setup({ planStore });
  const fragment = '#registration=' + Buffer.from(handoffText).toString('base64url');
  const history = { replaceState: () => {} };
  assert.equal(env.controller.consumeFragment({ hash: fragment, pathname: '/' }, history), true);
  assert.equal(env.controller.phase(), 'disconnected');
  assert.equal(planStore.read(), JSON.stringify(env.controller.plan.handoff));
  const broken = await setup({ planStore: memoryPlanStore(planStore.map) });
  assert.equal(broken.controller.consumeFragment({ hash: '#registration=%%', pathname: '/' }, history), true);
  assert.equal(broken.controller.phase(), 'inputError');
  assert.equal(planStore.read(), null, 'an invalid fragment leaves no copy to restore');
  assert.equal(broken.controller.restorePlan(), false);
  // A stored attempt keeps its priority and lock; the restored plan only shows the target.
  const sender = await setup({ planStore: memoryPlanStore() });
  sender.controller.prepare(handoffText);
  sender.controller.selectWallet('legacy');
  sender.wallet.behavior.send = 'deferred';
  const pending = sender.controller.deploy();
  await flush();
  assert.equal(sender.wallet.sends.length, 1);
  const resumed = await setup({ planStore: memoryPlanStore(sender.controller.planStore.map), db: sender.db, chain: sender.chain });
  assert.equal(resumed.controller.restorePlan(), true);
  assert.equal(resumed.controller.phase(), 'unknown', 'the stored row (reload during approval) wins the phase');
  assert.equal(resumed.controller.plan.address, planOf(sender.model).address);
  resumed.controller.selectWallet('legacy');
  assert.equal(resumed.controller.nextStage(), null, 'an unresolved record offers no stage');
  assert.equal(await resumed.controller.deploy(), false);
  assert.equal(resumed.wallet.requests.length, 0);
  assert.equal(resumed.wallet.sends.length, 0);
  sender.wallet.pendingSends[0].reject(Object.assign(new Error('User rejected'), { code: 4001 }));
  await pending;
  await flush();
});

test('a storage failure or a competing stored row stops the activation before any wallet send', async () => {
  // Storage aborts the admission: zero sends, send blocked.
  const env = await setup();
  const { controller, wallet, db } = env;
  controller.prepare(handoffText);
  controller.selectWallet('legacy');
  db.mode = 'aborted';
  assert.equal(await controller.deploy(), false);
  assert.equal(controller.phase(), 'storageError');
  assert.equal(wallet.sends.length, 0);
  assert.equal(controller.nextStage(), null);
  // Another tab admits its attempt between this tab's review and activation: this tab yields read-only.
  const shared = new MemoryAttemptDB();
  const chain = new FakeChain();
  const a = await setup({ db: shared, chain, tab: 1 });
  const b = await setup({ db: shared, chain, tab: 2, accounts: [OTHER] });
  await ready(a);
  b.controller.prepare(handoffText);
  b.controller.selectWallet('legacy');
  assert.equal(await b.controller.deploy(), true);
  assert.equal(b.wallet.sends.length, 1, 'the other tab sent');
  await flush();
  const writes = shared.writes;
  assert.equal(await a.controller.deploy(), false);
  assert.equal(a.wallet.sends.length, 0, 'this tab yields to the stored row with no wallet send');
  assert.equal(a.controller.attempt.from, OTHER, 'the other tab\'s attempt is displayed read-only');
  assert.equal(a.controller.nextStage(), null);
  assert.equal(shared.writes, writes, 'the yielding tab writes nothing');
});

test('a hashless unknown attempt refreshes read-only: expected-address readback only, state and lock unchanged', async () => {
  const env = await setup();
  const { controller, wallet, chain, db } = env;
  controller.prepare(handoffText);
  controller.selectWallet('legacy');
  wallet.behavior.send = 'deferred';
  const pending = controller.deploy();
  await flush();
  assert.equal(wallet.sends.length, 1);
  const reloaded = await setup({ db, chain });
  const { controller: c } = reloaded;
  assert.equal(c.phase(), 'unknown');
  assert.equal(c.attempt.hash, null);
  assert.equal(c.settlement, null, 'nothing is read on load');
  const calls = chain.calls.length;
  await c.refresh();
  assert.ok(chain.calls.length > calls, 'the explicit refresh reads');
  assert.equal(c.settlement.hashless, true);
  assert.equal(c.settlement.readback, 'not-deployed');
  assert.equal(c.phase(), 'unknown', 'an empty address is not proof that nothing was sent');
  assert.equal(c.clearable(), false);
  assert.equal(db.writes, 1, 'no write');
  assert.equal(reloaded.wallet.sends.length, 0);
  // The wallet later broadcasts and the deployment lands: readback deployed, but still not this send's receipt.
  wallet.releaseSend();
  await pending;
  await flush();
  chain.mine();
  chain.mine();
  await c.refresh();
  assert.equal(c.settlement.readback, 'deployed');
  assert.equal(c.attempt.state, 'unknown', 'a deployed readback is not confused with this send\'s receipt');
  assert.equal(c.clearable(), false);
  assert.ok(!chain.calls.some((call) => call.method === 'eth_getLogs'), 'no scan');
  assert.equal(reloaded.wallet.sends.length, 0);
  // Read failure stays honest.
  chain.faults.offline = true;
  await c.refresh();
  assert.equal(c.settlement.readback, 'unknown');
  assert.equal(c.phase(), 'unknown');
});
