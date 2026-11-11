'use strict';
// Native IndexedDB causal suite for the production AttemptStore + RegistrationController + WalletManager.
// - The production modules are bundled unmodified (esbuild, in memory) and served from a loopback test origin;
//   every other request (and any WebSocket) is denied and recorded.
// - Each case runs in a fresh Chromium context; competing pages are independently opened pages of that context and
//   share one real IndexedDB. Renderer process placement is not observed and is recorded UNKNOWN.
// - Wallets are fake EIP-1193 providers backed by FakeWallet (different accounts per page; every send captured)
//   and one read-only FakeChain double. Assertions read actual wallet sends and stored bytes/revisions.
// - A test-only unsafe store (checks outside the writing transaction / omits the revision) must fail the same
//   predicates the production store passes. No unsafe switch exists in production code.
// Usage: node tests/check-attempt-store.cjs <evidence.json>
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const esbuild = require('esbuild');
const { chromium } = require('playwright');
const { FakeChain, FakeWallet, legacyAttempt } = require('./support/fake-chain.cjs');

const APP = path.resolve(__dirname, '..');
const ROOT = path.resolve(APP, '../..');
const ACCOUNT = '0x1111111111111111111111111111111111111111';
const OTHER = '0x2222222222222222222222222222222222222222';
const BIGGAS = '0xdbba0';
const vectors = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests/fixtures/registry-vectors.json'), 'utf8'));
const ROW = vectors.vectors.find((v) => v.name === 'd1-pattern');
const HANDOFF = JSON.stringify({ chainId: 137, expectedAddress: ROW.address, keyID: ROW.keyID, publicKey: ROW.publicPoint,
  recipe: vectors.recipe, salt: ROW.salt, version: 1 });
const CASE_TIMEOUT_MS = 20_000;
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

/** Exact required case IDs; the judge rejects missing, duplicate, unknown, failed or not-evaluated rows. */
const CASE_IDS = [
  'admission.concurrent-empty', 'admission.hash-before-conflict', 'admission.reopen-loser', 'admission.abort-after-put', 'admission.post-commit-drift',
  'adoption.success-clear', 'adoption.failed-clear', 'adoption.first-hash-poll',
  'outcome.suspended-timeout-keeps-unsaved-hash', 'outcome.conflict-keeps-unsaved-hash-visible',
  'admission.sync-throw', 'admission.strict-unsupported', 'outcome.timeout-keeps-other-tab-hash',
  'outcome.malformed-keeps-other-tab-hash', 'outcome.4001-keeps-other-tab-hash', 'refresh.stale-same-id',
  'clear.stale-confirmation', 'clear.committed-keeps-unsaved-hash', 'late-hash.pending-manual-replaced', 'late-hash.wallet-fee-not-override',
  'late-hash.cancellation-retained', 'late-hash.success-retained', 'tombstone.no-resurrection', 'tombstone.aba',
  'corrupt.foreign-row', 'corrupt.unknown-field', 'open.timeout-late-success', 'connection.versionchange-release',
  'connection.page-close', 'bootstrap.legacy-import-clear-reload', 'bootstrap.legacy-invalid',
  'bootstrap.legacy-changed', 'bootstrap.concurrent-create', 'outcome.unsaved-retry',
  'control.unsafe-outside-transaction', 'control.unsafe-no-revision',
  'legacy.v1-override-locked', 'legacy.v1-pending-coexists', 'bootstrap.legacy-v2-refused',
];
// Source binding of this run (production modules plus this harness and its fixtures).
const SOURCES = ['attempt-store.js', 'controller.js', 'model.js', 'chains.js', 'wallet.js', 'app.js', 'vendor/ethers.js',
  'vendor/proxy.json', 'tests/check-attempt-store.cjs', 'tests/support/fake-chain.cjs'];

function binding() {
  const source = sha256(SOURCES.map((f) => f + '\0' + sha256(fs.readFileSync(path.join(APP, f)))).join('\n'));
  let head = null;
  try { head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim(); } catch { /* null */ }
  return { source, head, files: SOURCES };
}

async function bundle() {
  const result = await esbuild.build({
    stdin: { contents: [
      "export { AttemptStore, StorageError, DB_NAME, DB_VERSION, STORE_NAME, SINGLETON_KEY, LEGACY_KEY } from './attempt-store.js';",
      "export { RegistrationController, validateRecord } from './controller.js';",
      "export { WalletManager } from './wallet.js';",
      "export { ORIGIN } from './model.js';",
    ].join('\n'), resolveDir: APP, sourcefile: 'store-suite-entry.js', loader: 'js' },
    bundle: true, format: 'iife', globalName: 'Registration', platform: 'browser', target: ['es2022'], write: false,
    define: { 'process.env.NODE_ENV': '"production"', global: 'globalThis' }, logLevel: 'warning',
  });
  return result.outputFiles[0].text;
}

// -------------------------------------------------------------------------------------------------
// In-page harness (plain script): builds one production controller per page and exposes bounded probes.
const HARNESS = String.raw`
(() => {
  const R = window.Registration;
  const listeners = {};
  const provider = {
    request({ method, params }) {
      if (window.__syncThrow && method === 'eth_sendTransaction') {
        window.__syncThrowCalls = (window.__syncThrowCalls || 0) + 1;
        throw Object.assign(new Error('synchronous provider failure'), { code: -32603 });
      }
      return window.__wallet(method, params === undefined ? [] : params).then((answer) => {
        if (answer && answer.error) throw Object.assign(new Error(answer.error.message), { code: answer.error.code });
        return answer.ok;
      });
    },
    on(name, fn) { (listeners[name] = listeners[name] || new Set()).add(fn); },
    removeListener(name, fn) { if (listeners[name]) listeners[name].delete(fn); },
  };
  const timers = new Map();
  let timerId = 0;
  let offset = 0;
  // Manual controller clock (send timeout and polls); the store keeps the browser's real timers.
  const clock = { now: () => Date.now() + offset,
    setTimeout(fn, ms) { const id = ++timerId; timers.set(id, { at: clock.now() + ms, fn }); return id; },
    clearTimeout(id) { timers.delete(id); } };
  const rpc = (method, params) => window.__rpc(method, params).then((answer) => {
    if (answer.error) throw Object.assign(new Error(answer.error.message), answer.error.code === null ? {} : { code: answer.error.code });
    return answer.ok;
  });
  const H = window.H = {
    R, provider, clock,
    readLegacy: () => window.localStorage.getItem(R.LEGACY_KEY),
    store(StoreClass = R.AttemptStore) {
      return new StoreClass({ indexedDB: window.__factory || window.indexedDB, readLegacy: H.readLegacy,
        validateRecord: R.validateRecord });
    },
    create({ Store } = {}) {
      const win = Object.assign(new EventTarget(), { Event, ethereum: provider });
      let controller;
      const manager = new R.WalletManager({ win, config: { walletConnectProjectId: null, allowedDeploymentOrigin: R.ORIGIN },
        origin: location.origin, loadWalletConnect: () => { throw new Error('no WalletConnect'); },
        onChange: (event) => controller && controller.walletChanged(event) });
      H.storeInstance = H.store(Store || R.AttemptStore);
      // Compatibility suite exercises the retained singleton CAS contract. Address routing has its own native
      // suite (scoped-attempts.test.cjs), including same-address contention and real v1 database upgrade.
      H.storeInstance.forAddress = undefined;
      let n = 0;
      controller = new R.RegistrationController({ rpc, wallet: manager, store: H.storeInstance, clock,
        uuid: () => crypto.randomUUID ? crypto.randomUUID() : '00000000-0000-4000-8000-' + String(++n).padStart(12, '0'),
        onState: () => {} });
      manager.start();
      H.controller = controller;
      H.manager = manager;
      return controller;
    },
    async load() { await H.controller.loadAttempt(); return H.view(); },
    async ready() {
      const c = H.controller;
      if (c.initializing) await c.loadAttempt();
      c.prepare(window.__handoff);
      c.selectWallet('legacy');
      await c.connect();
      await c.inspect();
      return c.phase();
    },
    emit(name, arg) { for (const fn of listeners[name] || []) fn(arg); },
    async advance(ms) {
      offset += ms;
      for (;;) {
        const due = [...timers.entries()].filter(([, t]) => t.at <= clock.now()).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        timers.delete(due[0]);
        await due[1].fn();
      }
    },
    view() {
      const c = H.controller;
      const v = c.view();
      return { phase: v.phase, locked: v.locked, canSend: v.canSend, attempt: v.attempt && { id: v.attempt.id,
        hash: v.attempt.hash, state: v.attempt.state, reason: v.attempt.reason, from: v.attempt.from },
      notices: v.notices, storageError: v.storageError && v.storageError.code, resumeError: v.resumeError && v.resumeError.code,
      sendCount: v.sendCount, revision: c.snapshot ? c.snapshot.revision : null, clearable: v.clearable,
      sendNotice: v.sendNotice };
    },
    async settle() {
      for (let i = 0; i < 6; i++) await new Promise((r) => setTimeout(r, 15));
      return H.view();
    },
    /** Raw stored singleton via a separate native connection; null when the database does not exist. */
    async peek() {
      const names = (await indexedDB.databases()).map((d) => d.name);
      if (!names.includes(R.DB_NAME)) return { exists: false };
      return new Promise((resolve, reject) => {
        const request = indexedDB.open(R.DB_NAME);
        request.onerror = () => reject(new Error('peek open failed'));
        request.onsuccess = () => {
          const db = request.result;
          const stores = Array.from(db.objectStoreNames);
          if (!stores.includes(R.STORE_NAME)) { db.close(); return resolve({ exists: true, stores, version: db.version }); }
          const get = db.transaction(R.STORE_NAME, 'readonly').objectStore(R.STORE_NAME).get(R.SINGLETON_KEY);
          get.onsuccess = () => { db.close(); resolve({ exists: true, stores, version: db.version, row: get.result === undefined ? null : get.result }); };
          get.onerror = () => { db.close(); reject(new Error('peek get failed')); };
        };
      });
    },
    /** Raw write bypassing the store (models a corrupt/foreign writer). */
    async rawPut(value) {
      return new Promise((resolve, reject) => {
        const request = indexedDB.open(R.DB_NAME);
        request.onsuccess = () => {
          const db = request.result;
          const tx = db.transaction(R.STORE_NAME, 'readwrite');
          tx.objectStore(R.STORE_NAME).put(value, R.SINGLETON_KEY);
          tx.oncomplete = () => { db.close(); resolve(true); };
          tx.onabort = () => { db.close(); reject(new Error('raw put aborted')); };
        };
        request.onerror = () => reject(new Error('raw open failed'));
      });
    },
    /** Another cooperative writer: production store CAS from the latest row. */
    async write(raw) {
      const store = H.store();
      const { snapshot } = await store.load();
      const result = await store.compareAndSet(snapshot, raw);
      store.close();
      return { committed: result.committed, revision: result.snapshot.revision };
    },
  };
  // Test-only unsafe adapters (never shipped): one checks outside the writing transaction, one ignores revision.
  class UnsafeOutside extends R.AttemptStore {
    async compareAndSet(expected, nextRaw) {
      const current = await this.read();
      if (current.revision !== expected.revision || current.raw !== expected.raw) return { committed: false, snapshot: current };
      window.__atBarrier = true;
      await window.__barrier;
      return this.transact('readwrite', (now, store) => {
        const next = { version: 1, revision: now.revision + 1, raw: nextRaw, legacyRaw: now.legacyRaw };
        store.put(next, R.SINGLETON_KEY);
        return { committed: true, snapshot: Object.freeze(next) };
      });
    }
  }
  class UnsafeNoRevision extends R.AttemptStore {
    async compareAndSet(expected, nextRaw) {
      return this.transact('readwrite', (now, store) => {
        if (now.raw !== expected.raw) return { committed: false, snapshot: now };
        const next = { version: 1, revision: now.revision + 1, raw: nextRaw, legacyRaw: now.legacyRaw };
        store.put(next, R.SINGLETON_KEY);
        return { committed: true, snapshot: Object.freeze(next) };
      });
    }
  }
  H.unsafe = { UnsafeOutside, UnsafeNoRevision };
  window.__barrier = new Promise((resolve) => { window.__releaseBarrier = resolve; });
  // Native abort after put (before complete): the put request's success event fires first (this listener is
  // registered before any handler the store sets), then the transaction is aborted. A store reporting commit from
  // request success instead of transaction completion would therefore be caught. The order is logged.
  const put = IDBObjectStore.prototype.put;
  window.__abortLog = [];
  IDBObjectStore.prototype.put = function (...args) {
    const request = put.apply(this, args);
    if (window.__abortAfterPut) {
      const transaction = this.transaction;
      request.addEventListener('success', () => {
        window.__abortLog.push('put-success');
        transaction.abort();
        window.__abortLog.push('aborted');
      });
      transaction.addEventListener('complete', () => window.__abortLog.push('complete'));
    }
    return request;
  };
  // A browser that does not report strict durability (the store must fail closed, never downgrade).
  if (window.__noStrict) Object.defineProperty(IDBTransaction.prototype, 'durability', { get: () => 'default' });
  // Bounded, controllable delay of the native open request (open-timeout / late-success case).
  if (window.__holdOpen) {
    const native = indexedDB;
    window.__factory = { open(name, version) {
      const proxy = {};
      window.__releaseOpen = () => {
        const request = native.open(name, version);
        for (const type of ['upgradeneeded', 'success', 'error', 'blocked']) {
          request.addEventListener(type, (event) => { if (proxy['on' + type]) proxy['on' + type](event); });
        }
      };
      return proxy;
    } };
  }
})();
`;

// -------------------------------------------------------------------------------------------------

class Lab {
  constructor(browser, port, chain) {
    this.browser = browser;
    this.port = port;
    this.chain = chain;
    this.external = [];
    this.wallets = [];
  }

  get sends() { return this.wallets.reduce((n, w) => n + w.sends.length, 0); }

  async context() {
    this.ctx = await this.browser.newContext({ viewport: { width: 800, height: 600 } });
    const local = `http://127.0.0.1:${this.port}`;
    await this.ctx.route('**/*', (route) => {
      if (route.request().url().startsWith(local)) return route.continue();
      this.external.push(route.request().url());
      return route.abort('blockedbyclient');
    });
    await this.ctx.routeWebSocket(/./, (ws) => { this.external.push(ws.url()); ws.close(); });
    return this.ctx;
  }

  /** A new independently opened page of the case context with its own wallet/account. */
  async page({ account = ACCOUNT, flags = {}, legacy } = {}) {
    const page = await this.ctx.newPage();
    const wallet = new FakeWallet(this.chain, { accounts: [account] });
    this.wallets.push(wallet);
    page.errors = [];
    page.on('pageerror', (error) => page.errors.push(String(error.message).slice(0, 200)));
    await page.exposeFunction('__wallet', async (method, params) => {
      try { return { ok: await wallet.request({ method, params }) }; } catch (error) {
        return { error: { code: error.code, message: String(error.message) } };
      }
    });
    await page.exposeFunction('__rpc', async (method, params) => {
      try { return { ok: await this.chain.rpc(method, params) }; } catch (error) {
        return { error: { code: Number.isInteger(error.code) ? error.code : null, message: String(error.message) } };
      }
    });
    await page.addInitScript(({ handoff, flags: f, legacy: l }) => {
      window.__handoff = handoff;
      Object.assign(window, f);
      if (l !== undefined) localStorage.setItem('p256.registration.attempt.v1', l);
    }, { handoff: HANDOFF, flags, legacy });
    await page.goto(`http://127.0.0.1:${this.port}/`);
    await page.waitForFunction(() => window.H);
    page.wallet = wallet;
    page.run = (fn, arg) => page.evaluate(fn, arg);
    return page;
  }

  async close() { if (this.ctx) await this.ctx.close(); }
}

const ok = (checks, condition, name) => { checks[name] = condition ? 'pass' : 'fail'; };
const rowOf = async (page) => (await page.run(() => H.peek())).row;
const parse = (row) => (row && row.raw ? JSON.parse(row.raw) : null);

async function readyPage(lab, options) {
  const page = await lab.page(options);
  await page.run(() => { H.create(); });
  const phase = await page.run(() => H.ready());
  if (phase !== 'ready') throw new Error(`fixture did not reach ready (${phase})`);
  return page;
}

/** One send left awaiting the wallet (deferred) in a fresh page; returns the page. */
async function deferredSend(lab, options) {
  const page = await readyPage(lab, options);
  page.wallet.behavior.send = 'deferred';
  await page.run(() => H.controller.send());
  await page.run(() => H.settle());
  return page;
}

async function loadedPage(lab, options) {
  const page = await lab.page(options);
  await page.run(() => { H.create(); });
  await page.run(() => H.load());
  await page.run(() => H.settle());
  return page;
}

/** A sends (deferred), B loads the hashless attempt and reconciles `tx` read-only by manual hash. */
async function otherTabHash(lab, mutate = (tx) => tx, mine = 0) {
  const a = await deferredSend(lab);
  const b = await loadedPage(lab, { account: OTHER });
  const hash = lab.chain.submit(mutate({ ...a.wallet.built[0] }));
  for (let i = 0; i < mine; i++) lab.chain.mine();
  await b.run((h) => H.controller.enterHash(h), hash);
  await b.run(() => H.settle());
  return { a, b, hash };
}

/** A historical v1 record for the selected row, built with the shared fixture builder on this lab's chain. */
async function legacyRecord(lab, options = {}) {
  const model = await import('../model.js');
  const plan = model.buildPlan(model.parseHandoff(HANDOFF));
  return legacyAttempt(lab.chain, plan, options);
}

/** The sending page still shows its own hashless attempt (it has not seen the other tab's row). */
const notAdopted = (view) => Boolean(view.attempt) && view.attempt.hash === null && view.notices.newer === false;

/**
 * Bounded barrier on an observable condition instead of a fixed sleep: page A reconciled the delivered wallet reply
 * and adopted the other tab's newer row (hash shown, newer notice) with its read-only revalidation finished.
 * Returns that view, or null when the reply was not processed within the bound.
 */
async function replyProcessed(page, hash) {
  try {
    await page.waitForFunction((h) => {
      const v = H.view();
      return Boolean(v.attempt) && v.attempt.hash === h && v.notices.newer === true && !H.controller.refreshing;
    }, hash, { timeout: 5000 });
  } catch {
    return null;
  }
  return page.run(() => H.view());
}

async function concurrent(lab, c, Store) {
  const p1 = await lab.page({ account: ACCOUNT });
  const p2 = await lab.page({ account: OTHER });
  for (const p of [p1, p2]) {
    await p.run((unsafe) => { H.create({ Store: unsafe ? H.unsafe.UnsafeOutside : undefined }); }, Store === 'unsafe');
    const phase = await p.run(() => H.ready());
    if (phase !== 'ready') throw new Error(`fixture did not reach ready (${phase})`);
  }
  const revisions = [await p1.run(() => H.controller.snapshot.revision), await p2.run(() => H.controller.snapshot.revision)];
  ok(c, revisions[0] === 0 && revisions[1] === 0, 'both-read-same-empty-revision');
  const sends = [p1.run(() => H.controller.send()), p2.run(() => H.controller.send())];
  if (Store === 'unsafe') {
    // Both pages pass the outside-of-transaction check before either writes.
    await Promise.all([p1, p2].map((p) => p.waitForFunction(() => window.__atBarrier === true, null, { timeout: 8000 })));
    await Promise.all([p1, p2].map((p) => p.run(() => window.__releaseBarrier())));
  }
  const results = await Promise.all(sends);
  await Promise.all([p1, p2].map((p) => p.run(() => H.settle())));
  return { p1, p2, results };
}

async function terminalAdoption(lab, revert) {
  const c = {};
  const a = await readyPage(lab);
  const b = await readyPage(lab, { account: OTHER });
  await b.run(() => {
    const cas = H.storeInstance.compareAndSet.bind(H.storeInstance);
    const gate = new Promise((resolve) => { window.__releaseAdmission = resolve; });
    H.storeInstance.compareAndSet = async (...args) => {
      window.__admissionWaiting = true;
      await gate;
      return cas(...args);
    };
  });
  const sending = b.run(() => H.controller.send());
  sending.catch(() => {}); // Awaited below; a closed context after an earlier failure must not crash the suite.
  await b.waitForFunction(() => window.__admissionWaiting, null, { timeout: 5000 });
  await a.run(() => H.controller.send());
  await a.waitForFunction(() => H.controller.snapshot.revision === 2, null, { timeout: 5000 });
  await a.run(() => H.controller.stopTracking());
  const stored = await rowOf(a);
  lab.chain.mine({ revert }); lab.chain.mine();
  await b.run(() => window.__releaseAdmission());
  ok(c, await sending === false, 'loser-does-not-send');
  await b.waitForFunction(() => H.controller.clearable() && !H.controller.refreshing, null, { timeout: 5000 });
  ok(c, JSON.stringify(await rowOf(b)) === JSON.stringify(stored), 'terminal-adoption-keeps-pending-row');
  await b.run(() => { H.controller.requestClear(); return H.controller.confirmClear(); });
  const cleared = await rowOf(b);
  ok(c, cleared.raw === null && cleared.revision === stored.revision + 1, 'explicit-clear-tombstones-verified-row');
  ok(c, lab.sends === 1, 'one-send-total');
  return { checks: c, data: { revert } };
}

// -------------------------------------------------------------------------------------------------
// Cases. Each returns { checks, data }.

const CASES = {
  async 'admission.concurrent-empty'(lab) {
    const c = {};
    const { p1, p2, results } = await concurrent(lab, c);
    const row = await rowOf(p1);
    ok(c, lab.sends === 1, 'exactly-one-wallet-invocation');
    ok(c, results.filter(Boolean).length === 1, 'exactly-one-admission');
    // Admission (revision 1) plus the winner's own returned hash (revision 2); nothing else committed.
    ok(c, row && row.revision === 2 && /^0x[0-9a-f]{64}$/.test(parse(row).hash || ''), 'one-admission-one-outcome');
    const winner = results[0] ? p1 : p2;
    const loser = results[0] ? p2 : p1;
    ok(c, parse(row).from.toLowerCase() === winner.wallet.accounts[0].toLowerCase(), 'winner-bytes-retained');
    const lv = await loser.run(() => H.view());
    ok(c, lv.locked && lv.attempt && lv.attempt.id === parse(row).id && loser.wallet.sends.length === 0,
      'loser-adopts-read-only');
    ok(c, (await loser.run(() => H.controller.send())) === false && lab.sends === 1, 'loser-cannot-send');
    return { checks: c, data: { revision: row.revision } };
  },
  async 'admission.hash-before-conflict'(lab) {
    const c = {};
    const winner = await readyPage(lab);
    const loser = await readyPage(lab, { account: OTHER });
    await loser.run(() => {
      const original = H.storeInstance.compareAndSet.bind(H.storeInstance);
      const gate = new Promise((resolve) => { window.__releaseAdmission = resolve; });
      H.storeInstance.compareAndSet = async (...args) => {
        window.__admissionWaiting = true;
        await gate;
        return original(...args);
      };
    });
    const losingSend = loser.run(() => H.controller.send());
    losingSend.catch(() => {}); // Awaited below; a closed context after an earlier failure must not crash the suite.
    await loser.waitForFunction(() => window.__admissionWaiting === true, null, { timeout: 5000 });
    ok(c, await winner.run(() => H.controller.send()) === true, 'winner-admitted');
    await winner.waitForFunction(() => H.controller.snapshot.revision === 2 && H.controller.attempt.hash !== null,
      null, { timeout: 5000 });
    const stored = await rowOf(winner);
    ok(c, stored.revision === 2 && parse(stored).observed === null, 'hash-saved-before-conflict');
    await loser.run(() => window.__releaseAdmission());
    ok(c, await losingSend === false, 'loser-not-admitted');
    await loser.waitForFunction(() => H.controller.attempt.observed !== null && !H.controller.refreshing,
      null, { timeout: 5000 });
    ok(c, JSON.stringify(await rowOf(loser)) === JSON.stringify(stored), 'conflict-revalidation-keeps-exact-row');
    ok(c, lab.sends === 1 && loser.wallet.sends.length === 0, 'exactly-one-wallet-invocation');
    ok(c, await loser.run(() => H.controller.send()) === false, 'loser-cannot-resend');
    await loser.run(() => H.controller.refresh());
    const after = await rowOf(loser);
    ok(c, after.revision === 3 && parse(after).hash === parse(stored).hash && parse(after).observed !== null,
      'explicit-refresh-can-save-observations');
    ok(c, lab.sends === 1, 'refresh-never-sends');
    return { checks: c, data: { before: stored.revision, after: after.revision } };
  },
  'adoption.success-clear': (lab) => terminalAdoption(lab, false),
  'adoption.failed-clear': (lab) => terminalAdoption(lab, true),
  async 'adoption.first-hash-poll'(lab) {
    const c = {};
    const { a, hash } = await otherTabHash(lab);
    await a.run(async () => H.controller.adoptLatest(await H.storeInstance.read()));
    await a.waitForFunction(() => H.controller.pollTimer !== null, null, { timeout: 5000 });
    const before = await a.run(() => ({ started: H.controller.pollStarted, polls: H.controller.polls }));
    await a.run(async () => H.controller.adoptLatest(await H.storeInstance.read()));
    await a.waitForFunction(() => !H.controller.refreshing, null, { timeout: 5000 });
    ok(c, await a.run((x) => H.controller.pollStarted === x.started && H.controller.polls === x.polls, before),
      'same-id-window-preserved');
    lab.chain.mine(); lab.chain.mine();
    await a.run(() => H.advance(12_000));
    ok(c, await a.run(() => H.controller.phase()) === 'success', 'poll-follows-adopted-hash');
    ok(c, parse(await rowOf(a)).hash === hash && lab.sends === 1, 'same-hash-one-send');
    return { checks: c, data: {} };
  },
  async 'outcome.suspended-timeout-keeps-unsaved-hash'(lab) {
    const c = {};
    const a = await deferredSend(lab);
    await a.run(() => {
      const read = H.storeInstance.read.bind(H.storeInstance);
      const gate = new Promise((resolve) => { window.__releaseRead = resolve; });
      H.storeInstance.read = async () => {
        if (!window.__readWaiting) { window.__readWaiting = true; await gate; }
        return read();
      };
    });
    await a.run(() => H.advance(60_000));
    await a.waitForFunction(() => window.__readWaiting, null, { timeout: 5000 });
    await a.run(() => { window.__abortAfterPut = true; });
    a.wallet.releaseSend();
    await a.waitForFunction(() => H.controller.unsaved && H.controller.unsaved.outcome.kind === 'hash', null,
      { timeout: 5000 });
    const hash = await a.run(() => H.controller.unsaved.outcome.hash);
    await a.run(() => window.__releaseRead());
    await a.run(() => H.settle());
    ok(c, await a.run((h) => H.controller.unsaved.outcome.hash === h && H.controller.attempt.hash === h, hash),
      'weaker-timeout-keeps-visible-hash');
    ok(c, parse(await rowOf(a)).hash === null, 'failed-writes-do-not-persist');
    await a.run(() => { window.__abortAfterPut = false; return H.controller.refresh(); });
    ok(c, parse(await rowOf(a)).hash === hash && lab.sends === 1, 'explicit-retry-saves-hash-without-send');
    return { checks: c, data: {} };
  },
  async 'outcome.conflict-keeps-unsaved-hash-visible'(lab) {
    const c = {};
    const a = await deferredSend(lab);
    await a.run(() => H.advance(60_000)); await a.run(() => H.settle());
    const manual = lab.chain.submit(a.wallet.built[0]);
    lab.chain.mine({ revert: true }); lab.chain.mine();
    await a.run((h) => H.controller.enterHash(h), manual);
    const b = await loadedPage(lab);
    await a.run(() => {
      const cas = H.storeInstance.compareAndSet.bind(H.storeInstance);
      const gate = new Promise((resolve) => { window.__releaseClear = resolve; });
      H.storeInstance.compareAndSet = async (base, raw) => {
        if (raw === null) { window.__clearWaiting = true; await gate; }
        return cas(base, raw);
      };
      H.controller.requestClear();
    });
    const clearing = a.run(() => H.controller.confirmClear());
    clearing.catch(() => {}); // Awaited below; a closed context after an earlier failure must not crash the suite.
    await a.waitForFunction(() => window.__clearWaiting, null, { timeout: 5000 });
    lab.chain.reorg(2); await b.run(() => H.controller.refresh());
    const stored = await rowOf(b);
    await a.run(() => { window.__abortAfterPut = true; });
    a.wallet.releaseSend();
    await a.waitForFunction(() => H.controller.unsaved && H.controller.unsaved.outcome.kind === 'hash', null,
      { timeout: 5000 });
    const hash = await a.run(() => H.controller.unsaved.outcome.hash);
    await a.run(() => { window.__abortAfterPut = false; window.__releaseClear(); });
    await clearing;
    await a.waitForFunction((h) => H.controller.attempt.hash === h && !H.controller.refreshing,
      manual, { timeout: 5000 });
    await a.run(() => H.settle());
    const view = await a.run(() => H.view());
    ok(c, view.attempt.hash === manual && view.notices.unsaved && view.sendNotice.includes(hash)
      && view.sendNotice.includes('未保存'), 'separate-unsaved-hash-visible');
    ok(c, JSON.stringify(await rowOf(a)) === JSON.stringify(stored), 'adoption-does-not-retry-save');
    await a.run(() => H.controller.refresh());
    ok(c, parse(await rowOf(a)).hash === hash && lab.sends === 1, 'explicit-retry-only');
    return { checks: c, data: {} };
  },
  async 'admission.reopen-loser'(lab) {
    const c = {};
    const { p1, p2, results } = await concurrent(lab, c);
    const loser = results[0] ? p2 : p1;
    const before = await rowOf(loser);
    await loser.reload();
    await loser.waitForFunction(() => window.H);
    await loser.run(() => { H.create(); });
    await loser.run(() => H.load());
    await loser.run(() => H.settle());
    await loser.run(() => { const ctl = H.controller; ctl.prepare(window.__handoff); });
    const view = await loser.run(() => H.view());
    ok(c, view.locked && view.attempt !== null, 'reopened-loser-locked');
    ok(c, (await loser.run(() => H.controller.send())) === false, 'reopened-loser-cannot-send');
    const after = parse(await rowOf(loser));
    ok(c, lab.sends === 1 && after.id === parse(before).id && after.hash === parse(before).hash
      && after.from === parse(before).from, 'retained-attempt');
    return { checks: c, data: {} };
  },
  async 'admission.abort-after-put'(lab) {
    const c = {};
    const page = await readyPage(lab);
    await page.run(() => { window.__abortAfterPut = true; });
    const sent = await page.run(() => H.controller.send());
    const view = await page.run(() => H.settle());
    const row = await rowOf(page);
    const log = await page.run(() => window.__abortLog);
    ok(c, JSON.stringify(log) === '["put-success","aborted"]', 'put-success-observed-before-abort');
    ok(c, sent === false && lab.sends === 0, 'zero-wallet-invocation');
    ok(c, row.revision === 0 && row.raw === null, 'saved-bytes-unchanged');
    ok(c, view.phase === 'storageError' && !view.canSend, 'storage-error-blocks');
    return { checks: c, data: { row, log } };
  },
  async 'admission.post-commit-drift'(lab) {
    const c = {};
    const page = await readyPage(lab);
    // Instrumentation around the production store: a chain change lands after transaction completion and
    // before the controller's synchronous recheck.
    await page.run(() => {
      const store = H.storeInstance;
      const original = store.compareAndSet.bind(store);
      store.compareAndSet = async (expected, next) => {
        const result = await original(expected, next);
        if (result.committed && next !== null) H.emit('chainChanged', '0x1');
        return result;
      };
    });
    const sent = await page.run(() => H.controller.send());
    await page.run(() => H.settle());
    const row = await rowOf(page);
    ok(c, sent === false && lab.sends === 0, 'zero-wallet-invocation');
    ok(c, row.revision === 2 && row.raw === null, 'admission-conditionally-tombstoned');
    ok(c, !(await page.run(() => H.view())).canSend, 'fresh-review-required');
    return { checks: c, data: { revision: row.revision } };
  },
  async 'admission.sync-throw'(lab) {
    const c = {};
    const page = await readyPage(lab, { flags: { __syncThrow: true } });
    await page.run(() => H.controller.send());
    const view = await page.run(() => H.settle());
    const row = await rowOf(page);
    ok(c, (await page.run(() => window.__syncThrowCalls)) === 1 && view.sendCount === 1, 'one-invocation');
    ok(c, parse(row).state === 'unknown' && parse(row).reason === 'send-error', 'uncertain-unknown-saved');
    ok(c, (await page.run(() => H.controller.send())) === false && view.locked, 'locked-no-retry');
    return { checks: c, data: {} };
  },
  async 'admission.strict-unsupported'(lab) {
    const c = {};
    const page = await readyPage(lab, { flags: { __noStrict: true } });
    const sent = await page.run(() => H.controller.send());
    const view = await page.run(() => H.settle());
    const row = await rowOf(page);
    ok(c, sent === false && lab.sends === 0, 'zero-wallet-invocation');
    ok(c, row.revision === 0 && row.raw === null, 'no-downgraded-write');
    ok(c, view.phase === 'storageError', 'fails-closed');
    return { checks: c, data: {} };
  },
  async 'outcome.timeout-keeps-other-tab-hash'(lab) {
    const c = {};
    // The other tab recovers the hash of a wallet transaction with its own (higher) gas: v2 evidence, not override.
    const { a, b, hash } = await otherTabHash(lab, (tx) => ({ ...tx, gas: BIGGAS }));
    const recovered = await rowOf(b);
    ok(c, parse(recovered).hash === hash && parse(recovered).state === 'pending'
      && parse(recovered).observed.gas === BIGGAS, 'other-tab-hash-saved');
    await a.run(() => H.advance(60_000));
    const view = await a.run(() => H.settle());
    ok(c, JSON.stringify(await rowOf(a)) === JSON.stringify(recovered), 'timeout-cannot-erase');
    ok(c, view.attempt.hash === hash && view.notices.newer === true, 'adopts-newer-evidence');
    ok(c, lab.sends === 1, 'no-recovery-send');
    return { checks: c, data: {} };
  },
  async 'outcome.malformed-keeps-other-tab-hash'(lab) {
    const c = {};
    const { a, b, hash } = await otherTabHash(lab);
    const recovered = await rowOf(b);
    ok(c, notAdopted(await a.run(() => H.view())), 'not-adopted-before-reply');
    a.wallet.pendingSends[0].resolve('not-a-hash');
    const view = await replyProcessed(a, hash);
    ok(c, view !== null, 'reply-processed-adopts-newer');
    ok(c, JSON.stringify(await rowOf(a)) === JSON.stringify(recovered), 'malformed-cannot-erase');
    ok(c, lab.sends === 1, 'no-recovery-send');
    return { checks: c, data: {} };
  },
  async 'outcome.4001-keeps-other-tab-hash'(lab) {
    const c = {};
    const { a, b, hash } = await otherTabHash(lab);
    const recovered = await rowOf(b);
    ok(c, notAdopted(await a.run(() => H.view())), 'not-adopted-before-reply');
    a.wallet.pendingSends[0].reject(Object.assign(new Error('rejected'), { code: 4001 }));
    const view = await replyProcessed(a, hash);
    ok(c, view !== null, 'reply-processed-adopts-newer');
    ok(c, JSON.stringify(await rowOf(a)) === JSON.stringify(recovered), '4001-cannot-erase');
    ok(c, view !== null && view.phase !== 'rejected' && !view.clearable, 'not-rejected-not-clearable');
    ok(c, lab.sends === 1, 'no-recovery-send');
    return { checks: c, data: {} };
  },
  async 'refresh.stale-same-id'(lab) {
    const c = {};
    const { a, b, hash: manual } = await otherTabHash(lab);
    a.wallet.pendingSends[0].tx.gas = BIGGAS;
    a.wallet.releaseSend();
    await a.run(() => H.settle());
    await a.run(() => H.controller.refresh());
    await a.run(() => H.settle());
    const newer = await rowOf(a);
    ok(c, parse(newer).state === 'pending' && parse(newer).hash !== manual && parse(newer).observed.gas === BIGGAS,
      'newer-wallet-hash-saved');
    await b.run(() => H.controller.refresh());
    const bv = await b.run(() => H.settle());
    ok(c, JSON.stringify(await rowOf(b)) === JSON.stringify(newer), 'stale-refresh-cannot-restore');
    ok(c, bv.attempt.hash === parse(newer).hash, 'stale-tab-adopts');
    ok(c, lab.sends === 1, 'one-send');
    return { checks: c, data: {} };
  },
  async 'clear.committed-keeps-unsaved-hash'(lab) {
    const c = {};
    const a = await deferredSend(lab);
    await a.run(() => H.advance(60_000)); await a.run(() => H.settle());
    const manual = lab.chain.submit(a.wallet.built[0]);
    await a.run((h) => H.controller.enterHash(h), manual);
    await a.run(() => H.controller.stopTracking());
    lab.chain.mine({ revert: true }); lab.chain.mine();
    await a.run(async () => H.controller.adoptLatest(await H.storeInstance.read()));
    await a.waitForFunction(() => H.controller.clearable(), null, { timeout: 5000 });
    const before = await rowOf(a);
    ok(c, parse(before).state === 'pending', 'stored-pending-verified-failed');
    await a.run(() => {
      const cas = H.storeInstance.compareAndSet.bind(H.storeInstance);
      const gate = new Promise((resolve) => { window.__releaseClear = resolve; });
      H.storeInstance.compareAndSet = async (base, raw) => {
        if (raw === null) { window.__clearWaiting = true; await gate; }
        return cas(base, raw);
      };
      H.controller.requestClear();
    });
    const clearing = a.run(() => H.controller.confirmClear());
    clearing.catch(() => {}); // Awaited below; a closed context after an earlier failure must not crash the suite.
    await a.waitForFunction(() => window.__clearWaiting, null, { timeout: 5000 });
    await a.run(() => { window.__abortAfterPut = true; });
    a.wallet.releaseSend();
    await a.waitForFunction(() => H.controller.unsaved && H.controller.unsaved.outcome.kind === 'hash', null,
      { timeout: 5000 });
    const hash = await a.run(() => H.controller.unsaved.outcome.hash);
    await a.run(() => { window.__abortAfterPut = false; window.__releaseClear(); });
    await clearing;
    const view = await a.run(() => H.view());
    const after = await rowOf(a);
    ok(c, after.raw === null && after.revision === before.revision + 1, 'tombstone-completed');
    ok(c, view.notices.staleHash === hash && view.sendNotice.includes(hash), 'cleared-attempt-response-visible');
    ok(c, view.locked && view.notices.reloadRequired && !view.canSend, 'new-send-remains-locked');
    await a.run(() => H.controller.refresh());
    ok(c, (await rowOf(a)).raw === null && lab.sends === 1, 'no-resurrection-or-resend');
    return { checks: c, data: {} };
  },
  async 'clear.stale-confirmation'(lab) {
    const c = {};
    const a = await readyPage(lab);
    a.wallet.behavior.send = 'reject';
    await a.run(() => H.controller.send());
    await a.run(() => H.settle());
    const b = await loadedPage(lab, { account: OTHER });
    await b.run(() => H.controller.requestClear());
    ok(c, (await b.run(() => H.controller.view().clearPending)) === true, 'stale-confirmation-open');
    await a.run(() => { H.controller.requestClear(); return H.controller.confirmClear(); });
    a.wallet.behavior.send = 'deferred';
    const phase = await a.run(() => H.ready());
    if (phase !== 'ready') throw new Error(`re-ready failed (${phase})`);
    await a.run(() => H.controller.send());
    await a.run(() => H.settle());
    const newer = await rowOf(a);
    await b.run(() => H.controller.confirmClear());
    const bv = await b.run(() => H.settle());
    ok(c, JSON.stringify(await rowOf(b)) === JSON.stringify(newer), 'stale-clear-removes-nothing');
    ok(c, bv.attempt && bv.attempt.id === parse(newer).id && bv.locked, 'stale-tab-adopts-newer');
    ok(c, lab.sends === 2, 'no-extra-send');
    return { checks: c, data: {} };
  },
  async 'late-hash.pending-manual-replaced'(lab) {
    const c = {};
    const { a, b, hash: manual } = await otherTabHash(lab);
    const before = parse(await rowOf(b));
    ok(c, before.state === 'pending' && before.observed !== null, 'observed-pending-manual');
    a.wallet.releaseSend();
    await a.run(() => H.settle());
    const after = parse(await rowOf(a));
    ok(c, after.hash !== manual && after.state === 'pending', 'wallet-hash-replaces');
    ok(c, lab.sends === 1, 'one-send');
    return { checks: c, data: {} };
  },
  async 'late-hash.wallet-fee-not-override'(lab) {
    const c = {};
    // v2: a recovered manual hash whose wallet gas exceeds any old ceiling is ordinary evidence, never an override,
    // so the sending tab's own late wallet hash replaces it (no lateHash notice, no send).
    const { a, b, hash } = await otherTabHash(lab, (tx) => ({ ...tx, gas: BIGGAS }));
    const before = await rowOf(b);
    ok(c, parse(before).state === 'pending' && parse(before).version === 2, 'v2-wallet-gas-pending');
    a.wallet.releaseSend();
    const view = await a.run(() => H.settle());
    const after = parse(await rowOf(a));
    ok(c, after.hash !== hash && after.state === 'pending', 'wallet-hash-replaces');
    ok(c, !view.notices.lateHash && view.phase !== 'walletOverride', 'no-override-no-notice');
    ok(c, (await rowOf(a)).revision > before.revision && lab.sends === 1, 'no-send');
    return { checks: c, data: {} };
  },
  async 'late-hash.cancellation-retained'(lab) {
    const c = {};
    const { a, b, hash } = await otherTabHash(lab);
    const lineage = { ...parse(await rowOf(b)), state: 'unknown', reason: 'cancel-unverified',
      replacementHash: '0x' + 'cd'.repeat(32), effectiveNonce: '0x0' };
    const written = await b.run((raw) => H.write(raw), JSON.stringify(lineage));
    ok(c, written.committed, 'lineage-written');
    a.wallet.releaseSend();
    const view = await a.run(() => H.settle());
    ok(c, parse(await rowOf(a)).hash === hash, 'stored-hash-retained');
    ok(c, Boolean(view.notices.lateHash), 'late-hash-notice');
    ok(c, lab.sends === 1, 'no-send');
    return { checks: c, data: {} };
  },
  async 'late-hash.success-retained'(lab) {
    const c = {};
    const { a, hash } = await otherTabHash(lab, (tx) => tx, 2);
    const before = parse(await rowOf(a));
    ok(c, before.state === 'success', 'manual-success-saved');
    a.wallet.releaseSend();
    const view = await a.run(() => H.settle());
    const after = parse(await rowOf(a));
    ok(c, after.hash === hash && after.state === 'success', 'success-retained');
    ok(c, Boolean(view.notices.lateHash) && view.notices.lateHash !== hash, 'conflicting-hash-notice');
    ok(c, lab.sends === 1, 'zero-new-sends');
    return { checks: c, data: {} };
  },
  async 'tombstone.no-resurrection'(lab) {
    const c = {};
    const { a, b } = await otherTabHash(lab, (tx) => tx, 2);
    await b.run(() => { H.controller.requestClear(); return H.controller.confirmClear(); });
    const cleared = await rowOf(b);
    ok(c, cleared.raw === null, 'explicit-clear-tombstone');
    a.wallet.releaseSend();
    const view = await a.run(() => H.settle());
    ok(c, JSON.stringify(await rowOf(a)) === JSON.stringify(cleared), 'callback-does-not-resurrect');
    ok(c, Boolean(view.notices.staleHash) && view.sendNotice.includes(view.notices.staleHash) && view.locked,
      'hash-notice-and-locked-until-reload');
    ok(c, (await a.run(() => H.controller.send())) === false && lab.sends === 1, 'no-send');
    return { checks: c, data: {} };
  },
  async 'tombstone.aba'(lab) {
    const c = {};
    const a = await deferredSend(lab);
    const x = (await rowOf(a)).raw;
    const d = await loadedPage(lab, { account: OTHER });
    const old = await d.run(() => H.controller.snapshot);
    await a.run((raw) => H.write(raw), JSON.stringify({ ...JSON.parse(x), state: 'unknown', reason: 'send-timeout' }));
    await a.run((raw) => H.write(raw), x);
    const row = await rowOf(a);
    ok(c, row.raw === x && row.revision === old.revision + 2, 'same-bytes-newer-revision');
    const result = await d.run((expected) => H.storeInstance.compareAndSet(expected, null), old);
    ok(c, result.committed === false, 'old-revision-refused');
    ok(c, (await rowOf(a)).raw === x, 'bytes-retained');
    ok(c, lab.sends === 1, 'no-send');
    return { checks: c, data: {} };
  },
  async 'corrupt.foreign-row'(lab) {
    const c = {};
    const seed = await loadedPage(lab);
    const foreign = { version: 1, revision: 4, raw: '{"foreign":true}', legacyRaw: null };
    await seed.run((v) => H.rawPut(v), foreign);
    const page = await lab.page();
    await page.run(() => { H.create(); });
    const view = await page.run(() => H.load());
    ok(c, view.phase === 'resumeError', 'tamper-error');
    ok(c, JSON.stringify((await rowOf(page))) === JSON.stringify(foreign), 'not-repaired-or-deleted');
    await page.run(() => H.ready().catch(() => null));
    ok(c, (await page.run(() => H.controller.send())) === false && lab.sends === 0, 'no-send');
    return { checks: c, data: {} };
  },
  async 'corrupt.unknown-field'(lab) {
    const c = {};
    const seed = await loadedPage(lab);
    const extra = { version: 1, revision: 0, raw: null, legacyRaw: null, extra: true };
    await seed.run((v) => H.rawPut(v), extra);
    const page = await lab.page();
    await page.run(() => { H.create(); });
    const view = await page.run(() => H.load());
    ok(c, view.phase === 'resumeError', 'unknown-field-fails-closed');
    ok(c, JSON.stringify(await rowOf(page)) === JSON.stringify(extra), 'not-repaired');
    ok(c, lab.sends === 0, 'no-send');
    return { checks: c, data: {} };
  },
  async 'open.timeout-late-success'(lab) {
    const c = {};
    const page = await lab.page({ flags: { __holdOpen: true } });
    await page.run(() => { H.create(); });
    const started = Date.now();
    const view = await page.run(() => H.load());
    ok(c, view.phase === 'storageError' && Date.now() - started >= 4900, 'bounded-open-timeout');
    await page.run(() => window.__releaseOpen());
    await page.run(() => H.settle());
    const peek = await page.run(() => H.peek());
    ok(c, peek.exists === false, 'late-upgrade-aborted-no-database');
    await page.run(() => H.ready().catch(() => null));
    ok(c, (await page.run(() => H.view())).canSend === false && lab.sends === 0, 'no-send');
    return { checks: c, data: { waitedMs: Date.now() - started } };
  },
  async 'connection.versionchange-release'(lab) {
    const c = {};
    const page = await readyPage(lab);
    // A newer schema request from another page: this connection closes and further mutations fail closed.
    const other = await lab.page();
    const upgrade = await other.run(() => new Promise((resolve) => {
      const request = indexedDB.open(H.R.DB_NAME, H.R.DB_VERSION + 1);
      let blocked = false;
      request.onblocked = () => { blocked = true; };
      request.onupgradeneeded = () => {};
      request.onsuccess = () => { request.result.close(); resolve({ ok: true, blocked }); };
      request.onerror = () => resolve({ ok: false, blocked });
    }));
    ok(c, upgrade.ok && !upgrade.blocked, 'connection-released-not-blocking');
    const sent = await page.run(() => H.controller.send());
    await page.run(() => H.settle());
    ok(c, sent === false && lab.sends === 0, 'closed-connection-no-send');
    const fresh = await lab.page();
    await fresh.run(() => { H.create(); });
    ok(c, (await fresh.run(() => H.load())).phase === 'storageError', 'unexpected-version-fails-closed');
    return { checks: c, data: { upgrade } };
  },
  async 'connection.page-close'(lab) {
    const c = {};
    const a = await deferredSend(lab);
    const committed = await rowOf(a);
    await a.close();
    const b = await loadedPage(lab, { account: OTHER });
    const view = await b.run(() => H.view());
    ok(c, parse(committed).state === 'walletPending' && view.attempt && view.attempt.id === parse(committed).id,
      'committed-admission-survives-close');
    ok(c, view.phase === 'unknown' && view.locked, 'uncertain-unknown-locked');
    const written = await b.run(() => H.write(null).then((r) => r, () => ({ committed: 'error' })));
    ok(c, written.committed === true, 'connection-released-after-close');
    ok(c, lab.sends === 1, 'no-retry');
    return { checks: c, data: {} };
  },
  async 'bootstrap.legacy-import-clear-reload'(lab) {
    const c = {};
    // A valid historical v1 public record (the only version the legacy key ever held) as a definitive rejection.
    const record = { ...(await legacyRecord(lab, { submit: false })).record, state: 'rejected', reason: 'user-rejected' };
    const legacy = JSON.stringify(record);
    const page = await lab.page({ legacy });
    await page.run(() => { H.create(); });
    const view = await page.run(() => H.load());
    const row = await rowOf(page);
    ok(c, row.revision === 0 && row.raw === legacy && row.legacyRaw === legacy, 'first-creation-imports-exact-bytes');
    ok(c, view.phase === 'rejected' && view.clearable, 'imported-rejection-clearable');
    await page.run(() => { H.controller.requestClear(); return H.controller.confirmClear(); });
    const cleared = await rowOf(page);
    ok(c, cleared.revision === 1 && cleared.raw === null && cleared.legacyRaw === legacy, 'tombstone');
    await page.reload();
    await page.waitForFunction(() => window.H);
    await page.run(() => { H.create(); });
    const again = await page.run(() => H.load());
    ok(c, again.attempt === null && again.storageError === null, 'not-reimported');
    ok(c, JSON.stringify(await rowOf(page)) === JSON.stringify(cleared), 'tombstone-authoritative');
    ok(c, (await page.run(() => localStorage.getItem('p256.registration.attempt.v1'))) === legacy, 'legacy-untouched');
    return { checks: c, data: {} };
  },
  async 'bootstrap.legacy-invalid'(lab) {
    const c = {};
    const legacy = '{"version":1,"id":"tampered"}';
    const page = await lab.page({ legacy });
    await page.run(() => { H.create(); });
    const view = await page.run(() => H.load());
    ok(c, view.storageError === 'legacy-conflict' && view.phase === 'storageError', 'legacy-conflict-shown');
    ok(c, (await page.run(() => H.peek())).exists === false, 'no-database-created');
    ok(c, (await page.run(() => localStorage.getItem('p256.registration.attempt.v1'))) === legacy, 'legacy-untouched');
    await page.run(() => H.ready().catch(() => null));
    ok(c, (await page.run(() => H.controller.send())) === false && lab.sends === 0, 'no-send');
    return { checks: c, data: {} };
  },
  async 'bootstrap.legacy-changed'(lab) {
    const c = {};
    const seed = await loadedPage(lab);
    const before = await rowOf(seed);
    await seed.run(() => localStorage.setItem('p256.registration.attempt.v1', '{"changed":true}'));
    const page = await lab.page();
    await page.run(() => { H.create(); });
    const view = await page.run(() => H.load());
    ok(c, view.storageError === 'legacy-conflict', 'changed-legacy-warning');
    await page.run(() => { H.controller.prepare(window.__handoff); });
    ok(c, !(await page.run(() => H.view())).canSend, 'new-send-blocked');
    ok(c, JSON.stringify(await rowOf(page)) === JSON.stringify(before), 'idb-unchanged');
    ok(c, (await page.run(() => localStorage.getItem('p256.registration.attempt.v1'))) === '{"changed":true}',
      'legacy-untouched');
    return { checks: c, data: {} };
  },
  async 'bootstrap.concurrent-create'(lab) {
    const c = {};
    const pages = [await lab.page(), await lab.page({ account: OTHER })];
    const views = await Promise.all(pages.map((p) => p.run(() => { H.create(); return H.load(); })));
    const row = await rowOf(pages[0]);
    ok(c, views.every((v) => v.revision === 0 && v.storageError === null && v.resumeError === null), 'both-adopt-winner');
    ok(c, row.revision === 0 && row.raw === null, 'single-seed');
    return { checks: c, data: {} };
  },
  async 'legacy.v1-override-locked'(lab) {
    const c = {};
    // A byte-preserved v1 attempt whose wallet exceeded its frozen fee ceiling, in the unchanged native wrapper.
    const { raw } = await legacyRecord(lab, { override: { maxFeePerGas: '0x' + (100n * 10n ** 9n).toString(16) } });
    lab.chain.mine();
    lab.chain.mine();
    const seed = await loadedPage(lab);
    await seed.run((v) => H.rawPut(v), { version: 1, revision: 3, raw, legacyRaw: null });
    const page = await lab.page();
    await page.run(() => { H.create(); });
    await page.run(() => H.load());
    const view = await page.run(() => H.settle());
    const stored = parse(await rowOf(page));
    ok(c, view.phase === 'walletOverride' && !view.clearable && view.locked, 'v1-override-locked');
    ok(c, stored.version === 1 && stored.capWei === JSON.parse(raw).capWei
      && JSON.stringify(stored.transaction) === JSON.stringify(JSON.parse(raw).transaction), 'v1-frozen-fields-preserved');
    await page.run(() => { H.controller.requestClear(); return H.controller.confirmClear(); });
    ok(c, (await rowOf(page)).raw !== null, 'clear-refused');
    await page.run(() => H.ready().catch(() => null));
    ok(c, (await page.run(() => H.controller.send())) === false && lab.sends === 0, 'no-send');
    return { checks: c, data: {} };
  },
  async 'legacy.v1-pending-coexists'(lab) {
    const c = {};
    // A v1 pending attempt reloads and settles read-only under its original rules (here a canonical revert), is
    // explicitly cleared, and then a new v2 attempt is admitted by CAS in the same unchanged wrapper/database.
    const { raw } = await legacyRecord(lab);
    lab.chain.mine({ revert: true });
    lab.chain.mine();
    const seed = await loadedPage(lab);
    await seed.run((v) => H.rawPut(v), { version: 1, revision: 5, raw, legacyRaw: null });
    const page = await lab.page();
    await page.run(() => { H.create(); });
    await page.run(() => H.load());
    // Reload starts a read-only refresh asynchronously; observe its completion, not a fixed sleep.
    await page.waitForFunction(() => !H.controller.refreshing && !H.controller.resuming, null, { timeout: 5000 });
    const view = await page.run(() => H.settle());
    const settled = await rowOf(page);
    ok(c, view.phase === 'failed' && parse(settled).version === 1 && parse(settled).id === JSON.parse(raw).id
      && parse(settled).capWei === JSON.parse(raw).capWei, 'v1-settles-without-conversion');
    ok(c, view.clearable, 'resolved-v1-clearable');
    await page.run(() => { H.controller.requestClear(); return H.controller.confirmClear(); });
    const cleared = await rowOf(page);
    ok(c, cleared.raw === null && cleared.revision === settled.revision + 1 && cleared.version === 1, 'tombstone-in-same-wrapper');
    const phase = await page.run(() => H.ready());
    ok(c, phase === 'ready', 'fresh-v2-readiness');
    await page.run(() => H.controller.send());
    await page.run(() => H.settle());
    const admitted = await rowOf(page);
    // Admission and the wallet's hash outcome each commit one revision on top of the tombstone.
    ok(c, admitted.version === 1 && admitted.revision > cleared.revision && parse(admitted).version === 2
      && !('capWei' in parse(admitted)), 'v2-admitted-by-cas');
    ok(c, lab.sends === 1 && JSON.stringify(Object.keys(page.wallet.sends[0]).sort())
      === '["chainId","data","from","to","value"]', 'one-identity-only-send');
    return { checks: c, data: {} };
  },
  async 'bootstrap.legacy-v2-refused'(lab) {
    const c = {};
    // A structurally valid v2 record in the old localStorage key is never imported (legacy held v1 only).
    const source = await deferredSend(lab);
    const v2 = (await rowOf(source)).raw;
    ok(c, JSON.parse(v2).version === 2, 'v2-bytes');
    await lab.close();
    await lab.context();
    const page = await lab.page({ legacy: v2 });
    await page.run(() => { H.create(); });
    const view = await page.run(() => H.load());
    ok(c, view.storageError === 'legacy-conflict' && view.phase === 'storageError', 'legacy-conflict-shown');
    ok(c, (await page.run(() => H.peek())).exists === false, 'no-database-created');
    ok(c, (await page.run(() => localStorage.getItem('p256.registration.attempt.v1'))) === v2, 'legacy-untouched');
    return { checks: c, data: {} };
  },
  async 'outcome.unsaved-retry'(lab) {
    const c = {};
    const page = await deferredSend(lab);
    const stored = await rowOf(page);
    await page.run(() => { window.__abortAfterPut = true; });
    page.wallet.releaseSend();
    const view = await page.run(() => H.settle());
    ok(c, view.notices.unsaved === true && /^0x[0-9a-f]{64}$/.test(view.attempt.hash || ''), 'unsaved-hash-visible');
    ok(c, JSON.stringify(await rowOf(page)) === JSON.stringify(stored), 'stored-unchanged');
    await page.run(() => { window.__abortAfterPut = false; });
    await page.run(() => H.controller.refresh());
    const after = await page.run(() => H.settle());
    ok(c, after.notices.unsaved === false && parse(await rowOf(page)).hash === view.attempt.hash, 'explicit-retry-saves');
    ok(c, lab.sends === 1, 'no-extra-send');
    return { checks: c, data: {} };
  },
  async 'control.unsafe-outside-transaction'(lab) {
    // The same admission predicate run against a store that checks outside the writing transaction.
    const c = {};
    const { p1 } = await concurrent(lab, {}, 'unsafe');
    const row = await rowOf(p1);
    const predicate = lab.sends === 1 && row.revision === 2;
    ok(c, !predicate, 'unsafe-store-fails-admission-predicate');
    return { checks: c, data: { sends: lab.sends, revision: row.revision } };
  },
  async 'control.unsafe-no-revision'(lab) {
    const c = {};
    const a = await deferredSend(lab);
    const x = (await rowOf(a)).raw;
    const d = await lab.page({ account: OTHER });
    await d.run(() => { H.create({ Store: H.unsafe.UnsafeNoRevision }); return H.load(); });
    const old = await d.run(() => H.controller.snapshot);
    await a.run((raw) => H.write(raw), JSON.stringify({ ...JSON.parse(x), state: 'unknown', reason: 'send-timeout' }));
    await a.run((raw) => H.write(raw), x);
    const result = await d.run((expected) => H.storeInstance.compareAndSet(expected, null), old);
    ok(c, result.committed === true, 'unsafe-store-accepts-aba');
    return { checks: c, data: {} };
  },
};

/** Fail-closed judge over the exact case IDs (shared with the negative controls below). */
function judge(evidence, current) {
  const errors = [];
  if (!evidence || !Array.isArray(evidence.cases)) return ['evidence is malformed'];
  if (!current.source || !evidence.binding || evidence.binding.source !== current.source) errors.push('stale source');
  if (!current.head || evidence.binding.head !== current.head) errors.push('stale head');
  const ids = evidence.cases.map((r) => r.id);
  const duplicate = [...new Set(ids.filter((id, i) => ids.indexOf(id) !== i))];
  const missing = CASE_IDS.filter((id) => !ids.includes(id));
  const unknown = ids.filter((id) => !CASE_IDS.includes(id));
  if (duplicate.length) errors.push(`duplicate cases: ${duplicate.join(', ')}`);
  if (missing.length) errors.push(`missing cases: ${missing.join(', ')}`);
  if (unknown.length) errors.push(`unknown cases: ${unknown.join(', ')}`);
  for (const row of evidence.cases) {
    if (row.status !== 'PASS') errors.push(`${row.id} is ${row.status}`);
    if (row.runUUID !== evidence.runUUID) errors.push(`${row.id} belongs to another run`);
    if (!row.checks || !Object.keys(row.checks).length) errors.push(`${row.id} has no checks`);
  }
  return errors;
}

function controls(evidence, current) {
  const clone = () => JSON.parse(JSON.stringify(evidence));
  const cases = {
    complete: [clone(), true],
    'missing-case': [(() => { const e = clone(); e.cases.pop(); return e; })(), false],
    'duplicate-case': [(() => { const e = clone(); e.cases.push(e.cases[0]); return e; })(), false],
    'failed-case': [(() => { const e = clone(); e.cases[1].status = 'FAIL'; return e; })(), false],
    'not-evaluated-case': [(() => { const e = clone(); e.cases[2].status = 'NOT_EVALUATED'; return e; })(), false],
    'stale-source': [(() => { const e = clone(); e.binding.source = '0'.repeat(64); return e; })(), false],
    'other-run': [(() => { const e = clone(); e.cases[3].runUUID = crypto.randomUUID(); return e; })(), false],
    'unknown-case': [(() => { const e = clone(); e.cases.push({ ...e.cases[0], id: 'admission.extra' }); return e; })(), false],
    'malformed': [{}, false],
  };
  const out = {};
  for (const [name, [candidate, accept]] of Object.entries(cases)) {
    const accepted = judge(candidate, current).length === 0;
    out[name] = accepted === accept ? (accept ? 'accepted' : 'rejected') : `WRONG (${accepted ? 'accepted' : 'rejected'})`;
  }
  return out;
}

async function main() {
  const [evidencePath] = process.argv.slice(2);
  if (!evidencePath) throw new Error('usage: check-attempt-store.cjs <evidence.json>');
  const code = await bundle();
  const page = '<!doctype html><meta charset="utf-8"><title>attempt store suite</title>'
    + '<script src="/bundle.js"></script><script src="/harness.js"></script>';
  const server = http.createServer((req, res) => {
    const body = req.url === '/' ? page : req.url === '/bundle.js' ? code : req.url === '/harness.js' ? HARNESS : null;
    if (body === null) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'Content-Type': req.url === '/' ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8',
      'Cache-Control': 'no-store' });
    res.end(body);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const browser = await chromium.launch();
  const current = binding();
  const evidence = { suite: 'check-attempt-store', runUUID: crypto.randomUUID(), binding: current,
    bundleSHA256: sha256(code), browser: { name: 'chromium-headless-shell', version: browser.version(),
      playwright: require('playwright/package.json').version },
    processPlacement: 'UNKNOWN (independent pages of one context; renderer placement not observed)',
    startedAt: new Date().toISOString(), startedAtEpoch: Date.now() / 1000, cases: [] };
  const filter = process.env.CHECK_STORE_ONLY ? process.env.CHECK_STORE_ONLY.split(',') : null;
  try {
    for (const id of CASE_IDS) {
      if (filter && !filter.includes(id)) continue;
      const lab = new Lab(browser, port, new FakeChain());
      const started = Date.now();
      let row;
      try {
        await lab.context();
        let timer;
        // A case that outlives its bound keeps running until its context closes; its late rejection is that
        // closure, already reported as this case's timeout FAIL, never an unhandled crash of the whole suite.
        const run = CASES[id](lab);
        run.catch(() => {});
        const result = await Promise.race([run, new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(`case exceeded ${CASE_TIMEOUT_MS}ms`)), CASE_TIMEOUT_MS);
        })]).finally(() => clearTimeout(timer));
        const failed = Object.entries(result.checks).filter(([, v]) => v !== 'pass').map(([k]) => k);
        const pageErrors = lab.ctx.pages().flatMap((p) => p.errors || []);
        const problems = [...failed, ...(lab.external.length ? [`external requests: ${lab.external.slice(0, 3)}`] : []),
          ...pageErrors.map((e) => `page error: ${e}`)];
        row = { id, status: problems.length ? 'FAIL' : 'PASS', failures: problems, checks: result.checks,
          data: result.data, sends: lab.sends };
      } catch (error) {
        row = { id, status: 'FAIL', failures: [`case error: ${String(error.message).slice(0, 300)}`], checks: {} };
      }
      row.runUUID = evidence.runUUID;
      row.ms = Date.now() - started;
      evidence.cases.push(row);
      await lab.close().catch(() => {});
    }
  } finally {
    await browser.close();
    server.close();
  }
  evidence.finishedAt = new Date().toISOString();
  const errors = judge(evidence, binding());
  evidence.judgeControls = filter ? {} : controls(evidence, binding());
  const bad = Object.entries(evidence.judgeControls).filter(([, v]) => !['accepted', 'rejected'].includes(v));
  evidence.result = errors.length === 0 && bad.length === 0 && !filter ? 'PASS' : 'FAIL';
  evidence.errors = [...errors, ...bad.map(([k, v]) => `control ${k}: ${v}`)];
  evidence.counts = { required: CASE_IDS.length, cases: evidence.cases.length,
    passed: evidence.cases.filter((r) => r.status === 'PASS').length };
  fs.writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n');
  console.log(JSON.stringify({ suite: 'check-attempt-store', result: evidence.result, ...evidence.counts,
    errors: evidence.errors.slice(0, 20) }));
  return evidence.result === 'PASS' ? 0 : 1;
}

module.exports = { CASE_IDS, judge };

if (require.main === module) {
  main().then((code) => process.exit(code), (error) => { console.error(error.stack || error.message); process.exit(1); });
}
