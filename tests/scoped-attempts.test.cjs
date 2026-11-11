'use strict';
// Native Chromium IndexedDB + production controllers. Fake wallets/chain, no public network or real funds.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');
const esbuild = require('esbuild');
const { FakeChain, FakeWallet, legacyAttempt } = require('./support/fake-chain.cjs');
const APP = path.resolve(__dirname, '..');
const vectors = JSON.parse(fs.readFileSync(path.join(APP, 'tests/fixtures/registry-vectors.json')));
const handoffs = ['d1-pattern', 'd1-zero'].map((name) => {
  const row = vectors.vectors.find((v) => v.name === name);
  return JSON.stringify({ chainId: 137, expectedAddress: row.address, keyID: row.keyID,
    publicKey: row.publicPoint, recipe: vectors.recipe, salt: row.salt, version: 1 });
});

test('address scopes preserve legacy, isolate different Signers and serialize same-Signer sends', { timeout: 60000 }, async () => {
  const chain = new FakeChain();
  const model = await import('../model.js');
  const plan = (n) => model.buildPlan(model.parseHandoff(handoffs[n]));
  const legacy = legacyAttempt(chain, plan(0), { submit: false });
  const bundle = await esbuild.build({ stdin: { contents: [
    "export * from './attempt-store.js';", "export { RegistrationController, validateRecord, identityOf } from './controller.js';",
    "export { WalletManager } from './wallet.js';", "export { ORIGIN } from './model.js';",
  ].join('\n'), resolveDir: APP }, bundle: true, format: 'iife', globalName: 'R', write: false });
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', req.url === '/modules.js' ? 'application/javascript' : 'text/html');
    res.end(req.url === '/modules.js' ? bundle.outputFiles[0].text : '<script src="/modules.js"></script>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  try {
    await context.route('**/*', (route) => route.request().url().startsWith(origin + '/') ? route.continue() : route.abort());
    const wallets = [];
    async function page(owner = context) {
      const p = await owner.newPage();
      const wallet = new FakeWallet(chain, { accounts: [wallets.length % 2 ? '0x2222222222222222222222222222222222222222' : '0x1111111111111111111111111111111111111111'] });
      wallets.push(wallet);
      await p.exposeFunction('rpc', (method, params) => chain.rpc(method, params));
      await p.exposeFunction('walletRequest', async (request) => {
        try { return { value: await wallet.request(request) }; }
        catch (e) { return { error: { code: e.code, message: e.message } }; }
      });
      await p.goto(origin);
      return p;
    }
    const a = await page();
    // A real v1 database upgrade: no copying/re-encoding/deleting the singleton.
    const old = { version: 1, revision: 7, raw: legacy.raw, legacyRaw: null };
    await a.evaluate((row) => new Promise((resolve, reject) => {
      const q = indexedDB.open(R.DB_NAME, 1);
      q.onupgradeneeded = () => q.result.createObjectStore(R.STORE_NAME).put(row, R.SINGLETON_KEY);
      q.onsuccess = () => { window.oldDB = q.result; oldDB.onversionchange = () => { oldDB.close(); window.oldClosed = true; }; resolve(); };
      q.onerror = () => reject(q.error);
    }), old);
    async function create(p, index) {
      await p.evaluate(async ({ handoff }) => {
        const provider = { request: async (request) => {
          const r = await walletRequest(request);
          if (r.error) throw Object.assign(new Error(r.error.message), { code: r.error.code });
          return r.value;
        }, on() {}, removeListener() {} };
        const win = Object.assign(new EventTarget(), { Event, ethereum: provider });
        let c;
        const wallet = new R.WalletManager({ win, config: { walletConnectProjectId: null }, origin: location.origin,
          onChange: (event) => c && c.walletChanged(event) });
        const root = new R.AttemptStore({ indexedDB, readLegacy: () => localStorage.getItem(R.LEGACY_KEY), validateRecord: R.validateRecord });
        c = window.c = new R.RegistrationController({ rpc, wallet, store: root, uuid: () => crypto.randomUUID() });
        wallet.start();
        await c.loadAttempt();
        c.prepare(handoff);
        c.selectWallet('legacy');
        await c.connect();
      }, { handoff: handoffs[index] });
      await p.waitForFunction(() => !c.initializing);
    }
    await create(a, 0);
    assert.equal(await a.evaluate(() => c.view().locked), true, 'legacy A remains locked');
    assert.equal(await a.evaluate(() => oldClosed), true, 'upgrade closes v1 client');
    assert.equal(await a.evaluate(() => new Promise((resolve) => {
      const q = indexedDB.open(R.DB_NAME, 1);
      q.onerror = (event) => { event.preventDefault(); resolve(q.error.name); };
      q.onsuccess = () => { q.result.close(); resolve('unexpected success'); };
    })), 'VersionError', 'old client cannot reopen after upgrade');
    assert.equal(await a.evaluate(() => c.attempt.id), JSON.parse(legacy.raw).id);
    const b = await page();
    const competitor = await page();
    await Promise.all([create(b, 1), create(competitor, 1)]);
    assert.equal(await b.evaluate(() => c.view().locked), false, 'A must not block B');
    wallets[1].behavior.send = wallets[2].behavior.send = 'deferred';
    const admitted = await Promise.all([b.evaluate(() => c.deploy()), competitor.evaluate(() => c.deploy())]);
    const sender = admitted[0] ? b : competitor;
    const senderWallet = wallets[admitted[0] ? 1 : 2];
    for (let i = 0; i < 100 && !senderWallet.pendingSends.length; i++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(senderWallet.pendingSends.length, 1);
    // Switch public plan while the wallet reply is genuinely suspended, then return its late hash.
    const outcome = await sender.evaluate((handoff) => {
      const address = c.store.address;
      c.prepare(handoff);
      return { address, current: c.store.address, locked: c.view().locked };
    }, handoffs[0]);
    assert.equal(outcome.current, outcome.address, 'entered sender never redirects its store');
    assert.equal(outcome.locked, true);
    assert.equal(await sender.evaluate(() => c.storeAddress), plan(1).address.toLowerCase());
    senderWallet.releaseSend();
    await sender.waitForFunction((address) => c.storeAddress === address && !c.initializing,
      plan(0).address.toLowerCase());
    assert.equal(await sender.evaluate(() => c.attempt.address.toLowerCase()), plan(0).address.toLowerCase());
    assert.match(await sender.evaluate(async (address) => JSON.parse((await c.rootStore.forAddress(address).read()).raw).hash,
      plan(1).address), /^0x[0-9a-f]{64}$/, 'late reply remains in original row before switching');
    assert.equal(await sender.evaluate(() => c.plan.address.toLowerCase()), plan(0).address.toLowerCase());
    await sender.evaluate((handoff) => c.prepare(handoff), handoffs[1]);
    await sender.waitForFunction(() => !c.initializing && c.attempt && c.attempt.hash);
    assert.equal(wallets.reduce((n, w) => n + w.sends.length, 0), 1, 'same address CAS admits exactly one wallet send');
    assert.deepEqual(await b.evaluate(async () => (await c.rootStore.read())), old, 'legacy singleton byte-for-byte preserved');
    const bRow = await b.evaluate(() => c.store.read());
    assert.equal(JSON.parse(bRow.raw).address.toLowerCase(), plan(1).address.toLowerCase());
    assert.equal(await a.evaluate(() => c.attempt.address.toLowerCase()), plan(0).address.toLowerCase());
    const reopen = await page();
    await create(reopen, 1);
    assert.equal(await reopen.evaluate(() => c.view().locked), true, 'B reload resumes only B');
    assert.equal(await reopen.evaluate(() => c.attempt.id), JSON.parse(bRow.raw).id);
    await b.evaluate(async ({ other }) => {
      const snapshot = await c.store.read();
      const bad = { ...JSON.parse(snapshot.raw), address: other };
      window.badWrite = await c.store.compareAndSet(snapshot, JSON.stringify(bad)).then(() => false, () => true);
    }, { other: plan(0).address });
    assert.equal(await b.evaluate(() => badWrite), true, 'foreign record rejected');
    // A matching legacy row is copied unchanged; a scoped tombstone must mask it forever.
    await a.evaluate(async () => {
      const first = await c.store.read();
      const result = await c.store.compareAndSet(first, null);
      if (!result.committed) throw new Error('legacy tombstone did not commit');
      window.tombstone = result.snapshot;
      const stale = await c.store.compareAndSet(first, first.raw);
      if (stale.committed) throw new Error('stale legacy snapshot resurrected');
    });
    const tombstone = await a.evaluate(() => tombstone);
    assert.equal(tombstone.raw, null);
    assert.equal(tombstone.revision, old.revision + 1);
    assert.equal(await a.evaluate(async (address) => (await c.rootStore.forAddress(address).read()).raw,
      plan(0).address), null, 'reopen never reimports archived legacy bytes');
    assert.deepEqual(await b.evaluate(() => c.rootStore.read()), old);
    // A completed clear for A must never release or replace B after a target switch.
    await a.evaluate(async ({ raw }) => {
      const rejected = { ...JSON.parse(raw), state: 'rejected', reason: 'user-rejected' };
      await c.store.compareAndSet(await c.store.read(), JSON.stringify(rejected));
      await c.loadAttempt();
      if (!c.clearable()) throw new Error('fixture must be clearable');
      const store = c.store;
      const cas = store.compareAndSet.bind(store);
      const gate = new Promise((resolve) => { window.releaseClear = resolve; });
      store.compareAndSet = async (...args) => {
        const result = await cas(...args); window.clearCommitted = true; await gate; return result;
      };
      c.requestClear(); window.clearing = c.confirmClear();
    }, { raw: legacy.raw });
    await a.waitForFunction(() => window.clearCommitted);
    await a.evaluate((handoff) => {
      c.reloadRequired = true; c.clearedIdentity = 'old-reader-only-notice';
      c.prepare(handoff);
    }, handoffs[1]);
    assert.equal(await a.evaluate(() => c.reloadRequired || c.clearedIdentity), null, 'reader notices do not cross address scopes');
    await a.waitForFunction(() => !c.initializing);
    const selectedB = await a.evaluate(() => ({ key: c.snapshot.key, id: c.attempt.id }));
    await a.evaluate(async () => { releaseClear(); await clearing; });
    assert.deepEqual(await a.evaluate(() => ({ key: c.snapshot.key, id: c.attempt.id })), selectedB);
    // Deletion after initialization is not a fresh address, on either read or a reopened load.
    await a.evaluate(async (address) => {
      const db = await c.rootStore.open();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(R.STORE_NAME, 'readwrite');
        tx.objectStore(R.STORE_NAME).delete('signer:' + address.toLowerCase());
        tx.oncomplete = resolve; tx.onabort = () => reject(tx.error);
      });
    }, plan(0).address);
    assert.equal(await a.evaluate(async (address) => c.rootStore.forAddress(address).load()
      .then(() => null, (e) => e.code), plan(0).address), 'corrupt', 'missing scoped tombstone cannot reimport legacy');
    assert.deepEqual(await b.evaluate(() => c.rootStore.read()), old);
    // A completed rejection no longer makes this document permanently single-Signer.
    const fresh = await browser.newContext();
    await fresh.route('**/*', (route) => route.request().url().startsWith(origin + '/') ? route.continue() : route.abort());
    try {
      const rejected = await page(fresh), rejectedWallet = wallets.at(-1);
      await create(rejected, 0);
      rejectedWallet.behavior.send = 'reject';
      assert.equal(await rejected.evaluate(() => c.deploy()), true);
      await rejected.waitForFunction(() => c.attempt?.state === 'rejected' && !c.pendingWalletOutcomes && !c.outcomeWrites);
      await rejected.evaluate(async () => { c.requestClear(); await c.confirmClear(); });
      assert.equal(await rejected.evaluate(() => c.attempt), null);
      const savedA = await rejected.evaluate(() => c.store.read());
      await rejected.evaluate((h) => c.prepare(h), handoffs[1]);
      await rejected.waitForFunction((address) => c.storeAddress === address && !c.initializing, plan(1).address.toLowerCase());
      assert.equal(await rejected.evaluate(() => c.view().locked), false);
      assert.deepEqual(await rejected.evaluate((address) => c.rootStore.forAddress(address).read(), plan(0).address), savedA);
      assert.equal(rejectedWallet.sends.length, 1, 'selection and loading never send');
      rejectedWallet.behavior.send = 'deferred';
      assert.equal(await rejected.evaluate(() => c.deploy()), true);
      await rejected.waitForFunction(() => c.pendingWalletOutcomes === 1);
      await rejected.evaluate((h) => c.prepare(h), handoffs[0]);
      assert.equal(await rejected.evaluate(() => c.storeAddress), plan(1).address.toLowerCase(), 'hold owns original store');
      // A timeout persisted before the real response is not permission to switch stores.
      await rejected.evaluate(() => c.reconcileOutcome(R.identityOf(c.attempt), { kind: 'timeout' }));
      // The timeout does not settle the original provider promise.
      assert.equal(await rejected.evaluate(() => c.pendingWalletOutcomes), 1);
      rejectedWallet.releaseSend();
      await rejected.waitForFunction((address) => c.storeAddress === address && !c.initializing, plan(0).address.toLowerCase());
      assert.deepEqual(await rejected.evaluate(() => c.store.read()), savedA, 'B reply never resurrects cleared A');
      const savedB = await rejected.evaluate((address) => c.rootStore.forAddress(address).read(), plan(1).address);
      assert.match(JSON.parse(savedB.raw).hash, /^0x[0-9a-f]{64}$/);
      await rejected.evaluate((h) => c.prepare(h), handoffs[1]);
      await rejected.waitForFunction(() => !c.initializing && c.attempt?.hash);
      assert.equal(await rejected.evaluate(() => c.view().locked), true, 'returning to sent B resumes without resending');
      assert.equal(rejectedWallet.sends.length, 2, 'one rejected A, one explicit B request');
      // A failed manual result can be cleared while the original provider promise is still pending.
      // That tombstone must not allow a selected B plan to enter A's authority or request another send.
      await rejected.evaluate((h) => c.prepare(h), handoffs[0]);
      await rejected.waitForFunction((address) => c.storeAddress === address && !c.initializing,
        plan(0).address.toLowerCase());
      rejectedWallet.behavior.send = 'deferred';
      assert.equal(await rejected.evaluate(() => c.deploy()), true);
      await rejected.waitForFunction(() => c.pendingWalletOutcomes === 1);
      await rejected.evaluate(() => c.reconcileOutcome(R.identityOf(c.attempt), { kind: 'timeout' }));
      const manual = chain.submit({ ...rejectedWallet.built.at(-1) });
      chain.mine({ revert: true }); chain.mine();
      await rejected.evaluate((hash) => c.enterHash(hash), manual);
      assert.equal(await rejected.evaluate(() => c.phase()), 'failed');
      await rejected.evaluate(async () => { c.requestClear(); await c.confirmClear(); });
      await rejected.evaluate((h) => c.prepare(h), handoffs[1]);
      const before = await rejected.evaluate(() => c.store.read());
      assert.equal(await rejected.evaluate(() => c.view().locked), true);
      assert.equal(await rejected.evaluate(() => c.view().scopeWaiting), true);
      assert.equal(await rejected.evaluate(() => c.nextStage()), null);
      assert.equal(await rejected.evaluate(() => c.deploy()), false);
      assert.deepEqual(await rejected.evaluate(() => c.store.read()), before);
      assert.equal(rejectedWallet.sends.length, 3, 'retained original reply prevents additional requests');
      rejectedWallet.releaseSend(rejectedWallet.pendingSends.length - 1);
      await rejected.waitForFunction(() => !c.pendingWalletOutcomes && !c.outcomeWrites);
      assert.deepEqual(await rejected.evaluate(() => c.store.read()), before, 'late reply cannot resurrect tombstone');
      assert.equal(await rejected.evaluate(() => c.reloadRequired), true, 'cleared identity still requires reload');
    } finally { await fresh.close(); }
    await b.evaluate(() => localStorage.setItem(R.LEGACY_KEY, 'changed'));
    assert.equal(await b.evaluate(async () => {
      const snapshot = await c.store.read();
      return c.store.compareAndSet(snapshot, snapshot.raw).then(() => null, (e) => e.code);
    }), 'legacy-conflict');
  } finally {
    await context.close();
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
});
