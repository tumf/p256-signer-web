'use strict';
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

test('compact built UI: connect separately, send once, reject/retry, unknown/recheck, success, RPC recovery', { timeout: 60000 }, async () => {
  const chain = new FakeChain();
  const model = await import('../model.js');
  const plan = (n) => model.buildPlan(model.parseHandoff(handoffs[n]));
  const server = http.createServer(async (req, res) => {
    try {
      if (req.url === '/rpc') {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks));
        res.setHeader('Content-Type', 'application/json');
        try { res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: await chain.rpc(body.method, body.params) })); }
        catch (e) { res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: e.code || -32000, message: e.message } })); }
        return;
      }
      if (req.url === '/config.json') { res.setHeader('Content-Type', 'application/json'); res.end('{}'); return; }
      const file = req.url === '/' ? 'index.html' : req.url.slice(1);
      if (!/^[\w./-]+$/.test(file) || file.includes('..')) { res.writeHead(400).end(); return; }
      res.setHeader('Content-Type', file.endsWith('.js') ? 'application/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html');
      res.end(fs.readFileSync(path.join(APP, 'dist', file)));
    } catch { res.writeHead(404).end(); }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  // Mount the production controller/UI with a controlled pairing provider; no relay or send.
  const pairingProvider = (await esbuild.build({ stdin: { contents: `
    import { mountUI } from './ui.js';
    import { RegistrationController } from './controller.js';
    import { WalletManager } from './wallet.js';
    class EthereumProvider {
      static async init() { return new EthereumProvider(); }
      on(event, fn) { if (event === 'display_uri') queueMicrotask(() => fn('wc:' + '12'.repeat(32) + '@2?relay-protocol=irn&symKey=' + '34'.repeat(32))); }
      removeListener() {}
      connect() { return new Promise(() => {}); }
      disconnect() { return Promise.resolve(); }
    }
    let controller, render = () => {};
    const wallet = new WalletManager({ win: window,
      config: { walletConnectProjectId: 'ab'.repeat(16), allowedDeploymentOrigin: '${model.ORIGIN}' },
      origin: '${model.ORIGIN}', loadWalletConnect: async () => ({ EthereumProvider }),
      onChange: event => controller?.walletChanged(event) });
    controller = new RegistrationController({ rpc: async () => { throw Error('unused'); }, wallet,
      store: { async load() { return { snapshot: { raw: null, revision: 0 } }; } }, uuid: () => crypto.randomUUID(), onState: view => render(view) });
    render = mountUI(document, controller, { loadQR: () => import('./qr.js').then(m => m.default), clipboard() {} });
    await controller.loadAttempt(); controller.consumeFragment(location, history); wallet.start(); controller.emit();
    window.qrWallet = wallet;
    `, resolveDir: APP }, bundle: true, format: 'esm', write: false })).outputFiles[0].text;
  const browser = await chromium.launch({ headless: true });
  const contexts = [];
  const errors = [];
  try {
    async function open(index, { legacy = null } = {}) {
      const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
      contexts.push(context);
      await context.route('**/*', route => {
        if (route.request().url().startsWith('https://p256-signer.mini.tumf.dev/rpc')) {
          const body = route.request().postDataJSON();
          return chain.rpc(body.method, body.params).then(result => route.fulfill({json:{jsonrpc:'2.0',id:body.id,result}}),e=>route.fulfill({json:{jsonrpc:'2.0',id:body.id,error:{code:e.code||-32000,message:e.message}}}));
        }
        return route.request().url().startsWith(origin + '/') ? route.continue() : route.abort();
      });
      const p = await context.newPage();
      p.on('pageerror', (e) => errors.push(e.message));
      const wallet = new FakeWallet(chain, { accounts: ['0x1111111111111111111111111111111111111111'] });
      await p.exposeFunction('walletRequest', async (request) => {
        try { return { value: await wallet.request(request) }; }
        catch (e) { return { error: { code: e.code, message: e.message } }; }
      });
      await p.addInitScript(({ legacy }) => {
        window.ethereum = { request: async (request) => {
          const r = await walletRequest(request);
          if (r.error) throw Object.assign(new Error(r.error.message), { code: r.error.code });
          return r.value;
        }, on() {}, removeListener() {} };
        if (legacy) localStorage.setItem('p256.registration.attempt.v1', legacy);
      }, { legacy });
      await p.goto(origin + '/#registration=' + Buffer.from(handoffs[index]).toString('base64url'));
      await p.waitForFunction(() => window.__registration && !document.querySelector('main').matches('[aria-busy="true"]'));
      return { p, wallet };
    }
    const visibleButtons = (p) => p.locator('button:visible').allTextContents();
    const waitSend = (p) => p.waitForFunction(() => {
      const b = document.getElementById('send'); return b.getBoundingClientRect().height > 0 && !b.disabled;
    });
    const pairingContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
    contexts.push(pairingContext);
    const pairingPage = await pairingContext.newPage();
    await pairingPage.route('**/app.js', route => route.fulfill({ body: pairingProvider, contentType: 'text/javascript' }));
    await pairingPage.goto(origin + '/#registration=' + Buffer.from(handoffs[0]).toString('base64url'));
    await pairingPage.locator('#send:enabled').waitFor(); await pairingPage.click('#send');
    const { checkQRDownload } = await import('./support/qr-download.mjs');
    await checkQRDownload(pairingPage, 'pairing-qr');
    await pairingPage.click('#cancel-pairing');
    assert.equal(await pairingPage.locator('#pairing-qr + button').isDisabled(), true);
    assert.equal(await pairingPage.inputValue('#pairing-uri'), '');
    await pairingContext.close();
    // Reopening an app handoff can reuse the document: consume the new fragment, not the old tab plan.
    const { p: reused, wallet: reusedWallet } = await open(0);
    await waitSend(reused);
    await reused.evaluate(() => { window.documentMarker = 'same-document'; });
    for (const index of [1, 0, 1]) {
      await reused.goto(origin + '/#registration=' + Buffer.from(handoffs[index]).toString('base64url'));
      await reused.waitForFunction((address) => document.getElementById('plan-address').textContent === address && location.hash === '',
        plan(index).address, { timeout: 3000 });
      assert.equal(await reused.evaluate(() => window.documentMarker), 'same-document');
      await waitSend(reused);
      assert.equal(await reused.locator('#plan-state').textContent(), '');
      assert.equal(JSON.parse(await reused.evaluate(() => sessionStorage.getItem('p256.registration.plan.v1'))).expectedAddress, plan(index).address);
    }
    assert.equal(reusedWallet.requests.length, 0, 'handoff never connects or sends');
    await reused.goto(origin + '/#registration=bad');
    await reused.waitForFunction(() => document.getElementById('input-error').textContent && location.hash === '');
    assert.equal(await reused.locator('#plan').isVisible(), false, 'invalid handoff must not keep the old Signer');
    assert.equal(await reused.evaluate(() => sessionStorage.getItem('p256.registration.plan.v1')), null);
    await reused.reload();
    await reused.waitForFunction(() => window.__registration?.ready);
    assert.equal(await reused.locator('#plan').isVisible(), false, 'reload must not resurrect superseded input');
    const old = legacyAttempt(chain, plan(0), { submit: false });

    const { p, wallet } = await open(1, { legacy: old.raw });
    await waitSend(p);
    assert.deepEqual(await visibleButtons(p), ['ウォレットを接続']);
    for (const width of [390, 1280]) {
      await p.setViewportSize({ width, height: 900 });
      await p.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
      assert.equal(await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await p.evaluate(() => { document.documentElement.style.fontSize = ''; });
    }
    await p.setViewportSize({ width: 390, height: 844 });
    await p.locator('#send').focus();
    assert.equal(await p.locator('#send').evaluate((e) => e.getBoundingClientRect().height >= 48), true);
    await p.screenshot({ path: '/tmp/p256-compact-connect.png', fullPage: true });
    await p.keyboard.press('Enter');
    await p.waitForFunction(() => document.getElementById('send').textContent === '配備する');
    assert.equal(wallet.sends.length, 0, 'connect never submits a deployment');
    assert.match(await p.locator('#gas-note').innerText(), /ガス代/);
    await p.screenshot({ path: '/tmp/p256-compact-ready.png', fullPage: true });
    wallet.behavior.send = 'reject';
    await p.click('#send');
    await p.waitForFunction(() => document.body.dataset.phase === 'rejected');
    assert.deepEqual(await visibleButtons(p), ['もう一度配備する']);
    await p.screenshot({ path: '/tmp/p256-compact-cancelled.png', fullPage: true });
    await p.click('#clear');
    await p.click('#confirm-clear');
    await waitSend(p);
    wallet.behavior.send = 'normal';
    await p.click('#send');
    await p.waitForFunction(() => document.body.dataset.phase === 'txPending');
    assert.equal(wallet.sends.length, 2, 'one rejected request, one explicitly retried request');
    assert.equal(chain.writes, 1);
    // A persisted reply allows selecting A; its retained legacy unknown is adopted, not B's send.
    await p.goto(origin + '/#registration=' + Buffer.from(handoffs[0]).toString('base64url'));
    await p.waitForFunction((address) => document.getElementById('plan-address').textContent === address && location.hash === '', plan(0).address);
    await p.click('#payload-summary');
    await p.waitForFunction(() => document.body.dataset.phase === 'unknown');
    assert.equal(await p.locator('#send').isVisible(), false);
    assert.match(await p.locator('#attempt-detail-list').innerText(), new RegExp(plan(0).address, 'i'));

    await p.goto(origin + '/#registration=' + Buffer.from(handoffs[1]).toString('base64url'));
    await p.waitForFunction((address) => document.getElementById('plan-address').textContent === address && location.hash === '', plan(1).address);
    await p.click('#payload-summary');
    assert.equal(wallet.sends.length, 2, 'handoff switch never reuses send intent');
    chain.mine(); chain.mine();
    // Production polling is real-time (2s), not replaced by a synthetic state.
    await p.waitForFunction(() => document.body.dataset.phase === 'success');
    assert.deepEqual(await visibleButtons(p), ['アドレスをコピー']);
    assert.equal(await p.locator('#attempt-status').innerText(), '配備が完了しました。');
    await p.screenshot({ path: '/tmp/p256-compact-success.png', fullPage: true });
    assert.equal(await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    // Reload: different-Signer legacy warning must not reappear.
    await p.reload();
    await p.waitForFunction(() => document.body.dataset.phase === 'success');
    assert.equal(await p.locator('#plan-blocked').isVisible(), false);

    // A deployed address and a hashless unknown send are separate facts: compact status, retained recovery.
    const deployedUnknown = legacyAttempt(chain, plan(1), { submit: false });
    const { p: deployed, wallet: deployedWallet } = await open(1, { legacy: deployedUnknown.raw });
    await deployed.waitForFunction(() => document.getElementById('plan-state').textContent === 'すでに配備されています。');
    assert.equal(await deployed.locator('#section-settlement').isVisible(), false);
    assert.deepEqual(await visibleButtons(deployed), ['アドレスをコピー']);
    await deployed.click('#payload-summary');
    assert.equal(await deployed.locator('#manual-hash').isVisible(), true, 'recovery remains accessible');
    assert.equal(deployedWallet.sends.length, 0);
    for (const width of [390, 1280]) {
      await deployed.setViewportSize({ width, height: 900 });
      assert.equal(await deployed.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true,
        'expanded details wrap without hiding horizontal overflow');
    }

    // Hashless unknown gets a read-only recheck and no send action.
    const { p: unknown, wallet: unknownWallet } = await open(0, { legacy: old.raw });
    await unknown.waitForFunction(() => document.body.dataset.phase === 'unknown'
      && document.getElementById('plan-state').textContent !== '配備状態を確認中…');
    assert.deepEqual(await visibleButtons(unknown), ['状況を更新']);
    await unknown.click('#refresh');
    await unknown.waitForFunction(() => document.getElementById('refresh').textContent === '状況を更新');
    assert.equal(unknownWallet.sends.length, 0);
    await unknown.click('#payload-summary');
    assert.equal(await unknown.locator('#manual-hash').isVisible(), true);
    assert.equal(await unknown.locator('#send').isVisible(), false);
    await unknown.screenshot({ path: '/tmp/p256-compact-unknown.png', fullPage: true });

    // A late unsaved reply for A must stay actionable even while the public plan displays deployed B.
    const { p: held, wallet: heldWallet } = await open(0);
    await waitSend(held);
    await held.click('#send');
    await held.waitForFunction(() => document.getElementById('send').textContent === '配備する');
    heldWallet.behavior.send = 'deferred';
    await held.click('#send');
    for (let i = 0; i < 100 && !heldWallet.pendingSends.length; i++) await new Promise((r) => setTimeout(r, 10));
    assert.equal(heldWallet.pendingSends.length, 1);
    const readRows = () => held.evaluate(() => new Promise((resolve, reject) => {
      const q = indexedDB.open('p256.registration.attempts', 2);
      q.onerror = () => reject(q.error);
      q.onsuccess = () => {
        const db = q.result, tx = db.transaction('state', 'readonly'), store = tx.objectStore('state');
        const keys = store.getAllKeys(), values = store.getAll();
        tx.oncomplete = () => { db.close(); resolve(Object.fromEntries(keys.result.map((key, i) => [key, values.result[i]]))); };
        tx.onabort = () => { db.close(); reject(tx.error); };
      };
    }));
    const beforeHeld = await readRows();
    await held.goto(origin + '/#registration=' + Buffer.from(handoffs[1]).toString('base64url'));
    await held.waitForFunction((address) => document.getElementById('plan-address').textContent === address && location.hash === '', plan(1).address);
    await held.waitForFunction(() => document.getElementById('plan-state').textContent === 'すでに配備されています。');
    await held.evaluate(() => {
      const transaction = IDBDatabase.prototype.transaction;
      window.failAttemptWrites = true;
      IDBDatabase.prototype.transaction = function (...args) {
        if (window.failAttemptWrites && this.name === 'p256.registration.attempts' && args[1] === 'readwrite') {
          throw new DOMException('test outcome persistence failure', 'QuotaExceededError');
        }
        return transaction.apply(this, args);
      };
    });
    heldWallet.releaseSend();
    await held.waitForFunction(() => document.getElementById('attempt-context-text').textContent.includes('保存できませんでした'));
    assert.deepEqual(await readRows(), beforeHeld, 'failed outcome persistence changes no native rows');
    assert.equal(await held.locator('#payload-details').evaluate((e) => e.open), false);
    assert.equal(await held.locator('#send-error').isVisible(), true, 'foreign unsaved warning is outside folded details');
    assert.match(await held.locator('#send-error').innerText(), /ページを閉じず/);
    assert.equal(await held.locator('#refresh').isVisible(), true, 'foreign outcome persistence retry stays reachable');
    assert.equal(await held.locator('#send').isVisible(), false);
    assert.equal(await held.locator('#section-settlement').isVisible(), false, 'A is not presented as B settlement');
    await held.evaluate(() => { window.failAttemptWrites = false; });
    await held.click('#refresh');
    await held.waitForFunction(() => !document.getElementById('send-error').getBoundingClientRect().height);
    const afterHeld = await readRows(), heldKey = 'signer:' + plan(0).address.toLowerCase();
    const savedHeld = JSON.parse(afterHeld[heldKey].raw);
    assert.equal(savedHeld.id, JSON.parse(beforeHeld[heldKey].raw).id);
    assert.equal(savedHeld.address.toLowerCase(), plan(0).address.toLowerCase());
    assert.match(savedHeld.hash, /^0x[0-9a-f]{64}$/);
    delete beforeHeld[heldKey]; delete afterHeld[heldKey];
    // Safe automatic selection loads B's empty scope only after A's outcome is durable.
    const selectedKey = 'signer:' + plan(1).address.toLowerCase();
    assert.deepEqual(afterHeld[selectedKey], { version: 1, revision: 0, raw: null, legacyRaw: null });
    assert.equal(afterHeld['initialized:' + plan(1).address.toLowerCase()], true);
    delete afterHeld[selectedKey]; delete afterHeld['initialized:' + plan(1).address.toLowerCase()];
    assert.deepEqual(afterHeld, beforeHeld, 'retry changes no other retained row');
    assert.equal(heldWallet.sends.length, 1, 'retry persistence never sends again');
    assert.equal(await held.locator('#send-error').isVisible(), false);

    chain.faults.offline = true;
    const { p: offline } = await open(0);
    await offline.waitForFunction(() => document.getElementById('retry-inspection').getBoundingClientRect().height > 0);
    chain.faults.offline = false;
    await offline.click('#retry-inspection');
    await waitSend(offline);
    assert.deepEqual(await visibleButtons(offline), ['ウォレットを接続']);

    // Initial inspection failed; deployment then completes while its wallet reply/hash stays unknown.
    // Rechecking must update the normal status, not only the folded record details.
    chain.faults.offline = true;
    const { p: recovered, wallet: recoveredWallet } = await open(0, { legacy: old.raw });
    await recovered.waitForFunction(() => document.body.dataset.phase === 'unknown');
    await recovered.waitForLoadState('networkidle');
    const retained = () => recovered.evaluate(() => new Promise((resolve, reject) => {
      const q = indexedDB.open('p256.registration.attempts', 2);
      q.onerror = () => reject(q.error);
      q.onsuccess = () => {
        const db = q.result, tx = db.transaction('state', 'readonly'), rows = tx.objectStore('state').getAll();
        tx.oncomplete = () => { db.close(); resolve(rows.result); };
        tx.onabort = () => { db.close(); reject(tx.error); };
      };
    }));
    const beforeRefresh = await retained();
    chain.faults.offline = false;
    chain.preDeploy(plan(0));
    await recovered.click('#refresh');
    await recovered.waitForFunction(() => document.getElementById('attempt-context-text').textContent.includes('予定アドレスの読取り: 配備済み'));
    await recovered.waitForFunction(() => document.getElementById('plan-state').textContent === 'すでに配備されています。', null, { timeout: 5000 });
    assert.equal(await recovered.locator('#section-settlement').isVisible(), false);
    assert.deepEqual(await visibleButtons(recovered), ['アドレスをコピー']);
    assert.equal(await recovered.evaluate(() => document.body.dataset.phase), 'unknown', 'deployed is not a receipt');
    assert.deepEqual(await retained(), beforeRefresh, 'readback does not rewrite or delete unknown attempts');
    assert.equal(recoveredWallet.sends.length, 0);
    await recovered.click('#payload-summary');
    assert.equal(await recovered.locator('#manual-hash').isVisible(), true);
    for (const fault of ['mismatch', 'offline']) {
      chain.preDeploy(plan(0), { owner: fault === 'mismatch' ? '0x' + '11'.repeat(20) : undefined });
      chain.faults.offline = fault === 'offline';
      await recovered.click('#refresh');
      await recovered.waitForLoadState('networkidle');
      await recovered.waitForFunction(() => document.getElementById('plan-state').textContent !== '配備状態を確認中…');
      assert.notEqual(await recovered.locator('#plan-state').textContent(), 'すでに配備されています。', fault);
      assert.equal(await recovered.locator('#section-settlement').isVisible(), true);
      assert.equal(await recovered.locator('#send').isVisible(), false);
      assert.deepEqual(await retained(), beforeRefresh);
    }
    chain.faults.offline = false;
    assert.equal(recoveredWallet.sends.length, 0);

    // Switching back to a Signer with a hashless unknown must not flash that history as a current error.
    chain.preDeploy(plan(0));
    await recovered.click('#payload-summary');
    await recovered.goto(origin + '/#registration=' + Buffer.from(handoffs[1]).toString('base64url'));
    await recovered.waitForFunction((address) => document.getElementById('plan-address').textContent === address
      && document.getElementById('plan-state').textContent === 'すでに配備されています。', plan(1).address);
    const beforeSwitch = await retained();
    let releaseSwitch;
    const switchGate = new Promise((resolve) => { releaseSwitch = resolve; });
    let reachedSwitch;
    const switchStarted = new Promise((resolve) => { reachedSwitch = resolve; });
    let holdSwitch = true;
    await recovered.route('**/rpc', async (route) => {
      if (holdSwitch) { holdSwitch = false; reachedSwitch(); await switchGate; }
      await route.fallback();
    });
    await recovered.goto(origin + '/#registration=' + Buffer.from(handoffs[0]).toString('base64url'));
    await switchStarted;
    await recovered.waitForFunction((address) => document.getElementById('plan-address').textContent === address
      && document.body.dataset.phase === 'unknown', plan(0).address);
    try {
      assert.equal(await recovered.locator('#plan-state').innerText(), '配備状態を確認中…');
      assert.equal(await recovered.locator('#section-settlement').isVisible(), false, 'historical unknown stays folded while checking');
      assert.equal(await recovered.locator('#send').isVisible(), false);
      assert.equal(await recovered.locator('#refresh').isVisible(), false);
      assert.deepEqual(await retained(), beforeSwitch);
    } finally { releaseSwitch(); }
    await recovered.waitForFunction(() => document.getElementById('plan-state').textContent === 'すでに配備されています。');
    assert.equal(await recovered.locator('#section-settlement').isVisible(), false);
    assert.equal(recoveredWallet.sends.length, 0);

    // An older same-plan inspection must not overwrite the newer explicit refresh.
    // Delay its final block response after computing an undeployed result, then let refresh see deployment.
    chain.deployments.delete(plan(0).address.toLowerCase());
    const { p: stale, wallet: staleWallet } = await open(0, { legacy: old.raw });
    await stale.waitForFunction(() => document.body.dataset.phase === 'unknown');
    await stale.waitForLoadState('networkidle');
    let releaseRead;
    const pendingRead = new Promise((resolve) => { releaseRead = resolve; });
    let reachedRead;
    const reached = new Promise((resolve) => { reachedRead = resolve; });
    let readHeld = false;
    await stale.route('**/rpc', async (route) => {
      const body = route.request().postDataJSON();
      const response = await route.fetch({url: origin + '/rpc'});
      if (!readHeld && body.method === 'eth_getBlockByNumber' && body.params[0] !== 'latest') {
        readHeld = true;
        reachedRead();
        await pendingRead;
      }
      await route.fulfill({ response });
    });
    const reloading = stale.reload();
    await reached;
    await reloading;
    await stale.waitForFunction(() => document.body.dataset.phase === 'unknown');
    chain.preDeploy(plan(0));
    await stale.click('#refresh');
    await stale.waitForFunction(() => document.getElementById('plan-state').textContent === 'すでに配備されています。');
    releaseRead();
    await stale.waitForLoadState('networkidle');
    assert.equal(await stale.locator('#plan-state').innerText(), 'すでに配備されています。', 'old inspection cannot overwrite refresh');
    assert.equal(staleWallet.sends.length, 0);
    assert.deepEqual(errors, []);
  } finally {
    for (const context of contexts) await context.close();
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
});
