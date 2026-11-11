'use strict';
// Deterministic browser harness over the BUILT production page served by the real serve.py.
// - The page origin is the fixed https://p256-signer.tumf.dev (routed to the loopback server), so the
//   production WalletConnect origin check passes genuinely; one scenario uses the true loopback origin.
// - serve.py's only upstream is an in-process read-only chain double; a test-only EIP-1193 provider is
//   injected with addInitScript and backed by FakeWallet (captures every request, including the real send).
// - The WalletConnect relay is a local WebSocket mock (adapter proof, not real relay pairing).
// - Every expanded ui-states.json row is rendered through actual controller commands, settled, measured
//   (computed tokens/geometry against design section 8 and the pinned authority reference) and screenshotted.
// Usage: node tests/check-browser.cjs <evidence.json> <screenshot-dir>
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');
const { chromium } = require('playwright');
const oracle = require('./support/oracle.cjs');
const { FakeChain, FakeWallet, PROXY, GWEI, legacyAttempt } = require('./support/fake-chain.cjs');
const { expandAll, expandOriginal, w24Controls } = require('./support/matrix.cjs');

const APP = path.resolve(__dirname, '..');
const ROOT = path.resolve(APP, '../..');
const ORIGIN = 'https://p256-signer.tumf.dev';
const PROJECT = '0123456789abcdef0123456789abcdef';
const ACCOUNT = '0x1111111111111111111111111111111111111111';
const OTHER = '0x2222222222222222222222222222222222222222';
const vectors = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests/fixtures/registry-vectors.json'), 'utf8'));
const ROW = vectors.vectors.find((v) => v.name === 'd1-pattern');
const HANDOFF = JSON.stringify({ chainId: 137, expectedAddress: ROW.address, keyID: ROW.keyID, publicKey: ROW.publicPoint,
  recipe: vectors.recipe, salt: ROW.salt, version: 1 });
const OTHER_BINDING = HANDOFF.replace(ROW.address, vectors.vectors[0].address);
const LEGACY_KEY = 'p256.registration.attempt.v1';
const PLAN_KEY = 'p256.registration.plan.v1';
const TOKENS = { paper: 'rgb(245, 244, 237)', ink: 'rgb(23, 46, 40)', line: 'rgb(180, 192, 184)',
  accent: 'rgb(169, 237, 92)', focus: 'rgb(59, 116, 23)', field: 'rgb(255, 254, 248)', address: 'rgb(229, 235, 223)',
  addressBorder: 'rgb(77, 118, 42)', errorBg: 'rgb(250, 228, 222)', errorInk: 'rgb(122, 41, 22)' };

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)); });
    server.on('error', reject);
  });
}

/** Source/build/revision binding of this run. */
function digests() {
  const files = ['index.html', 'styles.css', 'ui.js', 'app.js', 'model.js', 'chains.js', 'wallet.js', 'controller.js',
    'attempt-store.js', 'qr.js', 'walletconnect.js', 'serve.py', 'build.mjs', 'package.json', 'package-lock.json', 'licenses.json',
    'vendor/proxy.json', 'vendor/ethers.cjs', 'vendor/ethers.js', 'tests/ui-states.json', 'tests/check-browser.cjs',
    'tests/support/fake-chain.cjs', 'tests/support/oracle.cjs', 'tests/support/matrix.cjs'];
  const source = sha256(files.map((f) => f + '\0' + sha256(fs.readFileSync(path.join(APP, f)))).join('\n'));
  const asset = sha256(fs.readFileSync(path.join(APP, 'dist/asset-manifest.json')));
  let head = null;
  let dirty = null;
  try {
    head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
    dirty = sha256(execFileSync('git', ['diff', 'HEAD', '--', '.'], { cwd: APP, encoding: 'utf8', maxBuffer: 64e6 })
      + execFileSync('git', ['status', '--porcelain', '--', '.'], { cwd: APP, encoding: 'utf8' }));
  } catch { /* outside git: recorded as null and rejected by the judge */ }
  return { source, asset, head, dirty };
}

/**
 * Fail-closed evidence judge shared with the negative controls. `states` are the declared ui-states.json rows:
 * every row must be measured at its own viewport, W24 rows need a passing subresult measured at the row width for
 * each declared control and a screenshot probe depicting the variant, W25 rows a screenshot taken while the inline
 * clear confirmation was shown.
 */
function judge(expectedIds, evidence, current, screenshotDir, states = []) {
  const errors = [];
  if (!evidence || !Array.isArray(evidence.rows)) return ['evidence is malformed'];
  const declared = new Map(states.map((state) => [state.id, state]));
  for (const key of ['source', 'asset', 'head', 'dirty']) {
    if (!current[key] || evidence.binding[key] !== current[key]) errors.push(`stale evidence: ${key} differs`);
  }
  const ids = evidence.rows.map((row) => row.id);
  const duplicate = [...new Set(ids.filter((id, i) => ids.indexOf(id) !== i))];
  const missing = expectedIds.filter((id) => !ids.includes(id));
  const unknown = ids.filter((id) => !expectedIds.includes(id));
  if (duplicate.length) errors.push(`duplicate rows: ${duplicate.join(', ')}`);
  if (missing.length) errors.push(`missing rows: ${missing.join(', ')}`);
  if (unknown.length) errors.push(`unknown rows: ${unknown.join(', ')}`);
  for (const row of evidence.rows) {
    if (row.status !== 'PASS') errors.push(`${row.id} is ${row.status}`);
    if (row.runUUID !== evidence.runUUID) errors.push(`${row.id} belongs to another run`);
    const file = row.screenshot && path.join(screenshotDir, row.screenshot);
    if (!file || !fs.existsSync(file) || sha256(fs.readFileSync(file)) !== row.screenshotSHA256) {
      errors.push(`${row.id} screenshot missing or changed`);
    }
    if (!row.measured || !row.settledPhase) errors.push(`${row.id} lacks measured values or settled state`);
    const state = declared.get(row.id);
    if (!state) continue;
    const width = state.viewport.width;
    const layoutWidth = state.textScale === 2 ? width * 2 : width;
    if (!row.measured || row.measured.viewport !== layoutWidth) {
      errors.push(`${row.id} was not measured at ${layoutWidth}`);
    }
    if (Array.isArray(state.controls)) {
      const sub = row.subresults || {};
      for (const control of state.controls) {
        const result = sub[control.element];
        if (!result) errors.push(`${row.id} omits control ${control.name}`);
        else if (result.result !== 'pass') errors.push(`${row.id} control ${control.name} is ${result.result}`);
        else if (result.viewport !== width) errors.push(`${row.id} control ${control.name} measured at ${result.viewport}`);
        else if (result.expect !== control.expect) errors.push(`${row.id} control ${control.name} expectation differs`);
      }
      const shot = row.atScreenshot;
      if (!shot || shot.result !== 'pass' || shot.variant !== state.variant || shot.control !== state.captureControl
        || shot.viewport !== width) errors.push(`${row.id} screenshot does not depict ${state.variant} at ${width}`);
    }
    if (state.row === 'W25') {
      const shot = row.atScreenshot;
      if (!shot || shot.confirmationVisible !== true || shot.clearHidden !== true || shot.viewport !== width) {
        errors.push(`${row.id} screenshot lacks the inline clear confirmation`);
      }
    }
  }
  return errors;
}

// -------------------------------------------------------------------------------------------------
// Fixture servers

function startUpstream(state) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', async () => {
      const request = JSON.parse(body);
      const hold = state.holds[request.method];
      if (hold) await hold.promise;
      try {
        const result = await state.chain.rpc(request.method, request.params);
        const text = JSON.stringify({ jsonrpc: '2.0', id: request.id, result });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(text);
      } catch (error) {
        if (!Number.isInteger(error.code)) { res.writeHead(503); return res.end('{}'); }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: request.id, error: { code: error.code, message: error.message } }));
      }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function startServe(port, upstreamPort, project) {
  const env = { ...process.env, REGISTRATION_PORT: String(port),
    POLYGON_RPC_URL: `http://127.0.0.1:${upstreamPort}/rpc` };
  delete env.WALLETCONNECT_PROJECT_ID;
  if (project) env.WALLETCONNECT_PROJECT_ID = project;
  const child = spawn(process.env.PYTHON || 'python3', [path.join(APP, 'serve.py')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  for (let i = 0; i < 50; i++) {
    if (child.exitCode !== null) throw new Error('serve.py exited');
    try {
      const ok = await new Promise((resolve) => {
        const r = http.get({ host: '127.0.0.1', port, path: '/config.json', headers: { Host: `127.0.0.1:${port}` } },
          (res) => { res.resume(); resolve(res.statusCode === 200); });
        r.on('error', () => resolve(false));
      });
      if (ok) return child;
    } catch { /* retry */ }
    await sleep(100);
  }
  child.kill();
  throw new Error('serve.py did not become ready within 50 probes');
}

// -------------------------------------------------------------------------------------------------
// Page harness

const INIT = (cfg) => {
  // Same-document markers: a navigation or reload would lose them.
  window.__documentMarker = true;
  window.__initialHistory = history.length;
  const listeners = {};
  const make = (id) => ({
    async request({ method, params }) {
      const answer = await window.__wallet(id, method, params === undefined ? [] : params);
      if (answer && answer.error) throw Object.assign(new Error(answer.error.message), { code: answer.error.code });
      return answer.ok;
    },
    on(name, fn) { (listeners[id + ':' + name] = listeners[id + ':' + name] || new Set()).add(fn); },
    removeListener(name, fn) { if (listeners[id + ':' + name]) listeners[id + ':' + name].delete(fn); },
  });
  window.__walletEmit = (id, name, arg) => { for (const fn of listeners[id + ':' + name] || []) fn(arg); };
  if (cfg.legacy) window.ethereum = make('legacy');
  const announced = cfg.announce.map((a) => Object.freeze({ info: Object.freeze({ uuid: a.uuid, name: a.name,
    icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>', rdns: 'test.' + a.uuid }),
  provider: a.sameAsLegacy && window.ethereum ? window.ethereum : make(a.uuid) }));
  window.addEventListener('eip6963:requestProvider', () => {
    for (const detail of announced) window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail }));
  });
  if (cfg.storage) for (const [k, v] of Object.entries(cfg.storage)) localStorage.setItem(k, v);
  if (cfg.storageUnavailable) {
    Object.defineProperty(window, 'localStorage', { get() { throw new DOMException('denied', 'SecurityError'); } });
  }
  if (cfg.storageUnavailable || cfg.idbUnavailable) {
    Object.defineProperty(window, 'indexedDB', { get() { throw new DOMException('denied', 'SecurityError'); } });
  }
  if (cfg.holdOpen) {
    // Bounded, test-controlled delay of the native open request (the store's own deadline still applies).
    const native = window.indexedDB;
    window.__nativeIDB = native;
    const wrapper = { open(name, version) {
      const proxy = {};
      window.__releaseOpen = () => {
        const request = native.open(name, version);
        for (const type of ['upgradeneeded', 'success', 'error', 'blocked']) {
          request.addEventListener(type, (event) => { if (proxy['on' + type]) proxy['on' + type](event); });
        }
      };
      return proxy;
    } };
    Object.defineProperty(window, 'indexedDB', { get: () => wrapper });
  }
  const setItem = Storage.prototype.setItem;
  Storage.prototype.setItem = function (k, v) {
    if (window.__failWrites) throw new DOMException('quota', 'QuotaExceededError');
    return setItem.call(this, k, v);
  };
  // Storage write failure: the native put succeeds, then its transaction aborts before completion.
  const put = IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put = function (...args) {
    const request = put.apply(this, args);
    if (window.__failWrites) this.transaction.abort();
    return request;
  };
};

/** The stored attempt row read through a separate native connection (null raw = tombstone). */
const IDB_PEEK = async (address) => {
  const name = 'p256.registration.attempts';
  const factory = window.__nativeIDB || indexedDB;
  if (!(await factory.databases()).some((d) => d.name === name)) return { exists: false, raw: null };
  return new Promise((resolve, reject) => {
    const request = factory.open(name);
    request.onerror = () => reject(new Error('peek open failed'));
    request.onsuccess = () => {
      const db = request.result;
      const get = db.transaction('state', 'readonly').objectStore('state').get('signer:' + address.toLowerCase());
      get.onsuccess = () => { db.close(); resolve({ exists: true, row: get.result ?? null, raw: get.result ? get.result.raw : null }); };
      get.onerror = () => { db.close(); reject(new Error('peek get failed')); };
    };
  });
};
const storedRow = (page, address = ROW.address) => page.evaluate(IDB_PEEK, address);
const storedRaw = async (page) => (await storedRow(page)).raw;

class Session {
  constructor(env, options = {}) {
    this.env = env;
    this.options = { legacy: true, announce: [], origin: 'allowed', server: 'withId', clock: false,
      viewport: { width: 1280, height: 900 }, ...options };
    this.chain = env.state.chain = new FakeChain();
    env.state.holds = {};
    this.wallets = {};
    this.external = [];
    this.wcChunk = false;
    this.relayFrames = [];
  }

  wallet(id = 'legacy') {
    if (!this.wallets[id]) this.wallets[id] = new FakeWallet(this.chain, { accounts: [ACCOUNT] });
    return this.wallets[id];
  }

  get sends() { return Object.values(this.wallets).reduce((n, w) => n + w.sends.length, 0); }

  async open({ fragment = '', storage = null, storageUnavailable = false, idbUnavailable = false, holdOpen = false,
    waitReady = true } = {}) {
    const env = this.env;
    this.context = await env.browser.newContext({ locale: 'ja-JP', colorScheme: 'light', reducedMotion: 'reduce',
      viewport: { ...this.options.viewport }, deviceScaleFactor: 1, timezoneId: 'Asia/Tokyo',
      bypassCSP: Boolean(this.options.bypassCSP) });
    const target = this.options.server === 'withId' ? env.portWithId : env.portNoId;
    const local = `http://127.0.0.1:${target}`;
    await this.context.route('**/*', (route) => {
      const url = route.request().url();
      if (url.startsWith(local)) return route.continue();
      this.external.push(url);
      return route.abort('blockedbyclient');
    });
    await this.context.route(`${ORIGIN}/**`, async (route) => {
      const url = new URL(route.request().url());
      if (url.pathname.includes('chunks/walletconnect-')) this.wcChunk = true;
      const headers = { ...route.request().headers(), host: `127.0.0.1:${target}` };
      if (headers.origin) headers.origin = local;
      // A fixture that closes its context while a proxied fetch is in flight disposes the response; that request is
      // abandoned (its row already finished) instead of crashing the whole suite with an unhandled rejection.
      try {
        const response = await route.fetch({ url: local + url.pathname + url.search, headers, maxRedirects: 0 });
        await route.fulfill({ response });
      } catch (error) {
        if (!/disposed|closed/i.test(String(error && error.message))) throw error;
      }
    });
    await this.context.routeWebSocket(/./, (ws) => {
      if (!ws.url().startsWith('wss://relay.walletconnect.com')) { this.external.push(ws.url()); return ws.close(); }
      // Local relay mock: acknowledge subscribe/publish so the real SDK can create a pairing URI.
      ws.onMessage((message) => {
        this.relayFrames.push(String(message).slice(0, 80));
        let request;
        try { request = JSON.parse(message); } catch { return; }
        if (!request.method) return;
        if (this.options.relayError) {
          return ws.send(JSON.stringify({ id: request.id, jsonrpc: '2.0', error: { code: -32000, message: 'relay down' } }));
        }
        ws.send(JSON.stringify({ id: request.id, jsonrpc: '2.0',
          result: request.method.endsWith('ubscribe') ? 'ab'.repeat(32) : true }));
      });
    });
    await this.context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: ORIGIN });
    this.page = await this.context.newPage();
    this.consoleErrors = [];
    this.page.on('pageerror', (error) => this.consoleErrors.push(`${error.name}: ${String(error.message).slice(0, 160)} `
      + `${String(error.stack || '').split('\n').slice(1, 3).join(' ').slice(0, 200)}`));
    await this.page.exposeFunction('__wallet', async (id, method, params) => {
      try { return { ok: await this.wallet(id).request({ method, params }) }; } catch (error) {
        return { error: { code: error.code, message: String(error.message) } };
      }
    });
    for (const id of ['legacy', ...this.options.announce.map((a) => a.uuid)]) this.wallet(id);
    await this.page.addInitScript(INIT, { legacy: this.options.legacy, announce: this.options.announce, storage,
      storageUnavailable, idbUnavailable, holdOpen });
    if (this.options.clock) await this.page.clock.install();
    const base = this.options.origin === 'allowed' ? ORIGIN : local;
    this.openedAt = Date.now();
    await this.page.goto(base + '/' + fragment);
    if (waitReady) await this.page.waitForFunction(() => window.__registration && document.body.dataset.phase);
    else await this.page.waitForFunction(() => document.body.dataset.phase);
    return this;
  }

  /** A second independently opened page of the same context (shared storage) with its own wallet/account. */
  async peer(account = OTHER) {
    const wallet = new FakeWallet(this.chain, { accounts: [account] });
    this.wallets.peer = wallet;
    const page = await this.context.newPage();
    page.errors = [];
    page.on('pageerror', (error) => this.consoleErrors.push(`peer ${error.name}: ${String(error.message).slice(0, 160)}`));
    await page.exposeFunction('__wallet', async (id, method, params) => {
      try { return { ok: await wallet.request({ method, params }) }; } catch (error) {
        return { error: { code: error.code, message: String(error.message) } };
      }
    });
    await page.addInitScript(INIT, { legacy: true, announce: [], storage: null });
    await page.goto(ORIGIN + '/#registration=' + Buffer.from(HANDOFF).toString('base64url'));
    await page.waitForFunction(() => window.__registration && document.body.dataset.phase);
    return { page, wallet };
  }

  async reload() {
    await this.page.reload();
    await this.page.waitForFunction(() => window.__registration && document.body.dataset.phase);
  }

  phase() { return this.page.evaluate(() => document.body.dataset.phase); }

  async waitPhase(...phases) {
    try {
      await this.page.waitForFunction((list) => list.includes(document.body.dataset.phase), phases, { timeout: 8000 });
    } catch {
      throw new Error(`phase ${await this.phase()} never became ${phases.join('|')}`);
    }
  }

  emit(id, name, arg) {
    if (name === 'accountsChanged') this.wallet(id).accounts = arg;
    if (name === 'chainChanged') this.wallet(id).chainId = arg;
    return this.page.evaluate(([i, n, a]) => window.__walletEmit(i, n, a), [id, name, arg]);
  }

  hold(method) {
    let release;
    const promise = new Promise((r) => { release = r; });
    this.env.state.holds[method] = { promise, release: () => { delete this.env.state.holds[method]; release(); } };
    return this.env.state.holds[method];
  }

  async close() {
    for (const hold of Object.values(this.env.state.holds)) hold.release();
    await this.context.close();
  }

  // Flow steps through the real controls.
  async prepare(text = HANDOFF) {
    await this.openDetails();
    await this.page.evaluate(() => { document.getElementById('manual-import').open = true; });
    await this.page.fill('#manual', text);
    await this.page.click('#prepare');
    await this.openDetails(false);
    await this.page.waitForFunction(() => !document.getElementById('plan-state').textContent.includes('確認中'));
  }

  /** Explicit connection only. A later activation supplies independent deployment consent. */
  async connect(id = 'legacy') {
    const choice = this.page.locator(`#wallet-${id.replace(/[^A-Za-z0-9_-]/g, '_')}`);
    if (!(await choice.isChecked())) await choice.check();
    await this.page.click('#send');
  }

  /** The per-tab remembered plan copy (sessionStorage), read directly. */
  rememberedPlan() {
    return this.page.evaluate((k) => sessionStorage.getItem(k), PLAN_KEY);
  }

  async edit(text) {
    await this.openDetails();
    await this.page.evaluate(() => { document.getElementById('manual-import').open = true; });
    await this.page.fill('#manual', text);
  }

  /** Opens folded diagnostics and recovery. */
  openDetails(open = true) {
    return this.page.evaluate((o) => { document.getElementById('payload-details').open = o; }, open);
  }

  /** One individual step control (connect / switch / inspect) from the technical details, as a recovery path. */
  async step(id) {
    await this.openDetails();
    await this.page.click('#' + id);
    await this.openDetails(false);
  }

  /** A ready review without a send: import, choose the wallet, then the individual connect and inspect recovery
   *  controls (technical details). The single action would continue into the send, so review-state fixtures stop
   *  here and activate it separately. */
  async toReady() {
    await this.prepare();
    await this.waitPhase('disconnected');
    await this.connect();
    await this.waitPhase('connected');
    await this.step('inspect');
    await this.waitPhase('ready');
  }

  /**
   * Seeds one historical v1 attempt (frozen ceilings, user cap 1 POL) built from the same plan, whose wallet
   * transaction carried `override`, into the authoritative native row (another writer, bypassing the store), mines
   * `mine` blocks and reloads: v1 records can no longer be created, only resumed read-only.
   */
  async seedLegacy({ override = null, submit = true, mine = 0, revert = false, mutate = (r) => r } = {}) {
    const model = await import('../model.js');
    const plan = model.buildPlan(model.parseHandoff(HANDOFF));
    const legacy = legacyAttempt(this.chain, plan, { from: ACCOUNT, override, submit });
    const raw = JSON.stringify(mutate(legacy.record));
    for (let i = 0; i < mine; i++) this.chain.mine({ revert: revert && i === 0 });
    await this.prepare();
    await this.page.evaluate(([value, address]) => new Promise((resolve, reject) => {
      const request = indexedDB.open('p256.registration.attempts');
      request.onsuccess = () => {
        const tx = request.result.transaction('state', 'readwrite');
        tx.objectStore('state').put({ version: 1, revision: 3, raw: value, legacyRaw: null }, 'signer:' + address.toLowerCase());
        tx.oncomplete = () => { request.result.close(); resolve(); };
        tx.onabort = () => reject(new Error('seed aborted'));
      };
      request.onerror = () => reject(new Error('seed open failed'));
    }), [raw, ROW.address]);
    await this.reload();
    return { ...legacy, raw };
  }

  async send() {
    await this.page.click('#send');
  }

  async refresh() {
    // Pending/success monitor automatically; exercise the retained diagnostic read without exposing a send.
    await this.page.evaluate(() => document.getElementById('refresh').click());
    await this.page.waitForFunction(() => !document.getElementById('refresh').disabled);
  }

  /** The user's path: import, choose the wallet, one activation of ウォレットで配備 up to the sent transaction. */
  async toPending() {
    await this.prepare();
    await this.waitPhase('disconnected');
    await this.connect();
    await this.waitPhase('connected');
    await this.send();
    await this.waitPhase('txPending');
  }

  async toSuccess() {
    await this.toPending();
    this.chain.mine();
    this.chain.mine();
    await this.refresh();
    await this.waitPhase('success');
  }
}

// -------------------------------------------------------------------------------------------------
// Scenarios: one per fixture; each returns state-level checks and the element expectations.

const S = {};
const ok = (checks, condition, name) => { checks[name] = condition ? 'pass' : 'fail'; };
const visible = (page, sel) => page.isVisible(sel);
const focusedId = (page) => page.evaluate(() => document.activeElement && document.activeElement.id);
/** Settlement dt/dd pairs as rendered (term -> value text). */
const attemptEntries = (page) => page.$$eval('#attempt-list > dt', (dts) => Object.fromEntries(dts.map((dt) =>
  [dt.textContent, dt.nextElementSibling ? dt.nextElementSibling.textContent : ''])));
/** App fee language that must never appear in a new (v2) review, pending or settlement path. */
const FEE_WORDS = ['gwei', 'ガス代', '手数料', '支払上限', '上限', 'gas', 'nonce'];
const feeFree = (text) => !FEE_WORDS.some((word) => text.toLowerCase().includes(word.toLowerCase()));
/** Settlement text including the folded v1-only technical rows (fee words must be absent from both for v2). */
const settlementText = async (page) => (await page.textContent('#attempt')) + (await page.textContent('#attempt-context')) + (await page.textContent('#attempt-technical'));
const settlementRows = async (page) => (await page.textContent('#attempt-list')) + (await page.textContent('#attempt-technical-list'));
/** Retired fee anatomy: absent from the DOM, not merely hidden. */
const noFeeAnatomy = (page) => page.evaluate(() => ['cap', 'cap-form', 'cap-error', 'cap-help', 'consent',
  'override-warning'].every((id) => document.getElementById(id) === null)
  && document.querySelector('label.consent, input[type=checkbox]') === null);
const EXACT_REQUEST_KEYS = '["chainId","data","from","to","value"]';

S.W01 = async (s) => {
  await s.open();
  const c = {};
  ok(c, (await s.phase()) === 'empty', 'empty');
  ok(c, await s.page.isDisabled('#connect'), 'wallet-disabled');
  ok(c, await s.page.isDisabled('#inspect'), 'inspect-disabled');
  ok(c, await s.page.isDisabled('#send') && (await s.page.textContent('#send')) === 'ウォレットを接続', 'action-disabled');
  ok(c, s.chain.calls.length === 0 && s.wallet().requests.length === 0, 'no-rpc-or-wallet-on-load');
  return { c, phases: ['empty'], show: ['#payload-summary', '#plan-empty'], hide: ['#plan', '#review'] };
};

async function fragmentCase(s, fragment, expectPhase, focus) {
  await s.open({ fragment });
  const c = {};
  await s.waitPhase(expectPhase);
  const nav = await s.page.evaluate(() => ({ hash: location.hash, length: history.length, initial: window.__initialHistory,
    marker: window.__documentMarker, navigations: performance.getEntriesByType('navigation').length, href: location.href }));
  ok(c, nav.hash === '' && nav.length === nav.initial && nav.marker === true && nav.navigations === 1
    && nav.href === ORIGIN_PLACEHOLDER, 'fragment-removed-without-navigation');
  ok(c, (await focusedId(s.page)) === focus, `focus-${focus}`);
  ok(c, s.sends === 0, 'zero-send');
  return c;
}
const ORIGIN_PLACEHOLDER = ORIGIN + '/';
S['W02.valid-fragment'] = async (s) => {
  const c = await fragmentCase(s, '#registration=' + Buffer.from(HANDOFF).toString('base64url'), 'disconnected',
    'plan-heading');
  ok(c, (await s.page.textContent('#plan-address')) === ROW.address, 'selected-row-address');
  ok(c, (await s.page.textContent('#plan-salt')) === ROW.salt, 'selected-row-salt');
  ok(c, s.wallet().requests.length === 0, 'no-connect');
  // A reload (fragment already removed) restores the same validated plan from this tab's copy: no wallet request,
  // no chain read, no send, and the wallet choice is explicit again.
  const canonical = (text) => JSON.stringify(Object.entries(JSON.parse(text)).sort());
  ok(c, canonical(await s.rememberedPlan()) === canonical(HANDOFF), 'validated-plan-remembered');
  const reads = s.chain.calls.length;
  await s.reload();
  await s.waitPhase('disconnected');
  ok(c, (await s.page.textContent('#plan-address')) === ROW.address && (await s.page.evaluate(() => location.hash)) === '',
    'plan-restored-after-reload');
  ok(c, (await s.page.$$('#wallet-choices input:checked')).length === 0 && await s.page.isDisabled('#send'),
    'restore-needs-explicit-wallet-choice');
  ok(c, s.wallet().requests.length === 0 && s.chain.calls.length > reads && s.chain.writes === 0 && s.sends === 0, 'restore-public-read-only-no-wallet');
  return { c, phases: ['disconnected'], show: ['#plan', '#plan-address'], hide: ['#input-error'] };
};
S['W02.invalid-fragment'] = async (s) => {
  const c = await fragmentCase(s, '#registration=' + Buffer.from('{"version":2}').toString('base64url') + '%%',
    'inputError', 'input-error');
  ok(c, !(await s.page.textContent('#input-error')).includes('version'), 'non-echoing');
  return { c, phases: ['inputError'], show: ['#input-error'], hide: ['#plan'] };
};
for (const [variant, text, code] of [['malformed', '{"version":1,', 'json'],
  ['oversize', '{"a":"' + 'x'.repeat(5000) + '"}', 'oversize'], ['wrong-binding', OTHER_BINDING, 'binding']]) {
  S[`W03.${variant}`] = async (s) => {
    await s.open();
    await s.prepare(text);
    await s.waitPhase('inputError');
    const c = {};
    ok(c, (await focusedId(s.page)) === 'input-error', 'focus-error');
    if (code === 'oversize') ok(c, (await s.page.inputValue('#manual')) === '', 'oversize-cleared');
    ok(c, await s.page.isDisabled('#connect'), 'review-inactive');
    ok(c, (await s.rememberedPlan()) === null, 'failed-confirmation-leaves-no-copy');
    // The same bytes planted as the tab's copy are refused at the same boundary on reload: nothing is restored.
    await s.page.evaluate(([k, t]) => sessionStorage.setItem(k, t), [PLAN_KEY, text]);
    await s.reload();
    await s.waitPhase('empty');
    ok(c, (await s.rememberedPlan()) === null && !(await visible(s.page, '#plan')), 'broken-copy-rejected-and-dropped');
    await s.edit( HANDOFF);
    ok(c, (await s.phase()) === 'empty', 'edit-invalidates');
    await s.edit( text);
    ok(c, s.sends === 0, 'zero-send');
    await s.page.click('#prepare');
    await s.waitPhase('inputError');
    await s.openDetails(false);
    return { c, phases: ['inputError'], show: ['#input-error'], hide: ['#plan'] };
  };
}
S['W04.no-wallet'] = async (s) => {
  s.options.legacy = false;
  s.options.server = 'noId';
  await s.open();
  await s.prepare();
  await s.waitPhase('disconnected');
  const c = {};
  ok(c, await visible(s.page, '#wallet-error') && (await s.page.textContent('#wallet-error')).includes('ウォレット拡張機能またはWalletConnectの設定'), 'install-instruction');
  ok(c, await s.page.isDisabled('#send') && s.sends === 0, 'no-wallet-no-send');
  ok(c, (await s.page.$$('#wallet-choices input:not([value="walletconnect"])')).length === 0, 'no-injected-choices');
  return { c, phases: ['disconnected'], show: ['#wallet-error'], hide: ['#no-wallet'] };
};
S['W04.unselected'] = async (s) => {
  s.options.announce = [{ uuid: 'wallet-a', name: 'Alpha Wallet' }, { uuid: 'wallet-b', name: 'Beta Wallet' }];
  await s.open();
  await s.prepare();
  await s.waitPhase('disconnected');
  const c = {};
  ok(c, (await s.page.$$('#wallet-choices input:checked')).length === 0, 'no-implicit-choice');
  ok(c, await s.page.isDisabled('#connect') && await s.page.isDisabled('#send'), 'connect-needs-selection');
  ok(c, await visible(s.page, '#wallet-fieldset'), 'next-step-choose-wallet');
  ok(c, Object.values(s.wallets).every((w) => w.requests.length === 0), 'no-account-request');
  return { c, phases: ['disconnected'], show: ['#wallet-choices'], hide: ['#no-wallet'] };
};
S['W04.legacy'] = async (s) => {
  await s.open();
  await s.prepare();
  await s.waitPhase('disconnected');
  const c = {};
  ok(c, (await s.page.textContent('#wallet-choices')).includes('Injected wallet (legacy)'), 'legacy-choice');
  if (!(await s.page.isChecked('#wallet-legacy'))) await s.page.check('#wallet-legacy');
  ok(c, s.wallet().requests.length === 0, 'choice-alone-requests-nothing');
  await s.step('connect');
  await s.waitPhase('connected');
  ok(c, s.wallet().requests[0].method === 'eth_requestAccounts', 'connect-requests-accounts-only-on-click');
  ok(c, (await s.page.getAttribute('#send', 'data-stage')) === 'inspect', 'single-action-continues-from-here');
  ok(c, s.sends === 0, 'zero-send');
  return { c, phases: ['connected'], show: ['#wallet-status'], hide: [] };
};
S['W04.multiple'] = async (s) => {
  s.options.announce = [{ uuid: 'wallet-a', name: 'Alpha <b>Wallet</b>' }, { uuid: 'wallet-a', name: 'Alpha again' },
    { uuid: 'wallet-b', name: 'Beta Wallet' }, { uuid: 'wallet-l', name: 'Legacy announced', sameAsLegacy: true }];
  await s.open();
  await s.prepare();
  await s.waitPhase('disconnected');
  const c = {};
  const names = await s.page.$$eval('#wallet-choices label', (els) => els.map((e) => e.textContent));
  ok(c, names.length === 4 && names.filter((n) => n.startsWith('Alpha')).length === 1, 'deduplicated');
  ok(c, !names.some((n) => n.includes('Injected wallet (legacy)')), 'legacy-identity-dedup');
  ok(c, (await s.page.$$('#wallet-choices img, #wallet-choices svg, #wallet-choices b')).length === 0, 'plain-text-names');
  return { c, phases: ['disconnected'], show: ['#wallet-choices'], hide: [] };
};
for (const [variant, options] of [['missing-id', { server: 'noId' }], ['wrong-origin', { origin: 'local' }]]) {
  S[`W05.${variant}`] = async (s) => {
    Object.assign(s.options, options);
    await s.open();
    await s.prepare();
    await s.waitPhase('disconnected');
    const c = {};
    ok(c, await s.page.isDisabled('#wallet-walletconnect'), 'wc-disabled');
    ok(c, (await s.page.textContent('#wallet-choices')).includes('WalletConnect設定未準備'), 'wc-not-ready-text');
    if (!(await s.page.isChecked('#wallet-legacy'))) await s.page.check('#wallet-legacy');
    await s.step('connect');
    await s.waitPhase('connected');
    ok(c, !s.wcChunk && s.relayFrames.length === 0, 'no-wc-chunk-or-relay');
    ok(c, s.sends === 0, 'zero-send');
    return { c, phases: ['connected'], show: ['#wallet-status'], hide: ['#pairing'] };
  };
}
S['W06.injected'] = async (s) => {
  await s.open();
  s.wallet().behavior.connect = 'hang';
  await s.prepare();
  await s.waitPhase('disconnected');
  await s.connect();
  await s.waitPhase('connecting');
  const c = {};
  ok(c, (await s.page.textContent('#connect')) === '接続中…' && await s.page.isDisabled('#connect'), 'busy-connect');
  ok(c, (await s.page.textContent('#send')) === '接続中…' && await s.page.isDisabled('#send')
    && (await s.page.getAttribute('#send', 'aria-busy')) === 'true', 'busy-action');
  ok(c, (await s.page.getAttribute('#wallet-status', 'aria-busy')) === 'true', 'aria-busy');
  ok(c, s.sends === 0, 'zero-send');
  return { c, phases: ['connecting'], show: ['#wallet-status'], hide: ['#review'] };
};
async function toPairing(s) {
  await s.open();
  await s.prepare();
  await s.waitPhase('disconnected');
  await s.connect('walletconnect');
  await s.page.waitForSelector('#pairing:not([hidden])', { timeout: 15000 });
  await s.page.waitForFunction(() => {
    const canvas = document.getElementById('pairing-qr');
    return canvas.getContext('2d').getImageData(128, 128, 1, 1).data[3] > 0;
  }, null, { timeout: 5000 }).catch(() => {});
}
S['W06.walletconnect'] = async (s) => {
  await toPairing(s);
  const c = {};
  ok(c, s.wcChunk, 'wc-lazy-chunk-loaded-after-explicit-connect');
  ok(c, (await s.page.inputValue('#pairing-uri')).startsWith('wc:'), 'pairing-uri');
  ok(c, await s.page.evaluate(() => document.getElementById('pairing-qr').getContext('2d')
    .getImageData(0, 0, 256, 256).data.some((v, i) => i % 4 === 0 && v < 128)), 'local-qr-drawn');
  ok(c, (await s.page.$$('w3m-modal, appkit-modal, iframe')).length === 0, 'no-appkit-modal');
  ok(c, s.sends === 0, 'zero-send');
  return { c, phases: ['connecting'], show: ['#pairing', '#pairing-qr', '#cancel-pairing'], hide: [] };
};
S['W07.cancelled'] = async (s) => {
  await toPairing(s);
  await s.page.click('#cancel-pairing');
  await s.waitPhase('disconnected');
  const c = {};
  ok(c, (await focusedId(s.page)) === 'send', 'focus-action');
  ok(c, !(await visible(s.page, '#pairing')), 'pairing-closed');
  ok(c, (await s.page.textContent('#wallet-error')).includes('中止'), 'honest-status');
  return { c, phases: ['disconnected'], show: ['#wallet-error'], hide: ['#pairing', '#review'] };
};
for (const [variant, mode, text] of [['rejected', 'reject', '拒否'], ['unavailable', 'unavailable', '接続できません']]) {
  S[`W07.${variant}`] = async (s) => {
    await s.open();
    s.wallet().behavior.connect = mode;
    await s.prepare();
    await s.waitPhase('disconnected');
    await s.connect();
    await s.page.waitForSelector('#wallet-error:not([hidden])');
    const c = {};
    ok(c, (await s.page.textContent('#wallet-error')).includes(text), 'error-text');
    ok(c, (await focusedId(s.page)) === 'send', 'focus-restored');
    ok(c, (await s.page.getAttribute('#send', 'data-stage')) === 'connect', 'retry-is-connect-not-send');
    ok(c, s.sends === 0, 'zero-send');
    return { c, phases: ['disconnected'], show: ['#wallet-error'], hide: ['#review'] };
  };
}
S.W08 = async (s) => {
  // Connected without a review: the individual connect control (technical details) does not continue.
  await s.open();
  await s.prepare();
  await s.waitPhase('disconnected');
  if (!(await s.page.isChecked('#wallet-legacy'))) await s.page.check('#wallet-legacy');
  await s.step('connect');
  await s.waitPhase('connected');
  const c = {};
  ok(c, (await s.page.textContent('#wallet-status')).includes(ACCOUNT), 'full-account');
  ok(c, await s.page.isEnabled('#inspect'), 'inspect-enabled');
  ok(c, (await s.page.getAttribute('#send', 'data-stage')) === 'inspect' && await s.page.isEnabled('#send'),
    'next-stage-inspect');
  ok(c, (await s.page.textContent('#send')) === '配備する', 'next-step-text');
  ok(c, s.sends === 0, 'zero-send');
  return { c, phases: ['connected'], show: ['#wallet-status', '#send'], hide: ['#switch', '#review'] };
};
for (const [variant, chain, mode, text] of [['wrong-chain', '0x1', null, 'chain 1'],
  ['switch-rejected', '0x1', 'reject', '手動で'], ['unknown-chain', '0xdead', '4902', '自動切替に対応していません']]) {
  S[`W09.${variant}`] = async (s) => {
    await s.open();
    s.wallet().chainId = chain;
    await s.prepare();
    await s.waitPhase('disconnected');
    const c = {};
    if (mode) {
      // One activation: connect, then the explicit 0x89 switch, which the wallet rejects; nothing continues.
      s.wallet().behavior.switch = mode;
      await s.connect();
      await s.waitPhase('wrongChain');
      await s.send();
      await s.page.waitForSelector('#wallet-error:not([hidden])');
      ok(c, (await s.page.textContent('#wallet-error')).includes(text), 'manual-switch-instruction');
      ok(c, (await s.page.getAttribute('#send', 'data-stage')) === 'switch', 'retry-is-switch-not-send');
      ok(c, !(await visible(s.page, '#review')), 'no-inspection-off-polygon');
    } else {
      // The individual connect control alone never switches: the wrong-network state stands until the action.
      if (!(await s.page.isChecked('#wallet-legacy'))) await s.page.check('#wallet-legacy');
      await s.step('connect');
      await s.waitPhase('wrongChain');
      ok(c, (await s.page.textContent('#wallet-status')).includes(text), 'wrong-network-text');
      ok(c, (await s.page.getAttribute('#send', 'data-stage')) === 'switch', 'next-stage-switch');
    }
    ok(c, await s.page.isDisabled('#inspect'), 'inspect-disabled');
    const switches = s.wallet().requests.filter((r) => r.method.startsWith('wallet_'));
    ok(c, switches.every((r) => r.method === 'wallet_switchEthereumChain' && r.params[0].chainId === '0x89'),
      'switch-0x89-only');
    ok(c, s.sends === 0, 'zero-send');
    ok(c, !(await visible(s.page, '#switch')), 'no-separate-switch-button');
    return { c, phases: ['wrongChain'], show: ['#send', '#wallet-status'], hide: ['#review'] };
  };
}
S.W10 = async (s) => {
  await s.open();
  await s.prepare();
  await s.waitPhase('disconnected');
  s.hold('eth_call');
  await s.connect();
  await s.waitPhase('connected');
  await s.send();
  await s.waitPhase('inspecting');
  const c = {};
  ok(c, (await s.page.getAttribute('#inspect-status', 'aria-busy')) === 'true', 'aria-busy');
  ok(c, (await s.page.textContent('#inspect')) === '照合中…', 'busy-text');
  ok(c, (await s.page.textContent('#send')) === '照合中…' && await s.page.isDisabled('#send'), 'busy-action');
  return { c, phases: ['inspecting'], show: ['#inspect-status'], hide: ['#review'],
    after: async () => {
      // Changed generation suppresses the stale result.
      await s.emit('legacy', 'accountsChanged', [OTHER]);
      s.env.state.holds.eth_call.release();
      await sleep(300);
      c['stale-result-suppressed'] = (await s.phase()) === 'connected' && !(await visible(s.page, '#review'))
        ? 'pass' : 'fail';
    } };
};
for (const [variant, mutate] of [['offline', (ch) => { ch.faults.offline = true; }],
  ['code', (ch) => { ch.faults.factoryCode = true; }], ['prediction', (ch) => { ch.faults.prediction = true; }],
  ['keyset', (ch, plan) => ch.preDeploy(plan, { owner: '0x' + '22'.repeat(20) })],
  ['block', (ch) => { ch.faults.blockFlip = true; }]]) {
  S[`W11.${variant}`] = async (s) => {
    await s.open();
    await s.prepare();
    await s.waitPhase('disconnected');
    mutate(s.chain, { address: ROW.address, keyID: ROW.keyID, x: ROW.x, y: ROW.y });
    await s.connect();
    await s.waitPhase('connected');
    await s.send();
    await s.waitPhase('inspectionError');
    const c = {};
    ok(c, (await focusedId(s.page)) === 'inspect-error', 'focus-error');
    ok(c, await s.page.isEnabled('#inspect'), 'retry-inspection');
    ok(c, (await s.page.getAttribute('#send', 'data-stage')) === 'inspect', 'retry-is-inspect-not-send');
    ok(c, !(await visible(s.page, '#review')) && s.sends === 0, 'no-ready-no-send');
    return { c, phases: ['inspectionError'], show: ['#inspect-error'], hide: ['#review', '#deployed'] };
  };
}
S.W12 = async (s) => {
  await s.open();
  s.chain.preDeploy({ address: ROW.address, keyID: ROW.keyID, x: ROW.x, y: ROW.y });
  await s.prepare();
  await s.waitPhase('disconnected');
  const c = {};
  ok(c, (await s.page.textContent('#plan-state')) === 'すでに配備されています。', 'strict-public-readback');
  ok(c, s.chain.calls.some((call) => call.method === 'eth_call') && s.chain.writes === 0, 'readback-block');
  ok(c, !(await visible(s.page, '#send')) && await noFeeAnatomy(s.page), 'no-fee-no-submit');
  ok(c, s.sends === 0 && s.wallet().requests.length === 0, 'no-wallet-needed-for-deployed');
  return { c, phases: ['disconnected'], show: ['#plan-state', '#copy-address'], hide: ['#review', '#send'] };
};
S.W13 = async (s) => {
  await s.open();
  await s.toReady();
  const c = {};
  const review = await s.page.textContent('#review-list');
  for (const field of ['Polygon · 137', ACCOUNT, '0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c', '0 POL', ROW.address,
    '照合ブロック']) {
    ok(c, review.includes(field), `review-${field.slice(0, 12)}`);
  }
  // Public key / keyID / salt are shown once, in the folded 技術情報 block bound to the same plan.
  const technical = await s.page.textContent('#plan-technical');
  for (const field of [ROW.publicPoint, ROW.keyID, ROW.salt]) ok(c, technical.includes(field), `review-${field.slice(0, 12)}`);
  ok(c, feeFree(review), 'operation-only-review');
  ok(c, await noFeeAnatomy(s.page), 'no-cap-consent-or-fee-explanation');
  ok(c, await s.page.isEnabled('#send') && (await s.page.textContent('#send')) === '配備する'
    && (await s.page.getAttribute('#send', 'data-stage')) === 'send', 'explicit-wallet-action-enabled');
  ok(c, (await s.page.textContent('#gas-note')).includes('ウォレットで確認'), 'next-step-send');
  ok(c, !(await visible(s.page, '#connect')) && !(await visible(s.page, '#inspect')), 'no-separate-step-buttons');
  ok(c, s.chain.calls.every((call) => !['eth_estimateGas', 'eth_maxPriorityFeePerGas'].includes(call.method)),
    'no-gas-fee-rpc');
  const reviewFocus = await focusedId(s.page);
  ok(c, ['plan-state', 'send'].includes(reviewFocus) && await visible(s.page, '#' + reviewFocus), 'focus-visible-review-or-action');
  ok(c, s.sends === 0, 'zero-send');
  return { c, phases: ['ready'], show: ['#plan', '#send'], hide: ['#deployed'] };
};
S['W14.storage'] = async (s) => {
  await s.open();
  await s.prepare();
  await s.waitPhase('disconnected');
  await s.page.evaluate(() => { window.__failWrites = true; });
  await s.connect();
  await s.waitPhase('connected');
  await s.send();
  await s.waitPhase('storageError');
  const c = {};
  ok(c, s.sends === 0, 'zero-send');
  const row = (await storedRow(s.page)).row;
  ok(c, row && row.revision === 0 && row.raw === null, 'aborted-admission-unsaved');
  ok(c, await visible(s.page, '#plan-blocked'), 'storage-alert-visible');
  ok(c, (await focusedId(s.page)) === 'plan-blocked' && (await s.page.getAttribute('#plan-blocked', 'role')) === 'alert', 'focus-main-storage-alert');
  return { c, phases: ['storageError'], show: ['#plan-blocked'], hide: ['#attempt'] };
};
S['W15.blocked'] = async (s) => {
  await s.open();
  await s.toReady();
  await s.step('disconnect');
  await s.waitPhase('disconnected');
  const c = {};
  ok(c, !(await visible(s.page, '#review')) && (await s.page.getAttribute('#send', 'data-stage')) === 'connect',
    'no-review-no-send-stage');
  ok(c, await s.page.isEnabled('#connect'), 'connect-available');
  ok(c, s.sends === 0, 'zero-send');
  return { c, phases: ['disconnected'], show: ['#send'], hide: ['#review', '#attempt'] };
};
S['W15.ready'] = async (s) => {
  await s.open();
  await s.toReady();
  const c = {};
  ok(c, await s.page.isEnabled('#send'), 'action-enabled');
  ok(c, await noFeeAnatomy(s.page), 'no-checkbox-or-cap');
  ok(c, (await storedRow(s.page)).row.raw === null, 'storage-ready-no-attempt');
  ok(c, s.sends === 0, 'explicit-send-only');
  return { c, phases: ['ready'], show: ['#send'], hide: ['#attempt'] };
};
for (const [variant, act, phase] of [
  ['account', (s) => s.emit('legacy', 'accountsChanged', [OTHER]), 'connected'],
  ['chain', (s) => s.emit('legacy', 'chainChanged', '0x1'), 'wrongChain'],
  ['input', (s) => s.edit( HANDOFF + ' '), 'empty'],
  ['disconnect', (s) => s.emit('legacy', 'disconnect', {}), 'disconnected'],
  ['provider', async (s) => {
    // Connected wallets hide the selector. Use the explicit disconnect recovery before choosing another provider.
    await s.step('disconnect');
    await s.waitPhase('disconnected');
    await s.page.check('#wallet-eip6963_wallet-b');
  }, 'disconnected']]) {
  S[`W16.${variant}`] = async (s) => {
    if (variant === 'provider') s.options.announce = [{ uuid: 'wallet-b', name: 'Beta Wallet' }];
    await s.open();
    await s.toReady();
    await act(s);
    await s.waitPhase(phase);
    const c = {};
    ok(c, !(await visible(s.page, '#review')), 'review-removed');
    // The single action never keeps a send stage across drift: it falls back to a fresh (read-only) step or nothing.
    ok(c, (await s.page.getAttribute('#send', 'data-stage')) !== 'send', 'ready-invalidated');
    ok(c, s.sends === 0, 'zero-send');
    return { c, phases: [phase], show: [], hide: ['#attempt', '#review'] };
  };
}
for (const [variant, act] of [['normal', null], ['account-changed', (s) => s.emit('legacy', 'accountsChanged', [OTHER])],
  ['chain-changed', (s) => s.emit('legacy', 'chainChanged', '0x1')], ['input-changed', (s) => s.edit( '{}')]]) {
  S[`W17.${variant}`] = async (s) => {
    await s.open();
    await s.toReady();
    s.wallet().behavior.send = 'deferred';
    await s.send();
    await s.page.evaluate(() => document.getElementById('send').click());
    await s.waitPhase('walletPending');
    const pendingRaw = await storedRaw(s.page);
    if (act) await act(s);
    await sleep(150);
    const c = {};
    ok(c, (await s.phase()) === 'walletPending', 'attempt-retained');
    ok(c, s.sends === 1, 'one-request');
    const pending = JSON.parse(pendingRaw);
    ok(c, (await storedRaw(s.page)) === pendingRaw && pending.address === ROW.address && pending.from === ACCOUNT,
      'pending-bytes-and-identity-retained');
    ok(c, (await s.page.getAttribute('#attempt-status', 'aria-busy')) === 'true', 'busy');
    ok(c, feeFree(await settlementText(s.page)), 'no-fee-summary');
    if (variant === 'input-changed') {
      ok(c, await visible(s.page, '#attempt-context') && (await s.page.textContent('#attempt-detail-list')).includes(ROW.address),
        'foreign-attempt-accessible-in-details');
    }
    return { c, phases: ['walletPending'], show: [variant === 'input-changed' ? '#attempt-context' : '#attempt'],
      hide: variant === 'input-changed' ? ['#attempt'] : [],
      after: async () => {
        s.wallet().releaseSend();
        await s.waitPhase('txPending');
        const settled = JSON.parse(await storedRaw(s.page));
        c['late-hash-follows-original'] = settled.id === pending.id && settled.address === pending.address
          && settled.from === pending.from && Boolean(settled.hash) && s.sends === 1 ? 'pass' : 'fail';
      } };
  };
}
S['W18.hash'] = async (s) => {
  await s.open();
  await s.toPending();
  const c = {};
  const list = await s.page.textContent('#attempt-list');
  ok(c, list.includes(ROW.address) && list.includes(ACCOUNT) && /0x[0-9a-f]{64}/.test(list), 'frozen-details');
  ok(c, feeFree(await settlementText(s.page)), 'no-fee-details');
  ok(c, (await focusedId(s.page)) === 'attempt-status', 'focus-settlement');
  await s.refresh();
  ok(c, s.sends === 1 && s.chain.writes === 1, 'refresh-read-only');
  return { c, phases: ['txPending'], show: ['#attempt'], hide: ['#clear'] };
};
S['W18.poll-timeout'] = async (s) => {
  s.options.clock = true;
  await s.open();
  await s.toPending();
  // Each fake 12 s step must not overlap an in-flight poll: the page's 10 s RPC abort timer runs on the same
  // fake clock, so wait for the poll's last read (the receipt) before advancing again.
  const receipts = () => s.chain.calls.filter((call) => call.method === 'eth_getTransactionReceipt').length;
  for (let i = 0; i < 160; i++) {
    if ((await s.page.textContent('#attempt-context-text')).includes('自動確認')) break;
    const before = receipts();
    await s.page.clock.runFor(12_000);
    for (let w = 0; w < 100 && receipts() === before; w++) await sleep(20);
    await sleep(200); // lets the receipt response reach the page before the next fake step
  }
  await s.page.waitForFunction(() => document.getElementById('attempt-context-text').textContent.includes('自動確認'),
    null, { timeout: 8000 });
  const c = {};
  ok(c, s.sends === 1, 'zero-further-sends');
  ok(c, await s.page.isEnabled('#refresh'), 'explicit-refresh');
  return { c, phases: ['txPending'], show: ['#refresh'], hide: [] };
};
S['W18.wallet-switched'] = async (s) => {
  await s.open();
  await s.toPending();
  await s.emit('legacy', 'chainChanged', '0x1');
  s.chain.mine();
  await s.refresh();
  const c = {};
  ok(c, (await s.phase()) === 'txPending', 'monitoring-independent-of-wallet-chain');
  ok(c, s.sends === 1, 'no-resubmit');
  // One confirmation proves current deployment, not final settlement. Keep that distinction visible in details.
  await s.page.waitForFunction(() => document.getElementById('plan-state').textContent === 'すでに配備されています。');
  await s.openDetails();
  const status = await s.page.textContent('#attempt-context-text');
  ok(c, status.includes('確定待ち') && status.includes('確認ブロック 1/2'), 'pending-not-promoted-to-success');
  const [pendingHash] = s.chain.txs.keys();
  ok(c, Boolean(pendingHash) && (await s.page.textContent('#attempt-detail-list')).includes(pendingHash), 'retained-pending-hash');
  ok(c, s.chain.writes === 1, 'refresh-read-only');
  await s.openDetails(false);
  ok(c, !(await visible(s.page, '#send')), 'deployed-normal-no-send');
  await s.openDetails();
  ok(c, await visible(s.page, '#attempt-context'), 'folded-pending-status-remains');
  return { c, phases: ['txPending'], show: ['#plan-state', '#attempt-context'], hide: ['#attempt', '#send', '#clear'] };
};
S.W19 = async (s) => {
  await s.open();
  await s.toSuccess();
  const c = {};
  const list = await s.page.textContent('#attempt-list');
  ok(c, list.includes('配備済み') && list.includes('受領ブロック') && /0x[0-9a-f]{64}/.test(list), 'operation-hash-block-status');
  ok(c, feeFree(await settlementText(s.page)), 'no-gas-cost-rows');
  ok(c, await visible(s.page, '#copy-address') && !(await visible(s.page, '#send')), 'success-copy-no-resend');
  ok(c, s.sends === 1, 'no-auto-send');
  const tx = s.wallet().sends[0];
  const decoded = oracle.decodeDeploy(tx.data, PROXY);
  ok(c, decoded.exact && decoded.salt === ROW.salt && decoded.keyID === ROW.keyID
    && oracle.derive(ROW.publicPoint, ROW.salt, PROXY).calldata === tx.data, 'captured-send-decodes-to-selected-row');
  ok(c, JSON.stringify(Object.keys(tx).sort()) === EXACT_REQUEST_KEYS, 'identity-only-request');
  return { c, phases: ['success'], show: ['#copy-address'], hide: ['#hash-form', '#clear'] };
};
const HIGHFEE = { maxFeePerGas: '0x' + (500n * GWEI).toString(16), maxPriorityFeePerGas: '0x' + (60n * GWEI).toString(16) };
const LOWFEE = { maxFeePerGas: '0x' + (31n * GWEI).toString(16), maxPriorityFeePerGas: '0x1' };
const BIGGAS = '0x' + (900000n).toString(16);
const W20 = {
  reverted: { revert: true, phase: 'failed', text: 'status 0' },
  rejected: { send: 'reject', phase: 'rejected', text: '拒否' },
  'identity-mismatch': { override: { data: '0x4af63f02' + '00'.repeat(64) }, phase: 'unknown', text: '一致しません' },
  'readback-mismatch': { faults: { deployWrongKey: true }, phase: 'unknown', text: '配備内容' },
  'nonce-overridden': { override: { nonce: '0x5' }, phase: 'success', text: '配備を確認' },
  // v2: wallet-selected fees/gas are the wallet's authority and never a walletOverride.
  'wallet-fee-higher': { override: HIGHFEE, phase: 'success', text: '配備を確認' },
  'wallet-fee-lower-reverted': { override: LOWFEE, revert: true, phase: 'failed', text: 'status 0' },
  'wallet-fee-higher-readback-unknown': { override: HIGHFEE, readbackUnavailable: true, phase: 'unknown', text: '読取りRPC' },
  'wallet-legacy-gasprice': { feeMode: 'legacy', phase: 'success', text: '配備を確認' },
  'wallet-gas-higher': { override: { gas: BIGGAS }, phase: 'success', text: '配備を確認' },
  'wallet-gas-lower-reverted': { override: { gas: '0x61a80' }, revert: true, phase: 'failed', text: 'status 0' },
  'wallet-gas-higher-readback-unknown': { override: { gas: BIGGAS }, readbackUnavailable: true, phase: 'unknown',
    text: '読取りRPC' },
  cancelled: { replace: 'cancel', phase: 'failed', text: '同じnonce' },
  'unrelated-replacement': { replace: 'unrelated', phase: 'failed', text: '同じnonce' },
};
for (const [variant, spec] of Object.entries(W20)) {
  S[`W20.${variant}`] = async (s) => {
    await s.open();
    await s.toReady();
    Object.assign(s.chain.faults, spec.faults || {});
    s.wallet().override = spec.override || null;
    if (spec.feeMode) s.wallet().feeMode = spec.feeMode;
    if (spec.send) s.wallet().behavior.send = spec.send;
    await s.send();
    await s.waitPhase(spec.send ? 'rejected' : 'txPending');
    let consumingHash = null;
    if (!spec.send) {
      await s.refresh();
      if (spec.replace) {
        const original = s.chain.mempool.pop();
        s.chain.txs.delete(original.hash);
        consumingHash = s.chain.submit(spec.replace === 'cancel'
          ? { from: original.from, to: original.from, data: '0x', value: '0x0', nonce: original.nonce, gas: '0x5208',
            maxFeePerGas: original.maxFeePerGas, maxPriorityFeePerGas: original.maxPriorityFeePerGas }
          : { from: original.from, to: '0x' + '44'.repeat(20), data: '0xa9059cbb', value: '0x0', nonce: original.nonce,
            gas: '0x10000', maxFeePerGas: original.maxFeePerGas, maxPriorityFeePerGas: original.maxPriorityFeePerGas });
      }
      s.chain.mine({ revert: spec.revert });
      s.chain.mine();
      if (spec.readbackUnavailable) s.chain.faults.readbackUnavailable = true;
      await s.refresh();
      await s.waitPhase(spec.phase);
    }
    const c = {};
    ok(c, (await s.page.textContent('#attempt-context-text')).includes(spec.text), 'state-text');
    ok(c, !(await s.page.textContent('#attempt-context-text')).includes('同意上限'), 'never-wallet-override');
    ok(c, feeFree(await settlementRows(s.page)), 'no-fee-rows');
    const clear = await visible(s.page, '#clear');
    ok(c, clear === ['failed', 'rejected'].includes(spec.phase), 'clear-only-when-resolved');
    if (spec.phase === 'failed' && spec.replace) {
      const entries = await attemptEntries(s.page);
      ok(c, typeof consumingHash === 'string'
        && (entries['消費した取引のハッシュ'] || '').toLowerCase() === consumingHash.toLowerCase(), 'consuming-hash');
    }
    ok(c, JSON.stringify(Object.keys(s.wallet().sends[0]).sort()) === EXACT_REQUEST_KEYS, 'identity-only-request');
    const stored = JSON.parse(await storedRaw(s.page));
    ok(c, stored.version === 2 && stored.state !== 'walletOverride', 'v2-record-no-override');
    ok(c, s.sends === 1 && s.chain.writes === (spec.send ? 0 : spec.replace ? 2 : 1), 'refresh-paths-read-only');
    if (spec.phase === 'unknown') {
      await s.page.waitForFunction(() => document.getElementById('plan-state').textContent !== '配備状態を確認中…');
      const deployed = (await s.page.textContent('#plan-state')) === 'すでに配備されています。';
      if (deployed) {
        // Current deployment and this attempt's transaction identity are independent evidence.
        await s.openDetails();
        ok(c, await visible(s.page, '#attempt-context') && !(await visible(s.page, '#send')), 'unknown-record-retained-folded');
        ok(c, s.sends === 1 && (await s.phase()) === 'unknown', 'unknown-not-promoted');
        return { c, phases: ['unknown'], show: ['#attempt-context'], hide: ['#attempt', '#send'] };
      }
    }
    return { c, phases: [spec.phase], show: ['#attempt'], hide: [] };
  };
}
// Historical v1 records (byte-preserved, frozen ceilings and user cap): original classification and evidence.
const BIGFEE = '0x' + (100n * GWEI).toString(16);
const L20 = {
  'fee-overridden-deployed': { override: { maxFeePerGas: BIGFEE }, phase: 'walletOverride', text: '配備済み' },
  'fee-overridden-not-deployed': { override: { maxFeePerGas: BIGFEE }, revert: true, phase: 'walletOverride', text: '未配備' },
  'fee-overridden-unknown': { override: { maxFeePerGas: BIGFEE }, reorg: true, phase: 'walletOverride', text: '不明' },
  'gas-overridden-within-limits': { override: { gas: '0x61a80' }, phase: 'success', text: '配備を確認', list: '要求と異なる' },
  'gas-overridden-deployed': { override: { gas: BIGGAS }, phase: 'walletOverride', text: '配備済み' },
  'gas-overridden-not-deployed': { override: { gas: BIGGAS }, revert: true, phase: 'walletOverride', text: '未配備' },
  'gas-overridden-unknown': { override: { gas: BIGGAS }, reorg: true, phase: 'walletOverride', text: '不明' },
};
for (const [variant, spec] of Object.entries(L20)) {
  S[`L20.${variant}`] = async (s) => {
    await s.open();
    const legacy = await s.seedLegacy({ override: spec.override, mine: 2, revert: spec.revert });
    await s.waitPhase(spec.phase);
    if (spec.reorg) {
      s.chain.reorg(2);
      await s.refresh();
    }
    await s.page.waitForFunction((t) => document.getElementById('attempt-context-text').textContent.includes(t), spec.text,
      { timeout: 8000 }).catch(() => {});
    const c = {};
    ok(c, (await s.page.textContent('#attempt-context-text')).includes(spec.text), 'state-text');
    const list = await s.page.textContent('#attempt-technical-list');
    ok(c, list.includes('要求 nonce / gas') && list.includes('要求 最大/優先手数料') && list.includes('支払上限'),
      'v1-requested-evidence');
    if (spec.list) ok(c, list.includes(spec.list), 'requested-vs-observed');
    if (spec.phase === 'walletOverride') {
      ok(c, (await s.page.textContent('#attempt-context-text')).includes('ウォレットが同意上限を超えて送信しました'), 'override-warning');
      ok(c, list.includes('実際'), 'observed-values');
    }
    ok(c, !(await visible(s.page, '#clear')), 'clear-only-when-resolved');
    const stored = JSON.parse(await storedRaw(s.page));
    ok(c, stored.version === 1 && stored.capWei === legacy.record.capWei && stored.id === legacy.record.id
      && JSON.stringify(stored.transaction) === JSON.stringify(legacy.record.transaction), 'v1-bytes-authority-retained');
    ok(c, s.sends === 0 && s.chain.writes === 1, 'read-only-resume');
    // Deployment and historical outcome are independent. A compact deployed view keeps history in Details.
    const deployed = (await s.page.textContent('#plan-state')) === 'すでに配備されています。';
    ok(c, !(await s.page.evaluate(() => document.getElementById('payload-details').open)), 'history-folded-by-default');
    await s.openDetails();
    ok(c, await visible(s.page, '#attempt-context') && await visible(s.page, '#attempt-technical'), 'history-accessible-in-details');
    return { c, phases: [spec.phase], show: deployed ? ['#plan-state', '#attempt-context', '#attempt-technical'] : ['#attempt'], hide: [] };
  };
}
S['W21.send-timeout'] = async (s) => {
  s.options.clock = true;
  await s.open();
  await s.toReady();
  s.wallet().behavior.send = 'deferred';
  await s.send();
  await s.waitPhase('walletPending');
  await s.page.clock.runFor(61_000);
  await s.waitPhase('unknown');
  const c = {};
  ok(c, (await s.page.textContent('#attempt-context-text')).includes('60秒'), 'timeout-text');
  ok(c, !(await visible(s.page, '#clear')) && s.sends === 1, 'no-retry-no-clear');
  ok(c, !(await visible(s.page, '#hash-form')), 'hash-form-folded-away-from-the-normal-flow');
  await s.openDetails();
  return { c, phases: ['unknown'], show: ['#hash-form'], hide: ['#clear'] };
};
S['W21.late-hash'] = async (s) => {
  s.options.clock = true;
  await s.open();
  await s.toReady();
  s.wallet().behavior.send = 'deferred';
  await s.send();
  await s.waitPhase('walletPending');
  await s.page.clock.runFor(61_000);
  await s.waitPhase('unknown');
  s.wallet().releaseSend();
  await s.waitPhase('txPending');
  const c = {};
  ok(c, s.sends === 1, 'late-hash-same-attempt');
  return { c, phases: ['txPending'], show: ['#attempt'], hide: ['#hash-form', '#refresh'] };
};
S['W21.rpc'] = async (s) => {
  await s.open();
  await s.toPending();
  s.chain.faults.offline = true;
  await s.refresh();
  await s.waitPhase('unknown');
  const c = {};
  ok(c, (await s.page.textContent('#attempt-context-text')).includes('読取りRPC'), 'rpc-unknown');
  ok(c, s.sends === 1 && !(await visible(s.page, '#clear')), 'locked');
  return { c, phases: ['unknown'], show: ['#attempt'], hide: ['#clear'] };
};
S['W21.reorg'] = async (s) => {
  await s.open();
  await s.toSuccess();
  s.chain.reorg(2);
  await s.refresh();
  await s.waitPhase('txPending');
  const c = {};
  ok(c, (await s.page.textContent('#attempt-context-text')).includes('再編成'), 'reorg-warning');
  ok(c, !(await visible(s.page, '#clear')) && s.sends === 1, 'success-revoked');
  return { c, phases: ['txPending'], show: ['#attempt'], hide: ['#clear'] };
};
S['W21.no-candidate'] = async (s) => {
  await s.open();
  await s.toPending();
  await s.refresh();
  const original = s.chain.mempool.pop();
  s.chain.txs.delete(original.hash);
  s.chain.nonces.set(original.from.toLowerCase(), BigInt(original.nonce) + 1n);
  s.chain.mine();
  await s.refresh();
  await s.waitPhase('unknown');
  const c = {};
  ok(c, (await s.page.textContent('#attempt-context-text')).includes('該当する取引が見つかりません'), 'no-candidate-text');
  ok(c, s.sends === 1, 'no-retry');
  return { c, phases: ['unknown'], show: ['#attempt'], hide: ['#clear'] };
};
async function resume(s, prepare, phase) {
  await s.open();
  await prepare(s);
  await s.context.clearCookies();
  await s.reload();
  await s.waitPhase(phase);
}
S['W22.pending'] = async (s) => {
  await resume(s, (x) => x.toPending(), 'txPending');
  const c = {};
  ok(c, !(await visible(s.page, '#wallet-status')), 'wallet-disconnected');
  ok(c, s.wallet().requests.filter((r) => r.method === 'eth_requestAccounts').length === 1, 'no-auto-reconnect');
  ok(c, (await s.page.textContent('#plan-address')) === ROW.address && await s.page.isDisabled('#send'),
    'plan-restored-attempt-keeps-priority');
  ok(c, s.sends === 1, 'never-resubmitted');
  return { c, phases: ['txPending'], show: ['#attempt', '#plan'], hide: [] };
};
S['W22.unknown'] = async (s) => {
  await resume(s, async (x) => {
    await x.toReady();
    x.wallet().behavior.send = 'deferred';
    await x.send();
    await x.waitPhase('walletPending');
  }, 'unknown');
  const c = {};
  ok(c, !(await visible(s.page, '#hash-form')), 'hash-form-not-in-normal-flow');
  ok(c, (await s.page.textContent('#attempt-context-text')).includes('復元できません'), 'unrecoverable-stated');
  ok(c, await s.page.isDisabled('#send') && (await s.page.getAttribute('#send', 'data-stage')) === '', 'no-stage');
  // 状況を更新 for a hashless record reads only the expected address: honest, read-only, still unknown and locked.
  const reads = s.chain.calls.length;
  await s.refresh();
  ok(c, (await s.page.textContent('#attempt-context-text')).includes('予定アドレスの読取り: 未配備')
    && (await s.page.textContent('#attempt-context-text')).includes('未送信とは限りません'), 'hashless-readback-honest');
  ok(c, (await s.phase()) === 'unknown' && s.chain.calls.length > reads && s.chain.writes === 0, 'readback-only-no-write');
  await s.openDetails();
  ok(c, await visible(s.page, '#hash-form'), 'manual-hash-read-only');
  await s.page.fill('#manual-hash', '0x' + 'ab'.repeat(32));
  await s.page.click('#check-hash');
  await s.page.waitForSelector('#hash-error:not([hidden])');
  ok(c, s.sends === 1 && !(await visible(s.page, '#clear')), 'locked');
  return { c, phases: ['unknown'], show: ['#hash-form', '#hash-error'], hide: ['#clear'] };
};
S['W22.success'] = async (s) => {
  await resume(s, (x) => x.toSuccess(), 'success');
  await s.page.waitForSelector('#copy-address:not([hidden])', { timeout: 8000 });
  const c = {};
  ok(c, s.sends === 1 && await visible(s.page, '#copy-address') && !(await visible(s.page, '#clear')), 'resolved-copy-without-resend');
  return { c, phases: ['success'], show: ['#copy-address'], hide: ['#clear', '#send'] };
};
S['W22.walletOverride'] = async (s) => {
  // Only historical v1 records can carry walletOverride; it reloads locked with its original evidence.
  await s.open();
  await s.seedLegacy({ override: { maxFeePerGas: BIGFEE }, mine: 2 });
  await s.waitPhase('walletOverride');
  await s.page.waitForFunction(() => document.getElementById('attempt-status').textContent.includes('配備済み'));
  const c = {};
  const list = await s.page.textContent('#attempt-technical-list');
  ok(c, list.includes('要求 最大/優先手数料') && list.includes('実際 最大/優先手数料') && list.includes('使用されたnonce')
    && list.includes('支払ったガス代'), 'requested-observed-effective-paid');
  ok(c, !(await visible(s.page, '#clear')) && s.sends === 0, 'locked-no-clear');
  ok(c, !(await visible(s.page, '#attempt-context')) && !(await s.page.evaluate(() => document.getElementById('payload-details').open)),
    'history-folded-by-default');
  await s.openDetails();
  ok(c, await visible(s.page, '#attempt-context') && await visible(s.page, '#attempt-technical')
    && (await s.page.textContent('#attempt-detail-list')).includes(ROW.address), 'history-accessible-in-details');
  return { c, phases: ['walletOverride'], show: ['#plan-state', '#attempt-context', '#attempt-technical'], hide: ['#clear', '#send'] };
};
S['L22.pending'] = async (s) => {
  await s.open();
  await s.seedLegacy();
  await s.waitPhase('txPending');
  const c = {};
  const list = await s.page.textContent('#attempt-technical-list');
  ok(c, list.includes('要求 nonce / gas') && list.includes('支払上限'), 'v1-evidence-read-only');
  ok(c, !(await visible(s.page, '#wallet-status')) && s.sends === 0, 'never-resubmitted');
  ok(c, JSON.parse(await storedRaw(s.page)).version === 1, 'not-converted');
  return { c, phases: ['txPending'], show: ['#plan'], hide: ['#clear'] };
};
S['L22.unknown'] = async (s) => {
  await s.open();
  await s.seedLegacy({ submit: false });
  await s.waitPhase('unknown');
  const c = {};
  // The manual hash form is recovery only (closed technical details), never a step of the normal flow.
  ok(c, !(await visible(s.page, '#hash-form')), 'hash-form-not-in-normal-flow');
  await s.openDetails();
  ok(c, await visible(s.page, '#hash-form'), 'manual-hash-read-only');
  ok(c, (await s.page.textContent('#attempt-technical-list')).includes('支払上限'), 'v1-evidence-read-only');
  ok(c, s.sends === 0 && !(await visible(s.page, '#clear')), 'locked');
  return { c, phases: ['unknown'], show: ['#hash-form'], hide: ['#clear'] };
};
S['L22.success'] = async (s) => {
  await s.open();
  await s.seedLegacy({ mine: 2 });
  await s.waitPhase('success');
  await s.page.waitForSelector('#copy-address:not([hidden])', { timeout: 8000 });
  const c = {};
  const list = await s.page.textContent('#attempt-technical-list');
  ok(c, list.includes('支払ったガス代') && list.includes('要求 最大/優先手数料'), 'v1-paid-and-requested-evidence');
  ok(c, s.sends === 0 && await visible(s.page, '#copy-address') && !(await visible(s.page, '#clear')), 'resolved-copy-without-resend');
  return { c, phases: ['success'], show: ['#copy-address'], hide: ['#clear', '#send'] };
};
S['L22.tampered'] = async (s) => {
  await s.open();
  // A v1 record whose cap was lowered below its frozen gas*maxFee product: tamper error, bytes kept.
  const legacy = await s.seedLegacy({ mutate: (r) => ({ ...r, capWei: '0x1' }) });
  await s.waitPhase('resumeError');
  const c = {};
  ok(c, (await s.page.textContent('#resume-error')) === '保存情報を検証できません', 'tamper-alert');
  ok(c, (await storedRaw(s.page)) === legacy.raw, 'not-deleted');
  ok(c, s.sends === 0, 'zero-submit');
  return { c, phases: ['resumeError'], show: ['#plan-blocked'], hide: ['#clear'] };
};
S['W22.tampered'] = async (s) => {
  const tampered = JSON.stringify({ version: 1, id: 'x', state: 'success' });
  await s.open();
  await s.prepare();
  // Another writer leaves unverifiable bytes in the authoritative row (bypassing the store), then the page reloads.
  await s.page.evaluate(([raw, address]) => new Promise((resolve, reject) => {
    const request = indexedDB.open('p256.registration.attempts');
    request.onsuccess = () => {
      const tx = request.result.transaction('state', 'readwrite');
      tx.objectStore('state').put({ version: 1, revision: 7, raw, legacyRaw: null }, 'signer:' + address.toLowerCase());
      tx.oncomplete = () => { request.result.close(); resolve(); };
      tx.onabort = () => reject(new Error('seed aborted'));
    };
    request.onerror = () => reject(new Error('seed open failed'));
  }), [tampered, ROW.address]);
  await s.reload();
  await s.waitPhase('resumeError');
  const c = {};
  ok(c, (await s.page.textContent('#resume-error')) === '保存情報を検証できません', 'tamper-alert');
  ok(c, (await storedRaw(s.page)) === tampered, 'not-deleted');
  await s.prepare();
  ok(c, (await s.phase()) === 'resumeError' && s.sends === 0, 'zero-submit');
  return { c, phases: ['resumeError'], show: ['#plan-blocked'], hide: ['#clear'] };
};
S['W22.storage-unavailable'] = async (s) => {
  await s.open({ storageUnavailable: true });
  await s.waitPhase('storageError');
  const c = {};
  ok(c, (await s.page.textContent('#storage-error')).includes('保存領域'), 'storage-alert');
  ok(c, s.sends === 0, 'zero-submit');
  return { c, phases: ['storageError'], show: ['#payload-summary'], hide: [] };
};
for (const variant of ['closed', 'open']) {
  S[`W23.${variant}`] = async (s) => {
    await s.open();
    await s.prepare();
    await s.waitPhase('disconnected');
    const c = {};
    if (variant === 'open') {
      await s.openDetails(false);
      await s.page.focus('#payload-summary');
      await s.page.keyboard.press('Enter');
      await s.page.waitForFunction(() => document.getElementById('payload-details').open);
      const text = await s.page.textContent('#payload');
      ok(c, text.includes(ROW.salt) && text.includes(ROW.publicPoint) && text.includes('calldata'), 'full-public-fields');
    }
    ok(c, (await s.page.evaluate(() => document.getElementById('payload-details').open)) === (variant === 'open'),
      'keyboard-toggle');
    ok(c, (await s.phase()) === 'disconnected', 'plan-unchanged');
    return { c, phases: ['disconnected'], show: variant === 'open' ? ['#payload'] : ['#payload-summary'], hide: [] };
  };
}
/** Inline clear confirmation as it stands when a W25 row is screenshotted. */
const confirmationProbe = (s) => async () => {
  const p = await s.page.evaluate(() => {
    const shown = (id) => { const el = document.getElementById(id); return Boolean(el && !el.closest('[hidden]')
      && el.getClientRects().length > 0); };
    return { confirmationVisible: shown('clear-confirm') && shown('clear-text') && shown('confirm-clear')
      && shown('cancel-clear'), clearHidden: !shown('clear'), text: document.getElementById('clear-text').textContent,
    focused: document.activeElement && document.activeElement.id, viewport: window.innerWidth,
    phase: document.body.dataset.phase };
  });
  p.recordPresent = Boolean(await storedRaw(s.page));
  return { ...p, result: p.confirmationVisible && p.clearHidden && p.recordPresent && p.phase === 'failed'
    ? 'pass' : 'fail' };
};

/** W25 rows are screenshotted while the inline confirmation is open; the decision runs afterwards. */
async function toClearConfirmation(s) {
  await s.open();
  await s.toPending();
  s.chain.mine({ revert: true });
  s.chain.mine();
  await s.refresh();
  await s.waitPhase('failed');
  await s.page.click('#clear');
  await s.page.waitForSelector('#clear-confirm:not([hidden])');
  const c = {};
  ok(c, (await s.page.textContent('#clear-text')).includes('この端末の送信記録だけを消去します'), 'confirmation-text');
  ok(c, !(await visible(s.page, '#clear')), 'clear-replaced-by-confirmation');
  ok(c, Boolean(await storedRaw(s.page)), 'record-present-while-confirming');
  return c;
}
const CONFIRMATION_VIEW = { phases: ['failed'], show: ['#clear-confirm', '#clear-text', '#confirm-clear', '#cancel-clear'],
  hide: ['#clear'] };
S['W25.cancel-clear'] = async (s) => {
  const c = await toClearConfirmation(s);
  return { c, ...CONFIRMATION_VIEW, atScreenshot: confirmationProbe(s),
    after: async () => {
      await s.page.click('#cancel-clear');
      await s.page.waitForSelector('#clear-confirm', { state: 'hidden' });
      c['cancel-restores-focus'] = (await focusedId(s.page)) === 'clear' ? 'pass' : 'fail';
      c['bytes-retained'] = Boolean(await storedRaw(s.page))
        && (await s.phase()) === 'failed' && await visible(s.page, '#clear') ? 'pass' : 'fail';
    } };
};
S['W25.confirm-clear'] = async (s) => {
  const c = await toClearConfirmation(s);
  return { c, ...CONFIRMATION_VIEW, atScreenshot: confirmationProbe(s),
    after: async () => {
      await s.page.click('#confirm-clear');
      await s.waitPhase('connected');
      const row = (await storedRow(s.page)).row;
      c['only-record-removed'] = row && row.raw === null && row.revision > 0 ? 'pass' : 'fail';
      c['returns-public-plan'] = await visible(s.page, '#plan') && (await focusedId(s.page)) === 'plan-heading'
        && !(await visible(s.page, '#attempt')) ? 'pass' : 'fail';
      c['no-send'] = s.sends === 1 ? 'pass' : 'fail';
    } };
};
S['W26.pairing-copy'] = async (s) => {
  await toPairing(s);
  await s.page.click('#copy-uri');
  const c = {};
  const clip = await s.page.evaluate(() => navigator.clipboard.readText());
  ok(c, clip.startsWith('wc:') && clip === await s.page.inputValue('#pairing-uri'), 'protocol-uri-only');
  ok(c, (await s.page.getAttribute('#pairing-uri', 'readonly')) !== null, 'readonly-uri');
  return { c, phases: ['connecting'], show: ['#pairing'], hide: [] };
};
S['W26.pairing-cancel'] = async (s) => {
  await toPairing(s);
  await s.page.keyboard.press('Escape');
  await s.waitPhase('disconnected');
  const c = {};
  ok(c, !(await visible(s.page, '#pairing')) && (await focusedId(s.page)) === 'send', 'escape-closes-returns-focus');
  ok(c, s.sends === 0, 'zero-send');
  return { c, phases: ['disconnected'], show: ['#wallet-error'], hide: ['#pairing'] };
};
S['W26.pairing-error'] = async (s) => {
  s.options.relayError = true;
  await s.open();
  await s.prepare();
  await s.waitPhase('disconnected');
  await s.connect('walletconnect');
  await s.page.waitForSelector('#wallet-error:not([hidden])', { timeout: 6000 }).catch(() => {});
  const c = {};
  const failed = await visible(s.page, '#wallet-error');
  if (!failed) {
    // The SDK may keep retrying an erroring relay; the user cancels and the status stays honest. With no pairing URI
    // there is no cancel control, and WalletConnect 2.26.0 rejects the erroring relay only after its own bounded
    // retries (observed ~70 s), so the honest error is awaited within 90 s rather than the default 30 s.
    await s.page.click('#cancel-pairing', { timeout: 1000 }).catch(() => {});
    await s.page.waitForSelector('#wallet-error:not([hidden])', { timeout: 90_000 });
  }
  ok(c, (await s.phase()) === 'disconnected', 'honest-error');
  ok(c, s.sends === 0, 'zero-send');
  return { c, phases: ['disconnected'], show: ['#wallet-error'], hide: ['#pairing'] };
};

// W27/W28: transactional storage states, rendered through the production store/controller/ui.

const INITIALIZING = '送信記録を確認しています。';
const NOTICE = {
  unsaved: '取引情報を保存できませんでした。ページを閉じずに「状況を更新」で再試行してください。',
  late: 'ウォレットが別の取引ハッシュを返しました。保存済みの記録を優先し、この記録は変更しません。',
  newer: '別のタブまたはウィンドウで更新された送信記録を表示しています。',
};
const minTarget = (page, id) => page.$eval('#' + id, (el) => Math.min(el.getBoundingClientRect().width,
  el.getBoundingClientRect().height));

// The store's bounded open deadline (5 s) is real time, so this row is captured mid-flow in a fresh session.
S['W27.initializing'] = Object.assign(async (s, state, env) => {
  await referenceMeasure(env, state.viewport.width);
  await s.open({ holdOpen: true, waitReady: false });
  await s.waitPhase('initializing');
  await s.prepare();
  const c = {};
  ok(c, (await s.phase()) === 'initializing', 'import-renders-while-loading');
  ok(c, (await s.page.textContent('#no-attempt')) === INITIALIZING
    && (await s.page.getAttribute('#no-attempt', 'aria-busy')) === 'true'
    && (await s.page.getAttribute('main', 'aria-busy')) === 'true', 'busy-status');
  ok(c, await s.page.isDisabled('#inspect') && await s.page.isDisabled('#send') && await noFeeAnatomy(s.page),
    'commands-disabled');
  const view = { phases: ['initializing'], show: ['#next-step', '#plan'], hide: ['#attempt', '#review', '#storage-error'] };
  const snap = await snapshot(env, s, state, view);
  ok(c, Date.now() - s.openedAt < 4500, 'captured-before-deadline');
  await s.page.evaluate(() => window.__releaseOpen());
  await s.waitPhase('disconnected');
  ok(c, (await s.page.getAttribute('main', 'aria-busy')) === 'false', 'completion-adopts-verified-storage');
  ok(c, (await storedRow(s.page)).row && (await storedRow(s.page)).row.revision === 0, 'empty-signer-authority-created');
  ok(c, s.sends === 0, 'zero-send');
  return { c, ...view, snap };
}, { perState: true });
S['W27.unavailable'] = async (s) => {
  await s.open({ idbUnavailable: true });
  await s.waitPhase('storageError');
  await s.prepare();
  const c = {};
  ok(c, (await s.page.textContent('#storage-error')).includes('保存領域'), 'storage-alert');
  ok(c, (await s.page.evaluate((k) => localStorage.getItem(k), LEGACY_KEY)) === null, 'no-localstorage-fallback');
  ok(c, await s.page.isDisabled('#inspect') && await s.page.isDisabled('#send'), 'send-blocked');
  ok(c, s.sends === 0, 'zero-send');
  return { c, phases: ['storageError'], show: ['#plan-blocked', '#plan'], hide: ['#attempt'] };
};
S['W27.legacy-conflict'] = async (s) => {
  const legacy = JSON.stringify({ version: 1, id: 'legacy', state: 'pending' });
  await s.open({ storage: { [LEGACY_KEY]: legacy } });
  await s.waitPhase('storageError');
  await s.prepare();
  const c = {};
  ok(c, (await s.page.textContent('#storage-error')).includes('旧形式'), 'legacy-alert-plain-text');
  ok(c, (await s.page.evaluate((k) => localStorage.getItem(k), LEGACY_KEY)) === legacy, 'legacy-bytes-preserved');
  ok(c, (await storedRow(s.page)).exists === false, 'no-database-created');
  ok(c, await visible(s.page, '#plan-blocked'), 'alert-visible');
  ok(c, await s.page.isDisabled('#inspect') && s.sends === 0, 'send-blocked');
  return { c, phases: ['storageError'], show: ['#plan-blocked'], hide: ['#attempt'] };
};

/** A sends (deferred, wallet pending); peer page B loads the same attempt and reconciles `tx` by manual hash. */
async function peerReconciles(s, mutate = (tx) => tx, mine = 0) {
  await s.open();
  await s.toReady();
  s.wallet().behavior.send = 'deferred';
  await s.send();
  await s.waitPhase('walletPending');
  const peer = await s.peer();
  await peer.page.waitForFunction(() => document.body.dataset.phase === 'unknown');
  const hash = s.chain.submit(mutate({ ...s.wallet().built[0] }));
  for (let i = 0; i < mine; i++) s.chain.mine();
  await peer.page.evaluate(() => { document.getElementById('payload-details').open = true; });
  await peer.page.fill('#manual-hash', hash);
  await peer.page.click('#check-hash');
  await peer.page.waitForFunction(() => !['unknown'].includes(document.body.dataset.phase));
  return { peer, hash };
}

S['W28.newer-evidence'] = async (s) => {
  // The peer recovers the wallet's own transaction (with its own higher gas: v2 evidence, not an override).
  const { peer, hash } = await peerReconciles(s, (tx) => ({ ...tx, gas: '0xdbba0' }));
  const c = {};
  ok(c, (await peer.page.evaluate(() => document.body.dataset.phase)) === 'txPending', 'peer-evidence-saved');
  const saved = JSON.parse(await storedRaw(s.page));
  // The sending tab's wallet answers malformed afterwards: it cannot erase the newer evidence.
  s.wallet().pendingSends[0].resolve('not-a-hash');
  await s.waitPhase('txPending');
  await s.page.waitForFunction((t) => document.getElementById('attempt-context-text').textContent.includes(t), NOTICE.newer);
  await s.page.waitForFunction(() => !document.getElementById('refresh').disabled);
  const stored = JSON.parse(await storedRaw(s.page));
  ok(c, stored.hash === hash && stored.state === 'pending' && saved.hash === hash, 'newer-evidence-retained');
  ok(c, (await s.page.textContent('#attempt-list')).includes(hash), 'full-hash-shown');
  ok(c, !(await visible(s.page, '#clear')) && await s.page.isDisabled('#send'), 'no-primary-send-or-clear');
  ok(c, s.sends === 1 && s.wallets.peer.sends.length === 0, 'one-send-total');
  await peer.page.close();
  return { c, phases: ['txPending'], show: ['#plan'], hide: ['#clear'] };
};
S['W28.unsaved-hash'] = async (s) => {
  await s.open();
  await s.toReady();
  s.wallet().behavior.send = 'deferred';
  await s.send();
  await s.waitPhase('walletPending');
  await s.page.evaluate(() => { window.__failWrites = true; });
  s.wallet().releaseSend();
  await s.page.waitForFunction((t) => document.getElementById('attempt-context-text').textContent.includes(t), NOTICE.unsaved);
  const c = {};
  const hash = await s.page.evaluate(() => document.getElementById('attempt-list').textContent.match(/0x[0-9a-f]{64}/));
  ok(c, Boolean(hash), 'returned-hash-visible');
  ok(c, JSON.parse(await storedRaw(s.page)).hash === null, 'stored-row-unchanged');
  ok(c, await s.page.isEnabled('#refresh') && (await minTarget(s.page, 'refresh')) >= 47.5, 'secondary-refresh-min48');
  ok(c, (await focusedId(s.page)) !== 'refresh', 'no-background-focus-steal');
  ok(c, s.sends === 1, 'one-send');
  return { c, phases: ['txPending'], show: ['#attempt', '#refresh'], hide: ['#clear', '#hash-form'],
    after: async () => {
      await s.page.evaluate(() => { window.__failWrites = false; });
      await s.refresh();
      await s.page.waitForFunction((t) => !document.getElementById('attempt-context-text').textContent.includes(t), NOTICE.unsaved);
      const saved = JSON.parse(await storedRaw(s.page));
      c['retry-saves-same-outcome'] = hash && saved.hash === hash[0] && s.sends === 1 ? 'pass' : 'fail';
    } };
};
S['W28.late-conflict'] = async (s) => {
  const { peer, hash } = await peerReconciles(s, (tx) => tx, 2);
  const c = {};
  ok(c, (await peer.page.evaluate(() => document.body.dataset.phase)) === 'success', 'peer-success-saved');
  const before = JSON.parse(await storedRaw(s.page));
  s.wallet().releaseSend();
  await s.page.waitForFunction((t) => document.getElementById('attempt-context-text').textContent.includes(t), NOTICE.late);
  await s.waitPhase('success');
  await s.page.waitForFunction(() => !document.getElementById('refresh').disabled);
  const stored = JSON.parse(await storedRaw(s.page));
  ok(c, stored.hash === hash && stored.state === 'success' && before.hash === hash, 'saved-lineage-retained');
  const entries = await attemptEntries(s.page);
  const late = entries['ウォレットが返した別のハッシュ（追跡しません）'] || '';
  ok(c, /^0x[0-9a-f]{64}$/.test(late) && late !== hash, 'conflicting-hash-plain-text');
  ok(c, entries['取引ハッシュ'] === hash, 'stored-hash-shown');
  ok(c, s.sends === 1 && s.wallets.peer.sends.length === 0, 'no-new-send');
  await peer.page.close();
  return { c, phases: ['success'], show: ['#attempt'], hide: ['#hash-form'] };
};

// W24: per-control subresults across a tour of reachable states, run once per expanded row in a context opened
// at that row's width. The expected controls and their per-variant expectation come from tests/ui-states.json.

/** A send command re-validates before any wallet call; wait until it has left the review/ready phases. */
function waitSubmitted(page) {
  return page.waitForFunction(() => !['ready', 'review'].includes(document.body.dataset.phase)
    || document.getElementById('send').getAttribute('aria-busy') !== 'true', null, { timeout: 8000 });
}

/** Live state of one control, read in the page (viewport is the measured layout width). */
const probeControl = (page, id) => page.evaluate((i) => {
  const e = document.getElementById(i);
  const c = getComputedStyle(e);
  return { control: i, viewport: window.innerWidth, phase: document.body.dataset.phase,
    focused: document.activeElement && document.activeElement.id, disabled: e.disabled === true,
    busy: e.getAttribute('aria-busy'), text: e.textContent.trim(), checked: e.checked === true, bg: c.backgroundColor,
    transform: c.transform, opacity: c.opacity,
    outline: [c.outlineStyle, c.outlineWidth, c.outlineColor, c.outlineOffset].join(' ') };
}, id);

/** Whether a probe taken at screenshot time depicts the row's variant on its capture control. */
function depictsVariant(variant, p, context) {
  if (variant === 'tab-focus') return p.focused === p.control && p.outline === `solid 3px ${TOKENS.focus} 4px`;
  if (variant === 'pressed') return p.bg === TOKENS.accent && p.transform === 'matrix(1, 0, 0, 1, 0, 1)';
  if (variant === 'disabled') return p.disabled && p.opacity === '0.45';
  if (variant === 'loading') return p.busy === 'true' && /…$/.test(p.text) && p.disabled;
  // Keyboard rows are captured on the explicit operation action right after its native activation: exactly one
  // wallet request, held pending in the wallet (busy, disabled), nothing else activated.
  if (variant === 'keyboard-enter' || variant === 'keyboard-space') {
    return p.control === 'send' && context.key === (variant === 'keyboard-enter' ? 'Enter' : 'Space')
      && context.sendsDelta === 1 && p.phase === 'walletPending' && p.busy === 'true' && p.disabled;
  }
  return false;
}

async function tour(s, state, env) {
  const page = s.page;
  const variant = state.variant;
  const expect = Object.fromEntries(state.controls.map((x) => [x.element, x]));
  const ids = state.controls.map((x) => x.element);
  const sub = {};
  let snap = null;
  const style = (id, prop) => page.$eval('#' + id, (el, p) => getComputedStyle(el)[p], prop);
  const mark = async (id, pass, note = '') => {
    if (sub[id] && sub[id].result === 'pass') return;
    const live = await page.evaluate(() => ({ viewport: window.innerWidth, phase: document.body.dataset.phase }));
    sub[id] = { name: expect[id].name, expect: expect[id].expect, result: pass ? 'pass' : `fail ${note}`,
      viewport: live.viewport, phase: live.phase };
  };
  // Row screenshot of the variant on the row's capture control, taken while the variant is in effect.
  const shoot = async (id, context = {}) => {
    if (snap || id !== state.captureControl) return;
    const phase = await s.phase();
    snap = await snapshot(env, s, state, { phases: [phase],
      show: ['#' + (variant.startsWith('keyboard-') && id === 'send' ? 'attempt-status' : id)], hide: [] }, {
      pointer: variant !== 'pressed',
      probe: async () => {
        const p = await probeControl(page, id);
        return { ...p, variant, result: depictsVariant(variant, p, context) ? 'pass' : 'fail' };
      } });
  };
  async function check(id) {
    if (sub[id] && sub[id].result === 'pass') return;
    const mode = expect[id].expect;
    const el = await page.$('#' + id);
    if (!el || !(await el.isVisible())) return;
    const tag = await el.evaluate((e) => e.tagName);
    const disabled = await el.evaluate((e) => e.disabled === true);
    if (mode === 'focus-ring') {
      if (disabled) return;
      await page.evaluate(() => document.activeElement && document.activeElement.blur());
      for (let i = 0; i < 80; i++) {
        await page.keyboard.press('Tab');
        if ((await focusedId(page)) === id) break;
      }
      const outline = await el.evaluate((e) => { const c = getComputedStyle(e); return [c.outlineStyle, c.outlineWidth,
        c.outlineColor, c.outlineOffset].join(' '); });
      const pass = (await focusedId(page)) === id && outline === `solid 3px ${TOKENS.focus} 4px`;
      await mark(id, pass, outline);
      if (pass) await shoot(id);
    } else if (mode === 'pointer-down-accent') {
      if (disabled || tag !== 'BUTTON') return;
      await el.scrollIntoViewIfNeeded();
      const box = await el.boundingBox();
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await page.mouse.down();
      const pressed = [await style(id, 'backgroundColor'), await style(id, 'transform')];
      const pass = pressed[0] === TOKENS.accent && pressed[1] === 'matrix(1, 0, 0, 1, 0, 1)';
      if (pass) await shoot(id);
      await page.mouse.move(1, 1);
      await page.mouse.up();
      await mark(id, pass, pressed.join(' '));
    } else if (mode === 'native-toggle') {
      if (disabled) return;
      if (id === 'payload-summary') {
        const before = await page.evaluate(() => document.getElementById('payload-details').open);
        await el.click();
        const after = await page.evaluate(() => document.getElementById('payload-details').open);
        await el.click();
        await mark(id, before !== after, 'native toggle');
      } else {
        const before = await el.isChecked();
        await el.click();
        const after = await el.isChecked();
        await el.click();
        await mark(id, before !== after && s.sends === 0, 'native toggle');
      }
    } else if (mode === 'native-focus') {
      if (disabled) return;
      await el.scrollIntoViewIfNeeded();
      const box = await el.boundingBox();
      await page.mouse.click(box.x + 5, box.y + box.height / 2);
      await mark(id, (await focusedId(page)) === id, 'native focus');
    } else if (mode === 'native-disabled' || mode === 'never-disabled') {
      if (disabled) {
        const opacity = await style(id, 'opacity');
        const clicked = s.sends;
        await el.evaluate((e) => e.click());
        const pass = opacity === '0.45' && s.sends === clicked;
        await mark(id, pass, `opacity ${opacity}`);
        if (pass) await shoot(id);
      } else if (mode === 'never-disabled') {
        // Never disabled by design: shown only in states where they apply (hidden otherwise).
        await mark(id, (await style(id, 'opacity')) === '1', 'enabled native');
      }
    } else if (mode === 'busy' || mode === 'no-loading-state') {
      // Loading is text + aria-busy, recorded when the control's command is in flight.
      const busy = await el.evaluate((e) => e.getAttribute('aria-busy'));
      if (mode === 'busy') {
        if (busy === 'true') {
          const pass = /…$/.test((await el.textContent()).trim()) && disabled;
          await mark(id, pass, 'busy text');
          if (pass) await shoot(id);
        }
      } else await mark(id, busy !== 'true', 'no loading state');
    } else if (['sends-once', 'no-send'].includes(mode)) {
      if (disabled || (mode === 'sends-once' && (await s.phase()) !== 'ready')) return;
      const key = variant === 'keyboard-enter' ? 'Enter' : 'Space';
      const before = s.sends;
      // The explicit action's wallet request is held pending so the row screenshot shows its busy state.
      if (mode === 'sends-once') s.wallet().behavior.send = 'deferred';
      await el.focus();
      await page.keyboard.press(key);
      if (mode === 'sends-once') {
        // The activation continues through connect/switch/inspection before its send: wait (bounded) for the
        // wallet request, or for the activation to settle without one.
        await waitSubmitted(page);
        for (let i = 0; i < 160 && s.sends === before; i++) {
          if (!(await page.evaluate(() => document.body.dataset.phase === 'walletPending'
            || document.getElementById('send').getAttribute('aria-busy') === 'true'))) break;
          await sleep(50);
        }
      }
      await sleep(80);
      if (mode === 'sends-once') {
        const pass = s.sends === before + 1;
        await mark(id, pass, 'explicit activation sends once');
        if (pass) await shoot(id, { key, sendsDelta: s.sends - before });
      } else {
        await mark(id, s.sends === before, key === 'Enter' ? 'enter never sends' : 'no send');
      }
    } else await mark(id, false, `unknown expectation ${mode}`);
  }
  const all = async () => { for (const id of ids) await check(id); };
  const loading = variant === 'loading';
  const held = {};
  s.wallet().chainId = '0x1';
  // The individual connect/switch/inspect controls live in the folded technical details; the tour measures them
  // there (the details toggle check clicks twice, leaving it open).
  await s.openDetails();
  await page.evaluate(() => { document.getElementById('manual-import').open = true; });
  if (loading) s.wallet().behavior.connect = 'deferred';
  // Phase-driven tour: keyboard/pointer checks may themselves activate a control, so each step reacts to
  // the settled phase instead of assuming the previous action's outcome.
  for (let step = 0; step < 60; step++) {
    // Keyboard variants toggle the details through its summary; keep the individual controls reachable.
    await s.openDetails();
    await page.evaluate(() => { document.getElementById('manual-import').open = true; });
    await all();
    const phase = await s.phase();
    const done = phase === 'failed' && await page.isVisible('#clear-confirm')
      && ids.every((id) => sub[id] !== undefined);
    if (done) break;
    if (phase === 'empty' || phase === 'inputError') await s.prepare();
    else if (phase === 'disconnected') {
      if (!(await page.isChecked('#wallet-legacy'))) await page.check('#wallet-legacy');
      else await page.click('#connect');
    } else if (phase === 'connecting') { if (s.wallet().releaseConnect) s.wallet().releaseConnect(); }
    else if (phase === 'wrongChain') await page.click('#switch');
    else if (phase === 'connected') {
      // Inspection reads identity only; holding its Factory prediction call keeps it visibly loading.
      if (loading && !held.inspection) held.inspection = s.hold('eth_call');
      await page.click('#inspect');
    } else if (phase === 'inspecting') { if (held.inspection) held.inspection.release(); }
    else if (phase === 'review' && (await page.getAttribute('#send', 'aria-busy')) === 'true') await waitSubmitted(page);
    else if (phase === 'ready') {
      // Inspection can settle between the per-control pass and this phase read: exercise every control in the
      // ready state (the explicit action included) before the tour activates the action itself.
      await all();
      if ((await s.phase()) !== 'ready') continue;
      if (loading) s.wallet().behavior.send = 'deferred';
      await page.click('#send');
      await waitSubmitted(page);
    } else if (phase === 'walletPending') { if (s.wallet().pendingSends.length) s.wallet().releaseSend(); }
    else if (phase === 'txPending') {
      s.chain.faults.offline = true;
      await s.refresh();
      await s.waitPhase('unknown');
    } else if (phase === 'unknown') {
      s.chain.faults.offline = false;
      if (loading && !held.refresh) {
        held.refresh = s.hold('eth_getTransactionByHash');
        await page.click('#refresh');
        await page.waitForFunction(() => document.getElementById('refresh').disabled);
        await all();
        held.refresh.release();
        await page.waitForFunction(() => !document.getElementById('refresh').disabled);
      } else {
        s.chain.mine({ revert: true });
        s.chain.mine();
        await s.refresh();
      }
    } else if (phase === 'failed') {
      if (!(await page.isVisible('#clear-confirm'))) await page.click('#clear');
    } else throw new Error(`tour reached unexpected phase ${phase}`);
    await sleep(60);
  }
  for (const id of ids) if (sub[id] === undefined) await mark(id, false, 'not exercised');
  return { sub, snap };
}
for (const variant of ['tab-focus', 'pressed', 'disabled', 'loading', 'keyboard-enter', 'keyboard-space']) {
  // perState: a fresh session per expanded row, opened at that row's viewport.
  S[`W24.${variant}`] = Object.assign(async (s, state, env) => {
    await s.open();
    const { sub, snap } = await tour(s, state, env);
    const c = Object.fromEntries(state.controls.map((x) => [`control-${x.name}`,
      sub[x.element] ? sub[x.element].result : 'fail omitted']));
    ok(c, s.sends === 1, 'one-explicit-send');
    ok(c, (await s.phase()) === 'failed' && await visible(s.page, '#clear-confirm'), 'tour-completed');
    ok(c, Boolean(snap), `variant-screenshot-on-${state.captureControl}`);
    if (!snap) throw new Error(`no ${variant} screenshot was captured on ${state.captureControl}`);
    return { c, phases: snap ? [snap.phase] : [], show: [], hide: [], subresults: sub, snap };
  }, { perState: true });
}

// -------------------------------------------------------------------------------------------------
// Measurement against design section 8 and the pinned authority reference

async function measure(page) {
  return page.evaluate(() => {
    const cs = (el) => getComputedStyle(el);
    const rect = (el) => { const r = el.getBoundingClientRect(); return { x: r.x, y: r.y, width: r.width, height: r.height }; };
    const main = document.querySelector('main');
    const body = cs(document.body);
    const compact = document.body.classList.contains('deployment');
    const sections = [...document.querySelectorAll('main > section')];
    const shown = (el) => el.checkVisibility();
    const buttons = [...document.querySelectorAll('main button')].filter(shown);
    const controls = [...document.querySelectorAll('main button, main textarea, main input[type=text], main summary, main label.choice')].filter(shown);
    const field = document.querySelector('textarea');
    const address = document.querySelector('.address');
    const primary = document.getElementById('send') || document.querySelector('main button:not(.secondary)');
    const h1 = document.querySelector('h1');
    const pad = parseFloat(cs(main).paddingLeft);
    return {
      compact, viewport: innerWidth, scrollWidth: document.documentElement.scrollWidth,
      body: { bg: body.backgroundColor, color: body.color, fontSize: body.fontSize, lineHeight: body.lineHeight,
        fontFamily: body.fontFamily, colorScheme: cs(document.documentElement).colorScheme },
      main: { ...rect(main), marginTop: cs(main).marginTop, maxWidth: cs(main).maxWidth,
        contentX: rect(main).x + pad, contentWidth: rect(main).width - 2 * pad },
      sections: sections.map((sec) => ({ id: sec.id, hidden: sec.hidden, display: cs(sec).display,
        borderTop: cs(sec).borderTopWidth, paddingTop: cs(sec).paddingTop, radius: cs(sec).borderTopLeftRadius,
        shadow: cs(sec).boxShadow, columns: cs(sec).gridTemplateColumns, ...rect(sec) })),
      h1: { fontSize: cs(h1).fontSize, lineHeight: cs(h1).lineHeight, letterSpacing: cs(h1).letterSpacing },
      field: { bg: cs(field).backgroundColor, border: cs(field).borderTopWidth + ' ' + cs(field).borderTopColor,
        radius: cs(field).borderTopLeftRadius, padding: cs(field).paddingTop, font: cs(field).fontSize + ' ' + cs(field).fontFamily,
        lineHeight: cs(field).lineHeight, minHeight: cs(field).minHeight },
      primary: { bg: cs(primary).backgroundColor, radius: cs(primary).borderTopLeftRadius, minHeight: cs(primary).minHeight },
      buttonWidths: buttons.map((el) => ({ id: el.id, ...rect(el), disabled: el.disabled, opacity: cs(el).opacity,
        parent: el.parentElement.clientWidth - parseFloat(cs(el.parentElement).paddingLeft) - parseFloat(cs(el.parentElement).paddingRight) })),
      minTarget: Math.min(...controls.map((el) => rect(el).height)),
      address: { bg: cs(address).backgroundColor, border: cs(address).borderLeftWidth, padding: cs(address).paddingTop,
        wrap: cs(address).overflowWrap, font: cs(address).fontFamily, fontSize: cs(address).fontSize },
      cards: [...document.querySelectorAll('main *')].filter((el) => cs(el).boxShadow !== 'none' || parseFloat(cs(el).borderTopLeftRadius) > 2).length,
      overflowingText: [...document.querySelectorAll('main *')].filter((el) => shown(el) && rect(el).right > innerWidth + 1).length,
    };
  });
}

function near(a, b, tolerance = 1) { return Math.abs(a - b) <= tolerance; }

/** Compact geometry replaces the retired three-column anatomy, not its inherited tokens or target sizes. */
function assertLayout(m, width) {
  const f = [];
  const expect = (cond, msg) => { if (!cond) f.push(msg); };
  expect(m.compact, 'compact deployment body');
  expect(m.body.bg === TOKENS.paper && m.body.color === TOKENS.ink, 'paper/ink tokens');
  expect(m.body.fontSize === '16px' && m.body.lineHeight === '27.2px', 'body rhythm');
  expect(m.body.fontFamily.includes('Hiragino Kaku Gothic ProN') && m.body.fontFamily.includes('Yu Gothic'), 'body font');
  expect(m.body.colorScheme === 'light', 'light scheme');
  expect(m.sections.map((s) => s.id).join(',') === 'section-plan,section-wallet,section-settlement', 'three semantic sections');
  for (const sec of m.sections.filter((s) => !s.hidden)) {
    expect(sec.display === 'block' && sec.borderTop === '0px' && sec.paddingTop === '8px', `${sec.id} compact section`);
    expect(sec.radius === '0px' && sec.shadow === 'none', `${sec.id} no card`);
  }
  expect(m.cards === 0, 'no rounded cards or shadows');
  const mainWidth = Math.min(560, width);
  expect(m.main.maxWidth === '560px' && m.main.marginTop === '56px'
    && near(m.main.width, mainWidth) && near(m.main.x, (width - mainWidth) / 2)
    && near(m.main.contentWidth, mainWidth - 48), `compact geometry ${JSON.stringify(m.main)}`);
  expect(near(parseFloat(m.h1.fontSize), Math.min(40, Math.max(30, width * 0.06)), .1)
    && near(parseFloat(m.h1.lineHeight), parseFloat(m.h1.fontSize) * 1.2, .1), 'compact heading rhythm');
  expect(m.field.bg === TOKENS.field && m.field.border === `1px ${TOKENS.line}` && m.field.radius === '2px'
    && m.field.padding === '13px' && m.field.font === '14px monospace' && m.field.lineHeight === '22.4px'
    && m.field.minHeight === '100px', 'manual field tokens');
  expect(m.primary.radius === '2px' && m.primary.minHeight === '48px', 'primary target tokens');
  for (const b of m.buttonWidths) {
    expect(b.height >= 47.5, `${b.id} target ${b.height}`);
    if (b.disabled) expect(b.opacity === '0.45', `${b.id} disabled opacity`);
    if (width <= 680 || b.id === 'send') expect(near(b.width, b.parent), `${b.id} full-width`);
  }
  expect(m.minTarget >= 47.5, `min target ${m.minTarget}`);
  expect(m.address.bg === 'rgba(0, 0, 0, 0)' && m.address.border === '0px' && m.address.padding === '0px'
    && m.address.wrap === 'anywhere' && m.address.font === 'monospace' && m.address.fontSize === '16px', 'compact address');
  expect(m.scrollWidth <= m.viewport && m.overflowingText === 0, 'no horizontal overflow');
  return f;
}

/** Only inherited tokens remain bound to the frozen pre-compact reference, not retired geometry. */
function compareReference(m, ref) {
  const f = [];
  for (const key of ['bg', 'color', 'fontFamily', 'lineHeight', 'colorScheme']) {
    if (m.body[key] !== ref.body[key]) f.push(`body.${key} differs from pinned reference`);
  }
  if (JSON.stringify(m.field) !== JSON.stringify(ref.field)) f.push('manual field differs from pinned reference');
  return f;
}

async function referenceMeasure(env, width) {
  if (env.reference[width]) return env.reference[width];
  const context = await env.browser.newContext({ viewport: { width, height: 900 }, locale: 'ja-JP', colorScheme: 'light',
    reducedMotion: 'reduce', javaScriptEnabled: false });
  await context.route('**/*', (route) => route.abort());
  const page = await context.newPage();
  const html = fs.readFileSync(path.join(__dirname, 'reference/index.html'), 'utf8')
    .replace(/<script[^>]*><\/script>/g, '').replace(/ hidden/g, '');
  await page.setContent(html);
  await page.evaluate(() => {
    // Third reference section heading/step for structural comparison; tokens are untouched.
    document.querySelectorAll('[hidden]').forEach((el) => el.removeAttribute('hidden'));
  });
  env.reference[width] = await measure(page);
  await context.close();
  return env.reference[width];
}

/**
 * Settle at the row's viewport, assert the expected view, measure and screenshot. `pointer: false` keeps the
 * pointer where it is (a held pointer-down); `probe` is read right after the screenshot, while the state still holds.
 */
async function snapshot(env, s, state, view, { pointer = true, probe = null } = {}) {
  const page = s.page;
  const width = state.viewport.width;
  const text200 = state.textScale === 2;
  const want = { width: text200 ? width * 2 : width, height: state.viewport.height };
  const current = page.viewportSize();
  if (!current || current.width !== want.width || current.height !== want.height) await page.setViewportSize(want);
  await page.evaluate((zoom) => { document.documentElement.style.zoom = zoom ? '2' : ''; }, text200);
  if (pointer) await page.mouse.move(0, 0);
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
  const failures = [];
  const phase = await s.phase();
  if (!view.phases.includes(phase)) failures.push(`settled phase ${phase} not ${view.phases.join('|')}`);
  for (const sel of view.show) if (!(await page.isVisible(sel))) failures.push(`${sel} not visible`);
  for (const sel of view.hide) if (await page.isVisible(sel)) failures.push(`${sel} visible`);
  const measured = await measure(page);
  if (measured.viewport !== want.width) failures.push(`measured at ${measured.viewport}, row needs ${want.width}`);
  if (text200) {
    if (measured.scrollWidth > measured.viewport) failures.push('200% text overflows horizontally');
    if (measured.minTarget < 47.5) failures.push('200% text target');
  } else {
    failures.push(...assertLayout(measured, width));
    if (width === 390 || width === 1280) failures.push(...compareReference(measured, await referenceMeasure(env, width)));
  }
  const file = `${state.id}.png`;
  const image = await page.screenshot({ path: path.join(env.screens, file), fullPage: true, animations: 'disabled' });
  const atScreenshot = probe ? await probe() : null;
  await page.evaluate(() => { document.documentElement.style.zoom = ''; });
  return { phase, measured, image, file, failures, atScreenshot };
}

async function screenshotRow(env, s, state, scenario, evidence) {
  // A scenario may have captured its row mid-flow (W24: while the variant is in effect at this row's width).
  const snap = scenario.snap || await snapshot(env, s, state, scenario, { probe: scenario.atScreenshot });
  const { phase, measured, image, file } = snap;
  const failures = [...snap.failures];
  if (snap.atScreenshot && snap.atScreenshot.result !== 'pass') {
    failures.push(`screenshot does not depict the row state: ${JSON.stringify(snap.atScreenshot).slice(0, 300)}`);
  }
  const stateFailures = Object.entries(scenario.c).filter(([, v]) => v !== 'pass').map(([k, v]) => `${k}: ${v}`);
  failures.push(...stateFailures);
  if (s.external.length) failures.push(`unexpected external requests: ${s.external.slice(0, 3).join(', ')}`);
  // The relay-error scenario's mock relay answers with JSON-RPC error objects, which the SDK rethrows as
  // non-Error unhandled rejections internally; they are recorded, any Error-typed page error still fails.
  const pageErrors = s.options.relayError ? s.consoleErrors.filter((e) => !/^: Object $/.test(e)) : s.consoleErrors;
  if (s.options.relayError) scenario.c['sdk-relay-rejections-recorded'] = 'pass';
  if (pageErrors.length) failures.push(`page errors: ${pageErrors.slice(0, 2).join(' | ')}`);
  evidence.rows.push({
    sdkRelayRejections: s.options.relayError ? s.consoleErrors.length : 0,
    id: state.id, row: state.row, variant: state.variant, fixture: state.fixture, runUUID: evidence.runUUID,
    status: failures.length ? 'FAIL' : 'PASS', failures, settledPhase: phase, checks: scenario.c,
    subresults: scenario.subresults || null, atScreenshot: snap.atScreenshot || null, viewport: state.viewport,
    textScale: state.textScale,
    locale: 'ja-JP', colorScheme: 'light', reducedMotion: 'reduce', screenshot: file, screenshotSHA256: sha256(image),
    measured: { viewport: measured.viewport, main: measured.main, sections: measured.sections.map((x) => ({ id: x.id,
      columns: x.columns, x: x.x, width: x.width })), body: measured.body, h1: measured.h1,
    scrollWidth: measured.scrollWidth, minTarget: measured.minTarget },
  });
}

/**
 * ui-states.json must equal the frozen delegate-deployment-fees inventory exactly (204 rows, record versions, W24
 * per-control expectations and capture controls). Its W24 control names must be the change matrix's list, and no
 * row may declare the retired cap/consent controls. The inventory must also be exactly the original expansion with
 * the documented retirements removed and the documented replacements added (no silent omission).
 */
const RETIRED = ['W14.invalid-cap', 'W14.too-low', 'W15.unchecked', 'W15.checked', 'W16.cap',
  ...['fee-overridden-deployed', 'fee-overridden-not-deployed', 'fee-overridden-unknown', 'gas-overridden-within-limits',
    'gas-overridden-deployed', 'gas-overridden-not-deployed', 'gas-overridden-unknown'].map((v) => `W20.${v}`)];
function declareControls(states, inventory, original) {
  if (JSON.stringify(states) !== JSON.stringify(inventory)) throw new Error('ui-states.json differs from ui-inventory.json');
  const kept = original.filter((s) => !RETIRED.includes(s.fixture)).map((s) => s.id);
  const ids = inventory.map((s) => s.id);
  const lost = kept.filter((id) => !ids.includes(id));
  if (lost.length) throw new Error(`inventory omits retained rows: ${lost.slice(0, 6).join(', ')}`);
  const retiredPresent = ids.filter((id) => RETIRED.some((fixture) => id.startsWith(fixture + '.')));
  if (retiredPresent.length) throw new Error(`inventory keeps retired rows: ${retiredPresent.join(', ')}`);
  const names = w24Controls();
  for (const state of states) {
    if (state.row !== 'W24') {
      if (state.controls || state.captureControl) throw new Error(`${state.id} declares W24 control expectations`);
      continue;
    }
    const declaredNames = (state.controls || []).map((c) => c.name);
    if (JSON.stringify(declaredNames) !== JSON.stringify(names)
      || state.controls.some((c) => !c.element || !c.expect || ['cap', 'consent'].includes(c.element))
      || !state.controls.some((c) => c.element === state.captureControl)) {
      throw new Error(`${state.id} control expectations do not cover the matrix W24 controls ${names.join('/')}`);
    }
  }
}

/** Wrong-design controls: each mutation of the real page must be rejected by the measurements. */
async function designControls(env) {
  const results = {};
  const mutations = {
    'wrong-paper': (page) => page.addStyleTag({ content: 'body{background:#ffffff !important}' }),
    'wrong-margins': (page) => page.addStyleTag({ content: 'main{margin:20px auto !important;max-width:900px !important}' }),
    'missing-section': (page) => page.evaluate(() => document.getElementById('section-settlement').remove()),
    'generic-card': (page) => page.addStyleTag({ content: 'section{display:block !important;border:1px solid #ddd !important;'
      + 'border-radius:12px !important;box-shadow:0 2px 8px rgba(0,0,0,.2) !important;padding:16px !important}' }),
    'old-breakpoint-650': (page) => page.addStyleTag({ content: '@media (max-width:680px) and (min-width:651px){'
      + '.deployment main{margin-top:55px !important}.intro,section{grid-template-columns:190px 1fr !important}}' }),
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    // Test-only CSP bypass so the wrong-design mutation can be injected into the real page.
    const s = new Session(env, { bypassCSP: true });
    await s.open();
    await s.prepare();
    await s.waitPhase('disconnected');
    const width = name === 'old-breakpoint-650' ? 670 : 1280;
    await s.page.setViewportSize({ width, height: 900 });
    await s.page.mouse.move(0, 0);
    const clean = assertLayout(await measure(s.page), width);
    await mutate(s.page);
    const measured = await measure(s.page);
    const found = assertLayout(measured, width).concat(width === 1280 ? compareReference(measured,
      await referenceMeasure(env, 1280)) : []);
    results[name] = clean.length === 0 && found.length > 0 ? 'rejected'
      : `NOT REJECTED (clean ${clean.join('; ').slice(0, 200)})`;
    await s.close();
  }
  return results;
}

function judgeControls(expectedIds, evidence, current, screens, states) {
  const clone = () => JSON.parse(JSON.stringify(evidence));
  const mutateRow = (id, change) => { const e = clone(); const row = e.rows.find((r) => r.id === id);
    if (row) change(row); else e.rows.pop(); return e; };
  const cases = {
    complete: [clone(), true],
    'deleted-row': [(() => { const e = clone(); e.rows.splice(3, 1); return e; })(), false],
    'duplicate-row': [(() => { const e = clone(); e.rows.push(e.rows[0]); return e; })(), false],
    'stale-source': [(() => { const e = clone(); e.binding.source = '0'.repeat(64); return e; })(), false],
    'stale-head': [(() => { const e = clone(); e.binding.head = 'deadbeef'; return e; })(), false],
    'failed-row': [(() => { const e = clone(); e.rows[5].status = 'FAIL'; return e; })(), false],
    'not-evaluated-row': [(() => { const e = clone(); e.rows[7].status = 'NOT_EVALUATED'; return e; })(), false],
    'other-run-row': [(() => { const e = clone(); e.rows[9].runUUID = crypto.randomUUID(); return e; })(), false],
    'changed-screenshot': [(() => { const e = clone(); e.rows[2].screenshotSHA256 = '0'.repeat(64); return e; })(), false],
    'unknown-row': [(() => { const e = clone(); e.rows.push({ ...e.rows[0], id: 'W99.390' }); return e; })(), false],
    // W24 390 row whose control subresults came from a 1280 tour (the shared-tour defect).
    'w24-390-subresults-at-1280': [mutateRow('W24.pressed.390', (row) => {
      row.subresults = Object.fromEntries(Object.entries(row.subresults || { send: {} })
        .map(([k, v]) => [k, { ...v, viewport: 1280 }]));
    }), false],
    'w24-missing-control': [mutateRow('W24.tab-focus.1280', (row) => { if (row.subresults) delete row.subresults.send; }), false],
    'w24-screenshot-not-variant': [mutateRow('W24.loading.390', (row) => { row.atScreenshot = { ...row.atScreenshot, result: 'fail' }; }), false],
    'w25-no-confirmation': [mutateRow('W25.cancel-clear.390', (row) => {
      row.atScreenshot = { ...row.atScreenshot, confirmationVisible: false };
    }), false],
    'row-measured-at-other-width': [mutateRow('W08.390', (row) => { row.measured = { ...row.measured, viewport: 1280 }; }), false],
  };
  const out = {};
  for (const [name, [candidate, accept]] of Object.entries(cases)) {
    const errors = judge(expectedIds, candidate, current, screens, states);
    const accepted = errors.length === 0;
    out[name] = accepted === accept ? (accept ? 'accepted' : 'rejected') : `WRONG (${accepted ? 'accepted' : 'rejected'})`;
  }
  return out;
}

async function main() {
  const [evidencePath, screens] = process.argv.slice(2);
  if (!evidencePath || !screens) throw new Error('usage: check-browser.cjs <evidence.json> <screenshot-dir>');
  fs.rmSync(screens, { recursive: true, force: true });
  fs.mkdirSync(screens, { recursive: true });
  const declared = JSON.parse(fs.readFileSync(path.join(__dirname, 'ui-states.json'), 'utf8'));
  const expanded = expandAll();
  declareControls(declared.states, expanded, expandOriginal());
  const expectedIds = expanded.map((s) => s.id);
  const refManifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'reference/manifest.json'), 'utf8'));
  for (const [name, digest] of Object.entries(refManifest.files)) {
    if (sha256(fs.readFileSync(path.join(__dirname, 'reference', name))) !== digest) {
      throw new Error(`pinned visual reference ${name} changed`);
    }
  }
  const missingScenario = [...new Set(expanded.map((s) => s.fixture))].filter((f) => !S[f]);
  if (missingScenario.length) throw new Error(`no scenario for ${missingScenario.join(', ')}`);
  const binding = digests();
  const browser = await chromium.launch();
  const reference = {};
  const lanes = [];
  const LANES = Number(process.env.CHECK_BROWSER_LANES || 4);
  const evidence = { suite: 'check-browser', runUUID: crypto.randomUUID(), binding,
    browser: { name: 'chromium-headless-shell', version: browser.version(), playwright: require('playwright/package.json').version },
    startedAt: new Date().toISOString(), startedAtEpoch: Date.now() / 1000, lanes: LANES, rows: [] };
  const started = Date.now();
  try {
    // Independent lanes: each has its own chain double, upstream and two serve.py instances.
    for (let i = 0; i < LANES; i++) {
      const state = { chain: null, holds: {} };
      const upstream = await startUpstream(state);
      const lane = { state, reference, screens, browser, upstream, portWithId: await freePort(), portNoId: await freePort() };
      lane.servers = [await startServe(lane.portWithId, upstream.address().port, PROJECT),
        await startServe(lane.portNoId, upstream.address().port, null)];
      lanes.push(lane);
    }
    const byFixture = new Map();
    // CHECK_BROWSER_ONLY is a development filter; the judge still requires every row, so it can never pass.
    const only = process.env.CHECK_BROWSER_ONLY ? process.env.CHECK_BROWSER_ONLY.split(',') : null;
    // Declared rows (matrix expansion plus the W24 control expectations validated above).
    for (const st of declared.states) {
      if (!only || only.includes(st.fixture)) byFixture.set(st.fixture, [...(byFixture.get(st.fixture) || []), st]);
    }
    // Fixtures dominated by bounded real-time waits start first so they overlap the rest instead of extending the
    // tail; evidence rows are still emitted in declared order below.
    const SLOW_FIRST = ['W26.pairing-error', 'W18.poll-timeout', 'W28.unsaved-hash'];
    const queue = [...byFixture.entries()].sort(([a], [b]) => (SLOW_FIRST.includes(b) ? 1 : 0) - (SLOW_FIRST.includes(a) ? 1 : 0));
    const results = new Map();
    const runFixture = async (env, fixture, states) => {
      const fixtureStarted = Date.now();
      const rows = { rows: [], runUUID: evidence.runUUID };
      if (S[fixture].perState) {
        // One fresh session per expanded row, opened at the row's own viewport (W24 control tours).
        for (const st of states) {
          const s = new Session(env, { viewport: { ...st.viewport } });
          try {
            const scenario = await S[fixture](s, st, env);
            await screenshotRow(env, s, st, scenario, rows);
          } catch (error) {
            rows.rows.push({ id: st.id, fixture, runUUID: evidence.runUUID, status: 'FAIL',
              failures: [`scenario error: ${String(error.message).slice(0, 300)}`] });
          }
          await s.close().catch(() => {});
        }
        if (process.env.CHECK_BROWSER_TIMING) process.stderr.write(`${fixture} ${Date.now() - fixtureStarted}ms\n`);
        return rows.rows;
      }
      const s = new Session(env);
      let scenario;
      try {
        scenario = await S[fixture](s);
      } catch (error) {
        for (const st of states) rows.rows.push({ id: st.id, fixture, runUUID: evidence.runUUID, status: 'FAIL',
          failures: [`scenario error: ${String(error.message).slice(0, 300)}`] });
        await s.close().catch(() => {});
        return rows.rows;
      }
      for (const st of states) {
        try {
          await screenshotRow(env, s, st, scenario, rows);
        } catch (error) {
          rows.rows.push({ id: st.id, fixture, runUUID: evidence.runUUID, status: 'FAIL',
            failures: [`capture error: ${String(error.message).slice(0, 300)}`] });
        }
      }
      if (scenario.after) {
        try { await scenario.after(); } catch (error) { scenario.c.after = `error ${String(error.message).slice(0, 120)}`; }
        const late = Object.entries(scenario.c).filter(([, v]) => v !== 'pass');
        if (late.length) for (const row of rows.rows) {
          row.status = 'FAIL';
          row.failures = [...(row.failures || []), ...late.map(([k, v]) => `${k}: ${v}`)];
        }
      }
      await s.close();
      if (process.env.CHECK_BROWSER_TIMING) process.stderr.write(`${fixture} ${Date.now() - fixtureStarted}ms\n`);
      return rows.rows;
    };
    await Promise.all(lanes.map(async (lane) => {
      while (queue.length) {
        const [fixture, states] = queue.shift();
        results.set(fixture, await runFixture(lane, fixture, states));
      }
    }));
    for (const fixture of byFixture.keys()) evidence.rows.push(...results.get(fixture));
    evidence.designControls = only ? {} : await designControls(lanes[0]);
  } finally {
    await browser.close();
    for (const lane of lanes) {
      for (const server of lane.servers) server.kill('SIGTERM');
      lane.upstream.close();
    }
  }
  evidence.finishedAt = new Date().toISOString();
  evidence.durationMs = Date.now() - started;
  const errors = judge(expectedIds, evidence, digests(), screens, declared.states);
  evidence.judgeControls = process.env.CHECK_BROWSER_ONLY ? {}
    : judgeControls(expectedIds, evidence, digests(), screens, declared.states);
  const badControls = Object.entries({ ...evidence.designControls, ...evidence.judgeControls })
    .filter(([, v]) => !['rejected', 'accepted'].includes(v));
  evidence.result = errors.length === 0 && badControls.length === 0 ? 'PASS' : 'FAIL';
  evidence.errors = [...errors, ...badControls.map(([k, v]) => `control ${k}: ${v}`)];
  evidence.counts = { required: expectedIds.length, rows: evidence.rows.length,
    passed: evidence.rows.filter((r) => r.status === 'PASS').length };
  fs.writeFileSync(evidencePath, JSON.stringify(evidence, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 2) + '\n');
  console.log(JSON.stringify({ suite: 'check-browser', result: evidence.result, ...evidence.counts,
    errors: evidence.errors.slice(0, 20) }));
  return evidence.result === 'PASS' ? 0 : 1;
}

module.exports = { judge, assertLayout, compareReference, Session, startUpstream, startServe, freePort, S };

if (require.main === module) {
  main().then((code) => process.exit(code), (error) => { console.error(error.stack || error.message); process.exit(1); });
}
