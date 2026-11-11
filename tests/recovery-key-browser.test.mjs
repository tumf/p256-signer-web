// Real Chromium renderer + native IndexedDB/reload; scripted SDK/chain/wallet only, never live transport.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';
import { chromium } from 'playwright';

const app = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sources = ['key-controller.js', 'key-change.js', 'recovery-session.js', 'recovery-panel.js',
  'saved-result-store.js', 'key-model.js', 'chains.js', 'key-reader.js', 'key-session.js', 'key-attempt-store.js', 'wallet.js',
  'key-change.html', 'tests/support/key-page-harness.mjs', 'tests/support/key-chain.mjs',
  'tests/support/key-fixtures.mjs', 'tests/recovery-key-browser.test.mjs'];
const hashes = () => Object.fromEntries(sources.map((p) => [p,
  createHash('sha256').update(readFileSync(path.join(app, p))).digest('hex')]));
const executablePath = process.env.CHROMIUM_EXECUTABLE_PATH || [
  '/Users/tumf/Library/Caches/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-mac-arm64/chrome-headless-shell',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].find(existsSync);
let browser, server, origin, initialHashes;

before(async () => {
  assert.ok(executablePath, 'existing Chromium executable required');
  initialHashes = hashes();
  const bundle = (await esbuild.build({ absWorkingDir: app, entryPoints: ['tests/support/key-page-harness.mjs'],
    bundle: true, format: 'esm', write: false, platform: 'browser', target: ['es2022'], logLevel: 'silent',
    define: { 'process.env.NODE_ENV': '"production"', global: 'globalThis' } })).outputFiles[0].text;
  const files = { '/key-change.html': [readFileSync(path.join(app, 'key-change.html')), 'text/html'],
    '/key-change.js': [bundle, 'text/javascript'], '/styles.css': [readFileSync(path.join(app, 'styles.css')), 'text/css'] };
  server = http.createServer((req, res) => {
    const file = files[req.url];
    res.writeHead(file ? 200 : 404, { 'Content-Type': file?.[1] || 'text/plain', 'Cache-Control': 'no-store' });
    res.end(file?.[0]);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ executablePath });
  console.log(JSON.stringify({ browser: browser.version(), executablePath, sourceHashes: initialHashes }));
});
after(async () => {
  await browser?.close();
  if (server) await new Promise((resolve) => server.close(resolve));
  if (initialHashes) assert.deepEqual(hashes(), initialHashes, 'reviewed sources changed during execution');
});

const wait = (p, fn) => p.waitForFunction(fn, undefined, { timeout: 10_000 });
const button = (p, name) => p.locator('#saved-recovery').getByRole('button', { name, exact: true });
const names = { load: '保存した要求を読み込む', connect: '回収専用でiPhoneに接続', inspect: '現在の接続情報を確認',
  recover: '保存済み結果を要求', close: '回収接続を閉じる' };
async function inputs(p) {
  await p.evaluate(() => window.__kh.chain.mine());
  await p.fill('#anchor', await p.evaluate(() => window.__kh.text.anchor1));
  await p.click('#inspect');
  await wait(p, () => window.__kh.controller.s.inspection.phase === 'ready');
  await p.fill('#bare-key', await p.evaluate(() => window.__kh.text.bare3));
  await p.fill('#fee-max', '1');
  await p.fill('#fee-priority', '1');
}

async function cold(t) {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  const external = [], errors = [];
  await context.route('**/*', (route) => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    external.push(route.request().url()); return route.abort();
  });
  await context.routeWebSocket('**/*', (socket) => { external.push(socket.url()); socket.close(); });
  const page = await context.newPage();
  page.on('pageerror', (e) => errors.push(e.message));
  await page.addInitScript(() => { window.__KEY_CHANGE_HARNESS__ = true; window.__keyHarnessParams = { keys: 'two' }; });
  t.after(async () => {
    try {
      assert.deepEqual(external, [], 'no external HTTP/WebSocket attempts');
      assert.deepEqual(errors, [], 'no renderer errors');
      assert.equal(await page.evaluate(() => window.__kh.peer.signs), 0, 'zero new signatures after reload');
      assert.deepEqual(await page.evaluate(() => window.__kh.controller.savedResultStore.list()), original.records,
        'retained unsigned evidence remains byte-identical');
    } finally { await context.close(); }
  });
  await page.goto(origin + '/key-change.html');
  await wait(page, () => window.__kh?.ready);
  await inputs(page);
  await page.evaluate(() => {
    const k = window.__kh, sign = k.peer.sign.bind(k.peer);
    k.peer.sign = async (envelope) => (window.__originalResult = await sign(envelope));
  });
  await page.click('#connect');
  await wait(page, () => window.__kh.controller.s.native.phase === 'connected');
  await page.click('#preview');
  await wait(page, () => window.__kh.controller.s.native.phase === 'preview');
  await page.click('#sign');
  await wait(page, () => window.__kh.controller.s.native.phase === 'verified');
  const original = await page.evaluate(async () => ({ result: window.__originalResult,
    records: await window.__kh.controller.savedResultStore.list(), signs: window.__kh.peer.signs }));
  assert.equal(original.signs, 1, 'one original disposable software signature');
  assert.equal(original.records.length, 1);
  await page.reload();
  await wait(page, () => window.__kh?.ready);
  assert.deepEqual(await page.evaluate(() => ({ signs: window.__kh.peer.signs,
    calls: window.__kh.native.client.calls.length, sends: window.__kh.provider.sends.length,
    signed: window.__kh.controller.s.native.signed })), { signs: 0, calls: 0, sends: 0, signed: null },
  'reload restores evidence only, no authority or requests');
  await inputs(page);
  await page.evaluate(({ result, record }) => {
    const k = window.__kh, handlers = {}, methods = ['p256_getKeyChangeContext', 'p256_recoverKeyChangeResult'];
    const fixture = window.__recovery = { handlers, methods, calls: [], result, record, hold: false, pending: false };
    fixture.client = {
      on(n, fn) { (handlers[n] ||= []).push(fn); },
      off(n, fn) { handlers[n] = (handlers[n] || []).filter((f) => f !== fn); },
      async disconnect() {
        if (fixture.holdDisconnect) await new Promise((resolve) => {
          fixture.disconnectPending = true; fixture.releaseDisconnect = resolve;
        });
      },
      async connect({ requiredNamespaces }) {
        fixture.calls.push(['connect', requiredNamespaces]);
        if (JSON.stringify(requiredNamespaces.eip155.methods) !== JSON.stringify(methods)) throw new Error('grant');
        fixture.approved = { topic: 'browser-review-only', expiry: k.controller.now() + 300,
          peer: { metadata: { url: record.context.origin } }, namespaces: { eip155: {
            accounts: [`eip155:137:${record.context.signer}`], methods, events: [] } } };
        return { approval: async () => fixture.approved };
      },
      async request({ request }) {
        fixture.calls.push([request.method, request.params]);
        if (request.method === methods[0]) return { ...await k.peer.context(), binding: '0x' + 'cc'.repeat(32) };
        if (request.method !== methods[1] || request.params[0] !== record.envelope) throw new Error('unexpected request');
        if (fixture.hold) await new Promise((resolve) => { fixture.release = resolve; fixture.pending = true; });
        return structuredClone(result);
      },
    };
    k.controller.client = fixture.client;
    const adopt = k.controller.adoptRecovered.bind(k.controller);
    k.controller.adoptRecovered = async (...args) => {
      fixture.adoptionEntered = true;
      try { return fixture.adopted = await adopt(...args); }
      finally { fixture.adoptionDone = true; }
    };
  }, { result: original.result, record: original.records[0] });
  await button(page, names.load).click();
  await wait(page, () => document.querySelector('#saved-recovery select').options.length === 1);
  assert.equal(await page.evaluate(() => window.__recovery.calls.length), 0, 'listing is offline');
  await button(page, names.connect).click();
  await wait(page, () => [...document.querySelector('#saved-recovery').querySelectorAll('button')].some(b => b.textContent === '現在の接続情報を確認' && !b.disabled));
  return page;
}
async function recover(p) {
  await button(p, names.inspect).click();
  await button(p, names.recover).click();
}
async function wallet(p) {
  await p.check('#wallet-choices input[value="legacy"]');
  await p.click('#wallet-connect');
  await wait(p, () => window.__kh.controller.sendReady());
  assert.equal(await p.locator('#send').isEnabled(), true);
}
async function rejected(p) {
  assert.deepEqual(await p.evaluate(() => ({ phase: window.__kh.controller.s.native.phase,
    signed: window.__kh.controller.s.native.signed, sends: window.__kh.provider.sends.length,
    send: window.__kh.controller.view().actions.send })), { phase: 'idle', signed: null, sends: 0, send: false });
  assert.equal(await p.locator('#send').isEnabled(), false);
  await p.evaluate(() => window.__kh.controller.send());
  assert.equal(await p.evaluate(() => window.__kh.provider.sends.length), 0);
}
const edits = {
  target: async (p) => p.fill('#bare-key', await p.evaluate(() => {
    const k = window.__kh.many(1)[0];
    return JSON.stringify({ v: '1', kind: 'p256-public-key', publicKey: k.publicKey, keyId: k.keyId });
  })),
  mode: async (p) => {
    await p.check('#mode-remove');
    await p.check(`#remove-choices input[value="${await p.evaluate(() => window.__kh.keys.k2.keyId)}"]`);
  },
  fee: async (p) => { await p.fill('#fee-max', '2'); await p.fill('#fee-priority', '2'); },
};
for (const [edit, change] of Object.entries(edits)) {
  for (const stage of ['connected', 'pending result', 'pending adoption']) {
    test(`R1 ${edit} edit during ${stage} rejects original recovery`, async (t) => {
      const p = await cold(t);
      if (stage === 'pending result') {
        await p.evaluate(() => { window.__recovery.hold = true; });
        await recover(p);
        await wait(p, () => window.__recovery.pending);
      } else if (stage === 'pending adoption') {
        await p.evaluate(() => {
          const k = window.__kh, rpc = k.controller.rpc;
          k.controller.rpc = async (...args) => {
            if (!window.__recovery.rpcPending) await new Promise((resolve) => {
              window.__recovery.rpcPending = true; window.__recovery.releaseRPC = resolve;
            });
            return rpc(...args);
          };
        });
        await recover(p);
        await wait(p, () => window.__recovery.rpcPending);
      }
      await change(p);
      assert.equal(await button(p, names.close).isDisabled(), true, 'edit cancels recovery panel');
      if (stage === 'pending result') await p.evaluate(() => window.__recovery.release());
      if (stage === 'pending adoption') {
        await p.evaluate(() => window.__recovery.releaseRPC());
        await wait(p, () => window.__recovery.adoptionDone);
        assert.equal(await p.evaluate(() => window.__recovery.adopted === true), false);
      }
      await rejected(p);
      assert.ok(await p.evaluate(() => !window.__kh.controller.plan().problem), 'edited plan independently valid');
      await button(p, names.connect).click();
      await wait(p, () => document.querySelector('#saved-recovery > [role=status]').textContent.includes('開始できません'));
      await rejected(p);
    });
  }
}

test('R2 unchanged authority across 31 blocks recovers original bytes and submits exactly once', async (t) => {
  const p = await cold(t);
  await p.evaluate(() => { const k = window.__kh; k.clock.offset += 62; for (let i = 0; i < 31; i++) k.chain.mine(); });
  await recover(p);
  await wait(p, () => window.__kh.controller.s.native.phase === 'verified');
  assert.ok(await p.evaluate(() => {
    const k = window.__kh, s = k.controller.s.native;
    return s.context.blockNumber - BigInt(window.__recovery.record.context.blockNumber) > 30n
      && k.controller.now() < s.signed.request.expiresAt;
  }));
  await wallet(p);
  await p.click('#send');
  await wait(p, () => !window.__kh.controller.s.attempt.sending && window.__kh.provider.sends.length === 1);
  await p.evaluate(async () => { await window.__kh.controller.send(); await window.__kh.controller.send(); });
  assert.equal(await p.evaluate(() => window.__kh.provider.sends.length), 1);
  assert.equal(await p.locator('#send').isEnabled(), false);
  assert.equal(await p.evaluate(() => window.__recovery.calls.filter(([m]) => m === 'p256_recoverKeyChangeResult').length), 1);
});

for (const loss of ['close', 'session_delete', 'session_expire', 'session_update', 'session_event']) {
  test(`R3 ${loss} immediately clears recovered authority and disables renderer Send`, async (t) => {
    const p = await cold(t);
    await recover(p);
    await wait(p, () => window.__kh.controller.s.native.phase === 'verified');
    await wallet(p);
    const immediate = await p.evaluate((loss) => {
      const r = window.__recovery;
      r.lateCallbacks = Object.values(r.handlers).flat();
      r.holdDisconnect = true; // Teardown latency must not delay renderer invalidation.
      if (loss === 'close') [...document.querySelectorAll('#saved-recovery button')]
        .find((b) => b.textContent === '回収接続を閉じる').click();
      else for (const fn of [...r.handlers[loss]]) fn({ topic: r.approved.topic });
      return { signed: window.__kh.controller.s.native.signed, ready: window.__kh.controller.view().actions.send,
        disabled: document.querySelector('#send').disabled };
    }, loss);
    assert.equal(immediate.signed, null, 'same-task memory authority cleared');
    assert.equal(immediate.ready, false, 'same-task Send eligibility cleared');
    assert.equal(await p.locator('#send').isEnabled(), false, 'disabled after event, before teardown resolves');
    assert.equal(await p.evaluate(() => window.__recovery.disconnectPending), true, 'SDK disconnect still pending');
    await p.evaluate(() => { const r = window.__recovery; r.holdDisconnect = false; r.releaseDisconnect(); });
    assert.equal(await p.locator('#send').isEnabled(), false);
    // Late callbacks from the disposed session must not revive it or submit anything.
    await p.evaluate(async () => { const r = window.__recovery;
      for (const fn of r.lateCallbacks) fn({ topic: r.approved.topic });
      await window.__kh.controller.send();
    });
    assert.equal(await p.evaluate(() => window.__kh.provider.sends.length), 0);
    assert.equal(await p.evaluate(() => window.__kh.controller.s.native.signed), null);
    assert.match(await p.locator('#approval-error').textContent(), /接続または応答/);
  });
}

for (const mutation of ['nonce', 'keys', 'policy']) {
  test(`R2 control: changed ${mutation} cannot recover or submit`, async (t) => {
    const p = await cold(t);
    await p.evaluate((mutation) => {
      const k = window.__kh;
      if (mutation === 'nonce') k.chain.state.nonce += 1n;
      if (mutation === 'keys') k.chain.state.keys = [k.keys.k1];
      if (mutation === 'policy') {
        const context = k.peer.context.bind(k.peer);
        k.peer.context = async () => ({ ...await context(), maxFeePerGas: '499000000000' });
      }
    }, mutation);
    await button(p, names.inspect).click();
    await wait(p, () => document.querySelector('#saved-recovery > [role=status]').textContent.includes('一致しません'));
    await rejected(p);
    assert.equal(await p.evaluate(() => window.__recovery.calls.filter(([m]) => m === 'p256_recoverKeyChangeResult').length), 0);
  });
}
