// Real Chromium DOM + IndexedDB reload + WebCrypto, scripted SignClient, no live relay/phone/wallet.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { build } from 'esbuild';
import { chromium } from 'playwright';
import { v, expected, VECTOR_CLOCK } from './support/safe-fixtures.mjs';

test('reload retains unsigned evidence, explicit recovery returns verified original result without sign or submit', async () => {
  const record = { version: 1, purpose: 'safe-tx-v1.5.0', requestId: JSON.parse(v.request.envelope).id,
    envelope: v.request.envelope, context: v.context.result, expected };
  const entry = `import { mountRecoveryPanel } from './recovery-panel.js';
    import { SavedResultStore } from './saved-result-store.js';
    import QR from './qr.js';
    const fixture = ${JSON.stringify({ record, result: v.result.result, now: VECTOR_CLOCK })};
    const store = new SavedResultStore(); window.store = store;
    window.seed = () => store.save(fixture.record); window.calls = [];
    const topic = 'fresh-recovery-topic';
    const client = { on() {}, off() {}, disconnect: async () => {},
      connect: async (p) => { window.calls.push(p); return {
        uri: 'wc:' + 'ab'.repeat(32) + '@2?relay-protocol=irn&symKey=' + 'cd'.repeat(32),
        approval: async () => { await new Promise(resolve => window.approve = resolve); return ({ topic, expiry: fixture.now + 300,
          peer: { metadata: { url: fixture.record.expected.origin } },
          namespaces: { eip155: { accounts: ['eip155:137:' + fixture.record.expected.signer],
            methods: ['p256_getSessionContext', 'p256_recoverSafeResult'], events: [] } } }); } }; },
      request: async (p) => { window.calls.push(p); return p.request.method === 'p256_getSessionContext'
        ? { ...fixture.record.context, binding: '0x' + '77'.repeat(32) } : fixture.result; } };
    window.panel = mountRecoveryPanel(document, document.querySelector('main'), {
      purpose: fixture.record.purpose, store, getExpected: () => fixture.record.expected,
      getClient: async () => client, clock: () => fixture.now,
      loadQR: async () => QR,
      adopted: async (r, value) => { window.recovered = { id: r.requestId, result: value.result }; return true; } });`;
  const bundle = (await build({ stdin: { contents: entry, resolveDir: new URL('..', import.meta.url).pathname },
    bundle: true, format: 'esm', write: false, platform: 'browser', logLevel: 'silent' })).outputFiles[0].text;
  const styles = readFileSync(new URL('../styles.css', import.meta.url));
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', req.url === '/app.js' ? 'text/javascript' : req.url === '/styles.css' ? 'text/css' : 'text/html');
    res.end(req.url === '/app.js' ? bundle : req.url === '/styles.css' ? styles : '<!doctype html><meta name="viewport" content="width=device-width"><link rel="stylesheet" href="/styles.css"><main></main><script type="module" src="/app.js"></script>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_EXECUTABLE_PATH });
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    const errors = [], external = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.route('**/*', (route) => {
      if (new URL(route.request().url()).hostname !== '127.0.0.1') { external.push(route.request().url()); return route.abort(); }
      return route.continue();
    });
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.waitForFunction(() => Boolean(window.panel));
    await page.evaluate(() => window.seed());
    await page.reload();
    await page.getByRole('button', { name: '保存した要求を読み込む', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('select').options.length === 1);
    assert.deepEqual(await page.evaluate(() => window.calls), []);
    assert.equal(await page.evaluate(() => window.recovered), undefined);
    const saved = await page.evaluate(() => window.store.list());
    assert.deepEqual(saved, [record]);
    assert.ok(!JSON.stringify(saved).includes('signerSignature'));
    await page.getByRole('button', { name: '回収専用でiPhoneに接続', exact: true }).click();
    const qr = page.locator('canvas');
    const download = page.getByRole('button', { name: 'QRをダウンロード', exact: true, includeHidden: true });
    await page.waitForFunction(() => Boolean(window.approve));
    const { checkQRDownload } = await import('./support/qr-download.mjs');
    await qr.evaluate(c => c.id = 'recovery-qr');
    await checkQRDownload(page, 'recovery-qr');
    assert.equal((await page.evaluate(() => window.calls)).length, 1, 'export does not call the peer');
    await page.evaluate(() => window.approve());
    await page.waitForFunction(() => document.querySelector('main > [role=status]').textContent.startsWith('接続しました'));
    assert.equal(await download.isDisabled(), true);
    assert.equal(await qr.evaluate(c => c.getContext('2d').getImageData(0, 0, 256, 256).data.every(x => x === 0)), true);
    await page.getByRole('button', { name: '現在の接続情報を確認', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('main > [role=status]').textContent.startsWith('照合しました'));
    await page.getByRole('button', { name: '保存済み結果を要求', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('main > [role=status]').textContent.startsWith('署名検証済み・未実行'));
    assert.deepEqual(await page.evaluate(() => window.recovered.result), v.result.result);
    assert.ok((await page.evaluate(() => window.calls)).every((p) => !/sign|send/i.test(p.request?.method ?? '')));
    assert.deepEqual(await page.evaluate(() => window.store.list()), [record]);
    await page.getByRole('button', { name: '回収接続を閉じる', exact: true }).click();
    await page.getByRole('button', { name: '回収専用でiPhoneに接続', exact: true }).click();
    await page.waitForFunction(() => !document.querySelector('canvas + button').disabled);
    const beforeClose = await page.evaluate(() => window.calls.length);
    await page.getByRole('button', { name: '回収接続を閉じる', exact: true }).click();
    assert.equal(await download.isDisabled(), true);
    assert.equal(await qr.evaluate(c => c.getContext('2d').getImageData(0, 0, 256, 256).data.every(x => x === 0)), true);
    await page.evaluate(() => window.approve());
    assert.equal(await download.isDisabled(), true);
    assert.equal(await page.evaluate(() => window.calls.length), beforeClose, 'cancel/late approval adds no request');
    assert.deepEqual(errors, []); assert.deepEqual(external, []);
    await page.screenshot({ path: 'artifacts/cold-recovery-browser-diagnostic.png', fullPage: true });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.screenshot({ path: 'artifacts/cold-recovery-browser-verified.png', fullPage: true });
  } finally { await browser?.close(); server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
});
