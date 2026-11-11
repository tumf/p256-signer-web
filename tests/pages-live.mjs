// Real HTTPS, real bundled SDK, read-only RPC; never approve, sign or submit.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { checkQRDownload } from './support/qr-download.mjs';

const base = 'https://tumf.github.io/p256-signer-web/';
const browser = await chromium.launch();
const context = await browser.newContext({ acceptDownloads: true });
try {
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  for (const route of ['', 'safe-request.html', 'safe-execute.html', 'key-change.html', 'prefund.html']) {
    const response = await page.goto(base + route);
    assert.equal(response.status(), 200, route);
    await page.waitForLoadState('networkidle');
    assert.equal(await page.evaluate(() => isSecureContext), true);
    assert.equal(await page.locator('meta[http-equiv="Content-Security-Policy"]').count(), 1);
  }
  await page.goto(base);
  const config = await page.evaluate(async () => (await fetch('./config.json')).json());
  assert.equal(config.allowedDeploymentOrigin, 'https://tumf.github.io');
  assert.match(config.walletConnectProjectId, /^[0-9a-f]{32}$/);
  const read = await page.evaluate(async () => {
    const r = await fetch('https://polygon-bor-rpc.publicnode.com/', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'omit',
      body: JSON.stringify({jsonrpc:'2.0', id:1, method:'eth_chainId', params:[]}) });
    return r.json();
  });
  assert.equal(read.result, '0x89');
  // Open a genuine pending SignClient pairing with a fresh synthetic public handoff.
  const { freshSigner } = await import('./support/safe-fixtures.mjs');
  const signer = await freshSigner();
  await page.goto(base + 'safe-request.html');
  await page.fill('#handoff', signer.json);
  await page.click('#handoff-check');
  await page.fill('#safe', '0x' + '11'.repeat(20));
  await page.fill('#recipient', '0x' + '22'.repeat(20));
  await page.fill('#value', '1');
  await page.fill('#nonce', '0');
  await page.click('#connect');
  await page.locator('#pairing:visible').waitFor({timeout:30000});
  const canvas = await page.locator('#pairing canvas').getAttribute('id');
  assert.ok(canvas);
  await checkQRDownload(page, canvas);
  await page.click('#disconnect');
  assert.equal(await page.locator(`#${canvas} + button`).isDisabled(), true);
  assert.deepEqual(errors, []);
  console.log('PASS: five real Pages routes, static config, secure context, live cross-origin read, real SDK pending pairing and PNG download/cancel; no wallet approval/sign/send');
} finally { await context.close(); await browser.close(); }
