// Real HTTPS, real bundled SDK, read-only RPC; never approve, sign or submit.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { checkQRDownload } from './support/qr-download.mjs';

const base = 'https://p256-signer.tumf.dev/';
const browser = await chromium.launch();
const context = await browser.newContext({ acceptDownloads: true });
try {
  const page = await context.newPage();
  const errors = [];
  let originRefused = false;
  const devtools = await context.newCDPSession(page);
  await devtools.send('Network.enable');
  devtools.on('Network.webSocketFrameReceived', event => {
    try {
      const message = JSON.parse(event.response.payloadData);
      if (message.error?.code === 3000 && message.error?.message === 'Unauthorized: origin not allowed') originRefused = true;
    } catch {}
  });
  page.on('pageerror', e => errors.push(e.message));
  for (const route of ['', 'safe-request.html', 'safe-execute.html', 'key-change.html', 'prefund.html']) {
    const response = await page.goto(base + route);
    assert.equal(response.status(), 200, route);
    await page.waitForLoadState('networkidle');
    assert.equal(await page.evaluate(() => isSecureContext), true);
    assert.equal(await page.locator('meta[http-equiv="Content-Security-Policy"]').count(), 1);
    if (['safe-request.html', 'key-change.html', 'prefund.html'].includes(route)) {
      const home = page.getByRole('link', {name:'配備Web', exact:true});
      assert.equal(await home.evaluate(link => link.href), base);
      await home.click();
      await page.waitForURL(base);
      assert.equal(page.url(), base);
    }
  }
  await page.goto(base);
  const config = await page.evaluate(async () => (await fetch('./config.json')).json());
  assert.equal(config.allowedDeploymentOrigin, 'https://p256-signer.tumf.dev');
  assert.match(config.walletConnectProjectId, /^[0-9a-f]{32}$/);
  for (const [host, chainId] of [['polygon-bor-rpc.publicnode.com','0x89'], ['ethereum-rpc.publicnode.com','0x1'],
      ['base-rpc.publicnode.com','0x2105'], ['base-sepolia-rpc.publicnode.com','0x14a34']]) {
    const read = await page.evaluate(async host => {
      const r = await fetch('https://' + host + '/', {
        method: 'POST', headers: {'Content-Type':'application/json'}, credentials:'omit', redirect:'error',
        body: JSON.stringify({jsonrpc:'2.0', id:1, method:'eth_chainId', params:[]}) });
      return r.json();
    }, host);
    assert.equal(read.jsonrpc, '2.0'); assert.equal(read.id, 1); assert.equal(read.result, chainId);
  }
  assert.deepEqual(errors, []);
  console.log('PASS: five real HTTPS routes, three project-home links, secure context, static config and four browser public RPC reads');
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
  try { await page.locator('#pairing:visible').waitFor({timeout:30000}); }
  catch { throw new Error(originRefused ? 'BLOCKED: Reown project refuses https://p256-signer.tumf.dev (Unauthorized: origin not allowed)' : 'Pairing did not open'); }
  const canvas = await page.locator('#pairing canvas').getAttribute('id');
  assert.ok(canvas);
  await checkQRDownload(page, canvas);
  await page.click('#disconnect');
  assert.equal(await page.locator(`#${canvas} + button`).isDisabled(), true);
  assert.deepEqual(errors, []);
  console.log('PASS: five real Pages routes, static config, secure context, live cross-origin read, real SDK pending pairing and PNG download/cancel; no wallet approval/sign/send');
} finally { await context.close(); await browser.close(); }
