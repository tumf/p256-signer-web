// Local browser export only. Synthetic pairing text never reaches a relay or wallet.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { build } from 'esbuild';
import { chromium } from 'playwright';
import { PNG } from 'pngjs';

const uri = (n) => `wc:${n.repeat(64)}@2?relay-protocol=irn&symKey=${'0'.repeat(64)}`;

test('local PNG export: current pixels, keyboard, replacement, stale work, errors and pagehide', async () => {
  const bundle = (await build({ stdin: { contents: `
    import { mountPairingQR } from './pairing-qr.js';
    import QR from './qr.js';
    window.pending = [];
    window.draw = mountPairingQR(document, document.querySelector('canvas'), async () => ({
      async toCanvas(canvas, uri, options) {
        if (window.failQR) throw Error('sensitive error must not be shown');
        await QR.toCanvas(canvas, uri, options);
        if (window.holdQR) await new Promise(resolve => pending.push(resolve));
      }
    }));`, resolveDir: new URL('..', import.meta.url).pathname }, bundle: true,
    platform: 'browser', format: 'esm', write: false })).outputFiles[0].text;
  const server = createServer((req, res) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; img-src 'self'; base-uri 'none'; object-src 'none'");
    res.setHeader('Content-Type', req.url === '/test.js' ? 'text/javascript' : 'text/html');
    res.end(req.url === '/test.js' ? bundle : '<!doctype html><meta charset="utf-8"><canvas width="256" height="256"></canvas><a href="#">fallback</a><script type="module" src="/test.js"></script>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch();
  const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  const errors = [], logs = [], external = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => logs.push(m.text()));
  await page.route('**/*', route => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    external.push('external-request'); return route.abort();
  });
  try {
    await page.goto(origin);
    await page.waitForFunction(() => window.draw);
    const button = page.getByRole('button', { name: 'QRをダウンロード' });
    assert.equal(await button.isDisabled(), true);
    await page.evaluate(value => draw(value), uri('1'));
    assert.equal(await button.isEnabled(), true);
    assert.match(await page.locator('body').innerText(), /接続情報.*共有せず/);
    const expected = await page.locator('canvas').evaluate(c => c.toDataURL('image/png'));
    const event = page.waitForEvent('download');
    await button.focus(); await page.keyboard.press('Enter');
    const download = await event;
    assert.equal(download.suggestedFilename(), 'walletconnect-qr.png');
    const bytes = readFileSync(await download.path());
    assert.deepEqual(bytes, Buffer.from(expected.split(',')[1], 'base64'));
    if (process.env.QR_DOWNLOAD_EVIDENCE_PATH) writeFileSync(process.env.QR_DOWNLOAD_EVIDENCE_PATH, bytes);
    const png = PNG.sync.read(bytes);
    assert.equal(png.width, 256); assert.equal(png.height, 256);
    assert.equal(png.data[3], 255); // Opaque white quiet zone, not transparent black.
    assert.ok(png.data.some((v, i) => i % 4 !== 3 && v === 0));
    await download.delete();
    assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);

    // A renderer already holding encoded bytes cannot overwrite B after replacement.
    await page.evaluate(value => { window.holdQR = true; void draw(value); }, uri('2'));
    await page.waitForFunction(() => pending.length === 1);
    assert.equal(await button.isDisabled(), true);
    await page.evaluate(value => { window.holdQR = false; return draw(value); }, uri('3'));
    const newer = await page.locator('canvas').evaluate(c => c.toDataURL());
    assert.notEqual(newer, expected);
    await page.evaluate(() => pending.shift()());
    assert.equal(await page.locator('canvas').evaluate(c => c.toDataURL()), newer);
    await page.evaluate(() => draw(null));
    assert.equal(await button.isDisabled(), true);
    assert.equal(await page.locator('canvas').evaluate(c => c.getContext('2d').getImageData(0, 0, 256, 256).data.every(x => x === 0)), true);

    await page.evaluate(value => { window.failQR = true; return draw(value); }, uri('4'));
    assert.equal(await button.isDisabled(), true);
    assert.match(await page.getByRole('status').innerText(), /生成できません/);
    assert.equal(await page.getByRole('link', { name: 'fallback' }).isVisible(), true);
    assert.ok(!await page.locator('body').innerText().then(t => t.includes('sensitive')));
    await page.evaluate(value => { window.failQR = false; return draw(value); }, uri('5'));
    await page.evaluate(() => { document.querySelector('canvas').toDataURL = () => { throw Error('secret'); }; });
    await button.click();
    assert.match(await page.getByRole('status').innerText(), /保存できません/);
    await page.evaluate(() => { delete document.querySelector('canvas').toDataURL; });
    await page.evaluate(value => { window.holdQR = true; void draw(value); }, uri('6'));
    await page.waitForFunction(() => pending.length === 1);
    await page.evaluate(() => { dispatchEvent(new Event('pagehide')); pending.shift()(); });
    assert.equal(await button.isDisabled(), true);
    assert.deepEqual(errors, []); assert.deepEqual(logs, []); assert.deepEqual(external, []);
  } finally {
    await context.close(); await browser.close(); await new Promise(resolve => server.close(resolve));
  }
});
