import assert from 'node:assert/strict';
import { test } from 'node:test';
import { startBrowser, stopBrowser, open, ORIGIN } from './support/key-browser.mjs';

test('key-change fragment fills public fields only and malformed input fills neither', async () => {
  await startBrowser();
  try {
    const { page, context, errors } = await open('390x844');
    const texts = await page.evaluate(() => window.__kh.text);
    const encode = (text) => '#key-change=' + Buffer.from(text).toString('base64url');
    for (const [fragment, valid] of [
      [encode(texts.anchor1 + '\n' + texts.bare2), true],
      [encode(texts.anchor1 + '\n{}'), false],
      ['#key-change=invalid!', false],
    ]) {
      await page.goto(ORIGIN + '/key-change.html' + fragment);
      // Fragment-only navigation does not rerun the page bootstrap.
      await page.reload();
      await page.waitForFunction(() => window.__kh?.ready === true);
      assert.equal(await page.locator('#anchor').inputValue(), valid ? texts.anchor1 : '');
      assert.equal(await page.locator('#bare-key').inputValue(), valid ? texts.bare2 : '');
      assert.equal(new URL(page.url()).hash, '');
      assert.deepEqual(await page.evaluate(() => [window.__kh.peer.signs, window.__kh.provider.sends.length]), [0, 0]);
      assert.equal(await page.locator('main').getAttribute('data-row'), 'KW01');
    }
    assert.deepEqual(errors, []);
    await context.close();
  } finally {
    await stopBrowser();
  }
});
