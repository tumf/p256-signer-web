import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

export async function checkQRDownload(page, canvasId) {
  const canvas = page.locator('#' + canvasId);
  const button = page.locator(`#${canvasId} + button`);
  await button.waitFor({ state: 'visible' });
  await page.waitForFunction(id => !document.getElementById(id).nextElementSibling.disabled, canvasId);
  const expected = await canvas.evaluate(c => c.toDataURL('image/png'));
  const event = page.waitForEvent('download');
  await button.focus(); await page.keyboard.press('Enter');
  const download = await event;
  assert.equal(download.suggestedFilename(), 'walletconnect-qr.png');
  assert.deepEqual(readFileSync(await download.path()), Buffer.from(expected.split(',')[1], 'base64'));
  await download.delete();
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
}
