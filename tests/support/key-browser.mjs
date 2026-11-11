// Test-only local Chromium environment for the key-change page: builds dist/ into a temporary directory, serves it
// through the real serve.py handler under the fixed origin, bundles the page harness and provides the explicit user
// steps (real DOM fills/clicks) shared by the rendered inventory and storage suites. Controlled peers only.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';
import { chromium } from 'playwright';

const here = path.dirname(fileURLToPath(import.meta.url));
export const app = path.resolve(here, '../..');
export const ORIGIN = 'https://p256-signer.tumf.dev';
export const inventory = JSON.parse(readFileSync(path.join(app, 'tests/key-ui-inventory.json')));
let dist, server, port, browser, harness;

export async function startBrowser() {
  dist = mkdtempSync(path.join(tmpdir(), 'key-page-'));
  const env = { ...process.env, REGISTRATION_DIST: dist };
  delete env.WALLETCONNECT_PROJECT_ID;
  const build = spawnSync(process.execPath, ['build.mjs'], { cwd: app, env, encoding: 'utf8', timeout: 120_000 });
  assert.equal(build.status, 0, build.stderr);
  server = spawn('python3', [path.join(here, 'serve-dist.py'), dist, ORIGIN], { cwd: app, env,
    stdio: ['pipe', 'pipe', 'inherit'] });
  const lines = createInterface({ input: server.stdout });
  port = Number((await new Promise((resolve) => lines.once('line', resolve))).replace('PORT ', ''));
  harness = (await esbuild.build({ absWorkingDir: app, entryPoints: ['tests/support/key-page-harness.mjs'], bundle: true,
    format: 'esm', write: false, platform: 'browser', target: ['es2022'], logLevel: 'silent',
    define: { 'process.env.NODE_ENV': '"production"', global: 'globalThis' } })).outputFiles[0].text;
  browser = await chromium.launch({ executablePath: process.env.CHROMIUM_EXECUTABLE_PATH || undefined });
  return { port, browser };
}

export async function stopBrowser() {
  await browser?.close();
  server?.stdin.end();
  server?.kill();
  if (dist) rmSync(dist, { recursive: true, force: true });
}

export const serverPort = () => port;

/** A context whose fixed-origin requests reach the real handler; the entry script is the harness unless `real`. */
export async function open(variant, { params = {}, real = false, styles = null, swapPage = null, context = null,
  html = null } = {}) {
  const v = inventory.variants[variant];
  const ctx = context || await browser.newContext({ viewport: { width: v.width, height: v.height },
    deviceScaleFactor: v.deviceScaleFactor, locale: 'ja-JP', colorScheme: 'light',
    reducedMotion: v.reducedMotion ? 'reduce' : 'no-preference' });
  const page = await ctx.newPage();
  const external = [], errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.addInitScript((p) => { window.__KEY_CHANGE_HARNESS__ = !p.real; window.__keyHarnessParams = p.params; },
    { params, real });
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== ORIGIN) { external.push(url.origin); return route.abort(); }
    if (!real && url.pathname === '/key-change.js') {
      return route.fulfill({ body: harness, contentType: 'text/javascript; charset=utf-8' });
    }
    if (styles !== null && url.pathname === '/styles.css') return route.fulfill({ body: styles, contentType: 'text/css' });
    const target = swapPage && url.pathname === '/key-change.html' ? '/safe-request.html' : url.pathname;
    const response = await route.fetch({ url: `http://127.0.0.1:${port}${target}` });
    // Negative controls only: a rewritten production page (e.g. a reinserted outer input or payment checkbox).
    if (html && url.pathname === '/key-change.html') return route.fulfill({ response, body: html(await response.text()) });
    if (swapPage && url.pathname === '/key-change.html') {
      const body = (await response.text()).replaceAll('01 / PUBLIC SIGNER', '01 / SIGNER').replaceAll('02 / TRANSFER', '02 / CHANGE')
        .replaceAll('03 / REQUEST', '03 / APPROVAL').replace('Safe送金の承認を、iPhoneに要求する。', '内部鍵の追加・削除');
      return route.fulfill({ response, body });
    }
    return route.fulfill({ response });
  });
  await page.goto(ORIGIN + '/key-change.html');
  if (!real && !swapPage) await page.waitForFunction(() => window.__kh?.ready === true);
  return { page, context: ctx, external, errors };
}

export const row = (page) => page.locator('main').getAttribute('data-row');
export async function until(page, id, timeout = 5000) {
  try {
    await page.waitForFunction((want) => document.querySelector('main').dataset.row === want, id, { timeout });
  } catch {
    throw new Error(`expected ${id}, saw ${await row(page)}`);
  }
}
export const kh = (page, fn, arg) => page.evaluate(fn, arg);


// ---------------------------------------------------------------------------------------------------------------
// Explicit user steps through the real DOM

export async function anchor(page, which = 'anchor1') {
  // A live chain has a recent head: mine one fixture block now, so a slow (loaded) run never inspects a head older
  // than the reader's 60s freshness window that only reflects when this page was opened.
  await kh(page, () => window.__kh.chain.mine());
  await page.fill('#anchor', await kh(page, (w) => window.__kh.text[w], which));
  await page.click('#inspect');
  await page.waitForFunction(() => !['KW01', 'KW03'].includes(document.querySelector('main').dataset.row));
}
export async function addChange(page, bare = 'bare2', fee = '1') {
  await page.check('#mode-add');
  await page.fill('#bare-key', await kh(page, (w) => window.__kh.text[w], bare));
  await page.fill('#fee-max', fee);
  await page.fill('#fee-priority', fee);
}
export async function removeChange(page, which = 'k2', fee = '1') {
  await page.check('#mode-remove');
  await page.check(`#remove-choices input[value="${await kh(page, (w) => window.__kh.keys[w].keyId, which)}"]`);
  await page.fill('#fee-max', fee);
  await page.fill('#fee-priority', fee);
}
export async function connected(page, change = addChange) {
  await anchor(page);
  await change(page);
  await page.click('#connect');
  await until(page, 'KW11');
}
export async function previewed(page, change = addChange) {
  await connected(page, change);
  await page.click('#preview');
  await page.waitForFunction(() => ['KW12', 'KW13'].includes(document.querySelector('main').dataset.row));
}
export async function verified(page, change = addChange) {
  await previewed(page, change);
  await page.click('#sign');
  await page.waitForFunction(() => document.querySelector('main').dataset.row !== 'KW14'
    && !document.querySelector('#verified').hidden);
}
export async function walletConnected(page, change = addChange, choice = 'legacy') {
  await verified(page, change);
  await page.check(`#wallet-choices input[value="${choice}"]`);
  await page.click('#wallet-connect');
  await page.waitForFunction(() => /^KW(18|20)/.test(document.querySelector('main').dataset.row));
}
/** The one explicit send action (no outer input or payment checkbox exists). */
export async function sent(page, { change = addChange, setup } = {}) {
  await walletConnected(page, change);
  if (setup) await kh(page, setup);
  await page.click('#send');
  await page.waitForFunction(() => window.__kh.controller.view().attempt.sending === false
    && window.__kh.controller.view().attempt.record !== null);
}
export async function reconciled(page, { submit = {}, after, change = addChange } = {}) {
  await sent(page, { change, setup: new Function(`window.__kh.provider.submit = ${JSON.stringify(submit)};`) });
  await kh(page, () => window.__kh.chain.mine());
  if (after) await kh(page, after);
  await page.click('#reconcile');
  await page.waitForFunction(() => !window.__kh.controller.view().attempt.reconciling
    && window.__kh.controller.view().attempt.outcome !== null);
}
export async function reconcileClick(page) {
  await page.click('#reconcile');
  await page.waitForFunction(() => !window.__kh.controller.view().attempt.reconciling
    && window.__kh.controller.view().attempt.outcome !== null);
}
export const unknownThen = (mutate) => async (page) => {
  await sent(page, { setup: () => { window.__kh.provider.sendMode = 'reject'; } });
  await kh(page, mutate);
  await page.click('#reconcile');
  await page.waitForFunction(() => window.__kh.controller.view().attempt.outcome !== null);
};
export const reloadAfter = (prepare) => async (page) => {
  await prepare(page);
  await page.reload();
  await page.waitForFunction(() => window.__kh?.ready === true);
};
/** Rewrites the current attempt into a legacy v1 record (test fixture) and waits until the page adopted it. */
export async function legacy(page, ceilings = {}) {
  const ok = await kh(page, (c) => window.__kh.legacy(c), ceilings);
  assert.equal(ok, true, 'legacy v1 seed');
}
export const tx = (field, value) => new Function(`const k = window.__kh; const h = k.controller.view().attempt.record.transactionHash;
  const t = k.chain.state.txs.get(h); t.${field} = ${value};`);
