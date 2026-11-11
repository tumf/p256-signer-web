// Test-only local Chromium environment for the prefund page: builds dist/ into a temporary directory, serves it through
// the real serve.py handler under the fixed origin, bundles the prefund and key-change page harnesses and provides the
// explicit user steps (real DOM fills/clicks) shared by the rendered inventory and storage suites. Controlled peers only.
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
export const inventory = JSON.parse(readFileSync(path.join(app, 'tests/fixtures/prefund-ui-inventory.json')));
/** Literal frozen v1 attempt bytes (never synthesized from a v2 record at runtime). */
export const v1Fixture = JSON.parse(readFileSync(path.join(app, 'tests/fixtures/prefund-attempt-v1.json')));
let dist, server, port, browser;
const bundles = {};

async function bundle(entry) {
  return (await esbuild.build({ absWorkingDir: app, entryPoints: [entry], bundle: true, format: 'esm', write: false,
    platform: 'browser', target: ['es2022'], logLevel: 'silent',
    define: { 'process.env.NODE_ENV': '"production"', global: 'globalThis' } })).outputFiles[0].text;
}

export async function startBrowser() {
  dist = mkdtempSync(path.join(tmpdir(), 'prefund-page-'));
  const env = { ...process.env, REGISTRATION_DIST: dist };
  delete env.WALLETCONNECT_PROJECT_ID;
  const build = spawnSync(process.execPath, ['build.mjs'], { cwd: app, env, encoding: 'utf8', timeout: 120_000 });
  assert.equal(build.status, 0, build.stderr);
  server = spawn('python3', [path.join(here, 'serve-dist.py'), dist, ORIGIN], { cwd: app, env,
    stdio: ['pipe', 'pipe', 'inherit'] });
  const lines = createInterface({ input: server.stdout });
  port = Number((await new Promise((resolve) => lines.once('line', resolve))).replace('PORT ', ''));
  bundles['/prefund.js'] = await bundle('tests/support/prefund-page-harness.mjs');
  bundles['/key-change.js'] = await bundle('tests/support/key-page-harness.mjs');
  browser = await chromium.launch({ executablePath: process.env.PREFUND_CHROMIUM_EXECUTABLE || undefined });
  return { port, browser, dist };
}

export async function stopBrowser() {
  await browser?.close();
  server?.stdin.end();
  server?.kill();
  if (dist) rmSync(dist, { recursive: true, force: true });
}

export const serverPort = () => port;
export const distDir = () => dist;

/** Browser context for an inventory row: 200% text is the same device at half the CSS viewport (browser zoom). */
export function contextOptions(row) {
  const [width, height] = row.viewport, scale = row.textScale || 1;
  return { viewport: { width: Math.round(width / scale), height: Math.round(height / scale) }, deviceScaleFactor: scale,
    locale: 'ja-JP', colorScheme: 'light', reducedMotion: row.reducedMotion ? 'reduce' : 'no-preference' };
}

/**
 * A page whose fixed-origin requests reach the real handler. Entry scripts are the harnesses unless `real`; `swap`
 * replaces a served page body (negative controls); `styles` replaces styles.css.
 */
export async function open(row, { params = {}, keyParams = {}, real = false, styles = null, swap = null, context = null,
  path: pagePath = '/prefund.html' } = {}) {
  const ctx = context || await browser.newContext(contextOptions(row));
  const page = await ctx.newPage();
  const external = [], errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.addInitScript((p) => {
    window.__PREFUND_HARNESS__ = !p.real; window.__KEY_CHANGE_HARNESS__ = !p.real;
    window.__prefundHarnessParams = p.params; window.__keyHarnessParams = p.keyParams;
  }, { params, keyParams, real });
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== ORIGIN) { external.push(url.origin); return route.abort(); }
    if (!real && bundles[url.pathname]) {
      return route.fulfill({ body: bundles[url.pathname], contentType: 'text/javascript; charset=utf-8' });
    }
    if (styles !== null && url.pathname === '/styles.css') return route.fulfill({ body: styles, contentType: 'text/css' });
    const response = await route.fetch({ url: `http://127.0.0.1:${port}${swap?.[url.pathname]?.from || url.pathname}` });
    if (swap?.[url.pathname]) return route.fulfill({ response, body: swap[url.pathname].edit(await response.text()) });
    return route.fulfill({ response });
  });
  await page.goto(ORIGIN + pagePath);
  if (!real && !swap) {
    await page.waitForFunction((key) => window[key]?.ready === true, pagePath === '/prefund.html' ? '__ph' : '__kh');
  }
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
export const ph = (page, fn, arg) => page.evaluate(fn, arg);
export const view = (page) => page.evaluate(() => {
  const v = window.__ph.controller.view();
  return JSON.parse(JSON.stringify({ row: v.row, attempt: { sending: v.attempt.sending, status: v.attempt.record?.status ?? null,
    outcome: v.attempt.outcome?.view ?? null, reconciling: v.attempt.reconciling } }));
});

// ---------------------------------------------------------------------------------------------------------------
// Explicit user steps through the real DOM

export async function inspected(page, which = 'authority') {
  await page.fill('#authority', await ph(page, (w) => window.__ph.text[w], which));
  await page.click('#inspect');
  await page.waitForFunction(() => !['PF01-initial', 'PF03-reading'].includes(document.querySelector('main').dataset.row));
}
export async function shortage(page, fee = '1') {
  await inspected(page);
  await page.fill('#fee', fee);
}
export async function walletConnected(page, choice = 'legacy') {
  await shortage(page);
  await page.check(`#wallet-choices input[value="${choice}"]`);
  await page.click('#wallet-connect');
  await page.waitForFunction(() => /^PF1[0-2]/.test(document.querySelector('main').dataset.row));
}
/** A complete review with a connected Polygon wallet: the explicit send button is the only remaining app step. */
export async function reviewed(page) {
  await walletConnected(page);
  await until(page, 'PF12-ready');
  await page.locator('#send:not([disabled])').waitFor();
}
export async function sent(page, setup = null) {
  await reviewed(page);
  if (setup) await ph(page, setup);
  await page.click('#send');
  await page.waitForFunction(() => window.__ph.controller.view().attempt.sending === false
    && window.__ph.controller.view().attempt.record !== null);
}
export async function reconcile(page) {
  await page.click('#reconcile');
  await page.waitForFunction(() => !window.__ph.controller.view().attempt.reconciling
    && window.__ph.controller.view().attempt.outcome !== null);
}
/** Sends with `setup`, mines one more block, runs `after` in the page and reconciles. */
export async function reconciled(page, { setup = null, after = null } = {}) {
  await sent(page, setup);
  await ph(page, () => window.__ph.chain.mine());
  if (after) await ph(page, after);
  await reconcile(page);
}
/**
 * Writes the literal v1 bytes `v1Fixture.valid[kind]` into the dedicated store's unchanged version-1 wrapper and
 * reloads (zero wallet calls). `chainTx` then gives the reloaded fixture chain the historical v1 wallet's own
 * transaction for that record (its saved caps), mined with one more confirmation block.
 */
export async function legacyRecord(page, kind, chainTx = null) {
  const raw = v1Fixture.valid[kind];
  await page.evaluate((value) => new Promise((resolve, reject) => {
    const r = indexedDB.open('p256.entrypoint-prefund.attempts', 1);
    r.onerror = reject;
    r.onsuccess = () => { const tx = r.result.transaction('state', 'readwrite');
      tx.objectStore('state').put({ version: 1, revision: 3, raw: value }, 'current');
      tx.oncomplete = () => { r.result.close(); resolve(); }; tx.onerror = reject; };
  }), raw);
  await page.reload();
  await page.waitForFunction(() => window.__ph?.ready === true);
  if (chainTx) {
    const record = JSON.parse(raw);
    await ph(page, ({ record: r, options }) => {
      const k = window.__ph;
      k.chain.submitDeposit({ from: r.walletAccount, to: r.entryPoint, value: '0x' + BigInt(r.amount).toString(16),
        data: '0xb760faf9' + '00'.repeat(12) + r.signer.slice(2), gas: '0x' + BigInt(r.outerGasLimit).toString(16),
        maxFeePerGas: '0x' + BigInt(r.outerMaxFeePerGas).toString(16),
        maxPriorityFeePerGas: '0x' + BigInt(r.outerMaxPriorityFeePerGas).toString(16), chainId: '0x89' },
      { hash: r.transactionHash, nonce: Number(r.walletPendingNonce), ...options,
        gasUsed: options.gasUsed !== undefined ? BigInt(options.gasUsed) : undefined });
      k.chain.mine();
      if (options.txNonce !== undefined) k.chain.state.txs.get(r.transactionHash).nonce = options.txNonce;
    }, { record, options: chainTx });
  }
}
export const reloadAfter = (prepare) => async (page) => {
  await prepare(page);
  await page.reload();
  await page.waitForFunction(() => window.__ph?.ready === true);
};
/** Holds the next call of `kind` ('eth_getTransactionCount' relay method, 'cas' or 'eth_chainId' wallet check). */
export async function holdNext(page, kind) {
  await ph(page, (k) => {
    if (k === 'cas') window.__ph.holdCas = true;
    else if (k === 'eth_chainId') window.__ph.provider.holdChain = true;
    else window.__ph.holdMethod = k;
  }, kind);
}
export const waitHeld = (page, name) => page.waitForFunction((n) => Boolean(window.__ph.holds[n]), name);
export const release = (page, name) => ph(page, (n) => window.__ph.release(n), name);
