// Rendered prefund page in local headless Chromium. The built dist/ is served through the real serve.py handler (real
// CSP) under the fixed origin; every PF child/viewport of tests/fixtures/prefund-ui-inventory.json is driven through the
// actual production renderer, PrefundController, FundingAttemptStore (native IndexedDB) and WalletManager, then judged by
// screenshot plus resolved-style/geometry/action assertions against the row's frozen controller row, version, exact
// message and send enablement. Deleted outer-fee controls, the consent checkbox and every v2 outer-cost/nonce summary
// must be absent; only literal v1 records show labeled read-only legacy evidence. PF24 rows render the production
// key-change page (KW09 link and plain return). Controlled peers only: local Chromium rendering evidence, NOT deployed,
// wallet or EVM evidence.
import assert from 'node:assert/strict';
import { checkQRDownload } from './support/qr-download.mjs';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { BUSY_ROWS, LEGACY_MESSAGES, MESSAGES, isError } from '../prefund-controller.js';
import { MESSAGES as KEY_MESSAGES } from '../key-controller.js';
import {
  ORIGIN, app, inspected, inventory, holdNext, legacyRecord, open, ph, reconcile, reconciled, release, reloadAfter,
  reviewed, sent, serverPort, shortage, startBrowser, stopBrowser, until, waitHeld, walletConnected,
} from './support/prefund-browser.mjs';

const OUT = process.env.PREFUND_UI_OUT || null;
const RUN_ID = process.env.PREFUND_UI_RUN_ID || randomUUID();
const SOURCES = ['prefund.html', 'prefund.js', 'prefund-controller.js', 'prefund-model.js', 'prefund-attempt-store.js',
  'key-change.html', 'key-change.js', 'key-controller.js', 'key-model.js', 'chains.js', 'key-reader.js', 'styles.css',
  'wallet.js',
  'tests/prefund-page.test.mjs', 'tests/fixtures/prefund-ui-inventory.json', 'tests/support/prefund-page-harness.mjs',
  'tests/support/prefund-chain.mjs', 'tests/support/prefund-browser.mjs', 'tests/support/key-page-harness.mjs',
  'tests/fixtures/prefund-attempt-v1.json'];
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const sourceDigest = () => Object.fromEntries(SOURCES.map((name) => [name, sha256(readFileSync(path.join(app, name)))]));
const P1 = (1060000n * 10n ** 9n).toString();
const vkey = (row) => `${row.viewport[0]}x${row.viewport[1]}`;

before(async () => {
  await startBrowser();
  if (OUT) mkdirSync(path.join(OUT, 'screens'), { recursive: true });
});
after(stopBrowser);

test('prefund current wallet QR export without transaction requests', async () => {
  const { page, context, errors, external } = await open({ viewport: [390, 844] });
  try {
    await shortage(page);
    await page.check('#wallet-choices input[value="walletconnect"]'); await page.click('#wallet-connect');
    await checkQRDownload(page, 'wallet-qr');
    assert.equal(await ph(page, () => window.__ph.provider.sends.length), 0);
    await page.click('#wallet-cancel');
    assert.equal(await page.locator('#wallet-qr + button').isDisabled(), true);
    assert.deepEqual(errors, []); assert.deepEqual(external, []);
  } finally { await context.close(); }
});

const submit = (body) => new Function(`window.__ph.provider.submit = { ${body} };`);
const txSet = (field, value) => new Function(`const k = window.__ph; const h = k.controller.view().attempt.record.transactionHash;
  const t = k.chain.state.txs.get(h); t.${field} = ${value};`);
const heldSend = (kind, inject) => async (p) => {
  await reviewed(p);
  await holdNext(p, kind);
  await p.click('#send');
  await waitHeld(p, kind);
  if (inject) { await inject(p); await release(p, kind); }
};
const typeAuthority = async (p, mutate) => {
  await p.fill('#authority', mutate(await ph(p, () => window.__ph.text.authority)));
  await p.click('#inspect');
};
const failInspect = (fn) => async (p) => { await ph(p, fn); await inspected(p); };
const keyAnchor = async (p) => {
  await p.fill('#anchor', await p.evaluate(() => window.__kh.text.anchor1));
  await p.click('#inspect');
  await p.waitForFunction(() => !['KW01', 'KW03'].includes(document.querySelector('main').dataset.row));
  await p.check('#mode-add');
  await p.fill('#bare-key', await p.evaluate(() => window.__kh.text.bare2));
  await p.fill('#fee-max', '1');
  await p.fill('#fee-priority', '1');
};

/**
 * One driver per inventory child: `{row, params?, keyParams?, page?, run(page, session)}`; `row` is the expected
 * controller row and must equal the inventory's frozen `controllerRow`.
 */
const DRIVERS = {
  'PF01-initial': { row: 'PF01-initial', run: async () => {} },
  'PF02-json': { row: 'PF02-json', run: (p) => typeAuthority(p, () => '{"v":"1","kind":"hybrid-key-authority"}') },
  'PF02-point': { row: 'PF02-point', run: (p) => typeAuthority(p, (t) => t.replace(/"publicKey":"0x04([0-9a-f]{4})/, '"publicKey":"0x040000')) },
  'PF02-id': { row: 'PF02-id', run: (p) => typeAuthority(p, (t) => t.replace(/"keyId":"[0-9a-f]{64}"/, `"keyId":"${'c'.repeat(64)}"`)) },
  'PF03-reading': { row: 'PF03-reading', run: async (p) => { await ph(p, () => { window.__ph.chain.delay = 600_000; }); await p.fill('#authority', await ph(p, () => window.__ph.text.authority)); await p.click('#inspect'); } },
  'PF03-cancelled-late': { row: 'PF03-cancelled-late', run: async (p) => {
    await ph(p, () => { window.__ph.chain.delay = 150; });
    await p.fill('#authority', await ph(p, () => window.__ph.text.authority)); await p.click('#inspect');
    await p.click('#inspect-cancel'); await p.waitForTimeout(400);
  } },
  'PF04-rpc': { row: 'PF04-rpc', run: failInspect(() => { window.__ph.chain.fail = () => true; }) },
  'PF04-chain': { row: 'PF04-mismatch', run: failInspect(() => { window.__ph.chain.state.chainId = 1n; }) },
  'PF04-ep-runtime': { row: 'PF04-ep-runtime', run: failInspect(() => { window.__ph.chain.entryPointCode = '0x00'; }) },
  'PF04-signer-runtime': { row: 'PF04-mismatch', run: failInspect(() => { window.__ph.chain.state.implementationCode = '0x00'; }) },
  'PF04-undeployed': { row: 'PF04-mismatch', run: failInspect(() => { window.__ph.chain.state.proxyCode = '0x'; }) },
  'PF04-membership': { row: 'PF04-mismatch', run: failInspect(() => { const k = window.__ph; k.chain.state.keys = [k.keys.k2]; }) },
  'PF04-stale': { row: 'PF04-stale', run: failInspect(() => { window.__ph.chain.state.blocks.at(-1).timestamp -= 1000n; }) },
  'PF04-partial-keys': { row: 'PF04-mismatch', run: failInspect(() => {
    const k = window.__ph, word = (n) => '0x' + n.toString(16).padStart(64, '0');
    k.chain.extraOverride = (method, params, value) => {
      if (method !== 'eth_call') return value;
      if (params[0].data === '0x1c03010a') return word(2n);
      if (params[0].data === '0x2ffeaad6') return '0x' + [word(32n), word(1n), value.slice(-64), word(0n)].map((w) => w.replace(/^0x/, '')).join('');
      return value;
    };
  }) },
  'PF04-block-reorg': { row: 'PF04-mismatch', run: failInspect(() => {
    const k = window.__ph; let seen = 0;
    k.chain.extraOverride = (method, params, value) => {
      if (method === 'eth_getBlockByNumber' && params[0] !== 'latest' && ++seen >= 1) return { ...value, hash: '0x' + '9'.repeat(64) };
      return value;
    };
  }) },
  'PF05-blank-fee': { row: 'PF05-blank-fee', run: (p) => inspected(p) },
  'PF05-format-fee': { row: 'PF05-format-fee', run: (p) => shortage(p, '1.0000000001') },
  'PF05-overflow-fee': { row: 'PF05-overflow-fee', run: (p) => shortage(p, '9'.repeat(41)) },
  'PF06-sufficient': { row: 'PF06-sufficient', params: { deposit: P1 }, run: (p) => shortage(p) },
  'PF07-shortage': { row: 'PF07-shortage', run: (p) => shortage(p) },
  'PF07-shortage-text200': { row: 'PF07-shortage', run: (p) => shortage(p) },
  'PF08-no-provider': { row: 'PF08-no-provider', params: { noWallets: true, walletConfig: 'wrong-origin' }, run: (p) => shortage(p) },
  'PF08-missing-project': { row: 'PF08-missing-project', params: { noWallets: true, walletConfig: 'missing' }, run: (p) => shortage(p) },
  'PF09-pairing': { row: 'PF09-pairing', run: async (p) => { await shortage(p); await p.check('#wallet-choices input[value="walletconnect"]'); await p.click('#wallet-connect'); await p.locator('#wallet-open[href^="wc:"]').waitFor(); } },
  'PF09-cancelled': { row: 'PF09-cancelled', run: async (p) => { await shortage(p); await p.check('#wallet-choices input[value="walletconnect"]'); await p.click('#wallet-connect'); await p.locator('#wallet-open[href^="wc:"]').waitFor(); await p.click('#wallet-cancel'); } },
  'PF09-rejected': { row: 'PF09-rejected', run: async (p) => { await shortage(p); await ph(p, () => { window.__ph.provider.connectMode = 'reject'; }); await p.check('#wallet-choices input[value="legacy"]'); await p.click('#wallet-connect'); } },
  'PF10-wrong-chain': { row: 'PF10-wrong-chain', params: { chainId: '0x1' }, run: (p) => walletConnected(p) },
  'PF10-switch-rejected': { row: 'PF10-switch-rejected', params: { chainId: '0x1' }, run: async (p) => { await walletConnected(p); await ph(p, () => { window.__ph.provider.switchMode = 'refuse'; }); await p.click('#wallet-switch'); } },
  // W < Q (Q = P1 here) refuses at the fresh send-time read; W = Q would be the wallet's decision.
  'PF11-balance-short': { row: 'PF11-balance-short', params: { balance: (BigInt(P1) - 1n).toString() }, focus: 'wallet-error', run: async (p) => { await reviewed(p); await p.click('#send'); }, sends: 0 },
  'PF12-checked': { row: 'PF12-ready', run: (p) => reviewed(p), sends: 0 },
  'PF12-focus': { row: 'PF12-ready', run: (p) => reviewed(p), beforeCapture: focusVariant },
  'PF12-pressed': { row: 'PF12-ready', run: (p) => reviewed(p), beforeCapture: pressedVariant, release: releasePress },
  // A valid inspected review, then an explicit wallet disconnect: the shell stays at PF12-ready with send disabled.
  'PF12-disabled': { row: 'PF12-ready', run: async (p) => { await reviewed(p); await p.click('#wallet-disconnect');
    await p.locator('#send[disabled]').waitFor(); }, after: disabledVariant, sends: 0 },
  'PF12-text200': { row: 'PF12-ready', run: (p) => reviewed(p), sends: 0 },
  'PF13-reading': { row: 'PF13-reading', run: async (p) => { await reviewed(p); await ph(p, () => { window.__ph.chain.delay = 600_000; }); await p.click('#send'); } },
  'PF13-nonce-wait': { row: 'PF13-nonce-wait', run: heldSend('eth_getTransactionCount') },
  'PF13-cas-wait': { row: 'PF13-cas-wait', run: heldSend('cas') },
  'PF13-fee-changed': { row: 'PF13-fee-changed', focus: 'fee', run: heldSend('eth_getTransactionCount', (p) => p.fill('#fee', '2')), sends: 0 },
  'PF13-wallet-lost': { row: 'PF13-wallet-lost', run: heldSend('eth_getTransactionCount', (p) => ph(p, () => window.__ph.provider.emit('accountsChanged', []))), sends: 0 },
  'PF13-reduced-motion': { row: 'PF13-reading', run: async (p) => { await reviewed(p); await ph(p, () => { window.__ph.chain.delay = 600_000; }); await p.click('#send'); } },
  'PF14-reserved': { row: 'PF14-reserved', run: heldSend('eth_chainId'), sends: 0 },
  'PF14-wallet-wait': { row: 'PF14-wallet-wait', run: async (p) => { await reviewed(p); await ph(p, () => { window.__ph.provider.sendMode = 'hang'; }); await p.click('#send'); await p.waitForFunction(() => window.__ph.provider.sends.length === 1); }, sends: 1 },
  'PF15-rejected': { row: 'PF15-rejected', focus: 'result-error', run: (p) => sent(p, () => { window.__ph.provider.sendMode = 'reject'; }), sends: 1 },
  'PF15-error': { row: 'PF15-error', focus: 'result-error', run: (p) => sent(p, () => { window.__ph.provider.sendMode = 'error'; }), sends: 1 },
  'PF15-timeout': { row: 'PF15-timeout', run: (p) => sent(p, () => { const k = window.__ph; k.provider.sendMode = 'hang'; const set = k.controller.setTimer;
    k.controller.setTimer = (fn, ms) => set(fn, ms === 300000 ? 50 : ms); }), sends: 1 },
  'PF15-malformed-hash': { row: 'PF15-malformed-hash', run: (p) => sent(p, () => { window.__ph.provider.sendMode = 'malformed'; }), sends: 1 },
  'PF15-late-hash': { row: 'PF15-late-hash', run: async (p) => {
    await sent(p, () => { const k = window.__ph; k.provider.sendMode = 'hang'; const set = k.controller.setTimer;
      k.controller.setTimer = (fn, ms) => set(fn, ms === 300000 ? 50 : ms); });
    await ph(p, () => window.__ph.provider.release());
  }, sends: 1 },
  'PF16-hash-no-receipt': { row: 'PF16-hash-no-receipt', run: (p) => sent(p, submit('mineBlock: false')), sends: 1 },
  'PF16-one-confirmation': { row: 'PF16-one-confirmation', run: async (p) => { await sent(p); await reconcile(p); }, sends: 1 },
  'PF17-outer-failed': { row: 'PF17-outer-failed', focus: 'result-error', run: (p) => reconciled(p, { setup: submit("status: '0x0', gasUsed: 30000n") }) },
  'PF18-foreign-tuple': { row: 'PF18-foreign-tuple', focus: 'result-error', run: (p) => reconciled(p, { after: txSet('value', "'0x1'") }) },
  'PF18-foreign-log': { row: 'PF18-foreign-log', run: (p) => reconciled(p, { setup: submit("logs: (d) => [{ ...d[0], topics: [d[0].topics[0], '0x' + '00'.repeat(12) + '22'.repeat(20)] }]") }) },
  'PF18-absent-event': { row: 'PF18-absent-event', run: (p) => reconciled(p, { setup: submit('logs: () => []') }) },
  'PF18-duplicate-event': { row: 'PF18-duplicate-event', run: (p) => reconciled(p, { setup: submit('logs: (d) => [d[0], { ...d[0] }]') }) },
  // v2: the actual transaction's priority exceeds its own max fee (no saved ceiling exists to compare against).
  'PF18-wrong-cost': { row: 'PF18-wrong-cost', run: (p) => reconciled(p, { after: txSet('maxPriorityFeePerGas', "'0x' + (BigInt(t.maxFeePerGas) + 1n).toString(16)") }) },
  'PF18-runtime': { row: 'PF18-runtime', run: (p) => reconciled(p, { after: () => { const k = window.__ph; const h = k.controller.view().attempt.record.transactionHash;
    k.chain.historicalCode.set(BigInt(k.chain.state.receipts.get(h).blockNumber), '0x00'); } }) },
  'PF18-reorg': { row: 'PF18-reorg', run: (p) => reconciled(p, { after: () => { const k = window.__ph; const h = k.controller.view().attempt.record.transactionHash;
    k.chain.reorg(BigInt(k.chain.state.receipts.get(h).blockNumber)); } }) },
  // v1 only: the historical record's saved nonce differs from its transaction's actual nonce.
  'PF18-nonce': { row: 'PF18-nonce', run: async (p) => { await legacyRecord(p, 'hashKnown', { txNonce: '0x5' }); await reconcile(p); }, sends: 0 },
  'PF19-success-ready': { row: 'PF19-success-ready', focus: 'outcome-heading', run: (p) => reconciled(p) },
  'PF20-consumed': { row: 'PF20-consumed', focus: 'outcome-heading', run: (p) => reconciled(p, { after: () => { const k = window.__ph; k.chain.state.deposit = 10n; k.chain.mine(); } }) },
  'PF20-read-failed': { row: 'PF20-read-failed', run: (p) => reconciled(p, { after: () => { window.__ph.chain.fail = (m) => m === 'eth_getStorageAt'; } }) },
  'PF20-authority-changed': { row: 'PF20-authority-changed', run: (p) => reconciled(p, { after: () => { const k = window.__ph; k.chain.state.keys = [k.keys.k2]; k.chain.mine(); } }) },
  'PF20-text200': { row: 'PF20-consumed', run: (p) => reconciled(p, { after: () => { const k = window.__ph; k.chain.state.deposit = 10n; k.chain.mine(); } }) },
  'PF21-unavailable': { row: 'PF21-unavailable', params: { storage: 'unavailable' }, run: (p) => shortage(p) },
  'PF21-blocked': { row: 'PF21-blocked', params: { storage: 'blocked' }, run: (p) => shortage(p) },
  'PF21-corrupt': { row: 'PF21-corrupt', run: reloadAfter(async (p) => {
    await p.evaluate(() => new Promise((resolve, reject) => {
      const r = indexedDB.open('p256.entrypoint-prefund.attempts', 1);
      r.onsuccess = () => { const tx = r.result.transaction('state', 'readwrite');
        tx.objectStore('state').put({ version: 1, revision: 4, raw: '{"version":1,"status":"reserved"}' }, 'current');
        tx.oncomplete = () => { r.result.close(); resolve(); }; tx.onerror = reject; };
    }));
  }) },
  'PF21-cas-conflict': { row: 'PF21-conflict', run: async (p, session) => {
    const other = await open(session.row, { context: session.context });
    await reviewed(other.page);
    await reviewed(p);
    await other.page.click('#send');
    await other.page.waitForFunction(() => window.__ph.controller.view().attempt.record !== null);
    await p.click('#send');
    session.otherSends = await other.page.evaluate(() => window.__ph.provider.sends.length);
  }, sends: 0 },
  'PF22-reserved': { row: 'PF22-reserved', run: reloadAfter((p) => sent(p, () => { window.__ph.provider.sendMode = 'reject'; })), sends: 0 },
  'PF22-hashKnown': { row: 'PF22-hashKnown', run: reloadAfter((p) => sent(p, submit('mineBlock: false'))), sends: 0 },
  'PF22-terminal': { row: 'PF22-terminal', run: reloadAfter((p) => reconciled(p)), sends: 0 },
  'PF23-new-attempt': { row: 'PF23-new-attempt', focus: 'authority', run: async (p) => { await reconciled(p); await p.click('#new-funding'); }, sends: 1 },
  // Literal frozen v1 bytes, loaded with zero wallet calls; the success/failure children re-prove them on chain.
  'PF22-v1-reserved': { row: 'PF22-reserved', run: (p) => legacyRecord(p, 'reserved'), sends: 0 },
  'PF22-v1-hashKnown': { row: 'PF22-hashKnown', run: (p) => legacyRecord(p, 'hashKnown'), sends: 0 },
  'PF22-v1-terminal': { row: 'PF22-terminal', run: (p) => legacyRecord(p, 'succeeded'), sends: 0 },
  'PF19-v1-success-ready': { row: 'PF19-success-ready', focus: 'outcome-heading', run: async (p) => { await legacyRecord(p, 'succeeded', {}); await reconcile(p); }, sends: 0 },
  'PF17-v1-outer-failed': { row: 'PF17-outer-failed', focus: 'result-error', run: async (p) => { await legacyRecord(p, 'outerFailed', { status: '0x0', gasUsed: '30000' }); await reconcile(p); }, sends: 0 },
  'PF24-link': { row: 'KW09', page: '/key-change.html', keyParams: { deposit: '0' }, run: keyAnchor },
  'PF24-return-inspect': { row: 'KW01', run: async (p) => {
    await shortage(p);
    await p.click('#back-link');
    await p.waitForFunction(() => window.__kh?.ready === true && document.querySelector('main').dataset.page === 'key-change');
  } },
};

/** Per-row action contract: the enabled primary/secondary control that must be available. */
const ACTION = { PF01: 'inspect', PF02: 'inspect', PF04: 'inspect', PF05: 'fee', 'PF06-sufficient': 'refresh',
  'PF07-shortage': 'wallet-choice', 'PF09-pairing': 'wallet-cancel', 'PF09-cancelled': 'wallet-connect',
  'PF09-rejected': 'wallet-connect', PF10: 'wallet-switch', PF11: 'wallet-disconnect', 'PF12-ready': 'send',
  'PF12-disabled': 'wallet-choice', 'PF03-reading': 'inspect-cancel', 'PF13-fee-changed': 'fee',
  'PF13-wallet-lost': 'wallet-choice', PF15: 'tx-hash', 'PF15-late-hash': 'reconcile', PF16: 'reconcile',
  PF17: 'new-funding', PF18: 'reconcile', PF19: 'new-funding', PF20: 'new-funding', PF22: 'reconcile',
  'PF22-terminal': 'new-funding', 'PF22-reserved': 'tx-hash', 'PF21-unavailable': 'storage-reload', 'PF21-blocked': 'storage-reload',
  'PF21-conflict': 'storage-reload', 'PF23-new-attempt': 'authority' };
const FOCUS_RING = ['solid', '3px', 'rgb(59, 116, 23)', '4px'];
const CUSTODY = '未使用分はSignerのデポジットに残ります。この画面では出金できません。出金には別のSigner承認操作が必要です。';
/** Deleted outer-fee/consent DOM and every outer-cost or substitute copy that must not exist in the production page. */
const REMOVED_IDS = ['outer-form', 'outer-fields', 'outer-gas', 'outer-max', 'outer-priority', 'outer-help', 'consent'];
const REMOVED_COPY = /外側取引の上限|外側ガス代の上限|ウォレットの最大支出|最大支出|ガス上限（整数|優先料 max|同意|最大[0-9０-９.]*POL|実際の支払いは使用量/;
const V2_HIDDEN_COPY = /実際のガス代|ウォレットnonce|nonce|外側ガス上限|優先料|旧形式 v1/;
const INNER_P_NOTE = 'Pは鍵操作1回分の前払いの目安です。今後の手数料や鍵変更の成功を保証しません。ウォレットの外側ガス代とは別です。';

/**
 * Resolved style/geometry/action judge of the CURRENT prefund page for one inventory row (`inv`: its frozen
 * controllerRow, attemptVersion, message and sendEnabled; or a bare `{controllerRow}`). Returns failed checks.
 */
async function judgePrefund(page, inv, driver) {
  const expectedRow = inv.controllerRow;
  const facts = await page.evaluate(() => {
    const css = (el) => getComputedStyle(el);
    const main = document.querySelector('main');
    const visible = (el) => el && !el.hidden && el.offsetParent !== null && el.getBoundingClientRect().height > 0;
    const sections = [...document.querySelectorAll('main > section')];
    const statuses = [...document.querySelectorAll('main .status[role]')].filter(visible)
      .map((el) => ({ id: el.id, role: el.getAttribute('role'), text: el.textContent }));
    const buttons = [...document.querySelectorAll('main button')].filter(visible);
    const targets = [...document.querySelectorAll('main .choice, main input[type=text]')].filter(visible);
    const overflowing = [...document.body.querySelectorAll('*')].filter(visible)
      .filter((el) => el.getBoundingClientRect().right > innerWidth + 0.5 || el.getBoundingClientRect().left < -0.5)
      .map((el) => el.id || el.tagName);
    const clipped = [...main.querySelectorAll('dd, dt, p, label, h1, h2, h3, .status, button, .step, a')].filter(visible)
      .filter((el) => el.scrollWidth > el.clientWidth + 1 && css(el).overflowX !== 'visible').map((el) => el.id || el.tagName);
    const content = sections[0]?.children[1];
    const enabled = (id) => { const el = document.getElementById(id); return Boolean(el && visible(el) && !el.disabled
      && !el.closest('fieldset')?.disabled && !el.readOnly); };
    return {
      row: main.dataset.row, page: main.dataset.page, title: document.querySelector('h1')?.textContent,
      steps: sections.map((s) => s.querySelector('.step')?.textContent), statuses,
      paper: css(document.body).backgroundColor, ink: css(document.body).color, font: css(document.body).fontSize,
      lineHeight: css(document.body).lineHeight, family: css(document.body).fontFamily,
      mainMax: css(main).maxWidth, mainPad: css(main).paddingLeft, display: sections[0] && css(sections[0]).display,
      columns: sections[0] && css(sections[0]).gridTemplateColumns, gap: sections[0] && css(sections[0]).columnGap,
      dl: [...document.querySelectorAll('main dl')].filter(visible).map((d) => css(d).gridTemplateColumns.split(' ')[0]),
      contentWidth: content?.getBoundingClientRect().width,
      h2: css(document.querySelector('h2')).fontSize, h1: parseFloat(css(document.querySelector('h1')).fontSize),
      buttons: buttons.map((b) => ({ id: b.id, h: b.getBoundingClientRect().height, w: b.getBoundingClientRect().width,
        disabled: b.disabled, opacity: css(b).opacity, radius: css(b).borderTopLeftRadius,
        transition: css(b).transitionDuration })),
      targets: targets.map((t) => [t.id || t.className, t.getBoundingClientRect().height]),
      scroll: document.documentElement.scrollWidth, inner: innerWidth, clipped, overflowing,
      text: main.innerText, busy: main.getAttribute('aria-busy'),
      search: location.search, hash: location.hash, path: location.pathname,
      footer: [...document.querySelectorAll('footer a')].map((a) => a.getAttribute('href')),
      back: visible(document.getElementById('back-link')) && document.getElementById('back-link').getAttribute('href'),
      custody: visible(document.getElementById('custody')) ? document.getElementById('custody').textContent : null,
      signerNote: visible(document.getElementById('signer')) ? document.getElementById('signer-note').textContent : null,
      deposit: visible(document.getElementById('deposit')) ? document.getElementById('deposit-list').innerText : null,
      invalid: [...document.querySelectorAll('[aria-invalid="true"]')].map((el) => el.id),
      enabled: Object.fromEntries(['inspect', 'inspect-cancel', 'fee', 'refresh', 'wallet-connect', 'wallet-cancel',
        'wallet-switch', 'wallet-disconnect', 'send', 'tx-hash', 'reconcile', 'new-funding', 'storage-reload',
        'authority'].map((id) => [id, enabled(id)])),
      removed: ['outer-form', 'outer-fields', 'outer-gas', 'outer-max', 'outer-priority', 'outer-help', 'consent']
        .filter((id) => document.getElementById(id)),
      checkboxes: document.querySelectorAll('main input[type=checkbox], main .consent').length,
      describedBy: [...document.querySelectorAll('[aria-describedby]')].flatMap((el) => el.getAttribute('aria-describedby')
        .split(/\s+/)).filter((id) => !document.getElementById(id)),
      html: document.querySelector('main').innerHTML,
      walletTitle: document.getElementById('wallet-title')?.textContent,
      reviewHeading: document.getElementById('review-heading')?.textContent,
      review: visible(document.getElementById('review')) ? document.getElementById('review-list').innerText : null,
      attemptList: visible(document.getElementById('attempt')) ? document.getElementById('attempt-list').innerText : null,
      outcome: visible(document.getElementById('outcome')) ? document.getElementById('outcome-list').innerText : null,
      walletChoice: [...document.querySelectorAll('#wallet-choices input')].some((i) => visible(i) && !i.disabled),
      focus: document.activeElement ? { id: document.activeElement.id, visible: visible(document.activeElement) } : null,
      interaction: (() => { const b = document.getElementById('send'), c = css(b);
        return { focusVisible: b.matches(':focus-visible'), active: b.matches(':active'), disabled: b.disabled,
          transform: c.transform, outline: [c.outlineStyle, c.outlineWidth, c.outlineColor, c.outlineOffset] }; })(),
    };
  });
  const mobile = facts.inner <= 680;
  const family = expectedRow.slice(0, 4);
  const fail = [];
  const check = (name, ok) => { if (!ok) fail.push(name); };
  check(`row:${facts.row}`, facts.row === expectedRow);
  check('page', facts.page === 'prefund' && facts.title === '前払い残高を入金');
  check('sections', JSON.stringify(facts.steps) === JSON.stringify(['01 / SIGNER', '02 / DEPOSIT', '03 / WALLET', '04 / RESULT']));
  const message = inv.message ?? MESSAGES[expectedRow];
  if (inv.message !== undefined) {
    check('frozen-message', message === ((inv.attemptVersion === '1' && LEGACY_MESSAGES[expectedRow]) || MESSAGES[expectedRow]));
  }
  const shown = facts.statuses.filter((s) => s.text === message);
  check('message', typeof message === 'string' && shown.length === 1 && facts.statuses.length === 1);
  check('message-role', shown.length === 1 && shown[0].role === (isError(expectedRow) ? 'alert' : 'status'));
  check('paper', facts.paper === 'rgb(245, 244, 237)');
  check('ink', facts.ink === 'rgb(23, 46, 40)');
  check('font', facts.font === '16px' && facts.lineHeight === '27.2px' && /Hiragino Kaku Gothic ProN/.test(facts.family));
  check('main', facts.mainMax === '1080px' && facts.mainPad === '24px');
  check('grid', facts.display === 'grid' && (mobile ? facts.columns?.split(' ').length === 1
    : facts.columns?.startsWith('190px ') && facts.gap === '24px'));
  check('dl', facts.dl.every((c) => c === (mobile ? '110px' : '150px')));
  check('headings', facts.h2 === '21px' && facts.h1 >= 32 && facts.h1 <= 55);
  check(`targets:${facts.targets.filter(([, h]) => h < 48).map(([id]) => id).join('/')}`,
    facts.buttons.every((b) => b.h >= 48) && facts.targets.every(([, h]) => h >= 48));
  check('mobile-buttons', !mobile || facts.buttons.every((b) => Math.abs(b.w - facts.contentWidth) <= 1));
  check('radius', facts.buttons.every((b) => b.radius === '2px'));
  check('disabled-style', facts.buttons.filter((b) => b.disabled).every((b) => b.opacity === '0.45'));
  check(`no-overflow:${facts.scroll}/${facts.inner}:${facts.overflowing.slice(0, 3).join('/')}`,
    facts.scroll <= facts.inner && facts.overflowing.length === 0);
  check(`no-clipping:${facts.clipped.slice(0, 3).join('/')}`, facts.clipped.length === 0);
  check('no-raw-error', !/(Error|undefined|NaN|\[object |prefund \w+|chain read|storage \w+)/.test(facts.text));
  check('no-url-authority', facts.search === '' && facts.hash === '' && facts.path === '/prefund.html');
  check('nav', ['key-change.html', '/'].every((href) => facts.footer.includes(href)) && facts.back === 'key-change.html');
  check(`busy:${facts.busy}`, facts.busy === String(BUSY_ROWS.has(expectedRow)));
  if (['PF07', 'PF12'].includes(family) || ['PF13-reading', 'PF13-nonce-wait', 'PF13-cas-wait'].includes(expectedRow)) {
    check('custody', facts.custody === CUSTODY);
    check('pdq', /必要な前払い P/.test(facts.deposit || '') && /現在のデポジット D/.test(facts.deposit || '')
      && /不足額 Q/.test(facts.deposit || ''));
  }
  if (['PF05', 'PF06', 'PF07', 'PF12'].includes(family)) check('signer-note', facts.signerNote === '前払い残高への入金は鍵の追加・削除ではありません。');
  const invalidField = { PF02: 'authority', PF05: 'fee' }[family];
  check(`aria-invalid:${facts.invalid.join('/')}`, invalidField ? facts.invalid.includes(invalidField) : facts.invalid.length === 0);
  const action = ACTION[inv.id] || ACTION[expectedRow] || ACTION[family];
  if (action) check(`action:${action}`, action === 'wallet-choice' ? facts.walletChoice : facts.enabled[action]);
  // Send enablement is exactly reviewReady() && !sending as frozen per child (PF12-disabled is a live disabled shell).
  const sendEnabled = inv.sendEnabled ?? expectedRow === 'PF12-ready';
  check(`send-enabled:${facts.enabled.send}`, facts.enabled.send === sendEnabled);
  // Deleted outer-fee controls and the consent checkbox are absent, not hidden; no dangling aria reference remains.
  check(`no-outer-controls:${facts.removed.join('/')}`, facts.removed.length === 0 && facts.checkboxes === 0);
  check(`no-dangling-aria:${facts.describedBy.join('/')}`, facts.describedBy.length === 0);
  check('no-outer-cost-copy', !REMOVED_COPY.test(facts.text) && !REMOVED_COPY.test(facts.html));
  check('section-copy', facts.walletTitle === '入金するウォレット' && facts.reviewHeading === '送信内容と入金額');
  if (facts.deposit !== null) check('inner-p-note', facts.deposit.includes(INNER_P_NOTE));
  if (facts.review !== null) {
    // Terms carry renderer-inserted zero-width breaks (chainId, depositTo): match their stable prefixes.
    check('review-list', /ネットワーク chain/.test(facts.review) && /送信元 from/.test(facts.review)
      && /送信先 to/.test(facts.review) && /受取 Signerのデポジット/.test(facts.review) && /data（deposit/.test(facts.review)
      && /(^|\n)入金額 value = 不足額 Q/.test(facts.review) && !/1\. 入金額/.test(facts.review));
  }
  if (['PF12-ready', 'PF13-reading', 'PF13-nonce-wait', 'PF13-cas-wait'].includes(expectedRow)) check('review-shown', facts.review !== null);
  // Version-specific evidence: v2 shows deposit evidence only; literal v1 alone shows its labeled read-only history.
  const legacy = inv.attemptVersion === '1';
  if (inv.attemptVersion !== undefined && inv.attemptVersion !== 'none') {
    const evidence = [facts.attemptList, facts.outcome].filter(Boolean).join('\n');
    if (legacy) {
      check('v1-history', /^履歴\s+旧形式 v1（読取り専用）/.test(facts.attemptList || '')
        && /ウォレットnonce（確認時）/.test(facts.attemptList) && /外側ガス上限/.test(facts.attemptList));
      if (['PF17-outer-failed', 'PF19-success-ready'].includes(expectedRow)) check('v1-verified-cost', /実際のガス代/.test(facts.outcome || ''));
    } else check('v2-no-gas-summary', !V2_HIDDEN_COPY.test(evidence));
    if (expectedRow === 'PF16-one-confirmation' && !legacy) check('v2-pending-no-outcome', facts.outcome === null);
    if (expectedRow === 'PF17-outer-failed') check('failure-evidence', /入金額\s+0（入金は確認されていません）/.test(facts.outcome || ''));
    if (['PF19-success-ready', 'PF20-consumed'].includes(expectedRow)) {
      check('deposit-evidence', /入金額（取引のvalue）/.test(facts.outcome || '') && /Depositedイベントの累計デポジット/.test(facts.outcome || ''));
    }
  }
  if (driver.row?.startsWith('PF13') && !BUSY_ROWS.has(driver.row)) check('no-hidden-send', !facts.enabled.send);
  if (facts.inner < 1280 && driver.reduced) check('reduced-motion', facts.buttons.every((b) => b.transition === '0s'));
  if (driver.focus) {
    check(`focus:${driver.focus}:${facts.focus?.id}`, facts.focus?.id === driver.focus && facts.focus.visible);
    await page.keyboard.press('Shift');
    const ring = await page.evaluate(() => { const el = document.activeElement, c = getComputedStyle(el);
      return [el.matches(':focus-visible'), c.outlineStyle, c.outlineWidth, c.outlineColor, c.outlineOffset]; });
    check(`focus-style:${ring.join('/')}`, JSON.stringify(ring) === JSON.stringify([true, ...FOCUS_RING]));
  }
  delete facts.html;
  return { fail, facts };
}

/** PF24 judge on the production key-change page: KW09 secondary funding link, or the plain manual return. */
async function judgeKeyChange(page, id, expectedRow) {
  const facts = await page.evaluate(() => {
    const visible = (el) => el && !el.hidden && el.offsetParent !== null && el.getBoundingClientRect().height > 0;
    const link = document.getElementById('prefund-link'), css = getComputedStyle(document.body);
    const box = link && visible(link) ? link.getBoundingClientRect() : null;
    return { row: document.querySelector('main').dataset.row, title: document.querySelector('h1').textContent,
      path: location.pathname, search: location.search, hash: location.hash,
      link: box ? { href: link.getAttribute('href'), text: link.textContent, h: box.height, right: box.right } : null,
      anchor: document.getElementById('anchor').value, paper: css.backgroundColor, ink: css.color,
      scroll: document.documentElement.scrollWidth, inner: innerWidth,
      alert: [...document.querySelectorAll('main .status[role]')].filter(visible).map((el) => el.textContent),
      sends: window.__kh.provider.sends.length, wallet: window.__kh.controller.view().wallet.status,
      requests: window.__kh.native.client.calls.length };
  });
  const fail = [];
  const check = (name, ok) => { if (!ok) fail.push(name); };
  check(`row:${facts.row}`, facts.row === expectedRow);
  check('page', facts.title === '内部鍵の追加・削除' && facts.path === '/key-change.html' && facts.search === '' && facts.hash === '');
  check('tokens', facts.paper === 'rgb(245, 244, 237)' && facts.ink === 'rgb(23, 46, 40)');
  check('no-overflow', facts.scroll <= facts.inner);
  check('message', facts.alert.includes(KEY_MESSAGES[expectedRow]));
  check('no-send-or-pairing', facts.sends === 0 && facts.wallet === 'disconnected' && facts.requests === 0);
  if (id === 'PF24-link') {
    check('link', facts.link?.href === 'prefund.html' && facts.link.text === '前払い残高を入金する' && facts.link.h >= 48
      && facts.link.right <= facts.inner);
  } else {
    check('manual-return', facts.anchor === '' && facts.link === null);
  }
  return { fail, facts };
}

/** PF12 keyboard focus: Tab from the wallet controls reaches the send button with the inherited visible ring. */
async function focusVariant(page) {
  await page.focus('#wallet-disconnect');
  await page.keyboard.press('Tab');
  const ring = await page.evaluate(() => { const el = document.activeElement, c = getComputedStyle(el);
    return [el.id, el.matches(':focus-visible'), c.outlineStyle, c.outlineWidth, c.outlineColor, c.outlineOffset]; });
  return JSON.stringify(ring) === JSON.stringify(['send', true, ...FOCUS_RING]) ? [] : [`focus-ring:${ring.join('/')}`];
}
/** PF12 pressed: the active send shows the inherited 1px press; releasing outside does not send. */
async function pressedVariant(page) {
  await page.locator('#send').scrollIntoViewIfNeeded();
  const box = await page.locator('#send').boundingBox();
  await page.mouse.move(box.x + 5, box.y + 5);
  await page.mouse.down();
  const transform = await page.locator('#send').evaluate((b) => getComputedStyle(b).transform);
  return transform === 'matrix(1, 0, 0, 1, 0, 1)' ? [] : [`pressed:${transform}`];
}
async function releasePress(page) {
  await page.mouse.move(0, 0);
  await page.mouse.up();
  assert.equal(await ph(page, () => window.__ph.provider.sends.length), 0, 'pressed-sent');
}
/** PF12 disabled: the retained review after a wallet disconnect has a native disabled send; activation reserves nothing. */
async function disabledVariant(page) {
  const facts = await page.locator('#send').evaluate((b) => [b.disabled, getComputedStyle(b).opacity]);
  await page.locator('#send').click({ force: true });
  const sends = await ph(page, () => window.__ph.provider.sends.length);
  const stored = await page.evaluate(() => new Promise((resolve) => {
    const r = indexedDB.open('p256.entrypoint-prefund.attempts', 1);
    r.onsuccess = () => { const get = r.result.transaction('state', 'readonly').objectStore('state').get('current');
      get.onsuccess = () => { r.result.close(); resolve(get.result.raw); }; };
  }));
  const live = await ph(page, () => [window.__ph.controller.reviewReady(), window.__ph.controller.view().row]);
  return JSON.stringify([facts, sends, stored, live]) === JSON.stringify([[true, '0.45'], 0, null, [false, 'PF12-ready']]) ? []
    : [`disabled:${facts.join('/')}:${sends}:${stored !== null}:${live.join('/')}`];
}

async function prepareCapture(page, driver) {
  // Full-page capture may adjust scroll; park the pointer before measuring, then establish explicit focus/press.
  await page.mouse.move(0, 0);
  return driver.beforeCapture ? await driver.beforeCapture(page) : [];
}

async function capture(page, id, key) {
  if (id === 'PF12-focus') assert.equal(await page.locator('#send').evaluate((b) => b.matches(':focus-visible')), true,
    'focus must be held before screenshot');
  if (id === 'PF12-pressed') assert.equal(await page.locator('#send').evaluate((b) => b.matches(':active')), true,
    'press must be held before screenshot');
  const png = await page.screenshot({ fullPage: true });
  const name = `${id}--${key}.png`;
  if (OUT) writeFileSync(path.join(OUT, 'screens', name), png);
  return { screenshot: `screens/${name}`, screenshotSha256: sha256(png), bytes: png.length };
}

/** Closed evaluator: unknown, duplicate, missing, stale, failed or NOT_EVALUATED rows prevent aggregate PASS. */
export function judgeInventory(inv, observation) {
  const errors = [];
  const wanted = new Set(inv.rows.map((r) => `${r.id}|${vkey(r)}`));
  const seen = new Set();
  for (const e of observation.entries || []) {
    const key = `${e.id}|${e.viewport}`;
    if (!wanted.has(key)) errors.push(`unknown ${key}`);
    if (seen.has(key)) errors.push(`duplicate ${key}`);
    seen.add(key);
    if (e.runId !== observation.runId) errors.push(`stale ${key}`);
    if (e.status !== 'PASS') errors.push(`${e.status} ${key}: ${(e.checks || []).join(',')}`);
    if (e.status === 'PASS' && !(e.bytes > 1000 && /^[0-9a-f]{64}$/.test(e.screenshotSha256 || ''))) errors.push(`screenshot ${key}`);
  }
  for (const key of wanted) if (!seen.has(key)) errors.push(`missing ${key}`);
  return { errors, evaluated: seen.size, required: wanted.size };
}

const observations = [];

test('capture preparation keeps neutral, focus and pressed states across a full-page screenshot', async () => {
  for (const row of inventory.rows.filter((r) => ['PF12-checked', 'PF12-focus', 'PF12-pressed'].includes(r.id))) {
    const session = await open(row), driver = DRIVERS[row.id], page = session.page;
    try {
      await driver.run(page, session);
      assert.deepEqual(await prepareCapture(page, driver), []);
      const before = await judgePrefund(page, row, driver);
      assert.deepEqual(before.fail, []);
      await capture(page, row.id, vkey(row));
      const after = await judgePrefund(page, row, driver);
      assert.deepEqual(after.fail, []);
      assert.deepEqual(after.facts.interaction, before.facts.interaction, `${row.id}|${vkey(row)} capture state`);
      assert.deepEqual(after.facts.focus, before.facts.focus, 'capture does not move keyboard focus');
      if (row.id === 'PF12-focus') assert.equal(after.facts.interaction.focusVisible, true);
      if (row.id === 'PF12-pressed') assert.equal(after.facts.interaction.active, true);
      if (driver.release) await driver.release(page);
      assert.equal(await ph(page, () => window.__ph.provider.sends.length), 0);
    } finally { await session.context.close(); }
  }
});

test('closed PF inventory: every child/viewport rendered by the production pages and judged', async () => {
  assert.equal(inventory.rows.length, 156);
  const ids = new Set(inventory.rows.map((r) => r.id));
  assert.equal(ids.size, 78);
  assert.equal(new Set(inventory.rows.map((r) => `${r.id}|${vkey(r)}`)).size, 156);
  for (const id of ids) {
    assert.deepEqual(inventory.rows.filter((r) => r.id === id).map(vkey).sort(), ['1280x900', '390x844'], id);
  }
  assert.deepEqual(inventory.removedChildIds, ['PF11-gas-invalid', 'PF11-fee-invalid', 'PF11-overflow', 'PF12-unchecked',
    'PF13-consent-revoked']);
  assert.deepEqual(inventory.removedChildIds.filter((id) => ids.has(id) || DRIVERS[id] || MESSAGES[id]), []);
  assert.deepEqual([...ids].filter((id) => !DRIVERS[id]), [], 'inventory IDs without a driver');
  assert.deepEqual(Object.keys(DRIVERS).filter((id) => !ids.has(id)), [], 'drivers outside the inventory');
  assert.deepEqual(inventory.rows.filter((r) => DRIVERS[r.id].row !== r.controllerRow).map((r) => r.id), [],
    'driver rows differ from the frozen controller rows');
  assert.deepEqual([...new Set(inventory.rows.filter((r) => r.sendEnabled).map((r) => r.id))],
    ['PF12-checked', 'PF12-focus', 'PF12-pressed', 'PF12-text200']);
  assert.ok(inventory.rows.every((r) => !/consent/.test(r.actions)), 'no consent action');
  const filter = process.env.PREFUND_UI_FILTER ? new RegExp(process.env.PREFUND_UI_FILTER) : null;
  const queue = inventory.rows.filter((r) => !filter || filter.test(`${r.id}|${vkey(r)}`));
  const worker = async () => {
    while (queue.length) {
      const row = queue.shift();
      const driver = { ...DRIVERS[row.id], reduced: row.reducedMotion };
      const entry = { id: row.id, viewport: vkey(row), textScale: row.textScale, reducedMotion: row.reducedMotion,
        owner: row.owner, status: 'NOT_EVALUATED', runId: RUN_ID };
      let session;
      try {
        session = await open(row, { params: driver.params || {}, keyParams: driver.keyParams || {}, path: driver.page });
        session.row = row;
        await driver.run(session.page, session);
        await until(session.page, driver.row);
        const variantFail = await prepareCapture(session.page, driver);
        const keyPage = row.owner === 'key-change';
        const { fail, facts } = keyPage ? await judgeKeyChange(session.page, row.id, driver.row)
          : await judgePrefund(session.page, row, driver);
        if (driver.sends !== undefined && !keyPage) {
          const sends = await ph(session.page, () => window.__ph.provider.sends.length);
          if (sends !== driver.sends) fail.push(`wallet-sends:${sends}`);
        }
        if (row.id === 'PF21-cas-conflict' && session.otherSends !== 1) fail.push(`conflict-sends:${session.otherSends}`);
        if (row.id === 'PF09-pairing' && !await session.page.locator('#wallet-qr').isVisible()) fail.push('qr');
        fail.push(...variantFail);
        const shot = await capture(session.page, row.id, vkey(row));
        const afterFacts = keyPage ? null : (await judgePrefund(session.page, row, driver)).facts;
        if (afterFacts && JSON.stringify(facts.interaction) !== JSON.stringify(afterFacts.interaction)) fail.push('capture-state-changed');
        if (driver.release) await driver.release(session.page);
        if (driver.after) fail.push(...await driver.after(session.page));
        Object.assign(entry, shot, { checks: fail.length ? fail : ['all'],
          status: fail.length || session.errors.length || session.external.length ? 'FAIL' : 'PASS',
          pageErrors: session.errors, external: session.external, cssViewport: facts.inner, facts,
          capturedInteraction: afterFacts?.interaction ?? null });
      } catch (error) {
        entry.status = 'FAIL';
        entry.checks = [String(error.message).slice(0, 200)];
      } finally {
        await session?.context.close();
      }
      observations.push(entry);
    }
  };
  await Promise.all(Array.from({ length: 4 }, worker));
  const result = judgeInventory(inventory, { runId: RUN_ID, entries: observations });
  if (OUT) {
    writeFileSync(path.join(OUT, 'prefund-ui-observation.json'), JSON.stringify({ runId: RUN_ID, sources: sourceDigest(),
      entries: observations.sort((a, b) => (a.id + a.viewport).localeCompare(b.id + b.viewport)) }, null, 2));
  }
  assert.deepEqual(result.errors, [], result.errors.slice(0, 20).join('\n'));
});

test('inventory evaluator rejects missing, duplicate, unknown, stale, failed and NOT_EVALUATED evidence', () => {
  const runId = 'r';
  const good = { runId, entries: inventory.rows.map((r) => ({ id: r.id, viewport: vkey(r), runId, status: 'PASS', bytes: 2000,
    screenshotSha256: 'a'.repeat(64) })) };
  assert.deepEqual(judgeInventory(inventory, good).errors, []);
  const variants = {
    missing: (o) => o.entries.pop(), duplicate: (o) => o.entries.push({ ...o.entries[0] }),
    unknown: (o) => o.entries.push({ ...o.entries[0], id: 'PF99-x' }), stale: (o) => { o.entries[0].runId = 'old'; },
    failed: (o) => { o.entries[1].status = 'FAIL'; }, unevaluated: (o) => { o.entries[2].status = 'NOT_EVALUATED'; },
    emptyShot: (o) => { o.entries[3].bytes = 0; },
  };
  for (const [name, mutate] of Object.entries(variants)) {
    const o = structuredClone(good);
    mutate(o);
    assert.ok(judgeInventory(inventory, o).errors.length > 0, name);
  }
});

test('real built entry: initial PF01 with no SDK load, external request, web storage or console error; constrained CSP', async () => {
  const { page, context, external, errors } = await open(inventory.rows[0], { real: true });
  const requested = [];
  page.on('request', (r) => requested.push(new URL(r.url()).pathname));
  await page.waitForFunction(() => document.querySelector('main').dataset.row === 'PF01-initial');
  const { fail } = await judgePrefund(page, inventory.rows[0], {});
  assert.deepEqual(fail, []);
  assert.ok(!requested.some((p) => /signclient|walletconnect/.test(p)), requested.join());
  assert.deepEqual(external, []);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);
  const response = await fetch(`http://127.0.0.1:${serverPort()}/prefund.html`);
  assert.equal(response.status, 200);
  const csp = response.headers.get('content-security-policy');
  assert.ok(!/frame-src/.test(csp) && /connect-src 'self' wss:\/\/relay\.walletconnect\.com https:\/\/relay\.walletconnect\.com;/.test(csp), csp);
  await context.close();
});

/** Base-revision outer-fee/consent markup and the combined maximum debit, reinserted as negative controls. */
const OUTER_FORM = `<form id="outer-form" novalidate><fieldset id="outer-fields"><legend>外側取引の上限（ウォレット負担・入金額とは別）</legend>
  <label for="outer-gas">ガス上限（整数、21000以上）</label><input type="text" id="outer-gas" aria-describedby="outer-help wallet-error">
  <small id="outer-help">見積りや自動入力はしません。</small></fieldset></form>\n      <div id="review" hidden>`;
const OUTER_REINSERTIONS = {
  outerForm: (body) => body.replace('<div id="review" hidden>', OUTER_FORM),
  hiddenOuterForm: (body) => body.replace('<div id="review" hidden>', OUTER_FORM.replace('<form id="outer-form" novalidate>', '<form id="outer-form" novalidate hidden>')),
  consent: (body) => body.replace('<button id="send"', '<label class="consent"><input type="checkbox" id="consent">表示した宛先・データ・入金額・費用上限で1回だけ送信することに同意します</label>\n        <button id="send"'),
  combinedDebit: (body) => body.replace('<p class="confirm">', '<p>3. ウォレットの最大支出 (1+2)：最大0.06 POL。実際の支払いは使用量に応じます</p><p class="confirm">'),
};

test('negative controls: absent CSS, overridden tokens, the old generic page, reinserted outer controls and a missing KW09 link fail the judges', async () => {
  const css = readFileSync(path.join(app, 'styles.css'), 'utf8');
  const row = inventory.rows.find((r) => r.id === 'PF01-initial' && r.viewport[0] === 1280);
  for (const [name, options] of Object.entries({
    noCss: { styles: '' },
    overridden: { styles: css.replace('--paper: #f5f4ed', '--paper: #ffffff') },
    cards: { styles: css + '\nsection{display:block!important;border:1px solid #000;border-radius:12px}' },
    generic: { swap: { '/prefund.html': { from: '/key-change.html', edit: (body) => body.replaceAll('内部鍵の追加・削除', '前払い残高を入金')
      .replace('02 / CHANGE', '02 / DEPOSIT').replace('03 / APPROVAL', '03 / WALLET').replace('04 / EXECUTE', '04 / RESULT')
      .replace('data-page="key-change"', 'data-page="prefund"') } } },
  })) {
    const session = await open(row, options);
    if (!options.swap) await session.page.waitForFunction(() => document.querySelector('main').dataset.row === 'PF01-initial');
    else await session.page.waitForTimeout(500);
    const { fail } = await judgePrefund(session.page, row, {});
    assert.ok(fail.length > 0, `${name} passed the judge`);
    await session.context.close();
  }
  // Reinserting the deleted outer-fee form, consent checkbox or combined-debit line fails the rendered judge of a
  // live ready review, even when the production controller still drives the page.
  const ready = inventory.rows.find((r) => r.id === 'PF12-checked' && r.viewport[0] === 1280);
  for (const [name, edit] of Object.entries(OUTER_REINSERTIONS)) {
    const session = await open(ready, { swap: { '/prefund.html': { edit } } });
    await session.page.waitForFunction(() => window.__ph?.ready === true);
    await DRIVERS['PF12-checked'].run(session.page, session);
    const { fail } = await judgePrefund(session.page, ready, {});
    assert.ok(fail.some((f) => /^(no-outer-controls|no-outer-cost-copy|no-dangling-aria)/.test(f)), `${name}: ${fail.join()}`);
    await session.context.close();
  }
  const linkRow = inventory.rows.find((r) => r.id === 'PF24-link' && r.viewport[0] === 1280);
  const missing = await open(linkRow, { path: '/key-change.html', keyParams: { deposit: '0' },
    swap: { '/key-change.html': { edit: (body) => body.replace(/<a id="prefund-link"[^>]*>[^<]*<\/a>/, '<span id="prefund-link" hidden></span>') } } });
  await missing.page.waitForFunction(() => window.__kh?.ready === true);
  await keyAnchor(missing.page);
  await until(missing.page, 'KW09');
  const { fail } = await judgeKeyChange(missing.page, 'PF24-link', 'KW09');
  assert.ok(fail.includes('link'), 'missing KW09 link passed the judge');
  await missing.context.close();
});
