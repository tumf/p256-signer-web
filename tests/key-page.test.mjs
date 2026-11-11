// Rendered key-change page in local headless Chromium. The built dist/ is served through the real serve.py handler
// (real CSP) under the fixed origin; every KW row/subcase of tests/key-ui-inventory.json is driven through the actual
// production renderer, controller, attempt store (native IndexedDB) and WalletManager, then judged by screenshot plus
// resolved-style/geometry assertions. Controlled peers only (fixture chain, software native peer, injected wallet):
// local Chromium rendering evidence, NOT deployed, iPhone, relay, wallet or EVM evidence. The standard wallet owns
// outer gas/fees/nonce: every row is also judged for the absence of outer inputs, quote and payment checkbox.
import assert from 'node:assert/strict';
import { checkQRDownload } from './support/qr-download.mjs';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { MESSAGES } from '../key-controller.js';
import {
  ORIGIN, addChange, anchor, app, connected, inventory, kh, legacy, open, previewed, reconcileClick, reconciled,
  reloadAfter, removeChange, sent, serverPort, startBrowser, stopBrowser, tx, unknownThen, until, verified,
  walletConnected,
} from './support/key-browser.mjs';

const OUT = process.env.KEY_UI_OUT || null;
const RUN_ID = process.env.KEY_UI_RUN_ID || randomUUID();
const SOURCES = ['key-change.html', 'key-change.js', 'key-controller.js', 'key-model.js', 'chains.js', 'key-reader.js',
  'key-session.js', 'key-attempt-store.js', 'styles.css', 'wallet.js', 'tests/key-page.test.mjs',
  'tests/key-ui-inventory.json', 'tests/support/key-page-harness.mjs', 'tests/support/key-chain.mjs',
  'tests/support/key-fixtures.mjs', 'tests/support/key-browser.mjs'];
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const sourceDigest = () => Object.fromEntries(SOURCES.map((name) => [name, sha256(readFileSync(path.join(app, name)))]));

/**
 * Independent fixed expectations (key-change-web spec / delegate-key-wallet-fees ui-state-matrix): the closed final
 * ID set, its count and exact visible copy. Never derived from the production MESSAGES table or observed rows.
 */
const EXPECTED_TEXT = {
  'KW01': '公開データを読み込んで確認してください。',
  'KW02': '公開データの形式・公開鍵・IDを確認してください。',
  'KW03': '公開データとチェーン情報を確認中です。',
  'KW04': 'チェーン情報を確認できません。時間をおいて再確認してください。',
  'KW05': '追加する鍵を確認してください。',
  'KW06': '削除する鍵と残る鍵を確認してください。',
  'KW07-curve': '公開鍵の形式または曲線上の点が不正です。',
  'KW07-duplicate': 'この鍵は登録済みです。',
  'KW07-last': '最後の鍵は削除できません。',
  'KW07-limit': '登録できる鍵は64個までです。',
  'KW08-blank': '署名対象の手数料上限と優先料を入力してください。',
  'KW08-bounds': '署名対象の手数料が許可上限または数値範囲を超えています。',
  'KW08-format': 'Gweiは小数9桁までの半角数値で入力してください。',
  'KW09': '前払い残高が不足しています。この画面では入金しません。別の入金画面で入金した後、ここで公開データから再確認してください。',
  'KW10': 'iPhoneで接続を承認してください。',
  'KW11': 'iPhoneに接続しました。要求内容を確認してください。',
  'KW12': 'この内容をiPhoneに要求します。',
  'KW13': 'この内容をiPhoneに要求します。',
  'KW14': 'iPhoneでの承認を待っています。',
  'KW15': '署名検証済み・未実行',
  'KW16-changed': '署名権限が変わりました。公開データから再確認してください。',
  'KW16-expired': '要求の期限が切れました。新しい接続で要求してください。',
  'KW16-invalid': '返された署名を検証できません。送信できません。',
  'KW16-lost': '接続または応答を確認できません。署名は採用していません。',
  'KW16-rejected': 'iPhoneで承認されませんでした。新しく接続してください。',
  'KW17-choices': '実行用ウォレットを選択してください。',
  'KW17-pairing': '実行用ウォレットで接続を承認してください。',
  'KW17-unavailable': '利用できるウォレット接続がありません。',
  'KW18-refused': '自動切替できません。ウォレット側でPolygonを選択してください。',
  'KW18-wrong': '実行用ウォレットをPolygonに切り替えてください。',
  'KW20': '鍵変更の内容を確認し、ウォレットで送信を承認してください。',
  'KW20-checking': '送信前のチェーン情報とウォレットnonceを確認しています。',
  'KW20-nonce': 'ウォレットのnonceを確認できません。送信していません。再確認してください。',
  'KW21': '送信記録を保存しました。ウォレットの応答を待っています。',
  'KW22-late-hash': '元の送信の取引ハッシュを受け取りました。結果を確認してください。',
  'KW22-no-hash': '送信結果は不明です。再送せず、取引ハッシュで確認してください。',
  'KW23-one': '1 / 2 承認。まだ鍵変更成功とは判定していません。',
  'KW23-pending': '取引の確定待ちです。鍵変更は未確認です。',
  'KW24': '外側取引は成功しましたが、鍵変更は失敗しました。費用は発生しています。',
  'KW25': '外側取引が失敗しました。鍵変更成功ではありません。以前の署名は未失効です。',
  'KW26-cap': 'ウォレットが承認済み費用上限を変更しました。結果を自動採用しません。',
  'KW26-event': '鍵変更の実行イベントを一意に確認できません。',
  'KW26-fees': '取引と受領情報のガス・手数料が整合しません。結果は未確定です。',
  'KW26-foreign': '保存した送信内容と取引が一致しません。',
  'KW26-reorg': 'ブロックの変更を検出しました。結果は未確定です。',
  'KW26-rpc': '実行後のチェーン情報を確認できません。',
  'KW26-same-block': '対象イベントは成功・状態競合で照合未完了',
  'KW26-state': '実行後の全鍵・nonceが予定と一致しません。',
  'KW26-state-advanced': 'この送信の実行は証明できません。現在の鍵は予定と異なります。',
  'KW26-state-resolved': '現在の状態は予定と一致しますが、この送信の実行は証明できません。',
  'KW27': '内部鍵の追加を検証しました。',
  'KW28': '内部鍵の削除を検証しました。',
  'KW29-conflict': '別の画面が送信記録を更新しました。再送せず確認してください。',
  'KW29-corrupt': '保存済み送信記録が不正です。上書きせず停止しました。',
  'KW29-unavailable': '送信記録を安全に保存できません。送信できません。',
  'KW30-hash': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  'KW30-reserved': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  'KW30-terminal': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  'KW30-v2-hash': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  'KW30-v2-reserved': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  'KW30-v2-terminal': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  'KW31': '鍵変更の内容を確認し、ウォレットで送信を承認してください。',
};
const REQUIRED_IDS = Object.keys(EXPECTED_TEXT);
const TEXT200 = ['KW02', 'KW12', 'KW14', 'KW21', 'KW22-no-hash', 'KW27'];
const REMOVED_IDS = ['KW19-blank', 'KW19-format', 'KW19-bounds', 'KW19-balance'];
const LEGACY_V1_ROWS = new Set(['KW26-cap', 'KW30-reserved', 'KW30-hash', 'KW30-terminal']);
const V2_RESTORED_ROWS = new Set(['KW30-v2-reserved', 'KW30-v2-hash', 'KW30-v2-terminal']);
/** Removed controls and copy: none may exist anywhere on the page, not even hidden. */
const REMOVED_CONTROLS = ['outer-form', 'outer-fields', 'outer-gas', 'outer-max', 'outer-priority', 'outer-help', 'consent'];
const REMOVED_COPY = ['外側トランザクションの上限', '外側取引の最大費用', '費用上限で1回だけ送信することに同意', '1200000以上',
  '1200000は受付の下限', '送信内容と費用の区分'];
const SEND_COSTS = [['1. 必要な前払い（Signerのデポジットから）', null], ['2. 確認したデポジット・不足', null],
  ['3. 受取人への払戻し', 'EntryPointが実際の費用 actualGasCost（最大P）を受取人に支払います。外側費用との差額は保証しません。']];

before(async () => {
  await startBrowser();
  if (OUT) mkdirSync(path.join(OUT, 'screens'), { recursive: true });
});
after(stopBrowser);

test('current iPhone and wallet pairing QR export without signing or sending', async () => {
  const { page, context, errors, external } = await open('390x844');
  try {
    await kh(page, () => { window.__kh.peer.pairingHold = true; });
    await anchor(page); await addChange(page); await page.click('#connect');
    await checkQRDownload(page, 'pairing-qr');
    assert.equal(await kh(page, () => window.__kh.peer.signs), 0);
    await page.click('#pairing-cancel');
    assert.equal(await page.locator('#pairing-qr + button').isDisabled(), true);
    await kh(page, () => { window.__kh.peer.pairingHold = false; });
    await page.click('#connect'); await until(page, 'KW11');
    await page.click('#preview'); await until(page, 'KW12');
    await page.click('#sign'); await page.locator('#verified:visible').waitFor();
    const signs = await kh(page, () => window.__kh.peer.signs);
    await page.check('#wallet-choices input[value="walletconnect"]'); await page.click('#wallet-connect');
    await checkQRDownload(page, 'wallet-qr');
    assert.equal(await kh(page, () => window.__kh.peer.signs), signs);
    assert.equal(await kh(page, () => window.__kh.provider.sends.length), 0);
    await page.click('#wallet-cancel');
    assert.equal(await page.locator('#wallet-qr + button').isDisabled(), true);
    assert.deepEqual(errors, []); assert.deepEqual(external, []);
  } finally { await context.close(); }
});

/** One driver per inventory ID; each returns { params?, run(page), page? } where params configure the harness. */
const DRIVERS = {
  KW01: { run: async () => {} },
  KW02: { run: async (p) => { await p.fill('#anchor', '{"v":"1","kind":"hybrid-key-authority"}'); await p.click('#inspect'); } },
  KW03: { run: async (p) => { await kh(p, () => { window.__kh.chain.delay = 600_000; }); await p.fill('#anchor', await kh(p, () => window.__kh.text.anchor1)); await p.click('#inspect'); } },
  KW04: { run: async (p) => { await kh(p, () => { window.__kh.chain.fail = () => true; }); await anchor(p); } },
  KW05: { run: async (p) => { await anchor(p); await addChange(p); } },
  KW06: { params: { keys: 'two' }, run: async (p) => { await anchor(p); await removeChange(p); } },
  'KW07-duplicate': { run: async (p) => { await anchor(p); await addChange(p, 'bare1'); } },
  'KW07-curve': { run: async (p) => { await anchor(p); await addChange(p); await p.fill('#bare-key', (await p.inputValue('#bare-key')).replace(/"publicKey":"0x04([0-9a-f]{4})/, '"publicKey":"0x040000')); } },
  'KW07-limit': { run: async (p) => { await kh(p, () => { const k = window.__kh; k.chain.state.keys = [k.keys.k1, ...k.many(63)]; }); await anchor(p); await addChange(p); } },
  'KW07-last': { run: async (p) => { await anchor(p); await p.check('#mode-remove'); await p.fill('#fee-max', '1'); await p.fill('#fee-priority', '1'); } },
  'KW08-blank': { run: async (p) => { await anchor(p); await addChange(p); await p.fill('#fee-max', ''); } },
  'KW08-format': { run: async (p) => { await anchor(p); await addChange(p, 'bare2', '1.0000000001'); } },
  'KW08-bounds': { run: async (p) => { await anchor(p); await addChange(p); await p.fill('#fee-priority', '2'); } },
  KW09: { params: { deposit: '0' }, run: async (p) => { await anchor(p); await addChange(p); } },
  KW10: { run: async (p) => { await kh(p, () => { window.__kh.peer.pairingHold = true; }); await anchor(p); await addChange(p); await p.click('#connect'); await p.locator('#pairing-open[href^="wc:"]').waitFor(); } },
  KW11: { run: (p) => connected(p) },
  KW12: { run: (p) => previewed(p) },
  KW13: { params: { keys: 'two' }, run: (p) => previewed(p, removeChange) },
  KW14: { run: async (p) => { await previewed(p); await kh(p, () => { window.__kh.peer.mode = 'hold'; }); await p.click('#sign'); } },
  KW15: { run: (p) => verified(p) },
  'KW16-rejected': { run: async (p) => { await previewed(p); await kh(p, () => { window.__kh.peer.mode = 'reject'; }); await p.click('#sign'); } },
  'KW16-lost': { run: async (p) => { await connected(p); await kh(p, () => window.__kh.native.client.emit('session_delete', window.__kh.native.client.topic)); } },
  'KW16-changed': { run: async (p) => { await previewed(p); await kh(p, () => { window.__kh.peer.binding = '0x' + 'c2'.repeat(32); }); await p.click('#sign'); } },
  'KW16-invalid': { run: async (p) => { await previewed(p); await kh(p, () => { window.__kh.peer.mode = 'invalid'; }); await p.click('#sign'); } },
  'KW16-expired': { run: async (p) => { await verified(p); await kh(p, () => window.__kh.controller.armExpiry(0)); } },
  'KW17-choices': { run: async (p) => { await verified(p); await p.check('#wallet-choices input[value="legacy"]'); } },
  'KW17-pairing': { run: async (p) => { await verified(p); await p.check('#wallet-choices input[value="walletconnect"]'); await p.click('#wallet-connect'); await p.locator('#wallet-open[href^="wc:"]').waitFor(); } },
  'KW17-unavailable': { params: { noWallets: true }, run: (p) => verified(p) },
  'KW18-wrong': { params: { chainId: '0x1' }, run: (p) => walletConnected(p) },
  'KW18-refused': { params: { chainId: '0x1' }, run: async (p) => { await walletConnected(p); await kh(p, () => { window.__kh.provider.switchMode = 'refuse'; }); await p.click('#wallet-switch'); } },
  KW20: { run: (p) => walletConnected(p) },
  'KW20-checking': { run: async (p) => { await walletConnected(p); await kh(p, () => { const k = window.__kh, rpc = k.controller.rpc;
    k.controller.rpc = (m, params) => (m === 'eth_getTransactionCount' ? new Promise(() => {}) : rpc(m, params)); }); await p.click('#send'); } },
  'KW20-nonce': { run: async (p) => { await walletConnected(p); await kh(p, () => { window.__kh.chain.fail = (m) => m === 'eth_getTransactionCount'; }); await p.click('#send'); } },
  KW21: { run: async (p) => { await walletConnected(p); await kh(p, () => { window.__kh.provider.sendMode = 'hang'; }); await p.click('#send'); } },
  'KW22-no-hash': { run: (p) => sent(p, { setup: () => { window.__kh.provider.sendMode = 'reject'; } }) },
  'KW22-late-hash': { run: async (p) => {
    await sent(p, { setup: () => { const k = window.__kh; k.provider.sendMode = 'hang'; const set = k.controller.setTimer;
      k.controller.setTimer = (fn, ms) => set(fn, ms === 300000 ? 50 : ms); } });
    await kh(p, () => window.__kh.provider.release());
  } },
  'KW23-pending': { run: async (p) => { await sent(p, { setup: () => { window.__kh.provider.submit = { mineBlock: false }; } }); await reconcileClick(p); } },
  'KW23-one': { run: async (p) => { await sent(p); await reconcileClick(p); } },
  KW24: { run: (p) => reconciled(p, { submit: { innerSuccess: false } }) },
  KW25: { run: (p) => reconciled(p, { submit: { outerStatus: '0x0' } }) },
  'KW26-reorg': { run: (p) => reconciled(p, { after: () => { const k = window.__kh; const h = k.controller.view().attempt.record.transactionHash; k.chain.reorg(BigInt(k.chain.state.receipts.get(h).blockNumber)); } }) },
  'KW26-foreign': { run: (p) => reconciled(p, { after: tx('input', "t.input.slice(0, -2) + '01'") }) },
  'KW26-event': { run: (p) => reconciled(p, { submit: { dropEvent: true } }) },
  'KW26-state': { run: (p) => reconciled(p, { after: () => { const k = window.__kh; k.chain.state.keys.push(k.keys.k3); } }) },
  'KW26-state-advanced': { run: unknownThen(() => { const k = window.__kh; k.chain.state.nonce += 1n; k.chain.state.keys = [k.keys.k1, k.keys.k3]; k.chain.mine(); }) },
  'KW26-same-block': { run: (p) => reconciled(p, { after: () => { window.__kh.chain.state.nonce += 1n; } }) },
  'KW26-rpc': { run: (p) => reconciled(p, { after: () => { window.__kh.chain.fail = (m) => m === 'eth_getStorageAt'; } }) },
  // v1 only: a legacy record whose stored gas ceiling (1200000) is below the wallet's actual gas (2200000).
  'KW26-cap': { run: (p) => reconciled(p, { after: () => window.__kh.legacy({ gas: '1200000' }) }) },
  'KW26-fees': { run: (p) => reconciled(p, { after: tx('maxPriorityFeePerGas', "'0x' + (BigInt(t.maxFeePerGas) + 1n).toString(16)") }) },
  'KW26-state-resolved': { run: unknownThen(() => { const k = window.__kh; k.chain.state.nonce += 1n; k.chain.state.keys = [k.keys.k1, k.keys.k2]; k.chain.mine(); }) },
  KW27: { run: (p) => reconciled(p) },
  KW28: { params: { keys: 'two' }, run: (p) => reconciled(p, { change: removeChange }) },
  'KW29-unavailable': { params: { storage: 'unavailable' }, run: async () => {} },
  'KW29-corrupt': { run: reloadAfter(async (p) => {
    await kh(p, () => new Promise((resolve, reject) => {
      const r = indexedDB.open('p256.key-change.attempts', 1);
      r.onsuccess = () => { const tx = r.result.transaction('state', 'readwrite');
        tx.objectStore('state').put({ version: 1, revision: 4, raw: '{"version":1,"status":"reserved"}' }, 'current');
        tx.oncomplete = () => { r.result.close(); resolve(); }; tx.onerror = reject; };
    }));
  }) },
  'KW29-conflict': { run: async (p, ctx) => {
    const other = await open('1280x900', { context: ctx.context });
    await walletConnected(other.page);
    await walletConnected(p);
    await other.page.click('#send');
    await other.page.waitForFunction(() => window.__kh.controller.view().attempt.record !== null);
    await p.click('#send');
    ctx.sends = await other.page.evaluate(() => window.__kh.provider.sends.length);
  } },
  // Existing KW30 rows explicitly restore legacy v1 records; KW30-v2-* restore new v2 records.
  'KW30-reserved': { run: reloadAfter(async (p) => { await sent(p, { setup: () => { window.__kh.provider.sendMode = 'reject'; } }); await legacy(p); }) },
  'KW30-hash': { run: reloadAfter(async (p) => { await sent(p); await legacy(p); }) },
  'KW30-terminal': { run: reloadAfter(async (p) => { await reconciled(p); await legacy(p); }) },
  'KW30-v2-reserved': { run: reloadAfter((p) => sent(p, { setup: () => { window.__kh.provider.sendMode = 'reject'; } })) },
  'KW30-v2-hash': { run: reloadAfter((p) => sent(p)) },
  'KW30-v2-terminal': { run: reloadAfter((p) => reconciled(p)) },
  KW31: { params: { hostileWallet: true }, run: async (p) => { await walletConnected(p, addChange, 'eip6963:hostile'); await p.focus('#wallet-disconnect'); await p.keyboard.press('Tab'); } },
};
DRIVERS.KW31.row = 'KW20';

/** Per-row action contract: the enabled primary (visible), and controls that must not be enabled. */
const PRIMARY = { KW01: 'inspect', KW02: 'inspect', KW04: 'inspect', KW05: 'connect', KW06: 'connect', KW11: 'preview',
  KW12: 'sign', KW13: 'sign', KW16: 'connect', 'KW17-choices': 'wallet-connect', KW18: 'wallet-switch', KW20: 'send',
  'KW20-checking': null, 'KW20-nonce': 'send' };
/** Rows where the one explicit send action is enabled (KW31's production row is KW20). */
const SEND_ENABLED = new Set(['KW20', 'KW20-nonce']);
const SECONDARY = { KW03: 'inspect-cancel', KW09: 'refresh', KW10: 'pairing-cancel', 'KW17-pairing': 'wallet-cancel',
  KW22: 'reconcile', KW23: 'reconcile', KW24: 'reconcile', KW25: 'new-change', KW26: 'reconcile', KW27: 'new-change',
  KW28: 'new-change', 'KW29-unavailable': 'storage-reload', 'KW29-conflict': 'storage-reload', KW30: 'reconcile',
  'KW26-state-advanced': 'new-change', 'KW26-state-resolved': 'new-change', 'KW30-terminal': 'new-change' };
/**
 * Design section 6 focus contract for the row the driver just reached: the failed field or the section alert for
 * input errors, the newly shown request/verified heading, and the result heading whenever a result is shown.
 */
// KW07-duplicate/KW07-limit are reached when the bare key is filled, and their drivers then keep typing the fees, so
// focus there belongs to the user's typing and is not judged.
const FOCUS_FIELD = { KW02: 'anchor', 'KW07-curve': 'bare-key', 'KW08-blank': 'fee-max', 'KW08-format': 'fee-max',
  'KW08-bounds': 'fee-max', 'KW20-nonce': 'execute-error' };
const FOCUS_HEADING = { KW12: 'request-heading', KW13: 'request-heading', KW15: 'verified-heading' };
const RESULT_ERROR = /^KW2[4-6]/;
function expectedFocus(row, base, outcomeShown, alertShown) {
  if (FOCUS_FIELD[row]) return FOCUS_FIELD[row];
  if (FOCUS_HEADING[base]) return FOCUS_HEADING[base];
  // A failed/uncertain result announces itself through the section alert; a verified result through its heading.
  if (RESULT_ERROR.test(row) && alertShown) return 'execute-error';
  if (/^KW2[3-8]$/.test(base) && outcomeShown) return 'outcome-heading';
  return null;
}
const SECTION_OF = (id) => { const n = Number(id.slice(2, 4)); return n <= 4 ? 'signer' : n <= 9 ? 'change' : n <= 16 ? 'approval' : 'execute'; };

const FOCUS_RING = JSON.stringify(['solid', '3px', 'rgb(59, 116, 23)', '4px']);

/** Resolved style/geometry judge of the CURRENT page for one expected row. Returns failed check names. */
async function judgePage(page, id, variant) {
  const expectedRow = DRIVERS[id]?.row || id;
  const base = expectedRow.split('-')[0];
  const facts = await page.evaluate(({ expectedRow, section, removedIds }) => {
    const css = (el) => getComputedStyle(el);
    const main = document.querySelector('main');
    const sections = [...document.querySelectorAll('main > section:not(#saved-recovery)')];
    const recovery = document.querySelector('main > section#saved-recovery');
    const visible = (el) => el && !el.hidden && el.offsetParent !== null && el.getBoundingClientRect().height > 0;
    const statusNode = document.getElementById(`${section}-status`), alertNode = document.getElementById(`${section}-error`);
    const buttons = [...document.querySelectorAll('main button')].filter(visible);
    const choices = [...document.querySelectorAll('main .choice, main .consent')].filter(visible);
    const inputs = [...document.querySelectorAll('main input[type=text], main textarea')].filter(visible);
    const overflowing = [...document.body.querySelectorAll('*')].filter(visible)
      .filter((el) => el.getBoundingClientRect().right > innerWidth + 0.5 || el.getBoundingClientRect().left < -0.5)
      .map((el) => `${el.id || el.tagName}${el.className ? '.' + el.className : ''}@${Math.round(el.getBoundingClientRect().right)}`);
    const clipped = [...main.querySelectorAll('dd, p, label, h1, h2, h3, .status, button, .step')].filter(visible)
      .filter((el) => el.scrollWidth > el.clientWidth + 1 && css(el).overflowX !== 'visible').map((el) => el.id || el.tagName);
    const content = sections[0]?.children[1];
    const section0 = sections[0] && css(sections[0]);
    return {
      row: main.dataset.row, title: document.querySelector('h1')?.textContent,
      steps: sections.map((s) => s.querySelector('.step')?.textContent),
      recovery: recovery?.getAttribute('aria-label'),
      sectionCount: document.querySelectorAll('main > section').length,
      status: visible(statusNode) ? statusNode.textContent : null, statusRole: statusNode?.getAttribute('role'),
      alert: visible(alertNode) ? alertNode.textContent : null, alertRole: alertNode?.getAttribute('role'),
      paper: css(document.body).backgroundColor, ink: css(document.body).color, font: css(document.body).fontSize,
      lineHeight: css(document.body).lineHeight, family: css(document.body).fontFamily,
      mainMax: css(main).maxWidth, mainPad: css(main).paddingLeft,
      columns: section0?.gridTemplateColumns, gap: section0?.columnGap, display: section0?.display,
      contentWidth: content?.getBoundingClientRect().width,
      h2: css(document.querySelector('h2')).fontSize, h1: parseFloat(css(document.querySelector('h1')).fontSize),
      buttons: buttons.map((b) => ({ id: b.id, h: b.getBoundingClientRect().height, w: b.getBoundingClientRect().width,
        disabled: b.disabled, opacity: css(b).opacity, secondary: b.classList.contains('secondary'),
        radius: css(b).borderTopLeftRadius, transition: css(b).transitionDuration, animation: css(b).animationName })),
      choices: choices.map((c) => c.getBoundingClientRect().height), inputs: inputs.map((i) => i.getBoundingClientRect().height
        >= 48 || i.tagName === 'TEXTAREA'),
      scroll: document.documentElement.scrollWidth, inner: innerWidth, clipped,
      overflowing: overflowing.length || document.documentElement.scrollWidth <= innerWidth ? overflowing
        : [...document.body.querySelectorAll('*')].filter((el) => el.scrollWidth > el.clientWidth + 1
          && ![...el.children].some((c) => c.scrollWidth > c.clientWidth + 1))
          .map((el) => `content:${el.id || el.tagName}:${(el.textContent || '').trim().slice(0, 24)}`),
      text: main.innerText, imgs: document.querySelectorAll('main img').length, pwned: Boolean(window.__pwned),
      footerLinks: [...document.querySelectorAll('footer a')].map((a) => a.getAttribute('href')),
      enabled: Object.fromEntries(['inspect', 'connect', 'preview', 'sign', 'wallet-connect', 'wallet-switch', 'send',
        'reconcile', 'new-change', 'refresh', 'inspect-cancel', 'pairing-cancel', 'wallet-cancel',
        'storage-reload'].map((id) => { const el = document.getElementById(id); return [id, Boolean(el && visible(el)
        && !el.disabled && !(el.closest('fieldset')?.disabled))]; })),
      busy: main.getAttribute('aria-busy'),
      removed: removedIds.filter((id) => document.getElementById(id)),
      checkboxes: [...document.querySelectorAll('main input[type=checkbox]')].map((el) => el.id),
      sendShown: visible(document.getElementById('send')), sendLabel: document.getElementById('send')?.textContent,
      sendHeading: visible(document.getElementById('send-review')) ? document.getElementById('send-heading').textContent : null,
      sendList: visible(document.getElementById('send-review')) ? [...document.querySelectorAll('#send-list dt')]
        .map((dt) => [dt.textContent.replaceAll('\u200b', ''), dt.nextElementSibling?.textContent]) : null,
      attemptShown: visible(document.getElementById('attempt')),
      attemptText: visible(document.getElementById('attempt')) ? document.getElementById('attempt-list').innerText : '',
      recordVersion: window.__kh?.controller.view().attempt.record?.version ?? null,
      reconcileEnabled: Boolean(document.getElementById('reconcile') && visible(document.getElementById('reconcile'))
        && !document.getElementById('reconcile').disabled),
      outcomeShown: visible(document.getElementById('outcome')),
      focus: (() => { const el = document.activeElement;
        return el ? { id: el.id, visible: visible(el) } : null; })(),
    };
  }, { expectedRow, section: SECTION_OF(expectedRow), removedIds: REMOVED_CONTROLS });
  const mobile = facts.inner <= 680;
  const fail = [];
  const check = (name, ok) => { if (!ok) fail.push(name); };
  check('row', facts.row === expectedRow);
  check('title', facts.title === '内部鍵の追加・削除');
  check('recovery-section', facts.recovery === '保存済み結果の回収' && facts.sectionCount === 5);
  check('sections', JSON.stringify(facts.steps) === JSON.stringify(['01 / SIGNER', '02 / CHANGE', '03 / APPROVAL', '04 / EXECUTE']));
  const message = EXPECTED_TEXT[expectedRow];
  check('message', typeof message === 'string' && MESSAGES[expectedRow] === message
    && (facts.status === message || facts.alert === message));
  check('message-role', facts.status === message ? facts.statusRole === 'status' : facts.alertRole === 'alert');
  check('paper', facts.paper === 'rgb(245, 244, 237)');
  check('ink', facts.ink === 'rgb(23, 46, 40)');
  check('font', facts.font === '16px' && facts.lineHeight === '27.2px' && /Hiragino Kaku Gothic ProN/.test(facts.family));
  check('main', facts.mainMax === '1080px' && facts.mainPad === '24px');
  check('grid', facts.display === 'grid' && (mobile ? facts.columns?.split(' ').length === 1
    : facts.columns?.startsWith('190px ') && facts.gap === '24px'));
  check('headings', facts.h2 === '21px' && facts.h1 >= 32 && facts.h1 <= 55);
  check('targets', facts.buttons.every((b) => b.h >= 48) && facts.choices.every((h) => h >= 48) && facts.inputs.every(Boolean));
  check('mobile-buttons', !mobile || facts.buttons.every((b) => Math.abs(b.w - facts.contentWidth) <= 1));
  check('radius', facts.buttons.every((b) => b.radius === '2px'));
  check('disabled-style', facts.buttons.filter((b) => b.disabled).every((b) => b.opacity === '0.45'));
  check(`no-overflow:${facts.scroll}/${facts.inner}:${facts.overflowing.slice(0, 4).join('/')}`, facts.scroll <= facts.inner && facts.overflowing.length === 0);
  check('no-clipping', facts.clipped.length === 0);
  check('no-raw-error', !/(Error|undefined|NaN|\[object |key-change \w+|chain read)/.test(facts.text));
  check('escaped', facts.imgs === 0 && !facts.pwned);
  check('nav', ['/', 'safe-request.html'].every((href) => facts.footerLinks.includes(href)));
  if (variant.includes('reduced')) check('reduced-motion', facts.buttons.every((b) => b.transition === '0s' && b.animation === 'none'));
  const primary = expectedRow in PRIMARY ? PRIMARY[expectedRow] : PRIMARY[base];
  if (primary) check(`primary:${primary}`, facts.enabled[primary]);
  // Wallet-owned outer payment: no outer input, quote, ceiling copy or payment checkbox anywhere, on every row.
  check(`no-outer-controls:${facts.removed.join('/')}`, facts.removed.length === 0);
  check(`no-payment-checkbox:${facts.checkboxes.join('/')}`, facts.checkboxes.every((id) => id === 'rollover-ack'));
  check('no-outer-copy', REMOVED_COPY.every((text) => !facts.text.includes(text)));
  if (facts.sendShown) check('send-label', facts.sendLabel === '表示した鍵変更を1回だけ送信');
  if (base === 'KW20') {
    check('send-review', facts.sendHeading === '鍵変更の送信内容' && Array.isArray(facts.sendList));
    const costs = (facts.sendList || []).filter(([term]) => /^\d\. /.test(term));
    check(`send-costs:${costs.map(([term]) => term).join('/')}`, costs.length === SEND_COSTS.length
      && SEND_COSTS.every(([term, value], i) => costs[i][0] === term && (value === null || costs[i][1] === value)));
  }
  // Attempt summary: legacy v1 rows keep their historical ceilings; v2 rows have none (and no substitute row).
  if (facts.attemptShown && facts.recordVersion !== null) {
    const legacyRows = /外側ガス上限/.test(facts.attemptText) && /外側手数料上限/.test(facts.attemptText);
    check(`record-version:${facts.recordVersion}`, facts.recordVersion === (LEGACY_V1_ROWS.has(expectedRow) ? 1 : 2));
    check('attempt-ceilings', LEGACY_V1_ROWS.has(expectedRow) ? legacyRows : !/外側.*上限/.test(facts.attemptText));
  }
  if (expectedRow === 'KW30-v2-hash' || expectedRow === 'KW30-hash') {
    check('restored-hash', /取引ハッシュ/.test(facts.attemptText) && facts.reconcileEnabled && !facts.sendShown);
  }
  const secondary = SECONDARY[expectedRow] || SECONDARY[base];
  if (secondary) check(`action:${secondary}`, facts.enabled[secondary]);
  const allowConnect = ['KW05', 'KW06', 'KW16'].includes(base);
  check('no-connect', allowConnect || !facts.enabled.connect);
  check('no-sign', ['KW12', 'KW13'].includes(base) || !facts.enabled.sign);
  check('no-send', SEND_ENABLED.has(expectedRow) || !facts.enabled.send);
  if (expectedRow === 'KW20-checking') check('send-disabled', facts.sendShown && !facts.enabled.send);
  if (['KW03', 'KW10', 'KW14', 'KW21'].includes(base) || expectedRow === 'KW20-checking') check('busy', facts.busy === 'true');
  const focusTarget = expectedFocus(expectedRow, base, facts.outcomeShown, facts.alert === message);
  if (focusTarget) {
    check(`focus:${focusTarget}:${facts.focus?.id}`, facts.focus?.id === focusTarget && facts.focus.visible);
    // The inherited :focus-visible ring follows keyboard modality (as on the base pages); a keyboard user's next
    // keystroke must show it on the moved focus target without moving focus.
    await page.keyboard.press('Shift');
    const ring = await page.evaluate(() => { const el = document.activeElement, c = getComputedStyle(el);
      return [el.id, el.matches(':focus-visible'), c.outlineStyle, c.outlineWidth, c.outlineColor, c.outlineOffset]; });
    check(`focus-style:${ring.join('/')}`, JSON.stringify(ring) === JSON.stringify([focusTarget, true,
      ...JSON.parse(FOCUS_RING)]));
  }
  return { fail, facts };
}

async function capture(page, id, variant) {
  const png = await page.screenshot({ fullPage: true });
  const name = `${id}--${variant}.png`;
  if (OUT) writeFileSync(path.join(OUT, 'screens', name), png);
  return { screenshot: `screens/${name}`, screenshotSha256: sha256(png), bytes: png.length };
}

const observations = [];

test('closed KW inventory: every row/subcase/viewport rendered by the production page and judged', async () => {
  const ids = new Set(inventory.entries.map((e) => e.id));
  assert.deepEqual([...ids].filter((id) => !DRIVERS[id]), [], 'inventory IDs without a driver');
  assert.deepEqual(Object.keys(DRIVERS).filter((id) => !ids.has(id)), [], 'drivers outside the inventory');
  // KEY_UI_FILTER narrows a local debugging run; the closed evaluator then reports every omitted entry as missing.
  const filter = process.env.KEY_UI_FILTER ? new RegExp(process.env.KEY_UI_FILTER) : null;
  const queue = inventory.entries.filter((e) => !filter || filter.test(`${e.id}|${e.variant}`));
  const worker = async () => {
    while (queue.length) {
      const { id, variant } = queue.shift();
      const driver = DRIVERS[id];
      const entry = { id, variant, status: 'NOT_EVALUATED', runId: RUN_ID };
      let session;
      try {
        session = await open(variant, { params: driver.params || {} });
        await driver.run(session.page, session);
        await until(session.page, driver.row || id);
        const { fail, facts } = await judgePage(session.page, id, variant);
        if (id === 'KW29-conflict' && session.sends !== 1) fail.push('conflict-sends');
        const shot = await capture(session.page, id, variant);
        // State-changing keyboard checks run after the judged screenshot of the row.
        if (id === 'KW31') fail.push(...await interaction(session.page));
        if (id === 'KW10') fail.push(...await pairingCancel(session.page));
        Object.assign(entry, shot, { checks: fail.length ? fail : ['all'],
          status: fail.length || session.errors.length || session.external.length ? 'FAIL' : 'PASS',
          pageErrors: session.errors, external: session.external, viewport: { width: facts.inner } });
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
    writeFileSync(path.join(OUT, 'key-ui-observation.json'), JSON.stringify({ runId: RUN_ID, sources: sourceDigest(),
      entries: observations.sort((a, b) => (a.id + a.variant).localeCompare(b.id + b.variant)) }, null, 2));
  }
  assert.deepEqual(result.errors, [], result.errors.slice(0, 20).join('\n'));
});

/**
 * KW31: keyboard order (Tab from the wallet disconnect reaches the send button directly; no outer input or payment
 * checkbox in between), visible focus, pressed and disabled styles, hostile label, Enter, and on a separate
 * controlled page keyboard activation of send invoking exactly one five-field wallet request.
 */
async function interaction(page) {
  const fail = [];
  const focus = await page.evaluate(() => { const c = getComputedStyle(document.activeElement);
    return [document.activeElement.id, c.outlineStyle, c.outlineWidth, c.outlineColor, c.outlineOffset]; });
  if (JSON.stringify(focus) !== JSON.stringify(['send', 'solid', '3px', 'rgb(59, 116, 23)', '4px'])) fail.push(`focus-style:${focus.join('/')}`);
  await page.keyboard.press('Shift+Tab');
  if (await page.evaluate(() => document.activeElement.id) !== 'wallet-disconnect') fail.push('tab-order-back');
  await page.keyboard.press('Tab');
  if (await page.evaluate(() => document.activeElement.id) !== 'send') fail.push('tab-order');
  if (await kh(page, () => window.__kh.provider.sends.length) !== 0) fail.push('focus-sent');
  const wallet = await page.locator('#wallet-choices').innerText();
  if (!wallet.includes('<img src=x onerror=window.__pwned=1>Evil"wallet')) fail.push('hostile-label-text');
  const pressed = page.locator('#wallet-disconnect');
  await pressed.scrollIntoViewIfNeeded();
  const pbox = await pressed.boundingBox();
  await page.mouse.move(pbox.x + 5, pbox.y + 5);
  await page.mouse.down();
  const transform = await pressed.evaluate((b) => getComputedStyle(b).transform);
  await page.mouse.move(0, 0);
  await page.mouse.up();
  if (transform !== 'matrix(1, 0, 0, 1, 0, 1)') fail.push(`pressed:${transform}`);
  // Enter activates a focused button: the focused wallet disconnect button disconnects the executor wallet.
  await page.focus('#wallet-disconnect');
  await page.keyboard.press('Enter');
  try {
    await page.waitForFunction(() => window.__kh.controller.view().wallet.status === 'disconnected', null, { timeout: 2000 });
  } catch { fail.push('keyboard-enter'); }
  if (await kh(page, () => window.__kh.provider.sends.length) !== 0) fail.push('disconnect-sent');
  const other = await open('1280x900');
  try {
    await walletConnected(other.page);
    await other.page.focus('#wallet-disconnect');
    await other.page.keyboard.press('Tab');
    await other.page.keyboard.press('Enter');
    await other.page.waitForFunction(() => window.__kh.controller.view().attempt.record?.status === 'hashKnown', null,
      { timeout: 5000 });
    const sends = await kh(other.page, () => window.__kh.provider.sends);
    if (sends.length !== 1) fail.push(`activation-sends:${sends.length}`);
    if (JSON.stringify(Object.keys(sends[0] || {}).sort()) !== JSON.stringify(['chainId', 'data', 'from', 'to', 'value'])) {
      fail.push('activation-request-fields');
    }
    await other.page.keyboard.press('Enter');
    if (await kh(other.page, () => window.__kh.provider.sends.length) !== 1) fail.push('activation-repeat');
  } catch (error) {
    fail.push(`activation:${String(error.message).slice(0, 60)}`);
  } finally { await other.context.close(); }
  return fail;
}

/** KW10: Tab reaches the pairing cancel, Enter cancels pairing, and focus is restored to #connect with a ring. */
async function pairingCancel(page) {
  const fail = [];
  await page.focus('#pairing-cancel');
  await page.keyboard.press('Enter');
  try {
    await page.waitForFunction(() => document.querySelector('main').dataset.row !== 'KW10', null, { timeout: 2000 });
  } catch { fail.push('pairing-cancel-enter'); return fail; }
  const focus = await page.evaluate(() => { const el = document.activeElement, c = getComputedStyle(el);
    return [el.id, el.matches(':focus-visible'), c.outlineStyle, c.outlineWidth, c.outlineColor, c.outlineOffset]; });
  if (JSON.stringify(focus) !== JSON.stringify(['connect', true, ...JSON.parse(FOCUS_RING)])) {
    fail.push(`pairing-cancel-focus:${focus.join('/')}`);
  }
  return fail;
}

/** Closed evaluator: unknown, duplicate, missing, stale, failed or NOT_EVALUATED entries prevent aggregate PASS. */
export function judgeInventory(inv, observation) {
  const errors = [];
  const wanted = new Set(inv.entries.map((e) => `${e.id}|${e.variant}`));
  const seen = new Set();
  for (const e of observation.entries || []) {
    const key = `${e.id}|${e.variant}`;
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

test('closed inventory is exactly the fixed 62 IDs / 130 entries, independent of production output', () => {
  assert.equal(REQUIRED_IDS.length, 62);
  const ids = [...new Set(inventory.entries.map((e) => e.id))].sort();
  assert.deepEqual(ids, [...REQUIRED_IDS].sort());
  assert.deepEqual([...inventory.requiredIds].sort(), [...REQUIRED_IDS].sort());
  assert.equal(inventory.entries.length, 130);
  assert.equal(inventory.requiredCount, 130);
  const keys = inventory.entries.map((e) => `${e.id}|${e.variant}`);
  assert.equal(new Set(keys).size, 130);
  for (const id of REQUIRED_IDS) {
    for (const variant of ['390x844', '1280x900']) assert.ok(keys.includes(`${id}|${variant}`), `${id}|${variant}`);
  }
  assert.deepEqual(inventory.entries.filter((e) => e.variant === '390x844-text200-reduced').map((e) => e.id).sort(),
    [...TEXT200].sort());
  for (const id of REMOVED_IDS) assert.ok(!ids.includes(id), id);
  for (const id of ['KW20-checking', 'KW20-nonce', 'KW26-fees', 'KW30-v2-reserved', 'KW30-v2-hash', 'KW30-v2-terminal',
    'KW26-cap']) assert.ok(ids.includes(id), id);
  // The production copy table carries every expected row text exactly; removed rows are gone from it too.
  for (const id of REQUIRED_IDS) if (id !== 'KW31') assert.equal(MESSAGES[id], EXPECTED_TEXT[id], id);
  assert.equal(EXPECTED_TEXT.KW31, MESSAGES.KW20);
  for (const id of REMOVED_IDS) assert.equal(MESSAGES[id], undefined, id);
  assert.ok(!JSON.stringify(inventory).includes('openspec/changes/'), 'permanent inventory must not cite an active change');
});

test('inventory evaluator rejects missing, duplicate, unknown, stale, failed and NOT_EVALUATED evidence', () => {
  const runId = 'r';
  const good = { runId, entries: inventory.entries.map((e) => ({ ...e, runId, status: 'PASS', bytes: 2000, screenshotSha256: 'a'.repeat(64) })) };
  assert.deepEqual(judgeInventory(inventory, good).errors, []);
  const variants = {
    missing: (o) => o.entries.pop(), duplicate: (o) => o.entries.push({ ...o.entries[0] }),
    unknown: (o) => o.entries.push({ ...o.entries[0], id: 'KW99' }), stale: (o) => { o.entries[0].runId = 'old'; },
    failed: (o) => { o.entries[1].status = 'FAIL'; }, unevaluated: (o) => { o.entries[2].status = 'NOT_EVALUATED'; },
    emptyShot: (o) => { o.entries[3].bytes = 0; },
  };
  for (const [name, mutate] of Object.entries(variants)) {
    const o = structuredClone(good);
    mutate(o);
    assert.ok(judgeInventory(inventory, o).errors.length > 0, name);
  }
});

test('real built entry: initial KW01 with no SDK load, external request, storage write or console error', async () => {
  const { page, context, external, errors } = await open('390x844', { real: true });
  const requested = [];
  page.on('request', (r) => requested.push(new URL(r.url()).pathname));
  await page.waitForFunction(() => document.querySelector('main').dataset.row === 'KW01');
  const { fail } = await judgePage(page, 'KW01', '390x844');
  assert.deepEqual(fail, []);
  assert.ok(!requested.some((p) => /signclient|walletconnect/.test(p)), requested.join());
  assert.deepEqual(external, []);
  assert.deepEqual(errors, []);
  assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);
  const response = await fetch(`http://127.0.0.1:${serverPort()}/key-change.html`);
  assert.match(response.headers.get('content-security-policy'), /frame-src https:\/\/verify\.walletconnect\.org/);
  await context.close();
});

test('negative controls: absent inherited CSS, collapsed sections and a renamed Safe page fail the visual judge', async () => {
  for (const [name, options] of Object.entries({
    noCss: { styles: '' },
    cards: { styles: readFileSync(path.join(app, 'styles.css'), 'utf8') + '\nsection{display:block!important;border:1px solid #000;border-radius:12px}' },
    overridden: { styles: readFileSync(path.join(app, 'styles.css'), 'utf8').replace('--paper: #f5f4ed', '--paper: #ffffff') },
    safePage: { swapPage: true },
    missingRecovery: { html: (html) => html.replace(/<section id="saved-recovery"[^>]*><\/section>/, '') },
    extraSection: { html: (html) => html.replace('</main>', '<section>unexpected</section></main>') },
  })) {
    const session = await open('1280x900', options);
    if (!options.swapPage) await session.page.waitForFunction(() => document.querySelector('main').dataset.row === 'KW01');
    const { fail } = await judgePage(session.page, 'KW01', '1280x900');
    assert.ok(fail.length > 0, `${name} passed the judge`);
    await session.context.close();
  }
});

test('negative controls: a retained outer input, payment checkbox, ceiling copy or disabled KW20 send fails the judge', async () => {
  const insert = (markup) => (html) => html.replace('<button id="send"', `${markup}\n        <button id="send"`);
  const controls = {
    outerInput: { html: insert('<label for="outer-gas">ガス上限</label><input type="text" id="outer-gas">') },
    hiddenOuterForm: { html: insert('<form id="outer-form" hidden><input type="text" id="outer-max"></form>') },
    paymentCheckbox: { html: insert('<label class="consent"><input type="checkbox" id="consent">表示した宛先・データ・費用上限で1回だけ送信することに同意します</label>') },
    renamedCheckbox: { html: insert('<label class="consent"><input type="checkbox" id="pay-ok">支払いに同意</label>') },
    ceilingCopy: { html: (html) => html.replace('<dl id="send-list"></dl>', '<dl id="send-list"></dl><p>3. 外側取引の最大費用（実行用ウォレット負担）</p>') },
    disabledSend: { after: () => { const c = window.__kh.controller, view = c.view.bind(c);
      c.view = () => { const v = view(); return { ...v, actions: { ...v.actions, send: false } }; }; c.emit(); } },
  };
  for (const [name, { html, after: patch }] of Object.entries(controls)) {
    const session = await open('1280x900', { html });
    try {
      await walletConnected(session.page);
      if (patch) await kh(session.page, patch);
      await until(session.page, 'KW20');
      const { fail } = await judgePage(session.page, 'KW20', '1280x900');
      assert.ok(fail.length > 0, `${name} passed the judge`);
    } finally { await session.context.close(); }
  }
  // Control: the unmodified page passes the same judge.
  const clean = await open('1280x900');
  try {
    await walletConnected(clean.page);
    assert.deepEqual((await judgePage(clean.page, 'KW20', '1280x900')).fail, []);
  } finally { await clean.context.close(); }
});
