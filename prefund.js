import { readURL } from './site.js';
// Prefund page: renders the typed prefund-controller view into prefund.html's four fixed sections and wires explicit
// user intents. Domain behavior comes only from typed presentation data, never from parsing visible labels. All public
// and peer text goes through textContent; raw error text is never shown. The bootstrap at the bottom injects the
// same-origin read-only RPC, the shared WalletManager (with truthful funding metadata) and the dedicated
// FundingAttemptStore; tests mount the same renderer with controlled dependencies.
import { CURRENT_TEXT, PrefundController } from './prefund-controller.js';
import { FundingAttemptStore } from './prefund-attempt-store.js';
import { ORIGIN, formatPol } from './key-model.js';
import { POLYGON, chainText } from './chains.js';
import { DEPOSIT_TO_SELECTOR, PREFUND_GAS, depositCall } from './prefund-model.js';
import { WalletManager } from './wallet.js';
import { mountPairingQR } from './pairing-qr.js';

/** Truthful WalletConnect metadata for this page (bounded override; other pages keep their defaults). */
export const PREFUND_METADATA = Object.freeze({ name: 'P-256 Signer 前払い残高',
  description: 'PolygonのSigner前払い残高へ入金します', url: ORIGIN, icons: Object.freeze([]) });

const SECTION = (row) => {
  const n = Number(row.slice(2, 4));
  return n <= 4 ? 'signer' : n <= 7 ? 'deposit' : n <= 12 ? 'wallet' : 'result';
};
// Error focus targets. PF11 (W < Q) falls back to wallet-error; PF13-wallet-lost goes to the wallet choice.
const FIELD = { PF02: 'authority', PF05: 'fee', 'PF13-fee-changed': 'fee', 'PF13-wallet-lost': 'wallet-choice' };
const STATUS_TEXT = { reserved: '保存済み・ウォレット応答待ち', hashKnown: '取引ハッシュ受信済み・未確認', unknown: '送信結果不明',
  confirming: '承認待ち', succeeded: '入金取引を検証済み', outerFailed: '取引失敗（入金なし）', uncertain: '未確定' };
// The view's one closed chain names every network row and native amount (Polygon until one is read).
let shownChain = POLYGON;
const pol = (wei) => `${wei} wei（${formatPol(wei)} ${shownChain.native}）`;
const gwei = (wei) => `${wei} wei`;

export function mountPrefundPage(doc, { controller, wallet, loadQR }) {
  const $ = (id) => doc.getElementById(id);
  let lastWalletUri = null, focusPending = null;

  function rows(id, entries) {
    const list = $(id);
    list.replaceChildren();
    for (const [term, value] of entries) {
      const dt = doc.createElement('dt'), dd = doc.createElement('dd');
      dt.textContent = term.replace(/([a-z])(?=[A-Z])|([/_-])/g, '$1$2\u200b');
      dd.textContent = value;
      dd.className = 'mono';
      list.append(dt, dd);
    }
  }
  const show = (id, visible) => { $(id).hidden = !visible; };
  const enable = (id, on) => { $(id).disabled = !on; };
  const sync = (id, value) => { if ($(id).value !== value && doc.activeElement !== $(id)) $(id).value = value; };
  const invalid = (id, on, described) => {
    if (on) $(id).setAttribute('aria-invalid', 'true'); else $(id).removeAttribute('aria-invalid');
    $(id).setAttribute('aria-describedby', described);
  };

  const drawQR = mountPairingQR(doc, $('wallet-qr'), loadQR);

  function render(view) {
    // The controller's one view chain: a governing attempt's recorded chain, otherwise the authority's.
    shownChain = view.chain || POLYGON;
    // The static Polygon header and switch words name the authority's chain (Polygon keeps the exact bytes).
    doc.querySelector('header span').textContent = chainText('EntryPoint前払い残高 · Polygon', shownChain);
    $('wallet-switch').textContent = chainText('Polygonに切り替える', shownChain);
    const section = SECTION(view.row);
    for (const name of ['signer', 'deposit', 'wallet', 'result']) {
      const status = $(`${name}-status`), alert = $(`${name}-error`);
      const mine = name === section;
      status.textContent = mine && !view.error ? view.message : '';
      status.hidden = !(mine && !view.error);
      alert.textContent = mine && view.error ? view.message : '';
      alert.hidden = !(mine && view.error);
    }
    const main = doc.querySelector('main');
    main.setAttribute('aria-busy', String(view.busy));
    main.dataset.row = view.row;

    // 01 SIGNER
    sync('authority', view.authorityText);
    $('authority').readOnly = !view.actions.editAuthority;
    invalid('authority', view.family === 'PF02', 'authority-help signer-error');
    enable('inspect', view.actions.inspect);
    show('inspect-cancel', view.actions.cancelInspect);
    const context = view.context;
    show('signer', Boolean(view.authority && context));
    if (view.authority && context) {
      $('signer-address').textContent = view.authority.signer;
      rows('signer-list', [['承認する鍵 keyID', view.authority.keyId], ['登録済みの鍵', `${context.keys.length}個（この鍵を含む）`],
        ['確認ブロック B', `${context.block.number} · ${context.block.hash}`],
        ['EntryPoint', `${view.entryPoint}（実行コード一致 ${context.entryPointCodeHash}）`]]);
    }

    // 02 DEPOSIT
    $('fee-fields').disabled = !view.actions.editFee;
    sync('fee', view.fee);
    invalid('fee', view.family === 'PF05', 'fee-help deposit-error');
    const plan = view.plan;
    show('deposit', Boolean(context && view.inspection === 'ready' && !view.governing));
    if (context && view.inspection === 'ready') {
      rows('deposit-list', [
        ['必要な前払い P', plan ? `${pol(plan.required)}（${PREFUND_GAS}ガス × ${gwei(plan.maxFee)}）` : '手数料上限の入力後に表示'],
        ['現在のデポジット D', pol(context.deposit)],
        ['不足額 Q（入金額）', plan ? pol(plan.amount) : '手数料上限の入力後に表示'],
        ['区分', 'Pは鍵操作1回分の前払いの目安です。今後の手数料や鍵変更の成功を保証しません。ウォレットの外側ガス代とは別です。'],
      ]);
    }
    show('custody', Boolean(plan && plan.amount > 0n && !view.governing));
    show('refresh', view.actions.refresh && (view.row === 'PF06-sufficient' || view.family === 'PF07'
      || view.family === 'PF12' || view.row === 'PF13-fee-changed'));

    // 03 WALLET
    const w = view.wallet;
    show('wallet', view.funding);
    const choices = $('wallet-choices');
    const key = JSON.stringify(w.choices.map((c) => [c.id, c.name, c.disabled]));
    if (choices.dataset.key !== key) {
      choices.replaceChildren(...w.choices.map((c) => {
        const label = doc.createElement('label'), input = doc.createElement('input'), text = doc.createElement('span');
        label.className = 'choice' + (c.disabled ? ' disabled' : '');
        input.type = 'radio'; input.name = 'wallet'; input.value = c.id; input.disabled = c.disabled;
        text.textContent = c.disabled && c.reason ? `${c.name}（${c.reason}）` : c.name;
        label.append(input, text);
        return label;
      }));
      choices.dataset.key = key;
    }
    for (const input of choices.querySelectorAll('input')) {
      input.checked = input.value === w.selectedId;
      input.disabled = w.choices.find((c) => c.id === input.value)?.disabled || !view.actions.walletChoose;
    }
    enable('wallet-connect', view.actions.walletConnect);
    show('wallet-connect', w.status === 'disconnected');
    show('wallet-pairing', Boolean(w.pairing) && view.funding);
    const walletUri = w.pairing?.uri || null;
    if (walletUri !== lastWalletUri) {
      lastWalletUri = walletUri;
      if (walletUri) $('wallet-open').href = walletUri; else $('wallet-open').removeAttribute('href');
      void drawQR(walletUri);
    }
    show('wallet-cancel', view.actions.walletCancel);
    show('wallet-switch', view.actions.walletSwitch);
    show('wallet-disconnect', view.actions.walletDisconnect && view.funding);
    show('wallet-account', Boolean(w.account) && view.funding);
    rows('wallet-account', w.account ? [['入金するアカウント', w.account], ['ネットワーク', w.chainId === shownChain.hex
      ? `${shownChain.name} (${shownChain.hex})` : `${shownChain.name}以外 (${w.chainId})`]] : []);
    // The wallet estimates, selects and confirms outer execution fees: the review shows only the exact deposit tuple.
    const review = view.review;
    show('review', Boolean(review && plan));
    if (review && plan) {
      rows('review-list', [
        ['ネットワーク chainId', `${shownChain.hex}（${shownChain.name}）`], ['送信元 from（ウォレット）', review.account],
        ['送信先 to（EntryPoint v0.7）', view.entryPoint],
        ['受取 Signerのデポジット', view.authority?.signerAddress || ''],
        ['data（depositTo）', `${depositCall(view.authority.signerAddress)}（${DEPOSIT_TO_SELECTOR} depositTo(signer)）`],
        ['入金額 value = 不足額 Q', pol(plan.amount)],
        ['注記', '入金額はSignerの鍵操作のガス予算として残り、サービス料金ではありません。この画面では出金できません。'],
      ]);
    }
    enable('send', view.actions.send);

    // 04 RESULT
    const a = view.attempt, record = a.record;
    const showRecord = view.governing || Boolean(a.storageError);
    show('attempt', showRecord);
    if (record && view.governing) {
      // v2 lists public lookup identity only. A historical v1 record is labeled read-only with its saved nonce/caps.
      const legacy = record.version === 1;
      const entries = [...(legacy ? [['履歴', '旧形式 v1（読取り専用）']] : []),
        ['状態', STATUS_TEXT[record.status]], ['記録ID', record.attemptId], ['Signer', record.signer],
        ['承認する鍵 keyID', record.authorizerKeyId], ['確認ブロック', `${record.inspectionBlockNumber} · ${record.inspectionBlockHash}`],
        ['必要な前払い P / 確認時のD', `${record.requiredDeposit} / ${record.observedDeposit} wei`],
        ['入金額 Q', pol(BigInt(record.amount))], ['ウォレット', record.walletAccount],
        ...(legacy ? [['ウォレットnonce（確認時）', record.walletPendingNonce],
          ['外側ガス上限 / 手数料上限 / 優先料', `${record.outerGasLimit} / ${record.outerMaxFeePerGas} / ${record.outerMaxPriorityFeePerGas} wei`]] : []),
        ['送信開始', `${record.sendStartedAt}（unix秒）`]];
      if (record.transactionHash) entries.push(['取引ハッシュ', record.transactionHash]);
      rows('attempt-list', entries);
    } else if (a.storageError) rows('attempt-list', [['状態', '送信記録を確認できません（上書き・削除はしません）']]);
    show('hash-form', view.actions.hashInput);
    sync('tx-hash', view.lookupText);
    show('reconcile', view.governing && !a.storageError);
    enable('reconcile', view.actions.reconcile);
    show('new-funding', view.actions.newFunding);
    show('storage-reload', view.actions.reloadStorage);
    const outcome = a.outcome;
    const costs = outcome?.costs;
    // Deposit evidence only. Actual gas cost is shown solely as chain-reverified history of a legacy v1 record; a v2
    // pending receipt (no amount and no failure) has no outcome panel.
    const legacyCost = Boolean(record && record.version === 1 && costs);
    const evidence = Boolean(costs && (costs.amount !== undefined || outcome.view === 'PF17-outer-failed' || legacyCost));
    show('outcome', evidence && view.governing);
    if (evidence) {
      const entries = legacyCost ? [['実際のガス代（ウォレット負担）', pol(costs.gasCost)]] : [];
      if (costs.amount !== undefined) {
        entries.push(['入金額（取引のvalue）', pol(costs.amount)]);
        entries.push(['Depositedイベントの累計デポジット', `${pol(costs.totalDeposit)}（入金額ではなく累計です）`]);
      } else if (outcome.view === 'PF17-outer-failed') entries.push(['入金額', '0（入金は確認されていません）']);
      rows('outcome-list', entries);
    }
    const current = outcome?.current;
    show('current', Boolean(current) && view.governing);
    if (current) {
      const entries = [];
      if (current.deposit !== undefined) {
        entries.push(['現在のデポジット', pol(current.deposit)], ['必要額に対する不足', pol(current.shortage)],
          ['確認ブロック', `${current.block.number} · ${current.block.hash}`]);
      }
      if (current.reason) entries.push(['現在の状態', CURRENT_TEXT[current.reason]]);
      rows('current-list', entries);
    }
    show('return-link', ['PF06', 'PF19', 'PF20'].includes(view.family));

    if (focusPending) {
      const target = focusPending === 'auto' ? autoFocus(view, section) : focusPending;
      const node = target === 'wallet-choice' ? $('wallet-choices').querySelector('input:not(:disabled)')
        : target && $(target);
      if (node && !node.hidden && node.offsetParent !== null) {
        if (node.tagName === 'H3' || node.tagName === 'DIV') node.tabIndex = -1;
        node.focus();
      }
    }
    focusPending = null;
  }

  /** Explicit commands place focus on their result or error once they complete; new draws never steal focus. */
  function autoFocus(view, section) {
    if (view.error) return FIELD[view.row] || FIELD[view.family] || `${section}-error`;
    // A completed review focuses the enabled send; a retained review without a live wallet focuses the wallet choice.
    if (view.row === 'PF12-ready') return view.actions.send ? 'send' : view.actions.walletConnect ? 'wallet-connect'
      : 'wallet-choice';
    if (view.family === 'PF03' || view.family === 'PF01') return 'inspect';
    if (['PF05', 'PF06', 'PF07'].includes(view.family)) return 'signer-heading';
    if (!$('outcome').hidden) return 'outcome-heading';
    if (!$('attempt').hidden) return 'attempt-heading';
    if (view.row === 'PF23-new-attempt') return 'authority';
    return null;
  }
  const command = (fn) => async () => {
    await fn();
    focusPending = 'auto';
    render(controller.view());
  };

  controller.onState = render;
  $('authority-form').addEventListener('submit', (e) => { e.preventDefault(); void command(() => controller.inspect())(); });
  $('authority').addEventListener('input', () => controller.setAuthorityText($('authority').value));
  $('inspect-cancel').addEventListener('click', () => { focusPending = 'inspect'; controller.cancelInspect(); });
  $('refresh').addEventListener('click', command(() => controller.inspect()));
  $('fee').addEventListener('input', () => controller.setFee($('fee').value));
  $('fee-form').addEventListener('submit', (e) => e.preventDefault());
  $('wallet-choices').addEventListener('change', (e) => { wallet.select(e.target.value); controller.walletChanged(); });
  $('wallet-connect').addEventListener('click', () => void wallet.connect());
  $('wallet-cancel').addEventListener('click', () => { focusPending = 'wallet-connect'; wallet.cancelPairing(); });
  $('wallet-switch').addEventListener('click', () => void controller.switchPolygon());
  $('wallet-disconnect').addEventListener('click', () => void wallet.disconnect());
  $('send').addEventListener('click', command(() => controller.send()));
  $('tx-hash').addEventListener('input', () => controller.setLookupHash($('tx-hash').value));
  $('hash-form').addEventListener('submit', (e) => { e.preventDefault(); void command(() => controller.reconcile())(); });
  $('reconcile').addEventListener('click', command(() => controller.reconcile()));
  $('new-funding').addEventListener('click', command(() => controller.newFunding()));
  $('storage-reload').addEventListener('click', command(() => controller.reloadAttempt()));
  render(controller.view());
  return { render };
}

// ---------------------------------------------------------------------------------------------------------------
// Production bootstrap (skipped when a local test harness mounts the renderer itself)

const RPC_TIMEOUT_MS = 10_000;
let rpcId = 0;

/** One read through the fixed same-origin relay route of one closed chain (`chains.js`); never caller text. */
async function relay(route, method, params) {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), RPC_TIMEOUT_MS);
  try {
    const response = await fetch(readURL(route, method), { method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal: abort.signal,
      body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }) });
    if (!response.ok) throw new TypeError('relay unavailable');
    const body = await response.json();
    if (body && body.error) throw Object.assign(new Error('RPC error'), { code: -32000 });
    return body.result;
  } finally {
    clearTimeout(timer);
  }
}

const rpcFor = (selected) => (method, params) => relay(selected.route, method, params);
const rpc = rpcFor(POLYGON);

async function loadConfig() {
  const response = await fetch('./config.json', { credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
  const text = await response.text();
  if (!response.ok || new TextEncoder().encode(text).length > 4096) throw new Error('config');
  return JSON.parse(text);
}

async function start() {
  let config = null;
  try { config = await loadConfig(); } catch { config = null; }
  let controller = null;
  const wallet = new WalletManager({ win: window, config, origin: location.origin, metadata: PREFUND_METADATA,
    loadWalletConnect: () => import('./walletconnect.js'), onChange: () => controller && controller.walletChanged() });
  let factory;
  try { factory = window.indexedDB || null; } catch { factory = null; }
  const store = new FundingAttemptStore({ indexedDB: factory || { open() { throw new Error('indexedDB unavailable'); } } });
  controller = new PrefundController({ rpc, rpcFor, wallet, store, clock: () => Math.floor(Date.now() / 1000),
    uuid: () => crypto.randomUUID() });
  mountPrefundPage(document, { controller, wallet, loadQR: () => import('./qr.js').then((module) => module.default) });
  wallet.start();
  addEventListener('pagehide', () => controller.destroy());
  await controller.start();
}

if (typeof window !== 'undefined' && !window.__PREFUND_HARNESS__) void start();
