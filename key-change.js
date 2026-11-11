import { readRPC as relay } from './read-rpc.js';
// Key-change page: renders the typed key-controller view into key-change.html's four fixed sections and wires
// explicit user intents. All public and peer text goes through textContent; no raw error text is ever shown.
// The bootstrap at the bottom injects the fixed public read-only RPC, the shared WalletManager (executor wallet), the
// dedicated attempt store and the lazily loaded SignClient; tests mount the same renderer with controlled deps.
import { KeyChangeController, MESSAGES } from './key-controller.js';
import { KeyAttemptStore } from './key-attempt-store.js';
import { mountRecoveryPanel } from './recovery-panel.js';
import { PURPOSE, TOTAL_GAS, parseKeyChangeFragment } from './key-model.js';
import { POLYGON, chainText } from './chains.js';
import { ENTRYPOINT, PRE_VERIFICATION_GAS, VERIFICATION_GAS, CALL_GAS, formatPol, typedDataHash, userOpHash }
  from './key-model.js';
import { WalletManager } from './wallet.js';
import { mountPairingQR } from './pairing-qr.js';

const SECTION = (row) => {
  const n = Number(row.slice(2, 4));
  return n <= 4 ? 'signer' : n <= 9 ? 'change' : n <= 16 ? 'approval' : 'execute';
};
const FIELD = { KW02: 'anchor', 'KW07-duplicate': 'bare-key', 'KW07-curve': 'bare-key', 'KW07-limit': 'bare-key',
  'KW08-blank': 'fee-max', 'KW08-format': 'fee-max', 'KW08-bounds': 'fee-max' };
const STATUS_TEXT = { reserved: '保存済み・ウォレット応答待ち', hashKnown: '取引ハッシュ受信済み・未確認', unknown: '送信結果不明',
  confirming: '承認待ち', succeeded: '鍵変更を検証済み', innerFailed: '鍵変更失敗（外側取引は成功）', outerFailed: '外側取引失敗',
  uncertain: '未確定', stateResolved: '現在の状態のみ一致（実行は未証明）' };
const BUSY = new Set(['KW03', 'KW10', 'KW14', 'KW20-checking', 'KW21']);
const gwei = (wei) => `${wei} wei`;

export function mountKeyChangePage(doc, { controller, wallet, loadQR }) {
  const $ = (id) => doc.getElementById(id);
  // The view's one closed chain names every network row and native amount (Polygon until an anchor is read).
  let chain = POLYGON;
  const pol = (wei) => `${wei} wei（${formatPol(wei)} ${chain.native}）`;
  let lastRow = null, lastNativeUri = null, lastWalletUri = null, rendered = false, focusPending = null;

  function rows(id, entries) {
    const list = $(id);
    list.replaceChildren();
    for (const [term, value] of entries) {
      const dt = doc.createElement('dt'), dd = doc.createElement('dd');
      // Soft break points inside long camelCase/path terms (dt has no overflow-wrap in the inherited CSS).
      dt.textContent = term.replace(/([a-z])(?=[A-Z])|([/_-])/g, '$1$2\u200b');
      dd.textContent = value;
      dd.className = 'mono';
      list.append(dt, dd);
    }
  }
  const keyLines = (keys, marker) => keys.map((k) => `${k.keyId}${k.keyId === marker ? '（承認する鍵）' : ''}`).join('\n');
  const show = (id, visible) => { $(id).hidden = !visible; };
  const enable = (id, on) => { $(id).disabled = !on; };

  const drawNativeQR = mountPairingQR(doc, $('pairing-qr'), loadQR);
  const drawWalletQR = mountPairingQR(doc, $('wallet-qr'), loadQR);

  function render(view) {
    // The controller's one view chain: a governing attempt's recorded chain, otherwise the anchor's.
    chain = view.chain || POLYGON;
    // The static Polygon header and switch words name the anchor's chain (Polygon keeps the exact bytes).
    doc.querySelector('header span').textContent = chainText('内部鍵の追加・削除 · Polygon', chain);
    $('wallet-switch').textContent = chainText('Polygonに切り替える', chain);
    const section = SECTION(view.row);
    for (const name of ['signer', 'change', 'approval', 'execute']) {
      const status = $(`${name}-status`), alert = $(`${name}-error`);
      const mine = name === section;
      status.textContent = mine && !view.error ? view.message : '';
      status.hidden = !(mine && !view.error);
      alert.textContent = mine && view.error ? view.message : '';
      alert.hidden = !(mine && view.error);
    }
    doc.querySelector('main').setAttribute('aria-busy', String(BUSY.has(view.row) || view.attempt.reconciling
      || view.native.phase === 'inspecting'));
    doc.querySelector('main').dataset.row = view.row;

    // 01 SIGNER
    const reading = view.inspection === 'reading';
    enable('inspect', view.actions.inspect);
    $('anchor').readOnly = reading;
    show('inspect-cancel', view.actions.cancelInspect);
    const context = view.context;
    show('signer', Boolean(view.anchor && context));
    if (view.anchor && context) {
      $('signer-address').textContent = view.anchor.signer;
      $('signer-keyid').textContent = view.anchor.keyId;
      $('signer-key').textContent = view.anchor.publicKey;
      $('signer-block').textContent = `${context.block.number} · ${context.block.hash}`;
      $('signer-nonce').textContent = context.nonce.toString();
    }

    // 02 CHANGE
    const ready = view.inspection === 'ready' && context;
    const editable = ready && ['idle', 'failed', 'connected'].includes(view.native.phase) && !view.attempt.sending;
    $('change-fields').disabled = !editable;
    show('keys', Boolean(ready));
    if (ready) {
      $('keys-count').textContent = String(context.keys.length);
      rows('keys-list', context.keys.map((k) => [k.keyId === view.anchor.keyId ? '承認する鍵' : '登録済み',
        `${k.keyId}\n${k.publicKey}`]));
      const choices = $('remove-choices');
      const ids = context.keys.map((k) => k.keyId).join();
      if (choices.dataset.ids !== ids) {
        choices.replaceChildren(...context.keys.map((k) => {
          const label = doc.createElement('label'), input = doc.createElement('input'), text = doc.createElement('span');
          label.className = 'choice';
          input.type = 'radio'; input.name = 'remove'; input.value = k.keyId;
          text.textContent = k.keyId + (k.keyId === view.anchor.keyId ? '（このiPhoneの鍵）' : '');
          label.append(input, text);
          return label;
        }));
        choices.dataset.ids = ids;
      }
      for (const input of choices.querySelectorAll('input')) input.checked = input.value === view.removeKeyId;
    }
    $('mode-add').checked = view.mode === 'add';
    $('mode-remove').checked = view.mode === 'remove';
    show('add-fields', view.mode === 'add');
    show('remove-fields', view.mode === 'remove');
    $('self-removal').textContent = view.selfRemoval ? MESSAGES.selfRemoval : '';
    show('self-removal', view.selfRemoval);
    show('effect', Boolean(view.plan && view.cost));
    if (view.plan && view.cost) {
      rows('effect-list', [
        ['操作', view.plan.action === 'add' ? `鍵の追加: ${view.plan.target.keyId}` : `鍵の削除: ${view.plan.target.keyId}`],
        ['鍵数', `${view.plan.before.length} → ${view.plan.after.length}`],
        ['必要な前払い P', pol(view.cost.required)],
        ['Signerのデポジット D', pol(view.cost.deposit)],
        ['不足額', pol(view.cost.shortfall)],
        ['注記', '使われなかったデポジットはSignerに残ります。前払いは運営者の手数料ではありません。'],
      ]);
    }
    show('refresh', view.row === 'KW09');
    // Secondary plain link to the separate funding page: no authority, fee or state travels in the URL.
    show('prefund-link', view.row === 'KW09');

    // 03 APPROVAL
    const n = view.native;
    const governing = Boolean(view.attempt.record) && !view.rollover;
    show('connect', ['idle', 'failed', 'pairing'].includes(n.phase) && !governing);
    enable('connect', view.actions.connectNative);
    show('pairing', n.phase === 'pairing');
    const nativeUri = n.phase === 'pairing' ? n.uri : null;
    if (nativeUri !== lastNativeUri) {
      lastNativeUri = nativeUri;
      if (nativeUri) $('pairing-open').href = nativeUri; else $('pairing-open').removeAttribute('href');
      void drawNativeQR(nativeUri);
    }
    show('preview', ['connected', 'inspecting'].includes(n.phase));
    enable('preview', view.actions.previewNative);
    const previewing = ['preview', 'approving'].includes(n.phase) && view.plan;
    show('request', Boolean(previewing));
    if (previewing) {
      const p = view.plan, op = p.operation;
      rows('request-list', [
        ['ネットワーク', chain.network], ['Signer (sender)', op.sender],
        ['承認する鍵 keyID', view.anchor.keyId], ['binding', n.context.binding],
        ['操作', p.action === 'add' ? '鍵の追加 addKey' : '鍵の削除 removeKey'],
        ['対象 keyID', p.target.keyId], ['対象の公開鍵', p.target.publicKey], ['nonce', op.nonce],
        ['callData', op.callData],
        ['accountGasLimits', `${op.accountGasLimits}（verification ${VERIFICATION_GAS} / call ${CALL_GAS}）`],
        ['preVerificationGas', String(PRE_VERIFICATION_GAS)],
        ['gasFees', `${op.gasFees}（priority ${gwei(view.fees.priorityFee)} / max ${gwei(view.fees.maxFee)}）`],
        ['initCode / paymasterAndData / signature', '0x / 0x / 0x'], ['EntryPoint', ENTRYPOINT],
        ['Hybrid EIP-712 H（署名対象）', typedDataHash(op, chain.decimal)],
        ['EntryPoint userOpHash', userOpHash(op, chain.decimal)],
        ['変更前の全鍵', keyLines(p.before, view.anchor.keyId)], ['変更後の全鍵', keyLines(p.after, view.anchor.keyId)],
        ['必要な前払い P', pol(view.cost.required)], ['要求ID・期限', '要求時に発行（発行から120秒）'],
      ]);
    }
    show('sign', Boolean(previewing));
    enable('sign', view.actions.requestSignature);
    $('sign').textContent = view.plan?.action === 'remove' ? 'この鍵を削除する要求' : '表示した鍵変更をiPhoneに要求';
    show('disconnect', view.actions.disconnectNative);
    show('verified', Boolean(view.signed) && n.phase === 'verified');
    if (view.signed && n.phase === 'verified') {
      const r = view.signed.request;
      rows('verified-list', [['要求ID', r.id], ['H', r.typedDataHash], ['userOpHash', r.userOpHash],
        ['commitment', r.commitment], ['signerSignature（96バイト）', view.signed.signerSignature],
        ['送信期限（ブラウザ）', `${r.expiresAt}（unix秒）`],
        ['意味', 'ブラウザでP-256署名を検証しただけで、まだ送信・実行していません。期限後はこのページから送信できませんが、署名自体がチェーン上で失効するわけではありません。']]);
    }

    // 04 EXECUTE
    const w = view.wallet;
    const walletStage = n.phase === 'verified' && !governing;
    show('wallet', walletStage);
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
    show('wallet-pairing', Boolean(w.pairing));
    const walletUri = w.pairing?.uri || null;
    if (walletUri !== lastWalletUri) {
      lastWalletUri = walletUri;
      if (walletUri) $('wallet-open').href = walletUri; else $('wallet-open').removeAttribute('href');
      void drawWalletQR(walletUri);
    }
    show('wallet-cancel', view.actions.walletCancel);
    show('wallet-switch', view.actions.walletSwitch);
    show('wallet-disconnect', view.actions.walletDisconnect && walletStage);
    show('wallet-account', Boolean(w.account) && walletStage);
    rows('wallet-account', w.account ? [['実行用アカウント（受取人も同じ）', w.account]] : []);
    // The wallet owns outer gas, fees and nonce: no outer input, quote or payment checkbox is rendered here.
    const sendStage = walletStage && w.status === 'connected';
    show('send-review', sendStage);
    if (sendStage && view.signed) {
      const signed = view.signed;
      rows('send-list', [
        ['送信先 to', `${ENTRYPOINT}（EntryPoint v0.7 handleOps）`], ['送信元 from', w.account],
        ['受取人 beneficiary', w.account], ['value', '0'], ['chainId', `${chain.hex}（${chain.name}）`],
        ['data', `handleOps([署名済みの鍵変更1件], ${w.account?.toLowerCase()})`],
        ['UserOperation', `${signed.request.userOpHash}（nonce ${signed.request.operation.nonce}）`],
        ['1. 必要な前払い（Signerのデポジットから）', pol(signed.cost.required)],
        ['2. 確認したデポジット・不足', `${pol(signed.cost.deposit)} / 不足 ${pol(signed.cost.shortfall)}`],
        ['3. 受取人への払戻し', 'EntryPointが実際の費用 actualGasCost（最大P）を受取人に支払います。外側費用との差額は保証しません。'],
      ]);
    }
    enable('send', view.actions.send);

    const a = view.attempt, record = a.record;
    show('attempt', Boolean(record) || Boolean(a.storageError));
    if (record) {
      const entries = [['状態', STATUS_TEXT[record.status]], ['記録ID', record.attemptId], ['Signer', record.signer],
        ['Signer nonce', record.signerNonce], ['userOpHash', record.userOpHash], ['H', record.typedDataHash],
        ['実行用アカウント・受取人', record.walletAccount]];
      // Legacy v1 records keep their historical ceilings (read-only bounds, no control or payment authority).
      if (record.version === 1) {
        entries.push(['外側ガス上限', record.outerGasLimit],
          ['外側手数料上限 / 優先料', `${record.outerMaxFeePerGas} / ${record.outerMaxPriorityFeePerGas} wei`]);
      }
      entries.push(['送信開始', `${record.sendStartedAt}（unix秒）`]);
      if (record.transactionHash) entries.push(['取引ハッシュ', record.transactionHash]);
      if (record.receipt) entries.push(['受領ブロック', `${record.receipt.blockNumber} · ${record.receipt.blockHash} · status ${record.receipt.status}`]);
      rows('attempt-list', entries);
    } else if (a.storageError) rows('attempt-list', [['状態', '送信記録を確認できません']]);
    show('hash-form', view.actions.hashInput);
    show('reconcile', Boolean(record) && a.storageError !== 'corrupt');
    enable('reconcile', view.actions.reconcile);
    show('new-change', view.actions.newChange);
    show('storage-reload', view.actions.reloadStorage);
    show('rollover-ack-label', Boolean(view.rollover?.needsAck));
    $('rollover-ack-text').textContent = view.rollover?.needsAck ? MESSAGES.rolloverAck : '';
    $('rollover-ack').checked = Boolean(view.rollover?.ack);
    const outcome = a.outcome, costs = view.costs;
    show('outcome', Boolean(outcome && (costs || outcome.keys)));
    if (outcome && (costs || outcome.keys)) {
      const entries = [];
      if (costs?.outerCost !== undefined) entries.push(['実際の外側費用', pol(costs.outerCost)]);
      if (costs?.actualGasCost !== undefined) {
        entries.push(['EntryPoint actualGasCost（受取人へ）', pol(costs.actualGasCost)]);
        entries.push(['実行用ウォレットの正味ガス支出', `${costs.net} wei（負の値は受取超過）`]);
      }
      if (outcome.keys) entries.push(['確認した全鍵', outcome.keys.map((k) => k.keyId).join('\n')]);
      rows('outcome-list', entries);
    }

    // Focus: field or alert for new errors; new result headings; never on first render.
    if (rendered && view.row !== lastRow) {
      const target = focusPending || (view.error ? FIELD[view.row] || `${section}-error`
        : view.row === 'KW05' || view.row === 'KW06' ? 'keys-heading'
          : view.row === 'KW12' || view.row === 'KW13' ? 'request-heading'
            : view.row === 'KW15' ? 'verified-heading'
              : /^KW2[3-8]|^KW26/.test(view.row) && !$('outcome').hidden ? 'outcome-heading' : null);
      const node = target && $(target);
      if (node && !node.hidden && node.offsetParent !== null) {
        if (node.tagName === 'H3' || node.tagName === 'DIV') node.tabIndex = -1;
        node.focus();
      }
    }
    focusPending = null;
    lastRow = view.row;
    rendered = true;
  }

  controller.onState = render;
  $('anchor-form').addEventListener('submit', (e) => { e.preventDefault(); void controller.inspect(); });
  $('anchor').addEventListener('input', () => controller.setAnchorText($('anchor').value));
  $('inspect-cancel').addEventListener('click', () => { focusPending = 'inspect'; controller.cancelInspect(); });
  $('refresh').addEventListener('click', () => void controller.inspect());
  $('mode-add').addEventListener('change', () => controller.setChange({ mode: 'add' }));
  $('mode-remove').addEventListener('change', () => controller.setChange({ mode: 'remove' }));
  $('bare-key').addEventListener('input', () => controller.setChange({ bareText: $('bare-key').value }));
  $('remove-choices').addEventListener('change', (e) => controller.setChange({ removeKeyId: e.target.value }));
  $('fee-max').addEventListener('input', () => controller.setChange({ feeMax: $('fee-max').value }));
  $('fee-priority').addEventListener('input', () => controller.setChange({ feePriority: $('fee-priority').value }));
  $('change-form').addEventListener('submit', (e) => e.preventDefault());
  $('connect').addEventListener('click', () => void controller.connectNative());
  $('pairing-cancel').addEventListener('click', () => { focusPending = 'connect'; void controller.disconnectNative(); });
  $('preview').addEventListener('click', () => void controller.previewNative());
  $('sign').addEventListener('click', () => void controller.requestSignature());
  $('disconnect').addEventListener('click', () => { focusPending = 'connect'; void controller.disconnectNative(); });
  $('wallet-choices').addEventListener('change', (e) => { wallet.select(e.target.value); controller.walletChanged(); });
  $('wallet-connect').addEventListener('click', () => void wallet.connect());
  $('wallet-cancel').addEventListener('click', () => { focusPending = 'wallet-connect'; wallet.cancelPairing(); });
  $('wallet-switch').addEventListener('click', () => void controller.switchPolygon());
  $('wallet-disconnect').addEventListener('click', () => void wallet.disconnect());
  $('send').addEventListener('click', () => void controller.send());
  $('hash-form').addEventListener('submit', (e) => { e.preventDefault(); void controller.reconcile($('tx-hash').value); });
  $('reconcile').addEventListener('click', () => void controller.reconcile($('tx-hash').value));
  $('new-change').addEventListener('click', () => void controller.newChange());
  $('rollover-ack').addEventListener('change', () => controller.setRolloverAck($('rollover-ack').checked));
  $('storage-reload').addEventListener('click', () => void controller.reloadAttempt());
  const host = doc.getElementById('saved-recovery');
  let recovery = null;
  if (host) recovery = mountRecoveryPanel(doc, host, { purpose: PURPOSE,
    getClient: () => controller.signClient(), clock: () => controller.now(),
    store: controller.savedResultStore,
    getExpected: () => {
      const p = controller.plan();
      if (controller.blocked() || controller.session || !p.plan || p.problem) throw new Error('input');
      const a = controller.s.anchor;
      return { anchor: { signerAddress: a.signerAddress, keyId: a.keyId, publicKey: a.publicKey },
        operation: p.plan.operation, beforeKeys: p.plan.before, expectedAfterKeys: p.plan.after,
        maxGasUnits: TOTAL_GAS.toString(), maxFeePerGas: p.fees.maxFee.toString() };
    },
    adopted: (record, result, session) => controller.adoptRecovered(record, result, session) });
  // Any independently entered operation/anchor change cancels even a not-yet-adopted recovery.
  for (const id of ['anchor', 'mode-add', 'mode-remove', 'bare-key', 'remove-choices', 'fee-max', 'fee-priority']) {
    for (const event of ['input', 'change']) $(id).addEventListener(event, () => void recovery?.close());
  }
  doc.defaultView?.addEventListener('pagehide', () => void recovery?.close());
  // `#key-change=` from the iPhone 「署名者を追加」: history is replaced first (no navigation), then the two public
  // fields are only filled; inspection, the iPhone approval and the wallet send stay explicit. Invalid → empty.
  const win = doc.defaultView;
  if (win && typeof win.location?.hash === 'string' && win.location.hash.startsWith('#key-change=')) {
    const hash = win.location.hash.slice(0, 12 + 5462);
    win.history.replaceState(null, '', win.location.pathname);
    try {
      const prefill = parseKeyChangeFragment(hash);
      $('anchor').value = prefill.authorityText;
      controller.setAnchorText(prefill.authorityText);
      $('mode-add').checked = true;
      $('bare-key').value = prefill.keyText;
      controller.setChange({ mode: 'add', bareText: prefill.keyText });
    } catch { /* Manual paste remains. */ }
  }
  render(controller.view());
  return { render, recovery };
}

// ---------------------------------------------------------------------------------------------------------------
// Production bootstrap (skipped when a local test harness mounts the renderer itself)


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
  const wallet = new WalletManager({ win: window, config, origin: location.origin,
    loadWalletConnect: () => import('./walletconnect.js'), onChange: () => controller && controller.walletChanged() });
  let factory;
  try { factory = window.indexedDB || null; } catch { factory = null; }
  const store = new KeyAttemptStore({ indexedDB: factory || { open() { throw new Error('indexedDB unavailable'); } } });
  controller = new KeyChangeController({ rpc, rpcFor, wallet, store,
    loadSignClient: () => import('./safe-signclient.js').then((module) => module.SignClient),
    loadConfig: async () => config, clock: () => Math.floor(Date.now() / 1000), uuid: () => crypto.randomUUID() });
  mountKeyChangePage(document, { controller, wallet, loadQR: () => import('./qr.js').then((module) => module.default) });
  wallet.start();
  addEventListener('pagehide', () => { controller.invalidateAuthority(); store.close(); });
  await controller.loadAttempt();
}

if (typeof window !== 'undefined' && !window.__KEY_CHANGE_HARNESS__) void start();
