// Renders the controller's typed view into the compact deployment document and forwards native
// control events to controller commands. It never inspects labels to decide domain behaviour.
// The main action connects without sending; its next activation requests deployment. Diagnostic controls and
// recovery stay under closed details; unsaved outcomes and safety errors stay visible.
// New (v2) operations show identity, hash, block and status only: the wallet owns gas/fees, so no app fee
// summary is rendered. Historical v1 records keep their original requested/observed fee evidence read-only.
import { formatPol, handoffChain } from './model.js';
import { POLYGON } from './chains.js';
import { mountPairingQR } from './pairing-qr.js';

const GWEI = 1_000_000_000n;

function gwei(wei) {
  const value = BigInt(wei);
  const whole = value / GWEI;
  const fraction = (value % GWEI).toString().padStart(9, '0').replace(/0+$/, '');
  return `${whole}${fraction ? '.' + fraction : ''} gwei`;
}

const READBACK = {
  deployed: '配備済み（固定実装・EOA管理者なし・この公開鍵1つを読取り確認）',
  'not-deployed': '未配備（予定アドレスにコードなし）',
  unknown: '不明（読取りできないか再編成中）',
  mismatch: '不一致',
};

const UNKNOWN_REASONS = {
  'send-timeout': 'ウォレットの応答が60秒以内にありません',
  'send-error': 'ウォレットとの通信が途切れました',
  'malformed-hash': 'ウォレットの応答が取引ハッシュではありません',
  reload: '承認待ちの間にページが再読み込みされました',
  'other-tab': '別のタブまたはウィンドウで送信が始まっています',
  'cancel-unverified': 'nonceを消費した別の取引を読取りで再確認できません',
  identity: '取引の内容（chain・from・to・data・value）が保存した送信と一致しません',
  readback: '確定した取引の配備内容を読取りで確認できません',
  rpc: '読取りRPCで確認できません',
  range: '置換取引の探索範囲（128ブロック）を超えました',
  'no-candidate': '送信元のnonceは使われましたが、該当する取引が見つかりません',
  'unverified-nonce': '実際に使われたnonceを確認できていないため、取消しとは判断できません',
  timeout: '置換取引の探索が時間内に終わりませんでした',
  status: '取引結果の形式が不正です',
  evidence: '取引の内容を読取りで一貫して確認できません',
  receipt: 'レシートが取引の内容（ブロック・gas）と一致しません',
};

const STORAGE_NOTICES = {
  initializing: '送信記録を確認しています。',
  unsaved: '取引情報を保存できませんでした。ページを閉じずに「状況を更新」で再試行してください。',
  lateConflict: 'ウォレットが別の取引ハッシュを返しました。保存済みの記録を優先し、この記録は変更しません。',
  newer: '別のタブまたはウィンドウで更新された送信記録を表示しています。読取りRPCで確認し直します。',
  cleared: 'この送信記録は別のタブまたはウィンドウで消去されました。新しい送信はページを再読み込みしてから行ってください。',
};

export function mountUI(doc, controller, { loadQR, clipboard }) {
  const $ = (id) => doc.getElementById(id);
  $('manual-import').append($('import-form'));
  $('import-form').hidden = false;
  $('manual-controls').append($('disconnect'));
  doc.querySelector('main').insertBefore($('send-error'), $('payload-details'));
  const show = (id, visible) => { $(id).hidden = !visible; };
  const text = (id, value) => { if ($(id).textContent !== value) $(id).textContent = value; };
  const alert = (id, error) => {
    show(id, Boolean(error));
    text(id, error ? error.message || String(error) : '');
  };
  let lastFocus = 0;
  let lastChoices = '';
  let lastQR = null;
  const drawQR = mountPairingQR(doc, $('pairing-qr'), loadQR);

  function rows(id, entries) {
    const list = $(id);
    const key = JSON.stringify(entries);
    if (list.dataset.key === key) return;
    list.dataset.key = key;
    list.replaceChildren(...entries.flatMap(([term, value, mono]) => {
      const dt = doc.createElement('dt');
      dt.textContent = term;
      const dd = doc.createElement('dd');
      dd.textContent = value;
      if (mono) dd.className = 'mono';
      return [dt, dd];
    }));
  }

  function renderChoices(view) {
    const choices = view.wallet.choices;
    const key = JSON.stringify([choices, view.wallet.selectedId]);
    if (key === lastChoices) return;
    lastChoices = key;
    const container = $('wallet-choices');
    container.replaceChildren(...choices.map((choice) => {
      const label = doc.createElement('label');
      label.className = 'choice' + (choice.disabled ? ' disabled' : '');
      const input = doc.createElement('input');
      input.type = 'radio';
      input.name = 'wallet';
      input.value = choice.id;
      input.id = 'wallet-' + choice.id.replace(/[^A-Za-z0-9_-]/g, '_');
      input.disabled = choice.disabled;
      input.checked = view.wallet.selectedId === choice.id;
      const name = doc.createElement('span');
      // Provider names are untrusted plain text; icons are never rendered.
      name.textContent = choice.name + (choice.reason ? ` — ${choice.reason}` : '');
      label.append(input, name);
      return label;
    }));
  }

  /** The one closed chain of the shown plan (or attempt record): its own name, ID and native currency. */
  function chainOfView(view, record) {
    try { return handoffChain((record || view.plan || {}).manifest || (view.plan || {}).handoff); } catch { return POLYGON; }
  }
  const chainLine = (chain) => `${chain.name} · ${chain.id}`;

  function walletStatus(view) {
    const w = view.wallet, target = chainOfView(view);
    if (w.status === 'connecting') return w.kind === 'walletconnect' && !w.pairing
      ? 'WalletConnectを準備しています…' : 'ウォレットの接続承認を待っています…';
    if (w.status === 'connected') return `接続中のアカウント: ${w.account}\nネットワーク: ${target.title}`;
    if (w.status === 'wrongChain') {
      const chain = w.chainId ? `chain ${BigInt(w.chainId)}` : '不明なネットワーク';
      return `接続中のアカウント: ${w.account}\nネットワーク: ${chain} — ${target.title}に切り替えてください。送信はできません。`;
    }
    return '';
  }

  /** Storage notices appended to the settlement status as plain bounded text (no new control or layout). */
  function noticeText(view) {
    const n = view.notices;
    return [n.unsaved && STORAGE_NOTICES.unsaved, n.lateHash && STORAGE_NOTICES.lateConflict,
      n.newer && STORAGE_NOTICES.newer, n.cleared && STORAGE_NOTICES.cleared].filter(Boolean)
      .map((line) => '\n' + line).join('');
  }

  function settlementText(view) {
    return phaseText(view) + noticeText(view);
  }

  function phaseText(view) {
    const a = view.attempt;
    const s = view.settlement;
    switch (view.phase) {
      case 'resuming': return '保存された送信記録を読取りRPCで確認しています。確認が終わるまで結果は表示しません。';
      case 'walletPending': return 'ウォレットでの承認を待っています。送信記録は保存済みです。新しい送信はできません。';
      case 'txPending': {
        const reason = s && s.reason === 'reorg' ? '\n受領ブロックが再編成されました。確定待ちに戻しています。'
          : s && s.reason === 'confirming' ? `\n確認ブロック ${s.confirmations}/2。配備内容は確認済みブロックで照合します。` : '';
        const expired = view.pollExpired ? '\n自動確認（最大10分）を終了しました。「状況を更新」で読取り確認できます。' : '';
        return `送信済み・確定待ちです。読取りRPCで確認しています。自動で再送しません。${reason}${expired}`;
      }
      case 'unknown':
        return `送信結果が不明です（${UNKNOWN_REASONS[a.reason] || '確認できません'}）。送信された可能性があるため、自動で再送・消去しません。`
          + (a.hash ? '' : '\n取引ハッシュは保存されていません。ウォレットの取引履歴にこの送信があれば、この「詳細」内で読取り照合できます。ハッシュがない限り、この端末からはこの送信の結果を復元できません。')
          + (s && s.hashless ? `\n予定アドレスの読取り: ${READBACK[s.readback] || s.readback}${s.block ? `（ブロック #${s.block.number}）` : ''}。これはこの送信の結果の確認ではなく、未配備でも未送信とは限りません。` : '');
      case 'success': return '配備を確認しました。2回の確認ブロック・受領ブロックの再照合・固定実装/EOA管理者なし/この公開鍵1つの読取りが一致しました。Safeへの登録やアプリの状態更新は行っていません。';
      case 'failed':
        if (a.reason === 'cancelled') return '同じnonceが別の確定取引で使われ、この配備は行われませんでした。';
        return a.version === 1 ? '取引は失敗しました（status 0）。支払済みのガス代は戻りません。'
          : '取引は失敗しました（status 0）。配備は行われていません。';
      case 'rejected': return 'ウォレットで送信が拒否されました（送信は報告されていません）。再度配備するには、記録を消去してから照合・確認をやり直してください。';
      case 'walletOverride':
        return `ウォレットが同意上限を超えて送信しました\n配備の読取り結果: ${READBACK[(s && s.readback) || 'unknown']}\nこの記録は消去・再送できません。`;
      default: return '';
    }
  }

  function attemptRows(view) {
    const a = view.attempt;
    const s = view.settlement;
    const entries = [['予定アドレス', a.address, true], ['送信元', a.from, true],
      ['ネットワーク', chainLine(chainOfView(view, a))], ['取引ハッシュ', a.hash || '未取得（不明）', true]];
    if (a.replacementHash) {
      const consuming = ['cancelled', 'cancel-unverified'].includes(a.reason);
      entries.push([consuming ? '消費した取引のハッシュ' : '置換後のハッシュ', a.replacementHash, true]);
    }
    if (view.notices.unsaved) entries.push(['保存状態', '未保存（このページにだけ表示しています）']);
    if (view.notices.lateHash) entries.push(['ウォレットが返した別のハッシュ（追跡しません）', view.notices.lateHash, true]);
    if (s) {
      if (s.readback && view.phase !== 'txPending' && !s.hashless) entries.push(['配備の読取り', READBACK[s.readback] || s.readback]);
      if (s.receipt) entries.push(['受領ブロック', `#${s.receipt.blockNumber} · 確認 ${s.confirmations}`]);
    }
    return entries;
  }

  /** Historical v1 recovery only: the original frozen request, its observed values and paid fee, read-only.
   *  Rendered inside the folded technical details; new (v2) records produce no rows here. */
  function attemptTechnicalRows(view) {
    const a = view.attempt;
    const s = view.settlement;
    if (a.version !== 1) return [];
    const t = a.transaction;
    const entries = [['要求 nonce / gas', `${BigInt(t.nonce)} / ${BigInt(t.gas)}`],
      ['要求 最大/優先手数料', `${gwei(t.maxFeePerGas)} / ${gwei(t.maxPriorityFeePerGas)}`],
      ['支払上限', `${formatPol(BigInt(a.capWei))} ${chainOfView(view, a).native}`]];
    const o = a.observed;
    if (o) {
      const differs = o.nonce !== t.nonce || o.gas !== t.gas || o.maxFeePerGas !== t.maxFeePerGas
        || o.maxPriorityFeePerGas !== t.maxPriorityFeePerGas;
      entries.push(['実際 nonce / gas', `${BigInt(o.nonce)} / ${BigInt(o.gas)}${differs ? '（要求と異なる）' : ''}`],
        ['実際 最大/優先手数料', `${gwei(o.maxFeePerGas)} / ${gwei(o.maxPriorityFeePerGas)}`]);
    }
    if (a.effectiveNonce) entries.push(['使用されたnonce', String(BigInt(a.effectiveNonce))]);
    if (s) {
      entries.push(['支払ったガス代', s.paidFee === null || s.paidFee === undefined ? '不明（受領前）'
        : `${formatPol(BigInt(s.paidFee))} ${chainOfView(view, a).native}`]);
    }
    return entries;
  }

  function focusTarget(view) {
    const target = view.focus.target;
    const visible = (id) => $(id).getClientRects().length && $(id);
    if (target === 'error') {
      return ['input-error', 'plan-blocked', 'wallet-error', 'inspect-error', 'send-error', 'storage-error',
        'resume-error'].map(visible).find(Boolean);
    }
    if (target === 'plan') return visible('plan') ? $('plan-heading') : $('manual');
    if (target === 'review') return visible('plan-state') || visible('send');
    if (target === 'settlement') return visible('attempt') ? $('attempt-status') : null;
    // The single action is the retry and the next step; without it, the wallet choice is the next step.
    if (target === 'connect') return $('send').disabled ? doc.querySelector('#wallet-choices input:not(:disabled)')
      : $('send');
    if (target === 'wallet') return $('send');
    if (target === 'clear') return $('clear');
    if (target === 'clear-confirm') return $('cancel-clear');
    return null;
  }

  function render(view) {
    const plan = view.plan;
    // 01 / PUBLIC PLAN
    alert('input-error', view.inputError);
    show('plan-empty', !plan);
    show('plan', Boolean(plan));
    const ownAttempt = Boolean(plan && view.attempt && view.attempt.address.toLowerCase() === plan.address.toLowerCase());
    const deployedTarget = view.publicInspection === 'deployed' || view.inspection.status === 'deployed';
    const checkingUnknown = ownAttempt && view.phase === 'unknown' && view.publicInspection === 'loading'
      && !view.notices.unsaved;
    const targetState = deployedTarget && view.phase !== 'success' ? 'すでに配備されています。'
      : plan && view.attempt && !ownAttempt ? view.notices.reloadRequired
        ? '以前の送信記録が変更されました。ページを再読み込みしてください。'
        : '別のSignerのウォレット応答または保存処理を待っています。選択したSignerへは処理後に切り替わります。'
        : view.scopeWaiting && !view.attempt ? '以前のウォレット応答または保存処理を待っています。処理が終わるまで配備できません。'
        : checkingUnknown ? '配備状態を確認中…' : ownAttempt ? '' : view.publicInspection === 'loading' ? '配備状態を確認中…'
        : view.publicInspection === 'unknown' || view.publicInspection === 'mismatch' ? '配備状態を確認できません。' : '';
    show('plan-state', Boolean(plan && targetState));
    text('plan-state', targetState);
    show('section-wallet', Boolean(plan && !ownAttempt && !view.attempt && !deployedTarget));
    show('retry-inspection', Boolean(plan && !ownAttempt && ['unknown', 'mismatch'].includes(view.publicInspection)));
    show('payload-details', true);
    show('attempt-context', false);
    show('manual-controls', !deployedTarget);
    show('plan-technical', Boolean(plan));
    show('section-settlement', ownAttempt && !checkingUnknown
      && (!deployedTarget || view.phase === 'success' || view.notices.unsaved));
    alert('plan-blocked', view.storageError || view.resumeError);
    show('copy-address', Boolean(plan && (deployedTarget || (ownAttempt && view.phase === 'success'))));
    if (plan) {
      text('plan-address', plan.address);
      if ($('plan-chain')) text('plan-chain', chainOfView(view).label);
      text('plan-key', plan.handoff.publicKey);
      text('plan-keyid', plan.handoff.keyID);
      text('plan-salt', plan.handoff.salt);
      text('payload', JSON.stringify({ ...plan.handoff, factory: plan.transaction.to, value: plan.transaction.value,
        calldata: plan.transaction.data }, null, 2));
    }
    // Public key / keyID / salt / JSON live in the folded 技術情報 block; the plan keeps address and network.
    show('plan-technical', Boolean(plan));
    // 02 / WALLET CONFIRM
    const w = view.wallet;
    renderChoices(view);
    show('wallet-inactive', false);
    $('wallet-fieldset').disabled = !plan || w.status === 'connecting';
    show('no-wallet', false);
    // Offer a choice only when multiple usable providers exist; WalletConnect is the default otherwise.
    const usable = w.choices.filter((c) => !c.disabled);
    show('wallet-fieldset', Boolean(plan && w.status === 'disconnected' && (usable.length !== 1 || !w.selectedId)));
    const connecting = w.status === 'connecting';
    // The individual recovery controls (technical details) never interleave with the single action in flight.
    const operating = Boolean(view.operation);
    $('connect').disabled = !plan || !w.selectedId || connecting || w.status === 'connected' || w.status === 'wrongChain'
      || operating;
    text('connect', connecting ? '接続中…' : '接続');
    $('connect').setAttribute('aria-busy', String(connecting));
    show('disconnect', w.status === 'connected' || w.status === 'wrongChain');
    const pairing = connecting && w.pairing;
    show('pairing', Boolean(pairing));
    if (pairing) {
      if ($('pairing-uri').value !== w.pairing.uri) $('pairing-uri').value = w.pairing.uri;
      if (lastQR !== w.pairing.uri) {
        lastQR = w.pairing.uri;
        void drawQR(w.pairing.uri);
      }
    } else if (lastQR !== null) {
      lastQR = null;
      $('pairing-uri').value = '';
      void drawQR(null);
    }
    const status = walletStatus(view);
    show('wallet-status', Boolean(status && !ownAttempt));
    text('wallet-status', w.status === 'connected' ? `ウォレット  ${w.account}` : status);
    $('wallet-status').setAttribute('aria-busy', String(connecting));
    alert('wallet-error', w.error);
    show('switch', w.status === 'wrongChain');
    $('switch').textContent = `${chainOfView(view).name}に切り替える`;
    $('switch').disabled = operating;
    const loading = view.inspection.status === 'loading';
    $('inspect').disabled = !view.canInspect || operating;
    text('inspect', loading ? '照合中…' : 'チェーン上で照合');
    $('inspect').setAttribute('aria-busy', String(loading));
    show('inspect-status', loading);
    text('inspect-status', loading ? '公式コード・Factoryの予定アドレス・配備状態を同じブロックで読取り照合しています…' : '');
    $('inspect-status').setAttribute('aria-busy', String(loading));
    alert('inspect-error', view.inspection.error);
    const deployed = view.inspection.status === 'deployed';
    show('deployed', false);
    if (deployed) {
      text('deployed-text', '配備済み');
    }
    const review = view.review;
    show('review', false);
    if (review) {
      // Operation identity only; the wallet shows and approves the final nonce, gas and fees.
      // Public key / keyID / salt stay readable in 技術情報 (same plan values); the address binds them.
      rows('review-list', [
        ['チェーン', chainLine(chainOfView(view))], ['送信元', review.from, true],
        ['宛先', plan ? plan.transaction.to : '', true], ['送金額', `0 ${chainOfView(view).native}`],
        ['予定アドレス', plan ? plan.address : '', true], ['照合ブロック', `#${review.block.number}`],
      ]);
    }
    // The single explicit action: enabled exactly when the controller reports a stage (never while an operation or
    // send is in flight); its busy text names the stage in progress. The stage is recomputed from the controller
    // on every render, so a cleared review never leaves a send stage behind.
    const busy = connecting || view.operation === 'connect' ? '接続中…'
      : view.operation === 'switch' ? `${chainOfView(view).name}へ切替中…`
        : loading || view.operation === 'inspect' ? '照合中…'
          : view.submitting || view.operation === 'send' ? 'ウォレットで承認待ち…' : null;
    show('send', Boolean(plan && !deployedTarget && !ownAttempt && (!view.locked || busy) && !view.storageError
      && !['loading', 'unknown', 'mismatch'].includes(view.publicInspection)));
    if (plan && !ownAttempt && !deployed && !view.stage && !view.locked && !view.storageError && usable.length === 0) {
      alert('wallet-error', { message: '利用できるウォレットがありません。ウォレット拡張機能またはWalletConnectの設定を確認してください。' });
    }
    $('send').disabled = !view.stage;
    $('send').dataset.stage = view.stage || '';
    text('send', busy || (w.status === 'disconnected' ? 'ウォレットを接続' : '配備する'));
    $('send').setAttribute('aria-busy', String(Boolean(busy)));
    show('gas-note', Boolean(plan && !ownAttempt && !deployed && w.status === 'connected'));
    const nextStep = view.initializing ? '送信記録を確認中…' : '';
    show('next-step', Boolean(nextStep));
    text('next-step', nextStep);
    $('next-step').setAttribute('aria-busy', String(Boolean(busy) || view.initializing));
    const foreignUnsaved = view.attempt && !ownAttempt && view.notices.unsaved;
    const sendNotice = [view.sendNotice, foreignUnsaved
      && `別のSigner（${view.attempt.address}）の送信記録です。\n${STORAGE_NOTICES.unsaved}`].filter(Boolean).join('\n');
    alert('send-error', sendNotice || null);
    show('attempt-context', Boolean(view.attempt && (ownAttempt || !deployedTarget)));
    show('attempt-technical', false);
    show('attempt-recovery', false);
    show('hash-form', false);
    if (view.attempt && !ownAttempt && !deployedTarget) {
      text('attempt-context-text', settlementText(view));
      rows('attempt-detail-list', attemptRows(view));
      show('clear', false);
      show('clear-confirm', false);
    }
    // 03 / SETTLEMENT
    alert('resume-error', view.resumeError);
    alert('storage-error', view.storageError);
    const attempt = view.attempt;
    show('no-attempt', false);
    // Storage initialization uses the existing settlement placeholder as its busy status.
    text('no-attempt', view.initializing ? STORAGE_NOTICES.initializing : '承認した送信の状況がここに表示されます。');
    $('no-attempt').setAttribute('aria-busy', String(view.initializing));
    show('attempt', Boolean(attempt && ownAttempt));
    if (!attempt) {
      show('attempt-technical', false);
      show('attempt-recovery', false);
      show('refresh', false);
      show('clear', false);
      show('clear-confirm', false);
    }
    if (attempt) {
      const warn = ['unknown', 'walletOverride', 'failed', 'rejected'].includes(view.phase);
      const notice = view.notices.unsaved || view.notices.lateHash || view.notices.cleared;
      $('attempt-status').className = 'status' + (view.phase === 'walletOverride' || (notice && !warn) ? ' warning'
        : warn ? ' error' : '');
      const statusText = { success: '配備が完了しました。', txPending: '配備中…',
        walletPending: 'ウォレットで承認してください。', unknown: '配備結果を確認できません。再送せず、状況を確認してください。',
        rejected: 'キャンセルしました。送信していません。', failed: '配備されませんでした。',
        resuming: '配備結果を確認中…' };
      text('attempt-status', (statusText[view.phase] || phaseText(view)) + noticeText(view));
      $('attempt-status').setAttribute('aria-busy', String(['walletPending', 'resuming'].includes(view.phase) || view.refreshing));
      rows('attempt-list', attemptRows(view));
      rows('attempt-detail-list', attemptRows(view));
      show('attempt-context', true);
      text('attempt-context-text', settlementText(view));
      const technical = attemptTechnicalRows(view);
      rows('attempt-technical-list', technical);
      show('attempt-technical', technical.length > 0 && (ownAttempt || !deployedTarget));
      // Manual hash reconciliation is recovery only, inside the closed technical details, never a normal step.
      show('attempt-recovery', view.phase === 'unknown' && !attempt.hash);
      show('hash-form', view.phase === 'unknown' && !attempt.hash);
      alert('hash-error', view.manualHashError ? { message: view.manualHashError } : null);
      // 状況を更新 also retries an unsaved wallet outcome, and reads only the expected address for a hashless unknown
      // attempt (read-only; it never sends).
      const inlineRefresh = ownAttempt && !checkingUnknown && (!deployedTarget || view.notices.unsaved);
      if (foreignUnsaved) $('send-error').after($('refresh'));
      else if (inlineRefresh) $('attempt').insertBefore($('refresh'), $('clear'));
      else $('attempt-context').append($('refresh'));
      show('refresh', view.notices.unsaved || view.phase === 'unknown' || view.pollExpired);
      $('refresh').disabled = view.refreshing;
      text('refresh', view.refreshing ? '確認中…' : '状況を更新');
      $('refresh').setAttribute('aria-busy', String(Boolean(view.refreshing)));
      const retryable = ownAttempt && ['rejected', 'failed'].includes(view.phase) && view.clearable;
      show('clear', retryable && !view.clearPending);
      text('clear', 'もう一度配備する');
      show('clear-confirm', retryable && view.clearPending);
    }
    doc.querySelector('main').setAttribute('aria-busy', String(view.initializing));
    // Settled phase for assistive-technology-neutral automation; public state only.
    doc.body.dataset.phase = view.phase;
    if (view.focus.seq !== lastFocus) {
      lastFocus = view.focus.seq;
      const element = focusTarget(view);
      if (element) element.focus();
    }
  }

  // Native control events -> controller commands only.
  $('import-form').addEventListener('submit', (event) => {
    event.preventDefault();
    controller.prepare($('manual').value);
    if (controller.inputError && controller.inputError.code === 'oversize') $('manual').value = '';
  });
  $('manual').addEventListener('input', () => controller.inputEdited());
  $('wallet-choices').addEventListener('change', (event) => {
    if (event.target && event.target.name === 'wallet') controller.selectWallet(event.target.value);
  });
  $('connect').addEventListener('click', () => controller.connect());
  $('disconnect').addEventListener('click', () => controller.disconnect());
  $('cancel-pairing').addEventListener('click', () => controller.cancelPairing());
  $('copy-uri').addEventListener('click', () => {
    const uri = $('pairing-uri').value;
    if (uri.startsWith('wc:')) clipboard(uri);
  });
  $('switch').addEventListener('click', () => controller.switchPolygon());
  $('inspect').addEventListener('click', () => controller.inspect());
  // The single explicit action: the controller continues from the settled state to the one send; it alone opens the
  // wallet's transaction approval.
  $('send').addEventListener('click', () => {
    if ($('send').dataset.stage === 'connect') controller.connect();
    else controller.deploy();
  });
  $('copy-address').addEventListener('click', () => {
    if (controller.plan) clipboard(controller.plan.address);
  });
  $('refresh').addEventListener('click', () => controller.refresh());
  $('hash-form').addEventListener('submit', (event) => {
    event.preventDefault();
    controller.enterHash($('manual-hash').value);
  });
  $('clear').addEventListener('click', () => controller.requestClear());
  $('cancel-clear').addEventListener('click', () => controller.cancelClear());
  $('confirm-clear').addEventListener('click', () => controller.confirmClear());
  doc.addEventListener('keydown', (event) => {
    // Escape closes inline pairing (not a modal); it never unlocks an entered send.
    if (event.key === 'Escape' && !$('pairing').hidden && !controller.attempt) controller.cancelPairing();
  });
  return render;
}
