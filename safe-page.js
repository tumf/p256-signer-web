// Safe approval page: explicit connect / inspect request / request approval / disconnect over one
// local operation generation. SDK, config, QR, clock and UUID are injected by safe-request.js.
// SafeSession retains only unsigned request evidence in its dedicated store before signing.
// No automatic pairing URI/signature/permission persistence or logs; explicit QR file export is user-controlled.
import { formatPol, parseFragment, parseHandoff } from './model.js';
import { SafeSession } from './safe-session.js';
import { mountPairingQR } from './pairing-qr.js';
import { mountRecoveryPanel } from './recovery-panel.js';
import { ORIGIN, expectedChain, expectedFrom, transaction, verifyResult } from './safe-request-model.js';
import { handoffChain } from './model.js';
import { POLYGON, chainText } from './chains.js';

export const MESSAGES = {
  idle: '公開データを確認してください。',
  ready: '送金内容を入力し、「iPhoneに接続」を押してください。',
  connecting: 'iPhoneで接続を許可してください。',
  connected: '接続しました。「要求内容を確認」でiPhoneの接続情報を照合します（署名は要求しません）。',
  inspecting: 'iPhoneの接続情報を照合しています。',
  inspected: '照合しました。表示した取引を確認してから承認を要求してください。',
  signing: 'iPhoneで内容を確認・承認し、Webへ返してください（要求の有効期間は発行から120秒）。',
  done: '署名を受信し、ブラウザで独立に検証しました。取引は送信・実行していません。',
  config: '接続を開始できません（このページの配信元・WalletConnect設定・ブラウザ暗号機能のいずれかが未準備です）。',
  connect: 'iPhoneと接続できませんでした（拒否・期限切れ・許可範囲の不一致を含む）。自動では再接続しません。',
  inspect: 'iPhoneの接続情報が、選んだSigner・入力したSafeと一致しないか取得できませんでした。署名は要求していません。接続を閉じました。',
  refused: 'iPhoneが拒否を返しました。署名結果は受け取っていません。自動では再送しません。新しい接続が必要です。',
  unknown: '署名結果を受け取れないか、検証できませんでした。受け取れなかったことは、iPhoneで署名されなかったことを証明しません。自動では再送しません。iPhoneの記録を確認し、新しい接続で操作してください。',
  lost: 'iPhoneとの接続が終了しました（更新・削除・期限切れ）。接続権限は復元しません。新しい接続が必要です。',
};
const BUSY = new Set(['connecting', 'inspecting', 'signing']);

export function mountSafePage(doc, { origin, location, history, loadConfig, loadSignClient, loadQR, clock, uuid }) {
  const $ = (id) => doc.getElementById(id);
  const inputs = ['safe', 'recipient', 'value', 'nonce'];
  const drawQR = mountPairingQR(doc, $('pairing-qr'), loadQR);
  let handoff = null, active = null, phase = 'idle', generation = 0, client = null, packet = null;

  function render() {
    const idle = phase === 'idle';
    $('handoff-fields').disabled = !idle;
    $('transfer-fields').disabled = !idle;
    $('connect').disabled = !idle || !handoff;
    $('inspect').disabled = phase !== 'connected';
    $('sign').disabled = phase !== 'inspected';
    $('disconnect').disabled = idle;
    $('packet-export').disabled = phase !== 'done' || !packet;
    doc.querySelector('main').setAttribute('aria-busy', String(BUSY.has(phase)));
    $('status').textContent = MESSAGES[idle ? (handoff ? 'ready' : 'idle') : phase];
  }
  function error(id, text) {
    const node = $(id);
    node.textContent = text || '';
    node.hidden = !text;
    if (text) node.focus();
  }
  function rows(id, entries) {
    const list = $(id);
    list.replaceChildren();
    for (const [term, value] of entries) {
      const dt = doc.createElement('dt'), dd = doc.createElement('dd');
      dt.textContent = term; dd.textContent = value; dd.className = 'mono';
      list.append(dt, dd);
    }
  }
  function clearPairing() {
    $('pairing').hidden = true;
    $('pairing-open').removeAttribute('href');
    void drawQR(null);
  }
  function clearOperation() {
    clearPairing();
    $('preview').hidden = true; $('preview-list').replaceChildren();
  }
  function clearResult() { packet = null; $('result').hidden = true; $('result-list').replaceChildren(); }

  // Explicit end of the local operation (user disconnect/cancel, page hide or failure). Old completions
  // see a newer generation and do nothing.
  async function end() {
    ++generation;
    const session = active;
    active = null; phase = 'idle'; packet = null;
    clearOperation(); clearResult(); render();
    if (session) await session.dispose().catch(() => {});
  }
  // The session closed itself: SDK update/event/delete/expiry, or a failed inspect/sign.
  function lost(session, cause) {
    if (active !== session) return;
    const was = phase;
    ++generation; active = null; phase = 'idle'; packet = null;
    clearOperation(); clearResult(); render();
    void session.dispose().catch(() => {});
    error('request-error', was === 'inspecting' ? MESSAGES.inspect
      : was === 'signing' ? (cause?.code === 5003 ? MESSAGES.refused : MESSAGES.unknown)
        : was === 'connecting' ? MESSAGES.connect : MESSAGES.lost);
  }

  /** The static Polygon header, introduction and value help name the handoff's chain (Polygon keeps the exact bytes). */
  function showChain(chain) {
    doc.querySelector('header span').textContent = chainText('Safe承認要求 · Polygon', chain);
    doc.querySelector('h1 + p').textContent = chainText('Polygon上のSafe v1.5.0から、ネイティブPOLを送る1件の取引だけを'
      + 'iPhoneに要求します。秘密鍵はiPhoneから出ません。', chain).replace('ネイティブPOL', `ネイティブ${chain.native}`);
    $('value-help').textContent = `1 ${chain.native} = 1000000000000000000 wei。表示時に${chain.native}へ換算します。`;
  }

  function showHandoff(text, fromFragment) {
    error('handoff-error', '');
    try {
      handoff = fromFragment ? parseFragment(text) : parseHandoff(text);
    } catch (e) {
      handoff = null; $('signer').hidden = true; showChain(POLYGON); render();
      error('handoff-error', e.message);
      return;
    }
    $('signer-address').textContent = handoff.expectedAddress;
    $('signer-key').textContent = handoff.publicKey;
    $('signer-keyid').textContent = handoff.keyID;
    $('signer-salt').textContent = handoff.salt;
    showChain(handoffChain(handoff));
    $('signer').hidden = false;
    render();
    $('signer-heading').focus();
  }

  async function signClient() {
    if (client) return client;
    const config = await loadConfig();
    if (origin !== ORIGIN || !globalThis.crypto?.subtle || config?.allowedDeploymentOrigin !== ORIGIN
        || !/^[0-9a-f]{32}$/.test(config?.walletConnectProjectId || '')) throw Object.assign(new Error('config'), { config: true });
    const SignClient = await loadSignClient();
    // SDK IKeyValueStorage held in memory only: a reload restores no pairing, session or result.
    const memory = new Map();
    const storage = { getKeys: async () => [...memory.keys()], getEntries: async () => [...memory.entries()],
      getItem: async (key) => memory.get(key), setItem: async (key, value) => { memory.set(key, value); },
      removeItem: async (key) => { memory.delete(key); } };
    client = await SignClient.init({ projectId: config.walletConnectProjectId, relayUrl: 'wss://relay.walletconnect.com',
      logger: 'silent', telemetryEnabled: false, storage, customStoragePrefix: 'p256-safe-request',
      metadata: { name: 'P256 Signer', description: 'P256 Signer Safe request', url: ORIGIN, icons: [] } });
    return client;
  }

  async function connect() {
    if (phase !== 'idle' || !handoff) return;
    error('transfer-error', ''); error('request-error', '');
    let expected;
    try {
      expected = expectedFrom(handoff, Object.fromEntries(inputs.map((id) => [id, $(id).value])));
    } catch (e) {
      error('transfer-error', e.message);
      $(e.field === 'same' ? 'safe' : e.field)?.focus();
      return;
    }
    const ticket = ++generation;
    phase = 'connecting'; clearResult(); render();
    try {
      const sdk = await signClient();
      if (ticket !== generation) return;
      const session = new SafeSession(sdk, expected, clock, (cause) => lost(session, cause));
      active = session;
      await session.connect(async (uri) => {
        if (ticket !== generation) return;
        $('pairing-open').href = uri;
        $('pairing').hidden = false;
        await drawQR(uri);
      });
      if (ticket !== generation) return;
      clearPairing(); phase = 'connected'; render();
    } catch (e) {
      if (ticket !== generation) return;
      await end();
      error('request-error', e?.config ? MESSAGES.config : MESSAGES.connect);
    }
  }

  async function inspect() {
    if (phase !== 'connected' || !active) return;
    const ticket = generation, session = active;
    error('request-error', '');
    phase = 'inspecting'; render();
    try {
      const context = await session.inspect();
      if (ticket !== generation || active !== session) return;
      const { body, safeTxHash } = transaction(session.expected), tx = body.tx;
      const chain = expectedChain(session.expected);
      rows('preview-list', [
        ['ネットワーク', chain.network], ['Origin', context.origin], ['Safe', session.expected.safe],
        ['Signer', session.expected.signer], ['keyID', context.keyId], ['Binding', context.binding],
        ['送金先 (to)', session.expected.recipient],
        ['金額 (value)', `${tx.value} wei（${formatPol(BigInt(tx.value))} ${chain.native}）`],
        ['data', `${tx.data}（ネイティブ送金のみ）`],
        ['operation', `${tx.operation}（CALL）`], ['safeTxGas', tx.safeTxGas], ['baseGas', tx.baseGas],
        ['gasPrice', tx.gasPrice], ['gasToken', tx.gasToken], ['refundReceiver', tx.refundReceiver], ['nonce', tx.nonce],
        ['SafeTxHash', safeTxHash], ['方式', `${context.purpose} · ${context.codecId}`],
      ]);
      $('preview').hidden = false;
      phase = 'inspected'; render();
      $('preview-heading').focus();
    } catch {
      if (ticket !== generation) return;
      await end();
      error('request-error', MESSAGES.inspect);
    }
  }

  async function sign() {
    if (phase !== 'inspected' || !active) return;
    const ticket = generation, session = active;
    error('request-error', '');
    phase = 'signing'; render();
    try {
      const signed = await session.signPacket(uuid());
      const result = { requestId: signed.request.id, safeTxHash: signed.request.safeTxHash, signerSignature: signed.result.signerSignature };
      if (ticket !== generation || active !== session) return;
      rows('result-list', [['要求ID', result.requestId], ['SafeTxHash', result.safeTxHash],
        ['Hybrid signerSignature（96バイト）', result.signerSignature],
        ['意味', 'ブラウザでのP-256署名検証のみ。Safeでの受理・取引実行は確認していません。']]);
      $('result').hidden = false;
      packet = signed; phase = 'done'; render();
      $('result-heading').focus();
    } catch (e) {
      if (ticket !== generation) return;
      await end();
      error('request-error', e?.code === 5003 ? MESSAGES.refused : MESSAGES.unknown);
    }
  }

  $('packet-export').addEventListener('click', async () => {
    if (phase !== 'done' || !packet) return;
    const ticket = generation, signed = packet;
    try {
      await verifyResult(signed.result, signed.request, signed.context, signed.expected, clock());
      if (ticket !== generation || packet !== signed || phase !== 'done') return;
      const url = URL.createObjectURL(new Blob([JSON.stringify(signed)], { type: 'application/json' }));
      const a = doc.createElement('a'); a.href = url; a.download = 'safe-approval-packet.json'; a.click(); URL.revokeObjectURL(url);
    } catch {
      if (ticket !== generation) return;
      clearResult(); render(); error('request-error', '署名packetの有効期限切れ、または検証失敗。保存できません。');
    }
  });

  $('handoff-form').addEventListener('submit', (event) => { event.preventDefault(); if (phase === 'idle') showHandoff($('handoff').value, false); });
  $('transfer-form').addEventListener('submit', (event) => { event.preventDefault(); void connect(); });
  $('inspect').addEventListener('click', () => { void inspect(); });
  $('sign').addEventListener('click', () => { void sign(); });
  $('disconnect').addEventListener('click', () => { error('request-error', ''); void end(); });
  // Changing the selected Signer invalidates it until it is checked again; inputs are locked while connected.
  $('handoff').addEventListener('input', () => { if (handoff) { handoff = null; $('signer').hidden = true; render(); } });

  // The public `#registration=` fragment (same format as the deployment page) is copied, removed from the
  // address bar without navigation and verified exactly like a paste.
  if (location.hash.startsWith('#registration=')) {
    const hash = location.hash;
    history.replaceState(null, '', location.pathname + location.search);
    showHandoff(hash, true);
  }
  const host = doc.getElementById('saved-recovery');
  let recovery = null;
  if (host) recovery = mountRecoveryPanel(doc, host, { purpose: 'safe-tx-v1.5.0',
    getClient: signClient, clock,
    getExpected: () => {
      if (phase !== 'idle' || !handoff) throw new Error('input');
      return expectedFrom(handoff, Object.fromEntries(inputs.map((id) => [id, $(id).value])));
    },
    adopted: async (record, recovered) => {
      const current = expectedFrom(handoff, Object.fromEntries(inputs.map((id) => [id, $(id).value])));
      if (phase !== 'idle' || JSON.stringify(current) !== JSON.stringify(record.expected)) return false;
      rows('result-list', [['要求ID', record.requestId], ['SafeTxHash', recovered.result.safeTxHash],
        ['Hybrid signerSignature（96バイト）', recovered.signerSignature], ['意味', '保存済み結果を独立検証。未送信・未実行。']]);
      $('result').hidden = false; $('result-heading').focus(); return true;
    } });
  doc.defaultView?.addEventListener('pagehide', () => void recovery?.close());
  render();
  return { end, recovery };
}
