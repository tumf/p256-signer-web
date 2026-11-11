import { SavedResultSession } from './recovery-session.js';
import { SavedResultStore } from './saved-result-store.js';
import { mountPairingQR } from './pairing-qr.js';
// A reload lists comparison evidence only. Every network action is a separate user activation.
export function mountRecoveryPanel(doc, host, { purpose, getExpected, getClient, clock,
  store = new SavedResultStore(), loadQR = () => import('./qr.js').then((m) => m.default), adopted = async () => true }) {
  const make = (tag, text) => { const n = doc.createElement(tag); n.textContent = text; return n; };
  const heading = make('h2', '保存済みの署名結果を回収');
  const note = make('p', '署名結果はこのブラウザに保存していません。元の要求を選び、入力内容を照合してiPhoneから受け取ります。新しい署名は要求しません。');
  const select = make('select', ''); select.setAttribute('aria-label', '保存した元の要求');
  const status = make('p', '記録を読み込んでください。'); status.setAttribute('role', 'status');
  const details = make('pre', ''); details.style && (details.style.whiteSpace = 'pre-wrap');
  const reloadButton = make('button', '保存した要求を読み込む');
  const connectButton = make('button', '回収専用でiPhoneに接続');
  const inspectButton = make('button', '現在の接続情報を確認');
  const recoverButton = make('button', '保存済み結果を要求');
  const closeButton = make('button', '回収接続を閉じる');
  const pairing = make('a', 'iPhoneで接続を開く'); pairing.hidden = true;
  const uriText = make('pre', '');
  const qr = make('canvas', ''); qr.width = 256; qr.height = 256; qr.hidden = true;
  qr.setAttribute('aria-label', '回収専用のiPhone接続QR');
  for (const b of [reloadButton, connectButton, inspectButton, recoverButton, closeButton]) b.type = 'button';
  const pairingArea = make('div', ''); pairingArea.hidden = true;
  pairingArea.append(pairing, qr, uriText);
  host.append(heading, note, reloadButton, select, details, connectButton, pairingArea,
    inspectButton, recoverButton, closeButton, status);
  const drawQR = mountPairingQR(doc, qr, loadQR);
  function clearPairing() {
    pairingArea.hidden = true; pairing.hidden = true; qr.hidden = true;
    pairing.removeAttribute?.('href'); uriText.textContent = ''; void drawQR(null);
  }
  let records = [], active = null, phase = 'idle', generation = 0;
  const draw = () => {
    select.disabled = phase !== 'idle'; reloadButton.disabled = phase !== 'idle';
    connectButton.disabled = phase !== 'idle' || records.length === 0;
    inspectButton.disabled = phase !== 'connected'; recoverButton.disabled = phase !== 'inspected';
    closeButton.disabled = phase === 'idle';
  };
  const selected = () => records[Number(select.value || 0)];
  const show = () => {
    const r = selected();
    details.textContent = r ? `要求ID: ${r.requestId}\n${r.envelope}` : '';
  };
  async function close() {
    ++generation;
    const session = active; active = null; phase = 'idle';
    clearPairing(); draw();
    if (session) await session.dispose().catch(() => {});
  }
  async function reload() {
    await close(); const ticket = generation;
    try {
      const list = await store.list(); if (ticket !== generation) return;
      records = list.filter((r) => r.purpose === purpose);
      select.replaceChildren(...records.map((r, i) => { const o = make('option', r.requestId); o.value = String(i); return o; }));
      select.value = '0'; show();
      status.textContent = records.length ? '元の要求を選び、通常画面の公開データと操作内容を入力してください。' : '保存した要求はありません。';
    } catch { records = []; select.replaceChildren(); details.textContent = '';
      status.textContent = '保存領域を読み込めません。記録を消去・上書きせず停止しました。'; }
    draw();
  }
  async function connect() {
    if (phase !== 'idle' || !selected()) return;
    let independent;
    try { independent = getExpected(selected()); }
    catch { status.textContent = '公開データと操作内容を通常画面に入力し、確認してください。'; return; }
    const ticket = ++generation, record = selected(); phase = 'connecting'; draw();
    status.textContent = 'iPhoneで回収専用の接続を許可してください。新しい署名は作りません。';
    try {
      const client = await getClient(); if (ticket !== generation) return;
      const session = new SavedResultSession(client, record, independent, clock, () => {
        if (active === session) { active = null; ++generation; phase = 'idle'; clearPairing();
          status.textContent = '接続が終了しました。結果は採用していません。'; draw(); }
      });
      active = session;
      await session.connect(async (uri) => {
        if (ticket !== generation) return;
        if (!/^wc:[0-9a-f]{64}@2\?/.test(uri)) throw new Error('pairing');
        // Standard URI is transient; no topic or pairing secret is persisted.
        uriText.textContent = uri; pairing.href = uri; pairing.hidden = false;
        pairingArea.hidden = false; qr.hidden = false;
        await drawQR(uri);
      });
      if (ticket !== generation || active !== session) return;
      clearPairing();
      phase = 'connected'; status.textContent = '接続しました。現在の接続情報を確認してください。';
    } catch { if (ticket === generation) { await close(); status.textContent = '回収接続を開始できません。入力とiPhoneの許可を確認してください。'; } }
    draw();
  }
  async function inspect() {
    if (phase !== 'connected' || !active) return;
    const session = active, ticket = generation; phase = 'inspecting'; draw();
    try { await session.inspect(); if (ticket !== generation || active !== session) return;
      phase = 'inspected'; status.textContent = '照合しました。元の要求ID・内容・期限を確認して回収を要求してください。';
    } catch { await close(); status.textContent = '現在の鍵・操作・許可が一致しません。回収していません。'; }
    draw();
  }
  async function recover() {
    if (phase !== 'inspected' || !active) return;
    const session = active, ticket = generation, record = selected(); phase = 'recovering'; draw();
    status.textContent = 'iPhoneで元の内容を確認し、回収を許可して「返す」を押してください。';
    try {
      const result = await session.recover(); if (ticket !== generation || active !== session) return;
      if (!await adopted(record, result, session)) throw new Error('adoption');
      if (ticket !== generation || active !== session) return;
      phase = 'verified'; clearPairing();
      status.textContent = purpose === 'safe-tx-v1.5.0'
        ? `署名検証済み・未実行。要求ID: ${record.requestId}。取引は送信していません。`
        : '署名検証済み・未実行。通常の実行用ウォレット接続と送信前確認へ進めます。';
    } catch (error) {
      await close(); status.textContent = error?.code === 5004 ? '元の要求の期限が切れました。延長・再署名はしていません。'
        : '回収できません。iPhoneの記録・現在の状態・元の期限を確認してください。新しい署名は要求していません。';
    }
    draw();
  }
  select.addEventListener('change', show);
  reloadButton.addEventListener('click', () => void reload());
  connectButton.addEventListener('click', () => void connect());
  inspectButton.addEventListener('click', () => void inspect());
  recoverButton.addEventListener('click', () => void recover());
  closeButton.addEventListener('click', () => void close());
  draw(); return { reload, connect, inspect, recover, close, status };
}
