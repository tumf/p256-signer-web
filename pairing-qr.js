// QR bytes stay in the document until the user explicitly downloads the current pairing.
export function mountPairingQR(doc, canvas, loadQR) {
  const button = doc.createElement('button');
  button.type = 'button';
  button.className = 'secondary';
  button.textContent = 'QRをダウンロード';
  button.disabled = true;
  const notice = doc.createElement('p');
  notice.className = 'muted';
  notice.textContent = '保存画像には接続情報が含まれます。共有せず、接続後に削除してください。';
  const status = doc.createElement('p');
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  canvas.after(button, notice, status);
  let generation = 0;

  button.addEventListener('click', () => {
    if (button.disabled) return;
    try {
      const link = doc.createElement('a');
      link.download = 'walletconnect-qr.png';
      link.href = canvas.toDataURL('image/png');
      doc.body.append(link);
      try { link.click(); } finally { link.remove(); }
      status.textContent = '';
    } catch {
      status.textContent = 'QR画像を保存できませんでした。ブラウザのダウンロード設定を確認してください。';
    }
  });

  async function render(uri) {
    const ticket = ++generation;
    button.disabled = true;
    status.textContent = '';
    canvas.getContext('2d')?.clearRect(0, 0, canvas.width, canvas.height);
    if (!uri) return;
    try {
      const QR = await loadQR();
      if (ticket !== generation) return;
      // Encode off-screen: a late renderer cannot overwrite a newer pairing's canvas.
      const pending = doc.createElement('canvas');
      await QR.toCanvas(pending, uri, { width: 256, margin: 2 });
      if (ticket !== generation) return;
      canvas.width = pending.width;
      canvas.height = pending.height;
      canvas.getContext('2d').drawImage(pending, 0, 0);
      button.disabled = false;
    } catch {
      if (ticket === generation) status.textContent = 'QRを生成できませんでした。接続リンクまたはURIを利用してください。';
    }
  }
  doc.defaultView?.addEventListener('pagehide', () => { void render(null); });
  return render;
}
