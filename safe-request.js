// Safe approval page bootstrap: real pinned SignClient (lazy chunk), fixed public config and local QR.
// Separate from the deployment wallet (no EthereumProvider, no wallet storage, no /rpc).
import { mountSafePage } from './safe-page.js';

const CONFIG_LIMIT = 4096;

async function loadConfig() {
  const response = await fetch('./config.json', { credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
  const text = await response.text();
  if (!response.ok || new TextEncoder().encode(text).length > CONFIG_LIMIT) throw new Error('config');
  return JSON.parse(text);
}

const page = mountSafePage(document, {
  origin: location.origin, location, history, loadConfig,
  loadSignClient: () => import('./safe-signclient.js').then((module) => module.SignClient),
  loadQR: () => import('./qr.js').then((module) => module.default),
  clock: () => Math.floor(Date.now() / 1000),
  uuid: () => crypto.randomUUID(),
});
addEventListener('pagehide', () => { void page.end(); });
