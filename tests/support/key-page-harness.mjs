// Test-only page entry for local Chromium: the production key-change.js renderer, key-controller, real
// KeyAttemptStore on the browser's native IndexedDB and the real shared WalletManager (discovering an injected
// EIP-1193 provider double), over the fixture chain and a software native SignClient double. Controlled from the test
// through window.__kh. NOT a relay, user wallet, iPhone or EVM; screenshots are local Chromium evidence only.
import { mountKeyChangePage } from '../../key-change.js';
import { KeyChangeController } from '../../key-controller.js';
import { KeyAttemptStore } from '../../key-attempt-store.js';
import { WalletManager } from '../../wallet.js';
import { WALLET_FEES, createChain, walletTransaction } from './key-chain.mjs';
import { K1, K2, anchorText, bareKeyText, contextWire, nativeClient, nativeSign, softwareKey } from './key-fixtures.mjs';

const params = window.__keyHarnessParams || {};
const SIGNER = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const EXECUTOR = '0x7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e';
const k1 = softwareKey(K1), k2 = softwareKey(K2), k3 = softwareKey(987654321n);
const clock = { offset: 0 };
const now = () => Math.floor(Date.now() / 1000) + clock.offset;
const chain = createChain({ signer: SIGNER, keys: params.keys === 'two' ? [k1, k2] : [k1], deposit: params.deposit !== undefined ? BigInt(params.deposit) : 10n ** 18n,
  balances: { [EXECUTOR]: params.balance !== undefined ? BigInt(params.balance) : 10n ** 18n }, now });
const binding = '0x' + 'b1'.repeat(32);
const peer = {
  signer: SIGNER, key: k1, binding, mode: 'ok', signs: 0, hold: null,
  async context() {
    const head = chain.head();
    if (peer.mode === 'changed-context') peer.binding = '0x' + 'c2'.repeat(32);
    return contextWire({ signer: SIGNER, key: peer.key, binding: peer.binding, chain: { keys: chain.state.keys,
      nonce: chain.state.nonce, blockNumber: head.number, blockHash: head.hash } });
  },
  async sign(envelope) {
    peer.signs++;
    if (peer.mode === 'hold') await new Promise((resolve) => { peer.hold = resolve; });
    if (peer.mode === 'reject') throw { code: 5003, message: 'rejected' };
    if (peer.mode === 'lost') throw new Error('transport');
    if (peer.mode === 'invalid') return { ...(await nativeSign({ envelope, key: peer.key, binding: peer.binding })), note: 'x' };
    return nativeSign({ envelope, key: peer.key, binding: peer.binding });
  },
  approve: (session) => (peer.pairingHold ? new Promise((resolve) => { peer.releasePairing = () => resolve(session); })
    : Promise.resolve(session)),
};
const native = nativeClient(peer);

// Injected EIP-1193 provider double discovered by the real WalletManager (legacy window.ethereum and EIP-6963). Like
// a standard wallet it records the exact page request (`sends`) and then picks its own outer gas/fees (`fees`).
const listeners = {};
const provider = {
  chainId: params.chainId || '0x89', sendMode: 'ok', sends: [], submit: {}, switchMode: 'ok', fees: WALLET_FEES,
  on(name, fn) { (listeners[name] ||= []).push(fn); },
  removeListener(name, fn) { listeners[name] = (listeners[name] || []).filter((f) => f !== fn); },
  emit(name, value) { for (const fn of listeners[name] || []) fn(value); },
  async request({ method, params: p }) {
    if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [EXECUTOR];
    if (method === 'eth_chainId') return provider.chainId;
    if (method === 'wallet_switchEthereumChain') {
      if (provider.switchMode === 'refuse') throw { code: 4001, message: 'rejected' };
      provider.chainId = '0x89';
      provider.emit('chainChanged', '0x89');
      return null;
    }
    if (method === 'eth_sendTransaction') {
      provider.sends.push(p[0]);
      if (provider.beforeSend) provider.atSend = await provider.beforeSend();
      if (provider.sendMode === 'reject') throw { code: 4001, message: 'rejected' };
      const tx = walletTransaction(p[0], provider.fees);
      if (provider.sendMode === 'hang') return new Promise((resolve) => { provider.release = () => resolve(chain.submit(tx, provider.submit)); });
      return chain.submit(tx, provider.submit);
    }
    throw { code: 4200, message: 'unsupported' };
  },
};
if (!params.noWallets) window.ethereum = provider;
if (params.hostileWallet) {
  addEventListener('eip6963:requestProvider', () => dispatchEvent(new CustomEvent('eip6963:announceProvider', {
    detail: { info: { uuid: 'hostile', name: '<img src=x onerror=window.__pwned=1>Evil"wallet', icon: 'data:image/svg+xml,<svg onload=alert(1)>' },
      provider } })));
}
class FakeEthereumProvider {
  static async init() { return new FakeEthereumProvider(); }
  on(name, fn) { if (name === 'display_uri') setTimeout(() => fn(`wc:${'ef'.repeat(32)}@2?relay-protocol=irn&symKey=${'01'.repeat(32)}`), 10); }
  removeListener() {}
  connect() { return new Promise(() => {}); }
  disconnect() { return Promise.resolve(); }
}
const config = params.noWallets ? null : { walletConnectProjectId: 'ab'.repeat(16), allowedDeploymentOrigin: location.origin };
let controller = null;
const wallet = new WalletManager({ win: window, config, origin: location.origin,
  loadWalletConnect: async () => ({ EthereumProvider: FakeEthereumProvider }),
  onChange: () => controller && controller.walletChanged() });
let factory = window.indexedDB;
if (params.storage === 'unavailable') factory = { open() { throw new Error('denied'); } };
const store = new KeyAttemptStore({ indexedDB: factory });
controller = new KeyChangeController({ rpc: chain.rpc, wallet, store, clock: now, uuid: () => crypto.randomUUID(),
  loadSignClient: async () => native.SignClient, loadConfig: async () => ({ walletConnectProjectId: 'ab'.repeat(16) }) });
mountKeyChangePage(document, { controller, wallet, loadQR: () => import('../../qr.js').then((m) => m.default) });
wallet.start();
window.__kh = { chain, peer, native, provider, wallet, controller, store, clock, keys: { k1, k2, k3 },
  many: (n) => Array.from({ length: n }, (_, i) => softwareKey(BigInt(i + 5000))),
  text: { anchor1: anchorText(SIGNER, k1), anchor2: anchorText(SIGNER, k2), bare1: bareKeyText(k1), bare2: bareKeyText(k2),
    bare3: bareKeyText(k3) }, EXECUTOR, ready: false,
  // Test-only legacy fixture: the current attempt rewritten by production CAS into the closed raw v1 schema with
  // historical outer ceilings, as a record stored before wallet-owned fees would be.
  legacy: ({ gas = '2200000', maxFee = '1000000000', priority = '1000000000' } = {}) => controller.update((r) => ({ ...r,
    version: 1, outerGasLimit: gas, outerMaxFeePerGas: maxFee, outerMaxPriorityFeePerGas: priority })) };
controller.loadAttempt().then(() => { window.__kh.ready = true; });
