// Test-only page entry for local Chromium: the production prefund.js renderer, PrefundController, real
// FundingAttemptStore on the browser's native IndexedDB and the real shared WalletManager (with the prefund metadata
// override) discovering an injected EIP-1193 provider double, over the prefund fixture chain. Controlled from the test
// through window.__ph. NOT a relay, user wallet or EVM; screenshots are local Chromium evidence only. The provider keeps
// the original application request in `sends` and, like a wallet, executes its own copy with its default fees.
import { PREFUND_METADATA, mountPrefundPage } from '../../prefund.js';
import { PrefundController } from '../../prefund-controller.js';
import { FundingAttemptStore } from '../../prefund-attempt-store.js';
import { WalletManager } from '../../wallet.js';
import { createPrefundChain, walletExecution } from './prefund-chain.mjs';
import { K1, K2, anchorText, softwareKey } from './key-fixtures.mjs';

const params = window.__prefundHarnessParams || {};
const SIGNER = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const FUNDER = '0x7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e';
const k1 = softwareKey(K1), k2 = softwareKey(K2);
const clock = { offset: 0 };
const now = () => Math.floor(Date.now() / 1000) + clock.offset;
const chain = createPrefundChain({ signer: SIGNER, keys: [k1], deposit: params.deposit !== undefined ? BigInt(params.deposit) : 0n,
  balances: { [FUNDER]: params.balance !== undefined ? BigInt(params.balance) : 10n ** 18n }, now });

// Pausable relay: a test may hold one method (e.g. the pending nonce) to render an awaited boundary.
const holds = {};
const hold = (name) => new Promise((resolve) => { holds[name] = { release: resolve }; window.__ph.held = name; });
const rpc = async (method, params_) => {
  if (window.__ph.holdMethod === method) { window.__ph.holdMethod = null; await hold(method); }
  return chain.rpc(method, params_);
};

const listeners = {};
const provider = {
  chainId: params.chainId || '0x89', sendMode: 'ok', connectMode: 'ok', switchMode: 'ok', sends: [], requests: [],
  submit: {}, holdChain: false, executed: [], execution: {},
  on(name, fn) { (listeners[name] ||= []).push(fn); },
  removeListener(name, fn) { listeners[name] = (listeners[name] || []).filter((f) => f !== fn); },
  emit(name, value) { for (const fn of listeners[name] || []) fn(value); },
  async request({ method, params: p }) {
    provider.requests.push(method);
    if (method === 'eth_requestAccounts') {
      if (provider.connectMode === 'reject') throw { code: 4001, message: 'rejected' };
      return [FUNDER];
    }
    if (method === 'eth_accounts') return [FUNDER];
    if (method === 'eth_chainId') {
      if (provider.holdChain) { provider.holdChain = false; await hold('eth_chainId'); }
      return provider.chainId;
    }
    if (method === 'wallet_switchEthereumChain') {
      if (provider.switchMode === 'refuse') throw { code: 4001, message: 'rejected' };
      provider.chainId = '0x89';
      provider.emit('chainChanged', '0x89');
      return null;
    }
    if (method === 'eth_sendTransaction') {
      provider.sends.push(structuredClone(p[0]));
      const tx = walletExecution(p[0], provider.execution);
      provider.executed.push(tx);
      if (provider.beforeSend) provider.atSend = await provider.beforeSend();
      if (provider.sendMode === 'reject') throw { code: 4001, message: 'rejected' };
      if (provider.sendMode === 'error') throw { code: -32603, message: 'internal' };
      if (provider.sendMode === 'malformed') return '0x1234';
      if (provider.sendMode === 'hang') return new Promise((resolve) => { provider.release = () => resolve(chain.submitDeposit(tx, provider.submit)); });
      return chain.submitDeposit(tx, provider.submit);
    }
    throw { code: 4200, message: 'unsupported' };
  },
};
if (!params.noWallets) window.ethereum = provider;
class FakeEthereumProvider {
  static async init(options) { window.__ph.wcOptions = options; return new FakeEthereumProvider(); }
  on(name, fn) { if (name === 'display_uri') setTimeout(() => fn(`wc:${'ef'.repeat(32)}@2?relay-protocol=irn&symKey=${'01'.repeat(32)}`), 10); }
  removeListener() {}
  connect() { return new Promise(() => {}); }
  disconnect() { return Promise.resolve(); }
}
const config = params.walletConfig === 'missing' ? null
  : { walletConnectProjectId: 'ab'.repeat(16),
    allowedDeploymentOrigin: params.walletConfig === 'wrong-origin' ? 'https://evil.example' : location.origin };
let controller = null;
const wallet = new WalletManager({ win: window, config, origin: location.origin, metadata: PREFUND_METADATA,
  loadWalletConnect: async () => ({ EthereumProvider: FakeEthereumProvider }),
  onChange: () => controller && controller.walletChanged() });
let factory = window.indexedDB;
if (params.storage === 'unavailable') factory = { open() { throw new Error('denied'); } };
if (params.storage === 'blocked') factory = { open() { const r = {}; setTimeout(() => r.onblocked?.(), 0); return r; } };
const store = new FundingAttemptStore({ indexedDB: factory });
const cas = store.compareAndSet.bind(store);
store.compareAndSet = async (...args) => {
  if (window.__ph.holdCas) { window.__ph.holdCas = false; await hold('cas'); }
  return cas(...args);
};
controller = new PrefundController({ rpc, wallet, store, clock: now, uuid: () => crypto.randomUUID() });
mountPrefundPage(document, { controller, wallet, loadQR: () => import('../../qr.js').then((m) => m.default) });
wallet.start();
window.__ph = { chain, provider, wallet, controller, store, clock, keys: { k1, k2 }, FUNDER, SIGNER, holds,
  release: (name) => { holds[name]?.release(); delete holds[name]; },
  text: { authority: anchorText(SIGNER, k1), authorityK2: anchorText(SIGNER, k2) }, ready: false };
controller.start().then(() => { window.__ph.ready = true; });
