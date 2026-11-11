// Child-process probe of the real pinned @walletconnect/ethereum-provider 2.26.0 through the production
// WalletManager with all network denied. Prints one JSON line and exits explicitly, because the SDK keeps
// internal timers alive. Adapter proof only: it never pairs with a real relay or wallet.
const seen = [];
globalThis.fetch = async (url) => { seen.push(['fetch', String(url)]); throw new TypeError('network denied'); };
globalThis.WebSocket = class {
  constructor(url) {
    seen.push(['ws', String(url)]);
    setTimeout(() => { if (this.onerror) this.onerror(new Error('denied')); if (this.onclose) this.onclose({ code: 1006 }); }, 5);
  }
  send() {}
  close() {}
};
const store = new Map();
globalThis.localStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v),
  removeItem: (k) => store.delete(k), clear: () => store.clear(), key: (i) => [...store.keys()][i],
  get length() { return store.size; } };
const ORIGIN = 'https://tumf.github.io';
const { WalletManager } = await import('../../wallet.js');
const real = await import('../../walletconnect.js');
let captured = null;
let instance = null;
const spy = { EthereumProvider: { init: async (options) => {
  captured = JSON.parse(JSON.stringify(options));
  instance = await real.EthereumProvider.init(options);
  return instance;
} } };
const target = Object.assign(new EventTarget(), { Event });
const manager = new WalletManager({ win: target, origin: ORIGIN,
  config: { walletConnectProjectId: '0123456789abcdef0123456789abcdef', allowedDeploymentOrigin: ORIGIN },
  loadWalletConnect: async () => spy });
manager.select('walletconnect');
const connecting = manager.connect();
for (let i = 0; i < 100 && !instance; i++) await new Promise((r) => setTimeout(r, 20));
await new Promise((r) => setTimeout(r, 300));
const during = manager.status;
manager.cancelPairing();
await connecting;
console.log(JSON.stringify({
  initialized: Boolean(instance), captured, during, after: manager.status, account: manager.account,
  rpc: instance && { chains: instance.rpc.chains, optionalChains: instance.rpc.optionalChains,
    methods: instance.rpc.methods, optionalMethods: instance.rpc.optionalMethods, rpcMap: instance.rpc.rpcMap,
    showQrModal: instance.rpc.showQrModal },
  modal: instance ? instance.modal === undefined ? null : 'present' : null, seen,
}));
process.exit(0);
