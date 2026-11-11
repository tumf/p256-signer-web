import { relayURL } from './site.js';
// Explicit wallet selection and lifecycle: EIP-6963 discovery, legacy EIP-1193 fallback and a lazily
// imported WalletConnect 2.26.0 EthereumProvider. Discovery never requests accounts; nothing here
// monitors the chain or sends on its own. The controller is the only caller of `request`.
import { ORIGIN } from './model.js';
import { CHAINS, POLYGON, chainText } from './chains.js';

/** The application wallet request allowlist; connect/disconnect are protocol API operations. */
export const WALLET_METHODS = Object.freeze(['eth_requestAccounts', 'eth_accounts', 'eth_chainId',
  'wallet_switchEthereumChain', 'eth_sendTransaction']);
export const MAX_PROVIDERS = 20;
export const MAX_NAME = 80;
export const WC_RELAY = 'wss://relay.walletconnect.com';
export const WC_NOT_READY = 'WalletConnect設定未準備';

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** WalletConnect is enabled only for a 32-hex public project ID served at the fixed allowed origin. */
export function walletConnectStatus(config, origin) {
  const projectId = config && typeof config.walletConnectProjectId === 'string'
    && /^[0-9a-f]{32}$/.test(config.walletConnectProjectId) ? config.walletConnectProjectId : null;
  if (!projectId) return { enabled: false, projectId: null, reason: 'missing-id' };
  if (!config || config.allowedDeploymentOrigin !== ORIGIN || origin !== ORIGIN) {
    return { enabled: false, projectId: null, reason: 'wrong-origin' };
  }
  return { enabled: true, projectId, reason: null };
}

/** The deployment page's WalletConnect metadata; callers that pass no override keep exactly these bytes. */
export const DEFAULT_METADATA = Object.freeze({ name: 'P-256 Signer 配備Web', description: '選んだSignerをPolygonへ配備します',
  url: ORIGIN, icons: Object.freeze([]) });
export const MAX_METADATA_NAME = 80;
export const MAX_METADATA_DESCRIPTION = 160;

/**
 * Optional bounded metadata override (the prefund page describes EntryPoint funding truthfully): exactly
 * `{name, description, url, icons}` with nonempty text name <= 80 and description <= 160 characters, url exactly the
 * pinned ORIGIN and icons `[]`. Anything else throws before any pairing. Omitted -> DEFAULT_METADATA.
 */
export function walletConnectMetadata(override) {
  if (override === undefined) return DEFAULT_METADATA;
  const text = (value, max) => typeof value === 'string' && value.trim() !== '' && value.length <= max
    && !/[\u0000-\u001f\u007f]/.test(value);
  if (!override || typeof override !== 'object' || Array.isArray(override)
      || Object.keys(override).sort().join() !== 'description,icons,name,url'
      || !text(override.name, MAX_METADATA_NAME) || !text(override.description, MAX_METADATA_DESCRIPTION)
      || override.url !== ORIGIN || !Array.isArray(override.icons) || override.icons.length !== 0) {
    throw walletError('metadata', 'invalid WalletConnect metadata');
  }
  return Object.freeze({ name: override.name, description: override.description, url: ORIGIN, icons: Object.freeze([]) });
}

/** The exact EthereumProvider.init options: the one target chain only (Polygon by default) with its own same-origin
 * relay route, no QR modal, no telemetry, two methods. */
export function walletConnectOptions(projectId, origin, metadata = DEFAULT_METADATA, chain = POLYGON) {
  if (CHAINS[chain?.decimal] !== chain) throw walletError('chain', 'unsupported chain');
  return {
    projectId,
    chains: [chain.id],
    optionalChains: [],
    methods: ['eth_sendTransaction', 'wallet_switchEthereumChain'],
    optionalMethods: [],
    events: ['accountsChanged', 'chainChanged'],
    optionalEvents: [],
    rpcMap: { [chain.id]: relayURL(chain.route) },
    showQrModal: false,
    telemetryEnabled: false,
    relayUrl: WC_RELAY,
    metadata: { name: metadata.name, description: chainText(metadata.description, chain), url: metadata.url, icons: [] },
  };
}

function walletError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

const CONNECT_MESSAGES = {
  rejected: 'ウォレットで接続が拒否されました。もう一度「接続」を押すと再試行できます。',
  cancelled: 'WalletConnectの接続を中止しました。',
  unavailable: 'ウォレットに接続できません。ウォレットの状態を確認して再接続してください。',
  malformed: 'ウォレットのアカウント応答が不正です。',
  switchRejected: 'ネットワークの切替が拒否されました。ウォレットで手動でPolygonへ切り替えてください。',
  switchUnsupported: 'このウォレットはPolygonへの自動切替に対応していません。ウォレットで手動で切り替えてください。',
};

function firstAccount(accounts) {
  if (!Array.isArray(accounts) || accounts.length === 0) return null;
  return typeof accounts[0] === 'string' && ADDRESS.test(accounts[0]) ? accounts[0] : undefined;
}

function normalChain(value) {
  // WalletConnect 2.26.0 returns a numeric chain ID from eth_chainId; injected wallets use hex.
  if (Number.isSafeInteger(value) && value > 0) return '0x' + value.toString(16);
  return typeof value === 'string' && /^0x[0-9a-fA-F]{1,16}$/.test(value) ? value.toLowerCase() : null;
}

export class WalletManager {
  /**
   * @param {object} options
   * @param {Window} options.win  event target with `ethereum` (legacy) and EIP-6963 events
   * @param {object} options.config  `/config.json`
   * @param {string} options.origin  `location.origin`
   * @param {() => Promise<{EthereumProvider: object}>} options.loadWalletConnect  lazy SDK import
   * @param {(event: object) => void} options.onChange
   * @param {object} [options.metadata]  bounded WalletConnect metadata override (walletConnectMetadata)
   */
  constructor({ win, config, origin, loadWalletConnect, onChange, metadata }) {
    this.metadata = walletConnectMetadata(metadata);
    /** The one closed chain the page operates on; set only from its parsed handoff or anchor. */
    this.target = POLYGON;
    this.win = win;
    this.origin = origin;
    this.loadWalletConnect = loadWalletConnect;
    this.onChange = onChange || (() => {});
    this.wc = walletConnectStatus(config, origin);
    this.announced = [];
    this.selectedId = null;
    this.provider = null;
    this.kind = null;
    this.status = 'disconnected';
    this.account = null;
    this.chainId = null;
    this.error = null;
    this.pairing = null;
    this.generation = 0;
    this.connectToken = 0;
    this.listeners = [];
    this.wcLoaded = false;
    this.abortPairing = null;
    // WalletConnect providers whose pairing was cancelled/abandoned, tracked independently of the current
    // selection: a session that connects on any of them later is disconnected even after a reselect.
    this.abandonedPairings = new WeakSet();
    this.wcOpened = new WeakSet();
    // Bumped whenever provider listeners are detached (select, connect, disconnect event, explicit disconnect).
    this.link = 0;
  }

  start() {
    this.win.addEventListener('eip6963:announceProvider', (event) => this.announce(event && event.detail));
    this.win.dispatchEvent(new this.win.Event('eip6963:requestProvider'));
    this.emit('discovery');
  }

  announce(detail) {
    if (!detail || typeof detail !== 'object' || !detail.info || typeof detail.info !== 'object') return;
    const { uuid, name } = detail.info;
    const provider = detail.provider;
    if (typeof uuid !== 'string' || !uuid || uuid.length > 100 || typeof name !== 'string'
        || !provider || typeof provider.request !== 'function') return;
    if (this.announced.some((item) => item.uuid === uuid || item.provider === provider)) return;
    if (this.announced.length >= MAX_PROVIDERS) return;
    // Name is plain text only; the announced icon (untrusted SVG/HTML) is never rendered.
    this.announced.push({ uuid, name: name.slice(0, MAX_NAME) || 'Wallet', provider });
    this.emit('discovery');
  }

  legacy() {
    const provider = this.win.ethereum;
    if (!provider || typeof provider.request !== 'function') return null;
    return this.announced.some((item) => item.provider === provider) ? null : provider;
  }

  /** Plain-data choices for rendering: EIP-6963 announcements, legacy fallback, WalletConnect. */
  choices() {
    const list = this.announced.map((item) => ({ id: 'eip6963:' + item.uuid, name: item.name, kind: 'eip6963',
      disabled: false, reason: null }));
    if (this.legacy()) list.push({ id: 'legacy', name: 'Injected wallet (legacy)', kind: 'legacy', disabled: false,
      reason: null });
    list.push({ id: 'walletconnect', name: 'WalletConnect', kind: 'walletconnect', disabled: !this.wc.enabled,
      reason: this.wc.enabled ? null : WC_NOT_READY });
    return list;
  }

  select(id) {
    const choice = this.choices().find((item) => item.id === id);
    if (!choice || choice.disabled || this.status === 'connecting') return false;
    if (this.selectedId === id) return true;
    this.detach();
    this.selectedId = id;
    this.provider = null;
    this.kind = choice.kind;
    this.account = null;
    this.chainId = null;
    this.status = 'disconnected';
    this.error = null;
    this.bump('select');
    return true;
  }

  injected(id) {
    if (id === 'legacy') return this.legacy();
    const item = this.announced.find((entry) => 'eip6963:' + entry.uuid === id);
    return item ? item.provider : null;
  }

  snapshot() {
    return {
      choices: this.choices(), selectedId: this.selectedId, kind: this.kind, status: this.status,
      account: this.account, chainId: this.chainId, error: this.error, pairing: this.pairing,
      generation: this.generation, walletConnect: { ...this.wc },
    };
  }

  emit(type) {
    this.onChange({ type, generation: this.generation });
  }

  bump(type) {
    this.generation++;
    this.emit(type);
  }

  /** Explicit connect for the selected choice only. Never sends; reconnect never restores consent. */
  async connect() {
    if (!this.selectedId || this.status === 'connecting') return;
    const token = ++this.connectToken;
    this.detach();
    this.status = 'connecting';
    this.error = null;
    this.account = null;
    this.chainId = null;
    this.bump('connecting');
    try {
      let provider;
      if (this.kind === 'walletconnect') {
        provider = await this.openWalletConnect(token);
      } else {
        provider = this.injected(this.selectedId);
        if (!provider) throw walletError('unavailable', CONNECT_MESSAGES.unavailable);
        await provider.request({ method: 'eth_requestAccounts' });
      }
      if (token !== this.connectToken) return this.discardLate(provider);
      const accounts = await provider.request({ method: 'eth_accounts' });
      const chainId = normalChain(await provider.request({ method: 'eth_chainId' }));
      if (token !== this.connectToken) return this.discardLate(provider);
      const account = firstAccount(accounts);
      if (!account || !chainId) throw walletError('malformed', CONNECT_MESSAGES.malformed);
      this.provider = provider;
      this.pairing = null;
      this.account = account;
      this.chainId = chainId;
      this.status = chainId === this.target.hex ? 'connected' : 'wrongChain';
      this.attach(provider);
      this.bump('connected');
    } catch (error) {
      if (token !== this.connectToken) return;
      const code = error && error.code === 4001 ? 'rejected'
        : error && ['malformed', 'unavailable', 'cancelled'].includes(error.code) ? error.code : 'unavailable';
      this.status = 'disconnected';
      this.pairing = null;
      this.error = { code, message: CONNECT_MESSAGES[code] };
      if (this.kind === 'walletconnect' && this.wcProvider) this.closeWalletConnect();
      this.bump('connect-failed');
    }
  }

  async openWalletConnect(token) {
    if (!this.wc.enabled) throw walletError('unavailable', WC_NOT_READY);
    const { EthereumProvider } = await this.loadWalletConnect();
    this.wcLoaded = true;
    if (token !== this.connectToken) throw walletError('cancelled', CONNECT_MESSAGES.cancelled);
    const provider = await EthereumProvider.init(walletConnectOptions(this.wc.projectId, this.origin, this.metadata,
      this.target));
    this.wcProvider = provider;
    this.wcOpened.add(provider);
    const onUri = (uri) => {
      if (token !== this.connectToken || typeof uri !== 'string' || !uri.startsWith('wc:') || uri.length > 2048) return;
      this.pairing = { uri };
      this.emit('pairing');
    };
    provider.on('display_uri', onUri);
    this.pairingCleanup = () => provider.removeListener('display_uri', onUri);
    if (!provider.session) {
      // Cancel settles this wait at once; the SDK's own pending connect is then discarded if it ever resolves.
      const cancelled = new Promise((_, reject) => {
        this.abortPairing = () => reject(walletError('cancelled', CONNECT_MESSAGES.cancelled));
      });
      const connecting = provider.connect();
      connecting.then(() => {
        if (token !== this.connectToken || this.abandonedPairings.has(provider)) this.discardLate(provider);
      }, () => { this.abandonedPairings.delete(provider); });
      try {
        await Promise.race([connecting, cancelled]);
      } finally {
        this.abortPairing = null;
      }
    }
    return provider;
  }

  closeWalletConnect() {
    const provider = this.wcProvider;
    this.releaseWalletConnect();
    if (!provider) return;
    // WalletConnect 2.26.0 disconnect() is a no-op while pairing is still pending, so remember the provider:
    // if its session connects later it is disconnected then (see openWalletConnect).
    if (!provider.session) this.abandonedPairings.add(provider);
    Promise.resolve().then(() => provider.disconnect()).catch(() => {});
  }

  discardLate(provider) {
    // A late connection after cancel/reselect is disconnected and cannot prepare a send, whatever is
    // selected now. Only WalletConnect providers this manager opened are ever disconnected here.
    if (!provider) return;
    if (provider === this.wcProvider) this.releaseWalletConnect();
    if (!this.wcOpened.has(provider) || provider === this.provider) return;
    this.abandonedPairings.delete(provider);
    Promise.resolve().then(() => provider.disconnect()).catch(() => {});
  }

  releaseWalletConnect() {
    this.wcProvider = null;
    if (this.pairingCleanup) this.pairingCleanup();
    this.pairingCleanup = null;
  }

  /** Cancels inline pairing: cleans listeners/session, closes the panel, never unlocks a send. */
  cancelPairing() {
    if (this.status !== 'connecting') return;
    this.connectToken++;
    this.pairing = null;
    this.status = 'disconnected';
    this.error = { code: 'cancelled', message: CONNECT_MESSAGES.cancelled };
    if (this.abortPairing) this.abortPairing();
    this.closeWalletConnect();
    this.bump('pairing-cancelled');
  }

  attach(provider) {
    if (typeof provider.on !== 'function') return;
    const on = (name, handler) => {
      provider.on(name, handler);
      this.listeners.push(() => (provider.removeListener || provider.off || (() => {})).call(provider, name, handler));
    };
    on('accountsChanged', (accounts) => {
      const account = firstAccount(accounts);
      if (!account) {
        this.account = null;
        this.status = 'disconnected';
      } else {
        this.account = account;
      }
      this.bump('accountsChanged');
    });
    on('chainChanged', (chainId) => {
      this.chainId = normalChain(chainId);
      if (this.status !== 'disconnected') this.status = this.chainId === this.target.hex ? 'connected' : 'wrongChain';
      this.bump('chainChanged');
    });
    on('disconnect', () => {
      this.account = null;
      this.chainId = null;
      this.status = 'disconnected';
      this.detach();
      this.bump('disconnect');
    });
  }

  detach() {
    this.link++;
    for (const remove of this.listeners.splice(0)) {
      try { remove(); } catch { /* listener already gone */ }
    }
  }

  /**
   * The page's one closed target chain. Changing it re-judges a live connection (a wallet on another chain is
   * `wrongChain` until the explicit switch); it never switches, connects or sends by itself.
   */
  setTarget(chain) {
    if (CHAINS[chain?.decimal] !== chain) throw walletError('chain', 'unsupported chain');
    if (chain === this.target) return;
    this.target = chain;
    if (this.status === 'connected' || this.status === 'wrongChain') {
      this.status = this.chainId === chain.hex ? 'connected' : 'wrongChain';
    }
    this.bump('target');
  }

  /** The legacy name of the explicit switch to the target chain. */
  async switchPolygon() { return this.switchChain(); }

  /** Explicit switch to the target chain only; 4902/rejection is a manual-switch instruction, never add-chain. */
  async switchChain() {
    if (!this.provider || this.status !== 'wrongChain') return;
    const provider = this.provider;
    const link = this.link;
    // A disconnect, reselect or reconnect while a wallet prompt is pending abandons this switch.
    const live = () => provider === this.provider && link === this.link && this.status !== 'disconnected';
    this.error = null;
    try {
      await this.request('wallet_switchEthereumChain', [{ chainId: this.target.hex }]);
      if (!live()) return;
      const chainId = normalChain(await this.request('eth_chainId', []));
      if (!live()) return;
      this.chainId = chainId;
      this.status = chainId === this.target.hex ? 'connected' : 'wrongChain';
    } catch (error) {
      if (!live()) return;
      const code = error && error.code === 4902 ? 'switchUnsupported' : 'switchRejected';
      // The fixed Polygon words name the target chain; Polygon keeps the exact bytes.
      this.error = { code, message: chainText(CONNECT_MESSAGES[code], this.target) };
    }
    this.bump('switch');
  }

  async disconnect() {
    this.connectToken++;
    const provider = this.provider;
    this.detach();
    this.provider = null;
    this.account = null;
    this.chainId = null;
    this.pairing = null;
    this.status = 'disconnected';
    this.error = null;
    if (this.kind === 'walletconnect') {
      this.wcProvider = provider || this.wcProvider;
      this.closeWalletConnect();
    }
    this.bump('disconnect');
  }

  /** The single gate to the selected provider. Unknown methods never reach the wallet. */
  request(method, params = []) {
    if (!WALLET_METHODS.includes(method)) return Promise.reject(walletError('forbidden', 'method not allowed'));
    if (!this.provider) return Promise.reject(walletError('unavailable', CONNECT_MESSAGES.unavailable));
    const result = this.provider.request({ method, params });
    return method === 'eth_chainId' ? Promise.resolve(result).then(normalChain) : result;
  }
}
