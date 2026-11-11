'use strict';
// Production wallet.js: EIP-6963/legacy discovery and lifecycle with fake EIP-1193 providers, the real
// pinned @walletconnect/ethereum-provider 2.26.0 initialized with network denied (adapter proof, not real
// relay pairing), a local session seam for pairing/cancel/late-connect, and the fork harness guards.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { FakeChain, FakeWallet } = require('./support/fake-chain.cjs');

const ORIGIN = 'https://tumf.github.io';
const PROJECT = '0123456789abcdef0123456789abcdef';
const load = () => import('../wallet.js');

function win(ethereum) {
  return Object.assign(new EventTarget(), { Event, ethereum });
}

function announce(target, uuid, name, provider) {
  target.dispatchEvent(Object.assign(new Event('eip6963:announceProvider'), {
    detail: { info: { uuid, name, icon: 'data:image/svg+xml,<svg onload=alert(1)>', rdns: 'x' }, provider } }));
}

test('WalletConnect configuration: only a 32-hex public ID at the fixed origin enables it', async () => {
  const { walletConnectStatus, walletConnectOptions } = await load();
  assert.deepEqual(walletConnectStatus(null, ORIGIN), { enabled: false, projectId: null, reason: 'missing-id' });
  assert.equal(walletConnectStatus({ walletConnectProjectId: 'XYZ', allowedDeploymentOrigin: ORIGIN }, ORIGIN).reason,
    'missing-id');
  assert.equal(walletConnectStatus({ walletConnectProjectId: PROJECT, allowedDeploymentOrigin: ORIGIN },
    'http://127.0.0.1:18763').reason, 'wrong-origin');
  assert.equal(walletConnectStatus({ walletConnectProjectId: PROJECT, allowedDeploymentOrigin: 'https://evil.example' },
    'https://evil.example').reason, 'wrong-origin');
  assert.equal(walletConnectStatus({ walletConnectProjectId: PROJECT, allowedDeploymentOrigin: ORIGIN }, ORIGIN).enabled,
    true);
  assert.deepEqual(walletConnectOptions(PROJECT, ORIGIN), {
    projectId: PROJECT, chains: [137], optionalChains: [], methods: ['eth_sendTransaction', 'wallet_switchEthereumChain'],
    optionalMethods: [], events: ['accountsChanged', 'chainChanged'], optionalEvents: [],
    rpcMap: { 137: 'https://p256-signer.mini.tumf.dev/rpc' }, showQrModal: false, telemetryEnabled: false,
    relayUrl: 'wss://relay.walletconnect.com',
    metadata: { name: 'P-256 Signer 配備Web', description: '選んだSignerをPolygonへ配備します', url: ORIGIN, icons: [] },
  });
});

test('discovery: bounded deduplicated plain-text choices, legacy fallback by identity, no account request', async () => {
  const { WalletManager } = await load();
  const chain = new FakeChain();
  const legacy = new FakeWallet(chain);
  const target = win(legacy);
  const manager = new WalletManager({ win: target, config: null, origin: ORIGIN, loadWalletConnect: () => {
    throw new Error('must not load');
  } });
  manager.start();
  assert.deepEqual(manager.choices().map((c) => c.id), ['legacy', 'walletconnect']);
  assert.equal(manager.choices()[1].disabled, true);
  assert.equal(manager.choices()[1].reason, 'WalletConnect設定未準備');
  const a = new FakeWallet(chain);
  announce(target, 'uuid-a', 'A'.repeat(200), a);
  announce(target, 'uuid-a', 'Duplicate', new FakeWallet(chain));
  announce(target, 'uuid-b', 'Same object', a);
  announce(target, 'uuid-legacy', 'Legacy announced', legacy);
  for (let i = 0; i < 40; i++) announce(target, `many-${i}`, `W${i}`, new FakeWallet(chain));
  const choices = manager.choices();
  assert.equal(choices.filter((c) => c.kind === 'eip6963').length, 20, 'bounded to 20');
  assert.equal(choices[0].name.length, 80, 'name bounded to 80');
  assert.equal(choices.some((c) => c.id === 'legacy'), false, 'announced legacy object is not listed twice');
  assert.equal(JSON.stringify(choices).includes('svg'), false, 'icons are never part of the choices');
  assert.equal(manager.selectedId, null, 'no implicit selection');
  assert.deepEqual([a, legacy].flatMap((w) => w.requests), [], 'discovery requests nothing');
  assert.equal(manager.select('walletconnect'), false, 'disabled WalletConnect cannot be selected');
});

test('injected lifecycle: explicit connect/reject/malformed/disconnect/reconnect/switch with the allowlist', async () => {
  const { WalletManager } = await load();
  const chain = new FakeChain();
  const wallet = new FakeWallet(chain);
  const events = [];
  const manager = new WalletManager({ win: win(wallet), config: null, origin: ORIGIN, loadWalletConnect: null,
    onChange: (e) => events.push(e.type) });
  manager.start();
  manager.select('legacy');
  wallet.behavior.connect = 'reject';
  await manager.connect();
  assert.equal(manager.status, 'disconnected');
  assert.equal(manager.error.code, 'rejected');
  wallet.behavior.connect = 'ok';
  wallet.accounts = ['not-an-address'];
  await manager.connect();
  assert.equal(manager.error.code, 'malformed');
  wallet.accounts = ['0x1111111111111111111111111111111111111111'];
  wallet.chainId = '0x1';
  await manager.connect();
  assert.equal(manager.status, 'wrongChain');
  await manager.switchPolygon();
  assert.equal(manager.status, 'connected');
  const generation = manager.generation;
  wallet.emitAccounts([]);
  assert.equal(manager.status, 'disconnected', 'empty accounts means disconnected');
  assert.ok(manager.generation > generation, 'events bump the generation');
  await manager.connect();
  wallet.emit('disconnect');
  assert.equal(manager.status, 'disconnected');
  for (const method of ['personal_sign', 'eth_sign', 'eth_signTypedData_v4', 'wallet_addEthereumChain',
    'eth_sendRawTransaction', 'wallet_requestPermissions']) {
    await assert.rejects(manager.request(method, []), (e) => e.code === 'forbidden', method);
  }
  const methods = new Set(wallet.requests.map((r) => r.method));
  assert.deepEqual([...methods].sort(), ['eth_accounts', 'eth_chainId', 'eth_requestAccounts',
    'wallet_switchEthereumChain']);
  assert.equal(wallet.sends.length, 0, 'no connection or control path sends');
  assert.ok(events.includes('connect-failed') && events.includes('switch'));
});

test('disconnect while wallet_switchEthereumChain is pending leaves the wallet disconnected', async () => {
  const { WalletManager } = await load();
  const wallet = new FakeWallet(new FakeChain(), { chainId: '0x1' });
  const manager = new WalletManager({ win: win(wallet), config: null, origin: ORIGIN, loadWalletConnect: null });
  manager.start();
  manager.select('legacy');
  await manager.connect();
  assert.equal(manager.status, 'wrongChain');
  const request = wallet.request.bind(wallet);
  let approveSwitch;
  wallet.request = (args) => (args.method === 'wallet_switchEthereumChain'
    ? new Promise((resolve) => { approveSwitch = () => resolve(request(args)); }) : request(args));
  const switching = manager.switchPolygon();
  await new Promise((r) => setImmediate(r));
  assert.equal(typeof approveSwitch, 'function', 'switch prompt is pending');
  wallet.emit('disconnect');
  assert.equal(manager.status, 'disconnected');
  assert.equal(wallet.listenerCount('disconnect'), 0, 'listeners detached');
  const generation = manager.generation;
  approveSwitch();
  await switching;
  assert.equal(manager.status, 'disconnected', 'a late switch result never revives a disconnected wallet');
  assert.equal(manager.account, null);
  assert.equal(manager.chainId, null);
  assert.equal(manager.error, null);
  assert.equal(manager.generation, generation, 'the abandoned switch emits nothing');
  assert.equal(wallet.listenerCount('accountsChanged') + wallet.listenerCount('chainChanged'), 0);
});

test('WalletConnect session seam: lazy load only on explicit connect, pairing URI, cancel and late connect', async () => {
  const { WalletManager } = await load();
  let loads = 0;
  const providers = [];
  class SeamProvider {
    static async init(options) {
      const provider = new SeamProvider(options);
      providers.push(provider);
      return provider;
    }
    constructor(options) {
      this.options = options;
      this.listeners = new Map();
      this.disconnects = 0;
      this.disconnectCalls = 0;
      this.session = null;
      this.uri = `wc:pair${providers.length}@2?relay-protocol=irn&symKey=00`;
      this.requests = [];
      this.connectPromise = new Promise((resolve, reject) => { this.finish = resolve; this.fail = reject; });
    }
    on(name, fn) { this.listeners.set(name, fn); }
    removeListener(name) { this.listeners.delete(name); }
    connect() { this.listeners.get('display_uri')(this.uri); return this.connectPromise; }
    approve() { this.session = {}; this.finish(); }
    // Like WalletConnect 2.26.0: disconnect() is a no-op while pairing is pending (no session yet).
    async disconnect() {
      this.disconnectCalls++;
      if (!this.session) return;
      this.session = null;
      this.disconnects++;
    }
    async request({ method }) {
      this.requests.push(method);
      if (method === 'eth_accounts') return ['0x3333333333333333333333333333333333333333'];
      if (method === 'eth_chainId') return '0x89';
      throw new Error('unexpected ' + method);
    }
  }
  const config = { walletConnectProjectId: PROJECT, allowedDeploymentOrigin: ORIGIN };
  const injected = new FakeWallet(new FakeChain());
  const manager = new WalletManager({ win: win(injected), config, origin: ORIGIN,
    loadWalletConnect: async () => { loads++; return { EthereumProvider: SeamProvider }; } });
  manager.start();
  assert.equal(loads, 0, 'no SDK load on discovery');
  assert.ok(manager.select('walletconnect'));
  assert.equal(loads, 0, 'no SDK load on select');
  // Cancel during pairing: listeners/session cleaned; a late session is discarded even after reselect.
  const first = manager.connect();
  await new Promise((r) => setImmediate(r));
  assert.equal(manager.pairing.uri, providers[0].uri);
  assert.deepEqual(providers[0].options.chains, [137]);
  assert.equal(providers[0].options.showQrModal, false);
  manager.cancelPairing();
  assert.equal(manager.status, 'disconnected');
  assert.equal(manager.pairing, null);
  assert.equal(providers[0].listeners.has('display_uri'), false, 'pairing listener removed');
  await first;
  await new Promise((r) => setImmediate(r));
  assert.ok(manager.select('legacy'), 'another wallet is selected after cancel');
  const before = providers[0].disconnects;
  const generation = manager.generation;
  providers[0].approve();
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
  assert.ok(providers[0].disconnects > before, 'late session approved after cancel is disconnected');
  assert.equal(providers[0].session, null);
  assert.equal(manager.status, 'disconnected', 'late connection after cancel stays disconnected');
  assert.equal(manager.account, null);
  assert.equal(manager.provider, null);
  assert.equal(manager.selectedId, 'legacy', 'the injected selection remains intact');
  assert.equal(manager.kind, 'legacy');
  assert.equal(manager.generation, generation, 'the late session changes no wallet state');
  assert.deepEqual(injected.requests, [], 'the injected wallet is untouched');
  assert.deepEqual(providers[0].requests, [], 'the late session is never queried');
  // A later explicit WalletConnect connect requires fresh pairing on a new provider; pairing failure is honest.
  assert.ok(manager.select('walletconnect'));
  const second = manager.connect();
  await new Promise((r) => setImmediate(r));
  assert.equal(providers.length, 2, 'a new provider is initialized');
  assert.notEqual(providers[1], providers[0]);
  assert.equal(manager.pairing.uri, providers[1].uri);
  assert.notEqual(manager.pairing.uri, providers[0].uri, 'the cancelled pairing URI is not reused');
  providers[1].fail(new Error('relay unavailable'));
  await second;
  assert.equal(manager.error.code, 'unavailable');
  // Success path identifies an account; no send method is ever called.
  const third = manager.connect();
  await new Promise((r) => setImmediate(r));
  providers[2].approve();
  await third;
  assert.equal(manager.status, 'connected');
  assert.equal(manager.account, '0x3333333333333333333333333333333333333333');
  assert.deepEqual(providers.flatMap((p) => p.requests).filter((m) => m === 'eth_sendTransaction'), []);
  await manager.disconnect();
  assert.equal(manager.status, 'disconnected');
  await new Promise((r) => setImmediate(r));
  assert.equal(providers[2].disconnects, 1, 'explicit disconnect ends the session');
});

test('real WalletConnect 2.26.0 chain response keeps an approved Polygon session connected', async () => {
  const { WalletManager } = await load();
  const { EthereumProvider } = await import('@walletconnect/ethereum-provider');
  const { UniversalProvider } = await import('@walletconnect/universal-provider');
  // Synthetic approved session, real SDK request path. No init/connect/relay, key or transaction.
  const account = '0x3333333333333333333333333333333333333333';
  const signer = new UniversalProvider({ logger: 'silent', disableProviderPing: true });
  signer.client = { core: { storage: {} }, request: () => { throw new Error('network forbidden'); } };
  signer.namespaces = { eip155: { chains: ['eip155:137'], methods: [], events: [],
    rpcMap: { 137: 'https://rpc.invalid' } } };
  signer.session = { topic: 'offline-fixture', namespaces: { eip155: {
    accounts: [`eip155:137:${account}`], methods: [], events: [],
  } } };
  signer.createProviders();
  const provider = new EthereumProvider();
  provider.signer = signer;
  provider.chainId = 137;
  let disconnects = 0;
  provider.disconnect = async () => { disconnects++; };
  const rawChain = await provider.request({ method: 'eth_chainId' });
  assert.equal(rawChain, 137, 'the pinned SDK returns a number, not EIP-1193 hex');
  const manager = new WalletManager({ win: win(), origin: ORIGIN,
    config: { walletConnectProjectId: PROJECT, allowedDeploymentOrigin: ORIGIN },
    loadWalletConnect: async () => ({ EthereumProvider: { init: async () => provider } }),
  });
  manager.select('walletconnect');
  await manager.connect();
  assert.equal(manager.status, 'connected');
  assert.equal(manager.chainId, '0x89');
  assert.equal(await manager.request('eth_chainId'), '0x89', 'controller revalidation sees the same chain');
  assert.equal(manager.account, account);
  assert.equal(disconnects, 0, 'an approved session must not be discarded as malformed');
  await manager.disconnect();
});

test('chain IDs are validated consistently on connect, events, reads and explicit switch', async () => {
  const { WalletManager } = await load();
  const wallet = new FakeWallet(new FakeChain(), { chainId: 137 });
  const manager = new WalletManager({ win: win(wallet), origin: ORIGIN, config: null });
  manager.start();
  manager.select('legacy');
  await manager.connect();
  assert.equal(manager.status, 'connected');
  assert.equal(await manager.request('eth_chainId'), '0x89');
  for (const value of [1, '0x1']) {
    wallet.emitChain(value);
    assert.equal(manager.status, 'wrongChain');
    assert.equal(await manager.request('eth_chainId'), '0x1');
    await manager.switchPolygon();
    assert.equal(manager.status, 'connected');
  }
  for (const value of [0, -1, 137.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '137', '', null, {}, true]) {
    wallet.emitChain(value);
    assert.equal(manager.chainId, null, `invalid chain: ${String(value)}`);
    assert.equal(manager.status, 'wrongChain');
    assert.equal(await manager.request('eth_chainId'), null);
    await manager.disconnect();
    await manager.connect();
    assert.equal(manager.status, 'disconnected');
    assert.equal(manager.error.code, 'malformed');
    wallet.chainId = 137;
    await manager.connect();
    assert.equal(manager.status, 'connected');
  }
  assert.equal(wallet.sends.length, 0);
  await manager.disconnect();
});

test('explicit switch accepts a numeric Polygon response after the wallet changes chains', async () => {
  const { WalletManager } = await load();
  const wallet = new FakeWallet(new FakeChain(), { chainId: 1 });
  const original = wallet.request.bind(wallet);
  let chainReads = 0;
  wallet.request = (request) => {
    if (request.method === 'wallet_switchEthereumChain') {
      wallet.requests.push(request);
      assert.deepEqual(request.params, [{ chainId: '0x89' }]);
      wallet.emitChain(137);
      return Promise.resolve(null);
    }
    if (request.method === 'eth_chainId') {
      chainReads++;
      assert.equal(typeof wallet.chainId, 'number');
    }
    return original(request);
  };
  const manager = new WalletManager({ win: win(wallet), origin: ORIGIN, config: null });
  manager.start();
  manager.select('legacy');
  await manager.connect();
  assert.equal(manager.status, 'wrongChain');
  await manager.switchPolygon();
  assert.equal(manager.error, null);
  assert.equal(chainReads, 2, 'connect and post-switch read both reached the provider');
  assert.equal(wallet.chainId, 137, 'fixture keeps the post-switch response numeric');
  assert.equal(manager.chainId, '0x89');
  assert.equal(manager.status, 'connected');
  assert.equal(await manager.request('eth_chainId'), '0x89');
  assert.equal(wallet.sends.length, 0);
  await manager.disconnect();
});

test('real @walletconnect/ethereum-provider 2.26.0 initializes with the exact options and only the relay host', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname,
    '../node_modules/@walletconnect/ethereum-provider/package.json'), 'utf8'));
  assert.equal(pkg.version, '2.26.0');
  const child = require('node:child_process').spawnSync(process.execPath, [path.join(__dirname,
    'support/wc-real-probe.mjs')], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(child.status, 0, child.stderr.slice(-500));
  const probe = JSON.parse(child.stdout.trim().split('\n').pop());
  assert.equal(probe.initialized, true, 'real EthereumProvider.init resolved');
  assert.deepEqual(probe.captured.chains, [137]);
  assert.deepEqual(probe.captured.methods, ['eth_sendTransaction', 'wallet_switchEthereumChain']);
  assert.equal(probe.captured.showQrModal, false);
  assert.equal(probe.captured.telemetryEnabled, false);
  // The SDK's own resolved session request namespace: Polygon only, the two methods, our relay RPC.
  assert.deepEqual(probe.rpc, { chains: ['eip155:137'], optionalChains: [], methods: ['eth_sendTransaction',
    'wallet_switchEthereumChain'], optionalMethods: [], rpcMap: { 137: 'https://p256-signer.mini.tumf.dev/rpc' }, showQrModal: false });
  assert.equal(probe.modal, null, 'no AppKit modal instance');
  assert.equal(probe.during, 'connecting', 'relay unreachable: pairing never completes');
  assert.equal(probe.after, 'disconnected');
  assert.equal(probe.account, null);
  assert.ok(probe.seen.length > 0, 'the SDK attempted its relay transport');
  for (const [kind, url] of probe.seen) {
    assert.equal(kind, 'ws', `no HTTP fetch at all (${url})`);
    assert.ok(url.startsWith('wss://relay.walletconnect.com?'), url);
  }
});

test('fork harness guards refuse unsafe endpoints, clients, chains and credentials before submission', async () => {
  const fork = require('./check-fork.cjs');
  for (const url of ['https://polygon.drpc.org', 'http://10.0.0.5:8545', 'http://localhost.evil.example:8545',
    'http://127.0.0.1:8545/?key=x', 'http://user:pw@127.0.0.1:8545', 'ws://127.0.0.1:8545']) {
    assert.throws(() => fork.requireLoopback(url), /loopback/, url);
  }
  assert.doesNotThrow(() => fork.requireLoopback('http://127.0.0.1:18545'));
  assert.throws(() => fork.requireClient('Geth/v1.13'), /anvil/i);
  assert.doesNotThrow(() => fork.requireClient('anvil/v1.8.3'));
  assert.throws(() => fork.requireChain('0x1'), /137/);
  assert.throws(() => fork.requireNoCredentials({ PRIVATE_KEY: '0xabc' }), /credential/);
  assert.throws(() => fork.requireNoCredentials({ FORK_RPC_URL: 'https://x', MNEMONIC: 'a b c' }), /credential/);
  assert.doesNotThrow(() => fork.requireNoCredentials({ FORK_RPC_URL: 'https://polygon.drpc.org' }));
  assert.throws(() => fork.requireForkSource('http://127.0.0.1:8545'), /public HTTPS/);
  assert.throws(() => fork.requireForkSource('https://user:secret@rpc.example'), /credential/);
  assert.throws(() => fork.requireForkSource('https://rpc.example/?apikey=1'), /credential/);
  assert.doesNotThrow(() => fork.requireForkSource('https://polygon.drpc.org'));
  // The harness submits the product plan output; a hardcoded or tampered transaction is refused.
  const plan = await fork.productPlan(fork.FIXTURE_HANDOFF);
  assert.equal(plan.address, fork.FIXTURE_HANDOFF.expectedAddress);
  assert.throws(() => fork.requireProductTransaction(plan, { ...plan.transaction, data: plan.transaction.data + '00' }),
    /product plan/);
  assert.throws(() => fork.requireProductTransaction(plan, { ...plan.transaction, value: '0x1' }), /product plan/);
  assert.doesNotThrow(() => fork.requireProductTransaction(plan, { ...plan.transaction }));
  assert.equal(fork.ANVIL_ARGS.includes('--fork-block-number') && fork.ANVIL_ARGS.includes('95559460'), true);
  assert.equal(fork.ANVIL_ARGS[fork.ANVIL_ARGS.indexOf('--host') + 1], '127.0.0.1');
  assert.equal(fork.ANVIL_ARGS[fork.ANVIL_ARGS.indexOf('--chain-id') + 1], '137');
  // The fork harness drives the production AttemptStore (over its in-process stand-in), never a write fallback.
  const { AttemptStore } = await import('../attempt-store.js');
  const store = new AttemptStore({ indexedDB: fork.memoryIndexedDB(), readLegacy: () => null, validateRecord: () => true });
  const { snapshot } = await store.load();
  assert.deepEqual({ ...snapshot }, { version: 1, revision: 0, raw: null, legacyRaw: null });
  assert.equal((await store.compareAndSet({ revision: 1, raw: null }, null)).committed, false);
  assert.equal((await store.compareAndSet(snapshot, null)).snapshot.revision, 1);
});
