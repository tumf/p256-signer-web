// Dedicated native key-change session over the pinned SignClient 2.26.0 (EngineTypes connect/request, session
// events). Exactly p256_getKeyChangeContext / p256_signKeyChangeRequest on eip155:137 for one signer account, no
// events. Single use: one connection, one context, at most one signature request. No grant, pairing URI, binding or
// signature is persisted, and no SDK event, reconnect or reload ever signs. Separate from SafeSession and the
// executor wallet.
import {
  anchorChain, KeyError, METHODS, ORIGIN, sameAuthority, validateNativeContext, verifyResult,
} from './key-model.js';

export const STORAGE_PREFIX = 'p256.key-change.session.v1';
const reason = { code: 6000, message: 'User disconnected' };
const LOSS = ['session_delete', 'session_expire', 'session_update', 'session_event'];

/** Classified session failure for the fixed page copy: rejected | lost | changed | invalid | expired. */
export class SessionError extends Error {
  constructor(kind) {
    super(`key-change session ${kind}`);
    this.name = 'SessionError';
    this.kind = kind;
  }
}
const denied = (kind = 'lost') => { throw new SessionError(kind); };

/** Maps a peer/SDK/model failure to its fixed class. Unknown delivery is `lost`, never `rejected`. */
export function classify(error) {
  if (error instanceof SessionError) return error.kind;
  if (error && error.code === 5003) return 'rejected';
  if (error && error.code === 5004) return 'expired';
  if (error && error.code === 4100) return 'changed';
  if (error instanceof KeyError) {
    if (error.code === 'expired') return 'expired';
    if (['changed', 'policy', 'context'].includes(error.code)) return 'changed';
    return 'invalid';
  }
  return 'lost';
}

/** SDK IKeyValueStorage held in memory only: a reload restores no pairing, session or result. */
export function memoryStorage() {
  const memory = new Map();
  return { getKeys: async () => [...memory.keys()], getEntries: async () => [...memory.entries()],
    getItem: async (key) => memory.get(key), setItem: async (key, value) => { memory.set(key, value); },
    removeItem: async (key) => { memory.delete(key); } };
}

/** The exact SignClient.init options for the native session: memory storage and its own prefix. */
export function signClientOptions(projectId) {
  return { projectId, relayUrl: 'wss://relay.walletconnect.com', logger: 'silent', telemetryEnabled: false,
    storage: memoryStorage(), customStoragePrefix: STORAGE_PREFIX,
    metadata: { name: 'P256 Signer', description: 'P256 Signer key change', url: ORIGIN, icons: [] } };
}

export class KeyChangeSession {
  /**
   * @param client  SignClient instance
   * @param anchor  parseAuthority() result: the only source of the expected signer/key
   * @param clock   unix seconds
   * @param changed called once when local authority ends (with the classified cause)
   */
  constructor(client, anchor, clock = () => Math.floor(Date.now() / 1000), changed = () => {}) {
    this.client = client; this.anchor = anchor; this.clock = clock; this.changed = changed;
    // The anchor's one closed chain: the proposal, the granted account and every request name it only.
    this.chain = anchorChain(anchor).caip2;
    this.generation = 0; this.busy = false; this.session = null; this.context = null; this.spent = false;
    this.listener = ({ topic }) => { if (topic === this.session?.topic) void this.close('lost').catch(() => {}); };
    for (const event of LOSS) client.on(event, this.listener);
  }

  check(session = this.session) {
    const ns = session?.namespaces, n = ns?.eip155;
    if (!session || !(session.expiry > this.clock()) || session.peer?.metadata?.url !== ORIGIN
        || !ns || Object.keys(ns).join() !== 'eip155' || !n || !Array.isArray(n.events) || n.events.length !== 0
        || !Array.isArray(n.methods) || n.methods.length !== 2 || !METHODS.every((m) => n.methods.includes(m))
        || !Array.isArray(n.accounts) || n.accounts.length !== 1
        || n.accounts[0].toLowerCase() !== `${this.chain}:${this.anchor.signerAddress}`
        || (n.chains !== undefined && (!Array.isArray(n.chains) || n.chains.length !== 1 || n.chains[0] !== this.chain))
        || session.sessionProperties || session.scopedProperties || session.authentication
        || session.walletPayResult) denied('lost');
  }

  alive(generation) { if (generation !== this.generation) denied('lost'); this.check(); }

  async connect(showURI) {
    if (this.busy || this.session || this.generation) denied('lost');
    this.busy = true; const generation = ++this.generation;
    try {
      // The SDK rewrites these into optionalNamespaces; native admission accepts that shape (fix-sign-namespace).
      const { uri, approval } = await this.client.connect({ requiredNamespaces: {
        eip155: { chains: [this.chain], methods: [...METHODS], events: [] } } });
      if (generation !== this.generation) denied('lost');
      if (uri) await showURI(uri);
      if (generation !== this.generation) denied('lost');
      const session = await approval();
      try { if (generation !== this.generation) denied('lost'); this.check(session); }
      catch (error) { await this.client.disconnect({ topic: session.topic, reason }).catch(() => {}); throw error; }
      this.session = session;
    } finally { if (generation === this.generation) this.busy = false; }
  }

  async readContext() {
    const result = await this.client.request({ topic: this.session.topic, chainId: this.chain,
      request: { method: METHODS[0], params: [] } });
    const context = validateNativeContext(result, this.anchor);
    const wire = structuredClone(result);
    wire.keys.forEach(Object.freeze);
    Object.freeze(wire.keys);
    return { context, wire: Object.freeze(wire) };
  }

  /** Explicit context retrieval: fixes the native authority a later request must match. Not signing consent. */
  async inspect() {
    if (this.busy || this.context || this.spent) denied('lost');
    this.check();
    this.busy = true; const generation = this.generation;
    try {
      const { context } = await this.readContext();
      this.alive(generation);
      this.context = context;
      return context;
    } catch (error) {
      if (generation === this.generation) await this.close(classify(error)).catch(() => {});
      throw new SessionError(classify(error));
    } finally { if (generation === this.generation) this.busy = false; }
  }

  /**
   * One explicit request. `prepare(nativeContext, validatedWire)` rereads the independent chain context and returns the exact
   * request (buildRequest) or throws; this rereads native context first and compares semantic authority.
   */
  async sign(prepare) {
    if (this.busy || !this.context || this.spent) denied('lost');
    this.check();
    this.busy = true; this.spent = true; const generation = this.generation, context = this.context;
    try {
      const { context: fresh, wire } = await this.readContext();
      this.alive(generation);
      if (!sameAuthority(fresh, context)) denied('changed');
      const request = await prepare(fresh, wire);
      this.alive(generation);
      if (!(this.clock() < request.expiresAt)) denied('expired');
      const result = await this.client.request({ topic: this.session.topic, chainId: this.chain,
        request: { method: METHODS[1], params: [request.envelope] } });
      this.alive(generation);
      const signerSignature = await verifyResult(result, request, context, this.clock());
      // No adoption before a generation recheck after the asynchronous cryptography.
      this.alive(generation);
      return Object.freeze({ request, signerSignature, rawSignature: result.rawSignature });
    } catch (error) {
      if (generation === this.generation) await this.close(classify(error)).catch(() => {});
      throw new SessionError(classify(error));
    } finally { if (generation === this.generation) this.busy = false; }
  }

  async close(cause) {
    const session = this.session;
    ++this.generation; this.session = null; this.context = null; this.busy = false;
    this.changed(cause);
    if (session) await this.client.disconnect({ topic: session.topic, reason });
  }

  async dispose() {
    for (const event of LOSS) this.client.off?.(event, this.listener);
    const changed = this.changed;
    this.changed = () => {};
    await this.close().finally(() => { this.changed = changed; });
  }
}
