import { buildRequest, expectedChain, issuedAtFor, validateContext, verifyResult, ORIGIN, METHODS } from './safe-request-model.js';
import { SavedResultStore } from './saved-result-store.js';
const denied = () => { throw new Error('Safe session unavailable or changed'); };
const reason = { code: 6000, message: 'User disconnected' };
const LOSS = ['session_delete', 'session_expire', 'session_update', 'session_event'];

// SDK 2.26.0 EngineTypes.connect/request and SignClientTypes session events.
// No persisted grant, wallet provider, automatic reconnect, retry or signing on events.
export class SafeSession {
  constructor(client, expected, clock = () => Math.floor(Date.now() / 1000), changed = () => {}, store = new SavedResultStore()) {
    this.client = client; this.expected = Object.freeze({ ...expected }); this.clock = clock;
    // The handoff's one closed chain: the proposal, the granted account and every request name it only.
    this.chain = expectedChain(this.expected).caip2;
    this.store = store;
    this.changed = changed; this.generation = 0; this.busy = false; this.session = null; this.context = null; this.spent = false;
    // Any update, event, delete or expiry of the authorized topic ends local authority; none ever signs.
    this.listener = ({ topic }) => { if (topic === this.session?.topic) void this.close().catch(() => {}); };
    for (const event of LOSS) client.on(event, this.listener);
  }
  check(session = this.session) {
    const ns = session?.namespaces, n = ns?.eip155;
    if (!session || !(session.expiry > this.clock()) || session.peer?.metadata?.url !== ORIGIN
        || !ns || Object.keys(ns).join() !== 'eip155' || !n || !Array.isArray(n.events) || n.events.length !== 0
        || !Array.isArray(n.methods) || n.methods.length !== 2 || !METHODS.every(m => n.methods.includes(m))
        || !Array.isArray(n.accounts) || n.accounts.length !== 1
        || n.accounts[0].toLowerCase() !== `${this.chain}:${this.expected.signer}`.toLowerCase()
        || (n.chains !== undefined && (!Array.isArray(n.chains) || n.chains.length !== 1 || n.chains[0] !== this.chain))
        || session.sessionProperties || session.scopedProperties || session.authentication || session.walletPayResult) denied();
  }
  alive(generation) { if (generation !== this.generation) denied(); this.check(); }
  // Single use: one connection, at most one signature request. Closing ends the object for good.
  async connect(showURI) {
    if (this.busy || this.session || this.generation) denied();
    this.busy = true; const generation = ++this.generation;
    try {
      const { uri, approval } = await this.client.connect({ requiredNamespaces: {
        eip155: { chains: [this.chain], methods: [...METHODS], events: [] } } });
      if (generation !== this.generation) denied();
      if (uri) await showURI(uri);
      if (generation !== this.generation) denied();
      const session = await approval();
      // A late or broadened approval is disconnected, never adopted.
      try { if (generation !== this.generation) denied(); this.check(session); }
      catch (error) { await this.client.disconnect({ topic: session.topic, reason }).catch(() => {}); throw error; }
      this.session = session;
    } finally { if (generation === this.generation) this.busy = false; }
  }
  // Explicit context retrieval. Not signing consent; fixes the authority a later request must match.
  async inspect() {
    if (this.busy || this.context || this.spent) denied(); this.check();
    this.busy = true; const generation = this.generation;
    try {
      const result = await this.client.request({ topic: this.session.topic, chainId: this.chain,
        request: { method: METHODS[0], params: [] } });
      this.alive(generation);
      this.context = validateContext(result, this.expected);
      return this.context;
    } catch (error) {
      if (generation === this.generation) await this.close(error).catch(() => {});
      throw error;
    } finally { if (generation === this.generation) this.busy = false; }
  }
  async sign(id = crypto.randomUUID()) { return this.#sign(id, false); }
  // Explicit in-memory handoff only; no export, persistence, collection or send side effect.
  async signPacket(id = crypto.randomUUID()) { return this.#sign(id, true); }
  async #sign(id, packet) {
    if (this.busy || !this.context || this.spent) denied(); this.check();
    this.busy = true; this.spent = true; const generation = this.generation, context = this.context, topic = this.session.topic;
    try {
      // Re-read over the very same authorized topic. Binding/key/policy rotation requires reconnect.
      const fresh = await this.client.request({ topic, chainId: this.chain,
        request: { method: METHODS[0], params: [] } });
      this.alive(generation); validateContext(fresh, this.expected);
      if (this.session.topic !== topic || Object.keys(context).some(k => fresh[k] !== context[k])) denied();
      const request = buildRequest(context, this.expected, id, issuedAtFor(this.clock()));
      this.alive(generation);
      // save resolves only after the unsigned record's strict IndexedDB transaction completes.
      await this.store.save({ version: 1, purpose: 'safe-tx-v1.5.0', requestId: request.id,
        envelope: request.envelope, context, expected: this.expected });
      this.alive(generation);
      const now = this.clock();
      if (this.session.topic !== topic || !Number.isSafeInteger(now)
          || now < request.issuedAt || now >= request.expiresAt) denied();
      const result = structuredClone(await this.client.request({ topic, chainId: this.chain,
        request: { method: METHODS[1], params: [request.envelope] } }));
      // The verified reply owns only scalar fields; freeze our copy, never the SDK's object.
      Object.freeze(result);
      this.alive(generation);
      const signerSignature = await verifyResult(result, request, context, this.expected, this.clock());
      this.alive(generation);
      if (packet) return Object.freeze({ owner: this.expected.signer.toLowerCase(),
        expected: this.expected, context, request, result });
      return Object.freeze({ requestId: request.id, safeTxHash: request.safeTxHash, signerSignature });
    } catch (error) {
      // Unknown delivery is not permission to submit another operation. Explicit reconnect required.
      if (generation === this.generation) await this.close(error).catch(() => {});
      throw error;
    } finally { if (generation === this.generation) this.busy = false; }
  }
  // `cause` (the failed operation's error, if any) only lets the page word its status; it grants nothing.
  async close(cause) {
    const session = this.session;
    ++this.generation; this.session = null; this.context = null; this.busy = false; this.changed(cause);
    if (session) await this.client.disconnect({ topic: session.topic, reason });
  }
  // Final teardown of this object: no later SDK event reaches it.
  async dispose() {
    for (const event of LOSS) this.client.off?.(event, this.listener);
    await this.close();
  }
}
