// Retrieval is a separate grant. Historical binding is comparison evidence, never current authority.
import { parseRecord, serializeRecord } from './saved-result-store.js';
import * as safe from './safe-request-model.js';
import * as key from './key-model.js';
const SAFE = 'safe-tx-v1.5.0';
const LOSS = ['session_delete', 'session_expire', 'session_update', 'session_event'];
const reason = { code: 6000, message: 'User disconnected' };
const denied = () => { throw new Error('Saved result recovery unavailable'); };
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
export class SavedResultSession {
  constructor(client, record, independent, clock = () => Math.floor(Date.now() / 1000), changed = () => {}) {
    this.client = client; this.record = parseRecord(serializeRecord(record));
    this.clock = clock; this.changed = changed; this.safe = record.purpose === SAFE;
    this.anchor = this.safe ? independent : independent.anchor;
    // Independent page input must select exactly the retained operation, not rewrite it.
    if (!equal(independent, this.record.expected)) denied();
    this.signer = this.safe ? this.anchor.signer : this.anchor.signerAddress;
    // The retained operation's own closed chain: the recovery grant and every request name it only.
    this.chain = (this.safe ? safe.expectedChain(this.anchor) : key.anchorChain(this.anchor)).caip2;
    this.methods = this.safe ? ['p256_getSessionContext', 'p256_recoverSafeResult']
      : ['p256_getKeyChangeContext', 'p256_recoverKeyChangeResult'];
    this.session = null; this.context = null; this.generation = 0; this.busy = false; this.spent = false;
    this.listener = ({ topic }) => { if (topic === this.session?.topic) void this.close().catch(() => {}); };
    for (const name of LOSS) client.on(name, this.listener);
  }
  check(session = this.session) {
    const ns = session?.namespaces, n = ns?.eip155, now = this.clock();
    if (!Number.isSafeInteger(now) || !session || !(session.expiry > now)
        || session.peer?.metadata?.url !== safe.ORIGIN || !ns || Object.keys(ns).join() !== 'eip155'
        || !n || !Array.isArray(n.methods) || n.methods.length !== 2 || !this.methods.every((m) => n.methods.includes(m))
        || !Array.isArray(n.events) || n.events.length || !Array.isArray(n.accounts) || n.accounts.length !== 1
        || n.accounts[0].toLowerCase() !== `${this.chain}:${this.signer}`.toLowerCase()
        || n.chains !== undefined && (!Array.isArray(n.chains) || n.chains.length !== 1 || n.chains[0] !== this.chain)
        || session.sessionProperties || session.scopedProperties || session.authentication || session.walletPayResult) denied();
  }
  alive(generation, topic = this.session?.topic) {
    if (generation !== this.generation || topic !== this.session?.topic) denied();
    this.check();
    const e = JSON.parse(this.record.envelope), now = this.clock();
    if (now < Number(e.issuedAt) || now >= Number(e.expiresAt)) denied();
  }
  async connect(showURI) {
    if (this.busy || this.generation) denied();
    const generation = ++this.generation; this.busy = true;
    try {
      const { uri, approval } = await this.client.connect({ requiredNamespaces: { eip155: {
        chains: [this.chain], methods: [...this.methods], events: [] } } });
      if (generation !== this.generation) denied();
      if (uri) await showURI(uri);
      if (generation !== this.generation) denied();
      const session = await approval();
      try { if (generation !== this.generation) denied(); this.check(session); }
      catch (error) { await this.client.disconnect({ topic: session.topic, reason }).catch(() => {}); throw error; }
      this.session = session;
    } finally { if (generation === this.generation) this.busy = false; }
  }
  validate(wire) {
    if (this.safe) return safe.validateContext(wire, this.anchor);
    const fresh = key.validateNativeContext(wire, this.anchor);
    const original = key.validateNativeContext(this.record.context, this.anchor);
    // Binding and observation block may differ; all key/nonce/policy authority must be identical.
    if (!key.sameAuthority({ ...fresh, binding: original.binding }, original)) denied();
    return fresh;
  }
  async read(generation, topic) {
    const wire = await this.client.request({ topic, chainId: this.chain,
      request: { method: this.methods[0], params: [] } });
    this.alive(generation, topic);
    return this.validate(wire);
  }
  async inspect() {
    if (this.busy || this.context || this.spent) denied();
    const generation = this.generation, topic = this.session?.topic;
    this.alive(generation, topic); this.busy = true;
    try { this.context = await this.read(generation, topic); return this.context; }
    catch (error) { await this.close().catch(() => {}); throw error; }
    finally { if (generation === this.generation) this.busy = false; }
  }
  async recover() {
    if (this.busy || !this.context || this.spent) denied();
    const generation = this.generation, topic = this.session?.topic;
    this.alive(generation, topic); this.busy = true; this.spent = true;
    try {
      const fresh = await this.read(generation, topic);
      if (this.safe ? !equal(fresh, this.context) : !key.sameAuthority(fresh, this.context)) denied();
      this.alive(generation, topic);
      const result = await this.client.request({ topic, chainId: this.chain,
        request: { method: this.methods[1], params: [this.record.envelope] } });
      this.alive(generation, topic);
      const r = this.record, e = JSON.parse(r.envelope);
      const context = this.safe ? r.context : key.validateNativeContext(r.context, r.expected.anchor);
      const request = this.safe ? safe.buildRequest(context, r.expected, r.requestId, Number(e.issuedAt))
        : key.buildRequest({ context, operation: r.expected.operation, id: r.requestId, issuedAt: Number(e.issuedAt) });
      const signerSignature = this.safe ? await safe.verifyResult(result, request, context, r.expected, this.clock())
        : await key.verifyResult(result, request, context, this.clock());
      this.alive(generation, topic);
      this.context = fresh;
      return Object.freeze({ result: Object.freeze({ ...result }), request, signerSignature });
    } catch (error) { await this.close().catch(() => {}); throw error; }
    finally { if (generation === this.generation) this.busy = false; }
  }
  async close() {
    const session = this.session;
    ++this.generation; this.session = null; this.context = null; this.busy = false; this.changed();
    if (session) await this.client.disconnect({ topic: session.topic, reason });
  }
  async dispose() {
    for (const name of LOSS) this.client.off?.(name, this.listener);
    await this.close();
  }
}
