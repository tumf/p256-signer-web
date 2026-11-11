// Browser v3 bridge session composition (docs/public-defi-spec-v1.md §1, §2.1.1, §3.1).
//
// Composes the fixed dedicated bridge peer, the exact granted namespace/account/chain/methods and explicit
// connect / inspect / request / retrieve steps over an injected SDK-like client. Requests are compiled by the existing
// independent defi-v3.js and every structured SDK result is copied, frozen and strictly verified by the independent
// defi-v3-result.js before any success. Nothing signs on connect, update or foreground; there is no fallback to legacy
// methods, no automatic retry, no external executor or dApp provider, and no storage of topics, URIs or session
// secrets (the topic lives only in this closure). Only a locally validated configuration created by
// createSessionConfig() is accepted; a request-supplied object can never stand in for it.
import { bytesToHex, computeRequest, get, hexToBytes, parseJSON } from './defi-v3.js';
import { verifyV3Result } from './defi-v3-result.js';

export const BRIDGE_ORIGIN = 'https://p256-signer.tumf.dev';
export const CHAIN = 'eip155:137';
export const CHAIN_ID = '137';
export const SIGN_METHOD = 'p256_signSafeRequestV3';
export const RESULT_METHOD = 'p256_getSafeRequestResultV3';
export const METHODS = Object.freeze([SIGN_METHOD, RESULT_METHOD]);

const ENVELOPE_KEYS = ['v', 'purpose', 'codecId', 'id', 'keyId', 'binding', 'signer', 'issuedAt', 'expiresAt',
  'payloadJson'];
const RPC_ERROR_CODES = new Set([-32601, -32602, -32000, 4001, 4100, 4200]);
const reason = { code: 6000, message: 'User disconnected' };
const LOSS = ['session_delete', 'session_expire', 'session_update', 'session_event'];
const sessionConfigs = new WeakSet();

export class V3SessionError extends Error {
  constructor(code) {
    super(`v3 bridge: ${code}`);
    this.name = 'V3SessionError';
    this.code = code;
  }
}

const fail = (code) => { throw new V3SessionError(code); };

/** The exact required namespace: eip155:137, the two v3 methods, no events. */
export function requiredNamespaces() {
  return { eip155: { chains: [CHAIN], methods: [...METHODS], events: [] } };
}

/** Locally selected Signer and Safe for the fixed bridge origin and chain. */
export function createSessionConfig(options) {
  const { signer, safe } = options ?? {};
  const address = /^0x[0-9a-f]{40}$/;
  if (typeof signer !== 'string' || typeof safe !== 'string'
      || !address.test(signer) || !address.test(safe) || signer === safe) fail('INVALID_CONFIG');
  const config = Object.freeze({ bridgeOrigin: BRIDGE_ORIGIN, chain: CHAIN, signer, safe });
  sessionConfigs.add(config);
  return config;
}

function sameSet(list, expected) {
  return Array.isArray(list) && list.length === expected.length && new Set(list).size === expected.length
    && expected.every((m) => list.includes(m));
}

/** Plain frozen envelope object: exactly the ten root strings in original order, values byte-identical. */
function envelopeObject(wire) {
  const root = parseJSON(wire);
  if (root.t !== 'object' || root.members.length !== ENVELOPE_KEYS.length) fail('INVALID_REQUEST');
  const envelope = {};
  root.members.forEach(([key, node], i) => {
    if (key !== ENVELOPE_KEYS[i] || node.t !== 'string') fail('INVALID_REQUEST');
    envelope[key] = node.v;
  });
  return Object.freeze(envelope);
}

/** Independent candidate identity for result verification, from the request bytes only. */
export function candidateFromWire(wire, sha256) {
  const envelope = envelopeObject(wire);
  const computed = computeRequest(wire, sha256);
  const payload = parseJSON(hexToBytes(envelope.payloadJson));
  const chain = get(payload, 'chainId');
  const safe = get(payload, 'safe');
  return Object.freeze({
    v: envelope.v, purpose: envelope.purpose, requestId: envelope.id, keyId: envelope.keyId,
    codecId: envelope.codecId, binding: envelope.binding, signer: envelope.signer,
    chainId: chain?.t === 'string' ? chain.v : null, safe: safe?.t === 'string' ? safe.v : null,
    commitment: bytesToHex(computed.commitment), signedDigest: bytesToHex(computed.signedDigest),
    envelope,
  });
}

/**
 * One explicit v3 bridge session over `client`:
 *   client.connect({ requiredNamespaces }) -> { uri?, approval: () -> Promise<Session> }
 *   client.request({ topic, chainId, request: { method, params } }) -> structured result
 *   client.disconnect({ topic, reason })
 * The pinned SignClient 2.26.0 rewrites requiredNamespaces into optionalNamespaces.
 */
export function createV3BridgeSession({ client, config, sha256, clock = () => Math.floor(Date.now() / 1000) }) {
  if (!sessionConfigs.has(config)) fail('INVALID_CONFIG');
  if (typeof sha256 !== 'function' || typeof clock !== 'function'
      || ['connect', 'request', 'disconnect', 'on', 'off'].some(name => typeof client?.[name] !== 'function')
      || typeof client?.session?.get !== 'function') fail('INVALID_CONFIG');
  const account = `${CHAIN}:${config.signer}`;
  let topic = null;
  let generation = 0;
  let state = 'idle';
  let disposed = false;
  let pendingDiscard = null;
  // requestId -> candidate (request data only; never result bytes or topics).
  const candidates = new Map();
  const outcomes = new Map();

  function connected() { return topic !== null; }

  function validSession(session) {
    const ns = session?.namespaces?.eip155, now = clock();
    return Number.isSafeInteger(now) && Number.isSafeInteger(session?.expiry) && session.expiry > now
      && typeof session?.topic === 'string' && /^[0-9a-f]{64}$/.test(session.topic)
      && session?.peer?.metadata?.url === BRIDGE_ORIGIN && Object.keys(session.namespaces ?? {}).length === 1
      && sameSet(ns?.accounts, [account]) && sameSet(ns?.methods, METHODS) && Array.isArray(ns?.events)
      && ns.events.length === 0 && (ns.chains === undefined || sameSet(ns.chains, [CHAIN]))
      && ['sessionProperties', 'scopedProperties', 'authentication', 'walletPayResult']
        .every(name => session[name] === undefined);
  }

  function current() {
    if (!connected()) fail('NOT_CONNECTED');
    try {
      const session = client.session.get(topic);
      if (session?.topic === topic && validSession(session)) return;
    } catch {}
    end('ended');
    fail('STALE_SESSION');
  }

  function end(next) {
    const old = topic;
    topic = null;
    generation += 1;
    pendingDiscard?.();
    pendingDiscard = null;
    if (old) void discard({ topic: old });
    candidates.clear();
    outcomes.clear();
    state = next;
  }

  async function discard(session) {
    if (typeof session?.topic === 'string') {
      try { await client.disconnect({ topic: session.topic, reason }); } catch {}
    }
  }

  async function connect(showURI) {
    if (disposed) fail('STALE_SESSION');
    if (connected() || state === 'connecting') fail('ALREADY_CONNECTED');
    const attempt = ++generation;
    state = 'connecting';
    let settled, discarded = false;
    const close = async () => {
      if (!settled || discarded) return;
      discarded = true;
      await discard(settled);
    };
    pendingDiscard = () => { void close(); };
    try {
      const { uri, approval } = await client.connect({ requiredNamespaces: requiredNamespaces() });
      const approved = approval().then(async session => {
        settled = session;
        if (attempt !== generation) await close();
        return session;
      });
      // Observe rejection while URI presentation is suspended; never expose an SDK error or URI in errors.
      approved.catch(() => {});
      try {
        if (uri && attempt === generation) await showURI(uri);
      } catch {
        void approved.then(close).catch(() => {});
        await close();
        fail('CONNECTION_FAILED');
      }
      const session = await approved;
      if (attempt !== generation) {
        await close();
        fail('STALE_SESSION');
      }
      if (!validSession(session)) {
        await close();
        fail('NAMESPACE_MISMATCH');
      }
      topic = session.topic;
      pendingDiscard = null;
      current();
      state = 'connected';
      return inspect();
    } catch (error) {
      if (attempt !== generation) fail('STALE_SESSION');
      state = 'idle';
      if (error instanceof V3SessionError) throw error;
      fail('CONNECTION_FAILED');
    }
  }

  /** Nonsecret inspection: never the topic, URI or any session secret. */
  function inspect() {
    return Object.freeze({
      state, connected: connected(), origin: BRIDGE_ORIGIN, chain: CHAIN, account: connected() ? account : null,
      methods: connected() ? METHODS : Object.freeze([]),
      outcomes: Object.freeze(Object.fromEntries(outcomes)),
    });
  }

  /** Ignore unrelated/retired topics; SDK store validation covers the eventual new settlement. */
  function handleEvent(name, event) {
    if (LOSS.includes(name) && connected() && event?.topic === topic) end('ended');
  }
  const listeners = LOSS.map(name => [name, event => handleEvent(name, event)]);
  for (const [name, listener] of listeners) client.on(name, listener);

  async function send(method, params, candidate) {
    current();
    const owner = generation;
    const sentTopic = topic;
    let response;
    try {
      response = await client.request({ topic: sentTopic, chainId: CHAIN, request: { method, params } });
    } catch (error) {
      if (owner !== generation) fail('STALE_SESSION');
      current();
      const code = error?.code;
      if (Number.isInteger(code) && RPC_ERROR_CODES.has(code)) {
        outcomes.set(candidate.requestId, 'rejected');
        throw new V3SessionError(`RPC_${code}`);
      }
      // Unknown delivery: never retried automatically; only an explicit retrieve may follow.
      outcomes.set(candidate.requestId, 'unknown');
      fail('DELIVERY_UNKNOWN');
    }
    if (owner !== generation) fail('STALE_SESSION');
    current();
    const verified = verifyV3Result(response, candidate, { sha256 });
    outcomes.set(candidate.requestId, 'verified');
    return verified;
  }

  /** Explicit request of exactly one v3 wire (Uint8Array). Params are exactly [envelopeObject]. */
  async function request(wire) {
    current();
    if (!(wire instanceof Uint8Array)) fail('INVALID_REQUEST');
    const candidate = candidateFromWire(wire, sha256);
    if (candidate.signer !== config.signer || candidate.chainId !== CHAIN_ID || candidate.safe !== config.safe)
      fail('ACCOUNT_MISMATCH');
    if (candidates.has(candidate.requestId)) fail('DUPLICATE_REQUEST');
    candidates.set(candidate.requestId, candidate);
    outcomes.set(candidate.requestId, 'pending');
    return send(SIGN_METHOD, [candidate.envelope], candidate);
  }

  /** Explicit saved-result retrieval for a request of this same session; never re-signs. */
  async function retrieve(requestId) {
    const candidate = candidates.get(requestId) ?? fail('UNKNOWN_REQUEST');
    return send(RESULT_METHOD, [{ id: candidate.requestId, commitment: candidate.commitment,
      binding: candidate.binding }], candidate);
  }

  async function disconnect() {
    end('disconnected');
  }

  async function dispose() {
    disposed = true;
    for (const [name, listener] of listeners) client.off(name, listener);
    await disconnect();
  }

  return Object.freeze({ connect, inspect, handleEvent, request, retrieve, disconnect, dispose });
}
