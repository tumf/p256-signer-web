// Test-only page entry: the production safe-page.js mounted with a controlled SignClient double.
// NOT a real relay, wallet or iPhone: it answers only what the rendered check scripts through window.__harness
// ({ jwk, context, expected, now }, injected before load).
import { mountSafePage } from '../../safe-page.js';
import { buildRequest, validateContext } from '../../safe-request-model.js';

const H = window.__harness;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const hex = (bytes) => '0x' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
const bytes = (text) => Uint8Array.from(text.slice(2).match(/../g), (b) => parseInt(b, 16));
H.calls = []; H.handlers = {}; H.sessions = 0;

class HarnessClient {
  static async init(options) {
    H.init = { ...options, storage: typeof options.storage?.setItem };
    return new HarnessClient();
  }
  on(event, fn) { (H.handlers[event] ||= []).push(fn); }
  off(event, fn) { H.handlers[event] = (H.handlers[event] || []).filter((h) => h !== fn); }
  async connect(params) {
    H.calls.push(['connect', params]);
    const topic = `harness-${++H.sessions}`;
    const session = { topic, expiry: H.now + 3600, peer: { metadata: { url: H.context.origin } },
      namespaces: { eip155: { accounts: [`eip155:137:${H.context.signer}`],
        methods: ['p256_getSessionContext', 'p256_signSafeRequest'], events: [] } } };
    return { uri: `wc:${'ab'.repeat(32)}@2?relay-protocol=irn&symKey=${'cd'.repeat(32)}`,
      approval: () => new Promise((resolve) => { H.approve = () => { H.topic = topic; resolve(session); }; }) };
  }
  async disconnect({ topic }) { H.calls.push(['disconnect', topic]); }
  async request({ topic, request }) {
    H.calls.push(['request', request.method, topic]);
    if (request.method === 'p256_getSessionContext') return structuredClone(H.context);
    const sent = JSON.parse(request.params[0]);
    const r = buildRequest(validateContext(H.context, H.expected), H.expected, sent.id, Number(sent.issuedAt));
    if (r.envelope !== request.params[0]) throw { code: -32602, message: 'invalid params' };
    if (H.refuse) throw { code: 5003, message: 'rejected' };
    const key = await crypto.subtle.importKey('jwk', H.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, bytes(r.safeTxHash)));
    let s = BigInt(hex(raw.slice(32)));
    if (s > N / 2n) s = N - s;
    const rawSignature = hex(raw.slice(0, 32)) + s.toString(16).padStart(64, '0');
    const prefix = H.keyHash;
    return { version: 1, requestId: sent.id, keyId: H.context.keyId, codecId: H.context.codecId,
      safeTxHash: r.safeTxHash, commitment: r.commitment, binding: H.context.binding, publicPoint: H.context.publicKey,
      rawSignature, signerSignature: prefix + rawSignature.slice(2) };
  }
}
H.emit = (event) => { for (const fn of H.handlers[event] || []) fn({ topic: H.topic }); };

mountSafePage(document, {
  origin: location.origin, location, history,
  loadConfig: async () => ({ walletConnectProjectId: 'ab'.repeat(16), allowedDeploymentOrigin: location.origin }),
  loadSignClient: async () => HarnessClient,
  loadQR: () => import('../../qr.js').then((module) => module.default),
  clock: () => H.now,
  uuid: () => crypto.randomUUID(),
});
