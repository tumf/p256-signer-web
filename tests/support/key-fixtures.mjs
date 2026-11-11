// Test-only SOFTWARE key-change fixtures: deterministic P-256 scalars, public anchors in the exact native export
// spelling, and a SignClient double that answers as the native peer (closed context/result wire of
// HybridKeySessionWire.swift) with real WebCrypto ECDSA over raw H. NOT a relay, iPhone, Secure Enclave or physical
// authentication. Never used by production code.
import ethers from '../../vendor/ethers.js';
import {
  CODEC_ID, ENTRYPOINT, IMPLEMENTATION, IMPLEMENTATION_CODE_HASH, METHODS, ORIGIN, PURPOSE, ZERO_ADDRESS,
  commitment, keyIdHash, keyIdOf, typedDataHash,
} from '../../key-model.js';

const U = ethers.utils;
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const A = P - 3n;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const G = [0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n];
const mod = (a, m = P) => ((a % m) + m) % m;
function inv(a, m = P) {
  let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return mod(s0, m);
}
function add(p, q) {
  if (!p) return q;
  if (!q) return p;
  if (p[0] === q[0] && mod(p[1] + q[1]) === 0n) return null;
  const l = p[0] === q[0] ? mod((3n * p[0] * p[0] + A) * inv(2n * p[1])) : mod((q[1] - p[1]) * inv(q[0] - p[0]));
  const x = mod(l * l - p[0] - q[0]);
  return [x, mod(l * (p[0] - x) - p[1])];
}
function mul(k, point = G) {
  let r = null, a = point;
  for (let n = k; n > 0n; n >>= 1n) { if (n & 1n) r = add(r, a); a = add(a, a); }
  return r;
}
const hex32 = (n) => n.toString(16).padStart(64, '0');
const b64u = (n) => Buffer.from(hex32(n), 'hex').toString('base64url');
const b64uBrowser = (n) => btoa(String.fromCharCode(...hex32(n).match(/../g).map((b) => parseInt(b, 16))))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const base64url = typeof Buffer !== 'undefined' ? b64u : b64uBrowser;

/** The design's nontrivial historical software scalars (never production keys). */
export const K1 = 0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef12345n % N;
export const K2 = 0x23456789abcdef123456789abcdef123456789abcdef123456789abcdef123456n % N;

export function softwareKey(scalar) {
  const [x, y] = mul(scalar);
  const publicKey = '0x04' + hex32(x) + hex32(y);
  return Object.freeze({ scalar, publicKey, keyId: keyIdOf(publicKey),
    jwk: { kty: 'EC', crv: 'P-256', x: base64url(x), y: base64url(y), d: base64url(scalar), ext: true } });
}

/** Raw low-S r||s of ECDSA P-256 over SHA256(H) (WebCrypto hashes raw H once). */
export async function signRaw(key, hash) {
  const subtle = globalThis.crypto.subtle;
  const k = await subtle.importKey('jwk', key.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const raw = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k, U.arrayify(hash)));
  let s = BigInt(U.hexlify(raw.slice(32)));
  if (s > N / 2n) s = N - s;
  return U.hexlify(raw.slice(0, 32)) + hex32(s);
}
export const highS = (raw) => raw.slice(0, 66) + hex32(N - BigInt('0x' + raw.slice(66)));

export const anchorText = (signer, key) => `{"v":"1","kind":"hybrid-key-authority","chainId":"137","signer":"${
  U.getAddress(signer)}","publicKey":"${key.publicKey}","keyId":"${key.keyId}"}`;
export const bareKeyText = (key) => `{"v":"1","kind":"p256-public-key","publicKey":"${key.publicKey}","keyId":"${
  key.keyId}"}`;

/** Exact `p256_getKeyChangeContext` wire for a chain observation `{keys, nonce, blockNumber, blockHash}`. */
export function contextWire({ signer, key, binding, chain, maxGasUnits = '1060000', maxFeePerGas = '500000000000' }) {
  return { version: 1, origin: ORIGIN, chainId: '137', signer: signer.toLowerCase(), entryPoint: ENTRYPOINT,
    keyId: key.keyId, publicKey: key.publicKey, binding, codecId: CODEC_ID, purpose: PURPOSE, maxValiditySeconds: 120,
    maxEnvelopeBytes: 32768, nonce: chain.nonce.toString(), blockNumber: chain.blockNumber.toString(),
    blockHash: chain.blockHash, implementation: IMPLEMENTATION, implementationCodeHash: IMPLEMENTATION_CODE_HASH,
    owner: ZERO_ADDRESS, maxGasUnits, maxFeePerGas,
    keys: [...chain.keys].sort((a, b) => (a.keyId < b.keyId ? -1 : 1)).map((k) => ({ keyId: k.keyId,
      publicKey: k.publicKey })) };
}

/**
 * Software native signing: parses the exact envelope, recomputes H and commitment from its fields (never trusting
 * peer hashes), signs SHA256(H) once and returns the closed result wire.
 */
export async function nativeSign({ envelope, key, binding }) {
  const e = JSON.parse(envelope);
  const op = e.body;
  // Like the native signer: the envelope's own closed chain names H, the commitment and the result (Polygon: '137').
  const h = typedDataHash(op, e.chainId);
  const c = commitment({ id: e.id, keyId: e.keyId, binding: e.binding, issuedAt: Number(e.issuedAt),
    expiresAt: Number(e.expiresAt), operation: op, typedHash: h, chainId: e.chainId });
  if (e.binding !== binding || e.keyId !== key.keyId) throw { code: 4100, message: 'unauthorized' };
  const rawSignature = await signRaw(key, h);
  return { version: 1, purpose: PURPOSE, requestId: e.id, keyId: key.keyId, codecId: CODEC_ID, commitment: c,
    binding, chainId: e.chainId, entryPoint: ENTRYPOINT, signer: e.signer, nonce: op.nonce, typedDataHash: h,
    publicPoint: key.publicKey, rawSignature, signerSignature: U.hexConcat([keyIdHash(key.keyId), rawSignature]) };
}

/**
 * SignClient double: `init()` returns a client whose single approved session answers the two methods through
 * `peer` hooks: `context()` -> wire, `sign(envelope)` -> wire (or throw). Records every call.
 */
export function nativeClient(peer) {
  const calls = [], handlers = {};
  let sessions = 0;
  const client = {
    calls, handlers, peer,
    on(event, fn) { (handlers[event] ||= []).push(fn); },
    off(event, fn) { handlers[event] = (handlers[event] || []).filter((h) => h !== fn); },
    emit(event, topic) { for (const fn of handlers[event] || []) fn({ topic }); },
    async connect(params) {
      calls.push(['connect', params]);
      const topic = `native-${++sessions}`;
      client.topic = topic;
      const session = { topic, expiry: (peer.now?.() ?? Math.floor(Date.now() / 1000)) + 3600,
        peer: { metadata: { url: peer.origin ?? ORIGIN } },
        namespaces: peer.namespaces?.() ?? { eip155: { accounts: [`eip155:137:${peer.signer.toLowerCase()}`],
          methods: [...METHODS], events: [] } } };
      return { uri: `wc:${'ab'.repeat(32)}@2?relay-protocol=irn&symKey=${'cd'.repeat(32)}`,
        approval: () => (peer.approve ? peer.approve(session) : Promise.resolve(session)) };
    },
    async disconnect({ topic }) { calls.push(['disconnect', topic]); },
    async request({ topic, chainId, request }) {
      calls.push(['request', request.method, topic, chainId]);
      if (request.method === METHODS[0]) return structuredClone(await peer.context());
      if (request.method === METHODS[1]) return structuredClone(await peer.sign(request.params[0]));
      throw { code: -32601, message: 'method not found' };
    },
  };
  return { client, SignClient: { init: async (options) => { client.options = options; return client; } } };
}
