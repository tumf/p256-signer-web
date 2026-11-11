// Independent strict v3 result validator for the browser bridge (docs/public-defi-spec-v1.md §2.1.1, result).
//
// Written separately from the Swift SafeDeFiResultCodec. It accepts exactly the same closed eleven-field object of
// canonical strings, compares every metadata field to values derived from the independently compiled candidate (never
// from the result's own claims), checks the public point against the candidate keyId (SHA-256 of the SEC1 point; no
// attempt is made to derive a point from a hash), keyIDHash = Keccak256(UTF8(keyId text)), signerSignature r||s ==
// rawSignature, low-S, and ECDSA P-256 over SHA-256(H), where H = candidate.signedDigest is the signing message.
// P-256 arithmetic is native BigInt. It never signs, stores, logs or retries, and errors carry only a fixed code.
import { bytesToHex, hexToBytes, keccak, parseJSON } from './defi-v3.js';

export const RESULT_FIELDS = Object.freeze(['v', 'purpose', 'requestId', 'keyId', 'codecId', 'binding', 'commitment',
  'signedDigest', 'publicPoint', 'rawSignature', 'signerSignature']);
export const MAX_RESULT_BYTES = 16 * 1024;

export class V3ResultError extends Error {
  constructor(code) {
    super(`v3 result rejected: ${code}`);
    this.name = 'V3ResultError';
    this.code = code;
  }
}

const fail = (code) => { throw new V3ResultError(code); };

// ---------- P-256 (secp256r1) ----------

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const A = P - 3n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const G = Object.freeze({
  x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
});
const HALF_N = N >> 1n;

const mod = (a, m) => { const r = a % m; return r >= 0n ? r : r + m; };

function inverse(a, m) {
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new V3ResultError('INVALID_SIGNATURE');
  return mod(s0, m);
}

function onCurve(pt) {
  return pt.x < P && pt.y < P && mod(pt.y * pt.y - (pt.x * pt.x * pt.x + A * pt.x + B), P) === 0n;
}

function add(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  let lambda;
  if (p1.x === p2.x) {
    if (mod(p1.y + p2.y, P) === 0n) return null;
    lambda = mod((3n * p1.x * p1.x + A) * inverse(2n * p1.y, P), P);
  } else {
    lambda = mod((p2.y - p1.y) * inverse(p2.x - p1.x, P), P);
  }
  const x = mod(lambda * lambda - p1.x - p2.x, P);
  return { x, y: mod(lambda * (p1.x - x) - p1.y, P) };
}

export function multiply(k, pt) {
  let result = null;
  let addend = pt;
  for (let n = k; n > 0n; n >>= 1n) {
    if (n & 1n) result = add(result, addend);
    addend = add(addend, addend);
  }
  return result;
}

export const P256 = Object.freeze({ N, G, HALF_N });

const toBig = (bytes) => BigInt(bytesToHex(bytes));

/** ECDSA P-256 verification of (r, s) over the 32-byte message `h` used directly as e. Low-S is enforced. */
export function verifyP256(publicPoint, h, r, s) {
  if (!(publicPoint instanceof Uint8Array) || publicPoint.length !== 65 || publicPoint[0] !== 0x04) {
    fail('INVALID_PUBLIC_KEY');
  }
  if (!(h instanceof Uint8Array) || h.length !== 32) fail('UNSUPPORTED_CANDIDATE');
  const q = { x: toBig(publicPoint.slice(1, 33)), y: toBig(publicPoint.slice(33)) };
  if (!onCurve(q)) fail('INVALID_PUBLIC_KEY');
  if (r <= 0n || r >= N || s <= 0n || s >= N) fail('INVALID_SIGNATURE');
  const e = toBig(h);
  const w = inverse(s, N);
  const point = add(multiply(mod(e * w, N), G), multiply(mod(r * w, N), q));
  if (point === null || mod(point.x, N) !== r) fail('INVALID_SIGNATURE');
  if (s > HALF_N) fail('HIGH_S');
  return true;
}

// ---------- closed structure ----------

const LOWER_HEX = /^0x(?:[0-9a-f]{2})*$/;

/** Copies an SDK structured result (or JSON text) into a frozen null-prototype object of own data strings. */
export function copyResult(value) {
  let source = value;
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    if (bytes.length > MAX_RESULT_BYTES) fail('OVERSIZE');
    // The strict lossless parser rejects duplicate member names, BOMs and malformed text.
    let root;
    try { root = parseJSON(bytes); } catch { fail('MALFORMED'); }
    if (root.t !== 'object') fail('MALFORMED');
    source = {};
    for (const [key, node] of root.members) {
      if (node.t !== 'string') fail('NON_STRING_FIELD');
      Object.defineProperty(source, key, { value: node.v, enumerable: true });
    }
  }
  if (typeof source !== 'object' || source === null || Array.isArray(source)) fail('MALFORMED');
  const proto = Object.getPrototypeOf(source);
  if (proto !== Object.prototype && proto !== null) fail('MALFORMED');
  if (Object.getOwnPropertySymbols(source).length) fail('UNKNOWN_FIELD');
  const descriptors = Object.getOwnPropertyDescriptors(source);
  const keys = Object.keys(descriptors);
  for (const key of keys) if (!RESULT_FIELDS.includes(key)) fail('UNKNOWN_FIELD');
  for (const key of RESULT_FIELDS) if (!(key in descriptors)) fail('MISSING_FIELD');
  const out = Object.create(null);
  let size = 2;
  for (const key of RESULT_FIELDS) {
    const d = descriptors[key];
    if (!('value' in d) || typeof d.value !== 'string') fail('NON_STRING_FIELD');
    if (!/^[\x20-\x7e]*$/.test(d.value)) fail('NON_STRING_FIELD');
    size += key.length + d.value.length + 6;
    out[key] = d.value;
  }
  if (size > MAX_RESULT_BYTES) fail('OVERSIZE');
  return Object.freeze(out);
}

function expectedMetadata(candidate) {
  const c = candidate ?? fail('UNSUPPORTED_CANDIDATE');
  const hex32 = (v) => (typeof v === 'string' && LOWER_HEX.test(v) && v.length === 66 ? v : fail('UNSUPPORTED_CANDIDATE'));
  if (c.v !== '3' || typeof c.purpose !== 'string' || typeof c.codecId !== 'string'
      || typeof c.requestId !== 'string' || !/^[0-9a-f]{64}$/.test(c.keyId ?? '')) fail('UNSUPPORTED_CANDIDATE');
  return [c.v, c.purpose, c.requestId, c.keyId, c.codecId, hex32(c.binding), hex32(c.commitment),
    hex32(c.signedDigest)];
}

/**
 * Verifies `value` (SDK structured result or JSON text) against the complete independently compiled `candidate`
 * ({v, purpose, requestId, keyId, codecId, binding, commitment, signedDigest}; hex strings lowercase 0x, keyId bare).
 * `sha256` is caller-supplied (bytes => bytes). Returns the frozen copy; throws V3ResultError with a fixed code.
 */
export function verifyV3Result(value, candidate, { sha256 }) {
  if (typeof sha256 !== 'function') fail('UNSUPPORTED_CANDIDATE');
  const expected = expectedMetadata(candidate);
  const result = copyResult(value);
  RESULT_FIELDS.slice(0, 8).forEach((field, i) => {
    if (result[field] !== expected[i]) fail(`METADATA_MISMATCH:${field}`);
  });
  const bytes = (field, length) => {
    const text = result[field];
    if (!LOWER_HEX.test(text) || text.length !== 2 + length * 2) fail(`INVALID_ENCODING:${field}`);
    return hexToBytes(text);
  };
  const point = bytes('publicPoint', 65);
  if (point[0] !== 0x04) fail('INVALID_ENCODING:publicPoint');
  const raw = bytes('rawSignature', 64);
  const signerSignature = bytes('signerSignature', 96);
  if (bytesToHex(signerSignature.slice(0, 32)) !== bytesToHex(keccak(new TextEncoder().encode(candidate.keyId)))) {
    fail('KEY_ID_HASH_MISMATCH');
  }
  if (bytesToHex(signerSignature.slice(32)) !== bytesToHex(raw)) fail('SIGNATURE_MISMATCH');
  if (bytesToHex(sha256(point)) !== '0x' + candidate.keyId) fail('IDENTITY_MISMATCH');
  // CryptoKit signs H as a message: ECDSA verifies SHA-256(H), not the raw Safe hash.
  verifyP256(point, sha256(hexToBytes(candidate.signedDigest)), toBig(raw.slice(0, 32)), toBig(raw.slice(32)));
  return result;
}
