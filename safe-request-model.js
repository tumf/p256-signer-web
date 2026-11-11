// Closed Hybrid v2 native-transfer profile. No caller-supplied hash, calldata or codec.
// The expected authority comes from a verified public registration handoff (which names exactly one closed chain)
// plus independently entered Safe/recipient/value/nonce; nothing returned by the peer can widen or replace it. The
// chain binds the session namespace, the context, the Safe EIP-712 domain, the commitment and the envelope body.
import ethers from './vendor/ethers.js';
import { ORIGIN, handoffChain } from './model.js';
import { POLYGON, chainOf } from './chains.js';

export { ORIGIN };
const U = ethers.utils;
/** The legacy default chain of an `expected` authority without its own `chainId` (Polygon). */
export const CHAIN = POLYGON.caip2;
export const METHODS = ['p256_getSessionContext', 'p256_signSafeRequest'];
export const VALIDITY_SECONDS = 120;
// Bounded forward clock skew: the iPhone requires issuedAt <= its now. expiresAt stays issuedAt + 120.
export const CLOCK_SKEW_SECONDS = 30;
const CODEC = 'hybrid-delegator-1.3.0/raw-p256-msg/v1', PURPOSE = 'safe-tx-v1.5.0';
const ZERO = '0x' + '00'.repeat(20), utf8 = U.toUtf8Bytes;
const UINT256 = 1n << 256n;
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const fail = () => { throw new Error('Safe request validation failed'); };
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) fail();
}
function hex(value, bytes) {
  if (typeof value !== 'string' || !new RegExp(`^0x[0-9a-f]{${bytes * 2}}$`).test(value)) fail();
  return value;
}
function address(value) {
  try { const a = U.getAddress(value); if (a === ZERO) fail(); return a.toLowerCase(); } catch { fail(); }
}
function uint(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value) || value.length > 78 || BigInt(value) >= UINT256) fail();
  return value;
}
const word = (n, size = 32) => U.zeroPad(U.arrayify(U.hexlify(BigInt(n))), size);
const keys = ['version', 'origin', 'chainId', 'safe', 'signer', 'keyId', 'publicKey', 'binding',
  'codecId', 'purpose', 'maxValiditySeconds', 'maxEnvelopeBytes'];
const types = { SafeTx: [['to', 'address'], ['value', 'uint256'], ['data', 'bytes'], ['operation', 'uint8'],
  ['safeTxGas', 'uint256'], ['baseGas', 'uint256'], ['gasPrice', 'uint256'], ['gasToken', 'address'],
  ['refundReceiver', 'address'], ['nonce', 'uint256']].map(([name, type]) => ({ name, type })) };

export const INPUT_MESSAGES = {
  safe: 'Safeアドレスは0x+40桁（大文字小文字混在はEIP-55チェックサム）の非ゼロアドレスで入力してください。',
  recipient: '送金先は0x+40桁（大文字小文字混在はEIP-55チェックサム）の非ゼロアドレスで入力してください。',
  value: '金額は0以上の整数のwei（先頭0なし、10進数）で入力してください。',
  nonce: 'Safe nonceは0以上の整数（先頭0なし、10進数）で入力してください。',
  same: 'SafeアドレスとSignerアドレスは別のアドレスである必要があります。',
};
class InputError extends Error {
  constructor(field) { super(INPUT_MESSAGES[field]); this.field = field; }
}

/**
 * Expected authority from a parseHandoff() result and the four independent text inputs. A non-Polygon handoff adds
 * its own `chainId`; a Polygon authority keeps the legacy shape (no `chainId`), so earlier saved records still match.
 */
export function expectedFrom(handoff, input) {
  const pick = (field, check) => { try { return check(String(input[field] ?? '').trim()); } catch { throw new InputError(field); } };
  const safe = pick('safe', address), recipient = pick('recipient', address);
  const value = pick('value', uint), nonce = pick('nonce', uint);
  if (safe === address(handoff.expectedAddress)) throw new InputError('same');
  const chain = handoffChain(handoff);
  return Object.freeze({ origin: ORIGIN, safe: U.getAddress(safe), signer: handoff.expectedAddress,
    publicKey: handoff.publicKey, keyId: handoff.keyID, recipient: U.getAddress(recipient), value, nonce,
    ...(chain === POLYGON ? {} : { chainId: chain.decimal }) });
}

/** The one closed chain of an expected authority: its own `chainId`, or Polygon for the legacy shape. */
export function expectedChain(expected) {
  if (!expected || !('chainId' in expected)) return POLYGON;
  const chain = chainOf(expected.chainId);
  if (!chain || chain === POLYGON) fail();
  return chain;
}

export function validateContext(c, expected) {
  exact(c, keys);
  if (expected.origin !== ORIGIN || c.origin !== ORIGIN || c.version !== 1 || c.chainId !== expectedChain(expected).decimal
      || c.codecId !== CODEC || c.purpose !== PURPOSE || c.maxValiditySeconds !== VALIDITY_SECONDS
      || c.maxEnvelopeBytes !== 32768 || address(c.safe) !== address(expected.safe)
      || address(c.signer) !== address(expected.signer) || address(c.safe) === address(c.signer)
      || c.publicKey !== expected.publicKey || c.keyId !== expected.keyId
      || c.keyId !== U.sha256(hex(c.publicKey, 65)).slice(2) || !c.publicKey.startsWith('0x04')) fail();
  hex(c.binding, 32);
  return Object.freeze({ ...c });
}

/** The complete planned native transfer and its Safe EIP-712 hash; independent of request ID and time. */
export function transaction(expected) {
  // Native-currency transfer only (POL on Polygon, ETH elsewhere); a token or call profile needs its own reviewed change.
  const chain = expectedChain(expected);
  const tx = Object.freeze({ to: address(expected.recipient), value: uint(expected.value), data: '0x', operation: '0',
    safeTxGas: '0', baseGas: '0', gasPrice: '0', gasToken: ZERO, refundReceiver: ZERO, nonce: uint(expected.nonce) });
  const body = Object.freeze({ chainId: chain.decimal, safe: address(expected.safe), tx });
  const safeTxHash = U._TypedDataEncoder.hash({ chainId: chain.id, verifyingContract: body.safe }, types, tx);
  return Object.freeze({ body, safeTxHash });
}

export const issuedAtFor = (now) => Math.max(0, now - CLOCK_SKEW_SECONDS);

export function buildRequest(c, expected, id, issuedAt) {
  validateContext(c, expected);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) || !Number.isSafeInteger(issuedAt)
      || issuedAt < 0 || issuedAt + VALIDITY_SECONDS > Number.MAX_SAFE_INTEGER) fail();
  const expiresAt = issuedAt + VALIDITY_SECONDS;
  const { body, safeTxHash } = transaction(expected), tx = body.tx;
  const e = { v: '2', id, purpose: PURPOSE, codecId: CODEC, keyId: c.keyId, binding: c.binding,
    issuedAt: String(issuedAt), expiresAt: String(expiresAt), body, signer: address(expected.signer) };
  const fields = [utf8(e.v), utf8(PURPOSE), utf8(CODEC), U.arrayify('0x' + id.replaceAll('-', '')),
    U.arrayify('0x' + c.keyId), U.arrayify(c.binding), word(issuedAt, 8), word(expiresAt, 8),
    word(expectedChain(expected).id),
    U.arrayify(body.safe), U.arrayify(tx.to), word(tx.value), U.arrayify(tx.data), word(tx.operation, 1),
    word(tx.safeTxGas), word(tx.baseGas), word(tx.gasPrice), U.arrayify(ZERO), U.arrayify(ZERO),
    word(tx.nonce), U.arrayify(safeTxHash), U.arrayify(e.signer)];
  const commitmentPreimage = U.hexlify(U.concat([utf8('p256-signer/safe-request/v2\0'),
    ...fields.flatMap((f) => [word(f.length, 4), f])]));
  const envelope = JSON.stringify(e);
  if (utf8(envelope).length > 32768) fail();
  return Object.freeze({ envelope, safeTxHash, commitmentPreimage, commitment: U.sha256(commitmentPreimage),
    id, issuedAt, expiresAt });
}

export async function verifyResult(result, request, context, expected, now) {
  validateContext(context, expected);
  const rebuilt = buildRequest(context, expected, request.id, request.issuedAt);
  if (!Number.isSafeInteger(now) || now < request.issuedAt || now >= request.expiresAt
      || JSON.stringify(rebuilt) !== JSON.stringify(request)) fail();
  exact(result, ['version', 'requestId', 'keyId', 'codecId', 'safeTxHash', 'commitment', 'binding',
    'publicPoint', 'rawSignature', 'signerSignature']);
  if (result.version !== 1 || result.requestId !== request.id || result.keyId !== context.keyId
      || result.codecId !== CODEC || result.safeTxHash !== request.safeTxHash
      || result.commitment !== request.commitment || result.binding !== context.binding
      || result.publicPoint !== context.publicKey) fail();
  const raw = hex(result.rawSignature, 64), r = BigInt('0x' + raw.slice(2, 66)), s = BigInt('0x' + raw.slice(66));
  if (r <= 0n || r >= order || s <= 0n || s > order / 2n) fail();
  const encoded = U.hexConcat([U.keccak256(utf8(context.keyId)), raw]);
  if (hex(result.signerSignature, 96) !== encoded) fail();
  const key = await crypto.subtle.importKey('raw', U.arrayify(context.publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  // WebCrypto hashes raw H once, exactly like CryptoKit/Security. Not SHA256(H) as input.
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, U.arrayify(raw), U.arrayify(request.safeTxHash))) fail();
  return encoded;
}
