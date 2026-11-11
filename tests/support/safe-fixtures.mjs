// Shared Safe request fixture data and test-key helpers. Registers no tests: suites import only this module,
// never each other.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import ethers from '../../vendor/ethers.js';
import { RECIPE, buildPlan, parseHandoff } from '../../model.js';

const U = ethers.utils;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

// Frozen upstream transport artifact: never regenerate expected values from this implementation.
const source = process.env.SAFE_SESSION_VECTORS || new URL('../fixtures/safe-session-vectors.json', import.meta.url);
const bytes = readFileSync(source);
assert.equal(createHash('sha256').update(bytes).digest('hex'), '0de46d2bd2497c833b0aeb5bf00c16f455ea6c42fdfcfa715e89d855ff788596');
export const v = JSON.parse(bytes);
// Origin binding migrated; retain upstream signature/envelope bytes unchanged.
v.context.result.origin = 'https://tumf.github.io';
export const envelope = JSON.parse(v.request.envelope);
const c = v.context.result;
/** The vector's expected authority (its Signer is a fixture value, not a handoff-derived address). */
export const expected = Object.freeze({ origin: c.origin, safe: c.safe, signer: c.signer, publicKey: c.publicKey,
  keyId: c.keyId, recipient: envelope.body.tx.to, value: envelope.body.tx.value, nonce: envelope.body.tx.nonce });
/** Clock at which issuedAtFor() reproduces the vector's issuedAt (30 s backdating). */
export const VECTOR_CLOCK = Number(envelope.issuedAt) + 30;

const hexOf = (buffer) => '0x' + Buffer.from(buffer).toString('hex');

/** A fresh public test key (never a production key), its valid v1 handoff and a WebCrypto low-S signer. */
export async function freshSigner(salt = '0x' + '11'.repeat(32)) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicKey = hexOf(await crypto.subtle.exportKey('raw', pair.publicKey));
  const keyID = U.sha256(publicKey).slice(2);
  const draft = { version: 1, recipe: RECIPE, chainId: 137, publicKey, keyID, salt };
  const json = JSON.stringify({ ...draft, expectedAddress: buildPlan(draft).address });
  const handoff = parseHandoff(json);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  return { pair, publicKey, keyID, handoff, json, jwk,
    /** Raw 64-byte P1363 signature over H (SHA-256 applied once by WebCrypto), normalized to low S. */
    async sign(hash, { highS = false } = {}) {
      const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, U.arrayify(hash)));
      let s = BigInt(hexOf(raw.slice(32)));
      if ((s > N / 2n) !== highS) s = N - s;
      return hexOf(raw.slice(0, 32)) + s.toString(16).padStart(64, '0');
    } };
}

/** The exact closed context the iPhone would return for `expected` and a test binding. */
export function contextFor(expected, binding = '0x' + '5a'.repeat(32)) {
  return { version: 1, origin: expected.origin, chainId: '137', safe: expected.safe, signer: expected.signer,
    keyId: expected.keyId, publicKey: expected.publicKey, binding, codecId: c.codecId, purpose: c.purpose,
    maxValiditySeconds: 120, maxEnvelopeBytes: 32768 };
}

/** The closed result object for a built request, signed with `rawSignature`. */
export function resultFor(request, context, rawSignature) {
  return { version: 1, requestId: request.id, keyId: context.keyId, codecId: context.codecId,
    safeTxHash: request.safeTxHash, commitment: request.commitment, binding: context.binding,
    publicPoint: context.publicKey, rawSignature,
    signerSignature: U.hexConcat([U.keccak256(U.toUtf8Bytes(context.keyId)), rawSignature]) };
}
