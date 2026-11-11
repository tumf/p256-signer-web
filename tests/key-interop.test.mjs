// Fresh Swift interoperability: consumes the outputs that `scripts/verify.py --key-change-web` regenerates in the
// same run from the production HybridKeyChangeCompiler (testFrozenRuntimeAgreement) and HybridKeyApprovalLedger
// (testConsentAndPersistedReplay) XCTests, and recomputes calldata, H, commitment and the verified signature with the
// Web key-model. Missing, stale or foreign outputs FAIL (never skip). Software keys; not device or EVM evidence.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import * as M from '../key-model.js';

const RUN = process.env.KEY_SWIFT_RUN_ID;
const load = (variable) => {
  assert.ok(RUN && process.env[variable], `${variable} and KEY_SWIFT_RUN_ID are required (run through verify.py)`);
  const data = JSON.parse(readFileSync(process.env[variable]));
  assert.equal(data.runID, RUN, `${variable} is not from this run`);
  return data;
};
const frozen = JSON.parse(readFileSync(new URL('./fixtures/key-swift-vectors.json', import.meta.url)));
const dec = (h) => BigInt(h).toString();
const opOf = (v) => ({ sender: v.sender, nonce: dec(v.nonce), initCode: v.initCode, callData: v.callData,
  accountGasLimits: v.accountGasLimits, preVerificationGas: dec(v.preVerificationGas), gasFees: v.gasFees,
  paymasterAndData: v.paymasterAndData, signature: '0x' });

test('fresh compiler vectors: Web calldata and H equal Swift, and equal the frozen copy', () => {
  const fresh = load('KEY_SWIFT_COMPILER_OUT');
  assert.equal(fresh.vectorCount, fresh.vectors.length);
  assert.ok(fresh.vectors.length >= 4);
  for (const v of fresh.vectors) {
    const point = '0x04' + v.x.slice(2) + v.y.slice(2);
    assert.equal(M.executeCall(v.sender, v.action === 'add' ? M.addKeyCall(point, v.keyID) : M.removeKeyCall(v.keyID)),
      v.callData, v.name);
    assert.equal(M.typedDataHash(opOf(v)), v.typedDataHash, v.name);
  }
  assert.deepEqual(fresh.vectors, frozen.compiler);
});

test('fresh ledger rows: Web commitment, H and WebCrypto verification agree; negatives are refused', async () => {
  const fresh = load('KEY_SWIFT_APPROVAL_OUT');
  assert.equal(fresh.purpose, M.PURPOSE);
  assert.equal(fresh.codecID, M.CODEC_ID);
  assert.ok(fresh.rows.length >= 2);
  const f = frozen.approvalFixture;
  for (const r of fresh.rows) {
    const operation = opOf(r), typedHash = M.typedDataHash(operation);
    assert.equal(typedHash, r.typedDataHash, r.name);
    const commitment = M.commitment({ id: r.requestID, keyId: r.keyID, binding: f.binding, issuedAt: f.issuedAt,
      expiresAt: f.expiresAt, operation, typedHash });
    assert.equal(commitment, r.commitment, r.name);
    const publicKey = '0x04' + r.x.slice(2) + r.y.slice(2);
    assert.equal(M.keyIdOf(publicKey), r.keyID);
    assert.equal(M.keyIdHash(r.keyID), r.keyIDHash);
    const request = { id: r.requestID, issuedAt: f.issuedAt, expiresAt: f.expiresAt, commitment, typedDataHash: typedHash,
      operation };
    const context = { keyId: r.keyID, binding: f.binding, signer: r.sender, publicKey };
    const result = (signature) => ({ version: 1, purpose: M.PURPOSE, requestId: r.requestID, keyId: r.keyID,
      codecId: M.CODEC_ID, commitment, binding: f.binding, chainId: '137', entryPoint: M.ENTRYPOINT, signer: r.sender,
      nonce: operation.nonce, typedDataHash: typedHash, publicPoint: publicKey, rawSignature: '0x' + signature.slice(66),
      signerSignature: signature });
    assert.equal(await M.verifyResult(result(r.signature), request, context, f.issuedAt + 10), r.signature, r.name);
    assert.equal(r.replayed, r.signature);
    for (const bad of ['highS', 'doubleHashed', 'wrongKey']) {
      await assert.rejects(M.verifyResult(result(r[bad]), request, context, f.issuedAt + 10), M.KeyError, `${r.name} ${bad}`);
    }
  }
});
