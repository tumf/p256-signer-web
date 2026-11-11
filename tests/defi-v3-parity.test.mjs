import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { computeRequest, bytesToHex } from '../defi-v3.js';

// One shared, nonsecret fixture: both browser and phone must recompute the same v3 operation.
test('browser v3 SafeTx matches the Swift fixture', () => {
  const vector = JSON.parse(readFileSync(new URL('fixtures/DeFiV3/web-swift-safe-tx.json', import.meta.url)));
  const wire = new TextEncoder().encode(vector.wire);
  const sha256 = (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest());
  const result = computeRequest(wire, sha256);
  assert.equal(bytesToHex(result.signedDigest), vector.signedDigest);
  assert.equal(bytesToHex(result.commitment), vector.commitment);
});
