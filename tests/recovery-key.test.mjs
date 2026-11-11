import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SavedResultSession } from '../recovery-session.js';
import { K1, K2, softwareKey, contextWire, nativeSign } from './support/key-fixtures.mjs';
import { PURPOSE, TOTAL_GAS, buildRequest, planChange, validateNativeContext } from '../key-model.js';
const now = 1700000030, signer = '0x' + '11'.repeat(20);
const key = softwareKey(K1), added = softwareKey(K2);
const anchor = { signerAddress: signer, keyId: key.keyId, publicKey: key.publicKey };
function fixture() {
  const context = contextWire({ signer, key, binding: '0x' + '22'.repeat(32),
    chain: { nonce: 0n, blockNumber: 100n, blockHash: '0x' + '33'.repeat(32), keys: [key] } });
  const plan = planChange({ signer, nonce: 0n, keys: [key], change: { kind: 'add', key: added },
    fees: { maxFee: 500n, priorityFee: 10n } });
  const request = buildRequest({ context: validateNativeContext(context, anchor), operation: plan.operation,
    id: '11111111-1111-1111-1111-111111111111', issuedAt: now - 30 });
  const expected = { anchor, operation: plan.operation, beforeKeys: plan.before, expectedAfterKeys: plan.after,
    maxGasUnits: TOTAL_GAS.toString(), maxFeePerGas: '500' };
  return { version: 1, purpose: PURPOSE, requestId: request.id, envelope: request.envelope, context, expected };
}
test('key recovery checks original crypto under a new binding without any new signature request', async () => {
  const record = fixture(), old = await nativeSign({ envelope: record.envelope, key, binding: record.context.binding });
  let signs = 1; const calls = [];
  const methods = ['p256_getKeyChangeContext', 'p256_recoverKeyChangeResult'];
  const session = { topic: 'new-key-topic', expiry: now + 300, peer: { metadata: { url: record.context.origin } },
    namespaces: { eip155: { accounts: [`eip155:137:${signer}`], methods, events: [] } } };
  const sdk = { on() {}, off() {}, disconnect: async () => {}, connect: async () => ({ approval: async () => session }),
    request: async (p) => {
      calls.push(p);
      if (p.request.method.includes('sign')) { signs++; throw new Error('sign forbidden'); }
      return p.request.method === methods[0] ? { ...record.context, binding: '0x' + '44'.repeat(32) } : old;
    } };
  const s = new SavedResultSession(sdk, record, record.expected, () => now);
  await s.connect(() => {}); await s.inspect();
  const got = await s.recover();
  assert.deepEqual(got.result, old);
  assert.equal(signs, 1);
  assert.deepEqual(calls.at(-1).request.params, [record.envelope]);
});
export { fixture };
