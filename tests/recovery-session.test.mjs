// Scripted SDK transport plus real WebCrypto; no relay or physical signer evidence.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SavedResultSession } from '../recovery-session.js';
import { expected, v, VECTOR_CLOCK } from './support/safe-fixtures.mjs';
const record = () => ({ version: 1, purpose: 'safe-tx-v1.5.0', requestId: v.request.id ?? JSON.parse(v.request.envelope).id,
  envelope: v.request.envelope, context: structuredClone(v.context.result), expected: structuredClone(expected) });
function peer() {
  const calls = [], handlers = {};
  const methods = ['p256_getSessionContext', 'p256_recoverSafeResult'];
  const session = { topic: 'fresh-topic', expiry: VECTOR_CLOCK + 300,
    peer: { metadata: { url: expected.origin } }, namespaces: { eip155: {
      accounts: [`eip155:137:${expected.signer}`], methods, events: [] } } };
  const sdk = { calls, handlers, session,
    on: (name, f) => { handlers[name] = f; }, off: (name) => { delete handlers[name]; },
    connect: async (p) => { calls.push(p); return { uri: 'wc:fixture', approval: async () => session }; },
    disconnect: async () => {},
    reply: async (p) => p.request.method === methods[0]
      ? { ...v.context.result, binding: '0x' + '77'.repeat(32) } : structuredClone(v.result.result),
    request: async (p) => { calls.push(p); return sdk.reply(p); } };
  return sdk;
}
test('new recovery-only grant returns original bytes with old binding; never signs', async () => {
  const sdk = peer(), r = record();
  const s = new SavedResultSession(sdk, r, r.expected, () => VECTOR_CLOCK);
  await s.connect(() => {});
  assert.equal(sdk.calls.length, 1);
  assert.deepEqual(sdk.calls[0].requiredNamespaces.eip155.methods,
    ['p256_getSessionContext', 'p256_recoverSafeResult']);
  await s.inspect();
  assert.equal(sdk.calls.length, 2);
  const recovered = await s.recover();
  assert.deepEqual(recovered.result, v.result.result);
  assert.equal(recovered.result.binding, r.context.binding);
  assert.equal(sdk.calls.at(-1).request.method, 'p256_recoverSafeResult');
  assert.deepEqual(sdk.calls.at(-1).request.params, [r.envelope]);
  assert.equal(sdk.calls.at(-1).topic, 'fresh-topic');
  assert.ok(sdk.calls.every((c) => !c.request?.method.includes('sign')));
  await assert.rejects(s.recover());
});
test('current binding cannot replace historical result binding', async () => {
  const sdk = peer(), r = record(), reply = sdk.reply;
  sdk.reply = async (p) => p.request.method.includes('recover')
    ? { ...v.result.result, binding: '0x' + '77'.repeat(32) } : reply(p);
  const s = new SavedResultSession(sdk, r, r.expected, () => VECTOR_CLOCK);
  await s.connect(() => {}); await s.inspect();
  await assert.rejects(s.recover());
});
test('lost authority during reply releases no signature', async () => {
  const sdk = peer(), r = record(), reply = sdk.reply;
  let resolve;
  sdk.reply = (p) => p.request.method.includes('recover') ? new Promise((r) => { resolve = r; }) : reply(p);
  const s = new SavedResultSession(sdk, r, r.expected, () => VECTOR_CLOCK);
  await s.connect(() => {}); await s.inspect();
  const pending = s.recover();
  await new Promise(setImmediate);
  sdk.handlers.session_delete({ topic: sdk.session.topic });
  resolve(v.result.result);
  await assert.rejects(pending);
});
test('ordinary namespace, corrupt record and changed independent input refuse before recovery RPC', async () => {
  for (const mutation of ['namespace', 'record', 'input']) {
    const sdk = peer(), r = record(), independent = structuredClone(r.expected);
    if (mutation === 'namespace') sdk.session.namespaces.eip155.methods[1] = 'p256_signSafeRequest';
    if (mutation === 'record') r.envelope += ' ';
    if (mutation === 'input') independent.nonce = '99';
    await assert.rejects(async () => {
      const s = new SavedResultSession(sdk, r, independent, () => VECTOR_CLOCK);
      await s.connect(() => {}); await s.inspect(); await s.recover();
    });
    assert.ok(!sdk.calls.some((p) => p.request?.method.includes('recover')));
  }
});
