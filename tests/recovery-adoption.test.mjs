import assert from 'node:assert/strict';
import { test } from 'node:test';
import { world, approve, k3, bareKeyText } from './support/key-world.mjs';
import { SavedResultSession } from '../recovery-session.js';
import { CODEC_ID, ENTRYPOINT, PURPOSE } from '../key-model.js';

async function setup() {
  const w = world(); await w.controller.loadAttempt(); await approve(w);
  const signed = w.controller.s.native.signed, [record] = await w.savedResultStore.list();
  const result = { version: 1, purpose: PURPOSE, requestId: signed.request.id, keyId: record.context.keyId,
    codecId: CODEC_ID, commitment: signed.request.commitment, binding: record.context.binding, chainId: '137',
    entryPoint: ENTRYPOINT, signer: record.context.signer, nonce: signed.request.operation.nonce,
    typedDataHash: signed.request.typedDataHash, publicPoint: record.context.publicKey,
    rawSignature: signed.rawSignature, signerSignature: signed.signerSignature };
  await w.controller.disconnectNative();
  const handlers = {}, methods = ['p256_getKeyChangeContext', 'p256_recoverKeyChangeResult'];
  const approved = { topic: 'review-only', expiry: w.controller.now() + 300,
    peer: { metadata: { url: record.context.origin } }, namespaces: { eip155: {
      accounts: [`eip155:137:${record.context.signer}`], methods, events: [] } } };
  const sdk = { on(n, f) { handlers[n] = f; }, off() {}, async disconnect() {},
    async connect() { return { approval: async () => approved }; },
    async request({ request }) { return request.method === methods[0]
      ? { ...await w.peer.context(), binding: '0x' + 'cc'.repeat(32) } : result; } };
  const session = new SavedResultSession(sdk, record, record.expected, () => w.controller.now());
  await session.connect(() => {});
  return { w, session, record, handlers, topic: approved.topic };
}
for (const edit of [{ bareText: bareKeyText(k3) }, { mode: 'remove' }, { feeMax: '2', feePriority: '2' }]) {
  test('changed independent input cannot adopt saved operation: ' + Object.keys(edit).join(), async () => {
    const { w, session, record } = await setup();
    try {
      w.controller.setChange(edit); await session.inspect(); const recovered = await session.recover();
      assert.equal(await w.controller.adoptRecovered(record, recovered, session), false);
      await w.controller.send(); assert.equal(w.wallet.sends.length, 0); assert.equal(w.peer.signs, 1);
    } finally { await session.dispose(); w.stop(); }
  });
}
test('unchanged semantic authority over 31 blocks uses current retrieval observation', async () => {
  const { w, session, record } = await setup();
  try {
    w.clock.offset += 62; for (let i = 0; i < 31; i++) w.chain.mine();
    await session.inspect(); const recovered = await session.recover();
    assert.equal(await w.controller.adoptRecovered(record, recovered, session), true);
    await w.controller.send(); assert.equal(w.wallet.sends.length, 1); assert.equal(w.peer.signs, 1);
  } finally { await session.dispose(); w.stop(); }
});
for (const loss of ['close', 'session_delete', 'session_expire', 'session_update', 'session_event']) {
  test('adopted recovery loses Send synchronously on ' + loss, async () => {
    const { w, session, record, handlers, topic } = await setup();
    try {
      await session.inspect(); const recovered = await session.recover();
      assert.equal(await w.controller.adoptRecovered(record, recovered, session), true);
      if (loss === 'close') void session.dispose(); else handlers[loss]({ topic });
      assert.equal(w.controller.view().actions.send, false); assert.equal(w.controller.s.native.signed, null);
      await w.controller.send(); assert.equal(w.wallet.sends.length, 0); assert.equal(w.peer.signs, 1);
      assert.deepEqual(await w.savedResultStore.list(), [record]);
    } finally { await session.dispose(); w.stop(); }
  });
}
test('fresh recovery read, not earlier inspect or historical block, gates adoption', async () => {
  const { w, session, record } = await setup();
  try {
    await session.inspect();
    w.clock.offset += 62; for (let i = 0; i < 31; i++) w.chain.mine();
    const recovered = await session.recover();
    assert.equal(await w.controller.adoptRecovered(record, recovered, session), true);
    await w.controller.send(); assert.equal(w.wallet.sends.length, 1); assert.equal(w.peer.signs, 1);
  } finally { await session.dispose(); w.stop(); }
});
test('edit then restore while asynchronous adoption runs still invalidates its generation', async () => {
  const { w, session, record } = await setup();
  try {
    await session.inspect(); const recovered = await session.recover();
    const original = w.controller.s.feeMax;
    const adopting = w.controller.adoptRecovered(record, recovered, session);
    w.controller.setChange({ feeMax: '2' }); w.controller.setChange({ feeMax: original });
    assert.equal(await adopting, false); assert.equal(w.wallet.sends.length, 0);
    assert.equal(w.controller.s.native.signed, null); assert.equal(w.peer.signs, 1);
  } finally { await session.dispose(); w.stop(); }
});
export { setup };
