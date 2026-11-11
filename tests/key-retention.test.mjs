// Controller adapter evidence only. Map storage runs the real closed-record validators;
// actual IndexedDB durability belongs to saved-result-store.test.mjs.
import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { METHODS, PURPOSE, TOTAL_GAS } from '../key-model.js';
import { SavedResultStore, StorageError } from '../saved-result-store.js';
import { KeyChangeController } from '../key-controller.js';
import { approve, world as createWorld } from './support/key-world.mjs';

const worlds = [];
const world = (options) => { const w = createWorld(options); worlds.push(w); return w; };
afterEach(() => worlds.splice(0).forEach((w) => w.stop()));
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };
const signCalls = (w) => w.native.client.calls.filter(([kind, method]) => kind === 'request' && method === METHODS[1]);

for (const [name, lose] of Object.entries({
  generation: (w) => { ++w.controller.opGen; },
  session: (w) => w.native.client.emit('session_delete', w.native.client.topic),
  anchor: (w) => w.controller.setAnchorText(w.controller.s.anchorText + ' '),
  edit: (w) => w.controller.setChange({ feeMax: '2' }),
  expected: (w) => { w.controller.s.feeMax = '2'; },
  inspection: (w) => { w.controller.s.inspection = { phase: 'idle', context: null }; },
  expiry: (w) => { w.clock.offset += 200; },
})) {
  test(`authority loss during save (${name}) leaves unsigned evidence but never signs`, async () => {
    const w = world(), entered = deferred(), commit = deferred();
    const save = w.savedResultStore.save.bind(w.savedResultStore);
    w.savedResultStore.save = async (record) => {
      entered.resolve(); await commit.promise; return save(record);
    };
    await w.controller.loadAttempt();
    const approving = approve(w);
    await Promise.race([entered.promise, approving]);
    lose(w);
    commit.resolve();
    await approving;
    assert.equal((await w.savedResultStore.list()).length, 1);
    assert.equal(signCalls(w).length, 0);
    assert.equal(w.peer.signs, 0);
    assert.equal(w.controller.s.native.signed, null);
    assert.equal(w.wallet.sends.length, 0);
  });
}

test('recovered key result enters existing explicit send flow without signing again', async () => {
  const w = world();
  await w.controller.loadAttempt();
  await approve(w);
  const signed = w.controller.s.native.signed;
  const [record] = await w.savedResultStore.list();
  const context = w.controller.s.native.context;
  await w.controller.disconnectNative();
  const session = { generation: 1, context, alive() {}, check() {}, dispose: async () => {} };
  const adopted = await w.controller.adoptRecovered(record, { request: signed.request,
    signerSignature: signed.signerSignature, rawSignature: signed.rawSignature }, session);
  assert.equal(adopted, true);
  assert.equal(w.controller.view().native.phase, 'verified');
  assert.equal(w.peer.signs, 1);
  assert.equal(w.wallet.sends.length, 0);
  assert.equal(w.controller.s.native.signed.request.envelope, record.envelope);
  await w.controller.send();
  assert.equal(w.wallet.sends.length, 1);
  assert.equal(w.peer.signs, 1);
  await w.controller.send();
  assert.equal(w.wallet.sends.length, 1);
});

test('production default is the real SavedResultStore, never a no-op', () => {
  assert.ok(new KeyChangeController({}).savedResultStore instanceof SavedResultStore);
});

for (const code of ['aborted', 'unavailable', 'durability', 'conflict', 'corrupt']) {
  test(`saved-result storage ${code} aborts the ordinary sign RPC`, async () => {
    const w = world();
    w.savedResultStore.save = async () => { throw new StorageError(code); };
    await w.controller.loadAttempt();
    await approve(w);
    assert.equal(signCalls(w).length, 0);
    assert.equal(w.peer.signs, 0);
    assert.equal(w.controller.s.native.signed, null);
    assert.equal(w.controller.view().actions.send, false);
    assert.equal(w.wallet.sends.length, 0);
    assert.equal(w.savedResultStore.rows.size, 0);
  });
}

test('unavailable native IndexedDB fails closed without the adapter seam', async () => {
  const w = world({ savedResultStore: new SavedResultStore({ indexedDB: null }) });
  await w.controller.loadAttempt(); await approve(w);
  assert.equal(signCalls(w).length, 0);
  assert.equal(w.peer.signs, 0);
  assert.equal(w.controller.s.native.signed, null);
  assert.equal(w.controller.view().actions.send, false);
});

test('unsigned retained records on reload confer no result or session authority', async () => {
  const w = world();
  await w.controller.loadAttempt(); await approve(w);
  const before = [...w.savedResultStore.rows.entries()];
  const reloaded = world({ savedResultStore: w.savedResultStore, indexedDB: w.indexedDB, chain: w.chain });
  await reloaded.controller.loadAttempt();
  await reloaded.controller.requestSignature(); await reloaded.controller.send();
  assert.deepEqual([...w.savedResultStore.rows.entries()], before);
  assert.equal(reloaded.controller.session, null);
  assert.equal(reloaded.controller.client, null);
  assert.equal(reloaded.controller.s.native.signed, null);
  assert.equal(reloaded.native.client.calls.length, 0);
  assert.equal(reloaded.peer.signs, 0);
  assert.equal(reloaded.wallet.sends.length, 0);
  assert.equal(reloaded.controller.view().actions.send, false);
});

test('exact unsigned full inputs finish saving before the ordinary sign RPC', async () => {
  const w = world();
  const entered = deferred(), commit = deferred();
  const save = w.savedResultStore.save.bind(w.savedResultStore);
  let wire, retained;
  const context = w.peer.context;
  w.peer.context = async () => {
    if (w.peer.contexts === 1) w.chain.mine();
    return (wire = await context());
  };
  w.savedResultStore.save = async (record) => {
    retained = record;
    entered.resolve();
    await commit.promise;
    return save(record);
  };
  await w.controller.loadAttempt();
  const approving = approve(w);
  await Promise.race([entered.promise, approving]);
  assert.ok(retained, 'the signing prepare callback must save first');
  assert.equal(signCalls(w).length, 0);
  assert.equal(w.peer.signs, 0);
  assert.equal(w.savedResultStore.rows.size, 0, 'pending storage is not a commit');
  assert.deepEqual(retained.context, wire, 'retain every validated wire field unchanged');
  const planned = w.controller.plan().plan;
  assert.deepEqual(retained.expected, {
    anchor: { signerAddress: w.controller.s.anchor.signerAddress, keyId: w.controller.s.anchor.keyId,
      publicKey: w.controller.s.anchor.publicKey },
    operation: planned.operation, beforeKeys: planned.before, expectedAfterKeys: planned.after,
    maxGasUnits: TOTAL_GAS.toString(), maxFeePerGas: '1000000000',
  });
  assert.equal(retained.version, 1);
  assert.equal(retained.purpose, PURPOSE);
  assert.equal(JSON.parse(retained.envelope).id, retained.requestId);
  assert.equal(retained.expected.operation.signature, '0x');
  commit.resolve();
  await approving;
  assert.equal(w.controller.view().native.phase, 'verified');
  assert.equal(signCalls(w).length, 1);
  const [saved] = await w.savedResultStore.list();
  assert.equal(saved.envelope, w.controller.s.native.signed.request.envelope);
  assert.deepEqual(saved, retained);
  for (const forbidden of ['rawSignature', 'signerSignature', 'topic', 'rpcId', 'grant', 'uri']) {
    assert.equal(JSON.stringify(saved).includes(`"${forbidden}"`), false, forbidden);
  }
});
