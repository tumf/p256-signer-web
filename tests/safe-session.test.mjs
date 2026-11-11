// SafeSession against a scripted SignClient double (EngineTypes connect/request/disconnect and session events).
// Adapter/state evidence only: no relay, iPhone or Secure Enclave is exercised.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SafeSession } from '../safe-session.js';
import { SavedResultStore, StorageError, serializeRecord, parseRecord } from '../saved-result-store.js';
import { CHAIN, METHODS } from '../safe-request-model.js';
import { VECTOR_CLOCK, envelope, expected, v } from './support/safe-fixtures.mjs';

const clock = () => VECTOR_CLOCK;
const tick = () => new Promise((resolve) => setImmediate(resolve));

function peer() {
  const handlers = {}, calls = [];
  const session = { topic: 'test-topic', expiry: 2000000000, peer: { metadata: { url: expected.origin } },
    namespaces: { eip155: { accounts: [`${CHAIN}:${expected.signer}`], methods: [...METHODS], events: [] } } };
  const sdk = { session, calls, handlers,
    reply: (p) => (p.request.method === METHODS[0] ? structuredClone(v.context.result) : structuredClone(v.result.result)),
    on: (event, fn) => { (handlers[event] ||= []).push(fn); },
    off: (event, fn) => { handlers[event] = (handlers[event] || []).filter((h) => h !== fn); },
    emit: (event, payload) => { for (const fn of handlers[event] || []) fn(payload); },
    connect: async (params) => { calls.push(['connect', params]); return { uri: 'wc:test', approval: async () => session }; },
    disconnect: async (params) => { calls.push(['disconnect', params]); },
    request: async (params) => { calls.push(['request', params]); return sdk.reply(params); } };
  return sdk;
}
const methods = (sdk) => sdk.calls.filter(([kind]) => kind === 'request').map(([, p]) => p.request.method);
// Explicit non-durable test implementation. Production IndexedDB durability is covered separately.
class MemoryRecords {
  constructor(beforeCommit = async () => {}) { this.rows = new Map(); this.beforeCommit = beforeCommit; }
  async save(record) {
    const raw = serializeRecord(record), key = JSON.stringify([record.purpose, record.requestId]);
    await this.beforeCommit();
    if (this.rows.has(key) && this.rows.get(key) !== raw) throw new StorageError('conflict');
    this.rows.set(key, raw);
    return parseRecord(raw);
  }
  list() { return [...this.rows.values()].map(parseRecord); }
}
async function inspected(sdk = peer(), changed = () => {}, store = new MemoryRecords()) {
  const s = new SafeSession(sdk, expected, clock, changed, store);
  await s.connect(() => {});
  await s.inspect();
  return s;
}

test('connect requests exactly eip155:137 with the two methods and no events; inspect is a separate call', async () => {
  const sdk = peer(), s = new SafeSession(sdk, expected, clock), shown = [];
  await s.connect((uri) => shown.push(uri));
  assert.deepEqual(shown, ['wc:test']);
  assert.deepEqual(sdk.calls, [['connect', { requiredNamespaces: { eip155: { chains: [CHAIN], methods: METHODS, events: [] } } }]]);
  const context = await s.inspect();
  assert.deepEqual(context, v.context.result);
  assert.deepEqual(sdk.calls[1], ['request', { topic: 'test-topic', chainId: CHAIN, request: { method: METHODS[0], params: [] } }]);
  assert.deepEqual(methods(sdk), [METHODS[0]]);
});

test('explicit sign re-reads context, sends one exact envelope, verifies the reply and cannot repeat', async () => {
  const sdk = peer(), s = await inspected(sdk);
  const result = await s.sign(envelope.id);
  assert.deepEqual(result, { requestId: envelope.id, safeTxHash: v.request.safeTxHash, signerSignature: v.result.result.signerSignature });
  assert.deepEqual(methods(sdk), [METHODS[0], METHODS[0], METHODS[1]]);
  assert.deepEqual(sdk.calls.at(-1), ['request', { topic: 'test-topic', chainId: CHAIN,
    request: { method: METHODS[1], params: [v.request.envelope] } }]);
  await assert.rejects(s.sign(envelope.id));
  await assert.rejects(s.inspect());
  assert.equal(methods(sdk).length, 3);
});

test('unsigned exact record commits before the sign RPC and never contains a signature or result', async () => {
  let commit;
  const store = new MemoryRecords(() => new Promise((resolve) => { commit = resolve; }));
  const sdk = peer(), s = await inspected(sdk, () => {}, store), reply = sdk.reply;
  const record = { version: 1, purpose: 'safe-tx-v1.5.0', requestId: envelope.id,
    envelope: v.request.envelope, context: v.context.result, expected };
  sdk.reply = (p) => {
    if (p.request.method === METHODS[1]) assert.deepEqual(store.list(), [record]);
    return reply(p);
  };
  const pending = s.sign(envelope.id);
  pending.catch(() => {});
  await tick();
  assert.deepEqual(methods(sdk), [METHODS[0], METHODS[0]]);
  assert.deepEqual(store.list(), []);
  assert.equal(typeof commit, 'function');
  commit();
  const result = await pending;
  assert.equal(result.signerSignature, v.result.result.signerSignature);
  assert.deepEqual(store.list(), [record]);
  assert.equal(JSON.stringify(store.list()).includes(result.signerSignature), false);
});

test('authority loss while retaining unsigned evidence prevents the sign RPC', async () => {
  const changes = {
    topic: async (sdk) => { sdk.session.topic = 'replacement-topic'; },
    account: async (sdk) => { sdk.session.namespaces.eip155.accounts = [`${CHAIN}:${expected.safe}`]; },
    expired: async (sdk) => { sdk.session.expiry = VECTOR_CLOCK; },
    close: async (sdk, s) => { await s.close(); },
    ...Object.fromEntries(['session_update', 'session_event', 'session_delete', 'session_expire'].map((event) =>
      [event, async (sdk) => { sdk.emit(event, { topic: 'test-topic' }); }])),
  };
  for (const [name, change] of Object.entries(changes)) {
    let commit;
    const store = new MemoryRecords(() => new Promise((resolve) => { commit = resolve; }));
    const sdk = peer(), s = await inspected(sdk, () => {}, store);
    const pending = s.sign(envelope.id);
    await tick();
    assert.equal(typeof commit, 'function', name);
    await change(sdk, s);
    commit();
    await assert.rejects(pending, /Safe session unavailable or changed/, name);
    assert.deepEqual(methods(sdk), [METHODS[0], METHODS[0]], name);
    assert.equal(store.list().length, 1, name); // Lost permission does not delete unsigned evidence.
    await assert.rejects(s.sign(envelope.id), name);
  }
});

test('original request expiry during unsigned storage prevents the sign RPC', async () => {
  let commit, now = VECTOR_CLOCK;
  const store = new MemoryRecords(() => new Promise((resolve) => { commit = resolve; }));
  const sdk = peer(), s = new SafeSession(sdk, expected, () => now, () => {}, store);
  await s.connect(() => {});
  await s.inspect();
  const pending = s.sign(envelope.id);
  pending.catch(() => {});
  await tick();
  assert.equal(typeof commit, 'function');
  now = Number(envelope.expiresAt);
  commit();
  await assert.rejects(pending);
  assert.deepEqual(methods(sdk), [METHODS[0], METHODS[0]]);
  assert.equal(store.list().length, 1);
});

test('storage rejection or abort closes the operation before any sign RPC', async () => {
  for (const code of ['unavailable', 'aborted']) {
    const failure = new StorageError(code), causes = [];
    const store = new MemoryRecords(async () => { throw failure; });
    const sdk = peer(), s = await inspected(sdk, (cause) => causes.push(cause), store);
    await assert.rejects(s.sign(envelope.id), (error) => error === failure);
    assert.deepEqual(methods(sdk), [METHODS[0], METHODS[0]], code);
    assert.deepEqual(store.list(), [], code);
    assert.deepEqual(causes, [failure], code);
    assert.equal(sdk.calls.at(-1)[0], 'disconnect', code);
    await assert.rejects(s.sign(envelope.id), code);
  }
});

test('four-argument constructor uses a real store and unavailable IndexedDB prevents signing', async () => {
  const sdk = peer(), s = new SafeSession(sdk, expected, clock, () => {});
  assert.ok(s.store instanceof SavedResultStore);
  assert.equal(globalThis.indexedDB, undefined, 'Node test has no native IndexedDB');
  await s.connect(() => {});
  await s.inspect();
  await assert.rejects(s.sign(envelope.id), (error) => error instanceof StorageError && error.code === 'unavailable');
  assert.deepEqual(methods(sdk), [METHODS[0], METHODS[0]]);
});

test('strict store schema refuses extra expected fields before any sign RPC', async () => {
  const sdk = peer();
  const s = new SafeSession(sdk, { ...expected, result: 'forbidden' }, clock, () => {}, new MemoryRecords());
  await s.connect(() => {});
  await s.inspect();
  await assert.rejects(s.sign(envelope.id), StorageError);
  assert.deepEqual(methods(sdk), [METHODS[0], METHODS[0]]);
});

test('broadened, foreign, expired or extended settlements are disconnected and never adopted', async () => {
  const mutations = {
    method: (p) => p.session.namespaces.eip155.methods.push('personal_sign'),
    missingMethod: (p) => p.session.namespaces.eip155.methods.pop(),
    account: (p) => p.session.namespaces.eip155.accounts.push(`${CHAIN}:${expected.recipient}`),
    otherSigner: (p) => { p.session.namespaces.eip155.accounts = [`${CHAIN}:${expected.safe}`]; },
    otherChain: (p) => { p.session.namespaces.eip155.accounts = [`eip155:1:${expected.signer}`]; },
    chains: (p) => { p.session.namespaces.eip155.chains = [CHAIN, 'eip155:1']; },
    events: (p) => p.session.namespaces.eip155.events.push('accountsChanged'),
    namespace: (p) => { p.session.namespaces.solana = p.session.namespaces.eip155; },
    peer: (p) => { p.session.peer.metadata.url += '/'; },
    expired: (p) => { p.session.expiry = VECTOR_CLOCK; },
    properties: (p) => { p.session.sessionProperties = { x: '1' }; },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const sdk = peer();
    mutate(sdk);
    await assert.rejects(new SafeSession(sdk, expected, clock).connect(() => {}), name);
    assert.deepEqual(sdk.calls.at(-1)[0], 'disconnect', name);
    assert.deepEqual(methods(sdk), [], name);
  }
});

test('cancel during pairing: the late approval is disconnected and the object cannot reconnect', async () => {
  const sdk = peer(), s = new SafeSession(sdk, expected, clock);
  let approve;
  sdk.connect = async () => ({ uri: 'wc:test', approval: () => new Promise((resolve) => { approve = resolve; }) });
  const pending = s.connect(() => {});
  await tick();
  await s.close();
  approve(sdk.session);
  await assert.rejects(pending);
  assert.deepEqual(sdk.calls, [['disconnect', { topic: 'test-topic', reason: { code: 6000, message: 'User disconnected' } }]]);
  await assert.rejects(s.connect(() => {}));
  await assert.rejects(s.inspect());
  assert.deepEqual(methods(sdk), []);
});

test('session update, event, delete or expiry clears authority and never signs', async () => {
  for (const event of ['session_update', 'session_event', 'session_delete', 'session_expire']) {
    const sdk = peer(), causes = [];
    const s = await inspected(sdk, (cause) => causes.push(cause));
    sdk.emit(event, { topic: 'other-topic' });
    assert.equal(causes.length, 0, event);
    sdk.emit(event, { topic: 'test-topic' });
    assert.deepEqual(causes, [undefined], event);
    await assert.rejects(s.sign(envelope.id), event);
    assert.deepEqual(methods(sdk), [METHODS[0]], event);
    await s.dispose();
    assert.deepEqual(sdk.handlers[event], [], event);
  }
});

test('stale completion: delete or cancel while the reply is pending discards it without retry', async () => {
  for (const when of [METHODS[0], METHODS[1]]) {
    const sdk = peer(), s = await inspected(sdk), causes = [];
    s.changed = (cause) => causes.push(cause);
    let release;
    const reply = sdk.reply;
    sdk.reply = (p) => (p.request.method === when ? new Promise((resolve) => { release = () => resolve(reply(p)); }) : reply(p));
    const pending = s.sign(envelope.id);
    await tick();
    sdk.emit('session_delete', { topic: 'test-topic' });
    release();
    await assert.rejects(pending, when);
    assert.equal(methods(sdk).filter((m) => m === METHODS[1]).length, when === METHODS[1] ? 1 : 0, when);
    assert.deepEqual(causes, [undefined], when);
  }
  const sdk = peer();
  let release;
  sdk.reply = (p) => new Promise((resolve) => { release = () => resolve(structuredClone(v.context.result)); });
  const s = new SafeSession(sdk, expected, clock);
  await s.connect(() => {});
  const pending = s.inspect();
  await tick();
  await s.close();
  release();
  await assert.rejects(pending);
});

test('context change before signing rejects without a sign request and requires reconnect', async () => {
  for (const [key, value] of Object.entries({ binding: '0x' + '01'.repeat(32), maxValiditySeconds: 60, extra: 1 })) {
    const sdk = peer(), s = await inspected(sdk), causes = [];
    s.changed = (cause) => causes.push(cause);
    sdk.reply = () => ({ ...structuredClone(v.context.result), [key]: value });
    await assert.rejects(s.sign(envelope.id), key);
    assert.deepEqual(methods(sdk), [METHODS[0], METHODS[0]], key);
    assert.equal(causes.length, 1, key);
    assert.equal(sdk.calls.at(-1)[0], 'disconnect', key);
  }
  const sdk = peer();
  sdk.reply = () => ({ ...structuredClone(v.context.result), safe: expected.recipient });
  const s = new SafeSession(sdk, expected, clock);
  await s.connect(() => {});
  await assert.rejects(s.inspect());
  await assert.rejects(s.sign(envelope.id));
  assert.deepEqual(methods(sdk), [METHODS[0]]);
});

test('iPhone rejection, transport error and malformed results close the session once, with the cause', async () => {
  const replies = {
    rejected: () => Promise.reject({ code: 5003, message: 'rejected' }),
    expired: () => Promise.reject({ code: 5004, message: 'expired' }),
    unknownField: () => ({ ...structuredClone(v.result.result), note: 'x' }),
    missingField: () => { const r = structuredClone(v.result.result); delete r.signerSignature; return r; },
    string: () => JSON.stringify(v.result.result),
  };
  for (const [name, fail] of Object.entries(replies)) {
    const sdk = peer(), causes = [];
    const s = await inspected(sdk, (cause) => causes.push(cause));
    const reply = sdk.reply;
    sdk.reply = (p) => (p.request.method === METHODS[1] ? fail() : reply(p));
    await assert.rejects(s.sign(envelope.id), () => true, name);
    assert.equal(causes.length, 1, name);
    if (name === 'rejected') assert.equal(causes[0].code, 5003);
    assert.equal(methods(sdk).filter((m) => m === METHODS[1]).length, 1, name);
    await assert.rejects(s.sign(envelope.id), () => true, name);
  }
});

test('sign or inspect without the preceding explicit step is refused before any request', async () => {
  const sdk = peer(), s = new SafeSession(sdk, expected, clock);
  await assert.rejects(s.inspect());
  await assert.rejects(s.sign(envelope.id));
  await s.connect(() => {});
  await assert.rejects(s.sign(envelope.id));
  assert.deepEqual(methods(sdk), []);
});
