// SignClient 2.26.0 contract double; no relay, UI, persistence or native signing.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { BRIDGE_ORIGIN, CHAIN, METHODS, createSessionConfig, createV3BridgeSession } from '../defi-v3-session.js';

const TOPIC = 'ab'.repeat(32), SIGNER = '0x' + '22'.repeat(20), SAFE = '0x' + '11'.repeat(20);
const reason = { code: 6000, message: 'User disconnected' };
test('pinned real SDK proposal approval and lifecycle with network denied', () => {
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('./support/defi-v3-sdk-probe.mjs', import.meta.url))],
    { encoding: 'utf8', timeout: 25_000 });
  assert.equal(result.status, 0, result.stderr);
  const probe = JSON.parse(result.stdout.trim().split('\n').at(-1));
  assert.deepEqual(probe, { sdk: '2.26.0', proposal: true, approval: true, lifecycle: true,
    publications: 1, persistedOutsideMemory: false, relayPairing: false });
});
const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject }; };
function peer() {
  const calls = [], handlers = new Map();
  const session = { topic: TOPIC, expiry: 2_000_000_000, peer: { metadata: { url: BRIDGE_ORIGIN } },
    namespaces: { eip155: { accounts: [`${CHAIN}:${SIGNER}`], methods: [...METHODS], events: [] } } };
  const client = {
    session: { get: () => session },
    on: (event, fn) => handlers.set(event, fn), off: event => handlers.delete(event),
    connect: async args => { calls.push(['connect', args]); return { approval: async () => session }; },
    request: async args => { calls.push(['request', args]); throw new Error('not configured'); },
    disconnect: async args => { calls.push(['disconnect', args]); },
  };
  const bridge = createV3BridgeSession({ client, config: createSessionConfig({ signer: SIGNER, safe: SAFE }),
    sha256: bytes => new Uint8Array(createHash('sha256').update(bytes).digest()), clock: () => 1_900_000_000 });
  return { client, session, calls, handlers, bridge };
}

test('expired or changed SDK authority blocks request before parsing and never sends', async () => {
  for (const mutate of [p => { p.session.expiry = 1_900_000_000; },
    p => { p.session.namespaces.eip155.methods.push('personal_sign'); },
    p => { p.client.session.get = () => { throw new Error('missing session'); }; }]) {
    const p = peer();
    await p.bridge.connect();
    mutate(p);
    await assert.rejects(p.bridge.request(new Uint8Array()), { code: 'STALE_SESSION' });
    assert.equal(p.bridge.inspect().connected, false);
    assert.equal(p.calls.filter(([name]) => name === 'request').length, 0);
  }
});

test('invalid SDK settlement expiry or extension is never adopted', async () => {
  for (const mutate of [s => { delete s.expiry; }, s => { s.expiry = 1_900_000_000; },
    s => { s.expiry = Infinity; }, s => { s.sessionProperties = {}; },
    s => { s.scopedProperties = {}; }, s => { s.authentication = []; }, s => { s.walletPayResult = {}; }]) {
    const p = peer(); mutate(p.session);
    await assert.rejects(p.bridge.connect(), { code: 'NAMESPACE_MISMATCH' });
    assert.deepEqual(p.calls.at(-1), ['disconnect', { topic: TOPIC, reason }]);
  }
});

test('SDK lifecycle events end authority and dispose removes listeners', async () => {
  for (const name of ['session_delete', 'session_update', 'session_expire', 'session_event']) {
    const p = peer(); await p.bridge.connect();
    assert.equal(typeof p.handlers.get(name), 'function');
    p.handlers.get(name)({ topic: 'cd'.repeat(32) });
    assert.equal(p.bridge.inspect().connected, true);
    p.handlers.get(name)({ topic: TOPIC });
    assert.equal(p.bridge.inspect().connected, false);
    assert.equal(p.calls.filter(([kind]) => kind === 'request').length, 0);
    await p.bridge.dispose();
    assert.equal(p.handlers.size, 0);
    await assert.rejects(p.bridge.connect(), { code: 'STALE_SESSION' });
  }
});

test('SDK failure carries a fixed error and releases connecting state', async () => {
  const p = peer();
  p.client.connect = async () => { throw new Error('secret transport detail'); };
  await assert.rejects(p.bridge.connect(), { code: 'CONNECTION_FAILED', message: 'v3 bridge: CONNECTION_FAILED' });
  assert.equal(p.bridge.inspect().state, 'idle');
});

test('URI display failure disconnects eventual approval', async () => {
  const p = peer();
  p.client.connect = async () => ({ uri: 'wc:fixture-not-a-real-uri', approval: async () => p.session });
  await assert.rejects(p.bridge.connect(() => { throw new Error('display secret'); }), { code: 'CONNECTION_FAILED' });
  assert.equal(p.bridge.inspect().connected, false);
  assert.deepEqual(p.calls, [['disconnect', { topic: TOPIC, reason }]]);
});

test('cancel before proposal delivery hides URI and closes late approval', { timeout: 2000 }, async () => {
  const p = peer(), proposal = deferred();
  let displayed = 0;
  p.client.connect = () => proposal.promise;
  const pending = p.bridge.connect(() => { displayed++; });
  const rejected = assert.rejects(pending, { code: 'STALE_SESSION' });
  await p.bridge.disconnect();
  proposal.resolve({ uri: 'wc:fixture-not-a-real-uri', approval: async () => p.session });
  await rejected;
  assert.equal(displayed, 0);
  assert.deepEqual(p.calls, [['disconnect', { topic: TOPIC, reason }]]);
});

test('concurrent connect is rejected before another SDK proposal', { timeout: 2000 }, async () => {
  const p = peer(), approval = deferred();
  let attempts = 0;
  p.client.connect = async () => { attempts++; return { approval: () => approval.promise }; };
  const first = p.bridge.connect();
  await tick();
  const second = p.bridge.connect().then(() => null, error => error.code);
  approval.resolve(p.session);
  await first;
  assert.equal(await second, 'ALREADY_CONNECTED');
  assert.equal(attempts, 1);
});

test('dispose while URI display is suspended still closes approval', async () => {
  const p = peer(), display = deferred(), approval = deferred();
  p.client.connect = async () => ({ uri: 'wc:fixture', approval: () => approval.promise });
  const pending = p.bridge.connect(() => display.promise);
  const rejected = assert.rejects(pending, { code: 'STALE_SESSION' });
  await tick();
  await p.bridge.dispose();
  approval.resolve(p.session);
  await tick();
  assert.deepEqual(p.calls, [['disconnect', { topic: TOPIC, reason }]]);
  display.resolve();
  await rejected;
});

test('old session loss does not cancel a fresh proposal and invalid authority is disconnected', async () => {
  const p = peer(); await p.bridge.connect();
  p.session.expiry = 0;
  await assert.rejects(p.bridge.request(new Uint8Array()), { code: 'STALE_SESSION' });
  await tick();
  assert.deepEqual(p.calls.at(-1), ['disconnect', { topic: TOPIC, reason }]);
  const approval = deferred();
  p.session.expiry = 2_000_000_000;
  p.session.topic = 'cd'.repeat(32);
  p.client.connect = async () => ({ approval: () => approval.promise });
  const pending = p.bridge.connect();
  await tick();
  p.handlers.get('session_delete')({ topic: TOPIC });
  approval.resolve(p.session);
  assert.equal((await pending).connected, true);
});

test('cancel during approval disconnects the late session', { timeout: 2000 }, async () => {
  const p = peer(), approval = deferred();
  let approvals = 0, displayed = 0;
  p.client.connect = async () => ({ uri: 'wc:fixture-not-a-real-uri', approval: () => { approvals++; return approval.promise; } });
  const pending = p.bridge.connect(() => { displayed++; });
  const rejected = assert.rejects(pending, { code: 'STALE_SESSION' });
  await tick();
  await p.bridge.disconnect();
  assert.equal(p.bridge.inspect().connected, false);
  approval.resolve(p.session);
  await rejected;
  assert.equal(displayed, 1);
  assert.equal(approvals, 1);
  assert.deepEqual(p.calls, [['disconnect', { topic: TOPIC, reason }]]);
  assert.equal(p.bridge.inspect().state, 'disconnected');
});
