// KeyChangeSession over (1) the real pinned @walletconnect/sign-client 2.26.0 with all network denied, proving the
// actual SDK proposal rewrite and the dedicated memory-only storage, and (2) a scripted SignClient double acting as
// the software native peer. Software keys only: no relay, iPhone, Secure Enclave or physical authentication.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { METHODS, buildRequest, keyIdHash, issuedAtFor, parseAuthority, planChange } from '../key-model.js';
import { KeyChangeSession, STORAGE_PREFIX, SessionError, classify, } from '../key-session.js';
import { K1, K2, anchorText, contextWire, nativeClient, nativeSign, signRaw, softwareKey } from './support/key-fixtures.mjs';

const k1 = softwareKey(K1), k2 = softwareKey(K2);
const SIGNER = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const anchor = parseAuthority(anchorText(SIGNER, k1));
const binding = '0x' + 'ab'.repeat(32);
const now = () => Math.floor(Date.now() / 1000);
const chain = { keys: [k1], nonce: 2n, blockNumber: 500n, blockHash: '0x' + '12'.repeat(32) };

function peer(overrides = {}) {
  const p = { signer: SIGNER, signs: 0, context: () => contextWire({ signer: SIGNER, key: k1, binding, chain }),
    sign: async (envelope) => { p.signs++; return nativeSign({ envelope, key: k1, binding }); }, ...overrides };
  return p;
}
const prepare = (native) => buildRequest({ context: native, operation: planChange({ signer: anchor.signerAddress,
  nonce: native.nonce, keys: native.keys, change: { kind: 'add', key: k2 }, fees: { maxFee: 10n ** 9n, priorityFee: 1n } })
  .operation, id: crypto.randomUUID(), issuedAt: issuedAtFor(now()) });
const methods = (client) => client.calls.filter(([k]) => k === 'request').map(([, m]) => m);

test('actual SignClient 2.26.0: dedicated prefix, memory storage, required namespaces rewritten to optional', () => {
  const out = spawnSync(process.execPath, [fileURLToPath(new URL('./support/key-sdk-probe.mjs', import.meta.url))],
    { cwd: fileURLToPath(new URL('..', import.meta.url)), encoding: 'utf8', timeout: 60_000 });
  assert.equal(out.status, 0, out.stderr);
  const probe = JSON.parse(out.stdout.trim().split('\n').at(-1));
  assert.equal(probe.proposals.length, 1);
  assert.deepEqual(probe.proposals[0].requiredNamespaces, {});
  assert.deepEqual(probe.proposals[0].optionalNamespaces, { eip155: { chains: ['eip155:137'], methods: [...METHODS],
    events: [] } });
  assert.equal(probe.proposals[0].proposer, 'https://tumf.github.io');
  assert.equal(probe.prefix, STORAGE_PREFIX);
  assert.equal(STORAGE_PREFIX, 'p256.key-change.session.v1');
  assert.ok(probe.storageKeys.length > 0 && probe.storageKeys.every((k) => k.includes(STORAGE_PREFIX)));
  assert.equal(probe.telemetryEnabled, false);
  assert.equal(probe.localStorage, 'undefined');
  assert.ok(probe.seen.every((u) => /walletconnect\.(com|org)/.test(u)), probe.seen.join());
});

test('connect, inspect and one explicit sign: exact methods, fresh context reread, verified result', async () => {
  const p = peer(), { client } = nativeClient(p);
  const s = new KeyChangeSession(client, anchor, now);
  await s.connect(() => {});
  assert.deepEqual(client.calls[0], ['connect', { requiredNamespaces: { eip155: { chains: ['eip155:137'],
    methods: [...METHODS], events: [] } } }]);
  assert.deepEqual(methods(client), []);
  const native = await s.inspect();
  assert.equal(native.binding, binding);
  assert.deepEqual(methods(client), [METHODS[0]]);
  const signed = await s.sign(prepare);
  assert.deepEqual(methods(client), [METHODS[0], METHODS[0], METHODS[1]]);
  assert.match(signed.signerSignature, /^0x[0-9a-f]{192}$/);
  assert.equal(p.signs, 1);
  await assert.rejects(s.sign(prepare));
  await assert.rejects(s.inspect());
  assert.equal(p.signs, 1);
});

test('prepare receives an isolated validated full wire context separately from semantic authority', async () => {
  let original;
  const p = peer({ context: () => (original = contextWire({ signer: SIGNER, key: k1, binding, chain })) });
  const { client } = nativeClient(p), s = new KeyChangeSession(client, anchor, now);
  await s.connect(() => {});
  const semantic = await s.inspect();
  assert.equal('origin' in semantic, false, 'ordinary semantic context stays unchanged');
  await s.sign((fresh, wire) => {
    assert.deepEqual(wire, original);
    assert.notEqual(wire, original);
    assert.notEqual(wire.keys, original.keys);
    assert.equal(typeof fresh.nonce, 'bigint');
    assert.equal(typeof wire.nonce, 'string');
    assert.equal(Object.isFrozen(wire), true);
    assert.equal(Object.isFrozen(wire.keys), true);
    assert.equal(Object.isFrozen(wire.keys[0]), true);
    original.keys[0].publicKey = k2.publicKey;
    assert.equal(wire.keys[0].publicKey, k1.publicKey);
    return prepare(fresh);
  });
  assert.equal(p.signs, 1);
});

test('invalid full wire is never reconstructed or passed to signing preparation', async () => {
  for (const mutate of [(wire) => { delete wire.origin; }, (wire) => { wire.topic = 'foreign'; }]) {
    const p = peer(), { client } = nativeClient(p), s = new KeyChangeSession(client, anchor, now);
    await s.connect(() => {}); await s.inspect();
    p.context = () => { const wire = contextWire({ signer: SIGNER, key: k1, binding, chain }); mutate(wire); return wire; };
    let prepared = false;
    await assert.rejects(s.sign((native) => { prepared = true; return prepare(native); }), (e) => e.kind === 'changed');
    assert.equal(prepared, false);
    assert.equal(p.signs, 0);
  }
});

test('broadened, foreign, expired or extended sessions are disconnected and never adopted', async () => {
  const session = (topic) => ({ topic, expiry: now() + 3600, peer: { metadata: { url: 'https://tumf.github.io' } },
    namespaces: { eip155: { accounts: [`eip155:137:${SIGNER.toLowerCase()}`], methods: [...METHODS], events: [] } } });
  const mutations = {
    method: (x) => x.namespaces.eip155.methods.push('personal_sign'), safe: (x) => { x.namespaces.eip155.methods = ['p256_getSessionContext', 'p256_signSafeRequest']; },
    event: (x) => x.namespaces.eip155.events.push('chainChanged'), account: (x) => x.namespaces.eip155.accounts.push('eip155:1:0x' + '11'.repeat(20)),
    otherSigner: (x) => { x.namespaces.eip155.accounts = ['eip155:137:0x' + '22'.repeat(20)]; },
    origin: (x) => { x.peer.metadata.url = 'https://evil.example'; }, expired: (x) => { x.expiry = now() - 1; },
    namespace: (x) => { x.namespaces.solana = { accounts: [], methods: [], events: [] }; },
    properties: (x) => { x.sessionProperties = { capabilities: '{}' }; }, chains: (x) => { x.namespaces.eip155.chains = ['eip155:1']; },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const p = peer({ approve: (x) => { const y = session(x.topic); mutate(y); return Promise.resolve(y); } });
    const { client } = nativeClient(p);
    const s = new KeyChangeSession(client, anchor, now);
    await assert.rejects(s.connect(() => {}), SessionError, name);
    assert.equal(client.calls.at(-1)[0], 'disconnect', name);
    await assert.rejects(s.inspect(), SessionError, name);
    assert.deepEqual(methods(client), [], name);
  }
});

test('changed authority before signing sends no sign request; classified failures close once', async () => {
  for (const [name, next] of Object.entries({
    binding: () => contextWire({ signer: SIGNER, key: k1, binding: '0x' + 'cd'.repeat(32), chain }),
    keys: () => contextWire({ signer: SIGNER, key: k1, binding, chain: { ...chain, keys: [k1, k2] } }),
    nonce: () => contextWire({ signer: SIGNER, key: k1, binding, chain: { ...chain, nonce: 3n } }),
    policy: () => contextWire({ signer: SIGNER, key: k1, binding, chain, maxFeePerGas: '1' }),
  })) {
    const causes = [], p = peer(), { client } = nativeClient(p);
    const s = new KeyChangeSession(client, anchor, now, (c) => causes.push(c));
    await s.connect(() => {});
    await s.inspect();
    p.context = next;
    await assert.rejects(s.sign(prepare), (e) => e.kind === 'changed', name);
    assert.deepEqual(methods(client), [METHODS[0], METHODS[0]], name);
    assert.deepEqual(causes, ['changed'], name);
    assert.equal(p.signs, 0);
  }
  const replies = {
    rejected: [() => Promise.reject({ code: 5003, message: 'rejected' }), 'rejected'],
    expired: [() => Promise.reject({ code: 5004, message: 'expired' }), 'expired'],
    transport: [() => Promise.reject(new Error('socket')), 'lost'],
    extra: [async (e) => ({ ...(await nativeSign({ envelope: e, key: k1, binding })), note: 'x' }), 'invalid'],
    wrongKey: [async (e) => {
      const r = await nativeSign({ envelope: e, key: k1, binding }), raw = await signRaw(k2, r.typedDataHash);
      return { ...r, rawSignature: raw, signerSignature: keyIdHash(k1.keyId) + raw.slice(2) };
    }, 'invalid'],
  };
  for (const [name, [sign, kind]] of Object.entries(replies)) {
    const causes = [], p = peer({ sign }), { client } = nativeClient(p);
    const s = new KeyChangeSession(client, anchor, now, (c) => causes.push(c));
    await s.connect(() => {});
    await s.inspect();
    await assert.rejects(s.sign(prepare), (e) => e.kind === kind, name);
    assert.deepEqual(causes, [kind], name);
    assert.equal(methods(client).filter((m) => m === METHODS[1]).length, 1, name);
  }
});

test('session events and closes end authority; late results after close are never adopted', async () => {
  const p = peer(), { client } = nativeClient(p);
  const causes = [];
  const s = new KeyChangeSession(client, anchor, now, (c) => causes.push(c));
  await s.connect(() => {});
  client.emit('session_event', client.topic);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(causes, ['lost']);
  await assert.rejects(s.inspect());
  assert.deepEqual(methods(client), []);
  let release;
  const p2 = peer({ sign: (e) => new Promise((resolve) => { release = () => resolve(nativeSign({ envelope: e, key: k1, binding })); }) });
  const { client: c2 } = nativeClient(p2);
  const s2 = new KeyChangeSession(c2, anchor, now);
  await s2.connect(() => {});
  await s2.inspect();
  const pending = s2.sign(prepare);
  for (let i = 0; i < 50 && !release; i++) await new Promise((r) => setTimeout(r, 5));
  await s2.close('lost');
  release();
  await assert.rejects(pending, (e) => e.kind === 'lost');
  // A result arriving after browser expiry is refused even though its signature is valid.
  let clock = now();
  const p3 = peer({ sign: async (e) => { clock += 200; return nativeSign({ envelope: e, key: k1, binding }); } });
  const { client: c3 } = nativeClient(p3);
  const s3 = new KeyChangeSession(c3, anchor, () => clock);
  await s3.connect(() => {});
  await s3.inspect();
  await assert.rejects(s3.sign(prepare), (e) => e.kind === 'expired');
  assert.equal(classify({ code: 4001 }), 'lost');
});
