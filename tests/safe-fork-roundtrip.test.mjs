// Offline controls for the isolated-fork v3 collection/persistence/send path (tests/support/safe-fork-roundtrip.mjs and
// the v3 branch of Execution.collect). Software test keys only; a fake Anvil-like fork; nothing reaches a network.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import ethers from '../vendor/ethers.js';
import { Execution } from '../safe-execute.js';
import { candidateFromWire } from '../defi-v3-session.js';
import { buildSafeTxWire, topicFor, writeOnce, writeRun, FILES as EXCHANGE } from './support/defi-v3-exchange-client.mjs';
import { createChain } from './support/key-chain.mjs';
import * as fork from './support/safe-fork-roundtrip.mjs';

const U = ethers.utils, Z = ethers.constants.AddressZero;
const PIN = JSON.parse(fs.readFileSync(new URL('fixtures/safe150-proxy.json', import.meta.url)));
const SAFE = '0x' + '5a'.repeat(20), ACCOUNT = '0x' + '77'.repeat(20);
const RECIPIENT = fork.FIXTURE_INTENT.recipient, VALUE = fork.FIXTURE_INTENT.value;
const BINDING = '0x' + 'ab'.repeat(32);
const SOURCE = { number: '95559460', hash: '0x464d98ef2bc90b455ce7dc52344bda4c95ccf395d523f02a7054a9a155d79729' };
let clockValue = 1_800_000_000;
const clock = () => clockValue;
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'p256-fork-test-'));

async function key() {
  const { pair, handoff } = await fork.ephemeralHandoff();
  return { pair, handoff, owner: { address: handoff.expectedAddress.toLowerCase(), kind: 'hybrid', publicKey: handoff.publicKey, keyId: handoff.keyID } };
}
const snapshotFor = (owner, nonce = '0', block = { number: '95559463', hash: '0x' + '11'.repeat(32) }) => ({ chainId: '137', safe: SAFE, version: '1.5.0',
  singleton: fork.SINGLETON, runtime: 'unverified-offline', guard: Z, fallback: Z, modules: [], owners: [owner], threshold: 1, nonce, account: ACCOUNT,
  block, generation: 0, attempt: 'none' });
const wireFor = (owner, extra = {}) => Buffer.from(buildSafeTxWire({ safe: SAFE, signer: owner.address, keyId: owner.keyId, binding: BINDING,
  issuedAt: clock(), nonce: '0', validity: 120, ...extra })).toString('utf8');
const mutate = (text, field, value) => { const o = JSON.parse(text); o[field] = value; return JSON.stringify(o); };

// ---------- Execution v3 collection (no RPC: the opt-out observation path) ----------

test('v3 result of the app codec is collected into the product Execution and encoded as the HybridDeleGator raw P-256 signature', async () => {
  const k = await key();
  const m = new Execution({ read: async () => snapshotFor(k.owner), now: clock });
  const loaded = await m.load({ kind: 'native', recipient: RECIPIENT, value: VALUE });
  const wire = wireFor(k.owner);
  const candidate = candidateFromWire(new TextEncoder().encode(wire), fork.sha256);
  assert.equal(candidate.signedDigest, loaded.operation.hash, 'v3 signedDigest is the Safe EIP-712 SafeTx hash');
  const result = await fork.testResult(wire, k.pair.privateKey, k.owner.publicKey);
  const view = await m.collect({ owner: k.owner.address, wire, result });
  assert.equal(view.count, 1);
  const prepared = await m.prepare([k.owner.address]);
  assert.equal(prepared.selected[0].kind, 'hybrid');
  const r = JSON.parse(result);
  assert.equal(prepared.selected[0].signature, r.signerSignature);
  assert.equal(prepared.selected[0].signature.length, 2 + 96 * 2);
  assert.equal(prepared.selected[0].signature.slice(0, 66), U.keccak256(U.toUtf8Bytes(k.owner.keyId)));
  assert.equal(prepared.selected[0].expires, Number(JSON.parse(wire).expiresAt));
  assert.equal(prepared.safeTxHash, loaded.operation.hash);
});

for (const change of ['safe', 'chain', 'nonce', 'recipient', 'value', 'signer', 'keyId', 'requestId', 'signature', 'point', 'binding', 'expired', 'purpose', 'nonowner'])
  test(`v3 collection refuses a ${change} mismatch and keeps zero signatures`, async () => {
    const k = await key(), other = await key();
    const m = new Execution({ read: async () => snapshotFor(k.owner), now: clock });
    await m.load({ kind: 'native', recipient: RECIPIENT, value: VALUE });
    let wire = wireFor(k.owner), owner = k.owner.address, signer = k.pair.privateKey, point = k.owner.publicKey;
    if (change === 'safe') wire = wireFor(k.owner, { safe: '0x' + '5b'.repeat(20) });
    if (change === 'nonce') wire = wireFor(k.owner, { nonce: '1' });
    if (change === 'recipient') wire = wireFor(k.owner, { variant: 2 });
    if (change === 'signer') wire = wireFor({ ...k.owner, address: other.owner.address });
    if (change === 'keyId') wire = wireFor({ ...k.owner, keyId: other.owner.keyId });
    if (change === 'expired') wire = wireFor(k.owner, { issuedAt: clock() - 121 });
    if (change === 'nonowner') owner = other.owner.address;
    if (change === 'chain' || change === 'value') {
      const o = JSON.parse(wire), payload = JSON.parse(Buffer.from(o.payloadJson.slice(2), 'hex').toString('utf8'));
      if (change === 'chain') payload.chainId = '1'; else payload.body.tx.value = '1';
      wire = mutate(wire, 'payloadJson', '0x' + Buffer.from(JSON.stringify(payload)).toString('hex'));
    }
    if (change === 'signature') signer = other.pair.privateKey;
    if (change === 'point') point = other.owner.publicKey;
    let result = await fork.testResult(wire, signer, point);
    if (change === 'requestId') result = mutate(result, 'requestId', randomUUID());
    if (change === 'binding') result = mutate(result, 'binding', '0x' + 'cd'.repeat(32));
    if (change === 'purpose') wire = mutate(wire, 'purpose', 'safe-message-v1.5.0/personal-v1'); // the result was made for the SafeTx purpose
    await assert.rejects(m.collect({ owner, wire, result }));
    assert.equal(m.view().count, 0);
    await assert.rejects(m.prepare([k.owner.address]));
  });

test('v3 packet shape is closed: legacy packet keys, non-string wire and oversize text are refused', async () => {
  const k = await key();
  const m = new Execution({ read: async () => snapshotFor(k.owner), now: clock });
  await m.load({ kind: 'native', recipient: RECIPIENT, value: VALUE });
  const wire = wireFor(k.owner), result = await fork.testResult(wire, k.pair.privateKey, k.owner.publicKey);
  await assert.rejects(m.collect({ owner: k.owner.address, wire, result, extra: 1 }), /Invalid schema/);
  await assert.rejects(m.collect({ owner: k.owner.address, wire: JSON.parse(wire), result }), /Invalid v3 packet/);
  await assert.rejects(m.collect({ owner: k.owner.address, wire, result: result + ' '.repeat(20000) }), /Invalid v3 packet/);
  await assert.rejects(m.collect({ owner: k.owner.address, wire, result: result.replace('"v":"3"', '"v":"3","x":"1"') }), /v3 result rejected/);
  assert.equal(m.view().count, 0);
});

// ---------- fake Anvil-like fork for the execute path ----------

function fakeFork(owner, { simulate = true, hook = () => {} } = {}) {
  const chain = createChain({ signer: owner.address, keys: [owner], now: clock });
  const abi = new U.Interface(['function VERSION() view returns(string)', 'function getOwners() view returns(address[])',
    'function getThreshold() view returns(uint256)', 'function nonce() view returns(uint256)', 'function getModulesPaginated(address,uint256) view returns(address[],address)',
    'function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes) returns(bool)']);
  const events = new U.Interface(['event ExecutionSuccess(bytes32 indexed txHash,uint256 payment)']);
  const types = { SafeTx: [['to', 'address'], ['value', 'uint256'], ['data', 'bytes'], ['operation', 'uint8'], ['safeTxGas', 'uint256'], ['baseGas', 'uint256'],
    ['gasPrice', 'uint256'], ['gasToken', 'address'], ['refundReceiver', 'address'], ['nonce', 'uint256']].map(([name, type]) => ({ name, type })) };
  const hashOf = (n) => (n === BigInt(SOURCE.number) ? SOURCE.hash : '0x' + n.toString(16).padStart(64, '0'));
  const blocks = [{ number: BigInt(SOURCE.number), state: { nonce: 0n, safe: 2n * 10n ** 18n, recipient: 0n }, txs: [] }];
  const blockOf = (b) => ({ number: '0x' + b.number.toString(16), hash: hashOf(b.number), parentHash: hashOf(b.number - 1n), timestamp: '0x' + clock().toString(16) });
  const latest = () => blocks[blocks.length - 1];
  const mine = (txs = []) => { const prev = latest(); blocks.push({ number: prev.number + 1n, state: { ...prev.state }, txs }); return latest(); };
  const at = (tag) => (tag === 'latest' ? latest() : blocks.find((b) => b.number === BigInt(tag)) ?? null);
  const txs = new Map(), receipts = new Map();
  mine(); // session block
  const f = { chain, blocks, sends: 0, calls: [] };
  f.rpc = async (method, params = []) => {
    f.calls.push(method);
    await hook(method, params, f);
    switch (method) {
      case 'web3_clientVersion': return 'anvil/v1.8.3-test';
      case 'eth_chainId': return '0x89';
      case 'anvil_mine': { for (let i = 0; i < Number(BigInt(params[0])); i++) mine(); return null; }
      case 'eth_getBlockByNumber': { const b = at(params[0]); return b ? blockOf(b) : null; }
      case 'eth_getCode': {
        const a = params[0].toLowerCase();
        if (a === SAFE) return PIN.runtime;
        if (a === fork.SINGLETON) return PIN.singletonRuntime;
        if (a === ACCOUNT || a === RECIPIENT) return '0x';
        return chain.rpc(method, params);
      }
      case 'eth_getStorageAt': return params[0].toLowerCase() === SAFE ? (params[1] === U.hexZeroPad('0x00', 32) ? U.hexZeroPad(fork.SINGLETON, 32) : U.hexZeroPad('0x00', 32)) : chain.rpc(method, params);
      case 'eth_getBalance': { const b = at(params[1]); const a = params[0].toLowerCase(); return '0x' + (a === SAFE ? b.state.safe : a === RECIPIENT ? b.state.recipient : 10n ** 21n).toString(16); }
      case 'eth_call': {
        if (params[0].to.toLowerCase() !== SAFE) return chain.rpc(method, params);
        const b = at(params[1] ?? 'latest'), name = abi.parseTransaction({ data: params[0].data }).name;
        if (name === 'execTransaction') return simulate ? '0x' + '0'.repeat(63) + '1' : '0x' + '0'.repeat(64);
        return abi.encodeFunctionResult(name, name === 'VERSION' ? ['1.5.0'] : name === 'getOwners' ? [[owner.address]] : name === 'getThreshold' ? [1]
          : name === 'nonce' ? [b.state.nonce] : [[], '0x0000000000000000000000000000000000000001']);
      }
      case 'eth_sendTransaction': {
        f.sends++;
        const tx = params[0], hash = '0x' + randomBytes(32).toString('hex');
        const args = abi.decodeFunctionData('execTransaction', tx.data);
        const b = mine([hash]);
        const H = U._TypedDataEncoder.hash({ chainId: 137, verifyingContract: SAFE }, types, { to: args[0], value: args[1].toString(), data: args[2], operation: args[3],
          safeTxGas: args[4].toString(), baseGas: args[5].toString(), gasPrice: args[6].toString(), gasToken: args[7], refundReceiver: args[8], nonce: b.state.nonce.toString() });
        b.state.nonce += 1n; b.state.safe -= BigInt(args[1].toString()); b.state.recipient += BigInt(args[1].toString());
        const block = blockOf(b);
        txs.set(hash, { hash, from: tx.from, to: tx.to, value: '0x0', input: tx.data, nonce: '0x0', chainId: '0x89', blockNumber: block.number, blockHash: block.hash,
          gas: '0x30000', maxFeePerGas: '0x3b9aca00', maxPriorityFeePerGas: '0x3b9aca00', type: '0x2' });
        const log = events.encodeEventLog(events.getEvent('ExecutionSuccess'), [H, 0]);
        receipts.set(hash, { transactionHash: hash, status: '0x1', blockNumber: block.number, blockHash: block.hash, from: tx.from, to: tx.to, gasUsed: '0x2000',
          effectiveGasPrice: '0x3b9aca00', logs: [{ address: SAFE, topics: log.topics, data: log.data, removed: false, transactionHash: hash, blockHash: block.hash, blockNumber: block.number }] });
        return hash;
      }
      case 'eth_getTransactionByHash': return txs.get(params[0]) ?? null;
      case 'eth_getTransactionReceipt': return receipts.get(params[0]) ?? null;
      default: throw new Error('unsupported ' + method);
    }
  };
  f.record = () => ({ version: 1, pid: 0, port: 0, url: 'http://127.0.0.1:1', clientVersion: 'anvil/v1.8.3-test', chainId: '137', source: SOURCE,
    session: { number: String(BigInt(SOURCE.number) + 1n), hash: hashOf(BigInt(SOURCE.number) + 1n) }, account: ACCOUNT,
    signer: { address: owner.address, keyId: owner.keyId, publicKey: owner.publicKey }, safe: { address: SAFE, nonce: '0' } });
  return f;
}

async function appLikeInputs(k, extra = {}) {
  const wire = Buffer.from(buildSafeTxWire({ safe: SAFE, signer: k.owner.address, keyId: k.owner.keyId, binding: BINDING, issuedAt: clock(), nonce: '0', validity: 120, ...extra })).toString('utf8');
  const result = await fork.testResult(wire, k.pair.privateKey, k.owner.publicKey);
  return { wire, result, requestId: JSON.parse(wire).id, safe: SAFE, safeNonce: '0', run: randomUUID() };
}
const owned = async () => true;

test('execute: verified result is persisted, reserved, sent once through the guarded wallet and read back with nonce and balance deltas', async () => {
  const k = await key(), f = fakeFork(k.owner), dir = tmp();
  const record = await fork.execute({ dir, fork: f.record(), rpc: f.rpc, inputs: await appLikeInputs(k), clock, ownership: owned });
  assert.equal(record.status, 'PASS', record.error);
  assert.equal(record.sends, 1); assert.equal(f.sends, 1);
  assert.deepEqual(record.receipt.nonce, { before: '0', after: '1' });
  assert.equal(record.receipt.balances.safeBefore, (2n * 10n ** 18n).toString());
  assert.equal(record.receipt.balances.recipientAfter, VALUE);
  assert.equal(record.readback.nonce, '1');
  for (const name of ['collected', 'attempt', 'sent', 'finish']) assert.ok(fs.existsSync(path.join(dir, fork.FILES[name])), name);
  const collected = JSON.parse(fs.readFileSync(path.join(dir, fork.FILES.collected), 'utf8')), attempt = JSON.parse(fs.readFileSync(path.join(dir, fork.FILES.attempt), 'utf8'));
  assert.equal(collected.safeTxHash, record.safeTxHash); assert.equal(attempt.state, 'SENDING'); assert.deepEqual(attempt.request, record.request);
  assert.deepEqual(record.steps, ['owned', 'snapshot', 'loaded', 'collected', 'prepared', 'preflighted', 'persisted', 'reserved', 'sent', 'receipt', 'readback']);
  // A second run against the same directory is locked: nothing is sent again.
  const again = await fork.execute({ dir, fork: f.record(), rpc: f.rpc, inputs: await appLikeInputs(k), clock, ownership: owned });
  assert.equal(again.status, 'ALREADY_SENT'); assert.equal(again.sends, 0); assert.equal(f.sends, 1);
});

test('execute: a failed durable save (collected or reservation) sends nothing', async () => {
  for (const stage of ['collected', 'reservation']) {
    const k = await key(), dir = tmp();
    const f = fakeFork(k.owner, { hook: (method, params) => {
      // Make the private directory unwritable exactly when the next durable write is due.
      if (stage === 'collected' && method === 'eth_call' && params[0].data?.startsWith('0x6a761202')) fs.chmodSync(dir, 0o500);
      if (stage === 'reservation' && fs.existsSync(path.join(dir, fork.FILES.collected))) fs.chmodSync(dir, 0o500);
    } });
    const record = await fork.execute({ dir, fork: f.record(), rpc: f.rpc, inputs: await appLikeInputs(k), clock, ownership: owned });
    fs.chmodSync(dir, 0o700);
    assert.equal(record.status, 'FAIL'); assert.match(record.error, /WRITE:/);
    assert.equal(record.sends, 0); assert.equal(f.sends, 0);
    assert.ok(!fs.existsSync(path.join(dir, fork.FILES.attempt)) && !fs.existsSync(path.join(dir, fork.FILES.sent)));
    assert.equal(fs.existsSync(path.join(dir, fork.FILES.collected)), stage === 'reservation');
  }
});

test('execute: preflight refusal on the fork, Safe/nonce drift and foreign intent never reach the wallet', async () => {
  const k = await key();
  for (const [name, options, inputs] of [
    ['preflight', { simulate: false }, {}],
    ['nonce', {}, { safeNonce: '1' }],
    ['safe', {}, { safe: '0x' + '5b'.repeat(20) }],
    ['intent', {}, { variant: 2 }]]) {
    const f = fakeFork(k.owner, options), dir = tmp();
    const base = await appLikeInputs(k, name === 'intent' ? { variant: 2 } : {});
    const record = await fork.execute({ dir, fork: f.record(), rpc: f.rpc, inputs: { ...base, ...(name === 'intent' ? {} : inputs) }, clock, ownership: owned });
    assert.equal(record.status, 'FAIL', name); assert.equal(f.sends, 0, name);
    assert.ok(!fs.existsSync(path.join(dir, fork.FILES.attempt)), name);
    if (name === 'nonce') assert.match(record.error, /NONCE_DRIFT/);
    if (name === 'safe') assert.match(record.error, /SAFE_MISMATCH/);
    if (name === 'intent') assert.match(record.error, /INTENT_MISMATCH/);
  }
});

test('execute: an existing reservation without a sent record is an ambiguous-state lock', async () => {
  const k = await key(), f = fakeFork(k.owner), dir = tmp();
  fork.persist(dir, fork.FILES.attempt, { state: 'SENDING', request: {} });
  const record = await fork.execute({ dir, fork: f.record(), rpc: f.rpc, inputs: await appLikeInputs(k), clock, ownership: owned });
  assert.equal(record.status, 'LOCKED_UNKNOWN'); assert.equal(record.sends, 0); assert.equal(f.calls.length, 0);
});

// ---------- exchange records: cancellation and identity ----------

function exchangeDir(dir, run, { error = null, context = { safe: SAFE, safeNonce: '0' } } = {}) {
  const ex = path.join(dir, 'exchange');
  fs.mkdirSync(ex, { mode: 0o700 });
  writeRun(ex, run, context);
  const topic = topicFor(run), wire = `{"v":"3","purpose":"safe-tx-v1.5.0/generic-v1","codecId":"x","id":"${randomUUID()}","keyId":"${'00'.repeat(32)}","binding":"${BINDING}","signer":"${ACCOUNT}","issuedAt":"1","expiresAt":"2","payloadJson":"0x7b7d"}`;
  const params = `[${wire}]`;
  const identity = { run, topic, chain: 'eip155:137', id: { t: 'integer', v: '1' }, method: 'p256_signSafeRequestV3' };
  writeOnce(ex, EXCHANGE.request, { ...identity, raw: `{"jsonrpc":"2.0","id":1,"method":"p256_signSafeRequestV3","params":${params}}` });
  const result = { ...identity, params };
  if (error) result.error = error; else { result.result = '{"v":"3"}'; result.resultSha256 = Buffer.from(fork.sha256(Buffer.from(result.result))).toString('hex'); }
  writeOnce(ex, EXCHANGE.result, result);
  return { ex, wire, identity };
}

test('finish: a cancelled (RPC 4001) exchange result yields CANCELLED with zero sends and no persistence', async () => {
  const dir = tmp(), run = randomUUID();
  exchangeDir(dir, run, { error: { code: 4001, message: 'user rejected' } });
  fork.persist(dir, fork.FILES.fork, { url: 'http://127.0.0.1:9', pid: 0, port: 9 });
  const record = await fork.finish({ dir, clock });
  assert.equal(record.status, 'CANCELLED'); assert.equal(record.code, 4001); assert.equal(record.sends, 0);
  assert.ok(!fs.existsSync(path.join(dir, fork.FILES.collected)) && !fs.existsSync(path.join(dir, fork.FILES.attempt)));
});

test('collectionInputs: identity, params, digest, run context and Web verdict mismatches are refused; exact records pass', () => {
  const dir = tmp(), run = randomUUID();
  const { ex, wire } = exchangeDir(dir, run);
  const result = JSON.parse(fs.readFileSync(path.join(ex, EXCHANGE.result), 'utf8'));
  assert.throws(() => fork.collectionInputs(ex, run), /MALFORMED:web-verdict/);
  const verdict = { run, status: 'verified', resultSha256: result.resultSha256, requestId: JSON.parse(wire).id, counts: { requests: 1, verified: 1 } };
  const write = (name, object) => fs.writeFileSync(path.join(ex, name), JSON.stringify(object));
  write(EXCHANGE.verdict, { ...verdict, status: 'failed' });
  assert.throws(() => fork.collectionInputs(ex, run), /WEB_VERDICT/);
  write(EXCHANGE.verdict, verdict);
  const inputs = fork.collectionInputs(ex, run);
  assert.equal(inputs.status, 'verified'); assert.equal(inputs.wire, wire); assert.equal(inputs.safe, SAFE); assert.equal(inputs.safeNonce, '0');
  assert.throws(() => fork.collectionInputs(ex, randomUUID()), /RUN_MISMATCH/);
  write(EXCHANGE.result, { ...result, params: `[${wire.replace('"v":"3"', '"v":"3 "')}]` });
  assert.throws(() => fork.collectionInputs(ex, run), /PARAMS_MISMATCH/);
  write(EXCHANGE.result, { ...result, id: { t: 'integer', v: '2' } });
  assert.throws(() => fork.collectionInputs(ex, run), /IDENTITY_MISMATCH/);
  write(EXCHANGE.result, { ...result, result: '{"v":"3" }' });
  assert.throws(() => fork.collectionInputs(ex, run), /RESULT_DIGEST/);
  write(EXCHANGE.result, { ...result, topic: 'ff'.repeat(32) });
  assert.throws(() => fork.collectionInputs(ex, run), /IDENTITY_MISMATCH/);
  write(EXCHANGE.result, result);
  write(EXCHANGE.run, { run, chain: 'eip155:137' });
  assert.throws(() => fork.collectionInputs(ex, run), /RUN_MISMATCH/);
});

test('guarded wallet: a send needs the exact durable reservation and refuses after a sent record; persist is write-once', async () => {
  const dir = tmp();
  let forwarded = 0;
  const rpc = async (method) => { if (method === 'eth_sendTransaction') forwarded++; return method === 'eth_chainId' ? '0x89' : '0x' + '11'.repeat(32); };
  const wallet = fork.guardedWallet({ rpc, account: ACCOUNT, dir });
  const request = { chainId: '0x89', from: ACCOUNT, to: SAFE, value: '0x0', data: '0x6a761202' };
  await assert.rejects(wallet.provider.request({ method: 'eth_sendTransaction', params: [request] }), (e) => e.code === 4100);
  fork.persist(dir, fork.FILES.attempt, { state: 'SENDING', request });
  assert.throws(() => fork.persist(dir, fork.FILES.attempt, { state: 'SENDING', request }), /EXISTS:attempt.json/);
  await assert.rejects(wallet.provider.request({ method: 'eth_sendTransaction', params: [{ ...request, data: '0x6a761203' }] }), (e) => e.code === 4100);
  await assert.rejects(wallet.provider.request({ method: 'eth_sendTransaction', params: [{ ...request, gas: '0x1' }] }), (e) => e.code === 4100);
  assert.equal(forwarded, 0); assert.equal(wallet.sends, 0);
  assert.match(await wallet.provider.request({ method: 'eth_sendTransaction', params: [request] }), /^0x11/);
  assert.equal(forwarded, 1); assert.equal(wallet.sends, 1);
  fork.persist(dir, fork.FILES.sent, { transactionHash: '0x' + '11'.repeat(32) });
  await assert.rejects(wallet.provider.request({ method: 'eth_sendTransaction', params: [request] }), /already sent/);
  await assert.rejects(wallet.provider.request({ method: 'eth_sign', params: [] }), (e) => e.code === 4200);
  assert.deepEqual(await wallet.provider.request({ method: 'eth_accounts' }), [ACCOUNT]);
});

test('extractWire and the fixture context: the home fixture Signer row and the Web candidate agree', () => {
  const request = { raw: '{"jsonrpc":"2.0","id":1,"method":"p256_signSafeRequestV3","params":[{"v":"3"}]}' };
  assert.equal(fork.extractWire(request, { params: '[{"v":"3"}]' }), '{"v":"3"}');
  assert.throws(() => fork.extractWire(request, { params: '[{"v":"3" }]' }), /PARAMS_MISMATCH/);
  assert.equal(fork.FIXTURE_HANDOFF.expectedAddress, '0x0e16A8196C3CFA5b9539181f60EB5Ab2784fe227');
  assert.equal(fork.FIXTURE_HANDOFF.keyID, '698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be');
  assert.equal(fork.FIXTURE_INTENT.recipient, '0x' + '33'.repeat(19) + '01');
});
