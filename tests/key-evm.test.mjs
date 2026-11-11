// Genuine local EVM execution of the production key-change path (references/local-evm-contract.md): a private
// loopback Anvil (no fork, no external URL) with the frozen EntryPoint v0.7, HybridDeleGator v1.3.0 and SCL runtimes
// and a real ERC1967 proxy. The actual key-model/key-reader/key-controller/key-attempt-store run unchanged; the wallet
// adapter asserts the exact five-field production request and then, as a standard wallet does, chooses its own
// coherent outer gas/fees before forwarding it to an Anvil software account; the native adapter only answers
// with software-key context/results. Neither manufactures receipts, keys or events. SOFTWARE keys, local EVM only:
// not Polygon, relay, user wallet, Secure Enclave or physical-authentication evidence.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import ethers from '../vendor/ethers.js';
import {
  ENTRYPOINT, IMPLEMENTATION, PROXY_RUNTIME_HASH, SELECTORS, USER_OPERATION_EVENT, addKeyCall, executeCall,
  handleOpsCall, keyIdHash, packHigh, removeKeyCall, typedDataHash, userOpHash,
} from '../key-model.js';
import { readContext } from '../key-reader.js';
import { KeyChangeController, matchingEvent } from '../key-controller.js';
import { KeyAttemptStore } from '../key-attempt-store.js';
import { memoryIndexedDB } from './support/memory-idb.mjs';
import { memorySavedResults } from './support/key-world.mjs';
import {
  K1, K2, anchorText, bareKeyText, contextWire, nativeClient, nativeSign, signRaw, softwareKey,
} from './support/key-fixtures.mjs';

const U = ethers.utils;
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const ENTRY_FIXTURE = path.join(root, 'tests/fixtures/EntryPoint');
const HYBRID_FIXTURE = path.join(root, 'tests/fixtures/HybridCodec');
const OUT = process.env.KEY_EVM_OUT || null;
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const k1 = softwareKey(K1), k2 = softwareKey(K2), k3 = softwareKey((K2 * 7n + 11n) % 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n);
const GWEI = '1';
/** Wallet-chosen outer parameters (higher than the former 1 gwei app ceiling, dynamic and legacy shapes). */
const WALLET_DYNAMIC = { gas: '0x2191c0', maxFeePerGas: '0xb2d05e00', maxPriorityFeePerGas: '0x77359400' };
const WALLET_LEGACY = { gas: '0x2dc6c0', gasPrice: '0xb2d05e00' };
let anvil, port, rpcId = 0, signer, executor, funder, anvilVersion;
const captured = { steps: [], controls: [], receipts: [], blocks: [], payloads: [], points: { k1: k1.publicKey, k2: k2.publicKey }, costs: [] };

async function rpc(method, params = []) {
  const response = await fetch(`http://127.0.0.1:${port}`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }) });
  const body = await response.json();
  if (body.error) throw Object.assign(new Error(body.error.message), { code: body.error.code, data: body.error.data });
  return body.result;
}
const freePort = () => new Promise((resolve) => {
  const server = createServer();
  server.listen(0, '127.0.0.1', () => { const { port: p } = server.address(); server.close(() => resolve(p)); });
});
async function waitReceipt(hash) {
  for (let i = 0; i < 100; i++) {
    const r = await rpc('eth_getTransactionReceipt', [hash]);
    if (r) return r;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('no receipt');
}
async function setupSend(tx) { return waitReceipt(await rpc('eth_sendTransaction', [tx])); }
const now = () => Math.floor(Date.now() / 1000);
const show = (v) => JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? x.toString() : x));

before(async () => {
  // Pinned tracked authority, validated before use.
  const manifest = JSON.parse(readFileSync(path.join(ENTRY_FIXTURE, 'manifest.json')));
  const snapshot = readFileSync(path.join(ENTRY_FIXTURE, 'entrypoint-runtime.json'));
  assert.equal(sha256(snapshot), '0d7cae8cf70eb2c61f9f73800c38c990a5d1316e26a1d47e4c8fd9537bf9fed0');
  assert.equal(manifest.snapshotSHA256, sha256(snapshot));
  const entry = JSON.parse(snapshot);
  const entryRuntime = Buffer.from(entry.runtime.slice(2), 'hex');
  assert.equal(sha256(entryRuntime), '674d73ee2acf6d72a5b32b6e05150b9ddcfcee0429a0e7914929faccbc2bf4d5');
  assert.equal(U.keccak256(entry.runtime), '0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58');
  assert.equal(entryRuntime.length, 16035);
  assert.equal(sha256(readFileSync(path.join(ENTRY_FIXTURE, 'LICENSE-GPL-3.0'))), manifest.licenseSHA256);
  const hybridManifest = JSON.parse(readFileSync(path.join(HYBRID_FIXTURE, 'manifest.json')));
  const hybridBytes = readFileSync(path.join(HYBRID_FIXTURE, 'hybrid-runtime.json'));
  assert.equal(sha256(hybridBytes), hybridManifest.files['hybrid-runtime.json']);
  const hybrid = JSON.parse(hybridBytes).contracts;

  const which = spawnSync('anvil', ['--version'], { encoding: 'utf8' });
  assert.equal(which.status, 0, 'locally installed anvil is required');
  anvilVersion = which.stdout.split('\n')[0];
  port = await freePort();
  anvil = spawn('anvil', ['--host', '127.0.0.1', '--port', String(port), '--chain-id', '137', '--hardfork', 'cancun',
    '--gas-limit', '12000000', '--base-fee', '0', '--gas-price', '1000000000', '--accounts', '2', '--quiet'],
  { stdio: ['ignore', 'ignore', 'pipe'] });
  let ready = false;
  for (let i = 0; i < 200 && !ready; i++) {
    try { ready = (await rpc('eth_chainId')) === '0x89'; } catch { await new Promise((r) => setTimeout(r, 25)); }
  }
  assert.ok(ready, 'anvil healthcheck');
  [funder, executor] = (await rpc('eth_accounts')).map((a) => a.toLowerCase());

  for (const [address, code, hash] of [[ENTRYPOINT, entry.runtime, entry.runtimeKeccak256],
    [hybrid.hybrid.address, hybrid.hybrid.runtime, hybrid.hybrid.keccak256],
    [hybrid.scl.address, hybrid.scl.runtime, hybrid.scl.keccak256]]) {
    await rpc('anvil_setCode', [address, code]);
    assert.equal(U.keccak256(await rpc('eth_getCode', [address, 'latest'])), hash, address);
  }
  assert.equal(hybrid.hybrid.address, IMPLEMENTATION);
  // Cancun has no P256 precompile at 0x100: the genuine SCL fallback verifies.
  assert.equal(await rpc('eth_call', [{ to: '0x' + '0'.repeat(37) + '100', data: '0x' + '00'.repeat(160) }, 'latest']), '0x');

  const init = new U.Interface(['function initialize(address,string[],uint256[],uint256[])']).encodeFunctionData(
    'initialize', [ethers.constants.AddressZero, [k1.keyId], ['0x' + k1.publicKey.slice(4, 68)],
      ['0x' + k1.publicKey.slice(68)]]);
  const deploy = hybrid.proxy.creationCode + U.defaultAbiCoder.encode(['address', 'bytes'], [IMPLEMENTATION, init]).slice(2);
  const created = await setupSend({ from: funder, data: deploy, gas: '0x7a1200' });
  assert.equal(created.status, '0x1');
  signer = created.contractAddress.toLowerCase();
  assert.equal(U.keccak256(await rpc('eth_getCode', [signer, 'latest'])), PROXY_RUNTIME_HASH);
});

after(async () => {
  if (anvil) {
    const exit = new Promise((resolve) => anvil.once('exit', (code, sig) => resolve({ code, sig })));
    anvil.kill('SIGTERM');
    captured.anvil = { version: anvilVersion, exit: await exit };
  }
  if (OUT) {
    mkdirSync(OUT, { recursive: true });
    writeFileSync(path.join(OUT, 'key-evm-capture.json'), JSON.stringify(captured, (k, v) => (typeof v === 'bigint'
      ? v.toString() : v), 2));
  }
});

async function captureStep(step, hash, state, costs = null) {
  const receipt = await rpc('eth_getTransactionReceipt', [hash]);
  const transaction = await rpc('eth_getTransactionByHash', [hash]);
  const block = await rpc('eth_getBlockByNumber', [receipt.blockNumber, false]);
  assert.equal(transaction.blockHash, receipt.blockHash);
  assert.equal(block.hash, receipt.blockHash);
  captured.steps.push({ step, transaction, receipt, block,
    keys: state.keys, nonce: state.nonce, costs });
}

/**
 * Wallet adapter: accepts ONLY a controller-prepared eth_sendTransaction with exactly from/to/data/value/chainId,
 * then adds its own outer gas/fees (`fees`) and forwards it to the Anvil executor account. Anvil picks the nonce.
 */
function evmWallet(fees = WALLET_DYNAMIC) {
  const wallet = {
    status: 'connected', chainId: '0x89', account: executor, generation: 1, selectedId: 'anvil', error: null,
    pairing: null, sends: [], fees,
    choices: () => [{ id: 'anvil', name: 'Anvil software executor', kind: 'legacy', disabled: false }],
    snapshot: () => ({ status: wallet.status, chainId: wallet.chainId, account: wallet.account, selectedId: 'anvil',
      choices: wallet.choices(), generation: wallet.generation, error: null, pairing: null }),
    switchPolygon: async () => {},
    async request(method, params) {
      assert.equal(method, 'eth_sendTransaction');
      wallet.sends.push(params[0]);
      assert.equal(params.length, 1);
      assert.deepEqual(Object.keys(params[0]).sort(), ['chainId', 'data', 'from', 'to', 'value']);
      assert.equal(params[0].chainId, '0x89');
      const tx = { ...params[0], ...wallet.fees };
      delete tx.chainId;
      return rpc('eth_sendTransaction', [tx]);
    },
  };
  return wallet;
}

/** Native adapter: software-key context from an independent chain read and software signing of the exact envelope. */
function nativePeer(key, binding = '0x' + createHash('sha256').update(key.keyId).digest('hex')) {
  const peer = {
    signer, signs: 0,
    async context() {
      const chain = await readContext(rpc, { signer, authorizer: key, now });
      return contextWire({ signer, key, binding, chain: { keys: chain.keys, nonce: chain.nonce,
        blockNumber: chain.block.number, blockHash: chain.block.hash } });
    },
    async sign(envelope) {
      peer.signs++;
      const result = await nativeSign({ envelope, key, binding });
      captured.payloads.push(JSON.parse(envelope));
      signatures.push(result.signerSignature);
      return result;
    },
  };
  return peer;
}

function controllerFor(store, key, wallet = evmWallet()) {
  const peer = nativePeer(key);
  const { SignClient } = nativeClient(peer);
  // Adapter evidence only: closed unsigned serialization, not browser durability.
  const savedResultStore = memorySavedResults();
  const sign = peer.sign;
  peer.sign = async (envelope) => {
    assert.ok((await savedResultStore.list()).some((r) => r.envelope === envelope), 'unsigned inputs saved before signing');
    return sign(envelope);
  };
  const controller = new KeyChangeController({ rpc, wallet, store, savedResultStore, clock: now, uuid: () => crypto.randomUUID(),
    loadSignClient: async () => SignClient, loadConfig: async () => ({ walletConnectProjectId: 'ab'.repeat(16) }) });
  return { controller, wallet, peer };
}

async function deposit(amount) {
  const data = U.id('depositTo(address)').slice(0, 10) + '00'.repeat(12) + signer.slice(2);
  assert.equal((await setupSend({ from: funder, to: ENTRYPOINT, data, value: '0x' + amount.toString(16) })).status, '0x1');
}
const depositOf = async () => BigInt(await rpc('eth_call', [{ to: ENTRYPOINT,
  data: SELECTORS.balanceOf + '00'.repeat(12) + signer.slice(2) }, 'latest']));
const balanceOf = async (a) => BigInt(await rpc('eth_getBalance', [a, 'latest']));

/** Drives one explicit add/remove through the production controller up to the verified signature. */
async function approve(controller, key, change) {
  controller.setAnchorText(anchorText(signer, key));
  await controller.inspect();
  assert.equal(controller.view().inspection, 'ready');
  controller.setChange({ ...change, feeMax: GWEI, feePriority: GWEI });
  await controller.connectNative();
  assert.equal(controller.view().row, 'KW11');
  await controller.previewNative();
  assert.match(controller.view().row, /^KW1[23]$/);
  await controller.requestSignature();
  assert.equal(controller.view().native.phase, 'verified', controller.view().row);
}

const P_REQUIRED = 1060000n * 1000000000n;
let store;
const signatures = [];

test('insufficient deposit blocks request and send without any wallet or native invocation', async () => {
  store = new KeyAttemptStore({ indexedDB: memoryIndexedDB() });
  const { controller, wallet, peer } = controllerFor(store, k1);
  await controller.loadAttempt();
  controller.setAnchorText(anchorText(signer, k1));
  await controller.inspect();
  controller.setChange({ mode: 'add', bareText: bareKeyText(k2), feeMax: GWEI, feePriority: GWEI });
  const view = controller.view();
  assert.equal(view.row, 'KW09');
  assert.equal(view.cost.required, P_REQUIRED);
  assert.equal(view.cost.shortfall, P_REQUIRED);
  assert.equal(view.actions.connectNative, false);
  await controller.connectNative();
  await controller.send();
  assert.equal(peer.signs, 0);
  assert.equal(wallet.sends.length, 0);
  // Over-uint120 inner fees are refused in production before any wallet call (AA94 is separately exercised below).
  controller.setChange({ feeMax: String((1n << 120n) / 1000000000n + 1n) });
  assert.equal(controller.view().row, 'KW08-bounds');
});

test('add k2: real handleOps through the production controller, exact event, keys, nonce and costs', async () => {
  await deposit(P_REQUIRED);
  const { controller, wallet, peer } = controllerFor(store, k1);
  await controller.loadAttempt();
  await approve(controller, k1, { mode: 'add', bareText: bareKeyText(k2) });
  const signed = controller.view().signed;
  const op = signed.request.operation;
  // Independent onchain cross-checks of H and the event hash.
  const hybridH = await rpc('eth_call', [{ to: signer, data: new U.Interface([
    'function getPackedUserOperationTypedDataHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes))'])
    .encodeFunctionData('getPackedUserOperationTypedDataHash', [[op.sender, op.nonce, op.initCode, op.callData,
      op.accountGasLimits, op.preVerificationGas, op.gasFees, op.paymasterAndData, '0x']]) }, 'latest']);
  assert.equal(hybridH, typedDataHash(op));
  const entryHash = await rpc('eth_call', [{ to: ENTRYPOINT, data: new U.Interface([
    'function getUserOpHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes))'])
    .encodeFunctionData('getUserOpHash', [[op.sender, op.nonce, op.initCode, op.callData, op.accountGasLimits,
      op.preVerificationGas, op.gasFees, op.paymasterAndData, '0x']]) }, 'latest']);
  assert.equal(entryHash, userOpHash(op));
  assert.notEqual(entryHash, typedDataHash(op));
  assert.equal(peer.signs, 1);

  assert.equal(controller.view().row, 'KW20');
  const depositBefore = await depositOf(), executorBefore = await balanceOf(executor);
  await controller.send();
  assert.equal(wallet.sends.length, 1);
  assert.equal(wallet.sends[0].to, ENTRYPOINT);
  assert.equal(wallet.sends[0].value, '0x0');
  assert.equal(wallet.sends[0].data, handleOpsCall(op, signed.signerSignature, executor));
  const record = controller.view().attempt.record;
  assert.equal(record.status, 'hashKnown');
  assert.equal(record.version, 2);
  assert.equal(record.walletPendingNonce, String(BigInt(await rpc('eth_getTransactionCount', [executor, 'pending'])) - 1n));
  assert.equal(record.beneficiary, executor);
  await controller.reconcile();
  assert.equal(controller.view().row, 'KW23-one');
  await rpc('evm_mine');
  await controller.reconcile();
  const view = controller.view();
  assert.equal(view.row, 'KW27', show(view.attempt.outcome));
  assert.equal(view.attempt.record.status, 'succeeded');
  const chain = await readContext(rpc, { signer, now });
  assert.deepEqual(chain.keys.map((k) => k.keyId).sort(), [k1.keyId, k2.keyId].sort());
  assert.equal(chain.nonce, 1n);
  // Cost relations in this controlled interval.
  const rc = await rpc('eth_getTransactionReceipt', [record.transactionHash]);
  captured.receipts.push(rc);
  captured.blocks.push(await rpc('eth_getBlockByNumber', [rc.blockNumber, false]));
  const event = matchingEvent(rc.logs.map((l) => ({ address: l.address.toLowerCase(), topics: l.topics, data: l.data })),
    view.attempt.record);
  assert.equal(event.success, true);
  const outerCost = BigInt(rc.gasUsed) * BigInt(rc.effectiveGasPrice);
  // The wallet's own fee choice is above the former 1 gwei ceiling; the signed inner budget is unchanged.
  const actualTx = await rpc('eth_getTransactionByHash', [record.transactionHash]);
  assert.equal(actualTx.maxFeePerGas, WALLET_DYNAMIC.maxFeePerGas);
  assert.ok(BigInt(rc.effectiveGasPrice) > 10n ** 9n);
  assert.ok(event.actualGasCost <= P_REQUIRED);
  assert.equal(depositBefore - await depositOf(), event.actualGasCost);
  assert.equal(executorBefore - await balanceOf(executor), outerCost - event.actualGasCost);
  assert.equal(view.costs.outerCost, outerCost);
  assert.equal(view.costs.actualGasCost, event.actualGasCost);
  captured.costs.push({ step: 'add-k2', outerCost, actualGasCost: event.actualGasCost });
  await captureStep('add-k2', record.transactionHash, chain, view.costs);
});

test('remove k1 authorized by k2: CAS rollover, fresh binding/request, valid self-removal settles', async () => {
  const { controller, wallet, peer } = controllerFor(store, k2);
  await controller.loadAttempt();
  assert.equal(controller.view().row, 'KW30-v2-terminal');
  assert.equal(controller.view().actions.connectNative, false);
  await controller.newChange();
  assert.ok(controller.view().rollover);
  const prior = controller.view().attempt.revision;
  await deposit(P_REQUIRED);
  await approve(controller, k2, { mode: 'remove', removeKeyId: k1.keyId });
  assert.equal(peer.signs, 1);
  await controller.send();
  assert.equal(wallet.sends.length, 1);
  assert.ok(controller.view().attempt.revision > prior);
  await rpc('evm_mine');
  await controller.reconcile();
  assert.equal(controller.view().row, 'KW28', show(controller.view().attempt.outcome));
  const chain = await readContext(rpc, { signer, now });
  assert.deepEqual(chain.keys.map((k) => k.keyId), [k2.keyId]);
  assert.equal(chain.nonce, 2n);
  await captureStep('remove-k1', controller.view().attempt.record.transactionHash, chain, controller.view().costs);
});

test('self-removal of the authorizing key (k2 removes itself after re-adding k1) verifies without membership', async () => {
  // This wallet chooses the legacy gasPrice fee shape.
  const { controller } = controllerFor(store, k2, evmWallet(WALLET_LEGACY));
  await controller.loadAttempt();
  await controller.newChange();
  await deposit(P_REQUIRED);
  await approve(controller, k2, { mode: 'add', bareText: bareKeyText(k1) });
  await controller.send();
  await rpc('evm_mine');
  await controller.reconcile();
  assert.equal(controller.view().row, 'KW27');
  await captureStep('re-add-k1', controller.view().attempt.record.transactionHash,
    await readContext(rpc, { signer, now }), controller.view().costs);
  await controller.newChange();
  await deposit(P_REQUIRED);
  await approve(controller, k2, { mode: 'remove', removeKeyId: k2.keyId });
  assert.equal(controller.view().selfRemoval, true);
  await controller.send();
  await rpc('evm_mine');
  await controller.reconcile();
  assert.equal(controller.view().row, 'KW28');
  const chain = await readContext(rpc, { signer, now });
  assert.deepEqual(chain.keys.map((k) => k.keyId), [k1.keyId]);
  await captureStep('self-remove-k2', controller.view().attempt.record.transactionHash, chain, controller.view().costs);
});

/** A directly signed operation (test-only, compiler bypass allowed) for the negative EVM controls. */
async function directOp({ key, nonce, inner, gasLimits = packHigh(700000n, 300000n), fees = packHigh(1000000000n, 1000000000n) }) {
  const op = { sender: signer, nonce: nonce.toString(), initCode: '0x', callData: executeCall(signer, inner),
    accountGasLimits: gasLimits, preVerificationGas: '60000', gasFees: fees, paymasterAndData: '0x', signature: '0x' };
  const raw = await signRaw(key, typedDataHash(op));
  return { op, signature: U.hexConcat([keyIdHash(key.keyId), raw]) };
}

test('controls: AA94, invalid signature, replay and inner last-key failure never change keys', async () => {
  const before = await readContext(rpc, { signer, now });
  const call = (data) => rpc('eth_call', [{ from: executor, to: ENTRYPOINT, data, gas: '0x2191c0' }, 'latest']);
  for (const [name, fields] of [
    ['verification-gas', { gasLimits: packHigh(1n << 120n, 300000n) }],
    ['call-gas', { gasLimits: packHigh(700000n, 1n << 120n) }],
    ['priority-fee', { fees: packHigh(1n << 120n, 1000000000n) }],
    ['max-fee', { fees: packHigh(1000000000n, 1n << 120n) }],
  ]) {
    const big = await directOp({ key: k1, nonce: before.nonce,
      inner: addKeyCall(k3.publicKey, k3.keyId), ...fields });
    let rejection;
    await assert.rejects(call(handleOpsCall(big.op, big.signature, executor)), (e) => {
      rejection = { message: e.message, data: e.data ?? null };
      return /AA94/.test(e.message + (e.data || ''));
    });
    const unchanged = await readContext(rpc, { signer, now });
    assert.deepEqual(unchanged.keys, before.keys);
    assert.equal(unchanged.nonce, before.nonce);
    captured.controls.push({ name, operation: big.op, rejection,
      nonce: unchanged.nonce, keys: unchanged.keys });
  }
  const forged = await directOp({ key: k3, nonce: before.nonce, inner: addKeyCall(k3.publicKey, k3.keyId) });
  await assert.rejects(call(handleOpsCall(forged.op, U.hexConcat([keyIdHash(k1.keyId), '0x' + forged.signature.slice(66)]),
    executor)), (e) => /AA24|AA23/.test(e.message + (e.data || '')));
  // Replay of the first, already executed, genuinely signed operation: its nonce is consumed.
  await assert.rejects(call(handleOpsCall(captured.payloads[0].body, signatures[0], executor)),
    (e) => /AA25/.test(e.message + (e.data || '')));
  // Inner failure: a compiler-bypassing removal of the only key (production planChange refuses it).
  await deposit(P_REQUIRED);
  const last = await directOp({ key: k1, nonce: before.nonce, inner: removeKeyCall(k1.keyId) });
  const rc = await setupSend({ from: executor, to: ENTRYPOINT, data: handleOpsCall(last.op, last.signature, executor),
    gas: '0x2191c0' });
  assert.equal(rc.status, '0x1');
  const record = { userOpHash: userOpHash(last.op), signer, signerNonce: last.op.nonce };
  const event = matchingEvent(rc.logs.map((l) => ({ address: l.address.toLowerCase(), topics: l.topics, data: l.data })),
    record);
  assert.equal(event.success, false);
  assert.ok(rc.logs.some((l) => l.topics[0] === USER_OPERATION_EVENT));
  const afterState = await readContext(rpc, { signer, now });
  assert.deepEqual(afterState.keys, before.keys);
  assert.equal(afterState.nonce, before.nonce + 1n);
  await captureStep('last-key-failure', rc.transactionHash, afterState);
});

test('a successful target event followed by another operation in the same block is a state conflict', async () => {
  const { controller, wallet } = controllerFor(store, k1);
  await controller.loadAttempt();
  await controller.newChange();
  assert.ok(controller.view().rollover, controller.view().row);
  await deposit(P_REQUIRED * 2n);
  await approve(controller, k1, { mode: 'add', bareText: bareKeyText(k2) });
  const nonce = BigInt(controller.view().signed.request.operation.nonce);
  await rpc('evm_setAutomine', [false]);
  try {
    await controller.send();
    assert.equal(wallet.sends.length, 1);
    const follow = await directOp({ key: k1, nonce: nonce + 1n, inner: addKeyCall(k3.publicKey, k3.keyId) });
    const followHash = await rpc('eth_sendTransaction', [{ from: funder, to: ENTRYPOINT,
      data: handleOpsCall(follow.op, follow.signature, funder), gas: '0x2191c0' }]);
    captured.followHash = followHash;
    await rpc('evm_mine');
    await rpc('evm_mine');
  } finally {
    await rpc('evm_setAutomine', [true]);
  }
  await controller.reconcile();
  const view = controller.view();
  assert.equal(view.row, 'KW26-same-block', show(view.attempt.outcome));
  assert.equal(view.attempt.record.status, 'uncertain');
  assert.notEqual(view.row, 'KW27');
  const state = await readContext(rpc, { signer, now });
  await captureStep('same-block-target', view.attempt.record.transactionHash, state, view.costs);
  await captureStep('same-block-follow', captured.followHash, state);
  assert.equal(captured.steps.at(-1).block.hash, captured.steps.at(-2).block.hash);
});
