// Genuine local EVM execution of the production prefund path: a private loopback Anvil (no fork, no external URL) with
// the pinned frozen EntryPoint v0.7 runtime, HybridDeleGator v1.3.0/SCL runtimes and a real ERC1967 proxy Signer. The
// actual prefund-model/prefund-controller/prefund-attempt-store and key-reader run unchanged over raw node receipts;
// the wallet adapter captures each controller-prepared send unchanged and, like a wallet, applies its own local
// execution defaults only to missing fields of its forwarded copy (both pages send five-key requests without
// outer gas, fees or nonce). Nothing here manufactures receipts, events or
// balances. SOFTWARE keys and local EVM only: not Polygon, a user wallet, relay or device evidence.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import ethers from '../vendor/ethers.js';
import { ENTRYPOINT, IMPLEMENTATION, PROXY_RUNTIME_HASH, SELECTORS } from '../key-model.js';
import { readContext } from '../key-reader.js';
import { KeyChangeController } from '../key-controller.js';
import { KeyAttemptStore } from '../key-attempt-store.js';
import { PrefundController } from '../prefund-controller.js';
import { FundingAttemptStore } from '../prefund-attempt-store.js';
import { DEPOSITED_EVENT, ENTRYPOINT_RUNTIME_HASH, depositCall, parseFundingAttempt } from '../prefund-model.js';
import { memoryIndexedDB } from './support/memory-idb.mjs';
import { memorySavedResults } from './support/key-world.mjs';
import { K1, K2, anchorText, bareKeyText, contextWire, nativeClient, nativeSign, softwareKey } from './support/key-fixtures.mjs';

const U = ethers.utils;
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const ENTRY_FIXTURE = path.join(root, 'tests/fixtures/EntryPoint');
const HYBRID_FIXTURE = path.join(root, 'tests/fixtures/HybridCodec');
const OUT = process.env.PREFUND_EVM_OUT || null;
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const k1 = softwareKey(K1), k2 = softwareKey(K2);
const P = 1060000n * 1000000000n;
const now = () => Math.floor(Date.now() / 1000);
const show = (v) => JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? x.toString() : x));
let anvil, port, rpcId = 0, signer, funder, executor, other, anvilVersion;
const captured = { steps: [], payloads: [], controls: [], fixtures: {} };

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
const setupSend = async (tx) => waitReceipt(await rpc('eth_sendTransaction', [tx]));
const depositOf = async (tag = 'latest') => BigInt(await rpc('eth_call', [{ to: ENTRYPOINT,
  data: SELECTORS.balanceOf + '00'.repeat(12) + signer.slice(2) }, tag]));

before(async () => {
  const manifest = JSON.parse(readFileSync(path.join(ENTRY_FIXTURE, 'manifest.json')));
  const snapshot = readFileSync(path.join(ENTRY_FIXTURE, 'entrypoint-runtime.json'));
  assert.equal(sha256(snapshot), '0d7cae8cf70eb2c61f9f73800c38c990a5d1316e26a1d47e4c8fd9537bf9fed0');
  assert.equal(manifest.snapshotSHA256, sha256(snapshot));
  const entry = JSON.parse(snapshot);
  assert.equal(U.keccak256(entry.runtime), ENTRYPOINT_RUNTIME_HASH);
  assert.equal(sha256(Buffer.from(entry.runtime.slice(2), 'hex')), manifest.runtimeSHA256);
  assert.equal(sha256(readFileSync(path.join(ENTRY_FIXTURE, 'LICENSE-GPL-3.0'))), manifest.licenseSHA256);
  const hybridManifest = JSON.parse(readFileSync(path.join(HYBRID_FIXTURE, 'manifest.json')));
  const hybridBytes = readFileSync(path.join(HYBRID_FIXTURE, 'hybrid-runtime.json'));
  assert.equal(sha256(hybridBytes), hybridManifest.files['hybrid-runtime.json']);
  const hybrid = JSON.parse(hybridBytes).contracts;
  captured.fixtures = { entrypointSnapshotSHA256: sha256(snapshot), entrypointRuntimeKeccak256: U.keccak256(entry.runtime),
    hybridSHA256: sha256(hybridBytes) };

  const which = spawnSync('anvil', ['--version'], { encoding: 'utf8' });
  assert.equal(which.status, 0, 'locally installed anvil is required');
  anvilVersion = which.stdout.split('\n')[0];
  port = await freePort();
  anvil = spawn('anvil', ['--host', '127.0.0.1', '--port', String(port), '--chain-id', '137', '--hardfork', 'cancun',
    '--gas-limit', '12000000', '--base-fee', '0', '--gas-price', '1000000000', '--accounts', '4', '--quiet'],
  { stdio: ['ignore', 'ignore', 'pipe'] });
  let ready = false;
  for (let i = 0; i < 200 && !ready; i++) {
    try { ready = (await rpc('eth_chainId')) === '0x89'; } catch { await new Promise((r) => setTimeout(r, 25)); }
  }
  assert.ok(ready, 'anvil healthcheck');
  [funder, executor, other] = (await rpc('eth_accounts')).map((a) => a.toLowerCase());
  for (const [address, code, hash] of [[ENTRYPOINT, entry.runtime, entry.runtimeKeccak256],
    [hybrid.hybrid.address, hybrid.hybrid.runtime, hybrid.hybrid.keccak256],
    [hybrid.scl.address, hybrid.scl.runtime, hybrid.scl.keccak256]]) {
    await rpc('anvil_setCode', [address, code]);
    assert.equal(U.keccak256(await rpc('eth_getCode', [address, 'latest'])), hash, address);
  }
  assert.equal(hybrid.hybrid.address, IMPLEMENTATION);
  const init = new U.Interface(['function initialize(address,string[],uint256[],uint256[])']).encodeFunctionData(
    'initialize', [ethers.constants.AddressZero, [k1.keyId], ['0x' + k1.publicKey.slice(4, 68)],
      ['0x' + k1.publicKey.slice(68)]]);
  const deploy = hybrid.proxy.creationCode + U.defaultAbiCoder.encode(['address', 'bytes'], [IMPLEMENTATION, init]).slice(2);
  const created = await setupSend({ from: funder, data: deploy, gas: '0x7a1200' });
  assert.equal(created.status, '0x1');
  signer = created.contractAddress.toLowerCase();
  assert.equal(U.keccak256(await rpc('eth_getCode', [signer, 'latest'])), PROXY_RUNTIME_HASH);
  assert.equal(await depositOf(), 0n);
});

after(async () => {
  if (anvil) {
    const exit = new Promise((resolve) => anvil.once('exit', (code, sig) => resolve({ code, sig })));
    anvil.kill('SIGTERM');
    captured.anvil = { version: anvilVersion, exit: await exit };
  }
  if (OUT) {
    mkdirSync(OUT, { recursive: true });
    writeFileSync(path.join(OUT, 'prefund-evm-capture.json'), show(captured));
  }
});

/** The wallet's own deterministic local execution choices (gas 100000, max fee and priority 2 Gwei). */
const WALLET_DEFAULTS = Object.freeze({ gas: '0x186a0', maxFeePerGas: '0x77359400', maxPriorityFeePerGas: '0x77359400' });
const PREFUND_KEYS = 'chainId,data,from,to,value';

/**
 * Wallet adapter: forwards ONLY controller-prepared calls to an Anvil software account; optionally loses the answer.
 * `sends`/`payloads` keep the application's original request; `execution` overrides the wallet's own choices.
 */
function evmWallet(account) {
  const wallet = {
    status: 'connected', chainId: '0x89', account, generation: 1, selectedId: 'anvil', error: null, pairing: null,
    sends: [], forwarded: [], execution: {}, loseResponse: false,
    choices: () => [{ id: 'anvil', name: 'Anvil software wallet', kind: 'legacy', disabled: false, reason: null }],
    snapshot: () => ({ status: wallet.status, chainId: wallet.chainId, account: wallet.account, selectedId: 'anvil',
      choices: wallet.choices(), generation: wallet.generation, error: null, pairing: null,
      walletConnect: { enabled: false, reason: 'missing-id' } }),
    switchPolygon: async () => {},
    async request(method, params) {
      if (method === 'eth_chainId') return rpc('eth_chainId');
      assert.equal(method, 'eth_sendTransaction');
      wallet.sends.push(structuredClone(params[0]));
      captured.payloads.push(structuredClone(params[0]));
      const tx = { ...params[0] };
      for (const [key, value] of Object.entries({ ...WALLET_DEFAULTS, ...wallet.execution })) {
        if (tx[key] === undefined && !(key !== 'gas' && tx.gasPrice !== undefined)) tx[key] = value;
      }
      delete tx.chainId;
      if (wallet.beforeForward) await wallet.beforeForward();
      wallet.forwarded.push(structuredClone(tx));
      const hash = await rpc('eth_sendTransaction', [tx]);
      if (wallet.loseResponse) { wallet.lostHash = hash; throw new Error('wallet response lost'); }
      return hash;
    },
  };
  return wallet;
}

function prefundFor(store, account = funder) {
  const wallet = evmWallet(account);
  const controller = new PrefundController({ rpc, wallet, store, clock: now, uuid: () => crypto.randomUUID() });
  return { controller, wallet };
}

async function review(controller, { fee = '1' } = {}) {
  await controller.start();
  controller.setAuthorityText(anchorText(signer, k1));
  await controller.inspect();
  controller.setFee(fee);
  return controller.view();
}

async function captureStep(step, hash, extra = {}) {
  const receipt = await rpc('eth_getTransactionReceipt', [hash]);
  const transaction = await rpc('eth_getTransactionByHash', [hash]);
  const block = await rpc('eth_getBlockByNumber', [receipt.blockNumber, false]);
  assert.equal(transaction.blockHash, receipt.blockHash);
  assert.equal(block.hash, receipt.blockHash);
  captured.steps.push({ step, transaction, receipt, block, currentDeposit: (await depositOf()).toString(),
    blockDeposit: (await depositOf(receipt.blockNumber)).toString(), ...extra });
}

let store;

test('shortfall exact deposit: production controller funds Q for the native Signer context and proves the event', async () => {
  store = new FundingAttemptStore({ indexedDB: memoryIndexedDB() });
  const { controller, wallet } = prefundFor(store);
  const view = await review(controller);
  assert.equal(view.row, 'PF12-ready', view.row);
  assert.equal(view.plan.required, P);
  assert.equal(view.plan.deposit, 0n);
  assert.equal(view.plan.amount, P);
  assert.equal(view.context.entryPointCodeHash, ENTRYPOINT_RUNTIME_HASH);
  const before = { deposit: await depositOf(), wallet: BigInt(await rpc('eth_getBalance', [funder, 'latest'])) };
  await controller.send();
  assert.equal(wallet.sends.length, 1);
  // The app sent exactly five keys; gas and fees are the wallet's own choices on its forwarded copy.
  assert.equal(Object.keys(wallet.sends[0]).sort().join(), PREFUND_KEYS);
  assert.deepEqual(wallet.sends[0], { from: funder, to: ENTRYPOINT, value: '0x' + P.toString(16), data: depositCall(signer),
    chainId: '0x89' });
  assert.deepEqual(wallet.forwarded[0], { from: funder, to: ENTRYPOINT, value: '0x' + P.toString(16),
    data: depositCall(signer), ...WALLET_DEFAULTS });
  assert.equal(controller.view().attempt.record.status, 'hashKnown');
  assert.equal(controller.view().attempt.record.version, 2);
  await controller.reconcile();
  assert.equal(controller.view().row, 'PF16-one-confirmation');
  await rpc('evm_mine');
  await controller.reconcile();
  const done = controller.view();
  assert.equal(done.row, 'PF19-success-ready', show(done.attempt.outcome));
  const record = done.attempt.record;
  const rc = await rpc('eth_getTransactionReceipt', [record.transactionHash]);
  assert.equal(rc.logs.length, 1);
  assert.equal(rc.logs[0].topics[0], DEPOSITED_EVENT);
  assert.equal(await depositOf(), P);
  const gasCost = BigInt(rc.gasUsed) * BigInt(rc.effectiveGasPrice);
  assert.equal(before.wallet - BigInt(await rpc('eth_getBalance', [funder, 'latest'])), P + gasCost);
  assert.equal(record.outcome.actualGasCost, gasCost.toString());
  assert.equal(record.outcome.walletNonce, BigInt((await rpc('eth_getTransactionByHash', [record.transactionHash])).nonce).toString());
  assert.equal(record.outcome.totalDeposit, P.toString());
  assert.equal(done.attempt.outcome.current.deposit, P);
  await captureStep('shortfall-deposit', record.transactionHash, { amount: P.toString(), gasCost: gasCost.toString(),
    depositBefore: before.deposit.toString(), totalDeposit: record.outcome.totalDeposit });
});

test('second inspection with zero shortage refuses funding with no wallet invocation', async () => {
  const { controller, wallet } = prefundFor(store);
  await controller.start();
  assert.equal(controller.view().row, 'PF22-terminal');
  await controller.newFunding();
  assert.equal(controller.view().row, 'PF23-new-attempt');
  const view = await review(controller);
  assert.equal(view.row, 'PF06-sufficient');
  assert.equal(view.plan.amount, 0n);
  await controller.send();
  assert.equal(wallet.sends.length, 0);
  captured.steps.push({ step: 'zero-shortage-no-send', currentDeposit: (await depositOf()).toString(),
    block: await rpc('eth_getBlockByNumber', ['latest', false]), sends: 0 });
});

test('funded deposit pays a real local key-change handleOps; funding itself never proves key-change success', async () => {
  const keyStore = new KeyAttemptStore({ indexedDB: memoryIndexedDB() });
  const binding = '0x' + createHash('sha256').update(k1.keyId).digest('hex');
  const peer = {
    signer, signs: 0,
    async context() {
      const chain = await readContext(rpc, { signer, authorizer: k1, now });
      return contextWire({ signer, key: k1, binding, chain: { keys: chain.keys, nonce: chain.nonce,
        blockNumber: chain.block.number, blockHash: chain.block.hash } });
    },
    async sign(envelope) { peer.signs++; return nativeSign({ envelope, key: k1, binding }); },
  };
  const { SignClient } = nativeClient(peer);
  const wallet = evmWallet(executor);
  wallet.execution = { gas: '0x2191c0' }; // handleOps uses the key wallet's 2200000-gas choice, not depositTo's default.
  // Real closed unsigned serializer; browser durability is exercised by the storage suites.
  const savedResultStore = memorySavedResults();
  const sign = peer.sign;
  peer.sign = async (envelope) => {
    assert.ok((await savedResultStore.list()).some((r) => r.envelope === envelope), 'unsigned inputs saved before signing');
    return sign(envelope);
  };
  const keys = new KeyChangeController({ rpc, wallet, store: keyStore, savedResultStore, clock: now, uuid: () => crypto.randomUUID(),
    loadSignClient: async () => SignClient, loadConfig: async () => ({ walletConnectProjectId: 'ab'.repeat(16) }) });
  await keys.loadAttempt();
  keys.setAnchorText(anchorText(signer, k1));
  await keys.inspect();
  keys.setChange({ mode: 'add', bareText: bareKeyText(k2), feeMax: '1', feePriority: '1' });
  assert.equal(keys.view().problem, null, keys.view().row);
  assert.equal(keys.view().cost.shortfall, 0n);
  await keys.connectNative();
  await keys.previewNative();
  await keys.requestSignature();
  assert.equal(keys.view().native.phase, 'verified', keys.view().row);
  // The key-change page sends only from/to/data/value/chainId; the Anvil wallet chooses outer gas, fees and nonce.
  const depositBefore = await depositOf();
  await keys.send();
  // Both pages delegate outer fields to the wallet; only its forwarded copy has execution choices.
  assert.equal(Object.keys(wallet.sends[0]).sort().join(), PREFUND_KEYS);
  const { chainId, ...prepared } = wallet.sends[0];
  assert.equal(chainId, '0x89');
  assert.deepEqual(wallet.forwarded[0], { ...prepared, ...WALLET_DEFAULTS, ...wallet.execution });
  assert.equal((await waitReceipt(keys.view().attempt.record.transactionHash)).status, '0x1');
  await rpc('evm_mine');
  await keys.reconcile();
  assert.equal(keys.view().row, 'KW27', show(keys.view().attempt.outcome));
  const state = await readContext(rpc, { signer, now });
  assert.deepEqual(state.keys.map((k) => k.keyId).sort(), [k1.keyId, k2.keyId].sort());
  const consumed = depositBefore - await depositOf();
  assert.ok(consumed > 0n && consumed <= P);
  await captureStep('key-change-after-funding', keys.view().attempt.record.transactionHash,
    { depositConsumed: consumed.toString(), keys: state.keys.map((k) => k.keyId) });
  // The verified funding transaction stays proved while current readiness is now a separate, consumed observation.
  const { controller } = prefundFor(store);
  await controller.start();
  await controller.reconcile();
  assert.equal(controller.view().row, 'PF20-consumed', show(controller.view().attempt.outcome));
  assert.equal(controller.view().attempt.record.status, 'succeeded');
});

test('outer failure: a real status0 depositTo under a low gas cap is gas-only and unlocks only explicit new funding', async () => {
  const { controller, wallet } = prefundFor(store);
  await controller.start();
  await controller.newFunding();
  const view = await review(controller);
  assert.equal(view.row, 'PF12-ready', view.row);
  const before = await depositOf();
  // The WALLET (not the app) chooses an insufficient gas limit: a genuine status0 depositTo.
  wallet.execution = { gas: '0x59d8' };
  await controller.send();
  assert.equal(wallet.sends.length, 1);
  assert.equal(Object.keys(wallet.sends[0]).sort().join(), PREFUND_KEYS);
  assert.equal(wallet.forwarded[0].gas, '0x59d8');
  await rpc('evm_mine');
  await controller.reconcile();
  const done = controller.view();
  assert.equal(done.row, 'PF17-outer-failed', show(done.attempt.outcome));
  const rc = await rpc('eth_getTransactionReceipt', [done.attempt.record.transactionHash]);
  assert.equal(rc.status, '0x0');
  assert.equal(await depositOf(), before);
  assert.equal(done.attempt.outcome.costs.gasCost, BigInt(rc.gasUsed) * BigInt(rc.effectiveGasPrice));
  assert.equal(done.attempt.record.outcome.gasUsed, BigInt(rc.gasUsed).toString());
  assert.equal(done.actions.newFunding, true);
  await captureStep('outer-failure', done.attempt.record.transactionHash, { depositBefore: before.toString() });
});

test('unknown wallet response never causes a second funding; the exact hash reconciles; a foreign tuple is refused', async () => {
  const { controller, wallet } = prefundFor(store);
  await controller.start();
  await controller.newFunding();
  await review(controller);
  wallet.loseResponse = true;
  const depositBefore = await depositOf();
  await controller.send();
  assert.equal(controller.view().row, 'PF15-error');
  assert.equal(wallet.sends.length, 1);
  await rpc('evm_mine');
  // The chain shows the nonce advanced and the deposit changed: still no new funding and no resend.
  assert.ok(await depositOf() > depositBefore);
  await controller.send();
  await controller.newFunding();
  const reloaded = prefundFor(store);
  await reloaded.controller.start();
  assert.equal(reloaded.controller.view().row, 'PF22-reserved');
  await reloaded.controller.send();
  await reloaded.controller.newFunding();
  assert.equal(wallet.sends.length + reloaded.wallet.sends.length, 1);
  // A real depositTo from a different wallet account with a different value is not this attempt.
  const foreign = await setupSend({ from: other, to: ENTRYPOINT, value: '0x1', data: depositCall(signer), gas: '0x186a0' });
  assert.equal(foreign.status, '0x1');
  await rpc('evm_mine');
  reloaded.controller.setLookupHash(foreign.transactionHash);
  await reloaded.controller.reconcile();
  assert.equal(reloaded.controller.view().row, 'PF18-foreign-tuple');
  assert.equal(parseFundingAttempt((await store.read()).raw).status, 'unknown');
  captured.controls.push({ name: 'foreign-wallet-tuple', transactionHash: foreign.transactionHash,
    from: foreign.from, view: 'PF18-foreign-tuple' });
  reloaded.controller.setLookupHash(wallet.lostHash);
  await reloaded.controller.reconcile();
  const view = reloaded.controller.view();
  assert.equal(view.row, 'PF19-success-ready', show(view.attempt.outcome));
  assert.equal(view.attempt.record.transactionHash, wallet.lostHash);
  await captureStep('unknown-then-reconciled', wallet.lostHash, { sends: wallet.sends.length + reloaded.wallet.sends.length });
});

test('wallet-owned nonce and fees above old caps: a real v2 deposit with a differing nonce and higher fees settles', async () => {
  const { controller, wallet } = prefundFor(store);
  await controller.start();
  await controller.newFunding();
  assert.equal(controller.view().row, 'PF23-new-attempt');
  // A higher inner fee makes P exceed the current deposit, so a positive shortage exists again.
  const view = await review(controller, { fee: '3' });
  assert.equal(view.row, 'PF12-ready', view.row);
  const hint = BigInt(await rpc('eth_getTransactionCount', [funder, 'pending']));
  // After the app's pending-nonce lookup the wallet itself first sends another of its own transactions.
  wallet.beforeForward = async () => { wallet.beforeForward = null; await setupSend({ from: funder, to: other, value: '0x1' }); };
  wallet.execution = { gas: '0x30d40', maxFeePerGas: '0x12a05f200', maxPriorityFeePerGas: '0x3b9aca00' };
  await controller.send();
  assert.equal(Object.keys(wallet.sends[0]).sort().join(), PREFUND_KEYS);
  await rpc('evm_mine');
  await controller.reconcile();
  const done = controller.view();
  assert.equal(done.row, 'PF19-success-ready', show(done.attempt.outcome));
  const record = done.attempt.record;
  const tx = await rpc('eth_getTransactionByHash', [record.transactionHash]);
  assert.equal(record.version, 2);
  assert.equal(record.walletPendingNonce, hint.toString());
  assert.equal(record.outcome.walletNonce, BigInt(tx.nonce).toString());
  assert.notEqual(record.outcome.walletNonce, record.walletPendingNonce);
  assert.equal(BigInt(tx.gas), 200000n);
  assert.ok(BigInt(tx.maxFeePerGas) > 1000000000n, 'above the old 1 Gwei fixture cap');
});
