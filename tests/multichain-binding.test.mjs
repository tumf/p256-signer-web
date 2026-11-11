// enable-multichain-operations: the Web side of the one common multichain safety acceptance, generic over the closed
// chain table (no per-chain suite). Pure functions, fake RPC and fake wallet providers only; no network, wallet, relay,
// storage or chain. Every case asserts that the chain a parsed handoff or anchor names is the only chain of every
// derived request, read, wallet target and record, and that another or unknown chain never escapes it.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import ethers from '../vendor/ethers.js';
import { CHAINS, INFRASTRUCTURE, POLYGON, chainOf, chainOfHex, chainOfId, chainText } from '../chains.js';
import { buildPlan, handoffChain, parseHandoff, RECIPE, CHAIN_ID } from '../model.js';
import * as safe from '../safe-request-model.js';
import * as key from '../key-model.js';
import { readContext } from '../key-reader.js';
import { WalletManager, walletConnectOptions } from '../wallet.js';
import { parseRecord, serializeRecord } from '../saved-result-store.js';
import { K1, K2, anchorText, contextWire, nativeSign, softwareKey } from './support/key-fixtures.mjs';

const U = ethers.utils;
const all = Object.values(CHAINS);
const vectors = JSON.parse(readFileSync(new URL('fixtures/registry-vectors.json', import.meta.url)));
const row = vectors.vectors.find((v) => v.name === 'd1-pattern');
const handoffText = (chain, overrides = {}) => JSON.stringify({ chainId: chain.id, expectedAddress: row.address,
  keyID: row.keyID, publicKey: row.publicPoint, recipe: chain.recipe, salt: row.salt, version: 1, ...overrides });
const code = (fn) => { try { fn(); } catch (e) { return e.code ?? e.message; } return 'accepted'; };

test('the closed chain table: exactly four chains, canonical lookups only', () => {
  assert.deepEqual(all.map((c) => c.id), [1, 137, 8453, 84532]);
  assert.deepEqual(all.map((c) => c.native), ['ETH', 'POL', 'ETH', 'ETH']);
  assert.deepEqual(all.map((c) => c.route), ['/rpc/1', '/rpc', '/rpc/8453', '/rpc/84532']);
  assert.equal(new Set(all.map((c) => c.implementationCodeHash)).size, 4, 'no runtime hash is shared across chains');
  assert.equal(new Set(all.map((c) => c.recipe)).size, 4);
  assert.equal(POLYGON.recipe, RECIPE, 'Polygon keeps the legacy recipe');
  assert.equal(POLYGON.decimal, String(CHAIN_ID));
  for (const chain of all) {
    assert.equal(chainOfId(chain.id), chain);
    assert.equal(chainOf(chain.decimal), chain);
    // A stored or wire `chainId` is text: the numeric form the Polygon-only format refused is still refused.
    assert.equal(chainOf(chain.id), null, `numeric ${chain.id}`);
    assert.equal(chainOfHex(chain.hex), chain);
    assert.equal(chain.caip2, `eip155:${chain.id}`);
  }
  for (const bad of ['0137', '+137', '137 ', '0x89', '10', '', '11155111', 137.5, -137, null, undefined, {}, '1e2']) {
    assert.equal(chainOf(bad), null, String(bad));
  }
  for (const bad of [10, 0, 137.5, -137, '137', 2 ** 53, NaN, null]) assert.equal(chainOfId(bad), null, String(bad));
  for (const bad of ['0x089', '0X89', '89', '0x', '0xa', '137']) assert.equal(chainOfHex(bad), null, bad);
  // Fixed Polygon-worded page texts: exact legacy bytes for Polygon, the other chain's own label otherwise.
  for (const text of ['入金用ウォレットをPolygonに切り替えてください。', 'Polygonに切り替える', '内部鍵の追加・削除 · Polygon']) {
    assert.equal(chainText(text, POLYGON), text);
    for (const chain of all.filter((c) => c !== POLYGON)) {
      assert.equal(chainText(text, chain), text.replaceAll('Polygon', chain.label));
      assert.ok(!chainText(text, chain).includes('Polygon'), `${chain.name} text names Polygon`);
    }
  }
  assert.equal(POLYGON.network, 'Polygon PoS · eip155:137');
  assert.equal(CHAINS[84532].network, 'Base Sepolia（テストネット） · eip155:84532');
  assert.equal(INFRASTRUCTURE.factory, '0x69aa2f9fe1572f1b640e1bbc512f5c3a734fc77c');
});

test('a deployment handoff names exactly one closed chain with its own recipe; the address is shared', () => {
  const addresses = new Set();
  for (const chain of all) {
    const handoff = parseHandoff(handoffText(chain));
    assert.equal(handoffChain(handoff), chain);
    assert.equal(handoff.chainId, chain.id);
    addresses.add(buildPlan(handoff).address);
    for (const other of all.filter((c) => c !== chain)) {
      assert.equal(code(() => parseHandoff(handoffText(chain, { recipe: other.recipe }))), 'chain',
        `${chain.name} chain with ${other.name} recipe`);
    }
    assert.equal(code(() => parseHandoff(handoffText(chain, { chainId: 10 }))), 'chain');
    assert.equal(code(() => parseHandoff(handoffText(chain, { recipe: 'optimism-10/hybrid-delegator-1.3.0/erc1967-create2/v1' }))),
      'recipe');
  }
  assert.deepEqual([...addresses], [row.address], 'one CREATE2 address on every closed chain');
});

test('a Safe request binds its handoff chain: context, EIP-712 domain, body, commitment and saved record', () => {
  const input = { safe: '0x1234567890123456789012345678901234567890', recipient: '0x2222222222222222222222222222222222222222',
    value: '123', nonce: '7' };
  const hashes = new Set(), commitments = new Set();
  for (const chain of all) {
    const handoff = parseHandoff(handoffText(chain));
    const expected = safe.expectedFrom(handoff, input);
    assert.equal('chainId' in expected, chain !== POLYGON, 'Polygon keeps the legacy expected shape');
    assert.equal(safe.expectedChain(expected), chain);
    const { body, safeTxHash } = safe.transaction(expected);
    assert.equal(body.chainId, chain.decimal);
    const types = { SafeTx: [['to', 'address'], ['value', 'uint256'], ['data', 'bytes'], ['operation', 'uint8'],
      ['safeTxGas', 'uint256'], ['baseGas', 'uint256'], ['gasPrice', 'uint256'], ['gasToken', 'address'],
      ['refundReceiver', 'address'], ['nonce', 'uint256']].map(([name, type]) => ({ name, type })) };
    assert.equal(safeTxHash, U._TypedDataEncoder.hash({ chainId: chain.id, verifyingContract: body.safe }, types, body.tx));
    hashes.add(safeTxHash);
    const context = { version: 1, origin: safe.ORIGIN, chainId: chain.decimal, safe: U.getAddress(input.safe),
      signer: handoff.expectedAddress, keyId: handoff.keyID, publicKey: handoff.publicKey,
      binding: '0x' + 'ab'.repeat(32), codecId: 'hybrid-delegator-1.3.0/raw-p256-msg/v1', purpose: 'safe-tx-v1.5.0',
      maxValiditySeconds: 120, maxEnvelopeBytes: 32768 };
    assert.doesNotThrow(() => safe.validateContext(context, expected));
    for (const other of [...all.filter((c) => c !== chain).map((c) => c.decimal), '10', '0137']) {
      assert.throws(() => safe.validateContext({ ...context, chainId: other }, expected), `${chain.name} context ${other}`);
    }
    const request = safe.buildRequest(context, expected, '01234567-89ab-4cde-8f01-23456789abcd', 1_700_000_000);
    assert.equal(JSON.parse(request.envelope).body.chainId, chain.decimal);
    commitments.add(request.commitment);
    // The saved record of this chain round-trips; the same record claiming another chain is refused.
    const record = { version: 1, purpose: 'safe-tx-v1.5.0', requestId: '01234567-89ab-4cde-8f01-23456789abcd',
      envelope: request.envelope, context, expected };
    assert.deepEqual(parseRecord(serializeRecord(record)), record);
    const other = all.find((c) => c !== chain);
    const forged = { ...record, expected: { ...expected, ...(other === POLYGON ? {} : { chainId: other.decimal }) } };
    if (other === POLYGON) delete forged.expected.chainId;
    assert.throws(() => serializeRecord(forged), `${chain.name} record replayed as ${other.name}`);
    if (chain === POLYGON) {
      assert.throws(() => safe.expectedChain({ ...expected, chainId: '137' }), 'Polygon has one canonical shape');
    }
  }
  assert.equal(hashes.size, 4, 'the same transfer has a distinct SafeTxHash on every chain');
  assert.equal(commitments.size, 4);
});

test('a key-change anchor binds its chain: native context ID and runtime, H and the block window', () => {
  const k1 = softwareKey(K1), signer = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
  const typed = new Set();
  for (const chain of all) {
    const text = anchorText(signer, k1).replace('"chainId":"137"', `"chainId":"${chain.decimal}"`);
    const anchor = key.parseAuthority(text);
    assert.equal(key.anchorChain(anchor), chain);
    assert.equal('chainId' in anchor, chain !== POLYGON, 'Polygon keeps the legacy anchor shape');
    const chainState = { nonce: 0n, blockNumber: 100n, blockHash: '0x' + '11'.repeat(32), keys: [k1] };
    const wire = { ...contextWire({ signer, key: k1, binding: '0x' + 'cd'.repeat(32), chain: chainState }),
      chainId: chain.decimal, implementationCodeHash: chain.implementationCodeHash };
    const context = key.validateNativeContext(wire, anchor);
    assert.equal(key.anchorChain(context), chain);
    for (const other of all.filter((c) => c !== chain)) {
      assert.throws(() => key.validateNativeContext({ ...wire, chainId: other.decimal }, anchor), `${chain.name} id`);
      assert.throws(() => key.validateNativeContext({ ...wire, implementationCodeHash: other.implementationCodeHash },
        anchor), `${chain.name} with ${other.name} runtime`);
    }
    const operation = { sender: signer.toLowerCase(), nonce: '0', initCode: '0x', callData: '0x' + '00'.repeat(8),
      accountGasLimits: '0x' + '00'.repeat(32), preVerificationGas: '60000', gasFees: '0x' + '00'.repeat(32),
      paymasterAndData: '0x', signature: '0x' };
    const h = key.typedDataHash(operation, chain.decimal);
    typed.add(h);
    // The window is the chain's own (about 60 seconds of its blocks).
    const native = { ...context, blockNumber: 100n }, web = { signer: context.signer, keys: context.keys, nonce: 0n };
    assert.equal(key.agree(native, { ...web, block: { number: 100n + chain.blockWindow } }), true);
    assert.throws(() => key.agree(native, { ...web, block: { number: 100n + chain.blockWindow + 1n } }));
  }
  assert.equal(typed.size, 4, 'H binds the chain');
  assert.throws(() => key.parseAuthority(anchorText(signer, k1).replace('"chainId":"137"', '"chainId":"10"')));
});

test('a key-change request names its anchor chain in the envelope, H, userOpHash and commitment; results never cross', async () => {
  const k1 = softwareKey(K1), k2 = softwareKey(K2), signer = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
  const binding = '0x' + 'ab'.repeat(32), requests = new Map();
  for (const chain of all) {
    const anchor = key.parseAuthority(anchorText(signer, k1).replace('"chainId":"137"', `"chainId":"${chain.decimal}"`));
    const chainState = { keys: [k1], nonce: 7n, blockNumber: 100n, blockHash: '0x' + '12'.repeat(32) };
    const wire = { ...contextWire({ signer: signer.toLowerCase(), key: k1, binding, chain: chainState }),
      chainId: chain.decimal, implementationCodeHash: chain.implementationCodeHash };
    const context = key.validateNativeContext(wire, anchor);
    const plan = key.planChange({ signer: signer.toLowerCase(), nonce: 7n, keys: context.keys,
      change: { kind: 'add', key: k2 }, fees: { maxFee: 10n ** 9n, priorityFee: 1n } });
    const request = key.buildRequest({ context, operation: plan.operation, id: '0b8e4a52-8f0a-4d7c-9a51-0f3f2a1b6c7d',
      issuedAt: key.issuedAtFor(1800000000) });
    assert.equal(JSON.parse(request.envelope).chainId, chain.decimal, `${chain.name} envelope chain`);
    assert.equal(request.typedDataHash, key.typedDataHash(plan.operation, chain.decimal));
    assert.equal(request.userOpHash, key.userOpHash(plan.operation, chain.decimal));
    requests.set(chain, { request, context, result: await nativeSign({ envelope: request.envelope, key: k1, binding }) });
  }
  assert.equal(new Set([...requests.values()].map((r) => r.request.typedDataHash)).size, 4, 'H differs per chain');
  assert.equal(new Set([...requests.values()].map((r) => r.request.commitment)).size, 4, 'commitment differs per chain');
  const now = 1800000000 + 10;
  for (const [chain, own] of requests) {
    await key.verifyResult(own.result, own.request, own.context, now);
    for (const [other, foreign] of requests) {
      if (other === chain) continue;
      await assert.rejects(key.verifyResult(foreign.result, own.request, own.context, now),
        `${other.name} result accepted for a ${chain.name} request`);
    }
  }
});

test('the key-context read refuses an RPC answering for another chain before any other read', async () => {
  for (const chain of all) {
    const calls = [];
    const rpc = async (method, params) => {
      calls.push([method, params]);
      if (method === 'eth_chainId') return chain.hex;
      throw Object.assign(new Error('stop'), { code: -32000 });
    };
    await assert.rejects(readContext(rpc, { signer: '0x' + '11'.repeat(20), now: () => 0, chain }));
    assert.equal(calls[0][0], 'eth_chainId');
    for (const other of all.filter((c) => c !== chain)) {
      const wrong = async (method) => (method === 'eth_chainId' ? other.hex : null);
      await assert.rejects(readContext(wrong, { signer: '0x' + '11'.repeat(20), now: () => 0, chain }),
        (error) => error.code === 'mismatch', `${chain.name} read answered as ${other.name}`);
    }
  }
});

test('the wallet target is the parsed chain only: init options, status and the explicit switch', async () => {
  for (const chain of all) {
    const options = walletConnectOptions('0'.repeat(32), 'https://tumf.github.io', undefined, chain);
    assert.deepEqual(options.chains, [chain.id]);
    assert.deepEqual(options.rpcMap, { [chain.id]: 'https://tumf.github.io' + chain.route });
    assert.deepEqual(options.optionalChains, []);
    // The pairing description names the target chain; Polygon keeps the exact legacy metadata bytes.
    assert.equal(options.metadata.description, chain === POLYGON ? '選んだSignerをPolygonへ配備します'
      : `選んだSignerを${chain.label}へ配備します`);
  }
  assert.throws(() => walletConnectOptions('0'.repeat(32), 'x', undefined, { ...POLYGON }));
  const requests = [];
  const wallet = new WalletManager({ win: { addEventListener() {}, removeEventListener() {}, dispatchEvent() {} },
    config: null, origin: 'https://tumf.github.io', loadWalletConnect: async () => ({}) });
  wallet.provider = { request: async ({ method, params }) => { requests.push([method, params]); return method === 'eth_chainId' ? CHAINS[8453].hex : null; } };
  wallet.status = 'connected'; wallet.chainId = POLYGON.hex;
  wallet.setTarget(CHAINS[8453]);
  assert.equal(wallet.status, 'wrongChain', 'a wallet on Polygon is wrong for a Base handoff');
  await wallet.switchChain();
  assert.deepEqual(requests.find(([m]) => m === 'wallet_switchEthereumChain')?.[1], [{ chainId: '0x2105' }]);
  assert.equal(wallet.status, 'connected');
  assert.throws(() => wallet.setTarget({ ...CHAINS[1] }), 'only the closed table entries are targets');
});

test('deployment attempts are scoped by chain and address: the same address on another chain is never this attempt', async () => {
  const { AttemptStore } = await import('../attempt-store.js');
  const { validateRecord } = await import('../controller.js');
  const { memoryIndexedDB } = await import('./support/memory-idb.mjs');
  const record = (chain) => {
    const plan = buildPlan(parseHandoff(handoffText(chain)));
    return JSON.stringify({ version: 2, id: '0b8e4a52-8f0a-4d7c-9a51-0f3f2a1b6c7d', manifest: { ...plan.handoff },
      chainId: chain.id, from: '0x' + '22'.repeat(20), to: plan.transaction.to, dataHash: plan.dataHash, salt: plan.salt,
      address: plan.address, transaction: { chainId: chain.hex, value: '0x0', nonce: '0x0' },
      submission: { blockNumber: '0x1', blockHash: '0x' + 'ab'.repeat(32) }, sendEntered: true, hash: null,
      replacementHash: null, state: 'walletPending', reason: null, observed: null, effectiveNonce: null });
  };
  const base = CHAINS[8453];
  const raw = { polygon: record(POLYGON), base: record(base) };
  assert.ok(validateRecord(raw.polygon) && validateRecord(raw.base), 'both are valid records of their own chain');
  const idb = memoryIndexedDB();
  const root = new AttemptStore({ indexedDB: idb, readLegacy: () => null, validateRecord });
  const polygon = root.forAddress(row.address), other = root.forAddress(row.address, base);
  const p = (await polygon.load()).snapshot, b = (await other.load()).snapshot;
  assert.deepEqual([p.key, b.key], [`signer:${row.address.toLowerCase()}`, `signer:8453:${row.address.toLowerCase()}`],
    'Polygon keeps the legacy row key; Base has its own');
  // A record of one chain can never be written into the other chain's scope.
  await assert.rejects(polygon.compareAndSet(p, raw.base), (e) => e.code === 'invalid');
  await assert.rejects(other.compareAndSet(b, raw.polygon), (e) => e.code === 'invalid');
  assert.equal((await polygon.compareAndSet(p, raw.polygon)).committed, true);
  // The committed Polygon attempt does not exist for the same address on Base, before or after a fresh load.
  assert.equal((await other.read()).raw, null);
  assert.equal((await root.forAddress(row.address, base).load()).snapshot.raw, null);
  assert.equal((await root.forAddress(row.address).read()).raw, raw.polygon);
  assert.equal((await other.compareAndSet(b, raw.base)).committed, true);
  assert.equal((await root.forAddress(row.address).read()).raw, raw.polygon, 'the Base write leaves Polygon unchanged');
  assert.throws(() => root.forAddress(row.address, { ...base }), (e) => e.code === 'invalid', 'closed table entries only');
});

test('a governing attempt keeps its own recorded chain in the view; only an explicit rollover reads the new anchor chain', async () => {
  const { world, SIGNER } = await import('./support/prefund-world.mjs');
  const { parseFundingAttempt, serializeFundingAttempt } = await import('../prefund-model.js');
  const { depositCall } = await import('../prefund-model.js');
  const w = world();
  try {
    const k1 = softwareKey(K1), signer = SIGNER.toLowerCase();
    const required = 1060000n * 1000000000n, observed = 60000000000000n;
    const recorded = parseFundingAttempt(serializeFundingAttempt({ version: 2,
      attemptId: '0b8e4a52-8f0a-4d7c-9a51-0f3f2a1b6c7d', status: 'reserved', chainId: '137',
      entryPoint: key.ENTRYPOINT, signer, authorizerKeyId: k1.keyId, authorizerPublicKey: k1.publicKey,
      inspectionBlockNumber: '100', inspectionBlockHash: '0x' + 'aa'.repeat(32), requiredDeposit: required.toString(),
      observedDeposit: observed.toString(), amount: (required - observed).toString(),
      walletAccount: '0x' + '7e'.repeat(20), walletPendingNonce: '3', calldataSHA256: key.sha256Hex(depositCall(signer)),
      sendStartedAt: '1760000000' }));
    const base = CHAINS[8453];
    const c = w.controller;
    c.s.authority = key.parseAuthority(anchorText(SIGNER, k1).replace('"chainId":"137"', '"chainId":"8453"'));
    assert.equal(c.view().chain, base, 'without a governing attempt the view is the authority chain');
    c.s.attempt.record = recorded;
    assert.equal(c.view().chain, POLYGON, 'a governing Polygon attempt is shown, reconciled and labeled as Polygon');
    c.s.rollover = true;
    assert.equal(c.view().chain, base, 'after the explicit new-funding rollover the authority chain governs again');
  } finally { w.stop?.(); }
});
