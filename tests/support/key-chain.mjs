// Test-only fixture-controlled JSON-RPC chain for parsing, state and negative-path tests of the key-change page.
// It answers exactly the reads key-reader.js issues (pinned proxy/implementation runtimes, ERC-7201 key storage,
// getter, enumeration, EntryPoint nonce/deposit) and models a handleOps submission's effect so receipts can be
// scripted. These are FIXTURE responses: explicitly NOT EVM execution evidence (tests/key-evm.test.mjs owns that).
import ethers from '../../vendor/ethers.js';
import proxy from '../../vendor/proxy.json' with { type: 'json' };
import hybridRuntime from '../fixtures/HybridCodec/hybrid-runtime.json' with { type: 'json' };
import {
  ENTRYPOINT, IMPLEMENTATION, IMPLEMENTATION_SLOT, SELECTORS, STORAGE_BASE, USER_OPERATION_EVENT, keyIdHash, userOpHash,
  word,
} from '../../key-model.js';

const U = ethers.utils;
export const PROXY_RUNTIME = '0x' + proxy.bytecode.slice(2 + 0x246 * 2);
export const IMPLEMENTATION_RUNTIME = hybridRuntime.contracts.hybrid.runtime;
const MAPPING_SLOT = word(BigInt(STORAGE_BASE) + 1n);
const q = (n) => '0x' + BigInt(n).toString(16);
const pad = (address) => '0x' + '00'.repeat(12) + address.slice(2).toLowerCase();
const handleOps = new U.Interface([
  'function handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)']);
const execute = new U.Interface(['function execute((address,uint256,bytes))']);
const keys = new U.Interface(['function addKey(string,uint256,uint256)', 'function removeKey(string)']);

/** The exact members of the production wallet request; everything else is the wallet's own choice. */
export const REQUEST_KEYS = Object.freeze(['chainId', 'data', 'from', 'to', 'value']);
/** Default outer parameters a fake STANDARD WALLET chooses for itself (dynamic-fee shape, 1 gwei, 2200000 gas). */
export const WALLET_FEES = Object.freeze({ gas: '0x2191c0', maxFeePerGas: '0x3b9aca00', maxPriorityFeePerGas: '0x3b9aca00' });
/** The transaction a fake wallet submits for a production request: request members plus its own outer choice. */
export const walletTransaction = (request, fees = WALLET_FEES) => ({ ...request, ...fees });

/**
 * `createChain({signer, keys:[{keyId,publicKey}], nonce, deposit, balances, now})`. `chain.rpc(method, params)`
 * answers like a node; `chain.submit(tx)` mines a handleOps transaction (one block) and returns its hash.
 * Every field is mutable for negative scripting (`chain.override`, `chain.mutate`).
 */
export function createChain({ signer, keys: initial, nonce = 0n, deposit = 0n, balances = {}, now = () =>
  Math.floor(Date.now() / 1000), chainId = 137n }) {
  const state = {
    signer: signer.toLowerCase(), keys: initial.map((k) => ({ ...k })), nonce: BigInt(nonce), deposit: BigInt(deposit),
    balances: Object.fromEntries(Object.entries(balances).map(([a, v]) => [a.toLowerCase(), BigInt(v)])),
    walletNonces: {}, blocks: [], txs: new Map(), receipts: new Map(), proxyCode: PROXY_RUNTIME,
    implementationCode: IMPLEMENTATION_RUNTIME, implementation: IMPLEMENTATION, owner: '0x' + '00'.repeat(20),
    entryPoint: ENTRYPOINT, chainId, baseFee: 0n,
  };
  const calls = [];
  const chain = { state, calls, override: null, delay: 0, fail: null };
  const mine = () => {
    const number = BigInt(state.blocks.length + 100);
    const b = { number, hash: U.keccak256(U.toUtf8Bytes(`block-${number}-${state.blocks.length}-${Math.random()}`)),
      timestamp: BigInt(now()) };
    state.blocks.push(b);
    return b;
  };
  mine();
  chain.mine = mine;
  chain.head = () => state.blocks.at(-1);
  chain.reorg = (number) => {
    const b = state.blocks.find((x) => x.number === number);
    b.hash = U.keccak256(U.toUtf8Bytes(`reorg-${number}-${Math.random()}`));
  };
  const slotOf = (keyId) => U.keccak256(U.hexConcat([keyIdHash(keyId), MAPPING_SLOT]));
  const storageAt = (address, slot) => {
    if (address !== state.signer) return word(0);
    if (slot === IMPLEMENTATION_SLOT) return pad(state.implementation);
    for (const k of state.keys) {
      const p = slotOf(k.keyId);
      if (slot === p) return '0x' + k.publicKey.slice(4, 68);
      if (slot === word(BigInt(p) + 1n)) return '0x' + k.publicKey.slice(68);
    }
    return word(0);
  };
  const ethCall = ({ to, data }) => {
    const target = to.toLowerCase(), sel = data.slice(0, 10);
    if (target === state.signer) {
      if (sel === '0x8da5cb5b') return pad(state.owner);
      if (sel === '0xb0d691fe') return pad(state.entryPoint);
      if (sel === '0x1c03010a') return word(state.keys.length);
      if (sel === '0x2ffeaad6') return U.hexConcat([word(32), word(state.keys.length),
        ...state.keys.map((k) => keyIdHash(k.keyId))]);
      if (sel === '0xd37aec92') {
        const id = U.toUtf8String('0x' + data.slice(2 + 8 + 128, 2 + 8 + 128 + 128));
        const k = state.keys.find((x) => x.keyId === id);
        return k ? U.hexConcat(['0x' + k.publicKey.slice(4, 68), '0x' + k.publicKey.slice(68)]) : word(0) + '00'.repeat(32);
      }
    }
    if (target === ENTRYPOINT && sel === SELECTORS.getNonce) return word(state.nonce);
    if (target === ENTRYPOINT && sel === SELECTORS.balanceOf) return word(state.deposit);
    throw Object.assign(new Error('execution reverted'), { code: 3 });
  };
  const blockObject = (b) => (b ? { number: q(b.number), hash: b.hash, timestamp: q(b.timestamp), parentHash: word(0) }
    : null);
  const answer = (method, p) => {
    switch (method) {
      case 'eth_chainId': return q(state.chainId);
      case 'eth_getBlockByNumber':
        return blockObject(p[0] === 'latest' ? chain.head() : state.blocks.find((b) => b.number === BigInt(p[0])));
      case 'eth_getCode':
        return p[0].toLowerCase() === state.signer ? state.proxyCode
          : p[0].toLowerCase() === IMPLEMENTATION ? state.implementationCode : '0x';
      case 'eth_getStorageAt': return storageAt(p[0].toLowerCase(), p[1]);
      case 'eth_call': return ethCall(p[0]);
      case 'eth_getBalance': return q(state.balances[p[0].toLowerCase()] ?? 0n);
      case 'eth_getTransactionCount': return q(state.walletNonces[p[0].toLowerCase()] ?? 0);
      case 'eth_getTransactionByHash': return state.txs.has(p[0]) ? structuredClone(state.txs.get(p[0])) : null;
      case 'eth_getTransactionReceipt': return state.receipts.has(p[0]) ? structuredClone(state.receipts.get(p[0])) : null;
      default: throw Object.assign(new Error('method not allowed'), { code: -32601 });
    }
  };
  chain.rpc = async (method, params = []) => {
    calls.push([method, params]);
    if (chain.delay) await new Promise((resolve) => setTimeout(resolve, chain.delay));
    if (chain.fail && chain.fail(method, params)) throw new TypeError('relay unavailable');
    const value = answer(method, params);
    return chain.override ? chain.override(method, params, value) : value;
  };

  /**
   * Models one handleOps transaction: decodes the single op, applies its add/remove when the nonce matches (no
   * signature verification: fixture only), charges deposit and mines it. Options script inner failure/outer status.
   */
  chain.submit = (tx, { innerSuccess = true, outerStatus = '0x1', mineBlock = true, actualGasCost = 123456789n,
    gasUsed = 400000n, extraLogs = [], dropEvent = false, eventOverride = null } = {}) => {
    const from = tx.from.toLowerCase();
    const walletNonce = state.walletNonces[from] ?? 0;
    state.walletNonces[from] = walletNonce + 1;
    const [ops, beneficiary] = handleOps.decodeFunctionData('handleOps', tx.data);
    const op = ops[0];
    const plain = { sender: op[0].toLowerCase(), nonce: op[1].toString(), initCode: op[2], callData: op[3],
      accountGasLimits: op[4], preVerificationGas: op[5].toString(), gasFees: op[6], paymasterAndData: op[7],
      signature: '0x' };
    const hash = U.keccak256(U.toUtf8Bytes(`tx-${from}-${walletNonce}-${Math.random()}`));
    const logs = [];
    const apply = () => {
      let applied = false;
      if (outerStatus === '0x1' && BigInt(plain.nonce) === state.nonce) {
        state.nonce += 1n;
        if (innerSuccess) {
          const [[, , inner]] = execute.decodeFunctionData('execute', plain.callData);
          const parsed = keys.parseTransaction({ data: inner });
          if (parsed.name === 'addKey') {
            const [keyId, x, y] = parsed.args;
            state.keys.push({ keyId, publicKey: '0x04' + x.toHexString().slice(2).padStart(64, '0')
              + y.toHexString().slice(2).padStart(64, '0') });
          } else state.keys = state.keys.filter((k) => k.keyId !== parsed.args[0]);
          applied = true;
        }
        state.deposit -= actualGasCost;
        if (!dropEvent) {
          const event = { address: ENTRYPOINT, topics: [USER_OPERATION_EVENT, userOpHash(plain), pad(plain.sender),
            pad('0x' + '00'.repeat(20))], data: U.hexConcat([word(plain.nonce), word(innerSuccess ? 1 : 0),
            word(actualGasCost), word(gasUsed)]) };
          logs.push(eventOverride ? eventOverride(event) : event);
        }
      }
      return applied;
    };
    logs.push(...extraLogs);
    const dynamic = tx.maxFeePerGas !== undefined || tx.maxPriorityFeePerGas !== undefined;
    const record = { hash, from, to: tx.to.toLowerCase(), value: tx.value, input: tx.data, gas: tx.gas,
      ...(dynamic ? { maxFeePerGas: tx.maxFeePerGas, maxPriorityFeePerGas: tx.maxPriorityFeePerGas, type: '0x2' }
        : { gasPrice: tx.gasPrice, type: '0x0' }),
      nonce: q(walletNonce), chainId: tx.chainId ?? '0x89', blockNumber: null, blockHash: null };
    state.txs.set(hash, record);
    chain.pendingReceipt = { hash, outerStatus, gasUsed, logs, beneficiary, apply };
    if (mineBlock) chain.include(hash);
    return hash;
  };
  /** Mines the pending submission into a new block (two-step scripting for pending/one-confirmation states). */
  chain.include = (hash) => {
    const pending = chain.pendingReceipt;
    pending.applied = pending.apply();
    const b = mine();
    const tx = state.txs.get(hash);
    tx.blockNumber = q(b.number);
    tx.blockHash = b.hash;
    // Node semantics: a dynamic-fee price is min(max, baseFee + priority) and is then also reported as gasPrice.
    const price = tx.type === '0x2' ? [BigInt(tx.maxFeePerGas), state.baseFee + BigInt(tx.maxPriorityFeePerGas)]
      .reduce((a, b) => (a < b ? a : b)) : BigInt(tx.gasPrice);
    tx.gasPrice = q(price);
    state.receipts.set(hash, { transactionHash: hash, status: pending.outerStatus, blockNumber: q(b.number),
      blockHash: b.hash, from: tx.from, to: tx.to, gasUsed: q(pending.gasUsed), effectiveGasPrice: q(price),
      logs: pending.logs.map((l) => ({ ...l, blockHash: b.hash, blockNumber: q(b.number), transactionHash: hash, removed: false })) });
    return b;
  };
  return chain;
}
