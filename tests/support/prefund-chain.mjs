// Test-only fixture-controlled JSON-RPC chain for the prefund page: the unchanged key-change fixture chain
// (key-chain.mjs) plus the pinned EntryPoint runtime bytes behind eth_getCode and a scripted depositTo(signer)
// submission that credits the deposit and emits the StakeManager Deposited log. These are FIXTURE responses:
// explicitly NOT EVM execution evidence (tests/prefund-evm.test.mjs owns that).
import ethers from '../../vendor/ethers.js';
import entryRuntime from '../fixtures/entrypoint-runtime.json' with { type: 'json' };
import { ENTRYPOINT } from '../../key-model.js';
import { DEPOSITED_EVENT, DEPOSIT_TO_SELECTOR, addressTopic } from '../../prefund-model.js';
import { createChain } from './key-chain.mjs';

const U = ethers.utils;
const q = (n) => '0x' + BigInt(n).toString(16);
export const ENTRYPOINT_RUNTIME = entryRuntime.runtime;

/** The fixture wallet's own deterministic execution choices (never the application's): gas, max fee and priority. */
export const WALLET_DEFAULTS = Object.freeze({ gas: '0x186a0', maxFeePerGas: '0x77359400', maxPriorityFeePerGas: '0x77359400' });

/**
 * The fixture wallet's forwarded copy of an application request: missing execution fields get WALLET_DEFAULTS (a
 * legacy `gasPrice` request stays legacy); explicitly supplied fields are preserved. The original is never mutated.
 */
export function walletExecution(request, overrides = {}) {
  const tx = { ...request, ...overrides };
  if (tx.gas === undefined) tx.gas = WALLET_DEFAULTS.gas;
  if (tx.gasPrice === undefined) {
    if (tx.maxFeePerGas === undefined) tx.maxFeePerGas = WALLET_DEFAULTS.maxFeePerGas;
    if (tx.maxPriorityFeePerGas === undefined) tx.maxPriorityFeePerGas = WALLET_DEFAULTS.maxPriorityFeePerGas;
  }
  return tx;
}

/**
 * `createPrefundChain(options)`: createChain's options. `chain.entryPointCode` is served for the pinned EntryPoint;
 * `chain.submitDeposit(tx, opts)` records one depositTo transaction (the next wallet nonce, or `hash`/`nonce` for a
 * literal historical record) and, unless `mineBlock: false`, includes it. Options script `status`,
 * `logs(defaultLogs) => logs`, `gasUsed`, `credit`. `tx` is the wallet's executed copy (EIP-1559 or legacy gasPrice).
 */
export function createPrefundChain(options) {
  const chain = createChain(options);
  chain.entryPointCode = ENTRYPOINT_RUNTIME;
  chain.historicalCode = new Map();
  const base = chain.override;
  chain.extraOverride = null;
  chain.override = (method, params, value) => {
    let result = value;
    if (method === 'eth_getCode' && params[0].toLowerCase() === ENTRYPOINT) {
      result = chain.historicalCode.get(BigInt(params[1])) ?? chain.entryPointCode;
    }
    if (base) result = base(method, params, result);
    return chain.extraOverride ? chain.extraOverride(method, params, result) : result;
  };
  chain.deposits = [];
  chain.submitDeposit = (tx, { status = '0x1', mineBlock = true, gasUsed = 45000n, logs = null, credit = true,
    hash: fixed = null, nonce = null } = {}) => {
    const from = tx.from.toLowerCase();
    const walletNonce = nonce ?? chain.state.walletNonces[from] ?? 0;
    chain.state.walletNonces[from] = walletNonce + 1;
    const hash = fixed || U.keccak256(U.toUtf8Bytes(`deposit-${from}-${walletNonce}-${Math.random()}`));
    const fees = tx.gasPrice !== undefined ? { gasPrice: tx.gasPrice, type: '0x0' }
      : { maxFeePerGas: tx.maxFeePerGas, maxPriorityFeePerGas: tx.maxPriorityFeePerGas, type: '0x2' };
    const record = { hash, from, to: tx.to.toLowerCase(), value: tx.value, input: tx.data, gas: tx.gas, ...fees,
      nonce: q(walletNonce), chainId: tx.chainId ?? '0x89', blockNumber: null, blockHash: null };
    chain.state.txs.set(hash, record);
    chain.deposits.push({ hash, tx: structuredClone(tx) });
    chain.pendingDeposit = { hash, status, gasUsed, logs, credit };
    if (mineBlock) chain.includeDeposit(hash);
    return hash;
  };
  chain.includeDeposit = (hash) => {
    const pending = chain.pendingDeposit;
    const tx = chain.state.txs.get(hash);
    const toSigner = tx.to === ENTRYPOINT && tx.input.startsWith(DEPOSIT_TO_SELECTOR);
    let defaults = [];
    if (pending.status === '0x1' && toSigner) {
      const account = '0x' + tx.input.slice(-40);
      if (pending.credit && account === chain.state.signer) chain.state.deposit += BigInt(tx.value);
      defaults = [{ address: ENTRYPOINT, topics: [DEPOSITED_EVENT, addressTopic(account)],
        data: '0x' + chain.state.deposit.toString(16).padStart(64, '0') }];
    }
    const logs = pending.logs ? pending.logs(defaults) : defaults;
    const b = chain.mine();
    tx.blockNumber = q(b.number);
    tx.blockHash = b.hash;
    chain.state.receipts.set(hash, { transactionHash: hash, status: pending.status, blockNumber: q(b.number),
      blockHash: b.hash, from: tx.from, to: tx.to, gasUsed: q(pending.gasUsed),
      effectiveGasPrice: q(BigInt(tx.maxFeePerGas ?? tx.gasPrice)),
      logs: logs.map((l) => ({ removed: false, ...l, blockHash: b.hash, blockNumber: q(b.number), transactionHash: hash })) });
    return b;
  };
  return chain;
}
