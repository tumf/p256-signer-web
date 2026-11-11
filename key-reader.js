// Coherent read-only inspection of one HybridDeleGator v1.3.0 Signer: the production HybridChainContextReader
// algorithm (HybridChainContextReader.swift), not the one-key deployment inspector. Every read goes through the
// caller's same-origin `rpc(method, params)` and is pinned to one block B. Chain/RPC observation is operator-trusted,
// not a light-client proof. Also the strict transaction/receipt/block parsers used by settlement, the bounded
// pending wallet-nonce lookup of the send preflight and the v2 actual outer fee coherence check.
import ethers from './vendor/ethers.js';
import {
  ENTRYPOINT, IMPLEMENTATION, IMPLEMENTATION_SLOT, MAX_KEYS, PROXY_RUNTIME_HASH,
  SELECTORS, STORAGE_BASE, UINT256_MAX, UINT64_MAX, ZERO_ADDRESS, isPoint, keyIdHash, keyIdOf, sortedKeys, word,
} from './key-model.js';
import { INFRASTRUCTURE, POLYGON } from './chains.js';

const U = ethers.utils;
export const REQUEST_TIMEOUT_MS = 10_000;
export const ACQUISITION_DEADLINE_MS = 60_000;
export const MAX_CONCURRENT_READS = 8;
export const MAX_BLOCK_AGE = 60;
export const MAX_CLOCK_SKEW = 5;
const SEL = {
  owner: '0x8da5cb5b', entryPoint: '0xb0d691fe', count: '0x1c03010a', hashes: '0x2ffeaad6', getKey: '0xd37aec92',
};

/** unavailable | malformed | mismatch | stale | input | fees: the class only, never endpoint, body or key bytes. */
export class ReadError extends Error {
  constructor(code) {
    super(`chain read ${code}`);
    this.name = 'ReadError';
    this.code = code;
  }
}
const fail = (code) => { throw new ReadError(code); };

export function quantity(text, max = UINT64_MAX) {
  if (typeof text !== 'string' || !/^0x(0|[1-9a-f][0-9a-f]*)$/.test(text) || text.length > 66) fail('malformed');
  const value = BigInt(text);
  if (value > max) fail('malformed');
  return value;
}
const qtext = (n) => '0x' + n.toString(16);
function data(text, max) {
  if (typeof text !== 'string' || !/^0x([0-9a-f]{2})*$/.test(text) || (text.length - 2) / 2 > max) fail('malformed');
  return text;
}
function hash32(text) {
  if (typeof text !== 'string' || !/^0x[0-9a-f]{64}$/.test(text) || /^0x0{64}$/.test(text)) fail('malformed');
  return text;
}
function lowerAddress(text) {
  if (typeof text !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(text)) fail('malformed');
  return text.toLowerCase();
}
const small = (wordHex) => {
  if (!/^0x[0-9a-f]{64}$/.test(wordHex) || !/^0x0{48}/.test(wordHex)) return null;
  return BigInt(wordHex);
};
const addressOf = (wordHex) => (/^0x0{24}[0-9a-f]{40}$/.test(wordHex) ? '0x' + wordHex.slice(26) : null);

/** One read with the per-request bound; transport errors become `unavailable`. */
async function call(rpc, method, params) {
  let timer;
  try {
    return await Promise.race([rpc(method, params), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new ReadError('unavailable')), REQUEST_TIMEOUT_MS);
    })]);
  } catch (error) {
    throw error instanceof ReadError ? error : new ReadError('unavailable');
  } finally {
    clearTimeout(timer);
  }
}

export async function chainId(rpc) {
  return quantity(await call(rpc, 'eth_chainId', []));
}

export function parseBlock(object) {
  if (!object || typeof object !== 'object') fail('malformed');
  return Object.freeze({ number: quantity(object.number), hash: hash32(object.hash),
    timestamp: quantity(object.timestamp) });
}
export async function block(rpc, number) {
  return parseBlock(await call(rpc, 'eth_getBlockByNumber', [number === null ? 'latest' : qtext(number), false]));
}
async function code(rpc, address, at) {
  return data(await call(rpc, 'eth_getCode', [address, qtext(at)]), 24576);
}
async function storage(rpc, address, slot, at) {
  const value = data(await call(rpc, 'eth_getStorageAt', [address, slot, qtext(at)]), 32);
  if (value.length !== 66) fail('malformed');
  return value;
}
async function ethCall(rpc, to, input, at, length) {
  const out = data(await call(rpc, 'eth_call', [{ to, data: input }, qtext(at)]), length);
  if ((out.length - 2) / 2 !== length) fail('malformed');
  return out;
}

/** Not older than the window and not ahead of the local clock beyond the skew. */
export function fresh(b, now) {
  if (!Number.isSafeInteger(now) || now < 0) fail('stale');
  const t = b.timestamp, current = BigInt(now);
  if (t > current + BigInt(MAX_CLOCK_SKEW) || current > t + BigInt(MAX_BLOCK_AGE)) fail('stale');
}

async function boundedMap(items, body) {
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await body(items[index]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(MAX_CONCURRENT_READS, items.length) }, worker));
  return results;
}

const MAPPING_SLOT = word(BigInt(STORAGE_BASE) + 1n);

async function keySet(rpc, signer, at) {
  const count = small(await ethCall(rpc, signer, SEL.count, at, 32));
  if (count === null) fail('malformed');
  if (count < 1n || count > BigInt(MAX_KEYS)) fail('mismatch');
  const n = Number(count);
  const list = await ethCall(rpc, signer, SEL.hashes, at, 64 + 32 * n);
  const words = Array.from({ length: n + 2 }, (_, i) => '0x' + list.slice(2 + 64 * i, 66 + 64 * i));
  if (small(words[0]) !== 32n) fail('malformed');
  if (small(words[1]) !== count) fail('mismatch');
  const hashes = words.slice(2);
  if (new Set(hashes).size !== n || hashes.some((h) => /^0x0{64}$/.test(h))) fail('mismatch');
  const entries = await boundedMap(hashes, async (h) => {
    const position = U.keccak256(U.hexConcat([h, MAPPING_SLOT]));
    const x = await storage(rpc, signer, position, at);
    const y = await storage(rpc, signer, word(BigInt(position) + 1n), at);
    const point = '0x04' + x.slice(2) + y.slice(2);
    if (!isPoint(point)) fail('mismatch');
    const keyId = keyIdOf(point);
    if (keyIdHash(keyId) !== h) fail('mismatch');
    const getKey = SEL.getKey + word(32).slice(2) + word(64).slice(2) + U.hexlify(U.toUtf8Bytes(keyId)).slice(2);
    const pair = await ethCall(rpc, signer, getKey, at, 64);
    if (pair !== U.hexConcat([x, y])) fail('mismatch');
    return { keyId, publicKey: point };
  });
  try { return sortedKeys(entries); } catch { return fail('mismatch'); }
}

/**
 * One complete coherent acquisition. `authorizer` (a parsed anchor) must be registered unless `historical`, which
 * reads at an exact `{number, hash}` without the freshness check (post-state verification after self-removal).
 * `executor` additionally reads the executor native balance at B. Returns frozen context or throws ReadError.
 */
export async function readContext(rpc, { signer, authorizer = null, executor = null, historical = null, now,
  chain = POLYGON }) {
  if (typeof signer !== 'string' || !/^0x[0-9a-f]{40}$/.test(signer) || signer === ZERO_ADDRESS) fail('input');
  let deadline;
  const run = async () => {
    if (await chainId(rpc) !== BigInt(chain.id)) fail('mismatch');
    const b = historical ? await block(rpc, historical.number) : await block(rpc, null);
    if (historical) {
      if (b.number !== historical.number || b.hash !== historical.hash) fail('mismatch');
    } else fresh(b, now());
    const at = b.number;
    // A non-Polygon chain proves its complete Factory, EntryPoint and SCL runtimes and the implementation's EntryPoint
    // at B first (HybridChainContextReader.swift); the frozen Polygon read sequence is unchanged.
    if (chain !== POLYGON) {
      for (const [address, expected] of [[INFRASTRUCTURE.factory, INFRASTRUCTURE.factoryCodeHash],
        [IMPLEMENTATION, chain.implementationCodeHash], [ENTRYPOINT, INFRASTRUCTURE.entryPointCodeHash],
        [INFRASTRUCTURE.scl, INFRASTRUCTURE.sclCodeHash]]) {
        if (U.keccak256(await code(rpc, address, at)) !== expected) fail('mismatch');
      }
      const implementationEntryPoint = addressOf(await ethCall(rpc, IMPLEMENTATION, SEL.entryPoint, at, 32));
      if (implementationEntryPoint === null) fail('malformed');
      if (implementationEntryPoint !== ENTRYPOINT) fail('mismatch');
    }
    if (U.keccak256(await code(rpc, signer, at)) !== PROXY_RUNTIME_HASH) fail('mismatch');
    const implementation = addressOf(await storage(rpc, signer, IMPLEMENTATION_SLOT, at));
    if (implementation === null) fail('malformed');
    if (implementation !== IMPLEMENTATION) fail('mismatch');
    if (U.keccak256(await code(rpc, IMPLEMENTATION, at)) !== chain.implementationCodeHash) fail('mismatch');
    const owner = addressOf(await ethCall(rpc, signer, SEL.owner, at, 32));
    if (owner === null) fail('malformed');
    if (owner !== ZERO_ADDRESS) fail('mismatch');
    const entryPoint = addressOf(await ethCall(rpc, signer, SEL.entryPoint, at, 32));
    if (entryPoint === null) fail('malformed');
    if (entryPoint !== ENTRYPOINT) fail('mismatch');
    const keys = await keySet(rpc, signer, at);
    if (authorizer && !keys.some((k) => k.keyId === authorizer.keyId && k.publicKey === authorizer.publicKey)) {
      fail('mismatch');
    }
    const nonce = small(await ethCall(rpc, ENTRYPOINT, SELECTORS.getNonce + word(BigInt(signer)).slice(2)
      + word(0).slice(2), at, 32));
    if (nonce === null) fail('mismatch');
    const deposit = BigInt(await ethCall(rpc, ENTRYPOINT, SELECTORS.balanceOf + word(BigInt(signer)).slice(2), at, 32));
    const executorBalance = executor === null ? null : quantity(await call(rpc, 'eth_getBalance', [executor, qtext(at)]),
      UINT256_MAX);
    const again = await block(rpc, at);
    if (again.number !== b.number || again.hash !== b.hash || again.timestamp !== b.timestamp) fail('mismatch');
    if (await chainId(rpc) !== BigInt(chain.id)) fail('mismatch');
    if (!historical) fresh(b, now());
    return Object.freeze({ chainId: chain.decimal, signer, implementation,
      implementationCodeHash: chain.implementationCodeHash,
      owner, entryPoint, keys, nonce, deposit, executorBalance, block: b });
  };
  try {
    return await Promise.race([run(), new Promise((_, reject) => {
      deadline = setTimeout(() => reject(new ReadError('unavailable')), ACQUISITION_DEADLINE_MS);
    })]);
  } catch (error) {
    throw error instanceof ReadError ? error : new ReadError('unavailable');
  } finally {
    clearTimeout(deadline);
  }
}

/**
 * `eth_getTransactionCount(account, 'pending')` through the same bounded read path (10s), as a canonical uint256
 * (valid `0x0` included). A lookup hint for reconciliation only: never a nonce requested from the wallet.
 */
export async function pendingNonce(rpc, account) {
  return quantity(await call(rpc, 'eth_getTransactionCount', [account, 'pending']), UINT256_MAX);
}

// ---------------------------------------------------------------------------------------------------------------
// Strict settlement reads (lookup handles until every field is checked)

const raw = (value) => (value === undefined ? null : value);

/**
 * `fees: 'legacy'` (v1 attempts) keeps the original combined fee parsing. `fees: 'raw'` (v2) leaves the actual gas
 * and fee members unparsed in `feeFields` so coherentFees() can classify them as fee evidence, not transport.
 */
export async function transaction(rpc, hash, { fees = 'legacy' } = {}) {
  const tx = await call(rpc, 'eth_getTransactionByHash', [hash]);
  if (tx === null) return null;
  if (!tx || typeof tx !== 'object' || tx.hash !== hash) fail('malformed');
  const common = {
    hash, from: lowerAddress(tx.from), to: tx.to === null ? null : lowerAddress(tx.to),
    value: quantity(tx.value, UINT256_MAX), input: data(tx.input, 1 << 20),
    nonce: quantity(tx.nonce), chainId: tx.chainId === undefined ? null : quantity(tx.chainId),
    blockNumber: tx.blockNumber === null || tx.blockNumber === undefined ? null : quantity(tx.blockNumber),
    blockHash: tx.blockHash === null || tx.blockHash === undefined ? null : hash32(tx.blockHash),
  };
  if (fees === 'raw') {
    return Object.freeze({ ...common, feeFields: Object.freeze({ gas: raw(tx.gas), maxFeePerGas: raw(tx.maxFeePerGas),
      maxPriorityFeePerGas: raw(tx.maxPriorityFeePerGas), gasPrice: raw(tx.gasPrice) }) });
  }
  const fee = tx.maxFeePerGas ?? tx.gasPrice, tip = tx.maxPriorityFeePerGas ?? tx.gasPrice;
  return Object.freeze({ ...common, gas: quantity(tx.gas), maxFeePerGas: quantity(fee, UINT256_MAX),
    maxPriorityFeePerGas: quantity(tip, UINT256_MAX) });
}

export async function receipt(rpc, hash, { fees = 'legacy' } = {}) {
  const r = await call(rpc, 'eth_getTransactionReceipt', [hash]);
  if (r === null) return null;
  if (!r || typeof r !== 'object' || r.transactionHash !== hash || !Array.isArray(r.logs) || r.logs.length > 256) {
    fail('malformed');
  }
  if (r.status !== '0x0' && r.status !== '0x1') fail('malformed');
  const transactionHash = hash32(r.transactionHash), blockHash = hash32(r.blockHash), blockNumber = quantity(r.blockNumber);
  const logs = r.logs.map((log) => {
    if (!log || typeof log !== 'object' || !Array.isArray(log.topics) || log.topics.length > 4
      || log.removed !== false || log.transactionHash !== transactionHash || log.blockHash !== blockHash
      || quantity(log.blockNumber) !== blockNumber) fail('malformed');
    return Object.freeze({ address: lowerAddress(log.address), topics: log.topics.map((t) => {
      if (typeof t !== 'string' || !/^0x[0-9a-f]{64}$/.test(t)) fail('malformed');
      return t;
    }), data: data(log.data, 1 << 16), blockHash, blockNumber, transactionHash, removed: false });
  });
  const common = { transactionHash, status: r.status, blockNumber,
    blockHash, from: lowerAddress(r.from), to: r.to === null ? null : lowerAddress(r.to), logs };
  if (fees === 'raw') {
    return Object.freeze({ ...common, feeFields: Object.freeze({ gasUsed: raw(r.gasUsed),
      effectiveGasPrice: raw(r.effectiveGasPrice) }) });
  }
  return Object.freeze({ ...common, gasUsed: quantity(r.gasUsed),
    effectiveGasPrice: quantity(r.effectiveGasPrice, UINT256_MAX) });
}

/**
 * v2 actual outer fee evidence of one mined transaction and its receipt (raw `feeFields`). Internal coherence only:
 * there is no application ceiling, floor or historical v1 value. A nonnull maxFeePerGas or maxPriorityFeePerGas
 * selects the dynamic shape (both required, max > 0, priority <= max, effective price within [priority, max] and
 * equal to any reported gasPrice); otherwise a positive gasPrice is the legacy shape (effective price equal to it).
 * Gas and gasUsed keep the uint64 reader bound, prices uint256; gas > 0, gasUsed <= gas and the checked outer cost
 * gasUsed x effectiveGasPrice fits uint256. Anything missing, malformed or contradictory throws ReadError('fees').
 */
export function coherentFees(tx, rc) {
  const q = (text, max) => {
    try { return quantity(text, max); } catch { return fail('fees'); }
  };
  const gas = q(tx.gas, UINT64_MAX);
  if (gas === 0n) fail('fees');
  let maxFee, priority, mined = null;
  if (tx.maxFeePerGas !== null || tx.maxPriorityFeePerGas !== null) {
    maxFee = q(tx.maxFeePerGas, UINT256_MAX);
    priority = q(tx.maxPriorityFeePerGas, UINT256_MAX);
    if (maxFee === 0n || priority > maxFee) fail('fees');
    if (tx.gasPrice !== null) mined = q(tx.gasPrice, UINT256_MAX);
  } else {
    maxFee = priority = mined = q(tx.gasPrice, UINT256_MAX);
    if (maxFee === 0n) fail('fees');
  }
  const gasUsed = q(rc.gasUsed, UINT64_MAX), effectiveGasPrice = q(rc.effectiveGasPrice, UINT256_MAX);
  if (gasUsed > gas || effectiveGasPrice > maxFee || effectiveGasPrice < priority
      || (mined !== null && effectiveGasPrice !== mined)) fail('fees');
  const outerCost = gasUsed * effectiveGasPrice;
  if (outerCost > UINT256_MAX) fail('fees');
  return Object.freeze({ gas, maxFeePerGas: maxFee, maxPriorityFeePerGas: priority, gasUsed, effectiveGasPrice,
    outerCost });
}
