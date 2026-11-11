// Test-only composition for Node controller/settlement tests: the production KeyChangeController over the fixture
// chain, a software native peer, a scripted wallet double and the actual KeyAttemptStore on an in-memory IndexedDB
// double. Fixture data only; browser storage and EVM execution are owned by other suites.
import { KeyAttemptStore } from '../../key-attempt-store.js';
import { KeyChangeController } from '../../key-controller.js';
import { parseRecord, serializeRecord } from '../../saved-result-store.js';
import { createChain, walletTransaction, WALLET_FEES } from './key-chain.mjs';
import { K1, K2, anchorText, bareKeyText, contextWire, nativeClient, nativeSign, softwareKey } from './key-fixtures.mjs';
import { memoryIndexedDB } from './memory-idb.mjs';

export const SIGNER = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
export const EXECUTOR = '0x' + '7e'.repeat(20);
export const k1 = softwareKey(K1), k2 = softwareKey(K2);
export const k3 = softwareKey(987654321n);

/**
 * A scripted EIP-1193-backed STANDARD WALLET double with the WalletManager surface the controller uses. It records the
 * exact production request (`sends`) and then, like a real wallet, chooses its own outer gas/fees (`fees`).
 */
export function walletDouble(chain) {
  const w = {
    status: 'connected', chainId: '0x89', account: EXECUTOR, generation: 1, selectedId: 'test', error: null,
    pairing: null, sends: [], mode: 'ok', submit: {}, release: null, fees: WALLET_FEES,
    choices: () => [{ id: 'test', name: 'Test wallet', kind: 'legacy', disabled: false, reason: null }],
    snapshot: () => ({ choices: w.choices(), selectedId: w.selectedId, kind: 'legacy', status: w.status,
      account: w.account, chainId: w.chainId, error: w.error, pairing: w.pairing, generation: w.generation,
      walletConnect: { enabled: false } }),
    switchPolygon: async () => {},
    async request(method, params) {
      if (method !== 'eth_sendTransaction') throw new Error('unexpected');
      w.sends.push(params[0]);
      w.observed?.(params[0]);
      if (w.mode === 'reject') throw { code: 4001, message: 'rejected' };
      if (w.mode === 'timeout') throw new Error('timeout');
      if (w.mode === 'malformed') return '0x1234';
      if (w.mode === 'nohash') return undefined;
      const tx = walletTransaction(params[0], w.fees);
      if (w.mode === 'hang') return new Promise((resolve) => { w.release = () => resolve(chain.submit(tx, w.submit)); });
      return chain.submit(tx, w.submit);
    },
  };
  return w;
}

// Adapter-only seam: real closed-record validators, no IndexedDB or durability claim.
export function memorySavedResults() {
  const rows = new Map();
  return { rows, async save(record) {
    const raw = serializeRecord(record), key = JSON.stringify([record.purpose, record.requestId]);
    if (rows.has(key) && rows.get(key) !== raw) throw new Error('conflict');
    rows.set(key, raw);
    return parseRecord(raw);
  }, async list() { return [...rows.values()].map(parseRecord); } };
}

export function world({ keys = [k1], deposit = 10n ** 18n, balance = 10n ** 18n, indexedDB = memoryIndexedDB(),
  nonce = 0n, now, chain: shared = null, savedResultStore = memorySavedResults() } = {}) {
  const clock = { offset: 0 };
  const time = now || (() => Math.floor(Date.now() / 1000) + clock.offset);
  // `chain` lets a reloaded world (same IndexedDB) observe the same fixture chain as the world that sent.
  const chain = shared
    || createChain({ signer: SIGNER, keys, nonce, deposit, balances: { [EXECUTOR]: balance }, now: time });
  const binding = '0x' + 'b1'.repeat(32);
  const peer = {
    signer: SIGNER, key: k1, binding, signs: 0, mode: 'ok', contexts: 0,
    async context() {
      peer.contexts++;
      const head = chain.head();
      return contextWire({ signer: SIGNER, key: peer.key, binding: peer.binding,
        chain: { keys: chain.state.keys, nonce: chain.state.nonce, blockNumber: head.number, blockHash: head.hash },
        maxFeePerGas: peer.maxFeePerGas ?? '500000000000' });
    },
    async sign(envelope) {
      peer.signs++;
      if (peer.mode === 'reject') throw { code: 5003, message: 'rejected' };
      return nativeSign({ envelope, key: peer.key, binding: peer.binding });
    },
  };
  const native = nativeClient(peer);
  const wallet = walletDouble(chain);
  const store = new KeyAttemptStore({ indexedDB });
  const timers = [];
  const controller = new KeyChangeController({ rpc: chain.rpc, wallet, store, savedResultStore, clock: time, uuid: () => crypto.randomUUID(),
    loadSignClient: async () => native.SignClient, loadConfig: async () => ({ walletConnectProjectId: 'ab'.repeat(16) }),
    setTimer: (fn, ms) => { const id = setTimeout(fn, ms); timers.push(id); return id; }, clearTimer: (id) => clearTimeout(id) });
  return { chain, peer, native, wallet, store, savedResultStore, controller, clock, indexedDB, binding,
    stop: () => timers.forEach((t) => clearTimeout(t)) };
}

/** Explicit intents up to a verified signature for `change` authorized by `key`. */
export async function approve(w, { key = k1, change = { mode: 'add', bareText: bareKeyText(k2) }, fee = '1' } = {}) {
  w.peer.key = key;
  w.controller.setAnchorText(anchorText(SIGNER, key));
  await w.controller.inspect();
  w.controller.setChange({ ...change, feeMax: fee, feePriority: fee });
  await w.controller.connectNative();
  await w.controller.previewNative();
  await w.controller.requestSignature();
  return w.controller.view();
}

/**
 * Test-only legacy fixture: rewrites the current (v2) attempt into the exact closed raw v1 schema with historical
 * outer ceilings through the production CAS, as a pre-existing v1 record would be stored. Never used in production.
 */
export async function seedLegacy(w, { gas = '2200000', maxFee = '1000000000', priority = '1000000000' } = {}) {
  const ok = await w.controller.update((r) => ({ ...r, version: 1, outerGasLimit: gas, outerMaxFeePerGas: maxFee,
    outerMaxPriorityFeePerGas: priority }));
  if (!ok) throw new Error('legacy seed refused');
  return w.controller.view().attempt.record;
}

export { anchorText, bareKeyText };
