// Test-only composition for Node prefund controller/settlement tests: the production PrefundController over the
// prefund fixture chain, a scripted wallet double with the WalletManager surface and the actual FundingAttemptStore on
// the in-memory IndexedDB double. Fixture data only; browser storage and EVM execution are owned by other suites.
import { FundingAttemptStore } from '../../prefund-attempt-store.js';
import { PrefundController } from '../../prefund-controller.js';
import { createPrefundChain, walletExecution } from './prefund-chain.mjs';
import { K1, K2, anchorText, softwareKey } from './key-fixtures.mjs';
import { memoryIndexedDB } from './memory-idb.mjs';

export const SIGNER = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
export const FUNDER = '0x' + '7e'.repeat(20);
export const k1 = softwareKey(K1), k2 = softwareKey(K2);
export const P1 = 1060000n * 1000000000n;

/**
 * A scripted EIP-1193-backed wallet with the WalletManager surface the controller uses. `sends` keeps the original
 * application requests; like a real wallet it executes its own copy with WALLET_DEFAULTS for missing execution fields
 * (`execution` overrides them, e.g. a legacy gasPrice or higher fees) and records that copy in `executed`.
 */
export function walletDouble(chain) {
  const w = {
    status: 'connected', chainId: '0x89', account: FUNDER, generation: 1, selectedId: 'test', error: null,
    pairing: null, sends: [], executed: [], execution: {}, chainQueries: 0, mode: 'ok', submit: {}, release: null,
    hold: null,
    choices: () => [{ id: 'test', name: 'Test wallet', kind: 'legacy', disabled: false, reason: null }],
    snapshot: () => ({ choices: w.choices(), selectedId: w.selectedId, kind: 'legacy', status: w.status,
      account: w.account, chainId: w.chainId, error: w.error, pairing: w.pairing, generation: w.generation,
      walletConnect: { enabled: false, reason: 'missing-id' } }),
    switchPolygon: async () => {},
    async request(method, params) {
      if (method === 'eth_chainId') {
        w.chainQueries++;
        if (w.hold) await w.hold('eth_chainId');
        return w.chainId;
      }
      if (method !== 'eth_sendTransaction') throw new Error('unexpected');
      w.sends.push(structuredClone(params[0]));
      const tx = walletExecution(params[0], w.execution);
      w.executed.push(tx);
      if (w.mode === 'reject') throw { code: 4001, message: 'rejected' };
      if (w.mode === 'error') throw new Error('wallet failure');
      if (w.mode === 'malformed') return '0x1234';
      if (w.mode === 'send-then-fail') { chain.submitDeposit(tx, w.submit); throw new Error('lost response'); }
      if (w.mode === 'hang') return new Promise((resolve) => { w.release = () => resolve(chain.submitDeposit(tx, w.submit)); });
      return chain.submitDeposit(tx, w.submit);
    },
    /** A wallet event: the generation advances and the controller must disarm the send and invalidate the review. */
    change(fields = {}) { Object.assign(w, fields); w.generation++; },
  };
  return w;
}

export function world({ keys = [k1], deposit = 0n, balance = 10n ** 18n, indexedDB = memoryIndexedDB(), chain = null,
  now } = {}) {
  const clock = { offset: 0 };
  const time = now || (() => Math.floor(Date.now() / 1000) + clock.offset);
  const c = chain || createPrefundChain({ signer: SIGNER, keys, deposit, balances: { [FUNDER]: balance }, now: time });
  const wallet = walletDouble(c);
  const store = new FundingAttemptStore({ indexedDB });
  const timers = [];
  const controller = new PrefundController({ rpc: c.rpc, wallet, store, clock: time, uuid: () => crypto.randomUUID(),
    setTimer: (fn, ms) => { const id = setTimeout(fn, ms); timers.push(id); return id; },
    clearTimer: (id) => clearTimeout(id) });
  wallet.onChange = () => controller.walletChanged();
  return { chain: c, wallet, store, controller, clock, indexedDB, stop: () => timers.forEach((t) => clearTimeout(t)) };
}

/** Explicit intents up to a complete reviewed funding (Q = P1 - deposit by default); the send click is separate. */
export async function reviewed(w, { key = k1, fee = '1' } = {}) {
  if (!w.controller.view().attempt.loaded) await w.controller.start();
  w.controller.setAuthorityText(anchorText(SIGNER, key));
  await w.controller.inspect();
  w.controller.setFee(fee);
  return w.controller.view();
}

/** Mines `n` empty blocks so the funding receipt reaches the required confirmations. */
export const mine = (w, n = 1) => { for (let i = 0; i < n; i++) w.chain.mine(); };

export { anchorText };
