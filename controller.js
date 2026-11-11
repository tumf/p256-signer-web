// Single owner of deployment state: import, wallet generation, read-only inspection, the explicit wallet-delegated
// deployment action (one single-flight wallet send), the durable public attempt record and read-only
// settlement/resume. New attempts are v2: the selected wallet owns nonce, gas and fees and final approval.
// Byte-preserved v1 records keep their original frozen ceilings and walletOverride semantics.
// The UI renders `view()` and calls these commands; it never decides domain behaviour from labels.
import {
  buildPlan, FACTORY, handoffChain, hexQuantity, inspect, INSPECTION_MESSAGES, parseFragment, parseHandoff,
  PublicError, quantity, scanReplacement, observe, verifyCancellation, verifySettlement,
} from './model.js';
import { STORAGE_MESSAGES, STORE_TIMEOUT_MS } from './attempt-store.js';

export const MAX_RECORD_BYTES = 16384;
export const SEND_TIMEOUT_MS = 60_000;
export const POLL_INTERVAL_MS = 12_000;
export const MAX_POLLS = 50;
export const POLL_WINDOW_MS = 600_000;
export const REFRESH_BUDGET_MS = 30_000;

// Closed exact schemas. v1: the original frozen-ceiling record (historical, read and reconciled only). v2: the
// wallet-delegated record: v1 keys minus capWei/maxTotal, and `transaction.nonce` is the pending-nonce lookup hint
// read just before admission (never a requested nonce, never proof of consumption).
const RECORD_KEYS_V1 = ['version', 'id', 'manifest', 'chainId', 'from', 'to', 'dataHash', 'salt', 'address',
  'transaction', 'capWei', 'maxTotal', 'submission', 'sendEntered', 'hash', 'replacementHash', 'state', 'reason',
  'observed', 'effectiveNonce'].sort();
const RECORD_KEYS_V2 = RECORD_KEYS_V1.filter((key) => key !== 'capWei' && key !== 'maxTotal');
const TX_KEYS_V1 = ['chainId', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce', 'value'];
const TX_KEYS_V2 = ['chainId', 'nonce', 'value'];
const OBSERVED_KEYS = ['gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce'];
const RECORD_STATES = ['walletPending', 'pending', 'unknown', 'success', 'failed', 'rejected', 'walletOverride'];
const CLEARABLE = ['success', 'failed', 'rejected'];
// Reasons marking `replacementHash` as the transaction that consumed the verified effective nonce
// (proved cancellation/unrelated replacement) rather than an identity-matching replacement.
const CANCEL_REASONS = ['cancelled', 'cancel-unverified'];
// Immutable attempt identity: the frozen request; state/hash/lineage/observations are not identity. The v1 list is
// unchanged (existing identities stay byte-compatible); v2 has no caps, so they are omitted, never `undefined`.
const IDENTITY_KEYS_V1 = ['id', 'version', 'manifest', 'chainId', 'from', 'to', 'dataHash', 'salt', 'address',
  'transaction', 'capWei', 'maxTotal', 'submission', 'sendEntered'];
const IDENTITY_KEYS_V2 = IDENTITY_KEYS_V1.filter((key) => key !== 'capWei' && key !== 'maxTotal');
// A wallet outcome is reconciled against the latest row at most this many times (with STORE_TIMEOUT_MS total).
const OUTCOME_ATTEMPTS = 3;
// Strength of a wallet outcome for one identity: a weaker outcome never replaces or releases a stronger held one.
const OUTCOME_RANK = { timeout: 1, malformed: 2, error: 2, hash: 3 };
const QUANTITY = /^0x(0|[1-9a-f][0-9a-f]{0,63})$/;
const HASH = /^0x[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export const MESSAGES = {
  drift: '送信前の再確認で配備内容または接続状態が変わりました。もう一度照合してください。',
  nonce: '送信前にこのアカウントの保留中nonceを読み取れなかったため、送信していません。もう一度照合してください。',
  deployedNow: '送信前の再確認で、この予定アドレスは配備済みと確認されました。送信しません。',
  storage: '送信記録をこの端末に保存できないため、送信できません。ブラウザの保存領域を確認してください。',
  storageUnavailable: 'このブラウザの保存領域を使えないため、送信記録を確認・保存できません。送信できません。',
  tampered: '保存情報を検証できません',
  hashFormat: '取引ハッシュは0xで始まる32バイトの16進数です。',
  hashMismatch: 'このハッシュは保存済みの配備内容（chain・from・to・data・value）と一致しません。',
  hashRpc: '取引ハッシュを読取りRPCで確認できませんでした。',
  locked: '未解決の配備記録があるため、新しい送信はできません。',
  otherAttempt: '別のタブまたはウィンドウの送信記録が保存されています。この記録を確認するまで新しい送信はできません。',
  hashBefore: 'このハッシュの取引は今回の送信より前のブロックで確定しています。この送信の取引ではありません。',
  legacy: STORAGE_MESSAGES.legacy,
  lateConflict: 'ウォレットが別の取引ハッシュを返しました。保存済みの記録を優先し、この記録は変更しません。',
  cleared: 'この送信記録は別のタブまたはウィンドウで消去されました。新しい送信はページを再読み込みしてから行ってください。',
  interrupted: '操作の途中でウォレットの状態または配備データが変わったため、配備を中断しました。送信していません。もう一度「ウォレットで配備」を押してください。',
};

const FALLBACK_MESSAGES = { ...INSPECTION_MESSAGES, json: '配備データを読み取れません。',
  fragment: '配備データを読み取れません。' };

/** Public Japanese error; a non-public failure is a JSON-RPC error (`rpc`) or unreachable transport (`offline`). */
function plainError(error, fallback = 'offline') {
  if (error instanceof PublicError) return { code: error.code, message: error.message };
  const code = fallback === 'offline' && error && Number.isInteger(error.code) ? 'rpc' : fallback;
  return { code, message: FALLBACK_MESSAGES[code] || INSPECTION_MESSAGES.offline };
}

function canonicalQuantity(value) {
  return typeof value === 'string' && QUANTITY.test(value);
}

/**
 * Validates one closed exact attempt schema (v1 or v2, discriminated by `version`) and every duplicated field
 * against a recomputed plan. Unknown versions, extra/missing keys and mixed v1/v2 fee fields are rejected.
 */
export function validateRecord(text) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > MAX_RECORD_BYTES) return null;
  let record;
  try { record = JSON.parse(text); } catch { return null; }
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  const v1 = record.version === 1;
  if (!v1 && record.version !== 2) return null;
  if (JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(v1 ? RECORD_KEYS_V1 : RECORD_KEYS_V2)) return null;
  try {
    if (typeof record.id !== 'string' || !/^[0-9a-f-]{36}$/.test(record.id)) return null;
    if (!record.manifest || typeof record.manifest !== 'object') return null;
    const handoff = parseHandoff(JSON.stringify(record.manifest));
    const plan = buildPlan(handoff);
    // The record's chain is its own manifest's closed chain, never another chain's (legacy records: Polygon).
    const chain = handoffChain(handoff);
    if (record.chainId !== chain.id || record.to !== FACTORY || record.dataHash !== plan.dataHash
        || record.salt !== handoff.salt || record.address !== plan.address) return null;
    if (typeof record.from !== 'string' || !ADDRESS.test(record.from)) return null;
    const tx = record.transaction;
    if (!tx || typeof tx !== 'object' || Array.isArray(tx)
        || JSON.stringify(Object.keys(tx).sort()) !== JSON.stringify(v1 ? TX_KEYS_V1 : TX_KEYS_V2)
        || tx.chainId !== chain.hex || tx.value !== '0x0' || !canonicalQuantity(tx.nonce)) return null;
    if (v1) {
      for (const key of ['gas', 'maxFeePerGas', 'maxPriorityFeePerGas']) {
        if (!canonicalQuantity(tx[key])) return null;
      }
      if (!canonicalQuantity(record.capWei) || !canonicalQuantity(record.maxTotal)) return null;
      const maxTotal = BigInt(tx.gas) * BigInt(tx.maxFeePerGas);
      if (BigInt(record.maxTotal) !== maxTotal || BigInt(record.capWei) < maxTotal || BigInt(tx.gas) === 0n
          || BigInt(tx.maxPriorityFeePerGas) > BigInt(tx.maxFeePerGas)) return null;
    } else if (record.state === 'walletOverride') {
      // Wallet-selected fees can never create an override for a v2 operation.
      return null;
    }
    const sub = record.submission;
    if (!sub || typeof sub !== 'object' || JSON.stringify(Object.keys(sub).sort()) !== '["blockHash","blockNumber"]'
        || !canonicalQuantity(sub.blockNumber) || typeof sub.blockHash !== 'string' || !HASH.test(sub.blockHash)) {
      return null;
    }
    if (record.sendEntered !== true || !RECORD_STATES.includes(record.state)) return null;
    for (const key of ['hash', 'replacementHash']) {
      if (record[key] !== null && (typeof record[key] !== 'string' || !HASH.test(record[key]))) return null;
    }
    if (record.replacementHash !== null && record.hash === null) return null;
    if (record.reason !== null && (typeof record.reason !== 'string' || record.reason.length > 40)) return null;
    if (record.observed !== null) {
      const observed = record.observed;
      if (typeof observed !== 'object' || JSON.stringify(Object.keys(observed).sort()) !== JSON.stringify(OBSERVED_KEYS)
          || !OBSERVED_KEYS.every((key) => canonicalQuantity(observed[key]))) return null;
      // v2 observations are canonical real-transaction quantities: positive gas, priority <= max.
      if (!v1 && (BigInt(observed.gas) === 0n || BigInt(observed.maxPriorityFeePerGas) > BigInt(observed.maxFeePerGas))) {
        return null;
      }
    }
    if (record.effectiveNonce !== null && (!canonicalQuantity(record.effectiveNonce) || record.hash === null)) return null;
    // A consuming-transaction lineage needs its effective nonce and replacement hash.
    if (CANCEL_REASONS.includes(record.reason) && (record.replacementHash === null || record.effectiveNonce === null
        || record.state !== (record.reason === 'cancelled' ? 'failed' : 'unknown'))) return null;
    // Only hash-bearing records can claim a chain outcome; rejected means no hash was returned.
    if (['pending', 'success', 'failed', 'walletOverride'].includes(record.state) && record.hash === null) return null;
    if (record.state === 'rejected' && record.hash !== null) return null;
    return { record, plan, handoff };
  } catch {
    return null;
  }
}

/** Key-sorted JSON, so equal values compare equal whatever key order the writer used. */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/** Exact immutable identity of a validated attempt record (version-aware; v1 strings are unchanged). */
export function identityOf(record) {
  return canonical((record.version === 2 ? IDENTITY_KEYS_V2 : IDENTITY_KEYS_V1).map((key) => record[key]));
}

/**
 * v1 only: sticky walletOverride, or validated observed values above the frozen ceilings (model.observe
 * comparisons). A v2 record has no app ceiling, so wallet-selected values are never an override.
 */
function overridden(record) {
  if (record.version === 2) return false;
  if (record.state === 'walletOverride') return true;
  return record.observed !== null && observe(record.observed, record).override;
}

/**
 * Closed wallet-outcome precedence against the latest stored row. Returns `foreign` (no identical identity: no
 * write), `unchanged` (stored evidence already wins or matches), `notice` (a different hash that stored
 * terminal/override/lineage evidence outranks; display only) or `write` with the next record.
 */
export function decideOutcome(raw, identity, outcome) {
  const valid = typeof raw === 'string' ? validateRecord(raw) : null;
  if (!valid || identityOf(valid.record) !== identity) return { kind: 'foreign' };
  const current = valid.record;
  if (outcome.kind === 'hash') {
    if (current.hash === outcome.hash) return { kind: 'unchanged', record: current };
    const replaceable = ['walletPending', 'pending', 'unknown'].includes(current.state)
      && current.replacementHash === null && !CANCEL_REASONS.includes(current.reason) && !overridden(current);
    if (!replaceable) return { kind: 'notice', record: current };
    return { kind: 'write', record: { ...current, hash: outcome.hash, replacementHash: null, effectiveNonce: null,
      observed: null, state: 'pending', reason: null } };
  }
  // Timeout, malformed reply, rejection or transport error never touch a stored hash or stronger evidence.
  if (current.hash !== null) return { kind: 'unchanged', record: current };
  let next = null;
  if (outcome.kind === 'timeout' && current.state === 'walletPending') next = { state: 'unknown', reason: 'send-timeout' };
  if (outcome.kind === 'malformed' && ['walletPending', 'unknown'].includes(current.state)) {
    next = { state: 'unknown', reason: 'malformed-hash' };
  }
  if (outcome.kind === 'error' && ['walletPending', 'unknown'].includes(current.state)) {
    // Only a genuine EIP-1193 4001 for the still-pending hashless attempt whose send has not timed out in this
    // page is a definitive rejection; after a timeout (saved or not) the attempt stays unknown.
    if (outcome.code === 4001 && current.state === 'walletPending' && !outcome.afterTimeout) {
      next = { state: 'rejected', reason: 'user-rejected' };
    } else if (outcome.afterTimeout && current.state === 'walletPending') {
      next = { state: 'unknown', reason: 'send-timeout' };
    } else {
      next = { state: 'unknown', reason: 'send-error' };
    }
  }
  if (!next || (next.state === current.state && next.reason === current.reason)) return { kind: 'unchanged', record: current };
  return { kind: 'write', record: { ...current, ...next } };
}

export class RegistrationController {
  /**
   * @param {object} deps
   * @param {(method: string, params: any[]) => Promise<any>} [deps.rpc]  same-origin read-only Polygon `/rpc`
   * @param {(chain: object) => (method: string, params: any[]) => Promise<any>} [deps.rpcFor]  the same-origin
   *   read-only relay route of one closed chain (`chains.js`); every read of a plan uses its own chain only
   * @param {import('./wallet.js').WalletManager} deps.wallet
   * @param {import('./attempt-store.js').AttemptStore} deps.store  transactional attempt authority (untrusted bytes)
   * @param {object} [deps.clock]  `{ now, setTimeout, clearTimeout }`
   * @param {() => string} deps.uuid
   * @param {(view: object) => void} [deps.onState]
   * @param {{read: () => string|null, write: (text: string) => void, remove: () => void}} [deps.planStore]
   *   bounded per-tab copy of the validated public plan (sessionStorage); never an attempt authority
   */
  constructor({ rpc, rpcFor, wallet, store, clock, uuid, onState, planStore }) {
    this.rpc = rpc;
    this.rpcFor = rpcFor || ((chain) => {
      if (chain.id !== 137) throw new PublicError('chain', INSPECTION_MESSAGES.chain);
      return (method, params) => this.rpc(method, params);
    });
    this.wallet = wallet;
    this.store = store;
    this.rootStore = store;
    this.storeAddress = null;
    this.storeChain = null;
    this.loadToken = null;
    this.planStore = planStore || null;
    this.clock = clock || { now: () => Date.now(), setTimeout: (f, ms) => setTimeout(f, ms),
      clearTimeout: (id) => clearTimeout(id) };
    this.uuid = uuid;
    this.onState = onState || (() => {});
    this.generation = 0;
    this.plan = null;
    this.inputError = null;
    this.inspection = { status: 'idle', error: null, result: null };
    // The fresh operation review, bound to the generation/wallet generation/provider/account it was inspected for.
    this.review = null;
    this.attempt = null;
    this.attemptPlan = null;
    this.settlement = null;
    this.storageError = null;
    this.resumeError = null;
    this.sendNotice = null;
    this.sendLock = false;
    this.clearPending = false;
    this.manualHashError = null;
    this.refreshing = false;
    this.refreshToken = null;
    this.resuming = false;
    this.nonceVerified = null;
    this.polls = 0;
    this.pollStarted = null;
    this.pollTimer = null;
    this.pollChain = null;
    this.pollExpired = false;
    this.focus = { target: null, seq: 0 };
    this.sendCount = 0;
    this.pendingWalletOutcomes = 0;
    this.outcomeWrites = 0;
    // Storage authority: nothing is admitted until the first load settles. `snapshot` is the last loaded, adopted
    // or committed store row and is the only base for a conditional write.
    this.initializing = true;
    this.snapshot = null;
    // A wallet outcome that could not be saved (kept in memory only), a conflicting late hash shown as a notice,
    // a newer same-attempt row adopted read-only, and a clear by another page that requires a reload.
    this.unsaved = null;
    this.lateHash = null;
    this.newerAdopted = false;
    this.reloadRequired = false;
    // A wallet callback for a sent attempt whose row is gone: the reload reason and any returned hash, kept until
    // reload independently of the displayed attempt, review invalidation and wallet events.
    this.staleNotice = null;
    this.staleHash = null;
    // Identity of an attempt this page sent or displayed whose row another page cleared or replaced. Its
    // "cleared elsewhere" notice belongs to that attempt only, never to a different live attempt displayed later.
    this.clearedIdentity = null;
    // The one explicit operation in flight (ウォレットで配備): its token binds the plan, the selected wallet and, once
    // connected, the provider/account it continues for. External drift cancels it; a send still has sendLock.
    this.operation = null;
    this.operationSeq = 0;
  }

  // -------------------------------------------------------------------------------------------
  // View

  setFocus(target) {
    this.focus = { target, seq: this.focus.seq + 1 };
  }

  emit() {
    const address = this.plan && this.plan.address.toLowerCase();
    // Attempts are scoped by the plan's own chain and address: the same address on another chain is a different
    // deployment, never this one's attempt or outcome.
    const chain = this.plan ? handoffChain(this.plan.handoff) : null;
    // A timeout is not a settled provider promise; keep every old-scope writer bound until it finishes.
    if (address && this.rootStore.forAddress && (address !== this.storeAddress || chain !== this.storeChain)
        && !this.pendingWalletOutcomes && !this.outcomeWrites && !this.sendLock && !this.unsaved
        && !this.operation && !this.refreshing && !(this.sendCount && this.reloadRequired)) {
      this.storeAddress = address;
      this.storeChain = chain;
      this.stopTracking();
      this.releaseAttempt();
      this.snapshot = null;
      this.resumeError = null;
      this.storageError = null;
      this.reloadRequired = false;
      this.clearedIdentity = this.staleNotice = this.staleHash = this.lateHash = null;
      this.store = this.rootStore.forAddress(address, chain);
      this.loadAttempt();
    }
    // The inline clear confirmation exists only while the attempt is still clearable.
    if (this.clearPending && !this.clearable()) this.clearPending = false;
    this.onState(this.view());
  }

  phase() {
    if (this.resumeError) return 'resumeError';
    if (this.initializing && !this.storageError) return 'initializing';
    // A reloaded hash-bearing record claims no outcome until its first read-only refresh completes.
    if (this.attempt && this.resuming) return 'resuming';
    if (this.attempt) return this.attempt.state === 'pending' ? 'txPending' : this.attempt.state;
    if (this.storageError) return 'storageError';
    if (!this.plan) return this.inputError ? 'inputError' : 'empty';
    const status = this.wallet.status;
    if (status === 'connecting') return 'connecting';
    if (status !== 'connected' && status !== 'wrongChain') return 'disconnected';
    if (status === 'wrongChain') return 'wrongChain';
    if (this.inspection.status === 'loading') return 'inspecting';
    if (this.inspection.status === 'error') return 'inspectionError';
    if (this.inspection.status === 'deployed') return 'deployed';
    if (this.inspection.status !== 'undeployed') return 'connected';
    return this.canSend() ? 'ready' : 'review';
  }

  locked() {
    return Boolean(this.attempt || this.resumeError || this.sendLock || this.reloadRequired || this.initializing
      || (this.rootStore.forAddress && (this.pendingWalletOutcomes || this.outcomeWrites || this.unsaved)));
  }

  canInspect() {
    return Boolean(this.plan) && this.wallet.status === 'connected' && !this.locked()
      && this.inspection.status !== 'loading' && !this.storageError;
  }

  /**
   * The explicit operation action is the only operation intent: a validated plan, a fresh review bound to the current
   * generation/wallet/provider/account on the plan's chain, ready storage, no attempt and no lock. No cap or checkbox.
   */
  canSend() {
    const r = this.review;
    return Boolean(this.plan && r && r.generation === this.generation && r.walletGeneration === this.wallet.generation
      && r.provider === this.wallet.provider && this.wallet.status === 'connected' && this.wallet.chainId === this.chainHex
      && this.wallet.account && this.wallet.account.toLowerCase() === r.from.toLowerCase()
      && !this.locked() && !this.storageError);
  }

  /**
   * The first stage the single explicit action ウォレットで配備 would perform now, or null when nothing can be done
   * (no plan, no selected wallet, an operation/send in flight, a stored attempt, a lock, storage failure, or a
   * deployed target). Exactly one of: connect, switch, inspect (read-only), send. One activation continues through
   * the following stages (deploy()) up to the single-flight send; only `send()` reaches eth_sendTransaction.
   */
  nextStage() {
    if (!this.plan || this.locked() || this.storageError || this.operation) return null;
    const status = this.wallet.status;
    if (status === 'connecting' || this.inspection.status === 'loading') return null;
    if (status === 'disconnected') return this.wallet.selectedId ? 'connect' : null;
    if (status === 'wrongChain') return 'switch';
    if (status !== 'connected') return null;
    if (this.canSend()) return 'send';
    return this.inspection.status === 'deployed' ? null : 'inspect';
  }

  view() {
    // Operation identity only: no estimate, gas, fee, total or nonce is reviewed by this page.
    const review = this.review && { from: this.review.from, block: this.review.block };
    const attempt = this.attempt && { ...this.attempt, address: this.attempt.address };
    const heldHash = this.unsaved && this.unsaved.outcome.kind === 'hash' ? this.unsaved.outcome.hash : null;
    const unsavedNotice = heldHash && (!this.shows(this.unsaved.identity) || attempt.hash !== heldHash)
      ? `保存済み記録とは別に、ウォレット応答を未保存で保持しています。\n${heldHash}\nページを閉じずに「状況を更新」で保存を再試行してください。`
      : null;
    return {
      phase: this.phase(), generation: this.generation, wallet: this.wallet.snapshot(),
      plan: this.plan && { address: this.plan.address, handoff: this.plan.handoff, transaction: this.plan.transaction },
      inputError: this.inputError, inspection: { status: this.inspection.status, error: this.inspection.error,
        block: this.inspection.result && this.inspection.result.block },
      review, canInspect: this.canInspect(), canSend: this.canSend(), locked: this.locked(),
      stage: this.nextStage(), operation: this.operation ? this.operation.stage : null,
      scopeWaiting: Boolean(this.rootStore.forAddress && (this.pendingWalletOutcomes || this.outcomeWrites || this.unsaved)),
      submitting: this.sendLock && (!this.attempt || this.attempt.state === 'walletPending'),
      attempt, settlement: this.settlement, storageError: this.storageError, resumeError: this.resumeError,
      sendNotice: [this.staleNotice, this.sendNotice, unsavedNotice].filter(Boolean).join('\n') || null, clearable: this.clearable(), clearPending: this.clearPending,
      manualHashError: this.manualHashError, refreshing: this.refreshing, pollExpired: this.pollExpired,
      focus: this.focus, sendCount: this.sendCount, initializing: this.initializing && !this.storageError,
      notices: { unsaved: Boolean(this.unsaved), lateHash: this.lateHash, newer: this.newerAdopted,
        reloadRequired: this.reloadRequired, staleHash: this.staleHash,
        cleared: Boolean(this.attempt) && identityOf(this.attempt) === this.clearedIdentity },
    };
  }

  // -------------------------------------------------------------------------------------------
  // Invalidation

  invalidateReview() {
    this.generation++;
    this.inspection = { status: 'idle', error: null, result: null };
    this.review = null;
    this.sendNotice = null;
  }

  /** Wallet select/connect/account/chain/disconnect events invalidate readiness, never an attempt. */
  walletChanged(event) {
    const op = this.operation;
    // Only the events of the operation's own current stage are expected; anything else is external drift and
    // cancels the operation at its next check (it never continues with stale intent, let alone sends).
    if (op && !(event && this.expectedEvent(op, event.type))) op.cancelled = true;
    if (event && event.type === 'discovery' && !this.wallet.selectedId) {
      const choices = this.wallet.choices().filter((choice) => !choice.disabled);
      if (choices.length === 1) this.selectWallet(choices[0].id);
    }
    if (event && ['discovery', 'pairing'].includes(event.type)) return this.emit();
    this.invalidateReview();
    if (event && event.type === 'connected') this.setFocus('wallet');
    if (event && ['pairing-cancelled', 'disconnect'].includes(event.type)) this.setFocus('connect');
    if (event && event.type === 'connect-failed') this.setFocus('connect');
    this.emit();
  }

  // -------------------------------------------------------------------------------------------
  // Import

  prepare(text) {
    this.invalidateReview();
    this.plan = null;
    this.inputError = null;
    try {
      this.plan = buildPlan(parseHandoff(text));
      this.targetPlan();
      this.setFocus('plan');
    } catch (error) {
      this.inputError = plainError(error, 'json');
      this.setFocus('error');
    }
    this.rememberPlan();
    this.emit();
  }

  inputEdited() {
    if (!this.plan && !this.inputError && this.inspection.status === 'idle') return;
    this.invalidateReview();
    this.plan = null;
    this.inputError = null;
    this.rememberPlan();
    this.emit();
  }

  /** The per-tab plan copy mirrors the current validated plan exactly (public manifest bytes only, or nothing). */
  rememberPlan() {
    if (!this.planStore) return;
    try {
      if (this.plan) this.planStore.write(JSON.stringify(this.plan.handoff));
      else this.planStore.remove();
    } catch {
      // A denied or full session store only loses the reload convenience; nothing else depends on it.
    }
  }

  /**
   * Restores the plan remembered by this tab after a reload (no fragment present). The copy passes exactly the
   * input boundary (parseHandoff/buildPlan); a missing, oversized, malformed or unbound copy is dropped. Restoring
   * never touches the wallet, the attempt store or any send path.
   */
  restorePlan() {
    if (!this.planStore || this.plan || this.inputError) return false;
    let text;
    try {
      text = this.planStore.read();
    } catch {
      return false;
    }
    if (typeof text !== 'string' || text === '') return false;
    let plan;
    try {
      plan = buildPlan(parseHandoff(text));
    } catch {
      try { this.planStore.remove(); } catch { /* unreadable copy stays unused */ }
      return false;
    }
    this.invalidateReview();
    this.plan = plan;
    this.targetPlan();
    this.inputError = null;
    this.setFocus('plan');
    this.emit();
    return true;
  }

  /** Consumes a nonempty fragment: replace history first (no navigation), then parse a bounded copy. */
  consumeFragment(location, history) {
    const hash = typeof location.hash === 'string' ? location.hash.slice(0, 5462 + 32) : '';
    const oversized = typeof location.hash === 'string' && location.hash.length > hash.length;
    if (!hash || hash === '#') return false;
    history.replaceState(null, '', location.pathname);
    this.invalidateReview();
    this.plan = null;
    this.inputError = null;
    try {
      if (oversized) throw new PublicError('oversize', '配備データが大きすぎます（JSON上限4096バイト）。');
      this.plan = buildPlan(parseFragment(hash));
      this.targetPlan();
      this.setFocus('plan');
    } catch (error) {
      this.inputError = plainError(error, 'fragment');
      this.setFocus('error');
    }
    // A fragment always wins over the remembered copy: a valid one replaces it, an invalid one leaves no copy.
    this.rememberPlan();
    this.emit();
    return true;
  }

  // -------------------------------------------------------------------------------------------
  // Wallet commands (never send)

  selectWallet(id) {
    if (this.wallet.select(id)) this.setFocus(null);
  }

  /** The read-only relay of a plan's own closed chain. */
  planRPC(plan) { return this.rpcFor(handoffChain(plan.handoff)); }

  /** The validated plan's chain becomes the wallet target; a wallet on another chain is then `wrongChain`. */
  targetPlan() {
    if (this.plan && typeof this.wallet.setTarget === 'function') this.wallet.setTarget(handoffChain(this.plan.handoff));
  }

  /** The current plan's chain (Polygon without a plan). */
  get chainHex() { return this.plan ? handoffChain(this.plan.handoff).hex : '0x89'; }

  connect() { return this.wallet.connect(); }

  cancelPairing() { this.wallet.cancelPairing(); }

  /** The explicit switch to the plan's chain (legacy name kept for the page binding). */
  switchPolygon() { return this.wallet.switchChain ? this.wallet.switchChain() : this.wallet.switchPolygon(); }

  disconnect() { return this.wallet.disconnect(); }

  // -------------------------------------------------------------------------------------------
  // Read-only inspection and review

  async inspect() {
    if (!this.canInspect()) return;
    const plan = this.plan;
    const from = this.wallet.account;
    this.invalidateReview();
    const generation = this.generation;
    const bound = { generation, walletGeneration: this.wallet.generation, provider: this.wallet.provider };
    this.inspection = { status: 'loading', error: null, result: null };
    this.emit();
    let result;
    try {
      result = await inspect(this.planRPC(plan), plan);
    } catch (error) {
      if (generation !== this.generation) return;
      this.inspection = { status: 'error', error: plainError(error), result: null };
      this.setFocus('error');
      return this.emit();
    }
    // A changed generation (input/provider/account/chain/disconnect) suppresses the stale result.
    if (generation !== this.generation) return;
    const block = { number: result.block.number.toString(), hash: result.block.hash };
    this.inspection = { status: result.kind, error: null, result: { block } };
    this.review = result.kind === 'undeployed' && bound.walletGeneration === this.wallet.generation
      && bound.provider === this.wallet.provider ? { ...bound, from, block } : null;
    this.setFocus('review');
    this.emit();
  }

  // -------------------------------------------------------------------------------------------
  // The single explicit action

  /**
   * ウォレットで配備: one explicit activation continues, stage by stage, from the settled state up to the single
   * send: connect (when disconnected), the explicit `0x89` switch (when off Polygon), the strict same-block
   * read-only inspection and then the unchanged single-flight `send()` (fresh revalidation, pending-nonce lookup,
   * durable CAS admission, exactly one eth_sendTransaction). The wallet's own connection, switch and transaction
   * approvals stay with the user; a rejected approval ends the activation at that stage with the wallet's message.
   *
   * The operation token is re-checked after every await (`live`): edited input, a different selection, provider,
   * account or chain, or a disconnect, and any wallet event that is not the expected result of the operation's own
   * current stage, cancel the activation before its next stage. A deployed readback completes without a send.
   * A repeated activation while one is in flight performs nothing. Resolves true only when a send was issued.
   */
  async deploy() {
    const stage = this.nextStage();
    if (stage === null) return false;
    const op = { seq: ++this.operationSeq, stage, plan: this.plan, selectedId: this.wallet.selectedId,
      provider: this.wallet.provider, from: this.wallet.account ? this.wallet.account.toLowerCase() : null,
      cancelled: false };
    this.operation = op;
    this.sendNotice = null;
    this.emit();
    // A stage that ends the activation releases the operation first, so the retry focus lands on the action.
    const ended = (focus) => {
      this.operation = null;
      if (focus) this.setFocus(focus);
      return false;
    };
    try {
      if (stage === 'connect') {
        await this.connect();
        if (!this.live(op)) return this.interrupted(op);
        // Rejected, unavailable, cancelled pairing or a malformed reply: the wallet error stands, nothing continues.
        if (this.wallet.status === 'disconnected' || !this.wallet.account) return ended('connect');
        op.provider = this.wallet.provider;
        op.from = this.wallet.account.toLowerCase();
      }
      if (this.wallet.status === 'wrongChain') {
        op.stage = 'switch';
        this.emit();
        await this.switchPolygon();
        if (!this.live(op)) return this.interrupted(op);
        // Rejected/4902 or still another chain: the manual-switch instruction stands, nothing continues.
        if (this.wallet.status !== 'connected') return ended('wallet');
      }
      if (!this.canSend()) {
        op.stage = 'inspect';
        await this.inspect();
        if (!this.live(op)) return this.interrupted(op);
        // Deployed readback: complete without a send. Inspection error: shown, nothing continues.
        if (this.inspection.status === 'deployed' || !this.canSend()) return ended(null);
      }
      op.stage = 'send';
      this.emit();
      return await this.send();
    } finally {
      if (this.operation === op) this.operation = null;
      this.emit();
    }
  }

  /** Wallet events that are the expected outcome of the operation's own current stage (never external drift). */
  expectedEvent(op, type) {
    switch (type) {
      case 'discovery': case 'pairing': return true;
      case 'connecting': case 'connected': case 'connect-failed': case 'pairing-cancelled': return op.stage === 'connect';
      case 'switch': return op.stage === 'switch';
      // The chain change the operation itself requested; any other chain, or one outside the switch stage, is drift.
      case 'chainChanged': return op.stage === 'switch' && this.wallet.chainId === this.chainHex;
      default: return false; // select, accountsChanged, disconnect and anything unknown
    }
  }

  /** The operation is still the current one and nothing it was started for has changed under it. */
  live(op) {
    if (this.operation !== op || op.cancelled || this.plan !== op.plan || this.wallet.selectedId !== op.selectedId
        || this.reloadRequired) return false;
    if (op.provider === null) return true;
    return this.wallet.provider === op.provider && this.wallet.status !== 'disconnected'
      && typeof this.wallet.account === 'string' && this.wallet.account.toLowerCase() === op.from;
  }

  /** External drift stopped the activation before its next stage: say so; the next activation starts afresh. */
  interrupted(op) {
    if (this.operation === op) this.operation = null;
    if (!this.attempt && !this.sendLock) {
      this.sendNotice = MESSAGES.interrupted;
      this.setFocus('error');
    }
    this.emit();
    return false;
  }

  // -------------------------------------------------------------------------------------------
  // Single-flight send

  /** The send stage of ウォレットで配備 (also the direct command). Synchronously locks before any await. */
  send() {
    if (this.sendLock || !this.canSend()) return Promise.resolve(false);
    this.sendLock = true;
    const frozen = {
      generation: this.generation, walletGeneration: this.wallet.generation, provider: this.wallet.provider,
      from: this.review.from, plan: this.plan, review: this.review,
    };
    this.sendNotice = null;
    this.emit();
    return this.revalidateAndSend(frozen);
  }

  drift(message = MESSAGES.drift) {
    this.sendLock = false;
    this.invalidateReview();
    this.sendNotice = message;
    this.setFocus('error');
    this.emit();
    return false;
  }

  unchanged(frozen) {
    return frozen.generation === this.generation && frozen.walletGeneration === this.wallet.generation
      && frozen.provider === this.wallet.provider && this.wallet.status === 'connected'
      && this.wallet.chainId === handoffChain(frozen.plan.handoff).hex && typeof this.wallet.account === 'string'
      && this.wallet.account.toLowerCase() === frozen.from.toLowerCase() && !this.reloadRequired;
  }

  async revalidateAndSend(frozen) {
    const { plan, review, from } = frozen;
    const chain = handoffChain(plan.handoff), rpc = this.planRPC(plan);
    let fresh;
    try {
      const accounts = await this.wallet.request('eth_accounts', []);
      const chainId = await this.wallet.request('eth_chainId', []);
      if (!Array.isArray(accounts) || typeof accounts[0] !== 'string'
          || accounts[0].toLowerCase() !== from.toLowerCase() || String(chainId).toLowerCase() !== chain.hex
          || !this.unchanged(frozen)) return this.drift();
      fresh = await inspect(rpc, plan);
      if (!this.unchanged(frozen)) return this.drift();
      if (fresh.kind === 'deployed') {
        this.sendLock = false;
        this.invalidateReview();
        this.inspection = { status: 'deployed', error: null, result: { block: {
          number: fresh.block.number.toString(), hash: fresh.block.hash } } };
        this.sendNotice = MESSAGES.deployedNow;
        this.setFocus('review');
        this.emit();
        return false;
      }
      if (fresh.block.number < BigInt(review.block.number)) return this.drift();
    } catch {
      return this.drift();
    }
    // The freshest pending nonce is lookup evidence only (saved as the hint, never sent): a change since review is not
    // drift, but an unavailable or malformed value blocks admission; nothing is invented in its place.
    let nonce;
    try {
      nonce = quantity(await rpc('eth_getTransactionCount', [from, 'pending']));
    } catch {
      return this.drift(MESSAGES.nonce);
    }
    if (!this.unchanged(frozen)) return this.drift();
    // The wallet chooses nonce, gas and fees and gives final approval: the request is the operation identity only.
    const request = { from, to: plan.transaction.to, data: plan.transaction.data, value: '0x0', chainId: chain.hex };
    const record = {
      version: 2, id: this.uuid(), manifest: { ...plan.handoff }, chainId: chain.id, from, to: plan.transaction.to,
      dataHash: plan.dataHash, salt: plan.salt, address: plan.address,
      transaction: { chainId: chain.hex, value: '0x0', nonce: hexQuantity(nonce) },
      submission: { blockNumber: hexQuantity(fresh.block.number), blockHash: fresh.block.hash },
      sendEntered: true, hash: null, replacementHash: null, state: 'walletPending', reason: null, observed: null,
      effectiveNonce: null,
    };
    // Admission: one native transaction compares the loaded revision/bytes (an empty slot) and saves the frozen
    // walletPending attempt. Conflict adopts the current row read-only; failure blocks. Either way: zero sends.
    const text = JSON.stringify(record);
    const expected = this.snapshot;
    // A stale callback may have locked this page while the read-only revalidation was awaited.
    if (!this.unchanged(frozen)) return this.drift();
    if (!expected || expected.raw !== null) return this.yieldToSnapshot(expected);
    let admitted;
    try {
      admitted = await this.store.compareAndSet(expected, text);
    } catch (error) {
      this.sendLock = false;
      this.invalidateReview();
      return this.failStorage(error, 'storage');
    }
    if (!admitted.committed) return this.yieldToSnapshot(admitted.snapshot);
    this.snapshot = admitted.snapshot;
    // Last synchronous check after transaction completion; then the wallet is invoked with no await or emit between.
    if (!this.unchanged(frozen)) return this.withdraw(admitted.snapshot, text);
    this.adopt(record, plan);
    this.sendCount++;
    this.pendingWalletOutcomes++;
    let pending;
    try {
      pending = this.wallet.request('eth_sendTransaction', [request]);
    } catch (error) {
      // A synchronous provider throw takes the same rejection/unknown path as a rejected promise.
      pending = Promise.reject(error);
    }
    this.emit();
    // Every outcome is bound to the original immutable identity, never to whichever record is displayed later.
    const identity = identityOf(record);
    let settled = false;
    // The timeout fact is kept here, so a later rejection is judged after it even when the timeout was not saved.
    let timedOut = false;
    const timer = this.clock.setTimeout(() => {
      if (settled) return;
      timedOut = true;
      this.reconcileOutcome(identity, { kind: 'timeout' });
    }, SEND_TIMEOUT_MS);
    // The original promise is never cancelled; a late hash belongs to this frozen attempt.
    pending.then((hash) => {
      settled = true;
      this.clock.clearTimeout(timer);
      const returned = typeof hash === 'string' && HASH.test(hash.toLowerCase()) ? hash.toLowerCase() : null;
      return this.reconcileOutcome(identity, returned ? { kind: 'hash', hash: returned } : { kind: 'malformed' })
        .finally(() => {
          this.pendingWalletOutcomes--;
          if (this.shows(identity)) this.sendLock = false;
          this.emit();
        });
    }, (error) => {
      settled = true;
      this.clock.clearTimeout(timer);
      return this.reconcileOutcome(identity, { kind: 'error', code: error && error.code, afterTimeout: timedOut })
        .finally(() => {
          this.pendingWalletOutcomes--;
          if (this.shows(identity)) this.sendLock = false;
          this.emit();
        });
    });
    return true;
  }

  /** Post-commit/pre-call drift: conditionally clear only this admission (zero sends); uncertainty keeps it. */
  async withdraw(admitted, text) {
    const store = this.store;
    this.sendLock = false;
    let result = null;
    try {
      result = await store.compareAndSet(admitted, null);
    } catch {
      result = null;
    }
    if (this.store !== store) return false;
    if (result) this.snapshot = result.snapshot;
    this.drift();
    if (!result || !result.committed) {
      // Cleanup failed or lost a race: the conservative stored evidence is presented locked, never retried.
      const shown = result ? result.snapshot : admitted;
      if (shown.raw !== null) this.resume(shown.raw, shown.raw === text ? 'reload' : 'other-tab');
    }
    return false;
  }

  adopt(record, plan) {
    this.attempt = record;
    this.attemptPlan = plan;
    this.settlement = null;
    this.clearPending = false;
    this.resuming = false;
    // Only an effective nonce fetched from this attempt's own hash in this session is verified.
    this.nonceVerified = null;
  }

  /** A send found a different row (or no usable base): zero wallet requests; present that row locked. */
  yieldToSnapshot(snapshot) {
    this.sendLock = false;
    this.invalidateReview();
    if (!snapshot) return this.failStorage(null, 'storage');
    this.snapshot = snapshot;
    if (snapshot.raw === null) {
      // Another page cleared and the base moved: fresh review is required.
      this.sendNotice = MESSAGES.drift;
      this.setFocus('error');
      this.emit();
      return false;
    }
    this.sendNotice = MESSAGES.otherAttempt;
    this.resume(snapshot.raw, 'other-tab');
    return false;
  }

  /** Reports a bounded storage failure: corrupt rows are tamper errors, legacy conflicts and others block sends. */
  failStorage(error, fallback = 'storage-unavailable') {
    const code = error && error.code;
    if (code === 'corrupt') {
      this.resumeError = { code: 'tampered', message: MESSAGES.tampered };
    } else if (code === 'legacy-conflict') {
      this.storageError = { code: 'legacy-conflict', message: MESSAGES.legacy };
    } else {
      this.storageError = fallback === 'storage' ? { code: 'storage', message: MESSAGES.storage }
        : { code: 'storage-unavailable', message: MESSAGES.storageUnavailable };
    }
    this.setFocus('error');
    this.emit();
    return false;
  }

  /**
   * Conditional write of the next record of the same attempt against the captured snapshot. Identical bytes are
   * not rewritten: the latest row is read instead, and a moved row is reported as a conflict.
   */
  async commit(captured, next) {
    const nextRaw = JSON.stringify(next);
    const base = captured.raw === null ? null : validateRecord(captured.raw);
    // A tombstone, corrupt row or another attempt is not ownership: it is never written over or recreated.
    if (!base || identityOf(base.record) !== identityOf(next)) return { committed: false, snapshot: await this.store.read() };
    if (nextRaw === captured.raw) {
      const latest = await this.store.read();
      return { committed: latest.revision === captured.revision && latest.raw === captured.raw, snapshot: latest };
    }
    return this.store.compareAndSet(captured, nextRaw);
  }

  /** Installs a committed row of the displayed attempt (never an older revision than the one shown). */
  install(record, snapshot) {
    if (this.snapshot && snapshot.revision < this.snapshot.revision) return false;
    this.snapshot = snapshot;
    this.attempt = record;
    return true;
  }

  /**
   * Read-only adoption of the row that won a conflict. Never writes. Another attempt is resumed; the same attempt
   * keeps its polling window and is revalidated once read-only; a tombstone releases only a resolved attempt.
   */
  adoptLatest(snapshot, { candidate = null, revalidate = true } = {}) {
    const previous = this.attempt;
    this.snapshot = snapshot;
    this.clearPending = false;
    this.sendLock = false;
    this.invalidateReview();
    this.refreshToken = null;
    this.refreshing = false;
    if (snapshot.raw === null) {
      this.stopTracking();
      const resolved = [previous, candidate].some((r) => r && CLEARABLE.includes(r.state));
      if (previous && !resolved) {
        // Another page cleared while this one still sees it unresolved: stay locked, never recreate it.
        this.reloadRequired = true;
        this.clearedIdentity = identityOf(previous);
        return this.emit();
      }
      this.releaseAttempt();
      this.setFocus('plan');
      return this.emit();
    }
    const valid = validateRecord(snapshot.raw);
    if (!valid) {
      this.resumeError = { code: 'tampered', message: MESSAGES.tampered };
      this.setFocus('error');
      return this.emit();
    }
    if (!previous || valid.record.id !== previous.id) {
      this.stopTracking();
      this.sendNotice = MESSAGES.otherAttempt;
      return this.resume(snapshot.raw, 'other-tab');
    }
    const record = valid.record;
    // Observations are re-fetched, never trusted from storage.
    record.observed = null;
    if (record.state === 'walletPending' && previous.state !== 'walletPending') {
      record.state = previous.state;
      record.reason = previous.reason;
    }
    // Even an unchanged hash can carry a different replacement or terminal lineage.
    this.settlement = null;
    this.nonceVerified = null;
    this.attempt = record;
    this.attemptPlan = valid.plan;
    this.newerAdopted = true;
    this.resuming = Boolean(revalidate && record.hash && record.state !== 'rejected');
    this.emit();
    if (this.resuming) {
      const tracking = this.pollChain;
      this.refresh({ background: true, adopted: true }).then(() => {
        // refresh installs a new record object; identity and tracking generation, not object identity, survive it.
        if (tracking !== this.pollChain || !this.shows(identityOf(record)) || this.pollTimer !== null || this.pollExpired) return;
        if (this.pollStarted === null) this.startPolling(); else this.schedulePoll();
      });
    }
  }

  // -------------------------------------------------------------------------------------------
  // Wallet outcome reconciliation

  /**
   * Reconciles one wallet outcome for the original identity against the latest row (bounded retries within
   * STORE_TIMEOUT_MS). Exhausted contention or storage failure keeps the outcome in memory as unsaved; nothing
   * here ever sends, clears or recreates a row. A held unsaved outcome of the same identity that is stronger than
   * `outcome` is reconciled in its place. A background retry (poll) never moves focus.
   */
  async reconcileOutcome(identity, outcome, options = {}) {
    this.outcomeWrites++;
    try {
      return await this.persistOutcome(identity, outcome, options);
    } finally {
      this.outcomeWrites--;
      this.emit();
    }
  }

  async persistOutcome(identity, outcome, { background = false } = {}) {
    const deadline = this.clock.now() + STORE_TIMEOUT_MS;
    let latest = null;
    let decision = null;
    for (let attempt = 0; attempt < OUTCOME_ATTEMPTS; attempt++) {
      try {
        latest = await this.store.read();
      } catch {
        break;
      }
      // Another callback may have retained a stronger result while the storage read was pending.
      const held = this.unsaved && this.unsaved.identity === identity ? this.unsaved.outcome : null;
      if (held && OUTCOME_RANK[held.kind] > OUTCOME_RANK[outcome.kind]) outcome = held;
      decision = decideOutcome(latest.raw, identity, outcome);
      if (decision.kind !== 'write') return this.applyOutcomeDecision(identity, outcome, decision, latest, background);
      let result;
      try {
        result = await this.store.compareAndSet(latest, JSON.stringify(decision.record));
      } catch {
        break;
      }
      if (result.committed) {
        return this.applyCommittedOutcome(identity, outcome, decision.record, result.snapshot, background);
      }
      if (this.clock.now() > deadline) break;
    }
    return this.retainUnsaved(identity, outcome, latest, background);
  }

  /** True when the displayed attempt (if any) is the outcome's original attempt. */
  shows(identity) {
    return Boolean(this.attempt) && identityOf(this.attempt) === identity;
  }

  /** Drops the held unsaved outcome of `identity` only when `outcome` subsumes it (never for a weaker one). */
  releaseUnsaved(identity, outcome) {
    const held = this.unsaved;
    if (held && held.identity === identity && OUTCOME_RANK[outcome.kind] >= OUTCOME_RANK[held.outcome.kind]) {
      this.unsaved = null;
    }
  }

  applyOutcomeDecision(identity, outcome, decision, latest, background = false) {
    if (decision.kind === 'foreign') {
      // Missing, cleared, corrupt or another attempt: no write, and this page sent that attempt, so sending stays
      // locked until an explicit reload whatever is displayed. A returned hash stays visible as a notice of its
      // own (never a row of another displayed attempt); it grants no send or clear authority.
      if (this.unsaved && this.unsaved.identity === identity) this.unsaved = null;
      this.reloadRequired = true;
      if (this.shows(identity)) this.clearedIdentity = identity;
      if (outcome.kind === 'hash') this.staleHash = outcome.hash;
      this.staleNotice = this.staleHash ? `${MESSAGES.cleared}\n${MESSAGES.lateConflict}\n${this.staleHash}`
        : MESSAGES.cleared;
      if (this.shows(identity) && latest.revision !== (this.snapshot && this.snapshot.revision)) {
        return this.adoptLatest(latest, { revalidate: false });
      }
      return this.emit();
    }
    this.releaseUnsaved(identity, outcome);
    if (decision.kind === 'notice') this.lateHash = outcome.hash;
    if (this.shows(identity) && (!this.snapshot || latest.revision !== this.snapshot.revision)) {
      return this.adoptLatest(latest);
    }
    return this.emit();
  }

  applyCommittedOutcome(identity, outcome, record, snapshot, background = false) {
    this.releaseUnsaved(identity, outcome);
    if (this.attempt && !this.shows(identity)) {
      if (!this.snapshot || snapshot.revision > this.snapshot.revision) this.snapshot = snapshot;
      return this.emit();
    }
    const previous = this.attempt;
    if (!this.install(record, snapshot)) return this.emit();
    if (!this.attemptPlan) this.attemptPlan = validateRecord(JSON.stringify(record)).plan;
    if (!previous || previous.hash !== record.hash) {
      this.settlement = null;
      this.nonceVerified = null;
      // A refresh still running for a previous (manual) hash must not apply its result to this record.
      this.refreshToken = null;
      this.refreshing = false;
    }
    // The wallet's own reply and the explicit retry move focus; a background poll retry never does.
    if (['hash', 'error'].includes(outcome.kind) && !background) this.setFocus('settlement');
    if (outcome.kind === 'hash') this.startPolling();
    this.emit();
  }

  /** Persistence failed: keep the outcome and identity in memory, disclose it, and let 状況を更新 retry it. */
  retainUnsaved(identity, outcome, latest, background = false) {
    // Reads and writes can both suspend across a stronger wallet callback.
    const held = this.unsaved && this.unsaved.identity === identity ? this.unsaved.outcome : null;
    if (held && OUTCOME_RANK[held.kind] > OUTCOME_RANK[outcome.kind]) outcome = held;
    const base = latest && latest.raw !== null ? latest.raw : this.snapshot && this.snapshot.raw;
    const decision = decideOutcome(base, identity, outcome);
    if (decision.kind !== 'write') {
      return this.applyOutcomeDecision(identity, outcome, decision, latest || this.snapshot, background);
    }
    // `outcome` is never weaker than a held outcome of this identity (merged in reconcileOutcome).
    this.unsaved = { identity, outcome };
    if (this.shows(identity)) {
      // Displayed only; the stored row is unchanged until an explicit retry commits this same outcome.
      this.attempt = { ...decision.record, observed: null };
      if (outcome.kind === 'hash') {
        this.settlement = null;
        this.refreshToken = null;
        this.refreshing = false;
      }
    }
    // A timeout and a background poll retry never move focus.
    if (outcome.kind !== 'timeout' && !background) this.setFocus('settlement');
    this.emit();
  }

  // -------------------------------------------------------------------------------------------
  // Tracking

  stopTracking() {
    if (this.pollTimer !== null) this.clock.clearTimeout(this.pollTimer);
    this.pollTimer = null;
    this.pollChain = {};
    // An in-flight refresh of the abandoned record is neither applied nor persisted.
    this.refreshToken = null;
    this.refreshing = false;
  }

  releaseAttempt() {
    this.attempt = null;
    this.attemptPlan = null;
    this.settlement = null;
    this.clearPending = false;
    this.sendLock = false;
    this.pollExpired = false;
    this.resuming = false;
    this.nonceVerified = null;
    this.newerAdopted = false;
    this.unsaved = null;
    this.invalidateReview();
  }

  // -------------------------------------------------------------------------------------------
  // Resume, settlement and clear (read-only)

  /** Loads the authoritative row before any deployment command is admitted. Never sends, deletes or repairs. */
  async loadAttempt() {
    const token = {};
    this.loadToken = token;
    const store = this.store;
    this.initializing = true;
    let loaded;
    try {
      loaded = await store.load();
    } catch (error) {
      if (this.loadToken !== token) return;
      this.initializing = false;
      return this.failStorage(error);
    }
    if (this.loadToken !== token) return;
    this.initializing = false;
    this.snapshot = loaded.snapshot;
    if (loaded.legacyConflict) {
      this.storageError = { code: 'legacy-conflict', message: MESSAGES.legacy };
      this.setFocus('error');
    }
    if (loaded.snapshot.raw === null || this.rootStore.forAddress && !this.storeAddress) return this.emit();
    this.resume(loaded.snapshot.raw, 'reload');
  }

  /** Adopts stored bytes read-only (never rewritten here); invalid bytes are a tampered resume error. */
  resume(text, reason) {
    const valid = validateRecord(text);
    if (!valid) {
      this.resumeError = { code: 'tampered', message: MESSAGES.tampered };
      this.setFocus('error');
      return this.emit();
    }
    const { record, plan } = valid;
    // Observations are re-fetched, never trusted from storage; a stored effective nonce is only a hint.
    record.observed = null;
    if (record.state === 'walletPending') {
      record.state = 'unknown';
      record.reason = reason;
    }
    this.adopt(record, plan);
    this.newerAdopted = false;
    const verify = Boolean(record.hash && record.state !== 'rejected');
    this.resuming = verify;
    this.setFocus('settlement');
    this.emit();
    if (verify) this.refresh({ adopted: reason === 'other-tab' }).then(() => this.startPolling());
  }

  startPolling() {
    if (this.pollTimer !== null) this.clock.clearTimeout(this.pollTimer);
    // A poll callback from an earlier chain that is still awaiting its refresh does not reschedule.
    this.pollChain = {};
    this.polls = 0;
    this.pollStarted = this.clock.now();
    this.pollExpired = false;
    this.schedulePoll();
  }

  schedulePoll() {
    if (!this.attempt || !this.attempt.hash || this.settledForPolling()) return;
    if (this.polls >= MAX_POLLS || this.clock.now() - this.pollStarted >= POLL_WINDOW_MS) {
      this.pollTimer = null;
      this.pollExpired = true;
      return this.emit();
    }
    const chain = this.pollChain;
    this.pollTimer = this.clock.setTimeout(async () => {
      this.pollTimer = null;
      this.polls++;
      await this.refresh({ background: true });
      if (chain === this.pollChain) this.schedulePoll();
    }, POLL_INTERVAL_MS);
  }

  settledForPolling() {
    const s = this.settlement;
    if (!this.attempt) return true;
    if (['success', 'failed'].includes(this.attempt.state)) return Boolean(s && s.state === this.attempt.state);
    return this.attempt.state === 'walletOverride' && s && s.readback !== 'unknown' && s.confirmations >= 2n;
  }

  /**
   * One bounded read-only refresh of the frozen attempt (explicit 状況を更新 or a poll). An unsaved wallet outcome is
   * retried first. The result commits only against the captured snapshot; a conflict adopts the newer row.
   */
  async refresh({ background = false, adopted = false } = {}) {
    if (this.unsaved && !adopted) {
      if (this.refreshing) return;
      const { identity, outcome } = this.unsaved;
      this.refreshing = true;
      if (!background) this.emit();
      await this.reconcileOutcome(identity, outcome, { background });
      this.refreshing = false;
      return this.emit();
    }
    const record = this.attempt;
    if (!record || this.refreshing) return;
    if (!record.hash) return this.readbackOnly(record);
    const captured = this.snapshot;
    const token = {};
    this.refreshToken = token;
    this.refreshing = true;
    if (!background) this.emit();
    const plan = this.attemptPlan;
    const deadline = this.clock.now() + REFRESH_BUDGET_MS;
    let result;
    // Record changes are collected and applied only if this refresh is still current for this record.
    const updates = {};
    try {
      if (record.replacementHash && CANCEL_REASONS.includes(record.reason)) {
        result = await this.recheckCancellation(record, plan, updates);
      } else {
        const target = record.replacementHash || record.hash;
        result = await verifySettlement(this.planRPC(plan), plan, record, target);
        if (target === record.hash && result.observed) updates.nonce = result.observed.nonce;
        if (result.state === 'pending' && result.reason === 'no-transaction') {
          result = await this.checkReplacement(record, plan, result, deadline, updates);
        }
      }
    } catch {
      result = { state: 'unknown', reason: 'rpc', readback: 'unknown', observed: null, paidFee: null, confirmations: 0n };
    }
    if (this.refreshToken !== token) return;
    // A record cleared or replaced meanwhile is neither applied nor written back.
    if (record !== this.attempt || !captured) {
      this.refreshing = false;
      return this.emit();
    }
    const next = { ...record };
    if ('replacementHash' in updates) next.replacementHash = updates.replacementHash;
    if (updates.nonce !== undefined) next.effectiveNonce = hexQuantity(updates.nonce);
    const settlement = this.settle(next, result);
    let outcome;
    try {
      if (adopted) {
        // Conflict revalidation may update presentation, never the retained row. Recheck the captured authority.
        const latest = await this.store.read();
        outcome = { committed: latest.revision === captured.revision && latest.raw === captured.raw, snapshot: latest };
      } else {
        outcome = await this.commit(captured, next);
      }
    } catch (error) {
      outcome = { error };
    }
    if (this.refreshToken !== token) return;
    this.refreshing = false;
    this.resuming = false;
    if (record !== this.attempt) return this.emit();
    if (outcome.error) {
      // Storage failed: the read-only result is shown, the stored row is unchanged, new sends stay blocked.
      this.storageError = { code: 'storage', message: MESSAGES.storage };
    } else if (!outcome.committed) {
      return this.adoptLatest(outcome.snapshot, { candidate: next, revalidate: !adopted });
    } else if (!this.install(next, outcome.snapshot)) {
      return this.emit();
    }
    if (outcome.error) this.attempt = next;
    if (updates.nonce !== undefined) this.nonceVerified = next.effectiveNonce;
    this.settlement = settlement;
    this.emit();
  }

  /**
   * A hashless unknown attempt (reload during approval, timeout, malformed reply): the only safe read is the
   * expected address itself, through the same strict same-block inspection. Presentation only: the record keeps
   * its unknown state and its lock, a deployed readback is not this send's receipt, and an undeployed one is not
   * proof that nothing was sent (the wallet may still hold or broadcast it). No scan, no write, no send.
   */
  async readbackOnly(record) {
    if (record.state !== 'unknown') return;
    const token = {};
    this.refreshToken = token;
    this.refreshing = true;
    this.emit();
    let readback = 'unknown';
    let block = null;
    try {
      const result = await inspect(this.planRPC(this.attemptPlan), this.attemptPlan);
      readback = result.kind === 'deployed' ? 'deployed' : 'not-deployed';
      block = { number: result.block.number.toString(), hash: result.block.hash };
    } catch (error) {
      readback = error instanceof PublicError && error.code === 'keyset' ? 'mismatch' : 'unknown';
    }
    if (this.refreshToken !== token) return;
    this.refreshing = false;
    if (record !== this.attempt) return this.emit();
    this.settlement = { state: 'unknown', reason: record.reason, readback, block, hashless: true, observed: null,
      paidFee: null, confirmations: 0n, receipt: null, replacementHash: null };
    this.emit();
  }

  async recheckCancellation(record, plan, updates) {
    const original = await verifySettlement(this.planRPC(plan), plan, record, record.hash);
    if (original.state === 'pending' && original.reason === 'no-transaction') {
      return verifyCancellation(this.planRPC(plan), plan, record, record.replacementHash, BigInt(record.effectiveNonce));
    }
    if (original.state === 'unknown' && original.reason === 'rpc') return { ...original, reason: 'cancel-unverified' };
    // The original transaction is visible again: the consuming lineage no longer applies.
    updates.replacementHash = null;
    if (original.observed) updates.nonce = original.observed.nonce;
    return original;
  }

  async checkReplacement(record, plan, result, deadline, updates) {
    const verified = this.nonceVerified !== null && this.nonceVerified === record.effectiveNonce;
    // A v2 nonce is only the wallet's lookup hint: without a nonce verified from our own hash there is no
    // consumed check or scan, and the attempt stays unresolved.
    if (record.version === 2 && !verified) return { ...result, state: 'unknown', reason: 'unverified-nonce' };
    // Without a verified effective nonce the requested nonce is only a hint (never cancellation proof).
    const nonce = BigInt(verified ? record.effectiveNonce : record.transaction.nonce);
    let mined;
    try {
      mined = quantity(await this.planRPC(plan)('eth_getTransactionCount', [record.from, 'latest']));
    } catch {
      return { ...result, state: 'unknown', reason: 'rpc' };
    }
    if (mined <= nonce) return result;
    // The nonce is consumed and our hash is gone: bounded scan for the same sender+effective nonce.
    const scan = await scanReplacement(this.planRPC(plan), plan, record, {
      fromBlock: BigInt(record.submission.blockNumber), effectiveNonce: nonce, verified, deadline,
      now: () => this.clock.now(),
    });
    if (scan.kind === 'replacement') {
      updates.replacementHash = scan.hash;
      return verifySettlement(this.planRPC(plan), plan, record, scan.hash);
    }
    if (scan.kind === 'cancelled') {
      // A detected walletOverride stays locked and never becomes failed: no consuming lineage is recorded.
      if (record.state === 'walletOverride') return { ...result, state: 'unknown', reason: 'cancel-unverified' };
      updates.replacementHash = scan.hash;
      return verifyCancellation(this.planRPC(plan), plan, record, scan.hash, nonce);
    }
    return { ...result, state: 'unknown', reason: scan.reason };
  }

  /** Applies a read-only settlement result to `record` (a copy) and returns the settlement to display. */
  settle(record, result) {
    const hadReceipt = Boolean(this.settlement && this.settlement.receipt) || ['success', 'failed'].includes(record.state);
    if (hadReceipt && result.state === 'pending' && !result.receipt) {
      // A receipt seen before is gone: the earlier outcome is revoked by a reorg, not still pending normally.
      result = { ...result, reason: 'reorg' };
    }
    let settlement = { ...result, replacementHash: record.replacementHash };
    if (result.observed) {
      const o = result.observed;
      record.observed = { nonce: hexQuantity(o.nonce), gas: hexQuantity(o.gas), maxFeePerGas: hexQuantity(o.maxFeePerGas),
        maxPriorityFeePerGas: hexQuantity(o.maxPriorityFeePerGas) };
    }
    // A detected wallet override stays locked whatever later readback/receipt shows.
    if (record.state === 'walletOverride' && result.state !== 'walletOverride') {
      return { ...settlement, state: 'walletOverride', readback: result.state === 'success'
        ? 'deployed' : result.readback || 'unknown' };
    }
    record.state = result.state;
    record.reason = result.reason ? String(result.reason).slice(0, 40) : null;
    return settlement;
  }

  /** Read-only reconciliation of a hashless attempt; the hash must match the frozen identity exactly. */
  async enterHash(text) {
    const record = this.attempt;
    const captured = this.snapshot;
    this.manualHashError = null;
    if (!record || record.hash || record.state !== 'unknown' || !captured) return;
    const hash = typeof text === 'string' ? text.trim().toLowerCase() : '';
    if (!HASH.test(hash)) {
      this.manualHashError = MESSAGES.hashFormat;
      return this.emit();
    }
    const result = await verifySettlement(this.planRPC(this.attemptPlan), this.attemptPlan, record, hash);
    // The wallet's own hash may have arrived meanwhile; it wins and the manual entry is dropped.
    if (record !== this.attempt || record.hash || record.state !== 'unknown') return this.emit();
    if (result.state === 'unknown' && result.reason === 'identity') {
      this.manualHashError = MESSAGES.hashMismatch;
      return this.emit();
    }
    // v2 inconsistent or malformed read evidence cannot prove the transaction postdates this send.
    if (['no-transaction', 'rpc', 'evidence', 'receipt'].includes(result.reason)) {
      this.manualHashError = MESSAGES.hashRpc;
      return this.emit();
    }
    // A transaction mined at or before the attempt's submission block predates this send.
    const mined = result.receipt ? result.receipt.blockNumber : result.minedBlock;
    if (mined !== null && mined !== undefined && mined <= BigInt(record.submission.blockNumber)) {
      this.manualHashError = MESSAGES.hashBefore;
      return this.emit();
    }
    const next = { ...record, hash };
    if (result.observed) next.effectiveNonce = hexQuantity(result.observed.nonce);
    const settlement = this.settle(next, result);
    let outcome;
    try {
      outcome = await this.commit(captured, next);
    } catch {
      this.manualHashError = MESSAGES.storage;
      return this.emit();
    }
    if (record !== this.attempt) return this.emit();
    if (!outcome.committed) return this.adoptLatest(outcome.snapshot, { candidate: next });
    if (!this.install(next, outcome.snapshot)) return this.emit();
    if (result.observed) this.nonceVerified = next.effectiveNonce;
    this.settlement = settlement;
    this.setFocus('settlement');
    this.emit();
    this.startPolling();
  }

  clearable() {
    const record = this.attempt;
    if (!record || this.resumeError || this.resuming || this.unsaved || !CLEARABLE.includes(record.state)) return false;
    if (record.state === 'rejected') return true;
    return Boolean(this.settlement && this.settlement.state === record.state
      && !(this.settlement.observed && this.settlement.observed.override));
  }

  requestClear() {
    if (!this.clearable()) return;
    this.clearPending = true;
    this.setFocus('clear-confirm');
    this.emit();
  }

  cancelClear() {
    this.clearPending = false;
    this.setFocus('clear');
    this.emit();
  }

  /**
   * Tombstones only the eligible resolved attempt in the snapshot this page verified, in one conditional
   * transaction, and returns to the public plan for fresh inspection. A newer row is adopted, never removed.
   */
  async confirmClear() {
    if (!this.clearPending || !this.clearable()) return;
    this.clearPending = false;
    const captured = this.snapshot;
    const store = this.store;
    const valid = captured && captured.raw !== null ? validateRecord(captured.raw) : null;
    // Read-only revalidation can resolve a stored pending row. Clear the exact verified snapshot, not its old label.
    if (!valid || identityOf(valid.record) !== identityOf(this.attempt) || overridden(valid.record)) {
      let latest;
      try { latest = await store.read(); } catch (error) {
        if (this.store === store) return this.failStorage(error, 'storage');
        return;
      }
      if (this.store !== store) return;
      return this.adoptLatest(latest);
    }
    let result;
    try {
      result = await store.compareAndSet(captured, null);
    } catch (error) {
      if (this.store === store) return this.failStorage(error, 'storage');
      return;
    }
    if (this.store !== store) return;
    if (!result.committed) return this.adoptLatest(result.snapshot);
    const held = this.unsaved;
    this.snapshot = result.snapshot;
    this.stopTracking();
    this.releaseAttempt();
    this.lateHash = null;
    this.setFocus('plan');
    if (held) {
      // A completed tombstone cannot restore the row, but it must not discard evidence received during the CAS.
      this.clearedIdentity = held.identity;
      this.reloadRequired = true;
      if (held.outcome.kind === 'hash') this.staleHash = held.outcome.hash;
      this.staleNotice = '記録の消去中に新しい取引情報を受け取りました。記録は復元しません。新しい送信はページを再読み込みしてから行ってください。'
        + (this.staleHash ? `\n${this.staleHash}` : '');
    }
    this.emit();
  }
}
