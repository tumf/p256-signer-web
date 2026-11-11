// EntryPoint prefund controller: one typed state over explicit user intents (inspect, inner fee, wallet, send, hash
// lookup, reconcile, new funding). It is a separate authority from the key-change executor: it never asks the iPhone to
// sign, never changes keys and never submits handleOps. Startup, reload and every wallet or storage event are
// read-only. The explicit send button is the only app-side approval: its click arms the current review internally, and
// every awaited pre-send boundary rechecks that armed ticket and the review, authority and wallet generations. A
// strict-durability CAS reservation of a new v2 record precedes the single wallet invocation of exactly
// {from,to,value,data,chainId}; the selected wallet owns gas, fees and nonce. Denial, error, timeout and malformed
// hashes keep the reservation (reconcile-only). Settlement requires the exact saved tuple, coherent actual costs,
// canonical receipt/block identity, two confirmations, the pinned EntryPoint runtime at the receipt block and exactly one
// matching Deposited event (v1 records additionally keep their saved nonce and caps); current readiness is separate.
// Dependencies (rpc, wallet, store, clock, uuid, timers) are injected; none bypasses verification.
import ethers from './vendor/ethers.js';
import { ENTRYPOINT, UINT256_MAX, anchorChain, formatPol, parseAuthority, sameKeys, sha256Hex } from './key-model.js';
import { POLYGON, chainOf, chainText } from './chains.js';
import {
  REQUEST_TIMEOUT_MS, ReadError, block, chainId, fresh, quantity, readContext, receipt as readReceipt,
  transaction as readTransaction,
} from './key-reader.js';
import {
  BOR_LOG_FEE_TRANSFER, ENTRYPOINT_RUNTIME_HASH, PREFUND_GAS, depositCall, fundingPlan, isBorProtocolLog,
  matchingDeposit, serializeFundingAttempt,
} from './prefund-model.js';
import { StorageError, parseFundingAttempt } from './prefund-attempt-store.js';

const U = ethers.utils;
export const WALLET_TIMEOUT_MS = 300_000;
export const RECONCILE_DEADLINE_MS = 60_000;
export const REQUIRED_CONFIRMATIONS = 2n;

/** Exact visible copy per row (design.md visual contract). Status text for progress rows, alert text for errors. */
export const MESSAGES = Object.freeze({
  'PF01-initial': 'Signerの公開データを貼り付けて、チェーン情報を確認してください。',
  'PF02-json': '公開データの形式を確認してください（hybrid-key-authority v1）。',
  'PF02-point': '公開鍵がP-256曲線上の点ではありません。',
  'PF02-id': 'keyIDが公開鍵と一致しません。',
  'PF03-reading': '公開データとチェーン情報を確認中です。',
  'PF03-cancelled-late': '確認を中止しました。遅れて届いた結果は使いません。',
  'PF04-rpc': 'チェーン情報を確認できません。時間をおいて再確認してください。',
  'PF04-mismatch': 'Signerを確認できません。配備・鍵・EntryPoint・チェーンが一致しません。',
  'PF04-ep-runtime': 'EntryPointの実行コードが固定値と一致しません。入金できません。',
  'PF04-stale': 'チェーン情報が古いか時刻が一致しません。再確認してください。',
  'PF05-blank-fee': '鍵操作の手数料上限 maxFeePerGas（Gwei）を入力してください。',
  'PF05-format-fee': 'Gweiは小数9桁までの半角数値で入力してください。',
  'PF05-overflow-fee': '手数料上限が許可された数値範囲を超えています。',
  'PF06-sufficient': '前払い残高は足りています。入金は不要です。鍵変更の画面で再確認してください。',
  'PF07-shortage': '前払い残高が不足しています。入金するウォレットを選んでください。',
  'PF08-no-provider': '利用できるウォレット接続がありません。入金できません。',
  'PF08-missing-project': 'WalletConnect設定未準備のため、利用できるウォレット接続がありません。',
  'PF09-pairing': 'ウォレットで接続を承認してください。',
  'PF09-cancelled': 'ウォレット接続を中止しました。もう一度接続できます。',
  'PF09-rejected': 'ウォレットで接続が拒否されました。',
  'PF10-wrong-chain': '入金用ウォレットをPolygonに切り替えてください。',
  'PF10-switch-rejected': '自動切替できません。ウォレット側でPolygonを選択してください。',
  'PF11-balance-short': 'ウォレット残高が入金額に足りません。',
  'PF12-ready': '入金内容を確認し、表示した入金を1回だけ送信してください。',
  'PF13-reading': '送信前にチェーン情報を再確認しています。',
  'PF13-nonce-wait': '送信前の参照情報を確認しています。',
  'PF13-cas-wait': '送信記録を保存しています。',
  'PF13-fee-changed': '入力が変わったため送信を中止しました。ウォレットは呼び出していません。',
  'PF13-wallet-lost': 'ウォレットが変わったため送信を中止しました。ウォレットは呼び出していません。',
  'PF14-reserved': '送信記録を保存しました。ウォレットの状態を確認しています。',
  'PF14-wallet-wait': '送信記録を保存しました。ウォレットの応答を待っています。再送しません。',
  'PF15-rejected': 'ウォレットで拒否されたか、結果が不明です。再送せず、取引ハッシュで確認してください。',
  'PF15-error': '送信結果は不明です。再送せず、取引ハッシュで確認してください。',
  'PF15-timeout': 'ウォレットの応答がありません。再送せず、取引ハッシュで確認してください。',
  'PF15-malformed-hash': 'ウォレットの応答が不正です。再送せず、取引ハッシュで確認してください。',
  'PF15-late-hash': '元の送信の取引ハッシュを受け取りました。結果を確認してください。',
  'PF16-hash-no-receipt': '取引の確定待ちです。入金はまだ確認していません。',
  'PF16-one-confirmation': '1 / 2 承認。まだ入金成功とは判定していません。',
  'PF17-outer-failed': '取引は失敗しました。入金はされていません。',
  'PF18-foreign-tuple': '保存した送信内容と取引が一致しません。結果を採用しません。',
  'PF18-foreign-log': '入金イベント以外の記録が含まれています。結果を採用しません。',
  'PF18-absent-event': '取引は成功しましたが、入金イベントを確認できません。',
  'PF18-duplicate-event': '入金イベントが重複しています。結果を採用しません。',
  'PF18-wrong-cost': '取引と受領記録の費用情報が一致しません。結果を採用しません。',
  'PF18-runtime': 'EntryPointの実行コードを確認できません。結果を採用しません。',
  'PF18-reorg': 'ブロックの変更を検出しました。結果は未確定です。',
  'PF18-nonce': 'ウォレットのnonceが保存した値と一致しません。結果を採用しません。',
  'PF19-success-ready': '入金取引を検証しました。現在の前払い残高は足りています。鍵変更の画面で再確認してください。',
  'PF20-consumed': '入金取引を検証しました。現在の鍵変更に必要な残高は再確認してください。',
  'PF20-read-failed': '入金取引を検証しました。現在の鍵変更に必要な残高は再確認してください。',
  'PF20-authority-changed': '入金取引を検証しました。現在の鍵変更に必要な残高は再確認してください。',
  'PF21-unavailable': '送信記録を安全に保存できません。送信できません。',
  'PF21-blocked': '別の画面が送信記録を使用中です。送信できません。',
  'PF21-corrupt': '保存済み送信記録が不正です。上書きせず停止しました。',
  'PF21-conflict': '別の画面が送信記録を更新しました。再送せず確認してください。',
  'PF22-reserved': '送信記録を復元しました。送信権限は復元せず、結果確認だけを行います。',
  'PF22-hashKnown': '送信記録を復元しました。送信権限は復元せず、結果確認だけを行います。',
  'PF22-terminal': '送信記録を復元しました。チェーンで再確認するまで結果は確定しません。',
  'PF23-new-attempt': '新しい入金を始めます。公開データからもう一度確認してください。',
});
/** Base wording kept only while a historical v1 record governs the page (its saved caps were user-approved). */
export const LEGACY_MESSAGES = Object.freeze({
  'PF17-outer-failed': '取引は失敗しました。入金はされていません。ガス代は発生しています。',
  'PF18-wrong-cost': '取引の費用が承認した上限と一致しません。結果を採用しません。',
});
export const CURRENT_TEXT = Object.freeze({
  consumed: '現在のデポジットは必要額より少なくなっています（後の操作で消費された可能性があります）。',
  'read-failed': '現在のSigner情報を読み取れませんでした。',
  'authority-changed': '現在のSignerの鍵・権限が変わっています。',
});
const ALERT_FAMILIES = new Set(['PF02', 'PF04', 'PF05', 'PF08', 'PF09', 'PF10', 'PF11', 'PF13', 'PF15', 'PF17',
  'PF18', 'PF21']);
const ALERT_EXCEPTIONS = new Set(['PF09-pairing', 'PF13-reading', 'PF13-nonce-wait', 'PF13-cas-wait']);
export const BUSY_ROWS = new Set(['PF03-reading', 'PF13-reading', 'PF13-nonce-wait', 'PF13-cas-wait', 'PF14-reserved',
  'PF14-wallet-wait']);
const TERMINAL_STATUSES = new Set(['succeeded', 'outerFailed']);
const VERIFIED_VIEWS = new Set(['PF17-outer-failed', 'PF19-success-ready', 'PF20-consumed', 'PF20-read-failed',
  'PF20-authority-changed']);

export const isError = (row) => ALERT_FAMILIES.has(row.slice(0, 4)) && !ALERT_EXCEPTIONS.has(row);
const lower = (address) => (typeof address === 'string' ? address.toLowerCase() : null);
const hexQ = (n) => '0x' + n.toString(16);
const HASH = /^0x[0-9a-fA-F]{64}$/;

class Stale extends Error {}
class Changed extends Error {}

/** unavailable | malformed | mismatch | stale | input | ep-runtime. */
export class FundingReadError extends ReadError {}

async function bounded(rpc, method, params) {
  let timer;
  try {
    return await Promise.race([rpc(method, params), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new ReadError('unavailable')), REQUEST_TIMEOUT_MS);
    })]);
  } catch (error) {
    throw error instanceof ReadError ? error : new ReadError('unavailable');
  } finally { clearTimeout(timer); }
}

/** keccak256 of the pinned EntryPoint code at one exact block. */
export async function entryPointCodeHash(rpc, number) {
  const code = await bounded(rpc, 'eth_getCode', [ENTRYPOINT, hexQ(number)]);
  if (typeof code !== 'string' || !/^0x([0-9a-f]{2}){0,24576}$/.test(code)) throw new ReadError('malformed');
  return U.keccak256(code);
}

/**
 * One fresh coherent funding inspection: the full readContext (deployed Signer, implementation, owner, EntryPoint
 * pointer, complete key set with the authorizer's membership, nonce, deposit and optional wallet balance at B), then
 * the pinned EntryPoint runtime hash at the same B, then a canonical B hash/timestamp, chain and freshness recheck
 * after that awaited read (readContext alone does not read EntryPoint code).
 */
export async function readFunding(rpc, { authority, executor = null, now }) {
  // The authority's one closed chain: the context, the EntryPoint identity and the closing check name it only.
  const chain = anchorChain(authority);
  const context = await readContext(rpc, { signer: authority.signerAddress, authorizer: authority, executor, now, chain });
  const b = context.block;
  if (await entryPointCodeHash(rpc, b.number) !== ENTRYPOINT_RUNTIME_HASH) throw new FundingReadError('ep-runtime');
  const again = await block(rpc, b.number);
  if (again.hash !== b.hash || again.timestamp !== b.timestamp) throw new ReadError('mismatch');
  if (await chainId(rpc) !== BigInt(chain.id)) throw new ReadError('mismatch');
  fresh(b, now());
  return Object.freeze({ ...context, entryPointCodeHash: ENTRYPOINT_RUNTIME_HASH });
}

const readReason = (error) => (error instanceof ReadError
  ? { 'ep-runtime': 'ep-runtime', stale: 'stale', mismatch: 'mismatch' }[error.code] || 'rpc' : 'rpc');
const authorityReason = (code) => (code === 'point' ? 'point' : code === 'keyId' ? 'id' : 'json');
const feeProblem = (code) => ({ blank: 'PF05-blank-fee', format: 'PF05-format-fee' }[code] || 'PF05-overflow-fee');

export class PrefundController {
  constructor({ rpc, rpcFor, wallet, store, clock, uuid, onState = () => {}, setTimer = (fn, ms) => setTimeout(fn, ms),
    clearTimer = (id) => clearTimeout(id) }) {
    Object.assign(this, { rpc, wallet, store, clock, uuid, onState, setTimer, clearTimer });
    // The read-only relay of one closed chain; without a per-chain factory only Polygon (`rpc`) is readable.
    this.rpcFor = rpcFor || ((chain) => {
      if (chain !== POLYGON) throw new ReadError('input');
      return (method, params) => this.rpc(method, params);
    });
    this.opGen = 0;
    this.reviewGen = 0;
    this.destroyed = false;
    this.s = {
      authorityText: '', authority: null, authorityError: null,
      inspection: { phase: 'idle', context: null, reason: null },
      fee: '', armed: null, reviewShell: null, balanceShort: false, walletFailure: null, cancelled: null,
      lastInvalidation: null, lookupText: '',
      attempt: { loaded: false, snapshot: null, record: null, storageError: null, restored: false, outcome: null,
        submission: null, sending: false, sendPhase: null, reconciling: false },
      rollover: null,
    };
  }

  emit() {
    if (this.destroyed) return;
    // The inspected review shell survives a later wallet disconnect (send disabled) until the review itself changes.
    if (this.reviewReady()) this.s.reviewShell = { account: lower(this.wallet.account) };
    this.onState(this.view());
  }

  now() { return this.clock(); }

  /** Startup: read the durable attempt only. Never connects, signs, sends or reconciles by itself. */
  async start() { await this.loadAttempt(); }

  /** Leaving the page drops memory authority (review, armed send, inspection); the durable attempt stays. */
  destroy() {
    this.invalidateAuthority();
    this.destroyed = true;
    try { this.store.close?.(); } catch { /* already closed */ }
  }

  // ---------------------------------------------------------------------------------------------------------------
  // 01 SIGNER

  setAuthorityText(text) {
    if (text === this.s.authorityText) return;
    this.s.authorityText = text;
    this.invalidateAuthority();
    this.emit();
  }

  invalidateAuthority() {
    ++this.opGen;
    ++this.reviewGen;
    this.s.authority = null;
    this.s.authorityError = null;
    this.s.inspection = { phase: 'idle', context: null, reason: null };
    this.s.armed = null;
    this.s.reviewShell = null;
    this.s.balanceShort = false;
    this.s.cancelled = null;
    this.s.lastInvalidation = 'fee-changed';
  }

  async inspect() {
    if (this.s.inspection.phase === 'reading' || this.s.attempt.sending) return;
    let authority;
    try {
      authority = parseAuthority(this.s.authorityText);
    } catch (error) {
      this.invalidateAuthority();
      this.s.authorityError = authorityReason(error.code);
      return this.emit();
    }
    const ticket = ++this.opGen;
    ++this.reviewGen;
    Object.assign(this.s, { authority, authorityError: null, armed: null, reviewShell: null, balanceShort: false,
      cancelled: null });
    if (typeof this.wallet.setTarget === 'function') this.wallet.setTarget(anchorChain(authority));
    this.s.inspection = { phase: 'reading', context: null, reason: null };
    this.emit();
    const executor = this.wallet.status === 'connected' ? lower(this.wallet.account) : null;
    try {
      const context = await readFunding(this.rpcFor(anchorChain(authority)), { authority, executor,
        now: () => this.now() });
      if (ticket !== this.opGen) return;
      this.s.inspection = { phase: 'ready', context, reason: null };
    } catch (error) {
      if (ticket !== this.opGen) return;
      this.s.inspection = { phase: 'unavailable', context: null, reason: readReason(error) };
    }
    this.emit();
  }

  /** Cancel of a pending read: the late completion sees a newer generation and is ignored. */
  cancelInspect() {
    if (this.s.inspection.phase !== 'reading') return;
    ++this.opGen;
    ++this.reviewGen;
    this.s.inspection = { phase: 'cancelled', context: null, reason: null };
    this.emit();
  }

  // ---------------------------------------------------------------------------------------------------------------
  // 02 DEPOSIT

  setFee(text) {
    if (text === this.s.fee) return;
    this.s.fee = text;
    this.s.reviewShell = null;
    // A new inner fee edit after an aborted send is the fresh review the PF13 recovery asks for.
    if (!this.s.attempt.sending) this.s.cancelled = null;
    this.invalidateReview('fee-changed');
    this.emit();
  }

  /** Clears the armed send and advances the review generation; an in-flight pre-send boundary then aborts. */
  invalidateReview(reason) {
    ++this.reviewGen;
    this.s.armed = null;
    this.s.balanceShort = false;
    this.s.lastInvalidation = reason;
  }

  /** P/D/Q from the independent inspection, or a typed problem. Never throws. */
  plan() {
    const context = this.s.inspection.context;
    if (this.s.inspection.phase !== 'ready' || !context) return { problem: null };
    let plan;
    try { plan = fundingPlan(this.s.fee, context.deposit); } catch (error) { return { problem: feeProblem(error.code) }; }
    return { problem: plan.amount === 0n ? 'PF06-sufficient' : null, plan };
  }

  // ---------------------------------------------------------------------------------------------------------------
  // 03 WALLET

  walletChanged() {
    // Any wallet event or generation change disarms the send and invalidates the review; it never connects or sends.
    this.invalidateReview('wallet-lost');
    if (this.wallet.status === 'connected' || this.wallet.status === 'connecting') this.s.walletFailure = null;
    // A newly connected wallet after an aborted send is a fresh wallet review (never an automatic send).
    if (this.wallet.status === 'connected' && !this.s.attempt.sending) this.s.cancelled = null;
    this.emit();
  }

  /** The explicit switch to the authority's chain (legacy name kept for the page binding). */
  async switchPolygon() {
    await (this.wallet.switchChain ? this.wallet.switchChain() : this.wallet.switchPolygon());
    this.s.walletFailure = this.wallet.status === 'wrongChain' && this.wallet.error ? 'refused' : null;
    this.emit();
  }

  blocked() {
    const a = this.s.attempt;
    return !a.loaded || a.storageError !== null || a.sending || (a.record !== null && this.s.rollover === null);
  }

  /**
   * Exact positive plan from a fresh inspection, a wallet on the authority's chain, available unlocked storage, no W<Q
   * refusal and no aborted send awaiting a fresh review (inner fee edit, refresh or wallet choice). Never depends on an outer fee: the wallet estimates and confirms execution fees.
   */
  reviewReady() {
    const planned = this.plan();
    return Boolean(planned.plan) && planned.problem === null && this.wallet.status === 'connected'
      && this.wallet.chainId === (this.s.authority ? anchorChain(this.s.authority) : POLYGON).hex
      && !this.s.balanceShort && !this.s.cancelled && !this.blocked();
  }

  setLookupHash(text) {
    this.s.lookupText = typeof text === 'string' ? text : '';
    this.emit();
  }

  lookupHash() {
    const text = this.s.lookupText.trim();
    return HASH.test(text) ? text.toLowerCase() : null;
  }

  // ---------------------------------------------------------------------------------------------------------------
  // 04 RESULT: explicit send, one reservation, one wallet invocation

  /** The explicit send click: the only app-side approval. It arms this review once; it is never persisted. */
  async send() {
    if (!this.reviewReady() || this.s.attempt.sending) return;
    const ticket = this.opGen, reviewGen = this.reviewGen, walletGen = this.wallet.generation;
    const armed = Object.freeze({ ticket, reviewGen, walletGen });
    this.s.armed = armed;
    const account = lower(this.wallet.account), authority = this.s.authority, inspected = this.s.inspection.context;
    const chain = anchorChain(authority), rpc = this.rpcFor(chain);
    const planned = this.plan().plan;
    const expected = this.s.rollover ? this.s.rollover.prior : this.s.attempt.snapshot;
    const a = this.s.attempt;
    a.sending = true;
    a.sendPhase = 'reading';
    this.s.cancelled = null;
    this.emit();
    const live = () => ticket === this.opGen && reviewGen === this.reviewGen && this.s.armed === armed
      && walletGen === this.wallet.generation && this.wallet.status === 'connected'
      && this.wallet.chainId === chain.hex && lower(this.wallet.account) === account;
    let reserved = null;
    try {
      // Fresh coherent context + EntryPoint identity + wallet balance at a fresh B.
      const current = await readFunding(rpc, { authority, executor: account, now: () => this.now() });
      if (!live()) throw new Stale();
      const again = fundingPlan(this.s.fee, current.deposit);
      if (current.signer !== inspected.signer || !sameKeys(current.keys, inspected.keys)
          || current.nonce !== inspected.nonce || again.required !== planned.required
          || current.deposit !== inspected.deposit || again.amount !== planned.amount) {
        // Never silently shrink or expand Q: redraw from the fresh read and require a new explicit send.
        this.s.inspection = { phase: 'ready', context: current, reason: null };
        throw new Changed();
      }
      // Amount-only affordability: W < Q refuses; W = Q is the wallet's decision (it owns value-plus-fee coverage).
      if (current.executorBalance === null || current.executorBalance < planned.amount) {
        this.s.balanceShort = true;
        throw new Changed();
      }
      a.sendPhase = 'nonce-wait';
      this.emit();
      // Lookup hint only: never sent to the wallet and never a v2 settlement equality predicate.
      const pending = quantity(await bounded(rpc, 'eth_getTransactionCount', [account, 'pending']));
      if (!live()) throw new Stale();
      fresh(current.block, this.now());
      const data = depositCall(current.signer);
      const record = {
        version: 2, attemptId: this.uuid(), status: 'reserved', chainId: chain.decimal, entryPoint: ENTRYPOINT,
        signer: current.signer, authorizerKeyId: authority.keyId, authorizerPublicKey: authority.publicKey,
        inspectionBlockNumber: current.block.number.toString(), inspectionBlockHash: current.block.hash,
        requiredDeposit: planned.required.toString(), observedDeposit: current.deposit.toString(),
        amount: planned.amount.toString(), walletAccount: account, walletPendingNonce: pending.toString(),
        calldataSHA256: sha256Hex(data),
        sendStartedAt: String(this.now()),
      };
      const raw = serializeFundingAttempt(record);
      a.sendPhase = 'cas-wait';
      this.emit();
      if (!live()) throw new Stale();
      const result = await this.store.compareAndSet(expected, raw);
      if (!result.committed) {
        this.adoptSnapshot(result.snapshot, 'conflict');
        throw new Stale();
      }
      reserved = result.snapshot;
      this.adoptSnapshot(reserved, null);
      this.s.rollover = null;
      a.sendPhase = 'reserved';
      this.emit();
      // Durable reservation exists: any authority loss now leaves it reconcile-only and invokes no wallet.
      if (!live()) return await this.recordSubmission(record.attemptId, null, 'error');
      let walletChain, chainTimer;
      try {
        fresh(current.block, this.now());
        walletChain = await Promise.race([this.wallet.request('eth_chainId', []), new Promise((_, reject) => {
          chainTimer = this.setTimer(() => reject(new Error('timeout')), REQUEST_TIMEOUT_MS);
        })]);
        fresh(current.block, this.now());
      } catch { return await this.recordSubmission(record.attemptId, null, 'error'); }
      finally { this.clearTimer(chainTimer); }
      if (!live() || walletChain !== chain.hex) return await this.recordSubmission(record.attemptId, null, 'error');
      a.sendPhase = 'wallet-wait';
      // Exactly five keys: no gas, gasPrice, fee, nonce or type instruction; the wallet estimates and confirms them.
      const tx = { from: this.wallet.account, to: ENTRYPOINT, value: hexQ(planned.amount), data, chainId: chain.hex };
      // Exactly one invocation for this reservation; synchronous throws still settle as unknown. It consumes the armed
      // review; a later send needs a newly valid review and another explicit click.
      const sending = (async () => this.wallet.request('eth_sendTransaction', [tx]))();
      this.s.armed = null;
      ++this.reviewGen;
      this.emit();
      let hash = null, reason = null, timedOut = false, timer;
      try {
        hash = await Promise.race([sending, new Promise((_, reject) => {
          timer = this.setTimer(() => { timedOut = true; reject(new Error('timeout')); }, WALLET_TIMEOUT_MS);
        })]);
        if (typeof hash !== 'string' || !HASH.test(hash)) { hash = null; reason = 'malformed-hash'; }
      } catch (error) {
        hash = null;
        reason = timedOut ? 'timeout' : error && error.code === 4001 ? 'rejected' : 'error';
      } finally { this.clearTimer(timer); }
      await this.recordSubmission(record.attemptId, hash, reason);
      // Serialize the timeout write before attaching even an already-resolved late hash.
      if (timedOut) sending.then((late) => this.lateHash(record.attemptId, late), () => {});
    } catch (error) {
      if (error instanceof StorageError) this.s.attempt.storageError = storageCode(error);
      else if (error instanceof Changed) this.s.armed = null;
      else if (error instanceof Stale) {
        if (!reserved && !a.storageError) this.s.cancelled = this.s.lastInvalidation || 'fee-changed';
      } else if (!reserved) {
        this.s.inspection = { phase: 'unavailable', context: null, reason: readReason(error) };
      }
      if (!reserved) { ++this.reviewGen; this.s.armed = null; }
    } finally {
      a.sending = false;
      a.sendPhase = null;
      this.emit();
    }
  }

  /** hashKnown with a canonical hash, otherwise unknown; neither ever re-enables a send. */
  async recordSubmission(attemptId, hash, reason) {
    const record = this.s.attempt.record;
    if (!record || record.attemptId !== attemptId) return;
    this.s.attempt.submission = hash ? null : reason || 'error';
    if (hash) await this.update((r) => ({ ...r, status: 'hashKnown', transactionHash: hash.toLowerCase() }));
    else await this.update((r) => ({ ...r, status: 'unknown' }));
  }

  /** A hash arriving after the bounded wait is attached to the ORIGINAL reservation only. */
  async lateHash(attemptId, hash) {
    const record = this.s.attempt.record;
    if (!record || record.attemptId !== attemptId || record.transactionHash || typeof hash !== 'string'
        || !HASH.test(hash)) return;
    if (await this.update((r) => ({ ...r, status: 'hashKnown', transactionHash: hash.toLowerCase() }))) {
      this.s.attempt.submission = 'late-hash';
    }
    this.emit();
  }

  adoptSnapshot(snapshot, storageError) {
    const a = this.s.attempt;
    a.snapshot = snapshot;
    try {
      const record = parseFundingAttempt(snapshot.raw);
      if (storageError || record?.attemptId !== a.record?.attemptId) {
        a.outcome = null; a.restored = false; a.submission = null;
      }
      a.record = record;
      a.storageError = storageError;
    } catch {
      a.record = null;
      a.storageError = 'corrupt';
    }
  }

  /** CAS from the exact current snapshot. A conflict or failure keeps the old bytes and reports it. */
  async update(change, expected = this.s.attempt.snapshot) {
    const a = this.s.attempt;
    if (!a.record || !expected || a.snapshot !== expected) return false;
    try {
      const raw = serializeFundingAttempt(change(a.record));
      if (raw === expected.raw) {
        const current = await this.store.read();
        if (a.snapshot !== expected) return false;
        if (current.revision === expected.revision && current.raw === expected.raw) return true;
        this.adoptSnapshot(current, 'conflict');
        return false;
      }
      const result = await this.store.compareAndSet(expected, raw);
      if (a.snapshot !== expected) return false;
      this.adoptSnapshot(result.snapshot, result.committed ? null : 'conflict');
      return result.committed;
    } catch (error) {
      a.storageError = error instanceof StorageError ? storageCode(error) : 'unavailable';
      return false;
    }
  }

  async loadAttempt() {
    try {
      const snapshot = await this.store.read();
      this.adoptSnapshot(snapshot, null);
      this.s.attempt.restored = this.s.attempt.record !== null;
    } catch (error) {
      this.s.attempt.storageError = error instanceof StorageError ? storageCode(error) : 'unavailable';
    }
    this.s.attempt.loaded = true;
    this.emit();
  }

  /** Explicit re-read of storage after a conflict/unavailable report; never clears or overwrites. */
  async reloadAttempt() {
    if (this.s.attempt.sending || this.s.attempt.storageError === 'corrupt') return;
    this.s.attempt.storageError = null;
    await this.loadAttempt();
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Reconciliation (explicit, bounded, read-only)

  async reconcile() {
    const a = this.s.attempt;
    if (!a.record || a.reconciling || a.sending || a.storageError) return;
    const supplied = a.record.transactionHash ? null : this.lookupHash();
    if (!a.record.transactionHash && !supplied) return;
    a.reconciling = true;
    this.emit();
    try {
      const outcome = await this.boundedSettle(a.record, supplied);
      if (outcome) { a.outcome = outcome; a.restored = false; a.submission = null; }
    } finally {
      a.reconciling = false;
      this.emit();
    }
  }

  /** settle() under the reconciliation deadline; writes are pinned to this pass's exact snapshot. */
  async boundedSettle(record, supplied) {
    let timer, active = true, snapshot = this.s.attempt.snapshot, proved = null;
    const write = async (change) => {
      if (!active || this.s.attempt.snapshot !== snapshot) throw new Stale();
      if (!await this.update(change, snapshot)) throw new Stale();
      snapshot = this.s.attempt.snapshot;
    };
    try {
      // Only this pass can establish proof; a persisted terminal hint is never a timeout fallback.
      const verified = (costs) => {
        if (!active || this.s.attempt.snapshot !== snapshot) throw new Stale();
        proved = { view: 'PF20-read-failed', costs, current: { reason: 'read-failed' } };
      };
      const result = await Promise.race([this.settle(record, supplied, write, verified),
        new Promise((resolve) => { timer = this.setTimer(() => { active = false;
          resolve(proved || { view: 'PF16-hash-no-receipt', unavailable: true }); }, RECONCILE_DEADLINE_MS); })]);
      // Current readiness may wait while another tab replaces the row. Validate before publishing any result.
      if (this.s.attempt.snapshot !== snapshot || !await this.update((r) => r, snapshot)) return null;
      return result;
    } catch (error) {
      if (error instanceof Stale) return null;
      return { view: 'PF16-hash-no-receipt', unavailable: true };
    } finally {
      active = false;
      this.clearTimer(timer);
    }
  }

  /**
   * One read-only settlement pass returning `{view, costs?, current?}` after persisting any verified change. A
   * supplied lookup hash is only attached to the reservation after the exact tuple (and, for v1, its saved nonce and
   * caps) match. v2 accepts the wallet's actual nonce and coherent fees; actual costs must be internally consistent for
   * both versions. Unverified, foreign and reorganized observations never unlock a new funding attempt.
   */
  async settle(record, supplied, write, verified) {
    const hash = record.transactionHash || supplied;
    // Every settlement read uses the record's own closed chain only.
    const chain = chainOf(record.chainId);
    if (!chain) return { view: 'PF16-hash-no-receipt', unavailable: true };
    const rpc = this.rpcFor(chain);
    const own = Boolean(record.transactionHash);
    const uncertain = async (view) => {
      if (own) await write((r) => ({ ...withoutOutcome(r), status: 'uncertain' }));
      return { view };
    };
    let tx;
    try { tx = await readTransaction(rpc, hash); } catch { return { view: 'PF16-hash-no-receipt', unavailable: true }; }
    if (tx === null) return { view: 'PF16-hash-no-receipt' };
    const amount = BigInt(record.amount);
    if (tx.from !== record.walletAccount || tx.to !== ENTRYPOINT || tx.value !== amount || tx.chainId !== BigInt(chain.id)
        || U.sha256(tx.input) !== record.calldataSHA256) return uncertain('PF18-foreign-tuple');
    // v1 alone saved approved bounds; a v2 pending nonce is only the lookup hint and v2 has no fee ceiling.
    const legacy = record.version === 1;
    if (legacy && tx.nonce !== BigInt(record.walletPendingNonce)) return uncertain('PF18-nonce');
    if (tx.maxPriorityFeePerGas > tx.maxFeePerGas) return uncertain('PF18-wrong-cost');
    if (legacy && (tx.gas > BigInt(record.outerGasLimit) || tx.maxFeePerGas > BigInt(record.outerMaxFeePerGas)
        || tx.maxPriorityFeePerGas > BigInt(record.outerMaxPriorityFeePerGas))) return uncertain('PF18-wrong-cost');
    if (!own) await write((r) => ({ ...r, status: 'hashKnown', transactionHash: hash }));
    let rc;
    try { rc = await readReceipt(rpc, hash); } catch { return { view: 'PF16-hash-no-receipt', unavailable: true }; }
    if (rc === null || tx.blockNumber === null) {
      await write((r) => ({ ...withoutOutcome(r), status: 'hashKnown' }));
      return { view: 'PF16-hash-no-receipt' };
    }
    if (rc.blockNumber !== tx.blockNumber || rc.blockHash !== tx.blockHash || rc.from !== record.walletAccount
        || rc.to !== ENTRYPOINT) return uncertain('PF18-reorg');
    // Actual receipt costs must fit the actual transaction (legacy gasPrice is normalized by the shared reader).
    if (rc.gasUsed > tx.gas || rc.effectiveGasPrice > tx.maxFeePerGas) return uncertain('PF18-wrong-cost');
    if (legacy && (rc.gasUsed > BigInt(record.outerGasLimit)
        || rc.effectiveGasPrice > BigInt(record.outerMaxFeePerGas))) return uncertain('PF18-wrong-cost');
    const gasCost = rc.gasUsed * rc.effectiveGasPrice;
    if (gasCost > UINT256_MAX) return uncertain('PF18-wrong-cost');
    let canonical, head;
    try {
      canonical = await block(rpc, rc.blockNumber);
      head = await block(rpc, null);
    } catch { return { view: 'PF16-hash-no-receipt', unavailable: true }; }
    if (canonical.hash !== rc.blockHash) return uncertain('PF18-reorg');
    if (head.number < rc.blockNumber + REQUIRED_CONFIRMATIONS - 1n) {
      await write((r) => ({ ...withoutOutcome(r), status: 'confirming' }));
      return { view: 'PF16-one-confirmation', costs: { gasCost } };
    }
    let runtime;
    try {
      if (await chainId(rpc) !== BigInt(chain.id)) return uncertain('PF18-reorg');
      runtime = await entryPointCodeHash(rpc, rc.blockNumber);
    } catch { return { view: 'PF16-hash-no-receipt', unavailable: true }; }
    if (runtime !== ENTRYPOINT_RUNTIME_HASH) return uncertain('PF18-runtime');
    let event = null;
    if (rc.status === '0x1') {
      event = matchingDeposit(rc, record);
      if (!event.ok) return uncertain({ absent: 'PF18-absent-event', duplicate: 'PF18-duplicate-event' }[event.reason]
        || 'PF18-foreign-log');
    } else if (!rc.logs.every((log) => isBorProtocolLog(log, rc, [BOR_LOG_FEE_TRANSFER]))) {
      // A status0 receipt may carry only Bor's LogFeeTransfer; any EntryPoint or other log stays uncertain.
      return uncertain('PF18-foreign-log');
    }
    // Bracket the canonical receipt read with one stable head; height alone misses a same-height reorg.
    let still, before;
    try {
      if (await chainId(rpc) !== BigInt(chain.id)) return uncertain('PF18-reorg');
      before = await block(rpc, null);
      still = await block(rpc, rc.blockNumber);
      head = await block(rpc, null);
    } catch { return { view: 'PF16-hash-no-receipt', unavailable: true }; }
    if (still.hash !== rc.blockHash || still.timestamp !== canonical.timestamp) return uncertain('PF18-reorg');
    if (head.number < rc.blockNumber + REQUIRED_CONFIRMATIONS - 1n) {
      await write((r) => ({ ...withoutOutcome(r), status: 'confirming' }));
      return { view: 'PF16-one-confirmation', costs: { gasCost } };
    }
    if (before.number !== head.number || before.hash !== head.hash) return uncertain('PF18-reorg');
    const outcome = { kind: rc.status === '0x1' ? 'succeeded' : 'outerFailed', transactionHash: hash,
      blockNumber: rc.blockNumber.toString(), blockHash: rc.blockHash, walletNonce: tx.nonce.toString(),
      gasUsed: rc.gasUsed.toString(), effectiveGasPrice: rc.effectiveGasPrice.toString(),
      actualGasCost: gasCost.toString() };
    if (rc.status === '0x0') {
      await write((r) => ({ ...r, status: 'outerFailed', outcome }));
      return { view: 'PF17-outer-failed', costs: { gasCost } };
    }
    await write((r) => ({ ...r, status: 'succeeded', outcome: { ...outcome, totalDeposit: event.totalDeposit.toString() } }));
    const costs = { gasCost, amount, totalDeposit: event.totalDeposit };
    verified(costs);
    // Current readiness is separate: a later operation may have consumed the deposit or changed authority.
    let current;
    try {
      current = await readContext(rpc, { signer: record.signer, authorizer: { keyId: record.authorizerKeyId,
        publicKey: record.authorizerPublicKey }, now: () => this.now(), chain });
    } catch (error) {
      const reason = error instanceof ReadError && error.code === 'mismatch' ? 'authority-changed' : 'read-failed';
      return { view: `PF20-${reason}`, costs, current: { reason } };
    }
    const required = BigInt(record.requiredDeposit);
    const shortage = current.deposit >= required ? 0n : required - current.deposit;
    const summary = { deposit: current.deposit, shortage, block: current.block, reason: shortage ? 'consumed' : null };
    return { view: shortage ? 'PF20-consumed' : 'PF19-success-ready', costs, current: summary };
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Explicit new funding after a reverified canonical terminal result

  async newFunding() {
    const a = this.s.attempt;
    if (!a.record || this.s.rollover || a.sending || a.reconciling || a.storageError
        || !TERMINAL_STATUSES.has(a.record.status)) return;
    const record = a.record, snapshot = a.snapshot;
    a.reconciling = true;
    this.emit();
    try {
      // A saved outcome is only a hint: the exact canonical transaction is verified again now.
      const verified = await this.boundedSettle(record, null);
      if (!verified) return;
      a.outcome = verified;
      a.restored = false;
      if (!VERIFIED_VIEWS.has(verified.view) || this.s.attempt.snapshot !== snapshot
          || !TERMINAL_STATUSES.has(this.s.attempt.record?.status)) return;
      this.s.rollover = { prior: this.s.attempt.snapshot };
      a.outcome = null;
      a.submission = null;
      this.s.lookupText = '';
      // The new attempt needs a new independent inspection, inner fee, review and explicit send.
      this.s.authorityText = '';
      this.s.fee = '';
      this.invalidateAuthority();
    } finally {
      a.reconciling = false;
      this.emit();
    }
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Typed view

  attemptRow() {
    const a = this.s.attempt, r = a.record;
    if (a.sending) return a.sendPhase === 'wallet-wait' ? 'PF14-wallet-wait' : 'PF14-reserved';
    if (a.outcome) return a.outcome.view;
    if (a.restored) {
      if (TERMINAL_STATUSES.has(r.status) || r.status === 'uncertain') return 'PF22-terminal';
      return r.transactionHash ? 'PF22-hashKnown' : 'PF22-reserved';
    }
    if (a.submission) return `PF15-${a.submission}`;
    switch (r.status) {
      case 'hashKnown': return 'PF16-hash-no-receipt';
      case 'confirming': return 'PF16-one-confirmation';
      case 'outerFailed': return 'PF17-outer-failed';
      case 'succeeded': case 'uncertain': return 'PF22-terminal';
      default: return 'PF15-error';
    }
  }

  walletRow() {
    const w = this.wallet;
    if (w.status === 'connecting') return w.pairing ? 'PF09-pairing' : 'PF07-shortage';
    if (w.status === 'wrongChain') return this.s.walletFailure === 'refused' ? 'PF10-switch-rejected' : 'PF10-wrong-chain';
    if (w.status !== 'connected') {
      if (!w.choices().some((c) => !c.disabled)) {
        return w.snapshot().walletConnect?.reason === 'missing-id' ? 'PF08-missing-project' : 'PF08-no-provider';
      }
      if (w.error?.code === 'cancelled') return 'PF09-cancelled';
      if (w.error?.code === 'rejected') return 'PF09-rejected';
      // A previously valid review stays shown after a wallet disconnect; live readiness (and send) is false.
      return w.status === 'disconnected' && this.s.reviewShell ? 'PF12-ready' : 'PF07-shortage';
    }
    if (this.s.balanceShort) return 'PF11-balance-short';
    return 'PF12-ready';
  }

  view() {
    const s = this.s, a = s.attempt, planned = this.plan();
    let row;
    if (a.storageError) row = `PF21-${a.storageError}`;
    else if (a.record && !s.rollover) row = this.attemptRow();
    else if (a.sending) row = `PF13-${a.sendPhase === 'reading' ? 'reading' : a.sendPhase}`;
    else if (s.rollover && s.inspection.phase === 'idle' && !s.authorityError) row = 'PF23-new-attempt';
    else if (s.inspection.phase === 'reading') row = 'PF03-reading';
    else if (s.inspection.phase === 'cancelled') row = 'PF03-cancelled-late';
    else if (s.inspection.phase === 'unavailable') row = `PF04-${s.inspection.reason}`;
    else if (s.inspection.phase === 'ready') {
      if (s.cancelled) row = `PF13-${s.cancelled}`;
      else if (planned.problem) row = planned.problem;
      else row = this.walletRow();
    } else row = s.authorityError ? `PF02-${s.authorityError}` : 'PF01-initial';
    if (!MESSAGES[row]) row = 'PF15-error';
    const governing = Boolean(a.record) && !s.rollover;
    const context = s.inspection.context;
    const inspected = s.inspection.phase === 'ready' && Boolean(context);
    const funding = inspected && Boolean(planned.plan) && planned.problem === null && !governing;
    const w = this.wallet;
    const preSend = a.sending && ['reading', 'nonce-wait', 'cas-wait'].includes(a.sendPhase);
    const lookup = this.lookupHash();
    const ready = this.reviewReady();
    const legacy = governing && a.record.version === 1;
    // The one chain this view is about: a governing attempt's own recorded chain (reconciled on that chain only),
    // otherwise the authority's (Polygon without one).
    const viewChain = governing ? chainOf(a.record.chainId) || POLYGON : s.authority ? anchorChain(s.authority) : POLYGON;
    return Object.freeze({
      // The fixed Polygon-worded rows name the view's chain; Polygon keeps the exact frozen message bytes.
      row, family: row.slice(0, 4), error: isError(row), chain: viewChain,
      message: chainText((legacy && LEGACY_MESSAGES[row]) || MESSAGES[row], viewChain),
      busy: BUSY_ROWS.has(row) || a.reconciling,
      authorityText: s.authorityText, authority: s.authority, authorityError: s.authorityError,
      inspection: s.inspection.phase, context, fee: s.fee, plan: planned.plan || null, problem: planned.problem,
      wallet: w.snapshot(), funding, governing, legacy,
      // The deposit review shell: a connected Polygon wallet, or the retained shell of a valid review after disconnect.
      review: funding && (w.status === 'connected' || (row === 'PF12-ready' && Boolean(s.reviewShell)))
        ? { account: lower(w.account) || s.reviewShell.account } : null,
      attempt: { record: a.record, revision: a.snapshot?.revision ?? null, storageError: a.storageError,
        loaded: a.loaded, sending: a.sending, sendPhase: a.sendPhase, reconciling: a.reconciling, outcome: a.outcome,
        restored: a.restored, submission: a.submission },
      rollover: Boolean(s.rollover), lookupText: s.lookupText,
      actions: {
        inspect: s.inspection.phase !== 'reading' && !a.sending && !governing,
        cancelInspect: s.inspection.phase === 'reading',
        editAuthority: s.inspection.phase !== 'reading' && !a.sending && !governing,
        editFee: inspected && !governing && (!a.sending || preSend),
        refresh: inspected && !a.sending && !governing,
        walletChoose: funding && w.status !== 'connecting' && !a.sending,
        walletConnect: funding && Boolean(w.selectedId) && w.status === 'disconnected' && !a.sending,
        walletCancel: w.status === 'connecting',
        walletSwitch: funding && w.status === 'wrongChain' && !a.sending,
        walletDisconnect: (w.status === 'connected' || w.status === 'wrongChain') && !governing,
        send: ready && !a.sending,
        hashInput: governing && !a.record.transactionHash && !a.sending && !a.reconciling,
        reconcile: governing && !a.sending && !a.reconciling && !a.storageError
          && (Boolean(a.record.transactionHash) || lookup !== null),
        newFunding: governing && !a.sending && !a.reconciling && !a.storageError
          && TERMINAL_STATUSES.has(a.record.status),
        reloadStorage: Boolean(a.storageError) && a.storageError !== 'corrupt' && !a.sending,
      },
      pol: formatPol, gasUnits: PREFUND_GAS, entryPoint: ENTRYPOINT,
    });
  }
}

function withoutOutcome(record) {
  const { outcome: _outcome, ...rest } = record;
  return rest;
}

function storageCode(error) {
  return error.code === 'corrupt' ? 'corrupt' : error.code === 'blocked' ? 'blocked' : 'unavailable';
}
