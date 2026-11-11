// Key-change controller: one typed state over explicit user intents (inspect, connect, preview, request, wallet
// connect/switch, send, reconcile, new change). Every asynchronous boundary rechecks the operation, native session
// and wallet generations; nothing signs or sends on startup, events, reconnect or reload. A fresh bounded preflight
// (full Signer state and the pending wallet nonce as a lookup hint) and a strict-durability CAS reservation of the
// exact operation precede the single wallet invocation, whose request carries only from/to/data/value/chainId: the
// standard wallet owns outer gas, fees, nonce and payment approval. Denial, timeout, error and malformed hashes keep
// that reservation. Settlement requires the exact tuple, canonical receipt/block identity, two confirmations, exactly
// one matching UserOperationEvent and the complete expected key map and nonce; legacy v1 records keep their outer
// ceilings, v2 records instead require internally coherent actual fees and an event within the signed inner budget.
// Dependencies (rpc, wallet, store, SignClient, clock, uuid, timers) are injected; none bypasses verification.
import ethers from './vendor/ethers.js';
import {
  anchorChain, ENTRYPOINT, PURPOSE, TOTAL_GAS, UINT256_MAX, USER_OPERATION_EVENT, ZERO_ADDRESS, agree, buildRequest, formatPol,
  handleOpsCall, innerFees, issuedAtFor, parseAuthority, parseBareKey, planChange, prefund, sameKeys, sha256Hex,
  typedDataHash, validateNativeContext, verifyResult,
} from './key-model.js';
import { POLYGON, chainOf, chainText } from './chains.js';
import {
  ACQUISITION_DEADLINE_MS, ReadError, block, coherentFees, pendingNonce, readContext, receipt as readReceipt,
  transaction as readTransaction,
} from './key-reader.js';
import { KeyChangeSession, SessionError, classify, signClientOptions } from './key-session.js';
import { StorageError, parseAttempt, serializeAttempt } from './key-attempt-store.js';
import { SavedResultStore, parseRecord, serializeRecord } from './saved-result-store.js';

const U = ethers.utils;
export const WALLET_TIMEOUT_MS = 300_000;
export const RECONCILE_DEADLINE_MS = 60_000;
export const REQUIRED_CONFIRMATIONS = 2n;

/** Exact visible copy (references/ui-subcases.md). Status for base rows, alert text for subcases. */
export const MESSAGES = Object.freeze({
  KW01: '公開データを読み込んで確認してください。',
  KW02: '公開データの形式・公開鍵・IDを確認してください。',
  KW03: '公開データとチェーン情報を確認中です。',
  KW04: 'チェーン情報を確認できません。時間をおいて再確認してください。',
  KW05: '追加する鍵を確認してください。',
  KW06: '削除する鍵と残る鍵を確認してください。',
  'KW07-duplicate': 'この鍵は登録済みです。',
  'KW07-curve': '公開鍵の形式または曲線上の点が不正です。',
  'KW07-limit': '登録できる鍵は64個までです。',
  'KW07-last': '最後の鍵は削除できません。',
  'KW08-blank': '署名対象の手数料上限と優先料を入力してください。',
  'KW08-format': 'Gweiは小数9桁までの半角数値で入力してください。',
  'KW08-bounds': '署名対象の手数料が許可上限または数値範囲を超えています。',
  KW09: '前払い残高が不足しています。この画面では入金しません。別の入金画面で入金した後、ここで公開データから再確認してください。',
  KW10: 'iPhoneで接続を承認してください。',
  KW11: 'iPhoneに接続しました。要求内容を確認してください。',
  KW12: 'この内容をiPhoneに要求します。',
  KW13: 'この内容をiPhoneに要求します。',
  KW14: 'iPhoneでの承認を待っています。',
  KW15: '署名検証済み・未実行',
  'KW16-rejected': 'iPhoneで承認されませんでした。新しく接続してください。',
  'KW16-lost': '接続または応答を確認できません。署名は採用していません。',
  'KW16-changed': '署名権限が変わりました。公開データから再確認してください。',
  'KW16-invalid': '返された署名を検証できません。送信できません。',
  'KW16-expired': '要求の期限が切れました。新しい接続で要求してください。',
  'KW17-choices': '実行用ウォレットを選択してください。',
  'KW17-pairing': '実行用ウォレットで接続を承認してください。',
  'KW17-unavailable': '利用できるウォレット接続がありません。',
  'KW18-wrong': '実行用ウォレットをPolygonに切り替えてください。',
  'KW18-refused': '自動切替できません。ウォレット側でPolygonを選択してください。',
  KW20: '鍵変更の内容を確認し、ウォレットで送信を承認してください。',
  'KW20-checking': '送信前のチェーン情報とウォレットnonceを確認しています。',
  'KW20-nonce': 'ウォレットのnonceを確認できません。送信していません。再確認してください。',
  KW21: '送信記録を保存しました。ウォレットの応答を待っています。',
  'KW22-no-hash': '送信結果は不明です。再送せず、取引ハッシュで確認してください。',
  'KW22-late-hash': '元の送信の取引ハッシュを受け取りました。結果を確認してください。',
  'KW23-pending': '取引の確定待ちです。鍵変更は未確認です。',
  'KW23-one': '1 / 2 承認。まだ鍵変更成功とは判定していません。',
  KW24: '外側取引は成功しましたが、鍵変更は失敗しました。費用は発生しています。',
  KW25: '外側取引が失敗しました。鍵変更成功ではありません。以前の署名は未失効です。',
  'KW26-reorg': 'ブロックの変更を検出しました。結果は未確定です。',
  'KW26-foreign': '保存した送信内容と取引が一致しません。',
  'KW26-event': '鍵変更の実行イベントを一意に確認できません。',
  'KW26-state': '実行後の全鍵・nonceが予定と一致しません。',
  'KW26-state-advanced': 'この送信の実行は証明できません。現在の鍵は予定と異なります。',
  'KW26-same-block': '対象イベントは成功・状態競合で照合未完了',
  'KW26-rpc': '実行後のチェーン情報を確認できません。',
  'KW26-cap': 'ウォレットが承認済み費用上限を変更しました。結果を自動採用しません。',
  'KW26-fees': '取引と受領情報のガス・手数料が整合しません。結果は未確定です。',
  'KW26-state-resolved': '現在の状態は予定と一致しますが、この送信の実行は証明できません。',
  KW27: '内部鍵の追加を検証しました。',
  KW28: '内部鍵の削除を検証しました。',
  'KW29-unavailable': '送信記録を安全に保存できません。送信できません。',
  'KW29-corrupt': '保存済み送信記録が不正です。上書きせず停止しました。',
  'KW29-conflict': '別の画面が送信記録を更新しました。再送せず確認してください。',
  'KW30-reserved': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  'KW30-hash': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  'KW30-terminal': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  'KW30-v2-reserved': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  'KW30-v2-hash': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  'KW30-v2-terminal': '送信記録を復元しました。署名・接続は復元せず、結果確認だけを行います。',
  selfRemoval: 'このiPhoneの鍵を削除します。以後は残る鍵が必要です。',
  rolloverAck: '以前の署名は未失効です。同じnonceの別要求を作ると、先に採用された要求だけが実行されます。',
});
export const ERROR_ROWS = new Set(['KW02', 'KW04', 'KW07', 'KW08', 'KW09', 'KW16', 'KW17-unavailable', 'KW18',
  'KW20-nonce', 'KW22', 'KW24', 'KW25', 'KW26', 'KW29']);

const EVENT_DONE = new Set(['succeeded', 'innerFailed', 'sameBlockConflict']);
const STALE_OUTER_FAILURE = new Set(['KW23-pending', 'KW26-foreign', 'KW26-reorg']);
const TERMINAL = new Set(['succeeded', 'innerFailed', 'outerFailed', 'stateResolved', 'uncertain']);
const lower = (address) => (typeof address === 'string' ? address.toLowerCase() : null);
const addressTopic = (address) => '0x' + '00'.repeat(12) + address.slice(2);

class Stale extends Error {}
/** The bounded pending wallet-nonce lookup failed, timed out or was malformed: no reservation, no wallet call. */
class NonceUnavailable extends Error {}

export class KeyChangeController {
  constructor({ rpc, rpcFor, wallet, store, savedResultStore = new SavedResultStore(), loadSignClient, loadConfig, clock, uuid, onState = () => {},
    setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = (id) => clearTimeout(id) }) {
    Object.assign(this, { rpc, wallet, store, savedResultStore, loadSignClient, loadConfig, clock, uuid, onState, setTimer, clearTimer });
    // The read-only relay of one closed chain; without a per-chain factory only Polygon (`rpc`) is readable.
    this.rpcFor = rpcFor || ((chain) => {
      if (chain !== POLYGON) throw new ReadError('input');
      return (method, params) => this.rpc(method, params);
    });
    this.opGen = 0;
    this.sendReviewGen = 0;
    this.client = null;
    this.session = null;
    this.expiryTimer = null;
    this.s = {
      anchorText: '', anchor: null, anchorError: false,
      inspection: { phase: 'idle', context: null },
      mode: 'add', bareText: '', removeKeyId: '', feeMax: '', feePriority: '',
      native: { phase: 'idle', uri: null, context: null, failure: null, signed: null },
      walletFailure: null, nonceFailure: false,
      attempt: { loaded: false, snapshot: null, record: null, storageError: null, restored: false, outcome: null,
        lateHash: false, sending: false, reconciling: false, lastHash: null, costs: null },
      rollover: null, rolloverAck: false,
    };
  }

  emit() { this.onState(this.view()); }

  now() { return this.clock(); }

  // ---------------------------------------------------------------------------------------------------------------
  // 01 SIGNER

  setAnchorText(text) {
    if (text === this.s.anchorText) return;
    this.s.anchorText = text;
    this.invalidateAuthority();
    this.emit();
  }

  /** Leaving, editing the anchor or a failed inspection drops memory authority; durable attempts stay. */
  invalidateAuthority() {
    ++this.opGen;
    this.s.anchor = null;
    this.s.anchorError = false;
    this.s.inspection = { phase: 'idle', context: null };
    void this.endNative(null);
  }

  /** The anchor's own closed chain and its read-only relay: every read, request and record of it names that chain. */
  chainOf(anchor = this.s.anchor) { return anchorChain(anchor); }

  rpcOf(chain) { return this.rpcFor(chain); }

  /** A durable record's own closed chain (`chainId`), never the page's current anchor. */
  recordChain(record) {
    const chain = chainOf(record?.chainId);
    if (!chain) throw new ReadError('input');
    return chain;
  }

  async inspect() {
    if (this.s.inspection.phase === 'reading' || this.s.attempt.sending) return;
    let anchor;
    try {
      anchor = parseAuthority(this.s.anchorText);
    } catch {
      this.invalidateAuthority();
      this.s.anchorError = true;
      return this.emit();
    }
    const ticket = ++this.opGen;
    void this.endNative(null);
    this.s.anchor = anchor; this.s.anchorError = false;
    if (typeof this.wallet.setTarget === 'function') this.wallet.setTarget(this.chainOf(anchor));
    this.s.inspection = { phase: 'reading', context: null };
    this.emit();
    try {
      const context = await readContext(this.rpcOf(this.chainOf(anchor)), { signer: anchor.signerAddress,
        authorizer: anchor, now: () => this.now(), chain: this.chainOf(anchor) });
      if (ticket !== this.opGen) return;
      this.s.inspection = { phase: 'ready', context };
      if (!context.keys.some((k) => k.keyId === this.s.removeKeyId)) this.s.removeKeyId = '';
    } catch {
      if (ticket !== this.opGen) return;
      this.s.inspection = { phase: 'unavailable', context: null };
    }
    this.emit();
  }

  /** Cancel of a pending read: the late completion sees a newer generation and is ignored. */
  cancelInspect() {
    if (this.s.inspection.phase !== 'reading') return;
    ++this.opGen;
    this.s.inspection = { phase: 'idle', context: null };
    this.emit();
  }

  // ---------------------------------------------------------------------------------------------------------------
  // 02 CHANGE (pure planning from the independent read; editing invalidates any native preview)

  setChange({ mode, bareText, removeKeyId, feeMax, feePriority }) {
    const before = JSON.stringify([this.s.mode, this.s.bareText, this.s.removeKeyId, this.s.feeMax, this.s.feePriority]);
    if (mode !== undefined) this.s.mode = mode === 'remove' ? 'remove' : 'add';
    if (bareText !== undefined) this.s.bareText = bareText;
    if (removeKeyId !== undefined) this.s.removeKeyId = removeKeyId;
    if (feeMax !== undefined) this.s.feeMax = feeMax;
    if (feePriority !== undefined) this.s.feePriority = feePriority;
    const after = JSON.stringify([this.s.mode, this.s.bareText, this.s.removeKeyId, this.s.feeMax, this.s.feePriority]);
    if (before !== after) {
      ++this.opGen;
      if (this.s.native.phase !== 'idle' && this.s.native.phase !== 'failed') void this.endNative(null);
    }
    this.emit();
  }

  /** The complete planned operation, or a typed change/fee problem. Never throws. */
  plan(nativeCap = this.s.native.context?.maxFeePerGas) {
    const context = this.s.inspection.context;
    if (this.s.inspection.phase !== 'ready' || !context) return { problem: null };
    let change;
    if (this.s.mode === 'add') {
      if (this.s.bareText.trim() === '') return { problem: 'change-missing' };
      let key;
      try { key = parseBareKey(this.s.bareText); } catch { return { problem: 'KW07-curve' }; }
      change = { kind: 'add', key };
    } else {
      if (context.keys.length <= 1) return { problem: 'KW07-last' };
      if (!this.s.removeKeyId) return { problem: 'change-missing' };
      change = { kind: 'remove', keyId: this.s.removeKeyId };
    }
    let fees;
    try {
      fees = innerFees(this.s.feeMax, this.s.feePriority, nativeCap);
    } catch (error) {
      try {
        planChange({ signer: context.signer, nonce: context.nonce, keys: context.keys, change,
          fees: { maxFee: 1n, priorityFee: 0n } });
      } catch (changeError) { return { problem: changeProblem(changeError) }; }
      return { problem: `KW08-${error.code}` };
    }
    let plan;
    try {
      plan = planChange({ signer: context.signer, nonce: context.nonce, keys: context.keys, change, fees });
    } catch (error) { return { problem: changeProblem(error) }; }
    const cost = prefund(fees.maxFee, context.deposit);
    return { problem: cost.shortfall > 0n ? 'KW09' : null, plan, fees, cost };
  }

  // ---------------------------------------------------------------------------------------------------------------
  // 03 APPROVAL: dedicated native session

  blocked() {
    const a = this.s.attempt;
    return !a.loaded || a.storageError !== null || a.sending || (a.record !== null && this.s.rollover === null)
      || (this.s.rollover?.needsAck && !this.s.rolloverAck);
  }

  async signClient() {
    if (this.client) return this.client;
    const config = await this.loadConfig();
    if (!/^[0-9a-f]{32}$/.test(config?.walletConnectProjectId || '') || !globalThis.crypto?.subtle) {
      throw new SessionError('lost');
    }
    const SignClient = await this.loadSignClient();
    this.client = await SignClient.init(signClientOptions(config.walletConnectProjectId));
    return this.client;
  }

  async connectNative() {
    const planned = this.plan();
    if (this.blocked() || planned.problem || !planned.plan || this.s.native.phase !== 'idle'
        && this.s.native.phase !== 'failed') return;
    const ticket = this.opGen, anchor = this.s.anchor;
    this.s.native = { phase: 'pairing', uri: null, context: null, failure: null, signed: null };
    this.emit();
    try {
      const client = await this.signClient();
      if (ticket !== this.opGen || this.s.native.phase !== 'pairing') return;
      const session = new KeyChangeSession(client, anchor, () => this.now(), (cause) => this.sessionLost(session, cause));
      this.session = session;
      await session.connect(async (uri) => {
        if (ticket !== this.opGen || this.session !== session) return;
        this.s.native.uri = uri;
        this.emit();
      });
      if (ticket !== this.opGen || this.session !== session) return;
      this.s.native = { phase: 'connected', uri: null, context: null, failure: null, signed: null };
    } catch (error) {
      if (ticket !== this.opGen || this.s.native.phase !== 'pairing') return;
      this.s.native = { phase: 'failed', uri: null, context: null, failure: classify(error), signed: null };
      this.dropSession();
    }
    this.emit();
  }

  /** Explicit cancel/disconnect: ends the native session; a durable attempt is untouched. */
  async disconnectNative() {
    await this.endNative(null);
    this.emit();
  }

  dropSession() {
    const session = this.session;
    this.session = null;
    if (session) void session.dispose().catch(() => {});
  }

  async endNative(failure) {
    this.s.nonceFailure = false;
    if (this.expiryTimer !== null) { this.clearTimer(this.expiryTimer); this.expiryTimer = null; }
    const session = this.session;
    this.session = null;
    this.s.native = failure ? { phase: 'failed', uri: null, context: null, failure, signed: null }
      : { phase: 'idle', uri: null, context: null, failure: null, signed: null };
    if (session) await session.dispose().catch(() => {});
  }

  sessionLost(session, cause) {
    if (this.session !== session) return;
    // A send already reserved keeps its durable record; only memory authority ends here.
    void this.endNative(cause || 'lost').then(() => this.emit());
  }

  async previewNative() {
    if (this.blocked() || this.s.native.phase !== 'connected' || !this.session) return;
    const ticket = this.opGen, session = this.session;
    this.s.native.phase = 'inspecting';
    this.emit();
    try {
      const native = await session.inspect();
      if (ticket !== this.opGen || this.session !== session) return;
      agree(native, this.s.inspection.context);
      this.s.native = { phase: 'preview', uri: null, context: native, failure: null, signed: null };
    } catch (error) {
      if (ticket !== this.opGen || this.session !== session) return;
      await this.endNative(classify(error));
    }
    this.emit();
  }

  async requestSignature() {
    const planned = this.plan();
    if (this.blocked() || this.s.native.phase !== 'preview' || !this.session || planned.problem) return;
    const ticket = this.opGen, session = this.session, anchor = this.s.anchor, inspected = this.s.inspection.context;
    const nativeGen = session.generation;
    const operation = planned.plan.operation;
    const live = () => {
      if (ticket !== this.opGen || this.session !== session || this.s.anchor !== anchor
          || this.s.inspection.phase !== 'ready' || this.s.inspection.context !== inspected
          || this.s.native.phase !== 'approving' || this.blocked()) throw new Stale();
      session.alive(nativeGen);
      const current = this.plan();
      if (current.problem || !current.plan || JSON.stringify(current.plan.operation) !== JSON.stringify(operation)
          || !sameKeys(current.plan.before, planned.plan.before) || !sameKeys(current.plan.after, planned.plan.after)) {
        throw new SessionError('changed');
      }
    };
    this.s.native.phase = 'approving';
    this.emit();
    try {
      const signed = await session.sign(async (native, wire) => {
        // Immediately before signing: independent chain context again, semantic authority (not block number).
        const web = await readContext(this.rpcOf(this.chainOf(anchor)), { signer: anchor.signerAddress,
          authorizer: anchor, now: () => this.now(), chain: this.chainOf(anchor) });
        live();
        if (!sameKeys(web.keys, inspected.keys) || web.nonce !== inspected.nonce) throw new SessionError('changed');
        agree(native, web);
        if (prefund(planned.fees.maxFee, web.deposit).shortfall > 0n) throw new SessionError('changed');
        const request = buildRequest({ context: native, operation, id: this.uuid(), issuedAt: issuedAtFor(this.now()) });
        await this.savedResultStore.save({ version: 1, purpose: PURPOSE, requestId: request.id,
          envelope: request.envelope, context: wire,
          expected: { anchor: { signerAddress: anchor.signerAddress, keyId: anchor.keyId, publicKey: anchor.publicKey },
            operation, beforeKeys: planned.plan.before, expectedAfterKeys: planned.plan.after,
            maxGasUnits: TOTAL_GAS.toString(), maxFeePerGas: planned.fees.maxFee.toString() } });
        live();
        return request;
      });
      if (ticket !== this.opGen || this.session !== session) return;
      this.s.native = { phase: 'verified', uri: null, context: this.s.native.context, failure: null,
        signed: { ...signed, plan: planned.plan, fees: planned.fees, cost: planned.cost } };
      this.armExpiry(signed.request.expiresAt);
    } catch (error) {
      if (ticket !== this.opGen || this.session !== session) return;
      await this.endNative(error instanceof Stale ? 'lost' : classify(error));
    }
    this.emit();
  }

  /** Adopt only an explicitly recovered original operation into the unchanged wallet preflight. */
  async adoptRecovered(record, recovered, session) {
    if (this.blocked() || this.session || this.s.inspection.phase !== 'ready' || !this.s.anchor) return false;
    const ticket = this.opGen, anchor = this.s.anchor, generation = session.generation;
    const r = parseRecord(serializeRecord(record)), x = r.expected;
    if (r.purpose !== PURPOSE || x.anchor.signerAddress !== anchor.signerAddress
        || x.anchor.keyId !== anchor.keyId || x.anchor.publicKey !== anchor.publicKey) return false;
    const matches = () => {
      const p = this.plan();
      return ticket === this.opGen && this.s.anchor === anchor && !this.blocked() && !this.session
        && p.plan && !p.problem && JSON.stringify(p.plan.operation) === JSON.stringify(x.operation)
        && sameKeys(p.plan.before, x.beforeKeys) && sameKeys(p.plan.after, x.expectedAfterKeys);
    };
    if (!matches()) return false;
    const context = validateNativeContext(r.context, anchor), e = JSON.parse(r.envelope);
    const request = buildRequest({ context, operation: x.operation, id: r.requestId, issuedAt: Number(e.issuedAt) });
    if (JSON.stringify(request) !== JSON.stringify(recovered.request)) return false;
    const result = { version: 1, purpose: PURPOSE, requestId: request.id, keyId: context.keyId,
      codecId: r.context.codecId, commitment: request.commitment, binding: context.binding,
      chainId: this.chainOf(anchor).decimal,
      entryPoint: ENTRYPOINT, signer: context.signer, nonce: request.operation.nonce,
      typedDataHash: request.typedDataHash, publicPoint: context.publicKey,
      rawSignature: recovered.rawSignature ?? recovered.result?.rawSignature, signerSignature: recovered.signerSignature };
    await verifyResult(result, request, context, this.now());
    session.alive(generation);
    if (!matches()) return false;
    const fresh = await readContext(this.rpcOf(this.chainOf(anchor)), { signer: anchor.signerAddress, authorizer: anchor,
      now: () => this.now(), chain: this.chainOf(anchor) });
    session.alive(generation);
    if (!matches() || this.now() >= request.expiresAt) return false;
    // Original context verifies original bytes; only the new retrieval observation is fresh authority.
    const current = session.context;
    if (!current || !sameKeys(current.keys, context.keys) || current.nonce !== context.nonce
        || current.signer !== context.signer || current.keyId !== context.keyId
        || current.publicKey !== context.publicKey || current.maxGasUnits !== context.maxGasUnits
        || current.maxFeePerGas !== context.maxFeePerGas) return false;
    agree(current, fresh);
    const added = x.expectedAfterKeys.filter((k) => !x.beforeKeys.some((b) => b.keyId === k.keyId));
    const removed = x.beforeKeys.filter((k) => !x.expectedAfterKeys.some((a) => a.keyId === k.keyId));
    const fees = { priorityFee: BigInt('0x' + x.operation.gasFees.slice(2, 34)),
      maxFee: BigInt('0x' + x.operation.gasFees.slice(34)) };
    const plan = planChange({ signer: context.signer, nonce: context.nonce, keys: x.beforeKeys,
      change: added.length === 1 ? { kind: 'add', key: added[0] } : { kind: 'remove', keyId: removed[0]?.keyId }, fees });
    if (JSON.stringify(plan.operation) !== JSON.stringify(x.operation)) return false;
    const changed = session.changed;
    session.changed = () => { changed?.(); this.sessionLost(session, 'lost'); };
    this.session = session;
    this.s.native = { phase: 'verified', uri: null, context: current, failure: null,
      signed: { request, signerSignature: recovered.signerSignature, rawSignature: result.rawSignature,
        plan, fees, cost: prefund(fees.maxFee, fresh.deposit) } };
    this.armExpiry(request.expiresAt); this.emit(); return true;
  }

  /** Browser permission to submit ends at expiry; the issued signature itself is not revoked onchain. */
  armExpiry(expiresAt) {
    const ms = Math.max(0, (expiresAt - this.now()) * 1000);
    this.expiryTimer = this.setTimer(() => {
      this.expiryTimer = null;
      if (this.s.native.phase === 'verified') {
        void this.endNative('expired').then(() => this.emit());
      }
    }, ms);
  }

  // ---------------------------------------------------------------------------------------------------------------
  // 04 EXECUTE: standard wallet (owns outer gas, fees, nonce and payment approval), reservation, one handleOps

  walletChanged() {
    // Any wallet event or generation change invalidates an in-flight send preflight; it never sends.
    ++this.sendReviewGen;
    this.s.nonceFailure = false;
    if (this.wallet.status === 'connected' || this.wallet.status === 'connecting') this.s.walletFailure = null;
    this.emit();
  }

  /** The explicit switch to the anchor's chain (legacy name kept for the page binding). */
  async switchPolygon() {
    await (this.wallet.switchChain ? this.wallet.switchChain() : this.wallet.switchPolygon());
    this.s.walletFailure = this.wallet.status === 'wrongChain' && this.wallet.error ? 'refused' : null;
    this.emit();
  }

  /**
   * Verified unexpired signature, live native session, a wallet connected on the anchor's chain and a reservable attempt
   * snapshot (or eligible explicit rollover). No outer input, quote, balance or payment checkbox participates.
   */
  sendReady() {
    const signed = this.s.native.signed;
    try { this.session?.alive(this.session.generation); } catch { return false; }
    return Boolean(this.session) && signed !== null && this.s.native.phase === 'verified' && this.wallet.status === 'connected'
      && this.wallet.chainId === this.chainOf().hex && !this.blocked() && this.now() < signed.request.expiresAt;
  }

  /** The explicit `表示した鍵変更を1回だけ送信` action: one bounded preflight, one reservation, one wallet request. */
  async send() {
    if (!this.sendReady()) return;
    const signed = this.s.native.signed, session = this.session, ticket = this.opGen;
    const nativeGen = session?.generation, reviewGen = this.sendReviewGen;
    const walletGen = this.wallet.generation, account = lower(this.wallet.account);
    const op = signed.request.operation, anchor = this.s.anchor, chain = this.chainOf(anchor);
    const expected = this.s.rollover ? this.s.rollover.prior : this.s.attempt.snapshot;
    // Synchronously busy: a second activation finds blocked() and returns before any read.
    this.s.attempt.sending = true;
    this.s.nonceFailure = false;
    this.emit();
    const live = () => {
      if (ticket !== this.opGen || reviewGen !== this.sendReviewGen
          || this.session !== session || this.s.native.signed !== signed
          || this.s.native.phase !== 'verified' || walletGen !== this.wallet.generation
          || this.wallet.status !== 'connected' || this.wallet.chainId !== chain.hex
          || lower(this.wallet.account) !== account || this.now() >= signed.request.expiresAt) return false;
      try { session.alive(nativeGen); return true; } catch { return false; }
    };
    let reserved = null;
    try {
      const { calldata, pending } = await this.preflight({ signed, session, anchor, account, live });
      if (!live()) throw new Stale();
      // New reservations are raw version 2: no outer gas/fee ceiling, the pending nonce only as a lookup hint.
      const record = {
        version: 2, attemptId: this.uuid(), status: 'reserved', chainId: chain.decimal, entryPoint: ENTRYPOINT,
        signer: op.sender, signerNonce: op.nonce, authorizerKeyId: anchor.keyId,
        typedDataHash: signed.request.typedDataHash, userOpHash: signed.request.userOpHash,
        calldataSHA256: sha256Hex(calldata), operation: op, beforeKeys: signed.plan.before,
        expectedAfterKeys: signed.plan.after, walletAccount: account, beneficiary: account,
        walletPendingNonce: pending.toString(), sendStartedAt: String(this.now()),
      };
      const raw = serializeAttempt(record);
      const result = await this.store.compareAndSet(expected, raw);
      if (!result.committed) {
        this.adoptSnapshot(result.snapshot, 'conflict');
        throw new Stale();
      }
      reserved = result.snapshot;
      this.adoptSnapshot(reserved, null);
      this.s.rollover = null; this.s.rolloverAck = false;
      this.emit();
      // Durable reservation exists. Any change now leaves it reconcile-only and invokes no wallet.
      if (!live()) throw new Stale();
      // Exactly five members: the wallet chooses gas, fees and nonce and presents its own payment approval.
      const tx = { from: this.wallet.account, to: ENTRYPOINT, data: calldata, value: '0x0', chainId: chain.hex };
      // The signature leaves memory with this single invocation; it can never be resent from this page.
      this.s.native.signed = null;
      // Invoke without another microtask gap after the final authority check; synchronous throws still settle unknown.
      const sending = (async () => this.wallet.request('eth_sendTransaction', [tx]))();
      void this.endNative(null);
      let hash = null, timedOut = false;
      let timer;
      try {
        hash = await Promise.race([sending, new Promise((_, reject) => {
          timer = this.setTimer(() => { timedOut = true; reject(new Error('timeout')); }, WALLET_TIMEOUT_MS);
        })]);
      } catch {
        hash = null;
      } finally { this.clearTimer(timer); }
      if (timedOut) sending.then((late) => this.lateHash(record.attemptId, late), () => {});
      await this.recordSubmission(record.attemptId, hash);
    } catch (error) {
      if (error instanceof StorageError) this.s.attempt.storageError = error.code === 'corrupt' ? 'corrupt' : 'unavailable';
      // The still-live verified signature stays in memory; only another explicit send repeats the preflight.
      else if (error instanceof NonceUnavailable) this.s.nonceFailure = live();
      else if (!(error instanceof Stale) && !reserved) await this.endNative(error instanceof SessionError ? error.kind
        : error instanceof ReadError ? 'changed' : 'lost');
    } finally {
      this.s.attempt.sending = false;
      this.emit();
    }
  }

  /**
   * Fresh coherent Signer state at one block (identity, full keys, nonce, deposit), the exact rebuilt operation, H
   * and calldata, then the pending wallet nonce, all under the 60s send-preflight deadline (each read 10s). A late
   * completion after the deadline returns nothing usable: the caller has already left. Executor balance is not read.
   */
  async preflight({ signed, session, anchor, account, live }) {
    const op = signed.request.operation;
    let stage = 'context', timer;
    const chain = this.chainOf(anchor), rpc = this.rpcOf(chain);
    const run = async () => {
      const fresh = await readContext(rpc, { signer: anchor.signerAddress, authorizer: anchor,
        now: () => this.now(), chain });
      if (!live()) throw new Stale();
      session.check();
      if (!sameKeys(fresh.keys, signed.plan.before) || fresh.nonce !== BigInt(op.nonce)) throw new SessionError('changed');
      if (prefund(signed.fees.maxFee, fresh.deposit).shortfall > 0n) throw new SessionError('changed');
      // Rebuild and byte-compare the operation, H and calldata from the frozen plan.
      const rebuilt = planChange({ signer: op.sender, nonce: BigInt(op.nonce), keys: signed.plan.before,
        change: signed.plan.action === 'add' ? { kind: 'add', key: signed.plan.target }
          : { kind: 'remove', keyId: signed.plan.target.keyId }, fees: signed.fees });
      if (Object.keys(op).some((k) => rebuilt.operation[k] !== op[k])
          || typedDataHash(op, chain.decimal) !== signed.request.typedDataHash) {
        throw new SessionError('changed');
      }
      const calldata = handleOpsCall(op, signed.signerSignature, account);
      if (handleOpsCall(rebuilt.operation, signed.signerSignature, account) !== calldata) throw new SessionError('changed');
      stage = 'nonce';
      let pending;
      try { pending = await pendingNonce(rpc, account); } catch { throw new NonceUnavailable(); }
      return { calldata, pending };
    };
    try {
      return await Promise.race([run(), new Promise((_, reject) => {
        timer = this.setTimer(() => reject(stage === 'nonce' ? new NonceUnavailable() : new ReadError('unavailable')),
          ACQUISITION_DEADLINE_MS);
      })]);
    } finally {
      this.clearTimer(timer);
    }
  }

  /** hashKnown with a canonical hash, otherwise unknown; neither ever re-enables a send. */
  async recordSubmission(attemptId, hash) {
    const valid = typeof hash === 'string' && /^0x[0-9a-fA-F]{64}$/.test(hash);
    const record = this.s.attempt.record;
    if (!record || record.attemptId !== attemptId) return;
    this.s.attempt.lastHash = valid ? hash.toLowerCase() : null;
    await this.update((r) => (valid ? { ...r, status: 'hashKnown', transactionHash: hash.toLowerCase() }
      : { ...r, status: 'unknown' }));
  }

  /** A hash arriving after the bounded wait is attached to the ORIGINAL reservation only. */
  async lateHash(attemptId, hash) {
    const record = this.s.attempt.record;
    if (!record || record.attemptId !== attemptId || record.transactionHash || typeof hash !== 'string'
        || !/^0x[0-9a-fA-F]{64}$/.test(hash)) return;
    this.s.attempt.lastHash = hash.toLowerCase();
    if (await this.update((r) => ({ ...r, status: 'hashKnown', transactionHash: hash.toLowerCase() }))) {
      this.s.attempt.lateHash = true;
    }
    this.emit();
  }

  adoptSnapshot(snapshot, storageError) {
    const a = this.s.attempt;
    a.snapshot = snapshot;
    try {
      const record = parseAttempt(snapshot.raw);
      if (storageError || record?.attemptId !== a.record?.attemptId) {
        a.outcome = null; a.restored = false; a.lateHash = false; a.lastHash = null;
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
      const raw = serializeAttempt(change(a.record));
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
      a.storageError = error instanceof StorageError && error.code === 'corrupt' ? 'corrupt' : 'unavailable';
      return false;
    }
  }

  async loadAttempt() {
    try {
      const snapshot = await this.store.read();
      this.adoptSnapshot(snapshot, null);
      this.s.attempt.restored = this.s.attempt.record !== null;
    } catch (error) {
      this.s.attempt.storageError = error instanceof StorageError && error.code === 'corrupt' ? 'corrupt'
        : 'unavailable';
    }
    this.s.attempt.loaded = true;
    this.emit();
  }

  /** Explicit re-read of storage after a conflict/unavailable report; never clears or overwrites. */
  async reloadAttempt() {
    if (this.s.attempt.sending) return;
    this.s.attempt.storageError = null;
    await this.loadAttempt();
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Reconciliation (explicit, bounded, read-only)

  async reconcile(hashInput = '') {
    const a = this.s.attempt;
    if (!a.record || a.reconciling || a.sending || a.storageError === 'corrupt') return;
    const input = hashInput.trim();
    if (input && (a.record.transactionHash || !/^0x[0-9a-fA-F]{64}$/.test(input))) return;
    a.reconciling = true;
    this.emit();
    try {
      const outcome = await this.boundedSettle(a.record, input ? input.toLowerCase() : null);
      if (outcome) { a.outcome = outcome; a.restored = false; a.lateHash = false; }
    } finally {
      a.reconciling = false;
      this.emit();
    }
  }

  /** settle() under the 60s reconciliation deadline; an expired deadline reads as unavailable data. */
  async boundedSettle(record, suppliedHash) {
    let timer, active = true, snapshot = this.s.attempt.snapshot;
    // Pin all writes to this pass's exact bytes. Never continue on a snapshot adopted after a conflict.
    const write = async (change) => {
      if (!active || this.s.attempt.snapshot !== snapshot) throw new Stale();
      if (!await this.update(change, snapshot)) throw new Stale();
      snapshot = this.s.attempt.snapshot;
    };
    try {
      const result = await Promise.race([this.settle(record, suppliedHash, write),
        new Promise((resolve) => { timer = this.setTimer(() => { active = false;
          resolve({ view: 'KW26-rpc' }); }, RECONCILE_DEADLINE_MS); })]);
      return this.s.attempt.snapshot === snapshot ? result : null;
    } catch (error) {
      if (error instanceof Stale) return null;
      throw error;
    } finally {
      active = false;
      this.clearTimer(timer);
    }
  }

  /**
   * One read-only settlement pass. Returns `{view, costs?}` after persisting any verified status change. A saved
   * outer failure is never trusted at a later inspection: when the exact canonical status0 receipt at two
   * confirmations is not re-verified now (transaction or receipt missing/pending, foreign tuple, reorg), the
   * attempt returns to reconcile-only `hashKnown` without its receipt summary or outcome, so no unchanged-nonce
   * rollover (b) is offered from stale data. Unavailable reads (KW26-rpc) leave the record as it is; other verified
   * observations (caps, events, state) keep the status settleOnce() persisted.
   */
  async settle(record, suppliedHash, write) {
    const result = await this.settleOnce(record, suppliedHash, write);
    const current = this.s.attempt.record;
    if (record.status === 'outerFailed' && STALE_OUTER_FAILURE.has(result.view) && current
        && current.attemptId === record.attemptId && current.transactionHash
        && (current.status === 'outerFailed' || (current.status === 'uncertain' && !current.outcome))) {
      await write((r) => {
        const { receipt: _receipt, ...rest } = withoutOutcome(r);
        return { ...rest, status: 'hashKnown' };
      });
    }
    return result;
  }

  async settleOnce(record, suppliedHash, write) {
    const hash = record.transactionHash || suppliedHash;
    if (!hash) return this.settleHashless(record, write);
    // Fee policy follows the validated raw version: v1 keeps its legacy ceilings and cap outcome, v2 never compares
    // the wallet's fee choice with any application value.
    const legacy = record.version === 1, fees = legacy ? 'legacy' : 'raw';
    // Every settlement read uses the record's own chain only.
    const chain = this.recordChain(record), rpc = this.rpcOf(chain);
    let tx;
    try { tx = await readTransaction(rpc, hash, { fees }); } catch { return { view: 'KW26-rpc' }; }
    if (tx === null) {
      // Absence is not failure; only an independently verified nonce advance makes the signature unexecutable.
      const advanced = await this.settleHashless(record, write);
      return advanced.view === 'KW22-no-hash' || advanced.view === 'KW26-rpc' ? { view: 'KW23-pending' } : advanced;
    }
    if (tx.from !== record.walletAccount || tx.to !== ENTRYPOINT || tx.value !== 0n || tx.chainId !== BigInt(chain.id)
        || U.sha256(tx.input) !== record.calldataSHA256) {
      return { view: 'KW26-foreign' };
    }
    const capped = legacy && (tx.gas > BigInt(record.outerGasLimit)
      || tx.maxFeePerGas > BigInt(record.outerMaxFeePerGas)
      || tx.maxPriorityFeePerGas > BigInt(record.outerMaxPriorityFeePerGas));
    // The fetched actual wallet nonce is diagnostic: recorded by CAS, never compared with the pending lookup hint.
    if (!record.transactionHash || record.actualWalletNonce !== tx.nonce.toString()) {
      await write((r) => ({ ...r, status: r.status === 'reserved' || r.status === 'unknown' ? 'hashKnown' : r.status,
        transactionHash: hash, actualWalletNonce: tx.nonce.toString() }));
    }
    if (capped) {
      await write((r) => ({ ...withoutOutcome(r), status: 'uncertain' }));
      return { view: 'KW26-cap' };
    }
    let rc;
    try { rc = await readReceipt(rpc, hash, { fees }); } catch { return { view: 'KW26-rpc' }; }
    if (rc === null || tx.blockNumber === null) {
      const advanced = await this.settleHashless(record, write);
      return advanced.view === 'KW22-no-hash' || advanced.view === 'KW26-rpc' ? { view: 'KW23-pending' } : advanced;
    }
    if (rc.blockNumber !== tx.blockNumber || rc.blockHash !== tx.blockHash || rc.from !== record.walletAccount
        || rc.to !== ENTRYPOINT) {
      await write((r) => ({ ...withoutOutcome(r), status: 'uncertain' }));
      return { view: 'KW26-reorg' };
    }
    let outerCost;
    if (legacy) {
      if (rc.gasUsed > tx.gas || rc.effectiveGasPrice > tx.maxFeePerGas) return { view: 'KW26-rpc' };
      outerCost = rc.gasUsed * rc.effectiveGasPrice;
    } else {
      try {
        outerCost = coherentFees(tx.feeFields, rc.feeFields).outerCost;
      } catch {
        // Incoherent actual fee evidence: uncertain and reconcile-only; a saved outcome is not kept.
        await write((r) => ({ ...withoutOutcome(r), status: 'uncertain' }));
        return { view: 'KW26-fees' };
      }
    }
    const receiptSummary = { blockNumber: rc.blockNumber.toString(), blockHash: rc.blockHash, status: rc.status };
    let canonical, head;
    try {
      canonical = await block(rpc, rc.blockNumber);
      head = await block(rpc, null);
    } catch { return { view: 'KW26-rpc' }; }
    if (canonical.hash !== rc.blockHash) {
      await write((r) => ({ ...withoutOutcome(r), status: 'uncertain' }));
      return { view: 'KW26-reorg' };
    }
    if (head.number < rc.blockNumber + REQUIRED_CONFIRMATIONS - 1n) {
      await write((r) => ({ ...withoutOutcome(r), status: 'confirming', receipt: receiptSummary }));
      return { view: 'KW23-one' };
    }
    const stillCanonical = async () => {
      try { return (await block(rpc, rc.blockNumber)).hash === rc.blockHash; } catch { return null; }
    };
    if (rc.status === '0x0') {
      const ok = await stillCanonical();
      if (ok !== true) return { view: ok === null ? 'KW26-rpc' : 'KW26-reorg' };
      await write((r) => ({ ...r, status: 'outerFailed', receipt: receiptSummary,
        outcome: { kind: 'outerFailed', actualOuterCostWei: outerCost.toString() } }));
      return { view: 'KW25', costs: { outerCost } };
    }
    const event = matchingEvent(rc.logs, record);
    if (event === null || (!legacy && !withinSignedBudget(event, record))) {
      await write((r) => ({ ...withoutOutcome(r), status: 'uncertain', receipt: receiptSummary }));
      return { view: 'KW26-event', costs: { outerCost } };
    }
    const costs = { outerCost, actualGasCost: event.actualGasCost, net: outerCost - event.actualGasCost };
    if (!event.success) {
      const ok = await stillCanonical();
      if (ok !== true) return { view: ok === null ? 'KW26-rpc' : 'KW26-reorg', costs };
      await write((r) => ({ ...r, status: 'innerFailed', receipt: receiptSummary,
        outcome: { kind: 'innerFailed', actualOuterCostWei: outerCost.toString(),
          actualGasCostWei: event.actualGasCost.toString() } }));
      return { view: 'KW24', costs };
    }
    let post;
    try {
      // Historical mode: exact receipt block, no freshness window, no authorizer membership (self-removal).
      post = await readContext(rpc, { signer: record.signer, chain, historical: { number: rc.blockNumber,
        hash: rc.blockHash }, now: () => this.now() });
    } catch (error) {
      return { view: error instanceof ReadError && error.code === 'mismatch' ? 'KW26-reorg' : 'KW26-rpc', costs };
    }
    const ok = await stillCanonical();
    if (ok !== true) return { view: ok === null ? 'KW26-rpc' : 'KW26-reorg', costs };
    const expectedNonce = BigInt(record.signerNonce) + 1n;
    const outcomeCosts = { actualOuterCostWei: outerCost.toString(), actualGasCostWei: event.actualGasCost.toString() };
    if (post.nonce === expectedNonce && sameKeys(post.keys, record.expectedAfterKeys)) {
      await write((r) => ({ ...r, status: 'succeeded', receipt: receiptSummary,
        outcome: { kind: 'succeeded', ...outcomeCosts } }));
      const action = record.expectedAfterKeys.length > record.beforeKeys.length ? 'KW27' : 'KW28';
      return { view: action, costs, keys: post.keys };
    }
    if (post.nonce > expectedNonce) {
      await write((r) => ({ ...r, status: 'uncertain', receipt: receiptSummary,
        outcome: { kind: 'sameBlockConflict', ...outcomeCosts } }));
      return { view: 'KW26-same-block', costs, keys: post.keys };
    }
    await write((r) => ({ ...withoutOutcome(r), status: 'uncertain', receipt: receiptSummary }));
    return { view: 'KW26-state', costs, keys: post.keys };
  }

  /** No hash: only an independently verified fresh nonce advance resolves anything, and never proves execution. */
  async settleHashless(record, write) {
    let fresh;
    try {
      fresh = await readContext(this.rpcOf(this.recordChain(record)), { signer: record.signer,
        now: () => this.now(), chain: this.recordChain(record) });
    } catch { return { view: 'KW26-rpc' }; }
    if (fresh.nonce <= BigInt(record.signerNonce)) return { view: 'KW22-no-hash' };
    if (sameKeys(fresh.keys, record.expectedAfterKeys)) {
      await write((r) => ({ ...withoutOutcome(r), status: 'stateResolved', outcome: { kind: 'stateResolved' } }));
      return { view: 'KW26-state-resolved', keys: fresh.keys };
    }
    await write((r) => ({ ...withoutOutcome(r), status: 'uncertain' }));
    return { view: 'KW26-state-advanced', keys: fresh.keys };
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Explicit rollover (`新しい鍵変更を作成`) under design section 5 (a)/(b)/(c)

  async newChange() {
    const a = this.s.attempt;
    if (!a.record || a.sending || a.reconciling || a.storageError) return;
    const record = a.record, snapshot = a.snapshot;
    a.reconciling = true;
    this.emit();
    try {
      let fresh;
      try {
        fresh = await readContext(this.rpcOf(this.recordChain(record)), { signer: record.signer,
          now: () => this.now(), chain: this.recordChain(record) });
      } catch {
        a.outcome = { view: 'KW26-rpc' };
        return;
      }
      if (this.s.attempt.snapshot !== snapshot) return;
      const reserved = BigInt(record.signerNonce);
      const established = record.outcome && EVENT_DONE.has(record.outcome.kind);
      if (fresh.nonce > reserved) {
        if (!established) {
          const resolved = sameKeys(fresh.keys, record.expectedAfterKeys);
          a.outcome = { view: resolved ? 'KW26-state-resolved' : 'KW26-state-advanced', keys: fresh.keys };
        }
        this.s.rollover = { prior: snapshot, needsAck: false };
      } else if (record.status === 'outerFailed' && fresh.nonce === reserved) {
        // (b) is never inferred from the saved status: the exact tuple, canonical status0 receipt (block hash
        // re-read by number) and two confirmations are re-verified against current chain data first.
        const verified = await this.boundedSettle(record, null);
        if (!verified) return;
        if (verified.view !== 'KW25') {
          a.outcome = verified;
          a.restored = false;
          return;
        }
        if (this.s.attempt.snapshot !== snapshot) return;
        a.outcome = verified;
        this.s.rollover = { prior: snapshot, needsAck: true };
        this.s.rolloverAck = false;
      } else return;
      a.restored = false;
      // A NEW explicitly authorized request needs fresh public inspection and a fresh native connection.
      this.invalidateAuthority();
    } finally {
      a.reconciling = false;
      this.emit();
    }
  }

  setRolloverAck(value) {
    if (!this.s.rollover?.needsAck) return;
    ++this.sendReviewGen;
    this.s.rolloverAck = Boolean(value);
    this.emit();
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Typed view

  /** The row of the durable attempt (when it governs the page). */
  attemptRow() {
    const a = this.s.attempt, r = a.record;
    if (a.sending && r?.status === 'reserved') return 'KW21';
    if (a.outcome) return a.outcome.view;
    if (a.restored) {
      const v = r.version === 2 ? 'KW30-v2-' : 'KW30-';
      if (TERMINAL.has(r.status)) return `${v}terminal`;
      return r.transactionHash ? `${v}hash` : `${v}reserved`;
    }
    if (a.lateHash) return 'KW22-late-hash';
    switch (r.status) {
      case 'reserved': return a.sending ? 'KW21' : 'KW22-no-hash';
      case 'unknown': return 'KW22-no-hash';
      case 'hashKnown': return 'KW23-pending';
      case 'confirming': return 'KW23-one';
      case 'succeeded': return r.expectedAfterKeys.length > r.beforeKeys.length ? 'KW27' : 'KW28';
      case 'innerFailed': return 'KW24';
      case 'outerFailed': return 'KW25';
      case 'stateResolved': return 'KW26-state-resolved';
      default: return r.outcome?.kind === 'sameBlockConflict' ? 'KW26-same-block' : 'KW26-event';
    }
  }

  view() {
    const s = this.s, a = s.attempt, planned = this.plan();
    const nativePhase = s.native.phase;
    let row;
    if (a.storageError) row = `KW29-${a.storageError}`;
    else if (a.record && !s.rollover) row = this.attemptRow();
    else if (a.sending) row = 'KW20-checking';
    else if (nativePhase === 'verified') {
      const w = this.wallet;
      if (w.status === 'connecting') row = w.pairing ? 'KW17-pairing' : 'KW17-choices';
      else if (w.status === 'wrongChain') row = s.walletFailure === 'refused' ? 'KW18-refused' : 'KW18-wrong';
      else if (w.status !== 'connected') {
        row = w.choices().some((c) => !c.disabled) ? (w.selectedId || w.error ? 'KW17-choices' : 'KW15')
          : 'KW17-unavailable';
      } else row = s.nonceFailure ? 'KW20-nonce' : 'KW20';
    } else if (nativePhase === 'failed') row = `KW16-${s.native.failure}`;
    else if (nativePhase === 'pairing') row = 'KW10';
    else if (nativePhase === 'connected' || nativePhase === 'inspecting') row = 'KW11';
    else if (nativePhase === 'preview') row = planned.plan?.action === 'remove' ? 'KW13' : 'KW12';
    else if (nativePhase === 'approving') row = 'KW14';
    else if (s.inspection.phase === 'reading') row = 'KW03';
    else if (s.inspection.phase === 'unavailable') row = 'KW04';
    else if (s.inspection.phase === 'ready') {
      if (planned.problem && planned.problem !== 'change-missing') row = planned.problem;
      else row = s.mode === 'remove' ? 'KW06' : 'KW05';
    } else row = s.anchorError ? 'KW02' : 'KW01';
    const base = row.split('-')[0];
    // The one chain this view is about: a governing attempt's own recorded chain (reconciled on that chain only),
    // otherwise the anchor's (Polygon without one). Fixed Polygon-worded rows name it; Polygon keeps the exact bytes.
    const viewChain = Boolean(a.record) && !s.rollover ? chainOf(a.record.chainId) || POLYGON : this.chainOf();
    const message = typeof MESSAGES[row] === 'string' ? chainText(MESSAGES[row], viewChain) : MESSAGES[row];
    const context = s.inspection.context;
    const signed = s.native.signed;
    const selfRemoval = s.mode === 'remove' && s.anchor && s.removeKeyId === s.anchor.keyId;
    const governing = Boolean(a.record) && !s.rollover;
    return Object.freeze({
      row, base, message, error: ERROR_ROWS.has(base) || ERROR_ROWS.has(row), chain: viewChain,
      anchor: s.anchor, anchorError: s.anchorError, anchorText: s.anchorText,
      inspection: s.inspection.phase, context, mode: s.mode, removeKeyId: s.removeKeyId,
      plan: planned.plan || null, fees: planned.fees || null, cost: planned.cost || null, problem: planned.problem,
      selfRemoval: Boolean(selfRemoval), native: { ...s.native }, signed,
      wallet: this.wallet.snapshot(),
      attempt: { record: a.record, revision: a.snapshot?.revision ?? null, storageError: a.storageError,
        loaded: a.loaded, sending: a.sending, reconciling: a.reconciling, outcome: a.outcome, restored: a.restored,
        lastHash: a.lastHash },
      rollover: s.rollover ? { needsAck: s.rollover.needsAck, ack: s.rolloverAck } : null,
      actions: {
        inspect: s.inspection.phase !== 'reading' && !a.sending,
        cancelInspect: s.inspection.phase === 'reading',
        connectNative: !this.blocked() && !planned.problem && Boolean(planned.plan)
          && (nativePhase === 'idle' || nativePhase === 'failed'),
        cancelNative: nativePhase === 'pairing',
        previewNative: !this.blocked() && nativePhase === 'connected',
        requestSignature: !this.blocked() && nativePhase === 'preview' && !planned.problem,
        disconnectNative: ['connected', 'inspecting', 'preview', 'approving', 'verified'].includes(nativePhase),
        walletChoose: nativePhase === 'verified' && !governing && this.wallet.status !== 'connecting',
        walletConnect: nativePhase === 'verified' && !governing && Boolean(this.wallet.selectedId)
          && this.wallet.status === 'disconnected',
        walletCancel: this.wallet.status === 'connecting',
        walletSwitch: this.wallet.status === 'wrongChain' && !governing,
        walletDisconnect: this.wallet.status === 'connected' || this.wallet.status === 'wrongChain',
        send: this.sendReady() && !a.sending,
        reconcile: Boolean(a.record) && !a.sending && !a.reconciling && a.storageError !== 'corrupt',
        hashInput: Boolean(a.record) && !a.record.transactionHash && !a.sending && !a.reconciling
          && a.storageError !== 'corrupt',
        newChange: Boolean(a.record) && !s.rollover && !a.sending && !a.reconciling && !a.storageError
          && rolloverCandidate(a.record, a.outcome),
        reloadStorage: Boolean(a.storageError) && a.storageError !== 'corrupt' && !a.sending,
      },
      costs: a.outcome?.costs || null,
      pol: formatPol, totalGas: TOTAL_GAS, entryPoint: ENTRYPOINT, zero: ZERO_ADDRESS,
    });
  }
}

function changeProblem(error) {
  return { duplicate: 'KW07-duplicate', limit: 'KW07-limit', last: 'KW07-last', curve: 'KW07-curve' }[error?.code]
    || 'KW07-curve';
}

function withoutOutcome(record) {
  const { outcome: _outcome, ...rest } = record;
  return rest;
}

/**
 * Rows offering an explicit new change; the fresh independent nonce check in newChange() decides eligibility.
 * Reserved/unknown/hash-known/confirming attempts stay reconcile-only until a verified result exists.
 */
function rolloverCandidate(record, outcome) {
  if (['succeeded', 'innerFailed', 'outerFailed', 'stateResolved', 'uncertain'].includes(record.status)) return true;
  return ['KW26-state-advanced', 'KW26-state-resolved'].includes(outcome?.view);
}

/**
 * v2: the event's actualGasCost must not exceed the prefund P = TOTAL_GAS x signed inner maxFee, nor the checked
 * actualGasUsed x signed inner maxFee. Bounds the inner reimbursement claim only; never the wallet's outer payment.
 */
export function withinSignedBudget(event, record) {
  const innerMaxFee = BigInt('0x' + record.operation.gasFees.slice(34));
  const used = event.actualGasUsed * innerMaxFee;
  return used <= UINT256_MAX && event.actualGasCost <= TOTAL_GAS * innerMaxFee && event.actualGasCost <= used;
}

/** The one canonical EntryPoint UserOperationEvent for this attempt, or null (missing, duplicate, malformed). */
export function matchingEvent(logs, record) {
  const candidates = logs.filter((log) => log.address === ENTRYPOINT && log.topics[0] === USER_OPERATION_EVENT);
  const mine = candidates.filter((log) => log.topics[1] === record.userOpHash);
  if (mine.length !== 1) return null;
  const log = mine[0];
  if (log.topics.length !== 4 || log.topics[2] !== addressTopic(record.signer)
      || log.topics[3] !== addressTopic(ZERO_ADDRESS) || log.data.length !== 2 + 64 * 4) return null;
  const words = [0, 1, 2, 3].map((i) => BigInt('0x' + log.data.slice(2 + 64 * i, 66 + 64 * i)));
  if (words[0] !== BigInt(record.signerNonce) || (words[1] !== 0n && words[1] !== 1n)) return null;
  return { success: words[1] === 1n, actualGasCost: words[2], actualGasUsed: words[3] };
}
