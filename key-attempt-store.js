// Transactional authority for the one current key-change attempt: a dedicated native IndexedDB singleton
// `{version:1, revision, raw}` (raw: canonical attempt JSON or null before the first reservation). Every update
// compares the exact revision and bytes inside the same strict-durability readwrite transaction that writes
// revision+1; completion is reported only from `oncomplete`. The transaction algorithm is attempt-store.js's,
// without its legacy import; the deployment database, schema and data are untouched. No fallback store, no clear.
// The record is public lookup identity only: never a signature, binding, session topic, grant, QR or private key.
// This is a local crash/race authority, not protection against a malicious same-origin process rewriting IndexedDB.
// The raw record carries an explicit integer `version`, independent of the wrapper version: 1 is the legacy closed
// schema with application outer gas/fee ceilings (parsed, round-tripped and reconciled exactly as before, never
// normalized or upgraded); 2 is every new reservation, whose outer gas, fees and nonce belong to the wallet.
import {
  ENTRYPOINT, OUTER_GAS_FLOOR, TOTAL_GAS, UINT120_MAX, UINT128_MAX, UINT256_MAX, UINT64_MAX, ZERO_ADDRESS,
  BODY_KEYS, checkOperation, isDecimal, isHash, isKeyId, isLowerAddress, isUUID, planChange, sortedKeys,
  typedDataHash, userOpHash,
} from './key-model.js';
import { chainOf } from './chains.js';

export const DB_NAME = 'p256.key-change.attempts';
export const DB_VERSION = 1;
export const STORE_NAME = 'state';
export const SINGLETON_KEY = 'current';
export const STORE_TIMEOUT_MS = 5000;
export const MAX_RECORD_BYTES = 32768;
export const STATUSES = Object.freeze(['reserved', 'hashKnown', 'unknown', 'confirming', 'succeeded', 'innerFailed',
  'outerFailed', 'uncertain', 'stateResolved']);
const OUTCOME_KINDS = ['succeeded', 'innerFailed', 'outerFailed', 'sameBlockConflict', 'stateResolved'];
const OUTER_CEILINGS = ['outerGasLimit', 'outerMaxFeePerGas', 'outerMaxPriorityFeePerGas'];
const REQUIRED_V1 = ['version', 'attemptId', 'status', 'chainId', 'entryPoint', 'signer', 'signerNonce',
  'authorizerKeyId', 'typedDataHash', 'userOpHash', 'calldataSHA256', 'operation', 'beforeKeys', 'expectedAfterKeys',
  'walletAccount', 'beneficiary', 'walletPendingNonce', ...OUTER_CEILINGS, 'sendStartedAt'];
/** v2: the v1 order with only the three outer ceilings deleted; no substitute gas, nonce or estimate member. */
const REQUIRED_V2 = REQUIRED_V1.filter((key) => !OUTER_CEILINGS.includes(key));
const OPTIONAL = ['transactionHash', 'actualWalletNonce', 'receipt', 'outcome'];
/** Version-specific closed member lists; any other raw version (string, missing, unknown) has none. */
const requiredFor = (version) => (version === 1 ? REQUIRED_V1 : version === 2 ? REQUIRED_V2 : null);
const WRAPPER_KEYS = '["raw","revision","version"]';

/** unavailable | timeout | blocked | closed | durability | corrupt | aborted | invalid | exhausted. */
export class StorageError extends Error {
  constructor(code) {
    super(`key-change storage ${code}`);
    this.name = 'StorageError';
    this.code = code;
  }
}
const corrupt = () => { throw new StorageError('corrupt'); };
const utf8Length = (text) => new TextEncoder().encode(text).length;

// ---------------------------------------------------------------------------------------------------------------
// Closed attempt v1/v2 schemas (key-change-web spec: Dedicated durable attempt authority)

function closed(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) corrupt();
  for (const key of Object.keys(value)) if (!required.includes(key) && !optional.includes(key)) corrupt();
  for (const key of required) if (!Object.prototype.hasOwnProperty.call(value, key)) corrupt();
}
const canonicalUint = (text, max) => (isDecimal(text) && BigInt(text) <= max ? BigInt(text) : corrupt());
const keyList = (list) => {
  if (!Array.isArray(list) || list.length < 1 || list.length > 64) corrupt();
  list.forEach((k) => closed(k, ['keyId', 'publicKey']));
  let sorted;
  try { sorted = sortedKeys(list); } catch { corrupt(); }
  if (sorted.some((k, i) => k.keyId !== list[i].keyId)) corrupt();
  return sorted;
};

/** Duplicate-name-rejecting parse of untrusted bytes (JSON.parse silently keeps the last duplicate). */
function strictParse(text) {
  let value;
  try { value = JSON.parse(text); } catch { corrupt(); }
  // Canonical bytes are exactly the serializer's output, so any duplicate or reordered member fails here.
  if (serializeAttempt(value, { trusted: true }) !== text) corrupt();
  return value;
}

/**
 * The only serializer: copies the listed fields in fixed order, never spreads untrusted input. `trusted` skips the
 * relationship validation (used inside strictParse, which validates afterwards).
 */
export function serializeAttempt(record, { trusted = false } = {}) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) corrupt();
  const out = {};
  // The member list follows the exact integer version; anything else is copied by the v1 list and then refused.
  for (const key of [...(requiredFor(record.version) || REQUIRED_V1), ...OPTIONAL]) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) continue;
    const value = record[key];
    if (key === 'operation') {
      if (!value || typeof value !== 'object') corrupt();
      out.operation = Object.fromEntries(BODY_KEYS.filter((k) => k in value).map((k) => [k, value[k]]));
      if (Object.keys(value).length !== Object.keys(out.operation).length) out.operation.__extra = true;
    } else if (key === 'beforeKeys' || key === 'expectedAfterKeys') {
      if (!Array.isArray(value)) corrupt();
      out[key] = value.map((k) => (k && typeof k === 'object'
        ? Object.keys(k).length === 2 ? { keyId: k.keyId, publicKey: k.publicKey } : { __extra: true } : k));
    } else if (key === 'receipt') {
      if (!value || typeof value !== 'object') corrupt();
      out.receipt = { blockNumber: value.blockNumber, blockHash: value.blockHash, status: value.status };
      if (Object.keys(value).length !== 3) out.receipt.__extra = true;
    } else if (key === 'outcome') {
      if (!value || typeof value !== 'object') corrupt();
      out.outcome = { kind: value.kind };
      for (const field of ['actualOuterCostWei', 'actualGasCostWei']) if (field in value) out.outcome[field] = value[field];
      if (Object.keys(value).length !== Object.keys(out.outcome).length) out.outcome.__extra = true;
    } else out[key] = value;
  }
  if (Object.keys(record).length !== Object.keys(out).length) out.__extra = true;
  const text = JSON.stringify(out);
  if (!trusted) validateAttempt(JSON.parse(text));
  if (utf8Length(text) > MAX_RECORD_BYTES) corrupt();
  return text;
}

/** Full closed validation including recomputed H, userOpHash and the exact add/remove key-map relation. */
export function validateAttempt(r) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) corrupt();
  const required = requiredFor(r.version);
  if (!required) corrupt();
  closed(r, required, OPTIONAL);
  // Every record names exactly one closed chain; its settlement reads and checks that chain only.
  if (!isUUID(r.attemptId) || !STATUSES.includes(r.status) || !chainOf(r.chainId)
      || r.entryPoint !== ENTRYPOINT || !isLowerAddress(r.signer) || r.signer === ZERO_ADDRESS
      || !isKeyId(r.authorizerKeyId) || !isHash(r.typedDataHash) || !isHash(r.userOpHash) || !isHash(r.calldataSHA256)
      || !isLowerAddress(r.walletAccount) || r.walletAccount === ZERO_ADDRESS || r.beneficiary !== r.walletAccount) {
    corrupt();
  }
  const nonce = canonicalUint(r.signerNonce, UINT64_MAX);
  canonicalUint(r.walletPendingNonce, UINT256_MAX);
  if (r.version === 1) {
    // Legacy outer ceilings: unchanged v1 bounds, kept only for historical records.
    const gas = canonicalUint(r.outerGasLimit, UINT64_MAX), maxFee = canonicalUint(r.outerMaxFeePerGas, UINT128_MAX);
    const tip = canonicalUint(r.outerMaxPriorityFeePerGas, UINT128_MAX);
    if (gas < OUTER_GAS_FLOOR || maxFee === 0n || tip > maxFee) corrupt();
  }
  if (canonicalUint(r.sendStartedAt, UINT64_MAX) === 0n) corrupt();
  closed(r.operation, BODY_KEYS);
  try { checkOperation(r.operation); } catch { corrupt(); }
  const op = r.operation;
  if (op.sender !== r.signer || op.nonce !== r.signerNonce || typedDataHash(op) !== r.typedDataHash
      || userOpHash(op) !== r.userOpHash) corrupt();
  const before = keyList(r.beforeKeys), after = keyList(r.expectedAfterKeys);
  if (!before.some((k) => k.keyId === r.authorizerKeyId)) corrupt();
  const priorityFee = BigInt('0x' + op.gasFees.slice(2, 34)), fee = BigInt('0x' + op.gasFees.slice(34));
  if (fee === 0n || fee > UINT120_MAX || priorityFee > fee) corrupt();
  let change;
  if (after.length === before.length + 1) {
    const added = after.filter((k) => !before.some((b) => b.keyId === k.keyId));
    if (added.length !== 1) corrupt();
    change = { kind: 'add', key: added[0] };
  } else if (after.length === before.length - 1) {
    const removed = before.filter((k) => !after.some((a) => a.keyId === k.keyId));
    if (removed.length !== 1) corrupt();
    change = { kind: 'remove', keyId: removed[0].keyId };
  } else corrupt();
  let plan;
  try { plan = planChange({ signer: r.signer, nonce, keys: before, change, fees: { maxFee: fee, priorityFee } }); }
  catch { corrupt(); }
  if (BODY_KEYS.some((k) => plan.operation[k] !== op[k]) || plan.after.length !== after.length
      || plan.after.some((k, i) => k.keyId !== after[i].keyId || k.publicKey !== after[i].publicKey)) corrupt();
  if ('transactionHash' in r && !isHash(r.transactionHash)) corrupt();
  if ('actualWalletNonce' in r) canonicalUint(r.actualWalletNonce, UINT256_MAX);
  if ('receipt' in r) {
    closed(r.receipt, ['blockNumber', 'blockHash', 'status']);
    canonicalUint(r.receipt.blockNumber, UINT256_MAX);
    if (!isHash(r.receipt.blockHash) || !['0x0', '0x1'].includes(r.receipt.status) || !('transactionHash' in r)) {
      corrupt();
    }
  }
  if ('outcome' in r) {
    closed(r.outcome, ['kind'], ['actualOuterCostWei', 'actualGasCostWei']);
    if (!OUTCOME_KINDS.includes(r.outcome.kind)) corrupt();
    for (const field of ['actualOuterCostWei', 'actualGasCostWei']) {
      if (field in r.outcome) canonicalUint(r.outcome[field], UINT256_MAX);
    }
    if (r.outcome.kind === 'stateResolved' && Object.keys(r.outcome).length !== 1) corrupt();
    if (r.outcome.kind !== 'stateResolved' && !('actualOuterCostWei' in r.outcome)) corrupt();
    if (['succeeded', 'innerFailed', 'sameBlockConflict'].includes(r.outcome.kind) && !('actualGasCostWei' in r.outcome)) {
      corrupt();
    }
    // v2 only: an EntryPoint reimbursement above the signed inner prefund P was never verified evidence.
    if (r.version === 2 && 'actualGasCostWei' in r.outcome && BigInt(r.outcome.actualGasCostWei) > TOTAL_GAS * fee) {
      corrupt();
    }
  }
  const outcome = r.outcome?.kind;
  const expected = { succeeded: 'succeeded', innerFailed: 'innerFailed', outerFailed: 'outerFailed',
    stateResolved: 'stateResolved' }[r.status];
  if (expected ? outcome !== expected : outcome !== undefined && !(r.status === 'uncertain'
      && outcome === 'sameBlockConflict')) corrupt();
  if (['hashKnown', 'confirming', 'succeeded', 'innerFailed', 'outerFailed'].includes(r.status)
      && !('transactionHash' in r)) corrupt();
  if (r.status === 'reserved' && ('transactionHash' in r || 'receipt' in r)) corrupt();
  return r;
}

/** The validated frozen record of canonical bytes, or a thrown `corrupt` StorageError. Null stays null. */
export function parseAttempt(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || utf8Length(raw) > MAX_RECORD_BYTES) corrupt();
  return deepFreeze(validateAttempt(strictParse(raw)));
}
function deepFreeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(deepFreeze); Object.freeze(value); }
  return value;
}

// ---------------------------------------------------------------------------------------------------------------
// Native IndexedDB singleton

export class KeyAttemptStore {
  constructor({ indexedDB }) {
    this.factory = indexedDB;
    this.db = null;
    this.opening = null;
    this.closed = false;
  }

  check(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || JSON.stringify(Object.keys(value).sort()) !== WRAPPER_KEYS || value.version !== DB_VERSION
        || !Number.isSafeInteger(value.revision) || value.revision < 0) corrupt();
    if (value.raw !== null) parseAttempt(value.raw);
    if (value.raw === null && value.revision !== 0) corrupt();
    return Object.freeze({ version: DB_VERSION, revision: value.revision, raw: value.raw });
  }

  open() {
    if (this.closed) return Promise.reject(new StorageError('closed'));
    if (this.db) return Promise.resolve(this.db);
    if (this.opening) return this.opening;
    this.opening = new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error, db) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.opening = null;
        if (error) reject(error); else resolve(db);
      };
      const timer = setTimeout(() => finish(new StorageError('timeout')), STORE_TIMEOUT_MS);
      let request;
      try {
        request = this.factory.open(DB_NAME, DB_VERSION);
      } catch {
        return finish(new StorageError('unavailable'));
      }
      request.onupgradeneeded = (event) => {
        const tx = event.target.transaction;
        // Version 1 is the only version: an upgrade is always first creation. After the deadline it aborts.
        if (settled || event.oldVersion !== 0) {
          try { tx.abort(); } catch { /* already finished */ }
          return;
        }
        try {
          event.target.result.createObjectStore(STORE_NAME)
            .put({ version: DB_VERSION, revision: 0, raw: null }, SINGLETON_KEY);
        } catch {
          try { tx.abort(); } catch { /* already finished */ }
        }
      };
      request.onblocked = () => finish(new StorageError('blocked'));
      request.onerror = (event) => {
        if (event && event.preventDefault) event.preventDefault();
        finish(new StorageError('unavailable'));
      };
      request.onsuccess = (event) => {
        const db = event.target.result;
        if (settled || this.closed) { db.close(); return; }
        const names = Array.from(db.objectStoreNames);
        if (db.version !== DB_VERSION || names.length !== 1 || names[0] !== STORE_NAME) {
          db.close();
          return finish(new StorageError('corrupt'));
        }
        db.onversionchange = () => { db.close(); this.release(); };
        db.onclose = () => this.release();
        this.db = db;
        finish(null, db);
      };
    });
    return this.opening;
  }

  release() { this.closed = true; this.db = null; }

  close() { if (this.db) this.db.close(); this.release(); }

  async transact(mode, work) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let tx;
      let failure = null;
      let value;
      let finished = false;
      let timer = null;
      const done = (error, result) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        if (error) reject(error); else resolve(result);
      };
      try {
        tx = mode === 'readwrite' ? db.transaction(STORE_NAME, 'readwrite', { durability: 'strict' })
          : db.transaction(STORE_NAME, 'readonly');
      } catch {
        return reject(new StorageError(this.closed ? 'closed' : 'unavailable'));
      }
      const abort = (error) => {
        const prior = failure;
        failure = failure || error;
        try { tx.abort(); } catch { failure = prior; }
      };
      tx.oncomplete = () => (failure ? done(failure) : done(null, value));
      tx.onabort = () => done(failure || new StorageError('aborted'));
      tx.onerror = (event) => {
        if (event && event.preventDefault) event.preventDefault();
        failure = failure || new StorageError('aborted');
      };
      timer = setTimeout(() => abort(new StorageError('timeout')), STORE_TIMEOUT_MS);
      if (mode === 'readwrite' && tx.durability !== 'strict') return abort(new StorageError('durability'));
      try {
        const store = tx.objectStore(STORE_NAME);
        const get = store.get(SINGLETON_KEY);
        get.onsuccess = () => {
          try {
            if (get.result === undefined) corrupt();
            value = work(this.check(get.result), store);
          } catch (error) {
            abort(error instanceof StorageError ? error : new StorageError('aborted'));
          }
        };
      } catch {
        abort(new StorageError('aborted'));
      }
    });
  }

  /** Latest validated singleton, read-only. */
  read() { return this.transact('readonly', (current) => current); }

  /**
   * Conditional write of `nextRaw` (a valid canonical record, never null) when the row still has exactly
   * `expected.revision` and `expected.raw`. `{committed:true, snapshot}` only after `complete`; `{committed:false,
   * snapshot}` with the valid conflicting row otherwise.
   */
  async compareAndSet(expected, nextRaw) {
    try { parseAttempt(nextRaw); } catch { throw new StorageError('invalid'); }
    if (nextRaw === null || !expected || !Number.isSafeInteger(expected.revision) || expected.revision < 0
        || (expected.raw !== null && typeof expected.raw !== 'string')) throw new StorageError('invalid');
    if (expected.revision >= Number.MAX_SAFE_INTEGER) throw new StorageError('exhausted');
    return this.transact('readwrite', (current, store) => {
      if (current.revision !== expected.revision || current.raw !== expected.raw) {
        return { committed: false, snapshot: current };
      }
      const next = { version: DB_VERSION, revision: current.revision + 1, raw: nextRaw };
      store.put(next, SINGLETON_KEY);
      return { committed: true, snapshot: Object.freeze(next) };
    });
  }
}
