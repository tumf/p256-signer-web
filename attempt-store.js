// Transactional authority per Signer address. The v1 `current` row is retained as read-only bootstrap evidence;
// each `signer:<address>` wrapper `{version:1, revision, raw, legacyRaw}` compares revision and exact bytes inside the same
// strict-durability readwrite transaction that writes revision+1. `raw:null` is a retained tombstone. The old
// localStorage key is read-only legacy input: imported only when the database is first created, never written.
// `raw` is exact v1 (historical frozen-ceiling) or v2 (wallet-delegated) attempt JSON; the legacy key only ever held
// v1, so bootstrap accepts v1 bytes alone. Bytes are untrusted; the revision is concurrency control, not
// authentication. No fallback store exists and no record is migrated or rewritten.
// enable-multichain-operations: a scope is one closed chain and one address. Polygon keeps the exact legacy
// `signer:<address>` / `initialized:<address>` rows; another chain uses `signer:<chainId>:<address>` /
// `initialized:<chainId>:<address>`, never imports the (Polygon-only) legacy row, and every row or write of a scope must
// be a record of exactly that chain and address, so the same address on another chain is never this attempt.
import { POLYGON, chainOfId } from './chains.js';

export const DB_NAME = 'p256.registration.attempts';
export const DB_VERSION = 2;
const WRAPPER_VERSION = 1; // Existing wrapper bytes stay unchanged during the address-key upgrade.
export const STORE_NAME = 'state';
export const SINGLETON_KEY = 'current';
export const LEGACY_KEY = 'p256.registration.attempt.v1';
export const STORE_TIMEOUT_MS = 5000;
export const MAX_STORED_BYTES = 16384;

const WRAPPER_KEYS = '["legacyRaw","raw","revision","version"]';

export const STORAGE_MESSAGES = {
  unavailable: 'このブラウザの保存領域を使えないため、送信記録を確認・保存できません。送信できません。',
  legacy: '以前の送信記録（この端末の旧形式）を検証できないか、内容が変わっています。記録は変更していません。新しい送信はできません。',
};

/** Bounded storage failure; `code` is one of the fixed values below, the message is fixed plain text. */
export class StorageError extends Error {
  constructor(code) {
    super(code === 'legacy-conflict' ? STORAGE_MESSAGES.legacy : STORAGE_MESSAGES.unavailable);
    this.name = 'StorageError';
    // unavailable | timeout | blocked | closed | durability | corrupt | legacy-conflict | exhausted | aborted | invalid
    this.code = code;
  }
}

function bounded(text) {
  return typeof text === 'string' && new TextEncoder().encode(text).length <= MAX_STORED_BYTES;
}

/** The old localStorage key predates v2: only a version-1 record may ever be imported from it. */
function legacyVersion(text) {
  try { return JSON.parse(text).version === 1; } catch { return false; }
}

export class AttemptStore {
  /**
   * @param {object} deps
   * @param {IDBFactory} deps.indexedDB  native browser factory (no fake fallback in production)
   * @param {() => (string|null)} deps.readLegacy  synchronous read-only legacy accessor (may throw)
   * @param {(text: string) => (object|null)} deps.validateRecord  the exact discriminated v1/v2 attempt validator
   */
  constructor({ indexedDB, readLegacy, validateRecord, address = null, chain = POLYGON }) {
    if (address !== null && !/^0x[0-9a-fA-F]{40}$/.test(address)) throw new StorageError('invalid');
    if (chainOfId(chain?.id) !== chain || (address === null && chain !== POLYGON)) throw new StorageError('invalid');
    this.address = address && address.toLowerCase();
    this.chain = chain;
    this.factory = indexedDB;
    this.readLegacy = readLegacy;
    this.validateRecord = validateRecord;
    this.db = null;
    this.opening = null;
    this.closed = false;
  }

  forAddress(address, chain = POLYGON) {
    return new this.constructor({ indexedDB: this.factory, readLegacy: this.readLegacy,
      validateRecord: this.validateRecord, address, chain });
  }

  /** The row key of this scope: Polygon keeps the legacy `<prefix>:<address>`; another chain is its own scope. */
  scopeKey(prefix) {
    return this.chain === POLYGON ? `${prefix}:${this.address}` : `${prefix}:${this.chain.id}:${this.address}`;
  }

  /** Whether a validated record belongs to exactly this scope's chain and address. */
  owns(record) {
    return record.address.toLowerCase() === this.address && record.chainId === this.chain.id;
  }

  /** The exact validated wrapper or a thrown `corrupt` error; a raw record must pass the v1/v2 validator. */
  check(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || JSON.stringify(Object.keys(value).sort()) !== WRAPPER_KEYS || value.version !== WRAPPER_VERSION
        || !Number.isSafeInteger(value.revision) || value.revision < 0) throw new StorageError('corrupt');
    if (value.raw !== null && (!bounded(value.raw) || !this.validateRecord(value.raw))) throw new StorageError('corrupt');
    if (value.legacyRaw !== null && !bounded(value.legacyRaw)) throw new StorageError('corrupt');
    return Object.freeze({ version: WRAPPER_VERSION, revision: value.revision, raw: value.raw, legacyRaw: value.legacyRaw });
  }

  /** Validated v1 legacy text for first creation; anything unreadable, invalid or v2 refuses bootstrap. */
  bootstrapLegacy() {
    let text;
    try { text = this.readLegacy(); } catch { return undefined; }
    if (text === null || text === undefined) return null;
    return bounded(text) && this.validateRecord(text) && legacyVersion(text) ? text : undefined;
  }

  /** Opens (once) with a bounded deadline. A late success after a reported failure only closes itself. */
  open() {
    if (this.closed) return Promise.reject(new StorageError('closed'));
    if (this.db) return Promise.resolve(this.db);
    if (this.opening) return this.opening;
    this.opening = new Promise((resolve, reject) => {
      let settled = false;
      let legacyRefused = false;
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
        // Version 2 closes old singleton-only clients; existing state is preserved byte-for-byte.
        if (event.oldVersion === 1 && !settled) return;
        const legacy = settled ? undefined : this.bootstrapLegacy();
        if (legacy === undefined || event.oldVersion !== 0) {
          legacyRefused = !settled && event.oldVersion === 0;
          try { tx.abort(); } catch { /* already finished */ }
          return;
        }
        try {
          const store = event.target.result.createObjectStore(STORE_NAME);
          store.put({ version: WRAPPER_VERSION, revision: 0, raw: legacy, legacyRaw: legacy }, SINGLETON_KEY);
        } catch {
          try { tx.abort(); } catch { /* already finished */ }
        }
      };
      request.onblocked = () => finish(new StorageError('blocked'));
      request.onerror = (event) => {
        if (event && event.preventDefault) event.preventDefault();
        finish(new StorageError(legacyRefused ? 'legacy-conflict' : 'unavailable'));
      };
      request.onsuccess = (event) => {
        const db = event.target.result;
        if (settled || this.closed) { db.close(); return; }
        const names = Array.from(db.objectStoreNames);
        if (db.version !== DB_VERSION || names.length !== 1 || names[0] !== STORE_NAME) {
          db.close();
          return finish(new StorageError('corrupt'));
        }
        // Another (newer) version or a deletion wants the database: release it and refuse further mutations.
        db.onversionchange = () => { db.close(); this.release(); };
        db.onclose = () => this.release();
        this.db = db;
        finish(null, db);
      };
    });
    return this.opening;
  }

  release() {
    this.closed = true;
    this.db = null;
  }

  /** Closes this page's connection; later calls fail closed. */
  close() {
    if (this.db) this.db.close();
    this.release();
  }

  /**
   * One transaction over the legacy guard and selected row. `work(current, store, key)` returns the
   * value to resolve on `complete`. Committed state is reported only from `oncomplete`; abort/error/timeout reject.
   */
  async transact(mode, work, initialize = false) {
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
      /** Aborts an active transaction; one already committing keeps reporting its real outcome. */
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
      // A browser that cannot honour strict durability fails closed instead of silently downgrading.
      if (mode === 'readwrite' && tx.durability !== 'strict') return abort(new StorageError('durability'));
      let store;
      try {
        store = tx.objectStore(STORE_NAME);
        const get = store.get(SINGLETON_KEY);
        get.onsuccess = () => {
          try {
            if (get.result === undefined) throw new StorageError('corrupt');
            const legacy = this.check(get.result);
            if (!this.address) { value = work(legacy, store, SINGLETON_KEY); return; }
            const record = legacy.raw === null ? null : this.validateRecord(legacy.raw).record;
            const key = this.scopeKey('signer');
            const apply = (row) => {
              const current = this.check(row);
              if (current.raw !== null && !this.owns(this.validateRecord(current.raw).record)) {
                throw new StorageError('corrupt');
              }
              // Legacy provenance remains a global guard, even for an empty address row.
              if (mode === 'readwrite') {
                let text;
                try { text = this.readLegacy(); } catch { throw new StorageError('legacy-conflict'); }
                if (text !== null && text !== undefined && text !== legacy.legacyRaw) throw new StorageError('legacy-conflict');
              }
              value = work(Object.freeze({ ...current, key }), store, key);
            };
            const scoped = store.get(key);
            scoped.onsuccess = () => {
              const markerKey = this.scopeKey('initialized');
              const marker = store.get(markerKey);
              marker.onsuccess = () => {
                try {
                  const missing = scoped.result === undefined;
                  if (marker.result === undefined && missing && initialize) {
                    const initial = record && this.owns(record) ? legacy
                      : { version: WRAPPER_VERSION, revision: 0, raw: null, legacyRaw: legacy.legacyRaw };
                    apply(initial);
                    store.add(initial, key);
                    store.add(true, markerKey);
                  } else {
                    // A missing established row is data loss, not an empty address or permission to reimport.
                    if (marker.result !== true || missing) throw new StorageError('corrupt');
                    apply(scoped.result);
                  }
                } catch (error) { abort(error instanceof StorageError ? error : new StorageError('aborted')); }
              };
            };
          } catch (error) {
            abort(error instanceof StorageError ? error : new StorageError('aborted'));
          }
        };
      } catch {
        abort(new StorageError('aborted'));
      }
    });
  }

  /** Latest validated authority, read-only. Scoped rows must have been initialized by load(). */
  read() {
    return this.transact('readonly', (current) => current);
  }

  /**
   * Startup read. `legacyConflict` is true when the readable legacy key differs from the imported provenance or
   * cannot be read. A scoped first load atomically retains its initial row and initialization marker; later
   * missing rows fail closed. An absent legacy key never clears or replaces the IDB row.
   */
  async load() {
    const snapshot = this.address ? await this.transact('readwrite', (current) => current, true) : await this.read();
    let legacyConflict = false;
    try {
      const text = this.readLegacy();
      legacyConflict = text !== null && text !== undefined && text !== snapshot.legacyRaw;
    } catch {
      legacyConflict = true;
    }
    return { snapshot, legacyConflict };
  }

  /**
   * Conditional write of `nextRaw` (exact v1/v2 JSON or null tombstone) when the row still has `expected.revision`
   * and exactly `expected.raw`. Returns `{committed:true, snapshot}` after `complete`, or `{committed:false,
   * snapshot}` with the valid conflicting row. A new claim over an empty slot rechecks the legacy provenance.
   */
  async compareAndSet(expected, nextRaw) {
    if (nextRaw !== null && (!bounded(nextRaw) || !this.validateRecord(nextRaw))) throw new StorageError('invalid');
    if (!expected || !Number.isSafeInteger(expected.revision) || expected.revision < 0
        || (expected.raw !== null && typeof expected.raw !== 'string')) throw new StorageError('invalid');
    if (expected.revision >= Number.MAX_SAFE_INTEGER) throw new StorageError('exhausted');
    if (this.address && nextRaw !== null && !this.owns(this.validateRecord(nextRaw).record)) {
      throw new StorageError('invalid');
    }
    return this.transact('readwrite', (current, store, key) => {
      if (this.address && expected.key !== key) throw new StorageError('invalid');
      if (current.revision !== expected.revision || current.raw !== expected.raw) {
        return { committed: false, snapshot: current };
      }
      if (current.revision >= Number.MAX_SAFE_INTEGER) throw new StorageError('exhausted');
      if (nextRaw !== null && current.raw === null) {
        let legacy;
        try { legacy = this.readLegacy(); } catch { throw new StorageError('legacy-conflict'); }
        if (legacy !== null && legacy !== undefined && legacy !== current.legacyRaw) {
          throw new StorageError('legacy-conflict');
        }
      }
      const next = { version: WRAPPER_VERSION, revision: current.revision + 1, raw: nextRaw, legacyRaw: current.legacyRaw };
      store.put(next, key);
      return { committed: true, snapshot: Object.freeze(this.address ? { ...next, key } : next) };
    });
  }
}
