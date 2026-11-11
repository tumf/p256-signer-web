// Transactional authority for the one current EntryPoint funding attempt: a dedicated native IndexedDB singleton
// `{version:1, revision, raw}` (raw: canonical attempt JSON or null before the first reservation) in its own database
// `p256.entrypoint-prefund.attempts`. Every update compares the exact revision and bytes inside the same
// strict-durability readwrite transaction that writes revision+1; completion is reported only from `oncomplete`. The
// transaction algorithm is key-attempt-store.js's, copied minimally; the deployment and key-change databases, schemas
// and data are untouched. No fallback store, no clear, no migration. The record is public lookup identity only.
// The wrapper/database version stays 1 and is not the record version: `raw` is a canonical v1 (historical, read-only
// recovery) or v2 record, admitted only by the closed version-dispatched parser; nothing is upgraded or rewritten on load.
// This coordinates this origin/browser profile's cooperating tabs only, not other profiles or devices.
import { PrefundError, parseFundingAttempt as parseRecord } from './prefund-model.js';

export const DB_NAME = 'p256.entrypoint-prefund.attempts';
export const DB_VERSION = 1;
export const STORE_NAME = 'state';
export const SINGLETON_KEY = 'current';
export const STORE_TIMEOUT_MS = 5000;
const WRAPPER_KEYS = '["raw","revision","version"]';

/** unavailable | timeout | blocked | closed | durability | corrupt | aborted | invalid | exhausted. */
export class StorageError extends Error {
  constructor(code) {
    super(`prefund storage ${code}`);
    this.name = 'StorageError';
    this.code = code;
  }
}
const corrupt = () => { throw new StorageError('corrupt'); };

/** The validated frozen record, or a thrown `corrupt` StorageError. */
export function parseFundingAttempt(raw) {
  try { return parseRecord(raw); } catch (error) { if (error instanceof PrefundError) corrupt(); throw error; }
}

// ---------------------------------------------------------------------------------------------------------------
// Native IndexedDB singleton

export class FundingAttemptStore {
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
    if (value.raw !== null) parseFundingAttempt(value.raw);
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
    try { parseFundingAttempt(nextRaw); } catch { throw new StorageError('invalid'); }
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
