// Unsigned comparison evidence only. Never restores permission or sends anything.
import { buildRequest, validateContext } from './safe-request-model.js';
import { PURPOSE, TOTAL_GAS, UINT120_MAX, UINT64_MAX, isDecimal, isPoint, isUUID, planChange, sameKeys,
  sortedKeys, validateNativeContext, buildRequest as buildKeyRequest } from './key-model.js';
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const uint = (v, max) => { if (!isDecimal(v) || BigInt(v) > max) fail(); return BigInt(v); };
function keyList(list) {
  if (!Array.isArray(list) || list.length < 1 || list.length > 64) fail();
  list.forEach((k) => closed(k, ['keyId', 'publicKey']));
  const sorted = sortedKeys(list);
  if (!sameKeys(sorted, list)) fail();
  return sorted;
}
function validateKey(r, e) {
  const x = r.expected;
  closed(x, ['anchor', 'operation', 'beforeKeys', 'expectedAfterKeys', 'maxGasUnits', 'maxFeePerGas']);
  closed(x.anchor, ['signerAddress', 'keyId', 'publicKey']);
  if (!isPoint(x.anchor.publicKey)) fail();
  const c = validateNativeContext(r.context, x.anchor);
  const before = keyList(x.beforeKeys), after = keyList(x.expectedAfterKeys);
  if (!sameKeys(before, c.keys) || x.operation.nonce !== r.context.nonce || x.operation.sender !== c.signer
      || uint(x.maxGasUnits, UINT64_MAX) !== TOTAL_GAS || c.maxGasUnits < TOTAL_GAS) fail();
  const max = uint(x.maxFeePerGas, UINT120_MAX);
  const op = x.operation;
  if (typeof op.gasFees !== 'string' || !/^0x[0-9a-f]{64}$/.test(op.gasFees)) fail();
  const priorityFee = BigInt('0x' + op.gasFees.slice(2, 34)), maxFee = BigInt('0x' + op.gasFees.slice(34));
  if (max === 0n || maxFee === 0n || maxFee > max || maxFee > c.maxFeePerGas || priorityFee > maxFee) fail();
  let change;
  if (after.length === before.length + 1) {
    const added = after.filter((k) => !before.some((b) => b.keyId === k.keyId));
    if (added.length !== 1) fail();
    change = { kind: 'add', key: added[0] };
  } else if (after.length === before.length - 1) {
    const removed = before.filter((k) => !after.some((a) => a.keyId === k.keyId));
    if (removed.length !== 1) fail();
    change = { kind: 'remove', keyId: removed[0].keyId };
  } else fail();
  const plan = planChange({ signer: c.signer, nonce: c.nonce, keys: before, change, fees: { maxFee, priorityFee } });
  if (!sameKeys(plan.after, after) || !same(plan.operation, op)) fail();
  return buildKeyRequest({ context: c, operation: op, id: r.requestId, issuedAt: Number(e.issuedAt) });
}

export const DB_NAME = 'p256-saved-result-recovery-v1';
export const DB_VERSION = 1;
export const STORE_NAME = 'requests';
export const MAX_RECORD_BYTES = 65536;
export const STORE_TIMEOUT_MS = 5000;
const SAFE = 'safe-tx-v1.5.0';
export class StorageError extends Error {
  constructor(code) { super(`saved-result storage ${code}`); this.name = 'StorageError'; this.code = code; }
}
const fail = (code = 'corrupt') => { throw new StorageError(code); };
const bytes = (text) => new TextEncoder().encode(text).length;
function closed(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join() !== [...keys].sort().join()) fail();
}
function validate(r) {
  closed(r, ['version', 'purpose', 'requestId', 'envelope', 'context', 'expected']);
  if (r.version !== 1 || ![SAFE, PURPOSE].includes(r.purpose) || !isUUID(r.requestId)
      || typeof r.envelope !== 'string' || bytes(r.envelope) > 32768) fail();
  const e = JSON.parse(r.envelope);
  const issuedAt = Number(e.issuedAt), expiresAt = Number(e.expiresAt);
  if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt) || expiresAt - issuedAt !== 120) fail();
  let rebuilt;
  if (r.purpose === SAFE) {
    // A non-Polygon authority carries its own closed `chainId`; the legacy Polygon shape has none.
    closed(r.expected, ['origin', 'safe', 'signer', 'publicKey', 'keyId', 'recipient', 'value', 'nonce',
      ...('chainId' in r.expected ? ['chainId'] : [])]);
    if (!isPoint(r.expected.publicKey)) fail();
    validateContext(r.context, r.expected);
    rebuilt = buildRequest(r.context, r.expected, r.requestId, Number(e.issuedAt));
  } else rebuilt = validateKey(r, e);
  if (rebuilt.envelope !== r.envelope) fail();
  return r;
}
export function serializeRecord(record) {
  try {
    validate(record);
    const raw = JSON.stringify(record);
    if (typeof raw !== 'string' || bytes(raw) > MAX_RECORD_BYTES) fail();
    validate(JSON.parse(raw));
    return raw;
  } catch { fail(); }
}
export function parseRecord(raw) {
  if (typeof raw !== 'string' || bytes(raw) > MAX_RECORD_BYTES) fail();
  try {
    const record = JSON.parse(raw);
    if (serializeRecord(record) !== raw) fail();
    return record;
  } catch { fail(); }
}
function stored(raw, id) {
  const r = parseRecord(raw);
  if (!same(key(r.purpose, r.requestId), id)) fail();
  return r;
}
function key(purpose, requestId) {
  if (![SAFE, PURPOSE].includes(purpose) || typeof requestId !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(requestId)) fail('invalid');
  return [purpose, requestId];
}
export class SavedResultStore {
  constructor({ indexedDB = globalThis.indexedDB } = {}) {
    this.factory = indexedDB;
    this.db = null;
    this.opening = null;
    this.closed = false;
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
        if (error) reject(error); else resolve(db);
      };
      const timer = setTimeout(() => finish(new StorageError('timeout')), STORE_TIMEOUT_MS);
      let request;
      try { request = this.factory.open(DB_NAME, DB_VERSION); }
      catch { return finish(new StorageError('unavailable')); }
      request.onupgradeneeded = (event) => {
        if (settled || event.oldVersion !== 0 || this.closed) { request.transaction.abort(); return; }
        request.result.createObjectStore(STORE_NAME);
      };
      request.onerror = () => finish(new StorageError(request.error?.name === 'VersionError' ? 'corrupt' : 'unavailable'));
      request.onblocked = () => finish(new StorageError('blocked'));
      request.onsuccess = () => {
        const db = request.result;
        if (settled || this.closed) { db.close(); return finish(new StorageError('closed')); }
        if (db.version !== DB_VERSION || db.objectStoreNames.length !== 1 || db.objectStoreNames[0] !== STORE_NAME) {
          db.close(); return finish(new StorageError('corrupt'));
        }
        const store = db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME);
        if (store.keyPath !== null || store.autoIncrement || store.indexNames.length !== 0) {
          db.close(); return finish(new StorageError('corrupt'));
        }
        db.onversionchange = () => this.close();
        this.opening = null;
        db.onclose = () => { this.closed = true; this.db = null; };
        this.db = db;
        finish(null, db);
      };
    });
    return this.opening;
  }
  close() { this.closed = true; this.db?.close(); this.db = null; }
  async transact(mode, work) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let tx, value, failure, timer;
      try {
        tx = mode === 'readwrite' ? db.transaction(STORE_NAME, mode, { durability: 'strict' }) : db.transaction(STORE_NAME, mode);
      } catch { return reject(new StorageError(this.closed ? 'closed' : 'unavailable')); }
      const abort = (error) => {
        failure ||= error instanceof StorageError ? error : new StorageError('aborted');
        try { tx.abort(); } catch { /* completion already queued */ }
      };
      tx.oncomplete = () => { clearTimeout(timer); failure ? reject(failure) : resolve(value); };
      tx.onabort = () => { clearTimeout(timer); reject(failure || new StorageError('aborted')); };
      tx.onerror = (event) => { event.preventDefault(); abort(new StorageError('aborted')); };
      timer = setTimeout(() => abort(new StorageError('timeout')), STORE_TIMEOUT_MS);
      if (mode === 'readwrite' && tx.durability !== 'strict') return abort(new StorageError('durability'));
      try { work(tx.objectStore(STORE_NAME), (result) => { value = result; }, abort); }
      catch (error) { abort(error); }
    });
  }
  async save(record) {
    let raw;
    try { raw = serializeRecord(record); } catch { fail('invalid'); }
    const r = parseRecord(raw), id = key(r.purpose, r.requestId);
    return this.transact('readwrite', (store, done, abort) => {
      const get = store.get(id);
      get.onsuccess = () => {
        try {
          if (get.result !== undefined) {
            stored(get.result, id);
            if (get.result !== raw) fail('conflict');
          } else store.add(raw, id);
          done(r);
        } catch (error) { abort(error); }
      };
    });
  }
  async remove(record, { acknowledged } = {}) {
    if (acknowledged !== true) fail('acknowledgement');
    let raw;
    try { raw = serializeRecord(record); } catch { fail('invalid'); }
    const r = parseRecord(raw), id = key(r.purpose, r.requestId);
    return this.transact('readwrite', (store, done, abort) => {
      const get = store.get(id);
      get.onsuccess = () => {
        try {
          if (get.result === undefined) fail('conflict');
          stored(get.result, id);
          if (get.result !== raw) fail('conflict');
          store.delete(id);
          done(true);
        } catch (error) { abort(error); }
      };
    });
  }
  read(purpose, requestId) {
    const id = key(purpose, requestId);
    return this.transact('readonly', (store, done, abort) => {
      const get = store.get(id);
      get.onsuccess = () => {
        try { done(get.result === undefined ? null : stored(get.result, id)); } catch (error) { abort(error); }
      };
    });
  }
  list() {
    return this.transact('readonly', (store, done, abort) => {
      const result = [], cursor = store.openCursor();
      cursor.onsuccess = () => {
        try {
          const row = cursor.result;
          if (!row) { done(result); return; }
          const r = parseRecord(row.value);
          if (JSON.stringify(row.key) !== JSON.stringify(key(r.purpose, r.requestId))) fail();
          result.push(r);
          row.continue();
        } catch (error) { abort(error); }
      };
    });
  }
}
