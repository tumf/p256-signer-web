// Test-only in-memory IDBFactory double for Node: the IndexedDB event shapes KeyAttemptStore uses (open with
// upgradeneeded/success, one object store, readwrite with durability, get/put/add, oncomplete/onabort). Writes apply on
// commit only. It is NOT browser storage and never cross-tab or durability evidence; Chromium tests own that.
// `control.readwrite` scripts every later readwrite transaction: 'commit' (default), 'hang' (never completes on its
// own, so only the store's deadline abort ends it) or 'abort' / 'error' (aborted, or an error event then abort, in
// place of commit). Reads are unaffected, and pending writes of a hung or aborted transaction are discarded. Like
// IndexedDB auto-commit, a transaction finishes only after every request it issued has delivered its callback, so an
// event-loop stall between scheduling the commit and the read can never complete it early with no result.
export function memoryIndexedDB({ durability = 'strict' } = {}) {
  const databases = new Map();
  const control = { readwrite: 'commit' };
  const later = (fn) => setTimeout(fn, 0);
  return {
    databases, control,
    open(name, version) {
      const request = {};
      later(() => {
        let data = databases.get(name);
        const fresh = !data;
        if (fresh) data = { version, stores: new Map() };
        const db = {
          version, onversionchange: null, onclose: null,
          get objectStoreNames() { return [...data.stores.keys()]; },
          createObjectStore(store) { data.stores.set(store, new Map()); return storeFor(data.stores.get(store), null); },
          close() {},
          transaction(store, mode, options = {}) { return transaction(data, store, mode, options); },
        };
        if (fresh) {
          const tx = { aborted: false, abort() { this.aborted = true; } };
          request.onupgradeneeded?.({ oldVersion: 0, target: { result: db, transaction: tx } });
          if (tx.aborted) return request.onerror?.({ preventDefault() {} });
          databases.set(name, data);
        }
        request.onsuccess?.({ target: { result: db } });
      });
      return request;
    },
  };

  function storeFor(map, pending, tx = null) {
    return {
      get(key) {
        const request = {};
        if (tx) tx.outstanding++;
        later(() => {
          request.result = structuredClone(map.get(key));
          request.onsuccess?.();
          if (tx) { tx.outstanding--; tx.settle(); }
        });
        return request;
      },
      put(value, key) {
        if (pending) pending.push([key, structuredClone(value)]);
        else map.set(key, structuredClone(value));
      },
      // IndexedDB `add`: like put, but an existing (committed or pending) key is a ConstraintError.
      add(value, key) {
        if (map.has(key) || (pending && pending.some(([k]) => k === key))) throw new Error('ConstraintError');
        this.put(value, key);
      },
    };
  }

  function transaction(data, name, mode, options) {
    const pending = [];
    const map = data.stores.get(name);
    const tx = {
      durability: mode === 'readwrite' ? (options.durability === 'strict' ? durability : 'default') : 'default',
      oncomplete: null, onabort: null, onerror: null, done: false, outstanding: 0, due: false,
      objectStore() { return storeFor(map, mode === 'readwrite' ? pending : null, tx); },
      settle() { if (tx.due && tx.outstanding === 0) later(finish); },
      abort() {
        if (tx.done) throw new Error('InvalidStateError');
        tx.done = true;
        later(() => tx.onabort?.());
      },
    };
    const script = mode === 'readwrite' ? control.readwrite : 'commit';
    if (script === 'hang') return tx;
    // Commit (or the scripted failure) once due and after every issued request's callback has run.
    const finish = () => {
      if (tx.done || tx.outstanding > 0) return;
      tx.done = true;
      if (script === 'abort' || script === 'error') {
        if (script === 'error') tx.onerror?.({ preventDefault() {} });
        tx.onabort?.();
        return;
      }
      for (const [key, value] of pending) map.set(key, value);
      tx.oncomplete?.();
    };
    setTimeout(() => { tx.due = true; tx.settle(); }, 5);
    return tx;
  }
}
