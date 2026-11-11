// Native Chromium IndexedDB, not fake-indexeddb. Loopback-only; no signing, wallet or relay.
// Run: node --test tests/saved-result-store.test.mjs
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import http from 'node:http';
import { build } from 'esbuild';
import { chromium } from 'playwright';
import { v, expected } from './support/safe-fixtures.mjs';

const safe = () => ({ version: 1, purpose: 'safe-tx-v1.5.0', requestId: JSON.parse(v.request.envelope).id,
  envelope: v.request.envelope, context: structuredClone(v.context.result), expected: structuredClone(expected) });
import { contextWire } from './support/key-fixtures.mjs';
import { planChange, buildRequest as keyRequest, TOTAL_GAS } from '../key-model.js';
const publicKey = v.context.result.publicKey, keyId = v.context.result.keyId;
// Public points only, no key generation or signing.
const otherPoint = '0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5';
import { keyIdOf } from '../key-model.js';
function keyRecord() {
  const signer = v.context.result.signer.toLowerCase(), key = { publicKey, keyId };
  const plan = planChange({ signer, nonce: 7n, keys: [key], change: { kind: 'add', key: { publicKey: otherPoint, keyId: keyIdOf(otherPoint) } },
    fees: { maxFee: 100n, priorityFee: 1n } });
  const context = contextWire({ signer, key, binding: '0x' + '12'.repeat(32),
    chain: { nonce: 7n, blockNumber: 100n, blockHash: '0x' + '34'.repeat(32), keys: [key] } });
  const r = keyRequest({ context, operation: plan.operation, id: safe().requestId, issuedAt: 1700000000 });
  return { version: 1, purpose: context.purpose, requestId: r.id, envelope: r.envelope, context,
    expected: { anchor: { signerAddress: signer, keyId, publicKey }, operation: plan.operation, beforeKeys: plan.before,
      expectedAfterKeys: plan.after, maxGasUnits: TOTAL_GAS.toString(), maxFeePerGas: '500' } };
}
let browser, server, origin;
before(async () => {
  const bundle = await build({ stdin: { contents: "export * from './saved-result-store.js';", resolveDir: new URL('..', import.meta.url).pathname },
    bundle: true, format: 'iife', globalName: 'Recovery', write: false, platform: 'browser', logLevel: 'silent' });
  server = http.createServer((req, res) => {
    res.setHeader('Content-Type', req.url === '/store.js' ? 'text/javascript' : 'text/html');
    res.end(req.url === '/store.js' ? bundle.outputFiles[0].text : '<script src="/store.js"></script>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_EXECUTABLE_PATH });
});
after(async () => { await browser?.close(); if (server) await new Promise((resolve) => server.close(resolve)); });
async function pages(t, count = 1) {
  const context = await browser.newContext();
  t.after(() => context.close());
  await context.route('**/*', (route) => route.request().url().startsWith(origin + '/') ? route.continue() : route.abort());
  await context.routeWebSocket(/.*/, (socket) => socket.close());
  return Promise.all(Array.from({ length: count }, async () => { const page = await context.newPage(); await page.goto(origin); return page; }));
}

test('native: durably save exact unsigned Safe record, reload, and read without any session', async (t) => {
  const [page] = await pages(t);
  const record = safe();
  assert.deepEqual(await page.evaluate(async (r) => {
    const s = new Recovery.SavedResultStore({ indexedDB });
    const saved = await s.save(r);
    s.close();
    return saved;
  }, record), record);
  await page.reload();
  assert.deepEqual(await page.evaluate(async (r) => {
    const s = new Recovery.SavedResultStore({ indexedDB });
    const found = await s.read(r.purpose, r.requestId);
    const list = await s.list();
    s.close();
    return { found, list };
  }, record), { found: record, list: [record] });
});

test('native: closed key-change record retains independent operation, full key maps and public anchors', async (t) => {
  const [page] = await pages(t);
  const record = keyRecord();
  assert.deepEqual(await page.evaluate(async (r) => {
    const s = new Recovery.SavedResultStore({ indexedDB });
    await s.save(r);
    const found = await s.read(r.purpose, r.requestId);
    s.close(); return found;
  }, record), record);
});

test('native: both purposes reject unknown fields, substituted binding/body, unsigned signature and oversize', async (t) => {
  const [page] = await pages(t);
  const cases = [];
  for (const original of [safe(), keyRecord()]) {
    for (const field of ['signature', 'result', 'topic', 'rpcId', 'pairingURI', 'grant', 'secret']) cases.push({ ...original, [field]: 'forbidden' });
    cases.push({ ...original, version: 2 }, { ...original, envelope: 'é'.repeat(32769) },
      { ...original, expected: { ...original.expected, result: 'forbidden' } },
      { ...original, context: { ...original.context, binding: '0x' + '88'.repeat(32) } },
      { ...original, envelope: original.envelope.replace('"issuedAt":', '"issuedAt":"1","issuedAt":') });
  }
  const k = keyRecord();
  const overflow = keyRecord();
  const oldTime = JSON.parse(overflow.envelope).issuedAt;
  overflow.envelope = overflow.envelope.replace(oldTime, String(Number.MAX_SAFE_INTEGER))
    .replace(JSON.parse(overflow.envelope).expiresAt, String(Number.MAX_SAFE_INTEGER + 120));
  cases.push(overflow);
  cases.push({ ...k, expected: { ...k.expected, maxFeePerGas: '0' } },
    { ...k, expected: { ...k.expected, maxGasUnits: '1' } },
    { ...k, expected: { ...k.expected, beforeKeys: [] } },
    { ...k, expected: { ...k.expected, expectedAfterKeys: k.expected.beforeKeys } },
    { ...k, expected: { ...k.expected, operation: { ...k.expected.operation, signature: '0x12' } } });
  assert.deepEqual(await page.evaluate(async (records) => {
    const s = new Recovery.SavedResultStore({ indexedDB });
    const results = [];
    for (const r of records) { try { await s.save(r); results.push('accepted'); } catch (error) { results.push(error.code); } }
    s.close(); return results;
  }, cases), cases.map(() => 'invalid'));
});

test('native: purpose + requestId separates records; concurrent tabs cannot overwrite immutable bytes', async (t) => {
  const [a, b] = await pages(t, 2);
  const r = safe();
  // Whitespace is semantically immaterial but exact retained envelope bytes must stay immutable.
  const other = { ...r, context: { ...r.context, binding: '0x' + '22'.repeat(32) },
    envelope: r.envelope.replace(r.context.binding, '0x' + '22'.repeat(32)) };
  const save = (p, row) => p.evaluate(async (record) => {
    const s = new Recovery.SavedResultStore({ indexedDB });
    try { await s.save(record); return 'saved'; } catch (e) { return e.code; } finally { s.close(); }
  }, row);
  assert.deepEqual((await Promise.all([save(a, r), save(b, other)])).sort(), ['conflict', 'saved']);
  assert.equal(await save(a, keyRecord()), 'saved');
  const rows = await a.evaluate(async () => { const s = new Recovery.SavedResultStore({ indexedDB }); const r = await s.list(); s.close(); return r; });
  assert.equal(rows.length, 2);
  assert.ok([r.envelope, other.envelope].includes(rows.find((row) => row.purpose === r.purpose).envelope));
});

test('native: deletion requires explicit acknowledgement and exact immutable bytes', async (t) => {
  const [page] = await pages(t);
  assert.deepEqual(await page.evaluate(async (r) => {
    const s = new Recovery.SavedResultStore({ indexedDB }); await s.save(r);
    const results = [];
    for (const ack of [undefined, false, 'true']) {
      try { await s.remove(r, { acknowledged: ack }); results.push('deleted'); } catch (e) { results.push(e.code); }
    }
    const changed = { ...r, context: { ...r.context, binding: '0x' + '22'.repeat(32) },
      envelope: r.envelope.replace(r.context.binding, '0x' + '22'.repeat(32)) };
    try { await s.remove(changed, { acknowledged: true }); } catch (e) { results.push(e.code); }
    results.push((await s.list()).length);
    await s.remove(r, { acknowledged: true }); results.push(await s.read(r.purpose, r.requestId));
    s.close(); return results;
  }, safe()), ['acknowledgement', 'acknowledgement', 'acknowledgement', 'conflict', 1, null]);
});

test('native: missing row is distinct from unavailable storage; repeated same bytes are idempotent', async (t) => {
  const [page] = await pages(t);
  assert.deepEqual(await page.evaluate(async (r) => {
    const s = new Recovery.SavedResultStore({ indexedDB });
    const results = [await s.read(r.purpose, r.requestId)];
    await s.save(r); await s.save(r);
    results.push((await s.list()).length);
    try { await s.save({ ...r, grant: undefined }); results.push('accepted'); } catch (e) { results.push(e.code); }
    s.close();
    try { await s.list(); } catch (e) { results.push(e.code); }
    try { await new Recovery.SavedResultStore({ indexedDB: null }).list(); } catch (e) { results.push(e.code); }
    return results;
  }, safe()), [null, 1, 'invalid', 'closed', 'unavailable']);
});

test('native: a valid record at a foreign key is corruption, not replaceable or removable evidence', async (t) => {
  const [page] = await pages(t);
  assert.deepEqual(await page.evaluate(async (r) => {
    const s = new Recovery.SavedResultStore({ indexedDB }); const db = await s.open();
    const foreign = { ...r, requestId: r.requestId.replace(/.$/, '9') };
    foreign.envelope = foreign.envelope.replace(r.requestId, foreign.requestId);
    await new Promise((resolve) => { const tx = db.transaction(Recovery.STORE_NAME, 'readwrite');
      tx.objectStore(Recovery.STORE_NAME).put(JSON.stringify(foreign), [r.purpose, r.requestId]); tx.oncomplete = resolve; });
    const result = [];
    for (const action of [() => s.read(r.purpose, r.requestId), () => s.save(r), () => s.remove(r, { acknowledged: true }), () => s.list()]) {
      try { await action(); result.push('accepted'); } catch (e) { result.push(e.code); }
    }
    s.close(); return result;
  }, safe()), ['corrupt', 'corrupt', 'corrupt', 'corrupt']);
});

test('native: unknown database layouts fail closed without replacing the store', async (t) => {
  for (const layout of ['keyPath', 'autoIncrement', 'index', 'extraStore', 'version']) {
    const [page] = await pages(t);
    assert.equal(await page.evaluate(async (layout) => {
      await new Promise((resolve, reject) => {
        const open = indexedDB.open(Recovery.DB_NAME, layout === 'version' ? 2 : 1);
        open.onupgradeneeded = () => {
          const store = open.result.createObjectStore(Recovery.STORE_NAME, layout === 'keyPath' ? { keyPath: 'id' }
            : layout === 'autoIncrement' ? { autoIncrement: true } : {});
          if (layout === 'index') store.createIndex('foreign', 'id');
          if (layout === 'extraStore') open.result.createObjectStore('foreign');
        };
        open.onsuccess = () => { open.result.close(); resolve(); }; open.onerror = reject;
      });
      const s = new Recovery.SavedResultStore({ indexedDB });
      try { await s.list(); return 'accepted'; } catch (e) { return e.code; } finally { s.close(); }
    }, layout), 'corrupt', layout);
  }
});

// Fault injection wraps real native transactions; it is not an IndexedDB model/mock.
test('native + fault injection: save waits completion, abort after add never reports success, strict durability required', async (t) => {
  const [page] = await pages(t);
  assert.deepEqual(await page.evaluate(async (r) => {
    const results = [];
    for (const mode of ['observe', 'abort', 'relaxed']) {
      const s = new Recovery.SavedResultStore({ indexedDB }); const db = await s.open();
      const native = db.transaction.bind(db); let completed = false;
      db.transaction = (...args) => {
        const tx = native(...(mode === 'relaxed' ? [args[0], args[1], { durability: 'relaxed' }] : args));
        tx.addEventListener('complete', () => { completed = true; });
        if (mode === 'abort') {
          const objectStore = tx.objectStore.bind(tx);
          tx.objectStore = (...names) => {
            const store = objectStore(...names), add = store.add.bind(store);
            store.add = (...values) => { const request = add(...values); request.addEventListener('success', () => tx.abort()); return request; };
            return store;
          };
        }
        return tx;
      };
      const row = { ...r, requestId: r.requestId.replace(/.$/, mode === 'observe' ? '1' : mode === 'abort' ? '2' : '3') };
      row.envelope = row.envelope.replace(r.requestId, row.requestId);
      try { await s.save(row); results.push(completed ? 'completed' : 'early'); } catch (e) { results.push(e.code); }
      db.transaction = native;
      results.push((await s.read(row.purpose, row.requestId)) !== null);
      s.close();
    }
    return results;
  }, safe()), ['completed', true, 'aborted', false, 'durability', false]);
});

test('native: corrupt stored evidence blocks reads, replacement and deletion without modifying bytes', async (t) => {
  const [page] = await pages(t);
  assert.deepEqual(await page.evaluate(async (r) => {
    const s = new Recovery.SavedResultStore({ indexedDB }); const db = await s.open();
    const bad = JSON.stringify({ ...r, version: 99 });
    await new Promise((resolve, reject) => { const tx = db.transaction(Recovery.STORE_NAME, 'readwrite');
      tx.objectStore(Recovery.STORE_NAME).put(bad, [r.purpose, r.requestId]); tx.oncomplete = resolve; tx.onabort = reject; });
    const results = [];
    for (const action of [() => s.read(r.purpose, r.requestId), () => s.list(), () => s.save(r), () => s.remove(r, { acknowledged: true })]) {
      try { await action(); results.push('accepted'); } catch (e) { results.push(e.code); }
    }
    const raw = await new Promise((resolve) => { const get = db.transaction(Recovery.STORE_NAME).objectStore(Recovery.STORE_NAME).get([r.purpose, r.requestId]); get.onsuccess = () => resolve(get.result); });
    s.close(); return [...results, raw === bad];
  }, safe()), ['corrupt', 'corrupt', 'corrupt', 'corrupt', true]);
});
