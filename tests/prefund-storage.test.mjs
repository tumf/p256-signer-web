// Real Chromium IndexedDB evidence for the dedicated funding attempt store, through the production prefund page,
// controller and FundingAttemptStore: strict durability, persist-before-send, cross-tab CAS with exactly one wallet
// invocation, corruption and mixed-version refusal without rewrite, versionchange release, dual-version (literal v1 and
// new v2) reload reconcile-only with byte-identical rows, an old-format v1 writer racing a v2 reservation, the
// chain-reverified v1 -> fresh v2 transition and byte preservation of the existing key-change database. Controlled peers
// (fixture chain, injected wallet): NOT EVM or wallet evidence.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import {
  holdNext, inventory, legacyRecord, open, ph, release, reviewed, sent, startBrowser, stopBrowser, until, v1Fixture,
  waitHeld,
} from './support/prefund-browser.mjs';

before(startBrowser);
after(stopBrowser);

const DESKTOP = inventory.rows.find((r) => r.viewport[0] === 1280);
const readRow = (name = 'p256.entrypoint-prefund.attempts') => new Promise((resolve, reject) => {
  const r = indexedDB.open(name, 1);
  r.onerror = () => reject(new Error('open'));
  r.onsuccess = () => {
    const tx = r.result.transaction('state', 'readonly');
    const get = tx.objectStore('state').get('current');
    get.onsuccess = () => { r.result.close(); resolve(get.result); };
  };
});

test('strict durability and persist-before-send: the reserved record is committed when the wallet is invoked', async () => {
  const { page, context } = await open(DESKTOP);
  try {
    await reviewed(page);
    await ph(page, () => { window.__ph.provider.beforeSend = () => new Promise((resolve, reject) => {
      const r = indexedDB.open('p256.entrypoint-prefund.attempts', 1);
      r.onerror = reject;
      r.onsuccess = () => { const get = r.result.transaction('state', 'readonly').objectStore('state').get('current');
        get.onsuccess = () => { r.result.close(); resolve(get.result); }; };
    }); });
    const durability = await page.evaluate(() => new Promise((resolve) => {
      const r = indexedDB.open('p256.entrypoint-prefund.attempts', 1);
      r.onsuccess = () => { const tx = r.result.transaction('state', 'readwrite', { durability: 'strict' });
        resolve(tx.durability); tx.abort(); r.result.close(); };
    }));
    assert.equal(durability, 'strict');
    await page.click('#send');
    await page.waitForFunction(() => window.__ph.controller.view().attempt.record?.status === 'hashKnown');
    const atSend = await ph(page, () => window.__ph.provider.atSend);
    assert.equal(atSend.revision, 1);
    assert.equal(JSON.parse(atSend.raw).status, 'reserved');
    assert.equal(JSON.parse(atSend.raw).version, 2);
    assert.deepEqual(Object.keys(atSend).sort(), ['raw', 'revision', 'version']);
    assert.equal(atSend.version, 1);
    assert.equal(await ph(page, () => window.__ph.provider.sends.length), 1);
    const names = await page.evaluate(async () => (await indexedDB.databases()).map((d) => d.name).sort());
    assert.deepEqual(names, ['p256.entrypoint-prefund.attempts']);
    assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);
    assert.ok(!/signature|binding|symKey|wc:|"d"/.test(atSend.raw));
  } finally { await context.close(); }
});

test('two tabs racing from the same snapshot cause exactly one wallet invocation; the other reports conflict', async () => {
  const first = await open(DESKTOP);
  const second = await open(DESKTOP, { context: first.context });
  try {
    for (const { page } of [first, second]) await reviewed(page);
    await Promise.all([first.page.click('#send'), second.page.click('#send')]);
    for (const { page } of [first, second]) {
      await page.waitForFunction(() => !window.__ph.controller.view().attempt.sending
        && (window.__ph.controller.view().attempt.record || window.__ph.controller.view().attempt.storageError));
    }
    const sends = await Promise.all([first, second].map(({ page }) => ph(page, () => window.__ph.provider.sends.length)));
    assert.equal(sends[0] + sends[1], 1);
    const rows = await Promise.all([first, second].map(({ page }) => page.locator('main').getAttribute('data-row')));
    assert.ok(rows.includes('PF21-conflict'), rows.join());
    assert.equal((await first.page.evaluate(readRow)).revision, 2);
  } finally { await first.context.close(); }
});

test('terminal successor in real IndexedDB invalidates stale success and rollover without altering its bytes', async () => {
  const first = await open(DESKTOP);
  try {
    await sent(first.page);
    await ph(first.page, async () => { window.__ph.chain.mine(); await window.__ph.controller.reconcile(); });
    await until(first.page, 'PF19-success-ready');
    const second = await open(DESKTOP, { context: first.context });
    const copyChain = async (from, to) => {
      const state = await ph(from, () => {
        const s = window.__ph.chain.state;
        return { ...s, txs: [...s.txs], receipts: [...s.receipts] };
      });
      await ph(to, (s) => Object.assign(window.__ph.chain.state, s,
        { txs: new Map(s.txs), receipts: new Map(s.receipts) }), state);
    };
    await copyChain(first.page, second.page);
    await ph(second.page, async () => {
      await window.__ph.controller.newFunding();
      window.__ph.chain.state.deposit = 0n;
      window.__ph.chain.mine();
    });
    await until(second.page, 'PF23-new-attempt');
    await sent(second.page);
    await ph(second.page, async () => { window.__ph.chain.mine(); await window.__ph.controller.reconcile(); });
    await until(second.page, 'PF19-success-ready');
    const successor = await second.page.evaluate(readRow);
    await copyChain(second.page, first.page);
    await ph(first.page, () => window.__ph.controller.reconcile());
    await until(first.page, 'PF21-conflict');
    await ph(first.page, () => window.__ph.controller.newFunding());
    const stale = await ph(first.page, () => {
      const v = window.__ph.controller.view();
      return { revision: v.attempt.revision, outcome: v.attempt.outcome, rollover: v.rollover,
        send: v.actions.send, newFunding: v.actions.newFunding };
    });
    assert.deepEqual(stale, { revision: successor.revision, outcome: null, rollover: false,
      send: false, newFunding: false });
    assert.deepEqual(await first.page.evaluate(readRow), successor);
    assert.equal(await ph(first.page, () => window.__ph.provider.sends.length), 1);
    assert.equal(await ph(second.page, () => window.__ph.provider.sends.length), 1);
  } finally { await first.context.close(); }
});

test('corrupt bytes are refused without rewrite; no send, reload or reconcile overwrites them', async () => {
  const { page, context } = await open(DESKTOP);
  try {
    const bad = { version: 1, revision: 4, raw: '{"version":1,"status":"reserved","amount":"1"}' };
    await page.evaluate((value) => new Promise((resolve) => {
      const r = indexedDB.open('p256.entrypoint-prefund.attempts', 1);
      r.onsuccess = () => { const tx = r.result.transaction('state', 'readwrite');
        tx.objectStore('state').put(value, 'current'); tx.oncomplete = () => { r.result.close(); resolve(); }; };
    }), bad);
    await page.reload();
    await page.waitForFunction(() => window.__ph?.ready === true);
    await until(page, 'PF21-corrupt');
    await ph(page, () => window.__ph.controller.send());
    await ph(page, () => window.__ph.controller.reloadAttempt());
    await ph(page, () => window.__ph.controller.reconcile());
    assert.equal(await ph(page, () => window.__ph.provider.sends.length), 0);
    assert.deepEqual(await page.evaluate(readRow), bad);
    assert.equal(await page.locator('main').getAttribute('data-row'), 'PF21-corrupt');
  } finally { await context.close(); }
});

test('reload restores reconcile-only state: no armed review, connection or send authority returns', async () => {
  const { page, context } = await open(DESKTOP);
  try {
    await sent(page, () => { window.__ph.provider.sendMode = 'reject'; });
    const before = await page.evaluate(readRow);
    await page.reload();
    await page.waitForFunction(() => window.__ph?.ready === true);
    await until(page, 'PF22-reserved');
    const v = await ph(page, () => { const x = window.__ph.controller.view();
      return [x.actions.send, x.actions.inspect, x.actions.walletChoose, x.actions.newFunding,
        window.__ph.controller.s.armed, window.__ph.wallet.status]; });
    assert.deepEqual(v, [false, false, false, false, null, 'disconnected']);
    assert.equal(await ph(page, () => window.__ph.provider.sends.length), 0);
    assert.ok(!(await ph(page, () => window.__ph.provider.requests)).includes('eth_requestAccounts'));
    assert.deepEqual(await page.evaluate(readRow), before);
  } finally { await context.close(); }
});

test('versionchange releases the store; the next send fails closed with no wallet invocation', async () => {
  const { page, context } = await open(DESKTOP);
  try {
    await reviewed(page);
    await page.evaluate(() => new Promise((resolve) => {
      const r = indexedDB.open('p256.entrypoint-prefund.attempts', 2);
      r.onupgradeneeded = () => {};
      r.onsuccess = () => { r.result.close(); resolve(); };
      r.onblocked = () => {};
    }));
    await page.click('#send');
    await page.waitForFunction(() => !window.__ph.controller.view().attempt.sending);
    assert.equal(await ph(page, () => window.__ph.provider.sends.length), 0);
    assert.equal(await page.locator('main').getAttribute('data-row'), 'PF21-unavailable');
  } finally { await context.close(); }
});

test('existing key-change and deployment databases stay byte-identical across a complete funding', async () => {
  const { page, context } = await open(DESKTOP);
  try {
    const keyRow = { version: 1, revision: 3, raw: null };
    await page.evaluate((value) => Promise.all(['p256.key-change.attempts', 'p256.registration.attempts'].map((name) =>
      new Promise((resolve) => {
        const r = indexedDB.open(name, 1);
        r.onupgradeneeded = () => r.result.createObjectStore('state');
        r.onsuccess = () => { const tx = r.result.transaction('state', 'readwrite');
          tx.objectStore('state').put(value, 'current'); tx.oncomplete = () => { r.result.close(); resolve(); }; };
      }))), keyRow);
    await sent(page);
    await ph(page, () => window.__ph.chain.mine());
    await page.click('#reconcile');
    await until(page, 'PF19-success-ready');
    for (const name of ['p256.key-change.attempts', 'p256.registration.attempts']) {
      assert.deepEqual(await page.evaluate(readRow, name), keyRow, name);
    }
    const names = await page.evaluate(async () => (await indexedDB.databases()).map((d) => d.name).sort());
    assert.deepEqual(names, ['p256.entrypoint-prefund.attempts', 'p256.key-change.attempts', 'p256.registration.attempts']);
  } finally { await context.close(); }
});

const writeRow = (page, value) => page.evaluate((v) => new Promise((resolve, reject) => {
  const r = indexedDB.open('p256.entrypoint-prefund.attempts', 1);
  r.onerror = reject;
  r.onsuccess = () => { const tx = r.result.transaction('state', 'readwrite');
    tx.objectStore('state').put(v, 'current'); tx.oncomplete = () => { r.result.close(); resolve(); }; tx.onerror = reject; };
}), value);

test('both record versions reload read-only and byte-identical; mixed or coerced versions stay corrupt without rewrite', async () => {
  const { page, context } = await open(DESKTOP);
  try {
    const expected = { reserved: 'PF22-reserved', unknown: 'PF22-reserved', hashKnown: 'PF22-hashKnown',
      confirming: 'PF22-hashKnown', uncertain: 'PF22-terminal', succeeded: 'PF22-terminal', outerFailed: 'PF22-terminal' };
    for (const [kind, row] of Object.entries(expected)) {
      const value = { version: 1, revision: 7, raw: v1Fixture.valid[kind] };
      await writeRow(page, value);
      await page.reload();
      await page.waitForFunction(() => window.__ph?.ready === true);
      await until(page, row);
      assert.deepEqual(await page.evaluate(readRow), value, kind);
      assert.deepEqual(await ph(page, () => [window.__ph.controller.view().actions.send, window.__ph.provider.sends.length,
        window.__ph.provider.requests.length]), [false, 0, 0], kind);
      assert.match(await page.locator('#attempt-list').innerText(), /旧形式 v1（読取り専用）/, kind);
    }
    // A fresh v2 row reloads the same way and lists no outer cap or nonce.
    await writeRow(page, { version: 1, revision: 0, raw: null });
    await page.reload();
    await page.waitForFunction(() => window.__ph?.ready === true);
    await sent(page, () => { window.__ph.provider.sendMode = 'reject'; });
    const v2 = await page.evaluate(readRow);
    assert.equal(JSON.parse(v2.raw).version, 2);
    await page.reload();
    await page.waitForFunction(() => window.__ph?.ready === true);
    await until(page, 'PF22-reserved');
    assert.deepEqual(await page.evaluate(readRow), v2);
    const listed = await page.locator('#attempt-list').innerText();
    assert.ok(!/旧形式|nonce|外側ガス上限/.test(listed), listed);
    // Mixed/coerced records are corrupt: never parsed by field inference, repaired or overwritten.
    const mixed = {
      v2WithCap: v2.raw.replace('"calldataSHA256"', '"outerGasLimit":"60000","calldataSHA256"'),
      v1Capless: v1Fixture.invalid.capless, stringVersion: v1Fixture.invalid.stringVersion,
      v2Labeled1: v2.raw.replace('{"version":2,', '{"version":1,'), v1Labeled2: v1Fixture.invalid.versionTwoWithCaps,
    };
    for (const [name, raw] of Object.entries(mixed)) {
      const value = { version: 1, revision: 9, raw };
      await writeRow(page, value);
      await page.reload();
      await page.waitForFunction(() => window.__ph?.ready === true);
      await until(page, 'PF21-corrupt');
      await ph(page, async () => { await window.__ph.controller.reloadAttempt(); await window.__ph.controller.reconcile();
        await window.__ph.controller.newFunding(); await window.__ph.controller.send(); });
      assert.deepEqual(await page.evaluate(readRow), value, name);
      assert.equal(await ph(page, () => window.__ph.provider.sends.length), 0, name);
    }
  } finally { await context.close(); }
});

/** The base (pre-v2) tab's reservation: the same strict CAS on revision/raw, writing literal v1 bytes. */
const oldWriter = (page, raw) => page.evaluate((v) => new Promise((resolve, reject) => {
  const r = indexedDB.open('p256.entrypoint-prefund.attempts', 1);
  r.onerror = reject;
  r.onsuccess = () => {
    const tx = r.result.transaction('state', 'readwrite', { durability: 'strict' });
    const store = tx.objectStore('state');
    let committed = false;
    const get = store.get('current');
    get.onsuccess = () => {
      if (get.result.revision === 0 && get.result.raw === null) {
        store.put({ version: 1, revision: 1, raw: v }, 'current');
        committed = true;
      }
    };
    tx.oncomplete = () => { r.result.close(); resolve(committed); };
    tx.onerror = reject;
  };
}), raw);

test('an old v1 writer racing a v2 reservation: exactly one reservation and at most one wallet invocation', async () => {
  for (const order of ['old-first', 'new-first']) {
    const { page, context } = await open(DESKTOP);
    try {
      await reviewed(page);
      let oldCommitted;
      if (order === 'old-first') {
        await holdNext(page, 'cas');
        await page.click('#send');
        await waitHeld(page, 'cas');
        oldCommitted = await oldWriter(page, v1Fixture.valid.reserved);
        await release(page, 'cas');
      } else {
        await page.click('#send');
        await page.waitForFunction(() => window.__ph.controller.view().attempt.record?.status === 'hashKnown');
        oldCommitted = await oldWriter(page, v1Fixture.valid.reserved);
      }
      await page.waitForFunction(() => !window.__ph.controller.view().attempt.sending);
      const stored = await page.evaluate(readRow);
      const sends = await ph(page, () => window.__ph.provider.sends.length);
      if (order === 'old-first') {
        assert.deepEqual([oldCommitted, sends, stored.raw], [true, 0, v1Fixture.valid.reserved], order);
        assert.equal(await page.locator('main').getAttribute('data-row'), 'PF21-conflict');
        // The new tab adopts the old reservation read-only after an explicit reload.
        await page.click('#storage-reload');
        await until(page, 'PF22-reserved');
        assert.equal(await ph(page, () => window.__ph.controller.view().actions.send), false);
      } else {
        assert.deepEqual([oldCommitted, sends, JSON.parse(stored.raw).version, stored.revision], [false, 1, 2, 2], order);
      }
    } finally { await context.close(); }
  }
});

test('chain-reverified terminal v1 transitions only by explicit new funding to a freshly reviewed v2 reservation', async () => {
  const { page, context } = await open(DESKTOP);
  try {
    await legacyRecord(page, 'succeeded', {});
    await until(page, 'PF22-terminal');
    const before = await page.evaluate(readRow);
    assert.equal(before.raw, v1Fixture.valid.succeeded);
    // The saved outcome is only a hint: reconciliation re-proves it on chain and CAS-updates it as v1 (the literal
    // fixture's outcome block differs from this fixture chain), then explicit new funding re-proves it again.
    await page.click('#reconcile');
    await until(page, 'PF19-success-ready');
    const reproved = await page.evaluate(readRow);
    assert.deepEqual([reproved.revision, JSON.parse(reproved.raw).version, JSON.parse(reproved.raw).status],
      [before.revision + 1, 1, 'succeeded']);
    await page.click('#new-funding');
    await until(page, 'PF23-new-attempt');
    assert.deepEqual(await page.evaluate(readRow), reproved);
    await ph(page, () => { window.__ph.chain.state.deposit = 0n; window.__ph.chain.mine(); });
    await sent(page);
    const next = await page.evaluate(readRow);
    assert.equal(JSON.parse(next.raw).version, 2);
    assert.notEqual(JSON.parse(next.raw).attemptId, JSON.parse(before.raw).attemptId);
    assert.equal(await ph(page, () => window.__ph.provider.sends.length), 1);
    assert.deepEqual(Object.keys(await ph(page, () => window.__ph.provider.sends[0])).sort(),
      ['chainId', 'data', 'from', 'to', 'value']);
  } finally { await context.close(); }
});
