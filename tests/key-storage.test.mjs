// Real Chromium IndexedDB evidence for the dedicated key-change attempt store, through the production page, controller
// and KeyAttemptStore: strict durability, persist-before-send, cross-tab CAS with exactly one wallet invocation,
// corruption refusal without rewrite, versionchange release, reload reconcile-only and two sequential changes in the
// same database, legacy v1 records restored without signing capability and replaced by v2 only at a new reservation.
// Controlled peers (fixture chain, software native peer, injected wallet): NOT EVM or wallet evidence.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { DB_NAME } from '../saved-result-store.js';
import {
  addChange, anchor, kh, legacy, open, reconcileClick, reconciled, removeChange, sent, startBrowser, stopBrowser, until,
  walletConnected,
} from './support/key-browser.mjs';

before(startBrowser);
after(stopBrowser);

const readRow = () => new Promise((resolve, reject) => {
  const r = indexedDB.open('p256.key-change.attempts', 1);
  r.onerror = () => reject(new Error('open'));
  r.onsuccess = () => {
    const tx = r.result.transaction('state', 'readonly');
    const get = tx.objectStore('state').get('current');
    get.onsuccess = () => { r.result.close(); resolve(get.result); };
  };
});

test('strict durability and persist-before-send: the reserved record is committed when the wallet is invoked', async () => {
  const { page, context } = await open('1280x900');
  await walletConnected(page);
  await kh(page, () => { window.__kh.provider.beforeSend = () => new Promise((resolve, reject) => {
    const r = indexedDB.open('p256.key-change.attempts', 1);
    r.onerror = reject;
    r.onsuccess = () => { const tx = r.result.transaction('state', 'readonly');
      const get = tx.objectStore('state').get('current');
      get.onsuccess = () => { r.result.close(); resolve(get.result); }; };
  }); });
  const durability = await page.evaluate(() => new Promise((resolve) => {
    const r = indexedDB.open('p256.key-change.attempts', 1);
    r.onsuccess = () => { const tx = r.result.transaction('state', 'readwrite', { durability: 'strict' });
      resolve(tx.durability); tx.abort(); r.result.close(); };
  }));
  assert.equal(durability, 'strict');
  const envelope = await kh(page, () => window.__kh.controller.s.native.signed.request.envelope);
  await page.click('#send');
  await page.waitForFunction(() => window.__kh.controller.view().attempt.record?.status === 'hashKnown');
  const atSend = await kh(page, () => window.__kh.provider.atSend);
  assert.equal(atSend.revision, 1);
  assert.equal(JSON.parse(atSend.raw).status, 'reserved');
  assert.equal(JSON.parse(atSend.raw).version, 2);
  assert.equal(await kh(page, () => window.__kh.provider.sends.length), 1);
  assert.deepEqual(Object.keys(await kh(page, () => window.__kh.provider.sends[0])).sort(),
    ['chainId', 'data', 'from', 'to', 'value']);
  const names = await page.evaluate(async () => (await indexedDB.databases()).map((d) => d.name).sort());
  assert.deepEqual(names, [DB_NAME, 'p256.key-change.attempts'].sort());
  const retained = await kh(page, () => window.__kh.controller.savedResultStore.list());
  assert.equal(retained.length, 1);
  const [unsigned] = retained;
  assert.equal(unsigned.envelope, envelope);
  assert.equal(unsigned.expected.operation.signature, '0x');
  for (const forbidden of ['rawSignature', 'signerSignature', 'topic', 'rpcId', 'grant', 'uri']) {
    assert.equal(JSON.stringify(unsigned).includes(`"${forbidden}"`), false, forbidden);
  }
  assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);
  await context.close();
});

test('two tabs racing from the same snapshot cause exactly one wallet invocation; the other reports conflict', async () => {
  const first = await open('1280x900');
  const second = await open('1280x900', { context: first.context });
  for (const { page } of [first, second]) {
    await walletConnected(page);
      }
  await Promise.all([first.page.click('#send'), second.page.click('#send')]);
  for (const { page } of [first, second]) {
    await page.waitForFunction(() => !window.__kh.controller.view().attempt.sending
      && (window.__kh.controller.view().attempt.record || window.__kh.controller.view().attempt.storageError));
  }
  const sends = await Promise.all([first, second].map(({ page }) => kh(page, () => window.__kh.provider.sends.length)));
  assert.equal(sends[0] + sends[1], 1);
  const rows = await Promise.all([first, second].map(({ page }) => page.locator('main').getAttribute('data-row')));
  assert.ok(rows.includes('KW29-conflict'), rows.join());
  const row = await first.page.evaluate(readRow);
  assert.equal(row.revision, 2);
  await first.context.close();
});

test('stale-tab settlement cannot overwrite a newer attempt in native IndexedDB', async () => {
  const first = await open('1280x900');
  try {
    await sent(first.page);
    await kh(first.page, () => window.__kh.chain.mine());
    const second = await open('1280x900', { context: first.context });
    await kh(second.page, () => {
      const k = window.__kh;
      k.chain.state.nonce = 1n; k.chain.state.keys = [k.keys.k1, k.keys.k2]; k.chain.mine();
    });
    await reconcileClick(second.page);
    await until(second.page, 'KW26-state-resolved');
    await second.page.click('#new-change');
    await second.page.waitForFunction(() => window.__kh.controller.view().rollover !== null);
    await sent(second.page, { change: (p) => addChange(p, 'bare3'),
      setup: () => { window.__kh.provider.submit = { mineBlock: false }; } });
    const successor = await second.page.evaluate(readRow);
    assert.equal(JSON.parse(successor.raw).status, 'hashKnown');
    await first.page.click('#reconcile');
    await until(first.page, 'KW29-conflict');
    assert.deepEqual(await first.page.evaluate(readRow), successor);
    assert.equal(await kh(first.page, () => window.__kh.controller.view().attempt.outcome), null);
    assert.equal(await kh(first.page, () => window.__kh.provider.sends.length), 1);
    assert.equal(await kh(second.page, () => window.__kh.provider.sends.length), 1);
  } finally { await first.context.close(); }
});

test('rendered send precheck refuses a wallet account change and native session loss', async () => {
  for (const cause of ['wallet', 'native']) {
    const { page, context, errors, external } = await open('390x844');
    try {
      await walletConnected(page);
      await kh(page, () => {
        const k = window.__kh, rpc = k.controller.rpc;
        k.controller.rpc = async (method, params) => {
          const value = await rpc(method, params);
          if (method === 'eth_getTransactionCount') {
            await new Promise((resolve) => { k.releasePrecheck = resolve; });
          }
          return value;
        };
      });
      await page.click('#send');
      await page.waitForFunction(() => Boolean(window.__kh.releasePrecheck));
      // The rendered page is busy during the bounded preflight and the send button cannot be activated again.
      assert.equal(await page.locator('main').getAttribute('data-row'), 'KW20-checking', cause);
      assert.equal(await page.locator('main').getAttribute('aria-busy'), 'true', cause);
      assert.equal(await page.locator('#send').isDisabled(), true, cause);
      if (cause === 'wallet') {
        await kh(page, () => window.__kh.provider.emit('accountsChanged', ['0x' + '55'.repeat(20)]));
      } else {
        await kh(page, () => window.__kh.native.client.emit('session_delete', window.__kh.native.client.topic));
      }
      await kh(page, () => window.__kh.releasePrecheck());
      await page.waitForFunction(() => !window.__kh.controller.view().attempt.sending);
      assert.equal(await kh(page, () => window.__kh.provider.sends.length), 0, cause);
      // Native loss ends the signature; a changed wallet account only allows another explicit send (new preflight).
      assert.equal(await page.locator('#send').isEnabled(), cause === 'wallet', cause);
      assert.equal(await kh(page, () => window.__kh.controller.view().attempt.record), null, cause);
      assert.deepEqual(external, []); assert.deepEqual(errors, []);
    } finally { await context.close(); }
  }
});

test('hash-known pending nonce advance exposes the ordinary new-change button', async () => {
  const { page, context } = await open('390x844');
  try {
    await sent(page, { setup: () => { window.__kh.provider.submit = { mineBlock: false }; } });
    await reconcileClick(page); await until(page, 'KW23-pending');
    assert.equal(await page.locator('#new-change').isVisible(), false);
    await kh(page, () => {
      const k = window.__kh;
      k.chain.state.nonce = 1n; k.chain.state.keys = [k.keys.k1, k.keys.k3]; k.chain.mine();
    });
    await reconcileClick(page); await until(page, 'KW26-state-advanced');
    assert.equal(await page.locator('#new-change').isEnabled(), true);
    await page.click('#new-change');
    await page.waitForFunction(() => window.__kh.controller.view().rollover !== null);
    assert.equal(await kh(page, () => window.__kh.provider.sends.length), 1);
  } finally { await context.close(); }
});

test('corrupt bytes are refused and never rewritten; reload restores no session, signature or send', async () => {
  const { page, context } = await open('390x844');
  await sent(page, { setup: () => { window.__kh.provider.sendMode = 'reject'; } });
  await page.reload();
  await page.waitForFunction(() => window.__kh?.ready === true);
  await until(page, 'KW30-v2-reserved');
  const view = await kh(page, () => { const v = window.__kh.controller.view();
    return { signed: v.signed, connect: v.actions.connectNative, send: v.actions.send, hash: v.actions.hashInput,
      connects: window.__kh.native.client.calls.length, sends: window.__kh.provider.sends.length }; });
  assert.deepEqual(view, { signed: null, connect: false, send: false, hash: true, connects: 0, sends: 0 });
  const corrupt = { version: 1, revision: 7, raw: '{"version":1,"status":"reserved","extra":true}' };
  await page.evaluate((value) => new Promise((resolve) => {
    const r = indexedDB.open('p256.key-change.attempts', 1);
    r.onsuccess = () => { const tx = r.result.transaction('state', 'readwrite');
      tx.objectStore('state').put(value, 'current'); tx.oncomplete = () => { r.result.close(); resolve(); }; };
  }), corrupt);
  await page.reload();
  await page.waitForFunction(() => window.__kh?.ready === true);
  await until(page, 'KW29-corrupt');
  await anchor(page);
  await addChange(page);
  assert.equal(await page.locator('#connect').isDisabled(), true);
  assert.deepEqual(await page.evaluate(readRow), corrupt);
  await context.close();
});

test('a versionchange from another tab releases the connection: later sends are refused without a wallet call', async () => {
  const { page, context } = await open('1280x900');
  await walletConnected(page);
  await page.evaluate(() => new Promise((resolve) => {
    const r = indexedDB.open('p256.key-change.attempts', 2);
    r.onupgradeneeded = () => {};
    r.onsuccess = () => { r.result.close(); resolve(); };
  }));
  await page.click('#send');
  await page.waitForFunction(() => !window.__kh.controller.view().attempt.sending);
  assert.equal(await kh(page, () => window.__kh.provider.sends.length), 0);
  assert.equal(await page.locator('main').getAttribute('data-row'), 'KW29-unavailable');
  await context.close();
});

test('two sequential distinct changes in one database, including a fresh authorizer after self-removal', async () => {
  const { page, context } = await open('1280x900');
  await reconciled(page);
  await until(page, 'KW27');
  const firstId = JSON.parse((await page.evaluate(readRow)).raw).attemptId;
  await page.click('#new-change');
  await page.waitForFunction(() => window.__kh.controller.view().rollover !== null);
  // k1 removes itself; k2 remains to authorize the next change.
  await page.fill('#anchor', await kh(page, () => window.__kh.text.anchor1));
  await page.click('#inspect');
  await page.waitForFunction(() => window.__kh.controller.view().inspection === 'ready');
  await removeChange(page, 'k1');
  await page.click('#connect');
  await until(page, 'KW11');
  await page.click('#preview');
  await until(page, 'KW13');
  await page.click('#sign');
  await page.waitForFunction(() => !document.querySelector('#verified').hidden);
  await page.click('#send');
  await page.waitForFunction(() => window.__kh.controller.view().attempt.record?.status === 'hashKnown'
    && window.__kh.controller.view().attempt.record.signerNonce === '1');
  await kh(page, () => window.__kh.chain.mine());
  await reconcileClick(page);
  await until(page, 'KW28');
  const second = JSON.parse((await page.evaluate(readRow)).raw);
  assert.notEqual(second.attemptId, firstId);
  assert.equal(second.authorizerKeyId, await kh(page, () => window.__kh.keys.k1.keyId));
  await page.click('#new-change');
  await page.waitForFunction(() => window.__kh.controller.view().rollover !== null);
  await kh(page, () => { window.__kh.peer.key = window.__kh.keys.k2; });
  await page.fill('#anchor', await kh(page, () => window.__kh.text.anchor2));
  await page.click('#inspect');
  await page.waitForFunction(() => window.__kh.controller.view().inspection === 'ready');
  await addChange(page, 'bare3');
  await page.click('#connect');
  await until(page, 'KW11');
  await page.click('#preview');
  await until(page, 'KW12');
  await page.click('#sign');
  await page.waitForFunction(() => !document.querySelector('#verified').hidden);
  await page.click('#send');
  await page.waitForFunction(() => window.__kh.controller.view().attempt.record?.signerNonce === '2');
  await kh(page, () => window.__kh.chain.mine());
  await reconcileClick(page);
  await until(page, 'KW27');
  assert.equal(await kh(page, () => window.__kh.provider.sends.length), 3);
  const third = await page.evaluate(readRow);
  assert.ok(third.revision >= 9, String(third.revision));
  assert.equal(JSON.parse(third.raw).authorizerKeyId, await kh(page, () => window.__kh.keys.k2.keyId));
  await context.close();
});

test('legacy v1 reload restores no signing capability and keeps exact bytes; v2 replaces it only at a new reservation', async () => {
  const { page, context } = await open('1280x900');
  try {
    await reconciled(page);
    await until(page, 'KW27');
    await legacy(page);
    const v1 = await page.evaluate(readRow);
    assert.equal(JSON.parse(v1.raw).version, 1);
    await page.reload();
    await page.waitForFunction(() => window.__kh?.ready === true);
    await until(page, 'KW30-terminal');
    const view = await kh(page, () => { const v = window.__kh.controller.view();
      return { signed: v.signed, connect: v.actions.connectNative, send: v.actions.send, sends: window.__kh.provider.sends.length,
        summary: document.getElementById('attempt-list').innerText }; });
    assert.deepEqual({ ...view, summary: undefined }, { signed: null, connect: false, send: false, sends: 0, summary: undefined });
    assert.match(view.summary, /外側ガス上限/);
    assert.deepEqual(await page.evaluate(readRow), v1, 'loading a v1 record never rewrites it');
    // The fresh chain of this reloaded page reflects the executed change: explicit rollover (a).
    await kh(page, () => { const k = window.__kh; k.chain.state.nonce = 1n; k.chain.state.keys = [k.keys.k1, k.keys.k2]; k.chain.mine(); });
    await page.click('#new-change');
    await page.waitForFunction(() => window.__kh.controller.view().rollover !== null);
    assert.deepEqual(await page.evaluate(readRow), v1, 'rollover alone rewrites nothing');
    await walletConnected(page, (p) => addChange(p, 'bare3'));
    await page.click('#send');
    await page.waitForFunction(() => window.__kh.controller.view().attempt.record?.version === 2
      && !window.__kh.controller.view().attempt.sending);
    const v2 = await page.evaluate(readRow);
    assert.equal(JSON.parse(v2.raw).version, 2);
    assert.equal('outerGasLimit' in JSON.parse(v2.raw), false);
    assert.ok(v2.revision > v1.revision);
    assert.equal(await kh(page, () => window.__kh.provider.sends.length), 1);
  } finally { await context.close(); }
});

test('rendered pending-nonce failure: alert, no reservation and no wallet call; explicit retry sends once', async () => {
  const { page, context } = await open('390x844');
  try {
    await walletConnected(page);
    await kh(page, () => { window.__kh.chain.fail = (m) => m === 'eth_getTransactionCount'; });
    await page.click('#send');
    await until(page, 'KW20-nonce');
    assert.equal(await page.evaluate(() => document.activeElement.id), 'execute-error');
    assert.equal((await page.evaluate(readRow)).revision, 0);
    assert.equal(await kh(page, () => window.__kh.provider.sends.length), 0);
    assert.equal(await page.locator('#send').isEnabled(), true);
    await kh(page, () => { window.__kh.chain.fail = null; });
    await page.click('#send');
    await page.waitForFunction(() => window.__kh.controller.view().attempt.record?.status === 'hashKnown');
    assert.equal(await kh(page, () => window.__kh.provider.sends.length), 1);
  } finally { await context.close(); }
});
