'use strict';
// Product-side controls for the pinned fork-wallet package: the tarball in the repository is the installed code, the
// facade pins chain 137 and keeps the loopback guard. Generic wallet behaviour is tested in the package itself.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const facade = require('./support/fork-wallet.cjs');
const APP = path.resolve(__dirname, '..');
const account = '0x' + '11'.repeat(20);
const origin = 'http://127.0.0.1:18546';

function fakeContext() {
  const ctx = { binding: null, pages: () => [] };
  ctx.exposeBinding = async (_, fn) => { ctx.binding = fn; };
  ctx.addInitScript = async () => {};
  return ctx;
}

test('pinned fork-wallet tarball matches the lock integrity, is the installed code, and the facade pins chain 137', async () => {
  const tarball = facade.PACKAGE_INPUTS[0];
  assert.equal(tarball, `tests/packages/fork-wallet-${facade.PACKAGE_VERSION}.tgz`);
  const lock = JSON.parse(fs.readFileSync(path.join(APP, 'package-lock.json'), 'utf8')).packages['node_modules/fork-wallet'];
  assert.equal(lock.resolved, 'file:' + tarball);
  assert.equal(lock.version, facade.PACKAGE_VERSION);
  const sha512 = 'sha512-' + crypto.createHash('sha512').update(fs.readFileSync(path.join(APP, tarball))).digest('base64');
  assert.equal(lock.integrity, sha512, 'repository tarball differs from the locked integrity');
  assert.deepEqual(facade.PACKAGE_INPUTS.slice(1), ['node_modules/fork-wallet/src/index.js', 'node_modules/fork-wallet/package.json']);
  for (const file of facade.PACKAGE_INPUTS) assert.ok(fs.existsSync(path.join(APP, file)), file);
  const source = fs.readFileSync(path.join(APP, facade.PACKAGE_INPUTS[1]), 'utf8');
  assert.ok(!/model\.js|oracle|check-fork|\/Users\//.test(source), 'package code carries no product or host paths');

  const options = { endpoint: 'http://127.0.0.1:18545', origin, account, validateTransaction() {}, beforeSend() {} };
  const ctx = fakeContext();
  const wallet = await facade.installForkWallet(ctx, options);
  assert.equal(wallet.chainId, facade.CHAIN_ID);
  const request = (method) => ctx.binding({ frame: { url: () => origin + '/' } }, { method, params: [] });
  assert.deepEqual(await request('eth_chainId'), { result: '0x89' });
  assert.deepEqual(await request('eth_requestAccounts'), { result: [account] });
  assert.equal((await request('eth_sign')).error.code, 4200);
  await assert.rejects(facade.installForkWallet(fakeContext(), { ...options, chainId: '0x1' }), /pins chainId/);
  await assert.rejects(facade.installForkWallet(fakeContext(), { ...options, endpoint: 'http://localhost:18545' }), /loopback/);
  await assert.rejects(facade.installForkWallet(fakeContext(), { ...options, endpoint: 'https://polygon.drpc.org' }), /loopback/);
  await assert.rejects(facade.installForkWallet(fakeContext(), { ...options, validateTransaction: undefined }), (e) => e.code === -32602);
  await assert.rejects(facade.installForkWallet(fakeContext(), { ...options, beforeSend: undefined }), (e) => e.code === -32602);
});
