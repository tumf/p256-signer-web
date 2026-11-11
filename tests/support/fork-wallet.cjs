'use strict';
// Thin Polygon-fork facade over the standalone `fork-wallet` package pinned as tests/packages/fork-wallet-<v>.tgz
// (devDependency, locked by integrity). The implementation lives in the package; this file only pins chain 137,
// keeps the product loopback guard and lists the installed package files so evidence digests the executed code,
// not just this facade. Test-only. Never import from a product entrypoint.
const fs = require('node:fs');
const path = require('node:path');
const guard = require('../check-fork.cjs');
const pkg = require('fork-wallet');
const APP = path.resolve(__dirname, '..', '..');
const PACKAGE_VERSION = require('fork-wallet/package.json').version;
const TARBALL = `tests/packages/fork-wallet-${PACKAGE_VERSION}.tgz`;
const CHAIN_ID = '0x89';
const pinned = JSON.parse(fs.readFileSync(path.join(APP, 'package.json'), 'utf8')).devDependencies['fork-wallet'];
if (pinned !== 'file:' + TARBALL) throw new Error(`fork-wallet pin ${pinned} does not match installed ${PACKAGE_VERSION}`);
/** Pinned tarball plus the actually installed package code; both belong in every evidence input digest. */
const PACKAGE_INPUTS = Object.freeze([TARBALL, path.relative(APP, require.resolve('fork-wallet')),
  path.relative(APP, require.resolve('fork-wallet/package.json'))]);

async function installForkWallet(context, options) {
  if (!options || Object.hasOwn(options, 'chainId')) throw new Error('Polygon facade pins chainId 0x89; pass no chainId');
  guard.requireLoopback(options.endpoint);
  return pkg.installForkWallet(context, { ...options, chainId: CHAIN_ID });
}
module.exports = { installForkWallet, PACKAGE_INPUTS, PACKAGE_VERSION, CHAIN_ID };
