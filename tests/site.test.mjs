import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { readURL, relayURL, SITE_URL } from '../site.js';

test('Pages project path and four fixed public read endpoints are closed', () => {
  assert.equal(SITE_URL, 'https://tumf.github.io/p256-signer-web/');
  const endpoints = {
    '/rpc':'https://polygon-bor-rpc.publicnode.com/',
    '/rpc/1':'https://ethereum-rpc.publicnode.com/',
    '/rpc/8453':'https://base-rpc.publicnode.com/',
    '/rpc/84532':'https://base-sepolia-rpc.publicnode.com/',
  };
  for (const [route, endpoint] of Object.entries(endpoints)) assert.equal(readURL(route, 'eth_chainId'), endpoint);
  for (const route of ['/rpc/42161', '/rpc?url=x', 'https://evil.example', '__proto__']) assert.throws(() => relayURL(route));
});
test('all page links and assets stay under the Pages project path', () => {
  for (const name of ['index.html', 'safe-request.html', 'safe-execute.html', 'key-change.html', 'prefund.html']) {
    const html = readFileSync(new URL('../' + name, import.meta.url), 'utf8');
    for (const [, value] of html.matchAll(/(?:href|src)="([^"]+)"/g)) {
      assert.ok(new URL(value, SITE_URL + name).href.startsWith(SITE_URL), name + ': ' + value);
    }
    if (['safe-request.html', 'key-change.html', 'prefund.html'].includes(name)) {
      assert.match(html, /href="\.\/">配備Web<\/a>/);
    }
  }
});
test('read transport cannot submit transactions or sign', () => {
  for (const method of ['eth_sendRawTransaction', 'eth_sendTransaction', 'eth_sign', 'personal_sign', 'wallet_switchEthereumChain', 'anvil_setBalance']) {
    assert.throws(() => readURL('/rpc', method));
  }
});
