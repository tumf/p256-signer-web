// Narrow rendered check of the Safe approval page in local headless Chromium. The page and deployment routes are
// built into a temporary directory and served through the real serve.py handler (real CSP headers) under the fixed
// origin. The happy path uses a controlled SignClient double: NOT a real relay, wallet, iPhone or Secure Enclave.
import assert from 'node:assert/strict';
import { checkQRDownload } from './support/qr-download.mjs';
import { runInNewContext } from 'node:vm';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { createChain } from './support/key-chain.mjs';

async function collectDownloaded(page, packet, now) {
  const U=ethers.utils,Z=ethers.constants.AddressZero,expected=packet.expected;
  const fixture=JSON.parse(readFileSync(new URL('fixtures/safe150-proxy.json',import.meta.url)));
  const singleton=fixture.singletonDeployment.address.toLowerCase();
  const key={publicKey:expected.publicKey,keyId:expected.keyId},chain=createChain({signer:expected.signer,keys:[key],now:()=>now});
  chain.head().timestamp=BigInt(now);
  const abi=new U.Interface(['function VERSION() view returns(string)','function getOwners() view returns(address[])','function getThreshold() view returns(uint256)','function nonce() view returns(uint256)','function getModulesPaginated(address,uint256) view returns(address[],address)']);
  const b=chain.head(),snapshot={chainId:'137',safe:expected.safe,version:'1.5.0',singleton,runtime:'unverified-offline',guard:Z,fallback:Z,modules:[],
    owners:[{address:expected.signer,kind:'hybrid',...key}],threshold:1,nonce:expected.nonce,account:'0x'+'77'.repeat(20),
    block:{number:b.number.toString(),hash:b.hash},generation:1,attempt:'none'};
  let simulations=0;
  await page.route('https://polygon-bor-rpc.publicnode.com/**',async route=>{
    const q=route.request().postDataJSON(),[target,slot]=q.params;let result;
    if(q.method==='eth_getCode'&&target===expected.safe.toLowerCase())result=fixture.runtime;
    else if(q.method==='eth_getCode'&&target===singleton)result=fixture.singletonRuntime;
    else if(q.method==='eth_getStorageAt'&&target===expected.safe.toLowerCase())result=slot===U.hexZeroPad('0x00',32)?U.hexZeroPad(singleton,32):U.hexZeroPad('0x00',32);
    else if(q.method==='eth_call'&&target.to===expected.safe.toLowerCase()&&target.data.startsWith('0x6a761202')){
      simulations++;assert.equal(q.params[1],'0x'+b.number.toString(16));assert.equal(target.from,snapshot.account);assert.equal(target.value,'0x0');
      result='0x'+'0'.repeat(63)+'1';
    }
    else if(q.method==='eth_call'&&target.to===expected.safe.toLowerCase()){
      const name=abi.parseTransaction({data:target.data}).name;
      result=abi.encodeFunctionResult(name,name==='VERSION'?['1.5.0']:name==='getOwners'?[[expected.signer]]:name==='getThreshold'?[1]:name==='nonce'?[expected.nonce]:[[],'0x0000000000000000000000000000000000000001']);
    } else result=await chain.rpc(q.method,q.params);
    await route.fulfill({json:{jsonrpc:'2.0',id:q.id,result}});
  });
  await page.goto(ORIGIN+'/safe-execute.html');
  await page.fill('#snapshot',JSON.stringify(snapshot));await page.fill('#recipient',expected.recipient);await page.fill('#value',expected.value);
  await page.click('#load');await page.waitForFunction(()=>document.querySelector('#preview').textContent||document.querySelector('#error').textContent);
  assert.equal(await page.locator('#error').textContent(),'');
  await page.locator('#packet-file').setInputFiles({name:'safe-approval-packet.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(packet))});
  await page.waitForFunction(()=>document.querySelector('#signature').value.length>0);assert.match(await page.locator('#status').textContent(),/0 \/ 1/);
  await page.click('#collect');await page.waitForFunction(()=>document.querySelector('#signature').value===''||document.querySelector('#error').textContent);
  assert.equal(await page.locator('#error').textContent(),'');await page.click('#prepare');
  await page.waitForFunction(()=>document.querySelector('#prepared').textContent||document.querySelector('#error').textContent);
  assert.equal(await page.locator('#error').textContent(),'');const prepared=JSON.parse(await page.locator('#prepared').textContent());
  assert.equal(prepared.safeTxHash,packet.request.safeTxHash);assert.equal(prepared.liveVerified,false);assert.equal(prepared.selected[0].kind,'hybrid');
  assert.equal(await page.locator('#execute').isDisabled(),true);
  assert.equal(simulations,0);assert.equal(await page.locator('#preflight').isDisabled(),false);
  await page.click('#preflight');await page.waitForFunction(()=>document.querySelector('#preflight-result').textContent||document.querySelector('#error').textContent);
  assert.equal(await page.locator('#error').textContent(),'');const simulation=JSON.parse(await page.locator('#preflight-result').textContent());
  assert.equal(simulations,1);assert.equal(simulation.simulationVerified,true);assert.equal(simulation.liveVerified,false);assert.equal(simulation.block.number,b.number.toString());
  assert.equal(await page.locator('#execute').isDisabled(),true);assert.ok(await noOverflow(page));
  await page.locator('#preflight').scrollIntoViewIfNeeded();await page.screenshot({path:path.join(tmpdir(),`native-preflight-${page.viewportSize().width}.png`)}); console.log(`native-preflight screenshot ${path.join(tmpdir(),`native-preflight-${page.viewportSize().width}.png`)}`);
  await page.click('#reset');assert.equal(await page.locator('#preflight-result').textContent(),'');assert.equal(await page.locator('#preflight').isDisabled(),true);
}

import { tmpdir } from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';
import { chromium } from 'playwright';
import ethers from '../vendor/ethers.js';
import { encodeBase64URL } from '../model.js';
import { expectedFrom, transaction, validateContext, verifyResult } from '../safe-request-model.js';
import { contextFor, freshSigner, v } from './support/safe-fixtures.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const app = path.resolve(here, '..');
const ORIGIN = 'https://tumf.github.io';
const DEPLOYMENT_CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
  + "connect-src 'self' https://polygon-bor-rpc.publicnode.com https://ethereum-rpc.publicnode.com https://base-rpc.publicnode.com https://base-sepolia-rpc.publicnode.com wss://relay.walletconnect.com https://relay.walletconnect.com; "
  + "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'";
let dist, server, port, browser, harness;

before(async () => {
  dist = mkdtempSync(path.join(tmpdir(), 'safe-page-'));
  const env = { ...process.env, REGISTRATION_DIST: dist };
  delete env.WALLETCONNECT_PROJECT_ID;
  const build = spawnSync(process.execPath, ['build.mjs'], { cwd: app, env, encoding: 'utf8', timeout: 120_000 });
  assert.equal(build.status, 0, build.stderr);
  server = spawn('python3', [path.join(here, 'support/serve-dist.py'), dist, ORIGIN], { cwd: app, env,
    stdio: ['pipe', 'pipe', 'inherit'] });
  const lines = createInterface({ input: server.stdout });
  port = Number((await new Promise((resolve) => lines.once('line', resolve))).replace('PORT ', ''));
  assert.ok(port > 0);
  harness = (await esbuild.build({ absWorkingDir: app, entryPoints: ['tests/support/safe-page-harness.mjs'],
    bundle: true, format: 'esm', write: false, platform: 'browser', target: ['es2022'] })).outputFiles[0].text;
  browser = await chromium.launch();
});

after(async () => {
  await browser?.close();
  server?.stdin.end();
  server?.kill();
  if (dist) rmSync(dist, { recursive: true, force: true });
});

/** A page whose fixed-origin requests reach the real handler; every other origin is recorded and aborted. */
async function open(width, { useHarness = false, init } = {}) {
  const context = await browser.newContext({ viewport: { width, height: 900 } });
  const page = await context.newPage();
  const external = [], errors = [], logs = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => logs.push(m.text()));
  if (init) await page.addInitScript(init.fn, init.arg);
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== ORIGIN) { external.push(url.origin); return route.abort(); }
    if (useHarness && url.pathname === '/safe-request.js') {
      return route.fulfill({ body: harness, contentType: 'text/javascript; charset=utf-8' });
    }
    const response = await route.fetch({ url: `http://127.0.0.1:${port}${url.pathname}` });
    return route.fulfill({ response });
  });
  return { page, context, external, errors, logs };
}

test('production bootstrap owns pagehide termination; removing its handler is detected', async () => {
  const source = readFileSync(new URL('../safe-request.js', import.meta.url), 'utf8');
  // Only substitute the imported mount collaborator; execute the production bootstrap/listener as written.
  const body = source.replace("import { mountSafePage } from './safe-page.js';", '');
  assert.notEqual(body, source);
  const exercise = async code => {
    let ended = 0; const handlers = {};
    runInNewContext(code, { document: {}, location: { origin: ORIGIN }, history: {},
      mountSafePage: () => ({ end: async () => { ended++; } }),
      addEventListener: (event, fn) => { handlers[event] = fn; } });
    handlers.pagehide?.(); await Promise.resolve(); return ended;
  };
  assert.equal(await exercise(body), 1);
  assert.equal(await exercise(body.replace("addEventListener('pagehide', () => { void page.end(); });", '')), 0);
});

const noOverflow = (page) => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);

test('served routes: Safe-only Verify CSP, deployment CSP byte-identical, no unsafe or wildcard source', async () => {
  for (const route of ['/', '/index.html', '/safe-request.html', '/config.json', '/safe-request.js']) {
    const response = await fetch(`http://127.0.0.1:${port}${route}`);
    assert.equal(response.status, 200, route);
    const csp = response.headers.get('content-security-policy');
    if (route === '/safe-request.html') {
      assert.match(csp, /frame-src https:\/\/verify\.walletconnect\.org https:\/\/verify\.walletconnect\.com;/);
      assert.match(csp, /script-src 'self';/);
      assert.ok(!csp.includes('unsafe-') && !csp.includes('*'));
    } else assert.equal(csp, DEPLOYMENT_CSP, route);
  }
  const deploymentPage = await (await fetch(`http://127.0.0.1:${port}/index.html`)).text();
  assert.doesNotMatch(deploymentPage, /href="safe-request\.html"/);
  assert.match(deploymentPage, /Signerを配備/);
  assert.deepEqual(await (await fetch(`http://127.0.0.1:${port}/config.json`)).json(),
    { walletConnectProjectId: null, allowedDeploymentOrigin: ORIGIN });
});

test('browser enforces CSP: Verify frame allowed only on the Safe page; inline script blocked on both', async () => {
  const probe = () => new Promise((resolve) => {
    const seen = [];
    document.addEventListener('securitypolicyviolation', (e) => seen.push(e.effectiveDirective));
    const frame = document.createElement('iframe');
    frame.src = 'https://verify.walletconnect.org/v3/attestation?probe=1';
    const script = document.createElement('script');
    script.textContent = 'window.inlineRan = true';
    document.body.append(frame, script);
    setTimeout(() => resolve({ seen, inline: Boolean(window.inlineRan) }), 500);
  });
  for (const [route, frameAllowed] of [['/safe-request.html', true], ['/', false]]) {
    const { page, context, errors } = await open(1280);
    await page.goto(ORIGIN + route);
    const result = await page.evaluate(probe);
    assert.equal(result.inline, false, route);
    assert.ok(result.seen.includes('script-src-elem'), route);
    assert.equal(result.seen.includes('frame-src'), !frameAllowed, route);
    assert.deepEqual(errors, [], route);
    await context.close();
  }
});

test('real built entry without a project ID fails closed before loading the SDK', async () => {
  const key = await freshSigner();
  const { page, context, external, errors } = await open(390);
  const requested = [];
  page.on('request', (r) => requested.push(new URL(r.url()).pathname));
  await page.goto(`${ORIGIN}/safe-request.html#registration=${encodeBase64URL(new TextEncoder().encode(key.json))}`);
  assert.equal(await page.evaluate(() => location.hash), '');
  assert.equal(await page.locator('#signer-address').textContent(), key.handoff.expectedAddress);
  await page.fill('#safe', v.policy.safe);
  await page.fill('#recipient', v.policy.recipient);
  await page.fill('#value', '1');
  await page.fill('#nonce', '0');
  await page.click('#connect');
  await page.locator('#request-error:visible').waitFor();
  assert.match(await page.locator('#request-error').textContent(), /WalletConnect設定/);
  assert.equal(await page.locator('#safe').isDisabled(), false);
  assert.equal(await page.locator('#disconnect').isDisabled(), true);
  assert.ok(!requested.some((p) => p.includes('safe-signclient')));
  assert.deepEqual(external, []);
  assert.deepEqual(errors, []);
  await context.close();
});

for (const stop of ['disconnect', 'session_delete', 'expiry']) test(`packet ${stop} removes displayed signature bytes`, async () => {
  const key = await freshSigner();
  const input = { safe: v.policy.safe, recipient: v.policy.recipient, value: '1', nonce: '12' };
  const expected = expectedFrom(key.handoff, input), ctx = validateContext(contextFor(expected), expected);
  const arg = { jwk: key.jwk, context: ctx, expected, now: Math.floor(Date.now() / 1000),
    keyHash: ethers.utils.keccak256(ethers.utils.toUtf8Bytes(ctx.keyId)) };
  const { page, context, errors, external } = await open(390,
    { useHarness: true, init: { fn: a => { window.__harness = a; }, arg } });
  try {
    await page.goto(ORIGIN + '/safe-request.html');
    await page.fill('#handoff', key.json); await page.click('#handoff-check');
    for (const [id, value] of Object.entries(input)) await page.fill('#' + id, value);
    await page.click('#connect'); await page.locator('#pairing:visible').waitFor();
    await page.evaluate(() => window.__harness.approve());
    await page.locator('#inspect:enabled').waitFor(); await page.click('#inspect');
    await page.locator('#sign:enabled').waitFor(); await page.click('#sign');
    await page.locator('#result:visible').waitFor();
    assert.match(await page.locator('#result-list').textContent(), /0x[0-9a-f]{192}/);
    if (stop === 'disconnect') await page.click('#disconnect');
    else if (stop === 'session_delete') await page.evaluate(() => window.__harness.emit('session_delete'));
    else {
      await page.evaluate(() => { window.__harness.now += 120; });
      await page.click('#packet-export'); await page.locator('#packet-export:disabled').waitFor({ state: 'attached' });
    }
    assert.equal(await page.locator('#result-list').textContent(), '', 'stop must remove signature bytes, not just disable export');
    assert.equal(await page.locator('#result').isHidden(), true);
    assert.equal(await page.locator('#packet-export').isDisabled(), true);
    assert.deepEqual(errors, []); assert.deepEqual(external, []);
  } finally { await context.close(); }
});

test('controlled-SDK happy path (not real relay): cancel, reconnect, inspect, explicit request, verify, loss', async () => {
  const key = await freshSigner('0x' + '33'.repeat(32));
  const input = { safe: v.policy.safe, recipient: v.policy.recipient, value: '1500000000000000000', nonce: '12' };
  const expected = expectedFrom(key.handoff, input);
  const ctx = validateContext(contextFor(expected), expected);
  const arg = { jwk: key.jwk, context: ctx, expected, now: Math.floor(Date.now() / 1000),
    keyHash: ethers.utils.keccak256(ethers.utils.toUtf8Bytes(ctx.keyId)) };
  for (const width of [390, 1280]) {
    const { page, context, external, errors, logs } = await open(width,
      { useHarness: true, init: { fn: (a) => { window.__harness = a; }, arg } });
    const H = (fn) => page.evaluate(fn);
    const calls = () => H(() => window.__harness.calls.filter(([k]) => k === 'request').map(([, m]) => m));
    const disabled = async () => Object.fromEntries(await Promise.all(['connect', 'inspect', 'sign', 'disconnect',
      'safe', 'handoff'].map(async (id) => [id, await page.locator('#' + id).isDisabled()])));
    await page.goto(ORIGIN + '/safe-request.html');
    assert.equal((await disabled()).connect, true);
    await page.fill('#handoff', key.json);
    await page.click('#handoff-check');
    assert.equal(await page.locator('#signer-keyid').textContent(), key.keyID);
    for (const [id, value] of Object.entries(input)) await page.fill('#' + id, value);
    // Keyboard submit of the native form is the connect action.
    await page.press('#nonce', 'Enter');
    await page.locator('#pairing:visible').waitFor();
    assert.deepEqual(await disabled(), { connect: true, inspect: true, sign: true, disconnect: false,
      safe: true, handoff: true });
    assert.equal(await page.locator('main').getAttribute('aria-busy'), 'true');
    assert.match(await page.locator('#pairing-open').getAttribute('href'), /^wc:/);
    await checkQRDownload(page, 'pairing-qr');
    await page.locator('#pairing').screenshot({ path: path.join(tmpdir(), `p256-qr-download-${width}.png`) });
    assert.deepEqual(await calls(), []);
    // Cancel while pairing; the late approval is disconnected and nothing is requested.
    await page.click('#disconnect');
    assert.equal(await page.locator('#pairing').isHidden(), true);
    assert.equal(await page.locator('#pairing-open').getAttribute('href'), null);
    assert.equal(await page.locator('#pairing-qr + button').isDisabled(), true);
    await H(() => window.__harness.approve());
    await page.waitForFunction(() => window.__harness.calls.some(([k, t]) => k === 'disconnect' && t === 'harness-1'));
    assert.deepEqual(await calls(), []);
    assert.equal((await disabled()).connect, false);
    // Explicit reconnect; connection alone requests nothing.
    await page.click('#connect');
    await page.locator('#pairing:visible').waitFor();
    await H(() => window.__harness.approve());
    await page.locator('#inspect:enabled').waitFor();
    assert.deepEqual(await calls(), []);
    assert.equal((await disabled()).sign, true);
    // Inspect: one context read, full planned transaction shown, still no signature request.
    await page.click('#inspect');
    await page.locator('#preview:visible').waitFor();
    const preview = await page.locator('#preview-list').textContent();
    for (const text of [transaction(expected).safeTxHash, expected.safe, expected.recipient, key.handoff.expectedAddress,
      ctx.binding, '1500000000000000000 wei（1.5 POL）', 'CALL', '0x0000000000000000000000000000000000000000']) {
      assert.ok(preview.includes(text), text);
    }
    assert.deepEqual(await calls(), ['p256_getSessionContext']);
    assert.equal(await noOverflow(page), true, `preview overflow at ${width}`);
    // Explicit request: fresh context, one sign request, browser verification of a genuine WebCrypto signature.
    await page.click('#sign');
    await page.locator('#result:visible').waitFor();
    assert.deepEqual(await calls(), ['p256_getSessionContext', 'p256_getSessionContext', 'p256_signSafeRequest']);
    const result = await page.locator('#result-list').textContent();
    assert.ok(result.includes(transaction(expected).safeTxHash));
    assert.match(result, /0x[0-9a-f]{192}/);
    assert.match(await page.locator('#status').textContent(), /取引は送信・実行していません/);
    assert.equal((await disabled()).sign, true);
    assert.equal(await noOverflow(page), true, `result overflow at ${width}`);
    assert.equal(await page.locator('#packet-export').isEnabled(),true);
    const downloaded=page.waitForEvent('download');await page.click('#packet-export');const download=await downloaded;
    const chunks=[];for await(const chunk of await download.createReadStream())chunks.push(chunk);
    const packet=JSON.parse(Buffer.concat(chunks).toString());
    assert.deepEqual(Object.keys(packet).sort(),['context','expected','owner','request','result']);
    assert.equal(packet.owner,expected.signer.toLowerCase());assert.deepEqual(packet.expected,expected);
    assert.equal(packet.request.safeTxHash,transaction(expected).safeTxHash);
    assert.equal(await verifyResult(packet.result,packet.request,packet.context,packet.expected,arg.now),packet.result.signerSignature);
    assert.equal((await calls()).filter(m=>m==='p256_signSafeRequest').length,1,'export must not request another signature');
    const collector=await open(width);
    await collectDownloaded(collector.page,packet,arg.now);assert.equal(await noOverflow(collector.page),true);
    assert.deepEqual(collector.errors,[]);assert.deepEqual(collector.external,[]);await collector.context.close();
    await H(()=>{window.__harness.now+=120;});
    await page.click('#packet-export');await page.locator('#packet-export:disabled').waitFor({ state: 'attached' });
    assert.match(await page.locator('#request-error').textContent(),/有効期限切れ/);
    await H(()=>{window.__harness.now-=120;});
    // Remote deletion afterwards: authority cleared, controls reset, nothing signed again.
    await H(() => window.__harness.emit('session_delete'));
    await page.locator('#request-error:visible').waitFor();
    assert.match(await page.locator('#request-error').textContent(), /接続が終了しました/);
    assert.equal(await page.locator('#packet-export').isDisabled(),true);
    assert.deepEqual(await disabled(), { connect: false, inspect: true, sign: true, disconnect: true,
      safe: false, handoff: false });
    // A new connection where the iPhone refuses: refused status, no success, no retry.
    await page.click('#connect');
    await page.locator('#pairing:visible').waitFor();
    await H(() => window.__harness.approve());
    await page.click('#inspect');
    await page.locator('#sign:enabled').waitFor();
    await H(() => { window.__harness.refuse = true; });
    await page.click('#sign');
    await page.locator('#request-error:visible').waitFor();
    assert.match(await page.locator('#request-error').textContent(), /拒否を返しました/);
    assert.equal(await page.locator('#result').isHidden(), true);
    assert.equal((await calls()).filter((m) => m === 'p256_signSafeRequest').length, 2);
    // An event before inspection never signs.
    await H(() => { window.__harness.refuse = false; });
    await page.click('#connect');
    await page.locator('#pairing:visible').waitFor();
    await H(() => window.__harness.approve());
    await page.locator('#inspect:enabled').waitFor();
    await H(() => window.__harness.emit('session_event'));
    await page.locator('#request-error:visible').waitFor();
    assert.equal((await calls()).filter((m) => m === 'p256_signSafeRequest').length, 2);
    const init = await H(() => window.__harness.init);
    assert.deepEqual([init.relayUrl, init.telemetryEnabled, init.storage, init.metadata.url],
      ['wss://relay.walletconnect.com', false, 'function', ORIGIN]);
    const storage = await H(() => [localStorage.length, sessionStorage.length]);
    assert.deepEqual(storage, [0, 0]);
    assert.ok(!logs.some((line) => line.includes('wc:')), 'pairing URI logged');
    assert.deepEqual(external, []);
    assert.deepEqual(errors, []);
    await context.close();
  }
});
