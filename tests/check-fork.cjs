'use strict';
// Guarded fork harness: its OWN loopback Anvil (chain 137) forked at Polygon block 95559460 runs the
// production controller/wallet/model with one ephemeral software P-256 public key, two salts and Anvil's local unlocked
// test account. It compares the captured transaction with the independent oracle and verifies deployed
// readback, then reverts the snapshot and stops Anvil. Network-backed: an operational observation, never a
// local gate. Unavailable fork data is reported UNKNOWN (exit 3), never PASS.
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const oracle = require('./support/oracle.cjs');

const FORK_BLOCK = 95559460;
const FORK_BLOCK_HASH = '0x464d98ef2bc90b455ce7dc52344bda4c95ccf395d523f02a7054a9a155d79729';
const ANVIL_ARGS = ['--host', '127.0.0.1', '--chain-id', '137', '--fork-block-number', String(FORK_BLOCK),
  '--no-storage-caching', '--silent'];
// Blockchain signing credentials; Anvil itself is launched with a scrubbed environment (PATH/HOME only).
const CREDENTIAL_KEYS = /PRIVATE_KEY|MNEMONIC|SEED_PHRASE|KEYSTORE|ETH_FROM|ETH_PASSWORD|^FOUNDRY_|^ANVIL_|^CAST_|DEPLOYER/i;
const PROXY = JSON.parse(fs.readFileSync(path.join(__dirname, '../vendor/proxy.json'), 'utf8')).bytecode;

// PUBLIC d=1 software point at a nonzero salt (vectors.json d1-pattern), used by the offline guard tests.
const FIXTURE_HANDOFF = Object.freeze({
  version: 1, recipe: 'polygon-137/hybrid-delegator-1.3.0/erc1967-create2/v1', chainId: 137,
  publicKey: '0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
  keyID: '698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be',
  salt: '0x0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186',
  expectedAddress: '0x1E8145d2351F4dF56093898517DAA227b2e614D9',
});

function requireLoopback(url) {
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error(`refusing non-loopback endpoint ${url}`); }
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1' || parsed.username || parsed.password
      || parsed.search || (parsed.pathname !== '/' && parsed.pathname !== '')) {
    throw new Error(`refusing non-loopback endpoint ${url}`);
  }
  return url;
}

function requireClient(version) {
  if (typeof version !== 'string' || !/^anvil\//i.test(version)) throw new Error(`refusing client ${version}: anvil only`);
}

function requireChain(chainId) {
  if (chainId !== '0x89') throw new Error(`refusing chain ${chainId}: chain 137 fork only`);
}

function requireNoCredentials(env) {
  const found = Object.keys(env).filter((key) => CREDENTIAL_KEYS.test(key) && env[key]);
  if (found.length) throw new Error(`refusing to run with credential-like environment: ${found.join(', ')}`);
}

/** The fork source is read-only public HTTPS without embedded credentials or API-key queries. */
function requireForkSource(url) {
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error('fork source must be a public HTTPS URL'); }
  if (parsed.protocol !== 'https:') throw new Error('fork source must be a public HTTPS URL');
  if (parsed.username || parsed.password || parsed.search) throw new Error('fork source must not carry credentials');
  return url;
}

async function productPlan(handoff) {
  const model = await import('../model.js');
  return model.buildPlan(model.parseHandoff(JSON.stringify(handoff)));
}

/** Only the exact product plan bytes may be submitted. */
function requireProductTransaction(plan, tx) {
  if (!tx || tx.to !== plan.transaction.to || tx.data !== plan.transaction.data || tx.value !== '0x0') {
    throw new Error('refusing a transaction that is not the product plan output');
  }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)); });
    server.on('error', reject);
  });
}

function rpcClient(url) {
  requireLoopback(url);
  let id = 0;
  return async (method, params = []) => {
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }) });
    const body = await response.json();
    if (body.error) throw Object.assign(new Error(body.error.message), { code: body.error.code });
    return body.result;
  };
}

function ephemeralHandoff(model) {
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const point = '0x' + publicKey.export({ format: 'der', type: 'spki' }).subarray(-65).toString('hex');
  const salt = '0x' + crypto.randomBytes(32).toString('hex');
  const keyID = crypto.createHash('sha256').update(Buffer.from(point.slice(2), 'hex')).digest('hex');
  const expectedAddress = oracle.derive(point, salt, PROXY).address;
  return { version: 1, recipe: model.RECIPE, chainId: 137, publicKey: point, keyID, salt, expectedAddress };
}

async function main(evidencePath) {
  const evidence = { suite: 'check-fork', forkBlock: FORK_BLOCK, result: 'UNKNOWN',
    scope: 'Two-salt controller/Anvil-adapter observation; not browser, standard-wallet, persisted-iPhone-row or physical-key acceptance',
    steps: {} };
  const write = () => evidencePath && fs.writeFileSync(evidencePath, JSON.stringify(evidence, (k, v) =>
    (typeof v === 'bigint' ? v.toString() : v), 2) + '\n');
  requireNoCredentials(process.env);
  const source = requireForkSource(process.env.FORK_RPC_URL || 'https://polygon.drpc.org');
  const port = await freePort();
  const url = requireLoopback(`http://127.0.0.1:${port}`);
  const anvil = spawn('anvil', [...ANVIL_ARGS, '--port', String(port), '--fork-url', source],
    { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: process.env.PATH, HOME: process.env.HOME } });
  const rpc = rpcClient(url);
  let snapshot = null;
  try {
    let version = null;
    for (let i = 0; i < 50 && !version; i++) {
      try { version = await rpc('web3_clientVersion'); } catch { await new Promise((r) => setTimeout(r, 300)); }
    }
    if (!version) {
      evidence.reason = 'fork unavailable (Anvil did not become ready from the historical Polygon RPC)';
      write();
      return 3;
    }
    requireClient(version);
    requireChain(await rpc('eth_chainId'));
    const fork = await rpc('eth_getBlockByNumber', ['0x' + FORK_BLOCK.toString(16), false]);
    if (!fork || fork.hash !== FORK_BLOCK_HASH) throw new Error('fork block hash differs from the pinned block');
    evidence.steps.anvil = { version, chainId: '0x89', forkBlockHash: fork.hash };
    snapshot = await rpc('evm_snapshot');
    const [account] = await rpc('eth_accounts');
    const model = await import('../model.js');
    const { RegistrationController } = await import('../controller.js');
    const { WalletManager } = await import('../wallet.js');
    const first = ephemeralHandoff(model);
    const secondSalt = '0x' + crypto.randomBytes(32).toString('hex');
    if (secondSalt === first.salt) throw new Error('distinct salts required');
    const second = { ...first, salt: secondSalt,
      expectedAddress: oracle.derive(first.publicKey, secondSalt, PROXY).address };
    if (second.expectedAddress === first.expectedAddress) throw new Error('distinct addresses required');
    evidence.steps.deployments = [];
    for (const handoff of [first, second]) {
      const plan = await productPlan(handoff);
      const captured = [];
      // EIP-1193 adapter: Anvil's local unlocked test account is the only signer, on loopback only.
      const provider = {
        on() {}, removeListener() {},
        async request({ method, params }) {
          if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [account];
          if (method === 'eth_chainId') return rpc('eth_chainId');
          if (method !== 'eth_sendTransaction') throw Object.assign(new Error('unsupported'), { code: 4200 });
          requireProductTransaction(plan, params[0]);
          captured.push(params[0]);
          return rpc('eth_sendTransaction', params);
        },
      };
      const target = Object.assign(new EventTarget(), { Event, ethereum: provider });
      const { AttemptStore } = await import('../attempt-store.js');
      const { validateRecord } = await import('../controller.js');
      const run = async () => {
        let controller;
        const wallet = new WalletManager({ win: target, config: null, origin: 'http://127.0.0.1',
          onChange: (e) => controller && controller.walletChanged(e) });
        // The production store over a minimal in-process IndexedDB stand-in (Node has none); native storage
        // behaviour is proved in Chromium by check-attempt-store.cjs, not by this chain-execution harness.
        const store = new AttemptStore({ indexedDB: memoryIndexedDB(), readLegacy: () => null, validateRecord });
        controller = new RegistrationController({ rpc, wallet, store, uuid: () => crypto.randomUUID() });
        await controller.loadAttempt();
        wallet.start();
        controller.prepare(JSON.stringify(handoff));
        controller.selectWallet('legacy');
        await controller.connect();
        await controller.inspect();
        return controller;
      };
      const controller = await run();
      // Wallet-delegated action: a coherent review is ready; Anvil's account (the wallet) picks nonce/gas/fees.
      if (controller.phase() !== 'ready') throw new Error(`inspection did not reach ready: ${controller.phase()}`);
      await controller.send();
      for (let i = 0; i < 50 && !controller.attempt.hash; i++) await new Promise((r) => setTimeout(r, 100));
      await rpc('anvil_mine', ['0x2']);
      await controller.refresh();
      const tx = captured[0];
      const decoded = oracle.decodeDeploy(tx.data, PROXY);
      const independent = oracle.derive(handoff.publicKey, handoff.salt, PROXY);
      const deploy = {
        handoff, sends: captured.length, phase: controller.phase(), hash: controller.attempt.hash,
        oracleCalldata: independent.calldata === tx.data, oracleAddress: independent.address === plan.address,
        decodedSalt: decoded.salt === handoff.salt, settlement: controller.settlement,
      };
      evidence.steps.deployments.push(deploy);
      if (captured.length !== 1 || controller.phase() !== 'success' || !deploy.oracleCalldata
          || !deploy.oracleAddress || !deploy.decodedSalt || controller.settlement.readback !== 'deployed') {
        throw new Error('fork deployment did not verify');
      }
      const readback = await model.readback(rpc, plan, 'latest');
      deploy.readback = readback;
      // Already-deployed repeat: readback-only, no further send.
      const repeat = await run();
      deploy.repeat = { phase: repeat.phase(), sends: captured.length };
      if (repeat.phase() !== 'deployed' || captured.length !== 1 || readback.state !== 'deployed') {
        throw new Error('already-deployed repeat did not stay read-only');
      }
    }
    // Recheck both after the second deployment, not only each immediately after its own send.
    for (const deploy of evidence.steps.deployments) {
      deploy.finalReadback = await model.readback(rpc, await productPlan(deploy.handoff), 'latest');
      if (deploy.finalReadback.state !== 'deployed') throw new Error('cross-Signer readback changed');
    }
    // Preserve the original single-deployment evidence keys for existing consumers.
    evidence.steps.deploy = evidence.steps.deployments[0];
    evidence.steps.readback = evidence.steps.deploy.readback;
    evidence.steps.repeat = evidence.steps.deploy.repeat;
    evidence.result = 'PASS';
    write();
    return 0;
  } catch (error) {
    evidence.result = 'FAIL';
    evidence.reason = String(error && error.message).slice(0, 300);
    write();
    return 1;
  } finally {
    if (snapshot !== null) { try { await rpc('evm_revert', [snapshot]); } catch { /* process stops anyway */ } }
    anvil.kill('SIGTERM');
  }
}

/**
 * Minimal single-process IndexedDB stand-in for the Node fork harness: one versioned database whose readwrite
 * transactions buffer puts and apply them only at completion; abort discards them. Events are dispatched
 * asynchronously like the native API. It is a test double, not native storage evidence.
 */
function memoryIndexedDB() {
  const data = new Map();
  let created = false;
  const later = (fn) => setTimeout(fn, 0);
  const transaction = (mode, options = {}) => {
    const pending = new Map();
    const tx = { durability: mode === 'readwrite' ? options.durability || 'default' : 'default', done: false,
      abort() {
        if (tx.done) throw new Error('InvalidStateError');
        tx.done = true;
        later(() => tx.onabort && tx.onabort());
      },
      objectStore() {
        return {
          get(key) {
            const request = {};
            later(() => {
              if (tx.done) return;
              request.result = data.has(key) ? structuredClone(data.get(key)) : undefined;
              if (request.onsuccess) request.onsuccess({ target: request });
              later(() => {
                if (tx.done) return;
                tx.done = true;
                for (const [k, v] of pending) data.set(k, v);
                if (tx.oncomplete) tx.oncomplete();
              });
            });
            return request;
          },
          put(value, key) { pending.set(key, structuredClone(value)); return {}; },
        };
      } };
    return tx;
  };
  return {
    open(name, version) {
      const request = {};
      later(() => {
        const db = { version, objectStoreNames: created ? ['state'] : [], close() {},
          transaction: (store, mode, options) => transaction(mode, options) };
        request.result = db;
        if (!created) {
          let aborted = false;
          request.transaction = { abort() { aborted = true; } };
          db.createObjectStore = () => ({ put(value, key) { data.set(key, structuredClone(value)); } });
          if (request.onupgradeneeded) request.onupgradeneeded({ target: request, oldVersion: 0 });
          if (aborted) { data.clear(); return request.onerror && request.onerror({}); }
          created = true;
          db.objectStoreNames = ['state'];
        }
        if (request.onsuccess) request.onsuccess({ target: request });
      });
      return request;
    },
  };
}

module.exports = { memoryIndexedDB, ANVIL_ARGS, FIXTURE_HANDOFF, FORK_BLOCK, requireLoopback, requireClient, requireChain,
  requireNoCredentials, requireForkSource, requireProductTransaction, productPlan, main };

if (require.main === module) {
  main(process.argv[2]).then((code) => process.exit(code), (error) => {
    console.error(String(error && error.message));
    process.exit(1);
  });
}
