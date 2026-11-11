// Owned isolated-fork Safe round trip for one app-returned v3 result (docs/mvp2-safe-fork-roundtrip.md). Test-only.
//
// `setup`: starts this process's OWN loopback Anvil (chain 137, the pinned Polygon fork block of check-fork.cjs, scrubbed
// environment, no credentials), deploys the DEBUG home fixture's Signer row (the public d=1 software key at the zero
// salt, through the unchanged registration plan and the real factory), creates a Safe v1.5.0 proxy owned only by that
// Signer (threshold 1) through the canonical proxy factory, funds it from Anvil's unlocked test account and records the
// run-bound context (`fork.json`). `finish`: imports the app's actual returned bytes from the exchange records through
// the product `Execution` (v3 collection), prepares with the Safe ProtocolKit encoder, preflights by eth_call on the
// fork, persists the collected result and a durable send reservation, submits once through a guarded wallet adapter,
// and reads the receipt, nonce and balances back. Nothing is signed here for the app run; cancellation, mismatch or a
// failed durable save leaves zero sends. `selftest` proves the same pipeline on the same fork with an EPHEMERAL test key
// and its own Safe (never the app's result; labelled as such).
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import ethers from '../../vendor/ethers.js';
import { buildPlan, parseHandoff, readback } from '../../model.js';
import { Execution, snapshot as checkSnapshot } from '../../safe-execute.js';
import { readExecutionContext } from '../../safe-execution-reader.js';
import { readExecutionReceipt } from '../../safe-execution-receipt.js';
import { block as readBlock } from '../../key-reader.js';
import { bytesToHex } from '../../defi-v3.js';
import { candidateFromWire } from '../../defi-v3-session.js';
import { RESULT_FIELDS } from '../../defi-v3-result.js';
import { CODEC_ID, FILES as EXCHANGE, SAFE_TX_PURPOSE, buildSafeTxWire, topicFor, writeOnce } from './defi-v3-exchange-client.mjs';

const require = createRequire(import.meta.url);
const guard = require('../check-fork.cjs');
const U = ethers.utils, ZERO = ethers.constants.AddressZero;
const APP = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
const PROXY_PIN = JSON.parse(fs.readFileSync(path.resolve(APP, 'tests/fixtures/safe150-proxy.json'), 'utf8'));

export const FILES = Object.freeze({ fork: 'fork.json', collected: 'collected.json', attempt: 'attempt.json', sent: 'sent.json',
  finish: 'finish.json', teardown: 'teardown.json', log: 'anvil.log' });
export const SINGLETON = '0xff51a5898e281db6dfc7855790607438df2ca44b';
export const PROXY_FACTORY = PROXY_PIN.factoryDeployment.address.toLowerCase();
/** The DEBUG home fixture's planned Signer row (SimulatorFixture.fixturePlannedAddress): d=1 public point, zero salt. */
export const FIXTURE_HANDOFF = Object.freeze({ ...guard.FIXTURE_HANDOFF, salt: '0x' + '00'.repeat(32),
  expectedAddress: '0x0e16A8196C3CFA5b9539181f60EB5Ab2784fe227' });
/** The fixture's one delivered request: destination variant 1, exactly 1 POL (DeFiSessionSimulatorFixture.payload). */
export const FIXTURE_INTENT = Object.freeze({ recipient: '0x' + '33'.repeat(19) + '01', value: '1000000000000000000' });
export const FUNDING_WEI = '0x' + (2n * 10n ** 18n).toString(16);
const SOURCE_BLOCK = Object.freeze({ number: String(guard.FORK_BLOCK), hash: '0x464d98ef2bc90b455ce7dc52344bda4c95ccf395d523f02a7054a9a155d79729' });

const safeABI = new U.Interface(['function setup(address[],uint256,address,bytes,address,address,uint256,address)',
  'function nonce() view returns(uint256)', 'function getOwners() view returns(address[])', 'function getThreshold() view returns(uint256)']);
const factoryABI = new U.Interface(['function createProxyWithNonce(address,bytes,uint256) returns(address)']);
export const sha256 = (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest());
const sha256hex = (text) => createHash('sha256').update(text).digest('hex');
const now = () => Math.floor(Date.now() / 1000);

export class ForkError extends Error {
  constructor(code, detail = '') { super(`fork roundtrip: ${code}${detail ? ` (${detail})` : ''}`); this.name = 'ForkError'; this.code = code; }
}
const fail = (code, detail) => { throw new ForkError(code, detail); };

// ---------- records ----------

function readJSON(dir, name) {
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')); } catch { fail(`MALFORMED:${name}`); }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) fail(`MALFORMED:${name}`);
  return parsed;
}

/** Durable write-once: private temp file, fsync, hard link (EEXIST on a second writer), directory fsync. */
export function persist(dir, name, object) {
  const final = path.join(dir, name), temp = path.join(dir, `.${name}.${randomUUID()}.tmp`);
  let fd = null;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeSync(fd, JSON.stringify(object, null, 2) + '\n');
    fs.fsyncSync(fd);
    fs.closeSync(fd); fd = null;
    fs.linkSync(temp, final);
    const dfd = fs.openSync(dir, 'r');
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  } catch (error) {
    fail(error?.code === 'EEXIST' ? `EXISTS:${name}` : `WRITE:${name}`, error?.code);
  } finally {
    if (fd !== null) fs.closeSync(fd);
    try { fs.unlinkSync(temp); } catch {}
  }
  return object;
}

// ---------- owned Anvil ----------

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)); });
    server.on('error', reject);
  });
}

export function rpcClient(url) {
  guard.requireLoopback(url);
  let id = 0;
  return async (method, params = []) => {
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }) });
    const body = await response.json();
    if (body.error) throw Object.assign(new Error(body.error.message), { code: body.error.code });
    return body.result;
  };
}

async function waitReceipt(rpc, hash) {
  for (let i = 0; i < 100; i++) {
    const receipt = await rpc('eth_getTransactionReceipt', [hash]);
    if (receipt) { if (receipt.status !== '0x1') fail('TX_FAILED', hash); return receipt; }
    await sleep(100);
  }
  return fail('TX_PENDING', hash);
}

async function blockAt(rpc, number) {
  const raw = await rpc('eth_getBlockByNumber', ['0x' + BigInt(number).toString(16), false]);
  if (!raw || !/^0x[0-9a-f]{64}$/.test(raw.hash ?? '')) fail('BLOCK_UNAVAILABLE', String(number));
  return { number: String(BigInt(raw.number)), hash: raw.hash, parentHash: raw.parentHash };
}

/** Starts this process's own Anvil fork (detached so a later step can finish against it) and pins its identity. */
export async function startAnvil({ dir, source }) {
  guard.requireNoCredentials(process.env);
  const forkSource = guard.requireForkSource(source || process.env.FORK_RPC_URL || 'https://polygon.drpc.org');
  const port = await freePort();
  const url = guard.requireLoopback(`http://127.0.0.1:${port}`);
  const log = fs.openSync(path.join(dir, FILES.log), 'a', 0o600);
  // Anvil's well-known default accounts carry code (EIP-7702 delegations) on the real Polygon fork; the product reader
  // requires a plain EOA executor, so this fork gets fresh random local test accounts (unlocked, never printed).
  const child = spawn('anvil', [...guard.ANVIL_ARGS, '--mnemonic-random', '--port', String(port), '--fork-url', forkSource],
    { detached: true, stdio: ['ignore', log, log], env: { PATH: process.env.PATH, HOME: process.env.HOME } });
  fs.closeSync(log);
  child.unref();
  const rpc = rpcClient(url);
  let clientVersion = null;
  for (let i = 0; i < 200 && !clientVersion; i++) {
    if (child.exitCode !== null) break;
    try { clientVersion = await rpc('web3_clientVersion'); } catch { await sleep(300); }
  }
  if (!clientVersion) { try { process.kill(child.pid, 'SIGTERM'); } catch {} fail('FORK_UNAVAILABLE', 'Anvil did not become ready from the pinned Polygon source'); }
  try {
    guard.requireClient(clientVersion);
    guard.requireChain(await rpc('eth_chainId'));
    const sourceBlock = await blockAt(rpc, SOURCE_BLOCK.number);
    if (sourceBlock.hash !== SOURCE_BLOCK.hash) fail('FORK_PIN', 'fork block hash differs from the pinned block');
    // Forked Anvil continues from the source block's clock; the product readers require fresh wall-clock blocks.
    await rpc('evm_setTime', [now()]);
  } catch (error) { try { process.kill(child.pid, 'SIGTERM'); } catch {} throw error; }
  return { pid: child.pid, port, url, clientVersion, forkSource };
}

function processCommand(pid) {
  try { return execFileSync('ps', ['-o', 'command=', '-p', String(pid)], { encoding: 'utf8' }).trim(); } catch { return ''; }
}

/** The recorded fork must still be OUR Anvil: live pid running anvil on the recorded port, same client, chain, blocks. */
export async function assertOwned(fork, rpc) {
  const command = processCommand(fork.pid);
  if (!/(^|\/)anvil(\s|$)/.test(command) || !command.includes(`--port ${fork.port}`) || !command.includes(`--chain-id 137`)) fail('NOT_OWNED', 'pid is not our anvil');
  if (await rpc('web3_clientVersion') !== fork.clientVersion) fail('NOT_OWNED', 'client version');
  guard.requireChain(await rpc('eth_chainId'));
  for (const b of [fork.source, fork.session]) {
    const seen = await blockAt(rpc, b.number);
    if (seen.hash !== b.hash) fail('NOT_OWNED', `block ${b.number}`);
  }
  if ((await blockAt(rpc, fork.session.number)).parentHash !== fork.source.hash) fail('NOT_OWNED', 'session linkage');
  return true;
}

export async function stopAnvil({ dir }) {
  const fork = readJSON(dir, FILES.fork);
  const command = processCommand(fork.pid);
  if (!command) { return persist(dir, FILES.teardown, { pid: fork.pid, stoppedAt: now(), state: 'already-gone' }); }
  if (!/(^|\/)anvil(\s|$)/.test(command) || !command.includes(`--port ${fork.port}`)) fail('NOT_OWNED', 'refusing to signal a foreign process');
  process.kill(fork.pid, 'SIGTERM');
  for (let i = 0; i < 50 && processCommand(fork.pid); i++) await sleep(100);
  return persist(dir, FILES.teardown, { pid: fork.pid, stoppedAt: now(), state: processCommand(fork.pid) ? 'signalled' : 'stopped' });
}

// ---------- real deployments on the owned fork (unchanged contracts and factories) ----------

export async function deploySigner(rpc, account, handoff = FIXTURE_HANDOFF) {
  const plan = buildPlan(parseHandoff(JSON.stringify(handoff)));
  if (plan.address.toLowerCase() !== handoff.expectedAddress.toLowerCase()) fail('SIGNER_PLAN', 'planned address differs from the fixture row');
  if (await rpc('eth_getCode', [plan.address, 'latest']) !== '0x') fail('SIGNER_EXISTS', 'fresh fork expected');
  const hash = await rpc('eth_sendTransaction', [{ from: account, to: plan.transaction.to, data: plan.transaction.data, value: '0x0' }]);
  await waitReceipt(rpc, hash);
  const state = await readback(rpc, plan, 'latest');
  if (state.state !== 'deployed') fail('SIGNER_READBACK', state.state);
  return { address: plan.address.toLowerCase(), keyId: handoff.keyID, publicKey: handoff.publicKey, salt: handoff.salt, deployTx: hash };
}

/** Safe v1.5.0 proxy: canonical factory, pinned singleton, `setup([owner], 1, 0, 0x, 0, 0, 0, 0)`; address cross-computed. */
export async function deploySafe(rpc, account, owner) {
  const initializer = safeABI.encodeFunctionData('setup', [[owner], 1, ZERO, '0x', ZERO, ZERO, 0, ZERO]);
  const saltNonce = BigInt('0x' + randomBytes(32).toString('hex'));
  const salt = U.keccak256(U.concat([U.keccak256(initializer), U.zeroPad(U.hexlify(saltNonce), 32)]));
  const creation = U.hexConcat([PROXY_PIN.creationCode, U.defaultAbiCoder.encode(['address'], [SINGLETON])]);
  const expected = U.getCreate2Address(PROXY_FACTORY, salt, U.keccak256(creation)).toLowerCase();
  const data = factoryABI.encodeFunctionData('createProxyWithNonce', [SINGLETON, initializer, saltNonce]);
  const hash = await rpc('eth_sendTransaction', [{ from: account, to: PROXY_FACTORY, data, value: '0x0' }]);
  await waitReceipt(rpc, hash);
  if (U.keccak256(await rpc('eth_getCode', [expected, 'latest'])) !== U.keccak256(PROXY_PIN.runtime)) fail('SAFE_CODE', 'proxy runtime differs from the pin');
  if (await rpc('eth_getStorageAt', [expected, U.hexZeroPad('0x00', 32), 'latest']) !== U.hexZeroPad(SINGLETON, 32)) fail('SAFE_SINGLETON');
  const call = async (name) => safeABI.decodeFunctionResult(name, await rpc('eth_call', [{ to: expected, data: safeABI.encodeFunctionData(name) }, 'latest']));
  const owners = (await call('getOwners'))[0].map((a) => a.toLowerCase());
  if (owners.length !== 1 || owners[0] !== owner || (await call('getThreshold'))[0].toString() !== '1' || (await call('nonce'))[0].toString() !== '0') fail('SAFE_SETUP');
  return { address: expected, saltNonce: saltNonce.toString(), deployTx: hash, owners, threshold: 1 };
}

export async function fund(rpc, account, to, value = FUNDING_WEI) {
  const hash = await rpc('eth_sendTransaction', [{ from: account, to, value }]);
  await waitReceipt(rpc, hash);
  return hash;
}

/** The product reader's acquisition, shaped as the page's import (`snapshot()`-validated). */
export async function readSnapshot(rpc, { safe, account, owner, clock = now }) {
  const o = await readExecutionContext(rpc, { safe, account, owners: [owner], now: clock });
  return checkSnapshot({ chainId: o.chainId, safe: o.safe, version: o.version, singleton: o.singleton, runtime: 'unverified-offline',
    guard: o.guard, fallback: o.fallback, modules: [], owners: o.owners.map((x) => ({ ...x })), threshold: o.threshold, nonce: o.nonce,
    account: o.account, block: { number: o.block.number.toString(), hash: o.block.hash }, generation: 0, attempt: 'none' });
}

/** Sets up the owned fork for one run and records its exact context. The directory must be fresh (mode 0700). */
export async function setup({ dir, source, handoff = FIXTURE_HANDOFF }) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (fs.existsSync(path.join(dir, FILES.fork))) fail('EXISTS:fork.json');
  const anvil = await startAnvil({ dir, source });
  const rpc = rpcClient(anvil.url);
  try {
    // The executor must be a plain EOA for the product reader; a well-known Anvil account may carry (EIP-7702) code on
    // the real Polygon fork, so the first code-free unlocked test account is used and recorded.
    const accounts = await rpc('eth_accounts');
    let account = null;
    for (const candidate of accounts) {
      if (/^0x[0-9a-fA-F]{40}$/.test(candidate) && await rpc('eth_getCode', [candidate, 'latest']) === '0x') { account = candidate; break; }
    }
    if (account === null) fail('NO_ACCOUNT', 'no code-free unlocked test account');
    const signer = await deploySigner(rpc, account.toLowerCase(), handoff);
    const safe = await deploySafe(rpc, account.toLowerCase(), signer.address);
    safe.fundTx = await fund(rpc, account.toLowerCase(), safe.address);
    const session = await blockAt(rpc, BigInt(SOURCE_BLOCK.number) + 1n);
    if (session.parentHash !== SOURCE_BLOCK.hash) fail('FORK_PIN', 'session block does not extend the pinned block');
    const owner = { address: signer.address, kind: 'hybrid', publicKey: signer.publicKey, keyId: signer.keyId };
    const snapshot = await readSnapshot(rpc, { safe: safe.address, account: account.toLowerCase(), owner });
    const record = { version: 1, pid: anvil.pid, port: anvil.port, url: anvil.url, clientVersion: anvil.clientVersion, forkSource: anvil.forkSource,
      chainId: '137', source: { number: SOURCE_BLOCK.number, hash: SOURCE_BLOCK.hash }, session: { number: session.number, hash: session.hash },
      account: account.toLowerCase(), signer, safe: { ...safe, nonce: snapshot.nonce }, snapshot, startedAt: now() };
    return persist(dir, FILES.fork, record);
  } catch (error) {
    try { process.kill(anvil.pid, 'SIGTERM'); } catch {}
    throw error;
  }
}

// ---------- collection inputs from the exchange records ----------

/** The exact original envelope text from the request/result records (never re-serialized from parsed values alone). */
export function extractWire(request, result) {
  if (typeof request.raw !== 'string' || typeof result.params !== 'string') fail('RECORD_SHAPE');
  let outer;
  try { outer = JSON.parse(request.raw); } catch { fail('RECORD_SHAPE'); }
  if (!Array.isArray(outer?.params) || outer.params.length !== 1 || typeof outer.params[0] !== 'object') fail('RECORD_SHAPE');
  const wire = JSON.stringify(outer.params[0]);
  if (result.params !== `[${wire}]` || !request.raw.endsWith(`,"params":${result.params}}`)) fail('PARAMS_MISMATCH');
  return wire;
}

/**
 * Reads the exchange records of `run` and decides what may be collected: a cancelled/error reply yields no inputs;
 * identity (run, topic, chain, method, typed id, params) must agree; the Web verdict must verify exactly this result.
 */
export function collectionInputs(exchangeDir, run) {
  const topic = topicFor(run);
  const runRecord = readJSON(exchangeDir, EXCHANGE.run);
  if (runRecord.run !== run || runRecord.chain !== 'eip155:137' || !/^0x[0-9a-f]{40}$/.test(runRecord.safe ?? '')
      || !/^(0|[1-9][0-9]*)$/.test(runRecord.safeNonce ?? '')) fail('RUN_MISMATCH');
  const request = readJSON(exchangeDir, EXCHANGE.request), result = readJSON(exchangeDir, EXCHANGE.result);
  for (const record of [request, result]) {
    if (record.run !== run || record.topic !== topic || record.chain !== 'eip155:137' || record.method !== 'p256_signSafeRequestV3') fail('IDENTITY_MISMATCH');
  }
  if (JSON.stringify(request.id) !== JSON.stringify(result.id) || typeof result.id?.t !== 'string' || typeof result.id?.v !== 'string') fail('IDENTITY_MISMATCH');
  const wire = extractWire(request, result);
  if (result.error !== undefined) {
    if (result.result !== undefined) fail('IDENTITY_MISMATCH');
    return { status: 'cancelled', code: result.error?.code ?? null, run, safe: runRecord.safe, safeNonce: runRecord.safeNonce };
  }
  if (typeof result.result !== 'string' || result.resultSha256 !== sha256hex(result.result)) fail('RESULT_DIGEST');
  const envelope = JSON.parse(wire);
  const verdict = readJSON(exchangeDir, EXCHANGE.verdict);
  if (verdict.run !== run || verdict.status !== 'verified' || verdict.resultSha256 !== result.resultSha256 || verdict.requestId !== envelope.id
      || verdict.counts?.verified !== 1 || verdict.counts?.requests !== 1) fail('WEB_VERDICT');
  return { status: 'verified', run, wire, result: result.result, resultSha256: result.resultSha256, requestId: envelope.id,
    safe: runRecord.safe, safeNonce: runRecord.safeNonce };
}

// ---------- execution against the owned fork ----------

/** EIP-1193 stand-in over the owned fork: Anvil's unlocked account signs; a send needs the exact durable reservation. */
export function guardedWallet({ rpc, account, dir }) {
  const wallet = { sends: 0, calls: [] };
  wallet.provider = { on() {}, removeListener() {}, async request({ method, params = [] }) {
    wallet.calls.push(method);
    if (method === 'eth_chainId') return rpc('eth_chainId');
    if (method === 'eth_accounts' || method === 'eth_requestAccounts') return [account];
    if (method === 'eth_getBlockByNumber') return rpc('eth_getBlockByNumber', params);
    if (method !== 'eth_sendTransaction') throw Object.assign(new Error('unsupported'), { code: 4200 });
    let attempt;
    try { attempt = readJSON(dir, FILES.attempt); } catch { throw Object.assign(new Error('no durable send reservation'), { code: 4100 }); }
    const tx = params[0];
    if (attempt.state !== 'SENDING' || !tx || ['chainId', 'from', 'to', 'value', 'data'].some((k) => attempt.request?.[k] !== tx[k]) || Object.keys(tx).length !== 5) {
      throw Object.assign(new Error('transaction differs from the durable reservation'), { code: 4100 });
    }
    if (fs.existsSync(path.join(dir, FILES.sent))) throw Object.assign(new Error('already sent'), { code: 4100 });
    wallet.sends++;
    return rpc('eth_sendTransaction', [{ from: tx.from, to: tx.to, value: tx.value, data: tx.data }]);
  } };
  return wallet;
}

function observer(rpc, clock) {
  return async (s, previous) => {
    const anchors = [{ number: BigInt(s.block.number), hash: s.block.hash }, ...(previous ? [previous] : [])];
    const check = async () => {
      for (const a of anchors) {
        const b = await readBlock(rpc, a.number);
        if (b.number !== a.number || b.hash !== a.hash || (a.timestamp !== undefined && b.timestamp !== a.timestamp)) fail('OBSERVATION_ANCHOR');
      }
    };
    await check();
    const result = await readExecutionContext(rpc, { safe: s.safe, account: s.account, owners: s.owners, now: clock });
    await check();
    return result;
  };
}

/**
 * Collects one verified v3 result into the product Execution, prepares, preflights, persists, sends once and reads back.
 * `inputs` = { wire, result } (exact texts); `intent` = the expected native transfer; `fork` = fork.json. Writes
 * collected.json, attempt.json (before the send), sent.json and finish.json into `dir`.
 */
export async function execute({ dir, fork, rpc, inputs, intent = FIXTURE_INTENT, clock = now, label = 'app-result', ownership = assertOwned }) {
  const record = { version: 1, mode: label, run: inputs.run ?? null, requestId: inputs.requestId ?? null, status: 'FAIL', sends: 0, steps: [] };
  const step = (name, value = true) => { record.steps.push(name); if (value !== true) record[name] = value; };
  const wallet = guardedWallet({ rpc, account: fork.account, dir });
  try {
    if (fs.existsSync(path.join(dir, FILES.attempt))) {
      record.status = fs.existsSync(path.join(dir, FILES.sent)) ? 'ALREADY_SENT' : 'LOCKED_UNKNOWN';
      record.error = 'a durable send reservation exists: never retried; read back the recorded attempt instead';
      return record;
    }
    await ownership(fork, rpc); step('owned');
    await rpc('anvil_mine', ['0x1']); // a fresh block for the product readers' freshness bound
    const owner = { address: fork.signer.address, kind: 'hybrid', publicKey: fork.signer.publicKey, keyId: fork.signer.keyId };
    const snapshot = await readSnapshot(rpc, { safe: fork.safe.address, account: fork.account, owner, clock });
    if (inputs.safe !== undefined && snapshot.safe !== inputs.safe) fail('SAFE_MISMATCH', 'fork Safe differs from the run record');
    if (inputs.safeNonce !== undefined && snapshot.nonce !== inputs.safeNonce) fail('NONCE_DRIFT', `Safe nonce ${snapshot.nonce} != run ${inputs.safeNonce}`);
    step('snapshot', { nonce: snapshot.nonce, block: snapshot.block });
    // The Web's own intended operation, independently of the signed bytes; the collection binds the two by hash.
    const candidate = candidateFromWire(new TextEncoder().encode(inputs.wire), sha256);
    const payload = JSON.parse(Buffer.from(candidate.envelope.payloadJson.slice(2), 'hex').toString('utf8'));
    const tx = payload?.body?.tx ?? fail('WIRE_SHAPE');
    if (tx.to?.toLowerCase() !== intent.recipient || tx.value !== intent.value || tx.data !== '0x') fail('INTENT_MISMATCH', 'the request body is not the fixture intent');
    const model = new Execution({ read: async () => snapshot, observe: observer(rpc, clock), advanceObservation: true, now: clock });
    const loaded = await model.load({ kind: 'native', recipient: intent.recipient, value: intent.value });
    step('loaded', { safeTxHash: loaded.operation.hash });
    await model.collect({ owner: owner.address, wire: inputs.wire, result: inputs.result }); step('collected');
    const prepared = await model.prepare([owner.address]); step('prepared', { calldataSha256: sha256hex(prepared.data), signatureBytesSha256: sha256hex(prepared.signatureBytes) });
    const preflight = await model.preflight(rpc); step('preflighted', { block: preflight.block.number.toString() });
    persist(dir, FILES.collected, { version: 1, mode: label, run: inputs.run ?? null, requestId: inputs.requestId ?? null, safe: snapshot.safe,
      signer: owner.address, keyId: owner.keyId, nonce: snapshot.nonce, safeTxHash: loaded.operation.hash, resultSha256: inputs.resultSha256 ?? sha256hex(inputs.result),
      wire: inputs.wire, result: inputs.result, signatureBytesSha256: record.prepared.signatureBytesSha256, calldataSha256: record.prepared.calldataSha256, collectedAt: clock() });
    step('persisted');
    const request = await model.walletRequest();
    const reservation = persist(dir, FILES.attempt, { version: 1, mode: label, run: inputs.run ?? null, safeTxHash: loaded.operation.hash, nonce: snapshot.nonce,
      request, state: 'SENDING', reservedAt: clock() });
    step('reserved');
    let sent;
    try {
      sent = await model.send({ wallet: wallet.provider, rpc, fork: { source: fork.source, session: fork.session } });
    } catch (error) {
      record.status = model.view().state === 'UNKNOWN' ? 'UNKNOWN' : 'FAIL';
      record.error = String(error?.message ?? error).slice(0, 300);
      record.sends = wallet.sends;
      return record;
    }
    persist(dir, FILES.sent, { ...sent, mode: label, sentAt: clock() });
    step('sent', { transactionHash: sent.transactionHash });
    await rpc('anvil_mine', ['0x3']);
    const receipt = await readExecutionReceipt(rpc, { request: reservation.request, safeTxHash: loaded.operation.hash, nonce: snapshot.nonce,
      effect: { kind: 'native', recipient: intent.recipient, value: intent.value } }, sent.transactionHash);
    step('receipt', { inclusion: receipt.inclusion.number.toString(), nonce: receipt.nonce, balances: receipt.balances, receiptVerified: receipt.receiptVerified });
    const after = await readSnapshot(rpc, { safe: fork.safe.address, account: fork.account, owner, clock });
    if (BigInt(after.nonce) !== BigInt(snapshot.nonce) + 1n) fail('NONCE_READBACK', after.nonce);
    step('readback', { nonce: after.nonce, block: after.block });
    record.status = 'PASS';
    record.sends = wallet.sends;
    record.transactionHash = sent.transactionHash;
    record.safeTxHash = loaded.operation.hash;
    record.request = reservation.request;
    return record;
  } catch (error) {
    record.error = error instanceof ForkError ? error.message : String(error?.message ?? error).slice(0, 300);
    record.sends = wallet.sends;
    return record;
  } finally {
    record.finishedAt = clock();
    try { persist(dir, FILES.finish, record); } catch { /* the finish record is evidence only; the attempt record is the lock */ }
  }
}

async function waitForRecords(exchangeDir, waitMs) {
  const deadline = Date.now() + waitMs;
  while (!fs.existsSync(path.join(exchangeDir, EXCHANGE.result)) || !(fs.existsSync(path.join(exchangeDir, EXCHANGE.verdict))
      || JSON.parse(fs.readFileSync(path.join(exchangeDir, EXCHANGE.result), 'utf8')).error !== undefined)) {
    if (Date.now() > deadline) fail('TIMEOUT:records');
    await sleep(250);
  }
}

/** `finish`: the app run. Waits (bounded) for the exchange result and Web verdict, then executes exactly once. */
export async function finish({ dir, waitMs = 0, clock = now }) {
  const fork = readJSON(dir, FILES.fork);
  const exchangeDir = path.join(dir, 'exchange');
  const run = readJSON(exchangeDir, EXCHANGE.run).run;
  if (waitMs > 0) await waitForRecords(exchangeDir, waitMs);
  const rpc = rpcClient(fork.url);
  let inputs;
  try { inputs = collectionInputs(exchangeDir, run); } catch (error) {
    return persist(dir, FILES.finish, { version: 1, mode: 'app-result', run, status: 'REFUSED', sends: 0, error: error.message, finishedAt: clock() });
  }
  if (inputs.status === 'cancelled') {
    return persist(dir, FILES.finish, { version: 1, mode: 'app-result', run, status: 'CANCELLED', code: inputs.code, sends: 0, finishedAt: clock() });
  }
  return execute({ dir, fork, rpc, inputs, clock });
}

// ---------- selftest with an EPHEMERAL key (never the app's result) ----------

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** Signs H like the app codec (P-256 over SHA-256(H), low S) and encodes the closed eleven-field result. */
export async function testResult(wire, key, publicKey) {
  const candidate = candidateFromWire(new TextEncoder().encode(wire), sha256);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(candidate.signedDigest.slice(2), 'hex')));
  let s = BigInt('0x' + Buffer.from(raw.slice(32)).toString('hex'));
  if (s > N / 2n) s = N - s;
  const rawSignature = '0x' + Buffer.from(raw.slice(0, 32)).toString('hex') + s.toString(16).padStart(64, '0');
  const values = { v: '3', purpose: candidate.purpose, requestId: candidate.requestId, keyId: candidate.keyId, codecId: candidate.codecId,
    binding: candidate.binding, commitment: candidate.commitment, signedDigest: candidate.signedDigest, publicPoint: publicKey, rawSignature,
    signerSignature: U.hexConcat([U.keccak256(U.toUtf8Bytes(candidate.keyId)), rawSignature]) };
  return '{' + RESULT_FIELDS.map((k) => `"${k}":"${values[k]}"`).join(',') + '}';
}

export async function ephemeralHandoff() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicKey = bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
  const keyID = U.sha256(publicKey).slice(2);
  const salt = '0x' + randomBytes(32).toString('hex');
  const draft = { version: 1, recipe: guard.FIXTURE_HANDOFF.recipe, chainId: 137, publicKey, keyID, salt };
  return { pair, handoff: { ...draft, expectedAddress: buildPlan(draft).address } };
}

/** Same fork pipeline, own Anvil, ephemeral software key: proves on-fork acceptance of the raw P-256 contract signature. */
export async function selftest({ dir, source, clock = now }) {
  const { pair, handoff } = await ephemeralHandoff();
  const fork = await setup({ dir, source, handoff });
  try {
    const wire = Buffer.from(buildSafeTxWire({ safe: fork.safe.address, signer: fork.signer.address, keyId: fork.signer.keyId,
      binding: '0x' + randomBytes(32).toString('hex'), issuedAt: clock(), nonce: fork.safe.nonce, validity: 120 })).toString('utf8');
    const result = await testResult(wire, pair.privateKey, fork.signer.publicKey);
    const rpc = rpcClient(fork.url);
    return await execute({ dir, fork, rpc, inputs: { wire, result, requestId: JSON.parse(wire).id, safe: fork.safe.address, safeNonce: fork.safe.nonce },
      clock, label: 'selftest-ephemeral-key' });
  } finally {
    await stopAnvil({ dir });
  }
}

// ---------- CLI ----------

function argument(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

const publicView = (record) => JSON.stringify(record, (k, v) => (['wire', 'result', 'signatureBytes', 'data'].includes(k) ? undefined : v), 2);

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const command = process.argv[2], dir = argument('--dir');
  if (!dir || !['setup', 'finish', 'stop', 'selftest'].includes(command)) {
    console.error('usage: safe-fork-roundtrip.mjs setup|finish|stop|selftest --dir <private run dir> [--fork-source https://...] [--wait-ms N]');
    process.exit(2);
  }
  try {
    let record;
    if (command === 'setup') record = await setup({ dir, source: argument('--fork-source') });
    else if (command === 'finish') record = await finish({ dir, waitMs: Number(argument('--wait-ms', '0')) });
    else if (command === 'stop') record = await stopAnvil({ dir });
    else record = await selftest({ dir, source: argument('--fork-source') });
    console.log(publicView(record));
    process.exit(command === 'finish' || command === 'selftest' ? (record.status === 'PASS' ? 0 : 1) : 0);
  } catch (error) {
    console.error(process.env.P256_FORK_DEBUG ? (error?.stack ?? String(error)) : String(error?.message ?? error));
    process.exit(error?.code === 'FORK_UNAVAILABLE' ? 3 : 1);
  }
}
