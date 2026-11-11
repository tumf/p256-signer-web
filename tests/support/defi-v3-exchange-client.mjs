// Run-unique bounded file exchange client for the DEBUG Simulator round trip (docs/mvp2-web-native-roundtrip.md).
//
// An SDK-like client for the unchanged createV3BridgeSession: connect() settles from the grant record the app's
// composition publishes after the explicit permission, request() writes the exact outer JSON-RPC bytes once and
// completes from the one result record the app's port writes at the explicit 「Webへ返却」. The result text is handed
// to the session unchanged, so the independent defi-v3-result.js verifies the app's actual bytes. Nothing here signs,
// retries, regenerates, or consumes another run: every record is bound to the run id, the run-derived topic, the typed
// RPC id, the method, the chain and the original params text. Neither the topic nor any signature is printed.
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, linkSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { bytesToHex } from '../../defi-v3.js';
import {
  BRIDGE_ORIGIN, CHAIN, CHAIN_ID, METHODS, SIGN_METHOD, V3SessionError, createSessionConfig, createV3BridgeSession,
} from '../../defi-v3-session.js';
import { V3ResultError } from '../../defi-v3-result.js';

export const FILES = Object.freeze({
  run: 'run.json', app: 'app.json', grant: 'grant.json', request: 'request.json', result: 'result.json',
  verdict: 'web-verdict.json',
});
export const CODEC_ID = 'hybrid-delegator-1.3.0/raw-p256-msg/v1';
export const SAFE_TX_PURPOSE = 'safe-tx-v1.5.0/generic-v1';
/** The fixture's trusted context: chain 137, Safe nonce 7 (DeFiSessionSimulatorFixture.context) unless run.json names one. */
export const FIXTURE_NONCE = '7';
/** SafeDeFiCompiler.maxValiditySeconds: the app refuses a longer issue-to-return window. */
export const MAX_VALIDITY_SECONDS = 120;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const HEX32 = /^0x[0-9a-f]{64}$/;
const BARE32 = /^[0-9a-f]{64}$/;
const RPC_CODES = new Set([-32601, -32602, -32000, 4001, 4100, 4200]);

export const sha256 = (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest());
const utf8 = (text) => new TextEncoder().encode(text);
const hexOf = (text) => bytesToHex(utf8(text));

export class ExchangeError extends Error {
  constructor(code) {
    super(`exchange: ${code}`);
    this.name = 'ExchangeError';
    this.code = code;
  }
}

const fail = (code) => { throw new ExchangeError(code); };

/** The run-derived session topic: both sides derive it, so a record of another run never matches. */
export function topicFor(run) {
  return bytesToHex(sha256(utf8(`p256-defi-exchange-topic:${run}`))).slice(2);
}

/** Creates `name` exactly once (hard link of a private temp file: a second writer fails, nothing is overwritten). */
export function writeOnce(dir, name, object) {
  const final = join(dir, name);
  const temp = join(dir, `.${name}.${randomUUID()}.tmp`);
  writeFileSync(temp, JSON.stringify(object), { mode: 0o600 });
  try {
    linkSync(temp, final);
  } catch (error) {
    fail(error?.code === 'EEXIST' ? `EXISTS:${name}` : `WRITE:${name}`);
  } finally {
    unlinkSync(temp);
  }
}

function readRecord(dir, name) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(join(dir, name), 'utf8'));
  } catch {
    fail(`MALFORMED:${name}`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) fail(`MALFORMED:${name}`);
  return parsed;
}

const str = (value) => (typeof value === 'string' ? value : null);

/**
 * Writes the run record the app binds to (the orchestrator does this; exported for the offline tests). `context`
 * (fork runs) adds the run-bound Safe the UI test types and the trusted Safe nonce the fixture context uses.
 */
export function writeRun(dir, run, context = null) {
  if (!RUN_ID.test(run)) fail('INVALID_RUN');
  const record = { run, chain: CHAIN };
  if (context !== null) {
    if (!ADDRESS.test(context.safe ?? '') || !DECIMAL.test(context.safeNonce ?? '')) fail('INVALID_RUN');
    record.safe = context.safe;
    record.safeNonce = context.safeNonce;
  }
  writeOnce(dir, FILES.run, record);
}

/**
 * The original SafeTx candidate for the fixture context (chain 137; nonce 7 unless given); Web owns it, the app never
 * builds it. `validity` seconds (<= the app compiler's maximum) is the issue-to-return window.
 */
export function buildSafeTxWire({ safe, signer, keyId, binding, id = randomUUID(), issuedAt, variant = 1,
  nonce = FIXTURE_NONCE, validity = 60 }) {
  if (!ADDRESS.test(safe) || !ADDRESS.test(signer) || !BARE32.test(keyId) || !HEX32.test(binding)) fail('INVALID_CANDIDATE');
  if (!Number.isSafeInteger(issuedAt) || issuedAt <= 0 || !DECIMAL.test(nonce) || !Number.isSafeInteger(validity)
      || validity < 1 || validity > MAX_VALIDITY_SECONDS) fail('INVALID_CANDIDATE');
  const to = '0x' + '33'.repeat(19) + (variant & 0xff).toString(16).padStart(2, '0');
  const zero = '0x' + '00'.repeat(20);
  const params = `[{"from":"${safe}","to":"${to}","value":"0xde0b6b3a7640000"}]`;
  const body = `{"tx":{"to":"${to}","value":"1000000000000000000","data":"0x","operation":"0","safeTxGas":"0",`
    + `"baseGas":"0","gasPrice":"0","gasToken":"${zero}","refundReceiver":"${zero}","nonce":"${nonce}"}}`;
  const payload = `{"chainId":"${CHAIN_ID}","safe":"${safe}","source":{"method":"eth_sendTransaction",`
    + `"idJson":"${hexOf('1')}","paramsJson":"${hexOf(params)}","origin":"https://app.example","chainRef":"${CHAIN}"},`
    + `"body":${body}}`;
  const fields = [['v', '3'], ['purpose', SAFE_TX_PURPOSE], ['codecId', CODEC_ID], ['id', id], ['keyId', keyId],
    ['binding', binding], ['signer', signer], ['issuedAt', String(issuedAt)], ['expiresAt', String(issuedAt + validity)],
    ['payloadJson', hexOf(payload)]];
  return utf8('{' + fields.map(([k, v]) => `"${k}":"${v}"`).join(',') + '}');
}

/**
 * The SDK-like client over one exchange directory for one run. Shape expected by createV3BridgeSession:
 *   connect() -> { approval }, request() -> result text, disconnect(), on/off, session.get().
 * Bounded waiting only (`timeoutMs` per wait); one request per run; the first result record settles it.
 */
export function createExchangeClient({ dir, run, timeoutMs = 60_000, pollMs = 200 }) {
  if (!RUN_ID.test(run ?? '')) fail('INVALID_RUN');
  const topic = topicFor(run);
  const calls = [];
  let session = null;
  let grant = null;
  let requested = false;

  async function waitFor(name) {
    const deadline = Date.now() + timeoutMs;
    while (!existsSync(join(dir, name))) {
      if (Date.now() > deadline) fail(`TIMEOUT:${name}`);
      await sleep(pollMs);
    }
    return readRecord(dir, name);
  }

  function adoptGrant(record) {
    const s = record.session, g = record.grant, ns = s?.namespaces?.eip155;
    if (record.run !== run || s?.topic !== topic) fail('GRANT_MISMATCH');
    if (typeof g !== 'object' || g === null || !ADDRESS.test(str(g.signer) ?? '') || !ADDRESS.test(str(g.safe) ?? '')
        || !BARE32.test(str(g.keyId) ?? '') || !HEX32.test(str(g.binding) ?? '') || g.chainId !== CHAIN_ID) {
      fail('GRANT_MISMATCH');
    }
    if (!Number.isSafeInteger(s.expiry) || typeof ns !== 'object' || ns === null) fail('GRANT_MISMATCH');
    // The session shape is the app's claim; the unchanged session validator judges it (never this client).
    session = Object.freeze({
      topic, expiry: s.expiry, peer: { metadata: { url: str(s.peer?.metadata?.url) } },
      namespaces: { eip155: {
        accounts: Array.isArray(ns.accounts) ? [...ns.accounts] : [], methods: Array.isArray(ns.methods) ? [...ns.methods] : [],
        events: Array.isArray(ns.events) ? [...ns.events] : [], ...(Array.isArray(ns.chains) ? { chains: [...ns.chains] } : {}),
      } },
    });
    grant = Object.freeze({ safe: g.safe, signer: g.signer, keyId: g.keyId, binding: g.binding, chainId: g.chainId });
    return session;
  }

  /** The published grant (public identity only); waits for the app's record. */
  async function peekGrant() {
    if (!grant) adoptGrant(await waitFor(FILES.grant));
    return grant;
  }

  async function connect(args) {
    calls.push('connect');
    if (typeof args?.requiredNamespaces !== 'object') fail('INVALID_CONNECT');
    return { approval: async () => (session ?? adoptGrant(await waitFor(FILES.grant))) };
  }

  async function request(args) {
    calls.push('request');
    const method = args?.request?.method, params = args?.request?.params;
    if (!session || args?.topic !== topic || args?.chainId !== CHAIN || typeof method !== 'string'
        || !Array.isArray(params)) fail('REQUEST_MISMATCH');
    if (requested) fail('ONE_REQUEST_PER_RUN');
    requested = true;
    const id = 1;
    const paramsText = JSON.stringify(params);
    const raw = `{"jsonrpc":"2.0","id":${id},"method":${JSON.stringify(method)},"params":${paramsText}}`;
    const typedId = { t: 'integer', v: String(id) };
    writeOnce(dir, FILES.request, { run, topic, chain: CHAIN, id: typedId, method, raw });
    const record = await waitFor(FILES.result);
    const sameId = typeof record.id === 'object' && record.id !== null && record.id.t === typedId.t
      && record.id.v === typedId.v;
    if (record.run !== run || record.topic !== topic || !sameId || record.method !== method || record.chain !== CHAIN
        || record.params !== paramsText) fail('RESULT_MISMATCH');
    if (record.error !== undefined) {
      const code = record.error?.code;
      if (!Number.isInteger(code) || !RPC_CODES.has(code) || record.result !== undefined) fail('RESULT_MISMATCH');
      const error = new Error('bridge error');
      error.code = code;
      throw error;
    }
    const text = str(record.result);
    if (text === null || bytesToHex(sha256(utf8(text))).slice(2) !== record.resultSha256) fail('RESULT_MISMATCH');
    return text;
  }

  async function disconnect() { calls.push('disconnect'); }

  return Object.freeze({
    calls, peekGrant, connect, request, disconnect, on() {}, off() {},
    session: { get: (t) => (session && t === topic ? session : undefined) },
  });
}

/** Nonsecret verdict: ids, hashes, counts and codes only (never topic, binding, signature or result text). */
function verdictOf(run, outcome, client, session) {
  const outcomes = session ? session.inspect().outcomes : {};
  return Object.freeze({
    run, ...outcome, outcomes,
    counts: { connects: client.calls.filter((c) => c === 'connect').length,
      requests: client.calls.filter((c) => c === 'request').length,
      verified: Object.values(outcomes).filter((o) => o === 'verified').length },
  });
}

/**
 * One explicit Web round trip: wait for the composition's grant, connect the unchanged session with a fixture config,
 * compile the original candidate here, request once and verify the app's returned bytes independently.
 */
export async function runExchange({ dir, run, safe, signer = null, timeoutMs = 60_000, pollMs = 200, variant = 1,
  nonce = FIXTURE_NONCE, validity = 60, clock = () => Math.floor(Date.now() / 1000) }) {
  const client = createExchangeClient({ dir, run, timeoutMs, pollMs });
  let session = null;
  try {
    const grant = await client.peekGrant();
    // Web's own expectation of the Safe (and Signer when given) must match the published grant before any write.
    if (grant.safe !== safe || (signer !== null && grant.signer !== signer)) fail('GRANT_MISMATCH');
    const config = createSessionConfig({ signer: signer ?? grant.signer, safe });
    session = createV3BridgeSession({ client, config, sha256, clock });
    const view = await session.connect(async () => {});
    if (client.calls.includes('request')) fail('SIGNED_ON_CONNECT');
    const wire = buildSafeTxWire({ safe: config.safe, signer: config.signer, keyId: grant.keyId, binding: grant.binding,
      issuedAt: clock(), variant, nonce, validity });
    const verified = await session.request(wire);
    const resultSha256 = bytesToHex(sha256(utf8(readRecord(dir, FILES.result).result))).slice(2);
    return verdictOf(run, { status: 'verified', account: view.account, requestId: verified.requestId,
      commitment: verified.commitment, signedDigest: verified.signedDigest, keyId: verified.keyId, resultSha256 },
    client, session);
  } catch (error) {
    const code = error instanceof V3SessionError || error instanceof V3ResultError || error instanceof ExchangeError
      ? error.code : 'UNEXPECTED';
    return verdictOf(run, { status: 'failed', code, error: error?.name ?? 'Error' }, client, session);
  } finally {
    await session?.dispose();
  }
}

function argument(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const dir = argument('--dir');
  const run = argument('--run');
  const safe = argument('--safe', '0x' + '11'.repeat(20));
  const signer = argument('--signer', null);
  const timeoutMs = Number(argument('--timeout-ms', '600000'));
  const nonce = argument('--nonce', FIXTURE_NONCE);
  const validity = Number(argument('--validity-seconds', '60'));
  if (!dir || !run) {
    console.error('usage: --dir <exchange dir> --run <uuid> [--safe 0x..] [--signer 0x..] [--nonce N] [--validity-seconds N] [--timeout-ms N]');
    process.exit(2);
  }
  const verdict = await runExchange({ dir, run, safe, signer, timeoutMs, nonce, validity });
  try { writeOnce(dir, FILES.verdict, verdict); } catch {}
  console.log(JSON.stringify(verdict));
  process.exit(verdict.status === 'verified' ? 0 : 1);
}
