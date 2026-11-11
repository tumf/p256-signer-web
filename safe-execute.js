import { relayURL } from './site.js';
// Non-sending preparation; the product page requires explicit read-only comparison, with no wallet or persistent signatures.
import ethers from './vendor/ethers.js';
import { readExecutionReceipt } from './safe-execution-receipt.js';
import { transaction, verifyResult } from './safe-request-model.js';
import { readExecutionContext, simulateExecution } from './safe-execution-reader.js';
import { block as readBlock, chainId as readChainId, fresh, parseBlock } from './key-reader.js';
import { candidateFromWire } from './defi-v3-session.js';
import { verifyV3Result } from './defi-v3-result.js';
import { get, hexToBytes, parseJSON } from './defi-v3.js';
const U = ethers.utils, ZERO = ethers.constants.AddressZero;
const SINGLETON = '0xff51a5898e281db6dfc7855790607438df2ca44b';
const types = { SafeTx: [['to', 'address'], ['value', 'uint256'], ['data', 'bytes'], ['operation', 'uint8'],
  ['safeTxGas', 'uint256'], ['baseGas', 'uint256'], ['gasPrice', 'uint256'], ['gasToken', 'address'],
  ['refundReceiver', 'address'], ['nonce', 'uint256']].map(([name, type]) => ({ name, type })) };
const adminABI = new U.Interface(['function addOwnerWithThreshold(address,uint256)']);
const execABI = new U.Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)']);
const reject = message => { throw new Error(message); };
const clone = value => JSON.parse(JSON.stringify(value));
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== keys.split(',').sort().join(',')) reject('Invalid schema');
}
function addr(value) {
  if (typeof value !== 'string') reject('Invalid address');
  const a = U.getAddress(value).toLowerCase();
  if (a === ZERO || BigInt(a) === 1n) reject('Zero/sentinel address');
  return a;
}
function uint(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value) || value.length > 78 || BigInt(value) >= 1n << 256n) reject('Invalid uint256');
  return value;
}
function hex(value, bytes) {
  if (typeof value !== 'string' || !new RegExp(`^0x[0-9a-f]{${bytes * 2}}$`).test(value)) reject('Invalid hex');
  return value;
}
function frozen(value) {
  if (value && typeof value === 'object') { for (const v of Object.values(value)) frozen(v); Object.freeze(value); }
  return value;
}
export function sdkNonce(value) {
  const n = BigInt(uint(value));
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) reject('SDK nonce exceeds MAX_SAFE_INTEGER');
  const result = Number(n);
  if (!Number.isSafeInteger(result) || BigInt(result) !== n) reject('SDK nonce roundtrip');
  return result;
}
export function snapshot(raw) {
  exact(raw, 'chainId,safe,version,singleton,runtime,guard,fallback,modules,owners,threshold,nonce,account,block,generation,attempt');
  if (raw.chainId !== '137' || raw.version !== '1.5.0' || raw.singleton !== SINGLETON
    || raw.runtime !== 'unverified-offline' || raw.guard !== ZERO || raw.fallback !== ZERO
    || !Array.isArray(raw.modules) || raw.modules.length || raw.attempt !== 'none') reject('Unsupported offline profile / pending or UNKNOWN');
  if (!Number.isSafeInteger(raw.generation) || raw.generation < 0) reject('Invalid generation');
  exact(raw.block, 'number,hash'); uint(raw.block.number); hex(raw.block.hash, 32); sdkNonce(raw.nonce);
  if (!Array.isArray(raw.owners) || raw.owners.length < 1 || raw.owners.length > 8
    || !Number.isSafeInteger(raw.threshold) || raw.threshold < 1 || raw.threshold > raw.owners.length) reject('Invalid Owners/threshold');
  const owners = raw.owners.map(o => {
    exact(o, o.kind === 'eoa' ? 'address,kind' : 'address,kind,publicKey,keyId');
    if (!['eoa', 'hybrid'].includes(o.kind)) reject('Unknown Owner kind');
    const a = addr(o.address);
    if (a === addr(raw.safe)) reject('Safe cannot own itself');
    if (o.kind === 'hybrid') {
      hex(o.publicKey, 65);
      if (!o.publicKey.startsWith('0x04') || o.keyId !== U.sha256(o.publicKey).slice(2)) reject('Invalid Hybrid key');
    }
    return { ...o, address: a };
  }).sort((a, b) => a.address.localeCompare(b.address));
  if (new Set(owners.map(o => o.address)).size !== owners.length) reject('Duplicate Owner');
  return frozen({ ...clone(raw), safe: addr(raw.safe), account: addr(raw.account), owners });
}
export function operation(s, input) {
  let tx;
  if (input?.kind === 'native') {
    exact(input, 'kind,recipient,value');
    tx = transaction({ safe: s.safe, recipient: addr(input.recipient), value: uint(input.value), nonce: s.nonce }).body.tx;
  } else if (input?.kind === 'addOwner') {
    exact(input, 'kind,newOwner,newThreshold,confirmed');
    const owner = addr(input.newOwner);
    if (input.confirmed !== true || s.owners.length >= 8 || owner === s.safe || s.owners.some(o => o.address === owner)
      || !Number.isSafeInteger(input.newThreshold) || input.newThreshold < 1 || input.newThreshold > s.owners.length + 1) reject('Owner/threshold not confirmed');
    if (s.owners.filter(o => o.kind === 'eoa').length < s.threshold) reject('Unsupported management: insufficient existing EOA Owners');
    tx = { to: s.safe, value: '0', data: adminABI.encodeFunctionData('addOwnerWithThreshold', [owner, input.newThreshold]),
      operation: '0', safeTxGas: '0', baseGas: '0', gasPrice: '0', gasToken: ZERO, refundReceiver: ZERO, nonce: s.nonce };
  } else reject('Unsupported operation');
  const body = { chainId: '137', safe: s.safe, tx };
  return frozen({ kind: input.kind, body, hash: U._TypedDataEncoder.hash({ chainId: 137, verifyingContract: s.safe }, types, tx) });
}

/** Independent bounded decoder: exact static order and contiguous SDK dynamic tails. */
export function decodeSignatures(bytes, selected) {
  if (!Array.isArray(selected) || selected.length < 1 || selected.length > 8) reject('Invalid selected Owners');
  const sorted = [...selected].sort((a, b) => a.owner.localeCompare(b.owner));
  if (new Set(sorted.map(s => s.owner)).size !== sorted.length) reject('Duplicate encoded Owner');
  const data = U.arrayify(bytes); let end = selected.length * 65;
  if (data.length < end) reject('Truncated signatures');
  for (let i = 0; i < sorted.length; i++) {
    const s = sorted[i], start = i * 65, part = U.hexlify(data.slice(start, start + 65));
    if (s.kind === 'hybrid') {
      const r = BigInt(U.hexlify(data.slice(start, start + 32))), offset = BigInt(U.hexlify(data.slice(start + 32, start + 64)));
      if (r !== BigInt(s.owner) || data[start + 64] !== 0 || offset !== BigInt(end) || end + 32 > data.length) reject('Invalid contract offset/order');
      const len = BigInt(U.hexlify(data.slice(end, end + 32)));
      if (len !== 96n || end + 128 > data.length || U.hexlify(data.slice(end + 32, end + 128)) !== s.signature) reject('Invalid contract inner');
      end += 128;
    } else if (s.kind !== 'eoa' || part !== s.signature) reject('Invalid EOA static signature/order');
  }
  if (end !== data.length) reject('Trailing signature data');
  return true;
}

async function encode(op, selected) {
  const { SafeBaseContract, SafeProvider, EthSafeSignature, EthSafeTransaction, calculateSafeTransactionHash } = await import('@safe-global/protocol-kit');
  const tx = new EthSafeTransaction({ ...op.body.tx, operation: 0, nonce: sdkNonce(op.body.tx.nonce) });
  // No Safe.init: its deployment probes would require chain evidence. Use the SDK's pure ABI encoder,
  // not fabricated eth_getCode success. Live getEncodedTransaction remains gated with the live adapter.
  const provider = await SafeProvider.init({ provider: { request: async () => reject('Offline SDK: RPC forbidden') }, safeVersion: '1.5.0' });
  const contract = new SafeBaseContract(137n, provider, [], '1.5.0', true, undefined, undefined, 'canonical');
  if (contract.getAddress().toLowerCase() !== SINGLETON) reject('SDK singleton drift');
  if (calculateSafeTransactionHash(op.body.safe, tx.data, '1.5.0', 137n) !== op.hash) reject('SDK hash mismatch');
  for (const s of selected) tx.addSignature(new EthSafeSignature(s.owner, s.signature, s.kind === 'hybrid'));
  const signatures = tx.encodedSignatures(); decodeSignatures(signatures, selected);
  const t = op.body.tx, args = [t.to, t.value, t.data, 0, t.safeTxGas, t.baseGas, t.gasPrice, t.gasToken, t.refundReceiver, signatures];
  const data = contract.encode('execTransaction', args);
  if (data !== execABI.encodeFunctionData('execTransaction', args)) reject('Independent calldata mismatch');
  return { data, signatures };
}

const V3_PURPOSE = 'safe-tx-v1.5.0/generic-v1', V3_CODEC = 'hybrid-delegator-1.3.0/raw-p256-msg/v1', V3_MAX_VALIDITY = 120;
const sha256 = bytes => hexToBytes(U.sha256(bytes));
/**
 * v3 Hybrid collection: `wire` is the exact original envelope text, `result` the exact returned result text.
 * Accepts only when the independently recompiled candidate names this Owner, its key and codec, chain 137, this
 * Safe and this exact body with signedDigest == H, the result verifies against that candidate (product validator:
 * metadata, key id, keccak key-id hash, cross-check, low-S, P-256 over SHA-256(H)) and the returned point is the
 * Owner's. Returns the 96-byte HybridDeleGator raw P-256 signature and the envelope's return deadline.
 */
async function collectV3(packet, o, op, now) {
  if (typeof packet.wire !== 'string' || typeof packet.result !== 'string' || packet.wire.length > 16384 || packet.result.length > 16384) reject('Invalid v3 packet');
  let c;
  try { c = candidateFromWire(new TextEncoder().encode(packet.wire), sha256); } catch { reject('Invalid v3 envelope'); }
  const e = c.envelope, issuedAt = Number(e.issuedAt), expiresAt = Number(e.expiresAt);
  if (c.v !== '3' || c.purpose !== V3_PURPOSE || c.codecId !== V3_CODEC || c.chainId !== '137'
    || !/^(0|[1-9][0-9]*)$/.test(e.issuedAt) || !/^(0|[1-9][0-9]*)$/.test(e.expiresAt) || !Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt)
    || expiresAt <= issuedAt || expiresAt - issuedAt > V3_MAX_VALIDITY) reject('Unsupported v3 envelope');
  if (addr(c.signer) !== o.address || c.keyId !== o.keyId || addr(c.safe) !== op.body.safe || c.signedDigest !== op.hash) reject('Changed v3 Safe/Owner/key/hash');
  let tx;
  try {
    const body = get(parseJSON(hexToBytes(e.payloadJson)), 'body'), node = get(body, 'tx');
    tx = Object.fromEntries(node.members.map(([k, v]) => { if (v.t !== 'string') reject('x'); return [k, v.v]; }));
  } catch { reject('Invalid v3 payload'); }
  const t = op.body.tx;
  if (Object.keys(tx).sort().join(',') !== Object.keys(t).sort().join(',') || addr(tx.to) !== t.to || uint(tx.value) !== t.value
    || tx.data.toLowerCase() !== t.data || tx.operation !== t.operation || uint(tx.safeTxGas) !== t.safeTxGas || uint(tx.baseGas) !== t.baseGas
    || uint(tx.gasPrice) !== t.gasPrice || tx.gasToken.toLowerCase() !== t.gasToken || tx.refundReceiver.toLowerCase() !== t.refundReceiver
    || uint(tx.nonce) !== t.nonce) reject('Changed v3 body');
  if (now < issuedAt || now >= expiresAt) reject('Request expired');
  let verified;
  try { verified = verifyV3Result(packet.result, c, { sha256 }); } catch (error) { reject(`v3 result rejected: ${error?.code ?? 'INVALID'}`); }
  if (verified.publicPoint !== o.publicKey || verified.requestId !== e.id) reject('Changed v3 key/Owner');
  return { signature: hex(verified.signerSignature, 96), expires: expiresAt };
}

export class Execution {
  #read; #observe; #advance; #lastObservation; #now; #lastTime; #generation = 0; #snapshot; #input; #operation; #signatures = new Map(); #state = 'EMPTY'; #deadline; #prepared; #preflighted; #attempt;
  constructor({ read, observe, advanceObservation = false, now = () => Math.floor(Date.now() / 1000) }) {
    if (typeof advanceObservation !== 'boolean' || advanceObservation && typeof observe !== 'function') reject('Observation required for advancement');
    this.#read = read; this.#observe = observe; this.#advance = advanceObservation; this.#now = now;
  }
  async #checkObservation(s, g) {
    if (!this.#observe) return;
    const o = await this.#observe(s, this.#lastObservation && { ...this.#lastObservation });
    if (g !== this.#generation) reject('Stale observation');
    exact(o, 'chainId,safe,account,version,singleton,guard,fallback,modules,owners,threshold,nonce,block,liveVerified');
    exact(o.block, 'number,hash,timestamp');
    if (o.liveVerified !== false || typeof o.block.number !== 'bigint' || typeof o.block.timestamp !== 'bigint'
      || o.block.number < BigInt(s.block.number) || o.block.timestamp < 0n
      || !/^0x[0-9a-f]{64}$/.test(o.block.hash) || /^0x0{64}$/.test(o.block.hash)
      || (!this.#advance || o.block.number === BigInt(s.block.number)) && (o.block.number.toString() !== s.block.number || o.block.hash !== s.block.hash)
      || !['chainId','safe','account','version','singleton','guard','fallback','modules','owners','threshold','nonce'].every(k => JSON.stringify(o[k]) === JSON.stringify(s[k])))
      reject('Changed observation');
    const last = this.#lastObservation;
    if (last && (o.block.number < last.number || o.block.timestamp < last.timestamp
      || o.block.number === last.number && (o.block.hash !== last.hash || o.block.timestamp !== last.timestamp))) reject('Changed observation');
    this.#lastObservation = { ...o.block };
  }
  invalidate() {
    this.#generation++; this.#lastObservation = undefined; this.#signatures.clear(); this.#prepared = undefined; this.#preflighted = undefined;
    // A UI reset cannot cancel a wallet request or discard its independent submission lock.
    if (!this.#attempt) this.#state = 'STOPPED';
    else if (this.#state === 'SENDING') this.#state = 'UNKNOWN';
  }
  #time() {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0 || now < this.#lastTime) { this.invalidate(); reject('Invalid clock'); }
    this.#lastTime = now;
    return now;
  }
  view() { return { state: this.#state, count: this.#signatures.size, threshold: this.#snapshot?.threshold, hash: this.#operation?.hash, attempted: !!this.#attempt }; }
  unsigned() { if (!this.#operation || this.#state === 'STOPPED') reject('No current operation'); return clone({ snapshot: this.#snapshot, operation: this.#operation }); }
  async load(input) {
    // ponytail: one submission per instance; cross-page recovery belongs to the trusted test harness.
    if (this.#attempt) reject('Submission already attempted: retain the original intent and read back; do not retry');
    this.invalidate(); const g = this.#generation;
    try {
      const s = snapshot(await this.#read()); if (g !== this.#generation) reject('Stale generation');
      await this.#checkObservation(s, g);
      if (g !== this.#generation) reject('Stale generation');
      const op = operation(s, input); this.#snapshot = s; this.#input = frozen(clone(input)); this.#operation = op;
      this.#lastTime = undefined; const now = this.#time();
      if (now > Number.MAX_SAFE_INTEGER - 120) reject('Invalid clock');
      this.#deadline = now + 120; this.#state = 'COLLECTING'; return this.unsigned();
    } catch (error) { if (g === this.#generation) this.invalidate(); throw error; }
  }
  async #fresh(g) {
    if (!['COLLECTING', 'PREPARED'].includes(this.#state) || g !== this.#generation) reject('Stale generation');
    try {
      if (this.#time() >= this.#deadline) reject('Request expired');
      const s = snapshot(await this.#read());
      // Imported intent stays fixed; the opt-in observer may veto against a newer coherent block.
      if (g !== this.#generation || JSON.stringify(s) !== JSON.stringify(this.#snapshot)
        || JSON.stringify(operation(s, this.#input)) !== JSON.stringify(this.#operation)) reject('Changed snapshot/body/generation');
      await this.#checkObservation(s, g);
    } catch (error) { if (g === this.#generation) this.invalidate(); throw error; }
  }
  async collect(packet) {
    const g = this.#generation;
    // Bound before deep copying untrusted messages; UI JSON text is bounded separately.
    if (JSON.stringify(packet)?.length > 65536) reject('Oversized signature packet');
    packet = clone(packet); await this.#fresh(g);
    const owner = addr(packet.owner), o = this.#snapshot.owners.find(o => o.address === owner);
    if (!o) reject('Nonowner'); if (this.#signatures.has(owner)) reject('duplicate Owner');
    let signature, expires = this.#deadline;
    if (o.kind === 'eoa') {
      exact(packet, 'owner,signature'); signature = hex(packet.signature, 65);
      const sig = U.splitSignature(signature);
      if (![27, 28].includes(Number.parseInt(signature.slice(-2), 16)) || sig.s === '0x' + '00'.repeat(32)
        || BigInt(sig.s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n
        || U.recoverAddress(this.#operation.hash, signature).toLowerCase() !== owner) reject('Invalid EOA typed signature');
    } else if (this.#operation.kind !== 'native') {
      reject('Hybrid management unsupported');
    } else if (packet.wire !== undefined) {
      // v3 generic SafeTx result (docs/public-defi-spec-v1.md §2.1.1): the original request envelope bytes and the
      // returned closed result text, both unchanged. The candidate is recompiled here from the envelope; its signed
      // digest must be this operation's Safe hash and its payload this exact body. Nothing is reinterpreted.
      exact(packet, 'owner,wire,result');
      ({ signature, expires } = await collectV3(packet, o, this.#operation, this.#time()));
    } else {
      exact(packet, 'owner,expected,context,request,result');
      const e = packet.expected;
      exact(e, 'origin,safe,signer,publicKey,keyId,recipient,value,nonce');
      if (addr(e.signer) !== owner || e.publicKey !== o.publicKey || e.keyId !== o.keyId
        || JSON.stringify(transaction(e).body) !== JSON.stringify(this.#operation.body)
        || packet.request.safeTxHash !== this.#operation.hash) reject('Changed Hybrid body/key/Owner');
      signature = await verifyResult(packet.result, packet.request, packet.context, e, this.#time());
      expires = packet.request.expiresAt;
    }
    await this.#fresh(g);
    if (this.#time() >= expires) { this.invalidate(); reject('Request expired'); }
    if (this.#signatures.has(owner)) reject('duplicate Owner');
    if (g !== this.#generation || !['COLLECTING', 'PREPARED'].includes(this.#state)) reject('Stale generation');
    this.#signatures.set(owner, frozen({ owner, kind: o.kind, signature, expires }));
    this.#prepared = undefined; this.#state = 'COLLECTING'; return this.view();
  }
  async prepare(owners = [...this.#signatures.keys()]) {
    const g = this.#generation; await this.#fresh(g);
    if (!Array.isArray(owners) || owners.length !== this.#snapshot.threshold || new Set(owners).size !== owners.length) reject('Select exactly threshold distinct Owners');
    const selected = owners.map(a => this.#signatures.get(addr(a)) || reject('Missing selected signature')).sort((a, b) => a.owner.localeCompare(b.owner));
    if (selected.some(s => this.#time() >= s.expires)) { this.invalidate(); reject('Request expired'); }
    const { data, signatures } = await encode(this.#operation, selected); await this.#fresh(g);
    if (selected.some(s => this.#time() >= s.expires)) { this.invalidate(); reject('Request expired'); }
    if (g !== this.#generation || !['COLLECTING', 'PREPARED'].includes(this.#state)) reject('Stale generation');
    this.#prepared = frozen({ chainId: '0x89', from: this.#snapshot.account, to: this.#snapshot.safe, value: '0x0', data,
      safeTxHash: this.#operation.hash, signatureBytes: signatures, selected, liveVerified: false,
      warning: 'OFFLINE ONLY: runtime, current key membership, contract acceptance, preflight, egress and receipt UNVERIFIED. Not authorization to send.' });
    this.#state = 'PREPARED'; return clone(this.#prepared);
  }
  // Data projection only. It is not a wallet capability or proof of live execution safety.
  async walletRequest() {
    const g = this.#generation, prepared = this.#prepared;
    if (this.#state !== 'PREPARED' || !prepared) reject('Prepare before projecting wallet request');
    await this.#fresh(g);
    if (g !== this.#generation || this.#state !== 'PREPARED' || this.#prepared !== prepared) reject('Stale preparation');
    const now = this.#time();
    if (now >= this.#deadline || prepared.selected.some(s => now >= s.expires)) { this.invalidate(); reject('Request expired'); }
    return Object.fromEntries(['chainId', 'from', 'to', 'value', 'data'].map(k => [k, prepared[k]]));
  }
  async preflight(rpc) {
    const g = this.#generation, prepared = this.#prepared;
    if (this.#state !== 'PREPARED' || !prepared || !this.#observe) reject('Observed preparation required');
    const current = () => g === this.#generation && this.#state === 'PREPARED' && this.#prepared === prepared;
    try {
      const request = await this.walletRequest();
      if (!current() || !this.#lastObservation) reject('Stale preparation');
      const result = await simulateExecution(rpc, { request, block: { ...this.#lastObservation }, now: () => this.#time() }, current);
      await this.#fresh(g);
      if (!current() || this.#time() >= this.#deadline || prepared.selected.some(s => this.#time() >= s.expires)) reject('Stale preparation');
      fresh(result.block, this.#time());
      this.#preflighted = prepared;
      return result;
    } catch (error) { if (g === this.#generation) this.invalidate(); throw error; }
  }
  /**
   * Isolated-fork submission only. Without an explicit adapter the product default stays refused.
   * The relay must answer as anvil (a public Polygon node never does), the profile's source/session blocks must
   * exist with exact hashes and parent linkage (binds this owned fork session, not any chain-137 node), and the
   * wallet must report the same chain, executor and session block (a wallet on the public chain fails here).
   * Only the fixed projection chainId/from/to/value/data is handed over; the wallet owns nonce/gas/fees.
   * A single submission is attempted; any failure after dispatch is UNKNOWN and never retried.
   */
  send(options) {
    if (options === undefined) reject('Live execution unavailable: runtime/preflight/egress/wallet evidence absent');
    exact(options, 'wallet,rpc,fork');
    return this.#send(options);
  }
  async #send(options) {
    const { wallet, rpc } = options, fork = clone(options.fork);
    if (typeof wallet?.request !== 'function' || typeof rpc !== 'function') reject('Isolated fork wallet adapter required');
    exact(fork, 'source,session');
    for (const b of [fork.source, fork.session]) { exact(b, 'number,hash'); uint(b.number); hex(b.hash, 32); if (/^0x0{64}$/.test(b.hash)) reject('Invalid fork profile'); }
    if (BigInt(fork.session.number) !== BigInt(fork.source.number) + 1n || fork.source.hash === fork.session.hash) reject('Invalid fork profile');
    const g = this.#generation, prepared = this.#prepared;
    if (this.#state !== 'PREPARED' || !prepared || !this.#observe || this.#preflighted !== prepared || this.#attempt) reject('Simulated observed preparation required');
    const current = () => g === this.#generation && this.#state === 'PREPARED' && this.#prepared === prepared;
    let request;
    try {
      request = await this.walletRequest(); // fresh authority/anchor observation and expiry
      if (!current() || !this.#lastObservation) reject('Stale preparation');
      const read = async (method, params) => { if (!current()) reject('Stale preparation'); const v = await rpc(method, params); if (!current()) reject('Stale preparation'); return v; };
      const client = await read('web3_clientVersion', []);
      if (typeof client !== 'string' || !/^anvil\//.test(client)) reject('Isolated fork required: relay client is not anvil');
      if (await readChainId(read) !== 137n) reject('Isolated fork required: chain');
      const at = async b => {
        const raw = await read('eth_getBlockByNumber', ['0x' + BigInt(b.number).toString(16), false]), parsed = parseBlock(raw);
        if (parsed.number !== BigInt(b.number) || parsed.hash !== b.hash) reject('Isolated fork required: block identity');
        return raw;
      };
      await at(fork.source); const session = await at(fork.session);
      if (session.parentHash !== fork.source.hash || this.#lastObservation.number < BigInt(fork.session.number)) reject('Isolated fork required: session linkage');
      const ask = async (method, params = []) => { if (!current()) reject('Stale preparation'); const v = await wallet.request({ method, params }); if (!current()) reject('Stale preparation'); return v; };
      if (await ask('eth_chainId') !== '0x89') reject('Wallet chain mismatch');
      const accounts = await ask('eth_accounts');
      if (!Array.isArray(accounts) || !accounts.some(a => typeof a === 'string' && a.toLowerCase() === request.from)) reject('Wallet account mismatch');
      const seen = await ask('eth_getBlockByNumber', ['0x' + BigInt(fork.session.number).toString(16), false]);
      if (!seen || typeof seen !== 'object' || seen.hash !== fork.session.hash) reject('Wallet fork session mismatch');
      await this.#fresh(g);
      const now = this.#time();
      if (!current() || now >= this.#deadline || prepared.selected.some(s => now >= s.expires)) reject('Stale preparation');
    } catch (error) { if (g === this.#generation) this.invalidate(); throw error; }
    const attempt = frozen({ request: { ...request }, safeTxHash: prepared.safeTxHash, nonce: this.#operation.body.tx.nonce });
    this.#attempt = attempt; this.#state = 'SENDING'; this.#signatures.clear(); this.#prepared = undefined; this.#preflighted = undefined;
    let hash;
    try { hash = await wallet.request({ method: 'eth_sendTransaction', params: [{ ...request }] }); }
    catch (error) { this.#state = 'UNKNOWN'; reject(`UNKNOWN: wallet reply failed after submission request; read back by hash, do not retry (${error?.message ?? error})`); }
    if (typeof hash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(hash) || /^0x0{64}$/.test(hash)) { this.#state = 'UNKNOWN'; reject('UNKNOWN: wallet returned no transaction hash; read back, do not retry'); }
    this.#state = 'SENT';
    return clone({ ...attempt, transactionHash: hash.toLowerCase(), liveVerified: false, receiptVerified: false,
      warning: 'Submitted through the isolated fork wallet only. Receipt, nonce and balance readback are separate; not public-chain evidence.' });
  }
}

const parse = (text, max = 65536) => {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > max) reject('JSON size limit');
  return JSON.parse(text);
};
let readId = 0;
export async function safeReadRPC(method, params, fetcher = globalThis.fetch) {
  const balance = method === 'eth_getBalance';
  if (balance && (!Array.isArray(params) || params.length !== 2 || typeof params[0] !== 'string' || !/^0x[0-9a-f]{40}$/.test(params[0]) || /^0x0{40}$/.test(params[0]) || typeof params[1] !== 'string' || !/^0x(0|[1-9a-f][0-9a-f]*)$/.test(params[1]) || params[1].length > 18)) reject('Exact balance block required');
  const lookup = ['eth_getTransactionByHash', 'eth_getTransactionReceipt'].includes(method);
  if (lookup && (!Array.isArray(params) || params.length !== 1 || typeof params[0] !== 'string' || !/^0x[0-9a-f]{64}$/.test(params[0]) || /^0x0{64}$/.test(params[0]))) reject('Exact transaction hash required');
  if (method === 'web3_clientVersion' && (!Array.isArray(params) || params.length)) reject('Exact client version read required');
  if (!lookup && !balance && !['eth_chainId', 'web3_clientVersion', 'eth_getBlockByNumber', 'eth_getCode', 'eth_getStorageAt', 'eth_call'].includes(method)
    || !Array.isArray(params)) reject('Read-only method required');
  const id = ++readId, body = JSON.stringify({ jsonrpc: '2.0', id, method, params });
  if (!Number.isSafeInteger(id) || new TextEncoder().encode(body).length > 32768) reject('Read size limit');
  const abort = new AbortController(); let timer, reader, active = true;
  const run = async () => {
    const response = await fetcher(relayURL('/rpc'), { method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin', referrerPolicy: 'no-referrer', redirect: 'error', cache: 'no-store', signal: abort.signal, body });
    if (!active || !response.ok || !response.body) reject('Read-only relay unavailable');
    reader = response.body.getReader(); const decoder = new TextDecoder('utf-8', { fatal: true });
    let text = '', size = 0;
    while (active) {
      const { done, value } = await reader.read();
      if (!active) reject('Read expired');
      if (done) break;
      size += value.byteLength;
      if (size > 2_000_000) reject('Read response size limit');
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    const result = JSON.parse(text);
    exact(result, 'jsonrpc,id,result');
    if (result.jsonrpc !== '2.0' || result.id !== id) reject('Read response mismatch');
    return result.result;
  };
  try { return await Promise.race([run(), new Promise((_, fail) => {
    timer = setTimeout(() => fail(new Error('Read timeout')), 10000);
  })]); }
  finally { active = false; clearTimeout(timer); abort.abort(); if (reader) void reader.cancel().catch(() => {}); }
}
// ponytail: fork dispatch requires a harness-injected fixed-endpoint adapter; an ambient wallet
// can switch from a fork to public Polygon between reads despite sharing chain ID 137.
export function mount(doc = document, now, rpc = safeReadRPC, wallet = () => undefined) {
  const el = id => doc.getElementById(id);
  let imported, prepared, simulated, receiptIntent, busy = false, revision = 0;
  const observe = async (s, current, previous) => {
    const read = async (method, params) => {
      if (!current()) reject('Stale observation');
      const value = await rpc(method, params);
      if (!current()) reject('Stale observation');
      return value;
    };
    const anchors = [{ number: BigInt(s.block.number), hash: s.block.hash }, ...(previous ? [previous] : [])];
    const checkAnchors = async () => {
      for (const anchor of anchors) {
        const b = await readBlock(read, anchor.number);
        if (b.number !== anchor.number || b.hash !== anchor.hash || anchor.timestamp !== undefined && b.timestamp !== anchor.timestamp) reject('Changed observation anchor');
      }
    };
    await checkAnchors();
    const result = await readExecutionContext(read, { safe: s.safe, account: s.account, owners: s.owners,
      now: now || (() => Math.floor(Date.now() / 1000)) });
    await checkAnchors(); return result;
  };
  const model = new Execution({ read: async () => imported, now, advanceObservation: true, observe: (s, previous) => {
    const r = revision;
    return observe(s, () => r === revision, previous);
  } });
  const render = () => {
    const v = model.view(); el('status').textContent = v.attempted
      ? `${v.state} — 送信試行を保持。停止・入力変更では取り消せません。再送不可・元の取引hashの読取り照合のみ。SafeTxHash: ${v.hash}`
      : `${v.state} — ${v.count} / ${v.threshold ?? '—'} Owner承認（元blockと最新権限のRPC照合必須・送信不可）`;
    el('load').disabled = busy || v.attempted; el('observe').disabled = busy;
    el('check-receipt').disabled = busy || !receiptIntent; el('receipt-hash').disabled = busy;
    el('packet-file').disabled = busy || v.state !== 'COLLECTING';
    el('collect').disabled = busy || v.state !== 'COLLECTING'; el('prepare').disabled = busy || v.state !== 'COLLECTING' || v.count < v.threshold;
    el('export').disabled = busy || !prepared;
    el('preflight').disabled = busy || !prepared || v.state !== 'PREPARED';
    // Fork-only: a simulated preparation, an explicit fork profile and an injected EIP-1193 wallet. Never default.
    el('execute').disabled = busy || !prepared || v.state !== 'PREPARED' || simulated !== prepared || !el('fork-profile').value.trim() || !wallet();
  };
  const clear = () => {
    revision++; busy = false; model.invalidate(); prepared = undefined; simulated = undefined;
    if (!model.view().attempted) { receiptIntent = undefined; el('sent').textContent = ''; }
    el('receipt-result').textContent = ''; el('preflight-result').textContent = ''; el('signature').value = ''; el('packet-file').value = ''; el('prepared').textContent = ''; el('preview').textContent = ''; el('observation').textContent = ''; el('error').textContent = ''; render();
  };
  const action = (fn, reset = false, clearsPrepared = true) => async () => {
    if (busy) return;
    if (reset) clear();
    const r = ++revision, current = () => r === revision;
    busy = true; el('preflight-result').textContent = ''; render(); el('error').textContent = '';
    try { await fn(current); } catch (e) { if (current()) { if (clearsPrepared) { prepared = undefined; el('prepared').textContent = ''; } if (model.view().state === 'STOPPED') el('preview').textContent = ''; el('error').textContent = e.message; } }
    finally { if (current()) { busy = false; render(); } }
  };
  el('load').addEventListener('click', action(async current => {
    imported = snapshot(parse(el('snapshot').value));
    const input = el('kind').value === 'native' ? { kind: 'native', recipient: el('recipient').value.trim(), value: el('value').value.trim() }
      : { kind: 'addOwner', newOwner: el('new-owner').value.trim(), newThreshold: Number(el('new-threshold').value), confirmed: el('confirm').checked };
    const result = await model.load(input);
    if (current()) el('preview').textContent = JSON.stringify(result, null, 2);
  }, true));
  el('observe').addEventListener('click', action(async current => {
    const s = snapshot(parse(el('snapshot').value));
    const observed = await observe(s, current);
    if (current()) el('observation').textContent = JSON.stringify(observed, (_key, value) =>
      typeof value === 'bigint' ? value.toString() : value, 2);
  }, true));
  el('packet-file').addEventListener('change', action(async current => {
    const files = Array.from(el('packet-file').files || []);
    el('signature').value = ''; el('packet-file').value = '';
    if (model.view().state !== 'COLLECTING') reject('Load operation before importing a packet');
    if (!files?.length) return;
    if (files.length !== 1 || !Number.isSafeInteger(files[0].size) || files[0].size < 1 || files[0].size > 65536) reject('Packet file size limit');
    const text = await files[0].text();
    if (!current()) return;
    parse(text); // Size/JSON syntax only. Owner, transaction and signature verification remain explicit collect.
    el('signature').value = text;
  }));
  el('collect').addEventListener('click', action(async current => { await model.collect(parse(el('signature').value)); if (current()) el('signature').value = ''; }));
  el('prepare').addEventListener('click', action(async current => {
    const result = await model.prepare(); if (!current()) return;
    prepared = result; const { operation: op, snapshot: s } = model.unsigned();
    const added = op.kind === 'addOwner' ? adminABI.decodeFunctionData('addOwnerWithThreshold',op.body.tx.data) : null; receiptIntent = { request: Object.fromEntries(['chainId','from','to','value','data'].map(k => [k, result[k]])), safeTxHash: result.safeTxHash, nonce: op.body.tx.nonce, effect: op.kind === 'native' ? { kind: 'native', recipient: op.body.tx.to, value: op.body.tx.value } : { kind: 'addOwner', owners: s.owners.map(o=>o.address), threshold: s.threshold, newOwner: added[0].toLowerCase(), newThreshold: Number(added[1].toString()) } };
    el('receipt-result').textContent = ''; el('prepared').textContent = JSON.stringify(prepared, null, 2);
  }));
  el('preflight').addEventListener('click', action(async current => {
    if (!prepared) reject('Prepared operation required');
    const result = await model.preflight(rpc);
    if (current()) { simulated = prepared; el('preflight-result').textContent = JSON.stringify(result, (_k, value) => typeof value === 'bigint' ? value.toString() : value, 2); }
  }));
  el('execute').addEventListener('click', action(async current => {
    if (!prepared || simulated !== prepared) reject('Simulated preparation required');
    const fork = parse(el('fork-profile').value, 4096), provider = wallet();
    if (!provider || typeof provider.request !== 'function') reject('No EIP-1193 wallet; isolated fork wallet required');
    try {
      const result = await model.send({ wallet: provider, rpc, fork });
      // A dispatched attempt cannot be replaced by load/reset; retain even a late hash for its readback.
      if (current()) el('receipt-hash').value = result.transactionHash;
      el('sent').textContent = JSON.stringify(result, null, 2);
    } finally {
      if (model.view().attempted) { prepared = undefined; simulated = undefined; el('prepared').textContent = ''; render(); }
    }
  }));
  el('fork-profile').addEventListener('input', () => { if (!busy) render(); });
  el('export').addEventListener('click', action(async current => {
    // Recheck original expiry/snapshot before exporting bytes; never auto-refresh or send.
    const result = await model.prepare(prepared.selected.map(s => s.owner)); if (!current()) return;
    const walletRequest = await model.walletRequest(); if (!current()) return;
    prepared = result;
    const url = URL.createObjectURL(new Blob([JSON.stringify({ ...prepared, walletRequest }, null, 2)], { type: 'application/json' }));
    const a = doc.createElement('a'); a.href = url; a.download = 'offline-safe-execution.json'; a.click(); URL.revokeObjectURL(url);
  }));
  el('check-receipt').addEventListener('click', action(async current => {
    el('receipt-result').textContent = '';
    if (!receiptIntent) reject('Prepare trusted intent before receipt lookup');
    const result = await readExecutionReceipt(rpc, receiptIntent, el('receipt-hash').value.trim(), current);
    if (current()) el('receipt-result').textContent = JSON.stringify(result, (_k, v) => typeof v === 'bigint' ? v.toString() : v, 2);
  }, false, false));
  el('receipt-hash').addEventListener('input', () => { if (busy) return; revision++; busy = false; el('receipt-result').textContent = ''; el('error').textContent = ''; render(); });
  el('reset').addEventListener('click', clear);
  for (const input of doc.querySelectorAll('[data-invalidates]')) input.addEventListener('input', clear);
  render(); return model;
}
if (typeof document !== 'undefined' && document.getElementById('safe-execution')) mount();
