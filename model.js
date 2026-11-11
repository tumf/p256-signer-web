// Public deployment model: strict v1 handoff import, the fixed HybridDeleGator recipe of one closed chain (the same
// Factory, implementation, proxy and CREATE2 address on every chain; each chain its own recipe ID and implementation
// runtime), block-bound read-only inspection and settlement classification. No wallet, no signing, no transport of its
// own: every chain read goes through the caller's `rpc(method, params)` for the handoff's own chain. New (v2)
// operations delegate nonce, gas and fees to the selected wallet; the fee policy below survives only for historical
// v1 records.
import ethers from './vendor/ethers.js';
import proxy from './vendor/proxy.json' with { type: 'json' };
import { CHAINS, chainOfId } from './chains.js';

const U = ethers.utils;

export const RECIPE = 'polygon-137/hybrid-delegator-1.3.0/erc1967-create2/v1';
export const CHAIN_ID = 137;
export const CHAIN_HEX = '0x89';
export const FACTORY = '0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c';
export const IMPLEMENTATION = '0x48dBe696A4D990079e039489bA2053B36E8FFEC4';
export const FACTORY_CODE_HASH = '0x82c94f0735e1e8ea2ffc1df4186cf5d3e28877459f9ff330289b99ea851e5ae9';
export const IMPLEMENTATION_CODE_HASH = '0xd8b4fd0fcd44ec79c86d8421ca79950e4d2e2b9a3e0b40b258d5d90d03fabef1';
export const IMPLEMENTATION_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
export const ORIGIN = 'https://tumf.github.io';
export const MAX_JSON_BYTES = 4096;
export const MAX_ENCODED = 5462;
export const FIELDS = ['chainId', 'expectedAddress', 'keyID', 'publicKey', 'recipe', 'salt', 'version'];
export const UINT256_MAX = (1n << 256n) - 1n;
export const REQUIRED_CONFIRMATIONS = 2n;

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const PROXY_BYTECODE = proxy.bytecode;
const hybrid = new U.Interface([
  'function initialize(address,string[],uint256[],uint256[])',
  'function owner() view returns (address)',
  'function getKeyIdHashesCount() view returns (uint256)',
  'function getKey(string) view returns (uint256,uint256)',
]);
const factory = new U.Interface([
  'function deploy(bytes,bytes32)',
  'function computeAddress(bytes32,bytes32) view returns (address)',
]);

/** A bounded, non-echoing failure with a stable code for state/tests and Japanese copy for the page. */
export class PublicError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const HANDOFF_MESSAGES = {
  oversize: '配備データが大きすぎます（JSON上限4096バイト）。',
  fragment: 'URLの配備データ形式が不正です。アプリから開き直すか、配備データを貼り付けてください。',
  encoding: '配備データの符号化（base64url/UTF-8）が不正です。',
  'not-v1': 'アプリの「配備データをコピー」で得たv1 JSONを貼り付けてください。公開鍵だけ・配列・URLは受け付けません。',
  json: '配備データがv1のJSONオブジェクトとして読めません。',
  duplicate: '配備データに重複した項目があります。',
  fields: '配備データの項目がv1の7項目と一致しません。',
  type: '配備データの値の型が不正です。',
  version: '対応していない配備データの版です。',
  recipe: '対応していない配備方式です。',
  chain: '配備方式とチェーンIDが一致しないか、対応する4チェーン（Ethereum・Polygon・Base・Base Sepolia）以外の配備データです。',
  publicKey: '公開鍵は0x04で始まる65バイトの小文字hexが必要です。',
  curve: 'P-256曲線上にない公開鍵です。',
  keyID: 'keyIDが公開鍵のSHA-256と一致しません。',
  salt: 'ソルトは32バイトの小文字hexが必要です。',
  address: '予定アドレスの形式（EIP-55）が不正です。',
  binding: '予定アドレスが公開鍵とソルトから再計算した値と一致しません。',
};

function handoffError(code) {
  return new PublicError(code, HANDOFF_MESSAGES[code]);
}

// ---------------------------------------------------------------------------------------------
// Strict flat-object JSON: one object of string keys mapped to strings or exact integers.

function parseFlatObject(text) {
  let i = 0;
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++; };
  const fail = (code = 'json') => { throw handoffError(code); };
  const string = () => {
    if (text[i] !== '"') fail();
    i++;
    let out = '';
    for (;;) {
      if (i >= text.length) fail();
      const c = text[i++];
      if (c === '"') return out;
      if (c.charCodeAt(0) < 0x20) fail();
      if (c !== '\\') { out += c; continue; }
      const e = text[i++];
      const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }[e];
      if (simple !== undefined) { out += simple; continue; }
      if (e !== 'u' || !/^[0-9a-fA-F]{4}$/.test(text.slice(i, i + 4))) fail();
      out += String.fromCharCode(parseInt(text.slice(i, i + 4), 16));
      i += 4;
    }
  };
  ws();
  if (text[i] !== '{') fail(text[i] === '[' ? 'not-v1' : 'json');
  i++;
  const object = Object.create(null);
  ws();
  if (text[i] === '}') { i++; } else {
    for (;;) {
      ws();
      const key = string();
      ws();
      if (text[i++] !== ':') fail();
      ws();
      let value;
      if (text[i] === '"') value = string();
      else {
        const m = /^-?(0|[1-9][0-9]*)/.exec(text.slice(i, i + 32));
        if (m) {
          i += m[0].length;
          // Fractions/exponents are not exact integers.
          if (text[i] === '.' || text[i] === 'e' || text[i] === 'E') fail('type');
          value = Number(m[0]);
          if (!Number.isSafeInteger(value)) fail('type');
        } else if ('{['.includes(text[i]) || /^(true|false|null)/.test(text.slice(i, i + 5))) {
          fail('type');
        } else fail();
      }
      if (Object.prototype.hasOwnProperty.call(object, key)) fail('duplicate');
      object[key] = value;
      ws();
      const sep = text[i++];
      if (sep === '}') break;
      if (sep !== ',') fail();
    }
  }
  ws();
  if (i !== text.length) fail();
  for (const [key, value] of Object.entries(object)) {
    if (!wellFormed(key) || (typeof value === 'string' && !wellFormed(value))) fail('encoding');
  }
  return object;
}

function wellFormed(text) {
  return typeof text.isWellFormed === 'function' ? text.isWellFormed()
    : !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(text);
}

function utf8Length(text) {
  return new TextEncoder().encode(text).length;
}

// ---------------------------------------------------------------------------------------------
// Handoff import

/** Validates one v1 JSON text (manual paste or decoded fragment) and returns the frozen handoff. */
export function parseHandoff(text) {
  if (typeof text !== 'string') throw handoffError('json');
  if (text.length > MAX_JSON_BYTES || !wellFormed(text)) {
    throw handoffError(text.length > MAX_JSON_BYTES ? 'oversize' : 'encoding');
  }
  if (utf8Length(text) > MAX_JSON_BYTES) throw handoffError('oversize');
  const trimmed = text.trim();
  if (/^0x/i.test(trimmed) || /^https?:/i.test(trimmed) || trimmed.startsWith('[')) throw handoffError('not-v1');
  const object = parseFlatObject(text);
  const keys = Object.keys(object).sort();
  if (keys.length !== FIELDS.length || keys.some((key, index) => key !== FIELDS[index])) throw handoffError('fields');
  const { version, recipe, chainId, publicKey, keyID, salt, expectedAddress } = object;
  for (const [value, kind] of [[version, 'number'], [chainId, 'number'], [recipe, 'string'], [publicKey, 'string'],
    [keyID, 'string'], [salt, 'string'], [expectedAddress, 'string']]) {
    if (typeof value !== kind) throw handoffError('type');
  }
  if (version !== 1) throw handoffError('version');
  // One closed chain: its own recipe identifier and exactly its chain ID (Polygon: the unchanged legacy recipe).
  const chain = Object.values(CHAINS).find((entry) => entry.recipe === recipe);
  if (!chain) throw handoffError('recipe');
  if (chainId !== chain.id) throw handoffError('chain');
  if (!/^0x04[0-9a-f]{128}$/.test(publicKey)) throw handoffError('publicKey');
  const x = BigInt('0x' + publicKey.slice(4, 68));
  const y = BigInt('0x' + publicKey.slice(68));
  if (x >= P || y >= P || (y * y) % P !== (((x * x % P) * x - 3n * x + B) % P + P) % P) throw handoffError('curve');
  if (!/^[0-9a-f]{64}$/.test(keyID) || U.sha256(publicKey).slice(2) !== keyID) throw handoffError('keyID');
  if (!/^0x[0-9a-f]{64}$/.test(salt)) throw handoffError('salt');
  if (!/^0x[0-9a-fA-F]{40}$/.test(expectedAddress)) throw handoffError('address');
  let canonical;
  try { canonical = U.getAddress(expectedAddress); } catch { throw handoffError('address'); }
  if (canonical !== expectedAddress) throw handoffError('address');
  const handoff = Object.freeze({ version, recipe, chainId, publicKey, keyID, salt, expectedAddress });
  if (buildPlan(handoff).address !== expectedAddress) throw handoffError('binding');
  return handoff;
}

/** The closed chain a validated handoff (or its plan) names; never another chain. */
export function handoffChain(handoff) {
  const chain = chainOfId(handoff?.chainId);
  if (!chain || chain.recipe !== handoff.recipe) throw handoffError('chain');
  return chain;
}

/** RFC 4648 section 5 without padding; rejects any noncanonical encoding before allocation. */
export function decodeBase64URL(text) {
  if (text.length > MAX_ENCODED) throw handoffError('oversize');
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) throw handoffError('encoding');
  const bytes = Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')
    + '='.repeat((4 - (text.length % 4)) % 4)), (c) => c.charCodeAt(0));
  if (encodeBase64URL(bytes) !== text) throw handoffError('encoding');
  if (bytes.length > MAX_JSON_BYTES) throw handoffError('oversize');
  return bytes;
}

export function encodeBase64URL(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Parses a location fragment `#registration=<base64url v1 JSON>`; nothing else is accepted. */
export function parseFragment(hash) {
  if (typeof hash !== 'string') throw handoffError('fragment');
  const prefix = '#registration=';
  if (hash.length > prefix.length + MAX_ENCODED) throw handoffError('oversize');
  if (!hash.startsWith(prefix)) throw handoffError('fragment');
  const encoded = hash.slice(prefix.length);
  if (/[&=#?]/.test(encoded)) throw handoffError('fragment');
  const bytes = decodeBase64URL(encoded);
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch {
    throw handoffError('encoding');
  }
  return parseHandoff(text);
}

// ---------------------------------------------------------------------------------------------
// Recipe

/** The fixed single-key deployment for one validated handoff. Value zero, no owner, no options. */
export function buildPlan(handoff) {
  const x = '0x' + handoff.publicKey.slice(4, 68);
  const y = '0x' + handoff.publicKey.slice(68);
  const initializer = hybrid.encodeFunctionData('initialize', [ZERO_ADDRESS, [handoff.keyID], [x], [y]]);
  const creation = U.hexConcat([PROXY_BYTECODE, U.defaultAbiCoder.encode(['address', 'bytes'], [IMPLEMENTATION,
    initializer])]);
  const creationHash = U.keccak256(creation);
  const address = U.getCreate2Address(FACTORY, handoff.salt, creationHash);
  const data = factory.encodeFunctionData('deploy', [creation, handoff.salt]);
  return Object.freeze({
    handoff, keyID: handoff.keyID, x, y, salt: handoff.salt, initializer, creation, creationHash, address,
    dataHash: U.keccak256(data),
    transaction: Object.freeze({ to: FACTORY, data, value: '0x0' }),
  });
}

// ---------------------------------------------------------------------------------------------
// Strict RPC value shapes

export function quantity(value) {
  if (typeof value !== 'string' || !/^0x(0|[1-9a-f][0-9a-f]{0,63})$/i.test(value)) {
    throw new PublicError('rpc', 'RPC応答の数値形式が不正です。');
  }
  return BigInt(value);
}

export function hexQuantity(value) {
  if (typeof value !== 'bigint' || value < 0n || value > UINT256_MAX) throw new PublicError('rpc', '数値が範囲外です。');
  return '0x' + value.toString(16);
}

function data(value) {
  if (typeof value !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(value)) {
    throw new PublicError('rpc', 'RPC応答のデータ形式が不正です。');
  }
  return value.toLowerCase();
}

function hash32(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new PublicError('rpc', 'RPC応答のハッシュ形式が不正です。');
  }
  return value.toLowerCase();
}

export const INSPECTION_MESSAGES = {
  offline: '選んだチェーンの読取りRPCに接続できません。時間をおいて再照合してください。',
  chain: '読取りRPCが配備データのチェーンではありません。',
  code: 'Factoryまたは実装の公式コードが固定値と一致しません。',
  prediction: 'Factoryの予定アドレスが選択した行と一致しません。',
  keyset: '予定アドレスに配備済みのコントラクトの実装・管理者・鍵が一致しません。安全な既存配備ではありません。',
  block: '照合中にブロックが変わったか再編成されました。再照合してください。',
  rpc: '読取りRPCの応答形式が不正です。',
};

function inspectionError(code, cause) {
  const error = new PublicError(code, INSPECTION_MESSAGES[code]);
  if (cause) error.cause = cause;
  return error;
}

/** A JSON-RPC error response (numeric code) is `rpc`; anything else is an unreachable transport (`offline`). */
async function read(rpc, method, params) {
  try {
    return await rpc(method, params);
  } catch (error) {
    if (error instanceof PublicError) throw error;
    throw inspectionError(error && Number.isInteger(error.code) ? 'rpc' : 'offline', error);
  }
}

/** Reads block B (number/hash) for a tag, validating its shape. Its fee fields are never read. */
async function block(rpc, tag) {
  const result = await read(rpc, 'eth_getBlockByNumber', [tag, false]);
  if (!result || typeof result !== 'object') throw inspectionError('block');
  try {
    return { number: quantity(result.number), hash: hash32(result.hash) };
  } catch { throw inspectionError('rpc'); }
}

async function runtimeHash(rpc, address, tag) {
  return U.keccak256(data(await read(rpc, 'eth_getCode', [address, tag])));
}

/**
 * Canonical contract readback at one block tag: `deployed` (exact pinned implementation, zero owner,
 * singleton key with the planned coordinates), `not-deployed`, or `mismatch`. Never success by itself.
 */
export async function readback(rpc, plan, tag) {
  const implementationHash = handoffChain(plan.handoff).implementationCodeHash;
  for (const [address, expected] of [[FACTORY, FACTORY_CODE_HASH], [IMPLEMENTATION, implementationHash]]) {
    if (await runtimeHash(rpc, address, tag) !== expected) return { state: 'mismatch', reason: 'code' };
  }
  const code = data(await read(rpc, 'eth_getCode', [plan.address, tag]));
  if (code === '0x') return { state: 'not-deployed' };
  const slot = hash32(await read(rpc, 'eth_getStorageAt', [plan.address, IMPLEMENTATION_SLOT, tag]));
  if (slot !== U.hexZeroPad(IMPLEMENTATION, 32).toLowerCase()) return { state: 'mismatch', reason: 'implementation' };
  // Read failures (transport or JSON-RPC errors, malformed result data) propagate as unavailable; only a
  // successfully read result that decodes to the wrong owner/key data, or an execution revert (EIP-1474
  // code 3, the contract's own answer), is a mismatch.
  const call = async (name, args = []) => {
    let raw;
    try {
      raw = data(await read(rpc, 'eth_call', [{ to: plan.address, data: hybrid.encodeFunctionData(name, args) }, tag]));
    } catch (error) {
      if (error && error.cause && error.cause.code === 3) return null;
      throw error;
    }
    try { return hybrid.decodeFunctionResult(name, raw); } catch { return null; }
  };
  const owner = await call('owner');
  if (!owner || owner[0] !== ZERO_ADDRESS) return { state: 'mismatch', reason: 'owner' };
  const count = await call('getKeyIdHashesCount');
  if (!count || !count[0].eq(1)) return { state: 'mismatch', reason: 'keyset' };
  const key = await call('getKey', [plan.keyID]);
  if (!key || !key[0].eq(plan.x) || !key[1].eq(plan.y)) return { state: 'mismatch', reason: 'keyset' };
  return { state: 'deployed' };
}

/**
 * Block-bound read-only inspection of one plan's deployment identity. Every read uses block B; B's hash is
 * fetched again at the end and any difference invalidates the whole result. Gas estimation and fee data belong
 * to the selected wallet and are never read here, so an RPC without fee support cannot block a valid operation.
 */
export async function inspect(rpc, plan) {
  const selected = handoffChain(plan.handoff);
  const chain = await read(rpc, 'eth_chainId', []);
  if (typeof chain !== 'string' || chain.toLowerCase() !== selected.hex) throw inspectionError('chain');
  const b = await block(rpc, 'latest');
  const tag = hexQuantity(b.number);
  for (const [address, expected] of [[FACTORY, FACTORY_CODE_HASH], [IMPLEMENTATION, selected.implementationCodeHash]]) {
    if (await runtimeHash(rpc, address, tag) !== expected) throw inspectionError('code');
  }
  let predicted;
  try {
    [predicted] = factory.decodeFunctionResult('computeAddress', data(await read(rpc, 'eth_call', [{
      to: FACTORY, data: factory.encodeFunctionData('computeAddress', [plan.creationHash, plan.salt]),
    }, tag])));
  } catch (error) {
    if (error instanceof PublicError && error.code === 'offline') throw error;
    throw inspectionError('prediction');
  }
  if (predicted !== plan.address) throw inspectionError('prediction');
  const existing = await readback(rpc, plan, tag);
  if (existing.state === 'mismatch') throw inspectionError(existing.reason === 'code' ? 'code' : 'keyset');
  const again = await block(rpc, tag);
  if (again.hash !== b.hash || again.number !== b.number) throw inspectionError('block');
  return { kind: existing.state === 'deployed' ? 'deployed' : 'undeployed', block: { number: b.number, hash: b.hash } };
}

// ---------------------------------------------------------------------------------------------
// Historical v1 fee policy and user cap (validation/display of byte-preserved v1 records and tests only)

/** gasLimit = ceil(estimate*120/100), maxPriority = tip, maxFee = 2*baseFee + tip; all positive uint256. */
export function ceilings({ estimate, baseFee, tip }) {
  const gasLimit = (estimate * 120n + 99n) / 100n;
  const maxPriorityFeePerGas = tip;
  const maxFeePerGas = 2n * baseFee + tip;
  const maxTotal = gasLimit * maxFeePerGas;
  for (const value of [gasLimit, maxPriorityFeePerGas, maxFeePerGas, maxTotal]) {
    if (value <= 0n || value > UINT256_MAX) throw new PublicError('fee', 'EIP-1559の手数料情報が範囲外です。');
  }
  return { gasLimit, maxPriorityFeePerGas, maxFeePerGas, maxTotal };
}

export const CAP_MESSAGES = {
  invalid: '支払上限は0以上の10進数（小数18桁まで、指数・符号なし）で入力してください。',
  zero: '支払上限は0より大きくしてください。',
  large: '支払上限が大きすぎます。',
  low: '支払上限が表示された最大ガス代より小さいため送信できません。',
};

/** Canonical decimal POL to wei; never floating point. */
export function parsePol(text) {
  if (typeof text !== 'string' || !/^(0|[1-9][0-9]*)(\.[0-9]{1,18})?$/.test(text) || text.length > 100) {
    throw new PublicError('invalid', CAP_MESSAGES.invalid);
  }
  const [whole, fraction = ''] = text.split('.');
  const wei = BigInt(whole) * 10n ** 18n + BigInt(fraction.padEnd(18, '0') || '0');
  if (wei === 0n) throw new PublicError('zero', CAP_MESSAGES.zero);
  if (wei > UINT256_MAX) throw new PublicError('large', CAP_MESSAGES.large);
  return wei;
}

export function formatPol(wei) {
  const whole = wei / 10n ** 18n;
  const fraction = (wei % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : `${whole}`;
}

// ---------------------------------------------------------------------------------------------
// Settlement

/**
 * Exact frozen identity `{ from, data, chainId? }` of a returned transaction: chain (the record's own chain, Polygon
 * when absent), from, Factory `to`, calldata and zero value. Nonce/gas/fees are wallet authority and compared separately.
 */
export function identityMatches(tx, identity) {
  try {
    return typeof tx === 'object' && tx !== null
      && (tx.chainId === undefined || tx.chainId === null || quantity(tx.chainId) === BigInt(identity.chainId ?? CHAIN_ID))
      && typeof tx.from === 'string' && tx.from.toLowerCase() === identity.from.toLowerCase()
      && typeof tx.to === 'string' && tx.to.toLowerCase() === FACTORY.toLowerCase()
      && data(tx.input) === identity.data.toLowerCase()
      && quantity(tx.value) === 0n;
  } catch {
    return false;
  }
}

/**
 * Independently observed nonce/gas/fees. A v1 record compares them with its frozen gas/fee/cap ceilings; a v2
 * record has no app ceiling, so wallet-selected values are only validated as coherent evidence (never override).
 */
export function observe(tx, attempt) {
  if (attempt.version === 2) return { ...walletObserved(tx), override: false, differs: false };
  const gas = quantity(tx.gas);
  const maxFeePerGas = quantity(tx.maxFeePerGas ?? tx.gasPrice);
  const maxPriorityFeePerGas = quantity(tx.maxPriorityFeePerGas ?? tx.gasPrice);
  const nonce = quantity(tx.nonce);
  const frozen = attempt.transaction;
  const override = gas > BigInt(frozen.gas) || maxFeePerGas > BigInt(frozen.maxFeePerGas)
    || maxPriorityFeePerGas > BigInt(frozen.maxPriorityFeePerGas) || gas * maxFeePerGas > BigInt(attempt.capWei);
  const differs = nonce !== BigInt(frozen.nonce) || gas !== BigInt(frozen.gas)
    || maxFeePerGas !== BigInt(frozen.maxFeePerGas) || maxPriorityFeePerGas !== BigInt(frozen.maxPriorityFeePerGas);
  return { nonce, gas, maxFeePerGas, maxPriorityFeePerGas, override, differs };
}

const absent = (value) => value === undefined || value === null;

/**
 * Canonical wallet-chosen quantities of a real transaction: positive gas, complete EIP-1559 fees with
 * priority <= max, or a legacy gasPrice (mapped to both fields) when both EIP-1559 fields are absent.
 * Partial or inconsistent fee fields throw.
 */
export function walletObserved(tx) {
  const gas = quantity(tx.gas);
  const nonce = quantity(tx.nonce);
  if (gas === 0n) throw new PublicError('rpc', INSPECTION_MESSAGES.rpc);
  let maxFeePerGas;
  let maxPriorityFeePerGas;
  if (!absent(tx.maxFeePerGas) && !absent(tx.maxPriorityFeePerGas)) {
    maxFeePerGas = quantity(tx.maxFeePerGas);
    maxPriorityFeePerGas = quantity(tx.maxPriorityFeePerGas);
    if (!absent(tx.gasPrice)) quantity(tx.gasPrice);
  } else if (absent(tx.maxFeePerGas) && absent(tx.maxPriorityFeePerGas) && !absent(tx.gasPrice)) {
    maxFeePerGas = quantity(tx.gasPrice);
    maxPriorityFeePerGas = maxFeePerGas;
  } else {
    throw new PublicError('rpc', INSPECTION_MESSAGES.rpc);
  }
  if (maxPriorityFeePerGas > maxFeePerGas) throw new PublicError('rpc', INSPECTION_MESSAGES.rpc);
  return { nonce, gas, maxFeePerGas, maxPriorityFeePerGas };
}

/**
 * Classifies one hash of a frozen attempt using read-only RPC only:
 * pending | success | failed | walletOverride (v1 only) | unknown (with reason). Never submits or retries.
 * A v2 receipt must also agree with the fetched transaction (inclusion block/hash, gasUsed <= gas,
 * effectiveGasPrice <= maxFeePerGas/gasPrice); disagreement or malformed fee evidence is `unknown`.
 */
export async function verifySettlement(rpc, plan, attempt, hash) {
  const result = { hash, observed: null, receipt: null, readback: 'unknown', paidFee: null, confirmations: 0n };
  let tx;
  try { tx = await rpc('eth_getTransactionByHash', [hash]); } catch { return { ...result, state: 'unknown', reason: 'rpc' }; }
  if (tx === null || tx === undefined) return { ...result, state: 'pending', reason: 'no-transaction' };
  if (typeof tx !== 'object' || typeof tx.hash !== 'string' || tx.hash.toLowerCase() !== hash.toLowerCase()
      || !identityMatches(tx, { from: attempt.from, data: plan.transaction.data, chainId: handoffChain(plan.handoff).id })) {
    return { ...result, state: 'unknown', reason: 'identity' };
  }
  const v2 = attempt.version === 2;
  try {
    result.observed = observe(tx, attempt);
    // Inclusion block as reported by the transaction (null while pending); not a settlement claim.
    result.minedBlock = tx.blockNumber === null || tx.blockNumber === undefined ? null : quantity(tx.blockNumber);
  } catch { return { ...result, state: 'unknown', reason: v2 ? 'evidence' : 'identity' }; }
  const override = result.observed.override;
  let receipt;
  try { receipt = await rpc('eth_getTransactionReceipt', [hash]); } catch {
    return { ...result, state: override ? 'walletOverride' : 'unknown', reason: 'rpc' };
  }
  if (receipt === null || receipt === undefined) {
    return { ...result, state: override ? 'walletOverride' : 'pending', reason: 'no-receipt' };
  }
  try {
    const receiptBlock = quantity(receipt.blockNumber);
    const receiptHash = hash32(receipt.blockHash);
    if (hash32(receipt.transactionHash) !== hash.toLowerCase()) throw new Error('receipt hash');
    const status = quantity(receipt.status);
    const gasUsed = quantity(receipt.gasUsed);
    const effectiveGasPrice = quantity(receipt.effectiveGasPrice);
    const paidFee = gasUsed * effectiveGasPrice;
    if (v2 && (result.minedBlock !== receiptBlock || absent(tx.blockHash) || hash32(tx.blockHash) !== receiptHash
        || gasUsed > result.observed.gas || effectiveGasPrice > result.observed.maxFeePerGas)) {
      return { ...result, state: 'unknown', reason: 'receipt' };
    }
    const head = quantity(await rpc('eth_blockNumber', []));
    const canonical = await rpc('eth_getBlockByNumber', [hexQuantity(receiptBlock), false]);
    if (!canonical || hash32(canonical.hash) !== receiptHash) {
      // The receipt's block is no longer canonical: revert to pending; a detected override stays locked.
      return { ...result, state: override ? 'walletOverride' : 'pending', reason: 'reorg' };
    }
    const back = await readback(rpc, plan, hexQuantity(receiptBlock));
    const recheck = await rpc('eth_getBlockByNumber', [hexQuantity(receiptBlock), false]);
    if (!recheck || hash32(recheck.hash) !== receiptHash) {
      return { ...result, state: override ? 'walletOverride' : 'pending', reason: 'reorg' };
    }
    // Fee, receipt and confirmations are exposed only from a receipt whose block was verified canonical twice.
    result.paidFee = paidFee;
    result.receipt = { blockNumber: receiptBlock, blockHash: receiptHash, status };
    result.confirmations = head >= receiptBlock ? head - receiptBlock + 1n : 0n;
    result.readback = back.state;
    if (override) return { ...result, state: 'walletOverride', reason: 'ceiling' };
    if (result.confirmations < REQUIRED_CONFIRMATIONS) return { ...result, state: 'pending', reason: 'confirming' };
    if (status === 1n) {
      return back.state === 'deployed' ? { ...result, state: 'success' }
        : { ...result, state: 'unknown', reason: 'readback' };
    }
    if (status === 0n) return { ...result, state: 'failed', reason: 'reverted' };
    return { ...result, state: 'unknown', reason: 'status' };
  } catch {
    return { ...result, state: override ? 'walletOverride' : 'unknown', reason: 'rpc' };
  }
}

/**
 * Re-validates the transaction that consumed an attempt's verified effective nonce (proved cancellation
 * or unrelated replacement): same sender and nonce, not the deployment identity, and a canonical receipt
 * with two confirmations and a block-hash recheck. The paid fee comes only from that canonical receipt.
 * Anything unavailable or unproved is `unknown`/`cancel-unverified`, never failed.
 */
export async function verifyCancellation(rpc, plan, attempt, hash, effectiveNonce) {
  const result = { hash, observed: null, receipt: null, readback: 'unknown', paidFee: null, confirmations: 0n,
    replacement: hash };
  const unverified = { ...result, state: 'unknown', reason: 'cancel-unverified' };
  try {
    const tx = await rpc('eth_getTransactionByHash', [hash]);
    if (!tx || typeof tx !== 'object' || hash32(tx.hash) !== hash.toLowerCase() || typeof tx.from !== 'string'
        || tx.from.toLowerCase() !== attempt.from.toLowerCase() || quantity(tx.nonce) !== effectiveNonce
        || identityMatches(tx, { from: attempt.from, data: plan.transaction.data, chainId: handoffChain(plan.handoff).id })) return unverified;
    const receipt = await rpc('eth_getTransactionReceipt', [hash]);
    if (!receipt) return unverified;
    const receiptBlock = quantity(receipt.blockNumber);
    const receiptHash = hash32(receipt.blockHash);
    if (hash32(receipt.transactionHash) !== hash.toLowerCase()) return unverified;
    const status = quantity(receipt.status);
    const paidFee = quantity(receipt.gasUsed) * quantity(receipt.effectiveGasPrice);
    const head = quantity(await rpc('eth_blockNumber', []));
    for (let check = 0; check < 2; check++) {
      const canonical = await rpc('eth_getBlockByNumber', [hexQuantity(receiptBlock), false]);
      if (!canonical || hash32(canonical.hash) !== receiptHash) return unverified;
    }
    const confirmations = head >= receiptBlock ? head - receiptBlock + 1n : 0n;
    if (confirmations < REQUIRED_CONFIRMATIONS) return unverified;
    return { ...result, state: 'failed', reason: 'cancelled', paidFee, confirmations,
      receipt: { blockNumber: receiptBlock, blockHash: receiptHash, status } };
  } catch {
    return unverified;
  }
}

/**
 * Bounded read-only replacement scan: canonical blocks [fromBlock, head] (at most 128) for a transaction
 * from the same sender with the verified effective nonce. Returns `{ kind: 'replacement', hash }` for an
 * exact deployment identity, `{ kind: 'cancelled', hash }` for a confirmed different transaction that
 * consumed that nonce, or `{ kind: 'none' }`. Unknown effective nonce is never cancellation proof.
 */
export async function scanReplacement(rpc, plan, attempt, { fromBlock, effectiveNonce, verified, deadline, now }) {
  const head = quantity(await rpc('eth_blockNumber', []));
  if (head < fromBlock) return { kind: 'none', reason: 'range' };
  const last = head - fromBlock + 1n > 128n ? fromBlock + 127n : head;
  const numbers = [];
  for (let n = fromBlock; n <= last; n++) numbers.push(n);
  let found = null;
  for (let index = 0; index < numbers.length && !found; index += 4) {
    if (now() > deadline) return { kind: 'none', reason: 'timeout' };
    const blocks = await Promise.all(numbers.slice(index, index + 4).map((n) => rpc('eth_getBlockByNumber',
      [hexQuantity(n), true])));
    for (const item of blocks) {
      if (!item || !Array.isArray(item.transactions)) throw new PublicError('rpc', INSPECTION_MESSAGES.rpc);
      for (const tx of item.transactions) {
        if (typeof tx !== 'object' || typeof tx.from !== 'string') continue;
        if (tx.from.toLowerCase() === attempt.from.toLowerCase() && quantity(tx.nonce) === effectiveNonce) {
          found = { tx, block: quantity(item.number) };
          break;
        }
      }
      if (found) break;
    }
  }
  if (!found) return { kind: 'none', reason: last < head ? 'range' : 'no-candidate' };
  if (identityMatches(found.tx, { from: attempt.from, data: plan.transaction.data, chainId: handoffChain(plan.handoff).id })) return { kind: 'replacement', hash: hash32(found.tx.hash) };
  if (!verified) return { kind: 'none', reason: 'unverified-nonce' };
  if (head - found.block + 1n < REQUIRED_CONFIRMATIONS) return { kind: 'none', reason: 'confirming' };
  return { kind: 'cancelled', hash: hash32(found.tx.hash) };
}
