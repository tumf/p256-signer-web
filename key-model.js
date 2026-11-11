// Key-change model: closed native public anchors, the exact HybridDeleGator v1.3.0 add/remove self-call,
// Hybrid EIP-712 H, EntryPoint v0.7 userOpHash, the native approval commitment and envelope, closed native
// context/result validation with real WebCrypto P-256 verification, and exact BigInt fee/cost arithmetic.
// No I/O: chain reads live in key-reader.js, transport in key-session.js, durable state in key-attempt-store.js.
import ethers from './vendor/ethers.js';
import { POLYGON, chainOf } from './chains.js';

const U = ethers.utils;

export const ORIGIN = 'https://tumf.github.io';
// The legacy default chain (Polygon); an anchor names its own closed chain (`anchorChain`).
export const CHAIN_ID = POLYGON.decimal;
export const CHAIN_HEX = POLYGON.hex;
export const CAIP_CHAIN = POLYGON.caip2;
export const ENTRYPOINT = '0x0000000071727de22e5e9d8baf0edac6f37da032';
export const IMPLEMENTATION = '0x48dbe696a4d990079e039489ba2053b36e8ffec4';
export const IMPLEMENTATION_CODE_HASH = '0xd8b4fd0fcd44ec79c86d8421ca79950e4d2e2b9a3e0b40b258d5d90d03fabef1';
export const PROXY_RUNTIME_HASH = '0xe14b20c9994b2d55b74984be5c5c88c3418281f0948b7bc7aa87e7c9ae5c6709';
export const IMPLEMENTATION_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
export const STORAGE_BASE = '0xa2b1bcb5e16cee2a8898b49cb0c3605e70c16f429f6002ed8b1bc5612a694900';
export const ZERO_ADDRESS = '0x' + '00'.repeat(20);
export const METHODS = Object.freeze(['p256_getKeyChangeContext', 'p256_signKeyChangeRequest']);
export const PURPOSE = 'hybrid-key-change-v1.3.0';
export const CODEC_ID = 'hybrid-delegator-1.3.0/raw-p256-msg/v1';
export const VALIDITY_SECONDS = 120;
export const CLOCK_SKEW_SECONDS = 30;
export const MAX_ENVELOPE_BYTES = 32768;
export const MAX_PUBLIC_BYTES = 4096;
export const MAX_KEYS = 64;
export const VERIFICATION_GAS = 700000n;
export const CALL_GAS = 300000n;
export const PRE_VERIFICATION_GAS = 60000n;
export const TOTAL_GAS = VERIFICATION_GAS + CALL_GAS + PRE_VERIFICATION_GAS;
/** Legacy v1 attempt records only: their stored outer gas ceiling had this floor. The Web never asks for one. */
export const OUTER_GAS_FLOOR = 1200000n;
export const UINT64_MAX = (1n << 64n) - 1n;
export const UINT120_MAX = (1n << 120n) - 1n;
export const UINT128_MAX = (1n << 128n) - 1n;
export const UINT256_MAX = (1n << 256n) - 1n;
export const GWEI = 1000000000n;
/** Native context blocks may trail or lead the Web block B by this many blocks (about 60s on Polygon). */
export const NATIVE_BLOCK_WINDOW = 30n;
export const COMMITMENT_DOMAIN = 'p256-signer/hybrid-key-approval/v1\0';

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const utf8 = (text) => U.toUtf8Bytes(text);
const keccakText = (text) => U.keccak256(utf8(text));
const selector = (signature) => keccakText(signature).slice(0, 10);
export const SELECTORS = Object.freeze({
  execute: selector('execute((address,uint256,bytes))'),
  addKey: selector('addKey(string,uint256,uint256)'),
  removeKey: selector('removeKey(string)'),
  handleOps: selector('handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)'),
  balanceOf: selector('balanceOf(address)'),
  getNonce: selector('getNonce(address,uint192)'),
});
export const USER_OPERATION_EVENT = keccakText(
  'UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)');
const DOMAIN_TYPE = keccakText('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)');
const USER_OP_TYPE = keccakText('PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,'
  + 'bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,address entryPoint)');
export const BODY_KEYS = Object.freeze(['sender', 'nonce', 'initCode', 'callData', 'accountGasLimits',
  'preVerificationGas', 'gasFees', 'paymasterAndData', 'signature']);
const ROOT_KEYS = ['v', 'id', 'purpose', 'codecId', 'keyId', 'binding', 'issuedAt', 'expiresAt', 'chainId',
  'entryPoint', 'signer', 'body'];
const CONTEXT_KEYS = ['version', 'origin', 'chainId', 'signer', 'entryPoint', 'keyId', 'publicKey', 'binding',
  'codecId', 'purpose', 'maxValiditySeconds', 'maxEnvelopeBytes', 'nonce', 'blockNumber', 'blockHash',
  'implementation', 'implementationCodeHash', 'owner', 'maxGasUnits', 'maxFeePerGas', 'keys'];
const RESULT_KEYS = ['version', 'purpose', 'requestId', 'keyId', 'codecId', 'commitment', 'binding', 'chainId',
  'entryPoint', 'signer', 'nonce', 'typedDataHash', 'publicPoint', 'rawSignature', 'signerSignature'];

/** A bounded failure with a fixed code; the message never echoes input. */
export class KeyError extends Error {
  constructor(code, field) {
    super(`key-change ${code}`);
    this.name = 'KeyError';
    this.code = code;
    if (field) this.field = field;
  }
}
const fail = (code, field) => { throw new KeyError(code, field); };

// ---------------------------------------------------------------------------------------------------------------
// Canonical text and words

export const isKeyId = (text) => typeof text === 'string' && /^[0-9a-f]{64}$/.test(text);
export const isHash = (text) => typeof text === 'string' && /^0x[0-9a-f]{64}$/.test(text);
export const isLowerAddress = (text) => typeof text === 'string' && /^0x[0-9a-f]{40}$/.test(text);
export const isDecimal = (text) => typeof text === 'string' && /^(0|[1-9][0-9]{0,77})$/.test(text)
  && BigInt(text) <= UINT256_MAX;
export const isUUID = (text) => typeof text === 'string'
  && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(text);

export function word(value, bytes = 32) {
  const n = BigInt(value);
  if (n < 0n || n >= 1n << BigInt(bytes * 8)) fail('word');
  return '0x' + n.toString(16).padStart(bytes * 2, '0');
}
const strip = (hex) => hex.slice(2);
const addressWord = (address) => '0x' + '00'.repeat(12) + strip(address.toLowerCase());
function dynamicBytes(hex) {
  const length = strip(hex).length / 2;
  const padding = (32 - (length % 32)) % 32;
  return word(length).slice(2) + strip(hex) + '00'.repeat(padding);
}
export const sha256Hex = (hex) => U.sha256(hex);
export const keyIdOf = (point) => U.sha256(point).slice(2);
export const keyIdHash = (keyId) => keccakText(keyId);

/** Lowercase 65-byte uncompressed `0x04||x||y` on P-256 with coordinates below the field prime. */
export function isPoint(point) {
  if (typeof point !== 'string' || !/^0x04[0-9a-f]{128}$/.test(point)) return false;
  const x = BigInt('0x' + point.slice(4, 68)), y = BigInt('0x' + point.slice(68));
  if (x >= P || y >= P) return false;
  return (y * y) % P === (((x * x % P) * x - 3n * x + B) % P + P) % P;
}

// ---------------------------------------------------------------------------------------------------------------
// Closed public anchors (PublicHandoff at 68c6f87): flat objects of strings only.

function wellFormed(text) {
  return typeof text.isWellFormed === 'function' ? text.isWellFormed()
    : !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(text);
}

/** The bounded flat parser algorithm of model.js narrowed to string values: no numbers, arrays or nesting. */
export function parseFlatStrings(text) {
  if (typeof text !== 'string' || !wellFormed(text) || new TextEncoder().encode(text).length > MAX_PUBLIC_BYTES) {
    fail('json');
  }
  let i = 0;
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++; };
  const string = () => {
    if (text[i] !== '"') fail('json');
    i++;
    let out = '';
    for (;;) {
      if (i >= text.length) fail('json');
      const c = text[i++];
      if (c === '"') return out;
      if (c.charCodeAt(0) < 0x20) fail('json');
      if (c !== '\\') { out += c; continue; }
      const e = text[i++];
      const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }[e];
      if (simple !== undefined) { out += simple; continue; }
      if (e !== 'u' || !/^[0-9a-fA-F]{4}$/.test(text.slice(i, i + 4))) fail('json');
      out += String.fromCharCode(parseInt(text.slice(i, i + 4), 16));
      i += 4;
    }
  };
  ws();
  if (text[i] !== '{') fail('json');
  i++;
  const object = Object.create(null);
  ws();
  if (text[i] === '}') i++;
  else {
    for (;;) {
      ws();
      const key = string();
      ws();
      if (text[i++] !== ':') fail('json');
      ws();
      if (text[i] !== '"') fail('type');
      const value = string();
      if (!wellFormed(key) || !wellFormed(value)) fail('json');
      if (Object.prototype.hasOwnProperty.call(object, key)) fail('duplicate');
      object[key] = value;
      ws();
      const sep = text[i++];
      if (sep === '}') break;
      if (sep !== ',') fail('json');
    }
  }
  ws();
  if (i !== text.length) fail('json');
  return object;
}

function closedFields(object, keys) {
  const names = Object.keys(object).sort();
  const wanted = [...keys].sort();
  if (names.length !== wanted.length || names.some((name, index) => name !== wanted[index])) fail('fields');
}

function publicIdentity(object) {
  if (!isPoint(object.publicKey)) fail('point');
  if (!isKeyId(object.keyId) || keyIdOf(object.publicKey) !== object.keyId) fail('keyId');
  return { publicKey: object.publicKey, keyId: object.keyId };
}

/**
 * `hybrid-key-authority`: selects the Signer on exactly one closed chain. Not membership, deployment or Factory
 * provenance proof. A non-Polygon anchor carries its own `chainId`; a Polygon anchor keeps the legacy shape.
 */
export function parseAuthority(text) {
  const object = parseFlatStrings(text);
  if (object.kind !== 'hybrid-key-authority') fail('kind');
  closedFields(object, ['v', 'kind', 'chainId', 'signer', 'publicKey', 'keyId']);
  if (object.v !== '1') fail('version');
  const chain = chainOf(object.chainId);
  if (!chain) fail('chain');
  const signer = object.signer;
  if (!/^0x[0-9a-fA-F]{40}$/.test(signer) || /^0x0{40}$/i.test(signer)) fail('signer');
  let checksum;
  try { checksum = U.getAddress(signer); } catch { fail('signer'); }
  if (checksum !== signer) fail('signer');
  const identity = publicIdentity(object);
  return Object.freeze({ kind: 'authority', signer, signerAddress: signer.toLowerCase(), ...identity,
    ...(chain === POLYGON ? {} : { chainId: chain.decimal }) });
}

/** The one closed chain of a parsed anchor (or a semantic context): its own `chainId`, Polygon for the legacy shape. */
export function anchorChain(anchor) {
  if (!anchor || !('chainId' in anchor)) return POLYGON;
  const chain = chainOf(anchor.chainId);
  if (!chain) fail('chain');
  return chain;
}

/**
 * `#key-change=<unpadded base64url(authority text LF key text)>` from the iPhone 「署名者を追加」. Prefill only: both
 * texts must pass the same parsers as a manual paste; nothing is inspected, connected, signed or sent by parsing.
 */
export function parseKeyChangeFragment(hash) {
  const prefix = '#key-change=';
  if (typeof hash !== 'string' || !hash.startsWith(prefix)) fail('fragment');
  const encoded = hash.slice(prefix.length);
  if (encoded.length > Math.ceil(MAX_PUBLIC_BYTES * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(encoded)
      || encoded.length % 4 === 1) fail('fragment');
  const bytes = Uint8Array.from(atob(encoded.replace(/-/g, '+').replace(/_/g, '/')
    + '='.repeat((4 - (encoded.length % 4)) % 4)), (c) => c.charCodeAt(0));
  let canonical = '';
  for (const byte of bytes) canonical += String.fromCharCode(byte);
  if (btoa(canonical).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') !== encoded) fail('fragment');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { fail('fragment'); }
  const parts = text.split('\n');
  // Exactly two untrimmed lines: no CR, padding or blank line is reinterpreted.
  if (parts.length !== 2 || parts.some((part) => part.trim() !== part || part === '')) fail('fragment');
  const authority = parseAuthority(parts[0]);
  const key = parseBareKey(parts[1]);
  if (key.keyId === authority.keyId) fail('fragment');
  return Object.freeze({ authorityText: parts[0], keyText: parts[1], authority, key });
}

/** `p256-public-key`: the only source of a key to add. Makes no membership claim. */
export function parseBareKey(text) {
  const object = parseFlatStrings(text);
  if (object.kind !== 'p256-public-key') fail('kind');
  closedFields(object, ['v', 'kind', 'publicKey', 'keyId']);
  if (object.v !== '1') fail('version');
  return Object.freeze({ kind: 'publicKey', ...publicIdentity(object) });
}

// ---------------------------------------------------------------------------------------------------------------
// Fees: ASCII decimal Gwei, at most nine fractional digits, to exact wei.

export function parseGwei(text) {
  if (typeof text !== 'string' || text === '') fail('blank');
  if (!/^(0|[1-9][0-9]{0,40})(\.[0-9]{1,9})?$/.test(text)) fail('format');
  const [whole, fraction = ''] = text.split('.');
  return BigInt(whole) * GWEI + BigInt(fraction.padEnd(9, '0'));
}

/** Signed inner fees. The native uint128 packing is unchanged; every value must also pass EntryPoint AA94. */
export function innerFees(maxText, priorityText, nativeMaxFee) {
  if (maxText === '' || priorityText === '') fail('blank');
  const maxFee = parseGwei(maxText), priorityFee = parseGwei(priorityText);
  if (maxFee <= 0n || maxFee > UINT120_MAX || priorityFee > maxFee || priorityFee > UINT120_MAX) fail('bounds');
  if (nativeMaxFee !== undefined && nativeMaxFee !== null && maxFee > nativeMaxFee) fail('bounds');
  return Object.freeze({ maxFee, priorityFee });
}

function checkedAdd(a, b) { const s = a + b; if (s > UINT256_MAX) fail('overflow'); return s; }
function checkedMul(a, b) { const p = a * b; if (p > UINT256_MAX) fail('overflow'); return p; }

/** Required prefund P against the signer EntryPoint deposit D. Shortfall blocks request and send. */
export function prefund(maxFee, deposit) {
  const units = checkedAdd(checkedAdd(VERIFICATION_GAS, CALL_GAS), PRE_VERIFICATION_GAS);
  const required = checkedMul(units, maxFee);
  return Object.freeze({ units, required, deposit, shortfall: deposit >= required ? 0n : required - deposit });
}

export function formatPol(wei) {
  const whole = wei / 10n ** 18n, fraction = (wei % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : `${whole}`;
}

// ---------------------------------------------------------------------------------------------------------------
// The exact compiler self-call and unsigned operation

export function addKeyCall(publicKey, keyId) {
  return SELECTORS.addKey + word(96).slice(2) + publicKey.slice(4, 68) + publicKey.slice(68)
    + dynamicBytes(U.hexlify(utf8(keyId)));
}
export function removeKeyCall(keyId) {
  return SELECTORS.removeKey + word(32).slice(2) + dynamicBytes(U.hexlify(utf8(keyId)));
}
export function executeCall(signer, inner) {
  return SELECTORS.execute + word(32).slice(2) + strip(addressWord(signer)) + word(0).slice(2) + word(96).slice(2)
    + dynamicBytes(inner);
}
export const packHigh = (high, low) => '0x' + word(high, 16).slice(2) + word(low, 16).slice(2);

/**
 * The before/after key maps and unsigned operation for one admitted change. `keys` is the complete sorted
 * independently read set; the bare key (add) is a parsed public anchor; remove selects an existing ID.
 */
export function planChange({ signer, nonce, keys, change, fees }) {
  if (!isLowerAddress(signer) || typeof nonce !== 'bigint' || nonce < 0n || nonce > UINT64_MAX) fail('input');
  const before = sortedKeys(keys);
  let after, inner, target;
  if (change.kind === 'add') {
    const key = change.key;
    if (!key || !isPoint(key.publicKey) || keyIdOf(key.publicKey) !== key.keyId) fail('curve');
    if (before.some((k) => k.keyId === key.keyId || k.publicKey === key.publicKey)) fail('duplicate');
    if (before.length >= MAX_KEYS) fail('limit');
    after = sortedKeys([...before, { keyId: key.keyId, publicKey: key.publicKey }]);
    inner = addKeyCall(key.publicKey, key.keyId);
    target = { keyId: key.keyId, publicKey: key.publicKey };
  } else if (change.kind === 'remove') {
    const existing = before.find((k) => k.keyId === change.keyId);
    if (!existing) fail('unknown');
    if (before.length <= 1) fail('last');
    after = before.filter((k) => k.keyId !== change.keyId);
    inner = removeKeyCall(change.keyId);
    target = existing;
  } else fail('input');
  const operation = Object.freeze({
    sender: signer, nonce: nonce.toString(), initCode: '0x', callData: executeCall(signer, inner),
    accountGasLimits: packHigh(VERIFICATION_GAS, CALL_GAS), preVerificationGas: PRE_VERIFICATION_GAS.toString(),
    gasFees: packHigh(fees.priorityFee, fees.maxFee), paymasterAndData: '0x', signature: '0x',
  });
  return Object.freeze({ action: change.kind, target: Object.freeze(target), before, after, operation });
}

export function sortedKeys(keys) {
  const list = keys.map((k) => Object.freeze({ keyId: k.keyId, publicKey: k.publicKey }));
  list.sort((a, b) => (a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0));
  const ids = new Set(list.map((k) => k.keyId)), points = new Set(list.map((k) => k.publicKey));
  if (ids.size !== list.length || points.size !== list.length
      || list.some((k) => !isPoint(k.publicKey) || keyIdOf(k.publicKey) !== k.keyId)) fail('keys');
  return Object.freeze(list);
}

/** Validates the nine canonical native fields; empty initCode/paymasterAndData/signature only. */
export function checkOperation(op) {
  if (!op || typeof op !== 'object' || Array.isArray(op)) fail('operation');
  closedFields(op, BODY_KEYS);
  if (!isLowerAddress(op.sender) || op.sender === ZERO_ADDRESS || !isDecimal(op.nonce)
      || !isDecimal(op.preVerificationGas) || op.initCode !== '0x' || op.paymasterAndData !== '0x'
      || op.signature !== '0x' || !/^0x([0-9a-f]{2}){4,4096}$/.test(op.callData)
      || !/^0x[0-9a-f]{64}$/.test(op.accountGasLimits) || !/^0x[0-9a-f]{64}$/.test(op.gasFees)) fail('operation');
  return op;
}

/** HybridDeleGator v1.3.0 EIP-712 hash of the PackedUserOperation (KeyChangeHash.swift). NOT getUserOpHash. */
export function typedDataHash(op, chainId = CHAIN_ID, entryPoint = ENTRYPOINT) {
  const domain = U.keccak256(U.hexConcat([DOMAIN_TYPE, keccakText('HybridDeleGator'), keccakText('1'),
    word(chainId), addressWord(op.sender)]));
  const struct = U.keccak256(U.hexConcat([USER_OP_TYPE, addressWord(op.sender), word(op.nonce),
    U.keccak256(op.initCode), U.keccak256(op.callData), op.accountGasLimits, word(op.preVerificationGas), op.gasFees,
    U.keccak256(op.paymasterAndData), addressWord(entryPoint)]));
  return U.keccak256(U.hexConcat(['0x1901', domain, struct]));
}

/** EntryPoint v0.7 getUserOpHash: keccak(abi.encode(keccak(pack(op)), entryPoint, chainId)), signature excluded. */
export function userOpHash(op, chainId = CHAIN_ID, entryPoint = ENTRYPOINT) {
  const packed = U.hexConcat([addressWord(op.sender), word(op.nonce), U.keccak256(op.initCode),
    U.keccak256(op.callData), op.accountGasLimits, word(op.preVerificationGas), op.gasFees,
    U.keccak256(op.paymasterAndData)]);
  return U.keccak256(U.hexConcat([U.keccak256(packed), addressWord(entryPoint), word(chainId)]));
}

/** handleOps([op with signature], beneficiary) calldata for EntryPoint v0.7. */
export function handleOpsCall(op, signature, beneficiary) {
  const coder = U.defaultAbiCoder;
  const tuple = [op.sender, op.nonce, op.initCode, op.callData, op.accountGasLimits, op.preVerificationGas,
    op.gasFees, op.paymasterAndData, signature];
  return SELECTORS.handleOps + coder.encode(
    ['tuple(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[]', 'address'],
    [[tuple], beneficiary]).slice(2);
}

// ---------------------------------------------------------------------------------------------------------------
// Native envelope and commitment (HybridKeyRequestEnvelope / KeyApprovalDigest.commitment)

export const issuedAtFor = (now) => Math.max(1, now - CLOCK_SKEW_SECONDS);

export function commitment({ id, keyId, binding, issuedAt, expiresAt, operation, typedHash,
  chainId = CHAIN_ID, entryPoint = ENTRYPOINT, signer = operation.sender }) {
  const fields = [utf8('1'), utf8(PURPOSE), utf8(CODEC_ID), U.arrayify('0x' + id.replaceAll('-', '')), utf8(keyId),
    U.arrayify(binding), U.arrayify(word(issuedAt, 8)), U.arrayify(word(expiresAt, 8)), U.arrayify(word(chainId)),
    U.arrayify(entryPoint), U.arrayify(signer), U.arrayify(operation.sender), U.arrayify(word(operation.nonce)),
    U.arrayify(operation.initCode), U.arrayify(operation.callData), U.arrayify(operation.accountGasLimits),
    U.arrayify(word(operation.preVerificationGas)), U.arrayify(operation.gasFees),
    U.arrayify(operation.paymasterAndData), U.arrayify(operation.signature), U.arrayify(typedHash)];
  return U.sha256(U.concat([utf8(COMMITMENT_DOMAIN), ...fields.flatMap((f) => [U.arrayify(word(f.length, 4)), f])]));
}

/** One exact request: envelope text, H, commitment and validity window. Recomputed, never taken from a peer. */
export function buildRequest({ context, operation, id, issuedAt }) {
  checkOperation(operation);
  if (!isUUID(id) || !Number.isSafeInteger(issuedAt) || issuedAt < 1) fail('request');
  const expiresAt = issuedAt + VALIDITY_SECONDS;
  const chainId = anchorChain(context).decimal;
  const typedHash = typedDataHash(operation, chainId);
  const envelope = { v: '1', id, purpose: PURPOSE, codecId: CODEC_ID, keyId: context.keyId, binding: context.binding,
    issuedAt: String(issuedAt), expiresAt: String(expiresAt), chainId, entryPoint: ENTRYPOINT,
    signer: context.signer, body: Object.fromEntries(BODY_KEYS.map((k) => [k, operation[k]])) };
  if (Object.keys(envelope).join() !== ROOT_KEYS.join()) fail('request');
  const text = JSON.stringify(envelope);
  if (utf8(text).length > MAX_ENVELOPE_BYTES) fail('request');
  return Object.freeze({ id, issuedAt, expiresAt, envelope: text, typedDataHash: typedHash,
    commitment: commitment({ id, keyId: context.keyId, binding: context.binding, issuedAt, expiresAt, operation,
      typedHash, chainId }),
    userOpHash: userOpHash(operation, chainId), operation });
}

// ---------------------------------------------------------------------------------------------------------------
// Closed native context and result (HybridKeySessionWire.swift)

function exactKeys(value, keys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype
      && Object.getPrototypeOf(value) !== null) fail(code);
  const names = Object.keys(value).sort(), wanted = [...keys].sort();
  if (names.length !== wanted.length || names.some((n, i) => n !== wanted[i])) fail(code);
}

/** The `p256_getKeyChangeContext` result for the selected anchor. Returns a frozen semantic copy. */
export function validateNativeContext(c, anchor) {
  exactKeys(c, CONTEXT_KEYS, 'context');
  const chain = anchorChain(anchor);
  if (c.version !== 1 || c.origin !== ORIGIN || c.chainId !== chain.decimal || c.codecId !== CODEC_ID
      || c.purpose !== PURPOSE || c.maxValiditySeconds !== VALIDITY_SECONDS || c.maxEnvelopeBytes !== MAX_ENVELOPE_BYTES
      || c.signer !== anchor.signerAddress || c.entryPoint !== ENTRYPOINT || c.keyId !== anchor.keyId
      || c.publicKey !== anchor.publicKey || c.implementation !== IMPLEMENTATION
      || c.implementationCodeHash !== chain.implementationCodeHash || c.owner !== ZERO_ADDRESS
      || !isHash(c.binding) || c.binding === '0x' + '00'.repeat(32) || !isHash(c.blockHash)
      || !isDecimal(c.nonce) || !isDecimal(c.blockNumber) || !isDecimal(c.maxGasUnits) || !isDecimal(c.maxFeePerGas)
      || BigInt(c.nonce) > UINT64_MAX || BigInt(c.maxGasUnits) === 0n || BigInt(c.maxFeePerGas) === 0n
      || !Array.isArray(c.keys) || c.keys.length < 1 || c.keys.length > MAX_KEYS) fail('context');
  for (const key of c.keys) exactKeys(key, ['keyId', 'publicKey'], 'context');
  let keys;
  try { keys = sortedKeys(c.keys); } catch { fail('context'); }
  if (keys.some((k, i) => k.keyId !== c.keys[i].keyId) || !keys.some((k) => k.keyId === c.keyId
      && k.publicKey === c.publicKey)) fail('context');
  return Object.freeze({ signer: c.signer, keyId: c.keyId, publicKey: c.publicKey, binding: c.binding,
    nonce: BigInt(c.nonce), blockNumber: BigInt(c.blockNumber), blockHash: c.blockHash, keys,
    maxGasUnits: BigInt(c.maxGasUnits), maxFeePerGas: BigInt(c.maxFeePerGas),
    ...(chain === POLYGON ? {} : { chainId: chain.decimal }) });
}

export const sameKeys = (a, b) => a.length === b.length
  && a.every((k, i) => k.keyId === b[i].keyId && k.publicKey === b[i].publicKey);

/**
 * Native and independently read Web context agree on identity, complete key map and nonce; their blocks may differ
 * within the window only. The native gas policy must admit the fixed gas total.
 */
export function agree(native, web) {
  if (native.signer !== web.signer || !sameKeys(native.keys, web.keys) || native.nonce !== web.nonce) fail('changed');
  const delta = native.blockNumber - web.block.number, window = anchorChain(native).blockWindow;
  if (delta > window || -delta > window) fail('changed');
  if (native.maxGasUnits < TOTAL_GAS) fail('policy');
  return true;
}

/** Same semantic authority (binding, identity, keys, nonce, policy); block observations are incidental. */
export function sameAuthority(a, b) {
  return a.signer === b.signer && a.keyId === b.keyId && a.publicKey === b.publicKey && a.binding === b.binding
    && a.nonce === b.nonce && sameKeys(a.keys, b.keys) && a.maxGasUnits === b.maxGasUnits
    && a.maxFeePerGas === b.maxFeePerGas;
}

/**
 * The `p256_signKeyChangeRequest` result: every closed field matches the request, then real WebCrypto ECDSA P-256
 * over raw H exactly once (the platform hashes it), low-S, and keccak256(ASCII keyId)||r||s. Returns the 96 bytes.
 */
export async function verifyResult(result, request, context, now, subtle = globalThis.crypto?.subtle) {
  exactKeys(result, RESULT_KEYS, 'result');
  if (!Number.isSafeInteger(now) || now < request.issuedAt || now >= request.expiresAt) fail('expired');
  const op = request.operation;
  if (result.version !== 1 || result.purpose !== PURPOSE || result.requestId !== request.id
      || result.keyId !== context.keyId || result.codecId !== CODEC_ID || result.commitment !== request.commitment
      || result.binding !== context.binding || result.chainId !== anchorChain(context).decimal
      || result.entryPoint !== ENTRYPOINT || result.signer !== context.signer || result.nonce !== op.nonce
      || result.typedDataHash !== request.typedDataHash
      || typedDataHash(op, anchorChain(context).decimal) !== request.typedDataHash
      || result.publicPoint !== context.publicKey) fail('result');
  if (typeof result.rawSignature !== 'string' || !/^0x[0-9a-f]{128}$/.test(result.rawSignature)) fail('result');
  const raw = result.rawSignature, r = BigInt('0x' + raw.slice(2, 66)), s = BigInt('0x' + raw.slice(66));
  if (r <= 0n || r >= N || s <= 0n || s > N / 2n) fail('result');
  const encoded = U.hexConcat([keyIdHash(context.keyId), raw]);
  if (result.signerSignature !== encoded) fail('result');
  if (!subtle) fail('crypto');
  const key = await subtle.importKey('raw', U.arrayify(context.publicKey), { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['verify']);
  if (!await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, U.arrayify(raw), U.arrayify(request.typedDataHash))) {
    fail('result');
  }
  return encoded;
}

export const LOW_S_ORDER = N;
