// Independent Web reference for the public DeFi v3 wire (docs/public-defi-spec-v1.md §2.1.1-§2.3.2).
//
// Written separately from the Swift compiler. Primitives: keccak256 from the vendored ethers 5.4.0 utils only,
// SHA-256 injected by the caller (Node crypto in tests), and native BigInt. The EIP-712 encoder below is
// independent of ethers' _TypedDataEncoder (which rejects recursive types and EIP712Domain declarations).
// This module computes hashes and commitments for review/cross-checking only; it never signs and enables no
// production capability.
import ethers from './vendor/ethers.js';

const U = ethers.utils;
const TWO256 = 1n << 256n;

export const COMMITMENT_DOMAIN = 'p256-signer/safe-request/v3\0';
export const PURPOSES = {
  'safe-tx-v1.5.0/generic-v1': 'safeTx',
  'safe-message-v1.5.0/eip712-v1': 'eip712',
  'safe-message-v1.5.0/personal-v1': 'personal',
};

// ---------- bytes ----------

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(hex)) throw new Error('bad hex');
  const out = new Uint8Array((hex.length - 2) / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(2 + i * 2, 4 + i * 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  return '0x' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

const utf8 = (text) => new TextEncoder().encode(text);
export const keccak = (bytes) => hexToBytes(U.keccak256(bytes));

function word(value) {
  let v = BigInt(value);
  if (v < 0n) v += TWO256;
  if (v < 0n || v >= TWO256) throw new Error('word range');
  return hexToBytes('0x' + v.toString(16).padStart(64, '0'));
}

function addressWord(hex) {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 20) throw new Error('address');
  return concat(new Uint8Array(12), bytes);
}

function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; }
function u64(n) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; }

// ---------- lossless JSON (key order, raw number tokens, duplicate rejection) ----------

export function parseJSON(bytes) {
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new Error('BOM');
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  let i = 0;
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i += 1; };
  const fail = () => { throw new Error(`json at ${i}`); };
  function str() {
    i += 1;
    let out = '';
    for (;;) {
      if (i >= text.length) fail();
      const c = text[i];
      if (c === '"') { i += 1; return out; }
      if (c === '\\') {
        const e = text[i + 1];
        i += 2;
        const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
        if (e in simple) { out += simple[e]; continue; }
        if (e !== 'u') fail();
        const unit = () => { const h = text.slice(i, i + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) fail(); i += 4; return parseInt(h, 16); };
        const hi = unit();
        if (hi >= 0xd800 && hi <= 0xdbff) {
          if (text.slice(i, i + 2) !== '\\u') fail();
          i += 2;
          const lo = unit();
          if (lo < 0xdc00 || lo > 0xdfff) fail();
          out += String.fromCharCode(hi, lo);
        } else if (hi >= 0xdc00 && hi <= 0xdfff) {
          fail();
        } else {
          out += String.fromCharCode(hi);
        }
        continue;
      }
      if (c.charCodeAt(0) < 0x20) fail();
      out += c;
      i += 1;
    }
  }
  function value() {
    ws();
    const c = text[i];
    if (c === '{') {
      i += 1;
      const members = [];
      const seen = new Set();
      ws();
      if (text[i] === '}') { i += 1; return { t: 'object', members }; }
      for (;;) {
        ws();
        if (text[i] !== '"') fail();
        const key = str();
        if (seen.has(key)) throw new Error('duplicate key');
        seen.add(key);
        ws();
        if (text[i] !== ':') fail();
        i += 1;
        members.push([key, value()]);
        ws();
        if (text[i] === ',') { i += 1; continue; }
        if (text[i] === '}') { i += 1; return { t: 'object', members }; }
        fail();
      }
    }
    if (c === '[') {
      i += 1;
      const items = [];
      ws();
      if (text[i] === ']') { i += 1; return { t: 'array', items }; }
      for (;;) {
        items.push(value());
        ws();
        if (text[i] === ',') { i += 1; continue; }
        if (text[i] === ']') { i += 1; return { t: 'array', items }; }
        fail();
      }
    }
    if (c === '"') return { t: 'string', v: str() };
    for (const [lit, v] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(lit, i)) { i += lit.length; return v === null ? { t: 'null' } : { t: 'bool', v }; }
    }
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!m) fail();
    i += m[0].length;
    return { t: 'number', raw: m[0] };
  }
  const root = value();
  ws();
  if (i !== text.length) fail();
  return root;
}

export function get(node, key) {
  if (node?.t !== 'object') return undefined;
  const hit = node.members.find(([k]) => k === key);
  return hit ? hit[1] : undefined;
}

function strOf(node) { if (node?.t !== 'string') throw new Error('string expected'); return node.v; }

/** Plain JS view (numbers as decimal strings) for cross-checks with other libraries. */
export function toPlain(node) {
  switch (node.t) {
    case 'object': return Object.fromEntries(node.members.map(([k, v]) => [k, toPlain(v)]));
    case 'array': return node.items.map(toPlain);
    case 'string': return node.v;
    case 'number': return node.raw;
    case 'bool': return node.v;
    default: return null;
  }
}

// ---------- Safe v1.5.0 hashes ----------

const SAFE_DOMAIN_TYPEHASH = keccak(utf8('EIP712Domain(uint256 chainId,address verifyingContract)'));
const SAFE_TX_TYPEHASH = keccak(utf8('SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,'
  + 'uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)'));
const SAFE_MSG_TYPEHASH = keccak(utf8('SafeMessage(bytes message)'));

export function safeDomainSeparator(chainId, safe) {
  return keccak(concat(SAFE_DOMAIN_TYPEHASH, word(chainId), addressWord(safe)));
}

export function safeTx(chainId, safe, tx) {
  const struct = keccak(concat(SAFE_TX_TYPEHASH, addressWord(tx.to), word(tx.value), keccak(hexToBytes(tx.data)),
    word(tx.operation), word(tx.safeTxGas), word(tx.baseGas), word(tx.gasPrice), addressWord(tx.gasToken),
    addressWord(tx.refundReceiver), word(tx.nonce)));
  const preimage = concat(Uint8Array.of(0x19, 0x01), safeDomainSeparator(chainId, safe), struct);
  return { preimage, hash: keccak(preimage) };
}

/** M = keccak(0x1901 || domainSeparator || keccak(SAFE_MSG_TYPEHASH || keccak(abi.encode(D)))), abi.encode(D) = D. */
export function safeMessage(chainId, safe, digest) {
  if (digest.length !== 32) throw new Error('digest');
  const struct = keccak(concat(SAFE_MSG_TYPEHASH, keccak(digest)));
  return keccak(concat(Uint8Array.of(0x19, 0x01), safeDomainSeparator(chainId, safe), struct));
}

export function personalDigest(message) {
  return keccak(concat(Uint8Array.of(0x19), utf8(`Ethereum Signed Message:\n${message.length}`), message));
}

// ---------- independent EIP-712 ----------

const DOMAIN_FIELDS = [['name', 'string'], ['version', 'string'], ['chainId', 'uint256'],
  ['verifyingContract', 'address'], ['salt', 'bytes32']];

function baseStruct(type) {
  const m = /^([A-Za-z_$][A-Za-z0-9_$]*)(\[[0-9]*\])*$/.exec(type);
  if (!m) throw new Error('type');
  return m[1];
}

function integerValue(node, bits, signed) {
  let v;
  if (node.t === 'number') {
    if (!/^-?(0|[1-9][0-9]*)$/.test(node.raw)) throw new Error('integer token');
    v = BigInt(node.raw);
  } else if (node.t === 'string') {
    const s = node.v;
    if (/^0x[0-9a-fA-F]+$/.test(s)) v = BigInt(s);
    else if (/^(0|[1-9][0-9]*)$/.test(s)) v = BigInt(s);
    else if (signed && /^-[1-9][0-9]*$/.test(s)) v = BigInt(s);
    else throw new Error('integer string');
  } else {
    throw new Error('integer type');
  }
  const max = signed ? (1n << BigInt(bits - 1)) - 1n : (1n << BigInt(bits)) - 1n;
  const min = signed ? -(1n << BigInt(bits - 1)) : 0n;
  if (v > max || v < min) throw new Error('integer range');
  return word(v);
}

export function typedDataDigest(bytes) {
  const root = parseJSON(bytes);
  const typesNode = get(root, 'types');
  const types = new Map(typesNode.members.map(([name, list]) => [name,
    list.items.map((f) => ({ name: strOf(get(f, 'name')), type: strOf(get(f, 'type')) }))]));
  const domainNode = get(root, 'domain');
  let mode = 'declared';
  if (!types.has('EIP712Domain')) {
    mode = 'derived';
    const present = new Set(domainNode.members.map(([k]) => k));
    types.set('EIP712Domain', DOMAIN_FIELDS.filter(([n]) => present.has(n)).map(([name, type]) => ({ name, type })));
  }
  const unhashed = [];
  const pointer = (k) => k.replaceAll('~', '~0').replaceAll('/', '~1');

  function encodeType(primary) {
    const deps = new Set();
    const walk = (name) => {
      for (const f of types.get(name)) {
        const base = baseStruct(f.type);
        if (types.has(base) && base !== primary && !deps.has(base)) { deps.add(base); walk(base); }
      }
    };
    walk(primary);
    const order = [primary, ...[...deps].sort()];
    return order.map((n) => `${n}(${types.get(n).map((f) => `${f.type} ${f.name}`).join(',')})`).join('');
  }

  function encodeValue(type, node, path) {
    const arr = /^(.*)\[([0-9]*)\]$/.exec(type);
    if (arr) {
      if (node.t !== 'array') throw new Error('array');
      if (arr[2] !== '' && node.items.length !== Number(arr[2])) throw new Error('array length');
      return keccak(concat(...node.items.map((item, i) => encodeValue(arr[1], item, `${path}/${i}`))));
    }
    if (types.has(type)) return hashStruct(type, node, path);
    if (type === 'bool') { if (node.t !== 'bool') throw new Error('bool'); return word(node.v ? 1 : 0); }
    if (type === 'address') return addressWord(strOf(node));
    if (type === 'string') return keccak(utf8(strOf(node)));
    if (type === 'bytes') return keccak(hexToBytes(strOf(node)));
    let m = /^bytes([1-9][0-9]?)$/.exec(type);
    if (m) {
      const b = hexToBytes(strOf(node));
      if (b.length !== Number(m[1])) throw new Error('bytesN');
      return concat(b, new Uint8Array(32 - b.length));
    }
    m = /^(u?)int([1-9][0-9]*)$/.exec(type);
    if (m) return integerValue(node, Number(m[2]), m[1] === '');
    throw new Error(`unknown type ${type}`);
  }

  function hashStruct(name, node, path) {
    if (node.t !== 'object') throw new Error('struct');
    const fields = types.get(name);
    const parts = [keccak(utf8(encodeType(name)))];
    for (const f of fields) {
      const v = get(node, f.name);
      if (v === undefined) throw new Error('missing field');
      parts.push(encodeValue(f.type, v, `${path}/${pointer(f.name)}`));
    }
    const declared = new Set(fields.map((f) => f.name));
    for (const [k] of node.members) if (!declared.has(k)) unhashed.push(`${path}/${pointer(k)}`);
    return keccak(concat(...parts));
  }

  const domainSeparator = hashStruct('EIP712Domain', domainNode, '/domain');
  if (unhashed.length) throw new Error('domain key');
  const messageHash = hashStruct(strOf(get(root, 'primaryType')), get(root, 'message'), '/message');
  const digest = keccak(concat(Uint8Array.of(0x19, 0x01), domainSeparator, messageHash));
  return { digest, domainSeparator, messageHash, mode, unhashed, root };
}

// ---------- commitment v3 ----------

/** SHA-256(domain || for each field: uint32BE(len) || bytes). `sha256` is caller-supplied (bytes => bytes). */
export function commitmentV3(fields, sha256) {
  const parts = [utf8(COMMITMENT_DOMAIN)];
  for (const field of fields) parts.push(u32(field.length), field);
  return sha256(concat(...parts));
}

function uuidBytes(id) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) throw new Error('uuid');
  return hexToBytes('0x' + id.replaceAll('-', ''));
}

/** Recomputes a complete v3 request from its wire bytes: digests and commitment. */
export function computeRequest(wire, sha256) {
  const root = parseJSON(wire);
  const field = (k) => strOf(get(root, k));
  const kind = PURPOSES[field('purpose')];
  if (!kind || field('v') !== '3') throw new Error('profile');
  const payloadJson = hexToBytes(field('payloadJson'));
  const payload = parseJSON(payloadJson);
  const chainId = BigInt(strOf(get(payload, 'chainId')));
  const safe = strOf(get(payload, 'safe'));
  const body = get(payload, 'body');
  const out = { kind, payloadJson };
  if (kind === 'safeTx') {
    const tx = Object.fromEntries(get(body, 'tx').members.map(([k, v]) => [k, strOf(v)]));
    const { preimage, hash } = safeTx(chainId, safe, tx);
    Object.assign(out, { safeTxPreimage: preimage, messageDigest: null, signedDigest: hash });
  } else if (kind === 'personal') {
    const bytes = hexToBytes(strOf(get(body, 'bytes')));
    const digest = personalDigest(bytes);
    Object.assign(out, { messageDigest: digest, signedDigest: safeMessage(chainId, safe, digest) });
  } else {
    const typed = typedDataDigest(hexToBytes(strOf(get(body, 'typedDataJson'))));
    Object.assign(out, { messageDigest: typed.digest, domainSeparator: typed.domainSeparator, domainMode: typed.mode,
      unhashedFieldPaths: typed.unhashed, signedDigest: safeMessage(chainId, safe, typed.digest), typed });
  }
  out.commitment = commitmentV3([
    utf8(field('v')), utf8(field('purpose')), utf8(field('codecId')), uuidBytes(field('id')),
    hexToBytes('0x' + field('keyId')), hexToBytes(field('binding')), u64(field('issuedAt')), u64(field('expiresAt')),
    hexToBytes(field('signer')), payloadJson, out.signedDigest,
  ], sha256);
  return out;
}
