'use strict';
// Independent derivation oracle: stdlib-only Keccak-256, ABI and CREATE2 written from the design, never from
// model.js or ethers. Used to decode captured wallet requests and Swift handoff output.
const crypto = require('node:crypto');

const ROUNDS = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n, 0x000000000000808bn,
  0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an, 0x0000000000000088n,
  0x0000000080008009n, 0x000000008000000an, 0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
  0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
const MASK = (1n << 64n) - 1n;

function rotl(v, n) {
  return n === 0 ? v : ((v << BigInt(n)) | (v >> BigInt(64 - n))) & MASK;
}

function keccak256(bytes) {
  const rate = 136;
  const padded = Buffer.alloc(Math.ceil((bytes.length + 1) / rate) * rate);
  Buffer.from(bytes).copy(padded);
  padded[bytes.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  let s = Array.from({ length: 5 }, () => Array(5).fill(0n));
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) s[i % 5][Math.floor(i / 5)] ^= padded.readBigUInt64LE(off + 8 * i);
    for (const rc of ROUNDS) {
      const c = [0, 1, 2, 3, 4].map((x) => s[x][0] ^ s[x][1] ^ s[x][2] ^ s[x][3] ^ s[x][4]);
      s = s.map((col, x) => col.map((v) => v ^ c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)));
      const m = Array.from({ length: 5 }, () => Array(5).fill(0n));
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) m[y][(2 * x + 3 * y) % 5] = rotl(s[x][y], ROT[x][y]);
      s = m.map((col, x) => col.map((v, y) => v ^ (~m[(x + 1) % 5][y] & MASK & m[(x + 2) % 5][y])));
      s[0][0] ^= rc;
    }
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(s[i % 5][Math.floor(i / 5)], 8 * i);
  return out;
}

const hex = (b) => '0x' + Buffer.from(b).toString('hex');
const bytes = (h) => Buffer.from(h.replace(/^0x/, ''), 'hex');
const word = (n) => { const b = Buffer.alloc(32); b.writeBigUInt64BE(BigInt(n), 24); return b; };
const dyn = (b) => Buffer.concat([word(b.length), b, Buffer.alloc((32 - (b.length % 32)) % 32)]);
const selector = (sig) => keccak256(Buffer.from(sig)).subarray(0, 4);

function checksum(addr20) {
  const lower = Buffer.from(addr20).toString('hex');
  const h = keccak256(Buffer.from(lower)).toString('hex');
  return '0x' + [...lower].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join('');
}

const FACTORY = '0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c';
const IMPLEMENTATION = '0x48dBe696A4D990079e039489bA2053B36E8FFEC4';

/** Recipe from a public point and salt, given the pinned proxy creation bytecode. */
function derive(pointHex, saltHex, proxyHex) {
  const point = bytes(pointHex);
  const keyID = crypto.createHash('sha256').update(point).digest('hex');
  const keyIDs = Buffer.concat([word(1), word(32), dyn(Buffer.from(keyID))]);
  const xs = Buffer.concat([word(1), point.subarray(1, 33)]);
  const ys = Buffer.concat([word(1), point.subarray(33)]);
  const initializer = Buffer.concat([selector('initialize(address,string[],uint256[],uint256[])'), word(0), word(128),
    word(128 + keyIDs.length), word(128 + keyIDs.length + xs.length), keyIDs, xs, ys]);
  const creation = Buffer.concat([bytes(proxyHex), Buffer.alloc(12), bytes(IMPLEMENTATION), word(64), dyn(initializer)]);
  const creationHash = keccak256(creation);
  const address = checksum(keccak256(Buffer.concat([Buffer.from([0xff]), bytes(FACTORY), bytes(saltHex),
    creationHash])).subarray(12));
  const calldata = Buffer.concat([selector('deploy(bytes,bytes32)'), word(64), bytes(saltHex), dyn(creation)]);
  return { keyID, initializer: hex(initializer), creation: hex(creation), creationHash: hex(creationHash), address,
    calldata: hex(calldata) };
}

/** Decodes `deploy(bytes,bytes32)` calldata strictly into creation + salt and splits the initializer. */
function decodeDeploy(calldataHex, proxyHex) {
  const data = bytes(calldataHex);
  if (!data.subarray(0, 4).equals(selector('deploy(bytes,bytes32)'))) throw new Error('not deploy(bytes,bytes32)');
  const offset = Number(data.readBigUInt64BE(4 + 24));
  const salt = hex(data.subarray(36, 68));
  const length = Number(data.readBigUInt64BE(4 + offset + 24));
  const creation = data.subarray(4 + offset + 32, 4 + offset + 32 + length);
  const proxy = bytes(proxyHex);
  if (!creation.subarray(0, proxy.length).equals(proxy)) throw new Error('creation does not start with pinned proxy');
  const args = creation.subarray(proxy.length);
  const implementation = checksum(args.subarray(12, 32));
  const initLength = Number(args.readBigUInt64BE(64 + 24));
  const initializer = args.subarray(96, 96 + initLength);
  const owner = hex(initializer.subarray(4 + 12, 36));
  const keyCount = Number(initializer.readBigUInt64BE(4 + 128 + 24));
  const x = hex(initializer.subarray(initializer.length - 32 * 3, initializer.length - 32 * 2));
  const y = hex(initializer.subarray(initializer.length - 32));
  const keyIDStart = 4 + 128 + 32 + 32 + 32;
  const keyID = initializer.subarray(keyIDStart, keyIDStart + 64).toString();
  return { salt, creation: hex(creation), implementation, owner, keyCount, keyID, x, y,
    exact: hex(Buffer.concat([selector('deploy(bytes,bytes32)'), word(64), bytes(salt), dyn(creation)])) === calldataHex };
}

module.exports = { keccak256, hex, bytes, checksum, derive, decodeDeploy, selector, FACTORY, IMPLEMENTATION };
