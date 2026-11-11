// Independent cross-implementation check of fresh Swift SafeDeFiCompiler output (docs/public-defi-spec-v1.md §2.1-§2.3).
//
// Reads $DEFI_V3_OUTPUT_DIR/vectors.json written by the Swift XCTest emitter in the same gate run (bound by
// $DEFI_V3_RUN_NONCE) and recomputes every SafeTx hash, EIP-191/EIP-712 digest D, SafeMessage hash M and v3
// commitment from the wire bytes with web/registration/defi-v3.js (vendored ethers keccak256, Node SHA-256,
// BigInt). A missing variable, file, nonce or purpose fails; nothing is skipped. ethers' own _TypedDataEncoder
// and hashMessage cross-check only the non-recursive cases they support. No network, key or signing.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import ethers from '../vendor/ethers.js';
import {
  bytesToHex, computeRequest, get, hexToBytes, parseJSON, personalDigest, safeMessage, toPlain, typedDataDigest,
} from '../defi-v3.js';

const U = ethers.utils;
const sha256 = (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest());
const REQUIRED_KINDS = ['safeTx', 'personal', 'eip712'];

/** Fail-closed reader for the fresh Swift output. */
export function loadVectors(env) {
  const dir = env.DEFI_V3_OUTPUT_DIR;
  if (!dir) throw new Error('DEFI_V3_OUTPUT_DIR is required');
  const nonce = env.DEFI_V3_RUN_NONCE;
  if (!nonce) throw new Error('DEFI_V3_RUN_NONCE is required');
  const text = readFileSync(path.join(dir, 'vectors.json'), 'utf8');
  if (!text.trim()) throw new Error('empty vectors.json');
  const vectors = JSON.parse(text);
  if (!Array.isArray(vectors) || vectors.length === 0) throw new Error('malformed vectors.json');
  for (const v of vectors) {
    if (v.runNonce !== nonce) throw new Error(`stale vector ${v.name}`);
    if (typeof v.wireHex !== 'string' || typeof v.swift?.commitment !== 'string') throw new Error('malformed vector');
  }
  for (const kind of REQUIRED_KINDS) {
    if (!vectors.some((v) => v.kind === kind)) throw new Error(`missing purpose ${kind}`);
  }
  return vectors;
}

const vectors = loadVectors(process.env);

test('fresh Swift vectors cover every purpose', () => {
  assert.ok(vectors.length >= 3);
  assert.deepEqual([...new Set(vectors.map((v) => v.kind))].sort(), [...REQUIRED_KINDS].sort());
});

for (const vector of vectors) {
  test(`independent recomputation: ${vector.name}`, () => {
    const wire = hexToBytes(vector.wireHex);
    const web = computeRequest(wire, sha256);
    assert.equal(web.kind, vector.kind);
    assert.equal(bytesToHex(web.payloadJson), vector.swift.payloadJson);
    assert.equal(bytesToHex(web.signedDigest), vector.swift.signedDigest);
    assert.equal(web.messageDigest === null ? null : bytesToHex(web.messageDigest), vector.swift.messageDigest);
    assert.equal(bytesToHex(web.commitment), vector.swift.commitment);
    if (vector.kind === 'safeTx') assert.equal(bytesToHex(web.safeTxPreimage), vector.swift.safeTxPreimage);
    if (vector.kind === 'eip712') {
      assert.equal(bytesToHex(web.domainSeparator), vector.swift.domainSeparator);
      assert.equal(web.domainMode, vector.swift.domainMode);
      assert.deepEqual(web.unhashedFieldPaths, vector.swift.unhashedFieldPaths);
    }
  });
}

/** Lowercases addresses so ethers does not apply EIP-55 checksum policy to fixture data. */
function plainForEthers(value) {
  if (Array.isArray(value)) return value.map(plainForEthers);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plainForEthers(v)]));
  }
  return typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value) ? value.toLowerCase() : value;
}

test('ethers cross-check: SafeTx, personal and non-recursive standard-domain typed data', () => {
  let checked = 0;
  for (const vector of vectors) {
    const root = parseJSON(hexToBytes(vector.wireHex));
    const payload = parseJSON(hexToBytes(get(root, 'payloadJson').v));
    const chainId = get(payload, 'chainId').v;
    const safe = get(payload, 'safe').v;
    const body = get(payload, 'body');
    if (vector.kind === 'safeTx') {
      const tx = toPlain(get(body, 'tx'));
      const hash = U._TypedDataEncoder.hash({ chainId, verifyingContract: safe }, {
        SafeTx: [['to', 'address'], ['value', 'uint256'], ['data', 'bytes'], ['operation', 'uint8'],
          ['safeTxGas', 'uint256'], ['baseGas', 'uint256'], ['gasPrice', 'uint256'], ['gasToken', 'address'],
          ['refundReceiver', 'address'], ['nonce', 'uint256']].map(([name, type]) => ({ name, type })),
      }, tx);
      assert.equal(hash, vector.swift.signedDigest);
      checked += 1;
    } else if (vector.kind === 'personal') {
      assert.equal(U.hashMessage(hexToBytes(get(body, 'bytes').v)), vector.swift.messageDigest);
      checked += 1;
    } else if (['eip712-mail', 'eip712-permit2', 'eip712-nested-arrays'].includes(vector.name)) {
      const typed = toPlain(parseJSON(hexToBytes(get(body, 'typedDataJson').v)));
      const types = { ...typed.types };
      delete types.EIP712Domain;
      const hash = U._TypedDataEncoder.hash(plainForEthers(typed.domain), types, plainForEthers(typed.message));
      assert.equal(hash, vector.swift.messageDigest);
      checked += 1;
    }
  }
  assert.ok(checked >= 9, `only ${checked} ethers cross-checks`);
});

test('reference sanity: published EIP-191/EIP-712 answers and SafeMessage wraps D, not raw D', () => {
  assert.equal(bytesToHex(personalDigest(new TextEncoder().encode('hello world'))),
    '0xd9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68');
  const mail = readFileSync(new URL('fixtures/DeFiV3/eip712-mail.json', import.meta.url));
  const typed = typedDataDigest(new Uint8Array(mail));
  assert.equal(bytesToHex(typed.digest), '0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2');
  const m = safeMessage(1n, '0x1111111111111111111111111111111111111111', typed.digest);
  assert.notEqual(bytesToHex(m), bytesToHex(typed.digest));
});

test('reference sanity: lossless parser keeps tokens, order and distinct NFC/NFD keys; rejects duplicates', () => {
  const doc = parseJSON(new TextEncoder().encode(
    '{"b":115792089237316195423570985008687907853269984665640564039457584007913129639935,"\u00e9":1,"e\u0301":2}'));
  assert.deepEqual(doc.members.map(([k]) => k), ['b', '\u00e9', 'e\u0301']);
  assert.equal(get(doc, 'b').raw, '115792089237316195423570985008687907853269984665640564039457584007913129639935');
  assert.throws(() => parseJSON(new TextEncoder().encode('{"a":1,"\\u0061":2}')), /duplicate/);
  assert.throws(() => parseJSON(Uint8Array.of(0x22, 0xc0, 0x80, 0x22)));
  assert.throws(() => parseJSON(new TextEncoder().encode('"\\ud800"')));
});

test('vector reader fails closed for missing, empty, malformed, stale and incomplete output', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'defi-v3-reader-'));
  try {
    const good = { name: 'x', kind: 'safeTx', runNonce: 'n1', wireHex: '0x', swift: { commitment: '0x' } };
    const all = REQUIRED_KINDS.map((kind) => ({ ...good, kind }));
    assert.throws(() => loadVectors({}), /DEFI_V3_OUTPUT_DIR/);
    assert.throws(() => loadVectors({ DEFI_V3_OUTPUT_DIR: dir }), /DEFI_V3_RUN_NONCE/);
    assert.throws(() => loadVectors({ DEFI_V3_OUTPUT_DIR: dir, DEFI_V3_RUN_NONCE: 'n1' }), /ENOENT/);
    writeFileSync(path.join(dir, 'vectors.json'), '');
    assert.throws(() => loadVectors({ DEFI_V3_OUTPUT_DIR: dir, DEFI_V3_RUN_NONCE: 'n1' }), /empty/);
    writeFileSync(path.join(dir, 'vectors.json'), '{"not":"a list"}');
    assert.throws(() => loadVectors({ DEFI_V3_OUTPUT_DIR: dir, DEFI_V3_RUN_NONCE: 'n1' }), /malformed/);
    writeFileSync(path.join(dir, 'vectors.json'), JSON.stringify(all));
    assert.throws(() => loadVectors({ DEFI_V3_OUTPUT_DIR: dir, DEFI_V3_RUN_NONCE: 'n2' }), /stale/);
    writeFileSync(path.join(dir, 'vectors.json'), JSON.stringify(all.slice(0, 2)));
    assert.throws(() => loadVectors({ DEFI_V3_OUTPUT_DIR: dir, DEFI_V3_RUN_NONCE: 'n1' }), /missing purpose eip712/);
    writeFileSync(path.join(dir, 'vectors.json'), JSON.stringify(all));
    assert.equal(loadVectors({ DEFI_V3_OUTPUT_DIR: dir, DEFI_V3_RUN_NONCE: 'n1' }).length, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
