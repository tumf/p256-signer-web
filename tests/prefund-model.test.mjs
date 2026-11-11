// Unit tests of the real prefund-model.js exports (pure, no I/O): exact P/D/Q arithmetic and its bounds, the depositTo
// ABI against an independent ethers Interface, the Deposited event shape and its cumulative meaning, the closed
// attempt schema/serializer with its strict v1/v2 version dispatch over pinned literal v1 bytes, the bounded
// WalletConnect metadata override and the authority parser reuse.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import ethers from '../vendor/ethers.js';
import { ENTRYPOINT, UINT120_MAX, UINT256_MAX, UINT64_MAX, parseAuthority, sha256Hex } from '../key-model.js';
import {
  DEPOSITED_EVENT, DEPOSIT_TO_SELECTOR, ENTRYPOINT_RUNTIME_HASH, MAX_ATTEMPT_BYTES, OUTCOME_FIELDS, PREFUND_GAS,
  PrefundError, REQUIRED_FIELDS, V1_REQUIRED_FIELDS, V2_REQUIRED_FIELDS, addressTopic, depositCall, fundingPlan,
  matchingDeposit, maximumDebit, outerFunding, parseFundingAttempt, requiredDeposit, serializeFundingAttempt,
  isBorProtocolLog, BOR_PROTOCOL_ADDRESS, BOR_LOG_TRANSFER, BOR_LOG_FEE_TRANSFER,
} from '../prefund-model.js';
import v1Fixture from './fixtures/prefund-attempt-v1.json' with { type: 'json' };
import { DEFAULT_METADATA, walletConnectMetadata, walletConnectOptions } from '../wallet.js';
import { K1, anchorText, softwareKey } from './support/key-fixtures.mjs';
import entryRuntime from 'fixtures/entrypoint-runtime.json' with { type: 'json' };

const U = ethers.utils;
const SIGNER = '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed';
const k1 = softwareKey(K1);
const code = (fn) => { try { fn(); } catch (error) { assert.ok(error instanceof PrefundError, String(error)); return error.code; } return null; };

/** A new-flow v2 record (no outer cap); `v1record` adds the frozen v1 caps for legacy cases. */
function record(fields = {}) {
  const required = 1060000n * 1000000000n, observed = 60000000000000n;
  return { version: 2, attemptId: '0b8e4a52-8f0a-4d7c-9a51-0f3f2a1b6c7d', status: 'reserved', chainId: '137',
    entryPoint: ENTRYPOINT, signer: SIGNER, authorizerKeyId: k1.keyId, authorizerPublicKey: k1.publicKey,
    inspectionBlockNumber: '100', inspectionBlockHash: '0x' + 'aa'.repeat(32), requiredDeposit: required.toString(),
    observedDeposit: observed.toString(), amount: (required - observed).toString(), walletAccount: '0x' + '7e'.repeat(20),
    walletPendingNonce: '3', calldataSHA256: sha256Hex(depositCall(SIGNER)), sendStartedAt: '1760000000', ...fields };
}
const CAPS = { outerGasLimit: '60000', outerMaxFeePerGas: '1000000000', outerMaxPriorityFeePerGas: '1000000000' };
function v1record(fields = {}) {
  const { calldataSHA256, sendStartedAt, ...head } = record({ version: 1 });
  return { ...head, ...CAPS, calldataSHA256, sendStartedAt, ...fields };
}
const outcomeOf = (extra = {}) => ({ kind: 'succeeded', transactionHash: '0x' + 'cd'.repeat(32), blockNumber: '101',
  blockHash: '0x' + 'bb'.repeat(32), walletNonce: '3', gasUsed: '45000', effectiveGasPrice: '1000000000',
  actualGasCost: '45000000000000', totalDeposit: '1060000000000000', ...extra });
const succeeded = (extra = {}, base = record) => base({ status: 'succeeded', transactionHash: '0x' + 'cd'.repeat(32),
  outcome: outcomeOf(extra) });

test('exact prefund arithmetic: P = 1060000 * maxFeeWei, Q = max(P - D, 0), never floating point', () => {
  assert.equal(PREFUND_GAS, 1060000n);
  assert.equal(requiredDeposit('1').required, 1060000n * 10n ** 9n);
  assert.equal(requiredDeposit('0.000000001').required, 1060000n);
  assert.equal(requiredDeposit('123.456789012').required, 1060000n * 123456789012n);
  const plan = fundingPlan('2', 5n);
  assert.deepEqual([plan.maxFee, plan.required, plan.deposit, plan.amount], [2n * 10n ** 9n, 2120000n * 10n ** 9n, 5n,
    2120000n * 10n ** 9n - 5n]);
  // amount vs deposit: exactly sufficient and over-funded deposits have no fundable amount.
  assert.equal(fundingPlan('1', 1060000n * 10n ** 9n).amount, 0n);
  assert.equal(fundingPlan('1', 10n ** 30n).amount, 0n);
  assert.equal(fundingPlan('1', 1060000n * 10n ** 9n - 1n).amount, 1n);
});

test('fee negatives: blank, format, zero, overflow beyond uint120 and non-canonical decimals refuse', () => {
  assert.equal(code(() => requiredDeposit('')), 'blank');
  for (const text of ['-1', '1e9', '01', '1.', '.5', '1.0000000001', ' 1', '1,0', '０', '0x10']) {
    assert.equal(code(() => requiredDeposit(text)), 'format', text);
  }
  assert.equal(code(() => requiredDeposit('0')), 'bounds');
  assert.equal(code(() => requiredDeposit('0.000000000')), 'bounds');
  const maxGwei = UINT120_MAX / 10n ** 9n;
  assert.equal(requiredDeposit(maxGwei.toString()).required, PREFUND_GAS * maxGwei * 10n ** 9n);
  assert.equal(code(() => requiredDeposit((maxGwei + 1n).toString())), 'overflow');
  assert.equal(code(() => requiredDeposit('9'.repeat(41))), 'overflow');
  assert.equal(code(() => fundingPlan('1', -1n)), 'input');
  assert.equal(code(() => fundingPlan('1', 1)), 'input');
});

test('legacy v1 outer caps and combined maximum wallet debit stay exact and bounded (frozen v1 compatibility only)', () => {
  const o = outerFunding('21000', '30', '2.5');
  assert.deepEqual([o.gas, o.maxFee, o.priorityFee], [21000n, 30n * 10n ** 9n, 2500000000n]);
  const d = maximumDebit(7n, o, 7n + 21000n * 30n * 10n ** 9n);
  assert.deepEqual([d.gasMaximum, d.total, d.short], [21000n * 30n * 10n ** 9n, 7n + 21000n * 30n * 10n ** 9n, false]);
  assert.equal(maximumDebit(7n, o, d.total - 1n).short, true);
  assert.equal(code(() => outerFunding('', '1', '1')), 'blank');
  assert.equal(code(() => outerFunding('20999', '1', '1')), 'gas-bounds');
  for (const gas of ['21000.0', '021000', '2.1e4', '-21000']) assert.equal(code(() => outerFunding(gas, '1', '1')), 'gas-format');
  assert.equal(code(() => outerFunding('18446744073709551616', '1', '1')), 'overflow');
  assert.equal(code(() => outerFunding('21000', '1', '2')), 'fee-bounds');
  assert.equal(code(() => outerFunding('21000', '0', '0')), 'fee-bounds');
  assert.equal(code(() => outerFunding('21000', '1.0000000001', '1')), 'fee-format');
  assert.equal(code(() => outerFunding('21000', String(1n << 100n), '1')), 'overflow');
});

test('depositTo ABI, Deposited event signature and pinned runtime identity match independent encodings', () => {
  const iface = new U.Interface(['function depositTo(address)', 'event Deposited(address indexed account, uint256 totalDeposit)']);
  assert.equal(DEPOSIT_TO_SELECTOR, '0xb760faf9');
  assert.equal(depositCall(SIGNER), iface.encodeFunctionData('depositTo', [SIGNER]));
  assert.equal(DEPOSITED_EVENT, iface.getEventTopic('Deposited'));
  assert.equal(ENTRYPOINT_RUNTIME_HASH, U.keccak256(entryRuntime.runtime));
  assert.equal(ENTRYPOINT_RUNTIME_HASH, entryRuntime.runtimeKeccak256);
  assert.equal(code(() => depositCall('0x' + '00'.repeat(20))), 'input');
  assert.equal(code(() => depositCall(SIGNER.toUpperCase().replace('0X', '0x'))), 'input');
});

test('matching deposit: exactly one EntryPoint Deposited log; totalDeposit is cumulative, never the amount', () => {
  const r = record();
  const rc = (logs) => ({ transactionHash: '0x' + 'cd'.repeat(32), blockHash: '0x' + 'bb'.repeat(32), blockNumber: 101n,
    logs: logs.map((l) => ({ removed: false, transactionHash: '0x' + 'cd'.repeat(32), blockHash: '0x' + 'bb'.repeat(32),
      blockNumber: 101n, ...l })) });
  const log = (total, fields = {}) => ({ address: ENTRYPOINT, topics: [DEPOSITED_EVENT, addressTopic(SIGNER)],
    data: '0x' + BigInt(total).toString(16).padStart(64, '0'), ...fields });
  const amount = BigInt(r.amount);
  // Another deposit preceded this one: the cumulative total exceeds D + Q and is still a valid exact event.
  const preceded = matchingDeposit(rc([log(amount + 10n ** 18n)]), r);
  assert.deepEqual(preceded, { ok: true, totalDeposit: amount + 10n ** 18n });
  assert.deepEqual(matchingDeposit(rc([log(amount)]), r), { ok: true, totalDeposit: amount });
  assert.equal(matchingDeposit(rc([log(amount - 1n)]), r).reason, 'foreign');
  assert.equal(matchingDeposit(rc([]), r).reason, 'absent');
  assert.equal(matchingDeposit(rc([log(amount), log(amount)]), r).reason, 'duplicate');
  assert.equal(matchingDeposit(rc([log(amount, { address: '0x' + '11'.repeat(20) })]), r).reason, 'absent');
  assert.equal(matchingDeposit(rc([log(amount, { topics: [DEPOSITED_EVENT, addressTopic('0x' + '22'.repeat(20))] })]), r).reason, 'foreign');
  assert.equal(matchingDeposit(rc([log(amount), { address: '0x' + '11'.repeat(20), topics: [], data: '0x' }]), r).reason, 'foreign');
  assert.equal(matchingDeposit(rc([log(amount, { topics: [DEPOSITED_EVENT, addressTopic(SIGNER), '0x' + '00'.repeat(32)] })]), r).reason, 'foreign');
  assert.equal(matchingDeposit(rc([log(amount, { data: '0x' + '00'.repeat(64) })]), r).reason, 'foreign');
  assert.equal(matchingDeposit(rc([log(amount, { removed: true })]), r).reason, 'foreign');
  assert.equal(matchingDeposit(rc([log(amount, { transactionHash: '0x' + 'ef'.repeat(32) })]), r).reason, 'foreign');
  assert.equal(matchingDeposit(rc([log(amount, { blockNumber: 102n })]), r).reason, 'foreign');
});

test('Bor protocol ABI: reject partial, malformed or foreign logs without promoting them to deposit evidence', () => {
  // Bor addTransferLog: topic0 + token/from/to address words, then five uint256 words.
  // https://github.com/0xPolygon/bor/blob/60f790c01faa98d9a605d5d8d0a13be4755ea27d/core/bor_fee_log.go
  const receipt = { transactionHash: '0x' + 'cd'.repeat(32), blockHash: '0x' + 'bb'.repeat(32), blockNumber: 101n };
  const r = record();
  const deposited = { ...receipt, removed: false, address: ENTRYPOINT, topics: [DEPOSITED_EVENT, addressTopic(SIGNER)],
    data: U.defaultAbiCoder.encode(['uint256'], [r.amount]) };
  for (const [name, topic] of [['LogTransfer', BOR_LOG_TRANSFER], ['LogFeeTransfer', BOR_LOG_FEE_TRANSFER]]) {
    const iface = new U.Interface([`event ${name}(address indexed token,address indexed from,address indexed to,uint256 amount,uint256 input1,uint256 input2,uint256 output1,uint256 output2)`]);
    const encoded = iface.encodeEventLog(iface.getEvent(name), [BOR_PROTOCOL_ADDRESS, r.walletAccount, ENTRYPOINT, 1, 2, 3, 4, 5]);
    const good = { ...receipt, removed: false, address: BOR_PROTOCOL_ADDRESS, ...encoded };
    assert.equal(encoded.topics[0], topic);
    assert.equal(isBorProtocolLog(good, receipt), true);
    assert.deepEqual(matchingDeposit({ ...receipt, logs: [good, deposited] }, r), { ok: true, totalDeposit: BigInt(r.amount) });
    assert.deepEqual(matchingDeposit({ ...receipt, logs: [good] }, r), { ok: false, reason: 'absent' });
    const bad = {
      partial: { topics: [topic], data: '0x' }, missingAddress: { topics: good.topics.slice(0, 3) },
      extraTopic: { topics: [...good.topics, addressTopic(SIGNER)] },
      token: { topics: [topic, addressTopic(SIGNER), ...good.topics.slice(2)] },
      padding: { topics: [topic, good.topics[1], '0x01' + good.topics[2].slice(4), good.topics[3]] },
      shortAddress: { topics: [topic, good.topics[1], r.walletAccount, good.topics[3]] },
      nullAddress: { topics: [topic, good.topics[1], null, good.topics[3]] },
      shortData: { data: good.data.slice(0, -64) }, extraData: { data: good.data + '00'.repeat(32) },
      noData: { data: undefined }, nonhex: { data: '0x' + 'g'.repeat(320) },
      removed: { removed: true }, transaction: { transactionHash: '0x' + 'aa'.repeat(32) },
      block: { blockHash: '0x' + 'aa'.repeat(32) }, number: { blockNumber: 102n },
    };
    for (const [variant, fields] of Object.entries(bad)) {
      const log = { ...good, ...fields };
      assert.equal(isBorProtocolLog(log, receipt), false, `${name}/${variant}`);
      assert.deepEqual(matchingDeposit({ ...receipt, logs: [deposited, log] }, r), { ok: false, reason: 'foreign' }, `${name}/${variant}`);
    }
    assert.equal(isBorProtocolLog(good, receipt, [BOR_LOG_FEE_TRANSFER]), topic === BOR_LOG_FEE_TRANSFER);
  }
});

test('closed attempt schema: canonical v2 round trip; extra, missing, reordered, duplicate and bad relationships refuse', () => {
  for (const r of [record(), record({ status: 'unknown' }), record({ status: 'hashKnown', transactionHash: '0x' + 'cd'.repeat(32) }),
    record({ status: 'confirming', transactionHash: '0x' + 'cd'.repeat(32) }),
    record({ status: 'uncertain', transactionHash: '0x' + 'cd'.repeat(32) }),
    succeeded(), record({ status: 'outerFailed', transactionHash: '0x' + 'cd'.repeat(32), outcome: { kind: 'outerFailed',
      transactionHash: '0x' + 'cd'.repeat(32), blockNumber: '101', blockHash: '0x' + 'bb'.repeat(32), walletNonce: '3',
      gasUsed: '22000', effectiveGasPrice: '1000000000', actualGasCost: '22000000000000' } })]) {
    const raw = serializeFundingAttempt(r);
    assert.deepEqual(JSON.parse(raw), r);
    assert.deepEqual(Object.keys(JSON.parse(raw)), [...V2_REQUIRED_FIELDS, ...Object.keys(r).filter((k) => !V2_REQUIRED_FIELDS.includes(k))]);
    assert.equal(serializeFundingAttempt(parseFundingAttempt(raw)), raw);
    assert.ok(Object.isFrozen(parseFundingAttempt(raw)));
    if (r.outcome) assert.ok(Object.isFrozen(parseFundingAttempt(raw).outcome));
  }
  assert.equal(parseFundingAttempt(null), null);
  const raw = serializeFundingAttempt(record());
  const bad = {
    extra: () => serializeFundingAttempt({ ...record(), note: 'x' }),
    missing: () => { const r = record(); delete r.walletPendingNonce; serializeFundingAttempt(r); },
    reordered: () => parseFundingAttempt(JSON.stringify(Object.fromEntries(Object.entries(record()).reverse()))),
    duplicate: () => parseFundingAttempt(raw.replace('"status":"reserved"', '"status":"succeeded","status":"reserved"')),
    whitespace: () => parseFundingAttempt(raw.replace(',', ', ')),
    amount: () => serializeFundingAttempt(record({ amount: '1' })),
    zeroAmount: () => serializeFundingAttempt(record({ observedDeposit: '1060000000000000', amount: '0' })),
    notMultiple: () => serializeFundingAttempt(record({ requiredDeposit: '1060000000000001', amount: '1000000000000001' })),
    calldata: () => serializeFundingAttempt(record({ calldataSHA256: '0x' + '00'.repeat(32) })),
    keyId: () => serializeFundingAttempt(record({ authorizerKeyId: 'a'.repeat(64) })),
    point: () => serializeFundingAttempt(record({ authorizerPublicKey: '0x04' + '11'.repeat(64) })),
    // Only the four closed chains, as canonical decimal text (enable-multichain-operations; chain 1 is now closed).
    chain: () => serializeFundingAttempt(record({ chainId: '10' })),
    chainNumber: () => serializeFundingAttempt(record({ chainId: 137 })),
    chainPadded: () => serializeFundingAttempt(record({ chainId: '0137' })),
    chainHex: () => serializeFundingAttempt(record({ chainId: '0x89' })),
    entry: () => serializeFundingAttempt(record({ entryPoint: '0x' + '11'.repeat(20) })),
    decimal: () => serializeFundingAttempt(record({ walletPendingNonce: '03' })),
    nonceBound: () => serializeFundingAttempt(record({ walletPendingNonce: (UINT64_MAX + 1n).toString() })),
    uppercase: () => serializeFundingAttempt(record({ walletAccount: '0x' + '7E'.repeat(20) })),
    reservedHash: () => serializeFundingAttempt(record({ transactionHash: '0x' + 'cd'.repeat(32) })),
    hashlessKnown: () => serializeFundingAttempt(record({ status: 'hashKnown' })),
    status: () => serializeFundingAttempt(record({ status: 'stateResolved' })),
    secret: () => serializeFundingAttempt({ ...record(), signature: '0x' + '11'.repeat(65) }),
    outcomeKind: () => serializeFundingAttempt(succeeded({ kind: 'outerFailed' })),
    outcomeCost: () => serializeFundingAttempt(succeeded({ actualGasCost: '1' })),
    outcomeTotal: () => serializeFundingAttempt(succeeded({ totalDeposit: '1' })),
    outcomeHash: () => serializeFundingAttempt(succeeded({ transactionHash: '0x' + 'ee'.repeat(32) })),
    outcomeExtra: () => serializeFundingAttempt(succeeded({ amount: '1' })),
    outcomeGasBound: () => serializeFundingAttempt(succeeded({ gasUsed: (UINT64_MAX + 1n).toString(), actualGasCost: '0' })),
    outcomeNonceBound: () => serializeFundingAttempt(succeeded({ walletNonce: (UINT64_MAX + 1n).toString() })),
    failedTotal: () => serializeFundingAttempt(record({ status: 'outerFailed', transactionHash: '0x' + 'cd'.repeat(32),
      outcome: succeeded().outcome })),
    terminalNoOutcome: () => serializeFundingAttempt(record({ status: 'succeeded', transactionHash: '0x' + 'cd'.repeat(32) })),
    large: () => parseFundingAttempt(' '.repeat(MAX_ATTEMPT_BYTES + 1)),
  };
  for (const [name, fn] of Object.entries(bad)) assert.equal(code(fn), 'corrupt', name);
  // A record of another closed chain is a valid record of that chain only; it round-trips unchanged.
  for (const chainId of ['1', '8453', '84532']) {
    const other = serializeFundingAttempt(record({ chainId }));
    assert.equal(parseFundingAttempt(other).chainId, chainId);
    assert.equal(serializeFundingAttempt(parseFundingAttempt(other)), other);
  }
});

test('literal v1 bytes: every status and terminal outcome is byte-identical and v1-era invalid bytes still fail', () => {
  assert.deepEqual(Object.keys(v1Fixture.valid), ['reserved', 'unknown', 'hashKnown', 'confirming', 'uncertain', 'succeeded',
    'outerFailed']);
  assert.equal(REQUIRED_FIELDS, V1_REQUIRED_FIELDS);
  for (const [status, raw] of Object.entries(v1Fixture.valid)) {
    const parsed = parseFundingAttempt(raw);
    assert.equal(parsed.version, 1, status);
    assert.equal(parsed.status, status);
    // Raw literal bytes, not this serializer compared with itself.
    assert.equal(serializeFundingAttempt(parsed), raw, status);
    assert.deepEqual(Object.keys(JSON.parse(raw)).slice(0, V1_REQUIRED_FIELDS.length), V1_REQUIRED_FIELDS, status);
    assert.ok(Object.isFrozen(parsed), status);
  }
  const s = parseFundingAttempt(v1Fixture.valid.succeeded);
  assert.deepEqual([s.outerGasLimit, s.outerMaxFeePerGas, s.outerMaxPriorityFeePerGas, s.outcome.walletNonce],
    ['60000', '1000000000', '1000000000', s.walletPendingNonce]);
  assert.deepEqual(Object.keys(s.outcome), OUTCOME_FIELDS);
  assert.ok(Object.keys(v1Fixture.invalid).length >= 15);
  for (const [name, raw] of Object.entries(v1Fixture.invalid)) assert.equal(code(() => parseFundingAttempt(raw)), 'corrupt', name);
  // The serializer keeps every v1 refusal: saved caps, saved-nonce outcome equality and cap-bounded actual costs.
  const v1bad = {
    gas: () => serializeFundingAttempt(v1record({ outerGasLimit: '20999' })),
    tip: () => serializeFundingAttempt(v1record({ outerMaxPriorityFeePerGas: '1000000001' })),
    zeroMax: () => serializeFundingAttempt(v1record({ outerMaxFeePerGas: '0', outerMaxPriorityFeePerGas: '0' })),
    gasBound: () => serializeFundingAttempt(v1record({ outerGasLimit: (UINT64_MAX + 1n).toString() })),
    outcomeGas: () => serializeFundingAttempt(succeeded({ gasUsed: '60001', actualGasCost: '60001000000000' }, v1record)),
    outcomePrice: () => serializeFundingAttempt(succeeded({ effectiveGasPrice: '1000000001', actualGasCost: '45000000045000' }, v1record)),
    outcomeNonce: () => serializeFundingAttempt(succeeded({ walletNonce: '4' }, v1record)),
  };
  for (const [name, fn] of Object.entries(v1bad)) assert.equal(code(fn), 'corrupt', name);
  assert.equal(code(() => serializeFundingAttempt(succeeded({}, v1record))), null);
});

test('version dispatch: exact v2 fields; any cap on v2, cap-less or partial v1, unknown or coerced versions fail closed', () => {
  assert.deepEqual(V2_REQUIRED_FIELDS, ['version', 'attemptId', 'status', 'chainId', 'entryPoint', 'signer',
    'authorizerKeyId', 'authorizerPublicKey', 'inspectionBlockNumber', 'inspectionBlockHash', 'requiredDeposit',
    'observedDeposit', 'amount', 'walletAccount', 'walletPendingNonce', 'calldataSHA256', 'sendStartedAt']);
  assert.deepEqual(V1_REQUIRED_FIELDS.filter((k) => !V2_REQUIRED_FIELDS.includes(k)), Object.keys(CAPS));
  const v2 = serializeFundingAttempt(record());
  assert.equal(code(() => parseFundingAttempt(serializeFundingAttempt(v1record()))), null);
  const mixtures = {
    v2AllCaps: () => serializeFundingAttempt({ ...record(), ...CAPS }),
    v2OneCap: () => serializeFundingAttempt({ ...record(), outerGasLimit: '60000' }),
    v2CapBytes: () => parseFundingAttempt(v2.replace('"walletPendingNonce":"3",', '"walletPendingNonce":"3","outerGasLimit":"60000",')),
    v1Capless: () => serializeFundingAttempt(record({ version: 1 })),
    v1Partial: () => { const r = v1record(); delete r.outerMaxFeePerGas; serializeFundingAttempt(r); },
    string: () => parseFundingAttempt(v2.replace('{"version":2,', '{"version":"2",')),
    null: () => parseFundingAttempt(v2.replace('{"version":2,', '{"version":null,')),
    boolean: () => parseFundingAttempt(v2.replace('{"version":2,', '{"version":true,')),
    three: () => parseFundingAttempt(v2.replace('{"version":2,', '{"version":3,')),
    zero: () => serializeFundingAttempt(record({ version: 0 })),
    float: () => parseFundingAttempt(v2.replace('{"version":2,', '{"version":2.0,')),
    missingVersion: () => { const r = record(); delete r.version; serializeFundingAttempt(r); },
    array: () => parseFundingAttempt('[2]'),
    reordered: () => parseFundingAttempt(v2.replace('"chainId":"137","entryPoint"', '"entryPoint"').replace(
      `"signer":"${SIGNER}"`, `"chainId":"137","signer":"${SIGNER}"`)),
    duplicateVersion: () => parseFundingAttempt(v2.replace('{"version":2,', '{"version":1,"version":2,')),
  };
  for (const [name, fn] of Object.entries(mixtures)) assert.equal(code(fn), 'corrupt', name);
});

test('v2 outcome: actual wallet nonce is independent of the pending hint; costs are a bounded product with no cap', () => {
  // A wallet-chosen nonce and fees above the old fixture caps are a valid v2 outcome; the hint stays unchanged.
  const high = succeeded({ walletNonce: '9', gasUsed: '100000', effectiveGasPrice: '2000000000',
    actualGasCost: '200000000000000' });
  const parsed = parseFundingAttempt(serializeFundingAttempt(high));
  assert.deepEqual([parsed.walletPendingNonce, parsed.outcome.walletNonce], ['3', '9']);
  assert.equal(code(() => serializeFundingAttempt(succeeded({ walletNonce: '9' }, v1record))), 'corrupt');
  // uint64 gasUsed times a uint256 price must still fit uint256 and equal the saved cost exactly.
  const price = UINT256_MAX / UINT64_MAX;
  assert.equal(code(() => serializeFundingAttempt(succeeded({ gasUsed: UINT64_MAX.toString(), effectiveGasPrice: price.toString(),
    actualGasCost: (UINT64_MAX * price).toString() }))), null);
  assert.equal(code(() => serializeFundingAttempt(succeeded({ gasUsed: UINT64_MAX.toString(),
    effectiveGasPrice: (price + 1n).toString(), actualGasCost: UINT256_MAX.toString() }))), 'corrupt');
  assert.equal(code(() => serializeFundingAttempt(succeeded({ actualGasCost: '45000000000001' }))), 'corrupt');
  assert.equal(code(() => serializeFundingAttempt(succeeded({ totalDeposit: '999999999999999' }))), 'corrupt');
  const failed = record({ status: 'outerFailed', transactionHash: '0x' + 'cd'.repeat(32), outcome: { ...outcomeOf({
    kind: 'outerFailed', walletNonce: '0' }) } });
  delete failed.outcome.totalDeposit;
  assert.equal(code(() => serializeFundingAttempt(failed)), null);
  assert.equal(code(() => serializeFundingAttempt({ ...failed, outcome: { ...failed.outcome, totalDeposit: '1' } })), 'corrupt');
});

test('authority admission reuses the closed native parser: malformed, duplicate member or point and wrong ID refuse', () => {
  const good = anchorText(SIGNER, k1);
  assert.equal(parseAuthority(good).signerAddress, SIGNER);
  const fails = (text) => { try { parseAuthority(text); return null; } catch (error) { return error.code; } };
  assert.equal(fails(good.replace('"publicKey"', '"publicKey":"' + k1.publicKey + '","publicKey"')), 'duplicate');
  assert.equal(fails(good.replace(k1.publicKey.slice(4, 8), '0000')), 'point');
  assert.equal(fails(good.replace(k1.keyId, 'b'.repeat(64))), 'keyId');
  // enable-multichain-operations: an unclosed, padded or hex chain refuses; a closed non-Polygon chain is admitted
  // as that chain only.
  assert.equal(fails(good.replace('"137"', '"10"')), 'chain');
  assert.equal(fails(good.replace('"137"', '"0137"')), 'chain');
  assert.equal(fails(good.replace('"137"', '"0x89"')), 'chain');
  assert.equal(parseAuthority(good.replace('"137"', '"8453"')).chainId, '8453');
  assert.equal(parseAuthority(good).chainId, undefined, 'the Polygon anchor keeps the legacy shape');
  assert.equal(fails(good.slice(0, -1)), 'json');
  assert.equal(fails(SIGNER), 'json');
});

test('bounded WalletConnect metadata override: truthful funding text accepted, malformed input refused, default unchanged', () => {
  const ORIGIN = 'https://tumf.github.io';
  assert.deepEqual(walletConnectMetadata(undefined), DEFAULT_METADATA);
  assert.deepEqual(walletConnectOptions('ab'.repeat(16), ORIGIN).metadata, { name: 'P-256 Signer 配備Web',
    description: '選んだSignerをPolygonへ配備します', url: ORIGIN, icons: [] });
  const ok = { name: 'P-256 Signer 前払い残高', description: 'PolygonのSigner前払い残高へ入金します', url: ORIGIN, icons: [] };
  assert.deepEqual(walletConnectOptions('ab'.repeat(16), ORIGIN, walletConnectMetadata(ok)).metadata, ok);
  for (const value of [null, [], 'x', { ...ok, name: '' }, { ...ok, name: ' ' }, { ...ok, name: 'n'.repeat(81) },
    { ...ok, description: 'd'.repeat(161) }, { ...ok, url: ORIGIN + '/' }, { ...ok, url: 'https://evil.example' },
    { ...ok, icons: ['https://evil.example/i.png'] }, { ...ok, extra: 1 }, { name: ok.name, url: ORIGIN, icons: [] },
    { ...ok, name: 'a\nb' }]) {
    assert.throws(() => walletConnectMetadata(value), (e) => e.code === 'metadata', JSON.stringify(value));
  }
});
