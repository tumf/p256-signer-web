// EntryPoint prefund model: the exact key-operation prefund P = 1060000 * maxFeeWei, the current Signer deposit D and
// the shortage Q = max(P - D, 0); the pinned EntryPoint v0.7 `depositTo(address)` call and `Deposited(address indexed
// account, uint256 totalDeposit)` event (account-abstraction 7af70c8, StakeManager.sol: totalDeposit is the CUMULATIVE
// balance, never the deposited amount); the frozen v1 outer wallet caps (legacy records only); and the closed public
// funding-attempt schema, versions 1 and 2, with its only serializer. New funding is v2: the selected wallet owns outer
// execution fees, so v2 carries no outer cap. Exact BigInt arithmetic, no floating point and no I/O.
import ethers from './vendor/ethers.js';
import {
  CHAIN_ID, ENTRYPOINT, TOTAL_GAS, UINT120_MAX, UINT128_MAX, UINT256_MAX, UINT64_MAX, ZERO_ADDRESS, isDecimal, isHash,
  isKeyId, isLowerAddress, isPoint, isUUID, keyIdOf, parseGwei, sha256Hex,
} from './key-model.js';

const U = ethers.utils;

export { ENTRYPOINT, CHAIN_ID };
import { chainOf } from './chains.js';
/** keccak256 of the pinned frozen EntryPoint v0.7 runtime (Tests/Fixtures/EntryPoint/manifest.json). */
export const ENTRYPOINT_RUNTIME_HASH = '0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58';
/** The fixed key-operation gas units the key-change page prefunds (verification + call + preVerification). */
export const PREFUND_GAS = TOTAL_GAS;
export const DEPOSIT_TO_SELECTOR = U.id('depositTo(address)').slice(0, 10);
export const DEPOSITED_EVENT = U.id('Deposited(address,uint256)');
export const OUTER_GAS_MINIMUM = 21000n;
export const MAX_ATTEMPT_BYTES = 16384;
export const STATUSES = Object.freeze(['reserved', 'hashKnown', 'unknown', 'confirming', 'succeeded', 'outerFailed',
  'uncertain']);
export const OUTCOME_KINDS = Object.freeze(['succeeded', 'outerFailed']);
/** Frozen v1 ordered required fields (base 9c39bc3); historical records only. */
export const V1_REQUIRED_FIELDS = Object.freeze(['version', 'attemptId', 'status', 'chainId', 'entryPoint', 'signer',
  'authorizerKeyId', 'authorizerPublicKey', 'inspectionBlockNumber', 'inspectionBlockHash', 'requiredDeposit',
  'observedDeposit', 'amount', 'walletAccount', 'walletPendingNonce', 'outerGasLimit', 'outerMaxFeePerGas',
  'outerMaxPriorityFeePerGas', 'calldataSHA256', 'sendStartedAt']);
/** The existing export keeps its v1 meaning. */
export const REQUIRED_FIELDS = V1_REQUIRED_FIELDS;
/** v2: exactly v1 minus its three outer caps. walletPendingNonce is a lookup hint, never a wallet instruction. */
export const V2_REQUIRED_FIELDS = Object.freeze(V1_REQUIRED_FIELDS.filter((key) => !['outerGasLimit',
  'outerMaxFeePerGas', 'outerMaxPriorityFeePerGas'].includes(key)));
const requiredFields = (version) => (version === 2 ? V2_REQUIRED_FIELDS : V1_REQUIRED_FIELDS);
export const OPTIONAL_FIELDS = Object.freeze(['transactionHash', 'outcome']);
export const OUTCOME_FIELDS = Object.freeze(['kind', 'transactionHash', 'blockNumber', 'blockHash', 'walletNonce',
  'gasUsed', 'effectiveGasPrice', 'actualGasCost', 'totalDeposit']);

/** A bounded failure with a fixed code; the message never echoes input. */
export class PrefundError extends Error {
  constructor(code) {
    super(`prefund ${code}`);
    this.name = 'PrefundError';
    this.code = code;
  }
}
const fail = (code) => { throw new PrefundError(code); };
const addressWord = (address) => '0x' + '00'.repeat(12) + address.slice(2).toLowerCase();
export const addressTopic = addressWord;

// ---------------------------------------------------------------------------------------------------------------
// Exact arithmetic

function checkedAdd(a, b) { const s = a + b; if (s > UINT256_MAX) fail('overflow'); return s; }
function checkedMul(a, b) { const p = a * b; if (p > UINT256_MAX) fail('overflow'); return p; }

/**
 * The bounded intended key-operation prefund for an explicit max fee (Gwei text, the key-change page's exact decimal
 * parser and its uint120 admission). Codes: blank | format | bounds | overflow. Not a guaranteed future fee.
 */
export function requiredDeposit(maxFeeText) {
  if (typeof maxFeeText !== 'string' || maxFeeText === '') fail('blank');
  let maxFee;
  try { maxFee = parseGwei(maxFeeText); } catch (error) { fail(error.code === 'blank' ? 'blank' : 'format'); }
  if (maxFee <= 0n) fail('bounds');
  if (maxFee > UINT120_MAX) fail('overflow');
  return Object.freeze({ maxFee, required: checkedMul(PREFUND_GAS, maxFee) });
}

/** P, D and Q = max(P - D, 0) at one inspection; Q > 0 is the only fundable amount. */
export function fundingPlan(maxFeeText, deposit) {
  if (typeof deposit !== 'bigint' || deposit < 0n || deposit > UINT256_MAX) fail('input');
  const { maxFee, required } = requiredDeposit(maxFeeText);
  return Object.freeze({ maxFee, required, deposit, amount: deposit >= required ? 0n : required - deposit });
}

/**
 * Legacy v1 explicit outer wallet caps (frozen v1 compatibility tests only; the v2 flow never calls this): canonical positive integer gas 21000..uint64, max fee and priority in Gwei with the
 * existing canonical limits (uint128, priority <= max). Codes: blank | gas-format | gas-bounds | fee-format |
 * fee-bounds | overflow.
 */
export function outerFunding(gasText, maxText, priorityText) {
  if (gasText === '' || maxText === '' || priorityText === '') fail('blank');
  if (typeof gasText !== 'string' || !/^[1-9][0-9]{0,77}$/.test(gasText)) fail('gas-format');
  const gas = BigInt(gasText);
  if (gas > UINT64_MAX) fail('overflow');
  if (gas < OUTER_GAS_MINIMUM) fail('gas-bounds');
  let maxFee, priorityFee;
  try { maxFee = parseGwei(maxText); priorityFee = parseGwei(priorityText); } catch { fail('fee-format'); }
  if (maxFee > UINT128_MAX || priorityFee > UINT128_MAX) fail('overflow');
  if (maxFee <= 0n || priorityFee > maxFee) fail('fee-bounds');
  return Object.freeze({ gas, maxFee, priorityFee });
}

/** Legacy v1 combined maximum wallet debit Q + gas * maxFee (frozen v1 compatibility tests only). */
export function maximumDebit(amount, outer, balance = null) {
  const gasMaximum = checkedMul(outer.gas, outer.maxFee);
  const total = checkedAdd(amount, gasMaximum);
  return Object.freeze({ gasMaximum, total, balance, short: balance !== null && balance < total });
}

// ---------------------------------------------------------------------------------------------------------------
// The exact call and event

/** `depositTo(signer)` calldata: selector and one zero-padded address word. Value carries the amount. */
export function depositCall(signer) {
  if (!isLowerAddress(signer) || signer === ZERO_ADDRESS) fail('input');
  return DEPOSIT_TO_SELECTOR + addressWord(signer).slice(2);
}

// Polygon PoS (Bor) appends protocol logs from the native-token system contract to ordinary receipts: LogTransfer for
// each nonzero native value transfer and LogFeeTransfer after execution, including reverted transactions.
export const BOR_PROTOCOL_ADDRESS = '0x0000000000000000000000000000000000001010';
export const BOR_LOG_TRANSFER = '0xe6497e3ee548a3372136af2fcb0696db31fc6cf20260707645068bd3fe97f3c4';
export const BOR_LOG_FEE_TRANSFER = '0x4dfe1bbbcf077ddc3e01291eea2d5c70c2b422b415d95645b9adcfd678cb1d63';

/**
 * Whether a receipt log is a tolerated Bor protocol log: the system address, one of `topic0s`, removed=false and
 * belonging to this receipt. Such logs are never deposit or amount evidence; they are only not refused as foreign.
 */
export function isBorProtocolLog(log, receipt, topic0s = [BOR_LOG_TRANSFER, BOR_LOG_FEE_TRANSFER]) {
  // Bor core/bor_fee_log.go (60f790c01faa98d9a605d5d8d0a13be4755ea27d): four topics and five uint256 words.
  return Boolean(log) && log.address === BOR_PROTOCOL_ADDRESS && Array.isArray(log.topics)
    && log.topics.length === 4 && topic0s.includes(log.topics[0])
    && log.topics[1] === addressTopic(BOR_PROTOCOL_ADDRESS)
    && log.topics.slice(2).every((t) => typeof t === 'string' && /^0x0{24}[0-9a-f]{40}$/.test(t))
    && typeof log.data === 'string' && /^0x[0-9a-f]{320}$/.test(log.data)
    && log.removed === false && log.transactionHash === receipt.transactionHash
    && log.blockHash === receipt.blockHash && log.blockNumber === receipt.blockNumber;
}

/**
 * The one EntryPoint Deposited event of a receipt for this record, or a typed refusal. Apart from tolerated Bor
 * protocol logs the receipt must carry exactly one log, from the pinned EntryPoint, with two topics (exact signature,
 * zero-padded signer), one uint256 word and removed=false, belonging to this receipt; totalDeposit is cumulative and
 * must be at least the funded amount. Returns `{ok:true, totalDeposit}` or `{ok:false, reason: absent | duplicate |
 * foreign}`.
 */
export function matchingDeposit(receipt, record) {
  const all = Array.isArray(receipt?.logs) ? receipt.logs : null;
  const logs = all ? all.filter((log) => !isBorProtocolLog(log, receipt)) : null;
  if (!logs || logs.length === 0) return { ok: false, reason: 'absent' };
  const deposits = logs.filter((log) => log && log.address === ENTRYPOINT && log.topics?.[0] === DEPOSITED_EVENT);
  if (deposits.filter((log) => log.topics[1] === addressTopic(record.signer)).length > 1) {
    return { ok: false, reason: 'duplicate' };
  }
  if (logs.length !== 1 || deposits.length !== 1) return { ok: false, reason: deposits.length ? 'foreign' : 'absent' };
  const log = deposits[0];
  if (log.removed !== false || log.transactionHash !== receipt.transactionHash || log.blockHash !== receipt.blockHash
      || log.blockNumber !== receipt.blockNumber || log.topics.length !== 2
      || log.topics[1] !== addressTopic(record.signer) || typeof log.data !== 'string'
      || !/^0x[0-9a-f]{64}$/.test(log.data)) return { ok: false, reason: 'foreign' };
  const totalDeposit = BigInt(log.data);
  if (totalDeposit < BigInt(record.amount)) return { ok: false, reason: 'foreign' };
  return { ok: true, totalDeposit };
}

// ---------------------------------------------------------------------------------------------------------------
// Closed funding attempt v1/v2 (public lookup identity only: no signature, session, grant, QR or secret). The numeric
// `version` alone selects the field list; nothing is inferred from the members, coerced, migrated or repaired.

const invalid = () => fail('corrupt');
const utf8Length = (text) => new TextEncoder().encode(text).length;
const uint = (text, max = UINT256_MAX) => (isDecimal(text) && BigInt(text) <= max ? BigInt(text) : invalid());

function closed(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  for (const key of Object.keys(value)) if (!required.includes(key) && !optional.includes(key)) invalid();
  for (const key of required) if (!Object.prototype.hasOwnProperty.call(value, key)) invalid();
}

/**
 * The only serializer: copies the listed fields of the record's version (v2 for numeric 2, otherwise the v1 list) in
 * fixed order, never spreads untrusted input; any extra member, including a cap on v2, is carried as `__extra` so
 * validation refuses it. `trusted` skips validation (strict parse validates afterwards).
 */
export function serializeFundingAttempt(record, { trusted = false } = {}) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) invalid();
  const out = {};
  for (const key of [...requiredFields(record.version), ...OPTIONAL_FIELDS]) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) continue;
    const value = record[key];
    if (key === 'outcome') {
      if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
      out.outcome = Object.fromEntries(OUTCOME_FIELDS.filter((k) => Object.prototype.hasOwnProperty.call(value, k))
        .map((k) => [k, value[k]]));
      if (Object.keys(value).length !== Object.keys(out.outcome).length) out.outcome.__extra = true;
    } else out[key] = value;
  }
  if (Object.keys(record).length !== Object.keys(out).length) out.__extra = true;
  const text = JSON.stringify(out);
  if (utf8Length(text) > MAX_ATTEMPT_BYTES) invalid();
  if (!trusted) validateFundingAttempt(JSON.parse(text));
  return text;
}

/**
 * Full closed validation including the exact call hash, P/D/Q relation, outcome tuple and status relationship. v1 keeps
 * its saved caps and outcome nonce equality; v2 has no cap and its outcome nonce is the actual one, not the hint.
 */
export function validateFundingAttempt(r) {
  if (!r || typeof r !== 'object' || Array.isArray(r) || (r.version !== 1 && r.version !== 2)) invalid();
  const legacy = r.version === 1;
  closed(r, requiredFields(r.version), OPTIONAL_FIELDS);
  // Every record names exactly one closed chain; its settlement reads and checks that chain only.
  if (!isUUID(r.attemptId) || !STATUSES.includes(r.status) || !chainOf(r.chainId)
      || r.entryPoint !== ENTRYPOINT || !isLowerAddress(r.signer) || r.signer === ZERO_ADDRESS
      || !isKeyId(r.authorizerKeyId) || !isPoint(r.authorizerPublicKey)
      || keyIdOf(r.authorizerPublicKey) !== r.authorizerKeyId || !isHash(r.inspectionBlockHash)
      || !isLowerAddress(r.walletAccount) || r.walletAccount === ZERO_ADDRESS || !isHash(r.calldataSHA256)
      || r.calldataSHA256 !== sha256Hex(depositCall(r.signer))) invalid();
  uint(r.inspectionBlockNumber, UINT64_MAX);
  const required = uint(r.requiredDeposit), observed = uint(r.observedDeposit), amount = uint(r.amount);
  if (required === 0n || required % PREFUND_GAS !== 0n || required / PREFUND_GAS > UINT120_MAX
      || observed >= required || amount !== required - observed) invalid();
  const nonce = uint(r.walletPendingNonce, UINT64_MAX);
  let gas = null, maxFee = null;
  if (legacy) {
    gas = uint(r.outerGasLimit, UINT64_MAX);
    maxFee = uint(r.outerMaxFeePerGas, UINT128_MAX);
    const tip = uint(r.outerMaxPriorityFeePerGas, UINT128_MAX);
    if (gas < OUTER_GAS_MINIMUM || maxFee === 0n || tip > maxFee) invalid();
  }
  if (uint(r.sendStartedAt, BigInt(Number.MAX_SAFE_INTEGER)) === 0n) invalid();
  const hashed = Object.prototype.hasOwnProperty.call(r, 'transactionHash');
  if (hashed && !isHash(r.transactionHash)) invalid();
  if (['reserved', 'unknown'].includes(r.status) && hashed) invalid();
  if (['hashKnown', 'confirming', 'uncertain', 'succeeded', 'outerFailed'].includes(r.status) && !hashed) invalid();
  const terminal = r.status === 'succeeded' || r.status === 'outerFailed';
  if (terminal !== Object.prototype.hasOwnProperty.call(r, 'outcome')) invalid();
  if (terminal) {
    const o = r.outcome, success = r.status === 'succeeded';
    closed(o, OUTCOME_FIELDS.filter((k) => k !== 'totalDeposit' || success));
    if (o.kind !== r.status || o.transactionHash !== r.transactionHash || !isHash(o.blockHash)) invalid();
    uint(o.blockNumber, UINT64_MAX);
    const used = uint(o.gasUsed, UINT64_MAX), price = uint(o.effectiveGasPrice), cost = uint(o.actualGasCost);
    const actualNonce = uint(o.walletNonce, UINT64_MAX);
    if (cost !== used * price) invalid();
    if (legacy && (actualNonce !== nonce || used > gas || price > maxFee)) invalid();
    if (success && uint(o.totalDeposit) < amount) invalid();
  }
  return r;
}

/** The validated frozen record of canonical bytes, or a thrown `corrupt` PrefundError. Null stays null. */
export function parseFundingAttempt(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || utf8Length(raw) > MAX_ATTEMPT_BYTES) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  // Canonical bytes are exactly the serializer's output: any duplicate, reordered or extra member fails here.
  if (serializeFundingAttempt(value, { trusted: true }) !== raw) invalid();
  return deepFreeze(validateFundingAttempt(value));
}

function deepFreeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(deepFreeze); Object.freeze(value); }
  return value;
}
