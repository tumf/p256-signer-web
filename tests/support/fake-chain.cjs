'use strict';
// Deterministic read-only Polygon double for local tests. It serves the REAL pinned Factory and
// HybridDeleGator runtime bytes (so runtime-hash checks are genuine), emulates CREATE2 prediction and
// the deployed key set from decoded deploy calldata, and mines submitted transactions on demand.
// It is test fixture state, not EVM execution; the guarded Anvil fork harness covers real execution.
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const oracle = require('./oracle.cjs');

const root = path.resolve(__dirname, '../..');
const runtime = JSON.parse(fs.readFileSync(path.join(__dirname, '../fixtures/polygon-runtime.json'), 'utf8'));
const hybridRuntime = JSON.parse(fs.readFileSync(path.join(root, 'tests/fixtures/HybridCodec/hybrid-runtime.json'),
  'utf8'));
const PROXY = JSON.parse(fs.readFileSync(path.join(__dirname, '../../vendor/proxy.json'), 'utf8')).bytecode;
const FACTORY = oracle.FACTORY.toLowerCase();
const IMPLEMENTATION = oracle.IMPLEMENTATION.toLowerCase();
const SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
// Any nonempty proxy runtime; only its presence is observable through the read API.
const PROXY_RUNTIME = '0x60806040527f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc54';
const SEL = Object.fromEntries(['computeAddress(bytes32,bytes32)', 'owner()', 'getKeyIdHashesCount()',
  'getKey(string)'].map((sig) => [oracle.hex(oracle.selector(sig)), sig]));

const q = (n) => '0x' + BigInt(n).toString(16);
const word = (n) => BigInt(n).toString(16).padStart(64, '0');
const GWEI = 1_000_000_000n;

class RpcError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

class FakeChain extends EventEmitter {
  constructor(options = {}) {
    super();
    this.chainHex = options.chainHex || '0x89';
    this.baseFee = options.baseFee ?? 30n * GWEI;
    this.tip = options.tip ?? 2n * GWEI;
    this.estimate = options.estimate ?? 400_000n;
    this.faults = { ...(options.faults || {}) };
    this.blocks = [];
    this.epoch = 0;
    this.nonces = new Map();
    this.mempool = [];
    this.txs = new Map();
    this.receipts = new Map();
    this.deployments = new Map();
    this.calls = [];
    this.writes = 0;
    for (let i = 0; i < 3; i++) this.mineEmpty();
  }

  get head() { return this.blocks[this.blocks.length - 1]; }

  blockHash(number) {
    return oracle.hex(oracle.keccak256(Buffer.from(`fake-polygon:${number}:${this.epoch}`)));
  }

  mineEmpty() {
    const number = BigInt(this.blocks.length + 1000);
    this.blocks.push({ number, hash: this.blockHash(number), baseFee: this.baseFee, txs: [] });
  }

  /** Mines one block including every mempool transaction (or `only` those hashes). */
  mine({ revert = false } = {}) {
    const number = BigInt(this.blocks.length + 1000);
    const block = { number, hash: this.blockHash(number), baseFee: this.baseFee, txs: [] };
    for (const tx of this.mempool.splice(0)) {
      block.txs.push(tx);
      tx.blockNumber = number;
      tx.blockHash = block.hash;
      let status = 1n;
      if (!revert && tx.to.toLowerCase() === FACTORY && tx.input.startsWith('0x4af63f02')) {
        try {
          const d = oracle.decodeDeploy(tx.input, PROXY);
          const address = oracle.checksum(oracle.keccak256(Buffer.concat([Buffer.from([0xff]),
            oracle.bytes(FACTORY), oracle.bytes(d.salt), oracle.keccak256(oracle.bytes(d.creation))])).subarray(12));
          if (this.deployments.has(address.toLowerCase())) status = 0n;
          else this.deployments.set(address.toLowerCase(), this.faults.deployWrongKey
            ? { implementation: IMPLEMENTATION, owner: d.owner, keys: [{ id: d.keyID, x: d.x, y: '0x' + '11'.repeat(32) }],
              tx: tx.hash }
            : { implementation: d.implementation.toLowerCase(), owner: d.owner, keys: [{ id: d.keyID, x: d.x, y: d.y }],
              tx: tx.hash });
        } catch { status = 0n; }
      } else if (revert) status = 0n;
      const gasUsed = BigInt(tx.gas) * 8n / 10n;
      const price = tx.type === '0x0' ? BigInt(tx.gasPrice)
        : this.baseFee + BigInt(tx.maxPriorityFeePerGas) < BigInt(tx.maxFeePerGas)
          ? this.baseFee + BigInt(tx.maxPriorityFeePerGas) : BigInt(tx.maxFeePerGas);
      this.receipts.set(tx.hash, { transactionHash: tx.hash, blockNumber: q(number), blockHash: block.hash,
        status: q(status), gasUsed: q(gasUsed), effectiveGasPrice: q(price) });
      this.nonces.set(tx.from.toLowerCase(), BigInt(tx.nonce) + 1n);
    }
    this.blocks.push(block);
    return block;
  }

  advance(count = 1) {
    for (let i = 0; i < count; i++) this.mine();
  }

  /** Removes the last `depth` blocks and their effects; their transactions disappear from the chain. */
  reorg(depth = 1) {
    this.epoch++;
    for (const block of this.blocks.splice(this.blocks.length - depth)) {
      for (const tx of block.txs) {
        this.receipts.delete(tx.hash);
        tx.blockNumber = null;
        tx.blockHash = null;
        this.mempool.push(tx);
        const nonce = BigInt(tx.nonce);
        if ((this.nonces.get(tx.from.toLowerCase()) || 0n) > nonce) this.nonces.set(tx.from.toLowerCase(), nonce);
        for (const [address, info] of this.deployments) {
          if (info.tx === tx.hash) this.deployments.delete(address);
        }
      }
    }
    for (const block of this.blocks) block.hash = this.blockHash(block.number);
    while (this.blocks.length < 3) this.mineEmpty();
  }

  /**
   * The wallet-side submission path (only reachable from the fake wallet, never from the relay). A transaction with
   * `gasPrice` and no EIP-1559 fields is a legacy (type 0) transaction; otherwise type 2.
   */
  submit(tx) {
    this.writes++;
    const hash = oracle.hex(oracle.keccak256(Buffer.from(JSON.stringify(tx) + ':' + this.writes)));
    const legacy = tx.gasPrice !== undefined && tx.maxFeePerGas === undefined && tx.maxPriorityFeePerGas === undefined;
    const fees = legacy ? { gasPrice: tx.gasPrice, type: '0x0' }
      : { maxFeePerGas: tx.maxFeePerGas, maxPriorityFeePerGas: tx.maxPriorityFeePerGas, type: '0x2' };
    const record = { hash, from: tx.from, to: tx.to, input: tx.data, value: tx.value || '0x0', nonce: tx.nonce,
      gas: tx.gas, ...fees, chainId: this.chainHex, blockNumber: null, blockHash: null };
    this.mempool.push(record);
    this.txs.set(hash, record);
    return hash;
  }

  /** Puts a deployment directly into state (already-deployed fixtures). */
  preDeploy(plan, overrides = {}) {
    this.deployments.set(plan.address.toLowerCase(), {
      implementation: overrides.implementation || IMPLEMENTATION, owner: overrides.owner || '0x' + '00'.repeat(20),
      keys: overrides.keys || [{ id: plan.keyID, x: plan.x, y: plan.y }],
    });
  }

  /** Mined (`latest`) or pending (mined + same-sender mempool + test bump) transaction count. */
  nonceOf(address, tag = 'pending') {
    const mined = this.nonces.get(address.toLowerCase()) || 0n;
    if (tag !== 'pending') return mined;
    const pending = this.mempool.filter((tx) => tx.from.toLowerCase() === address.toLowerCase()).length;
    return mined + BigInt(pending) + BigInt(this.faults.pendingNonceBump || 0);
  }

  /** Values a wallet would choose itself: next nonce, estimate*120%, 2*baseFee+tip / tip (or legacy gasPrice). */
  walletChoice(from, { legacy = false } = {}) {
    const fees = legacy ? { gasPrice: q(this.baseFee + this.tip) }
      : { maxFeePerGas: q(2n * this.baseFee + this.tip), maxPriorityFeePerGas: q(this.tip) };
    return { nonce: q(this.nonceOf(from, 'pending')), gas: q((this.estimate * 120n + 99n) / 100n), ...fees };
  }

  blockFor(tag) {
    if (tag === 'latest' || tag === 'pending') return this.head;
    if (typeof tag !== 'string' || !/^0x[0-9a-f]+$/.test(tag)) throw new RpcError(-32602, 'invalid block');
    return this.blocks.find((b) => b.number === BigInt(tag)) || null;
  }

  async rpc(method, params = []) {
    this.calls.push({ method, params });
    if (this.faults.offline) throw new TypeError('fetch failed');
    switch (method) {
      case 'eth_chainId': return this.chainHex;
      case 'eth_blockNumber': return q(this.head.number);
      case 'eth_getBlockByNumber': {
        const block = this.blockFor(params[0]);
        if (!block) return null;
        let hash = block.hash;
        if (this.faults.blockFlip && params[0] !== 'latest') {
          this.faults.blockFlipCount = (this.faults.blockFlipCount || 0) + 1;
          if (this.faults.blockFlipCount >= 1) hash = this.blockHash(block.number + 777n);
        }
        return { number: q(block.number), hash, baseFeePerGas: this.faults.noBaseFee ? undefined : q(block.baseFee),
          transactions: params[1] ? block.txs.map((tx) => ({ ...tx, blockNumber: q(block.number) }))
            : block.txs.map((tx) => tx.hash) };
      }
      case 'eth_getCode': {
        const [address, tag] = params;
        if (!this.blockFor(tag)) throw new RpcError(-32000, 'unknown block');
        const a = address.toLowerCase();
        if (a === FACTORY) return this.faults.factoryCode ? '0x6000' : runtime.factory.runtime;
        if (a === IMPLEMENTATION) return hybridRuntime.contracts.hybrid.runtime;
        return this.deployments.has(a) ? PROXY_RUNTIME : '0x';
      }
      case 'eth_getStorageAt': {
        const info = this.deployments.get(params[0].toLowerCase());
        if (!info || params[1] !== SLOT) return '0x' + word(0);
        return '0x' + info.implementation.slice(2).padStart(64, '0');
      }
      case 'eth_call': {
        const [{ to, data }, tag] = params;
        if (!this.blockFor(tag)) throw new RpcError(-32000, 'unknown block');
        const sig = SEL[data.slice(0, 10)];
        if (to.toLowerCase() === FACTORY && sig === 'computeAddress(bytes32,bytes32)') {
          const creationHash = data.slice(10, 74);
          const salt = data.slice(74, 138);
          let address = oracle.keccak256(Buffer.concat([Buffer.from([0xff]), oracle.bytes(FACTORY),
            Buffer.from(salt, 'hex'), Buffer.from(creationHash, 'hex')])).subarray(12).toString('hex');
          if (this.faults.prediction) address = 'de'.repeat(20);
          return '0x' + address.padStart(64, '0');
        }
        const info = this.deployments.get(to.toLowerCase());
        if (!info) return '0x';
        // Deployed-contract readback temporarily unavailable at the RPC (readback stays unknown, never mismatch).
        if (this.faults.readbackUnavailable) throw new RpcError(-32005, 'limit exceeded');
        if (sig === 'owner()') return '0x' + info.owner.slice(2).padStart(64, '0');
        if (sig === 'getKeyIdHashesCount()') return '0x' + word(info.keys.length);
        if (sig === 'getKey(string)') {
          const offset = Number(BigInt('0x' + data.slice(10, 74)));
          const length = Number(BigInt('0x' + data.slice(10 + offset * 2, 10 + offset * 2 + 64)));
          const id = Buffer.from(data.slice(10 + offset * 2 + 64, 10 + offset * 2 + 64 + length * 2), 'hex').toString();
          const key = info.keys.find((k) => k.id === id);
          return '0x' + (key ? key.x.slice(2) + key.y.slice(2) : word(0) + word(0));
        }
        throw new RpcError(3, 'execution reverted');
      }
      case 'eth_estimateGas': {
        const [tx, tag] = params;
        if (!tag || !this.blockFor(tag)) throw new RpcError(-32602, 'block-bound estimate required');
        if (this.faults.estimate || !tx.from) throw new RpcError(3, 'execution reverted');
        return q(this.estimate);
      }
      case 'eth_maxPriorityFeePerGas':
        if (this.faults.noTip) throw new RpcError(-32601, 'method not found');
        return q(this.tip);
      case 'eth_getTransactionCount': {
        const [address, tag] = params;
        if (tag === 'pending' && this.faults.pendingNonce) throw new RpcError(-32005, 'pending nonce unavailable');
        return q(this.nonceOf(address, tag));
      }
      case 'eth_getTransactionByHash': {
        const tx = this.txs.get(params[0]);
        return tx ? { ...tx, blockNumber: tx.blockNumber === null ? null : q(tx.blockNumber) } : null;
      }
      case 'eth_getTransactionReceipt': return this.receipts.get(params[0]) || null;
      default: throw new RpcError(-32601, `method ${method} not available in the read-only double`);
    }
  }
}

/**
 * Fake EIP-1193 wallet. It captures every request; only `eth_sendTransaction` reaches `chain.submit`. Like a real
 * wallet it chooses nonce/gas/fees itself for any field the dapp request omits (`feeMode: 'legacy'` = gasPrice);
 * `override` then replaces whatever it chose.
 */
class FakeWallet extends EventEmitter {
  constructor(chain, { accounts = ['0x1111111111111111111111111111111111111111'], chainId = '0x89' } = {}) {
    super();
    this.chain = chain;
    this.accounts = accounts;
    this.chainId = chainId;
    this.connected = false;
    this.behavior = { connect: 'ok', send: 'ok', switch: 'ok' };
    this.override = null;
    this.feeMode = 'eip1559';
    this.requests = [];
    // `sends`: the exact dapp requests; `built`: the full transactions this wallet chose and signed for them.
    this.sends = [];
    this.built = [];
    this.pendingSends = [];
  }

  emitAccounts(accounts) { this.accounts = accounts; this.emit('accountsChanged', accounts); }

  emitChain(chainId) { this.chainId = chainId; this.emit('chainChanged', chainId); }

  async request({ method, params = [] }) {
    this.requests.push({ method, params });
    switch (method) {
      case 'eth_requestAccounts':
        if (this.behavior.connect === 'reject') throw Object.assign(new Error('User rejected'), { code: 4001 });
        if (this.behavior.connect === 'hang') return new Promise(() => {});
        if (this.behavior.connect === 'unavailable') throw Object.assign(new Error('internal'), { code: -32603 });
        if (this.behavior.connect === 'deferred') {
          await new Promise((resolve) => { this.releaseConnect = resolve; });
        }
        this.connected = true;
        return this.accounts;
      case 'eth_accounts': return this.connected ? this.accounts : [];
      case 'eth_chainId': return this.chainId;
      case 'wallet_switchEthereumChain':
        if (this.behavior.switch === 'reject') throw Object.assign(new Error('rejected'), { code: 4001 });
        if (this.behavior.switch === '4902') throw Object.assign(new Error('unknown chain'), { code: 4902 });
        this.emitChain(params[0].chainId);
        return null;
      case 'eth_sendTransaction': {
        const tx = params[0];
        this.sends.push(JSON.parse(JSON.stringify(tx)));
        const mode = this.behavior.send;
        if (mode === 'reject') throw Object.assign(new Error('User rejected'), { code: 4001 });
        if (mode === 'error') throw Object.assign(new Error('transport'), { code: -32603 });
        if (mode === 'malformed') return 'not-a-hash';
        const chosen = this.chain.walletChoice(tx.from, { legacy: this.feeMode === 'legacy' });
        const submitted = { ...tx, ...Object.fromEntries(Object.entries(chosen).filter(([key]) => tx[key] === undefined)),
          ...(this.override || {}) };
        for (const key of Object.keys(submitted)) if (submitted[key] === undefined) delete submitted[key];
        this.built.push(JSON.parse(JSON.stringify(submitted)));
        if (mode === 'hang' || mode === 'deferred') {
          return new Promise((resolve, reject) => this.pendingSends.push({ tx: submitted, resolve, reject }));
        }
        return this.chain.submit(submitted);
      }
      default:
        throw Object.assign(new Error(`unsupported ${method}`), { code: 4200 });
    }
  }

  /** Resolves a deferred send with a real submission (late hash). */
  releaseSend(index = 0) {
    const pending = this.pendingSends[index];
    pending.resolve(this.chain.submit(pending.tx));
  }
}

/**
 * A historical v1 attempt exactly as the pre-delegation page froze it: requested nonce, gas limit
 * ceil(estimate*120%), maxFee 2*baseFee+tip, priority tip, user cap (default 1 POL) and gas*maxFee. With
 * `submit` (default) the wallet-side transaction is put on the chain with `override` applied (wallet authority) and
 * the record is `pending` on that hash; otherwise it is the hashless `walletPending` record. `plan` comes from
 * model.buildPlan. Returns the record, its exact bytes, the frozen request and the hash.
 */
function legacyAttempt(chain, plan, { from = '0x1111111111111111111111111111111111111111',
  id = '00000000-0000-4000-8000-00000000f001', capWei = 10n ** 18n, override = null, submit = true } = {}) {
  const gas = (chain.estimate * 120n + 99n) / 100n;
  const maxFeePerGas = 2n * chain.baseFee + chain.tip;
  const request = { from, to: plan.transaction.to, data: plan.transaction.data, value: '0x0', chainId: '0x89',
    nonce: q(chain.nonceOf(from, 'pending')), gas: q(gas), maxFeePerGas: q(maxFeePerGas),
    maxPriorityFeePerGas: q(chain.tip) };
  const head = chain.head;
  const hash = submit ? chain.submit({ ...request, ...(override || {}) }) : null;
  const record = { version: 1, id, manifest: { ...plan.handoff }, chainId: 137, from, to: plan.transaction.to,
    dataHash: plan.dataHash, salt: plan.salt, address: plan.address,
    transaction: { chainId: '0x89', value: '0x0', nonce: request.nonce, gas: request.gas,
      maxFeePerGas: request.maxFeePerGas, maxPriorityFeePerGas: request.maxPriorityFeePerGas },
    capWei: q(capWei), maxTotal: q(gas * maxFeePerGas),
    submission: { blockNumber: q(head.number), blockHash: head.hash },
    sendEntered: true, hash, replacementHash: null, state: submit ? 'pending' : 'walletPending', reason: null,
    observed: null, effectiveNonce: null };
  return { record, raw: JSON.stringify(record), request, hash };
}

module.exports = { FakeChain, FakeWallet, RpcError, PROXY, runtime, hybridRuntime, GWEI, legacyAttempt };
