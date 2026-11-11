// The four closed chains the iPhone signer admits (CAIP-2 eip155:<id>), restated for the Web: each with its fixed
// same-origin read-only relay route, wallet chain ID, native currency, deployment recipe, the complete HybridDeleGator
// v1.3.0 implementation runtime hash of that chain (its immutables cache that chain's EIP-712 domain, so no hash is
// shared or normalized) and the block window native context blocks may trail or lead the Web block by (about 60
// seconds). No other chain exists here. A page never chooses a chain: only a parsed public handoff or anchor naming
// exactly one of these selects it, and every read, request, wallet send and record then names that chain only.

function entry(id, name, native, route, recipe, implementationCodeHash, blockWindow, testnet = false) {
  const label = testnet ? `${name}（テストネット）` : name;
  return Object.freeze({
    id, decimal: String(id), hex: '0x' + id.toString(16), caip2: `eip155:${id}`, name, label,
    title: `${name}（${testnet ? 'テストネット・' : ''}chain ${id}）`,
    // The review row naming the network; Polygon keeps its exact legacy words.
    network: id === 137 ? 'Polygon PoS · eip155:137' : `${label} · eip155:${id}`,
    native, route, recipe, implementationCodeHash, blockWindow, testnet,
  });
}

export const CHAINS = Object.freeze({
  1: entry(1, 'Ethereum', 'ETH', '/rpc/1', 'ethereum-1/hybrid-delegator-1.3.0/erc1967-create2/v1',
    '0xf1fe1f6dab609a33e1cb24a61b508b2d7edb42de69f8088f85c63bfbb64428a9', 5n),
  137: entry(137, 'Polygon', 'POL', '/rpc', 'polygon-137/hybrid-delegator-1.3.0/erc1967-create2/v1',
    '0xd8b4fd0fcd44ec79c86d8421ca79950e4d2e2b9a3e0b40b258d5d90d03fabef1', 30n),
  8453: entry(8453, 'Base', 'ETH', '/rpc/8453', 'base-8453/hybrid-delegator-1.3.0/erc1967-create2/v1',
    '0x0d4c08ee7b169e8f4b5e6fe81f03395f6887a3952c0fd6139efd5cf7a14b4a85', 30n),
  84532: entry(84532, 'Base Sepolia', 'ETH', '/rpc/84532', 'base-sepolia-84532/hybrid-delegator-1.3.0/erc1967-create2/v1',
    '0x5c3c6720860eb4ebf2f71bac72c0156d6a41ebf45b4c8323069b6f9f1c6d85d5', 30n, true),
});

/** The legacy default chain: every record or message without its own chain ID means Polygon. */
export const POLYGON = CHAINS[137];

/**
 * One fixed Polygon-worded page text for one closed chain: the exact legacy bytes for Polygon (every frozen inventory,
 * visual judge and message table keeps them) and the same words naming the other chain otherwise.
 */
export function chainText(text, chain = POLYGON) {
  return chain === POLYGON ? text : text.replaceAll('Polygon', chain.label);
}

/**
 * The closed chain of a canonical decimal string (every stored, anchor or wire `chainId` field), or null; never a
 * number, alias, padding or prefix, so no record is admitted in a shape the Polygon-only format refused.
 */
export function chainOf(value) {
  return typeof value === 'string' && /^[1-9][0-9]{0,9}$/.test(value)
    && Object.prototype.hasOwnProperty.call(CHAINS, value) ? CHAINS[value] : null;
}

/** The closed chain of an exact integer chain ID (the numeric `chainId` of a v1 deployment handoff), or null. */
export function chainOfId(value) {
  return Number.isSafeInteger(value) ? chainOf(String(value)) : null;
}

/** The closed chain of an exact lowercase wallet chain ID (`0x89`), or null. */
export function chainOfHex(value) {
  if (typeof value !== 'string' || !/^0x[1-9a-f][0-9a-f]{0,8}$/.test(value)) return null;
  return chainOf(String(Number.parseInt(value.slice(2), 16)));
}

/**
 * The infrastructure every closed chain shares, each pinned by its complete runtime hash (the same values as
 * HybridReadChain.swift): a non-Polygon key-context read proves them at its block before trusting the Signer.
 */
export const INFRASTRUCTURE = Object.freeze({
  factory: '0x69aa2f9fe1572f1b640e1bbc512f5c3a734fc77c',
  factoryCodeHash: '0x82c94f0735e1e8ea2ffc1df4186cf5d3e28877459f9ff330289b99ea851e5ae9',
  entryPointCodeHash: '0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58',
  scl: '0xccd3b747f3dbd349fa3af4ebc7d0c31ae6f21dd1',
  sclCodeHash: '0x2b4a957fbff46f4609211f4dee870935ff4d930dbf17c7441e9178deb1913368',
});
