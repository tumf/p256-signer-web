// Pages has no backend. Closed, public HTTPS read endpoints; no operator credentials.
export const SITE_URL = 'https://tumf.github.io/p256-signer-web/';
const RPC = Object.freeze({
  '/rpc': 'https://polygon-bor-rpc.publicnode.com/',
  '/rpc/1': 'https://ethereum-rpc.publicnode.com/',
  '/rpc/8453': 'https://base-rpc.publicnode.com/',
  '/rpc/84532': 'https://base-sepolia-rpc.publicnode.com/',
});
export function relayURL(route) {
  if (!Object.hasOwn(RPC, route)) throw new TypeError('unknown read route');
  return RPC[route];
}
export const READ_METHODS = Object.freeze(['eth_chainId', 'web3_clientVersion', 'eth_blockNumber',
  'eth_maxPriorityFeePerGas', 'eth_getBlockByNumber', 'eth_getCode', 'eth_getStorageAt', 'eth_call',
  'eth_estimateGas', 'eth_getTransactionCount', 'eth_getTransactionByHash', 'eth_getTransactionReceipt',
  'eth_getBalance']);
export function readURL(route, method) {
  if (!READ_METHODS.includes(method)) throw new TypeError('read-only RPC method required');
  return relayURL(route);
}
