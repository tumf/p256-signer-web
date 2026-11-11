// Pages is static; only bounded read-only RPC uses the existing relay.
export const SITE_URL = 'https://tumf.github.io/p256-signer-web/';
export const RELAY_ORIGIN = 'https://p256-signer.mini.tumf.dev';
export function relayURL(route) {
  if (!['/rpc', '/rpc/1', '/rpc/8453', '/rpc/84532'].includes(route)) throw new TypeError('unknown relay route');
  return RELAY_ORIGIN + route;
}
