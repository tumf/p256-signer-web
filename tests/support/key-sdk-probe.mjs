// Child-process probe of the real pinned @walletconnect/sign-client 2.26.0 through the production KeyChangeSession
// with all network denied and the relay subscribe/publish stubbed (no relay is ever reached). Prints one JSON line
// and exits explicitly, because the SDK keeps internal timers alive. Adapter proof only, not a pairing.
const seen = [];
globalThis.WebSocket = class { constructor(url) { seen.push(String(url)); setTimeout(() => this.onerror?.(new Error('denied')), 5); } send() {} close() {} };
globalThis.fetch = async (url) => { seen.push(String(url)); throw new TypeError('network denied'); };
const { SignClient } = await import('@walletconnect/sign-client');
const { KeyChangeSession, signClientOptions } = await import('../../key-session.js');
const { parseAuthority } = await import('../../key-model.js');
const { K1, anchorText, softwareKey } = await import('./key-fixtures.mjs');
const anchor = parseAuthority(anchorText('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', softwareKey(K1)));
const options = signClientOptions('ab'.repeat(16));
const client = await SignClient.init(options);
const published = [];
client.core.relayer.subscribe = async () => 'subscription';
client.core.relayer.publish = async (topic) => { published.push(topic); };
const session = new KeyChangeSession(client, anchor, () => Math.floor(Date.now() / 1000));
let uri = null;
void session.connect((value) => { uri = value; }).catch(() => {});
for (let i = 0; i < 150 && (client.proposal.getAll().length === 0); i++) await new Promise((r) => setTimeout(r, 20));
const proposals = client.proposal.getAll().map((p) => ({ requiredNamespaces: p.requiredNamespaces,
  optionalNamespaces: p.optionalNamespaces, proposer: p.proposer?.metadata?.url }));
console.log(JSON.stringify({ proposals, storageKeys: await options.storage.getKeys(), prefix: options.customStoragePrefix,
  telemetryEnabled: options.telemetryEnabled, uri: typeof uri === 'string' && uri.startsWith('wc:'),
  localStorage: typeof globalThis.localStorage, seen }));
process.exit(0);
