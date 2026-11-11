// Real pinned SignClient proposal API, synthetic local settlement event; all outbound network denied.
// No relay pairing, native app, signature or public broadcast. Only nonsecret counters leave the child.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import { EventEmitter } from 'node:events';
let stage = 'load';
setTimeout(() => { console.error(`probe timeout: ${stage}`); process.exit(1); }, 15_000);
const deny = () => { throw new Error('network denied'); };
net.Socket.prototype.connect = deny;
tls.connect = http.request = http.get = https.request = https.get = deny;
globalThis.fetch = async () => { throw new Error('network denied'); };
globalThis.WebSocket = class extends EventEmitter {
  constructor() { super(); setImmediate(() => { const e = new Error('network denied'); this.onerror?.(e);
    if (this.listenerCount('error')) this.emit('error', e); }); }
  send() { deny(); } close() {}
};
const { SignClient } = await import('@walletconnect/sign-client');
const { memoryStorage } = await import('../../key-session.js');
const { createV3BridgeSession, createSessionConfig, BRIDGE_ORIGIN, CHAIN, METHODS, requiredNamespaces } =
  await import('../../defi-v3-session.js');
assert.equal(JSON.parse(readFileSync(new URL('../../node_modules/@walletconnect/sign-client/package.json', import.meta.url))).version, '2.26.0');
const storage = memoryStorage();
stage = 'init';
const client = await SignClient.init({ projectId: 'ab'.repeat(16), logger: 'silent', telemetryEnabled: false,
  customStoragePrefix: 'p256.defi.v3.probe', storage,
  metadata: { name: 'P256 fixture', description: 'Offline v3 probe', url: BRIDGE_ORIGIN, icons: [] } });
let publications = 0;
stage = 'connect';
client.core.relayer.subscribe = async () => 'offline-subscription';
client.core.relayer.publish = client.core.relayer.publishCustom = async () => { publications++; };
client.core.verify.register = async () => undefined; // No synthetic attestation is treated as authenticated.
const signer = '0x' + '22'.repeat(20), topic = 'ef'.repeat(32);
const bridge = createV3BridgeSession({ client, config: createSessionConfig({ signer, safe: '0x' + '11'.repeat(20) }),
  sha256: bytes => new Uint8Array(createHash('sha256').update(bytes).digest()) });
let displayed = false;
const pending = bridge.connect(uri => { assert.ok(uri.startsWith('wc:')); displayed = true; });
pending.catch(() => {});
let proposal;
for (let i = 0; i < 150 && (!proposal || !displayed); i++) {
  await new Promise(resolve => setTimeout(resolve, 20));
  proposal = client.proposal.getAll()[0];
}
assert.ok(proposal);
assert.ok(displayed, 'SDK connect must return before local settlement');
stage = 'settlement';
assert.deepEqual(proposal.requiredNamespaces, {});
assert.deepEqual(proposal.optionalNamespaces, requiredNamespaces());
const session = { topic, expiry: Math.floor(Date.now() / 1000) + 300, peer: { metadata: { url: BRIDGE_ORIGIN } },
  namespaces: { eip155: { accounts: [`${CHAIN}:${signer}`], methods: [...METHODS], events: [] } } };
await client.session.set(topic, session);
// Fulfil the SDK's real approval promise at its event seam, not via a fake connect implementation.
const event = client.engine.events.eventNames().find(name => String(name).includes(String(proposal.id)));
assert.ok(event);
client.engine.events.emit(event, { session });
stage = 'approval';
assert.equal((await pending).connected, true);
stage = 'lifecycle';
client.events.emit('session_update', { topic, id: 1, params: { namespaces: session.namespaces } });
assert.equal(bridge.inspect().connected, false);
await bridge.dispose();
console.log(JSON.stringify({ sdk: '2.26.0', proposal: true, approval: true, lifecycle: true,
  publications, persistedOutsideMemory: false, relayPairing: false }));
process.exit(0);
