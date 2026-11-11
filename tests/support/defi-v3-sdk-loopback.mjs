// Test-only opaque loopback relay. Real pinned SDKs own encryption, session and RPC history.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { writeFileSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import { buildSafeTxWire } from './defi-v3-exchange-client.mjs';
import { BRIDGE_ORIGIN, CHAIN, SIGN_METHOD, requiredNamespaces, candidateFromWire } from '../../defi-v3-session.js';
import { verifyV3Result } from '../../defi-v3-result.js';
const require = createRequire(import.meta.url);
const report = process.argv[2];
assert.ok(report === '--self-check' || (report && !report.startsWith('--')), 'report path required');
const sha256 = bytes => new Uint8Array(createHash('sha256').update(bytes).digest());
// Swift relay IDs exceed Number.MAX_SAFE_INTEGER. Echo their original JSON token, never a rounded Number.
const relayRPC = raw => JSON.parse(raw, (key, value, context) =>
  key === 'id' && typeof value === 'number' ? JSON.rawJSON(context.source) : value);
let phase = 'starting', errorCode, uri, session, configured = false, publications = 0, deliveries = 0, verified = false;
let externalDenied = 0, sequence = 0;
const subscriptions = new Map(), messages = new Map(), methods = new Set();
const status = () => ({ phase, ...(errorCode ? { errorCode } : {}), publications, deliveries, verified, externalDenied, methods: [...methods] });
const fail = code => { errorCode ??= code; phase = 'failed'; verified = false; };
const advance = next => { if (!errorCode) { phase = next; verified = next === 'verified'; } };
function finishReport(observations) {
  assert.ok(!errorCode && verified && phase === 'verified');
  assert.equal(observations.unknownEmits, 0); assert.equal(observations.signingCalls, 1);
  assert.ok(publications >= 4 && deliveries >= 4);
  assert.ok(observations.externalHTTPRefused > 0); assert.equal(externalDenied, 0);
  return { ...status(), scope: 'web-verification-only', swiftObservations: observations,
    sdk: '2.26.0', fixtureAuthority: true, publicRelay: false };
}
if (report === '--self-check') {
  const wideID = '{"id":1793947256123456789}';
  assert.notEqual(JSON.stringify(JSON.parse(wideID)), wideID, 'control reproduces rounded Swift relay ID');
  assert.equal(JSON.stringify(relayRPC(wideID)), wideID);
  for (const id of ['7', '"string-id"', 'null']) {
    const text = `{"id":${id}}`; assert.equal(JSON.stringify(relayRPC(text)), text);
  }
  const observations = { unknownEmits: 0, signingCalls: 1, externalHTTPRefused: 1 };
  publications = deliveries = 4;
  assert.throws(() => finishReport(observations));
  advance('verified');
  const evidence = finishReport(observations);
  assert.equal(evidence.scope, 'web-verification-only');
  assert.ok(!JSON.stringify(evidence).includes('swiftPassed'));
  assert.throws(() => finishReport({ ...observations, signingCalls: 2 }));
  fail('RELAY_PROTOCOL');
  for (const next of ['pairing', 'connected', 'requested', 'verified']) {
    advance(next); assert.equal(phase, 'failed'); assert.equal(verified, false);
  }
  fail('TIMEOUT'); assert.equal(errorCode, 'RELAY_PROTOCOL');
  assert.throws(() => finishReport(observations));
  console.log('PASS Node terminal failure and Web-only evidence (no sockets or SDK)');
  process.exit(0);
}
const { WebSocketServer } = require('ws');
const timeout = setTimeout(() => { fail('TIMEOUT'); writeFileSync(report, JSON.stringify(status())); process.exit(1); }, 480_000);
let submit, approvedSession;
const server = http.createServer(async (req, res) => {
  const reply = (code, object) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(object)); };
  try {
    if (req.method === 'GET' && req.url === '/status') return reply(200, status());
    if (req.method === 'GET' && req.url === '/pairing') return reply(uri ? 200 : 503, uri ? { uri } : {});
    if (req.method !== 'POST' || !['/config', '/finish'].includes(req.url)) return reply(404, {});
    let length = 0, chunks = [];
    for await (const chunk of req) { length += chunk.length; if (length > 4096) throw Error('BODY'); chunks.push(chunk); }
    const body = JSON.parse(Buffer.concat(chunks));
    if (req.url === '/config') {
      assert.ok(!errorCode); assert.equal(configured, false); configured = true;
      // Swift approval can return before JS receives settlement. Await the real SDK promise.
      await approvedSession; assert.ok(!errorCode); assert.ok(session);
      assert.match(body.publicPoint, /^0x04[0-9a-f]{128}$/);
      assert.equal(Buffer.from(sha256(Buffer.from(body.publicPoint.slice(2), 'hex'))).toString('hex'), body.keyId);
      const wire = buildSafeTxWire({ ...body, issuedAt: Number(body.issuedAt), validity: Number(body.expiresAt) - Number(body.issuedAt) });
      const candidate = candidateFromWire(wire, sha256);
      advance('requested');
      submit(wire, candidate, body.publicPoint).catch(() => fail('REQUEST_OR_VERIFICATION'));
      return reply(200, { accepted: true });
    }
    finishReport(body);
    reply(200, { finished: true });
    clearTimeout(timeout);
    setTimeout(() => {
      if (errorCode) { writeFileSync(report, JSON.stringify(status())); process.exit(1); }
      writeFileSync(report, JSON.stringify(finishReport(body))); process.exit(0);
    }, 100);
  } catch { reply(400, { errorCode: 'CONTROL_REJECTED' }); }
});
const wss = new WebSocketServer({ server, maxPayload: 1_048_576 });
function notify(socket, topic, data) {
  if (socket.readyState !== 1) return;
  const id = subscriptions.get(socket)?.get(topic); if (!id) return;
  socket.send(JSON.stringify({ jsonrpc: '2.0', id: ++sequence, method: 'irn_subscription', params: { id, data } }));
  deliveries++;
}
wss.on('connection', socket => {
  subscriptions.set(socket, new Map());
  socket.on('close', () => subscriptions.delete(socket));
  socket.on('error', () => {});
  socket.on('message', raw => {
    try {
      const rpc = relayRPC(raw.toString()), p = rpc.params;
      if (!rpc.method) return; // Subscription acknowledgements.
      if (/^(irn|iridium)_[A-Za-z]+$/.test(rpc.method) || ['wc_proposeSession', 'wc_approveSession'].includes(rpc.method)) methods.add(rpc.method);
      const result = value => socket.send(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: value }));
      const subscribe = topic => { assert.match(topic, /^[0-9a-f]{64}$/); const id = createHash('sha256').update(topic).digest('hex'); subscriptions.get(socket).set(topic, id); return id; };
      switch (rpc.method) {
        case 'wc_proposeSession': {
          subscribe(p.pairingTopic); // Optimized proposal implicitly subscribes the proposer.
          assert.equal(typeof p.sessionProposal, 'string');
          const data = { topic: p.pairingTopic, message: p.sessionProposal, publishedAt: Date.now(), tag: 1100 };
          messages.set(p.pairingTopic, [data]); publications++; result(true);
          setImmediate(() => { for (const peer of subscriptions.keys()) if (peer !== socket) notify(peer, p.pairingTopic, data); });
          break;
        }
        case 'wc_approveSession': {
          subscribe(p.sessionTopic); // Optimized approval implicitly subscribes the wallet.
          for (const [topic, message, tag] of [[p.pairingTopic, p.sessionProposalResponse, 1101],
                                               [p.sessionTopic, p.sessionSettlementRequest, 1102]]) {
            assert.match(topic, /^[0-9a-f]{64}$/);
            assert.equal(typeof message, 'string'); assert.ok(message.length < 1_048_576);
            const data = { topic, message, publishedAt: Date.now(), tag };
            const list = messages.get(topic) ?? []; assert.ok(list.length < 32); list.push(data); messages.set(topic, list);
            publications++;
            setImmediate(() => { for (const peer of subscriptions.keys()) if (peer !== socket) notify(peer, topic, data); });
          }
          result(true); break;
        }
        case 'irn_subscribe': {
          result(subscribe(p.topic));
          setImmediate(() => { for (const message of messages.get(p.topic) ?? []) notify(socket, p.topic, message); }); break;
        }
        case 'irn_batchSubscribe': {
          assert.ok(Array.isArray(p.topics) && p.topics.length <= 32); result(p.topics.map(subscribe));
          setImmediate(() => { for (const topic of p.topics) for (const message of messages.get(topic) ?? []) notify(socket, topic, message); }); break;
        }
        case 'irn_publish': {
          assert.match(p.topic, /^[0-9a-f]{64}$/); assert.equal(typeof p.message, 'string'); assert.ok(p.message.length < 1_048_576);
          const data = { topic: p.topic, message: p.message, publishedAt: Date.now(), tag: p.tag };
          const list = messages.get(p.topic) ?? []; assert.ok(list.length < 32); list.push(data); messages.set(p.topic, list);
          publications++; result(true);
          setImmediate(() => { for (const peer of subscriptions.keys()) if (peer !== socket) notify(peer, p.topic, data); }); break;
        }
        case 'irn_unsubscribe': subscriptions.get(socket).delete(p.topic); result(true); break;
        default: throw Error('METHOD:' + (/^[a-zA-Z_]{1,64}$/.test(rpc.method) ? rpc.method : 'invalid'));
      }
    } catch (error) { console.error('relay failure', error.name, String(error.message).slice(0, 120).replace(/[a-f0-9]{32,}/g, '[redacted]')); fail('RELAY_PROTOCOL'); socket.close(); }
  });
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
const originalConnect = net.Socket.prototype.connect;
const deny = () => { externalDenied++; throw Error('EXTERNAL_NETWORK_DENIED'); };
net.Socket.prototype.connect = function (...args) {
  const value = args[0];
  const options = Array.isArray(value) ? value[0] : value;
  const destPort = typeof options === 'object' ? options.port : options;
  const host = typeof options === 'object' ? options.host : args[1];
  if (Number(destPort) !== port || host !== '127.0.0.1') return deny();
  return originalConnect.apply(this, args);
};
tls.connect = https.request = https.get = deny;
globalThis.fetch = async () => deny();
const { SignClient } = await import('@walletconnect/sign-client');
const { memoryStorage } = await import('../../key-session.js');
assert.equal(JSON.parse(readFileSync(new URL('../../node_modules/@walletconnect/sign-client/package.json', import.meta.url))).version, '2.26.0');
try {
  const client = await SignClient.init({ projectId: 'ab'.repeat(16), logger: 'silent', telemetryEnabled: false,
    relayUrl: `ws://127.0.0.1:${port}`, storage: memoryStorage(), customStoragePrefix: `p256.loopback.${randomUUID()}`,
    metadata: { name: 'P256 fixture', description: 'Loopback test', url: BRIDGE_ORIGIN, icons: [] } });
  // No attestation is fabricated: Swift receives the SDK's real unknown Verify context.
  client.core.verify.register = async () => undefined;
  submit = async (wire, candidate, publicPoint) => {
    const response = await client.request({ topic: session.topic, chainId: CHAIN,
      request: { method: SIGN_METHOD, params: [JSON.parse(new TextDecoder().decode(wire))] }, expiry: 300 });
    const result = verifyV3Result(response, candidate, { sha256 });
    assert.equal(result.publicPoint, publicPoint);
    assert.throws(() => verifyV3Result({ ...response, rawSignature: '0x' + '00'.repeat(64) }, candidate, { sha256 }));
    advance('verified');
  };
  const pairing = await client.connect({ requiredNamespaces: {}, optionalNamespaces: requiredNamespaces() });
  uri = pairing.uri; assert.ok(uri?.startsWith('wc:'));
  approvedSession = pairing.approval().then(value => { session = value; advance('connected'); }).catch(() => fail('APPROVAL'));
  advance('pairing');
  console.log(JSON.stringify({ port }));
} catch { fail('SDK_START'); writeFileSync(report, JSON.stringify(status())); process.exit(1); }
