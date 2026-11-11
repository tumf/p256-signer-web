import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mountRecoveryPanel } from '../recovery-panel.js';
import { expected, v } from './support/safe-fixtures.mjs';
// Minimal DOM sink: UI uses only native textContent, buttons and select, never peer HTML.
class Node {
  constructor(tag) { this.tagName = tag; this.children = []; this.handlers = {}; this.value = ''; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  addEventListener(name, f) { this.handlers[name] = f; }
  setAttribute() {}
  after() {}
  getContext() { return { clearRect() {} }; }
}
test('list/reload reads only unsigned records, requires explicit connection and independent inputs', async () => {
  const doc = { createElement: (name) => new Node(name) }, host = new Node('section');
  const record = { version: 1, purpose: 'safe-tx-v1.5.0', requestId: JSON.parse(v.request.envelope).id,
    envelope: v.request.envelope, context: v.context.result, expected };
  let clients = 0, lists = 0, independent = 0;
  const panel = mountRecoveryPanel(doc, host, { purpose: record.purpose,
    store: { list: async () => { lists++; return [record]; } },
    getExpected: () => { independent++; throw new Error('independent inputs missing'); },
    getClient: async () => { clients++; }, clock: () => Number(JSON.parse(record.envelope).issuedAt) + 30 });
  await panel.reload();
  assert.equal(lists, 1); assert.equal(clients, 0); assert.equal(independent, 0);
  await panel.connect();
  assert.equal(independent, 1); assert.equal(clients, 0);
  assert.match(panel.status.textContent, /入力/);
  await panel.close();
});
