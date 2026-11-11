import { readURL } from './site.js';
// Page bootstrap: fixed public config, same-origin read-only RPC, wallet manager, controller and UI.
// Order matters: the transactional attempt store settles before any deployment command is admitted.
import { AttemptStore, LEGACY_KEY } from './attempt-store.js';
import { RegistrationController, validateRecord } from './controller.js';
import { mountUI } from './ui.js';
import { WalletManager } from './wallet.js';
import { inspect } from './model.js';
import { POLYGON } from './chains.js';

const RPC_TIMEOUT_MS = 10_000;
// Per-tab copy of the validated public plan so a reload shows the same plan (public manifest bytes only).
const PLAN_KEY = 'p256.registration.plan.v1';
let rpcId = 0;

/**
 * POST one JSON-RPC object to the same-origin relay route of one closed chain (`chains.js`; Polygon `/rpc`). The route
 * is the chain's fixed constant, never caller text. HTTP/transport failure has no numeric code.
 */
async function relay(route, method, params) {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), RPC_TIMEOUT_MS);
  try {
    const response = await fetch(readURL(route, method), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
      referrerPolicy: 'no-referrer', signal: abort.signal,
      body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
    });
    if (!response.ok) throw new TypeError(`relay HTTP ${response.status}`);
    const body = await response.json();
    if (body && body.error) {
      const error = new Error(String(body.error.message || 'RPC error').slice(0, 200));
      error.code = Number.isInteger(body.error.code) ? body.error.code : -32000;
      throw error;
    }
    return body.result;
  } finally {
    clearTimeout(timer);
  }
}

/** The read-only relay client of one closed chain. */
const rpcFor = (chain) => (method, params) => relay(chain.route, method, params);
const rpc = rpcFor(POLYGON);

async function loadConfig() {
  try {
    const response = await fetch('./config.json', { credentials: 'same-origin', cache: 'no-store' });
    return response.ok ? await response.json() : null;
  } catch {
    return null;
  }
}

async function start() {
  const config = await loadConfig();
  let controller;
  const wallet = new WalletManager({
    win: window, config, origin: location.origin,
    loadWalletConnect: () => import('./walletconnect.js'),
    onChange: (event) => controller && controller.walletChanged(event),
  });
  let publicInspection = 'idle';
  let observedPlan = null;
  let observation = null;
  let renderUI = () => {};
  const render = (view) => {
    if (controller.plan !== observedPlan) {
      observedPlan = controller.plan;
      publicInspection = observedPlan ? 'loading' : 'idle';
      if (observedPlan) queueMicrotask(observe);
    }
    renderUI({ ...view, publicInspection });
  };
  const observe = async () => {
    const plan = controller.plan;
    if (!plan) return;
    const token = {};
    observation = token;
    observedPlan = plan;
    publicInspection = 'loading';
    controller.emit();
    try {
      const result = await inspect(controller.planRPC(plan), plan);
      if (controller.plan !== plan || observation !== token) return;
      publicInspection = result.kind;
    } catch {
      if (controller.plan !== plan || observation !== token) return;
      publicInspection = 'unknown';
    }
    controller.emit();
  };
  let indexedDB = null;
  try {
    indexedDB = window.indexedDB || null;
  } catch {
    // Storage access denied: the store reports unavailable and sends stay blocked (no fallback store).
  }
  const factory = indexedDB || { open() { throw new Error('indexedDB unavailable'); } };
  // The old localStorage key is read-only legacy input; nothing in this page writes or removes it.
  const readLegacy = () => window.localStorage.getItem(LEGACY_KEY);
  const store = new AttemptStore({ indexedDB: factory, readLegacy, validateRecord });
  const planStore = {
    read: () => window.sessionStorage.getItem(PLAN_KEY),
    write: (text) => window.sessionStorage.setItem(PLAN_KEY, text),
    remove: () => window.sessionStorage.removeItem(PLAN_KEY),
  };
  controller = new RegistrationController({
    rpc, rpcFor, wallet, store, uuid: () => crypto.randomUUID(), onState: (view) => render(view), planStore,
  });
  renderUI = mountUI(document, controller, {
    loadQR: () => import('./qr.js').then((module) => module.default),
    clipboard: (value) => navigator.clipboard && navigator.clipboard.writeText(value),
  });
  // Storage loads first; the public fragment may be consumed meanwhile (history replaced, never navigated), but
  // inspection/consent/send stay disabled until the load settles. Without a fragment, the plan this tab remembered
  // is restored (validated like input; no wallet or send activity).
  const loading = controller.loadAttempt();
  if (!controller.consumeFragment(location, history)) controller.restorePlan();
  // App links can reuse this document; every nonempty fragment supersedes the remembered public plan.
  window.addEventListener('hashchange', () => controller.consumeFragment(location, history));
  wallet.start();
  document.getElementById('retry-inspection').addEventListener('click', observe);
  // The attempt's receipt and the selected address are independent facts; refresh both without sending.
  document.getElementById('refresh').addEventListener('click', observe);
  controller.emit();
  await loading;
  window.__registration = Object.freeze({ ready: true });
}

start();
