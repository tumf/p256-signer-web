// Test-only bootstrap: real product renderer/controller/wallet/IndexedDB and real same-origin read RPC.
// Bootstrap, RPC wrapper, config and SignClient are test replacements; not the shipped entrypoint.
// No relay, device or physical-auth evidence.
import {mountKeyChangePage} from '../../key-change.js';
import {KeyChangeController} from '../../key-controller.js';
import {KeyAttemptStore} from '../../key-attempt-store.js';
import {WalletManager} from '../../wallet.js';
import {nativeClient} from './key-fixtures.mjs';
const peer={signer:window.__keyFork.signer,
 context:()=>window.__keyForkNative({method:'context'}),
 sign:envelope=>window.__keyForkNative({method:'sign',envelope})};
const native=nativeClient(peer);
let id=0, controller;
const rpc=async(method,params=[])=>{
 const response=await fetch('/rpc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:++id,method,params})});
 if(!response.ok)throw new Error('read relay HTTP error');
 const body=await response.json();if(body.error)throw new Error('read relay RPC error');return body.result;
};
const wallet=new WalletManager({win:window,config:null,origin:location.origin,onChange:()=>controller?.walletChanged()});
const store=new KeyAttemptStore({indexedDB:window.indexedDB});
controller=new KeyChangeController({rpc,wallet,store,loadSignClient:async()=>native.SignClient,
 loadConfig:async()=>({walletConnectProjectId:'ab'.repeat(16)}),clock:()=>Math.floor(Date.now()/1000),uuid:()=>crypto.randomUUID()});
mountKeyChangePage(document,{controller,wallet,loadQR:()=>import('../../qr.js').then(m=>m.default)});
wallet.start();addEventListener('pagehide',()=>{controller.invalidateAuthority();store.close();});
window.__keyForkView=()=>controller.view();
await controller.loadAttempt();window.__keyForkReady=true;
