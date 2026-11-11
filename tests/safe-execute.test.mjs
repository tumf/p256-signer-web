import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import ethers from '../vendor/ethers.js';
import judge from './support/safe-execution-judge.cjs';
import { Execution, snapshot, operation, sdkNonce, decodeSignatures, mount } from '../safe-execute.js';
import * as executeModule from '../safe-execute.js';
import { mock } from 'node:test';
const runtimeFixture = JSON.parse(readFileSync(new URL('fixtures/safe150-proxy.json', import.meta.url)));
function observedChain(state = base([owner(wallets[0])], 1)) {
  const calls = [], abi = new U.Interface(['function VERSION() view returns(string)', 'function getOwners() view returns(address[])',
    'function getThreshold() view returns(uint256)', 'function nonce() view returns(uint256)', 'function getModulesPaginated(address,uint256) view returns(address[],address)']);
  const rpc = async (method, params) => {
    calls.push([method, params]);
    if (method === 'eth_chainId') return '0x89';
    if (method === 'eth_getBlockByNumber') return {number:'0x64',hash:'0x'+'11'.repeat(32),timestamp:'0x'+clock().toString(16)};
    if (method === 'eth_getCode') return params[0] === safe ? runtimeFixture.runtime : params[0] === base().singleton ? runtimeFixture.singletonRuntime : '0x';
    if (method === 'eth_getStorageAt') return params[1] === U.hexZeroPad('0x00',32) ? U.hexZeroPad(base().singleton,32) : U.hexZeroPad('0x00',32);
    const name = abi.parseTransaction({data:params[0].data}).name;
    return abi.encodeFunctionResult(name, name === 'VERSION' ? ['1.5.0'] : name === 'getOwners' ? [state.owners.map(o=>o.address)] : name === 'getThreshold' ? [state.threshold] : name === 'nonce' ? [state.nonce] : [[], '0x0000000000000000000000000000000000000001']);
  };
  return {rpc,calls};
}

for(const changed of ['none','original-before','original-after','previous-before','previous-after','current-after','rollback','timestamp','nonce'])test(`page advancing observation ${changed} keeps signed intent or stops`,async()=>{
 const state=base([owner(wallets[0])],1),c=observedChain(state);let height=100n,phase=false,latestRead=false;
 const h=n=>n===100n?state.block.hash:'0x'+n.toString(16).padStart(64,'0');
 const rpc=async(m,p)=>{
  if(m!=='eth_getBlockByNumber')return c.rpc(m,p);
  const n=p[0]==='latest'?height:BigInt(p[0]);if(p[0]==='latest')latestRead=true;
  let hash=h(n),timestamp=BigInt(clock());
  if(phase&&((changed==='original-before'&&n===100n)||(changed==='original-after'&&latestRead&&n===100n)||(changed==='previous-before'&&n===101n)||(changed==='previous-after'&&latestRead&&n===101n)||(changed==='current-after'&&latestRead&&n===102n&&p[0]!=='latest')))hash='0x'+'ee'.repeat(32);
  if(phase&&changed==='timestamp'&&n===102n)timestamp--;
  return {number:'0x'+n.toString(16),hash,timestamp:'0x'+timestamp.toString(16)};
 };
 const {el,m,downloads}=page(rpc);height=101n;await el('load').listeners.click();assert.equal(el('error').textContent,'');
 const original=m.unsigned();el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));
 phase=true;latestRead=false;height=changed==='rollback'?100n:102n;if(changed==='nonce')state.nonce='8';
 await el('collect').listeners.click();
 if(changed==='none'){assert.equal(el('error').textContent,'');assert.equal(m.view().count,1);height++;await el('prepare').listeners.click();assert.equal(m.view().state,'PREPARED');assert.deepEqual(m.unsigned(),original);await el('export').listeners.click();assert.equal(downloads(),1);}
 else {assert.notEqual(el('error').textContent,'');assert.equal(m.view().state,'STOPPED');assert.equal(m.view().count,0);assert.equal(downloads(),0);}
 assert.equal(el('execute').disabled,true);
});

test('receipt lookup is explicit and reset drops pending read',async()=>{
 const c=observedChain(),hold=barrier();let reads=0;
 const rpc=async(method,params)=>{if(method==='eth_getTransactionByHash'){reads++;await hold.promise;return null;}return c.rpc(method,params);};
 const {el,m}=page(rpc);await el('load').listeners.click();el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));
 await el('collect').listeners.click();await el('prepare').listeners.click();assert.equal(reads,0);
 el('receipt-hash').value='0x'+'22'.repeat(32);
 assert.equal(typeof el('check-receipt').listeners.click,'function');const pending=el('check-receipt').listeners.click();
 while(!reads)await new Promise(resolve=>setImmediate(resolve));el('reset').listeners.click();hold.resolve();await pending;
 assert.equal(reads,1);assert.equal(el('receipt-result').textContent,'');assert.equal(el('error').textContent,'');assert.equal(el('execute').disabled,true);
});

test('page reads a chosen packet file but collects only on explicit verification',async()=>{
  const {el,m}=page();await el('load').listeners.click();
  const text=JSON.stringify(eoa(wallets[0],m.view().hash));
  el('packet-file').files=[{size:new TextEncoder().encode(text).length,text:async()=>text}];
  assert.equal(typeof el('packet-file').listeners.change,'function');await el('packet-file').listeners.change();
  assert.equal(el('error').textContent,'');assert.equal(el('signature').value,text);assert.equal(m.view().count,0);
  await el('collect').listeners.click();assert.equal(el('error').textContent,'');assert.equal(m.view().count,1);
});

for(const change of ['reset','input'])test(`packet file read after ${change} cannot restore signature input`,async()=>{
  const {el,m}=page();await el('load').listeners.click();const hold=barrier();
  el('packet-file').files=[{size:2,text:()=>hold.promise}];
  assert.equal(typeof el('packet-file').listeners.change,'function');const pending=el('packet-file').listeners.change();
  if(change==='reset')el('reset').listeners.click();else el('value').listeners.input();
  hold.resolve('{}');await pending;assert.equal(el('signature').value,'');assert.equal(el('error').textContent,'');assert.equal(m.view().state,'STOPPED');
});

for(const kind of ['large','multiple','malformed','expanded','unreadable'])test(`packet file ${kind} rejects without retaining prior bytes`,async()=>{
  const {el}=page();await el('load').listeners.click();el('signature').value='old';let reads=0;
  const file={size:kind==='large'?65537:2,text:async()=>{reads++;if(kind==='unreadable')throw new Error('fixture');return kind==='malformed'?'!':kind==='expanded'?' '.repeat(65537):'{}';}};
  el('packet-file').files=kind==='multiple'?[file,file]:[file];
  assert.equal(typeof el('packet-file').listeners.change,'function');await el('packet-file').listeners.change();
  assert.notEqual(el('error').textContent,'');assert.equal(el('signature').value,'');assert.equal(reads,['large','multiple'].includes(kind)?0:1);
});

test('page load, collection, preparation and export use the production reader before exposing data', async () => {
  const c=observedChain(), {el,m,downloads}=page(c.rpc);
  const acquisitions=()=>c.calls.filter(([method,params])=>method==='eth_getBlockByNumber'&&params[0]==='latest').length;
  assert.equal(c.calls.length,0);
  await el('load').listeners.click();assert.equal(el('error').textContent,'');assert.equal(acquisitions(),1);
  el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));
  await el('collect').listeners.click();assert.equal(el('error').textContent,'');assert.equal(acquisitions(),3);
  await el('prepare').listeners.click();assert.equal(el('error').textContent,'');assert.equal(acquisitions(),5);
  const prepared=JSON.parse(el('prepared').textContent);assert.equal(prepared.liveVerified,false);
  await el('export').listeners.click();assert.equal(el('error').textContent,'');assert.equal(acquisitions(),8);
  assert.equal(downloads(),1);assert.equal(m.view().state,'PREPARED');assert.equal(el('execute').disabled,true);
  assert.throws(()=>m.send(),/Live execution unavailable/);
});

for(const stop of ['reset','drift'])test(`export projection final acquisition ${stop} prevents download`,async()=>{
 const state=base([owner(wallets[0])],1),c=observedChain(state),hold=barrier();let acquisitions=0;
 const rpc=async(method,params)=>{
  if(method==='eth_getBlockByNumber'&&params[0]==='latest'&&++acquisitions===8){
   if(stop==='drift')state.nonce='8';else await hold.promise;
  }return c.rpc(method,params);
 };
 const {el,m,downloads}=page(rpc);await el('load').listeners.click();
 el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));await el('collect').listeners.click();await el('prepare').listeners.click();
 const pending=el('export').listeners.click();
 if(stop==='reset'){while(acquisitions<8)await new Promise(resolve=>setImmediate(resolve));el('reset').listeners.click();hold.resolve();}
 await pending;assert.equal(downloads(),0);assert.equal(m.view().state,'STOPPED');assert.equal(el('prepared').textContent,'');
 if(stop==='drift')assert.match(el('error').textContent,/Changed observation/);else assert.equal(el('error').textContent,'');
});

for (const phase of ['load','collect','prepare','export']) test(`page ${phase} refuses changed chain reads without falling back to imported data`, async () => {
  const state=base([owner(wallets[0])],1), c=observedChain(state), {el,m,downloads}=page(c.rpc);
  if(phase!=='load')await el('load').listeners.click();
  if(['prepare','export'].includes(phase)){
    el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));await el('collect').listeners.click();
  }
  if(phase==='export')await el('prepare').listeners.click();
  if(phase==='collect')el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));
  state.nonce='8';await el(phase).listeners.click();
  assert.match(el('error').textContent,/Changed observation/);assert.equal(m.view().state,'STOPPED');assert.equal(m.view().count,0);
  assert.equal(el('preview').textContent,'','stopped operation must not display stale body');
  assert.equal(el('prepared').textContent,'');assert.equal(el('export').disabled,true);assert.equal(downloads(),0);
});

for(const change of ['reset','input']) test(`page ${change} clears a prior read error without retrying RPC`,async()=>{
  let calls=0;const {el,m}=page(async()=>{calls++;throw new Error('test-only read failure');});
  await el('load').listeners.click();assert.notEqual(el('error').textContent,'');assert.equal(calls,1);
  if(change==='reset')el('reset').listeners.click();else el('value').listeners.input();
  assert.equal(el('error').textContent,'');assert.equal(m.view().state,'STOPPED');assert.equal(calls,1);
});

for(const phase of ['load','collect','prepare','export']) test(`page ${phase} cancellation prevents late RPC continuation or data release`,async()=>{
  const c=observedChain(),hold=barrier();let paused=false,calls=0;
  const rpc=async(method,params)=>{calls++;if(paused)await hold.promise;return c.rpc(method,params);};
  const {el,m,downloads}=page(rpc);
  if(phase!=='load')await el('load').listeners.click();
  if(['prepare','export'].includes(phase)){
    el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));await el('collect').listeners.click();
  }
  if(phase==='export')await el('prepare').listeners.click();
  if(phase==='collect')el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));
  paused=true;const before=calls,pending=el(phase).listeners.click();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(calls,before+1);el('reset').listeners.click();hold.resolve();await pending;
  assert.equal(calls,before+1);assert.equal(m.view().state,'STOPPED');assert.equal(m.view().count,0);
  for(const id of ['preview','prepared','error'])assert.equal(el(id).textContent,'');
  assert.equal(downloads(),0);assert.equal(el('export').disabled,true);
});

for(const reason of ['unavailable','wrongChain','runtime','owner','block']) test(`page refuses ${reason} from the reader without offline fallback`,async()=>{
  const c=observedChain();const {el,m}=page(async(method,params)=>{
    if(reason==='unavailable')throw new Error('test-only unavailable');
    const value=await c.rpc(method,params);
    if(reason==='wrongChain'&&method==='eth_chainId')return '0x1';
    if(reason==='runtime'&&method==='eth_getCode'&&params[0]===safe)return '0x';
    if(reason==='owner'&&method==='eth_getCode'&&params[0]===owner(wallets[0]).address)return '0x6000';
    if(reason==='block'&&method==='eth_getBlockByNumber')return {...value,number:'0x65',hash:'0x'+'22'.repeat(32)};
    return value;
  });
  await el('load').listeners.click();assert.notEqual(el('error').textContent,'');
  assert.equal(m.view().state,'STOPPED');assert.equal(el('preview').textContent,'');
  assert.equal(el('collect').disabled,true);assert.equal(el('export').disabled,true);
});

test('explicit observation renders block-bound read but keeps collector STOPPED', async () => {
  const c=observedChain(), {el,m}=page(c.rpc);
  assert.equal(c.calls.length,0);await el('observe').listeners.click();
  assert.equal(el('error').textContent,'');
  const v=JSON.parse(el('observation').textContent);assert.equal(v.block.number,'100');assert.equal(v.liveVerified,false);
  assert.equal(m.view().state,'STOPPED');assert.equal(m.view().count,0);assert.equal(el('execute').disabled,true);
  assert.equal(el('collect').disabled,true);assert.equal(el('export').disabled,true);
  el('value').listeners.input();assert.equal(el('observation').textContent,'');
});
for(const change of ['reset','input']) test(`observation ${change} ignores late reply and stops additional RPC`, async()=>{
 const c=observedChain(),hold=barrier();let calls=0;
 const rpc=async(m,p)=>{calls++;if(calls===1)await hold.promise;return c.rpc(m,p);};
 const {el,m}=page(rpc);const pending=el('observe').listeners.click();await new Promise(resolve=>setImmediate(resolve));
 assert.equal(calls,1);await el('observe').listeners.click();assert.equal(calls,1);
 if(change==='reset')el('reset').listeners.click();else el('value').listeners.input();
 await el('load').listeners.click();const preview=el('preview').textContent,afterLoad=calls;
 assert.ok(afterLoad>1,'new load must perform its own reader acquisition');hold.resolve();await pending;
 assert.equal(calls,afterLoad);assert.equal(el('observation').textContent,'');assert.equal(el('error').textContent,'');
 assert.equal(el('preview').textContent,preview);assert.equal(m.view().state,'COLLECTING');assert.equal(el('execute').disabled,true);
});

test('read transport is same-origin, bounded and validates envelope before returning result', async()=>{
 assert.equal(typeof executeModule.safeReadRPC,'function');
 let called=0;
 const fetcher=async(url,options)=>{called++;assert.equal(url,'https://polygon-bor-rpc.publicnode.com/');assert.equal(options.redirect,'error');assert.equal(options.cache,'no-store');
  const q=JSON.parse(options.body);assert.equal(q.method,'eth_chainId');return new Response(JSON.stringify({jsonrpc:'2.0',id:q.id,result:'0x89'}));};
 assert.equal(await executeModule.safeReadRPC('eth_chainId',[],fetcher),'0x89');assert.equal(called,1);
 await assert.rejects(executeModule.safeReadRPC('eth_sendTransaction',[],fetcher));assert.equal(called,1);
 for(const make of [q=>({jsonrpc:'2.0',id:q.id+1,result:'0x89'}),q=>({jsonrpc:'2.0',id:q.id,error:{code:-1}}),q=>({jsonrpc:'2.0',id:q.id,result:'0x89',error:{}}),q=>({id:q.id,result:'0x89'}),q=>[q]]) {
  await assert.rejects(executeModule.safeReadRPC('eth_chainId',[],async(_u,o)=>new Response(JSON.stringify(make(JSON.parse(o.body))))));
 }
 const response = (options, bytes, status=200) => {
  const q=JSON.parse(options.body), text=JSON.stringify({jsonrpc:'2.0',id:q.id,result:'0x89'});
  return new Response(text.padEnd(bytes,' '),{status}); // Valid JSON/envelope; only size or HTTP status differs.
 };
 assert.equal(await executeModule.safeReadRPC('eth_chainId',[],async(_u,o)=>response(o,2_000_000)),'0x89');
 await assert.rejects(executeModule.safeReadRPC('eth_chainId',[],async(_u,o)=>response(o,2_000_001)),/Read response size limit/);
 await assert.rejects(executeModule.safeReadRPC('eth_chainId',[],async(_u,o)=>response(o,0,403)),/Read-only relay unavailable/);
});
test('balance transport admits exact address and fixed block only',async()=>{
 const SAFE='0x'+'33'.repeat(20);
 let calls=0;const fetcher=async(_u,o)=>{calls++;const q=JSON.parse(o.body);return new Response(JSON.stringify({jsonrpc:'2.0',id:q.id,result:'0x1'}));};
 assert.equal(await executeModule.safeReadRPC('eth_getBalance',[SAFE,'0x64'],fetcher),'0x1');
 for(const p of [[SAFE,'latest'],[SAFE,'pending'],['bad','0x64'],[SAFE,'0x064'],[SAFE,'0x64','extra']])await assert.rejects(executeModule.safeReadRPC('eth_getBalance',p,fetcher));
 assert.equal(calls,1);
});

test('receipt transport allows only one exact nonzero hash for transaction/receipt lookup',async()=>{
 let calls=0;const fetcher=async(_u,o)=>{calls++;const q=JSON.parse(o.body);return new Response(JSON.stringify({jsonrpc:'2.0',id:q.id,result:null}));};
 for(const m of ['eth_getTransactionByHash','eth_getTransactionReceipt']){
  assert.equal(await executeModule.safeReadRPC(m,['0x'+'11'.repeat(32)],fetcher),null);
  for(const p of [[],['latest'],['0x'+'00'.repeat(32)],['0x'+'11'.repeat(32),'latest']])await assert.rejects(executeModule.safeReadRPC(m,p,fetcher));
 }assert.equal(calls,2);
});

test('read transport aborts headers and body waits at deadline',async()=>{
 assert.equal(typeof executeModule.safeReadRPC,'function');mock.timers.enable({apis:['setTimeout']});
 try{for(const body of [false,true]){
  let signal,readerCancelled=false;
  const fetcher=(_u,o)=>{signal=o.signal;if(!body)return new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('aborted'))));
   return Promise.resolve(new Response(new ReadableStream({start(){},cancel(){readerCancelled=true;}})));};
  const pending=executeModule.safeReadRPC('eth_chainId',[],fetcher).then(()=> 'accepted',()=> 'rejected');
  await new Promise(resolve=>setImmediate(resolve));mock.timers.tick(10000);assert.equal(await pending,'rejected');assert.equal(signal.aborted,true);
  if(body)assert.equal(readerCancelled,true);
 }}finally{mock.timers.reset();}
});

import { buildRequest, expectedFrom } from '../safe-request-model.js';
import { freshSigner, contextFor, resultFor } from './support/safe-fixtures.mjs';
import { createChain } from './support/key-chain.mjs';

test('page Hybrid packet reaches PREPARED through Safe and Hybrid readers; removed key blocks export',async()=>{
  const k=await freshSigner(), hybrid={address:k.handoff.expectedAddress.toLowerCase(),kind:'hybrid',publicKey:k.publicKey,keyId:k.keyID};
  const raw=base([hybrid],1), c=observedChain(raw), chain=createChain({signer:hybrid.address,keys:[hybrid],now:clock});
  const rpc=(method,params)=>{
    const target=method==='eth_call'?params[0].to:params[0];
    if(['eth_getCode','eth_getStorageAt','eth_call'].includes(method)&&![safe,raw.singleton].includes(target))return chain.rpc(method,params);
    return c.rpc(method,params);
  };
  const {el,m,downloads}=page(rpc);el('snapshot').value=JSON.stringify(raw);
  await el('load').listeners.click();assert.equal(el('error').textContent,'');
  const expected=expectedFrom(k.handoff,{safe,recipient,value:'1',nonce:'7'}),context=contextFor(expected);
  const request=buildRequest(context,expected,crypto.randomUUID(),clock()-10);
  el('signature').value=JSON.stringify({owner:hybrid.address,expected,context,request,result:resultFor(request,context,await k.sign(request.safeTxHash))});
  await el('collect').listeners.click();assert.equal(el('error').textContent,'');assert.equal(m.view().count,1);
  await el('prepare').listeners.click();assert.equal(el('error').textContent,'');assert.equal(m.view().state,'PREPARED');
  const prepared=JSON.parse(el('prepared').textContent);assert.equal(prepared.selected[0].kind,'hybrid');assert.equal(prepared.liveVerified,false);
  chain.state.keys=[];await el('export').listeners.click();assert.match(el('error').textContent,/chain read mismatch/);
  assert.equal(m.view().state,'STOPPED');assert.equal(m.view().count,0);assert.equal(downloads(),0);assert.equal(el('prepared').textContent,'');
});

const U = ethers.utils, Z = ethers.constants.AddressZero;
const safe = '0x3333333333333333333333333333333333333333', recipient = '0x4444444444444444444444444444444444444444';
// Public software test keys, never used on chain or in a wallet.
const wallets = [1, 2, 3].map(n => new ethers.Wallet('0x' + String(n).padStart(64, '0')));
const owner = w => ({ address: w.address.toLowerCase(), kind: 'eoa' });
const base = (owners = wallets.slice(0, 2).map(owner), threshold = 2) => ({ chainId: '137', safe,
  version: '1.5.0', singleton: '0xff51a5898e281db6dfc7855790607438df2ca44b', runtime: 'unverified-offline',
  guard: Z, fallback: Z, modules: [], owners, threshold, nonce: '7', account: wallets[2].address.toLowerCase(),
  block: { number: '100', hash: '0x' + '11'.repeat(32) }, generation: 1, attempt: 'none' });
const input = { kind: 'native', recipient, value: '1' };
const eoa = (w, hash) => ({ owner: w.address.toLowerCase(), signature: U.joinSignature(w._signingKey().signDigest(hash)) });
const clock = () => 1800000000;
function setup(raw = base(), change = x => x) {
  let current = raw; const m = new Execution({ read: async () => change(structuredClone(current)), now: clock });
  return { m, set: x => { current = x; } };
}

test('explicit observation clears approvals and never adopts chain state for execution', async () => {
  const elements = new Map();
  const el = id => elements.get(id) || (elements.set(id, { value: '', textContent: '', disabled: false,
    listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; } }), elements.get(id));
  const doc = { getElementById: el, querySelectorAll: () => [el('snapshot')] };
  el('snapshot').value = JSON.stringify(base([owner(wallets[0])], 1));
  el('kind').value = 'native'; el('recipient').value = recipient; el('value').value = '1';
  let calls = 0, unavailable = false;
  const c = observedChain();
  const rpc = async (method, params) => { calls++; if (unavailable) throw new Error('fixture unavailable'); return c.rpc(method, params); };
  const m = mount(doc, clock, rpc);
  assert.equal(calls, 0, 'mount must not contact relay');
  await el('load').listeners.click();
  el('signature').value = JSON.stringify(eoa(wallets[0], m.view().hash));
  await el('collect').listeners.click(); assert.equal(m.view().count, 1);
  assert.equal(typeof el('observe').listeners.click, 'function');
  const before = calls; unavailable = true;
  await el('observe').listeners.click();
  assert.equal(calls, before + 1); assert.equal(m.view().count, 0); assert.equal(m.view().state, 'STOPPED');
  assert.equal(el('observation').textContent, ''); assert.match(el('error').textContent, /unavailable/);
  assert.equal(el('execute').disabled, true); assert.equal(el('export').disabled, true);
  assert.throws(() => m.send(), /unavailable/);
});

test('projected native request passes existing downstream transaction predicate; prepared metadata does not',async()=>{
 const {m}=setup(base([owner(wallets[0])],1));await m.load(input);await m.collect(eoa(wallets[0],m.view().hash));
 const p=await m.prepare(),request=await m.walletRequest();
 const expected={profile:'native-1wei',from:p.from,body:m.unsigned().operation.body,signatureBytes:p.signatureBytes,H:p.safeTxHash};
 assert.equal(judge.assertTransaction(request,expected),true);assert.throws(()=>judge.assertTransaction(p,expected),/exact schema/);
});

test('SDK nonce exact boundary, canonical decimal only, no rounding', () => {
  assert.equal(sdkNonce('9007199254740991'), Number.MAX_SAFE_INTEGER);
  for (const n of ['9007199254740992', '9007199254740993', '-1', '01', 1, String(1n << 256n)]) assert.throws(() => sdkNonce(n));
});

test('closed offline profile rejects unknown runtime, malformed fields and unsupported authority', () => {
  assert.equal(snapshot(base()).threshold, 2);
  for (const patch of [{ chainId: '1' }, { version: '1.4.1' }, { singleton: recipient }, { runtime: 'verified' },
    { threshold: 0 }, { threshold: 3 }, { threshold: 1.5 }, { owners: [owner(wallets[0]), owner(wallets[0])] },
    { owners: Array(9).fill(owner(wallets[0])) }, { modules: [recipient] }, { guard: recipient }, { fallback: recipient },
    { account: Z }, { nonce: '9007199254740992' }, { attempt: 'pending' }, { attempt: 'UNKNOWN' }, { extra: true }]) {
    assert.throws(() => snapshot({ ...base(), ...patch }), JSON.stringify(patch));
  }
});

test('native grammar and full body bind hash, refuse arbitrary call/gas/delegatecall', () => {
  const s = snapshot(base()), a = operation(s, input);
  for (const patch of [{ value: '2' }, { recipient: safe }]) assert.notEqual(operation(s, { ...input, ...patch }).hash, a.hash);
  for (const patch of [{ data: '0x12' }, { operation: 1 }, { safeTxGas: '1' }, { value: '01' }, { kind: 'batch' }]) assert.throws(() => operation(s, { ...input, ...patch }));
  assert.notEqual(operation(snapshot({ ...base(), nonce: '8' }), input).hash, a.hash);
});

test('real EOA signatures collect without auto prepare; SDK calldata independently matches complete body', async () => {
  const { m } = setup(); await m.load(input);
  await m.collect(eoa(wallets[1], m.view().hash));
  await assert.rejects(m.prepare(), /threshold/);
  await m.collect(eoa(wallets[0], m.view().hash));
  assert.equal(m.view().state, 'COLLECTING');
  const p = await m.prepare();
  assert.equal(m.view().state, 'PREPARED'); assert.equal(p.to, safe); assert.equal(p.value, '0x0');
  assert.equal(p.chainId, '0x89'); assert.equal(p.liveVerified, false);
  assert.equal(p.from, wallets[2].address.toLowerCase());
  const abi = new U.Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)']);
  const d = abi.decodeFunctionData('execTransaction', p.data);
  assert.equal(d[0].toLowerCase(), recipient); assert.equal(d[1].toString(), '1'); assert.equal(d[2], '0x');
  assert.equal(d[3], 0); for (const i of [4, 5, 6]) assert.equal(d[i].toString(), '0');
  assert.equal(d[7], Z); assert.equal(d[8], Z); assert.equal(U.arrayify(d[9]).length, 130);
  assert.throws(() => m.send(), /unavailable/);
  assert.equal(JSON.stringify(m.unsigned()).includes('signature'), false);
  const bytes = U.arrayify(p.signatureBytes); bytes[0] ^= 1;
  assert.throws(() => decodeSignatures(U.hexlify(bytes), p.selected), /EOA static/);
  assert.throws(() => decodeSignatures(U.hexlify(U.concat([bytes.slice(65), bytes.slice(0, 65)])), p.selected), /EOA static/);
});

test('duplicate, nonowner, wrong H, prevalidated, eth_sign and oversized packet rejected', async () => {
  const { m } = setup(); await m.load(input); const h = m.view().hash;
  for (const packet of [eoa(wallets[2], h), eoa(wallets[0], '0x' + '22'.repeat(32)),
    { ...eoa(wallets[0], h), signature: '0x' + '00'.repeat(65) }, { ...eoa(wallets[0], h), extra: 1 },
    { ...eoa(wallets[0], h), signature: '0x' + 'aa'.repeat(40000) }]) await assert.rejects(m.collect(packet));
  const sig = eoa(wallets[0], h); await m.collect(sig); await assert.rejects(m.collect(sig), /duplicate/);
});

test('two independently signed Hybrid Owners use 130-byte static area, distinct keys, exact dynamic offsets', async () => {
  const keys = [await freshSigner(), await freshSigner('0x' + '22'.repeat(32))];
  const owners = keys.map(k => ({ address: k.handoff.expectedAddress.toLowerCase(), kind: 'hybrid', publicKey: k.publicKey, keyId: k.keyID }));
  const { m } = setup(base(owners)); await m.load(input);
  const packets = [];
  for (const k of keys) {
    const expected = expectedFrom(k.handoff, { safe, recipient, value: '1', nonce: '7' });
    const context = contextFor(expected), request = buildRequest(context, expected, crypto.randomUUID(), clock() - 10);
    const result = resultFor(request, context, await k.sign(request.safeTxHash));
    const packet = { owner: k.handoff.expectedAddress.toLowerCase(), expected, context, request, result };
    packets.push(packet); await m.collect(packet);
  }
  const p = await m.prepare(); assert.equal(p.signatureBytes.length, 2 + (130 + 128 * 2) * 2);
  assert.equal(BigInt('0x' + p.signatureBytes.slice(66, 130)), 130n);
  assert.equal(BigInt('0x' + p.signatureBytes.slice(196, 260)), 258n);
  assert.throws(() => decodeSignatures('0x' + p.signatureBytes.slice(2, 66) + '41'.padStart(64, '0') + p.signatureBytes.slice(130), p.selected));
  assert.throws(() => decodeSignatures(p.signatureBytes + '00', p.selected));
  const mutate = (offset, bytes) => U.hexlify(U.concat([U.arrayify(p.signatureBytes).slice(0, offset), bytes,
    U.arrayify(p.signatureBytes).slice(offset + bytes.length)]));
  assert.throws(() => decodeSignatures(mutate(130, U.arrayify(U.hexZeroPad('0x5f', 32))), p.selected), /inner/);
  assert.throws(() => decodeSignatures(mutate(162, new Uint8Array(96)), p.selected), /inner/);
  const bytes = U.arrayify(p.signatureBytes);
  const reversed = U.hexlify(U.concat([bytes.slice(65, 130), bytes.slice(0, 65), bytes.slice(130)]));
  assert.throws(() => decodeSignatures(reversed, p.selected), /offset\/order/);
  const fresh = setup(base(owners)).m; await fresh.load(input);
  const tampered = structuredClone(packets[0]); tampered.result.rawSignature = '0x' + '01'.repeat(64);
  await assert.rejects(fresh.collect(tampered));
});

test('mixed Hybrid/EOA and three Owners select exactly threshold signatures', async () => {
  const k = await freshSigner();
  const hybrid = { address: k.handoff.expectedAddress.toLowerCase(), kind: 'hybrid', publicKey: k.publicKey, keyId: k.keyID };
  const { m } = setup(base([hybrid, ...wallets.slice(0, 2).map(owner)])); await m.load(input);
  const expected = expectedFrom(k.handoff, { safe, recipient, value: '1', nonce: '7' });
  const context = contextFor(expected), request = buildRequest(context, expected, crypto.randomUUID(), clock() - 10);
  await m.collect({ owner: hybrid.address, expected, context, request, result: resultFor(request, context, await k.sign(request.safeTxHash)) });
  await m.collect(eoa(wallets[1], m.view().hash)); await m.collect(eoa(wallets[0], m.view().hash));
  const p = await m.prepare([hybrid.address, owner(wallets[1]).address]);
  assert.equal(p.selected.length, 2); assert.equal(p.selected.filter(x => x.kind === 'hybrid').length, 1);
});

test('owner addition uses separate self CALL, explicit threshold, BEFORE approvals and no Hybrid signing', async () => {
  const { m } = setup(); const admin = { kind: 'addOwner', newOwner: recipient, newThreshold: 3, confirmed: true };
  await m.load(admin);
  const op = m.unsigned().operation; assert.equal(op.body.tx.to, safe); assert.equal(op.body.tx.value, '0');
  const abi = new U.Interface(['function addOwnerWithThreshold(address,uint256)']);
  assert.equal(abi.decodeFunctionData('addOwnerWithThreshold', op.body.tx.data)[1].toString(), '3');
  await m.collect(eoa(wallets[0], m.view().hash)); await assert.rejects(m.prepare());
  await m.collect(eoa(wallets[1], m.view().hash)); assert.equal((await m.prepare()).selected.length, 2);
  const request=await m.walletRequest();assert.deepEqual(Object.keys(request).sort(),['chainId','data','from','to','value']);assert.equal(request.to,safe);assert.equal(request.value,'0x0');
  for (const patch of [{ confirmed: false }, { newThreshold: 4 }, { newOwner: wallets[0].address }]) assert.throws(() => operation(snapshot(base()), { ...admin, ...patch }));
});

test('every authority/configuration change before collect or prepare stops and clears signatures', async () => {
  for (const patch of [{ nonce: '8' }, { threshold: 1 }, { account: recipient }, { chainId: '1' }, { generation: 2 },
    { owners: [owner(wallets[0]), owner(wallets[2])] }, { block: { number: '100', hash: '0x' + '22'.repeat(32) } }]) {
    const { m, set } = setup(); await m.load(input); await m.collect(eoa(wallets[0], m.view().hash));
    set({ ...base(), ...patch }); await assert.rejects(m.collect(eoa(wallets[1], m.view().hash)));
    assert.equal(m.view().state, 'STOPPED'); assert.equal(m.view().count, 0);
  }
});

test('invalidate during asynchronous refresh prevents late collection; errors clear state', async () => {
  let release; let raw = base(); const m = new Execution({ read: async () => raw, now: clock });
  await m.load(input); const packet = eoa(wallets[0], m.view().hash);
  raw = new Promise(resolve => { release = resolve; });
  const pending = m.collect(packet); m.invalidate(); release(base());
  await assert.rejects(pending); assert.equal(m.view().count, 0); assert.equal(m.view().state, 'STOPPED');
});

test('expiry, read failure, changed operation and prepared input changes cannot preserve export', async () => {
  let now = clock(), raw = base(); const m = new Execution({ read: async () => raw, now: () => now });
  await m.load(input); await m.collect(eoa(wallets[0], m.view().hash)); await m.collect(eoa(wallets[1], m.view().hash));
  now += 120; await assert.rejects(m.prepare(), /expired/); assert.equal(m.view().state, 'STOPPED');
  await m.load(input); raw = null; await assert.rejects(m.collect(eoa(wallets[0], m.view().hash)));
  assert.equal(m.view().count, 0);
});

test('invalid clock after valid EOA collection stops preparation and clears signatures', async () => {
  for (const invalid of [NaN, Infinity, -Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    let now = clock();
    const m = new Execution({ read: async () => base([owner(wallets[0])], 1), now: () => now });
    await m.load(input); await m.collect(eoa(wallets[0], m.view().hash));
    now = invalid;
    await assert.rejects(m.prepare(), /Invalid clock/);
    assert.equal(m.view().state, 'STOPPED'); assert.equal(m.view().count, 0);
    now = clock(); await assert.rejects(m.prepare(), /Stale generation/);
  }
});

test('each clock sample at load, collection and preparation fails closed', async () => {
  for (const invalid of [NaN, Infinity, -Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    const unloaded = new Execution({ read: async () => base(), now: () => invalid });
    await assert.rejects(unloaded.load(input), /Invalid clock/);
    assert.equal(unloaded.view().state, 'STOPPED');
    for (const phase of ['collect', 'prepare']) {
      for (let sample = 1; sample <= (phase === 'collect' ? 3 : 4); sample++) {
        let calls = 0, failAt = Infinity;
        const m = new Execution({ read: async () => base([owner(wallets[0])], 1),
          now: () => ++calls === failAt ? invalid : clock() });
        await m.load(input); const packet = eoa(wallets[0], m.view().hash);
        if (phase === 'prepare') await m.collect(packet);
        failAt = calls + sample;
        await assert.rejects(phase === 'collect' ? m.collect(packet) : m.prepare(), /Invalid clock/);
        assert.equal(m.view().state, 'STOPPED'); assert.equal(m.view().count, 0);
      }
    }
  }
});

test('clock rollback below load or a later accepted time clears approvals', async () => {
  for (const advance of [0, 10]) {
    let now = clock();
    const m = new Execution({ read: async () => base([owner(wallets[0])], 1), now: () => now });
    await m.load(input); now += advance; await m.collect(eoa(wallets[0], m.view().hash));
    now--;
    await assert.rejects(m.prepare(), /Invalid clock/);
    assert.equal(m.view().state, 'STOPPED'); assert.equal(m.view().count, 0);
  }
});

test('initial deadline rejects overflow and keeps the exact MAX_SAFE_INTEGER boundary', async () => {
  for (const start of [Number.MAX_SAFE_INTEGER - 119, Number.MAX_SAFE_INTEGER]) {
    const m = new Execution({ read: async () => base([owner(wallets[0])], 1), now: () => start });
    await assert.rejects(m.load(input), /Invalid clock/);
    assert.equal(m.view().state, 'STOPPED'); assert.equal(m.view().count, 0);
  }
  let now = Number.MAX_SAFE_INTEGER - 120;
  const m = new Execution({ read: async () => base([owner(wallets[0])], 1), now: () => now });
  await m.load(input); await m.collect(eoa(wallets[0], m.view().hash));
  now = Number.MAX_SAFE_INTEGER - 1; await m.prepare(); await m.prepare();
  now++; await assert.rejects(m.prepare(), /expired/);
  assert.equal(m.view().state, 'STOPPED'); assert.equal(m.view().count, 0);
});

test('page has accessible Japanese explicit controls; read-only observation separate from offline collection', () => {
  const html = readFileSync(new URL('../safe-execute.html', import.meta.url), 'utf8');
  assert.match(html, /lang="ja"/); assert.match(html, /aria-live="polite"/);
  for (const id of ['snapshot', 'recipient', 'value', 'new-owner', 'new-threshold', 'signature']) assert.match(html, new RegExp(`for="${id}"`));
  assert.match(html, /id="execute"[^>]*disabled/); assert.match(html, /safe-execute.js/);
  assert.match(html, /id="observe"/); assert.match(html, /id="observation"/);
  assert.match(html, /結果は実行権限やオフライン入力へ自動採用しません/);
  assert.equal(typeof mount, 'function');
});

test('invalid clock, rollback or original deadline blocks prepared page export', async () => {
  for (const invalid of [NaN, Infinity, -Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, clock() - 1, clock() + 120]) {
    let now = clock(), downloads = 0;
    const elements = new Map();
    const el = id => elements.get(id) || (elements.set(id, { value: '', textContent: '', disabled: false, checked: false,
      listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; } }), elements.get(id));
    const doc = { getElementById: el, querySelectorAll: () => [], createElement() { downloads++; return { click() {} }; } };
    el('snapshot').value = JSON.stringify(base([owner(wallets[0])], 1));
    el('kind').value = 'native'; el('recipient').value = recipient; el('value').value = '1';
    const m = mount(doc, () => now, observedChain().rpc); await el('load').listeners.click();
    el('signature').value = JSON.stringify(eoa(wallets[0], m.view().hash)); await el('collect').listeners.click();
    await el('prepare').listeners.click(); assert.equal(m.view().state, 'PREPARED');
    now = invalid; await el('export').listeners.click();
    assert.match(el('error').textContent, /Invalid clock|expired/);
    assert.equal(m.view().state, 'STOPPED'); assert.equal(m.view().count, 0);
    assert.equal(el('prepared').textContent, ''); assert.equal(el('export').disabled, true); assert.equal(downloads, 0);
  }
});

// A minimal DOM exercises actual page controller handlers, without a browser/network.
test('page controller explicit load, collect, prepare, export; input edits erase prepared data', async () => {
  const elements = new Map();
  const el = id => elements.get(id) || (elements.set(id, { value: '', textContent: '', disabled: false, checked: false,
    listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; } }), elements.get(id));
  const doc = { getElementById: el, querySelectorAll: () => ['snapshot', 'recipient', 'value', 'kind', 'new-owner', 'new-threshold', 'confirm'].map(el) };
  el('snapshot').value = JSON.stringify(base()); el('kind').value = 'native'; el('recipient').value = recipient; el('value').value = '1';
  mount(doc, clock, observedChain(base()).rpc); await el('load').listeners.click(); assert.match(el('status').textContent, /COLLECTING/);
  const unsigned = JSON.parse(el('preview').textContent), h = unsigned.operation.hash;
  for (const w of wallets.slice(0, 2)) { el('signature').value = JSON.stringify(eoa(w, h)); await el('collect').listeners.click(); }
  assert.equal(el('prepared').textContent, ''); await el('prepare').listeners.click();
  assert.match(el('prepared').textContent, /0x6a761202/); assert.equal(el('execute').disabled, true);
  el('value').value = '2'; el('value').listeners.input(); assert.equal(el('prepared').textContent, ''); assert.equal(el('export').disabled, true);
});

// Two queued microtasks place invalidation after #fresh resolves, before its caller resumes.
for (const phase of ['collect', 'prepare']) test(`${phase}: invalidation after final fresh completion cannot resurrect authority`, async () => {
  let reads = 0, invalidateAt = Infinity, invalidated = false;
  const m = new Execution({ read: () => {
    if (++reads === invalidateAt) queueMicrotask(() => queueMicrotask(() => { m.invalidate(); invalidated = true; }));
    return Promise.resolve(base([owner(wallets[0])], 1));
  }, now: clock });
  await m.load(input); const packet = eoa(wallets[0], m.view().hash);
  if (phase === 'prepare') await m.collect(packet);
  invalidateAt = reads + 2;
  await assert.rejects(phase === 'collect' ? m.collect(packet) : m.prepare(), /Stale generation/);
  assert.equal(invalidated, true); assert.equal(m.view().state, 'STOPPED'); assert.equal(m.view().count, 0);
});

test('product relay validates native simulation and actual HTTP denial before upstream',()=>{
 const result=spawnSync('python3',['-B',fileURLToPath(new URL('./check-safe-execution-server.py',import.meta.url))],{encoding:'utf8',timeout:30000});
 assert.equal(result.status,0,result.stdout+result.stderr);assert.match(result.stderr,/Ran 7 tests/);
});
for(const failure of ['false','revert'])test(`page native preflight ${failure} clears approval and never displays success`,async()=>{
 const c=observedChain();const rpc=async(m,p)=>{if(m==='eth_call'&&p[0].data.startsWith('0x6a761202')){if(failure==='revert')throw Error('revert');return '0x'+'0'.repeat(64);}return c.rpc(m,p);};
 const {el,m}=page(rpc);await el('load').listeners.click();el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));await el('collect').listeners.click();await el('prepare').listeners.click();await el('preflight').listeners.click();
 assert.notEqual(el('error').textContent,'');assert.equal(el('preflight-result').textContent,'');assert.equal(el('prepared').textContent,'');assert.equal(m.view().state,'STOPPED');assert.equal(m.view().count,0);assert.equal(el('execute').disabled,true);
});
for(const kind of ['native','addOwner'])test(`SDK-prepared calldata is admitted unchanged by product ${kind} simulation validator`,async()=>{
 const {m}=setup(base([owner(wallets[0])],1));await m.load(kind==='native'?input:{kind,newOwner:recipient,newThreshold:2,confirmed:true});await m.collect(eoa(wallets[0],m.view().hash));const prepared=await m.prepare();
 const wire={jsonrpc:'2.0',id:9,method:'eth_call',params:[Object.fromEntries(['from','to','value','data'].map(k=>[k,prepared[k]])),'0x64']};
 const script='import runpy,sys,json;v=runpy.run_path(sys.argv[1]);q=json.load(sys.stdin);assert v["validate_rpc"](json.dumps(q))==q';
 const result=spawnSync('python3',['-B','-c',script,fileURLToPath(new URL('../serve.py',import.meta.url))],{input:JSON.stringify(wire),encoding:'utf8',timeout:10000});assert.equal(result.status,0,result.stdout+result.stderr);
});
test('page native preflight is explicit, shows only simulation and reset discards a late result',async()=>{
 const c=observedChain();let simulations=0,hold;
 const rpc=async(m,p)=>{if(m==='eth_call'&&p[0].data.startsWith('0x6a761202')){simulations++;if(hold)await hold.promise;return '0x'+'0'.repeat(63)+'1';}return c.rpc(m,p);};
 const {el,m}=page(rpc);assert.equal(el('preflight').disabled,true);
 await el('load').listeners.click();el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));await el('collect').listeners.click();await el('prepare').listeners.click();
 assert.equal(simulations,0);assert.equal(el('preflight').disabled,false);assert.equal(typeof el('preflight').listeners.click,'function');
 await el('preflight').listeners.click();assert.equal(simulations,1);assert.equal(el('error').textContent,'');const result=JSON.parse(el('preflight-result').textContent);assert.equal(result.simulationVerified,true);assert.equal(result.liveVerified,false);assert.equal(el('execute').disabled,true);
 hold=barrier();const pending=el('preflight').listeners.click();while(simulations<2)await new Promise(r=>setImmediate(r));el('reset').listeners.click();hold.resolve();await pending;
 assert.equal(el('preflight-result').textContent,'');assert.equal(el('prepared').textContent,'');assert.equal(m.view().state,'STOPPED');assert.equal(el('preflight').disabled,true);assert.equal(el('execute').disabled,true);
});
function page(rpc = observedChain().rpc, wallet = () => undefined) {
  let downloads = 0;
  const elements = new Map();
  const el = id => elements.get(id) || (elements.set(id, { value: '', textContent: '', disabled: false, checked: false,
    listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; } }), elements.get(id));
  const doc = { getElementById: el, querySelectorAll: () => [el('value')], createElement() { downloads++; return { click() {} }; } };
  el('snapshot').value = JSON.stringify(base([owner(wallets[0])], 1));
  el('kind').value = 'native'; el('recipient').value = recipient; el('value').value = '1';
  return { el, m: mount(doc, clock, rpc, wallet), downloads: () => downloads };
}
test('ordinary page ignores ambient wallet even with a simulated preparation and fork profile', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'ethereum');
  let calls = 0;
  Object.defineProperty(globalThis, 'ethereum', { configurable: true, value: { request() { calls++; throw Error('ambient wallet forbidden'); } } });
  try {
    const c = observedChain();
    const rpc = async (method, params) => method === 'eth_call' && params[0].data.startsWith('0x6a761202')
      ? '0x' + '0'.repeat(63) + '1' : c.rpc(method, params);
    const elements = new Map();
    const el = id => elements.get(id) || (elements.set(id, { value: '', textContent: '', listeners: {}, addEventListener(t, fn) { this.listeners[t] = fn; } }), elements.get(id));
    const doc = { getElementById: el, querySelectorAll: () => [] };
    el('snapshot').value = JSON.stringify(base([owner(wallets[0])], 1));
    el('kind').value = 'native'; el('recipient').value = recipient; el('value').value = '1';
    const m = mount(doc, clock, rpc);
    await el('load').listeners.click();
    el('signature').value = JSON.stringify(eoa(wallets[0], m.view().hash));
    await el('collect').listeners.click(); await el('prepare').listeners.click(); await el('preflight').listeners.click();
    el('fork-profile').value = '{}'; el('fork-profile').listeners.input();
    assert.equal(el('execute').disabled, true);
    await el('execute').listeners.click();
    assert.equal(calls, 0); assert.match(el('error').textContent, /No EIP-1193 wallet/);
  } finally {
    if (descriptor) Object.defineProperty(globalThis, 'ethereum', descriptor); else delete globalThis.ethereum;
  }
});
function barrier() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function readyPage(phase) {
  const p = page(), { el, m } = p;
  if (phase !== 'load') await el('load').listeners.click();
  if (['prepare', 'export'].includes(phase)) {
    el('signature').value = JSON.stringify(eoa(wallets[0], m.view().hash));
    await el('collect').listeners.click();
  }
  if (phase === 'export') await el('prepare').listeners.click();
  if (phase === 'collect') el('signature').value = JSON.stringify(eoa(wallets[0], m.view().hash));
  return p;
}
for (const phase of ['load', 'collect', 'prepare', 'export']) test(`page busy ${phase}: overlapping handlers do not start work or supersede the result`, async () => {
  const { el, m, downloads } = await readyPage(phase), hold = barrier();
  const method = phase === 'export' ? 'prepare' : phase;
  let calls = 0;
  for (const name of ['load', 'collect', 'prepare']) {
    const original = m[name].bind(m);
    m[name] = async (...args) => {
      calls++;
      const result = await original(...args);
      if (name === method) await hold.promise;
      return result;
    };
  }
  const pending = el(phase).listeners.click();
  const overlaps = ['load', 'collect', 'prepare', 'export'].map(id => el(id).listeners.click());
  try {
    assert.equal(calls, 1, 'programmatic clicks must not enter model methods while busy');
    for (const id of ['load', 'collect', 'prepare', 'export']) assert.equal(el(id).disabled, true, id);
    assert.equal(el('reset').disabled, false); assert.equal(el('value').disabled, false);
  } finally { hold.resolve(); await Promise.all([pending, ...overlaps]); }
  assert.equal(el('error').textContent, ''); assert.equal(el('load').disabled, false);
  assert.equal(el('collect').disabled, ['prepare', 'export'].includes(phase));
  assert.equal(el('prepare').disabled, phase !== 'collect');
  assert.equal(el('export').disabled, !['prepare', 'export'].includes(phase));
  assert.equal(el('execute').disabled, true); assert.equal(downloads(), phase === 'export' ? 1 : 0);
  if (['prepare', 'export'].includes(phase)) {
    assert.equal(m.view().state, 'PREPARED'); assert.notEqual(el('prepared').textContent, '');
  }
});
for (const phase of ['load', 'collect', 'prepare', 'export']) test(`page ${phase}: resolved stale completion cannot restore UI or download`, async () => {
  const { el, m, downloads } = page();
  if (phase !== 'load') await el('load').listeners.click();
  if (['prepare', 'export'].includes(phase)) await m.collect(eoa(wallets[0], m.view().hash));
  if (phase === 'export') await el('prepare').listeners.click();
  if (phase === 'collect') el('signature').value = JSON.stringify(eoa(wallets[0], m.view().hash));
  const method = phase === 'export' ? 'prepare' : phase, original = m[method].bind(m);
  m[method] = (...args) => original(...args).then(result => {
    queueMicrotask(() => { el('value').listeners.input(); el('signature').value = 'new input'; });
    return result;
  });
  await el(phase).listeners.click();
  assert.equal(m.view().state, 'STOPPED'); assert.equal(el('preview').textContent, '');
  assert.equal(el('prepared').textContent, ''); assert.equal(el('signature').value, 'new input');
  assert.equal(el('export').disabled, true); assert.equal(downloads(), 0);
});
test('page stale error cannot clear newer prepared result', async () => {
  const { el, m } = page(); await el('load').listeners.click();
  let fail; const original = m.prepare.bind(m);
  m.prepare = () => new Promise((_, reject) => { fail = reject; });
  const old = el('prepare').listeners.click(); m.prepare = original;
  el('reset').listeners.click();
  await el('load').listeners.click(); await m.collect(eoa(wallets[0], m.view().hash));
  await el('prepare').listeners.click(); const newer = el('prepared').textContent;
  assert.notEqual(newer, ''); fail(new Error('old failure')); await old;
  assert.equal(el('prepared').textContent, newer); assert.equal(el('error').textContent, '');
  assert.equal(el('export').disabled, false);
});

for (const phase of ['load', 'collect', 'prepare', 'export']) {
  for (const invalidation of ['reset', 'input']) {
    for (const outcome of ['success', 'failure']) test(`page busy ${phase}: ${invalidation} permits new load; stale ${outcome} cannot release its gate`, async () => {
      const { el, m, downloads } = await readyPage(phase);
      const hold = barrier(), entered = barrier(), newer = barrier();
      const method = phase === 'export' ? 'prepare' : phase, original = m[method].bind(m);
      m[method] = async (...args) => {
        const result = await original(...args); entered.resolve(); await hold.promise;
        if (outcome === 'failure') throw new Error('stale failure');
        return result;
      };
      const old = el(phase).listeners.click(); await entered.promise;
      m[method] = original;
      if (invalidation === 'reset') el('reset').listeners.click();
      else { el('value').value = '2'; el('value').listeners.input(); }
      assert.equal(el('load').disabled, false); assert.equal(m.view().state, 'STOPPED');
      const load = m.load.bind(m); let calls = 0;
      m.load = async (...args) => { calls++; await newer.promise; return load(...args); };
      const pending = el('load').listeners.click();
      el('signature').value = 'new signature input';
      const visible = () => ['status', 'error', 'preview', 'prepared', 'signature'].map(id => [el(id).textContent, el(id).value]);
      const before = visible();
      hold.resolve(); await old;
      assert.deepEqual(visible(), before); assert.equal(downloads(), 0);
      for (const id of ['load', 'collect', 'prepare', 'export']) assert.equal(el(id).disabled, true, id);
      await el('load').listeners.click(); assert.equal(calls, 1);
      newer.resolve(); await pending;
      assert.equal(el('load').disabled, false); assert.equal(el('collect').disabled, false);
      assert.equal(el('prepare').disabled, true); assert.equal(el('export').disabled, true);
      assert.equal(el('error').textContent, ''); assert.equal(m.view().state, 'COLLECTING');
      assert.equal(JSON.parse(el('preview').textContent).operation.body.tx.value, invalidation === 'input' ? '2' : '1');
    });
  }
  test(`page busy ${phase}: current error releases controls and allows full recovery`, async () => {
    const { el, m, downloads } = await readyPage(phase), hold = barrier();
    const method = phase === 'export' ? 'prepare' : phase, original = m[method].bind(m);
    m[method] = async () => { await hold.promise; throw new Error('current failure'); };
    const pending = el(phase).listeners.click();
    for (const id of ['load', 'collect', 'prepare', 'export']) assert.equal(el(id).disabled, true, id);
    hold.resolve(); await pending; m[method] = original;
    assert.equal(el('error').textContent, 'current failure'); assert.equal(el('load').disabled, false);
    assert.equal(el('collect').disabled, ['load', 'export'].includes(phase));
    assert.equal(el('prepare').disabled, phase !== 'prepare');
    assert.equal(el('prepared').textContent, ''); assert.equal(el('export').disabled, true);
    assert.equal(downloads(), 0);
    await el('load').listeners.click();
    el('signature').value = JSON.stringify(eoa(wallets[0], m.view().hash)); await el('collect').listeners.click();
    await el('prepare').listeners.click(); await el('export').listeners.click();
    assert.equal(el('error').textContent, ''); assert.equal(el('load').disabled, false);
    assert.equal(el('export').disabled, false); assert.equal(downloads(), 1);
  });
}

test('genuine eth_sign v31/v32 and prevalidated v1 are not typed-data approvals', async () => {
  const { EthSafeSignature } = await import('@safe-global/protocol-kit');
  const keys = Array.from({ length: 16 }, (_, i) => new ethers.Wallet('0x' + (i + 1).toString(16).padStart(64, '0')));
  const seen = new Set();
  for (const w of keys) {
    const { m } = setup(base([owner(w)], 1)); await m.load(input);
    const personal = await w.signMessage(U.arrayify(m.view().hash));
    assert.equal(U.verifyMessage(U.arrayify(m.view().hash), personal), w.address);
    const v = parseInt(personal.slice(-2), 16) + 4;
    const encoded = new EthSafeSignature(owner(w).address, personal.slice(0, -2) + v.toString(16));
    await assert.rejects(m.collect({ owner: encoded.signer, signature: encoded.data }), /Invalid EOA typed signature/);
    seen.add(v); assert.equal(m.view().count, 0);
    if (seen.size === 2) break;
  }
  assert.deepEqual([...seen].sort(), [31, 32]);
  const { m } = setup(); await m.load(input);
  const prevalidated = U.hexConcat([U.hexZeroPad(wallets[0].address, 32), U.hexZeroPad('0x00', 32), '0x01']);
  await assert.rejects(m.collect({ owner: owner(wallets[0]).address, signature: prevalidated }), /Invalid EOA typed signature/);
  assert.equal(m.view().count, 0);
});

test('Hybrid management and insufficient existing EOA authority fail closed', async () => {
  const k = await freshSigner();
  const hybrid = { address: k.handoff.expectedAddress.toLowerCase(), kind: 'hybrid', publicKey: k.publicKey, keyId: k.keyID };
  const admin = { kind: 'addOwner', newOwner: recipient, newThreshold: 1, confirmed: true };
  for (const owners of [[hybrid], [hybrid, owner(wallets[0])]]) {
    const { m } = setup(base(owners, owners.length));
    await assert.rejects(m.load(admin), /insufficient existing EOA Owners/);
    assert.equal(m.view().state, 'STOPPED');
  }
  const { m } = setup(base([hybrid, ...wallets.slice(0, 2).map(owner)])); await m.load(admin);
  await assert.rejects(m.collect({ owner: hybrid.address }), /Hybrid management unsupported/);
  await m.collect(eoa(wallets[0], m.view().hash)); await assert.rejects(m.prepare(), /threshold/);
  assert.equal(m.view().count, 1);
});

test('snapshot changes during SDK preparation clear previously collected authority', async () => {
  for (const patch of [{ nonce: '8' }, { threshold: 1 }, { account: recipient }, { generation: 2 },
    { owners: [owner(wallets[0]), owner(wallets[2])] }, { block: { number: '101', hash: '0x' + '22'.repeat(32) } }]) {
    let reads = 0, changeAt = Infinity;
    const m = new Execution({ read: async () => ++reads === changeAt ? { ...base(), ...patch } : base(), now: clock });
    await m.load(input); for (const w of wallets.slice(0, 2)) await m.collect(eoa(w, m.view().hash));
    changeAt = reads + 2; await assert.rejects(m.prepare(), /Changed snapshot/);
    assert.equal(m.view().state, 'STOPPED'); assert.equal(m.view().count, 0);
  }
});

// ---- Isolated fork submission: explicit fork-only wallet adapter, never default or public send ----
const forkHash=n=>'0x'+n.toString(16).padStart(64,'0');
function forkChain(state=base([owner(wallets[0])],1)){
 const c=observedChain(state),f={client:'anvil/v1.3.0',parent:forkHash(99),sessionParent:forkHash(99),session:state.block.hash,calls:c.calls,simulation:'0x'+'0'.repeat(63)+'1'};
 f.rpc=async(m,p)=>{
  if(m==='web3_clientVersion'){c.calls.push([m,p]);return f.client;}
  if(m==='eth_call'&&p[0].data.startsWith('0x6a761202')){c.calls.push([m,p]);return f.simulation;}
  const v=await c.rpc(m,p);
  if(m==='eth_getBlockByNumber'){if(p[0]==='0x63')return {number:'0x63',hash:f.parent,parentHash:forkHash(98),timestamp:v.timestamp};return {...v,hash:f.session,parentHash:f.sessionParent};}
  return v;
 };
 f.profile=()=>({source:{number:'99',hash:f.parent},session:{number:'100',hash:f.session}});
 return f;
}
function forkWallet(f,{account=wallets[2].address.toLowerCase(),mode='approve'}={}){
 const w={calls:[],sends:0,account,chain:'0x89',mode,block:()=>({number:'0x64',hash:f.session}),before:async()=>{}};
 w.provider={request:async({method,params=[]})=>{w.calls.push([method,structuredClone(params)]);await w.before(method);
  if(method==='eth_chainId')return w.chain;if(method==='eth_accounts')return [w.account];
  if(method==='eth_getBlockByNumber')return w.block();
  if(method==='eth_sendTransaction'){w.sends++;if(w.mode==='reject')throw Object.assign(Error('test user rejected'),{code:4001});if(w.mode==='lost')throw Object.assign(Error('test: lost reply after submission'),{code:-32603});if(w.mode==='malformed')return '0x12';return forkHash(0xabcd);}
  throw Error('unsupported '+method);}};
 return w;
}
async function readyToSend(f=forkChain(),wallet=()=>forkWallet(f).provider){
 const p=page(f.rpc,wallet),{el,m}=p;await el('load').listeners.click();el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));
 await el('collect').listeners.click();await el('prepare').listeners.click();assert.equal(el('error').textContent,'');
 return p;
}
test('addOwner preflight copy exposes EOA authority and preserves fork-only warning',()=>{
 const html=readFileSync(new URL('../safe-execute.html',import.meta.url),'utf8');
 assert.match(html,/POL送金・Owner追加を固定blockで事前シミュレーション/);
 assert.match(html,/Owner追加は現在のEOA Ownerの明示承認と変更前thresholdが必要/);
 assert.doesNotMatch(html,/Owner追加は未対応/);
});
test('addOwner page requires explicit intent and current EOA threshold before preflight and fork-only send',async()=>{
 const state=base(wallets.slice(0,2).map(owner),2),f=forkChain(state),w=forkWallet(f),{el,m}=page(f.rpc,()=>w.provider);
 el('snapshot').value=JSON.stringify(state);el('kind').value='addOwner';el('new-owner').value=recipient;el('new-threshold').value='3';
 await el('load').listeners.click();assert.match(el('error').textContent,/not confirmed/);assert.equal(el('preflight').disabled,true);
 el('confirm').checked=true;await el('load').listeners.click();assert.equal(el('error').textContent,'');
 el('signature').value=JSON.stringify(eoa(wallets[2],m.view().hash));await el('collect').listeners.click();assert.match(el('error').textContent,/Nonowner/);assert.equal(m.view().count,0);
 el('signature').value=JSON.stringify(eoa(wallets[0],m.view().hash));await el('collect').listeners.click();
 assert.equal(el('prepare').disabled,true);assert.equal(el('preflight').disabled,true);assert.equal(el('execute').disabled,true);
 el('signature').value=JSON.stringify(eoa(wallets[1],m.view().hash));await el('collect').listeners.click();await el('prepare').listeners.click();assert.equal(el('error').textContent,'');
 assert.equal(el('preflight').disabled,false);assert.equal(el('execute').disabled,true);assert.throws(()=>m.send(),/Live execution unavailable/);
 await el('preflight').listeners.click();assert.equal(el('error').textContent,'');assert.equal(el('execute').disabled,true,'fork profile required');
 el('fork-profile').value=JSON.stringify(f.profile());el('fork-profile').listeners.input();assert.equal(el('execute').disabled,false);
 const prepared=JSON.parse(el('prepared').textContent),exec=new U.Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)']);
 const args=exec.decodeFunctionData('execTransaction',prepared.data),admin=new U.Interface(['function addOwnerWithThreshold(address,uint256)']);
 assert.equal(args[0].toLowerCase(),safe);assert.equal(args[1].toString(),'0');assert.equal(admin.decodeFunctionData('addOwnerWithThreshold',args[2])[1].toString(),'3');
 await el('execute').listeners.click();assert.equal(el('error').textContent,'');assert.equal(w.sends,1);assert.equal(m.view().state,'SENT');assert.equal(el('execute').disabled,true);
 assert.deepEqual(w.calls.at(-1),['eth_sendTransaction',[{chainId:'0x89',from:state.account,to:safe,value:'0x0',data:prepared.data}]]);
});

for(const change of ['threshold','signature','public','false','wallet'])test(`addOwner ${change} cannot reach wallet submission`,async()=>{
 const state=base([owner(wallets[0])],1),f=forkChain(state),w=forkWallet(f),{el,m}=page(f.rpc,()=>change==='wallet'?undefined:w.provider);
 el('kind').value='addOwner';el('new-owner').value=recipient;el('new-threshold').value='2';el('confirm').checked=true;
 await el('load').listeners.click();const packet=eoa(change==='signature'?wallets[1]:wallets[0],m.view().hash);packet.owner=owner(wallets[0]).address;
 el('signature').value=JSON.stringify(packet);await el('collect').listeners.click();
 if(change==='signature'){assert.match(el('error').textContent,/Invalid EOA typed signature/);assert.equal(m.view().count,0);assert.equal(el('preflight').disabled,true);return;}
 await el('prepare').listeners.click();el('fork-profile').value=JSON.stringify(f.profile());
 if(change==='threshold')state.threshold=2;if(change==='false')f.simulation='0x'+'0'.repeat(64);if(change==='public')f.client='bor/v1.5.0';
 await el('preflight').listeners.click();
 if(change==='public')await el('execute').listeners.click();
 assert.equal(el('execute').disabled,true);assert.equal(w.sends,0);
 if(change!=='wallet')assert.notEqual(el('error').textContent,'');
});
test('execute requires simulation, fork profile and wallet; argument-less send() keeps refusing',async()=>{
 const f=forkChain(),w=forkWallet(f),{el,m}=await readyToSend(f,()=>w.provider);
 assert.equal(el('execute').disabled,true);
 el('fork-profile').value=JSON.stringify(f.profile());assert.equal(typeof el('fork-profile').listeners.input,'function');el('fork-profile').listeners.input();
 assert.equal(el('execute').disabled,true,'simulation required');
 await assert.rejects(m.send({wallet:w.provider,rpc:f.rpc,fork:f.profile()}),/Simulated observed preparation/);assert.equal(m.view().state,'PREPARED');
 await el('preflight').listeners.click();assert.equal(el('error').textContent,'');assert.equal(el('execute').disabled,false);
 assert.throws(()=>m.send(),/Live execution unavailable/);
 const g=forkChain(),{el:el2}=await readyToSend(g,()=>undefined);el2('fork-profile').value=JSON.stringify(g.profile());await el2('preflight').listeners.click();assert.equal(el2('error').textContent,'');assert.equal(el2('execute').disabled,true,'wallet required');
 const h=forkChain(),{el:el3}=await readyToSend(h,()=>w.provider);await el3('preflight').listeners.click();assert.equal(el3('execute').disabled,true,'fork profile required');
 assert.equal(w.calls.length,0);assert.equal(w.sends,0);
});
test('fork-only execute submits the exact projection once, records SENT and binds readback to the returned hash',async()=>{
 const f=forkChain(),w=forkWallet(f),{el,m}=await readyToSend(f,()=>w.provider);
 el('fork-profile').value=JSON.stringify(f.profile());await el('preflight').listeners.click();
 const prepared=JSON.parse(el('prepared').textContent);
 const acquisitions=()=>f.calls.filter(([m,p])=>m==='eth_getBlockByNumber'&&p[0]==='latest').length;const before=acquisitions();
 assert.equal(typeof el('execute').listeners.click,'function');await el('execute').listeners.click();assert.equal(el('error').textContent,'');
 assert.equal(w.sends,1);assert.deepEqual(w.calls.map(([m])=>m),['eth_chainId','eth_accounts','eth_getBlockByNumber','eth_sendTransaction']);
 assert.deepEqual(w.calls[2][1],['0x64',false]);
 assert.deepEqual(w.calls[3][1],[{chainId:'0x89',from:prepared.from,to:safe,value:'0x0',data:prepared.data}]);
 assert.ok(acquisitions()>=before+2,'fresh observation before fork identity and again before submission');
 const order=f.calls.map(([m])=>m);assert.ok(order.indexOf('web3_clientVersion')>-1);
 const sent=JSON.parse(el('sent').textContent);assert.equal(sent.transactionHash,forkHash(0xabcd));assert.equal(sent.safeTxHash,prepared.safeTxHash);assert.equal(sent.nonce,'7');assert.equal(sent.liveVerified,false);assert.equal(sent.receiptVerified,false);
 assert.equal(el('receipt-hash').value,forkHash(0xabcd));assert.equal(el('check-receipt').disabled,false);
 assert.equal(m.view().state,'SENT');assert.equal(m.view().count,0);assert.equal(el('execute').disabled,true);assert.equal(el('export').disabled,true);assert.equal(el('preflight').disabled,true);assert.equal(el('prepared').textContent,'');
 await el('execute').listeners.click();assert.equal(w.sends,1);assert.notEqual(el('error').textContent,'');
 await assert.rejects(m.send({wallet:w.provider,rpc:f.rpc,fork:f.profile()}));assert.equal(w.sends,1);
 const lookups=()=>f.calls.filter(([m])=>m==='eth_getTransactionByHash');assert.equal(lookups().length,0);
 await el('check-receipt').listeners.click();assert.equal(lookups().length,1);assert.deepEqual(lookups()[0][1],[forkHash(0xabcd)]);
});
for(const change of ['client','source','session','linkage','walletChain','walletAccount','walletBlock','nonce','profileSchema','profileOrder','stale'])test(`fork gate ${change} refuses before any wallet submission`,async()=>{
 const state=base([owner(wallets[0])],1),f=forkChain(state),w=forkWallet(f),{el,m}=await readyToSend(f,()=>w.provider);
 const profile=f.profile();el('fork-profile').value=JSON.stringify(profile);await el('preflight').listeners.click();assert.equal(el('execute').disabled,false);
 if(change==='client')f.client='bor/v1.5.0';
 if(change==='source')profile.source.hash=forkHash(5);
 if(change==='session')profile.session.hash=forkHash(6);
 if(change==='linkage')f.sessionParent=forkHash(7);
 if(change==='walletChain')w.chain='0x1';
 if(change==='walletAccount')w.account=recipient;
 if(change==='walletBlock')w.block=()=>({number:'0x64',hash:forkHash(8)});
 if(change==='nonce')state.nonce='8';
 if(change==='profileSchema')profile.extra=true;
 if(change==='profileOrder')profile.session.number='101';
 if(change==='stale')w.before=async method=>{if(method==='eth_accounts')el('reset').listeners.click();};
 el('fork-profile').value=JSON.stringify(profile);
 await el('execute').listeners.click();
 assert.equal(w.sends,0,'no submission');assert.equal(el('execute').disabled,true);assert.equal(el('sent').textContent,'');
 // Argument validation refuses without touching state; every chain/wallet mismatch stops the collector.
 assert.equal(m.view().state,['profileSchema','profileOrder'].includes(change)?'PREPARED':'STOPPED');
 if(change==='stale')assert.equal(el('error').textContent,'');else assert.notEqual(el('error').textContent,'');
 if(['client','source','session','linkage','profileSchema','profileOrder'].includes(change))assert.equal(w.calls.length,0,'relay-side fork identity precedes wallet contact');
});
for(const mode of ['lost','reject','malformed'])test(`wallet ${mode} after dispatch becomes UNKNOWN: no retry, readback intent retained`,async()=>{
 const f=forkChain(),w=forkWallet(f,{mode}),{el,m}=await readyToSend(f,()=>w.provider);
 el('fork-profile').value=JSON.stringify(f.profile());await el('preflight').listeners.click();
 await el('execute').listeners.click();assert.equal(w.sends,1);assert.match(el('error').textContent,/UNKNOWN/);
 assert.equal(m.view().state,'UNKNOWN');assert.equal(m.view().count,0);assert.equal(el('execute').disabled,true);assert.equal(el('export').disabled,true);assert.equal(el('check-receipt').disabled,false);assert.equal(el('sent').textContent,'');
 await el('execute').listeners.click();assert.equal(w.sends,1);
 await assert.rejects(m.send({wallet:w.provider,rpc:f.rpc,fork:f.profile()}));assert.equal(w.sends,1);
 el('reset').listeners.click();assert.equal(m.view().state,'UNKNOWN');assert.equal(el('check-receipt').disabled,false);assert.equal(el('load').disabled,true);
});
for(const mode of ['approve','lost','malformed'])for(const change of ['reset','input'])test(`late ${mode} wallet reply preserves the submission lock after ${change}`,async()=>{
 const f=forkChain(),w=forkWallet(f,{mode}),{el,m}=await readyToSend(f,()=>w.provider);
 el('fork-profile').value=JSON.stringify(f.profile());await el('preflight').listeners.click();
 let release,entered;const dispatched=new Promise(resolve=>entered=resolve);
 w.before=async method=>{if(method==='eth_sendTransaction'){entered();await new Promise(resolve=>release=resolve);}};
 const pending=el('execute').listeners.click();await dispatched;
 assert.equal(m.view().state,'SENDING');assert.equal(m.view().attempted,true);
 if(change==='reset')el('reset').listeners.click();else{el('value').value='2';el('value').listeners.input();}
 m.invalidate();await assert.rejects(m.load(input),/Submission already attempted/);
 await el('load').listeners.click();assert.equal(m.view().state,'UNKNOWN');assert.equal(el('load').disabled,true);
 await assert.rejects(m.send({wallet:w.provider,rpc:f.rpc,fork:f.profile()}));
 const manualHash=forkHash(0x1234);el('receipt-hash').value=manualHash;
 release();await pending;assert.equal(m.view().state,mode==='approve'?'SENT':'UNKNOWN');assert.equal(m.view().count,0);
 assert.equal(el('receipt-hash').value,manualHash,'late reply must not overwrite an independent readback hash');
 if(mode==='approve')assert.equal(JSON.parse(el('sent').textContent).transactionHash,forkHash(0xabcd));else assert.equal(el('sent').textContent,'');
 assert.equal(w.sends,1);assert.equal(el('execute').disabled,true);assert.equal(el('check-receipt').disabled,false);
 assert.equal(el('prepared').textContent,'');assert.match(el('status').textContent,/再送不可/);
 await assert.rejects(m.load({...input,value:'2'}),/Submission already attempted/);
});
for (const mode of ['approve', 'lost', 'reject', 'malformed']) {
  for (const change of ['reset', 'input', 'observe']) test(`submission lock survives ${change} after ${mode}`, async () => {
    const f = forkChain(), w = forkWallet(f, { mode }), { el, m } = await readyToSend(f, () => w.provider);
    el('fork-profile').value = JSON.stringify(f.profile()); await el('preflight').listeners.click();
    const intent = m.unsigned(), receiptHash = forkHash(0xabcd);
    await el('execute').listeners.click();
    el('receipt-hash').value = receiptHash;
    const sent = el('sent').textContent;
    if (change === 'input') { el('value').value = '2'; el('value').listeners.input(); }
    else await el(change).listeners.click();
    assert.equal(m.view().state, mode === 'approve' ? 'SENT' : 'UNKNOWN');
    assert.equal(el('load').disabled, true);
    assert.equal(el('check-receipt').disabled, false);
    assert.equal(el('sent').textContent, sent);
    assert.equal(el('receipt-hash').value, receiptHash);
    await assert.rejects(m.load(input), /Submission already attempted/);
    await el('load').listeners.click();
    assert.deepEqual(m.unsigned(), intent, 'edited input must not replace the dispatched intent');
    el('signature').value = JSON.stringify(eoa(wallets[0], m.view().hash));
    for (const id of ['collect', 'prepare', 'preflight', 'execute']) await el(id).listeners.click();
    assert.equal(w.sends, 1);
    await el('check-receipt').listeners.click();
    assert.deepEqual(f.calls.filter(([method]) => method === 'eth_getTransactionByHash').at(-1)[1], [receiptHash]);
  });
}

test('model send without observation or simulation refuses before wallet contact',async()=>{
 const {m}=setup(base([owner(wallets[0])],1));await m.load(input);await m.collect(eoa(wallets[0],m.view().hash));await m.prepare();
 const f=forkChain(),w=forkWallet(f);
 await assert.rejects(m.send({wallet:w.provider,rpc:f.rpc,fork:f.profile()}),/Simulated observed preparation/);assert.equal(w.calls.length,0);
 for(const bad of [{},{wallet:w.provider},{wallet:{},rpc:f.rpc,fork:f.profile()},{wallet:w.provider,rpc:f.rpc,fork:{}},{wallet:w.provider,rpc:f.rpc,fork:{...f.profile(),source:{number:'99',hash:forkHash(0)}}}])await assert.rejects(async()=>m.send(bad));
 assert.equal(w.calls.length,0);
});
test('read transport admits web3_clientVersion with empty params only',async()=>{
 let called=0;const fetcher=async(_u,o)=>{called++;const q=JSON.parse(o.body);assert.deepEqual(q.params,[]);return new Response(JSON.stringify({jsonrpc:'2.0',id:q.id,result:'anvil/v1.3.0'}));};
 assert.equal(await executeModule.safeReadRPC('web3_clientVersion',[],fetcher),'anvil/v1.3.0');assert.equal(called,1);
 await assert.rejects(executeModule.safeReadRPC('web3_clientVersion',['x'],fetcher));await assert.rejects(executeModule.safeReadRPC('web3_sha3',[],fetcher));assert.equal(called,1);
});
