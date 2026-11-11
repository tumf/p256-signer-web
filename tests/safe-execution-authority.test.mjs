// An injected chain observation is only an additional veto on offline preparation.
// No public RPC, fork, wallet, or live execution permission.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Execution } from '../safe-execute.js';
import ethers from '../vendor/ethers.js';
import { buildRequest } from '../safe-request-model.js';
import { VECTOR_CLOCK, expected, v } from './support/safe-fixtures.mjs';
const Z=ethers.constants.AddressZero; assert.equal(typeof Z,'string');
const safe='0x'+'33'.repeat(20),account='0x'+'77'.repeat(20),owner='0x'+'44'.repeat(20),hash='0x'+'11'.repeat(32);
const raw=()=>({chainId:'137',safe,version:'1.5.0',singleton:'0xff51a5898e281db6dfc7855790607438df2ca44b',runtime:'unverified-offline',guard:Z,fallback:Z,modules:[],owners:[{address:owner,kind:'eoa'}],threshold:1,nonce:'7',account,block:{number:'100',hash},generation:1,attempt:'none'});
const observed=()=>({chainId:'137',safe,account,version:'1.5.0',singleton:raw().singleton,guard:Z,fallback:Z,modules:[],owners:[{address:owner,kind:'eoa'}],threshold:1,nonce:'7',block:{number:100n,hash,timestamp:1800000000n},liveVerified:false});
const input={kind:'native',recipient:'0x'+'55'.repeat(20),value:'1'};
function model(readObservation){let calls=0;const m=new Execution({read:async()=>raw(),observe:async()=>{calls++;return readObservation();},now:()=>1800000000});return {m,get calls(){return calls;}};}
test('opt-in block advancement preserves original body, signatures and deadline without authorizing send',async()=>{
 let height=100n,time=VECTOR_CLOCK;const owners=[{address:expected.signer.toLowerCase(),kind:'hybrid',publicKey:expected.publicKey,keyId:expected.keyId}],s={...raw(),safe:expected.safe.toLowerCase(),nonce:expected.nonce,owners};
 const m=new Execution({read:async()=>s,advanceObservation:true,observe:async()=>({...observed(),safe:s.safe,nonce:s.nonce,owners,block:{number:height,hash:height===100n?hash:'0x'+height.toString(16).padStart(64,'0'),timestamp:BigInt(time)}}),now:()=>time});
 const context=structuredClone(v.context.result),envelope=JSON.parse(v.request.envelope),request=buildRequest(context,expected,envelope.id,Number(envelope.issuedAt));
 await m.load({kind:'native',recipient:expected.recipient,value:expected.value});const original=m.unsigned();height++;
 await m.collect({owner:owners[0].address,expected,context,request,result:structuredClone(v.result.result)});height++;
 const prepared=await m.prepare();assert.deepEqual(m.unsigned(),original);assert.equal(prepared.safeTxHash,request.safeTxHash);assert.equal(prepared.liveVerified,false);
 height++;assert.equal((await m.walletRequest()).data,prepared.data);assert.equal(m.view().count,1);assert.throws(()=>m.send(),/Live execution unavailable/);
 time+=120;height++;await assert.rejects(m.walletRequest(),/Request expired/);assert.equal(m.view().state,'STOPPED');
});

for(const change of ['rollback','sameHash','sameTime','timeRegression','nonce','key','threshold','badHash','extra'])test(`advancement rejects ${change} without retaining approval`,async()=>{
 let n=100n,drift=false;const c=new Execution({read:async()=>raw(),advanceObservation:true,now:()=>1800000000,observe:async()=>{
  const o=observed();o.block={number:n,hash:n===100n?hash:'0x'+'22'.repeat(32),timestamp:1800000000n};
  if(drift){if(change==='rollback')o.block.number=99n;else if(change==='sameHash'){o.block.number=100n;o.block.hash='0x'+'33'.repeat(32);}else if(change==='sameTime'){o.block.number=100n;o.block.hash=hash;o.block.timestamp++;}else if(change==='timeRegression')o.block.timestamp--;else if(change==='nonce')o.nonce='8';else if(change==='key')o.owners[0].kind='hybrid';else if(change==='threshold')o.threshold=2;else if(change==='badHash')o.block.hash='not a hash';else o.extra=true;}return o;
 }});await c.load(input);drift=true;n++;await assert.rejects(c.prepare());assert.equal(c.view().state,'STOPPED');assert.equal(c.view().count,0);
});
test('advancement requires an observation function and boolean opt-in',()=>{for(const option of [{advanceObservation:true},{advanceObservation:1,observe:observed}])assert.throws(()=>new Execution({read:raw,...option}));});

test('matching injected read veto gate runs at load and prepare, without authorizing send',async()=>{
 const c=model(observed);await c.m.load(input);assert.equal(c.calls,1);
 await assert.rejects(c.m.prepare(),/Select exactly threshold distinct Owners/);assert.equal(c.calls,2);
 assert.throws(()=>c.m.send(),/Live execution unavailable/);
});
for(const change of ['nonce','owners','threshold','safe','blockHash','blockNumber','runtimeClaim','generationClaim'])test(`read mismatch ${change} refuses load without exposing an operation`,async()=>{
 const c=model(()=>{const v=observed();if(change==='nonce')v.nonce='8';else if(change==='owners')v.owners=[{address:account,kind:'eoa'}];else if(change==='threshold')v.threshold=2;else if(change==='safe')v.safe=account;else if(change==='blockHash')v.block.hash='0x'+'22'.repeat(32);else if(change==='blockNumber')v.block.number=101n;else if(change==='runtimeClaim')v.liveVerified=true;else v.generation=1;return v;});
 await assert.rejects(c.m.load(input));assert.equal(c.m.view().state,'STOPPED');assert.equal(c.calls,1);
});
test('late observation after explicit invalidate cannot restore collector state',async()=>{
 let release;const c=model(()=>new Promise(resolve=>{release=()=>resolve(observed());}));
 const pending=c.m.load(input);while(!release)await new Promise(resolve=>setImmediate(resolve));
 c.m.invalidate();release();await assert.rejects(pending,/Stale observation/);
 assert.equal(c.m.view().state,'STOPPED');assert.throws(()=>c.m.unsigned(),/No current operation/);
});
test('load invalidated after observation verification cannot resurrect collector state',async()=>{
 const c=model(()=>{queueMicrotask(()=>queueMicrotask(()=>c.m.invalidate()));return observed();});
 const [result]=await Promise.allSettled([c.m.load(input)]);
 assert.equal(c.m.view().state,'STOPPED');assert.equal(c.m.view().count,0);
 assert.equal(result.status,'rejected');assert.match(result.reason.message,/Stale generation/);
 assert.throws(()=>c.m.unsigned(),/No current operation/);
 assert.throws(()=>c.m.send(),/Live execution unavailable/);
});
test('superseded load cannot clear or replace the newer operation',async()=>{
 let successor,calls=0;
 const m=new Execution({read:async()=>raw(),observe:async()=>{
  if(++calls===1)queueMicrotask(()=>queueMicrotask(()=>{successor=m.load({...input,value:'2'});}));
  return observed();
 },now:()=>1800000000});
 await assert.rejects(m.load(input),/Stale generation/);await successor;
 assert.equal(calls,2);assert.equal(m.view().state,'COLLECTING');
 assert.equal(m.unsigned().operation.body.tx.value,'2');
});
// Frozen upstream software signature vector; observation remains a double, not chain evidence.
function hybrid(observeResult=value=>value,now=()=>VECTOR_CLOCK){
 const owners=[{address:expected.signer.toLowerCase(),kind:'hybrid',publicKey:expected.publicKey,keyId:expected.keyId}];
 const s={...raw(),safe:expected.safe.toLowerCase(),nonce:expected.nonce,owners};let calls=0;
 const observation=()=>({...observed(),safe:s.safe,nonce:s.nonce,owners:structuredClone(owners)});
 const m=new Execution({read:async()=>s,observe:async()=>observeResult(observation(),++calls),now});
 const context=structuredClone(v.context.result),envelope=JSON.parse(v.request.envelope);
 const request=buildRequest(context,expected,envelope.id,Number(envelope.issuedAt));
 return {m,input:{kind:'native',recipient:expected.recipient,value:expected.value},
  packet:{owner:owners[0].address,expected,context,request,result:structuredClone(v.result.result)},get calls(){return calls;}};
}
test('matching observed Hybrid packet reaches offline PREPARED and checks both collection and preparation boundaries',async()=>{
 const c=hybrid();await c.m.load(c.input);assert.equal(c.calls,1);
 await c.m.collect(c.packet);assert.equal(c.calls,3);
 const prepared=await c.m.prepare();assert.equal(c.calls,5);
 assert.equal(c.m.view().state,'PREPARED');assert.equal(prepared.liveVerified,false);
 assert.equal(prepared.safeTxHash,c.packet.request.safeTxHash);
 assert.equal(prepared.selected.length,1);assert.equal(prepared.selected[0].owner,c.packet.owner);
 assert.throws(()=>c.m.send(),/Live execution unavailable/);
});
test('prepared simulation uses the collected request and latest checked observation without enabling send',async()=>{
 const c=hybrid(o=>({...o,block:{...o.block,timestamp:BigInt(VECTOR_CLOCK)}}));await c.m.load(c.input);await c.m.collect(c.packet);const prepared=await c.m.prepare();
 assert.equal(typeof c.m.preflight,'function');const calls=[];
 const rpc=async(m,p)=>{calls.push([m,p]);if(m==='eth_chainId')return '0x89';if(m==='eth_getBlockByNumber')return {number:'0x64',hash,timestamp:'0x'+BigInt(VECTOR_CLOCK).toString(16)};if(m==='eth_call')return '0x'+'0'.repeat(63)+'1';assert.fail(m);};
 const result=await c.m.preflight(rpc);assert.equal(result.simulationVerified,true);assert.equal(result.liveVerified,false);
 assert.equal(calls.find(([m])=>m==='eth_call')[1][0].data,prepared.data);assert.equal(c.m.view().state,'PREPARED');assert.throws(()=>c.m.send(),/Live execution unavailable/);
});
test('preflight failure clears approval; invalidated completion cannot return success',async()=>{
 for(const invalidate of [false,true]){const c=hybrid(o=>({...o,block:{...o.block,timestamp:BigInt(VECTOR_CLOCK)}}));await c.m.load(c.input);await c.m.collect(c.packet);await c.m.prepare();
 assert.equal(typeof c.m.preflight,'function');const rpc=async(m,p)=>{if(m==='eth_chainId')return '0x89';if(m==='eth_getBlockByNumber')return {number:'0x64',hash,timestamp:'0x'+BigInt(VECTOR_CLOCK).toString(16)};if(m==='eth_call'){if(invalidate)c.m.invalidate();return '0x'+'0'.repeat(63)+(invalidate?'1':'0');}assert.fail(m);};
 await assert.rejects(c.m.preflight(rpc));assert.equal(c.m.view().state,'STOPPED');assert.equal(c.m.view().count,0);}
});
test('preflight refuses expiry during simulation and never retains an approval',async()=>{
 let time=VECTOR_CLOCK;const c=hybrid(o=>({...o,block:{...o.block,timestamp:BigInt(time)}}),()=>time);
 await c.m.load(c.input);await c.m.collect(c.packet);await c.m.prepare();
 const rpc=async(m)=>{if(m==='eth_chainId')return '0x89';if(m==='eth_getBlockByNumber')return {number:'0x64',hash,timestamp:'0x'+BigInt(VECTOR_CLOCK).toString(16)};time+=120;return '0x'+'0'.repeat(63)+'1';};
 await assert.rejects(c.m.preflight(rpc));assert.equal(c.m.view().state,'STOPPED');assert.equal(c.m.view().count,0);
});
for(const age of [60,61])test(`preflight rechecks simulated block age ${age} after delayed final observation`,async()=>{
 let time=VECTOR_CLOCK,release;const c=hybrid((o,n)=>{
  const observation={...o,block:{...o.block,timestamp:BigInt(VECTOR_CLOCK)}};
  return n===7?new Promise(resolve=>{release=()=>resolve(observation);}):observation;
 },()=>time);
 await c.m.load(c.input);await c.m.collect(c.packet);await c.m.prepare();
 const calls=[];const rpc=async(m)=>{calls.push(m);if(m==='eth_chainId')return '0x89';if(m==='eth_getBlockByNumber')return {number:'0x64',hash,timestamp:'0x'+BigInt(VECTOR_CLOCK).toString(16)};assert.equal(m,'eth_call');return '0x'+'0'.repeat(63)+'1';};
 const pending=c.m.preflight(rpc);const outcome=pending.then(value=>({value}),error=>({error}));
 while(!release)await new Promise(resolve=>setImmediate(resolve));
 assert.equal(c.calls,7);assert.equal(calls.length,5);time+=age;release();
 const result=await outcome;
 if(age===60){assert.equal(result.error,undefined);assert.equal(result.value.simulationVerified,true);assert.equal(result.value.liveVerified,false);assert.equal(c.m.view().state,'PREPARED');}
 else{assert.ok(result.error,'stale simulated block must reject after final observation');assert.match(result.error.message,/chain read stale/);assert.equal(c.m.view().state,'STOPPED');assert.equal(c.m.view().count,0);}
 assert.throws(()=>c.m.send(),/Live execution unavailable/);
});
test('preflight requires checked observation and cannot use offline-only preparation',async()=>{
 const s=raw(),wallet=new ethers.Wallet('0x'+'01'.repeat(32));s.owners=[{address:wallet.address.toLowerCase(),kind:'eoa'}];
 const m=new Execution({read:async()=>s,now:()=>VECTOR_CLOCK});await m.load(input);await m.collect({owner:wallet.address.toLowerCase(),signature:ethers.utils.joinSignature(wallet._signingKey().signDigest(m.unsigned().operation.hash))});await m.prepare();assert.equal(m.view().state,'PREPARED');
 await assert.rejects(m.preflight(()=>assert.fail('RPC must not run')),/Observed preparation required/);
});
test('wallet request is an isolated five-key projection of freshly rechecked preparation, never a send',async()=>{
 const c=hybrid();await c.m.load(c.input);await c.m.collect(c.packet);
 assert.equal(typeof c.m.walletRequest,'function');await assert.rejects(c.m.walletRequest(),/Prepare/);
 const prepared=await c.m.prepare(),before=c.calls,request=await c.m.walletRequest();
 assert.equal(c.calls,before+1);assert.deepEqual(Object.keys(request).sort(),['chainId','data','from','to','value']);
 assert.deepEqual(request,Object.fromEntries(['chainId','from','to','value','data'].map(k=>[k,prepared[k]])));
 request.data='0x';prepared.from=owner;
 const again=await c.m.walletRequest();assert.notEqual(again.data,'0x');assert.equal(again.from,account);
 assert.equal(c.m.view().state,'PREPARED');assert.throws(()=>c.m.send(),/Live execution unavailable/);
});
for(const change of ['nonce','keyId','blockHash'])test(`wallet request refuses fresh ${change} drift and clears authority`,async()=>{
 let drift=false;const c=hybrid(o=>{if(drift){if(change==='keyId')o.owners[0].keyId='00'.repeat(32);else if(change==='blockHash')o.block.hash='0x'+'22'.repeat(32);else o.nonce='8';}return o;});
 await c.m.load(c.input);await c.m.collect(c.packet);await c.m.prepare();drift=true;
 assert.equal(typeof c.m.walletRequest,'function');await assert.rejects(c.m.walletRequest(),/Changed observation/);
 assert.equal(c.m.view().state,'STOPPED');assert.equal(c.m.view().count,0);
});
test('wallet request cannot release old bytes after observation completion invalidates generation',async()=>{
 const c=hybrid((o,n)=>{if(n===6)queueMicrotask(()=>queueMicrotask(()=>c.m.invalidate()));return o;});
 await c.m.load(c.input);await c.m.collect(c.packet);await c.m.prepare();
 assert.equal(typeof c.m.walletRequest,'function');await assert.rejects(c.m.walletRequest());
 assert.equal(c.m.view().state,'STOPPED');assert.equal(c.m.view().count,0);
});

for(const stage of ['before','during'])test(`wallet request refuses expiry ${stage} its fresh observation`,async()=>{
 let now=VECTOR_CLOCK;const c=hybrid((o,n)=>{if(stage==='during'&&n===6)now+=120;return o;},()=>now);
 await c.m.load(c.input);await c.m.collect(c.packet);await c.m.prepare();if(stage==='before')now+=120;
 await assert.rejects(c.m.walletRequest(),/Request expired/);assert.equal(c.m.view().state,'STOPPED');assert.equal(c.m.view().count,0);
});
test('wallet request refuses a prepared object superseded while observation waits',async()=>{
 let release;const c=hybrid((o,n)=>n===6?new Promise(resolve=>{release=()=>resolve(o);}):o);
 await c.m.load(c.input);await c.m.collect(c.packet);await c.m.prepare();
 const old=c.m.walletRequest();while(!release)await new Promise(resolve=>setImmediate(resolve));
 await c.m.prepare();release();await assert.rejects(old,/Stale preparation/);assert.equal(c.m.view().state,'PREPARED');
 assert.ok((await c.m.walletRequest()).data.startsWith('0x6a761202'));
});
test('wallet request read failure invalidates without returning stale calldata',async()=>{
 const c=hybrid((o,n)=>{if(n===6)throw new Error('reader failed');return o;});
 await c.m.load(c.input);await c.m.collect(c.packet);await c.m.prepare();
 await assert.rejects(c.m.walletRequest(),/reader failed/);assert.equal(c.m.view().state,'STOPPED');assert.equal(c.m.view().count,0);
});

for(const field of ['publicKey','keyId'])test(`Hybrid ${field} mismatch clears a collected approval before prepare`,async()=>{
 const c=hybrid((o,n)=>{if(n>=4)o.owners[0][field]=field==='keyId'?'00'.repeat(32):'0x04'+'00'.repeat(64);return o;});
 await c.m.load(c.input);await c.m.collect(c.packet);assert.equal(c.m.view().count,1);
 await assert.rejects(c.m.prepare(),/Changed observation/);
 assert.equal(c.calls,4);assert.equal(c.m.view().state,'STOPPED');assert.equal(c.m.view().count,0);
 assert.throws(()=>c.m.unsigned(),/No current operation/);
});
for(const failAt of [1,2,3,4,5])test(`observation exception at read ${failAt} stops and clears authority`,async()=>{
 const c=hybrid((o,n)=>{if(n===failAt)throw new Error('observation unavailable');return o;});
 await assert.rejects((async()=>{await c.m.load(c.input);await c.m.collect(c.packet);await c.m.prepare();})(),/observation unavailable/);
 assert.equal(c.calls,failAt);assert.equal(c.m.view().state,'STOPPED');assert.equal(c.m.view().count,0);
 assert.throws(()=>c.m.send(),/Live execution unavailable/);
});
test('changed observation at prepare clears operation and cannot promote offline execution',async()=>{
 let v=observed();const c=model(()=>v);await c.m.load(input);v={...observed(),nonce:'8'};
 await assert.rejects(c.m.prepare());assert.equal(c.m.view().state,'STOPPED');assert.equal(c.calls,2);
 assert.throws(()=>c.m.send(),/Live execution unavailable/);
});
