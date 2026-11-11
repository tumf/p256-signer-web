// RPC-double contract tests, not chain observations or permission to send.

test('mixed EOA/Hybrid Owners and threshold use chain authority, not supplied threshold',async()=>{
 const c=world(),other='0x'+'88'.repeat(20);c.state.owners=[other,SIGNER];c.state.threshold=2;
 const v=await readExecutionContext(c.rpc,{...args(),owners:[{address:other,kind:'eoa'},...args().owners]});assert.equal(v.threshold,2);assert.equal(v.owners.length,2);
 const eoa=world();eoa.state.owners=[ACCOUNT];const pure=await readExecutionContext(eoa.rpc,{...args(),owners:[{address:ACCOUNT,kind:'eoa'}]});assert.equal(pure.owners[0].kind,'eoa');
 const contract=world();contract.setOverride((m,p,v)=>m==='eth_getCode'&&p[0]===ACCOUNT?'0x6000':v);await assert.rejects(readExecutionContext(contract.rpc,args()),/chain read mismatch/);
});
test('caller mutation during acquisition cannot replace validated owner/key intent',async()=>{
 const c=world(),input=args();let release,first=true;
 const rpc=(m,p)=>{if(first){first=false;return new Promise(resolve=>{release=()=>resolve(c.rpc(m,p));});}return c.rpc(m,p);};
 const pending=readExecutionContext(rpc,input);await new Promise(resolve=>setImmediate(resolve));input.safe=ACCOUNT;input.owners[0].address=ACCOUNT;input.owners[0].keyId='changed';release();
 const v=await pending;assert.equal(v.safe,SAFE);assert.equal(v.owners[0].address,SIGNER);assert.equal(v.owners[0].keyId,key.keyId);
});
test('per-call deadline suppresses late continuation; acquisition deadline bounds slow RPC',async()=>{
 mock.timers.enable({apis:['setTimeout']});
 try{
 let release,calls=0;const pending=readExecutionContext(()=>{calls++;return new Promise(resolve=>{release=resolve;});},args()).then(()=> 'accepted',e=>e.code);
 await new Promise(resolve=>setImmediate(resolve));mock.timers.tick(10000);assert.equal(await pending,'unavailable');release('0x89');await new Promise(resolve=>setImmediate(resolve));assert.equal(calls,1);
 const c=world();let count=0;const slow=(m,p)=>{count++;return new Promise(resolve=>setTimeout(()=>resolve(c.rpc(m,p)),9000));};
 const total=readExecutionContext(slow,args()).then(()=> 'accepted',e=>e.code);
 for(let i=0;i<8;i++){mock.timers.tick(9000);await new Promise(resolve=>setImmediate(resolve));}
 assert.equal(await total,'unavailable');const stopped=count;mock.timers.tick(60000);await new Promise(resolve=>setImmediate(resolve));assert.equal(count,stopped);
 }finally{mock.timers.reset();}
});


import assert from 'node:assert/strict';
import { mock, test } from 'node:test';
import { readFileSync } from 'node:fs';
import ethers from '../vendor/ethers.js';
import { readExecutionContext } from '../safe-execution-reader.js';
import { createChain } from './support/key-chain.mjs';
import { K1, softwareKey } from './support/key-fixtures.mjs';
const U=ethers.utils,Z=ethers.constants.AddressZero,SAFE='0x'+ '33'.repeat(20),SIGNER='0x'+ '55'.repeat(20),ACCOUNT='0x'+ '77'.repeat(20);
const key=softwareKey(K1),now=()=>1800000000;
const fixture=JSON.parse(readFileSync(new URL('fixtures/safe150-proxy.json',import.meta.url)));
const abi=new U.Interface(['function VERSION() view returns(string)','function getOwners() view returns(address[])','function getThreshold() view returns(uint256)','function nonce() view returns(uint256)','function getModulesPaginated(address,uint256) view returns(address[],address)']);
const guard=U.id('guard_manager.guard.address'),fallback=U.id('fallback_manager.handler.address');
function world(){
 const chain=createChain({signer:SIGNER,keys:[key],now});const calls=[];
 const state={owners:[SIGNER],threshold:1,nonce:'7',guard:U.hexZeroPad('0x00',32),fallback:U.hexZeroPad('0x00',32),modules:[],next:'0x0000000000000000000000000000000000000001',version:'1.5.0',proxy:fixture.runtime,singleton:fixture.singletonRuntime,slot:U.hexZeroPad(fixture.singletonDeployment.address,32).toLowerCase()};
 let override=(_m,_p,v)=>v;
 const rpc=async(m,p)=>{
 calls.push([m,structuredClone(p)]);let out;
 if(m==='eth_getCode'&&p[0]===SAFE)out=state.proxy;
 else if(m==='eth_getCode'&&p[0]===fixture.singletonDeployment.address.toLowerCase())out=state.singleton;
 else if(m==='eth_getCode'&&p[0]===ACCOUNT)out='0x';
 else if(m==='eth_getStorageAt'&&p[0]===SAFE)out=p[1]===guard?state.guard:p[1]===fallback?state.fallback:state.slot;
 else if(m==='eth_call'&&p[0].to===SAFE){
 const parsed=abi.parseTransaction({data:p[0].data});
 const name=parsed.name;out=abi.encodeFunctionResult(name,name==='getOwners'?[state.owners]:name==='getThreshold'?[state.threshold]:name==='nonce'?[state.nonce]:name==='VERSION'?[state.version]:[state.modules,state.next]);
 }else out=await chain.rpc(m,p);
 return override(m,p,out);
 };
 return {state,chain,calls,rpc,setOverride:f=>{override=f;}};
}
const args=()=>({safe:SAFE,account:ACCOUNT,owners:[{address:SIGNER,kind:'hybrid',publicKey:key.publicKey,keyId:key.keyId}],now});
test('Safe/Hybrid acquisition binds every read to B and never enables execution',async()=>{
 const c=world(),v=await readExecutionContext(c.rpc,args());
 assert.equal(v.safe,SAFE);assert.equal(v.nonce,'7');assert.equal(v.threshold,1);assert.equal(v.liveVerified,false);assert.equal(v.owners[0].publicKey,key.publicKey);
 assert.ok(Object.isFrozen(v)&&Object.isFrozen(v.owners)&&Object.isFrozen(v.owners[0]));
 for(const [m,p]of c.calls){assert.ok(['eth_chainId','eth_getBlockByNumber','eth_getCode','eth_getStorageAt','eth_call'].includes(m),m);if(['eth_getCode','eth_getStorageAt','eth_call'].includes(m))assert.equal(p.at(-1),'0x'+v.block.number.toString(16));}
 assert.equal(c.calls.filter(([m,p])=>m==='eth_getBlockByNumber'&&p[0]==='latest').length,1);
});
test('runtime, authority, configuration and Hybrid identity mismatches are refused',async()=>{
 for(const [name,mutate] of Object.entries({proxy:c=>c.state.proxy+='00',singleton:c=>c.state.singleton+='00',slot:c=>c.state.slot=U.hexZeroPad(ACCOUNT,32),version:c=>c.state.version='1.4.1',owner:c=>c.state.owners=[ACCOUNT],threshold:c=>c.state.threshold=0,guard:c=>c.state.guard=U.hexZeroPad(ACCOUNT,32),fallback:c=>c.state.fallback=U.hexZeroPad(ACCOUNT,32),modules:c=>c.state.modules=[ACCOUNT],next:c=>c.state.next=ACCOUNT,key:c=>c.chain.state.keys=[]})){const c=world();mutate(c);await assert.rejects(readExecutionContext(c.rpc,args()),/chain read mismatch/,name);}
});
test('block/chain recheck, stale clock and noncanonical/trailing ABI responses fail closed',async()=>{
 for(const field of ['hash','number','timestamp']){
 const c=world();let blocks=0;c.setOverride((m,p,v)=>m==='eth_getBlockByNumber'&&++blocks>=2?{...v,[field]:field==='hash'?'0x'+'ee'.repeat(32):'0x1'}:v);
 await assert.rejects(readExecutionContext(c.rpc,args()),undefined,field);
 }
 const c=world();let ids=0;c.setOverride((m,p,v)=>m==='eth_chainId'&&++ids>1?'0x1':v);await assert.rejects(readExecutionContext(c.rpc,args()));
 const stale=world();await assert.rejects(readExecutionContext(stale.rpc,{...args(),now:()=>1800000061}));
 const extra=world();extra.setOverride((m,p,v)=>m==='eth_call'&&p[0].to===SAFE?v+'00':v);await assert.rejects(readExecutionContext(extra.rpc,args()));
});
test('input rejected before RPC and unsigned observations never replace offline profile',async()=>{
 for(const patch of [{safe:Z},{account:Z},{owners:[]},{owners:[...args().owners,...args().owners]},{owners:[{...args().owners[0],keyId:'bad'}]},{extra:true}]){
 const c=world();await assert.rejects(readExecutionContext(c.rpc,{...args(),...patch}),/chain read input/);assert.equal(c.calls.length,0);
 }
});
