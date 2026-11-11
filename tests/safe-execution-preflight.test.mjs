// RPC doubles only: simulation is not wallet permission, egress proof or execution.
import assert from 'node:assert/strict';
import { test, mock } from 'node:test';
import * as reader from '../safe-execution-reader.js';
import ethers from '../vendor/ethers.js';
const U=ethers.utils,Z=ethers.constants.AddressZero;
const abi=new U.Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes) returns(bool)']);
const block={number:100n,hash:'0x'+'11'.repeat(32),timestamp:1800000000n};
const request=()=>({chainId:'0x89',from:'0x'+'77'.repeat(20),to:'0x'+'33'.repeat(20),value:'0x0',data:abi.encodeFunctionData('execTransaction',['0x'+'55'.repeat(20),'1','0x',0,0,0,0,Z,Z,'0x'+'44'.repeat(65)])});
const args=()=>({request:request(),block:{...block},now:()=>1800000000});
function world(change=(_m,_p,v)=>v){const calls=[];return {calls,rpc:async(m,p)=>{calls.push([m,structuredClone(p)]);const v=m==='eth_chainId'?'0x89':m==='eth_getBlockByNumber'?{number:'0x64',hash:block.hash,timestamp:'0x6b49d200'}:m==='eth_call'?abi.encodeFunctionResult('execTransaction',[true]):assert.fail(m);return change(m,p,v);}};}
const simulate=(...a)=>{assert.equal(typeof reader.simulateExecution,'function');return reader.simulateExecution(...a);};
test('exact executor/calldata at B returns a frozen simulation only, never send authority',async()=>{
 const c=world(),a=args(),v=await simulate(c.rpc,a);
 assert.deepEqual(c.calls.filter(([m])=>m==='eth_call'),[['eth_call',[{from:a.request.from,to:a.request.to,value:'0x0',data:a.request.data},'0x64']]]);
 assert.equal(v.simulationVerified,true);assert.equal(v.liveVerified,false);assert.deepEqual(v.block,block);assert.ok(Object.isFrozen(v)&&Object.isFrozen(v.block));
 assert.deepEqual(c.calls.map(([m])=>m),['eth_chainId','eth_getBlockByNumber','eth_call','eth_getBlockByNumber','eth_chainId']);
});
for(const [name,response]of [['internal false',abi.encodeFunctionResult('execTransaction',[false])],['empty','0x'],['noncanonical','0x'+'00'.repeat(31)+'02'],['trailing',abi.encodeFunctionResult('execTransaction',[true])+'00']])test(`preflight refuses ${name}`,async()=>{const c=world((m,p,v)=>m==='eth_call'?response:v);await assert.rejects(simulate(c.rpc,args()));});
test('changed block or chain and stale block refuse',async()=>{
 for(const field of ['hash','number','timestamp','chain']){let count=0;const c=world((m,p,v)=>{if(field==='chain')return m==='eth_chainId'?'0x1':v;if(m==='eth_getBlockByNumber'&&++count===2)return {...v,[field]:field==='hash'?'0x'+'22'.repeat(32):'0x1'};return v;});await assert.rejects(simulate(c.rpc,args()),undefined,field);}
 const c=world();await assert.rejects(simulate(c.rpc,{...args(),now:()=>1800000061}));assert.equal(c.calls.filter(([m])=>m==='eth_call').length,0);
});
test('invalid request/ABI/options fail before any RPC',async()=>{
 for(const patch of [{extra:true},{request:{...request(),chainId:'0x1'}},{request:{...request(),value:'0x1'}},{request:{...request(),from:request().to}},{request:{...request(),data:'0x1234'}},{request:{...request(),data:request().data+'00'}},{block:{...block,number:100}},{now:null}]){const c=world();await assert.rejects(simulate(c.rpc,{...args(),...patch}));assert.equal(c.calls.length,0);}
 const c=world();const a=args();a.request.data=abi.encodeFunctionData('execTransaction',['0x'+'55'.repeat(20),'1','0x',1,0,0,0,Z,Z,'0x'+'44'.repeat(65)]);await assert.rejects(simulate(c.rpc,a));assert.equal(c.calls.length,0);
});
test('caller mutation cannot replace request after first await; cancellation rejects delayed result',async()=>{
 const a=args(),original=structuredClone(a.request);let release;const c=world();let first=true;const rpc=(m,p)=>{if(first){first=false;return new Promise(r=>{release=()=>r(c.rpc(m,p));});}return c.rpc(m,p);};const pending=simulate(rpc,a);await new Promise(r=>setImmediate(r));a.request.from=Z;a.block.hash='bad';release();await pending;assert.deepEqual(c.calls.find(([m])=>m==='eth_call')[1][0],{from:original.from,to:original.to,value:original.value,data:original.data});
 let active=true;const d=world((m,p,v)=>{if(m==='eth_call')active=false;return v;});await assert.rejects(simulate(d.rpc,args(),()=>active));assert.equal(d.calls.length,3);
});
test('RPC revert and per-call deadline fail without late continuation',async()=>{
 const c=world((m,p,v)=>{if(m==='eth_call')throw Error('revert');return v;});await assert.rejects(simulate(c.rpc,args()));
 mock.timers.enable({apis:['setTimeout']});try{let release,calls=0;const pending=simulate(()=>{calls++;return new Promise(r=>{release=r;});},args()).then(()=>false,()=>true);await new Promise(r=>setImmediate(r));mock.timers.tick(10000);assert.equal(await pending,true);release('0x89');await new Promise(r=>setImmediate(r));assert.equal(calls,1);}finally{mock.timers.reset();}
});
