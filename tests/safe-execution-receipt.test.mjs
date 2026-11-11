// Synthetic RPC only: no send, EVM, live chain, state-effects or physical-device evidence.
import assert from 'node:assert/strict';
import { test, mock } from 'node:test';
import * as module from '../safe-execution-receipt.js';
import ethers from '../vendor/ethers.js';
const U=ethers.utils;
const hash=n=>'0x'+n.toString(16).padStart(64,'0');
const from='0x'+'77'.repeat(20),safe='0x'+'33'.repeat(20),H=hash(42),txHash=hash(43);
const eventABI=new U.Interface(['event ExecutionSuccess(bytes32 indexed txHash,uint256 payment)','event ExecutionFailure(bytes32 indexed txHash,uint256 payment)']);
function fixture(){
 const expected={request:{chainId:'0x89',from,to:safe,value:'0x0',data:'0x1234'},safeTxHash:H,nonce:'0',effect:null};
 const blocks=Object.fromEntries([99,100,101,102].map(n=>['0x'+n.toString(16),{number:'0x'+n.toString(16),hash:hash(n),parentHash:hash(n-1),timestamp:'0x6b49d200'}]));
 const ev=eventABI.encodeEventLog(eventABI.getEvent('ExecutionSuccess'),[H,0]);
 const log={address:safe,topics:ev.topics,data:ev.data,transactionHash:txHash,blockHash:hash(100),blockNumber:'0x64',removed:false};
 const tx={hash:txHash,from,to:safe,value:'0x0',input:'0x1234',nonce:'0x0',chainId:'0x89',blockNumber:'0x64',blockHash:hash(100),gas:'0x100000',gasPrice:'0x2'};
 const receipt={transactionHash:txHash,from,to:safe,status:'0x1',blockHash:hash(100),blockNumber:'0x64',gasUsed:'0x100',effectiveGasPrice:'0x2',logs:[log]};
 const calls=[];
 const rpc=async(method,params)=>{calls.push([method,params]);
  if(method==='eth_chainId')return '0x89';
  if(method==='eth_call'){assert.deepEqual(params[0],{to:safe,data:'0xaffed0e0'});return U.defaultAbiCoder.encode(['uint256'],[params[1]==='0x63'?0:1]);}
  if(method==='eth_getTransactionByHash')return structuredClone(tx);
  if(method==='eth_getTransactionReceipt')return structuredClone(receipt);
  if(method==='eth_getBlockByNumber')return structuredClone(blocks[params[0]==='latest'?'0x66':params[0]]);
  throw Error('unexpected method');
 };
 return {expected,blocks,tx,receipt,calls,rpc};
}
test('Safe 1.5 indexed execution hash is a topic, not a data word',async()=>{
 const f=fixture();
 // Actual canonical Safe 1.5.0 fork layout; independent of the fixture ABI encoder.
 f.receipt.logs[0].topics=['0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e',H];
 f.receipt.logs[0].data='0x'+'00'.repeat(32);
 assert.equal((await module.readExecutionReceipt(f.rpc,f.expected,txHash)).receiptVerified,true);
 f.receipt.logs[0].topics.pop();f.receipt.logs[0].data=H+'00'.repeat(32);
 await assert.rejects(module.readExecutionReceipt(f.rpc,f.expected,txHash));
});
for(const field of ['from','to','input','value','chainId','hash','blockHash'])test(`readback rejects transaction ${field} mismatch`,async()=>{
 const f=fixture();f.tx[field]=field==='input'?'0x1235':field==='value'?'0x1':field==='chainId'?'0x1':field.endsWith('Hash')||field==='hash'?hash(999):'0x'+'99'.repeat(20);
 await assert.rejects(module.readExecutionReceipt(f.rpc,f.expected,txHash));
});
for(const change of ['failed','missing','duplicate','foreign','wrongH','refund','removed','extraTopic','ancestry','reorg','pending','wrongChain'])test(`readback rejects ${change} evidence`,async()=>{
 const f=fixture();let rpc=f.rpc;
 if(change==='failed')f.receipt.status='0x0';
 if(change==='missing')f.receipt.logs=[];
 if(change==='duplicate')f.receipt.logs.push(structuredClone(f.receipt.logs[0]));
 if(change==='foreign')f.receipt.logs[0].address=from;
 if(change==='wrongH'||change==='refund'){
  const e=eventABI.encodeEventLog(eventABI.getEvent('ExecutionSuccess'),[change==='wrongH'?hash(9):H,change==='refund'?1:0]);Object.assign(f.receipt.logs[0],e);
 }
 if(change==='removed')f.receipt.logs[0].removed=true;
 if(change==='extraTopic')f.receipt.logs[0].topics.push(hash(7));
 if(change==='ancestry')f.blocks['0x65'].parentHash=hash(999);
 if(change==='reorg'){let reads=0;rpc=async(m,p)=>{const v=await f.rpc(m,p);if(m==='eth_getBlockByNumber'&&p[0]==='0x64'&&++reads===2)v.hash=hash(999);return v;};}
 if(change==='pending')rpc=async(m,p)=>m==='eth_getTransactionReceipt'?null:f.rpc(m,p);
 if(change==='wrongChain')rpc=async(m,p)=>m==='eth_chainId'?'0x1':f.rpc(m,p);
 await assert.rejects(module.readExecutionReceipt(rpc,f.expected,txHash));
});
test('caller cancellation drops late result and issues no further reads',async()=>{
 const f=fixture();let active=true,release,calls=0;
 const pending=module.readExecutionReceipt(async(m,p)=>{calls++;await new Promise(resolve=>{release=resolve;});return f.rpc(m,p);},f.expected,txHash,()=>active);
 while(!release)await new Promise(resolve=>setImmediate(resolve));active=false;release();await assert.rejects(pending);assert.equal(calls,1);
});
test('trusted intent is copied before await and not replaced by caller mutation',async()=>{
 const f=fixture();let release;
 const pending=module.readExecutionReceipt(async(m,p)=>{if(!release)await new Promise(resolve=>{release=resolve;});return f.rpc(m,p);},f.expected,txHash);
 while(!release)await new Promise(resolve=>setImmediate(resolve));f.expected.request.data='0xabcd';f.expected.safeTxHash=hash(999);release();
 assert.equal((await pending).safeTxHash,H);
});

test('Safe failure event cannot be hidden behind receipt status one or an additional success event',async()=>{
 const f=fixture(),e=eventABI.encodeEventLog(eventABI.getEvent('ExecutionFailure'),[H,0]);f.receipt.logs.push({...f.receipt.logs[0],...e});
 await assert.rejects(module.readExecutionReceipt(f.rpc,f.expected,txHash));
});
test('per-read timeout discards late response and cannot trigger more RPC',async()=>{
 mock.timers.enable({apis:['setTimeout']});let release,calls=0;
 try{
  const f=fixture(),pending=module.readExecutionReceipt(async()=>{calls++;return new Promise(resolve=>{release=resolve;});},f.expected,txHash).then(()=>false,()=>true);
  while(!release)await new Promise(resolve=>setImmediate(resolve));mock.timers.tick(10000);assert.equal(await pending,true);
  release('0x89');await new Promise(resolve=>setImmediate(resolve));assert.equal(calls,1);
 }finally{mock.timers.reset();}
});
for(const change of ['hash','metadata','zero','badData'])test(`invalid expected ${change} is rejected before RPC`,async()=>{
 const f=fixture();let calls=0;
 if(change==='hash')f.expected.safeTxHash='bad';if(change==='metadata')f.expected.request.liveVerified=false;
 if(change==='zero')f.expected.request.to='0x'+'00'.repeat(20);if(change==='badData')f.expected.request.data='0x1';
 await assert.rejects(module.readExecutionReceipt(async()=>{calls++;},f.expected,txHash));assert.equal(calls,0);
});

for(const bad of [undefined,0,'-1','00','1.0',((1n<<256n)-1n).toString()])test(`nonce input ${String(bad)} rejected before RPC`,async()=>{
 const f=fixture();f.expected.nonce=bad;let calls=0;await assert.rejects(module.readExecutionReceipt(async()=>{calls++;},f.expected,txHash));assert.equal(calls,0);
});
for(const kind of ['before','unchanged','jump','noncanonical','missing','priorMismatch','priorReorg'])test(`nonce readback rejects ${kind}`,async()=>{
 const f=fixture();let priorReads=0;
 const rpc=async(m,p)=>{
  if(m==='eth_call'){
   if(kind==='missing')throw Error('archive unavailable');
   if(kind==='noncanonical')return '0x01';
   if(kind==='before'&&p[1]==='0x63')return U.defaultAbiCoder.encode(['uint256'],[1]);
   if(['unchanged','jump'].includes(kind)&&p[1]==='0x64')return U.defaultAbiCoder.encode(['uint256'],[kind==='jump'?2:0]);
  }
  const v=await f.rpc(m,p);if(m==='eth_getBlockByNumber'&&p[0]==='0x63'&&(kind==='priorMismatch'||kind==='priorReorg'&&++priorReads===2))v.hash=hash(999);return v;
 };
 await assert.rejects(module.readExecutionReceipt(rpc,f.expected,txHash));
});
test('expected nonce is captured before await, not mutated by caller',async()=>{
 const f=fixture();let once=false;const rpc=async(m,p)=>{if(!once){once=true;f.expected.nonce='999';}return f.rpc(m,p);};
 assert.equal((await module.readExecutionReceipt(rpc,f.expected,txHash)).nonceVerified,true);
});

function nativeFixture(){
 const f=fixture(),recipient='0x'+'44'.repeat(20);f.expected.effect={kind:'native',recipient,value:'5'};
 const abi=new U.Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)']);
 f.tx.input=f.expected.request.data=abi.encodeFunctionData('execTransaction',[recipient,5,'0x',0,0,0,0,ethers.constants.AddressZero,ethers.constants.AddressZero,'0x']);
 const rpc=async(m,p)=>m==='eth_getBalance'?'0x'+(p[0]===safe?(p[1]==='0x63'?100n:95n):(p[1]==='0x63'?10n:15n)).toString(16):f.rpc(m,p);
 return {...f,read:rpc};
}
test('native transfer reads exact Safe debit and recipient credit at fixed block boundaries',async()=>{
 const f=nativeFixture();const result=await module.readExecutionReceipt(f.read,f.expected,txHash);assert.equal(result.balanceVerified,true);
 assert.deepEqual(result.balances,{safeBefore:'100',safeAfter:'95',recipientBefore:'10',recipientAfter:'15'});
 assert.equal(result.stateEffectsVerified,false);assert.equal(result.liveVerified,false);
});

for(const kind of ['debit','credit','malformed','overflow','archive','reorg','cancel'])test(`balance readback refuses ${kind}`,async()=>{
 const f=nativeFixture();let active=true,seen=false;const rpc=async(m,p)=>{
  if(m==='eth_getBalance'){
   seen=true;if(kind==='archive')throw Error('archive unavailable');if(kind==='malformed')return '0x00';if(kind==='overflow')return '0x1'+'0'.repeat(64);
   if(kind==='cancel')active=false;
   if(kind==='debit'&&p[0]===safe&&p[1]==='0x64')return '0x60';
   if(kind==='credit'&&p[0]!==safe&&p[1]==='0x64')return '0xe';
  }
  const v=await f.read(m,p);if(kind==='reorg'&&seen&&m==='eth_getBlockByNumber'&&p[0]==='0x64')v.hash=hash(999);return v;
 };await assert.rejects(module.readExecutionReceipt(rpc,f.expected,txHash,()=>active));assert.equal(seen,true);
});
for(const kind of ['missing','extra','sameSafe','sameExecutor','badValue','wrongRecipient','wrongAmount','data','operation','refund'])test(`native effect refuses ${kind} before RPC`,async()=>{
 const f=nativeFixture();const e=f.expected.effect;
 if(kind==='missing')delete f.expected.effect;if(kind==='extra')e.extra=1;if(kind==='sameSafe')e.recipient=safe;if(kind==='sameExecutor')e.recipient=from;
 if(kind==='badValue')e.value='01';if(kind==='wrongRecipient')e.recipient='0x'+'55'.repeat(20);if(kind==='wrongAmount')e.value='6';
 if(['data','operation','refund'].includes(kind)){
  const abi=new U.Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)']);const a=[e.recipient,5,'0x',0,0,0,0,ethers.constants.AddressZero,ethers.constants.AddressZero,'0x'];
  if(kind==='data')a[2]='0x12';if(kind==='operation')a[3]=1;if(kind==='refund')a[6]=1;
  f.expected.request.data=abi.encodeFunctionData('execTransaction',a);
 }
 let calls=0;await assert.rejects(module.readExecutionReceipt(async()=>{calls++;},f.expected,txHash));assert.equal(calls,0);
});
test('native effect copied before await; no effect never claims balance evidence',async()=>{
 const f=nativeFixture();let once=false;const rpc=async(m,p)=>{if(!once){once=true;f.expected.effect.value='999';}return f.read(m,p);};
 assert.equal((await module.readExecutionReceipt(rpc,f.expected,txHash)).balanceVerified,true);
 const g=fixture();const result=await module.readExecutionReceipt(g.rpc,g.expected,txHash);assert.equal(result.balanceVerified,false);assert.equal(result.balances,null);
});

function ownerFixture(){
 const f=fixture(),newOwner='0x'+'88'.repeat(20),oldOwner='0x'+'55'.repeat(20),z=ethers.constants.AddressZero;
 const abi=new U.Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)','function addOwnerWithThreshold(address,uint256)','function getOwners() view returns(address[])','function getThreshold() view returns(uint256)']);
 f.expected.effect={kind:'addOwner',owners:[oldOwner],threshold:1,newOwner,newThreshold:2};
 f.tx.input=f.expected.request.data=abi.encodeFunctionData('execTransaction',[safe,0,abi.encodeFunctionData('addOwnerWithThreshold',[newOwner,2]),0,0,0,0,z,z,'0x']);
 const read=async(m,p)=>{
  if(m==='eth_call'&&p[0].data!== '0xaffed0e0'){
   const name=abi.parseTransaction(p[0]).name;return abi.encodeFunctionResult(name,name==='getOwners'?[p[1]==='0x63'?[oldOwner]:[newOwner,oldOwner]]:[p[1]==='0x63'?1:2]);
  }return f.rpc(m,p);
 };return {...f,read,abi};
}
for(const change of ['priorSet','nextSet','duplicate','sentinel','priorThreshold','nextThreshold','trailing','archive','reorg','cancel'])test(`Owner readback refuses ${change}`,async()=>{
 const f=ownerFixture();let seen=false,active=true;
 const rpc=async(m,p)=>{
  if(m==='eth_call'&&p[0].data!=='0xaffed0e0'){
   seen=true;const name=f.abi.parseTransaction(p[0]).name,prior=p[1]==='0x63';
   if(change==='archive')throw Error('archive unavailable');if(change==='cancel')active=false;
   if(name==='getOwners'&&((change==='priorSet'&&prior)||(change==='nextSet'&&!prior)))return f.abi.encodeFunctionResult(name,[['0x'+'99'.repeat(20)]]);
   if(name==='getOwners'&&change==='duplicate')return f.abi.encodeFunctionResult(name,[[...f.expected.effect.owners,...f.expected.effect.owners]]);
   if(name==='getOwners'&&change==='sentinel')return f.abi.encodeFunctionResult(name,[['0x'+'0'.repeat(39)+'1']]);
   if(name==='getThreshold'&&((change==='priorThreshold'&&prior)||(change==='nextThreshold'&&!prior)))return f.abi.encodeFunctionResult(name,[prior?2:1]);
   if(change==='trailing')return (await f.read(m,p))+'00';
  }
  const v=await f.read(m,p);if(change==='reorg'&&seen&&m==='eth_getBlockByNumber'&&p[0]==='0x64')v.hash=hash(999);return v;
 };await assert.rejects(module.readExecutionReceipt(rpc,f.expected,txHash,()=>active));assert.equal(seen,true);
});
for(const change of ['duplicate','sentinel','safe','newExisting','threshold','newThreshold','calldata'])test(`Owner intent refuses ${change} before RPC`,async()=>{
 const f=ownerFixture(),e=f.expected.effect;
 if(change==='duplicate')e.owners.push(e.owners[0]);if(change==='sentinel')e.newOwner='0x'+'0'.repeat(39)+'1';if(change==='safe')e.newOwner=safe;
 if(change==='newExisting')e.newOwner=e.owners[0];if(change==='threshold')e.threshold=2;if(change==='newThreshold')e.newThreshold=0;if(change==='calldata')e.newThreshold=1;
 let calls=0;await assert.rejects(module.readExecutionReceipt(async()=>{calls++;},f.expected,txHash));assert.equal(calls,0);
});
test('Owner intent array and threshold copied before first await',async()=>{
 const f=ownerFixture();let once=false;const rpc=async(m,p)=>{if(!once){once=true;f.expected.effect.owners[0]='0x'+'99'.repeat(20);f.expected.effect.newThreshold=1;}return f.read(m,p);};
 assert.equal((await module.readExecutionReceipt(rpc,f.expected,txHash)).ownersVerified,true);
});
test('Owner addition reads original and expected full sets and thresholds',async()=>{
 const f=ownerFixture(),r=await module.readExecutionReceipt(f.read,f.expected,txHash);
 assert.equal(r.ownersVerified,true);assert.deepEqual(r.owners,{before:f.expected.effect.owners,after:[...f.expected.effect.owners,f.expected.effect.newOwner].sort(),thresholdBefore:1,thresholdAfter:2});
 assert.equal(r.balanceVerified,false);assert.equal(r.stateEffectsVerified,false);assert.equal(r.liveVerified,false);
});

test('readback verifies exact retained transaction and two linked descendant blocks, not full execution success',async()=>{
 const f=fixture();assert.equal(typeof module.readExecutionReceipt,'function');
 const result=await module.readExecutionReceipt(f.rpc,f.expected,txHash);
 assert.equal(result.receiptVerified,true);assert.equal(result.nonceVerified,true);assert.deepEqual(result.nonce,{before:'0',after:'1'});assert.equal(result.stateEffectsVerified,false);assert.equal(result.liveVerified,false);
 assert.equal(result.transactionHash,txHash);assert.equal(result.safeTxHash,H);assert.equal(result.inclusion.hash,hash(100));
 assert.match(result.warning,/nonce/);assert.equal(f.calls.some(([m])=>m.startsWith('eth_send')),false);
 assert.ok(f.calls.some(([m,p])=>m==='eth_getBlockByNumber'&&p[0]==='0x65'));
});
