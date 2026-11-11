// Read-only receipt evidence, not a send capability or full Safe state-effects acceptance.
import ethers from './vendor/ethers.js';
import { chainId, parseBlock, quantity, transaction, receipt, ReadError } from './key-reader.js';
const U=ethers.utils;
const events=new U.Interface(['event ExecutionSuccess(bytes32 indexed txHash,uint256 payment)','event ExecutionFailure(bytes32 indexed txHash,uint256 payment)']);
const fail=code=>{throw new ReadError(code);};
const exact=(v,keys)=>{if(!v||Object.getPrototypeOf(v)!==Object.prototype||Object.keys(v).sort().join(',')!==keys.split(',').sort().join(','))fail('input');};
const hash=v=>{if(typeof v!=='string'||!/^0x[0-9a-f]{64}$/.test(v)||/^0x0{64}$/.test(v))fail('input');return v;};
const address=v=>{if(typeof v!=='string'||!/^0x[0-9a-f]{40}$/.test(v)||/^0x0{40}$/.test(v))fail('input');return v;};
const q=n=>'0x'+n.toString(16);
const admin=new U.Interface(['function addOwnerWithThreshold(address,uint256)','function getOwners() view returns(address[])','function getThreshold() view returns(uint256)']);
const ownerSet=(values,safe)=>{
 if(!Array.isArray(values)||values.length<1||values.length>8)fail('input');
 const list=values.map(v=>address(v));
 if(list.some(v=>v===safe||v==='0x'+'0'.repeat(39)+'1')||new Set(list).size!==list.length)fail('input');return list.sort();
};
const threshold=(v,count)=>{if(!Number.isSafeInteger(v)||v<1||v>count)fail('input');return v;};
export async function readExecutionReceipt(rpc,expected,transactionHash,current=()=>true){
 exact(expected,'request,safeTxHash,nonce,effect');exact(expected.request,'chainId,from,to,value,data');
 // Copy trusted intent before the first await; imported bytes alone do not establish provenance.
 const w={...expected.request},H=hash(expected.safeTxHash),nonce=expected.nonce;hash(transactionHash);
 if(typeof nonce!=='string'||!/^(0|[1-9][0-9]{0,77})$/.test(nonce)||BigInt(nonce)>=(1n<<256n)-1n)fail('input');
 const n=BigInt(nonce),effect=expected.effect===null?null:{...expected.effect};
 if(effect?.kind==='addOwner'){
  exact(expected.effect,'kind,owners,threshold,newOwner,newThreshold');
  effect.owners=ownerSet(expected.effect.owners,w.to);threshold(effect.threshold,effect.owners.length);
  effect.after=ownerSet([...effect.owners,effect.newOwner],w.to);threshold(effect.newThreshold,effect.after.length);
 }
 if(effect!==null){
  if(effect.kind!=='addOwner'){
  exact(expected.effect,'kind,recipient,value');
  if(effect.kind!=='native'||address(effect.recipient)===w.to||effect.recipient===w.from||typeof effect.value!=='string'||!/^(0|[1-9][0-9]{0,77})$/.test(effect.value)||BigInt(effect.value)>=(1n<<256n))fail('input');
  }
  // Only retained zero-refund CALL profiles can request state observations.
  const abi=new U.Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)']);
  let args;try{args=abi.decodeFunctionData('execTransaction',w.data);if(abi.encodeFunctionData('execTransaction',args)!==w.data)fail('input');}catch{fail('input');}
  if(effect.kind==='addOwner'?(args[0].toLowerCase()!==w.to||!args[1].isZero()||args[2]!==admin.encodeFunctionData('addOwnerWithThreshold',[effect.newOwner,effect.newThreshold])):(args[0].toLowerCase()!==effect.recipient||args[1].toString()!==effect.value||args[2]!=='0x'))fail('input');
  if(args[3]!==0
   ||![args[4],args[5],args[6]].every(v=>v.isZero())||args[7]!==ethers.constants.AddressZero||args[8]!==ethers.constants.AddressZero)fail('input');
 }
 if(typeof rpc!=='function'||typeof current!=='function'||w.chainId!=='0x89'||w.value!=='0x0'||address(w.from)===address(w.to)
  ||typeof w.data!=='string'||!/^0x(?:[0-9a-f]{2})+$/.test(w.data)||w.data.length>131074)fail('input');
 let active=true,total;
 const check=()=>{if(!active||!current())fail('unavailable');};
 const call=async(method,params)=>{
  check();let timer;
  try{const value=await Promise.race([Promise.resolve().then(()=>{check();return rpc(method,params);}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new ReadError('unavailable')),10000);})]);check();return value;}
  catch(e){throw e instanceof ReadError?e:new ReadError('unavailable');}finally{clearTimeout(timer);}
 };
 const block=async number=>{
  const raw=await call('eth_getBlockByNumber',[number===null?'latest':q(number),false]),b=parseBlock(raw),parentHash=hash(raw.parentHash);
  if(b.hash===parentHash||number!==null&&b.number!==number)fail('mismatch');return {...b,parentHash};
 };
 const same=(a,b)=>a.number===b.number&&a.hash===b.hash&&a.parentHash===b.parentHash&&a.timestamp===b.timestamp;
 const run=async()=>{
  if(await chainId(call)!==137n)fail('mismatch');
  const tx=await transaction(call,transactionHash),r=await receipt(call,transactionHash);
  if(!tx||!r)fail('unavailable'); // Pending/not found is not success or permission to retry/send.
  if(tx.chainId!==137n||tx.from!==w.from||tx.to!==w.to||tx.value!==0n||tx.input!==w.data
   ||r.from!==w.from||r.to!==w.to||r.status!=='0x1'||tx.blockNumber!==r.blockNumber||tx.blockHash!==r.blockHash
   ||r.gasUsed===0n||r.gasUsed>tx.gas||r.effectiveGasPrice>tx.maxFeePerGas)fail('mismatch');
  let success=0;
  for(const log of r.logs){
   if(log.address!==w.to)continue;
   const topic=log.topics[0],yes=events.getEventTopic('ExecutionSuccess'),no=events.getEventTopic('ExecutionFailure');
   if(topic!==yes&&topic!==no)continue;
   if(topic===no)fail('mismatch');
   let decoded,encoded;
   try{decoded=events.decodeEventLog('ExecutionSuccess',log.data,log.topics);encoded=events.encodeEventLog(events.getEvent('ExecutionSuccess'),decoded);}catch{fail('malformed');}
   if(JSON.stringify(encoded.topics)!==JSON.stringify(log.topics)||encoded.data!==log.data||decoded.txHash!==H||!decoded.payment.isZero())fail('mismatch');success++;
  }
  if(success!==1)fail('mismatch');
  const inclusion=await block(r.blockNumber);if(inclusion.hash!==r.blockHash||inclusion.number===0n)fail('mismatch');
  const prior=await block(inclusion.number-1n);if(inclusion.parentHash!==prior.hash)fail('mismatch');
  const nonceAt=async b=>{
   const raw=await call('eth_call',[{to:w.to,data:'0xaffed0e0'},q(b.number)]);
   if(typeof raw!=='string'||!/^0x[0-9a-f]{64}$/.test(raw))fail('malformed');return BigInt(raw);
  };
  const before=await nonceAt(prior),after=await nonceAt(inclusion);
  // Conservative block-boundary evidence: other Safe executions in this block cause refusal.
  if(before!==n||after!==n+1n)fail('mismatch');
  let balances=null;
  if(effect?.kind==='native'){
   const balance=async(a,b)=>quantity(await call('eth_getBalance',[a,q(b.number)]),(1n<<256n)-1n);
   const safeBefore=await balance(w.to,prior),safeAfter=await balance(w.to,inclusion),recipientBefore=await balance(effect.recipient,prior),recipientAfter=await balance(effect.recipient,inclusion);
   if(safeBefore-safeAfter!==BigInt(effect.value)||recipientAfter-recipientBefore!==BigInt(effect.value))fail('mismatch');
   balances=Object.freeze(Object.fromEntries(Object.entries({safeBefore,safeAfter,recipientBefore,recipientAfter}).map(([k,v])=>[k,v.toString()])));
  }
  let owners=null;
  if(effect?.kind==='addOwner'){
   const read=async(name,b)=>{
    const raw=await call('eth_call',[{to:w.to,data:admin.encodeFunctionData(name)},q(b.number)]);
    if(typeof raw!=='string'||raw.length>1154)fail('malformed');
    let value;try{value=admin.decodeFunctionResult(name,raw);if(admin.encodeFunctionResult(name,value)!==raw)fail('malformed');}catch{fail('malformed');}
    return name==='getOwners'?ownerSet(value[0].map(v=>v.toLowerCase()),w.to):threshold(Number(value[0].toString()),8);
   };
   const old=await read('getOwners',prior),next=await read('getOwners',inclusion),oldT=await read('getThreshold',prior),nextT=await read('getThreshold',inclusion);
   if(JSON.stringify(old)!==JSON.stringify(effect.owners)||JSON.stringify(next)!==JSON.stringify(effect.after)||oldT!==effect.threshold||nextT!==effect.newThreshold)fail('mismatch');
   owners=Object.freeze({before:Object.freeze(old),after:Object.freeze(next),thresholdBefore:oldT,thresholdAfter:nextT});
  }
  // Verify the actual two-edge ancestry, not just a numerical head distance.
  const child=await block(inclusion.number+1n),grandchild=await block(inclusion.number+2n),head=await block(null);
  if(child.parentHash!==inclusion.hash||grandchild.parentHash!==child.hash||head.number<grandchild.number
   ||head.number===grandchild.number&&!same(head,grandchild))fail('mismatch');
  if(!same(await block(prior.number),prior)||!same(await block(inclusion.number),inclusion)||!same(await block(child.number),child)||!same(await block(grandchild.number),grandchild)||await chainId(call)!==137n)fail('mismatch');
  check();return Object.freeze({transactionHash,safeTxHash:H,inclusion:Object.freeze(inclusion),receiptVerified:true,nonceVerified:true,nonce:Object.freeze({before:before.toString(),after:after.toString()}),balanceVerified:balances!==null,balances,ownersVerified:owners!==null,owners,stateEffectsVerified:false,liveVerified:false,
   warning:'Receipt/event, block-boundary nonce and optional native balances or Owner sets only: runtime and transaction-level state attribution remain unverified. Not full execution success or send authorization.'});
 };
 try{return await Promise.race([run(),new Promise((_,reject)=>{total=setTimeout(()=>reject(new ReadError('unavailable')),60000);})]);}
 finally{active=false;clearTimeout(total);}
}
