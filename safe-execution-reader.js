// Read-only acquisition used by the preparation page as a mismatch veto; never authorizes a send.
import ethers from './vendor/ethers.js';
import { block, chainId, fresh, readContext, ReadError } from './key-reader.js';
import { isPoint, keyIdOf } from './key-model.js';
const U=ethers.utils,Z=ethers.constants.AddressZero,SENTINEL='0x0000000000000000000000000000000000000001';
const SINGLETON='0xff51a5898e281db6dfc7855790607438df2ca44b';
const PROXY_HASH='0x4e381985ca68b3e5d27b4425fa581c19cf33146d3f887a3cfca96f55528ea46f';
const SINGLETON_HASH='0xdda019cbd7c867a533a2a86e5c53434fdc50b13122b5a5ddb4a8df61b31c20f2';
const abi=new U.Interface(['function VERSION() view returns(string)','function getOwners() view returns(address[])','function getThreshold() view returns(uint256)','function nonce() view returns(uint256)','function getModulesPaginated(address,uint256) view returns(address[],address)']);
const fail=code=>{throw new ReadError(code);};
const exact=(v,keys)=>{if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).sort().join(',')!==keys.split(',').sort().join(','))fail('input');};
const address=v=>{if(typeof v!=='string'||!/^0x[0-9a-f]{40}$/.test(v)||v===Z||v===SENTINEL)fail('input');return v;};
function freeze(v){if(v&&typeof v==='object'){for(const child of Object.values(v))freeze(child);Object.freeze(v);}return v;}
/** Exact read-only simulation only; caller must separately establish runtime, signatures and send authority. */
export async function simulateExecution(rpc,options,current=()=>true){
 exact(options,'request,block,now');exact(options.request,'chainId,from,to,value,data');exact(options.block,'number,hash,timestamp');
 const w={...options.request},b={...options.block},now=options.now;
 if(typeof rpc!=='function'||typeof current!=='function'||typeof now!=='function'||w.chainId!=='0x89'||w.value!=='0x0'
  ||address(w.from)===address(w.to)||typeof w.data!=='string'||!/^0x(?:[0-9a-f]{2})+$/.test(w.data)||w.data.length>32770
  ||typeof b.number!=='bigint'||b.number<0n||b.number>0xffffffffffffffffn||typeof b.timestamp!=='bigint'||b.timestamp<0n
  ||typeof b.hash!=='string'||!/^0x[0-9a-f]{64}$/.test(b.hash)||/^0x0{64}$/.test(b.hash))fail('input');
 const exec=new U.Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes) returns(bool)']);
 let args;try{args=exec.decodeFunctionData('execTransaction',w.data);if(exec.encodeFunctionData('execTransaction',args)!==w.data)fail('input');}catch{fail('input');}
 if(args[3]!==0||![args[4],args[5],args[6]].every(v=>v.isZero())||args[7]!==Z||args[8]!==Z||args[9]==='0x')fail('input');
 let active=true;
 const check=()=>{if(!active||!current())fail('unavailable');};
 const call=async(method,params)=>{
  check();let timer;
  try{const value=await Promise.race([Promise.resolve().then(()=>{check();return rpc(method,params);}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new ReadError('unavailable')),10000);})]);check();return value;}
  catch(e){throw e instanceof ReadError?e:new ReadError('unavailable');}finally{clearTimeout(timer);}
 };
 const same=v=>v.number===b.number&&v.hash===b.hash&&v.timestamp===b.timestamp;
 try{
  fresh(b,now());if(await chainId(call)!==137n||!same(await block(call,b.number)))fail('mismatch');
  const result=await call('eth_call',[{from:w.from,to:w.to,value:w.value,data:w.data},'0x'+b.number.toString(16)]);
  // Exact ABI true only: neither an outer successful RPC nor internal false is Safe success.
  if(result!=='0x'+'0'.repeat(63)+'1')fail('mismatch');
  if(!same(await block(call,b.number))||await chainId(call)!==137n)fail('mismatch');
  fresh(b,now());check();
  return freeze({block:b,simulationVerified:true,liveVerified:false,warning:'Read-only simulation only. Runtime, current authority, egress, wallet and receipt are separate requirements; not permission to send.'});
 }finally{active=false;}
}
export async function readExecutionContext(rpc,options){
 exact(options,'safe,account,owners,now');
 const safe=address(options.safe),account=address(options.account),now=options.now;
 if(typeof rpc!=='function'||typeof now!=='function'||safe===account||!Array.isArray(options.owners)||options.owners.length<1||options.owners.length>8)fail('input');
 const owners=options.owners.map(o=>{
  exact(o,o?.kind==='hybrid'?'address,kind,publicKey,keyId':'address,kind');address(o.address);
  if(o.address===safe||!['hybrid','eoa'].includes(o.kind))fail('input');
  if(o.kind==='hybrid'&&(!isPoint(o.publicKey)||keyIdOf(o.publicKey)!==o.keyId))fail('input');
  return {...o};
 }).sort((a,b)=>a.address.localeCompare(b.address));
 if(new Set(owners.map(o=>o.address)).size!==owners.length)fail('input');
 let active=true,total;
 // ponytail: rpc owns cancellation; late replies are ignored and cannot start new calls.
 const call=async(method,params)=>{
  if(!active)fail('unavailable');let timer;
  try{return await Promise.race([Promise.resolve().then(()=>{if(!active)fail('unavailable');return rpc(method,params);}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new ReadError('unavailable')),10000);})]);}
  catch(e){throw e instanceof ReadError?e:new ReadError('unavailable');}
  finally{clearTimeout(timer);}
 };
 const run=async()=>{
  if(await chainId(call)!==137n)fail('mismatch');const b=await block(call,null);fresh(b,now());
  const at='0x'+b.number.toString(16);
  const data=async(method,params,max)=>{const v=await call(method,params);if(typeof v!=='string'||!/^0x(?:[0-9a-f]{2})*$/.test(v)||(v.length-2)/2>max)fail('malformed');return v;};
  const code=addr=>data('eth_getCode',[addr,at],24576);
  const slot=async key=>{const v=await data('eth_getStorageAt',[safe,key,at],32);if(v.length!==66)fail('malformed');return v;};
  const query=async(name,args=[])=>{
   const bytes=await data('eth_call',[{to:safe,data:abi.encodeFunctionData(name,args)},at],1024);
   let decoded;try{decoded=abi.decodeFunctionResult(name,bytes);if(abi.encodeFunctionResult(name,decoded)!==bytes)fail('malformed');}catch{fail('malformed');}return decoded;
  };
  if(U.keccak256(await code(safe))!==PROXY_HASH||await slot(U.hexZeroPad('0x00',32))!==U.hexZeroPad(SINGLETON,32)||U.keccak256(await code(SINGLETON))!==SINGLETON_HASH)fail('mismatch');
  if((await query('VERSION'))[0]!=='1.5.0')fail('mismatch');
  const actual=(await query('getOwners'))[0].map(a=>a.toLowerCase()).sort();
  if(JSON.stringify(actual)!==JSON.stringify(owners.map(o=>o.address)))fail('mismatch');
  const threshold=BigInt((await query('getThreshold'))[0].toString());
  if(threshold<1n||threshold>BigInt(owners.length))fail('mismatch');
  const nonce=(await query('nonce'))[0].toString();
  for(const key of ['guard_manager.guard.address','fallback_manager.handler.address'])if(await slot(U.id(key))!==U.hexZeroPad('0x00',32))fail('mismatch');
  const modules=await query('getModulesPaginated',[SENTINEL,1]);
  if(modules[0].length||modules[1].toLowerCase()!==SENTINEL)fail('mismatch');
  if(await code(account)!=='0x')fail('mismatch');
  for(const owner of owners){
   if(owner.kind==='eoa'){if(await code(owner.address)!=='0x')fail('mismatch');}
   else await readContext(call,{signer:owner.address,authorizer:{keyId:owner.keyId,publicKey:owner.publicKey},historical:{number:b.number,hash:b.hash},now});
  }
  const again=await block(call,b.number);
  if(again.number!==b.number||again.hash!==b.hash||again.timestamp!==b.timestamp||await chainId(call)!==137n)fail('mismatch');
  fresh(b,now());
  return freeze({chainId:'137',safe,account,version:'1.5.0',singleton:SINGLETON,owners,threshold:Number(threshold),nonce,guard:Z,fallback:Z,modules:[],block:{...b},liveVerified:false});
 };
 try{return await Promise.race([run(),new Promise((_,reject)=>{total=setTimeout(()=>reject(new ReadError('unavailable')),60000);})]);}
 catch(e){throw e instanceof ReadError?e:new ReadError('unavailable');}
 finally{active=false;clearTimeout(total);}
}
