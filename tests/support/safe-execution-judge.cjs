'use strict';
// Pure offline predicates only: no RPC, signature verification, extraction or sending.
// expected is independent trusted intent; transactionHash is the independently retained submitted hash.
// ponytail: only native 1wei, <=8 owners, zero guard/fallback and no modules; extend with a reviewed profile.
// Evidence is an exact raw-field projection (tests document keys), not proof of RPC provenance/ancestry.
// Before state is at the inclusion parent; after state is at inclusion. Return true means predicate only.
const assert = require('node:assert/strict');
const {utils:U,constants:{AddressZero:ZERO}} = require('../../vendor/ethers.cjs');
const abi = new U.Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)']);
const fields = [['to','address'],['value','uint256'],['data','bytes'],['operation','uint8'],['safeTxGas','uint256'],['baseGas','uint256'],['gasPrice','uint256'],['gasToken','address'],['refundReceiver','address'],['nonce','uint256']];
const types = {SafeTx:fields.map(([name,type])=>({name,type}))};
const MAX = (1n<<256n)-1n;
function exact(v, keys) {
  assert.ok(v && Object.getPrototypeOf(v)===Object.prototype,'plain object required');
  assert.deepEqual(Reflect.ownKeys(v).sort(),keys.split(',').sort(),'exact schema');
  for(const d of Object.values(Object.getOwnPropertyDescriptors(v))) assert.ok('value' in d && d.enumerable,'data properties required');
}
function list(v,max) {
  assert.ok(Array.isArray(v) && Object.getPrototypeOf(v)===Array.prototype && v.length<=max,'bounded array');
  assert.deepEqual(Reflect.ownKeys(v),[...Array.from({length:v.length},(_,i)=>String(i)),'length'],'dense plain array');
  for(let i=0;i<v.length;i++) {const d=Object.getOwnPropertyDescriptor(v,String(i));assert.ok('value' in d && d.enumerable,'array data properties');}
  return v;
}
function uint(v) {
  assert.ok(typeof v==='string' && v.length<=78 && /^(0|[1-9][0-9]*)$/.test(v),'decimal uint256');
  const n=BigInt(v);assert.ok(n<=MAX,'uint256 overflow');return n;
}
function quantity(v) {
  assert.ok(typeof v==='string' && v.length<=66 && /^0x(0|[1-9a-f][0-9a-f]*)$/.test(v),'canonical hex quantity');
  const n=BigInt(v);assert.ok(n<=MAX,'uint256 overflow');return n;
}
function bytes(v, max=65536) {assert.ok(typeof v==='string' && v.length<=2+2*max && /^0x(?:[0-9a-f]{2})*$/.test(v),'bounded hex bytes');return v;}
function hash(v) {bytes(v,32);assert.equal(v.length,66,'hash length');return v;}
function addr(v,zero=false) {assert.ok(typeof v==='string' && /^0x[0-9a-fA-F]{40}$/.test(v),'address');const a=U.getAddress(v).toLowerCase();assert.ok(zero||a!==ZERO,'zero address');return a;}
function assertTransaction(request, expected) {
  exact(expected,'profile,from,body,signatureBytes,H');assert.equal(expected.profile,'native-1wei','unsupported profile');
  const b=expected.body;exact(b,'chainId,safe,tx');assert.equal(b.chainId,'137');
  const t=b.tx;exact(t,fields.map(([k])=>k).join(','));
  const from=addr(expected.from),safe=addr(b.safe),recipient=addr(t.to);
  assert.equal(new Set([from,safe,recipient]).size,3,'distinct identities');
  for(const [k,type] of fields) {if(type.startsWith('uint'))uint(t[k]);}
  assert.equal(t.value,'1');assert.equal(t.data,'0x');
  for(const k of ['operation','safeTxGas','baseGas','gasPrice'])assert.equal(t[k],'0','native refund profile');
  assert.equal(addr(t.gasToken,true),ZERO);assert.equal(addr(t.refundReceiver,true),ZERO);
  bytes(expected.signatureBytes,8192);assert.ok(expected.signatureBytes.length>2,'empty signature');
  assert.equal(hash(expected.H),U._TypedDataEncoder.hash({chainId:137,verifyingContract:safe},types,t),'trusted Safe hash');
  const hasFees=request && ['gas','maxFeePerGas','maxPriorityFeePerGas'].some(k=>Object.hasOwn(request,k));
  exact(request,'from,to,chainId,value,data'+(hasFees?',gas,maxFeePerGas,maxPriorityFeePerGas':''));
  if(hasFees) {
    const gas=quantity(request.gas),fee=quantity(request.maxFeePerGas),priority=quantity(request.maxPriorityFeePerGas);
    assert.ok(gas>0n && gas<=5000000n,'gas bound');assert.ok(fee<=1000000000000n && priority<=fee,'fee bound');
    assert.ok(gas*fee<=5000000000000000000n,'total fee bound');
  }
  assert.equal(addr(request.from),from);assert.equal(addr(request.to),safe);
  assert.equal(quantity(request.chainId),137n);assert.equal(quantity(request.value),0n);
  bytes(request.data);const decoded=abi.decodeFunctionData('execTransaction',request.data);
  assert.equal(abi.encodeFunctionData('execTransaction',decoded),request.data,'noncanonical calldata');
  const args=[t.to,t.value,t.data,t.operation,t.safeTxGas,t.baseGas,t.gasPrice,t.gasToken,t.refundReceiver,expected.signatureBytes];
  assert.equal(request.data,abi.encodeFunctionData('execTransaction',args),'exact expected calldata');
  return true;
}
const events = new U.Interface(['event ExecutionSuccess(bytes32 txHash,uint256 payment)','event ExecutionFailure(bytes32 txHash,uint256 payment)']);
function block(b) {exact(b,'number,hash,parentHash');quantity(b.number);hash(b.hash);hash(b.parentHash);assert.notEqual(b.hash,b.parentHash,'block identity');}
function assertOutcome(e, expected, transactionHash) {
  exact(e,'request,transaction,receipt,inclusion,recheckedInclusion,head,beforeBlock,afterBlock,before,after');
  assertTransaction(e.request,expected);hash(transactionHash);
  const {request:w,transaction:t,receipt:r,inclusion:b,recheckedInclusion:recheck,head,beforeBlock:bb,afterBlock:ab}=e;
  for(const v of [b,recheck,head,bb,ab])block(v);
  assert.deepEqual(recheck,b,'inclusion recheck');assert.deepEqual(ab,b,'after canonical inclusion');
  assert.equal(quantity(bb.number)+1n,quantity(b.number),'before must be parent');assert.equal(bb.hash,b.parentHash);
  assert.ok(quantity(head.number)>=quantity(b.number)+2n,'two block depth');
  assert.notEqual(head.hash,b.hash);assert.notEqual(head.hash,bb.hash);
  exact(t,'hash,from,to,input,value,chainId,blockHash,blockNumber,transactionIndex'+(Object.hasOwn(w,'gas')?',gas,maxFeePerGas,maxPriorityFeePerGas':''));
  exact(r,'transactionHash,from,to,blockHash,blockNumber,transactionIndex,status,gasUsed,effectiveGasPrice,logs');
  assert.equal(hash(t.hash),transactionHash);assert.equal(hash(r.transactionHash),transactionHash);
  assert.equal(addr(t.from),addr(w.from));assert.equal(addr(t.to),addr(w.to));
  assert.equal(addr(r.from),addr(w.from));assert.equal(addr(r.to),addr(w.to));
  assert.equal(bytes(t.input),w.data);assert.equal(quantity(t.value),quantity(w.value));assert.equal(quantity(t.chainId),137n);
  for(const v of [t,r]) {assert.equal(hash(v.blockHash),b.hash);assert.equal(quantity(v.blockNumber),quantity(b.number));quantity(v.transactionIndex);}
  assert.equal(t.transactionIndex,r.transactionIndex);assert.equal(quantity(r.status),1n);
  const used=quantity(r.gasUsed),price=quantity(r.effectiveGasPrice);assert.ok(used>0n,'actual gas used');assert.ok(used*price<=MAX,'gas cost overflow');
  if(Object.hasOwn(w,'gas')) {
    for(const k of ['gas','maxFeePerGas','maxPriorityFeePerGas']) {quantity(t[k]);assert.equal(t[k],w[k],'submitted fee mismatch');}
    assert.ok(used<=quantity(w.gas),'gas exceeds submitted');assert.ok(price<=quantity(w.maxFeePerGas),'price exceeds submitted');
  }
  list(r.logs,1024);let successes=0;const indexes=new Set();
  for(const l of r.logs) {
    exact(l,'address,topics,data,transactionHash,blockHash,blockNumber,transactionIndex,logIndex,removed');
    const address=addr(l.address);assert.equal(l.removed,false);
    assert.equal(hash(l.transactionHash),transactionHash);assert.equal(hash(l.blockHash),b.hash);
    assert.equal(quantity(l.blockNumber),quantity(b.number));assert.equal(quantity(l.transactionIndex),quantity(r.transactionIndex));
    const index=quantity(l.logIndex).toString();assert.ok(!indexes.has(index),'duplicate log index');indexes.add(index);
    list(l.topics,4).forEach(hash);bytes(l.data);
    if(address!==addr(w.to))continue;
    const success=events.getEventTopic('ExecutionSuccess'),failure=events.getEventTopic('ExecutionFailure');
    if(l.topics[0]!==success && l.topics[0]!==failure)continue;
    const name=l.topics[0]===success?'ExecutionSuccess':'ExecutionFailure',decoded=events.decodeEventLog(name,l.data,l.topics);
    const encoded=events.encodeEventLog(events.getEvent(name),decoded);assert.deepEqual(l.topics,encoded.topics);assert.equal(l.data,encoded.data,'canonical event');
    assert.equal(name,'ExecutionSuccess','Safe ExecutionFailure');assert.equal(decoded.txHash,expected.H,'event Safe hash');assert.equal(decoded.payment.toString(),'0','refund payment');successes++;
  }
  assert.equal(successes,1,'unique Safe success');
  const identities=[addr(expected.from),addr(expected.body.safe),addr(expected.body.tx.to)];
  for(const [s,anchor] of [[e.before,bb],[e.after,ab]]) {
    exact(s,'block,nonce,balances,owners,threshold,guard,fallback,modules');exact(s.block,'number,hash');
    assert.equal(quantity(s.block.number),quantity(anchor.number));assert.equal(hash(s.block.hash),anchor.hash);
    quantity(s.nonce);exact(s.balances,identities.join(','));Object.values(s.balances).forEach(quantity);
    list(s.owners,8);assert.ok(s.owners.length>0,'owners required');
    const owners=s.owners.map(a=>addr(a));assert.equal(new Set(owners).size,owners.length,'duplicate owners');assert.ok(!owners.includes(identities[1]),'Safe self owner');
    const threshold=quantity(s.threshold);assert.ok(threshold>0n && threshold<=BigInt(owners.length),'threshold');
    assert.equal(addr(s.guard,true),ZERO,'unsupported guard');assert.equal(addr(s.fallback,true),ZERO,'unsupported fallback');
    list(s.modules,0);
  }
  for(const k of ['owners','threshold','guard','fallback','modules'])assert.deepEqual(e.after[k],e.before[k],'configuration changed: '+k);
  assert.equal(quantity(e.before.nonce),uint(expected.body.tx.nonce),'before nonce');
  assert.equal(quantity(e.after.nonce),quantity(e.before.nonce)+1n,'after nonce');
  const [payer,safe,recipient]=identities, before=e.before.balances,after=e.after.balances;
  assert.equal(quantity(before[safe])-quantity(after[safe]),1n,'Safe delta');
  assert.equal(quantity(after[recipient])-quantity(before[recipient]),1n,'recipient delta');
  assert.equal(quantity(before[payer])-quantity(after[payer]),used*price,'payer gas cost');
  return true;
}
module.exports={assertTransaction,assertOutcome};
