'use strict';
// Synthetic RPC-shaped fixtures are unit-only, never chain/receipt verification evidence.
const assert = require('node:assert/strict');
const {test} = require('node:test');
const ethers = require('../vendor/ethers.cjs');
const U = ethers.utils, Z = ethers.constants.AddressZero;
const abi = new U.Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)']);
const types = {SafeTx: [['to','address'],['value','uint256'],['data','bytes'],['operation','uint8'],['safeTxGas','uint256'],['baseGas','uint256'],['gasPrice','uint256'],['gasToken','address'],['refundReceiver','address'],['nonce','uint256']].map(([name,type])=>({name,type}))};
const A = n => '0x'+String(n).repeat(40), H = n => '0x'+String(n).repeat(64);
function fixture() {
  const tx = {to:A(3),value:'1',data:'0x',operation:'0',safeTxGas:'0',baseGas:'0',gasPrice:'0',gasToken:Z,refundReceiver:Z,nonce:'9007199254740993'};
  const body = {chainId:'137',safe:A(2),tx}, signatureBytes='0x'+'ab'.repeat(65);
  const expected = {profile:'native-1wei',from:A(1),body,signatureBytes,H:U._TypedDataEncoder.hash({chainId:137,verifyingContract:body.safe},types,tx)};
  return {expected,request:{from:A(1),to:A(2),chainId:'0x89',value:'0x0',data:encode(tx,signatureBytes)}};
}
function encode(t,s) {return abi.encodeFunctionData('execTransaction',[t.to,t.value,t.data,t.operation,t.safeTxGas,t.baseGas,t.gasPrice,t.gasToken,t.refundReceiver,s]);}
const judge = () => require('./support/safe-execution-judge.cjs');
function rejects(name, mutate) {test(name,()=>{const f=fixture();mutate(f);assert.throws(()=>judge().assertTransaction(f.request,f.expected));});}
test('unit-only exact native request accepts separately supplied trusted intent without mutation',()=>{
  const f=fixture(), copy=structuredClone(f);assert.equal(judge().assertTransaction(f.request,f.expected),true);assert.deepEqual(f,copy);
});
for(const [key,value] of [['from',A(4)],['to',A(4)],['chainId','0x1'],['value','0x1'],['data','0x']]) rejects('request binds '+key,f=>{f.request[key]=value;});
for(const key of ['from','to','chainId','value','data']) rejects('request requires '+key,f=>{delete f.request[key];});
for(const key of ['liveVerified','safeTxHash','signatureBytes','gasPrice','nonce','accessList']) rejects('export/extra key rejected '+key,f=>{f.request[key]=false;});
rejects('unsupported profile',f=>{f.expected.profile='addOwner';});
rejects('hash not derived from untrusted calldata',f=>{f.expected.H=H(5);});
rejects('expected signature exact',f=>{f.expected.signatureBytes='0x12';});
rejects('trailing ABI bytes',f=>{f.request.data+='00';});
rejects('noncanonical dynamic ABI offset',f=>{const data=f.request.data;f.request.data=data.slice(0,10+64*2)+('0'.repeat(61)+'160')+data.slice(10+64*3);});
for(const [key,value] of [['to',A(2)],['value','2'],['data','0x12'],['operation','1'],['safeTxGas','1'],['baseGas','1'],['gasPrice','1'],['gasToken',A(4)],['refundReceiver',A(4)]]) rejects('inner profile rejects '+key,f=>{f.expected.body.tx[key]=value;f.request.data=encode(f.expected.body.tx,f.expected.signatureBytes);f.expected.H=U._TypedDataEncoder.hash({chainId:137,verifyingContract:A(2)},types,f.expected.body.tx);});
for(const [name,mutate] of [
  ['zero payer',f=>{f.expected.from=f.request.from=Z;}],['same payer/Safe',f=>{f.expected.from=f.request.from=A(2);}],
  ['same recipient/payer',f=>{f.expected.body.tx.to=A(1);}],['same recipient/Safe',f=>{f.expected.body.tx.to=A(2);}],
  ['zero Safe',f=>{f.expected.body.safe=f.request.to=Z;}],['zero recipient',f=>{f.expected.body.tx.to=Z;}],
  ['wrong expected chain',f=>{f.expected.body.chainId='1';}],['nonce rounding',f=>{f.expected.body.tx.nonce='9007199254740992';}],
  ['uint256 overflow',f=>{f.expected.body.tx.nonce=String(1n<<256n);}],['numeric nonce',f=>{f.expected.body.tx.nonce=7;}],
  ['negative nonce',f=>{f.expected.body.tx.nonce='-1';}],['leading zero nonce',f=>{f.expected.body.tx.nonce='01';}],
  ['malformed address',f=>{f.request.from='0x1';}],['odd bytes',f=>{f.request.data='0x1';}],
  ['oversized bytes',f=>{f.request.data='0x'+'00'.repeat(65537);}],['empty signature',f=>{f.expected.signatureBytes='0x';}],
  ['malformed hash',f=>{f.expected.H='0x12';}],['expected extra field',f=>{f.expected.extra=true;}]
]) rejects(name,mutate);
for(const value of [137, '137','0x089','0x','-0x1','0X89']) rejects('raw chain quantity '+JSON.stringify(value),f=>{f.request.chainId=value;});
for(const value of [0,'0','0x00','0x1.0']) rejects('raw value quantity '+JSON.stringify(value),f=>{f.request.value=value;});
rejects('missing trusted intent',f=>{f.expected=undefined;});
rejects('missing request',f=>{f.request=undefined;});
rejects('array request',f=>{f.request=[];});
rejects('symbol request key',f=>{f.request[Symbol('hidden')]=1;});
rejects('nonenumerable request key',f=>{Object.defineProperty(f.request,'hidden',{value:1});});
rejects('inherited request fields',f=>{f.request=Object.create(f.request);});
rejects('request getter',f=>{Object.defineProperty(f.request,'data',{get(){return encode(f.expected.body.tx,f.expected.signatureBytes);},enumerable:true});});
test('max uint256 nonce is exact',()=>{const f=fixture();f.expected.body.tx.nonce=String((1n<<256n)-1n);f.expected.H=U._TypedDataEncoder.hash({chainId:137,verifyingContract:A(2)},types,f.expected.body.tx);assert.equal(judge().assertTransaction(f.request,f.expected),true);});
const fees = {gas:'0x4c4b40',maxFeePerGas:'0xe8d4a51000',maxPriorityFeePerGas:'0xe8d4a51000'};
test('optional complete EIP1559 bounds accept inclusive maximum and zero fees',()=>{
  const f=fixture();Object.assign(f.request,fees);assert.equal(judge().assertTransaction(f.request,f.expected),true);
  f.request.maxFeePerGas=f.request.maxPriorityFeePerGas='0x0';assert.equal(judge().assertTransaction(f.request,f.expected),true);
});
for(const k of Object.keys(fees)) rejects('fee trio missing '+k,f=>{Object.assign(f.request,fees);delete f.request[k];});
for(const [k,v] of [['gas','0x0'],['gas','0x4c4b41'],['maxFeePerGas','0xe8d4a51001'],['maxPriorityFeePerGas','0xe8d4a51001'],['gas',1],['maxFeePerGas','1'],['maxPriorityFeePerGas','0x00'],['gas','0x'+ 'f'.repeat(65)]]) rejects('fee bound '+k+' '+v,f=>{Object.assign(f.request,fees,{[k]:v});});
rejects('priority exceeds maxfee',f=>{Object.assign(f.request,fees,{maxFeePerGas:'0x1'});});
const events = new U.Interface(['event ExecutionSuccess(bytes32 txHash,uint256 payment)','event ExecutionFailure(bytes32 txHash,uint256 payment)']);
const q = n=>'0x'+BigInt(n).toString(16);
function outcomeFixture() {
  const f=fixture(), txHash=H(9), block={number:'0x64',hash:H(6),parentHash:H(5)};
  const transaction={hash:txHash,from:f.request.from,to:f.request.to,input:f.request.data,value:'0x0',chainId:'0x89',blockHash:block.hash,blockNumber:block.number,transactionIndex:'0x0'};
  const ev=events.encodeEventLog(events.getEvent('ExecutionSuccess'),[f.expected.H,0]);
  const log={address:A(2),...ev,transactionHash:txHash,blockHash:block.hash,blockNumber:block.number,transactionIndex:'0x0',logIndex:'0x0',removed:false};
  const receipt={transactionHash:txHash,from:A(1),to:A(2),blockHash:block.hash,blockNumber:block.number,transactionIndex:'0x0',status:'0x1',gasUsed:'0x5208',effectiveGasPrice:'0x2',logs:[log]};
  const before={block:{number:'0x63',hash:H(5)},nonce:q(f.expected.body.tx.nonce),balances:{[A(1)]:q(1n<<200n),[A(2)]:'0x64',[A(3)]:'0x0'},owners:[A(4)],threshold:'0x1',guard:Z,fallback:Z,modules:[]};
  const after=structuredClone(before);after.block={number:block.number,hash:block.hash};after.nonce=q(BigInt(f.expected.body.tx.nonce)+1n);after.balances[A(1)]=q((1n<<200n)-42000n);after.balances[A(2)]='0x63';after.balances[A(3)]='0x1';
  return {...f,txHash,evidence:{request:f.request,transaction,receipt,inclusion:block,recheckedInclusion:structuredClone(block),head:{number:'0x66',hash:H(8),parentHash:H(7)},beforeBlock:{number:'0x63',hash:H(5),parentHash:H(4)},afterBlock:structuredClone(block),before,after}};
}
function outcomeReject(name,mutate) {test('outcome rejects '+name,()=>{const f=outcomeFixture();mutate(f);assert.throws(()=>judge().assertOutcome(f.evidence,f.expected,f.txHash));});}
test('unit-only raw successful receipt and canonical anchors accept exact submitted transaction',()=>{
  const f=outcomeFixture(),copy=structuredClone(f);assert.equal(judge().assertOutcome(f.evidence,f.expected,f.txHash),true);assert.deepEqual(f,copy);
});
for(const key of ['request','transaction','receipt','inclusion','recheckedInclusion','head','beforeBlock','afterBlock','before','after']) outcomeReject('missing '+key,f=>{delete f.evidence[key];});
for(const [part,key,val] of [
 ['transaction','hash',H(1)],['transaction','from',A(4)],['transaction','to',A(4)],['transaction','input','0x'],['transaction','value','0x1'],['transaction','chainId','0x1'],['transaction','blockHash',H(4)],['transaction','blockNumber','0x65'],['transaction','transactionIndex','0x1'],
 ['receipt','transactionHash',H(1)],['receipt','from',A(4)],['receipt','to',A(4)],['receipt','blockHash',H(4)],['receipt','blockNumber','0x65'],['receipt','transactionIndex','0x1'],['receipt','status','0x0'],['receipt','status',true],['receipt','gasUsed','0x0'],['receipt','gasUsed','-1'],['receipt','effectiveGasPrice',2],
 ['inclusion','hash',H(1)],['inclusion','number','0x65'],['inclusion','parentHash',H(1)],['recheckedInclusion','hash',H(1)],['recheckedInclusion','number','0x65'],['recheckedInclusion','parentHash',H(1)],
 ['head','number','0x65'],['head','hash','0x12'],['head','parentHash','0x12'],['beforeBlock','number','0x62'],['beforeBlock','hash',H(1)],['afterBlock','number','0x65'],['afterBlock','hash',H(1)],['afterBlock','parentHash',H(1)]
]) outcomeReject(part+'.'+key,f=>{f.evidence[part][key]=val;});
for(const part of ['transaction','receipt','inclusion','recheckedInclusion','head','beforeBlock','afterBlock']) {
 for(const key of Object.keys(outcomeFixture().evidence[part])) outcomeReject('missing '+part+'.'+key,f=>{delete f.evidence[part][key];});
}
outcomeReject('missing independent transaction hash',f=>{f.txHash=undefined;});
outcomeReject('malformed independent transaction hash',f=>{f.txHash='0x1';});
outcomeReject('request mismatch',f=>{f.evidence.request.value='0x1';});
outcomeReject('metadata as evidence',f=>{f.evidence.liveVerified=true;});
outcomeReject('state override',f=>{f.evidence.stateOverride={};});
outcomeReject('status only',f=>{f.evidence.receipt.logs=[];});
outcomeReject('nonce only',f=>{f.evidence.receipt.status='0x0';});
outcomeReject('predecoded success',f=>{f.evidence.receipt.logs=[{success:true}];});
for(const [key,value] of [['address',A(4)],['topics',[]],['topics',[H(1)]],['data','0x'],['data','0x12'],['removed',true],['removed','false'],['transactionHash',H(1)],['blockHash',H(1)],['blockNumber','0x65'],['transactionIndex','0x1'],['logIndex','0x00']]) outcomeReject('raw log '+key+' '+JSON.stringify(value),f=>{f.evidence.receipt.logs[0][key]=value;});
for(const key of Object.keys(outcomeFixture().evidence.receipt.logs[0])) outcomeReject('missing log '+key,f=>{delete f.evidence.receipt.logs[0][key];});
for(const [name,event,hash,payment] of [['ExecutionFailure','ExecutionFailure',null,0],['wrong event H','ExecutionSuccess',H(1),0],['nonzero refund','ExecutionSuccess',null,1]]) outcomeReject(name,f=>{Object.assign(f.evidence.receipt.logs[0],events.encodeEventLog(events.getEvent(event),[hash||f.expected.H,payment]));});
outcomeReject('extra event topic',f=>{f.evidence.receipt.logs[0].topics.push(H(1));});
outcomeReject('trailing event data',f=>{f.evidence.receipt.logs[0].data+='00';});
outcomeReject('duplicate target',f=>{const l=structuredClone(f.evidence.receipt.logs[0]);l.logIndex='0x1';f.evidence.receipt.logs.push(l);});
outcomeReject('Safe failure alongside success',f=>{const l=structuredClone(f.evidence.receipt.logs[0]);Object.assign(l,events.encodeEventLog(events.getEvent('ExecutionFailure'),[H(1),0]));l.logIndex='0x1';f.evidence.receipt.logs.push(l);});
test('unrelated valid raw event is not Safe success or failure',()=>{const f=outcomeFixture(),l=structuredClone(f.evidence.receipt.logs[0]);l.address=A(4);Object.assign(l,events.encodeEventLog(events.getEvent('ExecutionFailure'),[H(1),0]));l.logIndex='0x1';f.evidence.receipt.logs.push(l);assert.equal(judge().assertOutcome(f.evidence,f.expected,f.txHash),true);});
test('submitted bounded EIP1559 transaction accepts actual gas and price',()=>{const f=outcomeFixture();Object.assign(f.request,fees);Object.assign(f.evidence.transaction,fees);assert.equal(judge().assertOutcome(f.evidence,f.expected,f.txHash),true);});
for(const [part,key,value] of [['receipt','gasUsed','0x4c4b41'],['receipt','effectiveGasPrice','0xe8d4a51001'],['transaction','gas','0x5208'],['transaction','maxFeePerGas','0x2'],['transaction','maxPriorityFeePerGas','0x2']]) outcomeReject('submitted fee '+part+'.'+key,f=>{Object.assign(f.request,fees);Object.assign(f.evidence.transaction,fees);f.evidence[part][key]=value;});
for(const part of ['before','after']) {
 for(const key of Object.keys(outcomeFixture().evidence[part])) outcomeReject('missing '+part+'.'+key,f=>{delete f.evidence[part][key];});
 for(const [key,val] of [['nonce','0x7'],['nonce',7],['nonce','0x00'],['nonce',q(1n<<256n)],['threshold','0x0'],['threshold','0x2'],['threshold',1],['owners',[]],['owners',[A(4),A(4)]],['owners',[Z]],['owners',[A(2)]],['guard',A(4)],['fallback',A(4)],['modules',[A(4)]],['modules',null],['balances',{}]]) outcomeReject(part+'.'+key+' '+JSON.stringify(val),f=>{f.evidence[part][key]=val;});
 for(const key of ['number','hash']) outcomeReject('missing '+part+'.block.'+key,f=>{delete f.evidence[part].block[key];});
 outcomeReject(part+' block hash',f=>{f.evidence[part].block.hash=H(1);});
 outcomeReject(part+' block number',f=>{f.evidence[part].block.number='0x62';});
 outcomeReject(part+' state extra',f=>{f.evidence[part].override=true;});
 outcomeReject(part+' config malformed',f=>{f.evidence[part].guard='0x1';});
 for(const a of [A(1),A(2),A(3)]) {
  outcomeReject('missing '+part+' balance '+a,f=>{delete f.evidence[part].balances[a];});
  outcomeReject('wrong '+part+' balance '+a,f=>{f.evidence[part].balances[a]=q(BigInt(f.evidence[part].balances[a])+1n);});
  for(const value of [0,'0','0x00','0x-1',q(1n<<256n)]) outcomeReject('malformed '+part+' balance '+a+' '+value,f=>{f.evidence[part].balances[a]=value;});
 }
 outcomeReject(part+' extra balance identity',f=>{f.evidence[part].balances[A(4)]='0x0';});
}
outcomeReject('changed owners',f=>{f.evidence.after.owners=[A(5)];});
outcomeReject('changed valid threshold',f=>{f.evidence.before.owners=f.evidence.after.owners=[A(4),A(5)];f.evidence.after.threshold='0x2';});
outcomeReject('nonce not advanced',f=>{f.evidence.after.nonce=f.evidence.before.nonce;});
outcomeReject('nonce increment precision',f=>{f.evidence.after.nonce=q(BigInt(f.evidence.after.nonce)+1n);});
outcomeReject('Safe lacks one wei',f=>{f.evidence.before.balances[A(2)]='0x0';});
outcomeReject('gas payer loss not rounded',f=>{f.evidence.after.balances[A(1)]=q(BigInt(f.evidence.after.balances[A(1)])+1n);});
outcomeReject('gas product uint256 overflow',f=>{f.evidence.receipt.gasUsed=q((1n<<256n)-1n);f.evidence.receipt.effectiveGasPrice='0x2';});
test('configuration unchanged with multiple owners is accepted',()=>{const f=outcomeFixture();for(const s of [f.evidence.before,f.evidence.after]){s.owners=[A(4),A(5)];s.threshold='0x2';}assert.equal(judge().assertOutcome(f.evidence,f.expected,f.txHash),true);});
test('zero effective gas price exact zero payer loss is accepted',()=>{const f=outcomeFixture();f.evidence.receipt.effectiveGasPrice='0x0';f.evidence.after.balances[A(1)]=f.evidence.before.balances[A(1)];assert.equal(judge().assertOutcome(f.evidence,f.expected,f.txHash),true);});
outcomeReject('sparse owners',f=>{f.evidence.before.owners=f.evidence.after.owners=Array(1);});
outcomeReject('ambiguous owner array property',f=>{f.evidence.before.owners.extra=true;f.evidence.after.owners.extra=true;});
outcomeReject('sparse extra raw topics',f=>{const l=structuredClone(f.evidence.receipt.logs[0]);l.address=A(4);l.logIndex='0x1';l.topics=Array(1);f.evidence.receipt.logs.push(l);});
outcomeReject('ambiguous raw log array property',f=>{f.evidence.receipt.logs.override=true;});
for(const part of ['before','after']) for(const key of ['owners','modules']) outcomeReject('ambiguous '+part+' '+key+' property',f=>{f.evidence[part][key].override=true;});
test('outcome rejects accessor evidence before reading it',()=>{const f=outcomeFixture();let reads=0;Object.defineProperty(f.evidence,'request',{enumerable:true,get(){reads++;return f.request;}});assert.throws(()=>judge().assertOutcome(f.evidence,f.expected,f.txHash));assert.equal(reads,0);});
test('identical eight unique owners accept and identical nine exceed the owner bound',()=>{
  const f=outcomeFixture(),owners=Array.from({length:9},(_,i)=>'0x'+(i+16).toString(16).padStart(40,'0'));
  for(const s of [f.evidence.before,f.evidence.after])s.owners=owners.slice(0,8);
  assert.equal(judge().assertOutcome(f.evidence,f.expected,f.txHash),true);
  for(const s of [f.evidence.before,f.evidence.after])s.owners.push(owners[8]);
  assert.throws(()=>judge().assertOutcome(f.evidence,f.expected,f.txHash),/bounded array/);
});
test('Success and unrelated event accept distinct log indexes but reject a duplicate index',()=>{
  const f=outcomeFixture(),success=f.evidence.receipt.logs[0],unrelated=structuredClone(success);
  unrelated.address=A(4);Object.assign(unrelated,events.encodeEventLog(events.getEvent('ExecutionFailure'),[H(1),0]));unrelated.logIndex='0x1';
  f.evidence.receipt.logs.push(unrelated);
  assert.equal(judge().assertOutcome(f.evidence,f.expected,f.txHash),true);
  unrelated.logIndex=success.logIndex;
  assert.throws(()=>judge().assertOutcome(f.evidence,f.expected,f.txHash),/duplicate log index/);
});
