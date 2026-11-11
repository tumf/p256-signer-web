'use strict';
// Offline re-judging of real fork evidence; mutation controls never create positive execution evidence.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {webcrypto,createHash} = require('node:crypto');
const changes = ['add', 'remove', 're-add', 'self-remove'];
const controls = ['cross-signer-domain-only', 'last-key-web', 'removed-key-web', 'unauthorized-web',
  'removed-key-fresh-nonce', 'unauthorized-fresh-nonce', 'last-key-contract', 'direct-EOA-add'];
const names = (rows, expected) => assert.deepEqual(rows.map(x => x.name).sort(), [...expected].sort(), 'required inventory');
const stable = ({block, ...state}) => state;
const keys = state => [...state.keys].sort((a,b) => a.keyId.localeCompare(b.keyId));
async function judge(e) {
  const km = await import('../../key-model.js');
  const {matchingEvent} = await import('../../key-controller.js');
  const U = (await import('../../vendor/ethers.js')).default.utils;
  const errors = new U.Interface(['error FailedOp(uint256 opIndex,string reason)', 'error NotEntryPointOrSelf()', 'error CannotRemoveLastSigner()']);
  const {signer, other, keys: publicKeys} = e.identities, [k1,k2,outsider] = publicKeys, account = e.chain.account;
  assert.notEqual(signer,other);assert.equal(e.chain.chainId,137);assert.equal(e.nativeApprovals,4);
  names(e.changes,changes);names(e.controls,controls);
  names(e.screenshots,[...changes.map(n => n+'-verified'),'last-key-web','removed-key-web','unauthorized-web']);
  const unchanged = s => assert.deepEqual(stable(s),stable(e.otherInitial),'other Signer changed');
  unchanged(e.otherFinal);
  async function signature(sig,H) {
    assert.match(sig,/^0x[0-9a-f]{192}$/);assert.match(H,/^0x[0-9a-f]{64}$/);
    const key = publicKeys.find(k => km.keyIdHash(k.keyId) === sig.slice(0,66));assert.ok(key,'unknown signature key');
    assert.equal(km.keyIdOf(key.publicKey),key.keyId);assert.ok(km.isPoint(key.publicKey));
    const s=BigInt('0x'+sig.slice(-64));assert.ok(s>0n&&s<=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n/2n);
    const pub = await webcrypto.subtle.importKey('raw',U.arrayify(key.publicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
    assert.ok(await webcrypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,U.arrayify('0x'+sig.slice(66)),U.arrayify(H)),'invalid retained signature');
    return key.keyId;
  }
  function stateBlock(s,b) {assert.equal(BigInt(s.block.number),BigInt(b.number));assert.equal(s.block.hash,b.hash);assert.equal(BigInt(s.block.timestamp),BigInt(b.timestamp));}
  function receipt(row,op,sig,success) {
    const {receipt:r,transaction:t,block:b} = row;
    assert.equal(r.status,'0x1');assert.equal(r.transactionHash,t.hash);assert.equal(r.blockHash,b.hash);assert.equal(t.blockHash,b.hash);
    assert.equal(r.blockNumber,b.number);assert.equal(t.blockNumber,b.number);assert.equal(t.from.toLowerCase(),account);assert.equal(t.to.toLowerCase(),km.ENTRYPOINT);assert.equal(BigInt(t.value),0n);
    assert.equal(t.input,km.handleOpsCall(op,sig,account));assert.equal(BigInt(t.chainId),137n);
    for (const l of r.logs) {assert.equal(l.transactionHash,r.transactionHash);assert.equal(l.blockHash,b.hash);assert.equal(l.blockNumber,b.number);assert.equal(l.removed,false);}
    const event = matchingEvent(r.logs.map(l=>({...l,address:l.address.toLowerCase()})),{userOpHash:km.userOpHash(op),signer:op.sender,signerNonce:op.nonce});
    assert.ok(event);assert.equal(event.success,success);return event;
  }
  for (const c of e.changes) {
    const {envelope,result} = c.approval, op = envelope.body, sig = result.signerSignature;
    assert.equal(op.sender,signer);assert.equal(op.nonce,c.before.nonce);assert.equal(result.typedDataHash,km.typedDataHash(op));
    assert.equal(await signature(sig,km.typedDataHash(op)),c.authorizer);assert.equal(envelope.keyId,c.authorizer);
    assert.ok(c.before.keys.some(k=>k.keyId===c.authorizer));
    const isAdd = c.name==='add'||c.name==='re-add';assert.equal(c.mode,isAdd?'add':'remove');
    assert.equal(c.selfRemoval,c.name==='self-remove');assert.equal(c.authorizer,c.name==='add'?k1.keyId:k2.keyId);
    assert.equal(c.target,c.name==='add'||c.name==='self-remove'?k2.keyId:k1.keyId);
    const change = isAdd?{kind:'add',key:publicKeys.find(k=>k.keyId===c.target)}:{kind:'remove',keyId:c.target};
    const planned=km.planChange({signer,nonce:BigInt(c.before.nonce),keys:c.before.keys,change,fees:km.innerFees('100','1')});
    assert.deepEqual(op,planned.operation);
    const expected=isAdd?[...c.before.keys,change.key]:c.before.keys.filter(k=>k.keyId!==c.target);
    assert.deepEqual(keys(c.after),keys({keys:expected}));assert.equal(BigInt(c.after.nonce),BigInt(c.before.nonce)+1n);unchanged(c.other);
    const ev=receipt(c,op,sig,true);const row=isAdd?'KW27':'KW28';
    assert.equal(c.view.row,row);assert.equal(c.view.record.status,'succeeded');assert.deepEqual(c.view.record.operation,op);
    assert.equal(c.view.record.userOpHash,km.userOpHash(op));assert.deepEqual(keys(c.view.outcome),keys(c.after));
    assert.equal(c.reload.row,row);assert.equal(c.reload.callsBefore,1);assert.equal(c.reload.callsAfter,1);
    assert.equal(c.walletCalls.length,1);assert.deepEqual(c.walletCalls[0].transaction,{from:account,to:km.ENTRYPOINT,data:km.handleOpsCall(op,sig,account),value:'0x0',chainId:'0x89'});
    assert.equal(BigInt(c.view.costs.actualGasCost),ev.actualGasCost);
    assert.equal(BigInt(c.view.costs.outerCost),BigInt(c.receipt.gasUsed)*BigInt(c.receipt.effectiveGasPrice));
  }
  const last=e.controls.find(c=>c.name==='last-key-contract');
  for(const [a,b] of [[e.changes[0].after,e.changes[1].before],[e.changes[1].after,last.before],[last.after,e.changes[2].before],[e.changes[2].after,e.changes[3].before]]){assert.deepEqual(keys(a),keys(b));assert.equal(a.nonce,b.nonce);}
  const v=e.revocation;assert.ok(v.validBefore.startsWith('0x1626ba7e'));assert.ok(v.invalidAfter.startsWith('0xffffffff'));assert.equal(v.stillValidOther,v.validBefore);
  assert.equal(BigInt(v.afterBlock.number),BigInt(e.changes[1].after.block.number));assert.equal(v.afterBlock.hash,e.changes[1].after.block.hash);assert.ok(BigInt(v.afterBlock.number)>BigInt(v.beforeBlock.number));assert.equal(await signature(v.signature,v.hash),k1.keyId);
  const p=e.crossSignerPositive;assert.equal(p.result,'0x');assert.equal(p.operation.sender,other);assert.equal(p.targetHash,km.typedDataHash(p.operation));assert.notEqual(p.sourceHash,p.targetHash);
  const types={PackedUserOperation:[['sender','address'],['nonce','uint256'],['initCode','bytes'],['callData','bytes'],['accountGasLimits','bytes32'],['preVerificationGas','uint256'],['gasFees','bytes32'],['paymasterAndData','bytes'],['entryPoint','address']].map(([name,type])=>({name,type}))};
  const typedHash=address=>U._TypedDataEncoder.hash({name:'HybridDeleGator',version:'1',chainId:137,verifyingContract:address},types,{...p.operation,entryPoint:km.ENTRYPOINT});
  assert.equal(p.sourceHash,typedHash(signer));assert.equal(p.targetHash,typedHash(other));
  const abi=new U.Interface(['function getPackedUserOperationTypedDataHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)) view returns(bytes32)']);
  const op=p.operation;assert.equal(p.hashCall,abi.encodeFunctionData('getPackedUserOperationTypedDataHash',[[op.sender,op.nonce,op.initCode,op.callData,op.accountGasLimits,op.preVerificationGas,op.gasFees,op.paymasterAndData,'0x']]));
  assert.equal(p.request.data,km.handleOpsCall(p.operation,p.signature,account));assert.equal(await signature(p.signature,p.targetHash),k1.keyId);
  assert.equal(await signature(p.wrongSignature,p.sourceHash),k1.keyId);assert.ok(p.sourceValid.startsWith('0x1626ba7e'));
  for(const s of [p.sourceState,p.targetState]) {stateBlock(s,p.block);assert.ok(s.keys.some(k=>k.keyId===k1.keyId));}
  for (const c of e.controls) {
    if(c.name.endsWith('-web')) {
      assert.equal(c.walletCalls,0);assert.equal(c.nativeApprovals,0);
      assert.equal(c.row,c.name==='last-key-web'?'KW07-last':'KW04');
      if(c.name==='last-key-web')assert.deepEqual(c.state.keys,[k2]);
      else assert.ok(!c.state.keys.some(k=>k.keyId===c.authorizer));
      continue;
    }
    if(c.name==='last-key-contract') {
      const op=c.operation;assert.equal(op.nonce,c.before.nonce);assert.deepEqual(c.before.keys,[k2]);
      assert.equal(op.callData,km.executeCall(signer,km.removeKeyCall(k2.keyId)));assert.equal(await signature(c.signature,km.typedDataHash(op)),k2.keyId);
      receipt(c,op,c.signature,false);assert.equal(c.innerSuccess,false);
      const logs=c.receipt.logs.filter(l=>l.address.toLowerCase()===km.ENTRYPOINT&&l.topics[0]===U.id('UserOperationRevertReason(bytes32,address,uint256,bytes)'));
      assert.equal(logs.length,1);assert.equal(logs[0].topics[1],km.userOpHash(op));assert.equal(logs[0].topics[2],'0x'+'00'.repeat(12)+signer.slice(2));
      const [nonce,data]=U.defaultAbiCoder.decode(['uint256','bytes'],logs[0].data);assert.equal(nonce.toString(),op.nonce);
      assert.equal(data,c.revertData);assert.equal(errors.parseError(data).name,'CannotRemoveLastSigner');
      assert.deepEqual(c.after.keys,c.before.keys);assert.equal(BigInt(c.after.nonce),BigInt(c.before.nonce)+1n);continue;
    }
    stateBlock(c.before,c.block);stateBlock(c.after,c.block);stateBlock(c.other,c.block);stateBlock(c.targetState,c.block);
    assert.deepEqual(c.before,c.after);unchanged(c.other);assert.equal(c.request.from,account);
    const decoded=errors.parseError(c.error.data);assert.equal(decoded.name,c.decoded.name);
    if(c.name==='direct-EOA-add') {
      assert.equal(decoded.name,'NotEntryPointOrSelf');assert.equal(c.request.to,signer);assert.equal(c.request.data,km.addKeyCall(outsider.publicKey,outsider.keyId));continue;
    }
    assert.equal(decoded.name,'FailedOp');assert.equal(decoded.args.opIndex.toString(),'0');assert.equal(decoded.args.reason,'AA24 signature error');
    assert.equal(c.decoded.reason,decoded.args.reason);assert.equal(c.operation.nonce,c.targetState.nonce);
    assert.equal(c.H,km.typedDataHash(c.operation));assert.equal(c.userOpHash,km.userOpHash(c.operation));assert.equal(c.request.to,km.ENTRYPOINT);
    assert.equal(c.request.data,km.handleOpsCall(c.operation,c.signature,account));
    const badKey=await signature(c.signature,c.signatureH), goodKey=await signature(c.positive.signature,c.H);
    assert.ok(c.targetState.keys.some(k=>k.keyId===goodKey));assert.equal(c.positive.result,'0x');
    assert.deepEqual(c.positive.request,{...c.request,data:km.handleOpsCall(c.operation,c.positive.signature,account)});
    if(c.name==='cross-signer-domain-only') {
      assert.equal(c.block.hash,p.block.hash);assert.deepEqual(c.operation,p.operation);assert.equal(c.signatureH,p.sourceHash);assert.equal(c.signature,p.wrongSignature);assert.equal(badKey,k1.keyId);
    } else {assert.equal(c.signatureH,c.H);assert.ok(!c.targetState.keys.some(k=>k.keyId===badKey));assert.equal(badKey,c.name==='removed-key-fresh-nonce'?k1.keyId:outsider.keyId);}
  }
  return true;
}
async function mutationChecks(e) {
  const mutations = [
    ...controls.map(name=>['missing/'+name,x=>{x.controls=x.controls.filter(c=>c.name!==name);}]),
    ...changes.map(name=>['missing/'+name,x=>{x.changes=x.changes.filter(c=>c.name!==name);}]),
    ['duplicate-control',x=>x.controls.push(x.controls[0])],
    ['foreign-block',x=>{x.controls.find(c=>c.name==='removed-key-fresh-nonce').block.hash='0x'+'00'.repeat(32);} ],
    ['missing-request',x=>{delete x.controls.find(c=>c.name==='unauthorized-fresh-nonce').request;}],
    ['changed-calldata',x=>{x.controls.find(c=>c.name==='unauthorized-fresh-nonce').request.data='0x';}],
    ['wrong-failure',x=>{x.controls.find(c=>c.name==='unauthorized-fresh-nonce').error.data='0x';}],
    ['AA23-not-signature',x=>{const c=x.controls.find(c=>c.name==='unauthorized-fresh-nonce');c.error.data=c.error.data.replace('41413234','41413233');c.decoded.reason='AA23 signature error';}],
    ['domain-input-changed',x=>{x.crossSignerPositive.hashCall='0x';}],
    ['last-key-reason',x=>{x.controls.find(c=>c.name==='last-key-contract').revertData='0x';}],
    ['domain-not-separated',x=>{x.crossSignerPositive.sourceHash=x.crossSignerPositive.targetHash;}],
    ['no-positive',x=>{x.controls.find(c=>c.name==='removed-key-fresh-nonce').positive.result=null;}],
    ['self-removal-not-proven',x=>{x.changes.find(c=>c.name==='self-remove').selfRemoval=false;}],
    ['inner-failure',x=>{x.changes[0].receipt.logs=x.changes[0].receipt.logs.slice(0,-1);} ],
    ['nonce-replay',x=>{x.controls.find(c=>c.name==='removed-key-fresh-nonce').operation.nonce='0';}],
    ['invalid-signature',x=>{x.controls.find(c=>c.name==='unauthorized-fresh-nonce').signature='0x'+'00'.repeat(96);} ],
    ['other-signer-changed',x=>{x.otherFinal.nonce='1';}],
    ['missing-screenshot',x=>x.screenshots.pop()]
  ];
  await judge(e);
  for(const [name,mutate] of mutations) {const bad=structuredClone(e);mutate(bad);await assert.rejects(()=>judge(bad),undefined,name+' accepted');}
  return {validAccepted:true,rejected:mutations.map(([name])=>name)};
}
function verifyFiles(e,filename) {
  const app=path.resolve(__dirname,'../..'), out=path.dirname(filename);
  const hash=f=>createHash('sha256').update(fs.readFileSync(f)).digest('hex');
  // The executed wallet is external: the pinned tarball and installed package code must be digested inputs, not only the facade.
  const {PACKAGE_INPUTS,PACKAGE_VERSION}=require('./fork-wallet.cjs');
  assert.equal(e.forkWalletPackage?.version,PACKAGE_VERSION);assert.deepEqual(e.forkWalletPackage.inputs,[...PACKAGE_INPUTS]);
  for(const p of PACKAGE_INPUTS)assert.ok(e.inputs[p],'missing package input '+p);
  for(const map of [e.inputs,e.bundledInputs]){assert.ok(Object.keys(map).length);for(const [p,h] of Object.entries(map)){const file=path.resolve(app,p);assert.ok(file.startsWith(app+path.sep));assert.equal(hash(file),h,'source mismatch: '+p);}}
  assert.equal(e.inputs['tests/support/key-fork-judge.cjs'],hash(__filename));assert.equal(e.scriptSHA256,hash(path.join(app,'tests/check-key-wallet-fork.cjs')));
  for(const s of e.screenshots){assert.match(s.name,/^[a-z-]+$/);assert.equal(hash(path.join(out,s.name+'.png')),s.sha256,'screenshot mismatch');}
  assert.equal(hash(path.join(out,'key-fork-page.js')),e.harnessSHA256);
}
module.exports={judge,mutationChecks,verifyFiles};
if(require.main===module) (async()=>{
  const filename=path.resolve(process.argv[2]);const e=JSON.parse(fs.readFileSync(filename));
  assert.equal(e.result,'PASS');assert.equal(e.reverted,true);assert.equal(e.childrenStopped,true);
  verifyFiles(e,filename);const checks=await mutationChecks(e);assert.deepEqual(e.judgeControls,checks);
  console.log('PASS offline evidence + '+checks.rejected.length+' mutation controls: '+filename);
})().catch(error=>{console.error(error);process.exitCode=1;});
