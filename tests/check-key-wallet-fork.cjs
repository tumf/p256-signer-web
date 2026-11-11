'use strict';
// Operational test only. Injected EIP-1193 wallet; real built page, native IndexedDB, real isolated Anvil.
const fs = require('node:fs');
const crypto = require('node:crypto');
const net = require('node:net');
const {spawn, execFileSync} = require('node:child_process');
const assert = require('node:assert/strict');
const path = require('node:path');
const APP = path.resolve(__dirname, '..');
const {installForkWallet, PACKAGE_INPUTS, PACKAGE_VERSION} = require('./support/fork-wallet.cjs');
const {judge, mutationChecks} = require('./support/key-fork-judge.cjs');
const {chromium} = require(APP+'/node_modules/playwright');
const guard = require(APP+'/tests/check-fork.cjs');
const oracle = require(APP+'/tests/support/oracle.cjs');
const sleep = ms => new Promise(r=>setTimeout(r,ms));
const freePort = () => new Promise((resolve,reject)=>{const s=net.createServer();s.on('error',reject);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
const evidence = {scope:'Production key-change renderer/controller/reader/session/IndexedDB with test bootstrap and software native peer, mock wallet, real owned Polygon fork. No live relay, physical authentication or standard wallet acceptance.', result:'UNKNOWN', deployments:[], screenshots:[], run:crypto.randomUUID()};
const OUT = path.resolve(APP, 'artifacts/key-wallet-fork', evidence.run);
fs.mkdirSync(OUT,{recursive:true});
const file = OUT+'/key-fork-evidence.json';
const digest = p => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
evidence.scriptSHA256=digest(__filename);
// The injected wallet is the pinned external fork-wallet package: its tarball and installed code are digested, not only the facade.
const inputs=['tests/check-key-wallet-fork.cjs','tests/check-wallet-fork.cjs','tests/support/fork-wallet.cjs',...PACKAGE_INPUTS,'tests/check-fork.cjs','tests/support/oracle.cjs','model.js','chains.js','wallet.js','controller.js','attempt-store.js','app.js','ui.js','serve.py','key-change.js','key-controller.js','key-model.js','key-reader.js','key-session.js','key-attempt-store.js','package.json','package-lock.json','build.mjs','tests/support/key-fork-page.mjs','tests/support/key-fixtures.mjs','tests/support/key-fork-judge.cjs','dist/asset-manifest.json'];
const assetManifest=JSON.parse(fs.readFileSync(path.join(APP,'dist/asset-manifest.json')));
for(const [asset,hash] of Object.entries(assetManifest.files))assert.equal(digest(path.join(APP,'dist',asset)),hash,'built asset mismatch: '+asset);
inputs.push(...Object.keys(assetManifest.files).map(asset=>'dist/'+asset));
evidence.inputs=Object.fromEntries(inputs.map(p=>[p,digest(path.join(APP,p))]));
evidence.forkWalletPackage={version:PACKAGE_VERSION,inputs:PACKAGE_INPUTS};
evidence.head=execFileSync('git',['rev-parse','HEAD'],{cwd:APP,encoding:'utf8'}).trim();
evidence.dirty=execFileSync('git',['status','--porcelain'],{cwd:APP,encoding:'utf8'});
function alive(child) {
 assert.ok(child && child.pid && !child.launchError && child.exitCode === null && child.signalCode === null && !child.killed,'owned child is not running');
 process.kill(child.pid,0);
}
function ownsPort(child,port) {
 alive(child);
 const output=execFileSync('/usr/sbin/lsof',['-nP','-a','-iTCP:'+port,'-sTCP:LISTEN','-Fp'],{encoding:'utf8'});
 assert.deepEqual([...new Set(output.split('\n').filter(s=>s.startsWith('p')).map(s=>Number(s.slice(1))))],[child.pid],'listener is not the owned child');
 alive(child);
}
let anvil,server,browser,snapshot,rpc,forkPort;
guard.requireNoCredentials(process.env);
(async()=>{
 forkPort=await freePort(); const webPort=await freePort();
 assert.notEqual(forkPort,webPort);
 const endpoint=guard.requireLoopback('http://127.0.0.1:'+forkPort);
 const origin='http://127.0.0.1:'+webPort;
 const source=guard.requireForkSource('https://polygon.drpc.org');
 let id=0;
 rpc=async(method,params=[])=>{const requestID=++id;const r=await fetch(endpoint,{method:'POST',redirect:'error',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:requestID,method,params}),signal:AbortSignal.timeout(15000)});assert.ok(r.ok,'RPC HTTP failure');const j=await r.json();assert.equal(j.jsonrpc,'2.0');assert.equal(j.id,requestID);assert.notEqual(Object.hasOwn(j,'result'),Object.hasOwn(j,'error'));if(j.error)throw Object.assign(new Error(j.error.message),{code:j.error.code,data:j.error.data});return j.result;};
 anvil=spawn('anvil',[...guard.ANVIL_ARGS,'--port',String(forkPort),'--fork-url',source],{env:{PATH:process.env.PATH,HOME:process.env.HOME},stdio:'ignore'});
 anvil.on('error',error=>{anvil.launchError=error;});
 let version;
 for(let n=0;n<60;n++){try{version=await rpc('web3_clientVersion');break;}catch{await sleep(300);}}
 assert.ok(version,'Anvil not ready');guard.requireClient(version);guard.requireChain(await rpc('eth_chainId'));
 ownsPort(anvil,forkPort);
 const block=await rpc('eth_getBlockByNumber',['0x'+guard.FORK_BLOCK.toString(16),false]);
 assert.equal(block.hash,'0x464d98ef2bc90b455ce7dc52344bda4c95ccf395d523f02a7054a9a155d79729');
 const initialLatest=await rpc('eth_getBlockByNumber',['latest',false]);
 assert.equal(initialLatest.hash,block.hash);assert.equal(BigInt(initialLatest.number),BigInt(guard.FORK_BLOCK));
 snapshot=await rpc('evm_snapshot');const [account]=await rpc('eth_accounts');
 evidence.chain={version,chainId:137,forkBlock:guard.FORK_BLOCK,hash:block.hash,account,initialLatest:initialLatest.number};
 server=spawn('python3',['serve.py'],{cwd:APP,env:{PATH:process.env.PATH,HOME:process.env.HOME,REGISTRATION_PORT:String(webPort),POLYGON_RPC_URL:endpoint},stdio:'ignore'});
 server.on('error',error=>{server.launchError=error;});
 let ready=false;for(let n=0;n<50;n++){try{const r=await fetch(origin+'/config.json');if(r.ok){ready=true;break;}}catch{}await sleep(100);}assert.ok(ready,'Web not ready');
 ownsPort(server,webPort);evidence.children={anvil:anvil.pid,server:server.pid,portsOwned:true};

 const model=await import(APP+'/model.js');
 const km=await import(APP+'/key-model.js');
 const {readContext}=await import(APP+'/key-reader.js');
 const {matchingEvent}=await import(APP+'/key-controller.js');
 const fixture=await import(APP+'/tests/support/key-fixtures.mjs');
 const U=(await import(APP+'/vendor/ethers.js')).default.utils;
 const errors=new U.Interface(['error FailedOp(uint256 opIndex,string reason)','error NotEntryPointOrSelf()','error CannotRemoveLastSigner()']);
 const makeKey=()=>fixture.softwareKey(BigInt('0x'+crypto.randomBytes(31).toString('hex')));
 const k1=makeKey(),k2=makeKey(),outsider=makeKey(); // In-memory ephemeral test keys, never recorded.
 const revocationH='0x'+crypto.randomBytes(32).toString('hex');
 const revocationSignature=U.hexConcat([km.keyIdHash(k1.keyId),await fixture.signRaw(k1,revocationH)]);
 const sigABI=new U.Interface(['function isValidSignature(bytes32,bytes) view returns(bytes4)']);
 const proxy=JSON.parse(fs.readFileSync(APP+'/vendor/proxy.json')).bytecode;
 const rows=[0,1].map(()=>{const salt='0x'+crypto.randomBytes(32).toString('hex');return {version:1,recipe:model.RECIPE,chainId:137,publicKey:k1.publicKey,keyID:k1.keyId,salt,expectedAddress:oracle.derive(k1.publicKey,salt,proxy).address};});
 const plans=await Promise.all(rows.map(guard.productPlan));
 assert.notEqual(plans[0].address,plans[1].address);
 async function receipt(hash){for(let n=0;n<100;n++){const rc=await rpc('eth_getTransactionReceipt',[hash]);if(rc)return rc;await sleep(100);}throw new Error('receipt timeout');}
 let lastControlData=null;
 function requireSetup(tx,label){
  if(label==='deploy'){const plan=plans.find(p=>p.transaction.data===tx.data);assert.ok(plan);assert.deepEqual(tx,plan.transaction);return;}
  if(label==='local fork EntryPoint prefund'||label==='other local prefund'){
   const address=label==='other local prefund'?other:signer;
   assert.deepEqual(tx,{to:km.ENTRYPOINT,data:U.id('depositTo(address)').slice(0,10)+'00'.repeat(12)+address.slice(2),value:'0x'+(10n**18n).toString(16)});return;
  }
  assert.equal(label,'compiler-bypassing last-key negative control');assert.ok(lastControlData);
  assert.deepEqual(tx,{to:km.ENTRYPOINT,data:lastControlData,gas:'0x7a1200'});
 }
 requireSetup(plans[0].transaction,'deploy');
 for(const bad of [{...plans[0].transaction,value:'0x1'},{...plans[0].transaction,to:account},{...plans[0].transaction,gas:'0x1'}])assert.throws(()=>requireSetup(bad,'deploy'));
 assert.throws(()=>requireSetup(plans[0].transaction,'unknown'));
 evidence.setupJudgeControls={valid:1,invalidRejected:4};
 async function setup(tx,label){requireSetup(tx,label);ownsPort(anvil,forkPort);guard.requireClient(await rpc('web3_clientVersion'));guard.requireChain(await rpc('eth_chainId'));ownsPort(anvil,forkPort);const hash=await rpc('eth_sendTransaction',[{from:account,...tx}]);const rc=await receipt(hash);assert.equal(rc.status,'0x1',label);evidence.setup??=[];evidence.setup.push({label,transaction:await rpc('eth_getTransactionByHash',[hash]),receipt:rc});return rc;}
 for(const plan of plans)await setup({...plan.transaction},'deploy');
 const [signer,other]=plans.map(p=>p.address.toLowerCase());
 evidence.identities={signer,other,keys:[k1,k2,outsider].map(({keyId,publicKey})=>({keyId,publicKey}))};
 const now=()=>Math.floor(Date.now()/1000);
 const publicState=async(address,block=null)=>{const s=await readContext(rpc,{signer:address,now,historical:block?{number:BigInt(block.number),hash:block.hash}:null});return {...s,nonce:s.nonce.toString(),deposit:s.deposit.toString()};};
 const keyIDs=s=>s.keys.map(k=>k.keyId).sort();
 await rpc('evm_setNextBlockTimestamp',[now()]);await rpc('evm_mine');
 await setup({to:km.ENTRYPOINT,data:U.id('depositTo(address)').slice(0,10)+'00'.repeat(12)+other.slice(2),value:'0x'+(10n**18n).toString(16)},'other local prefund');
 const initialOther=await publicState(other);
 const revocationCall=sigABI.encodeFunctionData('isValidSignature',[revocationH,revocationSignature]);
 const revocationBeforeBlock=await rpc('eth_getBlockByNumber',['latest',false]);
 const validBefore=await rpc('eth_call',[{to:signer,data:revocationCall},revocationBeforeBlock.number]);
 const initialKeys=await publicState(signer);assert.deepEqual(keyIDs(initialKeys),[k1.keyId]);assert.equal(initialKeys.nonce,'0');
 assert.deepEqual(keyIDs(initialOther),[k1.keyId]);assert.equal(initialOther.nonce,'0');
 assert.equal(sigABI.decodeFunctionResult('isValidSignature',validBefore)[0],'0x1626ba7e');
 async function unchangedOther(block=null){const s=await publicState(other,block);const {block:_,...a}=s,{block:__,...b}=initialOther;assert.deepEqual(a,b);return s;}
 await setup({to:km.ENTRYPOINT,data:U.id('depositTo(address)').slice(0,10)+'00'.repeat(12)+signer.slice(2),value:'0x'+(10n**18n).toString(16)},'local fork EntryPoint prefund');
 const binding='0x'+crypto.randomBytes(32).toString('hex');
 let authorizer=k1,expectedChange=null,expectedTx=null;
 const approvals=[];evidence.controls=[];
 async function nativeContext(){const state=await readContext(rpc,{signer,authorizer,now});return fixture.contextWire({signer,key:authorizer,binding,chain:{keys:state.keys,nonce:state.nonce,blockNumber:state.block.number,blockHash:state.block.hash}});}
 const esbuild=require(APP+'/node_modules/esbuild');
 const bundle=await esbuild.build({absWorkingDir:APP,entryPoints:['tests/support/key-fork-page.mjs'],bundle:true,format:'esm',write:false,metafile:true,platform:'browser',target:['es2022'],logLevel:'silent',define:{'process.env.NODE_ENV':'"production"',global:'globalThis'}});
 const harness=bundle.outputFiles[0].text;
 evidence.bundledInputs=Object.fromEntries(Object.keys(bundle.metafile.inputs).map(p=>[p,digest(path.resolve(APP,p))]));
 evidence.harnessSHA256=crypto.createHash('sha256').update(harness).digest('hex');fs.writeFileSync(OUT+'/key-fork-page.js',harness);
 browser=await chromium.launch({headless:true});evidence.browser=browser.version();
 async function pageFor(key){
  authorizer=key;
  const context=await browser.newContext({viewport:{width:1280,height:950},serviceWorkers:'block'});
  await context.routeWebSocket('**/*',s=>s.close());
  await context.route('**/*',async route=>{const url=new URL(route.request().url());if(url.origin!==origin)return route.abort();if(url.pathname==='/key-change.js')return route.fulfill({body:harness,contentType:'text/javascript'});await route.continue();});
  await context.addInitScript(({signer})=>{window.__KEY_CHANGE_HARNESS__=true;window.__keyFork={signer};},{signer});
  await context.exposeBinding('__keyForkNative',async(source,q)=>{
   assert.equal(new URL(source.frame.url()).origin,origin);
   if(q.method==='context')return nativeContext();
   assert.equal(q.method,'sign');assert.ok(expectedChange);
   const e=JSON.parse(q.envelope),state=await readContext(rpc,{signer,authorizer,now});
   const planned=km.planChange({signer,nonce:state.nonce,keys:state.keys,change:expectedChange,fees:km.innerFees('100','1')});
   assert.deepEqual(e.body,planned.operation);assert.equal(e.signer,signer);assert.equal(e.keyId,authorizer.keyId);
   const result=await fixture.nativeSign({envelope:q.envelope,key:authorizer,binding});
   const op=planned.operation;
   const args=[op.sender,op.nonce,op.initCode,op.callData,op.accountGasLimits,op.preVerificationGas,op.gasFees,op.paymasterAndData,'0x'];
   for(const [to,fn,want] of [[signer,'getPackedUserOperationTypedDataHash',km.typedDataHash(op)],[km.ENTRYPOINT,'getUserOpHash',km.userOpHash(op)]]){
    const data=new U.Interface([`function ${fn}((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)) view returns(bytes32)`]).encodeFunctionData(fn,[args]);
    assert.equal(await rpc('eth_call',[{to,data},'latest']),want);
   }
   expectedTx={from:account.toLowerCase(),to:km.ENTRYPOINT,data:km.handleOpsCall(op,result.signerSignature,account),value:'0x0',chainId:'0x89'};
   approvals.push({envelope:e,result});return result;
  });
  const wallet=await installForkWallet(context,{endpoint,origin,account,validateTransaction(tx){assert.ok(expectedTx);assert.deepEqual({...tx,from:tx.from.toLowerCase()},expectedTx);},beforeSend:async()=>{ownsPort(anvil,forkPort);ownsPort(server,webPort);}});
  const page=await context.newPage();page.on('pageerror',e=>{evidence.pageErrors??=[];evidence.pageErrors.push(e.message);});
  await page.goto(origin+'/key-change.html');await page.waitForFunction(()=>window.__keyForkReady);
  return {page,context,wallet};
 }
 async function row(page,want){try{await page.waitForFunction(w=>document.querySelector('main').dataset.row===w,want,{timeout:20000});}catch{throw new Error('expected '+want+'; '+await page.locator('main').getAttribute('data-row')+' '+await page.locator('body').innerText());}}
 async function shot(page,name){const p=OUT+'/'+name+'.png';await page.screenshot({path:p,fullPage:true});evidence.screenshots.push({name,sha256:digest(p)});}
 async function inspect(page,key){await page.locator('#anchor').fill(fixture.anchorText(signer,key));await page.locator('#inspect').click();await page.waitForFunction(()=>!['KW01','KW03'].includes(document.querySelector('main').dataset.row));}
 async function change(page,key,target,mode){
  await inspect(page,key);await page.locator('#mode-'+mode).check();
  if(mode==='add')await page.locator('#bare-key').fill(fixture.bareKeyText(target));
  else await page.locator('#remove-choices input[value="'+target.keyId+'"]').check();
  await page.locator('#fee-max').fill('100');await page.locator('#fee-priority').fill('1');
 }
 async function execute(key,target,mode,name=mode){
  const before=await publicState(signer),x=await pageFor(key),{page,wallet}=x;
  expectedChange=mode==='add'?{kind:'add',key:{keyId:target.keyId,publicKey:target.publicKey}}:{kind:'remove',keyId:target.keyId};
  await change(page,key,target,mode);await page.locator('#connect').click();await row(page,'KW11');await page.locator('#preview').click();await page.waitForFunction(()=>['KW12','KW13'].includes(document.querySelector('main').dataset.row));const selfRemoval=await page.evaluate(()=>window.__keyForkView().selfRemoval);assert.equal(selfRemoval,mode==='remove'&&key.keyId===target.keyId);await page.locator('#sign').click();await page.waitForFunction(()=>!document.querySelector('#verified').hidden);
  await page.locator('#wallet-choices input[value="legacy"]').check();await page.locator('#wallet-connect').click();await page.locator('#send').click();
  await page.waitForFunction(()=>window.__keyForkView().attempt.record?.transactionHash);
  assert.equal(wallet.submitted.length,1);await rpc('anvil_mine',['0x2']);await page.locator('#reconcile').click();await row(page,mode==='add'?'KW27':'KW28');
  const after=await publicState(signer);assert.equal(BigInt(after.nonce),BigInt(before.nonce)+1n);
  const expected=mode==='add'?[...keyIDs(before),target.keyId].sort():keyIDs(before).filter(id=>id!==target.keyId);assert.deepEqual(keyIDs(after),expected);
  const hash=wallet.submitted[0],rc=await receipt(hash),transaction=await rpc('eth_getTransactionByHash',[hash]),block=await rpc('eth_getBlockByNumber',[rc.blockNumber,false]);assert.equal(rc.status,'0x1');assert.equal(rc.blockHash,block.hash);assert.equal(transaction.blockHash,rc.blockHash);
  const a=approvals.at(-1),op=a.envelope.body;
  const event=matchingEvent(rc.logs.map(l=>({address:l.address.toLowerCase(),topics:l.topics,data:l.data})),{userOpHash:km.userOpHash(op),signer,signerNonce:op.nonce});assert.equal(event.success,true);
  const otherState=await unchangedOther();const view=await page.evaluate(()=>{const v=window.__keyForkView();return {row:v.row,record:v.attempt.record,outcome:v.attempt.outcome,costs:v.costs};});
  evidence.changes??=[];evidence.changes.push({name,mode,authorizer:key.keyId,target:target.keyId,selfRemoval,before,after,other:otherState,transaction,receipt:rc,block,view,approval:a,walletCalls:wallet.calls});await shot(page,name+'-verified');
  const count=wallet.calls.length;await page.reload();await page.waitForFunction(()=>window.__keyForkReady);assert.equal(wallet.calls.length,count);await page.locator('#reconcile').click();await row(page,mode==='add'?'KW27':'KW28');assert.equal(wallet.calls.length,count);
  evidence.changes.at(-1).reload={row:await page.locator('main').getAttribute('data-row'),callsBefore:count,callsAfter:wallet.calls.length};
  await x.context.close();return a;
 }
 await execute(k1,k2,'add');
 // Same exact operation, both Signers still register k1; change ONLY the EIP-712 domain.
 const domainBlock=await rpc('eth_getBlockByNumber',['latest',false]);
 const foreign=await direct(k1,other,undefined,domainBlock),op=foreign.op;
 const hashABI=new U.Interface(['function getPackedUserOperationTypedDataHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)) view returns(bytes32)']);
 const hashCall=hashABI.encodeFunctionData('getPackedUserOperationTypedDataHash',[[op.sender,op.nonce,op.initCode,op.callData,op.accountGasLimits,op.preVerificationGas,op.gasFees,op.paymasterAndData,'0x']]);
 const targetHash=await rpc('eth_call',[{to:other,data:hashCall},domainBlock.number]),sourceHash=await rpc('eth_call',[{to:signer,data:hashCall},domainBlock.number]);
 assert.equal(targetHash,km.typedDataHash(op));assert.notEqual(sourceHash,targetHash);
 assert.ok((await publicState(signer)).keys.some(k=>k.keyId===k1.keyId));assert.ok((await publicState(other)).keys.some(k=>k.keyId===k1.keyId));
 const positiveRequest={from:account,to:km.ENTRYPOINT,data:km.handleOpsCall(op,foreign.signature,account),gas:'0x7a1200'};
 const positive=await rpc('eth_call',[positiveRequest,domainBlock.number]);assert.equal(positive,'0x');
 const wrongSignature=U.hexConcat([km.keyIdHash(k1.keyId),await fixture.signRaw(k1,sourceHash)]);
 const sourceValid=await rpc('eth_call',[{to:signer,data:sigABI.encodeFunctionData('isValidSignature',[sourceHash,wrongSignature])},domainBlock.number]);
 assert.equal(sigABI.decodeFunctionResult('isValidSignature',sourceValid)[0],'0x1626ba7e');
 evidence.crossSignerPositive={operation:op,signature:foreign.signature,result:positive,request:positiveRequest,block:domainBlock,sourceState:await publicState(signer,domainBlock),targetState:await publicState(other,domainBlock),hashCall,targetHash,sourceHash,wrongSignature,sourceValid};
 await rejected('cross-signer-domain-only',km.ENTRYPOINT,km.handleOpsCall(op,wrongSignature,account),{op,signature:wrongSignature,signatureH:sourceHash,positiveSignature:foreign.signature},domainBlock);

 await execute(k2,k1,'remove'); // Added key can authorize, old key is actually removed.
 const current=await publicState(signer);assert.deepEqual(keyIDs(current),[k2.keyId]);
 const nativeCount=approvals.length;assert.equal(nativeCount,2);
 evidence.nativeApprovals=nativeCount;
 const revocationAfterBlock=await rpc('eth_getBlockByNumber',['latest',false]);
 const invalidAfter=await rpc('eth_call',[{to:signer,data:revocationCall},revocationAfterBlock.number]);
 assert.equal(sigABI.decodeFunctionResult('isValidSignature',invalidAfter)[0],'0xffffffff');
 const stillValidOther=await rpc('eth_call',[{to:other,data:revocationCall},revocationAfterBlock.number]);
 assert.equal(sigABI.decodeFunctionResult('isValidSignature',stillValidOther)[0],'0x1626ba7e');
 evidence.revocation={beforeBlock:revocationBeforeBlock,afterBlock:revocationAfterBlock,hash:revocationH,signature:revocationSignature,call:revocationCall,validBefore,invalidAfter,stillValidOther,sameBytes:true,usesNoNonce:true};
 for(const [name,key,target,mode,want] of [['last-key-web',k2,k2,'remove','KW07-last'],['removed-key-web',k1,k1,'add','KW04'],['unauthorized-web',outsider,outsider,'add','KW04']]){
  const x=await pageFor(key);await inspect(x.page,key);
  if(name==='last-key-web'){
   await x.page.locator('#mode-remove').check();await x.page.locator('#remove-choices input[value="'+k2.keyId+'"]').check();await x.page.locator('#fee-max').fill('100');await x.page.locator('#fee-priority').fill('1');
  }
  await row(x.page,want);assert.equal(await x.page.locator('#sign').isEnabled(),false);assert.equal(await x.page.locator('#send').isEnabled(),false);assert.equal(x.wallet.calls.length,0);evidence.controls.push({name,row:want,authorizer:key.keyId,state:await publicState(signer),walletCalls:0,nativeApprovals:approvals.length-nativeCount});await shot(x.page,name);await x.context.close();
 }
 assert.equal(approvals.length,nativeCount,'web refusal unexpectedly signed');
 async function direct(key,address=signer,inner=km.addKeyCall(outsider.publicKey,outsider.keyId),block=null){
  const s=await publicState(address,block);const op={sender:address,nonce:s.nonce,initCode:'0x',callData:km.executeCall(address,inner),accountGasLimits:km.packHigh(700000n,300000n),preVerificationGas:'60000',gasFees:km.packHigh(1000000000n,100000000000n),paymasterAndData:'0x',signature:'0x'};
  const signature=U.hexConcat([km.keyIdHash(key.keyId),await fixture.signRaw(key,km.typedDataHash(op))]);return {op,signature};
 }
 async function rejected(name,to,data,proof=null,block=null){
  const at=block??await rpc('eth_getBlockByNumber',['latest',false]);
  const before=await publicState(signer,at),ob=await unchangedOther(at),targetState=await publicState(proof?.op.sender??signer,at),request={from:account,to,data,gas:'0x7a1200'};
  let positive=null,err;
  if(proof){assert.equal(proof.op.nonce,targetState.nonce);const req={...request,data:km.handleOpsCall(proof.op,proof.positiveSignature,account)};const result=await rpc('eth_call',[req,at.number]);assert.equal(result,'0x');positive={request:req,result,signature:proof.positiveSignature};}
  try{await rpc('eth_call',[request,at.number]);}catch(e){err={message:e.message,code:e.code,data:e.data};}
  assert.ok(err&&/^0x[0-9a-f]+$/i.test(err.data),name+' missing ABI error: '+JSON.stringify(err));
  const decoded=errors.parseError(err.data);assert.equal(decoded.name,proof?'FailedOp':'NotEntryPointOrSelf');
  if(proof){assert.equal(decoded.args.opIndex.toString(),'0');assert.equal(decoded.args.reason,'AA24 signature error');}
  const canonical=await rpc('eth_getBlockByNumber',[at.number,false]);assert.equal(canonical.hash,at.hash);
  const after=await publicState(signer,at);assert.deepEqual(after,before);await unchangedOther(at);
  evidence.controls.push({name,request,block:at,error:err,decoded:{name:decoded.name,...(proof?{index:'0',reason:decoded.args.reason}:{})},before,after,other:ob,targetState,positive,...(proof?{operation:proof.op,signature:proof.signature,H:km.typedDataHash(proof.op),userOpHash:km.userOpHash(proof.op),signatureH:proof.signatureH??km.typedDataHash(proof.op)}:{})});
 }
 for(const [name,key] of [['removed-key-fresh-nonce',k1],['unauthorized-fresh-nonce',outsider]]){const block=await rpc('eth_getBlockByNumber',['latest',false]),d=await direct(key,signer,undefined,block);d.positiveSignature=U.hexConcat([km.keyIdHash(k2.keyId),await fixture.signRaw(k2,km.typedDataHash(d.op))]);await rejected(name,km.ENTRYPOINT,km.handleOpsCall(d.op,d.signature,account),d,block);}
 const last=await direct(k2,signer,km.removeKeyCall(k2.keyId));
 lastControlData=km.handleOpsCall(last.op,last.signature,account);
 const rc=await setup({to:km.ENTRYPOINT,data:lastControlData,gas:'0x7a1200'},'compiler-bypassing last-key negative control');
 const ev=matchingEvent(rc.logs.map(l=>({address:l.address.toLowerCase(),topics:l.topics,data:l.data})),{userOpHash:km.userOpHash(last.op),signer,signerNonce:last.op.nonce});assert.equal(ev.success,false);
 const failureLogs=rc.logs.filter(l=>l.address.toLowerCase()===km.ENTRYPOINT&&l.topics[0]===U.id('UserOperationRevertReason(bytes32,address,uint256,bytes)'));
 assert.equal(failureLogs.length,1);assert.equal(failureLogs[0].topics[1],km.userOpHash(last.op));
 const [failedNonce,revertData]=U.defaultAbiCoder.decode(['uint256','bytes'],failureLogs[0].data);assert.equal(failedNonce.toString(),last.op.nonce);assert.equal(revertData,errors.encodeErrorResult('CannotRemoveLastSigner',[]));assert.equal(errors.parseError(revertData).name,'CannotRemoveLastSigner');assert.equal(failureLogs[0].topics[2],'0x'+'00'.repeat(12)+signer.slice(2));
 const afterLast=await publicState(signer);assert.deepEqual(afterLast.keys,current.keys);assert.equal(BigInt(afterLast.nonce),BigInt(current.nonce)+1n);await unchangedOther();evidence.controls.push({name:'last-key-contract',innerSuccess:false,revertData,operation:last.op,signature:last.signature,receipt:rc,transaction:await rpc('eth_getTransactionByHash',[rc.transactionHash]),block:await rpc('eth_getBlockByNumber',[rc.blockNumber,false]),before:current,after:afterLast});
 await rejected('direct-EOA-add',signer,km.addKeyCall(outsider.publicKey,outsider.keyId));
 // Separate from k2 removing k1: the authorizer k2 now removes itself through the same UI.
 await execute(k2,k1,'add','re-add');await execute(k2,k2,'remove','self-remove');
 assert.equal(approvals.length,4);evidence.nativeApprovals=approvals.length;assert.deepEqual(keyIDs(await publicState(signer)),[k1.keyId]);
 for(const [p,h] of Object.entries(evidence.bundledInputs))assert.equal(digest(path.resolve(APP,p)),h,'bundle input changed: '+p);
 assert.ok(!evidence.pageErrors?.length);evidence.otherInitial=initialOther;evidence.otherFinal=await unchangedOther();
 for(const [p,hash] of Object.entries(evidence.inputs))assert.equal(digest(path.join(APP,p)),hash,'input changed: '+p);
 evidence.websocketPolicy='all blocked';
 const serialized=JSON.parse(JSON.stringify(evidence,(_,v)=>typeof v==='bigint'?v.toString():v));
 await judge(serialized);evidence.judgeControls=await mutationChecks(serialized);evidence.result='PASS';

})().catch(e=>{evidence.result='FAIL';evidence.error=e.message;console.error(e.message);process.exitCode=1;}).finally(async()=>{
 try{if(browser)await browser.close();if(snapshot&&rpc){ownsPort(anvil,forkPort);evidence.reverted=await rpc('evm_revert',[snapshot]);assert.equal(evidence.reverted,true);}}
 catch(e){evidence.result='FAIL';evidence.cleanupError=e.message;process.exitCode=1;}
 for(const child of [server,anvil])if(child){child.kill('SIGTERM');for(let i=0;i<50&&child.exitCode===null&&child.signalCode===null;i++)await sleep(100);if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');evidence.result='FAIL';evidence.cleanupError='child did not stop';process.exitCode=1;}}
 evidence.childrenStopped=[server,anvil].every(c=>!c||c.exitCode!==null||c.signalCode!==null);
 if(!evidence.childrenStopped){evidence.result='FAIL';evidence.cleanupError='child termination unconfirmed';process.exitCode=1;}
 fs.writeFileSync(file,JSON.stringify(evidence,(_,v)=>typeof v==='bigint'?v.toString():v,2)+'\n');
 console.log(evidence.result+': '+file);
});
