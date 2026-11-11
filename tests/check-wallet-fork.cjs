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
const {chromium} = require(APP+'/node_modules/playwright');
const guard = require(APP+'/tests/check-fork.cjs');
const oracle = require(APP+'/tests/support/oracle.cjs');
const sleep = ms => new Promise(r=>setTimeout(r,ms));
const freePort = () => new Promise((resolve,reject)=>{const s=net.createServer();s.on('error',reject);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
const evidence = {scope:'Built production registration page + injected mock wallet + native IndexedDB + real loopback Polygon fork. Not standard wallet or physical iPhone acceptance.', result:'UNKNOWN', deployments:[], screenshots:[], run:crypto.randomUUID()};
const OUT = path.resolve(APP, 'artifacts/wallet-fork', evidence.run);
fs.mkdirSync(OUT,{recursive:true});
const file = OUT+'/mock-fork-evidence.json';
const digest = p => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
evidence.scriptSHA256=digest(__filename);
// The injected wallet is the pinned external fork-wallet package: its tarball and installed code are digested, not only the facade.
const inputs=['tests/check-wallet-fork.cjs','tests/support/fork-wallet.cjs',...PACKAGE_INPUTS,'tests/check-fork.cjs','tests/support/oracle.cjs','model.js','chains.js','wallet.js','controller.js','attempt-store.js','app.js','ui.js','serve.py','dist/asset-manifest.json'];
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
function requireAdoption(v,winner,extraWalletCalls) {
 assert.equal(v.phase,'unknown');assert.equal(v.statusBusy,'false');assert.equal(v.attemptVisible,true);
 assert.ok(v.status.includes('別のタブまたはウィンドウで送信が始まっています'));
 assert.equal(v.sendDisabled,true);assert.equal(v.clearHidden,true);assert.equal(v.hashVisible,true);
 const record=JSON.parse(winner.raw);
 assert.equal(v.address,record.address);assert.equal(v.from,record.from);
 assert.deepEqual(v.stored,winner,'loser changed or did not observe the winning record');
 assert.equal(extraWalletCalls,0,'duplicate wallet call');
}
// Judge controls: no click / pending work, wrong identity, changed storage, enabled retry and an extra call all fail.
const sampleWinner={revision:1,raw:JSON.stringify({address:'test-address',from:'test-account'})};
const sample={phase:'unknown',statusBusy:'false',attemptVisible:true,status:'別のタブまたはウィンドウで送信が始まっています',sendDisabled:true,clearHidden:true,hashVisible:true,address:'test-address',from:'test-account',stored:sampleWinner};
requireAdoption(sample,sampleWinner,0);
for(const change of [{phase:'ready'},{statusBusy:'true'},{attemptVisible:false},{status:''},{sendDisabled:false},{clearHidden:false},{hashVisible:false},{address:'wrong'},{from:'wrong'},{stored:{...sampleWinner,revision:2}}]) assert.throws(()=>requireAdoption({...sample,...change},sampleWinner,0));
assert.throws(()=>requireAdoption(sample,sampleWinner,1));
evidence.judgeControls={validAccepted:true,invalidRejected:11};
let anvil,server,browser,snapshot,rpc,forkPort;
guard.requireNoCredentials(process.env);
(async()=>{
 forkPort=await freePort(); const webPort=await freePort();
 assert.notEqual(forkPort,webPort);
 const endpoint=guard.requireLoopback('http://127.0.0.1:'+forkPort);
 const origin='http://127.0.0.1:'+webPort;
 const source=guard.requireForkSource('https://polygon.drpc.org');
 let id=0;
 rpc=async(method,params=[])=>{const requestID=++id;const r=await fetch(endpoint,{method:'POST',redirect:'error',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:requestID,method,params}),signal:AbortSignal.timeout(15000)});assert.ok(r.ok,'RPC HTTP failure');const j=await r.json();assert.equal(j.jsonrpc,'2.0');assert.equal(j.id,requestID);assert.notEqual(Object.hasOwn(j,'result'),Object.hasOwn(j,'error'));if(j.error)throw Object.assign(new Error(j.error.message),{code:j.error.code});return j.result;};
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
 const proxy=JSON.parse(fs.readFileSync(APP+'/vendor/proxy.json')).bytecode;
 const {publicKey}=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const point='0x'+publicKey.export({format:'der',type:'spki'}).subarray(-65).toString('hex');
 const rows=[0,1].map(()=>{const salt='0x'+crypto.randomBytes(32).toString('hex');return {version:1,recipe:model.RECIPE,chainId:137,publicKey:point,keyID:crypto.createHash('sha256').update(Buffer.from(point.slice(2),'hex')).digest('hex'),salt,expectedAddress:oracle.derive(point,salt,proxy).address};});
 const plans=await Promise.all(rows.map(guard.productPlan));
 assert.notEqual(rows[0].salt,rows[1].salt);assert.notEqual(plans[0].address,plans[1].address);
 browser=await chromium.launch({headless:true});
 evidence.browser=browser.version();
 const context=await browser.newContext({viewport:{width:1280,height:950},serviceWorkers:'block'});
 await context.routeWebSocket('**/*',socket=>socket.close());
 evidence.websocketPolicy='all blocked';
 await context.route('**/*',r=>new URL(r.request().url()).origin===origin?r.continue():r.abort());
 const wallet=await installForkWallet(context,{endpoint,origin,account,
  validateTransaction(tx){const plan=plans.find(p=>p.transaction.data===tx.data);assert.ok(plan,'unexpected calldata');guard.requireProductTransaction(plan,tx);},
  async beforeSend(){
   ownsPort(anvil,forkPort);ownsPort(server,webPort);
   if(!wallet.submitted.length)assert.equal((await rpc('eth_getBlockByNumber',['latest',false])).hash,block.hash,'first send must start at pinned fork head');
  },
 });
 const {calls,submitted}=wallet;
 const page=await context.newPage();
 async function until(fn,label,p=page){for(let n=0;n<160;n++){alive(anvil);alive(server);if(await fn())return;await sleep(100);}throw new Error('timeout: '+label+'\n'+await p.locator('body').innerText());}
 async function shot(name,p=page){const pth=OUT+'/'+name+'.png';await p.screenshot({path:pth,fullPage:true});evidence.screenshots.push({name,sha256:digest(pth)});}
 async function view(p) {
  return p.evaluate(async()=>{
   const stored=await new Promise((resolve,reject)=>{
    const request=indexedDB.open('p256.registration.attempts',2);
    request.onupgradeneeded=()=>{request.transaction.abort();reject(new Error('expected existing attempt DB'));};
    request.onerror=()=>reject(request.error);request.onblocked=()=>reject(new Error('DB observation blocked'));
    request.onsuccess=()=>{const db=request.result;const tx=db.transaction('state','readonly');const get=tx.objectStore('state').get('signer:'+document.getElementById('plan-address').textContent.toLowerCase());
     tx.oncomplete=()=>{db.close();resolve(get.result);};tx.onabort=tx.onerror=()=>{db.close();reject(tx.error||new Error('DB observation failed'));};};
   });
   const $=id=>document.getElementById(id);const row=label=>[...$('attempt-list').querySelectorAll('dt')].find(e=>e.textContent===label)?.nextElementSibling?.textContent;
   return {phase:document.body.dataset.phase,status:$('attempt-status').textContent+'\n'+$('attempt-context-text').textContent,statusBusy:$('attempt-status').getAttribute('aria-busy'),attemptVisible:!$('attempt').hidden,sendDisabled:$('send').disabled,clearHidden:$('clear').hidden,hashVisible:!$('hash-form').hidden,address:row('予定アドレス'),from:row('送信元'),stored};
  });
 }
 async function open(p,row){await p.goto(origin+'/#registration='+Buffer.from(JSON.stringify(row)).toString('base64url'));if(await p.evaluate(()=>Boolean(location.hash)))await p.reload();await p.waitForFunction(()=>window.__registration?.ready);await until(()=>p.locator('#send').isVisible(),'connect available',p);await until(()=>p.locator('#send').isEnabled(),'connect enabled',p);assert.equal(await p.locator('#plan-address').innerText(),row.expectedAddress);assert.equal(await p.locator('#plan-salt').textContent(),row.salt);await p.locator('#send').click();await until(()=>p.locator('#inspect').isEnabled(),'inspect enabled',p);await p.locator('#payload-summary').click();await p.locator('#inspect').click();await p.locator('#payload-summary').click();}
 async function clear(){await until(()=>page.locator('#clear').isVisible(),'clear');await page.locator('#clear').click();await page.locator('#confirm-clear').click();await until(()=>page.locator('#attempt').isHidden(),'clear done');}
 async function success(p=page){await rpc('anvil_mine',['0x2']);await until(async()=> (await p.locator('#attempt-status').innerText()).startsWith('配備が完了しました。'),'success');}
 // First plan: definitive cancellation must submit nothing.
 await open(page,rows[0]);await until(()=>page.locator('#send').isEnabled(),'ready');
 wallet.setMode('reject');await page.locator('#send').click();await until(async()=> (await page.locator('#attempt-status').innerText()).startsWith('キャンセルしました。'),'rejected');
 assert.equal(submitted.length,0);evidence.rejection={walletCalls:calls.length,submitted:0};await shot('mock-rejected');await clear();
 // Real first deployment; then reload native saved attempt and verify no second send.
 await until(()=>page.locator('#send').isEnabled(),'ready again');wallet.setMode('approve');
 await page.locator('#send').click();await until(()=>Promise.resolve(submitted.length===1),'first submit');await success();await shot('mock-first-success');
 const before=calls.length;await page.reload();await page.waitForFunction(()=>window.__registration?.ready);await until(async()=> (await page.locator('#attempt-status').innerText()).startsWith('配備が完了しました。'),'reload');assert.equal(calls.length,before);
 evidence.reload={walletCallsUnchanged:true};
 await page.goto(origin+'/#registration='+Buffer.from(JSON.stringify(rows[0])).toString('base64url'));await until(()=>page.locator('#copy-address').isVisible(),'already deployed');assert.equal(calls.length,before);evidence.alreadyDeployed={sends:0};await shot('mock-already-deployed');
 // Second plan: competing pages share native IndexedDB; one admitted send at most. Drop response after mining.
 await open(page,rows[1]);await until(()=>page.locator('#send').isEnabled(),'second ready');
 const tab=await context.newPage();await open(tab,rows[1]);await until(()=>tab.locator('#send').isEnabled(),'tab ready');
 wallet.setMode('hold');await page.locator('#send').click();await until(()=>Promise.resolve(wallet.held),'held wallet');
 const count=calls.length;
 const winner=(await view(page)).stored;assert.equal(JSON.parse(winner.raw).state,'walletPending');
 assert.equal(await tab.locator('body').getAttribute('data-phase'),'ready');
 const beforeClick=await view(tab);assert.throws(()=>requireAdoption(beforeClick,winner,0));
 // Hold the losing tab's first send-time RPC. Zero calls during incomplete work must NOT pass the judge.
 let rpcPaused=false,releaseRPC;const rpcGate=new Promise(resolve=>{releaseRPC=resolve;});
 await tab.route(origin+'/rpc',async route=>{if(!rpcPaused){rpcPaused=true;await rpcGate;}await route.continue();});
 await tab.locator('#send').click({timeout:3000}); // A click failure is a test failure, not a success path.
 await until(()=>Promise.resolve(rpcPaused),'loser RPC entered',tab);
 const delayed=await view(tab);assert.equal(calls.length,count);assert.throws(()=>requireAdoption(delayed,winner,0));
 releaseRPC();
 await until(async()=>{const v=await view(tab);return v.phase==='unknown'&&v.statusBusy==='false'&&v.status.includes('別のタブまたはウィンドウで送信が始まっています');},'loser adopted retained attempt',tab);
 const adopted=await view(tab);requireAdoption(adopted,winner,calls.length-count);
 assert.deepEqual((await view(page)).stored,winner);await shot('mock-competing-tab-adopted',tab);
 evidence.competingTab={extraWalletCalls:calls.length-count,clicked:true,incompleteStatesRejected:{beforeClick:beforeClick.phase,rpcPaused:delayed.phase},adopted,winner};
 wallet.release('lost');await until(()=>Promise.resolve(submitted.length===2),'second submitted');
 await until(async()=> (await page.locator('body').getAttribute('data-phase'))==='unknown','unknown');assert.equal(calls.length,count);await shot('mock-unknown');
 await page.reload();await page.waitForFunction(()=>window.__registration?.ready);assert.equal(calls.length,count);
 await page.locator('#payload-summary').click();await page.locator('#manual-hash').fill(submitted[1]);await page.locator('#check-hash').click();await success();await page.locator('#payload-summary').click();await shot('mock-second-recovered');
 for(let i=0;i<2;i++){
  const tx=await rpc('eth_getTransactionByHash',[submitted[i]]);const receipt=await rpc('eth_getTransactionReceipt',[submitted[i]]);
  const readback=await model.readback(rpc,plans[i],'latest');assert.equal(readback.state,'deployed');assert.equal(receipt.status,'0x1');
  const decoded=oracle.decodeDeploy(tx.input,proxy);assert.equal(decoded.salt,rows[i].salt);assert.equal(tx.input,oracle.derive(point,rows[i].salt,proxy).calldata);
  evidence.deployments.push({handoff:rows[i],hash:submitted[i],receipt,readback,oracleCalldata:true});
 }
 evidence.retainedSuccess={scoped:true,noAutomaticResend:true};
 // Disconnect remains a product-path assertion; use a fresh undeployed public plan without clearing successes.
 const disconnectSalt='0x'+crypto.randomBytes(32).toString('hex');
 const disconnectRow={...rows[0],salt:disconnectSalt,expectedAddress:oracle.derive(point,disconnectSalt,proxy).address};
 const retained=(await view(page)).stored;
 await open(page,disconnectRow);
 await page.locator('#payload-summary').click();
 await until(()=>page.locator('#disconnect').isVisible(),'connected before disconnect control');
 await wallet.disconnect();
 await until(()=>page.locator('#disconnect').isHidden(),'product observed wallet disconnect');
 assert.equal(await page.locator('body').getAttribute('data-phase'),'disconnected');
 assert.equal(await page.locator('#send').innerText(),'ウォレットを接続');
 assert.equal(calls.length,count);assert.equal(submitted.length,2);
 const disconnected=await page.evaluate(async()=>({accounts:await window.ethereum.request({method:'eth_accounts'}),code:await window.ethereum.request({method:'eth_requestAccounts'}).then(()=>null,e=>e.code)}));
 assert.deepEqual(disconnected,{accounts:[],code:4900});
 evidence.productDisconnect={observed:true,phase:'disconnected',noAdditionalSend:true};evidence.disconnect=disconnected;
 await page.goto(origin+'/#registration='+Buffer.from(JSON.stringify(rows[1])).toString('base64url'));await page.reload();
 await page.waitForFunction(()=>window.__registration?.ready);
 await until(async()=> (await page.locator('body').getAttribute('data-phase'))==='success','retained success after disconnect');
 assert.deepEqual((await view(page)).stored,retained);

 assert.equal(submitted.length,2);assert.equal(calls.length,count);assert.equal(digest(__filename),evidence.scriptSHA256,'test changed during run');for(const [p,hash] of Object.entries(evidence.inputs))assert.equal(digest(path.join(APP,p)),hash,'input changed: '+p);evidence.walletCalls=calls;evidence.result='PASS';
})().catch(e=>{evidence.result='FAIL';evidence.error=e.message;console.error(e.message);process.exitCode=1;}).finally(async()=>{
 try{if(browser)await browser.close();if(snapshot&&rpc){ownsPort(anvil,forkPort);evidence.reverted=await rpc('evm_revert',[snapshot]);assert.equal(evidence.reverted,true);}}
 catch(e){evidence.result='FAIL';evidence.cleanupError=e.message;process.exitCode=1;}
 for(const child of [server,anvil])if(child){child.kill('SIGTERM');for(let i=0;i<50&&child.exitCode===null&&child.signalCode===null;i++)await sleep(100);if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');evidence.result='FAIL';evidence.cleanupError='child did not stop';process.exitCode=1;}}
 evidence.childrenStopped=[server,anvil].every(c=>!c||c.exitCode!==null||c.signalCode!==null);
 if(!evidence.childrenStopped){evidence.result='FAIL';evidence.cleanupError='child termination unconfirmed';process.exitCode=1;}
 fs.writeFileSync(file,JSON.stringify(evidence,(_,v)=>typeof v==='bigint'?v.toString():v,2)+'\n');
 console.log(evidence.result+': '+file);
});
