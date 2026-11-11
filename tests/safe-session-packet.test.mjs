// Local integration: scripted SignClient, software test vector, no RPC or wallet.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {SafeSession} from '../safe-session.js';
import {Execution} from '../safe-execute.js';
import {CHAIN,METHODS} from '../safe-request-model.js';
import {VECTOR_CLOCK,expected,envelope,v} from './support/safe-fixtures.mjs';
const Z='0x'+'00'.repeat(20),clock=()=>VECTOR_CLOCK;
function setup(){
 const handlers={},rows=[],calls=[];
 const session={topic:'packet-local',expiry:2000000000,peer:{metadata:{url:expected.origin}},namespaces:{eip155:{accounts:[`${CHAIN}:${expected.signer}`],methods:[...METHODS],events:[]}}};
 const reply=structuredClone(v.result.result);
 const client={on(e,f){handlers[e]=f;},off(){},connect:async()=>({uri:'wc:local-double',approval:async()=>session}),disconnect:async()=>{},request:async p=>{calls.push(p);return p.request.method===METHODS[0]?structuredClone(v.context.result):reply;}};
 const store={save:async row=>{rows.push(structuredClone(row));}};
 return {s:new SafeSession(client,expected,clock,()=>{},store),rows,calls,reply,client,handlers,session};
}
async function ready(c){await c.s.connect(()=>{});await c.s.inspect();}
function execution(){
 const raw={chainId:'137',safe:expected.safe.toLowerCase(),version:'1.5.0',singleton:'0xff51a5898e281db6dfc7855790607438df2ca44b',runtime:'unverified-offline',guard:Z,fallback:Z,modules:[],owners:[{address:expected.signer.toLowerCase(),kind:'hybrid',publicKey:expected.publicKey,keyId:expected.keyId}],threshold:1,nonce:expected.nonce,account:'0x'+'77'.repeat(20),block:{number:'100',hash:'0x'+'11'.repeat(32)},generation:1,attempt:'none'};
 return new Execution({read:async()=>structuredClone(raw),now:clock});
}
test('explicit signPacket returns verified isolated packet accepted by collector without persisting signature',async()=>{
 const c=setup();await ready(c);
 assert.equal(typeof c.s.signPacket,'function');
 const packet=await c.s.signPacket(envelope.id);
 assert.deepEqual(Object.keys(packet).sort(),['context','expected','owner','request','result']);
 assert.equal(packet.owner,expected.signer.toLowerCase());assert.equal(packet.result.signerSignature,v.result.result.signerSignature);
 for(const value of [packet,packet.context,packet.expected,packet.request,packet.result])assert.ok(Object.isFrozen(value));
 c.reply.rawSignature='0x00';assert.equal(packet.result.rawSignature,v.result.result.rawSignature);
 assert.equal(c.rows.length,1);assert.deepEqual(Object.keys(c.rows[0]).sort(),['context','envelope','expected','purpose','requestId','version']);
 assert.ok(!JSON.stringify(c.rows).includes(packet.result.rawSignature));
 const e=execution();await e.load({kind:'native',recipient:expected.recipient,value:expected.value});await e.collect(packet);
 const p=await e.prepare();assert.equal(p.liveVerified,false);assert.equal(p.safeTxHash,packet.request.safeTxHash);assert.equal(e.view().count,1);
 assert.throws(()=>e.send(),/Live execution unavailable/);
 await assert.rejects(c.s.sign(envelope.id));await assert.rejects(c.s.signPacket(envelope.id));
 assert.deepEqual(c.calls.map(p=>p.request.method),[METHODS[0],METHODS[0],METHODS[1]]);
 await c.s.dispose();
});
for(const field of ['binding','rawSignature','safeTxHash'])test(`signPacket rejects changed ${field} without releasing a packet`,async()=>{
 const c=setup();await ready(c);c.reply[field]='0x'+'00'.repeat(field==='rawSignature'?64:32);
 await assert.rejects(c.s.signPacket(envelope.id),/Safe request validation failed/);
 assert.equal(c.s.session,null);assert.equal(c.s.context,null);await assert.rejects(c.s.signPacket(envelope.id));
 assert.equal(c.calls.filter(p=>p.request.method===METHODS[1]).length,1);await c.s.dispose();
});
for(const loss of ['close','expiry','session_delete'])test(`pending signPacket ${loss} rejects late reply and blocks either signing API`,async()=>{
 const c=setup();await ready(c);let release;
 const old=c.client.request;c.client.request=async p=>p.request.method===METHODS[1]?(c.calls.push(p),new Promise(resolve=>{release=()=>resolve(c.reply);})):old(p);
 const pending=c.s.signPacket(envelope.id);const rejection=assert.rejects(pending);
 while(!release)await new Promise(resolve=>setImmediate(resolve));
 await assert.rejects(c.s.sign(envelope.id));await assert.rejects(c.s.signPacket(envelope.id));
 if(loss==='close')await c.s.close();else if(loss==='expiry')c.session.expiry=0;else c.handlers.session_delete({topic:c.session.topic});
 release();await rejection;assert.equal(c.s.session,null);
 assert.equal(c.calls.filter(p=>p.request.method===METHODS[1]).length,1);await c.s.dispose();
});
