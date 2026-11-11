import assert from 'node:assert/strict';
import { mock, test } from 'node:test';
import { readRPC } from '../read-rpc.js';
const reply = transform => async (_url, options) => {
  assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit');
  const {id} = JSON.parse(options.body);
  return new Response(JSON.stringify(transform({jsonrpc:'2.0', id, result:'0x89'})));
};
test('bounded public RPC validates envelope and preserves numeric errors only', async () => {
  assert.equal(await readRPC('/rpc','eth_chainId',[],reply(x=>x)), '0x89');
  for (const transform of [x=>({...x,id:x.id+1}), x=>({...x,jsonrpc:'1.0'}), x=>({...x,extra:1}), ()=>[]]) {
    await assert.rejects(readRPC('/rpc','eth_chainId',[],reply(transform)), /mismatch/);
  }
  await assert.rejects(readRPC('/rpc','eth_chainId',[],reply(x=>({jsonrpc:'2.0',id:x.id,error:{code:-32000,message:'untrusted'}}))), e=>e.code===-32000 && e.message==='RPC error');
  await assert.rejects(readRPC('/rpc','eth_chainId',[],reply(x=>({...x,result:'a'.repeat(2_000_001)}))), /size limit/);
  await assert.rejects(readRPC('/rpc','eth_sendRawTransaction',[],()=>{throw Error('must not fetch');}), /read-only/);
});
test('deadline bounds a hung upstream even when fetch ignores AbortSignal', async () => {
  mock.timers.enable({apis:['setTimeout']});
  try {
    const pending = readRPC('/rpc','eth_chainId',[],()=>new Promise(()=>{}));
    const check = assert.rejects(pending,/timeout/);
    mock.timers.tick(10000); await check;
  } finally {mock.timers.reset();}
});
export {};
