import { readURL } from './site.js';
let nextId = 0;
// Public RPC responses are untrusted: bound bytes, time, envelope and exact request ID.
export async function readRPC(route, method, params, fetcher = globalThis.fetch) {
  const id = ++nextId;
  if (!Number.isSafeInteger(id) || !Array.isArray(params)) throw new TypeError('invalid read');
  const body = JSON.stringify({jsonrpc:'2.0', id, method, params});
  if (new TextEncoder().encode(body).length > 32768) throw new TypeError('read request size limit');
  const url = readURL(route, method), abort = new AbortController();
  let timer, reader;
  const run = async () => {
    const response = await fetcher(url, {method:'POST', headers:{'Content-Type':'application/json'},
      credentials:'omit', redirect:'error', referrerPolicy:'no-referrer', cache:'no-store', signal:abort.signal, body});
    if (!response.ok || !response.body) throw new Error('read unavailable');
    reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8', {fatal:true});
    let text = '', size = 0;
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 2_000_000) throw new Error('read response size limit');
      text += decoder.decode(value, {stream:true});
    }
    text += decoder.decode();
    const result = JSON.parse(text);
    if (!result || Array.isArray(result) || result.jsonrpc !== '2.0' || result.id !== id
        || Object.keys(result).sort().join() !== (Object.hasOwn(result,'error') ? 'error,id,jsonrpc' : 'id,jsonrpc,result')) {
      throw new Error('read response mismatch');
    }
    if (Object.hasOwn(result,'error')) {
      if (!result.error || !Number.isInteger(result.error.code)) throw new Error('invalid RPC error');
      throw Object.assign(new Error('RPC error'), {code:result.error.code});
    }
    return result.result;
  };
  try { return await Promise.race([run(), new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('read timeout')), 10000);
  })]); }
  finally { clearTimeout(timer); abort.abort(); if (reader) void reader.cancel().catch(() => {}); }
}
