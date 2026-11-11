'use strict';
const $=id=>document.getElementById(id);
const provider=new ethers.providers.JsonRpcProvider('/rpc');
let plan=null,generation=0,safeGeneration=0;
function status(id,text,error=false){$(id).hidden=false;$(id).classList.toggle('error',error);$(id).textContent=text;}
function invalidate(){generation++;plan=null;$('plan').hidden=true;$('empty').hidden=false;$('export').disabled=true;$('status').hidden=true;$('inspect').disabled=false;}
$('points').addEventListener('input',invalidate);
$('keys').addEventListener('submit',event=>{
  event.preventDefault();invalidate();
  try {
    const value=$('points').value.trim();
    const points=value.startsWith('[')?JSON.parse(value):value.split(/\s+/);
    plan=registration.buildPlan(points);$('empty').hidden=true;$('plan').hidden=false;
    $('address').textContent=plan.address;$('keyCount').textContent=`${plan.keys.length}鍵のうち、どれか1鍵`;
    $('payload').textContent=JSON.stringify({address:plan.address,keys:plan.keys,transaction:plan.transaction},null,2);
  } catch(e){status('status',e.message,true);}
});
$('inspect').addEventListener('click',async()=>{
  if(!plan)return;const current=plan,epoch=generation;$('inspect').disabled=true;$('export').disabled=true;
  status('status','公式コード、予定アドレス、登録状態を照合中…');
  try {
    const result=await registration.inspect(provider,current);if(epoch!==generation)return;
    if(result.deployed)status('status',`配備済み。実装、EOA管理者なし、登録鍵${result.keys}個を照合しました。\n読取りブロック: ${result.block}`);
    else {
      const cost=ethers.BigNumber.from(result.gas).mul(result.gasPrice);
      status('status',`未配備。公式コードとFactoryの予定アドレスが一致しました。\n推定gas: ${result.gas}\n現在のgas価格で約 ${ethers.utils.formatEther(cost)} POL（確定価格・支払上限ではありません）\n読取りブロック: ${result.block}`);
      $('export').disabled=false;
    }
  } catch(e){if(epoch===generation)status('status',e.reason||e.message,true);}
  finally{if(epoch===generation)$('inspect').disabled=false;}
});
$('export').addEventListener('click',()=>{
  if(!plan||$('export').disabled)return;
  const blob=new Blob([JSON.stringify({chainId:plan.chainId,expectedAddress:plan.address,keys:plan.keys,transaction:plan.transaction},null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='signer-deployment-unsigned.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
$('safe').addEventListener('input',()=>{safeGeneration++;$('safeLink').hidden=true;$('safeStatus').hidden=true;$('checkSafe').disabled=false;});
$('checkSafe').addEventListener('click',async()=>{
  const epoch=++safeGeneration;$('safeLink').hidden=true;$('checkSafe').disabled=true;status('safeStatus','Safeの版を読取り中…');
  try {
    const address=ethers.utils.getAddress($('safe').value.trim());
    if((await provider.getNetwork()).chainId!==137)throw Error('Polygon以外には接続できません');
    const safe=new ethers.Contract(address,['function VERSION() view returns(string)','function getThreshold() view returns(uint256)'],provider);
    const block=await provider.getBlockNumber(),version=await safe.VERSION({blockTag:block});
    const m=/^(\d+)\.(\d+)\.(\d+)$/.exec(version);
    if(!m)throw Error('解釈できないSafeバージョンです');
    if(Number(m[1])<1||(Number(m[1])===1&&Number(m[2])<5))throw Error(`Safe ${version}は対象外です。1.5.0以上へ更新してください`);
    const threshold=await safe.getThreshold({blockTag:block});if(epoch!==safeGeneration)return;
    status('safeStatus',`Safe ${version} / 必要承認数 ${threshold.toString()}\n${version==='1.5.0'?'コントラクト互換性の試験対象版です。':'対象範囲ですが、この版の互換試験は未実施です。'}\nOwner追加はこの試作から送信しません。`);
    $('safeLink').href='https://app.safe.global/settings/setup?safe=matic:'+address;$('safeLink').hidden=false;
  } catch(e){if(epoch===safeGeneration)status('safeStatus',e.reason||e.message,true);}
  finally{if(epoch===safeGeneration)$('checkSafe').disabled=false;}
});
