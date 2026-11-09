import assert from 'node:assert/strict';
import test from 'node:test';
import {ownerCapability} from '../src/lib/session.ts';
const capability='a'.repeat(64),second='b'.repeat(64);
function browser(fragment,stored){
  const values=new Map(stored?[['komizo.owner.session',stored]]:[]), replacements=[];
  globalThis.window={location:{hash:fragment,pathname:'/app/mailroom/production',search:'?view=logs'},
    history:{replaceState:(_state,_title,path)=>{replacements.push(path);window.location.hash=''}},
    sessionStorage:{setItem:(key,value)=>values.set(key,value),getItem:key=>values.get(key)??null,removeItem:key=>values.delete(key)}};
  return {values,replacements};
}
test('owner-private fragment is erased before API use and survives same-origin reload state',()=>{
  const state=browser('#komizo-session='+capability);
  assert.equal(ownerCapability(),capability);assert.deepEqual(state.replacements,['/app/mailroom/production?view=logs']);
  assert.equal(window.location.hash,'');assert.equal(state.values.get('komizo.owner.session'),capability);
  assert.equal(ownerCapability(),capability);
});
test('new launch replaces the previous session; malformed bootstrap cannot retain its authority',()=>{
  const state=browser('#komizo-session='+second,capability);
  assert.equal(ownerCapability(),second);assert.equal(state.values.get('komizo.owner.session'),second);
  window.location.hash='#komizo-session=invalid';assert.equal(ownerCapability(),undefined);
  assert.equal(window.location.hash,'');assert.equal(state.values.has('komizo.owner.session'),false);
});
test('all owner calls use bearer authority, never cookies, query strings or redirects',async()=>{
  browser('#komizo-session='+capability);
  const calls=[];globalThis.fetch=async(path,options)=>{calls.push({path,options});return {ok:true,status:200,text:async()=>JSON.stringify({ok:true})}};
  const api=await import('../src/lib/api.ts');
  await api.readStatus();await api.readHistory();await api.readLogs('mailroom','production','api');
  await api.readOperation('mailroom','production','b'.repeat(32),'sha256:'+'c'.repeat(64));
  await api.runAction({application:'mailroom',instance:'production',action:'stop',release_digest:'sha256:'+'c'.repeat(64),nonce:'b'.repeat(32)});
  assert.equal(calls.length,5);
  for(const {path,options} of calls){assert.equal(options.headers.get('Authorization'),'Bearer '+capability);
    assert.equal(options.credentials,'omit');assert.equal(options.mode,'same-origin');assert.equal(options.redirect,'error');assert.ok(!path.includes(capability));}
  assert.equal(calls.at(-1).options.headers.get('X-Komizo-Request'),'1');
  window.location.hash='#komizo-session=invalid';
  await assert.rejects(api.readStatus(),/owner-private launcher/);assert.equal(calls.length,5);
});
