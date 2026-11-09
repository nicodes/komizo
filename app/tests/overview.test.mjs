import assert from 'node:assert/strict';
import test from 'node:test';
import {collectOverview} from '../src/lib/overview.ts';

test('history is read after the current host observation settles', async () => {
  let finish,settled=false;const calls=[];
  const pending=collectOverview({status:()=>{calls.push('status');return new Promise(resolve=>{finish=resolve})},
    history:async()=>{calls.push('history');return {samples:[]}}}).then(value=>{settled=true;return value});
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(calls,['status']);assert.equal(settled,false);
  finish({captured_at:'now',status:{instances:[]}});
  const snapshot=await pending;
  assert.deepEqual(calls,['status','history']);assert.equal(snapshot.status.captured_at,'now');
});

test('unavailable host status stays distinct from observed empty history', async () => {
  const snapshot=await collectOverview({status:async()=>{throw new Error('host offline')},history:async()=>({samples:[]})});
  assert.equal(snapshot.status,undefined);assert.deepEqual(snapshot.history.samples,[]);
  assert.equal(snapshot.errors.status,'Error: host offline');assert.equal(snapshot.errors.history,undefined);
});

test('history failure preserves the current status without rewriting the wire document', async () => {
  const status={captured_at:'now',status:{kind:'komizo.status',version:1,instances:[]}};
  const before=structuredClone(status);
  const snapshot=await collectOverview({status:async()=>status,history:async()=>{throw new Error('history unavailable')}});
  assert.deepEqual(snapshot.status,before);assert.deepEqual(status,before);
  assert.equal(snapshot.history,undefined);assert.equal(snapshot.errors.history,'Error: history unavailable');
});
