import assert from 'node:assert/strict';
import test from 'node:test';
import {collectOverview} from '../src/lib/overview.ts';

test('every refresh settles all evidence before publishing its snapshot', async () => {
  let finish; let settled=false; const calls=[];
  const readers={
    report:async()=>{calls.push('report');return {report:{at:'new'}}},
    events:async()=>{calls.push('events');return {events:[]}},
    metrics:()=>{calls.push('metrics');return new Promise(resolve=>{finish=resolve})},
    backups:async()=>{calls.push('backups');return {backups:[],note:'none'}},
  };
  const pending=collectOverview(readers).then(value=>{settled=true;return value});
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(calls,['report','events','metrics','backups']);
  assert.equal(settled,false);
  finish({metrics:{rows:[]}});
  assert.equal((await pending).report.at,'new');
});

test('failed evidence is distinct from measured empty evidence', async () => {
  const snapshot=await collectOverview({
    report:async()=>({report:{at:'new'}}),
    events:async()=>({events:[]}),
    metrics:async()=>{throw new Error('metrics unavailable')},
    backups:async()=>{throw new Error('backups unavailable')},
  });
  assert.deepEqual(snapshot.events,[]);
  assert.equal(snapshot.metrics,undefined);
  assert.equal(snapshot.errors.metrics,'Error: metrics unavailable');
  assert.equal(snapshot.errors.backups,'Error: backups unavailable');
  assert.equal(snapshot.errors.events,undefined);
});


test('nullable native observations render as empty evidence without changing wire documents', async () => {
  const wire = {
    report: {v:1, report:{at:'2026-11-03T05:00:00Z', server:{state:'ready',komizo:{}},
      system:{cores:2}, apps:null, problems:null, preview:{reaped:null,kept:0}}},
    events: {v:1,events:null},
    metrics: {v:1,metrics:{rows:null}},
    backups: {v:1,backups:[],note:'No backup state'},
  };
  const before=structuredClone(wire);
  const snapshot=await collectOverview(Object.fromEntries(
    Object.entries(wire).map(([name,value])=>[name,async()=>value])));
  assert.deepEqual(snapshot.report.apps,[]);
  assert.deepEqual(snapshot.report.problems,[]);
  assert.deepEqual(snapshot.report.preview.reaped,[]);
  assert.deepEqual(snapshot.events,[]);
  assert.deepEqual(snapshot.metrics.metrics.rows,[]);
  assert.equal(snapshot.report.server.state,'ready');
  assert.equal(snapshot.report.system.cores,2);
  assert.deepEqual(wire,before);
  assert.ok(Object.values(snapshot.errors).every(error=>error===undefined));
});
