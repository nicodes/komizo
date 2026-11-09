import assert from 'node:assert/strict';
import test from 'node:test';
import {actionable, deploymentStatus, operationID, propose, resourceNumber} from '../src/lib/deployment.ts';

const installed='sha256:'+'a'.repeat(64), prepared='sha256:'+'d'.repeat(64);
const instance={application:'mailroom',instance:'production',release_digest:installed,
  desired_running:true,operation_id:'c'.repeat(32),services:{web:{state:'running'}},
  actions:{start:{release_digest:installed},stop:{release_digest:installed},restart:{release_digest:installed},backup:{release_digest:installed}}};
const operation={kind:'komizo.operation',version:1,application:'mailroom',instance:'production',
  release_digest:installed,operation_id:instance.operation_id,phase:'ready',ok:true};

test('readiness needs exact installed operation evidence', () => {
  assert.equal(deploymentStatus(instance),'Readiness unverified');
  assert.equal(deploymentStatus({...instance,operations:[{...operation,release_digest:prepared}]}),'Readiness unverified');
  assert.equal(deploymentStatus({...instance,operations:[{...operation,operation_id:'f'.repeat(32)}]}),'Readiness unverified');
  assert.equal(deploymentStatus({...instance,operations:[operation]}),'Readiness passed');
  assert.equal(deploymentStatus({...instance,operations:[{...operation,ok:false,phase:'failed'}]}),'Operation failed');
  assert.equal(deploymentStatus({...instance,unresolved_operations:[{...operation,ok:false,phase:'needs_reconciliation'}]}),'Inspection required');
});

test('owner stop and prepared state remain distinct from failed readiness', () => {
  assert.equal(deploymentStatus({...instance,desired_running:false,operations:[operation]}),'Stopped by owner');
  assert.equal(deploymentStatus({...instance,desired_running:false,prepared:{release_digest:prepared}}),'Prepared while stopped');
  assert.equal(actionable(instance,'start'),false);
  assert.equal(actionable({...instance,desired_running:false},'restart'),false);
  assert.equal(actionable({...instance,unresolved_operations:[operation]},'backup'),false);
});

test('proposed identity matches host formula and binds explicit action release', async () => {
  assert.equal(await operationID('mailroom','production','b'.repeat(32)),'3a136f1b4cdd49cd0c83b4231129a21f');
  const stopped={...instance,desired_running:false,prepared:{release_digest:prepared},actions:{...instance.actions,start:{release_digest:prepared}}};
  const proposed=await propose(stopped,'start');
  assert.equal(proposed.request.release_digest,prepared);
  assert.equal(proposed.operation_id,await operationID('mailroom','production',proposed.request.nonce));
  const restarted=await propose({...instance,prepared:{release_digest:prepared}},'restart');
  assert.equal(restarted.request.release_digest,installed);
  await assert.rejects(propose({...stopped,actions:{}},'start'),/Refresh and inspect/);
  await assert.rejects(propose({...stopped,actions:{start:{release_digest:'invalid'}}},'start'),/Refresh and inspect/);
});

test('missing or invalid measurements do not become zero observations', () => {
  assert.equal(resourceNumber(undefined,'memory_bytes'),undefined);
  for(const value of [null,-1,Infinity,NaN,'42'])assert.equal(resourceNumber({memory_bytes:value},'memory_bytes'),undefined);
  assert.equal(resourceNumber({memory_bytes:0},'memory_bytes'),0);
  assert.equal(resourceNumber({usage_bytes:42},'memory_bytes','usage_bytes'),42);
});
