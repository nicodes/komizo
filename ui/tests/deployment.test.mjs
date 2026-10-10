import assert from 'node:assert/strict';
import test from 'node:test';
import {deploymentStatus} from '../src/lib/deployment.ts';

test('running, missing and stale evidence cannot certify readiness', () => {
  const app = {name:'prizm', version:'new', containers:[{state:'running'}]};
  assert.equal(deploymentStatus(app), 'Readiness unverified');
  assert.equal(deploymentStatus({...app, deployment:{candidate:'old', phase:'ready'}}), 'Readiness unverified');
  assert.equal(deploymentStatus({...app, deployment:{candidate:'new', phase:'activated'}}), 'Activated; readiness unverified');
});

test('current readiness failures and success remain distinct', () => {
  const app = {name:'prizm', version:'new'};
  assert.equal(deploymentStatus({...app, deployment:{candidate:'new', phase:'ready'}}), 'Readiness passed');
  assert.equal(deploymentStatus({...app, deployment:{candidate:'new', phase:'readiness_failed'}}), 'Readiness failed');
});
