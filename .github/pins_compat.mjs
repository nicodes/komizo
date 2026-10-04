// Adapt the unified caller schema to the released v0.9.0 dependency checker.
// Only its historical workflow-file read is virtualized. Snapshot/tool/action
// hashes and every original dependency-policy assertion run unchanged.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const oldPath = '.github/workflows/bun-updates.yml';
const newPath = '.github/workflows/dependency-maintenance.yml';
const read = fs.readFileSync;
const exists = fs.existsSync;
let projection;
if (!exists(oldPath) && exists(newPath)) {
  const workflow = Bun.YAML.parse(read(newPath, 'utf8'));
  const updates = Object.values(workflow.jobs ?? {}).filter(job =>
    job.steps?.some(step => /\bupdate-bun\.py\b/.test(step.run ?? '')));
  if (updates.length) {
    assert.equal(updates.length, 1, 'Exactly one issue-only Bun updater is required');
    const job = updates[0];
    const match = /^github\.ref == 'refs\/heads\/main' && \(github\.event_name != 'schedule' \|\| github\.event\.schedule == '([^']+)'\)$/.exec(job.if);
    assert.ok(match, 'Consolidated Bun updater must retain its main-only and original schedule guard');
    assert.ok(workflow.on.schedule.some(item => item.cron === match[1]), 'Bun schedule guard must be reachable');
    projection = JSON.stringify({...workflow, on: {...workflow.on, schedule: [{cron: match[1]}]},
      jobs: {update: {...job, if: "github.ref == 'refs/heads/main'"}}});
  }
}
function legacy(file) { return typeof file === 'string' && path.resolve(file) === path.resolve(oldPath); }
fs.existsSync = function(file) { return legacy(file) && projection ? true : exists.call(fs, file); };
fs.readFileSync = function(file, options) {
  return legacy(file) && projection ? (typeof options === 'string' || options?.encoding ? projection : Buffer.from(projection)) : read.call(fs, file, options);
};
try {
  assert.ok(process.env.CICD_ENGINEERING, 'Independently verified CICD_ENGINEERING is required');
  await import(pathToFileURL(path.join(process.env.CICD_ENGINEERING, 'helpers/pins.mjs')));
} finally {
  fs.existsSync = exists;
  fs.readFileSync = read;
}
