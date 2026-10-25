import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

export function verifyDependencyCoverage(config, files, bunWorkflow) {
  assert.equal(config.version, 2, 'Dependabot configuration must use version 2');
  assert.ok(Array.isArray(config.updates), 'Dependabot update coverage is required');
  const required = new Map([
    ['github-actions', new Set(['/'])],
    ['docker', new Set(['/deploy/images', ...files.filter(file => /(^|[/.])Dockerfile$/.test(file)).map(file => path.posix.dirname(file) === '.' ? '/' : '/' + path.posix.dirname(file))])],
    ['gomod', new Set(files.filter(file => /(^|\/)go\.mod$/.test(file))
      .map(file => path.posix.dirname(file) === '.' ? '/' : '/' + path.posix.dirname(file)))],
  ]);
  // A product with no Bun application has nothing for the Bun updater to
  // update, and sample-arcade and sample-client are exactly that: Godot clients with a
  // Go gate and no package.json anywhere. Requiring the workflow of them
  // asks for a scheduled job that would run `bun update` over nothing.
  //
  // Only the REQUIREMENT is lifted, not the checking: a workflow that is
  // there is still held to every rule below. And a product that HAS a Bun
  // application is still required to carry one, so deleting the workflow to
  // escape the checks fails -- that is the case worth catching.
  //
  // Nothing here forbids the workflow to a product without an application.
  // These products do run bun (pins.mjs is bun), and whether the updater is
  // useful to them is their decision, not this file's.
  const hasBunApplication = files.some(file => /^[^/]+\/package\.json$/.test(file));
  if (!hasBunApplication && !bunWorkflow) {
    return checkEcosystems(config, required);
  }
  assert.ok(bunWorkflow?.on?.schedule?.length, 'Bun native update schedule is required');
  assert.ok(bunWorkflow.on.schedule.every(item => /^\S+(?: \S+){4}$/.test(item.cron)), 'Bun schedule must be explicit');
  const job = bunWorkflow.jobs?.update;
  assert.equal(job?.if, "github.ref == 'refs/heads/main'", 'Bun writes are restricted to main');
  assert.equal(job?.environment, undefined, 'Bun updater must not receive production secrets');
  assert.deepEqual(job?.permissions, { contents: 'read', issues: 'write' }, 'Bun issue reporting must not grant code, PR or workflow writes');
  // Matched by what it runs, not by where it lives. A product that installs
  // the snapshot resolves the helper through $CICD_ENGINEERING, so an exact
  // vendored path here failed a product that was doing the right thing.
  assert.ok(job?.steps?.some(step => /\bupdate-bun\.py\b/.test(step.run ?? '')),
    'Pinned Bun updater must actually run');
  assert.ok(job?.steps?.some(step => step.uses?.startsWith('jdx/mise-action@')), 'Bun updater must install repository pins');
  return checkEcosystems(config, required);
}

function checkEcosystems(config, required) {
  for (const [ecosystem, directories] of required) {
    for (const directory of directories) {
      assert.ok(config.updates.some(update => update['package-ecosystem'] === ecosystem
        && [update.directory, ...(update.directories ?? [])].includes(directory)
        && ['daily', 'weekly', 'monthly'].includes(update.schedule?.interval)),
      `Dependabot must explicitly cover ${ecosystem} ${directory} with a supported schedule`);
    }
  }
}

if (import.meta.main) {
  const config = Bun.YAML.parse(fs.readFileSync('.github/dependabot.yml', 'utf8'));
  const files = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
  const bunWorkflow = fs.existsSync('.github/workflows/bun-updates.yml')
    ? Bun.YAML.parse(fs.readFileSync('.github/workflows/bun-updates.yml', 'utf8'))
    : null;
  verifyDependencyCoverage(config, files, bunWorkflow);
  console.log('Dependency update coverage includes the app, actions, images and every tracked Go module');
}
