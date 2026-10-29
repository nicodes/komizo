import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {gunzipSync} from 'node:zlib';

export function validateLock(lock, source, binding = null) {
  assert.equal(lock.version, 1, 'unsupported project lock');
  assert.match(lock.platform, /^v?\d+\.\d+\.\d+(?:-[\w.-]+)?$/, 'an exact platform release is required');
  assert.match(source, /^[a-f0-9]{40}$/, 'pin this action to a full source commit');
  assert.match(lock.platform_revision, /^[a-f0-9]{40}$/, 'pin the attested platform source');
  let expectedSource = lock.platform_revision;
  if (binding !== null) {
    assert.deepEqual(Object.keys(binding).sort(), ['action_revision', 'platform_revision', 'version'], 'unknown action binding fields');
    assert.equal(binding.version, 1, 'unsupported action source binding');
    assert.match(binding.action_revision, /^[a-f0-9]{40}$/, 'pin the action source');
    assert.equal(binding.platform_revision, lock.platform_revision, 'action binding names a different attested release source');
    expectedSource = binding.action_revision;
  }
  assert.equal(source, expectedSource, 'action source differs from the reviewed project binding');
  for (const field of ['manifest_sha256', 'runtime_sha256', 'recipe_sha256']) {
    assert.match(lock[field], /^[a-f0-9]{64}$/, `missing ${field}`);
  }
  const fields = ['version', 'platform', 'platform_revision', 'manifest_sha256', 'runtime_sha256', 'recipe_sha256'];
  assert.deepEqual(Object.keys(lock).sort(), fields.sort(), 'unknown lock fields');
  return `v${lock.platform.replace(/^v/, '')}`;
}

export async function readActionBinding(directory) {
  const filename = path.join(directory, '.github', 'komizo-action-source.json');
  let info;
  try { info = await fs.lstat(filename); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  assert.ok(info.isFile() && info.size <= 4096, 'action binding must be a bounded regular file');
  const resolved = await fs.realpath(filename);
  const root = await fs.realpath(directory);
  assert.ok(resolved.startsWith(root + path.sep), 'action binding leaves the project');
  return JSON.parse(await fs.readFile(filename, 'utf8'));
}

export function assetName(platform, architecture) {
  const systems = {linux: 'Linux', darwin: 'Darwin'};
  const architectures = {x64: 'x86_64', arm64: 'arm64'};
  assert.ok(systems[platform] && architectures[architecture], 'supported runners are Linux/macOS amd64/arm64');
  return `komizo_${systems[platform]}_${architectures[architecture]}.tar.gz`;
}

export function checksum(data, list, filename) {
  const records = list.split('\n').filter(Boolean).map(line => line.match(/^([a-f0-9]{64})\s+\*?([^\s]+)$/));
  assert.ok(records.every(Boolean), 'malformed release checksums');
  const selected = records.filter(record => record[2] === filename);
  assert.equal(selected.length, 1, 'release must contain exactly one matching checksum');
  assert.equal(createHash('sha256').update(data).digest('hex'), selected[0][1], 'release checksum differs');
}

// Extract only the expected regular executable from the authenticated archive.
export function executableFromArchive(archive) {
  const data = gunzipSync(archive, {maxOutputLength: 256 << 20});
  let executable;
  const seen = new Set();
  for (let offset = 0; offset + 512 <= data.length;) {
    const header = data.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) break;
    const text = (start, length) => header.subarray(start, start + length).toString('utf8').replace(/\0.*$/s, '');
    const name = text(0, 100);
    const sizeField = text(124, 12).trim();
    assert.match(sizeField, /^[0-7]+$/, 'invalid archive size');
    const size = Number.parseInt(sizeField, 8);
    assert.ok(Number.isSafeInteger(size) && size >= 0 && size <= (256 << 20), 'archive member exceeds bound');
    assert.ok(['komizo', 'README.md', 'LICENSE'].includes(name), 'unexpected archive member');
    assert.ok(header[156] === 0 || header[156] === 48, 'archive members must be regular files');
    assert.equal(text(345, 155), '', 'archive prefixes are not supported');
    assert.ok(!seen.has(name), 'duplicate archive member');
    seen.add(name);
    offset += 512;
    assert.ok(offset + size <= data.length, 'truncated archive');
    if (name === 'komizo') {
      assert.equal(executable, undefined, 'duplicate executable');
      assert.ok(size > 0, 'empty executable');
      executable = data.subarray(offset, offset + size);
    }
    offset += Math.ceil(size / 512) * 512;
  }
  assert.ok(executable, 'archive has no executable');
  return executable;
}

async function download(url, limit) {
  const response = await fetch(url, {signal: AbortSignal.timeout(120_000)});
  assert.equal(response.status, 200, `release download returned HTTP ${response.status}`);
  let size = 0;
  const chunks = [];
  for await (const chunk of response.body) {
    size += chunk.length;
    assert.ok(size <= limit, 'release download exceeds bound');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export async function main() {
  const workspace = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd());
  const directory = path.resolve(workspace, process.env.INPUT_DIRECTORY || '.');
  assert.ok(directory === workspace || directory.startsWith(workspace + path.sep), 'project directory leaves the workspace');
  const lock = JSON.parse(await fs.readFile(path.join(directory, 'komizo.lock'), 'utf8'));
  const tag = validateLock(lock, process.env.GITHUB_ACTION_REF || '', await readActionBinding(directory));
  const repository = process.env.GITHUB_ACTION_REPOSITORY || '';
  assert.match(repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, 'missing action repository identity');
  const asset = assetName(process.platform, process.arch);
  const base = `https://github.com/${repository}/releases/download/${tag}`;
  const [archive, sums] = await Promise.all([download(`${base}/${asset}`, 128 << 20), download(`${base}/checksums.txt`, 1 << 20)]);
  checksum(archive, sums.toString('utf8'), asset);
  const scratch = await fs.mkdtemp(path.join(process.env.RUNNER_TEMP, 'komizo-setup-'));
  const archivePath = path.join(scratch, asset);
  await fs.writeFile(archivePath, archive, {mode: 0o600});
  execFileSync('gh', ['attestation', 'verify', archivePath, '--repo', repository,
    '--source-digest', lock.platform_revision, '--source-ref', 'refs/heads/main',
    '--signer-workflow', `${repository}/.github/workflows/release.yml`, '--deny-self-hosted-runners'], {stdio: ['ignore', 'inherit', 'inherit']});
  const executable = path.join(scratch, 'komizo');
  await fs.writeFile(executable, executableFromArchive(archive), {mode: 0o700});
  // The installed CLI independently checks the complete manifest/lock/runtime binding.
  execFileSync(executable, ['--json', 'validate', '--directory', directory], {stdio: ['ignore', 'inherit', 'inherit']});
  await fs.appendFile(process.env.GITHUB_PATH, `${scratch}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {console.error(`komizo setup failed: ${error.message}`); process.exitCode = 1;});
}
