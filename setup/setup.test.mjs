import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import test from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {assetName, checksum, executableFromArchive, validateLock, readActionBinding} from './setup.mjs';

const source = '0123456789012345678901234567890123456789';
const lock = {version: 1, platform: '0.1.0', platform_revision: source,
  manifest_sha256: 'a'.repeat(64), runtime_sha256: 'b'.repeat(64), recipe_sha256: 'c'.repeat(64)};

test('setup requires the same exact action and locked platform source', () => {
  assert.equal(validateLock(lock, source), 'v0.1.0');
  for (const bad of [{...lock, platform: 'latest'}, {...lock, platform_revision: 'f'.repeat(40)},
    {...lock, runtime_sha256: ''}, {...lock, extra: true}]) assert.throws(() => validateLock(bad, source));
  assert.throws(() => validateLock(lock, 'main'));
});

test('the declared runner matrix maps to the published archives', () => {
  assert.equal(assetName('linux', 'x64'), 'komizo_Linux_x86_64.tar.gz');
  assert.equal(assetName('darwin', 'arm64'), 'komizo_Darwin_arm64.tar.gz');
  assert.throws(() => assetName('win32', 'x64'));
});

test('a release checksum is unique and matches actual bytes', () => {
  const data = Buffer.from('fixture');
  const line = `${createHash('sha256').update(data).digest('hex')}  asset.tar.gz`;
  checksum(data, line, 'asset.tar.gz');
  assert.throws(() => checksum(Buffer.from('changed'), line, 'asset.tar.gz'));
  assert.throws(() => checksum(data, `${line}\n${line}`, 'asset.tar.gz'));
});

function archive(entries) {
  const chunks=[];
  for (const [name,type,body='fixture'] of entries) {
    const header=Buffer.alloc(512);header.write(name);header.write(body.length.toString(8).padStart(11,'0')+'\0',124);header[156]=type.charCodeAt(0);
    chunks.push(header,Buffer.from(body),Buffer.alloc((512-body.length%512)%512));
  }
  chunks.push(Buffer.alloc(1024));return gzipSync(Buffer.concat(chunks));
}

test('archive extraction refuses links, traversal, duplicates and missing binaries', () => {
  assert.equal(executableFromArchive(archive([['komizo','0']])).toString(), 'fixture');
  for (const entries of [[['../komizo','0']], [['komizo','2']], [['komizo','0'],['komizo','0']], [['README.md','0']]]) {
    assert.throws(() => executableFromArchive(archive(entries)));
  }
});

test('a reviewed action binding preserves the immutable attested release identity', () => {
  const action = 'd'.repeat(40);
  const binding = {version: 1, platform_revision: source, action_revision: action};
  const before = structuredClone(lock);
  assert.equal(validateLock(lock, action, binding), 'v0.1.0');
  assert.deepEqual(lock, before);
  assert.throws(() => validateLock(lock, action));
  assert.throws(() => validateLock(lock, source, binding));
  for (const bad of [{...binding, version: 2}, {...binding, platform_revision: 'f'.repeat(40)},
    {...binding, action_revision: 'main'}, {...binding, extra: true}]) {
    assert.throws(() => validateLock(lock, action, bad));
  }
  assert.throws(() => validateLock({...lock, platform_revision: 'main'}, action, binding));
});

test('an optional action binding refuses links, oversized files and malformed JSON', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'komizo-action-binding-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  assert.equal(await readActionBinding(directory), null);
  await fs.mkdir(path.join(directory, '.github'));
  const filename = path.join(directory, '.github', 'komizo-action-source.json');
  const binding = {version: 1, platform_revision: source, action_revision: 'd'.repeat(40)};
  await fs.writeFile(filename, JSON.stringify(binding));
  assert.deepEqual(await readActionBinding(directory), binding);
  await fs.writeFile(filename, '{');
  await assert.rejects(() => readActionBinding(directory));
  await fs.writeFile(filename, ' '.repeat(4097));
  await assert.rejects(() => readActionBinding(directory));
  await fs.unlink(filename);
  await fs.writeFile(path.join(directory, 'target'), JSON.stringify(binding));
  await fs.symlink('../target', filename);
  await assert.rejects(() => readActionBinding(directory));
});
