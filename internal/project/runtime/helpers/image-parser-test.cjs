// Bounded adversarial inputs plus a valid image through the public API.
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createRequire } = require('node:module');
const app = path.resolve(process.argv[2] || 'app');
const fixtures = {
  icns: `const b=Buffer.alloc(16); b.write('icns'); b.writeUInt32BE(16,4); b.write('icp4',8); assert.throws(()=>size(b));`,
  icns_short_entry: `const b=Buffer.alloc(16); b.write('icns'); b.writeUInt32BE(16,4); b.write('icp4',8); b.writeUInt32BE(1,12); assert.throws(()=>size(b));`,
  jxl_partial_zero: `const b=Buffer.alloc(36); b.writeUInt32BE(12,0); b.write('JXL ',4); b.writeUInt32BE(12,12); b.write('ftyp',16); b.write('jxl ',20); b.write('jxlp',28); assert.throws(()=>size(b));`,
  heif_zero_box: `const b=Buffer.alloc(24); b.write('ftyp',4); b.write('heic',8); assert.throws(()=>size(b));`,
  valid_png: `const b=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jJr0AAAAASUVORK5CYII=','base64'); const got=size(b); assert.equal(got.width,1); assert.equal(got.height,1);`,
  valid_icns: `const b=Buffer.alloc(16); b.write('icns'); b.writeUInt32BE(16,4); b.write('icp4',8); b.writeUInt32BE(8,12); const got=size(b); assert.equal(got.width,16); assert.equal(got.height,16);`,
};
const resolve = createRequire(path.join(app, 'package.json'));
const entry = resolve.resolve('image-size');
for (const [name, source] of Object.entries(fixtures)) {
  const result = spawnSync(process.execPath, ['-e',
    `const assert=require('node:assert/strict'); const size=require(${JSON.stringify(entry)}); ${source}`],
  { timeout: 2000, encoding: 'utf8', maxBuffer: 100000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${name}: ${result.stderr}`);
  console.log(`image-size regression passed: ${name}`);
}
