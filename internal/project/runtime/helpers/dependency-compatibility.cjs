const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const path = require('node:path');
const { PassThrough } = require('node:stream');
const load = createRequire(path.resolve(process.argv[2] || 'app', 'package.json'));
const query = load('query-string');
assert.equal(query.parse('x=%20').x, ' ');
assert.equal(query.parse('x=%E2%82%AC').x, '€');
assert.equal(query.parse('x=%ZZ').x, '%ZZ');
const xcode = load('xcode');
const project = xcode.project('fixture.pbxproj');
project.hash = {project:{objects:{}}};
assert.match(project.generateUuid(), /^[0-9A-F]{24}$/);
const plistModule = load('@expo/plist');
const plist = plistModule.default || plistModule;
assert.deepEqual({...plist.parse(plist.build({name:'fixture & unicode €', count:2}))}, {name:'fixture & unicode €', count:2});
let jayson;
try { jayson = load('jayson/lib/utils'); } catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND' || !error.message.includes("'jayson/lib/utils'")) throw error;
}
async function streaming() {
  if (!jayson) return;
  await new Promise((resolve, reject) => {
    const stream = new PassThrough();
    const values = [];
    const timer = setTimeout(() => reject(new Error('stream parser failed to emit both requests')), 2000);
    jayson.parseStream(stream, {}, (error, value) => {
      if (error) { clearTimeout(timer); reject(error); return; }
      values.push(value);
      if (values.length === 2) {
        clearTimeout(timer);
        try { assert.deepEqual(values, [{id:1, method:'fixture'}, {id:2, result:'€'}]); resolve(); }
        catch (failure) { reject(failure); }
      }
    });
    stream.write('{"id":1,"method":"fix');
    stream.end('ture"}\n{"id":2,"result":"€"}');
  });
  await new Promise((resolve, reject) => {
    const stream = new PassThrough();
    const timer = setTimeout(() => reject(new Error('invalid JSON was not rejected')), 2000);
    jayson.parseStream(stream, {}, error => {
      clearTimeout(timer);
      error ? resolve() : reject(new Error('invalid JSON emitted a request'));
    });
    stream.end('{"unfinished":');
  });
}
streaming().then(() => console.log('Query decoding, UUID, XML, and JSON streaming compatibility passed')).catch(error => { console.error(error); process.exitCode=1; });
