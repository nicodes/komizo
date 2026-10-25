"""Exercise actual HTTP transport without launching a browser."""
from pathlib import Path
import subprocess
import unittest


class FixtureProxy(unittest.TestCase):
    def test_disposable_transport(self):
        helper = (Path(__file__).parents[1] / 'helpers/fixture-proxy.mjs').as_uri()
        program = r'''
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
const { fixtureProxy } = await import(HELPER);
const proxy = fixtureProxy();
const servers = [];
async function listen(handler) {
  const server = createServer(handler); servers.push(server);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return 'http://127.0.0.1:' + server.address().port;
}
try {
  const backend = await listen(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    if (req.url === '/redirect') { res.writeHead(307, {Location:'/destination'}).end(); return; }
    res.writeHead(201, {'Content-Type':'application/json', 'Set-Cookie':['a=1; HttpOnly','b=2']});
    res.end(JSON.stringify({ method:req.method, path:req.url, body:Buffer.concat(chunks).toString('hex'), auth:req.headers.authorization, cookie:req.headers.cookie, origin:req.headers.origin, host:req.headers.host }));
  });
  for (const target of ['https://127.0.0.1:1234','http://example.invalid:1234','http://127.0.0.1:1234/path','http://u:p@127.0.0.1:1234','http://127.0.0.1:1234/?x=1']) assert.throws(() => proxy.register('/api',target));
  assert.throws(() => proxy.register('/api/other', backend));
  proxy.register('/api', backend);
  assert.throws(() => proxy.register('/api', backend));
  const web = await listen((req,res) => { if (!proxy.handle(req,res)) res.writeHead(404).end(); });
  const bytes = Buffer.from([0,1,2,255]);
  const response = await fetch(web+'/api/v1/items?cursor=a%2Fb', {method:'POST',headers:{Authorization:'Bearer disposable',Cookie:'session=fixture',Origin:web},body:bytes});
  assert.equal(response.status,201);
  assert.deepEqual(response.headers.getSetCookie(),['a=1; HttpOnly','b=2']);
  assert.deepEqual(await response.json(), {method:'POST',path:'/v1/items?cursor=a%2Fb',body:bytes.toString('hex'),auth:'Bearer disposable',cookie:'session=fixture',origin:web,host:new URL(backend).host});
  assert.equal((await fetch(web+'/apix/v1/items')).status,404);
  const redirect = await fetch(web+'/api/redirect',{redirect:'manual'});
  assert.equal(redirect.status,307); assert.equal(redirect.headers.get('location'),'/destination');
  servers[0].closeAllConnections(); await new Promise(resolve => servers[0].close(resolve));
  assert.equal((await fetch(web+'/api/unavailable')).status,502);
} finally {
  for (const server of servers) { server.closeAllConnections(); server.close(); }
}
'''.replace('HELPER', repr(helper))
        subprocess.run(['node', '--input-type=module', '-e', program], check=True, timeout=30)
