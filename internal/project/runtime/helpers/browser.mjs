// Disposable caller-owned component fixtures and optional browser journeys.
import assert from 'node:assert/strict';
import { fixtureProxy } from './fixture-proxy.mjs';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join, extname, sep } from 'node:path';


export async function stackFixture(project, journey, { routeFile = path => path, kind = 'integration' } = {}) {
assert(['integration', 'artifact', 'browser'].includes(kind));
const root = process.cwd();
const scratch = await mkdtemp(join(tmpdir(), `${project}-browser-`));
const artifacts = resolve('.artifacts/' + kind);
await mkdir(artifacts, { recursive: true });
const children = [];
const servers = [];
let browser, context;
let failed = true;
const blockedRequests = [];
let stopping = false;
let cancel;
const cancelled = new Promise((_, reject) => { cancel = reject; });
const interrupt = () => cancel(new Error('Browser gate interrupted'));
process.on('SIGINT', interrupt);
process.on('SIGTERM', interrupt);
const deadline = setTimeout(() => cancel(new Error('Browser gate exceeded 30 minutes')), 1800000);
deadline.unref();
function start(command, args, env = {}) {
  if (stopping) throw new Error('Browser stack is stopping');
  const child = spawn(command, args, { cwd: root, env: { ...process.env, ...env },
    detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = '';
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
    logs = (logs + chunk.toString()).slice(-200000);
  });
  const completion = new Promise((accept, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => code === 0 ? accept() : reject(new Error(`${command} exited ${code ?? signal}\n${logs}`)));
  });
  // Long-running servers may exit during cleanup; their exit is checked by readiness.
  completion.catch(() => {});
  const entry = { child, completion, logs: () => logs };
  children.push(entry);
  return entry;
}
async function run(command, args, env = {}, timeout = 900000) {
  const entry = start(command, args, env);
  let timer;
  try {
    await Promise.race([entry.completion, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${command} exceeded ${timeout}ms`)), timeout);
    })]);
  } finally { clearTimeout(timer); }
}
async function listen(server) {
  servers.push(server);
  await new Promise((accept, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', accept); });
  return `http://127.0.0.1:${server.address().port}`;
}
async function port() {
  const server = createServer();
  const url = await listen(server);
  await new Promise(accept => server.close(accept));
  return new URL(url).port;
}
async function ready(url, entry) {
  for (let count = 0; count < 300; count++) {
    if (entry.child.exitCode !== null) throw new Error(`Service stopped before readiness: ${entry.logs()}`);
    try { if ((await fetch(url, { signal: AbortSignal.timeout(1000) })).ok) return; } catch {}
    await new Promise(accept => setTimeout(accept, 100));
  }
  throw new Error(`Readiness timeout: ${url}\n${entry.logs()}`);
}
async function json(url, method = 'GET', body, token) {
  const response = await fetch(url, { method, headers: { 'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(15000) });
  assert(response.ok, `${method} ${new URL(url).pathname}: HTTP ${response.status}: ${(await response.clone().text()).slice(0, 500)}`);
  return response.status === 204 ? null : response.json();
}
try {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'engineering-gate', alg: 'RS256', use: 'sig' };
  let keyFetches = 0;
  const issuerAPI = await listen(createServer((request, response) => {
    if (request.url !== '/jwks' && request.url !== '/v1/jwks') { response.writeHead(404).end(); return; }
    keyFetches++;
    response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ keys: [jwk] }));
  }));
  const proxy = fixtureProxy();
  const webRoot = resolve('app/dist-e2e');
  const web = await listen(createServer(async (request, response) => {
    if (proxy.handle(request, response)) return;
    try {
      const pathname = routeFile(decodeURIComponent(new URL(request.url, 'http://localhost').pathname));
      let file = resolve(webRoot, '.' + pathname);
      if (file !== webRoot && !file.startsWith(webRoot + sep)) { response.writeHead(403).end(); return; }
      try { if ((await stat(file)).isDirectory()) file = join(file, 'index.html'); }
      catch {
        if (!extname(pathname)) {
          try { await stat(file + '.html'); file += '.html'; }
          catch { file = join(webRoot, 'index.html'); }
        }
      }
      const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
        '.ttf': 'font/ttf', '.png': 'image/png', '.svg': 'image/svg+xml', '.json': 'application/json' };
      response.writeHead(200, { 'Content-Type': mime[extname(file)] || 'application/octet-stream' }).end(await readFile(file));
    } catch { response.writeHead(404).end(); }
  }));
  function token(subject = 'user_engineering', changes = {}) {
    const now = Math.floor(Date.now() / 1000);
    const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsigned = encode({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' }) + '.' + encode({
      iss: 'https://clerk.engineering.invalid', sub: subject, sid: 'sess_engineering',
      azp: web, iat: now, nbf: now - 5, exp: now + 1800, ...changes });
    return unsigned + '.' + sign('RSA-SHA256', Buffer.from(unsigned), privateKey).toString('base64url');
  }

  const result = await Promise.race([cancelled, journey({ root, scratch, artifacts, start, run, ready, json, port,
    web, issuerAPI, token, keyFetches: () => keyFetches, proxy: proxy.register,
    async page(signed, origins) {
      assert.equal(kind, 'browser', 'a component fixture cannot launch a browser');
      const require = createRequire(resolve('app/package.json'));
      const { chromium } = require('playwright');
      assert(Array.isArray(origins) && origins.length, 'declare the disposable backend origins');
      const allowed = new Set([web, ...origins]);
      browser = await chromium.launch({ headless: true });
      context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
      await context.route('**/*', route => {
        const request = route.request();
        const url = new URL(request.url());
        if (allowed.has(url.origin)) return route.continue();
        blockedRequests.push(url.origin + url.pathname);
        return route.abort('blockedbyclient');
      });
      await context.tracing.start({ screenshots: true, snapshots: true });
      await context.addInitScript(value => { window.__ENGINEERING_ISOLATED_AUTH = value; }, signed);
      const page = await context.newPage();
      page.setDefaultTimeout(20000);
      return page;
    },
  })]);
  assert.deepEqual(blockedRequests, [], 'browser attempted to leave the disposable stack');
  await writeFile(join(artifacts, 'journey.json'), JSON.stringify({ project, ...result }, null, 2) + '\n');
  failed = false;
  console.log(`${project}: ${kind} verification passed.`);
} finally {
  stopping = true;
  clearTimeout(deadline);
  const cleanupErrors = [];
  if (context) {
    if (failed) for (const page of context.pages()) await page.screenshot({ path: join(artifacts, 'failure.png') }).catch(() => {});
    await context.tracing.stop(failed ? { path: join(artifacts, 'trace.zip') } : {}).catch(() => {});
  }
  await browser?.close().catch(error => cleanupErrors.push(error));
  for (const entry of children.slice().reverse()) {
    if (entry.container) await new Promise((accept, reject) => {
      const cleanup = spawn('docker', ['rm', '-f', entry.container], { stdio: 'ignore', timeout: 30000 });
      cleanup.once('error', reject);
      cleanup.once('exit', code => code === 0 ? accept() : reject(new Error('Container cleanup failed')));
    }).catch(error => cleanupErrors.push(error));
    if (entry.child.exitCode === null && entry.child.signalCode === null) {
      try { process.kill(-entry.child.pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
      await Promise.race([entry.completion.catch(() => {}), new Promise(accept => setTimeout(accept, 5000))]);
      if (entry.child.exitCode === null && entry.child.signalCode === null) {
        try { process.kill(-entry.child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
        await entry.completion.catch(() => {});
      }
    }
  }
  for (const server of servers) { server.closeAllConnections(); server.close(); }
  await rm(scratch, { recursive: true, force: true });
  process.off('SIGINT', interrupt);
  process.off('SIGTERM', interrupt);
  if (cleanupErrors.length) throw new AggregateError(cleanupErrors, 'Browser stack cleanup failed');
}

}

export const browserGate = (project, journey, options = {}) => stackFixture(project, journey, { ...options, kind: 'browser' });
export const integrationGate = (project, journey, options = {}) => stackFixture(project, journey, { ...options, kind: 'integration' });
export const artifactGate = (project, journey, options = {}) => stackFixture(project, journey, { ...options, kind: 'artifact' });
