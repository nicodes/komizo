// Transport only: products choose the disposable backend and route prefix.
import { request as httpRequest } from 'node:http';
import assert from 'node:assert/strict';

const hopHeaders = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
function headers(source) {
  const excluded = new Set([...hopHeaders, ...(source.connection || '').split(',').map(value => value.trim().toLowerCase())]);
  return Object.fromEntries(Object.entries(source).filter(([name]) => !excluded.has(name.toLowerCase())));
}
export function fixtureProxy() {
  const routes = new Map();
  return {
    register(prefix, origin) {
      assert(/^\/[a-z][a-z0-9-]*$/.test(prefix), 'proxy requires a single explicit route prefix');
      const target = new URL(origin);
      assert(target.protocol === 'http:' && target.hostname === '127.0.0.1' && target.port && target.pathname === '/' && !target.search && !target.hash && !target.username && !target.password, 'proxy target must be a disposable loopback HTTP origin');
      assert(!routes.has(prefix), 'proxy prefix is already registered');
      routes.set(prefix, target.origin);
    },
    handle(request, response) {
      const path = new URL(request.url, 'http://localhost');
      const route = [...routes.entries()].find(([prefix]) => path.pathname === prefix || path.pathname.startsWith(prefix + '/'));
      if (!route) return false;
      const [prefix, origin] = route;
      const target = new URL(origin);
      const forwardedHeaders = headers(request.headers);
      forwardedHeaders.host = target.host;
      const upstream = httpRequest({ hostname: target.hostname, port: target.port, method: request.method,
        path: (path.pathname.slice(prefix.length) || '/') + path.search, headers: forwardedHeaders }, incoming => {
        response.writeHead(incoming.statusCode, headers(incoming.headers));
        incoming.on('error', () => response.destroy());
        incoming.pipe(response);
      });
      upstream.setTimeout(15000, () => upstream.destroy(new Error('fixture proxy timeout')));
      upstream.on('error', () => {
        if (response.headersSent) response.destroy();
        else response.writeHead(502).end('Disposable backend unavailable');
      });
      request.on('aborted', () => upstream.destroy());
      response.on('close', () => { if (!response.writableFinished) upstream.destroy(); });
      request.pipe(upstream);
      return true;
    },
  };
}
