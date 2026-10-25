// LOCAL_AUTH_ONLY: never part of a release image or a public bundle.
//
// A loopback issuer that mints Clerk-shaped tokens, so local development
// needs no Clerk tenant. The caller supplies its origins and header name.
//
// The point is not to fake authentication. The product's unchanged Clerk SDK
// still verifies the signature, the expiry and the authorized party -- it
// just fetches JWKS from 127.0.0.1 and validates a reserved .invalid issuer
// name that is never resolved. A developer gets a real token-shaped session
// without a real tenant, and the verification path exercised locally is the
// same code that runs in production.
//
// Every refusal below is deliberate. This process signs tokens, so anything
// that is not a loopback browser on the one origin it was told about gets
// nothing.
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { createServer } from 'node:http';

/** A literal 127.0.0.1 HTTP origin with a port, and nothing else. */
export function localOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash ||
      value !== url.origin) {
    throw new Error('Local auth requires a literal 127.0.0.1 HTTP origin with a port');
  }
  return url;
}

/**
 * One stable identity per email, so a developer's local data survives a
 * restart. Hashed rather than the address itself: the subject reaches the
 * database, and it should not be a mailbox.
 */
export function identityForEmail(input) {
  if (typeof input !== 'string') throw new Error('Enter an email address');
  const email = input.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error('Enter an email address');
  }
  return { email, subject: 'local_dev_' + createHash('sha256').update(email).digest('hex') };
}

/**
 * @param origin      where this issuer listens, e.g. http://127.0.0.1:8099
 * @param appOrigin   the one browser origin allowed to ask for a token
 * @param headerName  the product's own anti-form header, e.g. X-Example-Local-Auth.
 *                    A cross-origin HTML form cannot set a custom header, so
 *                    requiring one keeps a page on another site from driving
 *                    this even if it somehow reached the port.
 */
export function createLocalIssuer({ origin, appOrigin, headerName = 'X-Local-Auth' }) {
  const issuer = localOrigin(origin);
  localOrigin(appOrigin);
  const header = headerName.toLowerCase();
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: randomUUID(), alg: 'RS256', use: 'sig' };
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');

  const server = createServer(async (req, res) => {
    const reply = (status, value) => {
      res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(value));
    };
    if (req.headers.host !== issuer.host) return reply(403, { message: 'Invalid local host' });
    const browserOrigin = req.headers.origin;
    if (browserOrigin !== undefined && browserOrigin !== appOrigin) {
      return reply(403, { message: 'Local origin required' });
    }
    // A browser always sends Sec-Fetch-Site. Its presence without an Origin
    // means a browser deliberately withheld one; a CLI or native client sends
    // neither and is allowed.
    if (browserOrigin === undefined && req.headers['sec-fetch-site']) {
      return reply(403, { message: 'Browser origin required' });
    }
    if (browserOrigin === appOrigin) {
      res.setHeader('Access-Control-Allow-Origin', appOrigin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Headers', `Content-Type, ${headerName}`);
      res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    }
    if (req.method === 'OPTIONS') { res.writeHead(204).end(); return; }
    if (req.method === 'GET' && req.url === '/healthz') return reply(200, { status: 'ok', localOnly: true });
    if (req.method === 'GET' && ['/jwks', '/v1/jwks'].includes(req.url)) return reply(200, { keys: [jwk] });
    if (req.method !== 'POST' || req.url !== '/token') return reply(404, { message: 'Not found' });
    if (req.headers[header] !== '1' || req.headers['content-type'] !== 'application/json') {
      return reply(403, { message: 'Local JSON client required' });
    }
    try {
      const chunks = [];
      let length = 0;
      for await (const chunk of req) {
        length += chunk.length;
        if (length > 4096) return reply(413, { message: 'Request too large' });
        chunks.push(chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!body || Object.keys(body).some(key => key !== 'email')) throw new Error('Only email is accepted');
      const { email, subject } = identityForEmail(body.email);
      const now = Math.floor(Date.now() / 1000);
      const unsigned = encode({ alg: 'RS256', typ: 'JWT', kid: jwk.kid }) + '.' + encode({
        // A Clerk-shaped issuer the SDK will validate. This reserved .invalid
        // name is never fetched; JWKS comes from loopback.
        iss: 'https://clerk.local.invalid',
        sub: subject,
        sid: randomUUID(),
        azp: appOrigin,
        iat: now,
        nbf: now - 5,
        exp: now + 300,
      });
      const token = unsigned + '.' + sign('RSA-SHA256', Buffer.from(unsigned), privateKey).toString('base64url');
      reply(200, { email, token });
    } catch {
      reply(400, { message: 'Enter a valid email address; only email is accepted' });
    }
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  return server;
}

/**
 * Run it from a product's own one-line wrapper. The product passes the names
 * of its own variables, because every product spells its environment
 * differently and this helper should not have to know how.
 */
export function runFromEnvironment(env, { environmentVar, switchVar, originVar, appOriginVar, headerName }) {
  if (env[environmentVar] !== 'development' || env[switchVar] !== '1') {
    throw new Error(`Local issuer requires ${environmentVar}=development and ${switchVar}=1`);
  }
  const origin = env[originVar];
  const endpoint = localOrigin(origin);
  const server = createLocalIssuer({ origin, appOrigin: env[appOriginVar], headerName });
  server.listen(Number(endpoint.port), '127.0.0.1',
    () => console.log(`Local-only email sign-in: ${origin}`));
  return server;
}
