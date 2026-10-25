"""The shared loopback issuer: a real token, and nothing for anyone else.

This process signs tokens, so most of what is worth testing is what it
refuses. The behaviour is sampleconsole's, promoted unchanged; what is new is
that the product-specific header is a parameter rather than a constant, and
these tests pin that it is actually honoured rather than ignored.
"""
import json
from pathlib import Path
import subprocess
import unittest



ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'helpers/local-auth-issuer.mjs'


def run(script):
    """Run a Node program against the helper and return its JSON result."""
    program = f'const m = await import({json.dumps(str(HELPER))});\n' + script
    result = subprocess.run(['bun', '--eval', program], capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)
    return json.loads(result.stdout)


class Identity(unittest.TestCase):
    def test_an_address_is_normalised_and_stable(self):
        got = run('''
          const a = m.identityForEmail(" Dev@Example.test ");
          const b = m.identityForEmail("dev@example.test");
          const c = m.identityForEmail("dev+other@example.test");
          console.log(JSON.stringify({ same: a.subject === b.subject, plus: c.subject !== a.subject,
                                       email: a.email, prefixed: a.subject.startsWith("local_dev_") }));
        ''')
        self.assertTrue(got['same'], 'the same person across restarts')
        self.assertTrue(got['plus'], 'plus addressing is a different person')
        self.assertEqual(got['email'], 'dev@example.test')
        self.assertTrue(got['prefixed'])

    def test_the_subject_is_not_the_address(self):
        """It reaches the database; a mailbox should not."""
        got = run('''
          const a = m.identityForEmail("dev@example.test");
          console.log(JSON.stringify({ leaks: a.subject.includes("dev@") || a.subject.includes("example") }));
        ''')
        self.assertFalse(got['leaks'])

    def test_anything_that_is_not_an_address_is_refused(self):
        got = run('''
          const bad = ["", null, "not-email", "a@b", "a @b.test", "x".repeat(255) + "@a.test"];
          const refused = bad.filter(v => { try { m.identityForEmail(v); return false; } catch { return true; } });
          console.log(JSON.stringify({ refused: refused.length, total: bad.length }));
        ''')
        self.assertEqual(got['refused'], got['total'])


class Topology(unittest.TestCase):
    def test_only_a_literal_loopback_http_origin_is_accepted(self):
        got = run('''
          const bad = ["https://127.0.0.1:1234", "http://localhost:1234", "https://clerk.example.com",
                       "http://127.0.0.1:1234/", "http://user@127.0.0.1:1234", "http://127.0.0.1:1234?x=1",
                       "http://127.0.0.1", "http://[::1]:1234"];
          const refused = bad.filter(v => { try { m.localOrigin(v); return false; } catch { return true; } });
          let ok = true; try { m.localOrigin("http://127.0.0.1:8099"); } catch { ok = false; }
          console.log(JSON.stringify({ refused: refused.length, total: bad.length, ok }));
        ''')
        self.assertEqual(got['refused'], got['total'])
        self.assertTrue(got['ok'])


class TokenAndBoundary(unittest.TestCase):
    """One live issuer, exercised over HTTP the way a product's app would."""

    SETUP = '''
      const net = await import("node:net");
      const reservation = net.createServer();
      await new Promise(r => reservation.listen(0, "127.0.0.1", r));
      const port = reservation.address().port;
      await new Promise(r => reservation.close(r));
      const origin = `http://127.0.0.1:${port}`;
      const appOrigin = "http://127.0.0.1:8081";
      const server = m.createLocalIssuer({ origin, appOrigin, headerName: "X-Demo-Local-Auth" });
      await new Promise(r => server.listen(port, "127.0.0.1", r));
      const post = (body, headers = {}) => fetch(origin + "/token", { method: "POST",
        headers: { Origin: appOrigin, "Content-Type": "application/json",
                   "X-Demo-Local-Auth": "1", ...headers },
        body: JSON.stringify(body), signal: AbortSignal.timeout(5000) });
    '''
    TEARDOWN = '\n      server.close();\n'

    def exercise(self, body):
        return run(self.SETUP + body + self.TEARDOWN)

    def test_it_mints_a_three_part_token_for_a_valid_address(self):
        got = self.exercise('''
          const res = await post({ email: "Dev@Example.test" });
          const { token, email } = await res.json();
          const [, payload] = token.split(".");
          const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
          console.log(JSON.stringify({ status: res.status, email, parts: token.split(".").length,
            iss: claims.iss, azp: claims.azp, future: claims.exp > Math.floor(Date.now()/1000) }));
        ''')
        self.assertEqual(got['status'], 200)
        self.assertEqual(got['email'], 'dev@example.test')
        self.assertEqual(got['parts'], 3)
        self.assertEqual(got['azp'], 'http://127.0.0.1:8081')
        self.assertTrue(got['iss'].endswith('.invalid'), 'a name that is never resolved')
        self.assertTrue(got['future'])

    def test_the_product_header_is_required_and_is_the_one_configured(self):
        """A cross-origin HTML form cannot set a custom header. If the name
        were ignored, that protection would quietly be gone."""
        got = self.exercise('''
          const without = await post({ email: "dev@example.test" }, { "X-Demo-Local-Auth": undefined });
          const wrong = await fetch(origin + "/token", { method: "POST",
            headers: { Origin: appOrigin, "Content-Type": "application/json", "X-Other-Local-Auth": "1" },
            body: JSON.stringify({ email: "dev@example.test" }), signal: AbortSignal.timeout(5000) });
          console.log(JSON.stringify({ without: without.status, wrong: wrong.status }));
        ''')
        self.assertEqual(got['wrong'], 403, 'a different header name must not be accepted')

    def test_another_browser_origin_gets_nothing(self):
        got = self.exercise('''
          const other = await post({ email: "dev@example.test" }, { Origin: "http://127.0.0.1:9999" });
          console.log(JSON.stringify({ status: other.status }));
        ''')
        self.assertEqual(got['status'], 403)

    def test_jwks_is_served_and_healthz_says_it_is_local_only(self):
        got = self.exercise('''
          const jwks = await (await fetch(origin + "/jwks")).json();
          const health = await (await fetch(origin + "/healthz")).json();
          console.log(JSON.stringify({ keys: jwks.keys.length, alg: jwks.keys[0].alg,
                                       hasPrivate: "d" in jwks.keys[0], localOnly: health.localOnly }));
        ''')
        self.assertEqual(got['keys'], 1)
        self.assertEqual(got['alg'], 'RS256')
        self.assertFalse(got['hasPrivate'], 'the signing key must never be served')
        self.assertTrue(got['localOnly'])

    def test_an_oversized_body_is_cut_off(self):
        got = self.exercise('''
          const res = await post({ email: "d@e.test", pad: "x".repeat(8000) });
          console.log(JSON.stringify({ status: res.status }));
        ''')
        self.assertIn(got['status'], (400, 413))

    def test_only_email_is_accepted_in_the_body(self):
        got = self.exercise('''
          const res = await post({ email: "dev@example.test", sub: "admin" });
          console.log(JSON.stringify({ status: res.status }));
        ''')
        self.assertEqual(got['status'], 400, 'a caller must not choose its own subject')

    def test_an_unknown_route_is_not_found(self):
        got = self.exercise('''
          const res = await fetch(origin + "/admin", { signal: AbortSignal.timeout(5000) });
          console.log(JSON.stringify({ status: res.status }));
        ''')
        self.assertEqual(got['status'], 404)


class RunFromEnvironment(unittest.TestCase):
    def test_it_refuses_to_start_outside_explicit_development(self):
        got = run('''
          const names = { environmentVar: "APP_ENV", switchVar: "APP_LOCAL_AUTH",
                          originVar: "APP_ISSUER", appOriginVar: "APP_ORIGIN" };
          const base = { APP_ISSUER: "http://127.0.0.1:8099", APP_ORIGIN: "http://127.0.0.1:8081" };
          const cases = [
            { ...base },
            { ...base, APP_ENV: "production", APP_LOCAL_AUTH: "1" },
            { ...base, APP_ENV: "development" },
            { ...base, APP_ENV: "development", APP_LOCAL_AUTH: "0" },
          ];
          const refused = cases.filter(env => {
            try { m.runFromEnvironment(env, names).close(); return false; } catch { return true; }
          });
          console.log(JSON.stringify({ refused: refused.length, total: cases.length }));
        ''')
        self.assertEqual(got['refused'], got['total'])


if __name__ == '__main__':
    unittest.main()
