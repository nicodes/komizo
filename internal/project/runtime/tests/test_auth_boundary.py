"""The auth boundary gate: three environments, three identity sources.

Two of these tests exist because the first version of the gate got the
answer backwards in both directions -- it failed the product that implements
the contract best, and passed the ones that implement none of it. Both are
pinned here so neither can come back.
"""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest



ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'helpers/auth-boundary.mjs'

CLERK_API = {'provider': 'clerk', 'api': True, 'enforced': True}
CLERK_CLIENT = {'provider': 'clerk', 'api': False, 'enforced': True}
NO_PROVIDER = {'provider': 'none', 'api': False, 'enforced': True}

TAGGED_BYPASS = '''//go:build localdev

package clerkauth

import "os"

func local() string {
\tif os.Getenv("LOCAL_AUTH") == "1" {
\t\treturn devClerkID
\t}
\treturn ""
}

const devClerkID = "dev_local_user"
'''

REFUSAL = '''//go:build !localdev

package config

import (
\t"fmt"
\t"os"
)

func configureLocalAuth() error {
\tif os.Getenv("LOCAL_AUTH") != "" {
\t\treturn fmt.Errorf("local authentication requires the separately compiled localdev API")
\t}
\treturn nil
}
'''


def check(root, declared):
    program = (
        f'const m = await import({json.dumps(str(HELPER))});'
        'const [root, declared] = JSON.parse(process.argv[1]);'
        'console.log(JSON.stringify(m.checkAuthBoundary(root, declared)));'
    )
    result = subprocess.run(['bun', '--eval', program, json.dumps([str(root), declared])],
                            capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


def failures(findings):
    return [f['text'] for f in findings if f['level'] == 'fail']


class Product:
    """A throwaway product tree."""

    def __init__(self, directory):
        self.root = Path(directory)

    def go(self, relative, body):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        return self

    def workflow(self, name, body):
        path = self.root / '.github/workflows' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        return self

    def web(self, relative, body):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        return self

    def compliant(self):
        """The shape sampleconsole and sampleaddon have between them."""
        self.go('api/internal/clerkauth/local_auth.go', TAGGED_BYPASS)
        self.go('api/internal/config/local_auth_disabled.go', REFUSAL)
        self.workflow('pr-preview.yml',
                      'jobs:\n  p:\n    environment: Preview\n    steps:\n      - env:\n'
                      '          CLERK_SECRET_KEY_DEV: x\n'
                      '          CLERK_AUTHORIZED_PARTIES: https://pr-1.preview.example\n')
        self.workflow('cd.yml',
                      'jobs:\n  d:\n    environment: Production\n    steps:\n'
                      '      - env:\n          CLERK_SECRET_KEY_PROD: y\n')
        return self


class CompliantProduct(unittest.TestCase):
    def test_a_product_with_the_whole_contract_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            Product(directory).compliant()
            self.assertEqual(failures(check(directory, CLERK_API)), [])


class LocalBypass(unittest.TestCase):
    def test_a_runtime_flag_with_no_tagged_path_is_refused(self):
        """A product whose only dev mode is a runtime flag has no tagged
        path, which is what this reports. It does not try to find the flag:
        locating a grant by pattern is what made this rule wrong three times
        over. Whether a shipped binary can produce a development identity is
        a question for the image scan, which takes the artifact apart."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory)
            product.go('api/cmd/api/auth.go',
                       'package main\n\nimport "os"\n\nconst devClerkID = "dev_local_user"\n\n'
                       'func auth() string {\n\tif os.Getenv("APP_DEV") == "1" {\n'
                       '\t\treturn devClerkID\n\t}\n\treturn ""\n}\n')
            product.workflow('cd.yml', 'jobs:\n  d:\n    steps:\n      - env:\n          CLERK_SECRET_KEY_PROD: y\n')
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('no local development path', said)

    def test_having_no_local_path_at_all_is_a_failure_not_a_pass(self):
        """The first version passed this, which is backwards: no bypass means
        a developer points a laptop at a real Clerk instance."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            (product.root / 'api/internal/clerkauth/local_auth.go').unlink()
            (product.root / 'api/internal/config/local_auth_disabled.go').unlink()
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('no local development path', said)

    def test_a_bypass_with_no_refusal_counterpart_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            (product.root / 'api/internal/config/local_auth_disabled.go').unlink()
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('!localdev', said)

    def test_a_test_file_does_not_count_as_a_bypass(self):
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.go('api/internal/clerkauth/other_test.go',
                       'package clerkauth\n\nconst devClerkID = "dev_local_user"\n'
                       '// LOCAL_AUTH in a test\n')
            self.assertEqual(failures(check(directory, CLERK_API)), [])


class PublicVariables(unittest.TestCase):
    def test_a_client_only_public_variable_is_not_a_finding(self):
        """sampleconsole's EXPO_PUBLIC_LOCAL_AUTH_URL tells the app which local
        issuer to use. No server trusts it, so it grants nothing -- and the
        first version of this gate failed the best product in the fleet for
        having it."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.web('app/src/local-auth.ts',
                        'export const url = process.env.EXPO_PUBLIC_LOCAL_AUTH_URL;\n')
            self.assertEqual(failures(check(directory, CLERK_API)), [])

    def test_a_server_that_reads_one_is_a_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.go('api/internal/config/trust.go',
                       'package config\n\nimport "os"\n\n'
                       'func issuer() string { return os.Getenv("EXPO_PUBLIC_LOCAL_AUTH_URL") }\n')
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('browser-readable', said)
            self.assertIn('api/internal/config/trust.go', said)


class KeyRouting(unittest.TestCase):
    def test_one_workflow_reaching_both_instances_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.workflow('both.yml',
                             'jobs:\n  x:\n    steps:\n      - env:\n'
                             '          CLERK_SECRET_KEY_DEV: a\n'
                             '          CLERK_SECRET_KEY_PROD: b\n')
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('both.yml', said)

    def test_a_clerk_secret_outside_an_environment_is_refused(self):
        """The rule that replaced "the name carries a _DEV or _PROD suffix".
        A suffix is a promise -- it can be wrong and the check still passes.
        An environment is a mechanism: GitHub refuses a pull-request branch
        asking for one whose branch policy is main."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory)
            product.go('api/internal/clerkauth/local_auth.go', TAGGED_BYPASS)
            product.go('api/internal/config/local_auth_disabled.go', REFUSAL)
            product.workflow('cd.yml', 'jobs:\n  d:\n    steps:\n      - env:\n          CLERK_SECRET_KEY: y\n')
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('without declaring an environment', said)

    def test_an_unsuffixed_secret_is_fine_inside_an_environment(self):
        """The whole point of the change: CLERK_SECRET_KEY with no suffix is
        the fleet's name now, and the environment says which instance."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory)
            product.go('api/internal/clerkauth/local_auth.go', TAGGED_BYPASS)
            product.go('api/internal/config/local_auth_disabled.go', REFUSAL)
            product.workflow('cd.yml',
                             'jobs:\n  d:\n    environment: Production\n    steps:\n'
                             '      - env:\n          CLERK_SECRET_KEY: y\n')
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertNotIn('environment', said)

    def test_only_the_job_that_reads_the_secret_needs_one(self):
        """A workflow may hold unrelated jobs; the rule is per job, not per
        file, so an untouched lint job does not have to declare anything."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.workflow('cd.yml',
                             'jobs:\n  lint:\n    steps:\n      - run: echo hi\n'
                             '  d:\n    environment: Production\n    steps:\n'
                             '      - env:\n          CLERK_SECRET_KEY: y\n')
            self.assertEqual(failures(check(directory, CLERK_API)), [])


class PreviewHalf(unittest.TestCase):
    def test_a_preview_without_the_development_instance_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.workflow('pr-preview.yml',
                             'jobs:\n  p:\n    steps:\n      - env:\n'
                             '          CLERK_SECRET_KEY_PROD: x\n'
                             '          CLERK_AUTHORIZED_PARTIES: https://pr-1.preview.example\n')
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('development instance', said)

    def test_a_preview_scoped_to_the_preview_environment_is_accepted(self):
        """The Preview environment holds the development tenant on every
        product, so reading CLERK_SECRET_KEY from a job that declares it
        names the same instance CLERK_SECRET_KEY_DEV does -- and keeps the
        value behind the environment boundary rather than at repository
        level, where every job in the repository can read it."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.workflow('pr-preview.yml',
                             'jobs:\n  p:\n    environment: Preview\n    steps:\n'
                             '      - env:\n'
                             '          CLERK_SECRET_KEY: ${{ secrets.CLERK_SECRET_KEY }}\n'
                             '          CLERK_AUTHORIZED_PARTIES: https://pr-1.preview.example\n')
            self.assertEqual(failures(check(directory, CLERK_API)), [])

    def test_the_plain_key_without_an_environment_is_refused(self):
        """Without the declaration the same expression resolves at
        repository level, which is production's key. The environment is
        what makes the shorter name safe, so its absence is a failure and
        not a pass."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.workflow('pr-preview.yml',
                             'jobs:\n  p:\n    steps:\n'
                             '      - env:\n'
                             '          CLERK_SECRET_KEY: ${{ secrets.CLERK_SECRET_KEY }}\n'
                             '          CLERK_AUTHORIZED_PARTIES: https://pr-1.preview.example\n')
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('resolves to the repository-level production key', said)

    def test_a_preview_that_names_no_origin_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.workflow('pr-preview.yml',
                             'jobs:\n  p:\n    steps:\n      - env:\n          CLERK_SECRET_KEY_DEV: x\n')
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('never computes a per-PR origin', said)

    def test_an_origin_spelled_another_way_still_counts(self):
        """sampleservice hands one parsed origin policy to both CORS and Clerk's
        authorized-party handler. That is the contract, correctly kept, under
        a different name -- and an earlier version of this rule failed it for
        not saying CLERK_AUTHORIZED_PARTIES. The rule asks what the value is
        and where it goes, never what it is called."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.workflow('pr-preview.yml',
                             'jobs:\n  p:\n    environment: Preview\n    steps:\n      - run: |\n'
                             '          app_origin="https://pr-${PR_NUMBER}.preview.example"\n'
                             "          printf 'CORS_ALLOWED_ORIGINS=%s\\n' \"$app_origin\"\n"
                             '        env:\n          CLERK_SECRET_KEY_DEV: x\n')
            product.go('api/internal/clerkauth/azp.go',
                       'package clerkauth\n\nimport "os"\n\n'
                       '// AuthorizedPartyHandler takes the same policy CORS uses.\n'
                       'func policy() string { return os.Getenv("CORS_ALLOWED_ORIGINS") }\n')
            self.assertEqual(failures(check(directory, CLERK_API)), [])

    def test_a_preview_origin_that_does_not_vary_per_pull_request_is_refused(self):
        """A fixed origin in a preview workflow is production's origin: every
        preview would answer for the same Clerk audience, and for each other."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.workflow('pr-preview.yml',
                             'jobs:\n  p:\n    steps:\n      - env:\n'
                             '          CLERK_SECRET_KEY_DEV: x\n'
                             '          CLERK_AUTHORIZED_PARTIES: https://example.com\n')
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('does not vary per pull request', said)

    def test_an_origin_the_server_never_reads_is_refused(self):
        """Computing the right origin into a variable nothing consumes leaves
        the azp check deciding on something else."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.workflow('pr-preview.yml',
                             'jobs:\n  p:\n    steps:\n      - run: |\n'
                             '          app_origin="https://pr-${PR_NUMBER}.preview.example"\n'
                             "          printf 'UNUSED_ORIGINS=%s\\n' \"$app_origin\"\n"
                             '        env:\n          CLERK_SECRET_KEY_DEV: x\n')
            product.go('api/internal/clerkauth/azp.go',
                       'package clerkauth\n\nimport "os"\n\n'
                       'func policy() string { return os.Getenv("CORS_ALLOWED_ORIGINS") }\n'
                       '// AuthorizedPartyHandler consumes it.\n')
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('no Go source reads any of them', said)

    def test_no_preview_workflow_is_reported_but_does_not_fail(self):
        """The preview half cannot apply to a product that has no previews."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            (product.root / '.github/workflows/pr-preview.yml').unlink()
            findings = check(directory, CLERK_API)
            self.assertEqual(failures(findings), [])
            self.assertTrue(any('no preview workflow' in f['text'] for f in findings))


PREVIEW_WORKFLOW = """name: PR preview
on:
  pull_request:
    types: [opened, synchronize, reopened, closed]
jobs:
  preview-up:
    name: Deploy preview
    environment: Preview
    runs-on: ubuntu-24.04
    steps:
      - run: echo up
"""

BUILD_WITH_DEV_KEY = """name: CI
on:
  pull_request:
jobs:
  build:
    name: Build
    environment: Preview
    runs-on: ubuntu-24.04
    steps:
      - run: make build
        env:
          EXPO_PUBLIC_CLERK_PUBLISHABLE_KEY: ${{ github.event_name == 'pull_request' && vars.CLERK_PUBLISHABLE_KEY || 'pk_live_x' }}
"""

BUILD_WITH_ONE_KEY = """name: CI
on:
  pull_request:
jobs:
  build:
    name: Build
    runs-on: ubuntu-24.04
    steps:
      - run: make build
        env:
          EXPO_PUBLIC_CLERK_PUBLISHABLE_KEY: pk_live_x
"""


class BrowserOnlyClerk(unittest.TestCase):
    """Clerk in the browser, no server: `provider: clerk, api: False`.

    The per-PR origin and the secret key both assume a server. This shape
    has none, so the preview's tenant is decided by the PUBLISHABLE key
    baked into the bundle at build time -- and that is what gets checked.
    """

    def test_a_build_that_uses_the_development_key_on_pull_requests_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory)
            product.web('app/src/session.ts', 'import { useClerk } from "@clerk/clerk-react";\n')
            product.workflow('pr-preview.yml', PREVIEW_WORKFLOW)
            product.workflow('ci.yml', BUILD_WITH_DEV_KEY)
            self.assertEqual(failures(check(directory, CLERK_CLIENT)), [])

    def test_a_build_that_bakes_one_key_for_every_event_is_refused(self):
        """The real defect this was written for: a build.sh that hardcoded
        pk_live_ shipped the production tenant into every preview, and
        nothing caught it until previews were adopted."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory)
            product.web('app/src/session.ts', 'import { useClerk } from "@clerk/clerk-react";\n')
            product.workflow('pr-preview.yml', PREVIEW_WORKFLOW)
            product.workflow('ci.yml', BUILD_WITH_ONE_KEY)
            said = ' '.join(failures(check(directory, CLERK_CLIENT)))
            self.assertIn('development instance', said)

    def test_it_is_not_asked_for_a_per_pr_origin_it_cannot_consume(self):
        """A product with an API routes the origin into its CORS policy and
        its azp allowlist. With no server there is nowhere for it to go, so
        requiring it would only ever be satisfied by a variable nothing
        reads."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory)
            product.web('app/src/session.ts', 'import { useClerk } from "@clerk/clerk-react";\n')
            product.workflow('pr-preview.yml', PREVIEW_WORKFLOW)
            product.workflow('ci.yml', BUILD_WITH_DEV_KEY)
            said = ' '.join(f['text'] for f in check(directory, CLERK_CLIENT))
            self.assertNotIn('per-PR origin', said)


class DeclaredProvider(unittest.TestCase):
    def test_a_product_declaring_none_may_not_reference_clerk(self):
        with tempfile.TemporaryDirectory() as directory:
            Product(directory).web('app/src/session.ts', 'import { useClerk } from "@clerk/clerk-react";\n')
            said = ' '.join(failures(check(directory, NO_PROVIDER)))
            self.assertIn('declared auth.provider "none"', said)

    def test_a_product_declaring_none_and_using_none_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            Product(directory).web('app/src/main.ts', 'export const x = 1;\n')
            self.assertEqual(failures(check(directory, NO_PROVIDER)), [])

    def test_a_client_only_product_is_asked_for_no_server_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            Product(directory).web('app/src/session.ts', 'import { useClerk } from "@clerk/clerk-react";\n')
            self.assertEqual(failures(check(directory, CLERK_CLIENT)), [])

    def test_an_undeclared_product_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            said = ' '.join(failures(check(directory, None)))
            self.assertIn('no auth declaration in the caller policy', said)




if __name__ == '__main__':
    unittest.main()


class RecognisesStructureNotSpelling(unittest.TestCase):
    """The rule is about the build tag, not about a magic string.

    The gate failed sampleaddon's genuine local path because sampleaddon writes
    "sk_test_local_development_only" with underscores where sampleconsole uses a
    hyphen. A product should not have to spell a constant a particular way
    to satisfy a structural rule.
    """

    def test_a_tagged_bypass_counts_however_it_names_its_key(self):
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            (product.root / 'api/internal/clerkauth/local_auth.go').write_text(
                '//go:build localdev\n\npackage clerkauth\n\nimport "os"\n\n'
                'func local() string {\n\tif os.Getenv("SAMPLE_ADDON_LOCAL_AUTH") != "1" {\n'
                '\t\treturn ""\n\t}\n\treturn "sk_test_local_development_only"\n}\n')
            self.assertEqual(failures(check(directory, CLERK_API)), [])

    def test_a_call_site_of_a_tagged_grant_is_not_a_finding(self):
        """The rule flagged `devIdentity()` -- the CALL of a correctly tagged
        grant -- because the name matched its pattern. Structure, not names."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            product.go('api/cmd/api/auth.go',
                       'package main\n\nimport "os"\n\n'
                       'func auth(dev bool) string {\n'
                       '\tif identity, ok := devIdentity(); ok && dev && os.Getenv("APP_DEV") == "1" {\n'
                       '\t\treturn identity\n\t}\n\treturn ""\n}\n')
            self.assertEqual(failures(check(directory, CLERK_API)), [])

    def test_the_refusal_file_is_not_mistaken_for_the_bypass(self):
        """`//go:build !localdev` contains the word; it is the opposite file."""
        with tempfile.TemporaryDirectory() as directory:
            product = Product(directory).compliant()
            (product.root / 'api/internal/clerkauth/local_auth.go').unlink()
            said = ' '.join(failures(check(directory, CLERK_API)))
            self.assertIn('no local development path', said)
