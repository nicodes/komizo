import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('audit', Path(__file__).parents[1]/'helpers/audit.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class VerifiedRepairs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name)
        self.package = self.app/'node_modules/image-size'
        self.package.mkdir(parents=True)
        (self.package/'package.json').write_text(json.dumps({'version':'1.2.1'}))
        (self.package/'parser.js').write_text('reviewed repair')
        (self.app/'fix.patch').write_text('reviewed patch')
        self.repair = {'owner':'nicodes','rationale':'fixture','package':'image-size','version':'1.2.1',
            'review_date':str(datetime.date.today()+datetime.timedelta(days=1)),
            'patch':'fix.patch','patch_sha256':hashlib.sha256(b'reviewed patch').hexdigest(),
            'installed_sha256':{'parser.js':hashlib.sha256(b'reviewed repair').hexdigest()}}

    def test_patch_file_does_not_prove_it_was_installed(self):
        (self.package/'parser.js').write_text('unpatched parser')
        with self.assertRaisesRegex(RuntimeError, 'absent or modified'):
            module.verify_repair(self.app, self.repair)

    def test_a_second_unpatched_copy_is_not_covered(self):
        nested = self.app/'node_modules/other/node_modules/image-size'
        nested.mkdir(parents=True)
        (nested/'package.json').write_text('{"version":"1.2.1"}')
        (nested/'parser.js').write_text('unpatched parser')
        with self.assertRaisesRegex(RuntimeError, 'nested'):
            module.verify_repair(self.app, self.repair)

    def test_expired_upstream_review_is_required(self):
        self.repair['review_date'] = '2020-01-01'
        with self.assertRaisesRegex(RuntimeError, 'overdue'):
            module.verify_repair(self.app, self.repair)

    def test_exact_installed_repair(self):
        module.verify_repair(self.app, self.repair)


if __name__ == '__main__':
    unittest.main()


class AcceptedFindings(unittest.TestCase):
    """Accept only caller-reviewed findings with explicit ownership and expiry.

    Installed versions alone do not establish production reachability. The caller
    must record its rationale; verified local repairs remain a separate path.
    """

    def accepted(self, **over):
        base = {'kind': 'accepted', 'owner': 'nicodes', 'package': 'brace-expansion',
                'advisories': ['GHSA-qhr7-859c-m2p7'],
                'rationale': 'build-time only: reached through eslint and expo config '
                             'plugins, and nothing in production runs JavaScript.',
                'review_date': str(datetime.date.today() + datetime.timedelta(days=30))}
        base.update(over)
        return base

    def test_an_examined_finding_is_accepted(self):
        module.verify_accepted(self.accepted())

    def test_an_overdue_acceptance_fails_the_build(self):
        # The whole point. An acceptance with no end is a permanent hole
        # nobody revisits, which is worse than the strictness it replaces.
        with self.assertRaises(RuntimeError) as caught:
            module.verify_accepted(self.accepted(
                review_date=str(datetime.date.today() - datetime.timedelta(days=1))))
        self.assertIn('overdue', str(caught.exception))

    def test_every_acceptance_is_owned_and_dated(self):
        for missing in ('owner', 'rationale', 'package', 'advisories', 'review_date'):
            with self.subTest(missing=missing):
                entry = self.accepted()
                del entry[missing]
                with self.assertRaises(RuntimeError):
                    module.verify_accepted(entry)

    def test_a_rationale_has_to_say_something(self):
        # "wontfix" is not a review. The reader of this file months from now
        # needs to be able to check the reasoning, not just that a box was
        # ticked.
        with self.assertRaises(RuntimeError) as caught:
            module.verify_accepted(self.accepted(rationale='not exploitable'))
        self.assertIn('rationale somebody can review', str(caught.exception))


class WhatTheBuildLogSays(unittest.TestCase):
    """A build log is read months later by somebody deciding whether to trust
    a release. "Locally repaired and verified" about a finding that was
    merely accepted tells them the opposite of what happened: the dependency
    is still present and still unpatched."""

    def report(self, app, findings):
        import subprocess
        from unittest import mock
        completed = subprocess.CompletedProcess([], 1, json.dumps(findings), '')
        with mock.patch.object(module.subprocess, 'run', return_value=completed), \
             mock.patch.object(module.sys, 'argv', ['audit.py', str(app)]):
            from io import StringIO
            import contextlib
            out = StringIO()
            with contextlib.redirect_stdout(out):
                module.main()
            return out.getvalue()

    def test_an_accepted_finding_is_not_reported_as_repaired(self):
        app = Path(self.temp.name) if hasattr(self, 'temp') else None
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        app = Path(temp.name)
        (app/'security-remediations.json').write_text(json.dumps([{
            'kind': 'accepted', 'package': 'brace-expansion', 'owner': 'nicodes',
            'advisories': ['GHSA-qhr7-859c-m2p7'],
            'rationale': 'build-time only; nothing in production runs JavaScript at all.',
            'review_date': str(datetime.date.today() + datetime.timedelta(days=10))}]))
        said = self.report(app, {'brace-expansion': [
            {'severity': 'high', 'url': 'https://github.com/advisories/GHSA-qhr7-859c-m2p7'}]})
        self.assertIn('Accepted as unreachable', said)
        self.assertIn('expires', said)
        self.assertNotIn('repaired and verified', said)
