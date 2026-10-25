import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('policy', Path(__file__).resolve().parents[1]/'helpers/dependency-policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

class DependencyPolicy(unittest.TestCase):
    def test_routine_versions(self):
        self.assertTrue(policy.eligible('expo', '57.0.19', '57.0.20', 'version-update:semver-patch'))
        self.assertTrue(policy.eligible('example', '2.1.0', '2.2.0', 'version-update:semver-minor'))
        self.assertTrue(policy.eligible('example', '0.2.0', '0.2.1', 'version-update:semver-patch'))

    def test_review_boundaries(self):
        for name in ['@clerk/expo', '@noble/curves', 'github.com/pocketbase/pocketbase', 'golang.org/x/crypto', 'jose', 'jsonwebtoken', 'node-forge']:
            with self.subTest(name=name):
                self.assertFalse(policy.eligible(name, '1.0.0', '1.0.1', 'version-update:semver-patch'))
        for names, old, new, kind, group in [
            ('expo,react', '1.0.0', '1.0.1', 'patch', ''),
            ('expo', '1.0.0', '1.0.1', 'patch', 'framework'),
            ('example', '0.2.0', '0.3.0', 'minor', ''),
            ('example', '1.0.0', '2.0.0', 'minor', ''),
            ('example', '2.0.0', '1.0.0', 'patch', ''),
            ('example', '1.0.0', '1.1.0-rc.1', 'minor', ''),
            ('example', '', '1.1.0', 'minor', ''),
        ]:
            self.assertFalse(policy.eligible(names, old, new, f'version-update:semver-{kind}', group))
