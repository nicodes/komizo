import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('cache_evidence', Path(__file__).parents[1]/'helpers/cache-evidence.py')
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


class CacheEvidence(unittest.TestCase):
    def test_false_output_does_not_claim_a_miss(self):
        self.assertEqual(cache.state('true', 'false')['lookup'], 'fallback-or-miss')

    def test_missing_output_does_not_claim_a_hit(self):
        self.assertEqual(cache.state('true', '')['lookup'], 'unavailable')

    def test_disabled_cache_does_not_inherit_stale_output(self):
        self.assertEqual(cache.state('false', 'true'), {'enabled': False, 'lookup': 'disabled'})
