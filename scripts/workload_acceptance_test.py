import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('workload_acceptance.py'));fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)

def profile():
    h=hashlib.sha256(b'fixture').hexdigest()
    return {'version':1,'binary_sha256':h,'resources_sha256':h,'app_revisions':{'example':'a'*40},'probes':[{'url':'https://example.invalid/health','app':'example','revision':'a'*40}],'cases':[{'app':'example','operator':'full_inventory','repetitions':1},{'app':'example','operator':'operation_inspection','repetitions':1}]}

class WorkloadFixtureContract(unittest.TestCase):
    def test_unknown_or_weakened_profile_refuses(self):
        for mutate in [lambda p:p.update(seconds=1),lambda p:p['cases'][0].update(operator='cached'),lambda p:p['cases'][0].update(repetitions=0),lambda p:p['probes'][0].update(url='http://example.invalid/'),lambda p:p['probes'][0].update(revision='b'*40),lambda p:p.update(binary_sha256='latest')]:
            p=profile();mutate(p)
            with self.assertRaises(ValueError):fixture.validate(p)

    def test_later_success_never_hides_failure_and_independent_cases_continue(self):
        with patch.object(fixture.os,'geteuid',return_value=0),patch.object(Path,'read_bytes',return_value=b'fixture'),patch.object(fixture,'run_case',side_effect=[{'accepted':False,'cleanup':True},{'accepted':True,'cleanup':True}]) as run:
            result=fixture.run(profile())
        self.assertFalse(result['accepted']);self.assertEqual(len(result['results']),2);self.assertEqual(run.call_count,2)

    def test_cleanup_failure_and_preflight_failure_are_not_skipped_green(self):
        for value in [{'accepted':True,'cleanup':False},RuntimeError('fixture failure')]:
            with patch.object(fixture.os,'geteuid',return_value=0),patch.object(Path,'read_bytes',return_value=b'fixture'),patch.object(fixture,'run_case',side_effect=[value,{'accepted':True,'cleanup':True}]):
                result=fixture.run(profile())
            self.assertFalse(result['accepted']);self.assertEqual(len(result['results']),2)

    def test_changed_installed_binary_refuses_before_pressure(self):
        with patch.object(fixture.os,'geteuid',return_value=0),patch.object(Path,'read_bytes',return_value=b'changed'),patch.object(fixture,'run_case') as run:
            with self.assertRaises(ValueError):fixture.run(profile())
        run.assert_not_called()

if __name__=='__main__':unittest.main()
