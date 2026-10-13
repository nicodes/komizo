import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('workload_acceptance.py'));fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)

def profile():
    h=hashlib.sha256(b'fixture').hexdigest()
    return {'version':1,'binary_sha256':h,'resources_sha256':h,'app_revisions':{'example':'a'*40},'probes':[{'url':'https://example.invalid/health','app':'example','revision':'a'*40}],'cases':[{'app':'example','operator':'full_inventory','repetitions':1},{'app':'example','operator':'operation_inspection','repetitions':1}]}

class WorkloadFixtureContract(unittest.TestCase):
    def test_snapshot_distinguishes_cache_and_live_charges_with_actual_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            group=Path(directory)/'openrc.docker';group.mkdir()
            values={'memory.current':'120','memory.swap.current':'7','memory.events':'oom 0\noom_kill 0\n','memory.high':'100','memory.max':'160','cpu.stat':'usage_usec 4\n','io.stat':'','memory.stat':'anon 50\nfile 60\nkernel 10\ninactive_file 40\n'}
            for name,value in values.items():(group/name).write_text(value)
            row=fixture.snapshot([group])[str(group)]
            self.assertEqual(row['memory_charges'],{'anon':50,'file':60,'kernel':10,'inactive_file':40})
            self.assertEqual(row['memory.high'],'100');self.assertEqual(row['memory.max'],'160')

    def test_probe_cadence_respects_a_thirty_per_minute_service(self):
        clock=[0.0];tokens=30.0;last=0.0
        def read():
            nonlocal tokens,last
            tokens=min(30,tokens+(clock[0]-last)*.5);last=clock[0]
            self.assertGreaterEqual(tokens,1,'declared read cadence exhausted service budget');tokens-=1
        with patch.object(fixture.time,'monotonic',side_effect=lambda:clock[0]),patch.object(fixture.time,'sleep',side_effect=lambda seconds:clock.__setitem__(0,clock[0]+seconds)):
            for _ in range(7):
                read() # Each case retains its independent baseline.
                for _ in range(20):
                    start=clock[0];read();clock[0]+=.1
                    fixture.wait_for_probe_round(start,2)
        self.assertEqual(clock[0],280)

    def test_versioned_cadence_is_explicit_and_cannot_change_latency_limits(self):
        fixture.validate(profile())
        for value in (None,True,0,11,2.5):
            p=profile();p.update(version=2,probe_interval_seconds=value)
            with self.assertRaises(ValueError):fixture.validate(p)
        p=profile();p.update(version=2,probe_interval_seconds=2);fixture.validate(p)
        p['core_seconds']=3
        with self.assertRaises(ValueError):fixture.validate(p)

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
            if isinstance(value,Exception):
                self.assertEqual(result['results'][0]['operator'],'full_inventory')
                self.assertEqual(result['results'][0]['error'],'fixture failure')

    def test_changed_installed_binary_refuses_before_pressure(self):
        with patch.object(fixture.os,'geteuid',return_value=0),patch.object(Path,'read_bytes',return_value=b'changed'),patch.object(fixture,'run_case') as run:
            with self.assertRaises(ValueError):fixture.run(profile())
        run.assert_not_called()

if __name__=='__main__':unittest.main()
