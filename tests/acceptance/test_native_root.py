import importlib.util
import json
import tempfile
from unittest.mock import patch
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('native_root_tests', Path(__file__).with_name('native-root-tests.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class RootFixtureAdmission(unittest.TestCase):
    def output(self):
        return [dict(reason='compiler-artifact', target={'name': name}, executable='/owned/' + name)
                for name in reversed(native.TARGETS)]

    def test_every_native_suite_is_required_before_any_privileged_execution(self):
        rows = self.output()
        self.assertEqual(native.executables('\n'.join(map(json.dumps, rows))),
                         ['/owned/' + name for name in native.TARGETS])
        for changed in (rows[1:], rows + [rows[0]], rows[:-1] + [dict(rows[-1], executable=None)]):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                native.executables('\n'.join(map(json.dumps, changed)))

    def test_unrelated_build_program_cannot_replace_an_omitted_native_suite(self):
        rows = self.output()[1:]
        rows.append(dict(reason='compiler-artifact', target={'name': 'unrelated'}, executable='/foreign/program'))
        with self.assertRaises(RuntimeError):
            native.executables('\n'.join(map(json.dumps, rows)))


class CapacityCeiling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('native_capacity_fixture',Path(__file__).parents[1]/'support/native_host_acceptance.py')
        cls.fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.fixture)

    def test_margin_precedes_rounding_including_exact_and_adjacent_boundaries(self):
        unit=16*self.fixture.MiB
        for physical in (64*unit,64*unit+1,65*unit-1,128*unit+15*self.fixture.MiB):
            selected=self.fixture.memory_ceiling(physical)
            self.assertEqual(selected%unit,0)
            self.assertGreaterEqual(physical-selected,unit)
            self.assertLess(physical-selected,2*unit)
            self.assertLessEqual(selected,physical-1400*1024)
        for physical in (None,True,32*self.fixture.MiB,0,-1):
            with self.assertRaises(ValueError):self.fixture.memory_ceiling(physical)

    def test_actual_policy_keeps_reserves_and_parent_below_selected_boot_ceiling(self):
        mib=self.fixture.MiB
        for profile,raw,reserve in [('functional',2071482368,512*mib),('bounded',1000000000,256*mib)]:
            with self.subTest(profile=profile),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve();(root/'profile.json').write_text(json.dumps({'profile':profile}))
                with patch.object(self.fixture,'ROOT',root),patch.object(self.fixture,'measured_memory',return_value=raw):
                    policy=self.fixture.capacity()
                self.assertEqual(policy['physical_memory_bytes'],self.fixture.memory_ceiling(raw))
                self.assertEqual(policy['os_reserve_bytes'],reserve)
                self.assertEqual(policy['limits']['memory_bytes']+reserve,policy['physical_memory_bytes'])
                self.assertLessEqual(policy['physical_memory_bytes'],raw-1400*1024)
                self.assertEqual(policy['startup_memory_bytes'],(128 if profile=='functional' else 64)*mib)
                self.assertEqual(policy['infrastructure_reserve_bytes'],(192 if profile=='functional' else 128)*mib)


if __name__ == '__main__':
    unittest.main()
