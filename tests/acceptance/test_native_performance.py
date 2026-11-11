"""Finished loads retain measured kernel CPU evidence after their owned cgroup is removed."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SUPPORT = Path(__file__).parents[1] / 'support'
spec = importlib.util.spec_from_file_location('performance_acceptance_support', SUPPORT / 'native_host_acceptance.py')
acceptance = importlib.util.module_from_spec(spec); spec.loader.exec_module(acceptance)
spec = importlib.util.spec_from_file_location('native_performance_fixture', SUPPORT / 'native_host_performance.py')
fixture = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'acceptance': acceptance}):
    spec.loader.exec_module(fixture)


class FinishedLoadAccounting(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.group = '/komizo/production/native-fixture-load-owned'
        self.unit = self.group.rsplit('/', 1)[1]
        self.cgroups = self.root / 'cgroups'; self.cgroups.mkdir()
        self.events = {'komizo/memory.events': {'oom': 0, 'oom_kill': 0}}
        self.state = {'unit': self.unit, 'group': self.group, 'before': self.events, 'metrics': {'load_hot_bytes': 64 << 20}}
        (self.root / 'performance-state.json').write_text(json.dumps(self.state))
        self.completion = {'name':self.unit,'group':self.group,'exit_code':0,'timed_out':False,'populated':False,'cpu_usage_usec':2345678}
        self.commands = []

    def finish(self):
        with patch.object(fixture, 'ROOT', self.root), patch.object(fixture, 'CGROUP', self.cgroups), \
                patch.object(fixture.fixture_tasks, 'result', side_effect=lambda _:copy.deepcopy(self.completion)), \
                patch.object(fixture.fixture_tasks, 'stop', side_effect=lambda unit:self.commands.append(unit)), \
                patch.object(fixture.fixture_tasks, 'populated', return_value=False), \
                patch.object(fixture, 'oom', return_value=copy.deepcopy(self.events)), contextlib.redirect_stdout(io.StringIO()):
            fixture.finish({'load_seconds': 15})

    def test_successful_pruned_load_uses_the_actual_retained_counter_and_cleans_up(self):
        self.assertFalse((self.cgroups / self.group.removeprefix('/')).exists())
        self.finish()
        measured = json.loads((self.root / 'performance-metrics.json').read_bytes())
        self.assertEqual(measured['load_cpu_usec'], 2345678)
        self.assertTrue(measured['oom_events_unchanged']); self.assertTrue(measured['owned_load_removed'])
        self.assertEqual(self.commands,[self.unit])

    def test_missing_nonfinite_infinite_and_nonpositive_counters_refuse_without_success(self):
        for value in (None, '', '0', -1, 0, 'NaN', 'inf', '[not set]', '1e9', True, '1234',
                      18446744073709551615, 18446744073709551616):
            with self.subTest(value=value):
                self.completion['cpu_usage_usec'] = value; self.commands.clear()
                with self.assertRaisesRegex(ValueError, 'accounting is missing or invalid'):
                    self.finish()
                self.assertEqual(self.commands,[self.unit])
                self.assertFalse((self.root / 'performance-metrics.json').exists())

    def test_unaccounted_or_unsuccessful_load_cannot_report_a_positive_counter(self):
        for field, value in [('exit_code',9),('exit_code',True),('timed_out',True),('populated',True),('group','/foreign')]:
            with self.subTest(field=field), patch.dict(self.completion,{field:value}):
                self.commands.clear()
                with self.assertRaises(ValueError):self.finish()
                self.assertEqual(self.commands,[self.unit])
                self.assertFalse((self.root/'performance-metrics.json').exists())


class InstalledApkBoundary(unittest.TestCase):
    def test_actual_package_guard_selects_installed_identity_and_retains_exact_version_refusals(self):
        baseline=json.loads((SUPPORT.parent/'fixtures/native_host/baseline.json').read_bytes())
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'baseline.json').write_text(json.dumps(baseline))
            release=root/'os-release';release.write_text('ID=alpine\nVERSION_ID=3.24.3\n')
            executable=root/'apk.py'
            class GuardPassed(Exception):pass
            class LsmBoundary:
                def read_text(self):raise GuardPassed
            def selected_path(value):
                if str(value)=='/etc/os-release':return release
                if str(value)=='/sys/module/apparmor/parameters/enabled':return LsmBoundary()
                raise AssertionError('unexpected effect path '+str(value))
            def command(arguments,**options):
                if arguments[0]=='podman':return subprocess.CompletedProcess(arguments,0,b'5.8.10\n',b'')
                self.assertEqual(arguments[0],'apk')
                return subprocess.run([sys.executable,'-I','-B',str(executable),*arguments[1:]],capture_output=True,check=True)
            for identity in ['podman-5.8.10-r0','podman-5.8.9-r0','other-5.8.10-r0',
                    'podman-5.8.10-r0\npodman-5.8.10-r0','podman-5.8.10-r0 description:\nmetadata']:
                executable.write_text('import sys\nprint('+repr(identity)+
                    " if sys.argv[1:]==['info','--installed','-v','podman'] else 'podman descriptive package fields')\n")
                with self.subTest(identity=identity),patch.object(acceptance,'ROOT',root), \
                        patch.object(acceptance,'Path',side_effect=selected_path),patch.object(acceptance,'run',side_effect=command):
                    with self.assertRaises(GuardPassed if identity=='podman-5.8.10-r0' else ValueError):
                        acceptance.prepare()


if __name__ == '__main__': unittest.main()
