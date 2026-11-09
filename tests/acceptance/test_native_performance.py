"""Finished loads retain measured CPU evidence after systemd prunes their cgroup."""
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
        self.root = Path(self.temporary.name); self.group = '/komizo.slice/komizo-production.slice/komizo-fixture-load-owned.service'
        self.unit = self.group.rsplit('/', 1)[1]
        self.cgroups = self.root / 'cgroups'; self.cgroups.mkdir()
        self.events = {'komizo.slice/memory.events': {'oom': 0, 'oom_kill': 0}}
        self.state = {'unit': self.unit, 'group': self.group, 'before': self.events, 'metrics': {'load_hot_bytes': 64 << 20}}
        (self.root / 'performance-state.json').write_text(json.dumps(self.state))
        self.properties = {'SubState': 'exited', 'Result': 'success', 'ExecMainStatus': '0',
                           'CPUAccounting': 'yes', 'CPUUsageNSec': '2345678999'}
        self.commands = []; self.reads = []

    def command(self, argv, **options):
        self.commands.append(argv)
        if argv == ['systemctl', 'stop', self.unit]:
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        self.assertEqual(argv, ['systemctl', 'is-active', self.unit])
        return subprocess.CompletedProcess(argv, 3, b'inactive\n', b'')

    def show(self, unit, field):
        self.assertEqual(unit, self.unit); self.reads.append(field)
        return self.properties.get(field)

    def finish(self):
        with patch.object(fixture, 'ROOT', self.root), patch.object(fixture, 'CGROUP', self.cgroups), \
                patch.object(fixture, 'show', side_effect=self.show), patch.object(fixture, 'run', side_effect=self.command), \
                patch.object(fixture, 'oom', return_value=copy.deepcopy(self.events)), contextlib.redirect_stdout(io.StringIO()):
            fixture.finish({'load_seconds': 15})

    def test_successful_pruned_load_uses_the_actual_retained_counter_and_cleans_up(self):
        self.assertFalse((self.cgroups / self.group.removeprefix('/')).exists())
        self.finish()
        measured = json.loads((self.root / 'performance-metrics.json').read_bytes())
        self.assertEqual(measured['load_cpu_usec'], 2345678)
        self.assertTrue(measured['oom_events_unchanged']); self.assertTrue(measured['owned_load_removed'])
        self.assertIn('CPUAccounting', self.reads); self.assertIn('CPUUsageNSec', self.reads)
        self.assertEqual(self.commands, [['systemctl', 'stop', self.unit], ['systemctl', 'is-active', self.unit]])

    def test_missing_nonfinite_infinite_and_nonpositive_counters_refuse_without_success(self):
        for value in (None, '', '0', '-1', '1', '999', 'NaN', 'inf', '[not set]', '1e9', True, 1234,
                      '18446744073709551615', '18446744073709551616'):
            with self.subTest(value=value):
                self.properties['CPUUsageNSec'] = value; self.commands.clear()
                with self.assertRaisesRegex(ValueError, 'accounting is missing or invalid'):
                    self.finish()
                self.assertEqual(self.commands, [['systemctl', 'stop', self.unit]])
                self.assertFalse((self.root / 'performance-metrics.json').exists())

    def test_unaccounted_or_unsuccessful_load_cannot_report_a_positive_counter(self):
        for field, value in [('CPUAccounting', 'no'), ('CPUAccounting', None), ('Result', 'oom-kill'), ('ExecMainStatus', '9')]:
            with self.subTest(field=field), patch.dict(self.properties, {field: value}):
                self.commands.clear(); self.reads.clear()
                with self.assertRaises(ValueError): self.finish()
                self.assertNotIn('CPUUsageNSec', self.reads)
                self.assertEqual(self.commands, [['systemctl', 'stop', self.unit]])
                self.assertFalse((self.root / 'performance-metrics.json').exists())


if __name__ == '__main__': unittest.main()
