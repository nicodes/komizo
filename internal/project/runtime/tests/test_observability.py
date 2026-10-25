import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'helpers'/filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


contract = module('observed_contract', 'contract.py')
summary = module('timing_summary', 'timing-summary.py')


class ObservabilityTests(unittest.TestCase):
    def test_failure_timing_preserves_exit_code_without_command_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = contract.Runner({'stages': {'unit': [['adapter', 'secret-argument']]}})
            runner.root = Path(directory)
            with mock.patch.object(contract, 'identity', return_value='b'*64), \
                 mock.patch.object(contract.subprocess, 'check_output', return_value='a'*40+'\n'), \
                 mock.patch.object(contract.subprocess, 'run', side_effect=subprocess.CalledProcessError(7, ['adapter'])):
                with self.assertRaises(subprocess.CalledProcessError) as failure:
                    runner.stage('unit')
            self.assertEqual(failure.exception.returncode, 7)
            text = (runner.root/'timings.jsonl').read_text()
            rows = [json.loads(line) for line in text.splitlines()]
            self.assertEqual([row['exit_code'] for row in rows], [7, 7])
            self.assertNotIn('secret-argument', text)

    def test_unwritable_telemetry_does_not_mask_adapter_failure(self):
        runner = contract.Runner({'stages': {'unit': [['adapter']]}})
        with mock.patch.object(contract, 'identity', return_value='b'*64), \
             mock.patch.object(contract.subprocess, 'check_output', return_value='a'*40+'\n'), \
             mock.patch.object(contract.subprocess, 'run', side_effect=subprocess.CalledProcessError(9, ['adapter'])), \
             mock.patch.object(Path, 'mkdir', side_effect=OSError('unwritable')):
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                runner.stage('unit')
        self.assertEqual(failure.exception.returncode, 9)

    def test_summary_excludes_child_adapter_durations(self):
        rendered = summary.render([{'stage': 'unit', 'seconds': 3, 'exit_code': 0},
                                   {'stage': 'unit', 'seconds': 2, 'exit_code': 0, 'adapter': 'bash'}])
        self.assertEqual(rendered.count('| unit |'), 1)
        self.assertIn('3.000', rendered)

    def test_provenance_does_not_claim_tests_from_another_job(self):
        runner = contract.Runner({'stages': {'unit': [['adapter']], 'integration': [['adapter']]}})
        with mock.patch.object(contract.subprocess, 'check_output', return_value='a'*40+'\n'):
            self.assertIsNone(runner.provenance('b'*64)['tested_commit'])
            runner.done.update(['unit', 'integration'])
            self.assertIsNone(runner.provenance('b'*64)['tested_commit'])
            runner.test_receipts.update({name: {'source_commit': 'a'*40, 'input_identity': 'b'*64}
                                         for name in ('unit', 'integration')})
            self.assertEqual(runner.provenance('b'*64)['tested_commit'], 'a'*40)
            self.assertIsNone(runner.provenance('c'*64)['tested_commit'])
