"""Performance failures disclose finite facts, never arbitrary guest diagnostics."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock

spec=importlib.util.spec_from_file_location('native_performance_driver',Path(__file__).parents[1]/'support/native_host_vm.py')
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)


class PerformanceDiagnostics(unittest.TestCase):
    def test_missing_counter_retains_failure_class_without_private_stderr_or_stdout(self):
        guest=Mock()
        guest.command.return_value=subprocess.CompletedProcess([],1,b'private-output',
            b'Traceback\nFileNotFoundError: private-token/private-path/cpu.stat\n')
        with self.assertRaises(ValueError) as failure:
            driver.performance_metrics(guest,{'load_seconds':15})
        self.assertEqual(json.loads(str(failure.exception)),{'phase':'bounded_performance_collection',
            'exit_code':1,'exception_class':'FileNotFoundError','missing_cpu_stat':True})
        self.assertNotIn('private',str(failure.exception))

    def test_unknown_exception_text_does_not_become_a_public_diagnostic(self):
        guest=Mock()
        guest.command.return_value=subprocess.CompletedProcess([],1,b'',b'UntrustedError: secret-value\n')
        with self.assertRaises(ValueError) as failure:
            driver.performance_metrics(guest,{'load_seconds':15})
        self.assertEqual(json.loads(str(failure.exception))['exception_class'],'unclassified')
        self.assertNotIn('secret',str(failure.exception))

    def test_numeric_observation_excludes_unknown_state_and_refuses_nonfinite_or_string_values(self):
        metrics={key:1 for key in ('guest_memory_bytes','guest_milli_cpus','setup_seconds','deployment_seconds',
            'idle_control_pss_bytes','load_hot_bytes','load_cpu_usec')}
        metrics.update(route_seconds=[.1]*5,operator_seconds=[.2]*5,oom_events_unchanged=True,
            owned_load_removed=True,private_state='never export this')
        self.assertNotIn('private_state',driver.public_performance_observation(metrics))
        for invalid in (float('nan'),float('inf'),'secret-value'):
            metrics['idle_control_pss_bytes']=invalid
            with self.subTest(invalid=invalid),self.assertRaisesRegex(ValueError,'invalid public performance measurement'):
                driver.public_performance_observation(metrics)


if __name__=='__main__':unittest.main()
