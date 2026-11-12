"""Performance failures disclose finite facts, never arbitrary guest diagnostics."""
import ast
import copy
import importlib.util
import inspect
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

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


class NativeFailureDiagnostics(unittest.TestCase):
    def setUp(self):
        self.failure={'kind':'komizo.failure','version':1,'operation_id':'a'*32,
            'phase':'jobs','code':'jobs_failed','context':'job preparation exhausted its native lifetime reservation; start refused'}
        self.evidence={'kind':'komizo.native-fixture-evidence','version':1,
            'operations':[{'kind':'komizo.operation','version':1,'operation_id':'a'*32,
                'application':'pgbox','instance':'production','phase':'needs_reconciliation','failure':self.failure}],
            'containers':[{'id':'b'*64,'application':'pgbox','instance':'production','service':'initialize','state':'exited',
                'failure_observation':{'exit_code':0,'oom_killed':False,'error':'',
                    'logs':{'state':'observed','stdout':'retained native row\n','stderr':'','timed_out':False,
                        'stdout_truncated':False,'stderr_truncated':False,'command_exit_code':0}}}]}

    def observe(self, evidence=None, journal=b''):
        return json.loads(driver.native_failure_observation(
            json.dumps(self.evidence if evidence is None else evidence).encode(),journal,'bounded','c'*40,'d'*64))

    def test_only_closed_failure_and_container_fields_are_retained(self):
        self.evidence.update(Env=['NO_EXPORT=private'],Config={'Args':'private'},requests={'key':'private'})
        self.evidence['containers'][0].update(Env=['private'],Config={'private':'private'},Args=['private'])
        self.failure['unknown']='private'
        result=self.observe()
        self.assertEqual(result['operations'][0]['context']['text'],self.failure['context'])
        self.assertEqual(result['containers'][0]['exit_code'],0)
        self.assertIs(result['containers'][0]['oom_killed'],False)
        self.assertEqual(result['containers'][0]['logs']['command_exit_code'],0)
        self.assertNotIn('private',json.dumps(result))
        self.assertNotIn('Env',json.dumps(result))

    def test_context_logs_and_kernel_scrub_all_fixture_secret_canaries(self):
        canaries=['e'*48,'runtime-'+'f'*32,'migration-'+'1'*32,
            'SCRAM-SHA-256$4096:secret-salt$secret-key:server-key','md5'+'2'*32]
        text='auth failed '+' '.join(canaries)
        self.failure['context']=text
        self.evidence['containers'][0]['failure_observation']['logs']['stderr']=text
        result=self.observe(journal=('oom-kill: '+text).encode())
        for secret in canaries:self.assertNotIn(secret,json.dumps(result))
        for forbidden in ['-----BEGIN PRIVATE KEY-----\nsecret-pem\n-----END PRIVATE KEY-----',
            'host=private-host user=private-user password=private-password',
            'postgresql://user:private-password@private-host/db']:
            self.failure['context']=forbidden
            result=self.observe()
            self.assertNotIn('private-password',json.dumps(result));self.assertNotIn('secret-pem',json.dumps(result))
            self.assertNotIn('postgresql://',json.dumps(result))

    def test_context_and_logs_mark_their_truncation_and_oversized_values_unobserved(self):
        self.failure['context']='x'*6000
        logs=self.evidence['containers'][0]['failure_observation']['logs'];logs['stdout']='x'*6000;logs['timed_out']=True
        result=self.observe()
        self.assertEqual(len(result['operations'][0]['context']['text']),2048)
        self.assertTrue(result['operations'][0]['context']['truncated'])
        self.assertTrue(result['containers'][0]['logs']['timed_out'])
        self.assertTrue(result['containers'][0]['logs']['stdout']['truncated'])
        self.failure['context']='x'*65537
        self.assertEqual(self.observe()['operations'][0]['context']['state'],'unobserved')

    def test_parse_failure_duplicate_unknown_kind_and_oversized_input_are_unobserved(self):
        for raw in [None,b'not-json',b'{}',b'{"kind":1,"kind":2}',b'x'*((1<<20)+1),b'\xff',b'['*1500+b']'*1500]:
            with self.subTest(raw=str(raw)[:25]):
                result=json.loads(driver.native_failure_observation(raw,None,'bounded','c'*40,'d'*64))
                self.assertEqual(result['state'],'unobserved')
        self.evidence['kind']='unknown'
        self.assertEqual(self.observe()['state'],'unobserved')

    def test_forged_failure_or_container_identity_is_unobserved(self):
        for object_,field,value in [(self.failure,'operation_id','f'*32),
            (self.evidence['containers'][0],'id','not-a-container'),
            (self.evidence['containers'][0],'application','../foreign'),
            (self.evidence['containers'][0],'state','unknown')]:
            before=object_[field];object_[field]=value
            with self.subTest(field=field):self.assertEqual(self.observe()['state'],'unobserved')
            object_[field]=before

    def test_container_and_operation_inventory_bounds_are_not_silently_accepted(self):
        for field in ['operations','containers']:
            evidence=copy.deepcopy(self.evidence);evidence[field]*=33
            with self.subTest(field=field):self.assertEqual(self.observe(evidence)['state'],'unobserved')
            evidence[field]=None
            self.assertEqual(self.observe(evidence)['state'],'unobserved')

    def test_only_finite_kernel_oom_and_apparmor_lines_are_emitted(self):
        journal=b'private unrelated line\n'+b'oom-kill: owned synthetic podman\n'*12+b'apparmor="DENIED" operation="exec"\n'
        result=self.observe(journal=journal)
        self.assertEqual(len(result['kernel']['events']),8);self.assertTrue(result['kernel']['truncated'])
        self.assertNotIn('unrelated',json.dumps(result))
        self.assertEqual(self.observe(journal=b'x'*65537)['kernel']['state'],'unobserved')

    def test_complete_export_never_exceeds_32k_including_newline(self):
        self.failure['context']='\x00'*10000
        self.evidence['operations']*=4
        row=self.evidence['containers'][0]
        row['failure_observation']['logs'].update(stdout='\x00'*10000,stderr='\x00'*10000)
        self.evidence['containers']*=4
        encoded=driver.native_failure_observation(json.dumps(self.evidence).encode(),b'','bounded','c'*40,'d'*64)
        self.assertLessEqual(len(encoded.encode())+1,32768)
        self.assertEqual(json.loads(encoded)['reason'],'closed_export_limit')

    def test_success_is_completely_silent_and_does_not_parse_diagnostics(self):
        with patch.object(driver,'native_failure_observation',side_effect=AssertionError('not called')) as observed,\
                patch.object(driver.sys,'stderr',new_callable=io.StringIO) as output:
            driver.emit_native_failure(False,None,None,'bounded',None,None)
            observed.assert_not_called();self.assertEqual(output.getvalue(),'')

    def test_emission_and_output_failures_do_not_replace_original_exception(self):
        cleanup=Mock()
        with patch.object(driver,'native_failure_observation',side_effect=ValueError('private-error')),\
                patch.object(driver.sys,'stderr') as output:
            output.write.side_effect=OSError('closed stream')
            with self.assertRaisesRegex(RuntimeError,'original failure'):
                try:raise RuntimeError('original failure')
                finally:
                    driver.emit_native_failure(True,None,None,'bounded',None,None)
                    cleanup()
        cleanup.assert_called_once_with()

    def test_real_vm_finally_keeps_original_failure_and_owned_cleanup_without_new_commands(self):
        tree=ast.parse(inspect.getsource(driver.main))
        final=next(node.finalbody for node in ast.walk(tree) if isinstance(node,ast.Try)
            and any(isinstance(item,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='failed' for t in item.targets)
                for item in node.finalbody))
        function=ast.parse('def trial():\n    binary_sha="'+'d'*64+'"\n    try:\n        raise RuntimeError("original VM failure")\n    finally:\n        pass\n').body[0]
        function.body[-1].finalbody=copy.deepcopy(final)
        module=ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[]))
        with tempfile.TemporaryDirectory() as directory:
            process=Mock(pid=123);process.poll.return_value=None
            guest=Mock();guest.boot_diagnostics.return_value=b'{}'
            def command(value,**kwargs):
                body=json.dumps(self.evidence).encode() if value.endswith(' evidence') else b'{}'
                return subprocess.CompletedProcess([],0,body,b'')
            guest.command.side_effect=command
            namespace={**vars(driver),'process':process,'guest':guest,'args':SimpleNamespace(output=Path(directory),profile='bounded')}
            exec(compile(module,'<actual native VM finally>','exec'),namespace)
            with patch.object(driver.os,'killpg') as kill,patch.object(driver.sys,'stderr',new_callable=io.StringIO) as output:
                with self.assertRaisesRegex(RuntimeError,'original VM failure'):namespace['trial']()
            kill.assert_called_once_with(123,driver.signal.SIGTERM);process.wait.assert_called_once_with(timeout=15)
            self.assertEqual(len(guest.command.call_args_list),5)
            self.assertEqual(json.loads(output.getvalue())['kind'],'komizo.native-fixture-failure')


if __name__=='__main__':unittest.main()
