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
    def test_guard_deadline_kills_only_its_opened_fixture_interface(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            leaf=Path(directory)/'owned';leaf.mkdir();kill=leaf/'cgroup.kill';kill.write_text('0')
            sibling=Path(directory)/'sibling';sibling.write_text('untouched')
            guard,lease=fixture.fixture_guard(leaf,seconds=.05)
            self.assertEqual(guard.communicate(timeout=3)[0],b'deadline\n')
            os.close(lease)
            self.assertEqual(kill.read_text(),'1');self.assertEqual(sibling.read_text(),'untouched')

    def test_guard_normal_completion_preserves_workers_and_lost_parent_kills(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            leaf=Path(directory);kill=leaf/'cgroup.kill';kill.write_text('0')
            guard,lease=fixture.fixture_guard(leaf,seconds=3)
            fixture.finish_fixture_guard(guard,lease);self.assertEqual(kill.read_text(),'0')
            guard,lease=fixture.fixture_guard(leaf,seconds=3);os.close(lease)
            self.assertEqual(guard.communicate(timeout=3)[0],b'parent_lost\n');self.assertEqual(kill.read_text(),'1')

    def test_guard_refuses_symlink_and_never_reports_timeout_as_success(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            leaf=Path(directory)/'owned';leaf.mkdir();target=Path(directory)/'foreign';target.write_text('0')
            (leaf/'cgroup.kill').symlink_to(target)
            with self.assertRaises(OSError):fixture.fixture_guard(leaf)
            self.assertEqual(target.read_text(),'0');(leaf/'cgroup.kill').unlink();(leaf/'cgroup.kill').write_text('0')
            guard,lease=fixture.fixture_guard(leaf,seconds=.05);guard.wait(timeout=3)
            with self.assertRaisesRegex(RuntimeError,'not accepted'):fixture.finish_fixture_guard(guard,lease)

    def test_already_charged_group_still_allocates_and_touches_live_pages(self):
        import json,subprocess,sys
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'memory.current').write_text(str(64<<20))
            code=fixture.hot_memory_worker(root,32<<20,8<<20,seconds=.05)
            process=subprocess.run([sys.executable,'-I','-c',code],capture_output=True,text=True,timeout=3,check=True)
            rows=[json.loads(line) for line in process.stdout.splitlines()]
            self.assertEqual(rows,[{'ready':True,'hot_bytes':4<<20},{'peak_hot_bytes':4<<20}])
            # No readiness report is allowed when a real allocation cannot fit.
            code=fixture.hot_memory_worker(root,32<<20,0,seconds=.05)
            process=subprocess.run([sys.executable,'-I','-c',code],capture_output=True,text=True,timeout=3)
            self.assertNotEqual(process.returncode,0);self.assertEqual(process.stdout,'')

    def test_pressure_loss_exhausts_the_declared_offer_instead_of_silently_fading(self):
        import json,subprocess,sys
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);charge=root/'memory.current';charge.write_text(str(64<<20))
            code=fixture.hot_memory_worker(root,32<<20,8<<20,seconds=.5)
            process=subprocess.Popen([sys.executable,'-I','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            self.assertEqual(json.loads(process.stdout.readline()),{'ready':True,'hot_bytes':4<<20})
            charge.write_text('0')
            out,error=process.communicate(timeout=3)
            self.assertNotEqual(process.returncode,0)
            self.assertIn('hot memory offer exhausted',error)
            self.assertNotIn('peak_hot_bytes',out)

    def test_local_inventory_preserves_running_identity_without_cli(self):
        import json,socket,threading
        cid='a'*64;item={'Id':cid,'State':{'Running':True},'Config':{'Env':['PRIVATE=value']}}
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'engine.sock');server=socket.socket(socket.AF_UNIX);server.bind(path);server.listen();seen=[]
            def serve():
                client,_=server.accept();reader=client.makefile('rb')
                for value in [[{'Id':cid}],item]:
                    line=reader.readline().decode();seen.append(line.split()[1])
                    while reader.readline()!=b'\r\n':pass
                    body=json.dumps(value).encode();client.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
                reader.close();client.close()
            worker=threading.Thread(target=serve,daemon=True);worker.start()
            with patch.object(fixture,'command',side_effect=AssertionError('CLI inventory forbidden')):
                self.assertEqual(fixture.local_docker_inventory(path),[item])
            worker.join(timeout=5);server.close();self.assertFalse(worker.is_alive())
            self.assertEqual(seen,['/v1.47/containers/json','/v1.47/containers/'+cid+'/json'])

    def test_local_inventory_failure_has_no_cli_fallback(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(fixture,'command') as command:
            with self.assertRaises(OSError):fixture.local_docker_inventory(str(Path(directory)/'missing'))
        command.assert_not_called()

    def test_declared_control_drift_is_refused_without_pressure_or_writes(self):
        group={'memory_low_bytes':24,'memory_high_bytes':160,'memory_bytes':176,'swap_bytes':128,'pids':256,'cpu_weight':50}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'openrc.komizo-rootd';path.mkdir()
            values={'memory.low':'24','memory.high':'160','memory.max':'176','memory.swap.max':'128','pids.max':'256','cpu.weight':'50','cpu.max':'max 100000'}
            for key,value in values.items():(path/key).write_text(value)
            policy={'controls':{'openrc.komizo-rootd':group}};fixture.verify_control_limits(policy,root)
            (path/'memory.max').write_text('max')
            with self.assertRaisesRegex(AssertionError,'control_policy'):fixture.verify_control_limits(policy,root)
            self.assertEqual((path/'memory.max').read_text(),'max')

    def test_timed_out_read_names_route_phase_and_elapsed_time_without_retry(self):
        from types import SimpleNamespace
        connection=SimpleNamespace(request=lambda *a,**k:None,getresponse=lambda:(_ for _ in ()).throw(TimeoutError()),close=lambda:None)
        with patch.object(fixture.http.client,'HTTPSConnection',return_value=connection) as client,patch.object(fixture.time,'monotonic',side_effect=[10.0,12.0]):
            with self.assertRaises(AssertionError) as error:fixture.probe_route(profile()['probes'][0])
        import json
        result=json.loads(str(error.exception));self.assertEqual(result['url'],'https://example.invalid/health');self.assertEqual(result['phase'],'headers');self.assertEqual(result['seconds'],2);self.assertEqual(result['error_kind'],'TimeoutError');self.assertEqual(client.call_count,1)

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
