import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native_job_preparation',ROOT/'tests/support/native_host_job_preparation.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


class NativeJobPreparation(unittest.TestCase):
    def setUp(self):
        self.podman=SimpleNamespace(st_dev=7,st_ino=10)
        self.timeout=SimpleNamespace(st_dev=7,st_ino=11)
        self.receipt={'application':'scope','instance':'production','job':'initialize',
            'release_digest':'sha256:'+'a'*64,'ownership':'b'*32,'identity':'sha256:'+'c'*64,
            'container_name':'kmz-owned-job','native_timeout_seconds':14}
        common={'state':'S','start_ticks':123,'group':b'0::/komizo/control/controller\n',
                'uids':(0,0,0,0),'gids':(0,0,0,0)}
        self.controller={**common,'pid':200,'parent':1,'exe':SimpleNamespace(st_dev=7,st_ino=12),'argv':['komizo-box']}
        argv=['/usr/bin/podman','--remote=false','--cgroup-manager=cgroupfs','create',
            '--name','kmz-owned-job','--timeout','14']
        for name,key in [('application','application'),('instance','instance'),('service','job'),
                         ('release','release_digest'),('ownership','ownership'),('job.identity','identity')]:
            argv.extend(['--label','io.komizo.'+name+'='+self.receipt[key]])
        self.parent={**common,'pid':201,'parent':200,'exe':self.timeout,
            'argv':['/usr/bin/timeout','--signal=KILL','29.999s',*argv]}
        self.child={**common,'pid':202,'parent':201,'exe':self.podman,'argv':argv}
    def accepted(self):return fixture.creator_identity(self.child,self.parent,self.controller,self.receipt,self.podman,self.timeout)
    def test_only_complete_exact_root_controller_timeout_creator_chain_is_selected(self):
        self.assertTrue(self.accepted())
    def test_running_job_start_or_wrapper_is_never_selected_for_pause(self):
        for index,value in [(0,'/usr/bin/timeout'),(1,'--remote=true'),(2,'--cgroup-manager=systemd'),(3,'start')]:
            child=copy.deepcopy(self.child);child['argv'][index]=value
            with self.subTest(value=value):self.assertFalse(fixture.creator_identity(child,self.parent,self.controller,self.receipt,self.podman,self.timeout))
    def test_foreign_scope_and_timeout_and_duplicate_name_are_refused(self):
        for key in ['application','instance','job','release_digest','ownership','identity','container_name','native_timeout_seconds']:
            changed={**self.receipt,key:15 if key=='native_timeout_seconds' else 'foreign'}
            with self.subTest(key=key):self.assertFalse(fixture.creator_identity(self.child,self.parent,self.controller,changed,self.podman,self.timeout))
        self.child['argv'].extend(['--name',self.receipt['container_name']]);self.assertFalse(self.accepted())
    def test_sibling_parent_or_other_controller_is_refused(self):
        for object_,key,value in [(self.child,'parent',999),(self.parent,'parent',999),(self.controller,'pid',999)]:
            original=object_[key];object_[key]=value
            with self.subTest(key=key):self.assertFalse(self.accepted())
            object_[key]=original
    def test_other_executable_inode_is_refused(self):
        for object_ in [self.child,self.parent]:
            previous=object_['exe'];object_['exe']=SimpleNamespace(st_dev=7,st_ino=999)
            self.assertFalse(self.accepted());object_['exe']=previous
    def test_unprivileged_or_foreign_cgroup_or_dead_process_is_refused(self):
        for object_ in [self.child,self.parent,self.controller]:
            for key,value in [('uids',(10001,10001,10001,10001)),('gids',(10001,10001,10001,10001)),
                ('group',b'0::/komizo/production/foreign\n'),('start_ticks',0)]:
                original=object_[key];object_[key]=value
                with self.subTest(key=key):self.assertFalse(self.accepted())
                object_[key]=original
        for object_ in [self.child,self.parent]:
            original=object_['state'];object_['state']='Z';self.assertFalse(self.accepted());object_['state']=original
    def test_changed_guard_arguments_cannot_pause_the_native_watchdog(self):
        for argv in [['/usr/bin/timeout','--signal=TERM','29.999s',*self.child['argv']],
                     ['/usr/bin/timeout','--signal=KILL','29.999s','/usr/bin/podman','start','foreign']]:
            self.parent['argv']=argv;self.assertFalse(self.accepted())
    def test_all_worker_thread_children_are_unioned_without_unrelated_process_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            proc=Path(directory)
            def children(pid,tid,body):
                path=proc/str(pid)/'task'/str(tid);path.mkdir(parents=True);(path/'children').write_text(body)
            children(200,200,'')
            children(200,207,'201 201 299')
            children(201,201,'202')
            foreign={**self.parent,'pid':299,'exe':SimpleNamespace(st_dev=7,st_ino=999)}
            # No task/children file exists for the foreign wrapper or unrelated
            # process. A global scan or descent through either fails this case.
            (proc/'900').mkdir()
            values={201:self.parent,202:self.child,299:foreign}
            with mock.patch.object(fixture,'process',side_effect=lambda root,pid:values[pid]) as observed:
                candidates=list(fixture.creation_candidates(proc,200,self.timeout))
            self.assertEqual(candidates,[(self.child,self.parent)])
            self.assertEqual({call.args[1] for call in observed.call_args_list},{201,202,299})
            self.assertTrue(fixture.creator_identity(*candidates[0],self.controller,self.receipt,self.podman,self.timeout))
    def test_child_inventory_rejects_malformed_or_overlong_identifiers(self):
        for body in ['2 invalid','2 0','2 1','2 -3','2 12345678901','2 '+('3'*4096)]:
            with self.subTest(body=body[:32]),tempfile.TemporaryDirectory() as directory:
                proc=Path(directory);task=proc/'200/task/200';task.mkdir(parents=True);(task/'children').write_text(body)
                with self.assertRaises(ValueError):fixture.child_pids(proc,200)
    def test_child_and_task_inventories_remain_finitely_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            proc=Path(directory);task=proc/'200/task/200';task.mkdir(parents=True)
            (task/'children').write_text(' '.join(map(str,range(2,67))))
            with self.assertRaisesRegex(ValueError,'child inventory'):fixture.child_pids(proc,200)
            (task/'children').write_text('')
            for tid in range(201,329):
                child=task.parent/str(tid);child.mkdir();(child/'children').write_text('')
            with self.assertRaisesRegex(ValueError,'task inventory'):fixture.child_pids(proc,200)
    def test_foreign_parent_or_different_timeout_wrapper_is_not_descended(self):
        for changed in [{'parent':999},{'argv':['/usr/bin/timeout','--signal=TERM']},
                        {'exe':SimpleNamespace(st_dev=99,st_ino=11)}]:
            with self.subTest(changed=changed):
                parent={**self.parent,**changed}
                with mock.patch.object(fixture,'child_pids',return_value=[201]) as children, \
                     mock.patch.object(fixture,'process',return_value=parent):
                    self.assertEqual(list(fixture.creation_candidates(Path('/unused'),200,self.timeout)),[])
                children.assert_called_once_with(Path('/unused'),200)


class StoppedUpstreamRecovery(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name);self.app='prepoverrun';self.operation='a'*32
        self.canonical=lambda value:json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        self.digest=lambda value:'sha256:'+hashlib.sha256(value).hexdigest()
        namespace='kmz-'+hashlib.sha256((self.app+'\0production').encode()).hexdigest()[:20]
        self.config={'kind':'komizo.service-config','version':1,'application':self.app,'instance':'production',
            'service':'upstream','release_digest':'sha256:'+'b'*64,'ownership':'c'*32,
            'container_name':namespace+'-upstream','image_id':'sha256:'+'d'*64,'options':['--cap-drop=all'],
            'command':['sleep','120'],'health':{'command':['/bin/busybox','sh','-c',':']},'wanted':True}
        self.record={'name':self.config['container_name'],'id':'e'*64,'image':'registry.fixture/upstream',
            'config_digest':self.config['image_id'],'release_digest':self.config['release_digest'],
            'ownership':self.config['ownership'],'unit_sha256':self.digest(self.canonical(self.config)),'volumes':{}}
        self.installed={'operation_id':self.operation,'desired_running':True,'resources':{'containers':{'upstream':self.record}}}
        self.actual={'Id':self.record['id'],'Config':{'Labels':{
            'io.komizo.application':self.app,'io.komizo.instance':'production','io.komizo.service':'upstream',
            'io.komizo.release':self.record['release_digest'],'io.komizo.ownership':self.record['ownership']}},
            'State':{'Running':True,'Paused':False,'Pid':123,'StartedAt':'2026-11-12T12:00:00Z',
                'FinishedAt':'0001-01-01T00:00:00Z','ExitCode':0,'OOMKilled':False}}
        self.creation={'kind':'komizo.service-creation','version':1,'application':self.app,'instance':'production',
            'operation_id':self.operation,'service':'upstream','record':{**self.record,'id':''},
            'unit_body':self.canonical(self.config).decode()}
        self.path=self.root/'service-configs'/(self.record['name']+'.json');self.path.parent.mkdir()
        self.journal=self.root/'journal'/self.operation;self.journal.mkdir(parents=True)
        (self.root/'operations').mkdir()
        (self.root/'operations'/(self.operation+'.json')).write_bytes(self.canonical({'phase':'needs_reconciliation','ok':False}))
        self.write_creation();self.write_current()
        self.runtime=SimpleNamespace(registry=SimpleNamespace(canonical=self.canonical,digest=self.digest),
            installed=lambda app:copy.deepcopy(self.installed),container=lambda record:copy.deepcopy(self.actual))

    def write_creation(self):
        (self.journal/'service-creation-upstream.json').write_bytes(self.canonical(self.creation))

    def write_current(self):
        body=self.canonical(self.config);self.path.write_bytes(body)
        self.record['unit_sha256']=self.digest(body)
        (self.root/'units.json').write_bytes(self.canonical({str(self.path):{
            'application':self.app,'instance':'production','sha256':self.record['unit_sha256']}}))

    def snapshot(self):return fixture.upstream_snapshot(self.runtime,self.app,self.operation,self.root)

    def stop(self):
        self.config['wanted']=False;self.installed['desired_running']=False;self.write_current()
        self.actual['State'].update(Running=False,Pid=0,FinishedAt='2026-11-12T12:00:10Z',ExitCode=143)

    def test_normal_stop_changes_only_wanted_and_recovery_preserves_stopped_identity(self):
        before=self.snapshot();self.stop();stopped=self.snapshot()
        fixture.stopped_upstream(before,stopped)
        self.assertNotEqual(before['config_sha256'],stopped['config_sha256'])
        self.assertEqual(before['creation_sha256'],stopped['creation_sha256'])
        fixture.recovered_upstream(stopped,self.snapshot())

    def test_even_self_consistent_foreign_config_hash_is_not_accepted(self):
        for field,value in [('command',['sleep','999']),('options',['--privileged']),
            ('image_id','sha256:'+'f'*64),('wanted',False)]:
            with self.subTest(field=field):
                original=copy.deepcopy(self.config);self.config[field]=value;self.write_current()
                with self.assertRaisesRegex(ValueError,'differs beyond'):self.snapshot()
                self.config=original;self.write_current()

    def test_creation_identity_or_native_ownership_tamper_is_refused(self):
        for object_,key,value in [(self.creation['record'],'ownership','f'*32),
            (self.creation,'operation_id','f'*32),(self.actual,'Id','f'*64),
            (self.actual['Config']['Labels'],'io.komizo.ownership','f'*32)]:
            with self.subTest(key=key):
                original=object_[key];object_[key]=value;self.write_creation()
                with self.assertRaises(ValueError):self.snapshot()
                object_[key]=original;self.write_creation()

    def test_stop_requires_live_original_and_proves_unchanged_creation_and_operation(self):
        before=self.snapshot();self.stop();after=self.snapshot()
        for group,key,value in [('native','Running',True),('native','StartedAt','2026-11-12T12:00:05Z'),
            ('native','id','f'*64),(None,'creation_sha256','f'*64),(None,'original_operation_sha256','f'*64),
            (None,'config_sha256',before['config_sha256'])]:
            with self.subTest(key=key):
                changed=copy.deepcopy(after);(changed[group] if group else changed)[key]=value
                with self.assertRaises(ValueError):fixture.stopped_upstream(before,changed)

    def test_recovery_cannot_start_service_change_configuration_or_rewrite_original_evidence(self):
        self.stop();stopped=self.snapshot()
        for group,key,value in [('native','Running',True),('native','Pid',456),
            ('native','StartedAt','2026-11-12T12:00:20Z'),('native','FinishedAt','2026-11-12T12:00:21Z'),
            (None,'config_sha256','f'*64),(None,'original_operation_sha256','f'*64),
            (None,'creation_sha256','f'*64)]:
            with self.subTest(key=key):
                changed=copy.deepcopy(stopped);(changed[group] if group else changed)[key]=value
                with self.assertRaises(ValueError):fixture.recovered_upstream(stopped,changed)

    def test_actual_preparation_declarations_fit_unchanged_sum_allocation(self):
        def limits(memory,cpu,pids):
            return {'memory_bytes':memory*(1<<20),'memory_swap_bytes':memory*(1<<20),
                'milli_cpus':cpu,'pids':pids}
        for upstream,total in [(False,30),(True,20)]:
            workload={'services':{},'jobs':{},'assets':{'web':{'artifact':'web'}},
                'networks':{},'volumes':{},'routes':[]}
            unchanged={key:copy.deepcopy(workload[key]) for key in ['assets','networks','volumes','routes']}
            fixture.preparation_workload(workload,limits,total,upstream)
            values=[*workload['services'].values(),*workload['jobs'].values()]
            self.assertEqual(sum(value['limits']['milli_cpus'] for value in values),100)
            for key,budget in limits(96,100,32).items():
                self.assertLessEqual(sum(value['limits'][key] for value in values),budget)
                self.assertTrue(all(value['limits'][key]>0 for value in values))
            self.assertEqual(workload['jobs']['initialize']['timeout_seconds'],total)
            self.assertEqual({key:workload[key] for key in unchanged},unchanged)
            if upstream:
                self.assertEqual(workload['jobs']['initialize']['needs'],{'upstream':'healthy'})
                self.assertEqual(workload['services']['upstream']['artifact'],workload['jobs']['initialize']['artifact'])
                self.assertEqual(workload['services']['upstream']['networks'],[])
            else:self.assertEqual(workload['services'],{})


if __name__=='__main__':unittest.main()
