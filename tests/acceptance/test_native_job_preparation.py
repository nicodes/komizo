import copy
import importlib.util
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


if __name__=='__main__':unittest.main()
