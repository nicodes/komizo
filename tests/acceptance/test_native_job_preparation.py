import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

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


if __name__=='__main__':unittest.main()
