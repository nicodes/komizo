import importlib.util
from pathlib import Path
import tempfile
import unittest
import json
import hashlib
import contextlib
import os
from types import SimpleNamespace
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('maintenance_operator',Path(__file__).with_name('maintenance.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class MaintenanceTests(unittest.TestCase):
    def test_held_kernel_is_transaction_only_and_survives_userspace_apply(self):
        spec=importlib.util.spec_from_file_location('shared_platform_for_hold',Path(__file__).with_name('platform.py'))
        shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared)
        with tempfile.TemporaryDirectory() as root:
            root=Path(root)
            for name in ('etc/apk/keys','lib/apk/db','var/lib/komizo/apps','var/lib/komizo/releases','run/komizo','var/lib/komizo/maintenance/fixture'):
                (root/name).mkdir(parents=True,exist_ok=True)
            for name,body in {'etc/apk/world':'linux-lts\ndocker\n','etc/apk/repositories':'https://example.invalid/v3.24/main\n','lib/apk/db/installed':'fixture database','etc/apk/keys/fixture.pub':'fixture key'}.items():(root/name).write_text(body)
            stage=root/'var/lib/komizo/maintenance/fixture'
            calls=[]
            def run(args,required=True,timeout=90):
                calls.append(args)
                if args[:2]==['busybox','uname']:return 0,'x86_64' if args[-1]=='-m' else '6.18.38-0-lts'
                if args[:2]==['apk','query']:return 0,json.dumps([{'name':'linux-lts','version':'6.18.38-r0'}])
                if 'upgrade' in args:return 0,'(1/1) Upgrading zlib (1.3.2-r0 -> 1.3.2-r1)\n'
                if 'fetch' in args:
                    self.assertNotIn('--recursive',args)
                    self.assertNotIn('--world',args)
                    self.assertEqual(args[args.index('--match')+1],'package')
                    self.assertEqual(args[args.index('--from')+1],'repositories')
                    self.assertEqual(args[args.index('--output')+2:],['zlib-1.3.2-r1'])
                    cache=Path(args[args.index('--output')+1]);(cache/'zlib-1.3.2-r1.apk').write_bytes(b'fixture package')
                if 'add' in args:
                    self.assertIn('linux-lts=6.18.38-r0',(root/'etc/apk/world').read_text())
                if args[:3]==['apk','info','--exists']:return 0,args[-1].split('=')[0]
                if args==['komizo-box','report']:return 0,json.dumps({'inventory':{'status':'current'},'server':{'state':'ready'},'apps':[]})
                return 0,''
            p=shared.Platform(root,run,owner=os.getuid());operator=m.Maintenance(p)
            operator.inventory=lambda :{'boot_id':'original','running_kernel':'6.18.38-0-lts'}
            operator.serving=lambda :{'unchanged':True}
            with patch.object(m.os,'statvfs',return_value=SimpleNamespace(f_bavail=4<<30,f_frsize=1,f_favail=100000)):
                plan=operator.plan(str(stage),True)
                manifest=operator.manifest(stage,plan['manifest_sha256'])
                self.assertTrue(plan['kernel_held']);self.assertFalse(plan['reboot_required'])
                self.assertEqual(manifest['held_kernel_version'],'6.18.38-r0')
                self.assertNotIn('linux-lts=6.18.38-r0',(stage/'candidate-world').read_text())
                operator.apply(str(stage),plan['manifest_sha256'])
            self.assertNotIn('linux-lts=',(root/'etc/apk/world').read_text())
            self.assertTrue(any('add' in args for args in calls))
            fence=root/'var/lib/komizo/upgrades/pending.json';self.assertTrue(fence.exists())
            self.assertEqual(operator.finish(str(stage),plan['manifest_sha256'])['phase'],'accepted')
            self.assertFalse(fence.exists())
    def test_firewall_world_preserves_constraints_and_requires_both_packages(self):
        self.assertEqual(m.held_world('docker\nnftables=1.1.9-r0\n'), 'docker\nnftables=1.1.9-r0\nnftables-openrc\nopenssh\nlinux-lts\n')
    def test_transaction_refuses_removal_downgrade_duplicate_or_unsafe_version(self):
        self.assertEqual(m.changes('( 1/2) Upgrading linux-lts (6.18.55-r0 -> 6.18.56-r0)'),[{'name':'linux-lts','version':'6.18.56-r0','operation':'upgrading'}])
        for text in ('(1/1) Purging nftables (1.1.9-r0)','(1/1) Downgrading docker (2 -> 1)','(1/1) Installing test (../../unsafe)','(1/2) Installing test (1)\n(2/2) Installing test (1)'):
            with self.assertRaises(ValueError):m.changes(text)
    def test_manifest_rejects_path_escape_and_unreviewed_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            class P:
                def read(self,path,private=False):return path.read_bytes()
            operator=m.Maintenance(P());stage=Path(root)
            manifest={'version':1,'kind':'host-maintenance','before':{},'serving':{},'required_packages':list(m.REQUIRED),'files':[{'name':'test','version':'1','operation':'installing','file':'test-1.apk','bytes':1,'sha256':'a'*64}],'candidate_world_sha256':'b'*64,'reboot_required':False,'expires_at_unix':1}
            def write():
                body=json.dumps(manifest).encode();(stage/'manifest.json').write_bytes(body);return hashlib.sha256(body).hexdigest()
            operator.manifest(stage,write())
            manifest['files'][0]['file']='../test-1.apk'
            with self.assertRaises(ValueError):operator.manifest(stage,write())
            manifest['files'][0]['file']='test-1.apk';digest=write();(stage/'manifest.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'changed'):operator.manifest(stage,digest)
    def test_reboot_identity_is_fresh_and_typed(self):
        with tempfile.TemporaryDirectory() as root:
            class P:
                def path(self,path):return Path(root)/path.lstrip('/')
            operator=m.Maintenance(P());file=operator.p.path('/proc/sys/kernel/random/boot_id');file.parent.mkdir(parents=True)
            file.write_text('00000000-0000-0000-0000-000000000000\n');self.assertTrue(operator.boot_id())
            file.write_text('unknown')
            with self.assertRaises(ValueError):operator.boot_id()
    def test_reconciliation_retains_fence_until_real_boot_and_serving_acceptance(self):
        with tempfile.TemporaryDirectory() as root:
            stage=Path(root);expected='a'*64
            class P:
                def path(self,path):return stage/path.lstrip('/')
                def locks(self):return contextlib.nullcontext()
                def read(self,path,private=False):return path.read_bytes()
                def journal(self,path,value):self.record=value
                def sync(self,path):pass
                def run(self,args,timeout=90):
                    if args==['busybox','uname','-r']:return 0,'6.18.56-0-lts'
                    if args==['komizo-box','report']:return 0,json.dumps({'inventory':{'status':'current'},'server':{'state':'ready'},'apps':[]})
                    return 0,''
            p=P();operator=m.Maintenance(p)
            operator.stage=lambda path:stage
            manifest={'reboot_required':True,'before':{'boot_id':'old'},'files':[{'name':'linux-lts','version':'6.18.56-r0'}],'serving':{'intent':'original'}}
            operator.manifest=lambda path,digest:manifest
            operator.verify_packages=lambda manifest:None
            operator.inventory=lambda :{'boot_id':'new'}
            operator.serving=lambda :manifest['serving']
            fence=p.path('/var/lib/komizo/upgrades/pending.json');fence.parent.mkdir(parents=True)
            fence.write_text(json.dumps({'kind':'host-maintenance','stage':str(stage),'manifest_sha256':expected}))
            operator.boot_id=lambda :'old'
            with self.assertRaisesRegex(ValueError,'real reboot'):operator.finish(str(stage),expected)
            self.assertTrue(fence.exists())
            operator.boot_id=lambda :'new';operator.serving=lambda :{'intent':'changed'}
            with self.assertRaisesRegex(ValueError,'stop intent'):operator.finish(str(stage),expected)
            self.assertTrue(fence.exists())
            operator.serving=lambda :manifest['serving']
            result=operator.finish(str(stage),expected)
            self.assertEqual(result['phase'],'accepted');self.assertFalse(fence.exists())
            self.assertEqual(p.record['phase'],'accepted')

if __name__=='__main__':unittest.main()
