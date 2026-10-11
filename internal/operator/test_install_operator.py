import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

spec=importlib.util.spec_from_file_location('installation',Path(__file__).parent/'assets/install_operator.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class InstallationTests(unittest.TestCase):
    def fixture(self, directory, old=False):
        root=Path(directory)
        (root/'etc').mkdir()
        (root/'etc/fleet-operator.json').write_text('{"version":3,"repositories":{},"hosts":[]}')
        (root/'etc/fleet-operator-broker').write_text('FLEET_EDITOR_GID=123\n')
        for path in ('etc/fleet-operator.json','etc/fleet-operator-broker'):
            (root/path).chmod(0o600)
        bundle={name: ('new synthetic '+name).encode() for name in module.PATHS}
        calls=[]
        installation=module.Installation(bundle,root,os.getuid(),lambda *args:calls.append(args))
        if old:
            for name,path in installation.files.items():
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text('previous synthetic '+name)
                path.chmod(0o644)
        grants=root/'var/lib/fleet-operator/grants'
        grants.mkdir(parents=True)
        (grants/'claimed.json').write_text('synthetic claimed grant')
        return installation,calls,grants/'claimed.json'

    def test_cold_install_upgrade_and_recovery_preserve_policy_and_claimed_grants(self):
        for old in (False,True):
            with self.subTest(old=old),tempfile.TemporaryDirectory() as directory:
                installation,calls,grant=self.fixture(directory,old)
                before=installation.plan()
                after=installation.apply(before['plan_sha256'])
                self.assertEqual(after['before'],after['desired'])
                self.assertEqual(grant.read_text(),'synthetic claimed grant')
                self.assertEqual(before['policy_sha256'],after['policy_sha256'])
                recovered=installation.recover()
                self.assertEqual(recovered['before'],before['before'])
                self.assertEqual(grant.read_text(),'synthetic claimed grant')

    def test_changed_plan_refuses_before_stopping_any_service(self):
        with tempfile.TemporaryDirectory() as directory:
            installation,calls,_=self.fixture(directory,True)
            plan=installation.plan()
            (installation.root/'etc/fleet-operator.json').write_text('{"version":3,"changed":true}')
            with self.assertRaises(ValueError):installation.apply(plan['plan_sha256'])
            self.assertEqual(calls,[])
            self.assertFalse((installation.state/'installation.json').exists())

    def test_failed_start_restores_previous_code_and_records_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            installation,calls,_=self.fixture(directory,True)
            before=installation.plan()
            failed=False
            def control(*args):
                nonlocal failed
                calls.append(args)
                if args==('start','fleet-operator.service') and not failed:
                    failed=True
                    raise ValueError('synthetic start refusal')
            installation.control=control
            with self.assertRaises(ValueError):installation.apply(before['plan_sha256'])
            self.assertEqual(installation.plan()['before'],before['before'])
            self.assertEqual(json.loads((installation.state/'installation.json').read_text())['status'],'recovered')

    def test_process_death_after_swap_keeps_recoverable_intent_without_replaying_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            installation,calls,grant=self.fixture(directory,True)
            before=installation.plan()
            script='''import importlib.util,os,pathlib,sys,time
s=importlib.util.spec_from_file_location('installation',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
root=pathlib.Path(sys.argv[2])
def control(*args):
 if args==('start','fleet-operator.socket'):
  (root/'boundary').write_text('swapped')
  while True:time.sleep(1)
i=m.Installation({name:('new synthetic '+name).encode() for name in m.PATHS},root,os.getuid(),control)
i.apply(i.plan()['plan_sha256'])
'''
            child=subprocess.Popen([sys.executable,'-I','-c',script,str(Path(module.__file__)),directory],start_new_session=True)
            try:
                deadline=time.monotonic()+5
                while not (installation.root/'boundary').exists():
                    if child.poll() is not None or time.monotonic()>deadline:self.fail('installer boundary not reached')
                    time.sleep(.01)
                os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
                self.assertEqual(json.loads((installation.state/'installation.json').read_text())['status'],'prepared')
                self.assertEqual(installation.recover()['before'],before['before'])
                self.assertEqual(grant.read_text(),'synthetic claimed grant')
            finally:
                if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
                child.wait(timeout=5)

    def test_recovery_refuses_changed_authority_and_linked_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            installation,calls,_=self.fixture(directory,True)
            installation.apply(installation.plan()['plan_sha256'])
            calls.clear()
            (installation.root/'etc/fleet-operator.json').write_text('{"changed":true}')
            with self.assertRaises(ValueError):installation.recover()
            self.assertEqual(calls,[])
        with tempfile.TemporaryDirectory() as directory:
            installation,calls,_=self.fixture(directory)
            (installation.root/'usr').symlink_to(installation.root/'etc',target_is_directory=True)
            with self.assertRaises(ValueError):installation.plan()
            self.assertEqual(calls,[])
