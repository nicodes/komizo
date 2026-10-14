import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

def module(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

class ControlPreparation(unittest.TestCase):
    def test_plan_keeps_private_options_and_delegates_exact_four_file_review(self):
        m=module('control_preparer','controls_prepare.py');p=module('control_platform','platform.py');shared=module('control_shared','platform_prepare.py')
        m.HOST=shared.HOST;m.CONTROL_SERVICES=p.CONTROL_SERVICES;m.control_configuration=p.control_configuration
        group={'memory_low_bytes':24,'memory_high_bytes':160,'memory_bytes':176,'swap_bytes':128,'pids':256,'cpu_weight':50,'milli_cpus':0}
        resources=json.dumps({'controls':{'openrc.'+n:group for n in p.CONTROL_SERVICES}}).encode()
        observed={'resources':base64.b64encode(resources).decode(),'configs':{'docker':base64.b64encode(b'DOCKER_OPTS="private option"\n').decode(),'komizo-rootd':None,'komizo-api':None}}
        calls=[];m.run=lambda args,body=None: calls.append((args,body)) or (json.dumps(observed).encode() if body else b'')
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);root.chmod(0o700);m.protected_directory=lambda path:shared.protected_directory(path,root=root,owner=os.getuid())
            def prepare(*args):
                review=json.loads(args[-1].read_text());self.assertEqual([r['path'] for r in review['files']],['/etc/komizo/resources.json','/etc/conf.d/docker','/etc/conf.d/komizo-rootd','/etc/conf.d/komizo-api'])
                self.assertTrue(all(r['mode']==0o600 for r in review['files']))
                self.assertTrue((args[-1].parent/'docker.conf').read_bytes().startswith(b'DOCKER_OPTS="private option"\n'))
                self.assertTrue(all('cat >' not in call[-1] for call,_ in calls));return {'prepared':True}
            m.prepare=prepare
            self.assertTrue(m.prepare_controls('box.example.test','v0.0.106','a'*40,root/'release',root/'plan','plan')['prepared'])
            with self.assertRaises(ValueError):m.prepare_controls('box.example.test','v0.0.106','a'*40,root/'release',root/'plan','plan')

    def test_docker_children_inherit_soft_limit_and_caller_override_survives(self):
        import subprocess
        m=module('control_runtime','platform.py')
        group={'memory_low_bytes':96<<20,'memory_high_bytes':232<<20,'memory_bytes':248<<20,'swap_bytes':512<<20,'pids':1024,'cpu_weight':100,'milli_cpus':0}
        policy={'controls':{'openrc.'+n:group for n in m.CONTROL_SERVICES}}
        for before,expected,debug in [(b'',str(64<<20),'disablethp=1'),(b'GOMEMLIMIT=33554432\n','33554432','disablethp=1'),(b'GODEBUG=gctrace=0,disablethp=0\n',str(64<<20),'gctrace=0,disablethp=0')]:
            config=m.control_configuration(before,policy,'docker')
            with tempfile.TemporaryDirectory() as root:
                p=Path(root)/'docker.conf';p.write_bytes(config)
                env={'PATH':os.environ['PATH']}
                child_env=subprocess.check_output(['sh','-c','. "$1"; sh -c env','sh',str(p)],env=env,text=True)
                actual=next(row.partition('=')[2] for row in child_env.splitlines() if row.startswith('GOMEMLIMIT='))
                self.assertEqual(actual,expected)
                self.assertEqual(next(row.partition("=")[2] for row in child_env.splitlines() if row.startswith("GODEBUG=")),debug)
                self.assertEqual(m.control_configuration(config,policy,'docker'),config)
        for service in ('komizo-api','komizo-rootd'):
            self.assertNotIn(b'GOMEMLIMIT',m.control_configuration(b'',policy,service))

    def test_installer_default_is_persistent_idempotent_and_preserves_override(self):
        import subprocess
        source=Path(__file__).with_name('alpine-init.sh').read_text()
        block=source.split('# BEGIN Docker runtime memory default\n')[1].split('# END Docker runtime memory default')[0]
        for before,expected,debug in [(b'DOCKER_OPTS="private option"\n',str(64<<20),'disablethp=1'),(b'GOMEMLIMIT=33554432\n','33554432','disablethp=1'),(b'GODEBUG=disablethp=0\n',str(64<<20),'disablethp=0')]:
            with tempfile.TemporaryDirectory() as root:
                p=Path(root)/'docker';p.write_bytes(before)
                script=block.replace('/etc/conf.d/docker',str(p))
                for _ in range(2):subprocess.run(['sh','-c',script],check=True)
                self.assertEqual(p.read_text().count('export GOMEMLIMIT'),1)
                self.assertEqual(p.read_text().count('export GODEBUG'),1)
                env={'PATH':os.environ['PATH']}
                child_env=subprocess.check_output(['sh','-c','. "$1"; sh -c env','sh',str(p)],env=env,text=True)
                actual=next(row.partition('=')[2] for row in child_env.splitlines() if row.startswith('GOMEMLIMIT='))
                self.assertEqual(actual,expected)
                self.assertEqual(next(row.partition("=")[2] for row in child_env.splitlines() if row.startswith("GODEBUG=")),debug)
                self.assertTrue(p.read_bytes().startswith(before))

if __name__=='__main__':unittest.main()
