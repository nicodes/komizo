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

if __name__=='__main__':unittest.main()
