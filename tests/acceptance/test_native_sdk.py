"""The test SDK retains exact public bytes and never forwards the API token."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import time
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error

spec=importlib.util.spec_from_file_location('native_sdk',Path(__file__).parents[1]/'support/native_host_sdk.py')
sdk=importlib.util.module_from_spec(spec);spec.loader.exec_module(sdk)


class NativeSdk(unittest.TestCase):
    def metadata(self):
        return {'tag_name':'v'+sdk.VERSION,'draft':False,'assets':[{'id':sdk.ASSET_ID,'name':sdk.ASSET,'size':sdk.SIZE,
            'digest':'sha256:'+sdk.SHA256,'url':sdk.API+'assets/'+str(sdk.ASSET_ID)}]}

    def test_release_asset_must_keep_its_exact_id_name_size_and_digest(self):
        sdk.metadata(self.metadata())
        for key,value in [('id',123),('size',1),('digest','sha256:'+'0'*64),('name','different.tar.zst'),('url','https://elsewhere.invalid/asset')]:
            changed=self.metadata();changed['assets'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):sdk.metadata(changed)
        changed=self.metadata();changed['assets'].append(changed['assets'][0])
        with self.assertRaises(ValueError):sdk.metadata(changed)

    def test_official_cdn_receives_no_bearer_token_and_changed_bytes_refuse(self):
        body=b'pinned SDK bytes';calls=[]
        class Opener:
            def open(inner,request,timeout):
                calls.append(request)
                if len(calls)==1:return io.BytesIO(json.dumps(self.metadata()).encode())
                if len(calls)==2:raise urllib.error.HTTPError(request.full_url,302,'redirect',{'Location':'https://release-assets.githubusercontent.com/known?signature=ephemeral'},None)
                return io.BytesIO(body)
        with tempfile.TemporaryDirectory() as temporary,patch.object(sdk,'SIZE',len(body)),patch.object(sdk,'SHA256',hashlib.sha256(body).hexdigest()):
            target=Path(temporary)/'archive';sdk.download(target,'private-read-token',time.monotonic()+5,Opener())
            self.assertEqual(target.read_bytes(),body)
            self.assertEqual(calls[0].get_header('Authorization'),'Bearer private-read-token')
            self.assertEqual(calls[1].get_header('Authorization'),'Bearer private-read-token')
            self.assertIsNone(calls[2].get_header('Authorization'))
            calls.clear()
            with patch.object(sdk,'SHA256','0'*64),self.assertRaisesRegex(ValueError,'bytes changed'):
                sdk.download(Path(temporary)/'altered','private-read-token',time.monotonic()+5,Opener())

    def test_redirects_cannot_select_another_origin_scheme_or_credentials(self):
        for location in ['https://untrusted.invalid/file','http://release-assets.githubusercontent.com/file',
                         'https://user:password@release-assets.githubusercontent.com/file','https://release-assets.githubusercontent.com:8443/file']:
            calls=[]
            class Opener:
                def open(inner,request,timeout):
                    calls.append(request)
                    if len(calls)==1:return io.BytesIO(json.dumps(self.metadata()).encode())
                    raise urllib.error.HTTPError(request.full_url,302,'redirect',{'Location':location},None)
            with self.subTest(location=location),tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(ValueError,'official CDN'):
                    sdk.download(Path(temporary)/'archive','read-token',time.monotonic()+5,Opener())
                self.assertEqual(len(calls),2)
                self.assertFalse((Path(temporary)/'archive').exists())

    def test_deadline_and_size_have_no_unbounded_fallback(self):
        with self.assertRaisesRegex(ValueError,'deadline'):
            sdk.request('https://api.github.com/',{},time.monotonic()-1,object())
        class Opener:
            def open(inner,request,timeout):
                if request.full_url.endswith('v'+sdk.VERSION):return io.BytesIO(json.dumps(self.metadata()).encode())
                return io.BytesIO(b'oversized')
        with tempfile.TemporaryDirectory() as temporary,patch.object(sdk,'SIZE',1):
            with self.assertRaisesRegex(ValueError,'size or deadline'):
                sdk.download(Path(temporary)/'archive','read-token',time.monotonic()+5,Opener())


class NativeGuestReadinessEvidence(unittest.TestCase):
    def guest(self, statement):
        spec=importlib.util.spec_from_file_location('native_guest_readiness',Path(__file__).parents[1]/'support/native_host_vm.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        guest=module.Guest.__new__(module.Guest)
        guest.command=lambda command,**options: subprocess.run([sys.executable,'-I','-B','-c',statement],**options)
        return module,guest

    def test_original_failing_child_retains_only_a_bounded_stderr_tail(self):
        module,guest=self.guest("import sys;sys.stderr.write('x'*5000+'Permission denied (publickey).');sys.exit(255)")
        with patch.object(module.time,'monotonic',side_effect=[0,0,2,2]):
            with self.assertRaisesRegex(ValueError,'Permission denied') as result:
                guest.ready(SimpleNamespace(poll=lambda:None),1)
        self.assertIn('"returncode": 255',str(result.exception))
        self.assertLess(len(str(result.exception)),4500)

    def test_original_successful_child_remains_a_success(self):
        module,guest=self.guest("print('fixture cloud-ready')")
        with patch.object(module.time,'monotonic',return_value=0):
            guest.ready(SimpleNamespace(poll=lambda:None),1)

    def test_first_and_last_real_child_errors_survive_without_loosening_the_deadline(self):
        module,guest=self.guest('')
        messages=iter(['initial handshake failure','final public-key failure'])
        guest.command=lambda command,**options: subprocess.run([sys.executable,'-I','-B','-c',
            'import sys;sys.stderr.write('+repr(next(messages))+');sys.exit(255)'],**options)
        with tempfile.TemporaryDirectory() as directory:
            evidence=Path(directory)/'ssh.json'
            with patch.object(module.time,'monotonic',side_effect=[0,0,0,0,0,2,2]),patch.object(module.time,'sleep'):
                with self.assertRaisesRegex(ValueError,'final public-key failure'):
                    guest.ready(SimpleNamespace(poll=lambda:None),1,evidence=evidence)
            record=json.loads(evidence.read_bytes())
            self.assertIs(record['ready'],False);self.assertEqual(record['attempts'],2)
            self.assertEqual(record['first'],{'returncode':255,'stderr':'initial handshake failure'})
            self.assertEqual(record['last'],{'returncode':255,'stderr':'final public-key failure'})
            self.assertEqual(evidence.stat().st_mode&0o777,0o600)

    def test_dummy_root_enrollment_retains_only_key_authentication(self):
        module,_=self.guest('')
        key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummyDisposablePublicKey'
        user=module.fixture_root_user(key)
        self.assertEqual(user['ssh_authorized_keys'],[key])
        self.assertIs(user['lock_passwd'],False)
        self.assertEqual(user['hashed_passwd'],'*')
        self.assertNotIn('plain_text_passwd',user)

    def test_fixture_disables_only_optional_key_display_without_reclassifying_cloud_warnings(self):
        module,_=self.guest('')
        configuration=module.fixture_cloud_options()
        self.assertIs(configuration['ssh']['emit_keys_to_console'],False)
        self.assertIs(configuration['ssh_pwauth'],False)
        self.assertIs(configuration['disable_root'],False)
        self.assertNotIn('output',configuration)


if __name__=='__main__':unittest.main()
