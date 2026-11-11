"""The test SDK retains exact public bytes and never forwards the API token."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
import subprocess
import socket
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

    def test_profile_probe_exec_owns_its_proc_files_after_real_uid_handoff(self):
        if sys.platform!='linux' or not hasattr(os,'geteuid') or os.geteuid()!=0:
            self.skipTest('real UID handoff runs in the dedicated sudo Linux fixture step')
        status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        if int(status['CapEff'].strip(),16)&((1<<6)|(1<<7))!=((1<<6)|(1<<7)):
            if 'SUDO_UID' in os.environ:self.fail('the dedicated sudo Linux fixture requires real SETUID/SETGID')
            self.skipTest('this local sandbox lacks SETUID/SETGID; sudo Linux CI qualifies the real handoff')
        import pwd
        spec=importlib.util.spec_from_file_location('native_profile_probe',Path(__file__).parents[1]/'support/native_host_acceptance.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        identity=SimpleNamespace(pw_uid=65534,pw_gid=65534)
        observation="import json,os;print(json.dumps({'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'groups':os.getgroups(),'proc_attr_uid':os.stat('/proc/self/attr/current').st_uid}))"
        old=subprocess.run(['/usr/bin/python3','-I','-B','-c',
            'import os;os.setgroups([]);os.setgid(65534);os.setuid(65534);'+observation],
            capture_output=True,timeout=5,check=True)
        self.assertEqual(json.loads(old.stdout)['proc_attr_uid'],0)
        def actual_child(arguments,**options):
            arguments=arguments.copy();arguments[4]=observation
            return subprocess.run(arguments,capture_output=True,timeout=5,check=True,**options)
        with patch.object(pwd,'getpwnam',return_value=identity),patch.object(module,'run',side_effect=actual_child):
            result=module.profile_probe('komizo-proxy','komizo-proxy',[],[])
        self.assertEqual(result,{'uid':65534,'euid':65534,'gid':65534,'egid':65534,'groups':[],'proc_attr_uid':65534})

    def startup_fixture(self):
        if sys.platform!='linux' or not hasattr(os,'geteuid') or os.geteuid()!=0:
            self.skipTest('real private-root metadata controls run in the dedicated sudo Linux fixture step')
        module,_=self.guest('')
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        directory=Path(temporary.name);directory.chmod(0o700)
        boot='11111111-1111-1111-1111-111111111111'
        value={'kind':'komizo.infrastructure-startup-diagnostic','version':1,'diagnostic_only':True,
            'role':'proxy','boot_id':boot,'pid':123,'stage':'proxy_guard','errno':None,'error':'guard'}
        path=directory/'proxy.startup.json';path.write_text(json.dumps(value));path.chmod(0o600)
        return module,directory,boot,path,value

    def test_exact_private_diagnostic_and_embedded_source_preserve_only_closed_metadata(self):
        module,directory,boot,path,value=self.startup_fixture()
        result=module.startup_diagnostics(directory,boot)
        self.assertEqual(result['proxy'],value)
        self.assertEqual(result['controller'],{'state':'absent'})
        namespace={}
        exec(module.inspect.getsource(module.startup_diagnostics),namespace)
        self.assertEqual(namespace['startup_diagnostics'](directory,boot),result)
        for stage in ['notification_environment','notification_address','notification_socket',
                'notification_parent','notification_identity']:
            with self.subTest(stage=stage):
                current={**value,'stage':stage};path.write_text(json.dumps(current))
                self.assertEqual(module.startup_diagnostics(directory,boot)['proxy'],current)
        pending={**value,'stage':'exec','error':'pending'}
        path.write_text(json.dumps(pending))
        self.assertEqual(module.startup_diagnostics(directory,boot)['proxy'],pending)
        self.assertNotIn('accepted',pending)

    def test_diagnostic_tampering_public_permissions_links_and_extra_fields_never_export_data(self):
        module,directory,boot,path,value=self.startup_fixture()
        for key,item in [('role','controller'),('boot_id','22222222-2222-2222-2222-222222222222'),
                ('version',True),('pid',True),('stage','not-allowed'),('diagnostic_only',False),
                ('errno','fixture-private-marker'),('error','fixture-private-marker'),('error','pending'),
                ('environment','fixture-private-marker')]:
            with self.subTest(key=key):
                path.write_text(json.dumps({**value,key:item}));path.chmod(0o600)
                result=module.startup_diagnostics(directory,boot)
                self.assertEqual(result['proxy'],{'state':'refused'})
                self.assertNotIn('fixture-private-marker',json.dumps(result))
        path.write_text(json.dumps(value));path.chmod(0o644)
        self.assertEqual(module.startup_diagnostics(directory,boot)['proxy'],{'state':'refused'})
        path.chmod(0o600);path.write_bytes(b'x'*4097)
        self.assertEqual(module.startup_diagnostics(directory,boot)['proxy'],{'state':'refused'})
        path.unlink();os.mkfifo(path,0o600)
        self.assertEqual(module.startup_diagnostics(directory,boot)['proxy'],{'state':'refused'})
        path.unlink();other=directory/'other';other.write_text(json.dumps(value));other.chmod(0o600)
        path.symlink_to(other)
        self.assertEqual(module.startup_diagnostics(directory,boot)['proxy'],{'state':'refused'})
        path.unlink();os.link(other,path)
        self.assertEqual(module.startup_diagnostics(directory,boot)['proxy'],{'state':'refused'})
        directory.chmod(0o755)
        self.assertEqual(module.startup_diagnostics(directory,boot)['proxy'],{'state':'unavailable'})

    def test_fixed_notification_snapshot_reports_real_modes_without_reading_or_following_objects(self):
        if sys.platform!='linux':self.skipTest('Unix socket metadata fixture runs on Linux')
        module,_=self.guest('')
        first='/run/openrc';second=first+'/supervise-komizo-proxy.sock'
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)/'openrc';directory.mkdir(mode=0o755)
            path=directory/'notify.sock'
            with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as listener:
                listener.bind(str(path));path.chmod(0o755)
                original=os.lstat;calls=[]
                def fixed_lstat(value):
                    calls.append(value)
                    return original({first:directory,second:path}[value])
                with patch.object(os,'lstat',side_effect=fixed_lstat):
                    result=module.notification_metadata()
                    namespace={};exec(module.inspect.getsource(module.notification_metadata),namespace)
                    self.assertEqual(namespace['notification_metadata'](),result)
                self.assertEqual(set(calls),{first,second})
                self.assertEqual(result[first],{'uid':os.getuid(),'gid':os.getgid(),'mode':0o755,'type':'directory'})
                self.assertEqual(result[second],{'uid':os.getuid(),'gid':os.getgid(),'mode':0o755,'type':'socket'})
            path.unlink();path.symlink_to('private-target-not-read')
            with patch.object(os,'lstat',side_effect=fixed_lstat):
                self.assertEqual(module.notification_metadata()[second],{'state':'refused'})
            path.unlink()
            with patch.object(os,'lstat',side_effect=fixed_lstat):
                self.assertEqual(module.notification_metadata()[second],{'state':'absent'})
            directory.rmdir();directory.symlink_to('private-target-not-followed')
            calls.clear()
            with patch.object(os,'lstat',side_effect=fixed_lstat):
                self.assertEqual(module.notification_metadata(),{first:{'state':'refused'},second:{'state':'refused'}})
            self.assertEqual(calls,[first])


if __name__=='__main__':unittest.main()
