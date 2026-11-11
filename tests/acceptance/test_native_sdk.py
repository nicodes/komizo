"""The test SDK retains exact public bytes and never forwards the API token."""
import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import subprocess
import socket
import tarfile
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

    def failure_observer(self):
        if os.name!='posix':self.skipTest('owned process group observer runs on Unix')
        spec=importlib.util.spec_from_file_location('native_failure_observer',Path(__file__).parents[1]/'support/native_host_acceptance.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module,{'Id':'a'*64,'State':{'ExitCode':127,'Error':'native exit','OOMKilled':False}}

    def test_fixture_http_image_keeps_static_applets_and_refuses_missing_required_applets_before_blobs(self):
        spec=importlib.util.spec_from_file_location('native_image_registry',Path(__file__).parents[1]/'support/native_host_registry.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        original=subprocess.run
        def missing_applet(arguments,**options):
            applets={'sh','cat','awk','wget','nc','nslookup','sha256sum','timeout','sleep','touch'} if arguments[0]=='/bin/busybox.static' else {'httpd','telnet'}
            listing='\n'.join(sorted(applets-{missing}))
            return original([sys.executable,'-I','-B','-c','print('+repr(listing)+')'],**options)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for missing in ['cat','nslookup','awk','sha256sum','httpd']:
                with self.subTest(missing=missing),patch.object(module.subprocess,'run',side_effect=missing_applet):
                    with self.assertRaisesRegex(ValueError,'lacks required applets'):
                        module.image(root,'mailroom','a'*40)
                self.assertEqual(list(root.iterdir()),[])
            sources={'bin/busybox':b'exact-static-core','bin/busybox-extras':b'exact-extras','lib/ld-musl-x86_64.so.1':b'exact-musl'}
            with patch.object(module,'image_sources',return_value=sources):artifact=module.image(root,'mailroom','a'*40)
            manifest=json.loads((root/'blobs'/artifact['digest'][7:]).read_bytes())
            config=json.loads((root/'blobs'/manifest['config']['digest'][7:]).read_bytes())
            self.assertEqual(config['config']['Entrypoint'],['/bin/fixture-entrypoint'])
            with tarfile.open(root/'blobs'/manifest['layers'][0]['digest'][7:],'r:gz') as archive:
                for name,value in sources.items():self.assertEqual(archive.extractfile(name).read(),value)
                self.assertEqual(archive.getmember('lib/libc.musl-x86_64.so.1').linkname,'ld-musl-x86_64.so.1')
                dispatcher=archive.extractfile('bin/fixture-entrypoint').read()
                self.assertIn(b'exec /bin/busybox-extras httpd "$@"',dispatcher)
                self.assertIn(b'exec /bin/busybox "$@"',dispatcher)
                self.assertTrue(archive.extractfile('www/cgi-bin/who').read().startswith(b'#!/bin/busybox sh\n'))

    def test_failed_owned_container_streams_are_bounded_and_scrubbed_before_export(self):
        module,selected=self.failure_observer();original=subprocess.Popen;children=[]
        token='runtime-'+'b'*32;password='c'*48;verifier='SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy'
        class PrivateConfig:
            def get(self,*args):raise AssertionError('observer read configuration or environment')
        selected['Config']=PrivateConfig();selected['State']['Error']='native exit '+token
        text=('old line\n'*4000)+token+' '+password+' '+verifier+'\nactual exit 127\n'
        def child(arguments,**options):
            self.assertEqual(arguments,['/usr/bin/podman','--remote=false','logs','--tail','64','a'*64])
            command='import os;os.write(1,'+repr(text.encode())+');os.write(2,b"bounded stderr\\n")'
            value=original([sys.executable,'-I','-B','-c',command],**options);children.append(value);return value
        with patch.object(module.subprocess,'Popen',side_effect=child):result=module.fixture_failure_observation(selected,time.monotonic()+3)
        self.assertEqual((result['exit_code'],result['error'],result['oom_killed']),(127,'native exit [redacted]',False))
        self.assertIn('actual exit 127',result['logs']['stdout']);self.assertIn('[redacted]',result['logs']['stdout'])
        for name in ['stdout','stderr']:
            self.assertLessEqual(len(result['logs'][name].encode()),8192);self.assertLessEqual(len(result['logs'][name].splitlines()),64)
        self.assertTrue(result['logs']['stdout_truncated']);self.assertEqual(result['logs']['command_exit_code'],0)
        for secret in [token,password,verifier]:self.assertNotIn(secret,json.dumps(result))
        self.assertTrue(all(value.poll() is not None for value in children))

    def test_observer_shared_deadline_kills_and_reaps_only_its_owned_child(self):
        module,selected=self.failure_observer();original=subprocess.Popen;children=[]
        def child(arguments,**options):
            value=original([sys.executable,'-I','-B','-c','import time;time.sleep(10)'],**options);children.append(value);return value
        start=time.monotonic()
        with patch.object(module.subprocess,'Popen',side_effect=child):result=module.fixture_failure_observation(selected,start+0.15)
        self.assertTrue(result['logs']['timed_out']);self.assertLess(time.monotonic()-start,1.5)
        self.assertTrue(all(value.poll() is not None for value in children))
        with patch.object(module.subprocess,'Popen',side_effect=AssertionError('expired observer launched a child')):
            self.assertEqual(module.fixture_failure_observation(selected,start)['logs'],{'state':'deadline_expired'})
            self.assertEqual(module.fixture_failure_observation({**selected,'Id':'foreign'},start),{'state':'refused'})
            selected['State']['Error']='-----BEGIN TEST PRIVATE KEY----- fixture-only marker'
            self.assertEqual(module.fixture_failure_observation(selected,start)['error'],'[redacted fixture key]')

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


class ControllerListenerReadiness(unittest.TestCase):
    def module(self):
        spec=importlib.util.spec_from_file_location('native_controller_readiness',Path(__file__).parents[1]/'support/native_host_acceptance.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def listener(self):
        if sys.platform!='linux' or os.geteuid()!=0:
            self.skipTest('real root Unix peer/metadata controls run in the dedicated sudo Linux fixture step')
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        directory=Path(temporary.name);directory.chmod(0o750)
        path=directory/'control.sock'
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(listener.close)
        listener.bind(str(path));listener.listen(8);path.chmod(0o660)
        try:os.chown(directory,0,1);os.chown(path,0,1)
        except OSError as error:
            if error.errno not in {1,22}:raise
            if 'SUDO_UID' in os.environ:self.fail('dedicated sudo Linux fixture requires real protected socket ownership')
            self.skipTest('this local sandbox cannot assign a nonzero managed socket group')
        return directory,path,listener

    def test_real_root_listener_is_bound_to_the_exact_new_worker_and_current_socket(self):
        module=self.module();directory,path,_=self.listener();pid=os.getpid()
        with patch.object(module,'Path',return_value=directory),patch('grp.getgrnam',return_value=SimpleNamespace(gr_gid=1)),patch.object(module,'service_pid',return_value=pid):
            self.assertTrue(module.controller_listener_ready(pid,time.monotonic()+1))
            self.assertFalse(module.controller_listener_ready(pid+1,time.monotonic()+1))
        with patch.object(module,'Path',return_value=directory),patch('grp.getgrnam',return_value=SimpleNamespace(gr_gid=1)),patch.object(module,'service_pid',return_value=pid+1):
            self.assertFalse(module.controller_listener_ready(pid+1,time.monotonic()+1))
        with patch.object(module,'Path',return_value=directory),patch('grp.getgrnam',return_value=SimpleNamespace(gr_gid=1)),patch.object(module,'service_pid',side_effect=[pid,pid+1]):
            self.assertFalse(module.controller_listener_ready(pid,time.monotonic()+1))

    def test_world_access_links_foreign_groups_and_nonlisteners_cannot_satisfy_readiness(self):
        module=self.module();directory,path,_=self.listener();pid=os.getpid()
        with patch.object(module,'Path',return_value=directory),patch('grp.getgrnam',return_value=SimpleNamespace(gr_gid=1)),patch.object(module,'service_pid',return_value=pid):
            for mode in [0o666,0o600,0o777]:
                path.chmod(mode)
                with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'metadata'):
                    module.controller_listener_ready(pid,time.monotonic()+1)
            path.chmod(0o660);os.chown(path,0,0)
            with self.assertRaisesRegex(ValueError,'metadata'):module.controller_listener_ready(pid,time.monotonic()+1)
            os.chown(path,1,1)
            with self.assertRaisesRegex(ValueError,'metadata'):module.controller_listener_ready(pid,time.monotonic()+1)
            os.chown(path,0,1);directory.chmod(0o777)
            with self.assertRaisesRegex(ValueError,'metadata'):module.controller_listener_ready(pid,time.monotonic()+1)
            directory.chmod(0o750)
            path.unlink();path.write_bytes(b'never read this fixture content');path.chmod(0o660);os.chown(path,0,1)
            with self.assertRaisesRegex(ValueError,'metadata'):module.controller_listener_ready(pid,time.monotonic()+1)
            path.unlink();path.symlink_to('private-target-never-followed')
            with self.assertRaisesRegex(ValueError,'metadata'):module.controller_listener_ready(pid,time.monotonic()+1)

    def test_a_stale_socket_without_a_listener_refuses(self):
        module=self.module();directory,path,listener=self.listener();listener.close();pid=os.getpid()
        with patch.object(module,'Path',return_value=directory),patch('grp.getgrnam',return_value=SimpleNamespace(gr_gid=1)),patch.object(module,'service_pid',return_value=pid):
            with self.assertRaises(ConnectionRefusedError):module.controller_listener_ready(pid,time.monotonic()+1)
    def test_expired_budget_never_touches_or_connects_the_socket(self):
        module=self.module();pid=os.getpid()
        with patch.object(module,'Path',side_effect=AssertionError('expired probe touched the socket')):
            self.assertFalse(module.controller_listener_ready(pid,time.monotonic()-1))

    def test_restart_never_renews_the_original_deadline_or_repeats_the_owned_kill(self):
        if sys.platform!='linux':self.skipTest('the production pidfd restart control requires Linux')
        module=self.module()
        with patch.object(module,'service_pid',side_effect=[100,100,200]),patch.object(os,'pidfd_open',return_value=9,create=True),patch.object(os,'close'),patch('signal.pidfd_send_signal',create=True) as kill,patch.object(module.time,'monotonic',side_effect=[10,10,40,40]),patch.object(module.time,'sleep') as sleep,patch.object(module,'controller_listener_ready',return_value=False) as ready:
            with self.assertRaisesRegex(ValueError,'original deadline'):module.restart_controller()
        ready.assert_called_once_with(200,40);kill.assert_called_once();sleep.assert_not_called()


class SubmitFailureDiagnostics(unittest.TestCase):
    def functions(self, run):
        source=Path(__file__).parents[1]/'support/native_host_runtime.py'
        tree=ast.parse(source.read_text())
        selected=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in {'submit_failure','submit'}]
        namespace={'hashlib':hashlib,'json':json,'threading':threading,'run':run,'BINARY':'/usr/local/bin/komizo-box',
            'registry':SimpleNamespace(canonical=lambda value:b'private request body')}
        exec(compile(ast.Module(body=selected,type_ignores=[]),str(source),'exec'),namespace)
        return namespace

    def test_same_failed_result_retains_closed_metadata_without_request_response_or_stderr_data(self):
        secret='fixture-private-sentinel';stdout=(secret+' proof body').encode()
        stderr=('Error: Connection refused (os error 111) '+secret+' PRIVATE KEY '+('x'*10000)).encode()
        stderr+=b' Connection refused (os error 111)'
        calls=[]
        def run(*arguments,**options):
            calls.append((arguments,options));return subprocess.CompletedProcess([],7,stdout,stderr)
        functions=self.functions(run)
        with self.assertRaisesRegex(ValueError,'no JSON result') as failure:
            functions['submit']({'action':'stop','timeout_seconds':30})
        record=json.loads(str(failure.exception).split(': ',1)[1])
        self.assertEqual(set(record),{'returncode','stdout_bytes','stdout_sha256','stderr'})
        self.assertEqual(record['returncode'],7);self.assertEqual(record['stdout_bytes'],len(stdout))
        self.assertEqual(record['stdout_sha256'],'sha256:'+hashlib.sha256(stdout).hexdigest())
        self.assertIn('connection_refused',record['stderr']);self.assertIn('os_error=111',record['stderr'])
        self.assertLessEqual(len(record['stderr']),512);self.assertNotIn(secret,str(failure.exception))
        self.assertNotIn('PRIVATE KEY',str(failure.exception));self.assertNotIn('proof body',str(failure.exception))
        self.assertEqual(len(calls),1);self.assertEqual(calls[0][1]['timeout'],65)
        self.assertEqual(calls[0][1]['input'],b'private request body')

    def test_valid_result_is_unchanged_and_empty_result_is_not_retried(self):
        for body,expected in [(b'{"ok":true}',{'ok':True}),(b'',None)]:
            calls=[]
            def run(*arguments,**options):
                calls.append(arguments);return subprocess.CompletedProcess([],0,body,b'')
            functions=self.functions(run)
            if expected is None:
                with self.assertRaisesRegex(ValueError,'"stdout_bytes": 0'):functions['submit']({'action':'stop','timeout_seconds':1})
            else:self.assertEqual(functions['submit']({'action':'stop','timeout_seconds':1}),expected)
            self.assertEqual(len(calls),1)


class ProxyRefreshObserver(unittest.TestCase):
    def functions(self):
        source=Path(__file__).parents[1]/'support/native_host_runtime.py'
        tree=ast.parse(source.read_text())
        names={'proxy_stack_projection','proxy_cli_role','proxy_cli_snapshot','proxy_admin_profile','proxy_observer_failure','proxy_refresh_observation'}
        namespace={'os':os,'Path':Path,'json':json,'time':time,'service_pid':lambda role:123}
        exec(compile(ast.Module(body=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names],type_ignores=[]),str(source),'exec'),namespace)
        return namespace

    def test_stack_projection_never_exports_arguments_addresses_paths_or_unknown_states(self):
        functions=self.functions();secret='private-fixture-sentinel'
        body=(f'goroutine 9 [IO wait, 3 minutes]:\nnet/http.(*conn).serve(0xdeadbeef, {secret})\n\t/private/{secret}.go:91\n'
            f'goroutine 4 [{secret}]:\ngithub.com/caddyserver/caddy/v2.(*App).Stop({secret}(0xdeadbeef))\n\t/private/source.go:82\n').encode()
        result=functions['proxy_stack_projection'](body);text=json.dumps(result)
        self.assertEqual(result['goroutines'][0],{'id':4,'state':'other','functions':['v2.(*App).Stop']})
        self.assertEqual(result['goroutines'][1]['functions'],['http.(*conn).serve'])
        for private in [secret,'deadbeef','/private/','source.go']:self.assertNotIn(private,text)
        many=b''.join(f'goroutine {i+1} [select]:\nnet/http.worker(0xbeef)\n'.encode() for i in range(100))
        selected=functions['proxy_stack_projection'](many)
        self.assertEqual(len(selected['goroutines']),24);self.assertEqual(selected['omitted'],76)
        self.assertLess(len(json.dumps(selected).encode()),48<<10)
        with self.assertRaises(ValueError):functions['proxy_stack_projection'](b'x'*((512<<10)+1))

    def test_late_configuration_frames_replace_only_nonpriority_slots_within_the_existing_cap(self):
        project=self.functions()['proxy_stack_projection']
        ordinary=b''.join(f'net/http.frame{i}(0xbeef)\n'.encode() for i in range(20))
        body=b'goroutine 1 [semacquire]:\n'+ordinary+b'github.com/caddyserver/caddy/v2.changeConfig(0xbeef)\n'
        result=project(body);functions=result['goroutines'][0]['functions']
        self.assertEqual(len(functions),12);self.assertIn('v2.changeConfig',functions)
        self.assertIn('http.frame0',functions);self.assertNotIn('http.frame11',functions)
        self.assertLess(len(json.dumps(result).encode()),48<<10)

    def test_only_the_two_fixed_caddy_argv_shapes_are_classified(self):
        classify=self.functions()['proxy_cli_role']
        adapt=['/usr/local/bin/caddy','adapt','--adapter','caddyfile','--config','/var/lib/komizo/proxy-staged.caddy']
        reload=['/usr/local/bin/caddy','reload','--adapter','caddyfile','--config','/etc/komizo-proxy/Caddyfile','--address','unix//run/komizo-proxy/admin.sock']
        self.assertEqual(classify(adapt),'adapt');self.assertEqual(classify(reload),'reload')
        for altered in [adapt+['private-value'],['caddy',*adapt[1:]],adapt[:-1]+['/private/config'],reload[:-1]+['unix//private/socket']]:
            self.assertIsNone(classify(altered))

    def admin_fixture(self, peer=(123,1,1), mode=0o200):
        import stat
        import struct
        functions=self.functions();clock=[0.0];calls=[]
        metadata=SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFSOCK|mode,st_uid=1,st_gid=1,st_nlink=1)
        class FixedPath:
            def __init__(self,value):self.value=str(value)
            def __truediv__(self,value):return FixedPath(self.value+'/'+str(value))
            def __str__(self):return self.value
            def lstat(self):
                return SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=1,st_gid=1) if self.value=='/run/komizo-proxy' else metadata
            def open(self,*_):return io.BytesIO(b'123 (caddy) S '+b'1 '*18+b'99 0\n')
        class Connection:
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def settimeout(self,value):self.timeout=value;calls.append(('timeout',value))
            def connect(self,path):calls.append(('connect',path))
            def getsockopt(self,*_):return struct.pack('3i',*peer)
            def sendall(self,body):calls.append(('send',body))
            def recv(self,count):clock[0]+=self.timeout;raise socket.timeout()
        functions.update(Path=FixedPath,time=SimpleNamespace(monotonic=lambda:clock[0]))
        return functions,clock,calls,Connection

    def test_wrong_admin_peer_never_receives_the_readonly_request(self):
        functions,clock,calls,connection=self.admin_fixture((124,1,1))
        with patch('pwd.getpwnam',return_value=SimpleNamespace(pw_uid=1,pw_gid=1)),patch.object(socket,'socket',return_value=connection()):
            with self.assertRaisesRegex(ValueError,'peer'):functions['proxy_admin_profile'](4,threading.Event())
        self.assertFalse(any(kind=='send' for kind,_ in calls))

    def test_caddy_default_owner_write_socket_and_existing_private_modes_remain_exact(self):
        for mode in [0o200,0o600,0o700]:
            functions,clock,calls,connection=self.admin_fixture(mode=mode)
            class Response(connection):
                body=b'HTTP/1.0 200 OK\r\n\r\ngoroutine 1 [running]:\nnet/http.worker(0xbeef)\n'
                def recv(self,count):body=self.body;self.body=b'';return body
            with patch('pwd.getpwnam',return_value=SimpleNamespace(pw_uid=1,pw_gid=1)),patch.object(socket,'socket',return_value=Response()):
                result=functions['proxy_admin_profile'](4,threading.Event())
            self.assertEqual(result['goroutines'][0]['functions'],['http.worker'])
            self.assertEqual(sum(kind=='send' for kind,_ in calls),1)
        for mode in [0,0o400,0o660,0o777]:
            functions,clock,calls,connection=self.admin_fixture(mode=mode)
            with patch('pwd.getpwnam',return_value=SimpleNamespace(pw_uid=1,pw_gid=1)),patch.object(socket,'socket',return_value=connection()):
                with self.assertRaises(ValueError) as caught:functions['proxy_admin_profile'](4,threading.Event())
            self.assertEqual(functions['proxy_observer_failure'](caught.exception)['stage'],'socket_identity')
            self.assertFalse(any(kind in {'connect','send'} for kind,_ in calls))

    def test_failure_projection_reports_closed_stage_errno_and_http_status_without_private_text(self):
        import errno
        functions,clock,calls,connection=self.admin_fixture()
        class Denied(connection):
            def connect(self,path):raise OSError(errno.EACCES,'private-socket-path-and-error')
        with patch('pwd.getpwnam',return_value=SimpleNamespace(pw_uid=1,pw_gid=1)),patch.object(socket,'socket',return_value=Denied()):
            with self.assertRaises(OSError) as caught:functions['proxy_admin_profile'](4,threading.Event())
        self.assertEqual(functions['proxy_observer_failure'](caught.exception),
            {'state':'unavailable','stage':'connect','errno':errno.EACCES,'http_status':None})
        class Refused(connection):
            body=b'HTTP/1.0 403 Forbidden\r\nSecret: private-header\r\n\r\nprivate-response-body'
            def recv(self,count):body=self.body;self.body=b'';return body
        with patch('pwd.getpwnam',return_value=SimpleNamespace(pw_uid=1,pw_gid=1)),patch.object(socket,'socket',return_value=Refused()):
            with self.assertRaises(ValueError) as caught:functions['proxy_admin_profile'](4,threading.Event())
        result=functions['proxy_observer_failure'](caught.exception)
        self.assertEqual(result,{'state':'unavailable','stage':'http','errno':None,'http_status':403})
        self.assertNotIn('private',json.dumps(result))
        error=OSError(100000,'private-error');error.proxy_observer_stage=['private-stage'];error.proxy_observer_http_status=True
        self.assertEqual(functions['proxy_observer_failure'](error),
            {'state':'unavailable','stage':'unavailable','errno':None,'http_status':None})

    def test_one_get_respects_the_original_four_second_deadline_and_expired_probe_touches_nothing(self):
        functions,clock,calls,connection=self.admin_fixture()
        with patch('pwd.getpwnam',return_value=SimpleNamespace(pw_uid=1,pw_gid=1)),patch.object(socket,'socket',return_value=connection()):
            with self.assertRaises(TimeoutError):functions['proxy_admin_profile'](4,threading.Event())
        requests=[value for kind,value in calls if kind=='send']
        self.assertEqual(requests,[b'GET /debug/pprof/goroutine?debug=2 HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'])
        self.assertLessEqual(clock[0],4.001)
        with patch('pwd.getpwnam',side_effect=AssertionError('expired probe read identity')):
            with self.assertRaises(TimeoutError):functions['proxy_admin_profile'](clock[0],threading.Event())

    def test_diagnostic_failures_are_closed_and_share_one_budget(self):
        functions=self.functions();clock=[10.0];calls=[]
        functions['time']=SimpleNamespace(monotonic=lambda:clock[0])
        def children(deadline):calls.append(('children',deadline));clock[0]=11;raise ValueError('private-child-arguments')
        def profile(deadline,stop):self.fail('unavailable child evidence must not send the profile request')
        functions.update(proxy_cli_snapshot=children,proxy_admin_profile=profile)
        result=functions['proxy_refresh_observation']('a'*32,threading.Event())
        self.assertEqual(calls,[('children',11)])
        self.assertEqual(result['controller_children'],{'state':'unavailable','stage':'unavailable','errno':None,'http_status':None})
        self.assertEqual(result['proxy_profile'],{'state':'not_observed','reason':'child_observation_unavailable'})
        self.assertTrue(result['diagnostic_only']);self.assertNotIn('private',json.dumps(result))

    def test_profile_requires_exactly_one_live_owned_reload_child(self):
        functions=self.functions();live={'role':'reload','process_state':'sleeping'}
        cases=[({'state':'observed','caddy':[]},'reload_child_absent'),
            ({'state':'observed','caddy':[{'role':'adapt','process_state':'running'}]},'reload_child_absent'),
            ({'state':'observed','caddy':[live,live]},'reload_child_ambiguous')]
        cases += [({'state':'observed','caddy':[{'role':'reload','process_state':state}]},'reload_child_absent')
            for state in ('zombie','dead','other','stopped')]
        cases.append(({'state':'deadline_expired','caddy':[live]},'child_observation_unavailable'))
        for snapshot,reason in cases:
            with self.subTest(snapshot=snapshot):
                functions['proxy_cli_snapshot']=lambda deadline:snapshot
                functions['proxy_admin_profile']=lambda deadline,stop:self.fail('unproven reload must not send the profile request')
                result=functions['proxy_refresh_observation']('a'*32,threading.Event())
                self.assertEqual(result['proxy_profile'],{'state':'not_observed','reason':reason})

    def test_one_live_reload_profiles_once_with_the_original_deadline(self):
        functions=self.functions();clock=[10.0];calls=[];stop=threading.Event()
        functions['time']=SimpleNamespace(monotonic=lambda:clock[0])
        def children(deadline):
            calls.append(('children',deadline));clock[0]=11
            return {'state':'observed','caddy':[{'role':'adapt','process_state':'running'},
                {'role':'reload','process_state':'sleeping'}]}
        def profile(deadline,actual_stop):
            calls.append(('profile',deadline));self.assertIs(actual_stop,stop)
            raise TimeoutError('private-stack')
        functions.update(proxy_cli_snapshot=children,proxy_admin_profile=profile)
        result=functions['proxy_refresh_observation']('a'*32,stop)
        self.assertEqual(calls,[('children',11),('profile',14)])
        self.assertEqual(result['proxy_profile'],{'state':'deadline_expired','stage':'unavailable','errno':None,'http_status':None})
        self.assertNotIn('private',json.dumps(result))

    def test_http_raw_cap_marks_partial_profile_and_drops_the_incomplete_final_frame(self):
        functions,clock,calls,connection=self.admin_fixture()
        prefix=b'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\ngoroutine 1 [running]:\nnet/http.worker(0xbeef)\n'
        raw=prefix+b'net/http.Incomplete(private-fixture-sentinel'+b'x'*((512<<10)-len(prefix)-42)
        raw=raw[:512<<10].ljust(512<<10,b'x')
        class Response(connection):
            def __init__(self):self.offset=0
            def recv(self,count):
                chunk=raw[self.offset:self.offset+count];self.offset+=len(chunk);return chunk
        with patch('pwd.getpwnam',return_value=SimpleNamespace(pw_uid=1,pw_gid=1)),patch.object(socket,'socket',return_value=Response()):
            result=functions['proxy_admin_profile'](4,threading.Event())
        self.assertTrue(result['raw_limit_reached'])
        self.assertEqual(result['goroutines'][0]['functions'],['http.worker'])
        self.assertNotIn('private',json.dumps(result));self.assertEqual(sum(kind=='send' for kind,_ in calls),1)

    def test_real_unix_dummy_profile_preserves_only_safe_frames(self):
        if sys.platform!='linux' or os.geteuid()!=0:self.skipTest('real nonroot Unix admin peer is qualified in sudo Linux CI')
        functions=self.functions()
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);directory.chmod(0o700)
            try:os.chown(directory,1,1)
            except OSError as error:
                if error.errno not in {1,22}:raise
                if 'SUDO_UID' in os.environ:self.fail('sudo CI requires the real nonroot admin peer fixture')
                self.skipTest('local namespace cannot assign the nonroot admin identity')
            script='''import os,socket,sys
os.setgroups([]);os.setgid(1);os.setuid(1);os.umask(0o077)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(sys.argv[1]+'/admin.sock');os.chmod(sys.argv[1]+'/admin.sock',0o200);s.listen(1);s.settimeout(3)
c,_=s.accept();c.settimeout(2);request=b''
while b'\\r\\n\\r\\n' not in request:request+=c.recv(4096)
assert request==b'GET /debug/pprof/goroutine?debug=2 HTTP/1.0\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n'
c.sendall(b'HTTP/1.0 200 OK\\r\\nContent-Type: text/plain\\r\\n\\r\\ngoroutine 7 [IO wait]:\\nnet/http.(*conn).serve(0xbeef, private-fixture-sentinel)\\n\\t/private/source.go:7\\n');c.close();s.close()
'''
            child=subprocess.Popen([sys.executable,'-I','-B','-c',script,str(directory)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                end=time.monotonic()+2
                while not (directory/'admin.sock').exists():
                    if child.poll() is not None or time.monotonic()>=end:self.fail('owned Unix fixture failed to start')
                    time.sleep(.01)
                functions['Path']=lambda value:directory if str(value)=='/run/komizo-proxy' else Path(value)
                functions['service_pid']=lambda role:child.pid
                with patch('pwd.getpwnam',return_value=SimpleNamespace(pw_uid=1,pw_gid=1)):
                    result=functions['proxy_admin_profile'](time.monotonic()+2,threading.Event())
                self.assertEqual(result['goroutines'],[{'id':7,'state':'io_wait','functions':['http.(*conn).serve']}])
                self.assertNotIn('private',json.dumps(result));self.assertEqual(child.wait(timeout=1),0)
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=1)
                child.stderr.close()


if __name__=='__main__':unittest.main(verbosity=2)
