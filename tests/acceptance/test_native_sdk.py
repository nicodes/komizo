"""The test SDK retains exact public bytes and never forwards the API token."""
import ast
from contextlib import contextmanager
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


class NativePinnedImageTransport(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('native_image_transport',Path(__file__).parents[1]/'support/native_host_vm.py')
        self.vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.vm)
        self.baseline=json.loads((self.vm.FIXTURES/'baseline.json').read_text())

    def response(self,body,*,length=None,status=200,url=None):
        value=io.BytesIO(body)
        value.status=status
        value.headers={'Content-Length':str(len(body)) if length is None else length}
        value.geturl=lambda:url or self.baseline['cloud_image_transport']['url']
        return value

    def record(self,body,**changes):
        return {'url':self.baseline['cloud_image_transport']['url'],'max_bytes':len(body),
                'sha512':hashlib.sha512(body).hexdigest(),**changes}

    def test_mirror_preserves_the_entire_captured_image_and_capsule_identity(self):
        before=json.loads(json.dumps(self.baseline))
        self.assertEqual(hashlib.sha256(json.dumps(before['cloud_image'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                         'a40ca8315a3e6789519c0293b49595393678c9ce76b8524d5f93300a992f80a7')
        record=self.vm.fixture_image_download_record(self.baseline)
        self.assertEqual(self.baseline,before)
        self.assertEqual({k:v for k,v in record.items() if k not in {'url','signature_url'}},
                         {k:v for k,v in before['cloud_image'].items() if k not in {'url','signature_url'}})
        self.assertEqual({k:record[k] for k in ['url','signature_url']},before['cloud_image_transport'])
        options=self.vm.fixture_package_bootstrap(self.baseline)
        capsule=json.loads(options['write_files'][1]['content'])
        self.assertEqual(capsule,{'image':before['cloud_image'],'requested_packages':before['native_packages'],
                                 'closure':before['native_package_closure']})

    def test_transport_requires_exactly_the_two_reviewed_https_mirror_urls(self):
        good=self.baseline['cloud_image_transport']
        bad=[None,[],{}, {'url':good['url']},{**good,'sha512':'0'*128},
             *[{**good,'url':url} for url in ['http://dl-3.alpinelinux.org/alpine/file',
                good['url'].replace('dl-3.','elsewhere.'),good['url']+'?token=private',
                good['url']+'/different',good['url'].replace('https://','https://user:password@')]]]
        for value in bad:
            with self.subTest(transport=value),self.assertRaisesRegex(ValueError,'reviewed official mirror'):
                self.vm.fixture_image_download_record({**self.baseline,'cloud_image_transport':value})

    def test_success_keeps_one_download_original_read_size_timeout_and_hashes(self):
        body=b'complete pinned public image'
        for algorithm in ['sha512','sha256']:
            record={'url':self.record(body)['url'],'max_bytes':len(body),algorithm:hashlib.new(algorithm,body).hexdigest()}
            incoming=self.response(body);reads=[];read=incoming.read
            incoming.read=lambda size:(reads.append(size),read(size))[1]
            with self.subTest(algorithm=algorithm),tempfile.TemporaryDirectory() as directory:
                with patch.object(self.vm.urllib.request,'urlopen',return_value=incoming) as opened,patch.object(sys,'stderr',io.StringIO()) as stderr:
                    self.assertIsNone(self.vm.download(record,Path(directory)/'image'))
                opened.assert_called_once_with(record['url'],timeout=30)
                self.assertEqual(reads,[1<<20,1<<20]);self.assertEqual(stderr.getvalue(),'')
                self.assertEqual((Path(directory)/'image').read_bytes(),body)

    def test_byte_deadline_and_combined_failures_have_distinct_closed_evidence(self):
        body=b'12345'
        for maximum,observed,flags in [(4,100.25,(True,False)),(5,400,(False,True)),(4,400,(True,True))]:
            with self.subTest(flags=flags),tempfile.TemporaryDirectory() as directory:
                target=Path(directory)/'image'
                with patch.object(self.vm.urllib.request,'urlopen',return_value=self.response(body)),patch.object(self.vm.time,'monotonic',side_effect=[100,observed]):
                    with self.assertRaisesRegex(ValueError,'pinned fixture download exceeds its bound') as raised:
                        self.vm.download(self.record(body,max_bytes=maximum),target)
                evidence=json.loads(str(raised.exception).split(': ',1)[1])
                self.assertEqual((evidence['bytes_exceeded'],evidence['deadline_expired']),flags)
                self.assertEqual(evidence['received_bytes'],len(body));self.assertEqual(evidence['max_bytes'],maximum)
                self.assertEqual(evidence['elapsed_ms'],round((observed-100)*1000));self.assertEqual(evidence['deadline_seconds'],300)
                self.assertEqual((evidence['request_transport'],evidence['response_transport']),('dl-3.alpinelinux.org',)*2)
                self.assertTrue(evidence['response_url_matches_requested']);self.assertEqual(evidence['response_status'],200)
                self.assertEqual(evidence['response_content_length_bytes'],len(body));self.assertEqual(target.read_bytes(),b'')

    def test_diagnostic_omits_raw_urls_headers_and_body_and_has_a_fixed_shape(self):
        secret='SYNTHETIC-PRIVATE-MARKER';body=secret.encode()
        incoming=self.response(body,length=secret,status=secret,url='https://example.invalid/?token='+secret)
        record=self.record(body,max_bytes=1,url='https://example.invalid/?token='+secret)
        with tempfile.TemporaryDirectory() as directory,patch.object(self.vm.urllib.request,'urlopen',return_value=incoming),patch.object(self.vm.time,'monotonic',side_effect=[0,1]):
            with self.assertRaises(ValueError) as raised:self.vm.download(record,Path(directory)/'image')
        message=str(raised.exception);self.assertNotIn(secret,message);self.assertLess(len(message),1024)
        evidence=json.loads(message.split(': ',1)[1])
        self.assertEqual(set(evidence),{'kind','version','received_bytes','max_bytes','elapsed_ms','deadline_seconds',
            'bytes_exceeded','deadline_expired','request_transport','response_transport',
            'response_url_matches_requested','response_status','response_content_length_bytes'})
        self.assertIsNone(evidence['response_status']);self.assertIsNone(evidence['response_content_length_bytes'])

    def test_empty_changed_bytes_and_network_errors_still_refuse_without_retry(self):
        for body in [b'',b'changed']:
            with self.subTest(body=body),tempfile.TemporaryDirectory() as directory,patch.object(self.vm.urllib.request,'urlopen',return_value=self.response(body)) as opened:
                with self.assertRaisesRegex(ValueError,'differs from reviewed bytes'):
                    self.vm.download(self.record(b'original'),Path(directory)/'image')
                self.assertEqual(opened.call_count,1)
        original=TimeoutError('synthetic network timeout')
        with tempfile.TemporaryDirectory() as directory,patch.object(self.vm.urllib.request,'urlopen',side_effect=original) as opened:
            with self.assertRaises(TimeoutError) as raised:self.vm.download(self.record(b'original'),Path(directory)/'image')
            self.assertIs(raised.exception,original);self.assertEqual(opened.call_count,1)


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

    def test_ready_notification_paths_must_be_absent_including_dangling_links(self):
        module=self.module()
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);path=directory/'supervise-komizo-proxy.sock'
            with patch.object(module,'Path',return_value=directory),patch.object(module,'service_active',return_value=True) as active:
                module.ready_notifications_absent()
                roles=('komizo-controller','komizo-proxy','komizo-dns','komizo-expiry')
                self.assertEqual([args[0] for args,_ in active.call_args_list],list(roles))
                for role in roles:
                    selected=directory/('supervise-'+role+'.sock')
                    with self.subTest(role=role),socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as listener:
                        listener.bind(str(selected))
                        with self.assertRaisesRegex(ValueError,'retained'):module.ready_notifications_absent()
                    selected.unlink()
                path.symlink_to(directory/'absent-target')
                with self.assertRaisesRegex(ValueError,'retained'):module.ready_notifications_absent()
                path.unlink();path.write_bytes(b'foreign')
                with self.assertRaisesRegex(ValueError,'retained'):module.ready_notifications_absent()
                path.unlink();path.mkdir()
                with self.assertRaisesRegex(ValueError,'retained'):module.ready_notifications_absent()

    def test_unready_services_never_satisfy_notification_cleanup(self):
        module=self.module()
        with patch.object(module,'service_active',return_value=False),patch.object(module.os.path,'lexists') as present:
            with self.assertRaisesRegex(ValueError,'reported ready'):module.ready_notifications_absent()
            present.assert_not_called()

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


class ResourceMemoryEvents(unittest.TestCase):
    def events(self):
        source=Path(__file__).parents[1]/'support/native_host_runtime.py'
        node=next(node for node in ast.parse(source.read_text()).body
            if isinstance(node,ast.FunctionDef) and node.name=='instance_memory_events')
        namespace={'contextmanager':contextmanager}
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),namespace)
        return namespace['instance_memory_events']

    def test_same_instance_counter_fd_retains_delta_after_payload_directory_removal(self):
        if os.geteuid()!=0:self.skipTest('owned parent counter fixture requires sudo Linux CI')
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary)/'instance';parent.mkdir(mode=0o700)
            events=parent/'memory.events';events.write_text('oom_kill 0\n')
            payload=parent/'libpod-fixture';payload.mkdir();(payload/'memory.events').write_text('oom_kill 0\n')
            with self.events()(parent) as stream:
                original=os.fstat(stream.fileno());before=int(stream.read().split()[1])
                (payload/'memory.events').unlink();payload.rmdir()
                events.write_text('oom_kill 1\n');stream.seek(0);after=int(stream.read().split()[1])
                current=os.fstat(stream.fileno())
                self.assertEqual((current.st_dev,current.st_ino),(original.st_dev,original.st_ino))
                self.assertGreater(after,before)

    def test_retired_replaced_linked_or_writable_instance_parent_refuses(self):
        if os.geteuid()!=0:self.skipTest('owned parent counter fixture requires sudo Linux CI')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);parent=root/'instance';parent.mkdir(mode=0o700)
            (parent/'memory.events').write_text('oom_kill 0\n')
            with self.assertRaisesRegex(ValueError,'retired or replaced'),self.events()(parent):
                parent.rename(root/'retired');parent.mkdir(mode=0o700)
                (parent/'memory.events').write_text('oom_kill 1\n')
            link=root/'link';link.symlink_to(parent,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'protected'),self.events()(link):pass
            parent.chmod(0o777)
            with self.assertRaisesRegex(ValueError,'protected'),self.events()(parent):pass

    def test_pressure_requires_unchanged_source_nonzero_exit_and_positive_oom_delta(self):
        if os.geteuid()!=0:self.skipTest('owned parent counter fixture requires sudo Linux CI')
        source_file=Path(__file__).parents[1]/'support/native_host_runtime.py'
        node=next(node for node in ast.parse(source_file.read_text()).body
            if isinstance(node,ast.FunctionDef) and node.name=='resource_stress')
        for changed,delta,status,error,blocked in [(True,1,137,'installed identity',False),
                (False,0,137,'memory ceiling',False),(False,1,0,'memory ceiling',False),
                (False,1,137,'cleanup not ready',True)]:
            with self.subTest(changed=changed,delta=delta,status=status),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);cid='a'*64;owner='b'*32;calls=[];reads=[];writes=[]
                group='/komizo/production/kmz-'+hashlib.sha256(b'livebox\0production').hexdigest()[:20]
                parent=root/group.removeprefix('/');parent.mkdir(mode=0o700,parents=True)
                workload=group+'/service-api-'+owner;leaf=root/workload.removeprefix('/')/('libpod-'+cid);leaf.mkdir(parents=True)
                (leaf/'pids.current').write_text('1\n');(parent/'pids.events').write_text('max 0\n')
                (parent/'memory.events').write_text('oom_kill 0\n')
                record={'id':cid,'name':'fixture','ownership':owner}
                source={'application':'livebox','instance':'production','release_digest':'sha256:'+'c'*64,
                    'resources':{'containers':{'api':record}}}
                labels={'io.komizo.'+key:value for key,value in {'application':'livebox','instance':'production',
                    'service':'api','ownership':owner,'release':source['release_digest']}.items()}
                actual={'Id':cid,'State':{'CgroupPath':str(leaf.relative_to(root))},
                    'HostConfig':{'CgroupParent':workload},'Config':{'Labels':labels}}
                def installed(app):
                    reads.append(app)
                    return {**source,'release_digest':'changed'} if changed and len(reads)>1 else source
                def run(argv,**options):
                    calls.append((argv,options))
                    if argv[5]=='sh':(parent/'pids.events').write_text('max 1\n')
                    else:(parent/'memory.events').write_text('oom_kill '+str(delta)+'\n')
                    stderr=b"private-fixture-sentinel can't fork: Resource temporarily unavailable" if argv[5]=='sh' else b''
                    return SimpleNamespace(returncode=status,stderr=stderr,stdout=b'')
                def recovered(*arguments):
                    if blocked:raise ValueError('cleanup not ready')
                namespace={'hashlib':hashlib,'Path':lambda value:root if str(value)=='/sys/fs/cgroup' else Path(value),
                    'installed':installed,'container':lambda record:actual,'run':run,'instance_memory_events':self.events(),
                    'until':lambda predicate,seconds:self.assertTrue(predicate()),'ROOT':root,
                    'write':lambda path,value:writes.append(json.loads(json.dumps(value))),
                    'submit_failure':lambda result:{'returncode':result.returncode},
                    'pid_stress_recovered':recovered,'time':SimpleNamespace(monotonic=lambda:0)}
                exec(compile(ast.Module(body=[node],type_ignores=[]),str(source_file),'exec'),namespace)
                with self.assertRaisesRegex(ValueError,error):namespace['resource_stress']({})
                self.assertEqual(len(calls),1 if blocked else 2)
                if blocked:
                    self.assertIn('pid_pressure',writes[-1]);self.assertNotIn('before_memory_events',writes[-1])
                    self.assertEqual(writes[-1]['pid_pressure']['stderr_classes'],['fork_refused','resource_unavailable'])
                    self.assertNotIn('private-fixture-sentinel',json.dumps(writes[-1]))
                else:self.assertEqual(calls[1][1],{'ok':False,'timeout':30})

    def recovery(self,root,count=1):
        source_file=Path(__file__).parents[1]/'support/native_host_runtime.py'
        node=next(node for node in ast.parse(source_file.read_text()).body
            if isinstance(node,ast.FunctionDef) and node.name=='pid_stress_recovered')
        leaf=root/'payload';leaf.mkdir();(leaf/'pids.current').write_text(str(count))
        source={'release_digest':'sha256:'+'c'*64};record={'id':'a'*64,'ownership':'b'*32}
        workload='/komizo/production/kmz-fixture/service-api-'+record['ownership'];clock=[0.0];calls=[];observation={}
        value={'id':record['id'],'parent':workload,'application':'livebox','instance':'production','service':'api',
            'release':source['release_digest'],'ownership':record['ownership'],'running':True,'paused':False,
            'pid':123,'cgroup':workload+'/libpod-'+record['id']}
        def run(argv,**options):
            calls.append((argv,options));return SimpleNamespace(returncode=0,stdout=json.dumps(value).encode())
        namespace={'time':SimpleNamespace(monotonic=lambda:clock[0],sleep=lambda delay:clock.__setitem__(0,clock[0]+delay)),
            'json':json,'subprocess':subprocess,'run':run,'installed':lambda app:source}
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(source_file),'exec'),namespace)
        return SimpleNamespace(function=namespace['pid_stress_recovered'],namespace=namespace,clock=clock,calls=calls,
            observation=observation,value=value,leaf=leaf,args=(source,record,leaf,workload,1,10.0,observation))

    def test_dead_zero_pid_or_missing_payload_never_starts_an_inspection_or_memory_pressure(self):
        for missing in (False,True):
            with self.subTest(missing=missing),tempfile.TemporaryDirectory() as temporary:
                context=self.recovery(Path(temporary),0)
                if missing:(context.leaf/'pids.current').unlink()
                with self.assertRaisesRegex(ValueError,'original cleanup deadline'):context.function(*context.args)
                self.assertEqual(context.calls,[]);self.assertEqual(context.clock[0],10)

    def test_live_exact_scope_is_required_and_foreign_payload_or_source_refuses(self):
        for changed in (None,'id','cgroup','source'):
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as temporary:
                context=self.recovery(Path(temporary))
                if changed=='source':context.namespace['installed']=lambda app:{'changed':True}
                elif changed:context.value[changed]='foreign'
                if changed:
                    with self.assertRaisesRegex(ValueError,'ownership changed|installed identity'):context.function(*context.args)
                else:
                    context.function(*context.args);self.assertEqual(context.observation['pid_cleanup']['state'],'ready')
                self.assertEqual(len(context.calls),1)
                argv,options=context.calls[0];self.assertEqual(argv[-1],'a'*64)
                self.assertEqual(options,{'ok':False,'timeout':1});self.assertNotIn('.Env',argv[-2])

    def test_readonly_inspection_uses_remaining_original_deadline_without_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            context=self.recovery(Path(temporary));context.clock[0]=9.75
            def timeout(argv,**options):
                context.calls.append((argv,options));context.clock[0]=10
                raise subprocess.TimeoutExpired(argv,options['timeout'])
            context.namespace['run']=timeout
            with self.assertRaisesRegex(ValueError,'original cleanup deadline'):context.function(*context.args)
            self.assertEqual(len(context.calls),1);self.assertEqual(context.calls[0][1]['timeout'],.25)
            self.assertEqual(context.observation['pid_cleanup']['state'],'inspect_timeout')
            context.calls.clear()
            with patch.object(Path,'read_text',side_effect=AssertionError('expired gate must not read')):
                with self.assertRaisesRegex(ValueError,'original cleanup deadline'):context.function(*context.args)
            self.assertEqual(context.calls,[])

    def test_payload_enodev_can_recover_but_unknown_errno_refuses_immediately(self):
        import errno
        with tempfile.TemporaryDirectory() as temporary:
            context=self.recovery(Path(temporary));original=Path.read_text;reads=[]
            def retiring(path,*args,**options):
                reads.append(path)
                if len(reads)==1:raise OSError(errno.ENODEV,'private-fixture-sentinel')
                return original(path,*args,**options)
            with patch.object(Path,'read_text',new=retiring):context.function(*context.args)
            self.assertEqual(len(context.calls),1);self.assertEqual(context.observation['pid_cleanup']['state'],'ready')
            self.assertLess(context.clock[0],10);self.assertNotIn('private-fixture-sentinel',json.dumps(context.observation))
            context.calls.clear();context.clock[0]=0
            with patch.object(Path,'read_text',side_effect=OSError(errno.EIO,'private-fixture-sentinel')):
                with self.assertRaises(OSError) as caught:context.function(*context.args)
            self.assertEqual(caught.exception.errno,errno.EIO);self.assertEqual(context.calls,[])
            self.assertEqual(context.clock[0],0);self.assertEqual(context.observation['pid_cleanup']['errno'],errno.EIO)
            self.assertNotIn('private-fixture-sentinel',json.dumps(context.observation))


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
