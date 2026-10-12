import hashlib
import importlib.util
import json
import os
import signal
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('platform_operator', Path(__file__).with_name('platform.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Fixture:
    def __init__(self, root):
        self.root = Path(root)
        self.stage = self.root/'var/lib/komizo/upgrades/fixture'
        self.stage.mkdir(parents=True, mode=0o700)
        for name in ('run/komizo', 'var/lib/komizo/apps', 'etc/komizo', 'usr/local/bin'):
            (self.root/name).mkdir(parents=True, exist_ok=True)
        (self.root/'etc/komizo/agent.json').write_bytes(b'owner-model-roster-and-private-fixture')
        self.active = {'komizo-rootd', 'komizo-api'}
        self.calls = []
        files = []
        self.before = {}
        for path, name, mode in [('/usr/local/bin/komizo-box', 'box', 0o755), ('/var/lib/komizo/version', 'version', 0o644)]:
            old, new = b'old-'+name.encode(), b'new-'+name.encode()
            destination = self.root/path.lstrip('/')
            destination.write_bytes(old)
            os.chmod(destination, mode)
            self.before[path] = old
            (self.stage/name).write_bytes(new)
            files.append({'path': path, 'staged': name, 'before': hashlib.sha256(old).hexdigest(),
                          'after': hashlib.sha256(new).hexdigest(), 'mode': mode})
        receipt = {'version': 1, 'source': 'a'*40, 'authenticated': True, 'kind': 'self-upgrade', 'files': files, 'image': None}
        body = json.dumps(receipt).encode()
        (self.stage/'verified-release.json').write_bytes(body)
        manifest = {'version': 1, 'kind': 'self-upgrade', 'source': 'a'*40, 'release': 'v0.0.77', 'files': files,
                    'receipt_sha256': hashlib.sha256(body).hexdigest(), 'image': None, 'probes': []}
        body = json.dumps(manifest).encode()
        (self.stage/'manifest.json').write_bytes(body)
        self.expected = hashlib.sha256(body).hexdigest()
        for path in self.stage.iterdir():
            os.chmod(path, 0o600)
        self.p = module.Platform(self.root, self.run, os.getuid())

    def run(self, args, required=True):
        self.calls.append(args)
        if args[0] == 'rc-service':
            _, service, action = args
            if action == 'status':
                return (0 if service in self.active else 1), ''
            if action == 'stop':
                self.active.discard(service)
            elif action == 'start':
                self.active.add(service)
        if args == ['komizo-box', 'version']:
            return 0, '0.0.77\n'
        return 0, ''


class PlatformTests(unittest.TestCase):
    def task_fixture(self, root, registered=True):
        fixture = Fixture(root)
        program = fixture.root/'var/lib/komizo/tasks/example.sh'
        program.parent.mkdir(mode=0o700)
        program.write_bytes(b'#!/bin/sh\ncat\n')
        program.chmod(0o700)
        if registered:
            (fixture.root/'var/lib/komizo/apps/example.env').write_bytes(b'APP_NAME=example\n')
        wrapper = fixture.root/'usr/local/bin/task-example'
        wrapper.write_bytes(b'previous reviewed task wrapper')
        wrapper.chmod(0o755)
        candidate = fixture.stage/'task-example'
        candidate.write_bytes(b'candidate fixed executor wrapper')
        candidate.chmod(0o600)
        receipt = json.loads((fixture.stage/'verified-release.json').read_bytes())
        row = {'path': '/usr/local/bin/task-example', 'staged': 'task-example',
               'before': fixture.p.digest(wrapper), 'after': fixture.p.digest(candidate), 'mode': 0o755}
        receipt['files'].append(row)
        body = json.dumps(receipt).encode()
        (fixture.stage/'verified-release.json').write_bytes(body)
        manifest = json.loads((fixture.stage/'manifest.json').read_bytes())
        manifest['files'].append(row)
        manifest['receipt_sha256'] = hashlib.sha256(body).hexdigest()
        body = json.dumps(manifest).encode()
        (fixture.stage/'manifest.json').write_bytes(body)
        fixture.expected = hashlib.sha256(body).hexdigest()
        return fixture, program, wrapper

    def test_interrupted_task_wrapper_upgrade_restores_private_program_and_previous_wrapper(self):
        with tempfile.TemporaryDirectory() as root:
            fixture, program, wrapper = self.task_fixture(root)
            original = program.read_bytes()
            def interrupt(phase):
                if phase == 'replaced-2':
                    raise SystemExit('fixture disconnect after task wrapper replacement')
            fixture.p.checkpoint = interrupt
            with self.assertRaises(SystemExit):
                fixture.p.apply(fixture.stage, fixture.expected)
            self.assertEqual(wrapper.read_bytes(), b'candidate fixed executor wrapper')
            result = fixture.p.apply(fixture.stage, fixture.expected, recover=True)
            self.assertEqual(result['phase'], 'recovered')
            self.assertEqual(wrapper.read_bytes(), b'previous reviewed task wrapper')
            self.assertEqual(program.read_bytes(), original)
            self.assertEqual(program.stat().st_mode & 0o777, 0o700)

    def test_task_wrapper_for_unregistered_app_refuses_before_effects(self):
        with tempfile.TemporaryDirectory() as root:
            fixture, program, wrapper = self.task_fixture(root, registered=False)
            with self.assertRaises(ValueError):
                fixture.p.apply(fixture.stage, fixture.expected)
            self.assertEqual(wrapper.read_bytes(), b'previous reviewed task wrapper')
            self.assertEqual(fixture.calls, [])
            self.assertFalse((fixture.stage.parent/'pending.json').exists())

    def test_websocket_probe_requires_transport_challenge_and_source(self):
        class Connection:
            closed=False
            status=101
            source='a'*40
            valid=True
            def __init__(self,*args,**kwargs):pass
            def request(self,method,path,headers):self.headers=headers
            def getresponse(self):return self
            def getheader(self,name,default=None):
                if name=='X-Komizo-Revision':return self.source
                if name=='Upgrade':return 'websocket'
                if name=='Sec-WebSocket-Accept':
                    body=(self.headers['Sec-WebSocket-Key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()
                    return module.base64.b64encode(module.hashlib.sha1(body).digest()).decode() if self.valid else 'foreign'
                return default
            def close(self):Connection.closed=True
        with patch.object(module.http.client,'HTTPSConnection',Connection):
            probe={'url':'wss://example.test/','revision':'a'*40}
            self.assertTrue(module.Platform.probe_route(probe,1))
            self.assertTrue(Connection.closed)
            Connection.valid=False
            self.assertFalse(module.Platform.probe_route(probe,1))
            Connection.valid=True;Connection.source='b'*40
            self.assertFalse(module.Platform.probe_route(probe,1))

    def test_explicit_redirect_never_follows_an_unreviewed_location(self):
        probe={'url':'https://alias.example.test/','revision':'a'*40,'status':301,'location':'https://app.example.test/'}
        for status,location,source,accepted in ((301,probe['location'],'a'*40,True),
                (302,probe['location'],'a'*40,False),(301,'https://foreign.example.test/','a'*40,False),
                (301,probe['location'],'b'*40,False)):
            with patch.object(module.http.client,'HTTPSConnection') as connect:
                response=connect.return_value.getresponse.return_value;response.status=status
                response.getheader.side_effect=lambda name,default=None:{'Location':location,'X-Komizo-Revision':source}.get(name,default)
                self.assertEqual(module.Platform.probe_route(probe,1),accepted)
                connect.assert_called_once_with('alias.example.test',timeout=1)
                connect.return_value.request.assert_called_once_with('GET','/',headers={'Cache-Control':'no-cache'})
                connect.return_value.close.assert_called_once()

    def test_proxy_grant_rejects_uninstalled_redirect_targets(self):
        for location,accepted in (('https://app.example.test/',True),('https://foreign.example.test/',False),
                                  ('http://app.example.test/',False),('https://app.example.test/?token=synthetic',False)):
            with tempfile.TemporaryDirectory() as root:
                f=Fixture(root)
                value=json.loads((f.stage/'manifest.json').read_text())
                value.update(kind='proxy-upgrade', files=[{**value['files'][0],'path':'/srv/_proxy/compose.yml'}],
                    image={'reference':'ghcr.io/nicodes/platform-proxy@sha256:'+'b'*64,'id':'sha256:'+'b'*64,'previous_id':'sha256:'+'c'*64},
                    probes=[{'url':'https://app.example.test/','revision':'a'*40},
                            {'url':'https://alias.example.test/','revision':'a'*40,'status':301,'location':location}])
                receipt={'version':1,'kind':value['kind'],'source':value['source'],'authenticated':True,'files':value['files'],'image':value['image']}
                raw=json.dumps(receipt).encode();(f.stage/'verified-release.json').write_bytes(raw)
                value['receipt_sha256']=hashlib.sha256(raw).hexdigest()
                raw=json.dumps(value).encode();(f.stage/'manifest.json').write_bytes(raw)
                expected=hashlib.sha256(raw).hexdigest()
                if accepted:self.assertEqual(f.p.manifest(f.stage,expected)['probes'],value['probes'])
                else:
                    with self.assertRaises(ValueError):f.p.manifest(f.stage,expected)
                self.assertEqual(f.calls,[])

    def test_proxy_acceptance_waits_for_listener_but_preserves_exact_identity(self):
        class Response:
            status=200
            headers={'X-Komizo-Revision':'a'*40}
            def getheader(self,name,default=None):return self.headers.get(name,default)
            def read(self,maximum):return b'ready'
        with tempfile.TemporaryDirectory() as root:
            f=Fixture(root)
            f.p.run=lambda args,required=True:(0,'sha256:'+'b'*64)
            value={'image':{'id':'sha256:'+'b'*64},'probes':[{'url':'https://example.test/readyz','revision':'a'*40}]}
            with patch.object(module.http.client,'HTTPSConnection') as connect:
                request=connect.return_value.getresponse
                request.side_effect=[OSError('starting'),Response()]
                f.p.verify_proxy(value,1)
                self.assertEqual(request.call_count,2)
            Response.headers={'X-Komizo-Revision':'c'*40}
            with patch.object(module.http.client,'HTTPSConnection') as connect:
                connect.return_value.getresponse.return_value=Response()
                with self.assertRaisesRegex(ValueError,'deadline'):
                    f.p.verify_proxy(value,.02)
            with patch.object(module.http.client,'HTTPSConnection') as connect:
                connect.return_value.getresponse.side_effect=OSError('unavailable')
                with self.assertRaisesRegex(ValueError,'deadline'):
                    f.p.verify_proxy(value,.02)

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires a real Unix process')
    def test_sigkill_at_durable_boundaries_recovers_previous_files(self):
        for boundary in ('prepared', 'replaced-0', 'replaced-1'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as root:
                f = Fixture(root)
                pid = os.fork()
                if pid == 0:
                    def interrupt(phase):
                        if phase == boundary:
                            os.kill(os.getpid(), signal.SIGSTOP)
                    f.p.checkpoint = interrupt
                    try:
                        f.p.apply(f.stage, f.expected)
                    finally:
                        os._exit(1)
                try:
                    child, status = os.waitpid(pid, os.WUNTRACED)
                    self.assertEqual(child, pid)
                    self.assertTrue(os.WIFSTOPPED(status), status)
                finally:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                self.assertTrue((f.stage.parent/'pending.json').exists())
                recovered = f.p.apply(f.stage, f.expected, recover=True)
                self.assertEqual(recovered['phase'], 'recovered')
                for path, body in f.before.items():
                    self.assertEqual(f.p.path(path).read_bytes(), body)
                self.assertFalse((f.stage.parent/'pending.json').exists())

    def test_upgrade_preserves_service_state_agent_and_exact_files(self):
        with tempfile.TemporaryDirectory() as root:
            f = Fixture(root)
            config = (f.root/'etc/komizo/agent.json').read_bytes()
            result = f.p.apply(f.stage, f.expected)
            self.assertEqual(result['phase'], 'complete')
            self.assertEqual(f.active, {'komizo-rootd', 'komizo-api'})
            self.assertEqual((f.root/'etc/komizo/agent.json').read_bytes(), config)
            self.assertFalse((f.stage.parent/'pending.json').exists())
            self.assertFalse(any(a[0] == 'docker' for a in f.calls))
            self.assertFalse(result['application_restart'])

    def test_disconnect_at_every_replacement_recovers_exact_previous(self):
        for phase in ('prepared', 'replaced-0', 'replaced-1'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as root:
                f = Fixture(root)
                def disconnect(at):
                    if at == phase:
                        raise SystemExit('owned fixture disconnect')
                f.p.checkpoint = disconnect
                with self.assertRaises(SystemExit):
                    f.p.apply(f.stage, f.expected)
                self.assertTrue((f.stage.parent/'pending.json').exists())
                result = f.p.apply(f.stage, f.expected, recover=True)
                self.assertEqual(result['phase'], 'recovered')
                for path, body in f.before.items():
                    self.assertEqual(f.p.path(path).read_bytes(), body)
                self.assertEqual(f.active, {'komizo-rootd', 'komizo-api'})

    def test_failure_rolls_back_and_foreign_write_keeps_recovery_fence(self):
        with tempfile.TemporaryDirectory() as root:
            f = Fixture(root)
            def failure(at):
                if at == 'replaced-0':
                    raise ValueError('fixture readiness failure')
            f.p.checkpoint = failure
            with self.assertRaises(ValueError):
                f.p.apply(f.stage, f.expected)
            self.assertEqual(f.p.path('/usr/local/bin/komizo-box').read_bytes(), f.before['/usr/local/bin/komizo-box'])
            self.assertEqual(f.active, {'komizo-rootd', 'komizo-api'})
        with tempfile.TemporaryDirectory() as root:
            f = Fixture(root)
            def disconnect(at):
                if at == 'replaced-0':
                    raise SystemExit()
            f.p.checkpoint = disconnect
            with self.assertRaises(SystemExit):
                f.p.apply(f.stage, f.expected)
            f.p.path('/usr/local/bin/komizo-box').write_bytes(b'newer-owner-write')
            with self.assertRaisesRegex(ValueError, 'changed installed'):
                f.p.apply(f.stage, f.expected, recover=True)
            self.assertTrue((f.stage.parent/'pending.json').exists())
            self.assertEqual(f.p.path('/usr/local/bin/komizo-box').read_bytes(), b'newer-owner-write')

    def test_disconnect_after_acceptance_finishes_without_rolling_back(self):
        with tempfile.TemporaryDirectory() as root:
            f = Fixture(root)
            def disconnect(at):
                if at == 'complete':
                    raise SystemExit()
            f.p.checkpoint = disconnect
            with self.assertRaises(SystemExit):
                f.p.apply(f.stage, f.expected)
            result = f.p.apply(f.stage, f.expected, recover=True)
            self.assertEqual(result['phase'], 'complete')
            self.assertEqual(f.p.path('/usr/local/bin/komizo-box').read_bytes(), b'new-box')
            self.assertFalse((f.stage.parent/'pending.json').exists())

    def test_grant_drift_and_unknown_deployment_phase_refuse_before_effects(self):
        for condition in ('manifest', 'staged', 'installed', 'fence', 'other-platform'):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as root:
                f = Fixture(root)
                if condition == 'manifest':
                    (f.stage/'manifest.json').write_bytes(b'{}')
                elif condition == 'staged':
                    (f.stage/'box').write_bytes(b'foreign')
                elif condition == 'installed':
                    f.p.path('/usr/local/bin/komizo-box').write_bytes(b'foreign')
                elif condition == 'fence':
                    path = f.p.path('/var/lib/komizo/releases/example/operation.json')
                    path.parent.mkdir(parents=True)
                    path.write_text('{"version":2,"phase":"ready"}')
                    path.chmod(0o600)
                else:
                    path = f.stage.parent/'pending.json'
                    path.write_text('{"stage":"other","manifest":"other"}')
                    path.chmod(0o600)
                with self.assertRaises(ValueError):
                    f.p.apply(f.stage, f.expected)
                self.assertFalse(any(a[-1] in ('start', 'stop') for a in f.calls))



class ProxyPlatformTests(unittest.TestCase):
    def test_config_preflight_uses_only_staged_readonly_caddy_mount(self):
        with tempfile.TemporaryDirectory() as root:
            f = Fixture(root)
            proxy = f.root/'srv/_proxy'
            proxy.mkdir(parents=True)
            (proxy/'compose.yml').write_text('{}')
            (proxy/'Caddyfile').write_text('existing synthetic routes')
            files=[]
            for destination,name,new in [('/srv/_proxy/compose.yml','proxy-compose',b'candidate compose'),('/srv/_proxy/Caddyfile','proxy-caddy',b'candidate timeouts')]:
                (f.stage/name).write_bytes(new)
                os.chmod(f.stage/name,0o600)
                files.append({'path':destination,'staged':name,'before':f.p.digest(f.p.path(destination)),
                              'after':hashlib.sha256(new).hexdigest(),'mode':0o644})
            reference='ghcr.io/nicodes/platform-proxy@sha256:'+'b'*64
            image={'reference':reference,'id':'sha256:'+'c'*64,'previous_id':'sha256:'+'d'*64}
            receipt={'version':1,'source':'a'*40,'authenticated':True,'kind':'proxy-upgrade','files':files,'image':image}
            body=json.dumps(receipt).encode();(f.stage/'verified-release.json').write_bytes(body)
            value={'version':1,'kind':'proxy-upgrade','source':'a'*40,'release':'v0.20.0','files':files,
                   'receipt_sha256':hashlib.sha256(body).hexdigest(),'image':image,
                   'probes':[{'url':'https://example.test/health','revision':'a'*40}]}
            body=json.dumps(value).encode();(f.stage/'manifest.json').write_bytes(body)
            expected=hashlib.sha256(body).hexdigest()
            def fake(args,required=True):
                f.calls.append(args)
                if args[:3]==['docker','image','inspect']:return 0,image['id']
                if args[:2]==['docker','inspect']:return 0,image['previous_id']
                if args[-3:]==['config','--format','json']:
                    selected=args[args.index('--file')+1]
                    return 0,json.dumps({'services':{'komizo-proxy':{'image':'old' if selected==str(proxy/'compose.yml') else reference,
                        'volumes':[{'type':'bind','source':'/srv/_proxy/Caddyfile','target':'/etc/caddy/Caddyfile','read_only':True}]}}})
                return 0,''
            f.p.run=fake
            accepted=f.p.manifest(f.stage,expected)
            f.p.proxy_preflight(f.stage,accepted)
            definition=json.loads((f.stage/'proxy-preflight.json').read_text())
            volume=definition['services']['komizo-proxy']['volumes'][0]
            self.assertEqual(volume['source'],str(f.stage/'proxy-caddy'))
            self.assertTrue(volume['read_only'])
            self.assertEqual((proxy/'Caddyfile').read_text(),'existing synthetic routes')
            self.assertIn(str(f.stage/'proxy-preflight.json'),f.calls[-1])

if __name__ == '__main__':
    unittest.main()
