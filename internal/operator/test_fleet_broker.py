import importlib.util
import json
import os
from pathlib import Path
import tempfile
import signal
import socket
import subprocess
import sys
import time
import unittest

spec = importlib.util.spec_from_file_location('fleet_broker', Path(__file__).parent/'assets/fleet_broker.py')
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)


class BrokerTests(unittest.TestCase):
    def test_process_kill_at_durable_boundaries_requires_inspection_and_never_replays(self):
        for boundary in ('claimed','running','effect','completed'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                authority,message,grant,path,calls=self.fixture(directory)
                script='''import importlib.util,json,os,pathlib,sys,time
spec=importlib.util.spec_from_file_location('broker',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root=pathlib.Path(sys.argv[2]);boundary=sys.argv[3]
def pause():
    (root/'boundary').write_text(boundary)
    while True:time.sleep(1)
def execute(request):
    with (root/'effect').open('w') as out:out.write('synthetic external merge');out.flush();os.fsync(out.fileno())
    if boundary=='effect':pause()
    return {'merged':True}
b=m.Broker(root,execute,owner=os.getuid(),now=lambda:150)
original=b.receipt
def receipt(identifier,audit):
    if boundary=='claimed' and audit['status']=='running':pause()
    original(identifier,audit)
    if boundary==audit['status']:pause()
b.receipt=receipt
request=json.loads((root/('a'*32+'.json')).read_text())['request']
b.use(1234,{'grant':'a'*32,'request':request})
'''
                child=subprocess.Popen([sys.executable,'-I','-c',script,str(Path(broker.__file__)),directory,boundary],start_new_session=True)
                try:
                    deadline=time.monotonic()+5
                    while not (root/'boundary').exists():
                        if child.poll() is not None or time.monotonic()>deadline:self.fail('durable boundary not reached')
                        time.sleep(.01)
                    os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
                    audit=authority.inspect(grant['id'])
                    self.assertEqual(audit['status'],'completed' if boundary=='completed' else 'ambiguous')
                    with self.assertRaises(ValueError):authority.use(1234,message)
                    self.assertFalse(calls)
                    if boundary!='completed':
                        observed={'status':'completed' if (root/'effect').exists() else 'failed','synthetic_observation':True}
                        self.assertEqual(authority.inspect(grant['id'],lambda request:observed)['status'],observed['status'])
                        with self.assertRaises(ValueError):authority.use(1234,message)
                finally:
                    if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
                    child.wait(timeout=5)

    def test_total_process_deadline_bounds_effect_and_refuses_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o755)
            grants=root/'grants';grants.mkdir(mode=0o700)
            path=root/'operator.sock'
            listener=socket.socket(socket.AF_UNIX);listener.bind(str(path));path.chmod(0o666);listener.listen(8)
            uid=os.getuid() if os.getuid() else 65534
            request={'operation':'merge','repository':'nicodes/example','pull_request':1,'head':'b'*40}
            grant_id='a'*32
            grant={'version':1,'id':grant_id,'uid':uid,'issued':time.time(),'expires':time.time()+60,
                   'state':'issued','request':request,'reviewer':'synthetic process fixture'}
            grant_path=grants/(grant_id+'.json');grant_path.write_text(json.dumps(grant));grant_path.chmod(0o600)
            code="""import importlib.util,os,socket,sys,time
s=importlib.util.spec_from_file_location('broker',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.OPERATION_SECONDS=1
listener=socket.socket(fileno=int(sys.argv[2]))
m.dispatch(listener,m.Broker(sys.argv[3],lambda r:time.sleep(30),owner=os.getuid()))
"""
            child=subprocess.Popen([sys.executable,'-c',code,str(Path(broker.__file__)),str(listener.fileno()),str(grants)],pass_fds=(listener.fileno(),),start_new_session=True)
            client="""import os,socket,sys
if os.getuid()==0:os.setgroups([]);os.setgid(65534);os.setuid(65534)
s=socket.socket(socket.AF_UNIX);s.settimeout(4);s.connect(sys.argv[1]);s.sendall(sys.argv[2].encode());s.shutdown(socket.SHUT_WR);print(s.recv(65536).decode())
"""
            try:
                before=time.monotonic()
                reply=subprocess.check_output([sys.executable,'-c',client,str(path),json.dumps({'grant':grant_id,'request':request})],text=True,timeout=5)
                self.assertFalse(json.loads(reply)['ok']);self.assertLess(time.monotonic()-before,4)
                authority=broker.Broker(grants,lambda r:self.fail('ambiguous operation replayed'),owner=os.getuid())
                self.assertEqual(authority.inspect(grant_id)['status'],'ambiguous')
                with self.assertRaises(ValueError):authority.use(uid,{'grant':grant_id,'request':request})
            finally:
                listener.close()
                if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
                child.wait(timeout=5)

    def test_failure_retains_an_ambiguous_durable_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            authority,message,grant,path,calls=self.fixture(root)
            def fail(_):raise TimeoutError('synthetic interruption')
            authority.execute=fail
            with self.assertRaises(TimeoutError):authority.use(1234,message)
            receipt=json.loads(path.with_name(grant['id']+'.receipt.json').read_text())
            self.assertEqual(receipt['status'],'ambiguous')
            with self.assertRaises(ValueError):authority.use(1234,message)

    def test_service_owned_listener_survives_kill_and_slow_client_does_not_block_reports(self):
        # A retained listener models the service manager, with only synthetic
        # fixed callbacks. No installed socket, credential or GitHub call.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o755)
            grants=root/'grants';grants.mkdir(mode=0o700)
            path=root/'operator.sock'
            listener=socket.socket(socket.AF_UNIX);listener.bind(str(path));path.chmod(0o666);listener.listen(8)
            uid=os.getuid() if os.getuid() else 65534
            request={'operation':'host_report','host':'box.example'}
            grant_id='a'*32
            grant={'version':1,'id':grant_id,'uid':uid,'issued':time.time(),'expires':time.time()+60,
                   'state':'issued','request':request,'reviewer':'synthetic process fixture'}
            (grants/(grant_id+'.json')).write_text(json.dumps(grant));(grants/(grant_id+'.json')).chmod(0o600)
            code='''import importlib.util,os,socket,sys
s=importlib.util.spec_from_file_location('broker',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
listener=socket.socket(fileno=int(sys.argv[2]))
m.dispatch(listener,m.Broker(sys.argv[3],lambda r:{'synthetic':True},owner=os.getuid()))
'''
            def launch():return subprocess.Popen([sys.executable,'-c',code,str(Path(broker.__file__)),str(listener.fileno()),str(grants)],pass_fds=(listener.fileno(),),start_new_session=True)
            child=launch()
            slow=socket.socket(socket.AF_UNIX)
            try:
                slow.connect(str(path));slow.sendall(b'{')
                client='''import json,os,socket,sys
if os.getuid()==0:os.setgroups([]);os.setgid(65534);os.setuid(65534)
s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(sys.argv[1]);s.sendall(sys.argv[2].encode());s.shutdown(socket.SHUT_WR);print(s.recv(65536).decode())
'''
                before=time.monotonic()
                reply=subprocess.check_output([sys.executable,'-c',client,str(path),json.dumps({'grant':grant_id,'request':request})],text=True,timeout=5)
                self.assertTrue(json.loads(reply)['ok']);self.assertLess(time.monotonic()-before,3)
                os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
                child=launch()
                reply=subprocess.check_output([sys.executable,'-c',client,str(path),json.dumps({'grant':grant_id,'request':request})],text=True,timeout=5)
                self.assertFalse(json.loads(reply)['ok'])
                self.assertEqual(json.loads((grants/(grant_id+'.receipt.json')).read_text())['status'],'completed')
            finally:
                slow.close();listener.close()
                if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
                child.wait(timeout=5)
    def fixture(self, root):
        grant_id = 'a'*32
        request = {'operation': 'merge', 'repository': 'nicodes/example', 'pull_request': 1, 'head': 'b'*40}
        grant = {'version': 1, 'id': grant_id, 'uid': 1234, 'issued': 100, 'expires': 200,
                 'state': 'issued', 'request': request, 'reviewer': 'fixture reviewer'}
        path = Path(root)/(grant_id+'.json')
        path.write_text(json.dumps(grant))
        path.chmod(0o600)
        calls = []
        authority = broker.Broker(root, lambda r: calls.append(r) or {'merged': True}, os.getuid(), lambda: 150)
        return authority, {'grant': grant_id, 'request': request}, grant, path, calls

    def test_single_use_consumes_before_effect_and_records_real_principals(self):
        with tempfile.TemporaryDirectory() as root:
            authority, message, grant, path, calls = self.fixture(root)
            self.assertEqual(authority.use(1234, message), {'merged': True})
            self.assertEqual(json.loads(path.read_text())['state'], 'claimed')
            with self.assertRaises(ValueError):
                authority.use(1234, message)
            self.assertEqual(len(calls), 1)
            receipt = json.loads(path.with_name(grant['id']+'.receipt.json').read_text())
            self.assertFalse(receipt['independent_review_claimed'])
            self.assertEqual(receipt['uid'], 1234)

    def test_scope_principal_time_and_ambiguous_failure_cannot_be_replayed(self):
        for condition in ('uid', 'head', 'repository', 'pr', 'expiry', 'future', 'long', 'failed'):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as root:
                authority, message, grant, path, calls = self.fixture(root)
                uid = 1234
                if condition == 'uid':
                    uid = 1235
                elif condition == 'head':
                    message['request']['head'] = 'c'*40
                elif condition == 'repository':
                    message['request']['repository'] = 'nicodes/foreign'
                elif condition == 'pr':
                    message['request']['pull_request'] = 2
                elif condition == 'expiry':
                    authority.now = lambda: 201
                elif condition == 'future':
                    authority.now = lambda: 99
                elif condition == 'long':
                    grant['expires'] = 1100
                    path.write_text(json.dumps(grant))
                else:
                    def fail(r):
                        self.assertEqual(json.loads(path.read_text())['state'], 'claimed')
                        raise ValueError('fixture ambiguous outcome')
                    authority.execute = fail
                with self.assertRaises(ValueError):
                    authority.use(uid, message)
                self.assertFalse(calls)
                if condition == 'failed':
                    authority.execute = lambda r: calls.append(r)
                    with self.assertRaises(ValueError):
                        authority.use(uid, message)
                    self.assertFalse(calls)


if __name__ == '__main__':
    unittest.main()
