#!/usr/bin/env python3
"""A separate root operator for finite editor grants; no shell or credentials API."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import tempfile
import time

LIMIT = 65536
MAX_WORKERS = 4
OPERATION_SECONDS = 180
GRANTS = Path('/var/lib/fleet-operator/grants')
SOCKET = Path('/run/fleet-operator/operator.sock')
SHA = re.compile('[a-f0-9]{40}\\Z')
REPO = re.compile('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\\Z')


def validate_request(request):
    if not isinstance(request, dict):
        raise ValueError('grant request must be an object')
    operation = request.get('operation')
    fields = {'merge': {'operation', 'repository', 'pull_request', 'head'},
              'authorize_owner': {'operation', 'repository', 'revision', 'run_id'},
              'delivery': {'operation', 'repository', 'revision'},
              'host_report': {'operation', 'host'}}.get(operation)
    if fields is None or set(request) != fields:
        raise ValueError('grant operation has unexpected fields')
    if operation in ('merge', 'delivery', 'authorize_owner'):
        if not REPO.fullmatch(request['repository']) or not SHA.fullmatch(request['head' if operation == 'merge' else 'revision']):
            raise ValueError('grant requires exact repository and source revision')
    if operation == 'merge' and (type(request['pull_request']) is not int or request['pull_request'] <= 0):
        raise ValueError('grant requires the reviewed PR')
    if operation == 'authorize_owner' and (type(request['run_id']) is not int or request['run_id'] <= 0):
        raise ValueError('owner grant requires the reviewed CI run')
    if operation == 'host_report' and not re.fullmatch('[a-z0-9][a-z0-9.-]{0,252}', request['host']):
        raise ValueError('grant host is invalid')


class Broker:
    def __init__(self, grants, execute, owner=0, now=time.time):
        self.grants, self.execute, self.owner, self.now = Path(grants), execute, owner, now

    def protected(self, path):
        info = path.lstat()
        if info.st_uid != self.owner or info.st_mode & 0o077 or stat.S_ISLNK(info.st_mode):
            raise ValueError('grant authority is not private and protected')
        return info

    def use(self, uid, message):
        if (not isinstance(message, dict) or set(message) != {'grant', 'request'}
                or not re.fullmatch('[a-f0-9]{32}', message['grant'])):
            raise ValueError('operator requires a finite grant and fixed request')
        validate_request(message['request'])
        if not stat.S_ISDIR(self.protected(self.grants).st_mode):
            raise ValueError('grant directory is invalid')
        path = self.grants/(message['grant']+'.json')
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'r+b') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_mode & 0o077 or info.st_size > LIMIT:
                raise ValueError('grant is not a bounded protected regular file')
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            grant = json.loads(stream.read(LIMIT+1))
            now = self.now()
            if (set(grant) != {'version', 'id', 'uid', 'issued', 'expires', 'state', 'request', 'reviewer'}
                    or grant['version'] != 1 or grant['id'] != message['grant'] or grant['uid'] != uid
                    or type(uid) is not int or uid <= 0 or grant['state'] != 'issued'
                    or not isinstance(grant['issued'], (int, float)) or not isinstance(grant['expires'], (int, float))
                    or not grant['issued'] <= now < grant['expires'] <= grant['issued']+900
                    or grant['request'] != message['request'] or not isinstance(grant['reviewer'], str) or not grant['reviewer']):
                raise ValueError('grant scope, principal, lifetime or single-use state differs')
            # Consume durably before any effect. An interrupted/failed call needs
            # a new reviewed grant; a client cannot replay an ambiguous merge.
            grant['state'] = 'claimed'
            body = json.dumps(grant, sort_keys=True).encode()
            stream.seek(0)
            stream.write(body)
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())
            audit = {'version': 1, 'grant': grant['id'], 'uid': uid, 'reviewer': grant['reviewer'],
                     'executor': 'protected root operator', 'request_sha256': hashlib.sha256(json.dumps(grant['request'], sort_keys=True).encode()).hexdigest(),
                     'status': 'running', 'at': self.now(), 'independent_review_claimed': False}
            self.receipt(grant['id'], audit)
            try:
                result = self.execute(message['request'])
            except BaseException:
                audit.update(status='ambiguous' if message['request']['operation'] in ('merge', 'authorize_owner') else 'failed', at=self.now())
                self.receipt(grant['id'], audit)
                raise
            audit.update(status='completed', result=result, at=self.now())
            self.receipt(grant['id'], audit)
            return result

    def inspect(self, identifier, reconcile=None):
        if not isinstance(identifier, str) or not re.fullmatch('[a-f0-9]{32}', identifier):
            raise ValueError('inspection requires one exact grant identifier')
        self.protected(self.grants)
        path=self.grants/(identifier+'.json')
        self.protected(path)
        with os.fdopen(os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise ValueError('invalid grant')
            grant=json.loads(stream.read(LIMIT+1))
            try: fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                if reconcile: raise ValueError('operation is still running')
                return {'grant':identifier,'status':'running','inspection_required':False}
            receipt_path=self.grants/(identifier+'.receipt.json')
            if receipt_path.exists():
                self.protected(receipt_path)
                with os.fdopen(os.open(receipt_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as receipt:
                    audit=json.loads(receipt.read(LIMIT+1))
            else:
                audit={'version':1,'grant':identifier,'uid':grant['uid'],'reviewer':grant['reviewer'],
                       'status':grant['state'],'independent_review_claimed':False}
            # No live lock means a killed operation has an uncertain outcome.
            # Retain the claim: inspection never reissues or replays a grant.
            if grant['state']=='claimed' and audit['status'] in ('claimed','running'):
                audit.update(status='ambiguous',at=self.now())
                self.receipt(identifier,audit)
            if reconcile:
                if audit['status']!='ambiguous':raise ValueError('only an ambiguous operation needs reconciliation')
                actual=reconcile(grant['request'])
                if actual['status'] not in ('completed','failed','ambiguous'):raise ValueError('invalid observed outcome')
                audit.update(status=actual['status'],reconciliation=actual,at=self.now())
                self.receipt(identifier,audit)
            return audit

    def receipt(self, identifier, audit):
        fd, name = tempfile.mkstemp(prefix='.receipt-', dir=self.grants)
        try:
            with os.fdopen(fd, 'w') as out:
                json.dump(audit, out, sort_keys=True)
                out.flush()
                os.fchmod(out.fileno(), 0o600)
                os.fsync(out.fileno())
            os.replace(name, self.grants/(identifier+'.receipt.json'))
            descriptor = os.open(self.grants, os.O_DIRECTORY)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
        finally:
            if os.path.exists(name): os.unlink(name)


def installed_module():
    path = Path('/usr/local/libexec/fleet/fleet_operator.py')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('operator code is not protected')
    spec = importlib.util.spec_from_file_location('protected_operator', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    policy = module.private_policy(module.POLICY)
    return module, policy


def installed_operator():
    module, policy = installed_module()
    return lambda request: module.execute(request, policy)


def handle(connection, broker):
    def deadline(_signal, _frame):
        raise TimeoutError('operator operation exceeded its total deadline; inspect outcome before retry')
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(OPERATION_SECONDS)
    with connection:
        connection.settimeout(10)
        _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        try:
            body = bytearray()
            while len(body) <= LIMIT:
                chunk = connection.recv(min(4096, LIMIT+1-len(body)))
                if not chunk: break
                body.extend(chunk)
            if len(body) > LIMIT: raise ValueError('operator request exceeds its bound')
            result = broker.use(uid, json.loads(body))
            response={'ok':True,'result':result}
        except (ValueError, KeyError, TypeError, OSError):
            response={'ok':False,'reason':'operator refused or interrupted; inspect the protected receipt'}
        try: connection.sendall((json.dumps(response)+'\n').encode())
        except OSError: pass
    signal.alarm(0)


def serve(gid):
    if os.geteuid() != 0 or gid <= 0:
        raise ValueError('broker needs root and a separate editor group')
    SOCKET.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    info = SOCKET.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('operator socket directory is not protected')
    # systemd owns the socket across process death. Never unlink another live
    # listener or accept an editor-supplied path/descriptor.
    if os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1':
        raise ValueError('operator requires its service-owned activation socket')
    broker = Broker(GRANTS, installed_operator())
    def stop(_signal, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    with socket.socket(fileno=3) as listener:
        if listener.family != socket.AF_UNIX or listener.getsockname() != str(SOCKET):
            raise ValueError('activation socket differs from protected service')
        dispatch(listener, broker)


def dispatch(listener, broker):
    listener.settimeout(1)
    workers=set()
    while True:
        for pid in tuple(workers):
            if os.waitpid(pid,os.WNOHANG)[0]: workers.remove(pid)
        try: connection,_=listener.accept()
        except socket.timeout: continue
        if len(workers)>=MAX_WORKERS:
            connection.close()
            continue
        pid=os.fork()
        if pid==0:
            listener.close()
            try: handle(connection,broker)
            finally: os._exit(0)
        workers.add(pid)
        connection.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--editor-gid',type=int)
    modes.add_argument('--inspect')
    modes.add_argument('--reconcile')
    args=parser.parse_args()
    if args.editor_gid:serve(args.editor_gid)
    else:
        if os.geteuid()!=0:raise ValueError('inspection and reconciliation require the root operator')
        callback=None
        if args.reconcile:
            module,policy=installed_module()
            callback=lambda request:module.inspect_outcome(request,policy)
        print(json.dumps(Broker(GRANTS,None).inspect(args.inspect or args.reconcile,callback)))
