#!/usr/bin/env python3
"""Boot one pinned disposable Alpine guest and collect native host acceptance."""
import argparse
import ctypes
import hashlib
import importlib.util
import inspect
import json
import math
import os
from pathlib import Path
import shutil
import signal
import secrets
import selectors
import re
import shlex
import tomllib
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/fixtures/native_host'


def run(argv, *, timeout=60, **options):
    return subprocess.run(argv, check=options.pop('check',True), timeout=timeout, **options)


def native_failure_observation(evidence, journal, profile, source, binary_sha):
    """Project already-collected synthetic facts; never export raw guest records."""
    result={'kind':'komizo.native-fixture-failure','version':1,'profile':profile if profile in {'functional','bounded'} else 'unobserved',
        'source':{'revision':source if isinstance(source,str) and re.fullmatch('[a-f0-9]{40}',source) else None,
            'binary_sha256':binary_sha if isinstance(binary_sha,str) and re.fullmatch('[a-f0-9]{64}',binary_sha) else None}}
    def unobserved(reason):return {'state':'unobserved','reason':reason}
    def text(value,maximum):
        if not isinstance(value,str):return unobserved('invalid_text')
        if len(value)>65536:return unobserved('oversized_text')
        original=value
        if '-----BEGIN' in value or 'PRIVATE KEY' in value:value='[redacted fixture PEM]'
        elif re.search(r'(?i)\b(?:host|dbname|password|dsn)\s*=',value):value='[redacted fixture connection parameters]'
        else:
            value=re.sub(r'(?i)(?:runtime|migration)-[a-f0-9]{32}|(?<![a-f0-9])[a-f0-9]{48}(?![a-f0-9])|SCRAM-SHA-256\$[^\s]+|md5[a-f0-9]{32}',
                '[redacted fixture secret]',value)
            value=re.sub(r'(?i)\b(?:postgres(?:ql)?|https?|ssh)://[^\s]+','[redacted fixture URL]',value)
        return {'state':'observed','text':value[:maximum],'truncated':len(value)>maximum,
            'sha256':hashlib.sha256(original.encode()).hexdigest()}
    def token(value,pattern):return value if isinstance(value,str) and re.fullmatch(pattern,value) else None
    try:
        if not isinstance(evidence,bytes) or len(evidence)>1<<20:raise ValueError('missing_or_oversized_evidence')
        def unique(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError('duplicate_field')
                result[key]=value
            return result
        raw=json.loads(evidence,object_pairs_hook=unique)
        if (not isinstance(raw,dict) or raw.get('kind')!='komizo.native-fixture-evidence'
                or type(raw.get('version')) is not int or raw['version']!=1):raise ValueError('unknown_evidence_shape')
        operations=raw.get('operations');containers=raw.get('containers')
        if (not isinstance(operations,list) or not isinstance(containers,list)
                or len(operations)>32 or len(containers)>32):raise ValueError('invalid_inventory')
        failures=[]
        for item in operations:
            if (not isinstance(item,dict) or item.get('kind')!='komizo.operation'
                    or type(item.get('version')) is not int or item['version']!=1):raise ValueError('invalid_operation')
            failure=item.get('failure')
            if failure is None:continue
            identity=token(item.get('operation_id'),'[a-f0-9]{32}')
            app=token(item.get('application'),'[a-z][a-z0-9-]{0,62}')
            instance=token(item.get('instance'),r'production|pr-[1-9][0-9]*')
            if (not identity or not app or not instance or not isinstance(failure,dict)
                    or failure.get('kind')!='komizo.failure' or type(failure.get('version')) is not int
                    or failure['version']!=1 or failure.get('operation_id')!=identity):raise ValueError('invalid_failure_identity')
            phase=token(failure.get('phase'),'[a-z][a-z_]{0,63}');code=token(failure.get('code'),'[a-z][a-z_]{0,63}')
            if phase is None or code is None:raise ValueError('unknown_failure_phase_or_code')
            failures.append({'operation_id':identity,'application':app,'instance':instance,
                'kind':failure['kind'],'phase':phase,'code':code,'context':text(failure.get('context'),2048)})
        selected=[]
        for item in containers:
            if not isinstance(item,dict):raise ValueError('invalid_container')
            identity=token(item.get('id'),'[a-f0-9]{64}');app=token(item.get('application'),'[a-z][a-z0-9-]{0,62}')
            instance=token(item.get('instance'),r'production|pr-[1-9][0-9]*')
            service=token(item.get('service'),'[a-z][a-z0-9-]{0,62}')
            state=item.get('state')
            if not identity or not app or not instance or not service or state not in {'created','configured','running','exited','stopped','dead','paused'}:
                raise ValueError('invalid_container_identity_or_state')
            row={'id':identity,'application':app,'instance':instance,'service':service,'state':state}
            failure=item.get('failure_observation')
            if isinstance(failure,dict):
                row.update(exit_code=failure.get('exit_code') if type(failure.get('exit_code')) is int and 0<=failure['exit_code']<=255 else None,
                    oom_killed=failure.get('oom_killed') if type(failure.get('oom_killed')) is bool else None,
                    error=text(failure.get('error'),2048))
                logs=failure.get('logs')
                if isinstance(logs,dict) and logs.get('state')=='observed':
                    row['logs']={'state':'observed',**{name:text(logs.get(name),2048) for name in ['stdout','stderr']},
                        **{name:logs.get(name) if type(logs.get(name)) is bool else None
                            for name in ['timed_out','stdout_truncated','stderr_truncated']},
                        'command_exit_code':logs.get('command_exit_code') if type(logs.get('command_exit_code')) is int
                            and -255<=logs['command_exit_code']<=255 else None}
                else:row['logs']=unobserved('logs_not_observed')
            else:row['failure_observation']=unobserved('not_collected')
            selected.append(row)
        result.update(state='observed',operations=failures[:4],containers=selected[:4],
            inventories_truncated=len(failures)>4 or len(selected)>4)
    except (ValueError,TypeError,UnicodeError,RecursionError):
        result.update(state='unobserved',reason='missing_oversized_or_malformed_evidence')
    if isinstance(journal,bytes) and len(journal)<=65536:
        lines=[line for line in journal.decode(errors='replace').splitlines()
            if re.search(r'oom-kill:|Out of memory:|Memory cgroup out of memory:|apparmor="DENIED"',line)]
        result['kernel']={'state':'observed','events':[text(line,512) for line in lines[-8:]],'truncated':len(lines)>8}
    else:result['kernel']=unobserved('missing_or_oversized_journal')
    encoded=json.dumps(result,sort_keys=True)
    if len(encoded.encode())+1>32768:
        result={key:result[key] for key in ['kind','version','profile','source']}
        result.update(state='unobserved',reason='closed_export_limit')
        encoded=json.dumps(result,sort_keys=True)
    return encoded


def emit_native_failure(failed,evidence,journal,profile,source,binary_sha):
    if not failed:return
    try:
        print(native_failure_observation(evidence,journal,profile,source,binary_sha),file=sys.stderr,flush=True)
    except Exception:
        # Diagnostics cannot replace the original exception or skip owned cleanup.
        try:print('{"kind":"komizo.native-fixture-failure","version":1,"state":"unobserved","reason":"diagnostic_emission_failed"}',file=sys.stderr,flush=True)
        except Exception:pass


def download(record, target):
    algorithm = 'sha512' if 'sha512' in record else 'sha256'
    digest = hashlib.new(algorithm)
    count = 0
    deadline = time.monotonic() + 300
    with urllib.request.urlopen(record['url'], timeout=30) as source, target.open('xb') as output:
        while chunk := source.read(1 << 20):
            count += len(chunk)
            if count > record['max_bytes'] or time.monotonic() >= deadline:
                raise ValueError('pinned fixture download exceeds its bound')
            digest.update(chunk)
            output.write(chunk)
    if not count or digest.hexdigest() != record[algorithm]:
        raise ValueError('pinned fixture download differs from reviewed bytes')


def authenticate_image(record, image, directory):
    key = FIXTURES/'alpine-cloud-signing-key.asc'
    if hashlib.sha256(key.read_bytes()).hexdigest() != record['signing_key_sha256']:
        raise ValueError('Alpine signing key differs from its reviewed public bytes')
    if image.stat().st_size != record['size_bytes']:
        raise ValueError('Alpine cloud image length differs')
    signature = directory/'image.asc'
    download({'url':record['signature_url'],'sha256':record['signature_sha256'],'max_bytes':4096}, signature)
    home = directory/'gpg';home.mkdir(mode=0o700)
    listing = run(['gpg','--homedir',str(home),'--batch','--with-colons','--show-keys',str(key)],capture_output=True).stdout.decode()
    fingerprints = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
    if not fingerprints or fingerprints[0] != record['signing_fingerprint']:
        raise ValueError('Alpine image signer fingerprint differs from the official release key')
    run(['gpg','--homedir',str(home),'--batch','--import',str(key)],capture_output=True)
    status = run(['gpg','--homedir',str(home),'--batch','--status-fd=1','--verify',str(signature),str(image)],capture_output=True).stdout.decode()
    if not any(line.startswith('[GNUPG:] VALIDSIG '+record['signing_fingerprint']+' ') for line in status.splitlines()):
        raise ValueError('Alpine cloud image lacks its exact official signer')


def parent_lifetime(parent):
    # An aggregate timeout/crash of the driver must not leave its owned KVM
    # process running. No other guest or host process is selected by this hook.
    if ctypes.CDLL(None,use_errno=True).prctl(1,signal.SIGKILL)!=0:raise OSError(ctypes.get_errno(),'cannot bind owned guest lifetime')
    if os.getppid()!=parent:os.kill(os.getpid(),signal.SIGKILL)


def fixture_root_user(public_key):
    # Linux OpenSSH rejects a shadow account prefixed with '!'. Cloud-init
    # locks existing users by default; '*' keeps passwords unusable while
    # allowing only the disposable authorized key with ssh_pwauth disabled.
    return {'name': 'root', 'lock_passwd': False, 'hashed_passwd': '*',
        'ssh_authorized_keys': [public_key]}


def fixture_cloud_options():
    # Host keys are already pinned independently by Guest. Alpine's optional
    # console publisher helper is absent; its display is not authentication.
    return {'disable_root': False, 'ssh_pwauth': False,
        'ssh': {'emit_keys_to_console': False}}


def startup_diagnostics(directory=None, boot_id=None):
    """Read only the four fixed, private, non-authoritative startup records."""
    import json
    import os
    from pathlib import Path
    import re
    import stat
    roles = ('controller', 'proxy', 'dns', 'expiry')
    directory = Path('/run/komizo-infrastructure') if directory is None else Path(directory)
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip() if boot_id is None else boot_id
    result = {}
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value: raise ValueError('duplicate diagnostic field')
            value[key] = item
        return value
    try:
        info = directory.stat()
        if (any(p.is_symlink() for p in [directory, *directory.parents])
                or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('private diagnostic directory differs')
    except (OSError, ValueError):
        return {role: {'state': 'unavailable'} for role in roles}
    for role in roles:
        try:
            descriptor = os.open(directory / (role + '.startup.json'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                        or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                        or not 0 < before.st_size <= 4096):
                    raise ValueError('private bounded diagnostic required')
                raw = stream.read(4097)
                after = os.fstat(stream.fileno())
            if (len(raw) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError('diagnostic changed')
            value = json.loads(raw, object_pairs_hook=pairs)
            if (not isinstance(value, dict) or set(value) != {'kind', 'version', 'diagnostic_only', 'role', 'boot_id', 'pid', 'stage', 'errno', 'error'}
                    or value['kind'] != 'komizo.infrastructure-startup-diagnostic'
                    or type(value['version']) is not int or value['version'] != 1 or value['diagnostic_only'] is not True
                    or value['role'] != role or value['boot_id'] != boot_id
                    or re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value['boot_id']) is None
                    or type(value['pid']) is not int or value['pid'] <= 1
                    or value['stage'] not in {'files', 'leaf', 'monitor', 'parent', 'notification',
                        'notification_environment', 'notification_address', 'notification_socket',
                        'notification_parent', 'notification_identity', 'proxy_guard', 'confinement', 'exec', 'runner'}
                    or not (value['errno'] is None or type(value['errno']) is int)
                    or value['error'] not in {'io', 'guard', 'pending'}
                    or value['error'] == 'pending' and (value['stage'] != 'exec' or value['errno'] is not None)):
                raise ValueError('diagnostic schema differs')
            result[role] = value
        except FileNotFoundError:
            result[role] = {'state': 'absent'}
        except (OSError, ValueError, TypeError):
            result[role] = {'state': 'refused'}
    return result


def notification_metadata():
    """Observe only the two fixed notification objects; never follow links."""
    import os
    import stat
    result = {}
    paths = ('/run/openrc', '/run/openrc/supervise-komizo-proxy.sock')
    for index, path in enumerate(paths):
        if index and result[paths[0]].get('type') != 'directory':
            result[path] = {'state': 'refused'}
            continue
        try:
            info = os.lstat(path)
            expected = stat.S_ISDIR if index == 0 else stat.S_ISSOCK
            if not expected(info.st_mode):
                raise ValueError('fixed notification object has another type')
            result[path] = {'uid': info.st_uid, 'gid': info.st_gid,
                'mode': stat.S_IMODE(info.st_mode), 'type': 'directory' if index == 0 else 'socket'}
        except FileNotFoundError:
            result[path] = {'state': 'absent'}
        except (OSError, ValueError):
            result[path] = {'state': 'refused'}
    return result


def key(directory, name):
    path = directory / name
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)])
    return path


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class OwnedDirectory:
    """The evidence records cleanup of this guest, never shared host objects."""
    def __init__(self,output):self.output=output;self.process=None
    def __enter__(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='komizo-native-host-')
        self.path=Path(self.temporary.__enter__())
        return self
    def __exit__(self,kind,error,traceback):
        if self.process is not None and self.process.poll() is None:
            os.killpg(self.process.pid,signal.SIGTERM)
            try:self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid,signal.SIGKILL);self.process.wait(timeout=5)
        self.temporary.__exit__(kind,error,traceback)
        cleanup={'version':1,'owned_guest_removed':self.process is None or self.process.poll() is not None,
            'private_storage_removed':not self.path.exists(),'shared_images_removed':False}
        (self.output/'cleanup.json').write_text(json.dumps(cleanup,sort_keys=True)+'\n')
        if not cleanup['owned_guest_removed'] or not cleanup['private_storage_removed']:raise ValueError('owned disposable guest cleanup remains incomplete')


class Guest:
    def __init__(self, directory, keyfile, host_key, ssh_port):
        self.directory = directory
        self.key = keyfile
        known = directory / 'known_hosts'
        known.write_text('[127.0.0.1]:' + str(ssh_port) + ' ' + host_key.read_text())
        known.chmod(0o600)
        self.arguments = ['-i', str(keyfile), '-p', str(ssh_port), '-o', 'IdentitiesOnly=yes',
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(known),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=5', '-o', 'ConnectionAttempts=1',
            '-o', 'IdentityAgent=none', '-o', 'ControlMaster=no', '-o', 'ProxyCommand=none']

    def command(self, command, *, timeout=60, **options):
        return run(['ssh', *self.arguments, 'root@127.0.0.1', command], timeout=timeout, **options)

    def copy(self, source, target):
        # scp uses a different port option; all remaining transport fences match.
        arguments = self.arguments.copy()
        arguments[arguments.index('-p')] = '-P'
        run(['scp', '-q', *arguments, str(source), 'root@127.0.0.1:' + target], timeout=120)

    def fetch(self, source, target):
        arguments = self.arguments.copy()
        arguments[arguments.index('-p')] = '-P'
        run(['scp', '-q', *arguments, 'root@127.0.0.1:' + source, str(target)], timeout=120)

    def ready(self, process, deadline, *, evidence=None):
        observation = {'state': 'no authenticated SSH response'}
        first = None
        attempts = 0
        ready = False
        try:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise ValueError('disposable guest stopped before SSH readiness')
                attempts += 1
                try:
                    result = self.command('test -f /root/native-host/cloud-ready && cloud-init status --wait',
                        timeout=max(.01, min(15, deadline - time.monotonic())), capture_output=True, check=False)
                    # Only dummy fixture material exists here. Preserve the
                    # original SSH error without exporting argv/environment.
                    observation = {'returncode': result.returncode,
                        'stderr': result.stderr[-4096:].decode(errors='replace')}
                    if first is None: first = observation
                    if result.returncode == 0:
                        ready = True
                        return
                except subprocess.TimeoutExpired as error:
                    observation = {'state': 'cloud setup or SSH command timed out',
                        'stderr': (error.stderr or b'')[-4096:].decode(errors='replace')}
                except (subprocess.SubprocessError, OSError):
                    observation = {'state': 'SSH transport unavailable'}
                if first is None: first = observation
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(1, remaining))
            raise ValueError('disposable guest readiness deadline expired: ' + json.dumps(observation, sort_keys=True))
        finally:
            if evidence is not None:
                record = {'kind': 'komizo.disposable-guest-ssh-observations', 'version': 1,
                    'ready': ready, 'attempts': attempts, 'first': first, 'last': observation}
                try:
                    with evidence.open('x') as output:
                        os.fchmod(output.fileno(), 0o600)
                        output.write(json.dumps(record, sort_keys=True) + '\n')
                except OSError:
                    # Optional evidence never replaces the original result.
                    pass

    def boot_diagnostics(self):
        # Fixed read-only boot observations contain no process argv, environment
        # or private controller state. Each command and its exported bytes are
        # bounded independently, even when the OS has pending start jobs.
        script = inspect.getsource(startup_diagnostics) + '\n' + inspect.getsource(notification_metadata) + '''\nimport json, pathlib, subprocess, tempfile
commands = {
    'cloud_init': ['cloud-init', 'status', '--long', '--format=json'],
    'openrc': ['rc-status', '--all'],
    'apparmor': ['rc-service', 'apparmor', 'status'],
    'cloud_log': ['tail', '-c', '32768', '/var/log/cloud-init-output.log'],
    'service_log': ['tail', '-c', '16384', '/var/log/messages', '/var/log/rc.log'],
    'kernel': ['cat', '/sys/kernel/security/lsm', '/sys/module/apparmor/parameters/enabled'],
}
record = {'version': 1, 'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'observations': {}}
record['infrastructure_startup'] = startup_diagnostics(boot_id=record['boot_id'])
record['notification_metadata'] = notification_metadata()
for name, argv in commands.items():
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, timeout=5, check=False)
            item = {'returncode': result.returncode}
        except subprocess.TimeoutExpired:
            item = {'timed_out': True}
        output.seek(0)
        data = output.read(32769)
        item.update(text=data[:32768].decode(errors='replace'), truncated=len(data) > 32768)
        record['observations'][name] = item
print(json.dumps(record, sort_keys=True))
'''
        return self.command('python3 -I -B -c ' + shlex.quote(script), timeout=35, capture_output=True).stdout

    def submission_boundary(self, keyfile):
        arguments = self.arguments.copy()
        arguments[1] = str(keyfile)
        for command in ['id', 'sh', 'podman ps', 'komizo-box daemon','komizo-box dns --config /run/containers/networks/aardvark-dns -p 53 run']:
            result = subprocess.run(['ssh', *arguments, 'komizo-submit@127.0.0.1', command],
                input=b'', capture_output=True, timeout=15)
            if result.returncode == 0 or result.stdout:
                raise ValueError('submission SSH identity acquired a command or shell frontdoor')
        now = int(time.time())
        body = {'kind':'komizo.request','version':1,'authority':'owner','application':'mailroom','instance':'production',
            'action':'inspect','release_digest':'current','nonce':secrets.token_hex(16),'issued_at':now,
            'expires_at':now+120,'timeout_seconds':120,'proof':''}
        result = subprocess.run(['ssh', *arguments, 'komizo-submit@127.0.0.1', 'komizo-box submit'],
            input=json.dumps(body).encode(), capture_output=True, timeout=15)
        if json.loads(result.stdout).get('kind') != 'komizo.error':
            raise ValueError('submission SSH identity selected the independent root owner authority')
        result = subprocess.run(['ssh', *arguments, '-o', 'ExitOnForwardFailure=yes',
            '-R', '127.0.0.1:0:127.0.0.1:80', 'komizo-submit@127.0.0.1', 'komizo-box submit'],
            input=b'', capture_output=True, timeout=15)
        if result.returncode == 0 or b'remote port forwarding failed' not in result.stderr:
            raise ValueError('submission SSH identity permits network forwarding')

    def encrypted_export(self, record, metadata):
        now=int(time.time())
        body={'kind':'komizo.request','version':1,'authority':'owner','application':record['application'],'instance':record['instance'],
            'action':'export','release_digest':record['release_digest'],'operation':record['operation_id'],'export_name':metadata['name'],
            'nonce':secrets.token_hex(16),'issued_at':now,'expires_at':now+120,'timeout_seconds':60}
        if type(metadata['size_bytes']) is not int or not 0<metadata['size_bytes']<=1<<20:raise ValueError('owner export exceeds fixture policy')
        process=subprocess.Popen(['ssh',*self.arguments,'root@127.0.0.1','komizo-box submit'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        output=bytearray();errors=0;deadline=time.monotonic()+60
        try:
            process.stdin.write(json.dumps(body,separators=(',',':')).encode());process.stdin.close()
            with selectors.DefaultSelector() as selector:
                for stream in [process.stdout,process.stderr]:
                    os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic()>=deadline:raise ValueError('owner ciphertext transport exceeded its deadline')
                    for key,_ in selector.select(min(1,deadline-time.monotonic())):
                        data=os.read(key.fileobj.fileno(),65536)
                        if not data:selector.unregister(key.fileobj);continue
                        if key.fileobj is process.stdout:
                            output.extend(data)
                            if len(output)>metadata['size_bytes']+16384:raise ValueError('owner ciphertext exceeded its framed bound')
                        else:
                            errors+=len(data)
                            if errors>65536:raise ValueError('owner ciphertext diagnostics exceeded their bound')
            if process.wait(timeout=5):raise ValueError('owner ciphertext transport did not complete')
        finally:
            if process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
            process.stdout.close();process.stderr.close()
        line,separator,payload=bytes(output).partition(b'\n')
        expected={'kind':'komizo.export','version':1,'application':record['application'],'instance':record['instance'],
            'operation_id':record['operation_id'],'release_digest':record['release_digest'],'export_name':metadata['name'],
            'size_bytes':metadata['size_bytes'],'sha256':metadata['sha256']}
        if not separator or len(line)>16384 or json.loads(line)!=expected or len(payload)!=metadata['size_bytes'] or 'sha256:'+hashlib.sha256(payload).hexdigest()!=metadata['sha256']:
            raise ValueError('owner ciphertext framing or source identity differs from capture')
        return payload


class IsolatedOwner:
    """Execute the shipping client under a new UID with disposable SSH inputs."""
    def __init__(self,guest,cli):
        self.guest,self.cli=guest,cli
        self.name='kmz-cold-'+secrets.token_hex(6)
        self.directory=None;self.uid=None

    def __enter__(self):
        run(['sudo','-n','useradd','--system','--user-group','--no-create-home','--shell','/usr/sbin/nologin',self.name],capture_output=True)
        try:
            uid=int(run(['id','-u',self.name],capture_output=True).stdout)
            if uid in {0,os.getuid()}:raise ValueError('cold owner client must have an independent unprivileged UID')
            self.uid=uid
            self.directory=Path(tempfile.mkdtemp(prefix='komizo-cold-owner-'))
            self.home=self.directory/'home';self.home.mkdir(mode=0o700)
            tools=self.directory/'bin';tools.mkdir(mode=0o700)
            target=tools/'komizo';shutil.copyfile(self.cli,target);target.chmod(0o700)
            private=self.directory/'owner';shutil.copyfile(self.guest.key,private);private.chmod(0o600)
            pins=self.directory/'known_hosts';shutil.copyfile(self.guest.directory/'known_hosts',pins);pins.chmod(0o600)
            arguments=[str(private) if value==str(self.guest.key) else
                'UserKnownHostsFile='+str(pins) if value.startswith('UserKnownHostsFile=') else value for value in self.guest.arguments]
            wrapper=tools/'ssh';wrapper.write_text('#!/bin/sh\nexec /usr/bin/ssh '+shlex.join(arguments)+' "$@"\n');wrapper.chmod(0o700)
            gid=int(run(['id','-g',self.name],capture_output=True).stdout)
            # The client may write its home and use the disposable identity, but
            # cannot replace its own executable, SSH adapter or protected pins.
            run(['sudo','-n','chown','-R','root:'+str(gid),str(self.directory)],capture_output=True)
            run(['sudo','-n','chown',str(self.uid)+':'+str(gid),str(self.home),str(private)],capture_output=True)
            run(['sudo','-n','chmod','0555',str(tools),str(target),str(wrapper)],capture_output=True)
            run(['sudo','-n','chmod','0440',str(pins)],capture_output=True)
            run(['sudo','-n','chmod','0400',str(private)],capture_output=True)
            run(['sudo','-n','chmod','0710',str(self.directory)],capture_output=True)
            self.prefix=['sudo','-n','--user='+self.name,'--','/usr/bin/env','-i','--chdir='+str(self.home),'HOME='+str(self.home),
                'PATH='+str(tools)+':/usr/bin:/bin','LANG=C.UTF-8']
            # Scrubbing environment variables alone cannot isolate another process
            # with the same UID. Prove the kernel denies the orchestrator's Env.
            for protected in [Path('/proc/'+str(os.getpid())+'/environ'),self.guest.directory/'recipient.key']:
                if not protected.exists():raise ValueError('cold owner isolation probe lacks its protected input')
                probe=run([*self.prefix,'/usr/bin/python3','-I','-B','-c',
                    'import pathlib,sys\ntry: pathlib.Path(sys.argv[1]).open("rb").read(1)\nexcept PermissionError: sys.exit(0)\nsys.exit(1)',
                    str(protected)],capture_output=True)
            for immutable in [target,wrapper,pins]:
                run([*self.prefix,'/usr/bin/python3','-I','-B','-c',
                    'import pathlib,sys\ntry: pathlib.Path(sys.argv[1]).open("ab")\nexcept PermissionError: sys.exit(0)\nsys.exit(1)',
                    str(immutable)],capture_output=True)
            self.executable=target
            return self
        except BaseException:
            self.__exit__(None,None,None)
            raise

    def __exit__(self,*_):
        if self.uid is not None:
            run(['sudo','-n','pkill','-KILL','-u',str(self.uid)],capture_output=True,check=False)
        if self.directory is not None:
            run(['sudo','-n','rm','-rf','--',str(self.directory)],capture_output=True)
        run(['sudo','-n','userdel',self.name],capture_output=True)


def cold_owner(guest,directory,cli,isolated):
    observed=[]
    def command(action,*flags,timeout=120):
        began=time.monotonic()
        response=run([*isolated.prefix,str(isolated.executable),action,*flags],
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},capture_output=True,timeout=timeout)
        observed.append({'action':action,'seconds':time.monotonic()-began})
        value=json.loads(response.stdout)
        if not isinstance(value,dict):raise ValueError('cold owner client did not return a typed record')
        return value
    capabilities=command('capabilities')
    if capabilities.get('kind')!='komizo.capabilities' or capabilities.get('host')!={'os':'alpine','version':'3.24','engine':'podman','rootful':True}:
        raise ValueError('shipping owner client capability contract differs')
    flags=['--host','127.0.0.1','--application','pgbox','--instance','production']
    if command('status','--host','127.0.0.1').get('kind')!='komizo.status':raise ValueError('cold owner inventory failed')
    current=command('inspect',*flags);digest=current['installed']['release_digest']
    if not current['installed']['desired_running']:raise ValueError('cold owner initial state differs')
    stopped=command('stop',*flags)
    if not stopped.get('ok') or stopped.get('phase')!='prepared_stopped':raise ValueError('cold public owner Stop did not preserve intent')
    if command('inspect',*flags)['installed']['desired_running']:raise ValueError('cold owner inspection did not observe Stop')
    started=command('start',*flags)
    if not started.get('ok') or started.get('phase')!='ready' or started.get('release_digest')!=digest:raise ValueError('cold public owner Start changed accepted source')
    if command('logs',*flags,'--service','api').get('kind')!='komizo.logs':raise ValueError('cold owner logs did not retain typed scope')
    report={'accepted':True,'mode':'deterministic_public_cli','commands':len(observed),'seconds':sum(row['seconds'] for row in observed),
        'human_interventions':0,'provider_credentials_in_task':False,'source_checkout_in_task':False,
        'public_readme_sha256':hashlib.sha256((ROOT/'README.md').read_bytes()).hexdigest(),
        'observed':observed,'cli_sha256':hashlib.sha256(cli.read_bytes()).hexdigest()}
    return command,flags,report


def performance(guest,directory,cli,setup_seconds):
    with IsolatedOwner(guest,cli) as isolated:
        return isolated_performance(guest,directory,cli,setup_seconds,isolated)


def performance_metrics(guest,budget):
    response=guest.command('python3 /root/native-host/fixture_performance.py finish '+shlex.quote(json.dumps(budget)),
        timeout=budget['load_seconds']+20,capture_output=True,check=False)
    if response.returncode:
        # Never forward arbitrary guest stderr or an exception path. These fixed
        # facts distinguish collection failures without exporting private state.
        stderr=response.stderr[-8192:] if isinstance(response.stderr,bytes) else b''
        classes=re.findall(rb'^([A-Za-z]+Error):',stderr,re.MULTILINE)
        allowed={b'ValueError',b'RuntimeError',b'FileNotFoundError',b'PermissionError',b'KeyError',b'OSError',b'JSONDecodeError'}
        kind=classes[-1].decode() if classes and classes[-1] in allowed else 'unclassified'
        raise ValueError(json.dumps({'phase':'bounded_performance_collection','exit_code':response.returncode,
            'exception_class':kind,'missing_cpu_stat':kind=='FileNotFoundError' and b'cpu.stat' in stderr},sort_keys=True))
    return json.loads(response.stdout)


def public_performance_observation(metrics):
    fields={'guest_memory_bytes','guest_milli_cpus','setup_seconds','deployment_seconds','idle_control_pss_bytes',
        'route_seconds','operator_seconds','load_hot_bytes','load_cpu_usec','oom_events_unchanged','owned_load_removed'}
    selected={key:metrics[key] for key in sorted(fields)}
    for key,value in selected.items():
        samples=value if isinstance(value,list) else [value]
        if not samples or len(samples)>32 or any(type(v) not in (bool,int,float) or abs(v)>2**64 or not math.isfinite(v) for v in samples):
            raise ValueError('invalid public performance measurement: '+key)
    return selected


def isolated_performance(guest,directory,cli,setup_seconds,isolated):
    budget_path=ROOT/'tests/acceptance/acceptance-budgets.toml'
    budget=tomllib.loads(budget_path.read_text())
    command,flags,onboarding=cold_owner(guest,directory,cli,isolated)
    guest.command('python3 /root/native-host/fixture_performance.py start '+shlex.quote(json.dumps(budget)),timeout=30)
    routes=[];operators=[]
    for _ in range(budget['samples']):
        began=time.monotonic()
        guest.command("cd /root/native-host && python3 -I -B -c "+shlex.quote("import sys;sys.path.insert(0,'.');import fixture_runtime as r;r.fetch('pgbox',r.installed('pgbox')['release_digest'])"),timeout=budget['route_seconds'])
        routes.append(time.monotonic()-began)
        began=time.monotonic();observed=command('inspect',*flags,timeout=budget['operator_seconds']);operators.append(time.monotonic()-began)
        if observed.get('kind')!='komizo.instance' or not observed['installed']['desired_running']:raise ValueError('owner read under load lost exact running scope')
    metrics=performance_metrics(guest,budget)
    timings=json.loads(guest.command('cat /root/native-host/timings.json',capture_output=True).stdout)
    metrics.update(setup_seconds=setup_seconds,deployment_seconds=timings['deployment_seconds'],route_seconds=routes,operator_seconds=operators)
    print(json.dumps({'bounded_performance_observation':public_performance_observation(metrics)},sort_keys=True),flush=True)
    sys.path.insert(0,str(ROOT/'tests/acceptance'))
    from performance_acceptance import evaluate, SCOPE
    accepted=evaluate(metrics,budget)
    report={'version':1,'accepted':accepted,'budget':budget,'budget_sha256':hashlib.sha256(budget_path.read_bytes()).hexdigest(),
        'metrics':metrics,'scope':SCOPE}
    return report,onboarding


def owner_recovery(guest, directory, key, sources):
    report=json.loads(guest.command('cat /root/native-host/report.json',capture_output=True).stdout)
    checks={}
    records=report.get('owner_exports')
    applications={'pgbox'} if report['profile']=='bounded' else {'secretbox','pgbox'}
    if not isinstance(records,list) or {value['application'] for value in records}!=applications:
        raise ValueError('owner recovery lacks its expected captured synthetic instance')
    for record in records:
        if len(record['files'])!=2 or {metadata['name'] for metadata in record['files']}!={'snapshot.cms','receipt.json'}:
            raise ValueError('owner capture has an invalid encrypted file inventory')
        pair={metadata['name']:guest.encrypted_export(record,metadata) for metadata in record['files']}
        if set(pair)!={'snapshot.cms','receipt.json'}:raise ValueError('owner received an unexpected encrypted pair')
        receipt=json.loads(pair['receipt.json'])
        if receipt['deployment']['application']!=record['application'] or receipt['deployment']['release_digest']!=record['release_digest'] or receipt['ciphertext_sha256']!=hashlib.sha256(pair['snapshot.cms']).hexdigest():
            raise ValueError('owner backup receipt lost captured source or ciphertext identity')
        if receipt.get('format') != 2:
            raise ValueError('native capture did not use the accepted authenticated snapshot format')
        copied=directory/(record['application']+'-encrypted');copied.mkdir(mode=0o700)
        for name,body in pair.items():
            path=copied/name;path.write_bytes(body);path.chmod(0o600)
        payload=directory/(record['application']+'-restored');payload.mkdir(mode=0o700)
        recovered=sources.snapshot().unseal(copied,key,payload)
        if record['format']=='synthetic-sqlite-package-v2':
            with sqlite3.connect('file:'+str(payload/'data.db')+'?mode=ro',uri=True) as database:
                retained=database.execute('SELECT application,release_digest,value FROM evidence').fetchall()
            database.close()
            if retained != [(record['application'],record['release_digest'],'accepted\n')]:
                raise ValueError('owner synthetic decryption changed retained data or source identity')
            checks['synthetic_owner_decryption']='passed'
        elif record['format']=='postgresql-package-v2':
            manifest=recovered.get('postgresql',{})
            deployment=manifest.get('deployment',{})
            if (deployment.get('release_digest')!=record['release_digest']
                    or deployment.get('release',{}).get('providers')!=sources.providers
                    or deployment.get('provider')!=sources.providers
                    or deployment.get('release',{}).get('source')!=sources.source):
                raise ValueError('owner PostgreSQL package lost exact source or tested provider binding')
            dump=payload/'database.dump'
            if not dump.read_bytes().startswith(b'PGDMP') or dump.stat().st_size>1<<20:
                raise ValueError('owner PostgreSQL plaintext is not the bounded captured dump')
            guest.copy(dump,'/root/native-host/owner-postgres.dump')
            restored=json.loads(guest.command('python3 /root/native-host/fixture_postgres.py restore',timeout=120,capture_output=True).stdout)
            if (restored.get('kind')!='komizo.native-database-recovery' or restored.get('release_digest')!=record['release_digest']
                    or restored.get('current_source_ci_acceptance') is not False or restored.get('rows')!='passed'):
                raise ValueError('owner PostgreSQL restoration did not prove the captured installed source')
            checks['owner_postgresql_encrypted_restore']='passed';checks['owner_recovery_disposable_isolation']='passed'
            checks['source_bound_authenticated_snapshot']='passed'
        else:raise ValueError('owner received an unsupported synthetic recovery format')
    checks['owner_side_exact_framed_exports']='passed';checks['recovery_private_key_outside_capture_host']='passed'
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--proxy-binary', required=True, type=Path)
    parser.add_argument('--proxy-receipt', required=True, type=Path)
    parser.add_argument('--profile',choices=['functional','bounded'],default='functional')
    parser.add_argument('--cli',type=Path,help='exact shipping cold owner executable; required for the bounded profile')
    parser.add_argument('--cookbook-source',type=Path,default=os.environ.get('COOKBOOK_ROOT') or os.environ.get('RECIPE_SOURCE_SDK'))
    parser.add_argument('--tools-source',type=Path,default=os.environ.get('TOOLS_ROOT'))
    parser.add_argument('--output', type=Path, default=ROOT / '.artifacts/native-host')
    args = parser.parse_args()
    if args.profile=='bounded' and (args.cli is None or args.cli.is_symlink() or not args.cli.is_file()):raise ValueError('bounded native acceptance requires its exact cold owner client')
    binary = args.binary.absolute()
    if not binary.is_file() or binary.is_symlink():
        raise ValueError('native host acceptance requires its exact regular compiled binary')
    if not Path('/dev/kvm').exists() or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise ValueError('real native host acceptance requires accessible KVM; no simulated success fallback')
    baseline = json.loads((FIXTURES / 'baseline.json').read_text())
    if args.cookbook_source is None or args.tools_source is None:
        raise ValueError('native capture requires the selected immutable Cookbook and Tools source directories')
    spec=importlib.util.spec_from_file_location('native_recovery_sources',ROOT/'tests/support/native_host_recovery.py')
    recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery)
    sources=recovery.Sources(ROOT,args.cookbook_source,args.tools_source,source=os.environ.get('NATIVE_HOST_SOURCE',''),
        repository_id=os.environ.get('GITHUB_REPOSITORY_ID',''),tools_revision=baseline['proxy_tools_revision'])
    caddy=args.proxy_binary.absolute();proxy_receipt=args.proxy_receipt.absolute()
    for path,maximum in [(caddy,128<<20),(proxy_receipt,16384)]:
        if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=maximum:raise ValueError('native host requires exact ordinary proxy outputs')
    proxy_build=json.loads(proxy_receipt.read_bytes())
    expected_keys={'kind','version','tools_revision','platform','go_version','caddy_version','source_sha256','binary_sha256'}
    if (set(proxy_build)!=expected_keys or proxy_build['kind']!='komizo.proxy-build' or type(proxy_build['version']) is not int or proxy_build['version']!=1
            or proxy_build['tools_revision']!=baseline['proxy_tools_revision'] or proxy_build['platform']!='linux/amd64'
            or proxy_build['go_version']!=baseline['proxy_go_version'] or proxy_build['caddy_version']!=baseline['caddy_version']
            or proxy_build['source_sha256']!=baseline['proxy_source_sha256']
            or proxy_build['binary_sha256']!='sha256:'+hashlib.sha256(caddy.read_bytes()).hexdigest()):
        raise ValueError('native proxy bytes differ from their reviewed source receipt')
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    with OwnedDirectory(args.output) as disposable:
        directory = disposable.path
        owner = key(directory, 'owner')
        submit = key(directory, 'submission')
        host = key(directory, 'host')
        base = directory / 'base.qcow2'
        print('Downloading and authenticating the signed pinned Alpine cloud image',flush=True)
        download(baseline['cloud_image'], base)
        authenticate_image(baseline['cloud_image'], base, directory)
        recovery_key=directory/'recipient.key';recipient=directory/'recipient.crt'
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(recovery_key),
            '-out',str(recipient),'-days','2','-subj','/CN=disposable-native-owner'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        recovery_key.chmod(0o600)
        capture_bundle=sources.bundle(directory,recipient)
        profile=directory/'profile.json';profile.write_text(json.dumps(sources.profile(args.profile)))
        user_data = {**fixture_cloud_options(),
            'users': [fixture_root_user(owner.with_suffix('.pub').read_text().strip())],
            'ssh_keys': {'ed25519_private': host.read_text(), 'ed25519_public': host.with_suffix('.pub').read_text().strip()},
            'runcmd': [['sh', '-ec',
                'exec > /dev/ttyS0 2>&1; '
                'install -d -m 700 /root/native-host /root/native-host/apk-cache; '
                'printf "%s\\n" https://dl-cdn.alpinelinux.org/alpine/v3.24/main https://dl-cdn.alpinelinux.org/alpine/v3.24/community > /etc/apk/repositories; '
                'apk update; apk fetch --recursive --output /root/native-host/apk-cache ' +
                ' '.join(shlex.quote(p) for p in baseline['native_packages']) + '; '
                'cp -a /etc/apk/keys /root/native-host/apk-cache/keys; '
                'cp /etc/apk/repositories /root/native-host/apk-cache/repositories; '
                'cp /var/cache/apk/APKINDEX.* /root/native-host/apk-cache/; '
                'apk add --no-network /root/native-host/apk-cache/*.apk; '
                'apk info -vv > /root/native-host/apk-cache/installed.txt; '
                'cd /root/native-host/apk-cache; sha256sum *.apk > SHA256SUMS; '
                'tar -cf /root/native-host/alpine-packages.tar .; '
                'touch /root/native-host/cloud-ready']]}

        config = directory / 'user-data'
        config.write_text('#cloud-config\n' + json.dumps(user_data))
        config.chmod(0o600)
        metadata = directory / 'meta-data'
        metadata.write_text(json.dumps({'instance-id': 'komizo-native-acceptance', 'local-hostname': 'native-host'}))
        seed = directory / 'seed.iso'
        run(['cloud-localds', str(seed), str(config), str(metadata)])
        overlay = directory / 'guest.qcow2'
        run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(overlay), '16G'])
        ssh_port = port()
        guest = Guest(directory, owner, host.with_suffix('.pub'), ssh_port)
        console = args.output / 'console.log'
        with console.open('wb') as log:
            # The signed Limine cloud image boots the owned disk directly.
            owner_pid=os.getpid()
            process = subprocess.Popen(['qemu-system-x86_64', '-no-user-config', '-display', 'none',
                '-machine', 'q35,accel=kvm', '-cpu', 'host', '-m', '1024' if args.profile=='bounded' else '2048', '-smp', '1' if args.profile=='bounded' else '2',
                '-drive', 'file=' + str(overlay) + ',if=virtio,format=qcow2',
                '-drive', 'file=' + str(seed) + ',if=virtio,format=raw,readonly=on',
                '-netdev', 'user,id=net0,hostfwd=tcp:127.0.0.1:' + str(ssh_port) + '-:22',
                '-device', 'virtio-net-pci,netdev=net0', '-serial', 'stdio', '-monitor', 'none',
                '-device', 'virtio-rng-pci'], stdout=log, stderr=log, start_new_session=True,preexec_fn=lambda:parent_lifetime(owner_pid))
            disposable.process=process
            try:
                print('Booting the disposable guest and waiting for its bounded cloud setup',flush=True)
                guest.ready(process, time.monotonic() + 600, evidence=args.output/'initial-ssh.json')
                guest.copy(ROOT/'tests/support/native_host_alpine.py', '/root/native-host/alpine-boot.py')
                guest.command('mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security')
                guest.command('python3 -I -B /root/native-host/alpine-boot.py', timeout=30)
                initial_boot = guest.command('cat /proc/sys/kernel/random/boot_id', capture_output=True).stdout.strip()
                guest.command('reboot', timeout=15, check=False)
                time.sleep(3)
                guest.ready(process, time.monotonic() + 240)
                if guest.command('cat /proc/sys/kernel/random/boot_id', capture_output=True).stdout.strip() == initial_boot:
                    raise ValueError('AppArmor setup did not actually reboot the disposable guest')
                guest.command('test "$(cat /sys/module/apparmor/parameters/enabled)" = Y && grep -qw apparmor /sys/kernel/security/lsm && rc-service apparmor status')
                package_size = int(guest.command('stat -c %s /root/native-host/alpine-packages.tar', capture_output=True).stdout)
                if not 0 < package_size <= 512 << 20:
                    raise ValueError('public signed APK closure exceeds its finite bound')
                guest.fetch('/root/native-host/alpine-packages.tar', args.output/'alpine-packages.tar')
                archive = args.output/'alpine-packages.tar'
                if archive.stat().st_size != package_size:
                    raise ValueError('public APK closure copy is incomplete')
                (args.output/'alpine-packages.json').write_text(json.dumps({'kind':'komizo.alpine-public-package-closure','version':1,
                    'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'size_bytes':package_size,'image':baseline['cloud_image'],
                    'requested_packages':baseline['native_packages'],'signature_verification':'apk add --no-network with trusted distro keys',
                    'production_host_packages_changed':False},sort_keys=True)+'\n')
                setup_started=time.monotonic()
                print('Guest setup completed; installing the exact compiled native controller',flush=True)
                guest.copy(binary, '/usr/local/bin/komizo-box')
                binary_sha=hashlib.sha256(binary.read_bytes()).hexdigest()
                if guest.command('sha256sum /usr/local/bin/komizo-box',capture_output=True).stdout.decode().split()[0]!=binary_sha:
                    raise ValueError('guest native binary differs from the exact compiled source artifact')
                guest.copy(caddy, '/usr/local/bin/caddy')
                guest.command('install -d -m 755 /etc/komizo-proxy')
                guest.copy(proxy_receipt,'/etc/komizo-proxy/binary.json')
                guest.command('chmod 644 /etc/komizo-proxy/binary.json')
                guest.copy(submit.with_suffix('.pub'), '/root/native-host/submission.pub')
                guest.copy(recipient, '/root/native-host/recipient.crt')
                guest.copy(capture_bundle,'/root/native-host/capture-pgbox.bundle')
                if guest.command('sha256sum /root/native-host/capture-pgbox.bundle',capture_output=True).stdout.decode().split()[0]!=hashlib.sha256(capture_bundle.read_bytes()).hexdigest():
                    raise ValueError('guest backup program differs from its exact source/provider bundle')
                guest.command('chmod 700 /root/native-host/capture-pgbox.bundle; install -d -m 700 /root/native-host/recovery')
                for name,body in sources.helpers.items():
                    path=directory/name;path.write_bytes(body);path.chmod(0o400)
                    guest.copy(path,'/root/native-host/recovery/'+name)
                guest.command('chmod 400 /root/native-host/recovery/*.py; chmod 500 /root/native-host/recovery')
                guest.copy(profile,'/root/native-host/profile.json')
                guest.copy(ROOT / 'tests/support/native_host_acceptance.py', '/root/native-host/acceptance.py')
                guest.copy(ROOT / 'tests/support/native_host_fixture.py', '/root/native-host/fixture_tasks.py')
                guest.copy(ROOT / 'tests/support/native_host_runtime.py', '/root/native-host/fixture_runtime.py')
                guest.copy(ROOT / 'tests/support/native_host_job_preparation.py', '/root/native-host/fixture_job_preparation.py')
                guest.copy(ROOT / 'tests/support/native_host_registry.py', '/root/native-host/fixture_registry.py')
                guest.copy(ROOT / 'tests/support/native_host_secrets.py', '/root/native-host/fixture_secrets.py')
                guest.copy(ROOT / 'tests/support/native_host_backup.py', '/root/native-host/fixture_backup.py')
                guest.copy(ROOT / 'tests/support/native_host_postgres.py', '/root/native-host/fixture_postgres.py')
                guest.copy(ROOT / 'tests/support/native_host_preview.py', '/root/native-host/fixture_preview.py')
                guest.copy(ROOT / 'tests/support/native_host_performance.py','/root/native-host/fixture_performance.py')
                guest.copy(FIXTURES / 'baseline.json', '/root/native-host/baseline.json')
                print('Running native bootstrap and authority boundaries',flush=True)
                guest.command('chmod 755 /usr/local /usr/local/bin /usr/local/bin/komizo-box /usr/local/bin/caddy; chmod 600 /root/native-host/submission.pub; python3 /root/native-host/acceptance.py bootstrap', timeout=300)
                setup_seconds=time.monotonic()-setup_started
                guest.submission_boundary(submit)
                print('Running exact native workload effects and protected recovery fixtures',flush=True)
                guest.command('python3 /root/native-host/acceptance.py runtime', timeout=600)
                owner_checks=owner_recovery(guest,directory,recovery_key,sources)
                (args.output / 'owner-recovery.json').write_text(json.dumps({'version': 1,
                    'source': {'revision': os.environ.get('NATIVE_HOST_SOURCE'), 'binary_sha256': binary_sha},
                    'checks': owner_checks}, sort_keys=True) + '\n')
                if args.profile=='bounded':
                    measured,onboarding=performance(guest,directory,args.cli.absolute(),setup_seconds)
                    (args.output/'performance.json').write_text(json.dumps(measured,sort_keys=True)+'\n')
                    (args.output/'onboarding.json').write_text(json.dumps(onboarding,sort_keys=True)+'\n')
                before = guest.command('cat /proc/sys/kernel/random/boot_id', capture_output=True).stdout.strip()
                print('Rebooting the real guest with the artifact registry offline',flush=True)
                guest.command('reboot', timeout=15, check=False)
                time.sleep(3)
                guest.ready(process, time.monotonic() + 240)
                after = guest.command('cat /proc/sys/kernel/random/boot_id', capture_output=True).stdout.strip()
                if not before or before == after:
                    raise ValueError('native host acceptance did not observe a real guest reboot')
                guest.command('python3 /root/native-host/acceptance.py verify-reboot', timeout=180)
                result = guest.command('cat /root/native-host/report.json', capture_output=True).stdout
                (args.output / 'report.json').write_bytes(result)
                accepted = json.loads(result)
                accepted['source']={'revision':os.environ.get('NATIVE_HOST_SOURCE'),'binary_sha256':binary_sha}
                accepted['proxy_build']=proxy_build
                accepted['checks']['ssh_forced_submission'] = 'passed'
                accepted['checks']['ssh_forwarding_refused'] = 'passed'
                accepted['checks'].update(owner_checks)
                if args.profile=='bounded':
                    accepted['checks']['fixed_budget_performance']='passed';accepted['remaining']=[]
                (args.output / 'report.json').write_text(json.dumps(accepted,sort_keys=True)+'\n')
                if not accepted.get('ok'):
                    raise ValueError('native guest acceptance failed')
            finally:
                failed=sys.exc_info()[0] is not None
                failure_evidence=None;failure_journal=None
                if process.poll() is None:
                    try:
                        (args.output / 'boot.json').write_bytes(guest.boot_diagnostics())
                    except (OSError, subprocess.SubprocessError):
                        pass
                    try:
                        guest.command("dmesg | tail -c 65536 > /root/native-host/journal.log", timeout=20)
                        evidence = guest.command('cat /root/native-host/journal.log', timeout=20, capture_output=True).stdout
                        failure_journal=evidence
                        (args.output / 'journal.log').write_bytes(evidence)
                        status=guest.command('/usr/local/bin/komizo-box status',timeout=30,capture_output=True,check=False)
                        if status.returncode==0:(args.output/'status.json').write_bytes(status.stdout)
                        else:(args.output/'status-error.json').write_text(json.dumps({'code':status.returncode,'stderr':status.stderr.decode(errors='replace')[:2048]},sort_keys=True)+'\n')
                        runtime_evidence=guest.command('python3 /root/native-host/acceptance.py evidence',timeout=15,capture_output=True).stdout
                        failure_evidence=runtime_evidence
                        (args.output/'runtime-evidence.json').write_bytes(runtime_evidence)
                        if not (args.output/'report.json').exists():
                            report=guest.command('cat /root/native-host/report.json',timeout=10,capture_output=True).stdout
                            partial=json.loads(report);partial['source']={'revision':os.environ.get('NATIVE_HOST_SOURCE'),'binary_sha256':binary_sha}
                            (args.output/'report.json').write_text(json.dumps(partial,sort_keys=True)+'\n')
                    except (OSError, subprocess.SubprocessError):
                        pass
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                emit_native_failure(failed,failure_evidence,failure_journal,args.profile,
                    os.environ.get('NATIVE_HOST_SOURCE'),locals().get('binary_sha'))


if __name__ == '__main__':
    main()
