"""Protected, recoverable platform operations. Invoked by komizo-box as root.

The staging manifest is an operator grant: its protected receipt binds the
artifact already authenticated by the release preparer. It is not independent
review and never claims to constrain root. No project code or shell is executed.
"""
import contextlib
import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse

SHA = re.compile(r'[a-f0-9]{64}\Z')
REV = re.compile(r'[a-f0-9]{40}\Z')
APP = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,99}\Z')
SERVICES = ('komizo-rootd', 'komizo-api', 'komizo-agent')
TERMINAL = ('ready', 'prepared_stopped', 'reconciled')
STATIC_MOUNT = {'type': 'bind', 'source': '/srv/_public', 'target': '/srv/public',
                'read_only': True, 'bind': {'create_host_path': False}}
CONTROL_SERVICES = ('docker', 'komizo-rootd', 'komizo-api')
CONTROL_BEGIN = b'# BEGIN KOMIZO OPENRC CONTROL\n'
CONTROL_END = b'# END KOMIZO OPENRC CONTROL\n'


def control_configuration(before, policy, service):
    """Preserve caller configuration and replace only the managed limit block."""
    if service not in CONTROL_SERVICES or set(policy.get('controls', {})) != {'openrc.'+name for name in CONTROL_SERVICES}:
        raise ValueError('declared fixed control policy required')
    group=policy['controls']['openrc.'+service]
    fields={'memory.low':'memory_low_bytes','memory.high':'memory_high_bytes','memory.max':'memory_bytes',
            'memory.swap.max':'swap_bytes','pids.max':'pids','cpu.weight':'cpu_weight'}
    if any(type(group.get(field)) is not int or group[field]<0 for field in fields.values()) or group.get('milli_cpus')!=0:
        raise ValueError('invalid control settings')
    if before.count(CONTROL_BEGIN)!=before.count(CONTROL_END) or before.count(CONTROL_BEGIN)>1:
        raise ValueError('ambiguous managed control configuration')
    if CONTROL_BEGIN in before:
        start=before.index(CONTROL_BEGIN);end_start=before.index(CONTROL_END)
        if end_start<=start:raise ValueError('invalid managed control block')
        end=end_start+len(CONTROL_END)
        outside=before[:start]+before[end:]
    else:outside=before
    if re.search(rb'\brc_cgroup_settings\b',outside):raise ValueError('foreign control settings require explicit migration')
    settings='\n'.join(key+' '+str(group[field]) for key,field in fields.items())+'\ncpu.max max 100000\n'
    block=CONTROL_BEGIN+('rc_cgroup_settings=\''+settings+'\'\n').encode()+CONTROL_END
    if CONTROL_BEGIN in before:return before[:start]+block+before[end:]
    return before+(b'\n' if before and not before.endswith(b'\n') else b'')+block


class Platform:
    def __init__(self, root=Path('/'), run=None, owner=0, checkpoint=None):
        self.root, self.owner = Path(root), owner
        self.run = run or self.command
        self.checkpoint = checkpoint or (lambda phase: None)

    def path(self, absolute):
        return self.root / absolute.lstrip('/')

    def protected(self, path, private=False, directory=False):
        path = Path(path)
        for parent in [path, *path.parents]:
            info = parent.lstat()
            if info.st_uid != self.owner or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
                raise ValueError('platform path is not protected')
            if parent == self.root:
                break
        info = path.lstat()
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('platform parent must be a protected directory')
        elif not stat.S_ISREG(info.st_mode) or private and info.st_mode & 0o077:
            raise ValueError('platform input must be a protected regular file')
        return info

    def agent_configuration(self):
        # Default public installations do not require the optional operator
        # configuration. Bind its absence as carefully as its existing bytes.
        path=self.path('/etc/komizo/agent.json')
        try:
            return self.digest(path)
        except FileNotFoundError:
            self.protected(path.parent, directory=True)
            return None

    def read(self, path, maximum=65536, private=False):
        self.protected(path, private)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
                raise ValueError('platform input exceeds its type or byte bound')
            body = stream.read(maximum+1)
            if len(body) > maximum:
                raise ValueError('platform input exceeds its byte bound')
            return body

    def digest(self, path):
        info = self.protected(path)
        if info.st_size > 64*1024*1024:
            raise ValueError('platform file exceeds its byte bound')
        h = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            for block in iter(lambda: stream.read(65536), b''):
                h.update(block)
        return h.hexdigest()

    def identity(self, path):
        try:
            info = self.protected(path)
        except FileNotFoundError:
            self.protected(Path(path).parent, directory=True)
            return None, None
        return self.digest(path), stat.S_IMODE(info.st_mode)

    def authority_mode(self, destination):
        if destination in ('/etc/doas.conf', '/etc/komizo/resources.json', *('/etc/conf.d/'+name for name in CONTROL_SERVICES)):
            return 0o600
        patterns = ((r'/etc/komizo/workloads/([a-z][a-z0-9_-]{0,62})\.json', 0o600),
                    (r'/var/lib/komizo/tasks/([a-z][a-z0-9_-]{0,62})\.sh', 0o700),
                    (r'/usr/local/bin/(?:deploy|task|set-secret|set-release-secrets|export-backup)-([a-z][a-z0-9_-]{0,62})', 0o755))
        for pattern, mode in patterns:
            match = re.fullmatch(pattern, destination)
            if match:
                # The public registrar writes root-owned 0640 roster metadata.
                # It is authority by ownership and non-writability, not secrecy.
                self.protected(self.path('/var/lib/komizo/apps/'+match[1]+'.env'))
                return mode
        raise ValueError('workload migration path is outside the registered authority')

    def atomic(self, destination, source, mode):
        self.identity(destination)
        fd, temporary = tempfile.mkstemp(prefix='.komizo-platform-', dir=destination.parent)
        try:
            with os.fdopen(fd, 'wb') as out, open(source, 'rb') as incoming:
                shutil.copyfileobj(incoming, out, 65536)
                os.fchmod(out.fileno(), mode)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, destination)
            self.sync(destination.parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def sync(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def journal(self, stage, value):
        target = stage/'operation.json'
        fd, temporary = tempfile.mkstemp(prefix='.journal-', dir=stage)
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out, sort_keys=True)
            out.flush()
            os.fchmod(out.fileno(), 0o600)
            os.fsync(out.fileno())
        os.replace(temporary, target)
        self.sync(stage)

    def command(self, args, required=True, timeout=90):
        # Fixed executable, cwd, environment and output bound; no user shell.
        if type(timeout) is not int or not 1 <= timeout <= 900:
            raise ValueError('invalid platform command deadline')
        executables = {'rc-service': '/sbin/rc-service', 'docker': '/usr/bin/docker',
                       'komizo-box': '/usr/local/bin/komizo-box', 'doas': '/usr/bin/doas', 'busybox': '/bin/busybox',
                       'apk': '/sbin/apk', 'nft': '/usr/sbin/nft', 'uname': '/bin/uname', 'reboot': '/sbin/reboot'}
        executable = self.path(executables[args[0]])
        self.protected(executable)
        body = bytearray()
        process = subprocess.Popen([str(executable), *args[1:]], cwd='/',
                env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/root', 'LC_ALL': 'C'},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                start_new_session=True)
        end = time.monotonic()+timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = end-time.monotonic()
                    if remaining <= 0:
                        raise ValueError('platform command deadline exceeded')
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, min(65536, 1024*1024+1-len(body)))
                        if not chunk:
                            selector.unregister(key.fileobj)
                        body.extend(chunk)
                        if len(body) > 1024*1024:
                            raise ValueError('platform command output exceeds its bound')
            process.wait(timeout=max(.001, end-time.monotonic()))
            if required and process.returncode:
                raise ValueError('platform command refused')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            process.stdout.close()
        return process.returncode, body.decode()

    @contextlib.contextmanager
    def locks(self):
        apps = sorted(p.stem for p in self.path('/var/lib/komizo/apps').glob('*.env'))
        if len(apps) > 64 or any(not APP.fullmatch(a) for a in apps):
            raise ValueError('invalid protected platform roster')
        descriptors = []
        try:
            for name in [*(f'deploy-{a}.lock' for a in apps), 'operation.lock']:
                path = self.path('/run/komizo')/name
                fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                descriptors.append(fd)
                self.protected(path, True)
                end = time.monotonic()+30
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= end:
                            raise ValueError('platform queue deadline exceeded')
                        time.sleep(.05)
            if self.path('/var/lib/komizo/activations/pending.json').exists():
                raise ValueError('activation is pending')
            for path in self.path('/var/lib/komizo/releases').glob('*/operation.json'):
                op = json.loads(self.read(path, private=True))
                if op.get('version') != 1 or op.get('phase') not in TERMINAL:
                    raise ValueError('deployment fence requires reconciliation')
            yield
        finally:
            for fd in reversed(descriptors):
                os.close(fd)

    def manifest(self, stage, expected):
        body = self.read(stage/'manifest.json', private=True)
        if hashlib.sha256(body).hexdigest() != expected:
            raise ValueError('reviewed platform manifest changed')
        value = json.loads(body)
        required={'version', 'kind', 'source', 'release', 'files', 'receipt_sha256', 'image', 'probes'}
        if (not required <= set(value) or set(value)-required-{'resource_budget', 'static_mount'}
                or value['version'] != 1 or value['kind'] not in ('self-upgrade', 'proxy-upgrade', 'workload-authority')
                or not REV.fullmatch(value['source']) or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', value['release'])
                or not SHA.fullmatch(value['receipt_sha256']) or not 1 <= len(value['files']) <= 131):
            raise ValueError('invalid platform grant')
        receipt = json.loads(self.read(stage/'verified-release.json', private=True))
        if (self.digest(stage/'verified-release.json') != value['receipt_sha256']
                or receipt.get('version') != 1 or receipt.get('source') != value['source']
                or receipt.get('authenticated') is not True or receipt.get('kind') != value['kind']
                or receipt.get('files') != value['files'] or receipt.get('image') != value['image']):
            raise ValueError('protected release authentication receipt differs')
        if 'resource_budget' in value:
            if value['kind']!='proxy-upgrade' or receipt.get('resource_budget')!=value['resource_budget']:
                raise ValueError('proxy resources differ from protected receipt')
            self.check_resource_budget(value)
        if 'static_mount' in value:
            if (value['kind'] != 'proxy-upgrade' or value['static_mount'] != STATIC_MOUNT
                    or receipt.get('static_mount') != STATIC_MOUNT):
                raise ValueError('static mount differs from the protected receipt')
            self.protected(self.path('/srv/_public'), directory=True)
        paths = set()
        for row in value['files']:
            authority = value['kind'] == 'workload-authority'
            fields = {'path', 'staged', 'before', 'after', 'mode'} | ({'before_mode'} if authority else set())
            if set(row) != fields:
                raise ValueError('invalid platform file grant')
            destination = row['path']
            if authority:
                if (row['mode'] != self.authority_mode(destination)
                        or type(row['mode']) is not int
                        or (row['before'] is None) != (row['before_mode'] is None)
                        or row['before_mode'] is not None and (type(row['before_mode']) is not int or row['before_mode'] & 0o022 or not 0 <= row['before_mode'] <= 0o777)):
                    raise ValueError('invalid workload migration permissions')
            permitted = destination in ('/usr/local/bin/komizo', '/usr/local/bin/komizo-box', '/var/lib/komizo/version')
            for prefix in ('/usr/local/bin/deploy-', '/usr/local/bin/task-'):
                if destination.startswith(prefix):
                    app = destination.removeprefix(prefix)
                    permitted = bool(APP.fullmatch(app) and self.path(f'/var/lib/komizo/apps/{app}.env').exists())
                    if prefix.endswith('task-'):
                        permitted = permitted and self.path(f'/var/lib/komizo/tasks/{app}.sh').exists()
            if value['kind'] == 'proxy-upgrade':
                permitted = destination in ('/srv/_proxy/compose.yml','/srv/_proxy/Caddyfile')
            if authority:
                permitted = True
            if (not permitted or destination in paths or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', row['staged'])
                    or not (authority and row['before'] is None or isinstance(row['before'], str) and SHA.fullmatch(row['before']))
                    or not SHA.fullmatch(row['after']) or not authority and row['mode'] not in (0o644, 0o755)):
                raise ValueError('platform file is outside its declared authority')
            paths.add(destination)
            if self.digest(stage/row['staged']) != row['after']:
                raise ValueError('staged platform bytes differ')
        if value['kind'] == 'self-upgrade':
            if '/usr/local/bin/komizo-box' not in paths or '/var/lib/komizo/version' not in paths or value['image'] is not None or value['probes']:
                raise ValueError('self-upgrade requires its binary and version')
        elif value['kind'] == 'workload-authority':
            if value['image'] is not None or value['probes']:
                raise ValueError('workload authority migration cannot activate containers or routes')
        elif (not 1 <= len(paths) <= 2 or '/srv/_proxy/compose.yml' not in paths or not isinstance(value['image'], dict)
                or set(value['image']) != {'reference', 'id', 'previous_id'}
                or not re.fullmatch(r'ghcr.io/nicodes/platform-proxy@sha256:[a-f0-9]{64}', value['image']['reference'])
                or any(not re.fullmatch(r'sha256:[a-f0-9]{64}', value['image'][key]) for key in ('id', 'previous_id'))
                or not 1 <= len(value['probes']) <= 64):
            raise ValueError('proxy grant requires exact image and route probes')
        for probe in value['probes']:
            if (set(probe) not in ({'url', 'revision'}, {'url','revision','status','location'}) or not re.fullmatch(r'(?:https|wss)://[A-Za-z0-9.-]+/[A-Za-z0-9/_.-]*', probe['url'])
                    or not REV.fullmatch(probe['revision'])):
                raise ValueError('invalid platform readiness probe')
            if 'status' in probe:
                target=urllib.parse.urlsplit(probe['location'])
                hosts={urllib.parse.urlsplit(row['url']).hostname for row in value['probes']}
                if (not probe['url'].startswith('https://') or type(probe['status']) is not int
                        or probe['status'] not in (301,302,303,307,308) or target.scheme != 'https'
                        or target.hostname not in hosts or target.username or target.password
                        or target.port not in (None,443) or target.query or target.fragment or not target.path.startswith('/')):
                    raise ValueError('invalid explicit redirect readiness contract')
        return value

    def authority_preflight(self, stage, value):
        resource=next((stage/row['staged'] for row in value['files'] if row['path']=='/etc/komizo/resources.json'),None)
        controls=[row for row in value['files'] if row['path'] in ('/etc/conf.d/'+name for name in CONTROL_SERVICES)]
        if controls:
            if resource is None or len(controls)!=3:raise ValueError('control configuration binds all three services and the exact resource policy')
            policy=json.loads(self.read(resource,private=True,maximum=1<<20))
            for row in controls:
                path=self.path(row['path']);before=self.read(path,maximum=65536) if path.exists() else b''
                expected=control_configuration(before,policy,Path(row['path']).name)
                if self.read(stage/row['staged'],private=True,maximum=65536)!=expected:raise ValueError('control candidate changes foreign configuration or differs from policy')
        for row in value['files']:
            candidate = stage/row['staged']
            if row['path'].startswith('/etc/komizo/workloads/'):
                document = json.loads(self.read(candidate, private=True, maximum=1<<20))
                if document.get('app') != Path(row['path']).stem:
                    raise ValueError('workload policy names a different app')
                self.run(['komizo-box', 'workload', 'policy-check', '--policy', str(candidate)])
            elif row['path'] == '/etc/komizo/resources.json':
                if row['before'] is None:
                    raise ValueError('resource migration requires an existing protected policy')
                self.run(['komizo-box', 'workload', 'host-resources', '--check', '--policy', str(candidate), '--check-usage'])
            elif row['path'] == '/etc/doas.conf':
                self.run(['doas', '-C', str(candidate)])
            else:
                self.run(['busybox', 'sh', '-n', str(candidate)])

    def compose(self, file, *args):
        return self.run(['docker', 'compose', '--project-name', 'komizo-proxy', '--project-directory', '/srv/_proxy', '--file', str(file), *args])

    def proxy_preflight(self, stage, value):
        old = self.path('/srv/_proxy/compose.yml')
        compose_row = next(row for row in value['files'] if row['path'] == '/srv/_proxy/compose.yml')
        candidate = stage/compose_row['staged']
        old_doc = json.loads(self.compose(old, 'config', '--format', 'json')[1])
        new_doc = json.loads(self.compose(candidate, 'config', '--format', 'json')[1])
        if set(old_doc.get('services', {})) != {'komizo-proxy'} or set(new_doc.get('services', {})) != {'komizo-proxy'}:
            raise ValueError('proxy update requires one existing proxy service')
        image = new_doc['services']['komizo-proxy'].pop('image', None)
        old_doc['services']['komizo-proxy'].pop('image', None)
        if 'static_mount' in value:
            self.protected(self.path('/srv/_public'), directory=True)
            for document, required in ((new_doc, True), (old_doc, False)):
                volumes = document['services']['komizo-proxy'].get('volumes', [])
                if not isinstance(volumes, list) or any(not isinstance(row, dict) for row in volumes):
                    raise ValueError('static mount requires normalized explicit mounts')
                matches = [row for row in volumes if row.get('target') == '/srv/public']
                implicit = {**STATIC_MOUNT, 'bind': {'create_host_path': True}}
                normalized = {**STATIC_MOUNT, 'bind': {}}
                if (required and matches not in ([STATIC_MOUNT], [normalized])) or (matches and matches not in ([STATIC_MOUNT], [implicit], [normalized])):
                    raise ValueError('static mount differs from the fixed read-only public tree')
                if matches:
                    volumes.remove(matches[0])
        if 'resource_budget' in value:
            budget=value['resource_budget']
            fields={'mem_limit':budget['memory_bytes'],'memswap_limit':budget['total_memory_swap_bytes'],
                    'cpus':budget['milli_cpus']/1000,'pids_limit':budget['pids'],
                    'cgroup_parent':budget['cgroup_parent']}
            for field,wanted in fields.items():
                actual=new_doc['services']['komizo-proxy'].pop(field,'' if field=='cgroup_parent' else None)
                memory_decimal=(field in ('mem_limit','memswap_limit') and type(actual) is str and actual==str(wanted))
                if type(actual) is bool or (actual!=wanted and not memory_decimal):
                    raise ValueError('candidate proxy resources differ from the protected budget')
                old_doc['services']['komizo-proxy'].pop(field,None)
        if image != value['image']['reference'] or old_doc != new_doc:
            raise ValueError('proxy update may change only its image')
        identity = self.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image])[1].strip()
        if identity != value['image']['id']:
            raise ValueError('authenticated local proxy image missing')
        old_identity = self.run(['docker', 'inspect', '--format', '{{.Image}}', 'komizo-proxy'])[1].strip()
        if old_identity != value['image']['previous_id']:
            raise ValueError('running proxy changed after review')
        config_row = next((row for row in value['files'] if row['path'] == '/srv/_proxy/Caddyfile'), None)
        if config_row:
            # Override exactly the existing Caddyfile mount for preflight. The
            # installed Compose remains unchanged except for its reviewed image.
            definition = json.loads(self.compose(candidate, 'config', '--format', 'json')[1])
            volumes = definition['services']['komizo-proxy'].get('volumes', [])
            matches = [volume for volume in volumes if volume.get('target') == '/etc/caddy/Caddyfile']
            if len(matches) != 1 or matches[0].get('type') != 'bind' or matches[0].get('source') != '/srv/_proxy/Caddyfile' or matches[0].get('read_only') is not True:
                raise ValueError('proxy configuration mount differs from its protected contract')
            matches[0]['source'] = str(stage/config_row['staged'])
            preflight = stage/'proxy-preflight.json'
            if preflight.exists():
                raise ValueError('proxy preflight already exists; use a fresh stage')
            with open(preflight, 'x') as stream:
                json.dump(definition, stream)
                os.fchmod(stream.fileno(), 0o600)
            candidate = preflight
        self.compose(candidate, 'run', '--rm', '--no-deps', '--pull', 'never', '--entrypoint', '/usr/bin/caddy', 'komizo-proxy', 'validate', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile')

    def verify_proxy(self, value, deadline_seconds=30):
        identity = self.run(['docker', 'inspect', '--format', '{{.Image}}', 'komizo-proxy'])[1].strip()
        if identity != value['image']['id']:
            raise ValueError('installed proxy identity differs')
        if 'static_mount' in value:
            self.protected(self.path('/srv/_public'), directory=True)
            mounts = json.loads(self.run(['docker', 'inspect', '--format', '{{json .Mounts}}', 'komizo-proxy'])[1])
            matches = [row for row in mounts if row.get('Destination') == '/srv/public']
            if (len(matches) != 1 or matches[0].get('Type') != 'bind'
                    or matches[0].get('Source') != '/srv/_public' or matches[0].get('RW') is not False):
                raise ValueError('installed public tree is not the fixed read-only mount')
        # Compose has created the process; its listener may still be starting.
        # One deadline covers the complete route set, never a deadline per URL.
        end = time.monotonic()+deadline_seconds
        pending = list(value['probes'])
        while pending:
            for probe in list(pending):
                remaining = end-time.monotonic()
                if remaining <= 0:
                    raise ValueError('installed proxy route acceptance deadline exceeded')
                try:
                    if self.probe_route(probe,min(3,remaining)):
                        pending.remove(probe)
                except (OSError, TimeoutError):
                    pass
            if pending:
                time.sleep(min(.1,max(0,end-time.monotonic())))

    @staticmethod
    def probe_route(probe, timeout):
        if probe['url'].startswith('wss://'):
            parsed=urllib.parse.urlsplit(probe['url'])
            key=base64.b64encode(os.urandom(16)).decode()
            expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            connection=http.client.HTTPSConnection(parsed.hostname,timeout=timeout)
            try:
                connection.request('GET',parsed.path+('?' + parsed.query if parsed.query else ''),headers={
                    'Connection':'Upgrade','Upgrade':'websocket','Sec-WebSocket-Version':'13','Sec-WebSocket-Key':key})
                response=connection.getresponse()
                return (response.status==101 and response.getheader('X-Komizo-Revision')==probe['revision']
                        and response.getheader('Upgrade','').lower()=='websocket'
                        and response.getheader('Sec-WebSocket-Accept')==expected)
            finally:
                connection.close()
        parsed=urllib.parse.urlsplit(probe['url'])
        connection=http.client.HTTPSConnection(parsed.hostname,timeout=timeout)
        try:
            connection.request('GET',parsed.path,headers={'Cache-Control':'no-cache'})
            response=connection.getresponse()
            if 'status' in probe:
                return (response.status==probe['status'] and response.getheader('Location')==probe['location']
                        and response.getheader('X-Komizo-Revision')==probe['revision'])
            return (response.status==200 and response.getheader('X-Komizo-Revision')==probe['revision']
                    and bool(response.read(512).strip()))
        finally:
            connection.close()

    def check_resource_budget(self, value, installed=False):
        budget=value.get('resource_budget')
        if budget is None:return
        status,body=self.run(['komizo-box','workload','proxy-budget'])
        if status or json.loads(body)!=budget:
            raise ValueError('protected proxy resources changed; operation refused')
        if installed:
            status,body=self.run(['docker','inspect','--format','{{json .HostConfig}}','komizo-proxy'])
            actual=json.loads(body)
            expected={'Memory':budget['memory_bytes'],'MemorySwap':budget['total_memory_swap_bytes'],
                      'NanoCpus':budget['milli_cpus']*1000000,'PidsLimit':budget['pids'],'CgroupParent':budget['cgroup_parent']}
            if status or any(actual.get(name)!=wanted for name,wanted in expected.items()):
                raise ValueError('running proxy has not adopted the declared resource group and limits')

    def apply(self, stage, expected, recover=False):
        stage = Path(stage)
        if stage.parent != self.path('/var/lib/komizo/upgrades') or not re.fullmatch(r'[a-zA-Z0-9_-]{1,100}', stage.name):
            raise ValueError('platform stage must be in the protected upgrade directory')
        value = self.manifest(stage, expected)
        with self.locks():
            self.check_resource_budget(value)
            journal = stage/'operation.json'
            pending = self.path('/var/lib/komizo/upgrades/pending.json')
            if pending.exists():
                grant = json.loads(self.read(pending, private=True))
                if grant != {'stage': stage.name, 'manifest': expected}:
                    raise ValueError('another platform operation requires recovery')
            if recover:
                record = json.loads(self.read(journal, private=True))
                if record.get('manifest') != expected or record.get('phase') not in ('prepared', 'installing', 'recovering', 'complete', 'recovered'):
                    raise ValueError('platform recovery identity differs')
                if record['phase'] in ('complete', 'recovered'):
                    side = 'after' if record['phase'] == 'complete' else 'before'
                    if any(self.identity(self.path(row['path']))[0] != row[side] for row in value['files']):
                        raise ValueError('completed platform identity changed; fence retained')
                    if value['kind'] == 'workload-authority' and any(self.identity(self.path(row['path']))[1] != row['mode' if side == 'after' else 'before_mode'] for row in value['files']):
                        raise ValueError('completed workload permissions changed; fence retained')
                    if value['kind']=='self-upgrade' and self.agent_configuration()!=record['agent_configuration_sha256']:
                        raise ValueError('agent configuration changed; fence retained')
                    if value['kind'] == 'proxy-upgrade' and side == 'after':
                        self.verify_proxy(value)
                    if pending.exists():
                        pending.unlink()
                        self.sync(stage.parent)
                    return record
                self.restore(stage, value, record)
                return record
            if journal.exists():
                raise ValueError('platform operation already exists; inspect or recover it')
            for row in value['files']:
                identity = self.identity(self.path(row['path']))
                if identity[0] != row['before'] or value['kind'] == 'workload-authority' and identity[1] != row['before_mode']:
                    raise ValueError('installed platform bytes changed after review')
            services, configuration = [], None
            if value['kind'] == 'self-upgrade':
                services = [s for s in SERVICES if self.run(['rc-service', s, 'status'], False)[0] == 0]
                if 'komizo-rootd' not in services:
                    raise ValueError('self-upgrade requires the existing root worker')
                configuration = self.agent_configuration()
            elif value['kind'] == 'proxy-upgrade':
                self.proxy_preflight(stage, value)
            else:
                self.authority_preflight(stage, value)
            backup = stage/'previous'
            backup.mkdir(mode=0o700)
            for index, row in enumerate(value['files']):
                path = self.path(row['path'])
                if row['before'] is not None:
                    shutil.copyfile(path, backup/str(index))
                    os.chmod(backup/str(index), 0o600)
                    with open(backup/str(index), 'rb') as f:
                        os.fsync(f.fileno())
            self.sync(backup)
            record = {'version': 1, 'manifest': expected, 'source': value['source'], 'phase': 'prepared',
                      'services': services, 'agent_configuration_sha256': configuration,
                      'old_modes': [self.identity(self.path(r['path']))[1] for r in value['files']],
                      'application_restart': False}
            self.journal(stage, record)
            self.journal(stage.parent, {'stage': stage.name, 'manifest': expected})
            os.replace(stage.parent/'operation.json', pending)
            self.sync(stage.parent)
            self.checkpoint('prepared')
            try:
                record['phase'] = 'installing'
                self.journal(stage, record)
                for service in reversed(services):
                    self.run(['rc-service', service, 'stop'])
                for index, row in enumerate(value['files']):
                    self.atomic(self.path(row['path']), stage/row['staged'], row['mode'])
                    self.checkpoint('replaced-'+str(index))
                if value['kind'] == 'self-upgrade':
                    if self.run(['komizo-box', 'version'])[1].strip().removeprefix('v') != value['release'].removeprefix('v'):
                        raise ValueError('installed platform version differs')
                    if self.agent_configuration() != configuration:
                        raise ValueError('agent configuration changed during platform upgrade')
                    for service in services:
                        self.run(['rc-service', service, 'start'])
                    if self.path('/etc/komizo/resources.json').exists():
                        # OpenRC removes empty service groups on stop. Reapply
                        # current authority before observing the restarted box.
                        self.run(['komizo-box', 'workload', 'host-resources', '--apply'])
                    self.run(['komizo-box', 'rootd', '--once'])
                elif value['kind'] == 'proxy-upgrade':
                    recreate=['--force-recreate'] if 'resource_budget' in value else []
                    self.compose(self.path('/srv/_proxy/compose.yml'), 'up', '-d', *recreate, '--no-build', '--pull', 'never', 'komizo-proxy')
                    self.verify_proxy(value)
                    self.check_resource_budget(value,installed=True)
                elif any(row['path'] == '/etc/komizo/resources.json' for row in value['files']):
                    self.run(['komizo-box', 'workload', 'host-resources', '--apply'])
                for row in value['files']:
                    if self.identity(self.path(row['path'])) != (row['after'], row['mode']):
                        raise ValueError('installed platform bytes differ')
                record['phase'] = 'complete'
                self.journal(stage, record)
                self.checkpoint('complete')
                pending.unlink()
                self.sync(stage.parent)
                return record
            except Exception:
                self.restore(stage, value, record)
                raise

    def restore(self, stage, value, record):
        # An interruption may leave either side of an atomic replacement. A
        # third identity means another operator wrote it: keep the fence.
        for index, row in enumerate(value['files']):
            actual = self.identity(self.path(row['path']))
            sides = ((row['before'], record['old_modes'][index]), (row['after'], row['mode']))
            if actual not in sides or row['before'] is not None and self.digest(stage/'previous'/str(index)) != row['before']:
                raise ValueError('platform recovery refuses changed installed or backup bytes')
            if row['before'] is None and (stage/'previous'/str(index)).exists():
                raise ValueError('absent previous file has foreign recovery bytes')
        if value['kind'] == 'self-upgrade' and self.agent_configuration() != record['agent_configuration_sha256']:
            raise ValueError('platform recovery preserves changed agent configuration')
        record['phase'] = 'recovering'
        self.journal(stage, record)
        for service in reversed(record['services']):
            self.run(['rc-service', service, 'stop'])
        for index, row in enumerate(value['files']):
            if row['before'] is None:
                path = self.path(row['path'])
                if self.identity(path)[0] is not None:
                    path.unlink()
                    self.sync(path.parent)
            else:
                self.atomic(self.path(row['path']), stage/'previous'/str(index), record['old_modes'][index])
        if value['kind'] == 'proxy-upgrade':
            self.compose(self.path('/srv/_proxy/compose.yml'), 'up', '-d', '--no-build', '--pull', 'never', 'komizo-proxy')
            if self.run(['docker', 'inspect', '--format', '{{.Image}}', 'komizo-proxy'])[1].strip() != value['image']['previous_id']:
                raise ValueError('previous proxy identity unavailable; recovery fence retained')
            if 'static_mount' in value:
                previous = json.loads(self.compose(self.path('/srv/_proxy/compose.yml'), 'config', '--format', 'json')[1])
                wanted = [row for row in previous['services']['komizo-proxy'].get('volumes', []) if row.get('target') == '/srv/public']
                actual = json.loads(self.run(['docker', 'inspect', '--format', '{{json .Mounts}}', 'komizo-proxy'])[1])
                observed = [row for row in actual if row.get('Destination') == '/srv/public']
                implicit = {**STATIC_MOUNT, 'bind': {'create_host_path': True}}
                normalized = {**STATIC_MOUNT, 'bind': {}}
                if (len(wanted) != len(observed) or wanted and (wanted not in ([STATIC_MOUNT], [implicit], [normalized])
                        or observed[0].get('Type') != 'bind' or observed[0].get('Source') != '/srv/_public'
                        or observed[0].get('RW') is not False)):
                    raise ValueError('previous static mount differs; recovery fence retained')
        for service in record['services']:
            self.run(['rc-service', service, 'start'])
        if (value['kind'] == 'self-upgrade' and self.path('/etc/komizo/resources.json').exists()
                or value['kind'] == 'workload-authority' and any(row['path'] == '/etc/komizo/resources.json' for row in value['files'])):
            # Restoring bytes is insufficient after a partial controller write.
            # Failure leaves the durable fence for a measured operator drain.
            self.run(['komizo-box', 'workload', 'host-resources', '--apply'])
        record['phase'] = 'recovered'
        self.journal(stage, record)
        pending = self.path('/var/lib/komizo/upgrades/pending.json')
        if pending.exists():
            pending.unlink()
            self.sync(stage.parent)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 4 or sys.argv[1] not in ('apply', 'recover', 'inspect') or not SHA.fullmatch(sys.argv[3]):
        raise ValueError('platform requires root, a fixed operation, stage and manifest digest')
    platform = Platform()
    stage = Path(sys.argv[2])
    if sys.argv[1] == 'inspect':
        platform.manifest(stage, sys.argv[3])
        record = json.loads(platform.read(stage/'operation.json', private=True))
        print(json.dumps({k: record.get(k) for k in ('version', 'manifest', 'source', 'phase', 'application_restart')}))
    else:
        print(json.dumps(platform.apply(stage, sys.argv[3], sys.argv[1] == 'recover')))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('platform refused: '+str(error), file=sys.stderr)
        raise SystemExit(1)
