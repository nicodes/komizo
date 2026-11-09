#!/usr/bin/env python3
"""Boot one pinned disposable Debian guest and collect native host acceptance."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import secrets
import selectors
import shlex
import tomllib
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/fixtures/native_host'


def run(argv, *, timeout=60, **options):
    return subprocess.run(argv, check=options.pop('check',True), timeout=timeout, **options)


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


def parent_lifetime(parent):
    # An aggregate timeout/crash of the driver must not leave its owned KVM
    # process running. No other guest or host process is selected by this hook.
    if ctypes.CDLL(None,use_errno=True).prctl(1,signal.SIGKILL)!=0:raise OSError(ctypes.get_errno(),'cannot bind owned guest lifetime')
    if os.getppid()!=parent:os.kill(os.getpid(),signal.SIGKILL)


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

    def ready(self, process, deadline):
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError('disposable guest stopped before SSH readiness')
            try:
                self.command('test -f /root/native-host/cloud-ready && cloud-init status --wait', timeout=15,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except (subprocess.SubprocessError, OSError):
                time.sleep(1)
        raise ValueError('disposable guest readiness deadline expired')

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
            self.prefix=['sudo','-n','--user='+self.name,'--','/usr/bin/env','-i','HOME='+str(self.home),
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
        response=run([*isolated.prefix,str(isolated.executable),action,*flags],cwd=isolated.home,
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},capture_output=True,timeout=timeout)
        observed.append({'action':action,'seconds':time.monotonic()-began})
        value=json.loads(response.stdout)
        if not isinstance(value,dict):raise ValueError('cold owner client did not return a typed record')
        return value
    capabilities=command('capabilities')
    if capabilities.get('kind')!='komizo.capabilities' or capabilities.get('host')!={'os':'debian','version':'13','engine':'podman','rootful':True}:
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
    metrics=json.loads(guest.command('python3 /root/native-host/fixture_performance.py finish '+shlex.quote(json.dumps(budget)),timeout=budget['load_seconds']+20,capture_output=True).stdout)
    timings=json.loads(guest.command('cat /root/native-host/timings.json',capture_output=True).stdout)
    metrics.update(setup_seconds=setup_seconds,deployment_seconds=timings['deployment_seconds'],route_seconds=routes,operator_seconds=operators)
    sys.path.insert(0,str(ROOT/'tests/acceptance'))
    from performance_acceptance import evaluate, SCOPE
    accepted=evaluate(metrics,budget)
    report={'version':1,'accepted':accepted,'budget':budget,'budget_sha256':hashlib.sha256(budget_path.read_bytes()).hexdigest(),
        'metrics':metrics,'scope':SCOPE}
    return report,onboarding


def owner_recovery(guest, directory, key):
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
        encrypted=directory/(record['application']+'.cms');encrypted.write_bytes(pair['snapshot.cms']);encrypted.chmod(0o600)
        plaintext=run(['openssl','cms','-decrypt','-binary','-inform','DER','-in',str(encrypted),'-inkey',str(key)],capture_output=True).stdout
        if record['format']=='synthetic-volume-json':
            if json.loads(plaintext)!={'application':record['application'],'release_digest':record['release_digest'],'count':'accepted\n'}:
                raise ValueError('owner synthetic decryption changed retained data or source identity')
            checks['synthetic_owner_decryption']='passed'
        elif record['format']=='postgresql-custom':
            if not plaintext.startswith(b'PGDMP') or len(plaintext)>1<<20:raise ValueError('owner PostgreSQL plaintext is not the bounded captured dump')
            dump=directory/'owner-postgres.dump';dump.write_bytes(plaintext);dump.chmod(0o600)
            guest.copy(dump,'/root/native-host/owner-postgres.dump')
            restored=json.loads(guest.command('python3 /root/native-host/fixture_postgres.py restore',timeout=120,capture_output=True).stdout)
            if (restored.get('kind')!='komizo.native-database-recovery' or restored.get('release_digest')!=record['release_digest']
                    or restored.get('current_source_ci_acceptance') is not False or restored.get('rows')!='passed'):
                raise ValueError('owner PostgreSQL restoration did not prove the captured installed source')
            checks['owner_postgresql_encrypted_restore']='passed';checks['owner_recovery_disposable_isolation']='passed'
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
    parser.add_argument('--output', type=Path, default=ROOT / '.artifacts/native-host')
    args = parser.parse_args()
    if args.profile=='bounded' and (args.cli is None or args.cli.is_symlink() or not args.cli.is_file()):raise ValueError('bounded native acceptance requires its exact cold owner client')
    binary = args.binary.absolute()
    if not binary.is_file() or binary.is_symlink():
        raise ValueError('native host acceptance requires its exact regular compiled binary')
    if not Path('/dev/kvm').exists() or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise ValueError('real native host acceptance requires accessible KVM; no simulated success fallback')
    baseline = json.loads((FIXTURES / 'baseline.json').read_text())
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
        print('Downloading and authenticating the pinned Debian cloud image',flush=True)
        download(baseline['cloud_image'], base)
        recovery_key=directory/'recipient.key';recipient=directory/'recipient.crt'
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(recovery_key),
            '-out',str(recipient),'-days','2','-subj','/CN=disposable-native-owner'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        recovery_key.chmod(0o600)
        profile=directory/'profile.json';profile.write_text(json.dumps({'profile':args.profile}))
        user_data = {'disable_root': False, 'ssh_pwauth': False,
            'users': [{'name': 'root', 'ssh_authorized_keys': [owner.with_suffix('.pub').read_text().strip()]}],
            'ssh_keys': {'ed25519_private': host.read_text(), 'ed25519_public': host.with_suffix('.pub').read_text().strip()},
            'package_update': True,
            'packages': ['podman', 'uidmap', 'netavark', 'aardvark-dns', 'busybox-static', 'python3', 'curl', 'ca-certificates', 'nftables', 'strace'],
            'runcmd': [['sh', '-c', 'install -d -m 700 /root/native-host; touch /root/native-host/cloud-ready']]}
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
            # Debian GRUB needs the default console/video device model even
            # with a hidden display (Debian bug 1111240); the image stays exact.
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
                guest.ready(process, time.monotonic() + 600)
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
                guest.copy(profile,'/root/native-host/profile.json')
                guest.copy(ROOT / 'tests/support/native_host_acceptance.py', '/root/native-host/acceptance.py')
                guest.copy(ROOT / 'tests/support/native_host_runtime.py', '/root/native-host/fixture_runtime.py')
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
                owner_checks=owner_recovery(guest,directory,recovery_key)
                if args.profile=='bounded':
                    measured,onboarding=performance(guest,directory,args.cli.absolute(),setup_seconds)
                    (args.output/'performance.json').write_text(json.dumps(measured,sort_keys=True)+'\n')
                    (args.output/'onboarding.json').write_text(json.dumps(onboarding,sort_keys=True)+'\n')
                before = guest.command('cat /proc/sys/kernel/random/boot_id', capture_output=True).stdout.strip()
                print('Rebooting the real guest with the artifact registry offline',flush=True)
                guest.command('systemctl reboot', timeout=15)
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
                if process.poll() is None:
                    try:
                        guest.command("journalctl -b -u komizo-controller -u komizo-proxy -u 'kmz-*' -n 500 --no-pager > /root/native-host/journal.log", timeout=20)
                        evidence = guest.command('cat /root/native-host/journal.log', timeout=20, capture_output=True).stdout
                        (args.output / 'journal.log').write_bytes(evidence)
                        status=guest.command('/usr/local/bin/komizo-box status',timeout=30,capture_output=True,check=False)
                        if status.returncode==0:(args.output/'status.json').write_bytes(status.stdout)
                        else:(args.output/'status-error.json').write_text(json.dumps({'code':status.returncode,'stderr':status.stderr.decode(errors='replace')[:2048]},sort_keys=True)+'\n')
                        runtime_evidence=guest.command('python3 /root/native-host/acceptance.py evidence',timeout=15,capture_output=True).stdout
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


if __name__ == '__main__':
    main()
