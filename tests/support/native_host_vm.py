#!/usr/bin/env python3
"""Boot one pinned disposable Debian guest and collect native host acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import secrets
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/fixtures/native_host'


def run(argv, *, timeout=60, **options):
    return subprocess.run(argv, check=True, timeout=timeout, **options)


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


def key(directory, name):
    path = directory / name
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)])
    return path


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class Guest:
    def __init__(self, directory, keyfile, host_key, ssh_port):
        self.directory = directory
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
        for command in ['id', 'sh', 'podman ps', 'komizo-box daemon']:
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / '.artifacts/native-host')
    args = parser.parse_args()
    binary = args.binary.absolute()
    if not binary.is_file() or binary.is_symlink():
        raise ValueError('native host acceptance requires its exact regular compiled binary')
    if not Path('/dev/kvm').exists() or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise ValueError('real native host acceptance requires accessible KVM; no simulated success fallback')
    baseline = json.loads((FIXTURES / 'baseline.json').read_text())
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='komizo-native-host-') as temporary:
        directory = Path(temporary)
        owner = key(directory, 'owner')
        submit = key(directory, 'submission')
        host = key(directory, 'host')
        base = directory / 'base.qcow2'
        print('Downloading and authenticating the pinned Debian cloud image',flush=True)
        download(baseline['cloud_image'], base)
        archive = directory / 'caddy.tar.gz'
        print('Downloading and authenticating the pinned Caddy archive',flush=True)
        download(baseline['caddy_archive'], archive)
        caddy = directory / 'caddy'
        with tarfile.open(archive, 'r:gz') as package:
            entries = [entry for entry in package.getmembers() if entry.name == 'caddy']
            if len(entries) != 1 or not entries[0].isfile() or not 0 < entries[0].size <= 64 << 20:
                raise ValueError('reviewed Caddy archive lacks its bounded executable')
            caddy.write_bytes(package.extractfile(entries[0]).read())
        caddy.chmod(0o755)
        user_data = {'disable_root': False, 'ssh_pwauth': False,
            'users': [{'name': 'root', 'ssh_authorized_keys': [owner.with_suffix('.pub').read_text().strip()]}],
            'ssh_keys': {'ed25519_private': host.read_text(), 'ed25519_public': host.with_suffix('.pub').read_text().strip()},
            'package_update': True,
            'packages': ['podman', 'uidmap', 'netavark', 'aardvark-dns', 'busybox-static', 'python3', 'curl', 'ca-certificates', 'nftables'],
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
            process = subprocess.Popen(['qemu-system-x86_64', '-no-user-config', '-display', 'none',
                '-machine', 'q35,accel=kvm', '-cpu', 'host', '-m', '2048', '-smp', '2',
                '-drive', 'file=' + str(overlay) + ',if=virtio,format=qcow2',
                '-drive', 'file=' + str(seed) + ',if=virtio,format=raw,readonly=on',
                '-netdev', 'user,id=net0,hostfwd=tcp:127.0.0.1:' + str(ssh_port) + '-:22',
                '-device', 'virtio-net-pci,netdev=net0', '-serial', 'stdio', '-monitor', 'none',
                '-device', 'virtio-rng-pci'], stdout=log, stderr=log, start_new_session=True)
            try:
                print('Booting the disposable guest and waiting for its bounded cloud setup',flush=True)
                guest.ready(process, time.monotonic() + 600)
                print('Guest setup completed; installing the exact compiled native controller',flush=True)
                guest.copy(binary, '/usr/local/bin/komizo-box')
                binary_sha=hashlib.sha256(binary.read_bytes()).hexdigest()
                if guest.command('sha256sum /usr/local/bin/komizo-box',capture_output=True).stdout.decode().split()[0]!=binary_sha:
                    raise ValueError('guest native binary differs from the exact compiled source artifact')
                guest.copy(caddy, '/usr/local/bin/caddy')
                guest.copy(submit.with_suffix('.pub'), '/root/native-host/submission.pub')
                guest.copy(ROOT / 'tests/support/native_host_acceptance.py', '/root/native-host/acceptance.py')
                guest.copy(ROOT / 'tests/support/native_host_runtime.py', '/root/native-host/fixture_runtime.py')
                guest.copy(ROOT / 'tests/support/native_host_registry.py', '/root/native-host/fixture_registry.py')
                guest.copy(ROOT / 'tests/support/native_host_secrets.py', '/root/native-host/fixture_secrets.py')
                guest.copy(ROOT / 'tests/support/native_host_backup.py', '/root/native-host/fixture_backup.py')
                guest.copy(ROOT / 'tests/support/native_host_postgres.py', '/root/native-host/fixture_postgres.py')
                guest.copy(FIXTURES / 'baseline.json', '/root/native-host/baseline.json')
                print('Running native bootstrap, authority and release effects',flush=True)
                guest.command('chmod 755 /usr/local /usr/local/bin /usr/local/bin/komizo-box /usr/local/bin/caddy; chmod 600 /root/native-host/submission.pub; python3 /root/native-host/acceptance.py prepare', timeout=600)
                guest.submission_boundary(submit)
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
                accepted['checks']['ssh_forced_submission'] = 'passed'
                accepted['checks']['ssh_forwarding_refused'] = 'passed'
                (args.output / 'report.json').write_text(json.dumps(accepted,sort_keys=True)+'\n')
                if not accepted.get('ok'):
                    raise ValueError('native guest acceptance failed')
            finally:
                if process.poll() is None:
                    try:
                        guest.command("journalctl -b -u komizo-controller -u komizo-proxy -u 'kmz-*' -n 500 --no-pager > /root/native-host/journal.log", timeout=20)
                        evidence = guest.command('cat /root/native-host/journal.log', timeout=20, capture_output=True).stdout
                        (args.output / 'journal.log').write_bytes(evidence)
                        status=guest.command('/usr/local/bin/komizo-box status',timeout=30,capture_output=True).stdout
                        (args.output/'status.json').write_bytes(status)
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
