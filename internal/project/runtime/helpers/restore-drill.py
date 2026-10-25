#!/usr/bin/env python3
"""Boot an authenticated off-host snapshot with its real application images offline."""
import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def helper(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def docker(*args, input=None, timeout=60):
    try:
        result = subprocess.run(['docker', *args], input=input, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'Docker {args[0]} timed out during the isolated restore drill') from None
    if result.returncode:
        # Arguments may include disposable clone credentials. Never print them,
        # application logs, or restored database contents into a workflow log.
        raise RuntimeError(f'Docker {args[0]} failed during the isolated restore drill')
    return result.stdout.strip()


SERVING_DSN_VARIABLE = 'RUNTIME_DATABASE_URL_FILE'


def load_config(file):
    config = json.loads(Path(file).read_text())
    if not re.fullmatch(r'[a-z][a-z0-9-]*', config.get('project', '')):
        raise ValueError('restore config must name an explicit project')
    if not re.fullmatch(r'[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9][a-z0-9/._-]*', config.get('image_base', '')):
        raise ValueError('restore config must bind the application image namespace')
    required = {'postgresql': ('runtime_role', 'dsn_file', 'api_port', 'health_path', 'root', 'env'),
                'pocketbase': ('db', 'binary', 'port', 'api_port', 'root', 'env', 'data_path', 'health_path', 'serve_flags')}
    backend = config.get('backend')
    if backend not in required or any(key not in config for key in required[backend]):
        raise ValueError('restore config has an unknown backend or missing application settings')
    if backend == 'postgresql':
        for name, pattern in (('database', r'[a-z][a-z0-9_]{0,62}'),
                              ('role_namespace', r'[a-z][a-z0-9-]*')):
            if name in config and (not isinstance(config[name], str) or not re.fullmatch(pattern, config[name])):
                raise ValueError('restore config has an invalid PostgreSQL identity')
    if not isinstance(config['env'], dict) or any(not re.fullmatch(r'[A-Z][A-Z0-9_]*', name)
        or not isinstance(value, str) or '\n' in value or '\r' in value for name, value in config['env'].items()):
        raise ValueError('restore environment must contain bounded single-line values')
    return config


def probe_endpoint(docker_run, watched, url, timeout=175):
    """Poll `url` from inside the watched container's network namespace.

    The namespace is the isolated one the store was started in, so nothing
    here is reachable from the host or from any other container.
    """
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        if not json.loads(docker('inspect', watched))[0]['State']['Running']:
            raise RuntimeError('restored container exited before becoming healthy')
        try:
            body = docker_run(url)
            if time.monotonic() >= deadline:
                raise TimeoutError('restore health response arrived after its deadline')
            return body
        except RuntimeError:
            time.sleep(1)
    raise TimeoutError('restored service did not become healthy before its deadline')


def restored_blob_mounts(payload, config, uid):
    """Expose authenticated restored files, never an empty replacement volume."""
    files = payload/'files'
    if not config.get('blobs'):
        if files.exists() and any(files.rglob('*')):
            raise ValueError('snapshot files require an explicit application blob mount')
        return []
    files.mkdir(mode=0o700, exist_ok=True)
    paths = [files, *files.rglob('*')]
    if any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in paths):
        raise ValueError('restored blob mount must contain only authenticated regular files')
    if os.getuid() == 0:
        for path in paths:
            os.chown(path, uid, uid)
    return ['--mount', f'type=bind,src={files},dst={config["blobs"]},readonly']


def postgres_drill(project, export, key, pull=False, *, config):
    """Restore an authenticated snapshot into PostgreSQL and boot the product on it.

    Proves the same three things the PocketBase drill does -- the data comes
    back, the API serves against it, and the release's frontend artifact is a
    real document -- for a product whose store is PostgreSQL.
    """
    snapshot = helper('snapshot')
    receiver = helper('receive-backup')
    recovery = helper('postgres-recovery')
    containers = []
    report = {'project': project, 'network': 'none; shared isolated loopback only', 'published_ports': []}
    memory = Path('/proc/meminfo')
    if memory.exists():
        available = re.search(r'^MemAvailable:\s+(\d+) kB$', memory.read_text(), re.M)
        if not available or int(available[1]) < 768 * 1024:
            raise ValueError('restore drill requires 768 MiB of available host memory')
    with tempfile.TemporaryDirectory(prefix=f'{project}-restore-drill-') as directory:
        root = Path(directory)
        receiver.receive(export, root/'encrypted')
        payload = root/'payload'
        payload.mkdir(mode=0o700)
        # unseal authenticates the envelope, validates the payload against its
        # manifest and, for this backend, checks the PostgreSQL engine image
        # against the receipt. It reads the backend from the envelope rather
        # than being told, so an envelope of the other kind must be refused
        # here: booting a pocketbase snapshot through this path would find no
        # manifest and fail later, and further from the cause.
        evidence = snapshot.unseal(root/'encrypted', key, payload)
        if evidence.get('backend') != 'postgresql':
            raise ValueError('this product restores into PostgreSQL; the envelope is not a PostgreSQL snapshot')
        # The engine reference in a PostgreSQL envelope is the POSTGRES image,
        # not a product image, so the product revision comes from the
        # authenticated manifest rather than from a tag.
        manifest = evidence['postgresql']
        if manifest['project'] != project:
            raise ValueError('authenticated snapshot belongs to another product')
        revision = manifest['revision']
        if not re.fullmatch(r'[a-f0-9]{40}', revision):
            raise ValueError('authenticated snapshot does not name an exact product revision')
        # The components come from the manifest, not from a list here: it is
        # the authenticated statement of which images belong to this snapshot,
        # and validate_manifest has already bound each reference to this
        # project and revision.
        images = {}
        for component, declared in sorted(manifest['images'].items()):
            image = f'{config["image_base"]}-{component}:{revision}'
            if declared['reference'] != image:
                raise ValueError('authenticated snapshot declares a different application image')
            if pull:
                # Authenticate the encrypted project/revision before pulling.
                # Registry credentials stay on the host, outside every clone.
                docker('pull', '--quiet', image, timeout=180)
            images[component] = json.loads(docker('image', 'inspect', image))[0]['Id']
            # A tag is mutable; the snapshot named a digest. Booting whatever
            # currently answers to the tag would make the drill prove nothing
            # about the release the data came from.
            if images[component] != declared['image_id']:
                raise ValueError('application image differs from authenticated snapshot metadata')
        api_component = 'service' if 'service' in images else 'api'
        if 'gate' not in images or api_component not in images:
            raise ValueError('authenticated snapshot is missing an application or frontend image')
        uid = os.getuid() if os.getuid() else 65534
        prefix = project+'-restore-'+secrets.token_hex(8)
        common = ['--read-only', '--user', f'{uid}:{uid}', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
                  '--cpus=1', '--pids-limit=128', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m']
        try:
            with recovery.restored_database(payload, project, revision, pull=pull) as restored:
                store = restored['container']
                dsn = restored['credentials'][config['runtime_role']]
                netns = ['--network', f'container:{store}']

                def wget(url):
                    name = prefix+'-probe'
                    containers.append(name)
                    try:
                        return docker('run', '--name', name, *netns, *common, '--memory=64m',
                                      '--entrypoint', '/usr/bin/wget', images['gate'],
                                      '-qO-', '-T', '3', url, timeout=15)
                    finally:
                        docker('rm', '-f', '-v', name)
                        containers.remove(name)

                environment = root/'clone.env'
                environment.write_text(''.join(f'{name}={value}\n' for name, value in
                                               {**config['env'], SERVING_DSN_VARIABLE: config['dsn_file']}.items()))
                environment.chmod(0o600)
                api = prefix+'-api'
                containers.append(api)
                blobs = restored_blob_mounts(payload, config, uid)
                docker('run', '-d', '--name', api, *netns, *common, '--memory=192m', *blobs,
                       '--mount', f'type=bind,src={dsn},dst={config["dsn_file"]},readonly',
                       '--env-file', str(environment), images[api_component])
                probe_endpoint(wget, api, f'http://127.0.0.1:{config["api_port"]}{config["health_path"]}', timeout=120)
                if not json.loads(docker('inspect', api))[0]['State']['Running']:
                    raise RuntimeError('restored API did not remain running')
                gate = prefix+'-gate'
                containers.append(gate)
                docker('run', '-d', '--name', gate, *netns, *common, '--memory=96m',
                       '--entrypoint', '/usr/bin/caddy', images['gate'],
                       'file-server', '--root', config['root'], '--listen', '127.0.0.1:8088')
                html = probe_endpoint(wget, gate, 'http://127.0.0.1:8088/', timeout=45)
                if '<html' not in html.lower() or '<script' not in html.lower():
                    raise ValueError('the restored frontend artifact did not serve an application document')
                report.update({'revision': revision, 'images': {**images, 'engine': restored['engine']},
                               'archive_sha256': evidence['archive_sha256'], 'backend': 'postgresql',
                               'database_integrity': 'ok', 'database_restore': restored['database_restore'],
                               'database_boot': 'passed', 'backup_verified_at': evidence['verified_at'],
                               'ciphertext_sha256': snapshot.sha256(root/'encrypted'/'snapshot.cms'),
                               'files_restored': sum(name.startswith('files/') for name in manifest['files']),
                               'api_boot': 'passed', 'frontend_artifact': 'passed'})
        finally:
            failed = []
            for name in reversed(containers):
                try:
                    docker('rm', '-f', '-v', name)
                except RuntimeError:
                    failed.append(name)
            if failed:
                raise RuntimeError('isolated restore container cleanup failed')
    report['cleanup'] = 'passed'
    return report


def drill(project, export, key, pull=False, *, config):
    if config['project'] != project:
        raise ValueError('restore config belongs to another product')
    if config['backend'] == 'postgresql':
        return postgres_drill(project, export, key, pull, config=config)
    snapshot = helper('snapshot')
    receiver = helper('receive-backup')
    data_path = config['data_path']
    health_path = config['health_path']
    containers = []
    report = {'project': project, 'network': 'none; shared isolated loopback only', 'published_ports': []}
    memory = Path('/proc/meminfo')
    if memory.exists():
        available = re.search(r'^MemAvailable:\s+(\d+) kB$', memory.read_text(), re.M)
        if not available or int(available[1]) < 768 * 1024:
            raise ValueError('restore drill requires 768 MiB of available host memory')
    with tempfile.TemporaryDirectory(prefix=f'{project}-restore-drill-') as directory:
        root = Path(directory)
        receiver.receive(export, root/'encrypted')
        restored = root/'pb_data'
        restored.mkdir(mode=0o700)
        evidence = snapshot.unseal(root/'encrypted', key, restored)
        match = re.fullmatch(rf'{re.escape(config["image_base"])}-{config["db"]}:([a-f0-9]{{40}})', evidence['image_reference'])
        if not match:
            raise ValueError('authenticated snapshot image does not belong to this product')
        revision = match[1]
        components = [config['db'], 'gate'] + (['api'] if config.get('separate_api', True) else [])
        images = {}
        for component in components:
            image = f'{config["image_base"]}-{component}:{revision}'
            if pull:
                # Authenticate the encrypted project/revision before pulling.
                # Registry credentials stay on the host, outside every clone.
                docker('pull', '--quiet', image, timeout=180)
            images[component] = json.loads(docker('image', 'inspect', image))[0]['Id']
            if component == config['db'] and images[component] != evidence['image_id']:
                raise ValueError('restored database image differs from authenticated snapshot metadata')
        # Root-host installations give the clone to nobody. Local verification
        # uses the caller's UID, still nonroot in the container.
        uid = os.getuid() if os.getuid() else 65534
        if os.getuid() == 0:
            for path in [restored, *restored.rglob('*')]:
                os.chown(path, uid, uid)
        password = secrets.token_hex(32)
        env = {name: value.replace('{password}', password) for name, value in config['env'].items()}
        for name in config.get('required_environment', []):
            if name not in os.environ:
                raise ValueError('supply the required restore environment explicitly')
            env[name] = os.environ[name]
        environment = root/'clone.env'
        environment.write_text(''.join(f'{name}={value}\n' for name, value in env.items()))
        environment.chmod(0o600)
        settings_flags = config.get('settings_flags', [])
        prefix = project+'-restore-'+secrets.token_hex(8)
        common = ['--read-only', '--user', f'{uid}:{uid}', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
                  '--cpus=1', '--pids-limit=128', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m']
        private_env = ['--env-file', str(environment)]
        mount = ['--mount', f'type=bind,src={restored},dst={data_path}']
        try:
            # This affects only the decrypted disposable clone.
            bootstrap = prefix+'-bootstrap'
            containers.append(bootstrap)
            docker('run', '--name', bootstrap, '--network=none', *common, '--memory=192m', *private_env, *mount,
                   '--entrypoint', config['binary'], images[config['db']], 'superuser', 'upsert',
                   'restore@verification.invalid', password, f'--dir={data_path}', *settings_flags, timeout=180)
            db = prefix+'-db'
            containers.append(db)
            command = ['serve', f'--http=127.0.0.1:{config["port"]}', f'--dir={data_path}', *settings_flags]
            command += config['serve_flags']
            docker('run', '-d', '--name', db, '--network=none', *common, '--memory=192m', *private_env, *mount,
                   '--entrypoint', config['binary'], images[config['db']], *command)
            # The gate image supplies wget for the distroless service too.
            # Its helper processes share only this isolated network namespace.
            def probe(url, timeout=175):
                deadline = time.monotonic()+timeout
                while time.monotonic() < deadline:
                    state = json.loads(docker('inspect', db))[0]['State']
                    if not state['Running']:
                        raise RuntimeError('restored database exited before becoming healthy')
                    try:
                        name = prefix+'-probe'
                        if name not in containers:
                            containers.append(name)
                        body = docker('run', '--name', name, '--network', f'container:{db}', *common, '--memory=64m',
                                      '--entrypoint', '/usr/bin/wget', images['gate'], '-qO-', '-T', '3', url, timeout=15)
                        if time.monotonic() >= deadline:
                            raise TimeoutError('restore health response arrived after its deadline')
                        return body
                    except RuntimeError:
                        time.sleep(1)
                    finally:
                        docker('rm', '-f', '-v', name)
                        containers.remove(name)
                raise TimeoutError('restored service did not become healthy before its deadline')
            probe(f'http://127.0.0.1:{config["port"]}/api/health')
            if config.get('separate_api', True):
                api = prefix+'-api'
                containers.append(api)
                docker('run', '-d', '--name', api, '--network', f'container:{db}', *common, '--memory=128m', *private_env, images['api'])
                probe(f'http://127.0.0.1:{config["api_port"]}{health_path}', timeout=60)
                if not json.loads(docker('inspect', api))[0]['State']['Running']:
                    raise RuntimeError('restored API did not remain running')
            gate = prefix+'-gate'
            containers.append(gate)
            docker('run', '-d', '--name', gate, '--network', f'container:{db}', *common, '--memory=96m',
                   '--entrypoint', '/usr/bin/caddy', images['gate'], 'file-server', '--root', config['root'], '--listen', '127.0.0.1:8088')
            html = probe('http://127.0.0.1:8088/', timeout=45)
            if '<html' not in html.lower() or '<script' not in html.lower():
                raise ValueError('the restored frontend artifact did not serve an application document')
            report.update({'revision': revision, 'images': images, 'archive_sha256': evidence['archive_sha256'],
                           'database_integrity': 'ok', 'database_boot': 'passed', 'api_boot': 'passed', 'frontend_artifact': 'passed',
                           'backup_verified_at': evidence['verified_at'],
                           'ciphertext_sha256': snapshot.sha256(root/'encrypted'/'snapshot.cms')})
        finally:
            failed = []
            for name in reversed(containers):
                try:
                    docker('rm', '-f', '-v', name)
                except RuntimeError:
                    failed.append(name)
            if failed:
                raise RuntimeError('isolated restore container cleanup failed')
    report['cleanup'] = 'passed'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True)
    parser.add_argument('--config', type=Path, default=Path('deploy/restore.json'))
    parser.add_argument('--export', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--lock', type=Path, help='root-owned host lock for scheduled drills')
    parser.add_argument('--pull', action='store_true', help='pull authenticated exact-revision images on the restore runner')
    args = parser.parse_args()
    os.umask(0o077)
    def interrupted(number, _frame):
        # Ignore a second signal while the first unwinds owned container cleanup.
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
            signal.signal(signum, signal.SIG_IGN)
        raise InterruptedError(f'restore drill interrupted by signal {number}')
    for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(number, interrupted)
    # Includes the stream receive deadline; a stalled SSH sender cannot retain
    # a root worker indefinitely. Cleanup runs when the alarm unwinds the drill.
    signal.alarm(900)
    with args.lock.open('a') if args.lock else nullcontext() as lock:
        if lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix='restore-input-') as directory:
            export = args.export
            if str(export) == '-':
                export = Path(directory)/'export.tar'
                total = 0
                with export.open('xb') as output:
                    while block := sys.stdin.buffer.read(1024*1024):
                        total += len(block)
                        if total > 17 * 1024**3 + 1024**2 or shutil.disk_usage(directory).free < len(block) + 512 * 1024**2:
                            raise ValueError('restore input exceeds the size or disk headroom bound')
                        output.write(block)
            started_at = datetime.now(timezone.utc).isoformat()
            started = time.monotonic()
            report = drill(args.project, export, args.key, args.pull, config=load_config(args.config))
            report.update(version=1, started_at=started_at, completed_at=datetime.now(timezone.utc).isoformat(),
                          duration_seconds=round(time.monotonic()-started, 3))
            print(json.dumps(report, indent=2))
    signal.alarm(0)


if __name__ == '__main__':
    main()
