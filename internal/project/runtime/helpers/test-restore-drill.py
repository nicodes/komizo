#!/usr/bin/env python3
"""Exercise encryption and a complete offline restore using disposable local data."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tarfile
import tempfile
import time




def docker_bytes(*args, timeout=180):
    """Run docker and return raw stdout.

    The shared docker() helper decodes and strips its output, which would
    corrupt a pg_dump custom-format archive. Stderr is swallowed for the same
    reason the shared one swallows it: the arguments carry disposable
    credentials that must never reach a workflow log.
    """
    result = subprocess.run(['docker', *args], capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'Docker {args[0]} failed while building the restore fixture')
    return result.stdout


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



def postgres_fixture(project, revision, engine_reference, restore, snapshot, recovery, root, *, config):
    """Build a disposable PostgreSQL capture and package it as a recovery payload.

    Disposable throughout: an empty database with one fixture row, dumped out
    of a container that is destroyed immediately. Nothing here reads a live
    deployment, and the drill that consumes it restores into its own isolated
    container.
    """
    if not re.fullmatch(r'(?:docker\.io/library/)?postgres@sha256:[a-f0-9]{64}', engine_reference):
        raise ValueError('the fixture engine must be an immutable official postgres digest')
    engine = json.loads(restore.docker('image', 'inspect', engine_reference))[0]
    # The image states its own major; deriving it keeps the fixture honest
    # when the pinned digest moves, rather than asserting a number here that
    # package_capture would then reject against the capture report.
    declared = [value.split('=', 1)[1] for value in engine['Config']['Env'] or [] if value.startswith('PG_MAJOR=')]
    if len(declared) != 1 or not declared[0].isdigit():
        raise ValueError('the engine image does not declare exactly one PG_MAJOR')
    major = int(declared[0])
    database = config.get('database', project)
    capture = root/'capture'
    capture.mkdir(mode=0o700)
    password = secrets.token_hex(32)
    environment = root/'engine.env'
    # PGDATA under an owned bind mount, exactly as restored_database runs it:
    # with capabilities dropped the image's entrypoint cannot chown or chmod
    # anything, so the directories have to arrive already owned by the user
    # the container runs as, and the socket directory has to be a tmpfs with
    # that ownership rather than a path in the read-only image.
    environment.write_text(f'POSTGRES_USER=fixture_owner\nPOSTGRES_PASSWORD={password}\n'
                           f'POSTGRES_DB={database}\nPGDATA=/var/lib/postgresql/data\n')
    environment.chmod(0o600)
    uid = os.getuid() or 65534
    data = root/'engine-data'
    data.mkdir(mode=0o700)
    if os.getuid() == 0:
        os.chown(data, uid, uid)
    name = project+'-capture-fixture-'+secrets.token_hex(8)
    try:
        restore.docker('run', '-d', '--name', name, '--network=none', '--read-only',
                       '--user', f'{uid}:{uid}', '--cap-drop=ALL',
                       '--security-opt=no-new-privileges:true', '--memory=256m', '--cpus=1', '--pids-limit=128',
                       '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
                       '--tmpfs', f'/var/run/postgresql:rw,noexec,nosuid,uid={uid},gid={uid},mode=0770,size=8m',
                       '--mount', f'type=bind,src={data},dst=/var/lib/postgresql/data',
                       '--env-file', str(environment), engine_reference,
                       'postgres', '-c', 'listen_addresses=127.0.0.1')
        deadline = time.monotonic()+90
        while True:
            try:
                restore.docker('exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'fixture_owner', '-d', database)
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('fixture PostgreSQL did not become ready') from None
                time.sleep(.2)
        # One table with one row: enough that an empty or truncated dump
        # cannot pass the restore, and small enough to stay disposable.
        restore.docker('exec', '-i', name, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'fixture_owner',
                       '-d', database, input='CREATE TABLE restore_fixture(id int primary key);\n'
                                             'INSERT INTO restore_fixture VALUES (1);\n')
        dump = docker_bytes('exec', name, 'pg_dump', '-Fc', '--no-owner', '--no-tablespaces',
                            '-U', 'fixture_owner', '-d', database)
    finally:
        restore.docker('rm', '-f', '-v', name)
    (capture/'database.dump').write_bytes(dump)
    (capture/'database.dump').chmod(0o600)
    files = {'database.dump': {'size': (capture/'database.dump').stat().st_size,
                               'sha256': snapshot.sha256(capture/'database.dump')}}
    (capture/'capture.json').write_text(json.dumps({
        'snapshot_id': 'AAAA-BBBB-1', 'reclamation_fenced': True,
        'completed_at': datetime.now(timezone.utc).isoformat(),
        'database': database, 'major': major, 'files': files}))
    images = {}
    for component in ('api', 'gate'):
        reference = f'{config["image_base"]}-{component}:{revision}'
        images[component] = {'reference': reference,
                             'image_id': json.loads(restore.docker('image', 'inspect', reference))[0]['Id']}
    metadata = {'project': project, 'revision': revision, 'roles': [config['runtime_role']], 'images': images,
                'engine': {'reference': engine_reference, 'image_id': engine['Id'], 'major': major}}
    if 'role_namespace' in config:
        metadata['role_namespace'] = config['role_namespace']
    return recovery.package_capture(capture, root/'package', metadata)


def postgres_main(project, revision, engine, restore, snapshot, *, config, config_file):
    recovery = load('postgres-recovery')
    with tempfile.TemporaryDirectory(prefix=f'{project}-restore-fixture-') as directory:
        root = Path(directory)
        package = postgres_fixture(project, revision, engine, restore, snapshot, recovery, root, config=config)
        key, cert = root/'key.pem', root/'recipient.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-keyout', str(key),
            '-out', str(cert), '-days', '1', '-subj', '/CN=disposable-restore-fixture'], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        sealed = snapshot.seal(package, cert)
        export = root/'export.tar'
        with tarfile.open(export, 'w') as bundle:
            for file in ('snapshot.cms', 'receipt.json'):
                bundle.add(sealed/file, arcname=file)
        # The same bounded stdin path as the fixed host wrapper.
        with export.open('rb') as incoming:
            result = subprocess.run(['python3', str(Path(__file__).with_name('restore-drill.py')),
                '--project', project, '--config', str(config_file), '--export', '-', '--key', str(key)], stdin=incoming,
                text=True, capture_output=True, timeout=930)
        if result.returncode:
            raise RuntimeError('offline restore fixture failed: '+result.stderr)
        report = json.loads(result.stdout)
        assert report['cleanup'] == 'passed' and report['published_ports'] == []
        assert report['backend'] == 'postgresql' and report['database_restore'] == 'passed'
        print(json.dumps(report, indent=2))


def main(project, release, engine=None, *, config_file):
    restore = load('restore-drill')
    snapshot = load('snapshot')
    config = restore.load_config(config_file)
    if config['project'] != project:
        raise ValueError('fixture config belongs to another project')
    revision = json.loads(release.read_text())['revision']
    if config['backend'] == 'postgresql':
        if not engine:
            raise SystemExit('--engine is required for a PostgreSQL product: pass the pinned '
                             'postgres@sha256:... digest this product deploys')
        return postgres_main(project, revision, engine, restore, snapshot, config=config, config_file=config_file)
    component = config['db']
    reference = f'{config["image_base"]}-{component}:{revision}'
    image = json.loads(restore.docker('image', 'inspect', reference))[0]['Id']
    binary = config['binary']
    data_path = config['data_path']
    # Empty configuration is intentional: this fixture cannot inspect any live
    # container or obtain a real settings encryption key.
    os.environ['PB_ENCRYPTION_KEY'] = ''
    with tempfile.TemporaryDirectory(prefix=f'{project}-restore-fixture-') as directory:
        root = Path(directory)
        data = root/'data'
        data.mkdir(mode=0o700)
        uid = os.getuid() or 65534
        if os.getuid() == 0:
            os.chown(data, uid, uid)
        name = project+'-restore-fixture-'+secrets.token_hex(8)
        try:
            restore.docker('run', '--name', name, '--network=none', '--read-only', '--user', f'{uid}:{uid}',
                '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--memory=192m', '--cpus=1', '--pids-limit=128',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m', '--mount', f'type=bind,src={data},dst={data_path}',
                '--entrypoint', binary, image, 'superuser', 'upsert', 'fixture@verification.invalid',
                secrets.token_hex(32), f'--dir={data_path}', timeout=180)
        finally:
            restore.docker('rm', '-f', '-v', name)
        archive = root/'data.tar.gz'
        with tarfile.open(archive, 'w:gz') as bundle:
            for item in sorted(data.rglob('*')):
                bundle.add(item, arcname=str(item.relative_to(data)), recursive=False)
        (root/'verification.json').write_text(json.dumps({
            'archive_sha256': snapshot.sha256(archive), 'image_id': image, 'image_reference': reference,
            'verified_at': datetime.now(timezone.utc).isoformat()}))
        key, cert = root/'key.pem', root/'recipient.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-keyout', str(key),
            '-out', str(cert), '-days', '1', '-subj', '/CN=disposable-restore-fixture'], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        sealed = snapshot.seal(root, cert)
        export = root/'export.tar'
        with tarfile.open(export, 'w') as bundle:
            for file in ('snapshot.cms', 'receipt.json'):
                bundle.add(sealed/file, arcname=file)
        # Exercise the same bounded stdin path as the fixed host wrapper.
        with export.open('rb') as incoming:
            result = subprocess.run(['python3', str(Path(__file__).with_name('restore-drill.py')),
                '--project', project, '--config', str(config_file), '--export', '-', '--key', str(key)], stdin=incoming,
                text=True, capture_output=True, timeout=930)
        if result.returncode:
            raise RuntimeError('offline restore fixture failed: '+result.stderr)
        report = json.loads(result.stdout)
        assert report['cleanup'] == 'passed' and report['published_ports'] == []
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True)
    parser.add_argument('--config', type=Path, default=Path('deploy/restore.json'))
    parser.add_argument('--release', type=Path, default=Path('.artifacts/release/release.json'))
    parser.add_argument('--engine', help='the pinned postgres@sha256:... digest, for a PostgreSQL product')
    args = parser.parse_args()
    os.umask(0o077)
    main(args.project, args.release, args.engine, config_file=args.config)
