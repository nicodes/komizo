#!/usr/bin/env python3
"""Capture the disposable native PostgreSQL instance through its owned client."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil

PROJECT = 'pgbox'
RECOVERY_ROOT = None
_installed = None


def helper(name):
    if not isinstance(RECOVERY_ROOT, Path) or name not in {'installed_resource', 'postgres_client'}:
        raise ValueError('native capture requires its finite verified helper bundle')
    spec = importlib.util.spec_from_file_location('native_capture_' + name, RECOVERY_ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def capture(destination):
    destination = Path(destination)
    if (destination.is_symlink() or not destination.is_dir() or not destination.name.startswith('.export-')
            or destination.stat().st_mode & 0o077):
        raise ValueError('native capture requires private protected export staging')
    resources = helper('installed_resource')
    clients = helper('postgres_client')
    records = [resources.query(PROJECT, 'postgres')]
    revision, images, deployment = resources.metadata(records)
    if deployment['release']['source']['repository'] != 'nicodes/komizo':
        raise ValueError('native fixture capture selected another source repository')
    target = destination / 'capture'
    target.mkdir(mode=0o700)
    complete = False
    try:
        with clients.context(resources, records[0], destination, database='postgres', role='fixture', timeout=30) as client:
            if not re.match(r'^pg_dump \(PostgreSQL\) 18\.6(?:\s|$)', client.version()):
                raise ValueError('native capture requires its pinned PostgreSQL client')
            with client.session() as session:
                session.begin()
                if not re.fullmatch(r'18[0-9]{4}', session.query("SELECT current_setting('server_version_num')")):
                    raise ValueError('native capture server version differs')
                snapshot = session.export_snapshot()
                roles = session.query("SELECT rolname FROM pg_roles WHERE rolname='fixture'")
                if roles != 'fixture':
                    raise ValueError('native capture lost its initialized owner role')
                dump = target / 'database.dump'
                client.dump(snapshot, dump)
                if not 5 <= dump.stat().st_size <= 1 << 20 or not dump.read_bytes().startswith(b'PGDMP'):
                    raise ValueError('native capture has no bounded actual custom dump')
                session.verify_snapshot()
                session.commit()
            resources.unchanged(records)
        # The client helper must finish its ownership-checked cleanup before a
        # completed capture can authorize packaging or encrypted export.
        resources.unchanged(records)
        evidence = {'snapshot_id': snapshot, 'reclamation_fenced': True,
            'completed_at': datetime.now(timezone.utc).isoformat(), 'database': 'postgres', 'major': 18,
            'files': {'database.dump': {'size': dump.stat().st_size,
                'sha256': hashlib.sha256(dump.read_bytes()).hexdigest()}}}
        record = records[0]
        metadata = {'project': PROJECT, 'revision': revision, 'role_namespace': 'fixture', 'roles': ['fixture'],
            'engine': {'reference': record['image_ref'], 'image_id': record['image_config_digest'], 'major': 18},
            'images': images, 'deployment': deployment}
        for path, value in [(target / 'capture.json', evidence), (destination / 'images.json', metadata)]:
            path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')))
            path.chmod(0o600)
        complete = True
        return target
    finally:
        if not complete:
            shutil.rmtree(target)
            (destination / 'images.json').unlink(missing_ok=True)
