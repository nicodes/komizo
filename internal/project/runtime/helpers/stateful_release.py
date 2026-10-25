"""Small caller-owned data/credential contract; execution stays product-owned.

An image identity never authorizes replacing data. Forward-only is the default.
Rollback additionally needs exact disposable read/write evidence for both
binaries, the observed schema and unchanged data/credential contracts.
"""
import hashlib
import json
import re
import subprocess
from pathlib import Path

SHA = re.compile(r'[a-f0-9]{64}')
REVISION = re.compile(r'[a-f0-9]{40}')
IDENTITY = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}')


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate stateful contract field')
        value[key] = item
    return value


def materialize(path, revision):
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise ValueError('migration source needs an exact commit revision')
    path = Path(path)
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents) or not path.is_file() or path.stat().st_size > 32768:
        raise ValueError('stateful declaration must be a bounded regular caller-owned file')
    value = json.loads(path.read_bytes(), object_pairs_hook=_unique)
    if not isinstance(value, dict) or 'source_revision' in value:
        raise ValueError('the producer supplies the exact checked-out source revision')
    # Caller-owned source paths are producer inputs, never host execution
    # instructions. When supplied, verify both the migration bytes and their
    # immutable Git blob, then omit the path from the transport contract.
    migrations = value.get('migrations')
    if isinstance(migrations, list):
        normalized = []
        for entry in migrations:
            if isinstance(entry, dict) and 'source_path' in entry:
                if set(entry) != {'identity', 'sha256', 'source_path'}:
                    raise ValueError('invalid migration source binding')
                relative = entry['source_path']
                if (not isinstance(relative, str) or not re.fullmatch(r'[a-zA-Z0-9_./-]{1,256}', relative)
                        or relative.startswith('/') or any(part in {'', '.', '..'} for part in relative.split('/'))):
                    raise ValueError('migration source must be a clean repository-relative path')
                source = Path.cwd()/relative
                if (source.is_symlink() or any(parent.is_symlink() for parent in source.parents)
                        or not source.is_file() or source.stat().st_size > 4*1024*1024):
                    raise ValueError('migration source must be a bounded regular tracked file')
                raw = source.read_bytes()
                if hashlib.sha256(raw).hexdigest() != entry['sha256']:
                    raise ValueError('migration checksum differs from source')
                expected = subprocess.check_output(['git', 'rev-parse', revision+':'+relative], text=True, timeout=10).strip()
                actual = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
                if expected != actual:
                    raise ValueError('migration source differs from the immutable checked-out Git blob')
                entry = {key: entry[key] for key in ('identity', 'sha256')}
            normalized.append(entry)
        value = {**value, 'migrations': normalized}
    return validate({**value, 'source_revision': revision}, revision)


def validate(value, revision=None):
    if (not isinstance(value, dict) or set(value) != {'version', 'source_revision', 'schema',
            'data_revision', 'credential_revision', 'migrations', 'recovery_action'}
            or type(value['version']) is not int or value['version'] != 1
            or not isinstance(value['source_revision'], str) or not REVISION.fullmatch(value['source_revision'])
            or revision is not None and value['source_revision'] != revision):
        raise ValueError('stateful contract has an invalid exact source identity')
    schema = value['schema']
    if (not isinstance(schema, dict) or set(schema) != {'minimum', 'maximum', 'write'}
            or any(type(schema[key]) is not int or not 1 <= schema[key] <= 1000000 for key in schema)
            or not schema['minimum'] <= schema['write'] <= schema['maximum']):
        raise ValueError('invalid required schema range')
    for key in ('data_revision', 'credential_revision'):
        if not isinstance(value[key], str) or not IDENTITY.fullmatch(value[key]):
            raise ValueError('invalid data or credential revision')
    if not isinstance(value['recovery_action'], str) or value['recovery_action'] not in {'forward_only', 'image_rollback'}:
        raise ValueError('unsupported recovery action; restoring data is separate owner authority')
    migrations = value['migrations']
    if not isinstance(migrations, list) or not 1 <= len(migrations) <= 128:
        raise ValueError('stateful contract requires bounded migration identities')
    names = set()
    for entry in migrations:
        if (not isinstance(entry, dict) or set(entry) != {'identity', 'sha256'}
                or not isinstance(entry['identity'], str) or not IDENTITY.fullmatch(entry['identity'])
                or not isinstance(entry['sha256'], str) or not SHA.fullmatch(entry['sha256'])
                or entry['identity'] in names):
            raise ValueError('invalid or duplicate migration identity/checksum')
        names.add(entry['identity'])
    return value


def identity(value):
    validate(value)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def check_rollback(current, previous, evidence, current_revision, previous_revision, run_id):
    validate(current, current_revision)
    validate(previous, previous_revision)
    if current['recovery_action'] != 'image_rollback':
        raise ValueError('release is forward-only')
    if (not isinstance(evidence, dict) or type(evidence.get('version')) is not int or evidence['version'] != 2
            or evidence.get('current_contract_sha256') != identity(current)
            or evidence.get('previous_contract_sha256') != identity(previous)
            or evidence.get('current_revision') != current_revision or evidence.get('previous_revision') != previous_revision
            or evidence.get('run_id') != run_id or not isinstance(run_id, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', run_id)):
        raise ValueError('compatibility fixture belongs to another contract/run/revision')
    observed = evidence.get('observed_schema')
    if type(observed) is not int or observed != current['schema']['write'] or not previous['schema']['minimum'] <= observed <= previous['schema']['maximum']:
        raise ValueError('previous binary does not support the post-write schema')
    for key in ('data_revision', 'credential_revision'):
        if current[key] != previous[key] or evidence.get(key) != current[key]:
            raise ValueError('post-write data or credentials are incompatible')
    # Old migrations cannot be silently redefined by an additive release.
    old = {entry['identity']: entry['sha256'] for entry in previous['migrations']}
    new = {entry['identity']: entry['sha256'] for entry in current['migrations']}
    if any(new.get(name) != checksum for name, checksum in old.items()):
        raise ValueError('already-applied migration changed or disappeared')
    required = {'new_migrations', 'new_write', 'previous_read', 'previous_write',
                'previous_reload_read', 'new_reload_read'}
    if (evidence.get('status') != 'passed' or evidence.get('operations') != {key: 'passed' for key in required}
            or not SHA.fullmatch(str(evidence.get('snapshot_sha256', '')))):
        raise ValueError('both binaries must preserve writes in the exact disposable fixture')
    return True
