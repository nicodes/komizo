#!/usr/bin/env python3
"""Create a private, audience-bound routine-backup frame inside GitHub Actions."""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import urllib.parse


def manifest(environment):
    if environment.get('GITHUB_REF') != 'refs/heads/main' or environment.get('GITHUB_EVENT_NAME') not in ('schedule', 'workflow_dispatch'):
        raise ValueError('backup proof requires a scheduled or dispatched main workflow')
    fields = {'repository': ('GITHUB_REPOSITORY', r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'),
              'repository_id': ('GITHUB_REPOSITORY_ID', r'[1-9][0-9]{0,19}'),
              'revision': ('GITHUB_SHA', r'[a-f0-9]{40}'),
              'run_id': ('GITHUB_RUN_ID', r'[1-9][0-9]{0,19}'),
              'attempt': ('GITHUB_RUN_ATTEMPT', r'[1-9][0-9]{0,19}')}
    result = {'version': 1, 'purpose': 'routine-backup'}
    for key, (variable, pattern) in fields.items():
        value = environment.get(variable, '')
        if not re.fullmatch(pattern, value):
            raise ValueError('backup workflow identity is missing or invalid')
        result[key] = value
    return (json.dumps(result, sort_keys=True, separators=(',', ':'))+'\n').encode()


def identity(environment, audience):
    url = urllib.parse.urlsplit(environment.get('ACTIONS_ID_TOKEN_REQUEST_URL', ''))
    token = environment.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN', '')
    if (url.scheme != 'https' or not url.hostname or not url.hostname.endswith('.actions.githubusercontent.com')
            or url.username or url.password or url.port not in (None, 443) or url.fragment
            or not token or len(token) > 8192 or any(c in token for c in '\r\n\x00')):
        raise ValueError('GitHub OIDC request authority is unavailable')
    query = [(k, v) for k, v in urllib.parse.parse_qsl(url.query) if k != 'audience']
    path = urllib.parse.urlunsplit(('', '', url.path, urllib.parse.urlencode(query+[('audience', audience)]), ''))
    connection = http.client.HTTPSConnection(url.hostname, port=url.port or 443, timeout=10)
    try:
        connection.request('GET', path, headers={'Authorization': 'Bearer '+token})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError('GitHub OIDC request refused')
        body = response.read((32 << 10)+1)
        if len(body) > 32 << 10:
            raise ValueError('GitHub OIDC response exceeds its bound')
        document = json.loads(body)
        value = document.get('value') if isinstance(document, dict) else None
        if not isinstance(value, str) or not 0 < len(value) <= 24 << 10 or value.count('.') != 2 or any(c in value for c in '\r\n\x00'):
            raise ValueError('GitHub OIDC response has no bounded token')
        return value
    finally:
        connection.close()


def prepare(output, environment=None):
    environment = os.environ if environment is None else environment
    raw = manifest(environment)
    if not output.is_absolute() or output.resolve(strict=False) != output or output.exists() or output.is_symlink():
        raise ValueError('backup proof needs a new absolute private file')
    info = output.parent.lstat()
    if not output.parent.is_dir() or output.parent.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('backup proof parent must be protected')
    audience = 'komizo-operation:sha256:'+hashlib.sha256(raw).hexdigest()
    signed = identity(environment, audience)
    envelope = json.dumps({'manifest': base64.b64encode(raw).decode(), 'token': signed}, separators=(',', ':')).encode()
    frame = b'komizo-operation/v1:'+base64.b64encode(envelope)+b'\n'
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(frame)
        stream.flush()
        os.fsync(stream.fileno())
    return {'prepared': True, 'purpose': 'routine-backup', 'manifest_sha256': hashlib.sha256(raw).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.output)))
    except (ValueError, OSError, http.client.HTTPException):
        raise SystemExit('backup proof preparation refused; no token is logged') from None
