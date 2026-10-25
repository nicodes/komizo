#!/usr/bin/env python3
"""Test immutable creation using one tiny synthetic object, never a real backup.

A provider must create the first conditioned PUT, reject a changed duplicate,
then return the unchanged original bytes. No condition is dropped on failure.
The unique probe object is retained as evidence; production keys are untouched.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

spec = importlib.util.spec_from_file_location('backup_transport', Path(__file__).with_name('upload-backup.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
SECONDS = 90


def probe(credentials=None, put=None, open_request=None):
    credentials = credentials or transport.credentials()
    put = put or transport.put_object
    open_request = open_request or transport.urlopen
    deadline = time.monotonic()+SECONDS
    key = 'komizo-capability/'+secrets.token_hex(16)+'.txt'
    original = b'Komizo synthetic immutable-creation capability probe v1\n'
    url = 'https://'+credentials['BACKUP_S3_HOSTNAME']+'/'+credentials['BACKUP_S3_BUCKET']+'/'+key
    params = (credentials['BACKUP_S3_ACCESS_KEY'], credentials['BACKUP_S3_SECRET_KEY'], credentials['BACKUP_S3_HOSTNAME'], deadline)
    result = {'version': 1, 'kind': 'synthetic-immutable-creation', 'key': key,
              'observed_at': datetime.now(timezone.utc).isoformat(), 'bytes': len(original),
              'sha256': hashlib.sha256(original).hexdigest(), 'compatible': False}
    try:
        put(url, original, 'text/plain', *params)
    except (ValueError, RuntimeError, OSError) as error:
        result['reason'] = 'conditioned first creation refused'
        cause = error.__cause__
        if isinstance(cause, urllib.error.HTTPError): result['http_status'] = cause.code
        return result
    try:
        put(url, b'changed duplicate must never replace original\n', 'text/plain', *params)
    except ValueError as error:
        cause = error.__cause__
        if not isinstance(cause, urllib.error.HTTPError) or cause.code not in (409, 412):
            result['reason'] = 'duplicate refusal was not a verified conditional conflict'
            return result
        result['duplicate_status'] = cause.code
    except (RuntimeError, OSError):
        result['reason'] = 'duplicate creation could not be verified'
        return result
    else:
        result['reason'] = 'provider accepted overwrite despite immutable condition'
        return result
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    empty = hashlib.sha256(b'').hexdigest()
    headers = {'Host': params[2], 'x-amz-date': stamp, 'x-amz-content-sha256': empty}
    headers['Authorization'] = transport.authorization('GET',url,headers,empty,params[0],params[1])
    request = urllib.request.Request(url,headers=headers,method='GET')
    request.deadline = deadline
    try:
        with open_request(request,timeout=transport.remaining(deadline)) as response:
            body = response.read(len(original)+1)
            if response.status != 200 or body != original:
                result['reason'] = 'original bytes were not preserved'
                return result
    except (ValueError, RuntimeError, OSError):
        result['reason'] = 'original object could not be independently read'
        return result
    result['compatible'] = True
    return result


if __name__ == '__main__':
    if sys.argv[1:] != ['--worker']:
        if sys.argv[1:]: raise SystemExit('probe accepts no arguments')
        try:
            worker = subprocess.run([sys.executable,'-I',str(Path(__file__).resolve()),'--worker'],timeout=SECONDS)
        except subprocess.TimeoutExpired:
            raise SystemExit('synthetic storage probe exceeded its deadline; inspect retained probe before retry')
        raise SystemExit(worker.returncode)
    try:
        result = probe()
    except (ValueError, OSError):
        raise SystemExit('synthetic storage probe configuration refused')
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if result['compatible'] else 1)
