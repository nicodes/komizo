#!/usr/bin/env python3
"""PUT sealed backup ciphertext to S3-compatible storage from a CI runner."""
import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def allowed_slugs():
    try:
        values = json.loads(os.environ.get('BACKUP_ALLOWED_SLUGS', 'null'))
    except json.JSONDecodeError as error:
        raise ValueError('BACKUP_ALLOWED_SLUGS must be a reviewed JSON array') from error
    if (not isinstance(values, list) or not 1 <= len(values) <= 100
            or any(not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', value) for value in values)
            or len(set(values)) != len(values)):
        raise ValueError('BACKUP_ALLOWED_SLUGS must contain distinct reviewed project slugs')
    return values

MAX_CMS = 17 * 1024**3
MAX_RECEIPT = 64 * 1024
CHUNK_BYTES = 64 * 1024
TOTAL_SECONDS = 600
REGION = 'us-east-1'
SERVICE = 's3'
TAKEN_AT = re.compile(r'[0-9]{8}T[0-9]{6}Z')
BUCKET = re.compile(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]')
LABEL = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?')
CONTRACT = ('BACKUP_S3_ACCESS_KEY', 'BACKUP_S3_SECRET_KEY', 'BACKUP_S3_HOSTNAME', 'BACKUP_S3_BUCKET')
FORBIDDEN = ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY')


class RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('backup PUT refused an HTTP redirect')


def urlopen(request, timeout=600):
    deadline = getattr(request, 'deadline', time.monotonic()+timeout)
    class Connection(http.client.HTTPSConnection):
        def connect(self):
            self.timeout = remaining(deadline)
            super().connect()
        def send(self, data):
            if self.sock is None:
                self.connect()
            self.sock.settimeout(remaining(deadline))
            super().send(data)
        def getresponse(self):
            self.sock.settimeout(remaining(deadline))
            return super().getresponse()
    class Transport(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(Connection, req, context=self._context)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RefuseRedirect(), Transport())
    return opener.open(request, timeout=timeout)


def remaining(deadline):
    seconds = deadline-time.monotonic()
    if seconds <= 0:
        raise TimeoutError('backup transport exceeded its total deadline')
    return min(seconds, 10)


class Ciphertext:
    """One validated open inode, bounded hash/upload buffers, no whole-file copy."""
    def __init__(self, path, deadline):
        self.deadline = deadline
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise ValueError('snapshot.cms must be an accessible non-symlink regular file') from None
        self.stream = os.fdopen(fd, 'rb')
        self.info = os.fstat(fd)
        if not stat.S_ISREG(self.info.st_mode) or not 0 < self.info.st_size <= MAX_CMS:
            self.stream.close()
            raise ValueError('snapshot.cms must be a bounded nonempty regular file')
        self.size = self.info.st_size
        try:
            self.sha256 = self.hash()
        except BaseException:
            self.stream.close()
            raise

    def unchanged(self):
        now = os.fstat(self.stream.fileno())
        if any(getattr(now, key) != getattr(self.info, key) for key in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise ValueError('encrypted export changed during transport')

    def __iter__(self):
        self.unchanged()
        self.stream.seek(0)
        consumed = 0
        while consumed < self.size:
            remaining(self.deadline)
            chunk = self.stream.read(min(CHUNK_BYTES, self.size-consumed))
            if not chunk:
                raise ValueError('encrypted export was truncated')
            consumed += len(chunk)
            yield chunk
        self.unchanged()
        remaining(self.deadline)

    def hash(self):
        digest = hashlib.sha256()
        for chunk in self:
            digest.update(chunk)
        return digest.hexdigest()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()


def hmac_sha256(key, message):
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hmac.new(key, message, hashlib.sha256).digest()


def read_regular_file(path, limit, label):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError(f'{label} must be an accessible non-symlink regular file') from None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError(f'{label} must be a bounded regular file')
        data = stream.read(limit+1)
        after = os.fstat(stream.fileno())
        if len(data) > limit or any(getattr(info,k) != getattr(after,k) for k in ('st_size','st_mtime_ns','st_ctime_ns')):
            raise ValueError(f'{label} changed or exceeds its size bound')
        return data


def hostname(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 253 or any(mark in value for mark in ':/?#[]@'):
        raise ValueError('invalid BACKUP_S3_HOSTNAME')
    if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', value):
        raise ValueError('invalid BACKUP_S3_HOSTNAME')
    labels = value.split('.')
    if len(labels) < 2 or any(not LABEL.fullmatch(label) for label in labels):
        raise ValueError('invalid BACKUP_S3_HOSTNAME')
    return value


def bucket_name(value):
    if not isinstance(value, str) or not BUCKET.fullmatch(value) or '..' in value or re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', value):
        raise ValueError('invalid BACKUP_S3_BUCKET')
    return value


def object_keys(slug, taken_at):
    if slug not in allowed_slugs():
        raise ValueError('unknown backup slug')
    if not isinstance(taken_at, str) or not TAKEN_AT.fullmatch(taken_at):
        raise ValueError('invalid taken-at timestamp')
    try:
        datetime.strptime(taken_at, '%Y%m%dT%H%M%SZ')
    except ValueError as error:
        raise ValueError('invalid taken-at timestamp') from error
    prefix = f'{slug}-bk-{taken_at}'
    return f'{prefix}.cms', f'{prefix}.receipt.json'


def credentials():
    for name in FORBIDDEN:
        if name in os.environ:
            raise ValueError('refusing AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY; use BACKUP_S3_* names')
    values = {}
    for name in CONTRACT:
        value = os.environ.get(name)
        if not isinstance(value, str) or value == '':
            kind = 'secret' if name in ('BACKUP_S3_ACCESS_KEY', 'BACKUP_S3_SECRET_KEY') else 'variable'
            raise ValueError(
                f'missing {name}: the reusable backup workflow reads it from a repo-level '
                f'{kind} in the CALLER repository. Environment-scoped secrets resolve empty '
                'through workflow_call, and `secrets: inherit` only forwards names that '
                f'exist; create {name} at repository level in the caller and re-run')
        values[name] = value
    values['BACKUP_S3_HOSTNAME'] = hostname(values['BACKUP_S3_HOSTNAME'])
    values['BACKUP_S3_BUCKET'] = bucket_name(values['BACKUP_S3_BUCKET'])
    return values


def error_detail(error):
    """Reduce a bounded slice of the provider's error body to its S3 code/message."""
    try:
        body = error.read(4096)
    except (OSError, ValueError):
        return ''
    if not body:
        return ''
    text = body.decode('utf-8', 'replace')
    code = re.search(r'<Code>([^<]+)</Code>', text)
    message = re.search(r'<Message>([^<]+)</Message>', text)
    if code:
        detail = code.group(1).strip()
        if message:
            detail = f'{detail}: {message.group(1).strip()}'
        return f' ({detail})'
    snippet = ' '.join(text.split())[:200]
    return f' ({snippet})' if snippet else ''


def authorization(method, url, headers, payload_hash, access_key, secret_key):
    parsed = urllib.parse.urlsplit(url)
    canonical_uri = urllib.parse.quote(parsed.path or '/', safe='/')
    normalized = {key.lower(): value.strip() for key, value in headers.items()}
    signed = ';'.join(sorted(normalized))
    canonical_headers = ''.join(f'{key}:{normalized[key]}\n' for key in sorted(normalized))
    canonical_request = '\n'.join([method, canonical_uri, parsed.query, canonical_headers, signed, payload_hash])
    amz_date = normalized['x-amz-date']
    scope = f'{amz_date[:8]}/{REGION}/{SERVICE}/aws4_request'
    string_to_sign = '\n'.join([
        'AWS4-HMAC-SHA256', amz_date, scope,
        hashlib.sha256(canonical_request.encode('utf-8')).hexdigest(),
    ])
    signing_key = hmac_sha256(hmac_sha256(hmac_sha256(hmac_sha256(('AWS4' + secret_key).encode('utf-8'), amz_date[:8]), REGION), SERVICE), 'aws4_request')
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    return f'AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}'


def put_object(url, body, content_type, access_key, secret_key, host, deadline=None):
    deadline = deadline or time.monotonic()+TOTAL_SECONDS
    payload_hash = body.sha256 if isinstance(body, Ciphertext) else hashlib.sha256(body).hexdigest()
    now = datetime.now(timezone.utc)
    headers = {
        'Host': host,
        'Content-Type': content_type,
        'x-amz-content-sha256': payload_hash,
        'x-amz-date': now.strftime('%Y%m%dT%H%M%SZ'),
        'Content-Length': str(body.size if isinstance(body, Ciphertext) else len(body)),
        'If-None-Match': '*',
    }
    headers['Authorization'] = authorization('PUT', url, headers, payload_hash, access_key, secret_key)
    request = urllib.request.Request(url, data=body, method='PUT', headers=headers)
    request.deadline = deadline
    try:
        with urlopen(request, timeout=remaining(deadline)) as response:
            remaining(deadline)
            status = getattr(response, 'status', None) or response.getcode()
            if status not in {200, 201, 204}:
                raise RuntimeError(f'backup PUT returned HTTP {status}')
            return status
    except urllib.error.HTTPError as error:
        if error.code in {409, 412}:
            raise ValueError(f'backup object already exists{error_detail(error)}') from error
        raise RuntimeError(f'backup PUT returned HTTP {error.code}{error_detail(error)}') from error
    except urllib.error.URLError as error:
        raise RuntimeError(f'backup PUT could not reach {host}: {error.reason}') from error


def upload(slug, cms, receipt, taken_at):
    with Ciphertext(cms, time.monotonic()+TOTAL_SECONDS) as body:
        return upload_pair(slug, body, receipt, taken_at)


def upload_pair(slug, cms_body, receipt, taken_at):
    cms_key, receipt_key = object_keys(slug, taken_at)
    receipt_body = read_regular_file(receipt, MAX_RECEIPT, 'receipt.json')
    try:
        envelope = json.loads(receipt_body.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('receipt is not valid JSON') from error
    if not isinstance(envelope, dict) or envelope.get('format') != 1:
        raise ValueError('unknown encrypted envelope format')
    digest = envelope.get('ciphertext_sha256')
    if not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest):
        raise ValueError('invalid export checksum')
    if cms_body.sha256 != digest:
        raise ValueError('encrypted export transport checksum mismatch')
    secret = credentials()
    host, bucket = secret['BACKUP_S3_HOSTNAME'], secret['BACKUP_S3_BUCKET']
    cms_url = f'https://{host}/{bucket}/{cms_key}'
    receipt_url = f'https://{host}/{bucket}/{receipt_key}'
    put_object(cms_url, cms_body, 'application/octet-stream',
               secret['BACKUP_S3_ACCESS_KEY'], secret['BACKUP_S3_SECRET_KEY'], host, cms_body.deadline)
    cms_body.unchanged()
    try:
        put_object(receipt_url, receipt_body, 'application/json',
                   secret['BACKUP_S3_ACCESS_KEY'], secret['BACKUP_S3_SECRET_KEY'], host, cms_body.deadline)
    except (ValueError, RuntimeError, OSError) as error:
        raise RuntimeError(f'receipt PUT failed after {cms_key} may now exist') from error
    return {'slug': slug, 'cms_key': cms_key, 'receipt_key': receipt_key, 'hostname': host}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slug', required=True)
    parser.add_argument('--cms', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--taken-at', required=True)
    parser.add_argument('--transport-worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    if not args.transport_worker:
        # Also bound DNS resolution and any OS/library stall. This child alone
        # owns the transport; no ambient process or production service is killed.
        try:
            result = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()),
                                     *sys.argv[1:], '--transport-worker'], timeout=TOTAL_SECONDS)
        except subprocess.TimeoutExpired:
            raise SystemExit('backup upload interrupted at its deadline; object may exist; inspect before retry')
        raise SystemExit(result.returncode)
    print(json.dumps(upload(args.slug, args.cms, args.receipt, args.taken_at), indent=2))


if __name__ == '__main__':
    main()
