import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location('upload_backup', Path(__file__).resolve().parents[1]/'helpers/upload-backup.py')
uploader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uploader)

SLUGS = ('sampleapp', 'samplestore', 'sampleconsole', 'sampleservice', 'samplegame', 'sampleaddon', 'samplehost')
STAMP = '20260918T080033Z'
CONTRACT = {
    'BACKUP_ALLOWED_SLUGS': json.dumps(SLUGS),
    'BACKUP_S3_ACCESS_KEY': 'test-access-key',
    'BACKUP_S3_SECRET_KEY': 'test-secret-key',
    'BACKUP_S3_HOSTNAME': 'objects.example.test',
    'BACKUP_S3_BUCKET': 'backup-bucket',
}
BLOB_NOT_FOUND = (b'<?xml version="1.0" encoding="utf-8"?><Error>'
                  b'<Code>BlobNotFound</Code>'
                  b'<Message>The specified blob does not exist.</Message></Error>')


class FakeResponse:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getcode(self):
        return self.status


class FakeHTTP:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.calls = []

    def __call__(self, request, timeout=None):
        body = request.data or b''
        digest = hashlib.sha256()
        length = 0
        for chunk in ([body] if isinstance(body, bytes) else body):
            digest.update(chunk)
            length += len(chunk)
        self.calls.append({
            'method': request.get_method(),
            'url': request.full_url,
            'headers': {key.lower(): value for key, value in request.header_items()},
            'sha256': digest.hexdigest(),
            'length': length,
            'timeout': timeout,
        })
        item = self.statuses.pop(0)
        status, error_body = item if isinstance(item, tuple) else (item, b'')
        if status >= 400:
            raise urllib.error.HTTPError(request.full_url, status, 'error', hdrs={}, fp=io.BytesIO(error_body))
        return FakeResponse(status)


class UploadBackup(unittest.TestCase):
    def env(self, **changes):
        values = {key: value for key, value in os.environ.items()
                  if key not in {*CONTRACT, 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                                 'HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'}}
        values.update(CONTRACT)
        for key, value in changes.items():
            if value is None:
                values.pop(key, None)
            else:
                values[key] = value
        return patch.dict(os.environ, values, clear=True)

    def pair(self, root, payload=b'encrypted', receipt=None):
        cms = root/'snapshot.cms'
        cms.write_bytes(payload)
        if receipt is None:
            receipt = {'format': 1, 'ciphertext_sha256': hashlib.sha256(payload).hexdigest(),
                       'archive_sha256': 'a'*64, 'image_id': 'sha256:'+'b'*64}
        path = root/'receipt.json'
        path.write_text(json.dumps(receipt))
        return cms, path

    def test_allowlist_is_caller_owned_and_fails_closed(self):
        for value in [None, '', '{}', '[]', '["sampleapp", "sampleapp"]',
                      '["../other"]', '["SampleApp"]', '[1]', 'not-json']:
            with self.env(BACKUP_ALLOWED_SLUGS=value):
                with self.assertRaises(ValueError):
                    uploader.object_keys('sampleapp', STAMP)
        with self.env(BACKUP_ALLOWED_SLUGS='["custom-project"]'):
            self.assertEqual(uploader.object_keys('custom-project', STAMP)[0],
                             f'custom-project-bk-{STAMP}.cms')
            with self.assertRaises(ValueError):
                uploader.object_keys('sampleapp', STAMP)

    def test_key_naming_for_each_allowed_slug(self):
        fake = FakeHTTP([200, 200] * len(SLUGS))
        with tempfile.TemporaryDirectory() as directory, self.env(), patch.object(uploader, 'urlopen', fake):
            cms, receipt = self.pair(Path(directory))
            for slug in SLUGS:
                result = uploader.upload(slug, cms, receipt, STAMP)
                cms_key = f'{slug}-bk-{STAMP}.cms'
                receipt_key = f'{slug}-bk-{STAMP}.receipt.json'
                self.assertEqual(result, {
                    'slug': slug, 'cms_key': cms_key, 'receipt_key': receipt_key,
                    'hostname': 'objects.example.test',
                })
        self.assertEqual(len(fake.calls), 2 * len(SLUGS))
        sampleaddon = [call for call in fake.calls if 'sampleaddon-bk-20260918T080033Z' in call['url']]
        self.assertEqual([call['url'] for call in sampleaddon], [
            'https://objects.example.test/backup-bucket/sampleaddon-bk-20260918T080033Z.cms',
            'https://objects.example.test/backup-bucket/sampleaddon-bk-20260918T080033Z.receipt.json',
        ])

    def test_path_style_url_uses_env_hostname_and_bucket(self):
        fake = FakeHTTP([200, 200])
        with tempfile.TemporaryDirectory() as directory, self.env(), patch.object(uploader, 'urlopen', fake):
            cms, receipt = self.pair(Path(directory))
            uploader.upload('sampleapp', cms, receipt, STAMP)
        self.assertEqual([call['method'] for call in fake.calls], ['PUT', 'PUT'])
        for call in fake.calls:
            self.assertTrue(call['url'].startswith('https://objects.example.test/backup-bucket/'))
            self.assertNotIn('backup-bucket.objects.example.test', call['url'])
            self.assertNotIn('vultrobjects', call['url'])
            self.assertEqual(call['headers'].get('if-none-match'), '*')
            self.assertEqual(call['headers'].get('x-amz-content-sha256'), call['sha256'])
            self.assertIn('us-east-1/s3/aws4_request', call['headers'].get('authorization', ''))
            self.assertIn('Credential=test-access-key/', call['headers'].get('authorization', ''))
            self.assertNotIn('AWS_ACCESS_KEY_ID', call['headers'].get('authorization', ''))

    def test_rejects_unknown_slug_bad_timestamp_missing_env_and_aws_names(self):
        with tempfile.TemporaryDirectory() as directory:
            cms, receipt = self.pair(Path(directory))
            with self.env(), patch.object(uploader, 'urlopen', FakeHTTP([])):
                with self.assertRaises(ValueError):
                    uploader.upload('unknown', cms, receipt, STAMP)
                with self.assertRaises(ValueError):
                    uploader.upload('sampleaddon', cms, receipt, '2026-09-18T08:00:33Z')
                with self.assertRaises(ValueError):
                    uploader.upload('sampleaddon', cms, receipt, '20261301T000000Z')
            for name in CONTRACT:
                if name == 'BACKUP_ALLOWED_SLUGS': continue
                with self.env(**{name: None}), patch.object(uploader, 'urlopen', FakeHTTP([])):
                    with self.assertRaises(ValueError):
                        uploader.upload('sampleaddon', cms, receipt, STAMP)
                with self.env(**{name: ''}), patch.object(uploader, 'urlopen', FakeHTTP([])):
                    with self.assertRaises(ValueError):
                        uploader.upload('sampleaddon', cms, receipt, STAMP)
            with self.env(AWS_ACCESS_KEY_ID='AKIA-WRONG'), patch.object(uploader, 'urlopen', FakeHTTP([])):
                with self.assertRaises(ValueError):
                    uploader.upload('sampleaddon', cms, receipt, STAMP)
            with self.env(AWS_SECRET_ACCESS_KEY='wrong-secret'), patch.object(uploader, 'urlopen', FakeHTTP([])):
                with self.assertRaises(ValueError):
                    uploader.upload('sampleaddon', cms, receipt, STAMP)

    def test_refused_overwrite_does_not_put_receipt(self):
        fake = FakeHTTP([412])
        with tempfile.TemporaryDirectory() as directory, self.env(), patch.object(uploader, 'urlopen', fake):
            cms, receipt = self.pair(Path(directory))
            with self.assertRaises(ValueError):
                uploader.upload('sampleaddon', cms, receipt, STAMP)
        self.assertEqual(len(fake.calls), 1)
        self.assertTrue(fake.calls[0]['url'].endswith('.cms'))

    def test_conditional_404_never_drops_no_overwrite_protection(self):
        fake = FakeHTTP([(404, BLOB_NOT_FOUND), 200])
        with tempfile.TemporaryDirectory() as directory, self.env(), patch.object(uploader, 'urlopen', fake):
            cms, receipt = self.pair(Path(directory))
            with self.assertRaisesRegex(RuntimeError, 'HTTP 404'):
                uploader.upload('sampleaddon', cms, receipt, STAMP)
        self.assertEqual(len(fake.calls),1)
        self.assertEqual(fake.calls[0]['headers']['if-none-match'],'*')

    def test_persistent_404_raises_with_the_provider_error_code(self):
        # A genuine 404 fails without a retry that could permit replacement.
        fake = FakeHTTP([(404, BLOB_NOT_FOUND), (404, BLOB_NOT_FOUND)])
        with tempfile.TemporaryDirectory() as directory, self.env(), patch.object(uploader, 'urlopen', fake):
            cms, receipt = self.pair(Path(directory))
            with self.assertRaisesRegex(RuntimeError, r'HTTP 404 \(BlobNotFound'):
                uploader.upload('sampleaddon', cms, receipt, STAMP)
        self.assertEqual(len(fake.calls), 1)

    def test_stream_memory_is_bounded_and_changed_inode_refuses(self):
        import tracemalloc
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'large.cms'
            with path.open('wb') as stream:
                stream.truncate(64*1024*1024)
            tracemalloc.start()
            try:
                with uploader.Ciphertext(path,uploader.time.monotonic()+10) as body:
                    count=sum(len(chunk) for chunk in body)
                    self.assertEqual(count,64*1024*1024)
                    self.assertLess(tracemalloc.get_traced_memory()[1],1024*1024)
                    with path.open('r+b') as out:out.write(b'changed')
                    with self.assertRaisesRegex(ValueError,'changed'):
                        next(iter(body))
            finally:tracemalloc.stop()

    def test_total_deadline_rejects_before_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            cms,_=self.pair(Path(directory))
            with self.assertRaises(TimeoutError):
                uploader.Ciphertext(cms,uploader.time.monotonic()-1)

    def test_missing_contract_env_names_the_variable_and_the_remedy(self):
        with tempfile.TemporaryDirectory() as directory:
            cms, receipt = self.pair(Path(directory))
            for name in CONTRACT:
                if name == 'BACKUP_ALLOWED_SLUGS': continue
                with self.env(**{name: None}), patch.object(uploader, 'urlopen', FakeHTTP([])):
                    with self.assertRaises(ValueError) as raised:
                        uploader.upload('sampleaddon', cms, receipt, STAMP)
                message = str(raised.exception)
                self.assertIn(f'missing {name}', message)
                self.assertIn('repo-level', message)
                self.assertIn('caller', message.lower())

    def test_cms_put_failure_does_not_attempt_receipt_put(self):
        fake = FakeHTTP([500])
        with tempfile.TemporaryDirectory() as directory, self.env(), patch.object(uploader, 'urlopen', fake):
            cms, receipt = self.pair(Path(directory))
            with self.assertRaises(RuntimeError):
                uploader.upload('sampleaddon', cms, receipt, STAMP)
        self.assertEqual(len(fake.calls), 1)
        self.assertTrue(fake.calls[0]['url'].endswith('.cms'))

    def test_receipt_put_failure_after_cms_success_raises(self):
        fake = FakeHTTP([200, 500])
        with tempfile.TemporaryDirectory() as directory, self.env(), patch.object(uploader, 'urlopen', fake):
            cms, receipt = self.pair(Path(directory))
            with self.assertRaisesRegex(RuntimeError, 'sampleaddon-bk-20260918T080033Z.cms'):
                uploader.upload('sampleaddon', cms, receipt, STAMP)
        self.assertEqual([call['url'].rsplit('/', 1)[-1] for call in fake.calls], [
            'sampleaddon-bk-20260918T080033Z.cms',
            'sampleaddon-bk-20260918T080033Z.receipt.json',
        ])

    def test_does_not_read_aws_access_key_id_as_credentials(self):
        fake = FakeHTTP([200, 200])
        with tempfile.TemporaryDirectory() as directory, self.env(), patch.object(uploader, 'urlopen', fake):
            cms, receipt = self.pair(Path(directory))
            uploader.upload('samplestore', cms, receipt, STAMP)
        authorization = fake.calls[0]['headers']['authorization']
        self.assertIn('Credential=test-access-key/', authorization)
        source = Path(__file__).resolve().parents[1].joinpath('helpers/upload-backup.py').read_text()
        self.assertIn('BACKUP_S3_ACCESS_KEY', source)
        self.assertNotRegex(source, r"os\.environ\.get\('AWS_ACCESS_KEY_ID'\)")
        self.assertEqual(uploader.CONTRACT[0], 'BACKUP_S3_ACCESS_KEY')

    def test_no_boto3_import(self):
        self.assertNotIn('boto3', sys.modules)
        self.assertNotIn('botocore', sys.modules)
        self.assertNotIn('boto3', Path(__file__).resolve().parents[1].joinpath('helpers/upload-backup.py').read_text())
        self.assertNotIn('import boto', Path(__file__).resolve().parents[1].joinpath('helpers/upload-backup.py').read_text())

    def test_checksum_mismatch_and_symlink_refuse_before_http(self):
        fake = FakeHTTP([])
        with tempfile.TemporaryDirectory() as directory, self.env(), patch.object(uploader, 'urlopen', fake):
            root = Path(directory)
            cms, receipt = self.pair(root, payload=b'encrypted',
                                     receipt={'format': 1, 'ciphertext_sha256': 'c'*64})
            with self.assertRaises(ValueError):
                uploader.upload('sampleaddon', cms, receipt, STAMP)
            matching = root/'receipt-ok.json'
            matching.write_text(json.dumps({'format': 1, 'ciphertext_sha256': hashlib.sha256(b'encrypted').hexdigest()}))
            link = root/'link.cms'
            link.symlink_to(cms)
            with self.assertRaises(ValueError):
                uploader.upload('sampleaddon', link, matching, STAMP)
        self.assertEqual(fake.calls, [])


if __name__ == '__main__':
    unittest.main()
