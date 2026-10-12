import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import tarfile
import tempfile
import unittest
import contextlib
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).parent/'assets/fleet_publisher.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
REVISION, TREE = 'a'*40, 'd'*40
REFERENCE = 'ghcr.io/owner/product:'+REVISION


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root/'state'
        self.state.mkdir(mode=0o700)
        (self.state/'artifacts').mkdir(mode=0o700)
        for name, value in [('STATE', self.state), ('DELIVERIES', self.root/'deliveries'), ('OWNER', os.getuid())]:
            context = patch.object(publisher, name, value)
            context.start();self.addCleanup(context.stop)
        context = patch.object(publisher.operator, 'LOCKS', self.root/'locks')
        context.start();self.addCleanup(context.stop)
        context = patch.object(publisher.operator, 'lock_owner', lambda info: info.st_uid == os.getuid())
        context.start();self.addCleanup(context.stop)
        # A CI worker's tmp parent is legitimately UID 0. Only fixture ownership
        # is substituted; the executable remains a Root-only entry point.
        def protected(path):
            for parent in (path, *path.parents):
                info = parent.lstat()
                if parent.is_symlink() or not parent.is_dir() or info.st_mode & 0o022:
                    raise ValueError('unprotected fixture ancestry')
                if parent == self.root:
                    break
        context = patch.object(publisher, 'protected_directory', protected)
        context.start();self.addCleanup(context.stop)
        @contextlib.contextmanager
        def configuration():
            with tempfile.TemporaryDirectory(prefix='registry-', dir=self.root) as directory:
                yield Path(directory)
        context = patch.object(publisher, 'registry_configuration', configuration)
        context.start();self.addCleanup(context.stop)
        self.request = {'operation': 'publish', 'repository': 'owner/product', 'revision': REVISION, 'run_id': 42, 'artifact_id': 55}
        workflow = {'workflow_id': 100, 'workflow_path': '.github/workflows/cd.yml', 'app_id': 15368,
                    'event': 'push', 'jobs': ['Build'], 'integration_job': 'build'}
        token = self.root/'token'
        token.write_bytes(b'synthetic-fixture-token')
        token.chmod(0o600)
        self.contract = {'workflow': workflow, 'images': ['ghcr.io/owner/product'], 'username': 'owner', 'credential': str(token)}
        self.policy = {'version': 1, 'repositories': {'owner/product': self.contract}}
        now = datetime.now(timezone.utc)
        self.grant = {'version': 1, 'repository': 'owner/product', 'revision': REVISION, 'tree': TREE,
                      'head': 'b'*40, 'base': 'c'*40, 'kind': 'merge', 'scope': 'production-delivery',
                      'issued_at': now.isoformat(), 'expires_at': (now+timedelta(hours=1)).isoformat()}
        publisher.persist_delivery(self.grant)
        self.generation = 2
        self.producer_app = 15368
        self.main_reads = 0
        self.race_at = 0
        self.calls = []
        self.directories = []
        self.archive()

    def archive(self, *, bad_layer=False, foreign=False, revision=REVISION, linked=False):
        layer = b'synthetic uncompressed docker layer'
        configuration = json.dumps({'os': 'linux', 'architecture': 'amd64',
            'config': {'Labels': {'org.opencontainers.image.revision': revision,
                                 'org.opencontainers.image.source': 'https://github.com/owner/product'}},
            'rootfs': {'diff_ids': ['sha256:'+hashlib.sha256(layer).hexdigest()]}}).encode()
        self.config_sha = hashlib.sha256(configuration).hexdigest()
        reference = 'ghcr.io/owner/foreign:'+REVISION if foreign else REFERENCE
        image = io.BytesIO()
        with tarfile.open(fileobj=image, mode='w') as archive:
            files = {'manifest.json': json.dumps([{'Config': 'config.json', 'RepoTags': [reference], 'Layers': ['layer.tar']}]).encode(),
                     'config.json': configuration, 'layer.tar': layer+b'altered' if bad_layer else layer}
            for name, body in files.items():
                entry = tarfile.TarInfo(name);entry.size = len(body)
                archive.addfile(entry, io.BytesIO(body))
            if linked:
                entry = tarfile.TarInfo('escape');entry.type = tarfile.SYMTYPE;entry.linkname = '/etc/shadow'
                archive.addfile(entry)
        manifest = {'version': 1, 'repository': 'owner/product', 'revision': REVISION, 'tree': TREE,
                    'run_id': 42, 'attempt': 2, 'images': {reference: self.config_sha}}
        self.path = self.state/'artifacts/55.zip'
        with zipfile.ZipFile(self.path, 'w') as archive:
            archive.writestr('release.json', json.dumps(manifest))
            archive.writestr('images.tar', image.getvalue())
        self.path.chmod(0o600)
        self.archive_sha = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def backend(self, args):
        url = args[-1]
        if url.endswith('/git/ref/heads/main'):
            self.main_reads += 1
            return {'object': {'sha': 'f'*40 if self.main_reads == self.race_at else REVISION}}
        if '/git/commits/' in url:
            return {'sha': REVISION, 'tree': {'sha': TREE}, 'parents': [{'sha': 'c'*40}, {'sha': 'b'*40}]}
        if url.endswith('/check-runs?per_page=100'):
            return {'total_count': 1, 'check_runs': [{'name': 'Build', 'status': 'completed', 'conclusion': 'success',
                     'details_url': 'https://github.com/owner/product/actions/runs/42/job/101'}]}
        if '/attempts/' in url:
            return {'total_count': 1, 'jobs': [{'id': 101, 'name': 'Build', 'run_attempt': self.generation, 'head_sha': REVISION,
                'status': 'completed', 'conclusion': 'success', 'check_run_url': 'https://api.github.com/repos/owner/product/check-runs/201'}]}
        if '/check-runs/201' in url:
            return {'app': {'id': self.producer_app}, 'name': 'Build', 'head_sha': REVISION, 'check_suite': {'id': 300},
                'details_url': 'https://github.com/owner/product/actions/runs/42/job/101', 'status': 'completed', 'conclusion': 'success'}
        if '/actions/runs/42' in url:
            return {'id': 42, 'workflow_id': 100, 'path': '.github/workflows/cd.yml', 'event': 'push', 'head_sha': REVISION,
                'head_branch': 'main', 'repository': {'full_name': 'owner/product'}, 'head_repository': {'full_name': 'owner/product'},
                'status': 'in_progress', 'conclusion': None, 'run_attempt': 2, 'check_suite_id': 300}
        if '/actions/artifacts/55' in url:
            return {'id': 55, 'expired': False, 'name': 'fleet-publication-42-2', 'size_in_bytes': self.path.stat().st_size,
                'digest': 'sha256:'+self.archive_sha, 'workflow_run': {'id': 42, 'head_sha': REVISION}}
        raise AssertionError('unexpected evidence request: '+str(args))

    def transport(self, args, directory, deadline, body=None):
        self.calls.append(args)
        self.directories.append(directory)
        if args[0] == 'login':
            self.assertEqual(body, b'synthetic-fixture-token')
            (directory/'config.json').write_bytes(body)
        if args[0] == 'push':
            return ('digest: sha256:'+'e'*64+' size: 1024\n').encode()
        if args[:3] == ['manifest', 'inspect', '--verbose']:
            return json.dumps({'Descriptor': {'digest': 'sha256:'+'e'*64},
                'SchemaV2Manifest': {'config': {'digest': 'sha256:'+self.config_sha}}}).encode()
        if args[:2] == ['manifest', 'inspect']:
            self.assertEqual(args[2], 'ghcr.io/owner/product@sha256:'+'e'*64)
            return json.dumps({'config': {'digest': 'sha256:'+self.config_sha}}).encode()
        return b''

    def publish(self, transport=None):
        return publisher.execute(self.request, self.policy, self.backend, transport or self.transport)

    def test_exact_publication_retains_immutable_digest_cleans_credentials_and_refuses_replay(self):
        result = self.publish()
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['published'][REFERENCE]['manifest_digest'], 'sha256:'+'e'*64)
        self.assertTrue(all(not directory.exists() for directory in self.directories))
        before = len(self.calls)
        with self.assertRaisesRegex(ValueError, 'already claimed'):
            self.publish()
        self.assertEqual(len(self.calls), before)

    def test_main_race_wrong_producer_and_attempt_refuse_before_load_or_credential(self):
        for change in ('race', 'app', 'attempt'):
            with self.subTest(change=change):
                self.main_reads = 0;self.race_at = 2 if change == 'race' else 0
                self.producer_app = 99 if change == 'app' else 15368
                self.generation = 1 if change == 'attempt' else 2
                with patch.object(publisher, 'registry_login') as login, self.assertRaises(ValueError):
                    self.publish()
                login.assert_not_called();self.assertEqual(self.calls, [])

    def test_changed_artifact_layer_destination_revision_or_tar_link_has_zero_effects(self):
        for alteration in ('bytes', 'layer', 'destination', 'revision', 'link'):
            with self.subTest(alteration=alteration):
                self.archive(bad_layer=alteration == 'layer', foreign=alteration == 'destination',
                             revision='f'*40 if alteration == 'revision' else REVISION, linked=alteration == 'link')
                if alteration == 'bytes':
                    self.path.write_bytes(self.path.read_bytes()+b'changed')
                with patch.object(publisher, 'registry_login') as login, self.assertRaises(ValueError):
                    self.publish()
                login.assert_not_called();self.assertEqual(self.calls, [])

    def test_interrupted_upload_is_durable_ambiguous_and_reconciles_without_push(self):
        def interrupted(args, directory, deadline, body=None):
            result = self.transport(args, directory, deadline, body)
            if args[0] == 'push':
                raise ValueError('synthetic response lost after upload')
            return result
        with self.assertRaises(ValueError):
            self.publish(interrupted)
        self.assertTrue(all(not directory.exists() for directory in self.directories))
        request = {'operation': 'inspect', 'repository': 'owner/product', 'revision': REVISION}
        observed = publisher.execute(request, self.policy)
        self.assertEqual(observed['status'], 'ambiguous')
        self.calls.clear()
        request['operation'] = 'reconcile'
        result = publisher.execute(request, self.policy, transport=self.transport)
        self.assertEqual(result['status'], 'reconciled')
        self.assertFalse(any(args[0] in ('push', 'load') for args in self.calls))
        with self.assertRaises(ValueError):
            self.publish()

    def test_delivery_is_immutable_and_unsafe_artifact_descriptor_refuses(self):
        with self.assertRaises(ValueError):
            publisher.persist_delivery({**self.grant, 'tree': 'f'*40})
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.calls, [])
        self.path.unlink();os.mkfifo(self.path, 0o600)
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.calls, [])

    def test_expired_delivery_refuses_before_any_registry_operation(self):
        key = hashlib.sha256(b'owner/product').hexdigest()
        grant = {**self.grant, 'expires_at': (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()}
        publisher.atomic(publisher.DELIVERIES/key/(REVISION+'.json'), grant)
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.calls, [])

    def test_actual_process_death_retains_upload_intent_and_refuses_reexecution(self):
        child = os.fork()
        if child == 0:
            def killed(args, directory, deadline, body=None):
                result = self.transport(args, directory, deadline, body)
                if args[0] == 'push':
                    os.kill(os.getpid(), signal.SIGKILL)
                return result
            try:
                self.publish(killed)
            except BaseException:
                os._exit(2)
            os._exit(3)
        deadline = time.monotonic()+5
        try:
            while True:
                observed, status = os.waitpid(child, os.WNOHANG)
                if observed:
                    self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL)
                    break
                if time.monotonic() >= deadline:
                    self.fail('synthetic publisher child exceeded deadline')
                time.sleep(.01)
        finally:
            if not observed:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
        request = {'operation': 'inspect', 'repository': 'owner/product', 'revision': REVISION}
        result = publisher.execute(request, self.policy)
        self.assertEqual(result['status'], 'ambiguous')
        self.assertEqual(result['persisted_status'], 'uploading')
        with self.assertRaisesRegex(ValueError, 'already claimed'):
            self.publish()
        self.assertEqual(self.calls, [])

    def test_entrypoint_returns_no_untrusted_input_in_error(self):
        result = subprocess.run([sys.executable, '-I', publisher.__file__], input=b'{"credential":"never-echo-this"}',
                                capture_output=True, timeout=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'never-echo-this', result.stdout+result.stderr)

    def test_real_transport_bounds_output_and_kills_timed_out_process_group(self):
        script = 'import sys;sys.stdout.write("x"*100000);sys.stdout.flush()'
        with patch.object(publisher, 'DOCKER', ('/usr/bin/python3', '-I', '-c', script)):
            with self.assertRaisesRegex(ValueError, 'output exceeds'):
                publisher.docker(['ignored'], self.root, time.monotonic()+2)
        script = 'import time;time.sleep(30)'
        started = time.monotonic()
        with patch.object(publisher, 'DOCKER', ('/usr/bin/python3', '-I', '-c', script)):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                publisher.docker(['ignored'], self.root, time.monotonic()+.1)
        self.assertLess(time.monotonic()-started, 1)


if __name__ == '__main__':
    unittest.main()
