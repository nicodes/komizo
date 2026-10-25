import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('restore_drill', Path(__file__).parents[1]/'helpers/restore-drill.py')
drill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drill)


def fixture_config(project, postgres=False):
    owner = {'sampleaddon': 'example-games', 'sampleservice': 'sampleservicelogical'}.get(project, 'nicodes')
    return {'project': project, 'backend': 'postgresql' if postgres else 'pocketbase',
            'image_base': f'ghcr.io/{owner}/{project}', 'db': 'pb' if project == 'sampleservice' else 'db',
            'binary': '/app/pocketbase', 'port': 8090, 'api_port': 8080, 'root': '/srv/public/app',
            'data_path': '/pb/pb_data', 'health_path': '/health', 'env': {}, 'serve_flags': [],
            'runtime_role': project+'_runtime', 'dsn_file': '/run/secrets/database.url'}


class RestoreBoundaries(unittest.TestCase):
    def test_renamed_fixture_preserves_configured_database_and_role_namespace(self):
        spec = importlib.util.spec_from_file_location('restore_fixture', Path(__file__).parents[1]/'helpers/test-restore-drill.py')
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        pg = fixture.load('postgres-recovery')
        engine = 'postgres@sha256:' + 'b' * 64
        config = {**fixture_config('newapp', postgres=True), 'database': 'oldapp',
                  'role_namespace': 'oldapp', 'runtime_role': 'oldapp_runtime'}
        def docker(*args, **kwargs):
            if args[:2] == ('image', 'inspect'):
                return json.dumps([{'Id': 'sha256:' + 'b' * 64, 'Config': {'Env': ['PG_MAJOR=18']}}])
            return ''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_file = root/'config.json'; config_file.write_text(json.dumps(config))
            self.assertEqual(drill.load_config(config_file)['database'], 'oldapp')
            with patch.object(fixture.os, 'getuid', return_value=1000), patch.object(fixture, 'docker_bytes', return_value=b'PGDMPfixture'):
                result = fixture.postgres_fixture('newapp', 'a' * 40, engine,
                    SimpleNamespace(docker=docker), SimpleNamespace(sha256=pg.checksum), pg, root, config=config)
            manifest = json.loads((result/'verification.json').read_text())['postgresql']
            self.assertEqual(manifest['project'], 'newapp')
            self.assertEqual(manifest['database'], 'oldapp')
            self.assertEqual(manifest['role_namespace'], 'oldapp')
            self.assertEqual(manifest['roles'], ['oldapp_runtime'])
            self.assertIn('/newapp-api:', manifest['images']['api']['reference'])
            for name, invalid in [('database', 'oldapp\nPGDATA=/escape'), ('role_namespace', '../oldapp')]:
                config_file.write_text(json.dumps({**config, name: invalid}))
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'PostgreSQL identity'):
                    drill.load_config(config_file)

    def test_restored_files_are_mounted_readonly_instead_of_replaced_by_empty_tmpfs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'files').mkdir()
            original = root/'files'/'original.png'
            original.write_bytes(b'authenticated original')
            with patch.object(drill.os, 'getuid', return_value=1000):
                mounts = drill.restored_blob_mounts(root, {'blobs': '/blobs'}, 1000)
            self.assertEqual(mounts, ['--mount', f'type=bind,src={root}/files,dst=/blobs,readonly'])
            self.assertEqual(original.read_bytes(), b'authenticated original')
            with self.assertRaisesRegex(ValueError, 'explicit'):
                drill.restored_blob_mounts(root, {}, 1000)

    def test_registry_pull_requires_authenticated_product_and_image_identity(self):
        evidence = {'image_reference': 'ghcr.io/nicodes/wrong-db:'+'a'*40, 'image_id': 'sha256:'+'b'*64}
        snapshot = SimpleNamespace(unseal=lambda *_: evidence)
        receiver = SimpleNamespace(receive=lambda *_: None)
        def helper(name):
            return snapshot if name == 'snapshot' else receiver
        with patch.object(drill, 'helper', helper), patch.object(drill, 'docker') as docker:
            with self.assertRaisesRegex(ValueError, 'product'):
                drill.drill('samplestore', Path('/unused'), Path('/unused'), pull=True, config=fixture_config('samplestore'))
            docker.assert_not_called()
        evidence['image_reference'] = 'ghcr.io/nicodes/samplestore-db:'+'a'*40
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            return json.dumps([{'Id': 'sha256:'+'c'*64}]) if args[:2] == ('image', 'inspect') else ''
        with patch.object(drill, 'helper', helper), patch.object(drill, 'docker', docker):
            with self.assertRaisesRegex(ValueError, 'differs'):
                drill.drill('samplestore', Path('/unused'), Path('/unused'), pull=True, config=fixture_config('samplestore'))
        self.assertEqual(calls, [('pull', '--quiet', evidence['image_reference']),
                                 ('image', 'inspect', evidence['image_reference'])])

    def test_timeout_and_failures_never_disclose_clone_credentials(self):
        secret = 'disposable-secret-that-must-not-appear'
        with patch.object(drill.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['docker', 'run', secret], 1)):
            with self.assertRaises(RuntimeError) as raised:
                drill.docker('run', secret)
            self.assertNotIn(secret, str(raised.exception))
            self.assertTrue(raised.exception.__suppress_context__)
        with patch.object(drill.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, secret, secret)):
            with self.assertRaises(RuntimeError) as raised:
                drill.docker('run', secret)
            self.assertNotIn(secret, str(raised.exception))

    def test_new_product_backup_namespace_is_authenticated_before_any_pull(self):
        # sampleconsole is absent deliberately: it restores into PostgreSQL now,
        # and PostgresRestoreBoundaries covers the same guards for that path.
        for project, owner, component in [('sampleaddon','example-games','db'), ('sampleservice','sampleservicelogical','pb')]:
            evidence = {'image_reference': f'ghcr.io/nicodes/{project}-{component}:'+'a'*40, 'image_id':'sha256:'+'b'*64}
            snapshot = SimpleNamespace(unseal=lambda *_: evidence)
            receiver = SimpleNamespace(receive=lambda *_: None)
            with patch.object(drill, 'helper', lambda name: snapshot if name == 'snapshot' else receiver), patch.object(drill,'docker') as docker:
                with self.assertRaisesRegex(ValueError,'product'):
                    drill.drill(project,Path('/unused'),Path('/unused'),pull=True,config=fixture_config(project))
                docker.assert_not_called()
            evidence['image_reference'] = f'ghcr.io/{owner}/{project}-{component}:'+'a'*40
            calls = []
            def docker(*args, **kwargs):
                calls.append(args)
                return json.dumps([{'Id':'sha256:'+'c'*64}]) if args[:2] == ('image','inspect') else ''
            with patch.object(drill,'helper',lambda name: snapshot if name == 'snapshot' else receiver), patch.object(drill,'docker',docker):
                with self.assertRaisesRegex(ValueError,'differs'):
                    drill.drill(project,Path('/unused'),Path('/unused'),pull=True,config=fixture_config(project))
            self.assertEqual(calls, [('pull','--quiet',evidence['image_reference']),('image','inspect',evidence['image_reference'])])


def postgres_manifest(project='sampleapp', revision='a'*40, api_id='sha256:'+'c'*64):
    return {'project': project, 'revision': revision,
            'images': {'api': {'reference': f'ghcr.io/nicodes/{project}-api:{revision}', 'image_id': api_id},
                       'gate': {'reference': f'ghcr.io/nicodes/{project}-gate:{revision}', 'image_id': 'sha256:'+'c'*64}}}


class PostgresRestoreBoundaries(unittest.TestCase):
    """The PostgreSQL drill authenticates the same things the PocketBase one does.

    Each case stops the drill BEFORE any container starts, so these run
    without Docker; the end-to-end path is exercised by test-restore-drill.py
    against the product's real images.
    """

    def drill_with(self, evidence, project='sampleapp', docker=None):
        snapshot = SimpleNamespace(unseal=lambda *_: evidence)
        receiver = SimpleNamespace(receive=lambda *_: None)
        recovery = SimpleNamespace()
        helpers = {'snapshot': snapshot, 'receive-backup': receiver, 'postgres-recovery': recovery}
        with patch.object(drill, 'helper', helpers.get), patch.object(drill, 'docker', docker or (lambda *a, **k: '')):
            return drill.drill(project, Path('/unused'), Path('/unused'), pull=True, config=fixture_config(project, postgres=True))

    def test_explicit_backend_declarations_are_validated(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory)/'restore.json'
            config = fixture_config('example', postgres=True)
            file.write_text(json.dumps(config))
            self.assertEqual(drill.load_config(file), config)
            for key in ('runtime_role', 'dsn_file', 'api_port', 'health_path', 'root', 'env'):
                missing = dict(config); missing.pop(key)
                file.write_text(json.dumps(missing))
                with self.assertRaises(ValueError): drill.load_config(file)
        self.assertEqual(drill.SERVING_DSN_VARIABLE, 'RUNTIME_DATABASE_URL_FILE')

    def test_a_pocketbase_envelope_is_refused_by_a_postgresql_product(self):
        # No 'backend' key at all is how a PocketBase envelope reads.
        with self.assertRaisesRegex(ValueError, 'not a PostgreSQL snapshot'):
            self.drill_with({'image_reference': 'ghcr.io/nicodes/sampleapp-db:'+'a'*40})

    def test_a_snapshot_of_another_product_is_refused(self):
        evidence = {'backend': 'postgresql', 'postgresql': postgres_manifest(project='samplestore')}
        with self.assertRaisesRegex(ValueError, 'another product'):
            self.drill_with(evidence)

    def test_an_inexact_revision_is_refused(self):
        evidence = {'backend': 'postgresql', 'postgresql': postgres_manifest(revision='host-local:release')}
        with self.assertRaisesRegex(ValueError, 'exact product revision'):
            self.drill_with(evidence)

    def test_an_application_image_that_is_not_the_snapshot_s_is_refused(self):
        # The tag resolves locally, but to different bytes than the snapshot
        # named. Booting it would prove nothing about the release the data
        # came from, so the drill refuses rather than running green.
        evidence = {'backend': 'postgresql', 'postgresql': postgres_manifest(api_id='sha256:'+'d'*64)}
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            return json.dumps([{'Id': 'sha256:'+'c'*64}]) if args[:2] == ('image', 'inspect') else ''
        with self.assertRaisesRegex(ValueError, 'differs from authenticated'):
            self.drill_with(evidence, docker=docker)
        self.assertIn(('image', 'inspect', 'ghcr.io/nicodes/sampleapp-api:'+'a'*40), calls)
