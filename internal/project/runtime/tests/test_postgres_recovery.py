import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch


def helper(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1]/'helpers'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pg = helper('postgres-recovery')
snapshot = helper('snapshot')
ENGINE = 'postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
REVISION = 'a'*40


def payload(root, dump=b'PGDMPfixture', engine_id='sha256:'+'b'*64):
    root.mkdir(mode=0o700)
    (root/'database.dump').write_bytes(dump)
    (root/'files').mkdir()
    (root/'files'/'original.png').write_bytes(b'synthetic immutable original')
    (root/'secrets').mkdir()
    (root/'secrets'/'revocation.key').write_bytes(b'synthetic-only-recovery-key')
    manifest = {
        'format': pg.FORMAT, 'project': 'sampleapp', 'revision': REVISION, 'database': 'sampleapp',
        'engine': {'reference': ENGINE, 'image_id': engine_id, 'major': 18},
        'roles': ['sampleapp_owner', 'sampleapp_runtime'],
        'images': {name: {'reference': f'ghcr.io/nicodes/sampleapp-{name}:{REVISION}', 'image_id': 'sha256:'+'c'*64}
                   for name in ['api', 'gate']},
        # The parser validates this declaration; only a product capture test
        # can establish that its producer actually held the stated snapshot.
        'capture': {'snapshot_id': '00000003-0000001A-1', 'reclamation_fenced': True, 'completed_at': '2026-09-09T12:00:00+00:00'},
        'files': {str(file.relative_to(root)): {'size': file.stat().st_size, 'sha256': pg.checksum(file)}
                  for file in root.rglob('*') if file.is_file()},
    }
    (root/pg.MANIFEST).write_text(json.dumps(manifest))
    return manifest


def archive_payload(source, archive):
    with tarfile.open(archive, 'w:gz') as output:
        for file in sorted(source.rglob('*')):
            output.add(file, arcname=str(file.relative_to(source)), recursive=False)


class PostgreSQLArchiveBoundaries(unittest.TestCase):
    def test_completed_capture_packages_without_modifying_source_or_claiming_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); capture = root/'capture'
            manifest = payload(capture)
            (capture/pg.MANIFEST).unlink()
            report = {**manifest['capture'], 'database': manifest['database'], 'major': 18, 'files': manifest['files']}
            (capture/'capture.json').write_text(json.dumps(report))
            metadata = {key: manifest[key] for key in ['project', 'revision', 'engine', 'roles', 'images']}
            output = pg.package_capture(capture, root/'package', metadata)
            evidence = json.loads((output/'verification.json').read_text())
            self.assertEqual(evidence['backend'], 'postgresql')
            self.assertEqual(evidence['database_restore'], 'not_run')
            self.assertFalse((capture/pg.MANIFEST).exists())
            self.assertTrue((capture/'database.dump').is_file())
            (capture/'files'/'original.png').write_text('changed after capture')
            with self.assertRaisesRegex(ValueError, 'changed'):
                pg.package_capture(capture, root/'rejected', metadata)
            self.assertFalse((root/'rejected').exists())

    def test_renamed_project_retains_only_its_explicit_role_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = payload(root/'capture')
            manifest['project'] = 'newapp'
            for name in ('api', 'gate'):
                manifest['images'][name]['reference'] = f'ghcr.io/example/newapp-{name}:{REVISION}'
            with self.assertRaisesRegex(ValueError, 'application roles'):
                pg.validate_manifest(manifest)
            manifest['role_namespace'] = 'sampleapp'
            self.assertEqual(pg.validate_manifest(manifest, 'newapp', REVISION), manifest)
            (root/'capture'/pg.MANIFEST).unlink()
            report = {**manifest['capture'], 'database': manifest['database'], 'major': 18, 'files': manifest['files']}
            (root/'capture/capture.json').write_text(json.dumps(report))
            metadata = {key: manifest[key] for key in ('project', 'revision', 'engine', 'roles', 'images', 'role_namespace')}
            result = pg.package_capture(root/'capture', root/'package', metadata)
            packed = json.loads((result/'verification.json').read_text())['postgresql']
            self.assertEqual(packed['role_namespace'], 'sampleapp')
            self.assertEqual(packed['roles'], ['sampleapp_owner', 'sampleapp_runtime'])
            with self.assertRaisesRegex(ValueError, 'project mismatch'):
                pg.validate_manifest(packed, 'sampleapp', REVISION)
            for namespace in (None, [], '../sampleapp', 'restore_owner', 'sampleapp\n'):
                with self.subTest(namespace=namespace), self.assertRaisesRegex(ValueError, 'role namespace'):
                    pg.validate_manifest({**packed, 'role_namespace': namespace})
            for roles in (['otherapp_runtime'], ['restore_owner'], ['sampleapp_runtime', 'otherapp_owner']):
                with self.subTest(roles=roles), self.assertRaisesRegex(ValueError, 'application roles'):
                    pg.validate_manifest({**packed, 'roles': roles})
            wrong_images = copy.deepcopy(packed)
            wrong_images['images']['api']['reference'] = f'ghcr.io/example/sampleapp-api:{REVISION}'
            with self.assertRaisesRegex(ValueError, 'application image'):
                pg.validate_manifest(wrong_images)

    def test_complete_inventory_and_explicit_backend_without_fake_integrity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'payload'
            payload(source)
            archive = root/'data.tar.gz'; archive_payload(source, archive)
            target = root/'restored'; target.mkdir()
            with self.assertRaisesRegex(ValueError, 'PocketBase'):
                snapshot.restore(archive, target)
            target = root/'postgres'; target.mkdir()
            result = snapshot.restore(archive, target, backend='postgresql')
            self.assertEqual(result['archive_validation'], 'passed')
            self.assertEqual(result['database_restore'], 'not_run')
            self.assertEqual(result['application_restore'], 'not_run')
            self.assertEqual(result['postgresql']['project'], 'sampleapp')
            (target/'files'/'extra').write_text('undeclared')
            with self.assertRaisesRegex(ValueError, 'inventory'):
                pg.validate_payload(target)

    def test_wrong_project_revision_image_backend_and_manifest_types(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = payload(Path(directory)/'payload')
            with_owner_role = copy.deepcopy(manifest)
            with_owner_role['roles'].append('sampleapp')
            pg.validate_manifest(with_owner_role)
            for mutate in [
                lambda m: m.update(project='another-product'),
                lambda m: m.update(project=[]),
                lambda m: m['engine'].update(reference='postgres:latest'),
                lambda m: m['engine'].update(reference='attacker/postgres@sha256:'+'b'*64),
                lambda m: m['engine'].update(major=True),
                lambda m: m['capture'].update(reclamation_fenced=1),
                lambda m: m['images']['api'].update(reference='ghcr.io/attacker/sampleapp-api:'+REVISION),
                lambda m: m.update(roles=['restore_owner']),
                lambda m: m['files'].update({'../escape': {'size': 0, 'sha256': 'a'*64}}),
            ]:
                value = copy.deepcopy(manifest); mutate(value)
                with self.assertRaises(ValueError): pg.validate_manifest(value)
            with self.assertRaisesRegex(ValueError, 'project mismatch'):
                pg.validate_manifest(manifest, 'samplestore', REVISION)
            with self.assertRaisesRegex(ValueError, 'revision mismatch'):
                pg.validate_manifest(manifest, 'sampleapp', 'd'*40)
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                json.loads('{"format":1,"format":2}', object_pairs_hook=pg.unique_object)

    def test_image_owner_follows_project_org_and_refuses_wrong_org(self):
        with tempfile.TemporaryDirectory() as directory:
            sampleapp = payload(Path(directory)/'sampleapp')
            pg.validate_manifest(sampleapp)
            self.assertEqual(sampleapp['images']['api']['reference'], f'ghcr.io/nicodes/sampleapp-api:{REVISION}')
            sampleaddon = copy.deepcopy(sampleapp)
            sampleaddon.update(project='sampleaddon', database='sampleaddon', roles=['sampleaddon_owner', 'sampleaddon_runtime'])
            for name in ['api', 'gate']:
                sampleaddon['images'][name]['reference'] = f'ghcr.io/example-games/sampleaddon-{name}:{REVISION}'
            pg.validate_manifest(sampleaddon)
            wrong_org = copy.deepcopy(sampleaddon)
            wrong_org['images']['api']['reference'] = f'ghcr.io/nicodes/sampleaddon-api:{REVISION}'
            with self.assertRaisesRegex(ValueError, 'application image'):
                pg.validate_manifest(wrong_org)
            unknown = copy.deepcopy(sampleapp)
            unknown['project'] = '../unknown'
            with self.assertRaisesRegex(ValueError, 'invalid PostgreSQL recovery project'):
                pg.validate_manifest(unknown)

    def test_no_image_action_precedes_project_binding_and_no_error_discloses_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'payload'; payload(root)
            with patch.object(pg, 'docker') as docker:
                with self.assertRaisesRegex(ValueError, 'project mismatch'):
                    with pg.restored_database(root, 'samplestore', REVISION, pull=True): pass
                docker.assert_not_called()
            with patch.object(pg.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['private-password'], 1)):
                with self.assertRaises(RuntimeError) as raised: pg.docker('exec', 'private-password')
                self.assertNotIn('private-password', str(raised.exception))

    def test_authenticated_backend_cannot_be_downgraded_in_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'payload'; manifest = payload(source)
            archive = root/'data.tar.gz'; archive_payload(source, archive)
            evidence = {'archive_sha256': snapshot.sha256(archive), 'backend': 'postgresql',
                        'image_id': manifest['engine']['image_id'], 'image_reference': ENGINE,
                        'verified_at': manifest['capture']['completed_at']}
            (root/'verification.json').write_text(json.dumps(evidence))
            key, cert = root/'key.pem', root/'recipient.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-keyout', str(key),
                            '-out', str(cert), '-days', '1', '-subj', '/CN=synthetic-postgres-recovery'],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            encrypted = snapshot.seal(root, cert)
            restored = root/'restored'; restored.mkdir()
            result = snapshot.unseal(encrypted, key, restored)
            self.assertEqual(result['backend'], 'postgresql')
            self.assertEqual(result['database_restore'], 'not_run')
            receipt = json.loads((encrypted/'receipt.json').read_text())
            receipt['backend'] = 'pocketbase'
            (encrypted/'receipt.json').write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, 'backend'):
                snapshot.unseal(encrypted, key, restored)

    def test_links_truncation_and_changed_payload_remain_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'payload'; payload(source)
            (source/'files'/'original.png').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'inventory'): pg.validate_payload(source)
            (source/'files'/'alias').symlink_to(source/'database.dump')
            with self.assertRaises(ValueError): pg.validate_payload(source)
            archive = root/'bad.tar.gz'
            with tarfile.open(archive, 'w:gz') as output:
                item = tarfile.TarInfo('../escape'); item.size = 1
                output.addfile(item, io.BytesIO(b'x'))
            target = root/'restored'; target.mkdir()
            with self.assertRaises(ValueError): snapshot.restore(archive, target, backend='postgresql')

    def host_local_manifest(self, root):
        manifest = payload(root)
        manifest['revision'] = 'host-local:inapi-fold'
        manifest['images']['api']['reference'] = 'ghcr.io/nicodes/sampleapp-api:inapi-fold'
        manifest['images']['gate']['reference'] = 'ghcr.io/nicodes/sampleapp-gate:' + 'e'*40
        return manifest

    def test_host_local_transition_binds_each_component_tag_truthfully(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.host_local_manifest(Path(directory)/'payload')
            pg.validate_manifest(manifest)
            pg.validate_manifest(manifest, 'sampleapp', 'host-local:inapi-fold')
            with self.assertRaisesRegex(ValueError, 'revision mismatch'):
                pg.validate_manifest(manifest, 'sampleapp', REVISION)

    def test_mixed_hex_rollout_binds_each_component(self):
        # sampleconsole #181: the gate may roll on a different 40-hex tag than the
        # api; the api tag still anchors the single manifest revision.
        with tempfile.TemporaryDirectory() as directory:
            manifest = payload(Path(directory)/'payload')
            manifest['images']['gate']['reference'] = 'ghcr.io/nicodes/sampleapp-gate:' + 'f'*40
            pg.validate_manifest(manifest)

    def test_host_local_capture_packages_and_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); capture = root/'capture'
            manifest = self.host_local_manifest(capture)
            (capture/pg.MANIFEST).unlink()
            report = {**manifest['capture'], 'database': manifest['database'], 'major': 18, 'files': manifest['files']}
            (capture/'capture.json').write_text(json.dumps(report))
            metadata = {key: manifest[key] for key in ['project', 'revision', 'engine', 'roles', 'images']}
            output = pg.package_capture(capture, root/'package', metadata)
            evidence = json.loads((output/'verification.json').read_text())
            self.assertEqual(evidence['backend'], 'postgresql')

    def test_host_local_and_mixed_binding_stay_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            host = self.host_local_manifest(Path(directory)/'payload')
            refusals = [
                # Owner, product and component binding never relax.
                lambda m: m['images']['api'].update(reference='ghcr.io/attacker/sampleapp-api:inapi-fold'),
                lambda m: m['images']['api'].update(reference='ghcr.io/nicodes/samplestore-api:inapi-fold'),
                lambda m: m['images']['api'].update(reference='ghcr.io/nicodes/sampleapp-gate:inapi-fold'),
                # The api tag must anchor the recorded host-local revision.
                lambda m: m['images']['api'].update(reference='ghcr.io/nicodes/sampleapp-api:other-fold'),
                # Tags stay within the docker tag charset even in transition mode.
                lambda m: m['images']['gate'].update(reference='ghcr.io/nicodes/sampleapp-gate:-bad'),
                lambda m: m['images']['gate'].update(reference='ghcr.io/nicodes/sampleapp-gate:has/slash'),
                # The revision itself must be a 40-hex SHA or host-local:<tag>.
                lambda m: m.update(revision='host-local:'),
                lambda m: m.update(revision='host-local'),
                lambda m: m.update(revision='latest'),
            ]
            for mutate in refusals:
                value = copy.deepcopy(host); mutate(value)
                with self.assertRaisesRegex(ValueError, 'application image|project or revision'):
                    pg.validate_manifest(value)
            # Release mode keeps immutable 40-hex tags; 'latest' stays refused.
            release = copy.deepcopy(host)
            release['revision'] = REVISION
            release['images']['api']['reference'] = f'ghcr.io/nicodes/sampleapp-api:{REVISION}'
            release['images']['gate']['reference'] = 'ghcr.io/nicodes/sampleapp-gate:latest'
            with self.assertRaisesRegex(ValueError, 'application image'):
                pg.validate_manifest(release)
            # The api tag must equal the hex revision, not just any hex tag.
            release['images']['gate']['reference'] = f'ghcr.io/nicodes/sampleapp-gate:{REVISION}'
            release['images']['api']['reference'] = 'ghcr.io/nicodes/sampleapp-api:' + 'b'*40
            with self.assertRaisesRegex(ValueError, 'application image'):
                pg.validate_manifest(release)


    def test_service_named_api_side_binds_and_anchors_like_api(self):
        # Projects may deploy the API side under a service-named image; the
        # binding, anchoring and mixed-recording rules match api exactly.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'payload'; manifest = payload(source)
            manifest['images'] = {
                'service': {'reference': f'ghcr.io/nicodes/sampleapp-service:{REVISION}', 'image_id': 'sha256:'+'c'*64},
                'gate': {'reference': 'ghcr.io/nicodes/sampleapp-gate:' + 'f'*40, 'image_id': 'sha256:'+'c'*64},
            }
            (source/pg.MANIFEST).write_text(json.dumps(manifest))
            pg.validate_manifest(manifest)
            pg.validate_payload(source)
            drifting = copy.deepcopy(manifest)
            drifting['images']['service']['reference'] = 'ghcr.io/nicodes/sampleapp-service:' + 'd'*40
            with self.assertRaisesRegex(ValueError, 'not bound to the recovery project/revision'):
                pg.validate_manifest(drifting)

    def test_service_binding_stays_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = payload(Path(directory)/'payload')
            manifest['images'] = {
                'service': {'reference': f'ghcr.io/nicodes/sampleapp-service:{REVISION}', 'image_id': 'sha256:'+'c'*64},
                'gate': {'reference': f'ghcr.io/nicodes/sampleapp-gate:{REVISION}', 'image_id': 'sha256:'+'c'*64},
            }
            for mutate in [
                lambda m: m['images'].update(api=dict(m['images']['service'])),
                lambda m: m['images'].update(worker=dict(m['images']['service'])),
                lambda m: m['images']['service'].update(reference='ghcr.io/attacker/sampleapp-service:'+REVISION),
                lambda m: m['images']['service'].update(reference='ghcr.io/nicodes/sampleapp-api:'+REVISION),
            ]:
                value = copy.deepcopy(manifest); mutate(value)
                with self.assertRaises(ValueError): pg.validate_manifest(value)

    def test_host_local_service_tag_anchors_the_recorded_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.host_local_manifest(Path(directory)/'payload')
            manifest['images'] = {
                'service': {'reference': 'ghcr.io/nicodes/sampleapp-service:inapi-fold', 'image_id': 'sha256:'+'c'*64},
                'gate': manifest['images']['gate'],
            }
            pg.validate_manifest(manifest)
            pg.validate_manifest(manifest, 'sampleapp', 'host-local:inapi-fold')
            drifting = copy.deepcopy(manifest)
            drifting['images']['service']['reference'] = 'ghcr.io/nicodes/sampleapp-service:other-fold'
            with self.assertRaisesRegex(ValueError, 'not bound to the recovery project/revision'):
                pg.validate_manifest(drifting)

@unittest.skipUnless(os.environ.get('CICD_TEST_POSTGRES') == '1', 'make check requires the real isolated PostgreSQL control')
class PostgreSQLRestoreIntegration(unittest.TestCase):
    def test_real_custom_dump_restores_rows_and_acl_and_cleans_up(self):
        self.restore_roundtrip('sampleapp')

    def test_renamed_project_restores_existing_database_and_roles(self):
        self.restore_roundtrip('newapp')

    def restore_roundtrip(self, project):
        pg.docker('pull', '--quiet', ENGINE, timeout=180)
        image = json.loads(pg.docker('image', 'inspect', ENGINE))[0]['Id']
        name = 'cicd-pg-source-'+os.urandom(8).hex()
        uid = os.getuid() or 65534
        source_id = pg.docker('run', '-d', '--name', name, '--network=none', '--read-only', '--user', f'{uid}:{uid}',
                              '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--memory=256m',
                              '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
                              '--tmpfs', f'/var/run/postgresql:rw,uid={uid},gid={uid},mode=0770,size=8m',
                              '--tmpfs', f'/var/lib/postgresql:rw,uid={uid},gid={uid},mode=0700,size=128m',
                              '--env', 'POSTGRES_HOST_AUTH_METHOD=trust', '--env', 'POSTGRES_USER=sampleapp_owner',
                              '--env', 'POSTGRES_DB=sampleapp', '--env', 'PGDATA=/var/lib/postgresql/data', image,
                              'postgres', '-c', 'listen_addresses=127.0.0.1')
        self.addCleanup(lambda: pg.docker('rm', '-f', '-v', source_id))
        for _ in range(100):
            try:
                pg.docker('exec', source_id, 'pg_isready', '-h', '127.0.0.1', '-U', 'sampleapp_owner', '-d', 'sampleapp')
                break
            except RuntimeError: time.sleep(.1)
        else: self.fail('synthetic PostgreSQL source did not start')
        pg.docker('exec', '-i', source_id, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'sampleapp_owner', '-d', 'sampleapp', input='''
CREATE ROLE sampleapp_runtime LOGIN;
CREATE TABLE preserved(id integer PRIMARY KEY,value text NOT NULL);
INSERT INTO preserved VALUES(1,'captured');
GRANT SELECT ON preserved TO sampleapp_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE sampleapp_owner IN SCHEMA public GRANT SELECT ON TABLES TO sampleapp_runtime;
CREATE FUNCTION private_count() RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS 'SELECT count(*) FROM public.preserved';
REVOKE ALL ON FUNCTION private_count() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private_count() TO sampleapp_runtime;
''')
        pg.docker('exec', source_id, 'pg_dump', '-Fc', '-U', 'sampleapp_owner', '-d', 'sampleapp', '-f', '/tmp/database.dump')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'payload'; manifest = payload(source, engine_id=image)
            if project != 'sampleapp':
                manifest.update(project=project, role_namespace='sampleapp')
                for component in ('api', 'gate'):
                    manifest['images'][component]['reference'] = f'ghcr.io/example/{project}-{component}:{REVISION}'
            # Stream bytes rather than relying on Docker's archive-copy support
            # for a running read-only container with a tmpfs source file.
            with (source/'database.dump').open('wb') as output:
                copied = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', 'exec', source_id,
                                         'cat', '/tmp/database.dump'], stdout=output, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(copied.returncode, 0, 'could not stream the synthetic custom dump')
            manifest['files']['database.dump'] = {'size': (source/'database.dump').stat().st_size,
                                                 'sha256': pg.checksum(source/'database.dump')}
            (source/pg.MANIFEST).write_text(json.dumps(manifest))
            pg.docker('exec', source_id, 'psql', '-X', '-U', 'sampleapp_owner', '-d', 'sampleapp', '-c', "UPDATE preserved SET value='after snapshot'")
            with pg.restored_database(source, project, REVISION) as clone:
                restored_id = clone['container']
                self.assertEqual(clone['database_restore'], 'passed')
                self.assertNotIn('roles', clone)
                actual = pg.docker('exec', restored_id, 'psql', '-XAt', '-U', 'restore_owner', '-d', 'sampleapp', '-c', 'SELECT value FROM preserved')
                self.assertEqual(actual, 'captured')
                acl = pg.docker('exec', restored_id, 'psql', '-XAt', '-U', 'sampleapp_runtime', '-d', 'sampleapp', '-c', 'SELECT private_count()')
                self.assertEqual(acl, '1')
                public_acl = pg.docker('exec', restored_id, 'psql', '-XAt', '-U', 'restore_owner', '-d', 'sampleapp', '-c', "SELECT count(*) FROM pg_proc p, LATERAL aclexplode(p.proacl) a WHERE p.proname='private_count' AND a.grantee=0")
                self.assertEqual(public_acl, '0')
            with self.assertRaises(RuntimeError): pg.docker('inspect', restored_id)
            # A valid manifest/header cannot turn a broken pg_restore into a
            # passed database result. Owned-container cleanup still runs.
            (source/'database.dump').write_bytes((source/'database.dump').read_bytes()[:8])
            manifest['files']['database.dump'] = {'size': 8, 'sha256': pg.checksum(source/'database.dump')}
            (source/pg.MANIFEST).write_text(json.dumps(manifest))
            created = []
            real_docker = pg.docker
            def tracked(*args, **kwargs):
                if args[0] == 'run': created.append(args[args.index('--name')+1])
                return real_docker(*args, **kwargs)
            with patch.object(pg, 'docker', tracked), self.assertRaises(RuntimeError):
                with pg.restored_database(source, project, REVISION):
                    self.fail('corrupt custom dump yielded a restored database')
            self.assertEqual(len(created), 1)
            with self.assertRaises(RuntimeError): real_docker('inspect', created[0])
