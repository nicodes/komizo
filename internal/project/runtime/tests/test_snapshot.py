import importlib.util
from contextlib import closing
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('snapshot', Path(__file__).parents[1]/'helpers/snapshot.py')
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class SnapshotBoundaries(unittest.TestCase):
    def test_restore_refuses_a_member_that_would_exhaust_host_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root/'data.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                member = tarfile.TarInfo('data.db')
                member.size = 1
                tar.addfile(member, io.BytesIO(b'x'))
            target = root/'restored'
            target.mkdir()
            with patch.object(snapshot.shutil, 'disk_usage', return_value=type('Usage', (), {'free': 512*1024**2})()):
                with self.assertRaisesRegex(ValueError, 'headroom'):
                    snapshot.restore(archive, target)
            self.assertEqual(list(target.iterdir()), [])

    def test_encrypted_offhost_round_trip_and_tamper_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key, cert = root/'key.pem', root/'recipient.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                            '-keyout', str(key), '-out', str(cert), '-days', '1',
                            '-subj', '/CN=disposable-snapshot-test'], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            with closing(sqlite3.connect(root/'data.db')) as db:
                db.executescript('CREATE TABLE _collections (name TEXT); CREATE TABLE _migrations (name TEXT);')
            archive = root/'data.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar: tar.add(root/'data.db', arcname='data.db')
            evidence = {'archive_sha256': snapshot.sha256(archive), 'image_id': 'sha256:'+'a'*64,
                        'image_reference': 'ghcr.io/nicodes/example-db:'+'a'*40,
                        'verified_at': '2026-09-04T12:00:00+00:00'}
            (root/'verification.json').write_text(json.dumps(evidence))
            offhost = snapshot.seal(root, cert)
            target = root/'restored'; target.mkdir()
            self.assertEqual(snapshot.unseal(offhost, key, target)['archive_sha256'], evidence['archive_sha256'])
            receipt = json.loads((offhost/'receipt.json').read_text())
            receipt['image_reference'] = 'ghcr.io/nicodes/wrong-db:'+'b'*40
            (offhost/'receipt.json').write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, 'metadata'):
                snapshot.unseal(offhost, key, target)
            receipt['image_reference'] = evidence['image_reference']
            (offhost/'receipt.json').write_text(json.dumps(receipt))
            ciphertext = offhost/'snapshot.cms'
            ciphertext.write_bytes(ciphertext.read_bytes()[:-1] + bytes([ciphertext.read_bytes()[-1] ^ 1]))
            # Even a replacement transport checksum cannot hide a broken GCM tag.
            receipt = json.loads((offhost/'receipt.json').read_text())
            receipt['ciphertext_sha256'] = snapshot.sha256(ciphertext)
            (offhost/'receipt.json').write_text(json.dumps(receipt))
            with self.assertRaises(subprocess.CalledProcessError): snapshot.unseal(offhost, key, target)

    def test_committed_wal_is_restored_and_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'source'; source.mkdir()
            with closing(sqlite3.connect(source/'data.db')) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.executescript('CREATE TABLE _collections (name TEXT); CREATE TABLE _migrations (name TEXT);')
                db.execute("INSERT INTO _collections VALUES ('wal-committed')")
                db.commit()
                archive = root/'data.tar.gz'
                with tarfile.open(archive, 'w:gz') as tar:
                    for file in source.iterdir(): tar.add(file, arcname=file.name)
                target = root/'restore'; target.mkdir()
                evidence = snapshot.restore(archive, target, snapshot.sha256(archive))
                self.assertEqual(evidence['databases']['data.db']['integrity'], 'ok')
                with closing(sqlite3.connect(target/'data.db')) as restored:
                    self.assertEqual(restored.execute('SELECT name FROM _collections').fetchall(), [('wal-committed',)])
            with self.assertRaisesRegex(ValueError, 'checksum'):
                snapshot.restore(archive, root, '0'*64)
            archive.write_bytes(archive.read_bytes()[:-4])
            with self.assertRaises(EOFError):
                snapshot.restore(archive, target)

    def test_traversal_links_duplicate_names_and_missing_database(self):
        for attack in ('../escape', '/absolute', 'link', 'hardlink', 'duplicate', 'missing'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); archive = root/'data.tar.gz'
                with tarfile.open(archive, 'w:gz') as tar:
                    member = tarfile.TarInfo(attack)
                    if attack in ('link', 'hardlink'):
                        member.type = tarfile.SYMTYPE if attack == 'link' else tarfile.LNKTYPE
                        member.linkname = '/tmp/outside'
                    else: member.size = 1
                    tar.addfile(member, io.BytesIO(b'x'))
                    if attack == 'duplicate': tar.addfile(member, io.BytesIO(b'x'))
                target = root/'restore'; target.mkdir()
                with self.assertRaises(ValueError): snapshot.restore(archive, target)

    def test_pause_failure_never_copies_and_attempts_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); data = root/'data'; data.mkdir()
            destination = root/'backups'
            info = {'Id': 'a'*64, 'Image': 'sha256:'+'b'*64,
                    'State': {'Running': True, 'Paused': False},
                    'Config': {'Healthcheck': {'Test': ['CMD', 'probe']}},
                    'Mounts': [{'Source': str(data), 'Destination': '/data', 'Type': 'volume'}]}
            commands = []
            def docker(*args):
                commands.append(args)
                if args[0] == 'pause': raise RuntimeError('daemon transport failed')
                return ''
            with patch.object(snapshot, 'inspect', return_value=info), patch.object(snapshot, 'docker', docker), \
                    patch.object(snapshot, 'resumed_health'), patch.object(snapshot, 'restore') as restore:
                with self.assertRaisesRegex(RuntimeError, 'transport'):
                    snapshot.snapshot('db', '/data', destination)
                restore.assert_not_called()
            self.assertEqual([command[0] for command in commands], ['pause', 'unpause'])
            self.assertEqual(list(destination.iterdir()), [])

    def test_health_must_start_after_unpause(self):
        boundary = snapshot.timestamp_ns('2026-09-04T12:00:00.123456789Z')
        info = {'State': {'Running': True, 'Paused': False, 'Health': {'Status': 'healthy',
                'Log': [{'Start': '2026-09-04T12:00:00.123456788Z', 'ExitCode': 0}]}}}
        with patch.object(snapshot, 'inspect', return_value=info), patch.object(snapshot.time, 'sleep'):
            with self.assertRaises(TimeoutError): snapshot.resumed_health('db', boundary, timeout=.005)
        info['State']['Health']['Log'][0]['Start'] = '2026-09-04T12:00:00.123456790Z'
        with patch.object(snapshot, 'inspect', return_value=info): snapshot.resumed_health('db', boundary)
