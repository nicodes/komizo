import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('stateful', Path(__file__).resolve().parents[1]/'helpers/stateful_release.py')
stateful = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stateful)

INITIAL = 'CREATE TABLE records(id INTEGER PRIMARY KEY, value INTEGER NOT NULL)'
ADDITIVE = "ALTER TABLE records ADD COLUMN note TEXT NOT NULL DEFAULT ''"


def contracts():
    old = {'version': 1, 'source_revision': 'b'*40, 'schema': {'minimum': 1, 'maximum': 2, 'write': 1},
           'data_revision': 'records-v1', 'credential_revision': 'restricted-runtime-v1',
           'migrations': [{'identity': '001.sql', 'sha256': hashlib.sha256(INITIAL.encode()).hexdigest()}], 'recovery_action': 'forward_only'}
    new = copy.deepcopy(old)
    new.update(source_revision='a'*40, schema={'minimum': 1, 'maximum': 2, 'write': 2}, recovery_action='image_rollback')
    new['migrations'].append({'identity': '002.sql', 'sha256': hashlib.sha256(ADDITIVE.encode()).hexdigest()})
    return new, old


class StatefulContract(unittest.TestCase):
    def test_host_producer_canonical_identity_and_materialized_source(self):
        current = {'version': 1, 'source_revision': 'a'*40, 'schema': {'minimum': 1, 'maximum': 2, 'write': 2},
                   'data_revision': 'records-v1', 'credential_revision': 'runtime-grants-v1',
                   'migrations': [{'identity': '001.sql', 'sha256': 'b'*64}], 'recovery_action': 'forward_only'}
        self.assertEqual(stateful.identity(current), 'e8e790b253bd846e99adc4d63d399272f932bd9193957c08dee80806c2fd8fc3')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'declaration.json'
            declaration = {key: value for key, value in current.items() if key != 'source_revision'}
            path.write_text(json.dumps(declaration))
            self.assertEqual(stateful.materialize(path, 'a'*40), current)
            path.write_text('{"version":1,"version":1}')
            with self.assertRaises(ValueError): stateful.materialize(path, 'a'*40)
            path.write_text(json.dumps(current))
            with self.assertRaises(ValueError): stateful.materialize(path, 'a'*40)

    def test_real_disposable_old_new_processes_preserve_overlapping_writes(self):
        new, old = contracts()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory)/'fixture.sqlite'
            with sqlite3.connect(database) as connection:
                connection.execute(INITIAL)
                connection.execute(ADDITIVE)
                connection.execute("INSERT INTO records(value,note) VALUES(1,'new')")
            # Independent executables with distinct SQL shapes operate against
            # the same post-migration disposable database. No recovery artifact
            # or live credential participates in this fixture.
            code = "import sqlite3,sys; c=sqlite3.connect(sys.argv[1],timeout=5); c.execute(sys.argv[2]); c.commit()"
            writers = [subprocess.Popen([sys.executable, '-I', '-c', code, str(database), query]) for query in
                       ('INSERT INTO records(value) VALUES(2)', "INSERT INTO records(value,note) VALUES(3,'new')")]
            for writer in writers:
                self.assertEqual(writer.wait(timeout=10), 0)
            read = "import sqlite3,sys,json; c=sqlite3.connect(sys.argv[1]); print(json.dumps(c.execute(sys.argv[2]).fetchall()))"
            old_rows = json.loads(subprocess.check_output([sys.executable, '-I', '-c', read, str(database), 'SELECT value FROM records ORDER BY value'], timeout=10))
            new_rows = json.loads(subprocess.check_output([sys.executable, '-I', '-c', read, str(database), 'SELECT value,note FROM records ORDER BY value'], timeout=10))
            self.assertEqual(old_rows, [[1], [2], [3]])
            self.assertEqual(new_rows, [[1, 'new'], [2, ''], [3, 'new']])
            proof = {'version': 2, 'run_id': '123', 'current_revision': 'a'*40, 'previous_revision': 'b'*40,
                     'current_contract_sha256': stateful.identity(new), 'previous_contract_sha256': stateful.identity(old),
                     'observed_schema': 2, 'data_revision': new['data_revision'], 'credential_revision': new['credential_revision'],
                     'status': 'passed', 'snapshot_sha256': hashlib.sha256(database.read_bytes()).hexdigest(),
                     'operations': {name: 'passed' for name in ('new_migrations', 'new_write', 'previous_read', 'previous_write', 'previous_reload_read', 'new_reload_read')}}
            self.assertTrue(stateful.check_rollback(new, old, proof, 'a'*40, 'b'*40, '123'))
            for target in ('schema', 'migration', 'credentials', 'data', 'source', 'proof'):
                changed = copy.deepcopy(old)
                changed_proof = copy.deepcopy(proof)
                if target == 'schema': changed['schema']['maximum'] = 1
                if target == 'migration': changed['migrations'][0]['sha256'] = 'f'*64
                if target == 'credentials': changed['credential_revision'] = 'unrestricted-owner-v0'
                if target == 'data': changed['data_revision'] = 'records-v0'
                if target == 'source': changed['source_revision'] = 'c'*40
                if target == 'proof': changed_proof['operations']['new_reload_read'] = 'failed'
                changed_proof['previous_contract_sha256'] = stateful.identity(changed)
                with self.subTest(target=target), self.assertRaises(ValueError):
                    stateful.check_rollback(new, changed, changed_proof, 'a'*40, 'b'*40, '123')
            # A destructive rewrite actually breaks the old executable too.
            with sqlite3.connect(database) as connection:
                connection.execute('ALTER TABLE records RENAME COLUMN value TO value_text')
            failed = subprocess.run([sys.executable, '-I', '-c', read, str(database), 'SELECT value FROM records'], capture_output=True, timeout=10)
            self.assertNotEqual(failed.returncode, 0)

    def test_malformed_and_duplicate_contract_fields_refuse(self):
        new, _ = contracts()
        for change in ({'version': True}, {'recovery_action': 'restore_snapshot'}, {'recovery_action': []}, {'migrations': []},
                       {'schema': {'minimum': 1, 'maximum': 1, 'write': 2}}, {'migrations': new['migrations']*2},
                       {'credential_revision': 'private key material with whitespace'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                stateful.validate({**new, **change})
