import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('backup_proof', Path(__file__).parents[1]/'helpers/backup-proof.py')
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class BackupProof(unittest.TestCase):
    def environment(self):
        return {'GITHUB_REPOSITORY': 'example/product', 'GITHUB_REPOSITORY_ID': '123',
                'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': 'a'*40, 'GITHUB_RUN_ID': '456',
                'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_EVENT_NAME': 'schedule',
                'ACTIONS_ID_TOKEN_REQUEST_URL': 'https://fixture.actions.githubusercontent.com/token?audience=old',
                'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'synthetic-request-secret'}

    def test_private_frame_binds_exact_manifest_without_logging_token(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'operation.frame'
            with patch.object(proof, 'identity', return_value='header.body.signature') as identity:
                result = proof.prepare(output, self.environment())
            wire = output.read_bytes()
            self.assertTrue(wire.startswith(b'komizo-operation/v1:'))
            envelope = json.loads(base64.b64decode(wire.split(b':', 1)[1]))
            raw = base64.b64decode(envelope['manifest'])
            manifest = json.loads(raw)
            self.assertEqual(manifest, {'version': 1, 'purpose': 'routine-backup', 'repository': 'example/product',
                                       'repository_id': '123', 'revision': 'a'*40, 'run_id': '456', 'attempt': '2'})
            audience = 'komizo-operation:sha256:'+hashlib.sha256(raw).hexdigest()
            self.assertEqual(identity.call_args.args[1], audience)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('header.body.signature', json.dumps(result))
            before = output.read_bytes()
            with patch.object(proof, 'identity') as network:
                with self.assertRaises(ValueError): proof.prepare(output, self.environment())
                network.assert_not_called()
            self.assertEqual(output.read_bytes(), before)

    def test_foreign_context_is_refused_before_oidc_or_file_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'operation.frame'
            for variable, value in [('GITHUB_REF', 'refs/pull/1/merge'), ('GITHUB_EVENT_NAME', 'push'),
                                    ('GITHUB_SHA', 'main'), ('GITHUB_RUN_ATTEMPT', '0'), ('GITHUB_REPOSITORY_ID', '')]:
                environment = self.environment(); environment[variable] = value
                with self.subTest(variable=variable), patch.object(proof, 'identity') as network:
                    with self.assertRaises(ValueError): proof.prepare(output, environment)
                    network.assert_not_called(); self.assertFalse(output.exists())

    def test_issuer_request_has_bounded_response_and_never_follows_redirect(self):
        calls = []
        class Response:
            status = 200
            body = json.dumps({'value': 'header.body.signature'}).encode()
            def read(self, bound):
                self.assertion = bound
                return self.body[:bound]
        response = Response()
        class Connection:
            def __init__(self, hostname, **options): calls.append(('connect', hostname, options))
            def request(self, method, path, **options): calls.append(('request', method, path, options))
            def getresponse(self): return response
            def close(self): calls.append(('closed',))
        environment = self.environment()
        with patch.object(proof.http.client, 'HTTPSConnection', Connection):
            self.assertEqual(proof.identity(environment, 'bound-audience'), 'header.body.signature')
            self.assertEqual(calls[0][2]['timeout'], 10)
            self.assertIn('audience=bound-audience', calls[1][2]); self.assertNotIn('audience=old', calls[1][2])
            for status, body in [(302, b'{}'), (200, b'x'*(33 << 10)), (200, b'{"value":"malformed"}')]:
                response.status, response.body = status, body
                with self.assertRaises(ValueError): proof.identity(environment, 'bound-audience')
        for url in ('http://fixture.actions.githubusercontent.com/token', 'https://attacker.invalid/token',
                    'https://secret@fixture.actions.githubusercontent.com/token', 'https://fixture.actions.githubusercontent.com:8443/token'):
            environment['ACTIONS_ID_TOKEN_REQUEST_URL'] = url
            with patch.object(proof.http.client, 'HTTPSConnection') as network:
                with self.assertRaises(ValueError): proof.identity(environment, 'bound-audience')
                network.assert_not_called()


if __name__ == '__main__': unittest.main()
