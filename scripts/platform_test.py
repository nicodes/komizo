import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('platform_operator', Path(__file__).with_name('platform.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Fixture:
    def __init__(self, root):
        self.root = Path(root)
        self.stage = self.root/'var/lib/komizo/upgrades/fixture'
        self.stage.mkdir(parents=True, mode=0o700)
        for name in ('run/komizo', 'var/lib/komizo/apps', 'etc/komizo', 'usr/local/bin'):
            (self.root/name).mkdir(parents=True, exist_ok=True)
        (self.root/'etc/komizo/agent.json').write_bytes(b'owner-model-roster-and-private-fixture')
        self.active = {'komizo-rootd', 'komizo-api'}
        self.calls = []
        files = []
        self.before = {}
        for path, name, mode in [('/usr/local/bin/komizo-box', 'box', 0o755), ('/var/lib/komizo/version', 'version', 0o644)]:
            old, new = b'old-'+name.encode(), b'new-'+name.encode()
            destination = self.root/path.lstrip('/')
            destination.write_bytes(old)
            os.chmod(destination, mode)
            self.before[path] = old
            (self.stage/name).write_bytes(new)
            files.append({'path': path, 'staged': name, 'before': hashlib.sha256(old).hexdigest(),
                          'after': hashlib.sha256(new).hexdigest(), 'mode': mode})
        receipt = {'version': 1, 'source': 'a'*40, 'authenticated': True, 'kind': 'self-upgrade', 'files': files, 'image': None}
        body = json.dumps(receipt).encode()
        (self.stage/'verified-release.json').write_bytes(body)
        manifest = {'version': 1, 'kind': 'self-upgrade', 'source': 'a'*40, 'release': 'v0.0.77', 'files': files,
                    'receipt_sha256': hashlib.sha256(body).hexdigest(), 'image': None, 'probes': []}
        body = json.dumps(manifest).encode()
        (self.stage/'manifest.json').write_bytes(body)
        self.expected = hashlib.sha256(body).hexdigest()
        for path in self.stage.iterdir():
            os.chmod(path, 0o600)
        self.p = module.Platform(self.root, self.run, os.getuid())

    def run(self, args, required=True):
        self.calls.append(args)
        if args[0] == 'rc-service':
            _, service, action = args
            if action == 'status':
                return (0 if service in self.active else 1), ''
            if action == 'stop':
                self.active.discard(service)
            elif action == 'start':
                self.active.add(service)
        if args == ['komizo-box', 'version']:
            return 0, 'v0.0.77\n'
        return 0, ''


class PlatformTests(unittest.TestCase):
    def test_upgrade_preserves_service_state_agent_and_exact_files(self):
        with tempfile.TemporaryDirectory() as root:
            f = Fixture(root)
            config = (f.root/'etc/komizo/agent.json').read_bytes()
            result = f.p.apply(f.stage, f.expected)
            self.assertEqual(result['phase'], 'complete')
            self.assertEqual(f.active, {'komizo-rootd', 'komizo-api'})
            self.assertEqual((f.root/'etc/komizo/agent.json').read_bytes(), config)
            self.assertFalse((f.stage.parent/'pending.json').exists())
            self.assertFalse(any(a[0] == 'docker' for a in f.calls))
            self.assertFalse(result['application_restart'])

    def test_disconnect_at_every_replacement_recovers_exact_previous(self):
        for phase in ('prepared', 'replaced-0', 'replaced-1'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as root:
                f = Fixture(root)
                def disconnect(at):
                    if at == phase:
                        raise SystemExit('owned fixture disconnect')
                f.p.checkpoint = disconnect
                with self.assertRaises(SystemExit):
                    f.p.apply(f.stage, f.expected)
                self.assertTrue((f.stage.parent/'pending.json').exists())
                result = f.p.apply(f.stage, f.expected, recover=True)
                self.assertEqual(result['phase'], 'recovered')
                for path, body in f.before.items():
                    self.assertEqual(f.p.path(path).read_bytes(), body)
                self.assertEqual(f.active, {'komizo-rootd', 'komizo-api'})

    def test_failure_rolls_back_and_foreign_write_keeps_recovery_fence(self):
        with tempfile.TemporaryDirectory() as root:
            f = Fixture(root)
            def failure(at):
                if at == 'replaced-0':
                    raise ValueError('fixture readiness failure')
            f.p.checkpoint = failure
            with self.assertRaises(ValueError):
                f.p.apply(f.stage, f.expected)
            self.assertEqual(f.p.path('/usr/local/bin/komizo-box').read_bytes(), f.before['/usr/local/bin/komizo-box'])
            self.assertEqual(f.active, {'komizo-rootd', 'komizo-api'})
        with tempfile.TemporaryDirectory() as root:
            f = Fixture(root)
            def disconnect(at):
                if at == 'replaced-0':
                    raise SystemExit()
            f.p.checkpoint = disconnect
            with self.assertRaises(SystemExit):
                f.p.apply(f.stage, f.expected)
            f.p.path('/usr/local/bin/komizo-box').write_bytes(b'newer-owner-write')
            with self.assertRaisesRegex(ValueError, 'changed installed'):
                f.p.apply(f.stage, f.expected, recover=True)
            self.assertTrue((f.stage.parent/'pending.json').exists())
            self.assertEqual(f.p.path('/usr/local/bin/komizo-box').read_bytes(), b'newer-owner-write')

    def test_disconnect_after_acceptance_finishes_without_rolling_back(self):
        with tempfile.TemporaryDirectory() as root:
            f = Fixture(root)
            def disconnect(at):
                if at == 'complete':
                    raise SystemExit()
            f.p.checkpoint = disconnect
            with self.assertRaises(SystemExit):
                f.p.apply(f.stage, f.expected)
            result = f.p.apply(f.stage, f.expected, recover=True)
            self.assertEqual(result['phase'], 'complete')
            self.assertEqual(f.p.path('/usr/local/bin/komizo-box').read_bytes(), b'new-box')
            self.assertFalse((f.stage.parent/'pending.json').exists())

    def test_grant_drift_and_unknown_deployment_phase_refuse_before_effects(self):
        for condition in ('manifest', 'staged', 'installed', 'fence', 'other-platform'):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as root:
                f = Fixture(root)
                if condition == 'manifest':
                    (f.stage/'manifest.json').write_bytes(b'{}')
                elif condition == 'staged':
                    (f.stage/'box').write_bytes(b'foreign')
                elif condition == 'installed':
                    f.p.path('/usr/local/bin/komizo-box').write_bytes(b'foreign')
                elif condition == 'fence':
                    path = f.p.path('/var/lib/komizo/releases/example/operation.json')
                    path.parent.mkdir(parents=True)
                    path.write_text('{"version":2,"phase":"ready"}')
                    path.chmod(0o600)
                else:
                    path = f.stage.parent/'pending.json'
                    path.write_text('{"stage":"other","manifest":"other"}')
                    path.chmod(0o600)
                with self.assertRaises(ValueError):
                    f.p.apply(f.stage, f.expected)
                self.assertFalse(any(a[-1] in ('start', 'stop') for a in f.calls))


if __name__ == '__main__':
    unittest.main()
