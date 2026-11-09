"""Refuse weakened, substituted or privately scoped native release evidence."""
import copy
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch

import native_release
import test_native_release as fixtures
from candidate_evidence import CANDIDATE_STEPS, BOUNDED_STEPS, export
from performance_acceptance import SCOPE, evaluate
from release_acceptance import REQUIRED_STEPS, validate, validate_bundle

ENGINE = Path(__file__).parent
_driver_spec = importlib.util.spec_from_file_location('native_host_vm', ENGINE.parent / 'support/native_host_vm.py')
driver = importlib.util.module_from_spec(_driver_spec)
_driver_spec.loader.exec_module(driver)
CLEANUP = {'version': 1, 'owned_guest_removed': True, 'private_storage_removed': True, 'shared_images_removed': False}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AcceptanceGuards(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.NativeRelease('test_complete_standalone_payload_is_independently_source_bound')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.archives, self.source, self.release = fixture.root, fixture.source, fixture.tag
        self.budget = tomllib.loads((ENGINE / 'acceptance-budgets.toml').read_text())
        files = native_release.inventory(self.archives, self.source, self.release)
        host, proxy = files['komizo-box_Linux_x86_64']['sha256'], files['caddy_Linux_x86_64']['sha256']
        self.metrics = {'guest_memory_bytes': self.budget['guest_memory_bytes'], 'guest_milli_cpus': self.budget['guest_milli_cpus'],
            'setup_seconds': 30, 'deployment_seconds': 2, 'idle_control_pss_bytes': 48 << 20,
            'route_seconds': [.1] * 5, 'operator_seconds': [.2] * 5, 'load_hot_bytes': 64 << 20,
            'load_cpu_usec': 2_000_000, 'oom_events_unchanged': True, 'owned_load_removed': True,
            'control_processes': [dict(role=role, pid=index, pss_bytes=16 << 20, executable_sha256=digest,
                cgroup='/komizo.slice/komizo-' + ('proxy' if role == 'proxy' else 'control') + '.slice/owned.service')
                for index, (role, digest) in enumerate([('controller', host), ('proxy', proxy), ('dns', 'd' * 64)], 1)],
            'control_services_running': {'controller': True, 'proxy': True}}
        self.native = {'version': 1, 'release': self.release, 'source': self.source, 'candidate_cli': None,
            'signed_release_acceptance': True, 'cli_sha256': files['komizo_Linux_x86_64.tar.gz']['executable_sha256'],
            'host_sha256': host, 'proxy_sha256': proxy, 'runner_sha256': sha(ENGINE / 'cold-lifecycle-acceptance.py'),
            'authenticated_files': files, 'steps': [{'step': name, 'accepted': True} for name in sorted(REQUIRED_STEPS)],
            'profiles': {name: {'ok': True, 'profile': name, 'source': {'revision': self.source, 'binary_sha256': host},
                'checks': {check: 'passed' for check in (REQUIRED_STEPS if name == 'functional' else
                    {'real_reboot', 'bounded_full_postgresql_offline_reboot', 'fixed_budget_performance'})}}
                for name in ['functional', 'bounded']}}
        self.performance = {'version': 1, 'scope': SCOPE, 'accepted': True, 'budget': self.budget, 'metrics': self.metrics,
                            'budget_sha256': sha(ENGINE / 'acceptance-budgets.toml')}
        self.onboarding = {'accepted': True, 'commands': 6, 'seconds': 1, 'public_readme_sha256': sha(ENGINE.resolve().parents[1] / 'README.md'),
            'mode': 'deterministic_public_cli', 'human_interventions': 0, 'provider_credentials_in_task': False,
            'source_checkout_in_task': False, 'cli_sha256': self.native['cli_sha256']}

    def args(self):
        return copy.deepcopy([self.native, CLEANUP, self.performance, self.onboarding, self.release, self.source, self.budget])

    def test_rejects_vacuous_nonfinite_regressed_or_unloaded_measurements(self):
        self.assertTrue(evaluate(self.metrics, self.budget))
        for field, value in [('guest_memory_bytes', 2 << 30), ('guest_milli_cpus', 2000),
                ('route_seconds', []), ('route_seconds', [math.nan] * 5), ('operator_seconds', [6] * 5),
                ('idle_control_pss_bytes', 129 << 20), ('setup_seconds', 361), ('deployment_seconds', 121),
                ('load_hot_bytes', 0), ('load_cpu_usec', 0), ('oom_events_unchanged', False), ('owned_load_removed', False)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                evaluate({**self.metrics, field: value}, self.budget)

    def test_complete_actual_process_identity_and_protected_pool_accounting_are_required(self):
        for mutate in [lambda m: m['control_processes'].pop(),
                lambda m: m['control_processes'][1].update(pid=1),
                lambda m: m['control_processes'][0].update(pss_bytes=0),
                lambda m: m['control_processes'][1].update(cgroup='/other/owned.service'),
                lambda m: m['control_processes'][2].update(executable_sha256='unknown'),
                lambda m: m['control_services_running'].update(controller=False)]:
            metrics = copy.deepcopy(self.metrics); mutate(metrics)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                evaluate(metrics, self.budget)

    def test_promotion_refuses_wrong_source_candidate_missing_tests_cleanup_and_cold_owner(self):
        self.assertTrue(validate(*self.args()))
        for index, field, value in [(0, 'source', 'e' * 40), (0, 'candidate_cli', {'authenticated': False}),
                (0, 'signed_release_acceptance', False), (0, 'steps', []), (0, 'proxy_sha256', 'unknown'),
                (1, 'owned_guest_removed', False), (1, 'private_storage_removed', False), (1, 'shared_images_removed', True),
                (2, 'accepted', False), (2, 'version', True), (2, 'scope', 'unreviewed scope'),
                (3, 'human_interventions', 1), (3, 'source_checkout_in_task', True),
                (3, 'provider_credentials_in_task', True), (3, 'cli_sha256', 'e' * 64)]:
            args = self.args(); args[index][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(*args)

    def test_both_real_boot_profiles_exact_host_bytes_and_independent_control_classes_are_required(self):
        for mutate in [lambda n: n['profiles'].pop('bounded'),
                lambda n: n['profiles']['functional']['source'].update(binary_sha256='f' * 64),
                lambda n: n['profiles']['bounded']['source'].update(revision='f' * 40),
                lambda n: n['profiles']['functional']['checks'].pop('owner_postgresql_encrypted_restore'),
                lambda n: n['profiles']['bounded']['checks'].pop('fixed_budget_performance'),
                lambda n: n['profiles']['functional']['checks'].update(real_reboot='not_run')]:
            args = self.args(); mutate(args[0])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                validate(*args)
        args = self.args(); args[2]['metrics']['control_processes'][0]['executable_sha256'] = 'f' * 64
        with self.assertRaises(ValueError): validate(*args)

    def evidence(self, bundle):
        (bundle / 'komizo-performance.json').write_text(json.dumps(self.performance))
        summary = {'accepted': True, 'release': self.release, 'source': self.source, 'native': self.native,
            'cleanup': CLEANUP, 'onboarding': self.onboarding, 'performance_sha256': sha(bundle / 'komizo-performance.json')}
        (bundle / 'komizo-acceptance.json').write_text(json.dumps(summary))

    def test_replaced_checksums_cannot_swap_any_accepted_owner_host_proxy_or_receipt_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary); self.evidence(bundle)
            self.assertTrue(validate_bundle(bundle, self.release, self.source, self.archives))
            for name in ['komizo_Linux_x86_64.tar.gz', 'komizo-box_Linux_x86_64', 'caddy_Linux_x86_64', 'caddy_Linux_x86_64.json']:
                path = self.archives / name; original = path.read_bytes()
                path.write_bytes(original + b' ')
                (self.archives / 'checksums.txt').write_text(''.join(sha(self.archives / item) + '  ' + item + '\n'
                    for item in sorted(native_release.PAYLOAD)))
                with self.subTest(name=name), self.assertRaises(ValueError):
                    validate_bundle(bundle, self.release, self.source, self.archives)
                path.write_bytes(original)
            (self.archives / 'checksums.txt').write_text(''.join(sha(self.archives / item) + '  ' + item + '\n'
                for item in sorted(native_release.PAYLOAD)))
            self.assertTrue(validate_bundle(bundle, self.release, self.source, self.archives))

    def test_changed_runner_budget_readme_or_performance_hash_cannot_relabel_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            for mutate in [lambda: self.native.update(runner_sha256='e' * 64),
                    lambda: self.performance.update(budget_sha256='e' * 64),
                    lambda: self.onboarding.update(public_readme_sha256='e' * 64)]:
                saved = copy.deepcopy((self.native, self.performance, self.onboarding)); mutate(); self.evidence(bundle)
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    validate_bundle(bundle, self.release, self.source, self.archives)
                self.native, self.performance, self.onboarding = saved
            self.evidence(bundle); (bundle / 'komizo-performance.json').write_text(json.dumps({**self.performance, 'accepted': False}))
            with self.assertRaises(ValueError): validate_bundle(bundle, self.release, self.source, self.archives)

    def test_failed_run_exports_cleanup_without_private_fixture_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); observations = root / 'private'; observations.mkdir(); output = root / 'export'
            (observations / 'cleanup.json').write_text(json.dumps(CLEANUP))
            (observations / 'ssh-private-key').write_text('private-value-never-export')
            result = subprocess.run([sys.executable, '-I', '-B', str(ENGINE / 'release_acceptance.py'), '--observations', str(observations),
                '--output', str(output), '--release', self.release, '--source', self.source], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual({p.name for p in output.iterdir()}, {'cleanup-status.json', 'status.json'})
            self.assertEqual(json.loads((output / 'cleanup-status.json').read_text()), dict(verified=True, **CLEANUP))
            self.assertFalse(json.loads((output / 'status.json').read_text())['accepted'])
            self.assertNotIn('private-value-never-export', ''.join(p.read_text() for p in output.iterdir()))

    def test_release_evidence_refuses_private_or_unknown_nested_metadata(self):
        for mutate in [lambda n: n.update(private_diagnostic='never-export'),
                lambda n: n['profiles']['functional'].update(private_diagnostic='never-export'),
                lambda n: n['profiles']['functional']['checks'].update(private_diagnostic='never-export'),
                lambda n: n['authenticated_files']['komizo-box_Linux_x86_64'].update(private_path='/private/key')]:
            args = self.args(); mutate(args[0])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                validate(*args)
        for mutate in [lambda args: args[0]['steps'][0].update(private_diagnostic='never-export'),
                lambda args: args[2]['metrics'].update(private_diagnostic='never-export'),
                lambda args: args[2]['metrics']['control_processes'][0].update(private_path='/private/key')]:
            args = self.args(); mutate(args)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                validate(*args)

    def test_candidate_export_retains_both_profiles_and_fixed_budget_without_a_release_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); observations = root / 'private'; observations.mkdir()
            result = {'source': self.source, 'accepted': True, 'signed_release_acceptance': False,
                'github_credentials_present': False, 'candidate_cli': {'authenticated': False, 'sha256': self.native['cli_sha256']},
                'host_sha256': self.native['host_sha256'], 'proxy_sha256': self.native['proxy_sha256'],
                'profiles': {profile: {'ok': True, 'profile': profile,
                    'source': {'revision': self.source, 'binary_sha256': self.native['host_sha256']},
                    'checks': {name: 'passed' for name in required}} for profile,required in [('functional',CANDIDATE_STEPS),('bounded',BOUNDED_STEPS)]},
                'private_diagnostic': 'never-export'}
            result['candidate_cli']['private_key'] = 'never-export'
            result['profiles']['functional']['private_path'] = 'never-export'
            result['profiles']['functional']['checks']['private_diagnostic'] = 'never-export'
            (observations / 'candidate-deployment.json').write_text(json.dumps(result))
            (observations / 'performance.json').write_text(json.dumps(self.performance))
            (observations / 'onboarding.json').write_text(json.dumps(self.onboarding | {'private_key':'never-export'}))
            (observations / 'cleanup.json').write_text(json.dumps(CLEANUP)); (observations / 'private-key').write_text('never-export')
            output = root / 'export'; export(observations, output, self.source)
            self.assertEqual({p.name for p in output.iterdir()}, {'candidate-deployment.json','candidate-performance.json','candidate-onboarding.json','cleanup.json'})
            self.assertNotIn('never-export', ''.join(p.read_text() for p in output.iterdir()))
            self.assertEqual(json.loads((output / 'candidate-deployment.json').read_bytes())['source'], self.source)
            for mutate in [lambda r: r.update(signed_release_acceptance=True),
                    lambda r: r['candidate_cli'].update(authenticated=True),
                    lambda r: r['profiles']['functional']['source'].update(binary_sha256='f' * 64),
                    lambda r: r['profiles']['functional']['checks'].pop('owner_postgresql_encrypted_restore'),
                    lambda r: r['profiles'].pop('bounded'),
                    lambda r: r['profiles']['bounded']['checks'].pop('fixed_budget_performance'),
                    lambda r: r['profiles']['bounded']['source'].update(revision='f'*40)]:
                bad = copy.deepcopy(result); mutate(bad); (observations / 'candidate-deployment.json').write_text(json.dumps(bad))
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    export(observations, root / 'refused', self.source)
            (observations / 'candidate-deployment.json').write_text(json.dumps(result))
            for mutate in [lambda p: p['metrics'].update(guest_memory_bytes=2<<30),
                    lambda p: p['metrics'].update(guest_milli_cpus=2000),
                    lambda p: p['metrics'].update(oom_events_unchanged=False),
                    lambda p: p.update(budget_sha256='f'*64)]:
                bad=copy.deepcopy(self.performance);mutate(bad)
                (observations/'performance.json').write_text(json.dumps(bad))
                with self.subTest(mutate=mutate),self.assertRaises(ValueError):export(observations,root/'refused',self.source)
            with self.assertRaises(ValueError): export(observations, root / 'foreign', 'b' * 40)


class NativeBootGuards(unittest.TestCase):
    def test_bounded_reboot_verifies_its_own_graph_without_a_functional_only_application(self):
        spec = importlib.util.spec_from_file_location('native_fixture_acceptance', ENGINE.parent / 'support/native_host_acceptance.py')
        acceptance = importlib.util.module_from_spec(spec); spec.loader.exec_module(acceptance)
        runtime = Mock()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = {'profile': 'bounded', 'installed': {'static': 'sha256:' + 'a' * 64}, 'checks': {}, 'ok': False}
            (root / 'report.json').write_text(json.dumps(original))
            read_text = Path.read_text
            def selected_file(path, *args, **options):
                if str(path) == '/etc/komizo/capacity.json':
                    return '{}'
                return read_text(path, *args, **options)
            with patch.object(acceptance, 'ROOT', root), patch.object(acceptance, 'actual_boundaries') as boundaries, \
                    patch.object(acceptance, 'inspect', side_effect=AssertionError('bounded profile has no mailroom')), \
                    patch.dict(sys.modules, {'fixture_runtime': runtime}), patch.object(Path, 'read_text', selected_file):
                acceptance.verify_reboot()
            runtime.verify_reboot.assert_called_once_with()
            boundaries.assert_called_once_with({})
            result = json.loads((root / 'report.json').read_text())
            self.assertTrue(result['ok'])
            self.assertEqual(result['checks'], {'real_reboot': 'passed'})

    def test_cloud_setup_refusal_cannot_become_readiness_or_extend_its_deadline(self):
        guest = object.__new__(driver.Guest)
        process = Mock(); process.poll.return_value = None
        clock = [0.0]; bounds = []
        def command(argv, *, timeout, **options):
            bounds.append(timeout); clock[0] += timeout
            return subprocess.CompletedProcess(argv, 2, b'degraded', b'')
        guest.command = command
        with patch.object(driver.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(driver.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            with self.assertRaisesRegex(ValueError, 'readiness deadline expired.*returncode.*2'):
                guest.ready(process, 20)
        self.assertEqual(bounds, [15, 4])
        self.assertEqual(clock[0], 20)

    def test_success_requires_cloud_completion_and_a_live_owned_guest(self):
        guest = object.__new__(driver.Guest)
        guest.command = Mock(return_value=subprocess.CompletedProcess([], 0, b'done', b''))
        process = Mock(); process.poll.return_value = None
        guest.ready(process, driver.time.monotonic() + 1)
        self.assertIn('cloud-init status --wait', guest.command.call_args.args[0])
        process.poll.return_value = 1
        with self.assertRaisesRegex(ValueError, 'stopped before SSH readiness'):
            guest.ready(process, driver.time.monotonic() + 1)


if __name__ == '__main__':
    unittest.main()
