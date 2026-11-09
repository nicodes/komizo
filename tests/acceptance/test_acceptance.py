"""Refuse weakened, substituted or privately scoped native release evidence."""
import copy
import contextlib
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
from types import SimpleNamespace

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
                    {'real_reboot', 'bounded_full_postgresql_offline_reboot', 'fixed_budget_performance', 'source_bound_authenticated_snapshot'})}}
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
                lambda n: n['profiles']['bounded']['checks'].pop('source_bound_authenticated_snapshot'),
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
            boundaries.assert_called_once_with({}, phase='post-reboot')
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


class NativeCaptureGuards(unittest.TestCase):
    def test_tcp_control_uses_the_actual_installed_source_before_asserting_isolation(self):
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        digest = lambda body: 'sha256:' + hashlib.sha256(body).hexdigest()
        document = {'source': {'revision': 'c' * 40}}
        identity = digest(canonical(document))
        record = {'release_digest': identity, 'resources': {'containers': {'api': {'name': 'fixture-api'}}}}
        files = {'/var/lib/komizo/instances/pgbox--production.json': json.dumps(record),
            '/var/lib/komizo/releases/' + identity[7:] + '.json': json.dumps(document)}
        responses = [subprocess.CompletedProcess([], 0, b'HTTP/1.0 200 OK\r\n\r\n' + b'c' * 40),
                     subprocess.CompletedProcess([], 1, b'')]
        run = Mock(side_effect=responses)
        spec = importlib.util.spec_from_file_location('network_fixture', ENGINE.parent / 'support/native_host_runtime.py')
        fixture = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'acceptance': SimpleNamespace(ROOT=Path('/fixture'), MiB=1 << 20, BINARY='/fixture/box',
                run=run, write=Mock(), actual_boundaries=Mock(), capacity=Mock()),
                'fixture_registry': SimpleNamespace(canonical=canonical, digest=digest)}):
            spec.loader.exec_module(fixture)
        fixture.Path = lambda name: SimpleNamespace(read_text=lambda: files[name])
        fixture.container = lambda _: {'State': {'Running': True}, 'NetworkSettings': {'Networks': {'private': {'IPAddress': '10.0.0.2'}}}}
        fixture.cross_network_refused('pgbox', 'pgbox', 'api', 8080)
        self.assertEqual(run.call_count, 2)
        run.reset_mock(side_effect=True)
        run.return_value = subprocess.CompletedProcess([], 0, b'a' * 40)
        with self.assertRaisesRegex(ValueError, 'positive TCP control failed'):
            fixture.cross_network_refused('pgbox', 'pgbox', 'api', 8080)
        self.assertEqual(run.call_count, 1)

    def test_actual_source_identity_reaches_pinned_postgres_build_without_engine_side_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            identity = {'repository': 'nicodes/komizo', 'repository_id': '1315697543', 'revision': 'c' * 40}
            (root / 'profile.json').write_text(json.dumps({'source': identity}))
            run = Mock(side_effect=RuntimeError('immutable engine reached'))
            spec = importlib.util.spec_from_file_location('native_pg_fixture', ENGINE.parent / 'support/native_host_postgres.py')
            fixture = importlib.util.module_from_spec(spec)
            with patch.dict(sys.modules, {'acceptance': SimpleNamespace(ROOT=root, MiB=1 << 20, run=run, write=Mock()),
                    'fixture_registry': SimpleNamespace(), 'fixture_runtime': SimpleNamespace()}):
                spec.loader.exec_module(fixture)
                with self.assertRaisesRegex(RuntimeError, 'immutable engine reached'):
                    fixture.postgres_artifact()
            run.assert_called_once_with(['podman', '--remote=false', 'pull', fixture.BASE], timeout=300)
            recipe = (root / 'postgres-build/Containerfile').read_text()
            self.assertIn('https://github.com/' + identity['repository'], recipe)
            self.assertIn(identity['revision'], recipe)

    def adapter(self, failure=None):
        path = ENGINE.parent / 'fixtures/native_host/pg-capture.py'
        spec = importlib.util.spec_from_file_location('native_pg_capture', path)
        adapter = importlib.util.module_from_spec(spec); spec.loader.exec_module(adapter)
        state = {'committed': False, 'cleaned': False}
        record = {'image_ref': 'ghcr.io/example/postgres@sha256:' + 'a' * 64,
                  'image_config_digest': 'sha256:' + 'b' * 64}
        deployment = {'release': {'source': {'repository': 'nicodes/komizo'}}}
        resources = SimpleNamespace(query=lambda *args: record,
            metadata=lambda _: ('a' * 40, {}, deployment), unchanged=lambda _: None)
        class Session:
            def __enter__(self):return self
            def __exit__(self, *_):pass
            def begin(self):pass
            def query(self, sql):return '180006' if 'server_version_num' in sql else 'fixture'
            def export_snapshot(self):return '00000003-0000001A-1'
            def verify_snapshot(self):
                if failure == 'witness':raise ValueError('changed transaction witness')
            def commit(self):
                if failure == 'commit':raise ValueError('unacknowledged commit')
                state['committed'] = True
        class Client:
            def version(self):return 'pg_dump (PostgreSQL) 18.6'
            def session(self):return Session()
            def dump(self, _, output):output.write_bytes(b'PGDMPsynthetic-unit-data')
        @contextlib.contextmanager
        def client(*args, **options):
            yield Client()
            if failure == 'cleanup':raise ValueError('owned helper remains')
            state['cleaned'] = True
        helpers = {'installed_resource': resources, 'postgres_client': SimpleNamespace(context=client)}
        adapter.helper = helpers.__getitem__
        return adapter, state

    def test_capture_completion_requires_snapshot_commit_and_client_cleanup(self):
        adapter, state = self.adapter()
        with tempfile.TemporaryDirectory(prefix='.export-') as temporary:
            root = Path(temporary); target = adapter.capture(root)
            self.assertTrue(state['committed'] and state['cleaned'])
            evidence = json.loads((target / 'capture.json').read_text())
            self.assertEqual(evidence['files']['database.dump']['sha256'], sha(target / 'database.dump'))
            self.assertEqual(json.loads((root / 'images.json').read_text())['engine']['image_id'], 'sha256:' + 'b' * 64)

    def test_changed_snapshot_unacknowledged_commit_or_retained_helper_cannot_emit_capture(self):
        for failure in ['witness', 'commit', 'cleanup']:
            adapter, _ = self.adapter(failure)
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix='.export-') as temporary:
                root = Path(temporary)
                with self.assertRaises(ValueError):adapter.capture(root)
                self.assertFalse((root / 'capture').exists())
                self.assertFalse((root / 'images.json').exists())


class NativeRecoverySourceGuards(unittest.TestCase):
    def test_source_is_data_until_its_exact_clean_repository_and_bytes_are_admitted(self):
        spec = importlib.util.spec_from_file_location('native_host_recovery', ENGINE.parent / 'support/native_host_recovery.py')
        recovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(recovery)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            def git(*args):
                return subprocess.check_output(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
                    '-c', 'user.name=Native fixture', '-c', 'user.email=fixture@example.invalid', '-C', str(root), *args],
                    stderr=subprocess.PIPE, timeout=10)
            git('init', '-q')
            original = b'raise RuntimeError("source must not execute during admission")\n'
            path = root / 'fixture.py'; path.write_bytes(original)
            git('add', 'fixture.py'); git('commit', '-qm', 'Source fixture')
            git('remote', 'add', 'origin', 'https://github.com/nicodes/tools.git')
            revision = git('rev-parse', 'HEAD').decode().strip()
            self.assertEqual(recovery.selected(root, 'nicodes/tools', revision), root)
            self.assertEqual(recovery.source_file(root, revision, 'fixture.py'), original)
            for relative in ['../fixture.py', '/fixture.py', 'a/../fixture.py']:
                with self.subTest(relative=relative), self.assertRaises(ValueError):
                    recovery.source_file(root, revision, relative)
            with self.assertRaises(ValueError):recovery.selected(root, 'nicodes/other', revision)
            path.write_bytes(b'changed accepted bytes')
            with self.assertRaises(ValueError):recovery.source_file(root, revision, 'fixture.py')
            with self.assertRaises(subprocess.CalledProcessError):recovery.selected(root, 'nicodes/tools', revision)


if __name__ == '__main__':
    unittest.main()
