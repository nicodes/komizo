"""Finite package-input controls; synthetic APK bytes never attest signatures."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native_packages', ROOT / 'tests/support/native_host_packages.py')
packages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packages)


def canonical(value):
    return json.dumps(value, sort_keys=True).encode()


class ImmutablePackageInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.old_umask = os.umask(0o077)
        self.addCleanup(os.umask, self.old_umask)
        self.key_name = 'alpine-devel@lists.alpinelinux.org-deadbeef.rsa.pub'
        self.keys = self.root / 'official-image-keys'
        self.keys.mkdir()
        (self.keys / self.key_name).write_bytes(b'SYNTHETIC OFFICIAL PUBLIC KEY')
        self.files = {
            'crun-1.30.1-r0.apk': b'SYNTHETIC APK ONE',
            'podman-5.8.10-r0.apk': b'SYNTHETIC APK TWO',
            'keys/' + self.key_name: (self.keys / self.key_name).read_bytes(),
            'installed.txt': b'crun-1.30.1-r0 - synthetic\npodman-5.8.10-r0 - synthetic\n',
            'repositories': b'https://dl-cdn.alpinelinux.org/alpine/v3.24/main\n'
                            b'https://dl-cdn.alpinelinux.org/alpine/v3.24/community\n',
            'APKINDEX.01234567.tar.gz': b'SYNTHETIC ORIGINAL MAIN INDEX',
            'APKINDEX.89abcdef.tar.gz': b'SYNTHETIC ORIGINAL COMMUNITY INDEX'}
        self.files['SHA256SUMS'] = ''.join(
            packages.digest(raw) + '  ' + name + '\n'
            for name, raw in self.files.items() if name.endswith('.apk')).encode()
        self.config = {'image': {'sha512': 'a' * 128, 'signing_fingerprint': 'B' * 40},
            'requested_packages': ['crun=1.30.1-r0', 'podman=5.8.10-r0'],
            'closure': {'archive': {}, 'manifest': {}, 'apk_count': 2,
                        'trusted_keys': {self.key_name: packages.digest(self.files['keys/' + self.key_name])}}}
        self.calls = []
        self.fetches = []
        self.bind()

    def archive(self, extra=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:', format=tarfile.USTAR_FORMAT) as archive:
            for name in ['.', 'keys']:
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE
                member.mode = 0o700 if name == '.' else 0o755
                archive.addfile(member)
            for name, raw in self.files.items():
                member = tarfile.TarInfo('./' + name)
                member.size = len(raw)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(raw))
            if extra is not None:
                archive.addfile(extra, io.BytesIO(b'X') if extra.size else None)
        return output.getvalue()

    def bind(self, raw=None):
        self.archive_bytes = self.archive() if raw is None else raw
        prefix = 'https://github.com/nicodes/komizo/releases/download/native-alpine-3.24.3-x86_64-0123456789ab/'
        self.config['closure']['archive'] = {'url': prefix + 'alpine-packages.tar',
            'sha256': packages.digest(self.archive_bytes), 'size_bytes': len(self.archive_bytes)}
        self.manifest = {'kind': 'komizo.alpine-public-package-closure', 'version': 1,
            'production_host_packages_changed': False, 'image': self.config['image'],
            'requested_packages': self.config['requested_packages'],
            'sha256': packages.digest(self.archive_bytes), 'size_bytes': len(self.archive_bytes),
            'signature_verification': 'apk add --no-network with trusted distro keys'}
        self.manifest_bytes = canonical(self.manifest)
        self.config['closure']['manifest'] = {'url': prefix + 'alpine-packages.json',
            'sha256': packages.digest(self.manifest_bytes), 'size_bytes': len(self.manifest_bytes)}

    def downloader(self, record, target, deadline):
        self.assertGreater(deadline, 0)
        self.fetches.append(record['url'])
        target.write_bytes(self.manifest_bytes if target.suffix == '.json' else self.archive_bytes)

    def execute(self, argv, **options):
        self.calls.append((argv, options))
        return SimpleNamespace(returncode=0,
            stdout=self.files['installed.txt'] if argv == ['apk', 'info', '-vv'] else b'', stderr=b'')

    def install(self, execute=None):
        return packages.install(self.config, self.root / 'native-host', self.keys,
                                execute or self.execute, self.downloader)

    def test_exact_public_input_validates_and_only_stock_offline_apk_can_mark_ready(self):
        keys_before = {path.name: path.read_bytes() for path in self.keys.iterdir()}
        self.install()
        self.assertTrue((self.root / 'native-host/cloud-ready').exists())
        self.assertEqual(len(self.fetches), 2)
        command = self.calls[0][0]
        self.assertEqual(command[:5], ['apk', '--no-network', '--repositories-file', '/dev/null', '--cache-dir'])
        self.assertEqual(command[5], str(self.root / 'native-host/apk-cache'))
        self.assertEqual(command[6], 'add')
        self.assertEqual([Path(value).name for value in command[7:]],
                         sorted(name for name in self.files if name.endswith('.apk')))
        self.assertNotIn('--allow-untrusted', command)
        self.assertNotIn('--force-non-repository', command)
        self.assertNotIn('--keys-dir', command)
        self.assertEqual(self.calls[1][0], ['apk', 'info', '-vv'])
        self.assertEqual({path.name: path.read_bytes() for path in self.keys.iterdir()}, keys_before)
        self.assertEqual((self.root / 'native-host/alpine-packages.tar').read_bytes(), self.archive_bytes)

    def test_live_repository_wrong_host_redirect_source_and_mutable_urls_refuse(self):
        for url in ['http://github.com/nicodes/komizo/releases/download/native-alpine-3.24.3-x86_64-0123456789ab/alpine-packages.tar',
                    'https://dl-cdn.alpinelinux.org/alpine/v3.24/community/crun.apk',
                    self.config['closure']['archive']['url'] + '?mutable=1',
                    self.config['closure']['archive']['url'].replace('/nicodes/komizo/', '/foreign/repository/')]:
            with self.subTest(url=url):
                changed = copy.deepcopy(self.config)
                changed['closure']['archive']['url'] = url
                with self.assertRaises(ValueError):
                    packages.input_record(changed)
        self.assertEqual(self.calls, [])

    def test_duplicate_json_or_wrong_manifest_source_pins_image_and_bytes_refuse(self):
        with self.assertRaises(ValueError):
            packages.decode(b'{"image":1,"image":2}')
        for key, value in [('requested_packages', ['crun=1.31-r0']), ('image', {'sha512': 'f' * 128}),
                           ('production_host_packages_changed', True), ('sha256', 'f' * 64)]:
            with self.subTest(key=key):
                changed = dict(self.manifest, **{key: value})
                raw = canonical(changed)
                config = copy.deepcopy(self.config)
                config['closure']['manifest'].update(sha256=packages.digest(raw), size_bytes=len(raw))
                with self.assertRaises(ValueError):
                    packages.manifest_record(raw, config)
        with self.assertRaises(ValueError):
            packages.manifest_record(self.manifest_bytes + b' ', self.config)

    def test_archive_outer_digest_or_all_member_checksums_cannot_be_omitted(self):
        original = self.archive_bytes
        self.archive_bytes = original[:-1] + b'X'
        with self.assertRaisesRegex(ValueError, 'archive bytes differ'):
            self.install()
        self.assertEqual(self.calls, [])
        self.assertFalse((self.root / 'native-host/cloud-ready').exists())

    def test_self_consistent_outer_archive_still_refuses_changed_apk_member(self):
        self.files['crun-1.30.1-r0.apk'] = b'SYNTHETIC TAMPERED APK'
        self.bind()
        with self.assertRaisesRegex(ValueError, 'APK byte checksums differ'):
            self.install()
        self.assertEqual(self.calls, [])

    def test_missing_or_duplicate_package_checksum_refuses_before_install(self):
        self.files['SHA256SUMS'] = self.files['SHA256SUMS'].splitlines(keepends=True)[0]
        self.bind()
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(self.calls, [])

    def test_foreign_path_link_duplicate_and_special_members_refuse_even_with_valid_outer_digest(self):
        for name, kind in [('../escaped', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                           ('keys/foreign', tarfile.REGTYPE), ('crun-1.30.1-r0.apk', tarfile.REGTYPE),
                           ('linked.apk', tarfile.SYMTYPE), ('hardlink.apk', tarfile.LNKTYPE),
                           ('device.apk', tarfile.CHRTYPE)]:
            with self.subTest(name=name, kind=kind):
                member = tarfile.TarInfo(name)
                member.type = kind
                member.mode = 0o644
                member.size = 1 if kind == tarfile.REGTYPE else 0
                self.bind(self.archive(member))
                path = self.root / ('archive-' + str(len(list(self.root.glob('archive-*')))))
                path.write_bytes(self.archive_bytes)
                with self.assertRaises(ValueError):
                    packages.archive_record(path, self.config, self.keys)

    def test_original_signed_image_key_drift_missing_extra_or_link_refuses(self):
        key = self.keys / self.key_name
        before = key.read_bytes()
        key.write_bytes(b'SYNTHETIC FOREIGN KEY')
        with self.assertRaisesRegex(ValueError, 'official APK key differs'):
            self.install()
        self.assertEqual(self.calls, [])
        self.assertEqual(key.read_bytes(), b'SYNTHETIC FOREIGN KEY')
        key.write_bytes(before)

    def test_captured_keys_cannot_replace_the_signed_image_trust_keys(self):
        self.files['keys/' + self.key_name] = b'SYNTHETIC REPLACEMENT KEY'
        self.bind()
        with self.assertRaisesRegex(ValueError, 'captured APK keys differ'):
            self.install()
        self.assertEqual((self.keys / self.key_name).read_bytes(), b'SYNTHETIC OFFICIAL PUBLIC KEY')
        self.assertEqual(self.calls, [])

    def test_stock_apk_failure_or_inventory_drift_never_marks_ready(self):
        def refused(argv, **options):
            self.calls.append((argv, options))
            return SimpleNamespace(returncode=1, stdout=b'', stderr=b'SYNTHETIC APK SIGNATURE REFUSAL')
        with self.assertRaisesRegex(ValueError, 'signature or dependency verification refused'):
            self.install(refused)
        self.assertFalse((self.root / 'native-host/cloud-ready').exists())

    def test_even_successful_apk_cannot_accept_another_installed_inventory(self):
        def changed(argv, **options):
            result = self.execute(argv, **options)
            if argv == ['apk', 'info', '-vv']:
                result.stdout += b'SYNTHETIC EXTRA PACKAGE\n'
            return result
        with self.assertRaisesRegex(ValueError, 'installed package inventory differs'):
            self.install(changed)
        self.assertFalse((self.root / 'native-host/cloud-ready').exists())

    def test_uncertain_or_completed_input_is_not_replayed_in_an_existing_cache(self):
        self.install()
        calls, fetches = len(self.calls), len(self.fetches)
        with self.assertRaisesRegex(ValueError, 'fresh immutable package cache required'):
            self.install()
        self.assertEqual((len(self.calls), len(self.fetches)), (calls, fetches))

    def test_shared_cloud_init_uses_exact_source_helper_without_live_apk_resolution(self):
        source = ROOT / 'tests/support/native_host_vm.py'
        spec = importlib.util.spec_from_file_location('native_package_vm', source)
        vm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vm)
        baseline = json.loads((ROOT / 'tests/fixtures/native_host/baseline.json').read_bytes())
        options = vm.fixture_package_bootstrap(baseline)
        self.assertEqual(set(options), {'write_files', 'runcmd'})
        self.assertEqual(options['write_files'][0]['content'], (ROOT / 'tests/support/native_host_packages.py').read_text())
        selected = json.loads(options['write_files'][1]['content'])
        self.assertEqual(selected, {'image': baseline['cloud_image'], 'requested_packages': baseline['native_packages'],
                                    'closure': baseline['native_package_closure']})
        packages.input_record(selected)
        command = options['runcmd'][0][2]
        self.assertIn('python3 -I -B /root/native-host/package-bootstrap.py', command)
        self.assertNotIn('apk update', command)
        self.assertNotIn('apk fetch', command)
        self.assertTrue(all(row['owner'] == 'root:root' and row['permissions'] == '0600' for row in options['write_files']))

    def test_executable_refuses_nonroot_before_any_config_or_key_read(self):
        with patch.object(packages.os, 'geteuid', return_value=1001), patch.object(packages, 'ordinary') as read:
            with self.assertRaisesRegex(ValueError, 'disposable Root authority required'):
                packages.main()
            read.assert_not_called()

    def test_pure_file_validation_requires_the_actual_callers_ownership(self):
        key = self.keys / self.key_name
        self.assertEqual(packages.ordinary(key, 16384), b'SYNTHETIC OFFICIAL PUBLIC KEY')
        with patch.object(packages.os, 'geteuid', return_value=key.stat().st_uid + 1):
            with self.assertRaisesRegex(ValueError, 'unsafe package input file'):
                packages.ordinary(key, 16384)

    def test_https_fetch_requires_exact_complete_bytes_and_fixed_github_redirect(self):
        class Response(io.BytesIO):
            def geturl(self):
                return 'https://release-assets.githubusercontent.com/immutable-public-input?opaque=signed-query'
        path = self.root / 'fetched'
        record = self.config['closure']['archive']
        with patch.object(packages.urllib.request, 'urlopen', return_value=Response(self.archive_bytes)) as opening:
            packages.fetch(record, path, time.monotonic() + 30)
        self.assertEqual(path.read_bytes(), self.archive_bytes)
        opening.assert_called_once()
        self.assertLessEqual(opening.call_args.kwargs['timeout'], 30)

    def test_fetch_refuses_foreign_or_plaintext_final_origin_before_any_bytes(self):
        for number, url in enumerate(['http://release-assets.githubusercontent.com/input',
                'https://foreign.example/input', 'https://user@github.com/input',
                'https://github.com/input#fragment']):
            class Response(io.BytesIO):
                def geturl(self):
                    return url
            path = self.root / ('redirect-' + str(number))
            with patch.object(packages.urllib.request, 'urlopen', return_value=Response(self.archive_bytes)):
                with self.assertRaisesRegex(ValueError, 'redirect escaped'):
                    packages.fetch(self.config['closure']['archive'], path, time.monotonic() + 30)
            self.assertEqual(path.stat().st_size, 0)

    def test_fetch_expired_budget_tampering_short_or_excess_bytes_never_accepts(self):
        with patch.object(packages.urllib.request, 'urlopen') as opening:
            with self.assertRaisesRegex(ValueError, 'download deadline expired'):
                packages.fetch(self.config['closure']['archive'], self.root / 'expired', time.monotonic() - 1)
            opening.assert_not_called()
        for number, raw in enumerate([self.archive_bytes[:-1], self.archive_bytes + b'X',
                                      self.archive_bytes[:-1] + b'X']):
            class Response(io.BytesIO):
                def geturl(self):
                    return 'https://github.com/nicodes/komizo/public-input'
            with patch.object(packages.urllib.request, 'urlopen', return_value=Response(raw)):
                with self.assertRaises(ValueError):
                    packages.fetch(self.config['closure']['archive'], self.root / ('bytes-' + str(number)),
                                   time.monotonic() + 30)


if __name__ == '__main__':
    unittest.main()
