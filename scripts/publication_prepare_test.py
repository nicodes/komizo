"""Containerd/classic normalization must satisfy the protected publisher."""
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('publication_prepare', Path(__file__).with_name('publication_prepare.py'))
publisher = load('publisher', Path(__file__).resolve().parents[1] / 'internal/operator/assets/fleet_publisher.py')
REVISION = 'a' * 40
SOURCE = {'repository': 'example/product', 'revision': REVISION}
IMAGE = 'ghcr.io/example/product-core:' + REVISION


class Publication(unittest.TestCase):
    def fixture(self, root, *, compressed=True, change=None, extra=None):
        layer = b'synthetic layer bytes' * 100
        configuration = {'os': 'linux', 'architecture': 'amd64', 'config': {'Labels': {
            'org.opencontainers.image.revision': REVISION,
            'org.opencontainers.image.source': 'https://github.com/example/product'}},
            'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(layer).hexdigest()]}}
        if change:
            change(configuration)
        body = json.dumps(configuration).encode()
        config = 'blobs/sha256/' + hashlib.sha256(body).hexdigest()
        layer_path = 'blobs/sha256/layer'
        values = {'manifest.json': json.dumps([{'Config': config, 'RepoTags': [IMAGE], 'Layers': [layer_path]}]).encode(),
                  config: body, layer_path: gzip.compress(layer) if compressed else layer,
                  'index.json': b'OCI index metadata', 'oci-layout': b'OCI layout metadata'}
        raw = root/'raw.tar'
        with tarfile.open(raw, 'w') as archive:
            for name, value in values.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(value)
                archive.addfile(entry, io.BytesIO(value))
            if extra:
                archive.addfile(extra)
        return raw, hashlib.sha256(body).hexdigest()

    def test_both_save_formats_are_accepted_by_unchanged_protected_publisher(self):
        for compressed in (True, False):
            with self.subTest(compressed=compressed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                raw, config = self.fixture(root, compressed=compressed)
                normalized = root/'images.tar'
                observed = m.normalize(raw, normalized, [IMAGE], SOURCE, time.monotonic() + 10)
                self.assertEqual(observed, {IMAGE: config})
                self.assertEqual(publisher.image_archive(normalized, observed, REVISION, SOURCE['repository'],
                                                        time.monotonic() + 10), observed)
                with self.assertRaisesRegex(ValueError, 'layer content|unreferenced'):
                    publisher.image_archive(raw, observed, REVISION, SOURCE['repository'], time.monotonic() + 10)
                with tarfile.open(normalized) as archive:
                    self.assertEqual(len(archive.getmembers()), 3)

    def test_foreign_platform_revision_repository_or_corrupt_layer_refused(self):
        changes = [lambda c: c.update(architecture='arm64'), lambda c: c.update(os='windows'),
                   lambda c: c['config']['Labels'].update({'org.opencontainers.image.revision': 'b'*40}),
                   lambda c: c['config']['Labels'].update({'org.opencontainers.image.source': 'https://github.com/foreign/product'}),
                   lambda c: c['rootfs'].update(diff_ids=['sha256:' + 'b'*64])]
        for change in changes:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                raw, _ = self.fixture(root, change=change)
                with self.assertRaises(ValueError):
                    m.normalize(raw, root/'images.tar', [IMAGE], SOURCE, time.monotonic() + 10)
                self.assertFalse((root/'images.tar').exists())

    def test_unsafe_unselected_paths_and_links_are_refused(self):
        for name, kind in [('../foreign', tarfile.REGTYPE), ('/foreign', tarfile.REGTYPE),
                           ('index.json', tarfile.REGTYPE), ('foreign-link', tarfile.SYMTYPE)]:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                entry = tarfile.TarInfo(name)
                entry.type = kind
                raw, _ = self.fixture(root, extra=entry)
                with self.assertRaisesRegex(ValueError, 'unsafe, linked or repeated'):
                    m.normalize(raw, root/'images.tar', [IMAGE], SOURCE, time.monotonic() + 10)

    def test_deadline_expansion_and_publication_bounds_are_enforced(self):
        for setting in ('deadline', 'MAX_EXPANDED', 'MAX_ARCHIVE'):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                raw, _ = self.fixture(root)
                with patch.object(m, setting, 100) if setting != 'deadline' else patch.object(m, 'MAX_JSON', m.MAX_JSON):
                    with self.assertRaises(ValueError):
                        m.normalize(raw, root/'images.tar', [IMAGE], SOURCE,
                                    time.monotonic() - 1 if setting == 'deadline' else time.monotonic() + 10)

    def test_exact_tag_set_and_owner_required(self):
        for images in ([], [IMAGE, IMAGE], ['ghcr.io/foreign/core:' + REVISION],
                       [IMAGE[:-40] + 'b'*40], [IMAGE + '-latest']):
            with self.assertRaises(ValueError):
                m.references(images, SOURCE)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw, _ = self.fixture(root)
            with self.assertRaisesRegex(ValueError, 'image set differs'):
                m.normalize(raw, root/'images.tar', [IMAGE, 'ghcr.io/example/extra:' + REVISION], SOURCE, time.monotonic() + 10)

    def test_main_identity_uses_actual_clean_git_tree(self):
        environment = {'GITHUB_REPOSITORY': SOURCE['repository'], 'GITHUB_SHA': REVISION,
                       'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'push',
                       'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'}
        answers = {('rev-parse', 'HEAD'): REVISION, ('rev-parse', 'HEAD^{tree}'): 'c'*40,
                   ('status', '--porcelain', '--untracked-files=no'): ''}
        git = lambda args: answers[tuple(args)]
        accepted = m.identity(environment, git)
        self.assertEqual(accepted['tree'], 'c'*40)
        self.assertEqual(accepted['attempt'], 2)
        for key, value in [('GITHUB_REF', 'refs/pull/1/merge'), ('GITHUB_EVENT_NAME', 'pull_request'),
                           ('GITHUB_SHA', 'b'*40), ('GITHUB_RUN_ATTEMPT', '0')]:
            with self.assertRaises(ValueError):
                m.identity({**environment, key: value}, git)
        answers[('status', '--porcelain', '--untracked-files=no')] = ' M tracked-source'
        with self.assertRaisesRegex(ValueError, 'unchanged tested checkout'):
            m.identity(environment, git)

    def test_failed_save_cleans_only_new_output_and_never_overwrites_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = {**SOURCE, 'version': 1, 'tree': 'c'*40, 'run_id': 123, 'attempt': 1}
            existing = root/'existing'
            existing.mkdir()
            (existing/'retained').write_text('keep')
            with patch.object(m, 'identity', return_value=source), patch.object(m, 'save', side_effect=ValueError('save failed')) as save:
                with self.assertRaises(FileExistsError):
                    m.prepare([IMAGE], existing, {}, time.monotonic()+10)
                save.assert_not_called()
                with self.assertRaisesRegex(ValueError, 'save failed'):
                    m.prepare([IMAGE], root/'new', {}, time.monotonic()+10)
            self.assertFalse((root/'new').exists())
            self.assertEqual((existing/'retained').read_text(), 'keep')

    def test_streamed_save_size_bound_terminates_owned_child(self):
        import subprocess
        real = subprocess.Popen
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, 'MAX_ARCHIVE', 1024), patch.object(m.subprocess, 'Popen',
                side_effect=lambda args, **kwargs: real(['/usr/bin/python3', '-c', 'import sys,time;sys.stdout.buffer.write(b"x"*65536);sys.stdout.flush();time.sleep(60)'], **kwargs)):
            with self.assertRaisesRegex(ValueError, 'archive exceeds'):
                m.save([IMAGE], Path(tmp)/'raw.tar', time.monotonic()+10)


if __name__ == '__main__':
    unittest.main()
