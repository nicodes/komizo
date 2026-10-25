import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('godot_setup', Path(__file__).parents[1]/'helpers/godot-setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class VerifiedSetup(unittest.TestCase):
    def pin(self, data):
        return 'sha256:'+hashlib.sha256(data).hexdigest()

    def test_verified_cache_hit_never_downloads(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder)/'engine.zip'
            archive.write_bytes(b'reviewed')
            with patch.object(setup.urllib.request, 'urlopen') as download:
                self.assertEqual(setup.fetch('https://example.invalid', archive, self.pin(b'reviewed')), 'hit')
                download.assert_not_called()

    def test_corrupt_cache_is_replaced_only_with_verified_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder)/'engine.zip'
            archive.write_bytes(b'corrupt')
            with patch.object(setup.urllib.request, 'urlopen', return_value=io.BytesIO(b'reviewed')):
                self.assertEqual(setup.fetch('https://example.invalid', archive, self.pin(b'reviewed')), 'miss')
            self.assertEqual(archive.read_bytes(), b'reviewed')

    def test_wrong_download_fails_and_removes_partial_file(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder)/'engine.zip'
            archive.write_bytes(b'old')
            with patch.object(setup.urllib.request, 'urlopen', return_value=io.BytesIO(b'wrong')):
                with self.assertRaises(ValueError):
                    setup.fetch('https://example.invalid', archive, self.pin(b'reviewed'))
            self.assertEqual(archive.read_bytes(), b'old')
            self.assertEqual(list(Path(folder).iterdir()), [archive])

    def test_missing_template_pin_fails_before_download(self):
        with patch.object(setup, 'fetch') as download:
            with self.assertRaises(ValueError):
                setup.install('4.7.2', self.pin(b'engine'), '', True, Path('/unused'))
            download.assert_not_called()

    def test_invalid_version_and_digest_rejected(self):
        for pin in ['sha256:main', 'md5:'+64*'a', 'sha512:'+64*'a']:
            with self.assertRaises(ValueError):
                setup.checksum(pin)
        with self.assertRaises(ValueError):
            setup.install('../../evil', self.pin(b'engine'), '', False, Path('/unused'))

    def test_templates_reject_traversal_and_duplicate_flat_names(self):
        for names in [('templates/../evil',), ('a/template', 'b/template')]:
            with tempfile.TemporaryDirectory() as folder:
                archive = Path(folder)/'templates.tpz'
                with zipfile.ZipFile(archive, 'w') as output:
                    for name in names:
                        output.writestr(name, b'template')
                with self.assertRaises(ValueError):
                    setup.extract_templates(archive, Path(folder)/'output')
                self.assertEqual(list((Path(folder)/'output').iterdir()), [])
