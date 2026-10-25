import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('export_web', Path(__file__).parents[1]/'helpers/export-web.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ExportFailures(unittest.TestCase):
    def run_export(self, source, timeout=5):
        with tempfile.TemporaryDirectory() as app:
            module.export(app, 'dist', timeout, [sys.executable, '-c', source])

    def test_artifact_cannot_hide_failed_process(self):
        with self.assertRaisesRegex(RuntimeError, 'exited 7'):
            self.run_export("from pathlib import Path; p=Path('dist'); p.mkdir(); (p/'index.html').write_text('ok'); (p/'app.js').write_text('ok'); raise SystemExit(7)")

    def test_timeout_cannot_be_passed_by_partial_export(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_export("import time; from pathlib import Path; p=Path('dist'); p.mkdir(); (p/'index.html').write_text('partial'); time.sleep(30)", 0.1)

    def test_success_requires_javascript(self):
        with self.assertRaisesRegex(RuntimeError, 'JavaScript'):
            self.run_export("from pathlib import Path; p=Path('dist'); p.mkdir(); (p/'index.html').write_text('partial')")

    def test_successful_complete_export(self):
        self.run_export("from pathlib import Path; p=Path('dist'); p.mkdir(); (p/'index.html').write_text('ok'); (p/'app.js').write_text('ok')")


if __name__ == '__main__':
    unittest.main()

class CompilerCacheBoundaries(unittest.TestCase):
    def test_variant_isolation_and_corrupt_transform_refusal(self):
        import os
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root:
            app = Path(root)/'app'; app.mkdir()
            cache = Path(root)/'cache'
            with patch.dict(os.environ, {'EXPO_PUBLIC_API_URL': '/api'}, clear=True):
                with module.compiler_cache(app, 'dist', cache) as env:
                    production = Path(env['TMPDIR']); (production/'metro-cache').mkdir()
                    (production/'metro-cache/transform').write_bytes(b'reviewed')
                with module.compiler_cache(app, 'dist', cache) as env:
                    self.assertEqual(Path(env['TMPDIR']), production)
                with patch.dict(os.environ, {'ENGINEERING_E2E_AUTH': '1'}):
                    with module.compiler_cache(app, 'dist-e2e', cache) as env:
                        self.assertNotEqual(Path(env['TMPDIR']), production)
                (production/'metro-cache/transform').write_bytes(b'corrupt')
                with self.assertRaisesRegex(ValueError, 'successful export inventory'):
                    with module.compiler_cache(app, 'dist', cache): pass

    def test_failed_compile_does_not_leave_success_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            app = Path(root)/'app'; app.mkdir()
            cache = Path(root)/'cache'
            with self.assertRaises(RuntimeError):
                with module.compiler_cache(app, 'dist', cache) as env:
                    namespace = Path(env['TMPDIR'])
                    raise RuntimeError('compile failed')
            self.assertFalse((namespace/'state.json').exists())

    def test_declared_product_modes_and_dotenv_select_fresh_namespaces(self):
        import os
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root:
            app = Path(root)/'app'; app.mkdir()
            cache = Path(root)/'cache'
            with patch.dict(os.environ, {'FLEET_WEB_CACHE_ENV': 'APP_MODE', 'APP_MODE': 'production'}, clear=True):
                with module.compiler_cache(app, 'dist', cache) as env:
                    production = env['TMPDIR']
                with patch.dict(os.environ, {'APP_MODE': 'local', 'EXPO_NO_DOTENV': '1'}):
                    with module.compiler_cache(app, 'dist', cache) as env:
                        self.assertNotEqual(env['TMPDIR'], production)
                (app/'.env.production').write_text('EXPO_PUBLIC_API_URL=https://new.invalid')
                with module.compiler_cache(app, 'dist', cache) as env:
                    self.assertNotEqual(env['TMPDIR'], production)
                with patch.dict(os.environ, {'FLEET_WEB_CACHE_ENV': 'bad-name'}):
                    with self.assertRaisesRegex(ValueError, 'variable names'):
                        with module.compiler_cache(app, 'dist', cache): pass
