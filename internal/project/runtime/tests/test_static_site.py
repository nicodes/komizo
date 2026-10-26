#!/usr/bin/env python3
"""Verify foreground selection and the actual child argument/exit contract."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).parents[1]/'helpers/static-site.py'
SPEC = importlib.util.spec_from_file_location('static_site', HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class StaticSiteRecipeTest(unittest.TestCase):
    def test_only_supported_standard_astro_script_gets_foreground_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'node_modules/astro').mkdir(parents=True)
            for script, version, expected in [
                ('astro dev', '7.3.3', True),
                ('astro dev', '7.1.0', True),
                ('astro dev', '7.0.0', False),
                ('astro dev', '6.9.0', False),
                ('astro dev --host', '7.3.3', False),
                ('vite', '7.3.3', False),
            ]:
                with self.subTest(script=script, version=version):
                    (root/'package.json').write_text(json.dumps({'scripts': {'dev': script}}))
                    (root/'node_modules/astro/package.json').write_text(json.dumps({'version': version}))
                    argv = MODULE.development_command(root, ['--port', '34567'])
                    self.assertEqual('--ignore-lock' in argv, expected)
                    self.assertEqual(argv[-2:], ['--port', '34567'])

    def test_exec_preserves_arguments_environment_and_child_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'package.json').write_text(json.dumps({'scripts': {'dev': 'vite'}}))
            (root/'bin').mkdir()
            child = root/'bin/bun'
            child.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                             'open("observed.json","w").write(json.dumps([sys.argv[1:],os.environ["SITE_FIXTURE"]]))\n'
                             'sys.exit(19)\n')
            child.chmod(0o700)
            environment = dict(os.environ, PATH=str(root/'bin'), SITE_FIXTURE='preserved')
            result = subprocess.run([sys.executable, str(HELPER), 'a b', '$(literal)'], cwd=root, env=environment)
            self.assertEqual(result.returncode, 19)
            self.assertEqual(json.loads((root/'observed.json').read_text()), [['run', 'dev', 'a b', '$(literal)'], 'preserved'])


if __name__ == '__main__':
    unittest.main()
