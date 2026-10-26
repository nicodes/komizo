#!/usr/bin/env python3
"""Exercise real caller stage execution with checkout-owned tooling paths."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).with_name('godot-addon.py')


class AddonRecipeTest(unittest.TestCase):
    def test_owned_environment_failure_and_restored_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'scripts').mkdir()
            (root/'.artifacts/godot/bin').mkdir(parents=True)
            executable = root/'.artifacts/godot/bin/godot'
            executable.write_text('#!/bin/sh\nprintf fixture-runtime\n')
            executable.chmod(0o700)
            script = root/'scripts/unit.sh'
            script.write_text('set -eu\ntest "$GODOT_BIN" = "$PWD/.artifacts/godot/bin/godot"\ntest "$XDG_DATA_HOME" = "$PWD/.artifacts/godot-data"\ntest "$(godot)" = fixture-runtime\nexit 9\n')
            environment = dict(os.environ, GODOT_BIN='/unrelated/engine', XDG_DATA_HOME='/unrelated/user-data')
            result = subprocess.run([sys.executable, str(HELPER), 'unit'], cwd=root, env=environment, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            script.write_text(script.read_text().replace('exit 9', 'printf reached > reached'))
            subprocess.run([sys.executable, str(HELPER), 'unit'], cwd=root, env=environment, check=True)
            self.assertEqual((root/'reached').read_text(), 'reached')
            self.assertEqual(environment['XDG_DATA_HOME'], '/unrelated/user-data')
            script.unlink()
            self.assertNotEqual(subprocess.run([sys.executable, str(HELPER), 'unit'], cwd=root, capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
