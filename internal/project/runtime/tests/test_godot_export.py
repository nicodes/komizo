import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('godot_export', Path(__file__).resolve().parents[1]/'helpers/godot-export.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class ExportIsolation(unittest.TestCase):
    def test_engine_mutations_do_not_change_authored_project_and_real_theme_is_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)/'source'; project.mkdir()
            config = b'[gui]\ntheme/custom="res://theme.tres"\n'
            (project/'project.godot').write_bytes(config)
            (project/'asset.import').write_bytes(b'authored settings')
            (project/'theme.tres').write_bytes(b'authored theme')
            output = Path(directory)/'output/index.html'
            calls = []
            def run(command):
                copied = Path(command[command.index('--path')+1]); calls.append(command)
                (copied/'asset.import').write_bytes(b'engine normalization')
                if len(calls) == 1: self.assertIn(b'theme/custom=""', (copied/'project.godot').read_bytes())
                else: self.assertEqual((copied/'project.godot').read_bytes(), config)
                if '--export-release' in command: Path(command[-1]).write_bytes(b'export')
            helper.export(project, [('Web', output)], run=run)
            self.assertEqual((project/'asset.import').read_bytes(), b'authored settings')
            self.assertEqual((project/'project.godot').read_bytes(), config)
            self.assertEqual(output.read_bytes(), b'export')
            self.assertFalse(Path(calls[0][calls[0].index('--path')+1]).exists())

    def test_zero_exit_script_errors_fail(self):
        from unittest.mock import patch
        import subprocess
        with patch.object(helper.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'ERROR: invalid asset\n')):
            with self.assertRaises(RuntimeError): helper.checked(['godot'])
