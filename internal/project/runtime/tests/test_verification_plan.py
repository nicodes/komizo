import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[1] / 'helpers/verification-plan.py'
spec = importlib.util.spec_from_file_location('verification_plan', HELPER)
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


class VerificationPlanning(unittest.TestCase):
    def setUp(self):
        self.value = {'version': 1, 'full_targets': ['lint', 'unit', 'integration', 'build', 'e2e'],
                      'always': ['lint'], 'rules': [
                          {'paths': ['README.md', 'docs/*'], 'targets': ['lint']},
                          {'paths': ['unit-tests/*'], 'targets': ['unit']}]}

    def test_documentation_and_test_inputs_have_explicit_owners(self):
        self.assertEqual(planner.select(self.value, ['README.md'], 'pull_request')['targets'], ['lint'])
        self.assertEqual(planner.select(self.value, ['unit-tests/check.py'], 'local')['targets'], ['lint', 'unit'])
        self.assertEqual(planner.select(self.value, ['README.md', 'unit-tests/check.py'], 'local')['targets'], ['lint', 'unit'])
        legacy = {**self.value, 'full_targets': ['lint', 'test', 'build']}
        self.assertEqual(planner.select(legacy, ['runtime.py'], 'local')['targets'], ['lint', 'test', 'build'])

    def test_shared_unknown_deleted_renamed_or_production_inputs_require_full_gate(self):
        for names, event in [(['app/code.py'], 'pull_request'), (['engineering-plan.json'], 'pull_request'),
                             (['.github/workflows/ci.yml'], 'local'), (['app/package.json'], 'local'),
                             (['docs/deleted.md', 'app/renamed.py'], 'local'),
                             (['README.md'], 'push'), (['README.md'], 'workflow_dispatch')]:
            with self.subTest(names=names, event=event):
                self.assertEqual(planner.select(self.value, names, event)['mode'], 'full')

    def test_real_git_diff_covers_untracked_changes_and_both_sides_of_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', root], check=True)
            (root / 'README.md').write_text('original')
            (root / 'engineering-plan.json').write_text(json.dumps(self.value))
            subprocess.run(['git', '-C', root, 'add', '.'], check=True)
            subprocess.run(['git', '-C', root, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit', '-qm', 'baseline'], check=True)
            base = subprocess.check_output(['git', '-C', root, 'rev-parse', 'HEAD'], text=True).strip()
            (root / 'README.md').write_text('changed')
            def run(revision=base):
                return json.loads(subprocess.check_output(
                    ['python3', HELPER, '--base', revision, '--event', 'local'], cwd=root, text=True))
            self.assertEqual(run()['targets'], ['lint'])
            (root / 'new-code.py').write_text('code')
            self.assertEqual(run()['mode'], 'full')
            (root / 'new-code.py').unlink()
            (root / 'README.md').rename(root / 'runtime.py')
            self.assertEqual(run()['changed_paths'], ['README.md', 'runtime.py'])
            self.assertEqual(run()['mode'], 'full')
            self.assertEqual(run('f' * 40)['mode'], 'full')

    def test_invalid_policy_cannot_select_an_empty_or_injected_full_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            for patch in [{'full_targets': []}, {'full_targets': ['build;true']},
                          {'always': ['unknown']}, {'rules': [{'paths': ['../outside'], 'targets': ['lint']}]}]:
                path.write_text(json.dumps({**self.value, **patch}))
                with self.assertRaises(ValueError):
                    planner.policy(path)

