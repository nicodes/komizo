import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[1]/'helpers/contract.py'
spec = importlib.util.spec_from_file_location('contract', HELPER)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class ContractBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        subprocess.run(['git', 'init', '-q', self.root], check=True)
        (self.root/'.gitignore').write_text('.artifacts/\noutput/\n')
        (self.root/'input.txt').write_text('source')
        subprocess.run(['git', '-C', self.root, 'add', '.'], check=True)
        subprocess.run(['git', '-C', self.root, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'fixture'], check=True)
        self.data = {'version': 1, 'stages': {stage: {'inapplicable': 'fixture has no such capability'}
            for stage in contract.STAGES}, 'artifacts': ['output'], 'build_environment': ['BUILD_INPUT']}
        self.data['stages']['build'] = [['sh', '-c', 'mkdir -p output; cp input.txt output/value; echo build >> .artifacts/build-count']]
        self.data['stages']['e2e'] = [['sh', '-c', 'test -s output/value']]

    def run_target(self, target, success=True, environment=None):
        (self.root/'komizo.json').write_text(json.dumps(self.data))
        result = subprocess.run(['python3', HELPER, target], cwd=self.root, text=True,
            capture_output=True, env={**os.environ, **(environment or {})})
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result

    def count(self):
        return len((self.root/'.artifacts/build-count').read_text().splitlines())

    def test_build_reuse_requires_source_environment_and_exact_artifact_bytes(self):
        self.run_target('e2e')
        self.run_target('e2e')
        self.assertEqual(self.count(), 1)
        (self.root/'input.txt').write_text('new source')
        self.run_target('e2e')
        self.assertEqual(self.count(), 2)
        (self.root/'output/value').write_text('corrupted artifact')
        self.run_target('e2e')
        self.assertEqual(self.count(), 3)
        self.run_target('e2e', environment={'BUILD_INPUT': 'different configuration'})
        self.assertEqual(self.count(), 4)

    def test_missing_required_suite_fails_and_explicit_inapplicability_is_reported(self):
        self.data['stages']['unit'] = []
        self.run_target('test', success=False)
        self.data['stages']['unit'] = {'inapplicable': 'No pure logic in this fixture'}
        self.assertIn('inapplicable', self.run_target('test').stdout)

    def test_failed_build_and_source_mutation_cannot_leave_reusable_evidence(self):
        self.run_target('build')
        self.data['stages']['build'] = [['sh', '-c', 'exit 23']]
        self.run_target('build', success=False)
        self.assertFalse((self.root/'.artifacts/contract/build.json').exists())
        self.data['stages']['build'] = [['sh', '-c', 'echo mutation > input.txt']]
        self.run_target('build', success=False)
        self.assertFalse((self.root/'.artifacts/contract/build.json').exists())

    def test_parallel_processes_build_once(self):
        (self.root/'komizo.json').write_text(json.dumps(self.data))
        children = [subprocess.Popen(['python3', HELPER, 'e2e'], cwd=self.root,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(3)]
        for child in children:
            stdout, stderr = child.communicate(timeout=30)
            self.assertEqual(child.returncode, 0, (stdout, stderr))
        self.assertEqual(self.count(), 1)

    def test_symlinked_artifacts_are_rejected(self):
        self.data['stages']['build'] = [['sh', '-c', 'mkdir -p output; ln -s ../input.txt output/value']]
        self.run_target('build', success=False)

    def test_provenance_requires_executed_tests_against_unchanged_build_inputs(self):
        def run(*targets):
            (self.root/'komizo.json').write_text(json.dumps(self.data))
            result = subprocess.run(['python3', HELPER, *targets], cwd=self.root,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads((self.root/'.artifacts/contract/build.json').read_text())['provenance']

        proof = run('test', 'build')
        self.assertIsNone(proof['tested_commit'])
        self.assertEqual(proof['test_receipts'], {})
        self.data['stages']['unit'] = [['sh', '-c', 'test -s input.txt']]
        proof = run('test', 'build')
        self.assertEqual(proof['tested_commit'], proof['source_commit'])
        self.assertEqual(set(proof['test_receipts']), {'unit'})
        self.data['stages']['integration'] = [['sh', '-c', 'echo changed >> input.txt']]
        proof = run('test', 'build')
        self.assertIsNone(proof['tested_commit'])
        self.assertEqual(set(proof['test_receipts']), {'unit'})
        self.data['stages']['integration'] = [['sh', '-c', 'test -s input.txt']]
        proof = run('test', 'build')
        self.assertEqual(proof['tested_commit'], proof['source_commit'])
        self.assertEqual(set(proof['test_receipts']), {'unit', 'integration'})

    def test_failed_applicable_test_cannot_create_a_build_proof(self):
        self.data['stages']['unit'] = [['sh', '-c', 'exit 23']]
        (self.root/'komizo.json').write_text(json.dumps(self.data))
        result = subprocess.run(['python3', HELPER, 'test', 'build'], cwd=self.root,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 23)
        self.assertFalse((self.root/'.artifacts/contract/build.json').exists())
        failure = json.loads((self.root/'.artifacts/contract/failure.json').read_text())
        self.assertEqual(failure['stage'], 'unit')
        self.assertEqual(failure['exit_code'], 23)
        self.assertEqual(failure['rerun'], ['komizo', 'run', 'unit'])
        self.assertEqual(failure['source_commit'], subprocess.check_output(
            ['git', '-C', self.root, 'rev-parse', 'HEAD'], text=True).strip())

    def test_legacy_build_proof_without_execution_receipts_is_not_reused(self):
        self.run_target('build')
        path = self.root/'.artifacts/contract/build.json'
        evidence = json.loads(path.read_text())
        del evidence['provenance']['test_receipts']
        path.write_text(json.dumps(evidence))
        self.run_target('build')
        self.assertEqual(self.count(), 2)
        self.assertEqual(json.loads(path.read_text())['provenance']['test_receipts'], {})

class ImageNamespaceInputs(unittest.TestCase):
    def test_default_and_selected_namespaces_bind_the_declared_build_input(self):
        from unittest.mock import patch
        data = {'images':['{IMAGE_BASE}-gate:{revision}'], 'build_environment':['IMAGE_BASE'],
                'build_environment_defaults':{'IMAGE_BASE':'ghcr.io/example/product'}}
        with patch.dict(os.environ, {'IMAGE_BASE':''}):
            self.assertEqual(contract.resolve_images(data,'a'*40), ['ghcr.io/example/product-gate:'+'a'*40])
        with patch.dict(os.environ, {'IMAGE_BASE':'ghcr.io/example/preview'}):
            self.assertEqual(contract.resolve_images(data,'a'*40), ['ghcr.io/example/preview-gate:'+'a'*40])
        with patch.dict(os.environ, {'IMAGE_BASE':'untrusted; command'}), self.assertRaises(ValueError):
            contract.resolve_images(data,'a'*40)
        with self.assertRaises(ValueError):
            contract.resolve_images({**data,'build_environment':[]},'a'*40)


