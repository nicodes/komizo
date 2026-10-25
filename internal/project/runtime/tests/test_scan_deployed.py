import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('scan_deployed', Path(__file__).resolve().parents[1]/'helpers/scan-deployed.py')
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class DeployedRevision(unittest.TestCase):
    def test_failed_latest_deploy_does_not_hide_prior_success(self):
        responses = [[{'id': 3, 'sha': 'a'*40}, {'id': 2, 'sha': 'b'*40}],
                     [{'state': 'failure'}, {'state': 'success'}], [{'state': 'success'}]]
        with patch.object(scanner, 'api', side_effect=responses):
            self.assertEqual(scanner.deployed_revisions('nicodes/samplestore-be'), ['a'*40, 'b'*40])

    def test_missing_success_invalid_sha_or_protocol_fails(self):
        for responses in [[[]], [[{'id': 1, 'sha': 'main'}], [{'state': 'success'}]],
                          [[{'id': False}]], [[{'id': 1}], {}]]:
            with self.subTest(responses=responses), patch.object(scanner, 'api', side_effect=responses), self.assertRaises(ValueError):
                scanner.deployed_revisions('nicodes/samplestore-be')

    def test_caller_defines_components_without_registering_an_application(self):
        config = {'repository': 'example/widget', 'image_base': 'ghcr.io/example/widget',
                  'components': ['renderer', 'worker']}
        self.assertEqual(scanner.product_images(config, 'a'*40),
                         ['ghcr.io/example/widget-'+c+':'+'a'*40 for c in config['components']])
        for mutation in ({'components': ['worker', 'worker']}, {'components': ['../escape']},
                         {'image_base': 'ghcr.io/example/widget;exit'}):
            with self.assertRaises(ValueError): scanner.product_images({**config, **mutation}, 'a'*40)
        with self.assertRaises(ValueError): scanner.product_images(config, 'main')

    def test_repository_binding_and_malformed_declarations_fail_before_scanning(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory)/'scan.json'
            config = {'repository': 'example/widget', 'image_base': 'ghcr.io/example/widget', 'components': ['worker']}
            file.write_text(json.dumps(config))
            with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'example/widget'}):
                self.assertEqual(scanner.load_config(file), config)
            with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'example/other'}), self.assertRaises(ValueError):
                scanner.load_config(file)
            for slug in ('a/b/c', '../widget', 'example/widget;exit', 'example/widget\n'):
                file.write_text(json.dumps({**config, 'repository': slug}))
                with self.assertRaises(ValueError): scanner.load_config(file)
