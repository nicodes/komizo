"""report-failure.py files an owned failure issue in the caller's repository."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

HELPER = Path(__file__).parents[1]/'helpers/report-failure.py'


def load(repository, run='123456', revision='a'*40, workflow='Test'):
    env = {'GITHUB_REPOSITORY': repository, 'GITHUB_RUN_ID': run,
           'GITHUB_WORKFLOW': workflow, 'GITHUB_SHA': revision}
    commands = []
    def record(args, **kwargs):
        commands.append(list(args))
        return '[]' if args[:3] == ['gh', 'issue', 'list'] else ''
    spec = importlib.util.spec_from_file_location('report_failure', HELPER)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(os.environ, env), \
            patch('subprocess.check_output', side_effect=record) as check_output, \
            patch('subprocess.run', side_effect=record) as subprocess_run:
        spec.loader.exec_module(module)
    return commands, check_output, subprocess_run


class ReportFailureIdentity(unittest.TestCase):
    def test_every_portfolio_org_form_is_admitted(self):
        # The boundary is org-level (docs/ACTIVE-PROJECTS.md), so an adopting
        # portfolio repository needs no helper change — the merge-checked.py form.
        for repository in ['nicodes/sampleapp-be', 'nicodes/samplehost-be', 'example-games/sampleaddon-be',
                           'example-games/sampleconsole-be', 'example-games/samplegame',
                           'example-games/samplearcade', 'example-games/sampleclient', 'sampleservicelogical/sampleservice-be', 'example/widget']:
            commands, check_output, subprocess_run = load(repository)
            created = [args for args in commands if args[:3] == ['gh', 'issue', 'create']]
            self.assertEqual(len(created), 1, repository)
            self.assertIn('--repo', created[0])
            self.assertIn(repository, created[0])

    def test_non_portfolio_and_malformed_identities_are_rejected(self):
        for repository in ['owner/two/parts', 'owner/contains space',
                           'example-games/', 'nicodes', 'nicodes/trailing ', 'example-games/samplearcade\n']:
            with patch('subprocess.check_output') as check_output, patch('subprocess.run') as subprocess_run:
                with self.assertRaises(ValueError, msg=repository):
                    load(repository)
                check_output.assert_not_called()
                subprocess_run.assert_not_called()

    def test_malformed_run_and_revision_are_rejected(self):
        for kwargs in [{'run': 'not-a-number'}, {'run': '123\n456'}, {'revision': 'A'*40},
                       {'revision': 'a'*39}, {'revision': 'main'}]:
            with patch('subprocess.check_output') as check_output:
                with self.assertRaises(ValueError, msg=kwargs):
                    load('nicodes/example-be', **kwargs)
                check_output.assert_not_called()


if __name__ == '__main__':
    unittest.main()
