import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('merge', Path(__file__).resolve().parents[1]/'helpers/merge-checked.py')
merge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge)

class MergeEvidence(unittest.TestCase):
    def setUp(self):
        self.head = 'a'*40
        self.prefix = 'https://github.com/nicodes/example/actions/runs/123/'
        self.checks = [{'name': name, 'head_sha': self.head, 'status': 'completed', 'conclusion': 'success',
                        'app': {'slug': 'github-actions'}} for name in ['Test', 'Build']]
    def decide(self, checks, statuses=()):
        return merge.decision(checks, statuses, self.head, self.prefix)
    def test_missing_pending_skipped_failed_and_wrong_head(self):
        self.assertTrue(self.decide(self.checks))
        self.assertFalse(self.decide(self.checks[:1]))
        for update, raises in [({'status':'in_progress','conclusion':None}, False),
                               ({'conclusion':'skipped'}, True), ({'conclusion':'failure'}, True),
                               ({'head_sha':'b'*40}, True), ({'conclusion':'neutral'}, True)]:
            checks = copy.deepcopy(self.checks); checks[1].update(update)
            if raises:
                with self.assertRaises(ValueError): self.decide(checks)
            else: self.assertFalse(self.decide(checks))
    def test_only_own_running_check_is_excluded(self):
        check = {'name':'auto-merge','head_sha':self.head,'status':'in_progress', 'conclusion':None,
                 'details_url':self.prefix+'job/4'}
        self.assertTrue(self.decide(self.checks+[check]))
        check['details_url']='https://github.com/nicodes/example/actions/runs/999/job/4'
        self.assertFalse(self.decide(self.checks+[check]))
    def test_external_status_and_check_cannot_be_hidden(self):
        with self.assertRaises(ValueError):
            self.decide(self.checks, [{'context':'external','state':'failure'}])
        self.assertFalse(self.decide(self.checks, [{'context':'external','state':'pending'}]))
        checks = copy.deepcopy(self.checks); checks[1]['app']['slug']='other-app'
        self.assertFalse(self.decide(checks))
        checks = self.checks+[{'name':'extra','head_sha':self.head,'status':'completed','conclusion':'cancelled'}]
        with self.assertRaises(ValueError): self.decide(checks)

    def test_check_pagination_and_status_query(self):
        with patch.object(merge, 'api', side_effect=[{'check_runs': [1]*100}, {'check_runs': [2]}]) as api:
            self.assertEqual(len(merge.pages('checks?filter=latest', 'check_runs')), 101)
            self.assertEqual(api.call_args.args[0], 'checks?filter=latest&per_page=100&page=2')
        with patch.object(merge, 'api', return_value=[]) as api:
            self.assertEqual(merge.pages('statuses'), [])
            self.assertEqual(api.call_args.args[0], 'statuses?per_page=100&page=1')

class MergeIdentity(unittest.TestCase):
    def setUp(self):
        environment = dict(os.environ)
        environment.pop('GITHUB_REPOSITORY', None)
        fixture = patch.dict(os.environ, environment, clear=True)
        fixture.start(); self.addCleanup(fixture.stop)

    def test_workflow_caller_binding_is_required(self):
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'example/caller'}):
            with self.assertRaisesRegex(ValueError, 'workflow caller'):
                merge.check_identity('example/other', '7', 'a'*40, '123')

    def test_portfolio_orgs_admitted_and_foreign_or_malformed_rejected(self):
        admitted = ['nicodes/anything', 'example-games/samplearcade', 'example-games/sampleclient',
                    'example-games/example-games-web', 'example-games/samplegame', 'example-games/sampleaddon-be',
                    'example-games/sampleconsole-be', 'example-games/gd-audio', 'sampleservicelogical/sampleservice-be', 'example/widget']
        for repo in admitted:
            with self.subTest(repo=repo):
                merge.check_identity(repo, '7', 'a'*40, '123')
        rejected = ['sampleservicelogical', 'example-games/', 'example-games/HasUpper',
                    'example-games/under_score', 'example-games/two/parts', 'example-games/dot.git',
                    'example-games/samplearcade\n', 'nicodes/trailing ', ' nicodes/leading']
        for repo in rejected:
            with self.subTest(repo=repo):
                with self.assertRaises(ValueError) as raised:
                    merge.check_identity(repo, '7', 'a'*40, '123')
                self.assertEqual(str(raised.exception), 'invalid merge identity')
    def test_pr_run_and_head_validation_unchanged(self):
        for pr, head, run in [('x', 'a'*40, '123'), ('7', 'b'*39, '123'), ('7', 'A'*40, '123'),
                              ('7', 'a'*40, 'run')]:
            with self.subTest(pr=pr, head=head, run=run):
                with self.assertRaises(ValueError) as raised:
                    merge.check_identity('nicodes/anything', pr, head, run)
                self.assertEqual(str(raised.exception), 'invalid merge identity')

class DispatchChain(unittest.TestCase):
    def not_found(self):
        return subprocess.CalledProcessError(1, 'gh', stderr='gh: Not Found (HTTP 404)')
    def test_candidates_default_chain_and_target_first(self):
        self.assertEqual(merge.dispatch_candidates(''), ['cd.yml', 'ci.yml'])
        self.assertEqual(merge.dispatch_candidates('ci.yml'), ['ci.yml', 'cd.yml', 'ci.yml'])
        self.assertEqual(merge.dispatch_candidates('deploy.yaml'), ['deploy.yaml', 'cd.yml', 'ci.yml'])
    def test_invalid_target_rejected(self):
        for target in ['../ci.yml', 'a/ci.yml', '/ci.yml', '.yml', 'ci.yml;rm -rf', 'ci.json',
                       'ci.YML', 'ci.yml ']:
            with self.subTest(target=target):
                with self.assertRaises(ValueError) as raised:
                    merge.dispatch_candidates(target)
                self.assertEqual(str(raised.exception), 'invalid dispatch target')
    def test_chain_falls_from_cd_to_ci_on_404(self):
        with patch.object(merge, 'api', side_effect=[self.not_found(), {}, None]) as api:
            workflow = merge.dispatch('nicodes/example', ['cd.yml', 'ci.yml'])
        self.assertEqual(workflow, 'ci.yml')
        self.assertEqual([call.args for call in api.call_args_list],
                         [('repos/nicodes/example/actions/workflows/cd.yml',),
                          ('repos/nicodes/example/actions/workflows/ci.yml',),
                          ('repos/nicodes/example/actions/workflows/ci.yml/dispatches', 'POST', {'ref': 'main'})])
    def test_target_dispatched_when_it_exists(self):
        with patch.object(merge, 'api', side_effect=[{}, None]) as api:
            workflow = merge.dispatch('example-games/example-games-web', merge.dispatch_candidates('ci.yml'))
        self.assertEqual(workflow, 'ci.yml')
        self.assertEqual(api.call_count, 2)
    def test_loud_failure_when_no_candidate_exists(self):
        with patch.object(merge, 'api', side_effect=[self.not_found(), self.not_found()]):
            with self.assertRaises(ValueError) as raised:
                merge.dispatch('example-games/samplearcade', ['cd.yml', 'ci.yml'])
        self.assertIn('coverage', str(raised.exception))
    def test_probe_error_other_than_404_raises(self):
        with patch.object(merge, 'api', side_effect=[subprocess.CalledProcessError(1, 'gh', stderr='gh: Forbidden (HTTP 403)')]):
            with self.assertRaises(subprocess.CalledProcessError):
                merge.dispatch('nicodes/example', ['cd.yml', 'ci.yml'])
    def test_sampleapp_keeps_ci_when_cd_is_absent(self):
        # Behavior-preserving: sampleapp-be dispatched ci.yml before; the chain reaches it when cd.yml 404s.
        with patch.object(merge, 'api', side_effect=[self.not_found(), {}, None]) as api:
            workflow = merge.dispatch('nicodes/sampleapp-be', merge.dispatch_candidates(''))
        self.assertEqual(workflow, 'ci.yml')
        self.assertEqual(api.call_args_list[-1].args,
                         ('repos/nicodes/sampleapp-be/actions/workflows/ci.yml/dispatches', 'POST', {'ref': 'main'}))

class MergeMainFlow(unittest.TestCase):
    def test_main_merges_then_dispatches_the_target(self):
        head, merged = 'a'*40, 'b'*40
        env = {'GITHUB_REPOSITORY': 'example-games/sampleclient', 'PR_NUMBER': '7', 'EXPECTED_HEAD': head,
               'GITHUB_RUN_ID': '123', 'DISPATCH_TARGET': 'ci.yml'}
        pull = {'state': 'open', 'draft': False, 'head': {'sha': head},
                'user': {'login': 'dependabot[bot]'}, 'base': {'ref': 'main'}}
        checks = {'check_runs': [{'name': name, 'head_sha': head, 'status': 'completed',
                                  'conclusion': 'success', 'app': {'slug': 'github-actions'}}
                                 for name in ['Test', 'Build']]}
        responses = [pull, checks, [], pull, {'merged': True, 'sha': merged},
                     {'object': {'sha': merged}}, {}, None]
        with patch.dict(os.environ, env), patch.object(merge, 'api', side_effect=responses) as api:
            merge.main()
        self.assertEqual(api.call_args_list[-1].args,
                         ('repos/example-games/sampleclient/actions/workflows/ci.yml/dispatches', 'POST', {'ref': 'main'}))
    def test_main_rejects_an_invalid_target_before_any_api_call(self):
        env = {'GITHUB_REPOSITORY': 'example-games/sampleclient', 'PR_NUMBER': '7', 'EXPECTED_HEAD': 'a'*40,
               'GITHUB_RUN_ID': '123', 'DISPATCH_TARGET': '../ci.yml'}
        with patch.dict(os.environ, env), patch.object(merge, 'api') as api:
            with self.assertRaises(ValueError) as raised:
                merge.main()
        self.assertEqual(str(raised.exception), 'invalid dispatch target')
        api.assert_not_called()
