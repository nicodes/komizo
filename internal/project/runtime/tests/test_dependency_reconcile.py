"""Dependency merge authority: real signed-metadata parsing and negative controls."""
import base64
import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import zipfile



spec = importlib.util.spec_from_file_location('reconcile', Path(__file__).resolve().parents[1]/'helpers/dependency-reconcile.py')
reconcile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reconcile)


class DependencyGroups(unittest.TestCase):
    def setUp(self):
        self.updates = [{'dependency-name': 'example', 'dependency-version': '1.2.3', 'update-type': 'version-update:semver-patch'},
                        {'dependency-name': 'another', 'dependency-version': '2.4.0', 'update-type': 'version-update:semver-minor'}]

    def test_every_member_is_checked(self):
        judge = reconcile.policy_engine.review_reason
        self.assertIsNone(judge(self.updates))
        for change in ({'dependency-name': '@noble/curves'}, {'dependency-version': '0.4.0'},
                       {'update-type': 'version-update:semver-major'}, {'dependency-version': '2.4.0-rc.1'},
                       {'dependency-version': 'sha256:abcd'}, {'dependency-name': 'example'}):
            with self.subTest(change=change):
                updates = copy.deepcopy(self.updates)
                updates[1].update(change)
                self.assertIsNotNone(judge(updates))
        self.assertIsNotNone(judge(self.updates, maximum=1))
        self.assertIsNotNone(judge(self.updates, managed=['anoth*']))
        self.assertIsNotNone(judge(self.updates, sensitive=['anoth*']))
        for invalid in ([], {}, [None], [{'dependency-name': 'missing-version'}]):
            self.assertIsNotNone(judge(invalid))

    def commit(self, block=None):
        return {'sha': 'a'*40, 'author': {'login': 'dependabot[bot]'}, 'commit': {
            'verification': {'verified': True, 'reason': 'valid'},
            'message': 'Update dependencies\n\n---\n'+(block or 'updated-dependencies:\n- dependency-name: example\n  dependency-version: 1.2.3\n  update-type: version-update:semver-patch\n')+'...\n'}}

    def test_only_unchanged_verified_bot_metadata_is_admitted(self):
        commit = self.commit()
        self.assertEqual(reconcile.metadata([commit], 'a'*40)[0]['dependency-name'], 'example')
        for change in ({'author': {'login': 'maintainer'}}, {'sha': 'b'*40}):
            value = copy.deepcopy(commit); value.update(change)
            with self.assertRaises(ValueError): reconcile.metadata([value], 'a'*40)
        value = copy.deepcopy(commit); value['commit']['verification']['verified'] = False
        with self.assertRaises(ValueError): reconcile.metadata([value], 'a'*40)
        with self.assertRaises(ValueError): reconcile.metadata([commit, commit], 'a'*40)
        for block in ('updated-dependencies: &a [*a]\n', 'updated-dependencies: []\nupdated-dependencies: []\n', 'extra: data\n'):
            with self.subTest(block=block), self.assertRaises(ValueError):
                reconcile.metadata([self.commit(block)], 'a'*40)


class MergeBoundaries(unittest.TestCase):
    def setUp(self):
        self.policy = {'version': 1, 'mode': 'auto', 'ci_workflow': 'ci.yml', 'required_checks': ['Test', 'Build'],
                       'integration_job': 'test', 'dispatch_workflow': 'cd.yml', 'max_group_size': 10,
                       'managed_dependencies': [], 'sensitive_dependencies': []}
        self.repo, self.head, self.base, self.merged = 'example/widget', 'a'*40, 'b'*40, 'c'*40
        self.pull = {'state': 'open', 'draft': False, 'user': {'login': 'dependabot[bot]'},
                     'base': {'ref': 'main'}, 'head': {'sha': self.head, 'repo': {'full_name': self.repo}}}
        self.receipt = {'tree': 'd'*40}
        self.commit = {'parents': [{'sha': self.base}, {'sha': self.head}], 'tree': {'sha': self.receipt['tree']}}

    def test_policy_fails_closed(self):
        self.assertEqual(reconcile.validate_policy(self.policy), self.policy)
        for key, value in (('required_checks', []), ('max_group_size', 21), ('ci_workflow', '../ci.yml'),
                           ('integration_job', 'test;true'), ('dispatch_workflow', ''), ('managed_dependencies', 'all')):
            policy = copy.deepcopy(self.policy); policy[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): reconcile.validate_policy(policy)

    def run_merge(self, responses, state='ready', apply=True):
        with patch.object(reconcile, 'api', side_effect=responses) as api, \
                patch.object(reconcile, 'pages', side_effect=[[DependencyGroups().commit()], [{'filename': 'bun.lock'}]]), \
                patch.object(reconcile, 'ci_evidence', return_value=(state, 'fixture decision', self.receipt)):
            result = reconcile.inspect(self.repo, 7, self.base, self.policy, apply)
        return result, api

    def test_ready_head_merges_only_the_tested_tree_and_dispatches(self):
        result, api = self.run_merge([self.pull, {'id': 9, 'state': 'active'}, self.pull,
                                     {'object': {'sha': self.base}}, {'merged': True, 'sha': self.merged},
                                     self.commit, {'object': {'sha': self.merged}}, {'object': {'sha': self.merged}}, None])
        self.assertEqual(result['state'], 'merged')
        self.assertEqual(api.call_args_list[4].args, (f'repos/{self.repo}/pulls/7/merge', 'PUT', {'sha': self.head, 'merge_method': 'merge'}))
        self.assertEqual(api.call_args_list[-1].args, (f'repos/{self.repo}/actions/workflows/9/dispatches', 'POST', {'ref': 'main'}))

    def test_waiting_failed_stale_and_read_only_never_mutate(self):
        for state in ('waiting', 'blocked', 'stale', 'ready'):
            with self.subTest(state=state):
                result, api = self.run_merge([self.pull], state, apply=False)
                self.assertEqual(result['state'], state)
                self.assertEqual(api.call_count, 1)

    def test_moved_head_or_base_never_merges(self):
        for fresh, base in (({**self.pull, 'head': {'sha': 'e'*40}}, self.base), (self.pull, 'e'*40)):
            result, api = self.run_merge([self.pull, {'id': 9, 'state': 'active'}, fresh, {'object': {'sha': base}}])
            self.assertEqual(result['state'], 'stale')
            self.assertFalse(any(len(c.args) > 1 for c in api.call_args_list))

    def test_wrong_merged_tree_never_dispatches(self):
        commit = copy.deepcopy(self.commit); commit['tree']['sha'] = 'e'*40
        with self.assertRaisesRegex(ValueError, 'deployment refused'):
            self.run_merge([self.pull, {'id': 9, 'state': 'active'}, self.pull, {'object': {'sha': self.base}},
                            {'merged': True, 'sha': self.merged}, commit])

    def test_event_names_do_not_grant_merge_authority(self):
        with patch.object(reconcile, 'api', return_value={'path': '.github/workflows/other.yml', 'event': 'pull_request', 'status': 'completed'}) as api:
            self.assertEqual(reconcile.candidates(self.repo, {'workflow_run': {'id': 123}}, 'workflow_run', self.policy), [])
        with self.assertRaises(ValueError): reconcile.candidates(self.repo, {}, 'issue_comment', self.policy)

    def test_ci_identity_and_required_jobs_are_enforced(self):
        run = {'id': 123, 'run_attempt': 2, 'workflow_id': 4, 'path': '.github/workflows/ci.yml',
               'head_sha': self.head, 'event': 'pull_request', 'head_repository': {'full_name': self.repo},
               'repository': {'full_name': self.repo},
               'status': 'completed', 'conclusion': 'success'}
        jobs = [{'name': n, 'conclusion': 'success', 'status': 'completed', 'head_sha': self.head,
                 'run_attempt': 2} for n in ('Test', 'Build')]
        for mutate in ('none', 'wrong-workflow', 'failed', 'pending', 'skipped'):
            current = copy.deepcopy(run); selected = copy.deepcopy(jobs)
            if mutate == 'wrong-workflow': current['workflow_id'] = 99
            if mutate == 'failed': current['conclusion'] = 'failure'
            if mutate == 'pending': current['status'] = 'in_progress'
            if mutate == 'skipped': selected[1]['conclusion'] = 'skipped'
            with self.subTest(mutate=mutate), patch.object(reconcile, 'api', return_value={'id': 4}), \
                    patch.object(reconcile, 'pages', side_effect=[[current], selected, [], []]), \
                    patch.object(reconcile, 'integration', return_value=self.receipt):
                if mutate == 'skipped':
                    with self.assertRaises(ValueError): reconcile.ci_evidence(self.repo, self.head, self.base, self.policy)
                else:
                    state, _, _ = reconcile.ci_evidence(self.repo, self.head, self.base, self.policy)
                    self.assertEqual(state, {'none':'ready', 'wrong-workflow':'waiting', 'failed':'blocked', 'pending':'waiting'}[mutate])


if __name__ == '__main__':
    unittest.main()
