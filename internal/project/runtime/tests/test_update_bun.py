import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('update_bun', Path(__file__).parents[1]/'helpers/update-bun.py')
update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update)


class BunUpdates(unittest.TestCase):
    def setUp(self):
        environment = dict(os.environ)
        environment.pop('GITHUB_REPOSITORY', None)
        environment.pop('MAINTENANCE_ASSIGNEE', None)
        fixture = patch.dict(os.environ, environment, clear=True)
        fixture.start(); self.addCleanup(fixture.stop)

    def test_mismatched_workflow_caller_fails_before_api(self):
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'example/caller'}), patch.object(update, 'api') as api:
            with self.assertRaisesRegex(ValueError, 'workflow caller'):
                update.publish('example/other', 'a'*40, [], {})
            api.assert_not_called()

    def test_pinned_table_schema_and_out_of_range_updates(self):
        rows = update.parse_inventory('bun outdated v1.4.1 (4661e494f)\n|---|---|---|---|\n'
            '| Package | Current | Update | Latest |\n| @types/bun (dev) | 1.4.1 | 1.4.1 | 2.0.0 |\n')
        self.assertEqual(rows, [{'package': '@types/bun', 'current': '1.4.1', 'update': '1.4.1', 'latest': '2.0.0'}])
        for output in ['network unavailable', '| pkg | unknown | 1.0.0 | 2.0.0 |', '| pkg | 1.0.0 | 2.0.0 |']:
            with self.assertRaises(ValueError):
                update.parse_inventory(output)
        self.assertEqual(update.parse_inventory(''), [])

    def test_main_moved_blocks_all_writes(self):
        with patch.object(update, 'api', return_value={'object': {'sha': 'b'*40}}) as api:
            with self.assertRaises(ValueError):
                update.publish('nicodes/example-be', 'a'*40, [], {'app/bun.lock': 'changed'})
            self.assertEqual(api.call_count, 1)

    def test_transitive_refresh_creates_only_an_owned_issue(self):
        calls = []
        def api(repo, suffix, payload=None):
            calls.append((suffix, payload))
            if suffix == 'git/ref/heads/main': return {'object': {'sha': 'a'*40}}
            if suffix == 'issues': return {'number': 7}
            raise AssertionError('Only issue creation is permitted')
        with patch.object(update, 'api', side_effect=api), patch.object(update, 'run', return_value='[]') as run:
            update.publish('nicodes/example-be', 'a'*40, [], {'app/bun.lock': 'changed'})
        self.assertEqual(run.call_args.args[0][:3], ['gh', 'issue', 'list'])
        body = calls[-1][1]
        self.assertNotIn('assignees', body)
        self.assertIn('app/bun.lock', body['body'])
        self.assertIn('open a PR manually', body['body'])

    def test_existing_issue_is_updated_without_pr_or_code_writes(self):
        def run(args, **kwargs):
            if args[:3] == ['gh', 'issue', 'list']:
                return json.dumps([{'number': 4, 'title': 'Bun maintenance: available dependency updates'}])
            self.assertEqual(args[:3], ['gh', 'api', 'repos/nicodes/example-be/issues/4'])
            self.assertIn('PATCH', args)
            self.assertNotIn('assignees', json.loads(kwargs['input']))
            return '{}'
        with patch.object(update, 'api', return_value={'object': {'sha': 'a'*40}}) as api, patch.object(update, 'run', side_effect=run):
            update.publish('nicodes/example-be', 'a'*40, [], {'app/bun.lock': 'changed'})
            self.assertEqual(api.call_count, 1)

    def test_no_updates_does_not_close_or_create_issues(self):
        with patch.object(update, 'api', return_value={'object': {'sha': 'a'*40}}) as api, patch.object(update, 'run') as run:
            update.publish('nicodes/example-be', 'a'*40, [], {})
            self.assertEqual(api.call_count, 1)
            run.assert_not_called()

    def test_all_top_level_bun_applications_are_reported(self):
        files = 'app/package.json\0web/package.json\0e2e/package.json\0app/node_modules/no/package.json\0'
        def prepare(root, application):
            return [{'package': 'example', 'current': '1.0.0', 'update': '1.0.1', 'latest': '2.0.0'}], {application+'/bun.lock': 'new'}
        with patch.object(update, 'run', return_value=files), patch.object(update, 'prepare_application', side_effect=prepare):
            rows, changes = update.prepare(Path('/repo'))
        self.assertEqual([r['application'] for r in rows], ['app', 'e2e', 'web'])
        self.assertEqual(set(changes), {'app/bun.lock', 'web/bun.lock', 'e2e/bun.lock'})

    def test_the_products_own_package_directory_is_discovered(self):
        # example-games/samplegame tracks no `app/`; its Bun application is `playwright/`.
        files = 'playwright/package.json\0playwright/bun.lock\0'
        def prepare(root, application):
            return [], {application+'/bun.lock': 'new'}
        with patch.object(update, 'run', return_value=files), patch.object(update, 'prepare_application', side_effect=prepare) as prepare_application:
            rows, changes = update.prepare(Path('/repo'))
        self.assertEqual([call.args[1] for call in prepare_application.call_args_list], ['playwright'])
        self.assertEqual(set(changes), {'playwright/bun.lock'})
        with patch.object(update, 'run', return_value=''), patch.object(update, 'prepare_application') as prepare_application:
            with self.assertRaises(ValueError):
                update.prepare(Path('/repo'))
            prepare_application.assert_not_called()

    def test_only_portfolio_org_repositories_are_allowed(self):
        # Org-level boundary (docs/ACTIVE-PROJECTS.md), the merge-checked.py form:
        # an adopting portfolio repository needs no helper change.
        for repo in ['example-games/sampleaddon-be', 'example-games/sampleconsole-be', 'sampleservicelogical/sampleservice-be',
                     'example-games/samplegame', 'example-games/samplearcade', 'nicodes/anything', 'example/widget']:
            with patch.object(update, 'api', return_value={'object': {'sha': 'a'*40}}):
                update.publish(repo, 'a'*40, [], {})
        for repo in [ 'example-games/HasUpper', 'example-games/under_score',
                     'example-games/two/parts', 'example-games/dot.git', 'example-games/', 'nicodes',
                     'example-games/samplegame\n']:
            with patch.object(update, 'api') as api:
                with self.assertRaises(ValueError):
                    update.publish(repo, 'a'*40, [], {})
                api.assert_not_called()
