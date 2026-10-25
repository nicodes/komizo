import importlib.util
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('watch', Path(__file__).parents[1]/'helpers/watch-tools.py')
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)


class ToolWatchTests(unittest.TestCase):
    def test_caddy_updates_and_unknown_module_responses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'internal/project/runtime/helpers').mkdir(parents=True)
            for extension in ['mod', 'sum']:
                (root/'internal/project/runtime/helpers'/f'caddy.go.{extension}').write_text('fixture')
            modules = [{'Path': 'example.invalid/main', 'Main': True},
                {'Path': 'example.invalid/module', 'Version': 'v1.2.3',
                 'Update': {'Path': 'example.invalid/module', 'Version': 'v1.2.4'}}]
            with patch.object(watch.subprocess, 'check_output', return_value='\n'.join(map(json.dumps, modules))):
                self.assertEqual(watch.caddy_updates(root), [('Caddy: example.invalid/module', 'v1.2.3', 'v1.2.4')])
            for bad in ['', '{}', '{"Path":"example.invalid/module","Error":{"Err":"unavailable"}}',
                        '{"Path":"example.invalid/module","Update":{"Path":"other"}}']:
                with patch.object(watch.subprocess, 'check_output', return_value=bad):
                    with self.assertRaises(ValueError): watch.caddy_updates(root)

    def test_inherited_tools_are_not_repository_updates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = {'source': {'path': str(root/'.komizo.mise.toml')}, 'bump': '1.2.4'}
            parent = {'source': {'path': str(root.parent/'.komizo.mise.toml')}, 'bump': '99.0.0'}
            self.assertEqual(watch.updates(root, {'bun': '1.2.3'}, {'bun': local, 'go': parent}),
                             [('bun', '1.2.3', '1.2.4')])

    def test_unknown_versions_fail_and_downgrades_are_ignored(self):
        root = Path('/tmp/tool-watch-fixture')
        item = {'source': {'path': str(root/'.komizo.mise.toml')}, 'latest': '1.2.2'}
        self.assertEqual(watch.updates(root, {'bun': '1.2.3'}, {'bun': item}), [])
        item['latest'] = 'latest'
        with self.assertRaises(ValueError):
            watch.updates(root, {'bun': '1.2.3'}, {'bun': item})

    def test_table_form_github_pins_parse_and_compare(self):
        installed = {
            'bun': '1.4.1',
            'github:example-games/sampleaddon': {'version':'v0.0.8','bin':'sampleaddon'},
            'github:pocketbase/pocketbase': {'version':'v0.39.9'},
            'github:example-games/gd-observe': {'version':'cli-v0.0.5'},
        }
        root = Path('/tmp/tool-watch-fixture')
        config = str(root/'.komizo.mise.toml')
        outdated = {
            'bun': {'source': {'path': config}, 'bump': '1.4.2'},
            'github:example-games/sampleaddon': {'source': {'path': config}, 'latest': 'v0.0.9'},
            # Equal and older cores are not updates, decoration included.
            'github:pocketbase/pocketbase': {'source': {'path': config}, 'latest': 'v0.39.9'},
            'github:example-games/gd-observe': {'source': {'path': config}, 'latest': 'cli-v0.0.5'},
        }
        self.assertEqual(watch.updates(root, installed, outdated),
                         [('bun', '1.4.1', '1.4.2'),
                          ('github:example-games/sampleaddon', 'v0.0.8', 'v0.0.9')])

    def test_floating_pins_are_refused(self):
        root = Path('/tmp/tool-watch-fixture')
        item = {'source': {'path':str(root/'.komizo.mise.toml')},'latest':'3.12.8'}
        for pin in ['3','3.12','3.12.x','',None]:
            with self.assertRaises(ValueError): watch.updates(root,{'python':pin},{'python':item})

    def test_exact_pin_unreadable_upstream_fails_loudly(self):
        # An unreadable upstream answer fails with the actual pin and value.
        root = Path('/tmp/tool-watch-fixture')
        config = str(root/'.komizo.mise.toml')
        item = {'source': {'path': config}, 'latest': 'latest'}
        with self.assertRaises(ValueError) as failure:
            watch.updates(root, {'python': '3.12.0'}, {'python': item})
        message = str(failure.exception)
        self.assertIn("unrecognized upstream version 'latest'", message)
        self.assertIn('3.12.0', message)

    def test_table_form_decoration_variants_and_fail_closed(self):
        root = Path('/tmp/tool-watch-fixture')
        config = str(root/'.komizo.mise.toml')
        installed = {'github:godotengine/godot': {'version': '4.4.1-stable', 'exe': 'godot'}}
        newer = {'source': {'path': config}, 'latest': '4.5.1-stable'}
        self.assertEqual(watch.updates(root, installed, {'github:godotengine/godot': newer}),
                         [('github:godotengine/godot', '4.4.1-stable', '4.5.1-stable')])
        for installed_entry, latest in [({'asset_pattern': 'x'}, 'v1.0.0'),
                                        ({'version': 108}, 'v1.0.0'),
                                        ({'version': 'v1.0.0'}, 'latest'),
                                        ({'version': 'v1.0.0'}, 'v2.0'),
                                        ({'version': 'two.point.oh'}, 'v2.0.1')]:
            item = {'source': {'path': config}, 'latest': latest}
            with self.assertRaises(ValueError, msg=f'{installed_entry} / {latest}'):
                watch.updates(root, {'github:owner/tool': installed_entry}, {'github:owner/tool': item})

    def run_main(self, issues):
        root = Path(self.directory)
        (root/'komizo.json').write_text(json.dumps({'tools':{'bun':'1.2.3'}}))
        os.chdir(root)
        outdated = {'bun': {'source': {'path': str(root/'.komizo.mise.toml')}, 'bump': '1.2.4'}}
        def check_output(args, **kwargs):
            if args[0]=="fixture-komizo":
                return json.dumps({"ok":True,"data":{"tools":{"bun":"1.2.3"}}})
            if args[0] == 'mise':
                return json.dumps(outdated)
            self.assertEqual(args[:3], ['gh', 'issue', 'list'])
            return json.dumps(issues)
        calls = []
        def run(argv, **kwargs):
            # The body file lives in a TemporaryDirectory main() removes;
            # capture argv and body while the file still exists.
            calls.append((list(argv), Path(argv[argv.index('--body-file') + 1]).read_text()))
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'example/tools', 'MAINTENANCE_ASSIGNEE': 'example', 'KOMIZO_EXECUTABLE':'fixture-komizo'}), \
             patch.object(watch.subprocess, 'check_output', side_effect=check_output), \
             patch.object(watch.subprocess, 'run', side_effect=run):
            watch.main()
        self.assertEqual(len(calls), 1)
        return root, calls[0]

    def test_existing_issue_is_edited_with_add_assignee(self):
        # gh issue edit rejects --assignee (the fleet failure); its additive
        # --add-assignee keeps nicodes the owner without erroring when already
        # assigned. gh issue create has no --add-assignee, so only the edit
        # path uses it. The lowest-numbered open issue owns the report.
        title = 'Tool maintenance: pinned versions have updates'
        with tempfile.TemporaryDirectory() as self.directory:
            cwd = os.getcwd()
            self.addCleanup(os.chdir, cwd)
            root, (argv, body) = self.run_main([{'number': 9, 'title': title},
                                                {'number': 3, 'title': title}])
            self.assertEqual(argv[:8], ['gh', 'issue', 'edit', '3', '--repo', 'example/tools',
                                        '--add-assignee', 'example'])
            self.assertNotIn('--assignee', argv)
            self.assertIn('upstream releases', body)
            self.assertIn('| `bun` | `1.2.3` | `1.2.4` |', body)
            self.assertEqual(json.loads((root/'.artifacts/tool-updates.json').read_text()),
                             [['bun', '1.2.3', '1.2.4']])

    def test_missing_issue_is_created_with_assignee(self):
        title = 'Tool maintenance: pinned versions have updates'
        with tempfile.TemporaryDirectory() as self.directory:
            cwd = os.getcwd()
            self.addCleanup(os.chdir, cwd)
            _, (argv, body) = self.run_main([])
            self.assertEqual(argv[:7], ['gh', 'issue', 'create', '--title', title,
                                        '--repo', 'example/tools'])
            self.assertEqual(argv[7:9], ['--assignee', 'example'])
            self.assertNotIn('--add-assignee', argv)
            self.assertIn('upstream releases', body)
