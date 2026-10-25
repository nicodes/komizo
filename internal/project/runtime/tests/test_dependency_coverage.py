import json
from pathlib import Path
import subprocess
import unittest


class DependencyCoverage(unittest.TestCase):
    def test_new_go_modules_and_disabled_schedules_cannot_escape_updates(self):
        module = (Path(__file__).parents[1] / 'helpers/dependency-coverage.mjs').as_uri()
        program = f'''import {{ verifyDependencyCoverage }} from {json.dumps(module)};
const data = JSON.parse(process.argv[1]);
verifyDependencyCoverage(data.config, data.files, data.bun);
'''
        updates = [
            {'package-ecosystem': ecosystem, 'directories': directories, 'schedule': {'interval': 'weekly'}}
            for ecosystem, directories in [('github-actions', ['/']),
                                            ('docker', ['/deploy/images']), ('gomod', ['/api', '/pb'])]
        ]

        workflow = {'on': {'schedule': [{'cron': '17 10 * * 1'}]}, 'jobs': {'update': {
            'permissions': {'contents': 'read', 'issues': 'write'},
            'if': "github.ref == 'refs/heads/main'", 'steps': [
                {'uses': 'jdx/mise-action@'+'a'*40},
                {'run': 'python3 scripts/engineering/helpers/update-bun.py'}]}}}

        def check(files, entries=updates, bun=workflow):
            return subprocess.run(['bun', '--eval', program, json.dumps({
                'config': {'version': 2, 'updates': entries}, 'files': files, 'bun': bun})],
                capture_output=True, text=True, timeout=20)

        self.assertEqual(check(['app/package.json']).returncode, 0)
        self.assertEqual(check(['api/go.mod', 'pb/go.mod']).returncode, 0)
        self.assertNotEqual(check(['api/go.mod', 'pb/go.mod'], updates[:-1]).returncode, 0)
        self.assertNotEqual(check(['api/go.mod', 'pb/go.mod', 'worker/nested/go.mod']).returncode, 0)
        disabled = json.loads(json.dumps(updates))
        disabled[-1]['schedule'] = {}
        self.assertNotEqual(check(['api/go.mod'], disabled).returncode, 0)
        for index in range(2):
            self.assertNotEqual(check([], updates[:index] + updates[index+1:]).returncode, 0)

        self.assertNotEqual(check([], bun={}).returncode, 0)
        for permission in ['contents', 'pull-requests', 'actions']:
            excessive = json.loads(json.dumps(workflow))
            excessive['jobs']['update']['permissions'][permission] = 'write'
            self.assertNotEqual(check([], bun=excessive).returncode, 0)
        workflow['jobs']['update']['environment'] = 'production'
        self.assertNotEqual(check([]).returncode, 0)


class ProductsWithNoBunApplication(unittest.TestCase):
    """samplearcade and sampleclient are Godot clients with a Go gate and no
    package.json anywhere. Requiring a bun-updates workflow of them asks for
    a scheduled job that would run `bun update` over nothing -- and the read
    of that file was unconditional, so pins.mjs died on ENOENT before it
    could even say what it wanted.
    """

    def coverage(self, files, bun_workflow):
        program = (
            "const m = await import(%s);"
            "const [files, bun] = JSON.parse(process.argv[1]);"
            "try { m.verifyDependencyCoverage(JSON.parse(process.argv[2]), files, bun);"
            "      console.log('OK'); }"
            "catch (e) { console.log('REFUSED: ' + e.message); }"
        ) % json.dumps(str(Path(__file__).parents[1]/'helpers/dependency-coverage.mjs'))
        config = {'version': 2, 'updates': [
            {'package-ecosystem': 'github-actions', 'directories': ['/'],
             'schedule': {'interval': 'weekly'}},
            {'package-ecosystem': 'docker', 'directories': ['/deploy/images'],
             'schedule': {'interval': 'weekly'}},
        ]}
        result = subprocess.run(
            ['bun', '--eval', program, json.dumps([files, bun_workflow]), json.dumps(config)],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_no_bun_application_means_no_bun_workflow_is_required(self):
        self.assertEqual(self.coverage(['godot_client/project.godot'], None), 'OK')

    def test_a_workflow_that_is_there_is_still_checked(self):
        # Only the REQUIREMENT is lifted, not the checking. A first draft of
        # this also FORBADE the workflow to such a product, which is an
        # opinion this file has no business holding: these products do run
        # bun -- pins.mjs is bun -- and whether the updater is useful to them
        # is their decision.
        said = self.coverage(['godot_client/project.godot'],
                             {'on': {'schedule': [{'cron': '0 0 * * 1'}]}})
        self.assertIn('REFUSED', said)

    def test_a_product_WITH_a_bun_application_still_needs_it(self):
        # The case worth catching: an app exists and somebody deleted the
        # workflow. Keying on the application rather than on the workflow's
        # own presence is what keeps this failing.
        said = self.coverage(['app/package.json'], None)
        self.assertIn('Bun native update schedule is required', said)
