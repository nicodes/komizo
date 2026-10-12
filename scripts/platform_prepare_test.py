"""Public release planning: immutable embedded inputs and stale-plan refusal."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('platform_prepare', Path(__file__).with_name('platform_prepare.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Preparation(unittest.TestCase):
    def review_fixture(self, root):
        candidate = root/'candidate.sh'; candidate.write_bytes(b'#!/bin/sh\nexit 0\n'); candidate.chmod(0o600)
        review = root/'review.json'; review.write_text(json.dumps({'version':1,'files':[
            {'path':'/var/lib/komizo/tasks/example.sh','source':'candidate.sh','mode':0o700}]})); review.chmod(0o600)
        return review

    def test_authority_review_refuses_foreign_paths_permissions_links_and_traversal(self):
        for bad in ('path','mode','link','traversal','public'):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
                root = Path(tmp); root.chmod(0o700); review = self.review_fixture(root)
                document = json.loads(review.read_bytes())
                if bad == 'path': document['files'][0]['path'] = '/etc/shadow'
                elif bad == 'mode': document['files'][0]['mode'] = 0o755
                elif bad == 'traversal': document['files'][0]['source'] = '../candidate.sh'
                elif bad == 'public': (root/'candidate.sh').chmod(0o644)
                else:
                    (root/'candidate.sh').unlink(); (root/'candidate.sh').symlink_to('review.json')
                review.write_text(json.dumps(document))
                with self.protected_fixture(root), self.assertRaises(ValueError): m.authority_inputs(review)

    def test_authority_plan_is_read_only_records_absence_and_requires_installed_executor(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            root=Path(tmp); root.chmod(0o700); review=self.review_fixture(root)
            release=root/'release';release.mkdir(mode=0o700)
            (release/'komizo-box-linux-amd64').write_bytes(b'fixture released box')
            (release/'komizo_Linux_x86_64.tar.gz').write_bytes(b'fixture archive')
            (release/'embedded-agents.json').write_text(json.dumps({'sha256':m.digest(b'fixture released box'),'stamp':'a'*12}))
            version='0.0.88';calls=[]
            def run(args,body=None,**kwargs):
                calls.append((args,body)); command=args[-1]
                if command=='uname -m':return b'x86_64'
                if command=='komizo-box version':return version.encode()
                if command=='komizo-box report':return b'{"apps":[{"name":"example"}]}'
                raise AssertionError(args)
            with self.protected_fixture(root),patch.object(m,'verify',return_value='fixture template'),patch.object(m,'run',side_effect=run),patch.object(m,'remote_identity',return_value=(None,None)):
                plan=m.prepare('box.example.test','v0.0.88','a'*40,release,None,root/'authority-plan',authority_review=review)
                self.assertFalse(plan['applied']);self.assertTrue(all(body is None for _,body in calls))
                value=json.loads((root/'authority-plan/manifest.json').read_bytes())
                self.assertEqual(value['kind'],'workload-authority'); self.assertIsNone(value['files'][0]['before'])
                self.assertIsNone(value['files'][0]['before_mode']); self.assertEqual(value['files'][0]['mode'],0o700)
                self.assertEqual((root/'authority-plan/box').read_bytes(),b'fixture released box')
                version='0.0.87'
                with self.assertRaisesRegex(ValueError,'install this authenticated executor'):
                    m.prepare('box.example.test','v0.0.88','a'*40,release,None,root/'old-executor-plan',authority_review=review)

    def protected_fixture(self, root):
        protect = m.protected_directory
        return patch.object(m, 'protected_directory', side_effect=lambda path: protect(path, root=root, owner=os.getuid()))

    def test_wrapper_uses_only_fixed_installed_metadata(self):
        template = "<<'KOMIZO_DEPLOY_EOF'\nAPP_NAME=\"__APP_NAME__\"\nAPP_DIR=\"__APP_DIR__\"\nKOMIZO_DEPLOY_EOF\n"
        fields = {'APP_NAME': 'example', 'APP_DIR': '/srv/example', 'CONFIG_IMAGE': 'ghcr.io/owner/example-config',
            'PROXY_CONTAINER': 'komizo-proxy', 'PROXY_DIR': '/srv/_proxy', 'SCOPED_ENV': '',
            'ROUTE_FILE': '/srv/_proxy/routes/example.caddy'}
        previous = '\n'.join(f'{k}="{v}"' for k, v in fields.items())
        self.assertIn(b'APP_NAME="example"', m.wrapper(template, previous))
        for bad in (previous.replace('/srv/example', '$(foreign-command)'), previous.replace('/srv/example', '/srv/example;foreign')):
            with self.assertRaises(ValueError): m.wrapper(template, bad)
        with self.assertRaises(ValueError): m.wrapper(template.replace('__APP_NAME__', '__UNKNOWN__'), previous)


    def test_named_task_wrapper_has_fixed_authority_and_rejects_unsafe_names(self):
        template="<<'KOMIZO_TASK_EOF'\n#!/bin/sh\nexec /usr/local/bin/komizo-box workload task --policy /etc/komizo/workloads/__APP_NAME__.json -- \"$@\"\nKOMIZO_TASK_EOF\n"
        body=m.task_wrapper(template,'example').decode()
        self.assertIn('/etc/komizo/workloads/example.json -- "$@"',body)
        for name in ('../foreign','example;foreign','example\nforeign'):
            with self.assertRaises(ValueError): m.task_wrapper(template,name)
        with self.assertRaises(ValueError): m.task_wrapper(template.replace('__APP_NAME__','__UNKNOWN__'),'example')

    def test_plan_is_read_only_and_apply_refuses_changed_manifest_before_remote_effects(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            root = Path(tmp); root.chmod(0o700)
            release = root/'release'; release.mkdir(mode=0o700)
            (release/'komizo-box-linux-amd64').write_bytes(b'fixture released box')
            (release/'komizo_Linux_x86_64.tar.gz').write_bytes(b'fixture archive')
            metadata = {'sha256': m.digest(b'fixture released box'), 'stamp': 'a'*12}
            (release/'embedded-agents.json').write_text(json.dumps(metadata))
            stage = root/'reviewed-plan'; calls = []
            def run(args, body=None, **kwargs):
                calls.append((args, body))
                command = args[-1]
                if command == 'uname -m': return b'x86_64\n'
                if command == 'komizo-box version': return b'0.0.80\n'
                if command == 'komizo-box report': return b'{"apps":[]}'
                if command.startswith('sha256sum '): return ('b'*64+'  protected-file\n').encode()
                raise AssertionError(args)
            with self.protected_fixture(root), patch.object(m, 'verify', return_value='fixture template'), patch.object(m, 'run', side_effect=run):
                result = m.prepare('box.example.test', 'v0.0.81', 'a'*40, release, None, stage)
                self.assertTrue(result['prepared']); self.assertFalse(result['applied'])
                self.assertTrue(all(body is None for _, body in calls))
                calls.clear()
                manifest = stage/'manifest.json'; manifest.write_bytes(manifest.read_bytes()+b' ')
                with self.assertRaisesRegex(ValueError, 'reviewed prepared manifest'):
                    m.prepare('box.example.test', 'v0.0.81', 'a'*40, release, None, stage,
                              apply=True, resume=True, expected_manifest=result['manifest_sha256'])
                self.assertEqual(calls, [])


    def test_reviewed_plan_stages_once_and_uses_exact_typed_apply(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            root = Path(tmp); root.chmod(0o700)
            release = root/'release'; release.mkdir(mode=0o700)
            box = b'fixture released box'
            (release/'komizo-box-linux-amd64').write_bytes(box)
            (release/'komizo_Linux_x86_64.tar.gz').write_bytes(b'fixture archive')
            (release/'embedded-agents.json').write_text(json.dumps({'sha256': m.digest(box), 'stamp': 'a'*12}))
            stage = root/'reviewed-plan'; uploaded = {}; mutations = []
            def run(args, body=None, **kwargs):
                command = args[-1]
                if body is not None:
                    name = command.split('cat > ')[1].split(';')[0].rsplit('/',1)[1]
                    uploaded[name] = body; mutations.append(name); return b''
                if command == 'uname -m': return b'x86_64'
                if command == 'komizo-box version': return b'0.0.80'
                if command == 'komizo-box report': return b'{"apps":[]}'
                if command.startswith('sha256sum '):
                    name = command.rsplit('/',1)[1]
                    return ((m.digest(uploaded[name]) if uploaded else 'b'*64)+'  file').encode()
                if command.startswith('if test -d '): return b'absent'
                if 'install -d -m 700' in command: mutations.append('stage'); return b''
                if command.startswith('test ! -e '): return b''
                if 'box platform apply' in command:
                    expected = command.split()[-1]
                    self.assertEqual(expected, m.digest(uploaded['manifest.json']))
                    mutations.append('apply'); return b'{"phase":"complete","application_restart":false}'
                raise AssertionError(args)
            with self.protected_fixture(root), patch.object(m, 'verify', return_value='fixture template'), patch.object(m, 'run', side_effect=run):
                plan = m.prepare('box.example.test','v0.0.81','a'*40,release,None,stage)
                self.assertEqual(mutations, [])
                with self.assertRaisesRegex(ValueError, 'host or receipt'):
                    m.prepare('foreign.example.test','v0.0.81','a'*40,release,None,stage,True,True,plan['manifest_sha256'])
                self.assertEqual(mutations, [])
                applied = m.prepare('box.example.test','v0.0.81','a'*40,release,None,stage,True,True,plan['manifest_sha256'])
                self.assertTrue(applied['applied']); self.assertFalse(applied['application_restart'])
                self.assertEqual(mutations[-1], 'apply')
                self.assertEqual(uploaded['box'], box)

    def test_invalid_host_or_unprotected_ancestry_refuses_before_release_verification(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            root = Path(tmp); root.chmod(0o700)
            with patch.object(m, 'verify') as verify:
                for host in ('-oProxyCommand=foreign', 'box.example.test;foreign', 'root@box.example.test', ''):
                    with self.assertRaises(ValueError): m.prepare(host, 'v0.0.81', 'a'*40, root/'release', None, root/'stage')
                root.chmod(0o777)
                with self.assertRaises(ValueError): m.prepare('box.example.test', 'v0.0.81', 'a'*40, root/'release', None, root/'stage')
                verify.assert_not_called()
                root.chmod(0o700)


if __name__ == '__main__': unittest.main()
