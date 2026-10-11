"""Generic proxy lifecycle uses explicit operator inputs and exact prepared bytes."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('komizo_proxy_prepare',Path(__file__).with_name('proxy_prepare.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ProxyPreparation(unittest.TestCase):
    def protection(self,root):
        protect=m.protected_directory
        return patch.object(m,'protected_directory',side_effect=lambda path:protect(path,root=root,owner=os.getuid()))

    def test_listener_is_idempotent_and_unknown_policy_refuses(self):
        old='{\n email owner@example.test\n}\nimport routes/*\n'
        bounded=m.bounded_listener(old)
        self.assertIn(b'read_header 5s',bounded)
        self.assertIn(b'email owner@example.test',bounded)
        self.assertEqual(m.bounded_listener(bounded.decode()),bounded)
        with self.assertRaises(ValueError):m.bounded_listener('{\n servers { read_header 1h }\n}\n')

    def test_proxy_compose_changes_only_image_and_rejects_unknown_project(self):
        doc={'name':'komizo-proxy','services':{'komizo-proxy':{'image':'previous','volumes':['tls:/data']}}}
        converted=json.loads(m.compose_candidate(json.dumps(doc).encode(),'candidate'))
        self.assertEqual(converted['services']['komizo-proxy'].pop('image'),'candidate')
        doc['services']['komizo-proxy'].pop('image')
        self.assertEqual(converted,doc)
        with self.assertRaises(ValueError):m.compose_candidate(b'{"name":"foreign","services":{}}','candidate')

    def test_private_inputs_refuse_links_and_oversize(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            root=Path(tmp);root.chmod(0o700)
            source=root/'source';source.write_bytes(b'fixture');source.chmod(0o600)
            with self.protection(root):
                self.assertEqual(m.private_bytes(source),b'fixture')
                with self.assertRaises(ValueError):m.private_bytes(source,2)
                link=root/'link';link.symlink_to(source)
                with self.assertRaises(ValueError):m.private_bytes(link)

    def test_apply_requires_reviewed_host_and_digest_before_remote_effects(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            root=Path(tmp);root.chmod(0o700);stage=root/'stage';stage.mkdir(mode=0o700)
            probes=[{'url':'https://app.example.test/health','revision':'a'*40}]
            image={'reference':'ghcr.io/nicodes/platform-proxy@sha256:'+'b'*64}
            receipt={'host':'box.example.test','probes':probes}
            raw=(json.dumps(receipt)+'\n').encode();(stage/'verified-release.json').write_bytes(raw)
            manifest={'kind':'proxy-upgrade','source':'a'*40,'image':image,'receipt_sha256':m.digest(raw),'probes':probes}
            raw=(json.dumps(manifest)+'\n').encode();(stage/'manifest.json').write_bytes(raw)
            for file in stage.iterdir():file.chmod(0o600)
            with self.protection(root),patch.object(m,'run') as run,patch.object(m,'verify') as verify:
                with self.assertRaises(ValueError):m.prepare('foreign.example.test',image['reference'],'a'*40,stage,probes,True,m.digest(raw))
                with self.assertRaises(ValueError):m.prepare('box.example.test',image['reference'],'a'*40,stage,probes,True,'c'*64)
                run.assert_not_called();verify.assert_not_called()

    def test_incomplete_probe_inventory_refuses_before_image_prefetch(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            root=Path(tmp);root.chmod(0o700);stage=root/'plan';calls=[]
            def run(args,body=None,**kwargs):
                calls.append(args[-1])
                if args[-1]=='komizo-box report':return json.dumps({'server':{'komizo':{'version':'0.0.81'}},'apps':[{'runtime_state':'running','version':'a'*40,'hosts':[{'name':'app.example.test'}]}]}).encode()
                if args[-1]=='uname -m':return b'x86_64'
                raise AssertionError(args)
            with self.protection(root),patch.object(m,'verify',return_value=b'fixture authenticated provenance'),patch.object(m,'run',side_effect=run):
                with self.assertRaises(ValueError):m.prepare('box.example.test','ghcr.io/nicodes/platform-proxy@sha256:'+'b'*64,'a'*40,stage,[])
                self.assertFalse(any(command.startswith('docker pull') for command in calls))
