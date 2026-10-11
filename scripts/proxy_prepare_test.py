"""Generic proxy lifecycle uses explicit operator inputs and exact prepared bytes."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import base64
import hashlib
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


    def test_probe_keeps_reviewed_path_and_refuses_redirect(self):
        with patch.object(m.http.client,'HTTPSConnection') as connect:
            conn=connect.return_value;response=conn.getresponse.return_value
            response.status=302
            self.assertFalse(m.existing_probe({'url':'https://app.example.test/readyz','revision':'a'*40}))
            conn.request.assert_called_once_with('GET','/readyz')
            conn.close.assert_called_once()
        with patch.object(m.http.client,'HTTPSConnection') as connect:
            conn=connect.return_value;response=conn.getresponse.return_value;response.status=101
            def header(name,default=None):
                sent=conn.request.call_args.kwargs['headers']['Sec-WebSocket-Key']
                return {'X-Komizo-Revision':'a'*40,'Upgrade':'websocket','Sec-WebSocket-Accept':base64.b64encode(hashlib.sha1((sent+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()}.get(name,default)
            response.getheader.side_effect=header
            self.assertTrue(m.existing_probe({'url':'wss://socket.example.test/bridge/','revision':'a'*40}))
            self.assertEqual(conn.request.call_args.args,('GET','/bridge/'))
            conn.close.assert_called_once()

    def test_successful_proxy_apply_uses_prepared_bytes_and_interruption_never_replays(self):
        for interrupted in (False,True):
            with self.subTest(interrupted=interrupted),tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
                root=Path(tmp);root.chmod(0o700);stage=root/'plan';uploaded={};effects=[];journal=[]
                source='a'*40;reference='ghcr.io/nicodes/platform-proxy@sha256:'+'b'*64
                probes=[{'url':'https://app.example.test/readyz','revision':'c'*40}]
                compose=json.dumps({'name':'komizo-proxy','services':{'komizo-proxy':{'image':'old','volumes':['tls:/data']}}}).encode()
                listener=b'{\n email owner@example.test\n}\nimport routes/*\n'
                def run(args,body=None,**kwargs):
                    command=args[-1]
                    if body is not None:
                        uploaded[command.split('cat > ')[1].rsplit('/',1)[1]]=body;effects.append('upload');return b''
                    if command=='komizo-box report':return json.dumps({'server':{'komizo':{'version':'0.0.82'}},'apps':[{'runtime_state':'running','version':'c'*40,'hosts':[{'name':'app.example.test'}]}]}).encode()
                    if command=='uname -m':return b'x86_64'
                    if command.startswith('docker pull '):effects.append('prefetch');return b''
                    if command.startswith('docker image inspect --format "{{.Id}}"'):return ('sha256:'+'d'*64).encode()
                    if command.startswith('docker inspect --format'):return ('sha256:'+'e'*64).encode()
                    if command.startswith('docker image inspect --format'):return source.encode()
                    if command=='cat /srv/_proxy/compose.yml':return compose
                    if command=='cat /srv/_proxy/Caddyfile':return listener
                    if command.startswith('if test -d '):return b'existing' if uploaded else b'absent'
                    if 'install -d -m 700' in command:effects.append('stage');return b''
                    if command.startswith('test ! -e '):
                        if journal:raise subprocess.CalledProcessError(1,args)
                        return b''
                    if command.startswith('sha256sum '):return (m.digest(uploaded[command.rsplit('/',1)[1]])+'  file').encode()
                    if command.startswith('komizo-box platform apply '):
                        self.assertEqual(command.split()[-1],m.digest(uploaded['manifest.json']))
                        effects.append('apply');journal.append('started')
                        if interrupted:raise subprocess.TimeoutExpired(args,300)
                        return b'{"phase":"complete"}'
                    raise AssertionError(command)
                with self.protection(root),patch.object(m,'verify',return_value=b'fixture authenticated provenance'),patch.object(m,'existing_probe',return_value=True),patch.object(m,'run',side_effect=run):
                    plan=m.prepare('box.example.test',reference,source,stage,probes)
                    self.assertEqual(effects,['prefetch'])
                    self.assertEqual(json.loads((stage/'proxy-compose').read_bytes())['services']['komizo-proxy']['volumes'],['tls:/data'])
                    if interrupted:
                        with self.assertRaises(subprocess.TimeoutExpired):m.prepare('box.example.test',reference,source,stage,probes,True,plan['manifest_sha256'])
                    else:
                        applied=m.prepare('box.example.test',reference,source,stage,probes,True,plan['manifest_sha256']);self.assertTrue(applied['applied'])
                    before=list(effects)
                    with self.assertRaises(subprocess.CalledProcessError):m.prepare('box.example.test',reference,source,stage,probes,True,plan['manifest_sha256'])
                    self.assertEqual(effects,before)
                    self.assertEqual(effects.count('apply'),1)
                    self.assertEqual(uploaded['proxy-caddy'],m.bounded_listener(listener.decode()))
