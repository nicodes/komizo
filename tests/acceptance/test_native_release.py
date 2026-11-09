"""Keep source, artifact, platform and independent signer fences at release."""
import copy
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest

import native_release as release


def elf(machine,label):
    raw=bytearray(120);raw[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQ',raw,16,2,machine,1,0x400000,64)
    struct.pack_into('<HHH',raw,52,64,56,1);struct.pack_into('<I',raw,64,1)
    return bytes(raw)+label.encode()


def macho(arm,label):
    raw=bytearray(32);raw[:4]=b'\xcf\xfa\xed\xfe'
    struct.pack_into('<I',raw,4,0x0100000c if arm else 0x01000007);struct.pack_into('<I',raw,12,2)
    return bytes(raw)+label.encode()


def archive(path,binary,*,link=False):
    with tarfile.open(path,'w:gz',format=tarfile.USTAR_FORMAT) as package:
        for name,body in [('komizo',binary),('README.md',b'public usage'),('LICENSE',b'license')]:
            item=tarfile.TarInfo(name);item.mode=0o755 if name=='komizo' else 0o644
            if link and name=='komizo':item.type=tarfile.SYMTYPE;item.linkname='/bin/sh'
            else:item.size=len(body)
            package.addfile(item,None if item.issym() else io.BytesIO(body))


class NativeRelease(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.source='a'*40;self.tag='v0.0.123'
        for name in release.CLI_NAMES:
            binary=elf(183 if '_arm64.' in name else 62,name) if '_Linux_' in name else macho('_arm64.' in name,name)
            archive(self.root/name,binary)
        for name,(platform,machine) in release.HOSTS.items():
            raw=elf(machine,name);(self.root/name).write_bytes(raw)
            (self.root/(name+'.json')).write_text(json.dumps({'schema':1,'source':self.source,'version':self.tag[1:],
                'kind':'host','platform':platform,'dependencies':{},'sha256':release.digest(raw)}))
        baseline=json.loads((Path(__file__).resolve().parents[1]/'fixtures/native_host/baseline.json').read_text())
        for name,(platform,machine) in release.PROXIES.items():
            raw=elf(machine,name);(self.root/name).write_bytes(raw)
            (self.root/(name+'.json')).write_text(json.dumps({'kind':'komizo.proxy-build','version':1,
                'tools_revision':baseline['proxy_tools_revision'],'platform':platform,'go_version':baseline['proxy_go_version'],
                'caddy_version':baseline['caddy_version'],'source_sha256':baseline['proxy_source_sha256'],'binary_sha256':'sha256:'+release.digest(raw)}))
        self.checksums()

    def checksums(self):
        (self.root/'checksums.txt').write_text(''.join(release.digest((self.root/name).read_bytes())+'  '+name+'\n' for name in sorted(release.PAYLOAD)))

    def test_complete_standalone_payload_is_independently_source_bound(self):
        actual=release.inventory(self.root,self.source,self.tag)
        self.assertEqual(set(actual),release.PAYLOAD);self.assertEqual(len(actual),12)
        with self.assertRaises(ValueError):release.inventory(self.root,'b'*40,self.tag)
        path=self.root/'komizo-box_Linux_x86_64.json';receipt=json.loads(path.read_text());receipt['dependencies']={'api':'c'*64}
        path.write_text(json.dumps(receipt));self.checksums()
        with self.assertRaisesRegex(ValueError,'receipt'):release.inventory(self.root,self.source,self.tag)

    def test_replaced_checksums_and_receipt_cannot_replace_the_independent_signer(self):
        original=release.inventory(self.root,self.source,self.tag)
        def verified(arguments,**options):
            name=Path(arguments[3]).name
            row={'verificationResult':{'signature':{'certificate':{'subjectAlternativeName':release.WORKFLOW,
                'issuer':'https://token.actions.githubusercontent.com','sourceRepositoryDigest':self.source,'githubWorkflowRef':'refs/heads/main'}},
                'statement':{'subject':[{'name':name,'digest':{'sha256':original[name]['sha256']}}]}}}
            return subprocess.CompletedProcess(arguments,0,json.dumps([row]).encode(),b'')
        self.assertEqual(release.verify(self.root,self.source,self.tag,execute=verified)['artifacts'],original)
        name='komizo-box_Linux_x86_64';path=self.root/name;path.write_bytes(path.read_bytes()+b'changed bytes')
        receipt=json.loads((self.root/(name+'.json')).read_text());receipt['sha256']=release.digest(path.read_bytes())
        (self.root/(name+'.json')).write_text(json.dumps(receipt));self.checksums()
        release.inventory(self.root,self.source,self.tag)
        with self.assertRaisesRegex(ValueError,'attestation'):release.verify(self.root,self.source,self.tag,execute=verified)

    def test_wrong_platform_dynamic_interpreter_and_unsafe_archive_refuse(self):
        raw=bytearray(elf(62,'fixture'))
        with self.assertRaises(ValueError):release.host_elf(raw,183)
        struct.pack_into('<I',raw,64,3)
        with self.assertRaisesRegex(ValueError,'interpreter'):release.host_elf(raw,62)
        archive(self.root/'komizo_Linux_x86_64.tar.gz',elf(62,'fixture'),link=True);self.checksums()
        with self.assertRaisesRegex(ValueError,'archive'):release.inventory(self.root,self.source,self.tag)

    def test_checksum_closure_and_proxy_source_or_compiler_changes_refuse(self):
        path=self.root/'checksums.txt';saved=path.read_bytes();path.write_bytes(saved+b'0'*64+b'  ../unowned\n')
        with self.assertRaisesRegex(ValueError,'inventory'):release.inventory(self.root,self.source,self.tag)
        path.write_bytes(saved)
        proxy=self.root/'caddy_Linux_x86_64.json';receipt=json.loads(proxy.read_text());receipt['go_version']='1.26.0'
        proxy.write_text(json.dumps(receipt));self.checksums()
        with self.assertRaisesRegex(ValueError,'proxy receipt'):release.inventory(self.root,self.source,self.tag)

    def test_wrong_source_workflow_and_duplicate_metadata_fields_refuse(self):
        row={'verificationResult':{'signature':{'certificate':{'subjectAlternativeName':release.WORKFLOW,
            'issuer':'https://token.actions.githubusercontent.com','sourceRepositoryDigest':self.source,'githubWorkflowRef':'refs/heads/main'}},
            'statement':{'subject':[{'name':'fixture','digest':{'sha256':'b'*64}}]}}}
        release.attestation([row],'fixture','b'*64,self.source)
        for field,value in [('subjectAlternativeName',release.WORKFLOW.replace('release.yml','other.yml')),
                ('issuer','https://unapproved.example'),('sourceRepositoryDigest','c'*40),('githubWorkflowRef','refs/heads/other')]:
            changed=copy.deepcopy(row);changed['verificationResult']['signature']['certificate'][field]=value
            with self.assertRaises(ValueError):release.attestation([changed],'fixture','b'*64,self.source)
        with self.assertRaises(ValueError):json.loads('{"source":"a","source":"b"}',object_pairs_hook=release.unique)


if __name__=='__main__':unittest.main()
