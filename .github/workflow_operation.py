#!/usr/bin/env python3
"""Execute caller-owned fixed argv operations; never infer an application mapping."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile


def api(path):
    return json.loads(subprocess.check_output(['gh','api',path],text=True,timeout=60))

def positive(value):
    if not re.fullmatch(r'[1-9][0-9]*', value): raise ValueError('expected a positive immutable run/artifact ID')
    return value

def provenance(run, artifact, repo, run_id, artifact_id):
    if run['id'] != int(run_id) or artifact['id'] != int(artifact_id): raise ValueError('immutable ID mismatch')
    if run['repository']['full_name'] != repo or run['head_repository']['full_name'] != repo:
        raise ValueError('backup source must belong to this repository')
    if run['head_branch'] != 'main' or run['conclusion'] != 'success' or run['status'] != 'completed':
        raise ValueError('backup must come from a successful completed main run')
    if run['path'] not in {'.github/workflows/cd.yml','.github/workflows/backup.yml'}:
        raise ValueError('backup source is not an approved workflow')
    if run['event'] not in {'push','schedule','workflow_dispatch'}: raise ValueError('untrusted backup event')
    if artifact['expired'] or artifact.get('workflow_run',{}).get('id') != int(run_id):
        raise ValueError('backup artifact expired or belongs to another run')
    if not re.fullmatch(r'backup-[0-9]+(?:-[0-9]+)?',artifact['name']):
        raise ValueError('artifact is not an encrypted backup export')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', artifact.get('digest','')):
        raise ValueError('immutable artifact digest missing')


def recovery(root):
    repo=os.environ['GITHUB_REPOSITORY'];run_id=positive(os.environ['SOURCE_RUN_ID']);artifact_id=positive(os.environ['SOURCE_ARTIFACT_ID'])
    run=api(f'repos/{repo}/actions/runs/{run_id}'); artifact=api(f'repos/{repo}/actions/artifacts/{artifact_id}')
    provenance(run,artifact,repo,run_id,artifact_id)
    with tempfile.TemporaryDirectory(prefix='recovery-evidence-') as scratch:
        scratch=Path(scratch);size=artifact['size_in_bytes']
        if size > 2*1024**3 or shutil.disk_usage(scratch).free < size*5+512*1024**2:
            raise ValueError('artifact exceeds bounded runner capacity; validate this backup locally')
        archive=scratch/'artifact.zip'
        with archive.open('wb') as stream:
            subprocess.run(['gh','api',f'repos/{repo}/actions/artifacts/{artifact_id}/zip'],stdout=stream,check=True,timeout=900)
        with archive.open('rb') as stream:
            digest = hashlib.file_digest(stream,'sha256').hexdigest()
        if digest != artifact['digest'].split(':',1)[1]:
            raise ValueError('immutable backup artifact digest differs')
        exported=scratch/'export.tar'
        with zipfile.ZipFile(archive) as source,tarfile.open(exported,'w') as target:
            if sorted(source.namelist()) != ['receipt.json','snapshot.cms']:
                raise ValueError('backup artifact must contain only encrypted snapshot and receipt')
            for name in source.namelist():
                entry=source.getinfo(name)
                if entry.file_size > (64*1024 if name=='receipt.json' else 2*1024**3): raise ValueError('backup member exceeds bound')
                member=tarfile.TarInfo(name);member.size=entry.file_size
                with source.open(entry) as stream:target.addfile(member,stream)
        helper=Path(os.environ['CICD_ENGINEERING'])/'helpers/receive-backup.py'
        spec=importlib.util.spec_from_file_location('receive_backup',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        receipt=module.receive(exported,scratch/'checked')
        report={'transport_verified':True,'repository':repo,'run_id':int(run_id),'artifact_id':int(artifact_id),
                'source_revision':run['head_sha'],'ciphertext_sha256':receipt['ciphertext_sha256'],
                'metadata_authenticated':False,'database_restored':False,
                'next_step':'Use the reviewed local restore procedure; private recovery key stays local.'}
        evidence=root/'.artifacts/recovery';evidence.mkdir(parents=True,exist_ok=True)
        (evidence/'transport.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation');parser.add_argument('--root',default='.')
    args=parser.parse_args();root=Path(args.root).resolve()
    if os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REF')!='refs/heads/main':
        raise ValueError('operator operations require trusted main')
    if args.operation=='recovery-evidence':recovery(root);return
    operations=json.loads((root/'.github/workflow-operations.json').read_text());spec=operations[args.operation]
    for command in spec['commands']:
        if not isinstance(command,list) or not command or not all(isinstance(x,str) for x in command):raise ValueError('invalid fixed argv command')
        subprocess.run(command,cwd=root,check=True,timeout=spec.get('timeout_seconds',1800))
if __name__=='__main__':main()
