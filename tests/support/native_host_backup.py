#!/usr/bin/env python3
"""Exercise protected capture and bounded encrypted export in the real guest.

The disposable owner's key decrypts only this synthetic data fixture. This is
transport acceptance; PostgreSQL recovery has its own installed-source tests.
"""
import hashlib
import json
from pathlib import Path

from acceptance import ROOT, BINARY, run, write
import fixture_runtime as runtime
import fixture_registry as registry


CAPTURE = b'''#!/usr/bin/python3
import hashlib,json,os,pathlib,subprocess,sys,tempfile
request=json.load(sys.stdin)
assert request['kind']=='komizo.backup-request' and request['version']==1
app=request['application'];instance=request['instance']
assert app=='secretbox' and instance=='production'
root=pathlib.Path('/var/lib/komizo')
installed=json.loads((root/'instances'/f'{app}--{instance}.json').read_text())
assert installed['release_digest']==request['release_digest']==os.environ['KOMIZO_RELEASE_DIGEST']
assert request['operation_id']==os.environ['KOMIZO_OPERATION_ID']
release=json.loads((root/'releases'/(request['release_digest'][7:]+'.json')).read_text())
volume=installed['resources']['volumes']['data']['name']
mount=subprocess.check_output(['podman','--remote=false','volume','inspect',volume,'--format={{.Mountpoint}}'],text=True).strip()
data=(pathlib.Path(mount)/'count').read_bytes()
assert data==b'accepted\\n'
output=pathlib.Path(request['output_directory'])
assert str(output)==os.environ['KOMIZO_OUTPUT_DIRECTORY']
with tempfile.TemporaryDirectory(prefix='native-backup-',dir='/root/native-host') as temporary:
    plaintext=pathlib.Path(temporary)/'plain.json'
    plaintext.write_text(json.dumps({'application':app,'release_digest':request['release_digest'],'count':data.decode()}))
    subprocess.run(['openssl','cms','-encrypt','-binary','-aes-256-cbc','-outform','DER','-in',str(plaintext),'-out',str(output/'snapshot.cms'),'/root/native-host/recipient.crt'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
snapshot=(output/'snapshot.cms').read_bytes()
receipt={'version':1,'ciphertext_sha256':hashlib.sha256(snapshot).hexdigest(),'deployment':{'application':app,'release_digest':request['release_digest'],'source':release['source'],'provider':release.get('providers')}}
(output/'receipt.json').write_text(json.dumps(receipt,sort_keys=True,separators=(',',':')))
for path in output.iterdir():path.chmod(0o600)
'''


def export(app, release, operation, metadata):
    request=runtime.request(app,'export',release,operation=operation,export_name=metadata['name'])
    response=run([BINARY,'submit'],input=registry.canonical(request),ok=False)
    if response.returncode:raise ValueError('protected ciphertext export failed')
    line,separator,body=response.stdout.partition(b'\n')
    if not separator or len(line)>16384:raise ValueError('ciphertext export lacks its bounded typed header')
    header=json.loads(line)
    expected={'kind':'komizo.export','version':1,'application':app,'instance':'production','release_digest':release,
        'operation_id':operation,'export_name':metadata['name'],'size_bytes':metadata['size_bytes'],'sha256':metadata['sha256']}
    if header!=expected or len(body)!=metadata['size_bytes'] or registry.digest(body)!=metadata['sha256']:
        raise ValueError('export framing or ciphertext identity differs from accepted capture')
    return body


def prepare(report):
    app='secretbox';installed=runtime.installed(app);release=installed['release_digest']
    program=ROOT/'capture.py';write(program,CAPTURE,0o700)
    run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(ROOT/'recipient.key'),
        '-out',str(ROOT/'recipient.crt'),'-days','2','-subj','/CN=disposable-native-owner'])
    (ROOT/'recipient.key').chmod(0o600)
    path=Path('/etc/komizo/apps/'+app+'.json');policy=json.loads(path.read_text())
    policy['backup']={'program':str(program),'sha256':registry.digest(CAPTURE),'timeout_seconds':30,'max_export_bytes':1<<20}
    write(path,policy)
    capture=runtime.submit(runtime.request(app,'backup',release))
    if not capture.get('ok') or capture.get('backup',{}).get('status')!='ready':
        raise ValueError('protected encrypted capture did not complete: '+json.dumps(capture))
    metadata=capture['backup']['files']
    if sorted(value['name'] for value in metadata)!=['receipt.json','snapshot.cms']:raise ValueError('capture exported an unexpected file set')
    pair={value['name']:export(app,release,capture['operation_id'],value) for value in metadata}
    receipt=json.loads(pair['receipt.json'])
    if receipt['deployment']['release_digest']!=release or receipt['ciphertext_sha256']!=hashlib.sha256(pair['snapshot.cms']).hexdigest():
        raise ValueError('encrypted pair lost installed source or integrity binding')
    encrypted=ROOT/'synthetic-export.cms';write(encrypted,pair['snapshot.cms'])
    plaintext=run(['openssl','cms','-decrypt','-binary','-inform','DER','-in',str(encrypted),'-inkey',str(ROOT/'recipient.key')]).stdout
    restored=json.loads(plaintext)
    if restored!={'application':app,'release_digest':release,'count':'accepted\n'} or runtime.count(app)!=1:
        raise ValueError('owner-only synthetic encrypted recovery changed original data or source identity')
    unit='komizo-backup-'+capture['operation_id']+'.service'
    properties=run(['systemctl','show',unit,'--property=Slice,KillMode,ActiveState,ExecMainStatus']).stdout.decode().splitlines()
    if set(properties)!={'Slice=komizo-control.slice','KillMode=control-group','ActiveState=inactive','ExecMainStatus=0'}:
        raise ValueError('protected task escaped its finite systemd group or remained active')
    # The deliberately stopped instance must never be started for capture.
    stopped=runtime.submit(runtime.request('mailroom','backup',runtime.installed('mailroom')['release_digest']))
    if stopped.get('ok') is not False or runtime.count('mailroom')!=1:raise ValueError('routine stopped capture changed data or claimed a backup')
    # Absence is asserted against the actual namespace, including orphan data.
    runtime.host_policy('emptybox')
    absent=runtime.submit(runtime.request('emptybox','backup','absent'))
    if not absent.get('ok') or absent.get('backup',{}).get('status')!='absent':raise ValueError('empty namespace absence assertion failed')
    namespace='kmz-'+hashlib.sha256(b'emptybox\0production').hexdigest()[:20]
    orphan=namespace+'-orphan'
    run(['podman','--remote=false','volume','create',orphan])
    try:
        denied=runtime.submit(runtime.request('emptybox','backup','absent'))
        if denied.get('ok') is not False:raise ValueError('orphan data masqueraded as an empty installation')
    finally:run(['podman','--remote=false','volume','rm',orphan])
    report['checks'].update({'protected_encrypted_capture':'passed','exact_export_framing':'passed','encrypted_pair_integrity':'passed',
        'installed_source_backup_binding':'passed','synthetic_owner_decryption':'passed','backup_task_group_deadline':'passed',
        'stopped_backup_refused':'passed','namespace_absence_proof':'passed','orphan_data_absence_refused':'passed'})
