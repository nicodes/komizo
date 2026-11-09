#!/usr/bin/env python3
"""Exercise protected capture and bounded encrypted export in the real guest.

The disposable owner's private key stays outside the capture host. Database
restoration and product application journeys remain separately scoped proofs.
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
assert app in {'secretbox','pgbox'} and instance=='production'
root=pathlib.Path('/var/lib/komizo')
installed=json.loads((root/'instances'/f'{app}--{instance}.json').read_text())
assert installed['release_digest']==request['release_digest']==os.environ['KOMIZO_RELEASE_DIGEST']
assert request['operation_id']==os.environ['KOMIZO_OPERATION_ID']
release=json.loads((root/'releases'/(request['release_digest'][7:]+'.json')).read_text())
service='postgres' if app=='pgbox' else 'db'
resource=json.loads(subprocess.check_output(['/usr/local/bin/komizo-box','resource','--application',app,'--instance',instance,'--service',service]))
assert resource['release_digest']==request['release_digest'] and resource['deployment']['release']==release
if app=='pgbox':
    data=subprocess.check_output(['podman','--remote=false','exec',resource['container_name'],'pg_dump','--host=127.0.0.1','--username=fixture','--dbname=postgres','--format=custom'])
    assert data.startswith(b'PGDMP') and len(data)<1048576
else:
    volume=resource['volumes']['data']['name']
    mount=subprocess.check_output(['podman','--remote=false','volume','inspect',volume,'--format={{.Mountpoint}}'],text=True).strip()
    count=(pathlib.Path(mount)/'count').read_bytes()
    assert count==b'accepted\\n'
    data=json.dumps({'application':app,'release_digest':request['release_digest'],'count':count.decode()}).encode()
output=pathlib.Path(request['output_directory'])
assert str(output)==os.environ['KOMIZO_OUTPUT_DIRECTORY']
with tempfile.TemporaryDirectory(prefix='native-backup-',dir='/root/native-host') as temporary:
    plaintext=pathlib.Path(temporary)/'plain.json'
    plaintext.write_bytes(data)
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


def capture(app,report,format):
    installed=runtime.installed(app);release=installed['release_digest']
    program=ROOT/'capture.py';write(program,CAPTURE,0o700)
    if not (ROOT/'recipient.crt').is_file() or (ROOT/'recipient.key').exists():
        raise ValueError('capture host must receive only the owner public recipient certificate')
    path=Path('/etc/komizo/apps/'+app+'.json');policy=json.loads(path.read_text())
    policy['backup']={'program':str(program),'sha256':registry.digest(CAPTURE),'timeout_seconds':30,'max_export_bytes':1<<20,'services':['postgres' if app=='pgbox' else 'db']}
    write(path,policy)
    capture=runtime.submit(runtime.request(app,'backup',release))
    if (not capture.get('ok') or capture.get('backup',{}).get('status')!='ready'
            or capture['backup'].get('release_digest')!=release):
        raise ValueError('protected encrypted capture did not complete: '+json.dumps(capture))
    metadata=capture['backup']['files']
    if sorted(value['name'] for value in metadata)!=['receipt.json','snapshot.cms']:raise ValueError('capture exported an unexpected file set')
    pair={value['name']:export(app,release,capture['operation_id'],value) for value in metadata}
    receipt=json.loads(pair['receipt.json'])
    if receipt['deployment']['release_digest']!=release or receipt['ciphertext_sha256']!=hashlib.sha256(pair['snapshot.cms']).hexdigest():
        raise ValueError('encrypted pair lost installed source or integrity binding')
    report.setdefault('owner_exports',[]).append({'application':app,'instance':'production','release_digest':release,
        'operation_id':capture['operation_id'],'files':metadata,'format':format})
    unit='komizo-backup-'+capture['operation_id']+'.service'
    properties=run(['systemctl','show',unit,'--property=Slice,KillMode,ActiveState,ExecMainStatus']).stdout.decode().splitlines()
    if set(properties)!={'Slice=komizo-control.slice','KillMode=control-group','ActiveState=inactive','ExecMainStatus=0'}:
        raise ValueError('protected task escaped its finite systemd group or remained active')
    return capture


def capture_postgres(report):
    import fixture_postgres
    capture('pgbox',report,'postgresql-custom')
    if fixture_postgres.query('SELECT value FROM evidence')!=b'retained native row':raise ValueError('PostgreSQL capture changed initialized rows')
    report['checks']['protected_postgresql_encrypted_capture']='passed'


def prepare(report):
    capture('secretbox',report,'synthetic-volume-json')
    if runtime.count('secretbox')!=1:raise ValueError('protected capture changed retained data')
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
        'installed_source_backup_binding':'passed','capture_host_has_no_recovery_private_key':'passed','backup_task_group_deadline':'passed',
        'stopped_backup_refused':'passed','namespace_absence_proof':'passed','orphan_data_absence_refused':'passed'})
