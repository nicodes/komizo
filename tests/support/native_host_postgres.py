#!/usr/bin/env python3
"""Exercise the real immutable PostgreSQL base through native host admission."""
import copy
import hashlib
import json
from pathlib import Path
import secrets
import tarfile

from acceptance import ROOT, MiB, run, write
import fixture_registry as registry
import fixture_runtime as runtime

BASE='docker.io/library/postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
REVISION='a'*40


def postgres_artifact():
    context=ROOT/'postgres-build';context.mkdir(mode=0o700)
    (context/'Containerfile').write_text('FROM '+BASE+'\nLABEL org.opencontainers.image.source="https://github.com/example/pgbox" org.opencontainers.image.revision="'+REVISION+'"\n')
    run(['podman','--remote=false','pull',BASE],timeout=300)
    tag='localhost/native-pgbox:'+REVISION
    run(['podman','--remote=false','build','--format=oci','--layers=false','--pull=never','--network=none',
        '--file',str(context/'Containerfile'),'--tag',tag,str(context)],timeout=180)
    # The fixture adds source labels only; compare complete functional config
    # and ordered RootFS to the immutable upstream image before accepting it.
    base,wrapped=json.loads(run(['podman','--remote=false','image','inspect',BASE,tag]).stdout)
    left=copy.deepcopy(base['Config']);right=copy.deepcopy(wrapped['Config'])
    left.pop('Labels',None);right.pop('Labels',None)
    if left!=right or base['RootFS']!=wrapped['RootFS']:raise ValueError('source-label wrapper changed the PostgreSQL runtime')
    archive=ROOT/'postgres.oci.tar'
    run(['podman','--remote=false','save','--format=oci-archive','--output',str(archive),tag],timeout=180)
    blobroot=ROOT/'registry'/'blobs'
    with tarfile.open(archive,'r:') as package:
        descriptors=json.load(package.extractfile('index.json'))['manifests']
        if len(descriptors)!=1:raise ValueError('PostgreSQL fixture archive has ambiguous manifests')
        descriptor=descriptors[0]
        for member in package.getmembers():
            if not member.name.startswith('blobs/sha256/') or not member.isfile():continue
            identity=member.name.removeprefix('blobs/sha256/')
            target=blobroot/identity;source=package.extractfile(member);value=hashlib.sha256();size=0
            with target.open('wb') as output:
                while body:=source.read(1<<16):value.update(body);size+=len(body);output.write(body)
            if value.hexdigest()!=identity or size!=member.size:raise ValueError('PostgreSQL fixture archive blob changed')
        manifest=json.loads((blobroot/descriptor['digest'][7:]).read_bytes())
        config=json.loads((blobroot/manifest['config']['digest'][7:]).read_bytes())
        if config['os']!='linux' or config['architecture']!='amd64':raise ValueError('PostgreSQL fixture platform differs')
    archive.unlink()
    # Resolve the pinned image's actual postgres UID; there is no root workload.
    uid=run(['podman','--remote=false','run','--rm','--network=none','--read-only','--memory=64m','--pids-limit=32',
        '--entrypoint=id',tag,'-u','postgres']).stdout.decode().strip()
    gid=run(['podman','--remote=false','run','--rm','--network=none','--read-only','--memory=64m','--pids-limit=32',
        '--entrypoint=id',tag,'-g','postgres']).stdout.decode().strip()
    if not uid.isdecimal() or not gid.isdecimal() or int(uid)==0:raise ValueError('PostgreSQL fixture has no explicit unprivileged identity')
    return {'kind':'image','reference':'registry.fixture.test:5443/example/pgbox-postgres@'+descriptor['digest'],
        'digest':descriptor['digest'],'config_digest':manifest['config']['digest'],'platform':'linux/amd64'},uid+':'+gid


def query(sql):
    name=runtime.installed('pgbox')['resources']['containers']['postgres']['name']
    return run(['podman','--remote=false','exec',name,'psql','--host=127.0.0.1','--username=fixture','--dbname=postgres',
        '--no-psqlrc','--tuples-only','--no-align','--set=ON_ERROR_STOP=1','--command',sql]).stdout.strip()


def prepare(report):
    with Path('/etc/hosts').open('a') as output:output.write('127.0.0.1 pgbox.localhost\n')
    artifact,user=postgres_artifact();password=secrets.token_hex(24)
    alias=Path('/etc/komizo/pgbox-owner.env');write(alias,('PGUSER=fixture\nPGPASSWORD='+password+'\n').encode())
    policy=runtime.host_policy('pgbox');policy['limits']=runtime.limits(192,700,128);policy['max_image_bytes']=768*MiB
    policy['secrets']={'postgres-owner':{'path':str(alias),'services':['postgres'],'jobs':['initialize'],
        'environment_file':True,'mount':False,'generation':'a'*32}}
    write('/etc/komizo/apps/pgbox.json',policy)
    release=runtime.release('pgbox',REVISION,dynamic=True,graph=False)
    release['artifacts']['postgres']=artifact
    workload=release['workload'];workload['volumes']={'postgres-data':{}}
    workload['services']['postgres']={'artifact':'postgres','user':user,'limits':runtime.limits(128,300,64),
        'networks':['app'],'environment_files':['postgres-owner'],'environment':{'PGDATA':'/data/pg'},
        'volumes':[{'name':'postgres-data','target':'/data'}],
        'tmpfs':{'/tmp':{'size_bytes':16*MiB,'mode':0o1777}},
        'command':['sh','-ec','if [ ! -e "$PGDATA/PG_VERSION" ]; then printf %s "$PGPASSWORD" > /tmp/owner-password; initdb -D "$PGDATA" -U "$PGUSER" --pwfile=/tmp/owner-password --auth-local=trust --auth-host=scram-sha-256; rm /tmp/owner-password; fi; exec postgres -D "$PGDATA" -h 0.0.0.0 -c unix_socket_directories=/tmp -c shared_buffers=8MB -c max_connections=8 -c max_locks_per_transaction=16'],
        'health':{'command':['pg_isready','-h','127.0.0.1','-U','fixture','-d','postgres'],'interval_seconds':2,'timeout_seconds':2,'retries':30,'start_period_seconds':30}}
    workload['jobs']={'initialize':{'artifact':'postgres','user':user,'limits':runtime.limits(32,100,32),
        'networks':['app'],'environment_files':['postgres-owner'],'needs':{'postgres':'healthy'},'timeout_seconds':45,
        'command':['psql','-h','postgres','-U','fixture','-d','postgres','--no-psqlrc','--set=ON_ERROR_STOP=1',
            '--command',"CREATE TABLE evidence(value text NOT NULL); INSERT INTO evidence VALUES ('retained native row');"]}}
    workload['services']['api']['needs']={'initialize':'completed'}
    _,receipt=runtime.deploy(release,seconds=300)
    if not receipt.get('ok') or query('SELECT value FROM evidence')!=b'retained native row':
        raise ValueError('real PostgreSQL native DAG did not retain its initialized row: '+json.dumps(receipt))
    runtime.fetch('pgbox',receipt['release_digest'])
    role=query("SELECT rolpassword FROM pg_authid WHERE rolname='fixture'")
    old_record=runtime.installed('pgbox');before=runtime.container(old_record['resources']['containers']['postgres'])['Id']
    new_password=secrets.token_hex(24)
    update={'reference':'postgres-owner','expected_generation':'a'*32,'format':'environment-file',
        'value':'PGUSER=fixture\nPGPASSWORD='+new_password+'\n'}
    rotated=runtime.submit(runtime.request('pgbox','secret-set',receipt['release_digest'],secret_update=update))
    if not rotated.get('ok') or query("SELECT rolpassword FROM pg_authid WHERE rolname='fixture'")!=role or query('SELECT count(*) FROM evidence')!=b'1':
        raise ValueError('host alias provisioning changed initialized PostgreSQL credentials or rows')
    if runtime.container(old_record['resources']['containers']['postgres'])['Id']!=before:
        raise ValueError('owner alias rotation silently restarted PostgreSQL')
    stopped=runtime.submit(runtime.request('pgbox','stop',receipt['release_digest']))
    if stopped.get('phase')!='prepared_stopped':raise ValueError('real PostgreSQL stop intent was not preserved')
    report['postgres']={'release_digest':receipt['release_digest'],'base_reference':BASE,'image':artifact['config_digest']}
    report['checks'].update({'real_postgresql_api_dag':'passed','immutable_postgresql_base':'passed',
        'postgresql_rows_preserved_by_secret_rotation':'passed','initialized_postgresql_credentials_unchanged':'passed'})


def verify_reboot(report):
    installed=runtime.installed('pgbox');expected=report['postgres']['release_digest']
    if installed['desired_running'] or installed['release_digest']!=expected:raise ValueError('PostgreSQL stop intent changed at boot')
    for value in installed['resources']['containers'].values():
        observed=run(['podman','--remote=false','container','inspect',value['name']],ok=False)
        if observed.returncode==0 and json.loads(observed.stdout)[0]['State']['Running']:raise ValueError('stopped PostgreSQL ran at boot')
    # Release this synthetic app's reservation before starting the independent
    # PostgreSQL fixture. This test does not assert a small production host fit.
    secret=runtime.installed('secretbox')
    if not runtime.submit(runtime.request('secretbox','stop',secret['release_digest'])).get('ok'):
        raise ValueError('could not release the synthetic secret fixture reservation')
    started=runtime.submit(runtime.request('pgbox','start',expected))
    if not started.get('ok') or query('SELECT value FROM evidence')!=b'retained native row' or query('SELECT count(*) FROM evidence')!=b'1':
        raise ValueError('offline owner restart lost PostgreSQL data or replayed initialization')
    runtime.fetch('pgbox',expected)
    stopped=runtime.submit(runtime.request('pgbox','stop',expected))
    if stopped.get('phase')!='prepared_stopped':raise ValueError('PostgreSQL owner restart did not restore deliberate stop')
    report['checks'].update({'postgresql_offline_reboot_stop_intent':'passed','postgresql_offline_owner_restart':'passed',
        'postgresql_initialization_not_replayed':'passed','postgresql_retained_rows_after_reboot':'passed'})
