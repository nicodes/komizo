#!/usr/bin/env python3
"""Use the real PostgreSQL workload in a separately admitted preview namespace."""
import copy
import hashlib
import json
from pathlib import Path
import secrets
import time
import urllib.request

from acceptance import ROOT, BINARY, run, write, show
import fixture_postgres as postgres
import fixture_registry as registry
import fixture_runtime as runtime


def installed(instance):
    return json.loads(Path('/var/lib/komizo/instances/pgbox--'+instance+'.json').read_text())


def projected(document,instance):
    value=copy.deepcopy(document)
    hostname=instance+'.preview.localhost'
    for route in value['workload']['routes']:route['host']=hostname
    for check in value['workload']['readiness']:check['url']='https://'+hostname+'/'
    return value


def prepare(report):
    # Owner-controlled orphan refusal/repair below must not race the independent
    # periodic expiry service for the same nonblocking instance lock. Exercise
    # that shipped scheduler separately on the final fresh preview.
    if show('komizo-expire.timer','ActiveState')!='active':
        raise ValueError('installed preview expiry timer is not active')
    run(['systemctl','stop','komizo-expire.timer','komizo-expire.service'])
    if any(show(unit,'ActiveState') not in {'inactive','failed'} for unit in ['komizo-expire.timer','komizo-expire.service']):
        raise ValueError('scheduled expiry did not quiesce before the owner-controlled preview fixture')
    instance='pr-7';path=Path('/etc/komizo/apps/pgbox.json');policy=json.loads(path.read_text())
    policy['previews']={'environment':'preview','hostname_suffix':'preview.localhost','max_instances':1,'max_ttl_seconds':120,
        'limits':runtime.limits(192,500,128),'secrets':{'postgres-owner':{'path':'/var/lib/komizo/preview-secrets/pgbox/{instance}/postgres-owner.env',
            'services':['postgres'],'jobs':['initialize'],'environment_file':True,'mount':False,'generation':'b'*32}},
        'readiness':[{'url':'https://{instance}.preview.localhost/','status':200,'contains':postgres.source()['revision']}]}
    write(path,policy)
    for selected in ['pr-7','pr-8']:
        directory=Path('/var/lib/komizo/preview-secrets/pgbox')/selected;directory.mkdir(mode=0o700,parents=True,exist_ok=True);directory.chmod(0o700)
        write(directory/'postgres-owner.env',('PGUSER=fixture\nPGPASSWORD='+secrets.token_hex(24)+'\n').encode())
    with Path('/etc/hosts').open('a') as output:output.write('127.0.0.1 pr-7.preview.localhost pr-8.preview.localhost\n')
    production=runtime.installed('pgbox')
    document=json.loads(Path('/var/lib/komizo/releases/'+production['release_digest'][7:]+'.json').read_text())
    document['workload']['services']['postgres']['limits']['milli_cpus']=200
    document['workload']['services']['api']['limits']['milli_cpus']=100
    preview=projected(document,instance);identity=registry.digest(registry.canonical(preview))
    body=runtime.request('pgbox','deploy',identity,instance=instance,release=preview,ttl_seconds=60,timeout_seconds=180)
    receipt=runtime.submit(body)
    if not receipt.get('ok') or receipt.get('phase')!='ready':raise ValueError('native full PostgreSQL preview failed: '+json.dumps(receipt))
    value=installed(instance);preview_volume=value['resources']['volumes']['postgres-data'];production_volume=production['resources']['volumes']['postgres-data']
    if preview_volume==production_volume or value['resources']['networks']==production['resources']['networks']:
        raise ValueError('preview reused production data or network identity')
    if value['secret_snapshots']['postgres-owner']['sha256']==production['secret_snapshots']['postgres-owner']['sha256']:
        raise ValueError('preview acquired the production credential snapshot')
    if postgres.query('SELECT value FROM evidence',instance)!=b'retained native row':raise ValueError('preview did not initialize its separate database')
    postgres.query("UPDATE evidence SET value='preview-only row'",instance)
    if postgres.query('SELECT value FROM evidence')!=b'retained native row':raise ValueError('preview changed the production database')
    runtime.cross_network_refused('pgbox','pgbox','postgres',5432,source_instance=instance)
    runtime.cross_network_refused('pgbox','pgbox','postgres',5432,target_instance=instance)
    with urllib.request.urlopen('https://pr-7.preview.localhost/',timeout=5) as response:
        if response.headers.get('X-Komizo-Release')!=identity:raise ValueError('preview readiness used production release authority')
    other=projected(document,'pr-8')
    denied=runtime.submit(runtime.request('pgbox','deploy',registry.digest(registry.canonical(other)),instance='pr-8',
        release=other,ttl_seconds=60))
    if denied.get('ok') is not False:raise ValueError('preview maximum admitted another full database instance')
    # Admit the instance count, then make the complete reservation impossible.
    # A reviewed preparation program would write a marker immediately on entry;
    # refusal must precede that credential-effect boundary, not merely roll back
    # its resulting container or reservation afterward.
    saved=path.read_bytes();marker=ROOT/'capacity-prepare-entered'
    if marker.exists():raise ValueError('capacity refusal probe requires a fresh effect marker')
    prepare=ROOT/'capacity-prepare.py'
    program=b'#!/usr/bin/python3\nfrom pathlib import Path\nPath("/root/native-host/capacity-prepare-entered").write_text("entered")\n'
    write(prepare,program,0o700)
    capacity=json.loads(Path('/etc/komizo/capacity.json').read_text())
    allocations=Path('/var/lib/komizo/allocations.json');before=allocations.read_bytes()
    reserved=json.loads(before)['pgbox--pr-7']['memory_reservation_bytes']
    if reserved+policy['previews']['limits']['memory_bytes']<=capacity['previews']['memory_bytes']:
        raise ValueError('preview capacity refusal probe would fit its protected pool')
    credential=Path('/var/lib/komizo/preview-secrets/pgbox/pr-8/postgres-owner.env');credential_before=credential.read_bytes()
    try:
        policy['previews']['max_instances']=2
        policy['previews']['prepare']={'program':str(prepare),'sha256':registry.digest(program),
            'timeout_seconds':30,'max_export_bytes':1<<20,'services':[]}
        write(path,policy)
        refused_capacity=runtime.submit(runtime.request('pgbox','deploy',registry.digest(registry.canonical(other)),
            instance='pr-8',release=other,ttl_seconds=60))
        if (refused_capacity.get('kind')!='komizo.operation' or refused_capacity.get('ok') is not False
                or marker.exists() or credential.read_bytes()!=credential_before or allocations.read_bytes()!=before
                or Path('/var/lib/komizo/preview-prepared/pgbox--pr-8.json').exists()):
            raise ValueError('preview capacity refusal crossed its credential preparation boundary')
        write(ROOT/'capacity-prepare-refusal.json',{'instance':'pr-8','operation_id':refused_capacity['operation_id'],
            'preparation_entered':False,'credential_bytes_unchanged':True,'allocations_unchanged':True})
    finally:write(path,saved)
    unsafe=projected(document,'pr-8');unsafe['workload']['routes'][0]['host']='unapproved.localhost'
    refused=runtime.submit(runtime.request('pgbox','deploy',registry.digest(registry.canonical(unsafe)),instance='pr-8',
        release=unsafe,ttl_seconds=60))
    if refused.get('kind')!='komizo.error':raise ValueError('preview selected an unapproved route hostname')
    # A similarly named but unrecorded object is never included in owned expiry.
    namespace='kmz-'+hashlib.sha256(b'pgbox\0pr-7').hexdigest()[:20]
    foreign='borrowed-'+namespace+'-foreign';orphan=namespace+'-unrecorded'
    for name in [foreign,orphan]:
        if run(['podman','--remote=false','volume','exists',name],ok=False).returncode!=1:
            raise ValueError('preview fixture cannot borrow an existing foreign volume')
        run(['podman','--remote=false','volume','create',name])
    orphan_record=json.loads(run(['podman','--remote=false','volume','inspect',orphan]).stdout)[0]
    report['preview']={'instance':instance,'release_digest':identity,'expires_at':value['expires_at'],
        'volume':preview_volume['name'],'volume_record':preview_volume,'network_names':[record['name'] for record in value['resources']['networks'].values()],
        'production_volume':production_volume['name'],'foreign_volume':foreign,
        'namespace_orphan':orphan,'orphan_created_at':orphan_record['CreatedAt']}
    report['checks'].update({'preview_full_postgresql_namespace':'passed','preview_data_independence':'passed','preview_credential_independence':'passed',
        'preview_protected_readiness':'passed','preview_instance_limit_refused':'passed','preview_hostname_authority':'passed',
        'capacity_refusal_before_preview_credentials':'passed',
        'preview_production_tcp_refused':'passed'})


def expire(report):
    preview=report['preview'];deadline=time.monotonic()+125
    while int(time.time())<=preview['expires_at']:
        if time.monotonic()>deadline:raise ValueError('preview did not reach its bounded real TTL')
        time.sleep(1)
    operations=Path('/var/lib/komizo/operations');before=set(operations.glob('*.json'))
    refused=run([BINARY,'expire'],timeout=60,ok=False)
    if refused.returncode==0 or installed(preview['instance']).get('removed'):
        raise ValueError('unknown reserved-namespace storage was silently treated as absent')
    fresh=set(operations.glob('*.json'))-before
    if len(fresh)!=1:raise ValueError('orphan refusal did not execute one admitted expiry operation')
    operation=json.loads(fresh.pop().read_bytes())
    failure=json.loads((Path('/var/lib/komizo/journal')/operation['operation_id']/'failure.json').read_bytes())
    if (operation.get('application')!='pgbox' or operation.get('instance')!=preview['instance']
            or operation.get('phase')!='needs_reconciliation' or operation.get('ok') is not False
            or 'unreconciled instance resources prevent an absence assertion' not in failure.get('context','')):
        raise ValueError('expiry refused before proving the deliberate unrecorded resource')
    orphan=json.loads(run(['podman','--remote=false','volume','inspect',preview['namespace_orphan']]).stdout)[0]
    if orphan['CreatedAt']!=preview['orphan_created_at']:
        raise ValueError('preview expiry changed an unrecorded namespace volume')
    run(['podman','--remote=false','volume','inspect',preview['foreign_volume']])
    run(['podman','--remote=false','volume','inspect',preview['production_volume']])
    # The fixture owner removes only the orphan it deliberately created. A fresh
    # scoped expiry can then finish; the runtime never deletes unknown storage.
    run(['podman','--remote=false','volume','rm',preview['namespace_orphan']])
    run([BINARY,'expire'],timeout=60)
    value=installed(preview['instance'])
    if not value.get('removed') or value['desired_running'] or value['expires_at'] is not None or value['resources']['volumes']:
        raise ValueError('preview expiry did not remove its recorded ephemeral data')
    if run(['podman','--remote=false','volume','inspect',preview['volume']],ok=False).returncode==0:
        raise ValueError('preview expiry retained an ephemeral owned volume')
    for name in preview['network_names']:
        if run(['podman','--remote=false','network','inspect',name],ok=False).returncode==0:
            raise ValueError('preview expiry retained an owned network')
    run(['podman','--remote=false','volume','inspect',preview['production_volume']])
    run(['podman','--remote=false','volume','inspect',preview['foreign_volume']])
    run(['podman','--remote=false','volume','rm',preview['foreign_volume']])
    report['checks'].update({'preview_real_ttl_expiry':'passed','preview_owned_cleanup':'passed',
        'preview_unknown_namespace_refuses_absence':'passed',
        'preview_cleanup_preserves_foreign_resources':'passed','preview_cleanup_preserves_production_data':'passed'})
    refused=runtime.submit(runtime.request('pgbox','start',preview['release_digest'],instance=preview['instance']))
    if refused.get('ok') or installed(preview['instance'])['resources']['volumes']:
        raise ValueError('Start reanimated a removed preview without a fresh accepted deployment')
    document=json.loads(Path('/var/lib/komizo/releases/'+preview['release_digest'][7:]+'.json').read_text())
    def deploy(selected):
        identity=registry.digest(registry.canonical(selected))
        receipt=runtime.submit(runtime.request('pgbox','deploy',identity,instance=preview['instance'],release=selected,ttl_seconds=60))
        return identity,receipt
    def remove(identity):
        receipt=runtime.submit(runtime.request('pgbox','remove',identity,instance=preview['instance']))
        if not receipt.get('ok') or not installed(preview['instance']).get('removed'):
            raise ValueError('scoped ephemeral removal did not finish: '+json.dumps(receipt))
    identity,fresh=deploy(document)
    if not fresh.get('ok') or fresh.get('phase')!='ready':raise ValueError('fresh accepted preview deployment stayed stopped after TTL: '+json.dumps(fresh))
    regenerated=installed(preview['instance'])
    if regenerated['resources']['volumes']['postgres-data']==preview['volume_record']:
        raise ValueError('preview reopening reused the removed volume fingerprint')
    if postgres.query('SELECT value FROM evidence',preview['instance'])!=b'retained native row' or postgres.query('SELECT count(*) FROM evidence',preview['instance'])!=b'1':
        raise ValueError('preview reopening reused old data or replayed initialization')
    remove(identity)
    failed=json.loads(registry.canonical(document));failed['workload']['jobs']['initialize']['command']=['sh','-ec','exit 7']
    failed_identity,failure=deploy(failed)
    if failure.get('phase')!='needs_reconciliation' or failure.get('ok') is not False:
        raise ValueError('failed preview migration did not record its uncertainty fence')
    remove(failed_identity)
    identity,repaired=deploy(document)
    if not repaired.get('ok') or repaired.get('phase')!='ready' or postgres.query('SELECT count(*) FROM evidence',preview['instance'])!=b'1':
        raise ValueError('scoped failed-preview removal did not release its data and reconciliation fences: '+json.dumps(repaired))
    expires=installed(preview['instance'])['expires_at']
    run(['systemctl','start','komizo-expire.timer'])
    if show('komizo-expire.timer','ActiveState')!='active':
        raise ValueError('shipped preview expiry timer did not resume')
    deadline=time.monotonic()+125
    while not (installed(preview['instance']).get('removed') and show('komizo-expire.service','ActiveState')=='inactive'):
        if time.monotonic()>=deadline:raise ValueError('scheduled preview expiry exceeded its real TTL and timer interval')
        time.sleep(.5)
    removed=installed(preview['instance'])
    if (int(time.time())<expires or removed['desired_running'] or removed['expires_at'] is not None
            or removed['resources']['volumes'] or removed['resources']['networks'] or removed['resources']['containers']):
        raise ValueError('scheduled preview expiry did not remove only the expired owned graph')
    if show('komizo-expire.service','Result')!='success' or show('komizo-expire.service','ExecMainStatus')!='0':
        raise ValueError('scheduled expiry did not complete through the shipped service')
    run(['podman','--remote=false','volume','inspect',preview['production_volume']])
    report['checks'].update({'preview_removed_start_refused':'passed','preview_fresh_graph_after_expiry':'passed',
        'preview_reopen_initialization_once':'passed','failed_preview_scoped_remove':'passed','failed_preview_fresh_redeploy':'passed',
        'preview_scheduled_ttl_expiry':'passed'})
