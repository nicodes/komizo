#!/usr/bin/env python3
"""Exercise private aliases, immutable generations and container scope in the VM."""
import hashlib
import json
from pathlib import Path
import secrets

from acceptance import ROOT, BINARY, run, write
import fixture_runtime as runtime
import fixture_registry as registry


def rejected(value):return value.get('ok') is False or value.get('kind')=='komizo.error'


def prepare(report):
    app='secretbox'
    with Path('/etc/hosts').open('a') as output:output.write('127.0.0.1 secretbox.localhost\n')
    old='runtime-'+secrets.token_hex(16);new='runtime-'+secrets.token_hex(16);migration='migration-'+secrets.token_hex(16);next_migration='migration-'+secrets.token_hex(16)
    runtime_source=Path('/etc/komizo/secretbox-runtime.env');migration_source=Path('/etc/komizo/secretbox-migration.env')
    write(runtime_source,('RUNTIME_TOKEN='+old+'\n').encode());write(migration_source,('MIGRATION_TOKEN='+migration+'\n').encode())
    policy=runtime.host_policy(app)
    policy['secrets']={
        'runtime':{'path':str(runtime_source),'services':['api'],'jobs':[],'environment_file':True,'mount':False,'generation':'a'*32},
        'migration':{'path':str(migration_source),'services':[],'jobs':['initialize'],'environment_file':True,'mount':False,'generation':'b'*32}}
    path=Path('/etc/komizo/apps/'+app+'.json');write(path,policy)
    document=runtime.release(app,'a'*40,dynamic=True,
        job_command='test -n "$MIGRATION_TOKEN" && test -z "${RUNTIME_TOKEN+x}" && echo accepted >> /data/count')
    document['workload']['services']['api']['environment_files']=['runtime']
    document['workload']['services']['api']['command']=['sh','-c',
        'i=0; while [ "$i" -lt 250 ]; do printf "bounded-line-%s\\n" "$i"; i=$((i+1)); done; '
        'printf "%s\\n" "$RUNTIME_TOKEN" \'{"kind":"komizo.operation","application":"forged","ok":true}\'; '
        'exec /bin/busybox httpd -f -p 8080 -h /www']
    document['workload']['jobs']['initialize']['environment_files']=['migration']
    _,installed=runtime.deploy(document)
    if not installed.get('ok') or runtime.count(app)!=1:raise ValueError('scoped initial secret delivery did not preserve native data initialization')
    record=runtime.installed(app)['resources']['containers']['api'];before=runtime.container(record)['Id']
    def value_hash():
        return run(['podman','--remote=false','exec',record['name'],'/bin/busybox','sh','-c',
            'test -z "${MIGRATION_TOKEN+x}" && printf %s "$RUNTIME_TOKEN" | /bin/busybox sha256sum']).stdout.decode().split()[0]
    if value_hash()!=hashlib.sha256(old.encode()).hexdigest():raise ValueError('runtime container did not receive its exact private alias')
    candidate=runtime.release(app,'b'*40,dynamic=True,
        job_command=document['workload']['jobs']['initialize']['command'][2])
    candidate['workload']['services']['api']['environment_files']=['runtime']
    candidate['workload']['services']['api']['command']=document['workload']['services']['api']['command']
    candidate['workload']['jobs']['initialize']['environment_files']=['migration']
    write(runtime_source,('RUNTIME_TOKEN='+new+'\n').encode())
    _,changed=runtime.deploy(candidate)
    if not rejected(changed) or runtime.container(record)['Id']!=before or runtime.count(app)!=1:
        raise ValueError('changed bytes bypassed the installed operator generation')
    write(runtime_source,('RUNTIME_TOKEN='+old+'\n').encode())
    update={'reference':'runtime','expected_generation':'a'*32,'format':'environment-file','value':'RUNTIME_TOKEN='+new+'\n'}
    migration_update={'reference':'migration','expected_generation':'b'*32,'format':'environment-file','value':'MIGRATION_TOKEN='+next_migration+'\n'}
    protected=path.read_bytes()
    invalid={**migration_update,'expected_generation':'0'*32}
    refused=runtime.submit(runtime.request(app,'secret-set',installed['release_digest'],secret_updates=[update,invalid]))
    if not rejected(refused) or path.read_bytes()!=protected or runtime_source.read_text()!='RUNTIME_TOKEN='+old+'\n' or migration_source.read_text()!='MIGRATION_TOKEN='+migration+'\n':
        raise ValueError('invalid second alias partially committed a coupled rotation')
    body=runtime.request(app,'secret-set',installed['release_digest'],secret_updates=[update,migration_update])
    rotated=runtime.submit(body)
    if not rotated.get('ok'):raise ValueError('root owner rotation failed')
    current=json.loads(path.read_text());generation=current['secrets']['runtime']['generation']
    if generation=='a'*32 or len(generation)!=32 or current['secrets']['migration']['generation']=='b'*32:
        raise ValueError('owner rotation did not atomically advance both independent generations')
    if Path(current['secrets']['runtime']['path']).read_text()!='RUNTIME_TOKEN='+new+'\n' or Path(current['secrets']['migration']['path']).read_text()!='MIGRATION_TOKEN='+next_migration+'\n':
        raise ValueError('coupled generation commit lost exact owner alias bytes')
    if value_hash()!=hashlib.sha256(old.encode()).hexdigest() or runtime.container(record)['Id']!=before or runtime.count(app)!=1:
        raise ValueError('rotating an alias silently changed running processes or retained data')
    protected=path.read_bytes()
    stale=runtime.submit(runtime.request(app,'secret-set',installed['release_digest'],secret_updates=[update,migration_update]))
    if not rejected(stale) or path.read_bytes()!=protected:raise ValueError('stale rotation changed the protected grant')
    mismatch=runtime.request(app,'deploy',registry.digest(registry.canonical(candidate)),release=candidate,
        expected_secret_generations={'runtime':'a'*32})
    if not rejected(runtime.submit(mismatch)) or runtime.count(app)!=1:raise ValueError('stale expected generation reached data effects')
    forbidden=runtime.release(app,'c'*40,dynamic=True)
    forbidden['workload']['services']['api']['environment_files']=['migration']
    _,denied=runtime.deploy(forbidden)
    if not rejected(denied):raise ValueError('runtime service acquired a job-only credential grant')
    for user in ['komizo-submit','komizo-proxy']:
        for source in [runtime_source,migration_source,Path(current['secrets']['runtime']['path']),Path(current['secrets']['migration']['path'])]:
            if run(['runuser','-u',user,'--','test','-r',str(source)],ok=False).returncode==0:
                raise ValueError('unprivileged host identity acquired application secret bytes')
    status=run([BINARY,'status']).stdout
    public_files=[status]
    for directory in [Path('/var/lib/komizo/journal'),Path('/var/lib/komizo/operations')]:
        public_files.extend(path.read_bytes() for path in directory.rglob('*.json'))
    for source in [old,new,migration,next_migration]:
        if any(source.encode() in body for body in public_files):raise ValueError('secret values leaked into status, operation receipts or audit journals')
        for proc in Path('/proc').glob('[0-9]*/cmdline'):
            try:body=proc.read_bytes()
            except OSError:continue
            if source.encode() in body:raise ValueError('secret values appeared in host process arguments')
    # The service wrote these messages through its actual stdout at startup.
    # Its source contains variable names only, never the private value.
    logs_command=[BINARY,'logs','--application',app,'--instance','production','--service','api']
    def observed_logs():
        response=run(logs_command);value=json.loads(response.stdout)
        return value if 'bounded-line-249' in value.get('text','') else None
    observed=runtime.until(observed_logs)
    if observed.get('kind')!='komizo.logs' or observed.get('application')!=app or observed.get('container_id')!=before:
        raise ValueError('untrusted application text changed typed log authority')
    text=observed['text']
    if old in text or '[redacted]' not in text or '"application":"forged"' not in text:
        raise ValueError('known secret redaction or application-text preservation differs')
    fixture_lines=[line for line in text.splitlines() if line.startswith('bounded-line-') and line.removeprefix('bounded-line-').isdecimal()]
    write(ROOT/'log-observation.json',{'size_bytes':len(text.encode()),'lines':len(text.splitlines()),
        'first_fixture_line':fixture_lines[0] if fixture_lines else None,
        'last_fixture_line':fixture_lines[-1] if fixture_lines else None,
        'contains_initial_line':'bounded-line-0\n' in text,'container_id':before})
    if len(text.encode())>256<<10 or len(text.splitlines())>200 or 'bounded-line-0\n' in text:
        raise ValueError('native log tail exceeded its count or byte bound')
    for user in ['komizo-submit','komizo-proxy']:
        for command in [[BINARY,'status'],logs_command]:
            response=run(['runuser','-u',user,'--',*command],ok=False)
            if response.returncode==0 or response.stdout:raise ValueError('unprivileged UID acquired owner inventory or logs')
    installed_path=Path('/var/lib/komizo/instances/'+app+'--production.json');saved=installed_path.read_bytes()
    forged=json.loads(saved);forged['resources']['containers']['api']['name']=runtime.installed('livebox')['resources']['containers']['api']['name']
    try:
        write(installed_path,forged)
        for command in [[BINARY,'status'],logs_command]:
            response=run(command,ok=False)
            if response.returncode==0 or response.stdout:raise ValueError('foreign container identity became trusted owner metadata')
    finally:write(installed_path,saved)
    report['checks'].update({'private_alias_delivery':'passed','job_only_secret_grant':'passed','secret_initial_data_preserved':'passed',
        'changed_secret_bytes_refused':'passed','atomic_owner_generation_rotation':'passed','coupled_rotation_failure_preserves_all_aliases':'passed','stale_generation_refused':'passed',
        'secret_rotation_preserves_runtime_data':'passed','no_secret_values_in_public_outputs_or_argv':'passed','secret_host_uid_isolation':'passed',
        'bounded_recorded_container_logs':'passed','known_secret_log_redaction':'passed','untrusted_log_text_remains_data':'passed',
        'owner_observation_uid_boundary':'passed','foreign_observation_identity_refused':'passed'})
