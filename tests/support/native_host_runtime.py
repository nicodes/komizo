#!/usr/bin/env python3
"""Real native release effects against a private fixture registry inside the VM."""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.request

from acceptance import ROOT, BINARY, MiB, run, write, actual_boundaries, capacity
import fixture_registry as registry


def limits(memory=32,cpu=200,pids=32):
    return {'memory_bytes':memory*MiB,'memory_swap_bytes':memory*MiB,'milli_cpus':cpu,'pids':pids}


def until(check, seconds=30):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            value=check()
            if value:return value
        except (OSError,ValueError,subprocess.SubprocessError):pass
        time.sleep(.2)
    raise ValueError('native runtime fixture deadline expired')


def submit(body):
    value=run([BINARY,'submit'],input=registry.canonical(body),ok=False,timeout=body['timeout_seconds']+35)
    return json.loads(value.stdout)


def request(app,action,identity='current',**fields):
    now=int(time.time())
    return {'kind':'komizo.request','version':1,'authority':'owner','application':app,'instance':'production','action':action,
        'release_digest':identity,'nonce':secrets.token_hex(16),'issued_at':now,'expires_at':now+120,'timeout_seconds':180,**fields}


def installed(app):
    return json.loads(Path('/var/lib/komizo/instances/'+app+'--production.json').read_text())


def fetch(app, release, path='/', *, headers=None):
    body=urllib.request.Request('https://'+app+'.localhost'+path,headers=headers or {})
    with urllib.request.urlopen(body,timeout=5) as response:
        if response.headers.get('X-Komizo-Release')!=release:raise ValueError('public response has another installed source')
        return response.read()


def host_policy(app):
    value={'kind':'komizo.policy','version':1,'application':app,'authority':{'kind':'owner'},
        'artifact_prefixes':['registry.fixture.test:5443/example/'+app+'-'],'hostnames':[app+'.localhost'],
        'limits':limits(96,500,96),'max_image_bytes':64*MiB,'max_asset_bytes':MiB,'max_asset_file_bytes':MiB,
        'startup_memory_bytes':32*MiB}
    write('/etc/komizo/apps/'+app+'.json',value)
    return value


def release(app,revision,*,dynamic=False,unsafe=False,job_command=None,graph=True):
    repo=ROOT/'registry';repo.mkdir(exist_ok=True)
    artifact=registry.image(repo,app,revision) if dynamic else registry.static(repo,app,revision,unsafe=unsafe)
    workload={'services':{},'jobs':{},'assets':{},'networks':{},'volumes':{},'routes':[],
        'readiness':[{'url':'https://'+app+'.localhost/','status':200,'contains':revision}]}
    if dynamic:
        base={'artifact':'api','user':'10001:10001','limits':limits(),'networks':['app'],
            'command':['httpd','-f','-p','8080','-h','/www'],
            'health':{'command':['/bin/busybox','wget','-q','-O-','http://127.0.0.1:8080/'],'interval_seconds':2,'timeout_seconds':2,'retries':3}}
        workload['networks']={'app':{}}
        workload['services']={'db':copy.deepcopy(base),'api':copy.deepcopy(base)}
        workload['services']['api']['needs']={'initialize':'completed'}
        workload['services']['db']['volumes']=[{'name':'data','target':'/data'}]
        workload['volumes']={'data':{}}
        workload['jobs']={'initialize':{'artifact':'api','user':'10001:10001','limits':limits(16,100,16),
            'networks':['app'],'needs':{'db':'healthy'},'timeout_seconds':90,
            'volumes':[{'name':'data','target':'/data'}],
            'command':['sh','-c',job_command or 'echo accepted >> /data/count']}}
        workload['routes']=[{'host':app+'.localhost','path':'/','target':{'kind':'service','name':'api','port':8080}}]
        artifacts={'api':artifact}
        if not graph:
            workload['services']={'api':workload['services']['api']}
            workload['services']['api']['needs']={}
            workload['jobs']={};workload['volumes']={}
    else:
        artifacts={'web':artifact};workload['assets']={'web':{'artifact':'web','serving':{}}}
        workload['routes']=[{'host':app+'.localhost','path':'/','target':{'kind':'asset','name':'web'}}]
    return {'kind':'komizo.release','version':1,'application':app,'source':{'repository':'example/'+app,'repository_id':'123','revision':revision},
        'artifacts':artifacts,'workload':workload}


def deploy(document,*,seconds=180):
    body=request(document['application'],'deploy',registry.digest(registry.canonical(document)),release=document,timeout_seconds=seconds)
    result=submit(body)
    return body,result


def setup_registry():
    hosts='127.0.0.1 registry.fixture.test staticbox.localhost mailroom.localhost livebox.localhost badjob.localhost hungjob.localhost deadline.localhost unsafe.localhost warmup.localhost\n'
    with Path('/etc/hosts').open('a') as stream:stream.write(hosts)
    warm=ROOT/'warmup.Caddyfile'
    warm.write_text('{\n admin off\n storage file_system /var/lib/komizo-proxy/data\n auto_https disable_redirects\n}\nwarmup.localhost:9443 {\n tls internal\n respond 200\n}\n');warm.chmod(0o644)
    # Public configuration is copied outside root's private fixture directory.
    public=Path('/etc/komizo-proxy/warmup.Caddyfile');public.write_bytes(warm.read_bytes());public.chmod(0o644)
    run(['systemd-run','--unit=native-fixture-pki','--uid=komizo-proxy','--gid=komizo-proxy','--property=MemoryMax=128M',
        '--property=TasksMax=64','/usr/local/bin/caddy','run','--config',str(public),'--adapter','caddyfile'])
    ca=Path('/var/lib/komizo-proxy/data/pki/authorities/local/root.crt')
    until(lambda:ca.is_file())
    run(['systemctl','stop','native-fixture-pki.service'])
    trust=Path('/usr/local/share/ca-certificates/komizo-native-fixture.crt');trust.write_bytes(ca.read_bytes())
    run(['update-ca-certificates'])
    key=ROOT/'registry.key';csr=ROOT/'registry.csr';certificate=ROOT/'registry.crt';extension=ROOT/'registry.extensions'
    extension.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:registry.fixture.test\n')
    run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(csr),'-subj','/CN=registry.fixture.test'])
    run(['openssl','x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey','/var/lib/komizo-proxy/data/pki/authorities/local/root.key',
        '-CAcreateserial','-out',str(certificate),'-days','2','-extfile',str(extension)])
    key.chmod(0o600)
    (ROOT/'registry').mkdir(exist_ok=True)
    run(['systemd-run','--unit=native-fixture-registry','--property=MemoryMax=128M','--property=TasksMax=64',
        '/usr/bin/python3',str(ROOT/'fixture_registry.py'),'--root',str(ROOT/'registry'),'--cert',str(certificate),'--key',str(key)])
    def ready():
        try:urllib.request.urlopen('https://registry.fixture.test:5443/v2/',timeout=2)
        except urllib.error.HTTPError as error:return error.code==404
    until(ready)


def count(app):
    record=installed(app)['resources']['volumes']['data']
    path=run(['podman','--remote=false','volume','inspect',record['name'],'--format={{.Mountpoint}}']).stdout.decode().strip()
    return len((Path(path)/'count').read_text().splitlines())


def prepare():
    setup_registry()
    for app in ['staticbox','mailroom','livebox','badjob','hungjob','deadline','unsafe']:host_policy(app)
    static=release('staticbox','a'*40)
    body,result=deploy(static)
    if result.get('phase')!='ready' or not result.get('ok'):raise ValueError('actual static archive release failed: '+json.dumps(result))
    if b'a'*40 not in fetch('staticbox',result['release_digest']):raise ValueError('static source bytes differ')
    app=release('mailroom','a'*40,dynamic=True)
    mutation,ready=deploy(app)
    if ready.get('phase')!='ready' or not ready.get('ok'):raise ValueError('actual API/job release failed: '+json.dumps(ready))
    if b'a'*40 not in fetch('mailroom',ready['release_digest']) or count('mailroom')!=1:raise ValueError('DAG did not execute once against the retained data')
    forged=fetch('mailroom',ready['release_digest'],'/cgi-bin/who',headers={'X-Forwarded-For':'203.0.113.29'})
    if b'203.0.113.29' in forged:raise ValueError('untrusted forwarded client IP reached the application')
    if submit(mutation).get('kind')!='komizo.error' or count('mailroom')!=1:raise ValueError('accepted mutation replay executed again')
    _,live=deploy(release('livebox','a'*40,dynamic=True,graph=False))
    if not live.get('ok'):raise ValueError('independent supervised service did not activate')
    records=installed('mailroom')['resources']['containers'];before={name:value['id'] for name,value in records.items()}
    api=records['api']['name'];db=records['db']['name']
    run(['podman','--remote=false','exec',api,'/bin/busybox','nslookup',db])
    run(['systemctl','kill','--signal=KILL','--kill-whom=main','komizo-controller.service'])
    until(lambda:run(['systemctl','is-active','komizo-controller.service'],ok=False).stdout.strip()==b'active')
    if before!={name:value['id'] for name,value in installed('mailroom')['resources']['containers'].items()}:
        raise ValueError('controller death replaced supervised application containers')
    run(['podman','--remote=false','exec',api,'/bin/busybox','nslookup',db])
    fetch('mailroom',ready['release_digest'])
    stop=submit(request('mailroom','stop',ready['release_digest']))
    if stop.get('phase')!='prepared_stopped':raise ValueError('stop intent was not retained')
    next_release=release('mailroom','b'*40,dynamic=True)
    _,prepared=deploy(next_release)
    if prepared.get('phase')!='prepared_stopped' or count('mailroom')!=1:raise ValueError('stopped preparation executed jobs or changed retained data')
    if installed('mailroom')['release_digest']!=ready['release_digest']:raise ValueError('prepared candidate silently replaced installed identity')
    run(['systemctl','stop','native-fixture-registry.service'])
    report=json.loads((ROOT/'report.json').read_text())
    report['checks'].update({'static_archive':'passed','service_job_dag':'passed','mutation_replay':'passed',
        'source_bound_https':'passed','forwarded_ip_refused':'passed','controller_death':'passed',
        'dns_after_controller_death':'passed','stopped_candidate_no_jobs':'passed'})
    report['runtime_acceptance']=False
    report['remaining']=['failed/interrupted jobs','end-to-end deadline','unsafe archive','protected backup/export','complete resource stress']
    report['installed']={'static':result['release_digest'],'mailroom':ready['release_digest'],'prepared':prepared['release_digest'],
        'running':live['release_digest'],'containers':before}
    write(ROOT/'report.json',report)


def verify_reboot():
    report=json.loads((ROOT/'report.json').read_text());accepted=report['installed']
    if run(['systemctl','is-active','native-fixture-registry.service'],ok=False).stdout.strip()==b'active':raise ValueError('fixture registry must remain offline after reboot')
    if b'a'*40 not in fetch('staticbox',accepted['static']):raise ValueError('static release did not survive offline reboot')
    until(lambda:b'a'*40 in fetch('livebox',accepted['running']),seconds=60)
    record=installed('mailroom')
    if record['desired_running'] or count('mailroom')!=1:raise ValueError('stopped data or intent changed during real reboot')
    for container in record['resources']['containers'].values():
        info=run(['podman','--remote=false','container','inspect',container['name']],ok=False)
        if info.returncode==0 and json.loads(info.stdout)[0]['State']['Running']:raise ValueError('stopped application ran after real reboot')
    report['checks']['registry_offline_reboot']='passed';report['checks']['stopped_reboot_no_replay']='passed'
    write(ROOT/'report.json',report)
