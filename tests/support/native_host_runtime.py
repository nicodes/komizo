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


def container(record):
    return json.loads(run(['podman','--remote=false','container','inspect',record['name']]).stdout)[0]


def application_limits(app):
    record=installed(app)['resources']['containers']['api'];actual=container(record)
    pid=actual['State']['Pid']
    fields=dict(line.split(':',1) for line in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in line)
    if set(map(int,fields['Uid'].split()))!={10001} or int(fields['CapEff'].strip(),16):
        raise ValueError('actual application UID or capabilities exceed the release')
    group=next(line[3:] for line in Path('/proc/'+str(pid)+'/cgroup').read_text().splitlines() if line.startswith('0::'))
    path=Path('/sys/fs/cgroup')/group.removeprefix('/')
    while (path/'memory.max').read_text().strip()=='max':path=path.parent
    if (path/'memory.max').read_text().strip()!=str(32*MiB) or (path/'memory.swap.max').read_text().strip()!='0':
        raise ValueError('actual application memory/swap enforcement differs')
    if (path/'pids.max').read_text().strip()!='32':raise ValueError('actual application PID enforcement differs')
    quota,period=map(int,(path/'cpu.max').read_text().split())
    if quota*1000!=200*period:raise ValueError('actual application CPU enforcement differs')
    denied=run(['podman','--remote=false','exec','--user=0',record['name'],'/bin/busybox','touch','/unexpected-write'],ok=False)
    if denied.returncode==0 or b'Read-only file system' not in denied.stderr:raise ValueError('application root filesystem permits writes')
    if actual['HostConfig'].get('PortBindings'):raise ValueError('application published host ports')


def failures(report):
    bad=release('badjob','a'*40,dynamic=True,job_command='echo accepted >> /data/count; exit 7')
    _,result=deploy(bad)
    if result.get('phase')!='needs_reconciliation' or result.get('ok') is not False or count('badjob')!=1:
        raise ValueError('failed data job was not durably fenced')
    _,refused=deploy(bad)
    if refused.get('kind')!='komizo.error' or count('badjob')!=1:raise ValueError('failed data job was replayed')
    hanging=release('hungjob','a'*40,dynamic=True,job_command='echo accepted >> /data/count; /bin/busybox sleep 600')
    body=request('hungjob','deploy',registry.digest(registry.canonical(hanging)),release=hanging)
    child=subprocess.Popen([BINARY,'submit'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    child.stdin.write(registry.canonical(body));child.stdin.close()
    try:
        def running():
            return any(json.loads(path.read_text()).get('phase')=='running' for path in Path('/var/lib/komizo/jobs').rglob('*.json')
                if json.loads(path.read_text()).get('application')=='hungjob')
        until(running,seconds=60)
        run(['systemctl','kill','--signal=KILL','--kill-whom=main','komizo-controller.service'])
        until(lambda:run(['systemctl','is-active','komizo-controller.service'],ok=False).stdout.strip()==b'active')
        operation=hashlib.sha256(('komizo-operation-v1\0hungjob\0production\0'+body['nonce']).encode()).hexdigest()[:32]
        observed=submit(request('hungjob','inspect',body['release_digest'],operation=operation))
        if observed.get('phase')!='needs_reconciliation' or count('hungjob')!=1:raise ValueError('interrupted data job lost its durable uncertainty fence')
        _,refused=deploy(hanging)
        if refused.get('kind')!='komizo.error' or count('hungjob')!=1:raise ValueError('interrupted data job was replayed')
    finally:
        try:child.wait(timeout=10)
        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        child.stdout.close();child.stderr.close()
    deadline=release('deadline','a'*40,dynamic=True,job_command='/bin/busybox sleep 600')
    started=time.monotonic();_,bounded=deploy(deadline,seconds=8)
    if time.monotonic()-started>40 or bounded.get('ok') is not False:raise ValueError('admitted worker exceeded its original end-to-end deadline')
    _,unsafe=deploy(release('unsafe','a'*40,unsafe=True))
    if unsafe.get('phase')!='failed' or unsafe.get('ok') is not False:raise ValueError('unsafe archive reached activation')
    report['checks'].update({'failed_job_no_replay':'passed','interrupted_job_no_replay':'passed','worker_deadline':'passed','unsafe_archive':'passed'})


def resource_stress(report):
    app='livebox';record=installed(app)['resources']['containers']['api']
    namespace=hashlib.sha256(b'livebox\0production').hexdigest()[:20]
    unit='komizo-production-i'+namespace+'.slice'
    group=run(['systemctl','show',unit,'--property=ControlGroup','--value']).stdout.decode().strip()
    path=Path('/sys/fs/cgroup')/group.removeprefix('/')
    def event(file,key):return int(dict(line.split() for line in (path/file).read_text().splitlines())[key])
    previous=event('pids.events','max')
    # Sleeping children have a finite lifetime even when the shell cannot fork
    # another process. The stress stays below this application's PID ceiling.
    run(['podman','--remote=false','exec',record['name'],'/bin/busybox','sh','-c',
        'i=0; while [ "$i" -lt 80 ]; do /bin/busybox sleep 2 & i=$((i+1)); done; wait'],ok=False,timeout=20)
    if event('pids.events','max')<=previous:raise ValueError('actual application PID ceiling did not refuse excess children')
    previous=event('memory.events','oom_kill')
    result=run(['podman','--remote=false','exec',record['name'],'/bin/busybox','awk',
        'BEGIN {x="0123456789"; for (i=0;i<9;i++) x=x x; while (1) a[++n]=x n}'],ok=False,timeout=30)
    if result.returncode==0 or event('memory.events','oom_kill')<=previous:
        raise ValueError('actual application memory ceiling did not isolate excess allocation')
    until(lambda:b'a'*40 in fetch(app,installed(app)['release_digest']),seconds=30)
    fetch('staticbox',installed('staticbox')['release_digest'])
    prior=Path('/var/lib/komizo/instances/livebox--production.json').read_bytes()
    candidate=release(app,'b'*40,dynamic=True,graph=False)
    candidate['workload']['services']['api']['limits']=limits(128)
    _,denied=deploy(candidate)
    if denied.get('kind')!='komizo.error' or Path('/var/lib/komizo/instances/livebox--production.json').read_bytes()!=prior:
        raise ValueError('oversized release reached installation effects')
    report['checks'].update({'application_pid_stress':'passed','application_memory_stress':'passed',
        'other_application_survives_stress':'passed','oversized_release_refused_before_effects':'passed'})


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
    application_limits('mailroom')
    forged=fetch('mailroom',ready['release_digest'],'/cgi-bin/who',headers={'X-Forwarded-For':'203.0.113.29'})
    if b'203.0.113.29' in forged:raise ValueError('untrusted forwarded client IP reached the application')
    if submit(mutation).get('kind')!='komizo.error' or count('mailroom')!=1:raise ValueError('accepted mutation replay executed again')
    _,live=deploy(release('livebox','a'*40,dynamic=True,graph=False))
    if not live.get('ok'):raise ValueError('independent supervised service did not activate')
    records=installed('mailroom')['resources']['containers'];before={name:container(value)['Id'] for name,value in records.items()}
    api=records['api']['name'];db=records['db']['name']
    run(['podman','--remote=false','exec',api,'/bin/busybox','nslookup',db])
    run(['systemctl','kill','--signal=KILL','--kill-whom=main','komizo-controller.service'])
    until(lambda:run(['systemctl','is-active','komizo-controller.service'],ok=False).stdout.strip()==b'active')
    if before!={name:container(value)['Id'] for name,value in installed('mailroom')['resources']['containers'].items()}:
        raise ValueError('controller death replaced supervised application containers')
    run(['podman','--remote=false','exec',api,'/bin/busybox','nslookup',db])
    fetch('mailroom',ready['release_digest'])
    stop=submit(request('mailroom','stop',ready['release_digest']))
    if stop.get('phase')!='prepared_stopped':raise ValueError('stop intent was not retained')
    live_api=installed('livebox')['resources']['containers']['api']['name']
    run(['podman','--remote=false','exec',live_api,'/bin/busybox','nslookup',live_api])
    next_release=release('mailroom','b'*40,dynamic=True)
    _,prepared=deploy(next_release)
    if prepared.get('phase')!='prepared_stopped' or count('mailroom')!=1:raise ValueError('stopped preparation executed jobs or changed retained data')
    if installed('mailroom')['release_digest']!=ready['release_digest']:raise ValueError('prepared candidate silently replaced installed identity')
    report=json.loads((ROOT/'report.json').read_text())
    report['checks'].update({'static_archive':'passed','service_job_dag':'passed','mutation_replay':'passed',
        'source_bound_https':'passed','forwarded_ip_refused':'passed','controller_death':'passed',
        'dns_after_controller_death':'passed','dns_after_other_application_stop':'passed','stopped_candidate_no_jobs':'passed','application_kernel_limits':'passed',
        'application_uid_capabilities':'passed','application_read_only_root':'passed','no_published_application_ports':'passed'})
    failures(report)
    import fixture_secrets
    fixture_secrets.prepare(report)
    import fixture_backup
    fixture_backup.prepare(report)
    resource_stress(report)
    run(['systemctl','stop','native-fixture-registry.service'])
    report['runtime_acceptance']=False
    report['remaining']=['real PostgreSQL initialized-data and recovery controls']
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
    if 'failed_job_no_replay' in report['checks']:
        for application in ['badjob','hungjob']:
            if count(application)!=1:raise ValueError('data job replayed during a real reboot')
            record=installed(application)['resources']['containers']['api']
            info=run(['podman','--remote=false','container','inspect',record['name']],ok=False)
            if info.returncode==0 and json.loads(info.stdout)[0]['State']['Running']:
                raise ValueError('API bypassed its failed or interrupted job dependency during reboot')
        report['checks']['uncertain_job_reboot_no_replay']='passed'
    report['checks']['registry_offline_reboot']='passed';report['checks']['stopped_reboot_no_replay']='passed'
    write(ROOT/'report.json',report)
