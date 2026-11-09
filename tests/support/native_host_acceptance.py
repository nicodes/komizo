#!/usr/bin/env python3
"""Assert the native host boundary from inside the disposable Debian guest."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

ROOT = Path('/root/native-host')
BINARY = '/usr/local/bin/komizo-box'
CONTROLLER = 'komizo-controller.service'
PROXY = 'komizo-proxy.service'
MiB = 1 << 20


def run(argv, *, ok=True, **options):
    result = subprocess.run(argv, timeout=options.pop('timeout', 60), capture_output=True,
        env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8'}, **options)
    if ok and result.returncode:
        raise ValueError('native acceptance command failed: ' + argv[0] + '\n' + result.stderr.decode(errors='replace')[-2048:])
    return result


def write(path, value, mode=0o600):
    path = Path(path)
    body = json.dumps(value, sort_keys=True, separators=(',', ':')).encode() if not isinstance(value, bytes) else value
    with path.open('wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(body)


def show(unit, field):
    return run(['systemctl','show',unit,'--property='+field,'--value']).stdout.decode().strip()


def capacity():
    physical = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:'))) * 1024
    cpus = len(os.sched_getaffinity(0)) * 1000
    def limits(memory, cpu, pids):return {'memory_bytes':memory*MiB,'memory_swap_bytes':memory*MiB,'milli_cpus':cpu,'pids':pids}
    def infrastructure(memory, low, cpu, pids):
        return {'limits':limits(memory,cpu,pids),'controls':{'memory_low_bytes':low*MiB,'memory_high_bytes':(96 if memory==128 else 192)*MiB}}
    profile=json.loads((ROOT/'profile.json').read_text())['profile']
    if profile=='bounded':
        return {'kind':'komizo.capacity','version':1,'physical_memory_bytes':physical,'os_reserve_bytes':256*MiB,
            'physical_milli_cpus':cpus,'os_reserve_milli_cpus':100,
            'limits':{'memory_bytes':physical-256*MiB,'memory_swap_bytes':physical-256*MiB,'milli_cpus':cpus-100,'pids':512},
            'production':limits(512,700,256),'previews':limits(128,100,64),
            'control':infrastructure(128,32,300,128),'proxy':infrastructure(128,32,100,64),
            'infrastructure_reserve_bytes':128*MiB,'startup_memory_bytes':64*MiB,'disk_reserve_bytes':512*MiB,'max_instances':4}
    return {'kind':'komizo.capacity','version':1,'physical_memory_bytes':physical,'os_reserve_bytes':512*MiB,
        'physical_milli_cpus':cpus,'os_reserve_milli_cpus':250,
        'limits':{'memory_bytes':physical-512*MiB,'memory_swap_bytes':physical-512*MiB,'milli_cpus':cpus-250,'pids':1024},
        'production':limits(768,1000,256),'previews':limits(256,500,128),
        'control':infrastructure(256,96,500,256),'proxy':infrastructure(256,64,500,128),
        'infrastructure_reserve_bytes':192*MiB,'startup_memory_bytes':128*MiB,'disk_reserve_bytes':512*MiB,'max_instances':8}


def policy():
    return {'kind':'komizo.policy','version':1,'application':'mailroom','authority':{'kind':'owner'},
        'artifact_prefixes':['registry.fixture.test:5443/example/mailroom'], 'hostnames':['mailroom.localhost'],
        'readiness':[{'url':'https://mailroom.localhost/','status':200}],
        'limits':{'memory_bytes':256*MiB,'memory_swap_bytes':256*MiB,'milli_cpus':500,'pids':64}}


def request(action='inspect', selector='current'):
    now=int(time.time())
    return {'kind':'komizo.request','version':1,'authority':'owner','application':'mailroom','instance':'production',
        'action':action,'release_digest':selector,'nonce':secrets.token_hex(16),'issued_at':now,'expires_at':now+120,
        'timeout_seconds':120,'proof':''}


def inspect(body=None, user=None):
    arguments=[BINARY,'submit']
    if user:arguments=['runuser','-u',user,'--',*arguments]
    result=run(arguments,input=json.dumps(body or request()).encode(),ok=False)
    try:return json.loads(result.stdout)
    except ValueError:raise ValueError('native submission did not return one typed response') from None


def actual_boundaries(expected):
    for unit, allocation in [(CONTROLLER,expected['control']),(PROXY,expected['proxy'])]:
        if show(unit,'ActiveState')!='active':raise ValueError('native service is not active')
        group=show(unit,'ControlGroup')
        if not group.startswith('/komizo.slice/komizo-'):raise ValueError('infrastructure escaped protected parent slice')
        slice_group=Path('/sys/fs/cgroup')/str(Path(group).parent).removeprefix('/')
        limits=allocation['limits'];controls=allocation['controls']
        expected_files={'memory.max':str(limits['memory_bytes']), 'memory.swap.max':str(limits['memory_swap_bytes']-limits['memory_bytes']), 'memory.low':str(controls['memory_low_bytes']),
            'memory.high':str(controls['memory_high_bytes']),'pids.max':str(limits['pids'])}
        for name,value in expected_files.items():
            if (slice_group/name).read_text().strip()!=value:raise ValueError('actual infrastructure bound differs: '+name)
        quota,period=map(int,(slice_group/'cpu.max').read_text().split())
        if quota*1000 != limits['milli_cpus']*period:raise ValueError('actual infrastructure CPU bound differs')
    uid=int(run(['id','-u','komizo-proxy']).stdout)
    pid=int(show(PROXY,'MainPID'))
    statuses=dict(line.split(':',1) for line in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in line)
    if uid==0 or set(map(int,statuses['Uid'].split()))!={uid}:raise ValueError('proxy is not running as its actual unprivileged UID')
    if int(statuses['CapEff'].strip(),16) & ~(1 << 10):raise ValueError('proxy effective capabilities exceed low-port binding')
    controller=int(show(CONTROLLER,'MainPID'))
    for name in ['cmdline','environ']:
        response=run(['nsenter','--target',str(pid),'--mount','--','runuser','-u','komizo-proxy','--',
            'cat','/proc/'+str(controller)+'/'+name],ok=False)
        if response.returncode==0 or response.stdout:raise ValueError('actual proxy service can read another UID process metadata')
    run(['nsenter','--target',str(pid),'--mount','--','runuser','-u','komizo-proxy','--','test','-r','/proc/self/status'])
    if show(CONTROLLER,'KillMode')!='process' or show(CONTROLLER,'Type')!='notify':raise ValueError('controller supervision contract differs')
    for path in ['/var/lib/komizo/private-acceptance','/etc/komizo/controller.json']:
        if run(['runuser','-u','komizo-proxy','--','test','-r',path],ok=False).returncode==0:raise ValueError('proxy can read protected controller state')
    if run(['runuser','-u','komizo-proxy','--','test','-r','/var/lib/komizo-assets/public-acceptance'],ok=False).returncode:
        raise ValueError('proxy cannot read installed public assets')
    if run(['nsenter','--target',str(pid),'--mount','--','touch','/var/lib/komizo-assets/unexpected-write'],ok=False).returncode==0:
        raise ValueError('actual proxy mount namespace permits writes to public assets')
    if run(['runuser','-u','komizo-submit','--','test','-r','/var/lib/komizo/private-acceptance'],ok=False).returncode==0:
        raise ValueError('submission identity can read controller secrets')
    if show(PROXY,'Requires').split().count(CONTROLLER):raise ValueError('proxy lifetime depends on controller lifetime')


def prepare():
    baseline=json.loads((ROOT/'baseline.json').read_text())
    os_release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if os_release['ID'].strip('"')!='debian' or os_release['VERSION_ID'].strip('"')!=baseline['debian_version']:
        raise ValueError('guest differs from supported Debian baseline')
    version=run(['podman','--remote=false','version','--format={{.Client.Version}}']).stdout.decode().strip()
    if version!=baseline['podman_version']:raise ValueError('guest must exercise the declared distro Podman version')
    if run(['stat','-fc','%T','/sys/fs/cgroup']).stdout.strip()!=b'cgroup2fs':raise ValueError('guest does not have real unified cgroup v2')
    directory=Path('/etc/komizo');directory.mkdir(mode=0o700,exist_ok=True);directory.chmod(0o700)
    expected=capacity();write(directory/'capacity.json',expected)
    write(directory/'proxy.json',{'kind':'komizo.proxy','version':1,'trusted_proxies':[]})
    run([BINARY,'install','--authorized-keys',str(ROOT/'submission.pub')],timeout=240)
    proxy_receipt=Path('/etc/komizo-proxy/binary.json');accepted_receipt=proxy_receipt.read_bytes()
    run(['runuser','-u','komizo-proxy','--',BINARY,'proxy-guard'])
    changed=json.loads(accepted_receipt);changed['binary_sha256']='sha256:'+'0'*64
    try:
        write(proxy_receipt,changed,0o644)
        refused=run(['runuser','-u','komizo-proxy','--',BINARY,'proxy-guard'],ok=False)
        if refused.returncode==0 or refused.stdout:raise ValueError('unprivileged proxy guard accepted changed executable provenance')
    finally:write(proxy_receipt,accepted_receipt,0o644)
    run(['runuser','-u','komizo-proxy','--',BINARY,'proxy-guard'])
    dns=Path('/run/containers/networks/aardvark-dns');dns.mkdir(mode=0o700,parents=True,exist_ok=True)
    pidfile=dns/'aardvark.pid'
    write(pidfile,str(os.getpid()).encode())
    try:
        if run([BINARY,'dns-guard'],ok=False).returncode==0:raise ValueError('DNS helper accepted an unrelated live process from a stale pidfile')
    finally:pidfile.unlink()
    for arguments in [['--config','/tmp/foreign','-p','53','run'],['--config',str(dns),'-p','5353','run'],['--config',str(dns),'-p','53','run','/bin/sh']]:
        if run([BINARY,'dns',*arguments],ok=False).returncode==0:raise ValueError('DNS helper accepted an unbounded configuration, port or command')
    if run(['runuser','-u','komizo-submit','--',BINARY,'dns','--config',str(dns),'-p','53','run'],ok=False).returncode==0:
        raise ValueError('submission UID acquired shared DNS startup authority')
    write('/etc/komizo/apps/mailroom.json',policy())
    write('/var/lib/komizo/private-acceptance',b'private fixture bytes')
    write('/var/lib/komizo-assets/public-acceptance',b'public fixture bytes',0o644)
    actual_boundaries(expected)
    observation=inspect()
    if observation!={'kind':'komizo.instance','version':1,'application':'mailroom','instance':'production','installed':None}:
        raise ValueError('owner peer inspection did not retain exact application scope: '+json.dumps(observation))
    if inspect(user='komizo-submit').get('kind')!='komizo.error':raise ValueError('unprivileged peer selected owner authority')
    ledger=Path('/etc/komizo/bootstrap.json');prior=hashlib.sha256(ledger.read_bytes()).hexdigest()
    linked=ROOT/'linked-key';linked.symlink_to(ROOT/'submission.pub')
    if run([BINARY,'install','--authorized-keys',str(linked)],ok=False).returncode==0:raise ValueError('linked owner input was admitted')
    if hashlib.sha256(ledger.read_bytes()).hexdigest()!=prior:raise ValueError('unsafe bootstrap input caused protected effects')
    run([BINARY,'install','--authorized-keys',str(ROOT/'submission.pub')],timeout=240)
    if hashlib.sha256(ledger.read_bytes()).hexdigest()!=prior:raise ValueError('identical bootstrap did not preserve its ownership ledger')
    managed=Path('/usr/local/libexec/komizo-submit-shell');original=managed.read_bytes()
    try:
        write(managed,original+b'\n# foreign bytes\n',0o755)
        if run([BINARY,'install','--authorized-keys',str(ROOT/'submission.pub')],ok=False).returncode==0:
            raise ValueError('recorded bootstrap bytes changed without owner review')
        if hashlib.sha256(ledger.read_bytes()).hexdigest()!=prior:raise ValueError('foreign bootstrap bytes changed the ownership ledger')
    finally:write(managed,original,0o755)
    # Only the declared root-provided key set changes. Reinstall must prove its
    # previous ledger identity before admitting the replacement and restoring it.
    extra=ROOT/'upgrade-key'
    run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(extra)])
    replacement=ROOT/'replacement-keys.pub'
    write(replacement,(ROOT/'submission.pub').read_bytes()+extra.with_suffix('.pub').read_bytes())
    run([BINARY,'install','--authorized-keys',str(replacement)],timeout=240)
    if extra.with_suffix('.pub').read_text().split()[1] not in Path('/etc/ssh/komizo-submit/authorized_keys').read_text():
        raise ValueError('reviewed managed bootstrap update did not replace the accepted key set')
    run([BINARY,'install','--authorized-keys',str(ROOT/'submission.pub')],timeout=240)
    if hashlib.sha256(ledger.read_bytes()).hexdigest()!=prior:raise ValueError('reviewed key restoration changed unrelated bootstrap ownership')
    # A later root configuration layer must not silently undo confinement for
    # protected capture helpers that do not pass an explicit profile flag.
    override=Path('/etc/containers/containers.conf.d/99-native-unreviewed.conf')
    if override.exists() or override.is_symlink():raise ValueError('confinement override fixture encountered foreign configuration')
    prior=ledger.read_bytes()
    write(override,b'[containers]\napparmor_profile="unconfined"\n',0o644)
    try:
        refused=run([BINARY,'install','--authorized-keys',str(ROOT/'submission.pub')],ok=False,timeout=240)
        if refused.returncode==0 or b'effective root container defaults' not in refused.stderr:
            raise ValueError('later container configuration bypassed the protected default profile')
        if override.read_bytes()!=b'[containers]\napparmor_profile="unconfined"\n' or ledger.read_bytes()!=prior:
            raise ValueError('confinement refusal altered a borrowed configuration or ownership record')
    finally:override.unlink()
    run([BINARY,'install','--authorized-keys',str(ROOT/'submission.pub')],timeout=240)
    network=json.loads(run(['podman','--remote=false','info','--format=json']).stdout)['host']['networkBackendInfo']
    if network['dns']['path']!='/usr/local/libexec/komizo-network/aardvark-dns':raise ValueError('Podman bypassed the protected typed DNS helper')
    report={'kind':'komizo.native-host-acceptance','version':1,'ok':False,
        'scope':'bootstrap, peer boundary, proxy isolation, actual kernel limits, real reboot',
        'profile':json.loads((ROOT/'profile.json').read_text())['profile'],
        'runtime_acceptance':False,'baseline':baseline,'network_backend':network,
        'checks':{'supported_host':'passed','root_peer':'passed','forged_owner_peer':'passed','proxy_uid':'passed',
            'proxy_mount_write_refusal':'passed','proxy_process_metadata_isolation':'passed','secret_isolation':'passed',
            'kernel_limits':'passed','unsafe_filesystem':'passed','idempotent_install':'passed','managed_bootstrap_upgrade':'passed','foreign_bootstrap_bytes_refused':'passed',
            'apparmor_override_refused':'passed','typed_dns_helper_refusal':'passed','native_proxy_source_receipt':'passed','unprivileged_proxy_digest_guard':'passed'}}
    write(ROOT/'report.json',report)


def runtime():
    import fixture_runtime
    fixture_runtime.prepare()


def evidence():
    files={}
    for pattern in ['readiness-*.json','proxy-active-*.caddy','shared-dns.json','postgres-wrapper.json','postgres-diagnostic.json','postgres-initial.json','apparmor-boundary.json','deadline-observation.json','interrupted-deadline-observation.json','log-observation.json','task-deadline.json','task-helper-cleanup.json','resource-stress.json']:
        for path in list(ROOT.glob(pattern))[:16]:
            if path.is_file() and not path.is_symlink() and path.stat().st_size<=65536:files[path.name]=path.read_text()
    operations=[]
    for path in sorted(Path('/var/lib/komizo/operations').glob('*.json'))[-32:]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size>16384:continue
        record=json.loads(path.read_bytes());identity=record.get('operation_id','')
        if not __import__('re').fullmatch('[a-f0-9]{32}',identity):continue
        row={key:record[key] for key in ['kind','version','operation_id','application','instance','release_digest','phase','ok','reconciliation_required'] if key in record}
        failure=Path('/var/lib/komizo/journal')/identity/'failure.json'
        if failure.is_file() and not failure.is_symlink() and failure.stat().st_size<=16384:
            value=json.loads(failure.read_bytes());row['failure']={key:value[key] for key in ['kind','version','operation_id','phase','code','context','observed_at'] if key in value}
        operations.append(row)
    containers=[]
    for item in json.loads(run(['podman','--remote=false','ps','--all','--format=json']).stdout)[:32]:
        identity=item.get('Id') or item.get('ID') or item.get('id')
        if not isinstance(identity,str) or not __import__('re').fullmatch('[a-f0-9]{64}',identity):continue
        selected=json.loads(run(['podman','--remote=false','container','inspect',identity]).stdout)[0]
        labels=selected.get('Config',{}).get('Labels',{}) or {}
        if not labels.get('io.komizo.application'):continue
        pid=selected['State']['Pid'];label=Path('/proc/'+str(pid)+'/attr/current')
        containers.append({'id':selected['Id'],'application':labels['io.komizo.application'],'instance':labels.get('io.komizo.instance'),
            'service':labels.get('io.komizo.service'),'profile':selected.get('AppArmorProfile'),
            'pid':pid,'state':selected['State']['Status'],'kernel_label':label.read_text().strip() if pid and label.is_file() else None})
    assets={}
    for path in list(Path('/var/lib/komizo-assets').rglob('*'))[:128]:
        stat=path.lstat();assets[str(path)]={'mode':oct(stat.st_mode&0o7777),'uid':stat.st_uid,'gid':stat.st_gid,'size':stat.st_size}
    print(json.dumps({'kind':'komizo.native-fixture-evidence','version':1,'files':files,'assets':assets,'operations':operations,'containers':containers},sort_keys=True))


def verify_reboot():
    expected=json.loads(Path('/etc/komizo/capacity.json').read_text())
    actual_boundaries(expected)
    import fixture_runtime
    fixture_runtime.verify_reboot()
    expected_release=json.loads((ROOT/'report.json').read_text())['installed']['mailroom']
    observed=inspect().get('installed')
    if not observed or observed['release_digest']!=expected_release or observed['desired_running']:
        raise ValueError('stopped installed identity changed after reboot')
    report=json.loads((ROOT/'report.json').read_text());report['checks']['real_reboot']='passed';report['ok']=True
    write(ROOT/'report.json',report)


if __name__=='__main__':
    {'bootstrap':prepare,'runtime':runtime,'evidence':evidence,'verify-reboot':verify_reboot}[sys.argv[1]]()
