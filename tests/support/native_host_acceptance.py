#!/usr/bin/env python3
"""Assert the native host boundary from inside the disposable Alpine guest."""
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
CONTROLLER = 'komizo-controller'
PROXY = 'komizo-proxy'
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


def process_status(pid):
    return dict(line.split(':',1) for line in Path('/proc',str(pid),'status').read_text().splitlines() if ':' in line)


def process_group(pid):
    rows=Path('/proc',str(pid),'cgroup').read_text().splitlines()
    if len(rows)!=1 or not rows[0].startswith('0::/'):
        raise ValueError('native process lacks its exact unified cgroup')
    return rows[0][3:]


def service_pid(service):
    roles={'komizo-controller':('/komizo/control/controller',BINARY),
        'komizo-proxy':('/komizo/proxy/server','/usr/local/bin/caddy'),
        'komizo-dns':('/komizo/control/dns',BINARY),
        'komizo-expiry':('/komizo/control/watchdogs',BINARY)}
    if service not in roles:raise ValueError('unknown fixed OpenRC service')
    group, executable=roles[service]
    path=Path('/run/komizo-infrastructure')/(service+'.pid')
    metadata=path.lstat()
    if not path.is_file() or path.is_symlink() or metadata.st_uid!=0 or metadata.st_nlink!=1 or metadata.st_mode&0o022 or metadata.st_size>32:
        raise ValueError('OpenRC supervisor PID file is not protected')
    monitor=int(path.read_text())
    if monitor<=1 or Path('/proc',str(monitor),'exe').resolve()!=Path('/sbin/supervise-daemon').resolve():
        raise ValueError('fixed OpenRC monitor executable differs')
    if process_group(monitor)!=group or set(map(int,process_status(monitor)['Uid'].split()))!={0}:
        raise ValueError('OpenRC monitor escaped its root identity or resource leaf')
    children=Path('/proc',str(monitor),'task',str(monitor),'children').read_text().split()
    if len(children)!=1:raise ValueError('OpenRC monitor lacks its unique live worker')
    pid=int(children[0]);status=process_status(pid)
    if int(status['PPid'])!=monitor or status['State'].strip().startswith('Z') or process_group(pid)!=group:
        raise ValueError('OpenRC worker parent/lifetime/cgroup differs')
    if Path('/proc',str(pid),'exe').resolve()!=Path(executable).resolve():
        raise ValueError('fixed infrastructure worker executable differs')
    return pid


def service_active(service):
    if run(['rc-service',service,'status'],ok=False).returncode:return False
    try:return service_pid(service)>1
    except (OSError,ValueError):return False


def restart_controller():
    pid=service_pid(CONTROLLER);descriptor=os.pidfd_open(pid)
    try:
        if service_pid(CONTROLLER)!=pid:raise ValueError('controller identity changed before its owned kill')
        __import__('signal').pidfd_send_signal(descriptor,__import__('signal').SIGKILL)
    finally:os.close(descriptor)
    deadline=time.monotonic()+30
    while not service_active(CONTROLLER) or service_pid(CONTROLLER)==pid:
        if time.monotonic()>=deadline:raise ValueError('OpenRC did not supervise the killed controller')
        time.sleep(.1)


def dns_pid():
    runner=service_pid('komizo-dns')
    children=Path('/proc',str(runner),'task',str(runner),'children').read_text().split()
    if len(children)!=1:raise ValueError('fixed DNS runner lacks its unique owned child')
    pid=int(children[0])
    if (Path('/proc',str(pid),'exe').resolve()!=Path('/usr/libexec/podman/aardvark-dns').resolve()
            or process_group(pid)!='/komizo/control/dns' or int(process_status(pid)['PPid'])!=runner):
        raise ValueError('actual shared DNS child escaped its fixed supervision')
    return pid


def group_empty(group):
    path=Path('/sys/fs/cgroup')/group.removeprefix('/')/'cgroup.events'
    return not path.exists() or 'populated 0' in path.read_text().splitlines()


def task_completed(kind, operation):
    import re
    if kind not in {'backup','prepare','reconcile'} or not re.fullmatch('[a-f0-9]{32}',operation):
        raise ValueError('invalid exact protected task selector')
    root=Path('/var/lib/komizo/journal')/operation
    intent=json.loads((root/(kind+'-task.json')).read_bytes())
    completed=json.loads((root/(kind+'-completed.json')).read_bytes())
    unit='komizo-'+kind+'-'+operation+'.service'
    if (intent['unit']!=unit or type(completed.get('exit_code')) is not int
            or completed!={'unit_sha256':intent['unit_sha256'],'exit_code':0}
            or not group_empty('/komizo/control/'+unit)):
        raise ValueError('protected task lacks its exact successful exit and empty resource group')
    return completed


def measured_memory():
    return int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:'))) * 1024


def memory_ceiling(physical):
    # Kernel reservations can vary across an otherwise identical real boot.
    # Keep an explicit margin before rounding, even just above a boundary.
    if type(physical) is not int or physical<=32*MiB:
        raise ValueError('fixture physical memory measurement is invalid')
    return (physical-16*MiB)//(16*MiB)*(16*MiB)


def record_capacity(expected,phase):
    path=ROOT/'capacity-observation.json'
    observations=json.loads(path.read_bytes()) if path.exists() else {'version':1,'observations':[]}
    observations['observations'].append({'phase':phase,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'actual_memtotal_bytes':measured_memory(),'selected_ceiling_bytes':expected['physical_memory_bytes'],
        'parent_memory_bytes':expected['limits']['memory_bytes'],'os_reserve_bytes':expected['os_reserve_bytes'],
        'headroom_bytes':16*MiB,'rounding_bytes':16*MiB})
    write(path,observations)


def capacity():
    physical = memory_ceiling(measured_memory())
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


def profile_probe(profile, user, readable, denied, writes=()):
    # Enter the exact already-loaded profile without changing its executable
    # allowlist. All inputs are synthetic public fixture paths, not owner data.
    if profile not in {'komizo-proxy','komizo-dns'}:raise ValueError('unknown fixed profile probe')
    import pwd
    identity=pwd.getpwnam(user)
    program = r"""import json,os,sys
profile,uid,gid,readable,denied,writes=json.loads(sys.argv[1])
os.setgroups([]);os.setgid(gid);os.setuid(uid)
for path in writes:
 fd=os.open(path,os.O_WRONLY|os.O_APPEND);os.close(fd)
with open('/proc/self/attr/current','w') as output:output.write('changeprofile '+profile)
with open('/proc/self/attr/current') as source:label=source.read().strip()
assert label==profile+' (enforce)'
for path in readable:
 with open(path,'rb') as source:assert source.read(4096)
for path in denied:
 try:
  with open(path,'rb') as source:source.read(1)
 except PermissionError:pass
 else:raise ValueError('enforcing profile admitted a protected read')
for path in writes:
 try:
  with open(path,'ab') as output:output.write(b'unexpected')
 except PermissionError:pass
 else:raise ValueError('enforcing profile admitted an asset write')
print(json.dumps({'label':label,'reads_refused':len(denied),'writes_refused':len(writes)}))
"""
    result=run(['/usr/bin/python3','-I','-B','-c',program,json.dumps([profile,identity.pw_uid,identity.pw_gid,readable,denied,list(writes)])])
    return json.loads(result.stdout)


def actual_boundaries(expected,*,phase='bootstrap'):
    record_capacity(expected,phase)
    for unit, allocation in [(CONTROLLER,expected['control']),(PROXY,expected['proxy'])]:
        if not service_active(unit):raise ValueError('native service is not active')
        group=process_group(service_pid(unit))
        if group!={'komizo-controller':'/komizo/control/controller','komizo-proxy':'/komizo/proxy/server'}[unit]:raise ValueError('infrastructure escaped its fixed resource leaf')
        slice_group=Path('/sys/fs/cgroup')/str(Path(group).parent).removeprefix('/')
        limits=allocation['limits'];controls=allocation['controls']
        expected_files={'memory.max':str(limits['memory_bytes']), 'memory.swap.max':str(limits['memory_swap_bytes']-limits['memory_bytes']), 'memory.low':str(controls['memory_low_bytes']),
            'memory.high':str(controls['memory_high_bytes']),'pids.max':str(limits['pids'])}
        for name,value in expected_files.items():
            if (slice_group/name).read_text().strip()!=value:raise ValueError('actual infrastructure bound differs: '+name)
        quota,period=map(int,(slice_group/'cpu.max').read_text().split())
        if quota*1000 != limits['milli_cpus']*period:raise ValueError('actual infrastructure CPU bound differs')
    uid=int(run(['id','-u','komizo-proxy']).stdout)
    pid=service_pid(PROXY)
    statuses=dict(line.split(':',1) for line in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in line)
    if uid==0 or set(map(int,statuses['Uid'].split()))!={uid}:raise ValueError('proxy is not running as its actual unprivileged UID')
    for field in ['CapEff','CapPrm','CapInh','CapAmb','CapBnd']:
        if int(statuses[field].strip(),16)!=(1<<10):raise ValueError('actual proxy capability set differs: '+field)
    if statuses['NoNewPrivs'].strip()!='1' or statuses['Seccomp'].strip()!='2':raise ValueError('actual proxy lacks NNP/seccomp')
    if Path('/proc',str(pid),'attr/current').read_text().strip()!='komizo-proxy (enforce)':raise ValueError('actual proxy profile is not enforcing')
    controller=service_pid(CONTROLLER)
    for path in ['/var/lib/komizo/private-acceptance','/etc/komizo/controller.json']:
        if run(['runuser','-u','komizo-proxy','--','test','-r',path],ok=False).returncode==0:raise ValueError('proxy can read protected controller state')
    if run(['runuser','-u','komizo-proxy','--','test','-r','/var/lib/komizo-assets/public-acceptance'],ok=False).returncode:
        raise ValueError('proxy cannot read installed public assets')
    if run(['runuser','-u','komizo-proxy','--','touch','/var/lib/komizo-assets/unexpected-write'],ok=False).returncode==0:
        raise ValueError('actual proxy UID permits writes to public assets')
    canary=Path('/var/lib/komizo-assets/profile-write-fixture');write(canary,b'unchanged',0o666)
    try:
        profile_probe('komizo-proxy','komizo-proxy',['/var/lib/komizo-assets/public-acceptance','/proc/self/status'],
            ['/var/lib/komizo/private-acceptance','/etc/komizo/controller.json',
             '/proc/'+str(controller)+'/cmdline','/proc/'+str(controller)+'/environ'],[str(canary)])
        if canary.read_bytes()!=b'unchanged':raise ValueError('enforcing profile changed the public write canary')
    finally:canary.unlink()
    if run(['runuser','-u','komizo-submit','--','test','-r','/var/lib/komizo/private-acceptance'],ok=False).returncode==0:
        raise ValueError('submission identity can read controller secrets')
    proxy_script=Path('/etc/init.d/komizo-proxy').read_text()
    if 'komizo-controller' in proxy_script:raise ValueError('proxy lifetime depends on the controller')
    if not service_active('komizo-expiry'):raise ValueError('independent expiry is not supervised')
    # DNS is deliberately lazy: its first live proof follows actual networking.
    if phase=='bootstrap':return
    if not service_active('komizo-dns'):raise ValueError('real network lacks supervised DNS')
    child=dns_pid();status=process_status(child)
    for field in ['CapEff','CapPrm','CapInh','CapAmb','CapBnd']:
        if int(status[field].strip(),16)!=(1<<10):raise ValueError('actual DNS capability set differs')
    if (status['NoNewPrivs'].strip()!='1' or status['Seccomp'].strip()!='2'
            or Path('/proc',str(child),'attr/current').read_text().strip()!='komizo-dns (enforce)'):
        raise ValueError('actual DNS confinement differs')


def prepare():
    baseline=json.loads((ROOT/'baseline.json').read_text())
    os_release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if os_release['ID'].strip('"')!='alpine' or os_release['VERSION_ID'].strip('"')!=baseline['alpine_version']:
        raise ValueError('guest differs from the signed Alpine baseline')
    version=run(['podman','--remote=false','version','--format={{.Client.Version}}']).stdout.decode().strip()
    if version!=baseline['podman_version']:raise ValueError('guest must exercise the declared signed APK Podman version')
    if run(['apk','info','--installed','-v','podman']).stdout.decode().strip()!='podman-'+baseline['podman_package']:
        raise ValueError('actual Podman APK version differs from its tested closure')
    if Path('/sys/module/apparmor/parameters/enabled').read_text().strip()!='Y' or 'apparmor' not in Path('/sys/kernel/security/lsm').read_text().strip().split(','):
        raise ValueError('guest lacks its actually enabled AppArmor LSM')
    run(['rc-service','apparmor','status'])
    host=json.loads(run(['/usr/bin/podman','--remote=false','info','--format=json']).stdout)['host']
    if host['cgroupManager']!='cgroupfs' or host['cgroupVersion']!='v2':
        raise ValueError('actual native engine is outside unified cgroupfs')
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
        'runtime_acceptance':False,'baseline':baseline,'actual_platform':{'os_release':os_release,'kernel':run(['uname','-r']).stdout.decode().strip(),
            'openrc':run(['apk','info','--installed','-v','openrc']).stdout.decode().strip(),'apparmor_enabled':True,'engine_cgroup_manager':host['cgroupManager']},'network_backend':network,
        'checks':{'supported_host':'passed','root_peer':'passed','forged_owner_peer':'passed','proxy_uid':'passed',
            'proxy_asset_write_refusal':'passed','proxy_process_metadata_isolation':'passed','secret_isolation':'passed',
            'kernel_limits':'passed','unsafe_filesystem':'passed','idempotent_install':'passed','managed_bootstrap_upgrade':'passed','foreign_bootstrap_bytes_refused':'passed',
            'apparmor_override_refused':'passed','typed_dns_helper_refusal':'passed','native_proxy_source_receipt':'passed','unprivileged_proxy_digest_guard':'passed'}}
    write(ROOT/'report.json',report)


def runtime():
    import fixture_runtime
    fixture_runtime.prepare()


def evidence():
    files={}
    for pattern in ['capacity-observation.json','readiness-*.json','proxy-active-*.caddy','shared-dns.json','postgres-wrapper.json','postgres-diagnostic.json','postgres-initial.json','apparmor-boundary.json','deadline-observation.json','interrupted-deadline-observation.json','log-observation.json','task-deadline.json','task-helper-cleanup.json','task-start-observation.json','resource-stress.json']:
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
    import fixture_runtime
    fixture_runtime.verify_reboot()
    actual_boundaries(expected,phase='post-reboot')
    report=json.loads((ROOT/'report.json').read_text())
    if report['profile']=='functional':
        expected_release=report['installed']['mailroom']
        observed=inspect().get('installed')
        if not observed or observed['release_digest']!=expected_release or observed['desired_running']:
            raise ValueError('stopped installed identity changed after reboot')
    report['checks']['real_reboot']='passed';report['ok']=True
    write(ROOT/'report.json',report)


if __name__=='__main__':
    {'bootstrap':prepare,'runtime':runtime,'evidence':evidence,'verify-reboot':verify_reboot}[sys.argv[1]]()
