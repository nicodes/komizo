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
        return {'limits':limits(memory,cpu,pids),'controls':{'memory_low_bytes':low*MiB,'memory_high_bytes':192*MiB}}
    return {'kind':'komizo.capacity','version':1,'physical_memory_bytes':physical,'os_reserve_bytes':512*MiB,
        'physical_milli_cpus':cpus,'os_reserve_milli_cpus':250,
        'limits':{'memory_bytes':physical-512*MiB,'memory_swap_bytes':physical-512*MiB,'milli_cpus':cpus-250,'pids':1024},
        'production':limits(768,1000,256),'previews':limits(256,500,128),
        'control':infrastructure(256,96,500,256),'proxy':infrastructure(256,64,500,128),
        'infrastructure_reserve_bytes':192*MiB,'startup_memory_bytes':128*MiB,'disk_reserve_bytes':512*MiB,'max_instances':8}


def policy():
    return {'kind':'komizo.policy','version':1,'application':'mailroom','authority':{'kind':'owner'},
        'artifact_prefixes':['registry.fixture.test:5443/example/mailroom-'], 'hostnames':['mailroom.localhost'],
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
    report={'kind':'komizo.native-host-acceptance','version':1,'ok':False,
        'scope':'bootstrap, peer boundary, proxy isolation, actual kernel limits, real reboot',
        'runtime_acceptance':False,'baseline':baseline,
        'checks':{'supported_host':'passed','root_peer':'passed','forged_owner_peer':'passed','proxy_uid':'passed',
            'proxy_mount_write_refusal':'passed','secret_isolation':'passed','kernel_limits':'passed','unsafe_filesystem':'passed','idempotent_install':'passed'}}
    write(ROOT/'report.json',report)
    import fixture_runtime
    fixture_runtime.prepare()


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
    {'prepare':prepare,'verify-reboot':verify_reboot}[sys.argv[1]]()
