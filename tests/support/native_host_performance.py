#!/usr/bin/env python3
"""Observe bounded native infrastructure and one owned finite load in the guest."""
import hashlib
import json
from pathlib import Path
import secrets
import sys
import time

from acceptance import ROOT, run, write, show

CGROUP=Path('/sys/fs/cgroup')


def oom():
    return {str(path.relative_to(CGROUP)): {key:int(value) for key,value in (line.split() for line in path.read_text().splitlines()) if key.startswith('oom')}
        for path in (CGROUP/'komizo.slice').rglob('memory.events')}


def controls():
    rows=[]
    expected={'controller':('/usr/local/bin/komizo-box','komizo-control.slice'),
        'proxy':('/usr/local/bin/caddy','komizo-proxy.slice')}
    selected={int(show('komizo-controller.service','MainPID')):'controller',int(show('komizo-proxy.service','MainPID')):'proxy'}
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():continue
        try:
            executable=(path/'exe').resolve();role=selected.get(int(path.name))
            if role is None and executable.name=='aardvark-dns':role='dns'
            if role is None:continue
            group=next(line[3:] for line in (path/'cgroup').read_text().splitlines() if line.startswith('0::'))
            if role in expected and executable!=Path(expected[role][0]):raise ValueError('running infrastructure executable differs')
            pool=expected[role][1] if role in expected else 'komizo-control.slice'
            if not group.startswith('/komizo.slice/'+pool+'/'):raise ValueError('shared infrastructure escaped protected capacity')
            pss=sum(int(line.split()[1])*1024 for line in (path/'smaps_rollup').read_text().splitlines() if line.startswith('Pss:'))
            rows.append({'role':role,'pid':int(path.name),'pss_bytes':pss,'executable_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),'cgroup':group})
        except (FileNotFoundError,ProcessLookupError):continue
    if sum(row['role']=='controller' for row in rows)!=1 or sum(row['role']=='proxy' for row in rows)!=1 or not any(row['role']=='dns' for row in rows):
        raise ValueError('complete native control, proxy and shared DNS processes were not observed')
    return rows


def start(budget):
    if json.loads((ROOT/'profile.json').read_text())['profile']!='bounded':raise ValueError('performance requires the one CPU/one GiB profile')
    cpus=len(__import__('os').sched_getaffinity(0))*1000
    memory=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')))*1024
    if cpus!=budget['guest_milli_cpus'] or not budget['guest_memory_bytes']*9//10<memory<=budget['guest_memory_bytes']:
        raise ValueError('actual guest differs from the finite memory/CPU profile')
    rows=controls();unit='komizo-fixture-load-'+secrets.token_hex(8)+'.service'
    output='/run/'+unit+'.json'
    program=('import json,time\nhot=bytearray('+str(budget['load_memory_bytes'])+')\n'
        'for p in range(0,len(hot),4096):hot[p]=1\nprint(json.dumps({"hot_bytes":len(hot)}),flush=True)\n'
        'end=time.monotonic()+'+str(budget['load_seconds'])+'\nwhile time.monotonic()<end:\n for p in range(0,len(hot),4096):hot[p]=(hot[p]+1)&255\n')
    before=oom()
    run(['systemd-run','--unit='+unit,'--slice=komizo-production.slice','--uid=nobody','--gid=nogroup',
        '--property=Type=exec','--property=RemainAfterExit=yes','--property=MemoryMax=96M','--property=MemorySwapMax=0',
        '--property=TasksMax=8','--property=CPUQuota='+str(budget['load_milli_cpus']//10)+'%',
        '--property=RuntimeMaxSec='+str(budget['load_seconds']+15),'--property=StandardOutput=file:'+output,
        '/usr/bin/python3','-I','-B','-c',program])
    group=show(unit,'ControlGroup');path=CGROUP/group.removeprefix('/')
    if not group.startswith('/komizo.slice/komizo-production.slice/') or (path/'memory.max').read_text().strip()!=str(96<<20) or (path/'memory.swap.max').read_text().strip()!='0' or (path/'pids.max').read_text().strip()!='8':
        raise ValueError('owned performance load escaped its protected limits')
    quota,period=map(int,(path/'cpu.max').read_text().split())
    if quota*1000!=budget['load_milli_cpus']*period:raise ValueError('owned performance load CPU differs')
    end=time.monotonic()+10
    while not Path(output).exists() or not Path(output).stat().st_size:
        if time.monotonic()>=end:raise ValueError('finite load did not touch its memory')
        time.sleep(.05)
    hot=json.loads(Path(output).read_text())['hot_bytes']
    write(ROOT/'performance-state.json',{'unit':unit,'group':group,'before':before,'started':time.monotonic(),
        'metrics':{'guest_memory_bytes':budget['guest_memory_bytes'],'guest_milli_cpus':cpus,'load_hot_bytes':hot,
            'idle_control_pss_bytes':sum(row['pss_bytes'] for row in rows),'control_processes':rows,
            'control_services_running':{'controller':True,'proxy':True}}})


def finish(budget):
    state=json.loads((ROOT/'performance-state.json').read_text());unit=state['unit']
    path=CGROUP/state['group'].removeprefix('/');metrics=state['metrics']
    end=time.monotonic()+budget['load_seconds']+15
    try:
        while show(unit,'SubState')=='running':
            if time.monotonic()>=end:raise ValueError('owned finite load exceeded its deadline')
            time.sleep(.1)
        if show(unit,'Result')!='success' or show(unit,'ExecMainStatus')!='0':raise ValueError('owned finite load failed')
        metrics['load_cpu_usec']=int(dict(line.split() for line in (path/'cpu.stat').read_text().splitlines())['usage_usec'])
        after=oom()
        # Ignore only the load's newly created event file; it must also show no OOM.
        metrics['oom_events_unchanged']=all(after.get(name)==value for name,value in state['before'].items()) and all(
            not any(value.values()) for name,value in after.items() if name not in state['before'])
    finally:run(['systemctl','stop',unit])
    inactive=run(['systemctl','is-active',unit],ok=False)
    metrics['owned_load_removed']=inactive.returncode in {3,4} and inactive.stdout.strip() in {b'inactive',b'unknown'} and not path.exists()
    write(ROOT/'performance-metrics.json',metrics)
    print(json.dumps(metrics,sort_keys=True))


if __name__=='__main__':
    budget=json.loads(sys.argv[2])
    if sys.argv[1]=='start':start(budget)
    elif sys.argv[1]=='finish':finish(budget)
    else:raise ValueError('typed performance phase required')
