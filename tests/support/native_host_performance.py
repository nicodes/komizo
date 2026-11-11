#!/usr/bin/env python3
"""Observe bounded native infrastructure and one owned finite load in the guest."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import sys
import time

from acceptance import ROOT, run, write, service_pid, dns_pid

try:
    import fixture_tasks
except ModuleNotFoundError:
    import importlib.util
    _task_spec=importlib.util.spec_from_file_location('fixture_tasks',Path(__file__).with_name('native_host_fixture.py'))
    fixture_tasks=importlib.util.module_from_spec(_task_spec);_task_spec.loader.exec_module(fixture_tasks)

CGROUP=Path('/sys/fs/cgroup')


def oom():
    return {str(path.relative_to(CGROUP)): {key:int(value) for key,value in (line.split() for line in path.read_text().splitlines()) if key.startswith('oom')}
        for path in (CGROUP/'komizo').rglob('memory.events')}


def controls():
    selected={}
    for service in ['komizo-controller','komizo-proxy','komizo-dns','komizo-expiry']:
        worker=service_pid(service);role=service.removeprefix('komizo-')
        selected[worker]=role+'-runner' if role=='dns' else role
        monitor=int((Path('/run/komizo-infrastructure')/(service+'.pid')).read_text())
        selected[monitor]=role+'-supervisor'
    selected[dns_pid()]='dns'
    groups={'controller':'/komizo/control/controller','proxy':'/komizo/proxy/server',
        'dns':'/komizo/control/dns','expiry':'/komizo/control/watchdogs'}
    expected={'controller':'/usr/local/bin/komizo-box','proxy':'/usr/local/bin/caddy',
        'dns':'/usr/libexec/podman/aardvark-dns','dns-runner':'/usr/local/bin/komizo-box','expiry':'/usr/local/bin/komizo-box'}
    live=set()
    for group in groups.values():
        live.update(map(int,(CGROUP/group.removeprefix('/')/'cgroup.procs').read_text().split()))
    if live!=set(selected):
        raise ValueError('fixed infrastructure was not idle or has an unaccounted process')
    rows=[]
    for pid,role in selected.items():
        path=Path('/proc')/str(pid);executable=(path/'exe').resolve()
        original=role.removesuffix('-supervisor').removesuffix('-runner')
        required='/sbin/supervise-daemon' if role.endswith('-supervisor') else expected[role]
        group=next(line[3:] for line in (path/'cgroup').read_text().splitlines() if line.startswith('0::'))
        if executable!=Path(required).resolve() or group!=groups[original]:
            raise ValueError('running fixed infrastructure executable or cgroup differs')
        pss=sum(int(line.split()[1])*1024 for line in (path/'smaps_rollup').read_text().splitlines() if line.startswith('Pss:'))
        rows.append({'role':role,'pid':pid,'pss_bytes':pss,'executable_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),'cgroup':group})
    if len(rows)!=9:raise ValueError('complete fixed infrastructure PSS was not observed')
    return rows


def start(budget):
    if json.loads((ROOT/'profile.json').read_text())['profile']!='bounded':raise ValueError('performance requires the one CPU/one GiB profile')
    cpus=len(__import__('os').sched_getaffinity(0))*1000
    memory=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')))*1024
    if cpus!=budget['guest_milli_cpus'] or not budget['guest_memory_bytes']*9//10<memory<=budget['guest_memory_bytes']:
        raise ValueError('actual guest differs from the finite memory/CPU profile')
    # Expiry can briefly execute a pass. Sample only a genuinely idle complete
    # fixed graph; the unchanged setup deadline still includes this wait.
    until=time.monotonic()+5
    while True:
        try:rows=controls();break
        except ValueError as error:
            if str(error)!='fixed infrastructure was not idle or has an unaccounted process' or time.monotonic()>=until:raise
            time.sleep(.05)
    unit='native-fixture-load-'+secrets.token_hex(8)
    output=fixture_tasks.ROOT/(unit+'-stdout')
    program=('import json,time\nhot=bytearray('+str(budget['load_memory_bytes'])+')\n'
        'for p in range(0,len(hot),4096):hot[p]=1\nprint(json.dumps({"hot_bytes":len(hot)}),flush=True)\n'
        'end=time.monotonic()+'+str(budget['load_seconds'])+'\nwhile time.monotonic()<end:\n for p in range(0,len(hot),4096):hot[p]=(hot[p]+1)&255\n')
    before=oom()
    task=fixture_tasks.start(unit,['/usr/bin/python3','-I','-B','-c',program],
        memory=96<<20,pids=8,milli_cpus=budget['load_milli_cpus'],seconds=budget['load_seconds']+15,user='nobody',production=True)
    group=task['group'];path=CGROUP/group.removeprefix('/')
    if not group.startswith('/komizo/production/native-fixture-load-') or (path/'memory.max').read_text().strip()!=str(96<<20) or (path/'memory.swap.max').read_text().strip()!='0' or (path/'pids.max').read_text().strip()!='8':
        raise ValueError('owned performance load escaped its protected limits')
    quota,period=map(int,(path/'cpu.max').read_text().split())
    if quota*1000!=budget['load_milli_cpus']*period:raise ValueError('owned performance load CPU differs')
    end=time.monotonic()+10
    while not output.exists() or not output.stat().st_size:
        if time.monotonic()>=end:raise ValueError('finite load did not touch its memory')
        time.sleep(.05)
    hot=json.loads(output.read_text())['hot_bytes']
    write(ROOT/'performance-state.json',{'unit':unit,'group':group,'before':before,'started':time.monotonic(),
        'metrics':{'guest_memory_bytes':budget['guest_memory_bytes'],'guest_milli_cpus':cpus,'load_hot_bytes':hot,
            'idle_control_pss_bytes':sum(row['pss_bytes'] for row in rows),'control_processes':rows,
            'control_services_running':{'controller':True,'proxy':True}}})


def finish(budget):
    state=json.loads((ROOT/'performance-state.json').read_text());unit=state['unit']
    path=CGROUP/state['group'].removeprefix('/');metrics=state['metrics']
    end=time.monotonic()+budget['load_seconds']+15
    try:
        completion=fixture_tasks.result(unit)
        while completion is None:
            if time.monotonic()>=end:raise ValueError('owned finite load exceeded its deadline')
            time.sleep(.1);completion=fixture_tasks.result(unit)
        if (type(completion.get('exit_code')) is not int or completion['exit_code']!=0
                or completion.get('timed_out') is not False or completion.get('populated') is not False
                or completion.get('group')!=state['group']):
            raise ValueError('owned finite load failed or lost its quiescent result binding')
        # The independent supervisor snapshots the actual kernel counter only
        # after reaping/killing all descendants, before removing this cgroup.
        usage=completion.get('cpu_usage_usec')
        if type(usage) is not int or not 1<=usage<(1<<64)-1:
            raise ValueError('owned finite load CPU accounting is missing or invalid')
        metrics['load_cpu_usec']=usage
        after=oom()
        # Ignore only the load's newly created event file; it must also show no OOM.
        metrics['oom_events_unchanged']=all(after.get(name)==value for name,value in state['before'].items()) and all(
            not any(value.values()) for name,value in after.items() if name not in state['before'])
    finally:fixture_tasks.stop(unit)
    until=time.monotonic()+5
    while path.exists() and time.monotonic()<until:time.sleep(.02)
    metrics['owned_load_removed']=not path.exists() and not fixture_tasks.populated(state['group'])
    write(ROOT/'performance-metrics.json',metrics)
    print(json.dumps(metrics,sort_keys=True))


if __name__=='__main__':
    budget=json.loads(sys.argv[2])
    if sys.argv[1]=='start':start(budget)
    elif sys.argv[1]=='finish':finish(budget)
    else:raise ValueError('typed performance phase required')
