"""Validate actual fixed-budget measurements from the disposable Debian guest."""
import math
import re

SCOPE="one CPU and one GiB disposable Debian guest; synthetic PostgreSQL/API/static workload, finite background load and cold owner reads"


def evaluate(metrics, budget):
    fields={'guest_memory_bytes','guest_milli_cpus','setup_seconds','deployment_seconds','idle_control_pss_bytes','route_seconds','operator_seconds',
        'load_hot_bytes','load_cpu_usec','control_processes','control_services_running','oom_events_unchanged','owned_load_removed'}
    if set(metrics)!=fields:raise ValueError('performance metadata contains an unapproved field')
    if type(metrics.get('guest_memory_bytes')) is not int or metrics['guest_memory_bytes']!=budget['guest_memory_bytes'] or type(metrics.get('guest_milli_cpus')) is not int or metrics['guest_milli_cpus']!=budget['guest_milli_cpus']:
        raise ValueError('performance guest exceeds the reviewed CPU/memory profile')
    for name in ('setup_seconds','deployment_seconds','idle_control_pss_bytes'):
        value=metrics[name]
        if type(value) not in (int,float) or not math.isfinite(value) or not 0<value<=budget[name]:raise ValueError('performance budget refused: '+name)
    for name in ('route_seconds','operator_seconds'):
        samples=metrics[name]
        if len(samples)!=budget['samples'] or any(type(value) not in (int,float) or not math.isfinite(value) or not 0<value<=budget[name] for value in samples):
            raise ValueError('performance budget refused: '+name)
    if type(metrics['load_hot_bytes']) is not int or metrics['load_hot_bytes']!=budget['load_memory_bytes'] or type(metrics['load_cpu_usec']) is not int or metrics['load_cpu_usec']<1_000_000:
        raise ValueError('positive bounded memory/CPU load was not observed')
    rows=metrics['control_processes']
    if metrics['control_services_running']!={'controller':True,'proxy':True} or any(value is not True for value in metrics['control_services_running'].values()) or not isinstance(rows,list) or not 3<=len(rows)<=32:
        raise ValueError('complete native controller/proxy/DNS identities were not observed')
    if sum(row['role']=='controller' for row in rows)!=1 or sum(row['role']=='proxy' for row in rows)!=1 or not any(row['role']=='dns' for row in rows):
        raise ValueError('native control process roles differ')
    if len({row['pid'] for row in rows})!=len(rows) or sum(row['pss_bytes'] for row in rows)!=metrics['idle_control_pss_bytes']:
        raise ValueError('native control process accounting is incomplete')
    for row in rows:
        if set(row)!={'role','pid','pss_bytes','executable_sha256','cgroup'}:raise ValueError('control process metadata contains an unapproved field')
        if (row['role'] not in {'controller','proxy','dns'} or type(row['pid']) is not int or row['pid']<=0 or type(row['pss_bytes']) is not int or row['pss_bytes']<=0
                or not re.fullmatch('[a-f0-9]{64}',row['executable_sha256'])
                or not row['cgroup'].startswith('/komizo.slice/komizo-'+('proxy' if row['role']=='proxy' else 'control')+'.slice/')):
            raise ValueError('native control executable or protected pool differs')
    if metrics['oom_events_unchanged'] is not True or metrics['owned_load_removed'] is not True:raise ValueError('finite performance load did not preserve its boundary')
    return True
