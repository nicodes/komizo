#!/usr/bin/env python3
"""Bounded dummy processes for the disposable VM, never production authority."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import subprocess
import sys
import time

ROOT = Path('/root/native-host/fixture-tasks')
CGROUP = Path('/sys/fs/cgroup')


def write(path, value):
    temporary = path.with_suffix('.new')
    with temporary.open('x') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, sort_keys=True)
        stream.flush(); os.fsync(stream.fileno())
    temporary.replace(path)


def locations(name):
    if not re.fullmatch('native-fixture-[a-z0-9-]{1,64}', name):
        raise ValueError('invalid owned VM fixture name')
    return ROOT/(name+'.json'), ROOT/(name+'-ready.json'), ROOT/(name+'-exit.json')


def start(name, argv, *, memory=128<<20, pids=64, milli_cpus=1000, seconds=900, user='root', production=False):
    ROOT.mkdir(mode=0o700, exist_ok=True)
    spec, ready, result = locations(name)
    if any(p.exists() for p in [spec, ready, result]):
        raise ValueError('VM fixture identity was already used')
    identity = pwd.getpwnam(user)
    group = ('/komizo/production/' if production else '/native-fixture/') + name
    value = {'name':name, 'argv':argv, 'uid':identity.pw_uid, 'gid':identity.pw_gid,
        'group':group, 'memory':memory, 'pids':pids, 'milli_cpus':milli_cpus, 'seconds':seconds,
        'home':identity.pw_dir, 'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    write(spec, value)
    with (ROOT/(name+'-supervisor.log')).open('xb') as output:
        subprocess.Popen([sys.executable, '-I', '-B', __file__, str(spec)], stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
            env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME':'/root','LANG':'C.UTF-8'})
    until = time.monotonic()+10
    while not ready.exists():
        if result.exists() or time.monotonic() >= until:
            raise ValueError('owned VM fixture did not start inside its real limits')
        time.sleep(.05)
    state = json.loads(ready.read_bytes())
    if state['group'] != group or not populated(group):
        raise ValueError('owned VM fixture startup lacked actual group membership')
    return state


def populated(group):
    path = CGROUP/group.removeprefix('/')/'cgroup.events'
    return path.exists() and 'populated 1' in path.read_text().splitlines()


def result(name):
    spec, ready, result = locations(name)
    if not result.exists():
        return None
    value = json.loads(result.read_bytes())
    if value['spec_sha256'] != hashlib.sha256(spec.read_bytes()).hexdigest() or value['name'] != name:
        raise ValueError('owned VM fixture result lost its exact source binding')
    if populated(value['group']):
        raise ValueError('finished VM fixture still owns live descendants')
    return value


def stop(name):
    spec, ready, completion = locations(name)
    value = json.loads(spec.read_bytes())
    if value['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        if populated(value['group']):
            raise ValueError('VM fixture unexpectedly survived its boot')
        return
    if result(name) is None:
        # Stop only our exact spec-bound cgroup; the supervisor records/reaps it.
        path = CGROUP/value['group'].removeprefix('/')/'cgroup.kill'
        if path.exists(): path.write_text('1')
        until = time.monotonic()+10
        while result(name) is None:
            if time.monotonic() >= until: raise ValueError('owned VM fixture did not stop')
            time.sleep(.05)


def worker(spec):
    value = json.loads(spec.read_bytes())
    _, ready, completion = locations(value['name'])
    parent = CGROUP/str(Path(value['group']).parent).removeprefix('/')
    if value['group'].startswith('/native-fixture/'):
        parent.mkdir(exist_ok=True)
        (parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
    group = CGROUP/value['group'].removeprefix('/')
    group.mkdir()
    for name, body in {'memory.max':str(value['memory']), 'memory.swap.max':'0', 'pids.max':str(value['pids']),
                       'cpu.max':str(value['milli_cpus']*100)+' 100000'}.items():
        (group/name).write_text(body)
        if (group/name).read_text().strip() != body: raise ValueError('VM fixture limit readback differs')
    descriptor = os.open(group/'cgroup.procs', os.O_WRONLY|os.O_CLOEXEC)
    def enter():
        os.write(descriptor, str(os.getpid()).encode())
        os.close(descriptor)
        os.setgroups([]); os.setgid(value['gid']); os.setuid(value['uid'])
    with (ROOT/(value['name']+'-stdout')).open('xb') as output:
        child = subprocess.Popen(value['argv'], preexec_fn=enter, pass_fds=(descriptor,), stdout=output, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True,
            env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':value['home'],'LANG':'C.UTF-8'})
    os.close(descriptor)
    write(ready, {'name':value['name'], 'group':value['group'], 'pid':child.pid,
        'supervisor_pid':os.getpid(), 'spec_sha256':hashlib.sha256(spec.read_bytes()).hexdigest()})
    timed_out = False
    try: code = child.wait(timeout=value['seconds'])
    except subprocess.TimeoutExpired:
        timed_out = True; (group/'cgroup.kill').write_text('1'); code = child.wait(timeout=5)
    (group/'cgroup.kill').write_text('1')
    until = time.monotonic()+5
    while populated(value['group']):
        if time.monotonic() >= until: raise ValueError('owned VM fixture descendants remained live')
        time.sleep(.02)
    counters = dict(line.split() for line in (group/'cpu.stat').read_text().splitlines())
    write(completion, {'name':value['name'], 'group':value['group'], 'exit_code':code, 'timed_out':timed_out,
        'cpu_usage_usec':int(counters['usage_usec']), 'spec_sha256':hashlib.sha256(spec.read_bytes()).hexdigest(),
        'populated':False})
    group.rmdir()


if __name__ == '__main__':
    worker(Path(sys.argv[1]))
