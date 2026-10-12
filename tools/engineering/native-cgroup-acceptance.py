#!/usr/bin/env python3
"""Exercise shared service limits in a disposable local Docker cgroup namespace.

This is a Linux kernel fixture, not product, installer or OS-boot acceptance.
It intentionally OOM-kills synthetic workers inside their own application group.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid


PROGRAM = r'''
import json,os,select,signal,subprocess,time
from pathlib import Path
root=Path('/sys/fs/cgroup')
assert (root/'memory.max').read_text().strip()==str(1<<30)
assert Path('/proc/1/cgroup').read_text().strip()=='0::/'
assert {'cpu','memory','pids'} <= set((root/'cgroup.controllers').read_text().split())
host=root/'acceptance-host';host.mkdir()
for pid in (root/'cgroup.procs').read_text().split():
 try:(host/'cgroup.procs').write_text(pid)
 except ProcessLookupError:pass
(root/'cgroup.subtree_control').write_text('+cpu +memory +pids')
parent=root/'komizo-production';parent.mkdir()
def limits(path,memory,cpu,pids):
 for name,value in {'memory.max':str(memory),'memory.swap.max':'0','cpu.max':str(cpu)+' 100000','pids.max':str(pids)}.items():
  (path/name).write_text(value)
limits(parent,64<<20,60000,128)
(parent/'cgroup.subtree_control').write_text('+cpu +memory +pids')
app=parent/'producer';app.mkdir();limits(app,48<<20,20000,32)
# This phase tests the hard boundary. A lower soft threshold can throttle the
# allocation before it reaches memory.max and is a separate pressure fixture.
(app/'memory.low').write_text(str(16<<20));(app/'memory.high').write_text(str(48<<20))
(app/'cgroup.subtree_control').write_text('+cpu +memory +pids')
services=[]
for name in ['first','second']:
 path=app/name;path.mkdir();limits(path,32<<20,10000,16);services.append(path)
neighbor=parent/'neighbor';neighbor.mkdir();limits(neighbor,32<<20,10000,16)
(neighbor/'memory.low').write_text(str(16<<20))
children=[]
def child(path,code):
 p=subprocess.Popen(['python3','-I','-c','import sys,time;assert sys.stdin.buffer.read(1)==b"g";'+code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 children.append(p);(path/'cgroup.procs').write_text(str(p.pid));p.stdin.write(b'g');p.stdin.flush();return p
def line(p):
 assert select.select([p.stdout],[],[],1)[0],'synthetic core read exceeded one second'
 return p.stdout.readline()
events=lambda path,local=False:{k:int(v) for k,v in (row.split() for row in (path/('memory.events.local' if local else 'memory.events')).read_text().splitlines())}
before={'app':events(app),'neighbor':events(neighbor),'parent':events(parent,True),'root':events(root,True)}
try:
 peer=child(neighbor,'data=bytearray(12<<20);print("ready",flush=True)\nwhile sys.stdin.buffer.read(1)==b"p":print("pong",flush=True)')
 assert line(peer)==b'ready\n'
 workers=[child(path,'data=bytearray(28<<20);end=time.monotonic()+25\nwhile time.monotonic()<end:\n for offset in range(0,len(data),4096):data[offset]=(data[offset]+1)%256') for path in services]
 deadline=time.monotonic()+20;latencies=[]
 while events(app)['oom_kill']==before['app']['oom_kill']:
  for worker in workers:
   if worker.poll() is not None:
    assert worker.returncode in (0,-9),worker.stderr.read().decode()
  assert time.monotonic()<deadline,'shared hard limit did not refuse offered memory'
  start=time.monotonic();peer.stdin.write(b'p');peer.stdin.flush();assert line(peer)==b'pong\n';latencies.append(time.monotonic()-start);time.sleep(.05)
 for _ in range(20):
  start=time.monotonic();peer.stdin.write(b'p');peer.stdin.flush();assert line(peer)==b'pong\n';latencies.append(time.monotonic()-start)
 assert peer.poll() is None
 after={'app':events(app),'neighbor':events(neighbor),'parent':events(parent,True),'root':events(root,True)}
 assert after['neighbor']['oom_kill']==before['neighbor']['oom_kill']
 assert after['parent']['oom']==before['parent']['oom'] and after['root']['oom']==before['root']['oom']
 assert after['app']['oom_kill']>before['app']['oom_kill']
 print(json.dumps({'version':1,'scope':'native synthetic kernel boundary only; no product or OS boot acceptance','service_limits_bytes':[32<<20,32<<20],'offered_worker_bytes':[28<<20,28<<20],'shared_application_limit_bytes':48<<20,'production_limit_bytes':64<<20,'neighbor_offered_bytes':12<<20,'neighbor_core_deadline_seconds':1,'neighbor_core_latencies_seconds':latencies,'before':before,'after':after,'intentional_worker_oom_observed':True,'neighbor_survived':True,'provider_calls':False,'real_data_accessed':False}))
finally:
 for p in children:
  if p.poll() is None:os.killpg(p.pid,signal.SIGKILL)
 for p in children:p.wait(timeout=10)
'''


def run(args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=90, **kwargs)
    if result.returncode:
        raise RuntimeError('synthetic fixture refused: '+result.stderr.decode(errors='replace')[:4096])
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='immutable Alpine image with apk')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9./_-]+@sha256:[a-f0-9]{64}', args.image):
        raise ValueError('an immutable image reference is required')
    if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT'):
        raise ValueError('fixture requires an explicitly local default Docker context')
    endpoint = json.loads(run(['docker', 'context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}']).decode())
    if not endpoint.startswith('unix://'):
        raise ValueError('fixture refuses remote Docker endpoints')
    name = 'komizo-native-' + uuid.uuid4().hex[:12]
    cid = run(['docker', 'run', '-d', '--name', name, '--label', 'org.komizo.fixture='+name,
               '--privileged', '--cgroupns=private', '--init', '--cpus=1', '--memory=1g',
               '--memory-swap=1536m', '--pids-limit=512', args.image, 'sleep', '600']).decode().strip()
    if not re.fullmatch('[a-f0-9]{64}', cid):
        raise ValueError('invalid owned fixture identity')
    try:
        row = json.loads(run(['docker', 'inspect', cid]))[0]
        if (row['Id'] != cid or row['HostConfig']['Binds'] or row['Mounts']
                or row['HostConfig']['CgroupnsMode'] != 'private'
                or row['HostConfig']['PidMode'] or row['HostConfig']['PortBindings']
                or row['HostConfig']['Memory'] != 1 << 30
                or row['HostConfig']['MemorySwap'] != 1536 << 20
                or row['HostConfig']['NanoCpus'] != 1_000_000_000
                or row['HostConfig']['PidsLimit'] != 512
                or not row['HostConfig']['Init']
                or not row['HostConfig']['Privileged']
                or row['Config']['Labels'].get('org.komizo.fixture') != name):
            raise ValueError('fixture isolation differs')
        run(['docker', 'exec', cid, 'apk', 'add', '--no-cache', 'python3'])
        result = json.loads(run(['docker', 'exec', '-i', cid, 'python3', '-I', '-'], input=PROGRAM.encode()))
        result.update({'fixture_image':args.image, 'private_cgroup_namespace':True,
                       'host_mounts':False, 'docker_socket_mounted':False,
                       'executed_program_sha256':hashlib.sha256(PROGRAM.encode()).hexdigest(),
                       'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
        args.output.write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps({'accepted':True, 'scope':result['scope'],
                          'intentional_worker_oom_observed':True, 'neighbor_survived':True}))
    finally:
        row = json.loads(run(['docker', 'inspect', cid]))[0]
        if row['Id'] != cid or row['Config']['Labels'].get('org.komizo.fixture') != name:
            raise ValueError('refusing cleanup of foreign fixture')
        run(['docker', 'rm', '-f', cid])


if __name__ == '__main__':
    main()
