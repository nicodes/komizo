"""Fixed-budget measurements inside the owned 1 CPU/1 GiB lifecycle guest."""
import hashlib
import json
import math
from pathlib import Path
import subprocess
import time


def evaluate(metrics, budget):
    scalars = ('setup_seconds', 'deployment_seconds', 'idle_control_pss_bytes')
    for name in scalars:
        value = metrics[name]
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= budget[name]:
            raise ValueError('performance budget refused: '+name)
    for name, limit in (('route_seconds', budget['route_seconds']), ('operator_seconds', budget['operator_seconds'])):
        samples = metrics[name]
        if len(samples) != budget['samples'] or any(type(v) not in (int, float) or not math.isfinite(v) or not 0 < v <= limit for v in samples):
            raise ValueError('performance budget refused: '+name)
    if metrics['load_hot_bytes'] != budget['load_memory_bytes'] or metrics['load_cpu_usec'] < 1_000_000:
        raise ValueError('positive bounded memory/CPU load was not observed')
    processes=metrics['control_processes'];services=metrics['control_services_running']
    if set(services)!={'rootd','serve','agent'} or services['rootd'] is not True or any(sum(row['role']==role for row in processes)!=int(running) for role,running in services.items()) or sum(row['pss_bytes'] for row in processes)!=metrics['idle_control_pss_bytes']:
        raise ValueError('control service/process identity differs')
    if not metrics['oom_events_unchanged'] or not metrics['owned_load_removed']:
        raise ValueError('performance load did not preserve its boundary')
    return True


def measure(fixture, cli, env, address, probe, setup_seconds, deployment_seconds):
    path = Path(__file__).with_name('acceptance-budgets.json')
    budget = json.loads(path.read_bytes())
    metrics = {'setup_seconds': setup_seconds, 'deployment_seconds': deployment_seconds,
               'route_seconds': [], 'operator_seconds': []}
    controls=json.loads(fixture.python("""import hashlib,json,subprocess
+roles={'rootd':'komizo-rootd','serve':'komizo-api','agent':'komizo-agent'}
+rows=[]
+for p in Path('/proc').iterdir():
+ if not p.name.isdecimal():continue
+ try:
+  args=(p/'cmdline').read_bytes().split(bytes([0]))
+  if len(args)<2 or args[1].decode(errors='replace') not in roles:continue
+  executable=str((p/'exe').resolve()).removesuffix(' (deleted)')
+  if executable!='/usr/local/bin/komizo-box':continue
+  role=args[1].decode()
+  pss=sum(int(line.split()[1])*1024 for line in (p/'smaps_rollup').read_text().splitlines() if line.startswith('Pss:'))
+  rows.append({'role':role,'pid':int(p.name),'pss_bytes':pss,'executable_sha256':hashlib.sha256((p/'exe').read_bytes()).hexdigest()})
+ except (FileNotFoundError,ProcessLookupError):pass
+status={role:subprocess.run(['rc-service',service,'status'],capture_output=True).returncode==0 for role,service in roles.items()}
+assert status['rootd']
+assert all(sum(row['role']==role for row in rows)==int(running) for role,running in status.items())
+print(json.dumps({'processes':rows,'services_running':status}))
+""".replace('\n+','\n')))
    (fixture.output/'idle-controls.json').write_text(json.dumps(controls,indent=2)+'\n')
    metrics['control_processes']=controls['processes']
    metrics['control_services_running']=controls['services_running']
    metrics['idle_control_pss_bytes']=sum(row['pss_bytes'] for row in controls['processes'])
    before = fixture.python("import json\nroot=Path('/sys/fs/cgroup');print(json.dumps({k:int(v) for k,v in (line.split() for line in (root/'memory.events').read_text().splitlines()) if k.startswith('oom')}))")
    leaf = '/sys/fs/cgroup/komizo-production/komizo-performance'
    fixture.python("p=Path("+repr(leaf)+");p.mkdir();(p/'memory.max').write_text('100663296');(p/'memory.swap.max').write_text('0');(p/'pids.max').write_text('8');(p/'cpu.max').write_text('20000 100000')")
    worker = """import json,os,time
from pathlib import Path
Path(LEAF+'/cgroup.procs').write_text(str(os.getpid()))
os.setgroups([]);os.setgid(65534);os.setuid(65534)
hot=bytearray(HOT)
for offset in range(0,len(hot),4096):hot[offset]=1
print(json.dumps({'hot_bytes':len(hot)}),flush=True)
end=time.monotonic()+SECONDS
while time.monotonic()<end:
 for offset in range(0,len(hot),4096):hot[offset]=(hot[offset]+1)&255
""".replace('LEAF', repr(leaf)).replace('HOT', str(budget['load_memory_bytes'])).replace('SECONDS', str(budget['load_seconds']))
    proc = subprocess.Popen(['docker','exec',fixture.cid,'python3','-I','-c',worker],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        import select
        if not select.select([proc.stdout],[],[],15)[0]:
            raise ValueError('performance worker did not touch memory')
        metrics['load_hot_bytes'] = json.loads(proc.stdout.readline())['hot_bytes']
        for _ in range(budget['samples']):
            if proc.poll() is not None:
                raise ValueError('performance load ended before the samples')
            start = time.monotonic();probe();metrics['route_seconds'].append(time.monotonic()-start)
            start = time.monotonic()
            result = subprocess.run([str(cli),'--json','doctor','--host',address],env=env,capture_output=True,timeout=budget['operator_seconds'])
            metrics['operator_seconds'].append(time.monotonic()-start)
            if result.returncode or not json.loads(result.stdout)['ok']:
                raise ValueError('operator read failed under load')
            time.sleep(.25)
        _, errors = proc.communicate(timeout=budget['load_seconds']+15)
        if proc.returncode:
            raise ValueError('performance worker failed: '+errors.decode(errors='replace')[-512:])
        metrics['load_cpu_usec'] = int(fixture.python("p=Path("+repr(leaf)+");print(dict(line.split() for line in (p/'cpu.stat').read_text().splitlines())['usage_usec'])").strip())
    finally:
        # The enclosing native fixture also removes the entire owned guest on
        # any observer failure. This leaf never exists on a real application host.
        fixture.python("import os,signal,time\np=Path("+repr(leaf)+")\nfor pid in (p/'cgroup.procs').read_text().split():\n try:os.kill(int(pid),signal.SIGKILL)\n except ProcessLookupError:pass\nend=time.monotonic()+5\nwhile (p/'cgroup.procs').read_text().strip() and time.monotonic()<end:time.sleep(.05)\np.rmdir()")
        proc.communicate(timeout=10)
    after = fixture.python("import json\nroot=Path('/sys/fs/cgroup');print(json.dumps({k:int(v) for k,v in (line.split() for line in (root/'memory.events').read_text().splitlines()) if k.startswith('oom')}))")
    metrics.update(oom_events_unchanged=json.loads(before)==json.loads(after),owned_load_removed=True)
    result = {'version':1,'budget':budget,'budget_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'metrics':metrics,'accepted':False,
              'scope':'fixed 1 CPU/1 GiB disposable guest, 64 MiB touched background memory and 200m CPU for 15 seconds; sequential TLS and SSH prerequisite reads; no universal capacity or production SLO claim'}
    (fixture.output/'performance.json').write_text(json.dumps(result,indent=2)+'\n')
    result['accepted'] = evaluate(metrics,budget)
    (fixture.output/'performance.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
