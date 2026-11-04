#!/usr/bin/env python3
"""Exercise bounded synthetic serving pressure using operator-owned inputs."""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse

SHA = re.compile('[a-f0-9]{40}')
HASH = re.compile('[a-f0-9]{64}')
APP = re.compile('[a-z][a-z0-9-]{0,63}')
BOX = '/usr/local/bin/komizo-box'

def validate(p):
    fields={'version','binary_sha256','resources_sha256','app_revisions','probes','cases'}
    if type(p.get('version')) is not int or p['version'] not in (1,2):
        raise ValueError('unsupported workload profile')
    if p['version']==2:
        fields.add('probe_interval_seconds')
        interval=p.get('probe_interval_seconds')
        if type(interval) is not int or not 1<=interval<=10:raise ValueError('finite declared probe cadence required')
    if set(p) != fields:
        raise ValueError('unsupported workload profile')
    if not HASH.fullmatch(p['binary_sha256']) or not HASH.fullmatch(p['resources_sha256']):
        raise ValueError('exact installed binary and allocation hashes required')
    if not isinstance(p['app_revisions'],dict) or not 1 <= len(p['app_revisions']) <= 16:
        raise ValueError('finite application inventory required')
    if any(not APP.fullmatch(a) or not SHA.fullmatch(r) for a,r in p['app_revisions'].items()):
        raise ValueError('invalid application identity')
    if not 1 <= len(p['probes']) <= 32 or not 1 <= len(p['cases']) <= 8:
        raise ValueError('finite probe and case inventory required')
    for probe in p['probes']:
        if set(probe) != {'url','app','revision'} or probe['app'] not in p['app_revisions'] or probe['revision'] != p['app_revisions'][probe['app']]:
            raise ValueError('probe identity differs')
        u=urllib.parse.urlsplit(probe['url'])
        if u.scheme not in ('https','wss') or not u.hostname or u.username or u.password or u.query or u.fragment or len(probe['url'])>512:
            raise ValueError('probe must be a literal bounded TLS read')
    for case in p['cases']:
        if set(case) != {'app','operator','repetitions'} or case['app'] not in p['app_revisions'] or case['operator'] not in ('full_inventory','operation_inspection') or type(case['repetitions']) is not int or not 1 <= case['repetitions'] <= 3:
            raise ValueError('unsupported workload case')
    return p

def probe_route(probe):
    u=urllib.parse.urlsplit(probe['url']);c=http.client.HTTPSConnection(u.hostname,u.port,timeout=2)
    start=time.monotonic();phase='request'
    try:
        headers={'Cache-Control':'no-cache'};expected=None
        if u.scheme=='wss':
            key=base64.b64encode(os.urandom(16)).decode()
            expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            headers.update({'Connection':'Upgrade','Upgrade':'websocket','Sec-WebSocket-Version':'13','Sec-WebSocket-Key':key})
        c.request('GET',u.path or '/',headers=headers);phase='headers';r=c.getresponse()
        ok=r.getheader('X-Komizo-Revision')==probe['revision']
        if expected:ok=ok and r.status==101 and r.getheader('Upgrade','').lower()=='websocket' and r.getheader('Sec-WebSocket-Accept')==expected
        else:
            phase='body'
            nonempty=bool(r.read(512).strip())
            ok=ok and r.status==200 and nonempty
        elapsed=time.monotonic()-start
        if not ok or elapsed>=2:
            raise AssertionError(json.dumps({'contract':'core_read','url':probe['url'],'seconds':elapsed,'http_status':r.status,'revision_matches':r.getheader('X-Komizo-Revision')==probe['revision'],'content_present':nonempty if expected is None else None,'upgrade_matches':r.getheader('Sec-WebSocket-Accept')==expected if expected is not None else None},sort_keys=True))
        return elapsed
    except (OSError,http.client.HTTPException) as error:
        raise AssertionError(json.dumps({'contract':'core_read','url':probe['url'],'seconds':time.monotonic()-start,'phase':phase,'error_kind':type(error).__name__},sort_keys=True)) from error
    finally:c.close()

def command(args,timeout=20):
    return subprocess.check_output(args,timeout=timeout)

def local_docker_inventory(socket_path='/var/run/docker.sock'):
    class LocalConnection(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout);self.sock.connect(socket_path)
    connection=LocalConnection('localhost',timeout=8)
    deadline=time.monotonic()+20;remaining_bytes=32<<20
    def read(path,maximum):
        nonlocal remaining_bytes
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('local inventory deadline exceeded')
        connection.timeout=min(8,remaining)
        if connection.sock is not None:connection.sock.settimeout(connection.timeout)
        maximum=min(maximum,remaining_bytes)
        connection.request('GET',path)
        active_socket=connection.sock
        response=connection.getresponse()
        if response.status!=200:raise ValueError('local inventory unavailable')
        pieces=[];size=0
        while size<=maximum:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('local inventory deadline exceeded')
            active_socket.settimeout(min(8,remaining))
            piece=response.read1(min(65536,maximum+1-size))
            if not piece:break
            pieces.append(piece);size+=len(piece)
        body=b''.join(pieces)
        if len(body)>maximum:raise ValueError('local inventory exceeds its bound')
        remaining_bytes-=len(body)
        return json.loads(body)
    try:
        rows=read('/v1.47/containers/json',8<<20)
        if not isinstance(rows,list) or len(rows)>1024:raise ValueError('finite local inventory required')
        out=[]
        for row in rows:
            cid=row.get('Id')
            if not isinstance(cid,str) or not HASH.fullmatch(cid):raise ValueError('local container identity invalid')
            item=read('/v1.47/containers/'+cid+'/json',4<<20)
            if item.get('Id')!=cid or item.get('State',{}).get('Running') is not True:raise ValueError('running local identity differs')
            out.append(item)
        return out
    finally:connection.close()

def identity(p):
    rows=local_docker_inventory()
    containers={r['Id']:{'pid':r['State']['Pid'],'started':r['State']['StartedAt'],'image':r['Image'],'env_sha256':hashlib.sha256(json.dumps(r['Config']['Env'],sort_keys=True).encode()).hexdigest()} for r in rows if r['Config']['Labels'].get('com.docker.compose.project') in p['app_revisions']}
    paths=[Path('/etc/komizo/resources.json'),Path('/etc/komizo/agent.json')]
    for a in p['app_revisions']:paths.extend([Path('/srv')/a/'.env',Path('/etc/komizo/workloads')/(a+'.json'),Path('/var/lib/komizo/releases')/a/'operation.json'])
    return {'containers':containers,'files':{str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in paths},'fences_clear':not any((Path('/var/lib/komizo')/n/'pending.json').exists() for n in ('activations','upgrades'))}

def snapshot(groups):
    result={}
    for g in groups:
        row={k:(g/k).read_text() for k in ('memory.current','memory.swap.current','memory.events','memory.high','memory.max','cpu.stat','io.stat')}
        charges=dict((k,int(v)) for k,v in (line.split() for line in (g/'memory.stat').read_text().splitlines()))
        row['memory_charges']={k:charges.get(k) for k in ('anon','file','kernel','inactive_file')}
        row['memory_activity']={k:charges.get(k) for k in ('workingset_refault_file','pgscan','pgsteal')}
        result[str(g)]=row
    return result

def wait_for_probe_round(round_started,interval):
    delay=max(0,round_started+interval-time.monotonic())
    if delay:time.sleep(delay)

def verify_control_limits(policy,root=Path('/sys/fs/cgroup')):
    fields={'memory.low':'memory_low_bytes','memory.high':'memory_high_bytes','memory.max':'memory_bytes','memory.swap.max':'swap_bytes','pids.max':'pids','cpu.weight':'cpu_weight'}
    for name,group in policy.get('controls',{}).items():
        if name not in ('openrc.docker','openrc.komizo-rootd','openrc.komizo-api','openrc.sshd'):raise ValueError('unknown control group')
        expected={key:str(group[value]) for key,value in fields.items()};expected['cpu.max']='max 100000'
        for key,value in expected.items():
            actual=(root/name/key).read_text().strip()
            if actual!=value:raise AssertionError(json.dumps({'contract':'control_policy','group':name,'field':key,'expected':value,'actual':actual},sort_keys=True))

def hot_memory_worker(root,target,offered,seconds=40):
    # Reclaim and compressed swap can change a sibling's charge after readiness.
    # Keep refilling within the same finite offer while touching every hot page.
    return "import time,json;from pathlib import Path;chunks=[];charged=Path("+repr(str(root/'memory.current'))+")\ndef fill():\n while not chunks or int(charged.read_text())<"+str(target)+":\n  if sum(map(len,chunks))+(4<<20)>"+str(offered)+":raise RuntimeError('hot memory offer exhausted')\n  data=bytearray(4<<20)\n  for offset in range(0,len(data),4096):data[offset]=1\n  chunks.append(data);time.sleep(.02)\nfill()\nprint(json.dumps({'ready':True,'hot_bytes':sum(map(len,chunks))}),flush=True);end=time.monotonic()+"+str(seconds)+"\nwhile time.monotonic()<end:\n fill()\n for data in chunks:\n  for offset in range(0,len(data),4096):data[offset]=(data[offset]+1)%256\nprint(json.dumps({'peak_hot_bytes':sum(map(len,chunks))}),flush=True)"

def fixture_guard(leaf,seconds=120):
    # Hold the exact kernel interface, not a PID/name/path resolved after timeout.
    # The guard stays outside the synthetic leaf and survives client loss.
    kill=os.open(leaf/'cgroup.kill',os.O_WRONLY|os.O_NOFOLLOW)
    read,write=os.pipe()
    source='''import os,select,sys,time
kill,read=int(sys.argv[1]),int(sys.argv[2]);deadline=time.monotonic()+float(sys.argv[3])
reason='deadline'
while time.monotonic()<deadline:
 if select.select([read],[],[],max(0,deadline-time.monotonic()))[0]:
  if os.read(read,1)==b'd':print('completed',flush=True);raise SystemExit(0)
  reason='parent_lost';break
os.write(kill,b'1');print(reason,flush=True)
'''
    try:
        guard=subprocess.Popen([sys.executable,'-I','-c',source,str(kill),str(read),str(seconds)],pass_fds=(kill,read),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
    except BaseException:
        os.close(write);raise
    finally:
        os.close(kill);os.close(read)
    return guard,write

def finish_fixture_guard(guard,write):
    try:
        os.write(write,b'd')
    except BrokenPipeError:pass
    finally:os.close(write)
    result=guard.communicate(timeout=5)[0]
    if guard.returncode or result!=b'completed\n':raise RuntimeError('fixture guard fired or failed; pressure is not accepted')

def progress(stage,app,**values):
    print(json.dumps({'stage':stage,'app':app,**values},sort_keys=True),file=sys.stderr,flush=True)

def operation_observation_ready(report, app):
    # Root reconciliation is a stable serving state. The public lifecycle uses
    # the same vocabulary; an interrupted or stopped operation is not ready.
    operation=report.get('operation',{})
    return (operation.get('app')==app
            and operation.get('phase') in ('ready','reconciled')
            and report.get('private_bodies_omitted') is True)

def run_case(p,case,repetition):
    host_policy=json.loads(Path('/etc/komizo/resources.json').read_bytes())
    verify_control_limits(host_policy)
    app=case['app'];parent=Path('/sys/fs/cgroup/komizo-production');root=parent/app
    policy=json.loads((Path('/etc/komizo/workloads')/(app+'.json')).read_bytes())
    allowance=policy['resources']['startup_allowance_bytes'];high=int((root/'memory.high').read_text());hard=int((root/'memory.max').read_text())
    target=high-allowance+(12<<20);offered=hard-(32<<20)
    if not 16<<20 <= offered <= 1<<30:raise ValueError('unsupported finite pressure envelope')
    baseline={q['url']:probe_route(q) for q in p['probes']};unchanged=identity(p)
    if not unchanged['fences_clear']:raise ValueError('host recovery fence must be clear')
    groups=[parent,*[parent/a for a in p['app_revisions'] if (parent/a).is_dir()]]
    groups.extend(g for g in (parent.parent/n for n in ('openrc.docker','openrc.komizo-rootd','openrc.komizo-api','openrc.sshd')) if g.is_dir())
    before=snapshot(groups);leaf=root/('acceptance-'+os.urandom(5).hex());scratch=Path('/srv')/('komizo-synthetic-'+os.urandom(5).hex())
    children=[];guard=None
    result={'app':app,'operator':case['operator'],'repetition':repetition,'baseline_seconds':baseline,'before':before,'accepted':False,'cleanup':False,'latencies_seconds':{q['url']:[] for q in p['probes']},'operator_seconds':[]}
    def child(code):
        worker=subprocess.Popen(['python3','-I','-c','import sys,os;assert sys.stdin.buffer.read(1)==b"g";os.setgroups([]);os.setgid(65534);os.setuid(65534);'+code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        children.append(worker);(leaf/'cgroup.procs').write_text(str(worker.pid));worker.stdin.write(b'g');worker.stdin.close();return worker
    try:
        leaf.mkdir();scratch.mkdir(mode=0o700);os.chown(scratch,65534,65534)
        for name,value in [('memory.max',str(offered+(16<<20))),('memory.swap.max','0'),('pids.max','16'),('cpu.max','20000 100000')]: (leaf/name).write_text(value)
        guard,lease=fixture_guard(leaf)
        progress('allocated',app,leaf=str(leaf),scratch=str(scratch))
        memory=child(hot_memory_worker(root,target,offered))
        if not select.select([memory.stdout],[],[],30)[0]:raise AssertionError('hot pages not ready')
        ready=json.loads(memory.stdout.readline());result['actual_hot_memory_bytes']=ready['hot_bytes'];result['maximum_offered_hot_memory_bytes']=offered
        if ready.get('ready') is not True or type(ready.get('hot_bytes')) is not int or not 4<<20 <= ready['hot_bytes'] <= offered:raise AssertionError('positive touched hot memory required')
        result['pressure']=snapshot(groups)
        progress('pressure_ready',app,hot_bytes=ready['hot_bytes'],groups=result['pressure'])
        if int((root/'memory.current').read_text())<=high-allowance+(8<<20):raise AssertionError('pressure target absent')
        refusal=subprocess.run([BOX,'workload','startup-check','--policy','/etc/komizo/workloads/'+app+'.json'],capture_output=True,timeout=20)
        if refusal.returncode==0 or b'application serving pressure refuses startup' not in refusal.stderr or identity(p)!=unchanged:raise AssertionError('startup did not refuse before effects')
        result['startup_refused_before_effects']=True
        writer=child('import os,time,json;from pathlib import Path;p=Path('+repr(str(scratch/'io.bin'))+');start=time.monotonic()\nwith p.open("xb",buffering=0) as f:\n for index in range(8):f.write(b"x"*(1<<20));os.fsync(f.fileno())\nprint(json.dumps({"bytes":8<<20,"seconds":time.monotonic()-start}),flush=True)')
        started=time.monotonic();samples=[]
        while memory.poll() is None:
            if time.monotonic()-started>65:raise AssertionError('pressure deadline exceeded')
            round_started=time.monotonic()
            for q in p['probes']:result['latencies_seconds'][q['url']].append(probe_route(q))
            start=time.monotonic()
            if case['operator']=='full_inventory':
                report=json.loads(command([BOX,'report'],10))
                if report['server']['state']!='ready' or report.get('inventory',{}).get('status')!='current':raise AssertionError('full observation unavailable')
                revisions={a['name']:a['version'] for a in report['apps']}
                if any(revisions.get(a)!=r for a,r in p['app_revisions'].items()):raise AssertionError('serving source changed')
            else:
                report=json.loads(command([BOX,'workload','inspect','--policy','/etc/komizo/workloads/'+app+'.json'],10))
                if not operation_observation_ready(report,app):raise AssertionError('operation observation unavailable')
            elapsed=time.monotonic()-start;result['operator_seconds'].append(elapsed)
            if elapsed>=5:raise AssertionError('operator exceeded five seconds')
            samples.append(snapshot(groups))
            if p['version']==2:wait_for_probe_round(round_started,p['probe_interval_seconds'])
            else:time.sleep(.5) # Retain the historical v1 workload definition.
        if memory.returncode!=0 or writer.wait(timeout=15)!=0:raise AssertionError('synthetic worker failed')
        final_hot=json.loads(memory.stdout.read());peak=final_hot.get('peak_hot_bytes')
        if type(peak) is not int or not ready['hot_bytes']<=peak<=offered:raise AssertionError('bounded held hot memory unavailable')
        result['peak_hot_memory_bytes']=peak
        io=json.loads(writer.stdout.read());result['io_transfer']=io
        if io['bytes']!=8<<20 or io['seconds']<.75:raise AssertionError('fsync workload differs')
        after=snapshot(groups);result['after']=after;result['samples']=samples
        if identity(p)!=unchanged:raise AssertionError('private identity changed')
        verify_control_limits(host_policy)
        for group in before:
            def events(s):return dict((k,int(v)) for k,v in (l.split() for l in s[group]['memory.events'].splitlines()))
            if any(events(after)[k]!=events(before)[k] for k in ('oom','oom_kill')):raise AssertionError('new OOM event')
        if not all(result['latencies_seconds'].values()) or not result['operator_seconds']:raise AssertionError('empty pressure reading')
        result.update(accepted=True,private_identity_preserved=True,oom_delta=0)
    except Exception as error:
        result.update(error_type=type(error).__name__,error=str(error) if isinstance(error,AssertionError) else 'fixture failed; inspect retained measurements',after_failure=snapshot(groups),private_identity_preserved=identity(p)==unchanged)
    finally:
        try:
            for worker in children:
                if worker.poll() is None:os.killpg(worker.pid,signal.SIGKILL)
                worker.wait(timeout=30)
                for stream in [worker.stdout,worker.stderr]:stream.close()
            if guard is not None:
                try:finish_fixture_guard(guard,lease)
                except RuntimeError:result.update(accepted=False,guard_fired=True)
            if scratch.exists():shutil.rmtree(scratch)
            if leaf.exists():leaf.rmdir()
            result['cleanup']=True
        except Exception:
            result.update(accepted=False,cleanup_error='owned fixture cleanup requires inspection')
        progress('finished',app,accepted=result['accepted'],cleanup=result['cleanup'])
    return result

def run(p):
    validate(p)
    if os.geteuid()!=0:raise ValueError('pressure acceptance requires the trusted host operator')
    if hashlib.sha256(Path(BOX).read_bytes()).hexdigest()!=p['binary_sha256'] or hashlib.sha256(Path('/etc/komizo/resources.json').read_bytes()).hexdigest()!=p['resources_sha256']:raise ValueError('installed identity differs from profile')
    results=[]
    for case in p['cases']:
        for repetition in range(case['repetitions']):
            try:result=run_case(p,case,repetition)
            except Exception as error:result={'app':case['app'],'operator':case['operator'],'repetition':repetition,'accepted':False,'attempted':True,'error_type':type(error).__name__,'error':str(error)[:2048]}
            results.append(result)
    return {'version':p['version'],'probe_interval_seconds':p.get('probe_interval_seconds'),'observed_at_unix':time.time(),'profile_sha256':hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest(),'binary_sha256':p['binary_sha256'],'resources_sha256':p['resources_sha256'],'results':results,'accepted':bool(results) and all(r['accepted'] and r.get('cleanup') for r in results),'provider_calls':False,'real_backup_restore':False,'scope':'declared sequential host-origin TLS/WSS reads below two seconds; touched hot memory and 200m CPU for forty seconds; eight 1MiB fsync writes; startup refusal before effects; chosen fresh full report or light operation inspection below five seconds; no universal or concurrent-request SLO'}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--profile',type=Path,required=True);p.add_argument('--host');p.add_argument('--output',type=Path,required=True)
    args=p.parse_args(argv);raw=args.profile.read_bytes()
    if len(raw)>32768:raise ValueError('profile too large')
    profile=validate(json.loads(raw))
    if args.output.exists() or args.output.is_symlink():raise ValueError('new output file required')
    args.output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if args.host:
        if not re.fullmatch(r'root@[a-z0-9]+(?:[.-][a-z0-9]+)+',args.host):raise ValueError('literal trusted operator host required')
        source=globals().get('_SOURCE') or Path(__file__).read_text()
        source=source[:source.rindex("if __name__")]+"\nfor _signal in [signal.SIGHUP,signal.SIGTERM,signal.SIGINT]:signal.signal(_signal,lambda *_: (_ for _ in ()).throw(InterruptedError()))\nprint(json.dumps(run("+repr(profile)+")),flush=True)\n"
        # Charge the observer/guard to the existing Rootd control envelope before
        # Python starts; the recovery SSH daemon retains its independent reserve.
        remote='test -f /sys/fs/cgroup/openrc.komizo-rootd/cgroup.procs && echo $$ > /sys/fs/cgroup/openrc.komizo-rootd/cgroup.procs && exec python3 -I -'
        proc=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=10',args.host,remote],input=source.encode(),stdout=subprocess.PIPE,timeout=1800)
        if proc.returncode:raise ValueError('remote fixture failed; no acceptance inferred')
        if len(proc.stdout)>8<<20:raise ValueError('fixture evidence exceeds its bound')
        result=json.loads(proc.stdout)
    else:result=run(profile)
    with args.output.open('x') as f:os.chmod(args.output,0o600);json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({'accepted':result['accepted'],'results':len(result['results']),'evidence':str(args.output)}));return int(not result['accepted'])

if __name__=='__main__':raise SystemExit(main())
