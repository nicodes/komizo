#!/usr/bin/env python3
"""Real native release effects against a private fixture registry inside the VM."""
import copy
import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time
import urllib.request

from acceptance import ROOT, BINARY, MiB, run, write, actual_boundaries, capacity, service_active, service_pid, restart_controller, profile_probe, ready_notifications_absent
import fixture_registry as registry
try:
    import fixture_tasks
except ModuleNotFoundError:
    import importlib.util
    _task_spec=importlib.util.spec_from_file_location('fixture_tasks',Path(__file__).with_name('native_host_fixture.py'))
    fixture_tasks=importlib.util.module_from_spec(_task_spec);_task_spec.loader.exec_module(fixture_tasks)


def limits(memory=32,cpu=200,pids=32):
    return {'memory_bytes':memory*MiB,'memory_swap_bytes':memory*MiB,'milli_cpus':cpu,'pids':pids}


def until(check, seconds=30):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            value=check()
            if value:return value
        except (OSError,ValueError,subprocess.SubprocessError):pass
        time.sleep(.2)
    raise ValueError('native runtime fixture deadline expired')


def proxy_stack_projection(raw, deadline=None):
    import re
    if len(raw)>512<<10:raise ValueError('proxy profile exceeds its fixed raw bound')
    states={'running':'running','runnable':'runnable','IO wait':'io_wait','select':'select',
        'semacquire':'semaphore','sync.Mutex.Lock':'mutex','sync.RWMutex.Lock':'mutex',
        'chan receive':'channel_receive','chan send':'channel_send','sleep':'sleep',
        'GC worker (idle)':'gc_idle','GC assist wait':'gc_wait'}
    def priority(name):return any(word in name.lower() for word in ['load','config','stop','cleanup'])
    rows=[];current=None
    for index,line in enumerate(raw.decode(errors='replace').splitlines()):
        if deadline is not None and index%64==0 and time.monotonic()>=deadline:raise TimeoutError()
        header=re.fullmatch(r'goroutine ([0-9]{1,16}) \[([^\]\r\n]{1,160})\]:',line)
        if header:
            if len(rows)>=512:break
            current={'id':int(header[1]),'state':states.get(header[2].split(',',1)[0],'other'),'functions':[]}
            rows.append(current)
        elif current is not None and not line.startswith(('\t','created by ')) and '(' in line:
            symbol,_,tail=line.partition('(')
            if symbol.endswith('.'):
                receiver,separator,tail=tail.partition(').')
                if not separator or not re.fullmatch(r'\*?[A-Za-z_][A-Za-z0-9_\[\].*]{0,95}',receiver):continue
                method,separator,_=tail.partition('(')
                if not separator:continue
                symbol+='('+receiver+').'+method
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_./*()\[\]]{0,255}',symbol):continue
            name=symbol.rsplit('/',1)[-1]
            if '.' in name and not name.endswith('.go') and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.*()\[\]]{0,95}',name):
                functions=current['functions']
                if len(functions)<12:functions.append(name)
                elif priority(name) and name not in functions:
                    replace=next((index for index in range(11,-1,-1) if not priority(functions[index])),None)
                    if replace is not None:functions[replace]=name
    rows.sort(key=lambda row:(not any(priority(name) for name in row['functions']),row['id']))
    selected=rows[:24]
    return {'state':'observed','goroutines':selected,'omitted':len(rows)-len(selected),
        'goroutine_limit_reached':len(rows)==512,'raw_limit_reached':len(raw)==512<<10}


def proxy_cli_role(arguments):
    if arguments==['/usr/local/bin/caddy','adapt','--adapter','caddyfile','--config','/var/lib/komizo/proxy-staged.caddy']:return 'adapt'
    if arguments==['/usr/local/bin/caddy','reload','--adapter','caddyfile','--config','/etc/komizo-proxy/Caddyfile','--address','unix//run/komizo-proxy/admin.sock']:return 'reload'
    return None


def proxy_cli_snapshot(deadline):
    import stat
    if time.monotonic()>=deadline:raise TimeoutError()
    def read(path,limit):
        if time.monotonic()>=deadline:raise TimeoutError()
        with path.open('rb') as source:body=source.read(limit+1)
        if len(body)>limit:raise ValueError('process metadata exceeds fixed bound')
        return body
    def identity(pid):
        base=Path('/proc')/str(pid)
        fields=read(base/'stat',4096).decode().rsplit(') ',1)[1].split()
        uid=next(line for line in read(base/'status',8192).decode().splitlines() if line.startswith('Uid:'))
        if set(map(int,uid.split()[1:]))!={0}:raise ValueError('child owner differs')
        # An exited, still-unreaped child can have detached from its cgroup.
        # Count that owned zombie without inventing its unavailable executable.
        group=None if fields[0]=='Z' else read(base/'cgroup',512)
        return int(fields[1]),int(fields[19]),fields[0],group
    controller=service_pid('komizo-controller');_,birth,_,group=identity(controller)
    if group!=b'0::/komizo/control/controller\n':raise ValueError('controller group differs')
    tasks=[]
    for task in (Path('/proc')/str(controller)/'task').iterdir():
        if len(tasks)>=128:raise ValueError('controller task inventory exceeds bound')
        if task.name.isascii() and task.name.isdecimal():tasks.append(task)
    children=set()
    for task in tasks:
        values=read(task/'children',4096).split()
        if any(not value.isdigit() or len(value)>10 for value in values):raise ValueError('invalid direct child identity')
        children.update(map(int,values))
        if len(children)>64:raise ValueError('controller child inventory exceeds bound')
    binary=Path('/usr/local/bin/caddy');protected=binary.lstat()
    if not stat.S_ISREG(protected.st_mode) or protected.st_uid or protected.st_gid or protected.st_mode&0o022 or protected.st_nlink!=1:raise ValueError('proxy executable is not protected')
    result={'state':'observed','controller_pid':controller,'controller_start_ticks':birth,'total_children':len(children),
        'verified_children':0,'zombie_children':0,'unclassified_children':0,'unverified_children':0,'states':{},'caddy':[]}
    names={'R':'running','S':'sleeping','D':'disk_wait','Z':'zombie','T':'stopped','t':'stopped','X':'dead','I':'idle'}
    waits={'do_wait':'child_wait','pipe_read':'pipe_read','unix_stream_read_generic':'socket_read',
        'futex_wait_queue':'futex','futex_wait_queue_me':'futex','ep_poll':'poll','do_epoll_wait':'poll',
        'poll_schedule_timeout':'poll','wait_woken':'wait','hrtimer_nanosleep':'sleep','0':'running_or_hidden'}
    for pid in sorted(children):
        if time.monotonic()>=deadline:
            result['state']='deadline_expired';break
        descriptor=None
        try:
            descriptor=os.pidfd_open(pid);parent,start,state,group=identity(pid)
            if parent!=controller or start<=0:raise ValueError('child parent changed')
            if state!='Z' and group!=b'0::/komizo/control/controller\n':raise ValueError('child group differs')
            if identity(pid)[:2]!=(controller,start):raise ValueError('child generation changed')
            result['verified_children']+=1;label=names.get(state,'other')
            result['states'][label]=result['states'].get(label,0)+1
            if state=='Z':result['zombie_children']+=1
            result['unclassified_children']+=1
            base=Path('/proc')/str(pid)
            actual=(base/'exe').stat()
            if (actual.st_dev,actual.st_ino)!=(protected.st_dev,protected.st_ino):continue
            arguments=read(base/'cmdline',8192).removesuffix(b'\0').decode().split('\0')
            role=proxy_cli_role(arguments)
            if role is None:continue
            wchan=waits.get(read(base/'wchan',128).decode().strip(),'other')
            after_parent,after_start,after_state,after_group=identity(pid)
            if (after_parent,after_start)!=(controller,start):raise ValueError('child generation changed')
            if after_state!='Z' and after_group!=b'0::/komizo/control/controller\n':raise ValueError('child group changed')
            result['unclassified_children']-=1
            result['caddy'].append({'role':role,'pid':pid,'start_ticks':start,'process_state':names.get(after_state,'other'),'wchan':wchan})
        except (OSError,ValueError,IndexError,StopIteration,UnicodeError):pass
        finally:
            if descriptor is not None:os.close(descriptor)
    result['unverified_children']=len(children)-result['verified_children']
    if service_pid('komizo-controller')!=controller or identity(controller)[1]!=birth:raise ValueError('controller generation changed')
    return result


def proxy_admin_profile(deadline, stop):
    import pwd
    import socket
    import stat
    import struct
    stage='deadline';http_status=None
    try:
        if stop.is_set() or time.monotonic()>=deadline:raise TimeoutError()
        def start_ticks():
            if time.monotonic()>=deadline or stop.is_set():raise TimeoutError()
            with (Path('/proc')/str(pid)/'stat').open('rb') as source:body=source.read(4097)
            if len(body)>4096:raise ValueError('proxy process metadata exceeds bound')
            return int(body.decode().rsplit(') ',1)[1].split()[19])
        stage='account'
        account=pwd.getpwnam('komizo-proxy')
        stage='service_identity'
        pid=service_pid('komizo-proxy')
        birth=start_ticks()
        if birth<=0:raise ValueError('proxy start identity missing')
        stage='socket_metadata'
        directory=Path('/run/komizo-proxy');path=directory/'admin.sock'
        parent=directory.lstat();metadata=path.lstat()
        stage='socket_identity'
        if (account.pw_uid<=0 or account.pw_gid<=0 or not stat.S_ISDIR(parent.st_mode)
                or (parent.st_uid,parent.st_gid)!=(account.pw_uid,account.pw_gid) or stat.S_IMODE(parent.st_mode)!=0o700
                or not stat.S_ISSOCK(metadata.st_mode) or (metadata.st_uid,metadata.st_gid)!=(account.pw_uid,account.pw_gid)
                or metadata.st_nlink!=1 or stat.S_IMODE(metadata.st_mode) not in {0o200,0o600,0o700}):
            raise ValueError('proxy admin socket is not private')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            remaining=deadline-time.monotonic()
            if remaining<=0 or stop.is_set():raise TimeoutError()
            connection.settimeout(min(.2,remaining))
            stage='connect'
            connection.connect(str(path))
            stage='peer'
            peer=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if peer!=(pid,account.pw_uid,account.pw_gid) or service_pid('komizo-proxy')!=pid:raise ValueError('proxy admin peer differs')
            remaining=deadline-time.monotonic()
            if remaining<=0 or stop.is_set():raise TimeoutError()
            connection.settimeout(min(.2,remaining))
            stage='request'
            connection.sendall(b'GET /debug/pprof/goroutine?debug=2 HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
            stage='response'
            raw=bytearray()
            while len(raw)<512<<10:
                remaining=deadline-time.monotonic()
                if remaining<=0 or stop.is_set():raise TimeoutError()
                connection.settimeout(min(.2,remaining))
                try:chunk=connection.recv(min(8192,(512<<10)-len(raw)))
                except socket.timeout:continue
                if not chunk:break
                raw.extend(chunk)
                if b'\r\n\r\n' not in raw and len(raw)>16384:raise ValueError('proxy HTTP headers exceed bound')
            stage='http'
            header,separator,body=raw.partition(b'\r\n\r\n')
            status_fields=header.partition(b'\r\n')[0].split(b' ',2)
            if (len(status_fields)>=2 and status_fields[0] in (b'HTTP/1.0',b'HTTP/1.1')
                    and len(status_fields[1])==3 and status_fields[1].isdigit()):
                candidate=int(status_fields[1])
                if 100<=candidate<=599:http_status=candidate
            if not separator or len(header)>16384 or not header.startswith((b'HTTP/1.0 200 ',b'HTTP/1.1 200 ')) or b'transfer-encoding:' in header.lower():raise ValueError('proxy profile response refused')
            limited=len(raw)==512<<10
            if limited and not body.endswith(b'\n'):body=body.rpartition(b'\n')[0]+b'\n'
            stage='identity_recheck'
            fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink');current=path.lstat()
            if any(getattr(current,key)!=getattr(metadata,key) for key in fields) or service_pid('komizo-proxy')!=pid or start_ticks()!=birth:raise ValueError('proxy admin identity changed')
            stage='projection'
            result={'peer_pid':pid,'peer_start_ticks':birth,**proxy_stack_projection(body,deadline)}
            result['raw_limit_reached']=limited
            if time.monotonic()>=deadline or stop.is_set():raise TimeoutError()
            return result

    except Exception as error:
        error.proxy_observer_stage=stage
        error.proxy_observer_http_status=http_status
        raise


def proxy_observer_failure(error):
    stages={'deadline','account','service_identity','socket_metadata','socket_identity','connect',
        'peer','request','response','http','identity_recheck','projection'}
    stage=getattr(error,'proxy_observer_stage',None)
    errno=getattr(error,'errno',None)
    status=getattr(error,'proxy_observer_http_status',None)
    return {'state':'deadline_expired' if isinstance(error,TimeoutError) else 'unavailable',
        'stage':stage if isinstance(stage,str) and stage in stages else 'unavailable',
        'errno':errno if type(errno) is int and 0<=errno<=4095 else None,
        'http_status':status if type(status) is int and 100<=status<=599 else None}


def proxy_refresh_observation(operation, stop):
    import re
    if not re.fullmatch('[a-f0-9]{32}',operation):raise ValueError('invalid diagnostic operation')
    deadline=time.monotonic()+4
    value={'kind':'komizo.proxy-refresh-observation','version':1,'diagnostic_only':True,'operation_id':operation,'phase':'activating'}
    try:value['controller_children']=proxy_cli_snapshot(min(deadline,time.monotonic()+1))
    except Exception as error:value['controller_children']=proxy_observer_failure(error)
    children=value['controller_children']
    reloads=[row for row in children.get('caddy',[]) if row.get('role')=='reload'
        and row.get('process_state') in {'running','sleeping','disk_wait','idle'}]
    if children.get('state')!='observed':
        value['proxy_profile']={'state':'not_observed','reason':'child_observation_unavailable'}
    elif len(reloads)!=1:
        value['proxy_profile']={'state':'not_observed','reason':'reload_child_absent' if not reloads else 'reload_child_ambiguous'}
    else:
        try:value['proxy_profile']=proxy_admin_profile(deadline,stop)
        except Exception as error:value['proxy_profile']=proxy_observer_failure(error)
    if len(json.dumps(value,separators=(',',':')).encode())>48<<10:
        return {**{key:value[key] for key in ['kind','version','diagnostic_only','operation_id','phase']},'state':'export_limit_refused'}
    return value


def submit_failure(value):
    import re
    # Preserve only this command's result. Never export a response body, request,
    # environment, proof or arbitrary stderr through the diagnostic path.
    stderr=value.stderr[-2048:].decode(errors='replace').lower()
    known={'connection_refused':'connection refused','connection_reset':'connection reset',
        'socket_missing':'no such file or directory','permission_denied':'permission denied',
        'deadline':'deadline','timed_out':'timed out','host_refused':'host refused submission',
        'broken_pipe':'broken pipe'}
    errors=[key for key,text in known.items() if text in stderr]
    errors+=['os_error='+number for number in sorted(set(re.findall(r'\bos error ([0-9]{1,3})\b',stderr)))[:8]]
    if value.stderr:errors.append('[remaining stderr redacted]')
    return {'returncode':value.returncode,'stdout_bytes':len(value.stdout),
        'stdout_sha256':'sha256:'+hashlib.sha256(value.stdout).hexdigest(),'stderr':'; '.join(errors)[:512]}


def submit(body):
    stop=threading.Event();worker=None
    if body['action']=='deploy':
        def sample():
            observations=[];previous=None;activating_since=None;proxy_sampled=False
            operation=hashlib.sha256(('komizo-operation-v1\0'+body['application']+'\0'+body['instance']+'\0'+body['nonce']).encode()).hexdigest()[:32]
            operation_path=Path('/var/lib/komizo/operations/'+operation+'.json')
            url=body['release']['workload']['readiness'][0]['url']
            while not stop.is_set():
                try:
                    record=json.loads(operation_path.read_text()) if operation_path.exists() else {}
                    phase=record.get('phase','not_admitted')
                    now=time.monotonic()
                    if phase!='activating' or record.get('operation_id')!=operation:activating_since=None
                    elif activating_since is None:activating_since=now
                    elif not proxy_sampled and now-activating_since>=60:
                        proxy_sampled=True
                        diagnostic=proxy_refresh_observation(operation,stop)
                        if not stop.is_set():write(ROOT/'proxy-refresh-observation.json',diagnostic)
                    try:
                        with urllib.request.urlopen(url,timeout=2) as response:
                            observed={'phase':phase,'status':response.status,'release_digest':response.headers.get('X-Komizo-Release'),
                                'body':response.read(256).decode(errors='replace')}
                    except urllib.error.HTTPError as error:
                        observed={'phase':phase,'status':error.code,'release_digest':error.headers.get('X-Komizo-Release')}
                    except OSError as error:observed={'phase':phase,'error':str(error)[:256]}
                    if observed!=previous and len(observations)<8:
                        observations.append(observed);previous=observed
                        write(ROOT/('readiness-'+body['application']+'.json'),{'url':url,'observations':observations})
                    if phase=='readiness':
                        path=ROOT/('proxy-active-'+body['application']+'.caddy')
                        if not path.exists():write(path,Path('/etc/komizo-proxy/Caddyfile').read_bytes())
                except (OSError,ValueError):pass
                stop.wait(1)
        worker=threading.Thread(target=sample,daemon=True);worker.start()
    try:
        value=run([BINARY,'submit'],input=registry.canonical(body),ok=False,timeout=body['timeout_seconds']+35)
        try:return json.loads(value.stdout)
        except (json.JSONDecodeError,UnicodeDecodeError):
            raise ValueError('native submit returned no JSON result: '+json.dumps(submit_failure(value),sort_keys=True)) from None
    finally:
        stop.set()
        if worker is not None:worker.join(timeout=3)


def request(app,action,identity='current',**fields):
    now=int(time.time())
    return {'kind':'komizo.request','version':1,'authority':'owner','application':app,'instance':'production','action':action,
        'release_digest':identity,'nonce':secrets.token_hex(16),'issued_at':now,'expires_at':now+120,'timeout_seconds':180,**fields}


def installed(app):
    return json.loads(Path('/var/lib/komizo/instances/'+app+'--production.json').read_text())


def fetch(app, release, path='/', *, headers=None):
    body=urllib.request.Request('https://'+app+'.localhost'+path,headers=headers or {})
    with urllib.request.urlopen(body,timeout=5) as response:
        if response.headers.get('X-Komizo-Release')!=release:raise ValueError('public response has another installed source')
        return response.read()


def host_policy(app):
    value={'kind':'komizo.policy','version':1,'application':app,'authority':{'kind':'owner'},
        'artifact_prefixes':['registry.fixture.test:5443/example/'+app],'hostnames':[app+'.localhost'],
        'readiness':[{'url':'https://'+app+'.localhost/','status':200}],
        'limits':limits(96,500,96),'max_image_bytes':64*MiB,'max_asset_bytes':MiB,'max_asset_file_bytes':MiB,
        'startup_memory_bytes':32*MiB}
    write('/etc/komizo/apps/'+app+'.json',value)
    return value


def release(app,revision,*,dynamic=False,unsafe=False,job_command=None,graph=True,source=None):
    repo=ROOT/'registry';repo.mkdir(exist_ok=True)
    if source is not None and source['revision']!=revision:raise ValueError('fixture artifact source differs from its descriptor')
    artifact=registry.image(repo,app,revision,repository=source['repository'] if source else None) if dynamic else registry.static(repo,app,revision,unsafe=unsafe)
    workload={'services':{},'jobs':{},'assets':{},'networks':{},'volumes':{},'routes':[],
        'readiness':[{'url':'https://'+app+'.localhost/','status':200,'contains':revision}]}
    if dynamic:
        base={'artifact':'api','user':'10001:10001','limits':limits(),'networks':['app'],'stop_timeout_seconds':2,
            'command':['httpd','-f','-p','8080','-h','/www'],
            'health':{'command':['/bin/busybox','wget','-q','-O-','http://127.0.0.1:8080/'],'interval_seconds':2,'timeout_seconds':2,'retries':3}}
        workload['networks']={'app':{}}
        workload['services']={'db':copy.deepcopy(base),'api':copy.deepcopy(base)}
        workload['services']['api']['needs']={'initialize':'completed'}
        workload['services']['db']['volumes']=[{'name':'data','target':'/data'}]
        workload['volumes']={'data':{}}
        workload['jobs']={'initialize':{'artifact':'api','user':'10001:10001','limits':limits(16,100,16),
            'networks':['app'],'needs':{'db':'healthy'},'timeout_seconds':90,
            'volumes':[{'name':'data','target':'/data'}],
            'command':['sh','-c',job_command or 'echo accepted >> /data/count']}}
        workload['routes']=[{'host':app+'.localhost','path':'/','target':{'kind':'service','name':'api','port':8080}}]
        artifacts={'api':artifact}
        if not graph:
            workload['services']={'api':workload['services']['api']}
            workload['services']['api']['needs']={}
            workload['jobs']={};workload['volumes']={}
    else:
        artifacts={'web':artifact};workload['assets']={'web':{'artifact':'web','serving':{}}}
        workload['routes']=[{'host':app+'.localhost','path':'/','target':{'kind':'asset','name':'web'}}]
    return {'kind':'komizo.release','version':1,'application':app,'source':source or {'repository':'example/'+app,'repository_id':'123','revision':revision},
        'artifacts':artifacts,'workload':workload}


def enroll_empty(document):
    """The synthetic owner explicitly accepts only a never-started empty graph."""
    app=document['application'];identity=registry.digest(registry.canonical(document))
    record=Path('/var/lib/komizo/instances/'+app+'--production.json')
    if not document['workload']['volumes'] or record.exists():return False
    policy=Path('/etc/komizo/apps/'+app+'.json');selected=ROOT/('owner-data-'+app+'.json');write(selected,document)
    admitted=json.loads(run([BINARY,'policy','validate',str(policy),str(selected)]).stdout)
    if admitted.get('release_digest')!=identity or admitted.get('application')!=app:
        raise ValueError('offline owner policy review changed candidate identity')
    refused=submit(request(app,'deploy',identity,release=document))
    if refused.get('kind')!='komizo.operation' or refused.get('phase')!='failed' or refused.get('ok') is not False or record.exists():
        raise ValueError('unenrolled production expected a completed data-safety refusal: '+json.dumps(refused))
    prepared=submit(request(app,'data-prepare',identity,release=document))
    if prepared.get('phase')!='prepared_stopped' or not prepared.get('ok'):
        raise ValueError('explicit owner data preparation failed: '+json.dumps(prepared))
    resources=installed(app)['resources']
    for value in resources['containers'].values():
        if run(['podman','--remote=false','container','exists',value['name']],ok=False).returncode==0:
            raise ValueError('owner data preparation started a native service')
    for value in resources['volumes'].values():
        native=json.loads(run(['podman','--remote=false','volume','inspect',value['name']]).stdout)[0]
        if any(Path(native['Mountpoint']).iterdir()):raise ValueError('fresh synthetic owner enrollment found existing data')
    evidence={'kind':'komizo.data-evidence','version':1,'application':app,'instance':'production','release_digest':identity,
        'volumes':resources['volumes'],'created_at':int(time.time()),
        'source':{'kind':'empty','confirmation':'initialize-new-empty-application'}}
    body=registry.canonical(evidence)
    Path('/var/lib/komizo/data-evidence').mkdir(mode=0o700,exist_ok=True)
    write('/var/lib/komizo/data-evidence/'+app+'--production.json',body)
    wrong=submit(request(app,'data-accept',identity,data_evidence='sha256:'+'0'*64))
    if wrong.get('ok'):raise ValueError('owner data evidence hash was not enforced')
    # A valid empty assertion must also fail against native nonempty storage.
    first=next(iter(resources['volumes'].values()))
    native=json.loads(run(['podman','--remote=false','volume','inspect',first['name']]).stdout)[0]
    marker=Path(native['Mountpoint'])/'unaccepted-owner-data';marker.write_bytes(b'preserve')
    try:
        nonempty=submit(request(app,'data-accept',identity,data_evidence=registry.digest(body)))
        if nonempty.get('ok') or marker.read_bytes()!=b'preserve':
            raise ValueError('empty initialization accepted or modified existing native data')
    finally:marker.unlink()
    accepted=submit(request(app,'data-accept',identity,data_evidence=registry.digest(body)))
    if not accepted.get('ok'):raise ValueError('explicit empty native data acceptance failed: '+json.dumps(accepted))
    return True


def deploy(document,*,seconds=180):
    identity=registry.digest(registry.canonical(document))
    file=ROOT/('candidate-'+document['application']+'.json');write(file,document)
    validated=json.loads(run([BINARY,'release','validate',str(file)]).stdout)
    if validated!={'ok':True,'release_digest':identity}:raise ValueError('offline release validation changed exact candidate identity')
    fresh=enroll_empty(document)
    body=request(document['application'],'deploy',identity,release=document,timeout_seconds=seconds)
    result=submit(body)
    if fresh and result.get('ok'):
        if result.get('phase')!='prepared_stopped':raise ValueError('fresh owner enrollment silently activated production')
        body=request(document['application'],'start',identity,timeout_seconds=seconds)
        result=submit(body)
    return body,result


def setup_registry():
    hosts='127.0.0.1 registry.fixture.test staticbox.localhost mailroom.localhost livebox.localhost badjob.localhost hungjob.localhost deadline.localhost unsafe.localhost warmup.localhost\n'
    with Path('/etc/hosts').open('a') as stream:stream.write(hosts)
    warm=ROOT/'warmup.Caddyfile'
    warm.write_text('{\n admin off\n storage file_system /var/lib/komizo-proxy/data\n auto_https disable_redirects\n}\nwarmup.localhost:9443 {\n tls internal\n respond 200\n}\n');warm.chmod(0o644)
    # Public configuration is copied outside root's private fixture directory.
    public=Path('/etc/komizo-proxy/warmup.Caddyfile');public.write_bytes(warm.read_bytes());public.chmod(0o644)
    fixture_tasks.start('native-fixture-pki',['/usr/local/bin/caddy','run','--config',str(public),'--adapter','caddyfile'],user='komizo-proxy',seconds=60)
    ca=Path('/var/lib/komizo-proxy/data/pki/authorities/local/root.crt')
    until(lambda:ca.is_file())
    fixture_tasks.stop('native-fixture-pki')
    trust=Path('/usr/local/share/ca-certificates/komizo-native-fixture.crt');trust.write_bytes(ca.read_bytes())
    run(['update-ca-certificates'])
    key=ROOT/'registry.key';csr=ROOT/'registry.csr';certificate=ROOT/'registry.crt';extension=ROOT/'registry.extensions'
    extension.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:registry.fixture.test\n')
    run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(csr),'-subj','/CN=registry.fixture.test'])
    run(['openssl','x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey','/var/lib/komizo-proxy/data/pki/authorities/local/root.key',
        '-CAcreateserial','-out',str(certificate),'-days','2','-extfile',str(extension)])
    key.chmod(0o600)
    (ROOT/'registry').mkdir(exist_ok=True)
    fixture_tasks.start('native-fixture-registry',['/usr/bin/python3',str(ROOT/'fixture_registry.py'),'--root',str(ROOT/'registry'),'--cert',str(certificate),'--key',str(key)],seconds=1200)
    def ready():
        try:urllib.request.urlopen('https://registry.fixture.test:5443/v2/',timeout=2)
        except urllib.error.HTTPError as error:return error.code==404
    until(ready)


def count(app):
    record=installed(app)['resources']['volumes']['data']
    path=run(['podman','--remote=false','volume','inspect',record['name'],'--format={{.Mountpoint}}']).stdout.decode().strip()
    return len((Path(path)/'count').read_text().splitlines())


def container(record):
    return json.loads(run(['podman','--remote=false','container','inspect',record['name']]).stdout)[0]


def shared_dns(stage):
    rows=[]
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():continue
        try:
            executable=(process/'exe').resolve()
            if executable.name!='aardvark-dns':continue
            group=next(line[3:] for line in (process/'cgroup').read_text().splitlines() if line.startswith('0::'))
            # Read the actual daemon's kernel domain, UID, NNP/seccomp and five
            # capability sets; then exercise this exact loaded profile with a
            # root-owned readable synthetic secret (DAC alone would allow it).
            status=dict(line.split(':',1) for line in (process/'status').read_text().splitlines() if ':' in line)
            if ((process/'attr/current').read_text().strip()!='komizo-dns (enforce)'
                    or status['NoNewPrivs'].strip()!='1' or status['Seccomp'].strip()!='2'
                    or any(int(status[field].strip(),16)!=(1<<10) for field in ['CapEff','CapPrm','CapInh','CapAmb','CapBnd'])):
                raise ValueError('actual shared DNS confinement differs')
            proof=profile_probe('komizo-dns','root',['/etc/resolv.conf','/proc/self/status'],
                ['/var/lib/komizo/private-acceptance','/etc/komizo/controller.json','/etc/shadow'])
            private_unreadable=proof['reads_refused']==3
            rows.append({'pid':int(process.name),'cgroup':group,'executable_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
                'private_state_unreadable':private_unreadable})
        except (OSError,StopIteration):continue
    path=ROOT/'shared-dns.json';observations=json.loads(path.read_text()) if path.exists() else []
    observations.append({'stage':stage,'processes':rows});write(path,observations)
    return bool(rows) and all(row['cgroup']=='/komizo/control/dns' and row['private_state_unreadable'] for row in rows)


def cross_network_refused(source,target,service,port,*,source_instance='production',target_instance='production'):
    def selected(app,instance):return json.loads(Path('/var/lib/komizo/instances/'+app+'--'+instance+'.json').read_text())
    record=selected(source,source_instance)
    origin=record['resources']['containers']['api']['name']
    document=json.loads(Path('/var/lib/komizo/releases/'+record['release_digest'][7:]+'.json').read_text())
    if registry.digest(registry.canonical(document))!=record['release_digest']:
        raise ValueError('network control source descriptor changed')
    revision=document['source']['revision'].encode()
    destination=container(selected(target,target_instance)['resources']['containers'][service])
    if not destination['State']['Running']:raise ValueError('network isolation test needs a live destination')
    addresses=[network['IPAddress'] for network in destination['NetworkSettings']['Networks'].values() if network.get('IPAddress')]
    if not addresses:raise ValueError('network isolation test destination has no actual private address')
    def probe(address,port):
        return run(['podman','--remote=false','exec',origin,'/bin/busybox','timeout','4','/bin/busybox','sh','-c',
            'printf "GET / HTTP/1.0\\r\\n\\r\\n" | /bin/busybox nc -w 2 '+address+' '+str(port)],ok=False,timeout=8)
    positive=probe('127.0.0.1',8080)
    if positive.returncode or revision not in positive.stdout:raise ValueError('positive TCP control failed inside the source application')
    for address in addresses:
        result=probe(address,port)
        if result.returncode==0:raise ValueError('application or preview established an ungranted cross-network TCP connection')


def application_limits(app):
    record=installed(app)['resources']['containers']['api'];actual=container(record)
    pid=actual['State']['Pid']
    fields=dict(line.split(':',1) for line in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in line)
    if set(map(int,fields['Uid'].split()))!={10001} or int(fields['CapEff'].strip(),16):
        raise ValueError('actual application UID or capabilities exceed the release')
    group=next(line[3:] for line in Path('/proc/'+str(pid)+'/cgroup').read_text().splitlines() if line.startswith('0::'))
    path=Path('/sys/fs/cgroup')/group.removeprefix('/')
    while (path/'memory.max').read_text().strip()=='max':path=path.parent
    if (path/'memory.max').read_text().strip()!=str(32*MiB) or (path/'memory.swap.max').read_text().strip()!='0':
        raise ValueError('actual application memory/swap enforcement differs')
    if (path/'pids.max').read_text().strip()!='32':raise ValueError('actual application PID enforcement differs')
    quota,period=map(int,(path/'cpu.max').read_text().split())
    if quota*1000!=200*period:raise ValueError('actual application CPU enforcement differs')
    denied=run(['podman','--remote=false','exec','--user=0',record['name'],'/bin/busybox','touch','/unexpected-write'],ok=False)
    if denied.returncode==0 or b'Read-only file system' not in denied.stderr:raise ValueError('application root filesystem permits writes')
    if actual['HostConfig'].get('PortBindings'):raise ValueError('application published host ports')


def apparmor_boundary(app,report):
    record=installed(app)['resources']['containers']['api'];actual=container(record)
    if actual.get('AppArmorProfile')!='komizo-workload':raise ValueError('native service lacks explicit workload confinement')
    label=Path('/proc/'+str(actual['State']['Pid'])+'/attr/current').read_text().strip()
    if label not in {'komizo-workload (enforce)','komizo-workload//&crun (mixed)','komizo-workload//&crun (enforce)','crun//&komizo-workload (mixed)','crun//&komizo-workload (enforce)'}:
        raise ValueError('actual native process has an unexpected confinement label: '+label)
    status=Path('/proc/'+str(actual['State']['Pid'])+'/status').read_text()
    if status.split('NoNewPrivs:',1)[1].splitlines()[0].strip()!='1':raise ValueError('LSM repair removed no-new-privileges')
    delivered=run(['podman','--remote=false','exec',record['name'],'/bin/busybox','sh','-ec',
        "trap 'echo delivered' URG; kill -URG $$"])
    if delivered.stdout.strip()!=b'delivered':raise ValueError('same-profile SIGURG was not delivered')
    parent=Path(actual['State']['CgroupPath']).parent.name
    prefix=['podman','--remote=false','run','--rm','--pull=never','--image-volume=ignore','--http-proxy=false','--network=none','--read-only','--read-only-tmpfs=false',
        '--cap-drop=all','--security-opt=no-new-privileges','--user=10001:10001','--memory=32m','--memory-swap=32m',
        '--pids-limit=16','--cpu-period=1000000','--cpu-quota=100000','--cgroup-parent='+parent,
        '--label=io.komizo.fixture=signal-boundary','--entrypoint=/bin/busybox']
    default_helper=run([*prefix,actual['Image'],'sh','-ec',"/bin/busybox cat /proc/self/attr/current; trap 'echo delivered' URG; kill -URG $$"])
    if default_helper.stdout.decode().strip().splitlines()!=[label,'delivered']:
        raise ValueError('root Podman helper default does not preserve the reviewed profile and SIGURG')
    foreign_file=ROOT/'apparmor-foreign'
    write(foreign_file,Path('/etc/apparmor.d/komizo-workload').read_bytes().replace(b'komizo-workload',b'komizo-native-negative'))
    run(['/sbin/apparmor_parser','-r',str(foreign_file)],timeout=10)
    try:
        # Different LSM profile, but deliberately the same PID namespace and UID:
        # the denial must not rely solely on namespace or UID separation.
        foreign=run([*prefix,'--security-opt=apparmor=komizo-native-negative','--pid=container:'+actual['Id'],actual['Image'],'sh','-ec',
            '/bin/busybox cat /proc/self/attr/current; test -r /proc/1/status; if kill -URG 1; then exit 9; fi'])
        victim=subprocess.Popen(['setpriv','--reuid=10001','--regid=10001','--clear-groups','--no-new-privs','/bin/sleep','30'],
            env={'PATH':'/usr/bin:/bin'},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            until(lambda:Path('/proc/'+str(victim.pid)+'/status').exists() and
                '10001' in Path('/proc/'+str(victim.pid)+'/status').read_text().split('Uid:',1)[1].splitlines()[0],seconds=3)
            run(['setpriv','--reuid=10001','--regid=10001','--clear-groups','--no-new-privs','/bin/busybox','kill','-URG',str(victim.pid)])
            # Host PID visibility is granted only to this disposable negative probe.
            run([*prefix,'--security-opt=apparmor=komizo-workload','--pid=host',actual['Image'],'sh','-ec',
                'test -r /proc/'+str(victim.pid)+'/status; if kill -URG '+str(victim.pid)+'; then exit 9; fi'])
        finally:
            victim.terminate()
            try:victim.wait(timeout=5)
            except subprocess.TimeoutExpired:victim.kill();victim.wait(timeout=5)
    finally:
        run(['/sbin/apparmor_parser','-R',str(foreign_file)],timeout=10)
        foreign_file.unlink()
    write(ROOT/'apparmor-boundary.json',{'service_label':label,'foreign_profile_label':foreign.stdout.decode().strip(),'helper_default_label':default_helper.stdout.decode().splitlines()[0],'no_new_privileges':True,'same_uid_host_signal_baseline':'passed',
        'same_profile_sigurg':'passed','foreign_profile_refused':'passed','host_signal_refused':'passed'})
    report['checks'].update({'apparmor_signal_delivery':'passed','apparmor_stacked_profile_enforced':'passed',
        'apparmor_foreign_profile_signal_refused':'passed','apparmor_host_signal_refused':'passed','apparmor_root_helper_default':'passed'})


def failures(report):
    bad=release('badjob','a'*40,dynamic=True,job_command='echo accepted >> /data/count; exit 7')
    _,result=deploy(bad)
    if result.get('phase')!='needs_reconciliation' or result.get('ok') is not False or count('badjob')!=1:
        raise ValueError('failed data job was not durably fenced')
    _,refused=deploy(bad)
    if refused.get('kind')!='komizo.error' or count('badjob')!=1:raise ValueError('failed data job was replayed')
    hanging=release('hungjob','a'*40,dynamic=True,
        job_command='echo accepted >> /data/count; /bin/busybox sleep 30; echo late > /data/interrupted-late')
    enroll_empty(hanging)
    _,staged=deploy(hanging)
    if staged.get('phase')!='prepared_stopped':raise ValueError('interruption fixture did not stage its enrolled stopped source')
    body=request('hungjob','start',registry.digest(registry.canonical(hanging)),timeout_seconds=20)
    interrupted_started=time.monotonic()
    child=subprocess.Popen([BINARY,'submit'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    child.stdin.write(registry.canonical(body));child.stdin.close()
    try:
        def running():
            return any(json.loads(path.read_text()).get('phase')=='running' for path in Path('/var/lib/komizo/jobs').rglob('*.json')
                if json.loads(path.read_text()).get('application')=='hungjob')
        until(running,seconds=20)
        restart_controller()
        operation=hashlib.sha256(('komizo-operation-v1\0hungjob\0production\0'+body['nonce']).encode()).hexdigest()[:32]
        observed=submit(request('hungjob','inspect',body['release_digest'],operation=operation))
        if observed.get('phase')!='needs_reconciliation' or count('hungjob')!=1:raise ValueError('interrupted data job lost its durable uncertainty fence')
        _,refused=deploy(hanging)
        if refused.get('kind')!='komizo.error' or count('hungjob')!=1:raise ValueError('interrupted data job was replayed')
        receipts=[json.loads(path.read_text()) for path in Path('/var/lib/komizo/jobs').rglob('*.json')
            if json.loads(path.read_text()).get('application')=='hungjob']
        if len(receipts)!=1:raise ValueError('interrupted native job lost its exact durable creation identity')
        until(lambda:not json.loads(run(['podman','--remote=false','container','inspect',receipts[0]['container_id']]).stdout)[0]['State']['Running'],
            seconds=max(.1,25-(time.monotonic()-interrupted_started)))
        volume=installed('hungjob')['resources']['volumes']['data']
        mount=Path(run(['podman','--remote=false','volume','inspect',volume['name'],'--format={{.Mountpoint}}']).stdout.decode().strip())
        if (mount/'interrupted-late').exists():raise ValueError('controller death allowed native data effects beyond the admitted deadline')
        actual=json.loads(run(['podman','--remote=false','container','inspect',receipts[0]['container_id']]).stdout)[0]
        write(ROOT/'interrupted-deadline-observation.json',{'timeout_seconds':20,'declared_job_timeout_seconds':90,
            'elapsed_seconds':time.monotonic()-interrupted_started,'native_timeout_seconds':actual['Config']['Timeout'],
            'entered_job':True,'job_stopped':actual['State']['Running'] is False,'late_write_present':False})
    finally:
        try:child.wait(timeout=10)
        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        child.stdout.close();child.stderr.close()
    deadline=release('deadline','a'*40,dynamic=True,
        job_command='echo entered > /data/deadline-started; /bin/busybox sleep 12; echo late > /data/deadline-late')
    enroll_empty(deadline)
    _,staged=deploy(deadline)
    if staged.get('phase')!='prepared_stopped':raise ValueError('deadline fixture did not finish its separate owner preparation')
    body=request('deadline','start',registry.digest(registry.canonical(deadline)),timeout_seconds=8)
    started=time.monotonic();bounded=submit(body);elapsed=time.monotonic()-started
    write(ROOT/'deadline-observation.json',{'timeout_seconds':8,'elapsed_seconds':elapsed,'receipt':bounded})
    if elapsed>40 or bounded.get('ok') is not False:raise ValueError('admitted worker exceeded its original end-to-end deadline: '+json.dumps({'elapsed_seconds':elapsed,'receipt':bounded}))
    volume=installed('deadline')['resources']['volumes']['data']
    mount=Path(run(['podman','--remote=false','volume','inspect',volume['name'],'--format={{.Mountpoint}}']).stdout.decode().strip())
    receipts=[json.loads(path.read_text()) for path in Path('/var/lib/komizo/jobs').rglob('*.json')
        if json.loads(path.read_text()).get('application')=='deadline']
    if len(receipts)>1:raise ValueError('short deadline created duplicate native jobs')
    def stopped():
        if not receipts:return True
        value=json.loads(run(['podman','--remote=false','container','inspect',receipts[0]['container_id']]).stdout)[0]
        return value if value['State']['Running'] is False else None
    try:until(stopped,seconds=5)
    finally:
        write(ROOT/'deadline-observation.json',{'timeout_seconds':8,'elapsed_seconds':elapsed,'receipt':bounded,
            'job_stopped':bool(stopped()) if (mount/'deadline-started').exists() else None,'entered_job':(mount/'deadline-started').exists(),
            'outcome':'bounded_running_job' if (mount/'deadline-started').exists() else 'refused_before_job_effects',
            'late_write_present':(mount/'deadline-late').exists()})
    if (mount/'deadline-late').exists():raise ValueError('native job wrote retained data after its operation deadline')
    _,unsafe=deploy(release('unsafe','a'*40,unsafe=True))
    if unsafe.get('phase')!='failed' or unsafe.get('ok') is not False:raise ValueError('unsafe archive reached activation')
    report['checks'].update({'failed_job_no_replay':'passed','interrupted_job_no_replay':'passed','interrupted_job_native_deadline':'passed','worker_deadline':'passed',
        'worker_deadline_stops_job':'passed','unsafe_archive':'passed'})


@contextmanager
def instance_memory_events(path):
    import stat
    before=path.lstat()
    if not stat.S_ISDIR(before.st_mode) or before.st_uid!=0 or before.st_mode&0o022:
        raise ValueError('memory stress instance parent is not protected')
    with (path/'memory.events').open() as events:
        yield events
        after=path.lstat()
        if (after.st_dev,after.st_ino,after.st_uid,after.st_mode)!=(before.st_dev,before.st_ino,before.st_uid,before.st_mode):
            raise ValueError('memory stress instance parent was retired or replaced')


def pid_stress_recovered(source,record,leaf,workload,baseline,deadline,observation):
    import errno
    fields={'id':'.ID','running':'.State.Running','paused':'.State.Paused','pid':'.State.Pid',
        'cgroup':'.State.CgroupPath','parent':'.HostConfig.CgroupParent'}
    fields.update({key:'(index .Config.Labels "io.komizo.'+key+'")'
        for key in ('application','instance','service','release','ownership')})
    projection='{'+','.join('"'+key+'":{{json '+field+'}}' for key,field in fields.items())+'}'
    expected={'id':record['id'],'parent':workload,'application':'livebox','instance':'production',
        'service':'api','release':source['release_digest'],'ownership':record['ownership']}
    while time.monotonic()<deadline:
        state=observation['pid_cleanup']={'state':'waiting'}
        try:count=int((leaf/'pids.current').read_text())
        except OSError as error:
            if error.errno not in {errno.ENOENT,errno.ENODEV}:
                state.update(state='payload_read_error',errno=error.errno);raise
            state['state']='payload_absent' if error.errno==errno.ENOENT else 'payload_retired';count=None
        state['pids_current']=count
        if count==0:state['state']='payload_empty'
        elif count is not None and count>baseline:state['state']='pid_count_not_recovered'
        if count is not None and 0<count<=baseline:
            remaining=deadline-time.monotonic()
            if remaining<=0:break
            try:
                result=run(['podman','--remote=false','container','inspect','--format',projection,record['id']],
                    ok=False,timeout=min(1,remaining))
            except subprocess.TimeoutExpired:state['state']='inspect_timeout'
            else:
                state['inspect_returncode']=result.returncode
                if result.returncode:state['state']='inspect_failed'
                else:
                    if len(result.stdout)>8192:raise ValueError('PID cleanup inspection exceeds its closed bound')
                    value=json.loads(result.stdout)
                    if (not isinstance(value,dict) or set(value)!=set(fields)
                            or any(value[key]!=wanted for key,wanted in expected.items())):
                        state['state']='identity_refused';raise ValueError('PID cleanup container ownership changed')
                    if (type(value['running']) is not bool or type(value['paused']) is not bool
                            or type(value['pid']) is not int or not 0<=value['pid']<1<<31):
                        state['state']='state_refused';raise ValueError('PID cleanup native state is invalid')
                    state.update(running=value['running'],paused=value['paused'],pid=value['pid'])
                    if value['running'] and value['cgroup']!=workload+'/libpod-'+record['id']:
                        state['state']='identity_refused';raise ValueError('PID cleanup payload ownership changed')
                    if (value['running'] and not value['paused'] and value['pid']>1
                            and value['cgroup']==workload+'/libpod-'+record['id']):
                        if installed('livebox')!=source:
                            state['state']='source_refused';raise ValueError('PID cleanup installed identity changed')
                        if time.monotonic()<deadline:state['state']='ready';return
        remaining=deadline-time.monotonic()
        if remaining>0:time.sleep(min(.2,remaining))
    raise ValueError('PID stress did not recover its exact live container within the original cleanup deadline')


def resource_stress(report):
    app='livebox';source=installed(app);record=source['resources']['containers']['api']
    namespace=hashlib.sha256(b'livebox\0production').hexdigest()[:20]
    group='/komizo/production/kmz-'+namespace
    path=Path('/sys/fs/cgroup')/group.removeprefix('/')
    def event(file,key):return int(dict(line.split() for line in (path/file).read_text().splitlines())[key])
    actual=container(record)
    leaf=Path('/sys/fs/cgroup')/actual['State']['CgroupPath'].removeprefix('/')
    workload=group+'/service-api-'+record['ownership']
    if (source['application']!=app or source['instance']!='production'
            or set(source['resources']['containers'])!={'api'} or actual['Id']!=record['id']
            or actual['HostConfig']['CgroupParent']!=workload
            or leaf!=path/('service-api-'+record['ownership'])/('libpod-'+record['id'])
            or any(actual['Config']['Labels'].get('io.komizo.'+key)!=value for key,value in
                {'application':app,'instance':'production','service':'api','release':source['release_digest'],'ownership':record['ownership']}.items())):
        raise ValueError('memory stress target escaped its exact owned instance')
    baseline_pids=int((leaf/'pids.current').read_text())
    previous=event('pids.events','max')
    # Sleeping children have a finite lifetime even when the shell cannot fork
    # another process. The stress stays below this application's PID ceiling.
    pid_result=run(['podman','--remote=false','exec',record['name'],'/bin/busybox','sh','-c',
        'i=0; while [ "$i" -lt 80 ]; do /bin/busybox sleep 2 & i=$((i+1)); done; wait'],ok=False,timeout=20)
    cleanup_deadline=time.monotonic()+10
    pid_pressure=submit_failure(pid_result);pid_stderr=pid_result.stderr[-2048:].lower()
    pid_pressure['stderr_classes']=[name for name,patterns in {
        'fork_refused':(b"can't fork",b'cannot fork'),'resource_unavailable':(b'resource temporarily unavailable',),
        'exec_not_running':(b'can only create exec sessions on running containers',b'container state improper'),
        'oci_runtime':(b'oci runtime',),'killed':(b'killed',)}.items() if any(pattern in pid_stderr for pattern in patterns)]
    observation={'container_id':actual['Id'],'container_cgroup':str(leaf),'memory_events_cgroup':str(path),
        'baseline_pids':baseline_pids,'pid_pressure':pid_pressure,
        'before_pid_events':previous,'after_pid_events':event('pids.events','max'),'pid_cleanup':{'state':'not_started'}}
    write(ROOT/'resource-stress.json',observation)
    if observation['after_pid_events']<=previous:raise ValueError('actual application PID ceiling did not refuse excess children')
    # A shell refused another fork can exit while its finite children remain.
    # Finish the PID experiment before asking a new exec to allocate memory.
    try:pid_stress_recovered(source,record,leaf,workload,baseline_pids,cleanup_deadline,observation)
    finally:write(ROOT/'resource-stress.json',observation)
    def counters(stream):
        stream.seek(0);return {key:int(value) for key,value in (line.split() for line in stream.read().splitlines())}
    # Hierarchical instance counters retain descendant OOM events when the
    # bounded payload cgroup is removed during its supervised recovery.
    with instance_memory_events(path) as events:
        before=counters(events)
        result=run(['podman','--remote=false','exec',record['name'],'/bin/busybox','awk',
            'BEGIN {x="0123456789"; for (i=0;i<9;i++) x=x x; while (1) a[++n]=x n}'],ok=False,timeout=30)
        after=counters(events)
    if installed(app)!=source:raise ValueError('memory stress installed identity changed')
    write(ROOT/'resource-stress.json',{**observation,'before_memory_events':before,'after_memory_events':after,
        'exit_code':result.returncode,'stderr':result.stderr.decode(errors='replace')[:2048]})
    if result.returncode==0 or after.get('oom_kill',0)<=before.get('oom_kill',0):
        raise ValueError('actual application memory ceiling did not isolate excess allocation')
    until(lambda:b'a'*40 in fetch(app,installed(app)['release_digest']),seconds=30)
    fetch('staticbox',installed('staticbox')['release_digest'])
    prior=Path('/var/lib/komizo/instances/livebox--production.json').read_bytes()
    candidate=release(app,'b'*40,dynamic=True,graph=False)
    candidate['workload']['services']['api']['limits']=limits(128)
    _,denied=deploy(candidate)
    if denied.get('kind')!='komizo.error' or Path('/var/lib/komizo/instances/livebox--production.json').read_bytes()!=prior:
        raise ValueError('oversized release reached installation effects')
    report['checks'].update({'application_pid_stress':'passed','application_memory_stress':'passed',
        'other_application_survives_stress':'passed','oversized_release_refused_before_effects':'passed'})


def bounded_prepare():
    setup_registry();host_policy('staticbox')
    _,receipt=deploy(release('staticbox','a'*40))
    if not receipt.get('ok'):raise ValueError('bounded static activation failed: '+json.dumps(receipt))
    report=json.loads((ROOT/'report.json').read_text())
    import fixture_postgres
    fixture_postgres.prepare(report)
    apparmor_boundary('pgbox',report)
    if not shared_dns('bounded-full-postgresql-workload'):raise ValueError('bounded shared DNS escaped infrastructure accounting')
    ready_notifications_absent()
    report['checks']['shared_dns_control_budget']='passed'
    report['installed']={'static':receipt['release_digest']}
    report['runtime_acceptance']=False
    report['remaining']=['bounded performance and owner-client observations']
    write(ROOT/'report.json',report)
    fixture_tasks.stop('native-fixture-registry')


def prepare():
    if json.loads((ROOT/'profile.json').read_text())['profile']=='bounded':return bounded_prepare()
    setup_registry()
    for app in ['staticbox','mailroom','livebox','badjob','hungjob','deadline','unsafe']:host_policy(app)
    static=release('staticbox','a'*40)
    body,result=deploy(static)
    if result.get('phase')!='ready' or not result.get('ok'):raise ValueError('actual static archive release failed: '+json.dumps(result))
    if b'a'*40 not in fetch('staticbox',result['release_digest']):raise ValueError('static source bytes differ')
    public=Path('/var/lib/komizo-assets')/result['release_digest'][7:]/'web'/'index.html'
    if b'a'*40 not in run(['runuser','-u','komizo-proxy','--','cat',str(public)]).stdout:
        raise ValueError('unprivileged proxy UID cannot read exact installed asset bytes')
    if run(['runuser','-u','komizo-proxy','--','test','-w',str(public)],ok=False).returncode==0:
        raise ValueError('unprivileged proxy UID can change accepted public assets')
    app=release('mailroom','a'*40,dynamic=True)
    mutation,ready=deploy(app)
    if ready.get('phase')!='ready' or not ready.get('ok'):raise ValueError('actual API/job release failed: '+json.dumps(ready))
    if b'a'*40 not in fetch('mailroom',ready['release_digest']) or count('mailroom')!=1:raise ValueError('DAG did not execute once against the retained data')
    application_limits('mailroom')
    forged=fetch('mailroom',ready['release_digest'],'/cgi-bin/who',headers={'X-Forwarded-For':'203.0.113.29'})
    if b'203.0.113.29' in forged:raise ValueError('untrusted forwarded client IP reached the application')
    if submit(mutation).get('kind')!='komizo.error' or count('mailroom')!=1:raise ValueError('accepted mutation replay executed again')
    _,live=deploy(release('livebox','a'*40,dynamic=True,graph=False))
    if not live.get('ok'):raise ValueError('independent supervised service did not activate')
    cross_network_refused('livebox','mailroom','db',8080)
    cross_network_refused('mailroom','livebox','api',8080)
    records=installed('mailroom')['resources']['containers'];before={name:container(value)['Id'] for name,value in records.items()}
    dns_accounted=shared_dns('before-controller-death')
    ready_notifications_absent()
    api=records['api']['name'];db=records['db']['name']
    run(['podman','--remote=false','exec',api,'/bin/busybox','nslookup',db])
    if b'a'*40 not in run(['podman','--remote=false','exec',api,'/bin/busybox','wget','-q','-O-','http://db:8080/']).stdout:
        raise ValueError('same-network service TCP traffic was not preserved')
    restart_controller()
    dns_accounted=shared_dns('after-controller-death') and dns_accounted
    if before!={name:container(value)['Id'] for name,value in installed('mailroom')['resources']['containers'].items()}:
        raise ValueError('controller death replaced supervised application containers')
    run(['podman','--remote=false','exec',api,'/bin/busybox','nslookup',db])
    fetch('mailroom',ready['release_digest'])
    stop=submit(request('mailroom','stop',ready['release_digest']))
    if stop.get('phase')!='prepared_stopped':raise ValueError('stop intent was not retained')
    live_api=installed('livebox')['resources']['containers']['api']['name']
    dns_accounted=shared_dns('after-first-application-stop') and dns_accounted
    run(['podman','--remote=false','exec',live_api,'/bin/busybox','nslookup',live_api])
    if not dns_accounted:raise ValueError('actual shared DNS budget or private-state boundary differs; see shared-dns.json')
    next_release=release('mailroom','b'*40,dynamic=True)
    _,prepared=deploy(next_release)
    if prepared.get('phase')!='prepared_stopped' or count('mailroom')!=1:raise ValueError('stopped preparation executed jobs or changed retained data')
    if installed('mailroom')['release_digest']!=ready['release_digest']:raise ValueError('prepared candidate silently replaced installed identity')
    report=json.loads((ROOT/'report.json').read_text())
    report['checks'].update({'static_archive':'passed','service_job_dag':'passed','owner_empty_data_enrollment':'passed','nonempty_data_initialization_refused':'passed','unenrolled_production_refused':'passed','mutation_replay':'passed',
        'source_bound_https':'passed','forwarded_ip_refused':'passed','controller_death':'passed',
        'dns_after_controller_death':'passed','dns_after_other_application_stop':'passed','shared_dns_control_budget':'passed',
        'stopped_candidate_no_jobs':'passed','application_kernel_limits':'passed',
        'application_uid_capabilities':'passed','application_read_only_root':'passed','no_published_application_ports':'passed',
        'cross_application_tcp_refused':'passed','same_network_tcp_allowed':'passed','installed_asset_proxy_uid_read':'passed',
        'installed_asset_proxy_uid_write_refused':'passed'})
    apparmor_boundary('livebox',report)
    write(ROOT/'report.json',report)
    import fixture_postgres
    fixture_postgres.prepare(report)
    write(ROOT/'report.json',report)
    import fixture_preview
    fixture_preview.prepare(report)
    write(ROOT/'report.json',report)
    fixture_postgres.stop()
    failures(report)
    write(ROOT/'report.json',report)
    import fixture_secrets
    fixture_secrets.prepare(report)
    write(ROOT/'report.json',report)
    import fixture_backup
    fixture_backup.prepare(report)
    write(ROOT/'report.json',report)
    resource_stress(report)
    write(ROOT/'report.json',report)
    fixture_preview.expire(report)
    fixture_tasks.stop('native-fixture-registry')
    report['runtime_acceptance']=False
    report['remaining']=['small-host capacity acceptance']
    report['installed']={'static':result['release_digest'],'mailroom':ready['release_digest'],'prepared':prepared['release_digest'],
        'running':live['release_digest'],'containers':before}
    write(ROOT/'report.json',report)


def verify_reboot():
    report=json.loads((ROOT/'report.json').read_text());accepted=report['installed']
    if report['profile']=='bounded':
        import fixture_postgres
        until(lambda:b'a'*40 in fetch('staticbox',accepted['static']),seconds=60)
        until(lambda:fixture_postgres.source()['revision'].encode() in fetch('pgbox',report['postgres']['release_digest']),seconds=60)
        until(lambda:fixture_postgres.query('SELECT value FROM evidence')==b'retained native row',seconds=60)
        if fixture_postgres.query('SELECT count(*) FROM evidence')!=b'1':raise ValueError('bounded initialized PostgreSQL job replayed at boot')
        if not shared_dns('bounded-offline-reboot'):raise ValueError('bounded reboot lost shared DNS accounting')
        if fixture_tasks.populated('/native-fixture/native-fixture-registry'):raise ValueError('bounded reboot unexpectedly started registry')
        report['checks'].update({'bounded_full_postgresql_offline_reboot':'passed','postgresql_initialization_not_replayed':'passed'})
        write(ROOT/'report.json',report);return
    if fixture_tasks.populated('/native-fixture/native-fixture-registry'):raise ValueError('fixture registry must remain offline after reboot')
    if b'a'*40 not in fetch('staticbox',accepted['static']):raise ValueError('static release did not survive offline reboot')
    until(lambda:b'a'*40 in fetch('livebox',accepted['running']),seconds=60)
    record=installed('mailroom')
    if record['desired_running'] or count('mailroom')!=1:raise ValueError('stopped data or intent changed during real reboot')
    for container in record['resources']['containers'].values():
        info=run(['podman','--remote=false','container','inspect',container['name']],ok=False)
        if info.returncode==0 and json.loads(info.stdout)[0]['State']['Running']:raise ValueError('stopped application ran after real reboot')
    if 'failed_job_no_replay' in report['checks']:
        for application in ['badjob','hungjob']:
            if count(application)!=1:raise ValueError('data job replayed during a real reboot')
            record=installed(application)['resources']['containers']['api']
            info=run(['podman','--remote=false','container','inspect',record['name']],ok=False)
            if info.returncode==0 and json.loads(info.stdout)[0]['State']['Running']:
                raise ValueError('API bypassed its failed or interrupted job dependency during reboot')
        report['checks']['uncertain_job_reboot_no_replay']='passed'
    report['checks']['registry_offline_reboot']='passed';report['checks']['stopped_reboot_no_replay']='passed'
    import fixture_postgres
    fixture_postgres.verify_reboot(report)
    write(ROOT/'report.json',report)
