#!/usr/bin/env python3
"""Real one-CPU preparation contention; only disposable, exact owned CLI children."""
import hashlib
import json
import os
from pathlib import Path
import signal
import threading
import time


def bounded(path, maximum):
    with path.open('rb') as source:
        value=source.read(maximum+1)
    if len(value)>maximum:raise ValueError('preparation process observation exceeds bound')
    return value


def process(proc, pid):
    root=proc/str(pid)
    raw=bounded(root/'stat',4096).rsplit(b') ',1)[1].split()
    status=bounded(root/'status',8192).splitlines()
    identifiers=lambda key:tuple(map(int,next(line for line in status if line.startswith(key)).split()[1:]))
    return {'pid':pid,'state':raw[0].decode(),'parent':int(raw[1]),'start_ticks':int(raw[19]),
        'uids':identifiers(b'Uid:'),'gids':identifiers(b'Gid:'),
        'group':bounded(root/'cgroup',1024),'argv':bounded(root/'cmdline',65536).removesuffix(b'\0').decode().split('\0'),
        'exe':(root/'exe').stat()}


def child_pids(proc, pid):
    tasks=[]
    for task in (proc/str(pid)/'task').iterdir():
        if len(tasks)>=128:raise ValueError('preparation task inventory exceeds bound')
        if not task.name.isascii() or not task.name.isdecimal():raise ValueError('invalid preparation task identity')
        tasks.append(task)
    children=set()
    for task in tasks:
        try:values=bounded(task/'children',4096).split()
        except FileNotFoundError:continue  # A controller worker thread may exit.
        if any(not value.isdigit() or len(value)>10 or int(value)<=1 for value in values):raise ValueError('invalid preparation child identity')
        children.update(map(int,values))
        if len(children)>64:raise ValueError('preparation child inventory exceeds bound')
    return sorted(children)


def creation_candidates(proc, controller_pid, timeout):
    # Effects are spawned by a controller worker thread. Enumerate every TID's
    # direct children; reading all unrelated /proc processes can miss create.
    for parent_pid in child_pids(proc,controller_pid):
        try:
            parent=process(proc,parent_pid)
            if (parent['parent']!=controller_pid or parent['argv'][:2]!=['/usr/bin/timeout','--signal=KILL']
                    or (parent['exe'].st_dev,parent['exe'].st_ino)!=(timeout.st_dev,timeout.st_ino)):continue
            for pid in child_pids(proc,parent_pid):
                try:yield process(proc,pid),parent
                except (FileNotFoundError,ProcessLookupError):continue
        except (FileNotFoundError,ProcessLookupError):continue


def creator_identity(child, parent, controller, receipt, podman, timeout):
    """Finite exact ownership predicate, exercised with synthetic proc metadata."""
    argv=child['argv']
    def pairs(option):return [argv[i+1] for i in range(len(argv)-1) if argv[i]==option]
    labels=pairs('--label')
    expected={'io.komizo.application':receipt['application'],'io.komizo.instance':receipt['instance'],
        'io.komizo.service':receipt['job'],'io.komizo.release':receipt['release_digest'],
        'io.komizo.ownership':receipt['ownership'],'io.komizo.job.identity':receipt['identity']}
    same=lambda left,right:(left.st_dev,left.st_ino)==(right.st_dev,right.st_ino)
    return (argv[:4]==['/usr/bin/podman','--remote=false','--cgroup-manager=cgroupfs','create']
        and pairs('--name')==[receipt['container_name']]
        and pairs('--timeout')==[str(receipt['native_timeout_seconds'])]
        and all(labels.count(key+'='+value)==1 for key,value in expected.items())
        and child['parent']==parent['pid'] and parent['parent']==controller['pid']
        and child['start_ticks']>0 and parent['start_ticks']>0 and controller['start_ticks']>0
        and child['state'] in {'R','S','D'} and parent['state'] in {'R','S','D'}
        and child['group']==parent['group']==controller['group']==b'0::/komizo/control/controller\n'
        and all(value['uids']==value['gids']==(0,0,0,0) for value in [child,parent,controller])
        and same(child['exe'],podman) and same(parent['exe'],timeout)
        and parent['argv'][:2]==['/usr/bin/timeout','--signal=KILL']
        and len(parent['argv'])>=4 and parent['argv'][3:]==argv)


def pause_creation(runtime, body, seconds, result, errors, stop):
    proc=Path('/proc');descriptor=None;stopped=False
    controller_pid=runtime.service_pid('komizo-controller');controller=process(proc,controller_pid)
    operation=hashlib.sha256(('komizo-operation-v1\0'+body['application']+'\0production\0'+body['nonce']).encode()).hexdigest()[:32]
    namespace='kmz-'+hashlib.sha256((body['application']+'\0production').encode()).hexdigest()[:20]
    directory=Path('/var/lib/komizo/jobs')/namespace
    deadline=time.monotonic()+30
    try:
        podman=Path('/usr/bin/podman').stat();timeout=Path('/usr/bin/timeout').stat()
        while not stop.is_set() and time.monotonic()<deadline:
            receipts=list(directory.glob('*.json'))
            if len(receipts)>16:raise ValueError('preparation fixture receipt inventory exceeds bound')
            for path in receipts:
                receipt=json.loads(bounded(path,64<<10))
                if receipt.get('operation_id')!=operation:continue
                if (receipt['application']!=body['application'] or receipt['instance']!='production'
                        or receipt['release_digest']!=body['release_digest'] or receipt['phase']!='starting'
                        or receipt['container_id']):continue
                for child,parent in creation_candidates(proc,controller_pid,timeout):
                    pid=child['pid']
                    try:
                        if child['argv'][:4]!=['/usr/bin/podman','--remote=false','--cgroup-manager=cgroupfs','create']:continue
                        if not creator_identity(child,parent,controller,receipt,podman,timeout):continue
                        descriptor=os.pidfd_open(pid)
                        current=process(proc,pid)
                        current_parent=process(proc,current['parent']);current_controller=process(proc,controller_pid)
                        if (current['parent'],current['start_ticks'],current['argv'])!=(child['parent'],child['start_ticks'],child['argv']) or current_parent['start_ticks']!=parent['start_ticks'] or not creator_identity(current,current_parent,current_controller,receipt,podman,timeout):raise ValueError('owned create generation changed')
                        if runtime.service_pid('komizo-controller')!=controller_pid or process(proc,controller_pid)['start_ticks']!=controller['start_ticks']:raise ValueError('controller generation changed')
                        signal.pidfd_send_signal(descriptor,signal.SIGSTOP);stopped=True
                        settled=time.monotonic()+2
                        while process(proc,pid)['state'] not in {'T','t'}:
                            if time.monotonic()>=settled:raise ValueError('owned create did not stop')
                            time.sleep(.001)
                        began=time.monotonic()
                        if stop.wait(seconds):raise ValueError('request finished before its real preparation pause')
                        result.update({'operation_id':operation,'pid':pid,'start_ticks':child['start_ticks'],
                            'parent_pid':parent['pid'],'parent_start_ticks':parent['start_ticks'],
                            'controller_pid':controller_pid,'controller_start_ticks':controller['start_ticks'],
                            'container_name':receipt['container_name'],'native_timeout_seconds':receipt['native_timeout_seconds'],
                            'pause_seconds':time.monotonic()-began,'only_owned_create_paused':True,
                            'controller_and_timeout_watchdog_never_paused':True})
                        return
                    except (FileNotFoundError,ProcessLookupError):
                        if stopped:raise ValueError('owned stopped create process disappeared') from None
                        if descriptor is not None:os.close(descriptor);descriptor=None
                        continue
            stop.wait(.001)
        raise ValueError('exact owned create process was not observed before fixture deadline')
    except BaseException as error:errors.append(error)
    finally:
        if descriptor is not None:
            try:
                if stopped:signal.pidfd_send_signal(descriptor,signal.SIGCONT)
            except ProcessLookupError:pass
            finally:os.close(descriptor)


def delayed_deploy(runtime, document, seconds):
    body=runtime.request(document['application'],'deploy',runtime.registry.digest(runtime.registry.canonical(document)),release=document)
    result={};errors=[];stop=threading.Event()
    thread=threading.Thread(target=pause_creation,args=(runtime,body,seconds,result,errors,stop),daemon=True)
    thread.start();started=time.monotonic()
    try:operation=runtime.submit(body)
    finally:
        stop.set();thread.join(timeout=5)
    if thread.is_alive():raise ValueError('owned create pause worker did not settle')
    if errors:raise ValueError('owned create preparation pause failed: '+str(errors[0]))
    if result.get('pause_seconds',0)<seconds:raise ValueError('native preparation pause was not real monotonic elapsed time')
    return body,operation,{**result,'total_elapsed_seconds':time.monotonic()-started}


def receipts(application):
    namespace='kmz-'+hashlib.sha256((application+'\0production').encode()).hexdigest()[:20]
    paths=list((Path('/var/lib/komizo/jobs')/namespace).glob('*.json'))
    if len(paths)!=1:raise ValueError('preparation fixture requires exactly one durable job identity')
    return json.loads(bounded(paths[0],64<<10))


def upstream_snapshot(runtime, application, operation, state=Path('/var/lib/komizo')):
    """Observe only the declared disposable upstream and its protected closure."""
    namespace='kmz-'+hashlib.sha256((application+'\0production').encode()).hexdigest()[:20]
    installed=runtime.installed(application);record=installed['resources']['containers']['upstream']
    if record['name']!=namespace+'-upstream':raise ValueError('upstream record escaped its exact native name')
    creation_bytes=bounded(state/'journal'/operation/'service-creation-upstream.json',2<<20)
    creation=json.loads(creation_bytes);original=json.loads(creation['unit_body'])
    same=['name','ownership','image','config_digest','release_digest','volumes']
    if (creation['kind']!='komizo.service-creation' or creation['version']!=1
            or creation['application']!=application or creation['instance']!='production'
            or creation['operation_id']!=operation or creation['service']!='upstream'
            or creation['record']['id'] or any(creation['record'][key]!=record[key] for key in same)
            or original['wanted'] is not True
            or runtime.registry.digest(creation['unit_body'].encode())!=creation['record']['unit_sha256']):
        raise ValueError('upstream creation no longer binds its original accepted identity')
    path=state/'service-configs'/(record['name']+'.json')
    body=bounded(path,1<<20);config=json.loads(body)
    ledger=json.loads(bounded(state/'units.json',4<<20))[str(path)]
    identity=runtime.registry.digest(body)
    if (identity!=ledger['sha256'] or identity!=record['unit_sha256']
            or ledger['application']!=application or ledger['instance']!='production'
            or config!={**original,'wanted':installed['desired_running']}
            or body!=runtime.registry.canonical(config)):
        raise ValueError('upstream accepted configuration differs beyond its normal wanted transition')
    actual=runtime.container(record);labels=actual['Config']['Labels']
    expected={'io.komizo.application':application,'io.komizo.instance':'production',
        'io.komizo.service':'upstream','io.komizo.release':record['release_digest'],'io.komizo.ownership':record['ownership']}
    if actual['Id']!=record['id'] or any(labels.get(key)!=value for key,value in expected.items()):
        raise ValueError('upstream native container ownership changed')
    return {'record':record,'config_sha256':identity,'wanted':config['wanted'],
        'creation_sha256':hashlib.sha256(creation_bytes).hexdigest(),
        'creation_unit_sha256':creation['record']['unit_sha256'],
        'original_operation_sha256':hashlib.sha256(bounded(state/'operations'/(operation+'.json'),16384)).hexdigest(),
        'installed_operation_id':installed['operation_id'],'desired_running':installed['desired_running'],
        'native':{'id':actual['Id'],**{key:actual['State'][key] for key in [
            'Running','Paused','Pid','StartedAt','FinishedAt','ExitCode','OOMKilled']}}}


def stopped_upstream(before, after):
    if (before['wanted'] is not True or after['wanted'] is not False or after['desired_running'] is not False
            or before['config_sha256']!=before['creation_unit_sha256']
            or after['config_sha256']==before['config_sha256']
            or before['native']['Running'] is not True or after['native']['Running'] is not False
            or before['native']['Paused'] is not False or before['native']['Pid']<=0
            or before['native']['StartedAt']=='0001-01-01T00:00:00Z'
            or after['native']['FinishedAt']=='0001-01-01T00:00:00Z'
            or after['native']['Paused'] is not False or after['native']['Pid']!=0
            or before['native']['OOMKilled'] or after['native']['OOMKilled']
            or before['native']['id']!=after['native']['id']
            or before['native']['StartedAt']!=after['native']['StartedAt']
            or any(before[key]!=after[key] for key in ['creation_sha256','creation_unit_sha256',
                'original_operation_sha256','installed_operation_id'])):
        raise ValueError('normal Stop did not preserve the original upstream while accepting wanted=false')


def recovered_upstream(stopped, recovered):
    if stopped!=recovered:raise ValueError('owner recovery changed or started the stopped upstream service')


def preparation_workload(workload, limits, declared, upstream=False):
    workload['jobs']={'initialize':{'artifact':'job','user':'10001:10001',
        'limits':limits(16,50 if upstream else 100,16),'networks':[],'timeout_seconds':declared,
        'command':['sh','-c','echo preparation-job-entered']}}
    if upstream:
        # Sum admission still permits exactly the original 100m total: the
        # sleeping prerequisite and the job share that unchanged CPU envelope.
        workload['services']['upstream']={'artifact':'job','user':'10001:10001',
            'limits':limits(16,50,16),'networks':[],'stop_timeout_seconds':2,
            'command':['sleep','120'],
            'health':{'command':['/bin/busybox','sh','-c',':'],
                'interval_seconds':2,'timeout_seconds':2,'retries':3}}
        workload['jobs']['initialize']['needs']={'upstream':'healthy'}


def prepare(report):
    import fixture_runtime as runtime
    import fixture_tasks as tasks
    from acceptance import ROOT, MiB, run, write
    if len(os.sched_getaffinity(0))!=1 or report['profile']!='bounded':raise ValueError('preparation proof requires the unchanged one-CPU bounded profile')
    tasks.start('native-fixture-preparation-load',['/bin/busybox','sh','-c','while :; do :; done'],
        memory=4*MiB,pids=4,milli_cpus=100,seconds=120,production=True)
    observations={}
    try:
        for app,declared,pause in [('preptime',30,5),('prepoverrun',20,12)]:
            with Path('/etc/hosts').open('a') as output:output.write('127.0.0.1 '+app+'.localhost\n')
            policy=runtime.host_policy(app);policy['limits']=runtime.limits(96,100,32)
            write('/etc/komizo/apps/'+app+'.json',policy)
            document=runtime.release(app,'a'*40)
            document['artifacts']['job']=runtime.registry.image(ROOT/'registry',app,'a'*40)
            preparation_workload(document['workload'],runtime.limits,declared,app=='prepoverrun')
            body,result,observation=delayed_deploy(runtime,document,pause)
            receipt=receipts(app)
            actual=json.loads(run(['podman','--remote=false','container','inspect',receipt['container_id']]).stdout)[0]
            if (receipt['operation_id']!=observation['operation_id'] or actual['Id']!=receipt['container_id']
                    or actual['Config']['Timeout']!=receipt['native_timeout_seconds']
                    or not 0<receipt['native_timeout_seconds']<declared):raise ValueError('native timeout/identity proof differs')
            observation.update({'declared_total_seconds':declared,'receipt':receipt,'operation':result,
                'native_state':actual['State']})
            if app=='preptime':
                started=__import__('datetime').datetime.fromisoformat(actual['State']['StartedAt'].replace('Z','+00:00'))
                finished=__import__('datetime').datetime.fromisoformat(actual['State']['FinishedAt'].replace('Z','+00:00'))
                if (not result.get('ok') or result.get('phase')!='ready' or receipt['phase']!='completed'
                        or receipt['exit_code']!=0 or actual['State']['Running'] is not False
                        or actual['State']['ExitCode']!=0 or finished<started
                        or observation['total_elapsed_seconds']>=declared):raise ValueError('slow native preparation did not start/exit within unchanged total')
                runtime.fetch(app,body['release_digest'])
            else:
                state=actual['State']
                if (result.get('phase')!='needs_reconciliation' or result.get('ok') is not False
                        or receipt['phase']!='uncertain' or state['Status'] not in {'configured','created'}
                        or state['Running'] or state['Paused'] or state['Pid']!=0 or state['ExitCode']!=0 or state['OOMKilled']
                        or state['StartedAt']!='0001-01-01T00:00:00Z' or state['FinishedAt']!='0001-01-01T00:00:00Z'):
                    raise ValueError('preparation overrun did not refuse before any job start')
                refused=runtime.submit(runtime.request(app,'deploy',body['release_digest'],release=document))
                if refused.get('kind')!='komizo.error' or receipts(app)!=receipt:raise ValueError('uncertain never-started job replayed without owner recovery')
                upstream_before=upstream_snapshot(runtime,app,receipt['operation_id'])
            stopped=runtime.submit(runtime.request(app,'stop',body['release_digest']))
            if not stopped.get('ok') or runtime.installed(app)['desired_running']:raise ValueError('preparation fixture normal Stop failed')
            if app=='prepoverrun':
                upstream_stopped=upstream_snapshot(runtime,app,receipt['operation_id'])
                stopped_upstream(upstream_before,upstream_stopped)
                if receipts(app)!=receipt:raise ValueError('normal Stop changed the uncertain job receipt')
                recovered=runtime.submit(runtime.request(app,'recover',body['release_digest'],operation=receipt['operation_id']))
                abandoned=receipts(app)
                proof_path=Path('/var/lib/komizo/journal')/receipt['operation_id']/('job-never-started-'+receipt['identity'][7:]+'.json')
                proof=bounded(proof_path,64<<10);proof_value=json.loads(proof)
                if (not recovered.get('ok') or recovered.get('phase')!='ready'
                        or abandoned['phase']!='abandoned_before_start' or proof_value['receipt']!=receipt
                        or any(proof_value['native']['State'][key]!=state[key] for key in [
                            'Running','Paused','Pid','Status','ExitCode','StartedAt','FinishedAt','OOMKilled'])
                        or run(['podman','--remote=false','container','exists',receipt['container_id']],ok=False).returncode!=1):
                    raise ValueError('explicit owner recovery did not preserve/remove only never-started identity')
                upstream_recovered=upstream_snapshot(runtime,app,receipt['operation_id'])
                recovered_upstream(upstream_stopped,upstream_recovered)
                staged=runtime.submit(runtime.request(app,'deploy',body['release_digest'],release=document))
                if not staged.get('ok') or staged.get('phase')!='prepared_stopped':raise ValueError('fresh stopped deployment did not preserve stop intent')
                fresh=runtime.submit(runtime.request(app,'start',body['release_digest']))
                completed=receipts(app)
                if (not fresh.get('ok') or fresh.get('phase')!='ready' or completed['phase']!='completed'
                        or completed['container_id']==receipt['container_id'] or completed['ownership']==receipt['ownership']
                        or completed['operation_id']==receipt['operation_id'] or bounded(proof_path,64<<10)!=proof):
                    raise ValueError('fresh normal activation reused old job authority or changed its original evidence')
                runtime.fetch(app,body['release_digest'])
                fresh_upstream=runtime.container(runtime.installed(app)['resources']['containers']['upstream'])
                if not fresh_upstream['State']['Running']:raise ValueError('fresh normal activation did not start its healthy upstream dependency')
                final=runtime.submit(runtime.request(app,'stop',body['release_digest']))
                if not final.get('ok'):raise ValueError('recovered preparation fixture did not stop normally')
                observation.update({'owner_recovery':recovered,'abandoned_receipt':abandoned,'fresh_activation':fresh,
                    'completed_receipt':completed,'original_receipt_proof_sha256':hashlib.sha256(proof).hexdigest(),
                    'upstream_before_stop':upstream_before,'upstream_stopped':upstream_stopped,
                    'upstream_after_recovery':upstream_recovered})
            observations[app]=observation
    finally:tasks.stop('native-fixture-preparation-load')
    if tasks.populated('/komizo/production/native-fixture-preparation-load'):raise ValueError('owned preparation load remained active')
    write(ROOT/'job-preparation-observation.json',{'one_cpu':True,'fixed_budgets_unchanged':True,'observations':observations})
    report['checks'].update({name:'passed' for name in ['job_preparation_slow_1cpu','job_preparation_overrun_refused',
        'job_never_started_owner_recovery','job_never_started_fresh_activation']})
