#!/usr/bin/env python3
"""Exercise protected capture and bounded encrypted export in the real guest.

The disposable owner's private key stays outside the capture host. Database
restoration and product application journeys remain separately scoped proofs.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

from acceptance import ROOT, BINARY, run, write, task_completed, service_active, dns_pid, group_empty
import fixture_runtime as runtime
import fixture_registry as registry


CAPTURE = b'''#!/usr/bin/python3 -IB
from datetime import datetime,timezone
import hashlib,importlib.util,json,os,pathlib,shutil,sqlite3,subprocess,sys,tarfile,tempfile
request=json.load(sys.stdin)
assert request['kind']=='komizo.backup-request' and request['version']==1
app=request['application'];instance=request['instance']
assert app=='secretbox' and instance=='production'
root=pathlib.Path('/var/lib/komizo')
installed=json.loads((root/'instances'/f'{app}--{instance}.json').read_text())
assert installed['release_digest']==request['release_digest']==os.environ['KOMIZO_RELEASE_DIGEST']
assert request['operation_id']==os.environ['KOMIZO_OPERATION_ID']
release=json.loads((root/'releases'/(request['release_digest'][7:]+'.json')).read_text())
resource=json.loads(subprocess.check_output(['/usr/local/bin/komizo-box','resource','--application',app,'--instance',instance,'--service','db']))
assert resource['release_digest']==request['release_digest'] and resource['deployment']['release']==release
volume=resource['volumes']['data']['name']
mount=subprocess.check_output(['podman','--remote=false','volume','inspect',volume,'--format={{.Mountpoint}}'],text=True).strip()
retained=pathlib.Path(mount)/'count'
assert not retained.is_symlink() and retained.is_file() and retained.stat().st_nlink==1
count=retained.read_bytes();assert count==b'accepted\\n'
output=pathlib.Path(request['output_directory'])
assert str(output)==os.environ['KOMIZO_OUTPUT_DIRECTORY']
expected_helpers=__RECOVERY_HELPERS__
for name,identity in expected_helpers.items():
    assert name in {'snapshot.py','postgres-recovery.py'}
    path=pathlib.Path('/root/native-host/recovery')/name
    assert not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest()==identity
spec=importlib.util.spec_from_file_location('fixture_snapshot','/root/native-host/recovery/snapshot.py')
snapshot=importlib.util.module_from_spec(spec);spec.loader.exec_module(snapshot)
with tempfile.TemporaryDirectory(prefix='native-backup-',dir='/root/native-host') as temporary:
    package=pathlib.Path(temporary)
    database=package/'data.db'
    with sqlite3.connect(database) as connection:
        connection.executescript('CREATE TABLE _collections(name TEXT); CREATE TABLE _migrations(name TEXT); CREATE TABLE evidence(application TEXT,release_digest TEXT,value TEXT);')
        connection.execute('INSERT INTO evidence VALUES (?,?,?)',(app,request['release_digest'],count.decode()))
    connection.close()
    database.chmod(0o600)
    archive=package/'data.tar.gz'
    with tarfile.open(archive,'x:gz') as bundle:bundle.add(database,arcname='data.db',recursive=False)
    restored=package/'validation';restored.mkdir(mode=0o700)
    evidence=snapshot.restore(archive,restored)
    evidence.update(image_id=resource['image_config_digest'],image_reference=resource['image_ref'],verified_at=datetime.now(timezone.utc).isoformat())
    (package/'verification.json').write_text(json.dumps(evidence))
    sealed=snapshot.seal(package,pathlib.Path('/root/native-host/recipient.crt'))
    receipt=json.loads((sealed/'receipt.json').read_text());assert receipt['format']==2
    # This is a synthetic SQLite framing proof. The encrypted row independently
    # binds its scope; real PostgreSQL proves generic deployment authentication.
    receipt['deployment']={'application':app,'release_digest':request['release_digest'],'source':release['source'],'provider':release.get('providers')}
    shutil.copyfile(sealed/'snapshot.cms',output/'snapshot.cms')
    (output/'receipt.json').write_text(json.dumps(receipt,sort_keys=True,separators=(',',':')))
for path in output.iterdir():path.chmod(0o600)
'''


def export(app, release, operation, metadata):
    request=runtime.request(app,'export',release,operation=operation,export_name=metadata['name'])
    response=run([BINARY,'submit'],input=registry.canonical(request),ok=False)
    if response.returncode:raise ValueError('protected ciphertext export failed')
    line,separator,body=response.stdout.partition(b'\n')
    if not separator or len(line)>16384:raise ValueError('ciphertext export lacks its bounded typed header')
    header=json.loads(line)
    expected={'kind':'komizo.export','version':1,'application':app,'instance':'production','release_digest':release,
        'operation_id':operation,'export_name':metadata['name'],'size_bytes':metadata['size_bytes'],'sha256':metadata['sha256']}
    if header!=expected or len(body)!=metadata['size_bytes'] or registry.digest(body)!=metadata['sha256']:
        raise ValueError('export framing or ciphertext identity differs from accepted capture')
    return body


def capture(app,report,format):
    installed=runtime.installed(app);release=installed['release_digest']
    if app=='pgbox':
        program=ROOT/'capture-pgbox.bundle';body=program.read_bytes()
    else:
        helpers=json.loads((ROOT/'profile.json').read_text())['backup_helpers']
        if set(helpers)!={'snapshot.py','postgres-recovery.py'} or any(
                not isinstance(value,str) or not __import__('re').fullmatch('[a-f0-9]{64}',value) for value in helpers.values()):
            raise ValueError('synthetic capture requires its exact immutable recovery helper inventory')
        program=ROOT/'capture.py';body=CAPTURE.replace(b'__RECOVERY_HELPERS__',registry.canonical(helpers));write(program,body,0o700)
    if not (ROOT/'recipient.crt').is_file() or (ROOT/'recipient.key').exists():
        raise ValueError('capture host must receive only the owner public recipient certificate')
    path=Path('/etc/komizo/apps/'+app+'.json');policy=json.loads(path.read_text())
    policy['backup']={'program':str(program),'sha256':registry.digest(body),'timeout_seconds':30,'max_export_bytes':1<<20,'services':['postgres' if app=='pgbox' else 'db']}
    write(path,policy)
    capture=runtime.submit(runtime.request(app,'backup',release))
    if (not capture.get('ok') or capture.get('backup',{}).get('status')!='ready'
            or capture['backup'].get('release_digest')!=release):
        raise ValueError('protected encrypted capture did not complete: '+json.dumps(capture))
    metadata=capture['backup']['files']
    if sorted(value['name'] for value in metadata)!=['receipt.json','snapshot.cms']:raise ValueError('capture exported an unexpected file set')
    pair={value['name']:export(app,release,capture['operation_id'],value) for value in metadata}
    receipt=json.loads(pair['receipt.json'])
    if receipt['deployment']['release_digest']!=release or receipt['ciphertext_sha256']!=hashlib.sha256(pair['snapshot.cms']).hexdigest():
        raise ValueError('encrypted pair lost installed source or integrity binding')
    report.setdefault('owner_exports',[]).append({'application':app,'instance':'production','release_digest':release,
        'operation_id':capture['operation_id'],'files':metadata,'format':format})
    unit='komizo-backup-'+capture['operation_id']+'.service'
    task_completed('backup',capture['operation_id'])
    return capture


def capture_postgres(report):
    import fixture_postgres
    capture('pgbox',report,'postgresql-package-v2')
    if fixture_postgres.query('SELECT value FROM evidence')!=b'retained native row':raise ValueError('PostgreSQL capture changed initialized rows')
    report['checks']['protected_postgresql_encrypted_capture']='passed'


def interrupted_deadline(report):
    # This reviewed synthetic program deliberately ignores TERM and gives its
    # child a new session and starts a native helper. The delegated task parent
    # must own all three, independently of client/conmon process groups.
    program=ROOT/'task-deadline.py'
    payload=b'''#!/usr/bin/python3
import json,pathlib,re,signal,subprocess,sys,time
request=json.load(sys.stdin)
assert request['kind']=='komizo.backup-request' and request['application']=='secretbox'
root=pathlib.Path('/root/native-host');identity=request['operation_id']
(root/(identity+'-program-entered')).write_text('entered')
signal.signal(signal.SIGTERM,signal.SIG_IGN)
subprocess.Popen([sys.executable,'-I','-B','-c','import pathlib,signal,time,sys;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(12);pathlib.Path(sys.argv[1]).write_text("late")',str(root/(identity+'-late'))],start_new_session=True)
group=pathlib.Path('/proc/self/cgroup').read_text().strip()
expected='0::/komizo/control/komizo-backup-'+identity+'.service/runner'
assert group==expected
parent=group[3:].removesuffix('/runner')
resource=json.loads((root/(identity+'-helper-source.json')).read_text())
assert resource['release_digest']==request['release_digest']
volume=resource['volume']
name='native-task-'+identity;cidfile=root/(identity+'-helper.cid')
subprocess.Popen(['podman','--remote=false','--cgroup-manager=cgroupfs','run','--name='+name,'--cidfile='+str(cidfile),
    '--pull=never','--timeout=0','--cgroup-parent='+parent,'--image-volume=ignore','--http-proxy=false','--network=none',
    '--read-only','--read-only-tmpfs=false','--cap-drop=all','--security-opt=no-new-privileges','--user=10001:10001',
    '--memory=16m','--memory-swap=16m','--cpu-period=1000000','--cpu-quota=100000','--pids-limit=16',
    '--label=io.komizo.fixture.operation='+identity,'--volume='+volume+':/data:rw','--entrypoint=/bin/busybox',
    resource['image_config_digest'],'sh','-c','trap "" TERM; echo entered > /data/task-helper-started; /bin/busybox sleep 12; echo late > /data/task-helper-late'],
    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
end=time.monotonic()+5
while time.monotonic()<end:
    result=subprocess.run(['podman','--remote=false','--cgroup-manager=cgroupfs','container','inspect',name],capture_output=True)
    if result.returncode==0:
        actual=json.loads(result.stdout)[0]
        if actual['State']['Running']:
            assert actual['Config']['Timeout']==0
            assert actual['HostConfig']['CgroupParent']==parent
            current=pathlib.Path('/proc/'+str(actual['State']['Pid'])+'/cgroup').read_text().strip()
            assert current.startswith('0::'+parent+'/') and current!='0::'+parent+'/runner'
            conmon=actual['State']['ConmonPid']
            conmon_group=pathlib.Path('/proc/'+str(conmon)+'/cgroup').read_text().strip()
            assert conmon>0 and conmon_group.startswith('0::'+parent+'/')
            (root/(identity+'-helper.json')).write_text(json.dumps({'id':actual['Id'],'name':name,'pid':actual['State']['Pid'],
                'conmon_pid':conmon,'conmon_cgroup':conmon_group[3:],
                'parent':parent,'configured_parent':actual['HostConfig']['CgroupParent'],
                'cgroup':current[3:],'native_timeout_seconds':actual['Config']['Timeout'],'volume':volume}))
            break
    time.sleep(.05)
else:raise RuntimeError('native delegated helper did not start')
(root/(identity+'-entered')).write_text('entered')
time.sleep(600)
'''
    write(program,payload,0o700)
    path=Path('/etc/komizo/apps/secretbox.json');saved=path.read_bytes();policy=json.loads(saved)
    policy['backup']={'program':str(program),'sha256':registry.digest(payload),'timeout_seconds':90,
        'max_export_bytes':1<<20,'services':['db']}
    write(path,policy)
    release=runtime.installed('secretbox')['release_digest']
    source=json.loads(run([BINARY,'resource','--application','secretbox','--instance','production','--service','db']).stdout)
    if source['release_digest']!=release:raise ValueError('task helper source changed before its isolated deadline probe')
    nonce=secrets.token_hex(16)
    operation=hashlib.sha256(('komizo-operation-v1\0secretbox\0production\0'+nonce).encode()).hexdigest()[:32]
    write(ROOT/(operation+'-helper-source.json'),{'release_digest':release,
        'image_config_digest':source['image_config_digest'],'volume':source['volumes']['data']['name']})
    # Only data-only resource preparation is outside the negative probe. Its
    # real native create/start and all effects still share the same eight seconds.
    shared_dns_pid=dns_pid()
    if shared_dns_pid<=0:raise ValueError('task isolation proof lacks its shared control helper')
    dns_executable=Path('/proc')/str(shared_dns_pid)/'exe'
    dns_sha256=hashlib.sha256(dns_executable.read_bytes()).hexdigest()
    dns_group=Path('/proc',str(shared_dns_pid),'cgroup').read_text().strip()
    if dns_group!='0::/komizo/control/dns':
        raise ValueError('unrelated task isolation helper is outside the shared control budget')
    entered=ROOT/(operation+'-entered');late=ROOT/(operation+'-late')
    helper_record=ROOT/(operation+'-helper.json');helper_cid=ROOT/(operation+'-helper.cid')
    body=runtime.request('secretbox','backup',release,timeout_seconds=8,nonce=nonce)
    child=subprocess.Popen([BINARY,'submit'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    child.stdin.write(registry.canonical(body));child.stdin.close();began=time.monotonic()
    unit='komizo-backup-'+operation+'.service'
    write(ROOT/'task-start-observation.json',{'operation_id':operation,'program_entered':False,'helper_entered':False})
    try:
        runtime.until(entered.exists,seconds=7)
        helper=json.loads(helper_record.read_text())
        if helper['parent']!='/komizo/control/'+unit or not helper['cgroup'].startswith(helper['parent']+'/'):
            raise ValueError('native helper escaped its delegated protected task parent')
        mount=Path(run(['podman','--remote=false','volume','inspect',helper['volume'],'--format={{.Mountpoint}}']).stdout.decode().strip())
        if not (mount/'task-helper-started').exists():raise ValueError('native task helper did not enter its actual workload')
        # Bind the exact admitted root task runner before making its controller
        # absent, then kill that runner too. The separate watchdog must retain
        # the original absolute lifetime when both owners disappear.
        expected_argv=[BINARY,'task-run','--operation',operation,'--task','backup']
        runners=[]
        for candidate in Path('/proc').iterdir():
            if not candidate.name.isdecimal():continue
            try:
                argv=(candidate/'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
                if argv!=[part.encode() for part in expected_argv]:continue
                if ((candidate/'exe').resolve()!=Path(BINARY).resolve()
                        or (candidate/'cgroup').read_text().strip()!='0::/komizo/control/'+unit+'/runner'
                        or (candidate/'status').read_text().split('Uid:',1)[1].splitlines()[0].split()!=['0']*4):
                    raise ValueError('selected task runner lost its exact owned process binding')
                runners.append(int(candidate.name))
            except FileNotFoundError:continue
        if len(runners)!=1:raise ValueError('deadline probe lacks one exact protected task runner')
        runner_fd=os.pidfd_open(runners[0])
        # Keep the controller absent until the deadline passes; its independent
        # task must terminate without startup reconciliation doing that work.
        run(['rc-service','komizo-controller','stop'])
        if service_active('komizo-controller'):
            raise ValueError('task deadline fixture did not stop its controller')
        try:
            __import__('signal').pidfd_send_signal(runner_fd,__import__('signal').SIGKILL)
        finally:os.close(runner_fd)
        intent=json.loads((Path('/var/lib/komizo/journal')/operation/'backup-task.json').read_text())
        if time.monotonic_ns()>=intent['deadline_monotonic_ns']:
            raise ValueError('controller did not become absent before the protected task deadline')
        # Early cleanup is not the independent deadline proof. Keep both
        # native helper processes alive until two seconds before the original
        # absolute deadline, with both task owners already absent.
        sample_at=intent['deadline_monotonic_ns']-2_000_000_000
        if time.monotonic_ns()>=sample_at:
            raise ValueError('deadline probe cannot observe its original two-second margin')
        while time.monotonic_ns()<sample_at:
            left=sample_at-time.monotonic_ns()
            if left>0:time.sleep(min(.05,left/1e9))
        for field,group in [('pid','cgroup'),('conmon_pid','conmon_cgroup')]:
            process=Path('/proc')/str(helper[field])
            status=(process/'status').read_text()
            if ('State:\tZ' in status or (process/'cgroup').read_text().strip()!='0::'+helper[group]):
                raise ValueError('helper or conmon died before its independent absolute deadline')
        live_before_expiry=time.monotonic_ns()
        def quiescent():
            return group_empty('/komizo/control/'+unit)
        runtime.until(quiescent,seconds=12)
        elapsed=time.monotonic()-began
        if (Path('/var/lib/komizo/journal')/operation/'backup-completed.json').exists():
            raise ValueError('killed protected backup fabricated a successful completion')
        process=Path('/proc')/str(helper['pid'])
        try:
            state=(process/'status').read_text().split('State:',1)[1].splitlines()[0].strip().split()[0]
            helper_live=state!='Z' and helper['cgroup'] in (process/'cgroup').read_text()
        except FileNotFoundError:helper_live=False
        conmon=Path('/proc')/str(helper['conmon_pid'])
        try:conmon_live=not (conmon/'status').read_text().split('State:',1)[1].splitlines()[0].strip().startswith('Z')
        except FileNotFoundError:conmon_live=False
        helper_late=(mount/'task-helper-late').exists()
        dns_unchanged=dns_pid()==shared_dns_pid
        dns_unchanged=dns_unchanged and hashlib.sha256(dns_executable.read_bytes()).hexdigest()==dns_sha256
        dns_unchanged=dns_unchanged and Path('/proc',str(shared_dns_pid),'cgroup').read_text().strip()==dns_group
        if not dns_unchanged:raise ValueError('task expiry killed or replaced an unrelated shared control helper')
        write(ROOT/'task-deadline.json',{'timeout_seconds':8,'elapsed_seconds':elapsed,
            'controller_absent_at_expiry':True,'exact_task_runner_killed':runners[0],
            'helper_and_conmon_live_before_deadline_ns':live_before_expiry,'original_deadline_ns':intent['deadline_monotonic_ns'],'task_cgroup_quiescent':quiescent(),'late_write_present':late.exists(),
            'native_helper':helper,'helper_live_after_deadline':helper_live,'conmon_live_after_deadline':conmon_live,'helper_late_write':helper_late,
            'shared_control_helper':{'pid':shared_dns_pid,'executable_sha256':dns_sha256,'cgroup':dns_group[3:],'unchanged':dns_unchanged}})
        if elapsed>13 or late.exists() or helper_live or conmon_live or helper_late:
            raise ValueError('protected task or native/new-session descendant exceeded its absolute operation lifetime')
        report['checks'].update({'protected_task_absolute_deadline':'passed',
            'protected_task_survives_controller_death':'passed','protected_task_descendant_deadline':'passed',
            'protected_task_native_helper_deadline':'passed','protected_task_preserves_shared_control_helper':'passed'})
    finally:
        try:
            if helper_cid.exists():
                identity=helper_cid.read_text().strip()
                if __import__('re').fullmatch('[a-f0-9]{64}',identity):
                    engine=['podman','--remote=false','--cgroup-manager=cgroupfs']
                    observed=run([*engine,'container','inspect',identity],ok=False)
                    if observed.returncode==0 and json.loads(observed.stdout)[0]['Config']['Labels'].get('io.komizo.fixture.operation')==operation:
                        removed=run([*engine,'rm','--force','--time=0',identity],ok=False)
                        if removed.returncode:
                            # Podman5.4.2 saves a stopped unknown-exit state after
                            # detecting dead conmon, but returns an error from
                            # the first forced removal. Admit only that state.
                            current=json.loads(run([*engine,'container','inspect',identity]).stdout)[0]
                            state=current['State']
                            scope=Path('/sys/fs/cgroup/komizo/control')/unit/'cgroup.events'
                            empty=not scope.exists() or 'populated 0' in scope.read_text().splitlines()
                            write(ROOT/'task-helper-cleanup.json',{'container_id':identity,'parent_quiescent':empty,
                                'configured_parent':current['HostConfig']['CgroupParent'],
                                'state':{key:state.get(key) for key in ['Status','Running','Pid','ConmonPid','ExitCode','Error']}})
                            if (current['Id']!=identity or current['Config']['Labels'].get('io.komizo.fixture.operation')!=operation
                                    or current['HostConfig']['CgroupParent']!='/komizo/control/'+unit
                                    or state['Status']!='exited' or type(state['Pid']) is not int
                                    or not empty or state['Running'] is not False or state['Pid']!=0
                                    # Native5.4.2 inspect omits integer zero.
                                    or type(state.get('ConmonPid',0)) is not int or state.get('ConmonPid',0)!=0
                                    or type(state['ExitCode']) is not int or state['ExitCode']!=-1
                                    or state['Error']!='conmon died without writing exit file, container exit code could not be retrieved'):
                                raise ValueError('dead native helper lacks its exact quiescent unknown-exit cleanup state')
                            run([*engine,'rm',identity])
                        if run([*engine,'container','exists',identity],ok=False).returncode!=1:
                            raise ValueError('owned task helper metadata remained after scoped removal')
        finally:
            write(path,saved)
            run(['rc-service','komizo-controller','start'])
            runtime.until(lambda:service_active('komizo-controller'))
            try:child.wait(timeout=10)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
            response=child.stdout.read(16385)
            receipt=None
            if len(response)<=16384:
                try:
                    value=json.loads(response)
                    receipt={key:value[key] for key in ['kind','version','operation_id','phase','ok','reconciliation_required'] if key in value}
                except ValueError:pass
            write(ROOT/'task-start-observation.json',{'operation_id':operation,
                'program_entered':(ROOT/(operation+'-program-entered')).exists(),'helper_entered':entered.exists(),
                'transport_exit_code':child.returncode,'receipt':receipt})
            child.stdout.close();child.stderr.close()


def restored_first_start(report):
    """First activation of owner-transferred data has no old runtime parent."""
    app='restored'
    with Path('/etc/hosts').open('a') as output:output.write('127.0.0.1 '+app+'.localhost\n')
    policy=runtime.host_policy(app)
    helpers=json.loads((ROOT/'profile.json').read_text())['backup_helpers']
    if set(helpers)!={'snapshot.py','postgres-recovery.py'} or any(
            not isinstance(value,str) or not __import__('re').fullmatch('[a-f0-9]{64}',value) for value in helpers.values()):
        raise ValueError('restored-start capture requires its immutable recovery helpers')
    body=CAPTURE.replace(b'__RECOVERY_HELPERS__',registry.canonical(helpers)).replace(
        b"assert app=='secretbox' and instance=='production'",b"assert app=='restored' and instance=='production'")
    program=ROOT/'capture-restored.py';write(program,body,0o700)
    policy['backup']={'program':str(program),'sha256':registry.digest(body),'timeout_seconds':30,
        'max_export_bytes':1<<20,'services':['db']}
    write('/etc/komizo/apps/'+app+'.json',policy)
    document=runtime.release(app,'a'*40,dynamic=True)
    identity=registry.digest(registry.canonical(document))
    prepared=runtime.submit(runtime.request(app,'data-prepare',identity,release=document))
    if prepared.get('phase')!='prepared_stopped' or not prepared.get('ok'):
        raise ValueError('restored first-start data preparation failed: '+json.dumps(prepared))
    resources=runtime.installed(app)['resources']
    for record in resources['containers'].values():
        if run(['podman','--remote=false','container','exists',record['name']],ok=False).returncode!=1:
            raise ValueError('restored first-start fixture has a prior service container')
    volume=resources['volumes']['data']
    mount=Path(run(['podman','--remote=false','volume','inspect',volume['name'],'--format={{.Mountpoint}}']).stdout.decode().strip())
    if any(mount.iterdir()):raise ValueError('restored fixture expected a new empty retained volume')
    # Simulate the disposable owner's file transfer, not an earlier application
    # activation. The capture program requires this exact pre-migration value.
    seed=b'accepted\n';retained=mount/'count';retained.write_bytes(seed)
    os.chown(retained,10001,10001);os.chmod(retained,0o600)
    os.chown(mount,10001,10001);os.chmod(mount,0o700)
    snapshot=registry.digest(b'synthetic-owner-retained-file-transfer')
    verification={'kind':'komizo.data-verification','version':1,'application':app,'instance':'production',
        'release_digest':identity,'volumes':resources['volumes'],'snapshot_sha256':snapshot,'created_at':int(time.time()),
        'checks':{'database':'passed','authorization':'passed','files':'passed'},
        'observations':{'fixture':'synthetic-native-retained-file-transfer','retained_sha256':registry.digest(seed)}}
    verification_hash=registry.digest(registry.canonical(verification))
    reports=Path('/var/lib/komizo/data-evidence/reports');reports.mkdir(mode=0o700,parents=True,exist_ok=True)
    write(reports/(verification_hash[7:]+'.json'),verification)
    evidence={'kind':'komizo.data-evidence','version':1,'application':app,'instance':'production','release_digest':identity,
        'volumes':resources['volumes'],'created_at':int(time.time()),
        'source':{'kind':'transfer','snapshot_sha256':snapshot,'verification_sha256':verification_hash}}
    write('/var/lib/komizo/data-evidence/'+app+'--production.json',evidence)
    accepted=runtime.submit(runtime.request(app,'data-accept',identity,data_evidence=registry.digest(registry.canonical(evidence))))
    if not accepted.get('ok') or runtime.installed(app)['desired_running'] or retained.read_bytes()!=seed:
        raise ValueError('restored first-start data acceptance changed stopped data')
    staged=runtime.submit(runtime.request(app,'deploy',identity,release=document))
    if not staged.get('ok') or staged.get('phase')!='prepared_stopped' or retained.read_bytes()!=seed:
        raise ValueError('restored first-start source staging executed migration')
    namespace='kmz-'+hashlib.sha256((app+'\0production').encode()).hexdigest()[:20]
    parent=Path('/sys/fs/cgroup/komizo/production')/namespace
    if parent.exists() or parent.is_symlink():raise ValueError('restored fixture already has a runtime instance parent')
    started=runtime.submit(runtime.request(app,'start',identity))
    backup=started.get('backup',{})
    if (not started.get('ok') or started.get('phase')!='ready' or not parent.is_dir()
            or backup.get('status')!='ready' or backup.get('release_digest')!=identity
            or started.get('previous_release_digest')!=identity or runtime.count(app)!=2):
        raise ValueError('restored first Start failed backup-before-migration: '+json.dumps(started))
    # The protected capture asserted one retained row; initialization has now
    # appended the second. Both source-bound encrypted exports remain readable.
    if sorted(value['name'] for value in backup['files'])!=['receipt.json','snapshot.cms']:
        raise ValueError('restored first Start lacks its complete protected backup')
    for metadata in backup['files']:export(app,identity,started['operation_id'],metadata)
    if b'a'*40 not in runtime.fetch(app,identity):raise ValueError('restored first Start did not activate its selected source')
    runtime.application_limits(app)
    stopped=runtime.submit(runtime.request(app,'stop',identity))
    if not stopped.get('ok') or stopped.get('phase')!='prepared_stopped' or runtime.count(app)!=2:
        raise ValueError('restored first-start cleanup did not retain stopped data')
    report['checks']['restored_first_start_backup_before_migration']='passed'


def prepare(report):
    restored_first_start(report)
    capture('secretbox',report,'synthetic-sqlite-package-v2')
    if runtime.count('secretbox')!=1:raise ValueError('protected capture changed retained data')
    interrupted_deadline(report)
    # The deliberately stopped instance must never be started for capture.
    stopped=runtime.submit(runtime.request('mailroom','backup',runtime.installed('mailroom')['release_digest']))
    if stopped.get('ok') is not False or runtime.count('mailroom')!=1:raise ValueError('routine stopped capture changed data or claimed a backup')
    # Absence is asserted against the actual namespace, including orphan data.
    runtime.host_policy('emptybox')
    absent=runtime.submit(runtime.request('emptybox','backup','absent'))
    if not absent.get('ok') or absent.get('backup',{}).get('status')!='absent':raise ValueError('empty namespace absence assertion failed')
    namespace='kmz-'+hashlib.sha256(b'emptybox\0production').hexdigest()[:20]
    orphan=namespace+'-orphan'
    run(['podman','--remote=false','volume','create',orphan])
    try:
        denied=runtime.submit(runtime.request('emptybox','backup','absent'))
        if denied.get('ok') is not False:raise ValueError('orphan data masqueraded as an empty installation')
    finally:run(['podman','--remote=false','volume','rm',orphan])
    report['checks'].update({'protected_encrypted_capture':'passed','exact_export_framing':'passed','encrypted_pair_integrity':'passed',
        'installed_source_backup_binding':'passed','capture_host_has_no_recovery_private_key':'passed','backup_task_group_deadline':'passed',
        'stopped_backup_refused':'passed','namespace_absence_proof':'passed','orphan_data_absence_refused':'passed'})
