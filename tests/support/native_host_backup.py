#!/usr/bin/env python3
"""Exercise protected capture and bounded encrypted export in the real guest.

The disposable owner's private key stays outside the capture host. Database
restoration and product application journeys remain separately scoped proofs.
"""
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import time

from acceptance import ROOT, BINARY, run, write
import fixture_runtime as runtime
import fixture_registry as registry


CAPTURE = b'''#!/usr/bin/python3
import hashlib,json,os,pathlib,subprocess,sys,tempfile
request=json.load(sys.stdin)
assert request['kind']=='komizo.backup-request' and request['version']==1
app=request['application'];instance=request['instance']
assert app in {'secretbox','pgbox'} and instance=='production'
root=pathlib.Path('/var/lib/komizo')
installed=json.loads((root/'instances'/f'{app}--{instance}.json').read_text())
assert installed['release_digest']==request['release_digest']==os.environ['KOMIZO_RELEASE_DIGEST']
assert request['operation_id']==os.environ['KOMIZO_OPERATION_ID']
release=json.loads((root/'releases'/(request['release_digest'][7:]+'.json')).read_text())
service='postgres' if app=='pgbox' else 'db'
resource=json.loads(subprocess.check_output(['/usr/local/bin/komizo-box','resource','--application',app,'--instance',instance,'--service',service]))
assert resource['release_digest']==request['release_digest'] and resource['deployment']['release']==release
if app=='pgbox':
    data=subprocess.check_output(['podman','--remote=false','exec',resource['container_name'],'pg_dump','--host=127.0.0.1','--username=fixture','--dbname=postgres','--format=custom'])
    assert data.startswith(b'PGDMP') and len(data)<1048576
else:
    volume=resource['volumes']['data']['name']
    mount=subprocess.check_output(['podman','--remote=false','volume','inspect',volume,'--format={{.Mountpoint}}'],text=True).strip()
    count=(pathlib.Path(mount)/'count').read_bytes()
    assert count==b'accepted\\n'
    data=json.dumps({'application':app,'release_digest':request['release_digest'],'count':count.decode()}).encode()
output=pathlib.Path(request['output_directory'])
assert str(output)==os.environ['KOMIZO_OUTPUT_DIRECTORY']
with tempfile.TemporaryDirectory(prefix='native-backup-',dir='/root/native-host') as temporary:
    plaintext=pathlib.Path(temporary)/'plain.json'
    plaintext.write_bytes(data)
    subprocess.run(['openssl','cms','-encrypt','-binary','-aes-256-cbc','-outform','DER','-in',str(plaintext),'-out',str(output/'snapshot.cms'),'/root/native-host/recipient.crt'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
snapshot=(output/'snapshot.cms').read_bytes()
receipt={'version':1,'ciphertext_sha256':hashlib.sha256(snapshot).hexdigest(),'deployment':{'application':app,'release_digest':request['release_digest'],'source':release['source'],'provider':release.get('providers')}}
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
    program=ROOT/'capture.py';write(program,CAPTURE,0o700)
    if not (ROOT/'recipient.crt').is_file() or (ROOT/'recipient.key').exists():
        raise ValueError('capture host must receive only the owner public recipient certificate')
    path=Path('/etc/komizo/apps/'+app+'.json');policy=json.loads(path.read_text())
    policy['backup']={'program':str(program),'sha256':registry.digest(CAPTURE),'timeout_seconds':30,'max_export_bytes':1<<20,'services':['postgres' if app=='pgbox' else 'db']}
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
    properties=run(['systemctl','show',unit,'--property=Slice,KillMode,ActiveState,ExecMainStatus']).stdout.decode().splitlines()
    if set(properties)!={'Slice=komizo-control.slice','KillMode=control-group','ActiveState=inactive','ExecMainStatus=0'}:
        raise ValueError('protected task escaped its finite systemd group or remained active')
    return capture


def capture_postgres(report):
    import fixture_postgres
    capture('pgbox',report,'postgresql-custom')
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
expected='0::/komizo.slice/komizo-control.slice/komizo-backup-'+identity+'.service/runner'
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
    resource['image_config_digest'],'sh','-c','trap "" TERM; echo entered > /data/task-helper-started; sleep 12; echo late > /data/task-helper-late'],
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
    dns_pid=int(run(['systemctl','show','komizo-dns.service','--property=MainPID','--value']).stdout)
    if dns_pid<=0:raise ValueError('task isolation proof lacks its shared control helper')
    dns_executable=Path('/proc')/str(dns_pid)/'exe'
    dns_sha256=hashlib.sha256(dns_executable.read_bytes()).hexdigest()
    dns_group=Path('/proc',str(dns_pid),'cgroup').read_text().strip()
    if dns_group!='0::/komizo.slice/komizo-control.slice/komizo-dns.service':
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
        if helper['parent']!='/komizo.slice/komizo-control.slice/'+unit or not helper['cgroup'].startswith(helper['parent']+'/'):
            raise ValueError('native helper escaped its delegated protected task parent')
        mount=Path(run(['podman','--remote=false','volume','inspect',helper['volume'],'--format={{.Mountpoint}}']).stdout.decode().strip())
        if not (mount/'task-helper-started').exists():raise ValueError('native task helper did not enter its actual workload')
        # Keep the controller absent until the deadline passes; its independent
        # task must terminate without startup reconciliation doing that work.
        run(['systemctl','stop','komizo-controller.service'])
        if run(['systemctl','is-active','komizo-controller.service'],ok=False).stdout.strip()!=b'inactive':
            raise ValueError('task deadline fixture did not stop its controller')
        intent=json.loads((Path('/var/lib/komizo/journal')/operation/'backup-task.json').read_text())
        if time.monotonic_ns()>=intent['deadline_monotonic_ns']:
            raise ValueError('controller did not become absent before the protected task deadline')
        def quiescent():
            if run(['systemctl','is-active',unit],ok=False).stdout.strip() not in {b'inactive',b'failed'}:return False
            value=run(['systemctl','show',unit,'--property=ControlGroup','--value']).stdout.decode().strip()
            if not value:return True
            events=Path('/sys/fs/cgroup')/value.removeprefix('/')/'cgroup.events'
            return not events.exists() or 'populated 0' in events.read_text().splitlines()
        runtime.until(quiescent,seconds=12)
        elapsed=time.monotonic()-began
        process=Path('/proc')/str(helper['pid'])
        try:
            state=(process/'status').read_text().split('State:',1)[1].splitlines()[0].strip().split()[0]
            helper_live=state!='Z' and helper['cgroup'] in (process/'cgroup').read_text()
        except FileNotFoundError:helper_live=False
        helper_late=(mount/'task-helper-late').exists()
        dns_unchanged=int(run(['systemctl','show','komizo-dns.service','--property=MainPID','--value']).stdout)==dns_pid
        dns_unchanged=dns_unchanged and hashlib.sha256(dns_executable.read_bytes()).hexdigest()==dns_sha256
        dns_unchanged=dns_unchanged and Path('/proc',str(dns_pid),'cgroup').read_text().strip()==dns_group
        if not dns_unchanged:raise ValueError('task expiry killed or replaced an unrelated shared control helper')
        write(ROOT/'task-deadline.json',{'timeout_seconds':8,'elapsed_seconds':elapsed,
            'controller_absent_at_expiry':True,'task_cgroup_quiescent':quiescent(),'late_write_present':late.exists(),
            'native_helper':helper,'helper_live_after_deadline':helper_live,'helper_late_write':helper_late,
            'shared_control_helper':{'pid':dns_pid,'executable_sha256':dns_sha256,'cgroup':dns_group[3:],'unchanged':dns_unchanged}})
        if elapsed>13 or late.exists() or helper_live or helper_late:
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
                            scope=Path('/sys/fs/cgroup/komizo.slice/komizo-control.slice')/unit/'cgroup.events'
                            empty=not scope.exists() or 'populated 0' in scope.read_text().splitlines()
                            write(ROOT/'task-helper-cleanup.json',{'container_id':identity,'parent_quiescent':empty,
                                'configured_parent':current['HostConfig']['CgroupParent'],
                                'state':{key:state.get(key) for key in ['Status','Running','Pid','ConmonPid','ExitCode','Error']}})
                            if (current['Id']!=identity or current['Config']['Labels'].get('io.komizo.fixture.operation')!=operation
                                    or current['HostConfig']['CgroupParent']!='/komizo.slice/komizo-control.slice/'+unit
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
            run(['systemctl','start','komizo-controller.service'])
            runtime.until(lambda:run(['systemctl','is-active','komizo-controller.service'],ok=False).stdout.strip()==b'active')
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


def prepare(report):
    capture('secretbox',report,'synthetic-volume-json')
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
