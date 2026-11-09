#!/usr/bin/env python3
"""Exercise the real immutable PostgreSQL base through native host admission."""
import copy
import hashlib
import json
from pathlib import Path
import secrets
import time
import threading
import tarfile

from acceptance import ROOT, MiB, run, write
import fixture_registry as registry
import fixture_runtime as runtime

BASE='docker.io/library/postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
def source():return json.loads((ROOT/'profile.json').read_text())['source']


def postgres_artifact():
    identity=source();revision=identity['revision']
    context=ROOT/'postgres-build';context.mkdir(mode=0o700)
    (context/'Containerfile').write_text('FROM '+BASE+'\nLABEL org.opencontainers.image.source="https://github.com/'+identity['repository']+'" org.opencontainers.image.revision="'+revision+'"\n')
    run(['podman','--remote=false','pull',BASE],timeout=300)
    tag='localhost/native-pgbox:'+revision
    run(['podman','--remote=false','build','--format=oci','--layers','--pull=never','--network=none',
        '--file',str(context/'Containerfile'),'--tag',tag,str(context)],timeout=180)
    # The fixture adds source labels only; compare complete functional config
    # and ordered RootFS to the immutable upstream image before accepting it.
    base,wrapped=json.loads(run(['podman','--remote=false','image','inspect',BASE,tag]).stdout)
    left=copy.deepcopy(base['Config']);right=copy.deepcopy(wrapped['Config'])
    left.pop('Labels',None);right.pop('Labels',None)
    changed={key:{'base':left.get(key),'wrapped':right.get(key)} for key in sorted(left.keys()|right.keys()) if left.get(key)!=right.get(key) or (key in left)!=(key in right)}
    write(ROOT/'postgres-wrapper.json',{'base_reference':BASE,'config_differences':changed,'base_rootfs':base['RootFS'],'wrapped_rootfs':wrapped['RootFS']})
    if left!=right or base['RootFS']!=wrapped['RootFS']:raise ValueError('source-label wrapper changed PostgreSQL runtime; changed Config keys='+repr(sorted(changed))+', RootFS_equal='+str(base['RootFS']==wrapped['RootFS']))
    archive=ROOT/'postgres.oci.tar'
    run(['podman','--remote=false','save','--format=oci-archive','--output',str(archive),tag],timeout=180)
    blobroot=ROOT/'registry'/'blobs'
    with tarfile.open(archive,'r:') as package:
        descriptors=json.load(package.extractfile('index.json'))['manifests']
        if len(descriptors)!=1:raise ValueError('PostgreSQL fixture archive has ambiguous manifests')
        descriptor=descriptors[0]
        for member in package.getmembers():
            if not member.name.startswith('blobs/sha256/') or not member.isfile():continue
            identity=member.name.removeprefix('blobs/sha256/')
            target=blobroot/identity;incoming=package.extractfile(member);value=hashlib.sha256();size=0
            with target.open('wb') as output:
                while body:=incoming.read(1<<16):value.update(body);size+=len(body);output.write(body)
            if value.hexdigest()!=identity or size!=member.size:raise ValueError('PostgreSQL fixture archive blob changed')
        manifest=json.loads((blobroot/descriptor['digest'][7:]).read_bytes())
        config=json.loads((blobroot/manifest['config']['digest'][7:]).read_bytes())
        if config['os']!='linux' or config['architecture']!='amd64':raise ValueError('PostgreSQL fixture platform differs')
    archive.unlink()
    # Resolve the pinned image's actual postgres UID; there is no root workload.
    uid=run(['podman','--remote=false','run','--rm','--network=none','--read-only','--memory=64m','--pids-limit=32',
        '--entrypoint=id',tag,'-u','postgres']).stdout.decode().strip()
    gid=run(['podman','--remote=false','run','--rm','--network=none','--read-only','--memory=64m','--pids-limit=32',
        '--entrypoint=id',tag,'-g','postgres']).stdout.decode().strip()
    if not uid.isdecimal() or not gid.isdecimal() or int(uid)==0:raise ValueError('PostgreSQL fixture has no explicit unprivileged identity')
    return {'kind':'image','reference':'registry.fixture.test:5443/example/pgbox-postgres@'+descriptor['digest'],
        'digest':descriptor['digest'],'config_digest':manifest['config']['digest'],'platform':'linux/amd64'},uid+':'+gid


def query(sql, instance='production'):
    installed=json.loads(Path('/var/lib/komizo/instances/pgbox--'+instance+'.json').read_text())
    name=installed['resources']['containers']['postgres']['name']
    return run(['podman','--remote=false','exec',name,'psql','--host=127.0.0.1','--username=fixture','--dbname=postgres',
        '--no-psqlrc','--tuples-only','--no-align','--set=ON_ERROR_STOP=1','--command',sql]).stdout.strip()


def diagnostic():
    """Collect only bounded synthetic process/health/resource facts, never Env."""
    evidence={}
    try:
        record=runtime.installed('pgbox')['resources']['containers']['postgres']
        actual=runtime.container(record);identity=actual['Id']
        evidence['state']=actual['State'];evidence['exec_sessions']=actual.get('ExecIDs')
        evidence['processes']=run(['podman','--remote=false','top',identity,'hpid','pid','ppid','args'],ok=False,timeout=5).stdout.decode(errors='replace')[:16384]
        evidence['backend_processes']={}
        trace_pids=[]
        for row in evidence['processes'].splitlines()[1:32]:
            if not row.split()[0].isdecimal():continue
            base=Path('/proc')/row.split()[0]
            if not base.is_dir():continue
            evidence['backend_processes'][row.split()[0]]={key:(base/key).read_text()[:2048] for key in ['wchan','syscall','cgroup','attr/current'] if (base/key).is_file()}
            if ('authentication' in row or 'io worker 0' in row or row.split()[1]=='1') and len(trace_pids)<4:
                trace_pids.append(row.split()[0])
                evidence['backend_processes'][row.split()[0]]['fds']={item.name:{'target':str(item.readlink())[:256],'info':(base/'fdinfo'/item.name).read_text()[:256]} for item in sorted((base/'fd').iterdir(),key=lambda path:int(path.name))[:10]}
        traced=run(['timeout','--signal=TERM','--kill-after=1s','4s','strace','-k','-qq','-s','0','-e','trace=epoll_wait,poll,read,write,pread64,preadv,fcntl,kill,tgkill','-e','raw=read,write,pread64,preadv',*[argument for pid in trace_pids for argument in ['-p',pid]]],ok=False,timeout=6)
        evidence['syscalls']={'code':traced.returncode,'trace':traced.stderr.decode(errors='replace')[:12288]}
        native=json.loads(run(['podman','--remote=false','volume','inspect',runtime.installed('pgbox')['resources']['volumes']['postgres-data']['name']]).stdout)[0]
        device=Path(native['Mountpoint']).stat().st_dev
        evidence['volume_device']={'major':__import__('os').major(device),'minor':__import__('os').minor(device)}
        evidence['hba']='\n'.join(line for line in (Path(native['Mountpoint'])/'pg'/'pg_hba.conf').read_text().splitlines() if line and not line.startswith('#'))[:4096]
        for name in ['hosts','resolv.conf']:
            evidence[name]=run(['podman','--remote=false','exec',identity,'cat','/etc/'+name],ok=False,timeout=4).stdout.decode(errors='replace')[:2048]
        pid=actual['State']['Pid'];group=Path('/proc/'+str(pid)+'/cgroup').read_text().strip()
        evidence['cgroup']=group
        if group.startswith('0::/'):
            base=Path('/sys/fs/cgroup')/group[4:]
            evidence['events']={name:(base/name).read_text()[:4096] for name in ['memory.current','memory.events','memory.stat','pids.current','pids.events','cpu.stat'] if (base/name).is_file()}
            evidence['io_ancestors']={}
            while base.is_relative_to(Path('/sys/fs/cgroup')):
                evidence['io_ancestors'][str(base)]={name:(base/name).read_text()[:512] for name in ['io.max','io.stat','io.pressure'] if (base/name).is_file()}
                if base==Path('/sys/fs/cgroup'):break
                base=base.parent
        for name,command in [
            ('activity',['psql','host=/tmp user=fixture dbname=postgres connect_timeout=2','--no-psqlrc','--tuples-only','--no-align','--command',"SELECT pid,usename,application_name,client_addr,state,wait_event_type,wait_event FROM pg_stat_activity"]),
            ('sockets',['sh','-c','cat /proc/net/tcp; cat /proc/net/unix'])]:
            try:
                probe=run(['timeout','--signal=TERM','--kill-after=1s','4s','podman','--remote=false','exec',identity,*command],ok=False,timeout=6)
                evidence[name]={'code':probe.returncode,'stdout':probe.stdout.decode(errors='replace')[:8192],'stderr':probe.stderr.decode(errors='replace')[:1024]}
            except (OSError,ValueError,__import__('subprocess').SubprocessError) as error:evidence[name]={'error':type(error).__name__}
    except (OSError,ValueError,KeyError,__import__('subprocess').SubprocessError) as error:evidence['collector_error']=type(error).__name__
    for optional in ['sockets','hosts','resolv.conf']:
        if len(registry.canonical(evidence))>60000:
            evidence.pop(optional,None);evidence['truncated']=True
    write(ROOT/'postgres-diagnostic.json',evidence)


def initial_connections(stop):
    """Observe one initial Unix login and two finite TCP handshakes."""
    evidence={};deadline=time.monotonic()+120
    try:
        while not stop.is_set() and time.monotonic()<deadline:
            try:
                current=runtime.installed('pgbox')['resources']['containers']['postgres']
                actual=runtime.container(current)
                if actual['State']['Running']:
                    identity=actual['Id']
                    socket=run(['podman','--remote=false','exec',identity,'sh','-c','test -S /tmp/.s.PGSQL.5432'],ok=False,timeout=4)
                    if socket.returncode==0:break
            except (OSError,ValueError,KeyError,__import__('subprocess').SubprocessError):pass
            stop.wait(.2)
        else:return
        sql="SELECT json_build_object('settings',(SELECT json_object_agg(name,setting) FROM pg_settings WHERE name IN ('ssl','ssl_library','authentication_timeout','log_hostname','log_connections','listen_addresses','shared_preload_libraries','session_preload_libraries','local_preload_libraries')),'hba',(SELECT json_agg(json_build_object('number',rule_number,'type',type,'database',database,'user',user_name,'address',address,'method',auth_method,'error',error)) FROM pg_hba_file_rules))"
        for name,command in [
            ('unix',['psql','host=/tmp user=fixture dbname=postgres connect_timeout=2','--no-psqlrc','--tuples-only','--no-align','--command',sql]),
            ('tcp_default',['pg_isready','-h','127.0.0.1','-U','fixture','-d','postgres','-t','2']),
            ('tcp_without_negotiation',['psql','host=127.0.0.1 user=fixture dbname=postgres connect_timeout=2 sslmode=disable gssencmode=disable','--no-psqlrc','--tuples-only','--no-align','--command','SELECT 1'])]:
            began=time.monotonic()
            result=run(['timeout','--signal=TERM','--kill-after=1s','4s','podman','--remote=false','exec',identity,*command],ok=False,timeout=6)
            evidence[name]={'code':result.returncode,'seconds':time.monotonic()-began,'stdout':result.stdout.decode(errors='replace')[:8192],'stderr':result.stderr.decode(errors='replace')[:2048]}
            write(ROOT/'postgres-initial.json',evidence)
    except (OSError,ValueError,__import__('subprocess').SubprocessError) as error:
        evidence['collector_error']=type(error).__name__;write(ROOT/'postgres-initial.json',evidence)


def prepare(report):
    with Path('/etc/hosts').open('a') as output:output.write('127.0.0.1 pgbox.localhost\n')
    artifact,user=postgres_artifact();password=secrets.token_hex(24)
    alias=Path('/etc/komizo/pgbox-owner.env');write(alias,('PGUSER=fixture\nPGPASSWORD='+password+'\n').encode())
    policy=runtime.host_policy('pgbox');policy['limits']=runtime.limits(192,700,128);policy['max_image_bytes']=768*MiB
    policy['secrets']={'postgres-owner':{'path':str(alias),'services':['postgres'],'jobs':['initialize'],
        'environment_file':True,'mount':False,'generation':'a'*32}}
    write('/etc/komizo/apps/pgbox.json',policy)
    identity=source()
    release=runtime.release('pgbox',identity['revision'],dynamic=True,graph=False,source=identity)
    release['providers']=json.loads((ROOT/'profile.json').read_text())['providers']
    release['artifacts']['postgres']=artifact
    workload=release['workload'];workload['volumes']={'postgres-data':{}}
    workload['services']['postgres']={'artifact':'postgres','user':user,'limits':runtime.limits(128,300,64),
        'networks':['app'],'environment_files':['postgres-owner'],'environment':{'PGDATA':'/data/pg'},
        'volumes':[{'name':'postgres-data','target':'/data'}],
        'tmpfs':{'/tmp':{'size_bytes':16*MiB,'mode':0o1777}},
        'command':['sh','-ec','if [ ! -e "$PGDATA/PG_VERSION" ]; then printf %s "$PGPASSWORD" > /tmp/owner-password; initdb -D "$PGDATA" -U "$PGUSER" --pwfile=/tmp/owner-password --auth-local=trust --auth-host=scram-sha-256; rm /tmp/owner-password; printf "host all all 0.0.0.0/0 scram-sha-256\\n" >> "$PGDATA/pg_hba.conf"; fi; exec postgres -D "$PGDATA" -h 0.0.0.0 "$@"',
            'postgres','-c','unix_socket_directories=/tmp,@/komizo-capture','-c','shared_buffers=8MB','-c','max_connections=8','-c','max_locks_per_transaction=16'],
        'health':{'command':['pg_isready','-h','127.0.0.1','-U','fixture','-d','postgres'],'interval_seconds':2,'timeout_seconds':2,'retries':30,'start_period_seconds':30}}
    workload['jobs']={'initialize':{'artifact':'postgres','user':user,'limits':runtime.limits(32,100,32),
        'networks':['app'],'environment_files':['postgres-owner'],'needs':{'postgres':'healthy'},'timeout_seconds':45,
        'command':['psql','-h','postgres','-U','fixture','-d','postgres','--no-psqlrc','--set=ON_ERROR_STOP=1',
            '--command',"CREATE TABLE evidence(value text NOT NULL); INSERT INTO evidence VALUES ('retained native row');"]}}
    workload['services']['api']['needs']={'initialize':'completed'}
    started=time.monotonic()
    stop=threading.Event();observer=threading.Thread(target=initial_connections,args=(stop,),daemon=True);observer.start()
    try:_,receipt=runtime.deploy(release,seconds=120)
    finally:stop.set();observer.join(timeout=20)
    write(ROOT/'timings.json',{'deployment_seconds':time.monotonic()-started})
    if not receipt.get('ok') or query('SELECT value FROM evidence')!=b'retained native row':
        diagnostic()
        raise ValueError('real PostgreSQL native DAG did not retain its initialized row: '+json.dumps(receipt))
    runtime.fetch('pgbox',receipt['release_digest'])
    role=query("SELECT rolpassword FROM pg_authid WHERE rolname='fixture'")
    old_record=runtime.installed('pgbox');before=runtime.container(old_record['resources']['containers']['postgres'])['Id']
    new_password=secrets.token_hex(24)
    update={'reference':'postgres-owner','expected_generation':'a'*32,'format':'environment-file',
        'value':'PGUSER=fixture\nPGPASSWORD='+new_password+'\n'}
    rotated=runtime.submit(runtime.request('pgbox','secret-set',receipt['release_digest'],secret_updates=[update]))
    if not rotated.get('ok') or query("SELECT rolpassword FROM pg_authid WHERE rolname='fixture'")!=role or query('SELECT count(*) FROM evidence')!=b'1':
        raise ValueError('host alias provisioning changed initialized PostgreSQL credentials or rows')
    if runtime.container(old_record['resources']['containers']['postgres'])['Id']!=before:
        raise ValueError('owner alias rotation silently restarted PostgreSQL')
    import fixture_backup
    fixture_backup.capture_postgres(report)
    report['postgres']={'release_digest':receipt['release_digest'],'base_reference':BASE,'image':artifact['config_digest']}
    report['checks'].update({'real_postgresql_api_dag':'passed','immutable_postgresql_base':'passed',
        'postgresql_rows_preserved_by_secret_rotation':'passed','initialized_postgresql_credentials_unchanged':'passed'})


def stop():
    stopped=runtime.submit(runtime.request('pgbox','stop',runtime.installed('pgbox')['release_digest']))
    if stopped.get('phase')!='prepared_stopped':raise ValueError('real PostgreSQL stop intent was not preserved')


def restore_dump():
    dump=ROOT/'owner-postgres.dump'
    if not dump.is_file() or dump.is_symlink() or dump.stat().st_size>1<<20 or not dump.read_bytes().startswith(b'PGDMP'):
        raise ValueError('owner PostgreSQL restoration lacks its bounded authenticated custom dump')
    report=json.loads((ROOT/'report.json').read_text());identity=report['postgres']['release_digest']
    release=json.loads(Path('/var/lib/komizo/releases/'+identity[7:]+'.json').read_text())
    image=release['artifacts']['postgres']['config_digest'];user=release['workload']['services']['postgres']['user']
    if image!=report['postgres']['image']:raise ValueError('owner restoration selected another installed image')
    uid,gid=map(int,user.split(':'));dump.chmod(0o400);__import__('os').chown(dump,uid,gid)
    token=secrets.token_hex(16);name='native-owner-restore-'+token
    script='''initdb -D /recovery/data -U fixture --auth=trust >/dev/null
pg_ctl -D /recovery/data -l /tmp/server.log -o "-h '' -k /tmp -c shared_buffers=8MB -c max_connections=8" -w start >/dev/null
trap 'pg_ctl -D /recovery/data -m immediate -w stop >/dev/null || true' EXIT
pg_restore -h /tmp -U fixture -d postgres --no-owner --no-privileges --exit-on-error /restore.dump
psql -h /tmp -U fixture -d postgres --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 --command 'SELECT value FROM evidence; SELECT count(*) FROM evidence;'
'''
    try:
        restored=run(['timeout','--signal=TERM','--kill-after=5s','90s','podman','--remote=false','run','--name',name,
            '--label','io.komizo.fixture='+token,'--pull=never','--network=none','--read-only','--read-only-tmpfs=false',
            '--cap-drop=all','--security-opt=no-new-privileges','--image-volume=ignore','--user',user,
            '--memory=128m','--memory-swap=128m','--pids-limit=64','--cpu-period=1000000','--cpu-quota=200000','--http-proxy=false',
            '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777','--tmpfs','/recovery:rw,nosuid,nodev,noexec,size=64m,mode=1777',
            '--mount','type=bind,source='+str(dump)+',destination=/restore.dump,ro','--entrypoint=/bin/sh',image,'-ec',script],timeout=100)
        actual=json.loads(run(['podman','--remote=false','container','inspect',name]).stdout)[0]
        host=actual['HostConfig']
        if (restored.stdout.strip()!=b'retained native row\n1' or actual['State']['ExitCode']!=0
                or host['NetworkMode']!='none' or host['Memory']!=128*MiB or host['MemorySwap']!=128*MiB
                or host['PidsLimit']!=64 or host['CpuPeriod']!=1000000 or host['CpuQuota']!=200000
                or host.get('PortBindings') or not host['ReadonlyRootfs'] or actual['Config']['User']!=user
                or 'sha256:'+actual['Image'].removeprefix('sha256:')!=image):
            raise ValueError('owner PostgreSQL restore lost its rows, image or disposable isolation bounds')
        print(json.dumps({'kind':'komizo.native-database-recovery','version':1,'scope':'disposable owner PostgreSQL restoration',
            'current_source_ci_acceptance':False,'release_digest':identity,'image_config_digest':image,'rows':'passed',
            'network':'none','published_ports':[],'memory_bytes':128*MiB,'pids':64},sort_keys=True))
    finally:
        observed=run(['podman','--remote=false','container','inspect',name],ok=False)
        if observed.returncode==0:
            value=json.loads(observed.stdout)[0]
            if value['Config']['Labels'].get('io.komizo.fixture')!=token:raise ValueError('owner recovery cleanup encountered foreign container identity')
            run(['podman','--remote=false','rm','--force',name])
        dump.unlink(missing_ok=True)


def verify_reboot(report):
    installed=runtime.installed('pgbox');expected=report['postgres']['release_digest']
    if installed['desired_running'] or installed['release_digest']!=expected:raise ValueError('PostgreSQL stop intent changed at boot')
    for value in installed['resources']['containers'].values():
        observed=run(['podman','--remote=false','container','inspect',value['name']],ok=False)
        if observed.returncode==0 and json.loads(observed.stdout)[0]['State']['Running']:raise ValueError('stopped PostgreSQL ran at boot')
    # Release this synthetic app's reservation before starting the independent
    # PostgreSQL fixture. This test does not assert a small production host fit.
    secret=runtime.installed('secretbox')
    if not runtime.submit(runtime.request('secretbox','stop',secret['release_digest'])).get('ok'):
        raise ValueError('could not release the synthetic secret fixture reservation')
    started=runtime.submit(runtime.request('pgbox','start',expected))
    if not started.get('ok') or query('SELECT value FROM evidence')!=b'retained native row' or query('SELECT count(*) FROM evidence')!=b'1':
        raise ValueError('offline owner restart lost PostgreSQL data or replayed initialization')
    runtime.fetch('pgbox',expected)
    stopped=runtime.submit(runtime.request('pgbox','stop',expected))
    if stopped.get('phase')!='prepared_stopped':raise ValueError('PostgreSQL owner restart did not restore deliberate stop')
    report['checks'].update({'postgresql_offline_reboot_stop_intent':'passed','postgresql_offline_owner_restart':'passed',
        'postgresql_initialization_not_replayed':'passed','postgresql_retained_rows_after_reboot':'passed'})


if __name__=='__main__':
    import sys
    if sys.argv[1:]!=['restore']:raise SystemExit('expected explicit disposable owner restore')
    restore_dump()
