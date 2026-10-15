#!/usr/bin/env python3
"""Run public Komizo lifecycle commands on a disposable Alpine Docker host.

Root bootstraps synthetic local images through release-bootstrap. This does not
authenticate a new GitHub release, test product data or claim an OS/kernel boot.
The privileged guest has private PID/cgroup namespaces and no host mounts/socket.
"""
import argparse
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import ssl
import subprocess
import tarfile
import time
import traceback
import uuid

from onboarding_acceptance import Driver
from performance_acceptance import measure

BASE = 'alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6'
REGISTRY = 'registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
PROXY = 'ghcr.io/nicodes/platform-proxy@sha256:25d6dabfad5ff85e7d2b449f1662a981e785d6d7d51772585e88e19e207c13a3'
REVISION = '1' * 40


def run(args, *, body=None, env=None, timeout=120):
    result = subprocess.run(args, input=body, capture_output=True, env=env, timeout=timeout)
    if result.returncode:
        raise RuntimeError('fixture command refused: '+result.stdout.decode(errors='replace')[-4096:]+result.stderr.decode(errors='replace')[-4096:])
    return result.stdout


class Fixture:
    def __init__(self, cid, output):
        self.cid, self.output = cid, output
        self.steps = []

    def python(self, code, timeout=120):
        prefix = "import os\nfrom pathlib import Path\np=Path('/sys/fs/cgroup/komizo-os/cgroup.procs')\nif p.exists():p.write_text(str(os.getpid()))\n"
        return run(['docker', 'exec', '-i', self.cid, 'python3', '-I', '-'], body=(prefix+code).encode(), timeout=timeout)

    def command(self, args, timeout=120, body=None):
        program = 'import subprocess,sys\nr=subprocess.run('+repr(args)+',input='+repr(body)+',capture_output=True,timeout='+str(timeout-5)+')\nsys.stdout.buffer.write(r.stdout);sys.stderr.buffer.write(r.stderr);raise SystemExit(r.returncode)\n'
        return self.python(program, timeout)

    def write(self, path, body, mode=0o600):
        self.python('p=Path('+repr(path)+');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes('+repr(body)+');p.chmod('+str(mode)+')')

    def record(self, name, data):
        data['fixture_disk']=json.loads(self.python("import json,os\nv=os.statvfs('/var/lib');print(json.dumps({'size_bytes':v.f_blocks*v.f_frsize,'free_bytes':v.f_bfree*v.f_frsize}))"))
        self.steps.append({'step':name, 'accepted':True, 'evidence':data})
        (self.output/'progress.json').write_text(json.dumps(self.steps,indent=2)+'\n')
        print(json.dumps({'step':name,'accepted':True}),flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--release-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='fresh protected absolute directory')
    parser.add_argument('--candidate-cli', type=Path, help='explicit local client test; host matches baseline unless --candidate-host; acceptance is labeled provisional')
    parser.add_argument('--candidate-host', action='store_true', help='explicitly allow a local candidate host too; never counts as signed-release acceptance')
    parser.add_argument('--onboarding-adapter', type=Path, help='optional public-input-only argv planner; no provider secret enters the fixture')
    args = parser.parse_args()
    if args.candidate_host and not args.candidate_cli:
        raise ValueError('candidate host requires an explicit local candidate client')
    if os.geteuid()!=0 or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',args.release) or not re.fullmatch('[a-f0-9]{40}',args.source):
        raise ValueError('root and exact reviewed release/source are required')
    if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT'):
        raise ValueError('fixture requires local default Docker context')
    endpoint=json.loads(run(['docker','context','inspect','--format','{{json .Endpoints.docker.Host}}']))
    if not endpoint.startswith('unix://'):raise ValueError('remote Docker endpoint refused')
    disk=os.statvfs('/var/lib/docker')
    if disk.f_bfree*disk.f_frsize < (4<<30)+(512<<20):
        raise ValueError('fixture needs at least 4.5GiB free on the local Docker filesystem')
    source=Path(__file__).resolve().parents[2]/'scripts/platform_prepare.py'
    spec=importlib.util.spec_from_file_location('public_prepare',source);prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)
    prepare.protected_directory(args.output.parent);prepare.protected_directory(args.release_dir.parent)
    if not args.output.is_absolute() or args.output.exists():raise ValueError('fresh absolute output required')
    args.output.mkdir(mode=0o700)
    prepare.verify(args.release_dir,args.source,args.release)
    cli=args.release_dir/'komizo';verified_box=args.release_dir/'komizo-box-linux-amd64';box=verified_box
    candidate_receipt=None
    if args.candidate_cli:
        candidate=args.candidate_cli
        if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_file():
            raise ValueError('candidate CLI must be an absolute regular local executable')
        exported=args.output/'candidate-host'
        candidate_metadata=json.loads(run([str(candidate),'artifact','--arch','amd64','--output',str(exported)]))
        if (not args.candidate_host and exported.read_bytes()!=box.read_bytes()) or candidate_metadata['version'].removeprefix('v')!=args.release.removeprefix('v'):
            raise ValueError('candidate version or authenticated baseline host binding differs')
        candidate_receipt={'sha256':hashlib.sha256(candidate.read_bytes()).hexdigest(),'host_sha256':hashlib.sha256(exported.read_bytes()).hexdigest(),'candidate_host':args.candidate_host,'authenticated':False,'scope':'explicit local candidate; maintenance target artifacts remain the authenticated baseline; not signed-release acceptance'}
        if args.candidate_host:box=exported
        cli=candidate
    name='komizo-lifecycle-'+uuid.uuid4().hex[:12]
    cid=run(['docker','run','-d','--name',name,'--label','org.komizo.fixture='+name,
             '--privileged','--cgroupns=private','--init','--cpus=1','--memory=1g',
             '--memory-swap=1536m','--pids-limit=1024','--tmpfs','/run','--tmpfs','/tmp',BASE,'sleep','3600']).decode().strip()
    if not re.fullmatch('[a-f0-9]{64}',cid):raise ValueError('invalid fixture ID')
    fixture=Fixture(cid,args.output)
    loop=None
    failure_outputs={}
    try:
        row=json.loads(run(['docker','inspect',cid]))[0];h=row['HostConfig']
        if (row['Id']!=cid or h['Binds'] or any(m['Type']!='tmpfs' for m in row['Mounts']) or h['CgroupnsMode']!='private'
                or h['PidMode'] or h['PortBindings'] or h['Memory']!=1<<30 or h['MemorySwap']!=1536<<20
                or h['NanoCpus']!=1_000_000_000 or h['PidsLimit']!=1024 or not h['Init'] or not h['Privileged']
                or row['Config']['Labels'].get('org.komizo.fixture')!=name):
            raise ValueError('guest isolation differs')
        address=next(iter(row['NetworkSettings']['Networks'].values()))['IPAddress']
        run(['docker','exec',cid,'apk','add','--no-cache','python3','openssh','openrc','ca-certificates','strace'],timeout=180)
        fixture.python("root=Path('/sys/fs/cgroup');assert (root/'memory.max').read_text().strip()==str(1<<30)\nassert Path('/proc/1/cgroup').read_text().strip()=='0::/'\nhost=root/'komizo-os';host.mkdir()\nfor pid in (root/'cgroup.procs').read_text().split():\n try:(host/'cgroup.procs').write_text(pid)\n except ProcessLookupError:pass\n(root/'cgroup.subtree_control').write_text('+cpu +memory +pids +io')\nPath('/run/openrc').mkdir(exist_ok=True);Path('/run/openrc/softlevel').write_text('sysinit')\n")
        keys=args.output/'ssh';keys.mkdir(mode=0o700)
        run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(keys/'key')])
        (keys/'key').chmod(0o600)
        fixture.write('/root/.ssh/authorized_keys',(keys/'key.pub').read_bytes())
        fixture.python("Path('/root/.ssh').chmod(0o700)")
        fixture.command(['ssh-keygen','-A'])
        fixture.write('/etc/ssh/sshd_config',b'PermitRootLogin prohibit-password\nPasswordAuthentication no\n')
        fixture.command(['rc-service','sshd','start'])
        public=fixture.command(['cat','/etc/ssh/ssh_host_ed25519_key.pub']).decode().split()
        (keys/'known_hosts').write_text(address+' '+public[0]+' '+public[1]+'\n')
        wrapper=keys/'ssh'
        wrapper.write_text('#!/bin/sh\nexec /usr/bin/ssh -i '+shlex.quote(str(keys/'key'))+' -o IdentitiesOnly=yes -o UserKnownHostsFile='+shlex.quote(str(keys/'known_hosts'))+' -o GlobalKnownHostsFile=/dev/null "$@"\n');wrapper.chmod(0o700)
        env={**os.environ,'PATH':str(keys)+':'+os.environ['PATH']}
        # A private filesystem lets the synthetic postgres UID allocate space
        # even when the controller's filesystem has reserved blocks. Its sparse
        # backing file and loop device are owned only by this disposable guest.
        # Preallocation reserves its disk budget before any guest services run.
        fixture.command(['apk','add','--no-cache','losetup','e2fsprogs'])
        fixture.python("import stat\nfor index in range(128):\n p=Path('/dev/loop'+str(index))\n if p.exists():\n  info=p.stat();assert stat.S_ISBLK(info.st_mode) and info.st_rdev==os.makedev(7,index)\n else:os.mknod(p,stat.S_IFBLK|0o600,os.makedev(7,index))\n")
        fixture.python("p=Path('/root/komizo-fixture.img');fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)\ntry:os.posix_fallocate(fd,0,4<<30)\nfinally:os.close(fd)")
        loop=fixture.command(['losetup','--find','--show','/root/komizo-fixture.img']).decode().strip()
        if not re.fullmatch('/dev/loop[0-9]+',loop):raise ValueError('invalid owned loop device')
        fixture.command(['mkfs.ext4','-F','-m','0',loop])
        fixture.command(['mount',loop,'/var/lib'])
        fixture.python("Path('/var/lib/docker').mkdir(parents=True,exist_ok=True);Path('/var/lib/fixture-srv').mkdir();Path('/srv').mkdir(exist_ok=True)")
        fixture.command(['mount','--bind','/var/lib/fixture-srv','/srv'])
        fixture.write('/etc/docker/daemon.json',b'{"storage-driver":"overlay2","exec-opts":["native.cgroupdriver=cgroupfs"],"insecure-registries":["172.30.0.0/16"],"default-address-pools":[{"base":"172.30.0.0/16","size":24}]}\n')
        fixture.write('/usr/local/bin/komizo-box',box.read_bytes(),0o755)
        resources={'version':1,'physical_memory_bytes':1<<30,'os_reserve_bytes':128<<20,'physical_milli_cpus':1000,'os_reserve_milli_cpus':100,
                   'production':{'memory_bytes':512<<20,'swap_bytes':512<<20,'milli_cpus':600,'pids':512},
                   'proxy':{'memory_bytes':96<<20,'swap_bytes':64<<20,'milli_cpus':100,'pids':128},
                   'previews':{'memory_bytes':64<<20,'swap_bytes':0,'milli_cpus':100,'pids':128},
                   'preview_database':{'memory_bytes':128<<20,'swap_bytes':0,'milli_cpus':100,'pids':128}}
        fixture.write('/etc/komizo/resources.json',json.dumps(resources).encode())
        fixture.write('/etc/komizo/preview',b'DB_MEM_LIMIT=128m\n')
        # THP controls are host-global even in a privileged private-cgroup guest.
        # Hide this optional interface rather than tuning the controller kernel.
        fixture.python("import subprocess\np=Path('/sys/kernel/mm/transparent_hugepage')\nif p.is_dir():subprocess.check_call(['mount','-t','tmpfs','-o','size=64k,mode=0755,nosuid,nodev,noexec','komizo-fixture-kernel-mask',str(p)])\nassert not (p/'enabled').exists()\n")
        fixture.record('host_global_kernel_controls_masked',{'thp_control_exposed':False,'private_mount_namespace':True})
        driver=Driver(args.onboarding_adapter,args.output,(Path(__file__).resolve().parents[2]/'README.md').read_text(),cli,env,address)
        started=time.monotonic()
        init=driver.command('Prepare this fresh application host using the public CLI.',{},[str(cli),'--json','setup','--host',address],'setup',lambda data:data.get('prepared') is True)
        setup_seconds=driver.last_seconds
        assert json.loads(init)['ok'] and json.loads(init)['data']['prepared']
        (args.output/'init.log').write_bytes(init)
        fixture.record('public_setup',{'release':args.release,'source':args.source,'host_mounted_socket':False,'finite_groups':True})
        # IP clients omit TLS SNI. Give this disposable IP-only installation
        # an explicit certificate selection default; certificate verification
        # still checks the IP SAN and the fixture's trusted public CA.
        fixture.python("p=Path('/srv/_proxy/Caddyfile');body=p.read_text();assert body.count('\\n{\\n')==1;p.write_text(body.replace('\\n{\\n','\\n{\\n default_sni "+address+"\\n',1))")
        # Trust the guest's public CA before the long-lived worker creates its
        # first TLS client. A Go process keeps its initial system root pool.
        temporary_route='/srv/_proxy/routes/fixturebootstrap.caddy'
        fixture.write(temporary_route,(address+' {\n tls internal\n respond "fixture TLS bootstrap"\n}\n').encode(),0o644)
        fixture.command(['docker','exec','komizo-proxy','caddy','reload','--config','/etc/caddy/Caddyfile'])
        deadline=time.monotonic()+45
        while True:
            try:
                raw=fixture.command(['docker','cp','komizo-proxy:/data/caddy/pki/authorities/local/root.crt','-'])
                with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                    members=archive.getmembers()
                    assert len(members)==1 and members[0].isfile() and members[0].name=='root.crt' and members[0].size<16384
                    ca=archive.extractfile(members[0]).read()
                break
            except RuntimeError:
                if time.monotonic()>=deadline:raise
                time.sleep(.2)
        assert ca.startswith(b'-----BEGIN CERTIFICATE-----') and len(ca)<16384
        fixture.write('/usr/local/share/ca-certificates/fixture.crt',ca,0o644)
        fixture.command(['update-ca-certificates'])
        public_roots=Path(ssl.get_default_verify_paths().cafile).read_bytes()
        ca_file=args.output/'fixture-public-roots.pem'
        ca_file.write_bytes(public_roots+b'\n'+ca);ca_file.chmod(0o600)
        env['SSL_CERT_FILE']=str(ca_file)
        fixture.python('Path('+repr(temporary_route)+').unlink()')
        fixture.command(['docker','exec','komizo-proxy','caddy','reload','--config','/etc/caddy/Caddyfile'])
        fixture.command(['rc-service','komizo-rootd','restart'])
        # All paths, images and keys below belong only to this synthetic guest.
        fixture.command(['docker','run','-d','--name','fixture-registry','--memory','64m','--memory-swap','64m','--cpus','.1','--pids-limit','64','--cgroup-parent','/komizo-production','--network','edge','-e','REGISTRY_HTTP_ADDR=0.0.0.0:80',REGISTRY],timeout=180)
        # Use the owned registry's numeric private address. Neither registry
        # nor outer guest publishes ports; no host-file/DNS cache is involved.
        registry_address=fixture.command(['docker','inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}','fixture-registry']).decode().strip()
        if ipaddress.ip_address(registry_address) not in ipaddress.ip_network('172.30.0.0/16'):raise ValueError('registry escaped the declared private guest network')
        prefix=registry_address+'/example/fixturelocal-';config=prefix+'config'
        fixture.python("import time,urllib.request\nend=time.monotonic()+30\nwhile True:\n try:\n  response=urllib.request.urlopen("+repr('http://'+registry_address+'/v2/')+",timeout=1);assert response.status==200;break\n except Exception:\n  if time.monotonic()>=end:raise\n  time.sleep(.2)\n",timeout=40)
        fixture.write('/root/fixture/www/readyz',json.dumps({'revision':REVISION}).encode())
        fixture.write('/root/fixture/www/index.html',b'synthetic Komizo lifecycle fixture\n')
        fixture.write('/root/fixture/Gatefile',('FROM '+BASE+'\nRUN apk add --no-cache python3\nCOPY www /www\nCMD ["python3","-m","http.server","80","--directory","/www"]\n').encode())
        compose={'services':{'fixturelocal-gate':{'image':prefix+'gate:'+REVISION,'networks':['edge']}},'networks':{'edge':{'external':True,'name':'edge'}}}
        fixture.write('/root/fixture/compose.yml',json.dumps(compose).encode())
        fixture.write('/root/fixture/hostnames',(address+'\n').encode())
        fixture.write('/root/fixture/Configfile',b'FROM scratch\nCOPY compose.yml hostnames /config/\n')
        for component,dockerfile in [('gate','Gatefile'),('config','Configfile')]:
            fixture.command(['docker','build','-f','/root/fixture/'+dockerfile,'-t',prefix+component+':'+REVISION,'/root/fixture'],timeout=180)
            fixture.command(['docker','push',prefix+component+':'+REVISION],timeout=180)
        policy='/etc/komizo/workloads/fixturelocal.json'
        definition={'version':1,'app':'fixturelocal','config':config,'policy':{
            'version':1,'app':'fixturelocal','app_dir':'/srv/fixturelocal','image_prefix':prefix,'shared_network':'edge',
            'source_repository':'example/fixture','repository_id':'1',
            'resources':{'cgroup_parent':'/komizo-production','default':{'memory_bytes':32<<20,'memory_swap_bytes':32<<20,'milli_cpus':100},'max_memory_bytes':40<<20,'max_memory_swap_bytes':40<<20,'max_milli_cpus':100,'startup_allowance_bytes':8<<20},
            'readiness':{'probes':[{'url':'https://'+address+'/readyz','revision_field':'revision'}]}}}
        definition_file=args.output/'application.json';definition_file.write_text(json.dumps(definition)+'\n');definition_file.chmod(0o600)
        setup_args=[str(cli),'--json','setup','--host',address,'--definition',str(definition_file),'--key',str(keys/'app-key')]
        registered=json.loads(driver.command('Register the provided app definition and preserve its private key in the supplied file.',{'definition':str(definition_file),'key':str(keys/'app-key')},setup_args,'setup',lambda data:data.get('app_registered') is True));assert registered['ok'] and registered['data']['app_registered'] and not registered['data']['key_unchanged']
        key_hash=hashlib.sha256((keys/'app-key').read_bytes()).hexdigest()
        repeated=json.loads(run(setup_args,env=env,timeout=180));assert repeated['ok'] and repeated['data']['key_unchanged'] and hashlib.sha256((keys/'app-key').read_bytes()).hexdigest()==key_hash
        assert 'PRIVATE KEY' not in json.dumps(registered) and 'PRIVATE KEY' not in json.dumps(repeated)
        fixture.record('public_app_setup_idempotence',{'application_definition':True,'key_preserved':True,'private_key_not_printed':True})
        fixture.command(['komizo-box','workload','validate','--policy',policy,'--app','fixturelocal','--app-dir','/srv/fixturelocal','--version',REVISION,'--compose','/root/fixture/compose.yml','--output','/root/fixture/validated.json'])
        fixture.command(['komizo-box','workload','release-bootstrap','--policy',policy,'--version',REVISION,'--config-image',config+':'+REVISION,'--compose','/root/fixture/compose.yml'])
        fixture.write('/srv/fixturelocal/.env',('APP_VERSION='+REVISION+'\n').encode())
        fixture.write('/srv/fixturelocal/.komizo-image-retention',('CURRENT='+REVISION+'\nPREVIOUS=\n').encode())
        started=time.monotonic()
        deployment=json.loads(driver.command('Deploy the supplied exact source revision of fixturelocal and wait for completion.',{'revision':REVISION},[str(cli),'--json','deploy','--host',address,'--app','fixturelocal','--version',REVISION],'deploy',lambda data:data.get('completed') is True,timeout=180))
        deployment_seconds=driver.last_seconds
        assert deployment['ok'] and deployment['data']['completed']
        operation=deployment['data']['operation_id'];assert re.fullmatch('[a-f0-9]{32}',operation)
        inspection=json.loads(run([str(cli),'--json','operation','inspect','--host',address,'--app','fixturelocal'],env=env))
        assert inspection['ok'] and inspection['data']['inspection']['operation']['operation_id']==operation and not inspection['data']['reconciliation_required']
        fixture.record('public_bootstrapped_activation',{'revision':REVISION,'operation_id':operation,'authority':'operator-bootstrap','new_github_source_authentication_tested':False,'machine_interface':1})
        def identity():
            return json.loads(fixture.python("import hashlib,json\npaths=[Path('/srv/fixturelocal/.env'),Path("+repr(policy)+"),Path('/srv/fixturelocal/.komizo-image-retention')]\nmounts=json.loads(__import__('subprocess').check_output(['docker','inspect','--format','{{json .Mounts}}','komizo-proxy']))\nprint(json.dumps({'files':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},'certificates':sorted(m['Name'] for m in mounts if m['Type']=='volume' and m['Destination'] in ('/data','/config')),'platform_pending':Path('/var/lib/komizo/upgrades/pending.json').exists(),'activation_pending':Path('/var/lib/komizo/activations/pending.json').exists()}))"))
        def probe():
            return json.loads(fixture.python("import json,urllib.request\nr=urllib.request.urlopen('https://"+address+"/readyz',timeout=5);v=json.loads(r.read());assert v['revision']=="+repr(REVISION)+";assert r.status==200;print(json.dumps({'tls_verified':True,'revision':v['revision'],'status':r.status}))"))
        before=identity();assert not before['platform_pending'] and not before['activation_pending'];probe()
        stage=args.output/'self-upgrade'
        plan=json.loads(run([str(cli),'platform','plan','--host',address,'--release',args.release,'--source',args.source,'--release-dir',str(args.release_dir),'--stage',str(stage)],env=env,timeout=180))
        applied=json.loads(run([str(cli),'platform','apply','--host',address,'--release',args.release,'--source',args.source,'--release-dir',str(args.release_dir),'--stage',str(stage),'--resume','--expected-manifest',plan['manifest_sha256']],env=env,timeout=360))
        assert applied['applied'] and not applied['application_restart'] and identity()==before
        fixture.record('public_self_upgrade',{'manifest_sha256':plan['manifest_sha256'],'identity_preserved':True,'probe':probe()})
        probes_file=args.output/'proxy-probes.json'
        probes_file.write_text(json.dumps([{'url':'https://'+address+'/readyz','revision':REVISION}])+'\n');probes_file.chmod(0o600)
        proxy_source='16ea0d8fe96fac0f36221c0e1d51a71b195a7236'
        proxy_stage=args.output/'proxy-upgrade'
        proxy_args=[str(cli),'platform','proxy','plan','--host',address,'--reference',PROXY,'--source',proxy_source,'--stage',str(proxy_stage),'--probes',str(probes_file),'--bind-resources']
        proxy_plan=json.loads(run(proxy_args,env=env,timeout=180))
        proxy_args[3]='apply';proxy_args+=['--expected-manifest',proxy_plan['manifest_sha256']]
        proxy_result=json.loads(run(proxy_args,env=env,timeout=360))
        assert proxy_result['applied'] and identity()==before
        fixture.record('public_proxy_upgrade',{'manifest_sha256':proxy_plan['manifest_sha256'],'identity_preserved':True,'probe':probe()})
        fixture.python("p=Path('/var/lib/komizo/tasks');p.mkdir(mode=0o700,exist_ok=True);assert p.stat().st_uid==0 and p.stat().st_mode&0o777==0o700")
        authority=args.output/'authority-review';authority.mkdir(mode=0o700)
        task_body=b'#!/bin/sh\n# Synthetic operator-owned lifecycle fixture.\nexit 0\n'
        candidates=[('/var/lib/komizo/tasks/fixturelocal.sh','task.sh',task_body,0o700),
                    (policy,'policy.json',fixture.command(['cat',policy]),0o600)]
        for _,filename,body,_ in candidates:
            target=authority/filename;target.write_bytes(body);target.chmod(0o600)
        review=authority/'review.json'
        review.write_text(json.dumps({'version':1,'files':[{'path':path,'source':filename,'mode':mode} for path,filename,_,mode in candidates]})+'\n');review.chmod(0o600)
        authority_stage=args.output/'authority-interruption'
        authority_args=[str(cli),'platform','plan','--host',address,'--release',args.release,'--source',args.source,'--release-dir',str(args.release_dir),'--stage',str(authority_stage),'--authority-review',str(review)]
        authority_plan=json.loads(run(authority_args,env=env,timeout=180));expected=authority_plan['manifest_sha256']
        manifest=json.loads((authority_stage/'manifest.json').read_bytes())
        assert manifest['files'][0]['before'] is None and manifest['files'][0]['path']==candidates[0][0]
        remote='/var/lib/komizo/upgrades/'+authority_stage.name
        # The authenticated executor can finish the replacement/journal window
        # before an external observer is scheduled on a fast CI runner. Hold
        # only this synthetic file's actual rename exit in the guest kernel;
        # do not alter return values, executor bytes, or installed product code.
        interrupted_command=remote+'/box platform apply '+remote+' '+expected
        traced=['/usr/bin/strace','-f','-o','/root/fixture-interruption.trace',
                '-e','trace=rename,renameat,renameat2','-P',candidates[0][0],
                '--inject=rename,renameat,renameat2:delay_exit=20s',
                remote+'/box','platform','apply',remote,expected]
        forced=('#!/bin/sh\nset -eu\nif [ "${SSH_ORIGINAL_COMMAND-}" = '+shlex.quote(interrupted_command)+' ]; then\n exec '+shlex.join(traced)+'\nfi\nexec /bin/sh -c "${SSH_ORIGINAL_COMMAND-}"\n').encode()
        fixture.write('/root/fixture-command',forced,0o700)
        authorized=(keys/'key.pub').read_bytes()
        fixture.write('/root/.ssh/authorized_keys',b'command="/root/fixture-command" '+authorized)
        watcher="""import hashlib,json,os,signal,time
from pathlib import Path
Path('/sys/fs/cgroup/komizo-os/cgroup.procs').write_text(str(os.getpid()))
remote=Path(REMOTE);expected=DIGEST
end=time.monotonic()+90
while time.monotonic()<end:
 if Path('/var/lib/komizo/tasks/fixturelocal.sh').exists():
  pending=json.loads(Path('/var/lib/komizo/upgrades/pending.json').read_bytes());assert pending=={'stage':remote.name,'manifest':expected}
  wanted=[str(remote/'box').encode(),b'platform',b'apply',str(remote).encode(),expected.encode(),b''];leaders=[]
  for proc in Path('/proc').iterdir():
   if not proc.name.isdecimal():continue
   try:cmd=(proc/'cmdline').read_bytes().split(b'\\0')
   except (FileNotFoundError,ProcessLookupError):continue
   if cmd==wanted:leaders.append(int(proc.name))
  assert len(leaders)==1,leaders
  leader=leaders[0];children=[]
  for proc in Path('/proc').iterdir():
   if not proc.name.isdecimal():continue
   try:status=(proc/'status').read_text()
   except (FileNotFoundError,ProcessLookupError):continue
   if ('PPid:\\t'+str(leader)+'\\n') in status:children.append(int(proc.name))
  assert len(children)==1,children
  stopped=[];killed=False
  try:
   for pid in (children[0],leader):os.kill(pid,signal.SIGSTOP);stopped.append(pid)
   assert hashlib.sha256(Path('/proc/'+str(leader)+'/exe').read_bytes()).hexdigest()==BINARY_SHA
   status=Path('/proc/'+str(children[0])+'/status').read_text()
   assert int(next(line.split()[1] for line in status.splitlines() if line.startswith('TracerPid:')))>0
   assert hashlib.sha256(Path('/var/lib/komizo/tasks/fixturelocal.sh').read_bytes()).hexdigest()==TASK_SHA
   record=json.loads((remote/'operation.json').read_bytes());assert record['phase']=='installing'
   assert Path('/var/lib/komizo/tasks/fixturelocal.sh').exists()
   for pid in (children[0],leader):os.kill(pid,signal.SIGKILL)
   killed=True
  finally:
   if not killed:
    for pid in stopped:
     try:os.kill(pid,signal.SIGCONT)
     except ProcessLookupError:pass
  print(json.dumps({'actual_authenticated_executor_interrupted':True,'phase':record['phase'],'manifest_sha256':expected,'previous_absence_observed':True,'path_filtered_rename_exit_delay_seconds':20,'unmodified_executor':True,'fence_retained':Path('/var/lib/komizo/upgrades/pending.json').exists()}),flush=True);break
 time.sleep(.0005)
else:raise ValueError('private-file interruption window not observed')
""".replace('REMOTE',repr(remote)).replace('DIGEST',repr(expected)).replace('BINARY_SHA',repr(hashlib.sha256(verified_box.read_bytes()).hexdigest())).replace('TASK_SHA',repr(hashlib.sha256(task_body).hexdigest()))
        monitor=subprocess.Popen(['docker','exec','-i',cid,'python3','-I','-'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        monitor.stdin.write(watcher.encode());monitor.stdin.close()
        authority_args[2]='apply';authority_args+=['--resume','--expected-manifest',expected]
        try:
            interrupted=subprocess.run(authority_args,env=env,capture_output=True,timeout=180)
            assert interrupted.returncode!=0,'public authority apply completed instead of being interrupted'
            (args.output/'authority-interrupted.log').write_bytes(interrupted.stdout+interrupted.stderr)
            assert monitor.wait(timeout=95)==0,monitor.stderr.read().decode()
            interruption=json.loads(monitor.stdout.read());assert interruption['fence_retained']
        finally:
            if monitor.poll() is None:monitor.terminate();monitor.wait(timeout=10)
            fixture.write('/root/.ssh/authorized_keys',authorized)
            (args.output/'authority-watcher.log').write_bytes(monitor.stdout.read()+monitor.stderr.read())
        inspect_record=json.loads(run([str(cli),'--json','platform','inspect','--host',address,'--stage',remote,'--expected-manifest',expected],env=env))['data']
        assert inspect_record['phase']=='installing'
        fixture.write(candidates[0][0],b'#!/bin/sh\n# Changed synthetic fixture; must refuse recovery.\nexit 0\n',0o700)
        try:
            fixture.command(['komizo-box','platform','recover',remote,expected])
        except RuntimeError as error:
            assert 'changed installed' in str(error)
        else:raise AssertionError('foreign-writer recovery was accepted')
        fixture.write(candidates[0][0],task_body,0o700)
        recovered=json.loads(driver.command('Inspect the interrupted platform operation, then restore its recorded prior configuration. The operator authorizes this exact stage and manifest only.',{'stage':remote,'manifest':expected},[str(cli),'--json','platform','recover','--host',address,'--stage',remote,'--expected-manifest',expected],'platform recover',lambda data:data.get('phase')=='recovered'))['data'];assert recovered['phase']=='recovered'
        assert fixture.python("print(Path('/var/lib/komizo/tasks/fixturelocal.sh').exists())").strip()==b'False'
        assert identity()==before
        replay=fixture.python("import subprocess,json\nr=subprocess.run(['komizo-box','platform','apply',"+repr(remote)+","+repr(expected)+"],capture_output=True);print(json.dumps({'returncode':r.returncode,'error':r.stderr.decode()}))")
        replay=json.loads(replay);assert replay['returncode']!=0 and 'already exists' in replay['error']
        fixture.record('public_authority_interruption_recovery',{'interruption':interruption,'foreign_writer_refused':True,'prior_absence_and_policy_restored':True,'replay_refused':True,'identity_preserved':True,'probe':probe()})
        fixture.command(['docker','stop','fixture-registry'])
        submission=fixture.command(['komizo-box','workload','deployment-submit','--policy',policy,'--version',REVISION,'--local-only'],body=b'')
        operation=submission.decode().strip().splitlines()[-1];assert re.fullmatch('[a-f0-9]{32}',operation)
        fixture.command(['komizo-box','workload','activation-wait','--id',operation],timeout=180)
        assert identity()==before
        fixture.record('cached_current_registry_stopped',{'operation_id':operation,'identity_preserved':True,'probe':probe()})
        fixture.command(['komizo-box','app','stop','--app','fixturelocal'])
        fixture.command(['rc-service','komizo-rootd','restart'])
        report=json.loads(fixture.command(['komizo-box','report']));app=next(x for x in report['apps'] if x['name']=='fixturelocal')
        assert app['stopped'] and all(c['state']!='running' for c in app['containers'])
        fixture.command(['komizo-box','app','start','--app','fixturelocal'])
        assert identity()==before
        fixture.record('stop_intent_and_service_restart',{'deliberate_stop_preserved':True,'probe':probe(),'os_boot_tested':False})
        driver.save(True)
        performance=measure(fixture,cli,env,address,probe,setup_seconds,deployment_seconds)
        assert identity()==before
        fixture.record('fixed_budget_performance',{'accepted':performance['accepted'],'budget_sha256':performance['budget_sha256']})
        driver.save(True)
        fixture.record('public_onboarding',{'mode':'unfamiliar_agent' if args.onboarding_adapter else 'deterministic_public_cli','human_interventions':0})
        result={'version':1,'release':args.release,'source':args.source,'candidate_cli':candidate_receipt,'cli_sha256':hashlib.sha256(cli.read_bytes()).hexdigest(),'host_sha256':hashlib.sha256(box.read_bytes()).hexdigest(),'steps':fixture.steps,'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'scope':'public machine CLI setup, application definition and key idempotence, direct deployment and operation inspection, Root local bootstrap, activation, same-release self/proxy upgrade, actual authority executor interruption/foreign-writer refusal/recovery/replay, cached reconfiguration and stop intent across service restart; no new CI-source admission or OS boot claim',
                'private_cgroup_namespace':True,'host_global_kernel_controls_masked':True,'host_mounts':False,'host_docker_socket':False,'provider_calls':False,'real_data_accessed':False,'performance_accepted':performance['accepted'],'onboarding_mode':'unfamiliar_agent' if args.onboarding_adapter else 'deterministic_public_cli'}
        (args.output/'accepted.json').write_text(json.dumps(result,indent=2)+'\n')
    except Exception:
        failure_outputs['original-failure.txt']=traceback.format_exc().encode()[-16384:]
        try:
            failure_outputs['bootstrap-policy-diagnostics.json']=fixture.python("import json\np=Path('/etc/komizo/workloads/fixturelocal.json');d=Path('/srv/fixturelocal');print(json.dumps({'policy':json.loads(p.read_bytes()) if p.exists() else None,'compose_exists':(d/'compose.yml').exists(),'retention_exists':(d/'.komizo-image-retention').exists(),'operation_exists':Path('/var/lib/komizo/releases/fixturelocal/operation.json').exists()}))")
        except Exception:
            pass
        try:
            diagnostics=fixture.python("import json,subprocess\nids=subprocess.check_output(['docker','ps','-aq'],timeout=10).decode().split();rows=json.loads(subprocess.check_output(['docker','inspect',*ids],timeout=10)) if ids else [];print(json.dumps({'containers':[{'name':r['Name'],'state':{k:r['State'].get(k) for k in ('Running','OOMKilled','ExitCode','Error')}} for r in rows],'memory_events':{str(p):p.read_text() for p in Path('/sys/fs/cgroup').rglob('memory.events') if len(p.parts)<=6}}))\nr=subprocess.run(['docker','logs','--tail','40','komizo-previews'],capture_output=True,timeout=10);print((r.stdout+r.stderr).decode(errors='replace')[-8192:])",timeout=30)
            failure_outputs['failure-diagnostics.log']=diagnostics
            for component in ('komizo-proxy','fixturelocal-fixturelocal-gate-1'):
                r=fixture.python("import subprocess\nr=subprocess.run(['docker','logs','--tail','35',"+repr(component)+"],capture_output=True,timeout=10);print((r.stdout+r.stderr).decode(errors='replace')[-16384:])",timeout=30)
                failure_outputs[component+'-diagnostics.log']=r
            config=fixture.command(['cat','/srv/_proxy/Caddyfile'])
            failure_outputs['proxy-configuration.log']=config
            network=fixture.python("import json,subprocess,urllib.request,os\nprint(json.dumps({'proxy_environment_present':{k:bool(os.environ.get(k)) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')}}))\nfor p in Path('/srv/_proxy/routes').glob('*.caddy'):print(str(p)+'\\n'+p.read_text())\nfor url in ('https://"+address+"/readyz',):\n try:\n  response=urllib.request.urlopen(url,timeout=10);print(json.dumps({'url':url,'status':response.status,'revision':response.headers.get('X-Komizo-Revision'),'body':response.read(512).decode()}))\n except Exception as error:print(json.dumps({'url':url,'error':str(error)}))\nfor name in ('komizo-proxy','fixturelocal-fixturelocal-gate-1'):\n rows=json.loads(subprocess.check_output(['docker','inspect',name]));print(json.dumps({'name':name,'networks':rows[0]['NetworkSettings']['Networks']}))",timeout=150)
            failure_outputs['readiness-network-diagnostics.log']=network
        except Exception as error:
            failure_outputs['diagnostic-refusal.txt']=(str(error)[-4096:]+'\n').encode()
        raise
    finally:
        row=json.loads(run(['docker','inspect',cid]))[0]
        if row['Id']!=cid or row['Config']['Labels'].get('org.komizo.fixture')!=name:raise ValueError('foreign fixture cleanup refused')
        if loop is not None:
            associated=fixture.command(['losetup','--associated','/root/komizo-fixture.img','--noheadings','--output','NAME']).decode().split()
            if associated!=[loop]:raise ValueError('foreign loop backing identity; cleanup refused')
            # Detach is deferred by the kernel until the private guest mount
            # disappears; removal below closes its processes and namespace.
            fixture.command(['losetup','--detach',loop])
        run(['docker','rm','-f',cid],timeout=180)
        (args.output/'cleanup.json').write_text(json.dumps({'owned_container_removed':True,'shared_images_removed':False,'cid':cid})+'\n')
        for filename,body in failure_outputs.items():
            target=args.output/filename;target.write_bytes(body);target.chmod(0o600)


if __name__=='__main__':
    main()
