"""Reviewed Alpine package maintenance. Root remains the trusted operator."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import sys
import stat

REQUIRED=('nftables','nftables-openrc','docker','openssh','linux-lts')
CHANGE=re.compile(r'^\(\s*\d+/\d+\) (Upgrading|Installing|Downgrading) ([a-zA-Z0-9+_.-]+) \(([^)]*)\)$')

def checksum(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
    return h.hexdigest()

def changes(output):
    rows=[]
    for line in output.splitlines():
        if 'Purging ' in line:raise ValueError('package removal refused')
        match=CHANGE.match(line)
        if not match:continue
        operation,name,version=match.groups()
        if operation=='Downgrading':raise ValueError('package downgrade refused')
        target=version.split(' -> ')[-1]
        if not re.fullmatch('[a-zA-Z0-9+_.-]+',target):raise ValueError('invalid target version')
        rows.append({'name':name,'version':target,'operation':operation.lower()})
    if len(rows)>256 or len({r['name'] for r in rows})!=len(rows):raise ValueError('invalid package transaction')
    return rows

def held_world(world):
    lines=world.splitlines();names={re.split('[=<>~@]',l)[0] for l in lines}
    return '\n'.join(lines+[p for p in REQUIRED if p not in names])+'\n'

class Maintenance:
    def __init__(self,platform):self.p=platform
    def run(self,args,timeout=120):
        return self.p.run(args,timeout=timeout)[1]
    def inventory(self):
        installed=self.p.path('/lib/apk/db/installed')
        return {'installed_sha256':checksum(installed),'world_sha256':checksum(self.p.path('/etc/apk/world')),
                'repositories_sha256':checksum(self.p.path('/etc/apk/repositories')),
                'boot_id':self.boot_id(),
                'running_kernel':self.run(['busybox','uname','-r']).strip()}
    def boot_id(self):
        value=self.p.path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if not re.fullmatch('[a-f0-9-]{36}',value):raise ValueError('invalid boot identity')
        return value
    def serving(self):
        files={}
        paths=[self.p.path('/etc/komizo/resources.json'),self.p.path('/etc/komizo/agent.json'),self.p.path('/etc/ssh/sshd_config')]
        for pattern in ('/var/lib/komizo/apps/*.env','/var/lib/komizo/apps/*.stopped','/etc/komizo/workloads/*.json','/srv/*/compose.yml','/srv/*/.env','/etc/nftables.d/*.nft'):
            paths.extend(self.p.path(str(Path(pattern).parent)).glob(Path(pattern).name))
        if len(paths)>512:raise ValueError('serving inventory exceeds its bound')
        for path in paths:
            if path.exists():files[str(path)]=self.p.digest(path)
        ids=self.run(['docker','ps','-aq']).split()
        rows=json.loads(self.run(['docker','inspect',*ids])) if ids else []
        containers={}
        for row in rows:
            if row['State']['Status'] in ('removing','restarting','paused'):raise ValueError('unstable container state')
            name=row['Name'];containers[name]={'image':row['Image'],'running':row['State']['Running'],
                'config_sha256':hashlib.sha256(json.dumps(row['Config'],sort_keys=True).encode()).hexdigest(),
                'mounts':sorted(row['Mounts'],key=lambda m:m['Destination']),
                'ports':row['HostConfig']['PortBindings'],'cgroup_parent':row['HostConfig']['CgroupParent']}
        services={s:self.p.run(['rc-service',s,'status'],required=False)[0]==0 for s in ('komizo-rootd','komizo-api','komizo-agent','docker','sshd','nftables')}
        return {'files':files,'containers':containers,'services':services}
    def stage(self,path):
        stage=Path(path)
        if not stage.is_absolute() or stage.parent!=self.p.path('/var/lib/komizo/maintenance') or not re.fullmatch('[a-zA-Z0-9_-]{1,64}',stage.name):raise ValueError('fixed protected maintenance stage required')
        self.p.protected(stage,private=True,directory=True)
        return stage
    def clone(self,stage):
        root=stage/'solver';root.mkdir(mode=0o700)
        for d in ['etc/apk/keys','lib/apk/db','var/cache/apk']:(root/d).mkdir(parents=True,exist_ok=True)
        for name in ['installed','scripts.tar','triggers']:
            src=self.p.path('/lib/apk/db')/name
            if src.exists():self.p.protected(src);shutil.copyfile(src,root/'lib/apk/db'/name)
        for name in ['repositories','world']:shutil.copyfile(self.p.path('/etc/apk')/name,root/'etc/apk'/name)
        for key in self.p.path('/etc/apk/keys').glob('*'):
            self.p.protected(key);shutil.copyfile(key,root/'etc/apk/keys'/key.name)
        architecture=self.run(['busybox','uname','-m']).strip()
        if architecture not in ('x86_64','aarch64'):raise ValueError('unsupported maintenance architecture')
        (root/'etc/apk/arch').write_text(architecture+'\n')
        (root/'etc/apk/world').write_text(held_world((root/'etc/apk/world').read_text()))
        return root
    def plan(self,path):
        stage=self.stage(path)
        with self.p.locks():
            if self.p.path('/var/lib/komizo/upgrades/pending.json').exists():raise ValueError('existing recovery fence')
            space=os.statvfs(self.p.path('/'))
            if space.f_bavail*space.f_frsize<1<<30 or space.f_favail<4096:raise ValueError('insufficient ordinary maintenance staging space')
            before=self.inventory();serving=self.serving();solver=self.clone(stage)
            self.run(['apk','--root',str(solver),'--cache-dir',str(solver/'var/cache/apk'),'--timeout','30','update'],120)
            output=self.run(['apk','--root',str(solver),'--no-scripts','--no-commit-hooks','--no-logfile','--no-progress','--cache-dir',str(solver/'var/cache/apk'),'--timeout','30','upgrade','--simulate','--no-preupgrade'],120)
            packages=changes(output);cache=stage/'packages';cache.mkdir(mode=0o700)
            if packages:
                self.run(['apk','--root',str(solver),'--keys-dir',str(solver/'etc/apk/keys'),'--cache-dir',str(solver/'var/cache/apk'),'--timeout','30','fetch','--recursive','--world','--output',str(cache),*[r['name']+'='+r['version'] for r in packages]],600)
            files=[]
            for row in packages:
                file=cache/(row['name']+'-'+row['version']+'.apk')
                if file.stat().st_size>512<<20:raise ValueError('package too large')
                self.run(['apk','verify',str(file)],60)
                files.append({**row,'file':file.name,'bytes':file.stat().st_size,'sha256':checksum(file)})
            old=stage/'previous-world';shutil.copyfile(self.p.path('/etc/apk/world'),old);old.chmod(0o600)
            candidate=stage/'candidate-world';candidate.write_text((solver/'etc/apk/world').read_text());candidate.chmod(0o600)
            manifest={'version':1,'kind':'host-maintenance','before':before,'serving':serving,'required_packages':list(REQUIRED),'files':files,'candidate_world_sha256':checksum(candidate),'reboot_required':any(r['name']=='linux-lts' for r in packages),'expires_at_unix':time.time()+7200}
            self.p.journal(stage,{'phase':'planned','manifest':manifest})
            target=stage/'manifest.json';target.write_text(json.dumps(manifest,sort_keys=True)+'\n');target.chmod(0o600);self.p.sync(stage)
            return {'manifest_sha256':checksum(target),'packages':len(files),'reboot_required':manifest['reboot_required'],'removals':0,'required_packages':list(REQUIRED)}
    def manifest(self,stage,expected):
        file=stage/'manifest.json';body=self.p.read(file,private=True)
        if hashlib.sha256(body).hexdigest()!=expected:raise ValueError('maintenance manifest changed')
        value=json.loads(body)
        required={'version','kind','before','serving','required_packages','files','candidate_world_sha256','reboot_required','expires_at_unix'}
        if set(value)!=required or value['kind']!='host-maintenance' or value['version']!=1 or value['required_packages']!=list(REQUIRED):raise ValueError('unsupported maintenance plan')
        if not isinstance(value['files'],list) or len(value['files'])>256:raise ValueError('invalid package inventory')
        names=set()
        for row in value['files']:
            if set(row)!={'name','version','operation','file','bytes','sha256'} or row['operation'] not in ('installing','upgrading'):raise ValueError('invalid package operation')
            if any(not isinstance(row[k],str) or not re.fullmatch('[a-zA-Z0-9+_.-]+',row[k]) for k in ('name','version')) or row['file']!=row['name']+'-'+row['version']+'.apk' or not re.fullmatch('[a-f0-9]{64}',row['sha256']):raise ValueError('invalid package identity')
            if type(row['bytes']) is not int or not 1<=row['bytes']<=512<<20 or row['name'] in names:raise ValueError('invalid package size or duplicate')
            names.add(row['name'])
        if not re.fullmatch('[a-f0-9]{64}',value['candidate_world_sha256']) or type(value['reboot_required']) is not bool or value['reboot_required']!=('linux-lts' in names):raise ValueError('invalid maintenance boundary')
        return value
    def apply(self,path,expected):
        stage=self.stage(path);manifest=self.manifest(stage,expected)
        with self.p.locks():
            if self.inventory()!=manifest['before'] or self.serving()!=manifest['serving'] or time.time()>manifest['expires_at_unix']:raise ValueError('maintenance plan is stale')
            fence=self.p.path('/var/lib/komizo/upgrades/pending.json')
            if fence.exists():raise ValueError('maintenance requires inspection before replay')
            for row in manifest['files']:
                file=stage/'packages'/row['file'];info=self.p.protected(file)
                if info.st_size!=row['bytes'] or checksum(file)!=row['sha256']:raise ValueError('package bytes changed')
                self.run(['apk','verify',str(stage/'packages'/row['file'])],60)
            candidate=stage/'candidate-world'
            if self.p.digest(candidate)!=manifest['candidate_world_sha256']:raise ValueError('world changed')
            space=os.statvfs(self.p.path('/'))
            if space.f_bavail*space.f_frsize < max(256<<20,3*sum(r['bytes'] for r in manifest['files'])) or space.f_favail<4096:raise ValueError('insufficient ordinary package transaction space')
            self.p.journal(stage,{'phase':'applying','manifest_sha256':expected,'before':manifest['before']})
            fence.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with fence.open('x') as f:os.fchmod(f.fileno(),0o600);json.dump({'kind':'host-maintenance','stage':str(stage),'manifest_sha256':expected},f);f.flush();os.fsync(f.fileno())
            self.p.sync(fence.parent)
            self.p.atomic(self.p.path('/etc/apk/world'),candidate,0o644)
            if manifest['files']:
                self.run(['apk','--no-network','--timeout','30','add',*[str(stage/'packages'/r['file']) for r in manifest['files']]],900)
                # Local package filenames temporarily add exact world pins.
                # Restore the reviewed caller world with explicit firewall intent.
                self.p.atomic(self.p.path('/etc/apk/world'),candidate,0o644)
            for package in REQUIRED:self.run(['apk','info','--exists',package],10)
            self.run(['nft','list','ruleset'],10)
            self.verify_packages(manifest)
            after=self.inventory();self.p.journal(stage,{'phase':'reboot_required' if manifest['reboot_required'] else 'packages_installed','manifest_sha256':expected,'before':manifest['before'],'after':after})
            return {'phase':'reboot_required' if manifest['reboot_required'] else 'packages_installed','packages':len(manifest['files']),'manifest_sha256':expected,'fence_retained':True}
    def inspect(self,path,expected):
        stage=self.stage(path);manifest=self.manifest(stage,expected)
        op=json.loads(self.p.read(stage/'operation.json',private=True))
        return {'phase':op['phase'],'manifest_sha256':expected,'current':self.inventory(),'before':manifest['before'],'requires_reconciliation':op['phase']=='applying','fence_retained':self.p.path('/var/lib/komizo/upgrades/pending.json').exists()}
    def verify_packages(self,manifest):
        for row in manifest['files']:
            if self.run(['apk','info','--exists',row['name']+'='+row['version']],10).strip() not in ('',row['name']):raise ValueError('installed package identity differs')
        if self.p.digest(self.p.path('/etc/apk/world'))!=manifest['candidate_world_sha256']:raise ValueError('reviewed world differs')
    def finish(self,path,expected):
        stage=self.stage(path);manifest=self.manifest(stage,expected)
        with self.p.locks():
            fence=self.p.path('/var/lib/komizo/upgrades/pending.json')
            record=json.loads(self.p.read(fence,private=True))
            if record!={'kind':'host-maintenance','stage':str(stage),'manifest_sha256':expected}:raise ValueError('different maintenance fence')
            self.verify_packages(manifest)
            if manifest['reboot_required']:
                if self.boot_id()==manifest['before']['boot_id']:raise ValueError('real reboot still required')
                kernel=next(r['version'].split('-r')[0]+'-0-lts' for r in manifest['files'] if r['name']=='linux-lts')
                if self.run(['busybox','uname','-r']).strip()!=kernel:raise ValueError('running kernel differs from reviewed package')
            if self.serving()!=manifest['serving']:raise ValueError('serving configuration, stop intent or resources differ')
            report=json.loads(self.run(['komizo-box','report'],30))
            if report.get('inventory',{}).get('status')!='current' or report.get('server',{}).get('state')!='ready':raise ValueError('complete host observation unavailable')
            if any(a.get('runtime_state') in ('down','degraded','unknown') for a in report.get('apps',[])):raise ValueError('required application services unavailable')
            self.run(['nft','list','ruleset'],10)
            self.p.journal(stage,{'phase':'accepted','manifest_sha256':expected,'before':manifest['before'],'after':self.inventory(),'serving_identity_preserved':True})
            fence.unlink();self.p.sync(fence.parent)
            return {'phase':'accepted','manifest_sha256':expected,'serving_identity_preserved':True,'fence_retained':False}

def main():
    if os.geteuid()!=0 or len(sys.argv) not in (3,4) or sys.argv[1] not in ('plan','apply','inspect','finish'):raise ValueError('maintenance requires root, fixed operation and protected stage')
    m=Maintenance(Platform())
    if sys.argv[1]=='plan':
        if len(sys.argv)!=3:raise ValueError('plan accepts stage only')
        result=m.plan(sys.argv[2])
    else:
        if len(sys.argv)!=4 or not re.fullmatch('[a-f0-9]{64}',sys.argv[3]):raise ValueError('exact reviewed manifest required')
        result=getattr(m,sys.argv[1])(sys.argv[2],sys.argv[3])
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('maintenance refused: '+str(error),file=sys.stderr);raise SystemExit(1)
