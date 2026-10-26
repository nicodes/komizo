"""Provision only komizo's private preview database within protected resources."""
import hashlib,json,os,re,secrets,tempfile,time

IMAGE='postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
NAME='komizo-previews'
NETWORK='komizo-preview-store'
VOLUME='komizo-previews-data'
SETTINGS=['shared_buffers=8MB','max_connections=20','work_mem=1MB','maintenance_work_mem=16MB','autovacuum_max_workers=1','autovacuum_work_mem=8MB']
COMMAND=['postgres',*[arg for setting in SETTINGS for arg in ('-c',setting)]]

class PreviewDatabase:
    def __init__(self,platform):self.p=platform
    def run(self,*args):return self.p.run(['docker',*args],timeout=60)[1].strip()
    def inspect(self,cid):
        rows=json.loads(self.run('inspect',cid))
        if len(rows)!=1 or rows[0].get('Id')!=cid:raise ValueError('preview database identity unavailable')
        return rows[0]
    def validate(self,row,image):
        mounts=row.get('Mounts',[]);networks=set(row.get('NetworkSettings',{}).get('Networks',{}))
        if row.get('Name')!='/'+NAME or row.get('Image')!=image or row.get('HostConfig',{}).get('PortBindings') or networks!={NETWORK}:
            raise ValueError('existing preview database is outside the approved identity or private network')
        if len(mounts)!=1 or any(mounts[0].get(k)!=v for k,v in {'Type':'volume','Name':VOLUME,'Destination':'/var/lib/postgresql','RW':True}.items()):
            raise ValueError('preview database volume differs; no data mutation permitted')
    def configured(self,row,budget):
        limits=row.get('HostConfig',{})
        return row.get('Config',{}).get('Cmd')==COMMAND and all(limits.get(k)==v for k,v in {'Memory':budget['memory_bytes'],'MemorySwap':budget['memory_bytes'],'NanoCpus':budget['milli_cpus']*1000000,'PidsLimit':budget['pids'],'CgroupParent':'/komizo-preview-database'}.items())
    def provision(self,expected):
        stage=self.p.path('/var/lib/komizo/preview-database')
        with self.p.locks():
            body=self.p.read(self.p.path('/etc/komizo/resources.json'),private=True)
            if hashlib.sha256(body).hexdigest()!=expected:raise ValueError('preview database resources changed')
            policy=json.loads(body);budget=policy['preview_database']
            self.p.run(['komizo-box','workload','host-resources','--check','--check-usage','--policy','/etc/komizo/resources.json'])
            if budget['memory_bytes']<64<<20 or budget['swap_bytes']!=0:raise ValueError('preview database requires at least64MiB and no swap')
            group=self.p.path('/sys/fs/cgroup/komizo-preview-database')
            for key,wanted in {'memory.max':str(budget['memory_bytes']),'memory.swap.max':'0','cpu.max':str(budget['milli_cpus']*100)+' 100000','pids.max':str(budget['pids'])}.items():
                if self.p.read(group/key).decode().strip()!=wanted:raise ValueError('preview database controller drift')
            image=self.run('image','inspect','--format','{{.Id}}',IMAGE)
            if not re.fullmatch('sha256:[a-f0-9]{64}',image):raise ValueError('approved local Postgres image unavailable')
            listed=self.run('container','ls','--all','--no-trunc','--filter','name=^/'+NAME+'$','--format','{{.ID}}').splitlines()
            if len(listed)>1 or any(not re.fullmatch('[a-f0-9]{64}',cid) for cid in listed):raise ValueError('preview database inventory ambiguous')
            previous=self.inspect(listed[0]) if listed else None
            if previous:self.validate(previous,image)
            networks=self.run('network','ls','--filter','name=^'+NETWORK+'$','--format','{{.ID}}').splitlines()
            if len(networks)>1:raise ValueError('preview database network ambiguous')
            if networks:
                net=json.loads(self.run('network','inspect',networks[0]))[0]
                if net.get('Name')!=NETWORK or net.get('Internal') is not True or net.get('Labels',{}).get('io.komizo.role')!='preview-database':raise ValueError('preview database network ownership unavailable')
                if set(net.get('Containers',{}))-set(listed):raise ValueError('preview database network has active consumers')
            stage.mkdir(mode=0o700,parents=True,exist_ok=True);self.p.protected(stage,directory=True)
            record={'version':1,'phase':'prepared','resources_sha256':expected,'previous_container_id':listed[0] if listed else None,'image':image,'volume':VOLUME,'production_mutated':False,'volume_deleted':False}
            self.p.journal(stage,record)
            try:
                if not networks:self.run('network','create','--internal','--label','io.komizo.role=preview-database',NETWORK)
                matches=previous and self.configured(previous,budget)
                if previous and not matches:
                    if previous['State']['Running']:self.run('stop','--time','30',listed[0])
                    # Exact validated stopped identity, and no volume-removal flag.
                    self.run('rm',listed[0]);previous=None
                if not previous:
                    record['phase']='creating';self.p.journal(stage,record)
                    directory=self.p.path('/run/komizo');self.p.protected(directory,directory=True)
                    fd,path=tempfile.mkstemp(prefix='preview-db-',dir=directory)
                    try:
                        with os.fdopen(fd,'w') as f:
                            os.fchmod(f.fileno(),0o600);f.write('POSTGRES_PASSWORD='+secrets.token_hex(24)+'\nPOSTGRES_USER=postgres\nPOSTGRES_DB=postgres\nPOSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 '+ ' '.join('--set='+s for s in SETTINGS)+'\n')
                        cid=self.run('run','-d','--pull','never','--name',NAME,'--label','io.komizo.role=preview-database','--restart','unless-stopped','--network',NETWORK,'--cgroup-parent','/komizo-preview-database','--memory',str(budget['memory_bytes']),'--memory-swap',str(budget['memory_bytes']),'--cpus',str(budget['milli_cpus']/1000),'--pids-limit',str(budget['pids']),'--env-file',path,'--mount','type=volume,src='+VOLUME+',dst=/var/lib/postgresql',IMAGE,*COMMAND)
                    finally:os.unlink(path)
                    if not re.fullmatch('[a-f0-9]{64}',cid):raise ValueError('preview database creation identity unavailable')
                else:
                    cid=previous['Id']
                    if not previous['State']['Running']:self.run('start',cid)
                current=self.inspect(cid);self.validate(current,image)
                if not self.configured(current,budget):raise ValueError('created preview database resources differ from authority')
                record.update(phase='starting',container_id=cid);self.p.journal(stage,record)
                for attempt in range(30):
                    code,_=self.p.run(['docker','exec',cid,'pg_isready','-U','postgres','-d','postgres'],required=False,timeout=5)
                    if code==0:break
                    time.sleep(1)
                else:raise ValueError('preview database did not become ready')
                sql="SELECT current_setting('shared_buffers')='8MB' AND current_setting('max_connections')='20' AND NOT EXISTS (SELECT FROM pg_hba_file_rules WHERE type LIKE 'host%' AND auth_method='trust');"
                if self.run('exec',cid,'psql','-XAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres','-c',sql)!='t':raise ValueError('preview database memory/authentication settings unavailable')
                record.update(phase='ready',memory_bytes=budget['memory_bytes']);self.p.journal(stage,record)
                return record
            except Exception:
                record['phase']='failed';self.p.journal(stage,record);raise

if __name__=='__main__':
    import sys
    if os.geteuid()!=0 or len(sys.argv)!=2:raise ValueError('preview database requires the root operator and exact resource hash')
    print(json.dumps(PreviewDatabase(Platform()).provision(sys.argv[1])))
