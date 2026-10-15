import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

m=load('preview_database');platform=load('platform')
IMAGE='sha256:'+'e'*64
OLD='a'*64
NEW='b'*64

class Fixture:
    def __init__(self,root):
        self.root=Path(root);self.calls=[];self.fail_inventory=False;self.foreign=False;self.sql_ok=True;self.fail_create=False
        self.row={'Id':OLD,'Name':'/'+m.NAME,'Image':IMAGE,'Config':{'Cmd':['postgres']},'HostConfig':{'PortBindings':{}},'State':{'Running':True},'Mounts':[{'Type':'volume','Name':m.VOLUME,'Destination':'/var/lib/postgresql','RW':True}],'NetworkSettings':{'Networks':{m.NETWORK:{}}}}
        for n in ['etc/komizo','run/komizo','var/lib/komizo/apps','var/lib/komizo/releases','sys/fs/cgroup/komizo-preview-database']:(self.root/n).mkdir(parents=True,exist_ok=True)
        self.budget={'memory_bytes':64<<20,'swap_bytes':0,'milli_cpus':50,'pids':128}
        file=self.root/'etc/komizo/resources.json';file.write_text(json.dumps({'preview_database':self.budget}));file.chmod(0o600)
        for k,v in {'memory.max':str(64<<20),'memory.swap.max':'0','cpu.max':'5000 100000','pids.max':'128'}.items():(self.root/'sys/fs/cgroup/komizo-preview-database'/k).write_text(v)
        self.p=platform.Platform(self.root,self.run,owner=os.getuid())
    def run(self,args,required=True,timeout=90):
        self.calls.append(args)
        if args[0]=='komizo-box':return 0,''
        if args[1:3]==['image','inspect']:return 0,IMAGE
        if args[1:3]==['container','ls']:
            if self.fail_inventory:raise ValueError('inventory unavailable')
            return 0,self.row['Id'] if self.row else ''
        if args[1]=='inspect':return 0,json.dumps([self.row])
        if args[1:3]==['network','ls']:return 0,'network'
        if args[1:3]==['network','inspect']:return 0,json.dumps([{'Name':m.NETWORK,'Internal':True,'Labels':{'io.komizo.role':'preview-database'},'Containers':{'foreign':{}} if self.foreign else {self.row['Id']:{}} if self.row else {}}])
        if args[1]=='stop':
            assert args[-1]==OLD;self.row['State']['Running']=False
        elif args[1]=='rm':
            assert args==['docker','rm',OLD] and not self.row['State']['Running'];self.row=None
        elif args[1]=='run':
            path=Path(args[args.index('--env-file')+1]);assert path.stat().st_mode&0o077==0
            secret=path.read_text();assert 'POSTGRES_PASSWORD=' in secret and 'POSTGRES_HOST_AUTH_METHOD=trust' not in secret
            self.envfile=path
            if self.fail_create:raise ValueError('creation interrupted')
            assert args[args.index('--memory')+1]==str(64<<20) and args[args.index('--memory-swap')+1]==str(64<<20)
            assert args[args.index('--cgroup-parent')+1]=='/komizo-preview-database'
            self.row={'Id':NEW,'Name':'/'+m.NAME,'Image':IMAGE,'HostConfig':{'PortBindings':{}},'Mounts':[{'Type':'volume','Name':m.VOLUME,'Destination':'/var/lib/postgresql','RW':True}],'NetworkSettings':{'Networks':{m.NETWORK:{}}}}
            self.row['Config']={'Cmd':m.COMMAND};self.row['HostConfig'].update(Memory=64<<20,MemorySwap=64<<20,NanoCpus=50000000,PidsLimit=128,CgroupParent='/komizo-preview-database')
            return 0,NEW
        elif args[1]=='exec':return 0,('t' if self.sql_ok else 'f') if 'psql' in args else ''
        return 0,''
    def provision(self):
        import hashlib
        return m.PreviewDatabase(self.p).provision(hashlib.sha256((self.root/'etc/komizo/resources.json').read_bytes()).hexdigest())
    def mutations(self):return [a for a in self.calls if a[0]=='docker' and a[1] in ('run','start','stop','rm','update','volume')]

class PreviewDatabaseBoundary(unittest.TestCase):
    def test_reconfiguration_preserves_volume_uses_exact_identity_and_hides_password(self):
        with tempfile.TemporaryDirectory() as root:
            f=Fixture(root);result=f.provision()
            self.assertEqual(result['phase'],'ready');self.assertFalse(result['production_mutated']);self.assertFalse(result['volume_deleted'])
            self.assertEqual(result['container_id'],NEW);self.assertFalse(f.envfile.exists())
            self.assertEqual([a[1] for a in f.mutations()],['stop','rm','run'])
            self.assertNotIn('POSTGRES_PASSWORD=',str(f.calls));self.assertNotIn('POSTGRES_HOST_AUTH_METHOD=trust',str(f.calls))
    def test_wrong_image_volume_network_or_ports_refuse_before_mutations(self):
        for mutate in [lambda f:f.row.update(Image='sha256:'+'f'*64),lambda f:f.row['Mounts'][0].update(Name='gdam_postgres_data'),lambda f:f.row['HostConfig'].update(PortBindings={'5432/tcp':[{}]}),lambda f:f.row['NetworkSettings'].update(Networks={'edge':{}}),lambda f:setattr(f,'foreign',True),lambda f:setattr(f,'fail_inventory',True)]:
            with self.subTest(mutate=mutate),tempfile.TemporaryDirectory() as root:
                f=Fixture(root);mutate(f)
                with self.assertRaises(ValueError):f.provision()
                self.assertEqual(f.mutations(),[])
    def test_insufficient_capacity_or_controller_drift_refuses_without_docker(self):
        for key,value in [('memory.max','max'),('memory.swap.max','1'),('cpu.max','max 100000'),('pids.max','max')]:
            with tempfile.TemporaryDirectory() as root:
                f=Fixture(root);(f.root/'sys/fs/cgroup/komizo-preview-database'/key).write_text(value)
                with self.assertRaises(ValueError):f.provision()
                self.assertFalse(any(a[0]=='docker' for a in f.calls))
        with tempfile.TemporaryDirectory() as root:
            f=Fixture(root);f.budget['memory_bytes']=4<<20;(f.root/'etc/komizo/resources.json').write_text(json.dumps({'preview_database':f.budget}))
            with self.assertRaises(ValueError):f.provision()
            self.assertFalse(any(a[0]=='docker' for a in f.calls))
    def test_current_running_configuration_does_not_restart(self):
        with tempfile.TemporaryDirectory() as root:
            f=Fixture(root);f.row['Config']['Cmd']=m.COMMAND
            f.row['HostConfig'].update(Memory=64<<20,MemorySwap=64<<20,NanoCpus=50000000,PidsLimit=128,CgroupParent='/komizo-preview-database')
            self.assertEqual(f.provision()['container_id'],OLD);self.assertEqual(f.mutations(),[])
    def test_interrupted_creation_cleans_private_password_file_and_records_failure(self):
        with tempfile.TemporaryDirectory() as root:
            f=Fixture(root);f.fail_create=True
            with self.assertRaises(ValueError):f.provision()
            self.assertFalse(f.envfile.exists())
            record=json.loads((f.root/'var/lib/komizo/preview-database/operation.json').read_text())
            self.assertEqual(record['phase'],'failed');self.assertFalse(record['volume_deleted'])
            self.assertFalse(any(a[1]=='volume' for a in f.mutations()))
    def test_failed_authentication_postcondition_cannot_report_readiness(self):
        with tempfile.TemporaryDirectory() as root:
            f=Fixture(root);f.sql_ok=False
            with self.assertRaisesRegex(ValueError,'authentication'):f.provision()
            self.assertEqual(json.loads((f.root/'var/lib/komizo/preview-database/operation.json').read_text())['phase'],'failed')
    def test_changed_resource_hash_refuses_before_any_docker_call(self):
        with tempfile.TemporaryDirectory() as root:
            f=Fixture(root)
            with self.assertRaisesRegex(ValueError,'resources changed'):m.PreviewDatabase(f.p).provision('0'*64)
            self.assertFalse(f.calls)

if __name__=='__main__':unittest.main()
