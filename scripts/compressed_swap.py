"""Own a bounded, RAM-only swap device on small hosts; preserve caller swap."""
import json,os,stat,subprocess,tempfile
from pathlib import Path

LOGICAL=256<<20
LIMIT=64<<20

class CompressedSwap:
    def __init__(self,root=Path('/'),owner=0):self.root=Path(root);self.owner=owner;self.record=self.path('/var/lib/komizo/compressed-swap.json')
    def path(self,name):return self.root/name.lstrip('/')
    def protected(self,path,directory=False):
        for p in (path,*path.parents):
            s=p.lstat()
            if s.st_uid!=self.owner or s.st_mode&0o022 or stat.S_ISLNK(s.st_mode):raise ValueError('compressed swap path is not protected')
            if p==self.root:break
        s=path.lstat()
        if not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):raise ValueError('compressed swap input type differs')
        return s
    def read(self,path):
        self.protected(path)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            value=f.read(65537)
            if len(value)>65536:raise ValueError('compressed swap input exceeds bound')
            return value.strip()
    def write(self,path,value):
        self.protected(path)
        fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'w') as f:f.write(str(value))
    def command(self,name,*args):
        aliases={'modprobe':'/sbin/modprobe','mkswap':'/sbin/mkswap','swapon':'/sbin/swapon'}
        alias=self.path(aliases[name]);self.protected(alias.parent,directory=True)
        if alias.lstat().st_uid!=self.owner:raise ValueError('unowned compressed swap executable')
        target=alias.resolve(strict=True);self.protected(target)
        # Preserve BusyBox/kmod's trusted applet name as argv[0].
        result=subprocess.run([str(alias),*args],capture_output=True,timeout=15,env={'PATH':'/usr/sbin:/sbin:/usr/bin:/bin','LC_ALL':'C'})
        if len(result.stdout)>65536 or len(result.stderr)>65536 or result.returncode:raise ValueError('compressed swap command failed')
    def journal(self,row):
        self.protected(self.record.parent,directory=True)
        if self.record.exists():
            if self.protected(self.record).st_mode&0o077:raise ValueError('compressed swap record is not private')
        fd,temporary=tempfile.mkstemp(prefix='.compressed-swap-',dir=self.record.parent)
        try:
            with os.fdopen(fd,'w') as f:
                os.fchmod(f.fileno(),0o600);json.dump(row,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
            os.replace(temporary,self.record)
            d=os.open(self.record.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)
    def swaps(self):
        return {r.split()[0]:r.split() for r in self.read(self.path('/proc/swaps')).splitlines()[1:]}
    def group(self,row):
        path=self.path('/sys/block/zram'+str(row['device_id'])).resolve(strict=True);self.protected(path,directory=True);return path
    def device(self,row,group):
        node=self.path(row['device']);self.protected(node.parent,directory=True)
        s=node.lstat();major,minor=map(int,self.read(group/'dev').split(':'))
        if not stat.S_ISBLK(s.st_mode) or s.st_uid!=self.owner or s.st_mode&0o002 or (os.major(s.st_rdev),os.minor(s.st_rdev))!=(major,minor):raise ValueError('owned compressed swap device differs')
    def configuration(self,row,group):
        # mem_limit is write-only, and CONFIG_ZRAM_WRITEBACK may be disabled.
        values=list(map(int,self.read(group/'mm_stat').split()))
        if len(values)<4 or values[3]!=LIMIT or self.read(group/'disksize')!=str(LOGICAL) or '['+row['algorithm']+']' not in self.read(group/'comp_algorithm'):raise ValueError('compressed swap kernel settings differ')
        if (group/'backing_dev').exists() and self.read(group/'backing_dev')!='none':raise ValueError('compressed swap must have no backing disk')
        io=list(map(int,self.read(group/'io_stat').split()))
        if len(io)<3 or any(n<0 for n in io):raise ValueError('compressed swap counters unavailable')
    def apply(self,total):
        if type(total) is not int or total<=0:raise ValueError('measured positive host memory required')
        if total>2<<30:return {'status':'inapplicable'}
        boot=self.read(self.path('/proc/sys/kernel/random/boot_id'))
        previous=None
        if self.record.exists():
            if self.protected(self.record).st_mode&0o077:raise ValueError('compressed swap record is not private')
            previous=json.loads(self.read(self.record))
            required={'version','owner','device','device_id','logical_bytes','memory_limit_bytes','algorithm','previous_swappiness','phase'}
            if set(previous)-required-{'boot_id'} or not required<=set(previous) or type(previous['version']) is not int or previous['version']!=1 or previous['owner']!='komizo' or type(previous['device_id']) is not int or not 0<=previous['device_id']<1024 or previous['device']!='/dev/zram'+str(previous['device_id']) or previous['logical_bytes']!=LOGICAL or previous['memory_limit_bytes']!=LIMIT or previous['algorithm'] not in ('lz4','lzo-rle') or previous['phase'] not in ('allocated','ready') or type(previous['previous_swappiness']) is not int or not 0<=previous['previous_swappiness']<=200:raise ValueError('compressed swap ownership record differs')
        active=self.swaps()
        if previous and previous.get('boot_id',boot)==boot:
            row=previous;group=self.group(row);self.device(row,group)
            if row['device'] in active:
                self.configuration(row,group)
                row.update(phase='ready',boot_id=boot);self.journal(row)
                return {'status':'ready',**row}
            if row['phase']=='ready':raise ValueError('owned compressed swap unexpectedly inactive')
        else:
            if active:return {'status':'caller_swap_preserved'}
            disabled=self.path('/etc/komizo/no-compressed-swap')
            if disabled.exists():self.protected(disabled);return {'status':'disabled_by_owner'}
            control=self.path('/sys/class/zram-control/hot_add')
            if not control.exists():
                try:self.command('modprobe','zram','num_devices=0')
                except (FileNotFoundError,ValueError):return {'status':'kernel_unavailable'}
            if not control.exists():return {'status':'kernel_unavailable'}
            control=control.resolve(strict=True);number=self.read(control)
            if not number.isdigit() or int(number)>=1024:raise ValueError('compressed swap allocation identity differs')
            row={'version':1,'owner':'komizo','device':'/dev/zram'+number,'device_id':int(number),'logical_bytes':LOGICAL,'memory_limit_bytes':LIMIT,'algorithm':'lz4','previous_swappiness':int(self.read(self.path('/proc/sys/vm/swappiness'))),'phase':'allocated','boot_id':boot}
            group=self.group(row);self.device(row,group)
            if int(self.read(group/'disksize')) or int(self.read(group/'initstate')):raise ValueError('new compressed swap device was initialized')
            algorithms=self.read(group/'comp_algorithm').replace('[','').replace(']','').split()
            algorithm=next((name for name in ('lz4','lzo-rle') if name in algorithms),None)
            if algorithm is None:
                self.write(control.parent/'hot_remove',number)
                return {'status':'kernel_unavailable'}
            row['algorithm']=algorithm
            self.journal(row)
        if row['device'] in self.swaps():raise ValueError('compressed swap became active before initialization')
        if int(self.read(group/'disksize'))==0:
            if row['algorithm'] not in self.read(group/'comp_algorithm').replace('[','').replace(']','').split():raise ValueError('fast RAM compression unavailable')
            self.write(group/'comp_algorithm',row['algorithm']);self.write(group/'mem_limit',LIMIT);self.write(group/'disksize',LOGICAL)
        self.configuration(row,group);self.device(row,group)
        self.command('mkswap',str(self.path(row['device'])))
        self.command('swapon','-p','100',str(self.path(row['device'])))
        if row['device'] not in self.swaps():raise ValueError('owned compressed swap did not activate')
        self.write(self.path('/proc/sys/vm/swappiness'),max(row['previous_swappiness'],100))
        self.configuration(row,group);row.update(phase='ready',boot_id=boot);self.journal(row)
        return {'status':'ready',**row}

if __name__=='__main__':
    import sys
    if os.geteuid()!=0 or len(sys.argv)!=2:raise ValueError('compressed swap requires the local root resource operator')
    CompressedSwap().apply(int(sys.argv[1]))
