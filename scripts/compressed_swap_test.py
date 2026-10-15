import importlib.util,json,os,tempfile,unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('compressed',Path(__file__).with_name('compressed_swap.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
HEADER='Filename\tType\tSize\tUsed\tPriority\n'

class KernelFixture(m.CompressedSwap):
    def __init__(self,root):
        super().__init__(root,os.getuid());self.calls=[];self.allocations=0;self.limit=0;self.fail_swap=False
        for name,value in {'/proc/swaps':HEADER,'/proc/sys/kernel/random/boot_id':'boot-one','/proc/sys/vm/swappiness':'60','/sys/class/zram-control/hot_add':'0','/etc/komizo/no-unused-marker':'','/var/lib/komizo/placeholder':''}.items():
            p=self.path(name);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value)
        self.group_path=self.path('/sys/devices/virtual/block/zram0');self.group_path.mkdir(parents=True)
        self.path('/sys/block').mkdir();self.path('/sys/block/zram0').symlink_to(self.group_path)
        for name,value in {'disksize':'0','initstate':'0','dev':'252:0','comp_algorithm':'lzo-rle [lz4]','mem_limit':'','mm_stat':'0 0 0 0 0 0 0 0 0','io_stat':'0 0 0 0'}.items():(self.group_path/name).write_text(value)
        self.path('/dev').mkdir();self.path('/dev/zram0').write_text('fixture')
    def read(self,path):
        if path.name=='mem_limit':raise AssertionError('kernel mem_limit is write-only')
        if path.name=='hot_add':self.allocations+=1
        return super().read(path)
    def write(self,path,value):
        super().write(path,value)
        if path.name=='mem_limit':self.limit=int(value)
        if path.name=='comp_algorithm':path.write_text('lzo-rle ['+str(value)+']')
        if path.name=='disksize':
            (path.parent/'initstate').write_text('1');(path.parent/'mm_stat').write_text('0 0 0 '+str(self.limit)+' 0 0 0 0 0')
    def device(self,row,group):
        if row['device']!='/dev/zram0' or self.read(group/'dev')!='252:0':raise ValueError('fixture device identity differs')
    def command(self,name,*args):
        self.calls.append((name,*args))
        if name=='swapon':
            if self.fail_swap:self.fail_swap=False;raise ValueError('fixture activation interruption')
            self.path('/proc/swaps').write_text(HEADER+'/dev/zram0 partition 262140 0 100\n')

class CompressedSwapTests(unittest.TestCase):
    def test_fresh_kernel_write_only_limit_and_absent_writeback_activate_and_reuse_exact_device(self):
        with tempfile.TemporaryDirectory() as directory:
            f=KernelFixture(directory);r=f.apply(1<<30)
            self.assertEqual(r['status'],'ready');self.assertEqual(r['boot_id'],'boot-one')
            self.assertEqual(f.allocations,1);self.assertEqual(f.calls,[('mkswap',str(f.path('/dev/zram0'))),('swapon','-p','100',str(f.path('/dev/zram0')))])
            self.assertEqual(f.record.stat().st_mode&0o777,0o600);self.assertEqual(f.path('/proc/sys/vm/swappiness').read_text(),'100')
            f.path('/proc/sys/vm/swappiness').write_text('42');before=f.record.read_bytes();f.calls.clear()
            self.assertEqual(f.apply(1<<30)['status'],'ready');self.assertEqual(f.calls,[]);self.assertEqual(f.allocations,1)
            self.assertEqual(before,f.record.read_bytes());self.assertEqual(f.path('/proc/sys/vm/swappiness').read_text(),'42')
    def test_caller_swap_and_opt_out_never_allocate_or_format(self):
        with tempfile.TemporaryDirectory() as directory:
            f=KernelFixture(directory);f.path('/proc/swaps').write_text(HEADER+'/dev/owner partition 12345 1 20\n')
            self.assertEqual(f.apply(1<<30)['status'],'caller_swap_preserved')
            f.path('/proc/swaps').write_text(HEADER);f.path('/etc/komizo/no-compressed-swap').write_text('')
            self.assertEqual(f.apply(1<<30)['status'],'disabled_by_owner');self.assertEqual(f.calls,[]);self.assertEqual(f.allocations,0)
            self.assertEqual(f.apply(4<<30)['status'],'inapplicable')
    def test_interrupted_owned_initialization_resumes_without_allocating_another_device(self):
        with tempfile.TemporaryDirectory() as directory:
            f=KernelFixture(directory);f.fail_swap=True
            with self.assertRaisesRegex(ValueError,'interruption'):f.apply(1<<30)
            self.assertEqual(json.loads(f.record.read_text())['phase'],'allocated')
            self.assertEqual(f.apply(1<<30)['status'],'ready');self.assertEqual(f.allocations,1)
    def test_old_boot_never_reformats_callers_current_swap_even_at_the_same_device_number(self):
        with tempfile.TemporaryDirectory() as directory:
            f=KernelFixture(directory);f.apply(1<<30);before=f.record.read_bytes();f.calls.clear()
            f.path('/proc/sys/kernel/random/boot_id').write_text('boot-two')
            self.assertEqual(f.apply(1<<30)['status'],'caller_swap_preserved');self.assertEqual(f.calls,[]);self.assertEqual(before,f.record.read_bytes())
    def test_native_boot_recreates_only_after_previous_boot_and_no_caller_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            f=KernelFixture(directory);f.apply(1<<30);f.calls.clear()
            f.path('/proc/sys/kernel/random/boot_id').write_text('boot-two');f.path('/proc/swaps').write_text(HEADER)
            (f.group_path/'disksize').write_text('0');(f.group_path/'initstate').write_text('0');(f.group_path/'mm_stat').write_text('0 0 0 0 0')
            r=f.apply(1<<30)
            self.assertEqual(r['boot_id'],'boot-two');self.assertEqual(r['status'],'ready');self.assertEqual(f.allocations,2)
            self.assertEqual([c[0] for c in f.calls],['mkswap','swapon'])
    def test_root_pilot_record_is_adopted_only_after_actual_active_device_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            f=KernelFixture(directory);f.apply(1<<30);r=json.loads(f.record.read_text());r.pop('boot_id');f.record.write_text(json.dumps(r));f.calls.clear()
            self.assertEqual(f.apply(1<<30)['boot_id'],'boot-one');self.assertEqual(f.calls,[])
    def test_fast_fallback_and_owner_swappiness_are_generic_host_capabilities(self):
        with tempfile.TemporaryDirectory() as directory:
            f=KernelFixture(directory);(f.group_path/'comp_algorithm').write_text('[lzo-rle]');f.path('/proc/sys/vm/swappiness').write_text('150')
            self.assertEqual(f.apply(1<<30)['algorithm'],'lzo-rle');self.assertEqual(f.path('/proc/sys/vm/swappiness').read_text(),'150')

    def test_changed_backing_disk_or_kernel_limits_refuse_before_commands(self):
        for change in ('backing','limits','inactive'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory:
                f=KernelFixture(directory);f.apply(1<<30);f.calls.clear()
                if change=='backing':(f.group_path/'backing_dev').write_text('/dev/owner')
                if change=='limits':(f.group_path/'mm_stat').write_text('0 0 0 0 0')
                if change=='inactive':f.path('/proc/swaps').write_text(HEADER)
                with self.assertRaises(ValueError):f.apply(1<<30)
                self.assertEqual(f.calls,[])
    def test_regular_file_cannot_be_formatted_as_a_swap_device_and_writable_record_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            f=KernelFixture(directory)
            with self.assertRaisesRegex(ValueError,'device differs'):m.CompressedSwap.device(f,{'device':'/dev/zram0'},f.group_path)
            f.apply(1<<30);f.calls.clear();f.record.chmod(0o666)
            with self.assertRaisesRegex(ValueError,'not protected'):f.apply(1<<30)
            self.assertEqual(f.calls,[])

if __name__=='__main__':unittest.main()
