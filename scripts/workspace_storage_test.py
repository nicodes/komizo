import importlib.util
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('storage',Path(__file__).with_name('workspace_storage.py'));storage=importlib.util.module_from_spec(spec);spec.loader.exec_module(storage)

class StorageBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);(self.root/'.git').write_text('gitdir: fixture')
        self.calls=patch.object(storage.subprocess,'check_output',return_value=b'');self.calls.start();self.addCleanup(self.calls.stop)
        self.procs=patch.object(storage,'active',return_value=False);self.procs.start();self.addCleanup(self.procs.stop)
        self.mounts=patch.object(storage,'mounts',return_value=[]);self.mounts.start();self.addCleanup(self.mounts.stop)
        (self.root/'node_modules').mkdir();(self.root/'node_modules'/'module').write_bytes(b'owned')

    def test_changed_output_refuses_before_any_removal(self):
        import json
        plan=storage.plan(self.root,['node_modules']);path=self.root/'review.json';path.write_text(json.dumps(plan))
        (self.root/'node_modules'/'module').write_bytes(b'changed')
        with self.assertRaises(ValueError):storage.clean(path,storage.digest(plan))
        self.assertTrue((self.root/'node_modules'/'module').exists())

    def test_mount_tracked_file_process_and_evidence_cannot_be_cleaned(self):
        with patch.object(storage,'mounts',return_value=[self.root/'node_modules']):
            with self.assertRaises(ValueError):storage.plan(self.root,['node_modules'])
        with patch.object(storage,'active',return_value=True):
            with self.assertRaises(ValueError):storage.plan(self.root,['node_modules'])
        with patch.object(storage.subprocess,'check_output',return_value=b'tracked'):
            with self.assertRaises(ValueError):storage.plan(self.root,['node_modules'])
        for p in ['.artifacts','.artifacts/evidence','../node_modules','internal/agent/bin/../bin']:
            with self.assertRaises(ValueError):storage.plan(self.root,[p])

    def test_reviewed_owned_outputs_removed_and_symlinks_never_followed(self):
        import json
        outside=self.root/'important';outside.write_text('evidence')
        (self.root/'node_modules'/'link').symlink_to(outside)
        plan=storage.plan(self.root,['node_modules']);path=self.root/'review.json';path.write_text(json.dumps(plan))
        result=storage.clean(path,storage.digest(plan))
        self.assertEqual(result['removed'][0]['path'],'node_modules');self.assertEqual(outside.read_text(),'evidence')

    def test_root_reserve_is_never_counted_as_ordinary_available_space(self):
        class Stat: f_bavail=0;f_bfree=10000;f_frsize=4096;f_favail=1000
        with patch.object(storage.os,'statvfs',return_value=Stat()):
            self.assertFalse(storage.admission(self.root,1,1)['accepted'])

if __name__=='__main__':unittest.main()
