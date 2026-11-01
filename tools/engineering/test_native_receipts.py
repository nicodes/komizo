import hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
class NativeReceipts(unittest.TestCase):
    def test_refuses_wrong_source_version_digest_and_symlink(self):
        root=Path(__file__).resolve().parents[2]
        source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
        env={**os.environ,'VERSION':'fixture'}
        with tempfile.TemporaryDirectory() as temporary:
            binary=Path(temporary)/'komizo';binary.write_bytes(b'fixture bytes, never executed')
            metadata={'schema':1,'source':source,'version':'fixture','sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
            def accepted(values):
                binary.with_suffix('.json').write_text(json.dumps(values))
                return subprocess.run(['/usr/bin/python3',str(root/'tools/engineering/native-receipt.py'),str(binary)],cwd=root,env=env,capture_output=True).returncode==0
            self.assertTrue(accepted(metadata))
            for key,value in [('schema',2),('source','f'*40),('version','other'),('sha256','0'*64)]:
                with self.subTest(key=key):self.assertFalse(accepted({**metadata,key:value}))
            original=binary.with_name('original');binary.rename(original);binary.symlink_to(original)
            self.assertFalse(accepted(metadata))
