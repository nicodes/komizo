import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('receive', Path(__file__).resolve().parents[1]/'helpers/receive-backup.py')
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


class ReceiveBackup(unittest.TestCase):
    def test_roundtrip_rejects_checksum_duplicates_and_paths(self):
        receipt = {'format': 1, 'archive_sha256': 'a'*64,
                   'ciphertext_sha256': hashlib.sha256(b'encrypted').hexdigest(),
                   'image_id': 'sha256:'+'b'*64}
        cases = [('valid', 'snapshot.cms', b'encrypted', False),
                 ('changed', 'snapshot.cms', b'changed', False),
                 ('duplicate', 'snapshot.cms', b'encrypted', True),
                 ('escape', '../snapshot.cms', b'encrypted', False)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, path, payload, duplicate in cases:
                archive = root/(name+'.tar')
                with tarfile.open(archive, 'w') as output:
                    entries = [(path, payload), ('receipt.json', json.dumps(receipt).encode())]
                    if duplicate:
                        entries.append((path, payload))
                    for entry, data in entries:
                        info = tarfile.TarInfo(entry)
                        info.size = len(data)
                        output.addfile(info, io.BytesIO(data))
                if name == 'valid':
                    self.assertEqual(receiver.receive(archive, root/name), receipt)
                else:
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        receiver.receive(archive, root/name)


if __name__ == '__main__':
    unittest.main()
