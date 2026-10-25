import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('addon_restore', Path(__file__).resolve().parents[1]/'helpers/addon-restore.py')
helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)


class RestoreBoundaries(unittest.TestCase):
    def fixture(self, root, payload):
        (root/'gdam.json').write_text(json.dumps({'addons': {'@owner/addon': {'tag':'v1'}}}))
        (root/'addon-provenance.json').write_text(json.dumps({'@owner/addon':{
            'tag':'v1','asset_id':123,'asset_sha256':hashlib.sha256(payload).hexdigest()}}))

    def archive(self, name='plugin.cfg'):
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as archive:archive.writestr(name,b'reviewed bytes')
        return output.getvalue()

    def test_exact_asset_and_digest_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=self.archive();self.fixture(root,payload)
            def download(url,path):
                self.assertEqual(url,'https://api.github.com/repos/owner/addon/releases/assets/123');path.write_bytes(payload)
            helper.restore(root,download)
            self.assertEqual((root/'addons/@owner_addon/plugin.cfg').read_bytes(),b'reviewed bytes')

    def test_wrong_digest_preserves_previous_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root,self.archive());old=root/'addons/@owner_addon';old.mkdir(parents=True);(old/'retained').write_text('old')
            with self.assertRaises(ValueError):helper.restore(root,lambda url,path:path.write_bytes(b'changed'))
            self.assertEqual((old/'retained').read_text(),'old')

    def test_authenticated_traversal_archive_is_still_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=self.archive('../escaped');self.fixture(root,payload)
            with self.assertRaises(ValueError):helper.restore(root,lambda url,path:path.write_bytes(payload))
            self.assertFalse((root/'escaped').exists())

    def test_redirect_strips_authorization(self):
        import urllib.request
        request=urllib.request.Request('https://api.github.com/x',headers={'Authorization':'Bearer fixture'})
        redirected=helper.Redirect().redirect_request(request,None,302,'redirect',{},'https://assets.example.invalid/archive')
        self.assertIsNone(redirected.get_header('Authorization'))
