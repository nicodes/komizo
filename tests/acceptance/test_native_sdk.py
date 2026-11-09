"""The test SDK retains exact public bytes and never forwards the API token."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error

spec=importlib.util.spec_from_file_location('native_sdk',Path(__file__).parents[1]/'support/native_host_sdk.py')
sdk=importlib.util.module_from_spec(spec);spec.loader.exec_module(sdk)


class NativeSdk(unittest.TestCase):
    def metadata(self):
        return {'tag_name':'v'+sdk.VERSION,'draft':False,'assets':[{'id':sdk.ASSET_ID,'name':sdk.ASSET,'size':sdk.SIZE,
            'digest':'sha256:'+sdk.SHA256,'url':sdk.API+'assets/'+str(sdk.ASSET_ID)}]}

    def test_release_asset_must_keep_its_exact_id_name_size_and_digest(self):
        sdk.metadata(self.metadata())
        for key,value in [('id',123),('size',1),('digest','sha256:'+'0'*64),('name','different.tar.zst'),('url','https://elsewhere.invalid/asset')]:
            changed=self.metadata();changed['assets'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):sdk.metadata(changed)
        changed=self.metadata();changed['assets'].append(changed['assets'][0])
        with self.assertRaises(ValueError):sdk.metadata(changed)

    def test_official_cdn_receives_no_bearer_token_and_changed_bytes_refuse(self):
        body=b'pinned SDK bytes';calls=[]
        class Opener:
            def open(inner,request,timeout):
                calls.append(request)
                if len(calls)==1:return io.BytesIO(json.dumps(self.metadata()).encode())
                if len(calls)==2:raise urllib.error.HTTPError(request.full_url,302,'redirect',{'Location':'https://release-assets.githubusercontent.com/known?signature=ephemeral'},None)
                return io.BytesIO(body)
        with tempfile.TemporaryDirectory() as temporary,patch.object(sdk,'SIZE',len(body)),patch.object(sdk,'SHA256',hashlib.sha256(body).hexdigest()):
            target=Path(temporary)/'archive';sdk.download(target,'private-read-token',time.monotonic()+5,Opener())
            self.assertEqual(target.read_bytes(),body)
            self.assertEqual(calls[0].get_header('Authorization'),'Bearer private-read-token')
            self.assertEqual(calls[1].get_header('Authorization'),'Bearer private-read-token')
            self.assertIsNone(calls[2].get_header('Authorization'))
            calls.clear()
            with patch.object(sdk,'SHA256','0'*64),self.assertRaisesRegex(ValueError,'bytes changed'):
                sdk.download(Path(temporary)/'altered','private-read-token',time.monotonic()+5,Opener())

    def test_redirects_cannot_select_another_origin_scheme_or_credentials(self):
        for location in ['https://untrusted.invalid/file','http://release-assets.githubusercontent.com/file',
                         'https://user:password@release-assets.githubusercontent.com/file','https://release-assets.githubusercontent.com:8443/file']:
            calls=[]
            class Opener:
                def open(inner,request,timeout):
                    calls.append(request)
                    if len(calls)==1:return io.BytesIO(json.dumps(self.metadata()).encode())
                    raise urllib.error.HTTPError(request.full_url,302,'redirect',{'Location':location},None)
            with self.subTest(location=location),tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(ValueError,'official CDN'):
                    sdk.download(Path(temporary)/'archive','read-token',time.monotonic()+5,Opener())
                self.assertEqual(len(calls),2)
                self.assertFalse((Path(temporary)/'archive').exists())

    def test_deadline_and_size_have_no_unbounded_fallback(self):
        with self.assertRaisesRegex(ValueError,'deadline'):
            sdk.request('https://api.github.com/',{},time.monotonic()-1,object())
        class Opener:
            def open(inner,request,timeout):
                if request.full_url.endswith('v'+sdk.VERSION):return io.BytesIO(json.dumps(self.metadata()).encode())
                return io.BytesIO(b'oversized')
        with tempfile.TemporaryDirectory() as temporary,patch.object(sdk,'SIZE',1):
            with self.assertRaisesRegex(ValueError,'size or deadline'):
                sdk.download(Path(temporary)/'archive','read-token',time.monotonic()+5,Opener())


if __name__=='__main__':unittest.main()
