import importlib.util
import io
from pathlib import Path
import unittest
import urllib.error

spec=importlib.util.spec_from_file_location('probe',Path(__file__).parents[1]/'helpers/probe-backup-store.py')
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)

class Capability(unittest.TestCase):
    def test_requires_conditioned_creation_conflict_and_preserved_original(self):
        credentials={'BACKUP_S3_HOSTNAME':'store.example.test','BACKUP_S3_BUCKET':'fixtures','BACKUP_S3_ACCESS_KEY':'fixture-access','BACKUP_S3_SECRET_KEY':'fixture-secret'}
        for behavior,compatible in [('correct',True),('overwrite',False),('unsupported',False),('changed',False)]:
            values={}
            def put(url,body,*args):
                if behavior=='unsupported' or url in values and behavior!='overwrite':
                    http=urllib.error.HTTPError(url,404 if behavior=='unsupported' else 412,'fixture',{},io.BytesIO())
                    if http.code==412: raise ValueError('duplicate') from http
                    raise RuntimeError('unsupported') from http
                values[url]=body
            class Response(io.BytesIO):status=200
            def get(request,timeout):
                self.assertEqual(request.method,'GET')
                return Response(b'changed' if behavior=='changed' else values[request.full_url])
            result=probe.probe(credentials,put,get)
            self.assertEqual(result['compatible'],compatible)
            self.assertNotIn('fixture-secret',str(result));self.assertNotIn('fixture-access',str(result))
            self.assertTrue(result['key'].startswith('komizo-capability/'))
