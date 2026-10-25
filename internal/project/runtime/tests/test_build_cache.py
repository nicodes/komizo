import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HELPER = Path(__file__).parents[1]/'helpers/docker-build.py'
spec = importlib.util.spec_from_file_location('cache_builder', HELPER)
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)

class CacheBoundaries(unittest.TestCase):
    def test_failed_build_preserves_previous_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); cache = root/'api'; cache.mkdir()
            (cache/'index.json').write_text('reviewed previous cache')
            with patch.dict(os.environ, {'FLEET_BUILDKIT_CACHE': directory}), patch('sys.argv', ['docker-build.py','--cache-key','api','--','-t','example/api:revision','.']), patch.object(builder.subprocess,'run',side_effect=subprocess.CalledProcessError(1,'docker')):
                with self.assertRaises(subprocess.CalledProcessError): builder.main()
            self.assertEqual((cache/'index.json').read_text(), 'reviewed previous cache')
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['api','api.lock'])

    def test_success_replaces_cache_and_loads_without_publishing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); cache = root/'api'; cache.mkdir(); (cache/'index.json').write_text('old')
            def build(arguments, **kwargs):
                self.assertIn('--load', arguments); self.assertNotIn('--push', arguments)
                self.assertIn('type=local,src='+str(cache), arguments)
                destination = next(a for a in arguments if a.startswith('type=local,dest=')).split('dest=',1)[1].split(',mode=',1)[0]
                (Path(destination)/'index.json').write_text('new verified export')
            with patch.dict(os.environ, {'FLEET_BUILDKIT_CACHE': directory}), patch('sys.argv', ['docker-build.py','--cache-key','api','--','-t','example/api:revision','.']), patch.object(builder.subprocess,'run',side_effect=build): builder.main()
            self.assertEqual((cache/'index.json').read_text(), 'new verified export')

    def test_publish_and_path_injection_fail_before_docker(self):
        for arguments in (['--cache-key','../escape','--','.'], ['--cache-key','api','--','--push','.'], ['--cache-key','api','--','--output=type=registry','.']):
            with patch('sys.argv',['docker-build.py',*arguments]), patch.object(builder.subprocess,'run') as docker:
                with self.assertRaises(SystemExit): builder.main()
                docker.assert_not_called()
