"""Real TLS, bounded process memory and immutable object failure fixtures."""
import hashlib
import http.server
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]/'helpers/upload-backup.py'
spec = importlib.util.spec_from_file_location('transport_fixture', SOURCE)
uploader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uploader)


class BackupTransport(unittest.TestCase):
    def test_tls_large_ciphertext_has_fixed_memory_and_refuses_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root/'cert.pem', root/'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(key), '-out', str(cert), '-days', '1',
                            '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                           check=True, capture_output=True, timeout=20)
            objects, conditions = {}, []

            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args): pass
                def do_PUT(self):
                    conditions.append(self.headers.get('If-None-Match'))
                    if self.path == '/disconnect':
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    if self.path == '/slow': time.sleep(0.6)
                    digest = hashlib.sha256()
                    left = int(self.headers['Content-Length'])
                    length = left
                    while left:
                        chunk = self.rfile.read(min(left, 65536))
                        if not chunk: return
                        digest.update(chunk)
                        left -= len(chunk)
                    status = 412 if self.path in objects else (500 if self.path == '/receipt' else 200)
                    if status == 200: objects[self.path] = (length, digest.hexdigest())
                    self.send_response(status)
                    self.send_header('Content-Length', '0')
                    self.end_headers()

            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.daemon_threads = True
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host = f'127.0.0.1:{server.server_port}'
            ciphertext = root/'synthetic.cms'
            size = 256 << 20
            with ciphertext.open('wb') as stream: stream.truncate(size)
            code = '''import importlib.util,json,resource,ssl,sys,time
spec=importlib.util.spec_from_file_location('uploader',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
resource.setrlimit(resource.RLIMIT_AS,(128<<20,128<<20))
context=ssl.create_default_context(cafile=sys.argv[2]);ssl._create_default_https_context=lambda:context
with m.Ciphertext(sys.argv[3],time.monotonic()+30) as body:
    m.put_object('https://'+sys.argv[4]+'/object',body,'application/octet-stream','fixture','fixture',sys.argv[4],body.deadline)
    try: m.put_object('https://'+sys.argv[4]+'/object',body,'application/octet-stream','fixture','fixture',sys.argv[4],body.deadline)
    except ValueError: pass
    else: raise AssertionError('duplicate replaced an immutable object')
    print(json.dumps({'rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'sha256':body.sha256}))
'''
            try:
                result = subprocess.run([sys.executable, '-I', '-c', code, str(SOURCE), str(cert),
                                         str(ciphertext), host], check=True, text=True,
                                        capture_output=True, timeout=40)
                evidence = json.loads(result.stdout)
                self.assertLess(evidence['rss_kib'], 64 << 10)
                self.assertEqual(objects['/object'], (size, evidence['sha256']))
                context = ssl.create_default_context(cafile=cert)
                with patch.object(ssl, '_create_default_https_context', lambda: context):
                    for path in ('/disconnect', '/receipt'):
                        with self.assertRaises((RuntimeError, OSError, http.client.HTTPException)):
                            uploader.put_object('https://'+host+path, b'fixture', 'application/octet-stream',
                                                'fixture', 'fixture', host, time.monotonic()+2)
                    before = time.monotonic()
                    with self.assertRaises((RuntimeError, OSError)):
                        uploader.put_object('https://'+host+'/slow', b'fixture', 'application/octet-stream',
                                            'fixture', 'fixture', host, before+0.15)
                    self.assertLess(time.monotonic()-before, 0.5)
                self.assertTrue(conditions)
                self.assertTrue(all(condition == '*' for condition in conditions))
                self.assertNotIn('/receipt', objects)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
