import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = str(Path(__file__).parents[1]/'helpers/dev.py')


class OwnedDevelopment(unittest.TestCase):
    def test_stop_preserves_unrelated_listener_and_rejects_wrong_token(self):
        with tempfile.TemporaryDirectory() as root, socket.socket() as unrelated:
            unrelated.bind(('127.0.0.1', 0))
            unrelated.listen()
            process = subprocess.Popen([sys.executable, SCRIPT, 'run', '--', sys.executable,
                '-c', 'import time; time.sleep(90)'], cwd=root)
            try:
                endpoint = Path(root)/'.local/dev/control.sock'
                deadline = time.monotonic()+5
                while not endpoint.exists():
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.02)
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(3)
                    client.connect(str(endpoint))
                    client.sendall(json.dumps({'stop':'wrong-checkout-token'}).encode())
                    self.assertEqual(client.recv(100), b'refused\n')
                self.assertIsNone(process.poll())
                subprocess.run([sys.executable, SCRIPT, 'stop'], cwd=root, check=True, timeout=15)
                self.assertEqual(process.wait(timeout=5), 0)
                # An actual unrelated TCP listener still accepts after shutdown.
                with socket.create_connection(unrelated.getsockname(), timeout=2):
                    accepted, _ = unrelated.accept()
                    accepted.close()
                subprocess.run([sys.executable, SCRIPT, 'stop'], cwd=root, check=True, timeout=5)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=15)


    @unittest.skipUnless(sys.platform == 'linux', 'Linux nested PTY session ownership')
    def test_stop_reaps_detached_descendants_without_touching_unrelated_process(self):
        with tempfile.TemporaryDirectory() as root:
            code = "import os,time; from pathlib import Path; Path('escaped.pid').write_text(str(os.getpid())); time.sleep(90)"
            parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',"+repr(code)+"],start_new_session=True); time.sleep(90)"
            unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(90)'], start_new_session=True)
            process = subprocess.Popen([sys.executable, SCRIPT, 'run', '--', sys.executable, '-c', parent], cwd=root)
            try:
                pidfile = Path(root)/'escaped.pid'
                deadline = time.monotonic()+5
                while not pidfile.exists():
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(),deadline)
                    time.sleep(.02)
                escaped = int(pidfile.read_text())
                subprocess.run([sys.executable, SCRIPT, 'stop'], cwd=root, check=True, timeout=15)
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertFalse(Path('/proc',str(escaped)).exists(), 'separate-session child survived owned shutdown')
                self.assertIsNone(unrelated.poll())
            finally:
                if process.poll() is None:
                    process.terminate(); process.wait(timeout=15)
                unrelated.terminate(); unrelated.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
