"""Verify a packaged CLI serves its embedded API without developer toolchains."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

binary = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix='komizo-api-smoke-') as scratch:
    root = Path(scratch)
    report = root / 'report.json'
    report.write_text('{"v":1,"apps":[]}')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if k not in ('KOMIZO_API_BINARY', 'GH_TOKEN', 'GITHUB_TOKEN', 'MISE_GITHUB_TOKEN')}
    env.update(PATH='/usr/bin:/bin', HOME=scratch, TMPDIR=scratch)
    process = subprocess.Popen([binary, 'ui', '--port', str(port), '--report', str(report)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while True:
            if process.poll() is not None:
                raise AssertionError(process.stderr.read().decode())
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/report', timeout=1) as response:
                    body = json.load(response)
                assert body['v'] == 1
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=2) as response:
            assert response.status == 200 and b'<!doctype html' in response.read().lower()
        # The launcher unlinks its private executable as soon as exec succeeds.
        assert not list(root.glob('komizo-api-*'))
    finally:
        process.send_signal(signal.SIGTERM)
        try:
            code = process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
    assert code == 0, process.stderr.read().decode()
