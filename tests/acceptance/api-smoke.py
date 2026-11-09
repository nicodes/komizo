"""Verify packaged owner UI bytes and supervision without developer tooling."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

binary = str(Path(sys.argv[1]).resolve())
assets = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else Path(__file__).resolve().parents[2] / '.artifacts/ui'
assert (assets / 'index.html').is_file()


def children(parent):
    listing = subprocess.check_output(['/bin/ps', '-axo', 'pid=,ppid='], text=True)
    return [int(pid) for row in listing.splitlines() if len(parts := row.split()) == 2
            for pid, ppid in [parts] if int(ppid) == parent]


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    state = subprocess.run(['/bin/ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True, check=False)
    return bool(state.stdout.strip()) and not state.stdout.strip().startswith('Z')


with tempfile.TemporaryDirectory(prefix='komizo-api-smoke-') as scratch:
    root = Path(scratch)
    ssh = root / 'ssh'
    ssh.write_text(f"#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n"
                   f"root=Path({scratch!r})\n"
                   "assert sys.argv[-2:] == ['root@host.example.test','komizo-box status']\n"
                   "with (root/'calls').open('a') as stream:stream.write(json.dumps(sys.argv[1:])+'\\n')\n"
                   "print(json.dumps({'kind':'komizo.status','version':1,'instances':[]}))\n")
    ssh.chmod(0o700)
    env = {key: value for key, value in os.environ.items()
           if key not in ('KOMIZO_API_BINARY', 'KOMIZO_API_PAYLOAD', 'GH_TOKEN', 'GITHUB_TOKEN', 'MISE_GITHUB_TOKEN')}
    env.update(PATH=f'{scratch}:/usr/bin:/bin', HOME=scratch, TMPDIR=scratch)

    for abrupt in (False, True):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        process = subprocess.Popen([binary, 'ui', '--host', 'host.example.test', '--port', str(port)],
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        owned = []
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read().decode())
                try:
                    with urllib.request.urlopen(base + '/healthz', timeout=1) as response:
                        assert response.status == 200
                    owned = children(process.pid)
                    assert len(owned) == 1, owned
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(.05)
            try:
                with urllib.request.urlopen(base + '/api/status', timeout=2) as response:
                    status = json.load(response)
            except OSError as error:
                raise AssertionError({'status_error':type(error).__name__,'fake_ssh_entered':(root/'calls').exists(),
                                      'owner_alive':process.poll() is None,'owned_children':children(process.pid)}) from error
            assert status['kind'] == 'komizo.ui.status'
            assert status['host'] == 'host.example.test'
            assert status['status'] == {'kind': 'komizo.status', 'version': 1, 'instances': []}
            assert json.loads((root / 'calls').read_text().splitlines()[-1])[:4] == ['-T', '-o', 'BatchMode=yes', '-o']
            for source in sorted(assets.rglob('*')):
                if source.is_dir():
                    continue
                assert source.is_file() and not source.is_symlink()
                path = '/' + source.relative_to(assets).as_posix()
                raw = source.read_bytes()
                with urllib.request.urlopen(base + path, timeout=2) as response:
                    assert response.status == 200 and response.read() == raw, path
                    assert response.headers['ETag'] == '"' + hashlib.sha256(raw).hexdigest() + '"'
                    assert response.headers['X-Frame-Options'] == 'DENY'
                    assert response.headers['Cache-Control'] == ('public, max-age=31536000, immutable' if path.startswith('/assets/') else 'no-cache')
                with urllib.request.urlopen(urllib.request.Request(base + path, headers={'Range': 'bytes=0-7'}), timeout=2) as response:
                    assert response.status == 206 and response.read() == raw[:8]
                with urllib.request.urlopen(urllib.request.Request(base + path, headers={'Accept-Encoding': 'gzip'}), timeout=2) as response:
                    body = response.read()
                    assert (gzip.decompress(body) if response.headers.get('Content-Encoding') == 'gzip' else body) == raw
            with urllib.request.urlopen(base + '/app/mailroom/production', timeout=2) as response:
                assert response.read() == (assets / 'index.html').read_bytes()
            for path, headers in [('/api/status', {'Origin': 'https://attacker.example'}),
                                  ('/api/status', {'Host': 'attacker.example'})]:
                try:
                    urllib.request.urlopen(urllib.request.Request(base + path, headers=headers), timeout=2)
                    raise AssertionError('cross-origin owner access admitted')
                except urllib.error.HTTPError as error:
                    assert error.code == 403
            assert not list(root.glob('komizo-api-*')), 'private executable was not unlinked after exec'
        finally:
            process.send_signal(signal.SIGKILL if abrupt else signal.SIGTERM)
            try:
                code = process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise
            deadline = time.monotonic() + 5
            while any(alive(pid) for pid in owned) and time.monotonic() < deadline:
                time.sleep(.05)
            assert not any(alive(pid) for pid in owned), 'embedded API outlived its owner launcher'
        if not abrupt:
            assert code == 0, process.stderr.read().decode()
