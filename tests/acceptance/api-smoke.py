"""Verify packaged owner UI bytes and supervision without developer tooling."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import urllib.parse

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


with tempfile.TemporaryDirectory(prefix='komizo-api-smoke-', dir=Path(tempfile.gettempdir()).resolve()) as scratch:
    root = Path(scratch)
    ssh = root / 'ssh'
    ssh.write_text(f"#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n"
                   f"root=Path({scratch!r})\n"
                   "with (root/'calls').open('a') as stream:stream.write(json.dumps(sys.argv[1:])+'\\n')\n"
                   "assert sys.argv[-2:] == ['root@host.example.test','komizo-box status']\n"
                   "print(json.dumps({'kind':'komizo.status','version':1,'instances':[]}))\n")
    ssh.chmod(0o700)
    env = {key: value for key, value in os.environ.items()
           if key not in ('KOMIZO_API_BINARY', 'KOMIZO_API_PAYLOAD', 'GH_TOKEN', 'GITHUB_TOKEN', 'MISE_GITHUB_TOKEN')}
    env.update(PATH=f'{scratch}:/usr/bin:/bin', HOME=scratch, TMPDIR=scratch)

    previous_capability = None
    for abrupt in (False, True):
        (root / 'calls').unlink(missing_ok=True)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        process = subprocess.Popen([binary, 'ui', '--host', 'host.example.test', '--port', str(port)],
                                   env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        owned = []
        launcher = None
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
            launchers = list(root.glob('komizo-ui-*/index.html'))
            assert len(launchers) == 1, 'owner launcher was not created exactly once'
            launcher = launchers[0]
            assert launcher.parent.stat().st_mode & 0o7777 == 0o700
            assert launcher.stat().st_mode & 0o7777 == 0o600
            assert launcher.stat().st_uid == os.geteuid() and launcher.stat().st_nlink == 1
            capabilities = set(re.findall(r'#komizo-session=([a-f0-9]{64})', launcher.read_text()))
            assert len(capabilities) == 1, 'owner launcher lacks its closed session identity'
            capability = capabilities.pop()
            assert capability != previous_capability, 'owner capability was reused between launches'
            previous_capability = capability
            announcement = process.stdout.readline().decode().strip()
            assert announcement.startswith('Open the owner UI: file://')
            assert Path(urllib.parse.unquote(announcement.split('file://', 1)[1])) == launcher
            assert capability not in announcement
            processes = subprocess.check_output(['/bin/ps', 'eww', '-p', ','.join(map(str, [process.pid, *owned])), '-o', 'command='], text=True)
            assert capability not in processes, 'owner capability entered process arguments or environment'
            probe = '''import json,os,sys,urllib.request,urllib.error
from pathlib import Path
assert os.geteuid()!=int(sys.argv[3])
try:Path(sys.argv[1]).read_bytes()
except PermissionError:pass
else:raise AssertionError("foreign UID read private bootstrap")
base=sys.argv[2]
headers={"Origin":base,"X-Komizo-Request":"1","Content-Type":"application/json"}
for path in ("/api/status","/api/history","/api/logs","/api/operation","/api/actions"):
 data=json.dumps({"application":"mailroom","instance":"production","action":"stop","release_digest":"sha256:"+"a"*64,"nonce":"b"*32}).encode() if path.endswith("actions") else None
 request=urllib.request.Request(base+path,headers=headers,data=data)
 try:urllib.request.urlopen(request,timeout=3)
 except urllib.error.HTTPError as error:assert error.code==403
 else:raise AssertionError("foreign UID invoked owner API")
print("foreign UID bootstrap and forged owner requests refused")
'''
            command = ['/usr/bin/python3', '-I', '-B', '-c', probe, str(launcher), base, str(os.geteuid())]
            drop = None
            if os.geteuid() == 0:
                nobody = pwd.getpwnam('nobody')
                def drop():
                    os.setgroups([]); os.setgid(nobody.pw_gid); os.setuid(nobody.pw_uid)
            else:
                command = ['sudo', '-n', '-u', 'nobody', *command]
            checked = subprocess.run(command, env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent'},
                                     stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15, preexec_fn=drop)
            assert checked.returncode == 0, 'actual foreign-UID owner boundary failed: ' + checked.stderr[-1024:]
            assert not (root / 'calls').exists(), 'foreign UID reached owner transport'
            try:
                with urllib.request.urlopen(urllib.request.Request(base + '/api/status', headers={'Authorization': 'Bearer ' + capability}), timeout=2) as response:
                    status = json.load(response)
            except OSError as error:
                raise AssertionError({'status_error':type(error).__name__,'fake_ssh_entered':(root/'calls').exists(),
                                      'owner_alive':process.poll() is None,'owned_children':children(process.pid)}) from error
            assert status['kind'] == 'komizo.ui.status'
            assert status['host'] == 'host.example.test'
            assert status['status'] == {'kind': 'komizo.status', 'version': 1, 'instances': []}
            assert capability not in json.dumps(status)
            assert json.loads((root / 'calls').read_text().splitlines()[-1])[:4] == ['-T', '-o', 'BatchMode=yes', '-o']
            for source in sorted(assets.rglob('*')):
                if source.is_dir():
                    continue
                assert source.is_file() and not source.is_symlink()
                path = '/' + source.relative_to(assets).as_posix()
                raw = source.read_bytes()
                assert capability.encode() not in raw
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
                headers['Authorization'] = 'Bearer ' + capability
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
            if launcher is not None:
                assert not launcher.parent.exists(), 'owner-private bootstrap outlived its launcher'
        if not abrupt:
            assert code == 0, process.stderr.read().decode()
