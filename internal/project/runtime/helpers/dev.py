#!/usr/bin/env python3
"""Own one checkout's development stack; never discover shutdown targets by port."""
import argparse
import ctypes
import fcntl
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import subprocess
import sys
import time


def adopt_descendants():
    # mprocs opens separate PTY sessions. A process-group signal alone leaves
    # those children alive. Linux reparents orphaned descendants to this
    # supervisor; this setting affects only our own process, never the host.
    if sys.platform != 'linux':
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'cannot own development descendants')
    return True


def process_handle(pid):
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.pidfd_open(pid, 0)
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), 'cannot open owned process handle')
    return descriptor


def signal_handle(descriptor, signum):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.pidfd_send_signal(descriptor, signum, None, 0) < 0:
        raise OSError(ctypes.get_errno(), 'cannot signal owned process handle')


def stop_descendants(child):
    # Enumerate only the supervisor's descendants, never matching command names
    # or ports. pidfds bind signals to a process identity even if a PID is reused.
    handles = {}
    def collect(parent):
        try:
            children = (Path('/proc')/str(parent)/'task'/str(parent)/'children').read_text().split()
        except FileNotFoundError:
            return
        for value in children:
            pid = int(value)
            if pid not in handles:
                descriptor = None
                try:
                    before = (Path('/proc')/value/'stat').read_text().rsplit(')', 1)[1].split()
                    descriptor = process_handle(pid)
                    after = (Path('/proc')/value/'stat').read_text().rsplit(')', 1)[1].split()
                    if before[19] != after[19] or int(after[1]) != parent:
                        os.close(descriptor)
                        continue
                    handles[pid] = descriptor
                except ProcessLookupError:
                    continue
                except FileNotFoundError:
                    if descriptor is not None:
                        os.close(descriptor)
                    continue
            if not select.select([handles[pid]], [], [], 0)[0]:
                collect(pid)
    try:
        for phase, duration in [(signal.SIGTERM, 5), (signal.SIGKILL, 5)]:
            deadline = time.monotonic()+duration
            while time.monotonic() < deadline:
                collect(os.getpid())
                for descriptor in handles.values():
                    try:
                        signal_handle(descriptor, phase)
                    except ProcessLookupError:
                        pass
                child.poll()  # Popen owns reaping its immediate child.
                for pid in handles:
                    if pid != child.pid:
                        try:
                            os.waitpid(pid, os.WNOHANG)
                        except ChildProcessError:
                            pass
                if child.poll() is not None and all(select.select([fd], [], [], 0)[0] for fd in handles.values()):
                    # Catch a just-orphaned PTY child before declaring cleanup.
                    collect(os.getpid())
                    if all(select.select([fd], [], [], 0)[0] for fd in handles.values()):
                        return
                time.sleep(.05)
        raise RuntimeError('development descendant cleanup did not finish')
    finally:
        for descriptor in handles.values():
            os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['run', 'stop'])
    parser.add_argument('--state', default='.local/dev')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    root = Path.cwd()
    state = root/args.state
    if state.is_symlink():
        raise RuntimeError('development state must not be a symlink')
    os.umask(0o077)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state.stat().st_uid != os.getuid() or state.stat().st_mode & 0o077:
        raise RuntimeError('development state must be owned by this user and mode 0700')
    os.chdir(state)  # Relative Unix socket names also work in long checkout paths.
    if args.operation == 'stop':
        try:
            token = Path('token').read_text().strip()
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(15)
                client.connect('control.sock')
                client.sendall(json.dumps({'stop': token}).encode()+b'\n')
                if client.recv(100) != b'stopped\n':
                    raise RuntimeError('development supervisor refused the stop request')
        except (FileNotFoundError, ConnectionRefusedError):
            print('No development stack owned by this checkout is running.')
        return
    command = args.command
    if command[:1] == ['--']:
        command = command[1:]
    if not command:
        parser.error('run requires a command after --')
    with Path('lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('this checkout already owns a development stack') from None
        Path('control.sock').unlink(missing_ok=True)
        token = secrets.token_hex(32)
        Path('token').write_text(token)
        stopping = False

        def stop_requested(_signum, _frame):
            nonlocal stopping
            stopping = True

        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, stop_requested)
        with socket.socket(socket.AF_UNIX) as server:
            server.bind('control.sock')
            server.listen(4)
            owns_descendants = adopt_descendants()
            child = subprocess.Popen(command, cwd=root, start_new_session=True)
            clients = []
            try:
                while child.poll() is None and not stopping:
                    if not select.select([server], [], [], 0.1)[0]:
                        continue
                    client, _ = server.accept()
                    client.settimeout(2)
                    try:
                        request = client.recv(1024)
                        if json.loads(request).get('stop') == token:
                            stopping = True
                            clients.append(client)
                        else:
                            client.sendall(b'refused\n')
                            client.close()
                    except (ValueError, TimeoutError, OSError):
                        client.close()
            finally:
                # A live child remains our unreaped process-group leader, so a
                # stale PID file cannot cause this to signal somebody else's stack.
                if owns_descendants:
                    stop_descendants(child)
                elif child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                for client in clients:
                    try:
                        client.sendall(b'stopped\n')
                    except OSError:
                        pass
                    client.close()
                Path('control.sock').unlink(missing_ok=True)
                Path('token').unlink(missing_ok=True)
            if not stopping and child.returncode:
                raise SystemExit(child.returncode if child.returncode > 0 else 128-child.returncode)


if __name__ == '__main__':
    main()
