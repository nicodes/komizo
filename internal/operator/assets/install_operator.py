"""Install the authenticated operator bundle; retain policy, grants and outcomes."""
import argparse
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

PATHS = {'fleet_operator.py': '/usr/local/libexec/fleet/fleet_operator.py',
         'fleet_broker.py': '/usr/local/libexec/fleet/fleet_broker.py',
         'fleet-operator.service': '/etc/systemd/system/fleet-operator.service',
         'fleet-operator.socket': '/etc/systemd/system/fleet-operator.socket'}
MAX_BYTES = 256 * 1024


def digest(body):
    return hashlib.sha256(body).hexdigest()


def safe_directory(path, owner, root=Path('/'), create=True):
    relative = path.relative_to(root)
    parents = [root]
    for part in relative.parts:
        parents.append(parents[-1]/part)
    for parent in parents:
        try:
            info = parent.lstat()
        except FileNotFoundError:
            if not create:
                continue
            parent.mkdir(mode=0o755)
            info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError('operator destination directory is not protected')


def read(path, owner):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022 or info.st_size > MAX_BYTES:
            raise ValueError('operator state is not a protected bounded regular file')
        body = stream.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError('operator state exceeds its bound')
        return body


def atomic(path, body, owner, mode=0o644, root=Path('/')):
    safe_directory(path.parent, owner, root)
    if path.is_symlink():
        raise ValueError('linked operator destination refused')
    descriptor, temporary = tempfile.mkstemp(prefix='.operator-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)


def service(*arguments):
    result = subprocess.run(['/usr/bin/systemctl', *arguments],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, cwd='/',
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, timeout=20)
    if result.returncode:
        raise ValueError('operator service transition refused; inspect installed status')


class Installation:
    def __init__(self, bundle, root=Path('/'), owner=0, control=service):
        if set(bundle) != set(PATHS):
            raise ValueError('operator bundle file set differs')
        self.bundle = bundle
        self.root, self.owner, self.control = root, owner, control
        self.files = {name: root/path.lstrip('/') for name, path in PATHS.items()}
        self.state = root/'var/lib/fleet-operator'

    def plan(self):
        for path in self.files.values():
            safe_directory(path.parent,self.owner,self.root,False)
        before = {name: read(path, self.owner) for name, path in self.files.items()}
        policy = read(self.root/'etc/fleet-operator.json', self.owner)
        environment = read(self.root/'etc/fleet-operator-broker', self.owner)
        if policy is None or environment is None:
            raise ValueError('configure the private operator scope and editor role before installation')
        value = {'version': 1, 'desired': {name: digest(body) for name, body in self.bundle.items()},
                 'before': {name: None if body is None else digest(body) for name, body in before.items()},
                 'policy_sha256': digest(policy), 'environment_sha256': digest(environment)}
        value['plan_sha256'] = digest(json.dumps(value, sort_keys=True).encode())
        return value

    def restore(self, previous):
        if self.files['fleet-operator.service'].exists():
            self.control('stop', 'fleet-operator.service')
        if self.files['fleet-operator.socket'].exists():
            self.control('stop', 'fleet-operator.socket')
        for name, body in previous.items():
            path = self.files[name]
            if body is None:
                path.unlink(missing_ok=True)
            else:
                atomic(path, body.encode(), self.owner, root=self.root)
        self.control('daemon-reload')
        if previous['fleet-operator.socket'] is not None:
            self.control('start', 'fleet-operator.socket')
        if previous['fleet-operator.service'] is not None:
            self.remove_old_socket(previous)
            self.control('start', 'fleet-operator.service')

    def remove_old_socket(self, previous):
        if previous['fleet-operator.socket'] is not None:
            return
        path=self.root/'run/fleet-operator/operator.sock'
        safe_directory(path.parent,self.owner,self.root,False)
        try:
            info=path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=self.owner:
            raise ValueError('abandoned operator endpoint is not an owned socket')
        path.unlink()

    def apply(self, expected):
        if self.plan()['plan_sha256'] != expected:
            raise ValueError('installed operator changed after the reviewed plan')
        safe_directory(self.state, self.owner, self.root)
        os.chmod(self.state, 0o700)
        previous = {name: None if (body := read(path, self.owner)) is None else body.decode()
                    for name, path in self.files.items()}
        record = {'version': 1, 'plan': self.plan(), 'previous': previous, 'status': 'prepared'}
        journal = self.state/'installation.json'
        old = read(journal, self.owner)
        if old is not None and json.loads(old)['status'] == 'prepared':
            raise ValueError('previous installation is incomplete; recover it before applying')
        atomic(journal, json.dumps(record, sort_keys=True).encode(), self.owner, 0o600, self.root)
        # The service manager kills the exact broker control group. Claimed
        # grants remain ambiguous and are inspected separately, never replayed.
        try:
            if previous['fleet-operator.service'] is not None:
                self.control('stop', 'fleet-operator.service')
            if previous['fleet-operator.socket'] is not None:
                self.control('stop', 'fleet-operator.socket')
            self.remove_old_socket(previous)
            for name, body in self.bundle.items():
                atomic(self.files[name], body, self.owner, root=self.root)
            self.control('daemon-reload')
            self.control('start', 'fleet-operator.socket')
            self.control('start', 'fleet-operator.service')
            self.control('is-active', 'fleet-operator.socket', 'fleet-operator.service')
        except (OSError, ValueError, subprocess.SubprocessError):
            self.restore(previous)
            record['status'] = 'recovered'
            atomic(journal, json.dumps(record, sort_keys=True).encode(), self.owner, 0o600, self.root)
            raise
        record['status'] = 'completed'
        atomic(journal, json.dumps(record, sort_keys=True).encode(), self.owner, 0o600, self.root)
        return self.plan()

    def recover(self):
        body = read(self.state/'installation.json', self.owner)
        if body is None:
            raise ValueError('no retained operator installation is available')
        record = json.loads(body)
        if record.get('version') != 1 or set(record.get('previous', {})) != set(PATHS):
            raise ValueError('invalid protected installation journal')
        current = self.plan()
        if any(current[key] != record['plan'][key] for key in ('policy_sha256','environment_sha256')):
            raise ValueError('operator authority changed; reconcile it before restoring old code')
        self.restore(record['previous'])
        record['status'] = 'recovered'
        atomic(self.state/'installation.json', json.dumps(record, sort_keys=True).encode(), self.owner, 0o600, self.root)
        return self.plan()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('verb', choices=('plan', 'apply', 'status', 'recover'))
    parser.add_argument('--expected-plan', default='')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('operator installation requires the root operator')
    grp.getgrnam('fleet-editor')
    import sys
    wire = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(wire) > MAX_BYTES:
        raise ValueError('operator bundle exceeds its bound')
    bundle = {name: body.encode() for name, body in json.loads(wire).items()}
    # Validate the existing private scope against the new authenticated source
    # before stopping a service or writing an installation journal.
    namespace = {'__name__': 'authenticated_operator', '__file__': '/usr/local/libexec/fleet/fleet_operator.py'}
    exec(compile(bundle['fleet_operator.py'], '<authenticated-operator>', 'exec'), namespace)
    namespace['private_policy'](Path('/etc/fleet-operator.json'))
    installation = Installation(bundle)
    if args.verb in ('plan', 'status'):
        result = installation.plan()
        if args.verb == 'status':
            installation.control('is-active', 'fleet-operator.socket', 'fleet-operator.service')
    else:
        safe_directory(installation.state, 0)
        descriptor = os.open(installation.state/'installation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'r+'):
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = installation.apply(args.expected_plan) if args.verb == 'apply' else installation.recover()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        import sys
        print('operator installation refused: '+str(error), file=sys.stderr)
        raise SystemExit(1)
