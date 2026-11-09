"""Select exact source providers for the disposable capture and owner restore."""
import hashlib
import importlib.util
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tomllib

HELPERS = ('snapshot.py', 'postgres-recovery.py')


def git(root, *arguments):
    return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
        '-c', 'core.fsmonitor=false', '-C', str(root), *arguments],
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, timeout=30)


def selected(root, repository, revision):
    root = Path(root).absolute()
    if (not re.fullmatch('[a-f0-9]{40}', revision)
            or any(path.is_symlink() for path in [root, *root.parents]) or not root.is_dir()):
        raise ValueError('native recovery requires immutable source directories without links')
    origins = {prefix + repository + suffix for prefix in
        ['https://github.com/', 'git@github.com:', 'ssh://git@github.com/'] for suffix in ['', '.git']}
    if (git(root, 'rev-parse', 'HEAD').decode().strip() != revision
            or git(root, 'remote', 'get-url', 'origin').decode().strip() not in origins):
        raise ValueError('native recovery source identity differs from its selected repository and revision')
    git(root, 'diff', '--quiet', 'HEAD', '--')
    return root


def source_file(root, revision, relative):
    if (not isinstance(relative, str) or not 0 < len(relative) <= 256 or '\0' in relative
            or PurePosixPath(relative).is_absolute() or '..' in PurePosixPath(relative).parts
            or str(PurePosixPath(relative)) != relative):
        raise ValueError('native recovery source must stay inside its selected repository')
    path = root / relative
    if any(item.is_symlink() for item in [path, *path.parents]) or not path.is_file() or not 0 < path.stat().st_size <= 4 << 20:
        raise ValueError('native recovery helper must be bounded regular source')
    body = git(root, 'show', revision + ':' + relative)
    if path.read_bytes() != body:
        raise ValueError('native recovery helper differs from its immutable Git source')
    return body


class Sources:
    def __init__(self, root, cookbook, tools, *, source, repository_id, tools_revision):
        self.root = selected(root, 'nicodes/komizo', source)
        if not isinstance(repository_id, str) or not re.fullmatch('[1-9][0-9]{0,19}', repository_id):
            raise ValueError('native capture requires its actual source repository identity')
        cookbook_revision = tomllib.loads(source_file(self.root, source, 'mise.toml').decode())['vars']['cookbook_ref']
        self.cookbook = selected(cookbook, 'nicodes/cookbook', cookbook_revision)
        actual_tools = tomllib.loads(source_file(self.cookbook, cookbook_revision, 'mise.toml').decode())['vars']['tools_ref']
        if actual_tools != tools_revision:
            raise ValueError('native capture provider does not select the accepted format-2 Tools source')
        self.tools = selected(tools, 'nicodes/tools', tools_revision)
        self.providers = {'cookbook_revision': cookbook_revision, 'tools_revision': tools_revision, 'core_revision': source}
        self.source = {'repository': 'nicodes/komizo', 'repository_id': repository_id, 'revision': source}
        self.helpers = {name: source_file(self.tools, tools_revision, 'helpers/' + name) for name in HELPERS}
        self.hashes = {name: hashlib.sha256(body).hexdigest() for name, body in self.helpers.items()}

    def bundle(self, directory, recipient):
        program = directory / 'capture-pgbox.bundle'
        home = directory / 'bundle-home'; home.mkdir(mode=0o700)
        script = ('import sys;sys.path.insert(0,sys.argv[1]);import backup_bundle;'
            'backup_bundle.build(sys.argv[2],"pgbox","tests/fixtures/native_host/pg-capture.py",'
            '__import__("pathlib").Path(sys.argv[3]),__import__("pathlib").Path(sys.argv[4]))')
        subprocess.run([sys.executable, '-I', '-B', '-c', script, str(self.cookbook / 'cookbook'),
            str(self.root), str(recipient), str(program)], check=True, timeout=60,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(home), 'TOOLS_ROOT': str(self.tools)})
        return program

    def snapshot(self):
        for name, original in self.helpers.items():
            if source_file(self.tools, self.providers['tools_revision'], 'helpers/' + name) != original:
                raise ValueError('native owner recovery source changed after capture preparation')
        spec = importlib.util.spec_from_file_location('native_owner_snapshot', self.tools / 'helpers/snapshot.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def profile(self, name):
        return {'profile': name, 'source': self.source, 'providers': self.providers, 'backup_helpers': self.hashes}
