#!/usr/bin/env python3
"""Execute a caller-owned engineering contract without application knowledge."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import datetime
import sys

CONTEXT_KEYS = ('GITHUB_SERVER_URL', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID',
                'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'GITHUB_SHA',
                'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA', 'GITHUB_EVENT_NAME')
CONFIG_FILES = ('komizo.json', 'komizo.lock')


def checkout_binding():
    tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True, timeout=10).strip()
    clean = subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], timeout=30).returncode
    if clean not in (0, 1):
        raise ValueError('cannot determine tracked source state')
    return {'source_tree': tree, 'tracked_source_clean': clean == 0,
            'configuration_sha256': {name: sha(Path(name)) for name in CONFIG_FILES if Path(name).is_file()}}


def execution_context():
    return {key: os.environ[key] for key in CONTEXT_KEYS if os.environ.get(key)}


STAGES = ('install', 'lint', 'unit', 'integration', 'build', 'artifact-check',
          'browser-install', 'e2e', 'vuln', 'dev', 'stop', 'clean')
GROUPS = {'test': ('unit', 'integration'),
          'check': ('lint', 'unit', 'integration', 'build', 'artifact-check', 'vuln', 'browser-install', 'e2e')}


def default_manifest():
    return Path(os.environ.get('KOMIZO_CONTRACT', 'komizo.json'))


def load(file):
    data = json.loads(file.read_text())
    if type(data.get('version')) is not int or data.get('version') != 1 or set(data.get('stages', {})) != set(STAGES):
        raise ValueError('contract v1 must explicitly declare every stage')
    for stage, value in data['stages'].items():
        if isinstance(value, dict) and set(value) == {'inapplicable'} and isinstance(value['inapplicable'], str) and value['inapplicable'].strip():
            continue
        if not isinstance(value, list) or not value:
            raise ValueError(f'{stage}: supply commands or an explicit inapplicable reason')
        for command in value:
            if not isinstance(command, list) or not command or not all(isinstance(v, str) and v for v in command):
                raise ValueError(f'{stage}: commands must be nonempty argument arrays')
    source_only = (data.get('source_only_build') is True and not data.get('images')
                   and isinstance(data['stages']['artifact-check'], dict))
    if isinstance(data['stages']['build'], list) and not data.get('artifacts') and not source_only:
        raise ValueError('build must declare artifact paths')
    if not isinstance(data.get('artifacts', []), list):
        raise ValueError('artifact paths must be a list')
    for pattern in data.get('artifacts', []):
        if not isinstance(pattern, str) or Path(pattern).is_absolute() or '..' in Path(pattern).parts:
            raise ValueError('artifact paths must stay within the checkout')
    for name in data.get('build_environment', []):
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*', name):
            raise ValueError('invalid build environment key')
    for name in data.get('revision_environment', []):
        if name not in data.get('build_environment', []):
            raise ValueError('revision environment keys must be declared build inputs')
    if not set(data.get('build_environment_defaults', {})) <= set(data.get('build_environment', [])):
        raise ValueError('environment defaults must be declared build inputs')
    return data


def resolve_images(data, revision):
    resolved = []
    for reference in data.get('images', []):
        def substitute(match):
            name = match[1]
            if name == 'revision':
                return revision
            if name not in data.get('build_environment', []):
                raise ValueError('image template uses an undeclared environment key')
            value = os.environ.get(name) or data.get('build_environment_defaults', {}).get(name)
            if not isinstance(value, str) or not value:
                raise ValueError('image template requires a build input')
            return value
        reference = re.sub(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', substitute, reference)
        if not re.fullmatch(r'[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9][a-z0-9/._-]*:[a-f0-9]{40}', reference):
            raise ValueError('build image must bind a valid namespace and exact revision')
        resolved.append(reference)
    return resolved


def sha(file):
    with file.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(data):
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    paths = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard']).split(b'\0')
    files = {}
    for raw in paths:
        if not raw:
            continue
        path = Path(os.fsdecode(raw))
        # Outputs must not turn their own build into a cache miss.
        if any(path.match(pattern) or str(path).startswith(pattern.rstrip('/') + '/') for pattern in data['artifacts']):
            continue
        if path.is_symlink():
            files[str(path)] = {'link': os.readlink(path)}
        elif path.is_file():
            files[str(path)] = {'sha256': sha(path), 'executable': bool(path.stat().st_mode & 0o111)}
        else:
            files[str(path)] = None
    environment = {name: os.environ.get(name, '') for name in data.get('build_environment', [])}
    # Store a hash, never environment values (which can contain credentials).
    return hashlib.sha256(json.dumps({'revision': head, 'files': files,
        'environment': environment, 'variant': os.environ.get('BUILD_VARIANT', 'production'),
        'contract': data}, sort_keys=True).encode()).hexdigest()


def artifacts(data):
    found = {}
    for pattern in data['artifacts']:
        matches = sorted(Path('.').glob(pattern))
        files = []
        for match in matches:
            files.extend(sorted(match.rglob('*')) if match.is_dir() else [match])
        regular = [file for file in files if file.is_file()]
        if not regular:
            raise ValueError(f'build artifact missing: {pattern}')
        for file in regular:
            if file.is_symlink() or any(parent.is_symlink() for parent in file.parents):
                raise ValueError(f'build artifact is a symlink: {file}')
            found[str(file)] = sha(file)
    images = data.get('images', [])
    if images:
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        refs = resolve_images(data, revision)
        inspected = json.loads(subprocess.check_output(['docker', 'image', 'inspect', *refs], timeout=60))
        if len(inspected) != len(refs):
            raise ValueError('missing build image')
        for ref, image in zip(refs, inspected, strict=True):
            if ref not in image.get('RepoTags', []) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image.get('Id', '')):
                raise ValueError('invalid build image identity')
            found['image:'+ref] = image['Id']
    return found


class Runner:
    def __init__(self, data):
        self.data = data
        self.done = set()
        self.test_receipts = {}
        self.root = Path('.artifacts/contract')
        self.root.mkdir(parents=True, exist_ok=True)
        self.source_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        (self.root/'failure.json').unlink(missing_ok=True)

    def timing(self, name, started, result=0, outcome='executed', adapter=None):
        """Best-effort telemetry must never replace an adapter's outcome."""
        record = {'stage': name, 'seconds': round(time.monotonic()-started, 3),
                  'exit_code': result, 'outcome': outcome,
                  'source_commit': self.source_commit,
                  'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'RUNNER_OS', 'RUNNER_ARCH'):
            if os.environ.get(key):
                record[key.lower()] = os.environ[key]
        if adapter is not None:
            record['adapter'] = adapter
        try:
            record['toolchain_config_sha256'] = sha(Path('komizo.lock')) if Path('komizo.lock').is_file() else None
            self.root.mkdir(parents=True, exist_ok=True)
            with (self.root/'timings.jsonl').open('a') as stream:
                stream.write(json.dumps(record)+'\n')
        except OSError as error:
            print(f'timing output unavailable: {error}', file=sys.stderr)

    def provenance(self, input_identity):
        def git(*args):
            return subprocess.check_output(['git', *args], text=True).strip()
        source = git('rev-parse', 'HEAD')
        applicable = {name for name in ('unit', 'integration')
                      if isinstance(self.data['stages'][name], list)}
        verified = {name for name, receipt in self.test_receipts.items()
                    if receipt['input_identity'] == input_identity and receipt['source_commit'] == source}
        return {'version': 1, 'source_commit': source,
                'source_tree': git('rev-parse', 'HEAD^{tree}'),
                'input_identity': input_identity,
                'tested_commit': source if applicable and applicable <= verified else None,
                'test_receipts': self.test_receipts.copy(),
                'build_variant': os.environ.get('BUILD_VARIANT', 'production'),
                'toolchain_config_sha256': sha(Path('komizo.lock')) if Path('komizo.lock').is_file() else None}

    def stage(self, name):
        if name in self.done:
            return
        if name in GROUPS:
            receipt = self.root/'test.json'
            receipt.unlink(missing_ok=True)
            for child in self.data.get('check_targets', GROUPS[name]) if name == 'check' else GROUPS[name]:
                self.stage(child)
            self.test_proof()
            self.done.add(name)
            return
        value = self.data['stages'].get(name, self.data.get('tasks', {}).get(name))
        if isinstance(value, dict):
            print(f'{name}: inapplicable: {value["inapplicable"]}', flush=True)
            self.timing(name, time.monotonic(), outcome='inapplicable')
            self.done.add(name)
            return
        if name in ('e2e', 'artifact-check'):
            self.stage('build')
        if name == 'e2e' or (name == 'artifact-check' and self.data.get('artifact_browser', False)):
            self.stage('browser-install')
        if name == 'build':
            revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
            for key in self.data.get('revision_environment', []):
                if os.environ.get(key) and os.environ[key] != revision:
                    raise ValueError('build revision input differs from the current checkout')
        if name == 'build' and os.environ.get('BUILD_VARIANT', 'production') != 'production':
            raise ValueError('this contract builds production artifacts; use separate fixture outputs for test variants')
        if name == 'build' and self.fresh():
            print('build: reusing artifacts verified against source, environment and image identities', flush=True)
            self.timing(name, time.monotonic(), outcome='verified-reuse')
            self.done.add(name)
            return
        started = time.monotonic()
        result = 0
        before = identity(self.data) if name in ('build', 'unit', 'integration') else None
        test_source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() if name in ('unit', 'integration') else None
        if name == 'build':
            (self.root/'build.json').unlink(missing_ok=True)
        try:
            for command in value:
                print(f'{name}: running adapter {command[0]}', flush=True)
                adapter_started = time.monotonic()
                adapter_result = 0
                try:
                    subprocess.run(command, check=True)
                except subprocess.CalledProcessError as error:
                    adapter_result = error.returncode
                    raise
                except KeyboardInterrupt:
                    adapter_result = 130
                    raise
                except BaseException:
                    adapter_result = 1
                    raise
                finally:
                    self.timing(name, adapter_started, adapter_result, adapter=Path(command[0]).name)
            if name in ('unit', 'integration') and identity(self.data) == before:
                self.test_receipts[name] = {'source_commit': test_source, 'input_identity': before}
            if name == 'build':
                if identity(self.data) != before:
                    raise ValueError('build modified source inputs outside declared artifacts')
                evidence = {'identity': before, 'artifacts': artifacts(self.data),
                            'provenance': self.provenance(before)}
                temporary = self.root/'build.json.tmp'
                temporary.write_text(json.dumps(evidence, sort_keys=True)+'\n')
                temporary.replace(self.root/'build.json')
            self.done.add(name)
        except BaseException as error:
            result = error.returncode if isinstance(error, subprocess.CalledProcessError) else 130 if isinstance(error, KeyboardInterrupt) else 1
            # A bounded, secret-free rerun instruction complements the retained
            # runner log. Never serialize environment values or command arguments.
            failure = {'version': 1, 'stage': name, 'exit_code': result,
                       'source_commit': self.source_commit,
                       'execution_context': execution_context(),
                       'rerun': [] if name in self.data.get('tasks', {}) else ['komizo', 'run', name],
                       'reconciliation_required': name in self.data.get('tasks', {}),
                       'timings': '.artifacts/contract/timings.jsonl'}
            try:
                (self.root/'failure.json').write_text(json.dumps(failure, sort_keys=True)+'\n')
            except OSError:
                print('Failure summary unavailable; preserve the runner log', file=sys.stderr)
            if name == 'build':
                (self.root/'build.json').unlink(missing_ok=True)
            raise
        finally:
            self.timing(name, started, result)

    def test_proof(self):
        applicable = {name for name in ('unit', 'integration') if isinstance(self.data['stages'][name], list)}
        if not applicable or not applicable <= set(self.test_receipts):
            return
        proof = self.provenance(identity(self.data))
        if proof['tested_commit'] is not None:
            proof.update(checkout_binding(), execution_context=execution_context())
            temporary = self.root/'test.json.tmp'
            temporary.write_text(json.dumps(proof, sort_keys=True)+'\n')
            temporary.replace(self.root/'test.json')

    def fresh(self):
        try:
            evidence = json.loads((self.root/'build.json').read_text())
            return (isinstance(evidence['provenance']['test_receipts'], dict)
                    and evidence['identity'] == identity(self.data)
                    and evidence['artifacts'] == artifacts(self.data))
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('targets', nargs='+')
    parser.add_argument('--manifest', type=Path, default=default_manifest())
    args = parser.parse_args()
    data = load(args.manifest)
    if any(target not in (*STAGES, *GROUPS, 'validate', 'help', *data.get('tasks', {})) for target in args.targets):
        parser.error('unknown project target')
    if any(target in ('help', 'validate') for target in args.targets) and len(args.targets) != 1:
        parser.error('help and validate must be used alone')
    if args.targets == ['validate']:
        print('engineering contract v1: valid')
    elif args.targets == ['help']:
        print('Project stages: '+', '.join((*STAGES, *GROUPS)))
    else:
        # Checkout-wide lock: concurrent verification commands cannot race
        # shared outputs. Put it outside cleanable artifacts to preserve ownership.
        git_dir = Path(subprocess.check_output(['git', 'rev-parse', '--git-path', 'engineering.lock'], text=True).strip())
        if any(target in ('dev', 'stop') for target in args.targets):
            if len(args.targets) != 1:
                parser.error('dev and stop must be used alone')
            Runner(data).stage(args.targets[0])
            return
        with git_dir.open('a') as lock:
            runner = Runner(data)
            for target in args.targets:
                if target in data.get('tasks', {}):
                    # Named tasks may compose verification commands. Their
                    # child stages acquire the same checkout lock themselves.
                    runner.stage(target)
                    continue
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    runner.stage(target)
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
            # A focused selection earns a test receipt only when this very
            # invocation actually completed every applicable test stage.
            # A pure named task has no verification receipt to issue. Taking
            # this lock would deadlock when its parent verification stage
            # already owns it, even after the task's actual work finished.
            if runner.test_receipts:
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    runner.test_proof()
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode if error.returncode >= 0 else 128-error.returncode)
