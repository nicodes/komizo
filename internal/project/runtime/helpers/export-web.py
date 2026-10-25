#!/usr/bin/env python3
"""Export Expo with a bounded process lifetime and require a successful exit."""
import argparse
from contextlib import contextmanager, nullcontext
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess


def inventory(directory):
    if directory.is_symlink():
        raise ValueError('compiler cache directory must not be a symlink')
    result = {}
    for path in sorted(directory.rglob('*')) if directory.exists() else []:
        if path.is_symlink():
            raise ValueError('compiler cache contains a symlink')
        if path.is_file():
            result[str(path.relative_to(directory))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


@contextmanager
def compiler_cache(app, output_name, root):
    root = Path(root).absolute()
    if root.is_symlink():
        raise ValueError('compiler cache root must not be a symlink')
    root.mkdir(parents=True, exist_ok=True)
    # Metro hashes source contents itself. Bind its namespace to every dependency,
    # compiler configuration and declared build variant, including test auth.
    inputs = {name: hashlib.sha256((app/name).read_bytes()).hexdigest()
              for name in ('bun.lock', 'package.json', 'metro.config.js', 'metro.config.cjs',
                           'babel.config.js', 'babel.config.cjs', 'app.json', 'app.config.js',
                           'app.config.ts', 'tsconfig.json', 'tailwind.config.js', 'tailwind.config.cjs',
                           'postcss.config.js', 'postcss.config.cjs') if (app/name).is_file()}
    for dotenv in app.glob('.env*'):
        if dotenv.is_symlink():
            raise ValueError('dotenv compiler input must not be a symlink')
        if dotenv.is_file():
            inputs[dotenv.name] = hashlib.sha256(dotenv.read_bytes()).hexdigest()
    declared = os.environ.get('FLEET_WEB_CACHE_ENV', '').split()
    if any(not re.fullmatch(r'[A-Z][A-Z0-9_]*', name) for name in declared):
        raise ValueError('cache environment declarations must be variable names')
    environment = {key: value for key, value in os.environ.items()
                   if key.startswith(('EXPO_', 'ENGINEERING_E2E_')) or
                   key in ('NODE_ENV', 'BABEL_ENV')}
    environment.update({name: os.environ.get(name) for name in declared})
    identity = {'format': 2, 'output': output_name, 'inputs': inputs,
                'environment': environment,
                'toolchain': hashlib.sha256((app.parent/'.mise.toml').read_bytes()).hexdigest()
                if (app.parent/'.mise.toml').is_file() else None}
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    cache = root/key
    if cache.is_symlink():
        raise ValueError('compiler cache namespace must not be a symlink')
    cache.mkdir(exist_ok=True)
    with (cache/'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = cache/'state.json'
        contents = cache/'metro-cache'
        if state.is_symlink():
            raise ValueError('compiler cache state must not be a symlink')
        if state.exists():
            record = json.loads(state.read_text())
            if record.get('identity_sha256') != key or record.get('files') != inventory(contents):
                raise ValueError('compiler cache differs from its successful export inventory')
        elif contents.exists():
            # A failed/interrupted export has no valid receipt. Discard only our
            # namespace's generated transforms before running the compiler again.
            inventory(contents)
            shutil.rmtree(contents)
        state.unlink(missing_ok=True)
        try:
            yield {'TMPDIR': str(cache), 'TMP': str(cache), 'TEMP': str(cache)}
            state.write_text(json.dumps({'identity_sha256': key,
                                        'files': inventory(contents)}, sort_keys=True)+'\n')
        except BaseException:
            state.unlink(missing_ok=True)
            raise


def export(app, output_name, timeout=900, command=None, cache_root=None):
    app = Path(app).resolve(strict=True)
    if output_name not in ('dist', 'dist-e2e', 'dist-check'):
        raise ValueError('output must be dist, dist-e2e, or dist-check inside the app')
    output = app / output_name
    if output.is_symlink():
        raise ValueError('export output must not be a symlink')
    if output.exists():
        shutil.rmtree(output)
    cache_root = cache_root or os.environ.get('FLEET_WEB_CACHE')
    context = compiler_cache(app, output_name, cache_root) if cache_root else nullcontext({})
    with context as cache_environment:
        process = subprocess.Popen(command or ['bun', 'x', '--no-install', 'expo', 'export',
            '--platform', 'web', '--output-dir', output_name, *([] if cache_root else ['--clear'])], cwd=app,
            env={**os.environ, 'CI': '1', **cache_environment}, start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        finally:
            # The unreaped leader owns this process group throughout a timeout.
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        if status:
            raise RuntimeError(f'Expo exited {status}; artifacts do not override a failed export')
        if not (output/'index.html').is_file() or not (output/'index.html').stat().st_size:
            raise RuntimeError('Expo did not produce a nonempty index.html')
        files = sorted(p for p in output.rglob('*') if p.is_file())
        if not any(p.suffix == '.js' for p in files):
            raise RuntimeError('Expo did not produce JavaScript assets')
        if any(p.is_symlink() for p in output.rglob('*')):
            raise RuntimeError('export contains a symlink')
        manifest = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        (output/'export-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        print(f'Validated {len(files)} exported files in {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', default='app')
    parser.add_argument('--output', default='dist')
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    export(args.app, args.output, args.timeout)
