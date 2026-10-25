#!/usr/bin/env python3
"""Build and test the exact Caddy source in disposable local storage."""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

source = Path(__file__).resolve().parent
# Resolve the selected compiler before entering scratch: a mise shim there
# otherwise selects the user's global compiler instead of this repository's pin.
go_root = subprocess.check_output(['go', 'env', 'GOROOT'], text=True).strip()
compiler_environment = {**os.environ, 'PATH': str(Path(go_root)/'bin')+os.pathsep+os.environ['PATH']}
# Scratch has no VCS checkout. Do not inherit metadata from an unrelated
# parent directory; module checksums and selected compiler bind this fixture.
compiler_environment['GOFLAGS'] = os.environ.get('GOFLAGS', '') + ' -buildvcs=false'
selected_version = subprocess.check_output([str(Path(go_root)/'bin/go'), 'version'], text=True).split()[2]
with tempfile.TemporaryDirectory(prefix='caddy-engineering-') as directory:
    root = Path(directory)
    for original, target in [('caddy.go.mod', 'go.mod'), ('caddy.go.sum', 'go.sum'), ('caddy-main.go', 'main.go')]:
        shutil.copyfile(source/original, root/target)
    subprocess.run(['sh', str(source/'caddy-build.sh'), '--test'], cwd=root, env=compiler_environment, check=True, timeout=900)
    built_version = subprocess.check_output([str(Path(go_root)/'bin/go'), 'version', '-m', str(root/'caddy')],
                                            text=True).splitlines()[0].split()[-1]
    if built_version != selected_version:
        raise ValueError('Caddy was built with a different compiler from the selected toolchain')
    spec = importlib.util.spec_from_file_location('image_scan', source/'scan-image.py')
    scanner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scanner)
    report = subprocess.check_output(['govulncheck', '-mode=binary', '-json', str(root/'caddy')], text=True, timeout=600)
    verdict = scanner.judge_report(report)
    if verdict['reached']:
        raise ValueError(f'Caddy has vulnerable linked symbols: {verdict["reached"]}')
    print('Caddy: upstream race tests and live binary vulnerability scan passed.')
