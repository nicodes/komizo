#!/usr/bin/env python3
"""Default commands for a Go application with its main package at the root."""
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main(stage):
    output = Path('.artifacts/build')
    for path in [output.parent, output]:
        if path.is_symlink():
            raise ValueError('build output must stay inside this checkout')
    if stage == 'lint':
        formatted = subprocess.check_output(['gofmt', '-l', '.'], text=True)
        if formatted.strip():
            raise ValueError('run gofmt on: ' + formatted.strip())
        subprocess.run(['go', 'vet', './...'], check=True)
    elif stage == 'build':
        output.mkdir(parents=True, exist_ok=True)
        subprocess.run(['go', 'build', '-trimpath', '-o', str(output/'app'), '.'], check=True)
    elif stage == 'artifact-check':
        executable = output/'app'
        if executable.is_symlink() or not executable.is_file() or executable.stat().st_size == 0 or not os.access(executable, os.X_OK):
            raise ValueError('a nonempty executable build artifact is required')
    elif stage == 'clean':
        if output.exists():
            shutil.rmtree(output)
    else:
        raise ValueError('unknown Go recipe operation')


if __name__ == '__main__':
    main(sys.argv[1])
