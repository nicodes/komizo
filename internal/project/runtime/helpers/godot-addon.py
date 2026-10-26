#!/usr/bin/env python3
"""Owned Godot runtime and standard project stages for an addon recipe."""
import os
from pathlib import Path
import shutil
import subprocess
import sys


def run(stage):
    if stage not in {'install', 'lint', 'unit', 'build', 'artifact-check', 'clean'}:
        raise ValueError('unsupported addon recipe stage')
    root = Path.cwd()
    artifacts = root/'.artifacts'
    if artifacts.is_symlink():
        raise ValueError('addon tooling must stay inside the checkout')
    environment = dict(os.environ, GODOT_BIN=str(artifacts/'godot/bin/godot'),
                       XDG_DATA_HOME=str(artifacts/'godot-data'),
                       PATH=str(artifacts/'godot/bin')+os.pathsep+os.environ.get('PATH', ''))
    if stage == 'install':
        subprocess.run([sys.executable, str(Path(__file__).with_name('godot-setup.py')),
                        '--version', '4.7.2', '--expected-version', '4.7.2.stable.official.ed1daf0bf',
                        '--binary-checksum', 'sha256:cadd3204e728a35d3f13adb7fd0d7902636b79f6b95c40c265eb73b6c35329e4',
                        '--root', str(artifacts/'godot'), '--origin', 'godot-builds', '--templates',
                        '--templates-checksum', 'sha256:f298490b8d44d934be425a5a65a51bf15f422428b229a06a6e11d9ffea248011'],
                       env=environment, check=True)
    elif stage == 'clean':
        for path in (artifacts, root/'dist'):
            if path.is_symlink():
                raise ValueError('addon output must stay inside the checkout')
            if path.exists():
                shutil.rmtree(path)
    else:
        subprocess.run(['bash', 'scripts/'+stage+'.sh'], env=environment, check=True)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise ValueError('one addon recipe stage is required')
    run(sys.argv[1])
