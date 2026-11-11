#!/usr/bin/env python3
"""Enable the disposable Alpine guest's existing AppArmor LSM before testing."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path('/root/native-host')


def prepare():
    # This changes only the disposable test disk, before Komizo installation.
    # Refuse an unfamiliar loader rather than claiming an enforcing guest.
    candidates = [p for p in [Path('/boot/limine.conf'), Path('/boot/limine/limine.conf')]
                  if p.is_file() and not p.is_symlink()]
    if len(candidates) != 1:
        raise ValueError('signed Alpine fixture has an unsupported Limine configuration')
    path = candidates[0]
    before = path.read_bytes()
    if len(before) > 65536:
        raise ValueError('fixture boot configuration exceeds its bound')
    active = Path('/sys/kernel/security/lsm').read_text().strip().split(',')
    if not active or any(not re.fullmatch('[a-z_]+', name) for name in active):
        raise ValueError('disposable kernel LSM inventory is unavailable')
    selected = [name for name in active if name != 'capability']
    if 'apparmor' not in selected: selected.append('apparmor')
    lines = before.decode().splitlines()
    count = 0
    for i, line in enumerate(lines):
        if not re.match(r'\s*cmdline\s*:', line, re.I):
            continue
        prefix, value = line.split(':', 1)
        words = value.split()
        if any(w.startswith(('lsm=', 'security=', 'apparmor=', 'cgroup_no_v1=')) for w in words):
            raise ValueError('fixture has an unexplained LSM or cgroup override')
        lines[i] = prefix + ': ' + ' '.join(words + [
            'lsm='+','.join(selected), 'apparmor=1', 'security=apparmor', 'cgroup_no_v1=all'])
        count += 1
    if not count:
        raise ValueError('fixture Limine configuration has no Linux command line')
    path.write_text('\n'.join(lines) + '\n')
    with Path('/etc/rc.conf').open('a') as output:
        output.write('\n# Disposable native acceptance requires unified cgroups.\nrc_cgroup_mode="unified"\n')
    subprocess.run(['rc-update', 'add', 'cgroups', 'boot'], check=True, timeout=15)
    subprocess.run(['rc-update', 'add', 'apparmor', 'boot'], check=True, timeout=15)
    (ROOT/'alpine-boot-preparation.json').write_text(json.dumps({
        'kind': 'komizo.disposable-alpine-boot', 'version': 1,
        'path': str(path), 'before_sha256': hashlib.sha256(before).hexdigest(),
        'after_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'kernel_upgraded': False, 'requires_real_reboot': True}, sort_keys=True) + '\n')


if __name__ == '__main__':
    prepare()
