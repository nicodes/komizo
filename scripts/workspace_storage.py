#!/usr/bin/env python3
"""Bounded disk admission and reviewable cleanup of owned generated output."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

ALLOWED = re.compile(r'(?:[\w.-]+/)*node_modules|(?:[\w.-]+/)*(?:bin|dist)|\.artifacts/(?:venv|build)(?:/[\w.-]+)*')
MAX_FILES = 250000
MAX_BYTES = 5 << 30

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def admission(path, reserve_bytes, reserve_inodes):
    path = Path(path).absolute()
    while not path.exists():
        path = path.parent
    info = os.statvfs(path)
    result = {'path': str(path), 'available_bytes': info.f_bavail * info.f_frsize,
              'available_inodes': info.f_favail, 'reserve_bytes': reserve_bytes,
              'reserve_inodes': reserve_inodes, 'uses_reserved_root_blocks': False}
    result['accepted'] = result['available_bytes'] >= reserve_bytes and result['available_inodes'] >= reserve_inodes
    return result

def mounts():
    result = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        value = line.split()[4]
        value = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)
        result.append(Path(value))
    return result

def active(path):
    checked = 0
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():
            continue
        for link in ('cwd', 'exe'):
            try:
                value = (process/link).resolve(strict=True)
                if value == path or path in value.parents:
                    return True
            except (FileNotFoundError, ProcessLookupError):
                pass
            except PermissionError:
                raise ValueError('active process ownership cannot be inspected') from None
        try:
            for fd in (process/'fd').iterdir():
                checked += 1
                if checked > 100000:
                    raise ValueError('active descriptor inventory exceeded its bound')
                try:
                    value=fd.resolve(strict=True)
                    if value==path or path in value.parents:return True
                except (FileNotFoundError,ProcessLookupError):pass
        except (FileNotFoundError,ProcessLookupError):pass
        except PermissionError:
            raise ValueError('active descriptors cannot be inspected') from None
    return False

def inventory(root, relative):
    if not ALLOWED.fullmatch(relative) or '..' in Path(relative).parts:
        raise ValueError('cleanup accepts only declared generated output, never evidence or authority')
    path = root / relative
    if path.is_symlink() or not path.is_dir():
        raise ValueError('generated output must be an owned real directory')
    for parent in path.parents:
        if parent == root.parent:
            break
        if parent.is_symlink():
            raise ValueError('symlinked output ancestry refused')
    if any(m == path or path in m.parents for m in mounts()):
        raise ValueError('mounted output must be unmounted before cleanup')
    if active(path):
        raise ValueError('output is still used by a running process')
    tracked = subprocess.check_output(['git', '--literal-pathspecs', 'ls-files', '-z', '--', relative], cwd=root, timeout=10)
    if tracked:
        raise ValueError('tracked source or shipped output cannot be cleaned')
    entries = []
    total = 0
    deadline = time.monotonic()+60
    base = path.lstat()
    for directory, dirs, files in os.walk(path, followlinks=False):
        for name in sorted(dirs+files):
            item = Path(directory)/name
            info = item.lstat()
            if info.st_uid != os.geteuid() or info.st_dev != base.st_dev:
                raise ValueError('foreign ownership or filesystem refused')
            if len(entries) >= MAX_FILES or time.monotonic() > deadline:
                raise ValueError('cleanup inventory exceeded its bound')
            record = {'path': str(item.relative_to(path)), 'mode': info.st_mode, 'inode': info.st_ino}
            if stat.S_ISLNK(info.st_mode):
                record['link'] = os.readlink(item)  # unlinking never follows it
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                if total > MAX_BYTES:
                    raise ValueError('cleanup byte inventory exceeded its bound')
                checksum = hashlib.sha256()
                with item.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1 << 20), b''):
                        checksum.update(chunk)
                after = item.lstat()
                if (after.st_size, after.st_mtime_ns, after.st_ino) != (info.st_size, info.st_mtime_ns, info.st_ino):
                    raise ValueError('output changed during review')
                record.update(size=info.st_size, sha256=checksum.hexdigest())
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError('special files refused')
            entries.append(record)
    if base.st_uid != os.geteuid():
        raise ValueError('foreign output owner')
    return {'path': relative, 'device': base.st_dev, 'inode': base.st_ino,
            'owner': base.st_uid, 'bytes': total, 'files': len(entries),
            'inventory_sha256': digest(sorted(entries, key=lambda r:r['path']))}

def plan(root, paths):
    root = Path(root).absolute()
    if root.is_symlink() or not (root/'.git').is_file():
        raise ValueError('cleanup requires an isolated Git worktree')
    if len(paths)>32 or len(set(paths)) != len(paths):
        raise ValueError('cleanup needs at most 32 distinct output paths')
    if any(Path(a) in Path(b).parents for a in paths for b in paths if a != b):
        raise ValueError('overlapping output paths refused')
    return {'version':1, 'root':str(root), 'paths':[inventory(root,p) for p in paths]}

def clean(manifest, expected):
    raw = Path(manifest).read_bytes()
    if len(raw)>65536:
        raise ValueError('cleanup manifest exceeds its bound')
    reviewed = json.loads(raw)
    if set(reviewed) != {'version','root','paths'} or reviewed['version'] != 1 or digest(reviewed) != expected:
        raise ValueError('cleanup review digest differs')
    current = plan(reviewed['root'], [p['path'] for p in reviewed['paths']])
    if current != reviewed:
        raise ValueError('output changed since review; nothing removed')
    removed=[]
    for row in current['paths']:
        path=Path(current['root'])/row['path']
        # All destinations have been reviewed before the first removal.
        shutil.rmtree(path)
        removed.append({'path':row['path'],'bytes':row['bytes']})
    return {'version':1,'review_sha256':expected,'removed':removed,'shared_cache_pruned':False}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='operation',required=True)
    check=sub.add_parser('check');check.add_argument('--path',required=True);check.add_argument('--reserve-bytes',type=int,default=64<<20);check.add_argument('--reserve-inodes',type=int,default=1024)
    review=sub.add_parser('plan');review.add_argument('--root',required=True);review.add_argument('--path',action='append',required=True)
    apply=sub.add_parser('clean');apply.add_argument('--manifest',required=True);apply.add_argument('--expected-plan',required=True)
    args=p.parse_args(argv)
    try:
        if args.operation=='check':
            if args.reserve_bytes<0 or args.reserve_inodes<0:raise ValueError('storage reserves cannot be negative')
            result=admission(args.path,args.reserve_bytes,args.reserve_inodes);print(json.dumps(result,sort_keys=True));return int(not result['accepted'])
        if args.operation=='plan':
            result=plan(args.root,args.path);print(json.dumps({'plan':result,'sha256':digest(result)},sort_keys=True));return 0
        print(json.dumps(clean(args.manifest,args.expected_plan),sort_keys=True));return 0
    except (OSError,ValueError,subprocess.SubprocessError):
        print(json.dumps({'accepted':False,'reason':'storage operation refused; inspect ownership, active use, mounted/tracked paths and review identity'}));return 1

if __name__=='__main__':
    raise SystemExit(main())
