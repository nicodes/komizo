#!/usr/bin/env python3
"""Install caller-pinned Linux x86_64 Godot archives; verify every cache hit."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request
import urllib.error
import time
import zipfile


def checksum(value):
    algorithm, separator, digest = value.partition(':')
    lengths = {'sha256': 64, 'sha512': 128}
    if not separator or algorithm not in lengths or not re.fullmatch('[0-9a-f]{'+str(lengths.get(algorithm, 0))+'}', digest):
        raise ValueError('checksum must be a reviewed sha256: or sha512: digest')
    return algorithm, digest


def verified(path, pin):
    algorithm, expected = checksum(pin)
    if not path.is_file():
        return False
    digest = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest() == expected


def fetch(url, destination, pin):
    checksum(pin)
    if verified(destination, pin):
        return 'hit'
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=destination.name+'.', dir=destination.parent)
    temporary = Path(name)
    try:
        os.close(descriptor)
        for attempt in range(3):
            try:
                with temporary.open('wb') as output, urllib.request.urlopen(url, timeout=60) as source:
                    shutil.copyfileobj(source, output)
                break
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if attempt == 2:
                    raise
                time.sleep(2)
        if not verified(temporary, pin):
            raise ValueError('download checksum mismatch: '+destination.name)
        temporary.replace(destination)
        return 'miss'
    finally:
        temporary.unlink(missing_ok=True)


def extract_templates(archive, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as source:
        entries = [item for item in source.infolist() if not item.is_dir()]
        names = set()
        for item in entries:
            path = Path(item.filename)
            if path.is_absolute() or '..' in path.parts or path.name in names or (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('unsafe or duplicate template archive entry')
            names.add(path.name)
        for item in entries:
            with source.open(item) as data, (destination/Path(item.filename).name).open('wb') as output:
                shutil.copyfileobj(data, output)


def install(version, binary_pin, templates_pin, templates, root, origin='godot', expected_version=None):
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or origin not in ('godot', 'godot-builds'):
        raise ValueError('unsupported version or release origin')
    checksum(binary_pin)
    if templates:
        checksum(templates_pin)
    archives = root/'archives'
    binary_name = f'Godot_v{version}-stable_linux.x86_64'
    base = f'https://github.com/godotengine/{origin}/releases/download/{version}-stable/'
    binary_archive = archives/(binary_name+'.zip')
    state = fetch(base+binary_archive.name, binary_archive, binary_pin)
    binary_directory = root/'bin'
    binary_directory.mkdir(parents=True, exist_ok=True)
    executable = binary_directory/'godot'
    with zipfile.ZipFile(binary_archive) as source:
        entry = source.getinfo(binary_name)
        with source.open(entry) as data, executable.open('wb') as output:
            shutil.copyfileobj(data, output)
    executable.chmod(0o755)
    actual = subprocess.check_output([str(executable), '--version'], text=True, timeout=30).strip()
    if (expected_version is not None and actual != expected_version) or not actual.startswith(version+'.stable.'):
        raise ValueError('installed binary version mismatch')
    if templates:
        archive = archives/f'Godot_v{version}-stable_export_templates.tpz'
        fetch(base+archive.name, archive, templates_pin)
        data = Path(os.environ.get('XDG_DATA_HOME', str(Path.home()/'.local/share')))
        extract_templates(archive, data/'godot/export_templates'/f'{version}.stable')
    if os.environ.get('GITHUB_PATH'):
        with open(os.environ['GITHUB_PATH'], 'a', encoding='utf-8') as stream:
            stream.write(str(binary_directory)+'\n')
    print(f'Godot {actual}; verified archive cache {state}')
    return executable


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--binary-checksum', required=True)
    parser.add_argument('--templates-checksum', default='')
    parser.add_argument('--templates', action='store_true')
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--origin', choices=['godot', 'godot-builds'], default='godot')
    parser.add_argument('--expected-version')
    args = parser.parse_args()
    install(args.version, args.binary_checksum, args.templates_checksum, args.templates, args.root.resolve(), args.origin, args.expected_version)
