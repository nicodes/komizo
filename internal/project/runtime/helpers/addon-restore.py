#!/usr/bin/env python3
"""Restore caller-pinned GitHub addon archives; product verifiers remain authoritative."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import urllib.request
import zipfile
import os


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        redirected = super().redirect_request(request, fp, code, message, headers, url)
        if redirected:
            redirected.remove_header('Authorization')
        return redirected


def extract(archive, directory):
    with zipfile.ZipFile(archive) as source:
        seen = set()
        for entry in source.infolist():
            path = PurePosixPath(entry.filename)
            if (not entry.filename or '\\' in entry.filename or path.is_absolute() or
                    '..' in path.parts or str(path) in seen or
                    stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError('Unsafe or duplicate addon archive entry')
            seen.add(str(path))
        source.extractall(directory)


def restore(project, download=None):
    project = Path(project).resolve()
    manifest = json.loads((project/'gdam.json').read_text())['addons']
    lock = json.loads((project/'addon-provenance.json').read_text())
    if set(manifest) != set(lock):
        raise ValueError('Addon manifest and provenance must agree')
    addons = project/'addons'
    if addons.is_symlink():
        raise ValueError('Refusing linked addon root')
    addons.mkdir(exist_ok=True)
    for name, entry in lock.items():
        if not re.fullmatch(r'@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', name):
            raise ValueError('Invalid addon repository')
        if manifest[name]['tag'] != entry['tag'] or not re.fullmatch(r'[a-f0-9]{64}', entry['asset_sha256']):
            raise ValueError('Unreviewed addon release')
        if type(entry['asset_id']) is not int or entry['asset_id'] <= 0:
            raise ValueError('Expected exact release asset ID')
        with tempfile.TemporaryDirectory(prefix='addon-restore-') as directory:
            temporary = Path(directory)
            archive = temporary/'release.zip'
            url = f"https://api.github.com/repos/{name[1:]}/releases/assets/{entry['asset_id']}"
            if download:
                download(url, archive)
            else:
                headers = {'Accept': 'application/octet-stream', 'User-Agent': 'reviewed-addon-restore'}
                if os.environ.get('GITHUB_TOKEN'):
                    headers['Authorization'] = 'Bearer '+os.environ['GITHUB_TOKEN']
                opener = urllib.request.build_opener(Redirect())
                with opener.open(urllib.request.Request(url, headers=headers), timeout=120) as response:
                    with archive.open('wb') as output:
                        shutil.copyfileobj(response, output)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != entry['asset_sha256']:
                raise ValueError('Addon archive digest mismatch')
            staged = temporary/'unpacked'; staged.mkdir()
            extract(archive, staged)
            destination = addons/name.replace('/', '_')
            if destination.is_symlink():
                raise ValueError('Refusing linked addon destination')
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(staged, destination)
            print(f"Restored {name}@{entry['tag']} from reviewed asset {entry['asset_id']}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project')
    restore(parser.parse_args().project)
