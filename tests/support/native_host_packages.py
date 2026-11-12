#!/usr/bin/env python3
"""Install a complete immutable public APK input inside the signed test guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request

ROOT = Path('/root/native-host')
MAX_ARCHIVE = 512 << 20
MAX_DOCUMENT = 64 << 10


def require(value, message):
    if not value:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, 'duplicate package input field')
        result[name] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def input_record(value):
    require(type(value) is dict and set(value) == {'image', 'requested_packages', 'closure'},
            'unexpected package input shape')
    closure = value['closure']
    require(type(closure) is dict and set(closure) == {'archive', 'manifest', 'apk_count', 'trusted_keys'},
            'unexpected immutable closure shape')
    require(type(closure['apk_count']) is int and 0 < closure['apk_count'] <= 2048,
            'invalid finite package inventory')
    for name, maximum in [('archive', MAX_ARCHIVE), ('manifest', MAX_DOCUMENT)]:
        record = closure[name]
        require(type(record) is dict and set(record) == {'url', 'sha256', 'size_bytes'},
                'unexpected immutable download binding')
        url = urllib.parse.urlsplit(record['url'])
        expected_name = 'alpine-packages.tar' if name == 'archive' else 'alpine-packages.json'
        require(url.scheme == 'https' and url.netloc == 'github.com' and not url.query and not url.fragment
                and re.fullmatch(r'/nicodes/komizo/releases/download/native-alpine-3\.24\.3-x86_64-[a-f0-9]{12}/'
                                 + re.escape(expected_name), url.path), 'unreviewed package input URL')
        require(type(record['sha256']) is str and re.fullmatch('[a-f0-9]{64}', record['sha256'])
                and type(record['size_bytes']) is int and 0 < record['size_bytes'] <= maximum,
                'invalid immutable download hash or bound')
    keys = closure['trusted_keys']
    require(type(keys) is dict and 0 < len(keys) <= 8
            and all(re.fullmatch(r'alpine-devel@lists\.alpinelinux\.org-[a-f0-9]{8}\.rsa\.pub', name)
                    and type(sha) is str and re.fullmatch('[a-f0-9]{64}', sha) for name, sha in keys.items()),
            'invalid official APK key inventory')
    requested = value['requested_packages']
    require(type(requested) is list and 0 < len(requested) <= 128 and len(set(requested)) == len(requested)
            and all(type(item) is str and re.fullmatch(r'[a-z0-9][a-z0-9+_.-]*(?:=[a-zA-Z0-9+_.-]+)?', item)
                    for item in requested), 'invalid original requested package inventory')
    require(type(value['image']) is dict and value['image'].get('signing_fingerprint')
            and value['image'].get('sha512'), 'signed image identity missing')
    return value


def fetch(record, path, deadline):
    """No credentials, unverified TLS, mutable repository, or partial-file reuse."""
    count = 0
    sha = hashlib.sha256()
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'package input download deadline expired')
    with urllib.request.urlopen(record['url'], timeout=min(30, remaining)) as incoming, path.open('xb') as output:
        final = urllib.parse.urlsplit(incoming.geturl())
        require(final.scheme == 'https' and final.hostname in {
            'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
            and final.username is None and final.password is None and not final.fragment,
            'package input redirect escaped GitHub HTTPS')
        while chunk := incoming.read(1 << 20):
            count += len(chunk)
            require(count <= record['size_bytes'] and time.monotonic() < deadline,
                    'package input download exceeds its admitted bound')
            sha.update(chunk)
            output.write(chunk)
    require(count == record['size_bytes'] and sha.hexdigest() == record['sha256'],
            'immutable package input bytes differ')


def manifest_record(raw, config):
    require(len(raw) == config['closure']['manifest']['size_bytes']
            and digest(raw) == config['closure']['manifest']['sha256'], 'package manifest bytes differ')
    manifest = decode(raw)
    require(type(manifest) is dict and set(manifest) == {
        'image', 'kind', 'production_host_packages_changed', 'requested_packages',
        'sha256', 'signature_verification', 'size_bytes', 'version'}, 'package manifest shape differs')
    require(manifest['kind'] == 'komizo.alpine-public-package-closure' and type(manifest['version']) is int
            and manifest['version'] == 1 and manifest['production_host_packages_changed'] is False
            and manifest['image'] == config['image']
            and manifest['requested_packages'] == config['requested_packages']
            and manifest['sha256'] == config['closure']['archive']['sha256']
            and manifest['size_bytes'] == config['closure']['archive']['size_bytes']
            and manifest['signature_verification'] == 'apk add --no-network with trusted distro keys',
            'package closure escaped its original signed image, pins or accepted capture')
    return manifest


def ordinary(path, maximum):
    require(not any(p.is_symlink() for p in [path, *path.parents]), 'linked package input')
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
            and 0 < before.st_size <= maximum and not before.st_mode & 0o022, 'unsafe package input file')
    with path.open('rb') as source:
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    require(len(raw) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'package input changed during read')
    return raw


def archive_record(path, config, official_keys):
    """Verify the whole archive and every member before extracting any member."""
    expected = config['closure']['archive']
    with path.open('rb') as source:
        require(path.stat().st_size == expected['size_bytes']
                and hashlib.file_digest(source, 'sha256').hexdigest() == expected['sha256'],
                'package archive bytes differ')
    keys = config['closure']['trusted_keys']
    require(not official_keys.is_symlink() and official_keys.is_dir()
            and {p.name for p in official_keys.iterdir()} == set(keys), 'signed image APK trust set differs')
    for name, sha in keys.items():
        require(digest(ordinary(official_keys / name, 16384)) == sha, 'signed image official APK key differs')
    files = {}
    directories = set()
    total = 0
    with tarfile.open(path, 'r:') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            require(name not in files and name not in directories and len(files) + len(directories) < 4096,
                    'duplicate or excessive package archive members')
            require(name == '.' or (not PurePosixPath(name).is_absolute()
                    and all(part not in {'', '.', '..'} for part in name.split('/'))), 'package path escaped its cache')
            require(member.uid == member.gid == 0 and not member.pax_headers
                    and member.type in {tarfile.REGTYPE, tarfile.DIRTYPE}, 'package archive contains foreign or special metadata')
            if member.isdir():
                require(name in {'.', 'keys'} and member.size == 0, 'undeclared package directory')
                directories.add(name)
                continue
            allowed = (re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*\.apk', name)
                       or re.fullmatch(r'APKINDEX\.[a-f0-9]{8}\.tar\.gz', name)
                       or name in {'repositories', 'installed.txt', 'SHA256SUMS'}
                       or name in {'keys/' + key for key in keys})
            require(allowed and 0 < member.size <= 64 << 20 and member.mode == 0o644,
                    'package archive member escaped its finite public inventory')
            total += member.size
            require(total <= MAX_ARCHIVE, 'package archive expanded size exceeds its bound')
            files[name] = archive.extractfile(member).read(member.size + 1)
            require(len(files[name]) == member.size, 'incomplete package archive member')
    require(directories == {'.', 'keys'}, 'package archive directory inventory differs')
    apks = {name for name in files if name.endswith('.apk')}
    require(len(apks) == config['closure']['apk_count'], 'complete APK inventory differs')
    require(len([name for name in files if name.startswith('APKINDEX.')]) == 2, 'original repository indexes missing')
    require(set(files) == apks | {'repositories', 'installed.txt', 'SHA256SUMS'}
            | {name for name in files if name.startswith('APKINDEX.')} | {'keys/' + key for key in keys},
            'package archive inventory incomplete')
    require(files['repositories'] == b'https://dl-cdn.alpinelinux.org/alpine/v3.24/main\n'
            b'https://dl-cdn.alpinelinux.org/alpine/v3.24/community\n', 'original repository provenance differs')
    checksums = {}
    for line in files['SHA256SUMS'].decode('ascii').splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9+_.-]*\.apk)', line)
        require(match and match[2] not in checksums, 'invalid or duplicate APK checksum')
        checksums[match[2]] = match[1]
    require(set(checksums) == apks and all(digest(files[name]) == sha for name, sha in checksums.items()),
            'complete APK byte checksums differ')
    require(all(digest(files['keys/' + name]) == sha for name, sha in keys.items()),
            'captured APK keys differ from the signed image keys')
    return files


def install(config, root=ROOT, official_keys=Path('/etc/apk/keys'), execute=subprocess.run, downloader=fetch):
    input_record(config)
    require(root.is_absolute() and not any(path.is_symlink() for path in [root, *root.parents]),
            'ordinary absolute package cache required')
    root.mkdir(mode=0o700, exist_ok=True)
    require(root.stat().st_uid == os.geteuid(), 'package cache belongs to another caller')
    os.chmod(root, 0o700)
    cache = root / 'apk-cache'
    require(not cache.exists() and not cache.is_symlink(), 'fresh immutable package cache required')
    cache.mkdir(mode=0o700)
    manifest_path = root / 'alpine-packages.json'
    archive_path = root / 'alpine-packages.tar'
    deadline = time.monotonic() + 300  # Existing download bound; outer guest readiness remains 600s.
    downloader(config['closure']['manifest'], manifest_path, deadline)
    manifest_record(ordinary(manifest_path, MAX_DOCUMENT), config)
    downloader(config['closure']['archive'], archive_path, deadline)
    files = archive_record(archive_path, config, official_keys)
    for name, raw in files.items():
        destination = cache / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(raw)
    # The existing signed image's keys stay authoritative. Captured keys are
    # compared above and never copied to /etc/apk/keys. Explicit local APK paths
    # plus both offline flags prohibit current repository index resolution.
    arguments = ['apk', '--no-network', '--repositories-file', '/dev/null', '--cache-dir', str(cache), 'add',
                 *[str(cache / name) for name in sorted(files) if name.endswith('.apk')]]
    result = execute(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.PIPE, timeout=300, check=False)
    require(result.returncode == 0, 'official offline APK signature or dependency verification refused')
    observed = execute(['apk', 'info', '-vv'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=30, check=False)
    require(observed.returncode == 0 and len(observed.stdout) <= 1 << 20
            and observed.stdout == files['installed.txt'], 'exact accepted installed package inventory differs')
    (root / 'cloud-ready').touch(exist_ok=False)


def main():
    # The executable is a disposable-guest Root action. Pure archive/file
    # validation remains caller-owned so contributor tests need no privilege.
    require(os.geteuid() == 0, 'disposable Root authority required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    install(decode(ordinary(args.config, MAX_DOCUMENT)))


if __name__ == '__main__':
    main()
