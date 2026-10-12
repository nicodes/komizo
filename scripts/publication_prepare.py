"""Prepare a finite, credential-free publication artifact from tested images."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time

MAX_ARCHIVE = 4 * 1024**3
MAX_EXPANDED = 16 * 1024**3
MAX_JSON = 65536
SHA = re.compile(r'[a-f0-9]{40}')
REFERENCE = re.compile(r'ghcr\.io/([a-z0-9][a-z0-9_.-]*)/[a-z0-9][a-z0-9_.-]*:([a-f0-9]{40})')


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise ValueError('publication preparation deadline exceeded')
    return value


def metadata(args, deadline):
    with tempfile.TemporaryFile() as output:
        subprocess.run(args, stdout=output, stderr=subprocess.DEVNULL,
                       timeout=min(30, remaining(deadline)), check=True)
        if output.tell() > MAX_JSON:
            raise ValueError('source metadata exceeds its bound')
        output.seek(0)
        return output.read().decode().strip()


def identity(environment, git):
    repository = environment.get('GITHUB_REPOSITORY', '')
    revision = environment.get('GITHUB_SHA', '')
    if (environment.get('GITHUB_REF') != 'refs/heads/main'
            or environment.get('GITHUB_EVENT_NAME') not in ('push', 'workflow_dispatch')
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            or not SHA.fullmatch(revision)):
        raise ValueError('publication requires an exact main workflow identity')
    if git(['rev-parse', 'HEAD']) != revision or git(['status', '--porcelain', '--untracked-files=no']):
        raise ValueError('publication requires the unchanged tested checkout')
    tree = git(['rev-parse', 'HEAD^{tree}'])
    if not SHA.fullmatch(tree):
        raise ValueError('publication tree identity is invalid')
    run_id = int(environment.get('GITHUB_RUN_ID', '0'))
    attempt = int(environment.get('GITHUB_RUN_ATTEMPT', '0'))
    if run_id <= 0 or attempt <= 0:
        raise ValueError('publication requires a positive workflow run and attempt')
    return {'version': 1, 'repository': repository, 'revision': revision,
            'tree': tree, 'run_id': run_id, 'attempt': attempt}


def references(images, source):
    if not 1 <= len(images) <= 8 or len(set(images)) != len(images):
        raise ValueError('publication requires one to eight distinct images')
    for image in images:
        match = REFERENCE.fullmatch(image)
        if (not match or match[1] != source['repository'].split('/')[0].lower()
                or match[2] != source['revision'] or '..' in image.split('/')):
            raise ValueError('image requires its repository owner and exact tested source tag')


def save(images, raw, deadline):
    process = subprocess.Popen(['docker', 'image', 'save', *images], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        with selectors.DefaultSelector() as ready, raw.open('xb') as output:
            ready.register(process.stdout, selectors.EVENT_READ)
            total = 0
            while True:
                if not ready.select(min(1, remaining(deadline))):
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE:
                    raise ValueError('saved image archive exceeds its bound')
                output.write(chunk)
        if process.wait(timeout=remaining(deadline)) != 0:
            raise ValueError('image save refused')
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        process.stdout.close()


def normalize(raw, destination, images, source, deadline):
    """Keep selected classic Docker payloads; never extract input archive paths.

    containerd save includes OCI indexes and gzip blobs. Normalize those on the
    producer, keeping the protected publisher's stricter format unchanged.
    Configuration bytes are unchanged; layers are checked against rootfs diff IDs.
    """
    references(images, source)
    if not 0 < raw.stat().st_size <= MAX_ARCHIVE:
        raise ValueError('saved image archive exceeds its bound')
    with tarfile.open(raw, mode='r:') as archive, tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        entries = {}
        total = 0
        for entry in archive:
            remaining(deadline)
            path = PurePosixPath(entry.name)
            if (path.is_absolute() or '..' in path.parts or str(path) != entry.name.rstrip('/')
                    or str(path) in entries or not (entry.isfile() or entry.isdir())
                    or entry.size < 0 or (entry.isdir() and entry.size != 0)):
                raise ValueError('saved archive contains unsafe, linked or repeated paths')
            total += entry.size
            if len(entries) >= 10000 or total > MAX_EXPANDED:
                raise ValueError('saved archive exceeds validation bounds')
            entries[str(path)] = entry

        def small(name):
            entry = entries.get(name)
            if entry is None or not entry.isfile() or not 0 < entry.size <= MAX_JSON:
                raise ValueError('image metadata is missing or oversized')
            return archive.extractfile(entry).read(MAX_JSON + 1)

        manifests = json.loads(small('manifest.json'))
        if not isinstance(manifests, list) or len(manifests) != len(images):
            raise ValueError('saved image set differs from requested images')
        payloads, observed, normalized = {}, {}, []
        expanded = 0
        for manifest in manifests:
            if (not isinstance(manifest, dict) or set(manifest) != {'Config', 'RepoTags', 'Layers'}
                    or not isinstance(manifest['RepoTags'], list) or len(manifest['RepoTags']) != 1):
                raise ValueError('each saved image requires exactly one tested source tag')
            reference = manifest['RepoTags'][0]
            if reference not in images or reference in observed:
                raise ValueError('saved image destination differs or repeats')
            body = small(manifest['Config'])
            configuration = json.loads(body)
            labels = configuration.get('config', {}).get('Labels', {})
            if (configuration.get('os') != 'linux' or configuration.get('architecture') != 'amd64'
                    or labels.get('org.opencontainers.image.revision') != source['revision']
                    or labels.get('org.opencontainers.image.source') != 'https://github.com/' + source['repository']):
                raise ValueError('saved image source or platform differs')
            config_digest = hashlib.sha256(body).hexdigest()
            config_name = config_digest + '.json'
            config_path = Path(temporary) / config_name
            config_path.write_bytes(body)
            payloads[config_name] = config_path
            layers = manifest['Layers']
            diff_ids = configuration.get('rootfs', {}).get('diff_ids', [])
            if (not isinstance(layers, list) or not 1 <= len(layers) <= 128
                    or not isinstance(diff_ids, list) or len(layers) != len(diff_ids)):
                raise ValueError('unsupported saved image layer contract')
            output_layers = []
            for layer, wanted in zip(layers, diff_ids):
                if not isinstance(wanted, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', wanted):
                    raise ValueError('invalid layer diff identity')
                entry = entries.get(layer)
                if entry is None or not entry.isfile():
                    raise ValueError('saved image layer is missing')
                name = wanted[7:] + '/layer.tar'
                output_layers.append(name)
                # Repeated diff IDs still authenticate every selected input blob.
                path = Path(temporary) / ('layer-' + str(len(payloads)))
                digest, size = hashlib.sha256(), 0
                with archive.extractfile(entry) as stream, path.open('xb') as target:
                    magic = stream.read(2)
                    stream.seek(0)
                    content = gzip.GzipFile(fileobj=stream) if magic == b'\x1f\x8b' else stream
                    try:
                        while chunk := content.read(65536):
                            remaining(deadline)
                            size += len(chunk)
                            if expanded + size > MAX_EXPANDED:
                                raise ValueError('expanded image layers exceed their bound')
                            if expanded + size > MAX_ARCHIVE:
                                raise ValueError('selected image layers exceed publication bound')
                            digest.update(chunk)
                            target.write(chunk)
                    finally:
                        if content is not stream:
                            content.close()
                if 'sha256:' + digest.hexdigest() != wanted:
                    raise ValueError('saved image layer content differs from configuration')
                if name in payloads:
                    path.unlink()
                else:
                    payloads[name] = path
                    expanded += size
            observed[reference] = config_digest
            normalized.append({'Config': config_name, 'RepoTags': [reference], 'Layers': output_layers})
        if set(observed) != set(images):
            raise ValueError('saved images are incomplete')
        manifest_path = Path(temporary) / 'manifest.json'
        manifest_path.write_text(json.dumps(normalized, sort_keys=True, separators=(',', ':')))
        payloads['manifest.json'] = manifest_path
        # Reject before writing an archive that the publisher cannot accept.
        archive_size = 1024 + sum(512 + ((path.stat().st_size + 511) // 512) * 512
                                  for path in payloads.values())
        archive_size = ((archive_size + 10239) // 10240) * 10240
        if archive_size > MAX_ARCHIVE:
            raise ValueError('normalized archive exceeds publication bound')
        with tarfile.open(destination, mode='x', format=tarfile.USTAR_FORMAT) as target:
            for name, path in sorted(payloads.items()):
                remaining(deadline)
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = path.stat().st_size, 0o644, 0
                with path.open('rb') as stream:
                    target.addfile(info, stream)
        if destination.stat().st_size > MAX_ARCHIVE:
            raise ValueError('normalized archive exceeds publication bound')
        return observed


def prepare(images, output, environment, deadline):
    source = identity(environment, lambda args: metadata(['git', *args], deadline))
    references(images, source)
    output.parent.resolve(strict=True)
    output.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix='.save-', dir=output) as temporary:
            raw = Path(temporary) / 'raw.tar'
            save(images, raw, deadline)
            source['images'] = normalize(raw, output/'images.tar', images, source, deadline)
        (output/'release.json').write_text(json.dumps(source, sort_keys=True, separators=(',', ':')) + '\n')
    except BaseException:
        shutil.rmtree(output)
        raise
    return source


def main():
    parser = argparse.ArgumentParser(prog='komizo publication prepare')
    parser.add_argument('command', choices=['prepare'])
    parser.add_argument('--image', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.image, args.output, os.environ, time.monotonic() + 900)
    print(json.dumps({'prepared': True, 'output': str(args.output), 'images': len(args.image)}))


if __name__ == '__main__':
    main()
