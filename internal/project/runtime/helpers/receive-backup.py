#!/usr/bin/env python3
"""Validate an encrypted host export before uploading it as an off-host artifact."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile


def receive(archive, target):
    target.mkdir(mode=0o700)
    seen = set()
    with tarfile.open(archive, 'r:') as source:
        for member in source:
            if member.name not in {'snapshot.cms', 'receipt.json'} or member.name in seen or not member.isfile():
                raise ValueError('unexpected, duplicate, or unsafe encrypted export entry')
            if member.size > (17 * 1024**3 if member.name == 'snapshot.cms' else 64 * 1024):
                raise ValueError('encrypted export exceeds the size bound')
            if shutil.disk_usage(target).free < member.size + 512 * 1024**2:
                raise ValueError('insufficient disk headroom to receive encrypted export')
            seen.add(member.name)
            with source.extractfile(member) as incoming, (target / member.name).open('xb') as output:
                shutil.copyfileobj(incoming, output)
            (target / member.name).chmod(0o600)
    if seen != {'snapshot.cms', 'receipt.json'}:
        raise ValueError('encrypted export is incomplete')
    receipt = json.loads((target / 'receipt.json').read_text())
    if receipt.get('format') != 1:
        raise ValueError('unknown encrypted envelope format')
    for key in ['archive_sha256', 'ciphertext_sha256']:
        if not isinstance(receipt.get(key), str) or not re.fullmatch(r'[a-f0-9]{64}', receipt[key]):
            raise ValueError('invalid export checksum')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', receipt.get('image_id', '')):
        raise ValueError('invalid recorded image identity')
    with (target / 'snapshot.cms').open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != receipt['ciphertext_sha256']:
        raise ValueError('encrypted export transport checksum mismatch')
    # Image selection is authenticated only after decrypting the inner metadata.
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('target', type=Path)
    args = parser.parse_args()
    print(json.dumps(receive(args.archive, args.target), indent=2))
