#!/usr/bin/env python3
"""Scan every Go executable in an exact built image without executing its code."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile


def judge_report(raw):
    """Require a complete known protocol; distinguish module mentions from symbols."""
    decoder = json.JSONDecoder()
    messages = []
    while raw.strip():
        message, end = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[end:]
        if not isinstance(message, dict) or len(message) != 1:
            raise ValueError('invalid vulnerability protocol message')
        kind, value = next(iter(message.items()))
        if kind not in {'config', 'SBOM', 'progress', 'osv', 'finding'} or not isinstance(value, dict):
            raise ValueError('unknown vulnerability protocol message')
        messages.append(message)
    configs = [m['config'] for m in messages if 'config' in m]
    inventories = [m['SBOM'] for m in messages if 'SBOM' in m]
    if len(configs) != 1 or len(inventories) != 1:
        raise ValueError('scan must contain exactly one config and binary inventory')
    config = configs[0]
    for key, expected in {'protocol_version': 'v1.0.0', 'scanner_name': 'govulncheck',
                          'scanner_version': 'v1.7.0', 'scan_level': 'symbol', 'scan_mode': 'binary'}.items():
        if config.get(key) != expected:
            raise ValueError(f'unsupported scanner configuration: {key}')
    inventory = inventories[0]
    if not isinstance(inventory.get('modules'), list) or not inventory['modules']:
        raise ValueError('scan has no module inventory')
    reached, mentioned = set(), set()
    for message in messages:
        if 'finding' not in message:
            continue
        finding = message['finding']
        if set(finding) - {'osv', 'fixed_version', 'trace'}:
            raise ValueError('unknown finding fields')
        if not isinstance(finding.get('osv'), str) or not re.fullmatch(r'GO-\d{4}-\d+', finding['osv']):
            raise ValueError('finding has no advisory identity')
        if 'fixed_version' in finding and not isinstance(finding['fixed_version'], str):
            raise ValueError('invalid fixed version')
        trace = finding.get('trace')
        if not isinstance(trace, list) or not trace:
            raise ValueError('finding has no trace')
        for frame in trace:
            if not isinstance(frame, dict) or set(frame) - {'module', 'version', 'package', 'function', 'receiver', 'position'}:
                raise ValueError('unknown trace format')
            for key, value in frame.items():
                if key == 'position':
                    if not isinstance(value, dict):
                        raise ValueError('invalid trace position')
                elif not isinstance(value, str) or not value:
                    raise ValueError('invalid trace field')
            if not frame.get('module') or (frame.get('function') and not frame.get('package')):
                raise ValueError('incomplete trace identity')
        mentioned.add(finding['osv'])
        if trace[0].get('function'):
            # This also blocks reached advisories with no available fix. Missing
            # source positions are normal in binary mode and never exempt it.
            reached.add(finding['osv'])
    return {'reached': sorted(reached), 'mentioned': sorted(mentioned),
            'database_updated': config.get('db_last_modified', 'unknown')}


def is_upstream(member, upstream):
    """Does this image path name a binary the caller declared as upstream?

    Normalised on both sides. A tar member is "usr/bin/caddy"; an operator
    writes "/usr/bin/caddy", because that is what the path is inside the
    image. Comparing them raw matches nothing -- and a failed match here does
    not announce itself, it just silently applies no exemption while the
    command line looks exactly as though it did.
    """
    def norm(path):
        return '/' + path.lstrip('./').lstrip('/')
    return norm(member) in {norm(p) for p in upstream}


def forbidden_strings(binary, forbidden):
    """Which of these literals are present in a built executable.

    The question source inspection cannot answer. A product can move its
    development identity behind `//go:build localdev`, have every test pass
    in both builds, and still ship the string -- a build can do this through a
    seeding fixture whose code can never run. Whether the grant is reachable
    is a different question from whether the artifact carries it, and only
    the artifact can be asked the second one.

    Read as bytes, not decoded: a Go binary is not text, and a literal is
    present or it is not.
    """
    data = binary.read_bytes()
    return sorted(value for value in forbidden if value.encode() in data)


def scan(image, expected_go=None, upstream=(), forbidden=()):
    """Scan every Go executable in an image.

    `forbidden` names string literals that must not appear in any executable
    this organisation built -- a development identity, a local-only issuer
    name. An upstream binary is exempt for the same reason it is exempt from
    a reached advisory: it is somebody else's build and its contents are not
    this repository's to change.

    `upstream` names paths inside the image that WE DID NOT BUILD -- a binary
    that arrived in somebody else's base image. They are still scanned and
    still reported, and they do not fail the run.

    Caller-declared upstream binaries remain scanned and reported. The
    classification is per path; it does not exempt caller-built artifacts.

    It is narrow on purpose: one path at a time, named by the caller, on the
    caller's own line. Nothing here exempts a binary this organisation
    compiled -- for those, a reached advisory still fails the build.
    """
    info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image], text=True, timeout=30))
    if len(info) != 1 or not re.fullmatch(r'sha256:[a-f0-9]{64}', info[0]['Id']):
        raise ValueError('image identity is missing or ambiguous')
    identity = info[0]['Id']
    found = []
    with tempfile.TemporaryDirectory(prefix='go-image-scan-') as directory:
        root = Path(directory)
        container = subprocess.check_output(['docker', 'create', identity], text=True, timeout=30).strip()
        if not re.fullmatch(r'[a-f0-9]{64}', container):
            raise ValueError('Docker did not return a container ID')
        try:
            archive = root/'image.tar'
            subprocess.run(['docker', 'export', '--output', str(archive), container], check=True, timeout=300)
        finally:
            subprocess.run(['docker', 'rm', '-v', container], check=True, stdout=subprocess.DEVNULL, timeout=30)
        with tarfile.open(archive) as filesystem:
            for member in filesystem:
                if not member.isfile() or member.size < 4:
                    continue
                with filesystem.extractfile(member) as incoming:
                    if incoming.read(4) != b'\x7fELF':
                        continue
                    if member.size > 1024**3:
                        raise ValueError('image executable exceeds the scan size bound')
                    # Only extract to our own generated name. Archive paths and
                    # permissions are never applied to the host filesystem.
                    binary = root/'executable'
                    incoming.seek(0)
                    with binary.open('wb') as output:
                        shutil.copyfileobj(incoming, output)
                version = subprocess.run(['go', 'version', '-m', str(binary)], text=True,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                if version.returncode:
                    # A normal native ELF is not a Go executable. A file with
                    # Go build-info that the pinned Go tool cannot read fails.
                    if b'\xff Go buildinf:' in binary.read_bytes():
                        raise ValueError(f'cannot inspect Go executable {member.name}')
                    continue
                match = re.search(r': go(\d+\.\d+\.\d+)\b', version.stdout)
                if not match:
                    raise ValueError(f'Go executable has an unknown compiler: {member.name}')
                trusted = is_upstream(member.name, upstream)
                if expected_go is not None and match[1] != expected_go and not trusted:
                    raise ValueError(f'{member.name}: built by Go {match[1]}, expected {expected_go}')
                print(f'Scanning {member.name} in {identity}, built by Go {match[1]}', flush=True)
                if forbidden and not trusted:
                    present = forbidden_strings(binary, forbidden)
                    if present:
                        raise ValueError(
                            f'{member.name}: the shipped executable carries '
                            f'{", ".join(present)}. These are local-development literals and '
                            f'a release must not contain them, however unreachable the code '
                            f'that mentions them is.')
                result = subprocess.run(['govulncheck', '-mode=binary', '-json', str(binary)],
                                        check=True, stdout=subprocess.PIPE, text=True, timeout=600)
                verdict = judge_report(result.stdout)
                print(json.dumps(verdict), flush=True)
                if verdict['reached'] and not trusted:
                    raise ValueError(f'{member.name}: vulnerable linked symbols: {verdict["reached"]}')
                if verdict['reached']:
                    # Loud, every build. An accepted advisory that stops being
                    # mentioned is one nobody decides about again.
                    print(f'::warning::{member.name} is an upstream binary with reached '
                          f'advisories, accepted by --upstream: {verdict["reached"]}', flush=True)
                found.append({'path': member.name, 'go': match[1], 'upstream': trusted, **verdict})
        if not found:
            raise ValueError('expected a runtime image containing at least one Go executable')
    return {'image': image, 'image_id': identity, 'scanned': found}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--expected-go')
    parser.add_argument('--forbid', action='append', default=[], metavar='LITERAL',
                        help='a string no executable this organisation built may contain, '
                             'such as a development identity. Repeat for several.')
    parser.add_argument('--upstream', action='append', default=[], metavar='PATH',
                        help='a binary inside the image that we did not build; scanned and '
                             'reported, never fatal. Repeat for several.')
    args = parser.parse_args()
    print(json.dumps(scan(args.image, args.expected_go, args.upstream, args.forbid), indent=2))
