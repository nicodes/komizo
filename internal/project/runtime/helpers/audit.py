#!/usr/bin/env python3
"""Run the online Bun audit; accept only independently verified local repairs."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def verify_repair(app, repair):
    if datetime.date.fromisoformat(repair['review_date']) < datetime.date.today():
        raise RuntimeError('local security repair is overdue for upstream review')
    if not repair['owner'] or not repair['rationale']:
        raise RuntimeError('local security repair requires ownership and rationale')
    package = app/'node_modules'/repair['package']
    if json.loads((package/'package.json').read_text())['version'] != repair['version']:
        raise RuntimeError('security repair version does not match the installed package')
    for relative, expected in repair['installed_sha256'].items():
        target = package/relative
        if not target.resolve().is_relative_to(package.resolve()):
            raise RuntimeError('security repair names a file outside its package')
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f'security repair is absent or modified: {relative}')
    patch = app/repair['patch']
    if not patch.resolve().is_relative_to(app.resolve()):
        raise RuntimeError('patch is outside the app')
    if hashlib.sha256(patch.read_bytes()).hexdigest() != repair['patch_sha256']:
        raise RuntimeError('reviewed dependency patch changed')
    # Refuse a second unpatched copy hidden beneath another dependency.
    for manifest in (app/'node_modules').rglob('image-size/package.json'):
        for relative, expected in repair['installed_sha256'].items():
            if hashlib.sha256((manifest.parent/relative).read_bytes()).hexdigest() != expected:
                raise RuntimeError('a nested image-size copy lacks the verified repair')


def verify_accepted(accepted):
    """Accept only caller-reviewed findings with explicit ownership and expiry.

    Installed versions alone do not establish production reachability. The caller
    must record its rationale; verified local repairs remain a separate path.
    """
    for field in ('owner', 'rationale', 'package', 'advisories', 'review_date'):
        if not accepted.get(field):
            raise RuntimeError(f'an accepted finding needs {field}')
    if len(accepted['rationale']) < 40:
        raise RuntimeError('an accepted finding needs a rationale somebody can review, '
                           'not a word -- say why it cannot reach production')
    if datetime.date.fromisoformat(accepted['review_date']) < datetime.date.today():
        raise RuntimeError(f"accepted finding for {accepted['package']} is overdue for review "
                           f"({accepted['review_date']}); re-examine it or fix the dependency")


def main():
    app = Path(sys.argv[1] if len(sys.argv)>1 else 'app').resolve()
    result = subprocess.run(['bun', 'audit', '--json'], cwd=app,
                            text=True, capture_output=True, timeout=180)
    if result.returncode not in (0, 1):
        raise RuntimeError('online dependency audit could not complete')
    report = json.loads(result.stdout)
    if not isinstance(report, dict):
        raise RuntimeError('unrecognized audit response')
    if result.returncode and not report:
        raise RuntimeError('audit failed without findings; refusing a false pass')
    repairs_file = app/'security-remediations.json'
    repairs = json.loads(repairs_file.read_text()) if repairs_file.exists() else []
    resolved = {}
    expiry = {}
    for repair in repairs:
        kind = repair.get('kind', 'repaired')
        if kind == 'repaired':
            # We changed the dependency ourselves, so prove the change is
            # still installed and still does what it claimed.
            verify_repair(app, repair)
            if repair['package'] == 'image-size':
                # The one repair with a behavioural test of its own. It used
                # to be the ONLY repair this file would accept at all --
                # `if repair['package'] != 'image-size': raise` -- which put
                # one product's package name in the shared library and meant
                # no other product could ever declare anything.
                subprocess.run(['node', str(Path(__file__).with_name('image-parser-test.cjs')), str(app)],
                               check=True, timeout=30)
        elif kind == 'accepted':
            verify_accepted(repair)
            expiry[repair['package']] = repair['review_date']
        else:
            raise RuntimeError(f'unknown remediation kind: {kind!r}')
        for advisory in repair['advisories']:
            resolved[(repair['package'], advisory)] = kind
    remaining = []
    for package, findings in report.items():
        for finding in findings:
            advisory = finding['url'].rsplit('/', 1)[-1]
            kind = resolved.get((package, advisory))
            if kind is None:
                remaining.append(f'{package}: {finding["severity"]}: {finding["url"]}')
            elif kind == 'repaired':
                print(f'Locally repaired and verified: {package}: {advisory}')
            else:
                # Say which it was. An accepted finding is still present and
                # still unpatched, and reporting it as "repaired and
                # verified" tells the reader of a build log the opposite of
                # what happened.
                print(f'Accepted as unreachable, expires {expiry[package]}: {package}: {advisory}')
    if remaining:
        raise RuntimeError('unresolved dependency findings:\n'+'\n'.join(remaining))
    print('Online audit passed with all reported findings resolved or verified as locally repaired.')


if __name__ == '__main__':
    main()
