#!/usr/bin/env python3
"""Select caller-declared verification; unknown inputs always require the full gate.

This is a dependency policy, not a successful test receipt. Publication still
requires actual test and artifact evidence for its own source and configuration.
"""
import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

GROUPS = {'test': ['unit', 'integration'],
          'check': ['lint', 'unit', 'integration', 'build', 'artifact-check', 'vuln', 'browser-install', 'e2e']}
SENSITIVE = ('.github/*', '.mise.toml', 'Makefile', 'engineering*.json', '.gitmodules',
             '**/go.mod', '**/go.sum', 'go.mod', 'go.sum', '**/package.json', 'package.json',
             '*lock*', '**/*lock*', '*requirements*', '**/*requirements*')
TARGET = re.compile(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*')


def git(*args):
    return subprocess.check_output(['git', *args], stderr=subprocess.PIPE, timeout=30)


def policy(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 100_000:
        raise ValueError('a bounded regular caller policy is required')
    value = json.loads(path.read_text())
    if type(value.get('version')) is not int or value.get('version') != 1 or set(value) - {'version', 'full_targets', 'always', 'rules', 'force_full'}:
        raise ValueError('unsupported verification policy')
    full = value.get('full_targets')
    if not isinstance(full, list) or not full or len(full) != len(set(full)):
        raise ValueError('unique full verification targets required')
    if any(not isinstance(t, str) or not TARGET.fullmatch(t)
           or t in {'clean', 'dev', 'stop', 'deploy', 'publish', 'release'} for t in full):
        raise ValueError('full targets must be individual Make stages')
    always = value.get('always', [])
    if not isinstance(always, list) or not set(always) <= set(full):
        raise ValueError('always targets must belong to the full gate')
    rules = value.get('rules', [])
    if not isinstance(rules, list):
        raise ValueError('rules must be an array')
    for rule in rules:
        if set(rule) != {'paths', 'targets'} or not isinstance(rule['targets'], list) or not set(rule['targets']) <= set(full):
            raise ValueError('rules must select explicit full-gate targets')
    patterns = [*value.get('force_full', []), *(p for r in rules for p in r['paths'])]
    if any(not isinstance(p, str) or not p or p.startswith('/') or '..' in Path(p).parts or '\\' in p for p in patterns):
        raise ValueError('input patterns must remain inside the checkout')
    return value


def select(value, changed, event, policy_path='engineering-plan.json'):
    full = value['full_targets']
    reasons = []
    selected = set(value.get('always', []))
    fallback = event not in ('pull_request', 'local')
    if fallback:
        reasons.append('This event requires complete verification')
    for name in changed:
        if (not name or name.startswith('/') or '..' in Path(name).parts or '\\' in name
                or name == policy_path or any(fnmatch.fnmatchcase(name, p) for p in (*SENSITIVE, *value.get('force_full', [])))):
            fallback = True
            reasons.append(f'{name}: shared, policy or dependency input requires complete verification')
            continue
        matches = [r for r in value.get('rules', []) if any(fnmatch.fnmatchcase(name, p) for p in r['paths'])]
        if not matches:
            fallback = True
            reasons.append(f'{name}: no reviewed dependency rule; complete verification required')
        for rule in matches:
            selected.update(rule['targets'])
            reasons.append(f'{name}: selects ' + ', '.join(rule['targets']))
    return {'mode': 'full' if fallback else 'focused',
            'targets': full if fallback else [t for t in full if t in selected],
            'reasons': reasons or ['No changed inputs; always-required checks remain']}


def plan(base, path, event):
    value = policy(path)
    head = git('rev-parse', 'HEAD').decode().strip()
    if not re.fullmatch(r'[a-f0-9]{40}', base):
        raise ValueError('base must be an exact commit')
    unavailable = None
    try:
        git('cat-file', '-e', base + '^{commit}')
        git('merge-base', '--is-ancestor', base, head)
        # --no-renames exposes both sides of renames. Include dirty and untracked
        # inputs for local agents; ignored caches/outputs are never test authority.
        changed = sorted(set(os.fsdecode(x) for x in (
            git('diff', '--name-only', '--no-renames', '-z', base, '--') +
            git('ls-files', '--others', '--exclude-standard', '-z')).split(b'\0') if x))
    except subprocess.SubprocessError:
        changed = []
        unavailable = 'Base is unavailable or is not an ancestor; complete verification required'
    selection = select(value, changed, event, Path(path).as_posix())
    if unavailable:
        selection.update(mode='full', targets=value['full_targets'], reasons=[unavailable])
    return {'version': 1, 'head': head, 'base': base, 'changed_paths': changed,
            'policy_sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            'full_targets': value['full_targets'], **selection,
            'command': ['make', '--', *selection['targets']],
            'note': 'Selection is not test, build or publication evidence.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    parser.add_argument('--policy', type=Path, default=Path('engineering-plan.json'))
    parser.add_argument('--event', default=os.environ.get('GITHUB_EVENT_NAME', 'local'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--run', nargs='+', help='Run the selected subset of these canonical Make targets')
    args = parser.parse_args()
    result = plan(args.base, args.policy, args.event)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True), flush=True)
    if args.run:
        requested = []
        for target in args.run:
            if not TARGET.fullmatch(target):
                raise ValueError('invalid Make target')
            requested.extend([target] if target in result['full_targets'] else GROUPS.get(target, [target]))
        # Installation and policy checks outside the declared selectable gate
        # remain required. Only the caller's explicit full_targets can be omitted.
        selected = [t for t in dict.fromkeys(requested)
                    if t not in result['full_targets'] or t in result['targets']]
        if selected == ['install']:
            selected = []
        if selected:
            subprocess.run(['make', '--', *selected], check=True)
        else:
            print('No affected stages in this job; required workflow check completed with explicit selection evidence.')


if __name__ == '__main__':
    main()
