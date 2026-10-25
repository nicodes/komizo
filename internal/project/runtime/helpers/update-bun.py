#!/usr/bin/env python3
"""Report Bun updates in one owned issue; never create branches or PRs."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def run(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=kwargs.pop('timeout', 60), **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args[0]} {args[1]} failed (exit {result.returncode})')
    return result.stdout


def api(repo, suffix, payload=None):
    args = ['gh', 'api', f'repos/{repo}/{suffix}']
    if payload is not None:
        args += ['--method', 'POST', '--input', '-']
    result = run(args, input=None if payload is None else json.dumps(payload))
    return json.loads(result) if result.strip() else None


def parse_inventory(output):
    """Pinned Bun emits a table, not JSON. Reject unknown rows/schema."""
    rows = []
    for line in output.splitlines():
        line = line.strip()
        if not line or re.fullmatch(r'bun outdated v\d+\.\d+\.\d+ \([a-f0-9]+\)', line):
            continue
        if re.fullmatch(r'\|[-|]+\|', line):
            continue
        cells = [cell.strip() for cell in line.split('|')[1:-1]]
        if cells == ['Package', 'Current', 'Update', 'Latest']:
            continue
        if not line.startswith('|') or not line.endswith('|') or len(cells) != 4:
            raise ValueError('Bun outdated output schema changed')
        name = re.sub(r' \((dev|optional|peer)\)$', '', cells[0])
        if not re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9._-]+', name):
            raise ValueError('Unknown package name in Bun inventory')
        if not all(re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.+-]+)?', value) for value in cells[1:]):
            raise ValueError('Unknown version in Bun inventory')
        rows.append(dict(zip(['package', 'current', 'update', 'latest'], [name, *cells[1:]])))
    return rows


def prepare(root):
    tracked = set(run(['git', 'ls-files', '-z'], cwd=root).split('\0'))
    # Discover the product's own top-level package directories instead of
    # assuming `app/` — the same `*/package.json` scan pins.mjs uses.
    applications = sorted({str(Path(name).parent) for name in tracked
                           if name.endswith('/package.json') and name.count('/') == 1})
    if not applications:
        raise ValueError('The product must declare an application manifest')
    inventory, changes = [], {}
    for application in applications:
        rows, files = prepare_application(root, application)
        inventory.extend(dict(row, application=application) for row in rows)
        changes.update(files)
    return inventory, changes


def prepare_application(root, application):
    manifest = json.loads((root/application/'package.json').read_text())
    version = run(['bun', '--version']).strip()
    if manifest.get('packageManager') != 'bun@'+version:
        raise ValueError('Update automation must use the exact repository Bun pin')
    tracked = set(run(['git', 'ls-files', '-z'], cwd=root).split('\0'))
    required = [application+'/package.json', application+'/bun.lock']
    required += [application+'/'+value for value in manifest.get('patchedDependencies', {}).values()]
    if application+'/bunfig.toml' in tracked:
        required.append(application+'/bunfig.toml')
    # Dependency resolution gets no GitHub credential and executes no lifecycle scripts.
    env = {name: value for name, value in os.environ.items()
           if name not in {'GH_TOKEN', 'GITHUB_TOKEN', 'NODE_AUTH_TOKEN', 'NPM_TOKEN'}}
    env['NO_COLOR'] = '1'
    with tempfile.TemporaryDirectory(prefix='bun-update-') as temporary:
        work = Path(temporary)
        for name in required:
            source = root/name
            if name not in tracked or source.is_symlink() or not source.resolve().is_relative_to(root.resolve()/application):
                raise ValueError('Bun update input must be a tracked app file')
            target = work/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        inventory = parse_inventory(run(['bun', 'outdated'], cwd=work/application, env=env, timeout=600))
        run(['bun', 'update', '--lockfile-only', '--ignore-scripts', '--no-progress'],
            cwd=work/application, env=env, timeout=900)
        updated = json.loads((work/application/'package.json').read_text())
        # Preserve policies, overrides and patch declarations. Only Bun's dependency
        # range maintenance may change the manifest; no scripts or tooling edits.
        groups = {'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'}
        if {k:v for k,v in manifest.items() if k not in groups} != {k:v for k,v in updated.items() if k not in groups}:
            raise ValueError('Bun changed non-dependency manifest fields')
        changes = {name: (work/name).read_text() for name in [application+'/package.json', application+'/bun.lock']
                   if (work/name).read_bytes() != (root/name).read_bytes()}
    return inventory, changes


def publish(repo, base, inventory, changes):
    # Caller identity is checked before any API write.
    if os.environ.get('GITHUB_REPOSITORY', repo) != repo:
        raise ValueError('repository differs from the workflow caller')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*/[a-z0-9-]+', repo) or not re.fullmatch(r'[a-f0-9]{40}', base):
        raise ValueError('Invalid issue target')
    if api(repo, 'git/ref/heads/main')['object']['sha'] != base:
        raise ValueError('Main changed; rerun the update inventory on current main')
    if not inventory and not changes:
        print('No available updates or lockfile refresh. Existing issues remain for owner review.')
        return
    title = 'Bun maintenance: available dependency updates'
    existing = json.loads(run(['gh', 'issue', 'list', '--repo', repo, '--state', 'open',
        '--search', 'in:title "'+title+'"', '--limit', '100', '--json', 'number,title']))
    existing = [item for item in existing if item['title'] == title]
    rows = ''.join(f"| `{i.get('application', 'app')}` | `{i['package']}` | `{i['current']}` | `{i['update']}` | `{i['latest']}` |\n" for i in inventory)
    refresh = ('A within-range/transitive refresh would change: '+', '.join('`'+name+'`' for name in sorted(changes))+'.'
               if changes else 'No within-range lockfile or manifest refresh was found.')
    body = ('The pinned Bun found dependency maintenance work. `Update` respects the '
            'current manifest range; `Latest` also shows releases outside that range.\n\n'
            '| Application | Package | Current | Update | Latest |\n|---|---|---|---|---|\n'+rows+'\n'+refresh+'\n\n'
            'Owner decision (2026-09-05): this workflow creates or updates this issue only. '
            'It never creates branches or PRs, approves changes, merges or dispatches CI. '
            'Review the updates and open a PR manually. Run the complete `make check` and '
            'require passing Test and Build checks before merging. Authentication/cryptography, '
            'PocketBase, pre-1.0 minor and major updates require owner review.\n\n'
            'This workflow creates maintenance issues only; '
            'do not enable GitHub’s combined workflow PR creation/approval setting automatically.\n')
    if len(body) > 50000:
        raise ValueError('Update inventory exceeds the issue size limit')
    assignment = {'assignees': [os.environ['MAINTENANCE_ASSIGNEE']]} if os.environ.get('MAINTENANCE_ASSIGNEE') else {}
    if existing:
        run(['gh', 'api', f'repos/{repo}/issues/{min(i["number"] for i in existing)}', '--method', 'PATCH', '--input', '-'],
            input=json.dumps({'body': body, **assignment}))
        print('Updated the existing owned Bun maintenance issue.')
    else:
        issue = api(repo, 'issues', {'title': title, 'body': body, **assignment})
        print(f'Created owned Bun maintenance issue #{issue["number"]}.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true', help='resolve and report locally without GitHub writes')
    args = parser.parse_args()
    root = Path.cwd()
    inventory, changes = prepare(root)
    output = root/'.artifacts/bun-updates.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({'inventory': inventory, 'changed_files': sorted(changes)}, indent=2)+'\n')
    if not args.dry_run:
        if os.environ.get('GITHUB_REF') != 'refs/heads/main':
            raise ValueError('Bun update publication is restricted to main')
        publish(os.environ['GITHUB_REPOSITORY'], run(['git', 'rev-parse', 'HEAD']).strip(), inventory, changes)
    print(f'Bun inventory: {len(inventory)} available updates; {len(changes)} files would need a manual refresh.')


if __name__ == '__main__':
    main()
