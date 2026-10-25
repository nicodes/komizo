#!/usr/bin/env python3
"""Reconcile bot updates after CI; never execute or check out pull-request code."""
import argparse
import base64
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile


spec = importlib.util.spec_from_file_location('dependency_policy', Path(__file__).with_name('dependency-policy.py'))
policy_engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy_engine)
SHA = re.compile(r'[a-f0-9]{40}')
WORKFLOW = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.ya?ml')
MAX_BYTES = 1024 * 1024


def api(path, method='GET', body=None, binary=False):
    command = ['gh', 'api', '--method', method, '-H', 'Accept: application/vnd.github+json', path]
    if body is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(body).encode() if body is not None else None,
                            capture_output=True, timeout=60)
    if result.returncode:
        # gh's useful HTTP diagnosis was previously swallowed by CalledProcessError.
        raise ValueError(f'GitHub API {method} failed: {result.stderr.decode()[:500]}')
    if len(result.stdout) > 8 * MAX_BYTES:
        raise ValueError('GitHub response exceeds the byte limit')
    return result.stdout if binary else json.loads(result.stdout) if result.stdout.strip() else None


def pages(path, key=None):
    rows = []
    for page in range(1, 11):
        result = api(f'{path}{"&" if "?" in path else "?"}per_page=100&page={page}')
        chunk = result[key] if key else result
        if not isinstance(chunk, list):
            raise ValueError('invalid paginated response')
        rows.extend(chunk)
        if len(chunk) < 100:
            return rows
    raise ValueError('pagination exceeds its reviewed limit')


def contents(repo, ref, path):
    value = api(f'repos/{repo}/contents/{path}?ref={ref}')
    if value.get('type') != 'file' or value.get('encoding') != 'base64':
        raise ValueError('policy must be a regular Git file')
    raw = base64.b64decode(value['content'], validate=False)
    if len(raw) > MAX_BYTES:
        raise ValueError('policy exceeds its byte limit')
    return json.loads(raw)


def validate_policy(value):
    keys = {'version', 'mode', 'ci_workflow', 'required_checks', 'integration_job',
            'dispatch_workflow', 'max_group_size', 'managed_dependencies', 'sensitive_dependencies'}
    if not isinstance(value, dict) or set(value) != keys or value.get('version') != 1:
        raise ValueError('complete dependency policy v1 required')
    if value['mode'] not in ('auto', 'review') or not WORKFLOW.fullmatch(value['ci_workflow']):
        raise ValueError('invalid dependency mode or workflow')
    if not WORKFLOW.fullmatch(value['dispatch_workflow']):
        raise ValueError('explicit merged-main workflow required')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', value['integration_job']):
        raise ValueError('explicit integration job required')
    checks = value['required_checks']
    if not isinstance(checks, list) or not checks or len(set(checks)) != len(checks) or not all(isinstance(c, str) and c for c in checks):
        raise ValueError('nonempty unique required checks required')
    if type(value['max_group_size']) is not int or not 1 <= value['max_group_size'] <= 20:
        raise ValueError('invalid group size')
    for key in ('managed_dependencies', 'sensitive_dependencies'):
        if not isinstance(value[key], list) or not all(isinstance(p, str) and p for p in value[key]):
            raise ValueError('dependency patterns must be nonempty strings')
    return value


def metadata(commits, head):
    # Added maintainer commits invalidate auto-merge, even if the PR author is a bot.
    if len(commits) != 1 or commits[0].get('sha') != head:
        raise ValueError('automatic updates require one unchanged bot commit')
    commit = commits[0]
    verification = commit['commit'].get('verification', {})
    if (commit.get('author', {}).get('login') != 'dependabot[bot]'
            or verification.get('verified') is not True or verification.get('reason') != 'valid'):
        raise ValueError('verified Dependabot commit required')
    message = commit['commit']['message']
    if len(message) > 65536:
        raise ValueError('bot metadata exceeds its byte limit')
    blocks = re.findall(r'^---\s*\n(updated-dependencies:\n.*?)(?:^\.\.\.\s*$)', message, re.M | re.S)
    if len(blocks) != 1:
        raise ValueError('one signed dependency metadata block required')
    result = subprocess.run([os.environ['KOMIZO_EXECUTABLE'], '--json', 'metadata'],
        input=blocks[0].encode(), capture_output=True, timeout=10)
    if result.returncode or len(result.stdout)>65536:
        raise ValueError('dependency metadata parser refused the signed block')
    envelope=json.loads(result.stdout)
    if envelope.get('ok') is not True or not isinstance(envelope.get('data'),dict):
        raise ValueError('invalid dependency metadata parser response')
    return envelope['data']['updated-dependencies']


def integration(repo, head, base, run, policy):
    artifacts = pages(f"repos/{repo}/actions/runs/{run['id']}/artifacts", 'artifacts')
    name = f"fleet-integration-{run['id']}-{run['run_attempt']}"
    matches = [a for a in artifacts if a.get('name') == name]
    if len(matches) != 1 or matches[0].get('expired') or not 0 < matches[0].get('size_in_bytes', 0) <= MAX_BYTES:
        raise ValueError('current CI integration receipt missing, expired or ambiguous')
    raw = api(f"repos/{repo}/actions/artifacts/{matches[0]['id']}/zip", binary=True)
    if len(raw) > MAX_BYTES:
        raise ValueError('integration archive exceeds its byte limit')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if len(entries) != 1 or entries[0].filename != 'fleet-integration.json' or entries[0].file_size > MAX_BYTES:
            raise ValueError('unexpected integration archive contents')
        receipt = json.loads(archive.read(entries[0]))
    if (receipt.get('version') != 1 or receipt.get('repository') != repo
            or receipt.get('run_id') != run['id'] or receipt.get('attempt') != run['run_attempt']
            or receipt.get('job') != policy['integration_job'] or receipt.get('head') != head
            or not SHA.fullmatch(receipt.get('commit', '')) or not SHA.fullmatch(receipt.get('tree', ''))):
        raise ValueError('integration receipt does not match this CI attempt')
    if receipt.get('base') != base:
        return None
    commit = api(f"repos/{repo}/git/commits/{receipt['commit']}")
    if ([p.get('sha') for p in commit.get('parents', [])] != [base, head]
            or commit.get('tree', {}).get('sha') != receipt['tree']):
        raise ValueError('integration receipt differs from immutable Git objects')
    return receipt


def ci_evidence(repo, head, base, policy):
    workflow = api(f"repos/{repo}/actions/workflows/{policy['ci_workflow']}")
    runs = pages(f"repos/{repo}/actions/workflows/{workflow['id']}/runs?event=pull_request&head_sha={head}", 'workflow_runs')
    matching = [r for r in runs if r.get('head_sha') == head and r.get('event') == 'pull_request'
                and r.get('workflow_id') == workflow['id'] and r.get('path') == '.github/workflows/'+policy['ci_workflow']
                and r.get('repository', {}).get('full_name', '').lower() == repo.lower()
                and r.get('head_repository', {}).get('full_name', '').lower() == repo.lower()]
    if not matching:
        return 'waiting', 'required CI has not run', None
    run = max(matching, key=lambda r: r['id'])
    if run['status'] != 'completed':
        return 'waiting', 'required CI is still running', None
    if run['conclusion'] != 'success':
        return 'blocked', 'required CI failed', None
    jobs = pages(f"repos/{repo}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", 'jobs')
    for name in policy['required_checks']:
        matches = [j for j in jobs if j.get('name') == name]
        if (len(matches) != 1 or matches[0].get('conclusion') != 'success'
                or matches[0].get('status') != 'completed' or matches[0].get('head_sha') != head
                or matches[0].get('run_attempt') != run['run_attempt']):
            raise ValueError('required CI job is missing, skipped or ambiguous: '+name)
    # Failed auxiliary checks also block merging. Only this policy workflow is
    # excluded by authenticated workflow identity, never by a check-name prefix.
    checks = pages(f'repos/{repo}/commits/{head}/check-runs?filter=latest', 'check_runs')
    authenticated = {}
    for check in checks:
        if check.get('head_sha') != head:
            raise ValueError('check belongs to a different head')
        url = check.get('details_url', '')
        match = re.fullmatch(re.escape(f'https://github.com/{repo}/actions/runs/')+r'(\d+)/job/\d+', url)
        if match and check.get('app', {}).get('id') == 15368:
            number = int(match[1])
            if number not in authenticated:
                authenticated[number] = api(f'repos/{repo}/actions/runs/{number}')
            producer = authenticated[number]
            if (producer.get('head_sha') == head and producer.get('path') in
                    ('.github/workflows/dependency-policy.yml', '.github/workflows/dependabot.yml')):
                continue
        if check.get('status') != 'completed':
            return 'waiting', 'additional checks are still running', None
        if check.get('conclusion') not in ('success', 'skipped'):
            return 'blocked', 'an additional check failed', None
    statuses = pages(f'repos/{repo}/commits/{head}/statuses')
    latest = {}
    for status in statuses:
        latest.setdefault(status['context'], status)
    if any(s['state'] not in ('success', 'pending') for s in latest.values()):
        return 'blocked', 'an external status failed', None
    if any(s['state'] != 'success' for s in latest.values()):
        return 'waiting', 'an external status is pending', None
    receipt = integration(repo, head, base, run, policy)
    if receipt is None:
        return 'stale', 'CI tested an older base; rebase and rerun required', None
    return 'ready', 'all required checks and current-base integration passed', receipt


def inspect(repo, number, base, policy, apply=False):
    pull = api(f'repos/{repo}/pulls/{number}')
    head = pull['head']['sha']
    result = {'pull_request': number, 'head': head}
    if (pull.get('state') != 'open' or pull.get('draft') or pull['user']['login'] != 'dependabot[bot]'
            or pull['base']['ref'] != 'main' or pull['head']['repo']['full_name'].lower() != repo.lower()):
        return {**result, 'state': 'excluded', 'reason': 'not an open same-repository Dependabot update to main'}
    if policy['mode'] == 'review':
        return {**result, 'state': 'review', 'reason': 'shared-library updates require an agent review'}
    updates = metadata(pages(f'repos/{repo}/pulls/{number}/commits'), head)
    reason = policy_engine.review_reason(updates, policy['max_group_size'], policy['managed_dependencies'], policy['sensitive_dependencies'])
    if reason:
        return {**result, 'state': 'review', 'reason': reason}
    files = pages(f'repos/{repo}/pulls/{number}/files')
    if not files or any(f['filename'] in ('.github/dependency-policy.json', '.github/workflows/dependency-policy.yml', '.github/workflows/dependabot.yml') for f in files):
        return {**result, 'state': 'review', 'reason': 'merge policy changes require review'}
    if pull.get('mergeable_state') == 'dirty':
        return {**result, 'state': 'blocked', 'reason': 'merge conflict requires a bot rebase'}
    state, reason, receipt = ci_evidence(repo, head, base, policy)
    result.update(state=state, reason=reason)
    if state != 'ready' or not apply:
        return result
    # Probe the explicitly declared dispatch before an irreversible merge.
    target = api(f"repos/{repo}/actions/workflows/{policy['dispatch_workflow']}")
    if target.get('state') != 'active':
        raise ValueError('merged-main workflow is not active')
    fresh = api(f'repos/{repo}/pulls/{number}')
    if (fresh['head']['sha'] != head or fresh['state'] != 'open' or fresh.get('draft')
            or api(f'repos/{repo}/git/ref/heads/main')['object']['sha'] != base):
        return {**result, 'state': 'stale', 'reason': 'head or base moved before merge'}
    merged = api(f'repos/{repo}/pulls/{number}/merge', 'PUT', {'sha': head, 'merge_method': 'merge'})
    if merged.get('merged') is not True or not SHA.fullmatch(merged.get('sha', '')):
        raise ValueError('GitHub did not confirm the exact-head merge')
    commit = api(f"repos/{repo}/git/commits/{merged['sha']}")
    if ([p.get('sha') for p in commit.get('parents', [])] != [base, head]
            or commit.get('tree', {}).get('sha') != receipt['tree']):
        raise ValueError('merged tree differs from tested integration; deployment refused')
    if api(f'repos/{repo}/git/ref/heads/main')['object']['sha'] != merged['sha']:
        raise ValueError('main moved after merge; verify the newer main deployment')
    # Retain the merged identity even if dispatch fails; a red policy run must
    # distinguish a deployment failure from an unmerged pull request.
    errors = []
    for _ in range(3):
        try:
            if api(f'repos/{repo}/git/ref/heads/main')['object']['sha'] != merged['sha']:
                raise ValueError('main advanced; review the newer main deployment')
            api(f"repos/{repo}/actions/workflows/{target['id']}/dispatches", 'POST', {'ref': 'main'})
            break
        except ValueError as error:
            errors.append(str(error))
    else:
        return {**result, 'state': 'delivery-error', 'reason': errors[-1], 'merge_commit': merged['sha'],
                'dispatch_workflow': policy['dispatch_workflow']}
    return {**result, 'state': 'merged', 'reason': 'tested integration merged; main workflow dispatched',
            'merge_commit': merged['sha'], 'dispatch_workflow': policy['dispatch_workflow']}


def candidates(repo, event, name, policy):
    if name == 'pull_request_target':
        return [event['pull_request']['number']]
    if name == 'workflow_run':
        # Event data selects a lookup only; authenticated API evidence decides.
        run = api(f"repos/{repo}/actions/runs/{int(event['workflow_run']['id'])}")
        if (run.get('path') != '.github/workflows/'+policy['ci_workflow'] or run.get('event') != 'pull_request'
                or run.get('status') != 'completed'):
            return []
        return [p['number'] for p in run.get('pull_requests', [])]
    if name not in ('workflow_dispatch', 'schedule'):
        raise ValueError('unsupported dependency event')
    return [p['number'] for p in pages(f'repos/{repo}/pulls?state=open&base=main')
            if p['user']['login'] == 'dependabot[bot]' and not p.get('draft')][:20]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--pr', type=int, help='inspect one PR without modifying it; --apply required to merge')
    parser.add_argument('--output', type=Path, default=Path('dependency-report.json'))
    args = parser.parse_args()
    repo = os.environ['GITHUB_REPOSITORY']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('invalid repository identity')
    base = api(f'repos/{repo}/git/ref/heads/main')['object']['sha']
    if not SHA.fullmatch(base):
        raise ValueError('invalid main identity')
    policy = validate_policy(contents(repo, base, '.github/dependency-policy.json'))
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()) if not args.pr else {}
    numbers = [args.pr] if args.pr else candidates(repo, event, os.environ['GITHUB_EVENT_NAME'], policy)
    rows = []
    for number in numbers:
        try:
            row = inspect(repo, number, base, policy, args.apply)
        except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
            row = {'pull_request': number, 'state': 'error', 'reason': str(error)[:1000]}
        rows.append(row)
        print(json.dumps(row), flush=True)
        if row['state'] == 'merged':
            break  # Remaining PRs need a new integration against the new main.
    report = {'version': 1, 'repository': repo, 'base': base,
              'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'pull_requests': rows}
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write('Dependency decisions (review is a normal outcome):\n\n```json\n'+json.dumps(rows, indent=2)+'\n```\n')
    if any(r['state'] in ('error', 'delivery-error') for r in rows):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
