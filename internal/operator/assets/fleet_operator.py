#!/usr/bin/env python3
"""Execute fixed fleet operations through a private operator-owned policy.

This process runs outside the editor sandbox. It is not a shell proxy. It
accepts one bounded JSON request and never returns provider or SSH credentials.
"""
import contextlib
import fcntl
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import zipfile

POLICY = Path('/etc/fleet-operator.json')
LOCKS = Path('/var/lock/fleet-operator')
SHA = re.compile(r'[a-f0-9]{40}\Z')
REPOSITORY = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')
MAX_BYTES = 65536
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
COMMAND_SECONDS = 60
EXECUTABLES = {'gh': '/usr/bin/gh', 'ssh': '/usr/bin/ssh'}
OPERATOR_ENV = {'HOME': '/root', 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                'GH_CONFIG_DIR': '/root/.config/gh'}


def private_bytes(path):
    # Validate the opened object, not an earlier pathname lookup.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077
                or info.st_size > MAX_BYTES):
            raise ValueError('operator policy must be a private root-owned regular file')
        body = stream.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError('operator policy exceeds its size bound')
        return body


def private_json(path):
    return json.loads(private_bytes(path))


def private_policy(path):
    return validate_policy(private_json(path))


def validate_policy(value):
    required = {'version', 'repositories', 'hosts'}
    if value.get('version') != 3 or not required <= set(value) or set(value) - required - {'deployments', 'owner_workflows'}:
        raise ValueError('unsupported operator policy')
    if not isinstance(value['repositories'], dict) or not isinstance(value['hosts'], list):
        raise ValueError('invalid operator scope')
    owners = value.get('owner_workflows', {})
    if not isinstance(owners, dict) or not set(owners) <= set(value['repositories']):
        raise ValueError('owner workflows require an existing protected repository scope')
    for repo, contract, owner in [*( (r, c, False) for r,c in value['repositories'].items()),
                                 *( (r, c, True) for r,c in owners.items())]:
        if (not REPOSITORY.fullmatch(repo) or not isinstance(contract, dict)
                or set(contract) != {'workflow_id', 'workflow_path', 'app_id', 'event', 'jobs', 'integration_job'}
                or type(contract['workflow_id']) is not int or contract['workflow_id'] <= 0
                or type(contract['app_id']) is not int or contract['app_id'] <= 0
                or not re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml', contract['workflow_path'])
                or not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_-]{0,99}', contract['integration_job'])
                or contract['event'] not in (('push', 'workflow_dispatch') if owner else ('pull_request',))
                or not isinstance(contract['jobs'], list) or not contract['jobs']
                or len(set(contract['jobs'])) != len(contract['jobs'])
                or any(not isinstance(name, str) or not name.strip() for name in contract['jobs'])):
            raise ValueError('repository requires explicit workflow and producer identities')
    if any(not isinstance(host, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', host)
           for host in value['hosts']):
        raise ValueError('invalid operator host')
    for repo, binding in value.get('deployments', {}).items():
        if (repo not in value['repositories'] or not isinstance(binding,dict)
            or set(binding)!={'host','app','repository_id'} or binding['host'] not in value['hosts']
            or not re.fullmatch('[a-z][a-z0-9_-]{0,62}',binding['app'])
            or not isinstance(binding['repository_id'],str) or not re.fullmatch('[1-9][0-9]*',binding['repository_id'])):
            raise ValueError('delivery binding must belong to the protected repository and host scope')
    return value


def command(arguments):
    # Resolve tools independently of editor cwd/PATH and do not inherit project
    # credentials, Git/SSH overrides, Python settings or helper configuration.
    executable = EXECUTABLES.get(arguments[0])
    if executable is None:
        raise ValueError('unsupported operator executable')
    info = Path(executable).stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('operator executable must be protected and root-owned')
    process = subprocess.Popen([executable, *arguments[1:]], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                               cwd='/', env=OPERATOR_ENV, start_new_session=True)
    body = bytearray()
    deadline = time.monotonic() + COMMAND_SECONDS
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('operator command exceeded its deadline')
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, min(65536, MAX_OUTPUT_BYTES + 1 - len(body)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    body.extend(chunk)
                    if len(body) > MAX_OUTPUT_BYTES:
                        raise ValueError('operator evidence exceeds its size bound')
        process.wait(timeout=max(.001, deadline-time.monotonic()))
        if process.returncode:
            raise ValueError(f'operator command failed with exit {process.returncode}')
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.stdout.close()
    # gh merge may print a human confirmation. Re-fetch the PR for the fact.
    if arguments[:3] == ['gh', 'pr', 'merge']:
        return None
    if arguments[:2] == ['gh', 'api'] and re.fullmatch(r'repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/artifacts/[1-9][0-9]*/zip', arguments[-1]):
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            entries = archive.infolist()
            if len(entries) != 1 or entries[0].filename != 'fleet-integration.json' or entries[0].file_size > MAX_BYTES:
                raise ValueError('integration artifact has unexpected contents')
            return json.loads(archive.read(entries[0]))
    return json.loads(body) if body.strip() else None


def fields(request, allowed):
    if not isinstance(request, dict) or set(request) != set(allowed):
        raise ValueError('operation requires exactly its declared fields')


def checked_repository(policy, repository):
    if repository not in policy['repositories']:
        raise ValueError('repository is outside operator scope')


def verification_path(path):
    parts = Path(path).parts
    name = Path(path).name
    return (path.startswith(('.github/', 'tools/', 'scripts/', 'deploy/', 'fleet/', 'internal/operator/'))
            or any(part in ('test', 'tests', '__tests__', 'testdata', 'fixtures', 'spec', 'specs')
                   for part in parts[:-1])
            or name in ('AGENTS.md', 'komizo.json', 'komizo.lock', 'Makefile', '.mise.toml', 'Dockerfile',
                        'package.json', 'pyproject.toml', 'go.mod', 'go.sum')
            or name.startswith('test_') or re.search(r'_test\.[a-zA-Z0-9]+\Z', name) is not None
            or re.search(r'\.(?:test|spec)\.[a-zA-Z0-9]+\Z', name) is not None)


def review_contract(repository, number, head, run):
    changed = run(['gh', 'api', f'repos/{repository}/pulls/{number}/files?per_page=100'])
    if len(changed) >= 100:
        raise ValueError('large changes require a separately bounded operator review')
    paths = sorted(row['filename'] for row in changed)
    protected = any(verification_path(row['filename'])
                    or verification_path(row.get('previous_filename', '')) for row in changed)
    if not protected:
        return
    try:
        receipt = private_json(Path('/etc/fleet-operator-reviews')/(head+'.json'))
    except OSError:
        raise ValueError('verification machinery requires a protected operator review receipt') from None
    digest = hashlib.sha256(json.dumps(paths, separators=(',', ':')).encode()).hexdigest()
    if (receipt.get('version') != 1 or receipt.get('repository') != repository
            or receipt.get('head') != head or receipt.get('paths_sha256') != digest
            or receipt.get('ci_contract_reviewed') is not True
            or not re.fullmatch(r'[a-f0-9]{64}', receipt.get('evidence_sha256', ''))):
        raise ValueError('operator review does not bind the exact verification change')
    try:
        body = private_bytes(Path('/etc/fleet-operator-reviews')/(head+'.evidence.json'))
    except OSError:
        raise ValueError('operator review evidence is missing or inaccessible') from None
    if hashlib.sha256(body).hexdigest() != receipt['evidence_sha256']:
        raise ValueError('operator review evidence digest does not match')
    evidence = json.loads(body)
    if (not isinstance(evidence, dict) or evidence.get('version') != 1
            or evidence.get('repository') != repository or evidence.get('head') != head
            or evidence.get('reviewed_paths') != paths):
        raise ValueError('operator review evidence does not bind the exact verification change')


def authenticate_ci(repository, head, contract, checks, run, allow_running=False):
    """Bind mandatory successful checks to the approved Actions run and attempt.

    Actions metadata's head_sha is the PR head even when checkout tests the
    generated merge ref. Do not confuse it with the job's checked-out revision.
    Base freshness is independently enforced by strict branch protection where
    available; this evidence alone makes no claim about the checkout's base.
    """
    required = contract['jobs']
    rows = {name: [check for check in checks if check.get('name') == name]
            for name in required}
    authenticated_run = None
    cache = {}
    for name, matches in rows.items():
        if len(matches) != 1:
            raise ValueError('mandatory CI check is missing or ambiguous')
        check = matches[0]
        if (check.get('__typename') != 'CheckRun' or check.get('status') != 'COMPLETED'
                or check.get('conclusion') != 'SUCCESS'):
            raise ValueError('mandatory CI must be a successful authenticated check run')
        url = check.get('detailsUrl', '')
        match = re.fullmatch(r'https://github\.com/' + re.escape(repository)
                             + r'/actions/runs/([1-9][0-9]*)/job/([1-9][0-9]*)(?:\?[^#]*)?', url)
        if not match:
            raise ValueError('mandatory check has no scoped Actions identity')
        run_id, job_id = map(int, match.groups())
        if run_id not in cache:
            evidence = run(['gh', 'api', f'repos/{repository}/actions/runs/{run_id}'])
            attempt = evidence.get('run_attempt')
            if (evidence.get('id') != run_id or evidence.get('workflow_id') != contract['workflow_id']
                    or evidence.get('path') != contract['workflow_path']
                    or evidence.get('event') != contract['event']
                    or evidence.get('head_sha') != head
                    or evidence.get('head_repository', {}).get('full_name') != repository
                    or evidence.get('repository', {}).get('full_name') != repository
                    or not (evidence.get('status') == 'completed' and evidence.get('conclusion') == 'success'
                            or allow_running and evidence.get('status') == 'in_progress' and evidence.get('conclusion') is None)
                    or allow_running and evidence.get('head_branch') != 'main'
                    or type(attempt) is not int or attempt <= 0):
                raise ValueError('mandatory CI workflow identity differs from policy')
            jobs = run(['gh', 'api', f'repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100'])
            if jobs.get('total_count', 0) >= 100:
                raise ValueError('CI job evidence exceeds its bounded contract')
            cache[run_id] = evidence, jobs['jobs']
        evidence, jobs = cache[run_id]
        if authenticated_run is not None and authenticated_run != run_id:
            raise ValueError('mandatory jobs must come from the same workflow attempt')
        authenticated_run = run_id
        matches = [job for job in jobs if job.get('name') == name]
        if len(matches) != 1:
            raise ValueError('mandatory workflow job is missing or ambiguous')
        job = matches[0]
        if (job.get('id') != job_id or job.get('run_attempt') != evidence['run_attempt']
                or job.get('head_sha') != head or job.get('status') != 'completed'
                or job.get('conclusion') != 'success'):
            raise ValueError('mandatory CI job does not bind the current successful attempt')
        check_url = job.get('check_run_url', '')
        match = re.fullmatch(r'https://api\.github\.com/repos/' + re.escape(repository)
                             + r'/check-runs/([1-9][0-9]*)', check_url)
        if not match:
            raise ValueError('mandatory job has no scoped check-run identity')
        producer = run(['gh', 'api', f'repos/{repository}/check-runs/{match[1]}'])
        if (producer.get('app', {}).get('id') != contract['app_id']
                or producer.get('name') != name or producer.get('head_sha') != head
                or producer.get('check_suite', {}).get('id') != evidence.get('check_suite_id')
                or producer.get('details_url') != url
                or producer.get('status') != 'completed' or producer.get('conclusion') != 'success'):
            raise ValueError('mandatory check producer or source identity differs from policy')
    return authenticated_run


@contextlib.contextmanager
def repository_lock(repository):
    LOCKS.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = LOCKS.lstat()
    if not stat.S_ISDIR(info.st_mode) or not lock_owner(info) or info.st_mode & 0o077:
        raise ValueError('operator lock directory is not protected')
    path = LOCKS/(hashlib.sha256(repository.encode()).hexdigest()+'.lock')
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not lock_owner(info) or info.st_mode & 0o077:
            raise ValueError('operator lock is not protected')
        deadline = time.monotonic()+30
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError('operator merge queue exceeded its deadline')
                time.sleep(.05)
        yield
    finally:
        os.close(descriptor)


def lock_owner(info):
    return info.st_uid == 0


def authenticate_integration(repository, head, base, run_id, contract, run, owner=False):
    workflow = run(['gh', 'api', f'repos/{repository}/actions/runs/{run_id}'])
    attempt = workflow['run_attempt']
    result = run(['gh', 'api', f'repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100'])
    if result.get('total_count', 0) >= 100:
        raise ValueError('integration artifacts exceed their bounded contract')
    name = f'fleet-integration-{run_id}-{attempt}'
    artifacts = [row for row in result['artifacts'] if row.get('name') == name]
    if len(artifacts) != 1 or artifacts[0].get('expired') or type(artifacts[0].get('id')) is not int:
        raise ValueError('authenticated tested integration artifact missing or ambiguous')
    artifact = artifacts[0]
    if not 0 < artifact.get('size_in_bytes', 0) <= MAX_BYTES:
        raise ValueError('integration artifact exceeds its byte budget')
    value = run(['gh', 'api', f"repos/{repository}/actions/artifacts/{artifact['id']}/zip"])
    if (set(value) != {'version', 'repository', 'run_id', 'attempt', 'job', 'head', 'base', 'commit', 'tree', 'inputs_sha256'}
            or value['version'] != (2 if owner else 1) or value['repository'] != repository
            or value['run_id'] != run_id or value['attempt'] != attempt
            or value['job'] != contract['integration_job'] or value['head'] != head or value['base'] != base
            or not SHA.fullmatch(value['commit']) or not SHA.fullmatch(value['tree'])
            or not re.fullmatch('[a-f0-9]{64}', value['inputs_sha256'])):
        raise ValueError('CI tested a different integration or base')
    commit = run(['gh', 'api', f"repos/{repository}/git/commits/{value['commit']}"])
    if (commit.get('sha') != value['commit'] or commit.get('tree', {}).get('sha') != value['tree']
            or (owner and (value['commit'] != head or not 1 <= len(commit.get('parents', [])) <= 2
                           or commit['parents'][0].get('sha') != base))
            or (not owner and [parent.get('sha') for parent in commit.get('parents', [])] != [base, head])):
        raise ValueError('integration receipt differs from immutable Git objects')
    return {**value,'artifact_id':artifact['id']}


def execute(request, policy, run=command):
    if not isinstance(request, dict):
        raise ValueError('operator request must be an object')
    operation = request.get('operation')
    if operation == 'merge':
        checked_repository(policy, request.get('repository', ''))
        with repository_lock(request['repository']):
            return execute_merge(request, policy, run)
    if operation == 'authorize_owner':
        checked_repository(policy, request.get('repository', ''))
        with repository_lock(request['repository']):
            return execute_owner(request, policy, run)
    if operation == 'delivery':
        fields(request, ('operation', 'repository', 'revision'))
        repo, revision = request['repository'], request['revision']
        checked_repository(policy, repo)
        if not isinstance(revision, str) or not SHA.fullmatch(revision):
            raise ValueError('delivery requires an exact merge revision')
        result = run(['gh', 'api', f'repos/{repo}/actions/workflows/cd.yml/runs?branch=main&head_sha={revision}&per_page=100'])
        runs = [row for row in result['workflow_runs'] if row.get('head_sha') == revision and row.get('head_branch') == 'main']
        latest = runs[0] if runs else None
        return {'operation': operation, 'repository': repo, 'revision': revision,
                'status': latest.get('status') if latest else 'missing',
                'conclusion': latest.get('conclusion') if latest else None,
                'run_id': latest.get('id') if latest else None,
                'scope': 'CD evidence only; authenticated journeys and recovery require separate acceptance.'}
    if operation == 'host_report':
        fields(request, ('operation', 'host'))
        host = request['host']
        if host not in policy['hosts']:
            raise ValueError('host is outside operator scope')
        result = run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                      '-o', 'UpdateHostKeys=no', '-o', 'ForwardAgent=no', 'root@'+host, 'komizo-box report'])
        return {'operation': operation, 'host': host,
                'apps': [{key: app.get(key) for key in ('name', 'version', 'stopped')}
                         for app in result.get('apps', [])]}
    raise ValueError('unsupported operator action')


def execute_merge(request, policy, run):
    fields(request, ('operation', 'repository', 'pull_request', 'head'))
    repo, number, head = request['repository'], request['pull_request'], request['head']
    checked_repository(policy, repo)
    if type(number) is not int or number <= 0 or not isinstance(head, str) or not SHA.fullmatch(head):
        raise ValueError('merge requires a PR number and exact reviewed head')
    pr = run(['gh', 'api', f'repos/{repo}/pulls/{number}'])
    if (pr['state'] != 'open' or pr['draft'] or pr['base']['ref'] != 'main'
            or pr['head']['sha'] != head or pr['head']['repo']['full_name'] != repo):
        raise ValueError('PR identity differs from reviewed operator scope')
    check_evidence = run(['gh', 'pr', 'view', str(number), '--repo', repo, '--json', 'headRefOid,statusCheckRollup'])
    if check_evidence['headRefOid'] != head:
        raise ValueError('head changed before CI verification')
    checks = check_evidence['statusCheckRollup']
    present = set()
    for check in checks:
        name = check.get('name') or check.get('context')
        if check.get('__typename') == 'StatusContext':
            passed = check.get('state') == 'SUCCESS'
            done = check.get('state') in ('SUCCESS', 'FAILURE', 'ERROR')
            skipped = False
        else:
            done = check.get('status') == 'COMPLETED'
            passed = check.get('conclusion') == 'SUCCESS'
            skipped = check.get('conclusion') in ('SKIPPED', 'NEUTRAL')
        if not done or not (passed or skipped):
            raise ValueError('CI is pending or failed')
        if passed:
            present.add(name)
    run_id = authenticate_ci(repo, head, policy['repositories'][repo], checks, run)
    base = run(['gh', 'api', f'repos/{repo}/git/ref/heads/main'])['object']['sha']
    if not SHA.fullmatch(base): raise ValueError('invalid current merge base')
    integration = authenticate_integration(repo, head, base, run_id, policy['repositories'][repo], run)
    review_contract(repo, number, head, run)
    if run(['gh', 'api', f'repos/{repo}/git/ref/heads/main'])['object']['sha'] != base:
        raise ValueError('main advanced after integration verification')
    run(['gh', 'pr', 'merge', str(number), '--repo', repo, '--merge', '--match-head-commit', head])
    merged = run(['gh', 'api', f'repos/{repo}/pulls/{number}'])
    if not merged.get('merged') or merged['head']['sha'] != head:
        raise ValueError('merge outcome is unverified')
    commit = run(['gh', 'api', f"repos/{repo}/git/commits/{merged['merge_commit_sha']}"])
    if ([parent.get('sha') for parent in commit.get('parents', [])] != [base, head]
            or commit.get('tree', {}).get('sha') != integration['tree']):
        raise ValueError('merged integration differs; delivery authorization refused')
    delivery=authorize_delivery(repo, merged['merge_commit_sha'], integration, policy, run)
    return {'delivery_authorized':delivery, 'operation': 'merge', 'repository': repo, 'head': head,
            'merge_revision': merged['merge_commit_sha'], 'tested_base': base, 'tested_tree': integration['tree'], 'status': 'source_merged'}

def execute_owner(request, policy, run):
    """Authorize explicitly reviewed direct-main source using its actual CI tree.

    This is an additional owner route; it never substitutes main jobs for PR
    merge gates. A completed Test/Build may precede publication in a running CD,
    but every named check must authenticate to this same current run attempt.
    """
    fields(request, ('operation', 'repository', 'revision', 'run_id'))
    repo, revision, run_id = request['repository'], request['revision'], request['run_id']
    if not isinstance(revision, str) or not SHA.fullmatch(revision) or type(run_id) is not int or run_id <= 0:
        raise ValueError('owner delivery requires the exact source and CI run')
    contract = policy.get('owner_workflows', {}).get(repo)
    if contract is None or repo not in policy.get('deployments', {}):
        raise ValueError('owner delivery requires a separately approved main workflow and host binding')
    ref = ['gh', 'api', f'repos/{repo}/git/ref/heads/main']
    if run(ref)['object']['sha'] != revision:
        raise ValueError('owner revision is no longer current main')
    commit = run(['gh', 'api', f'repos/{repo}/git/commits/{revision}'])
    parents = commit.get('parents', [])
    if commit.get('sha') != revision or not 1 <= len(parents) <= 2 or not SHA.fullmatch(parents[0].get('sha', '')):
        raise ValueError('owner source has an unsupported immutable parent identity')
    evidence = run(['gh', 'api', f'repos/{repo}/commits/{revision}/check-runs?per_page=100'])
    if evidence.get('total_count', 0) >= 100:
        raise ValueError('owner check evidence exceeds its bound')
    checks = [{'__typename':'CheckRun', 'name':c.get('name'),
               'status':str(c.get('status', '')).upper(), 'conclusion':str(c.get('conclusion', '')).upper(),
               'detailsUrl':c.get('details_url')} for c in evidence['check_runs']]
    if authenticate_ci(repo, revision, contract, checks, run, allow_running=True) != run_id:
        raise ValueError('owner checks belong to a different CI run')
    integration = authenticate_integration(repo, revision, parents[0]['sha'], run_id, contract, run, owner=True)
    review = private_json(Path('/etc/fleet-owner-reviews')/(revision+'.json'))
    expected = {'version':1, 'repository':repo, 'revision':revision, 'tree':integration['tree'],
                'ci_run_id':run_id, 'ci_attempt':integration['attempt'],
                'integration_artifact_id':integration['artifact_id'], 'inputs_sha256':integration['inputs_sha256'],
                'owner_authorized':True}
    if review != expected:
        raise ValueError('protected owner review differs from the actual tested main source')
    if run(ref)['object']['sha'] != revision:
        raise ValueError('main advanced before owner delivery authorization')
    authorized = authorize_delivery(repo, revision, integration, policy, run, kind='owner')
    return {'operation':'authorize_owner', 'repository':repo, 'revision':revision,
            'tested_tree':integration['tree'], 'delivery_authorized':authorized}


def authorize_delivery(repository, revision, integration, policy, run, kind='merge'):
    binding=policy.get('deployments',{}).get(repository)
    if binding is None:return False
    if not SHA.fullmatch(revision):raise ValueError('invalid actual merge revision')
    now=datetime.now(timezone.utc)
    authorization={'version':1,'repository':repository,'repository_id':binding['repository_id'],
        'app':binding['app'],'revision':revision,'tree':integration['tree'],'head':integration['head'],
        'base':integration['base'],'ci_run_id':integration['run_id'],'ci_attempt':integration['attempt'],
        'integration_artifact_id':integration['artifact_id'],'inputs_sha256':integration['inputs_sha256'],
        'kind':kind,'scope':'production-delivery','issued_at':now.isoformat(),
        'expires_at':(now+timedelta(hours=4)).isoformat()}
    wire=base64.b64encode(json.dumps(authorization,sort_keys=True).encode()).decode()
    # All command structure and destinations come from protected policy. The
    # only wire argument is bounded base64 nonsecret authorization metadata.
    remote='komizo-box workload delivery-authorize --policy /etc/komizo/workloads/'+binding['app']+'.json --authorization '+wire
    run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
         '-o','UpdateHostKeys=no','-o','ForwardAgent=no','root@'+binding['host'],remote])
    retain_delivery(authorization)
    return True


def retain_delivery(authorization):
    import importlib.util
    spec = importlib.util.spec_from_file_location('protected_publisher', Path(__file__).with_name('fleet_publisher.py'))
    publisher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(publisher)
    publisher.persist_delivery(authorization)

def inspect_outcome(request, policy, run=command):
    """Observe an interrupted merge; this route cannot merge or replay effects."""
    if request.get('operation') == 'authorize_owner':
        return {'status':'ambiguous', 'scope':'inspect the protected host authorization; owner issuance cannot be automatically replayed'}
    if request.get('operation')!='merge':
        return {'status':'failed','scope':'read-only operation can be requested with a fresh grant'}
    fields(request, ('operation','repository','pull_request','head'))
    repo,head,number=request['repository'],request['head'],request['pull_request']
    checked_repository(policy,repo)
    if not SHA.fullmatch(head) or type(number) is not int or number<=0:raise ValueError('invalid inspected merge')
    pr=run(['gh','api',f'repos/{repo}/pulls/{number}'])
    if pr['head']['sha']!=head:
        return {'status':'ambiguous','reason':'PR head changed; manual review required'}
    if not pr.get('merged'):
        return {'status':'failed','reason':'GitHub confirms this PR is not merged','pr_state':pr['state']}
    revision=pr.get('merge_commit_sha','')
    if not SHA.fullmatch(revision):raise ValueError('merge outcome revision missing')
    commit=run(['gh','api',f'repos/{repo}/git/commits/{revision}'])
    if commit.get('sha')!=revision or not SHA.fullmatch(commit.get('tree',{}).get('sha','')):
        raise ValueError('immutable outcome unavailable')
    return {'status':'completed','merge_revision':revision,'tree':commit['tree']['sha'],
            'scope':'observed source outcome only; no delivery authorization or effects issued'}

def main():
    body = sys.stdin.buffer.read(MAX_BYTES+1)
    if len(body) > MAX_BYTES:
        raise ValueError('operator request exceeds its size bound')
    result = execute(json.loads(body), private_policy(POLICY))
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        # Never forward captured command output or policy/credential contents.
        print('operator refused: '+str(error), file=sys.stderr)
        raise SystemExit(1)
