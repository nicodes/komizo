"""Root-only, single-use publication of authenticated classic Docker archives.

The delivery receipt and policy are protected operator state, never request
fields. Product Actions must separately have Read package access. This program
does not claim that registry ACLs have been configured or that Root is isolated.
"""
import contextlib
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

spec = importlib.util.spec_from_file_location('protected_operator', Path(__file__).with_name('fleet_operator.py'))
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)

POLICY = Path('/etc/fleet-publisher.json')
STATE = Path('/var/lib/fleet-publisher')
DELIVERIES = Path('/var/lib/fleet-operator/deliveries')
MAX_ARCHIVE = 4 * 1024**3
MAX_EXPANDED = 16 * 1024**3
MAX_JSON = 65536
LIFETIME = 900
OWNER = 0
DOCKER = ('/usr/bin/docker',)
RUNTIME = Path('/run/fleet-publisher')
SHA256 = re.compile(r'[a-f0-9]{64}\Z')
IMAGE = re.compile(r'ghcr\.io/[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*\Z')


def protected_directory(path):
    if not path.is_absolute() or path != Path(os.path.abspath(path)):
        raise ValueError('publisher path must be absolute and canonical')
    for parent in (path, *path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o022:
            raise ValueError('publisher ancestry must be protected and root-owned')


@contextlib.contextmanager
def protected_file(path, maximum):
    protected_directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o077 or not 0 < info.st_size <= maximum:
            raise ValueError('publisher input must be private, regular and bounded')
        yield stream


def private_json(path):
    with protected_file(path, MAX_JSON) as stream:
        return json.load(stream)


def digest(stream, deadline, maximum):
    value = hashlib.sha256()
    total = 0
    while True:
        if time.monotonic() >= deadline:
            raise ValueError('publisher validation exceeded its deadline')
        body = stream.read(65536)
        if not body:
            return value.hexdigest()
        total += len(body)
        if total > maximum:
            raise ValueError('publisher stream exceeds its bound')
        value.update(body)


def atomic(path, value):
    protected_directory(path.parent)
    if path.is_symlink():
        raise ValueError('linked publication state refused')
    descriptor, temporary = tempfile.mkstemp(prefix='.publisher-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write((json.dumps(value, sort_keys=True) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)


def persist_delivery(value):
    """Retain the observed host grant for the separate publication boundary."""
    key = hashlib.sha256(value['repository'].encode()).hexdigest()
    directory = DELIVERIES/key
    # Never mkdir through an unchecked existing ancestor.
    missing = []
    parent = directory
    while not parent.exists():
        if parent.is_symlink():
            raise ValueError('linked delivery state refused')
        missing.append(parent)
        parent = parent.parent
    protected_directory(parent)
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
    protected_directory(directory)
    path = directory/(value['revision']+'.json')
    if path.exists() or path.is_symlink():
        if private_json(path) != value:
            raise ValueError('prior delivery differs; inspect without automatic renewal')
        return
    atomic(path, value)


def policy(path=POLICY):
    value = private_json(path)
    if set(value) != {'version', 'repositories'} or value['version'] != 1 or not isinstance(value['repositories'], dict):
        raise ValueError('unsupported publisher policy')
    for repository, contract in value['repositories'].items():
        if (not operator.REPOSITORY.fullmatch(repository)
                or not isinstance(contract, dict) or set(contract) != {'workflow', 'images', 'username', 'credential'}
                or not isinstance(contract['workflow'], dict)
                or not isinstance(contract['images'], list) or not 1 <= len(contract['images']) <= 8
                or len(set(contract['images'])) != len(contract['images'])
                or any(not IMAGE.fullmatch(image) or image.split('/')[1] != repository.split('/')[0].lower()
                       for image in contract['images'])
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}', contract['username'])
                or not isinstance(contract['credential'], str) or not contract['credential'].startswith('/')
                or contract['workflow'].get('event') not in ('push', 'workflow_dispatch')
                or not 1 <= len(contract['workflow'].get('jobs', [])) <= 8):
            raise ValueError('publisher needs finite protected source, producer and image scopes')
        # Reuse the operator's complete producer contract validation.
        operator_contract = {'version': 3, 'repositories': {repository: {**contract['workflow'], 'event': 'pull_request'}}, 'hosts': []}
        operator.validate_policy(operator_contract)
    return value


def authenticate(request, contract, grant, run):
    repository, revision = request['repository'], request['revision']
    now = datetime.now(timezone.utc)
    issued, expires = (datetime.fromisoformat(grant[field]) for field in ('issued_at', 'expires_at'))
    if (grant.get('version') != 1 or grant.get('repository') != repository or grant.get('revision') != revision
            or grant.get('scope') != 'production-delivery' or grant.get('kind') not in ('merge', 'owner')
            or issued.tzinfo is None or expires.tzinfo is None or issued > now or expires <= now
            or not 0 < (expires-issued).total_seconds() <= 14400):
        raise ValueError('protected final delivery authorization missing, expired or different')
    commit = run(['gh', 'api', f'repos/{repository}/git/commits/{revision}'])
    parents = [parent['sha'] for parent in commit.get('parents', [])]
    expected = [grant['base'], grant['head']] if grant['kind'] == 'merge' else None
    if (commit.get('sha') != revision or commit.get('tree', {}).get('sha') != grant['tree']
            or expected is not None and parents != expected
            or expected is None and (not 1 <= len(parents) <= 2 or parents[0] != grant['base'] or grant['head'] != revision)):
        raise ValueError('actual final source parents or tree differ from protected delivery')
    current_main(repository, revision, run)
    checks = run(['gh', 'api', f'repos/{repository}/commits/{revision}/check-runs?per_page=100'])
    if checks.get('total_count', 0) >= 100:
        raise ValueError('publication check evidence exceeds its bound')
    rows = [{'__typename': 'CheckRun', 'name': row.get('name'), 'status': str(row.get('status', '')).upper(),
             'conclusion': str(row.get('conclusion', '')).upper(), 'detailsUrl': row.get('details_url')}
            for row in checks['check_runs']]
    if operator.authenticate_ci(repository, revision, contract['workflow'], rows, run, allow_running=True) != request['run_id']:
        raise ValueError('publication belongs to a different authenticated CI run')
    workflow = run(['gh', 'api', f"repos/{repository}/actions/runs/{request['run_id']}"])
    artifact = run(['gh', 'api', f"repos/{repository}/actions/artifacts/{request['artifact_id']}"])
    if (artifact.get('id') != request['artifact_id'] or artifact.get('expired')
            or artifact.get('name') != f"fleet-publication-{request['run_id']}-{workflow['run_attempt']}"
            or artifact.get('workflow_run', {}).get('id') != request['run_id']
            or artifact.get('workflow_run', {}).get('head_sha') != revision
            or not 0 < artifact.get('size_in_bytes', 0) <= MAX_ARCHIVE
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', artifact.get('digest', ''))):
        raise ValueError('publication artifact has no exact immutable producer identity')
    return workflow['run_attempt'], artifact['digest'].removeprefix('sha256:')


def current_main(repository, revision, run):
    if run(['gh', 'api', f'repos/{repository}/git/ref/heads/main'])['object']['sha'] != revision:
        raise ValueError('main advanced before publication')


def image_archive(path, expected, revision, repository, deadline):
    """Validate classic Docker save without extracting tar paths or executing code."""
    with tarfile.open(path, mode='r:') as archive:
        entries = {}
        total = 0
        for entry in archive:
            name = PurePosixPath(entry.name)
            if (name.is_absolute() or '..' in name.parts or str(name) != entry.name.rstrip('/')
                    or entry.name in entries or not (entry.isfile() or entry.isdir())):
                raise ValueError('image archive contains linked, repeated or unsafe entries')
            total += entry.size
            if len(entries) >= 10000 or total > MAX_EXPANDED or time.monotonic() >= deadline:
                raise ValueError('image archive exceeds validation bounds')
            entries[entry.name] = entry
        def small(name):
            entry = entries.get(name)
            if entry is None or not entry.isfile() or not 0 < entry.size <= MAX_JSON:
                raise ValueError('image metadata missing or oversized')
            return archive.extractfile(entry).read(MAX_JSON + 1)
        manifests = json.loads(small('manifest.json'))
        if not isinstance(manifests, list) or not 1 <= len(manifests) <= 8:
            raise ValueError('unsupported image manifest count')
        observed = {}
        used = {'manifest.json'}
        for manifest in manifests:
            if set(manifest) != {'Config', 'RepoTags', 'Layers'} or not isinstance(manifest['RepoTags'], list) or len(manifest['RepoTags']) != 1:
                raise ValueError('images require one exact publication tag')
            reference = manifest['RepoTags'][0]
            used.add(manifest['Config'])
            body = small(manifest['Config'])
            configuration = json.loads(body)
            config_digest = hashlib.sha256(body).hexdigest()
            labels = configuration.get('config', {}).get('Labels', {})
            if (reference in observed or expected.get(reference) != config_digest
                    or configuration.get('os') != 'linux' or configuration.get('architecture') != 'amd64'
                    or labels.get('org.opencontainers.image.revision') != revision
                    or labels.get('org.opencontainers.image.source') != 'https://github.com/' + repository):
                raise ValueError('image configuration, source or finite destination differs')
            layers = manifest['Layers']
            diff_ids = configuration.get('rootfs', {}).get('diff_ids', [])
            if not isinstance(layers, list) or not 1 <= len(layers) <= 128 or len(layers) != len(diff_ids):
                raise ValueError('unsupported image layer contract')
            for layer, wanted in zip(layers, diff_ids):
                used.add(layer)
                entry = entries.get(layer)
                if entry is None or not entry.isfile():
                    raise ValueError('image layer missing')
                with archive.extractfile(entry) as stream:
                    if 'sha256:' + digest(stream, deadline, MAX_EXPANDED) != wanted:
                        raise ValueError('image layer content differs from configuration')
            observed[reference] = config_digest
        if observed != expected:
            raise ValueError('publication archive has an incomplete destination set')
        if any(entry.isfile() and name not in used for name, entry in entries.items()):
            raise ValueError('unreferenced image archive bytes refused')
    return observed


def prepare_artifact(stream, archive_sha, request, contract, grant, attempt, directory, deadline):
    if digest(stream, deadline, MAX_ARCHIVE) != archive_sha:
        raise ValueError('prepared artifact differs from authenticated GitHub digest')
    stream.seek(0)
    with zipfile.ZipFile(stream) as archive:
        entries = archive.infolist()
        if len(entries) != 2 or {entry.filename for entry in entries} != {'release.json', 'images.tar'}:
            raise ValueError('publication artifact requires exactly release.json and images.tar')
        if not 0 < archive.getinfo('release.json').file_size <= MAX_JSON or not 0 < archive.getinfo('images.tar').file_size <= MAX_ARCHIVE:
            raise ValueError('publication artifact expanded size exceeds bound')
        manifest = json.loads(archive.read('release.json'))
        if (set(manifest) != {'version', 'repository', 'revision', 'tree', 'run_id', 'attempt', 'images'}
                or manifest['version'] != 1 or manifest['repository'] != request['repository']
                or manifest['revision'] != request['revision'] or manifest['tree'] != grant['tree']
                or manifest['run_id'] != request['run_id'] or manifest['attempt'] != attempt
                or not isinstance(manifest['images'], dict) or not manifest['images']
                or not set(manifest['images']) <= {image + ':' + request['revision'] for image in contract['images']}
                or any(not isinstance(value, str) or not SHA256.fullmatch(value) for value in manifest['images'].values())):
            raise ValueError('publication manifest differs from final tested source or allowed images')
        image_path = directory/'images.tar'
        with archive.open('images.tar') as source, image_path.open('xb') as target:
            total = 0
            while chunk := source.read(65536):
                total += len(chunk)
                if total > MAX_ARCHIVE or time.monotonic() >= deadline:
                    raise ValueError('image extraction exceeds its bound')
                target.write(chunk)
        image_path.chmod(0o600)
        image_archive(image_path, manifest['images'], request['revision'], request['repository'], deadline)
    return image_path, manifest['images']


def docker(arguments, configuration, deadline, body=None):
    executable = Path(DOCKER[0])
    info = executable.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('publisher executable is not protected')
    remaining = min(300, deadline-time.monotonic())
    if remaining <= 0:
        raise ValueError('publication deadline exceeded')
    process = subprocess.Popen([*DOCKER, '--config', str(configuration), *arguments],
                               stdin=subprocess.PIPE if body is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
                               cwd='/', env={'PATH': '/usr/bin:/bin', 'HOME': str(configuration), 'LC_ALL': 'C'})
    try:
        if body is not None:
            # Only the <=4 KiB credential uses stdin. Artifacts use a private file.
            process.stdin.write(body)
            process.stdin.close()
            process.stdin = None
        output = bytearray()
        end = time.monotonic() + remaining
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                left = end-time.monotonic()
                if left <= 0:
                    raise ValueError('registry command exceeded its deadline')
                for key, _ in selector.select(left):
                    chunk = os.read(key.fd, min(65536, MAX_JSON+1-len(output)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(chunk)
                    if len(output) > MAX_JSON:
                        raise ValueError('registry output exceeds its bound')
        process.wait(timeout=max(.001, end-time.monotonic()))
        if process.returncode:
            raise ValueError('registry command refused; inspect publication state')
        return bytes(output)
    finally:
        # Kill descendants even when the immediate client exited first.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
        if process.stdin is not None:
            process.stdin.close()


def registry_login(contract, directory, deadline, transport):
    with protected_file(Path(contract['credential']), 4096) as stream:
        credential = stream.read(4097).strip()
    if not credential or b'\n' in credential or b'\r' in credential or len(credential) > 4096:
        raise ValueError('registry credential has an unsupported shape')
    transport(['login', 'ghcr.io', '--username', contract['username'], '--password-stdin'], directory, deadline, credential)


@contextlib.contextmanager
def registry_configuration():
    """Refuse disk-backed credential storage, including on process death."""
    protected_directory(RUNTIME.parent)
    if not RUNTIME.exists():
        RUNTIME.mkdir(mode=0o700)
    protected_directory(RUNTIME)
    if RUNTIME.stat().st_mode & 0o077:
        raise ValueError('registry runtime directory is not private')
    mounts = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        before, after = line.split(' - ', 1)
        mount = before.split()[4]
        # Only canonical unescaped ancestors are valid for this fixed path.
        if '\\' not in mount and RUNTIME.is_relative_to(Path(mount)):
            mounts.append((len(mount), after.split()[0]))
    if not mounts or max(mounts)[1] != 'tmpfs':
        raise ValueError('registry credentials require protected volatile storage')
    with tempfile.TemporaryDirectory(prefix='registry-', dir=RUNTIME) as directory:
        yield Path(directory)


def execute(request, protected_policy, run=operator.command, transport=docker):
    if not isinstance(request, dict):
        raise ValueError('publisher request must be an object')
    if request.get('operation') in ('inspect', 'reconcile'):
        return inspect(request, protected_policy, transport)
    operator.fields(request, {'operation', 'repository', 'revision', 'run_id', 'artifact_id'})
    repository, revision = request['repository'], request['revision']
    if (request['operation'] != 'publish' or repository not in protected_policy['repositories'] or not isinstance(revision, str) or not operator.SHA.fullmatch(revision)
            or any(type(request[field]) is not int or request[field] <= 0 for field in ('run_id', 'artifact_id'))):
        raise ValueError('publication request is outside protected scope')
    contract = protected_policy['repositories'][repository]
    key = hashlib.sha256(repository.encode()).hexdigest()
    deadline = time.monotonic() + LIFETIME
    original_run = run
    def bounded_run(arguments):
        if time.monotonic() >= deadline:
            raise ValueError('publication evidence exceeded its deadline')
        value = original_run(arguments)
        if time.monotonic() >= deadline:
            raise ValueError('publication evidence exceeded its deadline')
        return value
    run = bounded_run
    with operator.repository_lock(repository):
        protected_directory(STATE)
        grant = private_json(DELIVERIES/key/(revision+'.json'))
        journal = STATE/(key+'-'+revision+'.json')
        if journal.exists() or journal.is_symlink():
            raise ValueError('publication already claimed; inspect and reconcile without retry')
        attempt, archive_sha = authenticate(request, contract, grant, run)
        with tempfile.TemporaryDirectory(prefix='.publication-', dir=STATE) as directory:
            directory = Path(directory)
            with protected_file(STATE/'artifacts'/(str(request['artifact_id'])+'.zip'), MAX_ARCHIVE) as stream:
                image_path, images = prepare_artifact(stream, archive_sha, request, contract, grant, attempt, directory, deadline)
            current_main(repository, revision, run)
            record = {'version': 1, **request, 'attempt': attempt, 'archive_sha256': archive_sha,
                      'tree': grant['tree'], 'images': images, 'status': 'claimed', 'published': {}}
            atomic(journal, record)
            try:
                with registry_configuration() as configuration_directory:
                    transport(['load', '--input', str(image_path)], configuration_directory, deadline)
                    current_main(repository, revision, run)
                    # No secret access until exact source, producer and all bytes pass.
                    registry_login(contract, configuration_directory, deadline, transport)
                    for reference, configuration in images.items():
                        current_main(repository, revision, run)
                        if datetime.fromisoformat(grant['expires_at']) <= datetime.now(timezone.utc):
                            raise ValueError('delivery expired before upload')
                        record['status'] = 'uploading'
                        record['uploading'] = reference
                        atomic(journal, record)
                        pushed = transport(['push', reference], configuration_directory, deadline)
                        identities = re.findall(rb'digest: (sha256:[a-f0-9]{64}) size: [1-9][0-9]*', pushed)
                        if len(identities) != 1:
                            raise ValueError('push result has no unique manifest identity')
                        manifest_digest = identities[0].decode()
                        remote = json.loads(transport(['manifest', 'inspect', reference.split(':')[0]+'@'+manifest_digest], configuration_directory, deadline))
                        if remote.get('config', {}).get('digest') != 'sha256:' + configuration:
                            raise ValueError('registry configuration differs; reconcile without retry')
                        record['published'][reference] = {'config_digest': 'sha256:' + configuration, 'manifest_digest': manifest_digest}
                        atomic(journal, record)
                record['status'] = 'completed'
                record.pop('uploading', None)
                atomic(journal, record)
                return record
            except BaseException:
                record['status'] = 'ambiguous'
                atomic(journal, record)
                raise


def inspect(request, protected_policy, transport=docker):
    operator.fields(request, {'operation', 'repository', 'revision'})
    repository, revision = request['repository'], request['revision']
    if repository not in protected_policy['repositories'] or not isinstance(revision, str) or not operator.SHA.fullmatch(revision):
        raise ValueError('publication inspection is outside protected scope')
    key = hashlib.sha256(repository.encode()).hexdigest()
    with operator.repository_lock(repository):
        journal = STATE/(key+'-'+revision+'.json')
        record = private_json(journal)
        if request['operation'] == 'inspect':
            if record['status'] not in ('completed', 'reconciled'):
                return {**record, 'status': 'ambiguous', 'persisted_status': record['status']}
            return record
        if record['repository'] != repository or record['revision'] != revision or record['status'] == 'completed':
            raise ValueError('only an incomplete exact publication can be reconciled')
        contract = protected_policy['repositories'][repository]
        if not set(record['images']) <= {image+':'+revision for image in contract['images']}:
            raise ValueError('retained destinations differ from protected policy')
        deadline = time.monotonic()+LIFETIME
        found = {}
        with registry_configuration() as directory:
            registry_login(contract, directory, deadline, transport)
            for reference, configuration in record['images'].items():
                remote = json.loads(transport(['manifest', 'inspect', '--verbose', reference], directory, deadline))
                if (not isinstance(remote, dict) or remote.get('SchemaV2Manifest', {}).get('config', {}).get('digest') != 'sha256:'+configuration
                        or not re.fullmatch(r'sha256:[a-f0-9]{64}', remote.get('Descriptor', {}).get('digest', ''))):
                    raise ValueError('registry identity remains ambiguous; no upload replayed')
                found[reference] = {'config_digest': 'sha256:'+configuration, 'manifest_digest': remote['Descriptor']['digest']}
        record['published'] = found
        record['status'] = 'reconciled'
        record.pop('uploading', None)
        atomic(journal, record)
        return record


def main():
    if os.geteuid() != 0:
        raise ValueError('publication requires the trusted root operator')
    request = json.loads(sys.stdin.buffer.read(MAX_JSON + 1))
    print(json.dumps(execute(request, policy()), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile, tarfile.TarError, json.JSONDecodeError):
        print('publisher refused; inspect protected publication state', file=sys.stderr)
        raise SystemExit(1)
