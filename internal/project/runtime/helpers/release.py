#!/usr/bin/env python3
"""Record and publish the exact container images validated by the Build gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

# Artifact adapters also import this module by file path. Resolve its sibling
# from the verified snapshot rather than the caller's cwd or PYTHONPATH.
_contract_spec = importlib.util.spec_from_file_location(
    '_engineering_release_contract', Path(__file__).resolve().with_name('contract.py'))
contract = importlib.util.module_from_spec(_contract_spec)
_contract_spec.loader.exec_module(contract)

_stateful_spec = importlib.util.spec_from_file_location(
    '_engineering_stateful_release', Path(__file__).resolve().with_name('stateful_release.py'))
stateful_release = importlib.util.module_from_spec(_stateful_spec)
_stateful_spec.loader.exec_module(stateful_release)


def digest(file):
    with file.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def references(project, revision, components, image_base):
    if not re.fullmatch(r'[a-z][a-z0-9-]*', project):
        raise ValueError('invalid project name')
    if not re.fullmatch(r'[a-f0-9]{40}', revision):
        raise ValueError('release revision must be a full commit')
    if not components or len(set(components)) != len(components):
        raise ValueError('a release needs distinct image components')
    if any(not re.fullmatch(r'[a-z][a-z0-9-]*', component) for component in components):
        raise ValueError('invalid image component')
    if not re.fullmatch(r'[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9][a-z0-9/._-]*', image_base):
        raise ValueError('image base must be an explicit registry repository prefix')
    return [f'{image_base}-{component}:{revision}' for component in components]



def inspect(refs):
    images = json.loads(subprocess.check_output(['docker', 'image', 'inspect', *refs], timeout=60))
    if len(images) != len(refs):
        raise ValueError('Docker did not return every release image')
    result = {}
    for ref, image in zip(refs, images, strict=True):
        if ref not in image.get('RepoTags', []) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image['Id']):
            raise ValueError(f'image identity is missing: {ref}')
        result[ref] = image['Id']
    return result


def validate(manifest, project, revision, components, archive, image_base):
    refs = references(project, revision, components, image_base)
    if manifest.get('revision') != revision or manifest.get('project') != project:
        raise ValueError('release belongs to another project or commit')
    if 'stateful_contract' in manifest:
        stateful_release.validate(manifest['stateful_contract'], revision)
    if set(manifest.get('images', {})) != set(refs):
        raise ValueError('release image set differs from the declared components')
    if not all(re.fullmatch(r'sha256:[a-f0-9]{64}', value) for value in manifest['images'].values()):
        raise ValueError('release image ID is invalid')
    if not archive.is_file() or archive.is_symlink() or manifest.get('archive_sha256') != digest(archive):
        raise ValueError('release archive is missing or differs from the validated artifact')
    return refs


# Only public execution identifiers are recorded. Build environment values are
# hashed by the engineering contract, never included in this manifest.
CONTEXT_KEYS = contract.CONTEXT_KEYS


def source_binding():
    return contract.checkout_binding()


def source_relationship(revision):
    relationship = {'source_commit': revision, 'workflow_commit': os.environ.get('GITHUB_SHA') or None,
                    'pull_request_head': None, 'pull_request_base': None, 'pull_request_merge': None}
    event_path = os.environ.get('GITHUB_EVENT_PATH')
    if event_path:
        request = json.loads(Path(event_path).read_text()).get('pull_request')
        if request is not None:
            values = {'pull_request_head': request.get('head', {}).get('sha'),
                      'pull_request_base': request.get('base', {}).get('sha'),
                      'pull_request_merge': request.get('merge_commit_sha')}
            for key, value in values.items():
                if value is not None and (not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{40}', value)):
                    raise ValueError('invalid pull-request commit relationship')
                relationship[key] = value
    return relationship


def build_provenance(revision):
    return {'version': 1, 'source_commit': revision, **source_binding(),
            'input_identity': contract.identity(contract.load(contract.default_manifest())),
            # Build and Test may use different jobs/checkouts. Do not claim
            # head was tested merely because a workflow tests a merge commit.
            'tested_commit': None, 'source_relationship': source_relationship(revision),
            'build_context': {key: os.environ[key] for key in CONTEXT_KEYS if os.environ.get(key)}}


def validate_provenance(manifest, revision):
    relationship = source_relationship(revision)
    workflow = os.environ.get('GITHUB_SHA')
    if workflow and workflow != revision:
        if os.environ.get('GITHUB_EVENT_NAME') != 'pull_request' or relationship['pull_request_head'] != revision:
            raise ValueError('publisher source is neither its workflow commit nor its authenticated PR head')
    proof = manifest.get('provenance')
    if not isinstance(proof, dict) or type(proof.get('version')) is not int or proof['version'] != 1 or proof.get('source_commit') != revision:
        raise ValueError('release has no matching build source provenance; rebuild with this engineering baseline')
    if proof.get('tracked_source_clean') is not True:
        raise ValueError('release was built from modified tracked source; rebuild the committed source')
    binding = source_binding()
    if any(proof.get(key) != value for key, value in binding.items()):
        raise ValueError('release source tree or pinned configuration differs from the publisher checkout')
    if not isinstance(proof.get('input_identity'), str) or not re.fullmatch(r'[a-f0-9]{64}', proof['input_identity']):
        raise ValueError('release has no valid build input identity')
    context = proof.get('build_context')
    if not isinstance(context, dict) or set(context) - set(CONTEXT_KEYS) or any(not isinstance(value, str) or not value for value in context.values()):
        raise ValueError('invalid build execution context')
    # A failed publish can be retried using the prior successful Build artifact
    # in the same run. Different runs/repositories are never interchangeable.
    for key in ('GITHUB_SERVER_URL', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_SHA'):
        if context.get(key) != (os.environ.get(key) or None):
            raise ValueError('release artifact belongs to another workflow execution')
    if proof.get('source_relationship') != relationship:
        raise ValueError('build and publisher disagree about the PR source relationship')
    built, current = context.get('GITHUB_RUN_ATTEMPT'), os.environ.get('GITHUB_RUN_ATTEMPT')
    if built or current:
        if not built or not current or not built.isdecimal() or not current.isdecimal() or not 1 <= int(built) <= int(current):
            raise ValueError('release artifact has an invalid workflow attempt')
    return proof


def validate_test_evidence(directory, revision, expected_job):
    if directory.is_symlink() or any(parent.is_symlink() for parent in directory.parents):
        raise ValueError('test evidence directory must not be a symlink')
    files = sorted(directory.rglob('test.json')) if directory.is_dir() else []
    if not files:
        raise ValueError('publication needs completed applicable test evidence for this source')
    declaration = contract.load(contract.default_manifest())
    applicable = {name for name in ('unit', 'integration') if isinstance(declaration['stages'][name], list)}
    if not applicable:
        raise ValueError('publication cannot claim testing when every test stage is inapplicable')
    binding = source_binding()
    proofs = []
    for file in files:
        if file.is_symlink() or any(parent.is_symlink() for parent in file.parents):
            raise ValueError('test evidence must be a regular artifact')
        proof = json.loads(file.read_text())
        if not isinstance(proof, dict) or type(proof.get('version')) is not int or proof['version'] != 1 or proof.get('source_commit') != revision or proof.get('tested_commit') != revision:
            raise ValueError('tests belong to another source or do not establish a tested commit')
        if any(proof.get(key) != value for key, value in binding.items()) or proof.get('tracked_source_clean') is not True:
            raise ValueError('test source or pinned configuration differs from the publisher')
        identity = proof.get('input_identity')
        if not isinstance(identity, str) or not re.fullmatch(r'[a-f0-9]{64}', identity):
            raise ValueError('test input identity is invalid')
        receipts = proof.get('test_receipts')
        if not isinstance(receipts, dict) or not applicable <= receipts.keys():
            raise ValueError('applicable tests did not all produce receipts')
        for name in applicable:
            if receipts[name] != {'source_commit': revision, 'input_identity': identity}:
                raise ValueError('applicable test receipts do not match the tested inputs')
        context = proof.get('execution_context')
        if not isinstance(context, dict) or set(context)-set(CONTEXT_KEYS) or any(not isinstance(value, str) or not value for value in context.values()):
            raise ValueError('invalid test execution context')
        for key in ('GITHUB_SERVER_URL', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID'):
            if context.get(key) != (os.environ.get(key) or None):
                raise ValueError('tests belong to another workflow execution')
        if os.environ.get('GITHUB_RUN_ID'):
            if context.get('GITHUB_JOB') != expected_job or context.get('GITHUB_SHA') != os.environ.get('GITHUB_SHA'):
                raise ValueError('tests were not produced by the declared test job at the release commit')
            tested, current = context.get('GITHUB_RUN_ATTEMPT'), os.environ.get('GITHUB_RUN_ATTEMPT')
            if not isinstance(tested, str) or not isinstance(current, str) or not tested.isdecimal() or not current.isdecimal() or not 1 <= int(tested) <= int(current):
                raise ValueError('test evidence has an invalid workflow attempt')
        proofs.append(proof)
    return max(proofs, key=lambda proof: int(proof['execution_context'].get('GITHUB_RUN_ATTEMPT', '1')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['record', 'publish'])
    parser.add_argument('--project', required=True)
    parser.add_argument('--image-base')
    parser.add_argument('--revision', required=True)
    parser.add_argument('--components', nargs='+', required=True)
    parser.add_argument('--directory', type=Path, default=Path('.artifacts/release'))
    parser.add_argument('--test-evidence-directory', type=Path, default=None)
    parser.add_argument('--test-job', default='Test')
    parser.add_argument('--stateful-contract', type=Path, default=None)
    args = parser.parse_args()
    if args.test_evidence_directory is None:
        args.test_evidence_directory = Path('.artifacts/test-evidence' if os.environ.get('GITHUB_RUN_ID') else '.artifacts/contract')
    if args.image_base is None:
        declaration = json.loads(contract.default_manifest().read_text())['release']
        if set(declaration) != {'project', 'image_base'} or declaration['project'] != args.project:
            raise ValueError('release project differs from the caller-owned declaration')
        args.image_base = declaration['image_base']
    refs = references(args.project, args.revision, args.components, args.image_base)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
    if head != args.revision:
        raise ValueError('release revision must match the checked-out commit')
    archive = args.directory/'images.tar.gz'
    manifest_file = args.directory/'release.json'
    data_contract = None
    if args.stateful_contract is not None:
        data_contract = stateful_release.materialize(args.stateful_contract, args.revision)
        relative = args.stateful_contract.resolve().relative_to(Path.cwd().resolve()).as_posix()
        blob = subprocess.check_output(['git', 'rev-parse', args.revision+':'+relative], text=True, timeout=10).strip()
        raw = args.stateful_contract.read_bytes()
        actual = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if blob != actual:
            raise ValueError('stateful declaration must match the immutable checked-out source blob')
        # Initial adoption is deliberately forward-only. A future producer
        # may attach exact old/new binary fixture evidence; a declaration
        # alone must never manufacture automatic rollback authority.
        if data_contract['recovery_action'] != 'forward_only':
            raise ValueError('publication requires exact compatibility fixture evidence before allowing image rollback')
    if args.operation == 'record':
        manifest = {'project': args.project, 'revision': args.revision, 'images': inspect(refs),
                    'archive_sha256': digest(archive), 'provenance': build_provenance(args.revision)}
        if data_contract is not None:
            manifest['stateful_contract'] = data_contract
        manifest_file.write_text(json.dumps(manifest, indent=2)+'\n')
        validate(manifest, args.project, args.revision, args.components, archive, args.image_base)
    else:
        # CD checks out the merged commit. A modified tracked source cannot publish.
        subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--'], check=True, timeout=30)
        manifest = json.loads(manifest_file.read_text())
        validate(manifest, args.project, args.revision, args.components, archive, args.image_base)
        if manifest.get('stateful_contract') != data_contract:
            raise ValueError('stateful release contract differs from the clean publisher source')
        proof = validate_provenance(manifest, args.revision)
        test_proof = validate_test_evidence(args.test_evidence_directory, args.revision, args.test_job)
        subprocess.run(['docker', 'load', '--input', str(archive)], check=True, timeout=600)
        if inspect(refs) != manifest['images']:
            raise ValueError('loaded image IDs differ from the Build gate evidence')
        for ref in refs:
            subprocess.run(['docker', 'push', ref], check=True, timeout=600)
        publisher = {'version': 1, 'revision': args.revision, 'archive_sha256': manifest['archive_sha256'],
                     'images': manifest['images'], 'build_provenance': proof,
                     'tested_commit': args.revision, 'test_provenance': test_proof,
                     'publisher_context': {key: os.environ[key] for key in CONTEXT_KEYS if os.environ.get(key)}}
        if data_contract is not None:
            publisher['stateful_contract'] = data_contract
        (args.directory/'publication.json').write_text(json.dumps(publisher, indent=2)+'\n')
    print(f'{args.operation}: {args.project} {args.revision}: {len(refs)} validated images')


if __name__ == '__main__':
    main()
