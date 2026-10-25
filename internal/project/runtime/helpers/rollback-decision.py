#!/usr/bin/env python3
"""Deny automatic stateful rollback unless this release has exact compatibility proof."""
import argparse
import json
import os
from pathlib import Path
import re
import importlib.util

_spec = importlib.util.spec_from_file_location('_stateful_release_contract', Path(__file__).resolve().with_name('stateful_release.py'))
stateful_release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stateful_release)

OPERATIONS = {'new_migrations', 'new_write', 'previous_read', 'previous_write', 'previous_reload_read', 'new_reload_read'}


def decide(declaration, evidence, current, previous, run_id):
    denied = {'allowed': False, 'reason': 'compatibility is not declared and proven'}
    if declaration.get('automatic_image_rollback') is not True:
        return {**denied, 'reason': declaration.get('reason', 'release does not declare backward compatibility')}
    if evidence is None:
        return {**denied, 'reason': 'the previous-version read/write test produced no evidence'}
    try:
        stateful_release.check_rollback(declaration.get('stateful_contract'), declaration.get('previous_stateful_contract'), evidence, current, previous, run_id)
    except ValueError as error:
        return {**denied, 'reason': str(error)}
    if not all(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{40}', value) for value in [current, previous]):
        return {**denied, 'reason': 'current and previous revisions are not exact commits'}
    if not run_id or evidence.get('run_id') != run_id or evidence.get('current_revision') != current or evidence.get('previous_revision') != previous:
        return {**denied, 'reason': 'compatibility evidence belongs to a different run or revision'}
    if evidence.get('status') != 'passed' or evidence.get('operations') != {operation: 'passed' for operation in OPERATIONS}:
        return {**denied, 'reason': 'the previous version did not pass every post-migration read/write operation'}
    if not re.fullmatch(r'[a-f0-9]{64}', str(evidence.get('snapshot_sha256', ''))):
        return {**denied, 'reason': 'the compatibility test did not identify its post-write snapshot'}
    return {'allowed': True, 'previous_revision': previous, 'reason': 'declared compatibility and exact post-write read/write proof passed'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--declaration', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--current', required=True)
    parser.add_argument('--previous', default='')
    args = parser.parse_args()
    declaration = json.loads(args.declaration.read_text()) if args.declaration.exists() else {}
    evidence = json.loads(args.evidence.read_text()) if args.evidence.exists() else None
    result = decide(declaration, evidence, args.current, args.previous, os.environ.get('GITHUB_RUN_ID', ''))
    print(json.dumps(result, indent=2))
    if output := os.environ.get('GITHUB_OUTPUT'):
        with open(output, 'a') as stream:
            stream.write('allowed=' + str(result['allowed']).lower() + '\n')
            if result['allowed']:
                stream.write('previous_revision=' + result['previous_revision'] + '\n')
