#!/usr/bin/env python3
"""Record the actual PR integration or main commit checked by a Test job."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def identity(environment, git):
    head = environment['EXPECTED_HEAD']
    if not re.fullmatch('[a-f0-9]{40}', head):
        raise ValueError('exact PR head required')
    commit = git(['rev-parse', 'HEAD']).strip()
    tree = git(['rev-parse', 'HEAD^{tree}']).strip()
    # cat-file reads raw parents even with checkout's depth-one shallow clone.
    parents = [line[7:] for line in git(['cat-file', '-p', 'HEAD']).split('\n\n', 1)[0].splitlines()
               if line.startswith('parent ')]
    event = environment.get('GITHUB_EVENT_NAME', 'pull_request')
    owner = event in ('push', 'workflow_dispatch')
    if owner:
        if (environment.get('GITHUB_REF') != 'refs/heads/main' or environment.get('GITHUB_SHA') != head
                or commit != head or not 1 <= len(parents) <= 2):
            raise ValueError('main delivery identity requires the exact main checkout and raw parent identity')
    elif event != 'pull_request' or len(parents) != 2 or parents[1] != head:
        raise ValueError('Test must check out the integration, with the PR head as its second parent')
    value = {'version': 2 if owner else 1, 'repository': environment['GITHUB_REPOSITORY'],
             'run_id': int(environment['GITHUB_RUN_ID']),
             'attempt': int(environment['GITHUB_RUN_ATTEMPT']),
             'job': environment['GITHUB_JOB'], 'head': head, 'base': parents[0],
             'commit': commit, 'tree': tree}
    if any(not re.fullmatch('[a-f0-9]{40}', value[key]) for key in ('head', 'base', 'commit', 'tree')):
        raise ValueError('invalid integration identity')
    return value


def main():
    git = lambda args: subprocess.check_output(['git', *args], text=True, timeout=10)
    value = identity(os.environ, git)
    tracked = git(['ls-files']).splitlines()
    files = [path for path in tracked if Path(path).name in
             {'go.mod', 'go.sum', 'package.json', 'bun.lock', 'package-lock.json', 'komizo.json', 'komizo.lock'}
             or path.startswith('.github/')]
    value['inputs_sha256'] = hashlib.sha256(json.dumps(
        {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in files},
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    destination = Path('.artifacts/fleet-integration.json')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value, sort_keys=True)+'\n')


if __name__ == '__main__':
    main()
