#!/usr/bin/env python3
"""Keep one owned issue for a failing automation workflow, with a bounded body."""
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

repo = os.environ['GITHUB_REPOSITORY']
run = os.environ['GITHUB_RUN_ID']
workflow = os.environ['GITHUB_WORKFLOW']
revision = os.environ['GITHUB_SHA']
# Validate the caller's workflow identity before constructing issue arguments.
if not re.fullmatch(r'[\w.-]+/[\w.-]+', repo) or not run.isdigit() or not re.fullmatch(r'[a-f0-9]{40}', revision):
    raise ValueError('invalid workflow identity')
title = f'{workflow}: required automation failed'
body = (f'The required **{workflow}** workflow failed for `{revision}`.\n\n'
        f'[Run and bounded diagnostic artifacts](https://github.com/{repo}/actions/runs/{run})\n\n'
        'Inspect the failing stage before retrying. A failed gate is not a completed migration.\n')
if len(body) > 2000 or len(title) > 200:
    raise ValueError('failure report exceeds its bound')
result = subprocess.check_output(['gh', 'issue', 'list', '--repo', repo, '--state', 'open',
                                  '--search', f'in:title "{title}"', '--limit', '100', '--json', 'number,title'], text=True, timeout=60)
issues = [issue for issue in json.loads(result) if issue['title'] == title]
with tempfile.TemporaryDirectory() as directory:
    file = Path(directory)/'body.md'; file.write_text(body)
    if issues:
        command = ['gh', 'issue', 'comment', str(min(issue['number'] for issue in issues)), '--repo', repo, '--body-file', str(file)]
    else:
        command = ['gh', 'issue', 'create', '--repo', repo, '--title', title, '--body-file', str(file)]
    subprocess.run(command, check=True, timeout=60)
