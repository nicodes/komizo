#!/usr/bin/env python3
"""Retain requested cache state and measured aggregate setup overhead."""
import json
import os
from pathlib import Path
import time


def state(enabled, hit):
    if enabled != 'true':
        return {'enabled': False, 'lookup': 'disabled'}
    return {'enabled': True, 'lookup': {'true': 'exact-hit', 'false': 'fallback-or-miss'}.get(hit, 'unavailable')}


def main():
    started = os.environ.get('CACHE_STARTED_AT')
    record = {'version': 1, 'github_run_id': os.environ.get('GITHUB_RUN_ID'),
              'github_run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
              'source_commit': os.environ.get('GITHUB_SHA'),
              'job': os.environ.get('GITHUB_JOB'),
              'setup_seconds': round(time.monotonic()-float(started), 3) if started else None,
              'note': 'Setup includes restore actions and optional Buildx setup. Save overhead is recorded separately by GitHub job step timestamps. A false combined-cache output cannot distinguish fallback from miss.',
              'caches': {name: state(os.environ.get(name.upper()+'_CACHE_ENABLED'), os.environ.get(name.upper()+'_CACHE_HIT')) for name in ('go', 'web', 'layer')}}
    target = Path('.artifacts/contract/cache.json')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    main()
