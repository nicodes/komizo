#!/usr/bin/env python3
"""Summarize stage records without confusing adapter and parent durations."""
import argparse
import json
from pathlib import Path


def render(records):
    stages = [row for row in records if 'adapter' not in row]
    lines = ['### Engineering stages', '', '| Stage | Seconds | Outcome | Exit |',
             '| --- | ---: | --- | ---: |']
    for row in stages:
        lines.append(f'| {row["stage"]} | {row["seconds"]:.3f} | {row.get("outcome", "executed")} | {row["exit_code"]} |')
    return '\n'.join(lines)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=Path('.artifacts/contract/timings.jsonl'))
    parser.add_argument('--summary', type=Path)
    args = parser.parse_args()
    if not args.input.exists():
        return
    content = render([json.loads(line) for line in args.input.read_text().splitlines() if line])
    if args.summary:
        with args.summary.open('a') as stream:
            stream.write(content)
    else:
        print(content, end='')


if __name__ == '__main__':
    main()
