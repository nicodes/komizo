#!/usr/bin/env python3
"""Run a static site's development script under the checkout session lease."""
import json
import os
from pathlib import Path
import re
import sys


def read_package(path):
    with path.open('rb') as source:
        body = source.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise ValueError('package metadata exceeds the size limit')
    return json.loads(body)


def development_command(root, arguments):
    command = ['bun', 'run', 'dev']
    package = read_package(root/'package.json')
    if package.get('scripts', {}).get('dev') == 'astro dev':
        astro = read_package(root/'node_modules/astro/package.json')
        version = re.fullmatch(r'([0-9]+)\.([0-9]+)\.[0-9]+(?:[-+].*)?', astro.get('version', ''))
        if version and tuple(map(int, version.group(1, 2))) >= (7, 1):
            # komizo already owns the foreground process group and checkout
            # lease. Astro's agent auto-backgrounding and PID lock would add
            # another supervisor whose PID may outlive its process namespace.
            command.append('--ignore-lock')
    return command + arguments


if __name__ == '__main__':
    argv = development_command(Path.cwd(), sys.argv[1:])
    os.execvpe(argv[0], argv, os.environ)
