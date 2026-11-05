"""Verify candidate public deployment in the existing disposable Alpine fixture."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--source', required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or not re.fullmatch('[a-f0-9]{40}', args.source):
        raise ValueError('independent deployment requires its native Linux fixture and exact source')
    root = Path(__file__).resolve().parents[2]
    binary = args.binary.resolve(strict=True)
    if args.binary.is_symlink() or not binary.is_file() or not binary.is_relative_to(root):
        raise ValueError('candidate must be the actual checkout-owned built executable')
    output = root / '.artifacts/independent-deployment'
    if output.exists() or output.is_symlink():
        raise ValueError('independent deployment evidence must be fresh')
    private = Path('/root/komizo-independent-ci')
    runner = Path(__file__).parent
    environment = {key: value for key, value in os.environ.items() if key not in {'GH_TOKEN', 'GITHUB_TOKEN', 'MISE_GITHUB_TOKEN'}}
    subprocess.run(['sudo', 'install', '-d', '-m', '700', str(private / 'release')], check=True, env=environment)
    subprocess.run(['sudo', sys.executable, str(runner / 'cold-lifecycle-acceptance.py'),
        '--release', 'v0.0.0', '--source', args.source, '--release-dir', str(private / 'release'),
        '--candidate-cli', str(binary), '--candidate-host', '--deployment-only',
        '--output', str(private / 'observations')], check=True, env=environment, timeout=1740)
    subprocess.run(['sudo', sys.executable, str(runner / 'candidate_evidence.py'),
        '--observations', str(private / 'observations'), '--output', str(output), '--source', args.source],
        check=True, env=environment, timeout=60)
    subprocess.run(['sudo', 'chown', '-R', str(os.getuid()) + ':' + str(os.getgid()), str(output)], check=True, env=environment)


if __name__ == '__main__': main()
