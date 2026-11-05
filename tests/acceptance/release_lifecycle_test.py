"""Accept authenticated release bytes through the existing disposable Alpine lifecycle."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--release', required=True)
    parser.add_argument('--source', required=True)
    args = parser.parse_args()
    if (sys.platform != 'linux' or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', args.release)
            or not re.fullmatch('[a-f0-9]{40}', args.source) or not os.environ.get('GH_TOKEN')):
        raise ValueError('authenticated release acceptance requires native Linux and exact release/source')
    root = Path(__file__).resolve().parents[2]
    artifacts = args.artifacts.resolve(strict=True)
    if (artifacts != root / 'dist' or args.artifacts.is_symlink()
            or args.evidence.resolve() != root / '.artifacts/cli-publication-evidence'
            or args.evidence.exists() or args.evidence.is_symlink()):
        raise ValueError('release acceptance requires checkout-native archives and fresh evidence')
    for name in ('komizo_Linux_x86_64.tar.gz', 'checksums.txt'):
        path = artifacts / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('release inputs must be the accepted regular archive and checksums')
    private = Path('/root/komizo-native-release')
    runner = Path(__file__).parent
    subprocess.run(['sudo', 'install', '-d', '-m', '700', str(private / 'release')], check=True)
    subprocess.run(['sudo', 'install', '-m', '600', str(artifacts / 'komizo_Linux_x86_64.tar.gz'),
                    str(artifacts / 'checksums.txt'), str(private / 'release')], check=True)
    try:
        subprocess.run(['sudo', '--preserve-env=GH_TOKEN', sys.executable, str(runner / 'cold-lifecycle-acceptance.py'),
            '--release', args.release, '--source', args.source, '--release-dir', str(private / 'release'),
            '--output', str(private / 'observations')], check=True, timeout=2100)
    finally:
        # The existing exporter writes only bounded nonsecret source/performance/
        # cleanup summaries, including failure diagnostics, never fixture secrets.
        subprocess.run(['sudo', sys.executable, str(runner / 'release_acceptance.py'),
            '--observations', str(private / 'observations'), '--output', str(args.evidence),
            '--release', args.release, '--source', args.source], check=True, timeout=120)
    subprocess.run(['sudo', 'chown', '-R', str(os.getuid()) + ':' + str(os.getgid()), str(args.evidence)], check=True)


if __name__ == '__main__': main()
