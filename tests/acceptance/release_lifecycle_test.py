"""Gate publication on independently authenticated native host and owner bytes."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))

from native_release import SOURCE,TAG


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--artifacts',type=Path,required=True)
    parser.add_argument('--evidence',type=Path,required=True);parser.add_argument('--release',required=True);parser.add_argument('--source',required=True)
    args=parser.parse_args();root=Path(__file__).resolve().parents[2];runner=Path(__file__).parent
    if (sys.platform!='linux' or not SOURCE.fullmatch(args.source) or not TAG.fullmatch(args.release) or not os.environ.get('GH_TOKEN')
            or args.artifacts.is_symlink() or args.artifacts.resolve(strict=True)!=root/'dist'
            or args.evidence.resolve()!=root/'.artifacts/cli-publication-evidence' or args.evidence.exists() or args.evidence.is_symlink()):
        raise ValueError('exact authenticated checkout-native release and fresh evidence required')
    with tempfile.TemporaryDirectory(prefix='komizo-release-observations-') as temporary:
        observations=Path(temporary)/'private'
        try:
            subprocess.run([sys.executable,'-I','-B',str(runner/'cold-lifecycle-acceptance.py'),'--release',args.release,'--source',args.source,
                '--release-dir',str(args.artifacts.resolve()),'--output',str(observations)],check=True,timeout=2100)
        finally:
            subprocess.run([sys.executable,'-I','-B',str(runner/'release_acceptance.py'),'--observations',str(observations),'--output',str(args.evidence),
                '--release',args.release,'--source',args.source,'--artifacts',str(args.artifacts.resolve())],check=True,timeout=120)


if __name__=='__main__':main()
