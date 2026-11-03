#!/usr/bin/env bash
set -euo pipefail
# Release portability is checked by four native builders, including static musl Linux.
python3 - <<'CHECK'
from pathlib import Path
import subprocess
for platform in ('Linux_x86_64','Linux_arm64','Darwin_x86_64','Darwin_arm64'):
    path=Path('.artifacts/native-cli')/('komizo_'+platform)
    subprocess.run(['python3','scripts/engineering/native-receipt.py',str(path)],check=True)
CHECK
