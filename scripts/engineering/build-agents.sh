#!/usr/bin/env bash
set -euo pipefail
for platform in Linux_x86_64 Linux_arm64; do
  python3 scripts/engineering/native-receipt.py ".artifacts/native-host/komizo-box_$platform"
done
