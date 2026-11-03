#!/usr/bin/env bash
set -euo pipefail
mkdir -p dist
for platform in Linux_x86_64 Linux_arm64 Darwin_x86_64 Darwin_arm64; do
  python3 scripts/engineering/native-receipt.py ".artifacts/native-cli/komizo_$platform"
  directory="dist/komizo_$platform"
  mkdir -p "$directory"
  cp ".artifacts/native-cli/komizo_$platform" "$directory/komizo"
  chmod 755 "$directory/komizo"
  cp README.md LICENSE "$directory/"
  tar -C "$directory" -czf "dist/komizo_$platform.tar.gz" komizo README.md LICENSE
done
(cd dist && sha256sum -- *.tar.gz > checksums.txt)
