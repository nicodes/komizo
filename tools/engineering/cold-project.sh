#!/usr/bin/env bash
set -euo pipefail
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
archive="$PWD/dist/komizo_Linux_x86_64.tar.gz"
test -s "$archive"
mkdir "$scratch/bin" "$scratch/project"
tar -xzf "$archive" -C "$scratch/bin" komizo
git -C "$scratch/project" init -q

# Hide the CI mise-action installation. This acceptance must download and
# authenticate the platform's pinned bootstrap, then install a selected tool.
export PATH=/usr/bin:/bin
if command -v mise >/dev/null; then
  echo 'Cold project acceptance requires a PATH without mise' >&2
  exit 1
fi
export KOMIZO_CACHE_DIR="$scratch/cache"
export MISE_DATA_DIR="$scratch/tools"
export MISE_CACHE_DIR="$scratch/tool-cache"
export MISE_STATE_DIR="$scratch/state"
export MISE_CONFIG_DIR="$scratch/config"
cd "$scratch/project"
"$scratch/bin/komizo" init --recipe static-site
"$scratch/bin/komizo" exec --tools python -- python3 -c 'import sys; assert sys.version_info[:3] == (3, 13, 11); print("Cold project tool execution passed")'
test -x "$KOMIZO_CACHE_DIR/toolchain/2026.9.12-linux-amd64/mise"
