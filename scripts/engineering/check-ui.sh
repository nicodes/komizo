#!/usr/bin/env bash
set -euo pipefail
if ! command -v node >/dev/null 2>&1; then
  echo "::error::node is not on PATH -- mise did not install the pin, and the export check would silently not happen"
  exit 1
fi
cd app
npm ci --no-audit --no-fund
npm run typecheck
node --test tests/*.test.mjs
npm run build
cd ..
python3 scripts/verify-ui-build.py
