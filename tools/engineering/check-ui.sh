#!/usr/bin/env bash
set -euo pipefail
if ! command -v node >/dev/null 2>&1; then
  echo "::error::node is not on PATH -- mise did not install the pin, and the export check would silently not happen"
  exit 1
fi
cd ui
npm ci --no-audit --no-fund
npm run typecheck
node --test tests/*.test.mjs
npm run build
cd ..
if ! git diff --exit-code --stat internal/ui/dist; then
  echo "::error::internal/ui/dist is not what ui/ produces. Run \`make ui\` and commit the result."
  exit 1
fi

