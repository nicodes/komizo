#!/usr/bin/env bash
set -euo pipefail
export KOMIZO_REQUIRE_SHELLCHECK=1
mapfile -t packages < <(go list ./... | sed '\|/internal/workflows$|d;\|/internal/workload$|d;\|/internal/servicehealth$|d;\|/scripts$|d')
go test -race -count=1 -timeout 5m "${packages[@]}"
set -euo pipefail
shell_status=0
out="$(go test -race -count=1 -timeout 5m -v ./scripts)" || shell_status=$?
echo "$out"
if [ "$shell_status" -ne 0 ]; then
  exit "$shell_status"
fi
if grep -q 'no tests to run\|\[no test files\]' <<<"$out"; then
  echo "::error::the shell gate matched no tests -- it has been renamed or moved, and this guard has been passing on an empty run"
  exit 1
fi
if ! grep -q -- '--- PASS' <<<"$out"; then
  echo "::error::the shell gate produced no passing test, so nothing was actually checked"
  exit 1
fi
if grep -q -- '--- SKIP' <<<"$out"; then
  echo "::error::a shell check skipped itself -- the tool it needs is missing from this image"
  exit 1
fi
