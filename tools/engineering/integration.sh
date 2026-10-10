#!/usr/bin/env bash
set -euo pipefail
export KOMIZO_REQUIRE_SHELLCHECK=1
mapfile -t packages < <(go list ./... | sed '\|/internal/workflows$|d;\|/scripts$|d')
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

set -euo pipefail
GOOS=darwin GOARCH=amd64 go build ./...
for t in windows/amd64 freebsd/amd64 netbsd/amd64 openbsd/amd64 dragonfly/amd64 \
         aix/ppc64 illumos/amd64 solaris/amd64 wasip1/wasm js/wasm plan9/amd64; do
  os="${t%/*}"; arch="${t#*/}"
  echo "  cross  $os/$arch"
  GOOS="$os" GOARCH="$arch" go build ./...
  GOOS="$os" GOARCH="$arch" go vet ./...
done
GOOS=android GOARCH=arm64 go vet ./...
echo "  cross  android/arm64 (vet only; linking needs cgo)"

