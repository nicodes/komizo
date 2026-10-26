#!/usr/bin/env bash
set -euo pipefail
# Optional source-portability exploration. Supported Darwin/Linux archives are
# already cross-built and verified by komizo run build artifact-check in CI and Release.
# These extra operating systems are not published workstation targets.
for t in windows/amd64 freebsd/amd64 netbsd/amd64 openbsd/amd64 dragonfly/amd64 \
         aix/ppc64 illumos/amd64 solaris/amd64 wasip1/wasm js/wasm plan9/amd64; do
  os="${t%/*}"; arch="${t#*/}"
  echo "  cross  $os/$arch"
  GOOS="$os" GOARCH="$arch" go build ./...
  GOOS="$os" GOARCH="$arch" go vet ./...
done
GOOS=android GOARCH=arm64 go vet ./...
echo "  cross  android/arm64 (vet only; linking needs cgo)"
