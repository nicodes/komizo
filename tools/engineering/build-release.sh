#!/usr/bin/env bash
set -euo pipefail
rm -rf dist
mkdir -p dist

# The agents FIRST. internal/agent embeds them, and //go:embed reads the
# filesystem at build time -- so a CLI compiled before they exist ships
# without them and fails at the moment somebody runs `komizo init`.
# Always linux: this is the binary that goes on the server, whatever
# platform the CLI beside it is for.
test -s internal/agent/bin/komizo-box-linux-amd64
test -s internal/agent/bin/komizo-box-linux-arm64

build() {
  goos="$1"; goarch="$2"; os_label="$3"; arch_label="$4"
  name="komizo_${os_label}_${arch_label}"
  out="dist/$name"
  mkdir -p "$out"
  # CGO off so the binary is static and runs on any distro; -trimpath so
  # the archive does not carry the builder's paths.
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build \
    -trimpath -ldflags "-s -w -X main.version=$VERSION" \
    -o "$out/komizo" .
  cp README.md LICENSE "$out/"
  tar -C "$out" -czf "dist/$name.tar.gz" komizo README.md LICENSE
  echo "  $name"
}

# Where a person runs a terminal. The servers komizo manages are Alpine,
# but nothing of komizo is installed on them -- it is the workstation
# that needs a binary.
build linux  amd64 Linux  x86_64
build linux  arm64 Linux  arm64
build darwin amd64 Darwin x86_64
build darwin arm64 Darwin arm64

(cd dist && sha256sum -- *.tar.gz > checksums.txt)

