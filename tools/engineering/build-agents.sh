#!/usr/bin/env bash
set -euo pipefail
mkdir -p internal/agent/bin
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=${VERSION:-dev}" -o "internal/agent/bin/komizo-box-linux-$arch" ./cmd/komizo-box
done
