#!/usr/bin/env bash
set -euo pipefail
mkdir -p internal/agent/bin
trap 'rm -f internal/nativeapi/payload.gz' EXIT
for arch in amd64 arm64; do
  case "$arch" in amd64) label=x86_64 ;; arm64) label=arm64 ;; esac
  python3 tools/engineering/api-payload.py ".artifacts/native-api/komizo-api_Linux_$label"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -tags rustapi -trimpath -ldflags "-s -w -X main.version=${VERSION:-dev}" -o "internal/agent/bin/komizo-box-linux-$arch" ./cmd/komizo-box
done
