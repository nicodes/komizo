#!/bin/sh
# Run in a disposable directory containing caddy.go.mod as go.mod,
# caddy.go.sum as go.sum and caddy-main.go as main.go.
#
# This used to carry a patch. Caddy v2.11.4 could not compile against a
# cel-go new enough to fix GHSA-gcjh-h69q-9w9g: cel-go changed the
# interpreter signature and caddyhttp/celmatcher.go had not followed, so the
# build overlaid that one file, rewriting []interpreter.Interpretable{ to
# []interpreter.InterpretableV2{, with the upstream source pinned by SHA so
# the rewrite could not silently apply to something else.
#
# Caddy v2.11.6 adopted the same change and moved the dependency to
# cel.dev/cel-go, the module's new path. github.com/google/cel-go is now
# absent from go.mod and go.sum entirely rather than merely patched, so
# there is nothing left to overlay and the reviewed-SHA pin guards nothing.
# A patch nobody needs is a patch that rots, so it is gone.
#
# What still proves the property the patch existed for: helpers/test-caddy.py
# runs govulncheck against the built binary and fails on any vulnerable
# symbol actually linked in. That check is the contract; the overlay was one
# way of satisfying it.
set -eu
export GOTOOLCHAIN=local
go mod download
go mod vendor
go build -mod=vendor -trimpath -o caddy .
if [ "${1:-}" = --test ]; then
    # Go vendor intentionally omits upstream tests. Run those from a separate
    # full source copy with the same root dependency lock.
    version="$(go list -m -f '{{.Version}}' github.com/caddyserver/caddy/v2)"
    mkdir test-source
    cp go.mod go.sum test-source/
    cp -R "$(go env GOMODCACHE)/github.com/caddyserver/caddy/v2@${version}" test-source/upstream
    chmod -R u+w test-source/upstream
    (
        cd test-source
        go mod edit -replace github.com/caddyserver/caddy/v2=./upstream
        go test -mod=readonly -race -count=1 github.com/caddyserver/caddy/v2/modules/caddyhttp
    )
fi
