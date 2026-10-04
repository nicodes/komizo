#!/usr/bin/env bash
set -euo pipefail
set -euo pipefail
want="$(sed -n 's/^shellcheck *= *"\(.*\)"$/\1/p' .mise.toml)"
if [ -z "$want" ]; then
  echo "::error::.mise.toml pins no shellcheck version, so there is nothing for this to be"
  exit 1
fi
if ! command -v shellcheck >/dev/null 2>&1; then
  echo "::error::shellcheck is not on PATH -- mise did not install the pin, and every shell check below would SKIP itself green"
  exit 1
fi
got="$(shellcheck --version | sed -n 's/^version: //p')"
if [ "$got" != "$want" ]; then
  echo "::error::.mise.toml pins shellcheck $want but $got is on PATH. Those disagree about real rules, so this run would not be the check the pin describes."
  exit 1
fi
echo "shellcheck $got, as pinned"

shellcheck -s sh scripts/*.sh
shellcheck -s bash tools/engineering/*.sh
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "::error::gofmt would change these files:"
  echo "$unformatted"
  exit 1
fi

go vet ./...
