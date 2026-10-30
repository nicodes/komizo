#!/usr/bin/env bash
set -euo pipefail
want="$(python3 -c 'import tomllib; print(tomllib.load(open("mise.toml","rb"))["tools"]["shellcheck"])')"
if ! command -v shellcheck >/dev/null 2>&1; then
  echo "::error::shellcheck is not on PATH -- mise did not install the pin, and every shell check below would SKIP itself green"
  exit 1
fi
got="$(shellcheck --version | sed -n 's/^version: //p')"
if [ "$got" != "$want" ]; then
  echo "::error::mise.toml pins shellcheck $want but $got is on PATH. Those disagree about real rules, so this run would not be the check the pin describes."
  exit 1
fi
echo "shellcheck $got, as pinned"

shellcheck -s sh scripts/*.sh
shellcheck -s bash tools/engineering/*.sh
# Check authored source, including new files, without traversing ignored build
# scratch. Native fixtures can compile into an isolated worktree concurrently.
unformatted="$(git ls-files --cached --others --exclude-standard -z -- '*.go' | xargs -0 -r gofmt -l)"
if [ -n "$unformatted" ]; then
  echo "::error::gofmt would change these files:"
  echo "$unformatted"
  exit 1
fi

go vet ./...

actionlint
