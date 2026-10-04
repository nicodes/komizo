#!/usr/bin/env bash
set -euo pipefail
(cd dist && sha256sum --check checksums.txt)
set -euo pipefail
tmp="$(mktemp -d)"
tar -xzf dist/komizo_Linux_x86_64.tar.gz -C "$tmp"
got="$("$tmp/komizo" version)"
echo "$got"

# A requested version must be reported exactly -- that is a release, and
# the archive claiming a different version than the tag is the whole
# failure this guards.
#
# The default is not checked against the literal "dev". The binary falls
# back to the module version in its build info when no version was baked
# in, and in a git checkout the toolchain stamps a VCS pseudo-version --
# so a pull request legitimately reports 0.0.0-<date>-<sha>. Asserting
# "dev" here failed the first build after that fallback was added, which
# is the check being wrong rather than the binary.
if [ "$VERSION" != "dev" ]; then
  if [ "$got" != "komizo $VERSION" ]; then
    echo "::error::built binary reports '$got', expected 'komizo $VERSION'"
    exit 1
  fi
elif [ -z "${got#komizo }" ] || [ "${got#komizo }" = "$got" ]; then
  echo "::error::built binary reports '$got', expected 'komizo <version>'"
  exit 1
fi

