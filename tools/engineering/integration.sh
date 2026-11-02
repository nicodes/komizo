#!/usr/bin/env bash
set -euo pipefail
# Actual installed-byte and disposable-host acceptance runs in CI and Release.
# Local integration stays confined to the released client and its own scratch home.
bash tools/engineering/cold-client.sh
