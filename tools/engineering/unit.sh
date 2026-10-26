#!/usr/bin/env bash
set -euo pipefail
# Policy, parsers and acceptance decisions need no prepared host or CLI build.
go test -race -count=1 -timeout 5m ./internal/workflows ./internal/workload ./internal/servicehealth
python3 -m unittest discover -s tools/engineering -p 'test_*.py' -v
python3 scripts/platform_test.py
python3 scripts/platform_prepare_test.py
python3 -m unittest discover -s scripts -p maintenance_test.py -v
python3 -m unittest discover -s scripts -p workspace_storage_test.py -v
python3 -m unittest discover -s scripts -p workload_acceptance_test.py -v
python3 -m unittest discover -s scripts -p preview_database_test.py -v
python3 -m unittest discover -s scripts -p compressed_swap_test.py -v
python3 -m unittest discover -s scripts -p publication_prepare_test.py -v
python3 -m unittest discover -s scripts -p proxy_prepare_test.py -v

node --test setup/setup.test.mjs
# Each runtime fixture owns its own project declaration. Do not inherit the
# enclosing native check's resolved contract into those disposable projects.
env -u KOMIZO_CONTRACT python3 -m unittest discover -s internal/project/runtime/tests -p 'test_*.py' -v
