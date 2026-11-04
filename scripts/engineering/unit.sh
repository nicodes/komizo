#!/usr/bin/env bash
set -euo pipefail
cargo test --locked
python3 scripts/engineering/native-root-tests.py
cargo test --locked --manifest-path crates/api/Cargo.toml
python3 -m unittest discover -s scripts/engineering -p 'test_*.py' -v
python3 scripts/platform_test.py
python3 scripts/platform_prepare_test.py
python3 -m unittest discover -s scripts -p maintenance_test.py -v
python3 -m unittest discover -s scripts -p workload_acceptance_test.py -v
python3 -m unittest discover -s scripts -p preview_database_test.py -v
python3 -m unittest discover -s scripts -p compressed_swap_test.py -v
python3 -m unittest discover -s scripts -p proxy_prepare_test.py -v
