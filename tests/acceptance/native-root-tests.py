#!/usr/bin/env python3
"""Run Linux root integration fixtures without making Cargo's cache root-owned."""
import json
import os
import subprocess
import sys

TARGETS = (
    "deployment_assets", "deployment_authority", "deployment_contract",
    "deployment_controller", "deployment_data", "deployment_native",
    "deployment_recovery", "deployment_resources", "deployment_secrets",
    "deployment_store",
)


def executables(output):
    selected = {}
    for line in output.splitlines():
        row = json.loads(line)
        if row.get("reason") != "compiler-artifact" or not row.get("executable"):
            continue
        name = row.get("target", {}).get("name")
        if name not in TARGETS:
            continue
        if name in selected:
            raise RuntimeError(f"Repeated compiled root fixture for {name}")
        selected[name] = row["executable"]
    if set(selected) != set(TARGETS):
        raise RuntimeError("The complete native root fixture inventory was not compiled")
    return [selected[name] for name in TARGETS]


def main():
    if sys.platform != "linux":
        return
    if os.geteuid() != 0 and os.environ.get("GITHUB_ACTIONS") != "true":
        print("Native root fixtures run in Linux CI or under the root test runner.")
        return
    elevate = [] if os.geteuid() == 0 else ["sudo", "-n", "--"]
    sdk_check = os.path.join(os.path.dirname(__file__), "test_native_sdk.py")
    subprocess.run([*elevate, "/usr/bin/python3", "-I", "-B", sdk_check], check=True, timeout=60)
    result = subprocess.run(
        ["cargo", "test", "--locked", "--offline", *[argument for name in TARGETS for argument in ("--test", name)],
         "--no-run", "--message-format=json"],
        check=True, capture_output=True, text=True, timeout=300,
    )
    for executable in executables(result.stdout):
        subprocess.run([*elevate, executable], check=True, timeout=300)


if __name__ == "__main__":
    main()
