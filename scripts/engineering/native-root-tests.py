#!/usr/bin/env python3
"""Run the compiled native root fixtures without making Cargo's cache root-owned."""
import json
import os
import subprocess
import sys


def main():
    if sys.platform != "linux":
        return
    if os.geteuid() != 0 and os.environ.get("GITHUB_ACTIONS") != "true":
        print("Native root fixtures run in Linux CI or under the root test runner.")
        return
    for name in ("workload_commands", "host_release_operations"):
        result = subprocess.run(
            ["cargo", "test", "--locked", "--test", name, "--no-run", "--message-format=json"],
            check=True, capture_output=True, text=True,
        )
        executables = []
        for line in result.stdout.splitlines():
            row = json.loads(line)
            if row.get("reason") == "compiler-artifact" and row.get("target", {}).get("name") == name and row.get("executable"):
                executables.append(row["executable"])
        if len(executables) != 1:
            raise RuntimeError(f"Expected one compiled root fixture for {name}")
        command = executables
        if os.geteuid() != 0:
            command = ["sudo", "--", *command]
        subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
