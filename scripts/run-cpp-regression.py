#!/usr/bin/env python3
"""CTest adapter for Linux/x86 ISA requirements and legacy in-test skips."""

import argparse
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require", default="", help="comma-separated Linux CPU flags")
    parser.add_argument("--native-required", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("missing test command")
    if shutil.which(command[0]) is None:
        print(f"FAIL: missing or non-executable test: {command[0]}", file=sys.stderr)
        return 1
    required = set(filter(None, args.require.split(",")))
    try:
        # Intersect CPUs so a migrated test cannot land on an unsupported core.
        flags = [set(line.split(":", 1)[1].split())
                 for line in Path("/proc/cpuinfo").read_text().splitlines()
                 if line.startswith("flags") and ":" in line]
        available = set.intersection(*flags) if flags else set()
    except OSError:
        available = set()
    missing = required - available
    if required and (platform.machine() not in ("x86_64", "AMD64") or missing):
        print("SKIP: missing Linux/x86 CPU support: " + ",".join(sorted(missing or required)))
        return 1 if args.native_required else 77
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, errors="replace", check=False)
    except OSError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(result.stdout, end="", flush=True)
    if result.returncode:
        if args.native_required and result.returncode == 77:
            return 1
        return result.returncode if result.returncode > 0 else 1
    # These selected legacy executables return zero even when their native half skips.
    if re.search(r"(?m)^(?:SKIP(?:PED)?:|E1/E2/E3 SKIPPED:|\[B\] execution: SKIPPED)",
                 result.stdout):
        return 1 if args.native_required else 77
    return 0


if __name__ == "__main__":
    sys.exit(main())
