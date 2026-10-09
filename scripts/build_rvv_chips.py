#!/usr/bin/env python3
"""Rebuild a registered CHIPS stage2 source with the Linux-user reporting adapter."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

from rvv_tests import digest, save


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def build(args):
    scripts = Path(__file__).resolve().parent
    lock = json.loads((scripts / "rvv/sources.lock.json").read_text())["sources"]["chips"]
    upstream = args.upstream.resolve()
    source = args.source.resolve()
    if digest(source) != args.source_sha256:
        raise ValueError("source differs from the registered stage2 fixture")
    if git(upstream, "rev-parse", "HEAD") != lock["revision"]:
        raise ValueError("CHIPS checkout does not match sources.lock.json")
    if git(upstream, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("CHIPS tracked source has local changes")
    for relative, revision in lock["submodules"].items():
        submodule = upstream / relative
        if git(submodule, "rev-parse", "HEAD") != revision:
            raise ValueError("submodule revision mismatch: " + relative)
        if git(submodule, "status", "--porcelain", "--untracked-files=no"):
            raise ValueError("submodule has local changes: " + relative)
    compiler = shutil.which(args.compiler)
    if not compiler:
        raise ValueError("compiler not found: " + args.compiler)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source_copy = output / "test.S"
    shutil.copyfile(source, source_copy)
    elf = output / "test.elf"
    command = [compiler, "--target=riscv32-unknown-elf", "-march=rv32gv", "-mabi=ilp32f",
               "-static", "-mcmodel=medany", "-fvisibility=hidden", "-nostdlib", "-fuse-ld=lld",
               "-DENTROPY=0xdeadbeef", "-DLFSR_BITS=9",
               '-DCHIPS_ENV_HEADER="' + str(upstream / "env/ps/riscv_test.h") + '"',
               "-I" + str(scripts / "rvv/chips_user"),
               "-I" + str(upstream / "macros/general"),
               "-Wl,-T," + str(upstream / "env/ps/link.ld"), str(source_copy), "-o", str(elf)]
    save(output / "command.json", command)
    with (output / "stdout").open("wb") as so, (output / "stderr").open("wb") as se:
        result = subprocess.run(command, stdout=so, stderr=se, timeout=120)
    record = {"status": "BUILD_SUCCESS" if result.returncode == 0 else "BUILD_FAILED",
              "returncode": result.returncode, "source_sha256": digest(source_copy),
              "source_unmodified": source_copy.read_bytes() == source.read_bytes(),
              "upstream_revision": lock["revision"], "submodules": lock["submodules"],
              "adapter_sha256": digest(scripts / "rvv/chips_user/riscv_test.h"),
              "compiler_version": subprocess.check_output([compiler, "--version"], text=True),
              "elf_sha256": digest(elf) if elf.exists() else None,
              "expected_elf_sha256": args.expected_elf_sha256,
              "oracle": "unchanged expected values in supplied stage2 source; build is not oracle validation"}
    matched = not args.expected_elf_sha256 or record["elf_sha256"] == args.expected_elf_sha256
    record["matches_registered_elf"] = matched if args.expected_elf_sha256 else None
    save(output / "build.json", record)
    print(json.dumps(record))
    return 0 if result.returncode == 0 and matched else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--expected-elf-sha256")
    parser.add_argument("--compiler", default="clang-20")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("CHIPS build error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
