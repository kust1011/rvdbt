#!/usr/bin/env python3
"""Replay registered RVV self-checking ELFs; this runner is not an ISA oracle."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def load_manifest(path):
    manifest = json.loads(Path(path).read_text())
    cells = manifest["cells"]
    if not isinstance(cells, list) or not cells:
        raise ValueError("manifest must contain nonempty cells")
    seen = set()
    for cell in cells:
        name = cell["id"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", name):
            raise ValueError("unsafe case id")
        if name in seen:
            raise ValueError("duplicate case id: " + name)
        seen.add(name)
        if not re.fullmatch(r"[0-9a-f]{64}", cell["elf_sha256"]):
            raise ValueError("invalid ELF digest: " + name)
        if not isinstance(cell["flags"], list) or not all(isinstance(x, str) for x in cell["flags"]):
            raise ValueError("flags must be a string array")
        if type(cell["expected_returncode"]) is not int or cell["expected_returncode"] < 0:
            raise ValueError("host signals must not be accepted as expected traps")
        if not isinstance(cell["expected_stdout"], str):
            raise ValueError("expected_stdout must be a string")
        if type(cell["control"]) is not bool:
            raise ValueError("control must explicitly distinguish harness controls")
        if not cell["control"] and cell["expected_returncode"] != 0:
            raise ValueError("nonzero expected exit requires an explicit control case")
    timeout = manifest["timeout_seconds"]
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout_seconds must be finite and positive")
    return manifest


def classify(returncode, actual, cell, timed_out=False, error=None):
    if error:
        return "ERROR"
    if timed_out:
        return "TIMEOUT"
    if returncode is not None and returncode < 0:
        return "CRASH"
    if returncode != cell["expected_returncode"]:
        return "EXIT_MISMATCH"
    if actual != cell["expected_stdout"].encode():
        return "OUTPUT_MISMATCH"
    return "PASS"


def execute(cell, engine, inputs, out, environment, timeout):
    directory = out / cell["id"]
    directory.mkdir()
    work = directory / "work"
    (work / "fs").mkdir(parents=True)
    (work / "cache").mkdir()
    command = [str(engine)] + [x.replace("{WORK}", str(work)) for x in cell["flags"]]
    save(directory / "command.json", command)
    save(directory / "case.json", cell)
    source = inputs / (cell["elf_sha256"] + ".elf")
    stdout = directory / "stdout"
    stderr = directory / "stderr"
    returncode = None
    error = None
    timed_out = False
    begin = time.monotonic()
    try:
        shutil.copyfile(source, work / "fs" / "t.elf")
        if digest(work / "fs" / "t.elf") != cell["elf_sha256"]:
            raise ValueError("ELF bytes differ from registered input")
        with stdout.open("wb") as so, stderr.open("wb") as se:
            process = subprocess.Popen(command, cwd=work, env=environment,
                                       stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                                       start_new_session=True)
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                returncode = process.wait()
    except (OSError, ValueError) as exc:
        error = str(exc)
    stdout.touch(exist_ok=True)
    stderr.touch(exist_ok=True)
    status = classify(returncode, stdout.read_bytes(), cell, timed_out, error)
    result = {
        "id": cell["id"], "status": status, "control": cell["control"],
        "returncode": returncode, "error": error,
        "elapsed_seconds_for_timeout_diagnostics_only": time.monotonic() - begin,
        "elf_sha256": cell["elf_sha256"],
        "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr),
        "checker": "registered exit code and exact stdout of self-checking guest",
        "instruction_route": "NOT_OBSERVED_BY_THIS_RUNNER",
    }
    save(directory / "result.json", result)
    return result


def run(args):
    manifest_path = args.manifest.resolve()
    manifest = load_manifest(manifest_path)
    cells = manifest["cells"]
    if args.case:
        requested = set(args.case)
        if requested - {c["id"] for c in cells}:
            raise ValueError("requested case not present in manifest")
        cells = [c for c in cells if c["id"] in requested]
    if args.jobs < 1:
        raise ValueError("jobs must be positive")
    engine = args.engine.resolve()
    inputs = args.inputs.resolve()
    libraries = [p.resolve() for p in args.library_dir]
    if not engine.is_file() or not os.access(engine, os.X_OK):
        raise ValueError("engine is missing or not executable")
    if any(not p.is_dir() for p in libraries):
        raise ValueError("library directory is missing")
    if os.environ.get("LD_PRELOAD") or os.environ.get("LD_AUDIT"):
        raise ValueError("unset LD_PRELOAD/LD_AUDIT for registered runs")
    for cell in cells:
        source = inputs / (cell["elf_sha256"] + ".elf")
        if not source.is_file() or digest(source) != cell["elf_sha256"]:
            raise ValueError("missing or changed input: " + cell["id"])
    identities = {str(engine): digest(engine)}
    for directory in libraries:
        for library in directory.glob("*.so*"):
            if library.is_file():
                identities[str(library)] = digest(library)
    registered = manifest.get("candidate", {}).get("build", {})
    if registered:
        if digest(engine) != registered.get("stage/elfrun"):
            raise ValueError("engine is not the registered candidate; use a separately registered manifest")
        dbt_library = next((p / "libdbtjitshared.so" for p in libraries
                            if (p / "libdbtjitshared.so").is_file()), None)
        if dbt_library is None or digest(dbt_library) != registered.get("stage/libdbtjitshared.so"):
            raise ValueError("libdbtjitshared.so is not the registered candidate")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ)
    if libraries:
        environment["LD_LIBRARY_PATH"] = os.pathsep.join(map(str, libraries))
    save(out / "manifest.json", manifest)
    save(out / "invocation.json", {
        "argv": sys.argv, "manifest_sha256": digest(manifest_path),
        "runner_sha256": digest(__file__), "python": sys.version,
        "engine_files_before": identities, "selected_cases": [c["id"] for c in cells],
        "LD_LIBRARY_PATH": environment.get("LD_LIBRARY_PATH", ""), "jobs": args.jobs,
        "scope": "correctness replay; not a performance measurement or route-coverage proof",
    })
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda c: execute(c, engine, inputs, out, environment,
                                                manifest["timeout_seconds"]), cells))
    after = {p: digest(p) if Path(p).is_file() else None for p in identities}
    # Compare parsed manifests as serialization formatting need not match the source.
    unchanged = identities == after and load_manifest(manifest_path) == manifest
    counts = dict(Counter(r["status"] for r in results))
    success = unchanged and all(r["status"] == "PASS" for r in results)
    save(out / "results.json", results)
    summary = {
        "status": "PASS" if success else "FAIL", "counts": counts,
        "cases_executed": len(results), "controls": sum(r["control"] for r in results),
        "positive_case_counts": dict(Counter(r["status"] for r in results if not r["control"])),
        "control_expectation_counts": dict(Counter(r["status"] for r in results if r["control"])),
        "candidate_unchanged": unchanged, "engine_files_after": after,
        "instruction_coverage": "not inferred from case count",
    }
    save(out / "summary.json", summary)
    print(json.dumps(summary))
    return 0 if success else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True,
                        help="directory containing <sha256>.elf files")
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--library-dir", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True, help="must not already exist")
    parser.add_argument("--case", action="append")
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("RVV runner error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
