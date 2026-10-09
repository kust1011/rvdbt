#!/usr/bin/env python3
"""Check archived runner records against raw output; does not execute the DUT."""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

import rvv_tests as runner


def read(path):
    return json.loads(path.read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def audit(results, inputs):
    manifest = runner.load_manifest(results / "manifest.json")
    invocation = read(results / "invocation.json")
    summary = read(results / "summary.json")
    selected = invocation["selected_cases"]
    require(isinstance(selected, list) and selected, "empty selection")
    require(len(selected) == len(set(selected)), "duplicate selection")
    registered = {c["id"]: c for c in manifest["cells"]}
    require(set(selected) <= registered.keys(), "unregistered selection")
    require(invocation["engine_files_before"] == summary["engine_files_after"],
            "recorded executable identities changed")
    build = manifest.get("candidate", {}).get("build", {})
    for key, expected in build.items():
        name = Path(key).name
        matches = [value for path, value in invocation["engine_files_before"].items()
                   if Path(path).name == name]
        require(matches and all(value == expected for value in matches),
                "recorded build mismatch: " + name)
    checked = []
    for name in selected:
        cell = registered[name]
        directory = results / name
        require(read(directory / "case.json") == cell, "registration mismatch: " + name)
        record = read(directory / "result.json")
        require(record["id"] == name and record["control"] == cell["control"],
                "case identity mismatch: " + name)
        require(record["elf_sha256"] == cell["elf_sha256"], "ELF record mismatch: " + name)
        require(runner.digest(inputs / (cell["elf_sha256"] + ".elf")) == cell["elf_sha256"],
                "input mismatch: " + name)
        for stream in ("stdout", "stderr"):
            require(runner.digest(directory / stream) == record[stream + "_sha256"],
                    "raw stream mismatch: " + name + "/" + stream)
        command = read(directory / "command.json")
        require(isinstance(command, list) and command, "missing command: " + name)
        require(command[0] in invocation["engine_files_before"], "unknown engine: " + name)
        # Original absolute WORK paths remain valid provenance after relocation.
        work_flags = [arg for arg in command[1:] if arg.startswith("--fsroot=")]
        require(len(work_flags) == 1 and work_flags[0].endswith("/fs"),
                "missing work directory: " + name)
        work = work_flags[0][len("--fsroot="):-len("/fs")]
        require(command[1:] == [arg.replace("{WORK}", work) for arg in cell["flags"]],
                "command flags mismatch: " + name)
        # Preserve historical TIMEOUT: old records lack an independent timed_out field.
        status = runner.classify(record["returncode"], (directory / "stdout").read_bytes(),
                                 cell, record["status"] == "TIMEOUT", record["error"])
        require(status == record["status"], "classification mismatch: " + name)
        checked.append(record)
    require(checked == read(results / "results.json"), "aggregate records differ")
    require(dict(Counter(r["status"] for r in checked)) == summary["counts"],
            "summary counts differ")
    require(summary["cases_executed"] == len(checked), "case count differs")
    require(summary["controls"] == sum(c["control"] for c in checked), "control count differs")
    for field, control in (("positive_case_counts", False), ("control_expectation_counts", True)):
        require(summary[field] == dict(Counter(r["status"] for r in checked
                                              if r["control"] == control)), field + " differs")
    expected_status = "PASS" if all(r["status"] == "PASS" for r in checked) else "FAIL"
    require(summary["candidate_unchanged"] is True and summary["status"] == expected_status,
            "summary disposition differs")
    return {"archive_consistent": True, "records_checked": len(checked),
            "recorded_test_status": expected_status, "new_dut_executions": 0,
            "scope": "raw-record consistency, not independent ISA or execution attestation"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(audit(args.results, args.inputs)))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("Archive audit failed: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
