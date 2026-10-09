#!/usr/bin/env python3
"""Export a selected replay bundle without changing registered inputs or answers."""

import argparse
import json
from pathlib import Path
import shutil
import sys

from rvv_tests import digest, load_manifest, save


def export(args):
    manifest = load_manifest(args.manifest)
    selected = []
    matched = set()
    origins = {}
    for cell in manifest["cells"]:
        if cell.get("vlen") != args.vlen:
            continue
        aliases = [a for a in cell.get("aliases", [])
                   if a["batch"] == args.batch and a["test"] in args.test]
        if not aliases:
            continue
        matched.update(a["test"] for a in aliases)
        source = next((args.evidence_root / a["source_elf"] for a in aliases
                       if (args.evidence_root / a["source_elf"]).is_file()), None)
        if source is None or digest(source) != cell["elf_sha256"]:
            raise ValueError("original ELF missing or changed for " + cell["id"])
        origins[cell["elf_sha256"]] = source
        selected.append(cell)
    if matched != set(args.test):
        raise ValueError("no registered cases for: " + ", ".join(sorted(set(args.test) - matched)))
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "inputs").mkdir()
    for sha, source in origins.items():
        shutil.copyfile(source, args.output / "inputs" / (sha + ".elf"))
    manifest["cells"] = selected
    manifest["replay_selection"] = {
        "original_manifest_sha256": digest(args.manifest),
        "batch": args.batch, "tests": args.test, "vlen": args.vlen,
        "policy": "original cells, flags, expected outputs and candidate identity retained",
        "purpose": "runner reproducibility check; does not add semantic coverage",
    }
    save(args.output / "manifest.json", manifest)
    print(json.dumps({"selected_cases": len(selected), "distinct_ELFs": len(origins),
                      "output": str(args.output)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--batch", required=True)
    parser.add_argument("--test", action="append", required=True)
    parser.add_argument("--vlen", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        export(args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("RVV replay export error: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
