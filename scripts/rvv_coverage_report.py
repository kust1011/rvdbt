#!/usr/bin/env python3
"""Publish the existing per-form evidence index, without inventing coverage."""

import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import sys

from rvv_tests import digest, save


def export(source, output, supplements=None):
    csv.field_size_limit(sys.maxsize)
    with source.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    required_columns = {"form", "family", "rv32_elen64_applicability", "actual_final_join",
                        "configuration_scope", "unverified_json", "m1_actual_admission",
                        "final_unique_positive_cells"}
    if not rows or not required_columns <= rows[0].keys():
        raise ValueError("missing required per-form evidence columns")
    names = [r["form"] for r in rows]
    if len(names) != len(set(names)):
        raise ValueError("duplicate instruction forms")
    items = []
    for row in rows:
        item = {}
        for key, value in row.items():
            if key.endswith("_json"):
                item[key[:-5]] = json.loads(value) if value else None
            else:
                item[key] = value
        items.append(item)
    supplemental_records = []
    if supplements is not None:
        supplemental_records = json.loads(supplements.read_text())
        if not isinstance(supplemental_records, list):
            raise ValueError("supplemental evidence must be a list")
        identifiers = set()
        for record in supplemental_records:
            required_fields = {"id", "forms", "candidate", "configuration", "checker",
                               "result", "evidence", "limitations"}
            if not isinstance(record, dict) or not required_fields <= record.keys():
                raise ValueError("incomplete supplemental evidence record")
            if not isinstance(record["id"], str) or not record["id"] or record["id"] in identifiers:
                raise ValueError("duplicate or empty supplemental id")
            identifiers.add(record["id"])
            forms = record["forms"]
            if not isinstance(forms, list) or not forms or not all(isinstance(f, str) for f in forms):
                raise ValueError("supplement must name instruction forms")
            if len(forms) != len(set(forms)) or set(forms) - set(names):
                raise ValueError("unknown or duplicate supplemental form")
            if not all(record[k] for k in required_fields):
                raise ValueError("supplemental evidence fields must not be empty")
            for item in items:
                if item["form"] in forms:
                    item.setdefault("supplemental_evidence", []).append(record)
    families = sorted({r["family"] for r in rows})
    summary = []
    for family in families:
        group = [r for r in rows if r["family"] == family]
        required = [r for r in group if r["rv32_elen64_applicability"] == "REQUIRED"]
        summary.append({"family": family, "inventoried_forms": len(group),
                        "required_forms": len(required),
                        "forms_with_final_positive_records": sum(r["actual_final_join"] == "PASS_FINAL_MANIFEST_LEDGER_RAW" for r in required),
                        "forms_with_recorded_unverified_items": sum(bool(json.loads(r["unverified_json"])) for r in required)})
    output.mkdir(parents=True, exist_ok=False)
    save(output / "forms.json", items)
    save(output / "summary.json", {
        "source_sha256": digest(source), "form_count": len(rows),
        "applicability": dict(Counter(r["rv32_elen64_applicability"] for r in rows)),
        "families": summary,
        "supplements_sha256": digest(supplements) if supplements is not None else None,
        "supplemental_records": len(supplemental_records),
        "supplement_scope": "indexed separately; does not replace historical gaps or increment form PASS counts",
        "scope": "existing evidence index; no new DUT executions and no exhaustive-semantic claim",
    })
    lines = ["# RVV verification evidence", "",
             "This report summarizes registered evidence, not a new test run. A positive",
             "record verifies the original checker's observations in the recorded configuration;",
             "it does not establish every semantic case or a native/M1/M2 route.", "",
             "## Family summary", "",
             "| Family | Inventoried forms | Applicable forms | Forms with final positive records | Forms with recorded gaps |",
             "|---|---:|---:|---:|---:|"]
    for row in summary:
        lines.append("| {family} | {inventoried_forms} | {required_forms} | {forms_with_final_positive_records} | {forms_with_recorded_unverified_items} |".format(**row))
    lines += ["", "## Per-form evidence", "",
              "`forms.json` retains each form's source/checker/configuration evidence,",
              "original record locations, path-observation scope and unverified items.",
              "Cells, source occurrences, assertions and distinct instruction forms are different counts.",
              "The source CSV is identified in `summary.json`; all original limitations are retained.", ""]
    if supplemental_records:
        lines += ["## Supplemental evidence", "",
                  "Later scoped observations are attached to the relevant forms under",
                  "`supplemental_evidence`. Read their configuration, checker and limitations",
                  "alongside historical records. Indexing is not independent verification",
                  "and does not imply that every historical gap has been closed.", ""]
    (output / "README.md").write_text("\n".join(lines))
    print(json.dumps({"forms": len(rows), "families": len(families), "output": str(output)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forms", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--supplements", type=Path, help="scoped later evidence; preserves historical records")
    args = parser.parse_args()
    try:
        export(args.forms, args.output, args.supplements)
    except (OSError, ValueError, KeyError, csv.Error) as exc:
        print("RVV coverage export error: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
