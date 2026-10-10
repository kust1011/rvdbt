#!/usr/bin/env python3
"""Publish the existing per-form evidence index, without inventing coverage."""

import argparse
from collections import Counter
import csv
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote

from rvv_tests import digest, save


def markdown_text(value):
    """Keep source text literal, including pipes and HTML-like checker output."""
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace("\\", "\\\\")
            .replace("`", "\\`").replace("*", "\\*")
            .replace("_", "\\_").replace("[", "\\[")
            .replace("]", "\\]").replace("|", "\\|")
            .replace("\n", "<br>"))


def render_value(value, roots, page, depth=0):
    """Render every supplied field, with one list entry per fact (no JSON cells).

    Reference links are added only for existing local paths. Selectors and unknown
    paths remain verbatim; exporting does not audit their content or provenance.
    """
    indent = "  " * depth
    if isinstance(value, dict) and value:
        lines = []
        for key, child in value.items():
            lines.append(indent + "- **" + markdown_text(key) + "**:")
            lines.extend(render_value(child, roots, page, depth + 1))
        return lines
    if isinstance(value, list) and value:
        lines = []
        for index, child in enumerate(value, 1):
            if isinstance(child, (dict, list)):
                lines.append(indent + f"- Record {index}:")
                lines.extend(render_value(child, roots, page, depth + 1))
            else:
                lines.extend(render_value(child, roots, page, depth))
        return lines
    if value is None or value == "":
        label = "unknown / not supplied"
    elif value == [] or value == {}:
        label = "empty in source (no entries recorded)"
    elif isinstance(value, bool):
        label = str(value).lower()
    else:
        label = markdown_text(value)
    lines = [indent + "- " + label]
    if isinstance(value, str):
        # Paths are supplemental navigation; never rewrite the original string.
        for token in dict.fromkeys(re.findall(r"(?:artifacts/)?[\w./-]+\.[\w-]+", value)):
            for root in roots:
                target = root / token
                if target.is_file() or target.is_dir():
                    href = quote(os.path.relpath(target, page.parent), safe="/")
                    lines.append(indent + "  - Reference: [" + markdown_text(token) + "](" + href + ")")
                    break
    return lines


def example_results(item, arm):
    """Only statuses explicitly attached to final-join raw examples, not switches.

    The complete index and aggregate four-configuration result are separate facts.
    Examples may be a subset and must not be presented as execution totals.
    """
    statuses = Counter(example["status"]
                       for record in item.get("execution_evidence") or []
                       for example in record.get("raw_examples", [])
                       if example.get("arm") == arm and example.get("status"))
    return "; ".join(f"{key} ({count} examples)" for key, count in sorted(statuses.items())) or "unknown"


def export_readable(items, output, source, supplements):
    """Presentation only: do not modify items or any coverage accounting."""
    roots = [source.parent]
    # Existing indexes use paths relative to the thesis root (artifacts/...).
    roots.extend(parent.parent for parent in source.parents if parent.name == "artifacts")
    if supplements is not None:
        roots.insert(0, supplements.parent)
    (output / "forms").mkdir()
    (output / "families").mkdir()
    families = sorted({x["family"] for x in items})
    columns = ["form", "family", "applicability", "source_suite_records",
               "historical_name_record", "actual_final_join", "final_unique_positive_cells",
               "four_configurations_pass", "B_raw_examples", "M1_raw_examples",
               "M2_raw_examples", "Both_raw_examples", "supplement_records",
               "recorded_gap_items", "detail", "source_presence_detail",
               "execution_detail", "configuration_detail", "checker_state_detail",
               "build_detail", "admission_detail", "supplements_detail", "gaps_detail"]
    tsv_rows = []
    for index, item in enumerate(items, 1):
        # Stable ordinal filenames avoid interpreting source names as filesystem paths.
        detail = f"forms/{index:04d}.md"
        row = dict(form=item["form"], family=item["family"],
                   applicability=item["rv32_elen64_applicability"],
                   source_suite_records="; ".join(sorted(item.get("name_source_coverage") or {})) or "unknown",
                   supplement_records=len(item.get("supplemental_evidence", [])),
                   recorded_gap_items=len(item.get("unverified") or []), detail=detail)
        for key in ("historical_name_record", "actual_final_join", "final_unique_positive_cells", "four_configurations_pass"):
            row[key] = item.get(key) or "unknown"
        for label, arm in (("B", "B"), ("M1", "M1"), ("M2", "M2"), ("Both", "BOTH")):
            row[label + "_raw_examples"] = example_results(item, arm)
        for label, field in (("source_presence", "name_source_coverage"),
                             ("execution", "execution_evidence"),
                             ("configuration", "configuration_scope"),
                             ("checker_state", "source_checker_batches"),
                             ("build", "final_candidate_identity_evidence"),
                             ("admission", "m1_actual_admission"),
                             ("supplements", "supplemental_evidence"), ("gaps", "unverified")):
            row[label + "_detail"] = detail + "#" + field.replace("_", "-")
        tsv_rows.append(row)
        page = output / detail
        lines = ["# " + markdown_text(item["form"]), "",
                 "[Report](../README.md) · [Family](../families/" + f"{families.index(item['family']) + 1:02d}.md)", "",
                 "Source-suite records are name/source observations, not executions. Final-join",
                 "raw examples are sampled records; complete indexes and selectors are retained below.",
                 "Historical build identities and scoped supplements remain separate. Switches and",
                 "PASS do not establish native SIMD or target-specific M1/M2 admission.", "",
                 "All fields below retain source names and values. Empty entries are not proof of absence.",
                 "Configuration tuple positions retain their source ordering; no missing labels are inferred.", ""]
        fields = dict(item)
        for key in ("name_source_coverage", "execution_evidence", "configuration_scope",
                    "source_checker_batches", "final_candidate_identity_evidence",
                    "m1_actual_admission", "supplemental_evidence", "unverified"):
            fields.setdefault(key, None)
        for key, value in fields.items():
            lines += ["## " + key.replace("_", "-"), ""]
            lines.extend(render_value(value, roots, page))
            lines.append("")
        page.write_text("\n".join(lines))
    with (output / "forms.tsv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, delimiter="\t")
        writer.writeheader()
        writer.writerows(tsv_rows)
    links = []
    for index, family in enumerate(families, 1):
        filename = f"families/{index:02d}.md"
        group = [row for row in tsv_rows if row["family"] == family]
        links.append(f"- [{family}]({filename}) ({len(group)} named forms)")
        lines = ["# " + markdown_text(family), "", "[Report](../README.md)", "",
                 "Results below are the recorded final join, not source availability or method admission.", "",
                 "| Form | Applicability | Final join | Positive cells | Supplements | Gap items |",
                 "|---|---|---|---:|---:|---:|"]
        for row in group:
            lines.append("| [" + markdown_text(row["form"]) + "](../" + row["detail"] + ") | " +
                         " | ".join(markdown_text(row[key]) for key in
                                    ("applicability", "actual_final_join", "final_unique_positive_cells", "supplement_records", "recorded_gap_items")) + " |")
        (output / filename).write_text("\n".join(lines) + "\n")
    return ["## Readable per-form export", "",
            "[forms.tsv](forms.tsv) has one row per named form, including N/A. Its compact",
            "columns link to full per-form fields rather than embedding large evidence cells.",
            "B/M1/M2/Both columns count statuses in final-join **raw examples only**; they",
            "are not complete execution counts. `four_configurations_pass` is the separate",
            "source aggregate. Unknown means no supplied value/example, including for N/A.",
            "Suite names identify source records; read their states, booleans and selectors",
            "before claiming presence. Historical ACT filename associations remain historical.",
            "Checker/state scope, source configurations versus runtime observations, build",
            "references, admission evidence, supplements and gaps are retained in the details.",
            "Supplements do not erase historical gaps or add form PASSes. Existing local",
            "references are linked for navigation; this export does not audit those targets.", ""] + links + [""]


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
    lines += export_readable(items, output, source, supplements)
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
