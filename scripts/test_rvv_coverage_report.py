"""Readable-export controls; synthetic evidence is not ISA validation."""

import contextlib
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest

import rvv_coverage_report as coverage


class ReadableCoverageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def publish(self, **changes):
        row = dict(form="vadd.vv", family="integer_single_width",
                   rv32_elen64_applicability="REQUIRED",
                   actual_final_join="NO_FINAL_RECORD", configuration_scope="",
                   unverified_json='["overlap unknown"]', m1_actual_admission="not observed",
                   final_unique_positive_cells="0", execution_evidence_json="[]",
                   name_source_coverage_json='{"suite": {"state": "SOURCE_NAME_ONLY_NOT_RUNTIME"}}')
        supplements = changes.pop("supplements", None)
        row.update(changes)
        source = self.root / "forms.csv"
        with source.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(row))
            writer.writeheader()
            writer.writerow(row)
        supplemental_path = None
        if supplements is not None:
            supplemental_path = self.root / "supplements.json"
            supplemental_path.write_text(json.dumps(supplements))
        output = self.root / "coverage"
        with contextlib.redirect_stdout(io.StringIO()):
            coverage.export(source, output, supplemental_path)
        with (output / "forms.tsv").open(newline="") as stream:
            table = list(csv.DictReader(stream, delimiter="\t"))
        item = json.loads((output / "forms.json").read_text())[0]
        detail = (output / table[0]["detail"]).read_text()
        # Every navigation column resolves to a supplied or explicitly unknown section.
        for key, value in table[0].items():
            if key.endswith("_detail"):
                path, anchor = value.split("#")
                self.assertEqual(path, table[0]["detail"])
                self.assertIn("## " + anchor + "\n", detail)
        expected = {key[:-5] if key.endswith("_json") else key:
                    json.loads(value) if key.endswith("_json") else value
                    for key, value in row.items()}
        if supplements:
            expected["supplemental_evidence"] = supplements
        self.assertEqual(item, expected)
        return table[0], item, detail, json.loads((output / "summary.json").read_text())

    def test_na_retains_historical_name_records_without_required_pass(self):
        row, item, detail, summary = self.publish(
            form="vloxei64.v", family="indexed_memory",
            rv32_elen64_applicability="NOT_APPLICABLE",
            actual_final_join="NOT_APPLICABLE_NO_REQUIRED_EXECUTION",
            four_configurations_pass="NOT_APPLICABLE",
            act_legacy_execution_json=json.dumps({"archived_2048_records": 12,
                "candidate_identity": "historical engine; filename only"}))
        self.assertEqual(row["applicability"], "NOT_APPLICABLE")
        self.assertEqual(row["B_raw_examples"], "unknown")
        self.assertEqual(summary["families"][0]["required_forms"], 0)
        self.assertEqual(summary["families"][0]["forms_with_final_positive_records"], 0)
        self.assertIn("historical engine; filename only", detail)
        self.assertIn(coverage.markdown_text("NOT_APPLICABLE_NO_REQUIRED_EXECUTION"), detail)

    def test_source_only_does_not_create_runtime_or_admission(self):
        row, item, detail, summary = self.publish()
        self.assertEqual(row["source_suite_records"], "suite")
        self.assertEqual(row["final_unique_positive_cells"], "0")
        for arm in ("B", "M1", "M2", "Both"):
            self.assertEqual(row[arm + "_raw_examples"], "unknown")
        self.assertEqual(summary["families"][0]["forms_with_final_positive_records"], 0)
        self.assertIn(coverage.markdown_text("SOURCE_NAME_ONLY_NOT_RUNTIME"), detail)
        self.assertIn("unknown / not supplied", detail)
        self.assertNotIn("four_configurations_pass", item)
        self.assertIn("not observed", detail)

    def test_historical_runtime_examples_and_complete_index_are_distinct(self):
        evidence = self.root / "CANDIDATE_IDENTITY.json"
        evidence.write_text('{"build": "historical"}')
        row, item, detail, summary = self.publish(
            actual_final_join="PASS_FINAL_MANIFEST_LEDGER_RAW",
            final_unique_positive_cells="80", four_configurations_pass="YES",
            final_candidate_identity_evidence="CANDIDATE_IDENTITY.json",
            execution_evidence_json=json.dumps([{"complete_index": "unavailable/ALIAS_RESULTS.csv",
                "scope": "examples are not the full set", "raw_examples": [
                    {"arm": arm, "status": "PASS", "vlen": 1024}
                    for arm in ("B", "M1", "M2", "BOTH")]}]),
            source_checker_batches_json=json.dumps([{"checker": "selected words only",
                "direct_csr_assertions": {}, "labels_scope": "source sets, not runtime VL"}]))
        self.assertEqual(row["Both_raw_examples"], "PASS (1 examples)")
        self.assertEqual(row["final_unique_positive_cells"], "80")
        self.assertIn("selected words only", detail)
        self.assertIn("source sets, not runtime VL", detail)
        self.assertIn("[CANDIDATE\\_IDENTITY.json](../../CANDIDATE_IDENTITY.json)", detail)
        self.assertIn("unavailable/ALIAS\\_RESULTS.csv", detail)
        self.assertNotIn("](../../unavailable/", detail)
        self.assertEqual(item["m1_actual_admission"], "not observed")

    def test_scoped_supplement_preserves_failure_identity_and_gaps(self):
        supplement = dict(id="bounded", forms=["vadd.vv"], candidate="separate clean build",
            configuration="Both/VL15", checker="offline selected state",
            result="bounded observation; original whole-test FAIL remains",
            evidence="review.md;raw.json", limitations=["no intermediate CSR", "no restart"])
        row, item, detail, summary = self.publish(supplements=[supplement])
        self.assertEqual(row["supplement_records"], "1")
        self.assertEqual(row["recorded_gap_items"], "1")
        self.assertEqual(row["Both_raw_examples"], "unknown")
        self.assertEqual(summary["families"][0]["forms_with_final_positive_records"], 0)
        self.assertEqual(item["unverified"], ["overlap unknown"])
        self.assertIn("original whole-test FAIL remains", detail)
        self.assertIn("separate clean build", detail)
        self.assertIn("no intermediate CSR", detail)
        self.assertIn("overlap unknown", detail)


if __name__ == "__main__":
    unittest.main()
