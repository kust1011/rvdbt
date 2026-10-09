#!/usr/bin/env python3
"""Harness tests only: these synthetic processes do not verify RISC-V semantics."""

import contextlib
import base64
import csv
import io
import json
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest

import rvv_tests as runner
import rvv_coverage_report as coverage


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        placeholder = self.root / "input"
        placeholder.write_bytes(b"harness fixture, not an ELF")
        self.sha = runner.digest(placeholder)
        placeholder.rename(self.inputs / (self.sha + ".elf"))
        self.engine = self.root / "engine"
        self.engine.write_text("#!/bin/sh\nprintf 'PASS\\n'\n")
        self.engine.chmod(0o700)
        self.cell = {"id": "one", "elf_sha256": self.sha, "flags": [],
                     "expected_returncode": 0, "expected_stdout": "PASS\n", "control": False}
        self.manifest = self.root / "manifest.json"
        self.register()

    def register(self):
        self.manifest.write_text(json.dumps({"cells": [self.cell], "timeout_seconds": 1}))

    def args(self, **kwargs):
        values = dict(manifest=self.manifest, engine=self.engine, inputs=self.inputs,
                      output=self.root / "output", library_dir=[], jobs=1, case=None)
        values.update(kwargs)
        return SimpleNamespace(**values)

    def run_case(self, code):
        self.engine.write_text("#!/bin/sh\n" + code + "\n")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = runner.run(self.args())
        result = json.loads((self.root / "output" / "one" / "result.json").read_text())
        return rc, result["status"]

    def test_success(self):
        self.assertEqual(self.run_case("printf 'PASS\\n'"), (0, "PASS"))

    def test_binary_reference_output(self):
        del self.cell["expected_stdout"]
        self.cell["expected_stdout_base64"] = base64.b64encode(b"\x00\xff\x80").decode()
        self.register()
        self.assertEqual(self.run_case("printf '\\000\\377\\200'"), (0, "PASS"))

    def test_binary_reference_mismatch(self):
        del self.cell["expected_stdout"]
        self.cell["expected_stdout_base64"] = base64.b64encode(b"\x00\xff\x80").decode()
        self.register()
        self.assertEqual(self.run_case("printf '\\000\\377\\201'"), (1, "OUTPUT_MISMATCH"))

    def test_ambiguous_output_registration(self):
        self.cell["expected_stdout_base64"] = "AA=="
        self.register()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            runner.load_manifest(self.manifest)

    def test_pass_text_does_not_override_exit_failure(self):
        self.assertEqual(self.run_case("printf 'PASS\\n'; exit 7"), (1, "EXIT_MISMATCH"))

    def test_wrong_output(self):
        self.assertEqual(self.run_case("printf 'WRONG\\n'"), (1, "OUTPUT_MISMATCH"))

    def test_missing_output(self):
        self.assertEqual(self.run_case("exit 0"), (1, "OUTPUT_MISMATCH"))

    def test_extra_output_is_not_ignored(self):
        self.assertEqual(self.run_case("printf 'FAIL\\nPASS\\n'"), (1, "OUTPUT_MISMATCH"))

    def test_timeout(self):
        self.assertEqual(self.run_case("exec sleep 5"), (1, "TIMEOUT"))

    def test_crash(self):
        self.assertEqual(self.run_case("kill -TERM $$"), (1, "CRASH"))

    def test_skip_returncode_is_not_pass(self):
        self.assertEqual(self.run_case("exit 77"), (1, "EXIT_MISMATCH"))

    def test_no_stale_output_reuse(self):
        (self.root / "output").mkdir()
        with self.assertRaises(FileExistsError):
            runner.run(self.args())

    def test_missing_engine(self):
        self.engine.unlink()
        with self.assertRaisesRegex(ValueError, "engine is missing"):
            runner.run(self.args())

    def test_launch_error(self):
        self.engine.write_text("#!/nonexistent/loader\n")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runner.run(self.args()), 1)
        result = json.loads((self.root / "output" / "one" / "result.json").read_text())
        self.assertEqual(result["status"], "ERROR")

    def test_input_changed(self):
        (self.inputs / (self.sha + ".elf")).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "missing or changed input"):
            runner.run(self.args())

    def test_missing_input(self):
        (self.inputs / (self.sha + ".elf")).unlink()
        with self.assertRaisesRegex(ValueError, "missing or changed input"):
            runner.run(self.args())

    def test_case_selection_typo(self):
        with self.assertRaisesRegex(ValueError, "requested case"):
            runner.run(self.args(case=["not-registered"]))

    def test_duplicate_id(self):
        self.manifest.write_text(json.dumps({"cells": [self.cell, self.cell], "timeout_seconds": 1}))
        with self.assertRaisesRegex(ValueError, "duplicate case"):
            runner.load_manifest(self.manifest)

    def test_path_traversal(self):
        self.cell["id"] = "../escape"
        self.register()
        with self.assertRaisesRegex(ValueError, "unsafe case"):
            runner.load_manifest(self.manifest)

    def test_no_signal_as_expected_trap(self):
        self.cell["expected_returncode"] = -signal.SIGSEGV
        self.register()
        with self.assertRaisesRegex(ValueError, "host signals"):
            runner.load_manifest(self.manifest)

    def test_reject_wrong_registered_engine(self):
        data = json.loads(self.manifest.read_text())
        data["candidate"] = {"build": {"stage/elfrun": "0" * 64}}
        self.manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "not the registered candidate"):
            runner.run(self.args())

    def test_expected_failure_is_separate_from_positive_case(self):
        self.cell["expected_returncode"] = 1
        self.register()
        with self.assertRaisesRegex(ValueError, "explicit control"):
            runner.load_manifest(self.manifest)
        self.cell["control"] = True
        self.cell["expected_stdout"] = "FAIL\n"
        self.register()
        self.assertEqual(self.run_case("printf 'FAIL\\n'; exit 1"), (0, "PASS"))
        summary = json.loads((self.root / "output" / "summary.json").read_text())
        self.assertEqual(summary["positive_case_counts"], {})
        self.assertEqual(summary["control_expectation_counts"], {"PASS": 1})

    def test_parallel_outputs_are_isolated(self):
        data = json.loads(self.manifest.read_text())
        data["cells"].append(dict(self.cell, id="two", control=True))
        self.manifest.write_text(json.dumps(data))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runner.run(self.args(jobs=2)), 0)
        results = json.loads((self.root / "output" / "results.json").read_text())
        self.assertEqual([r["id"] for r in results], ["one", "two"])
        self.assertEqual(sum(r["control"] for r in results), 1)
        for name in ("one", "two"):
            self.assertTrue((self.root / "output" / name / "work" / "fs" / "t.elf").exists())

    def test_coverage_uses_actual_join_status_not_generic_pass(self):
        source = self.root / "forms.csv"
        row = dict(form="vadd.vv", family="integer_single_width",
                   rv32_elen64_applicability="REQUIRED",
                   actual_final_join="PASS_FINAL_MANIFEST_LEDGER_RAW",
                   configuration_scope="specified cases only", unverified_json='["tail"]',
                   m1_actual_admission="not observed", final_unique_positive_cells="4")
        with source.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(row))
            writer.writeheader()
            writer.writerow(row)
        with contextlib.redirect_stdout(io.StringIO()):
            coverage.export(source, self.root / "coverage")
        summary = json.loads((self.root / "coverage" / "summary.json").read_text())
        family = summary["families"][0]
        self.assertEqual(family["forms_with_final_positive_records"], 1)
        self.assertEqual(family["forms_with_recorded_unverified_items"], 1)

        later = dict(id="later", forms=["vadd.vv"], candidate="separate build",
                     configuration="one configuration", checker="external oracle",
                     result="PASS", evidence="raw path", limitations=["no restart"])
        supplemental = self.root / "supplements.json"
        supplemental.write_text(json.dumps([later]))
        with contextlib.redirect_stdout(io.StringIO()):
            coverage.export(source, self.root / "joined", supplemental)
        merged = json.loads((self.root / "joined/forms.json").read_text())[0]
        joined_summary = json.loads((self.root / "joined/summary.json").read_text())
        self.assertEqual(merged["unverified"], ["tail"])
        self.assertEqual(merged["final_unique_positive_cells"], "4")
        self.assertEqual(merged["supplemental_evidence"], [later])
        self.assertEqual(joined_summary["families"], summary["families"])
        self.assertEqual(joined_summary["supplemental_records"], 1)
        for invalid in ([dict(later, forms=["invented.form"])], [later, later],
                        [dict(later, checker="")], [dict(later, forms=[])], {"not": "list"}):
            with self.subTest(invalid=invalid):
                supplemental.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    coverage.export(source, self.root / "invalid", supplemental)
                self.assertFalse((self.root / "invalid").exists())


if __name__ == "__main__":
    unittest.main()
