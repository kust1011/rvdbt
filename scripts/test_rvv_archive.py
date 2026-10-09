"""Archive integrity controls, not guest instruction tests."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import audit_rvv_results as audit
import rvv_tests as runner


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        source = self.root / "placeholder"
        source.write_bytes(b"not an ISA fixture")
        sha = runner.digest(source)
        source.rename(self.inputs / (sha + ".elf"))
        engine = self.root / "engine"
        engine.write_text("#!/bin/sh\nprintf 'PASS\\n'\n")
        engine.chmod(0o700)
        manifest = self.root / "manifest.json"
        runner.save(manifest, {"timeout_seconds": 1, "cells": [{
            "id": "one", "elf_sha256": sha, "flags": ["--fsroot={WORK}/fs"],
            "expected_returncode": 0, "expected_stdout": "PASS\n", "control": False}]})
        self.results = self.root / "results"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runner.run(SimpleNamespace(manifest=manifest, inputs=self.inputs,
                engine=engine, library_dir=[], output=self.results, jobs=1, case=None)), 0)

    def test_unchanged_archive(self):
        self.assertEqual(audit.audit(self.results, self.inputs)["records_checked"], 1)

    def test_corrupt_raw(self):
        (self.results / "one/stdout").write_bytes(b"WRONG\n")
        with self.assertRaisesRegex(ValueError, "raw stream mismatch"):
            audit.audit(self.results, self.inputs)

    def test_forged_pass_with_updated_digest(self):
        raw = self.results / "one/stdout"
        raw.write_bytes(b"WRONG\n")
        path = self.results / "one/result.json"
        record = json.loads(path.read_text())
        record["stdout_sha256"] = runner.digest(raw)
        runner.save(path, record)
        with self.assertRaisesRegex(ValueError, "classification mismatch"):
            audit.audit(self.results, self.inputs)

    def test_changed_flags(self):
        runner.save(self.results / "one/command.json", [str(self.root / "engine"),
                    "--fsroot=/x/fs", "--vlen=4096"])
        with self.assertRaisesRegex(ValueError, "command flags mismatch"):
            audit.audit(self.results, self.inputs)

    def test_wrong_summary(self):
        path = self.results / "summary.json"
        summary = json.loads(path.read_text())
        summary["cases_executed"] = 900
        runner.save(path, summary)
        with self.assertRaisesRegex(ValueError, "case count differs"):
            audit.audit(self.results, self.inputs)

    def test_missing_input(self):
        next(self.inputs.iterdir()).unlink()
        with self.assertRaises(FileNotFoundError):
            audit.audit(self.results, self.inputs)
