# Accepted Ara inspection bundle — Task91

[Download the compressed review bundle](ara-review-task91.tar.gz). [Manifest](MANIFEST.json), [source navigation](SOURCES.md), [exact case inventory](CASES.json), [offline acceptance](OFFLINE_ACCEPTANCE.json), and [corrupted-output rejection](REJECTION_CHECK.json) are retained beside it.

Extract into a new directory, change into that directory, then run:

```sh
tar xzf /path/to/ara-review-task91.tar.gz
python3 tools/verify_rvv_ara_bundle.py .
```

Python 3.9+ and its standard library suffice; the checker works offline. It verifies payload identities and invokes the retained Ara parsers on stored stdout and exit codes. It also checks original source ranges, compiled adapter identities, Ara89 exact configurations/initialization, and the MAC function-scoped acceptance with whole-file failures. Archive integrity alone does not establish acceptance.

Task92 hardens package navigation: absolute/traversing names, symlinks in any
path component, and unmanifested references are rejected before evidence is
read. [Focused rejection tests](../../../scripts/test_rvv_ara_bundle.py) and
[Task92 checker controls](TASK92_CHECKS.json) cover this correction and a failed
raw assertion with its transport hashes updated. Original raw data and legal
prefix bookkeeping are unchanged. The rebuilt archive's
[Task92 offline acceptance](TASK92_OFFLINE_ACCEPTANCE.json) is retained alongside
the historical Task91 acceptance and rejection records.

Find a canonical form in `FORMS.json`, then follow its indices into `BINDINGS.json`. Every binding has package-relative source, adapter, raw, checker, configuration and build paths. `CASES.json` lists the exact case records; `deltas/` explains adapter differences. Original review/context/failure records are under `records/ara*/`. Absolute paths in those original receipts are provenance; `PATHS.json` supplies their included-file translations.

The package contains 2,430 bindings and 1,785 distinct bound raw receipts, plus eight preliminary Ara89 failures and ten Task85 reproductions. These are separate units, not a test count. Task90's exact 26 added forms and unchanged non-Ara sets remain accepted. See [the Task90 correction](TASK90_CORRECTION.json): M2 target admission is **UNOBSERVED/null**. `RVV_FAST` counts `rvv_fast::g_fast`; this batch did not enable the distinct M2 `RVV_ACTIVE_CHUNKS` census. Functional B/M1/M2/BOTH predicates remain PASS.

Read `NOTICE.md`, `licenses/`, `LICENSE_AUDIT.json` and `LEGAL_RESTORATIONS.json` inside the archive. Ara SHL-0.51, Regents BSD dependencies, Marco Paland printf MIT notices and the repository MIT license are retained. Missing historical extraction headers were restored only in distributed copies, with the exact compiled payload and its original hash recoverable by removing the recorded legal prefix. Raw receipts are unchanged.

This supplies portable inspection. [Portable external replay](../portable-external.md) handles live replay. Historical build/configuration commands and tool/binary identities are included; compilers, LLVM, sysroots/newlib, Spike/pk, DUT executables/libraries, guest binaries/objects, compiler IR, caches, Git object stores, huge TB dumps, ATG/RVISmith and unrelated suites are excluded.

Repo sources: [offline checker](../../../scripts/verify_rvv_ara_bundle.py), [streaming packager](../../../scripts/package_rvv_ara_review.py), [xbd finalizer](../../../scripts/finalize_rvv_ara_review.py). No guest or new golden was created by this checkpoint. Launcher owns the completion signal; the 22:00 delivery deadline is unchanged.
