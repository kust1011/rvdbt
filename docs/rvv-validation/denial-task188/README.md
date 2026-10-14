# Task188 offline denial adjudication

Original final181 controls: **592 exact expected diagnostic faults, 0 generic failures, 0 insufficient observations, 0 unexpected successes**. These remain denial controls. **Architectural fault-state PASS: 0**. The positive595-form /12,071,304-check headline has **zero numerical correction**; this task does not re-audit or add positive credit.

| Original suite | Controls | Exact expected fault | Generic failure | Insufficient observation |
|---|---:|---:|---:|---:|
|guard165|48|48|0|0|
|guard166|64|64|0|0|
|faults|480|480|0|0|
|Total|592|592|0|0|

There are148 controls per B/M1/M2/BOTH arm,148 distinct ELF targets,536 loads and56 stores. All original streams have a complete structured snapshot and exit1. All raw origin labels are `PredictedHelper`. No native admission is inferred: frozen179 formats `NativeUnit` incorrectly with that same label (`dbt/ukernel.cpp:272`).

## Predicate and independent expectations

The auditor first authenticates original source summaries against the final181 FOCUSED_PLAN, original records against the frozen audit PLAN, source-tool hashes, source/ELF hashes,179 build/library manifest identity, retained original-command flags and final command target/fsroot, and original audit command/execution/packet/ELF receipt hashes. Original stdout is also joined to packets and the execution's stdout hash; stderr is joined to its execution hash. No new executable identity is given179 credit. This is a retained-evidence identity join, not a claim that a command receipt alone proves current engine bytes or native admission.

Expectations are built **before reading stdout/stderr**, from the original case/setup and ELF symbols/data. A small ELF32 reader locates `target_0`, `memory_0`, `initial_0`, and `packet_0`. An independent encoding formula checks the exact target raw instruction. The source setup/constants and ELF initialized bytes establish prestate; the memory initializer formula is checked independently. The end of the data segment must be page aligned and equal to the buffer end. Address formulas independently select denied accesses: unit/strided guard165, declared index patterns in guard166, and FOF element-zero/partial-segment setup in faults. The lowest denied element is determined by the setup; any denied field/address in that segment is allowed because fields are unordered. This does not assume field0 or serialize segmented access as an ISA rule.

One complete JSON snapshot, owned terminal exit1, and the exact terminal `helper_sync signal=11 code=1` are required. PC/raw/element/field/address, load versus store, unmapped diagnostic reason, EEW/NF/VLEN, all ten captured CSRs (including vstart, unchanged FOF VL and sticky FP flags), declared scalar setup registers, completed load prefix, untouched vector registers and undisturbed prestart/tail bytes are checked. All32 GPR/FPR/vector entries must have complete extents. Uninitialized FPR values are not invented as zero goldens. Active destination bytes at/after the fault position are excluded from exact byte equality where V permits partial segment or spurious updates; no observed output supplies their expected values. Stores must preserve all vector registers.

The controlling [RVV V1.0 specification](https://github.com/riscvarchive/riscv-v-spec/blob/3570f998903f00352552b670f1f7b7334f0a144a/v-spec.adoc) is revision3570f998903f00352552b670f1f7b7334f0a144a: §3.7 (vstart), §7.7 (FOF element0 leaves VL unchanged), §7.8 (segment units/partial fields), and §17.1 (precise trap state and permitted updates). Diagnostic `access/reason` and terminal signal/code are captured and checked; **mcause/scause is absent**, so architectural numeric trap cause remains UNVERIFIED. Host signal/code is checked as captured provenance, never substituted for mcause.

`EXACT_EXPECTED_FAULT` means the captured denial matches this target/setup and the observable checks. It never emits ISA PASS. A semantic or identity contradiction, wrong target or process crash yields `GENERIC_FAILURE`; that label does not by itself establish a DUT ISA defect. Missing/truncated structured observation yields `INSUFFICIENT_OBSERVATION` with named missing fields and `UNVERIFIED`. An unexpected zero exit is reported separately. Original181 statuses are retained verbatim beside the new adjudication and never rewritten.

## Observation limits and bounded handoff

All592 full architectural fault-state obligations remain UNVERIFIED: there is no full pre-fault scalar GPR/FPR baseline and no handler-return/same-PC resumed completion/forward-progress observation. For56 stores, fault-time memory is missing, so committed store prefix/footprint cannot be established. No mcause/scause or reliable native-origin identity is captured. These are missing observations, not assumed DUT failures. The original test's exit-only blocked-obligations statement is preserved in the retained source summary; the available snapshots now support stronger observable checks without claiming recovery.

No additional execution is needed to correct these592 denial labels. Session0 owns production: integrate its formatter fix and bounded formatter assertions under its own new build identity. If stronger terminal-state evidence is later needed and authorized, add an owned fault-time memory observer for a bounded scalar-width store and segmented-store fixture, plus explicit scalar prestate capture; require only affected checks. Architectural cause requires an observer that actually exposes that field. The service-blocked recovery task stays blocked and must not be retried or renamed. No full positive rerun or speculative Linux expansion is proposed.

## Retained inputs and reproduction

Read-only capture is at `/home/user/research/materials/task188-denial-offline-20261014`, mirrored by original absolute paths. Its `ORIGINAL_CAPTURE.tar.gz` is2.4MiB, SHA256 `a5d2fa5dd9b05fc855be92cdeb20b6bff9b81eef6edda6cbae88c53fcce644f5`. Original remote focused streams remain at `xbd:/home/vick/rvv-task181/focused`; originals remain in165/166/168 namespaces. This capture selects only negative DUT records, source/ELF/commands/manifests and setup tools; it does not run references or positive predicates. The original PLAN/summary files necessarily contain their original positive/reference metadata.

`INPUTS.json.gz` records logical original-path SHA256 identities. `RESULT.json.gz` contains592 individual adjudications and independently derived expectations; `SUMMARY.json` is the compact result. These are additive188 artifacts. The read-only capture script emits a tar stream and performs no remote writes:

```sh
ssh xbd python3 - < scripts/rvv/denial188/capture.py > /tmp/denial188-inputs.tar.gz
mkdir -p /tmp/denial188-mirror
tar -xzf /tmp/denial188-inputs.tar.gz -C /tmp/denial188-mirror
python3 scripts/rvv/denial188/audit.py --mirror /tmp/denial188-mirror --output /tmp/denial188-result
RVV_DENIAL188_MIRROR=/tmp/denial188-mirror python3 -m unittest discover -s scripts/rvv/denial188 -p 'test_*.py' -v
```

Validation:13 tests pass, including all592 original fixtures, wrong PC/raw/element/address/field/cause, CSR/register corruption, truncated and duplicate snapshots, missing fields, target ELF corruption, and a wrong-target process SIGSEGV with matching keywords. Semantic corruption tests update the in-memory capture hash, demonstrating semantic rejection beyond hash mismatch. A crash cannot borrow a valid snapshot to pass. Tests mutate only memory. No guest/fault/retry/reference execution, full positive re-audit, production edits or original receipt changes occurred.
