# Task195 — bounded integration of reviewed shared allocator fix

**PASS within the requested ordinary QCG scope**, from `02f54af` on
`rvv/compliance192`. Read the production/test diff, original rc−6 allocator
panic, complete allocator fixture output, Task192 report and Session3's
`REVIEW194_FINDINGS.md` (review commit `49d9d3e`). The independent review accepts
region-sized storage and stable pointer lifetime for ordinary QCG; it does not
accept arbitrary multiple-range/inlining/LLVM jobs or recommend type expansion.
No production edit or allocator redesign was made here.

The production executable remains Task192 SHA256
`908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4`;
shared library remains
`79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af`.
Static library and previously executed allocator fixture identities are also
unchanged before/after. Source comparison checks all298 retained files:
only the two test repairs described below differ from the initial Task192 tree.
All guest calls use this unchanged production executable and library.

Before compiling, checked availability in xbd's isolated
`/home/vick/rvv-long-task192/build/bin`: only `elfrun` and the already-run
`qra_vpr_test` existed. Built exactly ten missing selected targets with `-j2`.
Three later builds rebuild only the failing test being repaired. No production
rebuild, guest ELF rebuild, reference execution or allocator-fixture repeat.

| Existing fixture | Final result | Evidence scope |
|---|---|---|
| `rvv_rvv_contract_test` | PASS, zero failures | Semantic/geometry assertions |
| `rvv_vector_run_codegen_test` | ALL CHECKS PASSED | Real QSel/RA/emission and code inspection; expected child panics |
| `vchunk_dataflow_test` | PASS, zero skipped | Static dataflow plus actual native E1/E2/E3, all SEWs |
| `vstatechunkload_test` | PASS | Actual native AVX512 window loads, dirty-global and two-window round trips |
| `rvv_ssa_edge_commit_test` | PASS, zero failures | QIR state/edge assertions |
| `rvv_active_vl_widen_bound_test` | PASS | Generated-code/shape contract |
| `rvv_active_vl_narrow_bound_test` | PASS | Generated-code/shape contract |
| `rvv_fp_shared_mask_test` | PASSED | QIR/emitted-mask contract and rejection controls |
| `rvv_active_mask_memory_test` | 227,948 checks, zero failures | Native memory/value execution and finite terminal boundary |
| `rvv_run_live_range_split_test` | PASS, zero failures | Structure/dataflow/emission contract |

Assertion counters are fixture counters, not unique ISA cases or a coverage
inventory. Source/QIR/codegen assertions and force-emit flags receive no native
execution credit. The memory fixture's existing finite SIGSEGV child exits after
checking vstart; it performs no repair, return, retry or blocked recovery.

Two existing fixtures had stale expectations. `vchunk_dataflow_test`'s D2/E2
filler loads had no consumers: existing last-use retirement releases them at
definition, so they create no sustained pressure. The first run returned1 with
three spill assertions failing, while all lane values passed. The repair retains
all fillers until stores after the tested add; native independent byte checks
also verify that every filler is unchanged. Corrected execution reports both add
inputs through frame slots, six spills/six fills, correct native results, no skips.

`rvv_fp_shared_mask_test` initially returned1 with16 assertions failing. Existing
FMA zero/infinity-product classification adds five `kmovw` reads per chunk,
including a read of a resident active mask. Its old counter omitted those reads,
and `ScratchUses` mistook `kmovw eax,k2` for a scratch write. Updated only these
expectations and the read recognizer; existing comparisons, active-mask producer
counts, resident-mask uses and rejection controls remain enforced. My added
checker self-test initially expected a permitted mask producer to count as a
scratch write; that corrected-fixture attempt returned1 with one failure. Fixed
that self-test expectation before the final pass. All three failed fixture
attempts, their binary identities, commands and hash receipts and raw outputs remain
retained with zero acceptance credit. Successful fixtures were never repeated.

The bounded external selection reuses original external guests in **B/M1/M2/BOTH**,
one execution per cell, without modifying ELF, answer, source or checker:

| Suite | Selected cases | Geometry | Accepted calls |
|---|---|---|---:|
| ACT | `Vx32-vwadd.vv-00`, `Vx32-vnsrl.wv-00`, `Vx32-vmand.mm-00`, `Vls32-vle32.v`, `Vls32-vse32.v` | Original VLEN1024, XLEN32/ELEN64 | 20/20 |
| CHIPS | `vwadd_vv-0`, `vnsrl_wv-0`, `vmand_mm-0`, `vle32_v-0`, `vse32_v-0` | Original geometry4096, narrowfixed128, mask1024, long4096 | 20/20 |

ACT uses the unchanged extracted original signature-summary predicate, frozen
embedded answer/signature and checker hashes; CHIPS uses unchanged `classify`
with original expected returncode and exact `CHIPS_PASS` stdout. Original oracle
and manifest provenance is retained. Relocated FS/cache and diagnostic
TB map/code, PC census and statistics are the only command additions.
No new full-state observability is claimed for these external checkers.

Actual `RVV_DIRECT` counters report nonzero whole-guest inline executions in
all40 cells. PC censuses report overflow0 and preserve helper families/counts;
TB maps/code and dynamic frame counters are retained. ACT M1/BOTH frame entries
are3 each for the two memory cases and mask case,285 for narrowing and318 for
widening. ACT B/M2 and every selected CHIPS cell have zero multi-frame entries.
These are whole-file observations, including setup operations; they are not
per-target native/multi-run proof. In particular, mask-case setup can execute
native routes without making `vmand.mm` a native multi-run. Flags receive no
execution credit. Compact route receipts retain exact inline/fallback and
helper-family counts per suite/case/arm.

Replayed **only four previously accepted baseline-int cases** from
`long192-int-w4096-e8-m8`: VL0,65,513,4095. Four DUT commands in the original arms
supply16 packet checks using the unchanged ELF and original pinned Spike packets;
no guest build/reference rerun. Existing full-state sequential predicates and
independent PC/code audit pass:1,040 target-PC/arm rows are singleton native.
These flags are not relabelled as multi-run execution.

The offline join now establishes **54 long192 cases / 216 DUT packet checks on
fixed192**, using200 unchanged earlier checks plus16 new checks. The earlier16
accepted191 baseline checks remain historical changed-build evidence; they are
not counted twice. Task192's original16 failed191 checks/four rc−6 commands
remain failures. Same-build routes are unchanged in aggregate: B/M2 each3,510
singleton rows; M1/BOTH each2,990 singleton,390 native multi-member and130 ordered
fallback rows. This supplies a finite common-production-build result for long192,
not new595 acceptance or exhaustive mixed-sequence/ISA conformance.

Task195's exact new execution denominator is **54 accepted commands**:10 fixture
passes,40 external calls,4 baseline DUT calls. There are **57 execution attempts**
including the three failed fixtures, plus four build commands. Independent
reference packets reused for the new baseline replay are four; the complete
long192 denominator remains54 references. The offline audit reads/hashes the
previous200 successful fixed192 receipts without rerunning them. No successful
191/192 command was repeated beyond the explicit changed-build regressions.

All builds use<=2 compiler workers, tests execute sequentially (existing terminal
children included), nice10 and inherited affinity. Endpoint checks enforce a
10GiB reserve; minimum recorded build/test free space is20,944,674,816 bytes.
These records are endpoint checks, not continuous machine-wide monitoring.
Raw is outside git; compact identities, selections, receipts, provenance,
retention and the offline audit are under
`docs/rvv-validation/integration-task195/`. Archive transfer identity and complete
member traversal and541 indexed file hashes are checked locally. The57,902,033-byte
archive is `/home/user/research/materials/task195-integration-raw-20261014/raw-receipts.tar.gz`,
SHA256 `14c3a9a9cda1f632bbd7aca06ad3c07a14521bd11983d56f75a08460af3938cb`;
`RETENTION.json` records both endpoints and814 traversed archive members.
One offline-audit attempt assumed an uncompressed ELF path, corrected to the
established lossless-storage reader; no guest repeat. Initial archive packaging
encountered the replay tool's unused broken `sail.ld`/`user.ld` reuse symlinks; omissions
are explicit, and no existing execution bytes are dropped. Packaging receipts
and controller logs remain outside git with raw.

Bounded work stops here. P4-04/187-01 remains service-blocked,
**NOT EXECUTED / NOT VERIFIED**. No recovery alternative, performance matrix,
Linux/LLVM expansion, full595 replay, push or email occurred. Local commit owns
this report, compact evidence and the two test-only repairs. Error signals were
sent on fixture failures; completion signals are `rvv-compliance195` and
`rvv-review-parallel-20261013`.
