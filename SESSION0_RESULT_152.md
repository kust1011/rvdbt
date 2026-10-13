# Task152 — integer comparisons and next multiply-accumulate family

Worker result complete; twenty comparison forms are ready for main acceptance. No claim of complete RVV semantic coverage.

Task151 scoped work committed locally as `3d3bb66`, excluding pycache; no Task151 guests rerun. Existing branch `test/rvv-directed-forms-20261013`; production DUT remains fixed e2559c5c host512. Main owns shared thesis state and session3 owns fixed-point in its separate worktree/raw namespace; neither was changed.

Comparison family `compare152` routes prepared `compare151_next.py` through the established runner/auditor. Finite denominator: 20 forms, 126,852 cases in 5,280 units; 121,652 ordinary cases and 5,200 reserved-start profile cases per arm. Twenty nonlowest mask-destination overlap encoding declarations remain NOT_RUN and earn no PASS.

Independent fixed Spike/pk zero-start and Sail0.14.1 nonzero-start pilot completed 2,988 cases / 14,940 checks / 600 commands, all stages zero. Each arm has 2,948 ordinary PASS and 40 PROFILE_RESERVED_START outcomes. The pilot run stage took 70.2486 seconds. 120/120 actual-packet controls rejected; supplemental 136/136 state/signedness controls and 20/20 inactive overlap controls rejected; 40/40 allowed tail/overlap variants accepted. All supplemental work uses retained pilot packets and no guest reruns. See [pilot evidence](docs/rvv-validation/directed-task152/pilot-evidence/), [semantic review](docs/rvv-validation/directed-task152/SEMANTIC_REVIEW.md), and [commands](docs/rvv-validation/directed-task152/COMMANDS.json).

The separately frozen full snapshot completed **126,852/126,852 cases, 634,260/634,260 checks and 26,400/26,400 commands**. Build/run/audit/controls/summary all returned zero. The complete audit replay verified all packets, 5,280 source/opcode units and 2,640 Sail adapters; there are no missing results, timeouts, reference blockers or unresolved DUT failures. Full actual-packet controls rejected 120/120 mutations. Each of Reference/B/M1/M2/BOTH has **121,652 ordinary PASS** and **5,200 PROFILE_RESERVED_START** outcomes. Twenty reserved encoding declarations stay NOT_RUN. The full run stage took 1,945.0493 seconds. Full build/run/audit/control/summary stages ran 08:48:11–09:37:21 UTC (49m10s). This is finite semantic evidence; per-target M1/M2 path admission is not claimed, and the auditor remains single-process.

All five arms have identical per-form counts below; FAIL and blocked are zero for every row.

| Form | Cases per arm | Ordinary PASS | Reserved-start profile |
|---|---:|---:|---:|
| vmseq.vv | 5,049 | 4,789 | 260 |
| vmseq.vx | 5,313 | 5,053 | 260 |
| vmseq.vi | 9,009 | 8,749 | 260 |
| vmsne.vv | 5,049 | 4,789 | 260 |
| vmsne.vx | 5,313 | 5,053 | 260 |
| vmsne.vi | 9,009 | 8,749 | 260 |
| vmsltu.vv | 5,049 | 4,789 | 260 |
| vmsltu.vx | 5,313 | 5,053 | 260 |
| vmslt.vv | 5,049 | 4,789 | 260 |
| vmslt.vx | 5,313 | 5,053 | 260 |
| vmsleu.vv | 5,049 | 4,789 | 260 |
| vmsleu.vx | 5,313 | 5,053 | 260 |
| vmsleu.vi | 9,009 | 8,749 | 260 |
| vmsle.vv | 5,049 | 4,789 | 260 |
| vmsle.vx | 5,313 | 5,053 | 260 |
| vmsle.vi | 9,009 | 8,749 | 260 |
| vmsgtu.vx | 5,313 | 5,053 | 260 |
| vmsgtu.vi | 9,009 | 8,749 | 260 |
| vmsgt.vx | 5,313 | 5,053 | 260 |
| vmsgt.vi | 9,009 | 8,749 | 260 |

DUT and reference identities match before/after; scoped runner/checker sources match the frozen full snapshot. All 32 vector registers, ten CSRs and scalar s0 receive pre/post predicates, with allowed sets for agnostic mask bits. No DUT-derived goldens. See [full evidence](docs/rvv-validation/directed-task152/full-evidence/), [stage status](docs/rvv-validation/directed-task152/FULL_STAGE_STATUS.json), [final evidence validation](docs/rvv-validation/directed-task152/FINAL_VALIDATION.json), and [build profile](docs/rvv-validation/directed-task152/BUILD_PROFILE.json).

Raw/source/compressed ELF records remain at `xbd:/home/vick/rvv-directed-task152/{pilot,full}`; compact evidence was copied without archive packaging or exhaustive retained-cache decompression. Build4/run8, nice10, no taskset; the shared 10GiB reserve remained enabled. Final load1.21/1.91/5.04, available memory40,376,119,296B, free disk17,445,076,992B (16.25GiB); monitored free disk never fell below that final value. See [timing/resources](docs/rvv-validation/directed-task152/TIMING_RESOURCES.json). No accepted guest or unchanged framework-control reruns, production changes, pushes, Linux/LLVM/performance expansion, session3 file/raw changes or shared thesis-state updates.

Next family prepared while current batch runs: vmacc/vnmsac/vmadd/vnmsub, each vv/vx, eight forms and 40,232 cases / 2,112 units. 38,152 ordinary and 2,080 reserved-start declarations; sixteen reserved encoding declarations NOT_RUN. Captured old destination supplies accumulator or multiplicand as appropriate; modular low-half arithmetic, RV32 sign extension, legal destructive overlap, preservation and policy predicates are source reviewed. Local checks: 296 checks, 72 distinct target encodings compiled and matched, all 40,232 layouts validated, 132 geometry prestate extents checked. 64-unit independent-reference pilot selector and actual-packet corruption utility ready. No next-family guests or PASS credit. See [next family](docs/rvv-validation/directed-task152/next-mac/README.md).

A local next-family preparation utility initially treated the shared ELF reader's section tuple as a dict; the TypeError and correction are preserved in next-mac/PREPARATION_FAILURES.json. No guest failure or oracle adjustment. An unchanged comparison preparation layout repeat was stopped; Task151 retains its complete extent/encoding evidence, and all seven targeted new-family checks passed.

Next action: route the prepared multiply-accumulate family through the shared runner/auditor, then admit its 64-unit independent fixed-reference pilot before full execution. Main owns acceptance, shared-state updates and merging both worker branches.

Completion signals: `rvv-directed-compare-20261013-152` and `rvv-review-parallel-20261013`.
