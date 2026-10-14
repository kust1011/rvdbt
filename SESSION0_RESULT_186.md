# Task186 — RVV memory exception-state audit and focused acceptance

Completed from `d1ec81f1a80a4dc33f29c12124e6dc02689d3934` in
`/home/user/research/materials/rvdbt-rvv-exception-20261014`.
Read thesis AGENTS/current execution entry/active plan without changing thesis.
No subagent was launched; Session3's independent audit remains separate.
Frozen179, delivery and W3 were not modified.

No confirmed production defect was found in the reviewed current QCG/interpreter
memory exception paths. No production edits were made and there is no original
failing production witness to claim fixed. This is not complete RVV conformance.
The actual source already handles absolute-zero FOF trapping, live vstart suffix
execution, whole-register encoded-EEW progress, ordered field/element commitment,
and singleton native cold exits. Old comments claiming terminal-only faults or
no nonzero vstart generation are stale and were not treated as source behavior.

The concrete [clause → source → test table](docs/rvv-validation/exception-task186/CLAUSE_SOURCE_TEST.md)
uses the already pinned official RVV1.0 source, revision
`3570f998903f00352552b670f1f7b7334f0a144a`, SHA256
`bfe42bd33dc6abeef5362f475605dda3d229e722257a613b0691cee760f04a19`.
It records implementation discretion for faulting segment subsets, FOF active
updates after trim, optional early shortening, permitted vstart rejection and
whole-register alignment. Source review includes native_fault, memory emissions,
translator publication/scanner boundaries, interpreter/helpers/host-copy,
allocator call boundaries, MMU admission, dispatcher, signal restore source and
existing unit/family/special/native/grouped/whole/bulk fault fixtures.

The only code change adds `fof_clause_cases` to the existing unit fixture.
Its 120 fresh-state cases cover VLEN128/1024, EEW8/16/32/64, NF1/2/3, M2:
24 absolute-zero terminal traps with original VL/exact field, 72 nontrapping
trims (first executed element1, masked element0, and two completed segments),
and 24 start=VL empty suffixes. The new oracle checks committed prefix and
mandatory undisturbed registers while allowing the specification's discretionary
faulting/later-active writes. No existing accepted assertion or oracle changed.
No terminal state is repaired and executed again.

Fresh isolated source/build: `xbd:/home/vick/rvdbt-exception-task186`.
Source identity verified for303 files plus442 dependency files copied from the
retained179 source into this new directory. Configure, fresh build and final
build all exit0. Actual Release Clang22.1.6 compile flags include
`-DRVV_HOST_CHUNK_BITS=512 -mavx512f -mavx512bw -ffp-contract=off`;
XLEN32 (`gpr_t=u32`) and ELEN64 (`ELEN_BITS=64`) are verified source constants,
not invented CMake switches. Native fixtures require actual AVX512F/BMI2, without
forced admission. [Manifest](docs/rvv-validation/exception-task186/MANIFEST.json)
contains compiler/CPU/flags/binary hashes; cache and source/dependency hashes are
retained beside it. No old frozen executable receipt is inherited by this build.
Build warnings are retained in `build.log.gz`; successful builds gated execution.

All10 accepted invocations exit0:

| Invocation | Reported checks | Fixture cells / terminal cells |
|---|---:|---:|
| unit memory | 10,042 | 1,368 cells, including120 new FOF |
| family memory | 323,407 | 59,424 cells |
| special memory | 254,648 | 26,290 cells |
| native unit fault | 6,142 | 40 cells |
| whole native fault | 6,185 | 24 terminal cells |
| whole `--normal-only` | 13,330 | 0 terminal cells |
| scalar vector-memory native fault | 2,029 | 44 terminal cells |
| grouped `--terminal` | 103 | 10 terminal cells |
| grouped `--normal-only` | 585 | 0 terminal cells |
| permitted bulk fault | 2,944 | 268 cells |

The reported counters sum to619,415; this is not a count of unique ISA cases or
all dynamic assertions (fork-child counter increments do not return to parent).
Normal/terminal cells have each fixture's existing meaning. Original acceptance
predicates were unchanged. Native/generated-byte/site/snapshot raw outputs are
retained in [raw-nice10.tar.gz](docs/rvv-validation/exception-task186/raw-nice10.tar.gz),
with per-invocation command/exit/hash/resource receipts in
`RESULTS-nice10.json.gz` and a readable [summary](docs/rvv-validation/exception-task186/RESULT_SUMMARY.json).

Resource correction: the first all-PASS pass accidentally nested two relative
nice adjustments and ran at nice19. It is retained separately in `raw.tar.gz`,
`RESULTS.json.gz`, `runner.log`, and `run_focused.attempt1.py`, excluded from
acceptance totals. The corrected runner asserts nice10 and children inherit it;
all10 focused invocations were rerun once and passed at nice10. No ISA/build
failure was discarded or relabelled. Own compilation is explicitly `-j2`,
execution sequential (one executing guest/fixture at once), offline work one
process, with no affinity/global changes. Accepted run endpoint free-space
minimum20.818GiB exceeds the10GiB reserve. These are endpoint process/load/disk
receipts, not continuous machine-wide concurrency measurements.

Production cost delta is exactly zero: no new translation metadata, emitted
normal instructions or cold-recovery work. Existing memory frames still pay
call/spill/admission/guard and publication costs; scalar vector-memory loops
already publish vstart per active element. Exact-site registration costs
translation/publication time; metadata search/TLS capture/event queue/FP closure/
unwind/snapshot copying occur on cold faults. No unconditional scalarization or
per-arithmetic-instruction checkpoint was introduced. No performance matrix,
LLVM expansion or general Linux scalar/atomic change was performed.

Remaining required obligations: guest-handler return, mapping repair followed by
same-PC retry or equivalent execution, and eventual forward progress of that
resumed instruction remain service-blocked and **NOT EXECUTED / NOT VERIFIED**.
No host harness bypass was used. Exit frontier plus independently initialized
normal/vstart execution does not discharge restart. Interrupt/debug-watchpoint
conditional behavior was reviewed but not injected. This bounded memory audit
and final181's finite595-form matrix do not establish complete exception-state
compliance or all-configuration correctness. Production remains unchanged, so
no full595 replay or external/performance matrix was opened.

Owned files are committed locally. Launcher completion signals are
`rvv-exception-186` and `rvv-review-parallel-20261013`.
