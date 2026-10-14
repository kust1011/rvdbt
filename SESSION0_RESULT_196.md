# Task196 — bounded allocator-cost comparison

From `c91c195`, **40/40 timed guest calls pass the original predicates**.
This sample does not establish zero cost or general performance acceptance.
Wall differences are small/variable and inconclusive; large-region translation
medians differ by about +0.6–0.9%. The measured allocator phase is lower in all
pairs (small paired ratios 0.629–0.768; large 0.903–0.996), an observation within
this sample, not a general speedup claim. Main reviews acceptability.

Two unchanged existing packed ELFs, each in B/BOTH: four cells total.
`integer-w1024-e32-m1-alias-zero` has three dependent arithmetic operations,
VLEN1024/e32/m1 and seven original packets; `long192-int-w4096-e8-m8` has
65 operations crossing the 64-instruction TB boundary, VLEN4096/e8/m8 and
four original packets. These are two guest workloads, not eleven independently
selected/rebuilt guests. The large integer guest already passed retained191
(Task192 baseline) and fixed192 (Task195). Small reuses Task191's accepted
sequence ELF/reference and checker. Short versus long is defined by existing
sequence/geometry evidence; no new QIR-size census was performed. Large B/BOTH
remain singleton routes in retained evidence; BOTH flags do not imply multi-run
execution. The crashing191 `long192-fp-w4096-e32-m4` is excluded entirely.

Five pairs per cell, order 191/192, 192/191, 191/192, 192/191, 191/192;
one child at a time, taskset CPU2, nice10, stdin DEVNULL, fresh private FS/cache
per call. CPU2's SMT sibling18 was checked: both showed 0% utilization over the
one-second admission sample. Admission requires each sibling below10% busy;
script stops if unavailable, with no retry. Affinity applies only to our child;
no other process or machine-wide setting changed. Shared host contention remains
possible: this is an observation, not an exclusive CPU reservation. Before/after
load was 0.088/0.209/0.559 and 1.023/0.406/0.614, respectively; complete
process observations are retained.
Disk reserve >=10GiB checked before every call; endpoint free space
18,717,048,832 / 18,702,585,856 bytes. These are endpoint/admission observations.

All values below are medians, retained191 / fixed192. Wall ratio is the median
of the five paired ratios, with their full range. RSS is Linux wait4 maximum
resident set size of each taskset/exec child, in KiB. Wall uses parent
perf_counter_ns from Popen start through wait4 return, including process startup,
loading, translation, execution and small stdout/stderr writes; it is **not
translation time**. Every trial is in [TRIALS.csv](docs/rvv-validation/cost-task196/TRIALS.csv).

| Cell | Wall ms 191 / 192 | Paired wall ratio (range) | Translation ms 191 / 192 | QRA ms 191 / 192 | Max RSS KiB 191 / 192 |
|---|---:|---:|---:|---:|---:|
| small/B | 36.443 / 35.382 | 0.971 (0.732–1.004) | 1.110 / 1.036 | 0.353 / 0.268 | 177252 / 176912 |
| small/BOTH | 34.898 / 34.293 | 0.984 (0.962–1.020) | 1.230 / 1.145 | 0.346 / 0.261 | 177164 / 176900 |
| large/B | 44.873 / 45.709 | 1.016 (0.990–1.092) | 7.772 / 7.821 | 0.811 / 0.769 | 181220 / 180872 |
| large/BOTH | 45.867 / 44.899 | 0.969 (0.965–0.999) | 7.759 / 7.826 | 0.882 / 0.826 | 181188 / 180964 |

Existing timing is verified in both retained source trees, byte-identical in
`dbt/execute.cpp:375`, `dbt/qmc/qcg/qcg.cpp:34` and `dbt/elfrun.cpp:1977`.
`CLOCK_MONOTONIC` brackets each `CompilerDoJob` on a JIT miss, before installation
and guest execution; emitted TRANSLATE_NS is the sum, not whole-process wall.
QSEL brackets QSelPass; QRA starts after QSel's sample and includes the intervening
QIR printer call plus QRegAllocPass; EMIT includes the next printer call and
emission/encoding, ending before DumpCode. Logging sinks are disabled by existing
flags/defaults. Phase samples are nested within translation, not additive to it.
Both receive `--measure-translation=1`; it also adds phase clock reads.
35 translation calls for every small trial,26 for every large trial, INTERP_BLOCKS0.
No instrumentation project or timer rebuild was needed.

Exact command changes from retained manifests, identical for both binaries:
remove dump-tbcode/dump-tbmap and PC/route/active-chunk/frame census options;
relocate private fsroot/cache and executable/library path; add the existing
translation timer. Preserve all other flags, including original hit counters,
RVV stats, trace0 and pure QCG aot0/aot-use-llvm0. No large trace logging in timed
runs. Each call checks unchanged `sequences177.check_isa` and `check_reference`
for every packet: 220/220 checks, exit0, no reference executions. Full raw
commands, stdout/stderr, timing totals, packet hashes and results are retained.

Build comparability: both Release Clang22, O3/NDEBUG, host chunk512,
FROUND_IMPL2 and AVX512F/BW. All290 compile commands match after isolated-root
relocation; allocator compiler flags and elfrun link commands match. ldd resolves
the same system libraries after ASLR/root normalization, with each build's
explicit LD_LIBRARY_PATH. Shared `libdbtjitshared.so` and `libasmjit.a` hashes
match; static DBT libraries differ as expected. Retained executable SHA256
`37a25624345214d97e3691cfd9f951166abfe92419ce2bbeca9c786b68227c14`,
fixed executable `908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4`;
identities checked before/after. The298-file retained source check differs only
in production qra.cpp and the three known192/195 test files. Compact complete
identities are in [COMPARABILITY.json](docs/rvv-validation/cost-task196/COMPARABILITY.json).
No additional changed-code-size result is reported; no census campaign.

Reproduce on xbd using the existing paths with a new empty output destination:
`nice -n 10 python3 paired196.py /home/vick/rvv-cost-task196-repeat`.
The [script](docs/rvv-validation/cost-task196/paired196.py) is committed;
[selection](docs/rvv-validation/cost-task196/SELECTION.json) pins ELF/reference
hashes and resource observations. Reproduction is documented, not executed.
Exact limit: two existing ELF bundles × two arms × five pairs × two builds =40
calls, no warmups, retries, discarded trials, new guest generation, reference
reruns, full matrix, compilations or code edits. No recovery/P4-04 equivalents,
Linux/LLVM expansion or push. No extra executions to improve noisy results.

Raw outside git: local
`/home/user/research/materials/task196-cost-raw-20261014/raw-receipts.tar.gz`,
remote `/home/vick/rvv-cost-task196-raw.tar.gz`; 3,207,529 bytes,
SHA256 `82a75dc05034798e779efad16dfd506a79053e61469e4da49fc11a4bbe17d7f0`.
All266 archive files were traversed and hashes compared to extracted bytes.
Controller log and summarizer are also outside git. [Retention receipt](docs/rvv-validation/cost-task196/RETENTION.json)
contains archive and script identities. Completion signal: `rvv-cost196`.
