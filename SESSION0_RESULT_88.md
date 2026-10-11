# Task88 — portable external replay from a fresh xbd checkout

Completed after main acceptance of Task87. Production dbt unchanged; main's dirty author-guide addition and pre-existing untracked files are preserved. No push/email/quota reset/P4 retry, broad campaign rerun, new goldens or historical evidence deletion. Launcher owns completion signal `rvv-portable-20261012-88`.

## Delivered workflow and checkpoint

Existing scripts/rvv tooling now supplies pinned dependency acquisition, licensed fixtures, strict observation checks, independent same-ELF Spike reference, full four-arm commands, emitted-ELF verification and current admission audit. Commands: [portable-external.md](docs/rvv-validation/portable-external.md). Source/header adaptations and notices: [Ara](scripts/rvv/fixtures/ara-vredsum/README.md), [RVVTS](scripts/rvv/fixtures/rvvts-20261089/README.md). Source lock includes Ara34bd3bc152421b4601a7bf3d6e8e91ffb545c99e, RVVTSed9a96e74f9c8367ce42da5b6526b9727a18a293, Spike20feb9c2bf2a7deab964d8190b0cbd4b4131bec3 and PK9c61d29846d8521d9487a57739330f9682d5b542.

Local checkpoint8a5b1e2 included scoped Task87 integration files and portable fixtures; followups a151183/9ec0d12/3425955/7a332f1 added packet controls, ELF/admission audits and launcher/parser repairs. Task87's24MB compact-input remains intact; optional compacting deferred. Author guide was excluded from staging. No restricted ATG/RVISmith fixtures or toolchains copied.

Independent checkout: xbd `/home/vick/rvv-portable88-20261012/repo`. Fresh full build started at69ce3f8 using Clang/LLVM22, Release, RVV_HOST_CHUNK_BITS512, Ninja -j2. All production dbt tree bytes equal every later Task88 checkpoint; new checkpoint verification reports no build work needed. Replay used clean checkpoint3425955; final offline audit/host checks use7a332f1. No historical executable/object reused. [Fresh build provenance](docs/rvv-validation/portable-task88/small/fresh-build-provenance.json) retains exact commands, source tree IDs, submodules, host, compiler, dependency hashes and actual ldd resolution.

| New object | SHA256 |
|---|---|
| elfrun | 9bb171b61e1f8f75b1b2779fdf368fb9fa53613546659bc1403b6744ccb31d43 |
| libdbtjitshared.so | 79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af |
| Ara ELF | b9ddda2c803990b6abfb2fae62850a0d3549e6fe53f7b2e766b1bcfe2e1b5d09 |
| RVVTS ELF | 6e4c4db7f29c0120dad057f04d8e39364041c2cd3713d360b5a0d790eef93fff |

## Actual observations

Two unique same-new-ELF Spike reference calls and eight successful DUT calls; all exits0, timeout=false, original checker PASS. One additional M1 CLI rejection exited1 before entering Ara. replay2 includes two revalidated/reused successful Ara receipts from replay1; it executes eight remaining cells, not ten additional calls. Raw receipts and checker results: [small bundle](docs/rvv-validation/portable-task88/README.md).

| Fixture | Arms including reference | Per-receipt observations |
|---|---|---|
| Complete Ara vredsum.c, VLEN1024 | Spike, B, M1, M2, Both | 4546-byte stdout; original5functions/20assertions/200element comparisons; summary `[0,20,20,200]`; zero flags/scalar assertions |
| RVVTS seed20261089 complete16instructions, VLEN2048/e32/m1/VL64 | Spike, B, M1, M2, Both | 8768-byte packet; all32v8192bytes,32full64FPR,10CSR exact; unchanged original MachineState.compare(diff_full=True) |

RVVTS CSR values in every reference/DUT packet: vl64, vtype80, vlenb256, vstart0, vxrm0, vxsat0, vcsr0, fflags21, frm0, fcsr21. FPR input injection, before/after FPR equality and unwritten vector registers also pass original comparison. Original inputs/body reused unchanged; external-API derivative, not an upstream canned test. No generator or new expected-value production. [ELF verification](docs/rvv-validation/portable-task88/small/replay2/elf-verification.json) joins all16 original encodings, inline input bytes,32FLD/64FSD full64 and32whole-register loads/stores; no compressed wrapper instructions, page-aligned observer RAM.

Ara original functions, literal operands/masks/expected values and main INIT_CHECK/enable_vec/function order/EXIT_CHECK survive; only function boundary observers added. Exact source/header patches are bundled. C/printf compile rv32g O0 without vectorization, LLVM IR→llc --no-integrated-as→rv32gv assembly; `.option arch,+v` preserves original inline RVV while C checker/runtime remains scalar. ilp32d with matching RV32 libgcc retains64-bit checker calculations. Linux/PK startup provides extension state; privileged bare-metal mstatus access is omitted by the accepted non-SPIKE header branch. Runtime adapts stack/RAM/write/exit/reporting, not the oracle.

## Current admission

[Admission audit](docs/rvv-validation/portable-task88/small/replay2/admission.json) uses new diagnostics and emitted host bytes, not historical claims. M1 and Both each report scans454, runs_formed67, multi_member_runs2, members_admitted72, guard_fallbacks0. Target original ordinals1–3 are FORM0x125bc..0x125c8, TB0x125a0/frame0, members3/k4/count1; TBcount1. Separate frame1 has4members, k4/count1 and is not counted as resource batching.

Each target frame has two genuine width2 batches [0,1]/[2,3]:12 live-in component loads→6FP lane operations→6 live-out stores; all first-batch stores precede second-batch masks/loads. No helper calls inside either native batch. Complete commands expose SSA/member order, bounded batches1, split0, component-separable0, grouped-component-major0, dep-probe0 and all typed/active-bound flags. B/M2 disable vector-run; Ara M1/Both have runs_formed0 and multi_member_runs0.

Current source corroborates this: rv32_vrun.h:434 fixes host register budget30; RvvRunBatchWidth:822 balances capacity into two width2 batches. rv32_vrun.cpp:1324 checks QCG/SSA/member order, shared FP masks, separability/bracket/no scalar broadcast and excludes competing order/split modes. rv32_qir.cpp:12348 `batched&&!grouped` emits masks→loads→members→stores per chunk range. Source hashes are bound in admission.json. This evidence combines valid invariant guest state, dynamic frame/TB count and exact native code; it has no direct per-batch branch telemetry.

## Failures preserved and checks

Private xbd dependency attempts remain intact: bare GCC configure lacked crt0/libc; freestanding PK next lacked newlib headers; configure CFLAGS were not retained by make. Explicit private newlib include in make succeeds. Spike configure found Boost headers but lacked system/regex libraries; private downloaded/extracted packages and explicit library names succeed. No machine-global packages/settings changed. New private Python venv installs numpy/jsonpickle/mergedeep. Missing mergedeep failed before first guest-build output; successful retry retained. Dependencies were fetched/built on xbd, not copied toolchains.

replay1's M1 duplicate `--rvv-run-frame-census` rejected before guest. Runner now supplies it once; checks were not weakened. Offline admission parser initially crossed objdump continuation lines and miscounted2/12stores; original raw/code stayed intact. Full instruction width and horizontal-whitespace parsing fix this, with the same12load/6operation/6store conditions. Initial terminal traceback is diagnosed in attempt-diagnoses.json; final stdout/stderr and raw host bytes are bundled.

Six focused host tests pass on xbd: changed expected observations; nonzero exit; timeout; missing/truncated output; omitted main initialization; changed vector/FPR/CSR full packets. Packet tests use the actual new Spike receipt and original comparator. These are tool checks, not ISA counts. Six Task87 integration tests still pass. Pinned Ara fetch/header hashes passed; copied266 raw/log artifacts and lossless gzip source/bundle hashes verify; all five Ara raw receipts independently recheck locally. Local system Python missing jsonpickle caused an attempted offline packet test import failure; the required six tests passed in the prepared xbd venv, without new guest executions.

## Scope and handoff

Raw/provenance bundle is about2.4MB. New source/build/bulky scratch stays on xbd; only small artifacts returned. Original source licenses, MIT printf notices and BSD3 original MachineState source are preserved. Full historical595-form evidence remains historical, with its original identities; this replay makes no595-form reproduction claim. Denominator627/595/32, Ara396 and other suite sets remain unchanged.

Inherited Ara source-object overreads remain: loading VL bytes from shorter masks/seed objects does not prove C bounds safety or access suppression. RVVTS excludes complete GPR/PC/mstatus/final-memory observation and per-instruction intermediate flags; v26 is later masked-overwritten, so final v26 is not an independent oracle for ordinal3's intermediate full component. General cross-frame pressure cuts, arbitrary geometry, precise fault/retry and Linux signal handling remain outside these results. No performance or whole-suite/conformance claim.

Next: main review of portable replay and remaining source dispositions/delivery acceptance, then EN/ZH/PDF/repo/email gates. No further guest batch started. Original deadline22:00 unchanged; Task88 is one checkpoint, not completion of the overall delivery plan.
