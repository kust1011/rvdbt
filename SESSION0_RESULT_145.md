# Task145 — implemented and executed project vadd form tests

Local branch **test/rvv-directed-forms-20261013**, based on exact55630c8.
Task144 scalar/Linux expansion is cancelled; only RVV tests/evidence changed.
Unrelated `scripts/__pycache__/` is preserved. No production changes or publication.

Implemented reusable parameterized **vadd.vv/vx/vi** generator, raw-state checker,
complete offline audit and rejection controls under `scripts/rvv/directed/`.
[Delivery and rerun instructions](docs/rvv-validation/directed-task145/README.md)
link the finite manifest, actual observations, build commands, raw paths, pins,
source review, Sail adapter verification and coverage gaps.

**Planned/executed:9,393/9,393 cases**, each on independent reference plus current
host512 B/M1/M2/Both: **46,965/46,965 PASS checks**, **3,960/3,960 commands**,
**106.85s**, four bounded workers after checking load. Per form:vv2,955;
vx3,219; vi3,219. Each DUT arm passes9,393. No missing/blocked/unresolved DUT
failures. Full offline reapplication checks every packet and target opcode;
396 Sail-adapted batches have verified shared bodies/data/target encodings.
**21/21 actual-packet corruption controls rejected;12/12 synthetic checks passed.**
Separate original/hardened pilots each350 checks earn no formal case credit.
Compilation/development wall time was not separately instrumented.

Oracle:fixed Spike20feb9c2+RV32 pk for7,893 cases with the same ELF as DUT;
existing fixed Sail0.14.1/e4b243f for1,500 initialized nonzero-vstart cases,
using per-invocation supported configuration and verified entry/exit-only
adaptation. Source-reviewed RVV1.0 predicates constrain every packet and accept
only permitted old/all-ones agnostic elements. No DUT-derived expected values.
Actual target post-CSRs are captured before any vector dump; all32v,10CSRs and
scalar source are checked. Arithmetic overflow, RV32 vx sign extension, simm5
boundaries, legal overlap, policies/masks, fractional/integer geometry and
length/chunk boundaries are included across six guest VLENs128–4096.

DUT exact **e2559c5cd930e919503c79b44af219c243041e86f5b83a157bec860814e8336b**:
**xbd:/home/vick/rvdbt-host512-task142-build/build/bin/elfrun**.
Formal remote raw:**xbd:/home/vick/rvv-directed-task145/corpus/**.
Local raw:**/home/user/research/materials/task145-directed-raw-20261013/**.
Archive:**xbd:/home/vick/task145-directed-final-raw.tar.gz**;
[authenticated transport](docs/rvv-validation/directed-task145/TRANSPORT.json).
Prelaunch compiler/transfer/exit-adapter failures are documented separately;
one initial transfer-error stderr is preserved from the tool transcript after
its probe pathname was reused. Formal raw and all failure controls remain intact.

No per-target M1/M2 admission claim. Remaining finite gaps include other host
widths/RV64, illegal encodings, vstart>=VL and vstart with zero/partial VL,
exhaustive interaction products and multi-instruction admission/live-out cases.
This completes the three-form template task, not the overall595-form program.
No external full rerun, production patch, Linux/scalar/atomic/LLVM expansion,
P4-04, handler return, mapping repair or same-PC retry. Launcher sends completion.
