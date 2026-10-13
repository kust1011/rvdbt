# Project directed vadd template — Task145

Implemented and executed **vadd.vv, vadd.vx and vadd.vi**. This is a project test
layer alongside the existing external suites. Production and external goldens
are unchanged. [Source/predicate review](REVIEW.md) explains source references,
agnostic permitted sets, state capture and the entry/exit-only Sail adapter.

| Form | Planned cases | Reference checks | B | M1 | M2 | Both |
|---|---:|---:|---:|---:|---:|---:|
| vadd.vv | 2,955 | 2,955 | 2,955 | 2,955 | 2,955 | 2,955 |
| vadd.vx | 3,219 | 3,219 | 3,219 | 3,219 | 3,219 | 3,219 |
| vadd.vi | 3,219 | 3,219 | 3,219 | 3,219 | 3,219 | 3,219 |
| Total | **9,393** | **9,393** | **9,393** | **9,393** | **9,393** | **9,393** |

All **46,965/46,965** checks PASS; zero missing/blocked/unresolved DUT failures.
Finite manifest precedes execution:22 SEW/LMUL pairs ×6 VLENs ×3 forms,
with finite per-geometry basic and interaction cases. 792 ELF batches ×5 engine
arms = **3,960 actual commands**, not46,965 process launches. The actual run took
**106.8503s** with4 workers, cores28–31, nice10; sum of command elapsed times384.225s.
Compilation/development wall time was not separately instrumented. Pilot70 cases
×5=350 checks (2.9032s) and the post-hardening pilot350 checks (2.8550s) are
separate, excluded from formal counts. No CHIPS/ACT/Ara full rerun occurred.

Reference:7,893 zero-vstart cases use fixed Spike20feb9c2 with pinned RV32 pk,
**the identical ELF as all DUT arms**. 1,500 nonzero-vstart cases use the existing
fixed Sail0.14.1/e4b243f binary and verified entry/exit adapter. Every reference
packet also satisfies independently sourced ISA predicates; every DUT active
lane agrees with that reference. [Identities](IDENTITIES.json) pins executable,
shared library and both reference engines. DUT is Task142 host512 **e2559c5c…**.
Flags use existing `scripts/rvv/fixtures/external-flags.json`; enabled methods or
aggregate statistics earn **no per-target admission claim**.

The case manifest is [MANIFEST.json.gz](MANIFEST.json.gz). Each entry includes
form, SEW, LMUL/EMUL, VLEN, requested/expected VL, mask, policy, vstart, layout,
operand, seed and ordinal. Full initialized data is reproducible from `initial`.
[Observed checks](OBSERVED_CHECKS.csv.gz) gives actual pre/post10-CSRs+s0, actual
32-register state hashes, exact raw offsets and oracle per case/arm. Its CSR order
is `vl,vtype,vlenb,vstart,vxrm,vxsat,vcsr,fflags,frm,fcsr,s0`.
[Build commands](BUILD_COMMANDS.json.gz), [guest pins](GUEST_PINS.json.gz),
[adapter verification](ADAPTER_VERIFICATION.json.gz), [full audit](AUDIT.json),
[summary](SUMMARY.json), [21 rejection controls](REJECTIONS.json), and
[prelaunch failures](PRELAUNCH.md) retain provenance and limitations.
12 synthetic checker tests additionally pass, including agnostic acceptance.

Actual remote root: **xbd:/home/vick/rvv-directed-task145/**. Formal outputs:
`corpus/{manifest.json,build-commands.json,results.json,summary.json}`;
`corpus/UNIT/{test.S,test.elf,sail.elf,sail-config.json}`;
`corpus/runs/UNIT/ARM/{command.json,execution.json,stdout,stderr,packets.bin,checks.json,errors.json}`.
Sail adds `signature`; DUT adds `tbmap`. Raw includes exact actually executed
`vadd.py` and separately hardened `vadd-final.py`. The semantic checker is identical.
The hardened launcher verifies guest/reference pins and propagates check failure
through its exit code; a fresh six-unit pilot verifies that version.

Authenticated archive: **xbd:/home/vick/task145-directed-final-raw.tar.gz**.
Local extraction: **/home/user/research/materials/task145-directed-raw-20261013/**.
[Transport record](TRANSPORT.json) authenticates archive bytes and every payload
file against the remote RAW_MANIFEST.json. Build/test sources, guest ELFs, all
commands/streams/checks, reference signatures, audits, rejection copies, pilots
and preserved adapter probes are included. Work caches/fs copies and separately
pinned reference executables are excluded; actual remote originals remain.

Run a fresh corpus with existing dependencies (new output paths required):

```sh
# Build locally with the existing Clang20, identical retained RVVTS link layout.
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv/directed/vadd.py build \
  --compiler clang-20 --output /tmp/task145-fresh \
  --link scripts/rvv/fixtures/rvvts-20261089/link.ld
# Transfer this directory, script and existing external-flags.json to a NEW xbd root.
# Check xbd load, then run <=4 workers with local affinity/nice only.
taskset -c 28-31 nice -n 10 python3 vadd.py run --root /path/to/fresh-corpus \
  --engine /home/vick/rvdbt-host512-task142-build/build/bin/elfrun \
  --spike /home/vick/rvv-directed-task145/deps/spike \
  --pk /home/vick/rvv-directed-task145/deps/pk \
  --sail /home/vick/rvv-act4-tools/bin/sail_riscv_sim \
  --flags external-flags.json --jobs 4
# Complete offline reapplication to a fresh output (no execution):
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv/directed/audit.py \
  /home/user/research/materials/task145-directed-raw-20261013/corpus /tmp/task145-audit-new
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv/directed/test_vadd.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rvv/directed/reject.py \
  /home/user/research/materials/task145-directed-raw-20261013/corpus /tmp/task145-reject-new
```

This covers3 forms, not the overall595-form delivery. Explicit finite gaps:
other host widths, RV64, illegal encodings, nonzero-vstart with VL0/partial or
vstart>=VL, exhaustive mask/policy/length products, repeated/live-out vector
sequences and per-PC M1/M2 admission. No Linux/scalar/atomic/LLVM expansion,
production patch, fault/restart, handler return, mapping repair, retry or P4-04.
No push/publication; launcher owns completion signaling.
