# Task149 completion from retained records

Completed in Task150 without rerunning guests. The original multiply/divide
batch covers 16 vv/vx forms of vmul/vmulh/vmulhu/vmulhsu/vdiv/vdivu/vrem/vremu:
97,360 cases, 486,800 packet checks and 21,120 commands. The separate 0/0 delta
adds 1,056 cases, 5,280 checks and 660 commands. Combined: **98,416 cases,
492,080 checks, 21,780 commands**, all PASS under the recorded predicates.
All original build/run/audit/controls/summary stage statuses are zero. Complete
offline replay, target opcode/source checks and Sail adapter verification are
already recorded; no new guest or replay credit is added here.

Each arm has 94,256 ordinary PASS and 4,160 PROFILE_RESERVED_START outcomes;
the latter are separate accepting-profile observations. Full arithmetic controls
reject 469/469 mutations; the delta rejects 16/16. Pilot results remain separate:
2,688 cases/13,440 checks and 32 delta cases/160 checks. DUT is the unchanged
e2559c5c host512 build; fixed Spike/Sail identities match before and after.

**Retained-ELF repair:** Task149's compressed arm ELF symlinks were dangling.
The retained repair reports record 512 pilot, 16,896 full, 16 zero-pilot and 528
zero-full aliases repaired (17,952 total). Each report verifies recovery through
an original arm-command ELF path and exact compiled ELF identity. Repair used
zero guest executions and preserved the permanent compressed bytes and original
execution records. New snapshots use the corrected shared alias writer.

Raw artifacts remain at `xbd:/home/vick/rvv-directed-task149/` in the four named
batches. [Retained completion records](docs/rvv-validation/directed-task150/task149-completion/)
include original stage, summary, audit, controls, per-form, identity, freeze and
repair records. Earlier extractor/control issues are preserved in
[FIRST_FAILURES.json](docs/rvv-validation/directed-task149/FIRST_FAILURES.json).
No unresolved recorded DUT failure. This is a worker result, **not main acceptance**,
and does not claim per-target M1/M2 admission or exhaustive semantic coverage.
