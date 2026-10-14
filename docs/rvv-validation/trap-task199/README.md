# Task199: terminal required-vstart checks

From `c90c735`; only the missing23-form dimension identified in Task198.
The unchanged denominator is595 applicable forms. No production change.

Normative authority is RVV1.0 in the official20240411 manual,
[`v-st-ext.adoc` at6ee57d8997021aaa8025e208164763fe12e03c19](https://raw.githubusercontent.com/riscv/riscv-isa-manual/6ee57d8997021aaa8025e208164763fe12e03c19/src/v-st-ext.adoc),
SHA256 `f114464f32de3825863df04ff903137685a94a89973a8b38df3c4e804adf116f`.
§3.7 preserves vstart on illegal-instruction exceptions. The vector-reduction,
vcpop, vfirst, vmsbf, vmsif, vmsof, viota and vcompress clauses require illegal
instruction for nonzero incoming vstart. Their restart-position descriptions
do not authorize clearing vstart for this illegal-instruction exception.
Expectations were fixed from these clauses and Task198's reconciliation.

`trap199.py` reads frozen181 accepted indices and authenticates each source
manifest hash. It reuses `permute162`, `reduction163`, `mask158`, `prefix169`
and `fpreduce174` initializers, target encoders and independent positive
predicates. All45 controls are accepted181 declarations, with observer-local
ordinal0. Each trap changes only vstart to1 and VL to0 or the control's
positive VL; the compress selector is v17 for the exact Task198 encoding.
Traps initialize every GPR/FPR to independent per-register sentinels before
the target. No DUT answer becomes an expected result.

All cases use VLEN128/m1/tu/mu; integer/mask/compress SEW8, FP SEW32
(widening destinations64). Positive VL is7 unmasked integer/mask/compress,
15 masked integer reductions/prefix/iota,16 masked pop/first,2 FP.
Masked integer reductions use accepted tail-only masks; pop/first use off
masks; prefix/iota use alternating masks; FP use all masks. These masked
cases include suppression conditions that still must trap. Unmasked controls
provide active successful execution for every form. Compress uses only vm1:
vm0 is reserved and receives no execution/coverage credit.

The existing fixed192 illegal terminal observer emits `ILLEGAL_INSN ip/raw`
and terminates. Its Release build has no full-state illegal snapshot. GDB
therefore stops immediately after that observer's `fflush`, before its inlined
termination assignment, and reads the existing CPUState fields in the same
shape as `WriteMemoryFaultSnapshot`. It then kills the inferior without
continuing. The fixed192 disassembly pins `ukernel::Execute()+0x2c2`
(ELF address0x69582); RBX holds CPUState across the preceding libc call.
`trap199_types.cpp` supplies debug types compiled from the exact fixed192
headers; this object is read by GDB and never linked into or loaded by the DUT.
There are no inferior function calls or guest-state writes by the observer.

Each accepted trap requires the exact original PC/raw diagnostic, trapno2,
all32 GPR and32 FPR sentinels, all512 active vector bytes and all ten CSRs:
fflags/frm/fcsr/vstart/vxsat/vxrm/vcsr/vl/vtype/vlenb. It also requires the FP
run closed. vstart remains1. Exit status alone earns no state credit.
Controls require the existing full packet predicate, including its permitted
mask-tail values. GDB's successful exit is a controller result; accepted
trap inferiors are intentionally killed at the inspected terminal boundary.

First execution: compress controls4; initial debugger attempt1 (observer
failure); corrected compress trap observations8. Only then the remaining22
forms ran, without waiting for main:176 controls and352 trap observations.
The initial attempt missed the optimized inline termination call and the
inferior exited1. Its raw diagnostic identifies the expected trap but cannot
verify state; its GDB expression also failed after exit. Original streams,
script and nonzero controller result remain retained. A separate preparation
attempt selected the wrong FP pilot entry and stopped before any guest;
corrected selection uses accepted181 `b174-089`. No DUT failure was found.

Final counts:90 trap cases/360 state observations,45 positive cases/180
packet checks,135 unique cases/540 accepted case-arm checks. Including the
one unverified original debugger attempt gives541 DUT launches. One sidecar
compile plus135 guest builds gives136 compiler calls. One worker, nice10,
no CPU pinning; resource gates precede and follow every compile/test command.
Resource minima and all per-form counts are in `SUMMARY.json`.

`EVIDENCE.json.gz` retains all135 declarations/accepted joins,540 command
receipts, all360 snapshots and terminal streams, all180 positive packets,
build/source hashes, executable/library identities, and the failed observer
receipt. `audit_trap199.py audit EVIDENCE.json.gz SUMMARY.json` rechecks the
original independent predicates and terminal state and rejects11 corrupted
observations (PC, reason, GPR, FPR, vector, vstart, flags, open FP run,
missing/wrong diagnostic or wrong raw). Run collection/audit at nice10.

Limits: finite configurations; B/M1/M2/BOTH switches do not prove native
admission at each target. No architectural-state credit for the initial
observer failure. Active architectural vector bytes are checked; unused
fixed-storage padding and a full guest-memory image are outside observation.
The debug stop/layout is bound to the exact fixed192 identity and needs
readjudication for another build. Resource readings are command endpoints,
not a continuous global guarantee. P4-04/equivalent recovery remains
NOT EXECUTED / NOT VERIFIED: no handler return, repair or same-PC retry.
Session0 owns larger/new-build replay. No reference execution, LLVM,
performance, thesis, publication or push.
