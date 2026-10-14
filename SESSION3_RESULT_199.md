# Task199 — required nonzero-vstart terminal traps

Closed Task198's missing semantic dimension for all23 required-trap forms on
unchanged fixed192, from `c90c735`. No DUT bug found; no production edit.
The595-form denominator is unchanged.

Read Task198 reconciliation and pinned official20240411 RVV1.0 clauses.
Illegal incoming vstart must trap even with VL0 or suppressed masks;
§3.7 preserves vstart on an illegal-instruction exception. Expected unchanged
state comes from independently initialized sentinels and existing initializers,
not DUT output. Existing per-form encodings and independent positive predicates
remain unchanged.

Compress pilot completed before the remaining22 forms were batched. Exact
smallest pilot: VLEN128/e8/m1/VL0/vstart1,
`vcompress.vm v8,v16,v17`, PC0x1042c/raw0x5f08a457. All four arms observed
ILLEGAL_INSN/trapno2 and preserved architectural state; positive VL7 also
passed. The permitted masked/unmasked variants of all other forms each cover
vstart1 with VL0 and positive VL; compress vm0 stays reserved/unexecuted.

| Coverage | Cases | B/M1/M2/BOTH observations |
|---|---:|---:|
| Compress required traps |2|8|
| Other22 forms required traps |88|352|
| Accepted181 zero-start positive controls |45|180|
| Total accepted |135|540|

All360 trap observations check original target PC, raw instruction, reason,
32 GPRs,32 FPRs,512 active vector bytes, ten CSRs including unchanged
vstart1, and closed FP run. All180 positive packets pass their existing
independent predicates. Masked integer reductions and pop/first use accepted
no-active masks; unmasked controls execute active elements for every form.
Eleven offline corruption controls reject damaged state/cause observations.

The existing Release illegal terminal observer prints PC/raw but has no
full-state formatter. Read-only GDB inspection at its post-fflush terminal
boundary supplies state, then kills the inferior; no returning handler,
memory repair, continuation or same-PC retry. A debug-types object reads exact
fixed192 header layouts and is never linked/loaded into the DUT. Neither
GDB exit0 nor DUT exit1 alone verifies architectural state. Exact stop,
positive joins and observer limits are in the
[evidence notes](docs/rvv-validation/trap-task199/README.md).

Preserved original failures: one preparation selection error before guest
execution; one initial debugger attempt missed an inlined termination call
and failed after guest exit1. It earns no state credit and was not overwritten.
Four original compress controls were reused; only the failed observation was
replaced by a separately retained corrected terminal run. Thus541 total DUT
launches comprise540 accepted unique case-arm checks plus one unverified
observer attempt.136 compiler calls include135 guest builds and one debug
types object. No reference calls or production build.

Executable SHA256
`908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4`;
library `79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af`.
Both identities match before/after. xbd isolated
`/home/vick/rvv-trap-task199`: one compile/test worker, nice10, inherited
affinity/no pinning, >=10GiB RAM/disk gated before/after each command.
[Summary](docs/rvv-validation/trap-task199/SUMMARY.json) and compact retained
packets/snapshots/receipts are committed with the tests.
[Raw retention](docs/rvv-validation/trap-task199/RETENTION.json) binds the
4.3MiB sparse archive on xbd and its matching local copy outside git;
all7441 members were traversed, including360 snapshots and the failed observer.

Finite VLEN128/e8 or e32/m1 coverage does not prove other configurations or
per-target native route admission. No full guest-memory/padding observation.
The fixed192 debug stop/layout cannot be transferred to a new build without
readjudication. Resource endpoints are sampled. Historical failures and
Task188 limitations remain unchanged. P4-04/equivalent recovery remains
**NOT EXECUTED / NOT VERIFIED**. Larger replay belongs to Session0.
No fault-recovery, LLVM, performance, thesis or publication expansion; no push.
Completion signals: `rvv-review197198` and `rvv-trap199`.
