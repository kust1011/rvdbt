# Task192 — confirmed long-VLEN ordinary-completion defect fixed

From `ba1c252`, branch `rvv/compliance192`. Found one production defect:
legal VLEN4096/e32/m4 FP sequences abort during QCG allocation because total
SSA tracks exceed the unrelated fixed2048-entry arrays. The65-operation guest
crosses the64-instruction TB limit. All four current191 arms abort with
`QRegAlloc: virtual-register track capacity exceeded`, rc-6 and empty output;
pinned Spike completes and passes the independent sequential predicate. Even
the first VL0 case cannot complete. This is an ordinary-completion failure,
not an arithmetic mismatch or an inferred missing instruction family.

**Requirement and exact fix.** Pinned RVV1.0 revision
`3570f998903f00352552b670f1f7b7334f0a144a`, §§3.2,3.4.3,4,5.2,5.4:
supported legal groups must execute with prescribed register mapping and
active/inactive/tail behavior, including no vector updates at VL0. In
`dbt/qmc/qcg/qra.cpp:124–177`, allocate tracks and both retirement arrays once
from the completed region's `NumAll()`, retaining stable addresses for physical
register maps. Check the existing16-bit index representation before allocation.
`qra.cpp:662–663` sizes optional pinning scratch by global count. The fix removes
the arbitrary total-value cap generally; live-register/spill-frame safety and
retirement rules remain in force. Three allocations per region use O(SSA count)
memory; no performance benefit or timing result is claimed.

**Existing versus new.** Read parent guidance/state,187 obligations,191
integration, pinned local specification and directed generators before execution.
Existing154/155/162/163/172/174/175/final181 already cover long-VLEN single-form
LMUL, masks/tails, widening/narrowing, permutations and reductions; these batches
were reused as evidence and not replayed. Retained177 manifests confirm integer
m1/m2 and FP m1/m2/mf2 sequences with at most five arithmetic operations.
[Pre-execution plan](docs/rvv-validation/long-task192/PLAN.md) identifies the
missing composition and actual source bounds:4096-bit register reservation,
4096 mask bits at e8/m8, runtime group mapping with fixed512-byte storage stride,
eight-chunk batches, separate run admission,64-member arrays and value lifetime.
No additional mask-width/group-addressing production bug was confirmed.

New `scripts/rvv/directed/long192.py` reuses177 assembly/capture, full-state
sequential integer/exact-rational FP predicates and original pinned Spike/pk.
It adds54 cases:2048/4096, integer e8/mf8,e16/m4,e8/m8; FP e32/mf2,e32/m4,
e64/m8; partial VL, physical/chunk boundaries and65 dependent operations.
An integer masked member forces publication before continuing. After observing
singleton-only admission, two disjoint65-op controls at2048/e32/m2 and
4096/e32/m1 supply actual M1/BOTH execution. Accepted five-op batches were not
repeated. Minimum fractional and integer group alignment/file bounds are checked.

**Validation order and result.** First retain the original four failing DUT
commands/16 failed packet checks. Build the isolated192 production executable,
run the affected allocator regression, then replay only the original failing
guest in four arms using unchanged ELF and original Spike packets. All16 checks
pass before the disjoint remaining cases run. `qra_vpr_test.cpp:970–1014,1559`
extends the existing retirement/call/global-sync test to274,2104 and16504 tracks;
the full allocator fixture passes, including live-pressure rejection and
cross-block lifetime checks. No new semantic oracle was needed.

Final accepted evidence:54 unique cases,54 independent reference packets,
216 DUT packet checks:16 on current191,200 on fixed192. The extra16 original
failed checks remain failures. This is14 Spike commands,60 DUT commands
(four failed), and one allocator-fixture command. Full vectors, prestate, CSRs
and saved scalars pass the original predicates. The original failure and
affected replay share the exact ELF/reference hashes.

Actual PC/census/generated-code audit: B/M2 each3510 singleton target-PC rows;
M1/BOTH each2990 singleton,390 native multi-member and130 ordered-run-fallback
rows. There are32 multi frames,24 with native executions; the eight non-native
entries are VL0. Additional active-bound singleton code is verified in M2/BOTH.
Large/fractional singleton cases get zero multi-run credit. The offline
[join](docs/rvv-validation/long-task192/audit192.py) checks receipt hashes,
source changes, original failures, independent audits and actual route evidence;
[summary](docs/rvv-validation/long-task192/SUMMARY.json) is PASS.

**Identity/resources/retention.** xbd isolated `/home/vick/rvv-long-task192`:
Release Clang22.1.6, host chunk512, unchanged191 configuration/library. New
`elfrun` SHA256 `908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4`.
The298-file191 source comparison differs only in owned `qra.cpp` and its test.
Production build exit0; compile<=2, correctness<=2, nice10, no affinity changes,
>=10GiB reserve (last archive endpoint21,962,133,504 bytes free).
Two SSH controller transports returned255 after remote completion; retained
build/run exit/result/resource records authenticate completion without repeats.
The full83,287,433-byte archive is outside git at
`/home/user/research/materials/task192-long-raw-20261014/raw-receipts.tar.gz`,
SHA256 `a21c4ab8ba25036251c0125cd8a59c6a00cfa441f18bb5a5f17ab88b720065d8`.
Archive SHA and complete member traversal verified locally; interrupted scp
partial retained and resumed using append verification. Compact original failure,
manifests, transport receipts and audit scripts are committed under
`docs/rvv-validation/long-task192/`; source/build binaries remain isolated on xbd.

**Remaining gaps.** This finite long-block composition is not a new595-form
common-build acceptance or exhaustive mixed-width/permutation/reduction sequence
proof. Existing single-form evidence is not relabelled as192 execution. Session3's
independent legality worktree was untouched; no new finding was supplied here.
187-01/P4-04 and equivalents remain service-blocked, NOT EXECUTED / NOT VERIFIED.
No permission repair/handler return/retry, Linux/scalar/LLVM expansion, broad
performance run, push/email/reset occurred. Completion signals:
`rvv-compliance192` and `rvv-review-parallel-20261013`.
