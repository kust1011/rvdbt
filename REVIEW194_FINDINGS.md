# Task194 independent RA review

**Accept the region-sized allocation change. No new safety defect established in
the reviewed QCG path; no index-type expansion is justified for the current RVV
JIT bounds.** Reviewed session0's current `qra.cpp` / `qra_vpr_test.cpp` diff;
their bytes match the source retained with the Task192 executable. Production
files in compliance192 and compliance193 were not edited.

The remaining representation limit is concrete, not a peak-pressure limit:
`qir.h:3928` computes a size_t index in `VRegsInfo::AddLocal`, appends the type,
then returns `RegN` (u16). With 32 globals, 65,503 locals produce NumAll=65,535
and last index=65,534. The next local returns 65,535 (`RegNBad`); another returns
0, aliasing global 0. The owned QIR-only probe reproduces this using the actual
header and arena implementation. This is a missing boundary observation, **not
a demonstrated supported-RVV misallocation**: session0's constructor rejects
NumAll>65,535 before constructing tracks or running retirement/allocation.
NumAll retains the wide count despite operand narrowing, and QSel only appends
locals, so an oversized QCG region cannot evade that guard.

If future work admits larger regions, enforce the bound in AddLocal *before*
appending/publishing the operand, or deliberately revise the complete index
representation. Merely widening RA counters would not fix operand truncation.
There is no recommendation here to expand types or rewrite the allocator.

## Allocation and lifetime checks

- `make_unique<RTrack[]>(n_all)` allocates once. Nothing resizes/replaces it;
  `p2v`, `p2v_vpr` retain stable addresses until the allocator dies. AddTrack's
  placement construction resets the default member initializers, including
  DEAD, NO_SPILL, GPR class, and false sync/pin/retirement state. No RTrack owns
  resources that would be lost by that construction.
- Both retirement arrays are value initialized: null block/last-use/instruction,
  zero definition count/index, false multi_block/queued. Queued prevents duplicate
  retirement entries, including two inputs naming one value. Each value supplies
  at most one entry, so n_retire<=n_all<=65,535. The final increments of n_vregs,
  n_retire and retire_pos can reach 65,535 without wrapping; their loops then stop.
  Count=65,536 would require wider counters and is correctly refused.
- Globals occupy the initial tracks, preserve state offsets/types and are excluded
  from retirement. Optional pinning vectors have n_globals entries, initialized
  to zero/false; every scratch access is guarded by a global-index check or a
  global-only scan. No local index reaches those vectors. Zero-global/zero-local
  allocations are legal and the corresponding loops are empty.
- QSel runs before RA and can append scalar temporaries. RA samples the completed
  count after QSel. RA's own spill/fill/move insertions use existing physical/slot
  operands and never add virtual values, preserving the allocation capacity.
- Spill-frame and physical-register bounds measure live pressure independently.
  Increasing total track capacity cannot make a frame hold more live values.
  Existing T3 still rejects 17 live 64-byte slots in the 1024-byte frame; T6/T7,
  T10/T11 retain last-use, cross-block and final-consumer ordering coverage.

## Actual supported region shapes

`execute.cpp:211,368` forms one page-clipped ip range for an ordinary JIT job.
`rv32_qir.cpp:2029–2037` creates/translates one QIR block per supplied range;
`TranslateIPRange:2183` stops normal straight-line translation at TB_MAX_INSNS=64.
Run formation uses the *remaining* instruction budget, and the 64-member bound
is statically joined to TB_MAX_INSNS. It is not 64 QIR nodes or 64 SSA values.

The admitted guest VLENs are powers of two 128..4096. A register needs at most
eight 512-bit chunks; an LMUL8 group needs at most 64 chunks. Read the actual
FP bodies: `RvvEmitTypedFpChunkBody:7770–7838` uses up to four fresh values per
chunk; `RvvEmitTypedFWidenChunkGroup:9229–9275` can use six (two narrow loads,
two conversions, old destination, result). Even a deliberately conservative
64-instruction shape of 64 chunks with six values plus one broadcast each has
24,672 tracks including 32 globals, well below 65,535. This is a bound for these
widest inspected lowering bodies, not a claim that every optional compiler mode
has the same bound. Helpers/active-mask nodes carry state offsets/immediates;
they do not allocate one SSA register per architectural element.

The eight-element batch arrays bound *residency*, not the total group chunks or
total SSA count. A 4096/e32/m4 sequence easily exceeds 2048 total tracks with
short-lived batches. Session0's 16,504-track fixture proves the distinction.

Do not generalize the ordinary-JIT bound to arbitrary CompilerJob inputs.
Multiple ranges accumulate in one Region, and AOT can gather several regions
(`llvmaot.cpp:1110–1122`). Optional inlining also has a source comment acknowledging
that the equality-based TB stop can be passed. These are outside Task192's
normal QCG execution profile. The existing LLVM CreateVGPRLocs u16 scan has no
equivalent range guard (`llvmgen.cpp:714`); this is a source-only pre-existing
limit, not a tested LLVM failure or a reason to expand this task into LLVM/AOT.

## Evidence and reproduction

Reused Task192's retained allocator execution: exit0, no timeout, 274/2104/16504
tracks terminate and sync all three globals. Expected T3 child panic is retained.
Raw source hashes and command/exit records are in
`docs/rvv-validation/ra-review-task194/session0-receipts.json`; stdout/stderr are
copied there from the archive, not regenerated. Read long192.py, audit192.py,
PLAN, SUMMARY and the production-result report: 54 unique cases, 216 accepted DUT
packets split between 191 and fixed192, 16 original failed packets retained.
That finite evidence is not full-matrix or unlimited-region acceptance.

One independent local probe, no production library, guest or reference execution:

```sh
clang++ -std=c++20 -O1 -I. docs/rvv-validation/ra-review-task194/qir_index_boundary.cpp dbt/arena.cpp -o /tmp/qir-index-boundary194
/tmp/qir-index-boundary194
```

It checks actual AddLocal/NumAll at the last supported count, sentinel index and
first wrapped index. Its mmap/Panic/log-registration services isolate the header
and production arena from the runtime; no index creation is mocked. Exit0.
