# RVV execution in QCG

This continuation starts from `Wendell-Lin/rvdbt` commit `d312b122`. The
source integration is a snapshot of the RVV research implementation, not a
fabricated series of intermediate commits. The measured thesis claims concern
QCG execution; the repository also contains experimental LLVM and tiering
code, whose presence is not evidence of completed online-AOT performance.

## Translation path

`rv32_qir.cpp` translates a guest translation block. With
`--rvv-vector-run=1`, it scans the instruction stream for a compatible run;
an ineligible run falls through to the original single-instruction translator.
Each admitted direct RVV route produces project-specific **QIR**, not LLVM IR.
Typed chunk nodes carry host-vector types and def-use. QCG's `QEmit` lowers
these nodes through AsmJit to x86 code in the translation cache. A typed
frame's runtime guard checks the guest state assumed by the fast body; a
mismatch takes the ordered semantic fallback.

Key source locations:

| Concern | Source |
|---|---|
| Translation-loop dispatch | `dbt/guest/rv32_qir.cpp`, `RvvScanVectorRun`, `RvvTranslateVectorRun` |
| Run membership and dataflow | `dbt/guest/rv32_vrun.cpp`, `FormRun` |
| Chunk batch sizing and residency bounds | `dbt/guest/rv32_vrun.h`, `RvvRunBatchWidth`, `RvvRunPeakLiveBound` |
| Typed QIR frame | `dbt/qmc/qir.h`, `InstRVVTypedChunkBegin/End` |
| Physical register allocation and temporary retirement | `dbt/qmc/qcg/qra.cpp`, `QRegAlloc::Run`, `AnalyzeVPRRetirement` |
| x86 guards and lane operations | `dbt/qmc/qcg/qemit.cpp`, `Emit_rvvtypedchunkbegin`, `Emit_vchunkadd` |
| Active-chunk planning and frame legality | `dbt/guest/rv32_active_chunk_plan.h`, `dbt/guest/rv32_frame_semantics.h` |

## Two bounded optimizations

**M1 (RVV-aware value retention).** Consider `vadd.vv v8,v2,v3` followed by
`vsub.vv v9,v8,v4`. Translating each instruction separately materializes
`v8` into guest `CPUState` and reloads it for the second instruction. An
admitted run keeps this intermediate as a host QIR value. The descriptor
records registers read before any definition (`live_in_mask`) and the final
definitions that must remain visible after the run (`live_out_mask` and
`last_def`). A final `v8` is still published if later guest code may read it.
Run formation stops or refuses on unsupported instruction shapes, control
flow, vector-configuration changes, incompatible chunk geometry, or resource
limits. This integrates known register-promotion principles into QCG's RVV
state and fallback protocol; register promotion itself is not claimed as a
new compiler invention.

**M2 (active-work chunk admission).** A guest `VLEN=1024`, `SEW=32`,
`LMUL=1` register has 32 elements. With 512-bit host chunks, indices 0--15
belong to the low chunk and 16--31 to the high chunk. At runtime `vl=20`,
the high chunk still contains four body elements and must retain its
partial lane mask; `vstart` and the instruction mask further determine which
elements update. At `vl=12`, the high chunk is entirely in the tail and
may be skipped. The planner uses destination-element geometry, so widening
and narrowing operations cannot accidentally use source-byte offsets as
element indices. The frame finalizer admits bounds only when omitted work is
a contiguous suffix and required publication/epilogue effects still execute.
Whole-register operations are not bounded by `vl`. A member-major
multi-instruction run cannot take a shared early exit that would skip later
members' live low chunks.

The four evaluation arms are baseline RVV QCG (`B`), M1, M2, and their
integrated configuration (`Both`). `Both` may change run formation and which
dynamic instructions are eligible for M2; it is not automatically a pure
two-factor interaction on identical instruction populations.

In the thesis's recorded performance configuration, Both enables promotion,
batching and per-instruction bounds; eligible integer groups can use
component-first emission. General floating-point grouped early-exit options
are disabled in that configuration. Separate focused tests of that available
path must not be used to describe every floating-point run in the measured
Both configuration.

## Register allocation and resource limits

Run formation, chunk batching and register allocation have separate roles.
`FormRun` estimates residency before accepting another instruction. Exceeding
the applicable register budget ends that run; the remaining instructions are
translated separately. For eligible routes, `RvvRunBatchWidth` selects a bounded
number of chunks to process together. Neither operation is the allocator
splitting a guest translation block.

`QRegAlloc::Run` walks the already constructed QIR blocks and assigns physical
registers subject to operand constraints. `AnalyzeVPRRetirement` first identifies
last uses of local vector temporaries confined to one QIR block. After allocating
the last consumer, `RetireAt` marks the temporary retired. Its physical register
can subsequently be reclaimed without saving a value that has no remaining
consumer. Cross-block values are excluded from this early-retirement analysis.
This is block-local last-use analysis, not global live-interval allocation.

Architectural state publication remains a QIR use: retiring a temporary after
its final store does not discard the RISC-V register value in `CPUState`.
Promotion can increase register pressure; batching and shorter temporary
lifetimes bound that increase rather than guaranteeing fewer registers than
the per-instruction baseline. Guarded chunk groups also restrict spill insertion,
so admission checks cannot be replaced by an assumption that RA will spill any
excess live values.

## Focused checks

Configure with Clang and LLVM as shown in the root README. The helper build
setting `-DRVV_HOST_CHUNK_BITS=128` does not select a 128-bit native QCG
backend or establish that every focused test can execute without AVX-512.
Use a compatible host for tests that execute generated native code. Tests
that only inspect plans or emitted code have different host requirements.

```sh
ninja -C build -j2 rvv_vector_run_admission_test rvv_vector_run_codegen_test \
  rvv_active_chunk_plan_test rvv_frame_finalizer_test rvv_rvv_contract_test
build/bin/rvv_vector_run_admission_test
build/bin/rvv_vector_run_codegen_test
build/bin/rvv_active_chunk_plan_test
build/bin/rvv_frame_finalizer_test
build/bin/rvv_rvv_contract_test
python3 scripts/vlen_propagation_audit.py .
```

The repository does not redistribute restricted benchmark binaries or
inputs. Focused checks and scoped RVV corpus results are not a proof of
complete native lowering or exhaustive RVV 1.0 conformance.

### Synchronous memory boundaries in multi-instruction runs (Task136)

QCG run residency and component-first ordering are valid across nontrapping
arithmetic members. They are not an architectural commit protocol for memory.
Permission/backing preflight does not prevent a later synchronous host fault.
A component-first memory run can execute a later instruction before all components
of an earlier instruction finish; a final-live-out map also discards prior values
when a later destination overlaps an earlier destination. Member-major issue alone
does not recover dirty intermediate values or partially completed loads.

The production QCG run scan therefore cuts at each memory instruction, using the
existing `VectorMemory` constraint. Whole-register loads/stores are the only memory
members in the run route table; ordinary unit, strided, indexed, segment and mask
memory already have separate instruction routes. Each memory instruction keeps its
normal singleton SIMD/scalar frame, per-chunk/field publication, precise guest PC,
exact finalized sites and terminal cold exit. The arithmetic islands on either
side still use the selected residency/ordering and promotion policy. Source values
reach architectural state before the singleton memory frame via the existing SSA
commit and HAS_CALLS allocation boundary. This also makes repeated/overlapping
load destinations observe the previous complete instruction before replacing its
completed prefix. No later instruction executes before the memory frame completes.

QCG additionally sends any multi-member memory frame from another producer to its
ordered checked fallback; a singleton annotation cannot grant it native ownership.
This applies to all currently recognized memory helper families, independent of
body ordering. The existing singleton guard misses remain checked. LLVM admission
and optional gather are unchanged. Restoring memory fusion would require a real
per-instruction recovery/commit protocol retaining overwritten prior values and
prohibiting later architectural effects until earlier faulting instructions finish;
entry preflight and final live-outs alone cannot establish it.
