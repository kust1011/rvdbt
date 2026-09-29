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
| Typed QIR frame | `dbt/qmc/qir.h`, `InstRVVTypedChunkBegin/End` |
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
the high chunk still contains four active elements and must execute with a
partial lane mask. At `vl=12`, the high chunk is entirely in the tail and
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

## Focused checks

Configure with Clang and LLVM as shown in the root README. On a host without
AVX-512, choose `-DRVV_HOST_CHUNK_BITS=128` for executable focused tests. An
AVX-512 build is not executable on such a host, even when a test's own code
would otherwise only inspect emitted instructions.

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
