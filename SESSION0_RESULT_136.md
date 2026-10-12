# Task136 — synchronous QCG memory instruction boundaries

Continued **7103885** on **fix/rvv-memory-families-issue-1**, while main audits135.
Implementation/test/design commit: **1fe19fb**. Evidence is committed separately.
No push or issue closure; the launcher sends completion.

**QCG memory instructions now delimit arithmetic runs.** Their existing singleton
SIMD/scalar bodies, exact finalized guest sites, completed-load publication and
terminal cold exits remain enabled. Arithmetic islands retain grouped promotion
and their selected body/ordering policy. Multi-member memory frames from other
producers take their existing ordered checked fallback. LLVM and optional gather
were not expanded.

## Actual admission before the fix

The retained production [baseline trace](docs/rvv-validation/grouped-memory-task136/receipts.tar.gz)
(`focused/baseline`) builds and emits forty streams, without executing guest code.
These are actual `RvvAdmitVectorRun`, `CompilerGenRegionIR`, allocation and QCG
emission, with force-emission switches off, guest VLEN1024 and host512.

| Actual route | Baseline formation/emission | Final formation/emission |
|---|---|---|
| Whole `vlNre` / `vsNr` | Twenty streams form one 5/6-member memory frame, two host chunks per member; **zero owned sites** | Two promoted arithmetic groups, one/two singleton memory frames, two/four owned SIMD sites |
| Ordinary unit `vle32` / `vse32` | Already cut the scan at memory: two arithmetic groups and singleton memory frames | Same legal grouping and singleton memory routes |
| Strided/indexed/segment/mask/scalar vector memory | No corresponding memory member row in this run former; their instruction routes remain separate | Unchanged; singleton Task135 ownership is not a grouped annotation |
| Arithmetic/FP component protocols | Register/FP state operations, **not guest memory** | Retain their existing arithmetic admission |

Only `LoadWhole` and `StoreWhole` are memory members in the run route table. Their
route predicate can admit whole shape candidates with the relevant switches on,
but the emitted grouped `special_memory_safe` call rejects whole transfers. Thus
these baseline memory frames actually select checked helpers; their native bodies
are emitted but not enabled. Unit/family grouped guard branches also existed in
QCG, but the production run former supplies no such members. A constructed
ordinary unit two-member frame could previously pass its preflight without exact
ownership; final adversarial unit/whole frames both select ordered checked calls,
even with a singleton PC annotation and component-major body flag.

## Concrete constraint and common fix

The baseline SSA body preloads live-ins, executes members and publishes **final
live-outs** at the run's end. Intermediate arithmetic and loaded values can remain
host values. A later definition of the same destination replaces its prior value
in `cur`; the final map does not preserve that older architectural instruction.
Materialize publishes via CPUState per member, but has no grouped exact site/PC
contract. Chunk-first ordering can execute and publish later members for component0
before an earlier memory member reaches a failing component1. Neither entry
permission preflight nor member-major issue alone solves these recovery problems.
The old whole guard kept those native bodies unreachable; its preflight cannot be
reinterpreted as permission to enable them.

The common fix is a **QCG instruction-frame boundary at memory**, documented in
[rvv-qcg.md](docs/rvv-qcg.md). `RunBackendCaps::memory_instruction_boundary` is set
by the production QCG translator, not LLVM. `FormRun` uses the existing
`VectorMemory` constraint before admitting a vector memory candidate. The cut
leaves that instruction for its original singleton route and permits subsequent
arithmetic to form another maximal run. It introduces no opcode/workload-specific
pair guard. QCG's emitter independently sends any recognized multi-member memory
frame to ordered checked fallback before executing its body. Singleton ownership
still explicitly requires `n_members==1`.

This preserves SIMD, and actually restores legal singleton whole SIMD execution
for streams that previously ran the entire grouped frame through helpers. It does
not globally disable native memory, arithmetic promotion, or component ordering.
The singleton's SSA commit and HAS_CALLS allocation boundary publish dirty prior
state before its guard/body. Each completed load chunk publishes before the next
access. Each memory frame finishes before the next arithmetic frame can execute,
so destination overlap cannot expose a later instruction at an earlier fault.
Existing checked guard misses and cold-exit cleanup remain intact. No runtime slot,
CPUState layout, AOT ABI, fault registry or signal callback change was needed.
ABI remains **a89957277993e0d9**.

## State and terminal observations

The focused stream starts with **addi x6,x0,0x123**, then a promoted pair:
`vadd v8,v1,v2` and `vxor v9,v8,v3`. It optionally completes an earlier load into
**the same v8**, then executes the fault-target load/store using x5. A later
`vadd v8,v8,v4` overwrites the same destination, followed by `vxor v10,v8,v3`.

Guest PCs are **80001234** for addi, **80001238/3c** for the prior pair, and
**80001240** for the target without the optional prior load. With that prior load,
it occupies **80001240** and the target is **80001244**. The later pair starts only
after the target instruction. x5 is **24000fc0**, x7 is **24000200**. The failing
second 64-byte chunk starts at **24001000**. All32 register slots have512 physical
bytes; guest VLEN is128 bytes per register, so full snapshots also check unused
slot bytes and unaffected destinations.

All **ten** terminal children are fresh and each observes exactly **one owned
SIGSEGV/SEGV_ACCERR** after raw host mprotect changes permissions without changing
MMU metadata. The original preflight still admits; the exact actual MOV fault
reaches the registered singleton cold block and production dispatcher checkpoint.
The child captures state and exits. No guest fault handler or faulting-MOV retry
executes.

* Eight default member-major cases: whole/unit × load/store × with/without the
  earlier same-destination load. Two additional whole load/store cases use
  chunk-first arithmetic ordering.
* Every prior arithmetic member completes across both components. x6 remains
  **0x123**. An earlier same-destination load remains complete except where the
  fault-target load's completed first chunk legitimately replaces it.
* Faulting loads publish their first64 bytes; their failed second chunk retains
  the prior instruction's destination bytes. No later v8 overwrite or v10 update
  is committed. All32 complete physical register slots match.
* Faulting stores retain their completed64 bytes and consume the correct prior
  arithmetic/load value. The remaining accessible memory bytes match initial
  state. Denied-page bytes are not read to claim a failed store's completion.
* Event raw word and PC identify the actual failed instruction. Whole `vs1r`
  uses encoded EEW1 and **vstart64**; whole `vl1re32` and ordinary unit32 use
  EEW4 and **vstart16**. VL32/vtype16/vlenb128 remain intact, NF1/field0 are exact.

The emitted sites retain actual width64 and encoded EEW independently. The final
normal receipt disassembly contains120 exact SIMD sites across40 streams; CPUState
spills/publication are excluded. Loads publish before the next guest access;
per-instruction cold blocks contain the real nonleaf teardown and terminal jump.
The production signal callback's retained disassembly has **zero calls**. All
fixture regions report **n_pins=0**; this is not arbitrary pinned/local-state
recovery evidence. No prior open FP bracket was newly injected in this task.

## Actual isolated host512 build and focused checks

Root: **xbd:/home/vick/rvdbt-grouped-memory-task136/**. Its source/dependencies were
copied from Task135, with a fresh isolated **build/** and the current changes
transferred. [Source equality](docs/rvv-validation/grouped-memory-task136/SOURCE_EQUALITY.json)
checks **298** build/production/test inputs directly against `git show 1fe19fb:<path>`;
[dependency equality](docs/rvv-validation/grouped-memory-task136/DEPENDENCY_EQUALITY.json)
checks **443** retained third-party files against Task135. Zero differences.

Actual AMD Ryzen9 9950X3D, AVX512F/BW/BMI2, Clang22/LLVM22.1.6, Release,
**RVV_HOST_CHUNK_BITS=512**, **-mavx512f -mavx512bw -O3 -DNDEBUG**. The
[flags audit](docs/rvv-validation/grouped-memory-task136/FLAGS_AUDIT.json) covers53
production commands,52 C++. `ldd -r` reports no unresolved symbols. Builds use
nice10, cores28–31, -j4; configure180s/build900s, internal-target build300s.
Checks run sequentially on core28 with60s bounds and core dumps disabled.
The external adapter uses nice10/core28/180s and preserves original call flags.
Final load0.17/0.32/0.40 is a scheduling observation, not performance evidence.

| Final focused check | Actual result |
|---|---|
| Grouped-boundary normal, five body/order modes, forty streams; two adversarial grouped frames | **585 parent checks PASS**, zero terminal children |
| Grouped-boundary one-time terminal batch | **103 parent checks PASS**, **10 terminal children**, all one owned SEGV |
| Existing scalar-native normal-only | **1,919 checks PASS**, zero terminal children |
| Existing whole-native normal-only | **13,330 checks PASS**, zero terminal children |
| Internal run admission | **PASS**, including explicit memory cut in both materialize modes |
| Focused run codegen `--memory-boundaries` | **PASS**,72 ordered pairs and6 extended-family admission cases; split memory frames and intervening promoted .vx pair at VLEN512/1024 |
| Three unchanged upstream original ACT B calls | **3/3 PASS** |

Upstream cases: **Vls8-vl1re8.v, Vls8-vl1re64.v, Vls8-vs1r.v**. The
[external audit](docs/rvv-validation/grouped-memory-task136/EXTERNAL_AUDIT.json)
checks full original call equality, original predicates from raw stdout/stderr,
flags except relocated paths, source/ELF/answer/checker/capture hashes and ELF32/LE.
No external input, answer, checker or acceptance predicate was changed. No guest
compilation, generator or reference-engine call occurred. These normal upstream
passes receive no fault-ownership credit.

Final [identities](docs/rvv-validation/grouped-memory-task136/FINAL_IDENTITY.json):

* elfrun: **1568d3108b6a33d1cc62c8c3fce011211744ab44aac9cdadae2316599a703d38**
* libdbtjitshared.so: **79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af**
* grouped fixture: **dd747d416c7730b40df124075f48a3b078f4945ec8c13a49e2783643c1f43fb6**

Production binaries were pinned before/after every focused/terminal execution.
**The grouped fixture was omitted from the initial pin list:** its hash was first
recorded after the terminal batch, followed by the final normal-only check with
that fixture pinned. Its final successful build and unchanged retained source are
recorded; the terminal batch does not receive a retroactive fixture pre-pin claim.
No terminal case was repeated to improve this evidence.

The [offline audit](docs/rvv-validation/grouped-memory-task136/OFFLINE_AUDIT.json)
authenticates **999 receipt files**, independently reconstructs all16384 vector
bytes and4096 accessible memory bytes for each terminal cell, checks event/PC/GPR
and CSR coordinates, compares actual baseline/final formation, and decodes all40
normal emitted shapes/120 sites. It executes zero guest instructions and finds
zero differences. The initial audit incorrectly expected a nonzero-membase operand;
actual disassembly uses **(%rax)** in this zero-membase build. The audit was corrected
without any guest execution or production change.

## Retained attempts and remaining obligations

Two fixture builds failed (missing translator include, then its namespace). Both
failures stop the build script; **no tests execute after either failed build**.
Baseline tracing follows the successful build. Two normal-only attempts failed on
the constructed checked frame's expected normal PC; checked helpers advance IP
past the last member (**8000123c**). The fixture expectation was corrected and a
subsequent successful rebuild/normal check passes. A rapid earlier transfer did
not trigger the expected fixture recompilation; later transfers explicitly touch
changed sources before building. Retained initial/final compiler logs and normal
streams receive no invented passing credit. No memory host faults occurred in
these attempts.

The broad internal `rvv_vector_run_codegen_test` invocation exits1 with **22
pinned byte/hash golden failures**, all in `CheckFlagOffGoldens`. Its other reported
checks, including memory-boundary checks, are not represented as an overall pass.
The four deliberate invalid-QIR panic children in that existing test are not guest
memory faults. Golden constants were **not** changed. The affected full invocation
remains an unresolved legacy codegen-oracle obligation; this task does not claim a
measured pre-change baseline for those22 comparisons. The final focused mode runs
the ordering/admission/emission checks needed for this change without that unrelated
historical-byte contract. Existing internal memory expectations were changed to
assert instruction boundaries, not removed or accepted as fused memory.

Remaining contracts: memory fusion would need per-instruction prior-state retention,
overlap recovery, exact member sites/PCs and commit ordering across all components.
This task resolves that constraint by using instruction frames, not by declaring
those absent maps safe. LLVM, optional gather and other unannotated native nodes
remain outside this ownership. Existing singleton unsupported backing,
split/wrapping accesses, guard misses and accepted signal-code restrictions retain
their earlier fallback/unowned contracts. Concurrent mapping/backing lifetime,
arbitrary live/pinned values, BUS_OBJERR injection and a newly open prior FP bracket
are not established here. Task135's scalar BUS contract is unchanged; this task's
native SIMD faults are SEGV only. Focused terminal geometry is VLEN1024/NF1 and
is not exhaustive ISA/restart validation.

No whole-corpus/performance rerun, guest handler return, mapping repair/same-PC
retry, P4-04/equivalent, push or closure occurred. **Guest restart is NOT verified.**

## Exact commands and retained locations

The remote helper scripts and every `*.command.json`, rc/stdout/stderr are retained
in the receipt archive. Build helpers exit on nonzero configure/build; focused and
external adapters additionally assert successful build and pinned production
identities before execution. The internal target build succeeds before either
internal test is launched.

```sh
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/build136.py'
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/focused136.py baseline rv32_grouped_memory_fault_test --baseline-trace'
# After the production fix and successful rebuild:
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/focused136.py normal-diagnose rv32_grouped_memory_fault_test --normal-only'
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/focused136.py terminal rv32_grouped_memory_fault_test --terminal'
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/focused136.py scalar-normal rv32_scalar_native_fault_test --normal-only'
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/focused136.py whole-normal rv32_whole_native_fault_test --normal-only'
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/extra136.py'
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/focused136.py admission rvv_vector_run_admission_test'
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/focused136.py codegen rvv_vector_run_codegen_test'
# Focused mode added, internal targets rebuilt successfully, identities refreshed:
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/focused136.py codegen-focused rvv_vector_run_codegen_test --memory-boundaries'
# The recorded external.command.json contains this exact adapter command:
taskset -c 28 nice -n 10 timeout 180 python3 /home/vick/rvdbt-grouped-memory-task136/replay_grouped_memory_task136.py /home/vick/rvdbt-grouped-memory-task136
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/focused136.py normal-pinned-final rv32_grouped_memory_fault_test --normal-only'
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/externalaudit136.py'
ssh xbd 'python3 /home/vick/rvdbt-grouped-memory-task136/collect136.py'
python3 scripts/audit_grouped_memory_task136.py /home/user/research/materials/task136-grouped-memory-raw-20261013 docs/rvv-validation/grouped-memory-task136/OFFLINE_AUDIT.json
python3 -m py_compile scripts/audit_grouped_memory_task136.py scripts/replay_grouped_memory_task136.py
git diff --check
```

`build136.py` runs exactly:

```sh
cmake -S /home/vick/rvdbt-grouped-memory-task136/source -B /home/vick/rvdbt-grouped-memory-task136/build -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang-22 -DCMAKE_CXX_COMPILER=clang++-22 -DLLVM_DIR=/usr/lib/llvm-22/cmake -DRVV_HOST_CHUNK_BITS=512 -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
taskset -c 28-31 nice -n 10 cmake --build /home/vick/rvdbt-grouped-memory-task136/build -j4 --target elfrun rv32_grouped_memory_fault_test rv32_scalar_native_fault_test rv32_native_memory_fault_test rv32_whole_native_fault_test
# extra136.py:
taskset -c 28-31 nice -n 10 cmake --build /home/vick/rvdbt-grouped-memory-task136/build -j4 --target rvv_vector_run_admission_test rvv_vector_run_codegen_test
```

[Receipt archive](docs/rvv-validation/grouped-memory-task136/receipts.tar.gz): SHA256
**05cf77db4c5577413343f9ea063cc8a66f6a3874b73ff16eeb65e82fff863d3e**.
Local raw: **/home/user/research/materials/task136-grouped-memory-raw-20261013/**.
Remote isolated source/build/receipts remain at the root above. Earlier task
receipts were not overwritten. Python syntax and `git diff --check` pass.
