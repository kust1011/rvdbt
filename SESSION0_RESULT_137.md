# Task137 — resolve all 22 flag-off golden failures

Continued **8732299** while main audits135/136. Code/test/audit commit:
**58c9612**. Evidence is committed separately. No push or closure; the launcher
signals main. **All 22 original failing assertions are resolved; remaining full-test
failures:0.** Production memory-boundary code and its checks remain intact.

## Purpose, accepted control and configuration

Read the original R1A.3b golden contract in archived commit **fd4404845**: flag-off
must preserve the accepted R1A.3a **8ce794a87** instruction sequence, independently
of the new vector-run body. Read the HM.2a **6f613f2e6** history and the inherited
**13d8b17bd** displacement-independent contract. The historical test also explicitly
records the later A13 base-range-guard exception, including its pre-fix constants.
Those originals were read from the research archive; they were not edited.

The last relevant accepted implementation containing **all existing golden values,
including A13**, is imported production **c2084aa**. A fresh isolated build of that
exact production source reproduces **all 16 rows / all 80 scalar golden comparisons**.
This is a measured small control, not a self-comparison or another corpus. The
control's only test changes add optional dumps and `--goldens-only`; its golden
values and comparisons stay unchanged. The exact instrumentation is retained in
[CONTROL_INSTRUMENTATION.diff.gz](docs/rvv-validation/flag-off-task137/CONTROL_INSTRUMENTATION.diff.gz).

Both arms use the same retained dependencies, Clang22/LLVM22.1.6, Release and
**RVV_HOST_CHUNK_BITS=512** on the actual Ryzen9 9950X3D with AVX512F/BW/BMI2.
The test's same `ApplyConfig` selects QCG, direct typed ALU/unit-memory routes,
direct setvl, component SSA/member order, hit counters on, vector_run=false,
extended families/census/live split/probe off. Its longstanding force-emission
knobs remain enabled for the disassembly test; it executes no emitted guest code.
There is no configuration substitution to recover the old output. The focused
production normal fixtures retain their existing route selection without force emission.

[Source equality](docs/rvv-validation/flag-off-task137/SOURCE_EQUALITY.json) validates
**276 control /297 final inputs**, zero differences, against the exact commits
(with the explicit control test instrumentation exception).
[Dependency equality](docs/rvv-validation/flag-off-task137/DEPENDENCY_EQUALITY.json)
checks **442 files** in asmjit/elfio, excluding `.git` metadata, against both arms
and Task136. No dependency differences. Full command/cache/compile-command receipts
are retained. The final flags audit covers **52 production commands,51 C++**, all
C++ using **-mavx512f -mavx512bw -O3 -DNDEBUG**. This count selects dbtstatic and
dbtjitshared objects; it does not claim every executable object is production.

## Instruction-level explanation, not an unchecked re-pin

The independently reconstructed expected output in
[audit_flag_off_task137.py](scripts/audit_flag_off_task137.py) must equal every
retained final normalized instruction line. It admits only these exact changes:

* **Twelve non-memory rows:** QIR, byte counts, line counts, register allocation,
  operations, branches and historical nodisp hashes are identical. Only
  `inc QWORD PTR [r13+0xa500]` / `[r13+0xa508]` become
  `[r13+0xa528]` / `[r13+0xa530]`. These are actual `rvv_direct_hits` and
  `rvv_direct_fallbacks` offsets. Five appended runtime stubs in
  **b028083 / ba817f6 /51b2fe5 /bfbb2c9** grow the embedded table by 40 bytes.
  Measured `offsetof`/table size in both arms confirms this cause. Only the
  layout-specific golden hashes change.
* **Two `add;vle;add` rows:** before the existing vtype/VL/vstart/base-range
  guards, **b028083 /bfbb2c9** add `mov rdi,r13; mov esi,raw; call
  rv32_native_memory_safe; test eax,eax; je fallback`. The fallback call changes
  from `rv32_vle` to `rv32_native_memory_fault`. After that arm, the emitted cold
  exit is `jmp join; pop rcx; mov rdi,r13; xor esi,esi; jmp
  rv32_native_memory_fault`. These are **+40 bytes /+10 instructions** at both
  guest VLENs. Existing architectural guards and `cmp eax,2^32-VLEN/8; ja
  fallback` survive; local branch targets relocate exactly as the retained diff
  specifies. CPUState counter offsets change as above. At VLEN1024,
  **d86355b** moves chunk0's publication before chunk1's guest load, retaining
  the same ZMM assignments and 64-byte windows. At VLEN512 there is one chunk
  and no publication-order change. This is the only changed QIR row.

The Task136 run split is not the cause of these flag-off changes: these streams
already use singleton memory frames with vector_run=false. Production admission,
site ownership, cold exit and boundary checks were not changed in Task137.
No erroneous production instruction was found by this comparison.

Raw bytes differ in **all 16 rows between separate current processes** because of
relative external helper calls and absolute cache pointers. QIR and normalized
instruction strings remain identical across both pre-change current processes,
the initial golden update and the final executable. Raw byte identity is therefore
unsuitable, as the original checker already recognized. The existing normalized
hash/byte-count/line-count contract is retained, not replaced by acceptance of any
current output. The scalar-only two rows retain every constant unchanged.

The original normalizer also masks long semantic immediates and external helper
identities. Task137 strengthens the two memory rows with an exact deterministic
protocol check: resolved calls must be ordered `vadd_vv`, `native_memory_safe`,
`native_memory_fault`, `vadd_vv`, then the existing `trace_cache`; exactly one cold
jump reaches `native_memory_fault`, and exactly one EAX range compare uses the
correct limit. At each VLEN, two mutation checks change the range limit and replace
preflight with the ordinary `rv32_vle` helper. **Both errors keep the legacy
normalized hash unchanged, but the protocol checker rejects them.** No emitted
mutation is executed. These checks run in the full test as well as the focused mode.

## Every original failure's disposition

There were 22 assertion failures across 14 rows, not 22 distinct kernels. `n` and
`n2` separately count the two normalized disassemblies. The complete old/new values,
exact QIR/raw x86 and hashes remain in the archive; the readable per-row diffs and
[offline audit](docs/rvv-validation/flag-off-task137/OFFLINE_AUDIT.json) independently
check the explanations above.

| Failure | Case / VLEN | Assertion | Before → after | Disposition |
|---:|---|---|---|---|
| 1 | add;sub / 512 | hash | `0x8a3f1ba968213a7b` → `0xf1a663ceab7e620f` | Counter displacement only |
| 2 | add;sub / 1024 | hash | `0x0dc21a369eac1ac9` → `0x20da4e7c6f9423a7` | Counter displacement only |
| 3 | mul;xor / 512 | hash | `0xf3783699ff16e3e7` → `0x5d3187053561a477` | Counter displacement only |
| 4 | mul;xor / 1024 | hash | `0x94b9af39e1c3a6e7` → `0xd378d3ff656b025d` | Counter displacement only |
| 5 | or;and / 512 | hash | `0x4156d3a3781aab04` → `0xb3c47d020b605746` | Counter displacement only |
| 6 | or;and / 1024 | hash | `0xdc2c8ed655d7f50f` → `0x295e075c5760de65` | Counter displacement only |
| 7 | six ops / 512 | hash | `0xd6646e36c43df63c` → `0x5325d967670a0818` | Counter displacement only |
| 8 | six ops / 1024 | hash | `0x7bfde7e97d68dc92` → `0x45430170ec234f90` | Counter displacement only |
| 9 | add;vle;add / 512 | bytes | `544` → `584` | Reviewed memory sequence |
| 10 | add;vle;add / 512 | lines n | `82` → `92` | Reviewed memory sequence |
| 11 | add;vle;add / 512 | lines n2 | `82` → `92` | Reviewed memory sequence |
| 12 | add;vle;add / 512 | hash | `0xe6242c695e058389` → `0xb4ebc357e28140f8` | Reviewed memory sequence |
| 13 | add;vle;add / 512 | nodisp hash | `0xc7e89f556cb9ccaa` → `0x68bbd118426230b2` | Reviewed memory sequence |
| 14 | add;vle;add / 1024 | bytes | `632` → `672` | Reviewed memory sequence |
| 15 | add;vle;add / 1024 | lines n | `94` → `104` | Reviewed memory sequence |
| 16 | add;vle;add / 1024 | lines n2 | `94` → `104` | Reviewed memory sequence |
| 17 | add;vle;add / 1024 | hash | `0xebe23dbe9c97d414` → `0x7670d62167245bc3` | Reviewed memory sequence |
| 18 | add;vle;add / 1024 | nodisp hash | `0x118928ba924d8b7b` → `0xb1250b51f6269121` | Reviewed memory sequence |
| 19 | no vsetvli add;sub / 512 | hash | `0x77d09eb08e5391ba` → `0x33ddf19f5c9dbe16` | Counter displacement only |
| 20 | no vsetvli add;sub / 1024 | hash | `0xdcf252606ec22d40` → `0x1f59430a1c2a72c2` | Counter displacement only |
| 21 | overlap chain / 512 | hash | `0xd4ab68023d85bfc5` → `0xf523da4dedb35f55` | Counter displacement only |
| 22 | overlap chain / 1024 | hash | `0xfc3056abfe9f23b9` → `0xf2ed81fcbd091cd3` | Counter displacement only |

The two `scalar only` rows are unchanged passing controls (112 bytes /22 lines,
hash `0x7adb91d6d25b35a8`, nodisp `0x79649824b01d18f4`). All 14 other nodisp hashes
outside the memory exceptions remain unchanged.

## Final successful builds and normal checks

Isolated root: **xbd:/home/vick/rvdbt-goldens-task137/**, with separate
**control/source, control/build, current/source, current/build**. Both build
folders are fresh; no Task135/136 tree or receipts were overwritten. Configure
limit 180s, build 900s; nice 10, cores28–31, -j4. Checks use nice 10/core 28/60s,
core dumps disabled. All tests are gated on successful build and complete
before/after binary pins. `ldd -r` on final elfrun has no unresolved symbols.

| Final check | Result |
|---|---|
| Full `rvv_vector_run_codegen_test` | **ALL CHECKS PASSED, exit0** |
| Focused all 16 goldens + exact protocol + four rejection mutations | **PASS** |
| Existing `--memory-boundaries` | **PASS**, unchanged 72 pairs /6 extended-family admission cases |
| `rvv_vector_run_admission_test` | **PASS** |
| Grouped memory `--normal-only` | **585 checks PASS**, terminal_cells=0 |
| Scalar native `--normal-only` | **1,919 checks PASS**, terminal_cells=0 |
| Whole native `--normal-only` | **13,330 checks PASS**, terminal_cells=0 |

The full internal test retains its four existing deliberately malformed-QIR panic
children. These are expected checker tests, not guest memory faults or restart
execution. No new fault/terminal/restart batch, external corpus or performance
campaign ran. No original upstream guest/input/answer/checker was edited.

[Final identities](docs/rvv-validation/flag-off-task137/CURRENT_BUILD_SUCCESS.json):
codegen **30adb6cead02e4228defe416e2bbbd976ec9f1dc09b7f86f71ade130db8cbb02**;
elfrun **da5209ae488403f3eb2a15af8bf0376df4844eefb46b9525c8a0834f8e3f4d5e**;
shared library **79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af**
(same library as Task136). Final source/build/test receipts and both arm binaries
remain remotely. The offline audit authenticates **1297 receipt files** and finds
zero unexplained instruction changes or remaining failures. Source revision metadata
was updated after the audit-script-only code-commit amendment; built inputs are unchanged.

## Retained attempts and practical limits

Initial control configure failed because the dependency copy was nested at the
wrong path; fixed before the successful configure/build. No test followed that
failed configure. The original failing current focused invocation reproduces
exactly 22 failures. Its printer's historical `ok` row prefix is diagnostic output,
not passing credit. An initial new protocol matcher forgot the existing epilogue
`trace_cache` call and indirect call; its focused/full attempts fail only the two
new protocol assertions. The matcher was corrected to include trace_cache and
resolve only direct numeric calls. Final successful checks use the corrected build.

An SSH disconnect occurred after the control metadata build wrote rc0 but before
its pin refresh completed; a subsequent identity gate rejected execution. A
successful bounded rebuild refreshed pins before the final control check. That
rejected launch ran zero tests. The collector initially checked the shared library
alone and encountered its executable-provided `dbt::Panic` symbol; the final loader
check properly covers elfrun and its library together. Both collector versions
are retained. None of these attempts changes the reported golden explanation or
receives final passing credit.

This task repairs the codegen oracle; it does not establish new fault/restart,
concurrency, backing-lifetime, grouped native memory, LLVM or gather guarantees.
Task135/136's limits remain. **Guest restart is NOT verified.** The golden still
uses historical objdump formatting and an FNV digest; external targets/range limits
now receive explicit checks for the affected memory rows, but this is not a claim
that every long immediate in every historical row has a symbolic oracle.

Commands are retained individually in `receipts/*/command.json`; representative
final commands are:

```sh
ssh xbd 'python3 /home/vick/rvdbt-goldens-task137/check_flag_off_task137.py control build-metadata'
ssh xbd 'python3 /home/vick/rvdbt-goldens-task137/check_flag_off_task137.py control final-dump'
ssh xbd 'python3 /home/vick/rvdbt-goldens-task137/check_flag_off_task137.py current build-metadata'
ssh xbd 'python3 /home/vick/rvdbt-goldens-task137/check_flag_off_task137.py current final-dump'
ssh xbd 'python3 /home/vick/rvdbt-goldens-task137/check_flag_off_task137.py current full-final2 rvv_vector_run_codegen_test'
ssh xbd 'python3 /home/vick/rvdbt-goldens-task137/check_flag_off_task137.py current memory-final rvv_vector_run_codegen_test --memory-boundaries'
ssh xbd 'python3 /home/vick/rvdbt-goldens-task137/check_flag_off_task137.py current admission-final rvv_vector_run_admission_test'
ssh xbd 'python3 /home/vick/rvdbt-goldens-task137/check_flag_off_task137.py current grouped-final rv32_grouped_memory_fault_test --normal-only'
ssh xbd 'python3 /home/vick/rvdbt-goldens-task137/check_flag_off_task137.py current scalar-final rv32_scalar_native_fault_test --normal-only'
ssh xbd 'python3 /home/vick/rvdbt-goldens-task137/check_flag_off_task137.py current whole-final rv32_whole_native_fault_test --normal-only'
python3 scripts/audit_flag_off_task137.py /home/user/research/materials/task137-goldens-raw-20261013 docs/rvv-validation/flag-off-task137/OFFLINE_AUDIT.json
```

[Receipt archive](docs/rvv-validation/flag-off-task137/receipts.tar.gz) SHA256:
**cbee552f2d484c974071cf37a068a79fe7d392d9b56b7401284aaa89bfc88e27**. Local extracted raw:
**/home/user/research/materials/task137-goldens-raw-20261013/**. Extraction reports
approximately 17s host-clock skew; every manifest byte authenticates. Python syntax
and `git diff --check` pass. No push, closure or direct message to main was sent;
the launcher owns completion signaling.
