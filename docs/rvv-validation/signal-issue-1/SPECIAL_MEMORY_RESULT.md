# Task118: precise mask and whole-register permission faults (Refs #1)

Implemented on current branch `fix/rvv-memory-families-issue-1`, parent
`ba817f6966a61b2e0071c5a2389cc35246d7d6af`. Task117 was not amended.
No push, issue closure, whole-suite/performance campaign, P4-04 or equivalent
repair/return/same-PC retry execution. Launcher owns completion signaling.

## Contract and routes

Read repository guidance (no applicable source AGENTS found), thesis artifact
AGENTS/status/active plan, the historical FAULT_CONTRACT, current Tasks113–117
contract, handlers, translator and both backends before implementation.
[RVV 1.0](https://github.com/riscvarchive/riscv-v-spec/blob/v1.0/v-spec.adoc)
§7.5 defines mask EVL=ceil(VL/8), EEW8 and byte vstart; §7.9 defines whole-register
EVL=NREG*VLEN/EEW independent of VL/vtype, aligned groups of1/2/4/8 registers,
and encoded-load-EEW/store-byte vstart. §3.4.4 permits whole-register memory
operations under vill; mask operations retain the existing vtype legality check.
Mask load tails remain undisturbed, a permitted tail-agnostic choice.

`SpecialMemory` passes the opcode's EVL and EEW to the existing
`rvv_ref::unit_stride_checked` → `memory_checked` loop. Each complete element is
permission-checked before copying; denial preserves original VL/type/PC,
absolute effective-element vstart and completed prefix. Split/wrapped denied
loads do not change any bytes of that element. Normal completion clears vstart.
`QueueOrdinaryMemoryFault` reuses value-only event creation and normal helper
return → FinishHelperMemoryFault → dispatcher capture: actual PC/raw, first
denied byte, access/reason, effective element, EEW, field0 and NREG as NF
(1 for masks). No new unwind or signal-frame implementation.

| Native route | Permission admission |
|---|---|
| QCG mask `vmemorynative` mode3 | New special-memory stub before typed-frame body |
| QCG whole `vmemorynative` mode4 | Same gate, independent of VL/vtype/vill |
| QCG Native-2 whole chunk groups, including materialized run bodies | Per-member typed-frame gate; existing shape/base guards remain |
| LLVM typed frames | Same special-memory conjunct before fast branch |
| LLVM vector-SSA `rvvload`/`rvvstore` | Separate `RvvWholeRegMemGuard` now calls the special stub; original vlenb/vstart/base guard remains |
| Whole helper fixed-copy dispatch | Existing sized-copy retained only after complete live admission |
| Experimental CCRF component images | Existing certificate checks now probe every declared read object before live execution/snapshot creation; existing write/private/epoch checks retained |

Run begin nodes now borrow the existing arena-owned member list; admission visits
every memory member, including those after arithmetic and with distinct bases.
The run scanner already cuts writes to a GPR before its use as a memory base.
The ordinary gates and SIMD bodies remain enabled. Special admission checks live
VLEN, zero vstart and a nonwrapping complete permitted range; nonzero vstart or
unsafe permissions select the precise helper. LLVM/QCG HAS_CALLS publication and
existing vector-SSA commits remain authoritative. CCRF is a certified fault-free
mode: an invalid permission certificate is rejected before component execution,
not converted into an architectural memory event. Reordered-component precise
fault delivery remains unimplemented. Its read predicate is exercised locally;
no CCRF campaign is claimed.

One appended runtime stub preserves earlier stub indices but moves fpu42272→42280
and CPUStateImpl42688→42704. CPUState stays42704; architectural gpr/ip/vec/trap
positions remain fixed. ABI changes b04553e010cbb4e9→ce212ddc4742de49. A local
shared-library fixture checks the production AOT gate rejects the old signature
and admits the current one; stale unchecked caches cannot survive this gate.

## Bounded build and evidence

Fresh xbd root `/home/vick/rvdbt-special-memory-20261012-task118`; initial load
0.21/0.22/0.29, later pre-build0.18/0.32/0.34. Two workers, cores28/29, nice10.
All443 copied dependency files hash-match Task117; old roots/results untouched.

```sh
cd /home/vick/rvdbt-special-memory-20261012-task118
cmake -S source -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=/usr/bin/clang-22 -DCMAKE_CXX_COMPILER=/usr/bin/clang++-22 \
  -DLLVM_PATH=/usr/lib/llvm-22 -DRVV_HOST_CHUNK_BITS=128 \
  -DRVDBT_FP_CONTRACT_OFF=ON -DRVDBT_FROUND_IMPL=2 -DRVDBT_HOST_FMA=OFF \
  -DRVDBT_FAST_STATS=ON -DRVDBT_CENSUS=ON
nice -n 10 taskset -c 28,29 cmake --build build --parallel 2 --target \
  elfrun rv32_special_memory_fault_test rv32_unit_memory_fault_test \
  rvv_llvm_wholereg_mem_test rvv_whole_reg_mem_route_test
clang-22 -shared -fPIC abi-old.c -o abi-old.so
clang-22 -shared -fPIC abi-new.c -o abi-new.so
ulimit -c 0
LD_LIBRARY_PATH=build/lib timeout 120 nice -n 10 taskset -c 28 \
  build/bin/rv32_special_memory_fault_test ./abi-old.so ./abi-new.so
# Run each of the other three host tests sequentially with the same prefix.
python3 normal_replay.py
python3 collect.py
```

Final local raw:

```text
ACTUAL_QCG_COMBINED native_hits=2 native_fallbacks=2 cells=4
ACTUAL_QCG_SPECIAL native_hits=12 native_fallbacks=108 cells=120
LOCAL_SPECIAL_MEMORY_PASS checks=254652 cells=26290 ABI=ce212ddc4742de49 impl=42704 state=42704 fpu=42280 (no guest retry)
AOT_ABI_REJECT task118 reason=mismatch artifact=b04553e010cbb4e9 build=ce212ddc4742de49
LOCAL_UNIT_MEMORY_PASS checks=9562 cells=1248 ABI=ce212ddc4742de49 (no guest retry)
rvv_llvm_wholereg_mem_test: PASS (0 failures)
rvv_whole_reg_mem_route_test: PASSED
```

Local special checks cover VLEN128–4096, all whole group sizes/load widths, mask
VL boundaries, nonzero/huge vstart, original VL0 and nonzero VL, vill, register
legality, load/store/read-only/write-only/unmapped permissions, whole register
boundaries, denied split elements and RV32 wrap. Full vector/memory prefixes,
tails and fault snapshots are checked. Actual QCG counters above come from six
single-instruction frames plus an arithmetic-first, two-base load/store frame;
its denied load/store checks preserve earlier arithmetic, prior load state and
the actual faulting member PC. LLVM evidence checks the special-stub call feeds the admission
branch, not executed LLVM optimized code.

Unchanged original Ara `vle1`(VLEN1024), `vse1`(2048), `vl1r`/`vs1r`(1024), each
B/M1/M2/BOTH:16 calls PASS,212 original assertions,35060 comparisons. Replay uses
existing SELECTED commands, original observations function/expected construction,
ELFs and sources; changes only executable/fs/cache paths. Original sequence,
completion, equality, PASSED/no-FAILED/no-ERROR predicates retained. No external
source/checker/expected-value repair or compilation. Aggregate external
RVV_DIRECT hits/fallbacks per arm:8/0,10/0,51/21,15/6 respectively. These counters
are not target-specific admission counts; whole-case helper census attributes
fallbacks to vmv.v.i. External normal assertions do not validate faults/restart.

Final elfrun SHA256 `533443050f4d1ad4dc49ca74f3e5ac4ca1ccc576f2b107d3771412a218ac3e31`.
All binary/source/dependency/fixture identities, commands, exact expected
observations and raw outputs are in `task118-evidence/` under the existing thesis
`artifacts/rvv_validation_delivery_20261009` directory. Remote root retains full
source archive and binaries. `SPECIAL_MEMORY_RESULTS.json` is a concise receipt.

Preserved failures:build-attempt1 caught an incorrect expected CPUState size
(42720 vs actual42704); attempt2 caught a misspelled test-only AOT API. First local
special run aborted on test-generated active-SEW1 chunk nodes: whole chunks must
use their existing full-transfer active-SEW0 form. A combined-route build also caught that begin nodes did not yet carry the
end node’s member list; the borrowed run-members field closes that gap.
Corrected harness and all final checks pass; no external oracle was changed. Earlier logs/results remain.

Remaining obligations:unexpected host SIGSEGV/SIGBUS and concurrent mapping
changes after admission; complete guest handler/return/restart; precise faults
inside reordered CCRF; scalar integer/FP/atomic guest-memory routes and host
syscall-buffer accesses outside these vector permission gates. Existing FOF
absolute-element-zero/later-element trim contract remains separate. No external
fault oracle, executed LLVM fault path, measured guard cost or full-suite result
is claimed for this binary. Issue#1 remains open; next work is review of this
increment and source-based closure of the remaining routes, within the blocked
retry restriction.
