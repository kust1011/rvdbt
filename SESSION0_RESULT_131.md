# Task131 — ordinary QCG singleton fault-to-dispatcher path

Continued **38fea4d**, main reviews130, on `fix/rvv-memory-families-issue-1`.
Code/test commit: **bfbb2c9**. Evidence is committed separately. No push or issue closure.

**Implemented and exercised a usable terminal fault-to-dispatcher path.** Ordinary
unmasked QCG singleton `vle`/`vse`, EEW32/64, retain normal SIMD when every active
chunk fits within one page of ordinary RAM. An unexpected synchronous host data
page fault enters an emitted cold exit and reaches the existing dispatcher unwind
with prior state, PC, address, `vstart`, and FP cleanup established. A crossing
active chunk selects the existing checked element machinery before any native
body operation. Native SIGBUS and guest restart are not verified or claimed.

## Source-grounded contract and design decision

**Earlier-index restart is permitted for suitable idempotent operations; a missing
intra-chunk frontier alone does not prohibit every precise-trap design.** The
faulting element itself need not have committed before trapping. This does not
make arbitrary chunk-boundary trap reporting correct merely because memory is
ordinary or `si_addr` lies inside the chunk.

The pinned [RVV 1.0 exception section](https://github.com/riscvarchive/riscv-v-spec/blob/3570f998903f00352552b670f1f7b7334f0a144a/v-spec.adoc#exception-handling)
(lines4833–4879 of the authenticated local source) specifies instruction PC and
trap-element `vstart`, commitment of older instructions and elements before
`vstart`, and no newer architectural changes. Its fourth precise-trap requirement
allows suffix changes when restarting and completing yields correct final state.
The following paragraphs permit earlier-index restart for operations with
protected inputs, allow later store updates in idempotent memory, prohibit those
updates in non-idempotent memory, and require eventual progress for the reported
element/segment. Ordinary unit-stride operands here have no overwritten address
input or vector source. The vector memory addressing section (lines1450–1463)
also disclaims element access ordering; ascending host observations are not a
specification guarantee. [Pins and hashes](docs/rvv-validation/native-memory-task131/AUTHORITATIVE_SOURCES.json).

The [Intel SDM, 325462-089US, October2025](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf)
provides the other boundary: Vol3A §7.5 describes fault-class machine-state
restoration; §7.6 distinguishes restarting ordinary instructions from partial
REP execution. §5.6/§6.11 define page access rights. Interrupt14, pp7-44–7-46,
defines the error bits and CR2 fault address. Vol2B MOVDQU/VMOVDQU8/16/32/64,
pp4-66–4-72, plus Vol2A Table2-51 TypeE4.nb and Vol1 §15.6.1 specify these
moves and active-element fault suppression. They provide no guest completed-lane
counter. We do not infer SIMD memory atomicity, ordered element completion, or
accessible-prefix completion from CR2/Linux `si_addr`.

**Chosen inference/implementation contract:** for an ordinary user data #PF caused
by translation/permission denial, all active bytes of a page-contained chunk
share the denied page. Its first active element is therefore denied too. Reporting
that first element is coherent without committing an accessible intra-chunk prefix:
there is no separately accessible page within this access. Earlier chunks have
already completed and published. The callback uses `si_addr` only to validate the
owned access footprint; the guest event reports the first byte of the selected
first denied element, not a completion index computed from `si_addr`.

A generic cross-page chunk restart can be correct with suitable idempotence,
state and progress guarantees; it is **not architecturally forbidden**. But repeated
restarts may continually revisit an accessible prefix while the two pages cannot
be available together. The current runtime has no backing/residency pin or
adaptive smaller native retry ABI establishing progress for that design. We chose
the smaller conservative alternative: reject only active **chunk** crossings, then
execute the checked element helper from the original instruction state. An
instruction may still span pages and use SIMD when its chunk boundaries coincide
with page boundaries. Full VL remains SIMD. Partial VL checks only active bytes;
masked-off bytes may cross an inaccessible page and cause no access. Nonzero
`vstart` goes through the existing checked helper. No operation is silently skipped.

Memory-type admission is consumed by this guard: an always-maintained MMU bitset
records anonymous mappings and `fstat`-identified regular-file mappings, clears on
unmap, and follows fixed/replacement mappings. Device/unknown backing falls back.
This is the ordinary idempotent-memory contract, not an MMIO guarantee. It assumes
the runtime's serialized guest execution/mapping/code-pool lifecycle and normal
host page access semantics. It does not establish safety against another host
thread replacing backing or mutating mappings during an instruction. Eventual
progress assumes the denied page can ultimately be made available; persistent
permission denial need not complete. No page repair or progress experiment ran.

## Actual implementation and lifetime

* `rvv_native_fault.{h,cpp}` publishes immutable exact-PC entries using a lock-free
  atomic head. Initial-exec TLS holds the invocation's CPUState/membase, pending
  entry pointer and selected address with lock-free atomics/`sig_atomic_t` fields.
  The callback allocates nothing, queries no MMU/CPUState, performs no C++ unwind,
  calls no library routine, and interprets no XSAVE. Production disassembly
  independently contains **zero call instructions**, including no lazy TLS call.
* `ukernel.cpp` invokes this callback before its unrelated-host-fault diagnostic
  path. Ownership requires an exact finalized guest SIMD PC, matching saved R13,
  the admitted membase/32-bit RAX, active access footprint, synchronous SIGSEGV
  MAPERR/ACCERR, vector14, user data #PF and matching read/write bit. Reserved,
  instruction-fetch, PKU, shadow-stack/SGX/other error bits, SIGBUS, interior PCs,
  CPUState/spill/publication PCs and unrelated addresses stay unowned. A partial
  arm's saved EDX describes its contiguous K7 **active** mask, never completion.
* `tcache` registers entries after final code relocation/copy, before execution.
  Entries survive `RevokeTarget`, which does not free the code. Init, whole-pool
  Invalidate and Destroy detach/free them with physical code lifetime on the
  serialized host stack. The old unordered-map inspector remains normal-context
  only; the signal callback never calls it. Default/offline/AOT publication does
  not gain runtime signal ownership.
* QRA's actual `HAS_CALLS` begin synchronizes dirty architectural globals and
  spills call-clobbered locals before the branched body. Task130's interleaved
  guest-load/destination-publication order remains. Local VPRs in the faulting
  chunk are discarded, not reconstructed; all previous guest results are in
  CPUState/memory. QRA refuses region pinning when there are calls. The test checks
  **zero actual pins** even with pinning requested; those cells are not claimed as
  allocated-pin recovery coverage. The emitter also synchronizes declared pins
  before its guard, should that allocator constraint ever change.
* Each frame records its emitted `cold_offset`. Success and helper return jump
  over the cold block. Host signal return lands on that block, pops this nonleaf
  alignment slot, supplies state/zero raw, and **tail-jumps** to the C++ terminal
  stub with proper SysV stack alignment. The normal helper fallback uses the same
  stub's nonzero-raw arm, consuming a checked-path selector at handler entry,
  before validation/trap. Thus guard misses cannot secretly use unowned bulk
  `dispatch_load/store_unit_stride` copies. Existing handler/census scopes finish
  normally before their established trap exit.
* The terminal arm queues `MemoryFaultEvent::NativeUnit` through the existing
  uthread event interface, sets instruction PC and chunk-first `vstart`, then calls
  `FinishHelperMemoryFault`. This harvests/closes an older deferred FP bracket,
  restores MXCSR and invokes the established `RaiseTrap`/dispatcher checkpoint.
  The host callback never longjmps. The native event codec admits SIGSEGV only.
* Two appended runtime stubs intentionally change the embedded table/AOT ABI:
  CPUState42720, FP offset42296, signature **a89957277993e0d9**. Architectural
  GPR/vector/PC offsets stay fixed. Existing layout gates reject incompatible AOT.

## Actual isolated host512 verification

Fresh isolated build: **xbd:/home/vick/rvdbt-native-memory-task131/**. New build
folder, Task130 source/dependencies inherited then current production files
applied. [Source equality](docs/rvv-validation/native-memory-task131/SOURCE_EQUALITY.json):
**292** tracked production/build regular files equal bfbb2c9, zero differences.
[Dependency equality](docs/rvv-validation/native-memory-task131/DEPENDENCY_EQUALITY.json):
**443** third-party files equal Task130, zero differences. Actual Clang22/LLVM22.1.6,
Release, **RVV_HOST_CHUNK_BITS=512, -mavx512f -mavx512bw**; real AVX512F/BMI2,
force emission off. [Compiled flags/cache](docs/rvv-validation/native-memory-task131/FLAGS_AUDIT.json).

Configure/build exit0; `ldd -r` has no unresolved symbols. Final production hashes:

* elfrun: **1833610ed0f95733b6deb140c210fbc7dfbcafbe71010e570414e2533701be54**
* libdbtjitshared.so: **79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af**

The shared library's sole `jitabi_shared.cpp` input did not change; identical shared
hash is expected, while the actual new fault path is linked into elfrun/dbtstatic.
Final test-capture refinements did not change either production hash. Build used
nice10, cores28–31, -j4, configure180s/build900s. Focused checks ran sequentially on
core28 with60s bounds. Observed load0.18/0.48/0.57 initially,0.41/0.45/0.51 at the
recorded final sample. No full suite or performance campaign.

| Focused check | Actual final result |
|---|---|
| rv32_native_memory_fault_test | exit0; 6,142 parent checks; 40 terminal fault cells |
| rv32_native_memory_site_test | exit0; 2,801 checks; 8 exact-PC inspection cells |
| vle32v_typedchunk_route_test | exit0, PASS; prior publication/order checks retained |
| vse32v_typedchunk_route_test | exit0, PASS; its intentional invalid-state-offset child rejection remains in stderr |
| rv32_unit_memory_fault_test | exit0; 9,562 checks; 1,248 cells, no guest retry |
| Original ACT B Vls32-vle32.v | PASS, unchanged original whole-file predicate |
| Original ACT B Vls64-vle64.v | PASS, unchanged original whole-file predicate |
| Original ACT B Vls32-vse32.v | PASS, unchanged original whole-file predicate |

The new test retains the real JIT region's branch, uses actual RA/emission/runtime
site registration and **jitabi::trampoline_to_jit** for normal and fault execution.
Its fault exit is the production emitted block. The portable fixture's unused
appended return lies beyond the executed JIT branch path and supplies neither
normal exit nor fault exit. Each cell has a distinct
initialized normal invocation followed by a forked child. Raw host mprotect in
that child leaves MMU metadata/epoch unchanged. Its callback delegates to the
production `dbt_sigaction_memory`; signal return executes the real emitted cold
block. The dispatcher `sigsetjmp` checkpoint then inspects/captures state and
terminates the child. It does not call guest signal delivery, a guest handler,
handler return, or the guest operation again.

32 native cells cover load/store × EEW32/64 × full/partial VL × first/second chunk
fault × pinning requested/off. Eight additional aligned crossing cells take the
checked fallback before SIMD and retain the exact completed prefix. All take
exactly one actual **SEGV_ACCERR**. MAPERR is accepted by the implementation but
not actual-fault tested; BUS is an explicit rejection, not BUS native coverage.
Checks include complete destination/tail, earlier stored memory, older allocated
`addi`, PC/event geometry, VL/vstart, a deliberately open FP bracket and restored
MXCSR. Another normal execution demonstrates partial VL with the nominal chunk
crossing a raw host-inaccessible page only in masked-off lanes.

[Offline audit](docs/rvv-validation/native-memory-task131/OFFLINE_AUDIT.json)
authenticates **314** receipt files and independently decodes **8 JIT shapes,
24 exact guest sites/cold blocks**. It checks all40 full terminal snapshots, all512
bytes of the destination slot, earlier memory, event/PC/GPR6/VL/vstart coordinates,
and the production callback's lack of calls. It runs zero guest instructions.

The unchanged Task130 adapter selected exactly the same three original ACT B
calls/flags/predicate and authenticated original source/ELF/checker/answer/capture.
[External audit](docs/rvv-validation/native-memory-task131/EXTERNAL_AUDIT.json)
checks unchanged inputs and final executable/library identity. The three calls
were rerun after the final production address/ownership refinement; both normal
attempts are retained. No upstream answers, sources or checkers changed and no
reference engine ran. Normal external passes receive no fault/restart credit.

## Evidence, attempts and remaining boundary

[Receipt archive](docs/rvv-validation/native-memory-task131/receipts.tar.gz): SHA256
**6b28f74fb7d5e4b469954a4f94743dd1b5e094c5683075224c53e5c843028028**.
Raw: **/home/user/research/materials/task131-native-memory-raw-20261013/**.
Remote isolated source/build/raw/external directories remain available. Archive
includes all build/check attempts, final CPU/compiler/cache/flags, source/dependency
identities, emitted code/site records,40 full dispatcher snapshots with layout,
completed memory bytes, callback disassembly and original external receipts.

One initial build failed because appending stubs moved the checked ABI layout;
the intentionally changed sizes/offsets were updated and rebuilt. Two initial
**normal harness** executions failed: first, an appended portable return followed
JIT literal-pool data; second, default trace-cache instrumentation inspected the
unmapped synthetic next guest PC. The final JIT fixture retains the actual branch
and disables trace inspection of that synthetic next PC. These failed attempts
preceded the successful terminal native-fault checks; neither was a repaired
fault/retry, and their rc134/streams remain. Subsequent builds/checks followed
actual production or evidence-capture changes, not a hidden guest retry. Preliminary
checks before capture retention are preserved separately. Local extraction emitted
future-timestamp notices because the remote clock was about17s ahead; the complete
manifest independently authenticates every byte. `git diff --check` passes.

There is **no remaining implementation blocker for the owned, page-contained
ordinary user data #PF path**. Broader native recovery remains incomplete:

* Ordinary SIMD **SIGBUS/backing or machine-check faults** do not establish that
  the first active element on a page is denied. Their exact completion/reporting
  contract needs a separate proof/ABI or pre-access selection of checked copies.
  The current host SIMD receipt and MMU permission census do not supply it; such
  faults remain unowned. No backing-lifetime/concurrent-mapping guarantee was added.
* Scalar-native unit loops, multi-member memory runs, LLVM-native memory, gathers,
  strided/indexed/segment memory, mask memory, whole-register SIMD and permitted
  helper bulk copies retain their separate existing boundaries. They receive no
  ownership from this singleton table. Existing checked helper/FOF machinery is
  distinct; this task does not turn those families into native recovered paths.
* CCRF recovery and guest signal continuation are separate. **Restart is NOT
  verified**: no guest handler return, repaired mapping/same-PC retry, P4-04 or
  equivalent ran. Source-grounded progress reasoning is not execution evidence.
