# Task133 — restore owned whole-register QCG singleton SIMD

Continued **fcaaa80**, while main audits132. Implementation/test commit:
**eaf45ab**. Evidence is committed separately. No push or closure.

Restored the actual whole-register QCG singleton SIMD body by extending Task131's
exact finalized guest-access site, prior-state synchronization, publication and
emitted cold-exit contract. Checks remain in place. Grouped QCG and LLVM
whole-register native admission remain disabled; neither inherits singleton
ownership. No per-workload special case or ISA change.

## Contract and changes

The singleton producer annotates its instruction PC. QCG accepts that annotation
only for **one instruction**, independent of the number of architectural registers
transferred. Thus `vl8re*.v`/`vs8r.v` can be singleton instructions; a frame containing
multiple guest instructions is grouped and remains unowned.

The annotated frame invokes `native_memory_safe`, which validates encoded whole
load EEW8/16/32/64 or store EEW8, unmasked whole encoding, legal nregs1/2/4/8 and
register alignment/range, configured VLEN/vlenb and zero vstart. Transfer bytes are
`nregs*vlenb`; EVL and fault element positions use encoded EEW, **never** ordinary
VL, SEW, LMUL or vill. Runtime vtype/VL are neither admission preconditions nor
body inputs. Each guest chunk must fit on one anonymous-provenance page, have the
required permission, and remain within the nonwrapping guest address space.
Unsupported backing, active chunk crossing, nonzero start and other guard misses
select the existing checked helper before any SIMD access.

The body now publishes **each completed load chunk before the next guest access**,
including at register-slot boundaries. CPUState uses its fixed architectural
register slots; guest memory remains contiguous. Stores retain every required
source byte and earlier completed store. This changes the previous four-load
batch into one load/publication pair per chunk without replacing SIMD moves by
scalar normal-path copies. Typed operation count stays `2*chunks`.

Exact sites retain the actual SIMD width separately from encoded EEW. Registration
now accepts EEW1/2 as needed for whole transfers, while permitting K7 partial-mask
metadata only at the existing EEW4/8. The callback's ordinary partial-mask codec
is otherwise unchanged; no general mask/width rewrite was needed. Whole sites are
unmasked at every EEW, even when the actual move is `vmovdqu64`.

Task131 ownership still requires exact finalized RIP, owner/state/membase/register
identity, synchronous user data #PF, matching read/write error bit and fault address
within the page-contained access. SIGBUS, nonaccepted #PF bits, unrelated access
and publication/spill PCs remain unowned. Signal return enters the emitted cold
block, which supplies the terminal C++ stub, **not the guest MOV again**. The stub
reports `vstart=displacement/encoded_EEW`, encoded EEW and nregs in the event, then
uses the existing FP cleanup and dispatcher unwind. The shared-page reasoning is
the Task131 contract: the first active element of that denied page-contained chunk
is denied; no intra-chunk lane completion is inferred from si_addr.

An additional fallback hole was found: `whole_regbytes` previously selected an
inline scalar native loop after the shared guard rejected SIMD. That branch is
removed. Whole singleton misses call checked whole handlers through the terminal
stub's nonzero-raw arm; grouped misses call their original checked handlers in guest
order. Shared `special_memory_safe` continues to reject whole-register encodings
for grouped QCG and LLVM. No new stub, CPUState layout or AOT ABI change:
**a89957277993e0d9**.

## Actual isolated host512 build and bounded evidence

Actual root: **xbd:/home/vick/rvdbt-whole-native-task133/**.
Source: **source/**, fresh isolated build: **build/**. Dependencies/source inherited
from Task132, current changes overlaid; no use of its old build directory.
[Source equality](docs/rvv-validation/whole-native-task133/SOURCE_EQUALITY.json):
**296** production/build/test files equal eaf45ab, zero differences.
[Dependency equality](docs/rvv-validation/whole-native-task133/DEPENDENCY_EQUALITY.json):
**443** files equal Task132, zero differences.

Real AVX512F/BMI2, Clang22/LLVM22.1.6, Release,
**RVV_HOST_CHUNK_BITS=512**, actual **-mavx512f -mavx512bw**, force emission off.
[Flags/cache](docs/rvv-validation/whole-native-task133/FLAGS_AUDIT.json).
Configure and final builds exit0; `ldd -r` has no unresolved symbols.
Nice10, cores28–31, -j4; configure180s/build900s. Checks sequential on core28,
60s each, core dumps disabled; external adapter180s. Final observed load0.61/0.70/0.55.
No full suite or performance matrix.

Final [production identities](docs/rvv-validation/whole-native-task133/PRODUCTION_IDENTITY.json):

* elfrun: **baac2151f634adb34132f5166e998b98c28b51616a50d7c55bbc829988ae6c98**
* libdbtjitshared.so: **79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af**

| Check | Result |
|---|---|
| Initial whole singleton terminal invocation | exit0; 6,184 parent checks; 24 terminal cells |
| Additional distinct whole load terminal geometries | exit0; 1,773 parent checks; 6 terminal cells |
| Final normal-only whole check | exit0; 13,330 checks; zero faults |
| Existing Task131 ordinary emitted dispatcher regression | exit0; 6,142 checks; 40 one-time terminal cells |
| Existing LLVM executable admission | exit0; 292 checks; 16 cells; all whole native hit counters zero |
| Unchanged external whole-register originals | **3/3 PASS**, original whole-file DUT predicates |

Whole checks use actual production translation, RA, finalized runtime site
registration and `jitabi::trampoline_to_jit`; the actual JIT branch and cold exit
remain. An older allocated scalar `addi` must survive. The normal-only batch tests
**48 load geometries**: VLEN128/512/1024 × nregs1/2/4/8 × encoded EEW8/16/32/64.
Store normal state is checked in the terminal geometry cells for every VLEN/nregs.
All fixed CPUState vector-register bytes are compared, including unused bytes
beyond small guest VLEN slots. Normal prestart1 and prestart=EVL completion, tails,
required stores, vstart clearing, vill/VL0 and unchanged VL/type are checked.
An extra actual anonymous SIMD completion uses ordinary vtype24 and VL123,
independently of the whole EVL. A page-contained regular-file mapping executes the
real emitted checked fallback and transfers full EVL; anonymous replacement executes
SIMD, with actual fallback counters distinguishing both routes.

The grouped normal check emits a two-member load/store frame, deliberately adds
a singleton annotation, and asserts zero published sites, actual emitted guard
fallback and final bytes. QCG ignores annotation when n_members !=1. LLVM's separate
executable check retains its actual safe/helper calls, preceding SSA publication,
PC, full state and zero native hits. These do not claim grouped/LLVM fault ownership.

There are **30 distinct whole terminal geometries**:26 native and4 checked
crossing/nonzero-start. All produce one actual SEGV_ACCERR per fresh child. Coverage
includes small register slots, multiple chunks per register, register-boundary
prefixes, every nregs, every load EEW, first-page and later-page failure, vill/VL0,
required store prefixes and older FP/MXCSR cleanup. Raw host mprotect leaves MMU
metadata unchanged; callback delegates to production `dbt_sigaction_memory`, then
the emitted exit reaches the dispatcher checkpoint. Each child captures the full
snapshot and terminates. No guest delivery/frame/handler/return is executed.

Only original ACT B **Vls8-vl1re8.v, Vls8-vl1re64.v, Vls8-vs1r.v** ran externally.
[External audit](docs/rvv-validation/whole-native-task133/EXTERNAL_AUDIT.json)
authenticates exact original call objects/flags/predicate and input, source, ELF,
answer, checker and capture hashes before/after. Original files were never edited,
no guest recompilation or reference engine ran. Normal passes receive no fault credit.

[Offline audit](docs/rvv-validation/whole-native-task133/OFFLINE_AUDIT.json)
authenticates **620** receipt files, independently recomputes all32 fixed register
slots in every retained whole terminal snapshot, checks event/PC/GPR/frontier
coordinates, and decodes **48 actual emitted shapes**. Each load site is followed
by CPUState publication before the next guest load; each recorded cold block has
the actual terminal tail jump. Production callback disassembly has zero calls.
The audit executes zero guest instructions and finds zero differences. Earlier
memory prefixes are asserted by the executable fixture; they are not separately
persisted or independently recomputed in this offline audit.

## Attempts and remaining disabled paths

Two builds failed: initial incorrect `dbt::u32` qualification (fixed to global u32),
then a fixture `Inst*` needed a derived cast for the adversarial grouped annotation.
The second command mistakenly continued after its failed test-only rebuild. Its
stale binary ignored `--extra-terminal`, so it ran **24 additional fresh one-time
terminal children of the earlier geometries**. This batch is retained under
`focused/extra` and receives **no additional coverage credit**. Physical whole
fault count is54, distinct geometry count30; it is not represented as30 total
executions. No child repaired backing, returned from a guest handler, or reentered
its faulting instruction. The next command explicitly gated execution on build
success, compiled the requested modes and ran six new geometries. All original
rc/streams and snapshots remain in the archive.

Initial24 terminal cells preceded a registration-only refinement that excludes
K7 metadata for EEW1/2; their whole sites are unmasked. Final6 cells and ordinary40
cells use the refined production. Subsequent fixture refinements ran normal-only;
production files/binaries did not change. Extra normal attempts are retained
separately; final13,330 count belongs to the final normal-only invocation.

Remaining disabled/unowned boundaries:

* **Grouped QCG whole-register and LLVM whole-register SIMD:** disabled by shared
  special admission; they lack the singleton synchronization/site/publication/cold
  ABI. Their checked fallback remains available. A singleton transferring several
  architectural registers is supported and must not be confused with these frames.
* **Whole singleton unsupported backing, chunk crossing, wrapping spans, nonzero
  vstart, VLEN mismatch and existing translator exclusions:** checked fallback.
  Nonzero/prestart completion remains architectural, not a skipped transfer.
* **Native SIGBUS, machine-check/nonaccepted #PF, concurrent mapping/backing
  replacement and unrelated state/spill faults:** unowned. Anonymous provenance
  is neither residency pinning nor a concurrency/backing lifetime proof.
* **Other unowned native families/backends, live RA/pinned-state recovery and CCRF:**
  not extended here. Ordinary owned Task131 SIMD remains; its focused regression
  passes. No grouped ownership is inferred from checked helper ownership.

No guest handler return, repaired-mapping/same-PC retry, P4-04/equivalent, full suite,
performance campaign, push or closure occurred. **Guest restart is NOT verified.**

[Receipt archive](docs/rvv-validation/whole-native-task133/receipts.tar.gz): SHA256
**3fc7595f2ada143a555bcc77774eb214422423190bb3a6ede083354170814054**.
Local raw: **/home/user/research/materials/task133-whole-native-raw-20261013/**.
Remote isolated source/build/receipts remain at the root above. Local extraction
reported approximately8s remote-clock timestamp skew; all bytes are authenticated.
`git diff --check` passes.
