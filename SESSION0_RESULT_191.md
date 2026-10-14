# Task191 — production build and bounded exception-fix integration

Completed from `cef9967` in the exception worktree. **Actual production build and
bounded integration PASS:** 50 accepted invocations, including 24 original
external indexed-load calls and 16 normal-sequence calls/68 packet checks.
Task189's fixture-only build is not relabelled as production acceptance. This
result supplies a new production identity and finite integration evidence; it
is not a new full595 acceptance or complete exception-conformance claim.

## Production identity and preservation

Built `elfrun`, `dbtstatic`, `dbtjitshared` and seven relevant test targets in the
updated isolated186 tree, `xbd:/home/vick/rvdbt-exception-task186`. The actual
`cmake --build ... -j2 --target ...` exits0; its exact target list, raw build log,
cache, compile flags and link command are retained in the archive's
`administrative/`. Tests were gated on build exit0 and matching source hashes.
Existing Release/Clang22.1.6, host chunk512, XLEN32/ELEN64 configuration remains;
AVX2/AVX512F/BMI2 are actual host capabilities, not forced runtime admission.
The unchanged shared-library bytes legitimately retain their prior identity.

| Artifact | SHA256 |
|---|---|
| `build/bin/elfrun` | `37a25624345214d97e3691cfd9f951166abfe92419ce2bbeca9c786b68227c14` |
| `build/lib/libdbtstatic.a` | `242afe91e6c537abd1c2e742a8a3269429d65b4b5d79ddd7731f03b1755df76c` |
| `build/lib/libdbtjitshared.so` | `79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af` |

[Manifest](docs/rvv-validation/integration-task191/MANIFEST.json) verifies298
source files and all tested binary hashes before/after. Compared with `cef9967`,
only the grouped **test** changes: seven added lines. No new production defect
was confirmed and no production edit was made. Runtime/translation cost delta
from189 is zero. Task189's anonymous-backing admission and NativeUnit formatter
fix are the production changes being integrated.

[Preservation](docs/rvv-validation/integration-task191/PRESERVATION.json) checks53
local179 receipt/report/script files byte-for-byte against `cef9967`. Frozen179
executable/library before/after hashes remain
`8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281` /
`79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af`.
Nothing was written into179's source/build/receipt namespaces. Task190's separate
immutable179 inexact-reduction work has no source conflict and is not counted
among191's results.

## Executed bounded results

| Invocation | Result |
|---|---|
| MMU mapping metadata lifecycle | PASS27/27 |
| RVV semantic/geometry contract | PASS, zero failures |
| vector-run codegen contract | ALL CHECKS PASSED |
| optional gather detailed fixture | PASS896 parent checks;17 normal/8 terminal cells |
| native unit terminal fixture | PASS6,142 parent checks;40 terminal cells |
| scalar-memory terminal fixture | PASS2,029 parent checks;44 terminal cells |
| grouped `--normal-only` | PASS585 parent checks |
| grouped `--terminal` | PASS103 parent checks;10 terminal cells |
| ACT: original `Vls32-vluxei32.v`, `Vls32-vloxei32.v` | 16 calls PASS: B/M1/M2/BOTH × gather0/1 |
| CHIPS: original `vluxei32_v-{0,1}`, `vloxei32_v-{0,1}` | 8 calls PASS: original BOTH × gather0/1 |
| retained177 integer alias, nonzero-start boundary, FP chain, cache reuse | 16 calls/68 packet checks PASS: B/M1/M2/BOTH |
| new anonymous mmap integration guest | 2 calls PASS: gather0/1 |

Parent assertion counters exclude checks performed inside fork children; they
are neither distinct ISA-case counts nor summed dynamic assertion counts.

External ELFs, source/checker/oracle identities and original signature/CHIPS
predicates are preserved. Execution options retain original arms; gather0/1 and
statistics are explicit diagnostic additions, with relocated FS/cache paths.
No reference guest or external guest rebuild occurred. ACT source inspection
finds94 unordered and102 ordered target instructions with equal `vd==vs2`;
these original aliases are executed as part of the unchanged whole files.
[Selection](docs/rvv-validation/integration-task191/SELECTION.json) records exact
calls, hashes and alias source lines. No claim that the original guest checker
observes every vector/scalar byte is added.

Counters distinguish request from execution. Every gather-off external run has
all four gather counters zero. Each enabled unordered ACT arm reports
`attempts=164 calls=0 elems=0 unmapped=163`: backing/shape refusal plus checked
fallback, not enabled fast-path acceptance. Ordered ACT and the selected CHIPS
cells have no optional-gather attempts. These zeros are retained, not presented
as proof of gather execution.

The new freestanding guest obtains anonymous memory via the supported mmap
syscall, initializes independent scalar values, executes distinct and overlapping
indexed loads, then unit-load/add/store operations. Scalar checks independently
verify both reversed gather results and the doubled unit-memory result. On the
actual production executable gather-off reports all-zero gather counters;
gather-on reports **`attempts=1 calls=1 elems=16 unmapped=0`**. The distinct
indexed load can use the existing QCG scalar-memory route; the overlapping load
fails that route's disjointness preflight (`rv32_interp.cpp:643–653`) and reaches
optional gather. Both runs report `inline_hits=9`, with zero helper calls for
`vle32.v`, `vse32.v`, `vadd.vv`. The offline audit asserts these counts; unrelated
anonymous SIMD remains enabled. The detailed optional fixture separately proves
five actual anonymous gather admissions, file-backed normal fallback before
publication, owned SIGBUS EOF fallback, alias preservation, misalignment/splits,
permission/mprotect/munmap/MAP_FIXED replacement and address-wrap boundaries.

The four retained normal units use original177 ELFs and retained independent
reference packets, without new reference execution. Their original full-state
and legal-tail predicates check prestate, complete defined vector state, CSRs
and saved scalars. This includes nonzero vstart and process-local cache reuse,
not a fault-return/retry experiment. [Sequence selection](docs/rvv-validation/integration-task191/SEQUENCE_SELECTION.json)
records exact cases and ELF/reference hashes.

## Terminal observations: reuse and narrow strengthening

The earlier187/188 weakness concerns external denial adjudication; it does
**not** establish that all detailed terminal fixtures lack memory/scalar checks.
Existing native fixture lines51–70 checks precise PC/vstart/event, older x6,
full destination, committed store bytes and retains snapshot/memory. Existing
scalar-loop fixture lines99–120 checks earlier element/field memory publication,
PC/event, older x6 and snapshots. Existing grouped fixture checks a separately
computed prefix/prior-member vector image, full accessible memory page against
an independent expected page, and blocks later overlapping commits.

Reused those fixtures. The narrow remaining assertion gap was explicit saved
scalar-array/no-unrelated-GPR-clobber coverage in the grouped terminal fixture.
It now seeds unrelated x11/x12/x28/x31, derives the scalar expectation before
execution (only the earlier `addi x6,x0,0x123` may change it), and checks **all32
saved and live GPRs** in each of10 terminal children. Existing full-vector and
independent expected-memory assertions remain unchanged. The offline audit
also compares all10 retained actual/expected memory pages. No new observer,
terminal repair, or repeated faulting instruction was necessary.

The added assertion checks explicit `Access::Load/Store` and
`Reason::HostFault`, alongside the existing exact NativeUnit/PC/raw/address/
element/EEW/NF/SIGSEGV event. These are access faults, not address-translation
page faults: if expressed in architectural synchronous-cause terminology,
load/store access fault is5/7, not page-fault13/15. This user-mode fixture does
not produce or assert an architectural numeric `mcause`. Existing189 tests
also check exact quoted NativeUnit/HostCopy/PredictedHelper origin formatting.

## Failures retained and resources

No accepted ISA failure was hidden. Two controller refusals occur before a new
guest: original ACT flags already included statistics, invalidating an overly
strict duplicate-option assertion; and the isolated186 source copy did not
contain Python sequence tools. The corrected controller normalizes the two
diagnostic options; matching repository tools were copied to a separate test
tool directory. Successful fixture and sequence invocations were not repeated.

The first new anonymous guest accidentally enabled compressed instructions
(`rv32gcv`); production reports ILLEGAL_INSN before its vector target. Its
failed build/run material remains under `anonymous-attempt1`. The corrected
`rv32gv` guest passes gather-off. Its first enabled run reached one actual
gather but the harness incorrectly expected two; original stdout/stderr and
traceback remain under `anonymous-on-expected2-attempt1` and administrative logs.
The source-grounded corrected expectation is exactly one; only that enabled
cell was repeated. The receipt writer raised before serializing those failed
anonymous checks, so their numeric return codes lack normal execution.json
receipts; they receive zero acceptance credit. There are50 accepted commands
and two additional unaccepted anonymous guest attempts. Raw logs and both guest
build commands are retained; no production failure was inferred from either
harness error.

Own production compilation uses `-j2`; the two tiny guest builds are serial.
Tests execute sequentially, including terminal children, peak one executing
fixture/guest. All accepted commands assert nice10, no affinity changes, and
10GiB available reserve. Minimum recorded test endpoint availability is
22,277,525,504 bytes (20.748GiB). Initial production-build df reports21GiB free;
its shell explicitly applies nice10. Test endpoint/process receipts and build
command/log evidence are not continuous machine-wide resource monitoring.
Earlier valid nice19 correctness evidence was not rerun for label normalization.

[Offline audit](docs/rvv-validation/integration-task191/audit191.py) independently
joins all50 per-call execution records, stdout/stderr hashes, identities,
counters and grouped memory pages. [Summary](docs/rvv-validation/integration-task191/SUMMARY.json).
[Raw receipts](docs/rvv-validation/integration-task191/raw-receipts.tar.gz),
7,195,869 bytes, SHA256
`55a2c5533dde136c9a9316e551cdb730abb8788983ccb17d0a7e1a1bf386a374`,
match the retained remote archive. Runtime binaries remain in isolated186.

## Exact remaining obligations and limits

**Mandatory behavior, still unverified:**187-01/P4-04 guest-handler return,
mapping repair, same-PC retry/equivalent resumed execution and eventual forward
progress remain service-blocked, NOT EXECUTED / NOT VERIFIED. Finite terminal
PC/vstart/prefix tests and independently initialized nonzero-start runs do not
prove this composition, including preservation of older FP flags and prevention
of newer commits. No repair/return/retry equivalent was launched.

**Conditional platform/configuration obligations:** interrupts/debug events
were not injected; device/non-idempotent access history and cross-hart RVWMO
claims need separate evidence if such environments are advertised. Optional
gather now has bounded terminal and production integration evidence under the
existing anonymous-mapping model; concurrent host mapping mutation,
resource-exhaustion host faults and new devices remain outside that model.
No general Linux/platform, LLVM or host-width expansion is claimed.

**Test-evidence gaps, distinct from confirmed ISA bugs:** the original592
external/directed denial controls still use the weak nonzero/text predicate
identified in187-03; they are failure controls, not precise fault-state proofs.
Their old records/predicates are unchanged. Future precise-denial adjudication
must join exact target PC/raw/access reason/vstart and observable state; the
new detailed fixture checks do not retroactively supply missing observations
for every original external denial. No whole595/new-common-build replay or
performance matrix was launched. Current191 acceptance is limited to the
selected tests/configuration; it adds no per-form inventory credit.

187-08's bounded inexact unordered-reduction category is separately addressed
by Session3 Task190 on immutable179: its report records360 cases/1,440 DUT
checks with independent tree-aware arithmetic predicates. That finite evidence
is not rerun or recredited here, and does not establish arbitrary-tree/all-format
FP conformance on191. XLEN32's32 ei64-index exclusions, legal partial-segment
commit discretion and FOF trim discretion remain legal choices, not new gaps.
No new mandatory mnemonic/configuration family was found in this integration.

Owned source/test/evidence/report are committed locally, without push, email or
thesis changes. Launcher `run191.sh` owns EXIT signals
`rvv-fault-integration-191` and `rvv-review-parallel-20261013`.
