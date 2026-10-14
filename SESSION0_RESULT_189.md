# Task189 — optional gather backing admission and fault-origin fix

Implemented in the exception worktree from `ad16d47`. The enabled
`--rvv-gather=1` file-backing fault hole is closed within the existing MMU mapping
model. Default remains off; prior default-off evidence is not invalidated.
No thesis/publication, external replay, performance matrix or new platform scope.
Session3's independent source finding is accepted; no subagent was launched.

## Implementation and ownership

`mmu::RangeReadableAnonymous` is the shared range admission: reject a host span
crossing 2^32, then require read permission and the existing
`native_copy_ram_pages` bit on every covered page. `MarkOrdinaryRam` already sets
that bit only for `MAP_ANONYMOUS` on both mmap paths. mmap replacement updates it,
munmap clears it, and mprotect updates permission without inventing backing facts.
Regular files (private or shared) remain ordinary/idempotent but do not receive
this anonymous bit. Optional detailed metadata is unnecessary; no new bitset,
backing stat call, mapping bookkeeping or mapping-epoch work was introduced.

`rv32_vector_gather.cpp` replaces its permission-only range preflight with this
predicate. Min/max merely bounds the range; neither it nor `range_readable`
proves no host faults. File/unknown backing, denied permission and unsuitable
signed gather offsets refuse before any destination publication. The existing
caller in `rv32_interp.cpp:869–876` then executes `OrdinaryMemory`, whose
`rvv_ref::memory_checked` publishes vstart before each element and calls the
owned `rvv_host_copy::Copy` leaf. Copy stages a complete load before modifying its
vector destination; its exact PC/address/direction/width signal boundary owns
SIGBUS/SIGSEGV. `QueueOrdinaryMemoryFault` records HostCopy or PredictedHelper;
the existing terminal dispatcher captures live state. The gather has **no fault
ownership**, and no recovery was added to it. `ukernel.cpp` checks native/copy
owners before generic termination; the former gather's unowned SIGBUS would
reach that generic path.

This admission relies on the existing mapping model: mapped anonymous RAM is
available while the instruction executes; mapping syscalls update the MMU facts
between instructions. It adds no guarantee for concurrent host mapping mutation,
resource-exhaustion faults, MMIO or new devices. Guest brk, ELF/BSS/stack and mmap
paths use the MMU; mremap allocates anonymous memory through it. File size checks
would not guarantee against later truncation, so no such substitute is used.

The existing shape gate still excludes nonzero vstart, masks, ordered accesses,
other EEWs and non-M1 data. Equal-EEW `vd==vs2` remains eligible on safe anonymous
RAM: each eight-element chunk snapshots its own indices before writing exactly
those elements, never future indices. Refusal leaves all indices intact; checked
fallback's faulting/later indices remain intact even after its earlier alias
loads. Unaligned anonymous loads and page splits remain eligible if both pages
qualify. Base+index RV32 addition may wrap to a valid low address; the sign-range
guard rejects high gather addresses, and element spans crossing 2^32 use checked
fallback. No blanket memory-SIMD disablement or change to other native routes.

`WriteMemoryFaultSnapshot` now formats `NativeUnit` as `NativeUnit`. The focused
fixture asserts exact quoted origin values for all three enums; the existing
native dispatcher fixture additionally asserts the formatter's exact origin from
actual terminal NativeUnit/HostCopy snapshots. Source ownership is retained.

## Focused results

Reused `xbd:/home/vick/rvdbt-exception-task186` incrementally after archiving the
prior touched source and recording the old native executable hash. Original
production gather/ukernel hashes match `ad16d47`. The new fixture was built against
that original production before changing admission. Its original mode installs
a diagnostic terminal signal observer, writes a small receipt, then `_exit`s;
it never invokes generic termination or returns to the original faulting gather.
Ownership absence is established by the production source, not by pretending
that this observer is a production recovery path.

| Executed command (under `build/bin/`) | Exit | Reported checks | Cells |
|---|---:|---:|---:|
| `rv32_optional_gather_fault_test --original` | 0 | 43 | 2 original terminal witnesses |
| `rv32_optional_gather_fault_test` | 0 | 896 | 17 normal, 8 terminal |
| `rv32_native_memory_fault_test` | 0 | 6,142 | 40 terminal plus existing normal invocations |

Original witnesses, both alias and distinct registers: actual gather calls=1,
SIGBUS=7/BUS_ADRERR=2 at `0x24001000`, first eight elements already committed,
`vstart=0`, and the next chunk unchanged. In the alias witness those earlier
values have replaced their original indices. This is expected detection of the
original production defect, not original correctness acceptance.

Fixed normal cells cover anonymous/file backing × alias/distinct × starts0/3/16,
plus anonymous misalignment, anonymous page split, ordered and masked shape
fallbacks, and wrapped base+index addition into low anonymous RAM. **Five** cells
actually take the gather, including alias and alignment/wrap cases. File cells
at start0 attempt gather but calls=0; starts3/16, ordered and masked forms do not
attempt it. The oracle uses seeded bytes/indices independently of the DUT,
checks prestart/suffix values, full destination including tail, other registers,
PC and completion. Edge checks additionally cover permission changes, munmap,
anonymous→file MAP_FIXED replacement, a mixed anonymous/file split span,
high signed offsets, empty VL, and refusal without alias mutation.

Fixed terminal cells: alias/distinct × first/later EOF fault (four), alias
start3→fault8, alias split-element EOF fault, alias later PROT_NONE denial and
alias address-wrap denial. All have calls=0. Six capture exactly one real
SIGBUS via the existing owned copy exit; two deny before host access. Every
terminal child checks the exact PC/raw/address/element/EEW/NF/origin, VL/vstart,
full committed-prefix and fault/suffix/index register state, and retains the
formatted snapshot. Misaligned split loads publish no partial vector element.
The start3 case is independently initialized; it is not an original-fault retry.

Reported parent check counts exclude increments in fork children. Native's
6,142 count consequently does not increase despite adding three formatter checks
in each of its40 children. No oracle relaxation or result relabelling.

Guest-handler return, mapping repair, same-PC retry/equivalents and resumed
forward progress remain **NOT EXECUTED / NOT VERIFIED**, including the existing
service-blocked obligation. Owned leaf redirection to its failure exit is the
existing terminal fault capture, not repair/retry of the guest instruction.

## Identity, failures and resources

[Manifest](docs/rvv-validation/gather-task189/MANIFEST.json) verifies298 local/remote
source file hashes, Clang22.1.6 and actual CPU. Existing Release configuration
remains host chunk512 with AVX512F/BW, XLEN32 and ELEN64; optional gather's TU
remains compiled with `-mavx2`. Actual AVX2 and native AVX512F/BMI2 are required by
the fixtures; no capability forcing. Cache/flags are retained in isolated186 and
the earlier186 artifact set, with the current cache hash in this manifest.

Fresh executable SHA256 identities:

- Original optional fixture: `55368d89ade8cd2f9f325ca58e573942c3fe5fb31508bfc5e45b26dfab5ff98e`
- Fixed optional fixture: `72c4353b8de096aaf03e54b513558b773cfe4c8499e2f2cb878a3b4a75eb5af3`
- Fixed native fixture: `9da69dc7dd193255c49ae9f2ab6feb659bf41102fd62e1b475b1e364e4817903`

The runner requires build exit0 and a changed executable hash before each tested
target. Two failed build attempts are preserved: unregistered new CMake target
(`original/build.log`, exit2), then a `std::min` u32/size_t type mismatch
(`fixed-built/build.log`, exit2). No tests followed either failure. Reconfigure
registered the fixture; an explicit u32 page-mask cast corrected the compile
failure. Two successful incremental build invocations produced original and
fixed tested identities. All retained outcomes are in
[raw-receipts.tar.gz](docs/rvv-validation/gather-task189/raw-receipts.tar.gz), including
failed logs, successful logs, stdout/stderr, binary terminal snapshots,
per-invocation commands/hashes/resources and the prior source snapshot. The
original executable itself is retained remotely under
`task189/original-built/original-executable` with its recorded hash. The current
fixture's later additions affect only its fixed mode; original mode reproduces
the same baseline witness when built against the original source.

Compilation used `-j2`; tests ran sequentially, one fixture child at a time
(well below8 workers), nice10, no affinity or global machine changes. Runner
asserts nice10 and a10GiB disk reserve; recorded minimum endpoint availability
was20.7957GiB. These are endpoint resource receipts, not continuous machine-wide
measurements. The first registration failure executed no compilation; CMake
regeneration was configuration only. Prior Task186's nice19 results retain their
semantic validity; Task189 ran no pass solely to adjust nice and used nice10 for
its subsequent compilation/tests.

## Source-grounded cost delta

Default-off runtime work is unchanged: the unchanged `config::rvv_gather` branch
short-circuits before any gather call, range scan or fallback admission. No
metadata maintenance or emitted QCG instructions were changed. New compiled
helper text exists, and fault JSON formatting adds a NativeUnit comparison only
when formatting a snapshot.

Enabled eligible operations keep the original O(VL) index min/max pre-scan and
range page walk. The new out-of-line shared predicate adds a function call,
nonwrapping-span comparison and one anonymous-backing bit test per readable
covered page. Existing read-permission checks remain. Sparse min/max gaps are
conservatively checked as before; file/unknown pages in a gap can refuse even if
no active lane touches them. No claim of measured cycles or throughput.

Enabled refused operations can pay the original pre-scan plus an early backing
refusal, then the existing checked element loop: address selection, vstart
publication, permission query, owned copy arming/staging and per-element call
cost (misaligned copies decompose into bytes). That cost now applies to regular
files, including currently fully backed ones, in exchange for correct SIGBUS
ownership and prefix state. No new per-element work was added to the eligible
anonymous gather body; default-off and other SIMD admission are unchanged.

Launcher `run189.sh` owns EXIT completion signals `rvv-gather-fix-189` and
`rvv-review-parallel-20261013`; this session leaves signalling to that launcher.
