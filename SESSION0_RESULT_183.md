# SESSION0_RESULT_183

Completed in `/tmp/rvv-delivery-task182`, branch `delivery/rvv-entry-task182`,
based on requested `74d8bb4`. Read182 report/entry/README and original155 dirty
source plus accepted159 snapshots. No worker tree edits, production changes,
full-suite rerun, dependency install/download, reference rebuild, publication or
email. Task181 remains the sole full queue owner; no181 acceptance is imported.

Selection now persists compact half-open accepted ranges for all102 entries
inside the frozen index. Each range expansion verifies the original selector
SHA256. Commands/smokes search later accepted entries when the first lacks the
requested configuration, never select rejected/reserved rows, and refuse a
unit with even one excluded row. Missing retained entries are reported on
failure.595 forms and3,017,262 accepted rows remain unchanged; historical mixed
builds, all failures, masks, Task179 identity and oracle restrictions remain
separate. The selection-plan hash still pins the original181 frozen input.
Five small local and clean-stage test methods cover malformed ranges/hashes,
invalid CLI values, rejected first-row selection, later-entry search, explicit
entry/config rejection, mixed accepted/rejected units and missing length data.
All102 range expansions match the original plan exactly.

Exact finalized `fixedpoint155.py`, `scaling155_next.py`, `narrowing155_next.py`
were imported from original155 dirty files only after byte comparison with
accepted159 snapshots. Provenance and hashes are in
`docs/rvv-validation/delivery-task182/INTEGRATION183.json`; this does not invent
an owner source commit. Shared `vadd.py`/`audit.py` are preserved. A new delivery
adapter integrates retained fixed-point/averaging packets with the current
shared dispatcher. It does not claim universal assembly/generator integration.
Older173/176 tool bundles remain archival, separate from default integration.
No181 launcher/queue module was imported or overwritten.

`rvv_verify.py preflight|export` reads verified originals once and exports only
one complete accepted unit: manifest/build subset, assembly/ELF, chosen DUT
command, successful Reference execution/checks/packets and pinned source/data.
It writes a compact derived index with original manifest/selector provenance;
source historical row marginal dimensions/counts remain identifiable and the
package's explicit unit count is in `EXPORT.json`/`export_provenance`. This is
an external input export recipe, not binary dependency redistribution in Git.

Fresh stage `xbd:/tmp/rvv-delivery-reproduce183` was extracted from a Git archive
of74d8bb4, overlaid only with owned183 delivery source/index files. It contains
no dirty155 checkout dependency. Actual compact export:

```sh
cd /tmp/rvv-delivery-reproduce183
DUT=/home/vick/rvdbt-host512-task179-build/build/bin/elfrun
LIB=/home/vick/rvdbt-host512-task179-build/build/lib/libdbtjitshared.so
REF=/home/vick/rvv-directed-task145/deps
nice -n 10 python3 scripts/rvv_verify.py preflight --form vsmul.vv \
  --unit vsmul-w128-e8-mf8-vv-zero --raw-root /home/vick \
  --output /home/vick/rvv-task183-vsmul-package
nice -n 10 python3 scripts/rvv_verify.py export --form vsmul.vv \
  --unit vsmul-w128-e8-mf8-vv-zero --raw-root /home/vick \
  --output /home/vick/rvv-task183-vsmul-package
PKG=/home/vick/rvv-task183-vsmul-package
nice -n 10 python3 scripts/rvv_verify.py smoke --form vsmul.vv \
  --unit vsmul-w128-e8-mf8-vv-zero --index "$PKG/index.json.gz" \
  --raw-root "$PKG/raw" --dut "$DUT" --output /home/vick/rvv-task183-vsmul
```

Default checkout adapter PASS:124 cases, one179 B DUT call, zero new references
or ELF builds. Package logical payload1,471,956 bytes (1.6MiB physical staging),
including exact snapshot source/data, not the huge original corpus. Smoke
successfully used only that package's relocated raw root and the installed DUT.
It catches non-vadd import/CSR/predicate/data integration issues. Receipts and
source/checker/output identities are committed under `delivery-task182/task183`.

`rvv_reproduce.py preflight|run` supplies the executable fresh ordinary vadd
path using existing `vadd.build`, `execute`, ISA and reference checker APIs;
it generates only `w128-e32-m1-vv-zero`,17 existing cases. Actual commands:

```sh
python3 scripts/rvv_reproduce.py preflight --compiler /usr/bin/clang-22 \
  --spike "$REF/spike" --pk "$REF/pk" --dut "$DUT" --dut-lib "$LIB" \
  --output /home/vick/rvv-task183-new-vadd
nice -n 10 python3 scripts/rvv_reproduce.py run --compiler /usr/bin/clang-22 \
  --spike "$REF/spike" --pk "$REF/pk" --dut "$DUT" --dut-lib "$LIB" \
  --output /home/vick/rvv-task183-new-vadd-final --admission-timeout 30
```

Final PASS: one ELF build, one pinned Spike/pk call and one179 B call,17 checked
cases; reference/output hashes both
`ffd45d308763827e7310e40fa842b0fde9b00373d8c493298c5400f33c0bc918`.
Compiler is installed Clang22, SHA256
`271764e9b47729e011b19740b79022842f1158dcfea1ff29336968738c909551`,
separately recorded from historical Clang20. No same historical ELF claim.
Linker input, Spike/pk and179 DUT/library hashes are checked; source revisions
for Spike/pk come from existing `sources.lock.json`. All roots, compiler,
linker script, runtime library paths and bounded timeouts are configurable.
No raw145 manifest/ELF/reference is required by this fresh path; only installed
pinned reference executables and the checkout's existing source/flags/link input.

Two earlier attempts remain disclosed in `task183/ATTEMPTS.json`: predicate
slot refusal (zero build/guest calls) and caller Path/string serialization error
after one successful compilation (zero guest calls). The corrected caller
passes the compiler string expected by the existing build API. Failed output
directories remain untouched. Task183 totals: two compiler invocations, two DUT
calls/141 DUT cases, one reference call/17 cases. No full family was rerun.

Both bounded paths acquire Task181 predicate slots and shared admission lock,
nice10 and inherited affinity; conservative shared guest/offline capacity and
10GiB reserve remain enforced. Fresh build also checks shared build limit4,
own build1. Final resource census saw two other guests and Task181's reserved
two predicate slots; actual predicate lock ownership prevents overbooking its
cross-controller slots. Capacity refusal is explicit; fresh slot wait is bounded
0..60 seconds, default30. There is no wait for181's full queue completion.

Other-family preflight commands (zero guests/builds/references) succeeded:

```sh
nice -n 10 python3 scripts/rvv_verify.py preflight --form vnclip.wv \
  --sew 8 --lmul mf8 --vlen 128 --vstart 0 --raw-root /home/vick \
  --output /home/vick/rvv-task183-narrow-preflight
nice -n 10 python3 scripts/rvv_verify.py preflight --form vfsqrt.v \
  --sew 32 --lmul m1 --vlen 128 --vstart 0 --raw-root /home/vick \
  --output /home/vick/rvv-task183-fpunary-preflight
```

Selected narrowing unit224 cases/2,522,732 logical bytes; FP-unary unit610
cases/6,634,570 bytes. These source/input preflights are not runtime acceptance
or default-adapter coverage, and exceed bounded smoke's128-case limit. Their
pinned snapshots/data can be exported using the identical selected-unit recipe;
use existing family APIs for larger units. General regenerate is not exposed
for those families: accepted snapshots differ in dispatch/assembly APIs and
adjacent JSON/spec dependencies. Missing default adapters/source data must not
be called fully portable or all-form reproduction. The reviewer README now
explains exact required retained packages, prerequisite/source pins and these
integration gaps. Original external readers remain separate; no new external
ISA experiments or upstream-suite credit.

Remaining gaps: owner-reviewed155/181 integration/receipts, larger/family-specific
regeneration and main-owned thesis/author/reply delivery. No semantic scope is
broadened: arbitrary inexact unordered reductions, reserved/source-illegal rows,
ACT blockers, Ara TEST_CASE3/4 failures, general restart/handler return/mapping
repair/same-PC retry/P4-04 and optimization admission restrictions stay intact.

Owned changes are committed locally. Completion signals after commit:
`rvv-delivery-reproduce-20261014-183` and `rvv-review-parallel-20261013`.
