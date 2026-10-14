# Task190 — bounded inexact unordered FP reductions

**Closed concrete187's missing bounded arithmetic category on immutable179:** 360 new cases, **1,440 DUT checks PASS** (360 each B/M1/M2/BOTH), **360 pinned Spike checks PASS**, zero failures or reference disagreements. All 1,800 retained packets were independently rechecked offline; 360 ELF targets and input blocks match their declarations. **17 local checker tests PASS; 1,080 corruptions of retained DUT packets rejected.** No production change or new ISA defect was found. This is finite implementation-tree evidence, not unrestricted FP conformance or closure of all RVV obligations.

Started from `7be3009` in the obligations worktree, after reading current thesis execution/plan state, actual reduction/rounding source and the official frozen specification. Only Task190 code/evidence/report are committed; no shared thesis edits, push or email. No guest fault, handler return, repair or same-PC retry was executed. Task189's optional gather admission/diagnostic changes do not enter this arithmetic evidence.

## Frozen implementation and permitted tree

Executable: `xbd:/home/vick/rvdbt-host512-task179-build/build/bin/elfrun`, SHA256 **8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281**. Library **79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af**. Before/after identities match. The original179 build manifest is retained at [BUILD_MANIFEST_179.json](docs/rvv-validation/directed-task181/BUILD_MANIFEST_179.json): RV32GCV, ELEN64, host chunk512, Release clang22, FP contraction off, host FMA disabled, FROUND_IMPL2. New guest VLEN is128/1024. No production rebuild occurs.

Selected source hashes match the immutable179 source snapshot exactly:

| Source | SHA256 | Read positions |
|---|---|---|
| `dbt/guest/rv32_vector_lower.h` | `2eb495e945cd2c5a012edd80d3c3c14e7ee9e19fc0fbf80b82454ab19c93baf4` |2264–2390,3214–3249|
| `dbt/guest/rv32_fpu.h` | `4c239aa194e681eb644cd5060593ba68375c6a937e5238c85bac09b91c57601c` |171–183,353–420|
| `dbt/config.h` | `b084ee39bc64c49ec347510702ef8aaa4efb522c433f1ae252a41e6dc889353e` |4211|

`vfred` starts with the SEW-width bits of `vs1[0]`, loops e=0 through VL−1, skips masked lanes, and adds at FP32/FP64 width. `vfwred` reads the FP64 seed, promotes each active FP32 operand exactly, and adds at FP64 width. Both store only the scalar result. The default `rvv_fred_specialize=0` uses the general loop; optional specialization branches also preserve order but are not enabled here. RNE/RTZ/RDN/RUP use the host rounding bracket; RMM uses the exact soft path. Flags are accumulated through `fs.raise`/`FRound.finish`.

Controlling source: [RVV V1.0, revision3570f998903f00352552b670f1f7b7334f0a144a](https://github.com/riscvarchive/riscv-v-spec/blob/3570f998903f00352552b670f1f7b7334f0a144a/v-spec.adoc), sections14,14.3.1–14.3.2 and14.4, retained [lines3826–4027](docs/rvv-validation/directed-task174/v-spec.adoc). A fresh official download equals the retained file, SHA256 `bfe42bd33dc6abeef5362f475605dda3d229e722257a613b0691cee760f04a19`.

The selected tree is a binary left comb. Every active input appears once, and each internal node rounds at destination precision/range using dynamic frm. Inactive branches copy the accumulator; root conversion to the same format is exact. It uses no optional final identity. This deterministic source tree satisfies the permitted unordered-tree contract; the specification explicitly permits ordered sum as an unordered implementation. Widening uses promoted inputs and a double-width accumulator. VL0 leaves the complete destination unchanged; VL>0 with no active lanes copies the seed in this selected implementation.

## Independent arithmetic and ISA distinction

[Inexact190](scripts/rvv/directed/inexact190.py) uses existing [fp157.py](scripts/rvv/directed/fp157.py) exact `Fraction` decoding, addition and rounding/flag utilities (45–115), plus Task174 operand/promotion and full-state packet checks. It does not call DUT arithmetic, harvest DUT goldens or replace the old exact/tree-invariant Task174 admission predicate. The tree topology comes from the production source; the numeric evaluation comes from independent rational rounding. Each recorded step includes operand, promoted word, exact rational sum, rounded word, newly raised flags and sticky union.

The implementation-specific predicate requires that particular sequential result and flags. A mismatch is a selected-tree regression; tree difference alone does not establish an ISA defect. The separate ISA witness evaluator enumerates binary trees over all labeled active leaves plus the seed, using minimum permitted destination-width nodes, with and without the optional final identity. Each admitted result has a constructive tree witness. It is a **sufficient legal subset**, not a complete oracle over arbitrary larger node formats. Nonmembership is UNVERIFIED and receives no PASS credit; it is not an ISA-defect verdict. Structural/preservation failures remain failures. No arbitrary Spike bit-equality check is imposed.

Example: FP32/RNE seed0, inputs `[2^24,1,-2^24]` gives selected words/flags `(0x4b800000,0)`, `(0x4b800000,NX)`, `(0,NX sticky)`. The middle exact sum is16777217. A permitted reassociation produces `(1.0,flags0)`. The corruption suite explicitly accepts that alternate through the ISA witness predicate while rejecting it through the selected-tree predicate. Equivalent FP64/FP32→FP64 cancellation uses2^53.

[EXPECTED.json.gz](docs/rvv-validation/inexact-task190/prepared/EXPECTED.json.gz) and the manifest were written **before guest compilation/execution**. The offline audit recomputes them and binds ELF setup/target bytes and full observed prestate; recorded expectations are never repinned to results.

## Manifest and results

[Declaration](docs/rvv-validation/inexact-task190/prepared/DECLARATION.json): six units, 60 cases/unit, **30 guest commands** (six Spike,24 DUT), two compiler slots, one sequential guest slot. The 12 templates × five frm × two configurations produce:

| Form/profile | Cases | DUT checks | Spike checks | Newly raised per-case flags:0 / NX / OF+NX |
|---|---:|---:|---:|---:|
|vfredusum FP32|120|480|120|30 /70 /20|
|vfredusum FP64|120|480|120|30 /70 /20|
|vfwredusum FP32→FP64|120|480|120|20 /96 /4|
|Total|360|1,440|360|80 /236 /44|

Configurations are VLEN128/LMUL2 and VLEN1024/LMUL1; sources v16, seed v24 and destination v8. Cases use VL0/2/3/4, unmasked/all-on/all-off/alternating masks, tu/mu and ta/ma, poisoned masked or beyond-VL lanes, and sticky flags0/2/3/4/8/9/16/31. The manifest supplies every exact input word and state value. Twelve named templates cover cancellation after loss, even/odd halfway seeds, positive/negative overflow, subnormal cancellation, all-sticky flags, two-active masking, partial length with poisoned tail, all-masked, zero-length and all-on two-active addition.250 cases newly raise NX with at least two active operands and no initially set NX.

**UF reachability:** every finite same-format operand is an integer multiple of that format's minimum subnormal. A finite tiny exact sum remains representable; addition therefore cannot newly raise UF in this selected tree. FP32 promotion to FP64 is exact and preserves the FP64 lattice. We test exact subnormal behavior and sticky UF preservation, rather than invent an inexact-underflow addition. OF is reachable in both same-width profiles. Widening OF occurs in RUP for positive max-FP64 seed plus max-FP32, and RDN for the negative counterpart; all other widening modes still exercise NX. Across840 active additions:508 exact,288 NX and44 OF+NX; new UF0.

[Audit](docs/rvv-validation/inexact-task190/AUDIT.json) checks complete packet extents/order, all ten CSRs and scalar operand, scalar FP preservation, all vector registers outside the scalar destination, allowed tail behavior, VL0 whole-state preservation, the independently recomputed step trace's final result/flag union, source/data/ELF identities and exact command-arm binding. Flags and fcsr corruptions are changed coherently so consistency checks alone cannot reject them. [Audited observations](docs/rvv-validation/inexact-task190/AUDITED_RESULTS.json.gz) record the actual unchanged destination for VL0; the original runner's VL0 arithmetic tuple is a seed placeholder, not an observed written result.

Spike/pk are the original family harness references: hashes `cddd7a406bd92836f220e929aca0f4925542e80d0b2246b8920e6f49648a6994` / `30f4e5906b13264ff98a8fa36dfea848f8504a65c028e96930329668f1f564ad`. Read the retained [Task174 reference source review](docs/rvv-validation/directed-task174/REFERENCE_SOURCE_REVIEW.json), `spike-vfredusum_vs.h`, `spike-vfwredusum_vs.h`, and `spike-v_ext_macros.h:1518–1526,1659–1688,1709–1717`: these use the same sequential order and widened addition. That source review is pinned to20feb9c2; actual execution is bound to retained binary hashes, without claiming a new source-to-binary reconstruction. **Observed agreement360/360; disagreement0.** Every reference packet independently satisfies a permitted-tree witness and full-state checks.104 cases have additional certified legal outcomes in [ALTERNATIVES.json.gz](docs/rvv-validation/inexact-task190/ALTERNATIVES.json.gz). Neither agreement nor the witness subset excludes other legal trees.

## Validation, preservation and reproduction

[17 tests](docs/rvv-validation/inexact-task190/TESTS.txt) cover analytical step constants, all360 synthetic states, legal alternate trees, bad destinations/flags/frm, preservation/tails/scalar FP, prestate, packet order/extent, sticky loss, zero-length, masked poison, exit and timeout rejection. Offline controls alter the original B packet in memory for each case: destination, other register and coherent fflags/fcsr. **1,080/1,080 rejected**, originals untouched. No corrupted guest is executed.

Resource gates recorded31 samples, nice10 throughout, minimum available RAM34.709GiB and free disk20.738GiB. Guest execution is sequential1 (≤4); compilation executor2 (≤2); no affinity is assigned. The10GiB reserve is gated before compilation and each guest command. These are sampled gates and structural own-worker limits, not continuous shared-host occupancy proof. Requested method switches are retained in [FLAGS.json](docs/rvv-validation/inexact-task190/FLAGS.json); no per-target native admission is inferred from enabling switches or from packet PASS.

Retained raw: `xbd:/home/vick/rvv-inexact-task190`; verified local archive: `/home/user/research/materials/task190-inexact-raw-20261014/rvv-inexact-task190-retained.tar.gz`. [RETENTION.json](docs/rvv-validation/inexact-task190/RETENTION.json) gives archive identity. Sources, guests, commands, compressed stdout/stderr, execution receipts, tbmaps and original executed runner remain available. Only new ELF materializations were removed after execution; their permanent compressed originals remain. No historical raw traversal or suite regeneration occurred.

The original executed runner is retained as `EXECUTED_INEXACT190.py`. After execution, the one reference nonmembership label was clarified from FAIL to UNVERIFIED, preserving the identical acceptance predicate and every observed PASS. The final auditor independently checks all original receipts; no guest was repeated. [SOURCE_SPEC_DATA.json](docs/rvv-validation/inexact-task190/SOURCE_SPEC_DATA.json) records executed/final code identities and reviewed source positions.

Reproduce local checker tests with `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/rvv/directed -p test_inexact190.py -v`. On xbd, in a **fresh** output namespace, invoke `inexact190.py prepare NEW`, copy the retained FLAGS.json into NEW, then use `RVV_COMPRESS=1 nice -n10 python3 .../inexact190.py build NEW` and `... run NEW`. Dependencies and immutable binary paths remain those in the retained snapshot. Offline only: `RVV_COMPRESS=1 nice -n10 python3 tools/audit_inexact190.py /home/vick/rvv-inexact-task190`.

Task181's original595 forms/12,071,304 positives and592 denial controls remain unchanged; Task190's1,440 DUT checks are additive, separately identified evidence for the missing category. General arbitrary-tree/format FP conformance, other geometries, native reduction admission and recovery obligations remain outside this bounded result. The launcher EXIT trap owns requested `rvv-fpreduce-inexact-190` and `rvv-review-parallel-20261013` completion signals after the owned commit.
