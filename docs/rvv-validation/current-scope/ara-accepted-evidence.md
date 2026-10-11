# Accepted Ara evidence integration (Task90)

Ara checked forms: 301 → 422; added 121; removed 0.

Exact additions: `vand.vx`, `vasub.vv`, `vasubu.vv`, `vfadd.vf`, `vfadd.vv`, `vfclass.v`, `vfcvt.f.x.v`, `vfcvt.f.xu.v`, `vfcvt.rtz.x.f.v`, `vfcvt.rtz.xu.f.v`, `vfcvt.x.f.v`, `vfcvt.xu.f.v`, `vfdiv.vf`, `vfdiv.vv`, `vfmacc.vf`, `vfmacc.vv`, `vfmadd.vf`, `vfmadd.vv`, `vfmax.vf`, `vfmax.vv`, `vfmerge.vfm`, `vfmin.vf`, `vfmin.vv`, `vfmsac.vf`, `vfmsac.vv`, `vfmsub.vf`, `vfmsub.vv`, `vfmul.vf`, `vfmul.vv`, `vfmv.v.f`, `vfncvt.f.f.w`, `vfncvt.f.x.w`, `vfncvt.f.xu.w`, `vfncvt.rod.f.f.w`, `vfnmacc.vf`, `vfnmacc.vv`, `vfnmadd.vf`, `vfnmadd.vv`, `vfnmsac.vf`, `vfnmsac.vv`, `vfnmsub.vf`, `vfnmsub.vv`, `vfrdiv.vf`, `vfrec7.v`, `vfredmax.vs`, `vfredmin.vs`, `vfredosum.vs`, `vfredusum.vs`, `vfrsqrt7.v`, `vfrsub.vf`, `vfsgnj.vf`, `vfsgnj.vv`, `vfsgnjn.vf`, `vfsgnjn.vv`, `vfsgnjx.vf`, `vfsgnjx.vv`, `vfslide1down.vf`, `vfslide1up.vf`, `vfsqrt.v`, `vfsub.vf`, `vfsub.vv`, `vfwadd.vf`, `vfwadd.vv`, `vfwadd.wf`, `vfwcvt.f.f.v`, `vfwcvt.rtz.x.f.v`, `vfwcvt.rtz.xu.f.v`, `vfwcvt.x.f.v`, `vfwcvt.xu.f.v`, `vfwmacc.vf`, `vfwmacc.vv`, `vfwmsac.vf`, `vfwmsac.vv`, `vfwmul.vf`, `vfwmul.vv`, `vfwnmacc.vf`, `vfwnmacc.vv`, `vfwnmsac.vf`, `vfwnmsac.vv`, `vfwredosum.vs`, `vfwredusum.vs`, `vfwsub.vf`, `vfwsub.vv`, `vfwsub.wf`, `vfwsub.wv`, `vmacc.vv`, `vmacc.vx`, `vmadc.vx`, `vmadc.vxm`, `vmadd.vv`, `vmadd.vx`, `vmerge.vxm`, `vmfeq.vf`, `vmfeq.vv`, `vmfge.vf`, `vmfgt.vf`, `vmfle.vf`, `vmfle.vv`, `vmflt.vf`, `vmflt.vv`, `vmfne.vf`, `vmfne.vv`, `vmseq.vx`, `vmsne.vx`, `vmul.vx`, `vmulh.vx`, `vmulhsu.vx`, `vmulhu.vx`, `vmv.s.x`, `vmv.v.x`, `vmv.x.s`, `vnmsac.vv`, `vnmsac.vx`, `vnmsub.vv`, `vnmsub.vx`, `vor.vx`, `vssseg2e8.v`, `vsuxei16.v`, `vsuxei32.v`, `vsuxei8.v`, `vxor.vx`

Frozen source set 424; version87 derived source set 425. Frozen inventory is unchanged.

293 extracted FP blocks: 291 all-five PASS; two reserved source-EEW-overlap failures. The 16 old RTZ-omitted blocks / 80 receipts remain invalid-context history.

No mixed FP16 whole-file PASS
Legacy adapters are explicit derivatives
MAC TEST_CASE3/4 failures retained
Zero multi-member-M1 admission
Form union is not configuration completeness
Masked FP source blocks may overread two-byte mask objects; no access-suppression proof
Extracted original predicates, not whole-file passes
Inherited short-object loads and prior checker-buffer contents remain
No multi-member M1 credit; M2 per-target admission unobserved
RVV_FAST counts rvv_fast::g_fast, not the M2 active-VL bounds
Reserved and incompatible source blocks excluded, not repaired

Bindings and content identities are in compact-input.json → ara_evidence. Accepted Ara raw/source inspection is packaged in [Task91 review bundle](../ara-review-task91/README.md); its BINDINGS.json supplies package-relative navigation. Historical absolute paths remain provenance. Canonical full-suite archives remain separate.

| Suite | Checked forms /595 | Endpoint forms /595 | Source-case rows | Registered DUT receipts | Registered reference receipts | Ledger rows |
|---|---:|---:|---:|---:|---:|---:|
| ACT | 590 | 0 | 4074 | 8336 | 3859 | 33898 |
| Ara | 422 | 0 | 1057 | 947 | 166 | 2255 |
| CHIPS | 595 | 0 | 5321 | 23204 | 60 | 29765 |
| CTK | 0 | 0 | 0 | 0 | 0 | 2 |
| FORCE-RISCV | 0 | 0 | 1 | 0 | 0 | 34 |
| QEMU | 0 | 0 | 28 | 1 | 2 | 163 |
| RVISmith | 0 | 43 | 46 | 292 | 117 | 2366 |
| RVV-ATG | 434 | 0 | 365 | 736 | 2 | 1747 |
| RVVTS | 0 | 58 | 664 | 2310 | 301 | 4102 |
| RiESCUE | 0 | 0 | 1 | 0 | 0 | 11 |
| SiFive RIF | 200 | 125 | 4086 | 8604 | 1370 | 22324 |
| Tenstorrent | 0 | 0 | 1056 | 0 | 0 | 1058 |
| libriscv | 0 | 198 | 22 | 80 | 38 | 654 |
| rv32emu | 0 | 0 | 3 | 8 | 3 | 736 |

| Task | Recorded new DUT calls | Recorded new reference calls | Audit denominator |
|---|---:|---:|---|
| 82 | 9 | 0 | three original full files |
| 83 | 16 | 4 | 20 |
| 84 | 120 | 30 | 30 |
| 85 | 1052 | 263 | 263 |
| 86 | 64 | 16 | 16 |
| 89 | 156 | 47 | three original full files |

Task83 denominator: 20 function obligations / six files; eight functions executed in four derivative programs. Tasks84/85/86: extracted blocks. Task85 includes invalid-context history; Task86 repairs 16 blocks. Task82 reuses six B/Spike receipts. Task85 also retains separate 8 DUT/2 Spike reproductions.

| Suite | Status unit | Denominator | Exact recorded status counts |
|---|---|---:|---|
| ACT | original ledger rows (all row kinds) | 33898 | {"BLOCKED": 15417, "N/A": 289, "NOT_RUN": 4, "PASS": 14110, "REFERENCE_ERROR": 4, "SEE_OUTPUT": 1919, "UNKNOWN": 2155} |
| Ara | original ledger rows (all row kinds) | 2255 | {"BLOCKED": 112, "BUILD_ERROR": 20, "N/A": 276, "NOT_RUN": 464, "PASS": 1331, "REFERENCE_ERROR": 3, "RESULT_MISMATCH": 49} |
| CHIPS | original ledger rows (all row kinds) | 29765 | {"BLOCKED": 43, "N/A": 126, "NOT_RUN": 2886, "PASS": 26104, "SEE_OUTPUT": 597, "UNKNOWN": 9} |
| CTK | original ledger rows (all row kinds) | 2 | {"BLOCKED": 1, "N/A": 1} |
| FORCE-RISCV | original ledger rows (all row kinds) | 34 | {"BLOCKED": 34} |
| QEMU | original ledger rows (all row kinds) | 163 | {"BLOCKED": 123, "N/A": 2, "PASS": 20, "RESULT_MISMATCH": 18} |
| RVISmith | original ledger rows (all row kinds) | 2366 | {"BLOCKED": 1491, "NOT_RUN": 580, "PASS": 295} |
| RVV-ATG | original ledger rows (all row kinds) | 1747 | {"BLOCKED": 466, "NOT_RUN": 357, "PASS": 922, "REFERENCE_ERROR": 2} |
| RVVTS | original ledger rows (all row kinds) | 4102 | {"BLOCKED": 108, "BUILD_ERROR": 9, "N/A": 32, "NOT_RUN": 113, "PASS": 2541, "PRIOR_DISPOSITION": 6, "PRIOR_JOIN_PASS": 195, "PRIOR_SOURCE_BLOCKER": 65, "REFERENCE_ERROR": 30, "RESULT_MISMATCH": 56, "SEE_FINITE_OUTPUTS": 595, "UNKNOWN": 352} |
| RiESCUE | original ledger rows (all row kinds) | 11 | {"BLOCKED": 11} |
| SiFive RIF | original ledger rows (all row kinds) | 22324 | {"BLOCKED": 5387, "BLOCKED_SHARED_PLATFORM": 1978, "BUILD_ERROR": 939, "NOT_RUN": 2623, "OPTIONAL_EXTENSION_UNSUPPORTED": 100, "PASS": 11167, "PLATFORM_ERROR": 2, "RV32_INDEX_EEW64_NA": 128} |
| Tenstorrent | original ledger rows (all row kinds) | 1058 | {"BLOCKED": 1, "N/A": 1057} |
| libriscv | original ledger rows (all row kinds) | 654 | {"BLOCKED": 504, "BUILD_ERROR": 2, "PASS": 132, "REFERENCE_ERROR": 4, "RESULT_MISMATCH": 12} |
| rv32emu | original ledger rows (all row kinds) | 736 | {"BLOCKED": 15, "MATCHED": 2, "NOT_REACHED_FIRST_ASSERTION_FAILURE": 301, "NOT_RUN": 396, "ORIGINAL_EXPECTED_MISMATCH": 1, "PASS": 7, "REFERENCE_ERROR": 3, "RESULT_MISMATCH": 11} |

Upstream suite case denominators are UNKNOWN. Source-case/receipt/status rows are different units. Overlay bindings are scoped acceptance records, not new call totals.

| Source-only relative to old accepted set | Finite disposition | Source status | Remaining source obligation |
|---|---|---|---|
| vand.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vfadd.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfadd.vv | ACCEPTED_SCOPED | {"N/A": 17} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfclass.v | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfcvt.f.x.v | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfcvt.f.xu.v | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfcvt.rtz.x.f.v | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfcvt.rtz.xu.f.v | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfcvt.x.f.v | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfcvt.xu.f.v | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfdiv.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfdiv.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmacc.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmacc.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmadd.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmadd.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmax.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmax.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmerge.vfm | ACCEPTED_SCOPED | {"N/A": 3} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmin.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmin.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmsac.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmsac.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmsub.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmsub.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmul.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmul.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfmv.v.f | ACCEPTED_SCOPED | {"N/A": 3} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfncvt.f.f.w | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfncvt.f.x.w | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfncvt.f.xu.w | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfncvt.rod.f.f.w | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfnmacc.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfnmacc.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfnmadd.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfnmadd.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfnmsac.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfnmsac.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfnmsub.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfnmsub.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfrdiv.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfrec7.v | ACCEPTED_SCOPED | {"N/A": 9} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfredmax.vs | ACCEPTED_SCOPED | {"BLOCKED": 4, "N/A": 13} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vfredmin.vs | ACCEPTED_SCOPED | {"BLOCKED": 4, "N/A": 13} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vfredosum.vs | ACCEPTED_SCOPED | {"BLOCKED": 4, "N/A": 13} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vfredusum.vs | ACCEPTED_SCOPED | {"BLOCKED": 4, "N/A": 13} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vfrsqrt7.v | ACCEPTED_SCOPED | {"N/A": 5} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfrsub.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfsgnj.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfsgnj.vv | ACCEPTED_SCOPED | {"N/A": 9} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfsgnjn.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfsgnjn.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfsgnjx.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfsgnjx.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfslide1down.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfslide1up.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfsqrt.v | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfsub.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfsub.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwadd.vf | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwadd.vv | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwadd.wf | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwadd.wv | SOURCE_BLOCKED | {"N/A": 4} | SEW16 requires optional FP16; Reserved: wide v2-v3 EEW64 source overlaps narrow v3 EEW32 source; prior Task85 raw/reproduction reused. |
| vfwcvt.f.f.v | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwcvt.rtz.x.f.v | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwcvt.rtz.xu.f.v | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwcvt.x.f.v | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwcvt.xu.f.v | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwmacc.vf | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwmacc.vv | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwmsac.vf | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwmsac.vv | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwmul.vf | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwmul.vv | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwnmacc.vf | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwnmacc.vv | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwnmsac.vf | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwnmsac.vv | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwredosum.vs | ACCEPTED_SCOPED | {"BLOCKED": 4, "N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vfwredusum.vs | ACCEPTED_SCOPED | {"BLOCKED": 4, "N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vfwsub.vf | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwsub.vv | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwsub.wf | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vfwsub.wv | ACCEPTED_SCOPED | {"N/A": 4} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmacc.vv | ACCEPTED_SCOPED | {"PASS": 8} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmacc.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmadc.vx | ACCEPTED_SCOPED | {"N/A": 4} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmadc.vxm | ACCEPTED_SCOPED | {"N/A": 4} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmadd.vv | ACCEPTED_SCOPED | {"PASS": 8} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmadd.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmerge.vxm | ACCEPTED_SCOPED | {"N/A": 4} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmfeq.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmfeq.vv | ACCEPTED_SCOPED | {"N/A": 13} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmfge.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmfgt.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmfle.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmfle.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmflt.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmflt.vv | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmfne.vf | ACCEPTED_SCOPED | {"N/A": 6} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmfne.vv | ACCEPTED_SCOPED | {"N/A": 13} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vmseq.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmsne.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmul.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmulh.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmulhsu.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmulhu.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmv.s.x | ACCEPTED_SCOPED | {"BLOCKED": 7} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmv.v.x | ACCEPTED_SCOPED | {"N/A": 4} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vmv.x.s | ACCEPTED_SCOPED | {"BLOCKED": 7} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vnmsac.vv | ACCEPTED_SCOPED | {"PASS": 8} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vnmsac.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vnmsub.vv | ACCEPTED_SCOPED | {"PASS": 8} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vnmsub.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vnsra.wv | SOURCE_BLOCKED | {"BLOCKED": 6} | Reserved: wide source v2-v3 EEW=2*SEW overlaps narrow source v3 EEW=SEW. No legal operand rewrite. |
| vnsrl.wv | SOURCE_BLOCKED | {"BLOCKED": 6} | Reserved: wide source v2-v3 EEW=2*SEW overlaps narrow source v3 EEW=SEW. No legal operand rewrite. |
| vor.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vssseg2e8.v | ACCEPTED_SCOPED | {"BLOCKED": 3} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |
| vssseg3e32.v | SOURCE_BLOCKED | {"BLOCKED": 1} | Original VL22 load and store exceed 64-element INP1/output: NF3 touches elements64,65 (e8 bytes64,65; e32 bytes256..263). Checker still compares original extent; reducing VL would rewrite test. |
| vssseg3e8.v | SOURCE_BLOCKED | {"BLOCKED": 1} | Original VL22 load and store exceed 64-element INP1/output: NF3 touches elements64,65 (e8 bytes64,65; e32 bytes256..263). Checker still compares original extent; reducing VL would rewrite test. |
| vsuxei16.v | ACCEPTED_SCOPED | {"N/A": 2} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vsuxei32.v | ACCEPTED_SCOPED | {"N/A": 2} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vsuxei8.v | ACCEPTED_SCOPED | {"N/A": 2} | Scoped predicates accepted; original full-file/profile/checker obligations remain as recorded. |
| vxor.vx | ACCEPTED_SCOPED | {"N/A": 8} | Ara89 extracted original predicates accepted; incompatible blocks and whole-file obligations retained. |

Task90 checkpoint: Ara396 →422; exactly26 additions, no removals. Task87 cumulative baseline remains301.

Ara89:166 original blocks /39 programs;830 block/arm bindings share195 valid receipts (156 DUT +39 reference). Eight failed preliminary Spike calls remain separate:47 actual references,203 total recorded calls. Zero new calls in this integration.

Ara89 exact additions: `vand.vx`, `vfredmax.vs`, `vfredmin.vs`, `vfredosum.vs`, `vfredusum.vs`, `vfwredosum.vs`, `vfwredusum.vs`, `vmacc.vx`, `vmadc.vx`, `vmadc.vxm`, `vmadd.vx`, `vmerge.vxm`, `vmseq.vx`, `vmsne.vx`, `vmul.vx`, `vmulh.vx`, `vmulhsu.vx`, `vmulhu.vx`, `vmv.s.x`, `vmv.v.x`, `vmv.x.s`, `vnmsac.vx`, `vnmsub.vx`, `vor.vx`, `vssseg2e8.v`, `vxor.vx`

Main reviewed166 preserved blocks,195 raw receipts and390 rejection controls. These controls are reused, not rerun by Task90. Whole-file PASS, multi-member M1 and M2 fast admission are not established.

M2 target admission: UNOBSERVED/null. RVV_FAST reads rvv_fast::g_fast (dbt/elfrun.cpp:2071); the distinct RVV_ACTIVE_CHUNKS census (2144) was not enabled. Zero FAST counters cannot establish zero M2 runtime-bounds admission.

All247 finite block dispositions, including81 exclusions and source limitations, and eight preliminary build identities are retained in compact-input.json → ara_evidence.ara89.
