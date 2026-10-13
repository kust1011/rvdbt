All sixteen forms have complete frozen guest execution and offline audit, with **semantic FAIL** from the reproduced missing-NV defect. `s1` is vs1 for vv and the NaN-boxed scalar for vf. B/M1/M2/BOTH have identical denominators.

| Form | Formula before one rounding | Reference PASS | DUT PASS / FAIL per arm | Failure obligation |
|---|---|---:|---:|---|
| vfmacc.vf | `s1*s2+old_vd` | 15,025 | 14,593 / 432 | 432 isolated invalid-product/qNaN cases |
| vfmacc.vv | `s1*s2+old_vd` | 14,683 | 14,233 / 450 | 432 isolated invalid-product/qNaN cases + 18 active single-on-mask cases |
| vfmadd.vf | `s1*old_vd+s2` | 15,025 | 14,593 / 432 | 432 isolated invalid-product/qNaN cases |
| vfmadd.vv | `s1*old_vd+s2` | 14,683 | 14,233 / 450 | 432 isolated invalid-product/qNaN cases + 18 active single-on-mask cases |
| vfmsac.vf | `s1*s2-old_vd` | 15,025 | 14,593 / 432 | 432 isolated invalid-product/qNaN cases |
| vfmsac.vv | `s1*s2-old_vd` | 14,683 | 14,233 / 450 | 432 isolated invalid-product/qNaN cases + 18 active single-on-mask cases |
| vfmsub.vf | `s1*old_vd-s2` | 15,025 | 14,593 / 432 | 432 isolated invalid-product/qNaN cases |
| vfmsub.vv | `s1*old_vd-s2` | 14,683 | 14,233 / 450 | 432 isolated invalid-product/qNaN cases + 18 active single-on-mask cases |
| vfnmacc.vf | `-s1*s2-old_vd` | 15,025 | 14,593 / 432 | 432 isolated invalid-product/qNaN cases |
| vfnmacc.vv | `-s1*s2-old_vd` | 14,683 | 14,233 / 450 | 432 isolated invalid-product/qNaN cases + 18 active single-on-mask cases |
| vfnmadd.vf | `-s1*old_vd-s2` | 15,025 | 14,593 / 432 | 432 isolated invalid-product/qNaN cases |
| vfnmadd.vv | `-s1*old_vd-s2` | 14,683 | 14,233 / 450 | 432 isolated invalid-product/qNaN cases + 18 active single-on-mask cases |
| vfnmsac.vf | `-s1*s2+old_vd` | 15,025 | 14,593 / 432 | 432 isolated invalid-product/qNaN cases |
| vfnmsac.vv | `-s1*s2+old_vd` | 14,683 | 14,233 / 450 | 432 isolated invalid-product/qNaN cases + 18 active single-on-mask cases |
| vfnmsub.vf | `-s1*old_vd+s2` | 15,025 | 14,593 / 432 | 432 isolated invalid-product/qNaN cases |
| vfnmsub.vv | `-s1*old_vd+s2` | 14,683 | 14,233 / 450 | 432 isolated invalid-product/qNaN cases + 18 active single-on-mask cases |

Isolated defect bins cover all 54 declared geometries, both multiplicand orders and frm0–3; the corresponding frm4 (RMM) witnesses pass. All 28,224 failed five-arm checks differ by missing NV only, with canonical result bits matching the independent reference. These failures remain FAIL in the full audit; no full-family PASS or M1/M2 admission is claimed.

Full controls cover each form/geometry plus every mode at the two small geometries: effective nonfused replacement, wrong destructive role and both sign flips are rejected by ISA and reference predicates. Original failure rows/packet offsets/hashes remain in full-findings and full-evidence. A production fix/new-pin regression and main/checker review remain unresolved.
