# Source integration requirements

Task181 owns validation/orchestration only. Its local tree is not claimed to
match the frozen179 production tree. Integrate the actual production sequence:

1. Task167 fused invalid-product flag fix (session3 commit `1f9a054`, original
   accepted fix `f238a5d`). Preserve the finalized invalid-product fixture and
   full-VL-mask-fusion test toggle.
2. Task172 `47028a8` FP64→FP32 precision-rounding underflow repair and finalized conversion
   fixture. [BUILD_MANIFEST_172.json](BUILD_MANIFEST_172.json) retains exact mixed-build original
   conversion provenance; final181 replay gives the accepted corrected matrices
   new179 DUT receipts without changing their ELFs or expected packets.
3. Exactly the three171 scalar insertion production hunks from `73fc8e2`:
   `vmvsx` and `vfmvsf` in `dbt/guest/rv32_interp.cpp`, and `Emit_vscalarmove` in
   `dbt/qmc/qcg/qemit.cpp`. Preserve the scalar insertion executable fixture and
   CMake registration. [BUILD_MANIFEST_174.json](BUILD_MANIFEST_174.json) defines
   the minimal immutable integration; historical171 whole-tree identity is not
   substituted for that source join.
4. Task179 `79da14c` returning trace observer frame-lifetime fix in
   `dbt/qmc/qcg/qemit.cpp`: remove only the erroneous nonleaf `FrameDestroy` in
   `Emit_Cache`. Its actual terminal exit retains the teardown. Preserve both
   leaf trace goldens and the paired-disassembly nonleaf goldens, plus the
   balanced FMA broadcast-scratch assertions. [BUILD_MANIFEST_179.json](BUILD_MANIFEST_179.json)
   pins the old/new files and frozen executable. The exact
   [production diff](PRODUCTION_174_TO179.diff) is retained.
5. Task180 `9b768b6` restores the inadvertently removed test-only assertions. It owns
   final P3 same179 checks; use its [restored test diff](TASK180_RESTORED_ASSERTIONS.diff) and final result as a
   separate source integration requirement. Do not mutate immutable179 to
   relabel test receipts or substitute another executable for181.

The frozen174 source is172 plus167 and the three171 production hunks;179 adds
only the trace-frame production fix. The shared library identity remains
unchanged. Main must preserve test/CMake integration and verify exact production
source hashes from the two manifests after any conflict resolution. This
validation commit does not cherry-pick production files or clear the155 dirty
state. A subsequently rebuilt executable has its own identity and receives no
implicit181 DUT receipt credit.

P3 actual admission/frame/path checks, scoped finite ISA matrices, original
ACT reference blockers and Ara scoped MAC outcomes stay distinct. No handler
return/repair/retry, arbitrary FP unordered sums, exhaustive Cartesian operands,
per-target optimization from arm flags, Linux or LLVM proof is added.
