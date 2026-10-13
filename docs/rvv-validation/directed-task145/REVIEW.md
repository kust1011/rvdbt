# Task145 source and predicate review

These are **project-authored tests**, not CHIPS/Ara/RVVTS upstream originals.
The template uses the retained RVVTS whole-register initialization/capture pattern,
link script, established external flags and bounded process-group receipt protocol
from `run_rvv_external.call`. CHIPS' pinned `configs/v/vadd.{vv,vx,vi}.toml`
contributes concrete arithmetic-edge design, rather than expected output. Sources
and compiler are authenticated in SOURCES.json. No external full suite is rerun.

Source-level review basis:

* [Frozen RVV1.0 specification](https://github.com/riscv/riscv-v-spec/blob/v1.0/v-spec.adoc),
  sections Vector Register Grouping, Vector Tail/Mask Agnostic, Vector Start Index,
  Prestart/Active/Inactive/Tail Elements, Vector Arithmetic Instruction Formats,
  and Vector Single-Width Integer Add and Subtract.
* [Fixed Spike vv](https://github.com/riscv-software-src/riscv-isa-sim/blob/20feb9c2bf2a7deab964d8190b0cbd4b4131bec3/riscv/insns/vadd_vv.h),
  [vx](https://github.com/riscv-software-src/riscv-isa-sim/blob/20feb9c2bf2a7deab964d8190b0cbd4b4131bec3/riscv/insns/vadd_vx.h),
  [vi](https://github.com/riscv-software-src/riscv-isa-sim/blob/20feb9c2bf2a7deab964d8190b0cbd4b4131bec3/riscv/insns/vadd_vi.h),
  and `v_ext_macros.h`, `decode_macros.h`, `vector_unit.cc` at that revision.
* [CHIPS parameterized vv cases](https://github.com/chipsalliance/riscv-vector-tests/blob/f76bff121dce91b6b23e1d37be77a5e44af914c3/configs/v/vadd.vv.toml)
  and adjacent vx/vi files at the same pinned revision.
* [Sail RISC-V release0.14.1](https://github.com/riscv/sail-riscv/releases/tag/0.14.1),
  existing executable build reports git `e4b243f`, Sail0.20.2/`3b7af38d...`.
  Its actual generated default configuration exposes
  `extensions.V.vstart.zero_required.arith` and VLEN/ELEN exponents.

The checker is independent of production: Python arbitrary-width unsigned
modular addition is reviewed against the instruction definition and independently
executed fixed Spike/Sail. No DUT source, output or algorithm supplies goldens.
This is an agent source review and complete oracle cross-check; no separate human
review or formal proof is asserted. The offline auditor reapplies the same checker;
it is not a second independent ISA implementation.

Review findings and explicit predicates:

1. ELEN64 requires SEW <= min(LMUL,1)*64; integer LMUL1/2/4/8 and fractional
   mf2/mf4/mf8 yield **22** supported pairs. Six pairs outside this profile are
   excluded, rather than execution failures deleted. All six VLENs are covered.
   Each input AVL is <= VLMAX, so observed VL must equal AVL. EMUL=LMUL.
2. Active lanes are `vstart <= i < vl` with enabled predicate, or unmasked.
   Addition wraps modulo 2^SEW. vx consumes the signed XLEN32 value when SEW64;
   lower SEWs retain the low bits. vi is sign-extended simm5 (-16 through15).
   Active outputs must satisfy both the ISA predicate and independent reference.
3. Prestart and undisturbed lanes retain their own observed old element, even
   with destination/source overlap. For an agnostic element, only its complete
   old element or complete all-ones element is accepted; bytewise mixing is
   rejected. Tail includes unused physical lanes in a fractional destination.
   No agnostic choice is made when VL=0. Agnostic bits are not blindly equated
   to Spike/Sail's particular choice. Non-destination vector registers remain
   bit-exact, including v0 and non-overwritten source groups.
4. Observe all initialized registers with whole stores while vstart=0; only then
   establish target configuration and vstart. Capture 10 pre-CSRs and s0. The
   next instruction is the target. Capture 10 post-CSRs and s0 **before** resetting
   vstart for any dump. VL/vtype/vlenb/vxrm/vxsat/vcsr/fflags/frm/fcsr remain unchanged;
   target vstart becomes0. Nonzero fixed CSR sentinels catch unintended clearing.
5. All vector register groups are aligned. Same-width integral LMUL groups
   permit equal or disjoint groups, so a misaligned partial group overlap is not
   a legal vadd case. Tests include vd=vs2, vv vd=vs1, vv same sources, and a group
   ending at v31. Illegal/reserved encodings are outside this arithmetic template.
6. Spike's `require_vector` forbids nonzero arithmetic vstart; the spec allows
   that implementation choice. The existing fixed Sail binary runs those cases
   with a per-invocation config (`arith=false`), without rebuilding or changing
   model semantics. No global setting is changed. All tested starts are within
   `0 < vstart < VL=VLMAX`; these are initialized ordinary arithmetic, not restart.
7. Sail machine execution needs enabled FS/VS at entry and signature termination
   at exit. The user and Sail builds compile one shared source; its only
   conditional sections are the entry status initialization and terminal IO.
   The auditor verifies shared-body hash, identical compiled `.data`, and exact
   target opcode/operand equality for every adapted case. The machine link changes
   only placement to0x80000000. Sail stops at the final verified `jal x0,0` after
   all observations. The DUT runs the unmodified user ELF also used for Spike.
8. Strict output extent/order and successful exit are mandatory. Every formal
   execution has its original streams, command, hashes, elapsed time and checks.
   Corruption controls use isolated copies of actual reference packets; formal
   streams are never edited. Synthetic controls additionally exercise permitted
   agnostic all-ones acceptance and disallowed values.

Finite-scope gaps: host widths other than512; illegal/reserved encodings; RV64;
vstart>=VL and nonzero-vstart with zero/partial VL; all masks crossed with every
policy/length; repeated/live-out vector instruction sequences and per-PC M1/M2
admission. No Linux/scalar/atomic/LLVM expansion, fault handler, return/retry,
mapping repair, same-PC retry, P4-04, production change or performance claim.
