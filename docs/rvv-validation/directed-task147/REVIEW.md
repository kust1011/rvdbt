# Task147 configuration oracle review

Agent source review before formal execution, pending main review. The active
upstream plan governs this three-form family. No production algorithms or DUT
outputs generate expected answers.

Read frozen [RVV 1.0 configuration section](https://github.com/riscv/riscv-v-spec/blob/v1.0/v-spec.adoc#configuration-setting-instructions-vsetvlivsetivlivsetvl),
§3.4 vtype, §3.7 vstart and §6. Read fixed
[Spike 20feb9c2 vector_unit.cc](https://github.com/riscv-software-src/riscv-isa-sim/blob/20feb9c2bf2a7deab964d8190b0cbd4b4131bec3/riscv/vector_unit.cc)
and vsetvli/vsetivli/vsetvl headers; read fixed
[Sail 0.14.1 vext_vset_insts.sail](https://github.com/riscv/sail-riscv/blob/0.14.1/model/extensions/V/vext_vset_insts.sail)
and vext_regs.sail. Original reviewed files and hashes are retained in Task147 raw.

For legal configurations: AVL<=VLMAX requires VL=AVL; VLMAX<AVL<2VLMAX
permits ceil(AVL/2)..VLMAX; AVL>=2VLMAX requires VLMAX. VL is deterministic
for equal AVL/VLMAX on each implementation. The checker validates the allowed
interval, actual rd==VL (x0 reads zero), exact vtype/vlenb/vstart, unchanged
vxrm/vxsat/vcsr/fflags/frm/fcsr, and all 32 vector registers. Independent reference
comparison covers exact invariants and exact VL/rd where unique, but never
requires the same permissible middle-interval choice. Spike selects VLMAX;
Sail's supported per-invocation vl_use_ceil=true selects ceil. Determinism keys
separate these independent implementations while combining forms, policies,
pre-states and equal-ratio geometries within each DUT arm.

rs1=x0/rd!=x0 means maximum unsigned XLEN AVL. rd=rs1=x0 preserves VL only
when SEW/LMUL ratio is unchanged. Legal policy changes and every other legal
equal-ratio SEW/LMUL predecessor are included, with zero/one/partial/full old
VL. vsetivli's 5-bit unsigned immediate is always0..31, including0/1/15/16/30/31
and applicable VLMAX edges. XLEN maximum is0xffffffff because the reused guest
platform is RV32. The exact target instruction at target_ordinal earns credit;
setup and observation configuration instructions do not.

vsetvl uses register vtype values, including rd/rs2 and rs1/rs2 overlap and x0
rs2 where it denotes e8/m1/tu/mu. Unsupported SEW/LMUL and each input upper
bit8..31 are separately labeled unsupported-vtype: under this fixed V1.0/ELEN64
profile they set exactly vill, VL=0 and rd=0, and clear vstart. These include
reserved vtype field encodings; they are unsupported vtype inputs, not illegal
OP-V opcode encodings. The models' fixed profile supports setting vill; optional
forward-compatible trap/emulation behavior is not universally ruled out by these
finite profile observations.

Reserved ratio-changing rd=rs1=x0 cases are observation-only for the target's
VL/vtype/vstart/rd. Only initialized input and unchanged vector registers/other
CSRs are checked and compared. They receive separate observed-reserved counts,
not legal semantic PASS credit. CSR-representable vstart>=old VLMAX cases are
separate reserved-vstart-profile observations: this implementation/model accepts
configuration and clears vstart. This is not a universal instruction-acceptance
claim for reserved states. Ordinary nonzero vstart and pre-existing vill recovery
are separately exercised. No vector instruction runs under vill before CSR/rd
capture: initialization/dump use legal e8/m1; the pre-vill setup is followed only
by scalar setup/capture and the configuration target. After target CSRs and rd
are stored, the observer clears start and restores legal e8/m1 for the whole
register dump. The packet represents target CSRs before this observer boundary;
post vector bytes follow it. Legal reconfiguration is specified not to modify
vector registers, and the entire dump must match initialized bytes.

The shared vadd.py builder/runner/packet/assembly captures and audit.py denominator,
ELF and Sail adapter verification are reused. No new platform. Old family defaults,
packet layout and generated bodies remain compatible. Full manifests precede
execution. Rejection controls independently alter rd, VL, vtype, vstart, vlenb,
other CSR and vector output, and also test missing output/crash/timeout,
coherent rd/VL outside the set, independent comparison, and acceptance of both
legal VL endpoints. Original formal packets are never altered.

Finite limits: other host widths/RV64, illegal opcode trap handling, exhaustive
scalar-register aliases/products and per-target M1/M2 admission. No production
changes, external full rerun, performance/publication, Linux/scalar/atomic/LLVM,
handler return, repair/retry or P4-04 equivalents.
