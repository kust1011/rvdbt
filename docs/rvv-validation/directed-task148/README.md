# Task148 directed tests

Two additive families use the existing runner, packets, observer and fixed
host512 e2559c5c with B/M1/M2/Both. Task145–147 executions and evidence are
untouched. See [Task148 result](../../../SESSION0_RESULT_148.md) for current
execution/audit status; per-form declarations and results are in `delta/` and
`shift/`, with [delta results](delta/PER_FORM_RESULTS.json) and
[shift results](shift/PER_FORM_RESULTS.json). Commands are in [COMMANDS.json](COMMANDS.json) and the two launch scripts.
Full commands, generated source/ELFs, raw packets, original failed attempts and
frozen scripts stay at **xbd:/home/vick/rvv-directed-task148/**. No archive.

`--family configuration148` adds immediate unsupported-vtype coverage, with
vsetvli bits8–10 and vsetivli bits8–9 only. Neither opcode selector bits nor
vsetvl observations supply that credit. All six VLENs and four policies cover
reserved SEW4–7, LMUL100, unsupported fractional SEW/LMUL pairs, each upper bit,
all upper bits and all encodable vtype bits. Selected AVL0/1/31, XLEN maximum
and rs1=x0 where encodable, nonzero starts, rd=x0, prior vill, and legal recovery
are explicit cases. The fixed profile sets exactly vill, VL=rd=0 and vstart=0;
all other captured CSRs/registers remain unchanged. Reserved input encodings are
reported as PROFILE_UNSUPPORTED_VTYPE, separate from legal recovery PASS.
Optional trap/emulation behavior is outside this accepting profile. Target CSRs
are captured before restoring legal e8/m1 to observe register bytes.

`--family shiftminmax148` adds vsll/vsrl/vsra.vv/vx/vi and
vmin/vminu/vmax/vmaxu.vv/vx. [RVV1.0](https://github.com/riscv/riscv-v-spec/blob/v1.0/v-spec.adoc)
§10, §11.6 and §11.10 were reviewed alongside pinned
[Spike20feb9c2](https://github.com/riscv-software-src/riscv-isa-sim/tree/20feb9c2bf2a7deab964d8190b0cbd4b4131bec3/riscv/insns)
and [Sail0.14.1](https://github.com/riscv/sail-riscv/blob/0.14.1/model/extensions/V/vext_arith_insts.sail).
Exact read-source hashes are in [SOURCE_REVIEW.json](SOURCE_REVIEW.json); originals
remain on xbd. Shift counts use low log2(SEW) bits, vi uses unsigned0–31,
vsra sign extends data, and min/max compare SEW-wide signed/unsigned values.
RV32 scalar operands truncate below XLEN and sign extend above XLEN, including
unsigned min/max. Shift vx extension cannot change its low count bits; SEW64 vi
cases distinguish accidental signed immediate counts. All32 immediates are tested.

The family inherits six VLENs, all22 legal ELEN64 SEW/LMUL pairs, four policies,
mask extremes/single bits/alternation, VL0/1/full/partial/chunk edges, source and
end-group overlaps, initialized starts below/equal/above VL and partial chunk
interactions. Data add signed boundaries, ties, high64/low32 scalar edges and
counts around SEW and count-mask boundaries. Start>=VLMAX results are labeled
PROFILE_RESERVED_START under Sail's per-invocation Vstart_Ignore profile;
VLMAX=VLEN cannot represent such a start in the writable CSR. min/max vi does
not exist. Other host widths/RV64, trap paths, exhaustive products and per-target
M1/M2 admission remain outside this finite family.

Every packet checks all32 vector registers, ten CSRs and scalar/rd pre/post.
Independent Spike executes the DUT ELF at zero start; fixed Sail uses verified
shared-body adapters for nonzero starts. Audit replays every packet, denominator,
target opcode and adapter using the reviewed checker. It is not a third ISA
oracle. Corruption controls include active answers, masks/tails/prestart/no-op
preservation, other registers, CSRs, scalar/pre-state, missing output/crash/timeout,
signedness/operation, scalar extension, unsigned immediate and count masking,
and direct independent-reference divergence. First control-witness mistakes are
retained, not classified as DUT failures.

Build each family with the command in COMMANDS.json into a fresh destination;
copy it to a fresh xbd root along with a frozen `scripts/` directory and FLAGS.
Check load/disk and combined worker capacity before launch. The scripts verify
snapshot hashes before/after; raw guest hashes and fixed DUT/reference identities
are checked too. Main owns broader review and the launcher completion signal.
