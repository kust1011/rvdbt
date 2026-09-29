// T6d: the fail-closed admission boundary of the four LLVM vector-SSA RVV routes.
//
// WHY THIS FILE EXISTS, AND WHY IT IS NOT ANOTHER PER-OPCODE ROUTE TEST
//
// Ten of the tree's RVV routes -- `vsetvli`, `vle32.v`, `vse32.v`, the six `.vv` integer ALU
// operations and the Native-3 `.vx` multiply/multiply-accumulate -- each have their own route test,
// and every one of those routes is reached through a decode Op the DECODER already narrowed.
// `vadd.vv` arrives as `Insn_vadd_vv`, a type only rv32_decode.h's exact
// `f6 == VF6_VADD && vm == 1` test can produce, so nothing else can reach the frame at all.
//
// FOUR ROUTES ARE NOT LIKE THAT, AND NONE OF THEM HAD A TEST BEFORE T6d:
//
//   TRANSLATOR(vfalu)   `Op::_vfalu` carries ELEVEN funct6 values x {OPFVV, OPFVF} x {masked,
//                       unmasked}: vfadd, vfsub, vfmin, vfmax, vfsgnj{,n,x}, vfdiv, vfmul and the
//                       two OPFVF-only reverse forms. The route admits FOUR of them, all OPFVV
//                       and all unmasked: vfadd, vfsub, vfmul, vfdiv.
//   TRANSLATOR(vfma)    `Op::_vfma` carries EIGHT funct6 values (vfmadd..vfnmsac) x two groups x vm.
//                       The route admits vfmadd in BOTH groups and nothing else.
//   TRANSLATOR(vfcmp)   `Op::_vfcmp` carries SIX funct6 values (vmfeq/vmfle/vmflt/vmfne/vmfgt/vmfge)
//                       across the two groups x vm. The route admits ONE of them.
//   TRANSLATOR(vmerge)  `Op::_vmerge` carries OPIVV/OPIVX/OPIVI x {vm=0 vmerge.v*m, vm=1 vmv.v.*}.
//                       The route admits ONE, and it is the MASKED one -- this is the only route in
//                       the tree that admits a masked guest instruction at all.
//
// For these four, "this really is the instruction the frame was written for" is the TRANSLATOR's
// own obligation, discharged by inline funct3/funct6/vm tests rather than by a type. That is the
// same shape RvvQcgTypedVleChunkAdmit's comment names as needing its own gate, and it is the shape
// where a one-bit slip produces structurally perfect, numerically WRONG code: a guest `vfmin`
// lowered through the vfsub frame, a `vfnmsub` through the vfmadd frame, a `vmflt` through the
// vmfgt frame, or an unmasked `vmv.v.v` through the masked merge frame. None of those would fault,
// crash or fall back -- each would silently compute the wrong lanes. Since the vfalu route admits
// four funct6 values rather than one, the sweep additionally pins WHICH four: an admission that
// grew to cover vfmin/vfmax or the sign-injection forms would fail here, because those are the
// members of `vfalu_supported` no single constrained intrinsic can express.
//
// WHAT IS ASSERTED, AND WHY THE SWEEP IS THE POINT
//
// Section 3 does not test a handful of chosen negatives. For each route it enumerates the WHOLE
// (funct3 x funct6 x vm) space -- 8 x 64 x 2 = 1024 words -- decodes every word with the real
// `insn::Decoder`, keeps the ones the decoder routes to that route's Op, and requires that the set
// of ADMITTED encodings is exactly the set this file declares, while every other encoding in the
// same decode class reaches the route's pre-existing helper. A file that listed negatives by hand
// could not state that; this one can, and it is what makes "the route admits these encodings and no
// others" checkable rather than asserted.
//
// Section 2 runs the admitted words FIRST and requires them to be admitted. Without that half every
// fail-closed row in sections 3-5 would pass on a build where the route was broken outright, which
// is the failure mode T6b names for its own LLVM-arm check.
//
// Sections 4 and 5 are the shape and gate rows: SEW, LMUL, register-group legality, the vmerge
// mask-overlap rule, the absence of an observed vtype, and each precondition of `RvvSSAEnabled()`.
//
// WHAT THIS FILE DOES NOT DO
//
//   * It adds no instruction semantics, changes no admission predicate and touches no helper. It is
//     a read-only audit of gates that already exist.
//   * It never runs LLVM. `CompilerGenRegionIR` is backend-independent and these four routes are
//     decided in `dbt/guest/rv32_qir.cpp`, where the LLVM/AOT arm is selected by two `config` reads
//     -- so no TargetMachine, no module, no object file. It builds and runs on any x86-64 host, with
//     or without AVX-512, and emits no host instruction of any width.
//   * It never executes anything it constructs. No PROT_EXEC page exists in this process.
//   * It makes no performance claim and times nothing.
//
// INSTRUCTION WORDS are BUILT from the field layout in rv32_decode.h rather than pasted, because a
// 1024-point sweep cannot be a list of literals. `EncOpV` is that layout written once, and section 1
// pins it against the four admitted words plus the vtype prologue, which ARE literals and were
// round-tripped through `llvm-mc-20 --disassemble -triple=riscv32 -mattr=+v,+d`:
//
//   0x0a861257  vfsub.vv    v4, v8, v12
//   0xa2861257  vfmadd.vv   v4, v12, v8
//   0x76865257  vmfgt.vf    v4, v8, fa2
//   0x5c860257  vmerge.vvm  v4, v8, v12, v0
//   0x0d057557  vsetvli     a0, a0, e32, m1, ta, ma

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

// `Op` unqualified is qir::Op (the QIR node opcode). The GUEST decode opcode enum is a different
// type with overlapping intent, so it is always spelled `gi::Op` below and never imported.
namespace gi = dbt::rv32::insn;

namespace
{

int g_failures = 0;

#define CHECK(cond)                                                                                          \
	do {                                                                                                 \
		if (!(cond)) {                                                                               \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

#define CHECK_EQ(a, b)                                                                                       \
	do {                                                                                                 \
		auto _a = (a);                                                                               \
		auto _b = (b);                                                                               \
		if (!(_a == _b)) {                                                                           \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,    \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Instruction encoding. The OP-V field layout from rv32_decode.h, written once.
//
//   funct6 [31:26] | vm [25] | vs2 [24:20] | vs1/rs1/imm [19:15] | funct3 [14:12] | vd [11:7] | 1010111
//
// and the OPCFG form `vsetvli rd, rs1, vtypei`, whose zimm11 sits at [30:20] with bit 31 clear.
// ---------------------------------------------------------------------------------------------
constexpr u32 OPV = 0b1010111u;

constexpr u32 EncOpV(u32 f6, u32 vm, u32 vs2, u32 vs1, u32 f3, u32 vd)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) | (vd << 7) | OPV;
}

// vtypei = vma[7] | vta[6] | vsew[5:3] | vlmul[2:0]; SEW = 8 << vsew, LMUL = signed 2^vlmul.
constexpr u32 VTypeI_TA_MA(u32 vsew, u32 vlmul) { return (1u << 7) | (1u << 6) | (vsew << 3) | vlmul; }
constexpr u32 EncVsetvli(u32 vtypei, u32 rs1, u32 rd)
{
	return (vtypei << 20) | (rs1 << 15) | (0b111u << 12) | (rd << 7) | OPV;
}

constexpr u32 VSEW_E8 = 0b000, VSEW_E16 = 0b001, VSEW_E32 = 0b010, VSEW_E64 = 0b011;
constexpr u32 VLMUL_M1 = 0b000, VLMUL_M2 = 0b001, VLMUL_M8 = 0b011;
constexpr u32 VLMUL_MF2 = 0b111;

constexpr u32 F3_OPIVV = 0b000, F3_OPFVV = 0b001, F3_OPFVF = 0b101;

char const *F3Name(u32 f3)
{
	switch (f3) {
	case 0b000: return "OPIVV";
	case 0b001: return "OPFVV";
	case 0b010: return "OPMVV";
	case 0b011: return "OPIVI";
	case 0b100: return "OPIVX";
	case 0b101: return "OPFVF";
	case 0b110: return "OPMVX";
	default: return "OPCFG";
	}
}

// Register numbers used by every constructed word. None is v0, so the vmerge route's "vd must not
// overlap the mask register" rule holds for the admitted word and can be falsified on its own row
// (section 4) instead of being accidentally satisfied nowhere.
constexpr u32 VD = 4, VS2 = 8, VS1 = 12;

// The vtype prologue. These four routes read `rvv_bb_vtype`, which only an in-block `vsetvli` sets;
// see section 5 for what happens without it.
constexpr u32 INSN_VSETVLI_E32M1 = 0x0d057557u;

// ---------------------------------------------------------------------------------------------
// The route table.
// ---------------------------------------------------------------------------------------------
struct Encoding {
	u32 f3, f6, vm;
};

struct Route {
	char const *name;
	gi::Op guest_op;   // the decode class this route sits inside
	Op qir_op;	     // the typed node the direct route constructs
	RuntimeStubId stub;  // the PRE-EXISTING helper every refusal must reach
	Encoding admitted[4]; // the encodings the route may admit
	unsigned n_admitted;
	bool needs_host_fma; // vfma additionally requires --rvv-vector-ssa-host-fma
};

// funct6 constants, from rv32_vector_lower.h -- the same values the reference helpers switch on.
constexpr u32 F6_VFADD = dbt::rv32::VF6_VFADD;
constexpr u32 F6_VFSUB = dbt::rv32::VF6_VFSUB;
constexpr u32 F6_VFMUL = dbt::rv32::VF6_VFMUL;
constexpr u32 F6_VFDIV = dbt::rv32::VF6_VFDIV;
constexpr u32 F6_VFMADD = dbt::rv32::VF6_VFMADD;
constexpr u32 F6_VMFGT = dbt::rv32::VF6_VMFGT;
constexpr u32 F6_VMERGE = dbt::rv32::VF6_VMERGE;

Route const ROUTES[] = {
    // OPFVV only, and exactly the four funct6 values `vfalu_llvm_constrained_vv_supported`
    // accepts -- the family rule in rv32_vector_lower.h, which is `vfalu_supported` intersected
    // with "one exact IEEE 754 arithmetic operation". vfmin/vfmax and vfsgnj{,n,x} are inside
    // `vfalu_supported` and deliberately OUTSIDE this set (no single constrained intrinsic has
    // their NaN/signed-zero or bitwise semantics); vfrdiv/vfrsub exist only in OPFVF, whose scalar
    // operand `InstRVVFALU` carries no room for. The sweep in section 3 is what makes that
    // exclusion checkable rather than asserted.
    {"vfalu", gi::Op::_vfalu, Op::_rvvfalu, RuntimeStubId::id_rv32_vfalu,
     {{F3_OPFVV, F6_VFADD, 1},
      {F3_OPFVV, F6_VFSUB, 1},
      {F3_OPFVV, F6_VFMUL, 1},
      {F3_OPFVV, F6_VFDIV, 1}}, 4, false},
    // BOTH groups: TRANSLATOR(vfma) refuses only when funct3 is neither OPFVV nor OPFVF, so
    // vfmadd.vv and vfmadd.vf are both admitted and the .vf form takes the rvvsplatf scalar path.
    {"vfma", gi::Op::_vfma, Op::_rvvfma, RuntimeStubId::id_rv32_vfma,
     {{F3_OPFVV, F6_VFMADD, 1}, {F3_OPFVF, F6_VFMADD, 1}}, 2, true},
    // OPFVF only, and that is the architecture's doing rather than the route's: vmfgt has no
    // vector-vector form (vfcmp_supported returns is_vf for it), so OPFVV vmfgt decodes to `ill`.
    {"vfcmp", gi::Op::_vfcmp, Op::_rvvfcmp, RuntimeStubId::id_rv32_vfcmp,
     {{F3_OPFVF, F6_VMFGT, 1}, {}}, 1, false},
    // vm = 0: the MASKED merge. vm = 1 is vmv.v.v, a different instruction that must keep the helper.
    {"vmerge", gi::Op::_vmerge, Op::_rvvmerge, RuntimeStubId::id_rv32_vmerge,
     {{F3_OPIVV, F6_VMERGE, 0}, {}}, 1, false},
};
bool IsAdmittedEncoding(Route const &r, u32 f3, u32 f6, u32 vm)
{
	for (unsigned i = 0; i < r.n_admitted; ++i) {
		if (r.admitted[i].f3 == f3 && r.admitted[i].f6 == f6 && r.admitted[i].vm == vm) {
			return true;
		}
	}
	return false;
}

u32 AdmittedWord(Route const &r, unsigned which = 0)
{
	return EncOpV(r.admitted[which].f6, r.admitted[which].vm, VS2, VS1, r.admitted[which].f3, VD);
}

// ---------------------------------------------------------------------------------------------
// Translation harness. Every knob these four routes read is set on EVERY translation, so no row can
// inherit another's global state -- the failure that would otherwise make a fail-closed row pass
// because an earlier row left a switch off.
// ---------------------------------------------------------------------------------------------
struct Env {
	bool aot_use_llvm = true;	  // the LLVM/AOT arm: these routes exist on it and nowhere else
	bool rvv_vector_ssa = true;	  // the typed vector-SSA substrate switch
	bool rvv_vector_ssa_host_fma = true;
	bool rvv_verify = false;
	bool rvv_direct = true;
	u32 vlen_bits = 512;
	u32 vsetvli = INSN_VSETVLI_E32M1; // 0 = translate the word alone, with no observed vtype
};

void ApplyEnv(Env const &e)
{
	config::aot_use_llvm = e.aot_use_llvm;
	config::rvv_vector_ssa = e.rvv_vector_ssa;
	config::rvv_vector_ssa_host_fma = e.rvv_vector_ssa_host_fma;
	config::rvv_verify = e.rvv_verify;
	config::rvv_direct = e.rvv_direct;
	config::vlen_bits = e.vlen_bits;
	// Nothing else in the RVV family may be on: a second route appearing in the region would make
	// every count below ambiguous about which frame produced it.
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_lowering = 1; // rv32::RvvLowering::Chunked
}

Region *TranslateWords(MemArena &arena, u32 const *words, unsigned n, Env const &e)
{
	ApplyEnv(e);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

Region *TranslateOne(MemArena &arena, u32 (&words)[2], u32 word, Env const &e)
{
	if (e.vsetvli == 0) {
		words[0] = word;
		return TranslateWords(arena, words, 1, e);
	}
	words[0] = e.vsetvli;
	words[1] = word;
	return TranslateWords(arena, words, 2, e);
}

unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			n += ins.GetOpcode() == op;
		}
	}
	return n;
}

unsigned CountHcall(Region *region, RuntimeStubId stub)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_hcall) {
				n += static_cast<InstHcall *>(&ins)->stub == stub;
			}
		}
	}
	return n;
}

gi::Op DecodeWord(u32 word)
{
	u32 w = word;
	return gi::Decoder<gi::Op>::Decode(&w);
}

// One row's verdict. `direct` means the typed node was constructed and no helper call for this
// route's stub was emitted; `helper` is the exact complement. Anything else is a THIRD state and is
// reported rather than folded into one of the two, because "neither" would otherwise read as a pass
// on whichever side the caller happened to be asserting.
enum class Verdict { Direct, Helper, Neither, Both };

Verdict Route1(MemArena &arena, Route const &r, u32 word, Env const &e)
{
	u32 words[2];
	Region *region = TranslateOne(arena, words, word, e);
	unsigned const nodes = CountOp(region, r.qir_op);
	unsigned const calls = CountHcall(region, r.stub);
	if (nodes == 1 && calls == 0) {
		return Verdict::Direct;
	}
	if (nodes == 0 && calls == 1) {
		return Verdict::Helper;
	}
	return (nodes && calls) ? Verdict::Both : Verdict::Neither;
}

char const *VerdictName(Verdict v)
{
	switch (v) {
	case Verdict::Direct: return "direct";
	case Verdict::Helper: return "helper";
	case Verdict::Both: return "BOTH";
	default: return "NEITHER";
	}
}

void ExpectHelper(Route const &r, u32 word, Env const &e, char const *why)
{
	MemArena arena(1u << 20);
	Verdict const v = Route1(arena, r, word, e);
	CHECK_EQ((int)v, (int)Verdict::Helper);
	if (v != Verdict::Helper) {
		fprintf(stderr, "    (%s word=%08x %s -> %s)\n", r.name, word, why, VerdictName(v));
	}
}

void ExpectDirect(Route const &r, u32 word, Env const &e, char const *why)
{
	MemArena arena(1u << 20);
	Verdict const v = Route1(arena, r, word, e);
	CHECK_EQ((int)v, (int)Verdict::Direct);
	if (v != Verdict::Direct) {
		fprintf(stderr, "    (%s word=%08x %s -> %s)\n", r.name, word, why, VerdictName(v));
	}
}

// ---------------------------------------------------------------------------------------------
// 1. The encoder is the decoder's layout.
//
// The sweep in section 3 builds 4096 words with EncOpV. If that function disagreed with
// rv32_decode.h's field layout by one bit, every row of the sweep would be testing a different
// instruction than it names -- and most of them would decode to `ill` and be skipped, so the sweep
// would still "pass". Pinning the encoder against words an external assembler round-tripped is what
// closes that.
// ---------------------------------------------------------------------------------------------
void CheckEncoderPin()
{
	printf("[1] encoder pinned against llvm-mc-20 round-tripped words\n");
	CHECK_EQ(EncOpV(F6_VFSUB, 1, VS2, VS1, F3_OPFVV, VD), 0x0a861257u); // vfsub.vv   v4, v8, v12
	CHECK_EQ(EncOpV(F6_VFMADD, 1, VS2, VS1, F3_OPFVV, VD), 0xa2861257u); // vfmadd.vv v4, v12, v8
	CHECK_EQ(EncOpV(F6_VMFGT, 1, VS2, VS1, F3_OPFVF, VD), 0x76865257u); // vmfgt.vf   v4, v8, fa2
	CHECK_EQ(EncOpV(F6_VMERGE, 0, VS2, VS1, F3_OPIVV, VD), 0x5c860257u); // vmerge.vvm v4, v8, v12, v0
	CHECK_EQ(EncVsetvli(VTypeI_TA_MA(VSEW_E32, VLMUL_M1), 10, 10), INSN_VSETVLI_E32M1);
	// The vtype the four routes are audited under really is e32/m1, and VLMAX really is VLEN/32.
	dbt::rv32::VType const vt{VTypeI_TA_MA(VSEW_E32, VLMUL_M1)};
	CHECK_EQ(vt.sew(), 32u);
	CHECK_EQ(vt.lmul_log2(), 0);
	CHECK_EQ(dbt::rv32::compute_vlmax(vt, 512u), 16u);
	printf("  5/5 words, vtype e32/m1 VLMAX(512) = %u\n", dbt::rv32::compute_vlmax(vt, 512u));
}

// ---------------------------------------------------------------------------------------------
// 2. The admitted encodings ARE admitted, at both VLENs RvvSSAEnabled() allows.
//
// This section is what stops every fail-closed row below from passing vacuously.
// ---------------------------------------------------------------------------------------------
void CheckAdmitted()
{
	printf("[2] the admitted encodings take the direct route\n");
	for (auto const &r : ROUTES) {
		for (unsigned a = 0; a < r.n_admitted; ++a) {
			u32 const word = AdmittedWord(r, a);
			CHECK_EQ((int)DecodeWord(word), (int)r.guest_op);
			for (u32 vlen : {512u, 1024u}) {
				Env e;
				e.vlen_bits = vlen;
				ExpectDirect(r, word, e, "admitted");
			}
			printf("  %-7s %s f6=%02x vm=%u word=%08x direct at VLEN 512 and 1024\n", r.name,
			       F3Name(r.admitted[a].f3), r.admitted[a].f6, r.admitted[a].vm, word);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// 3. THE SWEEP. The whole (funct3 x funct6 x vm) space, per route.
//
// For every one of the 1024 encodings: decode it with the real decoder; if it does not reach this
// route's Op it is another route's or `ill`'s business and is counted but not judged; if it does,
// it must be direct exactly when this file declares it admitted, and reach the route's own
// pre-existing helper otherwise.
//
// The two totals printed per route are the substance. "in class" is how many encodings the DECODER
// hands to this translator; "admitted" is how many of them the translator lets through. A widening
// slip -- `<=` where an equality belongs, a mistyped constant, a dropped `vm` test -- moves the
// second number and nothing else has to be predicted in advance for the test to catch it.
// ---------------------------------------------------------------------------------------------
void CheckSweep(Route const &r)
{
	unsigned in_class = 0, admitted = 0, helper = 0, other = 0;
	for (u32 f3 = 0; f3 < 8; ++f3) {
		for (u32 f6 = 0; f6 < 64; ++f6) {
			for (u32 vm = 0; vm < 2; ++vm) {
				u32 const word = EncOpV(f6, vm, VS2, VS1, f3, VD);
				if (DecodeWord(word) != r.guest_op) {
					++other;
					continue;
				}
				++in_class;
				MemArena arena(1u << 20);
				Env e;
				Verdict const v = Route1(arena, r, word, e);
				bool const want_direct = IsAdmittedEncoding(r, f3, f6, vm);
				if (want_direct) {
					++admitted;
				} else {
					++helper;
				}
				Verdict const want = want_direct ? Verdict::Direct : Verdict::Helper;
				CHECK_EQ((int)v, (int)want);
				if (v != want) {
					fprintf(stderr,
						"    (%s %s f6=%02x vm=%u word=%08x: want %s, got %s)\n",
						r.name, F3Name(f3), f6, vm, word, VerdictName(want),
						VerdictName(v));
				}
			}
		}
	}
	CHECK_EQ(admitted, r.n_admitted);
	CHECK(in_class > r.n_admitted); // a decode class with nothing else in it proves nothing
	printf("  %-7s %4u words in class, %u admitted, %u fail closed to %s (%u words elsewhere)\n",
	       r.name, in_class, admitted, helper, "its own helper", other);
}

void CheckAllSweeps()
{
	printf("[3] whole funct3 x funct6 x vm sweep, per route\n");
	for (auto const &r : ROUTES) {
		CheckSweep(r);
	}
}

// ---------------------------------------------------------------------------------------------
// 4. Shape rows: the vtype and the register operands.
//
// The sweep holds the vtype at e32/m1 and the registers at v4/v8/v12. These rows move the other
// two axes on the ADMITTED word, which is the only word for which "still refused" is a statement
// about the shape rule rather than about the encoding test that already refused it.
//
// `RvvPVectorSSAShapeAdmit` (rv32_qir.cpp) is the shared shape predicate for all four: SEW in {32, 64},
// integer LMUL, `nregs * (VLEN/512) <= 4` chunks, and vl == VLMAX carried into the emitted guard.
// ---------------------------------------------------------------------------------------------
bool CheckShapeGateRefuses(u32 vsetvli, char const *why)
{
	gi::V setvl{vsetvli};
	u8 sew = 0, nregs = 0;
	u16 evl = 0;
	bool const admitted = dbt::qir::rv32::RvvPVectorSSAShapeAdmit(setvl.zimm11(), 512, sew, nregs, evl);
	CHECK(!admitted);
	if (admitted) {
		fprintf(stderr, "    (shape gate unexpectedly admitted %s: sew=%u nregs=%u evl=%u)\n", why,
			sew, nregs, evl);
	}
	return !admitted;
}

void CheckShapeRows()
{
	printf("[4] shape rows on the admitted word\n");
	struct Row {
		char const *why;
		u32 vsetvli;
	};
	// SEW 8 and 16 are not FP element widths this substrate implements (Zvfh/Zvfbfmin are separate
	// extensions); fractional LMUL leaves vl < VLMAX covering only part of a register; LMUL=8 at
	// VLEN=512 is 8 chunks, past the four the vector-SSA group carries.
	Row const rows[] = {
	    {"SEW 8", EncVsetvli(VTypeI_TA_MA(VSEW_E8, VLMUL_M1), 10, 10)},
	    {"SEW 16", EncVsetvli(VTypeI_TA_MA(VSEW_E16, VLMUL_M1), 10, 10)},
	    {"LMUL 8 (8 chunks > 4)", EncVsetvli(VTypeI_TA_MA(VSEW_E32, VLMUL_M8), 10, 10)},
	    {"fractional LMUL 1/2", EncVsetvli(VTypeI_TA_MA(VSEW_E32, VLMUL_MF2), 10, 10)},
	};
	bool safe_to_translate[sizeof(rows) / sizeof(rows[0])]{};
	for (unsigned i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i) {
		// Check the pure admission decision first. If a mutant widens the four-chunk ceiling,
		// translating LMUL=8 would overrun fixed four-entry QIR arrays before ExpectHelper runs.
		safe_to_translate[i] = CheckShapeGateRefuses(rows[i].vsetvli, rows[i].why);
	}
	for (auto const &r : ROUTES) {
		for (unsigned i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i) {
			auto const &row = rows[i];
			if (!safe_to_translate[i])
				continue;
			Env e;
			e.vsetvli = row.vsetvli;
			ExpectHelper(r, AdmittedWord(r), e, row.why);
		}
		// SEW 64 with LMUL 1 and 2 IS in the shared shape predicate's envelope and is admitted;
		// asserting only the refusals would not distinguish "the SEW row works" from "SEW is
		// pinned to 32 and three of the four rows above are redundant".
		Env e64;
		e64.vsetvli = EncVsetvli(VTypeI_TA_MA(VSEW_E64, VLMUL_M1), 10, 10);
		ExpectDirect(r, AdmittedWord(r), e64, "SEW 64 LMUL 1");
		printf("  %-7s SEW 8/16 refused, LMUL 8 refused, mf2 refused, e64/m1 admitted\n", r.name);
	}

	// Register-group legality at LMUL=2: a group must be LMUL-aligned. v5 is not.
	printf("[4b] register-group legality at LMUL 2, and the vmerge mask-overlap rule\n");
	u32 const setvli_m2 = EncVsetvli(VTypeI_TA_MA(VSEW_E32, VLMUL_M2), 10, 10);
	for (auto const &r : ROUTES) {
		Env e;
		e.vsetvli = setvli_m2;
		// The aligned form is admitted, so the misaligned row below is about alignment and not
		// about LMUL 2 being refused outright.
		u32 const aligned = EncOpV(r.admitted[0].f6, r.admitted[0].vm, 8, 12, r.admitted[0].f3, 4);
		ExpectDirect(r, aligned, e, "LMUL 2, aligned groups");
		// vs2 = v5: not a multiple of 2, so not a legal LMUL=2 group.
		u32 const misaligned =
		    EncOpV(r.admitted[0].f6, r.admitted[0].vm, 5, 12, r.admitted[0].f3, 4);
		ExpectHelper(r, misaligned, e, "LMUL 2, vs2 = v5 misaligned");
		printf("  %-7s LMUL 2 aligned admitted, vs2=v5 refused\n", r.name);
	}
	// vmerge is the only route that reads v0 as a mask, so it is the only one with a vd/v0 overlap
	// rule -- RVV 1.0 forbids a masked instruction's destination overlapping the mask source.
	{
		Route const &vmerge = ROUTES[3];
		Env e;
		u32 const vd0 = EncOpV(F6_VMERGE, 0, VS2, VS1, F3_OPIVV, 0);
		ExpectHelper(vmerge, vd0, e, "vd = v0 overlaps the mask source");
		printf("  vmerge  vd = v0 refused (mask-source overlap)\n");
	}
}

// ---------------------------------------------------------------------------------------------
// 5. Gate rows: every precondition that is not a property of the instruction.
//
// RvvSSAEnabled() is `rvv_vector_ssa && aot_use_llvm && VLEN in {512, 1024}`. All four routes call
// it first, so each of its three terms is a separate fail-closed row -- and the VLEN term is why
// T6b's widening to 2048/4096 could not reach this family: above 1024 an LLVM compile still takes
// the pre-existing helper. `--rvv-vector-ssa-host-fma` is vfma's own additional switch.
//
// THE LAST ROW IS THE ONE WITH NO ANALOGUE IN THE NINE ELEMENT-WISE ROUTES. Those propose a
// candidate vtype when no in-block `vsetvli` was observed and let the emitted guard prove it at run
// time. These four do not: `RvvPVectorSSAShapeAdmit` returns false for `rvv_bb_vtype == ~0u`, so a
// block that inherits its vtype from a caller keeps the helper for all four.
// ---------------------------------------------------------------------------------------------
void CheckGateRows()
{
	printf("[5] gate rows\n");
	for (auto const &r : ROUTES) {
		{
			Env e;
			e.rvv_vector_ssa = false;
			ExpectHelper(r, AdmittedWord(r), e, "--rvv-vector-ssa off");
		}
		{
			Env e;
			e.aot_use_llvm = false;
			ExpectHelper(r, AdmittedWord(r), e, "pure QCG (aot_use_llvm off)");
		}
		for (u32 vlen : {128u, 256u, 2048u, 4096u}) {
			Env e;
			e.vlen_bits = vlen;
			ExpectHelper(r, AdmittedWord(r), e, "VLEN outside {512, 1024}");
		}
		{
			Env e;
			e.vsetvli = 0; // no observed vtype in this block
			ExpectHelper(r, AdmittedWord(r), e, "no in-block vsetvli");
		}
		printf("  %-7s refused: ssa off, pure QCG, VLEN 128/256/2048/4096, no observed vtype\n",
		       r.name);
	}
	// vfma's own switch, and it must be the ONLY route it moves.
	{
		Env e;
		e.rvv_vector_ssa_host_fma = false;
		for (auto const &r : ROUTES) {
			for (unsigned a = 0; a < r.n_admitted; ++a) {
				if (r.needs_host_fma) {
					ExpectHelper(r, AdmittedWord(r, a), e, "host-fma off");
				} else {
					ExpectDirect(r, AdmittedWord(r, a), e, "host-fma off, unaffected");
				}
			}
		}
		printf("  --rvv-vector-ssa-host-fma off: vfma refused, the other three unchanged\n");
	}
	// --rvv-verify is NOT a gate for these four, and stating that as a checked row rather than
	// leaving it out is the point: the six typed integer ALU routes and both memory routes DO
	// exclude themselves under it (their predicates test config::rvv_verify), and these four do
	// not. Whether that asymmetry should exist is a source question T6d records; what this row
	// asserts is only what the tree does today, so a later change to either side is visible.
	{
		Env e;
		e.rvv_verify = true;
		for (auto const &r : ROUTES) {
			ExpectDirect(r, AdmittedWord(r), e, "--rvv-verify on (no gate on this family)");
		}
		printf("  --rvv-verify on: all four still direct (no rvv_verify term in this family)\n");
	}
}

// ---------------------------------------------------------------------------------------------
// 6. The QCG backend cannot receive any of these nodes.
//
// Section 5's "pure QCG" row shows the TRANSLATOR refuses; this section states the second half,
// which is why that refusal is a boundary rather than a preference: `QEmit::Emit_rvvfalu` and its
// ten siblings are `RVV_SSA_QCG_UNSUPPORTED` (qmc/qcg/qemit.cpp) and Panic. So a routing bug that
// let one of these nodes into the scalar AsmJit backend would be a loud translation failure and
// never a silent re-opaqueification into a helper call.
//
// This is asserted from the emitted region rather than from the source text: with aot_use_llvm off,
// the region must contain ZERO nodes of every vector-SSA opcode -- not just this route's.
// ---------------------------------------------------------------------------------------------
void CheckNoSsaNodesOnQcg()
{
	printf("[6] pure QCG regions carry no vector-SSA node at all\n");
	static constexpr Op SSA_OPS[] = {Op::_rvvread,  Op::_rvvwrite, Op::_rvvsplatf, Op::_rvvload,
					 Op::_rvvstore, Op::_rvvfcmp, Op::_rvvmerge,  Op::_rvvfalu,
					 Op::_rvvfma,   Op::_rvvfpbegin, Op::_rvvfpend};
	for (auto const &r : ROUTES) {
		MemArena arena(1u << 20);
		u32 words[2];
		Env e;
		e.aot_use_llvm = false;
		Region *region = TranslateOne(arena, words, AdmittedWord(r), e);
		for (Op op : SSA_OPS) {
			CHECK_EQ(CountOp(region, op), 0u);
		}
		CHECK_EQ(CountHcall(region, r.stub), 1u);
	}
	printf("  4/4 routes: 0 of 11 vector-SSA opcodes, 1 helper call each\n");
}

} // namespace

int main()
{
	printf("=== T6d: LLVM vector-SSA RVV route admission boundary ===\n");
	CheckEncoderPin();
	CheckAdmitted();
	CheckAllSweeps();
	CheckShapeRows();
	CheckGateRows();
	CheckNoSsaNodesOnQcg();
	if (g_failures) {
		printf("\nT6D_SSA_ADMISSION_VERDICT: FAIL (%d)\n", g_failures);
		return 1;
	}
	printf("\nT6D_SSA_ADMISSION_VERDICT: PASS\n");
	return 0;
}
