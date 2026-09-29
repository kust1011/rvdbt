// S2.1: the exact unmasked `vsub.vv` typed V512 chunk route, verified mechanically at four levels
// -- decoder, constructed QIR, post-QRegAlloc allocation, and independently disassembled emitted
// host bytes.
//
// This file is the vsub twin of qmc/qcg/vmulvv_typedchunk_route_test.cpp and deliberately keeps its
// structure, so the two routes are checked to the same depth. It adds ONE class of check the add
// and multiply do not need and cannot have.
//
// WHY THIS ROUTE NEEDS AN EXTRA CLASS OF CHECK. Addition and low-half multiplication commute, so
// for those routes "the frame's operation reads this chunk's own two loads" is the whole obligation
// and the accepted tests check it as a SET (`(a,b) or (b,a)`). Subtraction does not commute. A
// frame that swapped its two inputs would still have: the right number of chunks, the right typed
// node, the right state windows, per-chunk def-use, disjoint ZMM sets across chunks, a correct
// guard, a correct fallback stub and correct counters -- and every lane of its result negated. So
// every place this file could have compared a set, it compares an ORDERED pair instead, and it does
// so against the guest's own operand roles:
//
//     RVV:  vsub.vv vd, vs2, vs1   =>   vd[i] = vs2[i] - vs1[i]
//           (rv32_vector_lower.h vialu_apply, VF6_VSUB: `a` from vs2, `b` from vs1, returns a - b)
//     QIR:  vchunksub d, in0, in1  =>   d = in0 - in1        (qir.h InstVChunkSub)
//     x86:  vpsubd    d, s0,  s1   =>   d = s0  - s1
//
// so input 0 / operand s0 must trace back to the load of VS2's state window, at every level.
// Section [7] makes that a falsifiable check rather than a restatement: it translates two guest
// words that differ ONLY by exchanging vs2 and vs1, and requires the decoded `vpsubd`'s FIRST
// source to follow the exchange. An emitter that emitted its operands in the other order would
// produce byte-identical output for those two words and fail there.
//
// WHAT THIS FILE PROVES
//
//   1. DECODER. Exactly one encoding class reaches the new op: OP-V / funct3=OPIVV /
//      funct6=VF6_VSUB / vm=1. Masked vsub.vv, vsub.vx, vrsub.vx, vssub.vv and vmin.vv still reach
//      Op::_vialu, while the three bitwise .vv encodings that used to sit in that family reach
//      their own ops since S2.2/S2.3/S2.4 (vxor.vv, vor.vv, vand.vv); vadd.vv still reaches
//      Op::_vadd_vv. No family is hijacked, and this file's claim about all of them is the same:
//      the SUB route must not capture any of them.
//   2. QIR. At VLEN=512 the admitted instruction becomes ONE 512-bit chunk (4 typed ops); at
//      VLEN=1024 TWO chunks (8 typed ops), in load-major order, at the exact low/high 64-byte
//      CPUState windows, with per-chunk def-use, no cross-chunk edge, and the minuend in input 0.
//      The body op is Op::_vchunksub with sew_bytes=4 -- the subtract is explicit in the IR, and it
//      is not the add or the multiply wearing a different name.
//   3. FALLBACK. Every forbidden shape keeps the pre-existing helper: zero typed nodes and one
//      `hcall [rv32_vialu]`. Each forbidden condition is exercised on its own axis, so a single
//      over-broad admission cannot hide behind another still-closed gate.
//   4. QRA. Three distinct physical VPRs at VLEN=512, six at VLEN=1024, all out of VPR_POOL, with
//      per-chunk def-use AND operand order surviving allocation, and no allocator-inserted V512 mov
//      inside the frame.
//   5. QEMIT. The real qcg::GenerateCode pipeline emits `vpsubd` (not vpaddd, not vpmulld, not a
//      scalar sequence), with the exact allocated ZMM operands in the exact order, the exact state
//      displacements, and at VLEN=1024 two chunks whose register sets are disjoint in the
//      externally decoded bytes.
//   6. OVERLAP. vd==vs2, vd==vs1 and vd==vs1==vs2 each still emit both of a chunk's source loads
//      before that chunk's destination store, which is what makes the legal overlaps correct. The
//      frozen S1.1-fix1 workload's own vsub.vv is the vd==vs2 case, so this is exercised on the
//      real word as well as on synthetic ones.
//   7. OPERAND-ROLE EXCHANGE. See above.
//
// WHAT IT DELIBERATELY NEVER DOES
//
//   * It never executes the emitted bytes. TestCompilerRuntime::AllocateCode resizes a
//     std::vector<u8> and returns its data pointer -- there is no mmap in this object's lifetime,
//     let alone a PROT_EXEC one. Runtime correctness is the xbd evidence's obligation, on a host
//     that actually has AVX-512.
//   * It never runs a guest program, never times anything, and makes no performance claim.
//
// HOST NOTE. RvvQcgTypedSubChunkAdmit's host-feature row is a real __builtin_cpu_supports probe, so
// on a machine without AVX-512F the route would fail closed and there would be nothing to inspect.
// `config::rvv_qcg_typed_chunk_sub_force_emit` bypasses ONLY that probe -- not the architectural
// guard, not the admitted shape -- which is exactly what lets the emitted shape be audited here.
// This is the same device the accepted C2.3a vadd and P3.5a vmul audits used.
//
// INSTRUCTION WORDS. Every encoding below was produced by an explicit field-assembly of the RVV 1.0
// OP-V layout and then independently round-tripped through `llvm-mc -triple=riscv32 -mattr=+v
// -show-encoding`, so the constants are not hand-transcribed hex.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
using namespace dbt::qcg;

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

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));

// Chunk 0 is a register's low 64-byte half, chunk 1 its high half -- the exact
// `r*VLEN_MAX_BYTES + chunk*64` formula RvvEmitTypedSubChunkGroup uses.
constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u;
}

// ---------------------------------------------------------------------------------------------
// Instruction words. Each is annotated with the disassembly llvm-mc independently produced for it.
// ---------------------------------------------------------------------------------------------
constexpr u32 INSN_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_E64M1 = 0x0d857557u; // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 INSN_VSETVLI_E32M2 = 0x0d157557u; // vsetvli a0, a0, e32, m2, ta, ma

constexpr u32 INSN_VSUB_VV = 0x0a1101d7u;	   // vsub.vv  v3, v1, v2
constexpr u32 INSN_VSUB_VV_SWAPPED = 0x0a2081d7u;  // vsub.vv  v3, v2, v1   (vs2/vs1 exchanged)
constexpr u32 INSN_VSUB_VV_D_EQ_S2 = 0x0a3101d7u;  // vsub.vv  v3, v3, v2   (vd == vs2)
constexpr u32 INSN_VSUB_VV_D_EQ_S1 = 0x0a1181d7u;  // vsub.vv  v3, v1, v3   (vd == vs1)
constexpr u32 INSN_VSUB_VV_ALL_SAME = 0x0a3181d7u; // vsub.vv  v3, v3, v3   (vd == vs1 == vs2)
constexpr u32 INSN_VSUB_VV_MASKED = 0x081101d7u;   // vsub.vv  v3, v1, v2, v0.t
constexpr u32 INSN_VSUB_VX = 0x0a1141d7u;	   // vsub.vx  v3, v1, sp
constexpr u32 INSN_VRSUB_VX = 0x0e1141d7u;	   // vrsub.vx v3, v1, sp
constexpr u32 INSN_VSSUB_VV = 0x8e1101d7u;	   // vssub.vv v3, v1, v2
constexpr u32 INSN_VAND_VV = 0x261101d7u;	   // vand.vv  v3, v1, v2
constexpr u32 INSN_VOR_VV = 0x2a1101d7u;	   // vor.vv   v3, v1, v2
constexpr u32 INSN_VXOR_VV = 0x2e1101d7u;	   // vxor.vv  v3, v1, v2
constexpr u32 INSN_VMIN_VV = 0x161101d7u;	   // vmin.vv  v3, v1, v2
constexpr u32 INSN_VADD_VV = 0x021101d7u;	   // vadd.vv  v3, v1, v2

// The two words the frozen S1.1-fix1 guest ELF actually contains (SHA-256
// 67fb07833ed040f7d318c20a85a123ac86d3269bc7ba8a5f4f1ef62c2563cb34, per the accepted S2.0 audit).
// Included so the route is tied to the real workload's encodings, not only to synthetic register
// choices. BOTH are the vd==vs2 overlap, which is the case where writing a destination before
// reading the other source would silently corrupt the minuend.
constexpr u32 INSN_VSUB_VV_S11_KERN = 0x0a848457u; // vsub.vv v8, v8, v9   (kern_sub, x8 unrolled)
constexpr u32 INSN_VSUB_VV_S11_MIX = 0x0a850457u;  // vsub.vv v8, v8, v10  (kern_mix)

constexpr u32 VS2_REG = 1; // v1
constexpr u32 VS1_REG = 2; // v2
constexpr u32 VD_REG = 3;  // v3

// ---------------------------------------------------------------------------------------------
// 1. Decoder admission table.
// ---------------------------------------------------------------------------------------------

// Minimal Decoder Provider whose `_##name` members are the Op enum values themselves, so
// Decoder<>::Decode returns the decoded opcode directly. The decoder template is shared with the
// interpreter and the translator, so this exercises the real routing rule, not a copy of it.
struct OpProvider {
#define OP(name, format_, flags_) static constexpr rv32::insn::Op _##name = rv32::insn::Op::_##name;
	RV32_OPCODE_LIST()
#undef OP
};

rv32::insn::Op DecodeWord(u32 word)
{
	u32 w = word;
	return rv32::insn::Decoder<OpProvider>::Decode(&w);
}

char const *OpName(rv32::insn::Op op)
{
	using Op32 = rv32::insn::Op;
	switch (op) {
	case Op32::_vsub_vv:
		return "vsub_vv";
	case Op32::_vialu:
		return "vialu";
	case Op32::_vadd_vv:
		return "vadd_vv";
	case Op32::_vsatadd:
		return "vsatadd";
	default:
		return "other";
	}
}

void CheckDecoder()
{
	printf("  decoder: exact unmasked vsub.vv -> Op::_vsub_vv, everything else unchanged\n");
	using Op32 = rv32::insn::Op;

	struct Row {
		char const *name;
		u32 word;
		Op32 want;
	};
	// The vsub.vv operand shapes this route admits all decode to the new op; every other row is a
	// shape the route must NOT capture, and each names the axis it varies.
	Row const rows[] = {
	    {"vsub.vv v3,v1,v2", INSN_VSUB_VV, Op32::_vsub_vv},
	    {"vsub.vv v3,v2,v1 (swapped)", INSN_VSUB_VV_SWAPPED, Op32::_vsub_vv},
	    {"vsub.vv vd==vs2", INSN_VSUB_VV_D_EQ_S2, Op32::_vsub_vv},
	    {"vsub.vv vd==vs1", INSN_VSUB_VV_D_EQ_S1, Op32::_vsub_vv},
	    {"vsub.vv vd==vs1==vs2", INSN_VSUB_VV_ALL_SAME, Op32::_vsub_vv},
	    {"vsub.vv (S1.1 kern_sub word)", INSN_VSUB_VV_S11_KERN, Op32::_vsub_vv},
	    {"vsub.vv (S1.1 kern_mix word)", INSN_VSUB_VV_S11_MIX, Op32::_vsub_vv},
	    // vm axis: a masked vsub.vv keeps the family handler.
	    {"vsub.vv masked (vm=0)", INSN_VSUB_VV_MASKED, Op32::_vialu},
	    // funct3 axis: the .vx form is OPIVX, a different group entirely.
	    {"vsub.vx", INSN_VSUB_VX, Op32::_vialu},
	    // funct6 axis: the reverse-subtract and the rest of the integer ALU family.
	    {"vrsub.vx", INSN_VRSUB_VX, Op32::_vialu},
	    // S2.2 gave vxor.vv its own decode family, S2.3 gave vor.vv one and S2.4 gave vand.vv one,
	    // exactly as S2.1 did for vsub.vv -- so all three of the bitwise .vv encodings have left
	    // the generic family. What THIS file has to assert about them is unchanged in substance --
	    // the sub route must not capture any of them -- so the expectations are updated to the
	    // encodings' real destinations rather than dropped. Their own routes are covered by
	    // vxorvv_/vorvv_/vandvv_typedchunk_route_test.
	    {"vand.vv", INSN_VAND_VV, Op32::_vand_vv},
	    {"vor.vv", INSN_VOR_VV, Op32::_vor_vv},
	    {"vxor.vv", INSN_VXOR_VV, Op32::_vxor_vv},
	    {"vmin.vv", INSN_VMIN_VV, Op32::_vialu},
	    // A DIFFERENT family whose mnemonic also says "sub": saturating subtract must not be
	    // captured by a funct6 test that was written too loosely.
	    {"vssub.vv", INSN_VSSUB_VV, Op32::_vsatadd},
	    // The pre-existing split this one is modelled on must be untouched.
	    {"vadd.vv", INSN_VADD_VV, Op32::_vadd_vv},
	};
	for (auto const &r : rows) {
		Op32 const got = DecodeWord(r.word);
		CHECK(got == r.want);
		if (got != r.want) {
			fprintf(stderr, "  decoder: %s (0x%08x) decoded to op %u (%s), expected %u (%s)\n",
				r.name, r.word, (unsigned)got, OpName(got), (unsigned)r.want,
				OpName(r.want));
		} else {
			printf("    ok  %-30s 0x%08x -> %s\n", r.name, r.word, OpName(r.want));
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Translation harness.
// ---------------------------------------------------------------------------------------------

// Every config knob the route reads, set explicitly on every translation so no test can inherit
// another's global state. The defaults are the fully-open configuration; the fallback table below
// flips exactly one field at a time off it.
struct RouteConfig {
	bool typed_chunk_sub = true;
	bool force_emit = true; // see the file header HOST NOTE
	bool aot_use_llvm = false;
	// S3.10a. This field did not exist before the LLVM route did, and it has to now: `vsub.vv` has
	// TWO admission gates as of S3.10a (RvvQcgTypedSubChunkAdmit for pure QCG,
	// RvvLLVMSubChunkAdmit for LLVM/AOT), and the second one reads config::rvv_vector_ssa. Leaving
	// it out of this struct would have meant the route read a global this file never set, which is
	// exactly the state-leak the comment above this struct forbids.
	bool rvv_vector_ssa = false;
	bool rvv_verify = false;
	bool rvv_direct = true;
	u32 vlen_bits = 512;
	u32 vsetvli_word = INSN_VSETVLI_E32M1;
	u32 sub_word = INSN_VSUB_VV;
};

// One region containing exactly the translated vsetvli + vsub.vv pair. Region is arena-allocated,
// so `arena` must outlive it -- both are locals in the caller's own scope.
Region *TranslateOne(MemArena &arena, u32 words[2], RouteConfig const &cfg)
{
	config::rvv_qcg_typed_chunk_sub = cfg.typed_chunk_sub;
	config::rvv_qcg_typed_chunk_sub_force_emit = cfg.force_emit;
	config::aot_use_llvm = cfg.aot_use_llvm;
	config::rvv_vector_ssa = cfg.rvv_vector_ssa;
	config::rvv_verify = cfg.rvv_verify;
	config::rvv_direct = cfg.rvv_direct;
	config::vlen_bits = cfg.vlen_bits;
	// The vadd and vmul routes' own switches stay off throughout: this file must observe the sub
	// route in isolation, and leaving them on would make a stray add/mul frame indistinguishable
	// from a sub one.
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_diag_chunk = false;

	CompilerJob::IpRangesSet ranges = {{0u, 8u}}; // two 4-byte instructions at ip 0 and 4
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

Region *TranslateCfg(MemArena &arena, u32 words[2], RouteConfig const &cfg)
{
	words[0] = cfg.vsetvli_word;
	words[1] = cfg.sub_word;
	return TranslateOne(arena, words, cfg);
}

struct Group {
	unsigned n_begin = 0, n_end = 0;
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body; // strictly between begin and end, in construction (== emission) order
};

Group FindGroup(Region *region)
{
	Group g;
	bool open = false;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				++g.n_begin;
				g.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				continue;
			}
			if (op == Op::_rvvtypedchunkend) {
				++g.n_end;
				g.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
				open = false;
				continue;
			}
			if (open) {
				g.body.push_back(&ins);
			}
		}
	}
	return g;
}

unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			n += (ins.GetOpcode() == op);
		}
	}
	return n;
}

// Number of hcalls to one specific runtime stub -- the fallback evidence: a non-admitted vsub.vv
// must produce exactly one call to the PRE-EXISTING rv32_vialu helper, not to a new stub.
unsigned CountHcall(Region *region, RuntimeStubId stub)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() != Op::_hcall) {
				continue;
			}
			n += (static_cast<InstHcall *>(&ins)->stub == stub);
		}
	}
	return n;
}

// ---------------------------------------------------------------------------------------------
// 2. Constructed QIR: exact admitted shape, including operand order.
// ---------------------------------------------------------------------------------------------
void CheckRoute(char const *tag, u32 vlen_bits, u32 nchunks, u32 expect_vlmax, u32 sub_word,
		u32 vs2_reg, u32 vs1_reg, u32 vd_reg)
{
	printf("  %s: vlen=%u expect nchunks=%u vlmax=%u\n", tag, vlen_bits, nchunks, expect_vlmax);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.sub_word = sub_word;
	Region *region = TranslateCfg(arena, words, cfg);

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	if (!g.begin || !g.end) {
		fprintf(stderr, "  %s: wrong number of typed-chunk frames\n", tag);
		return;
	}

	CHECK_EQ(g.begin->n_typed, (u8)(4 * nchunks));
	CHECK_EQ(g.begin->vlmax, expect_vlmax);
	// The fallback is the PRE-EXISTING vialu helper on both frame nodes -- no new stub entered the
	// build with this route.
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vialu);
	CHECK(g.end->stub == RuntimeStubId::id_rv32_vialu);
	// And there is no leftover helper call for this instruction: the frame replaced it.
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vialu), 0u);

	CHECK_EQ(g.body.size(), (size_t)(4 * nchunks));
	if (g.body.size() != 4 * nchunks) {
		return;
	}

	// Load-major: all 2*nchunks source loads, then all nchunks subtracts, then all nchunks stores.
	// Construction order IS emission order (QSel and QRegAlloc walk each block in list order and
	// only insert around an instruction, never reorder one).
	bool shape_ok = true;
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[2 * c]->GetOpcode() == Op::_vstatechunkload;
		shape_ok = shape_ok && g.body[2 * c + 1]->GetOpcode() == Op::_vstatechunkload;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[2 * nchunks + c]->GetOpcode() == Op::_vchunksub;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[3 * nchunks + c]->GetOpcode() == Op::_vstatechunkstore;
	}
	CHECK(shape_ok);
	if (!shape_ok) {
		fprintf(stderr, "  %s: frame body is not load-major vchunksub\n", tag);
		return;
	}
	// The subtract is EXPLICIT in the IR, and it is not one of the sibling ops wearing a different
	// name.
	CHECK_EQ(CountOp(region, Op::_vchunksub), nchunks);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), 0u);
	CHECK_EQ(CountOp(region, Op::_vchunkmul), 0u);

	std::vector<u32> vregs;
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(g.body[2 * c]);
		auto *l_s1 = static_cast<InstVStateChunkLoad *>(g.body[2 * c + 1]);
		auto *sub = static_cast<InstVChunkSub *>(g.body[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(g.body[3 * nchunks + c]);

		// Exact low/high state windows, disjoint by construction: chunk c of register r covers
		// [r*128 + 64c, r*128 + 64c + 64).
		CHECK_EQ(l_s2->offs, ChunkOffs(vs2_reg, c));
		CHECK_EQ(l_s1->offs, ChunkOffs(vs1_reg, c));
		CHECK_EQ(store->offs, ChunkOffs(vd_reg, c));

		CHECK_EQ((u32)sub->sew_bytes, 4u);

		// Typed V512 values throughout, in the vector register class.
		CHECK(l_s2->o(0).IsVVPR() && l_s2->o(0).GetType() == VType::V512);
		CHECK(l_s1->o(0).IsVVPR() && l_s1->o(0).GetType() == VType::V512);
		CHECK(sub->o(0).IsVVPR() && sub->o(0).GetType() == VType::V512);
		CHECK(store->i(0).IsVVPR() && store->i(0).GetType() == VType::V512);

		// ORDERED per-chunk def-use. Unlike the accepted add/mul tests this is NOT an
		// order-independent match: input 0 is the minuend and must be the VS2 load, input 1 the
		// subtrahend and must be the VS1 load. `(ma==b && mb==a)` -- which those tests accept --
		// is a negated result here, so it must fail.
		u32 const a = l_s2->o(0).GetVVPR(), b = l_s1->o(0).GetVVPR();
		CHECK_EQ(sub->i(0).GetVVPR(), a);
		CHECK_EQ(sub->i(1).GetVVPR(), b);
		CHECK_EQ(store->i(0).GetVVPR(), sub->o(0).GetVVPR());

		vregs.push_back(a);
		vregs.push_back(b);
		vregs.push_back(sub->o(0).GetVVPR());
	}

	// No cross-chunk dependency: 3 fresh virtual values per chunk, all distinct. At nchunks=2 that
	// is 6, which is exactly "chunk 1 reuses nothing chunk 0 defined".
	std::sort(vregs.begin(), vregs.end());
	size_t const before = vregs.size();
	vregs.erase(std::unique(vregs.begin(), vregs.end()), vregs.end());
	CHECK_EQ(vregs.size(), before);
	CHECK_EQ(vregs.size(), (size_t)(3 * nchunks));

	printf("  %s: OK %u chunk(s), %zu distinct V512 values, minuend=in0, stub=rv32_vialu\n", tag,
	       nchunks, vregs.size());
}

// ---------------------------------------------------------------------------------------------
// 3. Fallback table: every forbidden shape keeps the helper.
// ---------------------------------------------------------------------------------------------
void CheckFallback(char const *why, RouteConfig const &cfg)
{
	MemArena arena(1u << 20);
	u32 words[2];
	Region *region = TranslateCfg(arena, words, cfg);

	unsigned const n_begin = CountOp(region, Op::_rvvtypedchunkbegin);
	unsigned const n_sub = CountOp(region, Op::_vchunksub);
	unsigned const n_load = CountOp(region, Op::_vstatechunkload);
	unsigned const n_store = CountOp(region, Op::_vstatechunkstore);
	unsigned const n_helper = CountHcall(region, RuntimeStubId::id_rv32_vialu);

	CHECK_EQ(n_begin, 0u);
	CHECK_EQ(n_sub, 0u);
	CHECK_EQ(n_load, 0u);
	CHECK_EQ(n_store, 0u);
	// Exactly one call to the pre-existing helper -- the instruction still executes, through the
	// path this build already had.
	CHECK_EQ(n_helper, 1u);

	printf("    %-46s typed=0 helper_hcalls=%u  %s\n", why, n_helper,
	       (n_begin == 0 && n_sub == 0 && n_helper == 1) ? "ok" : "FAIL");
}

void CheckFallbackTable()
{
	printf("  fallback: every forbidden shape keeps hcall[rv32_vialu]\n");

	{ // the route's own switch, default off
		RouteConfig c;
		c.typed_chunk_sub = false;
		CheckFallback("--rvv-qcg-typed-chunk-sub off (the default)", c);
	}
	{ // S3.10a REWRITE OF A NOW-FALSE ASSERTION.
	  //
	  // This row used to read "LLVM/AOT backend has no lowering for vchunksub", flip
	  // aot_use_llvm on, and assert the helper. That claim was true until S3.10a and is false
	  // now: llvmgen.cpp lowers vchunksub through TChunkAluLower, and RvvLLVMSubChunkAdmit
	  // admits the route. The single case would still have PASSED -- rvv_vector_ssa defaults
	  // off, so the LLVM gate declines -- which is precisely why it had to be rewritten rather
	  // than left alone: it would have kept reporting "no lowering exists" while testing
	  // "vector-SSA happens to be off".
	  //
	  // What is true, and what these two rows now assert, is that the LLVM route needs BOTH of
	  // its switches. Each row turns exactly one of them off. The POSITIVE case -- both on,
	  // route admitted -- is not assertable from this file, which only ever inspects QIR
	  // through the QCG lens; it is proved by qmc/llvmgen/vsubvv_typedchunk_llvm_test.cpp
	  // against the real llvm::Function.
		RouteConfig c;
		c.aot_use_llvm = true;
		c.rvv_vector_ssa = false;
		CheckFallback("LLVM backend without --rvv-vector-ssa", c);
	}
	{ // ... and with vector-SSA on but the route's OWN per-op switch off. This is the row that
	  // pins S3.10a's gate choice: --rvv-vector-ssa alone must NOT sweep vsub.vv into the route.
		RouteConfig c;
		c.aot_use_llvm = true;
		c.rvv_vector_ssa = true;
		c.typed_chunk_sub = false;
		CheckFallback("LLVM backend without --rvv-qcg-typed-chunk-sub", c);
	}
	{ // --rvv-verify cannot see emitted code
		RouteConfig c;
		c.rvv_verify = true;
		CheckFallback("rvv_verify", c);
	}
	{ // the direct-lowering master switch
		RouteConfig c;
		c.rvv_direct = false;
		CheckFallback("rvv_direct off", c);
	}
	{ // VLEN axis: not a whole number of 512-bit chunks
		for (u32 vlen : {128u, 256u}) {
			RouteConfig c;
			c.vlen_bits = vlen;
			char buf[64];
			snprintf(buf, sizeof(buf), "VLEN=%u (not 512/1024)", vlen);
			CheckFallback(buf, c);
		}
	}
	{ // SEW axis: only e32 is admitted by this checkpoint
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E64M1;
		CheckFallback("SEW=64 (e64,m1)", c);
	}
	{ // LMUL axis: a register group is more than one register
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E32M2;
		CheckFallback("LMUL=2 (e32,m2)", c);
	}
	{ // encoding axis. None of these reaches TRANSLATOR(vsub_vv): the masked/.vx/vmin rows stay in
	  // the generic vialu family, and since S2.2/S2.3/S2.4 vxor.vv, vor.vv and vand.vv all have
	  // translators of their OWN whose routes are switched off here, so they fall through to the
	  // same helper. Either way the whole-region result is what matters and it is the same -- no
	  // typed node, one vialu helper call.
		struct Row {
			char const *why;
			u32 word;
		} const rows[] = {
		    {"masked vsub.vv (vm=0)", INSN_VSUB_VV_MASKED},
		    {"vsub.vx", INSN_VSUB_VX},
		    {"vrsub.vx", INSN_VRSUB_VX},
		    {"vand.vv", INSN_VAND_VV},
		    {"vor.vv", INSN_VOR_VV},
		    {"vxor.vv", INSN_VXOR_VV},
		    {"vmin.vv", INSN_VMIN_VV},
		};
		for (auto const &r : rows) {
			RouteConfig c;
			c.sub_word = r.word;
			CheckFallback(r.why, c);
		}
	}
	{ // vssub.vv reaches a DIFFERENT family (vsatadd), so its helper is not rv32_vialu at all.
	  // Checked separately rather than folded into the table above, because asserting
	  // "one rv32_vialu hcall" for it would be wrong.
		MemArena arena(1u << 20);
		u32 words[2];
		RouteConfig c;
		c.sub_word = INSN_VSSUB_VV;
		Region *region = TranslateCfg(arena, words, c);
		unsigned const n_begin = CountOp(region, Op::_rvvtypedchunkbegin);
		unsigned const n_sub = CountOp(region, Op::_vchunksub);
		unsigned const n_vialu = CountHcall(region, RuntimeStubId::id_rv32_vialu);
		unsigned const n_vsatadd = CountHcall(region, RuntimeStubId::id_rv32_vsatadd);
		CHECK_EQ(n_begin, 0u);
		CHECK_EQ(n_sub, 0u);
		CHECK_EQ(n_vialu, 0u);
		CHECK_EQ(n_vsatadd, 1u);
		printf("    %-46s typed=0 vialu_hcalls=%u vsatadd_hcalls=%u  %s\n", "vssub.vv",
		       n_vialu, n_vsatadd,
		       (n_begin == 0 && n_sub == 0 && n_vialu == 0 && n_vsatadd == 1) ? "ok" : "FAIL");
	}
}

// ---------------------------------------------------------------------------------------------
// 4. Post-QRegAlloc allocation.
// ---------------------------------------------------------------------------------------------
void CheckRoutePostQRA(char const *tag, u32 vlen_bits, u32 nchunks)
{
	printf("  %s (post-QRA): vlen=%u nchunks=%u\n", tag, vlen_bits, nchunks);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	Region *region = TranslateCfg(arena, words, cfg);

	// Exactly the two passes qcg::GenerateCode runs before constructing QEmit (qcg.cpp). QEmit and
	// QCodegen are deliberately never constructed here, so no host code exists on any host.
	ArchTraits::init();
	qcg::MachineRegionInfo mri;
	qcg::QSelPass::run(region, &mri);
	qcg::QRegAllocPass::run(region);

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	if (!g.begin) {
		return;
	}

	std::vector<Inst *> typed_ops;
	std::vector<Inst *> frame_movs;
	for (auto *ins : g.body) {
		(ins->GetOpcode() == Op::_mov ? frame_movs : typed_ops).push_back(ins);
	}
	// A scalar spill/fill of the preceding vsetvli's dirty a0 global may legally land inside the
	// frame; a V512 mov may not -- that would be a vector spill, fill or cross-class copy.
	for (auto *ins : frame_movs) {
		auto *u = static_cast<InstUnop *>(ins);
		bool const is_v512 = u->o(0).GetType() == VType::V512 || u->i(0).GetType() == VType::V512;
		CHECK(!is_v512);
	}
	CHECK_EQ(typed_ops.size(), (size_t)(4 * nchunks));
	if (typed_ops.size() != 4 * nchunks) {
		return;
	}

	std::vector<RegN> pregs;
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c]);
		auto *l_s1 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c + 1]);
		auto *sub = static_cast<InstVChunkSub *>(typed_ops[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(typed_ops[3 * nchunks + c]);

		CHECK(sub->GetOpcode() == Op::_vchunksub);
		CHECK_EQ(l_s2->offs, ChunkOffs(VS2_REG, c));
		CHECK_EQ(l_s1->offs, ChunkOffs(VS1_REG, c));
		CHECK_EQ(store->offs, ChunkOffs(VD_REG, c));

		bool const allocated = l_s2->o(0).IsPVPR() && l_s1->o(0).IsPVPR() && sub->o(0).IsPVPR() &&
				       sub->i(0).IsPVPR() && sub->i(1).IsPVPR() && store->i(0).IsPVPR();
		CHECK(allocated);
		if (!allocated) {
			continue;
		}
		for (auto o : {l_s2->o(0), l_s1->o(0), sub->o(0)}) {
			CHECK(ArchTraits::VPR_POOL.Test(o.GetPVPR()));
			CHECK(!ArchTraits::VPR_FIXED.Test(o.GetPVPR()));
		}

		// ORDERED again, and for the same reason as in the QIR check: allocation must not have
		// permuted the operand slots. A chunk whose subtract resolved to the OTHER chunk's
		// physical register, or to its own two registers in the wrong order, fails here.
		CHECK_EQ(sub->i(0).GetPVPR(), l_s2->o(0).GetPVPR());
		CHECK_EQ(sub->i(1).GetPVPR(), l_s1->o(0).GetPVPR());
		CHECK_EQ(sub->o(0).GetPVPR(), store->i(0).GetPVPR());

		pregs.push_back(l_s2->o(0).GetPVPR());
		pregs.push_back(l_s1->o(0).GetPVPR());
		pregs.push_back(sub->o(0).GetPVPR());
	}

	std::sort(pregs.begin(), pregs.end());
	pregs.erase(std::unique(pregs.begin(), pregs.end()), pregs.end());
	CHECK_EQ(pregs.size(), (size_t)(3 * nchunks));

	printf("  %s: OK post-QRA distinct VPRs=%zu frame movs=%zu (zmm", tag, pregs.size(),
	       frame_movs.size());
	for (auto p : pregs) {
		printf(" %u", p);
	}
	printf(")\n");
}

// ---------------------------------------------------------------------------------------------
// 5. Real emission + independent disassembly.
// ---------------------------------------------------------------------------------------------

// AllocateCode NEVER mmaps: it resizes a vector and returns its data pointer. That is the
// structural guarantee behind "the emitted bytes are never executed".
struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override
	{
		return false; // jit_mode
	}
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
};

struct DecodedVec {
	enum class Kind { LOAD, SUB, STORE } kind;
	std::string mnemonic;
	unsigned dst{}, src0{}, src1{};
	i64 disp{};
	bool has_disp{};
};

// "zmm<N>" -> N, rejecting any unconsumed suffix so a partially-recognised operand is reported as
// unparsed rather than misread.
bool ParseZmm(std::string const &tok, unsigned *out)
{
	if (tok.size() < 4 || tok.compare(0, 3, "zmm") != 0) {
		return false;
	}
	size_t i = 3;
	if (!isdigit((unsigned char)tok[i])) {
		return false;
	}
	unsigned v = 0;
	while (i < tok.size() && isdigit((unsigned char)tok[i])) {
		v = v * 10 + (unsigned)(tok[i] - '0');
		++i;
	}
	*out = v;
	return i == tok.size();
}

// "ZMMWORD PTR [r13+0x<hex>]" -> disp. Only the r13-relative form is accepted: vstatechunkload and
// vstatechunkstore address CPUState through the fixed state register, never a guest address.
bool ParseZmmWordR13(std::string const &tok, i64 *disp)
{
	static std::string const prefix = "ZMMWORD PTR [r13";
	if (tok.size() <= prefix.size() || tok.compare(0, prefix.size(), prefix) != 0) {
		return false;
	}
	size_t i = prefix.size();
	bool const neg = tok[i] == '-';
	if (tok[i] != '+' && tok[i] != '-') {
		return false;
	}
	++i;
	if (tok.compare(i, 2, "0x") != 0) {
		return false;
	}
	i += 2;
	size_t const start = i;
	i64 v = 0;
	while (i < tok.size() && isxdigit((unsigned char)tok[i])) {
		char const c = (char)tolower((unsigned char)tok[i]);
		v = v * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
		++i;
	}
	if (i == start || i >= tok.size() || tok[i] != ']' || i + 1 != tok.size()) {
		return false;
	}
	*disp = neg ? -v : v;
	return true;
}

std::vector<std::string> SplitCommas(std::string const &s)
{
	std::vector<std::string> out;
	size_t start = 0;
	for (size_t i = 0; i <= s.size(); ++i) {
		if (i == s.size() || s[i] == ',') {
			out.push_back(s.substr(start, i - start));
			start = i + 1;
		}
	}
	return out;
}

// Parse one objdump Intel-syntax line. Only the two shapes this frame can emit are recognised: a
// two-operand vmovdqu64 against [r13+disp], and a three-register vpsubd. Anything else returns
// false; the caller decides whether that is a harmless scalar line or an unaccounted ZMM line.
//
// vpaddd and vpmulld are NOT recognised here on purpose. If the route ever emitted a sibling
// operation -- the exact confusion this checkpoint has to rule out -- it would arrive as an
// unrecognised ZMM-bearing line and fail loudly, rather than being silently accepted as "some
// vector op". The operand ORDER is preserved in src0/src1 exactly as objdump printed it, which is
// what section [7] then exchanges.
bool ParseLine(std::string const &line, DecodedVec *out)
{
	size_t const tab = line.find('\t');
	if (tab == std::string::npos) {
		return false;
	}
	std::string const rhs = line.substr(tab + 1);
	size_t const sp = rhs.find(' ');
	std::string const mnem = sp == std::string::npos ? rhs : rhs.substr(0, sp);
	std::string const operand_str = sp == std::string::npos ? std::string() : rhs.substr(sp + 1);
	auto const ops = SplitCommas(operand_str);

	if (mnem == "vmovdqu64" && ops.size() == 2) {
		unsigned zr;
		i64 disp;
		if (ParseZmm(ops[0], &zr) && ParseZmmWordR13(ops[1], &disp)) {
			*out = DecodedVec{DecodedVec::Kind::LOAD, mnem, zr, 0, 0, disp, true};
			return true;
		}
		if (ParseZmmWordR13(ops[0], &disp) && ParseZmm(ops[1], &zr)) {
			*out = DecodedVec{DecodedVec::Kind::STORE, mnem, 0, zr, 0, disp, true};
			return true;
		}
		return false;
	}
	if (mnem == "vpsubd" && ops.size() == 3) {
		unsigned d, s0, s1;
		if (ParseZmm(ops[0], &d) && ParseZmm(ops[1], &s0) && ParseZmm(ops[2], &s1)) {
			*out = DecodedVec{DecodedVec::Kind::SUB, mnem, d, s0, s1, 0, false};
			return true;
		}
	}
	return false;
}

bool MentionsZmm(std::string const &line)
{
	return line.find("zmm") != std::string::npos;
}

// Write `code` to a private temp file and disassemble it as a raw flat x86-64 binary with GNU
// objdump. Fails loudly rather than skipping: a missing disassembler means this checkpoint's
// emission evidence cannot be produced at all.
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_s21_emit_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "  mkstemp failed: %s\n", strerror(errno));
		return {};
	}
	size_t written = 0;
	while (written < code.size()) {
		ssize_t const n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) {
			fprintf(stderr, "  write to temp file failed: %s\n", strerror(errno));
			close(fd);
			unlink(path);
			return {};
		}
		written += (size_t)n;
	}
	close(fd);

	std::string const cmd =
	    std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path + " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) {
		fprintf(stderr, "  popen(objdump) failed: %s\n", strerror(errno));
		unlink(path);
		return {};
	}
	std::vector<std::string> lines;
	char buf[1024];
	std::string cur;
	while (fgets(buf, sizeof(buf), p)) {
		cur += buf;
		if (!cur.empty() && cur.back() == '\n') {
			cur.pop_back();
			lines.push_back(cur);
			cur.clear();
		}
	}
	if (!cur.empty()) {
		lines.push_back(cur);
	}
	int const rc = pclose(p);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
		fprintf(stderr, "  objdump did not exit cleanly (raw status %d)\n", rc);
		return {};
	}
	return lines;
}

// Emit one admitted vsub.vv through the real pipeline and return the decoded ZMM census, or an
// empty vector on any structural failure. `vecs` is in emission order.
std::vector<DecodedVec> EmitAndDecode(char const *tag, u32 vlen_bits, u32 nchunks, u32 sub_word,
				      MemArena &arena, u32 (&words)[2], Region **out_region,
				      TestCompilerRuntime &cr)
{
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.sub_word = sub_word;
	Region *region = TranslateCfg(arena, words, cfg);
	*out_region = region;

	qir::CodeSegment segment(0u, 0x1000u);
	auto const code_span = qcg::GenerateCode(&cr, &segment, region, 0);
	CHECK(!code_span.empty());
	if (code_span.empty()) {
		return {};
	}
	std::vector<u8> const code(code_span.begin(), code_span.end());

	auto const lines = Disassemble(code);
	CHECK(!lines.empty());
	if (lines.empty()) {
		return {};
	}

	// Every decoded line is accounted for. A line naming a ZMM register that ParseLine does not
	// recognise is a hard failure with the offending text, not a silent drop -- that is what makes
	// the counts below a census rather than a filter.
	std::vector<DecodedVec> vecs;
	for (auto const &l : lines) {
		DecodedVec dv{};
		if (ParseLine(l, &dv)) {
			vecs.push_back(dv);
			continue;
		}
		bool const is_scalar = !MentionsZmm(l);
		CHECK(is_scalar);
		if (!is_scalar) {
			fprintf(stderr, "  %s: unrecognized ZMM-bearing line: %s\n", tag, l.c_str());
		}
	}
	CHECK_EQ(vecs.size(), (size_t)(4 * nchunks));
	if (vecs.size() != 4 * nchunks) {
		for (auto const &l : lines) {
			fprintf(stderr, "    %s\n", l.c_str());
		}
		return {};
	}
	return vecs;
}

void CheckRouteEmitted(char const *tag, u32 vlen_bits, u32 nchunks, u32 sub_word, u32 vs2_reg,
		       u32 vs1_reg, u32 vd_reg)
{
	printf("  %s (emitted): vlen=%u nchunks=%u\n", tag, vlen_bits, nchunks);

	MemArena arena(1u << 20);
	u32 words[2];
	TestCompilerRuntime cruntime;
	Region *region = nullptr;
	auto const vecs =
	    EmitAndDecode(tag, vlen_bits, nchunks, sub_word, arena, words, &region, cruntime);
	if (vecs.empty()) {
		return;
	}

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	if (!g.begin) {
		return;
	}
	CHECK_EQ(g.begin->n_typed, (u8)(4 * nchunks));
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vialu);

	std::vector<Inst *> typed_ops;
	for (auto *ins : g.body) {
		if (ins->GetOpcode() != Op::_mov) {
			typed_ops.push_back(ins);
		}
	}
	CHECK_EQ(typed_ops.size(), (size_t)(4 * nchunks));
	if (typed_ops.size() != 4 * nchunks) {
		return;
	}

	for (size_t i = 0; i < vecs.size(); ++i) {
		auto const &v = vecs[i];
		switch (v.kind) {
		case DecodedVec::Kind::LOAD:
			printf("  %s: vec[%zu] LOAD  %s zmm%u <- [r13+0x%llx]\n", tag, i, v.mnemonic.c_str(),
			       v.dst, (unsigned long long)v.disp);
			break;
		case DecodedVec::Kind::SUB:
			printf("  %s: vec[%zu] SUB   %s zmm%u <- zmm%u, zmm%u\n", tag, i, v.mnemonic.c_str(),
			       v.dst, v.src0, v.src1);
			break;
		case DecodedVec::Kind::STORE:
			printf("  %s: vec[%zu] STORE %s [r13+0x%llx] <- zmm%u\n", tag, i,
			       v.mnemonic.c_str(), (unsigned long long)v.disp, v.src0);
			break;
		}
	}

	bool shape_ok = true;
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[2 * c].kind == DecodedVec::Kind::LOAD;
		shape_ok = shape_ok && vecs[2 * c + 1].kind == DecodedVec::Kind::LOAD;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[2 * nchunks + c].kind == DecodedVec::Kind::SUB;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[3 * nchunks + c].kind == DecodedVec::Kind::STORE;
	}
	CHECK(shape_ok);
	if (!shape_ok) {
		fprintf(stderr, "  %s: decoded order is not load-major\n", tag);
		return;
	}

	std::vector<unsigned> chunk_regs[2];
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c]);
		auto *l_s1 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c + 1]);
		auto *sub = static_cast<InstVChunkSub *>(typed_ops[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(typed_ops[3 * nchunks + c]);
		auto const &d_l_s2 = vecs[2 * c];
		auto const &d_l_s1 = vecs[2 * c + 1];
		auto const &d_sub = vecs[2 * nchunks + c];
		auto const &d_store = vecs[3 * nchunks + c];

		bool const ok = l_s2->o(0).IsPVPR() && l_s1->o(0).IsPVPR() && sub->o(0).IsPVPR() &&
				store->i(0).IsPVPR();
		CHECK(ok);
		if (!ok) {
			continue;
		}

		CHECK_EQ((u32)d_l_s2.dst, (u32)l_s2->o(0).GetPVPR());
		CHECK(d_l_s2.has_disp);
		CHECK_EQ(d_l_s2.disp, (i64)ChunkOffs(vs2_reg, c));
		CHECK_EQ((u32)d_l_s1.dst, (u32)l_s1->o(0).GetPVPR());
		CHECK(d_l_s1.has_disp);
		CHECK_EQ(d_l_s1.disp, (i64)ChunkOffs(vs1_reg, c));

		// The emitted operation is the packed 32-bit SUBTRACT, at the exact allocated registers.
		CHECK(d_sub.mnemonic == "vpsubd");
		CHECK_EQ((u32)d_sub.dst, (u32)sub->o(0).GetPVPR());

		// THE ORDER GATE, from independently decoded bytes. `vpsubd d, s0, s1` is d = s0 - s1,
		// so s0 must be the register the VS2 window was loaded into and s1 the VS1 one. An
		// emitter that swapped them would still pass every other check in this function.
		CHECK_EQ(d_sub.src0, d_l_s2.dst);
		CHECK_EQ(d_sub.src1, d_l_s1.dst);
		if (d_sub.src0 != d_l_s2.dst || d_sub.src1 != d_l_s1.dst) {
			fprintf(stderr,
				"  %s: chunk %u decoded `vpsubd zmm%u,zmm%u,zmm%u`; minuend (vs2 window "
				"0x%llx) is zmm%u and subtrahend (vs1 window 0x%llx) is zmm%u\n",
				tag, c, d_sub.dst, d_sub.src0, d_sub.src1,
				(unsigned long long)d_l_s2.disp, d_l_s2.dst,
				(unsigned long long)d_l_s1.disp, d_l_s1.dst);
		}

		CHECK_EQ((u32)d_store.src0, (u32)d_sub.dst);
		CHECK(d_store.has_disp);
		CHECK_EQ(d_store.disp, (i64)ChunkOffs(vd_reg, c));

		if (c < 2) {
			chunk_regs[c] = {d_l_s2.dst, d_l_s1.dst, d_sub.dst};
		}
	}

	// No artificial cross-chunk dependency, re-derived from the externally decoded bytes: no
	// register named anywhere in chunk 0 is named anywhere in chunk 1.
	if (nchunks == 2) {
		bool disjoint = true;
		for (auto r0 : chunk_regs[0]) {
			for (auto r1 : chunk_regs[1]) {
				disjoint = disjoint && r0 != r1;
			}
		}
		CHECK(disjoint);
		printf("  %s: chunk0 zmm{%u,%u,%u} chunk1 zmm{%u,%u,%u} disjoint=%d\n", tag,
		       chunk_regs[0][0], chunk_regs[0][1], chunk_regs[0][2], chunk_regs[1][0],
		       chunk_regs[1][1], chunk_regs[1][2], (int)disjoint);
	}

	unsigned n_sub = 0, n_sibling = 0;
	for (auto const &v : vecs) {
		n_sub += (v.kind == DecodedVec::Kind::SUB);
		n_sibling += (v.mnemonic == "vpaddd" || v.mnemonic == "vpmulld");
	}
	CHECK_EQ(n_sub, nchunks);
	CHECK_EQ(n_sibling, 0u);

	printf("  %s: OK objdump-decoded %zu/%u zmm instructions, %u vpsubd (minuend first), "
	       "0 vpaddd/vpmulld, bytes never executed\n",
	       tag, vecs.size(), 4 * nchunks, n_sub);
}

// ---------------------------------------------------------------------------------------------
// 6. Legal operand overlap.
// ---------------------------------------------------------------------------------------------

// For each legal overlap, re-run the QIR shape check with that encoding's own source registers, and
// then assert the property the overlap actually depends on: within the frame, EVERY
// vstatechunkload precedes EVERY vstatechunkstore. That is what makes a destination that aliases a
// source read pre-instruction bytes.
void CheckOverlap(char const *tag, u32 vlen_bits, u32 nchunks, u32 expect_vlmax, u32 word, u32 vs2,
		  u32 vs1, u32 vd)
{
	CheckRoute(tag, vlen_bits, nchunks, expect_vlmax, word, vs2, vs1, vd);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.sub_word = word;
	Region *region = TranslateCfg(arena, words, cfg);

	Group g = FindGroup(region);
	if (!g.begin) {
		return;
	}
	int last_load = -1, first_store = -1;
	for (size_t i = 0; i < g.body.size(); ++i) {
		if (g.body[i]->GetOpcode() == Op::_vstatechunkload) {
			last_load = (int)i;
		}
		if (g.body[i]->GetOpcode() == Op::_vstatechunkstore && first_store < 0) {
			first_store = (int)i;
		}
	}
	CHECK(last_load >= 0 && first_store >= 0);
	CHECK(last_load < first_store);
	printf("  %s: OK all %d loads precede the first store (idx %d < %d)\n", tag,
	       (int)(2 * nchunks), last_load, first_store);
}

// ---------------------------------------------------------------------------------------------
// 7. Operand-role exchange: the falsifiability proof for every "minuend first" check above.
// ---------------------------------------------------------------------------------------------
//
// Translate two guest words that differ ONLY by exchanging vs2 and vs1:
//
//     vsub.vv v3, v1, v2   =>  v3 = v1 - v2
//     vsub.vv v3, v2, v1   =>  v3 = v2 - v1
//
// and require the decoded `vpsubd`'s FIRST source to follow the exchange -- i.e. to trace to v1's
// state window in the first case and to v2's in the second. This is what makes the order checks
// falsifiable rather than tautological: an emitter that always emitted (vs1, vs2) would produce two
// frames whose first source traced to the SAME architectural register for both words, and this
// function is the only one in the file that would notice.
void CheckOperandRoleExchange(u32 vlen_bits, u32 nchunks)
{
	printf("  operand-role exchange: vlen=%u\n", vlen_bits);

	struct Arm {
		char const *tag;
		u32 word;
		u32 vs2, vs1;
	} const arms[] = {
	    {"v3 = v1 - v2", INSN_VSUB_VV, 1, 2},
	    {"v3 = v2 - v1", INSN_VSUB_VV_SWAPPED, 2, 1},
	};

	i64 first_src_window[2] = {-1, -1};
	for (unsigned a = 0; a < 2; ++a) {
		MemArena arena(1u << 20);
		u32 words[2];
		TestCompilerRuntime cruntime;
		Region *region = nullptr;
		auto const vecs = EmitAndDecode(arms[a].tag, vlen_bits, nchunks, arms[a].word, arena,
						words, &region, cruntime);
		if (vecs.empty()) {
			return;
		}
		// Chunk 0's two loads and its subtract, by the load-major layout already gated above.
		auto const &d_l_s2 = vecs[0];
		auto const &d_l_s1 = vecs[1];
		auto const &d_sub = vecs[2 * nchunks];
		CHECK(d_sub.kind == DecodedVec::Kind::SUB);
		CHECK(d_l_s2.kind == DecodedVec::Kind::LOAD && d_l_s1.kind == DecodedVec::Kind::LOAD);
		if (d_sub.kind != DecodedVec::Kind::SUB) {
			return;
		}

		// Which architectural register did the FIRST source of the emitted subtract come from?
		// Answered from the decoded displacement, not from the QIR, so this cannot agree with the
		// translator by construction.
		i64 win = -1;
		if (d_sub.src0 == d_l_s2.dst) {
			win = d_l_s2.disp;
		} else if (d_sub.src0 == d_l_s1.dst) {
			win = d_l_s1.disp;
		}
		CHECK(win >= 0);
		first_src_window[a] = win;
		CHECK_EQ(win, (i64)ChunkOffs(arms[a].vs2, 0));
		printf("    %-14s vpsubd zmm%u,zmm%u,zmm%u  first source loaded from [r13+0x%llx] "
		       "(v%u window 0x%x)\n",
		       arms[a].tag, d_sub.dst, d_sub.src0, d_sub.src1, (unsigned long long)win,
		       arms[a].vs2, ChunkOffs(arms[a].vs2, 0));
	}

	// The two arms must NOT agree: that is the whole content of the check.
	CHECK(first_src_window[0] != first_src_window[1]);
	printf("    exchange observed: 0x%llx vs 0x%llx -- the minuend follows vs2, not a fixed slot\n",
	       (unsigned long long)first_src_window[0], (unsigned long long)first_src_window[1]);
}

} // namespace

int main()
{
	printf("S2.1 vsub.vv typed V512 chunk route\n");

	printf("[1] decoder\n");
	CheckDecoder();

	printf("[2] constructed QIR\n");
	CheckRoute("vlen512", 512, 1, 16, INSN_VSUB_VV, VS2_REG, VS1_REG, VD_REG);
	CheckRoute("vlen1024", 1024, 2, 32, INSN_VSUB_VV, VS2_REG, VS1_REG, VD_REG);

	// The frozen S1.1-fix1 workload's own words, at both admitted widths.
	CheckRoute("s11-kern_sub word vlen512", 512, 1, 16, INSN_VSUB_VV_S11_KERN, 8, 9, 8);
	CheckRoute("s11-kern_sub word vlen1024", 1024, 2, 32, INSN_VSUB_VV_S11_KERN, 8, 9, 8);
	CheckRoute("s11-kern_mix word vlen512", 512, 1, 16, INSN_VSUB_VV_S11_MIX, 8, 10, 8);
	CheckRoute("s11-kern_mix word vlen1024", 1024, 2, 32, INSN_VSUB_VV_S11_MIX, 8, 10, 8);

	printf("[3] fallback table\n");
	CheckFallbackTable();

	printf("[4] post-QRegAlloc\n");
	CheckRoutePostQRA("vlen512", 512, 1);
	CheckRoutePostQRA("vlen1024", 1024, 2);

	printf("[5] emitted host code\n");
	CheckRouteEmitted("vlen512", 512, 1, INSN_VSUB_VV, VS2_REG, VS1_REG, VD_REG);
	CheckRouteEmitted("vlen1024", 1024, 2, INSN_VSUB_VV, VS2_REG, VS1_REG, VD_REG);
	CheckRouteEmitted("s11-kern_sub vlen512", 512, 1, INSN_VSUB_VV_S11_KERN, 8, 9, 8);
	CheckRouteEmitted("s11-kern_sub vlen1024", 1024, 2, INSN_VSUB_VV_S11_KERN, 8, 9, 8);
	CheckRouteEmitted("s11-kern_mix vlen1024", 1024, 2, INSN_VSUB_VV_S11_MIX, 8, 10, 8);

	printf("[6] legal operand overlap\n");
	CheckOverlap("vd==vs2 vlen1024", 1024, 2, 32, INSN_VSUB_VV_D_EQ_S2, VD_REG, VS1_REG, VD_REG);
	CheckOverlap("vd==vs1 vlen1024", 1024, 2, 32, INSN_VSUB_VV_D_EQ_S1, VS2_REG, VD_REG, VD_REG);
	CheckOverlap("vd==vs1==vs2 vlen1024", 1024, 2, 32, INSN_VSUB_VV_ALL_SAME, VD_REG, VD_REG, VD_REG);
	// The overlap the frozen workload actually contains, at both widths.
	CheckOverlap("s11 vd==vs2 vlen512", 512, 1, 16, INSN_VSUB_VV_S11_KERN, 8, 9, 8);
	CheckOverlap("s11 vd==vs2 vlen1024", 1024, 2, 32, INSN_VSUB_VV_S11_KERN, 8, 9, 8);

	printf("[7] operand-role exchange (falsifiability of every order check above)\n");
	CheckOperandRoleExchange(512, 1);
	CheckOperandRoleExchange(1024, 2);

	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("OK: all checks passed\n");
	return 0;
}
