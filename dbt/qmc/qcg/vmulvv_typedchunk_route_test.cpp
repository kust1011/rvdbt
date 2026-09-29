// P3.5a / HM.2a: the exact unmasked `vmul.vv` typed V512 chunk route, verified mechanically at
// four levels -- decoder, constructed QIR, post-QRegAlloc allocation, and independently
// disassembled emitted host bytes -- at EVERY chunk count the generic rule produces.
//
// WHAT HM.2a ADDED, AND WHAT IT DID NOT
//
// P3.5a covered VLEN 512 and 1024, i.e. k=1 and k=2. HM.2a raised VLEN_MAX to 4096 and replaced
// the route's two-value VLEN test with RvvGenericChunkShapeAdmit's computed count -- after
// whole-chunk admission, `k = VLEN / 512`, an exact divide on a domain that refuses any VLEN which
// is not a whole number of host chunks, so no partial tail chunk exists at any width and none is
// claimed. The same route now reaches k=4 and k=8. Every check below that took a
// `nchunks` parameter was ALREADY written for a general k; the substantive HM.2a work in this file
// is (a) running all of them at 2048 and 4096, (b) turning the two k=2-only assertions -- the
// disjointness check and the two-element `chunk_regs` array -- into general ones, (c) asserting
// the lane partition rather than only the byte windows, and (d) emitting the certificate below.
//
// THE CERTIFICATE (RVV_RESEARCH_EXECUTION_PLAN_V10 section 3.1). `[8] certificate` prints one
// machine-readable `CERT,` row per chunk, carrying operation id, chunk id, lane range, byte
// window, def-use and the group's barrier/fallback identity. Nothing in production emits this: the
// row is DERIVED here from the QIR the production lowering built, which is the claim being made --
// that the independence certificate is already recoverable from the frame, not that rvdbt was
// taught to print one. An experiment-package parser re-checks completeness and disjointness from
// this text without trusting the assertions in this file.
//
// WHAT THIS FILE PROVES
//
//   1. DECODER. Exactly one encoding class reaches the new op: OP-V / funct3=OPMVV /
//      funct6=VF6_VMUL / vm=1. Masked vmul.vv, vmul.vx, and the rest of the vimul family
//      (vmulh/vmulhu/vmulhsu/vdiv/vrem/vmacc) all still reach Op::_vimul, and vadd.vv still
//      reaches Op::_vadd_vv. The family is NOT hijacked.
//   2. QIR. The admitted instruction becomes exactly k 512-bit chunks (4k typed ops) at VLEN
//      512/1024/2048/4096 -> k = 1/2/4/8, in load-major order, at the exact 64-byte CPUState
//      windows, with per-chunk def-use and no cross-chunk edge, and the k chunks tile the live
//      VLEN/8 bytes and the [0, VLMAX) lane range exactly once. The body op is Op::_vchunkmul with
//      sew_bytes=4 -- the multiply is explicit in the IR, not folded into a generic ALU node.
//   3. FALLBACK. Every forbidden shape keeps the pre-existing helper: zero typed nodes and one
//      `hcall [rv32_vimul]`. Each forbidden condition is exercised on its own axis, so a single
//      over-broad admission cannot hide behind another still-closed gate. HM.2a adds the two axes
//      the generic rule introduced: a VLEN that is not a whole number of host chunks, and a VLEN
//      whose k exceeds the fixed arrays' bound.
//   4. QRA. 3k distinct physical VPRs, all out of VPR_POOL, with per-chunk def-use surviving
//      allocation and no allocator-inserted V512 mov inside the frame -- including at k=8, where
//      24 simultaneous chunk values are live against a 30-register pool.
//   5. QEMIT. The real qcg::GenerateCode pipeline emits `vpmulld` (not vpaddd, not a scalar
//      sequence), exactly k of them per guest multiply, with the exact allocated ZMM operands and
//      the exact state displacements, and the k chunks' register sets are pairwise disjoint in the
//      externally decoded bytes.
//   6. OVERLAP. vd==vs2, vd==vs1 and vd==vs1==vs2 each still emit both of a chunk's source loads
//      before that chunk's destination store, which is what makes the legal overlaps correct.
//   7. THE REAL KERNEL. The frozen HM.2a microkernel's own strip-step body -- its vsetvli, two
//      vle32.v, EIGHT vmul.vv and vse32.v, as the words appear in the guest ELF -- is translated
//      as one region at each k, so "one guest operation becomes k chunks" is checked over eight
//      real consecutive operations rather than over one synthetic word.
//
// WHAT IT DELIBERATELY NEVER DOES
//
//   * It never executes the emitted bytes. TestCompilerRuntime::AllocateCode resizes a
//     std::vector<u8> and returns its data pointer -- there is no mmap in this object's lifetime,
//     let alone a PROT_EXEC one. This matters more at HM.2a than it did at P3.5a: the development
//     host is an Ivy Bridge i7-3770 with no AVX-512 at all, so these bytes could not be executed
//     here even deliberately, and HM.2a makes no dynamic claim about them.
//   * It never runs a guest program, never times anything, and makes no performance claim.
//
// HOST NOTE. RvvQcgTypedMulChunkAdmit's host-feature row is a real __builtin_cpu_supports probe,
// so on a machine without AVX-512F the route would fail closed and there would be nothing to
// inspect. `config::rvv_qcg_typed_chunk_mul_force_emit` bypasses ONLY that probe -- not the
// architectural guard, not the admitted shape -- which is exactly what lets the emitted shape be
// audited here. This is the same device the accepted C2.3a vadd audit used.
//
// INSTRUCTION WORDS. Every encoding below was produced by an explicit field-assembly of the RVV
// 1.0 OP-V layout and then independently round-tripped through `llvm-mc --disassemble
// -triple=riscv32 -mattr=+v`, so the constants are not hand-transcribed hex.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
// For rvvrun::kMaxChunks: the fallback table's high-VLEN axis names the bound the generic rule is
// checked against, rather than repeating the number.
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
// qir::PrinterPass::run(Region*) is available in every build -- only the LogStream overload is
// debug-only -- so the QIR artifact below is produced by the SAME Release binary that runs the
// assertions, not by a separate debug build whose translator would have to be argued equivalent.
#include "dbt/qmc/qir_printer.h"

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

// Chunk c is bytes [64c, 64c+64) of a register's own VLEN_MAX_BYTES slot -- the exact
// `r*VLEN_MAX_BYTES + chunk*64` formula RvvEmitTypedMulChunkGroup uses. At k=1 that is the whole
// live register; at k=8 the eight windows tile it.
constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u;
}

// The chunk count the generic rule must produce for a VLEN, computed here INDEPENDENTLY of
// RvvGenericChunkShapeAdmit so the test is not checking the implementation against itself.
constexpr u32 ExpectChunks(u32 vlen_bits) { return vlen_bits / 512u; }

// Lanes one 512-bit chunk carries at a given SEW, and the guest lane range chunk c owns. The
// certificate's lane_begin/lane_end and the "the k chunks partition [0, VLMAX)" assertion are both
// built from these two, not from anything the lowering said.
constexpr u32 LanesPerChunk(u32 sew_bytes) { return 64u / sew_bytes; }

// ---------------------------------------------------------------------------------------------
// Instruction words. Each is annotated with the disassembly llvm-mc independently produced for it.
// ---------------------------------------------------------------------------------------------
constexpr u32 INSN_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_E64M1 = 0x0d857557u; // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 INSN_VSETVLI_E32M2 = 0x0d157557u; // vsetvli a0, a0, e32, m2, ta, ma

constexpr u32 INSN_VMUL_VV = 0x961121d7u;	   // vmul.vv    v3, v1, v2
constexpr u32 INSN_VMUL_VV_D_EQ_S2 = 0x963121d7u;  // vmul.vv    v3, v3, v2   (vd == vs2)
constexpr u32 INSN_VMUL_VV_D_EQ_S1 = 0x9611a1d7u;  // vmul.vv    v3, v1, v3   (vd == vs1)
constexpr u32 INSN_VMUL_VV_ALL_SAME = 0x9631a1d7u; // vmul.vv    v3, v3, v3   (vd == vs1 == vs2)
constexpr u32 INSN_VMUL_VV_MASKED = 0x941121d7u;   // vmul.vv    v3, v1, v2, v0.t
constexpr u32 INSN_VMUL_VX = 0x961161d7u;	   // vmul.vx    v3, v1, sp
constexpr u32 INSN_VMULH_VV = 0x9e1121d7u;	   // vmulh.vv   v3, v1, v2
constexpr u32 INSN_VMULHU_VV = 0x921121d7u;	   // vmulhu.vv  v3, v1, v2
constexpr u32 INSN_VMULHSU_VV = 0x9a1121d7u;	   // vmulhsu.vv v3, v1, v2
constexpr u32 INSN_VDIV_VV = 0x861121d7u;	   // vdiv.vv    v3, v1, v2
constexpr u32 INSN_VMACC_VV = 0xb61121d7u;	   // vmacc.vv   v3, v2, v1
constexpr u32 INSN_VADD_VV = 0x021101d7u;	   // vadd.vv    v3, v1, v2

// The word the P3.2-accepted guest ELF actually contains (all eight of its vmul.vv are this
// single word, per the accepted P3.4 audit). Included so the route is tied to the real kernel's
// encoding, not only to synthetic register choices: vd=v8, vs2=v8, vs1=v9 -- which is also the
// vd==vs2 overlap.
constexpr u32 INSN_VMUL_VV_P3_KERNEL = 0x9684a457u; // vmul.vv v8, v8, v9

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

void CheckDecoder()
{
	printf("  decoder: exact unmasked vmul.vv -> Op::_vmul_vv, everything else unchanged\n");
	using Op32 = rv32::insn::Op;

	struct Row {
		char const *name;
		u32 word;
		Op32 want;
	};
	// The four vmul.vv operand shapes this route admits all decode to the new op; every other
	// row is a shape the route must NOT capture, and each names the axis it varies.
	Row const rows[] = {
	    {"vmul.vv v3,v1,v2", INSN_VMUL_VV, Op32::_vmul_vv},
	    {"vmul.vv vd==vs2", INSN_VMUL_VV_D_EQ_S2, Op32::_vmul_vv},
	    {"vmul.vv vd==vs1", INSN_VMUL_VV_D_EQ_S1, Op32::_vmul_vv},
	    {"vmul.vv vd==vs1==vs2", INSN_VMUL_VV_ALL_SAME, Op32::_vmul_vv},
	    {"vmul.vv (P3.2 guest ELF)", INSN_VMUL_VV_P3_KERNEL, Op32::_vmul_vv},
	    // vm axis: a masked vmul.vv keeps the family handler.
	    {"vmul.vv masked (vm=0)", INSN_VMUL_VV_MASKED, Op32::_vimul},
	    // funct3 axis: the .vx form is OPMVX, a different group entirely.
	    {"vmul.vx", INSN_VMUL_VX, Op32::_vimul},
	    // funct6 axis: the high-half, divide, remainder and accumulate members of the family.
	    {"vmulh.vv", INSN_VMULH_VV, Op32::_vimul},
	    {"vmulhu.vv", INSN_VMULHU_VV, Op32::_vimul},
	    {"vmulhsu.vv", INSN_VMULHSU_VV, Op32::_vimul},
	    {"vdiv.vv", INSN_VDIV_VV, Op32::_vimul},
	    {"vmacc.vv", INSN_VMACC_VV, Op32::_vimul},
	    // The pre-existing split this one is modelled on must be untouched.
	    {"vadd.vv", INSN_VADD_VV, Op32::_vadd_vv},
	};
	for (auto const &r : rows) {
		Op32 const got = DecodeWord(r.word);
		CHECK(got == r.want);
		if (got != r.want) {
			fprintf(stderr, "  decoder: %s (0x%08x) decoded to op %u, expected %u\n", r.name,
				r.word, (unsigned)got, (unsigned)r.want);
		} else {
			printf("    ok  %-24s 0x%08x -> %s\n", r.name, r.word,
			       r.want == Op32::_vmul_vv ? "vmul_vv"
							: (r.want == Op32::_vimul ? "vimul" : "vadd_vv"));
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Translation harness.
// ---------------------------------------------------------------------------------------------

// Every config knob the route reads, set explicitly on every translation so no test can inherit
// another's global state. `admit_all` is the fully-open configuration; the fallback table below
// flips exactly one field at a time off it.
struct RouteConfig {
	bool typed_chunk_mul = true;
	bool force_emit = true; // see the file header HOST NOTE
	bool aot_use_llvm = false;
	bool rvv_verify = false;
	bool rvv_direct = true;
	u32 vlen_bits = 512;
	u32 vsetvli_word = INSN_VSETVLI_E32M1;
	u32 mul_word = INSN_VMUL_VV;
};

// One region containing exactly `n` translated guest words at ip 0, 4, ... Region is
// arena-allocated, so `arena` must outlive it -- both are locals in the caller's own scope.
Region *TranslateWords(MemArena &arena, u32 *words, unsigned n, RouteConfig const &cfg)
{
	config::rvv_qcg_typed_chunk_mul = cfg.typed_chunk_mul;
	config::rvv_qcg_typed_chunk_mul_force_emit = cfg.force_emit;
	config::aot_use_llvm = cfg.aot_use_llvm;
	config::rvv_verify = cfg.rvv_verify;
	config::rvv_direct = cfg.rvv_direct;
	config::vlen_bits = cfg.vlen_bits;
	// The vadd route's own switches stay off throughout: this file must observe the mul route in
	// isolation, and leaving them on would make a stray vadd frame indistinguishable from a mul one.
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_diag_chunk = false;

	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

Region *TranslateCfg(MemArena &arena, u32 words[2], RouteConfig const &cfg)
{
	words[0] = cfg.vsetvli_word;
	words[1] = cfg.mul_word;
	return TranslateWords(arena, words, 2, cfg);
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

// Every typed frame in the region, in construction order. FindGroup above collapses a multi-frame
// region into one Group (its `begin`/`end` end up pointing at the LAST frame and `body` at the
// concatenation), which is exactly right for the single-instruction cases it was written for and
// exactly wrong for the eight-multiply kernel body. A frame left open at the end of the region is
// NOT returned -- it is reported by the caller as a missing `end`, rather than silently completed.
std::vector<Group> FindGroups(Region *region)
{
	std::vector<Group> out;
	Group cur;
	bool open = false;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				cur = Group{};
				cur.n_begin = 1;
				cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				continue;
			}
			if (op == Op::_rvvtypedchunkend) {
				if (open) {
					cur.n_end = 1;
					cur.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
					out.push_back(cur);
					open = false;
				}
				continue;
			}
			if (open) {
				cur.body.push_back(&ins);
			}
		}
	}
	return out;
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

// Number of hcalls to one specific runtime stub -- the fallback evidence: a non-admitted vmul.vv
// must produce exactly one call to the PRE-EXISTING rv32_vimul helper, not to a new stub.
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
// 2. Constructed QIR: exact admitted shape.
// ---------------------------------------------------------------------------------------------
void CheckRoute(char const *tag, u32 vlen_bits, u32 nchunks, u32 expect_vlmax, u32 mul_word,
		u32 vs2_reg, u32 vs1_reg, u32 vd_reg)
{
	printf("  %s: vlen=%u expect nchunks=%u vlmax=%u\n", tag, vlen_bits, nchunks, expect_vlmax);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.mul_word = mul_word;
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
	// The fallback is the PRE-EXISTING vimul helper on both frame nodes -- no new stub entered
	// the build with this route.
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vimul);
	CHECK(g.end->stub == RuntimeStubId::id_rv32_vimul);
	// And there is no leftover helper call for this instruction: the frame replaced it.
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vimul), 0u);

	CHECK_EQ(g.body.size(), (size_t)(4 * nchunks));
	if (g.body.size() != 4 * nchunks) {
		return;
	}

	// Load-major: all 2*nchunks source loads, then all nchunks multiplies, then all nchunks
	// stores. Construction order IS emission order (QSel and QRegAlloc walk each block in list
	// order and only insert around an instruction, never reorder one).
	bool shape_ok = true;
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[2 * c]->GetOpcode() == Op::_vstatechunkload;
		shape_ok = shape_ok && g.body[2 * c + 1]->GetOpcode() == Op::_vstatechunkload;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[2 * nchunks + c]->GetOpcode() == Op::_vchunkmul;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && g.body[3 * nchunks + c]->GetOpcode() == Op::_vstatechunkstore;
	}
	CHECK(shape_ok);
	if (!shape_ok) {
		fprintf(stderr, "  %s: frame body is not load-major vchunkmul\n", tag);
		return;
	}
	// The multiply is EXPLICIT in the IR, and it is not the add op wearing a different name.
	CHECK_EQ(CountOp(region, Op::_vchunkmul), nchunks);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), 0u);

	std::vector<u32> vregs;
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(g.body[2 * c]);
		auto *l_s1 = static_cast<InstVStateChunkLoad *>(g.body[2 * c + 1]);
		auto *mul = static_cast<InstVChunkMul *>(g.body[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(g.body[3 * nchunks + c]);

		// Exact low/high state windows, disjoint by construction: chunk c of register r covers
		// [r*128 + 64c, r*128 + 64c + 64).
		CHECK_EQ(l_s2->offs, ChunkOffs(vs2_reg, c));
		CHECK_EQ(l_s1->offs, ChunkOffs(vs1_reg, c));
		CHECK_EQ(store->offs, ChunkOffs(vd_reg, c));

		CHECK_EQ((u32)mul->sew_bytes, 4u);

		// Typed V512 values throughout, in the vector register class.
		CHECK(l_s2->o(0).IsVVPR() && l_s2->o(0).GetType() == VType::V512);
		CHECK(l_s1->o(0).IsVVPR() && l_s1->o(0).GetType() == VType::V512);
		CHECK(mul->o(0).IsVVPR() && mul->o(0).GetType() == VType::V512);
		CHECK(store->i(0).IsVVPR() && store->i(0).GetType() == VType::V512);

		// Per-chunk def-use: this chunk's multiply consumes exactly this chunk's own two loads
		// (order-independent -- nothing promises which QIR input slot holds which source), and
		// this chunk's store consumes exactly this chunk's own multiply.
		// GetVVPR, not GetVGPR: these are VECTOR virtual registers. The scalar accessor
		// asserts IsVGPR() and would abort here -- which is exactly what an assert-enabled
		// build caught when this was first written against the wrong accessor.
		u32 const a = l_s2->o(0).GetVVPR(), b = l_s1->o(0).GetVVPR();
		u32 const ma = mul->i(0).GetVVPR(), mb = mul->i(1).GetVVPR();
		CHECK((ma == a && mb == b) || (ma == b && mb == a));
		CHECK_EQ(store->i(0).GetVVPR(), mul->o(0).GetVVPR());

		vregs.push_back(a);
		vregs.push_back(b);
		vregs.push_back(mul->o(0).GetVVPR());
	}

	// No cross-chunk dependency: 3 fresh virtual values per chunk, all distinct. At nchunks=2 that
	// is 6, which is exactly "chunk 1 reuses nothing chunk 0 defined"; at nchunks=8 it is 24, and
	// the same statement covers all 28 pairs.
	std::sort(vregs.begin(), vregs.end());
	size_t const before = vregs.size();
	vregs.erase(std::unique(vregs.begin(), vregs.end()), vregs.end());
	CHECK_EQ(vregs.size(), before);
	CHECK_EQ(vregs.size(), (size_t)(3 * nchunks));

	// HM.2a. THE PARTITION, checked rather than assumed, and checked in BYTES and in LANES.
	//
	// "k lane-disjoint chunks" is the certificate's central claim, and the per-chunk offset
	// assertions above do not establish it on their own: they say each window is where the formula
	// puts it, not that the windows together cover the live register exactly once. A lowering that
	// emitted k copies of chunk 0, or k windows at a 32-byte stride, or k-1 windows plus a
	// duplicate, would satisfy every earlier check in some variant and fail here.
	//
	// The byte cover is over the register's LIVE bytes, VLEN/8, not over its VLEN_MAX_BYTES slot:
	// at VLEN=512 exactly one 64-byte window is live and the other seven slots of the reservation
	// are untouched, which is the property the chunk count has to get right.
	u32 const live_bytes = vlen_bits / 8;
	u32 const lanes_per_chunk = LanesPerChunk(4);
	std::vector<bool> byte_seen(live_bytes, false);
	std::vector<bool> lane_seen(expect_vlmax, false);
	bool cover_ok = true;
	for (u32 c = 0; c < nchunks; ++c) {
		u32 const off = ChunkOffs(vd_reg, c) - (ST_VREG_BASE + vd_reg * rv32::VLEN_MAX_BYTES);
		for (u32 b = 0; b < 64; ++b) {
			if (off + b >= live_bytes || byte_seen[off + b]) {
				cover_ok = false;
				break;
			}
			byte_seen[off + b] = true;
		}
		for (u32 l = 0; l < lanes_per_chunk; ++l) {
			u32 const lane = c * lanes_per_chunk + l;
			if (lane >= expect_vlmax || lane_seen[lane]) {
				cover_ok = false;
				break;
			}
			lane_seen[lane] = true;
		}
	}
	for (u32 b = 0; b < live_bytes; ++b) {
		cover_ok = cover_ok && byte_seen[b];
	}
	for (u32 l = 0; l < expect_vlmax; ++l) {
		cover_ok = cover_ok && lane_seen[l];
	}
	CHECK(cover_ok);
	// 64 bytes per chunk times k must BE the live register, and k lanes-per-chunk must be VLMAX.
	// Stated separately so a cover failure and an arithmetic failure are distinguishable.
	CHECK_EQ(nchunks * 64u, live_bytes);
	CHECK_EQ(nchunks * lanes_per_chunk, expect_vlmax);

	printf("  %s: OK %u chunk(s), %zu distinct V512 values, %u/%u bytes and %u/%u lanes covered "
	       "exactly once, stub=rv32_vimul\n",
	       tag, nchunks, vregs.size(), nchunks * 64u, live_bytes, nchunks * lanes_per_chunk,
	       expect_vlmax);
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
	unsigned const n_mul = CountOp(region, Op::_vchunkmul);
	unsigned const n_load = CountOp(region, Op::_vstatechunkload);
	unsigned const n_store = CountOp(region, Op::_vstatechunkstore);
	unsigned const n_helper = CountHcall(region, RuntimeStubId::id_rv32_vimul);

	CHECK_EQ(n_begin, 0u);
	CHECK_EQ(n_mul, 0u);
	CHECK_EQ(n_load, 0u);
	CHECK_EQ(n_store, 0u);
	// Exactly one call to the pre-existing helper -- the instruction still executes, through the
	// path this build already had.
	CHECK_EQ(n_helper, 1u);

	printf("    %-46s typed=0 helper_hcalls=%u  %s\n", why, n_helper,
	       (n_begin == 0 && n_mul == 0 && n_helper == 1) ? "ok" : "FAIL");
}

void CheckFallbackTable()
{
	printf("  fallback: every forbidden shape keeps hcall[rv32_vimul]\n");

	{ // the route's own switch, default off
		RouteConfig c;
		c.typed_chunk_mul = false;
		CheckFallback("--rvv-qcg-typed-chunk-mul off (the default)", c);
	}
	{ // LLVM/AOT backend has no lowering for vchunkmul
		RouteConfig c;
		c.aot_use_llvm = true;
		CheckFallback("aot_use_llvm (LLVM backend)", c);
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
	{ // VLEN axis, LOW: a guest register narrower than one host chunk. A 64-byte window on it
	  // would run into the next register's slot, so the rule must REFUSE these rather than round
	  // them up to a single partial chunk -- which is the difference between the exact divide the
	  // predicate performs and a ceiling.
		for (u32 vlen : {128u, 256u}) {
			RouteConfig c;
			c.vlen_bits = vlen;
			char buf[80];
			snprintf(buf, sizeof(buf), "VLEN=%u (partial host chunk)", vlen);
			CheckFallback(buf, c);
		}
	}
	{ // VLEN axis, HIGH: k beyond what the shared body's fixed arrays hold. This axis exists only
	  // because the rule is now computed rather than enumerated -- a two-value VLEN test could not
	  // have been over-broad in this direction. `vlen_supported()` already rejects 8192 before
	  // config::vlen_bits is ever set in a real run, so this drives the predicate directly, which
	  // is the point: the refusal must live in the predicate, not only in the option parser.
		RouteConfig c;
		c.vlen_bits = 8192;
		char buf[80];
		snprintf(buf, sizeof(buf), "VLEN=8192 (k=16 > kMaxChunks=%u)",
			 (unsigned)rv32::rvvrun::kMaxChunks);
		CheckFallback(buf, c);
	}
	{ // VLEN axis: a width above 512 that is NOT a whole number of host chunks. 768 leaves a
	  // 32-byte remainder, which no sequence of 64-byte windows can cover without running past
	  // the register, so the modulo -- not the power-of-two rule that happens to exclude 768
	  // upstream -- has to refuse it. Driven directly for the same reason as 8192.
	  //
	  // 1536 is deliberately NOT in this table: it is 3*512, so the generic rule admits it as k=3
	  // and lowers it correctly. That is not over-admission -- the rule's domain is bounded by
	  // rv32::vlen_supported(), which requires a power of two and is enforced by both the --vlen
	  // parser and ukernel::InitMainThread -- and pretending k=3 were refused here would assert a
	  // shape no run can produce.
		RouteConfig c;
		c.vlen_bits = 768;
		CheckFallback("VLEN=768 (not a whole number of host chunks)", c);
	}
	{ // SEW axis: e64 has no admitted packed multiply on this route
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E64M1;
		CheckFallback("SEW=64 (e64,m1)", c);
	}
	{ // LMUL axis: a register group is more than one register
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E32M2;
		CheckFallback("LMUL=2 (e32,m2)", c);
	}
	{ // encoding axis: masked and .vx never even reach this translator, but the whole-region
	  // result is what matters -- no typed node, one vimul helper call.
		RouteConfig c;
		c.mul_word = INSN_VMUL_VV_MASKED;
		CheckFallback("masked vmul.vv (vm=0)", c);
		RouteConfig d;
		d.mul_word = INSN_VMUL_VX;
		CheckFallback("vmul.vx", d);
		RouteConfig e;
		e.mul_word = INSN_VMULH_VV;
		CheckFallback("vmulh.vv", e);
		RouteConfig f;
		f.mul_word = INSN_VDIV_VV;
		CheckFallback("vdiv.vv", f);
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
		auto *mul = static_cast<InstVChunkMul *>(typed_ops[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(typed_ops[3 * nchunks + c]);

		CHECK(mul->GetOpcode() == Op::_vchunkmul);
		CHECK_EQ(l_s2->offs, ChunkOffs(VS2_REG, c));
		CHECK_EQ(l_s1->offs, ChunkOffs(VS1_REG, c));
		CHECK_EQ(store->offs, ChunkOffs(VD_REG, c));

		bool const allocated = l_s2->o(0).IsPVPR() && l_s1->o(0).IsPVPR() && mul->o(0).IsPVPR() &&
				       mul->i(0).IsPVPR() && mul->i(1).IsPVPR() && store->i(0).IsPVPR();
		CHECK(allocated);
		if (!allocated) {
			continue;
		}
		for (auto o : {l_s2->o(0), l_s1->o(0), mul->o(0)}) {
			CHECK(ArchTraits::VPR_POOL.Test(o.GetPVPR()));
			CHECK(!ArchTraits::VPR_FIXED.Test(o.GetPVPR()));
		}

		RegN const want_a = l_s2->o(0).GetPVPR(), want_b = l_s1->o(0).GetPVPR();
		RegN const got_a = mul->i(0).GetPVPR(), got_b = mul->i(1).GetPVPR();
		// Per-chunk def-use survives allocation. A chunk whose multiply resolved to the OTHER
		// chunk's physical register would pass a bare distinct-count check but not this.
		CHECK((got_a == want_a && got_b == want_b) || (got_a == want_b && got_b == want_a));
		CHECK_EQ(mul->o(0).GetPVPR(), store->i(0).GetPVPR());

		pregs.push_back(want_a);
		pregs.push_back(want_b);
		pregs.push_back(mul->o(0).GetPVPR());
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
	enum class Kind { LOAD, MUL, STORE } kind;
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
// two-operand vmovdqu64 against [r13+disp], and a three-register vpmulld. Anything else returns
// false; the caller decides whether that is a harmless scalar line or an unaccounted ZMM line.
//
// vpaddd is NOT recognised here on purpose. If the route ever emitted the add -- the exact
// confusion this checkpoint has to rule out -- it would arrive as an unrecognised ZMM-bearing line
// and fail loudly, rather than being silently accepted as "some vector op".
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
	if (mnem == "vpmulld" && ops.size() == 3) {
		unsigned d, s0, s1;
		if (ParseZmm(ops[0], &d) && ParseZmm(ops[1], &s0) && ParseZmm(ops[2], &s1)) {
			*out = DecodedVec{DecodedVec::Kind::MUL, mnem, d, s0, s1, 0, false};
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
	char path[] = "/tmp/rvdbt_p35a_emit_XXXXXX";
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

void CheckRouteEmitted(char const *tag, u32 vlen_bits, u32 nchunks)
{
	printf("  %s (emitted): vlen=%u nchunks=%u\n", tag, vlen_bits, nchunks);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	Region *region = TranslateCfg(arena, words, cfg);

	TestCompilerRuntime cruntime;
	qir::CodeSegment segment(0u, 0x1000u);
	auto const code_span = qcg::GenerateCode(&cruntime, &segment, region, 0);
	CHECK(!code_span.empty());
	if (code_span.empty()) {
		return;
	}
	std::vector<u8> const code(code_span.begin(), code_span.end());

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	if (!g.begin) {
		return;
	}
	CHECK_EQ(g.begin->n_typed, (u8)(4 * nchunks));
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vimul);

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

	auto const lines = Disassemble(code);
	CHECK(!lines.empty());
	if (lines.empty()) {
		return;
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

	for (size_t i = 0; i < vecs.size(); ++i) {
		auto const &v = vecs[i];
		switch (v.kind) {
		case DecodedVec::Kind::LOAD:
			printf("  %s: vec[%zu] LOAD  %s zmm%u <- [r13+0x%llx]\n", tag, i, v.mnemonic.c_str(),
			       v.dst, (unsigned long long)v.disp);
			break;
		case DecodedVec::Kind::MUL:
			printf("  %s: vec[%zu] MUL   %s zmm%u <- zmm%u, zmm%u\n", tag, i, v.mnemonic.c_str(),
			       v.dst, v.src0, v.src1);
			break;
		case DecodedVec::Kind::STORE:
			printf("  %s: vec[%zu] STORE %s [r13+0x%llx] <- zmm%u\n", tag, i,
			       v.mnemonic.c_str(), (unsigned long long)v.disp, v.src0);
			break;
		}
	}

	CHECK_EQ(vecs.size(), (size_t)(4 * nchunks));
	if (vecs.size() != 4 * nchunks) {
		for (auto const &l : lines) {
			fprintf(stderr, "    %s\n", l.c_str());
		}
		return;
	}

	bool shape_ok = true;
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[2 * c].kind == DecodedVec::Kind::LOAD;
		shape_ok = shape_ok && vecs[2 * c + 1].kind == DecodedVec::Kind::LOAD;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[2 * nchunks + c].kind == DecodedVec::Kind::MUL;
	}
	for (u32 c = 0; c < nchunks; ++c) {
		shape_ok = shape_ok && vecs[3 * nchunks + c].kind == DecodedVec::Kind::STORE;
	}
	CHECK(shape_ok);
	if (!shape_ok) {
		fprintf(stderr, "  %s: decoded order is not load-major\n", tag);
		return;
	}

	std::vector<std::vector<unsigned>> chunk_regs(nchunks);
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c]);
		auto *l_s1 = static_cast<InstVStateChunkLoad *>(typed_ops[2 * c + 1]);
		auto *mul = static_cast<InstVChunkMul *>(typed_ops[2 * nchunks + c]);
		auto *store = static_cast<InstVStateChunkStore *>(typed_ops[3 * nchunks + c]);
		auto const &d_l_s2 = vecs[2 * c];
		auto const &d_l_s1 = vecs[2 * c + 1];
		auto const &d_mul = vecs[2 * nchunks + c];
		auto const &d_store = vecs[3 * nchunks + c];

		bool const ok = l_s2->o(0).IsPVPR() && l_s1->o(0).IsPVPR() && mul->o(0).IsPVPR() &&
				store->i(0).IsPVPR();
		CHECK(ok);
		if (!ok) {
			continue;
		}

		CHECK_EQ((u32)d_l_s2.dst, (u32)l_s2->o(0).GetPVPR());
		CHECK(d_l_s2.has_disp);
		CHECK_EQ(d_l_s2.disp, (i64)ChunkOffs(VS2_REG, c));
		CHECK_EQ((u32)d_l_s1.dst, (u32)l_s1->o(0).GetPVPR());
		CHECK(d_l_s1.has_disp);
		CHECK_EQ(d_l_s1.disp, (i64)ChunkOffs(VS1_REG, c));

		// The emitted operation is the packed 32-bit MULTIPLY, at the exact allocated registers.
		CHECK(d_mul.mnemonic == "vpmulld");
		CHECK_EQ((u32)d_mul.dst, (u32)mul->o(0).GetPVPR());
		bool const reads_own_loads = (d_mul.src0 == d_l_s2.dst && d_mul.src1 == d_l_s1.dst) ||
					     (d_mul.src0 == d_l_s1.dst && d_mul.src1 == d_l_s2.dst);
		CHECK(reads_own_loads);
		if (!reads_own_loads) {
			fprintf(stderr,
				"  %s: chunk %u decoded mul reads zmm%u,zmm%u; own loads are zmm%u/zmm%u\n",
				tag, c, d_mul.src0, d_mul.src1, d_l_s2.dst, d_l_s1.dst);
		}

		CHECK_EQ((u32)d_store.src0, (u32)d_mul.dst);
		CHECK(d_store.has_disp);
		CHECK_EQ(d_store.disp, (i64)ChunkOffs(VD_REG, c));

		chunk_regs[c] = {d_l_s2.dst, d_l_s1.dst, d_mul.dst};
	}

	// No artificial cross-chunk dependency, re-derived from the externally decoded bytes: no
	// register named anywhere in chunk i is named anywhere in chunk j, for EVERY pair.
	//
	// P3.5a checked this only at nchunks==2, where there is one pair. HM.2a needs all k(k-1)/2 --
	// 28 pairs at k=8 -- because that is where the register file actually gets tight: 3k = 24
	// simultaneously-live V512 values against ArchTraits::VPR_POOL's 30. If the allocator ever
	// reused a register across chunks it would serialize two chunks that the guest ISA says are
	// independent, which is precisely the certificate's content being lost in code generation.
	{
		bool disjoint = true;
		for (u32 i = 0; i < nchunks; ++i) {
			for (u32 j = i + 1; j < nchunks; ++j) {
				for (auto ri : chunk_regs[i]) {
					for (auto rj : chunk_regs[j]) {
						disjoint = disjoint && ri != rj;
					}
				}
			}
		}
		CHECK(disjoint);
		printf("  %s: pairwise-disjoint=%d over %u chunk(s):", tag, (int)disjoint, nchunks);
		for (u32 c = 0; c < nchunks; ++c) {
			printf(" c%u{%u,%u,%u}", c, chunk_regs[c][0], chunk_regs[c][1],
			       chunk_regs[c][2]);
		}
		printf("\n");
	}

	unsigned n_mul = 0, n_add_like = 0;
	for (auto const &v : vecs) {
		n_mul += (v.kind == DecodedVec::Kind::MUL);
		n_add_like += (v.mnemonic == "vpaddd");
	}
	CHECK_EQ(n_mul, nchunks);
	CHECK_EQ(n_add_like, 0u);

	printf("  %s: OK objdump-decoded %zu/%u zmm instructions, %u vpmulld chain(s), 0 vpaddd, "
	       "bytes never executed\n",
	       tag, vecs.size(), 4 * nchunks, n_mul);
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
	cfg.mul_word = word;
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
// 7. The frozen HM.2a microkernel's real strip-step body.
// ---------------------------------------------------------------------------------------------
//
// These are the words `llvm-objdump -d` reads out of the guest ELF that
// experiments/.../scripts/build_guest.sh produces from src/guest_vmulvv_vla_microkernel.c, at
// vmulvv_vla_pass+0x1c..+0x4c -- not a synthetic sequence assembled here. The eight identical
// multiplies are the source file's VMUL8 unroll, and their vd==vs2 shape (v8 = v8 * v9) is the
// accumulator recurrence that makes operand order and load-major ordering observable.
//
// WHY THIS CASE EXISTS SEPARATELY. Every other check in this file translates ONE multiply, so
// "a guest operation becomes k chunks" is checked once per configuration. Here it is checked over
// eight consecutive real operations in one region, which is what rules out a lowering that is
// correct for the first frame and wrong for the rest -- and it is the shape HM.2b will consume.
//
// The vsetvli, the two vle32.v and the vse32.v are deliberately left on their default routes: their
// own typed switches are off in RouteConfig, so they lower to helpers. That is not a defect being
// tolerated, it is this checkpoint's scope: HM.2a routes the MULTIPLY, and a neighbouring helper
// call proves the frames are per-operation rather than a whole-loop rewrite.
constexpr u32 KERNEL_BODY[] = {
    0x0d0677d7u, // vsetvli a5, a2, e32, m1, ta, ma
    0x0206e407u, // vle32.v v8, (a3)
    0x0205e487u, // vle32.v v9, (a1)
    0x9684a457u, // vmul.vv v8, v8, v9   x8
    0x9684a457u, 0x9684a457u, 0x9684a457u, 0x9684a457u,
    0x9684a457u, 0x9684a457u, 0x9684a457u,
    0x0206e427u, // vse32.v v8, (a3)
};
constexpr unsigned KERNEL_N = sizeof(KERNEL_BODY) / sizeof(KERNEL_BODY[0]);
constexpr unsigned KERNEL_FIRST_MUL = 3; // word index of the first vmul.vv
constexpr unsigned KERNEL_MULS = 8;
static_assert(KERNEL_FIRST_MUL + KERNEL_MULS + 1 == KERNEL_N, "the kernel body word list drifted");

// Translate the kernel body and return its typed frames, with the region kept alive by `arena`.
// `out_region`, when given, receives the region so a caller can print its QIR.
std::vector<Group> KernelGroups(MemArena &arena, u32 *words, u32 vlen_bits,
				Region **out_region = nullptr)
{
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	for (unsigned i = 0; i < KERNEL_N; ++i) {
		words[i] = KERNEL_BODY[i];
	}
	Region *region = TranslateWords(arena, words, KERNEL_N, cfg);
	if (out_region) {
		*out_region = region;
	}
	return FindGroups(region);
}

// The kernel body's constructed QIR, verbatim, one artifact per width. This is rvdbt's own printer
// on the region the production translator built -- the same text `--logs qir` would emit in a debug
// build -- and it is what makes the certificate rows auditable against something other than this
// file's own accessors: every `rvvtypedchunkbegin ... body=4k`, every `vstatechunkload state:<off>`
// and every `vchunkmul sew4 [%d] [%a] [%b]` is visible in it.
void DumpKernelQir(u32 vlen_bits)
{
	MemArena arena(1u << 20);
	u32 words[KERNEL_N];
	Region *region = nullptr;
	auto const groups = KernelGroups(arena, words, vlen_bits, &region);
	CHECK_EQ(groups.size(), (size_t)KERNEL_MULS);
	printf("QIR_BEGIN vlen=%u k=%u frames=%zu\n", vlen_bits, ExpectChunks(vlen_bits),
	       groups.size());
	printf("%s", qir::PrinterPass::run(region).c_str());
	printf("QIR_END vlen=%u\n", vlen_bits);
}

void CheckKernelBody(u32 vlen_bits)
{
	u32 const k = ExpectChunks(vlen_bits);
	printf("  kernel body: vlen=%u expect %u frames x %u chunk(s)\n", vlen_bits, KERNEL_MULS, k);

	MemArena arena(1u << 20);
	u32 words[KERNEL_N];
	auto const groups = KernelGroups(arena, words, vlen_bits);

	// One frame per guest multiply, and NOT one frame for the loop: eight separate guards.
	CHECK_EQ(groups.size(), (size_t)KERNEL_MULS);
	if (groups.size() != KERNEL_MULS) {
		return;
	}
	for (size_t f = 0; f < groups.size(); ++f) {
		auto const &g = groups[f];
		CHECK_EQ(g.n_begin, 1u);
		CHECK_EQ(g.n_end, 1u);
		CHECK_EQ(g.begin->n_typed, (u8)(4 * k));
		CHECK_EQ(g.begin->raw, KERNEL_BODY[KERNEL_FIRST_MUL + f]);
		CHECK_EQ((u32)g.begin->n_members, 1u); // --rvv-vector-run is off; no run may form
		CHECK(g.begin->stub == RuntimeStubId::id_rv32_vimul);
		CHECK_EQ(g.body.size(), (size_t)(4 * k));
		if (g.body.size() != 4 * k) {
			continue;
		}
		// Each frame is a whole load-major body over v8 (=vd=vs2) and v9 (=vs1), and each
		// frame's k multiplies are its own.
		unsigned n_mul = 0;
		for (auto *ins : g.body) {
			n_mul += ins->GetOpcode() == Op::_vchunkmul;
		}
		CHECK_EQ(n_mul, k);
	}
	printf("  kernel body: OK %zu frames, %u vchunkmul each, %u total\n", groups.size(), k,
	       (unsigned)groups.size() * k);
}

// ---------------------------------------------------------------------------------------------
// 8. The independence certificate, emitted machine-readably.
// ---------------------------------------------------------------------------------------------
//
// One `CERT,` row per (guest operation, chunk). Every field is DERIVED from the QIR the production
// lowering built -- there is no certificate object in rvdbt and HM.2a did not add one. The claim
// this evidence supports is exactly that: the frame already carries operation identity, chunk
// identity, the lane partition, the def-use edges, the memory marker and the barrier, so a
// consumer does not need new production plumbing to read them.
//
// Columns, in RVV_RESEARCH_EXECUTION_PLAN_V10 section 3.1's order where they correspond:
//   vlen,k,sew            the configuration this row was produced under
//   op_index,op_pc,op_raw the operation id: which guest instruction, at which pc, with which word
//   grp_begin,grp_end     group_begin / group_end, as QIR instruction ids
//   chunk_id              component id within the operation
//   lane_begin,lane_end   half-open guest element range this chunk owns
//   byte_begin,byte_end   half-open byte range within the guest register
//   vd,vs1,vs2            architectural registers
//   def,use2,use1         def-use: the V512 value this chunk defines and the two it consumes
//   mem                   memory interval, or `nomem` -- an ALU frame touches only CPUState
//   barrier               the fallback this frame's guard falls back to
constexpr char const *CERT_HEADER =
    "CERT_HEADER,vlen,k,sew,op_index,op_pc,op_raw,grp_begin,grp_end,chunk_id,lane_begin,lane_end,"
    "byte_begin,byte_end,vd,vs1,vs2,def,use2,use1,mem,barrier";

void EmitCertificate(u32 vlen_bits)
{
	u32 const k = ExpectChunks(vlen_bits);
	u32 const sew_bytes = 4;
	u32 const lanes = LanesPerChunk(sew_bytes);

	MemArena arena(1u << 20);
	u32 words[KERNEL_N];
	auto const groups = KernelGroups(arena, words, vlen_bits);
	CHECK_EQ(groups.size(), (size_t)KERNEL_MULS);
	if (groups.size() != KERNEL_MULS) {
		return;
	}

	for (size_t f = 0; f < groups.size(); ++f) {
		auto const &g = groups[f];
		if (g.body.size() != 4 * k) {
			CHECK_EQ(g.body.size(), (size_t)(4 * k));
			continue;
		}
		u32 const op_pc = 4u * (u32)(KERNEL_FIRST_MUL + f);
		for (u32 c = 0; c < k; ++c) {
			auto *l_s2 = static_cast<InstVStateChunkLoad *>(g.body[2 * c]);
			auto *l_s1 = static_cast<InstVStateChunkLoad *>(g.body[2 * c + 1]);
			auto *mul = static_cast<InstVChunkMul *>(g.body[2 * k + c]);
			auto *store = static_cast<InstVStateChunkStore *>(g.body[3 * k + c]);
			// The architectural register a window belongs to, recovered from the
			// displacement rather than from the instruction word, so a wrong window shows
			// up as a wrong register in the certificate instead of being invisible.
			u32 const vs2 = (l_s2->offs - ST_VREG_BASE) / rv32::VLEN_MAX_BYTES;
			u32 const vs1 = (l_s1->offs - ST_VREG_BASE) / rv32::VLEN_MAX_BYTES;
			u32 const vd = (store->offs - ST_VREG_BASE) / rv32::VLEN_MAX_BYTES;
			u32 const byte_begin = (store->offs - ST_VREG_BASE) % rv32::VLEN_MAX_BYTES;
			printf("CERT,%u,%u,%u,%zu,0x%x,0x%08x,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,"
			       "nomem,rv32_vimul\n",
			       vlen_bits, k, sew_bytes * 8, f, op_pc,
			       KERNEL_BODY[KERNEL_FIRST_MUL + f], g.begin->GetId(), g.end->GetId(), c,
			       c * lanes, (c + 1) * lanes, byte_begin, byte_begin + 64, vd, vs1, vs2,
			       mul->o(0).GetVVPR(), mul->i(0).GetVVPR(), mul->i(1).GetVVPR());
		}
	}
}

} // namespace

int main()
{
	printf("P3.5a/HM.2a vmul.vv typed V512 chunk route, generic k = VLEN/512 after whole-chunk "
	       "admission\n");

	printf("[1] decoder\n");
	CheckDecoder();

	// The four runtime VLENs HM.2a covers, and the chunk count each must produce. The table is
	// written once and every section below iterates it, so a section that silently stopped
	// covering a width would have to be deleted rather than merely left behind.
	struct Width {
		u32 vlen, k, vlmax;
	};
	// vlmax = VLEN/SEW at SEW=32, LMUL=1 -- restated here as data rather than computed, so a
	// wrong VLMAX in the emitted guard is caught against an independent number.
	static constexpr Width kWidths[] = {
	    {512, 1, 16}, {1024, 2, 32}, {2048, 4, 64}, {4096, 8, 128}};

	printf("[2] constructed QIR\n");
	for (auto const &w : kWidths) {
		char tag[32];
		snprintf(tag, sizeof(tag), "vlen%u", w.vlen);
		CHECK_EQ(ExpectChunks(w.vlen), w.k);
		CheckRoute(tag, w.vlen, w.k, w.vlmax, INSN_VMUL_VV, VS2_REG, VS1_REG, VD_REG);

		// The real kernel's own word: v8=vs2 (== vd) and v9=vs1.
		snprintf(tag, sizeof(tag), "kernel-word vlen%u", w.vlen);
		CheckRoute(tag, w.vlen, w.k, w.vlmax, INSN_VMUL_VV_P3_KERNEL, 8, 9, 8);
	}

	printf("[3] fallback table\n");
	CheckFallbackTable();

	printf("[4] post-QRegAlloc\n");
	for (auto const &w : kWidths) {
		char tag[32];
		snprintf(tag, sizeof(tag), "vlen%u", w.vlen);
		CheckRoutePostQRA(tag, w.vlen, w.k);
	}

	printf("[5] emitted host code\n");
	for (auto const &w : kWidths) {
		char tag[32];
		snprintf(tag, sizeof(tag), "vlen%u", w.vlen);
		CheckRouteEmitted(tag, w.vlen, w.k);
	}

	printf("[6] legal operand overlap\n");
	// Run every legal overlap at every width. The accumulator recurrence in the frozen kernel is
	// the vd==vs2 form, and it is the one a load-major violation would corrupt; the other two are
	// checked at every k for the same reason, since the overlap argument is per chunk.
	for (auto const &w : kWidths) {
		char tag[48];
		snprintf(tag, sizeof(tag), "vd==vs2 vlen%u", w.vlen);
		CheckOverlap(tag, w.vlen, w.k, w.vlmax, INSN_VMUL_VV_D_EQ_S2, VD_REG, VS1_REG, VD_REG);
		snprintf(tag, sizeof(tag), "vd==vs1 vlen%u", w.vlen);
		CheckOverlap(tag, w.vlen, w.k, w.vlmax, INSN_VMUL_VV_D_EQ_S1, VS2_REG, VD_REG, VD_REG);
		snprintf(tag, sizeof(tag), "vd==vs1==vs2 vlen%u", w.vlen);
		CheckOverlap(tag, w.vlen, w.k, w.vlmax, INSN_VMUL_VV_ALL_SAME, VD_REG, VD_REG, VD_REG);
	}

	printf("[7] frozen microkernel strip-step body\n");
	for (auto const &w : kWidths) {
		CheckKernelBody(w.vlen);
	}

	printf("[8] independence certificate\n");
	printf("%s\n", CERT_HEADER);
	for (auto const &w : kWidths) {
		EmitCertificate(w.vlen);
	}

	printf("[9] constructed QIR of the kernel body\n");
	for (auto const &w : kWidths) {
		DumpKernelQir(w.vlen);
	}

	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("OK: all checks passed\n");
	return 0;
}
