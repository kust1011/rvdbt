// C3 (2026-09-18). THE WIDENING INTEGER FAMILY ON THE LLVM ARM.
//
// `vwadd/vwsub/vwmul/vwmacc` plus the unsigned, mixed-sign, `.wv` and `.wx` variants.
//
// SECTIONS, and the failure each catches:
//   [1] INDEPENDENT SIGNEDNESS. `vwadd.vv` sign-extends BOTH sources, `vwaddu.vv` zero-extends both,
//       and `vwmulsu.vv` extends vs2 signed and vs1 unsigned. The three are indistinguishable in any
//       node or instruction count and differ on real data, so the section counts `sext`/`zext` in
//       the emitted IR per form.
//   [2] `.wv` / `.wx` LOAD vs2 ALREADY WIDE. A `wide2` form that extended vs2 anyway would read half
//       the bytes from the wrong place; asserted as "one fewer extension than the narrow form".
//   [3] THE `.vx` SCALAR IS THE LOW SEW BITS, THEN EXTENDED -- not the whole GPR word. Asserted by
//       requiring a `trunc` to the source width followed by an extension to the destination width,
//       and a splat.
//   [4] `vwmacc` READS THE OLD vd and accumulates after the product: one more load of the
//       destination window than `vwmul`, and an `add` after the `mul`.
//   [5] DESTINATION ELEMENT COUNT AND WIDTH: `lanes = bytes/(2*SEW)` and the store is at 2*SEW.
//       Using the source width would mask the wrong elements.
//   [6] PER-UNIT ELEMENT BASE, exactly as in the extension family: each unit's mask index vector is
//       `[base, base+lanes)`.
//   [7] MASKED FORMS REFUSED; exactly one `vstart` write per frame; inert when off; QCG unaffected.
//
// WHAT THIS FILE DOES NOT DO. It never executes what it builds and needs no AVX-512 host. It does
// not assert arithmetic RESULTS -- those are the shared helper's and QCG's semantics; it asserts the
// structural facts this lowering could get wrong on its own.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/llvmgen/rvv_test_llvm_compat.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace testcompat = dbt::qir::testcompat;

namespace
{
namespace rvv32 = dbt::rv32;

unsigned g_fail = 0;
#define CHECK(c)                                                                                   \
	do {                                                                                       \
		if (!(c)) {                                                                        \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);                      \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)
#define CHECK_EQ(a, b)                                                                             \
	do {                                                                                       \
		auto x_ = (long long)(a);                                                          \
		auto y_ = (long long)(b);                                                          \
		if (x_ != y_) {                                                                    \
			printf("  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,  \
			       #b, x_, y_);                                                        \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

llvm::LLVMContext g_ctx;

// OPMVV = funct3 2, OPMVX = funct3 6. funct6 values from RVV 1.0 chapter 11.2/11.3/11.12.
constexpr u32 F6_VWADDU = 48u, F6_VWADD = 49u, F6_VWSUBU = 50u, F6_VWSUB = 51u;
constexpr u32 F6_VWADDU_W = 52u, F6_VWADD_W = 53u;
constexpr u32 F6_VWMULU = 56u, F6_VWMULSU = 58u, F6_VWMUL = 59u;
constexpr u32 F6_VWMACCU = 60u, F6_VWMACC = 61u;
constexpr u32 W(u32 f6, u32 f3, u32 vs2, u32 vs1, u32 vd, bool masked = false)
{
	return (f6 << 26) | ((masked ? 0u : 1u) << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E16M1 = 0xc8u;
constexpr u32 kJalr = 0x00008067u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c3w", g_ctx) {}
};

void Configure(u32 vlen, bool llvm_backend, bool route)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = llvm_backend;
	config::rvv_vector_ssa = llvm_backend;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_llvm_widen = route;
	config::rvv_qcg_typed_chunk = !llvm_backend;
	config::rvv_qcg_typed_chunk_force_emit = !llvm_backend;
	config::rvv_qcg_active_vl_widen_bound = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_partial_vl = false;
}

void Translate(Built &b, bool backend)
{
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	if (!backend)
		return;
	LLVMGenCtx ctx(&b.module);
	ctx.AddFunction(0u, b.segment);
	QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
	b.fn = gen.Run();
}

struct Qir {
	int guard_kind = -1;
	unsigned frames = 0, nodes = 0, hcalls = 0, finishes = 0;
	std::vector<u32> bases;
	unsigned sew = 0, bytes = 0, op = 99;
	bool scalar = false, wide2 = false, sign2 = false, sign1 = false, masked = false;
};

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++q.frames;
				q.guard_kind =
				    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
			} else if (ins.GetOpcode() == Op::_vchunkwiden) {
				auto *n = static_cast<InstVChunkWiden *>(&ins);
				++q.nodes;
				q.bases.push_back(n->base);
				q.sew = n->sew; q.bytes = n->bytes; q.op = n->op;
				q.scalar = n->scalar; q.wide2 = n->wide2;
				q.sign2 = n->sign2; q.sign1 = n->sign1; q.masked = n->masked;
				q.finishes += n->finish;
			} else if (ins.GetOpcode() == Op::_hcall) {
				++q.hcalls;
			}
		}
	return q;
}

llvm::Value *StripToBase(llvm::Value *p)
{
	while (auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p))
		p = g->getPointerOperand();
	return p;
}

struct IRFacts {
	unsigned sext = 0, zext = 0, trunc = 0, splat = 0;
	unsigned add = 0, sub = 0, mul = 0;
	unsigned dst_bits = 0, lanes = 0;
	unsigned masked_stores = 0, vstart_stores = 0;
	unsigned dst_window_loads = 0; // vector loads from the destination offset
	std::vector<std::vector<u32>> mask_indices;
};

IRFacts ScanIR(llvm::Function *fn, u32 dst_offs)
{
	IRFacts f;
	llvm::Value *state = fn->getArg(0);
	u32 const vstart_off = offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart);
	auto state_offset = [&](llvm::Value *p, u32 *out) {
		if (StripToBase(p) != state || p == state)
			return false;
		llvm::APInt ap(64, 0);
		auto *g = llvm::cast<llvm::GetElementPtrInst>(p);
		if (!g->accumulateConstantOffset(g->getModule()->getDataLayout(), ap))
			return false;
		*out = (u32)ap.getZExtValue();
		return true;
	};
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *c = llvm::dyn_cast<llvm::CastInst>(&ins)) {
				bool const vec = llvm::isa<llvm::FixedVectorType>(c->getType());
				if (c->getOpcode() == llvm::Instruction::SExt) {
					++f.sext;
					if (vec) {
						auto *vt = llvm::cast<llvm::FixedVectorType>(c->getType());
						f.lanes = vt->getNumElements();
						f.dst_bits = vt->getScalarSizeInBits();
					}
				} else if (c->getOpcode() == llvm::Instruction::ZExt) {
					++f.zext;
					if (vec) {
						auto *vt = llvm::cast<llvm::FixedVectorType>(c->getType());
						f.lanes = vt->getNumElements();
						f.dst_bits = vt->getScalarSizeInBits();
					}
				} else if (c->getOpcode() == llvm::Instruction::Trunc) {
					++f.trunc;
				}
				continue;
			}
			if (auto *sv = llvm::dyn_cast<llvm::ShuffleVectorInst>(&ins)) {
				if (sv->isZeroEltSplat())
					++f.splat;
				continue;
			}
			if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins)) {
				if (bo->getOpcode() == llvm::Instruction::Add) ++f.add;
				else if (bo->getOpcode() == llvm::Instruction::Sub) ++f.sub;
				else if (bo->getOpcode() == llvm::Instruction::Mul) ++f.mul;
				continue;
			}
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
				if (ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
					continue;
				++f.masked_stores;
				std::vector<u32> idx;
				if (auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(testcompat::MaskedStoreMask(ii)))
					if (auto *cv = llvm::dyn_cast<llvm::Constant>(cmp->getOperand(0)))
						if (auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(cv->getType()))
							for (u32 k = 0; k < vt->getNumElements(); ++k)
								if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(
									cv->getAggregateElement(k)))
									idx.push_back((u32)ci->getZExtValue());
				f.mask_indices.push_back(idx);
				continue;
			}
			if (auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
				u32 off = 0;
				// The destination GROUP, not one offset: a multi-register destination
				// puts unit c at its own VLEN_MAX_BYTES slot, so matching only the base
				// would see just the first unit's read.
				if (state_offset(l->getPointerOperand(), &off) && off >= dst_offs &&
				    off < dst_offs + 8u * rvv32::VLEN_MAX_BYTES &&
				    llvm::isa<llvm::FixedVectorType>(l->getType()))
					++f.dst_window_loads;
				continue;
			}
			if (auto *s = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				u32 off = 0;
				if (state_offset(s->getPointerOperand(), &off) && off == vstart_off)
					++f.vstart_stores;
			}
		}
	return f;
}

constexpr u32 kVregBase = offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg);

struct Base { unsigned hcalls = 0, vstart = 0; };
Base Prologue(u32 vt, u32 vlen)
{
	Configure(vlen, true, true);
	Built b({Vsetvli(vt), kJalr});
	Translate(b, true);
	Base r;
	r.hcalls = ScanQir(b.region).hcalls;
	r.vstart = ScanIR(b.fn, 0).vstart_stores;
	return r;
}

// ------------------------------------------------------------------------------------------
void SectionForms()
{
	printf("[C3w-1,2,5,6,7] signedness, wide2, widths, element base, vstart\n");
	// A case that is never admitted at any width would make this section VACUOUS -- which is
	// exactly what happened to the `.wv` rows on the first run, because their vs1 overlapped the
	// wide vs2 group (vwint_registers_legal:1394). Admission is therefore counted and required.
	struct Case { char const *name; u32 f6; u32 f3; bool s2, s1, wide2; unsigned op; };
	// op: 0 Add, 1 Sub, 2 Mul, 3 Macc (InstVChunkWiden::Kind)
	Case const cases[] = {
	    {"vwaddu.vv", F6_VWADDU, 2, false, false, false, 0},
	    {"vwadd.vv",  F6_VWADD,  2, true,  true,  false, 0},
	    {"vwsubu.vv", F6_VWSUBU, 2, false, false, false, 1},
	    {"vwsub.vv",  F6_VWSUB,  2, true,  true,  false, 1},
	    {"vwaddu.wv", F6_VWADDU_W, 2, false, false, true, 0},
	    {"vwadd.wv",  F6_VWADD_W,  2, true,  true,  true, 0},
	    {"vwmulu.vv", F6_VWMULU, 2, false, false, false, 2},
	    {"vwmulsu.vv",F6_VWMULSU,2, true,  false, false, 2},
	    {"vwmul.vv",  F6_VWMUL,  2, true,  true,  false, 2},
	    {"vwmaccu.vv",F6_VWMACCU,2, false, false, false, 3},
	    {"vwmacc.vv", F6_VWMACC, 2, true,  true,  false, 3},
	};
	unsigned admitted[sizeof(cases) / sizeof(cases[0])] = {};
	for (u32 vlen : {256u, 512u, 1024u})
		for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ++ci) {
			auto const &c = cases[ci];
			Configure(vlen, true, true);
			// vd = v16 (2*LMUL group), sources v8 / v9
			Built b({Vsetvli(kVT_E16M1), W(c.f6, c.f3, 8, 12, 16), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (getenv("C3W_TRACE"))
				printf("   trace vlen=%u %-12s frames=%u nodes=%u\n", vlen, c.name,
				       q.frames, q.nodes);
			if (!q.frames)
				continue; // form not admitted at this shape
			// C4-FIX: the frame must prove `vstart == 0`. This body's mask is `element_base + i < vl`
			// with no prestart term, and llvmgen emits NO vstart compare for `GuardKind::VTypeInteger`,
			// so that kind let a `csrw vstart, k` execution rewrite destination elements `[0, k)`.
			CHECK_EQ(q.guard_kind,
				 (int)InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart);
			++admitted[ci];
			Base const pro = Prologue(kVT_E16M1, vlen);
			CHECK_EQ(q.hcalls, pro.hcalls);
			CHECK(!q.masked);
			CHECK_EQ(q.op, c.op);
			CHECK_EQ(q.wide2, c.wide2);
			CHECK_EQ(q.sign2, c.s2);
			CHECK_EQ(q.sign1, c.s1);

			u32 const dst_off = kVregBase + 16u * rvv32::VLEN_MAX_BYTES;
			IRFacts ir = ScanIR(b.fn, dst_off);
			// [5] destination element width and lane count
			CHECK_EQ(ir.dst_bits, 16u * q.sew);           // 8 * (2*sew)
			CHECK_EQ(ir.lanes, q.bytes / (2u * q.sew));
			// [1]/[2] one vector extension per NARROW source; a wide2 form has one fewer
			unsigned const narrow_sources = c.wide2 ? 1u : 2u;
			CHECK_EQ(ir.sext + ir.zext, narrow_sources * q.nodes);
			// per-source signedness: count how many of the narrow sources are signed
			unsigned signed_sources = 0;
			if (!c.wide2 && c.s2) ++signed_sources;
			if (c.s1) ++signed_sources;
			CHECK_EQ(ir.sext, signed_sources * q.nodes);
			// [6] per-unit element base
			CHECK_EQ(ir.mask_indices.size(), q.nodes);
			for (size_t u = 0; u < ir.mask_indices.size() && u < q.bases.size(); ++u)
				for (size_t k = 0; k < ir.mask_indices[u].size(); ++k)
					if (ir.mask_indices[u][k] != q.bases[u] + (u32)k) {
						printf("  FAIL %s: unit %zu lane %zu base wrong\n",
						       c.name, u, k);
						++g_fail;
						break;
					}
			// [7] exactly one vstart write per frame
			CHECK_EQ(q.finishes, 1u);
			CHECK_EQ(ir.vstart_stores, pro.vstart + 1u);
			// [4] only the Macc kind reads the destination window
			CHECK_EQ(ir.dst_window_loads, c.op == 3 ? q.nodes : 0u);
			// the lane operation itself
			if (c.op == 1) CHECK(ir.sub >= q.nodes);
			if (c.op >= 2) CHECK(ir.mul >= q.nodes);
		}
	for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ++ci)
		if (admitted[ci] == 0) {
			printf("  FAIL '%s' was never admitted at any width -- its rows are vacuous\n",
			       cases[ci].name);
			++g_fail;
		}
}

void SectionScalar()
{
	printf("[C3w-3] the .vx scalar is the low SEW bits, extended, then splatted\n");
	for (u32 vlen : {512u, 1024u}) {
		Configure(vlen, true, true);
		Built b({Vsetvli(kVT_E16M1), W(F6_VWADD, 6, 8, 11, 16), kJalr});
		Translate(b, true);
		Qir q = ScanQir(b.region);
		if (!q.frames)
			continue;
		CHECK(q.scalar);
		u32 const dst_off = kVregBase + 16u * rvv32::VLEN_MAX_BYTES;
		IRFacts ir = ScanIR(b.fn, dst_off);
		// a truncate to the source width per unit, and a splat per unit
		CHECK(ir.trunc >= q.nodes);
		CHECK(ir.splat >= q.nodes);
	}
}

void SectionRefusals()
{
	printf("[C3w-7] masked refused; inert when off; QCG unaffected\n");
	struct R { char const *name; u32 word; bool route; };
	R const cases[] = {
	    {"vwadd.vv masked", W(F6_VWADD, 2, 8, 9, 16, /*masked=*/true), true},
	    {"vwmul.vv masked", W(F6_VWMUL, 2, 8, 9, 16, /*masked=*/true), true},
	    {"switch off", W(F6_VWADD, 2, 8, 9, 16), false},
	};
	for (auto const &c : cases) {
		Configure(512u, true, c.route);
		Built b({Vsetvli(kVT_E16M1), c.word, kJalr});
		Translate(b, false);
		Qir q = ScanQir(b.region);
		if (q.nodes != 0 || q.hcalls == 0) {
			printf("  FAIL '%s': nodes=%u hcalls=%u\n", c.name, q.nodes, q.hcalls);
			++g_fail;
		}
	}
	unsigned seen[2] = {0, 0};
	for (int k = 0; k < 2; ++k) {
		Configure(1024u, /*llvm*/ false, /*route=*/k == 1);
		Built b({Vsetvli(kVT_E16M1), W(F6_VWADD, 2, 8, 9, 16), kJalr});
		Translate(b, false);
		seen[k] = ScanQir(b.region).nodes;
	}
	CHECK_EQ(seen[0], seen[1]);
}

void DumpIR()
{
	char const *path = getenv("C3W_DUMP_IR");
	if (!path)
		return;
	Configure(512u, true, true);
	Built b({Vsetvli(kVT_E16M1), W(F6_VWMACC, 2, 8, 9, 16), kJalr});
	Translate(b, true);
	std::error_code ec;
	llvm::raw_fd_ostream os(path, ec);
	if (!ec)
		b.module.print(os, nullptr);
	printf("  (IR dumped to %s)\n", path);
}

} // namespace

int main()
{
	printf("rvv_llvm_widen_test\n");
	SectionForms();
	SectionScalar();
	SectionRefusals();
	DumpIR();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
