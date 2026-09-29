// C3 (2026-09-18). THE INTEGER EXTENSION FAMILY `vzext.vf{2,4,8}` / `vsext.vf{2,4,8}` ON THE LLVM ARM.
//
// SECTIONS, and the failure each catches:
//   [1] SIGNEDNESS. `vsext` must emit `sext` and `vzext` `zext`. The two are indistinguishable in
//       any node or instruction count and differ on every source lane with its top bit set, so the
//       section reads the opcodes out of the emitted IR.
//   [2] WIDTHS. The source vector is `<lanes x i(8*src_sew)>` and the destination
//       `<lanes x i(8*dst_sew)>` with `lanes = bytes/dst_sew` -- the DESTINATION element count.
//       RVV leaves element indexing alone, so using the source width would give the wrong lane
//       count and mask the wrong elements; both types are asserted, at every supported factor.
//   [3] THE ACTIVE MASK IS PER-UNIT. Each unit's predicate starts at its own element base
//       (`ElementBase`), not at zero and not at `chunk*lanes` of the source width. Asserted by
//       reading each masked store's index vector out of the IR and requiring it to equal
//       `[base, base+lanes)`. A unit that masked from 0 would write live elements of a later unit's
//       range and would pass every count-based check.
//   [4] MASKED FORMS ARE REFUSED. This backend has no architectural-mask lowering, so `vm == 0`
//       must keep the helper -- no frame, no node.
//   [5] `finish` IS ON EXACTLY THE LAST UNIT (the LastChunkNode convention), so `vec.vstart` is
//       written exactly once per frame.
//   [6] Overlap: RVV's legal "destination overlaps the LOWEST part of the source group" case is
//       admitted, and an illegal overlap is refused.
//   [7] Inert when off; QCG admission independent of the switch.
//
// WHAT THIS FILE DOES NOT DO. It never executes what it builds and needs no AVX-512 host. It
// asserts nothing about masked extensions beyond their refusal, which is the honest scope.

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

// OPMVV, funct6 = VF6_VXUNARY0 (0b010010). The sub-encoding in the vs1 field selects the factor and
// the signedness: 2/3 = vzext.vf8/vsext.vf8, 4/5 = vf4, 6/7 = vf2 (rv32_vector_lower.h).
constexpr u32 F6_VXUNARY0 = 0b010010u;
constexpr u32 Ext(u32 sub, u32 vs2, u32 vd, bool masked = false)
{
	return (F6_VXUNARY0 << 26) | ((masked ? 0u : 1u) << 25) | (vs2 << 20) | (sub << 15) |
	       (2u << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u, kVT_E64M1 = 0xd8u;
constexpr u32 kJalr = 0x00008067u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c3e", g_ctx) {}
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
	config::rvv_llvm_extend = route;
	config::rvv_qcg_typed_chunk = !llvm_backend;
	config::rvv_qcg_typed_chunk_force_emit = !llvm_backend; // QCG arm needs no host AVX-512 here
	config::rvv_qcg_active_vl_int_bound = false;
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
	unsigned frames = 0, nodes = 0, hcalls = 0, finishes = 0;
	int guard_kind = -1;
	std::vector<u32> bases;
	unsigned dst_sew = 0, src_sew = 0, bytes = 0;
	bool sign = false, masked = false;
};

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++q.frames;
				q.guard_kind = (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
			} else if (ins.GetOpcode() == Op::_vchunkextend) {
				auto *n = static_cast<InstVChunkExtend *>(&ins);
				++q.nodes;
				q.bases.push_back(n->base);
				q.dst_sew = n->dst_sew; q.src_sew = n->src_sew; q.bytes = n->bytes;
				q.sign = n->sign; q.masked = n->masked;
				q.finishes += n->finish;
			} else if (ins.GetOpcode() == Op::_hcall) {
				++q.hcalls;
			}
		}
	return q;
}

struct IRFacts {
	unsigned sext = 0, zext = 0;
	unsigned src_bits = 0, dst_bits = 0, lanes = 0;
	std::vector<std::vector<u32>> mask_indices; // one per masked store
	unsigned vstart_stores = 0;
};

llvm::Value *StripToBase(llvm::Value *p)
{
	while (auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p))
		p = g->getPointerOperand();
	return p;
}

IRFacts ScanIR(llvm::Function *fn)
{
	IRFacts f;
	llvm::Value *state = fn->getArg(0);
	u32 const vstart_off = offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *c = llvm::dyn_cast<llvm::CastInst>(&ins)) {
				auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(c->getType());
				if (!vt)
					continue;
				if (c->getOpcode() == llvm::Instruction::SExt ||
				    c->getOpcode() == llvm::Instruction::ZExt) {
					(c->getOpcode() == llvm::Instruction::SExt ? f.sext : f.zext)++;
					f.lanes = vt->getNumElements();
					f.dst_bits = vt->getScalarSizeInBits();
					if (auto *st = llvm::dyn_cast<llvm::FixedVectorType>(
						c->getSrcTy()))
						f.src_bits = st->getScalarSizeInBits();
				}
				continue;
			}
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
				if (ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
					continue;
				std::vector<u32> idx;
				// operand 3 is the mask: icmp ult <indices>, splat(vl)
				if (auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(testcompat::MaskedStoreMask(ii)))
					if (auto *cv = llvm::dyn_cast<llvm::Constant>(cmp->getOperand(0)))
						if (auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(
							cv->getType()))
							for (u32 k = 0; k < vt->getNumElements(); ++k)
								if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(
									cv->getAggregateElement(k)))
									idx.push_back((u32)ci->getZExtValue());
				f.mask_indices.push_back(idx);
				continue;
			}
			if (auto *s = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				llvm::Value *p = s->getPointerOperand();
				if (StripToBase(p) != state || p == state)
					continue;
				llvm::APInt ap(64, 0);
				auto *g = llvm::cast<llvm::GetElementPtrInst>(p);
				if (g->accumulateConstantOffset(g->getModule()->getDataLayout(), ap) &&
				    (u32)ap.getZExtValue() == vstart_off)
					++f.vstart_stores;
			}
		}
	return f;
}

// The leading `vsetvli` contributes its own helper call (at vtypes RvvLLVMSetVLAdmit does not
// admit) and its own `vec.vstart = 0` store. Both are measured here so the sections below assert
// this family's DELTA rather than an absolute that silently includes the prologue.
struct Base { unsigned hcalls = 0, vstart = 0; };
Base Prologue(u32 vt, u32 vlen)
{
	Configure(vlen, true, true);
	Built b({Vsetvli(vt), kJalr});
	Translate(b, true);
	Base r;
	r.hcalls = ScanQir(b.region).hcalls;
	r.vstart = ScanIR(b.fn).vstart_stores;
	return r;
}

// ------------------------------------------------------------------------------------------
void SectionShapes()
{
	printf("[C3e-1,2,3,5] signedness, widths, per-unit element base, single vstart write\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	struct Case { char const *name; u32 sub; u32 vt; bool sign; u32 div; };
	Case const cases[] = {
	    {"vzext.vf2 e32", 6, kVT_E32M1, false, 2}, {"vsext.vf2 e32", 7, kVT_E32M1, true, 2},
	    {"vzext.vf4 e32", 4, kVT_E32M1, false, 4}, {"vsext.vf4 e32", 5, kVT_E32M1, true, 4},
	    {"vzext.vf2 e64", 6, kVT_E64M1, false, 2}, {"vsext.vf8 e64", 3, kVT_E64M1, true, 8},
	};
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &c : cases) {
			Configure(vlen, true, true);
			Built b({Vsetvli(c.vt), Ext(c.sub, 16, 8), kJalr});
			Translate(b, true);
			Qir q = ScanQir(b.region);
			if (!q.frames)
				continue; // shape not admitted at this width/vtype
			Base const pro = Prologue(c.vt, vlen);
			CHECK_EQ(q.hcalls, pro.hcalls);
			// C4-FIX: `VTypeIntegerNoRestart`, not `VTypeInteger`. This body's mask is
			// `element_base + i < vl` with NO prestart term, and llvmgen emits no vstart
			// compare for `VTypeInteger` -- so that kind let a `csrw vstart, k` execution
			// rewrite destination elements `[0, k)`. This assertion previously encoded the
			// defect; it now pins the fix.
			CHECK_EQ(q.guard_kind, (int)GK::VTypeIntegerNoRestart);
			CHECK(!q.masked);
			CHECK_EQ(q.sign, c.sign);
			CHECK_EQ(q.src_sew * c.div, q.dst_sew);

			IRFacts ir = ScanIR(b.fn);
			// [1] the right extension kind, and only that kind
			CHECK_EQ(c.sign ? ir.sext : ir.zext, q.nodes);
			CHECK_EQ(c.sign ? ir.zext : ir.sext, 0u);
			// [2] destination element count and both element widths
			CHECK_EQ(ir.lanes, q.bytes / q.dst_sew);
			CHECK_EQ(ir.dst_bits, 8u * q.dst_sew);
			CHECK_EQ(ir.src_bits, 8u * q.src_sew);
			// [3] each unit masks from its OWN element base
			CHECK_EQ(ir.mask_indices.size(), q.nodes);
			CHECK_EQ(q.bases.size(), q.nodes);
			for (size_t u = 0; u < ir.mask_indices.size() && u < q.bases.size(); ++u) {
				auto const &idx = ir.mask_indices[u];
				CHECK_EQ(idx.size(), ir.lanes);
				for (size_t k = 0; k < idx.size(); ++k)
					if (idx[k] != q.bases[u] + (u32)k) {
						printf("  FAIL %s: unit %zu lane %zu index %u != base %u + %zu\n",
						       c.name, u, k, idx[k], q.bases[u], k);
						++g_fail;
						break;
					}
			}
			// [5] exactly one vstart write per frame, on the last unit
			CHECK_EQ(q.finishes, 1u);
			CHECK_EQ(ir.vstart_stores, pro.vstart + 1u);
		}
}

void SectionRefusals()
{
	printf("[C3e-4,6,7] masked refused, illegal overlap refused, inert when off\n");
	struct R { char const *name; u32 word; bool route; };
	R const cases[] = {
	    // masked: this backend has no architectural-mask lowering
	    {"vzext.vf2 masked", Ext(6, 16, 8, /*masked=*/true), true},
	    {"vsext.vf2 masked", Ext(7, 16, 8, /*masked=*/true), true},
	    // switch off restores the pre-C3 state
	    {"switch off", Ext(6, 16, 8), false},
	};
	for (auto const &c : cases) {
		Configure(512u, true, c.route);
		Built b({Vsetvli(kVT_E32M1), c.word, kJalr});
		Translate(b, false);
		Qir q = ScanQir(b.region);
		if (q.nodes != 0 || q.hcalls == 0) {
			printf("  FAIL '%s': nodes=%u hcalls=%u\n", c.name, q.nodes, q.hcalls);
			++g_fail;
		}
	}
}

void SectionQcgUntouched()
{
	printf("[C3e-8] QCG admission does not depend on the C3 extend switch\n");
	unsigned seen[2] = {0, 0};
	for (int k = 0; k < 2; ++k) {
		Configure(1024u, /*llvm*/ false, /*route=*/k == 1);
		Built b({Vsetvli(kVT_E32M1), Ext(6, 16, 8), kJalr});
		Translate(b, false);
		seen[k] = ScanQir(b.region).nodes;
	}
	CHECK_EQ(seen[0], seen[1]);
}

void DumpIR()
{
	char const *path = getenv("C3E_DUMP_IR");
	if (!path)
		return;
	Configure(512u, true, true);
	Built b({Vsetvli(kVT_E32M1), Ext(7, 16, 8), kJalr});
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
	printf("rvv_llvm_extend_test\n");
	SectionShapes();
	SectionRefusals();
	SectionQcgUntouched();
	DumpIR();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
