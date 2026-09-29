// C3 (2026-09-18). THE NARROWING SHIFTS `vnsrl` / `vnsra` ON THE LLVM ARM.
//
// SECTIONS, and the failure each catches:
//   [1] SIGNEDNESS. `vnsra` must emit `ashr` and `vnsrl` `lshr`; the two are identical in any count
//       and differ on every source lane with its top bit set.
//   [2] THE SHIFT AMOUNT IS MASKED MODULO 2*SEW -- the SOURCE width, not the destination's. RVV 1.0
//       12.3. Asserted by reading the `and` mask constant out of the IR: a mask of `SEW*8-1` would
//       silently drop the top bit of a legal shift count and no count-based check would notice.
//       CHECKED FOR THE RUNTIME-AMOUNT FORMS ONLY (`.wv`, `.wx`): the `.wi` immediate is 5 bits, so
//       the mask is the identity at every admitted SEW and LLVM folds it away. Stated rather than
//       asserted, so the row is not mistaken for coverage it does not have.
//   [3] THE NARROW STORE TRUNCATES. `vnsrl`/`vnsra` are not saturating, so the IR must contain a
//       `trunc` to the destination width and no saturation. This is exactly what separates them
//       from `vnclip`.
//   [4] WIDTHS: source `<lanes x i(16*sew)>`, destination `<lanes x i(8*sew)>`,
//       `lanes = bytes/(2*sew)`.
//   [5] PER-UNIT ELEMENT BASE and exactly one `vstart` write per frame.
//   [6] `vnclip` IS REFUSED BY THIS ROUTE. (2026-09-19: it is no longer helper-only -- order item 4
//       gave it its own node and its own switch, `--rvv-llvm-nclip`, because it rounds by `vxrm`
//       and sets `vxsat` and is therefore not `vnsra` with a clamp bolted on. What this section
//       still asserts, and what still matters, is that the SHIFT route does not admit it: a
//       "generalisation" that let `vnclip` into this frame would drop both of those semantics
//       silently.)
//   [7] Masked forms refused; inert when off; QCG admission independent of the switch.
//
// A named form that is never admitted would make its rows vacuous, so admission is COUNTED and a
// never-admitted form fails -- the guard added after the widening test's `.wv` rows turned out to be
// silently skipped.

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

// OPIVV = funct3 0, OPIVI = 3, OPIVX = 4. vnsrl = funct6 44, vnsra = 45, vnclipu = 46, vnclip = 47.
constexpr u32 F6_VNSRL = 44u, F6_VNSRA = 45u, F6_VNCLIPU = 46u, F6_VNCLIP = 47u;
constexpr u32 N(u32 f6, u32 f3, u32 vs2, u32 vs1, u32 vd, bool masked = false)
{
	return (f6 << 26) | ((masked ? 0u : 1u) << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E16M1 = 0xc8u, kVT_E32M1 = 0xd0u;
constexpr u32 kJalr = 0x00008067u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c3n", g_ctx) {}
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
	config::rvv_llvm_narrow = route;
	config::rvv_qcg_typed_chunk = !llvm_backend;
	config::rvv_qcg_typed_chunk_force_emit = !llvm_backend;
	config::rvv_qcg_active_vl_narrow_bound = false;
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
	unsigned sew = 0, bytes = 0, src = 9;
	bool arith = false, masked = false;
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
			} else if (ins.GetOpcode() == Op::_vchunknarrowshift) {
				auto *n = static_cast<InstVChunkNarrowShift *>(&ins);
				++q.nodes;
				q.bases.push_back(n->base);
				q.sew = n->sew; q.bytes = n->bytes; q.src = n->src;
				q.arith = n->arith; q.masked = n->masked;
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
	unsigned ashr = 0, lshr = 0, shl = 0, trunc = 0;
	unsigned src_bits = 0, dst_bits = 0, lanes = 0;
	std::vector<u64> and_masks;
	unsigned vstart_stores = 0;
	std::vector<std::vector<u32>> mask_indices;
};

IRFacts ScanIR(llvm::Function *fn)
{
	IRFacts f;
	llvm::Value *state = fn->getArg(0);
	u32 const vstart_off = offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins)) {
				auto const c = bo->getOpcode();
				if (c == llvm::Instruction::AShr) ++f.ashr;
				else if (c == llvm::Instruction::LShr) ++f.lshr;
				else if (c == llvm::Instruction::Shl) ++f.shl;
				else if (c == llvm::Instruction::And) {
					if (auto *cv = llvm::dyn_cast<llvm::Constant>(bo->getOperand(1)))
						if (auto *sp = cv->getSplatValue())
							if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(sp))
								f.and_masks.push_back(ci->getZExtValue());
				}
				continue;
			}
			if (auto *c = llvm::dyn_cast<llvm::CastInst>(&ins)) {
				if (c->getOpcode() == llvm::Instruction::Trunc &&
				    llvm::isa<llvm::FixedVectorType>(c->getType())) {
					++f.trunc;
					auto *dv = llvm::cast<llvm::FixedVectorType>(c->getType());
					f.dst_bits = dv->getScalarSizeInBits();
					f.lanes = dv->getNumElements();
					if (auto *sv = llvm::dyn_cast<llvm::FixedVectorType>(c->getSrcTy()))
						f.src_bits = sv->getScalarSizeInBits();
				}
				continue;
			}
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
				if (ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
					continue;
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
void SectionShifts()
{
	printf("[C3n-1..5] signedness, 2*SEW mask, truncating store, widths, element base\n");
	struct Case { char const *name; u32 f6; u32 f3; bool arith; };
	Case const cases[] = {
	    {"vnsrl.wv", F6_VNSRL, 0, false}, {"vnsra.wv", F6_VNSRA, 0, true},
	    {"vnsrl.wi", F6_VNSRL, 3, false}, {"vnsra.wi", F6_VNSRA, 3, true},
	    {"vnsrl.wx", F6_VNSRL, 4, false}, {"vnsra.wx", F6_VNSRA, 4, true},
	};
	unsigned admitted[sizeof(cases) / sizeof(cases[0])] = {};
	for (u32 vlen : {256u, 512u, 1024u})
		for (u32 vtsel = 0; vtsel < 2; ++vtsel) {
			u32 const vt = vtsel ? kVT_E32M1 : kVT_E16M1;
			for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ++ci) {
				auto const &c = cases[ci];
				Configure(vlen, true, true);
				// vd narrow (v8), vs2 wide group (v16), vs1 narrow (v12)
				Built b({Vsetvli(vt), N(c.f6, c.f3, 16, 12, 8), kJalr});
				Translate(b, true);
				Qir q = ScanQir(b.region);
				if (!q.frames)
					continue;
				// C4-FIX: the frame must prove `vstart == 0`. This body's mask is `element_base + i < vl`
				// with no prestart term, and llvmgen emits NO vstart compare for `GuardKind::VTypeInteger`,
				// so that kind let a `csrw vstart, k` execution rewrite destination elements `[0, k)`.
				CHECK_EQ(q.guard_kind,
					 (int)InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart);
				++admitted[ci];
				Base const pro = Prologue(vt, vlen);
				CHECK_EQ(q.hcalls, pro.hcalls);
				CHECK(!q.masked);
				CHECK_EQ(q.arith, c.arith);

				IRFacts ir = ScanIR(b.fn);
				// [1] the right shift kind, and never the other
				CHECK_EQ(c.arith ? ir.ashr : ir.lshr, q.nodes);
				CHECK_EQ(c.arith ? ir.lshr : ir.ashr, 0u);
				// [3] a truncating narrow, one per unit
				CHECK_EQ(ir.trunc, q.nodes);
				// [4] widths: source is twice the destination
				CHECK_EQ(ir.dst_bits, 8u * q.sew);
				CHECK_EQ(ir.src_bits, 16u * q.sew);
				CHECK_EQ(ir.lanes, q.bytes / (2u * q.sew));
				// [2] The amount is masked modulo 2*SEW (the SOURCE width).
				//
				// ONLY THE RUNTIME-AMOUNT FORMS CAN BE CHECKED THIS WAY, and that is a
				// property of the ISA rather than a gap in the lowering: the `.wi`
				// immediate is a 5-bit `uimm`, so `imm & (2*SEW-1)` is the IDENTITY at
				// every SEW this route admits (2*SEW is 32 or 64), and LLVM constant-folds
				// the `and` out of the IR entirely. Asserting its presence there would be
				// asserting an artefact of the folder. For `.wv` and `.wx` the amount is a
				// run-time value, the mask survives, and a wrong modulus is visible.
				if (q.src != 2) {
					bool found = false;
					for (u64 m : ir.and_masks)
						if (m == 16ull * q.sew - 1ull)
							found = true;
					if (!found) {
						printf("  FAIL %s: no and-mask of %llu (2*SEW-1) in the IR\n",
						       c.name, 16ull * q.sew - 1ull);
						++g_fail;
					}
				}
				// [5] per-unit element base and one vstart write
				for (size_t u = 0; u < ir.mask_indices.size() && u < q.bases.size(); ++u)
					for (size_t k = 0; k < ir.mask_indices[u].size(); ++k)
						if (ir.mask_indices[u][k] != q.bases[u] + (u32)k) {
							printf("  FAIL %s: unit %zu base wrong\n", c.name, u);
							++g_fail;
							break;
						}
				CHECK_EQ(q.finishes, 1u);
				CHECK_EQ(ir.vstart_stores, pro.vstart + 1u);
			}
		}
	for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ++ci)
		if (admitted[ci] == 0) {
			printf("  FAIL '%s' was never admitted -- its rows are vacuous\n", cases[ci].name);
			++g_fail;
		}
}

void SectionRefusals()
{
	printf("[C3n-6,7] vnclip refused, masked refused, inert when off\n");
	struct R { char const *name; u32 word; bool route; };
	R const cases[] = {
	    // vnclip needs the partial-arm node this backend cannot lower
	    {"vnclipu.wv", N(F6_VNCLIPU, 0, 16, 12, 8), true},
	    {"vnclip.wv", N(F6_VNCLIP, 0, 16, 12, 8), true},
	    {"vnsrl.wv masked", N(F6_VNSRL, 0, 16, 12, 8, /*masked=*/true), true},
	    {"switch off", N(F6_VNSRL, 0, 16, 12, 8), false},
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
		Built b({Vsetvli(kVT_E16M1), N(F6_VNSRL, 0, 16, 12, 8), kJalr});
		Translate(b, false);
		seen[k] = ScanQir(b.region).nodes;
	}
	CHECK_EQ(seen[0], seen[1]);
}

void DumpIR()
{
	char const *path = getenv("C3N_DUMP_IR");
	if (!path)
		return;
	Configure(512u, true, true);
	Built b({Vsetvli(kVT_E16M1), N(F6_VNSRA, 0, 16, 12, 8), kJalr});
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
	printf("rvv_llvm_narrow_shift_test\n");
	SectionShifts();
	SectionRefusals();
	DumpIR();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
