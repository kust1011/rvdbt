// ORDER ITEM 4 (2026-09-19): THE NARROWING CLIP ON THE LLVM ARM -- `vnclipu` / `vnclip`.
//
// LAST OF THE FIVE NARROW FIXED-POINT NODES, and the only one that is all three of the family's
// mechanisms at once: a 2*SEW source narrowed to SEW, a `vxrm` rounding shift, and a saturating
// clip into `vxsat`. It is also the only one whose shift is a RUNTIME VECTOR, which is what forced
// `RvvRoundoffIncrement` to be generalised rather than copied.
//
// THIS HARNESS WORKS ON A MEMORY IMAGE, not on matched state offsets, and that is deliberate. This
// node is an offset-carrying `InstNoOperands`: it loads the wide source and stores the narrow
// destination itself, and its source group is TWICE its destination group, so at VLEN 256 chunk 1's
// source lives in `v9` while its destination lives in the second half of `v4`. Reconstructing that
// mapping in the test would mean re-deriving the very geometry under test. Instead every state load
// in the vector-register window is served from a byte image of `vreg`, and every masked store is
// written back into it -- so the harness reproduces MEMORY, and the node's own offsets decide what
// lands where. A wrong offset then shows up as a wrong result rather than as a harness mismatch.
//
// SECTIONS:
//   [N1] Admission and inertness: all three forms (`.wv`, `.wx`, `.wi`), both signednesses,
//        masked refused, and the route inert with its flag off.
//   [N2] THE DIFFERENTIAL against `rvv_ref::vnclip` through a real `VectorState`, over both
//        signednesses, `.wv` and `.wi`, five VLENs, both `vl`s and ALL FOUR `vxrm` values.
//   [N3] SATURATION IN BOTH DIRECTIONS, and `vxsat` clear when nothing clips -- the case that
//        fails for a route which sets the flag unconditionally.
//   [N4] A clipping lane BEYOND `vl` must not set `vxsat`.
//   [N5] The module verifies.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/llvmgen/rvv_test_llvm_compat.h"
#include "dbt/qmc/qir.h"

#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <memory>
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

llvm::LLVMContext &g_ctx = dbt::qir::g_llvm_ctx;

constexpr u32 F6_VNCLIPU = 46u, F6_VNCLIP = 47u, F6_VNSRL = 44u;
constexpr u32 F3_WV = 0u, F3_WI = 3u, F3_WX = 4u;
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kVT_E32M1 = 0xd0u;
constexpr u32 kJalr = 0x00008067u;
// The destination group is LMUL 1 and the source group is 2*LMUL, so they must not overlap:
// `v4` for the narrow destination, `v8`/`v9` for the wide source, `v12` for the narrow shift.
constexpr u32 kVd = 4u, kVs2 = 8u, kVs1 = 12u;

constexpr u32 N(u32 f6, u32 f3, u32 vs2, u32 vs1, u32 vd, bool vm = true)
{
	return (f6 << 26) | ((vm ? 1u : 0u) << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("oi4nclip", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_nclip = on;
	config::rvv_llvm_narrow = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_active_vl_narrow_bound = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_direct_setvl = true;
}

void Translate(Built &b)
{
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	LLVMGenCtx ctx(&b.module);
	ctx.AddFunction(0u, b.segment);
	QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
	b.fn = gen.Run();
}

struct Qir {
	unsigned frames = 0, nodes = 0, hcalls = 0, finishes = 0;
	int guard_kind = -1;
	unsigned sew = 0, bytes = 0, src = 9;
	bool is_signed = false, masked = false;
	std::vector<u32> bases;
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
			} else if (ins.GetOpcode() == Op::_vchunknarrowclip) {
				auto *n = static_cast<InstVChunkNarrowClip *>(&ins);
				++q.nodes;
				q.bases.push_back(n->base);
				q.sew = n->sew;
				q.bytes = n->bytes;
				q.src = n->src;
				q.is_signed = n->is_signed;
				q.masked = n->masked;
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

u32 StateOffset(llvm::Value *p, llvm::Value *state)
{
	if (StripToBase(p) != state || p == state)
		return ~0u;
	auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p);
	if (!g)
		return ~0u;
	llvm::APInt ap(64, 0);
	if (!g->accumulateConstantOffset(g->getModule()->getDataLayout(), ap))
		return ~0u;
	return (u32)ap.getZExtValue();
}

constexpr u32 kVregOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg));
constexpr u32 kVregBytes = 32u * rvv32::VLEN_MAX_BYTES;
constexpr u32 kVlOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl));
constexpr u32 kVxrmOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vxrm));
constexpr u32 kVxsatOff = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vxsat));

void FoldToFixpoint(llvm::Function *fn)
{
	auto const &DL = fn->getParent()->getDataLayout();
	for (bool again = true; again;) {
		again = false;
		for (auto &bb : *fn)
			for (auto it = bb.begin(); it != bb.end();) {
				llvm::Instruction &I = *it++;
				if (I.isTerminator() || I.mayHaveSideEffects() || I.use_empty())
					continue;
				if (auto *c = llvm::ConstantFoldInstruction(&I, DL)) {
					I.replaceAllUsesWith(c);
					again = true;
				}
			}
	}
}

struct Folded {
	bool ok = false;
	std::vector<u8> mem;
	int vxsat_bit = -1;
	bool ored = false;
};

// Serve a vector load from the byte image, and write a masked store back into it.
Folded FoldUnit(Built &b, std::vector<u8> const &initial, u32 vl, u32 vxrm)
{
	Folded out;
	out.mem = initial;
	llvm::Function *fn = b.fn;
	llvm::Value *state = fn->getArg(0);
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
			if (!l)
				continue;
			u32 const o = StateOffset(l->getPointerOperand(), state);
			if (o == kVlOff) {
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), vl));
				continue;
			}
			if (o == kVxrmOff) {
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), vxrm));
				continue;
			}
			if (o == kVxsatOff) {
				// 0x80: a bit the emitter never writes, so it distinguishes an OR
				// from an assignment. Pinning to 0 would let `or(0,x)` fold to `x`.
				l->replaceAllUsesWith(llvm::ConstantInt::get(l->getType(), 0x80u));
				continue;
			}
			auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType());
			if (!vt || o == ~0u || o < kVregOff || o >= kVregOff + kVregBytes)
				continue;
			u32 const lane_bits = vt->getScalarSizeInBits(), lb8 = lane_bits / 8u;
			llvm::SmallVector<llvm::Constant *, 16> cv;
			for (u32 i = 0; i < vt->getNumElements(); ++i) {
				llvm::APInt w(lane_bits, 0);
				for (u32 k = 0; k < lb8; ++k)
					w |= llvm::APInt(lane_bits,
							 out.mem[o - kVregOff + i * lb8 + k])
					     << (8u * k);
				cv.push_back(llvm::ConstantInt::get(vt->getElementType(), w));
			}
			l->replaceAllUsesWith(llvm::ConstantVector::get(cv));
		}
	FoldToFixpoint(fn);

	bool got = false, any_store = false, all_ored = true;
	int bits = 0;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
				if (ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
					continue;
				u32 const o = StateOffset(ii->getArgOperand(1), state);
				if (o == ~0u || o < kVregOff || o >= kVregOff + kVregBytes)
					continue;
				auto *c = llvm::dyn_cast<llvm::Constant>(ii->getArgOperand(0));
				auto *m = llvm::dyn_cast<llvm::Constant>(
				    testcompat::MaskedStoreMask(ii));
				if (!c || !m)
					return out;
				auto *vt = llvm::cast<llvm::FixedVectorType>(c->getType());
				u32 const lb8 = vt->getScalarSizeInBits() / 8u;
				for (u32 i = 0; i < vt->getNumElements(); ++i) {
					auto *mk = llvm::dyn_cast_or_null<llvm::ConstantInt>(
					    m->getAggregateElement(i));
					auto *e = llvm::dyn_cast_or_null<llvm::ConstantInt>(
					    c->getAggregateElement(i));
					if (!mk || !e)
						return out;
					if (!mk->isOne())
						continue; // inactive: memory keeps its old bytes
					llvm::APInt w = e->getValue();
					for (u32 k = 0; k < lb8; ++k)
						out.mem[o - kVregOff + i * lb8 + k] =
						    (u8)w.lshr(8u * k).getZExtValue();
				}
				got = true;
				continue;
			}
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!st || StateOffset(st->getPointerOperand(), state) != kVxsatOff)
				continue;
			// Accumulated across chunks: each chunk's load was pinned to 0x80, so each
			// store carries only its own contribution. See the `vsmul` harness, where
			// taking the last store instead produced spurious failures.
			any_store = true;
			if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(st->getValueOperand())) {
				u64 const w = ci->getZExtValue();
				all_ored = all_ored && (w & 0x80u) != 0;
				bits |= (int)(w & 1u);
			} else if (auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(
				       st->getValueOperand())) {
				all_ored = all_ored && bo->getOpcode() == llvm::Instruction::Or;
			} else {
				all_ored = false;
			}
		}
	if (any_store) {
		out.ored = all_ored;
		out.vxsat_bit = bits;
	}
	out.ok = got;
	return out;
}

// The reference, on a real VectorState, and the same state used to build the initial byte image so
// the two arms genuinely start from identical memory.
struct Ref {
	std::vector<u8> mem;
	u32 vxsat = 0;
};

std::vector<u8> BuildImage(u32 vlen, std::vector<u64> const &wide, std::vector<u32> const &shifts,
			   u32 lanes)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	for (u32 e = 0; e < lanes; ++e) {
		vs->elem_put(kVs2, e, 8, vlen, wide[e]);
		vs->elem_put(kVs1, e, 4, vlen, shifts[e]);
		vs->elem_put(kVd, e, 4, vlen, 0xdeadbeefu);
	}
	std::vector<u8> mem(kVregBytes, 0);
	std::memcpy(mem.data(), &vs->vreg[0][0], kVregBytes);
	return mem;
}

Ref RefClip(bool is_signed, u32 f3, u32 imm, u32 vxrm, u32 vl, u32 vlen,
	    std::vector<u8> const &initial)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], initial.data(), kVregBytes);
	vs->vl = vl;
	vs->vstart = 0;
	vs->vxrm = vxrm;
	vs->vxsat = 0;
	rvv32::VSrc const src = f3 == F3_WV ? rvv32::VSrc::VV : rvv32::VSrc::VI;
	rvv32::rvv_ref::vnclip(*vs, is_signed, src, kVd, kVs2, kVs1, 0, imm, /*vm=*/true, vlen, vl,
			       4);
	Ref r;
	r.mem.assign(kVregBytes, 0);
	std::memcpy(r.mem.data(), &vs->vreg[0][0], kVregBytes);
	r.vxsat = vs->vxsat;
	return r;
}

struct KindRow { char const *name; u32 f6; bool is_signed; };
KindRow const kKinds[] = {
    {"vnclipu", F6_VNCLIPU, false},
    {"vnclip", F6_VNCLIP, true},
};
char const *kModes[] = {"rnu", "rne", "rdn", "rod"};

void SectionAdmission()
{
	printf("[N1] admission, all three forms, refusals, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds)
			for (u32 f3 : {F3_WV, F3_WX, F3_WI}) {
				Configure(vlen, true);
				u32 const s1 = f3 == F3_WV ? kVs1 : (f3 == F3_WX ? 3u : 5u);
				Built b({Vsetvli(kVT_E32M1), N(k.f6, f3, kVs2, s1, kVd), kJalr});
				Translate(b);
				Qir const q = ScanQir(b.region);
				if (!q.nodes)
					continue;
				++admitted;
				CHECK_EQ(q.frames, 1u);
				CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
				CHECK_EQ(q.is_signed, k.is_signed);
				CHECK_EQ(q.masked, false);
				CHECK_EQ(q.sew, 4u);
				// Exactly one vstart write per frame, on the last chunk.
				CHECK_EQ(q.finishes, 1u);
				u32 const lanes = q.bytes / 8u;
				for (u32 c = 0; c < q.bases.size(); ++c)
					CHECK_EQ(q.bases[c], c * lanes);
				Configure(vlen, false);
				Built o({Vsetvli(kVT_E32M1), N(k.f6, f3, kVs2, s1, kVd), kJalr});
				Translate(o);
				CHECK_EQ(ScanQir(o.region).nodes, 0u);
				CHECK(ScanQir(o.region).hcalls >= 1u);
			}
	printf("       %u admitted kind/form/width cells\n", admitted);
	// All three forms must appear at each of five widths for both signednesses, or a named row
	// below is vacuous.
	CHECK_EQ(admitted, 30u);

	struct Row { char const *why; u32 word; };
	Row const rows[] = {
	    {"masked (vm == 0)", N(F6_VNCLIP, F3_WV, kVs2, kVs1, kVd, false)},
	    {"vnsrl is a different route", N(F6_VNSRL, F3_WV, kVs2, kVs1, kVd)},
	    // The destination group overlaps the wide source group: RVV 1.0 5.2.
	    {"vd overlaps the wide source", N(F6_VNCLIP, F3_WV, kVs2, kVs1, kVs2 + 1u)},
	};
	for (u32 vlen : {256u, 512u})
		for (auto const &r : rows) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1), r.word, kJalr});
			Translate(b);
			if (ScanQir(b.region).nodes) {
				printf("  FAIL refusal not honoured (%s, vlen=%u)\n", r.why, vlen);
				++g_fail;
			}
		}
}

void RunCell(char const *label, u32 f6, bool is_signed, u32 f3, u32 imm, u32 vlen, u32 vl,
	     u32 vxrm, std::vector<u64> const &wide, std::vector<u32> const &shifts, unsigned *cells,
	     int want_vxsat)
{
	Configure(vlen, true);
	u32 const s1 = f3 == F3_WV ? kVs1 : imm;
	Built b({Vsetvli(kVT_E32M1), N(f6, f3, kVs2, s1, kVd), kJalr});
	Translate(b);
	if (!ScanQir(b.region).nodes || !b.fn)
		return;
	u32 const lanes = vlen / 32u;
	std::vector<u8> const initial = BuildImage(vlen, wide, shifts, lanes);
	Folded const f = FoldUnit(b, initial, vl, vxrm);
	if (!f.ok) {
		printf("  FAIL %s %s vlen=%u vl=%u: did not fold\n", label, kModes[vxrm], vlen, vl);
		++g_fail;
		return;
	}
	Ref const r = RefClip(is_signed, f3, imm, vxrm, vl, vlen, initial);
	// COMPARE THE WHOLE REGISTER IMAGE, not just the active lanes. That is what catches a
	// destination written outside `vl`, or a chunk whose offset landed in the wrong register.
	if (f.mem != r.mem) {
		u32 shown = 0;
		for (u32 i = 0; i < kVregBytes && shown < 4; ++i)
			if (f.mem[i] != r.mem[i]) {
				printf("  FAIL %s %s vlen=%u vl=%u: vreg byte %u (v%u+%u) emitted "
				       "%02x, reference %02x\n",
				       label, kModes[vxrm], vlen, vl, i,
				       i / rvv32::VLEN_MAX_BYTES, i % rvv32::VLEN_MAX_BYTES,
				       f.mem[i], r.mem[i]);
				++shown;
				++g_fail;
			}
	}
	if (f.vxsat_bit >= 0 && (u32)f.vxsat_bit != r.vxsat) {
		printf("  FAIL %s %s vlen=%u vl=%u: vxsat %d, reference %u\n", label, kModes[vxrm],
		       vlen, vl, f.vxsat_bit, r.vxsat);
		++g_fail;
	}
	if (want_vxsat >= 0) {
		CHECK_EQ(r.vxsat, (u32)want_vxsat);
		if (f.vxsat_bit >= 0 && f.vxsat_bit != want_vxsat) {
			printf("  FAIL %s %s vlen=%u vl=%u: emitted vxsat %d, expected %d\n", label,
			       kModes[vxrm], vlen, vl, f.vxsat_bit, want_vxsat);
			++g_fail;
		}
	}
	if (!f.ored) {
		printf("  FAIL %s %s vlen=%u vl=%u: vxsat was ASSIGNED, not ORed\n", label,
		       kModes[vxrm], vlen, vl);
		++g_fail;
	}
	++*cells;
}

void SectionDifferential()
{
	printf("[N2] the whole register image against rvv_ref::vnclip, across ALL FOUR vxrm\n");
	unsigned cells = 0;
	// Wide sources spanning both signs and the magnitudes that clip at small shifts, and shift
	// amounts including 0 (no rounding at all) and 63 (the modulo-2*SEW maximum).
	std::vector<u64> const wp = {
	    0x0000000000000000ull, 0xffffffffffffffffull, 0x000000007fffffffull,
	    0x0000000080000000ull, 0x7fffffffffffffffull, 0x8000000000000000ull,
	    0x00000000ffffffffull, 0x0000000100000000ull, 0xfffffffff0000000ull,
	    0x0123456789abcdefull, 0xfedcba9876543210ull, 0x00000000c0000000ull,
	    0x0000000040000000ull, 0xffffffff80000000ull, 0x0000000000000003ull,
	    0x0000000000000001ull};
	std::vector<u32> const sp = {0u, 1u, 2u, 31u, 32u, 63u, 3u, 30u,
				     0u, 1u, 33u, 62u, 5u, 16u, 1u, 0u};
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds)
			for (u32 f3 : {F3_WV, F3_WI}) {
				u32 const total = vlen / 32u;
				std::vector<u64> wide(total);
				std::vector<u32> shifts(total);
				for (u32 e = 0; e < total; ++e) {
					wide[e] = wp[e % wp.size()];
					shifts[e] = sp[e % sp.size()];
				}
				for (u32 vl : {total, total / 2u})
					for (u32 vxrm = 0; vxrm < 4; ++vxrm)
						RunCell(k.name, k.f6, k.is_signed, f3,
							/*imm=*/5u, vlen, vl, vxrm, wide, shifts,
							&cells, -1);
			}
	printf("       %u cells compared against the reference\n", cells);
	CHECK(cells > 0);
}

void SectionSaturation()
{
	printf("[N3] clipping in both directions, and vxsat clear when nothing clips\n");
	u32 const vlen = 256u, total = vlen / 32u;
	struct Case { char const *name; u64 w; u32 sh; int want_u; int want_s; };
	Case const cases[] = {
	    // shift 0: the wide value passes through and must clip if it does not fit SEW.
	    {"above the unsigned max", 0x0000000100000000ull, 0u, 1, 1},
	    {"above the signed max", 0x0000000080000000ull, 0u, 0, 1},
	    {"below the signed min", 0xffffffff00000000ull, 0u, 1, 1},
	    {"fits exactly (unsigned max)", 0x00000000ffffffffull, 0u, 0, 1},
	    {"fits exactly (signed max)", 0x000000007fffffffull, 0u, 0, 0},
	    {"shifted well inside", 0x7fffffffffffffffull, 40u, 0, 0},
	    {"zero", 0x0000000000000000ull, 0u, 0, 0},
	};
	for (auto const &c : cases)
		for (auto const &k : kKinds)
			for (u32 vxrm = 0; vxrm < 4; ++vxrm) {
				std::vector<u64> wide(total, c.w);
				std::vector<u32> shifts(total, c.sh);
				unsigned cells = 0;
				RunCell(c.name, k.f6, k.is_signed, F3_WV, 0u, vlen, total, vxrm,
					wide, shifts, &cells, k.is_signed ? c.want_s : c.want_u);
			}
}

// [N4] A CLIPPING LANE BEYOND `vl` MUST NOT SET THE FLAG.
//
// Written from the start here because the `vsmul` gate showed what its absence costs: the mutation
// that drops the active-lane gate from the `vxsat` reduction survives every test whose saturating
// lanes are all inside `vl`.
void SectionTailSaturation()
{
	printf("[N4] a clipping lane beyond vl must NOT set vxsat\n");
	unsigned checked = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		u32 const total = vlen / 32u, vl = total / 2u;
		if (vl == 0)
			continue;
		std::vector<u64> wide(total, 0ull);
		std::vector<u32> shifts(total, 0u);
		for (u32 e = vl; e < total; ++e)
			wide[e] = 0x0000000100000000ull; // clips for both signednesses
		for (auto const &k : kKinds)
			for (u32 vxrm = 0; vxrm < 4; ++vxrm) {
				unsigned cells = 0;
				RunCell("tail", k.f6, k.is_signed, F3_WV, 0u, vlen, vl, vxrm, wide,
					shifts, &cells, 0);
				checked += cells;
			}
	}
	printf("       %u tail cells\n", checked);
	CHECK(checked > 0);
}

void SectionVerify()
{
	printf("[N5] the emitted module verifies\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &k : kKinds) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT_E32M1), N(k.f6, F3_WV, kVs2, kVs1, kVd), kJalr});
			Translate(b);
			std::string err;
			llvm::raw_string_ostream es(err);
			if (llvm::verifyModule(b.module, &es)) {
				printf("  FAIL %s vlen=%u: %s\n", k.name, vlen, err.c_str());
				++g_fail;
			}
		}
}

} // namespace

int main()
{
	printf("rvv_llvm_nclip_test: order item 4, the narrowing clip\n");
	SectionAdmission();
	SectionDifferential();
	SectionSaturation();
	SectionTailSaturation();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
