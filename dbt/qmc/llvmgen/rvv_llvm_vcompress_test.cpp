// C6 (2026-09-19): `vcompress.vm` -- PACK THE SELECTED ELEMENTS INTO THE LOW END OF `vd`.
//
// THE ONE C6 FAMILY THAT IS NOT A PER-ELEMENT FUNCTION OF ITS INPUTS. The write index runs BEHIND
// the read index, so source element `e` lands at destination position `viota(vs1)[e]` -- and that
// is what every section here is built to pin, because a lowering that got the SELECTION right and
// the POSITIONS wrong would still produce the right multiset of values.
//
// THE PATTERNS ARE CHOSEN FOR THE POSITION, NOT THE SELECTION:
//   * a selector whose set bits are SPARSE and late, so the compressed values come from high
//     source elements and land at low destination ones -- a route that wrote in place would agree
//     with the reference only where the selector is a prefix;
//   * a selector that is a PREFIX (0x0f), which is exactly the case an in-place route gets right,
//     included so the contrast is in the same run;
//   * an EMPTY selector, where nothing is written and the whole destination keeps its fill;
//   * a FULL selector, where the compression is the identity;
//   * selectors spanning several chunks, so the running count has to carry across them.
//
// SECTIONS:
//   [C1] Admission and inertness, including LMUL > 1 being REFUSED (an addressing limit) and the
//        register-overlap rules.
//   [C2] The differential against `rvv_ref::vcompress`, whole register image.
//   [C3] Elements at or beyond the compressed COUNT are undisturbed -- which is not the same
//        statement as "at or beyond vl", and is the one that catches a store that ran too far.
//   [C4] The module verifies.

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
#include <cstring>
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

constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
// vta | vma | vsew << 3 | vlmul; LMUL 1 throughout.
constexpr u32 kVT[4] = {0xc0u, 0xc8u, 0xd0u, 0xd8u}; // e8, e16, e32, e64
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVd = 4u, kVs2 = 8u, kVs1 = 12u;
constexpr u32 F3_MV = 2u, F3_IV = 0u;

constexpr u32 R(u32 f6, u32 f3, u32 vs2, u32 vs1, u32 vd, bool vm = true)
{
	return (f6 << 26) | ((vm ? 1u : 0u) << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}
// funct6: vmandn 24, vmand 25, vmor 26, vmxor 27, vmorn 28, vmnand 29, vmnor 30, vmxnor 31.
constexpr u32 F6_BASE = 24u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c6vcompress", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_vcompress = on;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_vector_run = false;
	// OFF: the direct-state `vsetvli` route is admitted for exactly `e32, m1`, and with it on
	// `vec.vl` at SEW 32 is not a state LOAD this harness can pin.
	config::rvv_qcg_direct_setvl = false;
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
	unsigned op = 99;
	std::vector<u32> bases;
};
// vmsbf 1, vmsof 2, vmsif 3 in the encoding; 0 before / 1 including / 2 only-first on the node.

Qir ScanQir(Region *r)
{
	Qir q;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				++q.frames;
				q.guard_kind =
				    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)->guard_kind;
			} else if (ins.GetOpcode() == Op::_vcompressnative) {
				auto *n = static_cast<InstVCompress *>(&ins);
				++q.nodes;
				q.op = n->sew;
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

// THE POINTER HERE IS A CHAIN, AND ITS SECOND LINK IS DYNAMIC IN THE IR. `vcompress` stores at
// `vd_base + n * sew` where `n` is a running count, so the emitter builds a constant GEP to the
// register and then a second GEP by a computed byte offset. `accumulateConstantOffset` on the outer
// GEP alone sees only the outer index; the whole chain has to be walked, and it resolves only
// because `n` folds to a constant once the source is pinned.
u32 StateOffsetChain(llvm::Value *p, llvm::Value *state, llvm::DataLayout const &DL)
{
	u64 total = 0;
	while (auto *g = llvm::dyn_cast<llvm::GetElementPtrInst>(p)) {
		llvm::APInt ap(64, 0);
		if (!g->accumulateConstantOffset(DL, ap))
			return ~0u;
		total += ap.getZExtValue();
		p = g->getPointerOperand();
	}
	return p == state ? (u32)total : ~0u;
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
};

Folded FoldUnit(Built &b, std::vector<u8> const &initial, u32 vl)
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
			if (o == ~0u || o < kVregOff || o >= kVregOff + kVregBytes)
				continue;
			// BOTH the scalar seed load and the vector chunk loads come from here. The
			// seed is a plain integer at SEW, not a vector, so a filter on vector types
			// would leave it symbolic and nothing would fold.
			if (auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(l->getType())) {
				u32 const lb8 = vt->getScalarSizeInBits() / 8u;
				llvm::SmallVector<llvm::Constant *, 64> cv;
				for (u32 i = 0; i < vt->getNumElements(); ++i) {
					llvm::APInt w(vt->getScalarSizeInBits(), 0);
					for (u32 k = 0; k < lb8; ++k)
						w |= llvm::APInt(vt->getScalarSizeInBits(),
								 out.mem[o - kVregOff + i * lb8 + k])
						     << (8u * k);
					cv.push_back(llvm::ConstantInt::get(vt->getElementType(), w));
				}
				l->replaceAllUsesWith(llvm::ConstantVector::get(cv));
			} else if (auto *it = llvm::dyn_cast<llvm::IntegerType>(l->getType())) {
				u32 const lb8 = it->getBitWidth() / 8u;
				llvm::APInt w(it->getBitWidth(), 0);
				for (u32 k = 0; k < lb8; ++k)
					w |= llvm::APInt(it->getBitWidth(),
							 out.mem[o - kVregOff + k])
					     << (8u * k);
				l->replaceAllUsesWith(llvm::ConstantInt::get(it, w));
			}
		}
	FoldToFixpoint(fn);

	bool got = false;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			// THIS FAMILY STORES A PLAIN WORD, NOT A MASKED VECTOR. The blend is done in
			// the value -- `(computed & active) | (old & ~active)` -- because bits beyond
			// `vl` must be UNDISTURBED and there is no per-bit store predicate to express
			// that. A harness that only wrote back `masked.store` results saw no store at
			// all here and reported "did not fold" for every cell.
			if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				u32 const so = StateOffset(st->getPointerOperand(), state);
				if (so == ~0u || so < kVregOff || so >= kVregOff + kVregBytes)
					continue;
				auto *cv = llvm::dyn_cast<llvm::ConstantInt>(st->getValueOperand());
				if (!cv)
					return out;
				u32 const w8 = cv->getBitWidth() / 8u;
				for (u32 k = 0; k < w8; ++k)
					out.mem[so - kVregOff + k] =
					    (u8)cv->getValue().lshr(8u * k).getZExtValue();
				got = true;
				continue;
			}
			auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
			if (ii && ii->getIntrinsicID() == llvm::Intrinsic::masked_compressstore) {
				// value, ptr, mask -- and the selected lanes land CONTIGUOUSLY from
				// the pointer, which is the whole operation.
				auto const &DL = fn->getParent()->getDataLayout();
				u32 const o = StateOffsetChain(ii->getArgOperand(1), state, DL);
				if (o == ~0u || o < kVregOff || o >= kVregOff + kVregBytes)
					return out;
				auto *c = llvm::dyn_cast<llvm::Constant>(ii->getArgOperand(0));
				auto *m = llvm::dyn_cast<llvm::Constant>(ii->getArgOperand(2));
				if (!c || !m)
					return out;
				auto *vt = llvm::cast<llvm::FixedVectorType>(c->getType());
				u32 const lb8 = vt->getScalarSizeInBits() / 8u;
				u32 put = 0;
				for (u32 i = 0; i < vt->getNumElements(); ++i) {
					auto *mk = llvm::dyn_cast_or_null<llvm::ConstantInt>(
					    m->getAggregateElement(i));
					auto *e = llvm::dyn_cast_or_null<llvm::ConstantInt>(
					    c->getAggregateElement(i));
					if (!mk || !e)
						return out;
					if (!mk->isOne())
						continue;
					llvm::APInt w = e->getValue();
					for (u32 k = 0; k < lb8; ++k)
						out.mem[o - kVregOff + put * lb8 + k] =
						    (u8)w.lshr(8u * k).getZExtValue();
					++put;
				}
				got = true;
				continue;
			}
			if (!ii || ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
				continue;
			u32 const o = StateOffset(ii->getArgOperand(1), state);
			if (o == ~0u || o < kVregOff || o >= kVregOff + kVregBytes)
				continue;
			auto *c = llvm::dyn_cast<llvm::Constant>(ii->getArgOperand(0));
			auto *m = llvm::dyn_cast<llvm::Constant>(testcompat::MaskedStoreMask(ii));
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
					continue; // vl == 0: memory keeps its old bytes
				llvm::APInt w = e->getValue();
				for (u32 k = 0; k < lb8; ++k)
					out.mem[o - kVregOff + i * lb8 + k] =
					    (u8)w.lshr(8u * k).getZExtValue();
			}
			got = true;
		}
	out.ok = got;
	return out;
}

// A mask register is written as raw BYTES: its EEW is 1 and the guest's accessor is bit-indexed.
// THE FILL COVERS THE WHOLE REGISTER FILE, not just `kVd`. The destination here is an LMUL-SIZED
// GROUP -- eight registers at LMUL 8 -- so filling one register left the other seven at zero and
// [I3] reported every LMUL-8 element beyond `vl` as "written" when nothing had touched it. Filling
// everything and then laying the source over `vs2` is correct for any group size.
// `kVs1` carries the SELECTOR (a mask register) and `kVs2` the data; the whole file is filled so
// an LMUL-sized destination group is covered wherever it lands.
std::vector<u8> BuildImage(std::vector<u8> const &sel, std::vector<u8> const &dfill)
{
	std::vector<u8> mem(kVregBytes, dfill[0]);
	for (u32 i = 0; i < kVregBytes; ++i)
		mem[i] = dfill[i % dfill.size()];
	for (u32 i = 0; i < rvv32::VLEN_MAX_BYTES; ++i) {
		mem[kVs1 * rvv32::VLEN_MAX_BYTES + i] = sel[i % sel.size()];
		// The DATA is element-distinctive: byte i of vs2 is i, so a value landing at the
		// wrong destination position names the source element it came from.
		mem[kVs2 * rvv32::VLEN_MAX_BYTES + i] = (u8)(i * 7u + 1u);
	}
	return mem;
}

std::vector<u8> RefCompress(u32 vl, u32 vlen, u32 sew, std::vector<u8> const &initial)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], initial.data(), kVregBytes);
	vs->vl = vl;
	vs->vstart = 0;
	rvv32::rvv_ref::vcompress(*vs, kVd, kVs2, kVs1, vlen, vl, sew);
	std::vector<u8> mem(kVregBytes, 0);
	std::memcpy(mem.data(), &vs->vreg[0][0], kVregBytes);
	return mem;
}

// vcompress.vm: funct6 23, OPMVV, vm == 1 (vs1 IS the selector).
constexpr u32 CompressWord(u32 vs2, u32 vs1, u32 vd, bool vm = true, u32 f3 = 2u)
{
	return (23u << 26) | ((vm ? 1u : 0u) << 25) | (vs2 << 20) | (vs1 << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}
constexpr u32 kVT_E32M2 = 0xd1u; // LMUL 2: refused, an addressing limit

void SectionAdmission()
{
	printf("[C1] admission, the register rules, refusals, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT[si]), CompressWord(kVs2, kVs1, kVd), kJalr});
			Translate(b);
			Qir const q = ScanQir(b.region);
			if (!q.nodes)
				continue;
			++admitted;
			CHECK_EQ(q.frames, 1u);
			CHECK_EQ(q.nodes, 1u);
			CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
			CHECK_EQ(q.op, 1u << si);
			Configure(vlen, false);
			Built off({Vsetvli(kVT[si]), CompressWord(kVs2, kVs1, kVd), kJalr});
			Translate(off);
			CHECK_EQ(ScanQir(off.region).nodes, 0u);
			CHECK(ScanQir(off.region).hcalls >= 1u);
		}
	printf("       %u admitted SEW/width cells\n", admitted);
	CHECK_EQ(admitted, 20u);

	struct Row { char const *why; u32 vt; u32 word; };
	Row const rows[] = {
	    // LMUL 2: the destination position is a runtime value and the group is not contiguous.
	    {"LMUL 2 (an addressing limit, not a semantic one)", kVT_E32M2,
	     CompressWord(8u, kVs1, 4u)},
	    {"vm == 0 (vs1 IS the selector; there is no masked form)", kVT[2],
	     CompressWord(kVs2, kVs1, kVd, /*vm=*/false)},
	    {"vd overlaps vs2", kVT[2], CompressWord(kVd, kVs1, kVd)},
	    {"the selector lies in the destination group", kVT[2],
	     CompressWord(kVs2, kVd, kVd)},
	    {"OPIVV funct3", kVT[2], CompressWord(kVs2, kVs1, kVd, true, 0u)},
	};
	for (u32 vlen : {256u, 512u})
		for (auto const &r : rows) {
			Configure(vlen, true);
			Built b({Vsetvli(r.vt), r.word, kJalr});
			Translate(b);
			if (ScanQir(b.region).nodes) {
				printf("  FAIL refusal not honoured (%s, vlen=%u)\n", r.why, vlen);
				++g_fail;
			}
		}
}

struct Pat { char const *name; std::vector<u8> bytes; };
std::vector<Pat> Patterns()
{
	return {
	    {"empty (nothing written)", {0x00u}},
	    {"full (compression is the identity)", {0xffu}},
	    {"prefix 0x0f (the case an in-place route gets right)", {0x0fu, 0x00u, 0x00u, 0x00u}},
	    {"sparse and late", {0x00u, 0x00u, 0x80u, 0x00u, 0x00u, 0x00u, 0x01u, 0x00u}},
	    {"alternating", {0xaau}},
	    {"one bit at element 63", {0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u}},
	    {"period 9 bytes", {0x81u, 0x00u, 0x42u, 0x00u, 0x18u, 0x00u, 0x24u, 0x00u, 0x99u}},
	};
}

// The number of selected elements below `vl` -- the count the destination is written up to.
u32 SelectedCount(std::vector<u8> const &initial, u32 vl)
{
	u32 n = 0;
	for (u32 e = 0; e < vl; ++e)
		if ((initial[kVs1 * rvv32::VLEN_MAX_BYTES + e / 8u] >> (e % 8u)) & 1u)
			++n;
	return n;
}

void SectionDifferential()
{
	printf("[C2/C3] the whole register image against rvv_ref::vcompress\n");
	unsigned cells = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const sew = 1u << si, vlmax = vlen / (8u * sew);
			std::vector<u32> vls = {vlmax, 0u, 1u};
			if (vlmax > 3u)
				vls.push_back(3u);
			if (vlmax > 64u)
				vls.push_back(65u);
			if (vlmax > 1u)
				vls.push_back(vlmax / 2u + 1u);
			for (auto const &p : Patterns())
				for (u32 vl : vls) {
					Configure(vlen, true);
					Built b({Vsetvli(kVT[si]),
						 CompressWord(kVs2, kVs1, kVd), kJalr});
					Translate(b);
					if (!ScanQir(b.region).nodes || !b.fn)
						continue;
					std::vector<u8> const initial = BuildImage(p.bytes, {0xa7u});
					Folded const f = FoldUnit(b, initial, vl);
					if (!f.ok) {
						printf("  FAIL %s vlen=%u sew=%u vl=%u: did not "
						       "fold\n",
						       p.name, vlen, sew * 8u, vl);
						++g_fail;
						continue;
					}
					std::vector<u8> const r =
					    RefCompress(vl, vlen, sew, initial);
					if (f.mem != r) {
						unsigned shown = 0;
						for (u32 i = 0; i < kVregBytes && shown < 2; ++i)
							if (f.mem[i] != r[i]) {
								printf("  FAIL %s vlen=%u sew=%u "
								       "vl=%u: vreg byte %u (v%u+%u)"
								       " emitted %02x, reference "
								       "%02x\n",
								       p.name, vlen, sew * 8u, vl,
								       i,
								       i / rvv32::VLEN_MAX_BYTES,
								       i % rvv32::VLEN_MAX_BYTES,
								       f.mem[i], r[i]);
								++shown;
								++g_fail;
							}
					}
					// [C3] Elements at or beyond the COMPRESSED COUNT keep the
					// fill. Not "beyond vl": the destination is written only up
					// to the number of SELECTED elements, which is usually fewer,
					// and a store that ran to `vl` would pass a beyond-vl check.
					u32 const n = SelectedCount(initial, vl);
					u32 const dstb = kVd * rvv32::VLEN_MAX_BYTES;
					for (u32 e = n; e < vlmax; ++e) {
						bool bad = false;
						for (u32 k = 0; k < sew; ++k)
							if (f.mem[dstb + e * sew + k] != 0xa7u)
								bad = true;
						if (bad) {
							printf("  FAIL %s vlen=%u sew=%u vl=%u: "
							       "element %u beyond the compressed "
							       "count %u was written\n",
							       p.name, vlen, sew * 8u, vl, e, n);
							++g_fail;
							break;
						}
					}
					++cells;
				}
		}
	printf("       %u cells compared against the reference\n", cells);
	// 7 patterns x the per-width totals of `vls`:
	//   128: 5+5+5+4 = 19    1024: 6+5+5+5 = 21
	//   256: 5+5+5+5 = 20    2048: 6+6+5+5 = 22
	//   512: 5+5+5+5 = 20    -> 102 per pattern, 714 in all.
	CHECK_EQ(cells, 714u);
}

// [C5] `vstart` IS CLEARED IN THE EMITTED IR.
//
// Measured as a DIFFERENCE, routes-on minus routes-off, for the reason the mask-logical file
// records: the program's `vsetvli` has its own LLVM route which clears `vstart` too, but only at
// the vtype that route is admitted for, so an absolute count is wrong for some configurations for
// a reason unrelated to this family.
void SectionVstart()
{
	printf("[C5] vstart is cleared once per frame (routes-on minus routes-off)\n");
	u32 const kVstartOff =
	    (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart));
	auto count = [&](Built &b) {
		unsigned zeroes = 0;
		if (!b.fn)
			return zeroes;
		llvm::Value *state = b.fn->getArg(0);
		for (auto &bb : *b.fn)
			for (auto &ins : bb) {
				auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
				if (!st || StateOffset(st->getPointerOperand(), state) != kVstartOff)
					continue;
				auto *cv = llvm::dyn_cast<llvm::ConstantInt>(st->getValueOperand());
				if (cv && cv->isZero())
					++zeroes;
			}
		return zeroes;
	};
	unsigned checked = 0;
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			Configure(vlen, true);
			Built on({Vsetvli(kVT[si]), CompressWord(kVs2, kVs1, kVd), kJalr});
			Translate(on);
			if (!ScanQir(on.region).nodes || !on.fn)
				continue;
			Configure(vlen, false);
			Built off({Vsetvli(kVT[si]), CompressWord(kVs2, kVs1, kVd), kJalr});
			Translate(off);
			unsigned const a = count(on), b = count(off);
			if (a != b + 1u) {
				printf("  FAIL vlen=%u sew=%u: routes-on has %u stores of 0 to "
				       "vec.vstart and routes-off has %u; the frame should add "
				       "exactly one\n",
				       vlen, 8u << si, a, b);
				++g_fail;
			}
			++checked;
		}
	printf("       %u vstart cells\n", checked);
	CHECK(checked > 0);
}

void SectionVerify()
{
	printf("[C4] the emitted module verifies\n");
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT[si]), CompressWord(kVs2, kVs1, kVd), kJalr});
			Translate(b);
			std::string err;
			llvm::raw_string_ostream es(err);
			if (llvm::verifyModule(b.module, &es)) {
				printf("  FAIL vlen=%u sew=%u: %s\n", vlen, 8u << si, err.c_str());
				++g_fail;
			}
		}
}

} // namespace

int main()
{
	printf("rvv_llvm_vcompress_test: C6, vcompress.vm\n");
	SectionAdmission();
	SectionDifferential();
	SectionVstart();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
