// C6 (2026-09-19): `vid.v`, AND THE MASK-TO-SCALAR REDUCTIONS `vcpop.m` / `vfirst.m`.
//
// TWO FAMILIES IN ONE FILE because they are the two remaining C6 deliveries that reuse a QCG node
// wholesale, and because they fail in opposite directions: `vid.v` writes a VECTOR and nothing else,
// while `vcpop`/`vfirst` write an INTEGER REGISTER and nothing else. A harness that only watched the
// vector register file would call the second pair vacuously correct.
//
// SECTIONS:
//   [D1] `vid.v` admission and inertness, including LMUL 8 so the destination is a GROUP.
//   [D2] `vid.v` against `rvv_ref::vid` over the whole register image -- which also covers the
//        TRUNCATION at small SEW: at SEW 8 with LMUL 8 the indices wrap every 256 elements, and
//        the architectural answer is the wrapped value.
//   [D3] `vid.v` leaves elements at or beyond `vl` undisturbed.
//   [S1] `vcpop.m` / `vfirst.m` admission and inertness.
//   [S2] Both against `rvv_ref::vcpop_m` / `vfirst_m`, over mask patterns including all-zero (where
//        `vfirst` must return -1) and a first set bit in a LATE word (where a forward scan that
//        kept the last hit would be wrong).
//   [S3] `rd == x0` WRITES NOTHING.
//   [S4] The modules verify.

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
constexpr u32 kVT[4] = {0xc0u, 0xc8u, 0xd0u, 0xd8u}; // e8, e16, e32, e64 -- all LMUL 1
// LMUL 8 at SEW 8: VLMAX is VLEN, so the indices WRAP every 256 elements and the destination is
// an eight-register GROUP. Neither is reachable with the LMUL-1 rows above.
constexpr u32 kVT_E8M8 = 0xc3u;
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVd = 4u, kVs2 = 8u, kVs1 = 12u;
// LMUL 8 needs an 8-ALIGNED destination group (`reg_group_legal`), which `v4` is not.
constexpr u32 kVdM8 = 16u;
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
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c6vidcpop", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_vid = on;
	config::rvv_llvm_mscalar = on;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_vector_run = false;
	// OFF, DELIBERATELY, AND ONLY IN THIS FILE. The direct-state `vsetvli` route is admitted
	// for exactly `e32, m1` -- so with it on, `vec.vl` at SEW 32 is not a state LOAD this
	// harness can pin, and every SEW-32 cell folded to nothing while 8/16/64 folded fine. The
	// instruction under test is `vid.v` / `vcpop.m`, not `vsetvli`; isolating it is the point
	// of a focused check.
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
	unsigned frames = 0, nodes = 0, hcalls = 0, finishes = 0, scalars = 0;
	int guard_kind = -1;
	unsigned sew = 0, rd = 99;
	bool first = false, masked = true;
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
			} else if (ins.GetOpcode() == Op::_vchunkindex) {
				auto *n = static_cast<InstVChunkIndex *>(&ins);
				++q.nodes;
				q.bases.push_back(n->base);
				q.finishes += n->finish;
				q.sew = n->sew;
				q.masked = n->masked;
			} else if (ins.GetOpcode() == Op::_vmaskscalar) {
				auto *n = static_cast<InstVMaskScalar *>(&ins);
				++q.scalars;
				q.first = n->first;
				q.rd = n->rd;
				q.masked = n->masked;
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
constexpr u32 kGprOff = (u32)offsetof(CPUState, gpr);

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
	// THE GPR HALF. `vcpop`/`vfirst` touch no vector register at all, so `ok` (which tracks a
	// vector store) is false for them by construction -- their evidence is here.
	bool gpr_written = false;
	u32 gpr_value = 0, gpr_index = 99;
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
				if (so != ~0u && so >= kGprOff && so < kGprOff + 32u * 4u) {
					auto *g = llvm::dyn_cast<llvm::ConstantInt>(
					    st->getValueOperand());
					if (!g)
						return out;
					out.gpr_written = true;
					out.gpr_index = (so - kGprOff) / 4u;
					out.gpr_value = (u32)g->getZExtValue();
					continue;
				}
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
std::vector<u8> BuildMaskImage(std::vector<u8> const &src, std::vector<u8> const &dfill)
{
	std::vector<u8> mem(kVregBytes, 0);
	for (u32 i = 0; i < rvv32::VLEN_MAX_BYTES; ++i) {
		mem[kVs2 * rvv32::VLEN_MAX_BYTES + i] = src[i % src.size()];
		mem[kVd * rvv32::VLEN_MAX_BYTES + i] = dfill[i % dfill.size()];
	}
	return mem;
}

std::vector<u8> BuildFillImage(u8 fill)
{
	return std::vector<u8>(kVregBytes, fill);
}

std::vector<u8> RefVid(u32 vd, u32 vl, u32 vlen, u32 sew, std::vector<u8> const &initial)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], initial.data(), kVregBytes);
	vs->vl = vl;
	vs->vstart = 0;
	rvv32::rvv_ref::vid(*vs, vd, /*vm=*/true, vlen, vl, sew);
	std::vector<u8> mem(kVregBytes, 0);
	std::memcpy(mem.data(), &vs->vreg[0][0], kVregBytes);
	return mem;
}

u32 RefCpop(u32 vl, std::vector<u8> const &initial)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], initial.data(), kVregBytes);
	return rvv32::rvv_ref::vcpop_m(*vs, kVs2, /*vm=*/true, vl);
}

i32 RefFirst(u32 vl, std::vector<u8> const &initial)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], initial.data(), kVregBytes);
	return rvv32::rvv_ref::vfirst_m(*vs, kVs2, /*vm=*/true, vl);
}

// vid.v: OPMVV funct3, funct6 20 (VMUNARY0), sub-encoding 17 in the vs1 field.
constexpr u32 VidWord(u32 vd, bool vm = true)
{
	return (20u << 26) | ((vm ? 1u : 0u) << 25) | (0u << 20) | (17u << 15) | (2u << 12) |
	       (vd << 7) | 0x57u;
}
// vcpop.m is sub 16 and vfirst.m is sub 17, under funct6 16 (VWXUNARY0), OPMVV.
constexpr u32 ScalarWord(u32 rd, u32 vs2, bool first, bool vm = true)
{
	return (16u << 26) | ((vm ? 1u : 0u) << 25) | (vs2 << 20) | ((first ? 17u : 16u) << 15) |
	       (2u << 12) | (rd << 7) | 0x57u;
}

void SectionVidAdmission()
{
	printf("[D1] vid.v admission and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vti = 0; vti < 5; ++vti) {
			u32 const vt = vti < 4 ? kVT[vti] : kVT_E8M8;
			Configure(vlen, true);
			u32 const vd = vti < 4 ? kVd : kVdM8;
			Built b({Vsetvli(vt), VidWord(vd), kJalr});
			Translate(b);
			Qir const q = ScanQir(b.region);
			if (!q.nodes)
				continue;
			++admitted;
			CHECK_EQ(q.frames, 1u);
			CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
			CHECK_EQ(q.masked, false);
			CHECK_EQ(q.finishes, 1u);
			// The unit bases must step by the unit's own lane count, or `vid` writes the
			// wrong numbers -- which for THIS instruction is the same defect as writing
			// them to the wrong place.
			u32 const sew = vti < 4 ? (1u << vti) : 1u;
			u32 const lanes = std::min(vlen / 8u, 64u) / sew;
			for (u32 c = 0; c < q.bases.size(); ++c)
				CHECK_EQ(q.bases[c], c * lanes);
			Configure(vlen, false);
			Built off({Vsetvli(vt), VidWord(vd), kJalr});
			Translate(off);
			CHECK_EQ(ScanQir(off.region).nodes, 0u);
			CHECK(ScanQir(off.region).hcalls >= 1u);
		}
	printf("       %u admitted vtype/width cells\n", admitted);
	CHECK_EQ(admitted, 25u);
	for (u32 vlen : {256u, 512u}) {
		Configure(vlen, true);
		Built b({Vsetvli(kVT[2]), VidWord(kVd, /*vm=*/false), kJalr});
		Translate(b);
		if (ScanQir(b.region).nodes) {
			printf("  FAIL masked vid.v was admitted (vlen=%u)\n", vlen);
			++g_fail;
		}
	}
}

void SectionVid()
{
	printf("[D2/D3] vid.v against rvv_ref::vid, whole register image\n");
	unsigned cells = 0, tails = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vti = 0; vti < 5; ++vti) {
			u32 const vtraw = vti < 4 ? kVT[vti] : kVT_E8M8;
			u32 const sew = vti < 4 ? (1u << vti) : 1u;
			u32 const lmul = vti < 4 ? 1u : 8u;
			u32 const vlmax = vlen / (8u * sew) * lmul;
			std::vector<u32> vls = {vlmax, 0u, 1u};
			if (vlmax > 3u)
				vls.push_back(3u);
			if (vlmax > 1u)
				vls.push_back(vlmax / 2u + 1u);
			// THE LMUL-8 ROW NEEDS AN 8-ALIGNED DESTINATION, and using `v4` for it
			// meant admission silently refused every LMUL-8 cell -- so the truncation
			// claim this section makes was vacuous until the count below was asserted.
			u32 const vd = vti < 4 ? kVd : kVdM8;
			for (u32 vl : vls) {
				Configure(vlen, true);
				Built b({Vsetvli(vtraw), VidWord(vd), kJalr});
				Translate(b);
				if (!ScanQir(b.region).nodes || !b.fn)
					continue;
				// A distinctive fill so an undisturbed element is recognisable.
				std::vector<u8> const initial = BuildFillImage(0xa7u);
				Folded const f = FoldUnit(b, initial, vl);
				if (!f.ok) {
					printf("  FAIL vid vlen=%u sew=%u lmul=%u vl=%u: did not "
					       "fold\n",
					       vlen, sew * 8u, lmul, vl);
					++g_fail;
					continue;
				}
				std::vector<u8> const r = RefVid(vd, vl, vlen, sew, initial);
				if (f.mem != r) {
					unsigned shown = 0;
					for (u32 i = 0; i < kVregBytes && shown < 3; ++i)
						if (f.mem[i] != r[i]) {
							printf("  FAIL vid vlen=%u sew=%u lmul=%u "
							       "vl=%u: vreg byte %u (v%u+%u) "
							       "emitted %02x, reference %02x\n",
							       vlen, sew * 8u, lmul, vl, i,
							       i / rvv32::VLEN_MAX_BYTES,
							       i % rvv32::VLEN_MAX_BYTES, f.mem[i],
							       r[i]);
							++shown;
							++g_fail;
						}
				}
				// [D3] Elements at or beyond `vl` keep the fill, byte for byte.
				//
				// THE ADDRESS IS GROUP-RELATIVE, NOT FLAT. At LMUL 8 element `e`
				// lives in register `vd + (e * sew) / rb` at offset
				// `(e * sew) % rb`, where `rb` is VLEN/8 -- not at `vd * 512 +
				// e * sew`. The flat form read the wrong byte for every element
				// past the first register and reported two spurious failures at
				// VLEN 1024/2048, SEW 8, while the image comparison above -- which
				// uses the reference's OWN layout -- passed.
				u32 const rb = vlen / 8u;
				for (u32 e = vl; e < vlmax; ++e) {
					u32 const byte = e * sew;
					u32 const off = (vd + byte / rb) * rvv32::VLEN_MAX_BYTES +
							byte % rb;
					for (u32 k = 0; k < sew; ++k)
						if (f.mem[off + k] != 0xa7u) {
							printf("  FAIL vid vlen=%u sew=%u vl=%u: "
							       "element %u beyond vl was written\n",
							       vlen, sew * 8u, vl, e);
							++g_fail;
							e = vlmax;
							break;
						}
				}
				++tails;
				++cells;
			}
		}
	printf("       %u cells compared, %u with a checked tail\n", cells, tails);
	// EVERY CELL MUST HAVE RUN. 5 VLENs x 5 vtypes, with 4 `vl` values at VLMAX 1 and 5
	// otherwise -- a skipped row here is a vacuous claim, which is exactly what `v4` at LMUL 8
	// produced before this was asserted.
	CHECK_EQ(cells, 124u);
}

void SectionScalarAdmission()
{
	printf("[S1] vcpop.m / vfirst.m admission and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si)
			for (bool first : {false, true}) {
				Configure(vlen, true);
				Built b({Vsetvli(kVT[si]), ScalarWord(7u, kVs2, first), kJalr});
				Translate(b);
				Qir const q = ScanQir(b.region);
				if (!q.scalars)
					continue;
				++admitted;
				CHECK_EQ(q.frames, 1u);
				CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
				CHECK_EQ(q.first, first);
				CHECK_EQ(q.rd, 7u);
				CHECK_EQ(q.masked, false);
				Configure(vlen, false);
				Built off({Vsetvli(kVT[si]), ScalarWord(7u, kVs2, first), kJalr});
				Translate(off);
				CHECK_EQ(ScanQir(off.region).scalars, 0u);
				CHECK(ScanQir(off.region).hcalls >= 1u);
			}
	printf("       %u admitted form/SEW/width cells\n", admitted);
	CHECK_EQ(admitted, 40u);
	for (u32 vlen : {256u, 512u}) {
		Configure(vlen, true);
		Built b({Vsetvli(kVT[2]), ScalarWord(7u, kVs2, false, /*vm=*/false), kJalr});
		Translate(b);
		if (ScanQir(b.region).scalars) {
			printf("  FAIL masked vcpop.m was admitted (vlen=%u)\n", vlen);
			++g_fail;
		}
	}
}

void SectionScalar()
{
	printf("[S2] vcpop.m / vfirst.m against the reference, in a GPR\n");
	// Patterns: dense, sparse, ALL-ZERO (vfirst must answer -1), and one whose first set bit is
	// in a LATE word -- a forward scan that kept the LAST hit would be wrong on that one, and a
	// backward scan that kept the last would be wrong on the dense one.
	struct Pat { char const *name; std::vector<u8> bytes; };
	std::vector<Pat> const pats = {
	    {"dense", {0xffu}},
	    {"alternating", {0x55u}},
	    {"sparse", {0x00u, 0x00u, 0x00u, 0x01u}},
	    {"all zero", {0x00u}},
	    // THREE "late first bit" PATTERNS, not one. The word offset in `vfirst`'s answer is
	    // only observable when the first set bit is NOT in word 0, and with a single such
	    // pattern the mutation that drops that offset was caught by exactly ONE cell.
	    {"first bit in word 1", std::vector<u8>(8, 0x00u)},
	    {"first bit in word 2", std::vector<u8>(16, 0x00u)},
	    {"first bit in a late word", std::vector<u8>(31, 0x00u)},
	    {"byte index", {0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu}},
	};
	std::vector<Pat> ps = pats;
	ps[4].bytes.push_back(0x40u); // bit 70: word 1
	ps[5].bytes.push_back(0x04u); // bit 130: word 2
	ps[6].bytes.push_back(0x80u); // bit 255: word 3
	unsigned cells = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const vlmax = vlen / (8u << si);
			std::vector<u32> vls = {vlmax, 0u, 1u};
			if (vlmax > 3u)
				vls.push_back(3u);
			if (vlmax > 64u)
				vls.push_back(65u);
			if (vlmax > 1u)
				vls.push_back(vlmax - 1u);
			for (auto const &p : ps)
				for (bool first : {false, true})
					for (u32 vl : vls) {
						Configure(vlen, true);
						Built b({Vsetvli(kVT[si]),
							 ScalarWord(7u, kVs2, first), kJalr});
						Translate(b);
						if (!ScanQir(b.region).scalars || !b.fn)
							continue;
						std::vector<u8> const initial =
						    BuildMaskImage(p.bytes, {0x00u});
						Folded const f = FoldUnit(b, initial, vl);
						if (!f.gpr_written) {
							printf("  FAIL %s %s vlen=%u sew=%u vl=%u: no "
							       "GPR store\n",
							       first ? "vfirst" : "vcpop", p.name,
							       vlen, 8u << si, vl);
							++g_fail;
							continue;
						}
						CHECK_EQ(f.gpr_index, 7u);
						u32 const want =
						    first ? (u32)RefFirst(vl, initial)
							  : RefCpop(vl, initial);
						if (f.gpr_value != want) {
							printf("  FAIL %s %s vlen=%u sew=%u vl=%u: "
							       "emitted %08x, reference %08x\n",
							       first ? "vfirst" : "vcpop", p.name,
							       vlen, 8u << si, vl, f.gpr_value,
							       want);
							++g_fail;
						}
						// The vector register file must be untouched.
						if (f.mem != initial) {
							printf("  FAIL %s %s vlen=%u sew=%u vl=%u: "
							       "a vector register was written\n",
							       first ? "vfirst" : "vcpop", p.name,
							       vlen, 8u << si, vl);
							++g_fail;
						}
						++cells;
					}
		}
	printf("       %u cells compared against the reference\n", cells);
	CHECK(cells > 0);
}

// [S3] `rd == x0` WRITES NOTHING. x0 is hardwired zero; a store to it would corrupt the guest's
// zero register, which is a much worse failure than a wrong count.
void SectionX0()
{
	printf("[S3] rd == x0 writes no GPR\n");
	unsigned checked = 0;
	for (u32 vlen : {128u, 512u, 2048u})
		for (bool first : {false, true}) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT[2]), ScalarWord(0u, kVs2, first), kJalr});
			Translate(b);
			if (!ScanQir(b.region).scalars || !b.fn)
				continue;
			Folded const f = FoldUnit(b, BuildMaskImage({0xffu}, {0x00u}), vlen / 32u);
			if (f.gpr_written) {
				printf("  FAIL %s vlen=%u: wrote x%u with %08x\n",
				       first ? "vfirst" : "vcpop", vlen, f.gpr_index, f.gpr_value);
				++g_fail;
			}
			++checked;
		}
	printf("       %u x0 cells\n", checked);
	CHECK(checked > 0);
}

void SectionVerify()
{
	printf("[S4] the emitted modules verify\n");
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 vti = 0; vti < 5; ++vti) {
			u32 const vt = vti < 4 ? kVT[vti] : kVT_E8M8;
			for (u32 which = 0; which < 3; ++which) {
				Configure(vlen, true);
				u32 const w = which == 0 ? VidWord(kVd)
						: ScalarWord(7u, kVs2, which == 2);
				Built b({Vsetvli(vt), w, kJalr});
				Translate(b);
				std::string err;
				llvm::raw_string_ostream es(err);
				if (llvm::verifyModule(b.module, &es)) {
					printf("  FAIL vlen=%u vt=%u which=%u: %s\n", vlen, vt,
					       which, err.c_str());
					++g_fail;
				}
			}
		}
}

} // namespace

int main()
{
	printf("rvv_llvm_vidcpop_test: C6, vid.v and the mask-to-scalar reductions\n");
	SectionVidAdmission();
	SectionVid();
	SectionScalarAdmission();
	SectionScalar();
	SectionX0();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
