// C6 (2026-09-19): `viota.m` -- THE PREFIX SUM OF A MASK.
//
// Element `e` receives the number of active set bits STRICTLY BEFORE it. Unlike its sub-encoding
// siblings `vmsbf`/`vmsif`/`vmsof`, which are comparisons against one index, this is a running
// count -- the only genuinely cumulative cross-element computation in this checkpoint.
//
// THE THINGS THAT CAN GO WRONG HERE ARE ARITHMETIC, NOT STRUCTURAL, and the patterns below are
// chosen for them:
//   * OFF BY ONE AT THE LANE. `vd[e]` counts bits STRICTLY below `e`, so `vd[0]` is always 0 even
//     when bit 0 is set. A route counting `[0, e]` differs in every lane after a set bit.
//   * THE CHUNK PREFIX. The scalar term carries the count of every bit below the chunk; a route
//     that dropped it restarts from 0 in each chunk, which is invisible in a ONE-chunk frame.
//     Every pattern is therefore run at VLENs with several chunks.
//   * THE WORD PREFIX. `base` is a multiple of `lanes`, not of 64, so a chunk can start in the
//     middle of a source word; the partial-word term is the one a whole-word-only accumulator
//     misses.
//   * TRUNCATION AT SEW. At SEW 8 a count above 255 wraps, and that is the architectural answer.
//     Only a dense mask at a large VLEN reaches it.
//
// SECTIONS:
//   [I1] Admission and inertness, including the prefix trio (subs 1/2/3) being REFUSED here.
//   [I2] The differential against `rvv_ref::viota`, whole register image.
//   [I3] Elements at or beyond `vl` are undisturbed.
//   [I4] `vd[0]` is 0 even when bit 0 is set -- the strictly-before rule, stated directly.
//   [I5] The module verifies.

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
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("c6viota", g_ctx) {}
};

void Configure(u32 vlen, bool on)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_llvm_viota = on;
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
			} else if (ins.GetOpcode() == Op::_vmaskiota) {
				auto *n = static_cast<InstVMaskIota *>(&ins);
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
std::vector<u8> BuildImage(std::vector<u8> const &src, std::vector<u8> const &dfill)
{
	std::vector<u8> mem(kVregBytes, dfill[0]);
	for (u32 i = 0; i < kVregBytes; ++i)
		mem[i] = dfill[i % dfill.size()];
	for (u32 i = 0; i < rvv32::VLEN_MAX_BYTES; ++i)
		mem[kVs2 * rvv32::VLEN_MAX_BYTES + i] = src[i % src.size()];
	return mem;
}

std::vector<u8> RefIota(u32 vd, u32 vl, u32 vlen, u32 sew, std::vector<u8> const &initial)
{
	auto vs = std::make_unique<rvv32::VectorState>();
	std::memcpy(&vs->vreg[0][0], initial.data(), kVregBytes);
	vs->vl = vl;
	vs->vstart = 0;
	rvv32::rvv_ref::viota(*vs, vd, kVs2, /*vm=*/true, vlen, vl, sew);
	std::vector<u8> mem(kVregBytes, 0);
	std::memcpy(mem.data(), &vs->vreg[0][0], kVregBytes);
	return mem;
}

// funct6 20 (VMUNARY0), OPMVV; viota is sub-encoding 16, the prefix trio are 1/2/3.
constexpr u32 IotaWord(u32 sub, u32 vs2, u32 vd, bool vm = true, u32 f3 = 2u)
{
	return (20u << 26) | ((vm ? 1u : 0u) << 25) | (vs2 << 20) | (sub << 15) | (f3 << 12) |
	       (vd << 7) | 0x57u;
}
// The destination is an LMUL-sized GROUP, so it must be group-aligned; `v16` is aligned for LMUL 8.
constexpr u32 kVdM8 = 16u;
constexpr u32 kVT_E8M8 = 0xc3u;

void SectionAdmission()
{
	printf("[I1] admission, the group rules, refusals, and inertness\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	unsigned admitted = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vti = 0; vti < 5; ++vti) {
			u32 const vt = vti < 4 ? kVT[vti] : kVT_E8M8;
			u32 const vd = vti < 4 ? kVd : kVdM8;
			Configure(vlen, true);
			Built b({Vsetvli(vt), IotaWord(16u, kVs2, vd), kJalr});
			Translate(b);
			Qir const q = ScanQir(b.region);
			if (!q.nodes)
				continue;
			++admitted;
			CHECK_EQ(q.frames, 1u);
			CHECK_EQ(q.nodes, 1u);
			CHECK_EQ((int)q.guard_kind, (int)GK::VTypeIntegerNoRestart);
			CHECK_EQ(q.op, vti < 4 ? (1u << vti) : 1u); // the node carries SEW
			Configure(vlen, false);
			Built off({Vsetvli(vt), IotaWord(16u, kVs2, vd), kJalr});
			Translate(off);
			CHECK_EQ(ScanQir(off.region).nodes, 0u);
			CHECK(ScanQir(off.region).hcalls >= 1u);
		}
	printf("       %u admitted vtype/width cells\n", admitted);
	CHECK_EQ(admitted, 25u);

	struct Row { char const *why; u32 word; };
	Row const rows[] = {
	    // The prefix trio share this stub and funct6 and are a different computation.
	    {"vmsbf (sub 1) shares the stub", IotaWord(1u, kVs2, kVd)},
	    {"vmsof (sub 2)", IotaWord(2u, kVs2, kVd)},
	    {"vmsif (sub 3)", IotaWord(3u, kVs2, kVd)},
	    {"masked (vm == 0)", IotaWord(16u, kVs2, kVd, /*vm=*/false)},
	    {"vd == vs2", IotaWord(16u, kVs2, kVs2)},
	    {"OPIVV funct3", IotaWord(16u, kVs2, kVd, true, 0u)},
	};
	for (u32 vlen : {256u, 512u})
		for (auto const &r : rows) {
			Configure(vlen, true);
			Built b({Vsetvli(kVT[2]), r.word, kJalr});
			Translate(b);
			if (ScanQir(b.region).nodes) {
				printf("  FAIL refusal not honoured (%s, vlen=%u)\n", r.why, vlen);
				++g_fail;
			}
		}
	// THE SOURCE MUST NOT LIE INSIDE THE DESTINATION GROUP. At LMUL 8 with vd = v16 the group is
	// v16..v23, so v20 as the mask source is illegal -- and legal at LMUL 1, which is what makes
	// this a group rule rather than a blanket one.
	for (u32 vlen : {256u, 512u}) {
		Configure(vlen, true);
		Built bad({Vsetvli(kVT_E8M8), IotaWord(16u, 20u, kVdM8), kJalr});
		Translate(bad);
		if (ScanQir(bad.region).nodes) {
			printf("  FAIL source inside the destination group was admitted (vlen=%u)\n",
			       vlen);
			++g_fail;
		}
		Configure(vlen, true);
		Built good({Vsetvli(kVT[2]), IotaWord(16u, 20u, kVd), kJalr});
		Translate(good);
		if (!ScanQir(good.region).nodes) {
			printf("  FAIL the same registers at LMUL 1 were refused (vlen=%u)\n", vlen);
			++g_fail;
		}
	}
}

struct Pat { char const *name; std::vector<u8> bytes; };
std::vector<Pat> Patterns()
{
	return {
	    {"empty", {0x00u}},
	    {"dense (counts reach SEW-8 wrap at large VLEN)", {0xffu}},
	    {"bit 0 only", {0x01u, 0x00u, 0x00u, 0x00u}},
	    {"alternating", {0x55u}},
	    {"sparse", {0x00u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x80u, 0x00u}},
	    {"byte index", {0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu}},
	    // 9 bytes: the pattern does not repeat on a 64-bit boundary, so a chunk starting mid-word
	    // sees different bits than a whole-word accumulator would credit it with.
	    {"period 9 bytes", {0x81u, 0x00u, 0x42u, 0x00u, 0x18u, 0x00u, 0x24u, 0x00u, 0x99u}},
	};
}

void SectionDifferential()
{
	printf("[I2/I3] the whole register image against rvv_ref::viota\n");
	unsigned cells = 0;
	std::vector<u8> const fill = {0xa7u};
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (u32 vti = 0; vti < 5; ++vti) {
			u32 const vt = vti < 4 ? kVT[vti] : kVT_E8M8;
			u32 const sew = vti < 4 ? (1u << vti) : 1u;
			u32 const lmul = vti < 4 ? 1u : 8u;
			u32 const vd = vti < 4 ? kVd : kVdM8;
			u32 const vlmax = vlen / (8u * sew) * lmul;
			u32 const rb = vlen / 8u;
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
					Built b({Vsetvli(vt), IotaWord(16u, kVs2, vd), kJalr});
					Translate(b);
					if (!ScanQir(b.region).nodes || !b.fn)
						continue;
					std::vector<u8> const initial = BuildImage(p.bytes, fill);
					Folded const f = FoldUnit(b, initial, vl);
					if (!f.ok) {
						printf("  FAIL %s vlen=%u sew=%u lmul=%u vl=%u: did "
						       "not fold\n",
						       p.name, vlen, sew * 8u, lmul, vl);
						++g_fail;
						continue;
					}
					std::vector<u8> const r =
					    RefIota(vd, vl, vlen, sew, initial);
					if (f.mem != r) {
						unsigned shown = 0;
						for (u32 i = 0; i < kVregBytes && shown < 2; ++i)
							if (f.mem[i] != r[i]) {
								printf("  FAIL %s vlen=%u sew=%u "
								       "lmul=%u vl=%u: vreg byte %u "
								       "(v%u+%u) emitted %02x, "
								       "reference %02x\n",
								       p.name, vlen, sew * 8u, lmul,
								       vl, i,
								       i / rvv32::VLEN_MAX_BYTES,
								       i % rvv32::VLEN_MAX_BYTES,
								       f.mem[i], r[i]);
								++shown;
								++g_fail;
							}
					}
					// [I3] elements at or beyond vl keep the fill. The address is
					// GROUP-relative: at LMUL 8 element e lives in register
					// vd + (e*sew)/rb.
					for (u32 e = vl; e < vlmax; ++e) {
						u32 const byte = e * sew;
						u32 const off =
						    (vd + byte / rb) * rvv32::VLEN_MAX_BYTES +
						    byte % rb;
						bool bad = false;
						for (u32 k = 0; k < sew; ++k)
							if (f.mem[off + k] != 0xa7u)
								bad = true;
						if (bad) {
							printf("  FAIL %s vlen=%u sew=%u vl=%u: "
							       "element %u beyond vl was written\n",
							       p.name, vlen, sew * 8u, vl, e);
							++g_fail;
							break;
						}
					}
					++cells;
				}
		}
	printf("       %u cells compared against the reference\n", cells);
	// EVERY vtype x width x pattern x vl CELL MUST HAVE RUN: a silently-skipped row would make a
	// named claim above vacuous, which is how the `vid` LMUL-8 row went missing. The count is
	// 7 patterns x the per-width totals of `vls`, which vary because the list grows with VLMAX:
	//   VLEN  128: 5+5+5+4+6 = 25     1024: 6+5+5+5+6 = 27
	//   VLEN  256: 5+5+5+5+6 = 26     2048: 6+6+5+5+6 = 28
	//   VLEN  512: 5+5+5+5+6 = 26     -> 132 per pattern, 924 in all.
	CHECK_EQ(cells, 924u);
}

// [I4] `vd[0]` IS ZERO EVEN WHEN BIT 0 IS SET.
//
// `viota` counts bits STRICTLY BEFORE the element, so the first element is always 0 -- and a route
// that counted `[0, e]` instead would differ in EVERY lane from the first set bit onwards, but
// would still agree on an all-zero mask. Stated on a source whose bit 0 IS set, which is the only
// arrangement that separates them at element 0.
void SectionStrictlyBefore()
{
	printf("[I4] vd[0] is 0 even when the source's bit 0 is set\n");
	unsigned checked = 0;
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 si = 0; si < 4; ++si) {
			u32 const sew = 1u << si, vlmax = vlen / (8u * sew);
			Configure(vlen, true);
			Built b({Vsetvli(kVT[si]), IotaWord(16u, kVs2, kVd), kJalr});
			Translate(b);
			if (!ScanQir(b.region).nodes || !b.fn)
				continue;
			// 0xff: every bit set, so an inclusive count would make vd[0] == 1.
			Folded const f = FoldUnit(b, BuildImage({0xffu}, {0xa7u}), vlmax);
			if (!f.ok) {
				printf("  FAIL vlen=%u sew=%u: did not fold\n", vlen, sew * 8u);
				++g_fail;
				continue;
			}
			u32 const dst = kVd * rvv32::VLEN_MAX_BYTES;
			for (u32 k = 0; k < sew; ++k)
				if (f.mem[dst + k] != 0u) {
					printf("  FAIL vlen=%u sew=%u: vd[0] byte %u is %02x, not 0 "
					       "-- the count is not STRICTLY before\n",
					       vlen, sew * 8u, k, f.mem[dst + k]);
					++g_fail;
					break;
				}
			// And vd[1] must be 1 with a dense source, which is what shows the count
			// advances at all.
			if (vlmax > 1u) {
				u32 got = 0;
				for (u32 k = 0; k < sew; ++k)
					got |= (u32)f.mem[dst + sew + k] << (8u * k);
				if (got != 1u) {
					printf("  FAIL vlen=%u sew=%u: vd[1] is %u, not 1\n", vlen,
					       sew * 8u, got);
					++g_fail;
				}
			}
			++checked;
		}
	printf("       %u strictly-before cells\n", checked);
	CHECK(checked > 0);
}

void SectionVerify()
{
	printf("[I5] the emitted module verifies\n");
	for (u32 vlen : {128u, 512u, 2048u})
		for (u32 vti = 0; vti < 5; ++vti) {
			u32 const vt = vti < 4 ? kVT[vti] : kVT_E8M8;
			u32 const vd = vti < 4 ? kVd : kVdM8;
			Configure(vlen, true);
			Built b({Vsetvli(vt), IotaWord(16u, kVs2, vd), kJalr});
			Translate(b);
			std::string err;
			llvm::raw_string_ostream es(err);
			if (llvm::verifyModule(b.module, &es)) {
				printf("  FAIL vlen=%u vt=%u: %s\n", vlen, vt, err.c_str());
				++g_fail;
			}
		}
}

} // namespace

int main()
{
	printf("rvv_llvm_viota_test: C6, viota.m\n");
	SectionAdmission();
	SectionDifferential();
	SectionStrictlyBefore();
	SectionVerify();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
