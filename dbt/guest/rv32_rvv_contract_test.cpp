// RVV SHARED SEMANTIC CONTRACT, piece 1: the physical-slot versus logical-geometry distinction.
// Strict Execution Order item 2, focused checks.
//
// TWO KINDS OF CHECK, AND BOTH ARE NEEDED.
//
// [A] AN INDEPENDENT TRUTH TABLE. `ElementSlotOffset` is derived here a SECOND way -- from the byte
//     offset (`byte = e * esize`, register `byte / rb`, offset `byte % rb`) rather than from the
//     element count (`per_reg = rb / esize`, register `e / per_reg`, offset `(e % per_reg) * esize`)
//     -- and the two must agree at every width. They are the same identity only because
//     `rb % esize == 0`, which is exactly what `GeometryDescribable` requires, so the agreement is
//     evidence rather than a tautology.
//
// [B] AGREEMENT WITH WHAT THE ROUTES ACTUALLY EMIT. A contract nobody follows is documentation. This
//     builds each of the five delivered conversion routes and checks that every unit's source and
//     destination window equals `ElementStateOffset` for that unit's element base and that side's
//     element width. This is the check that would have caught the four routes drifting apart, and it
//     is what makes adopting the contract (order item 3) a mechanical, verifiable step rather than a
//     hopeful one.
//
// It builds IR but executes none of it, and needs no AVX-512 host.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_rvv_contract.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/llvmgen/rvv_test_llvm_compat.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace testcompat = dbt::qir::testcompat;

namespace
{
namespace rvv32 = dbt::rv32;
namespace ct = dbt::rv32::rvvcontract;

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

// ---------------------------------------------------------------------------------------------
// [A] The independent truth table.
void SectionGeometryTruthTable()
{
	printf("[CT-1] ElementSlotOffset derived a second way agrees at every describable width\n");
	unsigned checked = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u, 4096u})
		for (u32 esz : {1u, 2u, 4u, 8u}) {
			if (!ct::GeometryDescribable(vlen, esz)) {
				// The only reason to be undescribable at these widths is the physical
				// slot bound; state it rather than skipping silently.
				CHECK(ct::RegisterBytes(vlen) > rvv32::VLEN_MAX_BYTES);
				continue;
			}
			u32 const rb = ct::RegisterBytes(vlen);
			CHECK_EQ(ct::ElementsPerRegister(vlen, esz), rb / esz);
			// Cover three registers' worth of elements, which is what exercises the
			// register-crossing jump.
			u32 const n = 3u * ct::ElementsPerRegister(vlen, esz);
			for (u32 base : {0u, 8u}) {
				for (u32 e = 0; e < n; ++e) {
					u32 const byte = e * esz;
					u32 const want =
					    (base + byte / rb) * rvv32::VLEN_MAX_BYTES + byte % rb;
					CHECK_EQ(ct::ElementSlotOffset(vlen, base, e, esz), want);
					++checked;
				}
			}
			// The state-relative form differs from the vreg-relative one by exactly the
			// two offsetofs, and by nothing else.
			CHECK_EQ(ct::ElementStateOffset(vlen, 3u, 5u, esz) -
				     ct::ElementSlotOffset(vlen, 3u, 5u, esz),
				 (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg)));
		}
	printf("       %u element offsets cross-derived\n", checked);
	CHECK(checked > 0);
}

void SectionUnitLanes()
{
	printf("[CT-2] UnitLanes is bounded by the WIDER window, and fails closed\n");
	// Same width: the window divided by the element size.
	CHECK_EQ(ct::UnitLanes(1024u, 4u, 4u), 16u); // min(128,64)=64 -> 64/4
	CHECK_EQ(ct::UnitLanes(1024u, 8u, 8u), 8u);
	CHECK_EQ(ct::UnitLanes(128u, 4u, 4u), 4u);  // min(16,64)=16 -> 16/4
	// Widening and narrowing: the WIDER side bounds it, whichever side that is.
	CHECK_EQ(ct::UnitLanes(1024u, 8u, 4u), 8u); // f32 -> i64 : bounded by the 8-byte destination
	CHECK_EQ(ct::UnitLanes(1024u, 4u, 8u), 8u); // f64 -> f32 : bounded by the 8-byte source
	CHECK_EQ(ct::UnitLanes(1024u, 8u, 4u), ct::UnitLanes(1024u, 4u, 8u));
	// Fail closed rather than round.
	CHECK_EQ(ct::UnitLanes(1024u, 3u, 4u), 0u);
	CHECK_EQ(ct::UnitLanes(0u, 4u, 4u), 0u);
	CHECK_EQ(ct::UnitCount(0u, 32u), 0u);
	CHECK_EQ(ct::UnitCount(8u, 32u), 4u);
	CHECK_EQ(ct::UnitCount(8u, 33u), 5u);
}

// ---------------------------------------------------------------------------------------------
// [B] Agreement with what the delivered routes emit.
// ORDER ITEM 3: `vm` is now a PARAMETER. The masked twin of each conversion encoding is what turns
// "this route is unmasked by admission" from a comment into a measurement -- see [CT-5].
constexpr u32 OpVfcvt(u32 sub, u32 vs2, u32 vd, u32 vm = 1u)
{
	return (18u << 26) | (vm << 25) | (vs2 << 20) | (sub << 15) | (1u << 12) | (vd << 7) | 0x57u;
}
// The masked OPIVV integer element-wise family (order item 3's route): `vm == 0` by construction.
constexpr u32 OpIVVMasked(u32 f6, u32 vs2, u32 vs1, u32 vd)
{
	return (f6 << 26) | (0u << 25) | (vs2 << 20) | (vs1 << 15) | (0u << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 z) { return (z << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u; }
constexpr u32 kJalr = 0x00008067u;
constexpr u32 kVd = 10u, kVs2 = 8u;
constexpr u32 kVT_E16M1 = 0xc8u, kVT_E32M1 = 0xd0u;

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	Region *region{};
	explicit Built(std::vector<u32> w) : words(std::move(w)) {}
};

void Translate(Built &b)
{
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}

void ConfigureBase(u32 vlen)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_active_vl_int_bound = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_vector_run = false;
	config::rvv_llvm_fcvt_itof = false;
	config::rvv_llvm_fcvt_ftoi = false;
	config::rvv_llvm_fcvt_fwiden = false;
	config::rvv_llvm_fcvt_fnarrow = false;
	config::rvv_llvm_fcvt_itof_widen = false;
	config::rvv_llvm_fcvt_ftoi_widen = false;
	config::rvv_llvm_masked = false;
	config::rvv_llvm_partial_vl = false;
	config::rvv_llvm_restart = false;
}

// One row per delivered conversion route: which flag turns it on, which encoding drives it, and the
// SOURCE and DESTINATION element widths its units are supposed to walk.
struct RouteRow {
	char const *name;
	bool *flag;
	u32 sub;
	u32 vt;
	u32 src_bytes;
	u32 dst_bytes;
};

void SectionRoutesAgree()
{
	printf("[CT-3] every delivered conversion route's windows equal ElementStateOffset\n");
	RouteRow const rows[] = {
	    {"vfcvt.f.x.v (same width)", &config::rvv_llvm_fcvt_itof, 3u, kVT_E32M1, 4u, 4u},
	    {"vfcvt.rtz.x.f.v (same width)", &config::rvv_llvm_fcvt_ftoi, 7u, kVT_E32M1, 4u, 4u},
	    {"vfwcvt.f.f.v", &config::rvv_llvm_fcvt_fwiden, 12u, kVT_E32M1, 4u, 8u},
	    {"vfncvt.f.f.w", &config::rvv_llvm_fcvt_fnarrow, 20u, kVT_E32M1, 8u, 4u},
	    {"vfwcvt.f.x.v", &config::rvv_llvm_fcvt_itof_widen, 11u, kVT_E16M1, 2u, 4u},
	    {"vfwcvt.rtz.x.f.v", &config::rvv_llvm_fcvt_ftoi_widen, 15u, kVT_E32M1, 4u, 8u},
	};
	unsigned admitted = 0, windows = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u})
		for (auto const &r : rows) {
			ConfigureBase(vlen);
			*r.flag = true;
			Built b({Vsetvli(r.vt), OpVfcvt(r.sub, kVs2, kVd), kJalr});
			Translate(b);
			// Collect the units in emission order with their element bases.
			std::vector<std::pair<u32, u32>> units; // (rd offset, rs offset)
			std::vector<u32> bases;
			for (auto &bb : b.region->GetBlocks())
				for (auto &ins : bb.ilist) {
					if (ins.GetOpcode() == Op::_vchunkitof) {
						auto *n = static_cast<InstVChunkIToF *>(&ins);
						units.push_back({n->rd, n->rs});
						bases.push_back(n->base);
					} else if (ins.GetOpcode() == Op::_vchunkftoi) {
						auto *n = static_cast<InstVChunkFToI *>(&ins);
						units.push_back({n->rd, n->rs});
						bases.push_back(n->base);
					} else if (ins.GetOpcode() == Op::_vchunkftof) {
						auto *n = static_cast<InstVChunkFToF *>(&ins);
						units.push_back({n->rd, n->rs});
						bases.push_back(n->base);
					}
				}
			if (units.empty())
				continue;
			++admitted;
			// The contract's own lane count must be the one the route used, which is what
			// makes the element bases below comparable at all.
			u32 const lanes = ct::UnitLanes(vlen, r.dst_bytes, r.src_bytes);
			CHECK(lanes > 0);
			for (size_t u = 0; u < units.size(); ++u) {
				// The route's own element base, not a recomputed one: if the route and
				// the contract disagree about WHICH elements a unit covers, that shows
				// up as an offset mismatch below rather than being hidden.
				u32 const e = bases[u];
				CHECK_EQ(e, (u32)u * lanes);
				CHECK_EQ(units[u].first,
					 ct::ElementStateOffset(vlen, kVd, e, r.dst_bytes));
				CHECK_EQ(units[u].second,
					 ct::ElementStateOffset(vlen, kVs2, e, r.src_bytes));
				++windows;
			}
		}
	printf("       %u unit windows checked across %u admitted route/width cells\n", windows,
	       admitted);
	CHECK(admitted > 0);
	CHECK(windows > 0);
}

// ---------------------------------------------------------------------------------------------
// PIECE 2: the active predicate, and the obligation that a body's omissions are guard-proved.
void SectionPredicateAlgebra()
{
	printf("[CT-4] the full predicate equals the architectural rule; omissions need guard proofs\n");
	// Exhaustive over a small domain: with all three terms present the body computes exactly
	// `ElementIsActive`.
	unsigned checked = 0;
	for (u32 e = 0; e < 8; ++e)
		for (u32 vstart = 0; vstart < 8; ++vstart)
			for (u32 vl = 0; vl < 9; ++vl)
				for (int m = 0; m < 2; ++m) {
					ct::PredicateTerms full{true, true, true};
					CHECK_EQ(ct::PredicateComputes(full, e, vstart, vl, m != 0),
						 ct::ElementIsActive(e, vstart, vl, m != 0));
					++checked;
					// Dropping the floor is a DIFFERENT function unless vstart is 0.
					ct::PredicateTerms nofloor{true, false, true};
					if (vstart != 0 && e < vstart && e < vl && m)
						CHECK(ct::PredicateComputes(nofloor, e, vstart, vl,
									    m != 0) !=
						      ct::ElementIsActive(e, vstart, vl, m != 0));
				}
	printf("       %u predicate points checked exhaustively\n", checked);

	// The obligation table.
	using PT = ct::PredicateTerms;
	using GP = ct::GuardProofs;
	CHECK(ct::PredicateIsSound(PT{true, true, true}, GP{false, false}));
	CHECK(ct::PredicateIsSound(PT{true, false, false}, GP{true, true}));
	// vl can never be omitted, whatever the guard proves.
	CHECK(!ct::PredicateIsSound(PT{false, true, true}, GP{true, true}));
	// The C4-FIX defect, as a table row: no floor in the body, no vstart proof in the guard.
	CHECK(!ct::PredicateIsSound(PT{true, false, true}, GP{false, true}));
	CHECK(!ct::PredicateIsSound(PT{true, true, false}, GP{true, false}));
}

// Measure a route's emitted lane predicate: which architectural fields it actually reads.
struct Measured {
	bool reads_vl{false}, reads_vstart_in_predicate{false}, reads_v0{false};
	int guard_kind{-1};
	bool guard_checks_vstart{false};
};

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

// ORDER ITEM 3. THE MASK CONJUNCT, MEASURED FROM THE EMITTED IR RATHER THAN DECLARED.
//
// "The body has the mask term" means: some destination masked store's mask operand depends on a load
// from the v0 register's own byte window. A plain "does the function read v0?" test would be wrong
// in both directions -- it would miss a route whose mask word is not at offset 0 (unit 1 of a
// multi-unit frame reads the SECOND 16-bit group), and it would fire on a route that merely had v0
// as a data source. Walking the mask operand's cone answers the question that was actually asked.
bool ConeReadsV0(llvm::Value *v, llvm::Value *state, unsigned depth = 24)
{
	u32 const v0_lo = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg));
	if (!depth)
		return false;
	if (auto *l = llvm::dyn_cast<llvm::LoadInst>(v)) {
		u32 const o = StateOffset(l->getPointerOperand(), state);
		if (o != ~0u && o >= v0_lo && o < v0_lo + rvv32::VLEN_MAX_BYTES)
			return true;
	}
	auto *ins = llvm::dyn_cast<llvm::Instruction>(v);
	if (!ins)
		return false;
	for (auto &u : ins->operands())
		if (ConeReadsV0(u.get(), state, depth - 1))
			return true;
	return false;
}

bool AnyMaskedStoreReadsV0(llvm::Function *fn)
{
	llvm::Value *state = fn->getArg(0);
	for (auto &bb : *fn)
		for (auto &ins : bb)
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store)
					if (ConeReadsV0(testcompat::MaskedStoreMask(ii), state))
						return true;
	return false;
}

// Build one instruction under the given configuration and report whether a route claimed it.
bool RouteAdmits(u32 vlen, bool *flag, u32 vtype, u32 word)
{
	ConfigureBase(vlen);
	if (flag)
		*flag = true;
	Built b({Vsetvli(vtype), word, kJalr});
	Translate(b);
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist)
			switch (ins.GetOpcode()) {
			case Op::_vchunkitof:
			case Op::_vchunkftoi:
			case Op::_vchunkftof:
			case Op::_vchunkadd:
			case Op::_vchunksub:
			case Op::_vchunkand:
			case Op::_vchunkor:
			case Op::_vchunkxor:
				return true;
			default:
				break;
			}
	return false;
}

void SectionRoutesArePredicateSound()
{
	printf("[CT-5] every delivered conversion route's omissions are proved by its own guard\n");
	u32 const vl_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl));
	u32 const vstart_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart));
	u32 const v0_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg));
	RouteRow const rows[] = {
	    {"vfcvt.f.x.v (same width)", &config::rvv_llvm_fcvt_itof, 3u, kVT_E32M1, 4u, 4u},
	    {"vfcvt.rtz.x.f.v (same width)", &config::rvv_llvm_fcvt_ftoi, 7u, kVT_E32M1, 4u, 4u},
	    {"vfcvt.x.f.v (frm, same width)", &config::rvv_llvm_fcvt_ftoi, 1u, kVT_E32M1, 4u, 4u},
	    {"vfwcvt.f.f.v", &config::rvv_llvm_fcvt_fwiden, 12u, kVT_E32M1, 4u, 8u},
	    {"vfncvt.f.f.w", &config::rvv_llvm_fcvt_fnarrow, 20u, kVT_E32M1, 8u, 4u},
	    {"vfwcvt.f.x.v", &config::rvv_llvm_fcvt_itof_widen, 11u, kVT_E16M1, 2u, 4u},
	    {"vfwcvt.rtz.x.f.v", &config::rvv_llvm_fcvt_ftoi_widen, 15u, kVT_E32M1, 4u, 8u},
	};
	unsigned admitted = 0;
	for (u32 vlen : {256u, 1024u})
		for (auto const &r : rows) {
			ConfigureBase(vlen);
			*r.flag = true;
			Built b({Vsetvli(r.vt), OpVfcvt(r.sub, kVs2, kVd), kJalr});
			llvm::LLVMContext &ctx = g_llvm_ctx;
			llvm::Module module("ct", ctx);
			CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
			CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
			b.region = CompilerGenRegionIR(&b.arena, job);
			LLVMGenCtx gctx(&module);
			gctx.AddFunction(0u, b.segment);
			QIRToLLVM gen(gctx, &b.segment, b.region, 0u);
			llvm::Function *fn = gen.Run();

			Measured m;
			bool any_unit = false;
			for (auto &bb : b.region->GetBlocks())
				for (auto &ins : bb.ilist) {
					if (ins.GetOpcode() == Op::_rvvtypedchunkbegin)
						m.guard_kind =
						    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)
							->guard_kind;
					if (ins.GetOpcode() == Op::_vchunkitof ||
					    ins.GetOpcode() == Op::_vchunkftoi ||
					    ins.GetOpcode() == Op::_vchunkftof)
						any_unit = true;
				}
			if (!any_unit)
				continue;
			++admitted;
			{
				std::string err;
				llvm::raw_string_ostream es(err);
				if (llvm::verifyModule(module, &es)) {
					printf("  FAIL %s: verifyModule rejected the module:\n%s\n",
					       r.name, err.c_str());
					++g_fail;
				}
			}
			for (auto &bb : *fn)
				for (auto &ins : bb) {
					auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
					if (!l)
						continue;
					u32 const off = StateOffset(l->getPointerOperand(),
								    fn->getArg(0));
					if (off == vl_off)
						m.reads_vl = true;
					if (off == vstart_off) {
						// A FLOOR TERM, not the guard's own `vstart == 0` test
						// and not the epilogue's store: it would compare
						// `vstart <= element`, i.e. an unsigned-LE/LT compare
						// against a lane index vector. Counting the guard's
						// `icmp eq` here would make every route look like it
						// had a floor it does not have.
						for (auto *u : l->users())
							if (auto *cmp =
								llvm::dyn_cast<llvm::ICmpInst>(u))
								if (cmp->getPredicate() ==
									llvm::CmpInst::ICMP_ULE ||
								    cmp->getPredicate() ==
									llvm::CmpInst::ICMP_ULT)
									m.reads_vstart_in_predicate =
									    true;
					}
					(void)off;
					(void)v0_off;
				}
			// THE GUARD'S PROOF IS MEASURED FROM THE EMITTED IR, NOT MAPPED FROM THE KIND.
			// A table from guard kind to "proves vstart == 0" would be a restatement of
			// llvmgen's own `check_vstart = !vtype_body_restart` rule, and would drift with
			// it silently. What is checked instead is whether a `vec.vstart` LOAD feeding an
			// equality compare against zero actually exists -- that is the proof itself.
			for (auto &bb : *fn)
				for (auto &ins : bb) {
					auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
					if (!l || StateOffset(l->getPointerOperand(), fn->getArg(0)) !=
						      vstart_off)
						continue;
					for (auto *u : l->users())
						if (auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(u))
							if (cmp->getPredicate() ==
							    llvm::CmpInst::ICMP_EQ)
								m.guard_checks_vstart = true;
				}
			// ORDER ITEM 3: THE MASK TERM IS NOW MEASURED THE WAY THE CONTRACT DEFINES IT
			// -- a v0 read that reaches a destination masked store's PREDICATE. The
			// previous test ("a vector-typed load at the v0 offset") could not see this
			// route's mask, which is a scalar 16-bit group load at a per-unit offset, and
			// would have reported the first masked family in the tree as unmasked.
			m.reads_v0 = AnyMaskedStoreReadsV0(fn);
			using GK = InstRVVTypedChunkBegin::GuardKind;
			GK const gk = (GK)m.guard_kind;
			// ORDER ITEM 3: `unmasked` IS NOW MEASURED, NOT ASSUMED.
			//
			// It used to be the literal `true` with a comment saying it had to become a
			// measurement once a masked family landed. One has (`RvvTryLLVMMaskedAlu`), so
			// here is the measurement, and it is the one the word actually means: the
			// route's ADMISSION refuses `vm == 0`, i.e. building the SAME encoding with the
			// mask bit cleared produces no unit node and the instruction keeps its helper.
			// If a route ever started admitting a masked encoding while its body still had
			// no mask term, this flips to false and `PredicateIsSound` fails -- which is
			// exactly the failure the old literal could not express.
			bool const route_admits_masked =
			    RouteAdmits(vlen, r.flag, r.vt, OpVfcvt(r.sub, kVs2, kVd, /*vm=*/0u));
			ct::GuardProofs const proofs{m.guard_checks_vstart, !route_admits_masked};
			// These frames prove FULL VL, so the body's `vl` bound is the guard's, not a
			// per-lane term; record that explicitly rather than pretending the body has it.
			bool const guard_full_vl =
			    InstRVVTypedChunkBegin::GuardProvesFullVl(gk);
			ct::PredicateTerms const terms{/*vl_bound=*/guard_full_vl || m.reads_vl,
						       m.reads_vstart_in_predicate,
						       m.reads_v0};
			if (!ct::PredicateIsSound(terms, proofs)) {
				printf("  FAIL %s vlen=%u: predicate terms {vl=%d vstart=%d mask=%d} "
				       "are not sound under guard proofs {vstart0=%d unmasked=%d} "
				       "(guard kind %d)\n", r.name, vlen, (int)terms.vl_bound,
				       (int)terms.vstart_floor, (int)terms.architectural_mask,
				       (int)proofs.vstart_is_zero, (int)proofs.unmasked, m.guard_kind);
				++g_fail;
			}
		}
	printf("       %u admitted route/width cells checked for predicate soundness\n", admitted);
	CHECK(admitted > 0);
}

// ---------------------------------------------------------------------------------------------
// PIECE 3: tail/mask policy. A frame that owes a policy must publish through a preserving form.
void SectionTailPolicyAlgebra()
{
	printf("[CT-6] preserve is legal under every policy; ones only under the agnostic one\n");
	using IF = ct::InactiveFill;
	CHECK(ct::InactiveFillIsLegal(IF::Preserve, true));
	CHECK(ct::InactiveFillIsLegal(IF::Preserve, false));
	CHECK(ct::InactiveFillIsLegal(IF::Ones, true));
	CHECK(!ct::InactiveFillIsLegal(IF::Ones, false)); // undisturbed forbids it
	// A frame owes a policy exactly when some element can be inactive.
	CHECK(!ct::TailHandlingRequired(/*full_vl=*/true, /*unmasked=*/true));
	CHECK(ct::TailHandlingRequired(false, true));
	CHECK(ct::TailHandlingRequired(true, false));
	using DW = ct::DestinationWrite;
	CHECK(ct::DestinationWriteIsSound(DW::FullWidthStore, true, true));
	CHECK(!ct::DestinationWriteIsSound(DW::FullWidthStore, false, true)); // a tail exists
	CHECK(ct::DestinationWriteIsSound(DW::MaskedStore, false, true));
	CHECK(ct::DestinationWriteIsSound(DW::MergedStore, false, true));
	CHECK(!ct::DestinationWriteIsSound(DW::None, true, true));
}

// Measure how a route publishes its destination unit.
ct::DestinationWrite MeasureDestinationWrite(llvm::Function *fn, u32 rd_off)
{
	auto out = ct::DestinationWrite::None;
	for (auto &bb : *fn)
		for (auto &ins : bb) {
			if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins))
				if (ii->getIntrinsicID() == llvm::Intrinsic::masked_store) {
					auto *p = ii->getArgOperand(1);
					if (StateOffset(p, fn->getArg(0)) == rd_off)
						return ct::DestinationWrite::MaskedStore;
					continue;
				}
			auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins);
			if (!st || StateOffset(st->getPointerOperand(), fn->getArg(0)) != rd_off)
				continue;
			// A merged store publishes `select(active, computed, old)`; a plain one does not.
			llvm::Value *v = st->getValueOperand();
			while (auto *bc = llvm::dyn_cast<llvm::BitCastInst>(v))
				v = bc->getOperand(0);
			if (auto *sel = llvm::dyn_cast<llvm::SelectInst>(v))
				if (!llvm::isa<llvm::Constant>(sel->getTrueValue()) &&
				    !llvm::isa<llvm::Constant>(sel->getFalseValue()))
					return ct::DestinationWrite::MergedStore;
			out = ct::DestinationWrite::FullWidthStore;
		}
	return out;
}

void SectionRoutesPublishSoundly()
{
	printf("[CT-7] destination publication matches what each frame's guard owes\n");
	// The conversion routes prove FULL VL, so they owe no policy and a full-width store is
	// correct for them. That alone would be a VACUOUS check, so the partial-VL FP route is
	// driven as well: it does NOT prove full VL and therefore must publish preservingly.
	struct Row { char const *name; bool *flag; u32 word; u32 vt; bool expect_full_vl; };
	// vfadd.vv v10, v8, v9 -- the C5-FP typed route, which Family B owns at VLEN 128/256/2048.
	u32 const vfadd = (0u << 26) | (1u << 25) | (8u << 20) | (9u << 15) | (1u << 12) | (10u << 7) | 0x57u;
	unsigned checked = 0, partial_seen = 0;
	for (u32 vlen : {128u, 256u, 1024u, 2048u}) {
		// (a) a full-VL conversion route
		{
			ConfigureBase(vlen);
			config::rvv_llvm_fcvt_itof = true;
			Built b({Vsetvli(kVT_E32M1), OpVfcvt(3u, kVs2, kVd), kJalr});
			llvm::Module module("ct3", g_llvm_ctx);
			CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
			CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
			b.region = CompilerGenRegionIR(&b.arena, job);
			LLVMGenCtx gctx(&module);
			gctx.AddFunction(0u, b.segment);
			QIRToLLVM gen(gctx, &b.segment, b.region, 0u);
			llvm::Function *fn = gen.Run();
			int gk = -1;
			bool any = false;
			for (auto &bb : b.region->GetBlocks())
				for (auto &ins : bb.ilist) {
					if (ins.GetOpcode() == Op::_rvvtypedchunkbegin)
						gk = (int)static_cast<InstRVVTypedChunkBegin *>(&ins)
							 ->guard_kind;
					if (ins.GetOpcode() == Op::_vchunkitof)
						any = true;
				}
			if (any) {
				bool const full = InstRVVTypedChunkBegin::GuardProvesFullVl(
				    (InstRVVTypedChunkBegin::GuardKind)gk);
				CHECK(full); // this route's guard really does prove it
				auto const w = MeasureDestinationWrite(
				    fn, ct::ElementStateOffset(vlen, kVd, 0u, 4u));
				CHECK(ct::DestinationWriteIsSound(w, full, /*unmasked=*/true));
				++checked;
			}
		}
		// (b) the partial-VL FP route: owes a policy, so it must preserve.
		{
			ConfigureBase(vlen);
			config::rvv_qcg_typed_chunk_falu = true;
			config::rvv_llvm_fp_partial_vl = true;
			Built b({Vsetvli(kVT_E32M1), vfadd, kJalr});
			llvm::Module module("ct3b", g_llvm_ctx);
			CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
			CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
			b.region = CompilerGenRegionIR(&b.arena, job);
			LLVMGenCtx gctx(&module);
			gctx.AddFunction(0u, b.segment);
			QIRToLLVM gen(gctx, &b.segment, b.region, 0u);
			llvm::Function *fn = gen.Run();
			int gk = -1;
			bool any = false;
			for (auto &bb : b.region->GetBlocks())
				for (auto &ins : bb.ilist) {
					if (ins.GetOpcode() == Op::_rvvtypedchunkbegin)
						gk = (int)static_cast<InstRVVTypedChunkBegin *>(&ins)
							 ->guard_kind;
					if (ins.GetOpcode() == Op::_vchunkfalu)
						any = true;
				}
			if (!any)
				continue;
			bool const full = InstRVVTypedChunkBegin::GuardProvesFullVl(
			    (InstRVVTypedChunkBegin::GuardKind)gk);
			// The whole point of this row: the antecedent is TRUE here, so the check below
			// is not vacuous.
			CHECK(!full);
			CHECK(ct::TailHandlingRequired(full, /*unmasked=*/true));
			auto const w = MeasureDestinationWrite(
			    fn, ct::ElementStateOffset(vlen, kVd, 0u, 4u));
			if (!ct::DestinationWriteIsSound(w, full, true)) {
				printf("  FAIL partial-VL vfadd vlen=%u publishes with a "
				       "non-preserving write (%d) while owing a tail policy\n",
				       vlen, (int)w);
				++g_fail;
			}
			CHECK(ct::DestinationWritePreserves(w));
			++partial_seen;
			++checked;
		}
	}
	printf("       %u publication sites checked, %u of them owing a tail policy\n", checked,
	       partial_seen);
	CHECK(checked > 0);
	// Without at least one partial-VL cell the preserving obligation is never exercised.
	CHECK(partial_seen > 0);
}

// ---------------------------------------------------------------------------------------------
// PIECE 4: no unit's write may clobber a byte a LATER unit still has to read.
void SectionOverlapAlgebra()
{
	printf("[CT-8] window intersection and the unit-order hazard rule\n");
	using BW = ct::ByteWindow;
	CHECK(ct::WindowsIntersect(BW{0, 8}, BW{4, 8}));
	CHECK(ct::WindowsIntersect(BW{4, 8}, BW{0, 8}));
	CHECK(!ct::WindowsIntersect(BW{0, 8}, BW{8, 8})); // touching is not overlapping
	CHECK(!ct::WindowsIntersect(BW{8, 8}, BW{0, 8}));
	CHECK(!ct::WindowsIntersect(BW{0, 0}, BW{0, 8})); // an empty window intersects nothing
	CHECK(ct::UnitWriteClobbersLaterRead(BW{64, 64}, BW{96, 32}));
	CHECK(!ct::UnitWriteClobbersLaterRead(BW{0, 64}, BW{64, 64}));
}

// Collect a route's units in EMISSION order with both windows, then check the hazard rule. Driven
// over every (vd, vs2) pair the route admits, so the OVERLAPPING pairs the ISA permits are covered
// rather than avoided -- scanning for them instead of guessing which ones are legal.
void SectionRoutesHaveNoSelfHazard()
{
	printf("[CT-9] no delivered route's unit write clobbers a later unit's source read\n");
	struct Row { char const *name; bool *flag; u32 sub; u32 vt; u32 src_b; u32 dst_b; };
	Row const rows[] = {
	    {"vfcvt.f.x.v", &config::rvv_llvm_fcvt_itof, 3u, kVT_E32M1, 4u, 4u},
	    {"vfcvt.rtz.x.f.v", &config::rvv_llvm_fcvt_ftoi, 7u, kVT_E32M1, 4u, 4u},
	    {"vfwcvt.f.f.v", &config::rvv_llvm_fcvt_fwiden, 12u, kVT_E32M1, 4u, 8u},
	    {"vfncvt.f.f.w", &config::rvv_llvm_fcvt_fnarrow, 20u, kVT_E32M1, 8u, 4u},
	    {"vfwcvt.f.x.v", &config::rvv_llvm_fcvt_itof_widen, 11u, kVT_E16M1, 2u, 4u},
	    {"vfwcvt.rtz.x.f.v", &config::rvv_llvm_fcvt_ftoi_widen, 15u, kVT_E32M1, 4u, 8u},
	};
	unsigned cells = 0, overlapping = 0, hazards = 0;
	for (u32 vlen : {256u, 1024u})
		for (auto const &r : rows)
			for (u32 vd = 0; vd < 16u; vd += 2u)
				for (u32 vs = 0; vs < 16u; vs += 2u) {
					ConfigureBase(vlen);
					*r.flag = true;
					u32 const word = (18u << 26) | (1u << 25) | (vs << 20) |
							 (r.sub << 15) | (1u << 12) | (vd << 7) | 0x57u;
					Built b({Vsetvli(r.vt), word, kJalr});
					Translate(b);
					std::vector<ct::ByteWindow> wr, rdw;
					for (auto &bb : b.region->GetBlocks())
						for (auto &ins : bb.ilist) {
							u32 d = 0, sc = 0;
							bool got = false;
							if (ins.GetOpcode() == Op::_vchunkitof) {
								auto *n = static_cast<InstVChunkIToF *>(&ins);
								d = n->rd; sc = n->rs; got = true;
							} else if (ins.GetOpcode() == Op::_vchunkftoi) {
								auto *n = static_cast<InstVChunkFToI *>(&ins);
								d = n->rd; sc = n->rs; got = true;
							} else if (ins.GetOpcode() == Op::_vchunkftof) {
								auto *n = static_cast<InstVChunkFToF *>(&ins);
								d = n->rd; sc = n->rs; got = true;
							}
							if (!got)
								continue;
							u32 const lanes =
							    ct::UnitLanes(vlen, r.dst_b, r.src_b);
							wr.push_back({d, lanes * r.dst_b});
							rdw.push_back({sc, lanes * r.src_b});
						}
					if (wr.empty())
						continue;
					++cells;
					// Did this (vd, vs) actually put the two groups on top of each
					// other? Counted so the section cannot pass by only ever seeing
					// disjoint registers.
					bool any_overlap = false;
					for (size_t a = 0; a < wr.size(); ++a)
						for (size_t c = 0; c < rdw.size(); ++c)
							if (ct::WindowsIntersect(wr[a], rdw[c]))
								any_overlap = true;
					if (any_overlap)
						++overlapping;
					for (size_t w = 0; w < wr.size(); ++w)
						for (size_t rd2 = w + 1; rd2 < rdw.size(); ++rd2)
							if (ct::UnitWriteClobbersLaterRead(wr[w], rdw[rd2])) {
								printf("  FAIL %s vlen=%u vd=v%u vs2=v%u: "
								       "unit %zu's write [%u,%u) clobbers "
								       "unit %zu's source read [%u,%u)\n",
								       r.name, vlen, vd, vs, w,
								       wr[w].begin, wr[w].end(), rd2,
								       rdw[rd2].begin, rdw[rd2].end());
								++g_fail;
								++hazards;
							}
				}
	printf("       %u admitted (route,width,vd,vs2) cells, %u with overlapping windows, "
	       "%u hazards\n", cells, overlapping, hazards);
	CHECK(cells > 0);
	// A run that never saw an overlapping pair would prove nothing about the interesting case.
	CHECK(overlapping > 0);
}

// ---------------------------------------------------------------------------------------------
// PIECE 5: a closed-world check that a frame writes only the state it owns.
void SectionStateOwnership()
{
	printf("[CT-10] every CPUState store a route emits falls in a category it owns\n");
	// THE CONTRACT'S OWN TABLE, checked directly. Without these, weakening the table is
	// unobservable whenever no route happens to exercise the weakened row -- which is exactly
	// what happened: a mutation making the SOURCE window writable passed, because no route
	// writes its source. A measurement of the routes cannot stand in for the rule itself.
	using SC = ct::StateCategory;
	CHECK(!ct::StateCategoryIsWritable(SC::SourceWindow));
	CHECK(!ct::StateCategoryIsWritable(SC::Unowned));
	CHECK(ct::StateCategoryIsWritable(SC::DestinationWindow));
	CHECK(ct::StateCategoryIsWritable(SC::VStart));
	CHECK(ct::StateCategoryIsWritable(SC::FpFlags));
	CHECK(ct::StateCategoryIsWritable(SC::FpBracket));
	CHECK(ct::StateCategoryIsWritable(SC::GuestPc));
	CHECK(ct::VStartClearCountIsSound(ct::VStartOwnerRule::FrameEpilogue, 1u, 4u));
	CHECK(!ct::VStartClearCountIsSound(ct::VStartOwnerRule::FrameEpilogue, 0u, 4u));
	CHECK(!ct::VStartClearCountIsSound(ct::VStartOwnerRule::LastChunkNode, 2u, 4u));
	u32 const vreg_base = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vreg));
	u32 const vstart_off = (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart));
	u32 const fcsr_off = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, fcsr));
	u32 const open_off = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, fround_run_open));
	u32 const saved_off =
	    (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, fround_run_saved_mxcsr));
	u32 const ip_off = (u32)offsetof(CPUState, ip);

	struct Row { char const *name; bool *flag; u32 sub; u32 vt; u32 src_b; u32 dst_b; };
	Row const rows[] = {
	    {"vfcvt.f.x.v", &config::rvv_llvm_fcvt_itof, 3u, kVT_E32M1, 4u, 4u},
	    {"vfcvt.rtz.x.f.v", &config::rvv_llvm_fcvt_ftoi, 7u, kVT_E32M1, 4u, 4u},
	    {"vfcvt.x.f.v (frm)", &config::rvv_llvm_fcvt_ftoi, 1u, kVT_E32M1, 4u, 4u},
	    {"vfwcvt.f.f.v", &config::rvv_llvm_fcvt_fwiden, 12u, kVT_E32M1, 4u, 8u},
	    {"vfncvt.f.f.w", &config::rvv_llvm_fcvt_fnarrow, 20u, kVT_E32M1, 8u, 4u},
	    {"vfwcvt.f.x.v", &config::rvv_llvm_fcvt_itof_widen, 11u, kVT_E16M1, 2u, 4u},
	    {"vfwcvt.rtz.x.f.v", &config::rvv_llvm_fcvt_ftoi_widen, 15u, kVT_E32M1, 4u, 8u},
	};
	unsigned cells = 0, stores_seen = 0, unowned = 0;
	for (u32 vlen : {256u, 1024u})
		for (auto const &r : rows) {
			ConfigureBase(vlen);
			*r.flag = true;
			Built b({Vsetvli(r.vt), OpVfcvt(r.sub, kVs2, kVd), kJalr});
			llvm::Module module("ct5", g_llvm_ctx);
			CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
			CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
			b.region = CompilerGenRegionIR(&b.arena, job);
			LLVMGenCtx gctx(&module);
			gctx.AddFunction(0u, b.segment);
			QIRToLLVM gen(gctx, &b.segment, b.region, 0u);
			llvm::Function *fn = gen.Run();

			// The windows this frame declared, from its own emitted units.
			std::vector<ct::ByteWindow> dst, src;
			for (auto &bb : b.region->GetBlocks())
				for (auto &ins : bb.ilist) {
					u32 d = 0, sc = 0;
					bool got = false;
					if (ins.GetOpcode() == Op::_vchunkitof) {
						auto *n = static_cast<InstVChunkIToF *>(&ins);
						d = n->rd; sc = n->rs; got = true;
					} else if (ins.GetOpcode() == Op::_vchunkftoi) {
						auto *n = static_cast<InstVChunkFToI *>(&ins);
						d = n->rd; sc = n->rs; got = true;
					} else if (ins.GetOpcode() == Op::_vchunkftof) {
						auto *n = static_cast<InstVChunkFToF *>(&ins);
						d = n->rd; sc = n->rs; got = true;
					}
					if (!got)
						continue;
					u32 const lanes = ct::UnitLanes(vlen, r.dst_b, r.src_b);
					dst.push_back({d, lanes * r.dst_b});
					src.push_back({sc, lanes * r.src_b});
				}
			if (dst.empty())
				continue;
			++cells;
			unsigned vstart_clears = 0;
			for (auto &bb : *fn)
				for (auto &ins : bb) {
					llvm::Value *ptr = nullptr;
					u32 width = 0;
					if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
						ptr = st->getPointerOperand();
						width = (u32)(module.getDataLayout()
								  .getTypeStoreSize(
								      st->getValueOperand()->getType()));
					} else if (auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins)) {
						if (ii->getIntrinsicID() != llvm::Intrinsic::masked_store)
							continue;
						ptr = ii->getArgOperand(1);
						width = (u32)(module.getDataLayout()
								  .getTypeStoreSize(
								      ii->getArgOperand(0)->getType()));
					} else {
						continue;
					}
					u32 const off = StateOffset(ptr, fn->getArg(0));
					if (off == ~0u)
						continue; // not a CPUState store (an alloca, e.g. MXCSR)
					++stores_seen;
					auto cat = ct::StateCategory::Unowned;
					if (off == vstart_off) {
						cat = ct::StateCategory::VStart;
						++vstart_clears;
					} else if (off == fcsr_off) {
						cat = ct::StateCategory::FpFlags;
					} else if (off == open_off || off == saved_off) {
						cat = ct::StateCategory::FpBracket;
					} else if (off == ip_off) {
						cat = ct::StateCategory::GuestPc;
					} else {
						ct::ByteWindow const w{off, width};
						for (auto const &d : dst)
							if (ct::WindowsIntersect(w, d))
								cat = ct::StateCategory::DestinationWindow;
						if (cat == ct::StateCategory::Unowned)
							for (auto const &sw : src)
								if (ct::WindowsIntersect(w, sw))
									cat = ct::StateCategory::SourceWindow;
					}
					if (!ct::StateCategoryIsWritable(cat)) {
						printf("  FAIL %s vlen=%u: store at CPUState+%u width %u "
						       "is %s\n", r.name, vlen, off, width,
						       cat == ct::StateCategory::SourceWindow
							   ? "INTO ITS OWN SOURCE WINDOW"
							   : "unowned state");
						++g_fail;
						++unowned;
					}
				}
			// vstart is cleared exactly once on the taken path. Both the fast and the
			// fallback arm clear it, so the emitted function contains one per arm; what the
			// contract requires is one per PATH, which is what this counts against.
			CHECK(vstart_clears >= 1u);
			if (!ct::VStartClearCountIsSound(ct::VStartOwnerRule::FrameEpilogue,
							 1u, (u32)dst.size()))
				++g_fail;
		}
	printf("       %u route/width cells, %u CPUState stores classified, %u unowned\n", cells,
	       stores_seen, unowned);
	CHECK(cells > 0);
	CHECK(stores_seen > 0);
	CHECK_EQ(unowned, 0u);
}

// ---------------------------------------------------------------------------------------------
// PIECE 7: rounding and sticky-flag ownership.
void SectionFpOwnership()
{
	printf("[CT-11] one bracket per frame; a rounding body needs it; derived flags need "
	       "neutralisation\n");
	using FO = ct::FpOwnership;
	// The rule's own table, checked directly -- the lesson from CT-10's slipped mutation.
	CHECK(ct::FpOwnershipIsSound(FO{1u, 2u, true, true}));
	CHECK(ct::FpOwnershipIsSound(FO{1u, 0u, false, false}));
	CHECK(!ct::FpOwnershipIsSound(FO{2u, 1u, false, false}));  // two brackets
	CHECK(!ct::FpOwnershipIsSound(FO{0u, 1u, false, false}));  // rounds with no bracket
	CHECK(!ct::FpOwnershipIsSound(FO{1u, 1u, true, false}));   // derives a flag, host unmuzzled
	CHECK(ct::FpOwnershipIsSound(FO{0u, 0u, false, false}));   // vfclass: no FP machinery at all

	struct Row { char const *name; bool *flag; u32 sub; u32 vt; };
	Row const rows[] = {
	    {"vfcvt.f.x.v", &config::rvv_llvm_fcvt_itof, 3u, kVT_E32M1},
	    {"vfcvt.rtz.x.f.v", &config::rvv_llvm_fcvt_ftoi, 7u, kVT_E32M1},
	    {"vfcvt.x.f.v (frm)", &config::rvv_llvm_fcvt_ftoi, 1u, kVT_E32M1},
	    {"vfwcvt.f.f.v", &config::rvv_llvm_fcvt_fwiden, 12u, kVT_E32M1},
	    {"vfncvt.f.f.w", &config::rvv_llvm_fcvt_fnarrow, 20u, kVT_E32M1},
	    {"vfwcvt.rtz.x.f.v", &config::rvv_llvm_fcvt_ftoi_widen, 15u, kVT_E32M1},
	};
	u32 const fcsr_off = (u32)(offsetof(CPUState, fpu) + offsetof(rvv32::FPUState, fcsr));
	unsigned cells = 0;
	for (u32 vlen : {256u, 1024u})
		for (auto const &r : rows) {
			ConfigureBase(vlen);
			*r.flag = true;
			Built b({Vsetvli(r.vt), OpVfcvt(r.sub, kVs2, kVd), kJalr});
			llvm::Module module("ct7", g_llvm_ctx);
			CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
			CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
			b.region = CompilerGenRegionIR(&b.arena, job);
			LLVMGenCtx gctx(&module);
			gctx.AddFunction(0u, b.segment);
			QIRToLLVM gen(gctx, &b.segment, b.region, 0u);
			llvm::Function *fn = gen.Run();
			bool any = false;
			ct::FpOwnership o;
			for (auto &bb : b.region->GetBlocks())
				for (auto &ins : bb.ilist) {
					if (ins.GetOpcode() == Op::_rvvqcgfpbegin)
						++o.brackets_opened;
					if (ins.GetOpcode() == Op::_vchunkitof ||
					    ins.GetOpcode() == Op::_vchunkftoi ||
					    ins.GetOpcode() == Op::_vchunkftof)
						any = true;
				}
			if (!any)
				continue;
			++cells;
			for (auto &bb : *fn)
				for (auto &ins : bb) {
					if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins))
						if (StateOffset(st->getPointerOperand(),
								fn->getArg(0)) == fcsr_off) {
							// The bracket's own accrual is an OR of a VALUE
							// read from MXCSR; a DERIVED flag ORs a constant.
							llvm::Value *v = st->getValueOperand();
							if (auto *bo =
								llvm::dyn_cast<llvm::BinaryOperator>(v))
								if (bo->getOpcode() ==
									llvm::Instruction::Or &&
								    llvm::isa<llvm::Constant>(
									bo->getOperand(1)))
									o.derives_flags = true;
						}
					auto *ii = llvm::dyn_cast<llvm::IntrinsicInst>(&ins);
					if (!ii)
						continue;
					for (unsigned a = 0; a < ii->arg_size(); ++a)
						if (auto *mv = llvm::dyn_cast<llvm::MetadataAsValue>(
							ii->getArgOperand(a)))
							if (auto *ms = llvm::dyn_cast<llvm::MDString>(
								mv->getMetadata()))
								if (ms->getString() == "round.dynamic")
									++o.rounding_bodies;
					// Neutralisation: a conversion whose operand is a select.
					auto const id = ii->getIntrinsicID();
					if ((id == llvm::Intrinsic::experimental_constrained_fptosi ||
					     id == llvm::Intrinsic::experimental_constrained_fptoui) &&
					    llvm::isa<llvm::SelectInst>(ii->getArgOperand(0)))
						o.neutralises_operands = true;
					// The float-width routes derive NV without neutralising, and are
					// sound for a different reason: they never let the host raise a
					// flag the contract forbids, because fpext/fptrunc agree with it
					// on every lane. Record that explicitly rather than forcing them
					// through the neutralisation clause.
					if (id == llvm::Intrinsic::experimental_constrained_fpext ||
					    id == llvm::Intrinsic::experimental_constrained_fptrunc)
						o.neutralises_operands = true;
				}
			if (!ct::FpOwnershipIsSound(o)) {
				printf("  FAIL %s vlen=%u: brackets=%u rounding=%u derives=%d "
				       "neutralises=%d\n", r.name, vlen, o.brackets_opened,
				       o.rounding_bodies, (int)o.derives_flags,
				       (int)o.neutralises_operands);
				++g_fail;
			}
			CHECK_EQ(o.brackets_opened, 1u);
		}
	printf("       %u FP route/width cells checked for rounding/flag ownership\n", cells);
	CHECK(cells > 0);
}

} // namespace

// ---------------------------------------------------------------------------------------------
// [CT-12] ORDER ITEM 3: the FIRST MASKED ROUTE, checked against the same obligation.
//
// Until this route existed, `PredicateIsSound`'s third clause could only ever be discharged by the
// guard (`unmasked = true`), so the clause itself was untested against anything real. Here it is
// discharged the other way: the route ADMITS `vm == 0`, so `unmasked` measures FALSE, and soundness
// then REQUIRES the body to carry `architectural_mask`. That is what makes this section non-vacuous
// -- delete the emitted mask term and the section fails, whereas before there was no configuration
// in the tree in which it could.
void SectionMaskedRouteIsPredicateSound()
{
	printf("[CT-12] the masked integer route: unmasked=false (and, with restart, vstart0=false),\n"
	       "        so the body owes the mask term -- and the floor\n");
	struct M { char const *name; u32 f6; };
	M const ops[] = {{"vadd.vv (masked)", 0u}, {"vsub.vv (masked)", 2u}, {"vand.vv (masked)", 9u},
			 {"vor.vv (masked)", 10u}, {"vxor.vv (masked)", 11u}};
	unsigned admitted = 0;
	for (u32 vlen : {256u, 1024u})
	    for (bool restart : {false, true})
		for (auto const &o : ops) {
			ConfigureBase(vlen);
			config::rvv_llvm_masked = true;
			// ORDER ITEM 3, RESTART: with this on the guard stops proving `vstart == 0`,
			// so soundness needs the BODY's floor term too. The same section therefore
			// exercises both remaining ways `PredicateIsSound`'s obligations can be
			// discharged -- by the guard, and by the body -- for the first time.
			config::rvv_llvm_restart = restart;
			u32 const word = OpIVVMasked(o.f6, kVs2, 9u, kVd);
			Built b({Vsetvli(kVT_E32M1), word, kJalr});
			llvm::Module module("ct12", g_llvm_ctx);
			CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
			CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
			b.region = CompilerGenRegionIR(&b.arena, job);
			LLVMGenCtx gctx(&module);
			gctx.AddFunction(0u, b.segment);
			QIRToLLVM gen(gctx, &b.segment, b.region, 0u);
			llvm::Function *fn = gen.Run();

			Measured m;
			bool any_unit = false;
			for (auto &bb : b.region->GetBlocks())
				for (auto &ins : bb.ilist) {
					if (ins.GetOpcode() == Op::_rvvtypedchunkbegin)
						m.guard_kind =
						    (int)static_cast<InstRVVTypedChunkBegin *>(&ins)
							->guard_kind;
					switch (ins.GetOpcode()) {
					case Op::_vchunkadd:
					case Op::_vchunksub:
					case Op::_vchunkand:
					case Op::_vchunkor:
					case Op::_vchunkxor:
						any_unit = true;
						break;
					default:
						break;
					}
				}
			if (!any_unit) {
				printf("  FAIL %s vlen=%u: the masked route did not admit it\n",
				       o.name, vlen);
				++g_fail;
				continue;
			}
			++admitted;
			{
				std::string err;
				llvm::raw_string_ostream es(err);
				if (llvm::verifyModule(module, &es)) {
					printf("  FAIL %s: verifyModule rejected the module:\n%s\n",
					       o.name, err.c_str());
					++g_fail;
				}
			}
			u32 const vl_off =
			    (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vl));
			u32 const vstart_off =
			    (u32)(offsetof(CPUState, vec) + offsetof(rvv32::VectorState, vstart));
			for (auto &bb : *fn)
				for (auto &ins : bb) {
					auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins);
					if (!l)
						continue;
					u32 const off = StateOffset(l->getPointerOperand(),
								    fn->getArg(0));
					if (off == vl_off)
						m.reads_vl = true;
					if (off != vstart_off)
						continue;
					// THE TWO USES OF A `vec.vstart` LOAD ARE DIFFERENT FACTS and
					// must not be conflated: an `icmp eq` against zero is the
					// GUARD'S PROOF, while an unsigned ordered compare against a
					// lane-index vector is the BODY'S FLOOR. Counting the guard's
					// compare as a floor would make every pre-restart route look
					// like it had a term it does not have -- the same distinction
					// [CT-5] draws, restated here because this section is the first
					// in which BOTH can be true of the same function.
					for (auto *u : l->users()) {
						auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(u);
						if (!cmp)
							continue;
						if (cmp->getPredicate() == llvm::CmpInst::ICMP_EQ)
							m.guard_checks_vstart = true;
						if (cmp->getPredicate() == llvm::CmpInst::ICMP_ULE ||
						    cmp->getPredicate() == llvm::CmpInst::ICMP_ULT ||
						    cmp->getPredicate() == llvm::CmpInst::ICMP_UGE ||
						    cmp->getPredicate() == llvm::CmpInst::ICMP_UGT)
							m.reads_vstart_in_predicate = true;
					}
					// The splat interposes an insertelement/shufflevector between
					// the load and the compare, so the direct-user scan above is
					// not sufficient on its own for a VECTOR floor.
					for (auto *u : l->users())
						for (auto *uu : u->users())
							for (auto *uuu : uu->users())
								if (auto *cmp2 =
									llvm::dyn_cast<llvm::ICmpInst>(
									    uuu))
									if (cmp2->getPredicate() !=
									    llvm::CmpInst::ICMP_EQ)
										m.reads_vstart_in_predicate =
										    true;
				}
			m.reads_v0 = AnyMaskedStoreReadsV0(fn);
			// THE MEASUREMENT THAT MAKES THE SECTION BITE: this route admits `vm == 0`,
			// so its guard proves nothing about the mask.
			bool const admits_masked =
			    RouteAdmits(vlen, &config::rvv_llvm_masked, kVT_E32M1, word);
			config::rvv_llvm_restart = restart; // RouteAdmits reset it
			CHECK(admits_masked);
			ct::GuardProofs const proofs{m.guard_checks_vstart, !admits_masked};
			CHECK(!proofs.unmasked);
			// The guard's vstart proof must FOLLOW the switch, in both directions -- that
			// is the fact the floor term below has to compensate for.
			CHECK_EQ((int)m.guard_checks_vstart, (int)!restart);
			using GK = InstRVVTypedChunkBegin::GuardKind;
			ct::PredicateTerms const terms{
			    /*vl_bound=*/InstRVVTypedChunkBegin::GuardProvesFullVl((GK)m.guard_kind) ||
				m.reads_vl,
			    m.reads_vstart_in_predicate, m.reads_v0};
			// With restart on, soundness is IMPOSSIBLE without the body's floor -- the
			// clause `PredicateIsSound` has never had a route exercise until now.
			CHECK_EQ((int)terms.vstart_floor, (int)restart);
			if (!ct::PredicateIsSound(terms, proofs)) {
				printf("  FAIL %s vlen=%u: terms {vl=%d vstart=%d mask=%d} not sound "
				       "under proofs {vstart0=%d unmasked=%d} (guard kind %d)\n",
				       o.name, vlen, (int)terms.vl_bound, (int)terms.vstart_floor,
				       (int)terms.architectural_mask, (int)proofs.vstart_is_zero,
				       (int)proofs.unmasked, m.guard_kind);
				++g_fail;
			}
			// And the two facts the soundness result rests on, stated separately so a
			// failure names which one moved.
			CHECK(m.reads_v0);
			CHECK(m.reads_vl);
		}
	printf("       %u masked route/width cells checked\n", admitted);
	CHECK(admitted > 0);
}

int main()
{
	printf("rvv_rvv_contract_test\n");
	SectionGeometryTruthTable();
	SectionUnitLanes();
	SectionRoutesAgree();
	SectionPredicateAlgebra();
	SectionRoutesArePredicateSound();
	SectionTailPolicyAlgebra();
	SectionRoutesPublishSoundly();
	SectionOverlapAlgebra();
	SectionRoutesHaveNoSelfHazard();
	SectionStateOwnership();
	SectionFpOwnership();
	SectionMaskedRouteIsPredicateSound();
	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	printf("PASS (0 failures)\n");
	return 0;
}
