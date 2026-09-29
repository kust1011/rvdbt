// THE CFG-EDGE COMMIT INVARIANT FOR DIRTY P-VECTOR-SSA VALUES.
//
// WHAT THE INVARIANT IS
//
// `RV32Translator` keeps guest vector registers in a per-block cache (`rvv_chunk_values` /
// `rvv_chunk_valid` / `rvv_chunk_dirty`, plus the `rvv_fp_open` MXCSR bracket). The cache is
// BASIC-BLOCK scoped by construction: `TranslateIPRange` calls `RvvResetValues()` at the top of
// every ip range, so a successor block re-derives every guest vector value from `CPUState`.
//
//     INVARIANT: on EVERY edge that leaves a QIR block, every dirty chunk/mask must already have
//     been written back to `CPUState`, and the FP bracket must already be closed, by an
//     `RvvCommit` emitted IN THE PREDECESSOR BLOCK (or in a block that lies on that edge alone).
//
// A dirty value left live on an edge is not "still live" -- it is DROPPED, and the successor
// silently reads the value the producer overwrote. That is a wrong answer, not a slowdown.
//
// WHY THIS FILE EXISTS
//
// LLVM_FPCHAIN_E2E_20260910-1030 measured exactly that failure end to end: `MakeGBr`'s
// INTRA-REGION arm emitted `br` with no commit, and a 256-operation guest `vfadd.vv` chain
// produced `input + 206*0.25` where its own semantics are `input + 256*0.25`, at VLEN 512 and
// 1024, on both LLVM-backed execution modes. Commit `96ff24bca` repaired that arm in two lines but
// shipped no focused test: the only evidence was a whole-guest digest on an AVX-512 host.
//
// This file is that focused test, and it also covers the sibling edge the end-to-end gate could
// not reach -- `TranslateBrcc`'s in-region conditional successors, where the same hole existed and
// where a fix has to live in the SOURCE block because an in-region edge owns no block of its own.
//
// WHAT IS ASSERTED, per edge shape, at VLEN 512 and 1024
//
//   [1] clean-cache control  -- an edge with nothing dirty emits NO commit. This is what makes the
//       repair inert for every region that never leaves a vector value resident, and it fails if a
//       commit is ever made unconditional.
//   [2] in-region `br`       -- the producer block ends with `rvvfpend` + one `rvvwrite` per active
//       chunk, immediately before its terminator, at the exact `CPUState` offsets of the guest
//       register written; and the successor block RE-READS those same offsets.
//   [3] out-of-region `gbr`  -- unchanged pre-existing behaviour, asserted so a future edit to the
//       in-region arm cannot silently move the commit off this one.
//   [4] in-region `brcc`, BOTH successors  -- the commit is in the block that holds the `brcc`, so
//       it dominates both edges, and BOTH successor blocks re-read the committed offsets.
//   [5] mixed `brcc`         -- one in-region successor, one out-of-region: still exactly one
//       commit, in the source block, and the `gbr` edge's own commit is then empty.
//   [6] both-out-of-region `brcc` -- byte-identical QIR fingerprint to the pre-repair translator,
//       which is the arm the accepted AOT evidence was produced with.
//   [7] pure QCG (`--rvv-vector-ssa` off / `aot_use_llvm` off) -- no chunk cache exists, so no
//       `rvvread`/`rvvwrite`/`rvvfpbegin`/`rvvfpend` node is built at all and no commit can have
//       been added. Fingerprints are printed so a cross-build diff can confirm it.
//   [8] indirect edges (`gbrind` from `jalr`) are MEASURED AND REPORTED, not asserted. Fixing that
//       path is outside this checkpoint's authorisation; the number is here so the limitation is a
//       recorded fact rather than an omission.
//
// WHAT THIS FILE DOES NOT DO
//
//   * It changes no admission predicate and adds no RVV opcode.
//   * It builds QIR only. No backend runs, no object file is produced, nothing is executed, and no
//       vector instruction of any width is issued -- so it runs on any x86-64 host and its result
//       does not depend on `RVV_HOST_CHUNK_BITS`.
//   * It times nothing and makes no performance claim.
//
// PIPELINE, and it is the real one:
//     guest words -> qir::CompilerGenRegionIR (dbt/qmc/compile.cpp, the real RV32Translator)
// The ip-range set is supplied directly, which is what makes an edge in-region or not: `MakeGBr`
// and `TranslateBrcc` both decide that by looking the target up in `ip2bb`, and `ip2bb` holds
// exactly the entry ip of every range.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{

unsigned g_fail = 0;

#define CHECK(cond)                                                                                \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                   \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

#define CHECK_EQ(a, b)                                                                             \
	do {                                                                                       \
		auto va_ = (a);                                                                    \
		auto vb_ = (b);                                                                    \
		if (!(va_ == vb_)) {                                                               \
			printf("  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,  \
			       #b, (long long)va_, (long long)vb_);                                \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Guest words, built from the field layout rather than pasted.
// ---------------------------------------------------------------------------------------------
constexpr u32 OPCODE_OPV = 0b1010111u;
constexpr u32 OPCODE_BRANCH = 0b1100011u;
constexpr u32 OPCODE_JALR = 0b1100111u;
constexpr u32 OPCODE_AUIPC = 0b0010111u;
constexpr u32 F3_OPFVV = 0b001u;

u32 EncOpV(u32 funct6, u32 vm, u32 vs2, u32 vs1, u32 funct3, u32 vd)
{
	return (funct6 << 26) | (vm << 25) | (vs2 << 20) | (vs1 << 15) | (funct3 << 12) |
	       (vd << 7) | OPCODE_OPV;
}

// `vsetvli x10, x10, e32, m1, ta, ma`. rd and rs1 are both non-zero on purpose:
// RvvSetVLShapeAdmit refuses the rd==0 && rs1==0 "keep vl" form.
constexpr u32 VTYPEI_E32M1_TAMA = (1u << 7) | (1u << 6) | (0b010u << 3); // 0x0d0
static_assert(VTYPEI_E32M1_TAMA == 0x0d0u);
u32 EncVsetvli()
{
	return (VTYPEI_E32M1_TAMA << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | OPCODE_OPV;
}

// `vfadd.vv vd, vs2, vs1`, unmasked -- the encoding the just-widened LLVM falu arm admits.
u32 EncVfaddVV(u32 vd, u32 vs2, u32 vs1)
{
	return EncOpV(dbt::rv32::VF6_VFADD, 1, vs2, vs1, F3_OPFVV, vd);
}

// `bne x10, x11, imm` -- B-type immediate, reassembled from its five scattered fields so a wrong
// displacement is a build error in this function and not a silent edge to the wrong block.
u32 EncBne(i32 imm)
{
	u32 const u = (u32)imm;
	return (((u >> 12) & 1u) << 31) | (((u >> 5) & 0x3fu) << 25) | (11u << 20) | (10u << 15) |
	       (0b001u << 12) | (((u >> 1) & 0xfu) << 8) | (((u >> 11) & 1u) << 7) | OPCODE_BRANCH;
}

// `jalr rd, rs1, imm` -- the indirect edge. `EncRet()` is the canonical RISC-V return idiom
// (rd = x0, rs1 = ra = x1), which is the shape `jalr_class == 2` and the shadow-edge filter name.
u32 EncJalr(u32 rd, u32 rs1, u32 imm)
{
	return ((imm & 0xfffu) << 20) | (rs1 << 15) | (0b000u << 12) | (rd << 7) | OPCODE_JALR;
}
u32 EncRet() { return EncJalr(0, 1, 0); }
// `auipc rd, imm20` -- U-type. `insn::U::imm()` returns the field already shifted left by 12, so
// the target `direct_call_resolve::TryResolve` computes is `auipc_ip + (imm20 << 12) + jalr_imm`.
u32 EncAuipc(u32 rd, u32 imm20) { return (imm20 << 12) | (rd << 7) | OPCODE_AUIPC; }

// ---------------------------------------------------------------------------------------------
// The CPUState offsets the commit must use, derived here the same way RvvCommit derives them.
// ---------------------------------------------------------------------------------------------
u32 ChunkOffset(u32 vreg, u32 sub)
{
	return (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg) +
		     vreg * dbt::rv32::VLEN_MAX_BYTES + sub * 64u);
}

unsigned ActiveChunks(u32 vlen_bits) { return vlen_bits / 512u; } // LMUL = 1

// ---------------------------------------------------------------------------------------------
// Build harness.
// ---------------------------------------------------------------------------------------------
void ResetConfig()
{
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_falu = false;
	config::rvv_qcg_typed_chunk_fma = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_counters = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_vector_run = false;
	config::rvv_llvm_wide_vadd = false;
	config::rvv_llvm_wide_vadd_ssa = false;
	config::qcg_leaf_inline = false;
	config::aot_work_counter = false;
	config::aot_region_hit_count = false;
	config::aot_region_cycle_count = false;
	config::aot_brcc_real_weights = false;
	config::aot_use_llvm = false;
	// The three default-off jalr guard mechanisms are driven from these maps, and they are
	// process-global: a case that forgot to clear them would silently inherit the previous case's
	// shape. Cleared here so every fixture starts from the stock lowering.
	config::aot_fdre_lower = false;
	config::aot_guardonly_lower = false;
	config::aot_multiguard_lower = false;
	config::aot_direct_call_fusion = false;
	config::subst_stable_jalr = false;
	config::aot_return_directify = false;
	config::profile_brind_edges = false;
	config::sr_sampled_edges = false;
	config::aot_fdre_dominant_target.clear();
	config::aot_guardonly_target.clear();
	config::aot_multiguard_targets.clear();
	config::g_elf_exec_ranges.clear();
}

// The LLVM/AOT substrate: `--aot-use-llvm` plus `--rvv-vector-ssa`, which is what RvvSSAEnabled()
// requires. `--rvv-qcg-direct-setvl` is on so a `vsetvli` takes its direct route: the helper route
// would call TranslateHelper, which commits and resets the cache, and would therefore dissolve the
// very situation under test. That is a property of the fixture, stated rather than hidden.
void ConfigSSA(u32 vlen_bits)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = true;
	config::rvv_qcg_direct_setvl = true;
	config::vlen_bits = vlen_bits;
}

void ConfigPureQCG(u32 vlen_bits)
{
	ResetConfig();
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_qcg_direct_setvl = true;
	config::vlen_bits = vlen_bits;
}

struct Built {
	std::unique_ptr<MemArena> arena;
	Region *region = nullptr;
};

Built Build(std::vector<u32> const &words, CompilerJob::IpRangesSet ranges)
{
	Built b;
	b.arena = std::make_unique<MemArena>(1u << 20);
	static std::vector<u32> storage;
	storage = words;
	CompilerJob job(nullptr, (uptr)storage.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(b.arena.get(), job);
	return b;
}

// ---------------------------------------------------------------------------------------------
// QIR inspection.
// ---------------------------------------------------------------------------------------------
Block *BlockAt(Region *region, u32 entry_ip)
{
	for (auto &bb : region->GetBlocks()) {
		if (bb.entry_ip == entry_ip)
			return &bb;
	}
	return nullptr;
}

unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			n += ins.GetOpcode() == op;
	return n;
}

unsigned CountOpIn(Block *bb, Op op)
{
	unsigned n = 0;
	if (bb)
		for (auto &ins : bb->ilist)
			n += ins.GetOpcode() == op;
	return n;
}

std::vector<u32> WriteOffsetsIn(Block *bb)
{
	std::vector<u32> out;
	if (!bb)
		return out;
	for (auto &ins : bb->ilist) {
		if (ins.GetOpcode() == Op::_rvvwrite)
			out.push_back(static_cast<InstRVVWrite *>(&ins)->i(0).GetConst());
	}
	return out;
}

std::vector<u32> ReadOffsetsIn(Block *bb)
{
	std::vector<u32> out;
	if (!bb)
		return out;
	for (auto &ins : bb->ilist) {
		if (ins.GetOpcode() == Op::_rvvread)
			out.push_back(static_cast<InstRVVRead *>(&ins)->i(0).GetConst());
	}
	return out;
}

Op TerminatorOp(Block *bb)
{
	Op last = Op::Count;
	if (bb)
		for (auto &ins : bb->ilist)
			last = ins.GetOpcode();
	return last;
}

// The commit must be the LAST thing in the block before its terminator, because anything emitted
// after it could dirty the cache again. Returns the number of trailing `rvvwrite` immediately
// preceding the terminator, so "three writes somewhere earlier plus a later redefinition" cannot
// pass as "three writes on the edge".
unsigned TrailingWritesBeforeTerminator(Block *bb)
{
	if (!bb)
		return 0;
	std::vector<Op> ops;
	for (auto &ins : bb->ilist)
		ops.push_back(ins.GetOpcode());
	if (ops.empty())
		return 0;
	unsigned n = 0;
	// ops.back() is the terminator; walk backwards over the commit run.
	for (size_t k = ops.size() - 1; k-- > 0;) {
		if (ops[k] == Op::_rvvwrite)
			++n;
		else
			break;
	}
	return n;
}

// The blocks `TranslateBrcc::make_target` creates for an OUT-of-region successor: they lie on that
// edge alone and hold nothing but the commit and the `gbr`. `MakeGBr`'s own gbr arm emits into the
// current block instead of creating one, so this finds exactly the conditional-branch edge blocks.
// Writes (or reads) that name a specific guest vector register's chunk offsets, anywhere in the
// region. Counting *all* `rvvwrite` would fold in other blocks' commits of their own values, which
// is what makes a region-wide total the wrong instrument for "this value was committed once".
unsigned CountRegWrites(Region *region, u32 vreg, unsigned chunks)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_rvvwrite) {
				u32 off = static_cast<InstRVVWrite *>(&ins)->i(0).GetConst();
				for (unsigned c = 0; c < chunks; ++c)
					n += off == ChunkOffset(vreg, c);
			}
	return n;
}

unsigned CountRegWritesIn(Block *bb, u32 vreg, unsigned chunks)
{
	unsigned n = 0;
	if (bb)
		for (auto &ins : bb->ilist)
			if (ins.GetOpcode() == Op::_rvvwrite) {
				u32 off = static_cast<InstRVVWrite *>(&ins)->i(0).GetConst();
				for (unsigned c = 0; c < chunks; ++c)
					n += off == ChunkOffset(vreg, c);
			}
	return n;
}

std::vector<Block *> EdgeOnlyGbrBlocks(Region *region)
{
	std::vector<Block *> out;
	for (auto &bb : region->GetBlocks()) {
		bool ends_gbr = false, only_edge_ops = true;
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_gbr:
				ends_gbr = true;
				break;
			case Op::_rvvwrite:
			case Op::_rvvfpend:
				break;
			default:
				only_edge_ops = false;
				break;
			}
		}
		if (ends_gbr && only_edge_ops)
			out.push_back(&bb);
	}
	return out;
}

bool Contains(std::vector<u32> const &v, u32 x)
{
	for (u32 e : v)
		if (e == x)
			return true;
	return false;
}

// A total, order-preserving fingerprint of the constructed IR: opcode sequence per block plus the
// constants that make an edge or a commit what it is. Used for the pure-QCG and both-gbr arms,
// where the claim is "byte-identical", and printed so a cross-build diff can check it.
std::string Fingerprint(Region *region)
{
	std::string s;
	char buf[128];
	for (auto &bb : region->GetBlocks()) {
		snprintf(buf, sizeof(buf), "bb(%08x){", bb.entry_ip);
		s += buf;
		for (auto &ins : bb.ilist) {
			snprintf(buf, sizeof(buf), "%u", (unsigned)ins.GetOpcode());
			s += buf;
			switch (ins.GetOpcode()) {
			case Op::_rvvwrite:
				snprintf(buf, sizeof(buf), "[w=%u]",
					 static_cast<InstRVVWrite *>(&ins)->i(0).GetConst());
				s += buf;
				break;
			case Op::_rvvread:
				snprintf(buf, sizeof(buf), "[r=%u]",
					 static_cast<InstRVVRead *>(&ins)->i(0).GetConst());
				s += buf;
				break;
			case Op::_br:
				snprintf(buf, sizeof(buf), "[br=%08x]",
					 static_cast<InstBr *>(&ins)->ip);
				s += buf;
				break;
			default:
				break;
			}
			s += ",";
		}
		s += "}";
	}
	return s;
}

// ---------------------------------------------------------------------------------------------
// The word streams. Each is one guest shape, and the ip-range split is what decides in-region.
// ---------------------------------------------------------------------------------------------
//
// A. producer, then an in-region unconditional edge, then a native consumer.
//
//    ip 0   vsetvli                    establishes e32/m1 for this block
//    ip 4   vfadd.vv v1, v2, v3        PRODUCES v1 -- the dirty P-vector-SSA group
//    ip 8   vsetvli                    direct route: records the vtype, commits nothing
//    -- range boundary: TranslateIPRange runs out of range, MakeGBr(12) finds 12 in ip2bb --
//    ip 12  vfadd.vv v4, v1, v3        CONSUMES v1, in the successor block
//
// The second `vsetvli` at ip 8 is load-bearing twice: it is what makes ip 12 a NATIVE consumer
// (the block-entry heuristic in TranslateIPRange reads the word at ip-4 and accepts a constant
// `vsetvli`), and it is on the direct route so it does not itself commit.
std::vector<u32> WordsA()
{
	return {EncVsetvli(), EncVfaddVV(1, 2, 3), EncVsetvli(), EncVfaddVV(4, 1, 3)};
}
CompilerJob::IpRangesSet RangesA() { return {{0u, 12u}, {12u, 16u}}; }

// B. the same producer with the SAME ip ranges, but nothing dirty at the boundary: the only
// vector instruction is the vsetvli, so the cache is clean on the edge.
std::vector<u32> WordsB() { return {EncVsetvli(), EncVsetvli(), EncVsetvli(), EncVsetvli()}; }

// C. producer, then an OUT-of-region unconditional edge: one ip range, so MakeGBr's target is not
// in ip2bb and the pre-existing `gbr` arm carries the commit.
std::vector<u32> WordsC() { return {EncVsetvli(), EncVfaddVV(1, 2, 3)}; }
CompilerJob::IpRangesSet RangesC() { return {{0u, 8u}}; }

// D. producer, then a CONDITIONAL edge whose two successors are BOTH in-region, each with its own
// native consumer of v1.
//
//    ip 0   vsetvli
//    ip 4   vfadd.vv v1, v2, v3        PRODUCES v1
//    ip 8   bne x10, x11, +12          false edge -> ip 12, true edge -> ip 20
//    ip 12  vsetvli                    (false successor block head)
//    ip 16  vfadd.vv v4, v1, v3        CONSUMES v1 on the FALSE path
//    ip 20  vsetvli                    (true successor block head)
//    ip 24  vfadd.vv v5, v1, v3        CONSUMES v1 on the TRUE path
std::vector<u32> WordsD()
{
	return {EncVsetvli(),        EncVfaddVV(1, 2, 3), EncBne(12),         EncVsetvli(),
		EncVfaddVV(4, 1, 3), EncVsetvli(),        EncVfaddVV(5, 1, 3)};
}
CompilerJob::IpRangesSet RangesD() { return {{0u, 12u}, {12u, 20u}, {20u, 28u}}; }

// E. the mixed conditional: the FALSE successor (ip 12) is a range, the TRUE successor (ip 20) is
// not, so one edge is `br`-like and the other is a real `gbr` with its own block.
CompilerJob::IpRangesSet RangesE() { return {{0u, 12u}, {12u, 20u}}; }

// F. the both-out-of-region conditional: one range, neither successor in ip2bb. This is the arm
// every accepted AOT result was produced with and it must not change.
CompilerJob::IpRangesSet RangesF() { return {{0u, 12u}}; }

// G. producer, then an INDIRECT edge (`jalr x0, x1, 0` -- a guest return). The stock path: one
// `gbrind` terminating the producer's own block.
std::vector<u32> WordsG() { return {EncVsetvli(), EncVfaddVV(1, 2, 3), EncRet()}; }
CompilerJob::IpRangesSet RangesG() { return {{0u, 12u}}; }

// G0. the same indirect edge with NOTHING dirty on it -- the clean-cache control for section 8.
std::vector<u32> WordsG0() { return {EncVsetvli(), EncVsetvli(), EncRet()}; }

// H. producer, then an indirect edge the GUARD mechanisms rewrite. `jalr x5, x6, 0`: rd != rs1, so
// `rd_aliases_rs1` is false and each mechanism takes its general guard+fallback shape rather than
// its `!aot_use_llvm` early-out (which `RvvSSAEnabled()` makes unreachable anyway, since that
// predicate requires `aot_use_llvm`).
//
//   ip 0   vsetvli
//   ip 4   vfadd.vv v1, v2, v3      PRODUCES v1
//   ip 8   jalr x5, x6, 0           the guarded indirect edge
//   ip 12  vsetvli                  (--aot-fdre-lower's in-region HIT target)
//   ip 16  vfadd.vv v4, v1, v3      CONSUMES v1 on the hit path
std::vector<u32> WordsH()
{
	return {EncVsetvli(), EncVfaddVV(1, 2, 3), EncJalr(5, 6, 0), EncVsetvli(),
		EncVfaddVV(4, 1, 3)};
}
CompilerJob::IpRangesSet RangesH_fused() { return {{0u, 12u}, {12u, 20u}}; }
CompilerJob::IpRangesSet RangesH_single() { return {{0u, 12u}}; }

// J. producer, then an indirect edge `direct_call_resolve::TryResolve` proves is a local
// AUIPC+JALR pair, which lowers through `MakeGBr` and no `gbrind` at all.
//
//   ip 0   vsetvli
//   ip 4   vfadd.vv v1, v2, v3      PRODUCES v1
//   ip 8   auipc x6, 1              closest preceding write to x6  -> imm() == 0x1000
//   ip 12  jalr x5, x6, 0           target = 8 + 0x1000 + 0 = 0x1008
constexpr u32 kFusedTarget = 8u + 0x1000u;
std::vector<u32> WordsJ()
{
	return {EncVsetvli(), EncVfaddVV(1, 2, 3), EncAuipc(6, 1), EncJalr(5, 6, 0)};
}
CompilerJob::IpRangesSet RangesJ() { return {{0u, 16u}}; }

// ---------------------------------------------------------------------------------------------

void Section1_CleanCacheControl(u32 vlen)
{
	printf("[1] clean cache on the edge emits NO commit  (VLEN %u)\n", vlen);
	ConfigSSA(vlen);
	auto b = Build(WordsB(), RangesA());
	auto *src = BlockAt(b.region, 0u);
	CHECK(src != nullptr);
	CHECK_EQ(TerminatorOp(src), Op::_br);
	CHECK_EQ(CountOp(b.region, Op::_rvvwrite), 0u);
	CHECK_EQ(CountOp(b.region, Op::_rvvfpend), 0u);
	printf("      terminator=br  rvvwrite=%u  rvvfpend=%u\n", CountOp(b.region, Op::_rvvwrite),
	       CountOp(b.region, Op::_rvvfpend));
}

void Section2_InRegionUnconditional(u32 vlen)
{
	printf("[2] in-region unconditional edge (MakeGBr)  (VLEN %u)\n", vlen);
	unsigned const chunks = ActiveChunks(vlen);
	ConfigSSA(vlen);
	auto b = Build(WordsA(), RangesA());

	auto *src = BlockAt(b.region, 0u);
	auto *dst = BlockAt(b.region, 12u);
	CHECK(src != nullptr);
	CHECK(dst != nullptr);

	// The edge really is in-region: the producer block ends in `br` and holds no `gbr`. (The
	// region's LAST range still leaves the region, so a region-wide `gbr` count would be 1 here
	// and would say nothing about the edge under test.)
	CHECK_EQ(TerminatorOp(src), Op::_br);
	CHECK_EQ(CountOpIn(src, Op::_gbr), 0u);
	CHECK_EQ(CountOpIn(src, Op::_br), 1u);

	// The producer really is the direct P-vector-SSA route, not a helper: the FP bracket opened.
	CHECK_EQ(CountOpIn(src, Op::_rvvfpbegin), 1u);
	CHECK_EQ(CountOpIn(src, Op::_rvvfalu), 1u);

	// THE INVARIANT. One write per active chunk, at the offsets of v1, in the producer block, as
	// the trailing run before the terminator, with the FP bracket closed.
	auto writes = WriteOffsetsIn(src);
	CHECK_EQ(writes.size(), (size_t)chunks);
	CHECK_EQ(TrailingWritesBeforeTerminator(src), chunks);
	CHECK_EQ(CountOpIn(src, Op::_rvvfpend), 1u);
	for (unsigned c = 0; c < chunks; ++c)
		CHECK(Contains(writes, ChunkOffset(1, c)));

	// ...and the consumer on the other side of the edge re-reads exactly those offsets, which is
	// what makes the write load-bearing rather than decorative.
	auto reads = ReadOffsetsIn(dst);
	for (unsigned c = 0; c < chunks; ++c)
		CHECK(Contains(reads, ChunkOffset(1, c)));
	CHECK_EQ(CountOpIn(dst, Op::_rvvfalu), 1u);

	printf("      br  producer writes=%zu trailing=%u fpend=%u  consumer reads=%zu\n",
	       writes.size(), TrailingWritesBeforeTerminator(src), CountOpIn(src, Op::_rvvfpend),
	       reads.size());
}

void Section3_OutOfRegionUnconditional(u32 vlen)
{
	printf("[3] out-of-region unconditional edge (gbr, pre-existing)  (VLEN %u)\n", vlen);
	unsigned const chunks = ActiveChunks(vlen);
	ConfigSSA(vlen);
	auto b = Build(WordsC(), RangesC());
	auto *src = BlockAt(b.region, 0u);
	CHECK(src != nullptr);
	CHECK_EQ(TerminatorOp(src), Op::_gbr);
	CHECK_EQ(CountOp(b.region, Op::_br), 0u);
	auto writes = WriteOffsetsIn(src);
	CHECK_EQ(writes.size(), (size_t)chunks);
	CHECK_EQ(TrailingWritesBeforeTerminator(src), chunks);
	CHECK_EQ(CountOpIn(src, Op::_rvvfpend), 1u);
	printf("      gbr writes=%zu trailing=%u fpend=%u\n", writes.size(),
	       TrailingWritesBeforeTerminator(src), CountOpIn(src, Op::_rvvfpend));
}

void Section4_InRegionConditionalBothEdges(u32 vlen)
{
	printf("[4] in-region CONDITIONAL edge, both successors (TranslateBrcc)  (VLEN %u)\n", vlen);
	unsigned const chunks = ActiveChunks(vlen);
	ConfigSSA(vlen);
	auto b = Build(WordsD(), RangesD());

	auto *src = BlockAt(b.region, 0u);
	auto *dst_f = BlockAt(b.region, 12u); // the not-taken successor
	auto *dst_t = BlockAt(b.region, 20u); // the taken successor
	CHECK(src != nullptr);
	CHECK(dst_f != nullptr);
	CHECK(dst_t != nullptr);

	// Both edges really are in-region: one brcc, no gbr in the source block, and NO edge block was
	// created for either successor -- which is precisely why the commit cannot live on an edge.
	CHECK_EQ(TerminatorOp(src), Op::_brcc);
	CHECK_EQ(CountOpIn(src, Op::_gbr), 0u);
	CHECK_EQ(CountOp(b.region, Op::_brcc), 1u);
	CHECK_EQ(EdgeOnlyGbrBlocks(b.region).size(), (size_t)0);
	CHECK_EQ(src->GetSuccs().size(), (size_t)2);

	// THE INVARIANT, in the block that holds the terminator -- which is the only place that
	// dominates BOTH successors, since neither in-region edge owns a block of its own.
	auto writes = WriteOffsetsIn(src);
	CHECK_EQ(writes.size(), (size_t)chunks);
	CHECK_EQ(TrailingWritesBeforeTerminator(src), chunks);
	CHECK_EQ(CountOpIn(src, Op::_rvvfpend), 1u);
	for (unsigned c = 0; c < chunks; ++c)
		CHECK(Contains(writes, ChunkOffset(1, c)));

	// BOTH SUCCESSOR OUTCOMES: each re-reads the committed offsets.
	auto reads_f = ReadOffsetsIn(dst_f);
	auto reads_t = ReadOffsetsIn(dst_t);
	for (unsigned c = 0; c < chunks; ++c) {
		CHECK(Contains(reads_f, ChunkOffset(1, c)));
		CHECK(Contains(reads_t, ChunkOffset(1, c)));
	}
	CHECK_EQ(CountOpIn(dst_f, Op::_rvvfalu), 1u);
	CHECK_EQ(CountOpIn(dst_t, Op::_rvvfalu), 1u);

	// The commit happens ONCE for this terminator, not once per edge.
	CHECK_EQ(CountOpIn(src, Op::_rvvwrite), chunks);
	CHECK_EQ(CountOpIn(src, Op::_rvvfpend), 1u);

	printf("      brcc writes=%zu trailing=%u fpend=%u  false-reads=%zu true-reads=%zu\n",
	       writes.size(), TrailingWritesBeforeTerminator(src), CountOpIn(src, Op::_rvvfpend),
	       reads_f.size(), reads_t.size());
}

void Section5_MixedConditional(u32 vlen)
{
	printf("[5] mixed CONDITIONAL edge: one in-region successor, one gbr  (VLEN %u)\n", vlen);
	unsigned const chunks = ActiveChunks(vlen);
	ConfigSSA(vlen);
	auto b = Build(WordsD(), RangesE());

	auto *src = BlockAt(b.region, 0u);
	auto *dst_f = BlockAt(b.region, 12u);
	CHECK(src != nullptr);
	CHECK(dst_f != nullptr);
	CHECK_EQ(TerminatorOp(src), Op::_brcc);
	// Exactly one edge block: the true successor left the region and got one; the false successor
	// is in-region and got none.
	auto edge_blocks = EdgeOnlyGbrBlocks(b.region);
	CHECK_EQ(edge_blocks.size(), (size_t)1);

	auto writes = WriteOffsetsIn(src);
	CHECK_EQ(writes.size(), (size_t)chunks);
	CHECK_EQ(TrailingWritesBeforeTerminator(src), chunks);
	CHECK_EQ(CountOpIn(src, Op::_rvvfpend), 1u);
	// ONE commit for the whole terminator, in the source block. The gbr edge's own RvvCommit then
	// finds a clean cache and adds nothing -- which is what keeps the repair from double-storing
	// on the mixed shape, and it is the assertion a `clear_dirty = false` typo would break.
	if (!edge_blocks.empty()) {
		CHECK_EQ(CountOpIn(edge_blocks[0], Op::_rvvwrite), 0u);
		CHECK_EQ(CountOpIn(edge_blocks[0], Op::_rvvfpend), 0u);
	}

	auto reads_f = ReadOffsetsIn(dst_f);
	for (unsigned c = 0; c < chunks; ++c)
		CHECK(Contains(reads_f, ChunkOffset(1, c)));

	printf("      brcc src-writes=%zu edge-blocks=%zu edge-writes=%u region gbr=%u\n",
	       writes.size(), edge_blocks.size(),
	       edge_blocks.empty() ? 0u : CountOpIn(edge_blocks[0], Op::_rvvwrite),
	       CountOp(b.region, Op::_gbr));
}

void Section6_BothOutOfRegionConditional(u32 vlen)
{
	printf("[6] both-out-of-region CONDITIONAL edge -- the pre-existing arm  (VLEN %u)\n", vlen);
	unsigned const chunks = ActiveChunks(vlen);
	ConfigSSA(vlen);
	auto b = Build(WordsD(), RangesF());

	auto *src = BlockAt(b.region, 0u);
	CHECK(src != nullptr);
	CHECK_EQ(TerminatorOp(src), Op::_brcc);
	CHECK_EQ(CountOp(b.region, Op::_gbr), 2u);
	// The source block carries NO commit here: each gbr edge has a block of its own and commits
	// there, exactly as before the repair. Two edges, two commits, `chunks` writes each.
	auto edge_blocks = EdgeOnlyGbrBlocks(b.region);
	CHECK_EQ(edge_blocks.size(), (size_t)2);
	for (auto *eb : edge_blocks) {
		CHECK_EQ(CountOpIn(eb, Op::_rvvwrite), chunks);
		CHECK_EQ(CountOpIn(eb, Op::_rvvfpend), 1u);
	}
	CHECK_EQ(WriteOffsetsIn(src).size(), (size_t)0);
	CHECK_EQ(CountOpIn(src, Op::_rvvfpend), 0u);
	CHECK_EQ(CountOp(b.region, Op::_rvvwrite), 2u * chunks);
	CHECK_EQ(CountOp(b.region, Op::_rvvfpend), 2u);
	printf("      brcc src-writes=0 region writes=%u gbr=%u fpend=%u\n",
	       CountOp(b.region, Op::_rvvwrite), CountOp(b.region, Op::_gbr),
	       CountOp(b.region, Op::_rvvfpend));
	printf("      FINGERPRINT_BOTH_GBR_V%u %s\n", vlen, Fingerprint(b.region).c_str());
}

void Section7_PureQCGUnchanged(u32 vlen)
{
	printf("[7] pure QCG (RVV SSA off): no chunk cache, so no commit can exist  (VLEN %u)\n",
	       vlen);
	struct Case {
		char const *name;
		std::vector<u32> words;
		CompilerJob::IpRangesSet ranges;
	};
	Case cases[] = {
	    {"A_in_region_br", WordsA(), RangesA()},
	    {"C_out_of_region_gbr", WordsC(), RangesC()},
	    {"D_in_region_brcc", WordsD(), RangesD()},
	    {"E_mixed_brcc", WordsD(), RangesE()},
	    {"F_both_gbr_brcc", WordsD(), RangesF()},
	    {"G_indirect_gbrind", WordsG(), RangesG()},
	    {"H_indirect_guarded", WordsH(), RangesH_fused()},
	    {"J_indirect_resolved", WordsJ(), RangesJ()},
	};
	for (auto &c : cases) {
		ConfigPureQCG(vlen);
		auto b = Build(c.words, c.ranges);
		CHECK_EQ(CountOp(b.region, Op::_rvvwrite), 0u);
		CHECK_EQ(CountOp(b.region, Op::_rvvread), 0u);
		CHECK_EQ(CountOp(b.region, Op::_rvvfpbegin), 0u);
		CHECK_EQ(CountOp(b.region, Op::_rvvfpend), 0u);
		CHECK_EQ(CountOp(b.region, Op::_rvvfalu), 0u);
		printf("      FINGERPRINT_QCG_%s_V%u %s\n", c.name, vlen,
		       Fingerprint(b.region).c_str());
	}
}

void Section8_IndirectEdgeDefault(u32 vlen)
{
	printf("[8] indirect edge -- the STOCK gbrind path  (VLEN %u)\n", vlen);
	unsigned const chunks = ActiveChunks(vlen);

	// 8a. the clean-cache control first: an indirect edge with nothing resident emits no commit.
	ConfigSSA(vlen);
	{
		auto b = Build(WordsG0(), RangesG());
		CHECK_EQ(CountOp(b.region, Op::_gbrind), 1u);
		CHECK_EQ(CountOp(b.region, Op::_rvvwrite), 0u);
		CHECK_EQ(CountOp(b.region, Op::_rvvfpend), 0u);
		printf("      clean cache: gbrind=1 rvvwrite=0 rvvfpend=0\n");
	}

	// 8b. THE INVARIANT on the stock path. `jalr` carries Flags::Branch only, so PreSideeff never
	// runs for it and nothing upstream commits: before the repair this block held gbrind=1,
	// rvvwrite=0, rvvfpend=0 with v1 live and dirty.
	ConfigSSA(vlen);
	auto b = Build(WordsG(), RangesG());
	auto *src = BlockAt(b.region, 0u);
	CHECK(src != nullptr);
	CHECK_EQ(TerminatorOp(src), Op::_gbrind);
	CHECK_EQ(CountOp(b.region, Op::_gbrind), 1u);
	CHECK_EQ(CountOpIn(src, Op::_rvvfpbegin), 1u); // the producer really took the SSA route
	CHECK_EQ(CountOpIn(src, Op::_rvvfalu), 1u);

	auto writes = WriteOffsetsIn(src);
	CHECK_EQ(writes.size(), (size_t)chunks);
	CHECK_EQ(TrailingWritesBeforeTerminator(src), chunks);
	CHECK_EQ(CountOpIn(src, Op::_rvvfpend), 1u);
	for (unsigned c = 0; c < chunks; ++c)
		CHECK(Contains(writes, ChunkOffset(1, c)));
	// One commit of v1, not one per anything, in the whole region.
	CHECK_EQ(CountRegWrites(b.region, 1, chunks), chunks);
	CHECK_EQ(CountOp(b.region, Op::_rvvfpend), 1u);
	printf("      gbrind writes=%zu trailing=%u fpend=%u\n", writes.size(),
	       TrailingWritesBeforeTerminator(src), CountOpIn(src, Op::_rvvfpend));
}

// The three default-off guard mechanisms rewrite this edge into a `brcc` whose HIT successor never
// reaches the `gbrind`. They are the structurally distinct paths a commit placed next to the
// `gbrind` would bypass, which is the whole reason the repair sits in the source block instead.
void Section9_IndirectGuardedPaths(u32 vlen)
{
	printf("[9] indirect edge -- the GUARDED rewrites (fdre / guardonly / multiguard)  (VLEN %u)\n",
	       vlen);
	unsigned const chunks = ActiveChunks(vlen);

	auto assert_source_commit = [&](Region *region, char const *what) {
		auto *src = BlockAt(region, 0u);
		CHECK(src != nullptr);
		if (!src)
			return;
		// The source block ends in the guard compare, not in the dispatch.
		CHECK_EQ(TerminatorOp(src), Op::_brcc);
		auto writes = WriteOffsetsIn(src);
		CHECK_EQ(writes.size(), (size_t)chunks);
		CHECK_EQ(TrailingWritesBeforeTerminator(src), chunks);
		CHECK_EQ(CountOpIn(src, Op::_rvvfpend), 1u);
		for (unsigned c = 0; c < chunks; ++c)
			CHECK(Contains(writes, ChunkOffset(1, c)));
		// v1 IS COMMITTED EXACTLY ONCE IN THE WHOLE REGION, and it is here. Every other block
		// this mechanism builds -- the fallback holding the `gbrind`, each `hit_bb` holding a
		// `gbr` -- must contain no write of v1, because the source already committed and
		// cleared. A fallback-only repair would put v1's writes in the fallback and leave every
		// hit path dirty; this is the assertion that tells the two apart. (Region-wide
		// `rvvwrite` is deliberately NOT the instrument: a successor block that produces its own
		// value commits it legitimately, and folding that in would make the count structural
		// noise.)
		CHECK_EQ(CountRegWrites(region, 1, chunks), chunks);
		CHECK_EQ(CountRegWritesIn(src, 1, chunks), chunks);
		printf("      %-11s src-v1-writes=%u trailing=%u region-v1-writes=%u gbrind=%u gbr=%u brcc=%u\n",
		       what, CountRegWritesIn(src, 1, chunks), TrailingWritesBeforeTerminator(src),
		       CountRegWrites(region, 1, chunks), CountOp(region, Op::_gbrind),
		       CountOp(region, Op::_gbr), CountOp(region, Op::_brcc));
	};

	// 9a. --aot-fdre-lower: the HIT edge is a direct branch to a block ALREADY IN THIS REGION, so
	// the hit path is an in-region successor exactly like TranslateBrcc's, and it consumes v1.
	{
		ConfigSSA(vlen);
		config::aot_fdre_lower = true;
		config::aot_fdre_dominant_target[0u] = 12u;
		auto b = Build(WordsH(), RangesH_fused());
		assert_source_commit(b.region, "fdre");
		CHECK_EQ(CountOp(b.region, Op::_gbrind), 1u); // the miss path is unchanged
		auto *hit = BlockAt(b.region, 12u);
		CHECK(hit != nullptr);
		auto reads = ReadOffsetsIn(hit);
		for (unsigned c = 0; c < chunks; ++c)
			CHECK(Contains(reads, ChunkOffset(1, c))); // the hit path READS what was committed
		// ...and does not write v1 itself, so the read can only be seeing the source's commit.
		CHECK_EQ(CountRegWritesIn(hit, 1, chunks), 0u);
	}

	// 9b. --aot-guardonly-lower: the HIT edge is an external `gbr` in a block of its own.
	{
		ConfigSSA(vlen);
		config::aot_guardonly_lower = true;
		config::aot_guardonly_target[0u] = 0x100u;
		auto b = Build(WordsH(), RangesH_single());
		assert_source_commit(b.region, "guardonly");
		CHECK_EQ(CountOp(b.region, Op::_gbrind), 1u);
		CHECK_EQ(CountOp(b.region, Op::_gbr), 1u);
	}

	// 9c. --aot-multiguard-lower: an N-way chain -- N hit blocks, N-1 miss blocks, one fallback.
	{
		ConfigSSA(vlen);
		config::aot_multiguard_lower = true;
		config::aot_multiguard_targets[0u] = {0x100u, 0x200u};
		auto b = Build(WordsH(), RangesH_single());
		assert_source_commit(b.region, "multiguard");
		CHECK_EQ(CountOp(b.region, Op::_gbrind), 1u);
		CHECK_EQ(CountOp(b.region, Op::_gbr), 2u);
		CHECK_EQ(CountOp(b.region, Op::_brcc), 2u);
	}
}

// The resolved paths (--subst-stable-jalr / --aot-direct-call-fusion / --aot-return-directify) end
// in `MakeGBr`, which has committed on both of its arms since 96ff24bca/21b93af30. They were
// already correct, and the repair must leave them so -- one commit, not two, and in the same place.
void Section10_IndirectResolvedPath(u32 vlen)
{
	printf("[10] indirect edge -- the RESOLVED MakeGBr path (--aot-direct-call-fusion)  (VLEN %u)\n",
	       vlen);
	unsigned const chunks = ActiveChunks(vlen);
	ConfigSSA(vlen);
	config::aot_direct_call_fusion = true;
	config::g_elf_exec_ranges.push_back({0u, 0x2000u});
	auto b = Build(WordsJ(), RangesJ());
	auto *src = BlockAt(b.region, 0u);
	CHECK(src != nullptr);
	// It really took the fusion path: no indirect dispatch survives.
	CHECK_EQ(CountOp(b.region, Op::_gbrind), 0u);
	CHECK_EQ(TerminatorOp(src), Op::_gbr);
	auto writes = WriteOffsetsIn(src);
	CHECK_EQ(writes.size(), (size_t)chunks);            // ONE commit
	CHECK_EQ(CountRegWrites(b.region, 1, chunks), chunks); // ...not two
	CHECK_EQ(CountOp(b.region, Op::_rvvfpend), 1u);
	CHECK_EQ(TrailingWritesBeforeTerminator(src), chunks);
	printf("      fused target=0x%x gbr=%u gbrind=0 writes=%zu fpend=%u\n", kFusedTarget,
	       CountOp(b.region, Op::_gbr), writes.size(), CountOp(b.region, Op::_rvvfpend));
	printf("      FINGERPRINT_RESOLVED_JALR_V%u %s\n", vlen, Fingerprint(b.region).c_str());
}

} // namespace

int main()
{
	printf("RVV SSA EDGE-COMMIT INVARIANT\n");
	for (u32 vlen : {512u, 1024u}) {
		printf("\n=== VLEN %u ===\n", vlen);
		Section1_CleanCacheControl(vlen);
		Section2_InRegionUnconditional(vlen);
		Section3_OutOfRegionUnconditional(vlen);
		Section4_InRegionConditionalBothEdges(vlen);
		Section5_MixedConditional(vlen);
		Section6_BothOutOfRegionConditional(vlen);
		Section7_PureQCGUnchanged(vlen);
		Section8_IndirectEdgeDefault(vlen);
		Section9_IndirectGuardedPaths(vlen);
		Section10_IndirectResolvedPath(vlen);
	}
	printf("\nRVV_SSA_EDGE_COMMIT_VERDICT: %s (%u)\n", g_fail ? "FAIL" : "PASS", g_fail);
	return g_fail != 0;
}
