// P1c FREEZE / GATE. Not a semantic classifier: a canonical dump of what the translator produces,
// so routing every typed-chunk frame through one common close can be proved to change nothing.
//
// COVERAGE IS MEASURED, NOT ASSUMED. Hand-picking one guest word per producer means a wrong
// encoding silently produces no frame and the cell proves nothing. Instead this SWEEPS a structured
// space of guest words (OP-V funct6 x funct3 x vm x a few register triples x several vtypes, plus
// vector load/store major opcodes over width/mop/nf), keeps the FIRST word for each distinct frame
// SIGNATURE -- the multiset of body node opcodes plus the guard kind and member count -- and dumps
// those cells in full. The signature list printed at the end IS the coverage evidence.
//
// Each cell dumps the QIR node stream (opcode plus every decision-carrying field this file knows)
// and the emitted host bytes. Host bytes are the ground truth for node types whose fields this file
// does not spell out.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
alignas(4096) u8 g_code_buf[1u << 20];

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("p1c freeze: emitted region exceeds the fixed code buffer");
		memset(g_code_buf, 0, sz);
		return g_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};

constexpr u32 Vsetvli(u32 vsew, u32 vlmul)
{
	return ((0xc0u | (vsew << 3) | vlmul) << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u;
}

// env 0 = the P1b environment (the ten planner producers).  env 1 = the same plus every other QCG
// typed-chunk route this file can reach, so the remaining producer bodies actually build frames.
void ApplyEnv(u32 vlen, bool policies_on, int env)
{
	config::vlen_bits = vlen;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_vector_run = false;
	config::rvv_run_live_range_split = false;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_active_vl_int_bound = policies_on;
	config::rvv_qcg_active_vl_bound = policies_on;
	config::rvv_qcg_active_vl_widen_bound = policies_on;
	config::rvv_qcg_active_vl_narrow_bound = true;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_fma_force_emit = true;
	config::rvv_qcg_fp_shared_mask = true;
	config::rvv_qcg_narrow_chunk_width = true;
	config::rvv_qcg_narrow_chunk_width_force_emit = true;
	bool const b = env == 1;
	config::rvv_qcg_typed_chunk_sub = b;
	config::rvv_qcg_typed_chunk_mul = b;
	config::rvv_qcg_typed_chunk_xor = b;
	config::rvv_qcg_typed_chunk_or = b;
	config::rvv_qcg_typed_chunk_and = b;
	config::rvv_qcg_typed_chunk_shift = b;
	config::rvv_qcg_typed_chunk_vle = b;
	config::rvv_qcg_typed_chunk_vse = b;
	config::rvv_qcg_typed_chunk_vmv = b;
	config::rvv_qcg_typed_chunk_mem_e64 = b;
	config::rvv_qcg_typed_chunk_vadd_scalar = b;
	config::rvv_qcg_partial_vl = b;
	config::rvv_qcg_whole_reg = b;
	config::rvv_qcg_vx_mulacc = b;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_qcg_full_vl_fast_body = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
	config::rvv_lowering = 1;
}

std::string DumpNode(Inst *ins)
{
	char b[256];
	switch (ins->GetOpcode()) {
	case Op::_rvvtypedchunkbegin: {
		auto *n = static_cast<InstRVVTypedChunkBegin *>(ins);
		snprintf(b, sizeof b, "begin vtype=0x%x vlmax=%u n_typed=%u members=%u guard=%u vlenb=%u",
			 n->vtype, n->vlmax, (unsigned)n->n_typed, (unsigned)n->n_members,
			 (unsigned)n->guard_kind, n->vlenb);
		return b;
	}
	case Op::_rvvtypedchunkend: {
		auto *n = static_cast<InstRVVTypedChunkEnd *>(ins);
		snprintf(b, sizeof b, "end members=%u frame_clears_vstart=%d whole_regbytes=%u raw=0x%x",
			 (unsigned)n->n_members, (int)n->frame_clears_vstart,
			 (unsigned)n->whole_regbytes, n->raw);
		return b;
	}
	case Op::_vchunkactive: {
		auto *n = static_cast<InstVChunkActive *>(ins);
		snprintf(b, sizeof b, "vchunkactive chunk=%u element_base=%u", (unsigned)n->chunk,
			 n->element_base);
		return b;
	}
	case Op::_vchunkmaskset: {
		auto *n = static_cast<InstVChunkMaskSet *>(ins);
		snprintf(b, sizeof b, "vchunkmaskset chunk=%u lanes=%u", (unsigned)n->chunk,
			 (unsigned)n->lanes);
		return b;
	}
	case Op::_vchunkpartialalu: {
		auto *n = static_cast<InstVChunkPartialAlu *>(ins);
		snprintf(b, sizeof b,
			 "vchunkpartialalu op=%u sew=%u chunk=%u cb=%u rd=%u rs2=%u rs1=%u src1=%u "
			 "imm=%u am=%d m=%d base=%u fin=%d",
			 (unsigned)n->op, (unsigned)n->sew_bytes, (unsigned)n->chunk,
			 (unsigned)n->chunk_bytes, (unsigned)n->rd_offs, (unsigned)n->rs2_offs,
			 (unsigned)n->rs1_offs, (unsigned)n->src1_kind, n->imm,
			 (int)n->architectural_mask, (int)n->masked, n->element_base,
			 (int)n->finish_instruction);
		return b;
	}
	case Op::_vchunknarrowshift: {
		auto *n = static_cast<InstVChunkNarrowShift *>(ins);
		snprintf(b, sizeof b, "vchunknarrowshift rd=%u rs2=%u sew=%u bytes=%u base=%u fin=%d",
			 n->rd, n->rs2, (unsigned)n->sew, (unsigned)n->bytes, n->base, (int)n->finish);
		return b;
	}
	case Op::_vchunkwiden: {
		auto *n = static_cast<InstVChunkWiden *>(ins);
		snprintf(b, sizeof b, "vchunkwiden op=%u rd=%u sew=%u bytes=%u base=%u fin=%d",
			 (unsigned)n->op, n->rd, (unsigned)n->sew, (unsigned)n->bytes, n->base,
			 (int)n->finish);
		return b;
	}
	case Op::_vchunkextend: {
		auto *n = static_cast<InstVChunkExtend *>(ins);
		snprintf(b, sizeof b, "vchunkextend rd=%u dsew=%u ssew=%u bytes=%u base=%u fin=%d", n->rd,
			 (unsigned)n->dst_sew, (unsigned)n->src_sew, (unsigned)n->bytes, n->base,
			 (int)n->finish);
		return b;
	}
	case Op::_vchunkindex: {
		auto *n = static_cast<InstVChunkIndex *>(ins);
		snprintf(b, sizeof b, "vchunkindex rd=%u sew=%u bytes=%u base=%u fin=%d", n->rd,
			 (unsigned)n->sew, (unsigned)n->bytes, n->base, (int)n->finish);
		return b;
	}
	case Op::_vchunkfclass: {
		auto *n = static_cast<InstVChunkFClass *>(ins);
		snprintf(b, sizeof b, "vchunkfclass rd=%u sew=%u bytes=%u base=%u fin=%d", n->rd,
			 (unsigned)n->sew, (unsigned)n->bytes, n->base, (int)n->finish);
		return b;
	}
	case Op::_vchunkftoi: {
		auto *n = static_cast<InstVChunkFToI *>(ins);
		snprintf(b, sizeof b, "vchunkftoi rd=%u sew=%u bytes=%u base=%u", n->rd, (unsigned)n->sew,
			 (unsigned)n->bytes, n->base);
		return b;
	}
	case Op::_vchunkitof: {
		auto *n = static_cast<InstVChunkIToF *>(ins);
		snprintf(b, sizeof b, "vchunkitof rd=%u sew=%u bytes=%u base=%u", n->rd, (unsigned)n->sew,
			 (unsigned)n->bytes, n->base);
		return b;
	}
	case Op::_vchunkftof: {
		auto *n = static_cast<InstVChunkFToF *>(ins);
		snprintf(b, sizeof b, "vchunkftof rd=%u sew=%u bytes=%u base=%u", n->rd, (unsigned)n->sew,
			 (unsigned)n->bytes, n->base);
		return b;
	}
	case Op::_vchunkfalu: {
		auto *n = static_cast<InstVChunkFALU *>(ins);
		snprintf(b, sizeof b, "vchunkfalu sew=%u f6=%u chunk=%u kmask=%u m=%d",
			 (unsigned)n->sew_bytes, (unsigned)n->funct6, (unsigned)n->chunk,
			 (unsigned)n->kmask, (int)n->masked);
		return b;
	}
	case Op::_vchunkfma: {
		auto *n = static_cast<InstVChunkFMA *>(ins);
		snprintf(b, sizeof b, "vchunkfma sew=%u f6=%u chunk=%u kmask=%u m=%d",
			 (unsigned)n->sew_bytes, (unsigned)n->funct6, (unsigned)n->chunk,
			 (unsigned)n->kmask, (int)n->masked);
		return b;
	}
	case Op::_vmasklogic: {
		auto *n = static_cast<InstVMaskLogic *>(ins);
		snprintf(b, sizeof b, "vmasklogic op=%u rd=%u rs2=%u rs1=%u base=%u fin=%d",
			 (unsigned)n->op, n->rd, n->rs2, n->rs1, n->base, (int)n->finish);
		return b;
	}
	default:
		snprintf(b, sizeof b, "op%u", (unsigned)ins->GetOpcode());
		return b;
	}
}

struct Cell {
	std::string qir, hex;
	unsigned nodes = 0, frames = 0;
};

bool Build(u32 setup, u32 word, u32 vlen, bool on, int env, Cell *out, std::string *sig)
{
	ApplyEnv(vlen, on, env);
	MemArena arena{1u << 21};
	std::vector<u32> words = {setup, word};
	CompilerJob::IpRangesSet ranges = {{0u, (u32)words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	Region *region = CompilerGenRegionIR(&arena, job);

	std::multiset<int> body;
	std::string guard;
	bool open = false, any = false;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist) {
			out->qir += DumpNode(&ins);
			out->qir += '\n';
			++out->nodes;
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				auto *n = static_cast<InstRVVTypedChunkBegin *>(&ins);
				char t[64];
				snprintf(t, sizeof t, "guard%u/mem%u", (unsigned)n->guard_kind,
					 (unsigned)n->n_members);
				guard = t;
				open = true;
				any = true;
				++out->frames;
			} else if (ins.GetOpcode() == Op::_rvvtypedchunkend) {
				open = false;
			} else if (open) {
				body.insert((int)ins.GetOpcode());
			}
		}
	if (!any)
		return false;
	*sig = guard;
	for (int op : body)
		*sig += ":" + std::to_string(op);

	TestCompilerRuntime cr;
	CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&cr, &segment, region, 0);
	std::vector<u8> code(span.begin(), span.end());
	while (!code.empty() && code.back() == 0)
		code.pop_back();
	out->hex.reserve(code.size() * 2);
	for (u8 x : code) {
		char t[3];
		snprintf(t, sizeof t, "%02x", x);
		out->hex += t;
	}
	return !code.empty();
}

} // namespace

int main()
{
	printf("P1C_FREEZE v1\n");
	// The sweep space. Register triples are chosen aligned so LMUL groups are legal.
	static const u32 kSetups[] = {Vsetvli(0, 0), Vsetvli(1, 0), Vsetvli(2, 0), Vsetvli(2, 1),
				      Vsetvli(3, 1), Vsetvli(1, 1)};
	static const u32 kTriples[][3] = {{10, 12, 8}, {12, 10, 8}, {0, 17, 8}, {10, 3, 8},
					  {10, 16, 8}, {12, 6, 8},  {10, 0, 8}, {10, 1, 8}};
	struct Key {
		std::string sig;
		u32 vlen;
		int on, env;
		bool operator<(Key const &o) const
		{
			return std::tie(sig, vlen, on, env) < std::tie(o.sig, o.vlen, o.on, o.env);
		}
	};
	std::map<Key, std::pair<u32, u32>> chosen; // signature -> (setup, word)

	auto sweep = [&](u32 word) {
		for (u32 setup : kSetups)
			for (u32 vlen : {512u, 1024u})
				for (int on : {0, 1})
					for (int env : {0, 1}) {
						Cell c;
						std::string sig;
						if (!Build(setup, word, vlen, on != 0, env, &c, &sig))
							continue;
						Key k{sig, vlen, on, env};
						if (!chosen.count(k))
							chosen[k] = {setup, word};
					}
	};
	// OP-V (major 0x57): funct6 x funct3 x vm x register triples.
	for (u32 f6 = 0; f6 < 64; ++f6)
		for (u32 f3 : {0u, 1u, 2u, 3u, 5u, 6u})
			for (u32 vm : {0u, 1u})
				for (auto const &t : kTriples)
					sweep((f6 << 26) | (vm << 25) | (t[0] << 20) | (t[1] << 15) |
					      (f3 << 12) | (t[2] << 7) | 0x57u);
	// Vector loads (0x07) and stores (0x27): nf x mop x width x lumop.
	for (u32 major : {0x07u, 0x27u})
		for (u32 nf = 0; nf < 4; ++nf)
			for (u32 mop : {0u, 1u, 2u, 3u})
				for (u32 width : {0u, 5u, 6u, 7u})
					for (u32 lumop : {0u, 8u, 11u, 16u})
						for (u32 vm : {0u, 1u})
							sweep((nf << 29) | (mop << 26) | (vm << 25) |
							      (lumop << 20) | (16u << 15) |
							      (width << 12) | (8u << 7) | major);

	printf("distinct (signature, VLEN, policy, env) cells: %zu\n", chosen.size());
	std::set<std::string> sigs;
	for (auto const &kv : chosen)
		sigs.insert(kv.first.sig);
	printf("distinct frame signatures: %zu\n", sigs.size());
	unsigned n = 0;
	for (auto const &kv : chosen) {
		Cell c;
		std::string sig;
		if (!Build(kv.second.first, kv.second.second, kv.first.vlen, kv.first.on != 0,
			   kv.first.env, &c, &sig))
			continue;
		printf("=== CELL sig=%s setup=0x%08x word=0x%08x VLEN=%u policies=%d env=%d ===\n",
		       kv.first.sig.c_str(), kv.second.first, kv.second.second, kv.first.vlen,
		       kv.first.on, kv.first.env);
		printf("nodes=%u frames=%u code_len=%zu\n", c.nodes, c.frames, c.hex.size() / 2);
		fputs(c.qir.c_str(), stdout);
		printf("code=%s\n", c.hex.c_str());
		++n;
	}
	printf("P1C_FREEZE_OK cells=%u\n", n);
	return n ? 0 : 1;
}
