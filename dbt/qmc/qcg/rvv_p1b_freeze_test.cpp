// P1b BYTE-IDENTITY GATE. This file is not a semantic classifier and makes no claim about RVV
// semantics; it is a canonical dump of what the translator produces today, so the P1b refactor can
// be proved to change nothing.
//
// WHAT IT DUMPS, for every (shape, VLEN, policy) cell the accepted P1a suite covers:
//
//   1. the QIR node stream of the whole region, each node as `opcode` plus the FIELDS that carry a
//      decision -- element bases, chunk ordinals, `finish` flags, mask widths, the frame's
//      `n_typed` and the end node's `frame_clears_vstart`. An opcode-only dump would miss a wrong
//      immediate, which is the mistake class this gate exists for;
//   2. the emitted host bytes: length, sha256 and the full hex.
//
// The output is printed to stdout and nowhere else, so the frozen artifact is whatever the runner
// redirected it to. `--summary` prints only the per-cell digests, for a readable report table.
//
// NON-EMPTINESS IS CHECKED HERE, not left to the differ: two empty dumps compare equal. A cell that
// produced no frame, no QIR or no code makes this program exit non-zero.

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
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
int g_failures = 0;

// --- a tiny sha256, so the dump carries its own digest without a dependency -------------------
struct Sha256 {
	u32 h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
		    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
	u8 buf[64];
	u64 len = 0;
	size_t n = 0;
	static u32 ror(u32 x, u32 c) { return (x >> c) | (x << (32 - c)); }
	void block(u8 const *p)
	{
		static constexpr u32 k[64] = {
		    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
		    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
		    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
		    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
		    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
		    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
		    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
		    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
		    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
		    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
		    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};
		u32 w[64];
		for (int i = 0; i < 16; ++i)
			w[i] = ((u32)p[4 * i] << 24) | ((u32)p[4 * i + 1] << 16) |
			       ((u32)p[4 * i + 2] << 8) | (u32)p[4 * i + 3];
		for (int i = 16; i < 64; ++i) {
			u32 const s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
			u32 const s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}
		u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
		for (int i = 0; i < 64; ++i) {
			u32 const S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
			u32 const ch = (e & f) ^ (~e & g);
			u32 const t1 = hh + S1 + ch + k[i] + w[i];
			u32 const S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
			u32 const mj = (a & b) ^ (a & c) ^ (b & c);
			u32 const t2 = S0 + mj;
			hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
		}
		u32 const add[8] = {a, b, c, d, e, f, g, hh};
		for (int i = 0; i < 8; ++i)
			h[i] += add[i];
	}
	void update(void const *data, size_t sz)
	{
		auto const *p = (u8 const *)data;
		len += sz;
		while (sz) {
			size_t const take = std::min(sz, sizeof(buf) - n);
			memcpy(buf + n, p, take);
			n += take; p += take; sz -= take;
			if (n == sizeof(buf)) { block(buf); n = 0; }
		}
	}
	std::string final()
	{
		u64 const bits = len * 8;
		u8 pad = 0x80;
		update(&pad, 1);
		u8 zero = 0;
		while (n != 56)
			update(&zero, 1);
		u8 be[8];
		for (int i = 0; i < 8; ++i)
			be[i] = (u8)(bits >> (56 - 8 * i));
		len -= 8; // the length field is not part of the message
		update(be, 8);
		char out[65];
		for (int i = 0; i < 8; ++i)
			snprintf(out + 8 * i, 9, "%08x", h[i]);
		return std::string(out, 64);
	}
};

std::string Sha256Hex(std::string const &s)
{
	Sha256 x;
	x.update(s.data(), s.size());
	return x.final();
}

// --- the harness, identical in configuration to the accepted P1a suite ------------------------
alignas(4096) u8 g_code_buf[1u << 20];

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("p1b freeze: emitted region exceeds the fixed code buffer");
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
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 f3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 OPIVV = 0u, OPFVV = 1u, OPMVV = 2u, OPFVF = 5u;
constexpr u32 SEW16 = 1u, SEW32 = 2u;
constexpr u32 M1 = 0u, M2 = 1u;
constexpr u32 F6_VADD = 0b000000u, F6_VWADD = 0b110001u;
constexpr u32 F6_VNSRL = 0b101100u, F6_VNCLIP = 0b101111u;
constexpr u32 F6_VFADD = 0b000000u, F6_VFMADD = 0b101000u;
constexpr u32 F6_VXUNARY0 = 0b010010u, F6_VMUNARY0 = 0b010100u;
constexpr u32 F6_VFUNARY0 = 0b010010u, F6_VFUNARY1 = 0b010011u, F6_VFMERGE = 0b010111u;
constexpr u32 EXT_ZVF2 = 6u;

void ApplyEnv(u32 vlen, bool policies_on)
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
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_qcg_full_vl_fast_body = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
	config::rvv_lowering = 1;
}

// Every decision-carrying field of every node type these ten producers can emit. A node type not
// listed prints its opcode alone, which is still enough for the opcode-stream half of the gate.
std::string DumpNode(Inst *ins)
{
	char b[256];
	auto const op = ins->GetOpcode();
	switch (op) {
	case Op::_rvvtypedchunkbegin: {
		auto *n = static_cast<InstRVVTypedChunkBegin *>(ins);
		snprintf(b, sizeof b, "rvvtypedchunkbegin vtype=0x%x vlmax=%u n_typed=%u members=%u guard=%u",
			 n->vtype, n->vlmax, (unsigned)n->n_typed, (unsigned)n->n_members,
			 (unsigned)n->guard_kind);
		return b;
	}
	case Op::_rvvtypedchunkend: {
		auto *n = static_cast<InstRVVTypedChunkEnd *>(ins);
		snprintf(b, sizeof b, "rvvtypedchunkend members=%u frame_clears_vstart=%d whole_regbytes=%u",
			 (unsigned)n->n_members, (int)n->frame_clears_vstart, (unsigned)n->whole_regbytes);
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
			 "vchunkpartialalu op=%u sew=%u chunk=%u chunk_bytes=%u rd=%u rs2=%u rs1=%u "
			 "src1=%u imm=%u archmask=%d masked=%d element_base=%u finish=%d",
			 (unsigned)n->op, (unsigned)n->sew_bytes, (unsigned)n->chunk,
			 (unsigned)n->chunk_bytes, (unsigned)n->rd_offs, (unsigned)n->rs2_offs,
			 (unsigned)n->rs1_offs, (unsigned)n->src1_kind, n->imm,
			 (int)n->architectural_mask, (int)n->masked, n->element_base,
			 (int)n->finish_instruction);
		return b;
	}
	case Op::_vchunknarrowshift: {
		auto *n = static_cast<InstVChunkNarrowShift *>(ins);
		snprintf(b, sizeof b,
			 "vchunknarrowshift rd=%u rs2=%u rs1=%u imm=%u src=%u sew=%u bytes=%u base=%u "
			 "arith=%d masked=%d finish=%d",
			 n->rd, n->rs2, n->rs1, n->imm, (unsigned)n->src, (unsigned)n->sew,
			 (unsigned)n->bytes, n->base, (int)n->arith, (int)n->masked, (int)n->finish);
		return b;
	}
	case Op::_vchunkwiden: {
		auto *n = static_cast<InstVChunkWiden *>(ins);
		snprintf(b, sizeof b,
			 "vchunkwiden op=%u rd=%u rs2=%u rs1=%u sew=%u bytes=%u base=%u scalar=%d "
			 "zero=%d wide2=%d sign2=%d sign1=%d masked=%d finish=%d",
			 (unsigned)n->op, n->rd, n->rs2, n->rs1, (unsigned)n->sew, (unsigned)n->bytes,
			 n->base, (int)n->scalar, (int)n->zero, (int)n->wide2, (int)n->sign2,
			 (int)n->sign1, (int)n->masked, (int)n->finish);
		return b;
	}
	case Op::_vchunkextend: {
		auto *n = static_cast<InstVChunkExtend *>(ins);
		snprintf(b, sizeof b,
			 "vchunkextend rd=%u rs2=%u dst_sew=%u src_sew=%u bytes=%u base=%u sign=%d "
			 "masked=%d finish=%d",
			 n->rd, n->rs2, (unsigned)n->dst_sew, (unsigned)n->src_sew, (unsigned)n->bytes,
			 n->base, (int)n->sign, (int)n->masked, (int)n->finish);
		return b;
	}
	case Op::_vchunkindex: {
		auto *n = static_cast<InstVChunkIndex *>(ins);
		snprintf(b, sizeof b, "vchunkindex rd=%u sew=%u bytes=%u base=%u masked=%d finish=%d",
			 n->rd, (unsigned)n->sew, (unsigned)n->bytes, n->base, (int)n->masked,
			 (int)n->finish);
		return b;
	}
	case Op::_vchunkfclass: {
		auto *n = static_cast<InstVChunkFClass *>(ins);
		snprintf(b, sizeof b, "vchunkfclass rd=%u rs=%u sew=%u bytes=%u base=%u masked=%d finish=%d",
			 n->rd, n->rs, (unsigned)n->sew, (unsigned)n->bytes, n->base, (int)n->masked,
			 (int)n->finish);
		return b;
	}
	case Op::_vchunkftoi: {
		auto *n = static_cast<InstVChunkFToI *>(ins);
		snprintf(b, sizeof b, "vchunkftoi rd=%u rs=%u sew=%u bytes=%u base=%u", n->rd, n->rs,
			 (unsigned)n->sew, (unsigned)n->bytes, n->base);
		return b;
	}
	case Op::_vchunkitof: {
		auto *n = static_cast<InstVChunkIToF *>(ins);
		snprintf(b, sizeof b, "vchunkitof rd=%u rs=%u sew=%u bytes=%u base=%u", n->rd, n->rs,
			 (unsigned)n->sew, (unsigned)n->bytes, n->base);
		return b;
	}
	case Op::_vchunkftof: {
		auto *n = static_cast<InstVChunkFToF *>(ins);
		snprintf(b, sizeof b, "vchunkftof rd=%u rs=%u sew=%u bytes=%u base=%u", n->rd, n->rs,
			 (unsigned)n->sew, (unsigned)n->bytes, n->base);
		return b;
	}
	case Op::_vchunkfalu: {
		auto *n = static_cast<InstVChunkFALU *>(ins);
		snprintf(b, sizeof b, "vchunkfalu sew=%u f6=%u chunk=%u kmask=%u masked=%d",
			 (unsigned)n->sew_bytes, (unsigned)n->funct6, (unsigned)n->chunk,
			 (unsigned)n->kmask, (int)n->masked);
		return b;
	}
	case Op::_vchunkfma: {
		auto *n = static_cast<InstVChunkFMA *>(ins);
		snprintf(b, sizeof b, "vchunkfma sew=%u f6=%u chunk=%u kmask=%u masked=%d",
			 (unsigned)n->sew_bytes, (unsigned)n->funct6, (unsigned)n->chunk,
			 (unsigned)n->kmask, (int)n->masked);
		return b;
	}
	default:
		snprintf(b, sizeof b, "op%u", (unsigned)op);
		return b;
	}
}

struct Shape {
	char const *name;
	u32 vsew, vlmul, op;
};

Shape const kShapes[] = {
    {"vadd.vv     e32,m2", SEW32, M2, MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV)},
    {"vwadd.vv    e16,m1", SEW16, M1, MakeOpV(F6_VWADD, 1, 10, 12, 8, OPMVV)},
    {"vnsrl.wv    e16,m2", SEW16, M2, MakeOpV(F6_VNSRL, 1, 12, 10, 8, OPIVV)},
    {"vnclip.wv   e16,m2", SEW16, M2, MakeOpV(F6_VNCLIP, 1, 12, 10, 8, OPIVV)},
    {"vfadd.vv    e32,m2", SEW32, M2, MakeOpV(F6_VFADD, 1, 10, 12, 8, OPFVV)},
    {"vfmadd.vf   e32,m2", SEW32, M2, MakeOpV(F6_VFMADD, 1, 10, 3, 8, OPFVF)},
    {"vzext.vf2   e32,m2", SEW32, M2, MakeOpV(F6_VXUNARY0, 1, 12, EXT_ZVF2, 8, OPMVV)},
    {"vfmerge.vfm e32,m2", SEW32, M2, MakeOpV(F6_VFMERGE, 0, 10, 3, 8, OPFVF)},
    {"vfclass.v   e32,m2", SEW32, M2, MakeOpV(F6_VFUNARY1, 1, 10, 16, 8, OPFVV)},
    {"vid.v       e32,m2", SEW32, M2, MakeOpV(F6_VMUNARY0, 1, 0, 17, 8, OPMVV)},
    {"vfcvt.x.f.v e32,m2", SEW32, M2, MakeOpV(F6_VFUNARY0, 1, 10, 1, 8, OPFVV)},
};

} // namespace

int main(int argc, char **argv)
{
	bool const summary = argc > 1 && strcmp(argv[1], "--summary") == 0;
	printf("P1B_FREEZE v1\n");
	for (auto const &s : kShapes) {
		for (u32 vlen : {512u, 1024u}) {
			for (bool on : {false, true}) {
				ApplyEnv(vlen, on);
				MemArena arena{1u << 21};
				std::vector<u32> words = {Vsetvli(s.vsew, s.vlmul), s.op};
				CompilerJob::IpRangesSet ranges = {{0u, (u32)words.size() * 4u}};
				CompilerJob job(nullptr, (uptr)words.data(), CodeSegment(0u, 0x1000u),
						std::move(ranges));
				Region *region = CompilerGenRegionIR(&arena, job);

				std::string qir;
				unsigned nodes = 0, frames = 0;
				for (auto &bb : region->GetBlocks())
					for (auto &ins : bb.ilist) {
						qir += DumpNode(&ins);
						qir += '\n';
						++nodes;
						frames += ins.GetOpcode() == Op::_rvvtypedchunkbegin;
					}

				TestCompilerRuntime cr;
				CodeSegment segment(0u, 0x1000u);
				auto const span = qcg::GenerateCode(&cr, &segment, region, 0);
				std::vector<u8> code(span.begin(), span.end());
				while (!code.empty() && code.back() == 0)
					code.pop_back();

				std::string hex;
				hex.reserve(code.size() * 2);
				for (u8 b : code) {
					char t[3];
					snprintf(t, sizeof t, "%02x", b);
					hex += t;
				}

				char cell[128];
				snprintf(cell, sizeof cell, "%s | VLEN %4u | policies %s", s.name, vlen,
					 on ? "ON " : "OFF");

				// Non-emptiness is a gate, not a note: two empty dumps compare equal.
				if (nodes == 0 || frames != 1 || code.empty()) {
					fprintf(stderr,
						"  FAIL %s: nodes=%u frames=%u code=%zu (expected >0, 1, >0)\n",
						cell, nodes, frames, code.size());
					++g_failures;
				}

				std::string const body = qir + "code_len=" + std::to_string(code.size()) +
							 "\ncode=" + hex + "\n";
				printf("=== CELL %s ===\n", cell);
				printf("digest %s  nodes %u  code_len %zu\n", Sha256Hex(body).c_str(),
				       nodes, code.size());
				if (!summary)
					fputs(body.c_str(), stdout);
			}
		}
	}
	if (g_failures) {
		printf("FAILED: %d cell(s)\n", g_failures);
		return 1;
	}
	printf("P1B_FREEZE_OK cells=%zu\n", sizeof(kShapes) / sizeof(kShapes[0]) * 2 * 2);
	return 0;
}
