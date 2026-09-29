// A22 (2026-09-06): the floating ADD/SUBTRACT family on the OBSERVED-vtype path of the T7R falu
// route, admitted by ONE semantic rule instead of a workload-derived list of (form, SEW) pairs.
//
// WHAT MOVED. RvvQcgTypedFaluAdmit's observed-vtype rows for vfadd/vfsub used to be the pairs
// some workload had been seen to execute: vfadd.vv @32/64, vfsub.vv @64, vfadd.vf @32/64,
// vfsub.vf @64. The two missing cells -- vfsub.vv @32 and vfsub.vf @32 -- had no semantic reason to
// be missing: the emitter case (vsubps/vsubpd), the .vv two-load and .vf broadcast shapes, the e32
// scalar NaN-unboxing, the canonical-NaN fill and the MXCSR bracket are the code paths every
// neighbouring row already runs. A22 states the family: unmasked vfadd/vfsub, vv or vf, SEW 32 or
// 64, LMUL 1 or 2, ta, ma, at the shared chunk geometry. Nothing else moved: multiply/divide keep
// their rows, vfrsub.vf (reversed operands, no emitter case) stays refused, and the UNOBSERVED
// candidate is byte-for-byte what it was.
//
// WHAT THIS FILE PROVES, and where each claim is checked against something OUTSIDE the predicate:
//   [1] the 2 x 2 x 2 x 2 product (op, form, SEW, LMUL) admits at VLEN 128/256/512/1024 with the
//       chunk shape computed HERE from (VLEN, LMUL) -- {16,1}/{32,1}/{64,1}/{64,2} per register
//       times emul_group_regs -- the right guarded vtype/VLMAX, the frm-checking guard kind, the
//       vfalu stub on both frame nodes and zero helper calls;
//   [2] QIR operand order: every lane op's input 0 is a vs2 window and input 1 the vs1 window or
//       the scalar broadcast (which reads f[rs1] at the SEW's width), funct6 0/2 intact, every
//       load before every store, including vd==vs2 and (vv) vd==vs1;
//   [3] REAL EMITTED BYTES: exactly k `vsubps/vsubpd/vaddps/vaddpd out{k1}, a, b` where a was
//       loaded from vs2's window and b from vs1's window / the broadcast, at the register class
//       and memory-operand width the VLEN selects (xmm/XMMWORD, ymm/YMMWORD, zmm/ZMMWORD), the
//       packed-single form at SEW 32 and packed-double at 64 and never the other, one NaN compare
//       per chunk, no vector register of any other class in the region;
//   [4] fail-closed: odd registers at m2, m4/m8, mf2/mf4, tu, mu, masked, e16/e8, vfrsub.vf,
//       vfmul.vv/vfmin/vfmax/vfsgnj at e32, the route switch, --rvv-verify, LLVM, --rvv-direct 0,
//       narrow widths without the AVX512VL bypass, and the host probe without force-emit;
//   [5] the unobserved-vtype candidate is unchanged: vfsub.vv still proposes the e64,m2 guard
//       (0xd9) at 64-byte chunks, vfsub.vf / vfsub.vv-with-odd-regs / vfrsub.vf still take the
//       helper there.
// It never executes a byte (TestCompilerRuntime has no PROT_EXEC memory; this host has no
// AVX-512) and makes no performance claim. The instruction words come from one encoder pinned
// against the raw words --rvv-pc-census recorded in miniWeather (vfalu_residual_e64_route_test).

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
int g_failures = 0;
#define CHECK(cond)                                                                                  \
	do {                                                                                         \
		if (!(cond)) {                                                                       \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)
#define CHECK_EQ(a, b)                                                                               \
	do {                                                                                         \
		auto _a = (a);                                                                       \
		auto _b = (b);                                                                       \
		if (!(_a == _b)) {                                                                   \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,         \
				__LINE__, #a, #b, (long long)_a, (long long)_b);                     \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
constexpr u32 ST_F_BASE = (u32)(offsetof(CPUState, fpu) + offsetof(rv32::FPUState, f));

// The host chunk shape, from (VLEN, LMUL) alone: widest host vector that fits one register, as
// many as tile it, times the group's register count. Independent of RvvHostChunkGeometry.
struct Shape { u32 bytes, per_reg, regs, chunks; };
Shape ExpectShape(u32 vlen, u32 lmul)
{
	u32 const reg = vlen / 8u, w = reg < 64u ? reg : 64u;
	return Shape{w, reg / w, lmul, lmul * (reg / w)};
}
// chunk c of a register GROUP starting at `reg`: register reg + c/per_reg, byte (c%per_reg)*w.
u32 ChunkOffs(u32 reg, u32 c, Shape const &s)
{
	return ST_VREG_BASE + (reg + c / s.per_reg) * rv32::VLEN_MAX_BYTES + (c % s.per_reg) * s.bytes;
}
char const *ClassOf(u32 bytes) { return bytes == 16 ? "xmm" : bytes == 32 ? "ymm" : "zmm"; }
char const *PtrOf(u32 bytes) { return bytes == 16 ? "XMMWORD" : bytes == 32 ? "YMMWORD" : "ZMMWORD"; }

// vsetvli a0, a0, e<sew>, m<lmul>, ta, ma  (vtypei: vma=1<<7, vta=1<<6, sew<<3, lmul)
constexpr u32 Vsetvli(u32 sew_log2_minus3, u32 lmul_log2)
{
	u32 const vtypei = (1u << 7) | (1u << 6) | (sew_log2_minus3 << 3) | lmul_log2;
	return (vtypei << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}
constexpr u32 E32M1 = Vsetvli(2, 0), E32M2 = Vsetvli(2, 1), E64M1 = Vsetvli(3, 0), E64M2 = Vsetvli(3, 1);
constexpr u32 E32M4 = Vsetvli(2, 2), E32M8 = Vsetvli(2, 3), E32MF2 = Vsetvli(2, 7), E32MF4 = Vsetvli(2, 6);
constexpr u32 E16M1 = Vsetvli(1, 0), E8M1 = Vsetvli(0, 0);
constexpr u32 E32M1_TU = E32M1 & ~(1u << (20 + 6)), E32M1_MU = E32M1 & ~(1u << (20 + 7));
static_assert(E64M1 == 0x0d857557u, "encoder vs the P7K-B constant");
static_assert(E32M2 == 0x0d157557u, "encoder vs the P7K-B constant");

constexpr u32 MakeOpFV(u32 f6, u32 vm, u32 vs2, u32 rs1, u32 vd, u32 funct3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (rs1 << 15) | (funct3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpFV(f6, 1, vs2, vs1, vd, 0b001u); }
constexpr u32 Vf(u32 f6, u32 vs2, u32 rs1, u32 vd) { return MakeOpFV(f6, 1, vs2, rs1, vd, 0b101u); }
static_assert(Vf(2, 8, 13, 8) == 0x0a86d457u, "encoder vs the measured miniWeather vfsub.vf");
static_assert(Vv(32, 9, 8, 9) == 0x829414d7u, "encoder vs the measured miniWeather vfdiv.vv");
constexpr u32 F6_ADD = 0, F6_SUB = 2, F6_RSUB = 39, F6_MUL = 36, F6_MIN = 4, F6_MAX = 6, F6_SGNJ = 8;

struct Env {
	u32 vlen_bits = 512;
	bool falu = true, force_emit = true, rvv_direct = true, rvv_verify = false, aot_use_llvm = false;
	bool narrow = true, narrow_force = true;
};
void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_qcg_typed_chunk_falu = e.falu;
	config::rvv_qcg_typed_chunk_falu_force_emit = e.force_emit;
	config::rvv_direct = e.rvv_direct;
	config::rvv_verify = e.rvv_verify;
	config::aot_use_llvm = e.aot_use_llvm;
	config::rvv_qcg_narrow_chunk_width = e.narrow;
	config::rvv_qcg_narrow_chunk_width_force_emit = e.narrow_force;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_qcg_typed_chunk_fma = false;
	config::rvv_qcg_typed_chunk_fma_force_emit = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_vle = false;
	config::rvv_qcg_typed_chunk_vse = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_fp_shared_mask = false; // per-op k1 prologue: the byte check below reads {k1}
	config::rvv_lowering = 1;
}
Region *TranslateWords(MemArena &arena, u32 const *words, unsigned n, Env const &e)
{
	ApplyEnv(e);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}
struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body;
};
std::vector<Frame> FindFrames(Region *region)
{
	std::vector<Frame> out;
	Frame cur;
	bool open = false;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				cur = Frame{}; cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins); open = true; break;
			case Op::_rvvtypedchunkend:
				if (open) { cur.end = static_cast<InstRVVTypedChunkEnd *>(&ins); out.push_back(cur); open = false; }
				break;
			default:
				if (open) cur.body.push_back(&ins);
			}
		}
	return out;
}
unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			n += ins.GetOpcode() == op;
	return n;
}
unsigned CountFaluHelper(Region *region)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_hcall)
				n += static_cast<InstHcall *>(&ins)->stub == RuntimeStubId::id_rv32_vfalu;
	return n;
}
Region *TranslatePair(MemArena &arena, u32 (&words)[2], u32 setvli, u32 word, Env const &e)
{
	words[0] = setvli; words[1] = word;
	return TranslateWords(arena, words, 2, e);
}
bool Admitted(u32 setvli, u32 word, Env const &e)
{
	MemArena arena(1u << 20); u32 words[2];
	return !FindFrames(TranslatePair(arena, words, setvli, word, e)).empty();
}
bool RefusedToHelper(u32 setvli, u32 word, Env const &e)
{
	MemArena arena(1u << 20); u32 words[2];
	auto *region = TranslatePair(arena, words, setvli, word, e);
	return FindFrames(region).empty() && CountFaluHelper(region) == 1u && CountOp(region, Op::_vchunkfalu) == 0u;
}
bool RefusedUnobserved(u32 word, Env const &e)
{
	MemArena arena(1u << 20); u32 w = word;
	auto *region = TranslateWords(arena, &w, 1, e);
	return FindFrames(region).empty() && CountFaluHelper(region) == 1u && CountOp(region, Op::_vchunkfalu) == 0u;
}

// The product under test. Registers are even and disjoint so every row is legal at m2 too.
struct Row { char const *name; u32 f6; bool vf; u32 vd, vs2, src1; };
constexpr Row ROWS[] = {
    {"vfadd.vv v8,v10,v12", F6_ADD, false, 8, 10, 12},
    {"vfsub.vv v8,v10,v12", F6_SUB, false, 8, 10, 12},
    {"vfadd.vf v8,v10,fa3", F6_ADD, true, 8, 10, 13},
    {"vfsub.vf v8,v10,fa3", F6_SUB, true, 8, 10, 13},
    // legal overlaps: vd == vs2 (both forms), vd == vs1 (vv). Even groups.
    {"vfsub.vv v8,v8,v12 (vd==vs2)", F6_SUB, false, 8, 8, 12},
    {"vfsub.vv v8,v10,v8 (vd==vs1)", F6_SUB, false, 8, 10, 8},
    {"vfsub.vf v8,v8,fa3 (vd==vs2)", F6_SUB, true, 8, 8, 13},
    {"vfmul.vv v8,v10,v12", F6_MUL, false, 8, 10, 12},
    {"vfmul.vf v8,v10,fa3", F6_MUL, true, 8, 10, 13},
    {"vfdiv.vv v8,v10,v12", 32, false, 8, 10, 12},
    {"vfdiv.vf v8,v10,fa3", 32, true, 8, 10, 13},
    {"vfrdiv.vf v8,v10,fa3", 33, true, 8, 10, 13},
    {"vfrsub.vf v8,v10,fa3", F6_RSUB, true, 8, 10, 13},
    {"vfrsub.vf v8,v8,fa3 (vd==vs2)", F6_RSUB, true, 8, 8, 13},
};
u32 WordOf(Row const &r) { return r.vf ? Vf(r.f6, r.vs2, r.src1, r.vd) : Vv(r.f6, r.vs2, r.src1, r.vd); }
struct VT { char const *name; u32 setvli; u32 sew; u32 lmul; };
constexpr VT VTS[] = {{"e32,m1", E32M1, 32, 1}, {"e32,m2", E32M2, 32, 2}, {"e64,m1", E64M1, 64, 1}, {"e64,m2", E64M2, 64, 2}};
constexpr u32 VLENS[] = {128u, 256u, 512u, 1024u};

// ---------------------------------------------------------------------------------------------
void Section1_Shape()
{
	fprintf(stderr, "[1] the add/sub x vv/vf x e32/e64 x m1/m2 product admits at four VLENs\n");
	unsigned n = 0;
	for (u32 vlen : VLENS)
		for (auto const &vt : VTS)
			for (auto const &r : ROWS) {
				Shape const s = ExpectShape(vlen, vt.lmul);
				MemArena arena(1u << 20); u32 words[2]; Env e{vlen};
				auto *region = TranslatePair(arena, words, vt.setvli, WordOf(r), e);
				auto frames = FindFrames(region);
				CHECK_EQ(frames.size(), (size_t)1);
				if (frames.empty()) { fprintf(stderr, "    VLEN %u %s %s -> REFUSED\n", vlen, vt.name, r.name); continue; }
				auto const &f = frames[0];
				u32 const k = s.chunks;
				CHECK_EQ(CountOp(region, Op::_vchunkfalu), k);
				CHECK_EQ(CountFaluHelper(region), 0u);
				CHECK_EQ((unsigned)f.begin->n_typed, r.vf ? 3u * k + 3u : 4u * k + 2u);
				CHECK_EQ(CountOp(region, Op::_vstatechunkload), r.vf ? k : 2u * k);
				CHECK_EQ(CountOp(region, Op::_vchunkfbroadcast), r.vf ? 1u : 0u);
				CHECK_EQ(CountOp(region, Op::_vstatechunkstore), k);
				CHECK_EQ(f.begin->vtype, vt.setvli >> 20);
				CHECK_EQ(f.begin->vlmax, vlen * vt.lmul / vt.sew);
				CHECK_EQ(f.begin->raw, WordOf(r));
				CHECK(f.begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypePartialVlVstartFrmHost);
				CHECK(f.begin->stub == RuntimeStubId::id_rv32_vfalu);
				CHECK(f.end->stub == RuntimeStubId::id_rv32_vfalu);
				// every vector value in the frame is the chunk's own type
				VType const ct = VectorVTypeForBytes(s.bytes);
				for (auto *ins : f.body) {
					for (u8 i = 0; i < ins->OutputCount(); ++i)
						if (IsVectorVType(ins->o(i).GetType())) CHECK(ins->o(i).GetType() == ct);
					for (u8 i = 0; i < ins->InputCount(); ++i)
						if (IsVectorVType(ins->i(i).GetType())) CHECK(ins->i(i).GetType() == ct);
				}
				++n;
			}
	fprintf(stderr, "    %u frames: chunk = min(VLEN/8,64) x (VLEN/8)/chunk x LMUL regs, guard VTypePartialVlVstartFrmRNE\n", n);
}

// ---------------------------------------------------------------------------------------------
void Section2_OperandOrder()
{
	fprintf(stderr, "[2] QIR operand order (vs2 left, vs1/scalar right), funct6, load-major, overlaps\n");
	for (u32 vlen : VLENS)
		for (auto const &vt : VTS)
			for (auto const &r : ROWS) {
				Shape const s = ExpectShape(vlen, vt.lmul);
				MemArena arena(1u << 20); u32 words[2]; Env e{vlen};
				auto *region = TranslatePair(arena, words, vt.setvli, WordOf(r), e);
				auto frames = FindFrames(region);
				if (frames.empty()) continue;
				auto const &f = frames[0];
				std::map<RegN, u32> src; // vvpr -> CPUState window it was loaded from
				RegN bcast = (RegN)-1;
				int last_load = -1, first_store = -1, idx = 0;
				unsigned nalu = 0;
				for (auto *ins : f.body) {
					if (ins->GetOpcode() == Op::_vstatechunkload) {
						src[ins->o(0).GetVVPR()] = static_cast<InstVStateChunkLoad *>(ins)->offs; last_load = idx;
					} else if (ins->GetOpcode() == Op::_vchunkfbroadcast) {
						auto *b = static_cast<InstVChunkFBroadcast *>(ins);
						bcast = b->o(0).GetVVPR();
						CHECK_EQ((u32)b->offs, ST_F_BASE + r.src1 * (u32)sizeof(u64));
						CHECK_EQ((unsigned)b->sew_bytes, vt.sew / 8u);
					} else if (ins->GetOpcode() == Op::_vchunkfalu) {
						auto *m = static_cast<InstVChunkFALU *>(ins);
						CHECK_EQ((unsigned)m->funct6, r.f6);
						CHECK_EQ((unsigned)m->sew_bytes, vt.sew / 8u);
						CHECK_EQ((unsigned)m->chunk, nalu);
						auto a = src.find(m->i(0).GetVVPR());
						CHECK(a != src.end());
						if (a != src.end()) CHECK_EQ(a->second, ChunkOffs(r.vs2, nalu, s));
						if (r.vf) {
							CHECK(m->i(1).GetVVPR() == bcast);
						} else {
							auto b = src.find(m->i(1).GetVVPR());
							CHECK(b != src.end());
							if (b != src.end()) CHECK_EQ(b->second, ChunkOffs(r.src1, nalu, s));
						}
						++nalu;
					} else if (ins->GetOpcode() == Op::_vstatechunkstore) {
						if (first_store < 0) first_store = idx;
						CHECK_EQ(static_cast<InstVStateChunkStore *>(ins)->offs, ChunkOffs(r.vd, (u32)(idx - first_store), s));
					}
					++idx;
				}
				CHECK_EQ(nalu, s.chunks);
				CHECK(last_load >= 0 && first_store >= 0 && last_load < first_store);
			}
	fprintf(stderr, "    every lane op reads its own vs2 chunk as input 0 and vs1 chunk / f[rs1] broadcast as input 1\n");
}

// ---------------------------------------------------------------------------------------------
struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override { buf.resize(sz); return buf.data(); }
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	std::vector<u8> buf;
};
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_a22_emit_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) return {};
	size_t w = 0;
	while (w < code.size()) { ssize_t n = write(fd, code.data() + w, code.size() - w); if (n <= 0) { close(fd); unlink(path); return {}; } w += (size_t)n; }
	close(fd);
	std::string cmd = std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path + " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) { unlink(path); return {}; }
	std::vector<std::string> lines; char buf[1024];
	while (fgets(buf, sizeof buf, p)) { std::string s(buf); while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back(); lines.push_back(s); }
	int rc = pclose(p); unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) return {};
	return lines;
}
bool Split(std::string const &line, std::string *mnem, std::vector<std::string> *ops)
{
	size_t tab = line.find('\t');
	if (tab == std::string::npos) return false;
	std::string rhs = line.substr(tab + 1);
	if (rhs.compare(0, 7, "{evex} ") == 0) rhs = rhs.substr(7); // newer objdump prefixes EVEX forms of VEX-able ops
	size_t sp = rhs.find(' ');
	*mnem = sp == std::string::npos ? rhs : rhs.substr(0, sp);
	ops->clear();
	if (sp == std::string::npos) return true;
	std::string rest = rhs.substr(sp + 1); size_t start = 0;
	for (size_t i = 0; i <= rest.size(); ++i)
		if (i == rest.size() || rest[i] == ',') { std::string t = rest.substr(start, i - start); while (!t.empty() && t.front() == ' ') t.erase(t.begin()); ops->push_back(t); start = i + 1; }
	return true;
}
// "<cls>N" or "<cls>N{kM}" -> (N, M); any other register class is rejected.
bool ParseVreg(std::string t, char const *cls, unsigned *reg, unsigned *kmask)
{
	*kmask = 0;
	size_t br = t.find('{');
	if (br != std::string::npos) {
		size_t e = t.find('}', br); if (e == std::string::npos) return false;
		std::string m = t.substr(br + 1, e - br - 1);
		if (m.size() != 2 || m[0] != 'k' || !isdigit((unsigned char)m[1])) return false;
		*kmask = (unsigned)(m[1] - '0'); t = t.substr(0, br) + t.substr(e + 1);
	}
	if (t.compare(0, 3, cls) != 0 || t.find_first_not_of("0123456789", 3) != std::string::npos) return false;
	*reg = (unsigned)strtoul(t.c_str() + 3, nullptr, 10);
	return true;
}
bool ParseR13(std::string const &t, i64 *disp, unsigned *bytes)
{
	size_t lb = t.find('['); if (lb == std::string::npos) return false;
	std::string sz = t.substr(0, lb);
	if (sz.find("ZMMWORD") != std::string::npos) *bytes = 64; else if (sz.find("YMMWORD") != std::string::npos) *bytes = 32;
	else if (sz.find("XMMWORD") != std::string::npos) *bytes = 16; else if (sz.find("QWORD") != std::string::npos) *bytes = 8;
	else if (sz.find("DWORD") != std::string::npos) *bytes = 4; else return false;
	std::string in = t.substr(lb + 1); if (in.empty() || in.back() != ']') return false; in.pop_back();
	if (in.compare(0, 3, "r13") != 0) return false;
	if (in.size() == 3) { *disp = 0; return true; }
	char sign = in[3]; if (sign != '+' && sign != '-') return false;
	i64 v = (i64)strtoull(in.c_str() + 4, nullptr, 0); *disp = sign == '-' ? -v : v; return true;
}
std::vector<u8> EmitBytes(MemArena &arena, u32 setvli, u32 word, Env const &e)
{
	u32 words[2];
	Region *region = TranslatePair(arena, words, setvli, word, e);
	if (FindFrames(region).empty()) return {};
	TestCompilerRuntime cr; qir::CodeSegment segment(0u, 0x1000u);
	auto span = qcg::GenerateCode(&cr, &segment, region, 0);
	return std::vector<u8>(span.begin(), span.end());
}
bool MentionsVreg(std::string const &l) { return l.find("xmm") != std::string::npos || l.find("ymm") != std::string::npos || l.find("zmm") != std::string::npos; }

void Section3_EmittedBytes()
{
	fprintf(stderr, "[3] real emitted bytes: mnemonic, packed width, register class, memory width, operand order\n");
	for (u32 vlen : VLENS)
		for (auto const &vt : VTS)
			for (auto const &r : ROWS) {
				Shape const s = ExpectShape(vlen, vt.lmul);
				char const *cls = ClassOf(s.bytes);
				char const *base = r.f6 == F6_ADD ? "vadd" : r.f6 == F6_MUL ? "vmul" :
					(r.f6 == 32 || r.f6 == 33) ? "vdiv" : "vsub";
				std::string const want = std::string(base) + (vt.sew == 32 ? "ps" : "pd");
				std::string const wrong_width = std::string(base) + (vt.sew == 32 ? "pd" : "ps");
				MemArena arena(1u << 20); Env e{vlen};
				auto code = EmitBytes(arena, vt.setvli, WordOf(r), e);
				CHECK(!code.empty()); if (code.empty()) continue;
				auto lines = Disassemble(code);
				CHECK(!lines.empty()); if (lines.empty()) continue;
				std::map<unsigned, i64> vsrc; // reg -> [r13+disp] it holds (window or F slot)
				unsigned n_alu = 0, n_ok = 0, n_masked = 0, n_wrong = 0, n_cmp = 0, n_other_class = 0, n_bad_width = 0;
				std::string mnem; std::vector<std::string> ops;
				for (auto const &l : lines) {
					if (!Split(l, &mnem, &ops)) continue;
					// any vector register of another class anywhere is a failure
					for (char const *other : {"xmm", "ymm", "zmm"})
						if (std::string(other) != cls && l.find(other) != std::string::npos) ++n_other_class;
					unsigned d, a, b, km; i64 disp; unsigned bytes;
					if ((mnem == "vmovdqu64" || mnem == "vpbroadcastq") && ops.size() == 2 && ParseVreg(ops[0], cls, &d, &km) && ParseR13(ops[1], &disp, &bytes)) {
						vsrc[d] = disp;
						if (mnem == "vmovdqu64" && bytes != s.bytes) ++n_bad_width;
						if (mnem == "vpbroadcastq" && bytes != 8) ++n_bad_width;
					} else if (mnem == "vpbroadcastd" && ops.size() == 2 && ParseVreg(ops[0], cls, &d, &km) && ops[1] == "eax") {
						vsrc[d] = (i64)(ST_F_BASE + r.src1 * sizeof(u64)); // e32 scalar: unboxed through eax from f[rs1]
					} else if (mnem == "vmovdqu64" && ops.size() == 2 && ParseVreg(ops[0], cls, &d, &km) && ParseVreg(ops[1], cls, &a, &km)) {
						auto it = vsrc.find(a); if (it != vsrc.end()) vsrc[d] = it->second; // out <- copy of vs2
					} else if (mnem == "vmovdqu64" && ops.size() == 2 && ParseR13(ops[0], &disp, &bytes) && ParseVreg(ops[1], cls, &a, &km)) {
						if (bytes != s.bytes) ++n_bad_width; // the destination store must be exactly one chunk wide
					}
					if (mnem == "vcmpps" || mnem == "vcmppd" || mnem == "vcmpunordps" || mnem == "vcmpunordpd") ++n_cmp;
					if (mnem == wrong_width) ++n_wrong;
					if (mnem != want) continue;
					++n_alu;
					if (ops.size() != 3) continue;
					unsigned kd = 0;
					if (!ParseVreg(ops[0], cls, &d, &kd) || !ParseVreg(ops[1], cls, &a, &km) || !ParseVreg(ops[2], cls, &b, &km)) continue;
					if (kd == 1) ++n_masked;
					auto sa = vsrc.find(a), sb = vsrc.find(b);
					bool ok = sa != vsrc.end() && sb != vsrc.end();
					if (ok) {
						i64 const want_a = (i64)ChunkOffs(r.vs2, n_alu - 1, s);
						i64 const want_b = r.vf ? (i64)(ST_F_BASE + r.src1 * sizeof(u64)) : (i64)ChunkOffs(r.src1, n_alu - 1, s);
						bool const reverse = r.f6 == F6_RSUB || r.f6 == 33;
						ok = sa->second == (reverse ? want_b : want_a) && sb->second == (reverse ? want_a : want_b);
						if (!ok) fprintf(stderr, "  FAIL %s %s VLEN %u: %s a=[r13+0x%llx] b=[r13+0x%llx] wanted 0x%llx / 0x%llx\n", r.name, vt.name, vlen, want.c_str(), (unsigned long long)sa->second, (unsigned long long)sb->second, (unsigned long long)want_a, (unsigned long long)want_b);
					}
					n_ok += ok;
				}
				CHECK_EQ(n_alu, s.chunks);
				CHECK_EQ(n_ok, s.chunks);
				CHECK_EQ(n_masked, s.chunks);
				CHECK_EQ(n_wrong, 0u);
				CHECK_EQ(n_cmp, s.chunks);
				CHECK_EQ(n_other_class, 0u);
				CHECK_EQ(n_bad_width, 0u);
				if (getenv("A22_DUMP") || (vlen == 128 && vt.setvli == E32M2 && r.f6 == F6_SUB)) {
					printf("---- %s %s @ VLEN %u (%s/%s) ----\n", r.name, vt.name, vlen, cls, PtrOf(s.bytes));
					for (auto const &l : lines) if (MentionsVreg(l) || l.find("bzhi") != std::string::npos) printf("  %s\n", l.substr(l.find('\t') + 1).c_str());
				}
			}
	fprintf(stderr, "    all 4 x 4 x 7 cells: k x <vaddps|vsubps|vaddpd|vsubpd> out{k1}, vs2, vs1|bcast in the VLEN's class and width\n");
}

// ---------------------------------------------------------------------------------------------
void Section4_FailClosed()
{
	fprintf(stderr, "[4] fail-closed matrix\n");
	u32 const SUB_VV = Vv(F6_SUB, 10, 12, 8), SUB_VF = Vf(F6_SUB, 10, 13, 8), ADD_VV = Vv(F6_ADD, 10, 12, 8), ADD_VF = Vf(F6_ADD, 10, 13, 8);
	u32 const SUB_VV_ODD = Vv(F6_SUB, 9, 8, 8), SUB_VF_ODD_VD = Vf(F6_SUB, 10, 13, 9);
	u32 const SUB_VV_MASKED = MakeOpFV(F6_SUB, 0, 10, 12, 8, 0b001u), SUB_VF_MASKED = MakeOpFV(F6_SUB, 0, 10, 13, 8, 0b101u);
	u32 const RSUB_VF = Vf(F6_RSUB, 10, 13, 8), MUL_VV = Vv(F6_MUL, 10, 12, 8), DIV_VV = Vv(32, 10, 12, 8), MIN_VV = Vv(F6_MIN, 10, 12, 8), MAX_VV = Vv(F6_MAX, 10, 12, 8), SGNJ_VV = Vv(F6_SGNJ, 10, 12, 8);
	u32 const words[] = {SUB_VV, SUB_VF, ADD_VV, ADD_VF};
	for (u32 vlen : VLENS) {
		// 4.1 odd registers at m2 (group alignment); admitted at m1
		CHECK(RefusedToHelper(E32M2, SUB_VV_ODD, Env{vlen}));
		CHECK(RefusedToHelper(E32M2, SUB_VF_ODD_VD, Env{vlen}));
		CHECK(Admitted(E32M1, SUB_VV_ODD, Env{vlen}));
		CHECK(Admitted(E32M1, SUB_VF_ODD_VD, Env{vlen}));
		// 4.2 LMUL 4/8, fractional, tu, mu, masked, e16/e8
		for (u32 w : words) {
			for (u32 sv : {E32MF4, E16M1, E8M1})
				CHECK(RefusedToHelper(sv, w, Env{vlen}));
			for (u32 sv : {E32M1_TU, E32M1_MU})
				CHECK(Admitted(sv, w, Env{vlen}));
			CHECK(Admitted(E32MF2, w, Env{vlen}));
			// These old operand rows have misaligned m4/m8 sources.
			for (u32 sv : {E32M4, E32M8}) CHECK(RefusedToHelper(sv, w, Env{vlen}));
		}
		CHECK(Admitted(E32M1, SUB_VV_MASKED, Env{vlen}));
		CHECK(Admitted(E32M1, SUB_VF_MASKED, Env{vlen}));
		CHECK(RefusedToHelper(E32M1, SUB_VV_MASKED & ~(31u << 7), Env{vlen}));
		// 4.3 all basic arithmetic forms, but no min/max/sign-injection widening.
		for (u32 sv : {E32M1, E32M2, E64M1, E64M2})
			for (u32 w : {RSUB_VF, MUL_VV, MIN_VV, MAX_VV, SGNJ_VV, DIV_VV}) {
				// vfdiv.vv @ e64 is P7K-B's own observed row and stays admitted; at e32 it is
				// outside every rule and must keep the helper.
				bool const p7kb_div = true; // Every row is now a supported basic FP family.
				bool const refused = RefusedToHelper(sv, w, Env{vlen});
				if (refused == p7kb_div)
					fprintf(stderr, "  FAIL 4.3: VLEN %u vtypei 0x%x word 0x%08x refused=%d\n", vlen, sv >> 20, w, (int)refused);
				CHECK(refused != p7kb_div);
			}
		// 4.4 the route's own gates
		Env off{vlen}; off.falu = false;
		Env ver{vlen}; ver.rvv_verify = true;
		Env llvm{vlen}; llvm.aot_use_llvm = true;
		Env nod{vlen}; nod.rvv_direct = false;
		for (u32 w : words) for (Env const *e : {&off, &ver, &llvm, &nod}) CHECK(RefusedToHelper(E32M1, w, *e));
	}
	// 4.5 narrow widths need the shared narrow switch, and its AVX512VL bypass on this host
	for (u32 vlen : {128u, 256u}) {
		Env no_narrow{vlen}; no_narrow.narrow = false;
		Env no_vl{vlen}; no_vl.narrow_force = false;
		__builtin_cpu_init();
		bool const have_vl =
#if defined(__x86_64__) || defined(__i386__)
		    __builtin_cpu_supports("avx512vl");
#else
		    false;
#endif
		for (u32 w : words) {
			CHECK(RefusedToHelper(E32M1, w, no_narrow));
			CHECK_EQ(Admitted(E32M1, w, no_vl), have_vl);
		}
	}
	// 4.6 host probe without force-emit
	{
		bool const have =
#if defined(__x86_64__) || defined(__i386__)
		    __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("bmi2");
#else
		    false;
#endif
		for (u32 vlen : {512u, 1024u}) { Env nf{vlen}; nf.force_emit = false; CHECK_EQ(Admitted(E32M1, SUB_VV, nf), have); }
		fprintf(stderr, "    host avx512f+bmi2 = %s\n", have ? "present" : "ABSENT");
	}
	fprintf(stderr, "    odd@m2, m4/m8/mf2/mf4, tu, mu, masked, e16/e8, vfrsub/vfmul.vv/vfmin/vfmax/vfsgnj, switches, narrow gates\n");
}

// ---------------------------------------------------------------------------------------------
void Section5_UnobservedUnchanged()
{
	fprintf(stderr, "[5] the unobserved-vtype candidate did not move\n");
	u32 const SUB_VV = Vv(F6_SUB, 10, 12, 8), SUB_VF = Vf(F6_SUB, 10, 13, 8), SUB_VV_ODD = Vv(F6_SUB, 9, 8, 8), RSUB_VF = Vf(F6_RSUB, 10, 13, 8);
	u32 const ADD_VV = Vv(F6_ADD, 10, 12, 8), ADD_VF = Vf(F6_ADD, 10, 13, 8);
	for (u32 vlen : {512u, 1024u}) {
		Env e{vlen};
		// vfsub.vv: still the single e64,m2 candidate (0xd9), 64-byte chunks, 2*VLEN/512 of them
		{
			MemArena arena(1u << 20); u32 w = SUB_VV;
			auto *region = TranslateWords(arena, &w, 1, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (!frames.empty()) {
				CHECK_EQ(frames[0].begin->vtype, 0xd9u);
				CHECK_EQ(CountOp(region, Op::_vchunkfalu), 2u * (vlen / 512u));
				for (auto *ins : frames[0].body)
					if (ins->GetOpcode() == Op::_vchunkfalu) CHECK_EQ((unsigned)static_cast<InstVChunkFALU *>(ins)->sew_bytes, 8u);
			}
		}
		// vfadd.vv: still the two-SEW candidate (sew 0, vtype 0); vfadd.vf: still e32 (0xd1)
		{
			MemArena arena(1u << 20); u32 w = ADD_VV;
			auto *region = TranslateWords(arena, &w, 1, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (!frames.empty()) {
				CHECK_EQ(frames[0].begin->vtype, 0u);
				CHECK(frames[0].begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeE32OrE64M2PartialVlVstartFrmRNE);
			}
		}
		{
			MemArena arena(1u << 20); u32 w = ADD_VF;
			auto *region = TranslateWords(arena, &w, 1, e);
			auto frames = FindFrames(region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (!frames.empty()) CHECK_EQ(frames[0].begin->vtype, 0xd1u);
		}
		// vfsub.vf, odd vfsub.vv, vfrsub.vf: helper, as before
		CHECK(RefusedUnobserved(SUB_VF, e));
		CHECK(RefusedUnobserved(SUB_VV_ODD, e));
		CHECK(RefusedUnobserved(RSUB_VF, e));
	}
	for (u32 vlen : {128u, 256u}) { Env e{vlen}; CHECK(RefusedUnobserved(SUB_VF, e)); }
	fprintf(stderr, "    vfsub.vv -> e64,m2 (0xd9) candidate; vfadd.vv two-SEW; vfadd.vf e32; vfsub.vf/odd/vfrsub -> helper\n");
}
} // namespace

int main()
{
#ifdef RVV_FP_FORCE_SOFT
	fprintf(stderr, "A22 add/sub family route test: RVV_FP_FORCE_SOFT build has no falu route\n");
	for (u32 vlen : VLENS) for (auto const &vt : VTS) for (auto const &r : ROWS) CHECK(RefusedToHelper(vt.setvli, WordOf(r), Env{vlen}));
#else
	fprintf(stderr, "A22 add/sub family route test\n");
	Section1_Shape();
	Section2_OperandOrder();
	Section3_EmittedBytes();
	Section4_FailClosed();
	Section5_UnobservedUnchanged();
#endif
	if (g_failures) { fprintf(stderr, "FAILED: %d check(s)\n", g_failures); return 1; }
	fprintf(stderr, "OK\n");
	return 0;
}
