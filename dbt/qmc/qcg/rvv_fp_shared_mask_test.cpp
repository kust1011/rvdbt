// A12 (2026-09-05): ONE active-element mask per host chunk per FP typed frame, shared by every
// vfalu/vfma lane op of that chunk (config::rvv_qcg_fp_shared_mask, default off).
//
// WHAT IS CHECKED, AND WHAT EACH CHECK'S FAILURE LOOKS LIKE
//
//   [1] Single-instruction FP frames, four VLENs, four shapes, switch OFF and ON. OFF: no
//       vchunkmaskset in the frame, every lane op's kmask == 0, and its FP mask is built per op.
//       ON: exactly k masksets, all of them
//       between rvvqcgfpbegin and the first lane op, lane op c names kmask == 1+c, n_typed grew by
//       exactly k, host builds the shared FP mask once per chunk, lane op c is masked {k(1+c)},
//       and the FP scratch is k7 (k2 can name chunk 1's shared mask). Active-lane writeback
//       independently builds its own VL/vstart predicate, so aggregate mask-code counts include it.
//       Each maskset's clamp constants (base = c*lanes, lanes = chunk_bytes/SEW) are read back from
//       the disassembly, so a wrong lane count is caught here and not only on hardware.
//   [2] The run-time-SEW frame (vfadd.vv with an unobserved vtype) is NOT shared even with the
//       switch on: no maskset, kmask 0, per-op prologue kept.
//   [3] A vector run of mixed vfalu/vfma members (the A11 shape) at 128/512/1024: k masksets after
//       the bracket opens, every member's lane op names its chunk, FP-mask construction occurs
//       once per chunk rather than once per member; the frame's
//       declared n_typed is the count the emitter
//       saw (GenerateCode would Panic otherwise).
//   [4] The contract is enforced, not documented: (a) a node that names a mask register for the
//       wrong chunk, or for a run-time SEW, or beyond k6, Panics at construction; (b) a lane op
//       with kmask == 0 placed in a frame that holds shared masks Panics in the emitter (it would
//       overwrite k1/k2); (c) a lane op naming a shared mask in a frame that never set one Panics
//       in the emitter. All three run in a forked child and the parent requires an abnormal exit.
//
// Nothing here executes host bytes (TestCompilerRuntime never mmaps); the value-level proof that
// the shared mask equals the per-op mask is the A4/A4b/A9 oracle matrix run on hardware, recorded
// in QCG_RVV_A12_RESULT.md.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
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

constexpr u32 VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0,a0,e32,m1,ta,ma
constexpr u32 VSETVLI_E64M1 = 0x0d857557u;
constexpr u32 VSETVLI_E64M2 = 0x0d957557u;
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 funct3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (funct3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 1, vs2, vs1, vd, 0b001u); }
constexpr u32 Vf(u32 f6, u32 vs2, u32 rs1, u32 vd) { return MakeOpV(f6, 1, vs2, rs1, vd, 0b101u); }
constexpr u32 F6_VFADD = 0b000000u, F6_VFDIV = 0b100000u, F6_VFMADD = 0b101000u;
static_assert(Vf(F6_VFMADD, 8, 8, 9) == 0xa28454d7u, "vfmadd.vf v9,fs0,v8 (miniWeather word)");

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override { buf.resize(sz); return buf.data(); }
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	std::vector<u8> buf;
};

struct Env {
	u32 vlen_bits = 512;
	bool shared = false;
	bool vector_run = false;
};

void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_qcg_fp_shared_mask = e.shared;
	config::rvv_vector_run = e.vector_run;
	config::rvv_run_live_range_split = false;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_fma_force_emit = true;
	config::rvv_qcg_narrow_chunk_width = true;
	config::rvv_qcg_narrow_chunk_width_force_emit = true;
	config::rvv_qcg_typed_chunk = false;
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
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
	config::rvv_lowering = 1;
}

struct Built {
	MemArena arena{1u << 21};
	std::vector<u32> words;
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
};

void Translate(Built &b, std::vector<u32> const &words, Env const &e)
{
	ApplyEnv(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}
void Emit(Built &b)
{
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
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
				if (open) { out.push_back(cur); open = false; } break;
			default:
				if (open) cur.body.push_back(&ins); break;
			}
		}
	return out;
}

bool IsInstructionLine(std::string const &line)
{
	auto const start = line.find_first_not_of(" \t");
	if (start == std::string::npos)
		return false;
	auto const end = line.find_first_not_of("0123456789abcdefABCDEF", start);
	return end != std::string::npos && end > start && line[end] == ':';
}

std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_a12_emit_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) { fprintf(stderr, "  mkstemp: %s\n", strerror(errno)); return {}; }
	size_t written = 0;
	while (written < code.size()) {
		ssize_t n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) { close(fd); unlink(path); return {}; }
		written += (size_t)n;
	}
	close(fd);
	std::string cmd = std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path + " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) { unlink(path); return {}; }
	std::vector<std::string> lines;
	char buf[1024];
	while (fgets(buf, sizeof buf, p)) {
		std::string l(buf);
		if (!l.empty() && l.back() == '\n') l.pop_back();
		// A random filename in objdump's header can contain register names such as k2.
		if (IsInstructionLine(l)) lines.push_back(l);
	}
	int rc = pclose(p);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) { fprintf(stderr, "  objdump failed\n"); return {}; }
	return lines;
}

unsigned CountContaining(std::vector<std::string> const &lines, std::string const &needle)
{
	unsigned n = 0;
	for (auto const &l : lines) n += l.find(needle) != std::string::npos;
	return n;
}
unsigned CountMnem(std::vector<std::string> const &lines, std::string const &mnem)
{
	unsigned n = 0;
	for (auto const &l : lines) {
		auto c = l.find(':'); if (c == std::string::npos) continue;
		std::string rest = l.substr(c + 1);
		size_t s = rest.find_first_not_of(" \t"); if (s == std::string::npos) continue;
		rest = rest.substr(s);
		n += rest.compare(0, mnem.size(), mnem) == 0 && (rest.size() == mnem.size() || rest[mnem.size()] == ' ');
	}
	return n;
}
// Lines where kN is written as a scratch: a vcmp destination (`vcmp... kN{`), a knotw
// destination, or a kmovw into it that is not the maskset's own -- i.e. any mention of kN that is
// neither a `{kN}` writemask use nor `kmovw  kN,` (the producer).
unsigned ScratchUses(std::vector<std::string> const &lines, unsigned n)
{
	std::string const reg = "k" + std::to_string(n), use = "{" + reg + "}", prod = "kmovw  " + reg + ",";
	unsigned cnt = 0;
	for (auto const &l : lines) {
		if (!IsInstructionLine(l)) continue;
		if (l.find(reg) == std::string::npos) continue;
		if (l.find(prod) != std::string::npos) continue;
		if (l.find("knotw  k7," + reg) != std::string::npos) continue; // the tail READS it
		std::string t = l;
		for (size_t p; (p = t.find(use)) != std::string::npos;) t.erase(p, use.size());
		cnt += t.find(reg) != std::string::npos;
	}
	return cnt;
}
std::string Hex(u32 v) { char b[32]; snprintf(b, sizeof b, "0x%x", v); return b; }
std::string VlLoad()
{
	return "mov    eax,DWORD PTR [r13+" + Hex((u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vl))) + "]";
}

struct Shape { char const *name; u32 setvli; u32 word; u32 sew; u32 lmul; bool fma; };
constexpr Shape SHAPES[] = {
    {"vfadd.vv e32m1", VSETVLI_E32M1, Vv(F6_VFADD, 9, 10, 8), 4, 1, false},
    {"vfmadd.vf e32m1", VSETVLI_E32M1, Vf(F6_VFMADD, 8, 8, 9), 4, 1, true},
    {"vfadd.vv e64m2", VSETVLI_E64M2, Vv(F6_VFADD, 10, 12, 8), 8, 2, false},
    {"vfdiv.vf e64m1", VSETVLI_E64M1, Vf(F6_VFDIV, 10, 11, 8), 8, 1, false},
};

unsigned ChunkBytes(u32 vlen) { return vlen / 8 > 64 ? 64 : vlen / 8; }
unsigned Chunks(u32 vlen, u32 lmul) { return lmul * (vlen / 8) / ChunkBytes(vlen); }

// Everything a frame's QIR and host bytes say about its masks.
struct MaskFacts {
	unsigned masksets = 0, lane_ops = 0, first_lane_pos = 0, fpbegin_pos = 0, last_maskset_pos = 0;
	bool all_named = true, all_unnamed = true;
	std::vector<u8> kmasks;
};
MaskFacts Facts(Frame const &f)
{
	MaskFacts m;
	for (unsigned i = 0; i < f.body.size(); ++i) {
		auto *ins = f.body[i];
		switch (ins->GetOpcode()) {
		case Op::_rvvqcgfpbegin: m.fpbegin_pos = i; break;
		case Op::_vchunkmaskset: ++m.masksets; m.last_maskset_pos = i; break;
		case Op::_vchunkfalu: {
			auto *o = static_cast<InstVChunkFALU *>(ins);
			if (!m.lane_ops) m.first_lane_pos = i;
			++m.lane_ops; m.kmasks.push_back(o->kmask);
			m.all_named &= o->kmask == (u8)(1 + o->chunk); m.all_unnamed &= o->kmask == 0; break; }
		case Op::_vchunkfma: {
			auto *o = static_cast<InstVChunkFMA *>(ins);
			if (!m.lane_ops) m.first_lane_pos = i;
			++m.lane_ops; m.kmasks.push_back(o->kmask);
			m.all_named &= o->kmask == (u8)(1 + o->chunk); m.all_unnamed &= o->kmask == 0; break; }
		default: break;
		}
	}
	return m;
}

// Read the clamp constants of every maskset back out of the disassembly: each maskset is
//   mov eax,[vl]; [cmp eax,base; ja; xor; jmp; sub eax,base]; cmp eax,lanes; mov edx,lanes; ...
// so after each vl load the next `cmp    eax,0x..` immediates are (base?) then lanes.
bool MasksetConstantsMatch(std::vector<std::string> const &dis, unsigned k, unsigned lanes)
{
	unsigned found = 0;
	for (size_t i = 0; i < dis.size(); ++i) {
		if (dis[i].find(VlLoad()) == std::string::npos) continue;
		unsigned c = found;
		std::vector<u32> imms;
		for (size_t j = i + 1; j < dis.size() && j < i + 32; ++j) {
			auto p = dis[j].find("cmp    eax,0x");
			if (p != std::string::npos) imms.push_back((u32)strtoul(dis[j].c_str() + p + 13, nullptr, 16));
			if (dis[j].find("kmovw") != std::string::npos) break;
		}
		// VL clamps the upper bound; vstart subsequently removes the lower bound.
		bool ok = c == 0 ? (imms.size() == 3 && imms[0] == lanes && imms[1] == 0 &&
				      imms[2] == lanes)
				 : (imms.size() == 4 && imms[0] == c * lanes && imms[1] == lanes &&
				    imms[2] == c * lanes && imms[3] == lanes);
		if (!ok) {
			fprintf(stderr, "    maskset %u: unexpected clamp immediates", c);
			for (u32 imm : imms) fprintf(stderr, " 0x%x", imm);
			fputc('\n', stderr);
			return false;
		}
		++found;
		if (found == k) break; // later VL loads belong to the architectural writeback mask
	}
	return found == k;
}

void Section1_SingleFrames()
{
	fprintf(stderr, "[1] single-instruction FP frames: switch off = per-op k1/k2, on = per-chunk k(1+c), scratch k7\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		for (auto const &s : SHAPES) {
			unsigned const k = Chunks(vlen, s.lmul), lanes = ChunkBytes(vlen) / s.sew;
			u16 n_typed_off = 0;
			for (bool on : {false, true}) {
				Built b;
				Translate(b, {s.setvli, s.word}, Env{vlen, on, false});
				auto frames = FindFrames(b.region);
				CHECK_EQ(frames.size(), (size_t)1);
				if (frames.size() != 1) continue;
				auto m = Facts(frames[0]);
				CHECK_EQ(m.lane_ops, k);
				if (!on) {
					n_typed_off = frames[0].begin->n_typed;
					CHECK_EQ(m.masksets, 0u);
					CHECK(m.all_unnamed);
				} else {
					CHECK_EQ(m.masksets, k);
					CHECK(m.all_named);
					CHECK_EQ(frames[0].begin->n_typed, (u16)(n_typed_off + k));
					// every maskset sits after the bracket opens and before the first lane op
					CHECK(m.last_maskset_pos > m.fpbegin_pos && m.last_maskset_pos < m.first_lane_pos);
					for (unsigned c = 0; c < k; ++c) CHECK_EQ(m.kmasks[c], (u8)(1 + c));
				}
				Emit(b);
				auto dis = Disassemble(b.code);
				CHECK(!dis.empty());
				// Each chunk has an FP mask and a separate architectural writeback mask.
				// Both masks clamp VL and remove prestart lanes with BZHI.
				CHECK_EQ(CountContaining(dis, VlLoad()), 2u * k);
				CHECK_EQ(CountMnem(dis, "bzhi"), 4u * k);
				CHECK_EQ(CountMnem(dis, "kmovw"), 2u * k);
				CHECK_EQ(CountMnem(dis, "knotw"), s.fma ? 0u : k);
				if (on) {
					CHECK(MasksetConstantsMatch(dis, k, lanes));
					for (unsigned c = 0; c < k; ++c) {
						std::string km = "{k" + std::to_string(1 + c) + "}";
						CHECK(CountContaining(dis, km) >= 1); // the lane op and its vcmp
						CHECK_EQ(CountContaining(dis, "kmovw  k" + std::to_string(1 + c) + ","), 1u);
					}
					CHECK_EQ(CountContaining(dis, "{k7}"), (s.fma ? 2u : 3u) * k); // FP scratch + writeback
					// k2 may appear ONLY as chunk 1's resident mask (its kmovw and its {k2} uses),
					// never as a scratch destination.
					CHECK_EQ(ScratchUses(dis, 2), 0u);
					CHECK_EQ(CountContaining(dis, "kmovw  k7"), k); // writeback mask only
				} else {
					CHECK_EQ(CountContaining(dis, "{k2}"), (s.fma ? 1u : 2u) * k);
					CHECK_EQ(CountContaining(dis, "k7"), 2u * k); // writeback mask only
					CHECK_EQ(CountContaining(dis, "kmovw  k1,"), k);
					for (unsigned c = 2; c < k; ++c)
						CHECK_EQ(CountContaining(dis, "{k" + std::to_string(1 + c) + "}"), 0u);
				}
			}
			fprintf(stderr, "    VLEN %4u %-16s k=%u lanes=%2u ok\n", vlen, s.name, k, lanes);
		}
	}
}

void Section2_RuntimeSewFrameIsNotShared()
{
	fprintf(stderr, "[2] the two-vtype vfadd.vv frame (SEW decided at run time) keeps the per-op prologue\n");
	for (u32 vlen : {512u, 1024u}) {
		Built b;
		// no vsetvli: unobserved vtype; the candidate is m2, so the register numbers are even
		Translate(b, {Vv(F6_VFADD, 10, 12, 8)}, Env{vlen, true, false});
		auto frames = FindFrames(b.region);
		CHECK_EQ(frames.size(), (size_t)1);
		if (frames.size() != 1) continue;
		auto m = Facts(frames[0]);
		CHECK_EQ(frames[0].begin->guard_kind, InstRVVTypedChunkBegin::GuardKind::VTypeE32OrE64M2PartialVlVstartFrmRNE);
		CHECK_EQ(m.masksets, 0u);
		CHECK(m.all_unnamed);
		CHECK(m.lane_ops >= 1);
		for (auto *ins : frames[0].body)
			if (ins->GetOpcode() == Op::_vchunkfalu)
				CHECK_EQ(static_cast<InstVChunkFALU *>(ins)->sew_bytes, (u8)0);
		Emit(b);
		auto dis = Disassemble(b.code);
		CHECK_EQ(CountContaining(dis, "k7"), 0u);
		CHECK(CountMnem(dis, "kmovw") == 2 * m.lane_ops); // e32 arm + e64 arm, each its own prologue
		fprintf(stderr, "    VLEN %u: lane ops %u, kmovw %u, masksets 0\n", vlen, m.lane_ops, CountMnem(dis, "kmovw"));
	}
}

void Section3_RunFrame()
{
	fprintf(stderr, "[3] an FP vector run (mixed vfalu/vfma members, A11 shape): k masks for the whole run\n");
	// vsetvli e32m1; vfadd.vv v8,v9,v10; vfmadd.vf v9,fs0,v8; vfadd.vf v8,v8,fa5; vfadd.vv v8,v8,v9
	std::vector<u32> words = {VSETVLI_E32M1, Vv(F6_VFADD, 9, 10, 8), Vf(F6_VFMADD, 8, 8, 9),
				  Vf(F6_VFADD, 8, 15, 8), Vv(F6_VFADD, 8, 9, 8)};
	unsigned const members = 4;
	for (u32 vlen : {128u, 512u, 1024u}) {
		unsigned const k = Chunks(vlen, 1);
		u16 n_typed_off = 0;
		for (bool on : {false, true}) {
			Built b;
			Translate(b, words, Env{vlen, on, true});
			auto frames = FindFrames(b.region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.size() != 1) continue;
			CHECK_EQ(frames[0].begin->n_members, (u8)members);
			auto m = Facts(frames[0]);
			CHECK_EQ(m.lane_ops, members * k);
			if (!on) {
				n_typed_off = frames[0].begin->n_typed;
				CHECK_EQ(m.masksets, 0u); CHECK(m.all_unnamed);
			} else {
				CHECK_EQ(m.masksets, k); CHECK(m.all_named);
				CHECK_EQ(frames[0].begin->n_typed, (u16)(n_typed_off + k));
				CHECK(m.last_maskset_pos > m.fpbegin_pos && m.last_maskset_pos < m.first_lane_pos);
			}
			Emit(b); // Panics if the declared n_typed and the emitted count disagree
			auto dis = Disassemble(b.code);
			CHECK(!dis.empty());
			CHECK_EQ(CountContaining(dis, VlLoad()), on ? k : members * k);
			CHECK_EQ(CountMnem(dis, "bzhi"), 2u * (on ? k : members * k));
			CHECK_EQ(CountMnem(dis, "kmovw"), on ? k : members * k);
			CHECK_EQ(CountMnem(dis, "vaddps"), 3 * k);
			CHECK_EQ(CountMnem(dis, "vfmadd213ps"), k);
			if (on) {
				CHECK_EQ(ScratchUses(dis, 2), 0u);
				CHECK_EQ(CountContaining(dis, "knotw  k7,"), 3 * k);
				// per chunk: 3 vaddps + 1 vfmadd + 4 vcmp carry {k(1+c)}
				for (unsigned c = 0; c < k; ++c)
					CHECK_EQ(CountContaining(dis, "{k" + std::to_string(1 + c) + "}"), 8u);
			} else {
				CHECK_EQ(CountContaining(dis, "k7"), 0u);
				CHECK_EQ(CountContaining(dis, "knotw  k2,k1"), 3 * k);
			}
			fprintf(stderr, "    VLEN %4u shared=%d: k=%u members=%u lane ops=%u host kmovw=%u\n", vlen, on, k,
				members, m.lane_ops, CountMnem(dis, "kmovw"));
		}
	}
}

// Run `fn` in a child; true iff the child died abnormally or with a non-zero status (Panic).
bool DiesInChild(std::function<void()> fn)
{
	fflush(stderr);
	pid_t pid = fork();
	if (pid == 0) {
		freopen("/dev/null", "w", stderr);
		fn();
		_exit(0);
	}
	int st = 0;
	waitpid(pid, &st, 0);
	return !WIFEXITED(st) || WEXITSTATUS(st) != 0;
}

void Section4_ContractIsEnforced()
{
	fprintf(stderr, "[4] the mask contract Panics rather than miscompiles\n");
	// (a) node-level: a wrong register name, a run-time SEW, or reserved scratch k7.
	CHECK(DiesInChild([] {
		MemArena a(1u << 16);
		auto d = VOperand::MakeVVPR(VType::V512, 1), s = VOperand::MakeVVPR(VType::V512, 2);
		InstVChunkFALU n(d, s, s, 4, 0, /*chunk=*/0, /*kmask=*/2);
	}));
	CHECK(DiesInChild([] {
		auto d = VOperand::MakeVVPR(VType::V512, 1), s = VOperand::MakeVVPR(VType::V512, 2);
		InstVChunkFALU n(d, s, s, /*sew=*/0, 0, 0, /*kmask=*/1);
	}));
	CHECK(DiesInChild([] {
		auto d = VOperand::MakeVVPR(VType::V512, 1), s = VOperand::MakeVVPR(VType::V512, 2);
		InstVChunkFMA n(d, s, s, s, 4, 0b101000, /*chunk=*/6, /*kmask=*/7);
	}));
	CHECK(!DiesInChild([] { // the control: the legal form constructs
		auto d = VOperand::MakeVVPR(VType::V512, 1), s = VOperand::MakeVVPR(VType::V512, 2);
		InstVChunkFALU n(d, s, s, 4, 0, /*chunk=*/1, /*kmask=*/2);
		InstVChunkFMA m(d, s, s, s, 8, 0b101000, /*chunk=*/5, /*kmask=*/6);
		InstVChunkFALU recycled(d, s, s, 4, 0, /*chunk=*/6, /*kmask=*/1);
	}));
	CHECK(DiesInChild([] {
		Built b;
		Translate(b, {VSETVLI_E32M1, Vv(F6_VFADD, 9, 10, 8)}, Env{1024, true, false});
		// Chunk 0 owns k1, then chunk 6 replaces it before chunk 0's consumer.
		for (auto &f : FindFrames(b.region))
			for (auto *ins : f.body)
				if (ins->GetOpcode() == Op::_vchunkmaskset) {
					auto *mask = static_cast<InstVChunkMaskSet *>(ins);
					if (mask->chunk == 1) mask->chunk = 6;
				}
		Emit(b);
	}));
	// (b) emitter-level: a self-computing op inside a frame holding shared masks would clobber
	// k1/k2. Translate with sharing on, then flip ONE lane op back to kmask 0.
	CHECK(DiesInChild([] {
		Built b;
		Translate(b, {VSETVLI_E32M1, Vv(F6_VFADD, 9, 10, 8)}, Env{1024, true, false});
		for (auto &f : FindFrames(b.region))
			for (auto *ins : f.body)
				if (ins->GetOpcode() == Op::_vchunkfalu) { static_cast<InstVChunkFALU *>(ins)->kmask = 0; break; }
		Emit(b);
	}));
	// (c) emitter-level: an op naming a shared mask in a frame that never set one.
	CHECK(DiesInChild([] {
		Built b;
		Translate(b, {VSETVLI_E32M1, Vv(F6_VFADD, 9, 10, 8)}, Env{512, false, false});
		for (auto &f : FindFrames(b.region))
			for (auto *ins : f.body)
				if (ins->GetOpcode() == Op::_vchunkfalu) { static_cast<InstVChunkFALU *>(ins)->kmask = 1; break; }
		Emit(b);
	}));
	CHECK(!DiesInChild([] { // the control: the unmutated frames emit
		Built b;
		Translate(b, {VSETVLI_E32M1, Vv(F6_VFADD, 9, 10, 8)}, Env{1024, true, false});
		Emit(b);
		Built c;
		Translate(c, {VSETVLI_E32M1, Vv(F6_VFADD, 9, 10, 8)}, Env{512, false, false});
		Emit(c);
	}));
	fprintf(stderr, "    node-level 3/3 refused, emitter-level 3/3 refused, controls emit\n");
}
} // namespace

int main()
{
	fprintf(stderr, "A12: shared per-chunk active mask in FP typed frames\n");
	CHECK_EQ(ScratchUses({"/tmp/rvdbt_a12_emit_abk2cd:     file format binary"}, 2), 0u);
	CHECK_EQ(ScratchUses({"  1a: vcmpunordps k2{k1},zmm4,zmm4"}, 2), 1u);
	CHECK_EQ(ScratchUses({"  1a: vaddps zmm4{k2},zmm2,zmm3"}, 2), 0u);
	CHECK_EQ(ScratchUses({"  1a: knotw  k2,k1"}, 2), 1u);
	Section1_SingleFrames();
	Section2_RuntimeSewFrameIsNotShared();
	Section3_RunFrame();
	Section4_ContractIsEnforced();
	if (g_failures) { fprintf(stderr, "FAILED (%d)\n", g_failures); return 1; }
	fprintf(stderr, "PASSED\n");
	return 0;
}
