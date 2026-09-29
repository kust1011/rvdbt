// A13 (2026-09-05): unit-stride unmasked EEW=64 load/store through the SAME width-derived chunk frame
// as EEW=32 (config::rvv_qcg_typed_chunk_mem_e64, default off), plus the base-range guard.
//
//   [1] switch ON, four VLENs: `vsetvli e64,m1` + vle64.v / vse64.v build ONE frame each with
//       guard kind VTypeVlVstartBaseLimit, base_limit == 2^32 - VLEN/8, base_offs == the rs1 slot,
//       n_typed == 2k, k vchunkload (or vstatechunkload) values of the chunk width and k state
//       windows at rd*slot + c*chunk; host bytes: 2k `vmovdqu64` of the chunk class (xmm/ymm/zmm,
//       two zmm at 1024), the guard's `cmp eax,<limit>` + `ja`, no VEX, no add/sub on the base.
//   [2] switch OFF: the e64 words keep the helper (no frame, one hcall); the e32 frame carries the
//       base-range guard whether the switch is on or off (A13-FIX: the guard is the frame's
//       contract, not an e64 feature) and is otherwise the S1/P7N-D frame.
//   [3] fail-closed matrix with the switch ON: masked vle64/vse64, EEW != SEW in both directions
//       (vle64 under e32 -> EMUL 2; vle32 under e64 -> EMUL 1/2), LMUL 2, x0 base, EEW 8/16,
//       masked e64 on the LLVM backend, narrow-width switch off at 128/256
//       (512 still admitted), no host AVX-512 without force-emit.
//   [4] the guard-kind constructor refuses any other kind / a zero limit (forked child).
//
// Nothing here executes host bytes; the memory contract itself (per-lane data, unaligned bases,
// page-end, partial/zero vl on a guard miss, faults, the top-of-address-space case) is the guest
// oracle in QCG_RVV_A13_RESULT.md, run on hardware against pinned QEMU.

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

constexpr u32 VSETVLI_E32M1 = 0x0d057557u, VSETVLI_E64M1 = 0x0d857557u, VSETVLI_E64M2 = 0x0d957557u;
// unit-stride vector load/store: opcode | vd<<7 | width<<12 | rs1<<15 | lumop 0 | vm<<25 | mop 0 | mew 0 | nf 0
constexpr u32 Vle(u32 width, u32 rs1, u32 vd, u32 vm = 1) { return 0b0000111u | (vd << 7) | (width << 12) | (rs1 << 15) | (vm << 25); }
constexpr u32 Vse(u32 width, u32 rs1, u32 vs3, u32 vm = 1) { return 0b0100111u | (vs3 << 7) | (width << 12) | (rs1 << 15) | (vm << 25); }
constexpr u32 W8 = 0b000, W16 = 0b101, W32 = 0b110, W64 = 0b111;
constexpr u32 BASE = 16; // a6
static_assert(Vle(W32, 16, 8) == 0x02086407u, "vle32.v v8,(a6)");
static_assert(Vle(W64, 16, 8) == 0x02087407u, "vle64.v v8,(a6)");
static_assert(Vse(W64, 16, 8) == 0x02087427u, "vse64.v v8,(a6)");

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override { buf.resize(sz); return buf.data(); }
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	std::vector<u8> buf;
};
struct Env {
	u32 vlen_bits = 512;
	bool e64 = true;
	bool narrow = true;
	bool force_emit = true;
	bool llvm = false;
	bool partial = false;
};
void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_qcg_typed_chunk_mem_e64 = e.e64;
	config::rvv_qcg_typed_chunk_vle = true;
	config::rvv_qcg_typed_chunk_vse = true;
	config::rvv_qcg_typed_chunk_vle_force_emit = e.force_emit;
	config::rvv_qcg_typed_chunk_vse_force_emit = e.force_emit;
	config::rvv_qcg_narrow_chunk_width = e.narrow;
	config::rvv_qcg_narrow_chunk_width_force_emit = e.narrow && e.force_emit;
	config::aot_use_llvm = e.llvm;
	config::rvv_vector_ssa = e.llvm;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::rvv_lowering = 1;
	config::rvv_vector_run = false;
	config::rvv_run_live_range_split = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_falu = false;
	config::rvv_qcg_typed_chunk_fma = false;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_partial_vl = e.partial;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
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
struct Frame { InstRVVTypedChunkBegin *begin = nullptr; std::vector<Inst *> body; };
std::vector<Frame> FindFrames(Region *region)
{
	std::vector<Frame> out; Frame cur; bool open = false;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin: cur = Frame{}; cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins); open = true; break;
			case Op::_rvvtypedchunkend: if (open) { out.push_back(cur); open = false; } break;
			default: if (open) cur.body.push_back(&ins); break;
			}
		}
	return out;
}
unsigned CountOp(Region *r, Op op) { unsigned n = 0; for (auto &bb : r->GetBlocks()) for (auto &ins : bb.ilist) n += ins.GetOpcode() == op; return n; }
unsigned CountStub(Region *r, RuntimeStubId s) { unsigned n = 0; for (auto &bb : r->GetBlocks()) for (auto &ins : bb.ilist) if (ins.GetOpcode() == Op::_hcall) n += static_cast<InstHcall *>(&ins)->stub == s; return n; }

std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_a13_emit_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) return {};
	size_t w = 0;
	while (w < code.size()) { ssize_t n = write(fd, code.data() + w, code.size() - w); if (n <= 0) { close(fd); unlink(path); return {}; } w += (size_t)n; }
	close(fd);
	std::string cmd = std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path + " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) { unlink(path); return {}; }
	std::vector<std::string> lines; char buf[1024];
	while (fgets(buf, sizeof buf, p)) { std::string l(buf); if (!l.empty() && l.back() == '\n') l.pop_back(); lines.push_back(l); }
	int rc = pclose(p); unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) return {};
	return lines;
}
unsigned Count(std::vector<std::string> const &ls, std::string const &needle) { unsigned n = 0; for (auto const &l : ls) n += l.find(needle) != std::string::npos; return n; }
// instruction lines up to (and including) the last vmovdqu64: the code buffer is zero-padded and
// objdump decodes the padding as `add BYTE PTR [rax],al`.
std::vector<std::string> Body(std::vector<std::string> const &ls)
{
	size_t last = 0;
	for (size_t i = 0; i < ls.size(); ++i) if (ls[i].find("vmovdqu64") != std::string::npos) last = i;
	return std::vector<std::string>(ls.begin(), ls.begin() + (last ? last + 1 : 0));
}
std::string Hex(u32 v) { char b[32]; snprintf(b, sizeof b, "0x%x", v); return b; }
unsigned ChunkBytes(u32 vlen) { return vlen / 8 > 64 ? 64 : vlen / 8; }
unsigned Chunks(u32 vlen) { return (vlen / 8) / ChunkBytes(vlen); }
u32 GprOffs(u32 r) { return (u32)(offsetof(CPUState, gpr) + 4u * r); }
u32 VregOffs(u32 r) { return (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg)) + r * rv32::VLEN_MAX_BYTES; }
char const *Cls(u32 bytes) { return bytes == 16 ? "xmm" : bytes == 32 ? "ymm" : "zmm"; }

void CheckFrame(char const *tag, u32 vlen, bool store, u32 setvli, u32 word, bool base_guard, u32 sew)
{
	unsigned const k = Chunks(vlen), cb = ChunkBytes(vlen);
	Built b; Translate(b, {setvli, word}, Env{vlen, true});
	auto frames = FindFrames(b.region);
	CHECK_EQ(frames.size(), (size_t)1);
	if (frames.size() != 1) return;
	auto *bg = frames[0].begin;
	CHECK_EQ(bg->n_typed, (u16)(2 * k));
	CHECK_EQ(bg->vlmax, vlen / (8 * sew));
	CHECK_EQ(bg->stub, store ? RuntimeStubId::id_rv32_vse : RuntimeStubId::id_rv32_vle);
	if (base_guard) {
		CHECK(bg->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseLimit);
		CHECK_EQ(bg->base_limit, 0u - vlen / 8u);
		CHECK_EQ(bg->base_state_offs, (u16)GprOffs(BASE));
	} else {
		CHECK(bg->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstart);
	}
	CHECK_EQ(CountStub(b.region, RuntimeStubId::id_rv32_vle) + CountStub(b.region, RuntimeStubId::id_rv32_vse), 0u);
	unsigned mem = 0, st = 0;
	for (auto *ins : frames[0].body) {
		if (!store && ins->GetOpcode() == Op::_vchunkload) {
			auto *l = static_cast<InstVChunkLoad *>(ins);
			CHECK_EQ(VTypeToSize(l->o(0).GetType()), cb);
			CHECK_EQ(l->base_state_offs, (u16)GprOffs(BASE));
			CHECK_EQ(l->disp, (u16)(mem * cb));
			++mem;
		} else if (!store && ins->GetOpcode() == Op::_vstatechunkstore) {
			auto *s = static_cast<InstVStateChunkStore *>(ins);
			CHECK_EQ(s->offs, (u16)(VregOffs(8) + st * cb));
			++st;
		} else if (store && ins->GetOpcode() == Op::_vstatechunkload) {
			auto *l = static_cast<InstVStateChunkLoad *>(ins);
			CHECK_EQ(l->offs, (u16)(VregOffs(8) + st * cb));
			++st;
		} else if (store && ins->GetOpcode() == Op::_vchunkstore) {
			auto *s = static_cast<InstVChunkStore *>(ins);
			CHECK_EQ(VTypeToSize(s->i(1).GetType()), cb);
			CHECK_EQ(s->base_state_offs, (u16)GprOffs(BASE));
			CHECK_EQ(s->disp, (u16)(mem * cb));
			++mem;
		}
	}
	CHECK_EQ(mem, k); CHECK_EQ(st, k);
	Emit(b);
	auto dis = Body(Disassemble(b.code));
	CHECK(!dis.empty());
	CHECK_EQ(Count(dis, "vmovdqu64"), 2 * k);
	{
		unsigned same_class = 0;
		for (auto const &l : dis)
			if (l.find("vmovdqu64") != std::string::npos && l.find(Cls(cb)) != std::string::npos)
				++same_class;
		CHECK_EQ(same_class, 2 * k); // every vector move names the chunk class register
	}
	for (u32 other : {16u, 32u, 64u}) if (other != cb) CHECK_EQ(Count(dis, Cls(other)), 0u);
	// the guard
	CHECK_EQ(Count(dis, "cmp    eax," + Hex(0u - vlen / 8u)), base_guard ? 1u : 0u);
	CHECK_EQ(Count(dis, "ja "), base_guard ? 1u : 0u);
	CHECK_EQ(Count(dis, "mov    eax,DWORD PTR [r13+" + Hex(GprOffs(BASE)) + "]"), k + (base_guard ? 1u : 0u));
	// no address arithmetic on the base, no VEX (c4/c5) vector moves
	CHECK_EQ(Count(dis, "add    eax") + Count(dis, "add    rax") + Count(dis, "sub    eax") + Count(dis, "sub    rax") + Count(dis, "lea    "), 0u);
	fprintf(stderr, "    %-22s VLEN %4u k=%u chunk=%2u %s guard=%s ok\n", tag, vlen, k, cb, Cls(cb), base_guard ? "vtype/vl/vstart/base" : "vtype/vl/vstart");
}

void Section1_E64Frames()
{
	fprintf(stderr, "[1] switch ON: vle64.v / vse64.v at e64,m1 build the width-derived frame with the base-range guard\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		CheckFrame("vle64.v v8,(a6)", vlen, false, VSETVLI_E64M1, Vle(W64, BASE, 8), true, 8);
		CheckFrame("vse64.v v8,(a6)", vlen, true, VSETVLI_E64M1, Vse(W64, BASE, 8), true, 8);
	}
}

bool Refused(std::vector<u32> const &words, Env const &e, bool store)
{
	Built b; Translate(b, words, e);
	return FindFrames(b.region).empty() &&
	       CountStub(b.region, store ? RuntimeStubId::id_rv32_vse : RuntimeStubId::id_rv32_vle) == 1u &&
	       CountOp(b.region, Op::_vchunkload) == 0u && CountOp(b.region, Op::_vchunkstore) == 0u;
}
bool Admitted(std::vector<u32> const &words, Env const &e)
{
	Built b; Translate(b, words, e);
	return FindFrames(b.region).size() == 1;
}

void Section2_SwitchOffAndE32()
{
	fprintf(stderr, "[2] switch OFF: e64 keeps the helper; e32 carries the base-range guard with the switch off AND on\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u}) {
		Env off{vlen, false};
		CHECK(Refused({VSETVLI_E64M1, Vle(W64, BASE, 8)}, off, false));
		CHECK(Refused({VSETVLI_E64M1, Vse(W64, BASE, 8)}, off, true));
		// e32 with the switch OFF: the S1/P7N-D body, and (A13-FIX) the base-range guard on it.
		{
			Built b; Translate(b, {VSETVLI_E32M1, Vle(W32, BASE, 8)}, off);
			auto f = FindFrames(b.region); CHECK_EQ(f.size(), (size_t)1);
			if (f.size() == 1) {
				CHECK(f[0].begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseLimit);
				CHECK_EQ(f[0].begin->base_limit, 0u - vlen / 8u);
				CHECK_EQ(f[0].begin->n_typed, (u16)(2 * Chunks(vlen)));
				Emit(b); auto dis = Body(Disassemble(b.code));
				CHECK_EQ(Count(dis, "cmp    eax," + Hex(0u - vlen / 8u)), 1u);
				CHECK_EQ(Count(dis, "ja "), 1u);
				CHECK_EQ(Count(dis, "vmovdqu64"), 2 * Chunks(vlen));
			}
		}
		// e32 with the switch on: identical frame
		CheckFrame("vle32.v v8,(a6) [on]", vlen, false, VSETVLI_E32M1, Vle(W32, BASE, 8), true, 4);
		CheckFrame("vse32.v v8,(a6) [on]", vlen, true, VSETVLI_E32M1, Vse(W32, BASE, 8), true, 4);
	}
}

void Section3_FailClosed()
{
	fprintf(stderr, "[3] fail-closed matrix (switch ON)\n");
	struct Row { char const *why; u32 vlen; std::vector<u32> words; bool store; Env env; };
	std::vector<Row> rows = {
	    {"masked vle64.v v8,(a6),v0.t", 512, {VSETVLI_E64M1, Vle(W64, BASE, 8, 0)}, false, Env{512}},
	    {"masked vse64.v", 512, {VSETVLI_E64M1, Vse(W64, BASE, 8, 0)}, true, Env{512}},
	    {"vle64.v under e32,m1 (EMUL 2)", 512, {VSETVLI_E32M1, Vle(W64, BASE, 8)}, false, Env{512}},
	    {"vse64.v under e32,m1 (EMUL 2)", 512, {VSETVLI_E32M1, Vse(W64, BASE, 8)}, true, Env{512}},
	    {"vle32.v under e64,m1 (EMUL 1/2)", 512, {VSETVLI_E64M1, Vle(W32, BASE, 8)}, false, Env{512}},
	    {"vle64.v under e64,m2 (LMUL 2)", 512, {VSETVLI_E64M2, Vle(W64, BASE, 8)}, false, Env{512}},
	    {"vle64.v base x0", 512, {VSETVLI_E64M1, Vle(W64, 0, 8)}, false, Env{512}},
	    {"vle8.v under e64,m1", 512, {VSETVLI_E64M1, Vle(W8, BASE, 8)}, false, Env{512}},
	    {"vle16.v under e64,m1", 512, {VSETVLI_E64M1, Vle(W16, BASE, 8)}, false, Env{512}},
	    {"vle64.v, no vsetvli observed (e32 assumed)", 512, {Vle(W64, BASE, 8)}, false, Env{512}},
	    {"vle64.v at VLEN 128, narrow-width switch off", 128, {VSETVLI_E64M1, Vle(W64, BASE, 8)}, false, Env{128, true, false}},
	    {"vle64.v at VLEN 256, narrow-width switch off", 256, {VSETVLI_E64M1, Vle(W64, BASE, 8)}, false, Env{256, true, false}},
	};
	for (auto &r : rows) {
		bool ok = Refused(r.words, r.env, r.store);
		CHECK(ok);
		fprintf(stderr, "    %-48s -> %s\n", r.why, ok ? "helper" : "ADMITTED (bug)");
	}
	// narrow switch off does not affect 512
	CHECK(Admitted({VSETVLI_E64M1, Vle(W64, BASE, 8)}, Env{512, true, false}));
	// LLVM uses the same legal e64 shape; masking remains a helper-only form.
	{
		Env l{512, true, true, true, true};
		Built b; Translate(b, {VSETVLI_E64M1, Vle(W64, BASE, 8)}, l);
		auto e64 = FindFrames(b.region);
		CHECK_EQ(e64.size(), (size_t)1);
		if (e64.size() == 1) CHECK(e64[0].begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstart);
		CHECK_EQ(CountStub(b.region, RuntimeStubId::id_rv32_vle), 0u);
		Built masked; Translate(masked, {VSETVLI_E64M1, Vle(W64, BASE, 8, 0)}, l);
		CHECK(FindFrames(masked.region).empty());
		CHECK_EQ(CountStub(masked.region, RuntimeStubId::id_rv32_vle), 1u);
		Built c; Translate(c, {VSETVLI_E32M1, Vle(W32, BASE, 8)}, l);
		auto f = FindFrames(c.region);
		CHECK_EQ(f.size(), (size_t)1);
		if (f.size() == 1) CHECK(f[0].begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstart);
		fprintf(stderr, "    LLVM backend: e64/e32 frames admitted, masked e64 -> helper\n");
	}
	// host feature: without force-emit, admission follows CPUID
	{
		__builtin_cpu_init();
		bool const have = __builtin_cpu_supports("avx512f");
		Env e{512, true, true, false};
		CHECK_EQ(Admitted({VSETVLI_E64M1, Vle(W64, BASE, 8)}, e), have);
		fprintf(stderr, "    host avx512f=%s -> admission without force-emit = %s\n", have ? "yes" : "no", have ? "yes" : "no");
	}
}

bool DiesInChild(std::function<void()> fn)
{
	fflush(stderr);
	pid_t pid = fork();
	if (pid == 0) { freopen("/dev/null", "w", stderr); fn(); _exit(0); }
	int st = 0; waitpid(pid, &st, 0);
	return !WIFEXITED(st) || WEXITSTATUS(st) != 0;
}
void Section4_GuardKindConstructor()
{
	fprintf(stderr, "[4] the base-limit constructor is fail-closed\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	CHECK(DiesInChild([] { InstRVVTypedChunkBegin n(0xd8, 8, 0, RuntimeStubId::id_rv32_vle, 2, GK::VTypeVlVstart, 64, 0xffffffc0u); }));
	CHECK(DiesInChild([] { InstRVVTypedChunkBegin n(0xd8, 8, 0, RuntimeStubId::id_rv32_vle, 2, GK::VTypeVlVstartBaseLimit, 64, 0u); }));
	CHECK(DiesInChild([] { InstRVVTypedChunkBegin n(0xd8, 8, 0, RuntimeStubId::id_rv32_vle, 2, GK::VTypeVlVstartBaseLimit, 0x10000u, 0xffffffc0u); }));
	CHECK(!DiesInChild([] { InstRVVTypedChunkBegin n(0xd8, 8, 0, RuntimeStubId::id_rv32_vle, 2, GK::VTypeVlVstartBaseLimit, 64, 0xffffffc0u); }));
	fprintf(stderr, "    3/3 refused, control constructs\n");
}

void Section5_PartialElementWidth()
{
	fprintf(stderr, "[5] partial-vl memory keeps the encoded EEW in QIR and host opcodes\n");
	for (u32 sew : {4u, 8u}) {
		u32 const setvl = sew == 4 ? VSETVLI_E32M1 : VSETVLI_E64M1;
		u32 const width = sew == 4 ? W32 : W64;
		for (bool store : {false, true}) {
			Built b;
			Translate(b, {setvl, store ? Vse(width, BASE, 8) : Vle(width, BASE, 8)},
				  Env{512, true, true, true, false, true});
			auto frames = FindFrames(b.region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.size() != 1)
				continue;
			CHECK(frames[0].begin->guard_kind ==
			      InstRVVTypedChunkBegin::GuardKind::VTypeVlOrPartialVstartBaseLimit);
			CHECK_EQ(frames[0].begin->n_typed, (u16)4);
			CHECK_EQ(CountOp(b.region, Op::_rvvtypedchunkpartial), 1u);
			unsigned active_mem = 0, active_state = 0;
			for (auto *ins : frames[0].body) {
				if (!store && ins->GetOpcode() == Op::_vchunkload) {
					auto *n = static_cast<InstVChunkLoad *>(ins);
					if (n->active_sew) { CHECK_EQ(n->active_sew, sew); ++active_mem; }
				} else if (store && ins->GetOpcode() == Op::_vchunkstore) {
					auto *n = static_cast<InstVChunkStore *>(ins);
					if (n->active_sew) { CHECK_EQ(n->active_sew, sew); ++active_mem; }
				} else if (!store && ins->GetOpcode() == Op::_vstatechunkstore) {
					auto *n = static_cast<InstVStateChunkStore *>(ins);
					if (n->active_sew) { CHECK_EQ(n->active_sew, sew); ++active_state; }
				}
			}
			CHECK_EQ(active_mem, 1u);
			CHECK_EQ(active_state, store ? 0u : 1u);
			Emit(b);
			auto dis = Disassemble(b.code);
			unsigned const expected = sew == 8 ? 4u : store ? 1u : 2u;
			CHECK_EQ(Count(dis, sew == 4 ? "vmovdqu32" : "vmovdqu64"), expected);
			fprintf(stderr, "    %s%u partial arm uses %s\n", store ? "vse" : "vle",
				sew * 8, sew == 4 ? "vmovdqu32" : "vmovdqu64");
		}
	}
}
} // namespace

int main()
{
	fprintf(stderr, "A13: e64 unit-stride load/store through the shared width rule + base-range guard\n");
	Section1_E64Frames();
	Section2_SwitchOffAndE32();
	Section3_FailClosed();
	Section4_GuardKindConstructor();
	Section5_PartialElementWidth();
	if (g_failures) { fprintf(stderr, "FAILED (%d)\n", g_failures); return 1; }
	fprintf(stderr, "PASSED\n");
	return 0;
}
