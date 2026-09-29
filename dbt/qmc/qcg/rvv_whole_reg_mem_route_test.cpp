// A14 (2026-09-05): the whole-register transfer pair (vl<nf>re<eew>.v / vs<nf>r.v) under the same
// guest-memory contract as unit-stride: the QCG frame's guard is vlenb == VLEN/8, vstart == 0 AND
// base <= 2^32 - nregs*VLEN/8 -- the opcode's OWN transfer length, never vl.
//
//   [1] VLEN 128..4096 x nf {1,2,4,8} x EEW {8,16,32,64} (loads) and nf (stores): admitted,
//       with at most four live chunk temporaries per batch. The chunk width is the shared
//       RvvHostChunkGeometry's min(VLEN/8, 64) and chunks_per_reg = (VLEN/8)/width; frame has guard
//       kind VlenbVstartBaseLimit, vlenb == VLEN/8, base_limit == 2^32 - nregs*VLEN/8, n_typed ==
//       2*chunks, chunk windows r*VLEN/8 + k*width in memory and (vd+r)*slot + k*width in CPUState;
//       host: `cmp eax,<limit>` + `ja`, 2*chunks vmovdqu64 on xmm (128) / ymm (256) / zmm
//       (512, 1024), guard base read + one per chunk.
//   [2] fail-closed: x0 base, illegal group (vd not nf-aligned), stores with width != 0, a VLEN
//       that is not a whole number of host chunks (384/768), switch off.
//   [3] the constructor refuses the wrong kind / zero limit / bad vlenb.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qir.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
using namespace dbt;
using namespace dbt::qir;
namespace {
int g_failures = 0;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); ++g_failures; } } while (0)
#define CHECK_EQ(a, b) do { auto _a = (a); auto _b = (b); if (!(_a == _b)) { fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a, #b, (long long)_a, (long long)_b); ++g_failures; } } while (0)
// vl<nf>re<eew>.v vd,(rs1): LOAD-FP | vd<<7 | width<<12 | rs1<<15 | lumop 01000<<20 | vm 1<<25 | mop 0 | mew 0 | nf<<29
constexpr u32 W(u32 eew) { return eew == 8 ? 0b000u : eew == 16 ? 0b101u : eew == 32 ? 0b110u : 0b111u; }
constexpr u32 VlNre(u32 nf, u32 eew, u32 rs1, u32 vd) { return 0b0000111u | (vd << 7) | (W(eew) << 12) | (rs1 << 15) | (0b01000u << 20) | (1u << 25) | ((nf - 1) << 29); }
constexpr u32 VsNr(u32 nf, u32 rs1, u32 vs3, u32 width = 0) { return 0b0100111u | (vs3 << 7) | (width << 12) | (rs1 << 15) | (0b01000u << 20) | (1u << 25) | ((nf - 1) << 29); }
static_assert(VlNre(1, 8, 16, 8) == 0x02880407u, "vl1re8.v v8,(a6)");
static_assert(VsNr(2, 16, 8) == 0x22880427u, "vs2r.v v8,(a6)");
constexpr u32 BASE = 16;
struct TestCompilerRuntime final : CompilerRuntime {
	~TestCompilerRuntime() { if (mem) munmap(mem, size); }
	void *AllocateCode(size_t sz, uint) override {
		size = (sz + 64 + 4095) & ~size_t(4095);
		mem = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mem == MAP_FAILED) std::abort();
		return mem;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	void *mem{};
	size_t size{};
};
struct Env { u32 vlen = 512; bool whole = true; bool direct = true; };
void ApplyEnv(Env const &e)
{
	config::trace = false;
	config::vlen_bits = e.vlen; config::rvv_qcg_whole_reg = e.whole; config::rvv_qcg_whole_reg_force_emit = true;
	config::aot_use_llvm = false; config::rvv_vector_ssa = false; config::rvv_direct = e.direct; config::rvv_verify = false; config::rvv_lowering = 1;
	config::rvv_vector_run = false; config::rvv_run_live_range_split = false;
	config::rvv_qcg_typed_chunk = false; config::rvv_qcg_typed_chunk_vle = false; config::rvv_qcg_typed_chunk_vse = false;
	config::rvv_qcg_typed_chunk_falu = false; config::rvv_qcg_typed_chunk_fma = false; config::rvv_qcg_narrow_chunk_width = false;
	config::rvv_qcg_partial_vl = false; config::rvv_qcg_direct_setvl = false; config::rvv_qcg_diag_chunk = false; config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_hit_counter = false; config::rvv_lane_census = false; config::rvv_lane_census_out = nullptr;
}
struct Built { MemArena arena{1u << 21}; std::vector<u32> words; Region *region = nullptr; TestCompilerRuntime cr; std::vector<u8> code; };
void Translate(Built &b, std::vector<u32> const &words, Env const &e)
{
	ApplyEnv(e); b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}
void Emit(Built &b) { qir::CodeSegment seg(0u, 0x1000u); auto sp = qcg::GenerateCode(&b.cr, &seg, b.region, 0); b.code.assign(sp.begin(), sp.end()); }
struct Frame { InstRVVTypedChunkBegin *begin = nullptr; std::vector<Inst *> body; };
std::vector<Frame> FindFrames(Region *r)
{
	std::vector<Frame> out; Frame cur; bool open = false;
	for (auto &bb : r->GetBlocks()) for (auto &ins : bb.ilist) {
		if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) { cur = Frame{}; cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins); open = true; }
		else if (ins.GetOpcode() == Op::_rvvtypedchunkend) { if (open) { out.push_back(cur); open = false; } }
		else if (open) cur.body.push_back(&ins);
	}
	return out;
}
unsigned CountStub(Region *r, RuntimeStubId s) { unsigned n = 0; for (auto &bb : r->GetBlocks()) for (auto &ins : bb.ilist) if (ins.GetOpcode() == Op::_hcall) n += static_cast<InstHcall *>(&ins)->stub == s; return n; }
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_a14_emit_XXXXXX"; int fd = mkstemp(path); if (fd < 0) return {};
	size_t w = 0; while (w < code.size()) { ssize_t n = write(fd, code.data() + w, code.size() - w); if (n <= 0) { close(fd); unlink(path); return {}; } w += (size_t)n; }
	close(fd); std::string cmd = std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path + " 2>&1";
	FILE *p = popen(cmd.c_str(), "r"); if (!p) { unlink(path); return {}; }
	std::vector<std::string> ls; char buf[1024]; while (fgets(buf, sizeof buf, p)) { std::string l(buf); if (!l.empty() && l.back() == '\n') l.pop_back(); ls.push_back(l); }
	int rc = pclose(p); unlink(path); if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) return {};
	size_t last = 0; for (size_t i = 0; i < ls.size(); ++i) if (ls[i].find("vmovdqu64") != std::string::npos) last = i;
	return std::vector<std::string>(ls.begin(), ls.begin() + (last ? last + 1 : 0));
}
unsigned Count(std::vector<std::string> const &ls, std::string const &s) { unsigned n = 0; for (auto const &l : ls) n += l.find(s) != std::string::npos; return n; }
std::string Hex(u32 v) { char b[32]; snprintf(b, sizeof b, "0x%x", v); return b; }
u32 GprOffs(u32 r) { return (u32)(offsetof(CPUState, gpr) + 4u * r); }
u32 VregOffs(u32 r) { return (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg)) + r * rv32::VLEN_MAX_BYTES; }

void CheckFrame(u32 vlen, u32 nf, u32 eew, bool store)
{
	u32 const word = store ? VsNr(nf, BASE, 8) : VlNre(nf, eew, BASE, 8);
	u32 const reg_bytes = vlen / 8, cb = reg_bytes < 64 ? reg_bytes : 64, cpr = reg_bytes / cb, chunks = nf * cpr;
	Built b; Translate(b, {word}, Env{vlen, true});
	auto f = FindFrames(b.region);
	CHECK_EQ(f.size(), (size_t)1); if (f.size() != 1) return;
	auto *bg = f[0].begin;
	CHECK(bg->guard_kind == InstRVVTypedChunkBegin::GuardKind::VlenbVstartBaseLimit);
	CHECK_EQ(bg->vlenb, vlen / 8); CHECK_EQ(bg->base_limit, 0u - nf * reg_bytes); CHECK_EQ(bg->base_state_offs, (u16)GprOffs(BASE));
	CHECK_EQ(bg->n_typed, (u16)(2 * chunks));
	unsigned mem = 0, st = 0;
	auto rk = [&](u32 c, u32 &r, u32 &k) { r = c / cpr; k = c % cpr; };
	for (auto *ins : f[0].body) {
		u32 r, k;
		if (ins->GetOpcode() == Op::_vchunkload) { rk(mem, r, k); auto *l = static_cast<InstVChunkLoad *>(ins); CHECK_EQ(l->base_state_offs, (u16)GprOffs(BASE)); CHECK_EQ(l->disp, (u16)(r * reg_bytes + k * cb)); ++mem; }
		else if (ins->GetOpcode() == Op::_vstatechunkstore) { rk(st, r, k); auto *s = static_cast<InstVStateChunkStore *>(ins); CHECK_EQ(s->offs, (u16)(VregOffs(8 + r) + k * cb)); ++st; }
		else if (ins->GetOpcode() == Op::_vstatechunkload) { rk(st, r, k); auto *l = static_cast<InstVStateChunkLoad *>(ins); CHECK_EQ(l->offs, (u16)(VregOffs(8 + r) + k * cb)); ++st; }
		else if (ins->GetOpcode() == Op::_vchunkstore) { rk(mem, r, k); auto *s = static_cast<InstVChunkStore *>(ins); CHECK_EQ(s->base_state_offs, (u16)GprOffs(BASE)); CHECK_EQ(s->disp, (u16)(r * reg_bytes + k * cb)); ++mem; }
	}
	CHECK_EQ(mem, chunks); CHECK_EQ(st, chunks);
	unsigned live = 0, peak = 0;
	for (auto *ins : f[0].body) {
		if (ins->GetOpcode() == Op::_vchunkload || ins->GetOpcode() == Op::_vstatechunkload)
			peak = std::max(peak, ++live);
		if (ins->GetOpcode() == Op::_vchunkstore || ins->GetOpcode() == Op::_vstatechunkstore) {
			CHECK(live > 0);
			--live;
		}
	}
	CHECK_EQ(live, 0u); CHECK(peak <= 4);
	Emit(b); auto dis = Disassemble(b.code); CHECK(!dis.empty());
	CHECK_EQ(Count(dis, "vmovdqu64"), 2 * chunks);
	// A17: every data move is on the host register class the geometry chose -- and ONLY that one.
	CHECK_EQ(Count(dis, "xmm"), cb == 16 ? 2 * chunks : 0u); CHECK_EQ(Count(dis, "ymm"), cb == 32 ? 2 * chunks : 0u); CHECK_EQ(Count(dis, "zmm"), cb == 64 ? 2 * chunks : 0u);
	CHECK_EQ(Count(dis, "cmp    eax," + Hex(0u - nf * reg_bytes)), 1u); CHECK_EQ(Count(dis, "ja "), 1u);
	CHECK_EQ(Count(dis, "mov    eax,DWORD PTR [r13+" + Hex(GprOffs(BASE)) + "]"), chunks + 1u);
	CHECK_EQ(Count(dis, "add    eax") + Count(dis, "add    rax") + Count(dis, "lea    "), 0u);
}
bool Refused(u32 word, Env const &e, bool store)
{
	Built b; Translate(b, {word}, e);
	return FindFrames(b.region).empty() && CountStub(b.region, store ? RuntimeStubId::id_rv32_vsNr : RuntimeStubId::id_rv32_vlNre) == 1u;
}
bool DiesInChild(std::function<void()> fn) { fflush(stderr); pid_t pid = fork(); if (pid == 0) { freopen("/dev/null", "w", stderr); fn(); _exit(0); } int st = 0; waitpid(pid, &st, 0); return !WIFEXITED(st) || WEXITSTATUS(st) != 0; }

extern "C" __attribute__((noinline, naked)) void WholeEnter(void *, void *, void *);
extern "C" __attribute__((noinline, naked)) void WholeEnter(void *, void *, void *)
{
	asm("pushq %rbp\n\tpushq %rbx\n\tpushq %r12\n\tpushq %r13\n\tpushq %r14\n\tpushq %r15\n\t"
	    "movq %rdi,%r13\n\tmovq %rsi,%rbp\n\t");
	asm("sub $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("callq *%rdx\n\t");
	asm("add $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("popq %r15\n\tpopq %r14\n\tpopq %r13\n\tpopq %r12\n\tpopq %rbx\n\tpopq %rbp\n\tretq\n\t");
}

void CheckExecution(u32 vlen, u32 nf, u32 eew, bool store)
{
	u32 const vb = vlen / 8, total = nf * vb;
	Built b;
	Translate(b, {store ? VsNr(nf, BASE, 8) : VlNre(nf, eew, BASE, 8)}, Env{vlen, true});
	Emit(b);
	auto *code = static_cast<u8 *>(b.cr.mem);
	size_t n = b.code.size();
	if (code[0] == 0x51) code[n++] = 0x59;
	code[n] = 0xc3;
	CHECK_EQ(mprotect(code, b.cr.size, PROT_READ | PROT_EXEC), 0);
	auto *memory = static_cast<u8 *>(mmap(nullptr, 16384, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0));
	CHECK(memory != MAP_FAILED);
	if (memory == MAP_FAILED) return;
	for (u32 alignment : {0u, 1u, 7u}) for (u32 vl : {0u, 1u, 17u})
		for (u32 start : {0u, 1u, total / (store ? 1u : eew / 8u)}) {
		CPUState state(nullptr);
		memset(static_cast<void *>(&state), 0, sizeof state);
		for (u32 r = 0; r < 32; ++r) for (u32 i = 0; i < rv32::VLEN_MAX_BYTES; ++i)
			state.vec.vreg[r][i] = (u8)(r * 37u + i * 11u + 3u);
		for (u32 i = 0; i < 16384; ++i) memory[i] = (u8)(i * 13u + 9u);
		auto expected = state.vec;
		std::vector<u8> expected_mem(memory, memory + 16384);
		u32 const base = 4096 + alignment;
		u32 const start_byte = start * (store ? 1u : eew / 8u);
		for (u32 i = start_byte; i < total; ++i) {
			if (store) expected_mem[base + i] = state.vec.vreg[8 + i / vb][i % vb];
			else expected.vreg[8 + i / vb][i % vb] = memory[base + i];
		}
		state.vec.vlenb = vb;
		state.vec.vl = vl;
		state.vec.vtype = 0x80000000u; // Whole-register transfers ignore vill and vl.
		state.vec.vstart = start;
		state.gpr[BASE] = (u32)(uptr)(memory + base);
		WholeEnter(&state, nullptr, code);
		CHECK_EQ(memcmp(state.vec.vreg.data(), expected.vreg.data(), sizeof expected.vreg), 0);
		CHECK_EQ(memcmp(memory, expected_mem.data(), 16384), 0);
		CHECK_EQ(state.vec.vstart, 0u);
		CHECK_EQ(state.vec.vl, vl);
		CHECK_EQ(state.vec.vtype, 0x80000000u);
	}
	munmap(memory, 16384);
}
} // namespace
int main(int argc, char **argv)
{
	fprintf(stderr, "A14: whole-register transfers under the guest-memory contract\n");
	fprintf(stderr, "[1] shape + guard at VLEN 128/256/512/1024 x nf x EEW (loads) / nf (stores)\n");
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u, 4096u}) for (u32 nf : {1u, 2u, 4u, 8u}) {
		for (u32 eew : {8u, 16u, 32u, 64u}) CheckFrame(vlen, nf, eew, false);
		CheckFrame(vlen, nf, 0, true);
		u32 const cb = vlen / 8 < 64 ? vlen / 8 : 64, chunks = nf * (vlen / 8 / cb);
		fprintf(stderr, "    VLEN %4u nf %u: %u native chunks, batches <= 4\n", vlen, nf, chunks);
	}
	fprintf(stderr, "[2] fail-closed\n");
	CHECK(Refused(VlNre(1, 8, 0, 8), Env{512, true}, false));            // x0 base
	CHECK(Refused(VsNr(1, 0, 8), Env{512, true}, true));
	CHECK(Refused(VlNre(2, 8, BASE, 9), Env{512, true}, false));         // vd not nf-aligned
	CHECK(Refused(VsNr(4, BASE, 30), Env{512, true}, true));             // group past v31
	{ // a "vs1r.v" word with width != 0 is NOT a whole-register store to the decoder (rv32_decode.h pins
	  // funct3 == 000 for Op::_vsNr), so the admission row for it is unreachable; what can be checked
	  // is that no whole-register frame is built for such a word.
		Built b; Translate(b, {VsNr(1, BASE, 8, 0b110)}, Env{512, true});
		CHECK(FindFrames(b.region).empty());
	}
	CHECK(Refused(VlNre(1, 8, BASE, 8), Env{384, true}, false));         // A17: not a whole number of host chunks
	CHECK(Refused(VsNr(1, BASE, 8), Env{768, true}, true));
	CHECK(Refused(VlNre(1, 8, BASE, 8), Env{512, false}, false));        // switch off, at every width
	CHECK(Refused(VsNr(1, BASE, 8), Env{512, false}, true));
	CHECK(Refused(VlNre(1, 8, BASE, 8), Env{128, false}, false));
	CHECK(Refused(VsNr(1, BASE, 8), Env{256, false}, true));
	CHECK(Refused(VlNre(1, 8, BASE, 8), Env{512, true, false}, false));
	CHECK(Refused(VsNr(1, BASE, 8), Env{512, true, false}, true));
	CHECK(!Refused(VlNre(8, 8, BASE, 8), Env{4096, true}, false));
	CHECK(!Refused(VsNr(8, BASE, 8), Env{4096, true}, true));
	// A17 POSITIVE: 128/256 no longer keep the helper (they were the two "refused" rows before)
	CHECK(!Refused(VlNre(1, 8, BASE, 8), Env{128, true}, false));
	CHECK(!Refused(VsNr(1, BASE, 8), Env{256, true}, true));
	fprintf(stderr, "    exclusions checked, including global direct=0; 128/256 admitted\n");
	fprintf(stderr, "[3] constructor\n");
	using GK = InstRVVTypedChunkBegin::GuardKind;
	CHECK(DiesInChild([] { InstRVVTypedChunkBegin n(64u, 0u, RuntimeStubId::id_rv32_vlNre, 2, GK::VlenbVstart, 64u, 0xffffffc0u); }));
	CHECK(DiesInChild([] { InstRVVTypedChunkBegin n(64u, 0u, RuntimeStubId::id_rv32_vlNre, 2, GK::VlenbVstartBaseLimit, 64u, 0u); }));
	CHECK(DiesInChild([] { InstRVVTypedChunkBegin n(48u, 0u, RuntimeStubId::id_rv32_vlNre, 2, GK::VlenbVstartBaseLimit, 64u, 0xffffffc0u); }));   // not a power of two
	CHECK(DiesInChild([] { InstRVVTypedChunkBegin n(8u, 0u, RuntimeStubId::id_rv32_vlNre, 2, GK::VlenbVstartBaseLimit, 64u, 0xffffffc0u); }));    // below 16
	CHECK(DiesInChild([] { InstRVVTypedChunkBegin n(65536u, 0u, RuntimeStubId::id_rv32_vlNre, 2, GK::VlenbVstartBaseLimit, 64u, 0xffff0000u); })); // not representable
	for (u32 vb : {16u, 32u, 64u, 128u, 256u, 512u})
		CHECK(!DiesInChild([vb] { InstRVVTypedChunkBegin n(vb, 0u, RuntimeStubId::id_rv32_vlNre, 2, GK::VlenbVstartBaseLimit, 64u, 0u - vb); }));
	fprintf(stderr, "[4] A14-RESTART: the helper honours vstart (suffix moved, prefix kept, >= evl moves nothing)\n");
	{
		using namespace dbt::rv32;
		std::vector<u8> mem(1u << 16);
		for (u32 i = 0; i < mem.size(); ++i) mem[i] = (u8)(i * 31u + 7u);
		for (u32 vlen : {128u, 512u, 1024u}) {
			u32 const vb = vlen / 8;
			for (u32 nf : {1u, 2u, 4u, 8u}) for (u32 eew : {1u, 2u, 4u, 8u}) {
				u32 const evl = nf * vb / eew;
				for (u32 vstart : {1u, vb / eew + 1u, evl - 1u, evl, evl + 7u}) {
					if (nf == 1 && vstart == vb / eew + 1u) continue;
					auto vs = std::make_unique<VectorState>();
					for (u32 r = 0; r < nf; ++r) for (u32 i = 0; i < vb; ++i) vs->vreg[8 + r][i] = 0xA5;
					u32 start_byte = 0;
					bool const moves = rvv_ref::whole_reg_start_byte(vstart, eew, nf, vlen, &start_byte);
					CHECK_EQ(moves, vstart < evl);
					if (moves) { CHECK_EQ(start_byte, vstart * eew); rvv_ref::whole_reg_load(*vs, 8, mem.data(), 4096, nf, vlen, start_byte); }
					for (u32 r = 0; r < nf; ++r) for (u32 i = 0; i < vb; ++i) {
						u32 const gi = r * vb + i; u8 const want = (moves && gi >= start_byte) ? mem[4096 + gi] : 0xA5;
						if (vs->vreg[8 + r][i] != want) { CHECK(false); r = nf; break; }
					}
					// store: the memory prefix keeps its canary
					std::vector<u8> out(4096 + nf * vb + 64, 0xEE);
					for (u32 r = 0; r < nf; ++r) for (u32 i = 0; i < vb; ++i) vs->vreg[8 + r][i] = (u8)(r * 7 + i);
					if (moves) rvv_ref::whole_reg_store(*vs, 8, out.data(), 4096, nf, vlen, start_byte);
					for (u32 gi = 0; gi < nf * vb + 8; ++gi) {
						u8 const want = (moves && gi >= start_byte && gi < nf * vb) ? (u8)((gi / vb) * 7 + gi % vb) : 0xEE;
						if (out[4096 + gi] != want) { CHECK(false); break; }
					}
				}
			}
		}
		// the beyond-evl rule and the 64-bit start arithmetic
		u32 sb = 0;
		CHECK(!rvv_ref::whole_reg_start_byte(0xffffffffu, 8, 8, 1024, &sb));
		CHECK(!rvv_ref::whole_reg_start_byte(1024u, 1, 8, 1024, &sb));   // == evl
		CHECK(rvv_ref::whole_reg_start_byte(1023u, 1, 8, 1024, &sb) && sb == 1023u);
		fprintf(stderr, "    3 VLEN x 4 nf x 4 EEW x 5 vstart: prefix kept, suffix moved, >= evl untouched\n");
	}
	if (argc == 2 && std::string(argv[1]) == "--execute") {
		if (!__builtin_cpu_supports("avx512f") || !__builtin_cpu_supports("avx512vl")) return 77;
		for (u32 vl : {128u, 256u, 512u, 1024u, 2048u, 4096u}) for (u32 nf : {1u, 2u, 4u, 8u}) {
			fprintf(stderr, "execute VLEN=%u nf=%u\n", vl, nf);
			for (u32 eew : {8u, 16u, 32u, 64u}) CheckExecution(vl, nf, eew, false);
			CheckExecution(vl, nf, 8, true);
		}
		fprintf(stderr, "Executed 3240 cases: 6 widths, 4 groups, 5 forms, 3 alignments, 3 vl, 3 vstart\n");
	}
	if (g_failures) { fprintf(stderr, "FAILED (%d)\n", g_failures); return 1; }
	fprintf(stderr, "PASSED\n"); return 0;
}
