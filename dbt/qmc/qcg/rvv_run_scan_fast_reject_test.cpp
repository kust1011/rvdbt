// F1 scan fast-reject: focused equivalence tests. TEST-ONLY; host-code generation only (no execution),
// so it runs on any x86-64 host.
//
// Part A -- DIFFERENTIAL ADMISSION. For every tested (first instruction, vtype, VLEN, budget, boundary),
// whenever RV32Translator::RvvEmptyScanCut returns a value, the UNCHANGED full scan
// (RV32Translator::RvvAdmitVectorRun -> FormRun) must form ZERO members with EXACTLY that cut. The
// fast path must therefore never fire where the full scan forms a run (checked, counted), and its
// coverage of the full scan's empty answers is reported. The first instruction is followed by a
// genuine multi-member run tail, so a vector-member first instruction really can form a run.
//
// Part B -- TRANSLATOR EQUIVALENCE. Real and randomized mixed scalar/vector guest programs are
// translated through the production pipeline (CompilerGenRegionIR + qcg::GenerateCode) with
// config::rvv_run_scan_fast_reject off (the F0 path) and on, under the campaign's M1 and BOTH arms
// (generated from dbt/elfrun.cpp + the campaign FLAGS; rvv_both_boundary_campaign_config.h). The
// generated host code bytes and every run-statistics counter must be identical. An off-vs-off pair
// is built first as a determinism control, so a mismatch cannot be blamed on nondeterministic
// emission. *_force_emit is set so route admission does not ask the host CPU.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qcg/rvv_both_boundary_campaign_config.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::rv32;
using dbt::qir::CodeSegment;
using dbt::qir::CompilerJob;
using dbt::qir::rv32::RV32Translator;

namespace
{
int g_checks = 0, g_failures = 0;
#define CHECK_MSG(cond, ...)                                                                         \
	do {                                                                                         \
		++g_checks;                                                                          \
		if (!(cond)) {                                                                       \
			if (g_failures < 50) {                                                       \
				fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                 \
				fprintf(stderr, __VA_ARGS__);                                        \
				fprintf(stderr, "\n");                                               \
			}                                                                            \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

struct Rng {
	u64 s;
	u32 next()
	{
		s ^= s << 13;
		s ^= s >> 7;
		s ^= s << 17;
		return (u32)(s >> 11);
	}
};

// ---------------------------------------------------------------- encodings
constexpr u32 OpV(u32 f6, u32 vm, u32 vs2, u32 rs1, u32 f3, u32 vd)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (rs1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 VaddVV(u32 vd, u32 vs2, u32 vs1) { return OpV(0, 1, vs2, vs1, 0, vd); }
constexpr u32 VsubVV(u32 vd, u32 vs2, u32 vs1) { return OpV(2, 1, vs2, vs1, 0, vd); }
constexpr u32 VxorVV(u32 vd, u32 vs2, u32 vs1) { return OpV(11, 1, vs2, vs1, 0, vd); }
constexpr u32 VmaxuVV(u32 vd, u32 vs2, u32 vs1) { return OpV(6, 1, vs2, vs1, 0, vd); }
constexpr u32 VmulVV(u32 vd, u32 vs2, u32 vs1) { return OpV(37, 1, vs2, vs1, 2, vd); }
constexpr u32 VsllVI(u32 vd, u32 vs2, u32 imm) { return OpV(37, 1, vs2, imm, 3, vd); }
constexpr u32 Vsetvli(u32 rd, u32 rs1, u32 vt) { return (vt << 20) | (rs1 << 15) | (7u << 12) | (rd << 7) | 0x57u; }
constexpr u32 Addi(u32 rd, u32 rs1, i32 imm) { return ((u32)imm << 20) | (rs1 << 15) | (rd << 7) | 0x13u; }
constexpr u32 Add(u32 rd, u32 rs1, u32 rs2) { return (rs2 << 20) | (rs1 << 15) | (rd << 7) | 0x33u; }
constexpr u32 Lw(u32 rd, u32 rs1, i32 imm) { return ((u32)imm << 20) | (rs1 << 15) | (2u << 12) | (rd << 7) | 0x03u; }
constexpr u32 FaddD(u32 rd, u32 rs1, u32 rs2) { return (1u << 25) | (rs2 << 20) | (rs1 << 15) | (7u << 12) | (rd << 7) | 0x53u; }

u32 VT(u32 sew_log2, i32 lmul_log2, bool ta, bool ma)
{
	u32 const lm = lmul_log2 >= 0 ? (u32)lmul_log2 : (u32)(8 + lmul_log2);
	return (ma ? 0x80u : 0) | (ta ? 0x40u : 0) | (sew_log2 << 3) | lm;
}

// ---------------------------------------------------------------- Part A
struct Coverage {
	u64 cases = 0, fast = 0, full_formed = 0, full_empty_not_fast = 0;
};

void Differential(u32 raw, std::vector<u32> &mem, u32 vtype, u32 vlen, Coverage &cov)
{
	config::vlen_bits = vlen;
	mem[0] = raw;
	uptr const base = (uptr)mem.data();
	u32 const bytes = (u32)(mem.size() * 4);
	for (u32 budget : {0u, 1u, 64u})
		for (u32 boundary : {0u, 4u, bytes}) {
			auto const fast = RV32Translator::RvvEmptyScanCut(base, 0, boundary, budget, vtype);
			auto const full = RV32Translator::RvvAdmitVectorRun(base, 0, boundary, budget, vtype);
			++cov.cases;
			if (fast) {
				++cov.fast;
				CHECK_MSG(full.n_members == 0 && full.cut == *fast,
					  "raw=%08x vtype=%x vlen=%u budget=%u boundary=%u: fast cut %u, full "
					  "members=%u cut=%u",
					  raw, vtype, vlen, budget, boundary, (unsigned)*fast, (unsigned)full.n_members,
					  (unsigned)full.cut);
			} else if (full.n_members == 0) {
				++cov.full_empty_not_fast;
			}
			cov.full_formed += full.n_members > 0;
		}
}

void PartA()
{
	std::vector<u32> mem(64, 0);
	// A genuine run tail after the first instruction.
	for (u32 i = 1; i + 3 < mem.size(); i += 3) {
		mem[i] = VaddVV(8, 2, 3);
		mem[i + 1] = VsubVV(9, 8, 4);
		mem[i + 2] = VxorVV(10, 9, 8);
	}
	std::vector<u32> vtypes = {~0u, 0x80000000u};
	for (u32 sew = 0; sew < 4; ++sew)
		for (i32 lm = -3; lm <= 3; ++lm)
			for (int p = 0; p < 4; ++p)
				vtypes.push_back(VT(sew, lm, p & 1, p & 2));
	Coverage cov;
	// (1) the whole OP-V encoding space by funct6 x vm x funct3, four register patterns.
	u32 const regs[4][3] = {{8, 2, 3}, {0, 0, 0}, {1, 2, 3}, {31, 30, 29}};
	std::vector<u32> opv;
	for (u32 f6 = 0; f6 < 64; ++f6)
		for (u32 vm = 0; vm < 2; ++vm)
			for (u32 f3 = 0; f3 < 8; ++f3)
				for (auto const &r : regs)
					opv.push_back(OpV(f6, vm, r[1], r[2], f3, r[0]));
	// Every vtype at VLEN 1024; a representative subset (unobserved, e32m1, e64m2, e8mf2) elsewhere.
	std::vector<u32> const vt_subset = {~0u, VT(2, 0, false, false), VT(3, 1, true, true), VT(0, -1, true, false)};
	for (u32 vlen : {128u, 512u, 1024u, 2048u})
		for (u32 vt : vlen == 1024 ? vtypes : vt_subset)
			for (u32 raw : opv)
				Differential(raw, mem, vt, vlen, cov);
	// (2) every major opcode with random fields, and fully random words, at three vtypes.
	Rng rng{0x9e3779b97f4a7c15ull};
	for (u32 vlen : {512u, 1024u})
		for (u32 vt : {~0u, VT(2, 0, false, false), VT(3, 1, true, true)}) {
			for (u32 major = 0; major < 128; ++major)
				for (int k = 0; k < 64; ++k)
					Differential((rng.next() & ~0x7fu) | major, mem, vt, vlen, cov);
			for (int k = 0; k < 20000; ++k)
				Differential(rng.next(), mem, vt, vlen, cov);
		}
	// (3) the scalar forms that dominate real guests.
	for (u32 raw : {Addi(5, 5, 1), Add(5, 6, 7), Lw(5, 2, 8), FaddD(1, 2, 3), Vsetvli(10, 10, VT(2, 0, 0, 0)),
			0x00000013u /* nop */, 0x0000006fu /* jal x0,0 */})
		for (u32 vt : vtypes)
			Differential(raw, mem, vt, 1024, cov);
	printf("PART_A cases=%llu fast_reject=%llu full_formed=%llu full_empty_not_fast=%llu\n",
	       (unsigned long long)cov.cases, (unsigned long long)cov.fast, (unsigned long long)cov.full_formed,
	       (unsigned long long)cov.full_empty_not_fast);
	CHECK_MSG(cov.fast > 0 && cov.full_formed > 0, "Part A exercised neither side");
}

// ---------------------------------------------------------------- Part B
struct Runtime final : CompilerRuntime {
	~Runtime()
	{
		if (mem)
			munmap(mem, size);
	}
	void *AllocateCode(size_t n, uint) override
	{
		size = (n + 64 + 4095) & ~size_t(4095);
		mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mem == MAP_FAILED)
			Panic("fast-reject test: code mmap failed");
		return mem;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	void *mem{};
	size_t size{};
};

struct Out {
	std::vector<u8> code;
	rvvrun::Stats stats{};
	int panic_signal = 0; // nonzero: the translation itself aborted (fail-closed Panic)
};

char const *g_label = "";
Out TranslateInProcess(std::vector<u32> const &words, bool fast)
{
	if (getenv("FAST_REJECT_TRACE"))
		fprintf(stderr, "TRANSLATE %s fast=%d\n", g_label, (int)fast);
	config::rvv_run_scan_fast_reject = fast;
	rvvrun::g_stats = rvvrun::Stats{};
	MemArena arena{1u << 22};
	Runtime rt;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(words.size() * 4u)}};
	CompilerJob job(nullptr, reinterpret_cast<uptr>(words.data()), CodeSegment(0u, 0x1000u), std::move(ranges));
	auto *region = CompilerGenRegionIR(&arena, job);
	qir::CodeSegment seg(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&rt, &seg, region, 0);
	Out o;
	o.code.assign(span.begin(), span.end());
	o.stats = rvvrun::g_stats;
	return o;
}

// Each translation runs in a forked child, so a translator Panic (a fail-closed abort that exists
// on the F0 path too) is recorded as an OUTCOME and compared between the two settings instead of
// ending the test. The child sends code bytes and statistics back through a pipe.
Out Translate(std::vector<u32> const &words, bool fast)
{
	int fd[2];
	if (pipe(fd) != 0)
		Panic("pipe");
	pid_t const pid = fork();
	if (pid == 0) {
		close(fd[0]);
		int const devnull = open("/dev/null", O_WRONLY);
		dup2(devnull, 2); // the Panic backtrace is not the test's output
		Out const o = TranslateInProcess(words, fast);
		u64 const n = o.code.size();
		auto wr = [&](void const *p, size_t k) {
			for (size_t off = 0; off < k;) {
				ssize_t const r = write(fd[1], (char const *)p + off, k - off);
				if (r <= 0)
					_exit(3);
				off += (size_t)r;
			}
		};
		wr(&n, sizeof n);
		wr(o.code.data(), n);
		wr(&o.stats, sizeof o.stats);
		_exit(0);
	}
	close(fd[1]);
	Out o;
	std::vector<u8> buf;
	u8 tmp[65536];
	for (ssize_t r; (r = read(fd[0], tmp, sizeof tmp)) > 0;)
		buf.insert(buf.end(), tmp, tmp + r);
	close(fd[0]);
	int st = 0;
	waitpid(pid, &st, 0);
	if (WIFSIGNALED(st)) {
		o.panic_signal = WTERMSIG(st);
		return o;
	}
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || buf.size() < sizeof(u64))
		Panic("fast-reject test: translation child failed without a signal");
	u64 n;
	memcpy(&n, buf.data(), sizeof n);
	if (buf.size() != sizeof n + n + sizeof o.stats)
		Panic("fast-reject test: short child record");
	o.code.assign(buf.begin() + sizeof n, buf.begin() + sizeof n + n);
	memcpy(&o.stats, buf.data() + sizeof n + n, sizeof o.stats);
	return o;
}

bool SameStats(rvvrun::Stats const &a, rvvrun::Stats const &b)
{
	return a.scans == b.scans && a.runs_formed == b.runs_formed && a.multi_member_runs == b.multi_member_runs &&
	       a.members_admitted == b.members_admitted && !memcmp(a.cuts, b.cuts, sizeof a.cuts) &&
	       !memcmp(a.members_hist, b.members_hist, sizeof a.members_hist) && !memcmp(&a, &b, sizeof a);
}

struct PartBTotals {
	u64 programs = 0, bytes = 0, scans_off = 0, multi = 0, panics_both = 0;
};

void Compare(std::vector<u32> const &w, char const *what, PartBTotals &t)
{
	g_label = what;
	Out const off1 = Translate(w, false), off2 = Translate(w, false), on = Translate(w, true);
	CHECK_MSG(off1.panic_signal == off2.panic_signal && off1.panic_signal == on.panic_signal,
		  "%s: translation outcome differs (panic signal off/off/on = %d/%d/%d)", what, off1.panic_signal,
		  off2.panic_signal, on.panic_signal);
	if (off1.panic_signal) {
		++t.panics_both;
		printf("TRANSLATION_PANIC %s: words=", what);
		for (u32 x : w)
			printf("%08x,", x);
		printf("\n");
		CHECK_MSG(false, "%s: both scanner paths panicked (signal %d)", what, off1.panic_signal);
		return;
	}
	bool const det = off1.code == off2.code && SameStats(off1.stats, off2.stats);
	CHECK_MSG(det, "%s: off/off control not deterministic; comparison invalid", what);
	CHECK_MSG(off1.code == on.code, "%s: host code differs with fast-reject (%zu vs %zu bytes)", what,
		  off1.code.size(), on.code.size());
	CHECK_MSG(SameStats(off1.stats, on.stats),
		  "%s: run statistics differ with fast-reject (scans %llu/%llu formed %llu/%llu multi %llu/%llu)", what,
		  (unsigned long long)off1.stats.scans, (unsigned long long)on.stats.scans,
		  (unsigned long long)off1.stats.runs_formed, (unsigned long long)on.stats.runs_formed,
		  (unsigned long long)off1.stats.multi_member_runs, (unsigned long long)on.stats.multi_member_runs);
	++t.programs;
	t.bytes += off1.code.size();
	t.scans_off += off1.stats.scans;
	t.multi += off1.stats.multi_member_runs;
}

void PartB()
{
	u32 const e32 = VT(2, 0, false, false), e64 = VT(3, 0, false, false);
	std::vector<std::vector<u32>> fixed = {
	    // Phase-2 S1 and S4 shapes.
	    {Vsetvli(10, 10, e32), VaddVV(8, 2, 3), VsubVV(9, 8, 4), VmaxuVV(9, 9, 5), VaddVV(10, 9, 8), VxorVV(11, 10, 9)},
	    {VaddVV(8, 2, 3), VsubVV(9, 8, 4), VmaxuVV(9, 9, 5), VaddVV(10, 9, 8), VxorVV(11, 10, 9)},
	    // Scalar code between runs, a scalar prefix, and a scalar tail.
	    {Addi(5, 5, 1), Add(6, 5, 7), Vsetvli(10, 10, e32), VaddVV(8, 2, 3), VsubVV(9, 8, 4), Addi(5, 5, 4),
	     VmulVV(12, 8, 9), VxorVV(13, 12, 8), Add(7, 7, 5), VsllVI(14, 13, 3), VaddVV(15, 14, 2), Addi(6, 6, -1)},
	    // vtype change between runs, and FP scalar code.
	    {Vsetvli(10, 10, e32), VaddVV(8, 2, 3), VsubVV(9, 8, 4), Vsetvli(11, 11, e64), VaddVV(10, 9, 8),
	     VxorVV(11, 10, 9), FaddD(1, 2, 3), FaddD(4, 1, 1), VaddVV(12, 11, 10), VsubVV(13, 12, 11)},
	    // Pure scalar block: every scan is a fast reject.
	    {Addi(5, 5, 1), Add(6, 5, 7), Lw(8, 2, 16), Addi(9, 8, 3), FaddD(1, 2, 3), Add(10, 9, 6)},
	};
	u32 const pool[] = {VaddVV(8, 2, 3), VsubVV(9, 8, 4), VxorVV(10, 9, 8), VmaxuVV(11, 10, 5), VmulVV(12, 8, 9),
			    VsllVI(13, 12, 2), VaddVV(14, 13, 12), Addi(5, 5, 1), Add(6, 5, 7), Lw(7, 2, 8),
			    FaddD(1, 2, 3), Vsetvli(10, 10, e32), Vsetvli(11, 11, e64)};
	Rng rng{0x1234567887654321ull};
	std::vector<std::vector<u32>> random;
	for (int p = 0; p < 150; ++p) {
		std::vector<u32> w;
		if (p % 2)
			w.push_back(Vsetvli(10, 10, e32));
		for (int i = 0; i < 28; ++i)
			w.push_back(pool[rng.next() % (sizeof pool / sizeof pool[0])]);
		random.push_back(w);
	}
	char label[96];
	for (int arm = 0; arm < 2; ++arm) {
		PartBTotals t;
		for (u32 vlen : {512u, 1024u, 2048u}) {
			if (arm == 0)
				campaign_config::ApplyCampaignArm_M1();
			else
				campaign_config::ApplyCampaignArm_BOTH();
			campaign_config::ForceEmitAll();
			config::vlen_bits = vlen;
			config::trace = false;
			for (size_t i = 0; i < fixed.size(); ++i) {
				snprintf(label, sizeof label, "%s VLEN=%u fixed#%zu", arm ? "BOTH" : "M1", vlen, i);
				Compare(fixed[i], label, t);
			}
			for (size_t i = 0; i < random.size(); ++i) {
				snprintf(label, sizeof label, "%s VLEN=%u random#%zu", arm ? "BOTH" : "M1", vlen, i);
				Compare(random[i], label, t);
			}
		}
		printf("PART_B arm=%s programs=%llu host_bytes=%llu scans=%llu multi_member_runs=%llu "
		       "panics=%llu\n",
		       arm ? "BOTH" : "M1", (unsigned long long)t.programs, (unsigned long long)t.bytes,
		       (unsigned long long)t.scans_off, (unsigned long long)t.multi, (unsigned long long)t.panics_both);
		CHECK_MSG(t.multi > 0 && t.scans_off > t.multi, "Part B formed no runs or had no rejectable scans");
	}
}
} // namespace

int main()
{
	setvbuf(stdout, nullptr, _IONBF, 0);
	campaign_config::ApplyCampaignArm_M1();
	campaign_config::ForceEmitAll();
	PartA();
	PartB();
	printf("RVV_RUN_SCAN_FAST_REJECT_TEST checks=%d failures=%d\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
