// Z4B: the focused generated-code + value test for --rvv-qcg-typed-chunk-vlse-gather-census.
//
// WHAT THIS FILE OWNS, and only this. That the two Z4B counters mean what the report says they
// mean, and that arming them is the ONLY thing that changes. It owns no admission claim (the route
// test owns that), and it re-derives no architectural result of its own beyond re-checking, in
// every executed cell, that the census did not perturb one.
//
// It is deliberately NOT a second copy of the Z3 value differential. Z3's 6,489-cell sweep already
// owns the architectural result of the gather body; this file runs the smallest cell set that can
// separate the two counters from each other and from zero.
//
// -------------------------------------------------------------------------------------------
// [A] GENERATED CODE. The default-off inertness requirement, checked per cell rather than asserted.
//
//   A1  census off, gather off  vs  census ON, gather off      -> byte-identical.
//       Failure path: the increments were placed outside EmitRvvStridedGather's admission
//       predicate, so a node that has no gather body still pays for the diagnostic.
//   A2  census off, gather off  vs  census off, gather ON       -> Z3's own inertness, restated
//       here only so that A3's byte delta has a meaning. (Refused shapes only; on an admitted
//       shape the gather body is exactly what SHOULD differ.)
//   A3  census off, gather ON   vs  census ON, gather ON        -> differs by EXACTLY the two `inc`
//       sequences, one per counter, each appearing exactly once in the armed stream and zero
//       times in the unarmed one.
//       Failure path: an increment emitted per CHUNK instead of per execution (it would appear
//       twice at VLEN 1024), or emitted on only one of the two exits, or emitted unconditionally.
//
//   NOTE ON SCOPE. A1-A3 are WITHIN-build checks. The cross-build half of the requirement -- that
//   this tree's default-off bytes equal the pre-Z4B tree's bytes -- cannot be checked from inside
//   one binary and is carried by the round's `rvv_vlse_gather_route_test --off-hashes`/`--dump`
//   comparison against a snapshot build. This file does not claim it.
//
// -------------------------------------------------------------------------------------------
// [B] VALUE / SEMANTICS. The emitted bytes are executed against a real 4 GiB reservation and the
//     counters are read back afterwards.
//
//   B1  fast + fallback == 1 on every execution of an emitted gather body.
//       Failure path: an exit that increments neither (it would read 0) or both (2).
//   B2  fast == 1 exactly when vstart == 0 AND no architecturally ACTIVE element's guest address
//       exceeds 0xFFFFFFFC; fallback == 1 otherwise. The predicate is recomputed in this file from
//       the cell's own parameters, never read back from the emitted code.
//       Failure path: counting the vstart exit as a completion, or missing the per-chunk
//       address-space-top exit -- the exact two cases Z4 could only derive.
//   B3  with the census off, both counters stay 0 no matter what executed.
//       Failure path: a counter that is incremented by something other than this switch.
//   B4  every executed cell still reproduces rvv_ref::load_strided, armed and unarmed.
//       Failure path: the `inc` clobbering state the body needs (it writes only flags, and B4 is
//       what makes that a checked claim rather than a comment).
//
// HOST NOTE. The gather body is emitted only on AVX-512F+BMI2, and this file does NOT set the
// force-emit audit switch, because it EXECUTES what it emits. On a host without AVX-512 the [B]
// section reports itself skipped; [A] still runs, because it only assembles.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
int g_checks = 0, g_failures = 0;

#define CHECK_MSG(cond, ...)                                                                         \
	do {                                                                                         \
		++g_checks;                                                                          \
		if (!(cond)) {                                                                       \
			fprintf(stderr, "  FAIL %s:%d: ", __FILE__, __LINE__);                       \
			fprintf(stderr, __VA_ARGS__);                                                \
			fprintf(stderr, "\n");                                                       \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

StateReg regs[] = {{(u16)offsetof(CPUState, gpr), VType::I32, "x0"}};
StateInfo state_info{regs, 1};

struct Runtime final : CompilerRuntime {
	~Runtime()
	{
		if (mem)
			munmap(mem, size);
	}
	void *AllocateCode(size_t n, uint) override
	{
		size = (n + 64 + 4095) & ~size_t(4095);
		mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mem == MAP_FAILED)
			Panic("z4b census test: code mmap");
		return mem;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	void *mem{};
	size_t size{};
};

// The generated-code entry contract, identical to the Z3 value differential's.
extern "C" __attribute__((noinline, naked)) void Enter(void *, void *, void *);
extern "C" __attribute__((noinline, naked)) void Enter(void *, void *, void *)
{
	asm("pushq %rbp\n\tpushq %rbx\n\tpushq %r12\n\tpushq %r13\n\tpushq %r14\n\tpushq %r15\n\t"
	    "movq %rdi,%r13\n\tmovq %rsi,%rbp\n\t");
	asm("sub $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("callq *%rdx\n\t");
	asm("add $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("popq %r15\n\tpopq %r14\n\tpopq %r13\n\tpopq %r12\n\tpopq %rbx\n\tpopq %rbp\n\tretq\n\t");
}

// ---------------------------------------------------------------------------------------------
// Guest memory, same shape as the Z3 value differential: a 4 GiB PROT_NONE reservation with
// sub-ranges mapped into it, every byte a function of its own guest address, and the page PAST the
// reservation mapped with a constant that appears nowhere in guest memory -- in production that
// page is rvdbt's own heap, so a missing address-space-top guard becomes a deterministic value
// mismatch instead of a lucky SIGSEGV.
// ---------------------------------------------------------------------------------------------
constexpr u64 ASPACE = 1ull << 32;
constexpr u32 PAGE = 4096u;
constexpr u32 REGION_LOW = 0x00100000u;
constexpr u32 REGION_HIGH = 0x80010000u; // >= 2^31: the signed-index case
constexpr u32 REGION_BYTES = 0x10000u;
constexpr u8 PAST_END_FILL = 0xdd;
constexpr u32 TOP_LIMIT = 0xfffffffcu; // the emitted guard's own threshold

u8 *g_base = nullptr;

u8 PatternByte(u32 gaddr)
{
	u32 h = gaddr * 2654435761u;
	h ^= h >> 15;
	u8 b = (u8)(h ^ (gaddr >> 3));
	return b == PAST_END_FILL ? (u8)(b + 1) : b;
}

void MapAndFill(u32 gaddr, u32 len)
{
	void *p = ::mmap(g_base + gaddr, len, PROT_READ | PROT_WRITE,
			 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		Panic("z4b census test: guest mmap");
	for (u32 i = 0; i < len; ++i)
		g_base[gaddr + i] = PatternByte(gaddr + i);
}

void SetUpAddressSpace()
{
	void *r = ::mmap(nullptr, ASPACE + PAGE, PROT_NONE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (r == MAP_FAILED)
		Panic("z4b census test: address space reservation");
	g_base = (u8 *)r;
	void *q = ::mmap(g_base + ASPACE, PAGE, PROT_READ | PROT_WRITE,
			 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (q == MAP_FAILED)
		Panic("z4b census test: past-the-end page");
	memset(g_base + ASPACE, PAST_END_FILL, PAGE);
}

// ---------------------------------------------------------------------------------------------
// Emission.
// ---------------------------------------------------------------------------------------------
constexpr u32 VD = 8, RS1 = 16, RS2 = 5;

struct Emitted {
	Runtime rt;
	MemArena arena{1u << 21};
	std::vector<u8> bytes; // a copy, so two builds can be compared after both exist
	u8 *code = nullptr;
	bool has_gather = false;
};

bool HasIota(u8 const *p, size_t n)
{
	u8 pat[64]{};
	for (u32 e = 0; e < 16; ++e)
		memcpy(pat + e * 4, &e, 4);
	if (n < sizeof(pat))
		return false;
	for (size_t i = 0; i + sizeof(pat) <= n; ++i)
		if (!memcmp(p + i, pat, sizeof(pat)))
			return true;
	return false;
}

void ApplyCfg(u32 vlen, bool gather, bool census)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = false;
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_vlse_gather = gather;
	config::rvv_qcg_typed_chunk_vlse_gather_force_emit = false;
	config::rvv_qcg_typed_chunk_vlse_gather_census = census;
}

// `sew`/`isew` are the node's element widths; a shape with sew != 4 is one the gather route refuses,
// which is exactly what section [A]'s A1/A2 need.
void Build(Emitted &e, u32 vlen, u32 vlmax, u32 sew, bool gather, bool census)
{
	ApplyCfg(vlen, gather, census);
	Region *region = e.arena.New<Region>(&e.arena, &state_info);
	Builder b(region->CreateBlock());
	b.Create_vmemorynative((u8)VD, (u8)RS1, (u8)RS2, (u8)sew, (u8)sew, /*mode=*/1,
			       (u16)(vlen / 8), /*store=*/false, /*masked=*/false, /*nf=*/1,
			       /*fieldregs=*/1, (u16)vlmax);
	qcg::ArchTraits::init();
	auto code = qcg::GenerateCode(&e.rt, nullptr, region, 0);
	if (code.empty())
		Panic("z4b census test: empty region");
	e.bytes.assign(code.data(), code.data() + code.size());
	e.code = code.data();
	size_t k = code.size();
	if (e.code[0] == 0x51)	    // push rcx (non-leaf frame)
		e.code[k++] = 0x59; // pop rcx
	e.code[k++] = 0xc3;	    // ret
	e.has_gather = HasIota(e.bytes.data(), e.bytes.size());
}

// ---------------------------------------------------------------------------------------------
// Finding a census increment in the emitted bytes, derived rather than pasted.
//
// The emitted form is `mov rax, <absolute address of the counter>` followed by `inc qword ptr
// [rax]`. asmjit picks `movabs rax, imm64` (48 B8 + 8 bytes) when the address does not fit in an
// unsigned 32-bit immediate and the short `mov eax, imm32` (B8 + 4 bytes) when it does; which one a
// given run gets depends on where the loader put .bss, so the test accepts either and reports which.
// `inc qword ptr [rax]` is REX.W + FF /0 with mod=00, rm=000: 48 FF 00.
//
// REQUIRING THE `inc` TO FOLLOW THE ADDRESS IS THE POINT. Searching for the address alone would
// also match a stray constant; this matches an actual increment of that specific counter.
// ---------------------------------------------------------------------------------------------
u8 const INC_RAX[3] = {0x48, 0xff, 0x00};

size_t CountSub(std::vector<u8> const &hay, std::vector<u8> const &ned)
{
	if (ned.empty() || hay.size() < ned.size())
		return 0;
	size_t n = 0;
	for (size_t i = 0; i + ned.size() <= hay.size(); ++i)
		if (!memcmp(hay.data() + i, ned.data(), ned.size()))
			++n;
	return n;
}

struct IncSite {
	size_t count = 0;   // how many times this counter is incremented in the stream
	size_t enc_len = 0; // bytes the whole two-instruction sequence occupies
};

IncSite FindInc(std::vector<u8> const &code, void const *addr)
{
	u64 const a = (u64)(uptr)addr;
	for (int form = 0; form < 2; ++form) {
		std::vector<u8> pat;
		if (form == 0) { // movabs rax, imm64
			if (a <= 0xffffffffull)
				continue;
			pat = {0x48, 0xb8};
			for (int i = 0; i < 8; ++i)
				pat.push_back((u8)(a >> (8 * i)));
		} else { // mov eax, imm32
			if (a > 0xffffffffull)
				continue;
			pat = {0xb8};
			for (int i = 0; i < 4; ++i)
				pat.push_back((u8)(a >> (8 * i)));
		}
		pat.insert(pat.end(), INC_RAX, INC_RAX + 3);
		IncSite r;
		r.enc_len = pat.size();
		r.count = CountSub(code, pat);
		return r;
	}
	return {};
}

void *const ADDR_FAST = (void *)&dbt::rv32::g_vlse_gather_fast;
void *const ADDR_FB = (void *)&dbt::rv32::g_vlse_gather_fallback;

// ---------------------------------------------------------------------------------------------
// [A] Generated code.
// ---------------------------------------------------------------------------------------------
struct Shape {
	char const *name;
	u32 vlen, vtype, sew;
	bool admitted; // does the gather route admit this shape at all
};

Shape const SHAPES[] = {
    {"e32m1 @512", 512, 0xd0u, 4, true},   {"e32m1 @1024", 1024, 0xd0u, 4, true},
    {"e32m2 @512", 512, 0xd1u, 4, true},   {"e32m2 @1024", 1024, 0xd1u, 4, true},
    {"e32mf2 @512", 512, 0xd7u, 4, true},  {"e64m1 @512 (refused)", 512, 0xd8u, 8, false},
    {"e16m1 @1024 (refused)", 1024, 0xc8u, 2, false},
};

void CheckEmitted(Shape const &sh)
{
	u32 const vlmax = rv32::compute_vlmax(rv32::VType{sh.vtype}, sh.vlen);
	Emitted g0c0, g0c1, g1c0, g1c1;
	Build(g0c0, sh.vlen, vlmax, sh.sew, false, false);
	Build(g0c1, sh.vlen, vlmax, sh.sew, false, true);
	Build(g1c0, sh.vlen, vlmax, sh.sew, true, false);
	Build(g1c1, sh.vlen, vlmax, sh.sew, true, true);

	// A1: with the gather route OFF the census must be invisible -- there is no body to count.
	CHECK_MSG(g0c0.bytes == g0c1.bytes,
		  "%s A1: census moved bytes with the gather route off (%zu vs %zu)", sh.name,
		  g0c0.bytes.size(), g0c1.bytes.size());
	// A2: Z3's own inertness on a REFUSED shape, restated so A3's delta has a reference.
	if (!sh.admitted)
		CHECK_MSG(g0c0.bytes == g1c0.bytes,
			  "%s A2: the gather switch moved bytes on a refused shape", sh.name);

	// Nothing unarmed may carry either increment, ever.
	CHECK_MSG(FindInc(g0c0.bytes, ADDR_FAST).count == 0 &&
		      FindInc(g0c0.bytes, ADDR_FB).count == 0,
		  "%s: an unarmed build carries a census inc", sh.name);
	CHECK_MSG(FindInc(g1c0.bytes, ADDR_FAST).count == 0 &&
		      FindInc(g1c0.bytes, ADDR_FB).count == 0,
		  "%s: the unarmed gather build carries a census inc", sh.name);

	bool const emitted = g1c0.has_gather; // this host actually assembled the fast path
	if (!sh.admitted || !emitted) {
		// A refused shape (or a host without AVX-512) must stay byte-identical when armed.
		CHECK_MSG(g1c0.bytes == g1c1.bytes,
			  "%s: arming the census moved bytes where no gather body exists", sh.name);
		CHECK_MSG(FindInc(g1c1.bytes, ADDR_FAST).count == 0 &&
			      FindInc(g1c1.bytes, ADDR_FB).count == 0,
			  "%s: a census inc was emitted with no gather body", sh.name);
		printf("    %-24s no gather body -> armed bytes identical (%zu)\n", sh.name,
		       g1c1.bytes.size());
		return;
	}

	// A3: exactly one of each increment, and the byte delta is exactly their encoded length.
	IncSite const sf = FindInc(g1c1.bytes, ADDR_FAST), sb = FindInc(g1c1.bytes, ADDR_FB);
	size_t const nf = sf.count, nb = sb.count;
	CHECK_MSG(nf == 1, "%s A3: %zu fast-path increments, expected exactly 1 (chunks=%u)",
		  sh.name, nf, (vlmax + 15) / 16);
	CHECK_MSG(nb == 1, "%s A3: %zu fallback increments, expected exactly 1", sh.name, nb);
	size_t const delta = g1c1.bytes.size() - g1c0.bytes.size();
	size_t const want = sf.enc_len + sb.enc_len;
	CHECK_MSG(delta == want, "%s A3: armed build grew by %zu bytes, expected %zu", sh.name,
		  delta, want);
	printf("    %-24s VLMAX=%-4u chunks=%-2u armed delta=%zu B (fast=%zu fallback=%zu) ok\n",
	       sh.name, vlmax, (vlmax + 15) / 16, delta, nf, nb);
}

// ---------------------------------------------------------------------------------------------
// [B] Execution.
// ---------------------------------------------------------------------------------------------

// The emitted fast path completes iff vstart == 0 and no ACTIVE element's guest address exceeds
// 0xFFFFFFFC. Recomputed here from the cell's parameters, in RV32's own wrapping arithmetic.
bool FastPathExpected(u32 base, i32 stride, u32 vl, u32 vstart, u32 vlmax)
{
	if (vstart != 0)
		return false;
	u32 const n = vl < vlmax ? vl : vlmax;
	for (u32 e = vstart; e < n; ++e)
		if ((u32)(base + (u32)((i32)e * stride)) > TOP_LIMIT)
			return false;
	return true;
}

struct Counts {
	u64 fast, fallback;
};

// One execution. Returns the counters the emitted code produced, and checks the value result.
Counts RunCell(Emitted &e, Shape const &sh, u32 vlmax, u32 base, i32 stride, u32 vl, u32 vstart,
	       char const *what)
{
	CPUState st(nullptr);
	memset(&st, 0, sizeof st);
	st.vec.vlenb = (u16)(sh.vlen / 8);
	st.vec.vtype = sh.vtype;
	st.vec.vl = vl;
	st.vec.vstart = vstart;
	st.gpr[RS1] = base;
	st.gpr[RS2] = (u32)stride;
	for (u32 r = 0; r < 32; ++r)
		for (u32 i = 0; i < rv32::VLEN_MAX_BYTES; ++i)
			st.vec.vreg[r][i] = (u8)(0xA5u + r * 13u + i * 7u);

	rv32::VectorState ref = st.vec;
	rv32::rvv_ref::load_strided(ref, VD, g_base, base, stride, sh.vlen, vl, /*eew_bytes=*/4,
				    /*vm=*/true);

	// Process-global and cumulative, so zero them per execution: this file asserts on the count
	// produced by ONE run of the node, not on a running total.
	dbt::rv32::g_vlse_gather_fast = 0;
	dbt::rv32::g_vlse_gather_fallback = 0;
	Enter(&st, g_base, e.code);

	// B4: the census must not perturb the architectural result.
	bool ok = st.vec.vstart == ref.vstart;
	for (u32 r = 0; r < 32 && ok; ++r)
		if (memcmp(st.vec.vreg[r].data(), ref.vreg[r].data(), rv32::VLEN_MAX_BYTES))
			ok = false;
	CHECK_MSG(ok, "%s %s value mismatch base=0x%08x stride=%d vl=%u vstart=%u", sh.name, what,
		  base, (int)stride, vl, vstart);
	return {dbt::rv32::g_vlse_gather_fast, dbt::rv32::g_vlse_gather_fallback};
}

struct Case {
	char const *what;
	u32 base;
	i32 stride;
	u32 vl_kind; // 0 = full vlmax, 1 = half, 2 = zero, 3 = one
	u32 vstart;
};

Case const CASES[] = {
    // vstart == 0, entirely inside a mapped region: the fast path must complete.
    {"low/full", REGION_LOW + 0x800, 4, 0, 0},
    {"low/half", REGION_LOW + 0x800, 4, 1, 0},
    {"low/vl=0", REGION_LOW + 0x800, 4, 2, 0},
    {"low/vl=1", REGION_LOW + 0x800, 4, 3, 0},
    {"low/stride=0", REGION_LOW + 0x800, 0, 0, 0},
    {"low/negative", REGION_LOW + 0x4000, -16, 0, 0},
    {"high>=2^31", REGION_HIGH + 0x800, 4, 0, 0},
    {"wrap, none in window", 0xffffffc0u, 16, 0, 0},
    // the vstart exit
    {"vstart=1", REGION_LOW + 0x800, 4, 0, 1},
    {"vstart=3", REGION_LOW + 0x800, 4, 0, 3},
    // the address-space-top exit: every lane, then a mixed chunk, then a walk into the window
    {"top/all lanes", 0xfffffffdu, 0, 0, 0},
    {"top/mixed", 0xfffffffau, 1, 0, 0},
    {"top/walk in", 0xffffff00u, 17, 0, 0},
};

void RunShapeExec(Shape const &sh, bool census, unsigned &cells, unsigned &fast_seen,
		  unsigned &fb_seen)
{
	u32 const vlmax = rv32::compute_vlmax(rv32::VType{sh.vtype}, sh.vlen);
	Emitted e;
	Build(e, sh.vlen, vlmax, sh.sew, /*gather=*/true, census);
	if (!e.has_gather)
		return; // refused shape, or a host that cannot assemble the body
	for (auto const &c : CASES) {
		u32 const vl = c.vl_kind == 0 ? vlmax : c.vl_kind == 1 ? vlmax / 2
					       : c.vl_kind == 2 ? 0u
								: 1u;
		if (c.vstart >= vlmax)
			continue;
		Counts const got = RunCell(e, sh, vlmax, c.base, c.stride, vl, c.vstart, c.what);
		++cells;
		if (!census) {
			// B3: an unarmed build counts nothing, whatever it executed.
			CHECK_MSG(got.fast == 0 && got.fallback == 0,
				  "%s %s: unarmed build counted fast=%llu fallback=%llu", sh.name,
				  c.what, (unsigned long long)got.fast,
				  (unsigned long long)got.fallback);
			continue;
		}
		// B1: exactly one of the two outcomes, per execution.
		CHECK_MSG(got.fast + got.fallback == 1,
			  "%s %s: fast+fallback=%llu, expected 1 (vl=%u vstart=%u)", sh.name,
			  c.what, (unsigned long long)(got.fast + got.fallback), vl, c.vstart);
		// B2: and it is the one the ISA-level predicate says it is.
		bool const want_fast = FastPathExpected(c.base, c.stride, vl, c.vstart, vlmax);
		CHECK_MSG(got.fast == (want_fast ? 1u : 0u),
			  "%s %s: fast=%llu fallback=%llu, expected %s (base=0x%08x stride=%d "
			  "vl=%u vstart=%u)",
			  sh.name, c.what, (unsigned long long)got.fast,
			  (unsigned long long)got.fallback, want_fast ? "fast" : "fallback",
			  c.base, (int)c.stride, vl, c.vstart);
		if (want_fast)
			++fast_seen;
		else
			++fb_seen;
	}
}
} // namespace

int main()
{
	bool const capable = __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("bmi2");
	printf("Z4B vlse32.v gather census -- host avx512f+bmi2 = %s\n", capable ? "yes" : "no");
	printf("    counter addresses: fast=%p fallback=%p\n", ADDR_FAST, ADDR_FB);

	printf("[A] generated code: default-off inertness, and exactly two increments when armed\n");
	for (auto const &sh : SHAPES)
		CheckEmitted(sh);

	unsigned off_cells = 0, on_cells = 0, fast_seen = 0, fb_seen = 0, dummy = 0;
	if (!capable) {
		printf("[B] execution: SKIPPED, this host cannot execute a gather\n");
	} else {
		SetUpAddressSpace();
		MapAndFill(REGION_LOW, REGION_BYTES);
		MapAndFill(REGION_HIGH, REGION_BYTES);
		MapAndFill(0xffff0000u, 0x10000u);
		MapAndFill(0u, 0x10000u);

		printf("[B] execution, census OFF: the counters must stay at zero\n");
		for (auto const &sh : SHAPES)
			RunShapeExec(sh, false, off_cells, dummy, dummy);
		printf("    %u cells\n", off_cells);

		printf("[B] execution, census ON: one outcome per execution, and the right one\n");
		for (auto const &sh : SHAPES)
			RunShapeExec(sh, true, on_cells, fast_seen, fb_seen);
		printf("    %u cells: %u fast-path, %u fallback\n", on_cells, fast_seen, fb_seen);

		// A census that only ever saw one outcome would pass B1/B2 vacuously.
		CHECK_MSG(fast_seen > 0, "no cell completed the fast path");
		CHECK_MSG(fb_seen > 0, "no cell took the fallback");
		CHECK_MSG(on_cells == off_cells, "armed and unarmed cell counts differ (%u vs %u)",
			  on_cells, off_cells);
	}

	printf("\nZ4B_VLSE_GATHER_CENSUS_TEST checks=%d failures=%d exec_cells=%u fast=%u "
	       "fallback=%u %s\n",
	       g_checks, g_failures, on_cells, fast_seen, fb_seen,
	       capable ? "EXECUTED" : "EMIT_ONLY_ON_THIS_HOST");
	return g_failures ? 1 : 0;
}
