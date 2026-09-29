// Z3: the EXECUTABLE value differential for the `vlse32.v` AVX-512 gather body.
//
// WHAT THIS FILE OWNS. The architectural result. It builds the same `vmemorynative` node the route
// builds (the route test owns the claim that the decoder produces exactly this node, field by
// field, including its VLMAX), emits it into a PROT_EXEC page, RUNS it against a real 4 GiB mmu
// reservation, and compares the WHOLE vector register file with rvv_ref::load_strided -- the
// spec-shaped reference the interpreter itself uses. No expected bytes appear in this file:
// the oracle is computed, not written down (memory: fp-bracket-sharing-leaks-rounding-not-flags --
// assert on output words, not on a status flag).
//
// TWO ARMS PER CELL, both compared against the same oracle:
//   `loop`   -- the switch off: the pre-Z3 element loop. Runs on any x86-64 host.
//   `gather` -- the switch on. The route's own host-feature gate refuses to emit the fast path
//               without AVX-512F+BMI2, and this test does NOT set the force-emit audit switch, so
//               on a host without AVX-512 this arm emits the element loop too. That would make a
//               PASS meaningless, so every cell reports whether the gather was ACTUALLY emitted
//               (the 64-byte lane-index constant is searched for in the emitted bytes) and the
//               summary is GATHER_EXECUTED only when it was.
//
// THE ADDRESS CASES ARE THE POINT, and each one falsifies a specific defect:
//   * a base >= 2^31 -- with the P1 bias dropped, VPGATHERDD's SIGNED dword index would apply a
//     negative displacement to mmu::base and read host memory BELOW the reservation: wrong bytes or
//     a SIGSEGV, never the oracle's bytes.
//   * an access that WRAPS modulo 2^32 without entering the guarded window -- the lane arithmetic
//     must wrap exactly as `add edi,r10d` does in the element loop.
//   * an access whose active lanes reach into 0xFFFFFFFD..0xFFFFFFFF -- RV32 assembles those bytes
//     across the wrap; a gather cannot, so the chunk must leave for the element loop BEFORE it
//     stores. Without that guard the gather reads at mmu::base + 2^32, which is rvdbt's own heap.
//   * a nonzero vstart -- the fast path must decline entirely.
//   * a dense vl ladder 0..VLMAX at every stride, because a chunk-aligned ladder cannot see a
//     one-element error at a chunk boundary (memory: a-corpus-vl-ladder-is-chunk-aligned).
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
int g_checks = 0, g_failures = 0, g_gather_cells = 0, g_loop_cells = 0;

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
			Panic("z3 value test: code mmap");
		return mem;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	void *mem{};
	size_t size{};
};

// The generated-code entry contract, copied verbatim from ccrf_sequential_microkernel_test: r13 is
// R_STATE, rbp is R_MEMBASE, and QCG's frame wants its spill area below rsp.
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
// Guest memory. A 4 GiB PROT_NONE reservation with sub-ranges mapped into it -- the same shape
// mmu::Init builds -- and every byte is a function of its own guest address, so a load from the
// wrong address cannot accidentally produce the right value.
//
// WHY THE TEST OWNS THE RESERVATION INSTEAD OF CALLING mmu::Init. This build defines
// DBT_ZERO_MMU_BASE (config.h:16), so in a real run mmu::base is NULL and a guest address IS a host
// address. Under that layout guest page 0 cannot be mapped at all (the host's mmap_min_addr), and
// guest page 0 is exactly where a wrapping RV32 access lands -- so the wrap cases and the
// address-space-top guard would be untestable. R_MEMBASE is a runtime register value, not a
// compile-time constant, so supplying a non-null base here is faithful to both builds and is
// strictly the harder case for the P1 bias, which must now survive a nonzero base as well.
//
// THE PAGE PAST THE RESERVATION IS MAPPED ON PURPOSE, with a constant that appears nowhere in guest
// memory. In production that page is where ukernel hints rvdbt's own heap. Mapping it turns "the
// address-space-top guard is missing" from a possible SIGSEGV into a deterministic VALUE mismatch,
// which is what makes that mutation reproducible rather than lucky.
constexpr u64 ASPACE = 1ull << 32;
constexpr u32 PAGE = 4096u;
constexpr u32 REGION_LOW = 0x00100000u;	 // an ordinary low region
constexpr u32 REGION_HIGH = 0x80010000u; // >= 2^31: the signed-index case
constexpr u32 REGION_BYTES = 0x20000u;	 // Covers both signs of stride128 at e8m1 VLEN4096.
constexpr u8 PAST_END_FILL = 0xdd;

u8 *g_base = nullptr;

u8 PatternByte(u32 gaddr)
{
	u32 h = gaddr * 2654435761u;
	h ^= h >> 15;
	u8 b = (u8)(h ^ (gaddr >> 3));
	return b == PAST_END_FILL ? (u8)(b + 1) : b; // never collide with the past-the-end fill
}

void MapAndFill(u32 gaddr, u32 len)
{
	void *p = ::mmap(g_base + gaddr, len, PROT_READ | PROT_WRITE,
			 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		Panic("z3 value test: guest mmap");
	for (u32 i = 0; i < len; ++i)
		g_base[gaddr + i] = PatternByte(gaddr + i);
}

void SetUpAddressSpace()
{
	void *r = ::mmap(nullptr, ASPACE + PAGE, PROT_NONE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (r == MAP_FAILED)
		Panic("z3 value test: address space reservation");
	g_base = (u8 *)r;
	void *q = ::mmap(g_base + ASPACE, PAGE, PROT_READ | PROT_WRITE,
			 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (q == MAP_FAILED)
		Panic("z3 value test: past-the-end page");
	memset(g_base + ASPACE, PAST_END_FILL, PAGE);
}

// ---------------------------------------------------------------------------------------------
// One emitted node, executed.
// ---------------------------------------------------------------------------------------------
constexpr u32 VD = 8, RS1 = 16, RS2 = 5;

struct Emitted {
	Runtime rt;
	MemArena arena{1u << 21};
	u8 *code = nullptr;
	size_t bytes = 0;
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

void ApplyCfg(u32 vlen, bool gather)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = false;
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_vlse_gather = gather;
	// NOT set: the force-emit audit switch. This arm must be executable on this host.
	config::rvv_qcg_typed_chunk_vlse_gather_force_emit = false;
}

void Build(Emitted &e, u32 vlen, u32 vlmax, bool gather, u32 eew, bool masked)
{
	ApplyCfg(vlen, gather);
	Region *region = e.arena.New<Region>(&e.arena, &state_info);
	Builder b(region->CreateBlock());
	b.Create_vmemorynative((u8)VD, (u8)RS1, (u8)RS2, (u8)eew, /*isew=*/4, /*mode=*/1,
			       (u16)(vlen / 8), /*store=*/false, masked, /*nf=*/1,
			       /*fieldregs=*/1, (u16)vlmax);
	qcg::ArchTraits::init();
	auto code = qcg::GenerateCode(&e.rt, nullptr, region, 0);
	if (code.empty())
		Panic("z3 value test: empty region");
	e.code = code.data();
	e.bytes = code.size();
	// A hand-built region has no guest exit, so supply the epilogue the frame needs. QCG pushes
	// rcx only for a non-leaf frame; this node emits no call, so the frame is leaf here. The
	// first byte is checked rather than assumed.
	size_t k = e.bytes;
	if (e.code[0] == 0x51) // push rcx
		e.code[k++] = 0x59; // pop rcx
	e.code[k++] = 0xc3;	    // ret
	e.has_gather = HasIota(e.code, e.bytes);
}

// ---------------------------------------------------------------------------------------------
// A cell: one (vlen, vtype) shape, one base, one stride, one vl, one vstart.
// ---------------------------------------------------------------------------------------------
struct Shape {
	char const *name;
	u32 vlen, vtype;
	u32 eew{4};
	bool masked{};
};

bool RunCell(Emitted &e, Shape const &sh, u32 vlmax, u32 base, i32 stride, u32 vl, u32 vstart,
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
	// Poison the whole register file, so an undisturbed lane is a real assertion.
	for (u32 r = 0; r < 32; ++r)
		for (u32 i = 0; i < rv32::VLEN_MAX_BYTES; ++i)
			st.vec.vreg[r][i] = (u8)(0xA5u + r * 13u + i * 7u);

	rv32::VectorState ref = st.vec;
	rv32::rvv_ref::load_strided(ref, VD, g_base, base, stride, sh.vlen, vl,
				    sh.eew, /*vm=*/!sh.masked);

	Enter(&st, g_base, e.code);

	bool ok = true;
	for (u32 r = 0; r < 32 && ok; ++r)
		if (memcmp(st.vec.vreg[r].data(), ref.vreg[r].data(), rv32::VLEN_MAX_BYTES))
			ok = false;
	if (st.vec.vstart != ref.vstart)
		ok = false;
	CHECK_MSG(ok, "%s %s base=0x%08x stride=%d vl=%u vstart=%u vlmax=%u", sh.name, what, base,
		  (int)stride, vl, vstart, vlmax);
	return ok;
}

i32 const STRIDES[] = {4, -4, 0, 16, -16, 64, 3, -3, 7, 1, 128, -128};

void RunShape(Shape const &sh, bool gather, unsigned &cells)
{
	u32 const vlmax = rv32::compute_vlmax(rv32::VType{sh.vtype}, sh.vlen);
	Emitted e;
	Build(e, sh.vlen, vlmax, gather, sh.eew, sh.masked);
	if (gather && !e.has_gather) {
		printf("    %-20s gather NOT emitted on this host -- arm skipped\n", sh.name);
		return;
	}
	char const *what = gather ? "gather" : "loop";
	// [A] the two mapped regions, every stride, the dense vl ladder, vstart 0.
	for (i32 stride : STRIDES) {
		for (u32 region : {REGION_LOW, REGION_HIGH}) {
			// Centre the base so a negative stride at VLMAX stays inside the region.
			u32 const base = region + REGION_BYTES / 2;
			for (u32 vl = 0; vl <= vlmax; ++vl) {
				RunCell(e, sh, vlmax, base, stride, vl, 0, what);
				++cells;
			}
		}
	}
	// [B] nonzero vstart: the fast path must decline and the element loop must restart exactly.
	for (u32 vstart : {1u, 3u, vlmax > 1 ? vlmax - 1 : 1u}) {
		RunCell(e, sh, vlmax, REGION_LOW + 0x800, 4, vlmax, vstart, what);
		++cells;
	}
	// [C] an access that wraps modulo 2^32 with no lane inside the guarded window.
	for (u32 vl = 0; vl <= vlmax; ++vl) {
		RunCell(e, sh, vlmax, 0xffffffc0u, 16, vl, 0, what);
		++cells;
	}
	// [D] active lanes INSIDE 0xFFFFFFFD..0xFFFFFFFF: the memory-safety guard must fire.
	for (u32 vl = 0; vl <= vlmax; ++vl) {
		RunCell(e, sh, vlmax, 0xfffffffdu, 0, vl, 0, what);  // every lane in the window
		RunCell(e, sh, vlmax, 0xfffffffau, 1, vl, 0, what);  // a mixed chunk
		RunCell(e, sh, vlmax, 0xffffff00u, 17, vl, 0, what); // an unaligned walk into it
		cells += 3;
	}
	if (gather)
		++g_gather_cells;
	else
		++g_loop_cells;
}

Shape const SHAPES[] = {
    {"e32m1 @512", 512, 0xd0u},  {"e32m1 @1024", 1024, 0xd0u}, {"e32m2 @512", 512, 0xd1u},
    {"e32m2 @1024", 1024, 0xd1u}, {"e64m1 @512", 512, 0xd8u},  {"e32mf2 @512", 512, 0xd7u},
	{"e16m1 @1024", 1024, 0xc8u},
	{"e32m1 @4096", 4096, 0xd0u}, {"e32m2 @4096", 4096, 0xd1u},
	{"e64m1 @4096", 4096, 0xd8u},
	{"e8m1 @4096", 4096, 0xc0u, 1}, {"e16m1 @4096", 4096, 0xc8u, 2},
	{"e64m1 EEW64 @4096", 4096, 0xd8u, 8},
	{"masked e8m1 @4096", 4096, 0xc0u, 1, true},
	{"masked e16m1 @4096", 4096, 0xc8u, 2, true},
	{"masked e32m1 @4096", 4096, 0xd0u, 4, true},
	{"masked e64m1 @4096", 4096, 0xd8u, 8, true},
};
} // namespace

int main()
{
	bool const capable = __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("bmi2");
	printf("Z3 vlse32.v gather value differential -- host avx512f+bmi2 = %s\n",
	       capable ? "yes" : "no");

	SetUpAddressSpace();
	MapAndFill(REGION_LOW, REGION_BYTES);
	MapAndFill(REGION_HIGH, REGION_BYTES);
	MapAndFill(0xffff0000u, 0x10000u); // the last 64 KiB of the address space
	MapAndFill(0u, 0x10000u);	   // and the first, where a wrapping access lands

	unsigned loop_cells = 0, gather_cells = 0;
	unsigned gather_eligible_loop_cells = 0;
	printf("[loop] switch off: the pre-Z3 element loop against rvv_ref::load_strided\n");
	for (auto const &sh : SHAPES) {
		unsigned before = loop_cells;
		RunShape(sh, false, loop_cells);
		if (sh.eew == 4 && !sh.masked) gather_eligible_loop_cells += loop_cells - before;
	}
	printf("    %u cells\n", loop_cells);

	printf("[gather] switch on: the AVX-512 body against the same oracle\n");
	for (auto const &sh : SHAPES)
		if (sh.eew == 4 && !sh.masked) RunShape(sh, true, gather_cells);
	printf("    %u cells\n", gather_cells);

	if (capable)
		CHECK_MSG(gather_cells == gather_eligible_loop_cells,
			  "host is AVX-512 capable but the gather arm ran %u of %u cells",
			  gather_cells, gather_eligible_loop_cells);

	printf("\nZ3_VLSE_GATHER_VALUE_TEST checks=%d failures=%d loop_cells=%u gather_cells=%u "
	       "%s\n",
	       g_checks, g_failures, loop_cells, gather_cells,
	       gather_cells ? "GATHER_EXECUTED" : "GATHER_NOT_EXECUTED_ON_THIS_HOST");
	return g_failures ? 1 : 0;
}
