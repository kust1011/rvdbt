// Focused mechanism test for ONE operation: qir::InstVStateChunkLoad (`vstatechunkload`).
//
// SCOPE.  Nothing here is routed from a guest instruction; `vstatechunkload` has no producer
// anywhere in the translator and the only region that contains it is the one built below.  This
// says nothing about RVV lowering, about `vstatechunkstore` (which does not exist), or about
// performance.  What it establishes is the one claim the operation makes: it reads exactly 64
// bytes out of CPUState at a translation-time constant offset, off the state register, into an
// ordinary allocated V512 value -- and that those are the LIVE bytes.
//
// The observation channel is the pre-existing `vchunkstore`, which writes the loaded chunk to
// guest memory.  No new opcode is introduced to read the result back.
//
//   S1  the emitted load is byte-for-byte what an independent assembler produces for
//       `vmovdqu64 zmm<allocated>, [r13 + offs]` with a 64-byte operand, the store follows it
//       immediately, and the store consumes the SAME physical register the load defined.
//       Three wrong forms are assembled too and asserted ABSENT: an R_MEMBASE-relative load, an
//       absolute [disp32] load (the two branches of make_vmem) and the ALIGNED vmovdqa64.
//   X1  executed against a buffer of sizeof(CPUState) known bytes: two different offsets each
//       reproduce their own 64-byte CPUState window in guest memory, and the two windows differ,
//       so `offs` demonstrably reaches the address and is not a constant.
//   X2  executed with a guest global written in the same region immediately before the load.  The
//       loaded window must contain the NEW value.  This is the SIDEEFF claim from qir.h: without
//       the global sync AllocOp performs for a side-effecting op, the dirty value would still be
//       sitting in a host register and the window would read stale.
//
// EXECUTION MODE.  This workstation is Ivy Bridge (AVX only) and its silicon cannot retire a ZMM
// instruction.  X1/X2 therefore run in one of two modes, reported per run:
//
//   * native        -- on an AVX-512F host the emitted code executes as-is.
//   * trap-assisted -- otherwise, the emitted code is still entered with the real jitabi register
//                      contract (r13 = state), the real prologue really runs, and each #UD is
//                      caught as SIGILL.  The handler DECODES the faulting bytes -- the actual
//                      emitted bytes, not the builder's intent -- checks every EVEX field,
//                      resolves the address from the base register's live value in the trap frame
//                      plus the decoded displacement, moves the 64 bytes through a software ZMM
//                      file, and steps RIP over the instruction.
//
// What trap-assisted mode does and does not cover is worth being exact about.  It DOES verify the
// address the generated code actually forms (base register identity and displacement come out of
// the emitted bytes and the live trap frame), that the two instructions agree on a register, and
// the 64 bytes that move.  It does NOT verify the silicon behaviour of the instruction: notably an
// aligned vmovdqa64 would #GP on real hardware at these offsets but would be emulated happily
// here, which is exactly why S1 checks the unaligned encoding statically and the decoder rejects
// EVEX.pp != F3.
//
// Set VSTATE_DUMP=1 to print each region's post-RA listing and the emitted bytes.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qcg/qemit.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"
#include "dbt/qmc/qir_printer.h"

#include <csetjmp>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <ucontext.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
using namespace dbt::qcg;

namespace
{

int g_failures = 0;

#define CHECK(cond)                                                                                          \
	do {                                                                                                 \
		if (!(cond)) {                                                                               \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

#define CHECK_EQ(a, b)                                                                                       \
	do {                                                                                                 \
		auto _a = (a);                                                                               \
		auto _b = (b);                                                                               \
		if (!(_a == _b)) {                                                                           \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,   \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

bool Dumping()
{
	return getenv("VSTATE_DUMP") != nullptr;
}

std::string Hex(u8 const *p, size_t n)
{
	std::string s;
	char tmp[4];
	for (size_t i = 0; i < n; ++i) {
		snprintf(tmp, sizeof(tmp), "%02x", p[i]);
		if (!s.empty()) {
			s += ' ';
		}
		s += tmp;
	}
	return s;
}

// ---------------------------------------------------------------------------------------------
// CPUState-shaped bytes.
//
// The buffer is sizeof(CPUState) bytes and every offset used below is a REAL CPUState offset, for
// two reasons.  QEmit::Emit_vstatechunkload fails closed against sizeof(CPUState), so a toy state
// area could not reach the offsets a vector register file actually occupies; and the window this
// operation exists to read -- rv32::VectorState::vreg -- is only 16-byte aligned and sits at a
// non-64-byte-aligned base, which is the whole reason the emitted access must be unaligned.
//
// The bytes are never a constructed CPUState: CPUState has a deleted default constructor and holds
// non-trivial members, so it is treated strictly as raw storage addressed through offsetof.
// ---------------------------------------------------------------------------------------------

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
constexpr u32 ST_GPR_BASE = (u32)offsetof(CPUState, gpr);

// Two windows in the architectural vector register file: the low half of v2 and the HIGH half of
// v5.  The high half is deliberate -- at VLEN=1024 a 512-bit host chunk is exactly this, and it
// gives a second offset that no plausible hardcoding could produce by accident.
constexpr u32 OFFS_A = ST_VREG_BASE + 2 * rv32::VLEN_MAX_BYTES;
constexpr u32 OFFS_B = ST_VREG_BASE + 5 * rv32::VLEN_MAX_BYTES + 64;

// X3's round-trip destination: the low half of v9, chosen only so that it is a different vector
// register from OFFS_A and has live pattern bytes on both sides of it.
constexpr u32 OFFS_D = ST_VREG_BASE + 9 * rv32::VLEN_MAX_BYTES;

// The scalar guest register used by X2, and the 64-byte window containing it.
constexpr u32 ST_GPR3 = ST_GPR_BASE + 3 * sizeof(u32);
constexpr u32 OFFS_G = ST_GPR3 & ~63u;
constexpr u32 GPR3_IN_WINDOW = ST_GPR3 - OFFS_G;
constexpr u32 GPR3_MARKER = 0xA5A5C3C3u;

static_assert(OFFS_A + 64 <= sizeof(CPUState));
static_assert(OFFS_B + 64 <= sizeof(CPUState));
static_assert(OFFS_G + 64 <= sizeof(CPUState));
static_assert(OFFS_A + 64 <= InstVStateChunkLoad::STATE_OFFS_LIMIT);
static_assert(OFFS_B + 64 <= InstVStateChunkLoad::STATE_OFFS_LIMIT);
static_assert(GPR3_IN_WINDOW + sizeof(u32) <= 64);
static_assert(OFFS_D + 64 <= InstVStateChunkStore::STATE_OFFS_LIMIT);
static_assert(OFFS_D >= OFFS_A + 64 || OFFS_A >= OFFS_D + 64, "round-trip windows must not overlap");
// X3 checks the 64 bytes either side of the destination, so both neighbours must exist.
static_assert(OFFS_D >= 64);
static_assert(OFFS_D + 128 <= sizeof(CPUState));

// A second pair, both halves of ONE register (unlike OFFS_A/OFFS_B, which are different
// registers): the exact two-chunk vadd.vv shape --
// experiments/2026-08-24-0935-rvv-typed-chunk-vaddvv-route/docs/C2_1A_TWO_CHUNK_SOURCE_AUDIT.md
// section 21 -- used by X4 below to build one region with two independent (load, store) pairs.
constexpr u32 REG_TWO_CHUNK = 7;
constexpr u32 OFFS_LOW = ST_VREG_BASE + REG_TWO_CHUNK * rv32::VLEN_MAX_BYTES;
constexpr u32 OFFS_HIGH = OFFS_LOW + 64;

static_assert(OFFS_HIGH == OFFS_LOW + 64, "the two chunks must be the +0/+64 halves of one register");
static_assert(OFFS_HIGH + 64 <= sizeof(CPUState));
static_assert(OFFS_HIGH + 64 <= InstVStateChunkLoad::STATE_OFFS_LIMIT);

// A byte that depends on its own offset, so no two 64-byte windows can be confused and a load from
// the wrong displacement cannot coincidentally produce the right answer.
u8 StatePattern(size_t off)
{
	u32 h = (u32)off * 2654435761u;
	h ^= h >> 15;
	return (u8)(h * 40503u >> 13);
}

struct StateBuf {
	StateBuf()
	{
		// aligned_alloc requires a size that is a multiple of the alignment.
		sz = (sizeof(CPUState) + 4095) & ~size_t(4095);
		raw = (u8 *)aligned_alloc(4096, sz);
		CHECK(raw != nullptr);
		if (!raw) {
			return;
		}
		for (size_t i = 0; i < sz; ++i) {
			raw[i] = StatePattern(i);
		}
	}
	~StateBuf()
	{
		free(raw);
	}
	u8 *Window(u32 offs) const
	{
		return raw + offs;
	}
	u8 *raw{};
	size_t sz{};
};

// ---------------------------------------------------------------------------------------------
// Guest memory, for the observation store only.
//
// This build defines DBT_ZERO_MMU_BASE (dbt/config.h), so a guest address IS a host virtual
// address and the region has to be mapped at that exact address.
// ---------------------------------------------------------------------------------------------

constexpr u32 GUEST_BASE = 0x31000000u;
constexpr size_t GUEST_SZ = 64u << 10;
constexpr u32 GA_OUT = GUEST_BASE + 0x1000;

// X4's two destinations: far enough apart, and from GA_OUT, that the neighbour bytes it checks
// around one cannot land inside the other's window.
constexpr u32 GA_OUT_LO = GUEST_BASE + 0x2000;
constexpr u32 GA_OUT_HI = GUEST_BASE + 0x3000;
static_assert(GA_OUT_LO >= GA_OUT + 128 && GA_OUT_HI >= GA_OUT_LO + 128);
static_assert(GA_OUT_LO + 64 - GUEST_BASE <= GUEST_SZ);
static_assert(GA_OUT_HI + 64 - GUEST_BASE <= GUEST_SZ);

struct GuestMemEnv {
	GuestMemEnv()
	{
		mem = (u8 *)mmap((void *)(uptr)GUEST_BASE, GUEST_SZ, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
		ok = mem != MAP_FAILED && (uptr)mem == (uptr)GUEST_BASE;
		CHECK(ok);
		if (!ok) {
			fprintf(stderr, "  could not map guest memory at %08x (got %p)\n", GUEST_BASE, mem);
			mem = nullptr;
			return;
		}
		memset(mem, 0, GUEST_SZ);
	}
	~GuestMemEnv()
	{
		if (mem) {
			munmap(mem, GUEST_SZ);
		}
	}
	u8 *Out() const
	{
		return (u8 *)(uptr)GA_OUT;
	}
	bool ok{};
	u8 *mem{};
};

// ---------------------------------------------------------------------------------------------
// Region construction
// ---------------------------------------------------------------------------------------------

// X2 needs one guest global, and its state offset is a real CPUState scalar register slot.
enum GlobalId : RegN {
	G_VAL = 0,
	G_COUNT,
};

StateReg g_state_regs[] = {
    {(u16)ST_GPR3, VType::I32, "x3"},
};
StateInfo g_state_info{g_state_regs, G_COUNT};

VOperand Addr(u32 v)
{
	return VOperand::MakeConst(VType::I32, v);
}

struct TestRegion {
	explicit TestRegion(size_t arena_sz = 1u << 20) : arena(arena_sz)
	{
		region = arena.New<Region>(&arena, &g_state_info);
		bb = region->CreateBlock();
		qb = Builder(bb);
	}

	VOperand NewV()
	{
		return VOperand::MakeVVPR(VType::V512, qb.CreateVGPR(VType::V512));
	}

	MemArena arena;
	Region *region{};
	Block *bb{};
	Builder qb{nullptr};
};

// The region under test: read one CPUState chunk, write it to guest memory.  `write_global` adds
// the dirty-global store X2 needs, immediately before the load.
void BuildRegion(TestRegion &t, u32 offs, bool write_global)
{
	if (write_global) {
		t.qb.Create_mov(VOperand::MakeVGPR(VType::I32, G_VAL), Addr(GPR3_MARKER));
	}
	auto v = t.NewV();
	t.qb.Create_vstatechunkload(v, offs);
	t.qb.Create_vchunkstore(Addr(GA_OUT), v);
}

// ---------------------------------------------------------------------------------------------
// EVEX decoding.
//
// Only two instruction forms are accepted, and every field is checked rather than skipped: an
// unchecked field is a field that could be wrong without failing the test.  In particular
// EVEX.pp must be F3 (vmovdqu64) and not 66 (vmovdqa64), EVEX.L'L must say 512-bit, and no mask
// register or broadcast may be in play.
// ---------------------------------------------------------------------------------------------

struct Evex {
	bool ok{};
	char const *why{"not decoded"};
	bool is_store{};  // 0x7F stores the register, 0x6F loads it
	u8 vreg{};	  // 0..31
	bool has_base{};  // false = absolute [disp32]
	u8 base{};	  // x86 register encoding of the base
	i64 disp{};
	u8 len{};
};

Evex DecodeVmovdqu64(u8 const *p)
{
	Evex e;
	auto fail = [&e](char const *why) {
		e.ok = false;
		e.why = why;
		return e;
	};

	size_t n = 0;
	if (p[n] == 0x67) { // address-size override: a 32-bit effective address
		++n;
	}
	if (p[n] != 0x62) {
		return fail("not an EVEX prefix");
	}
	u8 P0 = p[n + 1], P1 = p[n + 2], P2 = p[n + 3];
	if ((P0 & 0x08) != 0) {
		return fail("EVEX P0 reserved bit");
	}
	if ((P0 & 0x03) != 0x01) {
		return fail("EVEX opcode map is not 0F");
	}
	u8 R = ((P0 >> 7) & 1) ^ 1; // R/X/B/R' are stored inverted
	u8 X = ((P0 >> 6) & 1) ^ 1;
	u8 B = ((P0 >> 5) & 1) ^ 1;
	u8 Rp = ((P0 >> 4) & 1) ^ 1;
	if (!((P1 >> 7) & 1)) {
		return fail("EVEX.W is 0: not the 64-bit-element form");
	}
	if(((((u8)(P1 >> 3)) & 0xF) ^ 0xF) != 0) {
		return fail("EVEX.vvvv is used: not a two-operand move");
	}
	if (!((P1 >> 2) & 1)) {
		return fail("EVEX P1 fixed bit is 0");
	}
	if ((P1 & 3) != 2) {
		return fail("EVEX.pp is not F3: this is not the UNALIGNED move");
	}
	if ((P2 >> 7) & 1) {
		return fail("EVEX.z set");
	}
	if (((P2 >> 5) & 3) != 2) {
		return fail("EVEX.L'L does not say 512-bit");
	}
	if ((P2 >> 4) & 1) {
		return fail("EVEX.b set: embedded broadcast");
	}
	if ((P2 & 7) != 0) {
		return fail("EVEX selects a mask register");
	}

	u8 opc = p[n + 4];
	if (opc == 0x6F) {
		e.is_store = false;
	} else if (opc == 0x7F) {
		e.is_store = true;
	} else {
		return fail("opcode is not movdqu64");
	}

	u8 modrm = p[n + 5];
	u8 mod = modrm >> 6, reg = (modrm >> 3) & 7, rm = modrm & 7;
	if (mod == 3) {
		return fail("register operand, not memory");
	}
	e.vreg = reg | (R << 3) | (Rp << 4);
	n += 6;

	if (rm == 4) { // SIB
		u8 sib = p[n++];
		u8 index = (sib >> 3) & 7, sbase = sib & 7;
		if (X || index != 4) {
			return fail("SIB index register in use");
		}
		if (!(mod == 0 && sbase == 5)) {
			return fail("unexpected SIB base");
		}
		i32 d32;
		memcpy(&d32, p + n, 4);
		n += 4;
		e.has_base = false;
		e.disp = d32; // absolute [disp32], sign-extended
		e.len = (u8)n;
		e.ok = true;
		return e;
	}
	if (mod == 0 && rm == 5) {
		return fail("RIP-relative");
	}
	e.has_base = true;
	e.base = rm | (B << 3);
	if (mod == 1) {
		// compressed displacement: disp8 * N, and N is 64 for a full 512-bit memory operand
		e.disp = (i64)(i8)p[n] * 64;
		n += 1;
	} else if (mod == 2) {
		i32 d32;
		memcpy(&d32, p + n, 4);
		n += 4;
		e.disp = d32;
	} else {
		e.disp = 0;
	}
	e.len = (u8)n;
	e.ok = true;
	return e;
}

// ---------------------------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------------------------

struct TestCompilerRuntime final : CompilerRuntime {
	~TestCompilerRuntime()
	{
		if (map_ptr) {
			munmap(map_ptr, map_sz);
		}
	}

	void *AllocateCode(size_t sz, uint align) override
	{
		// Slack for the `ret` appended below: a hand-built region has no gbr, so nothing
		// terminates it.  Extra slack so the decoder may always read a full instruction.
		map_sz = (sz + 64 + 4095) & ~size_t(4095);
		map_ptr = mmap(nullptr, map_sz, PROT_READ | PROT_WRITE | PROT_EXEC,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (map_ptr == MAP_FAILED) {
			map_ptr = nullptr;
			Panic("mmap RWX failed");
		}
		return map_ptr;
	}
	bool AllowsRelocation() const override
	{
		return false; // jit_mode
	}
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}

	void *map_ptr{};
	size_t map_sz{};
};

// Enter emitted code with the register and stack contract jitabi.cpp's trampoline_to_jit
// establishes: r13 = STATE, rbp = MEMBASE, and spillframe_size bytes of scratch immediately above
// the return address.  Written out here rather than reused because the real trampoline ends in
// `int3` -- it expects the region to leave through qcgstub_escape_*, which a hand-built region
// with no gbr cannot do.  Six pushes then `sub` leaves the frame 16-byte but NOT 64-byte aligned,
// which is exactly the condition that forces the unaligned vector encodings.
#define TEST_ASM extern "C" __attribute__((noinline, used, naked))

TEST_ASM void vstate_enter(void *state, void *membase, void *code);
TEST_ASM void vstate_enter(void *state, void *membase, void *code)
{
	asm("pushq	%rbp\n\t"
	    "pushq	%rbx\n\t"
	    "pushq	%r12\n\t"
	    "pushq	%r13\n\t"
	    "pushq	%r14\n\t"
	    "pushq	%r15\n\t"
	    "movq	%rdi, %r13\n\t"	  // STATE
	    "movq	%rsi, %rbp\n\t"); // MEMBASE
	asm("sub	$%c0, %%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("callq	*%rdx\n\t");
	asm("add	$%c0, %%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("popq	%r15\n\t"
	    "popq	%r14\n\t"
	    "popq	%r13\n\t"
	    "popq	%r12\n\t"
	    "popq	%rbx\n\t"
	    "popq	%rbp\n\t"
	    "retq	\n\t");
}

// Trap-assisted execution state.  All of it is plain storage touched only between a
// sigsetjmp and the return from vstate_enter.
struct TrapRecord {
	u8 vreg;
	bool is_store;
	bool has_base;
	u8 base;
	i64 disp;
	u8 len;
};

u8 g_zmm[32][64];
bool g_zmm_written[32];
volatile sig_atomic_t g_trap_n;
TrapRecord g_trap[8];
char const *volatile g_trap_why;
u8 *volatile g_code_lo;
u8 *volatile g_code_hi;
sigjmp_buf g_trap_escape;
volatile sig_atomic_t g_trap_escaped;

int GregOfEncoding(u8 enc)
{
	switch (enc) {
	case 0:
		return REG_RAX;
	case 1:
		return REG_RCX;
	case 2:
		return REG_RDX;
	case 3:
		return REG_RBX;
	case 4:
		return REG_RSP;
	case 5:
		return REG_RBP;
	case 6:
		return REG_RSI;
	case 7:
		return REG_RDI;
	default:
		return REG_R8 + (enc - 8);
	}
}

void SigillHandler(int, siginfo_t *, void *ucv)
{
	auto *uc = (ucontext_t *)ucv;
	auto *rip = (u8 *)(uptr)uc->uc_mcontext.gregs[REG_RIP];

	auto escape = [](char const *why) {
		g_trap_why = why;
		g_trap_escaped = 1;
		siglongjmp(g_trap_escape, 1);
	};

	if (rip < g_code_lo || rip >= g_code_hi) {
		escape("SIGILL outside the emitted region");
	}
	auto e = DecodeVmovdqu64(rip);
	if (!e.ok) {
		escape(e.why);
	}
	if (g_trap_n >= (sig_atomic_t)(sizeof(g_trap) / sizeof(g_trap[0]))) {
		escape("more trapped instructions than the region can contain");
	}

	u64 addr;
	if (e.has_base) {
		addr = (u64)uc->uc_mcontext.gregs[GregOfEncoding(e.base)] + (u64)e.disp;
	} else {
		addr = (u64)e.disp;
	}

	if (e.is_store) {
		if (!g_zmm_written[e.vreg]) {
			escape("store reads a ZMM that no preceding instruction defined");
		}
		memcpy((void *)(uptr)addr, g_zmm[e.vreg], 64);
	} else {
		memcpy(g_zmm[e.vreg], (void const *)(uptr)addr, 64);
		g_zmm_written[e.vreg] = true;
	}

	g_trap[g_trap_n] = {e.vreg, e.is_store, e.has_base, e.base, e.disp, e.len};
	g_trap_n = g_trap_n + 1;
	uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uptr)(rip + e.len);
}

bool HostHasAvx512()
{
	__builtin_cpu_init();
	return __builtin_cpu_supports("avx512f");
}

void InstallSigill()
{
	struct sigaction sa {
	};
	sa.sa_sigaction = SigillHandler;
	sa.sa_flags = SA_SIGINFO | SA_NODEFER;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGILL, &sa, nullptr)) {
		Panic("sigaction(SIGILL)");
	}
}

// Run the emitted region.  Returns false only if the trap path had to abandon it.
bool RunRegion(std::span<u8> code, StateBuf const &state)
{
	code.data()[code.size()] = 0xC3; // ret: a hand-built region has no terminator

	memset(g_zmm_written, 0, sizeof(g_zmm_written));
	g_trap_n = 0;
	g_trap_escaped = 0;
	g_trap_why = nullptr;
	g_code_lo = code.data();
	g_code_hi = code.data() + code.size() + 1;

	if (sigsetjmp(g_trap_escape, 1) == 0) {
		vstate_enter(state.raw, (void *)(uptr)GUEST_BASE, code.data());
		return true;
	}
	fprintf(stderr, "  trap-assisted execution abandoned: %s\n",
		g_trap_why ? g_trap_why : "unknown");
	return false;
}

char const *ModeName()
{
	return g_trap_n ? "trap-assisted" : "native AVX-512";
}

// ---------------------------------------------------------------------------------------------

template <typename F>
std::vector<u8> Assemble(F &&f)
{
	asmjit::CodeHolder code;
	if (code.init(asmjit::Environment::host())) {
		Panic("codeholder init");
	}
	asmjit::x86::Assembler a;
	code.attach(a._emitter());
	f(a);
	code.flatten();
	code.resolveUnresolvedLinks();
	std::vector<u8> out(code.codeSize());
	code.copyFlattenedData(out.data(), out.size());
	return out;
}

size_t CountOccurrences(std::span<u8> hay, std::vector<u8> const &needle)
{
	size_t n = 0;
	if (needle.empty() || needle.size() > hay.size()) {
		return 0;
	}
	for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
		if (memcmp(hay.data() + i, needle.data(), needle.size()) == 0) {
			++n;
		}
	}
	return n;
}

ssize_t FindOnce(std::span<u8> hay, std::vector<u8> const &needle)
{
	for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
		if (memcmp(hay.data() + i, needle.data(), needle.size()) == 0) {
			return (ssize_t)i;
		}
	}
	return -1;
}

// The compiled region plus everything the assertions need to talk about it.
struct Compiled {
	std::span<u8> code;
	u8 load_zmm{};
	u8 store_zmm{};
	ssize_t load_at{-1};
	size_t load_len{};
	size_t store_len{};
	bool found{};
};

Compiled CompileRegion(TestRegion &t, TestCompilerRuntime &cruntime, u32 offs)
{
	Compiled c;
	ArchTraits::init();
	c.code = qcg::GenerateCode(&cruntime, nullptr, t.region, 0);
	CHECK(!c.code.empty());
	if (Dumping()) {
		fprintf(stderr, "--- offs=%u ---\n%s\n  bytes: %s\n", offs,
			PrinterPass::run(t.region).c_str(), Hex(c.code.data(), c.code.size()).c_str());
	}
	if (c.code.empty()) {
		return c;
	}

	// The physical registers QRegAlloc chose.  Read out of the operands, never assumed.
	unsigned n_load = 0, n_store = 0;
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_vstatechunkload) {
				auto *v = static_cast<InstVStateChunkLoad *>(&ins);
				CHECK_EQ(v->inputs().size(), 0u); // no address operand exists
				CHECK(v->o(0).IsPVPR());
				CHECK_EQ((u32)v->offs, offs);
				c.load_zmm = v->o(0).GetPVPR();
				++n_load;
			} else if (ins.GetOpcode() == Op::_vchunkstore) {
				auto *v = static_cast<InstVChunkStore *>(&ins);
				CHECK(v->i(1).IsPVPR());
				c.store_zmm = v->i(1).GetPVPR();
				++n_store;
			}
		}
	}
	CHECK_EQ(n_load, 1u);
	CHECK_EQ(n_store, 1u);

	// Allocated out of the pool, and not one of the emitter's unmodelled zmm0/zmm1 scratch.
	CHECK(c.load_zmm < ArchTraits::VPR_NUM);
	CHECK(ArchTraits::VPR_POOL.Test(c.load_zmm));
	CHECK(!ArchTraits::VPR_FIXED.Test(c.load_zmm));
	// No copy was inserted: the store consumes the register the load defined.
	CHECK_EQ(c.store_zmm, c.load_zmm);

	// Byte-for-byte against an independent assembler.  The base register is restated as the
	// literal x86::r13 rather than QEmit::R_STATE, so a change of state register would fail here
	// instead of being carried along by the same constant.
	auto want_load = Assemble([&](asmjit::x86::Assembler &a) {
		a.vmovdqu64(asmjit::x86::Zmm(c.load_zmm),
			    asmjit::x86::ptr(asmjit::x86::r13, (int32_t)offs, 64));
	});
	CHECK_EQ(CountOccurrences(c.code, want_load), 1u);
	c.load_at = FindOnce(c.code, want_load);
	CHECK(c.load_at >= 0);
	if (c.load_at < 0) {
		fprintf(stderr, "    want: %s\n    code: %s\n", Hex(want_load.data(), want_load.size()).c_str(),
			Hex(c.code.data(), c.code.size()).c_str());
		return c;
	}

	// The three forms this op must NOT have been given.  make_vmem has exactly two branches under
	// zero_membase -- an absolute guest address and a 32-bit register address -- and its other
	// configuration adds R_MEMBASE; vmovdqa64 is the aligned encoding that would #GP here.
	auto bad_membase = Assemble([&](asmjit::x86::Assembler &a) {
		a.vmovdqu64(asmjit::x86::Zmm(c.load_zmm),
			    asmjit::x86::ptr(QEmit::R_MEMBASE, (int32_t)offs, 64));
	});
	auto bad_absolute = Assemble([&](asmjit::x86::Assembler &a) {
		auto m = asmjit::x86::ptr((u64)offs);
		m.setSize(64);
		a.vmovdqu64(asmjit::x86::Zmm(c.load_zmm), m);
	});
	auto bad_aligned = Assemble([&](asmjit::x86::Assembler &a) {
		a.vmovdqa64(asmjit::x86::Zmm(c.load_zmm),
			    asmjit::x86::ptr(asmjit::x86::r13, (int32_t)offs, 64));
	});
	CHECK_EQ(CountOccurrences(c.code, bad_membase), 0u);
	CHECK_EQ(CountOccurrences(c.code, bad_absolute), 0u);
	CHECK_EQ(CountOccurrences(c.code, bad_aligned), 0u);

	// Decode the emitted bytes independently of how they were built, and require the store to
	// begin exactly where the load ends and the region to end exactly where the store ends.
	auto dl = DecodeVmovdqu64(c.code.data() + c.load_at);
	CHECK(dl.ok);
	if (!dl.ok) {
		fprintf(stderr, "    load decode: %s\n", dl.why);
		return c;
	}
	CHECK(!dl.is_store);
	CHECK(dl.has_base);
	CHECK_EQ((u32)dl.base, (u32)ArchTraits::STATE);
	CHECK_EQ(dl.disp, (i64)offs);
	CHECK_EQ((u32)dl.vreg, (u32)c.load_zmm);
	c.load_len = dl.len;

	// Locate the store by scanning rather than by assuming, then assert separately that it sits
	// immediately after the load.  Adjacency is a real claim -- nothing may be scheduled between
	// the operation and its only consumer, and in particular the global sync a side-effecting op
	// forces belongs BEFORE the load, not between the two -- but it must not be able to hide the
	// execution results below, so a failure here is recorded and the test still runs.
	ssize_t store_at = -1;
	for (size_t i = (size_t)c.load_at + dl.len; i < c.code.size(); ++i) {
		auto probe = DecodeVmovdqu64(c.code.data() + i);
		if (probe.ok && probe.is_store) {
			store_at = (ssize_t)i;
			break;
		}
	}
	CHECK(store_at >= 0);
	if (store_at < 0) {
		fprintf(stderr, "    no store found after the load\n");
		return c;
	}
	CHECK_EQ(store_at, c.load_at + (ssize_t)dl.len);
	if (store_at != c.load_at + (ssize_t)dl.len) {
		fprintf(stderr, "    %zd byte(s) emitted between the load and its consumer: %s\n",
			store_at - c.load_at - (ssize_t)dl.len,
			Hex(c.code.data() + c.load_at + dl.len,
			    (size_t)(store_at - c.load_at - (ssize_t)dl.len))
			    .c_str());
	}

	auto ds = DecodeVmovdqu64(c.code.data() + store_at);
	CHECK_EQ((u32)ds.vreg, (u32)c.load_zmm);
	c.store_len = ds.len;
	CHECK_EQ((size_t)store_at + ds.len, c.code.size());

	c.found = true;
	return c;
}

// ---------------------------------------------------------------------------------------------

void S1_encoding()
{
	printf("S1 emitted load is [R_STATE + offs], 64 bytes, unaligned, into the allocated ZMM\n");

	for (u32 offs : {OFFS_A, OFFS_B, OFFS_G}) {
		TestRegion t;
		BuildRegion(t, offs, false);
		TestCompilerRuntime cruntime;
		auto c = CompileRegion(t, cruntime, offs);
		if (!c.found) {
			continue;
		}
		printf("  offs=%u (0x%x): zmm%u, load %zu bytes at [%zd,%zd), region %zu bytes\n", offs,
		       offs, c.load_zmm, c.load_len, c.load_at, c.load_at + (ssize_t)c.load_len,
		       c.code.size());
	}
}

void X1_execute_windows()
{
	printf("X1 executed against known CPUState-shaped bytes, two different windows\n");

	StateBuf state;
	GuestMemEnv guest;
	if (!state.raw || !guest.ok) {
		return;
	}

	u8 got[2][64];
	u32 const offsets[2] = {OFFS_A, OFFS_B};

	for (int k = 0; k < 2; ++k) {
		u32 offs = offsets[k];
		TestRegion t;
		BuildRegion(t, offs, false);
		TestCompilerRuntime cruntime;
		auto c = CompileRegion(t, cruntime, offs);
		if (!c.found) {
			return;
		}

		memset(guest.Out(), 0xCC, 64);
		if (!RunRegion(c.code, state)) {
			++g_failures;
			return;
		}
		if (g_trap_n) {
			// Both vector instructions were reached and emulated, in order.
			CHECK_EQ((int)g_trap_n, 2);
			CHECK(!g_trap[0].is_store);
			CHECK_EQ((u32)g_trap[0].base, (u32)ArchTraits::STATE);
			CHECK_EQ(g_trap[0].disp, (i64)offs);
			CHECK(g_trap[1].is_store);
		}

		memcpy(got[k], guest.Out(), 64);
		bool ok = memcmp(got[k], state.Window(offs), 64) == 0;
		CHECK(ok);
		if (!ok) {
			fprintf(stderr, "  offs=%u mismatch\n    got:  %s\n    want: %s\n", offs,
				Hex(got[k], 64).c_str(), Hex(state.Window(offs), 64).c_str());
		}
		printf("  offs=%u (0x%x) %s: 64/64 bytes equal CPUState[%u..%u), first byte %02x\n", offs,
		       offs, ModeName(), offs, offs + 64, got[k][0]);
	}

	// The two windows must differ, otherwise "reproduces its window" would be satisfiable by an
	// address that ignores offs entirely.
	CHECK(memcmp(got[0], got[1], 64) != 0);
}

void X2_execute_sideeff()
{
	printf("X2 executed with a dirty guest global inside the loaded window\n");

	StateBuf state;
	GuestMemEnv guest;
	if (!state.raw || !guest.ok) {
		return;
	}

	// The pre-existing bytes at the global's slot, so "the loaded window shows the new value" is
	// a statement about a value that really did change.
	u32 before;
	memcpy(&before, state.Window(ST_GPR3), sizeof(before));
	CHECK(before != GPR3_MARKER);

	TestRegion t;
	BuildRegion(t, OFFS_G, true);
	TestCompilerRuntime cruntime;
	auto c = CompileRegion(t, cruntime, OFFS_G);
	if (!c.found) {
		return;
	}

	memset(guest.Out(), 0xCC, 64);
	if (!RunRegion(c.code, state)) {
		++g_failures;
		return;
	}

	u32 loaded;
	memcpy(&loaded, guest.Out() + GPR3_IN_WINDOW, sizeof(loaded));
	CHECK_EQ(loaded, GPR3_MARKER);

	// Everything else in the window is still the untouched CPUState pattern: the sync wrote the
	// one global's slot and nothing wider.
	u8 want[64];
	memcpy(want, state.Window(OFFS_G), 64);
	memcpy(want + GPR3_IN_WINDOW, &GPR3_MARKER, sizeof(GPR3_MARKER));
	bool ok = memcmp(guest.Out(), want, 64) == 0;
	CHECK(ok);
	if (!ok) {
		fprintf(stderr, "  window mismatch\n    got:  %s\n    want: %s\n",
			Hex(guest.Out(), 64).c_str(), Hex(want, 64).c_str());
	}
	printf("  offs=%u (0x%x) %s: x3 slot read back %08x (was %08x), rest of the window unchanged\n",
	       OFFS_G, OFFS_G, ModeName(), loaded, before);
}

// ---------------------------------------------------------------------------------------------

// The counterpart operation.  One claim, and only one: a state->state round trip moves exactly the
// source window's 64 bytes into the destination window and touches nothing else in CPUState.
// Reuses the helpers above rather than growing a second harness -- the one thing it cannot borrow
// is CompileRegion, which is written around the load-plus-guest-memory-store shape.
void X3_state_round_trip()
{
	printf("X3 state -> state round trip: 64 bytes copied, nothing else in CPUState touched\n");

	StateBuf state;
	if (!state.raw) {
		return;
	}
	std::vector<u8> before(state.raw, state.raw + state.sz);
	// The copy has to be observable: if the two windows already agreed, a store that did nothing
	// at all would satisfy every check below.
	CHECK(memcmp(before.data() + OFFS_A, before.data() + OFFS_D, 64) != 0);

	TestRegion t;
	auto v = t.NewV();
	t.qb.Create_vstatechunkload(v, OFFS_A);
	t.qb.Create_vstatechunkstore(OFFS_D, v);

	ArchTraits::init();
	TestCompilerRuntime cruntime;
	auto code = qcg::GenerateCode(&cruntime, nullptr, t.region, 0);
	CHECK(!code.empty());
	if (code.empty()) {
		return;
	}
	if (Dumping()) {
		fprintf(stderr, "--- X3 ---\n%s\n  bytes: %s\n", PrinterPass::run(t.region).c_str(),
			Hex(code.data(), code.size()).c_str());
	}

	// The allocator's choices, read out of the operands.  There is one value, so both ops must
	// name the same register and no copy may have been inserted.
	u8 load_zmm = 0xFF, store_zmm = 0xFE;
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_vstatechunkload) {
				load_zmm = static_cast<InstVStateChunkLoad *>(&ins)->o(0).GetPVPR();
			} else if (ins.GetOpcode() == Op::_vstatechunkstore) {
				auto *sv = static_cast<InstVStateChunkStore *>(&ins);
				CHECK_EQ(sv->outputs().size(), 0u); // no result exists
				CHECK(sv->i(0).IsPVPR());
				CHECK_EQ((u32)sv->offs, OFFS_D);
				store_zmm = sv->i(0).GetPVPR();
			}
		}
	}
	CHECK_EQ(store_zmm, load_zmm);
	CHECK(ArchTraits::VPR_POOL.Test(store_zmm));
	CHECK(!ArchTraits::VPR_FIXED.Test(store_zmm));

	// The same three-way encoding check S1 makes for the load, applied to the store.  It runs
	// BEFORE execution deliberately: an R_MEMBASE-based store would write through an rbp that
	// points at unmapped guest space and take the process down instead of failing a check.
	auto want_store = Assemble([&](asmjit::x86::Assembler &a) {
		a.vmovdqu64(asmjit::x86::ptr(asmjit::x86::r13, (int32_t)OFFS_D, 64),
			    asmjit::x86::Zmm(store_zmm));
	});
	auto bad_membase = Assemble([&](asmjit::x86::Assembler &a) {
		a.vmovdqu64(asmjit::x86::ptr(QEmit::R_MEMBASE, (int32_t)OFFS_D, 64),
			    asmjit::x86::Zmm(store_zmm));
	});
	auto bad_aligned = Assemble([&](asmjit::x86::Assembler &a) {
		a.vmovdqa64(asmjit::x86::ptr(asmjit::x86::r13, (int32_t)OFFS_D, 64),
			    asmjit::x86::Zmm(store_zmm));
	});
	bool enc_ok = CountOccurrences(code, want_store) == 1;
	CHECK(enc_ok);
	CHECK_EQ(CountOccurrences(code, bad_membase), 0u);
	CHECK_EQ(CountOccurrences(code, bad_aligned), 0u);
	if (!enc_ok) {
		fprintf(stderr, "    want store: %s\n    code:       %s\n",
			Hex(want_store.data(), want_store.size()).c_str(),
			Hex(code.data(), code.size()).c_str());
		return; // executing an unrecognised store would write somewhere unknown
	}

	if (!RunRegion(code, state)) {
		++g_failures;
		return;
	}

	// 1. the destination window holds exactly the source window's original bytes
	bool copied = memcmp(state.raw + OFFS_D, before.data() + OFFS_A, 64) == 0;
	CHECK(copied);

	// 2. every byte that changed anywhere in CPUState lies inside that window.  Expressed as a
	//    bound on the changed range, not as a count: some source bytes may coincidentally equal
	//    the destination bytes they replaced, so "exactly 64 bytes differ" would be wrong.
	size_t n_diff = 0;
	ssize_t first = -1, last = -1;
	for (size_t i = 0; i < state.sz; ++i) {
		if (state.raw[i] != before[i]) {
			++n_diff;
			if (first < 0) {
				first = (ssize_t)i;
			}
			last = (ssize_t)i;
		}
	}
	CHECK(n_diff > 0);
	CHECK(first >= (ssize_t)OFFS_D);
	CHECK(last < (ssize_t)(OFFS_D + 64));
	if (first < (ssize_t)OFFS_D || last >= (ssize_t)(OFFS_D + 64)) {
		fprintf(stderr, "  changed bytes span [%zd,%zd], destination window is [%u,%u)\n", first,
			last, OFFS_D, OFFS_D + 64);
	}

	// 3. the immediate neighbours, checked separately because "adjacent bytes" is the claim
	CHECK(memcmp(state.raw + OFFS_D - 64, before.data() + OFFS_D - 64, 64) == 0);
	CHECK(memcmp(state.raw + OFFS_D + 64, before.data() + OFFS_D + 64, 64) == 0);

	printf("  0x%x -> 0x%x %s: zmm%u, 64/64 bytes copied, %zu byte(s) changed in CPUState, all "
	       "within [%u,%u), 64 bytes either side unchanged\n",
	       OFFS_A, OFFS_D, ModeName(), store_zmm, n_diff, OFFS_D, OFFS_D + 64);
}

// ---------------------------------------------------------------------------------------------
//
// C2.1b2 extension.  One region, two vstatechunkload ops at the +0 and +64 windows of the SAME
// register, each feeding its own independent vchunkstore to its own guest address -- the exact
// pair of offsets the two-chunk vadd.vv route (dbt/guest/rv32_qir.cpp's TRANSLATOR(vadd_vv),
// C2.1a design doc sections 11/17) would read for one register, minus the rvvtypedchunkbegin/end frame
// around it, checked here the same way S1/X1 already check one offset at a time.  This is a
// dataflow and register-file-occupancy test: distinct virtual identities, distinct physical ZMMs,
// correct def-use, correct bytes after one execution, no corruption outside either window.  It is
// NOT a claim that the two loads or the two stores execute concurrently, and nothing below should
// be read that way -- this harness cannot observe host-CPU instruction scheduling at all.
// ---------------------------------------------------------------------------------------------

// Build one region: load(OFFS_LOW)->store(GA_OUT_LO) and load(OFFS_HIGH)->store(GA_OUT_HI), as two
// independent pairs, both loads first (mirroring the typed route's own load-major construction
// order) then both stores.
void BuildTwoChunkRegion(TestRegion &t)
{
	auto v_lo = t.NewV();
	auto v_hi = t.NewV();
	// Independent virtual identities, checked here rather than assumed: CreateVGPR hands out a
	// fresh region-wide index each call, so these two must already differ before compilation.
	CHECK(v_lo.GetVVPR() != v_hi.GetVVPR());
	t.qb.Create_vstatechunkload(v_lo, OFFS_LOW);
	t.qb.Create_vstatechunkload(v_hi, OFFS_HIGH);
	t.qb.Create_vchunkstore(Addr(GA_OUT_LO), v_lo);
	t.qb.Create_vchunkstore(Addr(GA_OUT_HI), v_hi);
}

struct TwoChunkCompiled {
	std::span<u8> code;
	u8 lo_load_zmm{}, hi_load_zmm{};
	bool found{};
};

TwoChunkCompiled CompileTwoChunkRegion(TestRegion &t, TestCompilerRuntime &cruntime)
{
	TwoChunkCompiled c;
	ArchTraits::init();
	c.code = qcg::GenerateCode(&cruntime, nullptr, t.region, 0);
	CHECK(!c.code.empty());
	if (Dumping()) {
		fprintf(stderr, "--- two-chunk low=%u high=%u ---\n%s\n  bytes: %s\n", OFFS_LOW, OFFS_HIGH,
			PrinterPass::run(t.region).c_str(), Hex(c.code.data(), c.code.size()).c_str());
	}
	if (c.code.empty()) {
		return c;
	}

	unsigned n_load = 0, n_store = 0;
	u8 load_zmm[2] = {0xFF, 0xFF};
	u8 store_zmm[2] = {0xFF, 0xFF};
	u32 load_offs[2] = {};
	for (auto &bb : t.region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_vstatechunkload) {
				auto *v = static_cast<InstVStateChunkLoad *>(&ins);
				CHECK_EQ(v->inputs().size(), 0u); // no address operand exists
				CHECK(v->o(0).IsPVPR());
				if (n_load < 2) {
					load_zmm[n_load] = v->o(0).GetPVPR();
					load_offs[n_load] = v->offs;
				}
				++n_load;
			} else if (ins.GetOpcode() == Op::_vchunkstore) {
				auto *v = static_cast<InstVChunkStore *>(&ins);
				CHECK(v->i(1).IsPVPR());
				if (n_store < 2) {
					store_zmm[n_store] = v->i(1).GetPVPR();
				}
				++n_store;
			}
		}
	}
	CHECK_EQ(n_load, 2u);
	CHECK_EQ(n_store, 2u);
	if (n_load != 2 || n_store != 2) {
		return c;
	}

	// Exact +0/+64 windows, read off the compiled instructions, not assumed from the constants
	// used to build them.
	CHECK_EQ(load_offs[0], OFFS_LOW);
	CHECK_EQ(load_offs[1], OFFS_HIGH);
	CHECK_EQ(load_offs[1], load_offs[0] + 64);

	// Distinct physical allocation: two simultaneously live V512 values do not collapse onto one
	// ZMM, and neither lands on the emitter's unmodelled zmm0/zmm1 scratch.
	CHECK(load_zmm[0] < ArchTraits::VPR_NUM);
	CHECK(load_zmm[1] < ArchTraits::VPR_NUM);
	CHECK(ArchTraits::VPR_POOL.Test(load_zmm[0]));
	CHECK(ArchTraits::VPR_POOL.Test(load_zmm[1]));
	CHECK(!ArchTraits::VPR_FIXED.Test(load_zmm[0]));
	CHECK(!ArchTraits::VPR_FIXED.Test(load_zmm[1]));
	CHECK(load_zmm[0] != load_zmm[1]);

	// def-use: each store consumes its OWN load's register, and the two pairs share no register.
	CHECK_EQ(store_zmm[0], load_zmm[0]);
	CHECK_EQ(store_zmm[1], load_zmm[1]);
	CHECK(store_zmm[0] != load_zmm[1]);
	CHECK(store_zmm[1] != load_zmm[0]);

	c.lo_load_zmm = load_zmm[0];
	c.hi_load_zmm = load_zmm[1];

	// Byte-for-byte against an independent assembler, exactly one occurrence each, and the two
	// encoded loads must not overlap in the emitted byte stream -- S1's method, applied to both.
	auto want_lo = Assemble([&](asmjit::x86::Assembler &a) {
		a.vmovdqu64(asmjit::x86::Zmm(c.lo_load_zmm),
			    asmjit::x86::ptr(asmjit::x86::r13, (int32_t)OFFS_LOW, 64));
	});
	auto want_hi = Assemble([&](asmjit::x86::Assembler &a) {
		a.vmovdqu64(asmjit::x86::Zmm(c.hi_load_zmm),
			    asmjit::x86::ptr(asmjit::x86::r13, (int32_t)OFFS_HIGH, 64));
	});
	CHECK_EQ(CountOccurrences(c.code, want_lo), 1u);
	CHECK_EQ(CountOccurrences(c.code, want_hi), 1u);
	ssize_t lo_at = FindOnce(c.code, want_lo);
	ssize_t hi_at = FindOnce(c.code, want_hi);
	CHECK(lo_at >= 0);
	CHECK(hi_at >= 0);
	if (lo_at < 0 || hi_at < 0) {
		return c;
	}
	CHECK(hi_at >= lo_at + (ssize_t)want_lo.size() || lo_at >= hi_at + (ssize_t)want_hi.size());

	// Independently decode both, the same way S1/CompileRegion decode the one-offset case: base
	// register, displacement and destination ZMM all come out of the emitted bytes, not the
	// builder's intent.
	auto dlo = DecodeVmovdqu64(c.code.data() + lo_at);
	CHECK(dlo.ok);
	if (dlo.ok) {
		CHECK(!dlo.is_store);
		CHECK(dlo.has_base);
		CHECK_EQ((u32)dlo.base, (u32)ArchTraits::STATE);
		CHECK_EQ(dlo.disp, (i64)OFFS_LOW);
		CHECK_EQ((u32)dlo.vreg, (u32)c.lo_load_zmm);
	}
	auto dhi = DecodeVmovdqu64(c.code.data() + hi_at);
	CHECK(dhi.ok);
	if (dhi.ok) {
		CHECK(!dhi.is_store);
		CHECK(dhi.has_base);
		CHECK_EQ((u32)dhi.base, (u32)ArchTraits::STATE);
		CHECK_EQ(dhi.disp, (i64)OFFS_HIGH);
		CHECK_EQ((u32)dhi.vreg, (u32)c.hi_load_zmm);
	}

	c.found = true;
	return c;
}

void X4_two_chunks_one_register()
{
	printf("X4 one region, two chunks of the same register (low+high), one execution\n");

	StateBuf state;
	GuestMemEnv guest;
	if (!state.raw || !guest.ok) {
		return;
	}

	TestRegion t;
	BuildTwoChunkRegion(t);
	TestCompilerRuntime cruntime;
	auto c = CompileTwoChunkRegion(t, cruntime);
	if (!c.found) {
		return;
	}

	// Sentinel-fill the whole guest region so "nothing outside either destination window changed"
	// is checkable, not merely "the window itself is right."
	memset(guest.mem, 0x99, GUEST_SZ);
	if (!RunRegion(c.code, state)) {
		++g_failures;
		return;
	}

	u8 *out_lo = (u8 *)(uptr)GA_OUT_LO;
	u8 *out_hi = (u8 *)(uptr)GA_OUT_HI;

	bool lo_ok = memcmp(out_lo, state.Window(OFFS_LOW), 64) == 0;
	bool hi_ok = memcmp(out_hi, state.Window(OFFS_HIGH), 64) == 0;
	CHECK(lo_ok);
	CHECK(hi_ok);
	if (!lo_ok) {
		fprintf(stderr, "  low chunk mismatch\n    got:  %s\n    want: %s\n", Hex(out_lo, 64).c_str(),
			Hex(state.Window(OFFS_LOW), 64).c_str());
	}
	if (!hi_ok) {
		fprintf(stderr, "  high chunk mismatch\n    got:  %s\n    want: %s\n", Hex(out_hi, 64).c_str(),
			Hex(state.Window(OFFS_HIGH), 64).c_str());
	}
	// The two results must differ, otherwise "each window matches its own source" would be
	// satisfiable by an address that ignores which chunk it is.
	CHECK(memcmp(out_lo, out_hi, 64) != 0);

	// No out-of-window corruption: scan the ENTIRE mapped guest buffer -- already sentinel-filled
	// above -- and require every byte outside both destination windows to still be the sentinel.
	// The two windows themselves are already verified byte-exact above; this covers everything
	// else in the mapping, not just the immediate neighbours.
	auto in_either_window = [](u32 ga) {
		return (ga >= GA_OUT_LO && ga < GA_OUT_LO + 64) || (ga >= GA_OUT_HI && ga < GA_OUT_HI + 64);
	};
	size_t n_corrupted = 0;
	ssize_t first_bad_ga = -1;
	for (size_t i = 0; i < GUEST_SZ; ++i) {
		u32 ga = GUEST_BASE + (u32)i;
		if (in_either_window(ga)) {
			continue;
		}
		if (guest.mem[i] != 0x99) {
			++n_corrupted;
			if (first_bad_ga < 0) {
				first_bad_ga = (ssize_t)ga;
			}
		}
	}
	CHECK_EQ(n_corrupted, 0u);
	if (n_corrupted) {
		fprintf(stderr, "  %zu unexpected byte(s) outside both windows, first at guest 0x%08zx\n",
			n_corrupted, (size_t)first_bad_ga);
	}

	printf("  low  offs=%u (0x%x) zmm%u %s: 64/64 bytes equal CPUState[%u..%u), no corruption "
	       "outside the window\n",
	       OFFS_LOW, OFFS_LOW, c.lo_load_zmm, ModeName(), OFFS_LOW, OFFS_LOW + 64);
	printf("  high offs=%u (0x%x) zmm%u %s: 64/64 bytes equal CPUState[%u..%u), no corruption "
	       "outside the window\n",
	       OFFS_HIGH, OFFS_HIGH, c.hi_load_zmm, ModeName(), OFFS_HIGH, OFFS_HIGH + 64);
	printf("  one compiled region, run once -- not a claim about execution overlap or scheduling\n");
}

} // namespace

int main()
{
	printf("QCG vstatechunkload mechanism test\n");
	printf("  sizeof(CPUState)=%zu  vreg base=%u  VPR pool=%u  zero_membase=%d  host avx512f=%d\n",
	       sizeof(CPUState), ST_VREG_BASE, ArchTraits::VPR_POOL.count(), (int)config::zero_membase,
	       (int)HostHasAvx512());

	if (!HostHasAvx512()) {
		printf("  this host cannot retire a ZMM instruction: X1/X2 run trap-assisted "
		       "(see the file header)\n");
	}
	InstallSigill();

	S1_encoding();
	X1_execute_windows();
	X2_execute_sideeff();
	X3_state_round_trip();
	X4_two_chunks_one_register();

	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("OK: all checks passed\n");
	return 0;
}
