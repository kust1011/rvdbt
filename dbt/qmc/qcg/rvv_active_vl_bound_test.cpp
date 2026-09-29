// S1-1: the ACTIVE-VL BOUND node (`vchunkactive`) and the typed frame's body-done label.
//
// SCOPE. This file builds the node BY HAND and says nothing about which routes emit it -- the FP
// wiring is covered by rvv_active_vl_bound_stage2a_test.cpp / rvv_active_vl_bound_stage2d_fma_test.cpp
// and the integer wiring by rvv_active_vl_int_bound_test.cpp. Nothing here says anything about RVV
// lowering, about K7/K18, or about performance. What it establishes is that the node exists end to
// end (printer -> QSel -> QRegAlloc -> QEmit), that the branch it emits lands where the design says
// it must, and that the ways of misusing it are translation Panics rather than silent wrong code.
//
// WHY THE CHECKS ARE POSITIONAL AND NOT A BYTE DIFF. The obvious test -- emit the frame with and
// without the node and diff -- does not work and its failure is worth recording: every forward
// branch in the frame (the guard's two `jne fallback`, the join's `jmp done`) carries a rel32 that
// MOVES when 14 bytes are inserted, so "common prefix + common suffix" finds a spurious alignment
// inside the first displacement rather than the real insertion point. Every assertion below is
// therefore anchored on an independently assembled instruction located by its own bytes.
//
// WHAT IS CHECKED, AND WHAT EACH CHECK'S FAILURE LOOKS LIKE
//
//   [A] Printer. The node dumps as `vchunkactive` with chunk and element_base. S1-3 replaced
//       S1-1's `(chunk, lanes)` pair with the element index itself, so the dump now shows exactly
//       the immediate the `cmp` below carries. Failure = a dump that cannot distinguish two
//       different bounds, which is where a wrong unit (bytes rather than elements) is first
//       visible.
//
//   [B] The compare. Exactly the `cmp dword ptr [R_STATE + vec.vl], chunk*lanes` an independent
//       assembler produces, present once in the bounded frame and absent from the same frame built
//       without the node. `base` is deliberately 24 while the frame's VLMAX is 16, so this pattern
//       cannot be confused with the guard's own compare against vec.vl.
//
//   [C] The branch and its target. A `jbe` (rel8 or rel32) sits immediately after that compare, and
//       its displacement resolves to the FIRST byte of the FP epilogue -- located independently as
//       `stmxcsr [R_STATE + fpu.qcg_current_mxcsr]`, the opening instruction of
//       EmitCloseRvvFpBracket. That sequence occurs TWICE in a frame, and the test asserts exactly
//       two: Emit_rvvqcgfpbegin starts with a CONDITIONAL close that folds a preceding scalar
//       instruction's exceptions before installing the guest rounding mode. The bound must join the
//       second one. Failure = the branch retargeted at the join (the FP bracket would never close),
//       at the fallback, at fpbegin's inner close, or simply falling through.
//
//   [D] Work is really skipped. The frame's `vchunkmaskset` writes k(1+chunk); that `kmovw k4, edx`
//       is located independently and must lie strictly BETWEEN the branch and its target. Without
//       this, a target that happened to be the next instruction would pass [C].
//
//   [E] The target is not the fallback, and the whole epilogue is downstream of it: the fallback's
//       opening `inc qword ptr [R_STATE + rvv_direct_fallbacks]` is strictly after the target, and
//       so are `ldmxcsr` and `mov dword ptr [R_STATE + vec.vstart], 0`. Failure = an early-exited
//       body that leaves the host FP environment open, leaves vstart dirty, or re-runs the ordered
//       helpers over chunks it already stored.
//
//   [F] Fail-closed contracts, each in a forked child whose stderr the parent matches against the
//       EXPECTED Panic message -- an abnormal exit alone would also be produced by an unrelated
//       crash, and by the wrong Panic (this file already caught one such case: a full-VL frame
//       built through the 6-argument constructor Panics in the CONSTRUCTOR, never reaching the
//       emitter check it was meant to exercise):
//       (f1) a bound in a frame whose guard proved full VL (G11-A);
//       (f2) a frame that emits a bound but neither an FP epilogue nor a declared
//            `frame_clears_vstart` -- S1-3 turned S1-1's "no epilogue to join" Panic into the
//            stronger mirror check, because the frame and the body must agree about who writes
//            vec.vstart = 0 and the silent form of that disagreement is nobody writing it;
//       (f3) a bound outside any typed frame;
//       (f4) the node constructor rejects chunk >= 64 and an element_base at or above the largest
//            index any legal register group can name (qir::kMaxVectorElements).
//
// Nothing here executes host bytes. The value-level claim that skipping a `vl <= base` chunk is
// architecturally a no-op is NOT tested here -- this file's frame has no real body to compare
// against; that obligation belongs to the stages that wire the node into a route.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"
#include "dbt/qmc/qir_printer.h"

#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <sys/mman.h>
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
		long long _a = (long long)(a);                                                       \
		long long _b = (long long)(b);                                                       \
		if (_a != _b) {                                                                      \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,          \
				__LINE__, #a, #b, _a, _b);                                           \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

StateReg g_regs[] = {{(u16)offsetof(CPUState, gpr), VType::I32, "x0"}};
StateInfo g_state_info{g_regs, 1};

struct Runtime final : CompilerRuntime {
	void *mem = nullptr;
	size_t size = 0;
	~Runtime()
	{
		if (mem)
			munmap(mem, size);
	}
	void *AllocateCode(size_t n, uint) override
	{
		size = (n + 64 + 4095) & ~size_t(4095);
		mem = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mem == MAP_FAILED)
			Panic("active-vl test mmap");
		return mem;
	}
	bool AllowsRelocation() const override { return true; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};

// The register QEmit pins CPUState in (qemit.h: R_STATE = gpq(ArchTraits::STATE)), so an
// independently assembled instruction is comparable with the emitted one byte for byte.
auto const kStateReg = asmjit::x86::gpq(qcg::ArchTraits::STATE);

using GuardKind = InstRVVTypedChunkBegin::GuardKind;

// base = 24 while the frame's VLMAX is 16: the bound's compare and the guard's compare against the
// same field then differ in their immediate, so [B] cannot match the wrong instruction. kLanes is
// kept only to name the maskset's lane count, which is a DIFFERENT node's field; S1-3's bound
// carries kBase directly.
constexpr u8 kChunk = 3;
constexpr u8 kLanes = 8;
constexpr u32 kBase = (u32)kChunk * kLanes;
constexpr u32 kVlmax = 16;

// The frame every case builds. `with_bound` inserts exactly one vchunkactive before the maskset.
// `n_typed` is the honest count of nodes that increment QEmit's typed counter -- fpbegin, the
// optional bound, the maskset, the optional fpend -- and `end` Panics if it is wrong.
struct Frame {
	MemArena arena{1u << 20};
	Region *region{};
	std::vector<u8> code;

	// `default_kind` takes the 5-argument constructor, whose guard_kind defaults to
	// VTypeVlVstart -- the one GuardProvesFullVl admits. The 6-argument constructor rejects that
	// kind outright, so (f1) MUST come through here to reach the emitter at all.
	void Build(bool with_bound, GuardKind kind, bool with_epilogue = true,
		   bool default_kind = false)
	{
		region = arena.New<Region>(&arena, &g_state_info);
		Builder b(region->CreateBlock());
		u16 const n_typed = (u16)(2u + (with_bound ? 1u : 0u) + (with_epilogue ? 1u : 0u));
		if (default_kind)
			b.Create_rvvtypedchunkbegin(0xd9u, kVlmax, 0u, RuntimeStubId::id_rv32_vfalu,
						    n_typed);
		else
			b.Create_rvvtypedchunkbegin(0xd9u, kVlmax, 0u, RuntimeStubId::id_rv32_vfalu,
						    n_typed, kind);
		b.Create_rvvqcgfpbegin();
		if (with_bound)
			b.Create_vchunkactive(kChunk, kBase);
		b.Create_vchunkmaskset(kChunk, kLanes);
		if (with_epilogue)
			b.Create_rvvqcgfpend();
		b.Create_rvvtypedchunkend(0u, RuntimeStubId::id_rv32_vfalu);
	}

	void Emit()
	{
		Runtime rt;
		auto span = qcg::GenerateCode(&rt, nullptr, region, 0);
		code.assign(span.begin(), span.end());
	}
};

std::vector<u8> Assemble(std::function<void(asmjit::x86::Assembler &)> const &body)
{
	asmjit::CodeHolder holder;
	if (holder.init(asmjit::Environment::host()))
		Panic("active-vl test: asmjit init");
	asmjit::x86::Assembler a(&holder);
	body(a);
	holder.flatten();
	holder.resolveUnresolvedLinks();
	std::vector<u8> out(holder.codeSize());
	holder.copyFlattenedData(out.data(), out.size());
	return out;
}

unsigned CountBytes(std::vector<u8> const &hay, std::vector<u8> const &needle, size_t *first)
{
	unsigned n = 0;
	*first = SIZE_MAX;
	if (needle.empty() || needle.size() > hay.size())
		return 0;
	for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
		if (memcmp(hay.data() + i, needle.data(), needle.size()) != 0)
			continue;
		if (!n)
			*first = i;
		++n;
	}
	return n;
}

size_t Find(std::vector<u8> const &hay, std::vector<u8> const &needle)
{
	size_t at = SIZE_MAX;
	CountBytes(hay, needle, &at);
	return at;
}

// The FP bracket's CLOSE sequence appears twice in a frame, and that is not a defect to work
// around: Emit_rvvqcgfpbegin opens with a conditional EmitCloseRvvFpBracket() that folds a
// preceding scalar instruction's exceptions before installing the guest rounding mode, so
// `stmxcsr [qcg_current_mxcsr]` and `ldmxcsr [fround_run_saved_mxcsr]` occur once inside fpbegin
// and once in the epilogue. The epilogue is the LAST one.
size_t FindLast(std::vector<u8> const &hay, std::vector<u8> const &needle)
{
	size_t at = SIZE_MAX;
	if (needle.empty() || needle.size() > hay.size())
		return SIZE_MAX;
	for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
		if (memcmp(hay.data() + i, needle.data(), needle.size()) == 0)
			at = i;
	return at;
}

// A Panic aborts, so every fail-closed contract runs in a child. The child's stderr is captured and
// matched against the message the contract is supposed to produce: an abnormal exit on its own would
// also be produced by an unrelated crash or by a DIFFERENT Panic.
void ExpectPanic(char const *what, char const *expect, std::function<void()> const &body)
{
	char path[] = "/tmp/active_vl_panic_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0)
		Panic("active-vl test: mkstemp");
	fflush(stdout);
	fflush(stderr);
	pid_t const pid = fork();
	if (pid == 0) {
		dup2(fd, 2);
		close(fd);
		body();
		_exit(0);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	std::string out;
	{
		lseek(fd, 0, SEEK_SET);
		char buf[4096];
		ssize_t n;
		while ((n = read(fd, buf, sizeof(buf))) > 0)
			out.append(buf, (size_t)n);
	}
	close(fd);
	unlink(path);
	bool const clean = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	bool const matched = out.find(expect) != std::string::npos;
	if (clean || !matched) {
		fprintf(stderr, "  FAIL %s: expected Panic \"%s\" (clean_exit=%d matched=%d)\n", what,
			expect, (int)clean, (int)matched);
		++g_failures;
	} else {
		printf("  ok   %s -> \"%s\"\n", what, expect);
	}
}

void TestPrinter()
{
	MemArena arena(1u << 20);
	auto *region = arena.New<Region>(&arena, &g_state_info);
	Builder b(region->CreateBlock());
	b.Create_vchunkactive(kChunk, kBase);
	std::string const dump = qir::PrinterPass::run(region);
	bool const named = dump.find("vchunkactive") != std::string::npos;
	CHECK(named);
	CHECK(dump.find("chunk=3") != std::string::npos);
	CHECK(dump.find("element_base=24") != std::string::npos);
	printf("[A] printer: %s\n", named ? "vchunkactive chunk/element_base present" : "MISSING");
}

void TestEmission()
{
	Frame plain, bounded;
	plain.Build(false, GuardKind::VTypePartialVlVstartFrmHost);
	plain.Emit();
	bounded.Build(true, GuardKind::VTypePartialVlVstartFrmHost);
	bounded.Emit();
	CHECK(!plain.code.empty());
	CHECK(bounded.code.size() > plain.code.size());

	auto const vl_off =
	    (int32_t)offsetof(CPUState, vec) + (int32_t)offsetof(rv32::VectorState, vl);
	auto const want_cmp = Assemble([&](asmjit::x86::Assembler &a) {
		a.cmp(asmjit::x86::dword_ptr(kStateReg, vl_off), (int32_t)kBase);
	});

	// [B] one compare against vec.vl with THIS chunk's base, and none without the node.
	size_t cmp_at = SIZE_MAX, unused = SIZE_MAX;
	CHECK_EQ(CountBytes(bounded.code, want_cmp, &cmp_at), 1u);
	CHECK_EQ(CountBytes(plain.code, want_cmp, &unused), 0u);
	if (cmp_at == SIZE_MAX)
		return;
	printf("[B] cmp [vec.vl], %u at +%zu (%zu bytes), frame %zu -> %zu\n", kBase, cmp_at,
	       want_cmp.size(), plain.code.size(), bounded.code.size());

	// [C] a jbe immediately after it, targeting the first byte of the FP epilogue.
	size_t const jbe_at = cmp_at + want_cmp.size();
	size_t jbe_end = 0, target = 0;
	CHECK(jbe_at + 2 <= bounded.code.size());
	if (bounded.code[jbe_at] == 0x76) {
		jbe_end = jbe_at + 2;
		target = jbe_end + (size_t)(ptrdiff_t)(i8)bounded.code[jbe_at + 1];
	} else if (bounded.code[jbe_at] == 0x0f && bounded.code[jbe_at + 1] == 0x86) {
		i32 rel = 0;
		memcpy(&rel, bounded.code.data() + jbe_at + 2, 4);
		jbe_end = jbe_at + 6;
		target = jbe_end + (size_t)(ptrdiff_t)rel;
	} else {
		CHECK(!"the instruction after the bound's cmp is a jbe");
		return;
	}

	auto const want_stmxcsr = Assemble([&](asmjit::x86::Assembler &a) {
		a.stmxcsr(asmjit::x86::dword_ptr(
		    kStateReg, (int32_t)offsetof(CPUState, fpu) +
				   (int32_t)offsetof(rv32::FPUState, qcg_current_mxcsr)));
	});
	size_t first_stmxcsr = SIZE_MAX;
	// Two: fpbegin's conditional pre-close and the epilogue. The bound joins the SECOND.
	CHECK_EQ(CountBytes(bounded.code, want_stmxcsr, &first_stmxcsr), 2u);
	size_t const stmxcsr_at = FindLast(bounded.code, want_stmxcsr);
	CHECK(first_stmxcsr < stmxcsr_at);
	CHECK_EQ(target, stmxcsr_at);
	printf("[C] jbe at +%zu targets +%zu == FP epilogue stmxcsr\n", jbe_at, target);

	// [D] the frame's maskset really is inside the skipped range.
	auto const want_kmovw = Assemble([&](asmjit::x86::Assembler &a) {
		a.kmovw(asmjit::x86::KReg(1 + kChunk), asmjit::x86::edx);
	});
	size_t const kmovw_at = Find(bounded.code, want_kmovw);
	CHECK(kmovw_at != SIZE_MAX);
	CHECK(kmovw_at > jbe_end);
	CHECK(kmovw_at < target);
	printf("[D] skipped range [+%zu,+%zu) contains the maskset's kmovw k%u at +%zu\n", jbe_end,
	       target, 1u + kChunk, kmovw_at);

	// [E] the target is before the fallback, and the epilogue is downstream of it.
	auto const want_fallback = Assemble([&](asmjit::x86::Assembler &a) {
		a.inc(asmjit::x86::qword_ptr(kStateReg,
					     (int32_t)offsetof(CPUState, rvv_direct_fallbacks)));
	});
	size_t const fallback_at = Find(bounded.code, want_fallback);
	CHECK(fallback_at != SIZE_MAX);
	CHECK(target != fallback_at);
	CHECK(target < fallback_at);

	auto const want_ldmxcsr = Assemble([&](asmjit::x86::Assembler &a) {
		a.ldmxcsr(asmjit::x86::dword_ptr(
		    kStateReg, (int32_t)offsetof(CPUState, fpu) +
				   (int32_t)offsetof(rv32::FPUState, fround_run_saved_mxcsr)));
	});
	auto const want_vstart = Assemble([&](asmjit::x86::Assembler &a) {
		a.mov(asmjit::x86::dword_ptr(kStateReg,
					     (int32_t)offsetof(CPUState, vec) +
						 (int32_t)offsetof(rv32::VectorState, vstart)),
		      0);
	});
	size_t const ldmxcsr_at = FindLast(bounded.code, want_ldmxcsr);
	size_t const vstart_at = FindLast(bounded.code, want_vstart);
	CHECK(ldmxcsr_at != SIZE_MAX);
	CHECK(vstart_at != SIZE_MAX);
	CHECK(ldmxcsr_at > target);
	CHECK(vstart_at > target);
	printf("[E] fallback +%zu after target; ldmxcsr +%zu and vstart=0 +%zu after target\n",
	       fallback_at, ldmxcsr_at, vstart_at);
}

void TestFailClosed()
{
	ExpectPanic("bound in a full-VL frame",
		    "rvv active-vl bound inside a frame whose guard proved full VL", [] {
			    config::rvv_qcg_full_vl_fast_body = true;
			    Frame f;
			    f.Build(true, GuardKind::VTypeVlVstart, /*with_epilogue=*/true,
				    /*default_kind=*/true);
			    f.Emit();
		    });
	// S1-3: an FP frame with no epilogue leaves `rvv_typed_chunk_bound_open` set at `end`, where
	// it now meets the mirror check against InstRVVTypedChunkEnd::frame_clears_vstart (false for
	// every FP frame). Still fail-closed, and for a strictly stronger reason: binding the label
	// here without the translator having cleared the body's own vstart writes would emit a frame
	// that writes vec.vstart twice or not at all.
	ExpectPanic("bound with no FP epilogue and no declared frame vstart write",
		    "rvv active-vl bound: frame and body disagree about who clears vstart", [] {
			    Frame f;
			    f.Build(true, GuardKind::VTypePartialVlVstartFrmHost, /*with_epilogue=*/false);
			    f.Emit();
		    });
	ExpectPanic("bound outside a frame", "rvv active-vl bound outside a typed chunk group", [] {
		MemArena arena(1u << 20);
		auto *region = arena.New<Region>(&arena, &g_state_info);
		Builder b(region->CreateBlock());
		b.Create_vchunkactive(kChunk, kBase);
		Runtime rt;
		qcg::GenerateCode(&rt, nullptr, region, 0);
	});
	auto shape = [](u8 chunk, u32 element_base) {
		return [chunk, element_base] {
			MemArena arena(1u << 16);
			auto *region = arena.New<Region>(&arena, &g_state_info);
			Builder(region->CreateBlock()).Create_vchunkactive(chunk, element_base);
		};
	};
	ExpectPanic("chunk >= 64", "invalid vchunkactive shape", shape(64, 8));
	ExpectPanic("element_base >= kMaxVectorElements", "invalid vchunkactive shape",
		    shape(0, qir::kMaxVectorElements));
	// The largest index a legal group can name is one below the constant, and it must NOT Panic:
	// an off-by-one the other way would silently refuse the widest admitted frame.
	{
		MemArena arena(1u << 16);
		auto *region = arena.New<Region>(&arena, &g_state_info);
		Builder(region->CreateBlock()).Create_vchunkactive(63, qir::kMaxVectorElements - 1u);
		printf("  ok   element_base == kMaxVectorElements - 1 is accepted\n");
	}
}
} // namespace

int main()
{
	TestPrinter();
	TestEmission();
	TestFailClosed();
	if (g_failures) {
		printf("FAIL rvv_active_vl_bound_test: %d failure(s)\n", g_failures);
		return 1;
	}
	printf("PASS rvv_active_vl_bound_test\n");
	return 0;
}
