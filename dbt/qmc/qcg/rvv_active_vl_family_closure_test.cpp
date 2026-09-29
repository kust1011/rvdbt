// W29: the FIVE remaining producers whose frame shape already satisfied the shared planner's
// contract, wired to it — and this file is the evidence that wiring them moved nothing else.
//
//   integer active-range policy (`--rvv-qcg-active-vl-int-bound`), LastChunkNode `vstart`:
//     `vzext.vf{2,4,8}` / `vsext.vf{2,4,8}`   (`vext`,     InstVChunkExtend)
//     `vfmerge.vfm` / `vfmv.v.f`              (`vfmerge`,  InstVChunkPartialAlu Merge/Mov)
//     `vfclass.v`                             (`vfunary1`, InstVChunkFClass)
//     `vid.v`                                 (`vid`,      InstVChunkIndex)
//   FP active-range policy (`--rvv-qcg-active-vl-bound`), FrameEpilogue `vstart`:
//     `vfcvt` / `vfwcvt` / `vfncvt`           (`vfcvt`,    InstVChunkFToI/FToF/IToF)
//
// WHY THE TWO POLICIES SPLIT THAT WAY, checked here rather than asserted in a comment: `vfmerge`
// and `vfclass` are FP-TYPED but carry `GuardKind::VTypeInteger` and no FP bracket — they are a
// select and a bit classification, with no rounding — so their frame, their `vstart` ownership and
// their full-VL bound cost are the equal-width integer ones. `vfcvt` is the one that lives inside
// `rvvqcgfpbegin/rvvqcgfpend`, where the epilogue owns `vstart`. [F5] pins both directions: each
// family is byte-identical under the OTHER policy's switch.
//
// WHAT THIS FILE CAN AND CANNOT OBSERVE. These are AVX-512 bodies and this host has none, so
// nothing here EXECUTES the emitted bytes (the CompilerRuntime returns a buffer, never a PROT_EXEC
// mapping) and no assertion is value-level. `--rvv-qcg-typed-chunk-force-emit` bypasses exactly the
// host-feature admission row. The value-level obligation — that skipping a `vl <= element_base`
// unit is bit-for-bit the architectural no-op it already was — belongs to a QEMU differential on
// AVX-512 hardware and is NOT discharged here.
//
// WHAT IS CHECKED, AND WHAT EACH CHECK'S FAILURE LOOKS LIKE
//
//   [F1] SWITCH-OFF IS INERT, in the QIR and in the bytes. Zero `vchunkactive`, `n_typed` equal to
//        the legacy formula (`units`, and `units + 2` for `vfcvt`'s bracket), `finish` on exactly
//        the last body node for the four LastChunkNode families, `frame_clears_vstart == false`,
//        and NONE of the `cmp dword [vec.vl], imm` compares the ON arm would add is present.
//        Failure = a family was wired unconditionally, i.e. the switch is not the gate.
//
//   [F2] SWITCH-ON ADDS EXACTLY THE RIGHT SUFFIX BOUNDS. `units - 1` bounds for the four
//        LastChunkNode families (unit 0 omitted: its test would be `vl <= 0` and nobody would then
//        write `vstart`), `units` for `vfcvt` (the FP epilogue owns `vstart`, so unit 0 IS
//        boundable and its `vl <= 0` test covers the architecturally empty vector — the same shape
//        the accepted `vfalu`/`vfma` frames have). Each bound carries unit index `c` and
//        `element_base == c * stride` with the stride DERIVED IN THIS FILE from the RVV geometry,
//        never read back from a node; each bound IMMEDIATELY precedes its own unit's body node;
//        `n_typed` grew by exactly the bound count. Failure = a bound out of position, a missing or
//        extra unit-0 bound (which is also the silent `vstart` trap), or an `element_base` in BYTES
//        or in SOURCE elements — for `vext` the source stride differs by the extension divisor and
//        for `vfcvt` by the width ratio, and this check is what sees it.
//
//   [F3] THE TRANSFORMATION IS *ONLY* THOSE BOUNDS — the strongest statement available without
//        execution, decomposed exactly as the accepted S1-3W suite's [W2] decomposes it and for the
//        same recorded reason: a naive "splice the pairs out and require literal equality" is
//        WRONG, because the frame guard's forward `ja fallback` jumps OVER the body and its rel32
//        displacement MUST change when bytes are inserted between it and its target. (This suite
//        was first written with the naive form; it failed on every multi-unit shape with exactly
//        the inserted size showing up in two guard displacements, which is the same finding W2
//        records.) So the claim is four parts, each able to fail alone: (1) SIZE —
//        `on == off + sum(pair sizes)`, nothing else added or dropped; (2) EVERY UNIT BODY IS
//        BYTE-IDENTICAL, each body running from its `EmitRvvBodyMask` `mov eax,[vec.vl]` to the
//        next bound (ON) / next body (OFF), the last ending at the frame's single
//        `mov [vec.vstart], 0`; (3) THE TAIL IS BYTE-IDENTICAL from that write onward, modulo its
//        own shift; (4) THE PREFIX before the first inserted byte differs ONLY in 4-byte
//        little-endian fields whose ON value is the OFF value plus the total inserted size — i.e.
//        branch displacements over the body, and nothing else.
//
//   [F4] `vstart` AND FP-EPILOGUE OWNERSHIP SURVIVE. `mov dword [vec.vstart], 0` occurs exactly
//        ONCE in each arm of every shape; every bound's branch resolves to THAT offset; the offset
//        lies strictly before the fallback arm (located independently by
//        `inc qword [rvv_direct_fallbacks]`); and the per-unit `vec.vstart` READ count is the same
//        in both arms and equal to the unit count — prestart units are NOT skipped, they keep
//        running under their zero mask. For `vfcvt` the single write is the one
//        `Emit_rvvqcgfpend` emits INSIDE the MXCSR bracket, so an early-exited convert body still
//        folds its exception bits into `fflags` and still restores MXCSR. Failure = a write
//        duplicated or lost when ownership moved, or an exit that leaves the FP environment open.
//
//   [F5] THE POLICY ASSIGNMENT IS EXACT. The four integer-policy families are byte-identical with
//        only the FP switch on; `vfcvt` is byte-identical with only the integer switch on. Failure
//        = a family answers to the wrong switch, which would make every planned per-policy ablation
//        a measurement of both.
//
//   [F6] SINGLE-UNIT AND INELIGIBLE SHAPES. A fractional-LMUL frame with `units == 1` is
//        byte-identical ON vs OFF for the four LastChunkNode families (no suffix to retire), while
//        `vfcvt`'s single-unit frame legitimately gains its one unit-0 bound — the asymmetry is the
//        `vstart`-ownership rule, and it is asserted in both directions rather than averaged away.
//        A shape the route REFUSES (`vzext.vf8` at e16, where the destination element is narrower
//        than the extension divisor) produces no typed frame at all and identical bytes in both
//        arms. Failure = the planner was consulted where the route does not build a frame, or the
//        `units >= 2` conjunct was dropped.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
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

// ---------------------------------------------------------------------------------------------
// Guest encodings, from the field layout and the decoder's own conditions (rv32_decode.h), never
// as magic words.

constexpr u32 Vsetvli(u32 vsew, u32 vlmul)
{
	return ((0xc0u | (vsew << 3) | vlmul) << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u;
}
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 f3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 OPFVV = 1u, OPMVV = 2u, OPFVF = 5u;
constexpr u32 F6_VXUNARY0 = 0b010010u; // vzext/vsext, sub in the vs1 field
constexpr u32 F6_VMUNARY0 = 0b010100u; // vid.v is sub 10001 with vs2 == 0
constexpr u32 F6_VFUNARY0 = 0b010010u; // vfcvt family, sub in the vs1 field
constexpr u32 F6_VFUNARY1 = 0b010011u; // vfclass.v is sub 10000
constexpr u32 F6_VFMERGE = 0b010111u;
// vext sub-encodings: vzext.vf8=00010, vsext.vf8=00011, vzext.vf4=00100, vsext.vf4=00101,
// vzext.vf2=00110, vsext.vf2=00111 (vext_divisor: <=3 -> 8, <=5 -> 4, else 2).
constexpr u32 EXT_ZVF8 = 2u, EXT_ZVF4 = 4u, EXT_ZVF2 = 6u, EXT_SVF2 = 7u;
constexpr u32 SEW8 = 0u, SEW16 = 1u, SEW32 = 2u, SEW64 = 3u;
constexpr u32 M1 = 0u, M2 = 1u, MF2 = 7u;

// ---------------------------------------------------------------------------------------------
// ONE PROCESS-WIDE CODE BUFFER: [F3], [F5] and [F6] compare two emitted streams for literal
// equality and an emitted region can embed the address of its own buffer, so every emission is
// handed the SAME fixed address. Nothing is executed from it.
alignas(4096) u8 g_code_buf[1u << 20];

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("family closure test: emitted region exceeds the fixed code buffer");
		// ZEROED BEFORE EVERY EMISSION, and that is not hygiene -- it is a correctness
		// requirement of every byte comparison in this file. The returned region is rounded
		// up past the last instruction the emitter wrote, so the copied span's final bytes
		// are PADDING; in a shared buffer that padding is whatever the previous translation
		// left there, which differs between two arms for reasons that have nothing to do
		// with the switch. This suite was first written without the memset and [F3]'s tail
		// comparison failed on three convert shapes in exactly the last five bytes of the
		// region, with a stale VEX `kandw` from the previous shape showing up in one arm.
		memset(g_code_buf, 0, sz);
		return g_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};

struct Env {
	u32 vlen_bits = 512;
	bool int_bound = false;
	bool fp_bound = false;
};

void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
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
	// The two policy switches under test, and the third one held OFF so a widening frame can never
	// contribute a bound to any comparison here.
	config::rvv_qcg_active_vl_int_bound = e.int_bound;
	config::rvv_qcg_active_vl_narrow_bound = true; // W28's ablation control at its default
	config::rvv_qcg_active_vl_bound = e.fp_bound;
	config::rvv_qcg_active_vl_widen_bound = false;
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
	CompilerJob::IpRangesSet ranges = {{0u, (u32)words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}

// PADDING IS NOT CODE, AND ITS LENGTH IS NOT INVARIANT. The returned region is rounded up past the
// last emitted instruction, so the span ends in a run of bytes the emitter never wrote (zero, since
// AllocateCode clears the buffer). That run's LENGTH depends on the emitted size, which the switch
// under test changes by design: measured, the ON arm's region carried two more trailing zeros than
// the OFF arm's on six shapes, which made a byte-exact tail comparison fail for a reason that is not
// an instruction. Trailing zeros are therefore trimmed here, once, so every comparison in this file
// is over emitted instructions only. Trimming is symmetric: if a real final instruction ever ended
// in a zero byte it would be trimmed identically in both arms, and the tail comparison would still
// see any difference in the instruction before it.
void Emit(Built &b)
{
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
	while (!b.code.empty() && b.code.back() == 0)
		b.code.pop_back();
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
				cur = Frame{};
				cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				break;
			case Op::_rvvtypedchunkend:
				if (open) {
					cur.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
					out.push_back(cur);
					open = false;
				}
				break;
			default:
				if (open)
					cur.body.push_back(&ins);
				break;
			}
		}
	return out;
}

unsigned CountOp(Frame const &f, Op op)
{
	unsigned n = 0;
	for (auto *i : f.body)
		n += i->GetOpcode() == op;
	return n;
}

// The five families' body nodes, reduced to the two fields every check needs: the unit's element
// base, and whether this node carries the frame's `vstart = 0` write. `has_finish` is false for the
// convert nodes because they HAVE no such field — the FP bracket owns the write.
struct BodyNode {
	u32 base = 0;
	bool finish = false;
	bool has_finish = false;
};

bool IsBodyNode(Inst *i)
{
	switch (i->GetOpcode()) {
	case Op::_vchunkextend:
	case Op::_vchunkpartialalu:
	case Op::_vchunkfclass:
	case Op::_vchunkindex:
	case Op::_vchunkftoi:
	case Op::_vchunkftof:
	case Op::_vchunkitof:
		return true;
	default:
		return false;
	}
}

BodyNode ReadBody(Inst *i)
{
	switch (i->GetOpcode()) {
	case Op::_vchunkextend: {
		auto *n = static_cast<InstVChunkExtend *>(i);
		return {n->base, n->finish, true};
	}
	case Op::_vchunkpartialalu: {
		auto *n = static_cast<InstVChunkPartialAlu *>(i);
		return {n->element_base, n->finish_instruction, true};
	}
	case Op::_vchunkfclass: {
		auto *n = static_cast<InstVChunkFClass *>(i);
		return {n->base, n->finish, true};
	}
	case Op::_vchunkindex: {
		auto *n = static_cast<InstVChunkIndex *>(i);
		return {n->base, n->finish, true};
	}
	case Op::_vchunkftoi:
		return {static_cast<InstVChunkFToI *>(i)->base, false, false};
	case Op::_vchunkftof:
		return {static_cast<InstVChunkFToF *>(i)->base, false, false};
	default:
		return {static_cast<InstVChunkIToF *>(i)->base, false, false};
	}
}

// ---------------------------------------------------------------------------------------------
// Emitted-byte anchors. Every needle is assembled by an INDEPENDENT asmjit instance and located by
// its own bytes, never by an offset computed from the emitter's structure.

auto const kStateReg = asmjit::x86::gpq(qcg::ArchTraits::STATE);

std::vector<u8> Assemble(std::function<void(asmjit::x86::Assembler &)> const &body)
{
	asmjit::CodeHolder holder;
	if (holder.init(asmjit::Environment::host()))
		Panic("family closure test: asmjit init");
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

unsigned Count(std::vector<u8> const &hay, std::vector<u8> const &needle)
{
	size_t at = SIZE_MAX;
	return CountBytes(hay, needle, &at);
}

size_t Find(std::vector<u8> const &hay, std::vector<u8> const &needle)
{
	size_t at = SIZE_MAX;
	CountBytes(hay, needle, &at);
	return at;
}

int32_t const kVlOff = (int32_t)offsetof(CPUState, vec) + (int32_t)offsetof(rv32::VectorState, vl);
int32_t const kVstartOff =
    (int32_t)offsetof(CPUState, vec) + (int32_t)offsetof(rv32::VectorState, vstart);

std::vector<u8> BoundCmp(u32 element_base)
{
	return Assemble([&](asmjit::x86::Assembler &a) {
		a.cmp(asmjit::x86::dword_ptr(kStateReg, kVlOff), (int32_t)element_base);
	});
}
std::vector<u8> VstartClear()
{
	return Assemble([&](asmjit::x86::Assembler &a) {
		a.mov(asmjit::x86::dword_ptr(kStateReg, kVstartOff), 0);
	});
}
std::vector<u8> VstartLoad()
{
	return Assemble([&](asmjit::x86::Assembler &a) {
		a.mov(asmjit::x86::eax, asmjit::x86::dword_ptr(kStateReg, kVstartOff));
	});
}
std::vector<u8> VlLoad()
{
	// EmitRvvBodyMask's very first instruction, and therefore the first byte of a unit body.
	return Assemble([&](asmjit::x86::Assembler &a) {
		a.mov(asmjit::x86::eax, asmjit::x86::dword_ptr(kStateReg, kVlOff));
	});
}
std::vector<u8> FallbackInc()
{
	return Assemble([&](asmjit::x86::Assembler &a) {
		a.inc(asmjit::x86::qword_ptr(kStateReg,
					     (int32_t)offsetof(CPUState, rvv_direct_fallbacks)));
	});
}

std::vector<size_t> AllOffsets(std::vector<u8> const &hay, std::vector<u8> const &needle)
{
	std::vector<size_t> out;
	if (needle.empty() || needle.size() > hay.size())
		return out;
	for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
		if (memcmp(hay.data() + i, needle.data(), needle.size()) == 0)
			out.push_back(i);
	return out;
}

// Ported verbatim in behaviour from the accepted S1-3W suite: a differing byte run is acceptable
// only if it lies in a 4-byte little-endian field whose ON value is its OFF value plus `delta`,
// i.e. a branch displacement relocated by the inserted size. Anything else is a changed
// instruction and fails.
void CheckDiffersOnlyByRelocation(std::vector<u8> const &off, size_t off_begin,
				  std::vector<u8> const &on, size_t on_begin, size_t len,
				  i64 delta, char const *what, char const *name, u32 vlen)
{
	auto u32at = [](std::vector<u8> const &v, size_t at) {
		u32 x = 0;
		memcpy(&x, v.data() + at, 4);
		return x;
	};
	for (size_t i = 0; i < len;) {
		if (off[off_begin + i] == on[on_begin + i]) {
			++i;
			continue;
		}
		size_t j = i;
		while (j < len && off[off_begin + j] != on[on_begin + j])
			++j;
		bool explained = false;
		if (j - i <= 4)
			for (size_t w = (i >= 3 ? i - 3 : 0); w <= i && !explained; ++w)
				if (j <= w + 4 && w + 4 <= len &&
				    (i64)(i32)(u32at(on, on_begin + w) - u32at(off, off_begin + w)) ==
					delta)
					explained = true;
		if (!explained) {
			fprintf(stderr,
				"  FAIL %s VLEN %u: %s bytes [%zu, %zu) differ and are not a\n"
				"       displacement relocated by %lld\n",
				name, vlen, what, i, j, (long long)delta);
			fprintf(stderr, "       off:");
			for (size_t k = (i >= 6 ? i - 6 : 0); k < std::min(j + 6, len); ++k)
				fprintf(stderr, " %02x", off[off_begin + k]);
			fprintf(stderr, "\n       on :");
			for (size_t k = (i >= 6 ? i - 6 : 0); k < std::min(j + 6, len); ++k)
				fprintf(stderr, " %02x", on[on_begin + k]);
			fprintf(stderr, "\n");
			++g_failures;
		}
		i = j;
	}
}

// A `jbe` is rel8 or rel32 depending on distance; both forms are decoded rather than assumed.
bool DecodeJbe(std::vector<u8> const &code, size_t at, size_t *end, size_t *target)
{
	if (at + 2 > code.size())
		return false;
	if (code[at] == 0x76) {
		*end = at + 2;
		*target = *end + (size_t)(ptrdiff_t)(i8)code[at + 1];
		return true;
	}
	if (at + 6 <= code.size() && code[at] == 0x0f && code[at + 1] == 0x86) {
		i32 rel = 0;
		memcpy(&rel, code.data() + at + 2, 4);
		*end = at + 6;
		*target = *end + (size_t)(ptrdiff_t)rel;
		return true;
	}
	return false;
}

// ---------------------------------------------------------------------------------------------
// Shapes. Every geometric quantity is RE-DERIVED here from the RVV rules and each producer's own
// tiling, never read back from a node — that is what lets [F2]'s ladder check fail.

enum class Fam { Ext, FMerge, FClass, Id, FCvt };

struct Shape {
	char const *name;
	Fam fam;
	u32 vsew;    // vsetvli's vsew field (the vtype SEW)
	u32 vlmul;   // vsetvli's vlmul field
	int lmul_log2;
	u32 insn;
	u32 ext_div = 1;   // Ext: the extension divisor (2/4/8)
	u32 cvt_ss = 0;    // FCvt: source element bytes
	u32 cvt_sew = 0;   // FCvt: destination element bytes
	bool refused = false; // the route must build NO frame for this shape
};

u32 SewBytes(u32 vsew) { return 1u << vsew; }
u32 HostChunk(u32 vlen) { return std::min(vlen / 8u, 64u); }

// Units and the element stride, per producer, exactly as the producer computes them.
u32 Units(Shape const &s, u32 vlen)
{
	u32 const rb = vlen / 8u, bytes = HostChunk(vlen);
	switch (s.fam) {
	case Fam::Ext:
	case Fam::Id: {
		u32 const gb = s.lmul_log2 >= 0 ? (rb << s.lmul_log2) : (rb >> (-s.lmul_log2));
		return (gb + bytes - 1u) / bytes;
	}
	case Fam::FMerge:
	case Fam::FClass: {
		u32 const sew = SewBytes(s.vsew);
		u32 const vmax = s.lmul_log2 >= 0 ? (rb << s.lmul_log2) / sew : (rb >> (-s.lmul_log2)) / sew;
		return (vmax * sew + bytes - 1u) / bytes;
	}
	default: { // FCvt
		u32 const lanes = bytes / std::max(s.cvt_ss, s.cvt_sew);
		u32 const sew = SewBytes(s.vsew);
		u32 const vmax = s.lmul_log2 >= 0 ? (rb << s.lmul_log2) / sew : (rb >> (-s.lmul_log2)) / sew;
		return (vmax + lanes - 1u) / lanes;
	}
	}
}

u32 Stride(Shape const &s, u32 vlen)
{
	u32 const bytes = HostChunk(vlen);
	switch (s.fam) {
	case Fam::Ext:
	case Fam::FMerge:
	case Fam::FClass:
	case Fam::Id:
		return bytes / SewBytes(s.vsew); // destination elements per unit
	default:
		return bytes / std::max(s.cvt_ss, s.cvt_sew); // FCvt's `lanes`
	}
}

// The FP bracket owns `vstart` only for the convert family; the other four carry it on their last
// body node. That single fact decides the first boundable unit and the bound count.
bool FrameEpilogueOwner(Fam f) { return f == Fam::FCvt; }
u32 FirstBoundedUnit(Fam f) { return FrameEpilogueOwner(f) ? 0u : 1u; }
bool IntPolicy(Fam f) { return !FrameEpilogueOwner(f); }

u32 ExpectedBounds(Shape const &s, u32 vlen)
{
	u32 const u = Units(s, vlen), first = FirstBoundedUnit(s.fam);
	return u > first ? u - first : 0u;
}

u32 LegacyNTyped(Shape const &s, u32 vlen)
{
	// `vfcvt` declares its two bracket nodes on top of one node per unit; the other four declare
	// exactly one node per unit.
	return Units(s, vlen) + (s.fam == Fam::FCvt ? 2u : 0u);
}

// MULTI-UNIT SHAPES ONLY. At VLEN 512 an LMUL=1 group IS one host chunk (64 bytes), so every
// LMUL=1 row below would be a single-unit frame at 512 and could not carry a bound at all; those
// belong in [F6], and the `units >= 2` assertion in [F2] is what keeps this table honest. The
// `vfcvt` rows are the exception: its unit is `min(rb,64)/max(ss,sew)` ELEMENTS, so a widening or
// narrowing convert already has two units at LMUL=1.
Shape const kShapes[] = {
    // vzext/vsext: the destination element must be at least the divisor wide.
    {"vzext.vf2 e16,m2", Fam::Ext, SEW16, M2, 1, MakeOpV(F6_VXUNARY0, 1, 12, EXT_ZVF2, 8, OPMVV), 2},
    {"vsext.vf2 e32,m2", Fam::Ext, SEW32, M2, 1, MakeOpV(F6_VXUNARY0, 1, 12, EXT_SVF2, 8, OPMVV), 2},
    {"vzext.vf2 e32,m2", Fam::Ext, SEW32, M2, 1, MakeOpV(F6_VXUNARY0, 1, 12, EXT_ZVF2, 8, OPMVV), 2},
    {"vzext.vf4 e32,m2", Fam::Ext, SEW32, M2, 1, MakeOpV(F6_VXUNARY0, 1, 12, EXT_ZVF4, 8, OPMVV), 4},
    {"vzext.vf2 e64,m2", Fam::Ext, SEW64, M2, 1, MakeOpV(F6_VXUNARY0, 1, 12, EXT_ZVF2, 8, OPMVV), 2},
    {"vzext.vf2 e32,m2 masked", Fam::Ext, SEW32, M2, 1, MakeOpV(F6_VXUNARY0, 0, 12, EXT_ZVF2, 8, OPMVV), 2},
    // vfmerge.vfm (vm=0, v0 is an OPERAND) and vfmv.v.f (vm=1, vs2 fixed to 0).
    {"vfmerge.vfm e32,m2", Fam::FMerge, SEW32, M2, 1, MakeOpV(F6_VFMERGE, 0, 10, 3, 8, OPFVF)},
    {"vfmerge.vfm e64,m2", Fam::FMerge, SEW64, M2, 1, MakeOpV(F6_VFMERGE, 0, 10, 3, 8, OPFVF)},
    {"vfmv.v.f    e32,m2", Fam::FMerge, SEW32, M2, 1, MakeOpV(F6_VFMERGE, 1, 0, 3, 8, OPFVF)},
    // vfclass.v: OPFVV, funct6 010011, sub 10000.
    {"vfclass.v  e32,m2", Fam::FClass, SEW32, M2, 1, MakeOpV(F6_VFUNARY1, 1, 10, 16, 8, OPFVV)},
    {"vfclass.v  e64,m2", Fam::FClass, SEW64, M2, 1, MakeOpV(F6_VFUNARY1, 1, 10, 16, 8, OPFVV)},
    {"vfclass.v  e32,m2 masked", Fam::FClass, SEW32, M2, 1, MakeOpV(F6_VFUNARY1, 0, 10, 16, 8, OPFVV)},
    // vid.v: OPMVV, funct6 010100, sub 10001, vs2 == 0.
    {"vid.v      e8,m2 ", Fam::Id, SEW8, M2, 1, MakeOpV(F6_VMUNARY0, 1, 0, 17, 8, OPMVV)},
    {"vid.v      e32,m2", Fam::Id, SEW32, M2, 1, MakeOpV(F6_VMUNARY0, 1, 0, 17, 8, OPMVV)},
    {"vid.v      e32,m2 masked", Fam::Id, SEW32, M2, 1, MakeOpV(F6_VMUNARY0, 0, 0, 17, 8, OPMVV)},
    // vfcvt: same-width x.f (sub 1), widening f.f (sub 12), narrowing x.f (sub 17).
    {"vfcvt.x.f.v  e32,m2", Fam::FCvt, SEW32, M2, 1, MakeOpV(F6_VFUNARY0, 1, 10, 1, 8, OPFVV), 1, 4, 4},
    {"vfcvt.f.x.v  e64,m2", Fam::FCvt, SEW64, M2, 1, MakeOpV(F6_VFUNARY0, 1, 10, 3, 8, OPFVV), 1, 8, 8},
    {"vfwcvt.f.f.v e32,m1", Fam::FCvt, SEW32, M1, 0, MakeOpV(F6_VFUNARY0, 1, 10, 12, 8, OPFVV), 1, 4, 8},
    {"vfncvt.x.f.w e32,m1", Fam::FCvt, SEW32, M1, 0, MakeOpV(F6_VFUNARY0, 1, 10, 17, 8, OPFVV), 1, 8, 4},
    {"vfcvt.x.f.v  e32,m2 masked", Fam::FCvt, SEW32, M2, 1, MakeOpV(F6_VFUNARY0, 0, 10, 1, 8, OPFVV), 1, 4, 4},
};

// [F6] one-unit frames at VLEN 512 -- LMUL=1 for the four group-tiled families (the group is
// exactly one host chunk) and a same-width convert, whose 16 elements are one unit of 16 lanes --
// plus one shape the route must refuse outright.
Shape const kOneUnit[] = {
    {"vzext.vf2 e32,m1", Fam::Ext, SEW32, M1, 0, MakeOpV(F6_VXUNARY0, 1, 10, EXT_ZVF2, 8, OPMVV), 2},
    {"vfmerge.vfm e32,m1", Fam::FMerge, SEW32, M1, 0, MakeOpV(F6_VFMERGE, 0, 10, 3, 8, OPFVF)},
    {"vfclass.v e32,m1", Fam::FClass, SEW32, M1, 0, MakeOpV(F6_VFUNARY1, 1, 10, 16, 8, OPFVV)},
    {"vid.v     e32,m1", Fam::Id, SEW32, M1, 0, MakeOpV(F6_VMUNARY0, 1, 0, 17, 8, OPMVV)},
    {"vfcvt.x.f.v e32,m1", Fam::FCvt, SEW32, M1, 0, MakeOpV(F6_VFUNARY0, 1, 10, 1, 8, OPFVV), 1, 4, 4},
};
Shape const kRefused = {"vzext.vf8 e16,m1 (ds < div)", Fam::Ext, SEW16, M1, 0,
			MakeOpV(F6_VXUNARY0, 1, 10, EXT_ZVF8, 8, OPMVV), 8, 0, 0, true};

std::vector<u32> Program(Shape const &s) { return {Vsetvli(s.vsew, s.vlmul), s.insn}; }

Env ArmOn(Shape const &s, u32 vlen)
{
	return Env{vlen, IntPolicy(s.fam), !IntPolicy(s.fam)};
}
Env ArmOff(u32 vlen) { return Env{vlen, false, false}; }

bool OneFrame(Built &b, std::vector<Frame> &out, char const *name)
{
	out = FindFrames(b.region);
	if (out.size() != 1u) {
		fprintf(stderr, "  FAIL %s: expected exactly 1 typed frame, got %zu\n", name,
			out.size());
		++g_failures;
		return false;
	}
	return true;
}

// ---------------------------------------------------------------------------------------------

void TestOffIsInert()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built off;
			Translate(off, Program(s), ArmOff(vlen));
			std::vector<Frame> f;
			if (!OneFrame(off, f, s.name))
				continue;
			u32 const units = Units(s, vlen), stride = Stride(s, vlen);
			unsigned bodies = 0, finishes = 0, last_is_finish = 0;
			for (auto *i : f[0].body) {
				if (!IsBodyNode(i))
					continue;
				auto const n = ReadBody(i);
				++bodies;
				CHECK_EQ(n.base, (bodies - 1u) * stride);
				if (n.has_finish) {
					finishes += n.finish;
					last_is_finish = (bodies == units) && n.finish;
				}
			}
			CHECK_EQ(bodies, units);
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 0u);
			CHECK_EQ((unsigned)f[0].begin->n_typed, LegacyNTyped(s, vlen));
			// The four LastChunkNode families carry the write on their last node; the convert
			// family's nodes have no such field at all and the bracket owns it.
			CHECK_EQ(finishes, (FrameEpilogueOwner(s.fam) ? 0u : 1u));
			CHECK_EQ(last_is_finish, (FrameEpilogueOwner(s.fam) ? 0u : 1u));
			if (f[0].end)
				CHECK_EQ((int)f[0].end->frame_clears_vstart, 0);
			Emit(off);
			unsigned compares = 0;
			for (u32 c = FirstBoundedUnit(s.fam); c < units; ++c)
				compares += Count(off.code, BoundCmp(c * stride));
			CHECK_EQ(compares, 0u);
		}
	printf("    %zu shapes x 2 VLENs: legacy frame, legacy n_typed, zero vl compares\n",
	       sizeof(kShapes) / sizeof(kShapes[0]));
}

void TestOnLadder()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built on;
			Translate(on, Program(s), ArmOn(s, vlen));
			std::vector<Frame> f;
			if (!OneFrame(on, f, s.name))
				continue;
			u32 const units = Units(s, vlen), stride = Stride(s, vlen);
			u32 const first = FirstBoundedUnit(s.fam), want = ExpectedBounds(s, vlen);
			CHECK(units >= 2u); // every table row is a multi-unit frame by construction
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), want);
			CHECK_EQ((unsigned)f[0].begin->n_typed, LegacyNTyped(s, vlen) + want);
			if (f[0].end)
				CHECK_EQ((int)f[0].end->frame_clears_vstart,
					 (FrameEpilogueOwner(s.fam) ? 0 : 1));
			// Bound c immediately precedes unit c's body node, carries unit index c and
			// element base c*stride; units below `first` have none; no body node finishes.
			u32 unit = 0;
			bool pending = false;
			for (auto *i : f[0].body) {
				if (i->GetOpcode() == Op::_vchunkactive) {
					auto *n = static_cast<InstVChunkActive *>(i);
					CHECK_EQ((unsigned)n->chunk, unit);
					CHECK_EQ(n->element_base, unit * stride);
					CHECK(unit >= first);
					CHECK(!pending);
					pending = true;
					continue;
				}
				if (!IsBodyNode(i))
					continue;
				auto const n = ReadBody(i);
				CHECK_EQ(n.base, unit * stride);
				if (n.has_finish)
					CHECK(!n.finish);
				CHECK_EQ(pending, unit >= first);
				pending = false;
				++unit;
			}
			CHECK_EQ(unit, units);
		}
	printf("    bounds = units-%s, element_base == c*stride, one per unit, in position\n",
	       "1 (integer) / 0 (convert)");
}

// [F3] the four-part decomposition. See the header note: the naive splice cannot pass, because the
// frame guard's forward `ja fallback` displacement must change when bytes are inserted before its
// target.
//
// THE REGION ANCHOR IS THE BOUND'S OWN LAST BYTE, NOT THE BODY'S MASK PROLOGUE. `Emit_vchunkactive`
// emits the bound IMMEDIATELY before the body node it guards, so in the ON arm a bound's `jbe` ends
// exactly where that unit's body begins -- whatever that body's first instruction is. That matters:
// two of these five emitters do NOT start with `EmitRvvBodyMask` (Emit_vchunkfclass materialises its
// classification constants first, and Emit_vchunkindex builds its index vector first), so anchoring
// on the mask's `mov eax,[vec.vl]` -- which is what the accepted S1-3W suite can do, because its
// body starts there -- put the region boundary hundreds of bytes past the bound. The per-unit mask
// count is still asserted, just as a property rather than as an anchor.
void TestOnlyTheBoundsMoved()
{
	unsigned checked = 0;
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			u32 const units = Units(s, vlen), stride = Stride(s, vlen);
			u32 const first = FirstBoundedUnit(s.fam);
			if (units < 2u)
				continue;
			Built off, on;
			Translate(off, Program(s), ArmOff(vlen));
			Emit(off);
			Translate(on, Program(s), ArmOn(s, vlen));
			Emit(on);
			if (off.code.empty() || on.code.empty()) {
				CHECK(false);
				continue;
			}
			// One per-unit mask derivation per unit, in each arm: a property of the body,
			// asserted so that a body which stopped deriving its own mask fails here.
			CHECK_EQ(AllOffsets(off.code, VlLoad()).size(), units);
			CHECK_EQ(AllOffsets(on.code, VlLoad()).size(), units);
			size_t const vstart_off = Find(off.code, VstartClear());
			size_t const vstart_on = Find(on.code, VstartClear());
			CHECK(vstart_off != SIZE_MAX);
			CHECK(vstart_on != SIZE_MAX);
			if (vstart_off == SIZE_MAX || vstart_on == SIZE_MAX)
				continue;

			// Each bound's [cmp, jbe) range, located by its own immediate.
			std::vector<std::pair<size_t, size_t>> cut;
			bool ok = true;
			size_t total = 0;
			for (u32 c = first; c < units && ok; ++c) {
				auto const cmp = BoundCmp(c * stride);
				size_t at = SIZE_MAX, end = 0, target = 0;
				if (CountBytes(on.code, cmp, &at) != 1u || at == SIZE_MAX ||
				    !DecodeJbe(on.code, at + cmp.size(), &end, &target)) {
					CHECK(false);
					ok = false;
					break;
				}
				cut.push_back({at, end});
				total += end - at;
			}
			if (!ok)
				continue;
			std::sort(cut.begin(), cut.end());
			CHECK_EQ(cut.size(), ExpectedBounds(s, vlen));

			// (1) SIZE: the pairs and nothing else.
			CHECK_EQ(on.code.size(), off.code.size() + total);
			// (2) EVERY GUARDED BODY IS BYTE-IDENTICAL. Body i runs from the end of its own
			// bound to the start of the next bound, or to the frame's `vstart` write for the
			// last one; the OFF-arm counterpart is the same range shifted back by everything
			// inserted before it.
			size_t cum = 0;
			for (size_t i = 0; i < cut.size(); ++i) {
				cum += cut[i].second - cut[i].first;
				size_t const b_on = cut[i].second;
				size_t const e_on =
				    i + 1 < cut.size() ? cut[i + 1].first : vstart_on;
				size_t const b_off = b_on - cum;
				size_t const e_off =
				    i + 1 < cut.size() ? cut[i + 1].first - cum : vstart_off;
				CHECK_EQ(e_on - b_on, e_off - b_off);
				if (e_on - b_on != e_off - b_off)
					continue;
				CHECK_EQ(memcmp(off.code.data() + b_off, on.code.data() + b_on,
						e_on - b_on),
					 0);
			}
			// (3) THE TAIL from the single `vstart` write onward, modulo its own shift.
			CHECK_EQ(off.code.size() - vstart_off, on.code.size() - vstart_on);
			if (off.code.size() - vstart_off == on.code.size() - vstart_on)
				CheckDiffersOnlyByRelocation(off.code, vstart_off, on.code, vstart_on,
							     off.code.size() - vstart_off,
							     -(i64)total, "tail", s.name, vlen);
			// (4) THE HEAD before the first inserted byte -- the guard, plus (for the four
			// LastChunkNode families, whose unit 0 is never bounded) unit 0's whole body --
			// differs only in displacements relocated by the total insertion.
			size_t const head = cut.front().first;
			CHECK(head <= off.code.size());
			if (head <= off.code.size())
				CheckDiffersOnlyByRelocation(off.code, 0, on.code, 0, head, (i64)total,
							     "head", s.name, vlen);
			++checked;
		}
	CHECK(checked > 0);
	printf("    %u cells: size delta == the pairs exactly, every guarded body byte-identical,\n"
	       "    the tail and the head differ only in relocated displacements\n",
	       checked);
}

void TestVstartOwnership()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built off, on;
			Translate(off, Program(s), ArmOff(vlen));
			Emit(off);
			Translate(on, Program(s), ArmOn(s, vlen));
			Emit(on);
			u32 const units = Units(s, vlen), stride = Stride(s, vlen);
			// Exactly one architectural `vstart = 0` in each arm, wherever ownership sits.
			CHECK_EQ(Count(off.code, VstartClear()), 1u);
			CHECK_EQ(Count(on.code, VstartClear()), 1u);
			// Prestart units are not skipped: one `vec.vstart` read per unit, both arms.
			CHECK_EQ(Count(off.code, VstartLoad()), units);
			CHECK_EQ(Count(on.code, VstartLoad()), units);
			// Every bound lands on that single write, which precedes the fallback arm.
			size_t const vstart_at = Find(on.code, VstartClear());
			size_t const fallback_at = Find(on.code, FallbackInc());
			CHECK(vstart_at != SIZE_MAX);
			CHECK(fallback_at != SIZE_MAX);
			if (vstart_at == SIZE_MAX || fallback_at == SIZE_MAX)
				continue;
			CHECK(vstart_at < fallback_at);
			// WHERE THE BRANCH LANDS IS CONVENTION-SPECIFIC, and asserting one rule for
			// both would have hidden the other. For the four LastChunkNode families
			// Emit_rvvtypedchunkend binds the body-done label immediately BEFORE the
			// frame's single `vstart = 0`, so the target IS that write's offset. For the
			// convert family Emit_rvvqcgfpend binds it at the TOP of the FP epilogue --
			// before `EmitCloseRvvFpBracket()` -- so the target is strictly before the
			// write, and the bytes between them are exactly the fflags accrual and the
			// MXCSR restore that an early-exited body must still run. Both are checked as
			// what they are.
			auto const starts = AllOffsets(on.code, VlLoad());
			CHECK_EQ(starts.size(), units);
			size_t common = SIZE_MAX;
			for (u32 c = FirstBoundedUnit(s.fam); c < units; ++c) {
				auto const needle = BoundCmp(c * stride);
				size_t at = SIZE_MAX;
				if (CountBytes(on.code, needle, &at) != 1u)
					continue;
				size_t end = 0, target = 0;
				if (!DecodeJbe(on.code, at + needle.size(), &end, &target))
					continue;
				// Every bound in the frame leaves to the SAME place.
				if (common == SIZE_MAX)
					common = target;
				CHECK_EQ(target, common);
				if (FrameEpilogueOwner(s.fam)) {
					CHECK(target < vstart_at);
					// and it is past the last unit's body start, so the skipped
					// range contains real work rather than only the epilogue.
					if (starts.size() == units)
						CHECK(target > starts.back());
				} else {
					CHECK_EQ(target, vstart_at);
				}
				CHECK(target < fallback_at);
			}
		}
	printf("    one vstart write per arm, one vstart read per unit; every jbe lands on the\n");
	printf("    frame's vstart write (integer) or the top of the FP epilogue before it (convert)\n");
}

void TestPolicySeparation()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built off, other;
			Translate(off, Program(s), ArmOff(vlen));
			Emit(off);
			// The OTHER policy's switch, on its own: this family must not move at all.
			Translate(other, Program(s), Env{vlen, !IntPolicy(s.fam), IntPolicy(s.fam)});
			Emit(other);
			std::vector<Frame> f;
			if (OneFrame(other, f, s.name))
				CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 0u);
			CHECK(other.code == off.code);
		}
	printf("    each family is byte-identical under the other policy's switch\n");
}

void TestSingleUnitAndRefused()
{
	u32 const vlen = 512;
	for (auto const &s : kOneUnit) {
		CHECK_EQ(Units(s, vlen), 1u);
		Built off, on;
		Translate(off, Program(s), ArmOff(vlen));
		Emit(off);
		Translate(on, Program(s), ArmOn(s, vlen));
		Emit(on);
		std::vector<Frame> fo, fn;
		if (!OneFrame(off, fo, s.name) || !OneFrame(on, fn, s.name))
			continue;
		if (FrameEpilogueOwner(s.fam)) {
			// The convert family's epilogue owns `vstart`, so unit 0 IS boundable and a
			// one-unit frame legitimately gains exactly one bound with immediate 0.
			CHECK_EQ(CountOp(fn[0], Op::_vchunkactive), 1u);
			CHECK_EQ((unsigned)fn[0].begin->n_typed, (unsigned)fo[0].begin->n_typed + 1u);
			CHECK(on.code != off.code);
			CHECK_EQ(Count(on.code, BoundCmp(0)), 1u);
		} else {
			// The other four never bound unit 0, so the frame is byte-identical.
			CHECK_EQ(CountOp(fn[0], Op::_vchunkactive), 0u);
			CHECK_EQ((unsigned)fn[0].begin->n_typed, (unsigned)fo[0].begin->n_typed);
			if (fn[0].end)
				CHECK_EQ((int)fn[0].end->frame_clears_vstart, 0);
			CHECK(on.code == off.code);
		}
	}
	// A shape the route refuses: no typed frame in either arm, identical bytes.
	{
		Built off, on;
		Translate(off, Program(kRefused), ArmOff(vlen));
		Emit(off);
		Translate(on, Program(kRefused), ArmOn(kRefused, vlen));
		Emit(on);
		CHECK_EQ(FindFrames(off.region).size(), 0u);
		CHECK_EQ(FindFrames(on.region).size(), 0u);
		CHECK(on.code == off.code);
		CHECK(!on.code.empty());
	}
	printf("    one-unit frames: 4 integer families byte-identical, convert gains its unit-0\n");
    printf("    bound; the refused shape builds no frame in either arm\n");
}
} // namespace

int main()
{
	printf("[F1] the policy switch off is inert\n");
	TestOffIsInert();
	printf("[F2] on adds exactly the right suffix bounds\n");
	TestOnLadder();
	printf("[F3] and NOTHING else moved (size / bodies / tail / prefix)\n");
	TestOnlyTheBoundsMoved();
	printf("[F4] vstart / FP-epilogue ownership survives\n");
	TestVstartOwnership();
	printf("[F5] the two policies do not cross\n");
	TestPolicySeparation();
	printf("[F6] single-unit and refused shapes\n");
	TestSingleUnitAndRefused();
	if (g_failures) {
		printf("FAIL rvv_active_vl_family_closure_test: %d failure(s)\n", g_failures);
		return 1;
	}
	printf("PASS rvv_active_vl_family_closure_test\n");
	return 0;
}
