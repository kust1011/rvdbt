// S1-3W: `--rvv-qcg-active-vl-widen-bound` wired into the WIDENING integer route
// (RvvTryIntegerFamily's `id_rv32_vwint` block, every `InstVChunkWiden` node). The equal-width
// route (S1-3A, its own switch), narrowing, mask-logic, reduction, slide/gather, vector memory,
// whole-register transfers and multi-member vector runs are deliberately NOT wired by this switch,
// and this file is where that stays true.
//
// WHAT THIS FILE CAN AND CANNOT OBSERVE. The frames under test are AVX-512 bodies and this suite is
// built and run on a host with no AVX-512, so the emitted body cannot be EXECUTED here and no
// assertion below is a value-level one. `--rvv-qcg-typed-chunk-force-emit` bypasses exactly the
// host-feature admission row so the shape can be constructed and inspected; nothing here ever
// branches into the returned bytes (the CompilerRuntime hands back a std::vector, never a PROT_EXEC
// mapping). The value-level obligation -- that skipping a `vl <= element_base` chunk is bit-for-bit
// the architectural no-op it already was -- belongs to the QEMU differential on AVX-512 hardware
// (design matrix W12) and is NOT discharged here. What IS discharged here is everything the emitted
// bytes and the QIR can settle.
//
// THE ONE THING THAT IS WIDENING-SPECIFIC, AND WHY EVERY LADDER CHECK RE-DERIVES IT. A widening op's
// destination EEW is 2*SEW and its EMUL is 2*LMUL, but RVV leaves the ELEMENT INDEXING alone:
// destination element i is produced from source element i and `vl` counts elements. So chunk c's
// first element index is `c * chunk_bytes / (2 * SEW)` -- the DESTINATION lane count -- and every
// `lanes` in this file is computed from the shape table that way rather than read back from the
// node the translator built. Using the source lane count instead would double the stride, and the
// ladder checks are the ones that see it.
//
// WHAT IS CHECKED (design report matrix W1-W11), AND WHAT EACH CHECK'S FAILURE LOOKS LIKE
//
//   [W1] PARTIAL VL / THE ELEMENT LADDER. Over e8/e16/e32 x mf2/m1/m2/m4 x VLEN 512/1024: with the
//        switch ON the frame carries exactly `chunks - 1` bounds, bound c carries chunk index c and
//        `element_base == c * (chunk_bytes / (2*SEW))`, each bound IMMEDIATELY precedes its own
//        chunk node, chunk 0 has none, `n_typed == 2*chunks - 1`, every chunk node's `finish` is
//        clear and `frame_clears_vstart` is set. The branch is decoded and required to be `jbe`
//        (0x76 / 0x0f86), never `jb`. Failure = a chunk-0 bound (the full-VL cost of §7 would be
//        understated), a bound out of position, an `element_base` in BYTES or in SOURCE lanes (both
//        differ from the correct ladder by a factor this check sees), or a `jb`, which at exactly
//        `vl == lanes` would run one entirely-tail chunk -- correct output, no saving, and invisible
//        to any check that only counts bounds.
//
//   [W2] FULL VL: THE TRANSFORMATION IS EXACTLY "n-1 COMPARE/BRANCH PAIRS". The ON stream with the
//        `chunks - 1` `cmp`+`jbe` byte ranges SPLICED OUT is byte-for-byte the OFF stream. That is
//        the full-VL statement in its strongest available form: on a `vl == VLMAX` execution every
//        bound falls through, so the executed instructions are the OFF ones plus exactly those
//        pairs -- and nothing else moved, including the single `vstart` write. Failure = the switch
//        changed, added or dropped any other byte, or emitted a different number of bounds, either
//        of which invalidates the full-VL ablation's premise that it measures ONLY the never-taken
//        bound.
//
//   [W3] NON-ZERO vstart. The per-chunk body mask reads `vec.vstart` once per chunk, and that count
//        is the same in both arms and equal to `chunks`: prestart chunks are NOT skipped, they keep
//        running under their zero mask. `mov dword [vec.vstart], 0` occurs exactly once in each arm.
//        Failure = the bound was made to skip prestart chunks (counts drop below `chunks`), or the
//        ownership of the `vstart` write ended up duplicated or lost when it moved off the last
//        widening node onto the frame epilogue.
//
//   [W4] MASKED/UNMASKED: THE EARLY EXIT IS BLIND TO v0. The bound count and the whole ladder are
//        identical for `vm = 1` and `vm = 0` forms of the same instruction, and each bound is
//        exactly `cmp dword [vec.vl], imm` followed IMMEDIATELY by the `jbe`, with nothing between
//        them. Failure = a `kortest`-style test on the active mask, which would skip LIVE chunks
//        whenever `vstart > 0` made a leading chunk's mask zero.
//
//   [W5] LEGAL OVERLAP. Every overlap `vwint_registers_legal` admits -- the top-aligned narrow
//        source (`r + ng == vd + dg`), and the `.wv` wide `vs2` sharing `vd`'s group -- produces the
//        same per-chunk work in both arms and the same chunk order 0,1,2,...; and `vwmacc*` with a
//        top-aligned overlap is REJECTED outright (no frame at all), which is the accumulate form's
//        own rule and is asserted rather than assumed. Failure = the bound reordered or retargeted
//        chunk work. This is the watchdog for "delete a suffix, reorder nothing": with a destination
//        group twice its source group, a reordering would let a later chunk read source bytes an
//        earlier chunk had already overwritten.
//
//   [W6] `.wv` / `.wx` WIDE-vs2 FORMS. `vwadd.wv`, `vwsub.wv` and `vwaddu.wx` produce the SAME
//        ladder as the `.vv` form at the same vtype, even though their `vs2` window is `bytes`
//        rather than `bytes/2` and their source offset advances by `c*bytes` rather than
//        `c*bytes/2`. Failure = the bound was built from the source offset rather than from the
//        destination element index; the `.wv` and `.vv` ladders would then differ by a factor of
//        two and the `.wv` frame would skip live chunks.
//
//   [W7] `vwmacc*`. `vwmaccu.vv`, `vwmacc.vv`, `vwmaccsu.vv` and `vwmaccus.vx` bound like the rest,
//        and their per-chunk work -- including the `rd` window each accumulate reads back -- is
//        unchanged between the arms, with each chunk's `rd` read window equal to its own store
//        window. Failure = an accumulate whose read crossed a chunk boundary would make a skipped
//        chunk non-inert; a differing work multiset would mean the bound changed the accumulation.
//
//   [W8] NO CSR SIDE EFFECT. No widening frame, in either arm, contains ANY reference to
//        `vec.vxsat`, `vec.vxrm` or `fpsr/fflags`: the displacement of each is absent from the
//        emitted bytes. Each displacement is first checked to be too large for a disp8 form, so
//        absence of the 4-byte pattern is absence of the access; and an equal-width `vsadd.vv`
//        frame is emitted as a POSITIVE CONTROL proving the scan can see a `vxsat` access when one
//        exists. Failure = a saturating form silently added to `vwint_supported` without the sticky
//        flag's mask gating -- the one way a skipped chunk could stop being a no-op.
//
//   [W9] THE EMITTED SHAPE, EXACTLY. Every `jbe` in a bounded frame resolves to the SAME address;
//        that address is the offset of the frame's single `mov dword [vec.vstart], 0`; it is
//        strictly BEFORE the fallback arm (located independently by `inc qword
//        [rvv_direct_fallbacks]`); there is NO `cmp [vec.vl], 0` and no bound before chunk 0 (the
//        first bound lies after chunk 0's own body-mask install); and real work lies strictly inside
//        the skipped range (the last chunk's `kmovq k1, rdi`). Failure = an early exit landing on
//        the fallback would run the ordered helper on top of chunks the body had already stored; one
//        landing on the join would leave `vstart` dirty for the NEXT vector instruction.
//
//  [W10] EXCLUSIONS ARE STRUCTURAL, NOT COMMENTS. With the switch ON: a one-chunk frame (every
//        fractional-LMUL widening frame at VLEN 512) is byte-for-byte identical to the OFF arm; the
//        node's 64-chunk capacity is exercised at its exact boundary (VLEN 4096, e8/m4 -> 64 chunks,
//        63 bounds, top chunk index 63) and the route is shown to be UNABLE to exceed it, because
//        widening requires `emul_in_range(lmul_log2 + 1)` and so caps LMUL at 4; no widening
//        instruction ever lands in a multi-member run frame; and the emitter's fail-closed contracts
//        are exercised on hand-built WIDENING frames in forked children whose stderr must match the
//        expected Panic text -- a `Vlenb*` whole-register guard, a frame with a partial arm, and both
//        directions of the `frame_clears_vstart` / emitted-bound disagreement, which is exactly what
//        dropping the `chunks >= 2` conjunct produces. Failure of the last pair = the silent form is
//        a frame in which NOBODY writes `vstart = 0`, corrupting the NEXT vector instruction.
//
//  [W11] DEFAULT-OFF IS REALLY INERT, AND THE THREE SWITCHES ARE INDEPENDENT. With the switch clear,
//        every shape at every VLEN has zero bounds, `n_typed == chunks`, `finish` on exactly the
//        last chunk node, `frame_clears_vstart == false`, and none of the compares the ON arm would
//        add. And across the pairs: the widening switch leaves an equal-width frame and an FP frame
//        byte-identical (with the other switch both off and on), while the equal-width and FP
//        switches leave a widening frame byte-identical. Failure = one switch moved another route,
//        which would make every planned per-family ablation a measurement of two families.

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
#include <sys/wait.h>
#include <tuple>
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

// ---------------------------------------------------------------------------------------------
// Guest encodings, built from the field layout rather than copied as magic words.

// vsetvli rd=a0, rs1=a0, vtypei = ta|ma|(vsew<<3)|vlmul.
constexpr u32 Vsetvli(u32 vsew, u32 vlmul)
{
	return ((0xc0u | (vsew << 3) | vlmul) << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u;
}
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 f3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}
// The widening integer route accepts only the OPMVV and OPMVX funct3 encodings.
constexpr u32 OPMVV = 2u, OPMVX = 6u, OPIVV = 0u, OPFVV = 1u;

// funct6, RVV 1.0. Kept as the spec's bit patterns so a reader can check them against the manual.
constexpr u32 F6_VWADDU = 0b110000u, F6_VWADD = 0b110001u, F6_VWSUBU = 0b110010u,
	      F6_VWSUB = 0b110011u, F6_VWADDU_W = 0b110100u, F6_VWADD_W = 0b110101u,
	      F6_VWSUB_W = 0b110111u, F6_VWMULU = 0b111000u, F6_VWMULSU = 0b111010u,
	      F6_VWMUL = 0b111011u, F6_VWMACCU = 0b111100u, F6_VWMACC = 0b111101u,
	      F6_VWMACCUS = 0b111110u, F6_VWMACCSU = 0b111111u;
// Non-widening funct6 used only for the cross-route independence and positive-control checks.
constexpr u32 F6_VADD = 0u, F6_VSADD = 33u, F6_VFADD = 0u;

constexpr u32 SEW8 = 0u, SEW16 = 1u, SEW32 = 2u, SEW64 = 3u;
// vlmul field encodings: 000=m1 001=m2 010=m4 011=m8, 101=mf8 110=mf4 111=mf2.
constexpr u32 M1 = 0u, M2 = 1u, M4 = 2u, MF2 = 7u;

constexpr int LmulLog2(u32 vlmul) { return (vlmul & 0b100u) ? (int)vlmul - 8 : (int)vlmul; }

// ---------------------------------------------------------------------------------------------

// ONE PROCESS-WIDE CODE BUFFER, AND THAT IS THE POINT. [W2], [W10] and [W11] compare the emitted
// bytes of two separate translations for literal equality. An emitted region can embed the address
// of its own buffer, so two translations into two different heap allocations would differ in bytes
// that have nothing to do with the switch under test. Handing every emission the SAME fixed address
// removes that degree of freedom. Nothing is ever executed from it (no PROT_EXEC anywhere in this
// file); each emission is copied out immediately, so a later one overwriting it is harmless.
//
// THE BUFFER IS REFILLED WITH 0xCC ON EVERY ALLOCATION, AND THAT IS ALSO THE POINT. asmjit's
// flattened section size is rounded up to the section alignment, so the span QEmit returns is a few
// bytes LONGER than the emitted code (measured: 7 bytes of slack in one arm and 1 in the other of
// the same pair). Without the refill those slack bytes are whatever a previous, longer emission
// left in this buffer, and every byte-equality check in this file would be comparing stale data. The
// refill makes them a known constant that `Emit` then trims, so the streams compared below end where
// the code ends.
alignas(4096) u8 g_code_buf[1u << 21];

constexpr u8 kPadByte = 0xcc;

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("widen active-vl test: emitted region exceeds the fixed code buffer");
		last_size = sz;
		memset(g_code_buf, kPadByte, sizeof(g_code_buf));
		return g_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	size_t last_size = 0;
};

struct Env {
	u32 vlen_bits = 512;
	bool widen_bound = false;
	bool int_bound = false;
	bool fp_bound = false;
	bool vector_run = false;
};

void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_vector_run = e.vector_run;
	config::rvv_run_live_range_split = false;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	// The route under test, plus the audit-only host-feature bypass: this workstation has no
	// AVX-512, and nothing in this file executes the bytes.
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_active_vl_widen_bound = e.widen_bound;
	// The other two active-VL switches, so [W11] can show all three are independent.
	config::rvv_qcg_active_vl_int_bound = e.int_bound;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_fma_force_emit = true;
	config::rvv_qcg_narrow_chunk_width = true;
	config::rvv_qcg_narrow_chunk_width_force_emit = true;
	config::rvv_qcg_fp_shared_mask = true;
	config::rvv_qcg_active_vl_bound = e.fp_bound;
	// Everything else off, so the frame under test is the only thing in the region that can move.
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
	MemArena arena{1u << 22};
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

void Emit(Built &b)
{
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
	// Drop asmjit's section-alignment slack, which is not emitted code (see g_code_buf). The
	// amount is asserted to be smaller than the alignment: a larger run of kPadByte would mean
	// the emitter really did produce int3 bytes and the trim would be eating real output.
	size_t const full = b.code.size();
	while (!b.code.empty() && b.code.back() == kPadByte)
		b.code.pop_back();
	CHECK(full - b.code.size() < 8u);
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

std::vector<int> OpcodeStream(Region *r)
{
	std::vector<int> out;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			out.push_back((int)ins.GetOpcode());
	return out;
}

// Everything a widening chunk node says about WHICH bytes it touches and under WHICH predicate.
// `finish` is deliberately EXCLUDED: moving that one write is the transformation.
using Work = std::tuple<int, u32, u32, u32, int, int, u32, int, int, int, int, int, int>;

std::vector<Work> ChunkWork(Frame const &f)
{
	std::vector<Work> out;
	for (auto *i : f.body) {
		if (i->GetOpcode() != Op::_vchunkwiden)
			continue;
		auto *n = static_cast<InstVChunkWiden *>(i);
		out.push_back({(int)n->op, n->rd, n->rs2, n->rs1, (int)n->sew, (int)n->bytes, n->base,
			       (int)n->scalar, (int)n->zero, (int)n->wide2, (int)n->sign2,
			       (int)n->sign1, (int)n->masked});
	}
	return out;
}

std::vector<u32> ChunkBases(Frame const &f)
{
	std::vector<u32> out;
	for (auto *i : f.body)
		if (i->GetOpcode() == Op::_vchunkwiden)
			out.push_back(static_cast<InstVChunkWiden *>(i)->base);
	return out;
}

std::vector<u32> BoundLadder(Frame const &f)
{
	std::vector<u32> out;
	for (auto *i : f.body)
		if (i->GetOpcode() == Op::_vchunkactive)
			out.push_back(static_cast<InstVChunkActive *>(i)->element_base);
	return out;
}

// ---------------------------------------------------------------------------------------------
// Emitted-byte anchors. Every needle is assembled by an INDEPENDENT asmjit instance and located by
// its own bytes, never by an offset this file computed from the emitter's structure.

auto const kStateReg = asmjit::x86::gpq(qcg::ArchTraits::STATE);

std::vector<u8> Assemble(std::function<void(asmjit::x86::Assembler &)> const &body)
{
	asmjit::CodeHolder holder;
	if (holder.init(asmjit::Environment::host()))
		Panic("widen active-vl test: asmjit init");
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

int32_t const kVecOff = (int32_t)offsetof(CPUState, vec);
int32_t const kVlOff = kVecOff + (int32_t)offsetof(rv32::VectorState, vl);
int32_t const kVstartOff = kVecOff + (int32_t)offsetof(rv32::VectorState, vstart);
int32_t const kVxsatOff = kVecOff + (int32_t)offsetof(rv32::VectorState, vxsat);
int32_t const kVxrmOff = kVecOff + (int32_t)offsetof(rv32::VectorState, vxrm);

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

// [W2](3)/(4). A relocation-tolerant comparison of two byte ranges that are supposed to hold the
// SAME instructions at different offsets. Every differing byte run must be at most four bytes long
// and lie in a 4-byte little-endian field whose ON value is its OFF value plus `delta` -- i.e. a
// branch/call displacement the insertion relocated, and nothing else. Anything else (a changed
// opcode, a changed immediate, an extra or missing instruction) produces a run no window explains.
//
// The two `delta` values used below are not free parameters, they are the two directions a
// displacement can move when `total` bytes are inserted in the middle of the region:
//   * BEFORE the insertions, a forward branch's target moved later  -> displacement grows by total;
//   * AFTER them, a call to an ABSOLUTE target (the ordered helper stubs) has its own site moved
//     later while the target stayed  -> displacement shrinks by total.
// A range whose instructions really are identical and self-relative shows no difference at all.
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
			++g_failures;
		}
		i = j;
	}
}

std::vector<u8> VlLoad()
{
	// EmitRvvBodyMask's very first instruction, and therefore the start of a chunk body.
	return Assemble([&](asmjit::x86::Assembler &a) {
		a.mov(asmjit::x86::eax, asmjit::x86::dword_ptr(kStateReg, kVlOff));
	});
}
std::vector<u8> VstartLoad()
{
	return Assemble([&](asmjit::x86::Assembler &a) {
		a.mov(asmjit::x86::eax, asmjit::x86::dword_ptr(kStateReg, kVstartOff));
	});
}
std::vector<u8> BodyMaskInstall()
{
	// EmitRvvBodyMask's result lands in rdi and Emit_vchunkwiden installs it as k1 for every
	// chunk: one per chunk, and the last one must lie inside the skipped range.
	return Assemble(
	    [&](asmjit::x86::Assembler &a) { a.kmovq(asmjit::x86::KReg(1), asmjit::x86::rdi); });
}
std::vector<u8> FallbackInc()
{
	return Assemble([&](asmjit::x86::Assembler &a) {
		a.inc(asmjit::x86::qword_ptr(kStateReg, (int32_t)offsetof(CPUState, rvv_direct_fallbacks)));
	});
}

// [W8]'s scan. A CPUState field this far from R_STATE cannot be reached by a disp8 form, so the
// 4-byte little-endian displacement appearing NOWHERE in the stream means no instruction addresses
// the field. `Disp8Impossible` is asserted rather than assumed -- if a field ever moved close
// enough for a disp8, this scan would silently become vacuous.
bool Disp8Impossible(int32_t disp) { return disp > 127 || disp < -128; }
unsigned CountDisp(std::vector<u8> const &hay, int32_t disp)
{
	std::vector<u8> needle(4);
	memcpy(needle.data(), &disp, 4);
	size_t at = SIZE_MAX;
	return CountBytes(hay, needle, &at);
}

// A `jbe` is rel8 (0x76) or rel32 (0x0f 0x86); both forms are decoded rather than assumed, and a
// `jb` (0x72 / 0x0f 0x82) is rejected here rather than silently accepted -- see [W1].
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
// Shapes. `lanes` and `chunks` are RE-DERIVED here from the RVV geometry, not read back from the
// nodes: that is what makes the ladder checks able to fail.

struct Shape {
	char const *name;
	u32 vsew;  // vsetvli's vsew field
	u32 vlmul; // vsetvli's vlmul field
	u32 ss;    // SOURCE bytes per element; the destination element is 2*ss
	u32 insn;
};

u32 ChunkBytes(u32 vlen) { return std::min(vlen / 8u, 64u); }
u32 GroupBytes(Shape const &s, u32 vlen)
{
	int const sh = LmulLog2(s.vlmul) + 1;
	u32 const rb = vlen / 8u;
	return sh >= 0 ? (rb << sh) : (rb >> (-sh));
}
u32 Chunks(Shape const &s, u32 vlen)
{
	u32 const b = ChunkBytes(vlen);
	return (GroupBytes(s, vlen) + b - 1u) / b;
}
// THE DESTINATION lane count. Getting this wrong by the widening factor is the defect [W1] and [W6]
// exist to catch, so it is spelled out here and nowhere else.
u32 Lanes(Shape const &s, u32 vlen) { return ChunkBytes(vlen) / (2u * s.ss); }

// vd/vs2/vs1 are chosen legal for each row: `vwint_registers_legal` needs vd aligned to the
// DOUBLED group (2*LMUL registers) and the narrow sources aligned to LMUL.
Shape const kShapes[] = {
    // [W1] the SEW x LMUL matrix, .vv adds.
    {"vwadd.vv   e8,mf2 ", SEW8, MF2, 1, MakeOpV(F6_VWADD, 1, 10, 12, 8, OPMVV)},
    {"vwadd.vv   e8,m1  ", SEW8, M1, 1, MakeOpV(F6_VWADD, 1, 10, 12, 8, OPMVV)},
    {"vwadd.vv   e8,m2  ", SEW8, M2, 1, MakeOpV(F6_VWADD, 1, 12, 14, 8, OPMVV)},
    {"vwadd.vv   e8,m4  ", SEW8, M4, 1, MakeOpV(F6_VWADD, 1, 16, 20, 8, OPMVV)},
    {"vwaddu.vv  e16,mf2", SEW16, MF2, 2, MakeOpV(F6_VWADDU, 1, 10, 12, 8, OPMVV)},
    {"vwaddu.vv  e16,m1 ", SEW16, M1, 2, MakeOpV(F6_VWADDU, 1, 10, 12, 8, OPMVV)},
    {"vwsub.vv   e16,m2 ", SEW16, M2, 2, MakeOpV(F6_VWSUB, 1, 12, 14, 8, OPMVV)},
    {"vwsubu.vv  e16,m4 ", SEW16, M4, 2, MakeOpV(F6_VWSUBU, 1, 16, 20, 8, OPMVV)},
    {"vwadd.vv   e32,mf2", SEW32, MF2, 4, MakeOpV(F6_VWADD, 1, 10, 12, 8, OPMVV)},
    {"vwadd.vv   e32,m1 ", SEW32, M1, 4, MakeOpV(F6_VWADD, 1, 10, 12, 8, OPMVV)},
    {"vwadd.vv   e32,m2 ", SEW32, M2, 4, MakeOpV(F6_VWADD, 1, 12, 14, 8, OPMVV)},
    {"vwadd.vv   e32,m4 ", SEW32, M4, 4, MakeOpV(F6_VWADD, 1, 16, 20, 8, OPMVV)},
    // .vx scalar sources (rs1 = x11, deliberately non-zero so the GPR load is exercised).
    {"vwadd.vx   e16,m2 ", SEW16, M2, 2, MakeOpV(F6_VWADD, 1, 12, 11, 8, OPMVX)},
    {"vwsubu.vx  e32,m2 ", SEW32, M2, 4, MakeOpV(F6_VWSUBU, 1, 12, 11, 8, OPMVX)},
    // [W6] the .wv/.wx wide-vs2 forms: vs2 is ALREADY 2*SEW, so its window and its per-chunk
    // advance are twice the .vv ones while the element ladder must be identical.
    {"vwadd.wv   e16,m2 ", SEW16, M2, 2, MakeOpV(F6_VWADD_W, 1, 12, 16, 8, OPMVV)},
    {"vwsub.wv   e32,m2 ", SEW32, M2, 4, MakeOpV(F6_VWSUB_W, 1, 12, 16, 8, OPMVV)},
    {"vwaddu.wx  e16,m2 ", SEW16, M2, 2, MakeOpV(F6_VWADDU_W, 1, 12, 11, 8, OPMVX)},
    // multiplies
    {"vwmul.vv   e16,m2 ", SEW16, M2, 2, MakeOpV(F6_VWMUL, 1, 12, 14, 8, OPMVV)},
    {"vwmulu.vv  e32,m2 ", SEW32, M2, 4, MakeOpV(F6_VWMULU, 1, 12, 14, 8, OPMVV)},
    {"vwmulsu.vx e16,m2 ", SEW16, M2, 2, MakeOpV(F6_VWMULSU, 1, 12, 11, 8, OPMVX)},
    // [W7] the accumulate forms, which are the only widening shapes that READ rd.
    {"vwmaccu.vv e16,m2 ", SEW16, M2, 2, MakeOpV(F6_VWMACCU, 1, 12, 14, 8, OPMVV)},
    {"vwmacc.vv  e16,m2 ", SEW16, M2, 2, MakeOpV(F6_VWMACC, 1, 12, 14, 8, OPMVV)},
    {"vwmaccsu.vv e8,m2 ", SEW8, M2, 1, MakeOpV(F6_VWMACCSU, 1, 12, 14, 8, OPMVV)},
    {"vwmaccus.vx e16,m2", SEW16, M2, 2, MakeOpV(F6_VWMACCUS, 1, 12, 11, 8, OPMVX)},
    // [W4] masked forms of the same instructions.
    {"vwadd.vv   e16,m2 vm=0", SEW16, M2, 2, MakeOpV(F6_VWADD, 0, 12, 14, 8, OPMVV)},
    {"vwmacc.vv  e16,m2 vm=0", SEW16, M2, 2, MakeOpV(F6_VWMACC, 0, 12, 14, 8, OPMVV)},
    // [W5] the legal overlaps. Top-aligned narrow source: vs2 + ng == vd + dg, i.e. 10 + 2 == 8 + 4.
    {"vwadd.vv   e16,m2 top-aligned vs2", SEW16, M2, 2, MakeOpV(F6_VWADD, 1, 10, 14, 8, OPMVV)},
    {"vwadd.vv   e16,m2 top-aligned vs1", SEW16, M2, 2, MakeOpV(F6_VWADD, 1, 14, 10, 8, OPMVV)},
    // .wv with the wide vs2 IN vd's own group.
    {"vwadd.wv   e16,m2 vs2==vd", SEW16, M2, 2, MakeOpV(F6_VWADD_W, 1, 8, 14, 8, OPMVV)},
};

std::vector<u32> Program(Shape const &s) { return {Vsetvli(s.vsew, s.vlmul), s.insn}; }

// The frame a shape produces, or nullptr with a recorded failure: every shape in the table above is
// expected to route, and a shape that silently stopped routing would make every check on it vacuous.
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
			Translate(off, Program(s), Env{vlen, /*widen_bound=*/false});
			std::vector<Frame> f;
			if (!OneFrame(off, f, s.name))
				continue;
			unsigned const chunks = Chunks(s, vlen);
			CHECK_EQ(CountOp(f[0], Op::_vchunkwiden), chunks);
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 0u);
			CHECK_EQ((unsigned)f[0].begin->n_typed, chunks);
			CHECK(f[0].end != nullptr);
			if (f[0].end)
				CHECK_EQ((int)f[0].end->frame_clears_vstart, 0);
			unsigned finishes = 0, last_is_finish = 0, seen = 0;
			for (auto *i : f[0].body)
				if (i->GetOpcode() == Op::_vchunkwiden) {
					auto *n = static_cast<InstVChunkWiden *>(i);
					finishes += n->finish;
					++seen;
					last_is_finish = (seen == chunks) && n->finish;
				}
			CHECK_EQ(finishes, 1u);
			CHECK_EQ(last_is_finish, 1u);

			// None of the compares the ON arm would add is present. `element_base_c < vlmax`
			// for every c >= 1, so this cannot collide with the guard's own vl compare.
			Emit(off);
			CHECK(!off.code.empty());
			for (unsigned c = 1; c < chunks; ++c) {
				size_t at = SIZE_MAX;
				CHECK_EQ(CountBytes(off.code, BoundCmp(c * Lanes(s, vlen)), &at), 0u);
			}
		}
	printf("  ok   switch OFF: %zu shapes x 2 VLENs have no bound, n_typed == chunks,\n"
	       "       one finish on the last chunk, frame_clears_vstart == false\n",
	       sizeof(kShapes) / sizeof(kShapes[0]));
}

void TestOnShapeAndLadder()
{
	unsigned max_chunks = 0;
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			unsigned const chunks = Chunks(s, vlen), lanes = Lanes(s, vlen);
			max_chunks = std::max(max_chunks, chunks);
			Built on;
			Translate(on, Program(s), Env{vlen, /*widen_bound=*/true});
			std::vector<Frame> f;
			if (!OneFrame(on, f, s.name))
				continue;
			unsigned const bounds = CountOp(f[0], Op::_vchunkactive);
			CHECK_EQ(bounds, chunks >= 2 ? chunks - 1u : 0u);
			CHECK_EQ((unsigned)f[0].begin->n_typed, chunks + bounds);
			CHECK(f[0].end != nullptr);
			if (f[0].end)
				CHECK_EQ((int)f[0].end->frame_clears_vstart, (int)(chunks >= 2));

			// The ladder, the chunk index it carries, and its position relative to the
			// chunk it guards. `lanes` is the DESTINATION lane count derived above.
			unsigned expect_chunk = 1, finishes = 0;
			Inst *prev = nullptr;
			for (auto *i : f[0].body) {
				if (i->GetOpcode() == Op::_vchunkactive) {
					auto *n = static_cast<InstVChunkActive *>(i);
					CHECK_EQ((unsigned)n->chunk, expect_chunk);
					CHECK_EQ(n->element_base, expect_chunk * lanes);
					CHECK(n->chunk != 0); // chunk 0 is never bounded
					++expect_chunk;
				} else if (i->GetOpcode() == Op::_vchunkwiden) {
					auto *n = static_cast<InstVChunkWiden *>(i);
					finishes += n->finish;
					// The bound and the body it guards must agree about where the
					// chunk starts: one field against another, not a re-derivation.
					if (chunks >= 2 && n->base != 0) {
						CHECK(prev && prev->GetOpcode() == Op::_vchunkactive);
						if (prev && prev->GetOpcode() == Op::_vchunkactive)
							CHECK_EQ(
							    static_cast<InstVChunkActive *>(prev)->element_base,
							    n->base);
					}
				}
				prev = i;
			}
			CHECK_EQ(expect_chunk, chunks >= 2 ? chunks : 1u);
			CHECK_EQ(finishes, chunks >= 2 ? 0u : 1u);

			// And the chunk nodes' own bases still tile [0, VLMAX) at the same stride.
			auto const bases = ChunkBases(f[0]);
			CHECK_EQ(bases.size(), chunks);
			for (unsigned c = 0; c < bases.size(); ++c)
				CHECK_EQ(bases[c], c * lanes);

			// Every emitted branch is `jbe`, never `jb`: at exactly `vl == lanes` a `jb`
			// would execute one entirely-tail chunk. Correct output, zero saving, and
			// invisible to a check that only counts bounds.
			Emit(on);
			for (unsigned c = 1; c < chunks; ++c) {
				auto const cmp = BoundCmp(c * lanes);
				size_t at = SIZE_MAX;
				CHECK_EQ(CountBytes(on.code, cmp, &at), 1u);
				if (at == SIZE_MAX)
					continue;
				size_t end = 0, target = 0;
				CHECK(DecodeJbe(on.code, at + cmp.size(), &end, &target));
			}
		}
	CHECK(max_chunks >= 16u); // the table must actually reach deep ladders
	printf("  ok   switch ON: chunk 0 never bounded, ladder == c * (chunk_bytes / (2*SEW)),\n"
	       "       bound.element_base == the guarded node's own base, n_typed == 2*chunks - 1,\n"
	       "       every branch decodes as jbe (deepest ladder: %u chunks)\n",
	       max_chunks);
}

// [W2]. THE TRANSFORMATION IS EXACTLY "n-1 COMPARE/BRANCH PAIRS", STATED SO IT CAN FAIL.
//
// The obvious formulation -- splice the pairs out of the ON stream and require literal equality
// with the OFF stream -- is WRONG, and is recorded here rather than quietly dropped: a forward
// branch that jumps OVER the body (the frame guard's `ja fallback`, measured 14 bytes further in a
// one-pair frame) carries a rel32 displacement that MUST change when bytes are inserted between it
// and its target. Requiring those bytes to be equal would be requiring the insertion not to have
// happened. So the claim is decomposed into four parts, each of which can fail on its own:
//
//   (1) SIZE. `on.size() == off.size() + sum(pair sizes)`. Nothing else was added or dropped.
//   (2) EVERY CHUNK BODY IS BYTE-IDENTICAL. A chunk body starts at its EmitRvvBodyMask `mov eax,
//       [vec.vl]` and ends where the next bound (ON) or the next chunk (OFF) begins; the last one
//       ends at the frame's single `mov [vec.vstart], 0`. A body's own branches are internal to it
//       and span none of the inserted bytes, so these ranges cannot drift -- if they differ, the
//       switch changed real work.
//   (3) THE TAIL IS BYTE-IDENTICAL. Everything from the `vstart` write onward -- the join, the ip
//       write, the counters, the fallback arm and its ordered helper calls -- is equal byte for
//       byte, at its own (shifted) offset in each arm.
//   (4) THE PREFIX DIFFERS ONLY BY RELOCATION. In the region before chunk 0, every differing byte
//       run is at most four bytes long and lies in a 4-byte little-endian field whose ON value is
//       its OFF value PLUS the total inserted size -- i.e. a branch displacement over the body, and
//       nothing else. A changed instruction there would produce a run this cannot explain.
void TestFullVlIsExactlyTheAddedPairs()
{
	unsigned checked = 0;
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			unsigned const chunks = Chunks(s, vlen), lanes = Lanes(s, vlen);
			if (chunks < 2)
				continue;
			Built off, on;
			Translate(off, Program(s), Env{vlen, false});
			Translate(on, Program(s), Env{vlen, true});
			Emit(off);
			Emit(on);
			if (off.code.empty() || on.code.empty()) {
				CHECK(false);
				continue;
			}
			// Chunk body starts, one per chunk in each arm -- asserted, so a needle that
			// stopped matching would fail here rather than make the ranges below vacuous.
			auto const starts_off = AllOffsets(off.code, VlLoad());
			auto const starts_on = AllOffsets(on.code, VlLoad());
			CHECK_EQ(starts_off.size(), chunks);
			CHECK_EQ(starts_on.size(), chunks);
			size_t const vstart_off = Find(off.code, VstartClear());
			size_t const vstart_on = Find(on.code, VstartClear());
			CHECK(vstart_off != SIZE_MAX);
			CHECK(vstart_on != SIZE_MAX);
			if (starts_off.size() != chunks || starts_on.size() != chunks ||
			    vstart_off == SIZE_MAX || vstart_on == SIZE_MAX)
				continue;

			// The (chunks-1) [cmp, jbe) ranges, each located by its own immediate.
			std::vector<std::pair<size_t, size_t>> cut;
			bool ok = true;
			size_t total = 0;
			for (unsigned c = 1; c < chunks && ok; ++c) {
				auto const cmp = BoundCmp(c * lanes);
				size_t at = SIZE_MAX;
				size_t end = 0, target = 0;
				if (CountBytes(on.code, cmp, &at) != 1u || at == SIZE_MAX ||
				    !DecodeJbe(on.code, at + cmp.size(), &end, &target)) {
					CHECK(false);
					ok = false;
					break;
				}
				// The bound is adjacent to the chunk it guards IN THE BYTES, not only in
				// the QIR: the branch's last byte is the chunk body's first byte.
				CHECK_EQ(end, starts_on[c]);
				cut.push_back({at, end});
				total += end - at;
			}
			if (!ok)
				continue;
			std::sort(cut.begin(), cut.end());

			// (1)
			CHECK_EQ(on.code.size(), off.code.size() + total);
			// (2)
			for (unsigned c = 0; c < chunks; ++c) {
				size_t const e_off =
				    c + 1 < chunks ? starts_off[c + 1] : vstart_off;
				size_t const e_on = c + 1 < chunks ? cut[c].first : vstart_on;
				CHECK_EQ(e_off - starts_off[c], e_on - starts_on[c]);
				if (e_off - starts_off[c] != e_on - starts_on[c])
					continue;
				CHECK_EQ(memcmp(off.code.data() + starts_off[c],
						on.code.data() + starts_on[c], e_off - starts_off[c]),
					 0);
			}
			// (3)
			CHECK_EQ(off.code.size() - vstart_off, on.code.size() - vstart_on);
			if (off.code.size() - vstart_off == on.code.size() - vstart_on)
				CheckDiffersOnlyByRelocation(off.code, vstart_off, on.code, vstart_on,
							     off.code.size() - vstart_off,
							     -(i64)total, "tail", s.name, vlen);
			// (4)
			CHECK_EQ(starts_off[0], starts_on[0]);
			if (starts_off[0] == starts_on[0])
				CheckDiffersOnlyByRelocation(off.code, 0, on.code, 0, starts_off[0],
							     (i64)total, "prefix", s.name, vlen);
			++checked;
		}
	CHECK(checked > 0);
	printf("  ok   %u bounded shapes: size delta == the pairs exactly, every chunk body and the\n"
	       "       whole tail are byte-identical, and the prefix differs only in branch\n"
	       "       displacements shifted by exactly the inserted size\n",
	       checked);
}

// [W3].
void TestVstartOwnership()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			unsigned const chunks = Chunks(s, vlen);
			Built off, on;
			Translate(off, Program(s), Env{vlen, false});
			Translate(on, Program(s), Env{vlen, true});
			Emit(off);
			Emit(on);
			size_t a = SIZE_MAX;
			// Exactly one write, in each arm: it moved off the last widening node onto the
			// frame epilogue, it was not duplicated and it was not lost.
			CHECK_EQ(CountBytes(off.code, VstartClear(), &a), 1u);
			CHECK_EQ(CountBytes(on.code, VstartClear(), &a), 1u);
			// And the per-chunk body mask still READS vstart once per chunk in both arms:
			// prestart chunks keep running under their zero mask, they are not skipped.
			CHECK_EQ(CountBytes(off.code, VstartLoad(), &a), chunks);
			CHECK_EQ(CountBytes(on.code, VstartLoad(), &a), chunks);
		}
	printf("  ok   vstart written exactly once in each arm, and read by one per-chunk mask\n"
	       "       per chunk in both -- prestart chunks are never skipped\n");
}

// [W4].
void TestEarlyExitIsBlindToTheMask()
{
	for (u32 vlen : {512u, 1024u}) {
		struct Pair {
			char const *name;
			u32 f6, f3, src1;
		};
		// `.wv`'s vs2 is a WIDE group (v12..v15 here), so its vs1 has to sit outside that
		// group -- `vwint_registers_legal` refuses a vs1 that overlaps a wide vs2.
		Pair const pairs[] = {{"vwadd.vv  e16,m2", F6_VWADD, OPMVV, 14},
				      {"vwmacc.vv e16,m2", F6_VWMACC, OPMVV, 14},
				      {"vwadd.wv  e16,m2", F6_VWADD_W, OPMVV, 16}};
		for (auto const &p : pairs) {
			std::vector<u32> ladders[2];
			for (int vm = 0; vm < 2; ++vm) {
				Shape const s{p.name, SEW16, M2, 2,
					      MakeOpV(p.f6, (u32)vm, 12, p.src1, 8, p.f3)};
				Built on;
				Translate(on, Program(s), Env{vlen, true});
				std::vector<Frame> f;
				if (!OneFrame(on, f, s.name))
					continue;
				ladders[vm] = BoundLadder(f[0]);
				bool any_masked = false;
				for (auto *i : f[0].body)
					if (i->GetOpcode() == Op::_vchunkwiden)
						any_masked |=
						    static_cast<InstVChunkWiden *>(i)->masked;
				CHECK_EQ((int)any_masked, (int)(vm == 0));

				// And in the bytes: the bound is exactly two instructions, `cmp` then
				// `jbe`, with nothing -- no v0 load, no kortest -- between them.
				Emit(on);
				for (u32 base : ladders[vm]) {
					auto const cmp = BoundCmp(base);
					size_t at = SIZE_MAX;
					CHECK_EQ(CountBytes(on.code, cmp, &at), 1u);
					if (at == SIZE_MAX)
						continue;
					size_t end = 0, target = 0;
					CHECK(DecodeJbe(on.code, at + cmp.size(), &end, &target));
				}
			}
			CHECK(!ladders[0].empty());
			CHECK(ladders[0] == ladders[1]);
		}
	}
	printf("  ok   the ladder is identical for vm=1 and vm=0 on .vv/.wv/vwmacc, and every\n"
	       "       bound is `cmp [vec.vl], imm` immediately followed by its jbe\n");
}

// [W5] and [W7]: no chunk work moved, and the accumulate forms read back their own window.
void TestNoChunkWorkMoved()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built off, on;
			Translate(off, Program(s), Env{vlen, false});
			Translate(on, Program(s), Env{vlen, true});
			std::vector<Frame> fo, fn;
			if (!OneFrame(off, fo, s.name) || !OneFrame(on, fn, s.name))
				continue;
			CHECK(ChunkWork(fo[0]) == ChunkWork(fn[0]));
			// Chunk-major and in ascending base order in BOTH arms: the bound deletes a
			// suffix at run time and reorders nothing, which is what keeps the legal
			// overlaps ([W5]) safe -- a reordering could let a later chunk read source
			// bytes an earlier chunk had already overwritten.
			auto const bo = ChunkBases(fo[0]), bn = ChunkBases(fn[0]);
			CHECK(bo == bn);
			for (size_t c = 1; c < bo.size(); ++c)
				CHECK(bo[c] > bo[c - 1]);
		}
	printf("  ok   every chunk's (op, rd, rs2, rs1, sew, bytes, base, scalar, zero, wide2,\n"
	       "       sign2, sign1, masked) is unchanged and the bases are still ascending\n");
}

// [W5]: the accumulate forms may NOT overlap, and that is the route's own rule.
void TestAccumulateRefusesOverlap()
{
	// vwmacc.vv vd=v8 (group 8..11 at m2 widened), vs2=v10 -- top-aligned, which the
	// non-accumulate forms accept and `vwint_registers_legal` refuses for `acc`.
	std::vector<u32> const words = {Vsetvli(SEW16, M2), MakeOpV(F6_VWMACC, 1, 10, 14, 8, OPMVV)};
	for (u32 vlen : {512u, 1024u}) {
		Built b;
		Translate(b, words, Env{vlen, true});
		auto const frames = FindFrames(b.region);
		unsigned widen_nodes = 0, bounds = 0;
		for (auto const &f : frames) {
			widen_nodes += CountOp(f, Op::_vchunkwiden);
			bounds += CountOp(f, Op::_vchunkactive);
		}
		CHECK_EQ(widen_nodes, 0u); // the whole instruction falls back to the helper
		CHECK_EQ(bounds, 0u);
	}
	// The SAME overlap on a non-accumulate form does route, so the check above is about `acc`
	// and not about the overlap being rejected everywhere.
	{
		Built b;
		Translate(b, {Vsetvli(SEW16, M2), MakeOpV(F6_VWADD, 1, 10, 14, 8, OPMVV)},
			  Env{1024, true});
		std::vector<Frame> f;
		if (OneFrame(b, f, "vwadd.vv top-aligned vs2"))
			CHECK(CountOp(f[0], Op::_vchunkwiden) > 0u);
	}
	printf("  ok   vwmacc.vv with a top-aligned overlap does not route at all, while the same\n"
	       "       overlap on vwadd.vv does -- the exclusion is the accumulate rule, not the\n"
	       "       overlap rule\n");
}

// [W6]: the .wv/.wx wide-vs2 forms carry the SAME element ladder as .vv, even though their source
// window and per-chunk source advance are twice as large.
void TestWideSourceLadderMatchesNarrow()
{
	u32 const vlen = 1024;
	struct Row {
		char const *name;
		u32 f6, f3, src1;
		bool wide2;
	};
	Row const rows[] = {
	    {"vwadd.vv  e16,m2", F6_VWADD, OPMVV, 14, false},
	    {"vwadd.wv  e16,m2", F6_VWADD_W, OPMVV, 16, true},
	    {"vwaddu.wx e16,m2", F6_VWADDU_W, OPMVX, 11, true},
	};
	std::vector<u32> reference;
	for (auto const &r : rows) {
		Shape const s{r.name, SEW16, M2, 2, MakeOpV(r.f6, 1, 12, r.src1, 8, r.f3)};
		Built on;
		Translate(on, Program(s), Env{vlen, true});
		std::vector<Frame> f;
		if (!OneFrame(on, f, s.name))
			continue;
		auto const ladder = BoundLadder(f[0]);
		// Derived from the shape, not from the node: c * chunk_bytes / (2*SEW).
		std::vector<u32> want;
		for (u32 c = 1; c < Chunks(s, vlen); ++c)
			want.push_back(c * Lanes(s, vlen));
		CHECK(ladder == want);
		if (reference.empty())
			reference = ladder;
		else
			CHECK(ladder == reference);
		// And the wide2 flag really is set, so the row is not silently testing .vv twice.
		bool wide2 = false;
		for (auto *i : f[0].body)
			if (i->GetOpcode() == Op::_vchunkwiden)
				wide2 |= static_cast<InstVChunkWiden *>(i)->wide2;
		CHECK_EQ((int)wide2, (int)r.wide2);
		// The source offsets DO differ by the factor the ladder must ignore: a .wv chunk's
		// vs2 advances by `bytes`, a .vv chunk's by `bytes/2`.
		std::vector<u32> rs2;
		for (auto *i : f[0].body)
			if (i->GetOpcode() == Op::_vchunkwiden)
				rs2.push_back(static_cast<InstVChunkWiden *>(i)->rs2);
		if (rs2.size() >= 2)
			CHECK_EQ(rs2[1] - rs2[0], r.wide2 ? ChunkBytes(vlen) : ChunkBytes(vlen) / 2u);
	}
	CHECK(!reference.empty());
	printf("  ok   .vv, .wv and .wx share one element ladder while their per-chunk source\n"
	       "       advance differs by the widening factor\n");
}

// [W7]: each accumulate chunk reads back exactly its own store window.
void TestAccumulateReadsItsOwnWindow()
{
	u32 const vlen = 1024;
	u32 const f6s[] = {F6_VWMACCU, F6_VWMACC, F6_VWMACCSU};
	for (u32 f6 : f6s) {
		Shape const s{"vwmacc*", SEW16, M2, 2, MakeOpV(f6, 1, 12, 14, 8, OPMVV)};
		Built on;
		Translate(on, Program(s), Env{vlen, true});
		std::vector<Frame> f;
		if (!OneFrame(on, f, s.name))
			continue;
		unsigned c = 0;
		for (auto *i : f[0].body) {
			if (i->GetOpcode() != Op::_vchunkwiden)
				continue;
			auto *n = static_cast<InstVChunkWiden *>(i);
			CHECK_EQ((int)n->op, (int)InstVChunkWiden::Macc);
			// Emit_vchunkwiden's accumulate reads [rd, rd+bytes) and stores to the same
			// window, so a skipped chunk touches nothing another chunk depends on.
			CHECK_EQ(n->bytes, ChunkBytes(vlen));
			CHECK_EQ(n->base, c * Lanes(s, vlen));
			++c;
		}
		CHECK_EQ(c, Chunks(s, vlen));
	}
	printf("  ok   every vwmacc* chunk accumulates in its own [rd, rd+bytes) window at its own\n"
	       "       element base\n");
}

// [W8]: widening writes no CSR, and the scan that says so is shown to be able to see one.
void TestNoCsrSideEffect()
{
	CHECK(Disp8Impossible(kVxsatOff));
	CHECK(Disp8Impossible(kVxrmOff));
	// Positive control: an equal-width saturating add DOES accrue vxsat, through the same
	// emitter and into the same stream. If this count were zero the scan would be vacuous.
	{
		Built b;
		Translate(b, {Vsetvli(SEW32, M2), MakeOpV(F6_VSADD, 1, 10, 12, 8, OPIVV)},
			  Env{1024, false});
		Emit(b);
		CHECK(CountDisp(b.code, kVxsatOff) > 0u);
	}
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes)
			for (bool on : {false, true}) {
				Built b;
				Translate(b, Program(s), Env{vlen, on});
				Emit(b);
				CHECK_EQ(CountDisp(b.code, kVxsatOff), 0u);
				CHECK_EQ(CountDisp(b.code, kVxrmOff), 0u);
			}
	printf("  ok   no widening frame in either arm references vec.vxsat or vec.vxrm, and the\n"
	       "       same scan does find vxsat in an equal-width vsadd.vv frame\n");
}

// [W9].
void TestBranchTargetAndShape()
{
	for (u32 vlen : {512u, 1024u}) {
		Shape const s{"vwadd.vv e16,m2", SEW16, M2, 2, MakeOpV(F6_VWADD, 1, 12, 14, 8, OPMVV)};
		unsigned const chunks = Chunks(s, vlen), lanes = Lanes(s, vlen);
		CHECK(chunks >= 2);
		Built on;
		Translate(on, Program(s), Env{vlen, true});
		Emit(on);
		CHECK(!on.code.empty());

		size_t const vstart_at = Find(on.code, VstartClear());
		size_t const fallback_at = Find(on.code, FallbackInc());
		CHECK(vstart_at != SIZE_MAX);
		CHECK(fallback_at != SIZE_MAX);
		if (vstart_at == SIZE_MAX || fallback_at == SIZE_MAX)
			continue;

		// (c) there is no chunk-0 bound: neither the `vl <= 0` compare nor any bound before
		// chunk 0's own body-mask install.
		size_t unused = SIZE_MAX;
		CHECK_EQ(CountBytes(on.code, BoundCmp(0), &unused), 0u);
		size_t const first_mask = Find(on.code, BodyMaskInstall());
		size_t const first_bound = Find(on.code, BoundCmp(lanes));
		CHECK(first_mask != SIZE_MAX);
		CHECK(first_bound != SIZE_MAX);
		CHECK(first_mask < first_bound);

		size_t last_end = 0;
		for (unsigned c = 1; c < chunks; ++c) {
			auto const cmp = BoundCmp(c * lanes);
			size_t at = SIZE_MAX;
			CHECK_EQ(CountBytes(on.code, cmp, &at), 1u);
			if (at == SIZE_MAX)
				return;
			size_t end = 0, target = 0;
			CHECK(DecodeJbe(on.code, at + cmp.size(), &end, &target));
			// (a) every bound leaves to the SAME place, and that place is the single
			// vstart write; (b) which is strictly before the fallback arm. Landing on the
			// fallback would run the ordered helper on top of chunks already stored.
			CHECK_EQ(target, vstart_at);
			CHECK(target < fallback_at);
			last_end = end;
		}
		// Real work lies inside the last bound's skipped range: the final chunk's body mask.
		size_t const last_mask = FindLast(on.code, BodyMaskInstall());
		CHECK(last_mask != SIZE_MAX);
		CHECK(last_mask > last_end);
		CHECK(last_mask < vstart_at);
		printf("  ok   VLEN %-4u all %u jbe target +%zu == the single vstart write; fallback\n"
		       "       at +%zu; the last chunk's kmovq k1,rdi at +%zu is inside the skip\n",
		       vlen, chunks - 1, vstart_at, fallback_at, last_mask);
	}
}

// ---------------------------------------------------------------------------------------------
// [W10] exclusions.

void TestOneChunkFrameIsByteIdentical()
{
	unsigned checked = 0;
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			if (Chunks(s, vlen) != 1u)
				continue;
			Built off, on;
			Translate(off, Program(s), Env{vlen, false});
			Translate(on, Program(s), Env{vlen, true});
			Emit(off);
			Emit(on);
			CHECK(!off.code.empty());
			CHECK(off.code == on.code);
			CHECK(OpcodeStream(off.region) == OpcodeStream(on.region));
			++checked;
		}
	CHECK(checked > 0); // a table with no one-chunk shape would make this check vacuous
	printf("  ok   %u one-chunk frame(s) (fractional LMUL at VLEN 512) are byte-for-byte\n"
	       "       identical with the switch ON\n",
	       checked);
}

void TestChunkCapacityBoundary()
{
	// The node indexes chunks in [0, 64). The DEEPEST widening frame the route can build is
	// VLEN 4096 with LMUL 4: `vwint_registers_legal` needs emul_in_range(lmul_log2 + 1), so
	// LMUL 8 is refused outright and `chunks = (rb << (lmul_log2+1)) / 64` tops out at exactly
	// 64. This is therefore a BOUNDARY test, not an over-capacity one, and the `chunks <= 64`
	// conjunct is provably slack on this route -- asserted here so a future relaxation of the
	// LMUL rule cannot silently walk past the node's encoding.
	Shape const deepest{"vwadd.vv e8,m4", SEW8, M4, 1, MakeOpV(F6_VWADD, 1, 16, 20, 8, OPMVV)};
	u32 const vlen = 4096;
	CHECK_EQ(Chunks(deepest, vlen), 64u);
	Built b;
	Translate(b, Program(deepest), Env{vlen, true});
	std::vector<Frame> f;
	if (!OneFrame(b, f, deepest.name))
		return;
	CHECK_EQ(CountOp(f[0], Op::_vchunkwiden), 64u);
	CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 63u);
	unsigned top = 0;
	for (auto *i : f[0].body)
		if (i->GetOpcode() == Op::_vchunkactive)
			top = std::max(top, (unsigned)static_cast<InstVChunkActive *>(i)->chunk);
	CHECK_EQ(top, 63u);
	// LMUL 8 widening is refused by the route, which is why 64 is the ceiling.
	{
		Built m8;
		Translate(m8, {Vsetvli(SEW8, 3u), MakeOpV(F6_VWADD, 1, 16, 20, 8, OPMVV)},
			  Env{vlen, true});
		unsigned widen_nodes = 0;
		for (auto const &fr : FindFrames(m8.region))
			widen_nodes += CountOp(fr, Op::_vchunkwiden);
		CHECK_EQ(widen_nodes, 0u);
	}
	printf("  ok   VLEN 4096 e8,m4 is the route's deepest frame: 64 chunks, 63 bounds, top\n"
	       "       chunk index 63; LMUL 8 widening does not route at all\n");
}

void TestNoWideningInRunFrames()
{
	// No vector-run kind carries a widening member, so a widening bound can never land in a
	// multi-member frame. Asserted structurally rather than assumed: if widening is ever added
	// to the run set, this check fails and the exclusion has to be revisited.
	std::vector<u32> const words = {Vsetvli(SEW16, M2),
					MakeOpV(F6_VWADD, 1, 12, 14, 8, OPMVV),
					MakeOpV(F6_VWADD, 1, 12, 16, 8, OPMVV),
					MakeOpV(F6_VWADD, 1, 12, 18, 8, OPMVV)};
	for (u32 vlen : {512u, 1024u}) {
		Built b;
		Translate(b, words, Env{vlen, /*widen_bound=*/true, /*int_bound=*/false,
					/*fp_bound=*/false, /*vector_run=*/true});
		unsigned multi = 0, widen_in_multi = 0, widen_total = 0;
		for (auto const &f : FindFrames(b.region)) {
			widen_total += CountOp(f, Op::_vchunkwiden);
			if (f.begin->n_members > 1) {
				++multi;
				widen_in_multi += CountOp(f, Op::_vchunkwiden);
			}
		}
		CHECK(widen_total > 0u); // the words really did route, so this is not vacuous
		CHECK_EQ(multi, 0u);
		CHECK_EQ(widen_in_multi, 0u);
	}
	printf("  ok   widening instructions never form a multi-member run frame\n");
}

StateReg g_regs[] = {{(u16)offsetof(CPUState, gpr), VType::I32, "x0"}};
StateInfo g_state_info{g_regs, 1};

struct PanicRuntime final : CompilerRuntime {
	void *AllocateCode(size_t n, uint) override
	{
		buf.resize(n + 64);
		return buf.data();
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	std::vector<u8> buf;
};

void ExpectPanic(char const *what, char const *expect, std::function<void()> const &body)
{
	char path[] = "/tmp/widen_active_vl_panic_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0)
		Panic("widen active-vl test: mkstemp");
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
		fprintf(stderr, "       child said: %s\n", out.empty() ? "(nothing)" : out.c_str());
		++g_failures;
	} else {
		printf("  ok   %s -> \"%s\"\n", what, expect);
	}
}

using GuardKind = InstRVVTypedChunkBegin::GuardKind;

// Two WIDENING chunk nodes plus an optional bound, in a frame whose guard kind and
// `frame_clears_vstart` the caller chooses. `n_typed` is the honest count of nodes that increment
// QEmit's typed counter, so a case reaches the contract it is meant to exercise rather than dying on
// the counter check. Emit_rvvtypedchunkpartial is a boundary marker and does not count.
void BuildHandFrame(bool with_bound, GuardKind kind, bool frame_clears_vstart, bool with_partial)
{
	MemArena arena(1u << 20);
	auto *region = arena.New<Region>(&arena, &g_state_info);
	Builder b(region->CreateBlock());
	u32 const vo = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	u16 const n_typed = (u16)(2u + (with_bound ? 1u : 0u));
	b.Create_rvvtypedchunkbegin(0xc9u, 16u, 0u, RuntimeStubId::id_rv32_vwint, n_typed, kind);
	auto chunk = [&](u8 c, bool finish) {
		b.Create_vchunkwiden((u8)InstVChunkWiden::Add,
				     vo + 8u * rv32::VLEN_MAX_BYTES + c * 64u,
				     vo + 12u * rv32::VLEN_MAX_BYTES + c * 32u,
				     vo + 14u * rv32::VLEN_MAX_BYTES + c * 32u, /*sew=*/2, /*bytes=*/64,
				     /*base=*/c * 16u, false, false, false, true, true, false, finish);
	};
	chunk(0, false);
	if (with_bound)
		b.Create_vchunkactive(1, 16);
	if (with_partial)
		b.Create_rvvtypedchunkpartial();
	chunk(1, !frame_clears_vstart);
	b.Create_rvvtypedchunkend(0u, RuntimeStubId::id_rv32_vwint, /*whole_regbytes=*/0,
				  frame_clears_vstart);
	PanicRuntime rt;
	qcg::GenerateCode(&rt, nullptr, region, 0);
}

void TestFailClosed()
{
	ApplyEnv(Env{512, false});
	// A whole-register frame: its EVL is nregs*VLEN/EEW, so vec.vl bounds nothing there.
	ExpectPanic("bound in a Vlenb* whole-register frame",
		    "rvv active-vl bound inside a frame whose guard does not bound vec.vl", [] {
			    MemArena arena(1u << 20);
			    auto *region = arena.New<Region>(&arena, &g_state_info);
			    Builder b(region->CreateBlock());
			    b.Create_rvvtypedchunkbegin(64u, 0u, RuntimeStubId::id_rv32_vmvNr, (u16)1,
							GuardKind::VlenbVstart);
			    b.Create_vchunkactive(1, 16);
			    b.Create_rvvtypedchunkend(0u, RuntimeStubId::id_rv32_vmvNr);
			    PanicRuntime rt;
			    qcg::GenerateCode(&rt, nullptr, region, 0);
		    });
	// A frame with a partial arm reaches the join from outside the bounded body.
	ExpectPanic("bound in a widening frame with a partial arm",
		    "rvv active-vl bound in a frame with a partial arm", [] {
			    BuildHandFrame(true, GuardKind::VTypeIntegerTwoArm, true, true);
		    });
	// THE `chunks >= 2` MUTATION, both directions, on WIDENING nodes. Dropping that conjunct
	// produces exactly the first case: the translator clears every widening node's `finish` and
	// emits no bound, so nobody writes vstart = 0 and the NEXT vector instruction starts at a
	// stale prestart index.
	ExpectPanic("widening frame claims the vstart write but emitted no bound",
		    "rvv active-vl bound: frame and body disagree about who clears vstart", [] {
			    BuildHandFrame(false, GuardKind::VTypeInteger, true, false);
		    });
	ExpectPanic("widening body emitted a bound but the frame does not claim the vstart write",
		    "rvv active-vl bound: frame and body disagree about who clears vstart", [] {
			    BuildHandFrame(true, GuardKind::VTypeInteger, false, false);
		    });
	// The agreeing cases must NOT Panic, or the two above would pass for the wrong reason.
	BuildHandFrame(true, GuardKind::VTypeInteger, true, false);
	BuildHandFrame(false, GuardKind::VTypeInteger, false, false);
	printf("  ok   the agreeing widening frames (bound+claim, no-bound+no-claim) translate\n"
	       "       cleanly\n");
}

// ---------------------------------------------------------------------------------------------
// [W11] the three switches are independent.

void TestSwitchIndependence()
{
	std::vector<u32> const equal_width = {Vsetvli(SEW32, M2),
					      MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV)};
	std::vector<u32> const fp = {Vsetvli(SEW64, M2), MakeOpV(F6_VFADD, 1, 10, 12, 8, OPFVV)};
	std::vector<u32> const widen = {Vsetvli(SEW16, M2), MakeOpV(F6_VWADD, 1, 12, 14, 8, OPMVV)};

	for (u32 vlen : {512u, 1024u}) {
		// The widening switch does not move the equal-width route, with the equal-width
		// switch either off or on.
		for (bool ib : {false, true}) {
			Built a, b;
			Translate(a, equal_width, Env{vlen, false, ib});
			Translate(b, equal_width, Env{vlen, true, ib});
			Emit(a);
			Emit(b);
			CHECK(!a.code.empty());
			CHECK(a.code == b.code);
			CHECK(OpcodeStream(a.region) == OpcodeStream(b.region));
		}
		// ...nor the FP route, with the FP switch either off or on.
		for (bool fb : {false, true}) {
			Built a, b;
			Translate(a, fp, Env{vlen, false, false, fb});
			Translate(b, fp, Env{vlen, true, false, fb});
			Emit(a);
			Emit(b);
			CHECK(!a.code.empty());
			CHECK(a.code == b.code);
			CHECK(OpcodeStream(a.region) == OpcodeStream(b.region));
		}
		// And conversely: neither the equal-width nor the FP switch moves a widening frame.
		{
			Built base, ib, fb;
			Translate(base, widen, Env{vlen, false, false, false});
			Translate(ib, widen, Env{vlen, false, true, false});
			Translate(fb, widen, Env{vlen, false, false, true});
			Emit(base);
			Emit(ib);
			Emit(fb);
			CHECK(!base.code.empty());
			CHECK(base.code == ib.code);
			CHECK(base.code == fb.code);
		}
		// Turning the widening switch on with the others off adds bounds ONLY to the
		// widening frame, so the three checks above are not passing vacuously.
		{
			Built w;
			Translate(w, widen, Env{vlen, true});
			unsigned bounds = 0;
			for (auto const &f : FindFrames(w.region))
				bounds += CountOp(f, Op::_vchunkactive);
			CHECK_EQ(bounds, Chunks({"", SEW16, M2, 2, 0}, vlen) - 1u);
		}
		printf("  ok   VLEN %-4u the widening switch leaves the equal-width and FP routes\n"
		       "       byte-identical, and neither of those switches moves a widening frame\n",
		       vlen);
	}
}
} // namespace

int main()
{
	qcg::ArchTraits::init();
	printf("[W11a] the switch is really default-off\n");
	TestOffIsInert();
	printf("[W1] ON: chunk-0 omission, the destination element ladder, node placement, jbe\n");
	TestOnShapeAndLadder();
	printf("[W2] full VL: the delta is exactly chunks-1 cmp/jbe pairs\n");
	TestFullVlIsExactlyTheAddedPairs();
	printf("[W3] non-zero vstart still handled; vstart cleared exactly once\n");
	TestVstartOwnership();
	printf("[W4] the early exit is blind to v0\n");
	TestEarlyExitIsBlindToTheMask();
	printf("[W5/W7] no chunk work moved; legal overlaps and accumulate forms\n");
	TestNoChunkWorkMoved();
	TestAccumulateRefusesOverlap();
	printf("[W6] .wv/.wx wide sources share the .vv element ladder\n");
	TestWideSourceLadderMatchesNarrow();
	printf("[W7] vwmacc* accumulates in its own chunk window\n");
	TestAccumulateReadsItsOwnWindow();
	printf("[W8] no CSR side effect\n");
	TestNoCsrSideEffect();
	printf("[W9] the branch target and the emitted shape, exactly\n");
	TestBranchTargetAndShape();
	printf("[W10] exclusions\n");
	TestOneChunkFrameIsByteIdentical();
	TestChunkCapacityBoundary();
	TestNoWideningInRunFrames();
	TestFailClosed();
	printf("[W11b] the three switches are independent\n");
	TestSwitchIndependence();
	if (g_failures) {
		printf("FAIL rvv_active_vl_widen_bound_test: %d failure(s)\n", g_failures);
		return 1;
	}
	printf("PASS rvv_active_vl_widen_bound_test\n");
	return 0;
}
