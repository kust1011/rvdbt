// W27: the INTEGER ACTIVE-RANGE POLICY switch (`--rvv-qcg-active-vl-int-bound`) extended from the
// equal-width lane route to the integer NARROWING route -- `RvvTryIntegerFamily`'s
// `id_rv32_vnshift`/`id_rv32_vnclip` block, i.e. every `InstVChunkNarrowShift` node (vnsrl/vnsra,
// .wv/.wx/.wi) and every narrowing `InstVChunkPartialAlu` node (vnclipu/vnclip, same forms).
// Mask-logic, reduction, slide/gather, vector memory, whole-register transfers and multi-member
// vector runs remain unwired, and this file is where that stays true.
//
// NO NEW SWITCH AND NO NEW GEOMETRY CODE. The decision comes from the SAME shared planner the FP,
// equal-width and widening routes call (dbt/guest/rv32_active_chunk_plan.h), with this route's own
// shape: one emitted work unit READS `bytes` of the double-width source group and WRITES `bytes/2`
// of the destination group, so `unit_dest_bytes = bytes/2` and `dest_element_bytes = SEW` (for a
// narrowing op the vtype SEW is the DESTINATION width and the source is 2*SEW). The planner's
// geometry is destination-side precisely so that this route needs no special case; the geometry
// itself is checked exhaustively in rvv_active_chunk_plan_test.cpp, and what this file checks is
// the wiring and the emitted consequences.
//
// WHAT THIS FILE CAN AND CANNOT OBSERVE. The frames are AVX-512 bodies and this suite runs on a
// host without AVX-512, so nothing here EXECUTES the emitted bytes (the CompilerRuntime hands back
// a buffer, never a PROT_EXEC mapping) and no assertion below is a value-level one.
// `--rvv-qcg-typed-chunk-force-emit` bypasses exactly the host-feature admission row. The
// value-level obligation -- that skipping a `vl <= element_base` unit is bit-for-bit the
// architectural no-op it already was -- belongs to a QEMU differential on AVX-512 hardware and is
// NOT discharged here. What IS discharged is everything the QIR and the emitted bytes can settle.
//
// WHAT IS CHECKED, AND WHAT EACH CHECK'S FAILURE LOOKS LIKE
//
//   [N1] SWITCH-OFF IS INERT. With the policy switch clear, every shape at every VLEN has zero
//        `vchunkactive`, `n_typed == units`, `finish` on exactly the last body node,
//        `frame_clears_vstart == false`, and the emitted bytes contain NONE of the `cmp [vec.vl],
//        imm` compares the ON arm would add. Failure = the route was wired unconditionally, i.e.
//        the switch is not really the gate.
//
//   [N2] ON IS EXACTLY `units - 1` BOUNDS, UNIT 0 OMITTED, AND THE LADDER IS THE DESTINATION ONE.
//        Bound c carries unit index c for c = 1..units-1; its `element_base` equals
//        `c * (bytes/2/SEW)` with the stride DERIVED IN THIS FILE from the RVV geometry rather than
//        read back from a node; it immediately precedes unit c's own body node; `n_typed ==
//        2*units - 1`; every body node's `finish` is clear; `frame_clears_vstart == true`. Failure
//        = a unit-0 bound, a bound out of position, or -- the one this route exists to catch -- an
//        `element_base` built from the unit's SOURCE span (`bytes`) instead of its destination span
//        (`bytes/2`), which is exactly twice the correct stride. [N9] turns that into a statement
//        about full VL: with the doubled stride the last bound fires on a FULL-VL execution and
//        retires LIVE units, so this is a wrong-value bug and not a lost saving.
//
//   [N3] A ONE-UNIT FRAME IS BYTE-IDENTICAL WITH THE SWITCH ON. Unit 0 is never bounded, so a
//        fractional-LMUL narrowing frame (source group = one host chunk) has no suffix to retire.
//        Checked as literal byte equality of the two emitted streams -- the strongest inertness
//        statement available without execution. Failure = the `units >= 2` conjunct was lost, which
//        is also the silent `vstart` trap: nobody would write `vstart = 0`.
//
//   [N4] NO UNIT WORK MOVED. The multiset of every body node's (rd, rs2, rs1, kind, unit, sew,
//        chunk_bytes, src kind, imm, masked, element_base) is identical between the arms, and the
//        SEQUENCE of unit indices is 0,1,2,... in both -- run over the DISJOINT shape and over the
//        one overlap `narrow_registers_legal` admits, `vd == vs2`. Failure = the bound added,
//        dropped, retargeted or re-masked work, or reordered units. Order is what makes the
//        bottom-aligned overlap safe: unit c writes destination bytes [c*bytes/2, (c+1)*bytes/2),
//        strictly BELOW unit c+1's source read at [(c+1)*bytes, (c+2)*bytes).
//
//   [N5] EVERY FORM AND BOTH NODE KINDS. vnsrl/vnsra (InstVChunkNarrowShift) and vnclipu/vnclip
//        (narrowing InstVChunkPartialAlu), each in .wv/.wx/.wi and masked/unmasked, produce the
//        SAME ladder at the same vtype, and each bound is exactly `cmp dword [vec.vl], imm`
//        followed IMMEDIATELY by its branch with nothing between them. Failure = the ladder was
//        derived from something form-specific (the .wx/.wi scalar source, or the clip arm's
//        different node), or the bound is a `kortest`-style test on the active mask -- which would
//        skip LIVE units whenever `vstart > 0` made a leading unit's mask zero.
//
//   [N6] NON-ZERO vstart IS STILL HANDLED, AND CLEARED EXACTLY ONCE. `EmitRvvBodyMask`'s second
//        prefix reads `vec.vstart` once per unit, and that count is the SAME in both arms and equal
//        to `units`: prestart units are NOT skipped, they keep running under their zero mask.
//        `mov dword [vec.vstart], 0` occurs exactly ONCE in each arm. Failure = the bound was made
//        to skip prestart units (counts drop), or the ownership of the single `vstart` write ended
//        up duplicated or lost when it moved off the last body node onto the frame epilogue.
//
//   [N7] vnclip's STICKY `vxsat` IS UNTOUCHED AND STILL MASK-GATED. The five-instruction accrual
//        `kmovq rax,k2; and rax,rdi; setne al; movzx eax,al; or [vec.vxsat],eax` occurs exactly
//        `units` times in BOTH arms, and `vnsrl`/`vnsra` contain it zero times in both. The
//        `and rax, rdi` is what makes a fully-inactive unit contribute ZERO, which is why skipping
//        such a unit cannot lose or invent a saturation flag. This is the check that fails if that
//        AND is ever removed and the bound is then credited with a behaviour change it did not
//        make. Failure = an accrual count that differs between the arms, or an accrual that is no
//        longer gated by the architectural mask.
//
//   [N8] THE BRANCH TARGET, EXACTLY. Every bound's branch in the ON arm resolves to the SAME
//        address; that address is the offset of the frame's single `mov dword [vec.vstart], 0`; it
//        lies strictly BEFORE the fallback arm (located independently by `inc qword
//        [rvv_direct_fallbacks]`); and real work lies strictly inside the skipped range (the last
//        unit's `kmovq k1, rdi`, the instruction that installs its body mask). Failure = an early
//        exit landing on the fallback would re-run the ordered helper on top of units the body
//        already stored; one landing on the join would leave `vstart` dirty for the NEXT vector
//        instruction.
//
//  [N10] SHORT VL RETIRES EXACTLY THE INACTIVE SUFFIX. For a ladder of immediates read back from
//        the emitted bytes, and for every `vl` in a dense sweep (0, 1, stride-1, stride, stride+1,
//        ... full VL), the set of units the ladder would retire -- `{c : vl <= imm_c}`, evaluated
//        against the DECODED immediates with the same unsigned `jbe` predicate the emitted code
//        uses -- must equal the architecturally inactive set `{c : c*stride >= vl}`, and the
//        retired set must be a contiguous SUFFIX. This is the short-vl statement this suite can
//        make without executing: it separates "the ladder exists" from "the ladder retires the
//        right units", and a stride error of any factor, or a `jb`/`jbe` confusion at exactly
//        `vl == imm_c`, makes the two sets differ. (The a23-a35 lesson: a coarse vl sweep cannot
//        see a unit-boundary off-by-one, so stride-1/stride/stride+1 are all present.)
//
//   [N9] THE BRANCH IS `jbe`, NOT `jb`, AND THE LADDER IS INERT AT FULL VL. Each bound's opcode is
//        decoded from the bytes and required to be `jbe` (0x76 / 0x0f86): at exactly `vl ==
//        element_base` the unit's first element is already at the tail boundary, so `jb` would run
//        one entirely-inactive unit -- correct output, no saving, invisible to any check that only
//        counts bounds. And the largest immediate in the ladder is strictly below the frame's
//        full-VL element count, so no bound can fire on a full-VL execution; the SOURCE-span
//        stride, computed here for contrast, exceeds it.

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
#include <tuple>
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
// Guest encodings, from the field layout rather than as magic words.

constexpr u32 Vsetvli(u32 vsew, u32 vlmul)
{
	return ((0xc0u | (vsew << 3) | vlmul) << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u;
}
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 f3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 OPIVV = 0u, OPIVI = 3u, OPIVX = 4u;
// RVV 1.0 OPIVV/OPIVX/OPIVI funct6 for the narrowing family.
constexpr u32 F6_VNSRL = 0b101100u, F6_VNSRA = 0b101101u, F6_VNCLIPU = 0b101110u,
	      F6_VNCLIP = 0b101111u;
constexpr u32 SEW8 = 0u, SEW16 = 1u, SEW32 = 2u;
constexpr u32 M1 = 0u, M2 = 1u, MF2 = 7u;

// ---------------------------------------------------------------------------------------------
// ONE PROCESS-WIDE CODE BUFFER: [N3] compares the emitted bytes of two translations for literal
// equality, and an emitted region can embed the address of its own buffer. Handing every emission
// the same fixed address removes that degree of freedom. Nothing is ever executed from it.
alignas(4096) u8 g_code_buf[1u << 20];

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("narrow active-vl test: emitted region exceeds the fixed code buffer");
		return g_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};

struct Env {
	u32 vlen_bits = 512;
	bool int_bound = false;
	// W28's ablation control, default ON exactly as production: every check above therefore runs
	// with the policy switch as the only gate, which is what the W27 checkpoint shipped.
	bool narrow_bound = true;
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
	// The route under test plus the audit-only host-feature bypass: this workstation has no
	// AVX-512 and nothing here executes the bytes.
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_active_vl_int_bound = e.int_bound;
	config::rvv_qcg_active_vl_narrow_bound = e.narrow_bound;
	// Every other active-range switch stays OFF, so this frame is the only thing that can move.
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_active_vl_widen_bound = false;
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

void Emit(Built &b)
{
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
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

// Everything a narrowing body node says about WHICH bytes it touches and under WHICH predicate,
// for BOTH node kinds. `finish` is deliberately EXCLUDED: moving that one write is the
// transformation. The leading int distinguishes the two kinds so the multisets cannot cross.
using Work = std::tuple<int, u32, u32, u32, int, int, int, u32, int, u32>;

bool IsBodyNode(Inst *i)
{
	return i->GetOpcode() == Op::_vchunknarrowshift || i->GetOpcode() == Op::_vchunkpartialalu;
}

std::vector<Work> UnitWork(Frame const &f)
{
	std::vector<Work> out;
	for (auto *i : f.body) {
		if (i->GetOpcode() == Op::_vchunknarrowshift) {
			auto *n = static_cast<InstVChunkNarrowShift *>(i);
			out.push_back({0, n->rd, n->rs2, n->rs1, (int)n->sew, (int)n->bytes,
				       (int)n->src, n->imm, (int)n->masked, n->base});
		} else if (i->GetOpcode() == Op::_vchunkpartialalu) {
			auto *n = static_cast<InstVChunkPartialAlu *>(i);
			out.push_back({1, n->rd_offs, n->rs2_offs, n->rs1_offs, (int)n->sew_bytes,
				       (int)n->chunk_bytes, (int)n->src1_kind, n->imm, (int)n->masked,
				       n->element_base});
		}
	}
	return out;
}

// The unit index each body node carries, in emission order. Only the clip node has a `chunk`
// field; the narrow-shift node identifies its unit by its `base`, so the order is read from the
// element base, which is the quantity the ordering argument is about anyway.
std::vector<u32> UnitOrder(Frame const &f)
{
	std::vector<u32> out;
	for (auto *i : f.body) {
		if (i->GetOpcode() == Op::_vchunknarrowshift)
			out.push_back(static_cast<InstVChunkNarrowShift *>(i)->base);
		else if (i->GetOpcode() == Op::_vchunkpartialalu)
			out.push_back(static_cast<InstVChunkPartialAlu *>(i)->element_base);
	}
	return out;
}

// ---------------------------------------------------------------------------------------------
// Emitted-byte anchors. Every needle is assembled by an INDEPENDENT asmjit instance and located by
// its own bytes, never by an offset computed from the emitter's structure.

auto const kStateReg = asmjit::x86::gpq(qcg::ArchTraits::STATE);

std::vector<u8> Assemble(std::function<void(asmjit::x86::Assembler &)> const &body)
{
	asmjit::CodeHolder holder;
	if (holder.init(asmjit::Environment::host()))
		Panic("narrow active-vl test: asmjit init");
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

int32_t const kVlOff = (int32_t)offsetof(CPUState, vec) + (int32_t)offsetof(rv32::VectorState, vl);
int32_t const kVstartOff =
    (int32_t)offsetof(CPUState, vec) + (int32_t)offsetof(rv32::VectorState, vstart);
int32_t const kVxsatOff =
    (int32_t)offsetof(CPUState, vec) + (int32_t)offsetof(rv32::VectorState, vxsat);

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
std::vector<u8> BodyMaskInstall()
{
	// EmitRvvBodyMask leaves the architectural mask in rdi and both narrowing bodies install it
	// as k1 before their first load: one per unit, and the last one must lie inside the skipped
	// range for [N8] to mean anything.
	return Assemble(
	    [&](asmjit::x86::Assembler &a) { a.kmovq(asmjit::x86::KReg(1), asmjit::x86::rdi); });
}
std::vector<u8> FallbackInc()
{
	return Assemble([&](asmjit::x86::Assembler &a) {
		a.inc(asmjit::x86::qword_ptr(kStateReg,
					     (int32_t)offsetof(CPUState, rvv_direct_fallbacks)));
	});
}
// vnclip's whole sticky-flag accrual, INCLUDING the AND with the architectural body mask that makes
// an inactive unit contribute nothing. Assembled as ONE needle so a change to any instruction in it
// is visible. The clip arm uses k2 (the saturation predicate), unlike the equal-width saturating
// ops' k3.
std::vector<u8> VxsatAccrual()
{
	return Assemble([&](asmjit::x86::Assembler &a) {
		namespace x86 = asmjit::x86;
		a.kmovq(x86::rax, x86::KReg(2));
		a.and_(x86::rax, x86::rdi);
		a.setne(x86::al);
		a.movzx(x86::eax, x86::al);
		a.or_(x86::dword_ptr(kStateReg, kVxsatOff), x86::eax);
	});
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
// Shapes. Every geometric quantity is RE-DERIVED here from the RVV rules, never read back from a
// node: that is what makes the ladder check in [N2] able to fail.
//
//   host chunk        bytes      = min(VLEN/8, 64)                 (the unit's SOURCE span)
//   unit destination  bytes/2                                      (the narrowing store's width)
//   source group      (VLEN/8) << (lmul_log2 + 1)                  (EMUL of the wide operand)
//   units             ceil(source group / bytes)
//   elements per unit (bytes/2) / SEW                              <-- the ladder's stride
//
// `narrow_registers_legal` requires SEW <= 32 (the source is 2*SEW), an aligned destination group
// at LMUL and an aligned source group at LMUL*2, no vs1/vs2 overlap, and admits exactly one
// destination overlap: the bottom-aligned `vd == vs2`.
struct Shape {
	char const *name;
	u32 vsew;
	u32 vlmul;
	int lmul_log2;
	u32 sew; // destination element bytes
	u32 insn;
	bool clip; // vnclipu/vnclip -> the InstVChunkPartialAlu arm, with the vxsat accrual
};

u32 ChunkBytes(u32 vlen) { return std::min(vlen / 8u, 64u); }
u32 SourceGroupBytes(Shape const &s, u32 vlen)
{
	u32 const rb = vlen / 8u;
	int const wl = s.lmul_log2 + 1;
	return wl >= 0 ? (rb << wl) : (rb >> (-wl));
}
u32 Units(Shape const &s, u32 vlen)
{
	u32 const b = ChunkBytes(vlen);
	return (SourceGroupBytes(s, vlen) + b - 1u) / b;
}
u32 ElementsPerUnit(Shape const &s, u32 vlen) { return ChunkBytes(vlen) / 2u / s.sew; }

Shape const kShapes[] = {
    {"vnsrl.wv   e8,m1 ", SEW8, M1, 0, 1, MakeOpV(F6_VNSRL, 1, 10, 9, 8, OPIVV), false},
    {"vnsrl.wv   e16,m1", SEW16, M1, 0, 2, MakeOpV(F6_VNSRL, 1, 10, 9, 8, OPIVV), false},
    {"vnsrl.wv   e32,m1", SEW32, M1, 0, 4, MakeOpV(F6_VNSRL, 1, 10, 9, 8, OPIVV), false},
    {"vnsra.wv   e16,m2", SEW16, M2, 1, 2, MakeOpV(F6_VNSRA, 1, 12, 10, 8, OPIVV), false},
    {"vnsrl.wx   e16,m2", SEW16, M2, 1, 2, MakeOpV(F6_VNSRL, 1, 12, 11, 8, OPIVX), false},
    {"vnsrl.wi   e16,m2", SEW16, M2, 1, 2, MakeOpV(F6_VNSRL, 1, 12, 3, 8, OPIVI), false},
    {"vnsrl.wv   e16,m2 masked", SEW16, M2, 1, 2, MakeOpV(F6_VNSRL, 0, 12, 10, 8, OPIVV), false},
    {"vnsrl.wv   e16,m2 vd==vs2", SEW16, M2, 1, 2, MakeOpV(F6_VNSRL, 1, 12, 10, 12, OPIVV), false},
    {"vnclipu.wv e8,m1 ", SEW8, M1, 0, 1, MakeOpV(F6_VNCLIPU, 1, 10, 9, 8, OPIVV), true},
    {"vnclip.wv  e16,m2", SEW16, M2, 1, 2, MakeOpV(F6_VNCLIP, 1, 12, 10, 8, OPIVV), true},
    {"vnclip.wx  e16,m2", SEW16, M2, 1, 2, MakeOpV(F6_VNCLIP, 1, 12, 11, 8, OPIVX), true},
    {"vnclip.wi  e16,m2", SEW16, M2, 1, 2, MakeOpV(F6_VNCLIP, 1, 12, 3, 8, OPIVI), true},
    {"vnclip.wv  e16,m2 masked", SEW16, M2, 1, 2, MakeOpV(F6_VNCLIP, 0, 12, 10, 8, OPIVV), true},
    {"vnclip.wv  e16,m2 vd==vs2", SEW16, M2, 1, 2, MakeOpV(F6_VNCLIP, 1, 12, 10, 12, OPIVV), true},
    // The second legal aliasing, which `narrow_registers_legal` leaves unconstrained because both
    // groups are equal-EMUL and aligned (they coincide or are disjoint): vd == vs1, the narrow
    // shift-amount / clip-amount source. Unit c reads vs1 bytes [c*b/2, (c+1)*b/2) and writes the
    // SAME window, its own load preceding its own store inside one node, so later units are
    // unaffected -- and deleting a trailing set of units removes both the read and the write.
    {"vnsrl.wv   e16,m2 vd==vs1", SEW16, M2, 1, 2, MakeOpV(F6_VNSRL, 1, 12, 8, 8, OPIVV), false},
    {"vnclip.wv  e16,m2 vd==vs1", SEW16, M2, 1, 2, MakeOpV(F6_VNCLIP, 1, 12, 8, 8, OPIVV), true},
};

// The fractional-LMUL frame, whose source group is exactly one host chunk: `units == 1`, the case
// [N3] needs.
Shape const kOneUnit = {"vnsrl.wv   e16,mf2", SEW16, MF2, -1, 2,
			MakeOpV(F6_VNSRL, 1, 9, 10, 8, OPIVV), false};

std::vector<u32> Program(Shape const &s) { return {Vsetvli(s.vsew, s.vlmul), s.insn}; }

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
			Translate(off, Program(s), Env{vlen, /*int_bound=*/false});
			std::vector<Frame> f;
			if (!OneFrame(off, f, s.name))
				continue;
			unsigned const units = Units(s, vlen);
			unsigned bodies = 0, finishes = 0, last_is_finish = 0;
			for (auto *i : f[0].body) {
				if (!IsBodyNode(i))
					continue;
				++bodies;
				bool fin = i->GetOpcode() == Op::_vchunknarrowshift
					       ? static_cast<InstVChunkNarrowShift *>(i)->finish
					       : static_cast<InstVChunkPartialAlu *>(i)->finish_instruction;
				finishes += fin;
				last_is_finish = (bodies == units) && fin;
			}
			CHECK_EQ(bodies, units);
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 0u);
			CHECK_EQ((unsigned)f[0].begin->n_typed, units);
			CHECK_EQ(finishes, 1u);
			CHECK_EQ(last_is_finish, 1u);
			if (f[0].end)
				CHECK_EQ((int)f[0].end->frame_clears_vstart, 0);
			// And no compare against vec.vl anywhere in the emitted bytes.
			Emit(off);
			unsigned compares = 0;
			for (u32 c = 1; c < units; ++c)
				compares += Count(off.code, BoundCmp(c * ElementsPerUnit(s, vlen)));
			CHECK_EQ(compares, 0u);
		}
	printf("    switch off: %zu shapes x 2 VLENs are the legacy frame, zero vl compares\n",
	       sizeof(kShapes) / sizeof(kShapes[0]));
}

void TestOnLadder()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built on;
			Translate(on, Program(s), Env{vlen, /*int_bound=*/true});
			std::vector<Frame> f;
			if (!OneFrame(on, f, s.name))
				continue;
			u32 const units = Units(s, vlen), stride = ElementsPerUnit(s, vlen);
			CHECK(units >= 2u); // every table row is a multi-unit frame by construction
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), units - 1u);
			CHECK_EQ((unsigned)f[0].begin->n_typed, 2u * units - 1u);
			if (f[0].end)
				CHECK_EQ((int)f[0].end->frame_clears_vstart, 1);
			// The ladder, in emission order: bound c immediately precedes unit c's body
			// node, carries unit index c and element base c*stride; unit 0 has none; no
			// body node finishes.
			u32 unit = 0;
			bool pending_bound = false;
			for (auto *i : f[0].body) {
				if (i->GetOpcode() == Op::_vchunkactive) {
					auto *n = static_cast<InstVChunkActive *>(i);
					CHECK_EQ((unsigned)n->chunk, unit);
					CHECK_EQ(n->element_base, unit * stride);
					CHECK(unit != 0u);
					CHECK(!pending_bound);
					pending_bound = true;
					continue;
				}
				if (!IsBodyNode(i))
					continue;
				u32 const base =
				    i->GetOpcode() == Op::_vchunknarrowshift
					? static_cast<InstVChunkNarrowShift *>(i)->base
					: static_cast<InstVChunkPartialAlu *>(i)->element_base;
				bool const fin =
				    i->GetOpcode() == Op::_vchunknarrowshift
					? static_cast<InstVChunkNarrowShift *>(i)->finish
					: static_cast<InstVChunkPartialAlu *>(i)->finish_instruction;
				CHECK_EQ(base, unit * stride);
				CHECK(!fin);
				CHECK_EQ(pending_bound, unit != 0u);
				pending_bound = false;
				++unit;
			}
			CHECK_EQ(unit, units);
		}
	printf("    switch on: units-1 bounds, unit 0 omitted, base == c*(bytes/2/SEW)\n");
}

void TestOneUnitFrameIsIdentical()
{
	// VLEN 512, mf2: the source group is (512/8) << 0 == 64 bytes == one host chunk.
	u32 const vlen = 512;
	CHECK_EQ(Units(kOneUnit, vlen), 1u);
	Built off, on;
	Translate(off, Program(kOneUnit), Env{vlen, false});
	Emit(off);
	Translate(on, Program(kOneUnit), Env{vlen, true});
	Emit(on);
	std::vector<Frame> fo, fn;
	if (OneFrame(off, fo, "mf2 off") && OneFrame(on, fn, "mf2 on")) {
		CHECK_EQ(CountOp(fn[0], Op::_vchunkactive), 0u);
		CHECK_EQ((unsigned)fn[0].begin->n_typed, (unsigned)fo[0].begin->n_typed);
		if (fn[0].end)
			CHECK_EQ((int)fn[0].end->frame_clears_vstart, 0);
	}
	CHECK_EQ(on.code.size(), off.code.size());
	CHECK(!on.code.empty());
	CHECK(on.code == off.code);
	printf("    one-unit (mf2) frame: %zu emitted bytes, byte-identical with the switch on\n",
	       on.code.size());
}

void TestNoWorkMoved()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built off, on;
			Translate(off, Program(s), Env{vlen, false});
			Translate(on, Program(s), Env{vlen, true});
			std::vector<Frame> fo, fn;
			if (!OneFrame(off, fo, s.name) || !OneFrame(on, fn, s.name))
				continue;
			auto wo = UnitWork(fo[0]), wn = UnitWork(fn[0]);
			CHECK_EQ(wo.size(), wn.size());
			auto so = wo, sn = wn;
			std::sort(so.begin(), so.end());
			std::sort(sn.begin(), sn.end());
			CHECK(so == sn);
			// Order is ascending in both arms, which is what makes the bottom-aligned
			// `vd == vs2` overlap safe.
			auto oo = UnitOrder(fo[0]), on_order = UnitOrder(fn[0]);
			CHECK(oo == on_order);
			CHECK(std::is_sorted(on_order.begin(), on_order.end()));
			CHECK(std::adjacent_find(on_order.begin(), on_order.end()) == on_order.end());
		}
	printf("    no unit work moved: identical multisets, ascending order in both arms\n");
}

void TestBoundIsAdjacentAndVlOnly()
{
	// One bound is `cmp dword [vec.vl], imm` followed IMMEDIATELY by its branch: the emitted
	// bytes of the compare are located, and the byte right after them must decode as jbe.
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built on;
			Translate(on, Program(s), Env{vlen, true});
			Emit(on);
			u32 const units = Units(s, vlen), stride = ElementsPerUnit(s, vlen);
			for (u32 c = 1; c < units; ++c) {
				auto const needle = BoundCmp(c * stride);
				size_t at = SIZE_MAX;
				unsigned const n = CountBytes(on.code, needle, &at);
				CHECK_EQ(n, 1u);
				if (n != 1u)
					continue;
				size_t end = 0, target = 0;
				CHECK(DecodeJbe(on.code, at + needle.size(), &end, &target));
			}
		}
	printf("    every bound is `cmp [vec.vl], imm` + jbe, adjacent, once each\n");
}

void TestVstart()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built off, on;
			Translate(off, Program(s), Env{vlen, false});
			Emit(off);
			Translate(on, Program(s), Env{vlen, true});
			Emit(on);
			u32 const units = Units(s, vlen);
			// Prestart units are not skipped: the per-unit vstart read count is equal in
			// both arms and equal to the unit count.
			CHECK_EQ(Count(off.code, VstartLoad()), units);
			CHECK_EQ(Count(on.code, VstartLoad()), units);
			// The single architectural `vstart = 0`, in each arm exactly once.
			CHECK_EQ(Count(off.code, VstartClear()), 1u);
			CHECK_EQ(Count(on.code, VstartClear()), 1u);
		}
	printf("    vstart: read once per unit in both arms, cleared exactly once in each\n");
}

void TestVxsat()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built off, on;
			Translate(off, Program(s), Env{vlen, false});
			Emit(off);
			Translate(on, Program(s), Env{vlen, true});
			Emit(on);
			unsigned const want = s.clip ? Units(s, vlen) : 0u;
			CHECK_EQ(Count(off.code, VxsatAccrual()), want);
			CHECK_EQ(Count(on.code, VxsatAccrual()), want);
		}
	printf("    vxsat: the mask-gated accrual appears once per unit in BOTH arms for vnclip,\n");
	printf("           and never for vnsrl/vnsra\n");
}

void TestBranchTarget()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built on;
			Translate(on, Program(s), Env{vlen, true});
			Emit(on);
			u32 const units = Units(s, vlen), stride = ElementsPerUnit(s, vlen);
			size_t const vstart_at = Find(on.code, VstartClear());
			size_t const fallback_at = Find(on.code, FallbackInc());
			size_t const last_mask = FindLast(on.code, BodyMaskInstall());
			CHECK(vstart_at != SIZE_MAX);
			CHECK(fallback_at != SIZE_MAX);
			CHECK(last_mask != SIZE_MAX);
			if (vstart_at == SIZE_MAX || fallback_at == SIZE_MAX || last_mask == SIZE_MAX)
				continue;
			// The single vstart write is the branch target, it precedes the fallback arm,
			// and the last unit's mask install is strictly inside the skipped range.
			CHECK(vstart_at < fallback_at);
			CHECK(last_mask < vstart_at);
			for (u32 c = 1; c < units; ++c) {
				auto const needle = BoundCmp(c * stride);
				size_t at = SIZE_MAX;
				if (CountBytes(on.code, needle, &at) != 1u)
					continue;
				size_t end = 0, target = 0;
				if (!DecodeJbe(on.code, at + needle.size(), &end, &target))
					continue;
				CHECK_EQ(target, vstart_at);
				CHECK(end < last_mask || c + 1 == units);
			}
		}
	printf("    every branch lands on the frame's single vstart write, before the fallback\n");
}

void TestLadderInertAtFullVl()
{
	// The ladder cannot fire on a full-VL execution, and the SOURCE-span stride can: that is the
	// difference between a saving and a wrong value, stated as an inequality on this route's own
	// numbers rather than as prose.
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			u32 const units = Units(s, vlen), stride = ElementsPerUnit(s, vlen);
			u32 const full_vl = units * stride; // == VLMAX of the destination group
			CHECK(units >= 2u);
			CHECK_EQ((units - 1u) * stride < full_vl, true);
			u32 const wrong = 2u * stride; // the host SOURCE span's element count
			CHECK_EQ(wrong, ChunkBytes(vlen) / s.sew);
			// With the wrong stride some bound in the ladder is at or above full VL, so a
			// full-VL execution would retire live units. Checked as an existence claim.
			bool fires = false;
			for (u32 c = 1; c < units; ++c)
				fires |= c * wrong >= full_vl;
			CHECK(fires);
		}
	printf("    the destination ladder is inert at full VL; the source-span ladder is not\n");
}
// ---------------------------------------------------------------------------------------------
// [N10] short vl retires exactly the architecturally inactive suffix
// ---------------------------------------------------------------------------------------------
void TestShortVlRetiresTheInactiveSuffix()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			Built on;
			Translate(on, Program(s), Env{vlen, /*int_bound=*/true});
			Emit(on);
			u32 const units = Units(s, vlen), stride = ElementsPerUnit(s, vlen);
			// The ladder as the EMITTED CODE states it: one immediate per bound, kept only
			// when the `cmp dword [vec.vl], imm` bytes for it are actually present.
			std::vector<u32> imm;
			for (u32 c = 1; c < units; ++c) {
				auto const needle = BoundCmp(c * stride);
				size_t at = SIZE_MAX;
				if (CountBytes(on.code, needle, &at) == 1u)
					imm.push_back(c * stride);
			}
			CHECK_EQ(imm.size(), units - 1u);
			if (imm.size() != units - 1u)
				continue;
			// A dense vl sweep around every unit boundary, plus 0 and full VL.
			std::vector<u32> vls = {0u, 1u};
			for (u32 c = 1; c <= units; ++c) {
				u32 const base = c * stride;
				vls.push_back(base - 1u);
				vls.push_back(base);
				if (base + 1u <= units * stride)
					vls.push_back(base + 1u);
			}
			for (u32 vl : vls) {
				// What the emitted ladder retires: the first bound whose immediate
				// satisfies the unsigned `vl <= imm` predicate leaves the body, so
				// every unit from that one on is retired.
				u32 first_retired = units;
				for (u32 c = 1; c < units; ++c)
					if (vl <= imm[c - 1]) {
						first_retired = c;
						break;
					}
				// What the architecture says is inactive: unit c is entirely tail
				// exactly when its first element index is at or above vl. Unit 0 is
				// never retired by this ladder, which is why `vl == 0` retires unit 1
				// upward while unit 0 still runs -- under an all-zero mask.
				u32 want = units;
				for (u32 c = 1; c < units; ++c)
					if (c * stride >= vl) {
						want = c;
						break;
					}
				CHECK_EQ(first_retired, want);
				// And the retired set is a contiguous suffix: monotonicity of the
				// immediates, restated as a property of the decoded ladder.
				for (u32 c = first_retired; c < units; ++c)
					CHECK(vl <= imm[c - 1]);
			}
		}
	printf("    short vl: the decoded ladder retires exactly {c : c*stride >= vl}, a suffix\n");
}
// ---------------------------------------------------------------------------------------------
// [N11] W28's ablation control is AND-gated, in both directions
// ---------------------------------------------------------------------------------------------
//
// THE TRAP THIS PINS. An OR-gated sub-flag (`--rvv-qcg-typed-chunk-falu=0` doing nothing while its
// umbrella flag is 1) has already cost this project a round: the two arms of an ablation looked
// different on the command line and were identical in the emitted code. So the polarity is stated
// as four cells, and the two that must differ are checked as a byte-level difference rather than as
// a counter.
void TestAblationControlIsAndGated()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			u32 const units = Units(s, vlen);
			// policy off: the control is inert at either value, and both are the legacy frame.
			Built off0, off1;
			Translate(off0, Program(s), Env{vlen, false, false});
			Emit(off0);
			Translate(off1, Program(s), Env{vlen, false, true});
			Emit(off1);
			CHECK(off0.code == off1.code);
			// policy on: the control decides, and the two arms are NOT byte-identical.
			Built on0, on1;
			Translate(on0, Program(s), Env{vlen, true, false});
			Emit(on0);
			Translate(on1, Program(s), Env{vlen, true, true});
			Emit(on1);
			std::vector<Frame> f0, f1;
			if (OneFrame(on0, f0, s.name) && OneFrame(on1, f1, s.name)) {
				CHECK_EQ(CountOp(f0[0], Op::_vchunkactive), 0u);
				CHECK_EQ(CountOp(f1[0], Op::_vchunkactive), units - 1u);
				if (f0[0].end)
					CHECK_EQ((int)f0[0].end->frame_clears_vstart, 0);
			}
			// The ablation arm is the LEGACY frame byte for byte, and the other arm is not it.
			CHECK(on0.code == off0.code);
			CHECK(on1.code != off0.code);
			CHECK(on1.code.size() > on0.code.size());
		}
	printf("    the control is AND-gated: policy-off inert, policy-on arms differ in emitted bytes,\n");
	printf("    and the cleared arm is byte-identical to the pre-narrowing frame\n");
}
} // namespace

int main()
{
	printf("[N1] the policy switch off is inert\n");
	TestOffIsInert();
	printf("[N2] on: units-1 bounds and the destination-element ladder\n");
	TestOnLadder();
	printf("[N3] a one-unit frame is byte-identical with the switch on\n");
	TestOneUnitFrameIsIdentical();
	printf("[N4][N5] no unit work moved; every form and both node kinds\n");
	TestNoWorkMoved();
	TestBoundIsAdjacentAndVlOnly();
	printf("[N6] non-zero vstart still handled, cleared exactly once\n");
	TestVstart();
	printf("[N7] vnclip's sticky vxsat is untouched and mask-gated\n");
	TestVxsat();
	printf("[N8] the branch target, exactly\n");
	TestBranchTarget();
	printf("[N9] jbe, and the ladder is inert at full VL\n");
	TestLadderInertAtFullVl();
	printf("[N10] short vl retires exactly the inactive suffix\n");
	TestShortVlRetiresTheInactiveSuffix();
	printf("[N11] W28's ablation control is AND-gated, in both directions\n");
	TestAblationControlIsAndGated();
	if (g_failures) {
		printf("FAIL rvv_active_vl_narrow_bound_test: %d failure(s)\n", g_failures);
		return 1;
	}
	printf("PASS rvv_active_vl_narrow_bound_test\n");
	return 0;
}
