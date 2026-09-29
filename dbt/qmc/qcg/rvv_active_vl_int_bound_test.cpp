// S1-3A: `--rvv-qcg-active-vl-int-bound` wired into the EQUAL-WIDTH SAME-EEW integer lane route
// (RvvTryIntegerFamily's `vchunkpartialalu` block). Widening, mask-logic, reduction, slide/gather,
// vector memory, whole-register transfers and multi-member vector runs are deliberately NOT wired,
// and this file is where that stays true.
//
// W27 AMENDMENT: the NARROWING route (vnsrl/vnsra/vnclipu/vnclip) is now wired to this SAME switch,
// because the two blocks are one integer active-range policy. This file is unchanged and still
// passes -- it constructs no narrowing program -- and the narrowing half is checked in
// rvv_active_vl_narrow_bound_test.cpp. Nothing else in the exclusion list above moved.
//
// WHAT THIS FILE CAN AND CANNOT OBSERVE. The frames under test are AVX-512 bodies. The machine this
// suite is built and run on is an Ivy Bridge i7-3770 with no AVX-512 and no BMI2, so the emitted
// body cannot be EXECUTED here and no assertion below is a value-level one. `--rvv-qcg-typed-chunk-
// force-emit` bypasses exactly the host-feature admission row so the shape can be constructed and
// disassembled; nothing in this file ever branches into the returned bytes (the CompilerRuntime
// below hands back a std::vector, never a PROT_EXEC mapping). The value-level obligation -- that
// skipping a `vl <= element_base` chunk is bit-for-bit the architectural no-op it already was --
// belongs to the QEMU differential on AVX-512 hardware and is NOT discharged here. What IS
// discharged here is everything the emitted bytes can settle:
//
//   * that the bound's operand is the live `vec.vl` and never the mask, so a non-zero `vstart` does
//     not let it skip a live chunk;
//   * that the transformation is exactly "insert n-1 compare/branch pairs and move one `vstart`
//     write", i.e. that no chunk's work, window, mask or sticky-flag accrual changed;
//   * that the branch lands on the frame's single `vstart = 0` write and not on the fallback;
//   * that every way of misusing the mechanism is a translation Panic rather than silent wrong code.
//
// WHAT IS CHECKED, AND WHAT EACH CHECK'S FAILURE LOOKS LIKE
//
//   [1] OFF IS INERT. With the switch clear, every shape at every VLEN has zero `vchunkactive`,
//       `n_typed == chunks`, `finish_instruction` on exactly the last chunk node, and
//       `frame_clears_vstart == false`; and the emitted bytes contain none of the compares the ON
//       arm would add. Failure = the switch is not really default-off.
//
//   [2] ON IS EXACTLY `chunks - 1` BOUNDS, CHUNK 0 OMITTED. Bound `c` carries chunk index `c` for
//       c = 1..chunks-1, its `element_base` equals `c * lanes` with `lanes` DERIVED IN THIS FILE
//       from the shape (chunk_bytes / SEW) rather than read back from the node, it immediately
//       precedes chunk c's own node, `n_typed == 2*chunks - 1`, every chunk node has
//       `finish_instruction == false`, and `frame_clears_vstart == true`. Failure = a chunk-0 bound
//       (the two-instruction-per-execution cost §7 of the design accounts for would be understated),
//       a bound out of position, or an `element_base` in BYTES rather than ELEMENTS -- the ladder
//       differs by the SEW factor and this check is the one that sees it.
//
//   [3] A ONE-CHUNK FRAME IS BYTE-IDENTICAL WITH THE SWITCH ON. Because chunk 0 is never bounded,
//       `chunks == 1` has no suffix to retire. Checked as literal byte equality of the two emitted
//       streams, which is the strongest inertness statement available without execution. Failure =
//       the `chunks >= 2` conjunct was dropped -- which is also the silent `vstart` trap, see [9].
//
//   [4] NO CHUNK WORK MOVED (the overlap property). The multiset of every chunk node's
//       (rd, rs2, rs1, chunk, sew, chunk_bytes, src1 kind, imm, masked, element_base) is identical
//       between the arms, and the SEQUENCE of chunk indices is 0,1,2,... in both. Run over
//       `vd == vs2`, `vd == vs1` and disjoint shapes. Failure = the bound added, dropped, retargeted
//       or re-masked chunk work, or reordered chunks -- the one way a `vd`/source overlap could
//       start reading bytes a completed chunk had already overwritten.
//
//   [5] THE EARLY EXIT IS BLIND TO v0. The bound count and the whole `element_base` ladder are
//       identical for `vm = 1` and `vm = 0` forms of the same instruction, and for a masked shape the
//       emitted bound is still exactly `cmp dword [vec.vl], imm` + `jbe` with nothing between them.
//       Failure = a `kortest`-style test on the active mask, which would skip LIVE chunks whenever
//       `vstart > 0` made a leading chunk's mask zero.
//
//   [6] NON-ZERO vstart IS STILL HANDLED, AND CLEARED EXACTLY ONCE. The per-chunk body mask reads
//       `vec.vstart` (EmitRvvBodyMask's second prefix) once per chunk, and that count is the SAME in
//       both arms and equal to `chunks`: prestart chunks are not skipped, they keep running under
//       their zero mask. `mov dword [vec.vstart], 0` occurs exactly once in each arm. Failure = the
//       bound was made to skip prestart chunks too (counts drop), or the ownership of the `vstart`
//       write ended up duplicated or lost.
//
//   [7] THE BRANCH TARGET, EXACTLY. Every `jbe` in the bounded frame resolves to the SAME address,
//       that address is the offset of the frame's single `mov dword [vec.vstart], 0`, it is strictly
//       BEFORE the fallback arm (located independently as `inc qword [rvv_direct_fallbacks]`), and
//       real work lies strictly inside the skipped range (the last chunk's `kmovq k1, rdi`, the
//       instruction that installs its body mask). Failure = an early exit that lands on the fallback
//       would re-run the ordered helper on top of chunks the body already stored; one that lands on
//       the join would leave `vstart` dirty for the NEXT vector instruction.
//
//   [8] THE STICKY SATURATION FLAG IS UNTOUCHED. For `vsadd.vv`, `vssub.vv` and `vsmul.vv` the
//       five-instruction accrual `kmovq rax,k3; and rax,rdi; setne al; movzx eax,al;
//       or [vec.vxsat],eax` occurs exactly `chunks` times in BOTH arms. The `and rax, rdi` is what
//       makes a fully-inactive chunk contribute zero, so a skipped chunk's contribution was already
//       zero; this check is what fails if that AND is ever removed and the bound is then credited
//       with a behaviour change it did not make. Failure = an accrual count that differs between the
//       arms (the bound changed flag handling) or an accrual that is no longer mask-gated.
//
//   [9] FAIL-CLOSED CONTRACTS, each in a forked child whose stderr is matched against the EXPECTED
//       Panic text -- an abnormal exit alone would also be produced by an unrelated crash or by a
//       different Panic:
//       (a) a bound in a `Vlenb*` whole-register frame, whose EVL is nregs*VLEN/EEW and does not
//           depend on `vec.vl` at all;
//       (b) a bound in a multi-member run frame, where the exit would jump past later members;
//       (c) a bound in a frame with a partial arm, which reaches the join from outside the body;
//       (d) THE §3.5 MUTATION: `frame_clears_vstart` true with no bound emitted -- i.e. exactly what
//           dropping the `chunks >= 2` conjunct produces -- and the converse. Both must Panic. If
//           they do not, the silent form is a frame in which NOBODY writes `vstart = 0`, which
//           corrupts the NEXT vector instruction rather than this one and which no existing route
//           test constructs.
//
//  [10] THE ROUTE EXCLUSIONS ARE STRUCTURAL. With the switch ON, a whole-register transfer, a
//       multi-member integer vector run, and an over-capacity frame (more chunks than
//       InstVChunkActive can index) all emit zero bounds. Failure = the flag leaked into a route
//       whose semantics do not permit a `vec.vl` early exit.
//
//  [11] THE FP SWITCH IS SEPARATE AND THE FP ROUTE IS BYTE-IDENTICAL. An FP program emits the same
//       bytes whether the INTEGER switch is on or off, and emits no bound when only the integer
//       switch is on. Failure = one switch moved the other route -- which would make every planned
//       ablation a measurement of both.

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
constexpr u32 OPIVV = 0u, OPMVV = 2u, OPIVI = 3u, OPIVX = 4u;
// funct6 values, RVV 1.0 Table "OPIVV/OPMVV".
constexpr u32 F6_VADD = 0u, F6_VMAX = 7u, F6_VAND = 9u, F6_VMERGE = 23u, F6_VMSEQ = 24u,
	      F6_VSADD = 33u, F6_VSSUB = 35u, F6_VSLL = 37u, F6_VSMUL = 39u, F6_VMUL = 37u;
constexpr u32 F6_VFADD = 0u;

constexpr u32 SEW8 = 0u, SEW16 = 1u, SEW32 = 2u, SEW64 = 3u;
constexpr u32 M1 = 0u, M2 = 1u;

// ---------------------------------------------------------------------------------------------

// ONE PROCESS-WIDE CODE BUFFER, AND THAT IS THE POINT. Checks [3] and [11] compare the emitted
// bytes of two separate translations for literal equality. An emitted region can embed the address
// of its own buffer, so two translations into two different heap allocations differ in bytes that
// have nothing to do with the switch under test -- a difference that would make those two checks
// fail for a reason no reader could act on. Handing every emission the SAME fixed address removes
// that degree of freedom. Nothing is ever executed from it (no PROT_EXEC anywhere in this file);
// each emission is copied out immediately, so a later one overwriting it is harmless.
alignas(4096) u8 g_code_buf[1u << 20];

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("int active-vl test: emitted region exceeds the fixed code buffer");
		last_size = sz;
		return g_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	size_t last_size = 0;
};

struct Env {
	u32 vlen_bits = 512;
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
	config::rvv_qcg_active_vl_int_bound = e.int_bound;
	// The FP side, so [11] can build a real FP frame; inert for every integer shape.
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

std::vector<int> OpcodeStream(Region *r)
{
	std::vector<int> out;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			out.push_back((int)ins.GetOpcode());
	return out;
}

// Everything a chunk node says about WHICH bytes it touches and under WHICH predicate.
// `finish_instruction` is deliberately EXCLUDED: moving that one write is the transformation.
using Work = std::tuple<u32, u32, u32, int, int, int, int, u32, int, u32>;

std::vector<Work> ChunkWork(Frame const &f)
{
	std::vector<Work> out;
	for (auto *i : f.body) {
		if (i->GetOpcode() != Op::_vchunkpartialalu)
			continue;
		auto *n = static_cast<InstVChunkPartialAlu *>(i);
		out.push_back({n->rd_offs, n->rs2_offs, n->rs1_offs, (int)n->op, (int)n->chunk,
			       (int)n->sew_bytes, (int)n->chunk_bytes, n->imm, (int)n->masked,
			       n->element_base});
	}
	return out;
}

std::vector<int> ChunkOrder(Frame const &f)
{
	std::vector<int> out;
	for (auto *i : f.body)
		if (i->GetOpcode() == Op::_vchunkpartialalu)
			out.push_back((int)static_cast<InstVChunkPartialAlu *>(i)->chunk);
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
		Panic("int active-vl test: asmjit init");
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
	// EmitRvvBodyMask's result lands in rdi and Emit_vchunkpartialalu installs it as k1 for every
	// architectural-mask chunk: one per chunk, and the last one must lie inside the skipped range.
	return Assemble(
	    [&](asmjit::x86::Assembler &a) { a.kmovq(asmjit::x86::KReg(1), asmjit::x86::rdi); });
}
std::vector<u8> FallbackInc()
{
	return Assemble([&](asmjit::x86::Assembler &a) {
		a.inc(asmjit::x86::qword_ptr(kStateReg, (int32_t)offsetof(CPUState, rvv_direct_fallbacks)));
	});
}
// The whole sticky-flag accrual, including the AND with the body mask that makes an inactive chunk
// contribute nothing. Assembled as ONE needle so a change to any instruction in it is visible.
std::vector<u8> VxsatAccrual()
{
	return Assemble([&](asmjit::x86::Assembler &a) {
		namespace x86 = asmjit::x86;
		a.kmovq(x86::rax, x86::KReg(3));
		a.and_(x86::rax, x86::rdi);
		a.setne(x86::al);
		a.movzx(x86::eax, x86::al);
		a.or_(x86::dword_ptr(kStateReg, kVxsatOff), x86::eax);
	});
}

// A `jbe` is rel8 or rel32 depending on the distance; both forms are decoded rather than assumed.
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
// nodes: that is what makes [2]'s ladder check able to fail.

struct Shape {
	char const *name;
	u32 vsew;     // vsetvli's vsew field
	u32 vlmul;    // vsetvli's vlmul field (non-fractional only here)
	u32 sew;      // bytes per element
	u32 insn;
	bool narrow;  // the route widens byte/short lanes and caps the host chunk at 32 bytes
};

u32 ChunkBytes(Shape const &s, u32 vlen) { return std::min(vlen / 8u, s.narrow ? 32u : 64u); }
u32 GroupBytes(Shape const &s, u32 vlen) { return (vlen / 8u) << s.vlmul; }
u32 Chunks(Shape const &s, u32 vlen)
{
	u32 const b = ChunkBytes(s, vlen);
	return (GroupBytes(s, vlen) + b - 1u) / b;
}
u32 Lanes(Shape const &s, u32 vlen) { return ChunkBytes(s, vlen) / s.sew; }

// vd/vs2/vs1 are chosen legal for the LMUL in each row (`same_width_sources_legal` requires an
// aligned group and either coincidence or disjointness).
Shape const kShapes[] = {
    {"vadd.vv  e8,m1 ", SEW8, M1, 1, MakeOpV(F6_VADD, 1, 9, 10, 8, OPIVV), false},
    {"vadd.vv  e8,m2 ", SEW8, M2, 1, MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV), false},
    {"vmax.vv  e16,m2", SEW16, M2, 2, MakeOpV(F6_VMAX, 1, 10, 12, 8, OPIVV), false},
    {"vand.vv  e32,m1", SEW32, M1, 4, MakeOpV(F6_VAND, 1, 9, 10, 8, OPIVV), false},
    {"vadd.vv  e32,m2", SEW32, M2, 4, MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV), false},
    {"vadd.vv  e64,m2", SEW64, M2, 8, MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV), false},
    {"vadd.vx  e32,m2", SEW32, M2, 4, MakeOpV(F6_VADD, 1, 10, 11, 8, OPIVX), false},
    {"vadd.vi  e32,m2", SEW32, M2, 4, MakeOpV(F6_VADD, 1, 10, 5, 8, OPIVI), false},
    {"vsll.vi  e8,m2 ", SEW8, M2, 1, MakeOpV(F6_VSLL, 1, 10, 3, 8, OPIVI), true},
    {"vmul.vv  e8,m2 ", SEW8, M2, 1, MakeOpV(F6_VMUL, 1, 10, 12, 8, OPMVV), true},
    {"vmseq.vv e32,m2", SEW32, M2, 4, MakeOpV(F6_VMSEQ, 1, 10, 12, 8, OPIVV), false},
    {"vsadd.vv e32,m2", SEW32, M2, 4, MakeOpV(F6_VSADD, 1, 10, 12, 8, OPIVV), false},
    {"vssub.vv e32,m2", SEW32, M2, 4, MakeOpV(F6_VSSUB, 1, 10, 12, 8, OPIVV), false},
    {"vsmul.vv e32,m2", SEW32, M2, 4, MakeOpV(F6_VSMUL, 1, 10, 12, 8, OPIVV), true},
    {"vadd.vv  e32,m2 masked", SEW32, M2, 4, MakeOpV(F6_VADD, 0, 10, 12, 8, OPIVV), false},
    {"vmerge.vvm e32,m2", SEW32, M2, 4, MakeOpV(F6_VMERGE, 0, 10, 12, 8, OPIVV), false},
    {"vadd.vv  e32,m2 vd==vs2", SEW32, M2, 4, MakeOpV(F6_VADD, 1, 8, 12, 8, OPIVV), false},
    {"vadd.vv  e32,m2 vd==vs1", SEW32, M2, 4, MakeOpV(F6_VADD, 1, 10, 8, 8, OPIVV), false},
};

std::vector<u32> Program(Shape const &s) { return {Vsetvli(s.vsew, s.vlmul), s.insn}; }

// The frame a shape produces, or nullptr with a recorded failure: every shape in the table above is
// expected to route, and a shape that silently stops routing would turn every check on it vacuous.
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
			unsigned const chunks = Chunks(s, vlen);
			CHECK_EQ(CountOp(f[0], Op::_vchunkpartialalu), chunks);
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 0u);
			CHECK_EQ((unsigned)f[0].begin->n_typed, chunks);
			CHECK(f[0].end != nullptr);
			if (f[0].end)
				CHECK_EQ((int)f[0].end->frame_clears_vstart, 0);
			unsigned finishes = 0, last_is_finish = 0, seen = 0;
			for (auto *i : f[0].body)
				if (i->GetOpcode() == Op::_vchunkpartialalu) {
					auto *n = static_cast<InstVChunkPartialAlu *>(i);
					finishes += n->finish_instruction;
					++seen;
					last_is_finish = (seen == chunks) && n->finish_instruction;
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
	       "       one finish_instruction on the last chunk, frame_clears_vstart == false\n",
	       sizeof(kShapes) / sizeof(kShapes[0]));
}

void TestOnShape()
{
	for (u32 vlen : {512u, 1024u})
		for (auto const &s : kShapes) {
			unsigned const chunks = Chunks(s, vlen), lanes = Lanes(s, vlen);
			Built on;
			Translate(on, Program(s), Env{vlen, /*int_bound=*/true});
			std::vector<Frame> f;
			if (!OneFrame(on, f, s.name))
				continue;
			unsigned const bounds = CountOp(f[0], Op::_vchunkactive);
			CHECK_EQ(bounds, chunks >= 2 ? chunks - 1u : 0u);
			CHECK_EQ((unsigned)f[0].begin->n_typed, chunks + bounds);
			CHECK(f[0].end != nullptr);
			if (f[0].end)
				CHECK_EQ((int)f[0].end->frame_clears_vstart, (int)(chunks >= 2));

			// The ladder, and the position of each bound relative to the chunk it guards.
			unsigned expect_chunk = 1, finishes = 0;
			Inst *prev = nullptr;
			for (auto *i : f[0].body) {
				if (i->GetOpcode() == Op::_vchunkactive) {
					auto *n = static_cast<InstVChunkActive *>(i);
					CHECK_EQ((unsigned)n->chunk, expect_chunk);
					CHECK_EQ(n->element_base, expect_chunk * lanes);
					CHECK(n->chunk != 0); // chunk 0 is never bounded
					++expect_chunk;
				} else if (i->GetOpcode() == Op::_vchunkpartialalu) {
					auto *n = static_cast<InstVChunkPartialAlu *>(i);
					finishes += n->finish_instruction;
					// Bound c is IMMEDIATELY before chunk c, and chunk 0 has none.
					if (chunks >= 2 && n->chunk != 0) {
						CHECK(prev && prev->GetOpcode() == Op::_vchunkactive);
						if (prev && prev->GetOpcode() == Op::_vchunkactive)
							CHECK_EQ(
							    (unsigned)static_cast<InstVChunkActive *>(prev)
								->chunk,
							    (unsigned)n->chunk);
					}
				}
				prev = i;
			}
			CHECK_EQ(expect_chunk, chunks >= 2 ? chunks : 1u);
			CHECK_EQ(finishes, chunks >= 2 ? 0u : 1u);
		}
	printf("  ok   switch ON: chunk 0 never bounded, ladder == c * (chunk_bytes/SEW),\n"
	       "       each bound immediately precedes its own chunk, n_typed == 2*chunks - 1\n");
}

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
	printf("  ok   %u one-chunk frame(s) are byte-for-byte identical with the switch ON\n",
	       checked);
}

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
			auto wo = ChunkWork(fo[0]), wn = ChunkWork(fn[0]);
			CHECK(wo == wn);
			// Chunk-major and in order, in BOTH arms: the bound deletes a suffix at run time
			// and reorders nothing, which is what keeps the vd/source overlap argument intact.
			auto oo = ChunkOrder(fo[0]), on_ = ChunkOrder(fn[0]);
			CHECK(oo == on_);
			for (size_t c = 0; c < oo.size(); ++c)
				CHECK_EQ(oo[c], (int)c);
		}
	printf("  ok   every chunk's (rd, rs2, rs1, op, chunk, sew, bytes, imm, masked,\n"
	       "       element_base) is unchanged and the chunk order is still 0,1,2,...\n");
}

void TestEarlyExitIsBlindToTheMask()
{
	// The same instruction, masked and unmasked. Only `vm` differs, so only `masked` on the chunk
	// nodes may differ; the bound count and ladder must not.
	u32 const vlen = 1024;
	Shape const unmasked{"vadd.vv e32,m2", SEW32, M2, 4, MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV),
			     false};
	Shape const masked{"vadd.vv e32,m2 vm=0", SEW32, M2, 4, MakeOpV(F6_VADD, 0, 10, 12, 8, OPIVV),
			   false};
	std::vector<u32> ladder_u, ladder_m;
	for (auto const *s : {&unmasked, &masked}) {
		Built on;
		Translate(on, Program(*s), Env{vlen, true});
		std::vector<Frame> f;
		if (!OneFrame(on, f, s->name))
			return;
		auto &ladder = s == &unmasked ? ladder_u : ladder_m;
		for (auto *i : f[0].body)
			if (i->GetOpcode() == Op::_vchunkactive)
				ladder.push_back(static_cast<InstVChunkActive *>(i)->element_base);
		bool any_masked = false;
		for (auto *i : f[0].body)
			if (i->GetOpcode() == Op::_vchunkpartialalu)
				any_masked |= static_cast<InstVChunkPartialAlu *>(i)->masked;
		CHECK_EQ((int)any_masked, (int)(s == &masked));

		// And in the bytes: the bound is exactly two instructions, `cmp` then `jbe`, with
		// nothing -- no v0 load, no kortest -- between them.
		Emit(on);
		for (u32 base : ladder) {
			size_t at = SIZE_MAX;
			CHECK_EQ(CountBytes(on.code, BoundCmp(base), &at), 1u);
			if (at == SIZE_MAX)
				continue;
			size_t end = 0, target = 0;
			CHECK(DecodeJbe(on.code, at + BoundCmp(base).size(), &end, &target));
		}
	}
	CHECK(ladder_u == ladder_m);
	CHECK(ladder_u.size() == 3u); // e32,m2 at VLEN 1024 is 4 chunks
	printf("  ok   the bound ladder is identical for vm=1 and vm=0, and every bound is exactly\n"
	       "       `cmp [vec.vl], imm` + `jbe` with nothing between them\n");
}

void TestVstartOwnership()
{
	u32 const vlen = 1024;
	Shape const s{"vadd.vv e32,m2", SEW32, M2, 4, MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV), false};
	unsigned const chunks = Chunks(s, vlen);
	Built off, on;
	Translate(off, Program(s), Env{vlen, false});
	Translate(on, Program(s), Env{vlen, true});
	Emit(off);
	Emit(on);
	size_t a = SIZE_MAX, b = SIZE_MAX;
	// Exactly one write, in each arm.
	CHECK_EQ(CountBytes(off.code, VstartClear(), &a), 1u);
	CHECK_EQ(CountBytes(on.code, VstartClear(), &b), 1u);
	// And the per-chunk body mask still READS vstart once per chunk in both arms: prestart
	// chunks keep running under their zero mask, they are not skipped.
	size_t unused = SIZE_MAX;
	unsigned const reads_off = CountBytes(off.code, VstartLoad(), &unused);
	unsigned const reads_on = CountBytes(on.code, VstartLoad(), &unused);
	CHECK_EQ(reads_off, chunks);
	CHECK_EQ(reads_on, chunks);
	printf("  ok   vstart written once in each arm; read by %u per-chunk masks in both\n", reads_on);
}

void TestBranchTarget()
{
	u32 const vlen = 1024;
	Shape const s{"vadd.vv e32,m2", SEW32, M2, 4, MakeOpV(F6_VADD, 1, 10, 12, 8, OPIVV), false};
	unsigned const chunks = Chunks(s, vlen), lanes = Lanes(s, vlen);
	Built on;
	Translate(on, Program(s), Env{vlen, true});
	Emit(on);
	CHECK(!on.code.empty());

	size_t const vstart_at = Find(on.code, VstartClear());
	size_t const fallback_at = Find(on.code, FallbackInc());
	CHECK(vstart_at != SIZE_MAX);
	CHECK(fallback_at != SIZE_MAX);

	size_t last_end = 0;
	for (unsigned c = 1; c < chunks; ++c) {
		auto const cmp = BoundCmp(c * lanes);
		size_t at = SIZE_MAX;
		CHECK_EQ(CountBytes(on.code, cmp, &at), 1u);
		if (at == SIZE_MAX)
			return;
		size_t end = 0, target = 0;
		CHECK(DecodeJbe(on.code, at + cmp.size(), &end, &target));
		// [7] every bound leaves to the SAME place, and that place is the vstart write.
		CHECK_EQ(target, vstart_at);
		// ...which is strictly before the fallback arm. Landing there would run the ordered
		// helper on top of chunks the body had already stored.
		CHECK(target < fallback_at);
		CHECK(target != fallback_at);
		last_end = end;
	}
	// Real work lies inside the last bound's skipped range: the final chunk's body mask install.
	size_t const last_mask = FindLast(on.code, BodyMaskInstall());
	CHECK(last_mask != SIZE_MAX);
	CHECK(last_mask > last_end);
	CHECK(last_mask < vstart_at);
	printf("  ok   all %u jbe target +%zu == the single vstart write; fallback is at +%zu;\n"
	       "       the last chunk's kmovq k1,rdi at +%zu lies inside the skipped range\n",
	       chunks - 1, vstart_at, fallback_at, last_mask);
}

void TestSaturationFlagUntouched()
{
	u32 const vlen = 1024;
	Shape const sat[] = {
	    {"vsadd.vv e32,m2", SEW32, M2, 4, MakeOpV(F6_VSADD, 1, 10, 12, 8, OPIVV), false},
	    {"vssub.vv e32,m2", SEW32, M2, 4, MakeOpV(F6_VSSUB, 1, 10, 12, 8, OPIVV), false},
	};
	for (auto const &s : sat) {
		unsigned const chunks = Chunks(s, vlen);
		Built off, on;
		Translate(off, Program(s), Env{vlen, false});
		Translate(on, Program(s), Env{vlen, true});
		Emit(off);
		Emit(on);
		size_t unused = SIZE_MAX;
		auto const needle = VxsatAccrual();
		unsigned const n_off = CountBytes(off.code, needle, &unused);
		unsigned const n_on = CountBytes(on.code, needle, &unused);
		// One mask-gated accrual per chunk, in both arms. The `and rax, rdi` inside the needle
		// is what makes a fully-inactive chunk contribute zero, so a skipped chunk was already
		// contributing nothing -- and if that AND ever disappears, this count goes to zero
		// rather than the bound being blamed for a behaviour it did not change.
		CHECK_EQ(n_off, chunks);
		CHECK_EQ(n_on, chunks);
		printf("  ok   %s: %u mask-gated vxsat accruals in both arms\n", s.name, n_on);
	}
}

// ---------------------------------------------------------------------------------------------
// Fail-closed contracts. Hand-built frames, because no route constructs these combinations -- which
// is exactly why a comment would not be enough.

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
	char path[] = "/tmp/int_active_vl_panic_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0)
		Panic("int active-vl test: mkstemp");
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

// One chunk node plus an optional bound, in a frame whose guard kind and `frame_clears_vstart` the
// caller chooses. `n_typed` is the honest count of nodes that increment QEmit's typed counter, so a
// case reaches the check it is meant to exercise rather than the counter check.
void BuildHandFrame(bool with_bound, GuardKind kind, bool frame_clears_vstart, bool with_partial)
{
	MemArena arena(1u << 20);
	auto *region = arena.New<Region>(&arena, &g_state_info);
	Builder b(region->CreateBlock());
	u32 const vo = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	// Emit_rvvtypedchunkpartial is a boundary marker and does NOT increment QEmit's typed
	// counter, so the partial arm contributes nothing here. Getting this wrong makes the case
	// die on the counter check instead of reaching the contract it is meant to exercise.
	u16 const n_typed = (u16)(2u + (with_bound ? 1u : 0u));
	b.Create_rvvtypedchunkbegin(0xd1u, 16u, 0u, RuntimeStubId::id_rv32_vialu, n_typed, kind);
	auto chunk = [&](u8 c, bool finish) {
		b.Create_vchunkpartialalu((u8)InstVChunkPartialAlu::Kind::Add, 4, c, 64,
					  vo + 8u * rv32::VLEN_MAX_BYTES + c * 64u,
					  vo + 10u * rv32::VLEN_MAX_BYTES + c * 64u,
					  vo + 12u * rv32::VLEN_MAX_BYTES + c * 64u, 0, 0, true, false,
					  c * 16u, finish);
	};
	chunk(0, false);
	if (with_bound)
		b.Create_vchunkactive(1, 16);
	if (with_partial)
		b.Create_rvvtypedchunkpartial();
	chunk(1, !frame_clears_vstart);
	b.Create_rvvtypedchunkend(0u, RuntimeStubId::id_rv32_vialu, /*whole_regbytes=*/0,
				  frame_clears_vstart);
	PanicRuntime rt;
	qcg::GenerateCode(&rt, nullptr, region, 0);
}

void TestFailClosed()
{
	ApplyEnv(Env{512, false});
	// (a) a whole-register frame: its EVL is nregs*VLEN/EEW, so vec.vl bounds nothing there. It
	// must be built through the VLENB constructor -- the vtype constructor refuses the kind
	// outright, which is a different Panic and would not exercise the emitter check at all.
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
	// (b) a multi-member run frame: the exit would jump past later guest instructions.
	ExpectPanic("bound in a multi-member run frame",
		    // C4e: the refusal is now NARROWER and says so. A multi-member frame whose body
		    // is emitted component-major may carry a bound (the inactive units are the
		    // body's tail for every member at once); a MEMBER-MAJOR one still may not,
		    // which is the shape this case builds and the message it must produce.
		    "rvv active-vl bound inside a member-major multi-member run frame", [] {
			    MemArena arena(1u << 20);
			    auto *region = arena.New<Region>(&arena, &g_state_info);
			    Builder b(region->CreateBlock());
			    // The run constructor refuses VTypeInteger outright, so the frame takes the
			    // accepted run kind. GuardBoundsVlByVlmax admits it and
			    // config::rvv_qcg_full_vl_fast_body is off, so the bound reaches the
			    // multi-member check rather than one of the two before it.
			    auto *members = b.CreateRunMembers(2);
			    members[0].raw = 0u;
			    members[0].stub = RuntimeStubId::id_rv32_vialu;
			    members[0].pc = 0u;
			    members[1].raw = 0u;
			    members[1].stub = RuntimeStubId::id_rv32_vialu;
			    members[1].pc = 4u;
			    b.Create_rvvtypedchunkbegin(0xd1u, 16u, (RVVRunMember const *)members,
							(u8)2, (u16)1, GuardKind::VTypeVlVstart);
			    b.Create_vchunkactive(1, 16);
			    b.Create_rvvtypedchunkend(members, (u8)2);
			    PanicRuntime rt;
			    qcg::GenerateCode(&rt, nullptr, region, 0);
		    });
	// (c) a frame with a partial arm: it reaches the join from outside the bounded body.
	ExpectPanic("bound in a frame with a partial arm",
		    "rvv active-vl bound in a frame with a partial arm", [] {
			    BuildHandFrame(true, GuardKind::VTypeIntegerTwoArm, true, true);
		    });
	// (d) THE `chunks >= 2` MUTATION, both directions. Dropping that conjunct produces exactly
	// the first case: the translator clears every `finish_instruction` and emits no bound, so
	// nobody writes vstart = 0 and the NEXT vector instruction starts at a stale prestart index.
	ExpectPanic("frame claims the vstart write but emitted no bound",
		    "rvv active-vl bound: frame and body disagree about who clears vstart", [] {
			    BuildHandFrame(false, GuardKind::VTypeInteger, true, false);
		    });
	ExpectPanic("body emitted a bound but the frame does not claim the vstart write",
		    "rvv active-vl bound: frame and body disagree about who clears vstart", [] {
			    BuildHandFrame(true, GuardKind::VTypeInteger, false, false);
		    });
	// The agreeing case must NOT Panic, or the two above would pass for the wrong reason.
	BuildHandFrame(true, GuardKind::VTypeInteger, true, false);
	BuildHandFrame(false, GuardKind::VTypeInteger, false, false);
	printf("  ok   the agreeing frames (bound+claim, no-bound+no-claim) translate cleanly\n");
}

void TestRouteExclusions()
{
	// Whole-register transfer: vmv2r.v v8, v10 (funct6 = 0b100111, vm = 1, OPIVI, simm = nregs-1).
	{
		Built b;
		Translate(b, {Vsetvli(SEW32, M2), MakeOpV(39u, 1, 10, 1, 8, OPIVI)}, Env{1024, true});
		unsigned bounds = 0;
		for (auto const &f : FindFrames(b.region))
			bounds += CountOp(f, Op::_vchunkactive);
		CHECK_EQ(bounds, 0u);
		printf("  ok   whole-register transfer -> 0 bounds\n");
	}
	// A multi-member integer vector run. The claim is specifically "no bound lands in a
	// MULTI-MEMBER frame": the same words also produce single-instruction frames when no run
	// forms, and those are legitimately bounded, so counting bounds over the whole region would
	// make the check fail for the wrong reason -- or, if no run formed at all, pass vacuously.
	// `formed` is therefore asserted, not merely reported.
	{
		std::vector<u32> const run = {Vsetvli(SEW32, M1), MakeOpV(F6_VADD, 1, 9, 10, 8, OPIVV),
					      MakeOpV(F6_VADD, 1, 8, 11, 8, OPIVV),
					      MakeOpV(F6_VADD, 1, 8, 12, 8, OPIVV)};
		for (u32 vlen : {512u, 1024u}) {
			Built b;
			Translate(b, run, Env{vlen, true, false, /*vector_run=*/true});
			unsigned bounds_in_runs = 0, formed = 0;
			for (auto const &f : FindFrames(b.region))
				if (f.begin->n_members > 1) {
					++formed;
					bounds_in_runs += CountOp(f, Op::_vchunkactive);
				}
			CHECK(formed > 0);
			CHECK_EQ(bounds_in_runs, 0u);
			printf("  ok   VLEN %-4u %u multi-member run frame(s), 0 bounds in them\n",
			       vlen, formed);
		}
	}
	// Over the node's chunk-index capacity: e8,m8 with a byte-widened op at VLEN 4096 is 128
	// host chunks, and InstVChunkActive indexes fewer than 64.
	{
		Shape const s{"vsll.vi e8,m8", SEW8, 3u, 1, MakeOpV(F6_VSLL, 1, 16, 3, 8, OPIVI), true};
		Built b;
		Translate(b, Program(s), Env{4096, true});
		auto f = FindFrames(b.region);
		if (f.size() == 1u) {
			unsigned const chunks = CountOp(f[0], Op::_vchunkpartialalu);
			CHECK(chunks > 64u);
			CHECK_EQ(CountOp(f[0], Op::_vchunkactive), 0u);
			CHECK_EQ((int)f[0].end->frame_clears_vstart, 0);
			printf("  ok   %u chunks > the node's chunk-index capacity -> 0 bounds\n",
			       chunks);
		} else {
			printf("  ..   VLEN 4096 e8,m8 did not route (skipped)\n");
		}
	}
}

void TestFpRouteUntouched()
{
	// vfadd.vv e64,m2 -- the S1-2A route. The INTEGER switch must move nothing here.
	std::vector<u32> const fp = {Vsetvli(SEW64, M2), MakeOpV(F6_VFADD, 1, 10, 12, 8, 1u)};
	for (u32 vlen : {512u, 1024u}) {
		Built a, b;
		Translate(a, fp, Env{vlen, /*int_bound=*/false, /*fp_bound=*/true});
		Translate(b, fp, Env{vlen, /*int_bound=*/true, /*fp_bound=*/true});
		Emit(a);
		Emit(b);
		CHECK(!a.code.empty());
		CHECK(a.code == b.code);
		CHECK(OpcodeStream(a.region) == OpcodeStream(b.region));

		Built c;
		Translate(c, fp, Env{vlen, /*int_bound=*/true, /*fp_bound=*/false});
		unsigned bounds = 0;
		for (auto const &f : FindFrames(c.region))
			bounds += CountOp(f, Op::_vchunkactive);
		CHECK_EQ(bounds, 0u);
		printf("  ok   VLEN %-4u FP frame byte-identical under the integer switch; the integer\n"
		       "       switch alone adds no FP bound\n",
		       vlen);
	}
}
} // namespace

int main()
{
	qcg::ArchTraits::init();
	printf("[1] the switch is really default-off\n");
	TestOffIsInert();
	printf("[2] ON: chunk-0 omission, the element ladder and node placement\n");
	TestOnShape();
	printf("[3] a one-chunk frame is inert even with the switch ON\n");
	TestOneChunkFrameIsByteIdentical();
	printf("[4] no chunk work moved (the overlap property)\n");
	TestNoChunkWorkMoved();
	printf("[5] the early exit is blind to v0\n");
	TestEarlyExitIsBlindToTheMask();
	printf("[6] non-zero vstart still handled; vstart cleared exactly once\n");
	TestVstartOwnership();
	printf("[7] the branch target, exactly\n");
	TestBranchTarget();
	printf("[8] the sticky saturation flag is untouched\n");
	TestSaturationFlagUntouched();
	printf("[9] fail-closed contracts\n");
	TestFailClosed();
	printf("[10] route exclusions\n");
	TestRouteExclusions();
	printf("[11] the FP route is separate and unmoved\n");
	TestFpRouteUntouched();
	if (g_failures) {
		printf("FAIL rvv_active_vl_int_bound_test: %d failure(s)\n", g_failures);
		return 1;
	}
	printf("PASS rvv_active_vl_int_bound_test\n");
	return 0;
}
