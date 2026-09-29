// P2a: the focused test for --rvv-qcg-active-chunk-census.
//
// WHAT THIS FILE OWNS, and only this. That the two P2a counters mean what the report says they
// mean, that their population is the common finalizer's planner-eligible frames and nothing else,
// and that arming them is the ONLY thing that changes. It owns no admission claim, no lowering
// claim and no policy claim: the active-VL bound itself is owned by rvv_active_vl_int_bound_test /
// rvv_active_vl_bound_test / rvv_active_vl_widen_bound_test and the frame classification by
// rvv_frame_finalizer_test. This file adds a counter on top of those and checks the counter.
//
// -------------------------------------------------------------------------------------------
// WHAT THIS HOST CAN AND CANNOT OBSERVE -- READ THIS BEFORE CITING A RESULT.
//
// The frames under test are AVX-512 bodies. The Ivy Bridge i7-3770 development workstation has no
// AVX-512 and no BMI2, and the qemu-x86_64 available there (6.2) has no AVX in TCG at all, so the
// emitted body cannot be EXECUTED on it by any route; P2b runs this file on xbd (Ryzen 9 9950X3D)
// for exactly that reason. Section [A] is therefore the section that runs
// on this host, and it is an EMITTED-ARTIFACT section: it reads the counter sites, their immediates
// and the bound ladder out of the bytes and out of the QIR, and derives the exact counter values
// each (VLEN, policy, vl) cell must produce. Section [B] EXECUTES the same frames and asserts the
// counters the hardware actually produced plus the architectural result against the reference
// oracle; it reports itself SKIPPED unless the host has AVX-512F and BMI2, and on a host where it
// is skipped NOTHING in it has been exercised.
//
// -------------------------------------------------------------------------------------------
// [A] EMITTED ARTIFACT. Runs on every host.
//
//   A1  DEFAULT-OFF INERTNESS. With the census switch clear, neither counter's address appears in
//       the emitted bytes, at either VLEN, with the active-VL policies on or off.
//       Failure path: the adds were placed outside the switch, so every timed arm pays for them.
//
//   A2  ARMING ADDS THE CENSUS INSTRUCTIONS AND NOTHING ELSE. The armed stream with every census
//       site DELETED is byte-identical to the unarmed stream.
//       Failure path: the diagnostic perturbed a guard, a body node, a branch displacement or the
//       fallback arm. THIS IS ALSO THE HOST-INDEPENDENT FORM OF "THE ARCHITECTURAL OUTPUT DID NOT
//       CHANGE": every byte that is not a census instruction is the same byte, and a census
//       instruction writes only rax, the flags and one .bss word -- none of which is architectural
//       guest state, and none of which is live across a work-unit boundary or across the join.
//
//   A3  EXACTLY ONE AVAILABLE SITE PER FRAME, AND ITS IMMEDIATE IS THE UNIT COUNT. Read back out of
//       the emitted `add qword [rax], imm8`, compared against the unit count this file derives from
//       the SHAPE (VLEN, SEW, LMUL, host chunk width) and not from the node.
//       Failure path: an available count emitted per unit instead of per execution (it would be a
//       plain `inc` repeated), or a unit count taken from something other than the frame geometry.
//
//   A4  THE EXECUTED SITES ARE THE PREFIX ADD PLUS ONE PER BOUND. The join carries one
//       `add qword [rax], prefix` when the prefix is non-empty and NOTHING when it is empty, and
//       there are exactly as many `inc` sites as the frame has `vchunkactive` nodes.
//       Failure path: a prefix credited twice, or a bound whose fall-through is not counted -- both
//       of which would make the executed count a number with no definition.
//
//   A5  EVERY CENSUS SITE IS ON THE NATIVE ARM. Every site's offset is strictly BEFORE the frame's
//       `inc qword [R_STATE + rvv_direct_fallbacks]`, which is the first instruction of the
//       guard-miss arm and is located independently by its own encoding.
//       Failure path: a helper execution credited with host work units it never performed -- the
//       single error that would make the ratio meaningless rather than merely wrong.
//
//   A6  THE POLICY-OFF INVARIANT, STRUCTURALLY. With the policies off the frame carries no bound,
//       so `census_prefix_units == census_units` on the end node and the emitted executed site is
//       an add of the SAME immediate as the available site. executed == available on every
//       execution, at any vl, by construction rather than by a run.
//       Failure path: a prefix that is not the whole frame when nothing is bounded, which would
//       report skipped work in an arm that skips none.
//
//   A7  EXACT COUNTERS OVER A vl TABLE, DERIVED FROM THE EMITTED LADDER. For vl in {0, 1, one
//       unit, a partial vl, full vl - 1, full vl} the executed count implied by the frame's own
//       bound ladder (`vl <= element_base` exits) is compared against an expectation computed in
//       this file from the shape alone. Includes the FIRST INACTIVE UNIT cell, where vl lands
//       exactly on a unit's element base and that unit must NOT be counted.
//       Failure path: an off-by-one in which unit a bound guards, or a prefix that is not the
//       always-executed set.
//
//   A8  INELIGIBLE FRAMES CONTRIBUTE NOTHING. A vector run (multi-member), a whole-register
//       transfer and a vector memory frame carry `census_units == 0` on the end node and emit no
//       census site at all, armed.
//       Failure path: the census acquiring a population the finalizer never classified -- which is
//       exactly the "second eligibility classifier" this checkpoint must not create.
//
// -------------------------------------------------------------------------------------------
// [B] EXECUTION. SKIPPED unless the host has AVX-512F and BMI2 (P2b runs it on xbd).
//
//   B0  WHICH ARM RAN, asserted first, from `CPUState::rvv_direct_fallbacks`. Every cell states in
//       advance -- from the ISA rule in `ExpectHelper`, not from the measurement -- whether the
//       frame takes its native body or the helper, and a disagreement fails. Without this a frame
//       that silently fell back would report `available == 0` and be indistinguishable from a
//       counter that simply never fired.
//       (The one ISA-mandated helper cell is the FP frame at `vl == 0`: RVV 1.0 forbids updating
//       any destination element there, so `Emit_rvvtypedchunkbegin` sends it to the helper.)
//   B1  THE EXACT COUNTERS the emitted code actually produced, per (shape, VLEN, policy, vl) cell,
//       against the expectation this file computes from the SHAPE -- never from the node, the
//       ladder or the run. A helper cell must credit 0 and 0.
//   B2  (i) arming the census perturbs no bit of architectural vector state (armed vs unarmed, bit
//       for bit); (ii) the ACTIVE elements [0, vl) equal the existing reference lowering
//       (`rvv_ref::vialu` / `rvv_ref::vfalu`). The first mismatching element is printed with both
//       values rather than summarised.
//   B3  with the census off both counters stay 0 whatever executed.
//   B4  THE GUARD-FALLBACK NEGATIVE CONTROL, executed rather than argued: a frame compiled for one
//       vtype is run under a different, equally legal one, so the guard misses and the ordered
//       helper performs the whole instruction. `rvv_direct_fallbacks` must be 1 (the control really
//       fired), both counters must be 0 with the census ARMED, and the helper's own result must
//       still match the oracle under the vtype it actually saw.

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

// P2c NON-VACUITY ACCOUNTING. A post-state oracle that compared nothing would pass just as quietly
// as one that compared everything, so every category counts the elements it actually constrained
// and main() refuses a run in which any of them is empty.
struct Coverage {
	unsigned long long vl0_elems = 0;	// elements constrained by the `vl == 0` no-update rule
	unsigned long long tail_tu_elems = 0;	// tail elements constrained by vta = 0
	unsigned long long inactive_mu_elems = 0; // inactive body elements constrained by vma = 0
	unsigned long long prestart_elems = 0;	// prestart elements
	unsigned long long active_elems = 0;	// active body elements
	unsigned long long tail_skipped = 0;	// tail elements NOT compared (vta = 1)
	unsigned long long fflags_nonzero = 0;	// cells whose oracle accrued a non-zero fflags
	unsigned long long cells = 0;
};
Coverage g_cov;

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

// ---------------------------------------------------------------------------------------------
// Guest encodings, built from the field layout rather than copied as magic words.
// vtype bit layout (RVV 1.0 v-spec 3.4): vma = bit 7, vta = bit 6, vsew = bits 5:3, vlmul = 2:0.
// `vta = 0` is the TAIL-UNDISTURBED policy, under which every tail element is ISA-CONSTRAINED to
// keep its prior value -- which is what makes an illegal destination write observable at all.
constexpr u32 VTypeOf(u32 vsew, u32 vlmul, u32 vta, u32 vma = 1u)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
constexpr u32 Vsetvli(u32 vsew, u32 vlmul, u32 vta = 1u, u32 vma = 1u)
{
	return (VTypeOf(vsew, vlmul, vta, vma) << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u;
}
// `csrrw x0, vstart, a1` -- the ONLY way to present a non-zero `vstart` to the frame under test.
// The region's leading `vsetvli` resets vstart (rv32_interp.cpp: "Configuration instructions reset
// vstart"), so a preset value cannot survive it; this writes vstart AFTER it. `vstart` is a writable
// vector CSR (rv32_interp.cpp `rvv_csr_writable`), the translator lowers `csrrw` as a plain helper
// and does NOT discard the block's observed vtype, and the FP frame's `VTypePartialVlVstartFrmHost`
// guard deliberately does not test vstart -- so the value reaches the native body, which derives its
// prestart mask from it.
constexpr u32 CsrwVstartA1() { return (0x008u << 20) | (11u << 15) | (1u << 12) | (0u << 7) | 0x73u; }
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 f3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 OPIVV = 0u, OPFVV = 1u;
constexpr u32 F6_VADD = 0u, F6_VFADD = 0u;
constexpr u32 SEW32 = 2u;
constexpr u32 M2 = 1u;

// Whole-register load `vl2re32.v v8, (x16)`: nf-1 = 1, mop = 0, vm = 1, lumop = 8, width = 6.
constexpr u32 Vl2re32() { return (1u << 29) | (1u << 25) | (8u << 20) | (16u << 15) | (6u << 12) | (8u << 7) | 0x07u; }
// Unit-stride load `vle32.v v8, (x16)`.
constexpr u32 Vle32() { return (1u << 25) | (0u << 20) | (16u << 15) | (6u << 12) | (8u << 7) | 0x07u; }

// ONE PROCESS-WIDE CODE BUFFER, for the reason rvv_active_vl_int_bound_test states: an emitted
// region can embed the address of its own buffer, and A2 compares two translations byte for byte.
alignas(4096) u8 g_code_buf[1u << 20];

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("p2a census test: emitted region exceeds the fixed code buffer");
		memset(g_code_buf, 0, sz);
		return g_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};

struct Env {
	u32 vlen_bits = 512;
	bool policy = false;  // all three active-VL policies together
	bool census = false;
	bool vector_run = false;
	bool memory_routes = false;
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
	config::rvv_run_frame_census = false;
	// The routes under test, plus the audit-only host-feature bypass: section [A] never branches
	// into the bytes it builds, and section [B] refuses to run without the real host features.
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_fma_force_emit = true;
	config::rvv_qcg_fp_shared_mask = true;
	config::rvv_qcg_narrow_chunk_width = false;
	config::rvv_qcg_narrow_chunk_width_force_emit = false;
	// The three active-suffix policies, moved together: this file is not an ablation.
	config::rvv_qcg_active_vl_int_bound = e.policy;
	config::rvv_qcg_active_vl_bound = e.policy;
	config::rvv_qcg_active_vl_widen_bound = e.policy;
	config::rvv_qcg_active_vl_narrow_bound = e.policy;
	// THE SWITCH UNDER TEST.
	config::rvv_qcg_active_chunk_census = e.census;
	// The ineligible-frame routes A8 needs, off otherwise so nothing else can move.
	config::rvv_qcg_whole_reg = e.memory_routes;
	config::rvv_qcg_whole_reg_force_emit = e.memory_routes;
	config::rvv_qcg_typed_chunk_vle = e.memory_routes;
	config::rvv_qcg_typed_chunk_vle_force_emit = e.memory_routes;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_typed_chunk_shift = false;
	config::rvv_qcg_typed_chunk_vse = false;
	config::rvv_qcg_typed_chunk_vmv = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_qcg_full_vl_fast_body = false;
	config::rvv_qcg_typed_chunk_vlse_gather_census = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
	config::rvv_lowering = 1;
	// NOT A ROUTE SETTING, AND THE ONE THING SECTION [B] CANNOT RUN WITHOUT. `config::trace`
	// defaults to TRUE (config.h), and with it on `Emit_Cache` appends
	// `movabs rax, qcgstub_trace_cache; call rax` to the region, whose helper walks a
	// CPUState-owned `ip2ip_counts` map this harness never populates -- on a real execution that
	// is a SIGFPE in `DumpTraceCache`, which is exactly how section [B] first died on xbd. It is a
	// diagnostic tracer, not part of any route under test, and turning it off removes a runtime
	// dependency from the emitted region rather than changing what the region computes. Section
	// [A] is unaffected in substance: every one of its checks compares two builds made with this
	// same env, so only the absolute byte counts it prints move.
	config::trace = false;
}

struct Built {
	MemArena arena{1u << 21};
	std::vector<u32> words;
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
};

void Build(Built &b, std::vector<u32> const &words, Env const &e)
{
	ApplyEnv(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
	// The returned span is padded to an alignment boundary and the buffer was zeroed before
	// emission, so the tail is padding whose LENGTH depends on the body size. Trim it, exactly as
	// rvv_p1c_freeze_test does, or A2's byte comparison would be comparing padding.
	while (!b.code.empty() && b.code.back() == 0)
		b.code.pop_back();
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<u32> bound_bases; // every InstVChunkActive's element_base, in emission order
	unsigned falu_nodes = 0;      // how many _vchunkfalu anchors the body carries
};

std::vector<Frame> FindFrames(Region *region)
{
	std::vector<Frame> out;
	Frame cur;
	bool open = false;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_rvvtypedchunkbegin) {
				cur = Frame{};
				cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
			} else if (ins.GetOpcode() == Op::_rvvtypedchunkend) {
				if (open) {
					cur.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
					out.push_back(cur);
					open = false;
				}
			} else if (open && ins.GetOpcode() == Op::_vchunkactive) {
				cur.bound_bases.push_back(
				    static_cast<InstVChunkActive *>(&ins)->element_base);
			} else if (open && ins.GetOpcode() == Op::_vchunkfalu) {
				++cur.falu_nodes;
			}
		}
	return out;
}

// ---------------------------------------------------------------------------------------------
// Finding a census site in the emitted bytes, derived rather than pasted.
//
// The emitted form is `mov rax, <absolute address of the counter>` followed by either
// `inc qword ptr [rax]` (REX.W FF /0, mod=00 rm=000 -> 48 FF 00) or `add qword ptr [rax], imm8`
// (REX.W 83 /0 -> 48 83 00 imm8). asmjit picks `movabs rax, imm64` (48 B8 + 8) when the address
// does not fit in an unsigned 32-bit immediate and the short `mov eax, imm32` (B8 + 4) when it
// does, which depends on where the loader put .bss -- so both forms are accepted, as the Z4B
// gather-census test already does for the same two counters' shape.
//
// REQUIRING THE INCREMENT TO FOLLOW THE ADDRESS IS THE POINT: matching the address alone would also
// match a stray constant, whereas this matches an actual advance of that specific counter.
// ---------------------------------------------------------------------------------------------
struct Site {
	size_t offset = 0;  // where the `mov` starts
	size_t length = 0;  // bytes the whole two-instruction sequence occupies
	long long amount = 0; // 1 for the `inc` form, the imm8 for the `add` form
};

std::vector<u8> AddrPrefix(void const *addr)
{
	u64 const a = (u64)(uptr)addr;
	std::vector<u8> pat;
	if (a > 0xffffffffull) {
		pat = {0x48, 0xb8};
		for (int i = 0; i < 8; ++i)
			pat.push_back((u8)(a >> (8 * i)));
	} else {
		pat = {0xb8};
		for (int i = 0; i < 4; ++i)
			pat.push_back((u8)(a >> (8 * i)));
	}
	return pat;
}

std::vector<Site> FindSites(std::vector<u8> const &code, void const *addr)
{
	std::vector<Site> out;
	auto const pre = AddrPrefix(addr);
	for (size_t i = 0; i + pre.size() + 3 <= code.size(); ++i) {
		if (memcmp(code.data() + i, pre.data(), pre.size()))
			continue;
		u8 const *p = code.data() + i + pre.size();
		if (p[0] == 0x48 && p[1] == 0xff && p[2] == 0x00) {
			out.push_back({i, pre.size() + 3, 1});
		} else if (i + pre.size() + 4 <= code.size() && p[0] == 0x48 && p[1] == 0x83 &&
			   p[2] == 0x00) {
			out.push_back({i, pre.size() + 4, (long long)(signed char)p[3]});
		}
	}
	return out;
}

// A2's deletion: remove every census site from the stream, leaving the architectural bytes, and
// keep the two maps A2's displacement arithmetic needs.
struct Stripped {
	std::vector<u8> code;	     // the armed stream with every census site removed
	std::vector<size_t> to_armed; // stripped offset -> armed offset
	std::vector<size_t> before;   // armed offset -> census bytes strictly before it
};

Stripped StripSites(std::vector<u8> const &code, std::vector<Site> a, std::vector<Site> const &b)
{
	a.insert(a.end(), b.begin(), b.end());
	std::vector<bool> drop(code.size(), false);
	for (auto const &s : a)
		for (size_t k = s.offset; k < s.offset + s.length && k < code.size(); ++k)
			drop[k] = true;
	Stripped out;
	out.before.assign(code.size() + 1, 0);
	for (size_t k = 0; k < code.size(); ++k) {
		out.before[k + 1] = out.before[k] + (drop[k] ? 1u : 0u);
		if (!drop[k]) {
			out.code.push_back(code[k]);
			out.to_armed.push_back(k);
		}
	}
	return out;
}

i32 Rel32(std::vector<u8> const &c, size_t p)
{
	return (i32)((u32)c[p] | ((u32)c[p + 1] << 8) | ((u32)c[p + 2] << 16) | ((u32)c[p + 3] << 24));
}

// A2's core. A differing byte run must lie inside the DISPLACEMENT FIELD of a branch or call whose
// opcode bytes are identical in both streams, AND the displacement must have changed by exactly the
// number of census bytes that instruction now jumps over. `field` receives the displacement start.
//
// WHY THE SECOND HALF MATTERS. Accepting "some branch displacement moved" would also accept a
// retargeted branch -- the one way the census could change control flow while leaving every opcode
// in place. Requiring the delta to equal the inserted bytes in [branch, target) makes that a
// failure: a branch that now lands somewhere else has a delta no insertion explains.
bool DisplacementExplained(std::vector<u8> const &armed, Stripped const &st,
			   std::vector<u8> const &unarmed, size_t run_start, size_t run_end,
			   size_t *field_len_out)
{
	// The candidate displacement starts: 1 or 2 bytes of opcode, then rel32; or 1 byte then rel8.
	struct Form { size_t opbytes, dispbytes; };
	static Form const forms[] = {{2, 4}, {1, 4}, {1, 1}};
	for (auto const &fm : forms) {
		if (run_start < fm.opbytes)
			continue;
		size_t const p = run_start; // the run must begin AT the displacement start
		if (run_end > p + fm.dispbytes)
			continue;
		// Opcode bytes identical in both streams, and a real branch/call opcode.
		bool ok = true;
		for (size_t k = 1; k <= fm.opbytes; ++k)
			ok = ok && st.code[p - k] == unarmed[p - k];
		if (!ok)
			continue;
		u8 const o0 = st.code[p - fm.opbytes];
		bool is_branch = false;
		if (fm.opbytes == 2 && fm.dispbytes == 4)
			is_branch = o0 == 0x0f && (st.code[p - 1] & 0xf0) == 0x80; // jcc rel32
		else if (fm.opbytes == 1 && fm.dispbytes == 4)
			is_branch = o0 == 0xe9 || o0 == 0xe8; // jmp / call rel32
		else
			is_branch = o0 == 0xeb || (o0 & 0xf0) == 0x70; // jmp / jcc rel8
		if (!is_branch)
			continue;
		if (fm.dispbytes != 4)
			continue; // a rel8 field cannot carry the deltas an insertion produces
		size_t const armed_p = st.to_armed[p];
		i32 const d_armed = Rel32(armed, armed_p), d_unarmed = Rel32(unarmed, p);
		i64 const t_armed = (i64)armed_p + 4 + d_armed;
		// An in-buffer target moved by the census bytes between the branch and it; an
		// out-of-buffer target (a runtime stub) did not move at all.
		i64 const inserted = (t_armed >= 0 && (size_t)t_armed <= armed.size())
					 ? (i64)st.before[(size_t)t_armed] - (i64)st.before[armed_p]
					 : -(i64)st.before[armed_p];
		if ((i64)d_armed - (i64)d_unarmed != inserted)
			return false;
		*field_len_out = fm.dispbytes;
		return true;
	}
	return false;
}

// A5's independent landmark: `inc qword ptr [R_STATE + rvv_direct_fallbacks]`, the first
// instruction of the guard-miss arm. The displacement is an offsetof, never a number.
size_t FindFallbackArm(std::vector<u8> const &code)
{
	u32 const off = (u32)offsetof(CPUState, rvv_direct_fallbacks);
	// REX.WB FF /0 with mod=10, rm=101 (r13 + disp32): 49 FF 85 <disp32>.
	u8 pat[7] = {0x49, 0xff, 0x85, (u8)off, (u8)(off >> 8), (u8)(off >> 16), (u8)(off >> 24)};
	for (size_t i = 0; i + sizeof(pat) <= code.size(); ++i)
		if (!memcmp(code.data() + i, pat, sizeof(pat)))
			return i;
	return (size_t)-1;
}

void *const ADDR_AVAIL = (void *)&dbt::rv32::g_rvv_chunks_available;
void *const ADDR_EXEC = (void *)&dbt::rv32::g_rvv_chunks_executed;

// ---------------------------------------------------------------------------------------------
// The shapes, and the geometry this file derives for them INDEPENDENTLY of any node.
// ---------------------------------------------------------------------------------------------
struct Shape {
	char const *name;
	u32 word;	 // the guest instruction
	u32 vsew, vlmul; // its vsetvli
	u32 sew_bytes;
	bool fp;      // FP route: the frame epilogue owns vstart, so unit 0 IS boundable
	u32 vta = 1u; // 1 = tail-agnostic, 0 = tail-undisturbed
	u32 vma = 1u; // 1 = mask-agnostic, 0 = mask-undisturbed
	u32 prestart = 0u; // if non-zero, the region writes this to `vstart` before the vector op
	bool census = true; // participate in the census assertions of [A] and [B]
};

// The vtype this shape's `vsetvli` installs, and therefore the one its frame's guard demands.
constexpr u32 ShapeVType(Shape const &sh) { return VTypeOf(sh.vsew, sh.vlmul, sh.vta, sh.vma); }
// Is the instruction itself masked (vm == 0)?
constexpr bool ShapeMasked(Shape const &sh) { return ((sh.word >> 25) & 1u) == 0u; }

// The guest program for one shape. Two or three words; see CsrwVstartA1.
inline std::vector<u32> ShapeProgram(Shape const &sh)
{
	std::vector<u32> w = {Vsetvli(sh.vsew, sh.vlmul, sh.vta, sh.vma)};
	if (sh.prestart)
		w.push_back(CsrwVstartA1());
	w.push_back(sh.word);
	return w;
}

Shape const SHAPES[] = {
    // The four SEWs give four different element strides (8, 16, 32 and 64 lanes per host work
    // unit), which is what makes A7's ladder check a check of the STRIDE and not of one constant.
    // LMUL 2 at both VLENs gives 2 and 4 work units, so every cell has a real suffix to bound.
    {"vadd.vv e64m2", MakeOpV(F6_VADD, 1, 12, 10, 8, OPIVV), 3u, M2, 8, false},
    {"vadd.vv e32m2", MakeOpV(F6_VADD, 1, 12, 10, 8, OPIVV), SEW32, M2, 4, false},
    {"vadd.vv e16m2", MakeOpV(F6_VADD, 1, 12, 10, 8, OPIVV), 1u, M2, 2, false},
    {"vadd.vv e8m2", MakeOpV(F6_VADD, 1, 12, 10, 8, OPIVV), 0u, M2, 1, false},
    // The FP route, and the reason it is here: its `vstart` write lives in the frame epilogue, so
    // its first bounded unit is 0 and its always-executed prefix is EMPTY. That is the cell that
    // exercises `EmitRvvActiveChunkCensusAdd`'s `n == 0` path at the join.
    {"vfadd.vv e32m2", MakeOpV(F6_VFADD, 1, 12, 10, 8, OPFVV), SEW32, M2, 4, true},
    // P2c. THE SAME FP FRAME UNDER TAIL-UNDISTURBED POLICY. Under `vta = 0` every tail element is
    // ISA-constrained to keep its prior value, so the whole destination register group can be
    // byte-compared against the reference instead of only its active prefix -- which is the only
    // way an illegal destination write becomes observable. See the [C] section.
    {"vfadd.vv e32m2 tu", MakeOpV(F6_VFADD, 1, 12, 10, 8, OPFVV), SEW32, M2, 4, true, 0u},
    // P2c. "MASKED / PRESTART ELEMENTS WHERE APPLICABLE" -- and both ARE applicable to this route,
    // which had to be established rather than assumed:
    //
    //   MASKED: RvvQcgTypedFaluAdmit refuses a masked encoding only when the destination is v0
    //   (`vm == 0 && (dynamic_vtype || vd == 0)`), so `vfadd.vv v8, v12, v10, v0.t` IS admitted,
    //   and Emit_vchunkfalu has an `ins->masked` arm that ANDs v0 into the active mask. Under
    //   `vma = 0` every INACTIVE body element is then ISA-constrained to keep its prior value.
    //
    //   PRESTART: the FP frame's `VTypePartialVlVstartFrmHost` guard deliberately does NOT test
    //   vstart (qemit.cpp skips the vstart compare for exactly that kind), and the body derives its
    //   prestart mask from `vec.vstart`. The value is installed by `csrrw x0, vstart, a1` AFTER the
    //   region's own vsetvli, which is the only placement that survives -- see CsrwVstartA1.
    //
    // Both are `census = false`: they exist to exercise the ORACLE, and leaving them out of the
    // census assertions keeps P2a/P2b's established counts exactly as they were.
    {"vfadd.vv e32m2 masked mu/tu", MakeOpV(F6_VFADD, 0, 12, 10, 8, OPFVV), SEW32, M2, 4, true, 0u,
     0u, 0u, false},
    {"vfadd.vv e32m2 vstart=5 tu", MakeOpV(F6_VFADD, 1, 12, 10, 8, OPFVV), SEW32, M2, 4, true, 0u,
     1u, 5u, false},
};

constexpr u32 HOST_CHUNK_BYTES = 64; // one zmm work unit; narrow chunk width is off above

struct Geom {
	u32 units, lanes, prefix; // prefix = always-executed units, with the policy ON
};

// Derived from VLEN, SEW and LMUL alone. `prefix` is 0 for a FrameEpilogue-convention frame (the FP
// route: nothing rides on the last body node, so unit 0 is boundable) and 1 for a LastChunkNode
// frame (the integer routes: the last node carries the vstart write, so a frame with every unit
// skippable would have no body left to reach the epilogue's precondition).
Geom Geometry(Shape const &sh, u32 vlen)
{
	u32 const group_bytes = (vlen / 8) * (1u << sh.vlmul);
	Geom g{};
	g.units = group_bytes / HOST_CHUNK_BYTES;
	g.lanes = HOST_CHUNK_BYTES / sh.sew_bytes;
	g.prefix = sh.fp ? 0u : 1u;
	return g;
}

// The count of units reached at this `vl`, from the shape alone. See A7.
u32 ExpectedExecuted(Geom const &g, bool policy, u32 vl)
{
	if (!policy)
		return g.units; // no bound: every unit is reached, tail units included
	u32 reached = (vl + g.lanes - 1) / g.lanes; // units with at least one element below vl
	if (reached < g.prefix)
		reached = g.prefix;
	if (reached > g.units)
		reached = g.units;
	return reached;
}

// The same number, but computed from the ladder the translator actually emitted.
u32 LadderExecuted(Frame const &f, u32 vl)
{
	u32 n = f.end->census_prefix_units;
	for (u32 base : f.bound_bases)
		if (vl > base)
			++n;
	return n;
}

// ---------------------------------------------------------------------------------------------
// [A]
// ---------------------------------------------------------------------------------------------
void CheckShape(Shape const &sh, u32 vlen, bool policy)
{
	if (!sh.census)
		return; // an oracle-only shape; see the note on SHAPES
	std::vector<u32> const words = ShapeProgram(sh);
	Geom const g = Geometry(sh, vlen);

	Built off, on;
	Build(off, words, Env{vlen, policy, /*census=*/false});
	Build(on, words, Env{vlen, policy, /*census=*/true});

	auto frames = FindFrames(on.region);
	if (frames.size() != 1) {
		printf("    %-16s VLEN=%-5u policy=%d  no single typed frame (%zu) -- shape not built\n",
		       sh.name, vlen, (int)policy, frames.size());
		return;
	}
	Frame const &f = frames[0];
	size_t a2_disp_fields = 0;

	// The end node must carry the geometry this file derived independently.
	CHECK_MSG(f.end->census_units == g.units,
		  "%s VLEN=%u policy=%d: end node says %u units, shape says %u", sh.name, vlen,
		  (int)policy, (unsigned)f.end->census_units, g.units);
	u32 const want_prefix = policy && g.units > g.prefix ? g.prefix : g.units;
	CHECK_MSG(f.end->census_prefix_units == want_prefix,
		  "%s VLEN=%u policy=%d: end node prefix %u, expected %u", sh.name, vlen, (int)policy,
		  (unsigned)f.end->census_prefix_units, want_prefix);
	// The bound ladder and the prefix are two statements of one split.
	CHECK_MSG(f.bound_bases.size() == f.end->census_units - f.end->census_prefix_units,
		  "%s VLEN=%u policy=%d: %zu bounds but units-prefix = %u", sh.name, vlen,
		  (int)policy, f.bound_bases.size(),
		  (unsigned)(f.end->census_units - f.end->census_prefix_units));
	for (size_t c = 0; c < f.bound_bases.size(); ++c)
		CHECK_MSG(f.bound_bases[c] == (want_prefix + (u32)c) * g.lanes,
			  "%s VLEN=%u policy=%d: bound %zu guards element %u, expected %u", sh.name,
			  vlen, (int)policy, c, f.bound_bases[c], (want_prefix + (u32)c) * g.lanes);

	// A1: the unarmed stream carries neither counter.
	CHECK_MSG(FindSites(off.code, ADDR_AVAIL).empty() && FindSites(off.code, ADDR_EXEC).empty(),
		  "%s VLEN=%u policy=%d A1: an unarmed build carries a census site", sh.name, vlen,
		  (int)policy);

	auto const av = FindSites(on.code, ADDR_AVAIL);
	auto const ex = FindSites(on.code, ADDR_EXEC);

	// A3: exactly one available site, and its immediate is the unit count.
	CHECK_MSG(av.size() == 1, "%s VLEN=%u policy=%d A3: %zu available sites, expected 1", sh.name,
		  vlen, (int)policy, av.size());
	if (av.size() == 1)
		CHECK_MSG(av[0].amount == (long long)g.units,
			  "%s VLEN=%u policy=%d A3: available site adds %lld, expected %u", sh.name,
			  vlen, (int)policy, av[0].amount, g.units);

	// A4: one prefix add when the prefix is non-empty, plus one `inc` per bound.
	size_t const want_incs = f.bound_bases.size();
	size_t const want_adds = want_prefix ? 1u : 0u;
	size_t incs = 0, adds = 0;
	long long add_amount = -1;
	for (auto const &s : ex) {
		if (s.amount == 1 && s.length == AddrPrefix(ADDR_EXEC).size() + 3) {
			++incs;
		} else {
			++adds;
			add_amount = s.amount;
		}
	}
	// A prefix of exactly 1 is emitted as an `inc`, which is the same instruction a bound's
	// fall-through emits; separate them by POSITION instead -- the prefix add is the only executed
	// site that lies after the last bound (it sits at the join).
	if (want_prefix == 1 && want_adds == 1) {
		CHECK_MSG(ex.size() == want_incs + 1,
			  "%s VLEN=%u policy=%d A4: %zu executed sites, expected %zu", sh.name, vlen,
			  (int)policy, ex.size(), want_incs + 1);
	} else {
		CHECK_MSG(incs == want_incs,
			  "%s VLEN=%u policy=%d A4: %zu per-bound increments, expected %zu", sh.name,
			  vlen, (int)policy, incs, want_incs);
		CHECK_MSG(adds == want_adds,
			  "%s VLEN=%u policy=%d A4: %zu prefix adds, expected %zu", sh.name, vlen,
			  (int)policy, adds, want_adds);
		if (want_adds == 1)
			CHECK_MSG(add_amount == (long long)want_prefix,
				  "%s VLEN=%u policy=%d A4: prefix add is %lld, expected %u", sh.name,
				  vlen, (int)policy, add_amount, want_prefix);
	}

	// A4b: EVERY PER-BOUND INCREMENT SITS ON THE BOUND'S FALL-THROUGH PATH. The bound emits
	// `cmp dword [R_STATE+vec.vl], imm` followed by `jbe body_done`; the increment must be the
	// instruction AFTER that `jbe`, never before it.
	//
	// WITHOUT THIS CHECK NOTHING IN SECTION [A] SEES THE DIFFERENCE. An increment emitted before
	// the compare would credit the unit the frame is about to SKIP, and it would still be one
	// increment per bound, still inside the native arm, still leave the stripped stream equal to
	// the unarmed one, and still leave the QIR ladder untouched -- so A2, A4, A5 and A7 would all
	// pass on a counter that counts the wrong set. This is the assertion that fails.
	for (auto const &site : ex) {
		bool preceded_by_jbe = false;
		if (site.offset >= 6 && on.code[site.offset - 6] == 0x0f &&
		    on.code[site.offset - 5] == 0x86)
			preceded_by_jbe = true; // jbe rel32
		if (site.offset >= 2 && on.code[site.offset - 2] == 0x76)
			preceded_by_jbe = true; // jbe rel8
		// The join's prefix site is the one executed site that is NOT preceded by a bound; it
		// is identified by lying after every bound site, i.e. after the last `jbe` in the frame.
		bool const is_join = &site == &ex.back() && want_prefix != 0;
		if (is_join)
			continue;
		CHECK_MSG(preceded_by_jbe,
			  "%s VLEN=%u policy=%d A4b: an executed-counter site at %zu does not follow "
			  "a `jbe` -- it is not on a bound's fall-through path",
			  sh.name, vlen, (int)policy, site.offset);
	}

	// A6: with the policies off the two join immediates are the same number.
	if (!policy) {
		CHECK_MSG(ex.size() == 1 && av.size() == 1 && ex[0].amount == av[0].amount,
			  "%s VLEN=%u A6: policy-off frame does not credit executed == available "
			  "(%zu/%zu sites)",
			  sh.name, vlen, ex.size(), av.size());
		CHECK_MSG(f.bound_bases.empty(),
			  "%s VLEN=%u A6: a policy-off frame carries %zu bounds", sh.name, vlen,
			  f.bound_bases.size());
	}

	// A5: every site is on the native arm, strictly before the guard-miss arm.
	size_t const fb = FindFallbackArm(on.code);
	CHECK_MSG(fb != (size_t)-1, "%s VLEN=%u policy=%d A5: no fallback arm found", sh.name, vlen,
		  (int)policy);
	if (fb != (size_t)-1) {
		bool all_before = true;
		for (auto const *v : {&av, &ex})
			for (auto const &s : *v)
				all_before = all_before && s.offset < fb;
		CHECK_MSG(all_before,
			  "%s VLEN=%u policy=%d A5: a census site lies at or past the fallback arm "
			  "(offset %zu)",
			  sh.name, vlen, (int)policy, fb);
	}

	// A2: deleting the census sites reproduces the unarmed stream exactly.
	auto const st = StripSites(on.code, av, ex);
	// A2a: THE SIZE IS EXACTLY ACCOUNTED FOR. Deleting the census sites restores the unarmed
	// length to the byte, which is what rules out a widened branch, an alignment shift or any
	// other instruction the diagnostic might have caused to be re-encoded.
	CHECK_MSG(st.code.size() == off.code.size(),
		  "%s VLEN=%u policy=%d A2a: armed stream minus its %zu census bytes is %zu bytes, "
		  "unarmed is %zu",
		  sh.name, vlen, (int)policy, on.code.size() - st.code.size(), st.code.size(),
		  off.code.size());
	if (st.code.size() == off.code.size()) {
		// A2b: every remaining difference is a branch DISPLACEMENT whose change equals exactly
		// the census bytes that branch now jumps over. See DisplacementExplained.
		size_t k = 0, disp_fields = 0;
		std::vector<size_t> unexplained;
		while (k < st.code.size()) {
			if (st.code[k] == off.code[k]) {
				++k;
				continue;
			}
			size_t run_end = k;
			while (run_end < st.code.size() && st.code[run_end] != off.code[run_end])
				++run_end;
			size_t flen = 0;
			if (DisplacementExplained(on.code, st, off.code, k, run_end, &flen)) {
				++disp_fields;
				k = k + flen;
			} else {
				unexplained.push_back(k);
				k = run_end;
			}
		}
		CHECK_MSG(unexplained.empty(),
			  "%s VLEN=%u policy=%d A2b: %zu differing byte run(s) are not branch "
			  "displacements explained by the inserted bytes (first at %zu)",
			  sh.name, vlen, (int)policy, unexplained.size(),
			  unexplained.empty() ? 0 : unexplained[0]);
		if (!unexplained.empty()) {
			size_t const d = unexplained[0];
			fprintf(stderr, "    stripped:");
			for (size_t q = (d > 8 ? d - 8 : 0); q < d + 16 && q < st.code.size(); ++q)
				fprintf(stderr, "%s%02x", q == d ? " | " : " ", st.code[q]);
			fprintf(stderr, "\n    unarmed :");
			for (size_t q = (d > 8 ? d - 8 : 0); q < d + 16 && q < off.code.size(); ++q)
				fprintf(stderr, "%s%02x", q == d ? " | " : " ", off.code[q]);
			fprintf(stderr, "\n");
		}
		a2_disp_fields = disp_fields;
	}

	// A7: the exact counter values over a vl table, ladder against shape.
	u32 const full = g.units * g.lanes;
	u32 const vls[] = {0u, 1u, g.lanes, full / 2u, full - 1u, full};
	char const *names[] = {"vl=0", "vl=1", "vl=lanes (first inactive unit)", "vl=half",
			       "vl=full-1", "vl=full"};
	for (size_t k = 0; k < sizeof(vls) / sizeof(vls[0]); ++k) {
		u32 const want = ExpectedExecuted(g, policy, vls[k]);
		u32 const got = LadderExecuted(f, vls[k]);
		CHECK_MSG(got == want,
			  "%s VLEN=%u policy=%d A7 %s: ladder gives executed=%u, shape says %u "
			  "(units=%u lanes=%u prefix=%u)",
			  sh.name, vlen, (int)policy, names[k], got, want, g.units, g.lanes,
			  want_prefix);
		CHECK_MSG(got <= f.end->census_units,
			  "%s VLEN=%u policy=%d A7 %s: executed %u exceeds available %u", sh.name,
			  vlen, (int)policy, names[k], got, (unsigned)f.end->census_units);
	}

	printf("    %-16s VLEN=%-5u policy=%d units=%-2u lanes=%-2u prefix=%-2u bounds=%-2zu "
	       "sites(av=%zu ex=%zu) delta=%zuB disp_fields=%zu\n",
	       sh.name, vlen, (int)policy, g.units, g.lanes, want_prefix, f.bound_bases.size(),
	       av.size(), ex.size(), on.code.size() - off.code.size(), a2_disp_fields);
}

// A8: the frames the common finalizer refuses contribute nothing at all.
void CheckIneligible(u32 vlen)
{
	struct Cell {
		char const *name;
		std::vector<u32> words;
		bool vector_run;
	};
	// THREE REASONS THE COMMON CLOSE REFUSES A FRAME, one cell each. The fourth reason a reader
	// will look for -- MultiMember -- is NOT covered here: forming a vector run needs
	// rvvrun::FormRun to admit the pair, which this file does not drive, and the MultiMember
	// classification is owned by rvv_frame_finalizer_test. What IS covered is that the census
	// population is the finalizer's `reason == None` set, from three different refusals.
	std::vector<Cell> const cells = {
	    // WholeRegisterEvl: EVL is nregs*VLEN/EEW and does not depend on vec.vl at all.
	    {"vl2re32.v (whole-register)", {Vsetvli(SEW32, M2), Vl2re32()}, false},
	    // MemoryOrProtocol: a guest memory access.
	    {"vle32.v (guest memory)", {Vsetvli(SEW32, 0), Vle32()}, false},
	    // MemoryOrProtocol again, by the OTHER clause: this shape takes the older per-opcode
	    // vadd route, whose guard proves `vl == VLMAX && vstart == 0`. Every bound there would be
	    // a translation-time constant false, so the finalizer refuses the frame -- and the census
	    // must refuse it too, rather than report a frame whose units are all trivially "executed".
	    {"vadd.vv e32m1 (guard proves full VL)",
	     {Vsetvli(SEW32, 0u), MakeOpV(F6_VADD, 1, 12, 10, 8, OPIVV)}, false},
	};
	for (auto const &c : cells) {
		Built b;
		Env e{vlen, /*policy=*/true, /*census=*/true, c.vector_run, /*memory_routes=*/true};
		Build(b, c.words, e);
		auto const frames = FindFrames(b.region);
		unsigned ineligible = 0;
		for (auto const &f : frames) {
			bool const is_run = f.end->n_members != 1;
			bool const whole = f.end->whole_regbytes != 0;
			if (!is_run && !whole && f.end->census_units != 0)
				continue; // an eligible frame in this cell; the run cell has one
			++ineligible;
			CHECK_MSG(f.end->census_units == 0 && f.end->census_prefix_units == 0,
				  "%s VLEN=%u A8: an ineligible frame carries units=%u prefix=%u",
				  c.name, vlen, (unsigned)f.end->census_units,
				  (unsigned)f.end->census_prefix_units);
			CHECK_MSG(f.bound_bases.empty(),
				  "%s VLEN=%u A8: an ineligible frame carries %zu bounds", c.name,
				  vlen, f.bound_bases.size());
		}
		printf("    %-28s VLEN=%-5u frames=%zu ineligible=%u av_sites=%zu ex_sites=%zu\n",
		       c.name, vlen, frames.size(), ineligible,
		       FindSites(b.code, ADDR_AVAIL).size(), FindSites(b.code, ADDR_EXEC).size());
		if (frames.empty())
			continue;
		// If EVERY frame in the cell is ineligible there must be no site at all.
		bool any_eligible = false;
		for (auto const &f : frames)
			any_eligible = any_eligible || f.end->census_units != 0;
		if (!any_eligible)
			CHECK_MSG(FindSites(b.code, ADDR_AVAIL).empty() &&
				      FindSites(b.code, ADDR_EXEC).empty(),
				  "%s VLEN=%u A8: a census site was emitted for an ineligible frame",
				  c.name, vlen);
	}
}

// ---------------------------------------------------------------------------------------------
// [B] EXECUTION. Compiled everywhere, RUN only on a host with AVX-512F and BMI2.
//
// THE ORACLE IS TWO-LAYERED, ON PURPOSE. Comparing the emitted body's whole destination group
// against a spec model would drag in the tail-agnostic fill policy, which is not what this file
// owns and not what P2a changed. So:
//
//   (i)  the ARMED and UNARMED executions of the same frame on the same input state must leave
//        BIT-IDENTICAL vector state -- that is the "the census perturbed nothing" claim, and it
//        needs no model at all;
//   (ii) the ACTIVE elements [vstart, vl) of the unarmed execution must equal `rvv_ref::vialu`,
//        the existing reference lowering every route test and the QEMU differential already use.
//        Restricting to the active range is what keeps the tail policy out of it.
//
// Together they say: the frame still computes the architecturally specified result, and arming the
// census changed no bit of it.
// ---------------------------------------------------------------------------------------------
struct ExecRuntime final : CompilerRuntime {
	~ExecRuntime()
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
			Panic("p2a census test: code mmap");
		last = (u8 *)mem;
		return mem;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	void *mem{};
	u8 *last{};
	size_t size{};
};

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

struct ExecBuilt {
	MemArena arena{1u << 21};
	std::vector<u32> words;
	ExecRuntime rt;
	Region *region = nullptr;
	u8 *code = nullptr;
};

void BuildExec(ExecBuilt &b, std::vector<u32> const &words, Env const &e)
{
	ApplyEnv(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.rt, &segment, b.region, 0);
	if (span.empty())
		Panic("p2a census test: empty region");
	b.code = b.rt.last;
	size_t k = span.size();
	if (b.code[0] == 0x51)	    // push rcx (non-leaf frame)
		b.code[k++] = 0x59; // pop rcx
	b.code[k++] = 0xc3;	    // ret
}


// One execution. Fills the state deterministically, runs, and returns the counters this run
// produced. `out` receives the post-execution vector state.
// vd is a 2-register group at LMUL 2 (v8, v9); the sources are v10/v11 and v12/v13; v0 is the mask
// register for the masked shapes. No group overlaps another, which is what lets "every register
// outside the destination group is untouched" be a check rather than a caveat.
constexpr u32 VD = 8, VS2 = 12, VS1 = 10;

// The deterministic initial vector state. INTEGER shapes get an arbitrary byte pattern; the FP
// shape gets small integer-VALUED single-precision floats in every 4-byte lane, so that `vfadd`
// produces exact, finite, NaN-free results and the oracle comparison below is a comparison of
// ARITHMETIC rather than of NaN payload canonicalisation -- which is not what this file owns.
void FillVectorState(rv32::VectorState *v, bool fp)
{
	for (u32 r = 0; r < 32; ++r)
		for (u32 i = 0; i < rv32::VLEN_MAX_BYTES; ++i)
			v->vreg[r][i] = (u8)(0xA5u + r * 13u + i * 7u);
	if (!fp)
		return;
	for (u32 r = 0; r < 32; ++r)
		for (u32 e = 0; e * 4 + 4 <= rv32::VLEN_MAX_BYTES; ++e) {
			// P2c. THE INEXACT STIMULUS, so the fflags comparison is not vacuously 0 == 0.
			// In one lane of every seven, vs2 holds 1.0f and vs1 holds 2^-30: the sum rounds
			// back to 1.0f and raises NX. Every value stays finite and normal, so nothing here
			// depends on NaN payload canonicalisation, which this file does not own.
			float f = (float)(int)(1 + ((r * 7u + e * 3u) % 97u)) * 0.5f;
			if ((e % 7u) == 3u) {
				if (r == VS1)
					f = 0x1p-30f;
				else if (r == VS2)
					f = 1.0f;
			}
			memcpy(v->vreg[r].data() + e * 4, &f, 4);
		}
}

struct RunResult {
	rv32::VectorState vec{};
	u64 avail = 0, exec = 0;
	u64 fallbacks = 0; // CPUState::rvv_direct_fallbacks: did the guard-miss arm run?
	u32 fcsr = 0;
};

// `state_vlen` is the ARCHITECTURAL VLEN the guest state reports (`vec.vlenb`), which is normally
// the VLEN the frame was compiled for and is deliberately NOT so in the guard-miss control below.
// `avl` is x[a0], the application vector length the region's own leading `vsetvli` consumes.
//
// THAT LEADING `vsetvli` IS WHY THE RUNTIME STATE IS SET THE WAY IT IS. The region translated here
// is `{vsetvli a0,a0,<vtype>; <vector op>}`, so at run time the vsetvli OVERWRITES `vec.vtype` with
// the compiled vtype and sets `vec.vl = min(x[a0], VLMAX)` before the frame's guard ever runs -- and
// it also resets `vec.vstart` (rv32_interp.cpp: "Configuration instructions reset vstart"). Presetting
// vtype or vstart here therefore cannot survive to the guard, which is exactly how P2b's first
// guard-miss attempt failed. `vec.vlenb` is the one piece of architectural state the vsetvli reads
// rather than writes.
void RunOne(ExecBuilt &b, Shape const &sh, u32 state_vlen, u32 vtype, u32 avl, RunResult *out,
	    u32 fcsr = 0, rv32::VectorState const *seed = nullptr)
{
	CPUState st(nullptr);
	memset(&st, 0, sizeof st);
	st.fpu.fcsr = fcsr;
	st.vec.vlenb = (u16)(state_vlen / 8);
	st.vec.vtype = vtype;
	st.vec.vl = avl;
	st.vec.vstart = 0;
	if (seed)
		st.vec = *seed;
	else
		FillVectorState(&st.vec, sh.fp);
	st.vec.vlenb = (u16)(state_vlen / 8);
	st.vec.vtype = vtype;
	st.vec.vl = avl;
	st.vec.vstart = 0;
	st.gpr[10] = avl;
	st.gpr[11] = sh.prestart; // consumed by `csrrw x0, vstart, a1` when the shape has one

	dbt::rv32::g_rvv_chunks_available = 0;
	dbt::rv32::g_rvv_chunks_executed = 0;
	Enter(&st, nullptr, b.code);
	out->avail = dbt::rv32::g_rvv_chunks_available;
	out->exec = dbt::rv32::g_rvv_chunks_executed;
	out->fallbacks = st.rvv_direct_fallbacks;
	out->fcsr = st.fpu.fcsr;
	out->vec = st.vec;
}

// Does this frame take the HELPER instead of its native body at this `vl`?
//
// DERIVED FROM THE FRAME'S OWN GUARD KIND, NOT FROM THE MEASUREMENT, and then cross-checked against
// `CPUState::rvv_direct_fallbacks` in every cell -- so a wrong rule here fails the test loudly
// instead of silently reclassifying a cell. It already has: P2b's first attempt asserted "an FP
// frame falls back at vl == 0" from the ISA rule alone, and xbd showed the frame taking its native
// arm, because only TWO of the guard kinds emit that compare.
//
// `Emit_rvvtypedchunkbegin` emits `cmp dword [vec.vl], 0; je fallback` for exactly
// `VTypePartialVlVstartFrmRNE` and `VTypeE32OrE64M2PartialVlVstartFrmRNE` (qemit.cpp, comment A4:
// RVV 1.0 requires that no destination element be updated when vl == 0, and those bodies' masked
// lane ops would still apply their tail policy). The statically-typed FP route this file builds gets
// `VTypePartialVlVstartFrmHost` instead, which carries no such compare -- so its vl == 0 execution
// is a NATIVE one, with every chunk's lane mask empty.
//
// Every other guard miss in this matrix is impossible by construction: the region's leading
// `vsetvli` writes vtype, clamps vl to VLMAX and resets vstart before the guard runs. See
// RunGuardMissCell for the one input it does not touch.
bool GuardSendsVlZeroToHelper(qir::InstRVVTypedChunkBegin::GuardKind k)
{
	using GK = qir::InstRVVTypedChunkBegin::GuardKind;
	return k == GK::VTypePartialVlVstartFrmRNE || k == GK::VTypeE32OrE64M2PartialVlVstartFrmRNE;
}

// ---------------------------------------------------------------------------------------------
// [C] THE FULL ARCHITECTURAL POST-STATE ORACLE (P2c).
//
// P2b compared only the ACTIVE elements [0, vl) of the destination and therefore could say nothing
// about `vl == 0`, where that range is empty. This section compares EVERY piece of post-state the
// ISA constrains, against the same reference lowering the route tests and the QEMU differential
// already use.
//
// WHAT IS CONSTRAINED, AND UNDER WHICH POLICY
//
//   vstart          RVV 1.0: every vector instruction that executes to completion resets vstart to
//                   0. Constrained always.
//   vl, vtype       not written by an arithmetic instruction. Constrained always.
//   other registers no vector register outside the destination GROUP may be written -- including
//                   v0, the mask register. Constrained always, under every policy.
//   destination     [0, vstart)   PRESTART: never updated. Constrained always.
//                   [vstart, vl)  BODY: active elements take the result; INACTIVE (mask 0) elements
//                                 are undisturbed when vma = 0 and unconstrained when vma = 1.
//                   [vl, VLMAX)   TAIL: undisturbed when vta = 0; unconstrained when vta = 1.
//                   vl == 0       no element of the destination may be updated AT ALL, tail policy
//                                 notwithstanding. This is the rule rvdbt itself states, in
//                                 Emit_rvvtypedchunkbegin's comment A4: "RVV 1.0 requires that no
//                                 destination element is updated when vl == 0 (all lanes are tail
//                                 AND nothing may be written)". It is the reason the
//                                 VTypePartialVlVstartFrmRNE guard sends vl == 0 to the helper.
//   fflags          the accrued exception flags must be the reference's.
//
// WHY THE TAIL CANNOT BE BYTE-COMPARED UNDER vta = 1. Tail-agnostic leaves each tail element free to
// be EITHER its previous value OR all ones, independently, and RVV 1.0 permits an implementation to
// choose differently per element and per execution. There is therefore no byte pattern an oracle
// could require. The reference lowering writes only [vstart, vl) -- i.e. it implements the
// UNDISTURBED choice -- so byte-comparing its tail against the emitted body's would be testing an
// implementation choice, not the ISA. Those elements are consequently EXCLUDED, and that exclusion
// is exactly why the `vta = 0` shape and the `vl == 0` cells exist: they move the same bytes back
// under an ISA constraint so that an illegal write becomes observable.
//
// The reference is handed the same seed, the same vtype, the same vl, the same vstart and the same
// fcsr, so every difference reported below is a difference in what the EMITTED CODE did.
// ---------------------------------------------------------------------------------------------

u32 LmulRegs(Shape const &sh) { return 1u << sh.vlmul; }

// Is register `r` part of this shape's destination register group?
bool InDestGroup(Shape const &sh, u32 r) { return r >= VD && r < VD + LmulRegs(sh); }

// The reference post-state, from the existing reference lowering, plus the fflags it accrued.
void Oracle(Shape const &sh, u32 vlen, u32 vtype, u32 vl, u32 vstart, rv32::VectorState const &seed,
	    rv32::VectorState *ref, u32 *ref_fcsr, u32 in_fcsr)
{
	*ref = seed;
	ref->vlenb = (u16)(vlen / 8);
	ref->vtype = vtype;
	ref->vl = vl;
	ref->vstart = vstart;
	bool const vm = !ShapeMasked(sh);
	if (sh.fp) {
		rv32::FPUState fs{};
		memset(&fs, 0, sizeof fs);
		fs.fcsr = in_fcsr;
		rv32::rvv_ref::vfalu(*ref, fs, F6_VFADD, /*is_vf=*/false, VD, VS2, VS1, vm, vlen, vl,
				     sh.sew_bytes, vstart);
		*ref_fcsr = fs.fcsr;
	} else {
		rv32::rvv_ref::vialu(*ref, F6_VADD, rv32::VSrc::VV, VD, VS2, VS1, /*rs1_val=*/0,
				     /*simm5=*/0, vm, vlen, vl, sh.sew_bytes);
		*ref_fcsr = in_fcsr;
	}
	// Every vector instruction that completes resets vstart; the reference models the elements,
	// not the CSR, so state the architectural post-value here rather than reading it back.
	ref->vstart = 0;
}

// Reports the FIRST mismatch in this cell and returns false. `label` identifies the cell.
// `seed`, `got` and `ref` are non-const because VectorState::elem_u is not a const member in
// rv32_vector.h. This file does not change production code to make it one.
bool CheckPostState(Shape const &sh, u32 vlen, bool policy, char const *label, u32 vtype, u32 vl,
		    u32 vstart, rv32::VectorState &seed, rv32::VectorState &got, u32 got_fflags,
		    rv32::VectorState &ref, u32 ref_fflags)
{
	u32 const vlmax = rv32::compute_vlmax(rv32::VType{vtype}, vlen);
	char msg[640];
	auto fail = [&](void) {
		CHECK_MSG(false, "%s VLEN=%u policy=%d %s [C]: %s", sh.name, vlen, (int)policy, label,
			  msg);
		return false;
	};

	// C1-C3: the CSR post-state.
	if (got.vstart != 0) {
		snprintf(msg, sizeof msg, "vstart = %u after the instruction, must be 0", got.vstart);
		return fail();
	}
	if (got.vl != vl) {
		snprintf(msg, sizeof msg, "vl = %u, must be unchanged at %u", got.vl, vl);
		return fail();
	}
	if (got.vtype != vtype) {
		snprintf(msg, sizeof msg, "vtype = 0x%x, must be unchanged at 0x%x", got.vtype, vtype);
		return fail();
	}

	// C4: nothing outside the destination group may be written, under any policy.
	for (u32 r = 0; r < 32; ++r) {
		if (InDestGroup(sh, r))
			continue;
		if (memcmp(got.vreg[r].data(), seed.vreg[r].data(), rv32::VLEN_MAX_BYTES) == 0)
			continue;
		u32 b = 0;
		while (b < rv32::VLEN_MAX_BYTES && got.vreg[r][b] == seed.vreg[r][b])
			++b;
		snprintf(msg, sizeof msg,
			 "v%u byte %u was written (0x%02x -> 0x%02x); only v%u..v%u may be written", r,
			 b, seed.vreg[r][b], got.vreg[r][b], VD, VD + LmulRegs(sh) - 1);
		return fail();
	}

	// C5: the destination, element by element, under the policy that actually applies.
	bool const tail_constrained = (sh.vta == 0) || vl == 0;
	bool const masked = ShapeMasked(sh);
	for (u32 e = 0; e < vlmax; ++e) {
		u64 const want = ref.elem_u(VD, e, sh.sew_bytes, vlen);
		u64 const seeded = seed.elem_u(VD, e, sh.sew_bytes, vlen);
		u64 const have = got.elem_u(VD, e, sh.sew_bytes, vlen);
		char const *why;
		if (vl == 0) {
			// The ISA rule rvdbt states in qemit.cpp comment A4. `ref` left the seed
			// untouched here, so `want == seeded`.
			why = "vl == 0: RVV 1.0 updates NO destination element, whatever the tail "
			      "policy (qemit.cpp comment A4 states this rule as rvdbt's own)";
			++g_cov.vl0_elems;
		} else if (e < vstart) {
			why = "prestart element: never updated";
			++g_cov.prestart_elems;
		} else if (e >= vl) {
			if (!tail_constrained) {
				++g_cov.tail_skipped;
				continue; // tail-agnostic: unconstrained, see the header note
			}
			why = "tail element under vta = 0 (tail-undisturbed): must keep its prior value";
			++g_cov.tail_tu_elems;
		} else if (masked && !ref.mask_get(0, e)) {
			if (sh.vma != 0)
				continue; // inactive body element under vma = 1: unconstrained
			why = "inactive body element under vma = 0 (mask-undisturbed): must keep its "
			      "prior value";
			++g_cov.inactive_mu_elems;
		} else {
			why = "active body element";
			++g_cov.active_elems;
		}
		if (have == want)
			continue;
		snprintf(msg, sizeof msg,
			 "FIRST MISMATCH at destination element %u (of vlmax %u, vl %u, vstart %u) -- "
			 "oracle 0x%016llx, emitted 0x%016llx, seed 0x%016llx; %s",
			 e, vlmax, vl, vstart, (unsigned long long)want, (unsigned long long)have,
			 (unsigned long long)seeded, why);
		return fail();
	}

	// C6: the accrued FP exception flags.
	++g_cov.cells;
	g_cov.fflags_nonzero += ref_fflags != 0;
	if (got_fflags != ref_fflags) {
		snprintf(msg, sizeof msg, "fflags = 0x%02x, oracle 0x%02x", got_fflags, ref_fflags);
		return fail();
	}
	return true;
}

void RunExecCells(Shape const &sh, u32 vlen, bool policy, unsigned &cells, unsigned &helper_cells)
{
	std::vector<u32> const words = ShapeProgram(sh);
	Geom const g = Geometry(sh, vlen);
	ExecBuilt off, on;
	BuildExec(off, words, Env{vlen, policy, /*census=*/false});
	BuildExec(on, words, Env{vlen, policy, /*census=*/true});

	// The frame's own guard demands this exact vtype; `Vsetvli` above encodes it.
	u32 const vtype = ShapeVType(sh);
	u32 const full = g.units * g.lanes;
	u32 const vls[] = {0u, 1u, g.lanes, full / 2u, full - 1u, full};
	char const *names[] = {"vl=0", "vl=1", "vl=lanes(first inactive unit)", "vl=half",
			       "vl=full-1", "vl=full"};
	// Which arm each cell must take, read off the frame's own guard kind before anything runs.
	auto const frames = FindFrames(on.region);
	if (frames.size() != 1)
		return;
	bool const vl0_helper = GuardSendsVlZeroToHelper(frames[0].begin->guard_kind);

	for (size_t k = 0; k < sizeof(vls) / sizeof(vls[0]); ++k) {
		u32 const vl = vls[k];
		// ONE seed, handed to both runs and to the oracle, so every byte the three compare
		// came from the same place. The destination group v8/v9 is seeded with the same
		// nontrivial pattern as every other register -- that is what makes an illegal write
		// at `vl == 0` observable rather than invisible.
		rv32::VectorState seed{};
		memset(&seed, 0, sizeof seed);
		seed.vlenb = (u16)(vlen / 8);
		seed.vtype = vtype;
		seed.vl = vl;
		seed.vstart = 0;
		FillVectorState(&seed, sh.fp);
		RunResult r_off{}, r_on{};
		RunOne(off, sh, vlen, vtype, vl, &r_off, 0, &seed);
		RunOne(on, sh, vlen, vtype, vl, &r_on, 0, &seed);
		bool const helper = vl0_helper && vl == 0;

		// WHICH ARM RAN, asserted before anything is read off the counters. Without this a
		// frame that silently fell back would report available == 0 and could be mistaken for
		// a counter that simply did not fire.
		CHECK_MSG(r_on.fallbacks == (helper ? 1u : 0u),
			  "%s VLEN=%u policy=%d %s: rvv_direct_fallbacks=%llu, expected %u -- the "
			  "frame took the %s arm, not the one the ISA rule predicts",
			  sh.name, vlen, (int)policy, names[k],
			  (unsigned long long)r_on.fallbacks, helper ? 1u : 0u,
			  r_on.fallbacks ? "helper" : "native");
		CHECK_MSG(r_off.fallbacks == r_on.fallbacks,
			  "%s VLEN=%u policy=%d %s: arming the census changed which arm ran (%llu "
			  "vs %llu)",
			  sh.name, vlen, (int)policy, names[k],
			  (unsigned long long)r_off.fallbacks, (unsigned long long)r_on.fallbacks);

		// B3: an unarmed build counts nothing, whatever it executed.
		CHECK_MSG(r_off.avail == 0 && r_off.exec == 0,
			  "%s VLEN=%u policy=%d %s B3: unarmed build counted available=%llu "
			  "executed=%llu",
			  sh.name, vlen, (int)policy, names[k], (unsigned long long)r_off.avail,
			  (unsigned long long)r_off.exec);

		// B1: THE EXACT COUNTERS, against the SHAPE-derived expectation (not the ladder, and
		// not the node). A helper execution contributes NOTHING to either counter -- that is
		// the negative control the `vl == 0` FP cell carries for free, and the one the
		// deliberate guard-miss cell below carries on purpose.
		if (sh.census) {
			u32 const want_avail = helper ? 0u : g.units;
			u32 const want_exec = helper ? 0u : ExpectedExecuted(g, policy, vl);
			CHECK_MSG(r_on.avail == want_avail,
				  "%s VLEN=%u policy=%d %s B1: available=%llu, expected %u", sh.name,
				  vlen, (int)policy, names[k], (unsigned long long)r_on.avail,
				  want_avail);
			CHECK_MSG(r_on.exec == want_exec,
				  "%s VLEN=%u policy=%d %s B1: executed=%llu, expected %u (units=%u "
				  "lanes=%u prefix=%u)",
				  sh.name, vlen, (int)policy, names[k],
				  (unsigned long long)r_on.exec, want_exec, g.units, g.lanes,
				  policy && g.units > g.prefix ? g.prefix : g.units);
		}

		// B2(i): arming the census perturbed no bit of architectural vector state.
		bool same = r_off.vec.vstart == r_on.vec.vstart && r_off.vec.vl == r_on.vec.vl &&
			    r_off.vec.vtype == r_on.vec.vtype && r_off.vec.vxsat == r_on.vec.vxsat;
		for (u32 rg = 0; rg < 32 && same; ++rg)
			if (memcmp(r_off.vec.vreg[rg].data(), r_on.vec.vreg[rg].data(),
				   rv32::VLEN_MAX_BYTES))
				same = false;
		CHECK_MSG(same, "%s VLEN=%u policy=%d %s B2: armed and unarmed results differ",
			  sh.name, vlen, (int)policy, names[k]);

		// [C] P2c: THE FULL ARCHITECTURAL POST-STATE, not merely [0, vl). See the section
		// header above for exactly which state each policy constrains and why the
		// tail-agnostic tail is excluded.
		//
		// A HELPER cell is checked with the same oracle: the ordered helper is supposed to
		// implement the whole instruction, so its post-state is constrained identically.
		rv32::VectorState ref{};
		u32 ref_fcsr = 0;
		Oracle(sh, vlen, vtype, vl, sh.prestart, seed, &ref, &ref_fcsr, /*in_fcsr=*/0);
		CheckPostState(sh, vlen, policy, names[k], vtype, vl, sh.prestart, seed, r_on.vec,
			       r_on.fcsr & 0x1fu, ref, ref_fcsr & 0x1fu);

		++cells;
		helper_cells += helper ? 1u : 0u;
	}
}

// THE GUARD-FALLBACK NEGATIVE CONTROL, executed.
//
// WHAT MAKES THE GUARD MISS, AND WHY IT IS THE ROUNDING MODE. The region under test begins with its
// own `vsetvli`, and that instruction writes or resets EVERY other input the frame's guard reads:
//
//   vec.vtype   overwritten with the compiled vtype;
//   vec.vl      set to min(x[a0], VLMAX), so it can never exceed the compiled vlmax;
//   vec.vstart  reset to 0 ("Configuration instructions reset vstart", rv32_interp.cpp);
//   VLEN        taken from `config::vlen_bits` by the vsetvli helper, NOT from `vec.vlenb`, so the
//               architectural vector length cannot be varied at run time either.
//
// Presetting any of those into a miss is therefore impossible in this single-block construction --
// both were tried on xbd and both were absorbed by the vsetvli. `fcsr` is the one architectural
// input the guard reads and the vsetvli does not touch.
//
// frm = RMM (4). It is a LEGAL RISC-V rounding mode -- so the helper completes instead of raising an
// illegal-instruction trap this harness has no uthread to deliver -- and it misses BOTH rounding
// guards the FP chunk routes emit: `VTypePartialVlVstartFrmRNE`'s `test [fcsr], 0xe0; jnz fallback`
// (any non-RNE mode) and `VTypePartialVlVstartFrmHost`'s `and eax, 0xe0; cmp eax, 3<<5; ja fallback`
// (RMM and the reserved modes are not MXCSR modes). The reference lowering is handed the SAME fcsr,
// so both sides round identically; the inputs are exact in any case.
//
// THIS IS THE CELL THAT WOULD EXPOSE A CENSUS SITE ON THE GUARD-MISS ARM. The helper performs the
// whole instruction and the native body runs no work unit at all, so a counter that credited this
// arm would report host work units for an execution that performed none -- the single error that
// makes the ratio meaningless rather than merely wrong.
//
// SCOPE, STATED HONESTLY: this control is the FP route's guard. The integer routes' guard cannot be
// missed from a single-block region for the reason above, so their fallback arm is covered by [A]'s
// A5 (every census site lies strictly before `inc [rvv_direct_fallbacks]`, checked in all 20
// shape/VLEN/policy cells) plus the fact that both arms are emitted by ONE function,
// `Emit_rvvtypedchunkend`, for every frame.
void RunGuardMissCell(Shape const &sh, u32 vlen, bool policy, unsigned &cells)
{
	if (!sh.census)
		return;
	if (!sh.fp)
		return; // see the scope note above
	constexpr u32 kFrmRmm = 4u;
	u32 const fcsr = kFrmRmm << 5;
	std::vector<u32> const words = ShapeProgram(sh);
	Geom const g = Geometry(sh, vlen);
	ExecBuilt on;
	BuildExec(on, words, Env{vlen, policy, /*census=*/true});

	u32 const vtype = ShapeVType(sh);
	u32 const full = g.units * g.lanes;
	// A PARTIAL vl, so a bounded frame that had taken its native body WOULD have exited early and
	// credited a number strictly between the prefix and `units`. Both counters must still be 0.
	u32 const avl = full / 2u;

	RunResult r{};
	RunOne(on, sh, vlen, vtype, avl, &r, fcsr);

	CHECK_MSG(r.vec.vl == avl,
		  "%s VLEN=%u policy=%d GUARD-MISS setup: the leading vsetvli left vl=%u, expected %u",
		  sh.name, vlen, (int)policy, r.vec.vl, avl);
	// The guard really missed, and the helper really ran. Without this the two zeros below would
	// be indistinguishable from a counter that simply never fired.
	CHECK_MSG(r.fallbacks == 1,
		  "%s VLEN=%u policy=%d GUARD-MISS: rvv_direct_fallbacks=%llu, expected 1 -- the "
		  "guard did not miss with frm=RMM (fcsr=0x%x)",
		  sh.name, vlen, (int)policy, (unsigned long long)r.fallbacks, fcsr);
	// B4: and it contributed NOTHING to either counter, with the census ARMED.
	CHECK_MSG(r.avail == 0 && r.exec == 0,
		  "%s VLEN=%u policy=%d B4 GUARD-MISS: the helper arm credited available=%llu "
		  "executed=%llu, both must be 0 (a native execution here would have credited "
		  "available=%u)",
		  sh.name, vlen, (int)policy, (unsigned long long)r.avail,
		  (unsigned long long)r.exec, g.units);
	// The helper still computed the right answer under the rounding mode it actually saw.
	rv32::VectorState ref{};
	memset(&ref, 0, sizeof ref);
	ref.vlenb = (u16)(vlen / 8);
	ref.vtype = vtype;
	ref.vl = avl;
	ref.vstart = 0;
	FillVectorState(&ref, sh.fp);
	rv32::FPUState fs{};
	memset(&fs, 0, sizeof fs);
	fs.fcsr = fcsr;
	rv32::rvv_ref::vfalu(ref, fs, F6_VFADD, false, VD, VS2, VS1, true, vlen, avl, sh.sew_bytes);
	for (u32 e = 0; e < avl; ++e) {
		u64 const want = ref.elem_u(VD, e, sh.sew_bytes, vlen);
		u64 const got = r.vec.elem_u(VD, e, sh.sew_bytes, vlen);
		if (want != got) {
			CHECK_MSG(false,
				  "%s VLEN=%u policy=%d GUARD-MISS: FIRST MISMATCH at element %u -- "
				  "oracle 0x%016llx, helper 0x%016llx",
				  sh.name, vlen, (int)policy, e, (unsigned long long)want,
				  (unsigned long long)got);
			break;
		}
	}
	++cells;
}

// P2c [A9]. APPLICABILITY, AS A CHECKED FACT RATHER THAN AN ASSUMPTION.
//
// The task asks for masked and prestart coverage "where applicable". This prints, and asserts, what
// is actually applicable: which of the FP shapes build a typed frame at all, which guard kind that
// frame carries, and whether its body is really the `_vchunkfalu` route the oracle claims to be
// testing. A shape that silently failed to build a frame would make its whole oracle column vacuous.
void CheckOracleShapeApplicability(Shape const &sh, u32 vlen)
{
	if (!sh.fp)
		return;
	Built b;
	Build(b, ShapeProgram(sh), Env{vlen, /*policy=*/true, /*census=*/true});
	auto const frames = FindFrames(b.region);
	unsigned falu = 0, eligible = 0;
	unsigned guard = 0;
	for (auto const &f : frames) {
		falu += f.falu_nodes;
		eligible += f.end->census_units != 0;
		guard = (unsigned)f.begin->guard_kind;
	}
	printf("    %-30s VLEN=%-5u frames=%zu falu_nodes=%u eligible=%u guard_kind=%u masked=%d "
	       "vta=%u vma=%u vstart=%u\n",
	       sh.name, vlen, frames.size(), falu, eligible, guard, (int)ShapeMasked(sh), sh.vta,
	       sh.vma, sh.prestart);
	CHECK_MSG(frames.size() == 1,
		  "%s VLEN=%u [A9]: %zu typed frames, expected exactly 1 -- its oracle column would "
		  "be vacuous",
		  sh.name, vlen, frames.size());
	CHECK_MSG(falu > 0,
		  "%s VLEN=%u [A9]: the frame carries no _vchunkfalu node, so it is NOT the FP "
		  "chunk route this file claims to be testing",
		  sh.name, vlen);
}

} // namespace

int main()
{
	bool const capable = __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("bmi2");
	qcg::ArchTraits::init();
	printf("P2a active-chunk census -- host avx512f+bmi2 = %s\n", capable ? "yes" : "no");
	printf("    counter addresses: available=%p executed=%p\n", ADDR_AVAIL, ADDR_EXEC);

	printf("[A] emitted artifact: site placement, immediates, inertness, and the exact ladder\n");
	for (u32 vlen : {512u, 1024u})
		for (int policy : {0, 1})
			for (auto const &sh : SHAPES)
				CheckShape(sh, vlen, policy != 0);

	printf("[A9] P2c oracle-shape applicability: masked and prestart really do build FP frames\n");
	for (u32 vlen : {512u, 1024u})
		for (auto const &sh : SHAPES)
			CheckOracleShapeApplicability(sh, vlen);

	printf("[A8] frames the common finalizer refuses contribute nothing\n");
	for (u32 vlen : {512u, 1024u})
		CheckIneligible(vlen);

	unsigned exec_cells = 0, helper_cells = 0, guard_miss_cells = 0;
	if (!capable) {
		printf("[B] execution: SKIPPED -- this host cannot execute an AVX-512 chunk body.\n"
		       "    NOTHING in section [B] has been exercised by this run: its exact-counter\n"
		       "    and architectural-oracle assertions are UNEXERCISED and must be run on an\n"
		       "    AVX-512 host before either is cited. Section [A] above is what this run\n"
		       "    established, and A2 is its architectural claim: the armed stream minus its\n"
		       "    census sites IS the unarmed stream, byte for byte.\n");
	} else {
		printf("[B] execution: exact counters, and the architectural result against the "
		       "rvv_ref oracle\n");
		for (u32 vlen : {512u, 1024u})
			for (int policy : {0, 1})
				for (auto const &sh : SHAPES)
					RunExecCells(sh, vlen, policy != 0, exec_cells, helper_cells);
		printf("    %u executed cells (%u of them ISA-mandated helper cells)\n", exec_cells,
		       helper_cells);
		printf("[B4] guard-fallback negative control: the helper arm credits neither counter\n");
		for (u32 vlen : {512u, 1024u})
			for (int policy : {0, 1})
				for (auto const &sh : SHAPES)
					RunGuardMissCell(sh, vlen, policy != 0, guard_miss_cells);
		printf("    %u guard-miss cells\n", guard_miss_cells);
		printf("[C] post-state oracle coverage (an empty category would pass vacuously):\n"
		       "    cells=%llu  active=%llu  vl0-no-update=%llu  tail(vta=0)=%llu  "
		       "inactive(vma=0)=%llu  prestart=%llu\n"
		       "    tail elements SKIPPED as unconstrained (vta=1)=%llu   cells with non-zero "
		       "oracle fflags=%llu\n",
		       g_cov.cells, g_cov.active_elems, g_cov.vl0_elems, g_cov.tail_tu_elems,
		       g_cov.inactive_mu_elems, g_cov.prestart_elems, g_cov.tail_skipped,
		       g_cov.fflags_nonzero);
		CHECK_MSG(g_cov.vl0_elems > 0, "[C] the vl == 0 no-update rule constrained no element");
		CHECK_MSG(g_cov.tail_tu_elems > 0, "[C] no tail element was constrained by vta = 0");
		CHECK_MSG(g_cov.inactive_mu_elems > 0,
			  "[C] no inactive body element was constrained by vma = 0");
		CHECK_MSG(g_cov.prestart_elems > 0, "[C] no prestart element was constrained");
		CHECK_MSG(g_cov.active_elems > 0, "[C] no active body element was compared");
		CHECK_MSG(g_cov.fflags_nonzero > 0,
			  "[C] the oracle never accrued a non-zero fflags, so C6 is vacuous");
		// A control that never fired would pass vacuously.
		CHECK_MSG(exec_cells > 0, "[B] ran no cell on a capable host");
		CHECK_MSG(guard_miss_cells > 0, "[B4] ran no guard-miss cell on a capable host");
		// helper_cells is NOT gated: whether any cell is an ISA-mandated helper cell is a
		// property of the guard kinds these shapes get, and for the statically-typed routes
		// built here it is legitimately zero. The negative control that must fire is B4.
	}

	printf("\nP2A_ACTIVE_CHUNK_CENSUS_TEST checks=%d failures=%d exec_cells=%u helper_cells=%u "
	       "guard_miss_cells=%u %s\n",
	       g_checks, g_failures, exec_cells, helper_cells, guard_miss_cells,
	       capable ? "HOST_AVX512" : "EMIT_ONLY_ON_THIS_HOST");
	return g_failures ? 1 : 0;
}
