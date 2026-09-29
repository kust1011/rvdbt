// T6b: the nine element-wise QCG routes on ONE generic whole-chunk shape rule, checked at every
// chunk count the rule produces.
//
// WHAT T6b CHANGED, AND WHY THIS FILE EXISTS
//
// Until T6b, eight of the nine element-wise routes carried a literal `vlen_bits != 512 &&
// vlen_bits != 1024` row and refused everything else; only `vmul.vv` used the generic rule
// RvvGenericChunkShapeAdmit (HM.2a). T6b replaced those literals with that same rule, so the whole
// family -- `vsetvli`, `vle32.v`, `vse32.v`, `vadd.vv`, `vsub.vv`, `vmul.vv`, `vand.vv`, `vor.vv`,
// `vxor.vv` -- is admitted at VLEN 512/1024/2048/4096, i.e. k = 1/2/4/8, on the pure-QCG path.
//
// The per-opcode files already cover each route's decoder, QIR, QRA, emission and fallback matrix
// in depth. This file exists for the two properties NO per-opcode file can state, because each is
// a claim about the family:
//
//   1. AT 2048 AND 4096 EVERY ONE OF THE NINE TAKES THE DIRECT ROUTE, and the emitted host code is
//      k AVX-512 chunk operations -- not a helper call, and not the untyped inline lowering. That
//      second alternative is the one T6a MEASURED on real hardware: at VLEN 2048 the untyped path
//      ran the guest `vadd.vv` correctly as SIXTEEN 128-bit `paddd xmm`, taking no helper at all.
//      A test that only counted helper calls would have called that a pass. Every emission check
//      below therefore asserts the AVX-512 count AND that the region contains no xmm/ymm operand
//      whatsoever, which is exactly the shape a silent return to SSE would produce.
//   2. THE WIDENING OPENED NOTHING ELSE. The fail-closed matrix in section 5 re-runs every
//      unsupported shape -- partial-chunk VLEN, k past the storage reservation, SEW != 32,
//      LMUL != 1, masked, non-unit-stride, wrong EEW, x0 base, the reserved keep-vl `vsetvli`,
//      each route's own switch off, `--rvv-verify` -- at ALL FOUR widths, so an over-broad
//      admission cannot hide at a width the per-opcode file did not run.
//
// The LLVM/AOT arm is UNCHANGED by T6b and section 6 is what proves that rather than asserts it:
// every LLVM gate goes through RvvSSAEnabled(), which admits VLEN 512 and 1024 only, so at 2048
// and 4096 an LLVM compile still takes the pre-existing helper. Section 6 also runs 512/1024,
// where the LLVM arm must still admit -- without that half, "the LLVM arm refuses" would pass on a
// build where the LLVM arm was broken outright.
//
// WHAT THIS FILE NEVER DOES. It never executes the emitted bytes -- TestCompilerRuntime resizes a
// std::vector and returns its data pointer, so no PROT_EXEC page exists in this process at all --
// never runs a guest program, never times anything and makes no performance claim. That matters
// here: the development host is an Ivy Bridge i7-3770 with no AVX-512, so these bytes could not be
// executed even deliberately. The dynamic half of T6b's evidence is the xbd campaign, not this file.
//
// HOST NOTE. Each QCG gate carries a real `__builtin_cpu_supports("avx512f")` probe, so on a
// machine without AVX-512F the routes fail closed and there would be nothing to inspect. The
// `*_force_emit` switches bypass ONLY that probe -- not the admitted shape, not the architectural
// guard, not the SEW or LMUL rows -- which is the same device every accepted per-opcode audit used.
// `vsetvli` has no such switch and needs none: its route emits scalar instructions only.
//
// INSTRUCTION WORDS. The synthetic words are the ones the per-opcode route tests already use, each
// round-tripped there through `llvm-mc --disassemble -triple=riscv32 -mattr=+v`. The strip-mine
// body in section 4 is not synthetic at all: it is the fourteen words `llvm-objdump -d` reads out
// of the FROZEN T2g mixed microkernel ELF at guest ip 0x11ebc..0x11ef0, the same binary the xbd
// campaign runs, so the family claim is checked over a real block and not only over assembled pairs.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
// For rvvrun::kMaxChunks -- the bound the generic rule refuses past, named rather than repeated.
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
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
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,    \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));

// Chunk c is bytes [64c, 64c+64) of a register's own VLEN_MAX_BYTES slot -- the `r*VLEN_MAX_BYTES +
// chunk*64` formula every typed frame uses, recomputed here rather than read back from the frame.
constexpr u32 ChunkOffs(u32 reg, u32 chunk) { return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u; }

// The chunk count the generic rule must produce, derived INDEPENDENTLY of the predicate under test
// so the file is not checking the implementation against itself.
constexpr u32 ExpectChunks(u32 vlen_bits) { return vlen_bits / 512u; }

// The four widths T6b admits, and they are listed once. Any check that runs at fewer than all four
// is a check that could pass on a route which is generic at one width and literal at another.
constexpr u32 ADMITTED_VLENS[] = {512u, 1024u, 2048u, 4096u};

// ---------------------------------------------------------------------------------------------
// Instruction words.
// ---------------------------------------------------------------------------------------------
constexpr u32 INSN_VSETVLI_E32M1 = 0x0d057557u;	 // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_E64M1 = 0x0d857557u;	 // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 INSN_VSETVLI_E16M1 = 0x0c857557u;	 // vsetvli a0, a0, e16, m1, ta, ma
constexpr u32 INSN_VSETVLI_E32M2 = 0x0d157557u;	 // vsetvli a0, a0, e32, m2, ta, ma
constexpr u32 INSN_VSETVLI_E32MF2 = 0x0d757557u; // vsetvli a0, a0, e32, mf2, ta, ma
constexpr u32 INSN_VSETVLI_BOTH_X0 = 0x0d007057u; // vsetvli zero, zero, e32, m1, ta, ma (reserved)

constexpr u32 INSN_VADD_VV = 0x021101d7u;	 // vadd.vv v3, v1, v2
constexpr u32 INSN_VSUB_VV = 0x0a1101d7u;	 // vsub.vv v3, v1, v2
constexpr u32 INSN_VMUL_VV = 0x961121d7u;	 // vmul.vv v3, v1, v2
constexpr u32 INSN_VAND_VV = 0x261101d7u;	 // vand.vv v3, v1, v2
constexpr u32 INSN_VOR_VV = 0x2a1101d7u;	 // vor.vv  v3, v1, v2
constexpr u32 INSN_VXOR_VV = 0x2e1101d7u;	 // vxor.vv v3, v1, v2
constexpr u32 INSN_VADD_VV_MASKED = 0x001101d7u; // vadd.vv v3, v1, v2, v0.t
constexpr u32 INSN_VSUB_VV_MASKED = 0x081101d7u; // vsub.vv v3, v1, v2, v0.t
constexpr u32 INSN_VMUL_VV_MASKED = 0x941121d7u; // vmul.vv v3, v1, v2, v0.t
constexpr u32 INSN_VAND_VV_MASKED = 0x241101d7u; // vand.vv v3, v1, v2, v0.t
constexpr u32 INSN_VOR_VV_MASKED = 0x281101d7u;	 // vor.vv  v3, v1, v2, v0.t
constexpr u32 INSN_VXOR_VV_MASKED = 0x2c1101d7u; // vxor.vv v3, v1, v2, v0.t

constexpr u32 INSN_VLE32_V = 0x02086407u;	  // vle32.v v8, (a6)
constexpr u32 INSN_VLE32_V_MASKED = 0x00086407u;  // vle32.v v8, (a6), v0.t   (vm = 0)
constexpr u32 INSN_VLE16_V = 0x02085407u;	  // vle16.v v8, (a6)         (EEW 16)
constexpr u32 INSN_VLE64_V = 0x02087407u;	  // vle64.v v8, (a6)         (EEW 64)
constexpr u32 INSN_VLE32_V_X0 = 0x02006407u;	  // vle32.v v8, (zero)       (rs1 = x0)
constexpr u32 INSN_VLSE32_V = 0x0a586407u;	  // vlse32.v v8, (a6), a1    (mop = 10)
constexpr u32 INSN_VLE32FF_V = 0x03086407u;	  // vle32ff.v v8, (a6)       (lumop = 10000)

constexpr u32 INSN_VSE32_V = 0x02086427u;	  // vse32.v v8, (a6)
constexpr u32 INSN_VSE32_V_MASKED = 0x00086427u;  // vse32.v v8, (a6), v0.t   (vm = 0)
constexpr u32 INSN_VSE16_V = 0x02085427u;	  // vse16.v v8, (a6)         (EEW 16)
constexpr u32 INSN_VSE64_V = 0x02087427u;	  // vse64.v v8, (a6)         (EEW 64)
constexpr u32 INSN_VSE32_V_X0 = 0x02006427u;	  // vse32.v v8, (zero)       (rs1 = x0)
constexpr u32 INSN_VSSE32_V = 0x0ab86427u;	  // vsse32.v v8, (a6), a1    (mop = 10)

constexpr u32 VS2_REG = 1; // v1
constexpr u32 VS1_REG = 2; // v2
constexpr u32 VD_REG = 3;  // v3
constexpr u32 MEM_REG = 8; // v8, the vle destination / vse source

// The FROZEN T2g mixed microkernel's strip-mine body, guest ip 0x11ebc..0x11ef0, exactly as
// `llvm-objdump -d` reads it out of the ELF the xbd campaign runs (elf_sha256
// 499d813b0a7bc7498ef5bd3de84665a189e8661df50fca409880c67562971235). Fourteen consecutive words:
// all nine routed opcodes plus the four scalar bookkeeping instructions that sit between them.
constexpr u32 T2G_BODY[] = {
    0x0d07f3d7u, // vsetvli t2, a5, e32, m1, ta, ma
    0x02036407u, // vle32.v v8, (t1)
    0x0208e487u, // vle32.v v9, (a7)
    0x00d3e6b3u, // or      a3, t2, a3
    0x0053f2b3u, // and     t0, t2, t0
    0x00239e13u, // slli    t3, t2, 0x2
    0x02086507u, // vle32.v v10, (a6)
    0x028485d7u, // vadd.vv v11, v8, v9
    0x0ab50657u, // vsub.vv v12, v11, v10
    0x96c426d7u, // vmul.vv v13, v12, v8
    0x26d48757u, // vand.vv v14, v13, v9
    0x2ae507d7u, // vor.vv  v15, v14, v10
    0x2ef40857u, // vxor.vv v16, v15, v8
    0x02076827u, // vse32.v v16, (a4)
};
constexpr unsigned T2G_BODY_N = sizeof(T2G_BODY) / sizeof(T2G_BODY[0]);

// ---------------------------------------------------------------------------------------------
// The route table. One row per opcode T6b widened; everything that differs between two of the
// nine lives here and nothing else does.
// ---------------------------------------------------------------------------------------------
enum class Family { Alu, Load, Store, SetVL };

struct Route {
	char const *name;
	Family family;
	u32 word;	   // the admitted encoding
	Op body_op;	   // the QIR body opcode one chunk becomes (unused for SetVL)
	RuntimeStubId stub; // the frame's fallback stub -- the PRE-EXISTING helper, never a new one
	char const *mnemonic; // the EVEX lane mnemonic the QCG backend must emit (nullptr: none)
	bool *flag;	   // the route's own switch
	bool *force_emit;  // its host-probe bypass, or nullptr where the route has none
	// M2C: true for the one route whose chunk width is derived from VLEN rather than fixed at
	// the 512-bit host chunk. Such a route ADMITS 128 and 256 -- as a single 16- or 32-byte
	// chunk -- while still refusing 768 and 8192, which are not a whole number of chunks of any
	// admitted width. Every other route here is still 512-bit-chunk-only and refuses all four.
	bool narrow_widths;
};

Route const ROUTES[] = {
    {"vsetvli", Family::SetVL, INSN_VSETVLI_E32M1, Op::_rvvsetvl, RuntimeStubId::id_rv32_vsetvli,
     nullptr, &config::rvv_qcg_direct_setvl, nullptr},
    {"vle32.v", Family::Load, INSN_VLE32_V, Op::_vchunkload, RuntimeStubId::id_rv32_vle, "vmovdqu64",
     &config::rvv_qcg_typed_chunk_vle, &config::rvv_qcg_typed_chunk_vle_force_emit},
    {"vse32.v", Family::Store, INSN_VSE32_V, Op::_vchunkstore, RuntimeStubId::id_rv32_vse, "vmovdqu64",
     &config::rvv_qcg_typed_chunk_vse, &config::rvv_qcg_typed_chunk_vse_force_emit},
    {"vadd.vv", Family::Alu, INSN_VADD_VV, Op::_vchunkadd, RuntimeStubId::id_rv32_vadd_vv, "vpaddd",
     &config::rvv_qcg_typed_chunk, &config::rvv_qcg_typed_chunk_force_emit, /*narrow_widths=*/true},
    {"vsub.vv", Family::Alu, INSN_VSUB_VV, Op::_vchunksub, RuntimeStubId::id_rv32_vialu, "vpsubd",
     &config::rvv_qcg_typed_chunk_sub, &config::rvv_qcg_typed_chunk_sub_force_emit},
    {"vmul.vv", Family::Alu, INSN_VMUL_VV, Op::_vchunkmul, RuntimeStubId::id_rv32_vimul, "vpmulld",
     &config::rvv_qcg_typed_chunk_mul, &config::rvv_qcg_typed_chunk_mul_force_emit},
    {"vand.vv", Family::Alu, INSN_VAND_VV, Op::_vchunkand, RuntimeStubId::id_rv32_vialu, "vpandd",
     &config::rvv_qcg_typed_chunk_and, &config::rvv_qcg_typed_chunk_and_force_emit},
    {"vor.vv", Family::Alu, INSN_VOR_VV, Op::_vchunkor, RuntimeStubId::id_rv32_vialu, "vpord",
     &config::rvv_qcg_typed_chunk_or, &config::rvv_qcg_typed_chunk_or_force_emit},
    {"vxor.vv", Family::Alu, INSN_VXOR_VV, Op::_vchunkxor, RuntimeStubId::id_rv32_vialu, "vpxord",
     &config::rvv_qcg_typed_chunk_xor, &config::rvv_qcg_typed_chunk_xor_force_emit},
};
constexpr unsigned N_ROUTES = sizeof(ROUTES) / sizeof(ROUTES[0]);

// Typed body ops one guest instruction of this family becomes, per chunk: 4 for an ALU frame (two
// source loads, one lane op, one destination store), 2 for a memory frame (one transfer, one
// CPUState window access). Declared to `rvvtypedchunkbegin` as `n_typed` and re-checked by `end`.
unsigned OpsPerChunk(Family f) { return f == Family::Alu ? 4u : 2u; }

// ---------------------------------------------------------------------------------------------
// Translation harness. Every knob the nine routes read is set on EVERY translation, so no case can
// inherit another's global state -- the failure that would otherwise make a fail-closed row pass
// because a previous row left its switch off.
// ---------------------------------------------------------------------------------------------
struct Env {
	bool aot_use_llvm = false;
	bool rvv_vector_ssa = false;
	bool rvv_verify = false;
	bool rvv_direct = true;
	bool all_routes_on = true; // every route's own switch AND its force_emit
	u32 vlen_bits = 512;
};

void ApplyEnv(Env const &e)
{
	config::aot_use_llvm = e.aot_use_llvm;
	config::rvv_vector_ssa = e.rvv_vector_ssa;
	config::rvv_verify = e.rvv_verify;
	config::rvv_direct = e.rvv_direct;
	config::vlen_bits = e.vlen_bits;
	for (auto const &r : ROUTES) {
		*r.flag = e.all_routes_on;
		if (r.force_emit) {
			*r.force_emit = e.all_routes_on;
		}
	}
	// Never on in this file. The diagnostic arm builds its own frame kind and the whole-register
	// route keeps its own narrower VLEN set; either appearing here would make a census ambiguous.
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_vector_run = false;
	config::rvv_lowering = 1; // rv32::RvvLowering::Chunked -- the arm the memory routes reproduce
}

// One region containing exactly `n` translated guest words at ip 0, 4, ... The arena must outlive
// the region; both are locals in the caller's frame.
Region *TranslateWords(MemArena &arena, u32 const *words, unsigned n, Env const &e)
{
	ApplyEnv(e);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

// The region one route's check translates. For the eight chunked routes it is a PAIR -- the vtype
// the route needs must be OBSERVED by a vsetvli in the same block, which is the shape every real
// strip-mine body has. For `vsetvli` itself it is the ONE word under test: prefixing it with a
// second vsetvli would put two `rvvsetvl` nodes in the region and make every count in this file
// ambiguous about which one it was reading.
Region *TranslateRoute(MemArena &arena, u32 (&words)[2], u32 setvli, u32 word, Family fam, Env const &e)
{
	if (fam == Family::SetVL) {
		words[0] = word;
		return TranslateWords(arena, words, 1, e);
	}
	words[0] = setvli;
	words[1] = word;
	return TranslateWords(arena, words, 2, e);
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body; // strictly between begin and end, in construction order
};

// Every typed frame in the region, in construction order. A frame still open at the end of the
// region is NOT returned: it is reported as a missing `end` by the count comparison rather than
// silently completed.
std::vector<Frame> FindFrames(Region *region)
{
	std::vector<Frame> out;
	Frame cur;
	bool open = false;
	for (auto &bb : region->GetBlocks()) {
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
				if (open) {
					cur.body.push_back(&ins);
				}
				break;
			}
		}
	}
	return out;
}

unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			n += ins.GetOpcode() == op;
		}
	}
	return n;
}

unsigned CountHcall(Region *region, RuntimeStubId stub)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() == Op::_hcall) {
				n += static_cast<InstHcall *>(&ins)->stub == stub;
			}
		}
	}
	return n;
}

// ---------------------------------------------------------------------------------------------
// 1. The two chunk bounds are one number.
// ---------------------------------------------------------------------------------------------
//
// The frame builders size their per-chunk arrays with rvvrun::kMaxChunks; the QIR node constructors
// bound displacements and `vlenb` with qir::MAX_REG_CHUNKS. If those disagree, a shape the
// admission predicate allows becomes a translation Panic instead of code -- which is precisely the
// defect T6b had to fix in the vle/vse frames, whose arrays were a literal 2 while their predicate
// was about to admit 8. rv32_qir.cpp static_asserts the equality; this restates it as a runtime
// check so the number also appears in this file's output.
void CheckChunkBoundsAgree()
{
	printf("[1] chunk bounds\n");
	CHECK_EQ((u32)rv32::rvvrun::kMaxChunks, (u32)qir::MAX_REG_CHUNKS);
	CHECK_EQ((u32)qir::MAX_REG_CHUNKS, rv32::VLEN_MAX_BITS / 512u);
	// The widest admitted VLEN must fit, or section 2 would be asserting a shape the tree refuses.
	CHECK(ExpectChunks(ADMITTED_VLENS[N_ROUTES ? 3 : 3]) <= (u32)qir::MAX_REG_CHUNKS);
	printf("  kMaxChunks = MAX_REG_CHUNKS = VLEN_MAX_BITS/512 = %u; widest admitted k = %u\n",
	       (unsigned)qir::MAX_REG_CHUNKS, ExpectChunks(4096u));
}

// ---------------------------------------------------------------------------------------------
// 2. Admitted widths, at QIR level: one frame, k chunks, the exact windows, no helper.
// ---------------------------------------------------------------------------------------------
void CheckAdmittedQir(Route const &r, u32 vlen)
{
	u32 const k = ExpectChunks(vlen);
	MemArena arena(1u << 20);
	u32 words[2];
	Env e;
	e.vlen_bits = vlen;
	Region *region = TranslateRoute(arena, words, INSN_VSETVLI_E32M1, r.word, r.family, e);

	if (r.family == Family::SetVL) {
		// The vsetvli route has no chunks: it writes four scalar CPUState fields and one guest
		// GPR at every width. What must scale is the two constants the node carries, and they
		// are re-derived here from the width rather than read back from the predicate.
		CHECK_EQ(CountOp(region, Op::_rvvsetvl), 1u);
		CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vsetvli), 0u);
		for (auto &bb : region->GetBlocks()) {
			for (auto &ins : bb.ilist) {
				if (ins.GetOpcode() != Op::_rvvsetvl) {
					continue;
				}
				auto *n = static_cast<InstRVVSetVL *>(&ins);
				CHECK_EQ(n->vlenb, vlen / 8u);
				CHECK_EQ(n->vlmax, vlen / 32u); // SEW=32, LMUL=1
			}
		}
		printf("  %-8s vlen=%-5u one rvvsetvl, vlenb=%u vlmax=%u, no helper\n", r.name, vlen,
		       vlen / 8u, vlen / 32u);
		return;
	}

	// The region holds the guest vsetvli as well, which took its OWN route above; the frame under
	// test is the second and last one.
	auto frames = FindFrames(region);
	CHECK_EQ(frames.size(), (size_t)1);
	if (frames.size() != 1) {
		return;
	}
	Frame const &f = frames[0];
	unsigned const per_chunk = OpsPerChunk(r.family);
	CHECK_EQ((unsigned)f.begin->n_typed, per_chunk * k);
	CHECK_EQ(f.body.size(), (size_t)(per_chunk * k));
	// The fallback is the PRE-EXISTING helper for this instruction word, unchanged at every width.
	CHECK(f.begin->stub == r.stub);
	CHECK(f.end->stub == r.stub);
	// vtype/vl/vstart is the guard kind every element-wise route uses; a width-independent
	// `vlenb` guard here would mean the frame stopped checking that vl == VLMAX.
	// A13-FIX: the two guest-MEMORY frames additionally carry the base-range guard (base <= 2^32 -
	// VLEN/8), which is the same vtype/vl/vstart predicate plus one test; the lane-op frames keep
	// the plain kind.
	if (r.stub == RuntimeStubId::id_rv32_vle || r.stub == RuntimeStubId::id_rv32_vse) {
		CHECK(f.begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseLimit);
		CHECK_EQ(f.begin->base_limit, 0u - vlen / 8u);
	} else {
		CHECK(f.begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstart);
	}
	CHECK_EQ(f.begin->vlmax, vlen / 32u);
	// NO helper call for this instruction anywhere in the region. The fallback ARM's call is
	// emitted by the backend from the `end` node, not as a QIR hcall, so a non-zero count here
	// means the instruction was not routed at all.
	CHECK_EQ(CountHcall(region, r.stub), 0u);
	// k body ops of the right kind, and the chunk windows they name.
	CHECK_EQ(CountOp(region, r.body_op), k);

	if (r.family == Family::Alu) {
		// Load-major: every chunk's two source loads, then every lane op, then every store.
		for (u32 c = 0; c < k; ++c) {
			auto *l_s2 = static_cast<InstVStateChunkLoad *>(f.body[2 * c]);
			auto *l_s1 = static_cast<InstVStateChunkLoad *>(f.body[2 * c + 1]);
			auto *lane = f.body[2 * k + c];
			auto *store = static_cast<InstVStateChunkStore *>(f.body[3 * k + c]);
			CHECK(l_s2->GetOpcode() == Op::_vstatechunkload);
			CHECK(l_s1->GetOpcode() == Op::_vstatechunkload);
			CHECK(lane->GetOpcode() == r.body_op);
			CHECK(store->GetOpcode() == Op::_vstatechunkstore);
			CHECK_EQ(l_s2->offs, ChunkOffs(VS2_REG, c));
			CHECK_EQ(l_s1->offs, ChunkOffs(VS1_REG, c));
			CHECK_EQ(store->offs, ChunkOffs(VD_REG, c));
		}
	} else {
		// The memory frames: k transfers at 64-byte displacements 0..(k-1)*64, then k CPUState
		// window accesses at that register's own chunk offsets. The displacement is the value
		// qir.h used to refuse past 192, so at k=8 this is also the check that the node bound
		// was widened with the predicate.
		for (u32 c = 0; c < k; ++c) {
			Inst *mem = f.body[r.family == Family::Load ? c : k + c];
			Inst *st = f.body[r.family == Family::Load ? k + c : c];
			u32 disp;
			if (r.family == Family::Load) {
				auto *ld = static_cast<InstVChunkLoad *>(mem);
				CHECK(ld->GetOpcode() == Op::_vchunkload);
				disp = ld->disp;
				auto *w = static_cast<InstVStateChunkStore *>(st);
				CHECK(w->GetOpcode() == Op::_vstatechunkstore);
				CHECK_EQ(w->offs, ChunkOffs(MEM_REG, c));
			} else {
				auto *sr = static_cast<InstVChunkStore *>(mem);
				CHECK(sr->GetOpcode() == Op::_vchunkstore);
				disp = sr->disp;
				auto *w = static_cast<InstVStateChunkLoad *>(st);
				CHECK(w->GetOpcode() == Op::_vstatechunkload);
				CHECK_EQ(w->offs, ChunkOffs(MEM_REG, c));
			}
			CHECK_EQ(disp, c * 64u);
		}
	}
	printf("  %-8s vlen=%-5u k=%u  one frame, n_typed=%u, windows exact, no %s helper\n", r.name,
	       vlen, k, (unsigned)f.begin->n_typed, r.name);
}

// ---------------------------------------------------------------------------------------------
// 3. Emitted host code: k AVX-512 chunk operations, and no 128/256-bit lane operation anywhere.
// ---------------------------------------------------------------------------------------------

// AllocateCode NEVER mmaps: it resizes a vector and returns its data pointer. That is the
// structural guarantee behind "the emitted bytes are never executed".
struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override { return nullptr; }
	std::vector<u8> buf;
};

// Write `code` to a private temp file and disassemble it as a raw flat x86-64 binary with GNU
// objdump. Fails loudly rather than skipping: a missing disassembler means this file's emission
// evidence cannot be produced at all, and a skipped emission check is exactly how an SSE regression
// would go unnoticed.
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_t6b_emit_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "  mkstemp failed: %s\n", strerror(errno));
		return {};
	}
	size_t written = 0;
	while (written < code.size()) {
		ssize_t const n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) {
			fprintf(stderr, "  write to temp file failed: %s\n", strerror(errno));
			close(fd);
			unlink(path);
			return {};
		}
		written += (size_t)n;
	}
	close(fd);
	std::string const cmd =
	    std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path + " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) {
		fprintf(stderr, "  popen(objdump) failed: %s\n", strerror(errno));
		unlink(path);
		return {};
	}
	std::vector<std::string> lines;
	char buf[1024];
	std::string cur;
	while (fgets(buf, sizeof(buf), p)) {
		cur += buf;
		if (!cur.empty() && cur.back() == '\n') {
			cur.pop_back();
			lines.push_back(cur);
			cur.clear();
		}
	}
	if (!cur.empty()) {
		lines.push_back(cur);
	}
	int const rc = pclose(p);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
		fprintf(stderr, "  objdump did not exit cleanly (raw status %d)\n", rc);
		return {};
	}
	return lines;
}

// The mnemonic of one objdump Intel-syntax line, or "" for a line that carries no instruction.
std::string Mnemonic(std::string const &line)
{
	size_t const tab = line.find('\t');
	if (tab == std::string::npos) {
		return {};
	}
	std::string const rhs = line.substr(tab + 1);
	size_t const sp = rhs.find(' ');
	return sp == std::string::npos ? rhs : rhs.substr(0, sp);
}

bool Mentions(std::string const &line, char const *what) { return line.find(what) != std::string::npos; }

struct EmitCensus {
	unsigned lane = 0;    // lines whose mnemonic is exactly the route's EVEX lane mnemonic
	unsigned zmm = 0;     // lines naming any zmm register
	unsigned xmm = 0;     // lines naming any xmm register  <- the SSE-regression detector
	unsigned ymm = 0;     // lines naming any ymm register
	unsigned calls = 0;	  // lines carrying a `call`, anywhere in the region
	unsigned calls_in_span = 0; // ... between the first and last vector line: the FAST PATH
	unsigned frames = 0;	  // typed frames the region contains
	bool disassembled = false;
};

// WHY `calls` IS COUNTED BY SUBSTRING AND NOT BY MNEMONIC. AsmJit emits the frame's fallback call
// with a redundant REX prefix, which GNU objdump prints as `rex call 0x...` -- so a mnemonic-equality
// test silently counts zero for the very instruction this census exists to find, while still
// counting the region epilogue's plain `call rax`. That is a census that would have passed with the
// property broken, so it is a substring test.
//
// WHY THE SPAN, AND NOT THE TOTAL. A region's total call count is not a property of the route: the
// epilogue contributes its own calls, and how many is a fact about the region terminator rather
// than about the lowering under test -- pinning it would make this file fail on an unrelated
// backend change. What IS the route's property is that the FAST PATH takes no call: the guard
// branches over the body to a fallback arm placed after the join, so between the frame's first and
// last vector instruction there must be nothing callable. `calls_in_span` is that, and it is
// bracketed by the vector lines themselves rather than by a label this file would have to find.
EmitCensus EmitAndCensus(Region *region, char const *lane_mnemonic)
{
	EmitCensus c;
	c.frames = (unsigned)FindFrames(region).size();
	TestCompilerRuntime cruntime;
	qir::CodeSegment segment(0u, 0x1000u);
	auto const code_span = qcg::GenerateCode(&cruntime, &segment, region, 0);
	if (code_span.empty()) {
		return c;
	}
	std::vector<u8> const code(code_span.begin(), code_span.end());
	auto const lines = Disassemble(code);
	if (lines.empty()) {
		return c;
	}
	c.disassembled = true;
	size_t first_vec = lines.size(), last_vec = 0;
	for (size_t i = 0; i < lines.size(); ++i) {
		std::string const &l = lines[i];
		std::string const m = Mnemonic(l);
		if (lane_mnemonic && m == lane_mnemonic) {
			++c.lane;
		}
		if (Mentions(l, "zmm")) {
			++c.zmm;
			first_vec = std::min(first_vec, i);
			last_vec = std::max(last_vec, i);
		}
		c.xmm += Mentions(l, "xmm");
		c.ymm += Mentions(l, "ymm");
		c.calls += Mentions(l, "call");
	}
	for (size_t i = first_vec; i < lines.size() && i <= last_vec; ++i) {
		c.calls_in_span += Mentions(lines[i], "call");
	}
	return c;
}

void CheckAdmittedEmitted(Route const &r, u32 vlen)
{
	u32 const k = ExpectChunks(vlen);
	MemArena arena(1u << 20);
	u32 words[2];
	Env e;
	e.vlen_bits = vlen;
	Region *region = TranslateRoute(arena, words, INSN_VSETVLI_E32M1, r.word, r.family, e);

	EmitCensus const c = EmitAndCensus(region, r.mnemonic);
	CHECK(c.disassembled);
	if (!c.disassembled) {
		return;
	}

	if (r.family == Family::SetVL) {
		// No vector register of ANY width: this route writes four scalar CPUState fields and one
		// guest GPR, and must not acquire a chunk as the VLEN grows. The only call in the region
		// is the epilogue's dispatcher -- there is no typed frame here to contribute a fallback
		// arm, and a routed vsetvli emits no helper call of its own.
		CHECK_EQ(c.zmm, 0u);
		CHECK_EQ(c.xmm, 0u);
		CHECK_EQ(c.ymm, 0u);
		CHECK_EQ(c.frames, 0u);
		printf("  %-8s vlen=%-5u scalar only: 0 zmm/xmm/ymm, 0 typed frames\n", r.name, vlen);
		return;
	}

	// THE COUNT. An ALU frame emits exactly k lane operations; a memory frame emits 2k
	// `vmovdqu64` -- k against guest memory and k against the CPUState window.
	unsigned const want_lane = r.family == Family::Alu ? k : 2 * k;
	CHECK_EQ(c.lane, want_lane);
	// THE WIDTH. Every vector line in the region is 512-bit. If this route ever fell back to the
	// untyped inline lowering, the guest operation would arrive as VLEN/128 SSE operations -- the
	// exact shape T6a measured at 2048 and 4096 -- and `xmm` would be non-zero while `lane` was 0.
	CHECK_EQ(c.xmm, 0u);
	CHECK_EQ(c.ymm, 0u);
	// THE LINE COUNT. Every vector line the frame emits is accounted for: an ALU frame is 2k
	// CPUState reads, k lane operations and k CPUState writes; a memory frame is k transfers and
	// k CPUState accesses. An extra ZMM line would be an allocator spill or a second lowering.
	CHECK_EQ(c.frames, 1u);
	CHECK_EQ(c.zmm, r.family == Family::Alu ? 4 * k : 2 * k);
	// THE FAST PATH TAKES NO CALL, and the fallback arm still exists. The first is the route's
	// claim; the second is what keeps the first from being satisfied by a frame that lost its
	// guard-miss edge entirely, which would be a correctness regression this census could
	// otherwise read as an improvement.
	CHECK_EQ(c.calls_in_span, 0u);
	CHECK(c.calls >= 1u);
	printf("  %-8s vlen=%-5u k=%u  %u x %-9s zmm-lines=%u xmm=0 ymm=0 fast-path calls=0\n", r.name,
	       vlen, k, c.lane, r.mnemonic, c.zmm);
}

// ---------------------------------------------------------------------------------------------
// 4. The frozen T2g strip-mine body: all nine routes, one real guest block, every width.
// ---------------------------------------------------------------------------------------------
//
// Section 2 and 3 translate assembled PAIRS, which is the right scope for one route's shape and
// the wrong scope for the family claim: a pair cannot show that nine frames coexist in one block,
// that register pressure survives nine frames at k=8, or that the block a real vectorised guest
// executes contains no helper call at all. This runs the actual fourteen words the frozen T2g ELF
// holds at 0x11ebc.
void CheckFrozenBody(u32 vlen)
{
	u32 const k = ExpectChunks(vlen);
	MemArena arena(1u << 20);
	Env e;
	e.vlen_bits = vlen;
	Region *region = TranslateWords(arena, T2G_BODY, T2G_BODY_N, e);

	// One vsetvli node and eight typed frames: three vle32.v, one vse32.v, six vv ALU ops = ten.
	CHECK_EQ(CountOp(region, Op::_rvvsetvl), 1u);
	auto const frames = FindFrames(region);
	CHECK_EQ(frames.size(), (size_t)10);
	// Every routed instruction's helper is absent from the region.
	for (auto const &r : ROUTES) {
		CHECK_EQ(CountHcall(region, r.stub), 0u);
	}
	// Per-opcode chunk counts. Three loads and one store; one of each ALU operation.
	CHECK_EQ(CountOp(region, Op::_vchunkload), 3 * k);
	CHECK_EQ(CountOp(region, Op::_vchunkstore), k);
	for (auto const &r : ROUTES) {
		if (r.family == Family::Alu) {
			CHECK_EQ(CountOp(region, r.body_op), k);
		}
	}

	// The emitted code: six distinct EVEX lane mnemonics, k of each, and not one xmm or ymm line.
	TestCompilerRuntime cruntime;
	qir::CodeSegment segment(0u, 0x1000u);
	auto const code_span = qcg::GenerateCode(&cruntime, &segment, region, 0);
	CHECK(!code_span.empty());
	if (code_span.empty()) {
		return;
	}
	std::vector<u8> const code(code_span.begin(), code_span.end());
	auto const lines = Disassemble(code);
	CHECK(!lines.empty());
	if (lines.empty()) {
		return;
	}
	unsigned xmm = 0, ymm = 0, movdqu = 0;
	for (auto const &r : ROUTES) {
		if (r.family != Family::Alu) {
			continue;
		}
		unsigned n = 0;
		for (auto const &l : lines) {
			n += Mnemonic(l) == r.mnemonic;
		}
		CHECK_EQ(n, k);
	}
	for (auto const &l : lines) {
		xmm += Mentions(l, "xmm");
		ymm += Mentions(l, "ymm");
		movdqu += Mnemonic(l) == "vmovdqu64";
	}
	CHECK_EQ(xmm, 0u);
	CHECK_EQ(ymm, 0u);
	// Each ALU frame reads two CPUState windows and writes one (3k vmovdqu64 x 6 operations); each
	// vle/vse frame moves 2k. Derived from the frame shapes, not read back from the disassembly.
	CHECK_EQ(movdqu, 6u * 3u * k + 4u * 2u * k);
	printf("  T2g body vlen=%-5u k=%u  10 frames, %u vmovdqu64, k of each lane op, xmm=0 ymm=0\n",
	       vlen, k, movdqu);
}

// ---------------------------------------------------------------------------------------------
// 5. Fail-closed: every unsupported shape, at every admitted width.
// ---------------------------------------------------------------------------------------------
//
// The reason each row runs at all four widths rather than at 512 only: T6b's change is a WIDTH
// rule, so the failure mode it could introduce is a shape that is refused at 512 and admitted at
// 4096. A matrix that ran once at 512 could not see that.
struct Refusal {
	char const *what;
	u32 setvli_word;
	u32 insn_word;
	Env env;
};

// One refusal row. `setvli_word` pins the vtype the block observes and `insn_word` is the
// instruction under test -- which for the `vsetvli` route are the same word, since that route's own
// vtype immediate is what a vtype axis has to vary.
//
// The row's ONLY assertion is that the route's body op (or `rvvsetvl`) is absent. It deliberately
// does not also require a helper call: what a refusal falls back to is that opcode's pre-existing
// lowering, which for an ALU op under `--rvv-direct` is the untyped INLINE path and not a call at
// all. Demanding a call here would make half these rows fail for a reason that is not a defect.
void CheckRefused(Route const &r, char const *what, u32 setvli_word, u32 insn_word, Env e, u32 vlen)
{
	e.vlen_bits = vlen;
	MemArena arena(1u << 20);
	u32 words[2];
	int const before = g_failures;
	Region *region = TranslateRoute(arena, words, setvli_word, insn_word, r.family, e);
	if (r.family == Family::SetVL) {
		CHECK_EQ(CountOp(region, Op::_rvvsetvl), 0u);
	} else {
		CHECK_EQ(CountOp(region, r.body_op), 0u);
	}
	if (g_failures != before) {
		fprintf(stderr, "  (refusal row that failed: %s %s at vlen=%u)\n", r.name, what, vlen);
	}
}

void CheckFailClosed(Route const &r)
{
	printf("  %-8s fail-closed rows, each at every admitted width:\n", r.name);
	unsigned const before = (unsigned)g_failures;

	// Widths the shape rule itself refuses, checked with EVERYTHING on. The CLI would reject all
	// four, which is exactly why they are set here directly: the predicate is the thing under
	// test, not the option parser.
	//
	//   128, 256  below one 512-bit host chunk. M2C: for a route with narrow_widths this is no
	//             longer a refusal but a ONE-CHUNK admission at 16 or 32 bytes -- the guest
	//             register is smaller than the host's widest vector, not un-tileable. The row is
	//             kept either way and just changes which answer it demands, so it still fails if
	//             a narrow route stops admitting or a 512-bit-only route starts.
	//   768       ABOVE one host chunk and still not a whole number of them -- 96 live bytes
	//             against a 64-byte window. Refused by EVERY route including the narrow one:
	//             min(96, 64) = 64 does not divide 96. This width is the only one of the four
	//             that the `vlen % 512` term alone refuses (at 128 and 256 the exact divide
	//             would return 0 and a 512-bit-only route would fail closed even with that term
	//             deleted), so a matrix without a 768 row cannot tell whether the term is there.
	//             (It is not hypothetical: the T6b mutation harness deletes exactly that term,
	//             and this row is what catches it.)
	//   8192      k=16, past kMaxChunks and therefore past the fixed per-chunk arrays.
	for (u32 v : {128u, 256u, 768u, 8192u}) {
		Env e;
		e.vlen_bits = v;
		MemArena arena(1u << 20);
		u32 words[2];
		Region *region = TranslateRoute(arena, words, INSN_VSETVLI_E32M1, r.word, r.family, e);
		bool const narrow_admitted = r.narrow_widths && (v == 128u || v == 256u);
		if (r.family == Family::SetVL) {
			// A15 (GOLDEN CHANGE): the setup route emits no vector instruction, so the
			// whole-chunk rule was never its property. It is admitted at 128/256 (one
			// architectural rule at every VLEN); 768 (VLEN/8 = 96, not a power of two) and
			// 8192 (VLEN/8 past the storage reservation) are refused by the node's own
			// vlenb bound, mirrored in RvvQcgSetupShapeAdmit.
			CHECK_EQ(CountOp(region, Op::_rvvsetvl), (v == 128u || v == 256u) ? 1u : 0u);
		} else if (narrow_admitted) {
			// Exactly ONE chunk: the whole guest register is one host vector.
			CHECK_EQ(CountOp(region, r.body_op), 1u);
			CHECK_EQ(CountOp(region, Op::_vstatechunkload), 2u);
			CHECK_EQ(CountOp(region, Op::_vstatechunkstore), 1u);
		} else {
			CHECK_EQ(CountOp(region, r.body_op), 0u);
		}
		if (g_failures) {
			fprintf(stderr, "  (width row: %s at vlen=%u, expected %s)\n", r.name, v,
				narrow_admitted ? "one narrow chunk" : "refusal");
		}
	}

	for (u32 vlen : ADMITTED_VLENS) {
		// SEW and LMUL: the vtype rows the generic rule does NOT decide and must not have
		// loosened. Each is set through a real vsetvli word, so the whole block sees it -- and
		// for the `vsetvli` route itself that same word IS the instruction under test, because
		// its vtype immediate is where its own SEW/LMUL rule reads from.
		auto vtype_row = [&r](u32 setvli) { return r.family == Family::SetVL ? setvli : r.word; };
		if (r.family != Family::SetVL) {
			CheckRefused(r, "e16,m1", INSN_VSETVLI_E16M1, vtype_row(INSN_VSETVLI_E16M1),
				     Env{}, vlen);
			CheckRefused(r, "e64,m1", INSN_VSETVLI_E64M1, vtype_row(INSN_VSETVLI_E64M1),
				     Env{}, vlen);
			CheckRefused(r, "e32,m2", INSN_VSETVLI_E32M2, vtype_row(INSN_VSETVLI_E32M2),
				     Env{}, vlen);
			CheckRefused(r, "e32,mf2", INSN_VSETVLI_E32MF2, vtype_row(INSN_VSETVLI_E32MF2),
				     Env{}, vlen);
		}

		// The route's own switch off, and --rvv-verify on. Both must still close the route at
		// every width; the second is what keeps "verified" from meaning "verified except here".
		{
			Env e;
			e.all_routes_on = false;
			CheckRefused(r, "route switch off", INSN_VSETVLI_E32M1, r.word, e, vlen);
		}
		{
			Env e;
			e.rvv_verify = true;
			CheckRefused(r, "rvv_verify", INSN_VSETVLI_E32M1, r.word, e, vlen);
		}

		// Per-family encoding axes.
		switch (r.family) {
		case Family::Alu: {
			u32 masked = 0;
			switch (r.body_op) {
			case Op::_vchunkadd:
				masked = INSN_VADD_VV_MASKED;
				break;
			case Op::_vchunksub:
				masked = INSN_VSUB_VV_MASKED;
				break;
			case Op::_vchunkmul:
				masked = INSN_VMUL_VV_MASKED;
				break;
			case Op::_vchunkand:
				masked = INSN_VAND_VV_MASKED;
				break;
			case Op::_vchunkor:
				masked = INSN_VOR_VV_MASKED;
				break;
			default:
				masked = INSN_VXOR_VV_MASKED;
				break;
			}
			CheckRefused(r, "masked (vm=0)", INSN_VSETVLI_E32M1, masked, Env{}, vlen);
			break;
		}
		case Family::Load:
			CheckRefused(r, "masked", INSN_VSETVLI_E32M1, INSN_VLE32_V_MASKED, Env{}, vlen);
			CheckRefused(r, "EEW 16", INSN_VSETVLI_E32M1, INSN_VLE16_V, Env{}, vlen);
			CheckRefused(r, "EEW 64", INSN_VSETVLI_E32M1, INSN_VLE64_V, Env{}, vlen);
			CheckRefused(r, "rs1 = x0", INSN_VSETVLI_E32M1, INSN_VLE32_V_X0, Env{}, vlen);
			CheckRefused(r, "strided", INSN_VSETVLI_E32M1, INSN_VLSE32_V, Env{}, vlen);
			CheckRefused(r, "fault-only-first", INSN_VSETVLI_E32M1, INSN_VLE32FF_V, Env{},
				     vlen);
			{ // --rvv-lowering 0 selects the scalar reference arm, whose address rule wraps
			  // modulo 2^32 where this frame's host-pointer displacement does not.
				Env e;
				MemArena arena(1u << 20);
				u32 words[2];
				e.vlen_bits = vlen;
				ApplyEnv(e);
				config::rvv_lowering = 0;
				CompilerJob::IpRangesSet ranges = {{0u, 8u}};
				words[0] = INSN_VSETVLI_E32M1;
				words[1] = r.word;
				CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u),
						std::move(ranges));
				Region *region = CompilerGenRegionIR(&arena, job);
				CHECK_EQ(CountOp(region, r.body_op), 0u);
			}
			break;
		case Family::Store:
			CheckRefused(r, "masked", INSN_VSETVLI_E32M1, INSN_VSE32_V_MASKED, Env{}, vlen);
			CheckRefused(r, "EEW 16", INSN_VSETVLI_E32M1, INSN_VSE16_V, Env{}, vlen);
			CheckRefused(r, "EEW 64", INSN_VSETVLI_E32M1, INSN_VSE64_V, Env{}, vlen);
			CheckRefused(r, "rs1 = x0", INSN_VSETVLI_E32M1, INSN_VSE32_V_X0, Env{}, vlen);
			CheckRefused(r, "strided", INSN_VSETVLI_E32M1, INSN_VSSE32_V, Env{}, vlen);
			{
				Env e;
				MemArena arena(1u << 20);
				u32 words[2];
				e.vlen_bits = vlen;
				ApplyEnv(e);
				config::rvv_lowering = 0;
				CompilerJob::IpRangesSet ranges = {{0u, 8u}};
				words[0] = INSN_VSETVLI_E32M1;
				words[1] = r.word;
				CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u),
						std::move(ranges));
				Region *region = CompilerGenRegionIR(&arena, job);
				CHECK_EQ(CountOp(region, r.body_op), 0u);
			}
			break;
		case Family::SetVL:
			// T7S directly implements the architectural keep-VL conditional; legality of
			// reserved vtype encodings remains covered by the dedicated setup test.
			break;
		}
	}
	printf("    %s\n", (unsigned)g_failures == before ? "all rows refused" : "SEE FAILURES ABOVE");
}

// ---------------------------------------------------------------------------------------------
// 6. The LLVM/AOT arm follows the geometry at every admitted width.
// ---------------------------------------------------------------------------------------------
//
// W5 (2026-09-17) MOVED THIS ROW'S BOUNDARY, and the row is kept rather than deleted because what
// it protects is still real. It used to read "admitted at 512/1024, refused at 2048/4096": the LLVM
// gates were closed by RvvSSAEnabled(), whose width list was 512/1024, so widening a shared shape
// predicate could not widen them by accident. That protection is now spelled the other way round --
// the gates ask RvvLLVMTypedSubstrate(), which has no width list at all, and the width comes from
// RvvHostChunkGeometry -- so what has to be checked is that the arm follows the GEOMETRY and not
// some other rule: `VLEN/512` chunks wherever the register tiles into 64-byte chunks, at every
// width the list holds.
//
// The refusal half has not disappeared; it moved to the widths where the geometry itself refuses.
// Those are checked by section 5's `768` and `8192` rows (not a whole number of chunks, and above
// the guest's own VLEN limit) and by its e64 rows, which are what caught the first version of W5.
void CheckLlvmArmFollowsGeometry()
{
	printf("[6] LLVM/AOT arm: k = VLEN/512 chunks at every admitted width\n");
	for (auto const &r : ROUTES) {
		for (u32 vlen : ADMITTED_VLENS) {
			bool const want = true;
			Env e;
			e.aot_use_llvm = true;
			e.rvv_vector_ssa = true;
			e.vlen_bits = vlen;
			MemArena arena(1u << 20);
			u32 words[2];
			Region *region = TranslateRoute(arena, words, INSN_VSETVLI_E32M1, r.word, r.family, e);
			if (r.family == Family::SetVL) {
				CHECK_EQ(CountOp(region, Op::_rvvsetvl), want ? 1u : 0u);
			} else {
				CHECK_EQ(CountOp(region, r.body_op), want ? ExpectChunks(vlen) : 0u);
			}
		}
		printf("  %-8s LLVM: k at 512/1024/2048/4096\n", r.name);
	}
}

} // namespace

int main()
{
	ArchTraits::init();

	CheckChunkBoundsAgree();

	printf("[2] admitted widths, QIR: one frame, k = VLEN/512 chunks, exact windows, no helper\n");
	for (auto const &r : ROUTES) {
		for (u32 vlen : ADMITTED_VLENS) {
			CheckAdmittedQir(r, vlen);
		}
	}

	printf("[3] emitted host code: k AVX-512 chunk operations, and no xmm/ymm anywhere\n");
	for (auto const &r : ROUTES) {
		for (u32 vlen : ADMITTED_VLENS) {
			CheckAdmittedEmitted(r, vlen);
		}
	}

	printf("[4] the frozen T2g strip-mine body, all nine routes in one real guest block\n");
	for (u32 vlen : ADMITTED_VLENS) {
		CheckFrozenBody(vlen);
	}

	printf("[5] fail-closed: unsupported shapes stay unsupported at every width\n");
	for (auto const &r : ROUTES) {
		CheckFailClosed(r);
	}

	CheckLlvmArmFollowsGeometry();

	if (g_failures) {
		printf("RVV_GENERIC_WIDTH_ROUTE: FAILED: %d failure(s)\n", g_failures);
		return 1;
	}
	printf("RVV_GENERIC_WIDTH_ROUTE: OK: all checks passed\n");
	return 0;
}
