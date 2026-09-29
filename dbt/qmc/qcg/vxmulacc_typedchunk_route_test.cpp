// Native-3: the unmasked e32/LMUL=1 `vmul.vx` / `vmacc.vx` route, verified mechanically at four
// levels -- decoder, constructed QIR, post-QRegAlloc allocation, and independently disassembled
// emitted host bytes -- at every admitted width.
//
// A21 (2026-09-06). THE WIDTH IS NOW THE SHARED RULE. Before A21 the route's shape predicate
// enumerated VLEN {512, 1024} by name and the emitter built literal V512 nodes at 64-byte
// displacements, so at VLEN 128/256 every vmul.vx/vmacc.vx kept the rv32_vimul helper while every
// sibling instruction in the same strip ran directly (A17 §2.3: 3.3e8 / 1.6e8 helper calls in GEMM).
// The QCG arm now takes its width from RvvRouteChunkShape -- RvvHostChunkGeometry, chunk =
// min(VLEN/8, 64) bytes, count = (VLEN/8)/chunk -- so the admitted widths are 16/32/64/64x2 bytes
// at VLEN 128/256/512/1024 (and 64xk above, as vmul.vv), and every check below is parameterised on
// the chunk width computed INDEPENDENTLY here (ExpectShape) rather than read from the predicate.
// The narrow widths are EVEX xmm/ymm forms (AVX512VL), and the emitted-bytes section proves the
// register CLASS, the memory operand SIZE and the displacements, not just the counts. The LLVM arm
// is unchanged and still admits VLEN 512/1024 only (its own test); the CCRF component scope is
// unchanged (ccrf_sequential_microkernel_test).
//
// WHAT MAKES THIS ROUTE DIFFERENT FROM ITS EIGHT SIBLINGS, and therefore what this file has to
// prove that theirs do not:
//
//   A. THE DECODER DOES NOT NARROW THE SHAPE. Every accepted `.vv` route has its own decode op
//      (`vmul_vv`, `vsub_vv`, ...), so by the time its translator runs, funct6, funct3 and vm are
//      already pinned. `Op::_vimul` carries the WHOLE OPMVV+OPMVX multiply/divide/multiply-
//      accumulate family -- twelve funct6 values, two source forms, masked and unmasked -- so this
//      translator is reached by fourteen encodings that must keep the helper. Section [1] states
//      that as a decoder fact and section [3] exercises each refusal on its own axis.
//   B. THE SCALAR. `vd[i] = vs2[i] * x[rs1]` takes one operand from an INTEGER register, so the
//      frame carries a `vchunkbroadcast` -- and its correctness is entirely "which guest register,
//      read from where". Sections [2] and [5] pin the CPUState offset to the slot of the register
//      the ENCODING names, at three different rs1 values including x0, so no workload's register
//      number or value can be baked in.
//   C. THE ACCUMULATOR. `vmacc.vx` READS its destination. No accepted route does. Section [6]
//      requires every vd chunk load to precede every vd chunk store -- which at VLEN 1024 is
//      exactly "chunk 0's write must not pollute chunk 1's read" -- and does so independently of
//      the overlap argument the `.vv` routes already make.
//
// WHAT THIS FILE PROVES
//
//   1. DECODER. vmul.vx, vmacc.vx and twelve sibling encodings ALL reach Op::_vimul: the decoder
//      does not distinguish them, so the route's own predicate must, and vmul.vv/vadd.vv still
//      reach their own ops -- the accepted splits are not disturbed.
//   2. QIR. The admitted instruction becomes exactly ONE broadcast plus k*(3) or k*(5) typed ops at
//      VLEN 128/256/512/1024 -> {16,1}/{32,1}/{64,1}/{64,2}, in load-major order, at the exact
//      chunk-width CPUState windows, every value of the chunk's own VType (V128/V256/V512), with
//      per-chunk def-use and no cross-chunk edge. The broadcast's state offset is the guest GPR
//      slot of the encoding's rs1 and its lane width is 4.
//   3. FALLBACK. Every forbidden shape keeps the pre-existing helper: zero typed nodes and exactly
//      one `hcall [rv32_vimul]`. Each condition is exercised on its own axis.
//   4. QRA. Distinct physical VPRs out of VPR_POOL, per-chunk def-use surviving allocation, the one
//      broadcast register shared by every chunk's multiply, and no allocator-inserted V512 mov.
//   5. QEMIT. The real qcg::GenerateCode pipeline emits exactly one `vpbroadcastd <cls>, DWORD PTR
//      [r13+<gpr slot>]`, exactly k `vpmulld`, and exactly k `vpaddd` for vmacc.vx / ZERO for
//      vmul.vx -- with the exact allocated operands in the register class the VLEN selects
//      (xmm at 128, ymm at 256, zmm at 512/1024), memory operands of exactly the chunk width
//      (XMMWORD/YMMWORD/ZMMWORD), NO vector register of any other class anywhere in the region,
//      and the exact state displacements. The decoded frame is printed per guest word.
//   6. ACCUMULATOR AND OVERLAP. vmacc.vx reads vd before writing it at both widths, and the legal
//      vd == vs2 overlap (which the frozen guest's own vmul.vx has) still reads pre-instruction
//      bytes.
//   7. THE REAL KERNEL. The two words the frozen PolyBench gemm guest actually contains --
//      `vmul.vx v8, v8, a1` and `vmacc.vx v9, s7, v8` -- routed as they appear in that ELF, and in
//      the strip-mine body shape where the vsetvli is NOT in the block.
//
// WHAT IT DELIBERATELY NEVER DOES
//
//   * It never executes the emitted bytes. TestCompilerRuntime::AllocateCode resizes a
//     std::vector<u8> and returns its data pointer -- there is no mmap in this object's lifetime,
//     let alone a PROT_EXEC one. The development host is an Ivy Bridge i7-3770 with no AVX-512 at
//     all, so these bytes could not be executed here even deliberately.
//   * It never runs a guest program, never times anything, and makes no performance claim.
//
// HOST NOTE. RvvQcgVxMulAccAdmit's host-feature row is a real __builtin_cpu_supports probe, so on a
// machine without AVX-512F the route fails closed and there would be nothing to inspect.
// `config::rvv_qcg_vx_mulacc_force_emit` bypasses ONLY that probe -- not the architectural guard,
// not the admitted shape -- which is what lets the emitted shape be audited here. Same device the
// accepted vadd/vmul audits use.
//
// INSTRUCTION WORDS. Every encoding below was produced by explicit field-assembly of the RVV 1.0
// OP-V layout and then independently round-tripped through `llvm-mc --disassemble -triple=riscv32
// -mattr=+v`, so the constants are not hand-transcribed hex.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
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

// Chunk c is bytes [c*w, (c+1)*w) of a register's own VLEN_MAX_BYTES slot, w the host chunk width.
constexpr u32 ChunkOffs(u32 reg, u32 chunk, u32 chunk_bytes)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * chunk_bytes;
}

// The CPUState slot of one guest integer register -- what the broadcast must read. Computed here
// from offsetof rather than from the translator's own expression, so the two are independent.
constexpr u32 GprOffs(u32 reg) { return (u32)(offsetof(CPUState, gpr) + 4u * reg); }

// The host chunk shape the route must produce for a VLEN, computed INDEPENDENTLY of the predicate
// and of RvvHostChunkGeometry: the widest host vector that fits the register, and as many of them
// as tile it. (128 -> 16x1, 256 -> 32x1, 512 -> 64x1, 1024 -> 64x2, 2048 -> 64x4, 4096 -> 64x8.)
struct Shape {
	u32 bytes, count;
};
constexpr Shape ExpectShape(u32 vlen_bits)
{
	u32 const reg = vlen_bits / 8u;
	u32 const w = reg < 64u ? reg : 64u;
	return Shape{w, reg / w};
}
constexpr char const *ClassOf(u32 chunk_bytes)
{
	return chunk_bytes == 16 ? "xmm" : chunk_bytes == 32 ? "ymm" : "zmm";
}
constexpr char const *PtrSizeOf(u32 chunk_bytes)
{
	return chunk_bytes == 16 ? "XMMWORD" : chunk_bytes == 32 ? "YMMWORD" : "ZMMWORD";
}

// ---------------------------------------------------------------------------------------------
// Instruction words. Each is annotated with the disassembly llvm-mc independently produced for it.
// ---------------------------------------------------------------------------------------------
constexpr u32 INSN_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_E64M1 = 0x0d857557u; // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 INSN_VSETVLI_E32M2 = 0x0d157557u; // vsetvli a0, a0, e32, m2, ta, ma

// The two admitted forms, in the operand layout the ISA manual writes them in.
constexpr u32 INSN_VMUL_VX = 0x961161d7u;	 // vmul.vx  v3, v1, sp
constexpr u32 INSN_VMACC_VX = 0xb61161d7u;	 // vmacc.vx v3, sp, v1
// The legal overlap: vd == vs2. The frozen guest's own vmul.vx is exactly this shape.
constexpr u32 INSN_VMUL_VX_D_EQ_S2 = 0x963161d7u;  // vmul.vx  v3, v3, sp
constexpr u32 INSN_VMACC_VX_D_EQ_S2 = 0xb63161d7u; // vmacc.vx v3, sp, v3
// rs1 == x0. Architecturally a scalar of 0; nothing about it is special-cased.
constexpr u32 INSN_VMUL_VX_RS1_X0 = 0x961061d7u;  // vmul.vx  v3, v1, zero
constexpr u32 INSN_VMACC_VX_RS1_X0 = 0xb61061d7u; // vmacc.vx v3, zero, v1
// The boundary registers: vd = vs2 = v31, rs1 = x31.
constexpr u32 INSN_VMUL_VX_BOUNDARY = 0x97ffefd7u; // vmul.vx  v31, v31, t6

// Refusals, one per axis.
constexpr u32 INSN_VMUL_VX_MASKED = 0x941161d7u;  // vmul.vx  v3, v1, sp, v0.t
constexpr u32 INSN_VMACC_VX_MASKED = 0xb41161d7u; // vmacc.vx v3, sp, v1, v0.t
constexpr u32 INSN_VMULH_VX = 0x9e1161d7u;	  // vmulh.vx   v3, v1, sp
constexpr u32 INSN_VMULHU_VX = 0x921161d7u;	  // vmulhu.vx  v3, v1, sp
constexpr u32 INSN_VMULHSU_VX = 0x9a1161d7u;	  // vmulhsu.vx v3, v1, sp
constexpr u32 INSN_VDIV_VX = 0x861161d7u;	  // vdiv.vx    v3, v1, sp
constexpr u32 INSN_VDIVU_VX = 0x821161d7u;	  // vdivu.vx   v3, v1, sp
constexpr u32 INSN_VREM_VX = 0x8e1161d7u;	  // vrem.vx    v3, v1, sp
constexpr u32 INSN_VNMSAC_VX = 0xbe1161d7u;	  // vnmsac.vx  v3, sp, v1
constexpr u32 INSN_VMADD_VX = 0xa61161d7u;	  // vmadd.vx   v3, sp, v1
constexpr u32 INSN_VNMSUB_VX = 0xae1161d7u;	  // vnmsub.vx  v3, sp, v1
constexpr u32 INSN_VMACC_VV = 0xb61121d7u;	  // vmacc.vv   v3, v2, v1
constexpr u32 INSN_VMUL_VV = 0x961121d7u;	  // vmul.vv    v3, v1, v2
constexpr u32 INSN_VADD_VV = 0x021101d7u;	  // vadd.vv    v3, v1, v2

// The two words the frozen T5c-0 PolyBench gemm guest (gemm_large.elf, sha256 aef92c369c...)
// actually contains, read out of it with `llvm-objdump -d --mattr=+v`:
//   11798: 0d007357  vsetvli t1, zero, e32, m1, ta, ma
//   1179c: 02876407  vl1re32.v v8, (a4)
//   117a0: 9685e457  vmul.vx v8, v8, a1        <- vd == vs2, scalar in a1 = x11
//   117a4: 02870427  vs1r.v v8, (a4)
//   11890: 028de407  vl1re32.v v8, (s11)
//   11894: 02866487  vl1re32.v v9, (a2)
//   1189c: b68be4d7  vmacc.vx v9, s7, v8       <- accumulator v9, scalar in s7 = x23
//   118a0: 028604a7  vs1r.v v9, (a2)
constexpr u32 INSN_KERNEL_VMUL_VX = 0x9685e457u;  // vmul.vx  v8, v8, a1
constexpr u32 INSN_KERNEL_VMACC_VX = 0xb68be4d7u; // vmacc.vx v9, s7, v8
constexpr u32 KERNEL_MUL_VD = 8, KERNEL_MUL_VS2 = 8, KERNEL_MUL_RS1 = 11;   // a1 = x11
constexpr u32 KERNEL_MACC_VD = 9, KERNEL_MACC_VS2 = 8, KERNEL_MACC_RS1 = 23; // s7 = x23

constexpr u32 VS2_REG = 1; // v1
constexpr u32 VD_REG = 3;  // v3
constexpr u32 RS1_REG = 2; // sp = x2

// ---------------------------------------------------------------------------------------------
// 1. Decoder: it does NOT narrow this route's shape.
// ---------------------------------------------------------------------------------------------

struct OpProvider {
#define OP(name, format_, flags_) static constexpr rv32::insn::Op _##name = rv32::insn::Op::_##name;
	RV32_OPCODE_LIST()
#undef OP
};

rv32::insn::Op DecodeWord(u32 word)
{
	u32 w = word;
	return rv32::insn::Decoder<OpProvider>::Decode(&w);
}

void CheckDecoder()
{
	printf("  decoder: the whole vimul family shares ONE op, so the route's predicate is the gate\n");
	using Op32 = rv32::insn::Op;

	struct Row {
		char const *name;
		u32 word;
		Op32 want;
	};
	// The first two are the admitted forms and the next twelve are refusals -- and the point of
	// the table is that ALL FOURTEEN decode to the SAME op. Nothing upstream of the route's own
	// predicate distinguishes them, which is why that predicate reads the instruction word field
	// by field instead of trusting the op it arrived under.
	Row const rows[] = {
	    {"vmul.vx (ADMITTED)", INSN_VMUL_VX, Op32::_vimul},
	    {"vmacc.vx (ADMITTED)", INSN_VMACC_VX, Op32::_vimul},
	    {"vmul.vx masked", INSN_VMUL_VX_MASKED, Op32::_vimul},
	    {"vmacc.vx masked", INSN_VMACC_VX_MASKED, Op32::_vimul},
	    {"vmulh.vx", INSN_VMULH_VX, Op32::_vimul},
	    {"vmulhu.vx", INSN_VMULHU_VX, Op32::_vimul},
	    {"vmulhsu.vx", INSN_VMULHSU_VX, Op32::_vimul},
	    {"vdiv.vx", INSN_VDIV_VX, Op32::_vimul},
	    {"vdivu.vx", INSN_VDIVU_VX, Op32::_vimul},
	    {"vrem.vx", INSN_VREM_VX, Op32::_vimul},
	    {"vnmsac.vx", INSN_VNMSAC_VX, Op32::_vimul},
	    {"vmadd.vx", INSN_VMADD_VX, Op32::_vimul},
	    {"vnmsub.vx", INSN_VNMSUB_VX, Op32::_vimul},
	    {"vmacc.vv", INSN_VMACC_VV, Op32::_vimul},
	    // The two pre-existing splits must be untouched by Native-3.
	    {"vmul.vv (its OWN op)", INSN_VMUL_VV, Op32::_vmul_vv},
	    {"vadd.vv (its OWN op)", INSN_VADD_VV, Op32::_vadd_vv},
	};
	for (auto const &r : rows) {
		Op32 const got = DecodeWord(r.word);
		CHECK(got == r.want);
		if (got != r.want) {
			fprintf(stderr, "  decoder: %s (0x%08x) decoded to op %u, expected %u\n", r.name,
				r.word, (unsigned)got, (unsigned)r.want);
		} else {
			printf("    ok  %-24s 0x%08x -> %s\n", r.name, r.word,
			       r.want == Op32::_vimul
				   ? "vimul"
				   : (r.want == Op32::_vmul_vv ? "vmul_vv" : "vadd_vv"));
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Translation harness.
// ---------------------------------------------------------------------------------------------

// Every config knob the route reads, set explicitly on every translation so no test can inherit
// another's global state. `admit_all` is the fully-open configuration; the fallback table flips
// exactly one field at a time off it.
struct RouteConfig {
	bool vx_mulacc = true;
	bool force_emit = true; // see the file header HOST NOTE
	bool aot_use_llvm = false;
	bool rvv_verify = false;
	bool rvv_direct = true;
	bool partial_vl = false; // Isolate the original full-body layout unless explicitly testing both arms.
	u32 vlen_bits = 512;
	// A21: the shared narrow-width switch and its audit twin. On by default here because this
	// file's four-width rows are exactly the widths that switch reaches; the fallback table turns
	// it off at 128/256 to prove the helper is kept when it is off. The audit twin bypasses ONLY
	// the AVX512VL probe (this host has no AVX-512 at all).
	bool narrow_width = true;
	bool narrow_force_emit = true;
	// When false the block contains NO vsetvli, so rvv_bb_vtype stays ~0u and the translator takes
	// its candidate-proposal entry -- the shape the frozen strip-mine body has, since clang hoists
	// the vsetvli out of the loop body.
	bool with_vsetvli = true;
	u32 vsetvli_word = INSN_VSETVLI_E32M1;
	u32 vx_word = INSN_VMUL_VX;
};

Region *TranslateWords(MemArena &arena, u32 *words, unsigned n, RouteConfig const &cfg)
{
	config::rvv_qcg_vx_mulacc = cfg.vx_mulacc;
	config::rvv_qcg_vx_mulacc_force_emit = cfg.force_emit;
	config::aot_use_llvm = cfg.aot_use_llvm;
	config::rvv_verify = cfg.rvv_verify;
	config::rvv_direct = cfg.rvv_direct;
	config::rvv_qcg_partial_vl = cfg.partial_vl;
	config::rvv_qcg_typed_chunk_force_emit = cfg.force_emit;
	config::vlen_bits = cfg.vlen_bits;
	config::rvv_qcg_narrow_chunk_width = cfg.narrow_width;
	config::rvv_qcg_narrow_chunk_width_force_emit = cfg.narrow_force_emit;
	// Every sibling route stays off throughout: this file must observe the Native-3 route in
	// isolation, and leaving them on would make a stray frame indistinguishable from this one's.
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_typed_chunk_vle = false;
	config::rvv_qcg_typed_chunk_vse = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_vector_run = false;

	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	return CompilerGenRegionIR(&arena, job);
}

// words[] must outlive the returned region; both are locals in the caller's own scope.
Region *TranslateCfg(MemArena &arena, u32 words[2], RouteConfig const &cfg)
{
	if (cfg.with_vsetvli) {
		words[0] = cfg.vsetvli_word;
		words[1] = cfg.vx_word;
		return TranslateWords(arena, words, 2, cfg);
	}
	words[0] = cfg.vx_word;
	return TranslateWords(arena, words, 1, cfg);
}

struct Group {
	unsigned n_begin = 0, n_end = 0;
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body;
};

Group FindGroup(Region *region)
{
	Group g;
	bool open = false;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				++g.n_begin;
				g.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				continue;
			}
			if (op == Op::_rvvtypedchunkend) {
				++g.n_end;
				g.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
				open = false;
				continue;
			}
			if (open) {
				g.body.push_back(&ins);
			}
		}
	}
	return g;
}

unsigned CountOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			n += (ins.GetOpcode() == op);
		}
	}
	return n;
}

unsigned CountHcall(Region *region, RuntimeStubId stub)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			if (ins.GetOpcode() != Op::_hcall) {
				continue;
			}
			n += (static_cast<InstHcall *>(&ins)->stub == stub);
		}
	}
	return n;
}

// The route's own body layout, named once. is_macc decides both the node count and which of the
// two shapes below the body must have.
//
//   vmul.vx   bcast | k*(load vs2) | k*(mul) | k*(store vd)
//   vmacc.vx  bcast | k*(load vs2, load vd)  | k*(mul, add) | k*(store vd)
unsigned BodyLen(bool is_macc, unsigned k) { return 1u + k * (is_macc ? 5u : 3u); }

void CheckRestartRoute(u32 vlen, bool macc, bool known_vtype)
{
	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.partial_vl = true;
	cfg.vlen_bits = vlen;
	cfg.vx_word = macc ? INSN_VMACC_VX : INSN_VMUL_VX;
	cfg.with_vsetvli = known_vtype;
	Region *region = TranslateCfg(arena, words, cfg);
	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	if (!g.begin || !g.end) return;
	Shape const sh = ExpectShape(vlen);
	unsigned const full = BodyLen(macc, sh.count);
	CHECK(g.begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeIntegerTwoArm);
	CHECK_EQ(g.begin->n_typed, full + sh.count);
	CHECK_EQ(g.body.size(), full + 1u + sh.count);
	CHECK_EQ(CountOp(region, Op::_rvvtypedchunkpartial), 1u);
	CHECK_EQ(CountOp(region, Op::_vchunkpartialalu), sh.count);
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vimul), 0u);
	if (g.body.size() != full + 1u + sh.count) return;
	CHECK(g.body[full]->GetOpcode() == Op::_rvvtypedchunkpartial);
	for (u32 c = 0; c < sh.count; ++c) {
		CHECK(g.body[full + 1 + c]->GetOpcode() == Op::_vchunkpartialalu);
		auto *p = static_cast<InstVChunkPartialAlu *>(g.body[full + 1 + c]);
		CHECK_EQ(p->op, (u8)(macc ? InstVChunkPartialAlu::Kind::Macc : InstVChunkPartialAlu::Kind::Mul));
		CHECK(p->architectural_mask);
		CHECK(!p->masked);
		CHECK_EQ(p->element_base, c * sh.bytes / 4u);
		CHECK_EQ(p->finish_instruction, c + 1 == sh.count);
		CHECK_EQ(p->rd_offs, ChunkOffs(VD_REG, c, sh.bytes));
		CHECK_EQ(p->rs2_offs, ChunkOffs(VS2_REG, c, sh.bytes));
	}
}

// ---------------------------------------------------------------------------------------------
// 2. Constructed QIR: exact admitted shape.
// ---------------------------------------------------------------------------------------------
void CheckRoute(char const *tag, u32 vlen_bits, u32 expect_vlmax, u32 word, bool is_macc,
		u32 vd_reg, u32 vs2_reg, u32 rs1_reg, bool with_vsetvli)
{
	Shape const sh = ExpectShape(vlen_bits);
	u32 const nchunks = sh.count, cb = sh.bytes;
	VType const ct = VectorVTypeForBytes(cb);
	printf("  %s: vlen=%u chunk=%ux%u vlmax=%u macc=%d vd=v%u vs2=v%u rs1=x%u vsetvli_in_block=%d\n",
	       tag, vlen_bits, cb, nchunks, expect_vlmax, (int)is_macc, vd_reg, vs2_reg, rs1_reg,
	       (int)with_vsetvli);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.vx_word = word;
	cfg.with_vsetvli = with_vsetvli;
	Region *region = TranslateCfg(arena, words, cfg);

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	CHECK_EQ(g.n_end, 1u);
	if (!g.begin || !g.end) {
		fprintf(stderr, "  %s: wrong number of typed-chunk frames\n", tag);
		return;
	}

	unsigned const want_body = BodyLen(is_macc, nchunks);
	CHECK_EQ(g.begin->n_typed, (u8)want_body);
	CHECK_EQ(g.begin->vlmax, expect_vlmax);
	// The guard is the ACCEPTED vtype/vl/vstart predicate, not Native-2's vlenb-only kind: this
	// route's SEW, LMUL and element count all come from vtype, so vtype is a precondition here.
	CHECK(g.begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeVlVstart);
	// The fallback is the PRE-EXISTING vimul helper on both frame nodes -- no new stub entered the
	// build with this route.
	CHECK(g.begin->stub == RuntimeStubId::id_rv32_vimul);
	CHECK(g.end->stub == RuntimeStubId::id_rv32_vimul);
	// And there is no leftover helper call for this instruction: the frame replaced it.
	CHECK_EQ(CountHcall(region, RuntimeStubId::id_rv32_vimul), 0u);

	CHECK_EQ(g.body.size(), (size_t)want_body);
	if (g.body.size() != want_body) {
		return;
	}

	// [a] THE SCALAR. Exactly one broadcast, first, reading the CPUState slot of the register the
	// ENCODING names -- computed here from offsetof, not from the translator's expression.
	CHECK_EQ(CountOp(region, Op::_vchunkbroadcast), 1u);
	CHECK(g.body[0]->GetOpcode() == Op::_vchunkbroadcast);
	if (g.body[0]->GetOpcode() != Op::_vchunkbroadcast) {
		return;
	}
	auto *bcast = static_cast<InstVChunkBroadcast *>(g.body[0]);
	CHECK_EQ((u32)bcast->offs, GprOffs(rs1_reg));
	CHECK_EQ((u32)bcast->sew_bytes, 4u);
	// A21: the broadcast -- and every value in the frame -- is the CHUNK's type, so a 128-bit
	// register is splatted into an xmm and never into a zmm that would then be stored 64 wide.
	CHECK(bcast->o(0).GetType() == ct);
	for (auto *ins : g.body) {
		for (u8 k = 0; k < ins->OutputCount(); ++k)
			if (IsVectorVType(ins->o(k).GetType()))
				CHECK(ins->o(k).GetType() == ct);
		for (u8 k = 0; k < ins->InputCount(); ++k)
			if (IsVectorVType(ins->i(k).GetType()))
				CHECK(ins->i(k).GetType() == ct);
	}

	// [b] LOAD-MAJOR. Sources, then lane operations, then destinations -- as node positions, so a
	// reordering is a structural failure rather than a numeric one.
	unsigned const n_src = is_macc ? 2u * nchunks : nchunks;
	std::vector<Inst *> const src(g.body.begin() + 1, g.body.begin() + 1 + n_src);
	std::vector<Inst *> const alu(g.body.begin() + 1 + n_src,
				      g.body.end() - (ptrdiff_t)nchunks);
	std::vector<Inst *> const dst(g.body.end() - (ptrdiff_t)nchunks, g.body.end());
	for (auto *s : src) {
		CHECK(s->GetOpcode() == Op::_vstatechunkload);
	}
	for (auto *d : dst) {
		CHECK(d->GetOpcode() == Op::_vstatechunkstore);
	}
	CHECK_EQ(alu.size(), (size_t)(is_macc ? 2u * nchunks : nchunks));

	// [c] PER-CHUNK WINDOWS AND DEF-USE.
	std::vector<RegN> defined;
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(src[is_macc ? 2 * c : c]);
		CHECK(l_s2->GetOpcode() == Op::_vstatechunkload);
		CHECK_EQ(l_s2->offs, ChunkOffs(vs2_reg, c, cb));

		auto *mul = static_cast<InstVChunkMul *>(alu[is_macc ? 2 * c : c]);
		CHECK(mul->GetOpcode() == Op::_vchunkmul);
		CHECK_EQ((u32)mul->sew_bytes, 4u);
		// Chunk c's multiply consumes chunk c's OWN vs2 load and the ONE broadcast. Every chunk
		// sharing the same scalar value is the statement that x[rs1] is read once per
		// instruction, not once per chunk.
		bool const mul_srcs_ok =
		    (mul->i(0).GetVVPR() == l_s2->o(0).GetVVPR() &&
		     mul->i(1).GetVVPR() == bcast->o(0).GetVVPR()) ||
		    (mul->i(1).GetVVPR() == l_s2->o(0).GetVVPR() &&
		     mul->i(0).GetVVPR() == bcast->o(0).GetVVPR());
		CHECK(mul_srcs_ok);

		auto *store = static_cast<InstVStateChunkStore *>(dst[c]);
		CHECK(store->GetOpcode() == Op::_vstatechunkstore);
		CHECK_EQ(store->offs, ChunkOffs(vd_reg, c, cb));

		defined.push_back(l_s2->o(0).GetVVPR());
		defined.push_back(mul->o(0).GetVVPR());

		if (!is_macc) {
			CHECK_EQ(store->i(0).GetVVPR(), mul->o(0).GetVVPR());
			continue;
		}
		// vmacc: the accumulator load and the add.
		auto *l_acc = static_cast<InstVStateChunkLoad *>(src[2 * c + 1]);
		CHECK(l_acc->GetOpcode() == Op::_vstatechunkload);
		CHECK_EQ(l_acc->offs, ChunkOffs(vd_reg, c, cb));
		auto *add = static_cast<InstVChunkAdd *>(alu[2 * c + 1]);
		CHECK(add->GetOpcode() == Op::_vchunkadd);
		CHECK_EQ((u32)add->sew_bytes, 4u);
		bool const add_srcs_ok = (add->i(0).GetVVPR() == mul->o(0).GetVVPR() &&
					  add->i(1).GetVVPR() == l_acc->o(0).GetVVPR()) ||
					 (add->i(1).GetVVPR() == mul->o(0).GetVVPR() &&
					  add->i(0).GetVVPR() == l_acc->o(0).GetVVPR());
		CHECK(add_srcs_ok);
		CHECK_EQ(store->i(0).GetVVPR(), add->o(0).GetVVPR());
		defined.push_back(l_acc->o(0).GetVVPR());
		defined.push_back(add->o(0).GetVVPR());
	}

	// [d] NO CROSS-CHUNK EDGE, and no value defined twice. The broadcast is the ONE value chunks
	// share, and it is a source for all of them and a destination for none.
	defined.push_back(bcast->o(0).GetVVPR());
	std::vector<RegN> sorted = defined;
	std::sort(sorted.begin(), sorted.end());
	CHECK(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end());

	// [e] Node counts, as a census over the whole region rather than only the frame.
	CHECK_EQ(CountOp(region, Op::_vchunkmul), nchunks);
	CHECK_EQ(CountOp(region, Op::_vchunkadd), is_macc ? nchunks : 0u);
	CHECK_EQ(CountOp(region, Op::_vstatechunkload), n_src);
	CHECK_EQ(CountOp(region, Op::_vstatechunkstore), nchunks);

	printf("    ok  body=%u (1 bcast @ state:0x%x + %u src + %u alu + %u dst) chunk_vtype=%s\n",
	       want_body, (unsigned)bcast->offs, n_src, (unsigned)alu.size(), nchunks, ClassOf(cb));
}

// ---------------------------------------------------------------------------------------------
// 3. Fallback table.
// ---------------------------------------------------------------------------------------------
void CheckFallback(char const *why, RouteConfig const &cfg)
{
	MemArena arena(1u << 20);
	u32 words[2];
	Region *region = TranslateCfg(arena, words, cfg);

	unsigned const n_begin = CountOp(region, Op::_rvvtypedchunkbegin);
	unsigned const n_bcast = CountOp(region, Op::_vchunkbroadcast);
	unsigned const n_mul = CountOp(region, Op::_vchunkmul);
	unsigned const n_add = CountOp(region, Op::_vchunkadd);
	unsigned const n_load = CountOp(region, Op::_vstatechunkload);
	unsigned const n_store = CountOp(region, Op::_vstatechunkstore);
	unsigned const n_helper = CountHcall(region, RuntimeStubId::id_rv32_vimul);

	CHECK_EQ(n_begin, 0u);
	CHECK_EQ(n_bcast, 0u);
	CHECK_EQ(n_mul, 0u);
	CHECK_EQ(n_add, 0u);
	CHECK_EQ(n_load, 0u);
	CHECK_EQ(n_store, 0u);
	// Exactly one call to the pre-existing helper -- the instruction still executes, through the
	// path this build already had.
	CHECK_EQ(n_helper, 1u);

	printf("    %-52s typed=0 helper_hcalls=%u  %s\n", why, n_helper,
	       (n_begin == 0 && n_bcast == 0 && n_helper == 1) ? "ok" : "FAIL");
}

void CheckFallbackTable()
{
	printf("  fallback: every forbidden shape keeps hcall[rv32_vimul]\n");

	{ // the route's own switch, default off
		RouteConfig c;
		c.vx_mulacc = false;
		CheckFallback("--rvv-qcg-vx-mulacc off (the default)", c);
	}
	{ // the QCG arm refuses outright on the LLVM backend; the LLVM arm needs --rvv-vector-ssa,
	  // which is off here, so this configuration must reach the helper rather than either arm.
		RouteConfig c;
		c.aot_use_llvm = true;
		CheckFallback("aot_use_llvm without --rvv-vector-ssa", c);
	}
	{ // --rvv-verify cannot see emitted code
		RouteConfig c;
		c.rvv_verify = true;
		CheckFallback("rvv_verify", c);
	}
	{ // the direct-lowering master switch
		RouteConfig c;
		c.rvv_direct = false;
		CheckFallback("rvv_direct off", c);
	}
	{ // VLEN axis, LOW, with the shared narrow-width switch OFF: the pre-A21 rule {64, VLEN/512}
	  // has no chunk for a register narrower than 64 bytes, so the helper is kept. This is the
	  // row that says the narrow widths are reachable ONLY through --rvv-qcg-narrow-chunk-width,
	  // the same switch every sibling route needs for them.
		for (u32 vlen : {128u, 256u}) {
			RouteConfig c;
			c.vlen_bits = vlen;
			c.narrow_width = false;
			char buf[96];
			snprintf(buf, sizeof(buf), "VLEN=%u with --rvv-qcg-narrow-chunk-width off", vlen);
			CheckFallback(buf, c);
		}
	}
	{ // VLEN axis, NOT A WHOLE NUMBER OF HOST CHUNKS: the shared geometry refuses (48- and
	  // 96-byte registers are not 16/32/64-byte host vectors and are never rounded), switch on or
	  // off. Same refusal as vadd.vv/vmul.vv at these widths (rvv_narrow_width_route_test).
		for (u32 vlen : {384u, 768u}) {
			for (bool nw : {true, false}) {
				RouteConfig c;
				c.vlen_bits = vlen;
				c.narrow_width = nw;
				char buf[96];
				snprintf(buf, sizeof(buf), "VLEN=%u (not a whole host chunk) narrow=%d",
					 vlen, (int)nw);
				CheckFallback(buf, c);
			}
		}
	}
	{ // The AVX512VL probe of the narrow widths is real: with the F probe bypassed but the VL
	  // probe NOT bypassed, this host (no AVX-512) must keep the helper at 128/256 -- and the
	  // 64-byte widths are unaffected by that probe (they are checked below in [2], where the
	  // narrow audit twin is on and does nothing at 512/1024).
		for (u32 vlen : {128u, 256u}) {
			RouteConfig c;
			c.vlen_bits = vlen;
			c.narrow_force_emit = false;
			char buf[96];
			snprintf(buf, sizeof(buf), "VLEN=%u without the AVX512VL audit bypass", vlen);
			CheckFallback(buf, c);
		}
	}
	{ // SEW axis: e64 has no admitted packed multiply or broadcast on this route
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E64M1;
		CheckFallback("SEW=64 (e64,m1)", c);
	}
	{ // LMUL axis: a register group is more than one register
		RouteConfig c;
		c.vsetvli_word = INSN_VSETVLI_E32M2;
		CheckFallback("LMUL=2 (e32,m2)", c);
	}
	{ // ENCODING axis. This is the block that carries the weight for THIS route, because the
	  // decoder sent every one of these words to the same translator as the two admitted forms.
	  // Each is refused by a different field of the predicate.
		struct Row {
			char const *why;
			u32 word;
		};
		Row const rows[] = {
		    {"masked vmul.vx (vm=0)", INSN_VMUL_VX_MASKED},
		    {"masked vmacc.vx (vm=0)", INSN_VMACC_VX_MASKED},
		    {"vmulh.vx (high half)", INSN_VMULH_VX},
		    {"vmulhu.vx (high half, unsigned)", INSN_VMULHU_VX},
		    {"vmulhsu.vx (high half, mixed sign)", INSN_VMULHSU_VX},
		    {"vdiv.vx", INSN_VDIV_VX},
		    {"vdivu.vx", INSN_VDIVU_VX},
		    {"vrem.vx", INSN_VREM_VX},
		    {"vnmsac.vx (SUBTRACTS the product)", INSN_VNMSAC_VX},
		    {"vmadd.vx (vd is a MULTIPLICAND)", INSN_VMADD_VX},
		    {"vnmsub.vx (vd is a MULTIPLICAND)", INSN_VNMSUB_VX},
		    {"vmacc.vv (OPMVV: no scalar)", INSN_VMACC_VV},
		};
		for (auto const &r : rows) {
			RouteConfig c;
			c.vx_word = r.word;
			CheckFallback(r.why, c);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// 4. Post-QRegAlloc allocation.
// ---------------------------------------------------------------------------------------------
void CheckRoutePostQRA(char const *tag, u32 vlen_bits, u32 word, bool is_macc)
{
	Shape const sh = ExpectShape(vlen_bits);
	u32 const nchunks = sh.count;
	printf("  %s (post-QRA): vlen=%u chunk=%ux%u macc=%d\n", tag, vlen_bits, sh.bytes, nchunks,
	       (int)is_macc);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.vx_word = word;
	Region *region = TranslateCfg(arena, words, cfg);

	// Exactly the two passes qcg::GenerateCode runs before constructing QEmit (qcg.cpp). QEmit and
	// QCodegen are deliberately never constructed here, so no host code exists on any host.
	ArchTraits::init();
	qcg::MachineRegionInfo mri;
	qcg::QSelPass::run(region, &mri);
	qcg::QRegAllocPass::run(region);

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	if (!g.begin) {
		return;
	}

	std::vector<Inst *> typed_ops;
	std::vector<Inst *> frame_movs;
	for (auto *ins : g.body) {
		(ins->GetOpcode() == Op::_mov ? frame_movs : typed_ops).push_back(ins);
	}
	// A scalar spill/fill of the preceding vsetvli's dirty a0 global may legally land inside the
	// frame; a vector mov (any of V128/V256/V512) may not -- that would be a vector spill, fill
	// or cross-class copy.
	for (auto *ins : frame_movs) {
		auto *u = static_cast<InstUnop *>(ins);
		bool const is_vec = IsVectorVType(u->o(0).GetType()) || IsVectorVType(u->i(0).GetType());
		CHECK(!is_vec);
	}
	unsigned const want_body = BodyLen(is_macc, nchunks);
	CHECK_EQ(typed_ops.size(), (size_t)want_body);
	if (typed_ops.size() != want_body) {
		return;
	}

	auto *bcast = static_cast<InstVChunkBroadcast *>(typed_ops[0]);
	CHECK(bcast->GetOpcode() == Op::_vchunkbroadcast);
	CHECK(bcast->o(0).IsPVPR());
	if (!bcast->o(0).IsPVPR()) {
		return;
	}
	RegN const p_bcast = bcast->o(0).GetPVPR();
	CHECK(ArchTraits::VPR_POOL.Test(p_bcast));
	CHECK(!ArchTraits::VPR_FIXED.Test(p_bcast));

	unsigned const n_src = is_macc ? 2u * nchunks : nchunks;
	std::vector<RegN> pregs{p_bcast};
	for (u32 c = 0; c < nchunks; ++c) {
		auto *l_s2 = static_cast<InstVStateChunkLoad *>(typed_ops[1 + (is_macc ? 2 * c : c)]);
		auto *mul = static_cast<InstVChunkMul *>(typed_ops[1 + n_src + (is_macc ? 2 * c : c)]);
		auto *store = static_cast<InstVStateChunkStore *>(typed_ops[want_body - nchunks + c]);
		CHECK(l_s2->GetOpcode() == Op::_vstatechunkload);
		CHECK(mul->GetOpcode() == Op::_vchunkmul);
		CHECK(store->GetOpcode() == Op::_vstatechunkstore);

		bool const allocated = l_s2->o(0).IsPVPR() && mul->o(0).IsPVPR() && mul->i(0).IsPVPR() &&
				       mul->i(1).IsPVPR() && store->i(0).IsPVPR();
		CHECK(allocated);
		if (!allocated) {
			continue;
		}
		for (auto o : {l_s2->o(0), mul->o(0)}) {
			CHECK(ArchTraits::VPR_POOL.Test(o.GetPVPR()));
			CHECK(!ArchTraits::VPR_FIXED.Test(o.GetPVPR()));
		}
		// Per-chunk def-use survives allocation: this chunk's multiply reads THIS chunk's vs2
		// register and the shared broadcast register, in either order.
		RegN const a = mul->i(0).GetPVPR(), b = mul->i(1).GetPVPR();
		RegN const want = l_s2->o(0).GetPVPR();
		CHECK((a == want && b == p_bcast) || (b == want && a == p_bcast));

		pregs.push_back(want);
		pregs.push_back(mul->o(0).GetPVPR());

		if (!is_macc) {
			CHECK_EQ(mul->o(0).GetPVPR(), store->i(0).GetPVPR());
			continue;
		}
		auto *l_acc = static_cast<InstVStateChunkLoad *>(typed_ops[1 + 2 * c + 1]);
		auto *add = static_cast<InstVChunkAdd *>(typed_ops[1 + n_src + 2 * c + 1]);
		CHECK(l_acc->GetOpcode() == Op::_vstatechunkload);
		CHECK(add->GetOpcode() == Op::_vchunkadd);
		CHECK(l_acc->o(0).IsPVPR() && add->o(0).IsPVPR());
		if (!l_acc->o(0).IsPVPR() || !add->o(0).IsPVPR()) {
			continue;
		}
		RegN const aa = add->i(0).GetPVPR(), ab = add->i(1).GetPVPR();
		CHECK((aa == mul->o(0).GetPVPR() && ab == l_acc->o(0).GetPVPR()) ||
		      (ab == mul->o(0).GetPVPR() && aa == l_acc->o(0).GetPVPR()));
		CHECK_EQ(add->o(0).GetPVPR(), store->i(0).GetPVPR());
		pregs.push_back(l_acc->o(0).GetPVPR());
		pregs.push_back(add->o(0).GetPVPR());
	}

	std::sort(pregs.begin(), pregs.end());
	pregs.erase(std::unique(pregs.begin(), pregs.end()), pregs.end());
	// One broadcast plus, per chunk, the vs2 value and the product -- and for vmacc the
	// accumulator and the sum. Every one of them a distinct physical vector register.
	CHECK_EQ(pregs.size(), (size_t)(1u + nchunks * (is_macc ? 4u : 2u)));

	printf("    ok  distinct VPRs=%zu frame movs=%zu bcast=%s%u\n", pregs.size(),
	       frame_movs.size(), ClassOf(sh.bytes), (unsigned)p_bcast);
}

// ---------------------------------------------------------------------------------------------
// 5. Real emission + independent disassembly.
// ---------------------------------------------------------------------------------------------

// AllocateCode NEVER mmaps: it resizes a vector and returns its data pointer. That is the
// structural guarantee behind "the emitted bytes are never executed".
struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override
	{
		return false; // jit_mode
	}
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
};

struct DecodedVec {
	enum class Kind { LOAD, STORE, MUL, ADD, BCAST } kind;
	std::string mnemonic;
	unsigned dst{}, src0{}, src1{};
	i64 disp{};
	bool has_disp{};
};

// A21: the expected register class is a PARAMETER. "xmm"/"ymm"/"zmm" followed by a number; a
// register of any other class is not parsed, and the caller fails on every unparsed line that
// names one -- so "a zmm at VLEN 128" is a loud failure, not a silently ignored line.
bool ParseVreg(std::string const &tok, char const *cls, unsigned *out)
{
	if (tok.size() < 4 || tok.compare(0, 3, cls) != 0) {
		return false;
	}
	size_t i = 3;
	if (!isdigit((unsigned char)tok[i])) {
		return false;
	}
	unsigned v = 0;
	while (i < tok.size() && isdigit((unsigned char)tok[i])) {
		v = v * 10 + (unsigned)(tok[i] - '0');
		++i;
	}
	*out = v;
	return i == tok.size();
}

// "<SIZE> PTR [r13+0x<hex>]" -> disp. Only the r13-relative form is accepted: every CPUState access
// this frame makes goes through the fixed state register, never a guest address. `size` is checked
// because it is what separates the 64-byte chunk windows from the 4-byte scalar the broadcast reads.
bool ParsePtrR13(std::string const &tok, char const *size, i64 *disp)
{
	std::string const prefix = std::string(size) + " PTR [r13";
	if (tok.size() <= prefix.size() || tok.compare(0, prefix.size(), prefix) != 0) {
		return false;
	}
	size_t i = prefix.size();
	bool const neg = tok[i] == '-';
	if (tok[i] != '+' && tok[i] != '-') {
		return false;
	}
	++i;
	if (tok.compare(i, 2, "0x") != 0) {
		return false;
	}
	i += 2;
	size_t const start = i;
	i64 v = 0;
	while (i < tok.size() && isxdigit((unsigned char)tok[i])) {
		char const c = (char)tolower((unsigned char)tok[i]);
		v = v * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
		++i;
	}
	if (i == start || i >= tok.size() || tok[i] != ']' || i + 1 != tok.size()) {
		return false;
	}
	*disp = neg ? -v : v;
	return true;
}

std::vector<std::string> SplitCommas(std::string const &s)
{
	std::vector<std::string> out;
	size_t start = 0;
	for (size_t i = 0; i <= s.size(); ++i) {
		if (i == s.size() || s[i] == ',') {
			out.push_back(s.substr(start, i - start));
			start = i + 1;
		}
	}
	return out;
}

// Parse one objdump Intel-syntax line. Only the four shapes this frame can emit are recognised.
// Anything else returns false; the caller fails loudly on any unrecognised ZMM-bearing line, which
// is what makes the counts below a census rather than a filter.
//
// vpaddd IS recognised here, unlike in the vmul.vv route test, because this frame legitimately
// emits it -- for vmacc.vx and only for vmacc.vx. The check that a vmul.vx frame has ZERO of them
// is therefore a count against a recognised mnemonic rather than a parse failure.
bool ParseLine(std::string const &line, DecodedVec *out, char const *cls, char const *ptr_size)
{
	size_t const tab = line.find('\t');
	if (tab == std::string::npos) {
		return false;
	}
	std::string const rhs = line.substr(tab + 1);
	size_t const sp = rhs.find(' ');
	std::string const mnem = sp == std::string::npos ? rhs : rhs.substr(0, sp);
	std::string const operand_str = sp == std::string::npos ? std::string() : rhs.substr(sp + 1);
	auto const ops = SplitCommas(operand_str);

	if (mnem == "vmovdqu64" && ops.size() == 2) {
		unsigned zr;
		i64 disp;
		// The memory operand SIZE is the chunk width: XMMWORD at 128, YMMWORD at 256,
		// ZMMWORD at 512/1024. A 64-byte window on a 16-byte register would parse as a
		// ZMMWORD next to an xmm and be rejected here.
		if (ParseVreg(ops[0], cls, &zr) && ParsePtrR13(ops[1], ptr_size, &disp)) {
			*out = DecodedVec{DecodedVec::Kind::LOAD, mnem, zr, 0, 0, disp, true};
			return true;
		}
		if (ParsePtrR13(ops[0], ptr_size, &disp) && ParseVreg(ops[1], cls, &zr)) {
			*out = DecodedVec{DecodedVec::Kind::STORE, mnem, 0, zr, 0, disp, true};
			return true;
		}
		return false;
	}
	if (mnem == "vpbroadcastd" && ops.size() == 2) {
		unsigned zr;
		i64 disp;
		if (ParseVreg(ops[0], cls, &zr) && ParsePtrR13(ops[1], "DWORD", &disp)) {
			*out = DecodedVec{DecodedVec::Kind::BCAST, mnem, zr, 0, 0, disp, true};
			return true;
		}
		return false;
	}
	if ((mnem == "vpmulld" || mnem == "vpaddd") && ops.size() == 3) {
		unsigned d, s0, s1;
		if (ParseVreg(ops[0], cls, &d) && ParseVreg(ops[1], cls, &s0) &&
		    ParseVreg(ops[2], cls, &s1)) {
			*out = DecodedVec{mnem == "vpmulld" ? DecodedVec::Kind::MUL
							   : DecodedVec::Kind::ADD,
					  mnem, d, s0, s1, 0, false};
			return true;
		}
	}
	return false;
}

// Any vector register of ANY class. Used for the census: every line naming one must have parsed
// as one of the frame's four shapes IN THE EXPECTED CLASS, so a stray xmm/ymm/zmm of the wrong
// class -- or a wrong-width memory operand -- is an unaccounted line and a failure.
bool MentionsVreg(std::string const &line)
{
	return line.find("xmm") != std::string::npos || line.find("ymm") != std::string::npos ||
	       line.find("zmm") != std::string::npos;
}

// Write `code` to a private temp file and disassemble it as a raw flat x86-64 binary with GNU
// objdump. Fails loudly rather than skipping: a missing disassembler means this checkpoint's
// emission evidence cannot be produced at all.
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_n3_emit_XXXXXX";
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
	    std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path +
	    " 2>&1";
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

void CheckRouteEmitted(char const *tag, u32 vlen_bits, u32 word, bool is_macc, u32 vd_reg,
		       u32 vs2_reg, u32 rs1_reg)
{
	Shape const sh = ExpectShape(vlen_bits);
	u32 const nchunks = sh.count, cb = sh.bytes;
	char const *cls = ClassOf(cb), *psz = PtrSizeOf(cb);
	printf("  %s (emitted): vlen=%u chunk=%ux%u class=%s macc=%d guest_word=0x%08x\n", tag,
	       vlen_bits, cb, nchunks, cls, (int)is_macc, word);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.vx_word = word;
	Region *region = TranslateCfg(arena, words, cfg);

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

	// Every decoded line is accounted for. A line naming a vector register that ParseLine does
	// not recognise IN THE EXPECTED CLASS AND WIDTH is a hard failure with the offending text,
	// not a silent drop. The parsed frame is printed, guest word first, so the report can cite
	// guest PC -> emitted instruction rather than totals.
	std::vector<DecodedVec> vecs;
	unsigned unparsed_vec = 0;
	for (auto const &l : lines) {
		DecodedVec dv{};
		if (ParseLine(l, &dv, cls, psz)) {
			vecs.push_back(dv);
			printf("      0x%08x -> %s\n", word, l.c_str() + (l.find('\t') + 1));
			continue;
		}
		if (MentionsVreg(l)) {
			++unparsed_vec;
			fprintf(stderr, "  %s: unaccounted vector-register line: %s\n", tag, l.c_str());
		}
	}
	CHECK_EQ(unparsed_vec, 0u);

	unsigned n_bcast = 0, n_mul = 0, n_add = 0, n_load = 0, n_store = 0;
	for (auto const &v : vecs) {
		switch (v.kind) {
		case DecodedVec::Kind::BCAST:
			++n_bcast;
			// THE SCALAR'S ADDRESS, read back out of the emitted bytes: the CPUState slot of
			// the guest register the ENCODING names, and a 4-byte operand rather than a
			// 64-byte one. A wrong register here would be an ordinary-looking splat of the
			// wrong value.
			CHECK_EQ((u32)v.disp, GprOffs(rs1_reg));
			break;
		case DecodedVec::Kind::MUL:
			++n_mul;
			break;
		case DecodedVec::Kind::ADD:
			++n_add;
			break;
		case DecodedVec::Kind::LOAD:
			++n_load;
			break;
		case DecodedVec::Kind::STORE:
			++n_store;
			// Every chunk write is into vd's own slot, at a chunk-width displacement inside
			// the VLEN/8 bytes the register actually occupies -- never beyond them.
			CHECK((u32)v.disp >= ChunkOffs(vd_reg, 0, cb) &&
			      (u32)v.disp + cb <= ChunkOffs(vd_reg, 0, cb) + vlen_bits / 8u);
			CHECK(((u32)v.disp - ChunkOffs(vd_reg, 0, cb)) % cb == 0);
			break;
		}
	}
	// ONE broadcast, k multiplies, and k adds for vmacc / ZERO for vmul. The zero is the assertion
	// that separates the two admitted forms in the emitted bytes rather than only in the QIR.
	CHECK_EQ(n_bcast, 1u);
	CHECK_EQ(n_mul, nchunks);
	CHECK_EQ(n_add, is_macc ? nchunks : 0u);
	CHECK_EQ(n_load, is_macc ? 2u * nchunks : nchunks);
	CHECK_EQ(n_store, nchunks);

	// The broadcast register feeds every multiply, in the emitted bytes.
	unsigned bcast_reg = ~0u;
	for (auto const &v : vecs) {
		if (v.kind == DecodedVec::Kind::BCAST) {
			bcast_reg = v.dst;
		}
	}
	unsigned mul_using_bcast = 0;
	for (auto const &v : vecs) {
		if (v.kind == DecodedVec::Kind::MUL &&
		    (v.src0 == bcast_reg || v.src1 == bcast_reg)) {
			++mul_using_bcast;
		}
	}
	CHECK_EQ(mul_using_bcast, nchunks);

	// The vs2 source windows are read, and they are vs2's, not vd's -- which for the non-overlap
	// registers used here is a distinguishable statement.
	unsigned vs2_loads = 0;
	for (auto const &v : vecs) {
		if (v.kind == DecodedVec::Kind::LOAD && (u32)v.disp >= ChunkOffs(vs2_reg, 0, cb) &&
		    (u32)v.disp + cb <= ChunkOffs(vs2_reg, 0, cb) + vlen_bits / 8u) {
			++vs2_loads;
		}
	}
	CHECK(vs2_loads >= nchunks);

	printf("    ok  vpbroadcastd=%u @DWORD[r13+0x%x] vpmulld=%u vpaddd=%u loads=%u stores=%u all %s/%s\n",
	       n_bcast, GprOffs(rs1_reg), n_mul, n_add, n_load, n_store, cls, psz);
}

// ---------------------------------------------------------------------------------------------
// 6. Accumulator read-before-write, and the legal vd == vs2 overlap.
// ---------------------------------------------------------------------------------------------
//
// These are two DIFFERENT obligations and the test states them separately:
//
//   * ACCUMULATOR: vmacc.vx reads vd. Every load of a vd window must precede every store to a vd
//     window. At VLEN 1024 that is exactly "chunk 0's write must not pollute chunk 1's read", and
//     an emitter that interleaved per chunk would fail this while passing every count above.
//   * OVERLAP: vd == vs2 is legal and is what the frozen guest's own vmul.vx does. The multiply
//     must see the PRE-instruction vs2 bytes, which is the same ordering seen from the other side.
void CheckAccumulatorOrder(char const *tag, u32 vlen_bits, u32 word, bool is_macc, u32 vd_reg)
{
	u32 const nchunks = ExpectShape(vlen_bits).count;
	printf("  %s (order): vlen=%u k=%u macc=%d vd=v%u\n", tag, vlen_bits, nchunks, (int)is_macc,
	       vd_reg);

	MemArena arena(1u << 20);
	u32 words[2];
	RouteConfig cfg;
	cfg.vlen_bits = vlen_bits;
	cfg.vx_word = word;
	Region *region = TranslateCfg(arena, words, cfg);

	Group g = FindGroup(region);
	CHECK_EQ(g.n_begin, 1u);
	if (!g.begin) {
		return;
	}

	u32 const vd_lo = ChunkOffs(vd_reg, 0, 64), vd_hi = vd_lo + rv32::VLEN_MAX_BYTES;
	int last_read = -1, first_write = -1;
	int n_reads = 0, n_writes = 0;
	for (size_t i = 0; i < g.body.size(); ++i) {
		auto *ins = g.body[i];
		if (ins->GetOpcode() == Op::_vstatechunkload) {
			u32 const o = static_cast<InstVStateChunkLoad *>(ins)->offs;
			if (o >= vd_lo && o < vd_hi) {
				last_read = (int)i;
				++n_reads;
			}
		}
		if (ins->GetOpcode() == Op::_vstatechunkstore) {
			u32 const o = static_cast<InstVStateChunkStore *>(ins)->offs;
			if (o >= vd_lo && o < vd_hi) {
				if (first_write < 0) {
					first_write = (int)i;
				}
				++n_writes;
			}
		}
	}
	CHECK_EQ(n_writes, (int)nchunks);
	// A vmacc frame reads vd once per chunk; a vmul frame whose vd == vs2 reads it once per chunk
	// too, through the vs2 load. Either way the reads must all be behind the first write.
	CHECK(n_reads >= (int)nchunks);
	CHECK(first_write >= 0);
	CHECK(last_read >= 0);
	CHECK(last_read < first_write);

	printf("    ok  vd reads=%d (last at body[%d]) writes=%d (first at body[%d])\n", n_reads,
	       last_read, n_writes, first_write);
}

} // namespace

int main()
{
	printf("Native-3 vmul.vx / vmacc.vx typed chunk route with a scalar broadcast (A21: shared width rule)\n");

	printf("[1] decoder\n");
	CheckDecoder();

	struct Width {
		u32 vlen, vlmax;
	};
	// vlmax = VLEN/SEW at SEW=32, LMUL=1 -- restated here as data rather than computed, so a wrong
	// VLMAX in the emitted guard is caught against an independent number. The four teacher VLENs.
	static constexpr Width kWidths[] = {{128, 4}, {256, 8}, {512, 16}, {1024, 32}};

	printf("[2] constructed QIR\n");
	for (auto const &w : kWidths) {
		char tag[64];
		Shape const sh = ExpectShape(w.vlen);
		CHECK_EQ(sh.bytes * sh.count, w.vlen / 8u);

		snprintf(tag, sizeof(tag), "vmul.vx vlen%u", w.vlen);
		CheckRoute(tag, w.vlen, w.vlmax, INSN_VMUL_VX, false, VD_REG, VS2_REG, RS1_REG, true);
		snprintf(tag, sizeof(tag), "vmacc.vx vlen%u", w.vlen);
		CheckRoute(tag, w.vlen, w.vlmax, INSN_VMACC_VX, true, VD_REG, VS2_REG, RS1_REG, true);

		// rs1 = x0. The scalar is the slot of x0, which is never written and reads zero -- the
		// same word the helper reads. Nothing special-cases it, and this is the check that
		// says so.
		snprintf(tag, sizeof(tag), "vmul.vx rs1=x0 vlen%u", w.vlen);
		CheckRoute(tag, w.vlen, w.vlmax, INSN_VMUL_VX_RS1_X0, false, VD_REG, VS2_REG, 0, true);
		snprintf(tag, sizeof(tag), "vmacc.vx rs1=x0 vlen%u", w.vlen);
		CheckRoute(tag, w.vlen, w.vlmax, INSN_VMACC_VX_RS1_X0, true, VD_REG, VS2_REG, 0, true);

		// The boundary registers: v31 and x31.
		snprintf(tag, sizeof(tag), "vmul.vx v31/x31 vlen%u", w.vlen);
		CheckRoute(tag, w.vlen, w.vlmax, INSN_VMUL_VX_BOUNDARY, false, 31, 31, 31, true);

		// The legal overlap.
		snprintf(tag, sizeof(tag), "vmul.vx vd==vs2 vlen%u", w.vlen);
		CheckRoute(tag, w.vlen, w.vlmax, INSN_VMUL_VX_D_EQ_S2, false, VD_REG, VD_REG, RS1_REG,
			   true);
		snprintf(tag, sizeof(tag), "vmacc.vx vd==vs2 vlen%u", w.vlen);
		CheckRoute(tag, w.vlen, w.vlmax, INSN_VMACC_VX_D_EQ_S2, true, VD_REG, VD_REG, RS1_REG,
			   true);

		// THE FROZEN GUEST'S OWN WORDS, in the shape its strip-mine body has: NO vsetvli in the
		// block, so the translator takes its candidate-proposal entry and the emitted guard --
		// not a translation-time observation -- is what proves the vtype.
		snprintf(tag, sizeof(tag), "FROZEN vmul.vx v8,v8,a1 vlen%u", w.vlen);
		CheckRoute(tag, w.vlen, w.vlmax, INSN_KERNEL_VMUL_VX, false, KERNEL_MUL_VD,
			   KERNEL_MUL_VS2, KERNEL_MUL_RS1, false);
		snprintf(tag, sizeof(tag), "FROZEN vmacc.vx v9,s7,v8 vlen%u", w.vlen);
		CheckRoute(tag, w.vlen, w.vlmax, INSN_KERNEL_VMACC_VX, true, KERNEL_MACC_VD,
			   KERNEL_MACC_VS2, KERNEL_MACC_RS1, false);
	}
	// [2b] Above 1024 the shared rule is the pre-existing {64, VLEN/512}, as for vmul.vv. Before
	// A21 this route refused 2048/4096 by name; now it follows the same rule as its `.vv` twin,
	// with or without the narrow switch (which changes nothing at >= 512 by construction).
	printf("[2b] shared rule above 1024 (parity with vmul.vv)\n");
	for (u32 vlen : {2048u, 4096u}) {
		char tag[64];
		snprintf(tag, sizeof(tag), "vmacc.vx vlen%u", vlen);
		CheckRoute(tag, vlen, vlen / 32u, INSN_VMACC_VX, true, VD_REG, VS2_REG, RS1_REG, true);
	}

	printf("[3] fallback table\n");
	CheckFallbackTable();
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u, 4096u})
		for (bool macc : {false, true})
			for (bool known : {false, true}) CheckRestartRoute(vlen, macc, known);

	printf("[4] post-QRegAlloc\n");
	for (auto const &w : kWidths) {
		char tag[64];
		snprintf(tag, sizeof(tag), "vmul.vx vlen%u", w.vlen);
		CheckRoutePostQRA(tag, w.vlen, INSN_VMUL_VX, false);
		snprintf(tag, sizeof(tag), "vmacc.vx vlen%u", w.vlen);
		CheckRoutePostQRA(tag, w.vlen, INSN_VMACC_VX, true);
	}

	printf("[5] emitted host code\n");
	for (auto const &w : kWidths) {
		char tag[64];
		snprintf(tag, sizeof(tag), "vmul.vx vlen%u", w.vlen);
		CheckRouteEmitted(tag, w.vlen, INSN_VMUL_VX, false, VD_REG, VS2_REG, RS1_REG);
		snprintf(tag, sizeof(tag), "vmacc.vx vlen%u", w.vlen);
		CheckRouteEmitted(tag, w.vlen, INSN_VMACC_VX, true, VD_REG, VS2_REG, RS1_REG);
		snprintf(tag, sizeof(tag), "vmul.vx rs1=x0 vlen%u", w.vlen);
		CheckRouteEmitted(tag, w.vlen, INSN_VMUL_VX_RS1_X0, false, VD_REG, VS2_REG, 0);
		snprintf(tag, sizeof(tag), "FROZEN vmul.vx v8,v8,a1 vlen%u", w.vlen);
		CheckRouteEmitted(tag, w.vlen, INSN_KERNEL_VMUL_VX, false, KERNEL_MUL_VD,
				  KERNEL_MUL_VS2, KERNEL_MUL_RS1);
		snprintf(tag, sizeof(tag), "FROZEN vmacc.vx vlen%u", w.vlen);
		CheckRouteEmitted(tag, w.vlen, INSN_KERNEL_VMACC_VX, true, KERNEL_MACC_VD,
				  KERNEL_MACC_VS2, KERNEL_MACC_RS1);
	}

	printf("[6] accumulator read-before-write and legal overlap\n");
	for (auto const &w : kWidths) {
		char tag[64];
		snprintf(tag, sizeof(tag), "vmacc.vx accumulator vlen%u", w.vlen);
		CheckAccumulatorOrder(tag, w.vlen, INSN_VMACC_VX, true, VD_REG);
		snprintf(tag, sizeof(tag), "vmacc.vx vd==vs2 vlen%u", w.vlen);
		CheckAccumulatorOrder(tag, w.vlen, INSN_VMACC_VX_D_EQ_S2, true, VD_REG);
		snprintf(tag, sizeof(tag), "vmul.vx vd==vs2 vlen%u", w.vlen);
		CheckAccumulatorOrder(tag, w.vlen, INSN_VMUL_VX_D_EQ_S2, false, VD_REG);
		snprintf(tag, sizeof(tag), "FROZEN vmul.vx v8,v8,a1 vlen%u", w.vlen);
		CheckAccumulatorOrder(tag, w.vlen, INSN_KERNEL_VMUL_VX, false, KERNEL_MUL_VD);
	}

	if (g_failures) {
		printf("\nFAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("\nOK: every check passed\n");
	return 0;
}
