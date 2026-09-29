// Native-3: focused test for the typed `vmul.vx` / `vmacc.vx` V512 chunk group as lowered by the
// LLVM/AOT backend.
//
// WHAT THIS FILE OBSERVES, and why it is a different layer from its QCG sibling.
// dbt/qmc/qcg/vxmulacc_typedchunk_route_test.cpp routes the same guest words through the same real
// translator, but every one of its checks stops at QIR, post-QRegAlloc operands, or
// objdump-decoded AsmJit bytes -- all of which are the pure-QCG (JIT) backend. None of them can see
// whether the LLVM/AOT tier admits the route at all, and before Native-3 it did not: T5b-1 §7
// recorded `vmul.vx`/`vmacc.vx` as the one hot family with NO typed lowering in EITHER backend.
//
// This file drives the REAL LLVM path end to end and inspects the REAL generated llvm::Function:
//
//     encoded guest words
//       -> qir::CompilerGenRegionIR   (the real RV32Translator, dbt/qmc/compile.cpp)
//       -> qir::QIRToLLVM::Run()      (the real LLVM backend, dbt/qmc/llvmgen/llvmgen.cpp)
//       -> llvm::Function, walked instruction by instruction below
//
// Nothing here runs a guest, mmaps code, creates a TargetMachine, runs an optimisation pipeline or
// emits an object file. The IR inspected is the IR QIRToLLVM produces, before any LLVM pass.
// Consequently NO claim about host instructions, ZMM registers, scheduling, artifacts or speed is
// made or implied by any check in this file.
//
// WHAT IS SPECIFIC TO THIS ROUTE, and therefore what this file checks that no sibling can:
//
//   * THE SCALAR IS A STATE LOAD PLUS A SPLAT, NOT A CONSTANT AND NOT A PER-LANE LOAD.
//     `vd[i] = vs2[i] * x[rs1]` reads ONE guest integer register. CheckAdmitted requires exactly one
//     i32 load from the CPUState slot of the register the ENCODING names, requires it to feed a
//     shufflevector splat whose mask is all-zero, and requires the splat to be an operand of every
//     multiply in the frame. A constant scalar would fail the load check; a per-lane gather would
//     fail the count; a wrong rs1 would fail the offset, which is computed here from offsetof.
//   * NO HELPER IS HIDING IN THE DIRECT ARM. The fast block must contain ZERO calls. That is the
//     assertion the checkpoint's whole claim rests on, because "LLVM produces vector code" is
//     defeated by one `call` the structural checks would otherwise walk straight past.
//   * THE ACCUMULATE FORM READS ITS DESTINATION. `vmacc.vx` is `vd += vs2 * x[rs1]`, so the fast arm
//     must load vd's chunks and every one of those loads must precede every store to vd. No accepted
//     route has this obligation, and at VLEN 1024 it is exactly "chunk 0's write must not pollute
//     chunk 1's read".
//   * LOW-HALF, NOT WIDENING, for the multiply -- and MODULAR, not saturating, for the add. Both are
//     modulo 2^SEW, so the function must contain no vector sext/zext/trunc and no value wider than
//     one 512-bit chunk, and neither binary operator may carry nsw or nuw.
//   * FOURTEEN SIBLING ENCODINGS SHARE THIS TRANSLATOR. `Op::_vimul` is the whole OPMVV+OPMVX
//     multiply family, so CheckSiblingsStillFailClosed drives eleven of them plus the two masked
//     forms and requires a helper call and no typed frame for each.
//
// WHAT WOULD FAIL HERE, stated so each assertion has a named failure it catches:
//   * a constant or per-lane scalar                        -> the splat/load structure checks
//   * the wrong guest register broadcast                   -> the CPUState offset check (3 rs1
//     values, including x0, whose slot is a different offset from every other register's)
//   * a helper call left in the direct arm                 -> CountCalls(fast) == 0
//   * vmacc lowered without reading vd                     -> the vd-load count check
//   * vd written before it is read                         -> the accumulator order check
//   * add/sub substituted for the multiply, or the add
//     dropped from vmacc                                   -> the per-opcode v16i32 counts
//   * nsw/nuw attached                                     -> the wrap-flag check
//   * a widening multiply                                  -> the no-cast/no-wide-vector assertions
//   * `Op::_vchunkbroadcast` missing from TChunkCheckBodyOp's whitelist -> the backend Panics while
//     building any admitted case, so the process aborts and the test cannot report success
//   * either LLVM gate switch dropped                      -> CheckGateNeedsBothSwitches
//   * partial vl or a wrong vtype admitted by the guard    -> CheckGuardRejectsPartialVl
//   * the elfaot option or the route-contract row dropped  -> CheckAotPlumbing

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_printer.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

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

// The module below MUST be built in `dbt::qir::g_llvm_ctx` (llvmgen.h) and not in a context of this
// file's own: QIRToLLVM builds every type and constant out of that one, so a private context would
// produce a function whose operands belong to a different LLVMContext than its module -- which
// llvm::verifyFunction reports as "Function context does not match Module context" and which would
// otherwise be discovered as a mysterious verifier failure rather than as this.

// ---------------------------------------------------------------------------------------------
// Guest encodings, built from the instruction fields rather than pasted, then cross-checked in
// main() against the exact constants the QCG route test uses for the same instructions and against
// the two words read out of the frozen guest ELF.
// ---------------------------------------------------------------------------------------------

constexpr u32 Zimm11(u32 vsew, u32 vlmul, u32 vta, u32 vma)
{
	return (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
}
constexpr u32 EncodeVsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}
// OPMVX: funct6[31:26], vm[25], vs2[24:20], rs1[19:15], funct3=0b110, vd[11:7], opcode 0x57.
constexpr u32 EncodeOpmvx(u32 f6, u32 vd, u32 vs2, u32 rs1, u32 vm = 1)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (rs1 << 15) | (0b110u << 12) | (vd << 7) | 0x57u;
}
// OPMVV, the vector-vector twin of the above: funct3 = 0b010 and the [19:15] field is vs1.
constexpr u32 EncodeOpmvv(u32 f6, u32 vd, u32 vs2, u32 vs1, u32 vm = 1)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (vs1 << 15) | (0b010u << 12) | (vd << 7) | 0x57u;
}

constexpr u32 F6_VMUL = 0b100101, F6_VMACC = 0b101101;
constexpr u32 F6_VMULH = 0b100111, F6_VMULHU = 0b100100, F6_VMULHSU = 0b100110;
constexpr u32 F6_VDIV = 0b100001, F6_VDIVU = 0b100000, F6_VREM = 0b100011, F6_VREMU = 0b100010;
constexpr u32 F6_VNMSAC = 0b101111, F6_VMADD = 0b101001, F6_VNMSUB = 0b101011;

constexpr u32 VTYPE_E32_M1_TA_MA = Zimm11(/*vsew=*/2, /*vlmul=*/0, /*vta=*/1, /*vma=*/1);
constexpr u32 VTYPE_E64_M1_TA_MA = Zimm11(/*vsew=*/3, /*vlmul=*/0, /*vta=*/1, /*vma=*/1);
constexpr u32 VTYPE_E32_M2_TA_MA = Zimm11(/*vsew=*/2, /*vlmul=*/1, /*vta=*/1, /*vma=*/1);

constexpr u32 INSN_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 INSN_VSETVLI_E64M1 = 0x0d857557u; // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 INSN_VSETVLI_E32M2 = 0x0d157557u; // vsetvli a0, a0, e32, m2, ta, ma

// The two words the frozen T5c-0 PolyBench gemm guest actually contains.
constexpr u32 INSN_KERNEL_VMUL_VX = 0x9685e457u;  // vmul.vx  v8, v8, a1   (vd == vs2, rs1 = x11)
constexpr u32 INSN_KERNEL_VMACC_VX = 0xb68be4d7u; // vmacc.vx v9, s7, v8   (vd = v9, rs1 = x23)

constexpr u32 VS2_REG = 1, VD_REG = 3, RS1_REG = 2;

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
constexpr u32 ST_VEC = (u32)offsetof(CPUState, vec);
constexpr u32 ST_VTYPE = ST_VEC + (u32)offsetof(rv32::VectorState, vtype);
constexpr u32 ST_VL = ST_VEC + (u32)offsetof(rv32::VectorState, vl);

constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * rv32::VLEN_MAX_BYTES + chunk * 64u;
}
// The CPUState slot of one guest integer register. Computed here from offsetof, independently of
// the translator's own expression, so a wrong rs1 is a detectable numeric difference.
constexpr u32 GprOffs(u32 reg) { return (u32)(offsetof(CPUState, gpr) + 4u * reg); }

// ---------------------------------------------------------------------------------------------
// Driving the real pipeline.
// ---------------------------------------------------------------------------------------------

void ResetConfig()
{
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_mul_force_emit = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_typed_chunk_vle = false;
	config::rvv_qcg_typed_chunk_vse = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_vx_mulacc_force_emit = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_diag_chunk_force_emit = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_counters = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_vector_run = false;
	config::aot_use_llvm = false;
	config::aot_work_counter = false;
	config::aot_region_hit_count = false;
	config::aot_region_cycle_count = false;
	config::aot_diag_direct_funcs = nullptr;
	config::aot_diag_inline_funcs = nullptr;
	config::aot_brcc_real_weights = false;
}

struct Built {
	std::unique_ptr<llvm::Module> mod;
	std::unique_ptr<MemArena> arena;
	std::unique_ptr<LLVMGenCtx> gctx;
	llvm::Function *fn = nullptr;
	Region *region = nullptr;
};

Built BuildLLVM(u32 const *words, unsigned n, u32 vlen_bits)
{
	Built b;
	config::vlen_bits = vlen_bits;

	b.arena = std::make_unique<MemArena>(1u << 20);
	CompilerJob::IpRangesSet ranges = {{0u, 4u * n}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(b.arena.get(), job);

	b.mod = std::make_unique<llvm::Module>("native3_test", g_llvm_ctx);
	b.gctx = std::make_unique<LLVMGenCtx>(b.mod.get());
	CodeSegment segment(0u, 0x1000u);
	b.gctx->AddFunction(0u, segment);
	QIRToLLVM gen(*b.gctx, &segment, b.region, 0u);
	b.fn = gen.Run();
	return b;
}

// The LLVM/AOT arm of the route: aot_use_llvm on, and BOTH of the route's switches on. The QCG
// force-emit switch is deliberately left off -- the LLVM gate carries no host-feature probe, which
// CheckLlvmRouteNeedsNoForceEmit pins on a host with no AVX-512F at all.
Built BuildLLVMRoute(u32 const *words, unsigned n, u32 vlen_bits, bool ssa = true, bool flag = true)
{
	ResetConfig();
	config::aot_use_llvm = true;
	config::rvv_vector_ssa = ssa;
	config::rvv_qcg_vx_mulacc = flag;
	return BuildLLVM(words, n, vlen_bits);
}

unsigned CountQirOp(Region *r, Op op)
{
	unsigned n = 0;
	for (auto &bb : r->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			n += ins.GetOpcode() == op;
		}
	}
	return n;
}

// ---------------------------------------------------------------------------------------------
// IR inspection helpers.
// ---------------------------------------------------------------------------------------------

llvm::Value *StripCasts(llvm::Value *v)
{
	while (auto *c = llvm::dyn_cast<llvm::BitCastInst>(v)) {
		v = c->getOperand(0);
	}
	return v;
}

bool IsV16I32(llvm::Type *t)
{
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(t);
	return vt && vt->getNumElements() == 16 && vt->getElementType()->isIntegerTy(32);
}

bool IsV8I64(llvm::Type *t)
{
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(t);
	return vt && vt->getNumElements() == 8 && vt->getElementType()->isIntegerTy(64);
}

// Any fixed vector whose total width exceeds one 512-bit chunk. The frame partitions in QIR and
// hands LLVM one chunk per value, so nothing this wide may exist -- that is what separates this
// lowering from "let the type legalizer split a <32 x i32>".
bool IsWiderThanChunk(llvm::Type *t)
{
	auto *vt = llvm::dyn_cast<llvm::FixedVectorType>(t);
	if (!vt || !vt->getElementType()->isIntegerTy()) {
		return false;
	}
	return vt->getNumElements() * vt->getElementType()->getIntegerBitWidth() > 512;
}

std::vector<llvm::BasicBlock *> BlocksNamed(llvm::Function *fn, char const *prefix)
{
	std::vector<llvm::BasicBlock *> out;
	for (auto &bb : *fn) {
		if (bb.getName().starts_with(prefix)) {
			out.push_back(&bb);
		}
	}
	return out;
}

bool StateOffsetOf(llvm::Value *ptr, llvm::Value *statev, u64 *offs)
{
	auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(StripCasts(ptr));
	if (!gep || gep->getPointerOperand() != statev || gep->getNumIndices() != 1) {
		return false;
	}
	auto *idx = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
	if (!idx || !gep->getSourceElementType()->isIntegerTy(8)) {
		return false;
	}
	*offs = idx->getZExtValue();
	return true;
}

unsigned CountCalls(llvm::BasicBlock *bb)
{
	unsigned n = 0;
	for (auto &ins : *bb) {
		n += llvm::isa<llvm::CallInst>(&ins);
	}
	return n;
}

unsigned CountBinOpV16I32(llvm::BasicBlock *bb, llvm::Instruction::BinaryOps opc)
{
	unsigned n = 0;
	for (auto &ins : *bb) {
		auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
		n += bo && bo->getOpcode() == opc && IsV16I32(bo->getType());
	}
	return n;
}

unsigned CountVectorExtOrTrunc(llvm::Function *fn)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			if (!llvm::isa<llvm::SExtInst>(&ins) && !llvm::isa<llvm::ZExtInst>(&ins) &&
			    !llvm::isa<llvm::TruncInst>(&ins)) {
				continue;
			}
			n += ins.getType()->isVectorTy();
		}
	}
	return n;
}

unsigned CountWideVectorValues(llvm::Function *fn)
{
	unsigned n = 0;
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			n += IsWiderThanChunk(ins.getType());
			for (auto &op : ins.operands()) {
				n += IsWiderThanChunk(op->getType());
			}
		}
	}
	return n;
}

struct ChunkOp {
	llvm::Instruction *ins = nullptr;
	u64 offs = 0;
	unsigned pos = 0; // position within the block, for the ordering checks
};

void CollectChunkMemOps(llvm::BasicBlock *bb, llvm::Value *statev, std::vector<ChunkOp> *loads,
			std::vector<ChunkOp> *stores)
{
	unsigned pos = 0;
	for (auto &ins : *bb) {
		u64 offs = 0;
		if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
			if (IsV8I64(ld->getType()) &&
			    StateOffsetOf(ld->getPointerOperand(), statev, &offs)) {
				loads->push_back({ld, offs, pos});
			}
		} else if (auto *st = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
			if (IsV8I64(st->getValueOperand()->getType()) &&
			    StateOffsetOf(st->getPointerOperand(), statev, &offs)) {
				stores->push_back({st, offs, pos});
			}
		}
		++pos;
	}
}

// Every i32 load in the block whose address is a CPUState offset. The scalar the broadcast reads is
// one of these; the guard's vtype/vl/vstart/vlenb reads are the others, and they are excluded by
// offset so a missing scalar cannot be masked by a guard read.
std::vector<ChunkOp> CollectScalarStateLoads(llvm::BasicBlock *bb, llvm::Value *statev)
{
	std::vector<ChunkOp> out;
	unsigned pos = 0;
	for (auto &ins : *bb) {
		u64 offs = 0;
		if (auto *ld = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
			if (ld->getType()->isIntegerTy(32) &&
			    StateOffsetOf(ld->getPointerOperand(), statev, &offs)) {
				out.push_back({ld, offs, pos});
			}
		}
		++pos;
	}
	return out;
}

// A splat is `shufflevector <insertelement poison, x, 0>, poison, zeroinitializer`. Returns the
// scalar it replicates, or nullptr. The all-zero mask is what makes it a SPLAT rather than an
// arbitrary permutation, and it is checked rather than assumed.
llvm::Value *SplatSource(llvm::Value *v)
{
	auto *sv = llvm::dyn_cast<llvm::ShuffleVectorInst>(StripCasts(v));
	if (!sv || !sv->isZeroEltSplat()) {
		return nullptr;
	}
	auto *ie = llvm::dyn_cast<llvm::InsertElementInst>(sv->getOperand(0));
	if (!ie) {
		return nullptr;
	}
	auto *idx = llvm::dyn_cast<llvm::ConstantInt>(ie->getOperand(2));
	if (!idx || !idx->isZero()) {
		return nullptr;
	}
	return ie->getOperand(1);
}

std::string PrintFn(llvm::Function *fn)
{
	std::string s;
	llvm::raw_string_ostream os(s);
	fn->print(os);
	return s;
}

// ---------------------------------------------------------------------------------------------
// The admitted case.
// ---------------------------------------------------------------------------------------------
void CheckAdmitted(char const *tag, u32 vlen_bits, unsigned nchunks, u32 expect_vlmax, u32 word,
		   bool is_macc, u32 vd, u32 vs2, u32 rs1)
{
	printf("%s: vlen=%u k=%u macc=%d vd=v%u vs2=v%u rs1=x%u\n", tag, vlen_bits, nchunks,
	       (int)is_macc, vd, vs2, rs1);

	u32 words[2] = {INSN_VSETVLI_E32M1, word};
	Built b = BuildLLVMRoute(words, 2, vlen_bits);
	CHECK(b.fn != nullptr);
	if (!b.fn) {
		return;
	}
	CHECK(!llvm::verifyFunction(*b.fn, &llvm::errs()));

	// The QIR the backend was handed: one frame, one broadcast, k multiplies, k adds for vmacc.
	CHECK_EQ(CountQirOp(b.region, Op::_rvvtypedchunkbegin), 1u);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkbroadcast), 1u);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkmul), nchunks);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkadd), is_macc ? nchunks : 0u);

	auto const fasts = BlocksNamed(b.fn, "rvv.tchunk.direct");
	auto const slows = BlocksNamed(b.fn, "rvv.tchunk.fallback");
	CHECK_EQ(fasts.size(), 1u);
	CHECK_EQ(slows.size(), 1u);
	if (fasts.size() != 1 || slows.size() != 1) {
		return;
	}
	auto *fast = fasts[0];
	auto *slow = slows[0];

	// THE CLAIM. No call in the direct arm, and exactly one in the fallback arm -- the helper this
	// route replaces, reached only on a guard miss.
	CHECK_EQ(CountCalls(fast), 0u);
	CHECK_EQ(CountCalls(slow), 1u);

	llvm::Value *statev = b.fn->getArg(0);

	// [a] THE SCALAR: exactly one i32 CPUState load in the fast arm, at the slot of the guest
	// register the ENCODING names, feeding an all-zero-mask splat.
	auto const scalars = CollectScalarStateLoads(fast, statev);
	CHECK_EQ(scalars.size(), 1u);
	if (scalars.size() != 1) {
		return;
	}
	CHECK_EQ((u32)scalars[0].offs, GprOffs(rs1));
	// The guard's own state reads live in the ENTRY block, not the fast arm, so this count cannot
	// be satisfied by one of them -- but assert the distinctness anyway, since a future guard move
	// would otherwise silently weaken the check above.
	CHECK((u32)scalars[0].offs != ST_VTYPE && (u32)scalars[0].offs != ST_VL);

	unsigned n_splats = 0;
	llvm::Value *splat = nullptr;
	for (auto &ins : *fast) {
		if (auto *sv = llvm::dyn_cast<llvm::ShuffleVectorInst>(&ins)) {
			CHECK(sv->isZeroEltSplat());
			CHECK(IsV16I32(sv->getType()));
			CHECK_EQ(SplatSource(sv), (llvm::Value *)scalars[0].ins);
			splat = sv;
			++n_splats;
		}
	}
	// ONE splat, not one per chunk: `x[rs1]` cannot change during one instruction.
	CHECK_EQ(n_splats, 1u);
	if (!splat) {
		return;
	}

	// [b] THE LANE OPERATIONS: k multiplies over <16 x i32>, k adds for vmacc and ZERO for vmul,
	// and no other v16i32 arithmetic at all.
	CHECK_EQ(CountBinOpV16I32(fast, llvm::Instruction::Mul), nchunks);
	CHECK_EQ(CountBinOpV16I32(fast, llvm::Instruction::Add), is_macc ? nchunks : 0u);
	CHECK_EQ(CountBinOpV16I32(fast, llvm::Instruction::Sub), 0u);
	CHECK_EQ(CountBinOpV16I32(fast, llvm::Instruction::And), 0u);
	CHECK_EQ(CountBinOpV16I32(fast, llvm::Instruction::Or), 0u);
	CHECK_EQ(CountBinOpV16I32(fast, llvm::Instruction::Xor), 0u);

	// Every multiply takes the splat as an operand -- the statement that the scalar reaches every
	// lane operation -- and no arithmetic carries a wrap flag, because both operations are modulo
	// 2^SEW and lane overflow is ordinary rather than exceptional.
	unsigned muls_using_splat = 0;
	for (auto &ins : *fast) {
		auto *bo = llvm::dyn_cast<llvm::BinaryOperator>(&ins);
		if (!bo || !IsV16I32(bo->getType())) {
			continue;
		}
		CHECK(!bo->hasNoSignedWrap());
		CHECK(!bo->hasNoUnsignedWrap());
		if (bo->getOpcode() == llvm::Instruction::Mul &&
		    (StripCasts(bo->getOperand(0)) == splat || StripCasts(bo->getOperand(1)) == splat)) {
			++muls_using_splat;
		}
	}
	CHECK_EQ(muls_using_splat, nchunks);

	// [c] NOT A WIDENING LOWERING and NOT one wide vector: no vector cast, nothing above 512 bits.
	CHECK_EQ(CountVectorExtOrTrunc(b.fn), 0u);
	CHECK_EQ(CountWideVectorValues(b.fn), 0u);

	// [d] THE CPUState WINDOWS, and for vmacc the ACCUMULATOR READ-BEFORE-WRITE.
	std::vector<ChunkOp> loads, stores;
	CollectChunkMemOps(fast, statev, &loads, &stores);
	CHECK_EQ(loads.size(), (size_t)(is_macc ? 2u * nchunks : nchunks));
	CHECK_EQ(stores.size(), (size_t)nchunks);

	unsigned vd_loads = 0, vs2_loads = 0;
	unsigned last_vd_read = 0, first_vd_write = ~0u;
	bool saw_vd_read = false;
	for (auto const &l : loads) {
		bool const is_vd = l.offs >= ChunkOffs(vd, 0) &&
				   l.offs < ChunkOffs(vd, 0) + rv32::VLEN_MAX_BYTES;
		bool const is_vs2 = l.offs >= ChunkOffs(vs2, 0) &&
				    l.offs < ChunkOffs(vs2, 0) + rv32::VLEN_MAX_BYTES;
		CHECK(is_vd || is_vs2);
		vd_loads += is_vd;
		vs2_loads += is_vs2;
		if (is_vd) {
			last_vd_read = l.pos;
			saw_vd_read = true;
		}
	}
	for (auto const &s : stores) {
		CHECK(s.offs >= ChunkOffs(vd, 0) &&
		      s.offs < ChunkOffs(vd, 0) + rv32::VLEN_MAX_BYTES);
		first_vd_write = std::min(first_vd_write, s.pos);
	}
	// vmacc reads vd once per chunk. A vmul whose vd == vs2 reads it once per chunk too, through
	// the vs2 load, so the ordering assertion below applies in both cases and is asserted whenever
	// any vd read exists.
	if (is_macc) {
		CHECK_EQ(vd_loads, vd == vs2 ? 2u * nchunks : nchunks);
	}
	CHECK(vs2_loads >= nchunks);
	if (saw_vd_read) {
		CHECK(last_vd_read < first_vd_write);
	}

	// Each chunk's 64-byte windows, exactly.
	for (unsigned c = 0; c < nchunks; ++c) {
		bool found_store = false;
		for (auto const &s : stores) {
			found_store = found_store || s.offs == ChunkOffs(vd, c);
		}
		CHECK(found_store);
		bool found_src = false;
		for (auto const &l : loads) {
			found_src = found_src || l.offs == ChunkOffs(vs2, c);
		}
		CHECK(found_src);
	}

	printf("  ok  fast: calls=0 splat=1 @state:0x%x mul=%u add=%u loads=%zu stores=%zu\n",
	       GprOffs(rs1), nchunks, is_macc ? nchunks : 0u, loads.size(), stores.size());
	(void)expect_vlmax;
}

// ---------------------------------------------------------------------------------------------
// Non-admitted shapes.
// ---------------------------------------------------------------------------------------------
void CheckNotAdmitted(char const *tag, u32 const *words, unsigned n, u32 vlen_bits, char const *why)
{
	Built b = BuildLLVMRoute(words, n, vlen_bits);
	CHECK(b.fn != nullptr);
	if (!b.fn) {
		return;
	}
	CHECK_EQ(CountQirOp(b.region, Op::_rvvtypedchunkbegin), 0u);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkbroadcast), 0u);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkmul), 0u);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkadd), 0u);
	CHECK_EQ(BlocksNamed(b.fn, "rvv.tchunk.direct").size(), 0u);
	// The instruction still executes, through the helper this build already had.
	unsigned calls = 0;
	for (auto &bb : *b.fn) {
		calls += CountCalls(&bb);
	}
	CHECK(calls >= 1u);
	printf("  not admitted (%-40s vlen=%u): no typed frame, %u call(s)  ok\n", why, vlen_bits,
	       calls);
}

// FOURTEEN ENCODINGS SHARE THIS TRANSLATOR. Each row is refused by a different field of
// RvvVxMulAccShapeAdmit, and every one of them must still reach the helper.
void CheckSiblingsStillFailClosed(u32 vlen_bits)
{
	struct Row {
		char const *why;
		u32 word;
	};
	Row const rows[] = {
	    {"vmul.vx masked (vm=0)", EncodeOpmvx(F6_VMUL, VD_REG, VS2_REG, RS1_REG, 0)},
	    {"vmacc.vx masked (vm=0)", EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG, 0)},
	    {"vmulh.vx (high half)", EncodeOpmvx(F6_VMULH, VD_REG, VS2_REG, RS1_REG)},
	    {"vmulhu.vx", EncodeOpmvx(F6_VMULHU, VD_REG, VS2_REG, RS1_REG)},
	    {"vmulhsu.vx", EncodeOpmvx(F6_VMULHSU, VD_REG, VS2_REG, RS1_REG)},
	    {"vdiv.vx", EncodeOpmvx(F6_VDIV, VD_REG, VS2_REG, RS1_REG)},
	    {"vdivu.vx", EncodeOpmvx(F6_VDIVU, VD_REG, VS2_REG, RS1_REG)},
	    {"vrem.vx", EncodeOpmvx(F6_VREM, VD_REG, VS2_REG, RS1_REG)},
	    {"vremu.vx", EncodeOpmvx(F6_VREMU, VD_REG, VS2_REG, RS1_REG)},
	    {"vnmsac.vx (SUBTRACTS the product)", EncodeOpmvx(F6_VNMSAC, VD_REG, VS2_REG, RS1_REG)},
	    {"vmadd.vx (vd is a MULTIPLICAND)", EncodeOpmvx(F6_VMADD, VD_REG, VS2_REG, RS1_REG)},
	    {"vnmsub.vx (vd is a MULTIPLICAND)", EncodeOpmvx(F6_VNMSUB, VD_REG, VS2_REG, RS1_REG)},
	    {"vmacc.vv (OPMVV: no scalar)", EncodeOpmvv(F6_VMACC, VD_REG, VS2_REG, RS1_REG)},
	};
	for (auto const &r : rows) {
		u32 w[2] = {INSN_VSETVLI_E32M1, r.word};
		CheckNotAdmitted("sibling", w, 2, vlen_bits, r.why);
	}
}

// ---------------------------------------------------------------------------------------------
// Gates.
// ---------------------------------------------------------------------------------------------
void CheckGateNeedsBothSwitches(u32 vlen_bits, u32 word, bool is_macc)
{
	printf("gate: BOTH --rvv-vector-ssa and --rvv-qcg-vx-mulacc are required (vlen=%u macc=%d)\n",
	       vlen_bits, (int)is_macc);
	u32 words[2] = {INSN_VSETVLI_E32M1, word};
	{
		Built b = BuildLLVMRoute(words, 2, vlen_bits, /*ssa=*/false, /*flag=*/true);
		CHECK_EQ(CountQirOp(b.region, Op::_vchunkbroadcast), 0u);
		printf("  --rvv-vector-ssa off -> no typed frame  ok\n");
	}
	{
		Built b = BuildLLVMRoute(words, 2, vlen_bits, /*ssa=*/true, /*flag=*/false);
		CHECK_EQ(CountQirOp(b.region, Op::_vchunkbroadcast), 0u);
		printf("  --rvv-qcg-vx-mulacc off (the default) -> no typed frame  ok\n");
	}
	{
		Built b = BuildLLVMRoute(words, 2, vlen_bits, /*ssa=*/true, /*flag=*/true);
		CHECK_EQ(CountQirOp(b.region, Op::_vchunkbroadcast), 1u);
		CHECK_EQ(CountQirOp(b.region, Op::_vchunkmul), vlen_bits / 512u);
		printf("  both on -> the frame exists  ok\n");
	}
}

// The LLVM arm has NO host-feature probe, and this test runs on a host with no AVX-512F at all --
// so the fact that every admitted case above produced a frame WITHOUT the force-emit switch is the
// proof. Stated as its own check so the property is named rather than incidental.
void CheckLlvmRouteNeedsNoForceEmit()
{
	printf("gate: the LLVM arm admits with force_emit OFF (this host has no AVX-512F)\n");
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG)};
	// BuildLLVMRoute's own ResetConfig clears force_emit, so the assertion below is about the
	// state the frame was ACTUALLY built under rather than about a value set beforehand -- which is
	// the whole content of the claim, and is why the check comes after the build and not before it.
	// (CheckQcgArmStillAdmits leaves force_emit on, because the QCG arm needs it on this host.)
	Built b = BuildLLVMRoute(words, 2, 512);
	CHECK(!config::rvv_qcg_vx_mulacc_force_emit);
	CHECK_EQ(CountQirOp(b.region, Op::_vchunkbroadcast), 1u);
	printf("  ok\n");
}

// The pure-QCG arm must be unmoved by everything above: with aot_use_llvm off and the route flag on,
// the QCG gate is what admits, and it produces the SAME QIR node counts.
void CheckQcgArmStillAdmits(u32 vlen_bits, u32 word, bool is_macc)
{
	printf("gate: the pure-QCG arm still admits the same shape (vlen=%u macc=%d)\n", vlen_bits,
	       (int)is_macc);
	ResetConfig();
	config::aot_use_llvm = false;
	config::rvv_qcg_vx_mulacc = true;
	config::rvv_qcg_vx_mulacc_force_emit = true; // no AVX-512F on this host
	u32 words[2] = {INSN_VSETVLI_E32M1, word};
	MemArena arena(1u << 20);
	config::vlen_bits = vlen_bits;
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	Region *r = CompilerGenRegionIR(&arena, job);
	CHECK_EQ(CountQirOp(r, Op::_vchunkbroadcast), 1u);
	CHECK_EQ(CountQirOp(r, Op::_vchunkmul), vlen_bits / 512u);
	CHECK_EQ(CountQirOp(r, Op::_vchunkadd), is_macc ? vlen_bits / 512u : 0u);
	printf("  ok\n");
}

// The guard the frame emits must read vl and compare it against VLMAX, so a partial vl takes the
// helper at RUN time even though translation admitted the shape. Read out of the IR rather than
// asserted from the source.
void CheckGuardRejectsPartialVl(u32 vlen_bits, u32 expect_vlmax)
{
	printf("guard: vl is compared against VLMAX=%u (vlen=%u)\n", expect_vlmax, vlen_bits);
	u32 words[2] = {INSN_VSETVLI_E32M1, EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG)};
	Built b = BuildLLVMRoute(words, 2, vlen_bits);
	CHECK(b.fn != nullptr);
	if (!b.fn) {
		return;
	}
	llvm::Value *statev = b.fn->getArg(0);
	bool found_vl_cmp = false;
	for (auto &bb : *b.fn) {
		for (auto &ins : bb) {
			auto *icmp = llvm::dyn_cast<llvm::ICmpInst>(&ins);
			if (!icmp || icmp->getPredicate() != llvm::CmpInst::ICMP_EQ) {
				continue;
			}
			auto *ld = llvm::dyn_cast<llvm::LoadInst>(icmp->getOperand(0));
			auto *ci = llvm::dyn_cast<llvm::ConstantInt>(icmp->getOperand(1));
			u64 offs = 0;
			if (!ld || !ci || !StateOffsetOf(ld->getPointerOperand(), statev, &offs)) {
				continue;
			}
			if ((u32)offs == ST_VL) {
				CHECK_EQ((u32)ci->getZExtValue(), expect_vlmax);
				found_vl_cmp = true;
			}
		}
	}
	CHECK(found_vl_cmp);
	printf("  ok\n");
}

// ---------------------------------------------------------------------------------------------
// AOT reachability, at the source level.
//
// A lowering plus a gate makes the route REACHABLE IN THIS PROCESS; neither of them proves an
// ARTIFACT can ever take it. That needs an `elfaot` option that can set the flag and a
// `kRvvRouteContract` row that carries the parent's value to every background builder -- and their
// absence is exactly the defect T1a recorded for vsub.vv (a complete, tested, unreachable route).
// ---------------------------------------------------------------------------------------------
std::string ReadFile(char const *rel)
{
	std::string const path = std::string(DBT_SOURCE_ROOT) + "/" + rel;
	std::ifstream f(path);
	if (!f) {
		fprintf(stderr, "  FAIL cannot open %s\n", path.c_str());
		++g_failures;
		return {};
	}
	std::ostringstream ss;
	ss << f.rdbuf();
	return ss.str();
}

void CheckAotPlumbing()
{
	printf("AOT reachability (source-level):\n");
	std::string const aot = ReadFile("dbt/elfaot.cpp");
	CHECK(aot.find("\"rvv-qcg-vx-mulacc\"") != std::string::npos);
	CHECK(aot.find("dbt::config::rvv_qcg_vx_mulacc = opts.rvv_qcg_vx_mulacc;") !=
	      std::string::npos);
	printf("  elfaot: --rvv-qcg-vx-mulacc declared and assigned to config\n");

	std::string const boot = ReadFile("dbt/aot/aot_boot.cpp");
	auto const tbl = boot.find("kRvvRouteContract[]");
	CHECK(tbl != std::string::npos);
	auto const tbl_end = boot.find("};", tbl);
	CHECK(tbl_end != std::string::npos);
	if (tbl != std::string::npos && tbl_end != std::string::npos) {
		std::string const body = boot.substr(tbl, tbl_end - tbl);
		CHECK(body.find("\"rvv-qcg-vx-mulacc\"") != std::string::npos);
		CHECK(body.find("&config::rvv_qcg_vx_mulacc") != std::string::npos);
	}
	printf("  aot_boot: kRvvRouteContract carries the flag to every spawn site\n");

	std::string const audit = ReadFile("scripts/vlen_propagation_audit.py");
	CHECK(audit.find("(\"rvv-qcg-vx-mulacc\", \"rvv_qcg_vx_mulacc\", \"Route\")") != std::string::npos);
	printf("  vlen_propagation_audit.py: ROUTE_FLAGS mirror updated in lockstep\n");
}

} // namespace

int main(int argc, char **argv)
{
	bool dump_ir = false;
	for (int i = 1; i < argc; ++i) {
		dump_ir = dump_ir || strcmp(argv[i], "--dump-ir") == 0;
	}
	printf("Native-3 typed vmul.vx / vmacc.vx LLVM route test\n");

	// The field-built encodings reproduce the exact constants the QCG route test uses, and the two
	// words read out of the frozen guest ELF. A drift in either direction is caught here rather
	// than by two files quietly testing different instructions.
	CHECK_EQ(EncodeVsetvli(VTYPE_E32_M1_TA_MA), INSN_VSETVLI_E32M1);
	CHECK_EQ(EncodeVsetvli(VTYPE_E64_M1_TA_MA), INSN_VSETVLI_E64M1);
	CHECK_EQ(EncodeVsetvli(VTYPE_E32_M2_TA_MA), INSN_VSETVLI_E32M2);
	CHECK_EQ(EncodeOpmvx(F6_VMUL, VD_REG, VS2_REG, RS1_REG), 0x961161d7u);  // vmul.vx v3,v1,sp
	CHECK_EQ(EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG), 0xb61161d7u); // vmacc.vx v3,sp,v1
	CHECK_EQ(EncodeOpmvx(F6_VMUL, 8, 8, 11), INSN_KERNEL_VMUL_VX);
	CHECK_EQ(EncodeOpmvx(F6_VMACC, 9, 8, 23), INSN_KERNEL_VMACC_VX);

	printf("\n== admitted: VLEN=512, one chunk ==\n");
	CheckAdmitted("vmul.vx v512", 512, 1, 16, EncodeOpmvx(F6_VMUL, VD_REG, VS2_REG, RS1_REG),
		      false, VD_REG, VS2_REG, RS1_REG);
	CheckAdmitted("vmacc.vx v512", 512, 1, 16, EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG),
		      true, VD_REG, VS2_REG, RS1_REG);

	printf("\n== admitted: VLEN=1024, two independent chunks ==\n");
	CheckAdmitted("vmul.vx v1024", 1024, 2, 32, EncodeOpmvx(F6_VMUL, VD_REG, VS2_REG, RS1_REG),
		      false, VD_REG, VS2_REG, RS1_REG);
	CheckAdmitted("vmacc.vx v1024", 1024, 2, 32, EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG),
		      true, VD_REG, VS2_REG, RS1_REG);

	printf("\n== admitted: the scalar is the ENCODING's rs1, at three values ==\n");
	for (u32 vlen : {512u, 1024u}) {
		unsigned const k = vlen / 512u;
		// x0: its slot is never written and reads zero -- the same word the helper reads.
		CheckAdmitted("vmul.vx rs1=x0", vlen, k, 0, EncodeOpmvx(F6_VMUL, VD_REG, VS2_REG, 0),
			      false, VD_REG, VS2_REG, 0);
		CheckAdmitted("vmacc.vx rs1=x0", vlen, k, 0,
			      EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, 0), true, VD_REG, VS2_REG, 0);
		// x31: the last register, and a different slot from every other.
		CheckAdmitted("vmul.vx rs1=x31", vlen, k, 0,
			      EncodeOpmvx(F6_VMUL, 31, 31, 31), false, 31, 31, 31);
	}

	printf("\n== admitted: the legal vd == vs2 overlap ==\n");
	for (u32 vlen : {512u, 1024u}) {
		unsigned const k = vlen / 512u;
		CheckAdmitted("vmul.vx vd==vs2", vlen, k, 0,
			      EncodeOpmvx(F6_VMUL, VD_REG, VD_REG, RS1_REG), false, VD_REG, VD_REG,
			      RS1_REG);
		CheckAdmitted("vmacc.vx vd==vs2", vlen, k, 0,
			      EncodeOpmvx(F6_VMACC, VD_REG, VD_REG, RS1_REG), true, VD_REG, VD_REG,
			      RS1_REG);
	}

	printf("\n== admitted: THE FROZEN GUEST'S OWN WORDS ==\n");
	for (u32 vlen : {512u, 1024u}) {
		unsigned const k = vlen / 512u;
		CheckAdmitted("FROZEN vmul.vx v8,v8,a1", vlen, k, 0, INSN_KERNEL_VMUL_VX, false, 8, 8,
			      11);
		CheckAdmitted("FROZEN vmacc.vx v9,s7,v8", vlen, k, 0, INSN_KERNEL_VMACC_VX, true, 9, 8,
			      23);
	}

	printf("\n== gates ==\n");
	for (u32 vlen : {512u, 1024u}) {
		CheckGateNeedsBothSwitches(vlen, EncodeOpmvx(F6_VMUL, VD_REG, VS2_REG, RS1_REG), false);
		CheckGateNeedsBothSwitches(vlen, EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG), true);
		CheckQcgArmStillAdmits(vlen, EncodeOpmvx(F6_VMUL, VD_REG, VS2_REG, RS1_REG), false);
		CheckQcgArmStillAdmits(vlen, EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG), true);
	}
	CheckLlvmRouteNeedsNoForceEmit();

	printf("\n== guard: partial vl takes the helper ==\n");
	CheckGuardRejectsPartialVl(512, 16);
	CheckGuardRejectsPartialVl(1024, 32);

	printf("\n== the thirteen sibling encodings that share this translator ==\n");
	CheckSiblingsStillFailClosed(512);
	CheckSiblingsStillFailClosed(1024);

	printf("\n== non-admitted vtype shapes stay on the helper path ==\n");
	for (u32 vlen : {512u, 1024u}) {
		{
			u32 w[2] = {INSN_VSETVLI_E64M1,
				    EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG)};
			CheckNotAdmitted("e64,m1", w, 2, vlen, "unsupported SEW (e64)");
		}
		{
			u32 w[2] = {INSN_VSETVLI_E32M2,
				    EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG)};
			CheckNotAdmitted("e32,m2", w, 2, vlen, "unsupported LMUL (m2)");
		}
	}
	printf("\n== VLEN outside the measured envelope ==\n");
	for (u32 vlen : {2048u, 4096u}) {
		u32 w[2] = {INSN_VSETVLI_E32M1, EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG)};
		CheckNotAdmitted("vlen>1024", w, 2, vlen, "outside the Native-3 envelope");
	}

	printf("\n== AOT plumbing ==\n");
	CheckAotPlumbing();

	if (dump_ir) {
		u32 words[2] = {INSN_VSETVLI_E32M1, EncodeOpmvx(F6_VMACC, VD_REG, VS2_REG, RS1_REG)};
		Built b = BuildLLVMRoute(words, 2, 1024);
		printf("\n----- IR DUMP vmacc.vx (vlen=1024) -----\n%s", PrintFn(b.fn).c_str());
	}

	if (g_failures) {
		printf("\nFAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("\nOK: every check passed\n");
	return 0;
}
