// Inspect production translation and LLVM lowering, not a separately assembled fixture.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdio>

using namespace dbt;
using namespace dbt::qir;

int main()
{
	unsigned failures = 0;
	for (u32 width : {512u, 1024u}) {
		for (bool materialize : {false, true}) {
		for (bool partial : {false, true}) {
			config::vlen_bits = width;
			config::aot_use_llvm = true;
			config::rvv_direct = true;
			config::rvv_lowering = 1;
			config::rvv_vector_ssa = true;
			config::rvv_vector_run = true;
			config::rvv_run_body_materialize = materialize;
			config::rvv_run_order_chunk_major = false;
			config::rvv_run_live_range_split = false;
			// elfaot does not have the QCG-only base switch; LLVM admission uses vector_ssa.
			config::rvv_qcg_typed_chunk = false;
			config::rvv_qcg_vx_mulacc = true;
			config::rvv_qcg_partial_vl = partial;
			// vsetvli a0,a0,e32,m1,ta,ma; vmul.vx v8,v8,a1;
			// vmacc.vx v9,s7,v8; jalr x0,x1,0.
			u32 words[] = {0x0d057557u, 0x9685e457u, 0xb68be4d7u, 0x00008067u};
			MemArena arena(1u << 21);
			CompilerJob::IpRangesSet ranges = {{0u, sizeof(words)}};
			CodeSegment segment(0u, 0x1000u);
			CompilerJob job(nullptr, (uptr)words, segment, std::move(ranges));
			auto *region = CompilerGenRegionIR(&arena, job);
			unsigned frames = 0;
			for (auto &bb : region->GetBlocks())
				for (auto &ins : bb.ilist)
					if (ins.GetOpcode() == Op::_rvvtypedchunkbegin &&
					    static_cast<InstRVVTypedChunkBegin *>(&ins)->n_members == 2)
						++frames;
			llvm::Module module("integer_run", g_llvm_ctx);
			LLVMGenCtx ctx(&module);
			ctx.AddFunction(0u, segment);
			QIRToLLVM gen(ctx, &segment, region, 0u);
			auto *fn = gen.Run();
			unsigned fast_calls = 0, fallback_calls = 0, muls = 0, adds = 0, active_stores = 0;
			unsigned vector_loads = 0;
			unsigned partial_guard_cmps = 0;
			for (auto &bb : *fn) {
				llvm::ConstantInt *last_pc = nullptr;
				for (auto &ins : bb) {
					if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&ins))
						vector_loads += bb.getName() == "rvv.tchunk.direct" && load->getType()->isVectorTy();
					if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&ins))
						last_pc = llvm::dyn_cast<llvm::ConstantInt>(store->getValueOperand());
					if (auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(&ins))
						partial_guard_cmps += cmp->getPredicate() == llvm::ICmpInst::ICMP_ULE;
					if (auto *call = llvm::dyn_cast<llvm::CallBase>(&ins)) {
						auto *callee = call->getCalledFunction();
						bool intrinsic = callee && callee->isIntrinsic();
						if (bb.getName() == "rvv.tchunk.direct") {
							fast_calls += !intrinsic;
							active_stores += intrinsic && callee->getName().starts_with("llvm.masked.store.");
						}
						if (bb.getName() == "rvv.tchunk.fallback") {
							unsigned member = fallback_calls++;
							auto *raw = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(1));
							if (member >= 2 || !raw || raw->getZExtValue() != words[member + 1] ||
							    !last_pc || last_pc->getZExtValue() != 4 * (member + 1)) ++failures;
						}
					}
					if (auto *op = llvm::dyn_cast<llvm::BinaryOperator>(&ins)) {
						if (!op->getType()->isVectorTy()) continue;
						muls += op->getOpcode() == llvm::Instruction::Mul;
						adds += op->getOpcode() == llvm::Instruction::Add;
						if (op->hasNoSignedWrap() || op->hasNoUnsignedWrap()) ++failures;
					}
				}
			}
			bool valid = !llvm::verifyFunction(*fn, &llvm::errs());
			bool pass = frames == 1 && fast_calls == 0 && fallback_calls == 2 &&
				muls == 2 * width / 512 && adds == width / 512 && valid &&
				vector_loads == (materialize ? 3u : 2u) * width / 512 &&
				partial_guard_cmps == unsigned(partial && !materialize) &&
				active_stores == (partial && !materialize ? 2 * width / 512 : 0);
			fprintf(stderr, "width=%u materialize=%d partial=%d frames=%u fast_calls=%u fallback_calls=%u mul=%u add=%u active_stores=%u %s\n",
				width, materialize, partial, frames, fast_calls, fallback_calls, muls, adds, active_stores, pass ? "PASS" : "FAIL");
			failures += !pass;
		}
		}
	}
	return failures != 0;
}
