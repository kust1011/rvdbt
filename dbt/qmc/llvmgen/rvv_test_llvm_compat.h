#pragma once

// ORDER ITEM 5 (C8/C9, 2026-09-19): THE ONE PLACE THAT KNOWS WHERE A MASKED STORE'S MASK IS.
//
// FOUND BY BUILDING THE TREE ON THE PRODUCTION HOST, which is the whole reason that step exists.
// Every focused check that inspects a `llvm.masked.store` read its mask as `getArgOperand(3)`,
// which is correct on the development host's LLVM 20 and WRONG on xbd's LLVM 22:
//
//   LLVM 20  int_masked_store : (anyvector, anyptr, i32 align, <N x i1> mask)   mask = operand 3
//   LLVM 22  int_masked_store : (anyvector, anyptr,            <N x i1> mask)   mask = operand 2
//
// The alignment moved from an argument to a parameter attribute. `IRBuilder::CreateMaskedStore`
// still takes an `Align` in both, so THE EMITTED CODE IS UNAFFECTED and no production path changes;
// what was wrong was every test's assumption about the operand index. On LLVM 22 the tests read a
// different value (or, for the 3-operand form, the mask's own type position), so the mask-term
// assertions silently measured nothing and reported zero -- four of six order-item-3/4 checks
// failed on xbd while all six passed locally.
//
// It is a header rather than a copy in each test because the failure mode of a copy is exactly what
// happened here: one shared fact, restated in nine files, none of which was version-guarded.

#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"

namespace dbt::qir::testcompat
{

// The mask operand of an `llvm.masked.store` call.
inline llvm::Value *MaskedStoreMask(llvm::CallInst const *ii)
{
#if LLVM_VERSION_MAJOR >= 22
	return ii->getArgOperand(2);
#else
	return ii->getArgOperand(3);
#endif
}

// The mask operand of an `llvm.masked.load` call. Same change, one position earlier: LLVM 20's
// signature is `(ptr, i32 align, mask, passthru)` and LLVM 22's is `(ptr, mask, passthru)`.
inline llvm::Value *MaskedLoadMask(llvm::CallInst const *ii)
{
#if LLVM_VERSION_MAJOR >= 22
	return ii->getArgOperand(1);
#else
	return ii->getArgOperand(2);
#endif
}

// C6 (2026-09-20): the mask and passthru operands of an `llvm.masked.gather` call.
//
// THE SAME CHANGE AGAIN, and found the same way -- by building on the production host. The gather
// carried an alignment ARGUMENT in LLVM 20 and carries a parameter attribute in LLVM 22:
//
//   LLVM 20  int_masked_gather : (anyvector ptrs, i32 align, <N x i1> mask, anyvector passthru)
//   LLVM 22  int_masked_gather : (anyvector ptrs,            <N x i1> mask, anyvector passthru)
//
// `rvv_llvm_gatherslide_test` folds the gather itself against a register-file image, so on LLVM 22
// it read the PASSTHRU where it expected the mask and fell off the end for the passthru -- every
// cell reported "did not fold", 1,724 failures on xbd while the same binary passed locally. The
// emitted code is again unaffected: `IRBuilder::CreateMaskedGather` takes an `Align` in both.
inline llvm::Value *MaskedGatherMask(llvm::CallInst const *ii)
{
#if LLVM_VERSION_MAJOR >= 22
	return ii->getArgOperand(1);
#else
	return ii->getArgOperand(2);
#endif
}

inline llvm::Value *MaskedGatherPassThru(llvm::CallInst const *ii)
{
#if LLVM_VERSION_MAJOR >= 22
	return ii->getArgOperand(2);
#else
	return ii->getArgOperand(3);
#endif
}

// C7 (2026-09-20): the mask operand of an `llvm.masked.scatter` call. Same change once more:
//
//   LLVM 20  int_masked_scatter : (anyvector value, anyvector ptrs, i32 align, <N x i1> mask)
//   LLVM 22  int_masked_scatter : (anyvector value, anyvector ptrs,            <N x i1> mask)
//
// Added WITH the gather accessors rather than after xbd reported it, because by this point the
// pattern is established: every masked memory intrinsic in this family moved its alignment from an
// argument to a parameter attribute between 20 and 22.
inline llvm::Value *MaskedScatterMask(llvm::CallInst const *ii)
{
#if LLVM_VERSION_MAJOR >= 22
	return ii->getArgOperand(2);
#else
	return ii->getArgOperand(3);
#endif
}

} // namespace dbt::qir::testcompat
