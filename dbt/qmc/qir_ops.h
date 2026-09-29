#pragma once

#define QIR_DEF_APPLY_CLASS2BASE(name, cls, flags) CLASS(cls, name, name)

#define QIR_DEF_LIST(LEAF, BASE, CLASS)                                                                      \
	BASE(hcall, InstHcall, Flags::SIDEEFF | Flags::HAS_CALLS)                                            \
	BASE(br, InstBr, 0)                                                                                  \
	BASE(brcc, InstBrcc, 0)                                                                              \
	BASE(gbr, InstGBr, Flags::REXIT)                                                                     \
	BASE(gbrind, InstGBrind, Flags::REXIT)                                                               \
	BASE(vmload, InstVMLoad, Flags::SIDEEFF)                                         					 \
	BASE(vmload2, InstVMLoad2, Flags::SIDEEFF)										                     \
	BASE(vmload4, InstVMLoad4, Flags::SIDEEFF)										                     \
	BASE(vmstore, InstVMStore, Flags::SIDEEFF)                                       					 \
	BASE(vmstore2, InstVMStore2, Flags::SIDEEFF)										                     \
	BASE(vmstore4, InstVMStore4, Flags::SIDEEFF)										                     \
	/* RVV direct lowering: inline SSE2 for vadd.vv, guarded, helper on fallback */                      \
	BASE(rvvaddv, InstRVVAddV, Flags::SIDEEFF | Flags::HAS_CALLS)                                        \
	/* T7m certificate-selected 64-byte sibling component, lowered directly with four XMM ops. */       \
	BASE(ccrfchunk, InstCCRFChunk, Flags::SIDEEFF | Flags::HAS_CALLS)                                    \
	/* T7p identity-bound compute-region sibling stream. One node owns one region invocation: */         \
	/* vector live-ins are loaded once, certified vadd.vv members execute in a host loop, and */         \
	/* vector live-outs are published once. There is no helper or per-member synchronization. */        \
	BASE(ccrfcompute, InstCCRFComputeRegion, Flags::SIDEEFF | Flags::HAS_CALLS)                           \
	/* DIAGNOSTIC CONTROL, NOT THE METHOD. An untyped side-effect-node group that flattens      */      \
	/* Emit_rvvaddv's emitter loop into one node per 512-bit host chunk. These ops carry NO      */      \
	/* operands (InstNoOperands): no QIR value, no def-use edge, no register allocation. Chunk   */      \
	/* data still travels through CPUState memory and each chunk's ZMM is hardcoded by the       */      \
	/* emitter from the node's `index`. It exists only as the A/B control for the typed          */      \
	/* V512-value lowering, and to show the guard/fallback plumbing is connected.                */      \
	/* HAS_CALLS sits on `begin` because that is where the register allocator must place the     */      \
	/* call boundary: the guard `begin` emits jumps PAST the chunk ops to the fallback label     */      \
	/* bound by `end`, so a spill placed at `end` would be skipped on exactly the path that      */      \
	/* makes the call.                                                                           */      \
	BASE(rvvdiagchunkbegin, InstRVVDiagChunkBegin, Flags::SIDEEFF | Flags::HAS_CALLS)                    \
	BASE(rvvdiagchunkadd, InstRVVDiagChunkAdd, Flags::SIDEEFF)                                           \
	BASE(rvvdiagchunkend, InstRVVDiagChunkEnd, Flags::SIDEEFF)                                           \
	/* Typed 512-bit host chunk values (see qir.h). Real V512 operands with def-use, allocated  */      \
	/* by QRegAlloc's VPR class. SIDEEFF on load/store because they touch guest memory, exactly */      \
	/* as vmload/vmstore do; vchunkadd/mul/sub/xor/or are pure.                                 */      \
	/* ROUTING, per op -- do not read the group as one. vchunkadd is routed from vadd.vv,       */      \
	/* vchunkmul from vmul.vv, vchunksub from vsub.vv, vchunkxor from vxor.vv, vchunkor from    */      \
	/* vor.vv and vchunkand from vand.vv. vchunkload is routed from exact unmasked unit-stride  */      \
	/* vle32.v (S2.6) and vchunkstore from exact unmasked unit-stride vse32.v (S2.7), in BOTH   */      \
	/* cases ONLY in the op's INDIRECT addressing form and only for that one admitted shape     */      \
	/* (EEW=32 from the encoding, SEW=32/LMUL=1 so EMUL=1, vstart=0, vl=VLMAX, VLEN 512 or      */      \
	/* 1024, pure QCG, base register != x0); every other shape keeps the pre-existing rv32_vle  */      \
	/* / rv32_vse helper. Their DIRECT addressing form remains unrouted -- its only callers are */      \
	/* the mechanism tests -- see the per-op routing notes in qir.h.                            */      \
	BASE(vchunkload, InstVChunkLoad, Flags::SIDEEFF)                                                     \
	BASE(vchunkadd, InstVChunkAdd, 0)                                                                    \
	/* T7b: one original vadd.vv over one or two V512 SSA chunks. LLVM alone joins/splits the   */      \
	/* chunks around one VLEN-wide add; the pure-QCG backend rejects this node.                 */      \
	BASE(vwideaddssa, InstRVVWideAddSSA, 0)                                                              \
	/* Separate opcode rather than an ALU-selector field on vchunkadd: the accepted vadd.vv     */      \
	/* route, its emitter and its tests all read `vchunkadd` as "this frame adds", and widening */      \
	/* that op into a two-operation node would change an accepted signature for no gain. One    */      \
	/* opcode per host instruction also keeps Emit_* free of an operation switch.               */      \
	BASE(vchunkmul, InstVChunkMul, 0)                                                                    \
	/* Routed from vsub.vv (S2.1). Separate opcode for the same reason vchunkmul is one, plus  */      \
	/* one this op has on its own: subtraction does not commute, so its input ORDER is part of */      \
	/* its meaning (input 0 minus input 1) rather than a naming convention -- see qir.h.       */      \
	BASE(vchunksub, InstVChunkSub, 0)                                                                    \
	/* Routed from vxor.vv (S2.2). Separate opcode again, and the first BITWISE one: its      */      \
	/* sew_bytes records the admitted guest SEW but does not select a host instruction, since */      \
	/* an unmasked 512-bit xor is lane-width-independent -- see qir.h.                        */      \
	BASE(vchunkxor, InstVChunkXor, 0)                                                                    \
	/* Routed from vor.vv (S2.3). Separate opcode for the same reasons vchunkxor is one, and */      \
	/* NOT a selector field added to vchunkxor: `vpxord` and `vpord` are different host      */      \
	/* instructions, and folding them into one node would put the choice between them behind */      \
	/* a field whose wrong value produces working, structurally perfect, wrong-valued code.  */      \
	BASE(vchunkor, InstVChunkOr, 0)                                                                      \
	/* Routed from vand.vv (S2.4). Separate opcode for the same reasons vchunkor is one, and  */      \
	/* the argument is at its strongest here: `vpandd`, `vpord` and `vpxord` are three near-  */      \
	/* identical host instructions and this is the THIRD of them to be routed, so a selector  */      \
	/* field would now be a three-way choice whose wrong value produces working, structurally */      \
	/* perfect, wrong-valued code -- see qir.h.                                                */      \
	BASE(vchunkand, InstVChunkAnd, 0)                                                                    \
	/* P7N-B. Routed from vsll.vi and vsrl.vi (the exact unmasked OPIVI forms). SEPARATE  */      \
	/* opcodes rather than a shift-kind field, for the reason vchunkor is separate from  */      \
	/* vchunkxor: `vpslld` and `vpsrld` are different host instructions, and the opcode  */      \
	/* name is the only textual thing a dump carries to tell a left shift from a right   */      \
	/* one. Flags are `0` -- pure register-to-register lane computation, no side effect. */      \
	/* THESE ARE THE FIRST ONE-SOURCE chunk ALU ops: the shift amount is a 5-bit         */      \
	/* translation-time IMMEDIATE from the guest encoding, not a second vector operand.  */      \
	BASE(vchunksll, InstVChunkSll, 0)                                                                    \
	BASE(vchunksrl, InstVChunkSrl, 0)                                                                    \
	BASE(vchunkstore, InstVChunkStore, Flags::SIDEEFF)                                                   \
	/* Reads 64 bytes of CPUState (NOT guest memory) at a validated constant offset into a      */      \
	/* V512 value. SIDEEFF because the window it reads may overlap a state slot that a guest    */      \
	/* global is currently holding dirty in a host register -- see qir.h.                       */      \
	BASE(vstatechunkload, InstVStateChunkLoad, Flags::SIDEEFF)                                           \
	/* Writes a V512 value to 64 bytes of CPUState (NOT guest memory) at a validated constant  */      \
	/* offset. SIDEEFF for both reasons: it is a memory write, and the window may overlap a    */      \
	/* guest global's state slot -- see the limitation noted in qir.h.                         */      \
	BASE(vstatechunkstore, InstVStateChunkStore, Flags::SIDEEFF)                                         \
	/* Native-3. Reads ONE 32-bit word of CPUState -- a guest GPR slot -- at a validated       */      \
	/* constant offset and splats it across every lane of a V512 value. Routed from the        */      \
	/* SCALAR operand of unmasked e32/LMUL=1 `vmul.vx` and `vmacc.vx` (rv32_qir.cpp), and      */      \
	/* from nothing else. SIDEEFF for vstatechunkload's reason and no weaker: the word it      */      \
	/* reads IS a guest global's state slot, so the allocator must have synced that global     */      \
	/* back to CPUState before it runs -- which the enclosing rvvtypedchunkbegin's HAS_CALLS   */      \
	/* guarantees -- and a pure node could be hoisted across a helper call that writes it.     */      \
	BASE(vchunkbroadcast, InstVChunkBroadcast, Flags::SIDEEFF)                                           \
	BASE(vchunkfbroadcast, InstVChunkFBroadcast, Flags::SIDEEFF)                                        \
	BASE(vchunkfalu, InstVChunkFALU, 0)                                                                \
	/* P7I. The FUSED three-input form of the line above; see qir.h InstVChunkFMA for why it is  */     \
	/* a separate node and not a third operand on vchunkfalu. Flags are `0` for exactly the      */     \
	/* same reason vchunkfalu's are: it is a pure register-to-register lane computation that     */     \
	/* touches no memory and no guest global, and every CPUState access in its frame belongs to  */     \
	/* the surrounding vstatechunkload/vstatechunkstore pair, which carry SIDEEFF themselves.    */     \
	BASE(vchunkfma, InstVChunkFMA, 0)                                                                  \
	/* THE ONE-SOURCE FP LANE OP. vfsqrt.v has a single vector operand: there is no second      */     \
	/* register in the encoding and no identity element that could stand in for one, so it gets */     \
	/* its own node rather than a vchunkfalu with an invented operand -- an invented operand    */     \
	/* would be a live value the allocator must keep, and a lie about the dataflow. This is the */     \
	/* same reason vchunksll is separate from the two-source bitwise ops, one level up in the   */     \
	/* FP world. Flags are `0`: pure register-to-register lane computation, no memory, no guest */     \
	/* global, exactly as vchunkfalu and vchunkfma. See qir.h InstVChunkFSqrt.                  */     \
	BASE(vchunkfsqrt, InstVChunkFSqrt, 0)                                                              \
	/* P9. THE MASK-PRODUCING FP COMPARE. Its destination is a MASK register -- one BIT per     */     \
	/* element -- not a vector of SEW-wide lanes, so unlike every lane op above it produces no  */     \
	/* V512 value at all: it deposits its bits straight into the destination mask register in   */     \
	/* CPUState, blending with the old byte so masked-off and tail bits stay undisturbed (which */     \
	/* is what the reference helper leaves behind). SIDEEFF for vstatechunkstore's reason and no */     \
	/* weaker: it writes CPUState, and the window may overlap a guest global's slot.            */     \
	BASE(vchunkfcmpstate, InstVChunkFCmpState, Flags::SIDEEFF)                                         \
	/* P10. THE WIDENING CONVERT, and the ONLY new node the widening FP family needs. f32 -> f64 */     \
	/* is exact, so the family's definition -- widen both operands, then do ONE operation at the */     \
	/* wide width -- is reproduced by this convert followed by the EXISTING vchunkfalu at SEW 8. */     \
	/* Its input is half as wide as its output, which is why it cannot be a vchunkfalu row.      */     \
	/* Flags 0: pure register-to-register, exactly as the other lane ops.                        */     \
	BASE(vchunkfwidencvt, InstVChunkFWidenCvt, 0)                                                      \
	/* P7L-B1. THE DEPENDENCY PROBE. A VALUE-PRESERVING copy that additionally READS a second   */     \
	/* chunk, so the emitted code carries a RAW edge the value does not need. It exists only to */     \
	/* let a timing arm ask whether two sibling chunk chains were overlapping; it is an         */     \
	/* experiment instrument, never a lowering. Flags are `0` for exactly vchunkfalu's reason:  */     \
	/* pure register-to-register, no memory, no guest global. See qir.h InstVChunkDep.          */     \
	BASE(vchunkdep, InstVChunkDep, 0)                                                                  \
	/* A3: partial-vl arm. maskset reads vec.vl and writes host opmask k(1+chunk); merge selects   */     \
	/* per lane between the old vd chunk and the computed chunk; partial marks the second arm.    */     \
	BASE(vchunkmaskset, InstVChunkMaskSet, Flags::SIDEEFF)                                             \
	/* S1-1: the ACTIVE-VL BOUND. Reads the live vec.vl and leaves the FP body early when this   */     \
	/* chunk starts at or above it. SIDEEFF for vchunkmaskset's reason -- it reads CPUState --   */     \
	/* and additionally because it is control flow the scheduler must not move. See qir.h.       */     \
	BASE(vchunkactive, InstVChunkActive, Flags::SIDEEFF)                                               \
	BASE(vchunkpartialalu, InstVChunkPartialAlu, Flags::SIDEEFF)                                       \
	BASE(vmasklogic, InstVMaskLogic, Flags::SIDEEFF)                                                 \
	BASE(vmaskscalar, InstVMaskScalar, Flags::SIDEEFF)                                               \
	BASE(vmaskiota, InstVMaskIota, Flags::SIDEEFF)                                               \
	BASE(vscalarmove, InstVScalarMove, Flags::SIDEEFF)                                           \
	BASE(vcompressnative, InstVCompress, Flags::SIDEEFF)                                        \
	BASE(vreducenative, InstVReduce, Flags::SIDEEFF)                                            \
	BASE(vgathernative, InstVGather, Flags::SIDEEFF)                                            \
	BASE(vfestimate, InstVFEstimate, Flags::SIDEEFF)                                            \
	BASE(vmemorynative, InstVMemory, Flags::SIDEEFF)                                            \
	BASE(vwholemove, InstVWholeMove, Flags::SIDEEFF)                                            \
	BASE(vfreducenative, InstVFReduce, Flags::SIDEEFF)                                          \
	BASE(vchunkindex, InstVChunkIndex, Flags::SIDEEFF)                                               \
	BASE(vchunkfclass, InstVChunkFClass, Flags::SIDEEFF)                                             \
	BASE(vchunkfestimate, InstVChunkFEstimate, Flags::SIDEEFF)                                       \
	BASE(vchunkfmerge, InstVChunkFMerge, Flags::SIDEEFF)                                             \
	/* Order item 4: the SATURATING integer add/sub family. SIDEEFF, unlike vchunkadd's `0`,   */      \
	/* and the difference is the whole of what makes it a separate node: saturation sets       */      \
	/* `vec.vxsat`, a STICKY architectural flag, so this lane operation is not pure.           */      \
	BASE(vchunksatadd, InstVChunkSatAdd, Flags::SIDEEFF)                                             \
	/* Order item 4: the carry/borrow family. Flags are `0`, unlike vchunksatadd's SIDEEFF:    */      \
	/* `vadc`/`vsbc` raise nothing and set no sticky flag -- they read v0 as a DATA operand    */      \
	/* and write vd, which is an ordinary pure lane computation.                              */      \
	BASE(vchunkadc, InstVChunkAdc, 0)                                                                \
	/* Order item 4: the fixed-point AVERAGING family. Flags are `0` like vchunkadc's:         */      \
	/* `vaadd`/`vasub` set no sticky flag. They READ `vec.vxrm`, but a read is not a side      */      \
	/* effect -- the emitter loads it at the point of use, so a frame that somehow contained   */      \
	/* a write to it would still order correctly against this node's load.                     */      \
	BASE(vchunkavg, InstVChunkAvg, 0)                                                                \
	/* Order item 4: the FRACTIONAL MULTIPLY. SIDEEFF like vchunksatadd and for the same       */      \
	/* reason: its one overflow case (MIN*MIN) sets the sticky `vec.vxsat`, so a pure node     */      \
	/* would let the optimiser drop a dead vsmul and lose the flag with it.                    */      \
	BASE(vchunkfracmul, InstVChunkFracMul, Flags::SIDEEFF)                                           \
	/* Order item 4: the NARROWING CLIP. SIDEEFF for `vec.vxsat`, like vchunkfracmul, and     */      \
	/* additionally because -- like its sibling vchunknarrowshift -- it is an offset-carrying */      \
	/* node that loads and stores CPUState itself rather than taking SSA operands.            */      \
	BASE(vchunknarrowclip, InstVChunkNarrowClip, Flags::SIDEEFF)                                     \
	BASE(vchunkitof, InstVChunkIToF, Flags::SIDEEFF)                                                 \
	BASE(vchunkftoi, InstVChunkFToI, Flags::SIDEEFF)                                                 \
	BASE(vchunkftof, InstVChunkFToF, Flags::SIDEEFF)                                                 \
	BASE(vmaskprefix, InstVMaskPrefix, Flags::SIDEEFF)                                               \
	BASE(vchunkextend, InstVChunkExtend, Flags::SIDEEFF)                                             \
	BASE(vchunkwiden, InstVChunkWiden, Flags::SIDEEFF)                                               \
	BASE(vchunknarrowshift, InstVChunkNarrowShift, Flags::SIDEEFF)                                   \
	BASE(rvvtypedchunkpartial, InstRVVTypedChunkPartial, Flags::SIDEEFF)                               \
	/* Non-trapping scalar integer maintenance kept in guest order inside a vector SSA run. */       \
	BASE(rvvrunscalar, InstRVVRunScalar, Flags::SIDEEFF)                                             \
	BASE(rvvqcgfpbegin, InstRVVQCGFPBegin, Flags::SIDEEFF)                                              \
	BASE(rvvqcgfpend, InstRVVQCGFPEnd, Flags::SIDEEFF)                                                  \
	/* Guard/fallback frame around a TYPED V512 body (see qir.h). HAS_CALLS sits on `begin`    */      \
	/* for the same reason it does on rvvdiagchunkbegin -- the call boundary must be placed    */      \
	/* before the guard, because the guard-taken path is the one that calls the helper -- and  */      \
	/* additionally because it is what leaves nothing dirty for the typed ops to sync inside   */      \
	/* the branched-over window.                                                               */      \
	BASE(rvvtypedchunkbegin, InstRVVTypedChunkBegin, Flags::SIDEEFF | Flags::HAS_CALLS)                  \
	BASE(rvvtypedchunkend, InstRVVTypedChunkEnd, Flags::SIDEEFF)                                         \
	/* S2.9, widened by Native-1. Routed from exact `vsetvli rd, rs1, e32, m1, ta, ma` at      */      \
	/* VLEN 512/1024 in every register combination except rd == x0 && rs1 == x0, the reserved  */      \
	/* keep-vl form (see qir.h InstRVVSetVL). rs1 == x0 supplies AVL = ~0u. It computes        */      \
	/* vl = min(AVL, VLMAX) UNSIGNED over the whole u32 AVL domain and then writes the guest   */      \
	/* rd plus CPUState.vec.{vtype,vl,vstart,vlenb}. Every other vsetvli/vsetivli/vsetvl form  */      \
	/* keeps the unchanged rv32_vsetvli / rv32_vsetvl helper.                                  */      \
	/* SIDEEFF because it writes memory whose effect is invisible in its def-use edges -- the  */      \
	/* same reason vstatechunkstore carries it. Deliberately NOT HAS_CALLS: it makes no call,  */      \
	/* and that absence is the whole difference from the hcall boundary it replaces. The       */      \
	/* consequence is stated rather than discovered -- QRegAlloc::AllocOp's side-effect loop   */      \
	/* syncs dirty globals at this node, which is strictly cheaper than CallOp, which would    */      \
	/* additionally spill every call-clobbered register.                                       */      \
	BASE(rvvsetvl, InstRVVSetVL, Flags::SIDEEFF)                                                         \
	BASE(rvvsetvlreg, InstRVVSetVLReg, Flags::SIDEEFF)                                                   \
	BASE(rvvread, InstRVVRead, 0)                                                                        \
	BASE(rvvwrite, InstRVVWrite, Flags::SIDEEFF)                                                         \
	BASE(rvvsplatf, InstRVVSplatF, 0)                                                                    \
	BASE(rvvload, InstRVVLoad, Flags::SIDEEFF | Flags::HAS_CALLS)                                        \
	BASE(rvvstore, InstRVVStore, Flags::SIDEEFF | Flags::HAS_CALLS)                                      \
	BASE(rvvfcmp, InstRVVFCmp, Flags::SIDEEFF | Flags::HAS_CALLS)                                        \
	BASE(rvvmerge, InstRVVMerge, Flags::SIDEEFF | Flags::HAS_CALLS)                                      \
	BASE(rvvfalu, InstRVVFALU, Flags::SIDEEFF | Flags::HAS_CALLS)                                        \
	BASE(rvvfma, InstRVVFMA, Flags::SIDEEFF | Flags::HAS_CALLS)                                          \
	BASE(rvvfpbegin, InstRVVFPBegin, Flags::SIDEEFF)                                                      \
	BASE(rvvfpend, InstRVVFPEnd, Flags::SIDEEFF)                                                          \
	BASE(setcc, InstSetcc, 0)                                                                            \
	/* unary */                                                                                          \
	LEAF(mov, InstUnop, 0)                                                                               \
	CLASS(InstUnop, mov, mov)                                                                            \
	/* binary */                                                                                         \
	LEAF(add, InstBinop, 0)                                                                              \
	LEAF(sub, InstBinop, 0)                                                                              \
	LEAF(and, InstBinop, 0)                                                                              \
	LEAF(or, InstBinop, 0)                                                                               \
	LEAF(xor, InstBinop, 0)                                                                              \
	LEAF(sra, InstBinop, 0)                                                                              \
	LEAF(srl, InstBinop, 0)                                                                              \
	LEAF(sll, InstBinop, 0)                                                                              \
	LEAF(mul, InstBinop, 0)                                                                              \
	LEAF(mulh, InstBinop, 0)                                                                             \
	LEAF(mulhsu, InstBinop, 0)                                                                           \
	LEAF(mulhu, InstBinop, 0)                                                                            \
	LEAF(div, InstBinop, 0)                                                                              \
	LEAF(divu, InstBinop, 0)                                                                             \
	LEAF(rem, InstBinop, 0)                                                                              \
	LEAF(remu, InstBinop, 0)                                                                             \
	CLASS(InstBinop, add, remu)																			 

#define QIR_OPS_LIST(OP) QIR_DEF_LIST(OP, OP, EMPTY_MACRO)
#define QIR_LEAF_OPS_LIST(LEAF) QIR_DEF_LIST(LEAF, EMPTY_MACRO, EMPTY_MACRO)
#define QIR_BASE_OPS_LIST(BASE) QIR_DEF_LIST(EMPTY_MACRO, BASE, EMPTY_MACRO)
#define QIR_CLASS_LIST(CLASS) QIR_DEF_LIST(EMPTY_MACRO, QIR_DEF_APPLY_CLASS2BASE, CLASS)
