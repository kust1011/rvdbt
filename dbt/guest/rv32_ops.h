#pragma once

#define RV32_OPCODE_LIST()                                                                                   \
	OP(ill, Base, Flags::Trap)                                                                           \
	/**** RV32I ****/                                                                                    \
	OP(lui, U, 0)                                                                                        \
	OP(auipc, U, 0)                                                                                      \
	OP(jal, J, Flags::Branch)                                                                            \
	OP(jalr, I, Flags::Branch)                                                                           \
	OP(beq, B, Flags::Branch)                                                                            \
	OP(bne, B, Flags::Branch)                                                                            \
	OP(blt, B, Flags::Branch)                                                                            \
	OP(bge, B, Flags::Branch)                                                                            \
	OP(bltu, B, Flags::Branch)                                                                           \
	OP(bgeu, B, Flags::Branch)                                                                           \
	OP(lb, I, Flags::MayTrap)                                                                            \
	OP(lh, I, Flags::MayTrap)                                                                            \
	OP(lw, I, Flags::MayTrap)                                                                            \
	OP(lbu, I, Flags::MayTrap)                                                                           \
	OP(lhu, I, Flags::MayTrap)                                                                           \
	OP(sb, S, Flags::MayTrap)                                                                            \
	OP(sh, S, Flags::MayTrap)                                                                            \
	OP(sw, S, Flags::MayTrap)                                                                            \
	OP(addi, I, 0)                                                                                       \
	OP(slti, I, 0)                                                                                       \
	OP(sltiu, I, 0)                                                                                      \
	OP(xori, I, 0)                                                                                       \
	OP(ori, I, 0)                                                                                        \
	OP(andi, I, 0)                                                                                       \
	OP(slli, IS, 0)                                                                                      \
	OP(srai, IS, 0)                                                                                      \
	OP(srli, IS, 0)                                                                                      \
	OP(sub, R, 0)                                                                                        \
	OP(add, R, 0)                                                                                        \
	OP(sll, R, 0)                                                                                        \
	OP(slt, R, 0)                                                                                        \
	OP(sltu, R, 0)                                                                                       \
	OP(xor, R, 0)                                                                                        \
	OP(sra, R, 0)                                                                                        \
	OP(srl, R, 0)                                                                                        \
	OP(or, R, 0)                                                                                         \
	OP(and, R, 0)                                                                                        \
	OP(fence, Base, 0)                                                                                   \
	OP(fencei, Base, 0)                                                                                  \
	OP(ecall, Base, Flags::Trap)                                                                         \
	OP(ebreak, Base, Flags::Trap)                                                                        \
	/**** RV32A ****/                                                                                    \
	OP(lrw, A, 0)                                                                                        \
	OP(scw, A, 0)                                                                                        \
	OP(amoswapw, A, 0)                                                                                   \
	OP(amoaddw, A, 0)                                                                                    \
	OP(amoxorw, A, 0)                                                                                    \
	OP(amoandw, A, 0)                                                                                    \
	OP(amoorw, A, 0)                                                                                     \
	OP(amominw, A, 0)                                                                                    \
	OP(amomaxw, A, 0)                                                                                    \
	OP(amominuw, A, 0)                                                                                   \
	OP(amomaxuw, A, 0)                                                                                   \
	/**** RV32M ****/                                                                                    \
	OP(mul, R, 0)                                                                                        \
	OP(mulh, R, 0)                                                                                       \
	OP(mulhsu, R, 0)                                                                                     \
	OP(mulhu, R, 0)                                                                                      \
	OP(div, R, 0)                                                                                        \
	OP(divu, R, 0)                                                                                       \
	OP(rem, R, 0)                                                                                        \
	OP(remu, R, 0)                                                                                       \
	/*** RV32Zicsr ***/                                                                                  \
	OP(csrrw, Zicsr, 0)                                                                                   \
	OP(csrrs, Zicsr, 0)                                                                                   \
	OP(csrrc, Zicsr, 0)                                                                                   \
	OP(csrrwi, Zicsr, 0)                                                                                  \
	OP(csrrsi, Zicsr, 0)                                                                                  \
	OP(csrrci, Zicsr, 0)                                                                                   \
	/**** RV32F / RV32D. `fpop` is the whole OP-FP major opcode keyed by funct7 (arith, sqrt,   \
	 **** sign-inject, min/max, compare, classify, convert, move); the four FMA major opcodes  \
	 **** stay separate because they ARE separate opcodes. ****/                                        \
	OP(flw, I, Flags::MayTrap)                                                                            \
	OP(fld, I, Flags::MayTrap)                                                                            \
	OP(fsw, S, Flags::MayTrap)                                                                            \
	OP(fsd, S, Flags::MayTrap)                                                                            \
	OP(fpop, R, Flags::MayTrap)                                                                           \
	OP(fmadd, R, Flags::MayTrap)                                                                          \
	OP(fmsub, R, Flags::MayTrap)                                                                          \
	OP(fnmsub, R, Flags::MayTrap)                                                                         \
	OP(fnmadd, R, Flags::MayTrap)                                                                         \
	OP(mret, Base, 0)                                                                                     \
	/**** RVV 1.0 -- compiler-observed strip-mined integer subset (see DESIGN.md).           \
	 **** Every other RVV encoding stays unmapped and therefore decodes to `ill` (fail closed). \
	 **** ALL FOUR are MayTrap: each one can raise ILLEGAL_INSN on a reserved vtype, an        \
	 **** out-of-range EMUL or an illegal register group, and MayTrap is what makes the JIT     \
	 **** spill the guest ip before the helper call -- without it the trap reports a stale PC. ****/     \
	OP(vsetvli, V, Flags::HasRd | Flags::MayTrap)                                                         \
	OP(vsetvl, V, Flags::MayTrap)                                                                         \
	/**** Unit-stride memory at ANY EEW: the width field selects it, independently of SEW. ****/         \
	OP(vle, V, Flags::MayTrap)                                                                            \
	OP(vse, V, Flags::MayTrap)                                                                            \
	/**** Strided memory: byte stride from a scalar register, any EEW. ****/                             \
	OP(vlse, V, Flags::MayTrap)                                                                           \
	OP(vleff, V, Flags::MayTrap)                                                                          \
	OP(vsse, V, Flags::MayTrap)                                                                           \
	OP(vlxei, V, Flags::MayTrap)                                                                     \
	OP(vsxei, V, Flags::MayTrap)                                                                     \
	OP(vlseg, V, Flags::MayTrap)                                                                     \
	OP(vsseg, V, Flags::MayTrap)                                                                     \
	OP(vadd_vv, V, Flags::MayTrap)                                                                        \
	/**** Exact unmasked vmul.vv, split out of the `vimul` family below for the same reason    \
	 **** vadd.vv is split out of `vialu`: it is the encoding with a direct typed-QCG chunk    \
	 **** lowering (P3.5a). Semantics are unchanged and still come from the family's own       \
	 **** rvv_fast::try_imul / rvv_ref::vimul pair, and every OTHER vimul encoding -- masked   \
	 **** vmul.vv, vmul.vx, and the whole mulh/div/rem/macc set -- still reaches `vimul`. ****/         \
	OP(vmul_vv, V, Flags::MayTrap)                                                                        \
	/**** Exact unmasked vsub.vv, split out of the `vialu` family below for exactly the reason \
	 **** vadd.vv is: it is the encoding with a direct typed-QCG chunk lowering (S2.1).        \
	 **** Semantics are unchanged and still come from the family's own rvv_fast::try_ialu /    \
	 **** rvv_ref::vialu pair, and every OTHER vialu encoding -- masked vsub.vv, vsub.vx, and  \
	 **** the whole min/max/and/or/xor/shift set at any vm -- still reaches `vialu`. ****/               \
	OP(vsub_vv, V, Flags::MayTrap)                                                                        \
	/**** Exact unmasked vxor.vv, split out of the `vialu` family below for exactly the reason \
	 **** vsub.vv is: it is the encoding with a direct typed-QCG chunk lowering (S2.2).        \
	 **** Semantics are unchanged and still come from the family's own rvv_fast::try_ialu /    \
	 **** rvv_ref::vialu pair. Masked vxor.vv and vxor.vx/vi deliberately KEEP reaching        \
	 **** `vialu`, as does its remaining bitwise sibling vand.vv (funct6 001001). ****/                 \
	OP(vxor_vv, V, Flags::MayTrap)                                                                        \
	/**** Exact unmasked vor.vv, split out of the `vialu` family below for exactly the reason \
	 **** vxor.vv is: it is the encoding with a direct typed-QCG chunk lowering (S2.3).       \
	 **** Semantics are unchanged and still come from the family's own rvv_fast::try_ialu /   \
	 **** rvv_ref::vialu pair. This is the SECOND of the three adjacent bitwise funct6 values \
	 **** to leave the family, so the remaining one -- vand.vv (001001) -- was the whole of   \
	 **** the non-capture control until S2.4 split it too, and masked vor.vv plus vor.vx/vi   \
	 **** still reach `vialu`. ****/                                                                    \
	OP(vor_vv, V, Flags::MayTrap)                                                                         \
	/**** Exact unmasked vand.vv, split out of the `vialu` family below for exactly the reason \
	 **** vor.vv is: it is the encoding with a direct typed-QCG chunk lowering (S2.4).        \
	 **** Semantics are unchanged and still come from the family's own rvv_fast::try_ialu /   \
	 **** rvv_ref::vialu pair. This is the THIRD and LAST of the three adjacent bitwise       \
	 **** funct6 values to leave the family, so there is no unrouted bitwise sibling left to  \
	 **** control against; masked vand.vv plus vand.vx/vi still reach `vialu`, and so do the  \
	 **** family's remaining members (vrsub, vmin/vmax, the shifts). ****/                              \
	OP(vand_vv, V, Flags::MayTrap)                                                                        \
	/**** P7N-B. Exact UNMASKED vsll.vi and vsrl.vi, split out of the `vialu` family for       \
	 **** exactly the reason vand.vv is: they are the encodings with a direct typed-QCG chunk \
	 **** lowering. Semantics are unchanged and still come from the family's own              \
	 **** rvv_fast::try_ialu / rvv_ref::vialu pair -- H_vsll_vi and H_vsrl_vi forward the     \
	 **** same instruction word to the same Impl_vialu body, so funct6 is still read from the \
	 **** word (and is VF6_VSLL / VF6_VSRL by decode).                                        \
	 ****                                                                                     \
	 **** THESE ARE THE FIRST OPIVI SPLITS. Every earlier split took a `.vv` encoding whose   \
	 **** rs1 field names a VECTOR register; here the rs1 field is a 5-bit UNSIGNED IMMEDIATE \
	 **** shift amount. That is an RVV 1.0 encoding property of the OPIVI group, not a        \
	 **** property of these two opcodes, and it is what the run's `opivi_imm_src1` proof bit  \
	 **** and the route's one-source chunk body exist for.                                    \
	 ****                                                                                     \
	 **** EVERY other encoding this could match still reaches `vialu`: masked vsll.vi/vsrl.vi \
	 **** (vm=0), the .vv and .vx forms of both shifts, and the whole arithmetic-shift family \
	 **** (vsra at any src). vsra is deliberately NOT split: it is an ARITHMETIC shift and    \
	 **** would need vpsrad, a different host instruction, so admitting it here would be a    \
	 **** second lowering hiding behind one predicate. ****/                                            \
	OP(vsll_vi, V, Flags::MayTrap)                                                                        \
	OP(vsrl_vi, V, Flags::MayTrap)                                                                        \
	/**** A6. Exact UNMASKED vadd.vx (OPIVX) and vadd.vi (OPIVI), split out of `vialu` for      \
	 **** exactly the reason vadd.vv is: they are the encodings with a direct typed-QCG chunk   \
	 **** lowering. H_vadd_vx / H_vadd_vi forward the same word to the same Impl_vialu body,   \
	 **** so funct6/funct3 are still read from the word. Masked forms and every other OPIVX/   \
	 **** OPIVI vialu encoding still reach `vialu`. ****/                                                \
	OP(vadd_vx, V, Flags::MayTrap)                                                                        \
	OP(vadd_vi, V, Flags::MayTrap)                                                                        \
	/**** RVV integer families. Each op covers a whole encoding family keyed by funct6, so ~40 \
	 **** mnemonics share one handler instead of becoming 40 special cases. The DECODER admits \
	 **** only the funct6 values each family implements; everything else still reaches `ill`. ****/     \
	OP(vsetivli, V, Flags::HasRd | Flags::MayTrap)                                                        \
	OP(vialu, V, Flags::MayTrap)                                                                          \
	OP(vicmp, V, Flags::MayTrap)                                                                          \
	OP(vmlogic, V, Flags::MayTrap)                                                                        \
	OP(vmerge, V, Flags::MayTrap)                                                                         \
	OP(vid, V, Flags::MayTrap)                                                                            \
	OP(vext, V, Flags::MayTrap)                                                                        \
	OP(vslide, V, Flags::MayTrap)                                                                      \
	OP(vrgather, V, Flags::MayTrap)                                                                    \
	OP(vsatadd, V, Flags::MayTrap)                                                                     \
	OP(vavg, V, Flags::MayTrap)                                                                        \
	OP(vnshift, V, Flags::MayTrap)                                                                     \
	OP(vadc, V, Flags::MayTrap)                                                                      \
	OP(vsmul, V, Flags::MayTrap)                                                                     \
	OP(vlm, V, Flags::MayTrap)                                                                       \
	OP(vsm, V, Flags::MayTrap)                                                                       \
	OP(vfwarith, V, Flags::MayTrap)                                                                  \
	OP(vfwred, V, Flags::MayTrap)                                                                    \
	OP(vsshift, V, Flags::MayTrap)                                                                   \
	OP(vnclip, V, Flags::MayTrap)                                                                    \
	OP(vwred, V, Flags::MayTrap)                                                                     \
	OP(vmaskpop, V, Flags::MayTrap)                                                                  \
	OP(vmunary, V, Flags::MayTrap)                                                                   \
	OP(vcompress, V, Flags::MayTrap)                                                                 \
	OP(vwint, V, Flags::MayTrap)                                                                          \
	OP(vimul, V, Flags::MayTrap)                                                                          \
	/**** Reductions + the scalar element interface (element 0 used as a scalar slot). ****/             \
	OP(vred, V, Flags::MayTrap)                                                                           \
	/**** Vector floating point: arithmetic/min-max/sign-inject, FMA, compare->mask,          \
	 **** conversions (single/widening/narrowing), reductions, sqrt/classify, merge/move. ****/         \
	OP(vfalu, V, Flags::MayTrap)                                                                          \
	OP(vfma, V, Flags::MayTrap)                                                                           \
	OP(vfcmp, V, Flags::MayTrap)                                                                          \
	OP(vfcvt, V, Flags::MayTrap)                                                                          \
	OP(vfunary1, V, Flags::MayTrap)                                                                       \
	OP(vfred, V, Flags::MayTrap)                                                                          \
	OP(vfmerge, V, Flags::MayTrap)                                                                        \
	OP(vfmvfs, V, Flags::HasRd | Flags::MayTrap)                                                          \
	OP(vfmvsf, V, Flags::MayTrap)                                                                           \
	OP(vmvsx, V, Flags::MayTrap)                                                                          \
	OP(vmvxs, V, Flags::HasRd | Flags::MayTrap)                                                                            \
	/**** Whole-register transfers: vtype-independent by definition (ignore SEW/LMUL/vl/vill). ****/     \
	OP(vmvNr, V, Flags::MayTrap)                                                                          \
	OP(vlNre, V, Flags::MayTrap)                                                                          \
	OP(vsNr, V, Flags::MayTrap)                                                                           \
