Complete Ara vredsum.c, revision34bd3bc152421b4601a7bf3d6e8e91ffb545c99e.
Original source is vredsum.original.c; context_original_vredsum.c adds only function
begin/end observation calls. Original five functions, order, INIT_CHECK,
enable_vec and EXIT_CHECK survive byte-for-byte after removing those calls.

The accepted ara-remainder52/ara82 adapter is reused. vector_macros.h preserves
upstream copyright/SPDX and checker calculations; changes add observation calls,
read CSR into uintptr_t then zero-extend on RV32, and route exit through
ara_finish. Linux-user/PK startup provides enabled FP/vector state, so privileged
mstatus writes in enable_vec are unavailable and the existing non-SPIKE branch
is used. user_runtime supplies write/exit ecalls, scalar memcpy/memset, buffered
printf and observation records. start.S supplies stack/main; link.ld maps RAM.
No masks, operands, expected literals or checker comparison loops are changed.
Compare fetched vector_macros.h against the bundled adapter to inspect every
header delta. Unused header macro adaptations are retained from the accepted
adapter; they do not become new ISA checks.

C and printf compile as rv32g, O0, without compiler vectorization, through LLVM
IR and llc --no-integrated-as; asm_environment.h enables +v for original inline
assembly, then clang assembles as rv32gv. This prevents C-generated RVV from
clobbering fixed guest vector registers and keeps original RVV mnemonics and
scalar typed checker calculations. ilp32d and matching RV32 libgcc preserve
64-bit C arithmetic. printf.c/h retain the complete MIT notice; other copied
headers retain their own notices. Ara LICENSE is included.

Inherited limitation: VLOAD_8 may read VL bytes from shorter source mask/seed
objects. This replay preserves the original objects and does not establish
source-language bounds safety or access suppression. Twenty assertions compare
200 elements at VLEN1024; this is one complete source file, not the Ara suite.
