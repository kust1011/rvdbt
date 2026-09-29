// M6B. THE FAIL-CLOSED PANICS IN llvmgen ARE UNREACHABLE, PROVEN BEHAVIOURALLY.
//
// M6B gave QIRToLLVM::Emit_ccrfchunk and Emit_ccrfcompute definitions, because without them the
// whole offline LLVM compiler did not LINK (QIR_OPS_LIST declares one Emit_ per op and the Visitor
// dispatches every one). Both definitions are `Panic`. A Panic is only the right answer if no ccrf
// node can ever reach that backend, and that is a claim about the FRONTEND, not about llvmgen.
//
// The two ccrf constructors in dbt/guest/rv32_qir.cpp are:
//     RvvEmitWholeRegChunkGroup   -- reached only when RvvQcgWholeRegAdmit  returned nonzero
//     RvvEmitVxMulAccChunkGroup   -- reached only when RvvQcgVxMulAccShape  returned a shape
// so "no ccrf node on an LLVM compile" reduces to "both predicates return 0 when aot_use_llvm".
// Both predicates are private, so this file does not call them. It proves the same thing through
// the ONLY public entry -- qir::CompilerGenRegionIR, the real translator -- by observing whether
// the route's typed frame appears in the constructed QIR.
//
// WHAT MAKES THIS FALSIFIABLE, which is the whole point.
//
// A test that only asserts "the LLVM arm has no typed frame" would also pass if the route were
// dead for some unrelated reason -- a wrong instruction word, a refused SEW, or (on a host with no
// AVX-512) the feature probe. Each case here therefore comes in a PAIR:
//
//     control  aot_use_llvm = false  ->  the typed frame IS present
//     subject  aot_use_llvm = true   ->  the typed frame is ABSENT and a helper hcall is present
//
// The control is what makes the subject mean something: it proves this exact word, at this exact
// VLEN and SEW, on THIS host, really does reach the route. Deleting `if (config::aot_use_llvm)
// return 0;` from either predicate makes the corresponding subject case produce the frame, and the
// subject assertion fails. That is the required "flip the predicate and the test must fail".
//
// HOST NOTE, and it is why the two routes are handled differently here.
//   * RvvQcgVxMulAccShape has a force-emit twin (config::rvv_qcg_vx_mulacc_force_emit) that
//     bypasses ONLY the __builtin_cpu_supports("avx512f") probe. Its control therefore works on
//     any x86 host, including the AVX-512-less build host.
//   * RvvQcgWholeRegAdmit has NO force-emit twin, by deliberate design (see its comment). On a host
//     without AVX-512F its control CANNOT be established, so this file does not pretend otherwise:
//     it reports WHOLEREG_CONTROL=unavailable and marks that route's pair as NOT PROVEN on this
//     host, instead of printing a green subject assertion that would pass with the predicate
//     deleted. On an AVX-512 host both pairs run.
//
// It never executes emitted bytes, never runs a guest, never times anything.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
int failures = 0, checks = 0;

#define CHECK(cond, ...)                                                                             \
	do {                                                                                         \
		++checks;                                                                            \
		if (!(cond)) {                                                                       \
			++failures;                                                                  \
			printf("  FAIL %s:%d ", __FILE__, __LINE__);                                 \
			printf(__VA_ARGS__);                                                         \
			printf("\n");                                                                \
		}                                                                                    \
	} while (0)

// --- guest words, taken verbatim from the accepted route tests -------------------------------
constexpr u32 INSN_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 INSN_VMUL_VX = 0x961161d7u;	// vmul.vx  v3, v1, sp
constexpr u32 INSN_VL1RE32 = 0x02856407u;	// vl1re32.v v8,(a0)
constexpr u32 INSN_VS1R = 0x02850427u;		// vs1r.v    v8,(a0)

struct Counts {
	unsigned tchunk_begin = 0, tchunk_end = 0, ccrf_chunk = 0, ccrf_compute = 0, hcall = 0;
};

Counts Tally(Region *region)
{
	Counts c;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin: ++c.tchunk_begin; break;
			case Op::_rvvtypedchunkend: ++c.tchunk_end; break;
			case Op::_ccrfchunk: ++c.ccrf_chunk; break;
			case Op::_ccrfcompute: ++c.ccrf_compute; break;
			case Op::_hcall: ++c.hcall; break;
			default: break;
			}
		}
	}
	return c;
}

// Reset every switch this file touches, so no case inherits another's configuration.
void ResetConfig()
{
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::rvv_vector_run = false;
	config::rvv_vector_ssa = false;
	config::aot_use_llvm = false;
	config::rvv_qcg_typed_chunk = false;
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_vx_mulacc_force_emit = false;
}

Counts TranslateWords(std::vector<u32> const &words, u32 vlen_bits, bool use_llvm,
		      void (*extra)(void))
{
	MemArena arena(1u << 20);
	ResetConfig();
	config::vlen_bits = vlen_bits;
	extra();
	config::aot_use_llvm = use_llvm;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(4u * words.size())}};
	CompilerJob job(nullptr, (uptr)words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	return Tally(CompilerGenRegionIR(&arena, job));
}

bool HostHasAvx512f()
{
#if defined(__x86_64__) || defined(__i386__)
	return __builtin_cpu_supports("avx512f");
#else
	return false;
#endif
}

// --- [1] vx-mulacc: control and subject, on every host ---------------------------------------
void TestVxMulAcc(u32 vlen)
{
	auto arm = [](void) {
		config::rvv_qcg_vx_mulacc = true;
		config::rvv_qcg_vx_mulacc_force_emit = true; // bypasses ONLY the AVX-512 probe
	};
	std::vector<u32> words = {INSN_VSETVLI_E32M1, INSN_VMUL_VX};

	Counts ctl = TranslateWords(words, vlen, /*use_llvm=*/false, arm);
	CHECK(ctl.tchunk_begin == 1 && ctl.tchunk_end == 1,
	      "vlen=%u CONTROL (aot_use_llvm=0) did not take the vx-mulacc route: begin=%u end=%u. "
	      "Without a control the subject below proves nothing.",
	      vlen, ctl.tchunk_begin, ctl.tchunk_end);
	CHECK(ctl.ccrf_chunk == 0 && ctl.ccrf_compute == 0,
	      "vlen=%u CONTROL built a ccrf node without CCRF scope configured (chunk=%u compute=%u)",
	      vlen, ctl.ccrf_chunk, ctl.ccrf_compute);

	Counts sub = TranslateWords(words, vlen, /*use_llvm=*/true, arm);
	CHECK(sub.tchunk_begin == 0 && sub.tchunk_end == 0,
	      "vlen=%u SUBJECT (aot_use_llvm=1) TOOK the QCG vx-mulacc route: begin=%u end=%u. "
	      "RvvQcgVxMulAccShape's `if (config::aot_use_llvm) return none;` is not refusing.",
	      vlen, sub.tchunk_begin, sub.tchunk_end);
	CHECK(sub.ccrf_chunk == 0 && sub.ccrf_compute == 0,
	      "vlen=%u SUBJECT built a ccrf node -- it would reach QIRToLLVM's Panic (chunk=%u compute=%u)",
	      vlen, sub.ccrf_chunk, sub.ccrf_compute);
	CHECK(sub.hcall >= 1, "vlen=%u SUBJECT kept no helper: hcall=%u", vlen, sub.hcall);
	printf("  ok  vx-mulacc vlen=%u: control frame=1, llvm frame=0 ccrf=0 helper=%u\n", vlen,
	       sub.hcall);
}

// --- [2] whole-register: control needs a real AVX-512 host ------------------------------------
void TestWholeReg(u32 vlen, bool have_avx512)
{
	auto arm = [](void) { config::rvv_qcg_whole_reg = true; };
	for (u32 word : {INSN_VL1RE32, INSN_VS1R}) {
		std::vector<u32> words = {word};
		Counts sub = TranslateWords(words, vlen, /*use_llvm=*/true, arm);
		CHECK(sub.ccrf_chunk == 0 && sub.ccrf_compute == 0,
		      "vlen=%u word=%08x SUBJECT built a ccrf node (chunk=%u compute=%u)", vlen, word,
		      sub.ccrf_chunk, sub.ccrf_compute);

		if (!have_avx512) {
			// State it rather than print a green line the predicate deletion would survive.
			printf("  --  whole-reg vlen=%u word=%08x: WHOLEREG_CONTROL=unavailable "
			       "(host has no AVX-512F and this route has no force-emit twin); "
			       "subject checked but NOT PROVEN on this host\n",
			       vlen, word);
			continue;
		}
		Counts ctl = TranslateWords(words, vlen, /*use_llvm=*/false, arm);
		CHECK(ctl.tchunk_begin == 1 && ctl.tchunk_end == 1,
		      "vlen=%u word=%08x CONTROL did not take the whole-reg route: begin=%u end=%u",
		      vlen, word, ctl.tchunk_begin, ctl.tchunk_end);
		CHECK(sub.tchunk_begin == 0 && sub.tchunk_end == 0,
		      "vlen=%u word=%08x SUBJECT (aot_use_llvm=1) TOOK the QCG whole-reg route: "
		      "begin=%u end=%u. RvvQcgWholeRegAdmit's aot_use_llvm refusal is not firing.",
		      vlen, word, sub.tchunk_begin, sub.tchunk_end);
		printf("  ok  whole-reg vlen=%u word=%08x: control frame=1, llvm frame=0 ccrf=0\n",
		       vlen, word);
	}
}

} // namespace

int main()
{
	bool const avx512 = HostHasAvx512f();
	printf("M6B ccrf-llvm-unreachable test  HOST_AVX512F=%s\n", avx512 ? "yes" : "no");
	printf("WHOLEREG_CONTROL=%s\n", avx512 ? "available" : "unavailable");

	printf("[1] vx-mulacc route refuses under aot_use_llvm\n");
	TestVxMulAcc(512);
	TestVxMulAcc(1024);

	printf("[2] whole-register route refuses under aot_use_llvm\n");
	TestWholeReg(512, avx512);
	TestWholeReg(1024, avx512);

	printf("\n%d checks, %d failed\n", checks, failures);
	if (!avx512)
		printf("NOTE: whole-reg pair NOT PROVEN on this host; run on an AVX-512 host for the "
		       "complete result.\n");
	printf("%s\n", failures ? "CCRF_LLVM_UNREACHABLE_FAIL" : "CCRF_LLVM_UNREACHABLE_PASS");
	return failures ? 1 : 0;
}
