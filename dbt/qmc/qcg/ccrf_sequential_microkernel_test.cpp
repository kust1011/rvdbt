// T7m focused executable differential for the production CCRF chunk operation.  The frozen
// microkernel is three real RVV words (whole load, vmul.vx, whole store).  Its ordinary side uses
// rvdbt's architectural RVV substrate; its materialized side enters real qcg-generated executable
// code twice, once for each certificate-shaped 64-byte sibling.  No expected result bytes appear.
#include "dbt/arena.h"
#include "dbt/ccrf_materializer.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector_lower.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_builder.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <sys/mman.h>

using namespace dbt;
using namespace dbt::qir;

namespace {
constexpr u32 kLoad = 0x02856407u;  // vl1re32.v v8,(a0)
constexpr u32 kMul = 0x9685e457u;   // vmul.vx v8,v8,a1
constexpr u32 kStore = 0x02850427u; // vs1r.v v8,(a0)
constexpr u32 kVlen = 1024, kVlenb = 128;

StateReg regs[] = {{(u16)offsetof(CPUState, gpr), VType::I32, "x0"}};
StateInfo state_info{regs, 1};

struct Runtime final : CompilerRuntime {
	~Runtime() { if (mem) munmap(mem, size); }
	void *AllocateCode(size_t n, uint) override {
		size = (n + 64 + 4095) & ~size_t(4095);
		mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mem == MAP_FAILED) Panic("ccrf microkernel mmap");
		return mem;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	void *mem{}; size_t size{};
};

extern "C" __attribute__((noinline, naked)) void Enter(void *, void *, void *);
extern "C" __attribute__((noinline, naked)) void Enter(void *, void *, void *) {
	asm("pushq %rbp\n\tpushq %rbx\n\tpushq %r12\n\tpushq %r13\n\tpushq %r14\n\tpushq %r15\n\t"
	    "movq %rdi,%r13\n\tmovq %rsi,%rbp\n\t");
	asm("sub $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("callq *%rdx\n\t");
	asm("add $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("popq %r15\n\tpopq %r14\n\tpopq %r13\n\tpopq %r12\n\tpopq %rbx\n\tpopq %rbp\n\tretq\n\t");
}
}

int main(int argc, char **argv) {
	bool require_avx512 = false, negative_missing = false;
	char const *code_out = nullptr;
	for (int i = 1; i < argc; ++i) {
		std::string const arg = argv[i];
		if (arg == "--require-avx512") require_avx512 = true;
		else if (arg == "--negative-missing-avx512") negative_missing = true;
		else if (arg == "--code-out" && i + 1 < argc) code_out = argv[++i];
		else { fprintf(stderr, "unknown argument: %s\n", argv[i]); return 2; }
	}
	if (negative_missing) {
		auto selected = ccrf::SelectComponentLowering(false, true);
		if (selected != ccrf::ComponentLowering::Unavailable) {
			fprintf(stderr, "CCRF_AVX512_REQUIRED_NEGATIVE_FAIL\n"); return 1;
		}
		printf("CCRF_AVX512_REQUIRED_NEGATIVE_PASS reason=AVX512_REQUIRED_HOST_FEATURE_MISSING generated=0 executed=0 helpers=0\n");
		return 0;
	}
#if defined(__x86_64__) || defined(__i386__)
	bool const host_avx512f = __builtin_cpu_supports("avx512f");
#else
	bool const host_avx512f = false;
#endif
	auto selected = ccrf::SelectComponentLowering(host_avx512f, require_avx512);
	if (selected == ccrf::ComponentLowering::Unavailable) {
		fprintf(stderr, "CCRF_MICROKERNEL_REJECT reason=AVX512_REQUIRED_HOST_FEATURE_MISSING\n");
		return 2;
	}
	auto const host_width = selected == ccrf::ComponentLowering::AVX512ZMM
		? InstCCRFChunk::HostWidth::AVX512ZMM : InstCCRFChunk::HostWidth::FunctionalXMM;
	config::vlen_bits = kVlen;
	CPUState ordinary(nullptr), generated(nullptr);
	ordinary.vec.vlenb = generated.vec.vlenb = kVlenb;
	ordinary.vec.vl = generated.vec.vl = 32;
	ordinary.vec.vtype = generated.vec.vtype = 0xd0;
	ordinary.gpr[10] = generated.gpr[10] = 0;
	ordinary.gpr[11] = generated.gpr[11] = 0x9e3779b9u;
	alignas(64) u8 ordinary_mem[kVlenb], generated_mem[kVlenb];
	generated.ccrf_read_base = generated_mem;
	for (u32 i = 0; i < kVlenb; ++i) ordinary_mem[i] = generated_mem[i] = (u8)(i * 37u + 11u);

	rv32::rvv_ref::whole_reg_load(ordinary.vec, 8, ordinary_mem, 0, 1, kVlen);
	rv32::rvv_ref::vimul(ordinary.vec, rv32::VF6_VMUL, rv32::VSrc::VX, 8, 8, 11,
		ordinary.gpr[11], true, kVlen, ordinary.vec.vl, 4);
	rv32::rvv_ref::whole_reg_store(ordinary.vec, 8, ordinary_mem, 0, 1, kVlen);

	MemArena arena(1u << 20); Region *region = arena.New<Region>(&arena, &state_info);
	Builder b(region->CreateBlock());
	for (u8 component = 0; component != 2; ++component) {
		b.Create_ccrfchunk(kLoad, InstCCRFChunk::Kind::WholeLoad, component, kVlenb, host_width);
		b.Create_ccrfchunk(kMul, InstCCRFChunk::Kind::MulVX, component, kVlenb, host_width);
		b.Create_ccrfchunk(kStore, InstCCRFChunk::Kind::WholeStore, component, kVlenb, host_width);
		printf("QIR_CCRF raw_load=0x%08x raw_mul=0x%08x raw_store=0x%08x component=chunk_%u host_width=%s\n",
		       kLoad, kMul, kStore, component,
		       host_width == InstCCRFChunk::HostWidth::AVX512ZMM ? "zmm512" : "xmm128_fallback");
	}
	qcg::ArchTraits::init(); Runtime runtime;
	auto code = qcg::GenerateCode(&runtime, nullptr, region, 0);
	if (code.empty()) return 2;
	// ccrfchunk is conservatively call-classified, so QCG's normal non-leaf frame pushes rcx.
	// A hand-built region has no guest exit to destroy that frame; supply the exact epilogue here.
	code.data()[code.size()] = 0x59;     // pop rcx
	code.data()[code.size() + 1] = 0xc3; // ret
	Enter(&generated, generated_mem, code.data());
	if (code_out) {
		std::ofstream out(code_out, std::ios::binary | std::ios::trunc);
		out.write(reinterpret_cast<char const *>(code.data()), (std::streamsize)code.size());
		if (!out) { fprintf(stderr, "CCRF_CODE_WRITE_FAIL\n"); return 2; }
	}
	if (memcmp(ordinary_mem, generated_mem, kVlenb) ||
	    memcmp(ordinary.vec.vreg[8].data(), generated.vec.vreg[8].data(), kVlenb)) {
		fprintf(stderr, "CCRF_MICROKERNEL_DIFFERENTIAL_FAIL\n"); return 1;
	}
	printf("CCRF_MICROKERNEL_DIFFERENTIAL_PASS components=2 generated_bytes=%zu lowering=%s helpers=0\n",
	       code.size(), host_width == InstCCRFChunk::HostWidth::AVX512ZMM ? "AVX512_ZMM" :
	       "FUNCTIONAL_XMM_FALLBACK_NONPERFORMANCE");
	return 0;
}
