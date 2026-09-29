// F1 GUARD (2026-09-23): store-masked partial-vl for mixed FP-bracket vector runs.
//
// WHAT IS UNDER TEST. An M1 vector run that mixes FP lane members (vfalu/vfma) with lane-local
// integer members (vmv.v.*, vfmv.v.f, vsll.vi/vsrl.vi, integer .vv) used to be guarded with
// `vl == VLMAX` (VTypeVlVstartFrmRNE), so every partial-vl execution ran the whole frame through
// the ordered helper fallback (LavaMD @ VLEN 2048: 576,000 fallbacks). With
// --rvv-run-fp-store-masked-partial-vl=1 such a frame is guarded `vl <= VLMAX`
// (VTypePartialVlVstartFrmRNE) and every live-out store is masked by the live vl.
//
// THE REFERENCE is the campaign B arm (no runs: each instruction is its own single-instruction
// frame with its own partial-vl arm), plus an INDEPENDENT tail check against the seed state.
// Arms, all from the generated campaign config (rvv_both_boundary_campaign_config.h):
//   B, M1 switch off (= F1 scan-only), M1 switch on, BOTH switch off, BOTH switch on.
//
// CHECKS, each with the defect it catches:
//   [S] structure: mixed multi-member frames carry VTypePartialVlVstartFrmRNE and only masked
//       live-out stores with the switch on, and VTypeVlVstartFrmRNE and only unmasked stores with
//       it off; frames without an integer member and programs without an FP member emit the SAME
//       host bytes in both switch positions (the change cannot leak into other frames).
//   [V] value, dense vl ladder 0..VLMAX+2 and a frm != RNE case: every arm's full vector file,
//       vl/vtype/vstart, GPRs and fcsr equal B's, except that a TAIL lane of a register written
//       by a pure-FP run may be all ones (the F0 tail-agnostic fill, legal at vta = 1).
//   [T] strict: where every multi-member frame of the build is a mixed frame guarded partial,
//       the switch-on arms equal B BYTE FOR BYTE (tail- and mask-undisturbed) -- an unmasked
//       store would leak a shifted/renamed/all-ones tail and fail here.
//   [F] fallbacks: at 0 < vl <= VLMAX and frm == RNE the switch-on arms take no more fallbacks
//       than B; at 0 < vl < VLMAX the switch-off arms take strictly more whenever the build has a
//       mixed frame (so the test observes the old guard, i.e. [F] is falsifiable).

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qcg/rvv_both_boundary_campaign_config.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
long g_checks = 0;
long g_failures = 0;
// Failures by check family ([S] [V] [T] [F], anything else under '?'), so a mutation run can show
// WHICH family caught it -- in particular that a value family catches what the structure family
// also catches.
long g_fail_by[128] = {};

#define CHECK_MSG(cond, ...)                                                                         \
	do {                                                                                         \
		++g_checks;                                                                          \
		if (!(cond)) {                                                                       \
			char msg_[512];                                                              \
			snprintf(msg_, sizeof msg_, __VA_ARGS__);                                    \
			++g_fail_by[(msg_[0] == '[' && (unsigned char)msg_[1] < 128) ? msg_[1] : '?']; \
			if (g_failures < 200)                                                        \
				fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg_);        \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Guest encodings (RVV 1.0). All unmasked (vm = 1).
// ---------------------------------------------------------------------------------------------
constexpr u32 OPIVV = 0, OPFVV = 1, OPIVI = 3, OPIVX = 4, OPFVF = 5;
constexpr u32 OpV(u32 f6, u32 f3, u32 vd, u32 vs2, u32 src1)
{
	return (f6 << 26) | (1u << 25) | (vs2 << 20) | (src1 << 15) | (f3 << 12) | (vd << 7) | 0x57u;
}
constexpr u32 Vsetvli(u32 rd, u32 rs1, u32 vtype)
{
	return (vtype << 20) | (rs1 << 15) | (7u << 12) | (rd << 7) | 0x57u;
}
u32 VfaddVV(u32 vd, u32 vs2, u32 vs1) { return OpV(0b000000, OPFVV, vd, vs2, vs1); }
u32 VfsubVV(u32 vd, u32 vs2, u32 vs1) { return OpV(0b000010, OPFVV, vd, vs2, vs1); }
u32 VfmulVV(u32 vd, u32 vs2, u32 vs1) { return OpV(0b100100, OPFVV, vd, vs2, vs1); }
u32 VfaddVF(u32 vd, u32 vs2, u32 f) { return OpV(0b000000, OPFVF, vd, vs2, f); }
u32 VfmaccVF(u32 vd, u32 f, u32 vs2) { return OpV(0b101100, OPFVF, vd, vs2, f); }
u32 VmvVV(u32 vd, u32 vs1) { return OpV(0b010111, OPIVV, vd, 0, vs1); }
u32 VmvVX(u32 vd, u32 x) { return OpV(0b010111, OPIVX, vd, 0, x); }
u32 VmvVI(u32 vd, u32 imm5) { return OpV(0b010111, OPIVI, vd, 0, imm5 & 31u); }
u32 VfmvVF(u32 vd, u32 f) { return OpV(0b010111, OPFVF, vd, 0, f); }
u32 VsllVI(u32 vd, u32 vs2, u32 sh) { return OpV(0b100101, OPIVI, vd, vs2, sh); }
u32 VsrlVI(u32 vd, u32 vs2, u32 sh) { return OpV(0b101000, OPIVI, vd, vs2, sh); }
u32 VaddVV(u32 vd, u32 vs2, u32 vs1) { return OpV(0b000000, OPIVV, vd, vs2, vs1); }
u32 VxorVV(u32 vd, u32 vs2, u32 vs1) { return OpV(0b001011, OPIVV, vd, vs2, vs1); }

constexpr u32 MakeVType(u32 sew_log2_bytes, u32 lmul_log2, bool ta, bool ma)
{
	return (ma ? 1u << 7 : 0u) | (ta ? 1u << 6 : 0u) | (sew_log2_bytes << 3) | lmul_log2;
}

// Kinds of guest program. `mixed` programs contain an FP member AND a lane-local integer member
// that M1 can put in one run; `fp_only` / `int_only` are the controls the switch must not touch.
enum class Kind { Mixed, FpOnly, IntOnly };
struct Program {
	char const *name;
	Kind kind;
	std::vector<u32> body; // after the vsetvli
	u32 written_mask;      // vector registers the program writes (by base register number)
};

// Register numbers are all even so every program is legal at LMUL 2 as well.
std::vector<Program> Programs()
{
	return {
	    // The LavaMD @ VLEN 2048 frame shapes (LAVAMD_V2048_M1_FALLBACK_AUDIT.md section 1).
	    {"mov,fma", Kind::Mixed, {VmvVV(4, 2), VfmaccVF(4, 1, 6)}, 1u << 4},
	    {"mov,falu,mov,falu,mov,falu,falu",
	     Kind::Mixed,
	     {VmvVX(8, 11), VfaddVV(10, 8, 2), VmvVI(12, 3), VfmulVV(14, 12, 10), VfmvVF(16, 1),
	      VfsubVV(18, 16, 14), VfaddVV(20, 18, 2)},
	     (1u << 8) | (1u << 10) | (1u << 12) | (1u << 14) | (1u << 16) | (1u << 18) | (1u << 20)},
	    {"falu,mov", Kind::Mixed, {VfaddVV(4, 2, 6), VmvVV(8, 4)}, (1u << 4) | (1u << 8)},
	    {"fma,mov", Kind::Mixed, {VfmaccVF(4, 1, 2), VmvVV(6, 4)}, (1u << 4) | (1u << 6)},
	    {"fma,mov,fma,mov,fma",
	     Kind::Mixed,
	     {VfmaccVF(4, 1, 2), VmvVV(6, 4), VfmaccVF(6, 2, 8), VmvVV(10, 6), VfmaccVF(10, 1, 12)},
	     (1u << 4) | (1u << 6) | (1u << 10)},
	    {"sll_vi,fma,falu,fma,falu",
	     Kind::Mixed,
	     {VsllVI(4, 2, 3), VfmaccVF(4, 1, 6), VfaddVV(8, 4, 6), VfmaccVF(8, 2, 4),
	      VfmulVV(10, 8, 4)},
	     (1u << 4) | (1u << 8) | (1u << 10)},
	    // In-place overlap: vd == vs2 for the shifts and the FP ops.
	    {"sll_vi(inplace),falu,srl_vi,falu",
	     Kind::Mixed,
	     {VsllVI(2, 2, 1), VfaddVV(2, 2, 4), VsrlVI(6, 2, 2), VfmulVV(6, 6, 4)},
	     (1u << 2) | (1u << 6)},
	    // Integer .vv members, and an FP member reading an integer member's tail.
	    {"vadd,falu,vxor,falu",
	     Kind::Mixed,
	     {VaddVV(4, 2, 6), VfaddVV(8, 4, 2), VxorVV(10, 8, 2), VfmulVV(12, 10, 8)},
	     (1u << 4) | (1u << 8) | (1u << 10) | (1u << 12)},
	    // An FP op reading a broadcast defined by a move (tail of the broadcast is garbage).
	    {"vfmv,falu.vf,mov", Kind::Mixed, {VfmvVF(4, 2), VfaddVF(6, 4, 1), VmvVV(8, 6)},
	     (1u << 4) | (1u << 6) | (1u << 8)},
	    // Controls.
	    {"fp-only falu,falu,fma", Kind::FpOnly, {VfaddVV(4, 2, 6), VfmulVV(8, 4, 2), VfmaccVF(8, 1, 6)},
	     (1u << 4) | (1u << 8)},
	    {"int-only vadd,sll,mov", Kind::IntOnly, {VaddVV(4, 2, 6), VsllVI(8, 4, 2), VmvVV(10, 8)},
	     (1u << 4) | (1u << 8) | (1u << 10)},
	};
}

// ---------------------------------------------------------------------------------------------
// Harness (the same JIT entry the M1 value test uses).
// ---------------------------------------------------------------------------------------------
struct Runtime final : CompilerRuntime {
	~Runtime()
	{
		if (mem)
			munmap(mem, size);
	}
	void *AllocateCode(size_t n, uint) override
	{
		size = (n + 64 + 4095) & ~size_t(4095);
		mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
			   -1, 0);
		if (mem == MAP_FAILED)
			Panic("fp store-masked test: code mmap failed");
		last = static_cast<u8 *>(mem);
		return mem;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	void *mem{};
	u8 *last{};
	size_t size{};
};

extern "C" __attribute__((noinline, naked)) void FsmEnter(void *, void *, void *);
extern "C" __attribute__((noinline, naked)) void FsmEnter(void *, void *, void *)
{
	asm("pushq %rbp\n\tpushq %rbx\n\tpushq %r12\n\tpushq %r13\n\tpushq %r14\n\tpushq %r15\n\t"
	    "movq %rdi,%r13\n\tmovq %rsi,%rbp\n\t");
	asm("sub $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("callq *%rdx\n\t");
	asm("add $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("popq %r15\n\tpopq %r14\n\tpopq %r13\n\tpopq %r12\n\tpopq %rbx\n\tpopq %rbp\n\tretq\n\t");
}

// M1-on-recompute: the guard switch on, --rvv-run-fp-store-mask-reuse-shared=0 (each masked store
// derives its own vl mask, the first F1-guard commit's emission).
enum Arm { ArmB, ArmM1Off, ArmM1On, ArmM1OnRecompute, ArmBothOff, ArmBothOn, ArmCount };
char const *ArmName(int a)
{
	static char const *n[] = {"B", "M1-off", "M1-on", "M1-on-recompute", "BOTH-off", "BOTH-on"};
	return n[a];
}
bool SwitchOn(int a) { return a == ArmM1On || a == ArmM1OnRecompute || a == ArmBothOn; }
bool ReuseShared(int a) { return a != ArmM1OnRecompute; }
bool g_execute = false;

void ApplyArm(int arm, u32 vlen)
{
	switch (arm) {
	case ArmB: campaign_config::ApplyCampaignArm_B(); break;
	case ArmM1Off:
	case ArmM1On:
	case ArmM1OnRecompute: campaign_config::ApplyCampaignArm_M1(); break;
	default: campaign_config::ApplyCampaignArm_BOTH(); break;
	}
	if (!g_execute)
		campaign_config::ForceEmitAll();
	config::vlen_bits = vlen;
	config::rvv_run_fp_store_masked_partial_vl = SwitchOn(arm);
	config::rvv_run_fp_store_mask_reuse_shared = ReuseShared(arm);
	config::trace = false;
}

using GuardKind = InstRVVTypedChunkBegin::GuardKind;

struct Frame {
	u8 n_members = 0;
	GuardKind guard = GuardKind::VTypeVlVstart;
	bool has_fp = false, has_int = false;
	unsigned stores_masked = 0, stores_unmasked = 0;
	unsigned stores_kmask = 0, stores_bad_kmask = 0; // shared-mask stores; kmask != 1 + chunk
};

struct Built {
	MemArena arena{1u << 22};
	std::vector<u32> words;
	Runtime runtime;
	Region *region{};
	u8 *code{};
	std::vector<u8> bytes;
	std::vector<Frame> frames;
	unsigned mixed_frames = 0, fp_only_multi = 0;
};

bool IsFpRaw(u32 raw)
{
	u32 const f3 = (raw >> 12) & 7u, f6 = raw >> 26;
	// vfmv.v.f (OPFVF, funct6 010111) is a MOVE member, not an FP lane op.
	return (f3 == OPFVV || f3 == OPFVF) && f6 != 0b010111u;
}

void Build(Built &b, std::vector<u32> words)
{
	b.words = std::move(words);
	CompilerJob::IpRangesSet ranges = {{0u, static_cast<u32>(b.words.size() * 4u)}};
	CompilerJob job(nullptr, reinterpret_cast<uptr>(b.words.data()), CodeSegment(0u, 0x1000u),
			std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	Frame *open = nullptr;
	for (auto &bb : b.region->GetBlocks())
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin: {
				auto &bi = static_cast<InstRVVTypedChunkBegin &>(ins);
				b.frames.push_back({.n_members = bi.n_members, .guard = bi.guard_kind});
				open = &b.frames.back();
				break;
			}
			case Op::_vstatechunkstore:
				if (open) {
					auto &st = static_cast<InstVStateChunkStore &>(ins);
					if (st.active_sew)
						++open->stores_masked;
					else
						++open->stores_unmasked;
					if (st.kmask) {
						++open->stores_kmask;
						open->stores_bad_kmask += st.kmask != 1u + st.chunk;
					}
				}
				break;
			case Op::_rvvtypedchunkend: {
				auto &ei = static_cast<InstRVVTypedChunkEnd &>(ins);
				if (open) {
					for (u32 m = 0; m < ei.n_members; ++m) {
						bool const fp = IsFpRaw(ei.members[m].raw);
						open->has_fp |= fp;
						open->has_int |= !fp;
					}
					if (open->n_members > 1 && open->has_fp && open->has_int)
						++b.mixed_frames;
					if (open->n_members > 1 && open->has_fp && !open->has_int)
						++b.fp_only_multi;
				}
				open = nullptr;
				break;
			}
			default: break;
			}
		}
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.runtime, &segment, b.region, 0);
	CHECK_MSG(!span.empty(), "generated region is empty");
	b.code = b.runtime.last;
	b.bytes.assign(span.begin(), span.end());
	size_t n = span.size();
	if (b.code[0] == 0x51)
		b.code[n++] = 0x59;
	b.code[n] = 0xc3;
}

// ---------------------------------------------------------------------------------------------
// State.
// ---------------------------------------------------------------------------------------------
struct Outcome {
	rv32::VectorState vec;
	u32 gpr[32];
	u32 fcsr;
	u64 fallbacks;
};

u32 FloatBits(float f)
{
	u32 x;
	memcpy(&x, &f, 4);
	return x;
}
u64 DoubleBits(double f)
{
	u64 x;
	memcpy(&x, &f, 8);
	return x;
}

// Every lane of every register holds a finite, mostly inexact FP value of the run's SEW, so a
// tail overwrite with any other value is visible and the FP members raise NX.
void Seed(rv32::VectorState &vec, u32 sew_bytes, u32 salt)
{
	for (u32 r = 0; r < 32; ++r)
		for (u32 i = 0; i < rv32::VLEN_MAX_BYTES / sew_bytes; ++i) {
			double const v =
			    (double)((int)((r * 37u + i * 13u + salt * 7u) % 211u) - 105) / 7.0 + 0.001 * r;
			if (sew_bytes == 4) {
				u32 const x = FloatBits((float)v);
				memcpy(vec.vreg[r].data() + 4u * i, &x, 4);
			} else {
				u64 const x = DoubleBits(v);
				memcpy(vec.vreg[r].data() + 8u * i, &x, 8);
			}
		}
}

void Execute(Built &b, rv32::VectorState const &seed, u32 avl, u32 frm, u32 sew_bytes, Outcome &o)
{
	CPUState state(nullptr);
	memset(static_cast<void *>(&state), 0, sizeof state);
	state.vec = seed;
	state.vec.vlenb = static_cast<u16>(config::vlen_bits / 8u);
	state.gpr[10] = avl;
	state.gpr[11] = sew_bytes == 4 ? FloatBits(2.5f) : 0x40000000u;
	if (sew_bytes == 4) {
		state.fpu.f[1] = 0xffffffff00000000ull | FloatBits(1.1f);
		state.fpu.f[2] = 0xffffffff00000000ull | FloatBits(-0.3f);
	} else {
		state.fpu.f[1] = DoubleBits(1.1);
		state.fpu.f[2] = DoubleBits(-0.3);
	}
	state.fpu.set_frm(frm);
	FsmEnter(&state, nullptr, b.code);
	o.vec = state.vec;
	memcpy(o.gpr, state.gpr.data(), sizeof o.gpr);
	o.fcsr = state.fpu.fcsr;
	o.fallbacks = state.rvv_direct_fallbacks;
}

u32 RegGroup(u32 lmul_log2) { return lmul_log2 <= 3 ? (1u << lmul_log2) : 1u; }

// ---------------------------------------------------------------------------------------------
// Totals.
// ---------------------------------------------------------------------------------------------
struct Totals {
	long builds = 0, cases = 0, strict_cases = 0, agnostic_tail_lanes = 0;
	long mixed_frames_on = 0, mixed_frames_off = 0, partial_fallback_cases_off = 0;
	long identical_controls = 0;
} T;

void RunConfig(Program const &p, u32 vlen, u32 vtype)
{
	u32 const sew_log2 = (vtype >> 3) & 7u, lmul_log2 = vtype & 7u;
	u32 const sew_bytes = 1u << sew_log2;
	bool const vta = (vtype >> 6) & 1u;
	u32 const vlmax = (vlen / 8u) * RegGroup(lmul_log2) / sew_bytes;
	std::vector<u32> words{Vsetvli(10, 10, vtype)};
	words.insert(words.end(), p.body.begin(), p.body.end());
	std::string const tag = std::string(p.name) + " vlen" + std::to_string(vlen) + " vtype=0x" +
				[&] { char s[8]; snprintf(s, sizeof s, "%x", vtype); return std::string(s); }();

	Built b[ArmCount];
	for (int a = 0; a < ArmCount; ++a) {
		ApplyArm(a, vlen);
		Build(b[a], words);
		++T.builds;
	}

	if (getenv("FSM_VERBOSE"))
		printf("  cfg %-40s M1 frames=%zu mixed=%u fp_multi=%u\n", tag.c_str(), b[ArmM1On].frames.size(),
		       b[ArmM1On].mixed_frames, b[ArmM1On].fp_only_multi);
	// [S] structure.
	for (int a : {ArmB, ArmM1Off, ArmM1On, ArmM1OnRecompute, ArmBothOff, ArmBothOn})
		for (auto const &f : b[a].frames) {
			// A shared-mask store exists ONLY in a switch-on, reuse-on mixed frame, and always
			// names its own chunk's register.
			bool const may_kmask = SwitchOn(a) && ReuseShared(a) && f.n_members > 1 && f.has_fp &&
					       f.has_int;
			CHECK_MSG(may_kmask || f.stores_kmask == 0,
				  "[S] %s %s: %u shared-mask stores outside a store-masked mixed frame",
				  tag.c_str(), ArmName(a), f.stores_kmask);
			CHECK_MSG(f.stores_bad_kmask == 0, "[S] %s %s: shared-mask store names another chunk",
				  tag.c_str(), ArmName(a));
			if (may_kmask)
				CHECK_MSG(f.stores_kmask == f.stores_masked,
					  "[S] %s %s: %u of %u masked stores reuse the shared mask", tag.c_str(),
					  ArmName(a), f.stores_kmask, f.stores_masked);
		}
	for (int a : {ArmM1Off, ArmM1On, ArmM1OnRecompute, ArmBothOff, ArmBothOn}) {
		for (auto const &f : b[a].frames) {
			if (f.n_members < 2 || !f.has_fp || !f.has_int)
				continue;
			if (SwitchOn(a)) {
				CHECK_MSG(f.guard == GuardKind::VTypePartialVlVstartFrmRNE,
					  "[S] %s %s: mixed frame guard %u, want PartialVlVstartFrmRNE", tag.c_str(),
					  ArmName(a), (unsigned)f.guard);
				CHECK_MSG(f.stores_unmasked == 0 && f.stores_masked > 0,
					  "[S] %s %s: mixed frame stores masked=%u unmasked=%u", tag.c_str(),
					  ArmName(a), f.stores_masked, f.stores_unmasked);
			} else {
				CHECK_MSG(f.guard == GuardKind::VTypeVlVstartFrmRNE,
					  "[S] %s %s: mixed frame guard %u, want VlVstartFrmRNE", tag.c_str(),
					  ArmName(a), (unsigned)f.guard);
				CHECK_MSG(f.stores_masked == 0,
					  "[S] %s %s: switch-off mixed frame has %u masked stores", tag.c_str(),
					  ArmName(a), f.stores_masked);
			}
		}
	}
	T.mixed_frames_on += b[ArmM1On].mixed_frames;
	T.mixed_frames_off += b[ArmM1Off].mixed_frames;
	CHECK_MSG(b[ArmM1On].mixed_frames == b[ArmM1Off].mixed_frames &&
			  b[ArmM1On].frames.size() == b[ArmM1Off].frames.size(),
		  "[S] %s: run formation differs between switch positions", tag.c_str());
	CHECK_MSG(b[ArmB].mixed_frames == 0 && b[ArmB].fp_only_multi == 0,
		  "[S] %s: B arm formed a multi-member frame", tag.c_str());
	if (b[ArmM1On].mixed_frames == 0) {
		// No mixed frame: the switch must be byte-inert.
		CHECK_MSG(b[ArmM1On].bytes == b[ArmM1Off].bytes &&
				  b[ArmM1OnRecompute].bytes == b[ArmM1Off].bytes,
			  "[S] %s: M1 host bytes differ without a mixed frame", tag.c_str());
		CHECK_MSG(b[ArmBothOn].bytes == b[ArmBothOff].bytes,
			  "[S] %s: BOTH host bytes differ without a mixed frame", tag.c_str());
		T.identical_controls += 2;
	}
	if (p.kind != Kind::Mixed)
		CHECK_MSG(b[ArmM1On].mixed_frames == 0, "[S] %s: control formed a mixed frame",
			  tag.c_str());

	if (!g_execute)
		return;

	bool const strict = b[ArmM1On].mixed_frames > 0 && b[ArmM1On].fp_only_multi == 0;
	u32 const group = RegGroup(lmul_log2);
	std::vector<std::pair<u32, u32>> cases; // (avl, frm)
	for (u32 avl = 0; avl <= vlmax + 2; ++avl)
		cases.push_back({avl, 0});
	cases.push_back({vlmax / 2 + 1, 1}); // frm = RTZ: every FP frame must take its fallback
	for (auto [avl, frm] : cases) {
		rv32::VectorState seed{};
		Seed(seed, sew_bytes, avl);
		Outcome o[ArmCount];
		for (int a = 0; a < ArmCount; ++a) {
			ApplyArm(a, vlen);
			Execute(b[a], seed, avl, frm, sew_bytes, o[a]);
		}
		++T.cases;
		u32 const vl = o[ArmB].vec.vl;
		CHECK_MSG(vl == (avl < vlmax ? avl : vlmax), "%s: B vl=%u avl=%u vlmax=%u", tag.c_str(), vl,
			  avl, vlmax);
		for (int a = 1; a < ArmCount; ++a) {
			Outcome const &x = o[a], &r = o[ArmB];
			CHECK_MSG(x.vec.vl == r.vec.vl && x.vec.vtype == r.vec.vtype &&
					  x.vec.vstart == r.vec.vstart,
				  "[V] %s %s avl=%u: vl/vtype/vstart %u/%x/%u vs B %u/%x/%u", tag.c_str(),
				  ArmName(a), avl, x.vec.vl, x.vec.vtype, x.vec.vstart, r.vec.vl, r.vec.vtype,
				  r.vec.vstart);
			CHECK_MSG(memcmp(x.gpr, r.gpr, sizeof x.gpr) == 0, "[V] %s %s avl=%u: GPRs differ",
				  tag.c_str(), ArmName(a), avl);
			CHECK_MSG(x.fcsr == r.fcsr, "[V] %s %s avl=%u frm=%u: fcsr %x vs B %x", tag.c_str(),
				  ArmName(a), avl, frm, x.fcsr, r.fcsr);
			// Per register, per element: active lanes exact; tail lanes exact or (vta and
			// written) all ones.
			for (u32 reg = 0; reg < 32; ++reg) {
				bool const written = (p.written_mask >> (reg & ~(group - 1u))) & 1u;
				u32 const base_reg = reg & ~(group - 1u);
				for (u32 e = 0; e < rv32::VLEN_MAX_BYTES / sew_bytes; ++e) {
					u8 const *xp = x.vec.vreg[reg].data() + e * sew_bytes;
					u8 const *rp = r.vec.vreg[reg].data() + e * sew_bytes;
					if (memcmp(xp, rp, sew_bytes) == 0)
						continue;
					// Element index within the register GROUP.
					u32 const elem = (reg - base_reg) * (vlen / 8u / sew_bytes) + e;
					bool const in_group = e < vlen / 8u / sew_bytes;
					bool ones = true;
					for (u32 k = 0; k < sew_bytes; ++k)
						ones = ones && xp[k] == 0xff;
					bool const legal_tail = in_group && written && vta && elem >= vl && ones &&
								!(SwitchOn(a) && strict);
					if (legal_tail) {
						++T.agnostic_tail_lanes;
						continue;
					}
					CHECK_MSG(false,
						  "[%s] %s %s avl=%u frm=%u: v%u elem %u differs from B%s",
						  (SwitchOn(a) && strict) ? "T" : "V", tag.c_str(), ArmName(a), avl,
						  frm, reg, elem, ones ? " (all ones)" : "");
					break;
				}
			}
			// [T] independent of B: the tail of every register equals the SEED.
			if (SwitchOn(a) && strict)
				for (u32 reg = 0; reg < 32; ++reg) {
					u32 const base_reg = reg & ~(group - 1u);
					for (u32 e = 0; e < vlen / 8u / sew_bytes; ++e) {
						u32 const elem = (reg - base_reg) * (vlen / 8u / sew_bytes) + e;
						if (elem < vl && ((p.written_mask >> base_reg) & 1u))
							continue;
						if (memcmp(x.vec.vreg[reg].data() + e * sew_bytes,
							   seed.vreg[reg].data() + e * sew_bytes, sew_bytes) != 0) {
							CHECK_MSG(false,
								  "[T] %s %s avl=%u: v%u elem %u disturbed",
								  tag.c_str(), ArmName(a), avl, reg, elem);
							break;
						}
					}
				}
		}
		if (strict)
			++T.strict_cases;
		// [F] fallbacks.
		if (frm == 0 && vl > 0) {
			for (int a : {ArmM1On, ArmM1OnRecompute, ArmBothOn})
				CHECK_MSG(o[a].fallbacks <= o[ArmB].fallbacks,
					  "[F] %s %s avl=%u: fallbacks %llu > B %llu", tag.c_str(), ArmName(a),
					  avl, (unsigned long long)o[a].fallbacks,
					  (unsigned long long)o[ArmB].fallbacks);
			if (vl < vlmax && b[ArmM1Off].mixed_frames > 0) {
				for (int a : {ArmM1Off, ArmBothOff})
					CHECK_MSG(o[a].fallbacks > o[ArmB].fallbacks,
						  "[F] %s %s avl=%u: switch-off fallbacks %llu not above B %llu",
						  tag.c_str(), ArmName(a), avl,
						  (unsigned long long)o[a].fallbacks,
						  (unsigned long long)o[ArmB].fallbacks);
				++T.partial_fallback_cases_off;
			}
		}
	}
}
} // namespace

int main()
{
#if defined(__x86_64__)
	__builtin_cpu_init();
	g_execute = __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw") &&
		    __builtin_cpu_supports("bmi2");
#endif
	if (!g_execute)
		printf("NOTE: host lacks AVX-512; structural checks only (no execution)\n");
	auto const progs = Programs();
	// vta = 1 / vma = 1 (the FP routes admit only these into a run) at e32/e64 LMUL 1 and e32
	// LMUL 2; and a vta = 0 control, where no FP member joins a run and the switch is inert.
	u32 const vtypes[] = {MakeVType(2, 0, true, true), MakeVType(3, 0, true, true), MakeVType(2, 1, true, true),
			      MakeVType(2, 0, false, false)};
	std::vector<long> mixed_per_prog(progs.size(), 0);
	for (u32 vlen : {512u, 1024u, 2048u})
		for (u32 vt : vtypes)
			for (size_t i = 0; i < progs.size(); ++i) {
				long const before = T.mixed_frames_on;
				RunConfig(progs[i], vlen, vt);
				mixed_per_prog[i] += T.mixed_frames_on - before;
			}
	// Every mixed program must actually form a mixed frame somewhere, or it tests nothing.
	for (size_t i = 0; i < progs.size(); ++i)
		if (progs[i].kind == Kind::Mixed)
			CHECK_MSG(mixed_per_prog[i] > 0, "program %s never formed a mixed frame",
				  progs[i].name);
	if (g_execute) {
		CHECK_MSG(T.strict_cases > 0, "no strict case ran");
		CHECK_MSG(T.partial_fallback_cases_off > 0, "no switch-off partial fallback case ran");
	}
	printf("RVV_RUN_FP_STORE_MASKED_TEST execute=%d builds=%ld cases=%ld strict_cases=%ld "
	       "mixed_frames_on=%ld mixed_frames_off=%ld partial_fallback_cases_off=%ld "
	       "identical_controls=%ld agnostic_tail_lanes=%ld checks=%ld failures=%ld\n",
	       (int)g_execute, T.builds, T.cases, T.strict_cases, T.mixed_frames_on, T.mixed_frames_off,
	       T.partial_fallback_cases_off, T.identical_controls, T.agnostic_tail_lanes, g_checks,
	       g_failures);
	printf("  failures_by_family S=%ld V=%ld T=%ld F=%ld other=%ld\n", g_fail_by[(int)'S'],
	       g_fail_by[(int)'V'], g_fail_by[(int)'T'], g_fail_by[(int)'F'], g_fail_by[(int)'?']);
	for (size_t i = 0; i < progs.size(); ++i)
		printf("  mixed_frames[%s]=%ld\n", progs[i].name, mixed_per_prog[i]);
	return g_failures == 0 ? 0 : 1;
}
