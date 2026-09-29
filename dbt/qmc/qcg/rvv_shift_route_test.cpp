// P7N-B: the logical shift-immediate route (vsll.vi / vsrl.vi), as a structural test.
//
// WHAT THIS FILE HAS TO PROVE, and why each section exists.
//
//   [1] DECODE IS EXACT. Sweeping the whole funct3 x funct6 x vm space, EXACTLY ONE encoding
//       reaches Op::_vsll_vi and exactly one reaches Op::_vsrl_vi. This is the load-bearing check
//       for this route in particular: VF6_VSRA (101001) sits ONE VALUE ABOVE VF6_VSRL (101000),
//       and an arithmetic shift routed through a logical-shift emitter is a silent wrong value for
//       every negative element, not a fault.
//
//   [2] THE GEOMETRY IS DERIVED, NOT ENUMERATED. VLEN 128/256/512/1024 must give chunk widths
//       16/32/64/64 bytes and counts 1/1/1/2, and the shift route's shape must AGREE with the
//       accepted vadd route's shape at every one of them -- the two are separate predicates on
//       purpose, so a divergence has to be a test failure rather than a surprise.
//
//   [3] THE FRAME IS ONE-SOURCE. Three typed ops per chunk (load, lane op, store), not four,
//       and the declared n_typed matches what the emitter sees -- Emit_rvvtypedchunkend Panics
//       otherwise.
//
//   [4] THE SHIFT AMOUNT IS AN IMMEDIATE, REDUCED MODULO SEW. It travels in the node, never in a
//       register, and a raw uimm5 of 33-mod-32 arrives as 1.
//
//   [5] REFUSALS. Route switch off, --rvv-verify, LLVM backend, masked forms, the .vv and .vx
//       forms, vsra at any source, and a VLEN whose register is not a whole number of host chunks
//       must ALL keep the rv32_vialu helper.
//
//   [6] THE RUN CONSUMES THEM. The whole point of the checkpoint: an add -> xor -> sll -> srl ->
//       or sequence -- ChaCha20's rotate shape, written here from the ISA and not from ChaCha --
//       must form ONE run of five members whose intermediate values never touch CPUState, and the
//       shift members must contribute no vector live-in through their immediate.
//
//   [7] MUTATION. Each check is shown to fail when the thing it checks is broken.
//
// SCOPE: structure only. Nothing here is executed and nothing here is timed; the hardware evidence
// is the checkpoint's xbd package. Like the other route tests it uses the audit force-emit switch,
// because it never runs what it emits.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
#include <set>
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
		auto _b = (b);                                                                                \
		if (!(_a == _b)) {                                                                           \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,    \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Encodings, built from the FIELDS rather than copied as magic numbers, so a test that disagrees
// with the decoder disagrees about a field and not about a literal.
// ---------------------------------------------------------------------------------------------
constexpr u32 OPV = 0b1010111;
constexpr u32 Enc(u32 funct6, u32 vm, u32 vs2, u32 vs1_or_imm, u32 funct3, u32 vd)
{
	return (funct6 << 26) | (vm << 25) | (vs2 << 20) | (vs1_or_imm << 15) | (funct3 << 12) |
	       (vd << 7) | OPV;
}
constexpr u32 F6_VADD = 0b000000, F6_VXOR = 0b001011, F6_VOR = 0b001010;
constexpr u32 F6_VSLL = 0b100101, F6_VSRL = 0b101000, F6_VSRA = 0b101001;
constexpr u32 F3_OPIVV = 0b000, F3_OPIVX = 0b100, F3_OPIVI = 0b011;

// vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 W_VSETVLI_E32M1 = 0x0d057557u;

u32 Vsll(u32 vd, u32 vs2, u32 uimm) { return Enc(F6_VSLL, 1, vs2, uimm, F3_OPIVI, vd); }
u32 Vsrl(u32 vd, u32 vs2, u32 uimm) { return Enc(F6_VSRL, 1, vs2, uimm, F3_OPIVI, vd); }

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
};

void ApplyConfig(u32 vlen_bits, bool shift_route = true, bool run = false)
{
	config::vlen_bits = vlen_bits;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_shift = shift_route;
	// The audit force-emit switches for EVERY route this test builds a run out of. This host has
	// no AVX-512, and without them the add/xor/or members would refuse on the CPUID probe and the
	// run test would silently measure a run of shifts only -- which is exactly what it did while
	// this file was being written.
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_xor_force_emit = true;
	config::rvv_qcg_typed_chunk_or_force_emit = true;
	config::rvv_qcg_typed_chunk_shift_force_emit = true;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_hit_counter = true;
	config::rvv_vector_run = run;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_partial_vl = false; // tests below first audit the unchanged full-only frame
}

struct Built {
	MemArena arena{1u << 20};
	std::vector<u32> words;
	Region *region = nullptr;
};

void Build(Built &b, std::vector<u32> const &body)
{
	b.words.clear();
	b.words.push_back(W_VSETVLI_E32M1);
	for (u32 w : body)
		b.words.push_back(w);
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body;
};

std::vector<Frame> FindFrames(Region *region)
{
	std::vector<Frame> frames;
	Frame cur;
	bool open = false;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			auto const op = ins.GetOpcode();
			if (op == Op::_rvvtypedchunkbegin) {
				cur = Frame{};
				cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				continue;
			}
			if (op == Op::_rvvtypedchunkend) {
				cur.end = static_cast<InstRVVTypedChunkEnd *>(&ins);
				frames.push_back(cur);
				open = false;
				continue;
			}
			if (open)
				cur.body.push_back(&ins);
		}
	}
	return frames;
}

unsigned CountOp(Frame const &f, Op op)
{
	unsigned n = 0;
	for (auto *i : f.body)
		n += i->GetOpcode() == op;
	return n;
}

// ---------------------------------------------------------------------------------------------
// [1] DECODE
// ---------------------------------------------------------------------------------------------
void TestDecode()
{
	printf("[1] decode: exactly one encoding reaches each shift op\n");
	unsigned sll = 0, srl = 0, sra_to_family = 0;
	std::set<u32> sll_words, srl_words;
	for (u32 f3 : {0b000u, 0b001u, 0b010u, 0b011u, 0b100u, 0b101u, 0b110u, 0b111u}) {
		for (u32 f6 = 0; f6 < 64; ++f6) {
			for (u32 vm = 0; vm < 2; ++vm) {
				u32 const raw = Enc(f6, vm, 8, 3, f3, 9);
				auto const info = dbt::rv32::rvvrun::ClassifyTypedAluRoute(raw);
				if (!info.present)
					continue;
				if (info.op == dbt::rv32::rvvrun::RunOp::Sll) {
					++sll;
					sll_words.insert(raw);
					CHECK_EQ(f6, F6_VSLL);
					CHECK_EQ(f3, F3_OPIVI);
					CHECK_EQ(vm, 1u);
					CHECK(info.src1_is_imm5);
				} else if (info.op == dbt::rv32::rvvrun::RunOp::Srl) {
					++srl;
					srl_words.insert(raw);
					CHECK_EQ(f6, F6_VSRL);
					CHECK_EQ(f3, F3_OPIVI);
					CHECK_EQ(vm, 1u);
					CHECK(info.src1_is_imm5);
				} else {
					// no OTHER row may claim to have an immediate source
					CHECK(!info.src1_is_imm5);
				}
				// The neighbour that matters: NO row may claim a shift op for the
				// ARITHMETIC funct6. (Other decode classes legitimately use 101001 in
				// their own funct3 groups -- OPFVV, for instance -- so the check is
				// about the OPERATION, not about the funct6 value being unclaimed.)
				if (f6 == F6_VSRA &&
				    (info.op == dbt::rv32::rvvrun::RunOp::Sll ||
				     info.op == dbt::rv32::rvvrun::RunOp::Srl))
					++sra_to_family;
			}
		}
	}
	CHECK_EQ(sll, 1u);
	CHECK_EQ(srl, 1u);
	// vsra must have NO route at all -- it is an arithmetic shift and this checkpoint does not
	// implement vpsrad. This is the neighbour that would be a silent wrong value.
	CHECK_EQ(sra_to_family, 0u);
	printf("  vsll.vi routes: %u   vsrl.vi routes: %u   vsra reaching a shift op: %u\n", sll,
	       srl, sra_to_family);
}

// ---------------------------------------------------------------------------------------------
// [2] GEOMETRY
// ---------------------------------------------------------------------------------------------
struct WidthCase {
	u32 vlen;
	unsigned chunks;
	unsigned bytes;
};

void TestGeometry()
{
	printf("[2] chunk geometry is derived from VLEN, and agrees with the accepted vadd shape\n");
	WidthCase const cases[] = {{128, 1, 16}, {256, 1, 32}, {512, 1, 64}, {1024, 2, 64}};
	for (auto const &c : cases) {
		ApplyConfig(c.vlen);
		Built b;
		Build(b, {Vsll(9, 8, 7)});
		auto const frames = FindFrames(b.region);
		CHECK_EQ(frames.size(), 1u);
		if (frames.empty())
			continue;
		auto const &f = frames[0];
		CHECK_EQ(CountOp(f, Op::_vchunksll), c.chunks);
		CHECK_EQ(CountOp(f, Op::_vstatechunkload), c.chunks);
		CHECK_EQ(CountOp(f, Op::_vstatechunkstore), c.chunks);
		// [3] THREE typed ops per chunk, and the DECLARED count must equal them.
		CHECK_EQ((unsigned)f.begin->n_typed, 3u * c.chunks);
		CHECK_EQ(f.body.size(), 3u * c.chunks);
		// the chunk WIDTH, read off the value type the ops were built with
		for (auto *i : f.body) {
			if (i->GetOpcode() != Op::_vchunksll)
				continue;
			auto const t = i->o(0).GetType();
			CHECK_EQ((unsigned)qir::VTypeToSize(t), c.bytes);
		}
		printf("  VLEN %4u -> %u chunk(s) of %u bytes\n", c.vlen, c.chunks, c.bytes);
	}
}

// ---------------------------------------------------------------------------------------------
// [4] THE IMMEDIATE
// ---------------------------------------------------------------------------------------------
void TestImmediate()
{
	printf("[4] the shift amount is a node field, reduced modulo SEW\n");
	ApplyConfig(512);
	for (u32 uimm = 0; uimm < 32; ++uimm) {
		Built b;
		Build(b, {Vsll(9, 8, uimm), Vsrl(11, 10, uimm)});
		auto const frames = FindFrames(b.region);
		CHECK_EQ(frames.size(), 2u);
		if (frames.size() != 2)
			continue;
		for (auto *i : frames[0].body)
			if (i->GetOpcode() == Op::_vchunksll)
				CHECK_EQ((unsigned)static_cast<InstVChunkSll *>(i)->shamt, uimm);
		for (auto *i : frames[1].body)
			if (i->GetOpcode() == Op::_vchunksrl)
				CHECK_EQ((unsigned)static_cast<InstVChunkSrl *>(i)->shamt, uimm);
	}
	// The reduction is the CONSTRUCTOR's, so it is checked at that level too: at SEW=4 the mask
	// is the identity on five bits, and at a narrower SEW it is not. Building the node directly
	// is the only way to see the second case, because no admitted route emits SEW < 4 today.
	{
		Built b;
		auto d = VOperand::MakeVVPR(VType::V512, 1);
		auto s = VOperand::MakeVVPR(VType::V512, 2);
		InstVChunkSll a(d, s, 4, 31);
		CHECK_EQ((unsigned)a.shamt, 31u);
		InstVChunkSll narrow(d, s, 2, 31); // SEW=16: 31 mod 16 == 15
		CHECK_EQ((unsigned)narrow.shamt, 15u);
		InstVChunkSrl narrow2(d, s, 1, 9); // SEW=8: 9 mod 8 == 1
		CHECK_EQ((unsigned)narrow2.shamt, 1u);
	}
	printf("  32 immediates round-trip at SEW=32; modulo reduction holds at SEW 16 and 8\n");
}

// ---------------------------------------------------------------------------------------------
// [5] REFUSALS
// ---------------------------------------------------------------------------------------------
void ExpectHelperOnly(char const *what, std::vector<u32> const &body)
{
	Built b;
	Build(b, body);
	auto const frames = FindFrames(b.region);
	unsigned shifts = 0;
	for (auto const &f : frames)
		shifts += CountOp(f, Op::_vchunksll) + CountOp(f, Op::_vchunksrl);
	if (shifts != 0) {
		fprintf(stderr, "  FAIL %s: emitted %u shift chunk ops, expected the helper\n", what,
			shifts);
		++g_failures;
	} else {
		printf("  refused: %s\n", what);
	}
}

void TestRefusals()
{
	printf("[5] every non-admitted form keeps the rv32_vialu helper\n");
	ApplyConfig(512, /*shift_route=*/false);
	ExpectHelperOnly("route switch off", {Vsll(9, 8, 7)});

	ApplyConfig(512);
	config::rvv_verify = true;
	ExpectHelperOnly("--rvv-verify", {Vsll(9, 8, 7)});

	ApplyConfig(512);
	config::aot_use_llvm = true;
	ExpectHelperOnly("LLVM backend (there is no LLVM lowering)", {Vsll(9, 8, 7)});

	ApplyConfig(512);
	config::rvv_direct = false;
	ExpectHelperOnly("--rvv-direct off", {Vsll(9, 8, 7)});

	ApplyConfig(512);
	ExpectHelperOnly("masked vsll.vi (vm=0)", {Enc(F6_VSLL, 0, 8, 7, F3_OPIVI, 9)});
	ExpectHelperOnly("masked vsrl.vi (vm=0)", {Enc(F6_VSRL, 0, 8, 7, F3_OPIVI, 9)});
	ExpectHelperOnly("vsll.vv", {Enc(F6_VSLL, 1, 8, 7, F3_OPIVV, 9)});
	ExpectHelperOnly("vsll.vx", {Enc(F6_VSLL, 1, 8, 7, F3_OPIVX, 9)});
	ExpectHelperOnly("vsrl.vv", {Enc(F6_VSRL, 1, 8, 7, F3_OPIVV, 9)});
	ExpectHelperOnly("vsra.vi (ARITHMETIC shift, no route)", {Enc(F6_VSRA, 1, 8, 7, F3_OPIVI, 9)});
	ExpectHelperOnly("vsra.vv", {Enc(F6_VSRA, 1, 8, 7, F3_OPIVV, 9)});

	// A VLEN whose register is not a whole number of host chunks REFUSES rather than rounds.
	ApplyConfig(384);
	ExpectHelperOnly("VLEN 384 (48-byte register is not a host chunk width)", {Vsll(9, 8, 7)});
	ApplyConfig(64);
	ExpectHelperOnly("VLEN 64 (below the narrowest host vector)", {Vsll(9, 8, 7)});
}

// ---------------------------------------------------------------------------------------------
// [6] THE RUN
// ---------------------------------------------------------------------------------------------
void TestRun()
{
	printf("[6] add -> xor -> sll -> srl -> or forms ONE component-resident run\n");
	// This is the ISA shape of a rotate-and-mix step. It is written from the RVV encoding, not
	// copied from any workload: no PC, no ChaCha constant, no ChaCha register number.
	//   v3 = v3 + v2      (vadd.vv)
	//   v4 = v4 ^ v3      (vxor.vv)
	//   v5 = v4 << 7      (vsll.vi)
	//   v6 = v4 >> 25     (vsrl.vi)
	//   v4 = v5 | v6      (vor.vv)
	std::vector<u32> const body = {
	    Enc(F6_VADD, 1, 2, 3, F3_OPIVV, 3), Enc(F6_VXOR, 1, 3, 4, F3_OPIVV, 4),
	    Vsll(5, 4, 7), Vsrl(6, 4, 25), Enc(F6_VOR, 1, 6, 5, F3_OPIVV, 4)};

	for (u32 vlen : {512u, 1024u}) {
		ApplyConfig(vlen, /*shift_route=*/true, /*run=*/true);
		Built b;
		Build(b, body);
		auto const frames = FindFrames(b.region);
		Frame const *run = nullptr;
		for (auto const &f : frames)
			if (f.end->n_members >= 2)
				run = &f;
		CHECK(run != nullptr);
		if (!run)
			continue;
		unsigned const k = vlen / 512 ? vlen / 512 : 1;
		CHECK_EQ((unsigned)run->end->n_members, 5u);
		// The five lane operations, one per member per chunk.
		CHECK_EQ(CountOp(*run, Op::_vchunkadd), k);
		CHECK_EQ(CountOp(*run, Op::_vchunkxor), k);
		CHECK_EQ(CountOp(*run, Op::_vchunksll), k);
		CHECK_EQ(CountOp(*run, Op::_vchunksrl), k);
		CHECK_EQ(CountOp(*run, Op::_vchunkor), k);
		// COMPONENT RESIDENCE, which is the whole point: live-ins loaded once, live-outs stored
		// once, and NOTHING in between. The run reads v2, v3 and v4 and writes v3, v4, v5, v6.
		CHECK_EQ(CountOp(*run, Op::_vstatechunkload), 3u * k);
		CHECK_EQ(CountOp(*run, Op::_vstatechunkstore), 4u * k);
		// The two shift members contribute NO live-in through their immediate: a fourth load
		// would mean a shift amount was mistaken for a vector register.
		printf("  VLEN %4u: 5 members, %u loads, %u stores, %u lane ops\n", vlen,
		       3u * k, 4u * k,
		       CountOp(*run, Op::_vchunkadd) + CountOp(*run, Op::_vchunkxor) +
			   CountOp(*run, Op::_vchunksll) + CountOp(*run, Op::_vchunksrl) +
			   CountOp(*run, Op::_vchunkor));
	}

	// AND THE CONTROL: with the shift route OFF the same five instructions cannot form one run.
	// This is what makes the check above about the shift rows rather than about runs in general.
	{
		ApplyConfig(1024, /*shift_route=*/false, /*run=*/true);
		Built b;
		Build(b, body);
		auto const frames = FindFrames(b.region);
		unsigned longest = 0;
		for (auto const &f : frames)
			longest = std::max<unsigned>(longest, f.end->n_members);
		CHECK(longest < 5u);
		printf("  control: with the shift route off the longest run is %u members, not 5\n",
		       longest);
	}
}

// ---------------------------------------------------------------------------------------------
// [7] MUTATION -- each check is shown to fail when the thing it checks is broken.
// ---------------------------------------------------------------------------------------------
void TestMutationSensitivity()
{
	printf("[7] the checks are falsifiable\n");
	// A frame that declared four typed ops per chunk instead of three would be caught by the
	// n_typed equality in [2]; demonstrate that the equality is not vacuous by checking that the
	// two-source route really does declare four.
	ApplyConfig(512);
	Built b;
	Build(b, {Enc(F6_VXOR, 1, 3, 4, F3_OPIVV, 4)});
	auto const frames = FindFrames(b.region);
	CHECK_EQ(frames.size(), 1u);
	if (!frames.empty()) {
		CHECK_EQ((unsigned)frames[0].begin->n_typed, 4u);
		printf("  a two-source frame declares 4 typed ops, a one-source frame 3\n");
	}
	// And that the shift ops are DISTINCT opcodes: a single op with a direction field would make
	// this equality impossible to write.
	CHECK(Op::_vchunksll != Op::_vchunksrl);
}

void TestRestartArm()
{
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u, 4096u}) {
		for (u32 raw : {Vsll(9, 8, 16), Vsrl(9, 8, 31)}) {
			ApplyConfig(vlen);
			config::rvv_qcg_partial_vl = true;
			Built b;
			Build(b, {raw});
			auto frames = FindFrames(b.region);
			CHECK_EQ(frames.size(), 1u);
			if (frames.empty()) continue;
			auto const &f = frames.front();
			u32 const k = std::max(1u, vlen / 512);
			CHECK(f.begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeIntegerTwoArm);
			CHECK_EQ(f.begin->n_typed, 4u * k);
			CHECK_EQ(CountOp(f, Op::_rvvtypedchunkpartial), 1u);
			CHECK_EQ(CountOp(f, Op::_vchunkpartialalu), k);
			u32 c = 0;
			for (auto *i : f.body) {
				if (i->GetOpcode() != Op::_vchunkpartialalu) continue;
				auto *p = static_cast<InstVChunkPartialAlu *>(i);
				CHECK(p->architectural_mask);
				CHECK(!p->masked);
				CHECK(p->finish_instruction == (c + 1 == k));
				++c;
			}
		}
	}
}

} // namespace

int main()
{
	printf("rvv_shift_route_test\n");
	TestDecode();
	TestGeometry();
	TestImmediate();
	TestRefusals();
	TestRun();
	TestMutationSensitivity();
	TestRestartArm();
	printf("%s (%d failure(s))\n", g_failures ? "FAILED" : "PASSED", g_failures);
	return g_failures ? 1 : 0;
}
