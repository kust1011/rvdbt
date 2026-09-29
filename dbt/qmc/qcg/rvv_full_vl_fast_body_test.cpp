// G11-A (2026-09-07): --rvv-qcg-full-vl-fast-body, default off.
//
// A typed frame whose OWN emitted guard tests `vl` with `jne VLMAX` and `vstart` with `jne 0`
// (qir::InstRVVTypedChunkBegin::GuardProvesFullVl) has proved that the prestart set [0, vstart)
// and the tail set [vl, VLMAX) are both empty. For an UNMASKED vfalu/vfma member the active-element
// predicate is therefore the translation-time constant all-ones, so the lane op needs no mask
// derivation, no `{k}`, no tail-agnostic fill, and -- for the funct6 arms whose host operation
// writes every lane without reading the destination -- no destination seed.
//
// WHAT IS CHECKED, AND WHAT EACH CHECK'S FAILURE LOOKS LIKE
//
//   [1] EXACT GUARD ELIGIBILITY. GuardProvesFullVl is evaluated over ALL 17 GuardKind values and
//       must be true for exactly {VTypeVlVstart, VTypeVlVstartFrmRNE, VTypeVlVstartBaseLimit}. A
//       kind that weakens vl to `<=`, lets the body handle vstart, reaches its body through a
//       partial-arm branch, or is vtype-independent must be false. Widening the predicate by one
//       row fails here rather than on hardware.
//
//   [2] EMITTED-CODE ABSENCE/PRESENCE on the one frame shape that is eligible AND contains FP lane
//       ops: a vector run with both an integer and an FP member (e32 is the only width at which
//       that is expressible), which FormRun guards with VTypeVlVstartFrmRNE. Switch OFF: the
//       per-chunk prologue (vl load, bzhi, kmovw), `{k1}` on every lane op, and the `knotw` +
//       `vpternlogd $0xff` tail fill are all present. Switch ON: every one of those is GONE, while
//       the arithmetic, the integer member, the NaN canonicalisation (vcmpps + the 0x7fc00000
//       broadcast + vmovaps) and the frame's own guard are UNCHANGED IN COUNT. Absence alone would
//       pass if the frame stopped being emitted, so the presence half is not decoration.
//
//   [3] THE DESTINATION SEED IS DISCRIMINATED, NOT DROPPED. In the same eligible frame and with the
//       switch on, vfadd/vfsub/vfmul/vfdiv lose their `vmovdqu64 zmm,zmm` seed while vfmin, vfmax,
//       vfsgnj and vfmadd KEEP it -- min/max writes the destination through three partial masks and
//       the lanes no mask covers must still hold the seeded vs2, sign injection uses it as a
//       VPTERNLOG input, and every FMA form reads it as multiplicand or accumulator. A predicate
//       that is degenerate in EITHER direction fails: the elidable rows would keep a dead seed, the
//       non-elidable rows would lose a live one.
//
//   [4] REJECTED FRAMES ARE BYTE-IDENTICAL. The whole emitted byte stream with the switch on must
//       equal the stream with it off for: an FP-only run (VTypePartialVlVstartFrmRNE -- vl <= VLMAX,
//       the partial-vl case), a single-instruction FP frame (VTypePartialVlVstartFrmHost -- the
//       body handles a non-zero vstart, i.e. the restart case), a run-time-SEW frame, a masked
//       (vm = 0) frame, an integer-only run (an ELIGIBLE guard kind with no FP lane op, which also
//       proves integer bodies were not disturbed) and the LLVM backend. This is the check that the
//       fast body is not entered for a partial vl or a restartable frame.
//
//   [5] A12 SUPERSESSION / COHERENCE. For an eligible frame the emitted bytes must be IDENTICAL
//       whether the A12 shared masks are on or off, because an admitted frame builds none either
//       way. This is the design contradiction the checkpoint had to fix: a frame cannot both hold a
//       resident k(1+chunk) and claim its lane ops are unmasked.
//
//   [6] THE COHERENCE CHECK IS ENFORCED, NOT DOCUMENTED (fork + abnormal exit). Hand-built QIR that
//       puts a `vchunkmaskset` inside a frame whose guard kind the predicate admits must Panic in
//       QEmit with the switch ON, and must emit normally with the switch OFF. Without the negative
//       control the Panic could be firing for an unrelated reason.
//
// SCOPE. Structure and translation only. NOTHING HERE EXECUTES THE EMITTED BYTES: the development
// host is an Ivy Bridge i7-3770 with no AVX-512, so these frames cannot run in this process, and
// like every other route test in this tree the audit force-emit switches bypass ONLY the host
// feature probe, never the architectural guard. No timing, no performance claim.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <cstring>
#include <functional>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
using GuardKind = InstRVVTypedChunkBegin::GuardKind;

namespace
{
int g_failures = 0;
#define CHECK(cond)                                                                                  \
	do {                                                                                         \
		if (!(cond)) {                                                                       \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)
#define CHECK_EQ(a, b)                                                                               \
	do {                                                                                         \
		auto _a = (a);                                                                       \
		auto _b = (b);                                                                       \
		if (!(_a == _b)) {                                                                   \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,         \
				__LINE__, #a, #b, (long long)_a, (long long)_b);                     \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

// ---------------------------------------------------------------------------------------------
// instruction words, built by field encoders (nothing hand-transcribed)

constexpr u32 VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0,a0,e32,m1,ta,ma
constexpr u32 VSETVLI_E64M1 = 0x0d857557u;
constexpr u32 MakeOpV(u32 f6, u32 vm, u32 vs2, u32 src1, u32 vd, u32 funct3)
{
	return (f6 << 26) | (vm << 25) | (vs2 << 20) | (src1 << 15) | (funct3 << 12) | (vd << 7) | 0x57u;
}
// OPFVV (funct3 001), OPFVF (101), OPIVV (000); vm = 1 is the unmasked encoding, vm = 0 masked.
constexpr u32 Vv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 1, vs2, vs1, vd, 0b001u); }
constexpr u32 VvM(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 0, vs2, vs1, vd, 0b001u); }
constexpr u32 Vf(u32 f6, u32 vs2, u32 rs1, u32 vd) { return MakeOpV(f6, 1, vs2, rs1, vd, 0b101u); }
constexpr u32 Iv(u32 f6, u32 vs2, u32 vs1, u32 vd) { return MakeOpV(f6, 1, vs2, vs1, vd, 0b000u); }

constexpr u32 F6_VADD = 0b000000u;
constexpr u32 F6_VFADD = 0b000000u, F6_VFSUB = 0b000010u, F6_VFMIN = 0b000100u,
	      F6_VFMAX = 0b000110u, F6_VFSGNJ = 0b001000u, F6_VFDIV = 0b100000u,
	      F6_VFMUL = 0b100100u, F6_VFMADD = 0b101000u;
static_assert(Iv(F6_VADD, 1, 2, 8) == 0x02110457u, "vadd.vv v8,v1,v2");
static_assert(Vv(F6_VFADD, 8, 9, 8) == 0x02849457u, "vfadd.vv v8,v8,v9");
static_assert(Vf(F6_VFMADD, 8, 8, 9) == 0xa28454d7u, "vfmadd.vf v9,fs0,v8 (miniWeather word)");

// ---------------------------------------------------------------------------------------------

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override { buf.resize(sz); return buf.data(); }
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	std::vector<u8> buf;
};

struct Env {
	u32 vlen_bits = 512;
	bool full_vl = false;  // G11-A, the switch under test
	bool shared = false;   // A12
	bool vector_run = true;
	bool llvm = false;
};

void ApplyEnv(Env const &e)
{
	config::vlen_bits = e.vlen_bits;
	config::rvv_qcg_full_vl_fast_body = e.full_vl;
	// F1 GUARD (2026-09-23). This test's only FP vehicle for a full-VL-guarded frame is the mixed
	// integer+FP run (see MixedRun), which --rvv-run-fp-store-masked-partial-vl=1 moves to the
	// partial kind that G11-A does not admit. Pin the F0 conjunction so the subject under test,
	// G11-A, keeps its vehicle; rvv_fp_component_run_test [6] pins both switch positions.
	config::rvv_run_fp_store_masked_partial_vl = false;
	config::rvv_qcg_fp_shared_mask = e.shared;
	config::rvv_vector_run = e.vector_run;
	config::rvv_run_live_range_split = false;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_run_dep_probe_cross = false;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = e.llvm;
	config::rvv_vector_ssa = false;
	config::rvv_vector_ssa_host_fma = false;
	config::rvv_qcg_typed_chunk_falu = true;
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_fma_force_emit = true;
	config::rvv_qcg_narrow_chunk_width = true;
	config::rvv_qcg_narrow_chunk_width_force_emit = true;
	// The integer .vv routes, so a run can hold BOTH an integer and an FP member -- the only
	// shape FormRun guards with VTypeVlVstartFrmRNE, i.e. the only eligible frame with FP ops.
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_sub_force_emit = true;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_direct_setvl = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
	config::rvv_lowering = 1;
}

struct Built {
	MemArena arena{1u << 21};
	std::vector<u32> words;
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
};

void Translate(Built &b, std::vector<u32> const &words, Env const &e)
{
	ApplyEnv(e);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}
void Emit(Built &b)
{
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
}
void Build(Built &b, std::vector<u32> const &words, Env const &e)
{
	Translate(b, words, e);
	Emit(b);
}

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	std::vector<Inst *> body;
};
std::vector<Frame> FindFrames(Region *region)
{
	std::vector<Frame> out;
	Frame cur;
	bool open = false;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin:
				cur = Frame{};
				cur.begin = static_cast<InstRVVTypedChunkBegin *>(&ins);
				open = true;
				break;
			case Op::_rvvtypedchunkend:
				if (open) { out.push_back(cur); open = false; }
				break;
			default:
				if (open) cur.body.push_back(&ins);
				break;
			}
		}
	return out;
}
unsigned CountOp(Frame const &f, Op op)
{
	unsigned n = 0;
	for (auto *i : f.body) n += i->GetOpcode() == op;
	return n;
}

// ---------------------------------------------------------------------------------------------
// disassembly (same reader the A12 test uses)

bool IsInstructionLine(std::string const &line)
{
	auto const start = line.find_first_not_of(" \t");
	if (start == std::string::npos) return false;
	auto const end = line.find_first_not_of("0123456789abcdefABCDEF", start);
	return end != std::string::npos && end > start && line[end] == ':';
}
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_g11_emit_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) { fprintf(stderr, "  mkstemp: %s\n", strerror(errno)); return {}; }
	size_t written = 0;
	while (written < code.size()) {
		ssize_t n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) { close(fd); unlink(path); return {}; }
		written += (size_t)n;
	}
	close(fd);
	std::string cmd = std::string("objdump -D -b binary -m i386:x86-64 -M intel "
				      "--no-show-raw-insn ") + path + " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) { unlink(path); return {}; }
	std::vector<std::string> lines;
	char buf[1024];
	while (fgets(buf, sizeof buf, p)) {
		std::string l(buf);
		if (!l.empty() && l.back() == '\n') l.pop_back();
		if (IsInstructionLine(l)) lines.push_back(l);
	}
	int rc = pclose(p);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) { fprintf(stderr, "  objdump failed\n"); return {}; }
	return lines;
}
unsigned CountContaining(std::vector<std::string> const &lines, std::string const &needle)
{
	unsigned n = 0;
	for (auto const &l : lines) n += l.find(needle) != std::string::npos;
	return n;
}
unsigned CountMnem(std::vector<std::string> const &lines, std::string const &mnem)
{
	unsigned n = 0;
	for (auto const &l : lines) {
		auto c = l.find(':');
		if (c == std::string::npos) continue;
		std::string rest = l.substr(c + 1);
		size_t s = rest.find_first_not_of(" \t");
		if (s == std::string::npos) continue;
		rest = rest.substr(s);
		n += rest.compare(0, mnem.size(), mnem) == 0 &&
		     (rest.size() == mnem.size() || rest[mnem.size()] == ' ');
	}
	return n;
}
std::string Hex(u32 v) { char b[32]; snprintf(b, sizeof b, "0x%x", v); return b; }
// The per-chunk prologue's vl READ. The frame's own guard compares vl in memory
// (`cmp DWORD PTR [r13+..],..`) and is deliberately not matched by this.
std::string VlLoad()
{
	return "mov    eax,DWORD PTR [r13+" +
	       Hex((u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vl))) + "]";
}
std::string VstartLoad()
{
	return "mov    eax,DWORD PTR [r13+" +
	       Hex((u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart))) + "]";
}
// `vmovdqu64 zmm,zmm` (no memory operand, no writemask) is the destination seed.
unsigned SeedCopies(std::vector<std::string> const &lines)
{
	unsigned n = 0;
	for (auto const &l : lines) {
		auto c = l.find("vmovdqu64");
		if (c == std::string::npos) continue;
		if (l.find("PTR") != std::string::npos) continue;
		if (l.find('{') != std::string::npos) continue;
		++n;
	}
	return n;
}

// Two `Built` objects hold their guest words at different heap addresses, and the emitter embeds
// that address (and the runtime stub targets) as 64-bit absolute immediates. Raw byte equality
// would therefore fail for reasons that have nothing to do with the switch under test, so the
// comparison is over the disassembly with every long hex literal masked. An immediate's VALUE does
// not change an instruction's length, so a real difference still shows up as a different line, a
// different mnemonic or a different instruction count.
std::string Normalize(std::vector<std::string> const &lines)
{
	std::string out;
	for (auto const &l : lines) {
		auto c = l.find(':');
		std::string rest = c == std::string::npos ? l : l.substr(c + 1);
		std::string t;
		for (size_t i = 0; i < rest.size();) {
			if (rest.compare(i, 2, "0x") == 0) {
				size_t j = i + 2;
				while (j < rest.size() && isxdigit((unsigned char)rest[j])) ++j;
				if (j - i - 2 >= 9) { t += "ABS"; i = j; continue; }
			}
			t += rest[i++];
		}
		out += t;
		out += '\n';
	}
	return out;
}

unsigned ChunkBytes(u32 vlen) { return vlen / 8 > 64 ? 64 : vlen / 8; }
unsigned Chunks(u32 vlen) { return (vlen / 8) / ChunkBytes(vlen); }

// ---------------------------------------------------------------------------------------------

void Section1_GuardEligibility()
{
	fprintf(stderr, "[1] GuardProvesFullVl over all 17 guard kinds\n");
	struct Row { GuardKind k; char const *name; bool want; };
	// Every value of the enum, with the fact that decides it.
	Row const rows[] = {
	    {GuardKind::VTypeVlVstart, "VTypeVlVstart (vl == VLMAX, vstart == 0)", true},
	    {GuardKind::VlenbVstart, "VlenbVstart (vtype-independent whole register)", false},
	    {GuardKind::VTypePartialVlVstartFrmRNE, "VTypePartialVlVstartFrmRNE (vl <= VLMAX)", false},
	    {GuardKind::VTypeE32OrE64M2PartialVlVstartFrmRNE, "dynamic SEW, vl <= VLMAX", false},
	    {GuardKind::VTypeVlVstartFrmRNE, "VTypeVlVstartFrmRNE (the mixed run)", true},
	    {GuardKind::VTypeVlOrPartialVstart, "VTypeVlOrPartialVstart (A3 two-arm)", false},
	    {GuardKind::VTypeVlVstartBaseLimit, "VTypeVlVstartBaseLimit (+ base range)", true},
	    {GuardKind::VlenbVstartBaseLimit, "VlenbVstartBaseLimit (whole register)", false},
	    {GuardKind::VTypeInteger, "VTypeInteger (body handles vstart/mask/tail)", false},
	    {GuardKind::VTypeIntegerTwoArm, "VTypeIntegerTwoArm (partial-arm branch)", false},
	    {GuardKind::VTypeIntegerNoRestart, "VTypeIntegerNoRestart (vl <= VLMAX)", false},
	    {GuardKind::VTypePartialVlVstartFrmHost, "VTypePartialVlVstartFrmHost (restartable)", false},
	    {GuardKind::VTypeFpNoRestart, "VTypeFpNoRestart (reduction)", false},
	    {GuardKind::VlenbRestartable, "VlenbRestartable (whole-register memory)", false},
	    {GuardKind::VTypeFpAnyRM, "VTypeFpAnyRM (vl <= VLMAX)", false},
	    {GuardKind::VTypeFpAnyRMNoRestart, "VTypeFpAnyRMNoRestart (reduction)", false},
	    {GuardKind::VTypeVlOrPartialVstartBaseLimit, "VTypeVlOrPartialVstartBaseLimit", false},
	};
	CHECK_EQ(sizeof(rows) / sizeof(rows[0]), (size_t)17); // every enumerator is listed
	unsigned admitted = 0;
	for (auto const &r : rows) {
		bool const got = InstRVVTypedChunkBegin::GuardProvesFullVl(r.k);
		if (got != r.want)
			fprintf(stderr, "  FAIL %s: got %d want %d\n", r.name, (int)got, (int)r.want);
		g_failures += got != r.want;
		admitted += got;
	}
	CHECK_EQ(admitted, 3u);
	fprintf(stderr, "    17 kinds, %u admitted\n", admitted);
}

// The one eligible frame shape that contains FP lane ops: a run with an integer AND an FP member.
// e32 is the only width at which an integer route and an FP route can be members of the same run,
// which is why FormRun's conjunction (VTypeVlVstartFrmRNE) is reachable at all.
std::vector<u32> MixedRun(u32 fp_word)
{
	return {VSETVLI_E32M1, Iv(F6_VADD, 1, 2, 8), fp_word};
}

void Section2_EmittedCode()
{
	fprintf(stderr, "[2] eligible frame (mixed integer+FP run): what disappears and what does not\n");
	for (u32 vlen : {128u, 512u, 1024u}) {
		unsigned const k = Chunks(vlen);
		std::vector<u32> const words = MixedRun(Vv(F6_VFADD, 8, 9, 8));
		std::vector<std::string> dis[2];
		unsigned nodes[2] = {0, 0};
		for (int on = 0; on < 2; ++on) {
			Built b;
			Build(b, words, Env{vlen, on != 0, /*shared=*/false});
			auto frames = FindFrames(b.region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.size() != 1) return;
			CHECK(frames[0].begin->guard_kind == GuardKind::VTypeVlVstartFrmRNE);
			CHECK_EQ(frames[0].begin->n_members, (u8)2);
			nodes[on] = CountOp(frames[0], Op::_vchunkfalu);
			dis[on] = Disassemble(b.code);
			CHECK(!dis[on].empty());
		}
		// The QIR is UNCHANGED: this is an emitter-side elision, not a different lowering.
		CHECK_EQ(nodes[0], k);
		CHECK_EQ(nodes[1], k);

		// ABSENCE, with the switch on.
		CHECK_EQ(CountContaining(dis[0], VlLoad()), k);
		CHECK_EQ(CountContaining(dis[1], VlLoad()), 0u);
		CHECK_EQ(CountContaining(dis[0], VstartLoad()), k);
		CHECK_EQ(CountContaining(dis[1], VstartLoad()), 0u);
		// EmitRvvFpLaneMask emits TWO bzhi per chunk: the vl window and the prestart removal.
		CHECK_EQ(CountMnem(dis[0], "bzhi"), 2 * k);
		CHECK_EQ(CountMnem(dis[1], "bzhi"), 0u);
		CHECK_EQ(CountMnem(dis[0], "kmovw"), k);
		CHECK_EQ(CountMnem(dis[1], "kmovw"), 0u);
		CHECK_EQ(CountMnem(dis[0], "knotw"), k);         // the tail fill's ~active
		CHECK_EQ(CountMnem(dis[1], "knotw"), 0u);
		CHECK_EQ(CountMnem(dis[0], "vpternlogd"), k);    // the all-ones tail fill
		CHECK_EQ(CountMnem(dis[1], "vpternlogd"), 0u);
		// k1 is the ACTIVE mask and must be gone; k2 is the NaN scratch and must NOT be --
		// the unordered compare that feeds it is data-dependent, not a vl fact.
		// k1 (the ACTIVE mask) writemasks the lane op and the NaN-detect compare: 2 per chunk.
		CHECK_EQ(CountContaining(dis[0], "{k1}"), 2 * k);
		CHECK_EQ(CountContaining(dis[1], "{k1}"), 0u);
		// k2 (the SCRATCH) writemasks the NaN merge and the tail fill: 2 per chunk with the
		// switch off, 1 with it on, because the tail fill is gone and the NaN merge is not.
		CHECK_EQ(CountContaining(dis[0], "{k2}"), 2 * k);
		CHECK_EQ(CountContaining(dis[1], "{k2}"), k);

		// PRESENCE: the frame is still a frame and still does the arithmetic. Without this
		// half, a frame that stopped being emitted at all would pass the absence checks.
		char const *kept[] = {"vaddps", "vpaddd", "vcmpunordps", "vmovaps", "vpbroadcastd",
				      "stmxcsr", "ldmxcsr"};
		for (auto const *m : kept) {
			unsigned const off = CountMnem(dis[0], m), onn = CountMnem(dis[1], m);
			CHECK(off > 0);     // it was there to begin with
			CHECK_EQ(onn, off); // and the switch did not touch it
		}
		CHECK_EQ(CountMnem(dis[0], "vaddps"), k); // the FP member
		CHECK_EQ(CountMnem(dis[0], "vpaddd"), k); // the integer member
		for (int on = 0; on < 2; ++on) {
			CHECK_EQ(CountContaining(dis[on], "0x7fc00000"), k); // canonical NaN, kept
			// The frame's OWN guard, unchanged. It compares vl and vstart IN MEMORY, which
			// is why the per-chunk `mov eax,[vl]` can go to zero while the guard remains --
			// and it is the guard, not the elided prologue, that proves the predicate.
			CHECK_EQ(CountContaining(dis[on],
						 "cmp    DWORD PTR [r13+" +
						     Hex((u32)(offsetof(CPUState, vec) +
							       offsetof(rv32::VectorState, vl))) + "]"),
				 1u);
			CHECK_EQ(CountContaining(dis[on],
						 "cmp    DWORD PTR [r13+" +
						     Hex((u32)(offsetof(CPUState, vec) +
							       offsetof(rv32::VectorState, vstart))) + "]"),
				 1u);
		}
		// The seed: vfadd's arm writes every lane without reading the destination.
		CHECK_EQ(SeedCopies(dis[0]), k);
		CHECK_EQ(SeedCopies(dis[1]), 0u);
		fprintf(stderr, "    VLEN %4u k=%u: vl loads %u->%u, bzhi %u->%u, kmovw %u->%u, "
				"tail fill %u->%u, seeds %u->%u, vaddps %u (both)\n",
			vlen, k, CountContaining(dis[0], VlLoad()), CountContaining(dis[1], VlLoad()),
			CountMnem(dis[0], "bzhi"), CountMnem(dis[1], "bzhi"),
			CountMnem(dis[0], "kmovw"), CountMnem(dis[1], "kmovw"),
			CountMnem(dis[0], "vpternlogd"), CountMnem(dis[1], "vpternlogd"),
			SeedCopies(dis[0]), SeedCopies(dis[1]), CountMnem(dis[1], "vaddps"));
	}
}

void Section3_SeedDiscrimination()
{
	fprintf(stderr, "[3] the destination seed is dropped only where the host arm fully "
			"overwrites the destination\n");
	struct Row { char const *name; u32 word; bool seed_elidable; char const *why; };
	Row const rows[] = {
	    {"vfadd.vv", Vv(F6_VFADD, 8, 9, 8), true, "one vaddps writes every lane"},
	    {"vfsub.vv", Vv(F6_VFSUB, 8, 9, 8), true, "one vsubps writes every lane"},
	    {"vfmul.vv", Vv(F6_VFMUL, 8, 9, 8), true, "one vmulps writes every lane"},
	    {"vfdiv.vv", Vv(F6_VFDIV, 8, 9, 8), true, "one vdivps writes every lane"},
	    {"vfmin.vv", Vv(F6_VFMIN, 8, 9, 8), false, "three partial masks; uncovered lanes keep vs2"},
	    {"vfmax.vv", Vv(F6_VFMAX, 8, 9, 8), false, "three partial masks; uncovered lanes keep vs2"},
	    {"vfsgnj.vv", Vv(F6_VFSGNJ, 8, 9, 8), false, "the destination is a VPTERNLOG input"},
	    {"vfmadd.vf", Vf(F6_VFMADD, 8, 8, 9), false, "213 form reads the destination"},
	};
	u32 const vlen = 512;
	unsigned const k = Chunks(vlen);
	unsigned elidable_seen = 0, kept_seen = 0;
	for (auto const &r : rows) {
		Built b;
		Build(b, MixedRun(r.word), Env{vlen, /*full_vl=*/true, /*shared=*/false});
		auto frames = FindFrames(b.region);
		CHECK_EQ(frames.size(), (size_t)1);
		if (frames.size() != 1) continue;
		CHECK(frames[0].begin->guard_kind == GuardKind::VTypeVlVstartFrmRNE);
		auto dis = Disassemble(b.code);
		CHECK(!dis.empty());
		unsigned const seeds = SeedCopies(dis);
		CHECK_EQ(seeds, r.seed_elidable ? 0u : k);
		elidable_seen += r.seed_elidable;
		kept_seen += !r.seed_elidable;
		// The mask machinery is gone for every row -- the seed rule is orthogonal to it.
		CHECK_EQ(CountMnem(dis, "bzhi"), 0u);
		CHECK_EQ(CountMnem(dis, "kmovw"), 0u);
		fprintf(stderr, "    %-10s seeds %u (%s)\n", r.name, seeds, r.why);
	}
	// Both directions were exercised: a predicate that always returned true or always false
	// would fail above, and this pins that the table itself is not one-sided.
	CHECK(elidable_seen >= 2 && kept_seen >= 2);
}

void Section4_RejectedFramesAreByteIdentical()
{
	fprintf(stderr, "[4] frames the predicate rejects emit identical code\n");
	struct Row { char const *name; std::vector<u32> words; Env off, on; };
	auto env = [](u32 vlen, bool full_vl, bool shared, bool llvm) {
		Env e; e.vlen_bits = vlen; e.full_vl = full_vl; e.shared = shared; e.llvm = llvm;
		return e;
	};
	std::vector<Row> rows;
	// FP-only run: every member's route permits vl < VLMAX, so the run guards vl <= VLMAX
	// (VTypePartialVlVstartFrmRNE). THE PARTIAL-VL CASE.
	rows.push_back({"FP-only run (vl <= VLMAX)",
			{VSETVLI_E32M1, Vv(F6_VFADD, 8, 9, 8), Vv(F6_VFSUB, 8, 9, 10)},
			env(512, false, false, false), env(512, true, false, false)});
	// A single-instruction FP frame: the body handles a non-zero vstart. THE RESTART CASE.
	rows.push_back({"single vfadd.vv frame (body handles vstart)",
			{VSETVLI_E32M1, Vv(F6_VFADD, 8, 9, 8)},
			env(512, false, false, false), env(512, true, false, false)});
	// e64 single instruction: a different route, same rejection.
	rows.push_back({"single vfadd.vv e64 frame", {VSETVLI_E64M1, Vv(F6_VFADD, 8, 9, 8)},
			env(512, false, false, false), env(512, true, false, false)});
	// A masked (vm = 0) guest instruction never reaches an unmasked typed route at all; whatever
	// it lowers to must be unchanged.
	rows.push_back({"masked vfadd.vv (vm = 0)", {VSETVLI_E32M1, VvM(F6_VFADD, 8, 9, 8)},
			env(512, false, false, false), env(512, true, false, false)});
	// No vsetvli: the frame's SEW is resolved at run time, so `lanes` is not a constant.
	rows.push_back({"run-time SEW (no observed vtype)", {Vv(F6_VFADD, 8, 9, 8)},
			env(512, false, false, false), env(512, true, false, false)});
	// An ELIGIBLE guard kind with no FP lane op: proves integer bodies were not disturbed.
	rows.push_back({"integer-only run (eligible kind, no FP op)",
			{VSETVLI_E32M1, Iv(F6_VADD, 1, 2, 8), Iv(F6_VADD, 8, 2, 9)},
			env(512, false, false, false), env(512, true, false, false)});
	// The LLVM backend: QCG-only change.
	rows.push_back({"LLVM backend", MixedRun(Vv(F6_VFADD, 8, 9, 8)),
			env(512, false, false, true), env(512, true, false, true)});
	for (auto const &r : rows) {
		Built a, b;
		Build(a, r.words, r.off);
		Build(b, r.words, r.on);
		CHECK(!a.code.empty());
		CHECK_EQ(a.code.size(), b.code.size());
		bool same = a.code.size() == b.code.size() &&
			    Normalize(Disassemble(a.code)) == Normalize(Disassemble(b.code));
		CHECK(same);
		fprintf(stderr, "    %-42s %zu bytes, identical=%d\n", r.name, a.code.size(),
			(int)same);
	}
}

void Section5_A12Supersession()
{
	fprintf(stderr, "[5] an admitted frame emits the same bytes with the A12 shared masks on "
			"or off\n");
	for (u32 vlen : {512u, 1024u}) {
		std::vector<u32> const words = MixedRun(Vv(F6_VFADD, 8, 9, 8));
		Built noshare, share;
		Build(noshare, words, Env{vlen, /*full_vl=*/true, /*shared=*/false});
		Build(share, words, Env{vlen, /*full_vl=*/true, /*shared=*/true});
		// The frame builds no vchunkmaskset either way: that is the coherence fix. A frame
		// cannot hold a resident k(1+chunk) AND claim its lane ops are unmasked.
		auto fs = FindFrames(share.region);
		CHECK_EQ(fs.size(), (size_t)1);
		if (fs.size() == 1) {
			CHECK_EQ(CountOp(fs[0], Op::_vchunkmaskset), 0u);
			for (auto *i : fs[0].body)
				if (i->GetOpcode() == Op::_vchunkfalu)
					CHECK_EQ((unsigned)static_cast<InstVChunkFALU *>(i)->kmask, 0u);
		}
		CHECK_EQ(noshare.code.size(), share.code.size());
		bool same = noshare.code.size() == share.code.size() &&
			    Normalize(Disassemble(noshare.code)) == Normalize(Disassemble(share.code));
		CHECK(same);
		// and with the switch OFF the A12 masks still appear, so the check above is not
		// passing because A12 never does anything in this shape.
		Built off_share;
		Build(off_share, words, Env{vlen, /*full_vl=*/false, /*shared=*/true});
		auto fo = FindFrames(off_share.region);
		CHECK_EQ(fo.size(), (size_t)1);
		if (fo.size() == 1)
			CHECK_EQ(CountOp(fo[0], Op::_vchunkmaskset), Chunks(vlen));
		fprintf(stderr, "    VLEN %4u: admitted frame identical A12 off/on (%zu bytes); "
				"switch off still builds %u masksets\n",
			vlen, share.code.size(),
			fo.size() == 1 ? CountOp(fo[0], Op::_vchunkmaskset) : 0u);
	}
}

bool DiesInChild(std::function<void()> fn)
{
	fflush(stderr);
	pid_t pid = fork();
	if (pid == 0) {
		freopen("/dev/null", "w", stderr);
		fn();
		_exit(0);
	}
	int st = 0;
	waitpid(pid, &st, 0);
	return !WIFEXITED(st) || WEXITSTATUS(st) != 0;
}

void Section6_CoherencePanic()
{
	fprintf(stderr, "[6] a shared lane mask inside an admitted frame is a translation failure\n");
	// The incoherent state is produced the only way it can be: translate with the switch OFF and
	// the A12 shared masks ON, so the frame really does carry vchunkmaskset nodes, then flip the
	// switch before emitting. QEmit now considers the frame admitted -- the exact disagreement
	// between the two passes the design has to rule out -- and the result would be a lane op that
	// claims to be unmasked while a mask register was written for it.
	auto translate_shared_then_emit = [](bool full_vl_at_emit) {
		Built b;
		Translate(b, MixedRun(Vv(F6_VFADD, 8, 9, 8)),
			  Env{512, /*full_vl=*/false, /*shared=*/true});
		config::rvv_qcg_full_vl_fast_body = full_vl_at_emit;
		Emit(b);
	};
	CHECK(DiesInChild([&] { translate_shared_then_emit(true); }));
	// The negative control: the same translation, emitted with the switch off, must succeed --
	// otherwise the Panic above could be firing for an unrelated reason.
	CHECK(!DiesInChild([&] { translate_shared_then_emit(false); }));
	// And the coherent admitted frame (translated AND emitted with the switch on) emits.
	CHECK(!DiesInChild([] {
		Built b;
		Build(b, MixedRun(Vv(F6_VFADD, 8, 9, 8)), Env{512, /*full_vl=*/true, /*shared=*/true});
	}));
	fprintf(stderr, "    incoherent frame refused; both controls emit\n");
}

} // namespace

int main()
{
	printf("rvv_full_vl_fast_body_test\n");
	Section1_GuardEligibility();
	Section2_EmittedCode();
	Section3_SeedDiscrimination();
	Section4_RejectedFramesAreByteIdentical();
	Section5_A12Supersession();
	Section6_CoherencePanic();
	if (g_failures) {
		fprintf(stderr, "FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("OK\n");
	return 0;
}
