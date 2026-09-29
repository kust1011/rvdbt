// R1A.3b: the QCG code generator for a multi-member vector run (VRUN), and its correctness closure.
//
// WHAT THIS FILE HAS TO PROVE, AND WHY EACH SECTION EXISTS
//
//   [1] FLAG OFF CHANGES NO GENERATED CODE. Not a self-comparison: the goldens below are pinned
//       normalized disassemblies captured from the ACCEPTED R1A.3a tree (commit 8ce794a87) with
//       production source unmodified, and preserved in the checkpoint's raw/ directory. If any
//       R1A.3b change perturbed the flag-off path, these hashes move.
//
//   [2] ONE FRAME, GENERIC IN THE OPERATIONS. All 36 ordered pairs over the six accepted typed
//       integer ALU routes, at both VLENs, become ONE guarded frame whose shape depends only on the
//       run's dataflow -- never on which pair it is. Three named pairs are additionally pinned
//       against the descriptor the admission scan produced for the same words. If the codegen
//       contained an opcode-pair special case, 34 of the 36 would differ.
//
//   [3] COMPONENT SSA ACROSS THE GUEST INSTRUCTION BOUNDARY. The second member's source OPERAND is
//       the first member's destination VALUE -- the same allocated register, not a reload. This is
//       the property R1A.0 measured as missing, and it is asserted on the QIR def-use graph and
//       again on the emitted registers, not inferred from instruction counts.
//
//   [4] NO SPILL AND NO ALLOCATOR MOVE INSIDE THE GUARDED BODY, after the REAL QSel + QRegAlloc
//       passes. A spill inside an open group is a Panic (qir.h), not a slowdown, so this is a
//       correctness property of the admission bound rather than a quality metric.
//
//   [5] THE EMITTED CODE ITSELF, read back from objdump:
//         * exactly ONE guard -- three compares, all jumping to the SAME fallback label, and every
//           vector instruction of the body before that label, so the guard covers the whole run;
//         * exactly `|live_in| * k` ZMM loads at the live-in windows and `|live_out| * k` ZMM
//           stores at the final live-out windows, and NOTHING between two members' lane operations;
//         * the fast arm leaves the LAST member's guest PC before the join;
//         * the fallback arm calls the members' original helpers IN GUEST ORDER, each preceded by
//           a store of THAT member's guest PC.
//
//   [6] EVERY ARCHITECTURALLY LEGAL OPERAND OVERLAP, plus a run whose second member overwrites the
//       first member's destination -- where the intermediate value must never reach CPUState.
//
//   [7] THE TRANSLATOR CONSUMES EXACTLY THE ADMITTED MEMBERS: no more (a barrier splits the run),
//       no fewer (an odd tail keeps its own single-member frame), and never under the LLVM backend.
//
// SCOPE. Correctness and mechanism only. Nothing here is timed and nothing here supports a
// performance claim; the end-to-end execution evidence lives in the checkpoint's xbd package.
//
// HOST NOTE. This file never executes what it emits, so the six QCG routes' AVX-512F admission
// probes are bypassed with their audit `force-emit` switches and the codegen is exercised on hosts
// without AVX-512. The xbd execution package uses NO force-emit switch anywhere.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_decode.h"
#include "dbt/guest/rv32_lane_region_bridge.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_printer.h"

#include <algorithm>
#include <map>
#include <set>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;
namespace rvvrun = dbt::rv32::rvvrun;
using rvvrun::RunOp;

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
		auto _b = (b);                                                                               \
		if (!(_a == _b)) {                                                                           \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,    \
				#b, (long long)_a, (long long)_b);                                           \
			++g_failures;                                                                        \
		}                                                                                            \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Instruction words. Every constant was produced by assembling the mnemonic with the xPack GNU
// RISC-V toolchain (riscv-none-elf-gcc 14.2.0, -march=rv32imafdv) and reading the encoding back out
// of `objdump -d`; the listings are preserved under the checkpoint's raw/ directory.
// ---------------------------------------------------------------------------------------------
constexpr u32 W_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0,a0,e32,m1,ta,ma
constexpr u32 W_VADD_V3_V1_V2 = 0x021101d7u; // vadd.vv v3,v1,v2
constexpr u32 W_VSUB_V4_V3_V2 = 0x0a310257u; // vsub.vv v4,v3,v2
constexpr u32 W_VMUL_V5_V3_V4 = 0x963222d7u; // vmul.vv v5,v3,v4
constexpr u32 W_VXOR_V6_V5_V4 = 0x2e520357u; // vxor.vv v6,v5,v4
constexpr u32 W_VOR_V7_V6_V5 = 0x2a6283d7u;  // vor.vv  v7,v6,v5
constexpr u32 W_VAND_V8_V7_V6 = 0x26730457u; // vand.vv v8,v7,v6
constexpr u32 W_VADD_V3_V3_V2 = 0x023101d7u; // vadd.vv v3,v3,v2   (vd == vs2)
constexpr u32 W_VSUB_V3_V3_V2 = 0x0a3101d7u; // vsub.vv v3,v3,v2   (vd == vs2)
constexpr u32 W_VADD_V3_V1_V3 = 0x021181d7u; // vadd.vv v3,v1,v3   (vd == vs1)
constexpr u32 W_VADD_V3_V3_V3 = 0x023181d7u; // vadd.vv v3,v3,v3   (vd == vs1 == vs2)
constexpr u32 W_VADD_V3_V1_V1 = 0x021081d7u; // vadd.vv v3,v1,v1   (vs1 == vs2)
constexpr u32 W_OP_ADD = 0x021101d7u;	     // vadd.vv v3,v1,v2
constexpr u32 W_OP_SUB = 0x0a1101d7u;	     // vsub.vv v3,v1,v2
constexpr u32 W_OP_MUL = 0x961121d7u;	     // vmul.vv v3,v1,v2
constexpr u32 W_OP_XOR = 0x2e1101d7u;	     // vxor.vv v3,v1,v2
constexpr u32 W_OP_OR = 0x2a1101d7u;	     // vor.vv  v3,v1,v2
constexpr u32 W_OP_AND = 0x261101d7u;	     // vand.vv v3,v1,v2
constexpr u32 W_VLE32 = 0x0205e087u;	     // vle32.v v1,(a1)
// The THREE SEQUENCES R1A.3c registered, with their exact dataflow: `op1 v3,v1,v2` then
// `op2 v4,v3,v5`. The second member's OTHER source is v5, a register the run does not produce, so
// the run's live-in is {v1,v2,v5} and the component-SSA body loads 3k chunks where the
// materializing body loads 4k -- which is what makes B - C exactly k. Reusing v2 there instead
// (as the shape-only cases above do) makes it 2k, and would not be the registered sequence.
constexpr u32 W_VSUB_V4_V3_V5 = 0x0a328257u; // vsub.vv v4,v3,v5
constexpr u32 W_VXOR_V4_V3_V5 = 0x2e328257u; // vxor.vv v4,v3,v5
constexpr u32 W_VAND_V4_V3_V5 = 0x26328257u; // vand.vv v4,v3,v5
constexpr u32 W_ADDI = 0x00150513u;	     // addi a0,a0,1

constexpr u32 ST_VREG_BASE = (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
constexpr u32 ST_IP = (u32)offsetof(CPUState, ip);
// The guard's first compare reads this. FirstGuardIndex below used to look for the literal
// `[r13+0x10d0]`, which was this offset while VLEN_MAX was 1024 and silently stopped being it when
// HM.2a raised the reservation to 4096: the helper then found no guard, returned insns.size(), and
// made "the prologue is identical across arms" compare whole functions instead of prologues.
// Derived from the declaration for the same reason ST_IP and ChunkOffs are.
constexpr u32 ST_VTYPE =
    (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vtype));

constexpr u32 ChunkOffs(u32 reg, u32 chunk)
{
	return ST_VREG_BASE + reg * dbt::rv32::VLEN_MAX_BYTES + chunk * 64u;
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint align) override
	{
		if (shared_buf) {
			shared_buf->resize(sz);
			return shared_buf->data();
		}
		buf.resize(sz);
		return buf.data();
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	{
		return nullptr;
	}
	std::vector<u8> buf;
	std::vector<u8> *shared_buf = nullptr;
};

// Every knob any admission predicate or emitter reads, set on EVERY translation so no case can
// inherit another's global state.
// R1A.3d body mode and research-counter state for the next ApplyConfig. Defaulted to the ACCEPTED
// behaviour (component SSA, counter emitted), so every pre-R1A.3d check in this file keeps testing
// exactly what it tested before without being touched.
bool g_body_materialize = false;
bool g_hit_counter = true;
bool g_lane_census = false;
// P6C issue-order arm for the next ApplyConfig. Defaulted to the ACCEPTED order (member-major), so
// every check written before P6C keeps testing exactly what it tested before without being touched.
bool g_run_order_chunk_major = false;
// P6C-R (2026-09-10). THE EXTENDED MEMBER FAMILIES, opt-in, default OFF.
//
// The five member kinds the issue-order switch used to refuse at admission -- MulX, MAccX,
// LoadWhole, StoreWhole and Mov -- plus the two FP kinds are each behind their OWN route switch,
// and none of those switches is enabled by the accepted ApplyConfig above. That is exactly why the
// pre-repair `[P6C-1]` gate could never fail: every word it enumerated took a switch arm that does
// not read the order flag, so the assertion was vacuous for the rows that actually broke.
// Enabling them unconditionally would move this file's pinned goldens, so the extension is a flag:
// with it false every pre-existing check translates under byte-for-byte the configuration it was
// written against, and the extended checks turn it on for themselves.
bool g_run_extended_families = false;
// P7M-E frame-census arm for the next ApplyConfig. Default OFF, which is what makes every check
// written before it -- including the pinned flag-off goldens -- translate under byte-for-byte the
// configuration it was written against.
bool g_frame_census = false;
// P7L-B1-SPLIT arms for the next ApplyConfig. All default OFF, so every check written before this
// section translates under byte-for-byte the configuration it was written against.
bool g_live_split = false;
unsigned g_probe_depth = 0;
bool g_probe_cross = false;
// The values a fresh process starts with, captured in main() before any test runs.
bool g_startup_body_materialize = true;
bool g_startup_hit_counter = false;
bool g_startup_run_order_chunk_major = true;

void ApplyConfig(u32 vlen_bits, bool vector_run)
{
	config::rvv_vector_run = vector_run;
	config::rvv_lane_census = g_lane_census;
	config::rvv_lane_census_out = nullptr;
	config::rvv_run_body_materialize = g_body_materialize;
	config::rvv_run_order_chunk_major = g_run_order_chunk_major;
	config::rvv_qcg_hit_counter = g_hit_counter;
	config::rvv_run_frame_census = g_frame_census; // P7M-E
	config::rvv_run_live_range_split = g_live_split;   // P7L-B1-SPLIT
	config::rvv_run_dep_probe_depth = g_probe_depth;
	config::rvv_run_dep_probe_cross = g_probe_cross;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::vlen_bits = vlen_bits;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_mul = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_and = true;
	config::rvv_qcg_typed_chunk_vle = true;
	config::rvv_qcg_typed_chunk_vse = true;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_sub_force_emit = true;
	config::rvv_qcg_typed_chunk_mul_force_emit = true;
	config::rvv_qcg_typed_chunk_xor_force_emit = true;
	config::rvv_qcg_typed_chunk_or_force_emit = true;
	config::rvv_qcg_typed_chunk_and_force_emit = true;
	config::rvv_qcg_typed_chunk_vle_force_emit = true;
	config::rvv_qcg_typed_chunk_vse_force_emit = true;
	config::rvv_qcg_diag_chunk = false;
	// P6C-R: set on EVERY call in both directions, so no section can inherit another's value --
	// the same hermetic-state rule the block above follows. `false` reproduces the accepted
	// configuration exactly, because each of these defaults to false in config.h and nothing else
	// in this file writes them.
	config::rvv_qcg_typed_chunk_vmv = g_run_extended_families;
	config::rvv_qcg_typed_chunk_vmv_force_emit = g_run_extended_families;
	config::rvv_qcg_whole_reg = g_run_extended_families;
	config::rvv_qcg_whole_reg_force_emit = g_run_extended_families;
	config::rvv_qcg_vx_mulacc = g_run_extended_families;
	config::rvv_qcg_vx_mulacc_force_emit = g_run_extended_families;
	config::rvv_qcg_typed_chunk_falu = g_run_extended_families;
	config::rvv_qcg_typed_chunk_falu_force_emit = g_run_extended_families;
	config::rvv_qcg_typed_chunk_fma = g_run_extended_families;
	config::rvv_qcg_typed_chunk_fma_force_emit = g_run_extended_families;
}

// FNV-1a 64. Self-contained and stable; the point is only that a difference changes it.
u64 Fnv1a(std::string const &s)
{
	u64 h = 1469598103934665603ull;
	for (unsigned char x : s) {
		h ^= x;
		h *= 1099511628211ull;
	}
	return h;
}

// Write `code` to a private temp file and disassemble it as a raw flat x86-64 binary with GNU
// objdump. Fails loudly rather than skipping: a missing disassembler means this checkpoint's
// emission evidence cannot be produced at all. (Same helper the six accepted route tests use.)
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_r1a3b_emit_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "  mkstemp failed: %s\n", strerror(errno));
		return {};
	}
	size_t written = 0;
	while (written < code.size()) {
		ssize_t const n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) {
			fprintf(stderr, "  write to temp file failed: %s\n", strerror(errno));
			close(fd);
			unlink(path);
			return {};
		}
		written += (size_t)n;
	}
	close(fd);

	std::string const cmd =
	    std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path +
	    " 2>&1";
	FILE *p = popen(cmd.c_str(), "r");
	if (!p) {
		fprintf(stderr, "  popen(objdump) failed: %s\n", strerror(errno));
		unlink(path);
		return {};
	}
	std::vector<std::string> lines;
	char buf[1024];
	std::string cur;
	while (fgets(buf, sizeof(buf), p)) {
		cur += buf;
		if (!cur.empty() && cur.back() == '\n') {
			cur.pop_back();
			lines.push_back(cur);
			cur.clear();
		}
	}
	if (!cur.empty()) {
		lines.push_back(cur);
	}
	int const rc = pclose(p);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
		fprintf(stderr, "  objdump did not exit cleanly (raw status %d)\n", rc);
		return {};
	}
	return lines;
}

// THE FLAG-OFF GOLDEN IS NORMALIZED DISASSEMBLY, NOT RAW BYTES, and that is forced by the emitter
// rather than chosen for convenience: in jit_mode QEmit::make_stubcall_target embeds the ABSOLUTE
// runtime address of the helper stub (`asmjit::imm(stub_tab[stub])`), so the same translation
// produces different bytes in two processes under ASLR. Normalizing hex literals of six or more
// digits removes exactly those addresses and nothing else -- every mnemonic, every register number,
// every CPUState displacement (all far below 0x100000) and every intra-blob branch target survives,
// which is the level at which "the generated code is unchanged" is a meaningful claim.
std::string NormalizedDisasm(std::vector<std::string> const &lines, unsigned *n_lines)
{
	std::string out;
	unsigned n = 0;
	for (auto const &line : lines) {
		auto const tab = line.find('\t');
		if (tab == std::string::npos)
			continue; // objdump header / blank
		std::string body = line.substr(tab + 1);
		std::string norm;
		for (size_t i = 0; i < body.size();) {
			if (body.compare(i, 2, "0x") == 0) {
				size_t j = i + 2;
				while (j < body.size() && isxdigit((unsigned char)body[j]))
					++j;
				if (j - i - 2 >= 6) {
					norm += "0xABS";
					i = j;
					continue;
				}
			}
			norm += body[i++];
		}
		out += norm;
		out += '\n';
		++n;
	}
	if (n_lines)
		*n_lines = n;
	return out;
}

// The same normalisation, plus every `[r13+0x...]` CPUState displacement collapsed.
//
// WHY IT EXISTS (HM.2a). The hashes below pin the flag-off generated code against the accepted
// R1A.3a tree. Raising VLEN_MAX from 1024 to 4096 grows the `vreg` slot from 128 to 512 bytes, so
// every state displacement in that code moves and every one of those hashes moves with it -- for a
// reason that has nothing to do with what the goldens are meant to protect.
//
// Re-pinning alone would replace a checked claim with an unchecked one. This second hash is what
// keeps it checked: it is invariant under any CPUState layout change, so an identical value on the
// old tree and the new one says the instruction sequence, the register allocation, the immediates
// and the control flow are unchanged and ONLY the displacements moved. The values in
// `hash_nodisp` below were harvested from a scratch build of the parent commit `13d8b17bd` and
// then required, unchanged, here.
std::string NormalizedDisasmNoDisp(std::vector<std::string> const &lines, unsigned *n_lines)
{
	std::string const src = NormalizedDisasm(lines, n_lines);
	std::string out;
	static std::string const pfx = "[r13+0x";
	for (size_t i = 0; i < src.size();) {
		if (src.compare(i, pfx.size(), pfx) == 0) {
			size_t j = i + pfx.size();
			while (j < src.size() && isxdigit((unsigned char)src[j]))
				++j;
			if (j < src.size() && src[j] == ']') {
				out += "[r13+DISP]";
				i = j + 1;
				continue;
			}
		}
		out += src[i++];
	}
	return out;
}

// One translated region plus the host code the real backend emitted for it.
struct Built {
	MemArena arena{1u << 20};
	std::vector<u32> words;
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
	std::vector<std::string> lines;
};

void Build(Built &b, std::vector<u32> const &words, u32 vlen_bits, bool vector_run, bool emit = true)
{
	ApplyConfig(vlen_bits, vector_run);
	b.words = words;
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	if (!emit)
		return;
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
	b.lines = Disassemble(b.code);
}

// ---------------------------------------------------------------------------------------------
// QIR frame view
// ---------------------------------------------------------------------------------------------

struct Frame {
	InstRVVTypedChunkBegin *begin = nullptr;
	InstRVVTypedChunkEnd *end = nullptr;
	std::vector<Inst *> body; // strictly between begin and end, in construction order
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

bool IsAluChunkOp(Op op)
{
	return op == Op::_vchunkadd || op == Op::_vchunksub || op == Op::_vchunkmul ||
	       op == Op::_vchunkxor || op == Op::_vchunkor || op == Op::_vchunkand;
}

Op AluOpFor(RunOp op)
{
	switch (op) {
	case RunOp::Add:
		return Op::_vchunkadd;
	case RunOp::Sub:
		return Op::_vchunksub;
	case RunOp::Mul:
		return Op::_vchunkmul;
	case RunOp::Xor:
		return Op::_vchunkxor;
	case RunOp::Or:
		return Op::_vchunkor;
	case RunOp::And:
		return Op::_vchunkand;
	case RunOp::None:
		break;
	}
	// No chunk op corresponds to RunOp::None; Count can never equal a real opcode, which makes a
	// missing row a failed comparison rather than a silent match.
	return Op::Count;
}

char const *HostMnemFor(RunOp op)
{
	switch (op) {
	case RunOp::Add:
		return "vpaddd";
	case RunOp::Sub:
		return "vpsubd";
	case RunOp::Mul:
		return "vpmulld";
	case RunOp::Xor:
		return "vpxord";
	case RunOp::Or:
		return "vpord";
	case RunOp::And:
		return "vpandd";
	case RunOp::None:
		break;
	}
	return "?";
}

// Every typed body op carries its V512 operands in the same two slots, so one accessor serves the
// whole family and no per-opcode branch is needed to read the def-use graph.
void ForEachV512Operand(Inst *ins, void (*fn)(void *, VOperand, bool is_def), void *ctx)
{
	auto const op = ins->GetOpcode();
	if (op == Op::_vstatechunkload) {
		fn(ctx, static_cast<InstVStateChunkLoad *>(ins)->o(0), true);
		return;
	}
	if (op == Op::_vstatechunkstore) {
		fn(ctx, static_cast<InstVStateChunkStore *>(ins)->i(0), false);
		return;
	}
	if (IsAluChunkOp(op)) {
		auto *w = static_cast<InstWithOperands<1, 2> *>(ins);
		fn(ctx, w->o(0), true);
		fn(ctx, w->i(0), false);
		fn(ctx, w->i(1), false);
	}
}

// ---------------------------------------------------------------------------------------------
// Disassembly line records
// ---------------------------------------------------------------------------------------------

struct Line {
	u64 addr = 0;
	std::string mnem;
	std::string ops;
};

std::vector<Line> ParseLines(std::vector<std::string> const &raw)
{
	std::vector<Line> out;
	for (auto const &l : raw) {
		auto const tab = l.find('\t');
		if (tab == std::string::npos)
			continue;
		std::string const head = l.substr(0, tab);
		auto const colon = head.find(':');
		if (colon == std::string::npos)
			continue;
		Line rec;
		rec.addr = strtoull(head.c_str(), nullptr, 16);
		std::string body = l.substr(tab + 1);
		size_t i = 0;
		while (i < body.size() && body[i] == ' ')
			++i;
		size_t const sp = body.find(' ', i);
		rec.mnem = body.substr(i, sp == std::string::npos ? std::string::npos : sp - i);
		if (sp != std::string::npos) {
			size_t j = sp;
			while (j < body.size() && body[j] == ' ')
				++j;
			rec.ops = body.substr(j);
		}
		// objdump prints "rex call TARGET" when the call carries a redundant REX prefix.
		if (rec.mnem == "rex") {
			size_t j = 0;
			while (j < rec.ops.size() && rec.ops[j] != ' ')
				++j;
			std::string const m = rec.ops.substr(0, j);
			while (j < rec.ops.size() && rec.ops[j] == ' ')
				++j;
			rec.ops = rec.ops.substr(j);
			rec.mnem = m;
		}
		out.push_back(rec);
	}
	return out;
}

// "DWORD PTR [r13+0xNN],0xMM" -> (disp, imm). Anything else is not a state-slot immediate store.
bool ParseStateImmStore(Line const &l, u32 *disp, u64 *imm)
{
	if (l.mnem != "mov")
		return false;
	static std::string const pre = "DWORD PTR [r13+0x";
	if (l.ops.size() <= pre.size() || l.ops.compare(0, pre.size(), pre) != 0)
		return false;
	size_t i = pre.size();
	u32 d = 0;
	size_t const start = i;
	for (; i < l.ops.size() && isxdigit((unsigned char)l.ops[i]); ++i) {
		char const c = (char)tolower((unsigned char)l.ops[i]);
		d = d * 16 + (u32)(c <= '9' ? c - '0' : c - 'a' + 10);
	}
	if (i == start || i + 2 >= l.ops.size() || l.ops[i] != ']' || l.ops[i + 1] != ',')
		return false;
	if (l.ops.compare(i + 2, 2, "0x") != 0 && !isdigit((unsigned char)l.ops[i + 2]))
		return false;
	*disp = d;
	*imm = strtoull(l.ops.c_str() + i + 2, nullptr, 0);
	return true;
}

enum class VecKind { None, Load, Store, Alu };

struct VecOp {
	VecKind kind = VecKind::None;
	std::string mnem;
	unsigned d = 0, s0 = 0, s1 = 0;
	u32 disp = 0;
	u64 addr = 0;
};

bool ParseZmm(std::string const &tok, unsigned *out)
{
	if (tok.size() < 4 || tok.compare(0, 3, "zmm") != 0)
		return false;
	size_t i = 3;
	if (!isdigit((unsigned char)tok[i]))
		return false;
	unsigned v = 0;
	while (i < tok.size() && isdigit((unsigned char)tok[i]))
		v = v * 10 + (unsigned)(tok[i++] - '0');
	*out = v;
	return i == tok.size();
}

bool ParseZmmWordR13(std::string const &tok, u32 *disp)
{
	static std::string const pre = "ZMMWORD PTR [r13+0x";
	if (tok.size() <= pre.size() || tok.compare(0, pre.size(), pre) != 0)
		return false;
	size_t i = pre.size();
	size_t const start = i;
	u32 d = 0;
	for (; i < tok.size() && isxdigit((unsigned char)tok[i]); ++i) {
		char const c = (char)tolower((unsigned char)tok[i]);
		d = d * 16 + (u32)(c <= '9' ? c - '0' : c - 'a' + 10);
	}
	if (i == start || i + 1 != tok.size() || tok[i] != ']')
		return false;
	*disp = d;
	return true;
}

std::vector<std::string> SplitOps(std::string const &s)
{
	std::vector<std::string> out;
	size_t i = 0;
	while (true) {
		size_t const c = s.find(',', i);
		size_t const end = c == std::string::npos ? s.size() : c;
		std::string tok = s.substr(i, end - i);
		size_t const a = tok.find_first_not_of(' ');
		size_t const b = tok.find_last_not_of(' ');
		out.push_back(a == std::string::npos ? "" : tok.substr(a, b - a + 1));
		if (c == std::string::npos)
			break;
		i = c + 1;
	}
	return out;
}

// Every line that mentions a ZMM must parse into one of the three shapes a typed frame can contain.
// A ZMM line this does not recognise is a HARD FAILURE, which is what makes "there is no allocator
// move and no spill inside the body" an assertion rather than an absence of evidence.
bool ParseVec(Line const &l, VecOp *out)
{
	if (l.ops.find("zmm") == std::string::npos)
		return false;
	auto const ops = SplitOps(l.ops);
	VecOp v;
	v.mnem = l.mnem;
	v.addr = l.addr;
	if (l.mnem == "vmovdqu64" && ops.size() == 2) {
		unsigned z;
		u32 d;
		if (ParseZmm(ops[0], &z) && ParseZmmWordR13(ops[1], &d)) {
			v.kind = VecKind::Load;
			v.d = z;
			v.disp = d;
			*out = v;
			return true;
		}
		if (ParseZmmWordR13(ops[0], &d) && ParseZmm(ops[1], &z)) {
			v.kind = VecKind::Store;
			v.s0 = z;
			v.disp = d;
			*out = v;
			return true;
		}
		return false;
	}
	if (ops.size() == 3) {
		unsigned d, s0, s1;
		if (ParseZmm(ops[0], &d) && ParseZmm(ops[1], &s0) && ParseZmm(ops[2], &s1)) {
			v.kind = VecKind::Alu;
			v.d = d;
			v.s0 = s0;
			v.s1 = s1;
			*out = v;
			return true;
		}
	}
	return false;
}

struct Emitted {
	std::vector<Line> lines;
	// Only the `jne`s that belong to the FRAME's guard: each one immediately follows a compare
	// against one of the three guarded CPUState::vec fields. A region also contains unrelated
	// `jne`s (the tail dispatch's cache probe), and counting those would make "one guard" mean
	// nothing.
	std::vector<u64> jne_targets;
	std::vector<VecOp> vecs;
	std::vector<std::pair<u32, u64>> imm_stores;
	std::vector<u64> call_addrs;
};

Emitted ReadEmitted(Built &b)
{
	Emitted e;
	e.lines = ParseLines(b.lines);
	static u32 const guarded[] = {
	    (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vtype)),
	    (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vl)),
	    (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vstart)),
	};
	bool prev_is_guard_cmp = false;
	for (auto const &l : e.lines) {
		if (l.mnem == "jne" && prev_is_guard_cmp)
			e.jne_targets.push_back(strtoull(l.ops.c_str(), nullptr, 0));
		{
			u32 d;
			u64 v;
			Line as_cmp = l;
			as_cmp.mnem = "mov"; // ParseStateImmStore only differs by the mnemonic name
			prev_is_guard_cmp = false;
			if (l.mnem == "cmp" && ParseStateImmStore(as_cmp, &d, &v))
				for (u32 g : guarded)
					prev_is_guard_cmp |= d == g;
		}
		VecOp v;
		if (ParseVec(l, &v)) {
			e.vecs.push_back(v);
		} else if (l.ops.find("zmm") != std::string::npos) {
			fprintf(stderr, "  FAIL unparsed ZMM line at %#llx: %s %s\n",
				(unsigned long long)l.addr, l.mnem.c_str(), l.ops.c_str());
			++g_failures;
		}
		u32 disp;
		u64 imm;
		if (ParseStateImmStore(l, &disp, &imm))
			e.imm_stores.push_back({disp, imm});
		if (l.mnem == "call")
			e.call_addrs.push_back(l.addr);
	}
	return e;
}

// ---------------------------------------------------------------------------------------------
// [1] Flag-off goldens, pinned from the accepted R1A.3a tree.
// ---------------------------------------------------------------------------------------------

struct GoldenRow {
	char const *name;
	std::vector<u32> words;
	u32 vlen;
	size_t bytes;
	unsigned lines;
	u64 hash;	 // pinned against THIS tree's CPUState layout
	u64 hash_nodisp; // pinned against the parent commit's; layout-invariant
};

std::vector<GoldenRow> Goldens()
{
	std::vector<u32> const add_sub = {W_VSETVLI_E32M1, W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2};
	std::vector<u32> const mul_xor = {W_VSETVLI_E32M1, W_VMUL_V5_V3_V4, W_VXOR_V6_V5_V4};
	std::vector<u32> const or_and = {W_VSETVLI_E32M1, W_VOR_V7_V6_V5, W_VAND_V8_V7_V6};
	std::vector<u32> const six = {W_VSETVLI_E32M1, W_OP_ADD, W_OP_SUB, W_OP_MUL,
				      W_OP_XOR,	      W_OP_OR,	W_OP_AND};
	std::vector<u32> const with_mem = {W_VSETVLI_E32M1, W_VADD_V3_V1_V2, W_VLE32, W_OP_ADD};
	std::vector<u32> const no_setvli = {W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2};
	std::vector<u32> const overlap = {W_VSETVLI_E32M1, W_VADD_V3_V3_V2, W_VSUB_V3_V3_V2};
	std::vector<u32> const scalar = {W_ADDI, W_ADDI, W_ADDI};
	// HM.2a RE-PINNED THE `hash` COLUMN AND ONLY THAT COLUMN. Raising VLEN_MAX from 1024 to 4096
	// moved every CPUState displacement in this code, so 14 of the 16 literal hashes moved with
	// it; the two `scalar only` rows did not, because they touch no vector register, which is the
	// first corroboration that the cause is the layout and not the code.
	//
	// `bytes`, `lines` and `hash_nodisp` were NOT re-pinned: they carried over from the parent
	// commit `13d8b17bd` unchanged, harvested from a scratch build of it with this same file.
	// Identical byte counts, identical line counts and an identical displacement-invariant hash
	// together say the instruction sequence, register allocation, immediates and control flow are
	// the same code, relabelled. That is the claim the `hash` column was protecting, and it is
	// still checked -- by `hash_nodisp` -- rather than replaced by a fresh unchecked number.
	//
	// `overlap chain` sharing `add;sub`'s nodisp hash, and the two `scalar only` rows sharing one
	// at both widths, are both expected: the first differs from add;sub only in which registers
	// the displacements name, and the second emits no width-dependent code at all.
	return {
	    {"add;sub", add_sub, 512, 416u, 64u, 0x8a3f1ba968213a7bull, 0xbb40172cbbe58730ull},
	    {"add;sub", add_sub, 1024, 488u, 72u, 0x0dc21a369eac1ac9ull, 0xec6549fc11bc008eull},
	    {"mul;xor", mul_xor, 512, 424u, 63u, 0xf3783699ff16e3e7ull, 0x4995a880aff40ba7ull},
	    {"mul;xor", mul_xor, 1024, 496u, 71u, 0x94b9af39e1c3a6e7ull, 0x2cb32a6fd2355728ull},
	    {"or;and", or_and, 512, 416u, 64u, 0x4156d3a3781aab04ull, 0x46991404a4a325c7ull},
	    {"or;and", or_and, 1024, 488u, 72u, 0xdc2c8ed655d7f50full, 0x352cd8230c411e3eull},
	    {"six ops", six, 512, 928u, 133u, 0xd6646e36c43df63cull, 0x3c6b5b6f930eb1e5ull},
	    {"six ops", six, 1024, 1144u, 157u, 0x7bfde7e97d68dc92ull, 0xa5a1d2109ea5294full},
	    // A13-FIX (2026-09-05): the vle32.v frame in this kernel now carries the base-range guard
	    // (`mov eax,[r13+gpr]; cmp eax,2^32-VLEN/8; ja fallback`, +16 bytes / +1 line at 512, +8
	    // bytes / +4 lines at 1024), so these two rows were RE-PINNED from the fixed tree; the
	    // pre-A13-FIX bytes (528/81, 624/90 and the hashes 0xf41d90cbafac7c1c / 0x4ae0180549aceb33,
	    // 0xee03fcbb1c3981f6 / 0xa0862f9371876d89) carried a host-pointer window that could leave
	    // the guest space and were deliberately not preserved. The other rows are unchanged.
	    {"add;vle;add", with_mem, 512, 544u, 82u, 0xe6242c695e058389ull, 0xc7e89f556cb9ccaaull},
	    {"add;vle;add", with_mem, 1024, 632u, 94u, 0xebe23dbe9c97d414ull, 0x118928ba924d8b7bull},
	    {"no vsetvli add;sub", no_setvli, 512, 344u, 53u, 0x77d09eb08e5391baull,
	     0xfebe10e6fb44e4d2ull},
	    {"no vsetvli add;sub", no_setvli, 1024, 416u, 61u, 0xdcf252606ec22d40ull,
	     0x09237025ccea7f9cull},
	    {"overlap chain", overlap, 512, 416u, 64u, 0xd4ab68023d85bfc5ull, 0xbb40172cbbe58730ull},
	    {"overlap chain", overlap, 1024, 488u, 72u, 0xfc3056abfe9f23b9ull, 0xec6549fc11bc008eull},
	    {"scalar only", scalar, 512, 112u, 22u, 0x7adb91d6d25b35a8ull, 0x79649824b01d18f4ull},
	    {"scalar only", scalar, 1024, 112u, 22u, 0x7adb91d6d25b35a8ull, 0x79649824b01d18f4ull},
	};
}

void CheckFlagOffGoldens()
{
	printf("[1] flag off: generated code identical to the accepted R1A.3a tree (8ce794a87) up to "
	       "CPUState displacements\n");
	for (auto const &g : Goldens()) {
		Built b;
		Build(b, g.words, g.vlen, /*vector_run=*/false);
		unsigned n = 0, n2 = 0;
		auto const norm = NormalizedDisasm(b.lines, &n);
		u64 const h = Fnv1a(norm);
		u64 const h2 = Fnv1a(NormalizedDisasmNoDisp(b.lines, &n2));
		CHECK_EQ(b.code.size(), g.bytes);
		CHECK_EQ(n, g.lines);
		CHECK_EQ(n2, g.lines);
		CHECK_EQ(h, g.hash);
		// The layout-invariant half. Byte count, line count and this hash all carried over
		// from the parent commit unchanged, which is what makes the moved `hash` above a
		// displacement relabelling rather than a code change.
		CHECK_EQ(h2, g.hash_nodisp);
		// Structural half of the same claim: with the switch off no frame may cover more than
		// one guest instruction, whatever the hash says.
		for (auto const &f : FindFrames(b.region)) {
			CHECK_EQ((unsigned)f.begin->n_members, 1u);
			CHECK_EQ((unsigned)f.end->n_members, 1u);
		}
		printf("    ok  %-20s vlen=%-4u %4zu bytes %3u lines %#018llx nodisp=%#018llx\n",
		       g.name, g.vlen, b.code.size(), n, (unsigned long long)h,
		       (unsigned long long)h2);
	}
}

void CheckLaneCensusCodegenInvisible()
{
	printf("[T7g] analysis-only lane census changes no QIR or generated byte\n");
	std::vector<u32> const words = {W_VSETVLI_E32M1, W_OP_ADD, W_OP_SUB, W_OP_MUL,
					W_OP_XOR, W_OP_OR, W_OP_AND, W_ADDI};
	for (u32 const vlen : {512u, 1024u}) {
		dbt::rv32::lane_region_bridge::Reset();
		// QCG has address-sensitive relative calls, so both arms must use the same backing
		// address for a meaningful raw-byte comparison. The saved `off.code` remains private.
		std::vector<u8> same_code_address;
		same_code_address.reserve(4096);
		g_lane_census = false;
		Built off;
		off.cr.shared_buf = &same_code_address;
		Build(off, words, vlen, /*vector_run=*/false);
		auto const off_qir = qir::PrinterPass::run(off.region);

		g_lane_census = true;
		Built on;
		on.cr.shared_buf = &same_code_address;
		Build(on, words, vlen, /*vector_run=*/false);
		auto const on_qir = qir::PrinterPass::run(on.region);
		g_lane_census = false;

		CHECK(off_qir == on_qir);
		CHECK(off.code == on.code);
		printf("    ok  vlen=%-4u QIR identical; %zu generated bytes byte-for-byte identical\n",
		       vlen, off.code.size());
	}
	dbt::rv32::lane_region_bridge::Reset();
}

// ---------------------------------------------------------------------------------------------
// [2]/[3] One frame per run, generic in the operations, with component SSA across the boundary.
// ---------------------------------------------------------------------------------------------

struct RouteRow {
	char const *name;
	u32 word; // writes v3 from vs2=v1, vs1=v2
	RunOp op;
	RuntimeStubId stub;
};

constexpr RouteRow kRoutes[] = {
    {"vadd.vv", W_OP_ADD, RunOp::Add, RuntimeStubId::id_rv32_vadd_vv},
    {"vsub.vv", W_OP_SUB, RunOp::Sub, RuntimeStubId::id_rv32_vialu},
    {"vmul.vv", W_OP_MUL, RunOp::Mul, RuntimeStubId::id_rv32_vimul},
    {"vxor.vv", W_OP_XOR, RunOp::Xor, RuntimeStubId::id_rv32_vialu},
    {"vor.vv", W_OP_OR, RunOp::Or, RuntimeStubId::id_rv32_vialu},
    {"vand.vv", W_OP_AND, RunOp::And, RuntimeStubId::id_rv32_vialu},
};

// The QIR-level obligations of one two-member frame, checked against the descriptor the ADMISSION
// scan produced for the same words -- so the codegen is compared with the admission's own dataflow,
// not with a second copy of it written here.
void CheckFrameAgainstDescriptor(char const *tag, Built &b, u32 w0, u32 w1, u32 vlen, RunOp op0,
				 RunOp op1, RuntimeStubId stub0, RuntimeStubId stub1)
{
	u8 const k = (u8)(vlen / 512);
	auto const frames = FindFrames(b.region);
	CHECK_EQ(frames.size(), (size_t)1);
	if (frames.size() != 1)
		return;
	auto const &f = frames[0];

	std::vector<u32> mem = {w0, w1};
	ApplyConfig(vlen, true);
	auto const d = qir::rv32::RV32Translator::RvvAdmitVectorRun(
	    (uptr)mem.data(), 0u, 8u, 2u, dbt::rv32::VTYPE_E32_M1_TA_MA);
	CHECK_EQ((unsigned)d.n_members, 2u);
	if (d.n_members != 2)
		return;

	CHECK_EQ((unsigned)f.begin->n_members, 2u);
	CHECK_EQ((unsigned)f.end->n_members, 2u);
	// The members, in guest order, with the PCs the ordered fallback arm needs. The words sit at
	// guest pc 4 and 8 because a vsetvli precedes them in the built region.
	CHECK_EQ(f.end->members[0].raw, w0);
	CHECK_EQ(f.end->members[1].raw, w1);
	CHECK(f.end->members[0].stub == stub0);
	CHECK(f.end->members[1].stub == stub1);
	CHECK_EQ(f.end->members[0].pc, 4u);
	CHECK_EQ(f.end->members[1].pc, 8u);

	unsigned const n_in = (unsigned)__builtin_popcount(d.live_in_mask);
	unsigned const n_out = (unsigned)__builtin_popcount(d.live_out_mask);

	std::vector<Op> body;
	for (auto *ins : f.body)
		body.push_back(ins->GetOpcode());
	CHECK_EQ(body.size(), (size_t)((n_in + n_out + 2u) * k));
	unsigned n_load = 0, n_store = 0, n_alu = 0;
	for (auto op : body) {
		n_load += op == Op::_vstatechunkload;
		n_store += op == Op::_vstatechunkstore;
		n_alu += IsAluChunkOp(op);
	}
	CHECK_EQ(n_load, n_in * k);
	CHECK_EQ(n_store, n_out * k);
	CHECK_EQ(n_alu, 2u * k);
	CHECK_EQ((unsigned)f.begin->n_typed, (n_in + n_out + 2u) * k);

	// Order: every load before every lane op, every store after every lane op. The second half
	// is what "no intermediate materialization" means at QIR level -- a store between the two
	// members would land here.
	size_t last_load = 0, first_store = body.size(), first_alu = body.size(), last_alu = 0;
	for (size_t i = 0; i < body.size(); ++i) {
		if (body[i] == Op::_vstatechunkload)
			last_load = i;
		if (body[i] == Op::_vstatechunkstore && first_store == body.size())
			first_store = i;
		if (IsAluChunkOp(body[i])) {
			if (first_alu == body.size())
				first_alu = i;
			last_alu = i;
		}
	}
	CHECK(last_load < first_alu);
	CHECK(last_alu < first_store);

	// The operations are the run's own, in the run's order, and they are the six DISTINCT chunk
	// ops -- not one of them wearing another's name.
	for (u8 c = 0; c < k; ++c) {
		CHECK(body[first_alu + c] == AluOpFor(op0));
		CHECK(body[first_alu + k + c] == AluOpFor(op1));
	}

	// [3] FULL DEF-USE VERIFICATION, INCLUDING THE CROSS-INSTRUCTION EDGE.
	//
	// Rather than spot-checking the carried edge, rebuild the entire (guest register, chunk) ->
	// value map from the guest instruction fields the ADMISSION scan decoded, and require every
	// member operand to be exactly the value that map says it is. Two things this catches that a
	// spot check does not: a source bound to the WRONG register (both operands would still be
	// live values, and the counts would still be right), and a carried value that happens to
	// match by luck when the two sources are the same register.
	//
	// VOperand has no operator==; the comparable identity of a pre-allocation typed chunk value
	// is its VIRTUAL VPR number, and both sides must be VVPR for the comparison to mean anything.
	auto same = [](VOperand a, VOperand b) {
		return a.IsVVPR() && b.IsVVPR() && a.GetVVPR() == b.GetVVPR();
	};
	// Pass 1's loads define the live-in components, in ascending register order, k chunks each.
	// The map is keyed the way the run's dataflow is keyed, not the way the emitter iterates.
	VOperand cur[dbt::rv32::VREG_NUM][2];
	bool have[dbt::rv32::VREG_NUM][2] = {};
	{
		unsigned li = 0;
		for (u32 r = 0; r < dbt::rv32::VREG_NUM; ++r) {
			if (!(d.live_in_mask & (1u << r)))
				continue;
			for (u8 c = 0; c < k; ++c, ++li) {
				auto *ld = static_cast<InstVStateChunkLoad *>(f.body[li]);
				// The window this load reads must be that register's chunk c.
				CHECK_EQ((u32)ld->offs, ChunkOffs(r, c));
				cur[r][c] = ld->o(0);
				have[r][c] = true;
			}
		}
		CHECK_EQ(li, n_in * k);
	}
	unsigned carried = 0;
	for (u8 i = 0; i < 2; ++i) {
		auto const &m = d.members[i];
		VOperand def[2];
		for (u8 c = 0; c < k; ++c) {
			auto *op = static_cast<InstWithOperands<1, 2> *>(f.body[first_alu + i * k + c]);
			CHECK(have[m.rs2][c] && have[m.rs1][c]);
			if (!have[m.rs2][c] || !have[m.rs1][c])
				continue;
			// i(0) is the vs2 chunk and i(1) the vs1 chunk, for every member of every run.
			CHECK(same(op->i(0), cur[m.rs2][c]));
			CHECK(same(op->i(1), cur[m.rs1][c]));
			if (i == 1 && m.src2_def == 0)
				carried += same(op->i(0), cur[m.rs2][c]);
			if (i == 1 && m.src1_def == 0)
				carried += same(op->i(1), cur[m.rs1][c]);
			def[c] = op->o(0);
		}
		// Published only after BOTH sources of every chunk are bound, which is what makes the
		// legal operand overlaps read pre-instruction values.
		for (u8 c = 0; c < k; ++c) {
			cur[m.rd][c] = def[c];
			have[m.rd][c] = true;
		}
	}
	// At least one component really crossed the guest instruction boundary in these fixtures.
	if (d.members[1].src2_def == 0 || d.members[1].src1_def == 0)
		CHECK(carried >= k);
	// Pass 3 stores each live-out register's FINAL value, at that register's own windows.
	{
		unsigned so = 0;
		for (u32 r = 0; r < dbt::rv32::VREG_NUM; ++r) {
			if (!(d.live_out_mask & (1u << r)))
				continue;
			for (u8 c = 0; c < k; ++c, ++so) {
				auto *st = static_cast<InstVStateChunkStore *>(
				    f.body[first_store + so]);
				CHECK_EQ((u32)st->offs, ChunkOffs(r, c));
				CHECK(same(st->i(0), cur[r][c]));
			}
		}
		CHECK_EQ(so, n_out * k);
	}
	(void)tag;
}

void CheckNamedPairsAndAllPairs()
{
	printf("[2] one guarded frame per run, generic in the two operations\n");
	struct Named {
		char const *name;
		u32 w0, w1;
		RunOp op0, op1;
		RuntimeStubId s0, s1;
	};
	Named const named[] = {
	    {"add->sub", W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2, RunOp::Add, RunOp::Sub,
	     RuntimeStubId::id_rv32_vadd_vv, RuntimeStubId::id_rv32_vialu},
	    {"mul->xor", W_VMUL_V5_V3_V4, W_VXOR_V6_V5_V4, RunOp::Mul, RunOp::Xor,
	     RuntimeStubId::id_rv32_vimul, RuntimeStubId::id_rv32_vialu},
	    {"or->and", W_VOR_V7_V6_V5, W_VAND_V8_V7_V6, RunOp::Or, RunOp::And,
	     RuntimeStubId::id_rv32_vialu, RuntimeStubId::id_rv32_vialu},
	};
	for (auto const &n : named) {
		for (u32 vlen : {512u, 1024u}) {
			Built b;
			// emit=false: the def-use assertion below is about the QIR the translator
			// BUILT. qcg::GenerateCode rewrites every operand to a physical register in
			// place, so running it first would replace the virtual identity being checked
			// with the allocated one (which section [5] checks on the emitted code).
			Build(b, {W_VSETVLI_E32M1, n.w0, n.w1}, vlen, /*vector_run=*/true,
			      /*emit=*/false);
			CheckFrameAgainstDescriptor(n.name, b, n.w0, n.w1, vlen, n.op0, n.op1, n.s0,
						    n.s1);
			printf("    ok  %-10s vlen=%u  frame matches the admission descriptor\n",
			       n.name, vlen);
		}
	}

	printf("[2b] all 36 ordered pairs over the six routes build the same frame\n");
	unsigned ok = 0;
	for (auto const &a : kRoutes) {
		for (auto const &c : kRoutes) {
			for (u32 vlen : {512u, 1024u}) {
				u8 const k = (u8)(vlen / 512);
				Built b;
				Build(b, {W_VSETVLI_E32M1, a.word, c.word}, vlen, true, /*emit=*/false);
				auto const frames = FindFrames(b.region);
				bool good = frames.size() == 1;
				if (good) {
					auto const &f = frames[0];
					unsigned n_load = 0, n_store = 0, n_alu = 0;
					for (auto *ins : f.body) {
						n_load += ins->GetOpcode() == Op::_vstatechunkload;
						n_store += ins->GetOpcode() == Op::_vstatechunkstore;
						n_alu += IsAluChunkOp(ins->GetOpcode());
					}
					// Both members are `v3 = v1 op v2`: live-in {v1,v2}, live-out
					// {v3}. Two loads, two lane ops, one store per chunk -- the
					// SAME shape for every pair, which is the point.
					good = f.begin->n_members == 2 && f.end->n_members == 2 &&
					       n_load == 2u * k && n_store == 1u * k &&
					       n_alu == 2u * k &&
					       f.body[2 * k]->GetOpcode() == AluOpFor(a.op) &&
					       f.body[3 * k]->GetOpcode() == AluOpFor(c.op) &&
					       f.end->members[0].stub == a.stub &&
					       f.end->members[1].stub == c.stub &&
					       f.end->members[0].raw == a.word &&
					       f.end->members[1].raw == c.word;
				}
				if (!good) {
					fprintf(stderr, "  FAIL pair %s -> %s vlen=%u frames=%zu\n",
						a.name, c.name, vlen, frames.size());
					++g_failures;
				} else {
					++ok;
				}
			}
		}
	}
	printf("    ok  %u/72 (36 ordered pairs x 2 VLENs) built one frame of identical shape\n", ok);
	CHECK_EQ(ok, 72u);
}

// ---------------------------------------------------------------------------------------------
// [4] After the REAL allocator: no spill, no allocator move, every operand a pool VPR.
// ---------------------------------------------------------------------------------------------

void CheckAllocation()
{
	printf("[4] post-QRegAlloc: no spill and no allocator move inside the guarded body\n");
	struct Row {
		char const *name;
		u32 w0, w1;
	};
	Row const rows[] = {
	    {"add->sub", W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2},
	    {"mul->xor", W_VMUL_V5_V3_V4, W_VXOR_V6_V5_V4},
	    {"or->and", W_VOR_V7_V6_V5, W_VAND_V8_V7_V6},
	};
	for (auto const &r : rows) {
		for (u32 vlen : {512u, 1024u}) {
			u8 const k = (u8)(vlen / 512);
			Built b;
			// Exactly the two passes qcg::GenerateCode runs before constructing QEmit.
			Build(b, {W_VSETVLI_E32M1, r.w0, r.w1}, vlen, true, /*emit=*/false);
			qcg::MachineRegionInfo mri;
			qcg::QSelPass::run(b.region, &mri);
			qcg::QRegAllocPass::run(b.region);

			auto const frames = FindFrames(b.region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.size() != 1)
				continue;

			unsigned movs = 0;
			std::vector<unsigned> pregs;
			for (auto *ins : frames[0].body) {
				// Any `mov` inside an open group would be an allocator spill, fill or
				// copy -- QEmit::Emit_mov Panics on one, so seeing it here at all is
				// already the failure.
				movs += ins->GetOpcode() == Op::_mov;
				struct Ctx {
					std::vector<unsigned> *pregs;
					int *failures;
				} ctx{&pregs, &g_failures};
				ForEachV512Operand(
				    ins,
				    [](void *c, VOperand o, bool) {
					    auto *x = (Ctx *)c;
					    if (o.GetType() != VType::V512)
						    return;
					    if (!o.IsPVPR() ||
						!qcg::ArchTraits::VPR_POOL.Test(o.GetPVPR())) {
						    fprintf(stderr,
							    "  FAIL body operand is not an "
							    "allocated pool VPR\n");
						    ++*x->failures;
						    return;
					    }
					    x->pregs->push_back(o.GetPVPR());
				    },
				    &ctx);
			}
			CHECK_EQ(movs, 0u);
			std::sort(pregs.begin(), pregs.end());
			pregs.erase(std::unique(pregs.begin(), pregs.end()), pregs.end());
			// Four distinct component values per chunk for these rows: two live-in loads
			// and the two members' results. A spill would have reduced this and inserted
			// a mov; a reload would have added a fifth.
			CHECK_EQ(pregs.size(), (size_t)(4u * k));
			printf("    ok  %-10s vlen=%-4u %zu distinct pool ZMMs, 0 allocator movs\n",
			       r.name, vlen, pregs.size());
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [5] The emitted code, read back from objdump.
// ---------------------------------------------------------------------------------------------

void CheckEmitted()
{
	printf("[5] emitted host code: one guard, no state traffic between members, ordered fallback\n");
	struct Row {
		char const *name;
		u32 w0, w1;
		RunOp op0, op1;
		u32 in0, in1;	// live-in guest vector registers
		u32 out0, out1; // live-out guest vector registers
	};
	Row const rows[] = {
	    {"add->sub", W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2, RunOp::Add, RunOp::Sub, 1, 2, 3, 4},
	    {"mul->xor", W_VMUL_V5_V3_V4, W_VXOR_V6_V5_V4, RunOp::Mul, RunOp::Xor, 3, 4, 5, 6},
	    {"or->and", W_VOR_V7_V6_V5, W_VAND_V8_V7_V6, RunOp::Or, RunOp::And, 5, 6, 7, 8},
	};
	for (auto const &r : rows) {
		for (u32 vlen : {512u, 1024u}) {
			u8 const k = (u8)(vlen / 512);
			Built b;
			Build(b, {W_VSETVLI_E32M1, r.w0, r.w1}, vlen, true);
			auto const e = ReadEmitted(b);

			// ---- ONE GUARD, COVERING BOTH MEMBERS -----------------------------------
			// Three architectural compares, all jumping to the SAME label. A second
			// frame would contribute a second triple and a second label.
			CHECK_EQ(e.jne_targets.size(), (size_t)3);
			bool one_target = !e.jne_targets.empty();
			for (auto t : e.jne_targets)
				one_target &= t == e.jne_targets[0];
			CHECK(one_target);
			u64 const fallback = e.jne_targets.empty() ? 0 : e.jne_targets[0];

			// ---- FAST BODY ----------------------------------------------------------
			std::vector<VecOp> loads, stores, alus;
			for (auto const &v : e.vecs) {
				if (v.kind == VecKind::Load)
					loads.push_back(v);
				else if (v.kind == VecKind::Store)
					stores.push_back(v);
				else if (v.kind == VecKind::Alu)
					alus.push_back(v);
			}
			CHECK_EQ(loads.size(), (size_t)(2 * k));
			CHECK_EQ(stores.size(), (size_t)(2 * k));
			CHECK_EQ(alus.size(), (size_t)(2 * k));
			// Every vector instruction of the frame is inside the guarded region: the
			// fallback label is after all of them.
			for (auto const &v : e.vecs)
				CHECK(v.addr < fallback);

			// The live-in windows are exactly the two source registers' chunks, and the
			// live-out windows exactly the two destinations' chunks. A reload of an
			// intermediate would add a load at the intermediate register's window; an
			// intermediate materialization would add a store at it.
			std::vector<u32> want_loads, want_stores, got_loads, got_stores;
			for (u8 c = 0; c < k; ++c) {
				want_loads.push_back(ChunkOffs(r.in0, c));
				want_loads.push_back(ChunkOffs(r.in1, c));
				want_stores.push_back(ChunkOffs(r.out0, c));
				want_stores.push_back(ChunkOffs(r.out1, c));
			}
			for (auto const &v : loads)
				got_loads.push_back(v.disp);
			for (auto const &v : stores)
				got_stores.push_back(v.disp);
			std::sort(want_loads.begin(), want_loads.end());
			std::sort(want_stores.begin(), want_stores.end());
			std::sort(got_loads.begin(), got_loads.end());
			std::sort(got_stores.begin(), got_stores.end());
			CHECK(want_loads == got_loads);
			CHECK(want_stores == got_stores);

			// ---- NOTHING BETWEEN THE TWO MEMBERS ------------------------------------
			// The R1A.0 gap closed, read off the machine code: between the last lane op
			// of member 0 and the first lane op of member 1 there is no ZMM load or store
			// at all, and member 1 consumes member 0's destination REGISTER.
			if (alus.size() == (size_t)(2 * k)) {
				u64 const m0_last = alus[k - 1].addr;
				u64 const m1_first = alus[k].addr;
				unsigned between = 0;
				for (auto const &v : e.vecs)
					between += (v.kind != VecKind::Alu) && v.addr > m0_last &&
						   v.addr < m1_first;
				CHECK_EQ(between, 0u);
				for (u8 c = 0; c < k; ++c) {
					CHECK(alus[c].mnem == HostMnemFor(r.op0));
					CHECK(alus[k + c].mnem == HostMnemFor(r.op1));
					CHECK(alus[k + c].s0 == alus[c].d);
				}
				// The two chunks stay in disjoint register sets at VLEN=1024.
				if (k == 2) {
					CHECK(alus[0].d != alus[1].d);
					CHECK(alus[2].d != alus[3].d);
				}
			}

			// ---- PRECISE IP ON BOTH ARMS --------------------------------------------
			// Stores to CPUState::ip in the whole region, in emission order:
			//   0     the leading vsetvli's own PreSideeff
			//   pc_0  member 0's PreSideeff, before the guard
			//   pc_1  fast arm exit, after the body   <- both arms must leave the SAME pc
			//   pc_0  fallback arm, before helper 0
			//   pc_1  fallback arm, before helper 1
			// There is deliberately NO store of pc_1 inside the fast body: R1A.2b section 4
			// permits omitting run-interior IP writes on the arm that cannot trap, and
			// requires them on the arm that calls helpers.
			std::vector<u64> ip_imms;
			for (auto const &s : e.imm_stores)
				if (s.first == ST_IP)
					ip_imms.push_back(s.second);
			std::vector<u64> const want_ip = {0ull, 4ull, 8ull, 4ull, 8ull};
			CHECK(ip_imms == want_ip);
			if (ip_imms != want_ip) {
				fprintf(stderr, "  ip stores were:");
				for (auto v : ip_imms)
					fprintf(stderr, " %llu", (unsigned long long)v);
				fprintf(stderr, "\n");
			}

			// ---- ORDERED FALLBACK ---------------------------------------------------
			// After the fallback label, in order: pc_0, raw_0, call, pc_1, raw_1, call.
			// A swapped order here is a silently wrong program, so the sequence is read
			// as a whole rather than as two independent counts.
			std::vector<std::string> seq;
			for (auto const &l : e.lines) {
				if (l.addr < fallback)
					continue;
				u32 disp;
				u64 imm;
				if (ParseStateImmStore(l, &disp, &imm) && disp == ST_IP) {
					seq.push_back("ip=" + std::to_string(imm));
				} else if ((l.mnem == "mov" || l.mnem == "movabs") &&
					   l.ops.compare(0, 4, "rsi,") == 0) {
					// `movabs` is what asmjit emits when the raw guest word does
					// not fit a signed 32-bit immediate (e.g. vmul.vv, whose top
					// bit is set). Missing it would silently drop that member's
					// argument from the checked sequence.
					seq.push_back(
					    "raw=" +
					    std::to_string(strtoull(l.ops.c_str() + 4, nullptr, 0)));
				} else if (l.mnem == "call") {
					seq.push_back("call");
				} else if (l.mnem == "jmp" || l.mnem == "ret") {
					break;
				}
			}
			std::vector<std::string> const want_seq = {
			    "ip=4", "raw=" + std::to_string(r.w0), "call",
			    "ip=8", "raw=" + std::to_string(r.w1), "call"};
			bool prefix_ok = seq.size() >= want_seq.size();
			for (size_t i = 0; prefix_ok && i < want_seq.size(); ++i)
				prefix_ok = seq[i] == want_seq[i];
			CHECK(prefix_ok);
			if (!prefix_ok) {
				fprintf(stderr, "  fallback sequence was:");
				for (auto const &s : seq)
					fprintf(stderr, " %s", s.c_str());
				fprintf(stderr, "\n");
			}
			printf("    ok  %-10s vlen=%-4u guard=1 loads=%zu alus=%zu stores=%zu "
			       "between=0 ip=[0,4,8,4,8] fallback=[%08x,%08x]\n",
			       r.name, vlen, loads.size(), alus.size(), stores.size(), r.w0, r.w1);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [6] Operand overlap, and the overwrite chain.
// ---------------------------------------------------------------------------------------------

void CheckOverlap()
{
	printf("[6] every legal operand overlap, and an intermediate that must never be stored\n");
	struct Row {
		char const *name;
		u32 w0, w1;
		u32 want_in, want_out; // guest vector register masks
	};
	Row const rows[] = {
	    {"vd==vs2 then use", W_VADD_V3_V3_V2, W_VSUB_V4_V3_V2, (1u << 3) | (1u << 2),
	     (1u << 3) | (1u << 4)},
	    {"vd==vs1 then use", W_VADD_V3_V1_V3, W_VSUB_V4_V3_V2,
	     (1u << 1) | (1u << 3) | (1u << 2), (1u << 3) | (1u << 4)},
	    {"vd==vs1==vs2", W_VADD_V3_V3_V3, W_VSUB_V4_V3_V2, (1u << 3) | (1u << 2),
	     (1u << 3) | (1u << 4)},
	    {"vs1==vs2", W_VADD_V3_V1_V1, W_VSUB_V4_V3_V2, (1u << 1) | (1u << 2),
	     (1u << 3) | (1u << 4)},
	    // The second member OVERWRITES the first member's destination: the intermediate must
	    // never reach CPUState, so live-out is ONE register and there are k stores, not 2k.
	    {"overwrite chain", W_VADD_V3_V3_V2, W_VSUB_V3_V3_V2, (1u << 3) | (1u << 2), 1u << 3},
	};
	for (auto const &r : rows) {
		for (u32 vlen : {512u, 1024u}) {
			u8 const k = (u8)(vlen / 512);
			std::vector<u32> mem = {r.w0, r.w1};
			ApplyConfig(vlen, true);
			auto const d = qir::rv32::RV32Translator::RvvAdmitVectorRun(
			    (uptr)mem.data(), 0u, 8u, 2u, dbt::rv32::VTYPE_E32_M1_TA_MA);
			CHECK_EQ((unsigned)d.n_members, 2u);
			CHECK_EQ(d.live_in_mask, r.want_in);
			CHECK_EQ(d.live_out_mask, r.want_out);

			Built b;
			Build(b, {W_VSETVLI_E32M1, r.w0, r.w1}, vlen, true);
			auto const e = ReadEmitted(b);
			unsigned n_load = 0, n_store = 0, n_alu = 0;
			for (auto const &v : e.vecs) {
				n_load += v.kind == VecKind::Load;
				n_store += v.kind == VecKind::Store;
				n_alu += v.kind == VecKind::Alu;
			}
			CHECK_EQ(n_load, (unsigned)__builtin_popcount(r.want_in) * k);
			CHECK_EQ(n_store, (unsigned)__builtin_popcount(r.want_out) * k);
			CHECK_EQ(n_alu, 2u * k);
			printf("    ok  %-18s vlen=%-4u loads=%u alus=%u stores=%u\n", r.name, vlen,
			       n_load, n_alu, n_store);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// [7] The translator consumes exactly the admitted members, and nothing else.
// ---------------------------------------------------------------------------------------------

void CheckConsumption()
{
	printf("[7] the translator consumes exactly the admitted members\n");
	{
		Built b;
		Build(b, {W_VSETVLI_E32M1, W_OP_ADD, W_OP_SUB, W_OP_MUL, W_OP_XOR, W_OP_OR, W_OP_AND},
		      512, true);
		auto const frames = FindFrames(b.region);
		// M2E: with the prototype two-member cap gone, all six routed operations form ONE
		// maximal run. The invariant this case is really about is unchanged and is checked
		// below: every lane operation appears exactly once, in guest order.
		CHECK_EQ(frames.size(), (size_t)1);
		CHECK_EQ((unsigned)frames[0].begin->n_members, 6u);
		// All six lane operations present exactly once, in guest order: nothing was dropped
		// by being consumed, and nothing was emitted twice.
		std::vector<Op> alus;
		for (auto &bb : b.region->GetBlocks())
			for (auto &ins : bb.ilist)
				if (IsAluChunkOp(ins.GetOpcode()))
					alus.push_back(ins.GetOpcode());
		std::vector<Op> const want = {Op::_vchunkadd, Op::_vchunksub, Op::_vchunkmul,
					      Op::_vchunkxor, Op::_vchunkor,  Op::_vchunkand};
		CHECK(alus == want);
		printf("    ok  six routed ops -> ONE six-member frame, all six lane ops in order\n");
	}
	{
		Built b;
		Build(b, {W_VSETVLI_E32M1, W_VADD_V3_V1_V2, W_VLE32, W_OP_ADD}, 512, true);
		auto const frames = FindFrames(b.region);
		CHECK_EQ(frames.size(), (size_t)3);
		for (auto const &f : frames)
			CHECK_EQ((unsigned)f.begin->n_members, 1u);
		printf("    ok  a memory barrier between two members -> three single-member frames\n");
	}
	{
		Built b;
		Build(b, {W_VSETVLI_E32M1, W_OP_ADD, W_OP_SUB, W_OP_MUL}, 512, true);
		auto const frames = FindFrames(b.region);
		// M2E: one maximal run of three, not a two-member run plus a leftover.
		CHECK_EQ(frames.size(), (size_t)1);
		if (frames.size() == 1)
			CHECK_EQ((unsigned)frames[0].begin->n_members, 3u);
		printf("    ok  three routed ops -> one three-member run\n");
	}
	{
		// LLVM now admits a register-only integer run through the shared typed-frame path.
		// This checks translation admission; LLVM IR/runtime correctness is tested separately.
		Built b;
		ApplyConfig(512, true);
		config::aot_use_llvm = true;
		config::rvv_vector_ssa = true;
		b.words = {W_VSETVLI_E32M1, W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2};
		CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
		CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u),
				std::move(ranges));
		b.region = CompilerGenRegionIR(&b.arena, job);
		auto const frames = FindFrames(b.region);
		CHECK_EQ(frames.size(), (size_t)1);
		if (frames.size() == 1)
			CHECK_EQ((unsigned)frames[0].begin->n_members, 2u);
		printf("    ok  LLVM backend admits one two-member integer run\n");
	}
}

// Print one representative frame's disassembly, so the checkpoint's raw log contains the actual
// machine code the assertions above are about rather than only their verdicts.
// ---------------------------------------------------------------------------------------------
// R1A.3d [8]-[15]. The three-arm ablation: A = per-instruction guard, B = one shared guard with a
// materializing body, C = one shared guard with component SSA.
//
// Everything below tests ONE claim in different ways: each pair of arms differs by a SINGLE
// factor. A -> B removes one whole frame's guard scaffolding and nothing else; B -> C removes the
// intermediate's `k` CPUState reloads and nothing else.
// ---------------------------------------------------------------------------------------------

struct Ins {
	u32 addr;
	std::string text;
};

// objdump lines are `  <hex>:\t<mnemonic> <operands>`; anything else is header or padding.
std::vector<Ins> ParseInsns(std::vector<std::string> const &lines)
{
	std::vector<Ins> out;
	for (auto const &line : lines) {
		auto const tab = line.find('\t');
		if (tab == std::string::npos)
			continue;
		auto const colon = line.find(':');
		if (colon == std::string::npos || colon > tab)
			continue;
		std::string const head = line.substr(0, colon);
		char *endp = nullptr;
		unsigned long const a = strtoul(head.c_str(), &endp, 16);
		if (endp == nullptr || *endp != '\0' || head.empty())
			continue;
		std::string body = line.substr(tab + 1);
		size_t b0 = 0;
		while (b0 < body.size() && isspace((unsigned char)body[b0]))
			++b0;
		out.push_back(Ins{(u32)a, body.substr(b0)});
	}
	return out;
}

std::string CounterText(size_t off)
{
	char buf[64];
	snprintf(buf, sizeof(buf), "QWORD PTR [r13+0x%x]", (unsigned)off);
	return std::string(buf);
}

std::string const &FallbackIncText()
{
	static std::string const s = CounterText(offsetof(CPUState, rvv_direct_fallbacks));
	return s;
}

std::string const &HitIncText()
{
	static std::string const s = CounterText(offsetof(CPUState, rvv_direct_hits));
	return s;
}

bool Has(std::string const &hay, std::string const &needle)
{
	return hay.find(needle) != std::string::npos;
}

bool StartsWith(std::string const &s, char const *p)
{
	return s.compare(0, strlen(p), p) == 0;
}

// A typed frame's fallback arm is exactly the half-open range between the join `jmp` and the
// address that `jmp` targets: the emitter binds `done` immediately after the last helper call.
// Identifying it this way needs no label information and is self-checking -- the first instruction
// of every span found must be the guard-miss counter, which is what distinguishes a frame join
// from any other jump in the blob.
std::vector<std::pair<size_t, size_t>> FallbackSpans(std::vector<Ins> const &insns)
{
	std::vector<std::pair<size_t, size_t>> spans;
	for (size_t i = 0; i + 1 < insns.size(); ++i) {
		if (!StartsWith(insns[i].text, "jmp "))
			continue;
		auto const pos = insns[i].text.find("0x");
		if (pos == std::string::npos)
			continue;
		unsigned long const target = strtoul(insns[i].text.c_str() + pos + 2, nullptr, 16);
		size_t j = i + 1;
		while (j < insns.size() && insns[j].addr < target)
			++j;
		if (j >= insns.size() || insns[j].addr != (u32)target || j == i + 1)
			continue;
		if (!Has(insns[i + 1].text, FallbackIncText()))
			continue; // not a typed frame join
		spans.push_back({i + 1, j});
	}
	return spans;
}

// Instructions a guard HIT executes, up to a constant that is identical in all three arms: the
// whole blob minus every frame's fallback arm. CheckArmLedger additionally pins that the code
// after the last frame is byte-identical across arms, so that constant provably cancels.
unsigned NonFallbackCount(std::vector<Ins> const &insns,
			  std::vector<std::pair<size_t, size_t>> const &spans)
{
	unsigned n = (unsigned)insns.size();
	for (auto const &sp : spans)
		n -= (unsigned)(sp.second - sp.first);
	return n;
}

// Helper stub addresses and the region-epilogue pointer pool are absolute runtime values under
// ASLR; normalize them exactly as the flag-off goldens do and nothing else.
std::string SpanText(std::vector<Ins> const &insns, size_t from, size_t to)
{
	std::string out;
	for (size_t i = from; i < to && i < insns.size(); ++i) {
		std::string const &t = insns[i].text;
		for (size_t c = 0; c < t.size();) {
			if (t.compare(c, 2, "0x") == 0) {
				size_t e = c + 2;
				while (e < t.size() && isxdigit((unsigned char)t[e]))
					++e;
				if (e - c - 2 >= 6) {
					out += "0xABS";
					c = e;
					continue;
				}
			}
			out += t[c++];
		}
		out += '\n';
	}
	return out;
}

// The epilogue's intra-blob branch targets necessarily move when the frames above it change size,
// so "identical" there means the same instructions in the same order, not the same literal
// addresses. Compare the mnemonic sequence, which is what "the constant cancels" actually needs.
std::string MnemonicSeq(std::vector<Ins> const &insns, size_t from, size_t to)
{
	std::string out;
	for (size_t i = from; i < to && i < insns.size(); ++i) {
		std::string const &t = insns[i].text;
		size_t e = t.find(' ');
		out += (e == std::string::npos) ? t : t.substr(0, e);
		out += '\n';
	}
	return out;
}

// Index of the first instruction of the first typed frame: the guard's vtype compare.
//
// A NOT-FOUND RESULT IS A HARD FAILURE, not `insns.size()`. Returning the end silently turned the
// two prologue-equality checks in CheckArmLedger into whole-function comparisons -- which happen to
// fail, so the defect was visible, but a differently-shaped tree could equally well have made them
// pass vacuously. The caller has already established that a frame exists.
size_t FirstGuardIndex(std::vector<Ins> const &insns)
{
	char want[48];
	snprintf(want, sizeof(want), "[r13+0x%x]", (unsigned)ST_VTYPE);
	for (size_t i = 0; i < insns.size(); ++i)
		if (StartsWith(insns[i].text, "cmp ") && Has(insns[i].text, want))
			return i;
	fprintf(stderr, "  FAIL FirstGuardIndex: no `cmp ... %s` in %zu instructions\n", want,
		insns.size());
	++g_failures;
	return insns.size();
}

unsigned CountText(std::vector<Ins> const &insns, std::string const &needle)
{
	unsigned n = 0;
	for (auto const &i : insns)
		n += Has(i.text, needle);
	return n;
}

// The three registered R1A.3c sequences plus an overlap shape, at both widths.
struct ArmCase {
	char const *name;
	std::vector<u32> words;
};

std::vector<ArmCase> ArmCases()
{
	return {
	    {"addsub", {W_VSETVLI_E32M1, W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}},
	    {"mulxor", {W_VSETVLI_E32M1, W_VMUL_V5_V3_V4, W_VXOR_V6_V5_V4}},
	    {"orand", {W_VSETVLI_E32M1, W_VOR_V7_V6_V5, W_VAND_V8_V7_V6}},
	    {"overwrite", {W_VSETVLI_E32M1, W_VADD_V3_V3_V2, W_VSUB_V3_V3_V2}},
	};
}

struct ArmBuild {
	Built b;
	std::vector<Ins> insns;
	std::vector<std::pair<size_t, size_t>> spans;
};

// arm: 0 = A (run off), 1 = B (materialize), 2 = C (ssa).
void BuildArm(ArmBuild &ab, std::vector<u32> const &words, u32 vlen, int arm, bool hit_counter,
	      bool frame_census = false)
{
	g_body_materialize = (arm == 1);
	g_hit_counter = hit_counter;
	g_frame_census = frame_census; // P7M-E; false for every pre-existing caller
	Build(ab.b, words, vlen, arm != 0);
	g_body_materialize = false;
	g_hit_counter = true;
	g_frame_census = false;
	ab.insns = ParseInsns(ab.b.lines);
	// The emitted buffer is zero-padded, and objdump decodes that padding into instructions --
	// a DIFFERENT number of them per arm, because the arms have different code sizes. Every
	// region ends with the exit trampoline `movabs rax, <addr>` / `call rax`, so cutting there
	// removes the padding and nothing real. Without this, the counts below would compare code
	// plus a per-arm amount of decoded padding.
	for (size_t i = ab.insns.size(); i-- > 0;) {
		if (ab.insns[i].text == "call   rax") {
			ab.insns.resize(i + 1);
			break;
		}
	}
	ab.spans = FallbackSpans(ab.insns);
}

// [8] The body mode must be invisible to admission. If it were not, arms B and C could form
//     DIFFERENT runs and the ablation would have two factors instead of one.
void CheckBodyModeInvisibleToAdmission()
{
	printf("[8] the body selector never reaches admission: identical descriptors and stats\n");
	unsigned compared = 0;
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &ra : kRoutes) {
			for (auto const &rc : kRoutes) {
				std::vector<u32> mem = {ra.word, rc.word};
				rvvrun::RunDescriptor d[2];
				rvvrun::Stats st[2];
				for (int m = 0; m < 2; ++m) {
					g_body_materialize = (m == 1);
					ApplyConfig(vlen, true);
					g_body_materialize = false;
					rvvrun::g_stats = rvvrun::Stats{};
					d[m] = qir::rv32::RV32Translator::RvvAdmitVectorRun(
					    (uptr)mem.data(), 0u, 8u, 2u,
					    dbt::rv32::VTYPE_E32_M1_TA_MA);
					rvvrun::RecordStats(d[m]);
					st[m] = rvvrun::g_stats;
				}
				CHECK_EQ((unsigned)d[0].n_members, (unsigned)d[1].n_members);
				CHECK_EQ(d[0].live_in_mask, d[1].live_in_mask);
				CHECK_EQ(d[0].live_out_mask, d[1].live_out_mask);
				CHECK_EQ(d[0].touched_mask, d[1].touched_mask);
				CHECK_EQ((unsigned)d[0].nchunks, (unsigned)d[1].nchunks);
				CHECK_EQ((unsigned)d[0].peak_live_bound,
					 (unsigned)d[1].peak_live_bound);
				CHECK_EQ((unsigned)d[0].cut, (unsigned)d[1].cut);
				CHECK_EQ(d[0].end_pc, d[1].end_pc);
				CHECK_EQ(d[0].vtype_raw, d[1].vtype_raw);
				CHECK_EQ(d[0].vlmax, d[1].vlmax);
				bool same_members = true, same_defs = true;
				for (u8 mi = 0; mi < d[0].n_members; ++mi) {
					auto const &x = d[0].members[mi];
					auto const &y = d[1].members[mi];
					same_members &= x.pc == y.pc && x.raw == y.raw &&
							x.stub == y.stub && x.op == y.op &&
							x.rd == y.rd && x.rs1 == y.rs1 &&
							x.rs2 == y.rs2 &&
							x.sew_bytes == y.sew_bytes &&
							x.nchunks == y.nchunks &&
							x.src1_def == y.src1_def &&
							x.src2_def == y.src2_def;
				}
				for (unsigned r = 0; r < dbt::rv32::VREG_NUM; ++r)
					same_defs &= d[0].last_def[r] == d[1].last_def[r];
				CHECK(same_members);
				CHECK(same_defs);
				CHECK_EQ((unsigned)st[0].members_admitted,
					 (unsigned)st[1].members_admitted);
				CHECK_EQ((unsigned)st[0].multi_member_runs,
					 (unsigned)st[1].multi_member_runs);
				++compared;
			}
		}
	}
	printf("    ok  %u ordered pairs x VLEN: descriptor and scan stats identical in both "
	       "bodies\n",
	       compared);
}

// [9] The materialize frame at QIR level: 4*m*k typed ops, and the members hand values to each
//     other through CPUState -- a store lands before the next member's loads.
void CheckMaterializeFrameShape()
{
	printf("[9] materialize body: 4*m*k typed ops, per-member CPUState loads and stores\n");
	for (u32 vlen : {512u, 1024u}) {
		u8 const k = (u8)(vlen / 512);
		for (auto const &c : ArmCases()) {
			ArmBuild ab;
			BuildArm(ab, c.words, vlen, 1, true);
			auto const frames = FindFrames(ab.b.region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.size() != 1)
				continue;
			auto const &f = frames[0];
			unsigned n_load = 0, n_store = 0, n_alu = 0;
			for (auto *ins : f.body) {
				n_load += ins->GetOpcode() == Op::_vstatechunkload;
				n_store += ins->GetOpcode() == Op::_vstatechunkstore;
				n_alu += IsAluChunkOp(ins->GetOpcode());
			}
			CHECK_EQ((unsigned)f.body.size(), 8u * k);
			CHECK_EQ((unsigned)f.begin->n_typed, 8u * k);
			CHECK_EQ(n_load, 4u * k);  // two sources per member, per chunk
			CHECK_EQ(n_store, 2u * k); // one destination per member, per chunk
			CHECK_EQ(n_alu, 2u * k);
			size_t last_load = 0, first_store = f.body.size();
			for (size_t i = 0; i < f.body.size(); ++i) {
				if (f.body[i]->GetOpcode() == Op::_vstatechunkload)
					last_load = i;
				if (f.body[i]->GetOpcode() == Op::_vstatechunkstore &&
				    first_store == f.body.size())
					first_store = i;
			}
			// This is the DEFINING property of arm B and the exact inverse of the
			// component-SSA check in [2]: an intermediate store precedes a later load.
			CHECK(first_store < last_load);
		}
	}
	printf("    ok  four shapes x VLEN: 8k typed ops, with an intermediate store before the "
	       "next member's loads\n");
}

// [10] The two bodies share a frame, so everything outside the body -- guard, join, ordered
//      fallback arm, per-member guest PCs -- must be identical.
void CheckFallbackAndGuardIdentical()
{
	printf("[10] the two bodies' ordered fallback arm and guard are identical\n");
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &c : ArmCases()) {
			ArmBuild bm, cs;
			BuildArm(bm, c.words, vlen, 1, true);
			BuildArm(cs, c.words, vlen, 2, true);
			CHECK_EQ(bm.spans.size(), (size_t)1);
			CHECK_EQ(cs.spans.size(), (size_t)1);
			if (bm.spans.size() != 1 || cs.spans.size() != 1)
				continue;
			std::string const fb_b =
			    SpanText(bm.insns, bm.spans[0].first, bm.spans[0].second);
			std::string const fb_c =
			    SpanText(cs.insns, cs.spans[0].first, cs.spans[0].second);
			CHECK(fb_b == fb_c);
			CHECK(Has(bm.insns[bm.spans[0].first].text, FallbackIncText()));
			unsigned gb = 0, gc = 0;
			for (auto const &i : bm.insns)
				gb += StartsWith(i.text, "cmp ") || StartsWith(i.text, "jne ");
			for (auto const &i : cs.insns)
				gc += StartsWith(i.text, "cmp ") || StartsWith(i.text, "jne ");
			CHECK_EQ(gb, gc);
		}
	}
	printf("    ok  four shapes x VLEN: fallback arm text identical, guard instruction counts "
	       "identical\n");
}

// [11] The research hit counter is one `inc` PER TYPED FRAME. Turning it off must remove exactly
//      that many instructions and change nothing else, and must leave the guard-miss counter --
//      the validity gate a counter-free timing arm still carries -- untouched.
void CheckHitCounterScope()
{
	printf("[11] hit counter on/off: the delta is exactly the number of typed frames\n");
	// A shape with more than one frame kind: a typed guest load frame plus the two ALU frames.
	std::vector<u32> const mixed = {W_VSETVLI_E32M1, W_VLE32, W_VADD_V3_V1_V2,
					W_VSUB_V4_V3_V2};
	for (u32 vlen : {512u, 1024u}) {
		for (int arm = 0; arm < 3; ++arm) {
			for (auto const &c : ArmCases()) {
				ArmBuild on, off;
				BuildArm(on, c.words, vlen, arm, true);
				BuildArm(off, c.words, vlen, arm, false);
				unsigned const frames = CountText(on.insns, HitIncText());
				CHECK_EQ(frames, arm == 0 ? 2u : 1u);
				CHECK_EQ(CountText(off.insns, HitIncText()), 0u);
				CHECK_EQ((unsigned)on.insns.size() - (unsigned)off.insns.size(),
					 frames);
				CHECK_EQ(CountText(on.insns, FallbackIncText()),
					 CountText(off.insns, FallbackIncText()));
			}
			ArmBuild on, off;
			BuildArm(on, mixed, vlen, arm, true);
			BuildArm(off, mixed, vlen, arm, false);
			unsigned const frames = CountText(on.insns, HitIncText());
			// vsetvli takes the direct-state route and opens no frame, so the mix is one
			// vle32 frame plus two ALU frames, or plus one when the run is consumed.
			CHECK_EQ(frames, arm == 0 ? 3u : 2u);
			CHECK_EQ((unsigned)on.insns.size() - (unsigned)off.insns.size(), frames);
			CHECK_EQ(CountText(off.insns, HitIncText()), 0u);
			CHECK_EQ(CountText(on.insns, FallbackIncText()),
				 CountText(off.insns, FallbackIncText()));
		}
	}
	printf("    ok  three arms x VLEN: counter-off removes exactly one instruction per typed "
	       "frame; the guard-miss counter is never gated\n");
}

// [P7M-E] THE PER-FRAME DYNAMIC CENSUS: what it registers, what it emits, and what it does not.
//
// WHAT THIS CAN AND CANNOT ESTABLISH ON THIS HOST. It never executes what it emits (see the file's
// HOST NOTE), so it proves the INSTRUMENT -- which frames get an identity, that the increment
// exists exactly once per registered frame, that it targets that frame's own slot, and that it sits
// on the fast-arm-only path -- not the counts a real run produces. The counts themselves need a
// host that can execute AVX-512, which this one cannot.
std::vector<rvvrun::FrameCensusEntry> CensusSnapshot()
{
	std::vector<rvvrun::FrameCensusEntry> out;
	rvvrun::FrameCensusForEach(
	    [](rvvrun::FrameCensusEntry const &e, void *ctx) {
		    static_cast<std::vector<rvvrun::FrameCensusEntry> *>(ctx)->push_back(e);
	    },
	    &out);
	return out;
}

// `movabs rax,<slot>` + `inc QWORD PTR [rax]` is the pair EmitRvvFrameCensusIncr emits.
unsigned CountCensusIncr(std::vector<Ins> const &insns)
{
	unsigned n = 0;
	for (size_t i = 0; i + 1 < insns.size(); ++i)
		n += StartsWith(insns[i].text, "movabs rax,") &&
		     Has(insns[i + 1].text, "inc    QWORD PTR [rax]");
	return n;
}

// [P7L-B1-SPLIT] THE DEPTH-1 MATCHED DEPENDENCE INSTRUMENT INSIDE THE ACCEPTED LIVE-SPLIT BODY.
//
// WHAT THIS HAS TO ESTABLISH, because the whole experiment is single-factor or it is nothing:
//
//   S1  VLEN 512 (k = 1): the two arms are BYTE-IDENTICAL. Not "equivalent" -- memcmp of the
//       emitted buffer. `(c + 1) % k == c` at k = 1, so this must hold by construction.
//   S2  VLEN 1024 (k = 2): same instruction count, same mnemonic multiset, same code size, same
//       loads and stores. Any spill, extra move or size drift shows up here.
//   S3  the probe is present and its count is exactly one per (member, component) at depth 1.
//   S4  the def-use SHAPES differ in exactly the intended way, read back from emitted registers:
//         indep   every `vpblendmq` has s0 == s1 -- k component-local chains of length 1;
//         serial  no `vpblendmq` has s0 == s1, and the second of each member's pair READS THE
//                 FIRST'S DESTINATION -- one chain crossing the two components.
//   S5  planning and emission agree. Not asserted with a CHECK: `Emit_rvvtypedchunkend` Panics
//       when `rvv_typed_chunk_seen != rvv_typed_chunk_expected`, and `RvvEmitVectorRunGroup`
//       Panics when the emitting pass's `typed_ops` differs from the planning pass's. Reaching
//       the end of this function at all is the assertion.
struct ProbeShape {
	bool ok = false;
	unsigned n_probe = 0;	  // vpblendmq count
	unsigned same_src = 0;	  // probes whose two sources are the same register
	unsigned chained = 0;	  // probes reading a previous probe's destination
	unsigned n_load = 0, n_store = 0, n_lane = 0;
};

ProbeShape ReadProbeShape(Built &b)
{
	ProbeShape sh;
	auto const e = ReadEmitted(b);
	std::set<unsigned> probe_def; // physical zmm currently holding a probe result
	for (auto const &v : e.vecs) {
		if (v.kind == VecKind::Load) {
			++sh.n_load;
			probe_def.erase(v.d);
			continue;
		}
		if (v.kind == VecKind::Store) {
			++sh.n_store;
			continue;
		}
		if (v.kind != VecKind::Alu)
			continue;
		if (v.mnem != "vpblendmq") {
			++sh.n_lane;
			probe_def.erase(v.d); // a lane op overwrites whatever the register held
			continue;
		}
		++sh.n_probe;
		sh.same_src += v.s0 == v.s1;
		sh.chained += probe_def.count(v.s0) != 0 || probe_def.count(v.s1) != 0;
		probe_def.insert(v.d);
	}
	sh.ok = true;
	return sh;
}

void CheckLiveSplitDepth1Probe()
{
	printf("[P7L-B1-SPLIT] depth-1 dependence instrument in the live-split body: matched arms, "
	       "two shapes\n");
	// Two lane ops with a real cross-member dependence (vsub reads vadd's destination), which is
	// the member shape the accepted Blackscholes and LavaMD frames are made of. No memory member:
	// `split` is refused for a run with one, so this is the shape the split body actually sees.
	std::vector<u32> const words = {W_VSETVLI_E32M1, W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2};
	unsigned const n_vector_members = 2;
	for (u32 vlen : {512u, 1024u}) {
		unsigned const k = vlen / 512u;
		Built ind, ser;
		g_live_split = true;
		g_probe_depth = 1;
		g_probe_cross = false;
		Build(ind, words, vlen, /*vector_run=*/true);
		g_probe_cross = true;
		Build(ser, words, vlen, /*vector_run=*/true);
		g_live_split = false;
		g_probe_depth = 0;
		g_probe_cross = false;

		// -- S2 (and S1's precondition): matched size, count and multiset.
		//
		// IDENTITY IS NORMALIZED DISASSEMBLY, NOT RAW BYTES, for the reason `NormalizedDisasm`
		// states: in jit_mode `QEmit::make_stubcall_target` embeds the ABSOLUTE runtime address
		// of the helper stub, so two translations in the same process land on different
		// addresses and their raw bytes differ for a reason that has nothing to do with the
		// arms. Normalizing hex literals of six or more digits removes exactly those addresses;
		// every mnemonic, register number, CPUState displacement and intra-blob branch target
		// survives. This is the same level at which this file's pinned flag-off goldens are
		// compared, so it is the file's own definition of "the generated code is unchanged".
		unsigned nli = 0, nls = 0;
		std::string const di = NormalizedDisasm(ind.lines, &nli);
		std::string const ds = NormalizedDisasm(ser.lines, &nls);
		CHECK_EQ(ind.code.size(), ser.code.size());
		CHECK_EQ(nli, nls);
		auto ii = ParseInsns(ind.lines), si = ParseInsns(ser.lines);
		CHECK_EQ(ii.size(), si.size());
		std::map<std::string, unsigned> mi, ms;
		for (auto const &x : ii)
			++mi[x.text.substr(0, x.text.find(' '))];
		for (auto const &x : si)
			++ms[x.text.substr(0, x.text.find(' '))];
		CHECK(mi == ms);

		// -- S2 continued: the FRAME the two arms declared is the same frame. `probe_cross`
		// is not read by admission, by the descriptor or by the residency planner, so a
		// difference here would mean the two arms lowered different runs and the contrast
		// would not be single-factor.
		auto const fi = FindFrames(ind.region), fs = FindFrames(ser.region);
		CHECK_EQ(fi.size(), (size_t)1);
		CHECK_EQ(fs.size(), (size_t)1);
		if (fi.size() == 1 && fs.size() == 1) {
			CHECK_EQ((unsigned)fi[0].begin->n_typed, (unsigned)fs[0].begin->n_typed);
			CHECK_EQ((unsigned)fi[0].begin->n_members, (unsigned)fs[0].begin->n_members);
			CHECK_EQ(fi[0].body.size(), fs[0].body.size());
		}

		// -- S2 continued: NO SPILL AND NO ALLOCATOR MOVE inside the guarded body, on either
		// arm. A spill there is a `QEmit::Emit_mov` Panic rather than a slowdown, so this is
		// the assertion that the probe's temporaries were absorbed by the budget charge and
		// not by the allocator. Same predicate the P6C order checks use.
		for (int arm = 0; arm < 2; ++arm) {
			auto const &ab = (arm == 0 ? ind : ser);
			auto const ins = ParseInsns(ab.lines);
			auto const spans = FallbackSpans(ins);
			size_t const g = FirstGuardIndex(ins);
			size_t const stop = spans.empty() ? ins.size() : spans[0].first;
			unsigned moves = 0, stack = 0;
			for (size_t x = g; x < stop && x < ins.size(); ++x) {
				std::string const &t = ins[x].text;
				if (Has(t, "rsp") || Has(t, "rbp"))
					++stack;
				if (StartsWith(t, "vmovdqu64 "))
					continue;
				if (StartsWith(t, "mov ") && Has(t, "0xb8"))
					continue; // guest PC store
				if (StartsWith(t, "mov ") || StartsWith(t, "movabs "))
					++moves;
			}
			CHECK_EQ(moves, 0u);
			CHECK_EQ(stack, 0u);
		}

		ProbeShape const pi = ReadProbeShape(ind), ps = ReadProbeShape(ser);
		CHECK(pi.ok && ps.ok);
		// -- S2: identical state traffic and identical lane work.
		CHECK_EQ(pi.n_load, ps.n_load);
		CHECK_EQ(pi.n_store, ps.n_store);
		CHECK_EQ(pi.n_lane, ps.n_lane);
		CHECK_EQ(pi.n_lane, n_vector_members * k);
		// -- S3: exactly one probe per (member, component) at depth 1.
		CHECK_EQ(pi.n_probe, n_vector_members * k);
		CHECK_EQ(ps.n_probe, n_vector_members * k);

		if (k == 1) {
			// -- S1: byte identity. At k = 1 `probe_src[(c + 1) % k]` IS `probe_src[c]`,
			// so there is no operand left to differ and no special case is needed.
			CHECK(di == ds);
			// Both arms are therefore the degenerate "same source" shape.
			CHECK_EQ(pi.same_src, pi.n_probe);
			CHECK_EQ(ps.same_src, ps.n_probe);
			CHECK_EQ(pi.chained, 0u);
			CHECK_EQ(ps.chained, 0u);
			printf("    ok  vlen=512   k=1  arms IDENTICAL normalized disasm (%zu bytes), "
			       "%u probes, %u lane ops, loads=%u stores=%u\n",
			       ind.code.size(), pi.n_probe, pi.n_lane, pi.n_load, pi.n_store);
			continue;
		}

		// -- S1's converse: at k = 2 the arms must NOT be identical, or the serialised arm
		// would be testing nothing.
		CHECK(di != ds);
		// -- S4 indep: k component-local chains of length 1. Every probe reads one value
		// twice, so it cannot depend on the other component and cannot depend on another
		// probe.
		CHECK_EQ(pi.same_src, pi.n_probe);
		CHECK_EQ(pi.chained, 0u);
		// -- S4 serial: one chain crossing the components. No probe reads a single value
		// twice, and exactly one probe per member reads the other probe's destination.
		CHECK_EQ(ps.same_src, 0u);
		CHECK_EQ(ps.chained, n_vector_members);
		printf("    ok  vlen=1024  k=2  same %zu bytes / %zu insns / identical multiset; "
		       "indep %u local chains (same_src=%u chained=0), serial cross chain "
		       "(same_src=0 chained=%u); loads=%u stores=%u lane=%u both\n",
		       ind.code.size(), ii.size(), pi.n_probe, pi.same_src, ps.chained, pi.n_load,
		       pi.n_store, pi.n_lane);
	}
}

void CheckFrameCensusScope()
{
	printf("[P7M-E] frame census: registers only MULTI-member frames, emits one increment "
	       "each, and changes nothing else\n");
	// Two multi-member runs in ONE region, separated by a scalar barrier that cuts the run. This
	// is what makes `frame_index` a real assertion rather than a constant: a wiring bug that
	// always wrote 0, or that never reset per translation, fails here.
	std::vector<u32> const two_runs = {W_VSETVLI_E32M1, W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2, W_ADDI,
					   W_VMUL_V5_V3_V4,  W_VXOR_V6_V5_V4};
	for (u32 vlen : {512u, 1024u}) {
		unsigned const k = vlen / 512u;

		// (a) SWITCH OFF: nothing registered, nothing emitted -- in BOTH the run arm and the
		//     single-instruction arm.
		for (int arm = 0; arm < 3; ++arm) {
			size_t const before = CensusSnapshot().size();
			ArmBuild off;
			BuildArm(off, two_runs, vlen, arm, /*hit_counter=*/true,
				 /*frame_census=*/false);
			CHECK_EQ(CensusSnapshot().size() - before, (size_t)0);
			CHECK_EQ(CountCensusIncr(off.insns), 0u);
		}

		// (b) SWITCH ON, RUN ARM: exactly the two multi-member frames are registered, with
		//     ascending indices, this region's entry PC, their static member counts and k.
		size_t const before = CensusSnapshot().size();
		ArmBuild on, off;
		BuildArm(on, two_runs, vlen, /*arm=*/2, true, /*frame_census=*/true);
		BuildArm(off, two_runs, vlen, /*arm=*/2, true, /*frame_census=*/false);
		auto const snap = CensusSnapshot();
		CHECK_EQ(snap.size() - before, (size_t)2);
		if (snap.size() - before == 2) {
			for (unsigned f = 0; f < 2; ++f) {
				auto const &e = snap[before + f];
				CHECK_EQ((unsigned)e.tb_pc, 0u); // the harness's region entry ip
				CHECK_EQ((unsigned)e.frame_index, f);
				CHECK_EQ((unsigned)e.n_members, 2u);
				CHECK_EQ((unsigned)e.k, k);
				// Never executed here, so the slot must still read zero. This is
				// what makes "the increment is not on the translation path" an
				// assertion rather than a claim.
				CHECK_EQ((unsigned long long)e.count, 0ull);
			}
		}

		// (c) THE EMITTED DELTA IS EXACTLY THE INSTRUMENT: one increment pair per registered
		//     frame, two instructions each, and no other instruction moved.
		CHECK_EQ(CountCensusIncr(on.insns), 2u);
		CHECK_EQ((unsigned)on.insns.size() - (unsigned)off.insns.size(), 2u * 2u);

		// (d) NO HELPER AND NO FALLBACK EDGE IS INTRODUCED. The guard-miss counter is emitted
		//     once per frame on the fallback arm and is never gated, so an unchanged count is
		//     an unchanged set of fallback arms; the fallback spans are the calls themselves.
		CHECK_EQ(CountText(on.insns, FallbackIncText()),
			 CountText(off.insns, FallbackIncText()));
		CHECK_EQ(on.spans.size(), off.spans.size());
		// And the increment is on the FAST arm: no fallback span contains one.
		for (auto const &s : on.spans) {
			std::vector<Ins> span(on.insns.begin() + (long)s.first,
					      on.insns.begin() + (long)s.second);
			CHECK_EQ(CountCensusIncr(span), 0u);
		}

		// (e) SINGLE-MEMBER FRAMES ARE NOT REGISTERED. Arm 0 emits one typed frame per guest
		//     instruction; if those were counted, the census would answer the same ambiguous
		//     question `rvv_direct_hits` already answers.
		size_t const before_a0 = CensusSnapshot().size();
		ArmBuild a0;
		BuildArm(a0, two_runs, vlen, /*arm=*/0, true, /*frame_census=*/true);
		CHECK_EQ(CensusSnapshot().size() - before_a0, (size_t)0);
		CHECK_EQ(CountCensusIncr(a0.insns), 0u);
		printf("    ok  vlen=%-5u k=%u  2 frames registered (idx 0,1; members 2,2; k=%u), "
		       "+2 insns each, fallback arms and single-member frames untouched\n",
		       vlen, k, k);
	}
}

// [12] THE R1A.3d LEDGER, on the guard-hit path, in the emitted code, with the counter off,
//      because that is how the arms will be timed:
//
//        A - B = 7    one frame's guard (3 cmp + 3 jne) and its jmp over the fallback arm, for
//                     every shape and both widths -- the two bodies emit the same typed-op total
//                     as arm A does across its two frames, so only the scaffolding differs;
//        B - C = k    for the THREE REGISTERED SEQUENCES, whose second member's other source is a
//                     register the run does not produce. Stated generally, B - C is
//                     `(4m - (|live_in| + |live_out| + m)) * k`, and the registered dataflow makes
//                     that exactly k. Both forms are checked, so the specific claim cannot pass by
//                     accident and the general one cannot hide a shape-dependent bug.
struct LedgerCase {
	char const *name;
	std::vector<u32> words;
};

std::vector<LedgerCase> RegisteredSequences()
{
	return {
	    {"addsub", {W_VSETVLI_E32M1, W_OP_ADD, W_VSUB_V4_V3_V5}},
	    {"mulxor", {W_VSETVLI_E32M1, W_OP_MUL, W_VXOR_V4_V3_V5}},
	    {"orand", {W_VSETVLI_E32M1, W_OP_OR, W_VAND_V4_V3_V5}},
	};
}

void CheckArmLedger()
{
	printf("[12] emitted ledger with the counter off: A-B = 7 and B-C = k\n");
	for (u32 vlen : {512u, 1024u}) {
		unsigned const k = vlen / 512u;
		for (auto const &c : RegisteredSequences()) {
			// First pin the dataflow this claim depends on, from the admission scan.
			std::vector<u32> mem = {c.words[1], c.words[2]};
			ApplyConfig(vlen, true);
			auto const d = qir::rv32::RV32Translator::RvvAdmitVectorRun(
			    (uptr)mem.data(), 0u, 8u, 2u, dbt::rv32::VTYPE_E32_M1_TA_MA);
			CHECK_EQ((unsigned)d.n_members, 2u);
			CHECK_EQ((unsigned)__builtin_popcount(d.live_in_mask), 3u);
			CHECK_EQ((unsigned)__builtin_popcount(d.live_out_mask), 2u);

			ArmBuild a, b, cc;
			BuildArm(a, c.words, vlen, 0, false);
			BuildArm(b, c.words, vlen, 1, false);
			BuildArm(cc, c.words, vlen, 2, false);
			CHECK_EQ(a.spans.size(), (size_t)2);
			CHECK_EQ(b.spans.size(), (size_t)1);
			CHECK_EQ(cc.spans.size(), (size_t)1);
			if (a.spans.empty() || b.spans.empty() || cc.spans.empty())
				continue;
			unsigned const na = NonFallbackCount(a.insns, a.spans);
			unsigned const nb = NonFallbackCount(b.insns, b.spans);
			unsigned const nc = NonFallbackCount(cc.insns, cc.spans);
			CHECK_EQ(na - nb, 7u);
			CHECK_EQ(nb - nc, k);
			CHECK_EQ(CountText(a.insns, HitIncText()), 0u);
			CHECK_EQ(CountText(b.insns, HitIncText()), 0u);
			CHECK_EQ(CountText(cc.insns, HitIncText()), 0u);
			// The constant these counts carry -- prologue and region epilogue -- provably
			// cancels: the code after the last frame's join target is identical in all
			// three arms.
			std::string const ta =
			    MnemonicSeq(a.insns, a.spans.back().second, a.insns.size());
			std::string const tb =
			    MnemonicSeq(b.insns, b.spans.back().second, b.insns.size());
			std::string const tc =
			    MnemonicSeq(cc.insns, cc.spans.back().second, cc.insns.size());
			CHECK(ta == tb);
			CHECK(tb == tc);
			// The prologue -- everything before the first guard -- is the other half of
			// that constant, and it is byte-identical because nothing above the frame
			// changed at all.
			CHECK(SpanText(a.insns, 0, FirstGuardIndex(a.insns)) ==
			      SpanText(b.insns, 0, FirstGuardIndex(b.insns)));
			CHECK(SpanText(b.insns, 0, FirstGuardIndex(b.insns)) ==
			      SpanText(cc.insns, 0, FirstGuardIndex(cc.insns)));
			// And the A-B difference really is one guard plus its jmp, not something else
			// that happens to sum to seven.
			unsigned ca = 0, cb = 0, ja = 0, jb = 0;
			for (auto const &i : a.insns) {
				ca += StartsWith(i.text, "cmp ");
				ja += StartsWith(i.text, "jne ");
			}
			for (auto const &i : b.insns) {
				cb += StartsWith(i.text, "cmp ");
				jb += StartsWith(i.text, "jne ");
			}
			CHECK_EQ(ca - cb, 3u);
			CHECK_EQ(ja - jb, 3u);
			printf("    ok  %-8s vlen=%-4u A=%u B=%u C=%u  A-B=%u  B-C=%u  (k=%u)\n",
			       c.name, vlen, na, nb, nc, na - nb, nb - nc, k);
		}
	}

	// The general form, over all 36 ordered pairs at both widths: A - B is always 7, and B - C
	// is always what the descriptor's own dataflow predicts.
	unsigned pairs = 0;
	for (u32 vlen : {512u, 1024u}) {
		unsigned const k = vlen / 512u;
		for (auto const &ra : kRoutes) {
			for (auto const &rc : kRoutes) {
				std::vector<u32> const words = {W_VSETVLI_E32M1, ra.word, rc.word};
				std::vector<u32> mem = {ra.word, rc.word};
				ApplyConfig(vlen, true);
				auto const d = qir::rv32::RV32Translator::RvvAdmitVectorRun(
				    (uptr)mem.data(), 0u, 8u, 2u, dbt::rv32::VTYPE_E32_M1_TA_MA);
				unsigned const li = (unsigned)__builtin_popcount(d.live_in_mask);
				unsigned const lo = (unsigned)__builtin_popcount(d.live_out_mask);
				unsigned const want_bc = (4u * 2u - (li + lo + 2u)) * k;
				ArmBuild a, b, cc;
				BuildArm(a, words, vlen, 0, false);
				BuildArm(b, words, vlen, 1, false);
				BuildArm(cc, words, vlen, 2, false);
				unsigned const na = NonFallbackCount(a.insns, a.spans);
				unsigned const nb = NonFallbackCount(b.insns, b.spans);
				unsigned const nc = NonFallbackCount(cc.insns, cc.spans);
				CHECK_EQ(na - nb, 7u);
				CHECK_EQ(nb - nc, want_bc);
				++pairs;
			}
		}
	}
	printf("    ok  %u ordered pairs x VLEN: A-B = 7 always; B-C matches the descriptor's own "
	       "dataflow every time\n",
	       pairs);
}

// [13] A spill inside an open group is a Panic, not a slowdown, so "no allocator move" is a
//      correctness property of the admission bound -- and that bound now has to cover this body.
void CheckMaterializeAllocation()
{
	printf("[13] materialize body: no spill and no allocator move inside the guarded body\n");
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &c : ArmCases()) {
			ArmBuild ab;
			BuildArm(ab, c.words, vlen, 1, true);
			// A spill would have Panicked during emission, so reaching here is half the
			// proof; the other half is that nothing but the body's own vector traffic and
			// the guest-PC store sits between the guard and the join.
			CHECK(!ab.b.code.empty());
			CHECK_EQ(ab.spans.size(), (size_t)1);
			if (ab.spans.empty())
				continue;
			// Only the GUARDED BODY, from the guard's first compare to the join. The
			// region prologue above it legitimately contains scalar moves (the vsetvli
			// direct-state route writes four CPUState fields); a move there is not an
			// allocator move inside an open group and is not what this checks.
			unsigned moves = 0;
			for (size_t i = FirstGuardIndex(ab.insns); i < ab.spans[0].first; ++i) {
				std::string const &t = ab.insns[i].text;
				if (StartsWith(t, "vmovdqu64 "))
					continue; // the body's own CPUState traffic
				if (StartsWith(t, "mov ") && Has(t, "0xb8"))
					continue; // guest PC store
				if (StartsWith(t, "mov ") || StartsWith(t, "movabs "))
					++moves;
			}
			CHECK_EQ(moves, 0u);
		}
	}
	printf("    ok  four shapes x VLEN: guarded materialize body carries no allocator move\n");
}

// [14] Every architecturally legal operand overlap, under the materialize body. Load-major within
//      a member is a correctness property, not a scheduling preference.
void CheckMaterializeOverlap()
{
	printf("[14] materialize body: every architecturally legal operand overlap\n");
	struct Row {
		char const *name;
		u32 w0, w1;
	};
	Row const rows[] = {
	    {"vd==vs2 then use", W_VADD_V3_V3_V2, W_VSUB_V4_V3_V2},
	    {"vd==vs1 then use", W_VADD_V3_V1_V3, W_VSUB_V4_V3_V2},
	    {"vd==vs1==vs2", W_VADD_V3_V3_V3, W_VSUB_V4_V3_V2},
	    {"vs1==vs2", W_VADD_V3_V1_V1, W_VSUB_V4_V3_V2},
	    {"overwrite chain", W_VADD_V3_V3_V2, W_VSUB_V3_V3_V2},
	};
	for (auto const &r : rows) {
		for (u32 vlen : {512u, 1024u}) {
			u8 const k = (u8)(vlen / 512);
			ArmBuild ab;
			BuildArm(ab, {W_VSETVLI_E32M1, r.w0, r.w1}, vlen, 1, true);
			auto const frames = FindFrames(ab.b.region);
			CHECK_EQ(frames.size(), (size_t)1);
			if (frames.size() != 1)
				continue;
			auto const &f = frames[0];
			CHECK_EQ((unsigned)f.body.size(), 8u * k);
			// Per member: 2k loads, then k lane ops, then k stores. Both sources of every
			// chunk are read before any destination of that member is written, so all
			// three overlaps read the pre-instruction bytes.
			bool shape = true;
			for (unsigned m = 0; m < 2; ++m) {
				size_t const base = (size_t)m * 4u * k;
				for (unsigned c = 0; c < 2u * k; ++c)
					shape &= f.body[base + c]->GetOpcode() ==
						 Op::_vstatechunkload;
				for (unsigned c = 0; c < k; ++c)
					shape &= IsAluChunkOp(
					    f.body[base + 2u * k + c]->GetOpcode());
				for (unsigned c = 0; c < k; ++c)
					shape &= f.body[base + 3u * k + c]->GetOpcode() ==
						 Op::_vstatechunkstore;
			}
			CHECK(shape);
			// The emitted vector traffic matches: 4k loads and 2k stores regardless of
			// overlap, because every member goes through CPUState in this arm.
			auto const e = ReadEmitted(ab.b);
			unsigned n_load = 0, n_store = 0, n_alu = 0;
			for (auto const &v : e.vecs) {
				n_load += v.kind == VecKind::Load;
				n_store += v.kind == VecKind::Store;
				n_alu += v.kind == VecKind::Alu;
			}
			CHECK_EQ(n_load, 4u * k);
			CHECK_EQ(n_store, 2u * k);
			CHECK_EQ(n_alu, 2u * k);
			printf("    ok  %-18s vlen=%-4u loads=%u alus=%u stores=%u\n", r.name, vlen,
			       n_load, n_alu, n_store);
		}
	}
}

// [15] With the two new switches at their defaults, nothing moves. [1] already pins arm A's
//      flag-off bytes; this pins the CONSUMED-run path by showing the default IS the explicit
//      `ssa` + counter-on configuration, and that a single-member frame ignores both switches.
void CheckDefaultsUnchanged()
{
	printf("[15] the new switches at their defaults reproduce the accepted configuration\n");
	// Captured in main() before any test touched the globals, so this is the value a build
	// starts with and not whatever the previous section last applied.
	CHECK(g_startup_body_materialize == false);
	CHECK(g_startup_hit_counter == true);
	std::vector<u32> const one = {W_VSETVLI_E32M1, W_VADD_V3_V1_V2};
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &c : ArmCases()) {
			Built def;
			g_body_materialize = false;
			g_hit_counter = true;
			Build(def, c.words, vlen, true);
			ArmBuild ssa;
			BuildArm(ssa, c.words, vlen, 2, true);
			// Normalized disassembly, not raw bytes: two separately built regions embed
			// different absolute addresses for the branch-counter table and the helper
			// stubs, exactly as the flag-off goldens in [1] already account for.
			unsigned nd = 0, ns = 0;
			CHECK(NormalizedDisasm(def.lines, &nd) ==
			      NormalizedDisasm(ssa.b.lines, &ns));
			CHECK_EQ(nd, ns);
		}
		ArmBuild m1_ssa, m1_mat;
		BuildArm(m1_ssa, one, vlen, 2, true);
		BuildArm(m1_mat, one, vlen, 1, true);
		unsigned n1 = 0, n2 = 0;
		CHECK(NormalizedDisasm(m1_ssa.b.lines, &n1) == NormalizedDisasm(m1_mat.b.lines, &n2));
		CHECK_EQ(n1, n2);
		CHECK_EQ(m1_ssa.b.code.size(), m1_mat.b.code.size());
		CHECK_EQ(CountText(m1_ssa.insns, HitIncText()), 1u);
	}
	printf("    ok  default == explicit ssa with the counter on; a single-member frame is "
	       "identical in both bodies\n");
}

// [16] EVERY ACCEPTED ROUTE'S SINGLE-INSTRUCTION BODY IS THE SHARED CONSTRUCTION.
//
// This is the load-bearing structural claim of the whole ablation. Arm A minus arm B is supposed
// to be the guard scaffolding and NOTHING else, which is only true if arm A's per-instruction body
// and arm B's per-member body are the same construction for EVERY route -- not just for the two
// that happened to share a helper first. If `vmul` (say) kept its own hand-written body, the
// mulxor comparison would be resting on two emitters that currently agree by coincidence.
//
// Checked per route, at both widths, on the constructed QIR rather than on the disassembly: the
// single-instruction frame's body must be op-for-op and offset-for-offset identical to each member
// body of a two-member materialize run over the same instruction word.
void CheckEveryRouteSharesTheBody()
{
	printf("[16] all six accepted routes build their body with the shared construction\n");
	for (u32 vlen : {512u, 1024u}) {
		u8 const k = (u8)(vlen / 512);
		for (auto const &r : kRoutes) {
			// arm A: the accepted single-instruction frame for this route.
			ArmBuild single;
			BuildArm(single, {W_VSETVLI_E32M1, r.word}, vlen, 0, true);
			auto const sf = FindFrames(single.b.region);
			CHECK_EQ(sf.size(), (size_t)1);
			// arm B: a two-member materialize run over the SAME word twice, so both members
			// have the same operand windows as the single-instruction frame.
			ArmBuild run;
			BuildArm(run, {W_VSETVLI_E32M1, r.word, r.word}, vlen, 1, true);
			auto const rf = FindFrames(run.b.region);
			CHECK_EQ(rf.size(), (size_t)1);
			if (sf.size() != 1 || rf.size() != 1)
				continue;
			auto const &a = sf[0].body;
			auto const &b = rf[0].body;
			CHECK_EQ((unsigned)a.size(), 4u * k);
			CHECK_EQ((unsigned)b.size(), 8u * k);
			if (a.size() != 4u * k || b.size() != 8u * k)
				continue;
			// Both members of the run must reproduce the single-instruction body exactly.
			bool same = true;
			for (unsigned m = 0; m < 2; ++m) {
				for (unsigned i = 0; i < 4u * k; ++i) {
					Inst *x = a[i];
					Inst *y = b[m * 4u * k + i];
					same &= x->GetOpcode() == y->GetOpcode();
					if (x->GetOpcode() == Op::_vstatechunkload) {
						same &= ((InstVStateChunkLoad *)x)->offs ==
							((InstVStateChunkLoad *)y)->offs;
					} else if (x->GetOpcode() == Op::_vstatechunkstore) {
						same &= ((InstVStateChunkStore *)x)->offs ==
							((InstVStateChunkStore *)y)->offs;
					}
				}
			}
			CHECK(same);
			// And the lane operation really is this route's, so "identical" is not identical
			// to the WRONG operation.
			unsigned lane = 0;
			for (auto *ins : a)
				if (IsAluChunkOp(ins->GetOpcode()))
					lane += ins->GetOpcode() == AluOpFor(r.op);
			CHECK_EQ(lane, (unsigned)k);
			printf("    ok  %-8s vlen=%-4u single-instruction body == each run member body "
			       "(%u ops, offsets and lane op identical)\n",
			       r.name, vlen, (unsigned)a.size());
		}
	}
}

// R1A.3d generated-code census: the three arms side by side, for the implementation package.
void DumpArms(u32 vlen)
{
	static char const *kArmName[3] = {"A (per-instruction guard)", "B (shared guard, materialize)",
					  "C (shared guard, component SSA)"};
	for (auto const &c : ArmCases()) {
		for (int arm = 0; arm < 3; ++arm) {
			ArmBuild ab;
			BuildArm(ab, c.words, vlen, arm, false);
			unsigned const n = NonFallbackCount(ab.insns, ab.spans);
			printf("\n=== %s  vlen=%u  arm=%s  counter=off  bytes=%zu  insns=%zu  "
			       "guard-hit=%u  frames=%zu\n",
			       c.name, vlen, kArmName[arm], ab.b.code.size(), ab.insns.size(), n,
			       ab.spans.size());
			for (size_t i = 0; i < ab.insns.size(); ++i) {
				bool fb = false;
				for (auto const &sp : ab.spans)
					fb |= i >= sp.first && i < sp.second;
				printf("  %-9s %s\n", fb ? "[fallb]" : "", ab.insns[i].text.c_str());
			}
		}
	}
}

void DumpRepresentative()
{
	printf("\n[dump] add->sub at VLEN=512 and VLEN=1024, flag on\n");
	for (u32 vlen : {512u, 1024u}) {
		Built b;
		Build(b, {W_VSETVLI_E32M1, W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, vlen, true);
		printf("--- QIR, vlen=%u ---\n%s\n", vlen, qir::PrinterPass::run(b.region).c_str());
		printf("--- host code, vlen=%u ---\n", vlen);
		for (auto const &l : b.lines)
			printf("%s\n", l.c_str());
	}
}

// ---------------------------------------------------------------------------------------------
// M2E: TB-bounded, register-resident, width-correct runs.
//
// Everything above tests the two-member prototype. M2E removed that cap and replaced it with the
// three limits a run is actually representable-bounded by (rv32_vrun.h header): the translation
// block, the QIR node's typed-op count and member array, and the host vector register file. It
// also gave the run body ONE coherent chunk shape, so a run is width-correct at every VLEN the
// member route admits.
//
// The properties below are what "register-resident" means operationally, and each is checked
// separately because a lowering can satisfy some and not others:
//
//   E1  ONE frame per maximal run; live-ins loaded once; every intermediate an SSA value; the
//       final live-out stored once. Counted at all four widths.
//   E2  the frame's values carry the right TYPE and the emitted bytes the right WIDTH.
//   E3  at VLEN 1024 the low and high halves are register-disjoint across EVERY member, not just
//       inside one.
//   E4  the ordered fallback still names every member, in guest order, with its own guest PC; the
//       fast arm leaves the LAST member's PC.
//   E5  the bounds are derived, not literal, and the QIR capacity rule cuts rather than Panics.
// ---------------------------------------------------------------------------------------------

// A chain of `n` back-to-back `vadd.vv v8,v8,v9` -- the M1 shape: one accumulator, one invariant
// addend, so every member but the first reads the previous member's result.
constexpr u32 W_VADD_V8_V8_V9 = 0x02848457u; // vadd.vv v8, v8, v9 -- the exact M1 word

std::vector<u32> DepChain(unsigned n, bool with_vsetvli)
{
	std::vector<u32> w;
	if (with_vsetvli)
		w.push_back(W_VSETVLI_E32M1);
	for (unsigned i = 0; i < n; ++i)
		w.push_back(W_VADD_V8_V8_V9);
	return w;
}

struct M2EWidth {
	u32 vlen;
	u32 chunk_bytes;
	u32 k;
	VType vt;
	char const *reg;
};

M2EWidth const M2E_WIDTHS[] = {
    {128u, 16u, 1u, VType::V128, "xmm"},
    {256u, 32u, 1u, VType::V256, "ymm"},
    {512u, 64u, 1u, VType::V512, "zmm"},
    {1024u, 64u, 2u, VType::V512, "zmm"},
};

// E1 + E2: structure and width of one maximal run.
void M2E_CheckMaximalRun(M2EWidth const &w, unsigned n_members)
{
	// emit=false: this case inspects the QIR, and GenerateCode rewrites every register operand
	// in place to a PHYSICAL one, which would erase the def-use relation the residency check
	// below is about. The emitted side is M2E_CheckEmittedRun's job.
	Built b;
	Build(b, DepChain(n_members, true), w.vlen, true, /*emit=*/false);
	auto const frames = FindFrames(b.region);
	CHECK_EQ(frames.size(), (size_t)1);
	if (frames.size() != 1)
		return;
	auto const &f = frames[0];
	CHECK_EQ((unsigned)f.begin->n_members, n_members);

	// The whole point: ONE guard frame, live-ins loaded once, intermediates in SSA, live-out
	// stored once. live_in = {v8, v9}, live_out = {v8}, so the body is
	// (2 + 1 + n) * k typed ops with exactly 2k loads and 1k stores whatever n is.
	unsigned n_load = 0, n_add = 0, n_store = 0, n_other = 0;
	unsigned wrong_type = 0;
	for (auto *ins : f.body) {
		switch (ins->GetOpcode()) {
		case Op::_vstatechunkload:
			++n_load;
			wrong_type += ins->o(0).GetType() != w.vt;
			break;
		case Op::_vstatechunkstore:
			++n_store;
			wrong_type += ins->i(0).GetType() != w.vt;
			break;
		case Op::_vchunkadd:
			++n_add;
			wrong_type += ins->o(0).GetType() != w.vt || ins->i(0).GetType() != w.vt ||
				      ins->i(1).GetType() != w.vt;
			break;
		default:
			++n_other;
			break;
		}
	}
	CHECK_EQ(n_load, 2u * w.k);
	CHECK_EQ(n_add, n_members * w.k);
	CHECK_EQ(n_store, 1u * w.k);
	CHECK_EQ(n_other, 0u);
	CHECK_EQ(wrong_type, 0u);
	CHECK_EQ((unsigned)f.begin->n_typed, (2u + 1u + n_members) * w.k);

	// Register residency, stated as a dataflow fact: every add after the first reads a value
	// DEFINED BY AN EARLIER ADD in this frame, not loaded from CPUState. Counting the loads
	// alone would not say that -- 2k loads with n reloads hidden among them would give the same
	// total if the body also stored.
	std::vector<qir::RegN> defined;
	unsigned chained = 0, from_memory = 0;
	auto is_defined = [&](qir::RegN r) {
		return std::find(defined.begin(), defined.end(), r) != defined.end();
	};
	std::vector<qir::RegN> loaded;
	for (auto *ins : f.body) {
		if (ins->GetOpcode() == Op::_vstatechunkload && ins->o(0).IsVVPR())
			loaded.push_back(ins->o(0).GetVVPR());
	}
	for (auto *ins : f.body) {
		if (ins->GetOpcode() != Op::_vchunkadd)
			continue;
		for (auto opnd : {ins->i(0), ins->i(1)}) {
			if (!opnd.IsVVPR())
				continue;
			if (is_defined(opnd.GetVVPR()))
				++chained;
			else if (std::find(loaded.begin(), loaded.end(), opnd.GetVVPR()) != loaded.end())
				++from_memory;
		}
		if (ins->o(0).IsVVPR())
			defined.push_back(ins->o(0).GetVVPR());
	}
	// Each member reads two sources per chunk. The invariant addend v9 is always a live-in, and
	// the accumulator v8 is a live-in only for the FIRST member; every later member's accumulator
	// source is the previous member's SSA result.
	CHECK_EQ(chained, (n_members - 1) * w.k);
	CHECK_EQ(from_memory, (n_members + 1) * w.k);

	printf("    M2E vlen=%-5u n=%-3u frame: %u load / %u add / %u store, n_typed=%u, "
	       "%u chained SSA reads, all %s\n",
	       w.vlen, n_members, n_load, n_add, n_store, (unsigned)f.begin->n_typed, chained,
	       qir::vtype_names[to_underlying(w.vt)]);
}

// E2 (bytes) + E3: emitted width, and low/high register disjointness across EVERY member.
void M2E_CheckEmittedRun(M2EWidth const &w, unsigned n_members)
{
	Built b;
	Build(b, DepChain(n_members, true), w.vlen, true);
	CHECK(!b.code.empty());
	unsigned const want_bits = w.chunk_bytes * 8u;

	// Per lane, the set of vector registers the lane's adds use, over the whole run.
	std::vector<std::set<std::string>> lane_regs(w.k);
	std::vector<std::set<std::string>> per_add_regs;
	unsigned n_add = 0, wrong_width = 0;
	// The adds appear in member order, k per member: member i, chunk c is add i*k + c.
	for (auto const &l : b.lines) {
		std::string t = l;
		size_t tab = t.find('\t');
		if (tab == std::string::npos)
			continue;
		t = t.substr(tab + 1);
		while (!t.empty() && t[0] == '{')
			t = t.substr(t.find('}') + 2);
		if (t.compare(0, 7, "vpaddd ") != 0)
			continue;
		std::string ops = t.substr(7);
		unsigned lane = n_add % w.k;
		++n_add;
		per_add_regs.emplace_back();
		size_t pos = 0;
		while (pos < ops.size()) {
			size_t e = ops.find(',', pos);
			std::string tok = ops.substr(pos, e == std::string::npos ? e : e - pos);
			while (!tok.empty() && tok.front() == ' ')
				tok.erase(tok.begin());
			if (tok.compare(0, 3, w.reg) != 0)
				++wrong_width;
			lane_regs[lane].insert(tok);
			per_add_regs.back().insert(tok);
			if (e == std::string::npos)
				break;
			pos = e + 1;
		}
	}
	CHECK_EQ(n_add, n_members * w.k);
	CHECK_EQ(wrong_width, 0u);

	// Post-RA, every add's three operands are distinct registers -- an add whose destination
	// aliased a source would be a different instruction from the one the QIR describes.
	unsigned aliased = 0;
	for (auto const &regs : per_add_regs)
		aliased += regs.size() != 3;
	CHECK_EQ(aliased, 0u);

	if (w.k == 2) {
		// NOT asserted here: that the two lanes occupy disjoint register SETS over the whole
		// run. With 30 pool registers and n members the allocator necessarily recycles, and a
		// register the other lane reuses at a LATER member is a WAR/WAW that hardware renaming
		// removes -- it is not a dependence, and demanding otherwise would be demanding a
		// property of the register allocator rather than of the chains. The dependence
		// question is settled exactly, and pre-RA, by M2E_CheckLaneIndependence.
		printf("    M2E vlen=%u n=%u: %u adds (%u low, %u high), every add's 3 operands "
		       "distinct\n",
		       w.vlen, n_members, n_add, n_add / 2, n_add / 2);
	} else {
		printf("    M2E vlen=%u n=%u: %u x %s add, %zu distinct registers, all %u-bit\n",
		       w.vlen, n_members, n_add, w.reg, lane_regs[0].size(), want_bits);
	}
}


// E3: LANE INDEPENDENCE, decided on the def-use graph rather than on register numbers.
//
// "Two register-disjoint low/high chains across every member" is a statement about DEPENDENCE, and
// dependence lives in the SSA graph: after register allocation the two lanes necessarily share
// physical registers (there are 30 of them and 2n values), and a register the other lane reuses
// later is a WAR the hardware renames away. So this walks the frame's typed body, assigns every
// value a lane from the CPUState window its load or store names, and requires that no operation
// ever reads a value belonging to the other lane.
void M2E_CheckLaneIndependence(M2EWidth const &w, unsigned n_members)
{
	Built b;
	Build(b, DepChain(n_members, true), w.vlen, true, /*emit=*/false);
	auto const frames = FindFrames(b.region);
	CHECK_EQ(frames.size(), (size_t)1);
	if (frames.size() != 1)
		return;

	constexpr u32 slot = dbt::rv32::VLEN_MAX_BYTES;
	// The window offsets are absolute CPUState offsets, so the vreg array base has to come off
	// before the chunk index is read out of them -- vec.vreg starts at 208, not at 0.
	constexpr u32 vreg_base =
	    (u32)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
	auto lane_at = [&](u32 offs) -> unsigned {
		CHECK(offs >= vreg_base);
		return ((offs - vreg_base) % slot) / w.chunk_bytes;
	};
	std::map<qir::RegN, unsigned> lane_of;
	unsigned cross_lane_reads = 0, mismatched_add = 0, unlaned = 0;
	std::vector<unsigned> per_lane_adds(w.k, 0);

	for (auto *ins : frames[0].body) {
		switch (ins->GetOpcode()) {
		case Op::_vstatechunkload: {
			auto *l = static_cast<InstVStateChunkLoad *>(ins);
			// The lane is the chunk index inside the guest register the window names.
			lane_of[l->o(0).GetVVPR()] = lane_at(l->offs);
			break;
		}
		case Op::_vchunkadd: {
			auto *a = static_cast<InstVChunkAdd *>(ins);
			auto it0 = lane_of.find(a->i(0).GetVVPR());
			auto it1 = lane_of.find(a->i(1).GetVVPR());
			if (it0 == lane_of.end() || it1 == lane_of.end()) {
				++unlaned;
				break;
			}
			if (it0->second != it1->second) {
				++mismatched_add; // one add reading both lanes
				++cross_lane_reads;
			}
			CHECK(it0->second < w.k);
			if (it0->second < w.k)
				per_lane_adds[it0->second]++;
			lane_of[a->o(0).GetVVPR()] = it0->second;
			break;
		}
		case Op::_vstatechunkstore: {
			auto *st = static_cast<InstVStateChunkStore *>(ins);
			unsigned const want = lane_at(st->offs);
			auto it = lane_of.find(st->i(0).GetVVPR());
			if (it == lane_of.end())
				++unlaned;
			else if (it->second != want)
				++cross_lane_reads; // a lane's result stored into the other's window
			break;
		}
		default:
			break;
		}
	}
	CHECK_EQ(unlaned, 0u);
	CHECK_EQ(mismatched_add, 0u);
	CHECK_EQ(cross_lane_reads, 0u);
	for (unsigned c = 0; c < w.k; ++c)
		CHECK_EQ(per_lane_adds[c], n_members);
	printf("    M2E vlen=%-5u n=%-3u lanes=%u: %u adds per lane, 0 cross-lane reads, "
	       "0 mixed-lane adds\n",
	       w.vlen, n_members, w.k, n_members);
}

// E4: the ordered fallback names every member, in guest order, each with its own guest PC; the
// fast arm leaves the LAST member's PC.
void M2E_CheckOrderedFallback(unsigned n_members)
{
	Built b;
	Build(b, DepChain(n_members, true), 512u, true);
	auto const frames = FindFrames(b.region);
	CHECK_EQ(frames.size(), (size_t)1);
	if (frames.size() != 1)
		return;
	CHECK_EQ((unsigned)frames[0].end->n_members, n_members);
	for (unsigned i = 0; i < n_members; ++i) {
		// pc of member i is 4 (the vsetvli) + 4*i.
		CHECK_EQ(frames[0].end->members[i].pc, 4u + 4u * i);
		CHECK_EQ(frames[0].end->members[i].raw, W_VADD_V8_V8_V9);
	}
	// Emitted: one guest-PC store per member on the fallback arm, plus one on the fast arm for
	// the last member, and one helper call per member.
	// Count the MEMBER helper calls by the raw word each one passes, not every call in the
	// listing: the block also calls the vsetvli helper and its own exit stub.
	unsigned n_member_args = 0, n_ip_stores = 0;
	for (auto const &l : b.lines) {
		if (l.find("mov    rsi,0x2848457") != std::string::npos)
			++n_member_args;
		if (l.find("mov    DWORD PTR [r13+0xb8]") != std::string::npos)
			++n_ip_stores;
	}
	CHECK_EQ(n_member_args, n_members);
	// One guest-PC store per member on the ordered fallback arm, plus the fast arm's single
	// store of the LAST member's pc, plus the frame-external ones for the other instructions.
	CHECK(n_ip_stores >= n_members + 1);
	printf("    M2E ordered fallback: %u members, %u member helper calls, %u guest-PC stores\n",
	       n_members, n_member_args, n_ip_stores);
}


// E4b: the FALLBACK REPRESENTATION invariants, checked as refusals rather than as things the
// current translator happens to get right. Each builds a malformed member list directly and
// requires construction to Panic; run in forked children because a Panic aborts.
template <typename F>
void M2E_ExpectPanic(char const *what, F &&fn)
{
	fflush(stdout);
	fflush(stderr);
	pid_t pid = fork();
	if (pid == 0) {
		fn();
		_exit(0); // reached only if the malformed list was accepted
	}
	int status = 0;
	if (waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "  FAIL %s: waitpid\n", what);
		++g_failures;
		return;
	}
	bool const refused = WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT;
	if (!refused) {
		fprintf(stderr, "  FAIL %s: malformed member list ACCEPTED\n", what);
		++g_failures;
		return;
	}
	printf("    refused: %s\n", what);
}

void M2E_CheckFallbackInvariants()
{
	printf("[M2E] the ordered fallback's member list is validated, not assumed\n");
	auto make = [](unsigned n, bool consecutive, bool with_pc) {
		std::vector<qir::RVVRunMember> m(n);
		for (unsigned i = 0; i < n; ++i) {
			m[i].raw = W_VADD_V8_V8_V9;
			m[i].stub = RuntimeStubId::id_rv32_vadd_vv;
			if (with_pc)
				m[i].pc = consecutive ? 4u * i : 4u * i + (i ? 4u : 0u);
		}
		return m;
	};
	// A multi-member run whose members have no guest PC: the ordered fallback arm would call
	// each helper without setting state->ip, so a trap inside member i would report member 0's
	// PC. This is exactly the invariant M2E's larger runs make load-bearing.
	M2E_ExpectPanic("a multi-member run with no per-member guest PC", [&] {
		auto m = make(4, true, /*with_pc=*/false);
		qir::InstRVVTypedChunkEnd node(m.data(), 4);
		(void)node;
	});
	// Members must be CONSECUTIVE guest instructions: the fallback arm reproduces the guest
	// sequence, so a gap would silently skip an instruction.
	M2E_ExpectPanic("a run whose members are not consecutive guest instructions", [&] {
		auto m = make(4, /*consecutive=*/false, true);
		qir::InstRVVTypedChunkEnd node(m.data(), 4);
		(void)node;
	});
	// More members than the frame can carry.
	M2E_ExpectPanic("a run larger than the frame's member capacity", [&] {
		auto m = make(qir::RVV_RUN_MAX_MEMBERS + 1u, true, true);
		qir::InstRVVTypedChunkEnd node(m.data(), qir::RVV_RUN_MAX_MEMBERS + 1u);
		(void)node;
	});
	// A member with no fallback stub: the arm would have nothing to call.
	M2E_ExpectPanic("a run member with no fallback stub", [&] {
		auto m = make(4, true, true);
		m[2].stub = RuntimeStubId::Count;
		qir::InstRVVTypedChunkEnd node(m.data(), 4);
		(void)node;
	});
}

// E5: the bounds are DERIVED. These are compile-time facts; asserting them here is what makes a
// future edit that reintroduces a literal cap fail this test rather than pass silently.
void M2E_CheckDerivedBounds()
{
	printf("[M2E] the run bound is derived from representation limits, not chosen\n");
	static_assert(rvvrun::kMaxRunMembers == dbt::rv32::TB_MAX_INSNS,
		      "the run bound must be the translation block's instruction bound");
	static_assert(qir::RVV_RUN_MAX_MEMBERS == rvvrun::kMaxRunMembers,
		      "the QIR frame must carry every member the scan can admit");
	static_assert(rvvrun::kMaxDescriptorMembers == rvvrun::kMaxRunMembers, "");
	CHECK_EQ((unsigned)rvvrun::kMaxRunMembers, (unsigned)dbt::rv32::TB_MAX_INSNS);
	CHECK((unsigned)rvvrun::kMaxRunMembers > 2u); // the prototype cap is gone

	// The typed-op capacity rule is body-independent and is the one the scan uses.
	// The rule is the MAX of the two bodies, so it is body-independent: admission cannot depend
	// on which body mode is configured.
	CHECK_EQ(rvvrun::RvvRunTypedOpCount(2, 1, 64, 1), 256u); // 4*64 materialize > 67 ssa
	CHECK_EQ(rvvrun::RvvRunTypedOpCount(2, 1, 4, 1), 16u);   // 4*4 materialize > 7 ssa
	CHECK_EQ(rvvrun::RvvRunTypedOpCount(2, 1, 64, 2), 512u);
	printf("    kMaxRunMembers=%u == TB_MAX_INSNS, RVV_RUN_MAX_MEMBERS=%u, capacity=%u\n",
	       (unsigned)rvvrun::kMaxRunMembers, (unsigned)qir::RVV_RUN_MAX_MEMBERS,
	       (unsigned)rvvrun::kMaxTypedOpsPerFrame);
}

// E5 (dynamic): the QIR node can represent every run the other two limits admit, and a run that
// could not fit would be CUT during the scan rather than Panicked at emit time.
void M2E_CheckCapacityCut()
{
	// The largest body any admitted run can ask for, at the widest admitted chunk count.
	CHECK(rvvrun::RvvRunTypedOpCount(2, 1, rvvrun::kMaxRunMembers, rvvrun::kMaxChunks) <=
	      rvvrun::kMaxTypedOpsPerFrame);
	// ...and the rule really does refuse something: it is a bound, not a tautology.
	CHECK(rvvrun::RvvRunTypedOpCount(2, 1, 255, 255) > rvvrun::kMaxTypedOpsPerFrame);
	Built b;
	Build(b, DepChain(80, true), 512u, true, /*emit=*/false);
	auto const frames = FindFrames(b.region);
	CHECK(!frames.empty());
	unsigned total_members = 0, max_members = 0;
	for (auto const &f : frames) {
		total_members += f.begin->n_members;
		max_members = std::max<unsigned>(max_members, f.begin->n_members);
		CHECK((unsigned)f.begin->n_typed <= (unsigned)rvvrun::kMaxTypedOpsPerFrame);
	}
	// THE TB BOUND, observed rather than asserted from the constant: the ip range offers 80
	// adds, but a translation block holds TB_MAX_INSNS guest instructions and the vsetvli is one
	// of them, so 63 adds are translated at all -- and they form ONE run. The stream is bounded
	// by the block, not by a member cap and not by the QIR node.
	CHECK_EQ(total_members, (unsigned)dbt::rv32::TB_MAX_INSNS - 1u);
	CHECK_EQ(frames.size(), (size_t)1);
	CHECK(max_members <= (unsigned)rvvrun::kMaxRunMembers);
	printf("    M2E TB bound: 80 adds offered -> %zu frame(s), %u members (TB_MAX_INSNS-1), "
	       "every n_typed <= %u\n",
	       frames.size(), max_members, (unsigned)rvvrun::kMaxTypedOpsPerFrame);
}

// Termination: the largest run the bounds permit must translate AND generate code without
// hanging. Run in a forked child under an alarm so a regression is a named failure, not a hung
// test binary -- the same discipline M2B's allocator regression uses, and it covers the same
// allocator: a 63-member run at VLEN 1024 creates far more QIR virtual registers than the
// two-member prototype ever did.
void M2E_CheckTermination()
{
	printf("[M2E] the largest admitted run translates and generates code\n");
	for (auto const &w : M2E_WIDTHS) {
		fflush(stdout);
		fflush(stderr);
		pid_t pid = fork();
		if (pid == 0) {
			alarm(60);
			Built b;
			Build(b, DepChain(80, true), w.vlen, true);
			_exit(b.code.empty() ? 2 : 0);
		}
		int status = 0;
		CHECK(waitpid(pid, &status, 0) == pid);
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "  FAIL M2E termination vlen=%u: signal %d%s\n", w.vlen,
				WTERMSIG(status),
				WTERMSIG(status) == SIGALRM ? " (watchdog)" : "");
			++g_failures;
			continue;
		}
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		printf("    vlen=%u: 80-add chain translated and emitted\n", w.vlen);
	}
}

void M2E_CheckAll()
{
	printf("--- M2E TB-bounded register-resident runs ---\n");
	M2E_CheckDerivedBounds();
	printf("[M2E] one maximal run per block: structure and value types\n");
	for (auto const &w : M2E_WIDTHS)
		for (unsigned n : {13u, 51u, 63u})
			M2E_CheckMaximalRun(w, n);
	printf("[M2E] emitted width, operand distinctness and lane independence\n");
	for (auto const &w : M2E_WIDTHS)
		M2E_CheckEmittedRun(w, 51u);
	for (auto const &w : M2E_WIDTHS)
		for (unsigned n : {13u, 51u, 63u})
			M2E_CheckLaneIndependence(w, n);
	printf("[M2E] ordered fallback and precise guest PC\n");
	M2E_CheckOrderedFallback(13u);
	M2E_CheckOrderedFallback(51u);
	M2E_CheckFallbackInvariants();
	printf("[M2E] QIR typed-op capacity cuts rather than Panics\n");
	M2E_CheckCapacityCut();
	M2E_CheckTermination();
}

// ---------------------------------------------------------------------------------------------
// M2F: the materialize arm's typed-op DECLARATION must reach the QIR node intact.
//
// M2E widened InstRVVTypedChunkBegin::n_typed, QEmit's expected/seen pair and llvmgen's
// tchunk_expected to u16, but RvvEmitVectorRunGroup still passed `(u8)n_typed`. Builder::Create_*
// forwards perfectly, so the argument was deduced as u8 and only widened back at the constructor,
// after the high bits were gone.
//
// WHY NOTHING CAUGHT IT. The SSA body is (|live_in| + |live_out| + m) * k, at most 134 for the
// largest admissible run, so arm C fits in a u8 at every supported shape and can never expose the
// truncation. Every pre-existing materialize case built a two-member run, where 4*m*k is 8 or 16.
// The one place the arithmetic WAS checked -- M2E_CheckCapacityCut's
// `RvvRunTypedOpCount(2,1,64,1) == 256` -- tests the capacity rule, not the transport of its
// result into the node. So the tests covered the number and the field, and not the assignment
// between them.
//
// This case is the missing one: a FULL 64-member materialize run, whose declaration is 256 typed
// ops at k=1 and 512 at k=2 -- the first shapes that do not fit a u8.
// ---------------------------------------------------------------------------------------------

// 64 adds and NO vsetvli. A translation block holds TB_MAX_INSNS instructions, so DepChain(n,true)
// spends one slot on the vsetvli and can never reach more than 63 members; only this shape reaches
// a full 64. The run still forms: FormRun takes the candidate vtype the single-instruction routes
// propose when no in-block vsetvli was observed, and the emitted guard proves it at run time.
unsigned const M2F_FULL_MEMBERS = (unsigned)dbt::rv32::TB_MAX_INSNS;

void M2F_CheckMaterializeDeclarationNotTruncated()
{
	printf("[M2F] materialize declaration survives the node: full %u-member frame, all widths\n",
	       M2F_FULL_MEMBERS);
	// Stated as arithmetic first, so the test says what it is defending rather than only
	// exercising it: these are the two counts the M3 B arm needs, and both exceed a u8.
	CHECK_EQ(4u * M2F_FULL_MEMBERS * 1u, 256u);
	CHECK_EQ(4u * M2F_FULL_MEMBERS * 2u, 512u);
	CHECK(4u * M2F_FULL_MEMBERS * 1u > 255u);

	for (auto const &w : M2E_WIDTHS) {
		unsigned const k = w.k;
		unsigned const want_materialize = 4u * M2F_FULL_MEMBERS * k;

		// --- arm B (materialize), QIR ---
		Built b;
		g_body_materialize = true;
		Build(b, DepChain(M2F_FULL_MEMBERS, false), w.vlen, true, /*emit=*/false);
		g_body_materialize = false;
		auto const bf = FindFrames(b.region);
		CHECK_EQ(bf.size(), (size_t)1);
		if (bf.size() != 1)
			continue;
		CHECK_EQ((unsigned)bf[0].begin->n_members, M2F_FULL_MEMBERS);
		// THE REGRESSION. Under the defect this was (u8)256 == 0 and (u8)512 == 0.
		CHECK_EQ((unsigned)bf[0].begin->n_typed, want_materialize);
		// ...and the declaration matches the body that is actually there, op for op.
		unsigned n_load = 0, n_store = 0, n_alu = 0;
		for (auto *ins : bf[0].body) {
			n_load += ins->GetOpcode() == Op::_vstatechunkload;
			n_store += ins->GetOpcode() == Op::_vstatechunkstore;
			n_alu += IsAluChunkOp(ins->GetOpcode());
		}
		CHECK_EQ((unsigned)bf[0].body.size(), want_materialize);
		CHECK_EQ(n_load, 2u * M2F_FULL_MEMBERS * k);
		CHECK_EQ(n_alu, 1u * M2F_FULL_MEMBERS * k);
		CHECK_EQ(n_store, 1u * M2F_FULL_MEMBERS * k);
		CHECK_EQ(n_load + n_alu + n_store, want_materialize);

		// --- arm C (ssa), same words, same width: the contrast that explains the miss ---
		Built c;
		Build(c, DepChain(M2F_FULL_MEMBERS, false), w.vlen, true, /*emit=*/false);
		auto const cf = FindFrames(c.region);
		CHECK_EQ(cf.size(), (size_t)1);
		if (cf.size() != 1)
			continue;
		unsigned const want_ssa = (2u + 1u + M2F_FULL_MEMBERS) * k;
		CHECK_EQ((unsigned)cf[0].begin->n_typed, want_ssa);
		CHECK((unsigned)cf[0].begin->n_typed <= 255u); // why arm C never exposed the defect
		CHECK(want_materialize > (unsigned)cf[0].begin->n_typed);

		// --- item 2: B and C differ ONLY in the body ---
		// Same admission (one frame, same member count), same single guard, same ordered
		// fallback member list. If the materialize switch had leaked into admission, the
		// descriptor or the guard, one of these would differ.
		CHECK_EQ((unsigned)bf[0].begin->n_members, (unsigned)cf[0].begin->n_members);
		CHECK_EQ(bf[0].begin->vtype, cf[0].begin->vtype);
		CHECK_EQ(bf[0].begin->vlmax, cf[0].begin->vlmax);
		CHECK_EQ(bf[0].begin->raw, cf[0].begin->raw);
		CHECK((unsigned)bf[0].begin->guard_kind == (unsigned)cf[0].begin->guard_kind);
		CHECK_EQ((unsigned)bf[0].begin->stub, (unsigned)cf[0].begin->stub);
		CHECK_EQ((unsigned)bf[0].end->n_members, (unsigned)cf[0].end->n_members);
		for (unsigned i = 0; i < M2F_FULL_MEMBERS; ++i) {
			CHECK_EQ(bf[0].end->members[i].pc, cf[0].end->members[i].pc);
			CHECK_EQ(bf[0].end->members[i].raw, cf[0].end->members[i].raw);
			CHECK_EQ((unsigned)bf[0].end->members[i].stub,
				 (unsigned)cf[0].end->members[i].stub);
		}
		// The ONE thing that may differ: the body.
		CHECK(bf[0].body.size() != cf[0].body.size());

		// --- the emitter agrees: begin declared == seen == end ---
		// Emit_rvvtypedchunkend Panics unless the emitter saw exactly n_typed typed body ops,
		// so reaching non-empty code IS the begin/seen/end agreement. Run in a forked child so
		// a regression is a named failure rather than an aborted test binary.
		fflush(stdout);
		fflush(stderr);
		pid_t pid = fork();
		if (pid == 0) {
			alarm(120);
			Built e;
			g_body_materialize = true;
			Build(e, DepChain(M2F_FULL_MEMBERS, false), w.vlen, true);
			g_body_materialize = false;
			_exit(e.code.empty() ? 2 : 0);
		}
		CHECK(pid > 0);
		int status = 0;
		CHECK(waitpid(pid, &status, 0) == pid);
		CHECK(WIFEXITED(status));
		CHECK_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
		printf("    ok  vlen=%-5u k=%u  materialize n_typed=%-4u (ssa %u) declared==body==emitted\n",
		       w.vlen, k, want_materialize, want_ssa);
	}
}

// ---------------------------------------------------------------------------------------------
// [P6C] P6A ESTIMAND D: the sibling-chunk ISSUE-ORDER ablation.
//
// WHAT THIS SECTION HAS TO PROVE. `--rvv-run-order=chunk` swaps the member loop and the chunk loop
// of the vector-run SSA body and does NOTHING else. That claim is only worth anything if all of
// the following are checked, because each one is a way the switch could have quietly become a
// second factor:
//
//   D1 the switch never reaches admission -- identical descriptor and identical scan stats;
//   D2 the QIR frame is the same frame -- same vtype, vlmax, member list, n_typed, and the same
//      multiset of body ops, with pass 1's loads still all first and pass 3's stores still all
//      last, at the same CPUState displacements;
//   D3 the emitted host instruction MULTISET is identical, with zero spill and no extra call;
//   D4 the guard, the join and the ordered fallback arm are byte-identical (after the usual
//      absolute-address normalisation), as is the prologue;
//   D5 the dataflow SHAPE is identical -- k equal-length chains, every lane op reading only its
//      own chunk -- while the ISSUE ORDER is exactly the expected permutation;
//   D6 at k = 1 the two arms are the SAME CODE, because the two nestings coincide when there is
//      one chunk. This is the harness's own falsification check: if D5's order reconstruction
//      were reading noise, or if the switch leaked into anything but the loop nesting, k = 1
//      would not come out identical.
//
// D5 is the load-bearing one and it is deliberately not phrased as "the two arms differ". A test
// that only demanded a difference would pass if the switch corrupted the body. It asserts the
// exact expected permutation on BOTH arms, reconstructed from the emitted register def-use graph.
//
// Nothing here is timed, and nothing here claims either order is faster. Whether the ordering
// changes execution time is Estimand D's measurement, which this checkpoint does not perform.
// ---------------------------------------------------------------------------------------------

// vadd.vv encodings for the chain shapes, assembled with the same xPack riscv-none-elf 14.2.0
// toolchain and read back out of objdump as every other constant in this file was.
// W_VADD_V8_V8_V9 (0x02848457) is already defined above by the M2E section and is the exact M1
// chain word; these two are its siblings. Re-assembled and read back out of objdump for this
// checkpoint, which is also how the shared constant was re-confirmed.
constexpr u32 W_VADD_V10_V10_V9 = 0x02a48557u; // vadd.vv v10,v10,v9 (M4A chain B)
constexpr u32 W_VADD_V4_V4_V2 = 0x02410257u;   // vadd.vv v4,v4,v2

struct OrderCase {
	char const *name;
	std::vector<u32> words;
	unsigned n_members;
};

// The guest shapes the ablation has to hold for. `serial8`/`serial16` are the M4A/EXP1M chain
// itself -- one accumulator, one addend, every member reading the previous member's result -- and
// `twin8` is M4A's two-accumulator interleave, so a run whose members are NOT one chain is covered
// too. The registered two-member pairs are included because they are the shapes every other
// section of this file already pins.
std::vector<OrderCase> OrderCases()
{
	std::vector<u32> serial8 = {W_VSETVLI_E32M1};
	for (unsigned i = 0; i < 8; ++i)
		serial8.push_back(W_VADD_V8_V8_V9);
	std::vector<u32> serial16 = {W_VSETVLI_E32M1};
	for (unsigned i = 0; i < 16; ++i)
		serial16.push_back(W_VADD_V8_V8_V9);
	std::vector<u32> twin8 = {W_VSETVLI_E32M1};
	for (unsigned i = 0; i < 4; ++i) {
		twin8.push_back(W_VADD_V8_V8_V9);
		twin8.push_back(W_VADD_V10_V10_V9);
	}
	return {
	    {"serial8", serial8, 8},
	    {"serial16", serial16, 16},
	    {"twin8", twin8, 8},
	    {"addsub", {W_VSETVLI_E32M1, W_VADD_V3_V1_V2, W_VSUB_V4_V3_V2}, 2},
	    {"overwrite", {W_VSETVLI_E32M1, W_VADD_V3_V3_V2, W_VSUB_V3_V3_V2}, 2},
	    {"two-chain2", {W_VSETVLI_E32M1, W_VADD_V3_V3_V2, W_VADD_V4_V4_V2}, 2},
	};
}

// P6C-R (2026-09-10). THE SEVEN MEMBER KINDS THE PRE-REPAIR GATE COULD NOT SEE.
//
// Five of these -- MulX, MAccX, LoadWhole, StoreWhole and Mov -- were refused by
// RvvRunMemberChunks whenever chunk-major order was selected, because the chunk-major arm of
// RvvEmitVectorRunGroup was a second, smaller copy of the member loop with no arm for them. The
// repair deleted that copy and made the arm call the shared `emit_members` one component at a
// time, so the refusals could go. FAlu and FMA were never refused by the order flag, but they were
// equally invisible to the old gate: their route switch is off in the accepted ApplyConfig.
//
// Every word below was assembled with the same xPack riscv-none-elf toolchain the rest of this
// file's constants came from and read back out of objdump:
//
//   02876407  vl1re32.v v8,(a4)      02870427  vs1r.v    v8,(a4)
//   9685e457  vmul.vx   v8,v8,a1     b68be4d7  vmacc.vx  v9,s7,v8
//   02849457  vfadd.vv  v8,v8,v9     b2a414d7  vfmacc.vv v9,v8,v10
//   a2a414d7  vfmadd.vv v9,v8,v10
//   5e02b457  vmv.v.i   v8,5         5e05c4d7  vmv.v.x   v9,a1
//   5e065557  vfmv.v.f  v10,fa2      5e0485d7  vmv.v.v   v11,v9
//   02858657  vadd.vv   v12,v8,v11
constexpr u32 W_VL1RE32_V8_A4 = 0x02876407u;
constexpr u32 W_VS1R_V8_A4 = 0x02870427u;
constexpr u32 W_VMUL_VX_V8_V8_A1 = 0x9685e457u;
constexpr u32 W_VMACC_VX_V9_S7_V8 = 0xb68be4d7u;
constexpr u32 W_VFADD_VV_V8_V8_V9 = 0x02849457u;
constexpr u32 W_VFMACC_VV_V9_V8_V10 = 0xb2a414d7u;
constexpr u32 W_VFMADD_VV_V9_V8_V10 = 0xa2a414d7u;
constexpr u32 W_VMV_V_I_V8_5 = 0x5e02b457u;
constexpr u32 W_VMV_V_X_V9_A1 = 0x5e05c4d7u;
constexpr u32 W_VFMV_V_F_V10_FA2 = 0x5e065557u;
constexpr u32 W_VMV_V_V_V11_V9 = 0x5e0485d7u;
constexpr u32 W_VADD_V12_V8_V11 = 0x02858657u;

// FormRun refuses to put a memory member and an FP member in one run, so the memory/OPMVX kinds
// and the FP kinds are separate cases rather than one long list. `n_members` is the count the
// descriptor must report in BOTH arms; it is written here rather than read back, so a repair that
// silently admitted fewer members would fail rather than redefine the expectation.
std::vector<OrderCase> ExtendedOrderCases()
{
	return {
	    // LoadWhole, MulX, MAccX, StoreWhole -- the G1 load -> .vx -> store dataflow.
	    {"mem-vx",
	     {W_VSETVLI_E32M1, W_VL1RE32_V8_A4, W_VMUL_VX_V8_V8_A1, W_VMACC_VX_V9_S7_V8,
	      W_VS1R_V8_A4},
	     4},
	    // Mov in all four source forms (imm, x-scalar, f-scalar, vector rename) plus one
	    // arithmetic member that consumes a moved value.
	    {"moves",
	     {W_VSETVLI_E32M1, W_VMV_V_I_V8_5, W_VMV_V_X_V9_A1, W_VFMV_V_F_V10_FA2,
	      W_VMV_V_V_V11_V9, W_VADD_V12_V8_V11},
	     5},
	    // FAlu and both FMA operand roles (vd as addend, vd as multiplicand).
	    {"fp",
	     {W_VSETVLI_E32M1, W_VFADD_VV_V8_V8_V9, W_VFMACC_VV_V9_V8_V10,
	      W_VFMADD_VV_V9_V8_V10},
	     3},
	};
}

void BuildOrderArm(ArmBuild &ab, std::vector<u32> const &words, u32 vlen, bool chunk_major)
{
	g_run_order_chunk_major = chunk_major;
	Build(ab.b, words, vlen, true);
	g_run_order_chunk_major = false;
	ab.insns = ParseInsns(ab.b.lines);
	for (size_t i = ab.insns.size(); i-- > 0;) {
		if (ab.insns[i].text == "call   rax") {
			ab.insns.resize(i + 1);
			break;
		}
	}
	ab.spans = FallbackSpans(ab.insns);
}

// The chunk index a CPUState vector displacement names. `slot` is the per-register reservation and
// `stride` the distance between consecutive chunks, both derived from the declarations rather than
// written as literals, for the reason ST_VTYPE's comment gives.
int ChunkOfDisp(u32 disp, u32 stride)
{
	if (disp < ST_VREG_BASE)
		return -1;
	u32 const slot = dbt::rv32::VLEN_MAX_BYTES;
	u32 const within = (disp - ST_VREG_BASE) % slot;
	if (within % stride != 0)
		return -1;
	return (int)(within / stride);
}

// The emitted body's def-use graph, reconstructed in program order from the physical ZMM registers.
// Physical registers are reused, so this walks the frame once and lets each write take ownership --
// which is exactly what a def-use reconstruction is, and is why it can be done on the allocated
// code at all.
struct OrderShape {
	bool ok = false;
	std::vector<int> alu_chunk;  // chunk label of each lane op, in EMISSION order
	std::vector<int> alu_index;  // its position within that chunk's chain
	std::vector<unsigned> chain_len; // lane ops per chunk
	unsigned n_load = 0, n_store = 0, n_alu = 0;
	bool linear_chain = true;    // every lane op after the first reads its chunk's previous def
	unsigned cross_chunk = 0;    // lane ops whose two sources are labelled differently
};

OrderShape ReadOrderShape(Built &b, u32 stride, unsigned k)
{
	OrderShape sh;
	auto const e = ReadEmitted(b);
	std::map<unsigned, int> owner;	  // physical zmm -> chunk label
	std::map<unsigned, int> owner_seq; // physical zmm -> index of the lane op that defined it
	std::vector<int> last_def(k, -1);  // per chunk, the lane op index that defined its live value
	sh.chain_len.assign(k, 0);
	for (auto const &v : e.vecs) {
		if (v.kind == VecKind::Load) {
			int const c = ChunkOfDisp(v.disp, stride);
			if (c < 0 || (unsigned)c >= k) {
				fprintf(stderr, "  FAIL load at unrecognised chunk disp 0x%x\n",
					v.disp);
				++g_failures;
				return sh;
			}
			owner[v.d] = c;
			owner_seq.erase(v.d);
			++sh.n_load;
			continue;
		}
		if (v.kind == VecKind::Store) {
			int const c = ChunkOfDisp(v.disp, stride);
			auto const it = owner.find(v.s0);
			if (c < 0 || it == owner.end() || it->second != c) {
				fprintf(stderr,
					"  FAIL store of a value labelled %d into chunk %d\n",
					it == owner.end() ? -1 : it->second, c);
				++g_failures;
				return sh;
			}
			++sh.n_store;
			continue;
		}
		if (v.kind != VecKind::Alu)
			continue;
		auto const i0 = owner.find(v.s0), i1 = owner.find(v.s1);
		if (i0 == owner.end() || i1 == owner.end()) {
			fprintf(stderr, "  FAIL lane op reads a register the frame never defined\n");
			++g_failures;
			return sh;
		}
		if (i0->second != i1->second)
			++sh.cross_chunk;
		int const c = i0->second;
		int const idx = (int)sh.chain_len[(unsigned)c];
		// The chain property: this op must consume the value the previous op of the SAME
		// chunk produced. On the first op of a chunk there is no predecessor to consume.
		if (idx > 0) {
			int const prev = last_def[(unsigned)c];
			bool reads_prev = false;
			auto const p0 = owner_seq.find(v.s0), p1 = owner_seq.find(v.s1);
			if (p0 != owner_seq.end() && p0->second == prev)
				reads_prev = true;
			if (p1 != owner_seq.end() && p1->second == prev)
				reads_prev = true;
			if (!reads_prev)
				sh.linear_chain = false;
		}
		sh.alu_chunk.push_back(c);
		sh.alu_index.push_back(idx);
		++sh.chain_len[(unsigned)c];
		owner[v.d] = c;
		owner_seq[v.d] = (int)sh.alu_chunk.size() - 1;
		last_def[(unsigned)c] = (int)sh.alu_chunk.size() - 1;
		++sh.n_alu;
	}
	sh.ok = true;
	return sh;
}

// Sorted mnemonic multiset of the whole blob: the "same host instructions, different order" gate.
std::string MnemonicMultiset(std::vector<Ins> const &insns)
{
	std::vector<std::string> m;
	for (auto const &i : insns) {
		size_t const e = i.text.find(' ');
		m.push_back(e == std::string::npos ? i.text : i.text.substr(0, e));
	}
	std::sort(m.begin(), m.end());
	std::string out;
	for (auto const &x : m) {
		out += x;
		out += '\n';
	}
	return out;
}

// [D1] The issue order must be invisible to admission, for the same reason the body mode must be:
//      otherwise the two arms could form DIFFERENT runs and the ablation would have two factors.
void P6C_CheckOrderInvisibleToAdmission()
{
	printf("[P6C-1] the issue-order selector never reaches admission\n");
	unsigned compared = 0;
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &ra : kRoutes) {
			for (auto const &rc : kRoutes) {
				std::vector<u32> mem = {ra.word, rc.word};
				rvvrun::RunDescriptor d[2];
				rvvrun::Stats st[2];
				for (int m = 0; m < 2; ++m) {
					g_run_order_chunk_major = (m == 1);
					ApplyConfig(vlen, true);
					g_run_order_chunk_major = false;
					rvvrun::g_stats = rvvrun::Stats{};
					d[m] = qir::rv32::RV32Translator::RvvAdmitVectorRun(
					    (uptr)mem.data(), 0u, 8u, 2u,
					    dbt::rv32::VTYPE_E32_M1_TA_MA);
					rvvrun::RecordStats(d[m]);
					st[m] = rvvrun::g_stats;
				}
				CHECK_EQ((unsigned)d[0].n_members, (unsigned)d[1].n_members);
				CHECK_EQ(d[0].live_in_mask, d[1].live_in_mask);
				CHECK_EQ(d[0].live_out_mask, d[1].live_out_mask);
				CHECK_EQ(d[0].touched_mask, d[1].touched_mask);
				CHECK_EQ((unsigned)d[0].nchunks, (unsigned)d[1].nchunks);
				CHECK_EQ((unsigned)d[0].chunk_bytes, (unsigned)d[1].chunk_bytes);
				CHECK_EQ((unsigned)d[0].peak_live_bound,
					 (unsigned)d[1].peak_live_bound);
				CHECK_EQ((unsigned)d[0].cut, (unsigned)d[1].cut);
				CHECK_EQ(d[0].end_pc, d[1].end_pc);
				CHECK_EQ(d[0].vtype_raw, d[1].vtype_raw);
				CHECK_EQ(d[0].vlmax, d[1].vlmax);
				bool same_members = true, same_defs = true;
				for (u8 mi = 0; mi < d[0].n_members; ++mi) {
					auto const &x = d[0].members[mi];
					auto const &y = d[1].members[mi];
					same_members &= x.pc == y.pc && x.raw == y.raw &&
							x.stub == y.stub && x.op == y.op &&
							x.rd == y.rd && x.rs1 == y.rs1 &&
							x.rs2 == y.rs2 &&
							x.sew_bytes == y.sew_bytes &&
							x.nchunks == y.nchunks &&
							x.src1_def == y.src1_def &&
							x.src2_def == y.src2_def;
				}
				for (unsigned r = 0; r < dbt::rv32::VREG_NUM; ++r)
					same_defs &= d[0].last_def[r] == d[1].last_def[r];
				CHECK(same_members);
				CHECK(same_defs);
				CHECK_EQ((unsigned)st[0].members_admitted,
					 (unsigned)st[1].members_admitted);
				CHECK_EQ((unsigned)st[0].multi_member_runs,
					 (unsigned)st[1].multi_member_runs);
				++compared;
			}
		}
	}

	// P6C-R. THE ROWS THE PAIR SWEEP ABOVE STRUCTURALLY CANNOT REACH.
	//
	// `kRoutes` is six integer OPIVV forms, so every descriptor above is built from `RunOp::Add`,
	// `Sub`, `Mul`, `Xor`, `Or` and `And` -- and not one of those took a switch arm that read the
	// order flag. The five kinds that DID (`MulX`, `MAccX`, `LoadWhole`, `StoreWhole`, `Mov`) plus
	// the two FP kinds are enumerated here instead, with their route switches on, so this gate now
	// fails if any of them ever reads a body selector again. It is the falsifiable half of the
	// claim `--rvv-run-order` makes in its own help text.
	//
	// The descriptor comparison is the same one the sweep above makes, and the member count is
	// asserted against the case's declared value as well: an arm that silently admitted FEWER
	// members would otherwise agree with itself.
	unsigned extended = 0;
	g_run_extended_families = true;
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &c : ExtendedOrderCases()) {
			// `RvvAdmitVectorRun` starts the scan AT the first word, and a `vsetvli` is a
			// GuardStateWrite that cuts a run at once -- so the configuring word that the
			// codegen carrier needs in the instruction stream must not be in the scanned
			// range. The observed vtype is passed explicitly instead, exactly as the pair
			// sweep above does. Asserted rather than assumed, so a case whose first word
			// stops being the vsetvli fails here instead of silently scanning one word less.
			CHECK_EQ(c.words.at(0), W_VSETVLI_E32M1);
			std::vector<u32> const body(c.words.begin() + 1, c.words.end());
			rvvrun::RunDescriptor d[2];
			rvvrun::Stats st[2];
			for (int m = 0; m < 2; ++m) {
				g_run_order_chunk_major = (m == 1);
				ApplyConfig(vlen, true);
				g_run_order_chunk_major = false;
				rvvrun::g_stats = rvvrun::Stats{};
				d[m] = qir::rv32::RV32Translator::RvvAdmitVectorRun(
				    (uptr)body.data(), 0u, (u32)body.size() * 4u, (u32)body.size(),
				    dbt::rv32::VTYPE_E32_M1_TA_MA);
				rvvrun::RecordStats(d[m]);
				st[m] = rvvrun::g_stats;
			}
			CHECK_EQ((unsigned)d[0].n_members, c.n_members);
			CHECK_EQ((unsigned)d[1].n_members, c.n_members);
			CHECK_EQ((unsigned)d[0].n_members, (unsigned)d[1].n_members);
			CHECK_EQ(d[0].live_in_mask, d[1].live_in_mask);
			CHECK_EQ(d[0].live_out_mask, d[1].live_out_mask);
			CHECK_EQ(d[0].touched_mask, d[1].touched_mask);
			CHECK_EQ((unsigned)d[0].nchunks, (unsigned)d[1].nchunks);
			CHECK_EQ((unsigned)d[0].chunk_bytes, (unsigned)d[1].chunk_bytes);
			CHECK_EQ((unsigned)d[0].peak_live_bound, (unsigned)d[1].peak_live_bound);
			CHECK_EQ((unsigned)d[0].cut, (unsigned)d[1].cut);
			CHECK_EQ(d[0].end_pc, d[1].end_pc);
			CHECK_EQ(d[0].vtype_raw, d[1].vtype_raw);
			CHECK_EQ(d[0].vlmax, d[1].vlmax);
			bool same_members = true;
			for (u8 mi = 0; mi < d[0].n_members && mi < d[1].n_members; ++mi) {
				auto const &x = d[0].members[mi];
				auto const &y = d[1].members[mi];
				same_members &= x.pc == y.pc && x.raw == y.raw &&
						x.stub == y.stub && x.op == y.op && x.rd == y.rd &&
						x.rs1 == y.rs1 && x.rs2 == y.rs2 &&
						x.sew_bytes == y.sew_bytes &&
						x.nchunks == y.nchunks && x.src1_def == y.src1_def &&
						x.src2_def == y.src2_def;
			}
			CHECK(same_members);
			CHECK_EQ((unsigned)st[0].members_admitted, (unsigned)st[1].members_admitted);
			CHECK_EQ((unsigned)st[0].multi_member_runs, (unsigned)st[1].multi_member_runs);
			CHECK_EQ((unsigned)st[0].runs_formed, (unsigned)st[1].runs_formed);
			for (unsigned r = 0; r < rvvrun::kCutReasonCount; ++r)
				CHECK_EQ((unsigned)st[0].cuts[r], (unsigned)st[1].cuts[r]);
			++extended;
		}
	}
	g_run_extended_families = false;

	printf("    ok  %u ordered pairs x VLEN + %u extended-family cases x VLEN: descriptor, "
	       "member list, scan stats and cut vector identical in both orders\n",
	       compared, extended);
}

// [D2] The QIR frame is the SAME frame: same declaration, same member list, same body multiset,
//      and pass 1 / pass 3 untouched -- all loads still first, all stores still last, at the same
//      displacements.
void P6C_CheckFrameIdentity()
{
	printf("[P6C-2] QIR frame identity: declaration, member list, body multiset, passes 1 and 3\n");
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &c : OrderCases()) {
			Built b[2];
			for (int m = 0; m < 2; ++m) {
				g_run_order_chunk_major = (m == 1);
				Build(b[m], c.words, vlen, true, /*emit=*/false);
				g_run_order_chunk_major = false;
			}
			auto const f0 = FindFrames(b[0].region), f1 = FindFrames(b[1].region);
			CHECK_EQ(f0.size(), (size_t)1);
			CHECK_EQ(f1.size(), (size_t)1);
			if (f0.size() != 1 || f1.size() != 1)
				continue;
			auto const *g0 = f0[0].begin;
			auto const *g1 = f1[0].begin;
			// The AUTHORITATIVE ordered member list lives on `end`; `begin` carries only
			// member 0's raw/stub (qir.h). Both are compared.
			auto const *e0 = f0[0].end;
			auto const *e1 = f1[0].end;
			unsigned const k = vlen / 512u;
			CHECK_EQ((unsigned)g0->vtype, (unsigned)g1->vtype);
			CHECK_EQ((unsigned)g0->vlmax, (unsigned)g1->vlmax);
			CHECK_EQ((unsigned)g0->n_members, (unsigned)g1->n_members);
			CHECK_EQ((unsigned)g0->n_members, c.n_members);
			CHECK_EQ((unsigned)g0->n_typed, (unsigned)g1->n_typed);
			CHECK_EQ((unsigned)g0->raw, (unsigned)g1->raw);
			CHECK_EQ((unsigned)g0->stub, (unsigned)g1->stub);
			CHECK_EQ((unsigned)g0->guard_kind, (unsigned)g1->guard_kind);
			CHECK_EQ((unsigned)g0->vlenb, (unsigned)g1->vlenb);
			CHECK_EQ((unsigned)e0->n_members, (unsigned)e1->n_members);
			CHECK_EQ((unsigned)e0->n_members, c.n_members);
			bool same_members = true;
			for (unsigned i = 0; i < e0->n_members; ++i)
				same_members &= e0->members[i].pc == e1->members[i].pc &&
						e0->members[i].raw == e1->members[i].raw &&
						e0->members[i].stub == e1->members[i].stub;
			CHECK(same_members);
			CHECK_EQ(f0[0].body.size(), f1[0].body.size());

			// Body op multiset, and the pass structure: every load precedes every lane op,
			// which precedes every store, in BOTH arms. That is what "pass 1 and pass 3 are
			// not touched by this switch" means at QIR level.
			for (int m = 0; m < 2; ++m) {
				auto const &body = (m == 0 ? f0 : f1)[0].body;
				unsigned n_load = 0, n_store = 0, n_alu = 0;
				size_t last_load = 0, first_alu = body.size(), last_alu = 0,
				       first_store = body.size();
				for (size_t i = 0; i < body.size(); ++i) {
					auto const op = body[i]->GetOpcode();
					if (op == Op::_vstatechunkload) {
						++n_load;
						last_load = i;
					} else if (op == Op::_vstatechunkstore) {
						++n_store;
						if (first_store == body.size())
							first_store = i;
					} else if (IsAluChunkOp(op)) {
						++n_alu;
						if (first_alu == body.size())
							first_alu = i;
						last_alu = i;
					} else {
						CHECK(false); // a body op that is none of the three
					}
				}
				CHECK_EQ(n_alu, c.n_members * k);
				CHECK(last_load < first_alu);
				CHECK(last_alu < first_store);
				CHECK_EQ((unsigned)body.size(), n_load + n_alu + n_store);
				CHECK_EQ((unsigned)g0->n_typed, n_load + n_alu + n_store);
			}
			// The load and store displacements, in order, are identical between the arms:
			// this switch moves lane ops and nothing else.
			std::string disp[2];
			for (int m = 0; m < 2; ++m) {
				auto const &body = (m == 0 ? f0 : f1)[0].body;
				for (auto *ins : body) {
					char buf[64];
					if (ins->GetOpcode() == Op::_vstatechunkload) {
						snprintf(buf, sizeof(buf), "L%u\n",
							 (unsigned)static_cast<InstVStateChunkLoad *>(
							     ins)->offs);
						disp[m] += buf;
					} else if (ins->GetOpcode() == Op::_vstatechunkstore) {
						snprintf(buf, sizeof(buf), "S%u\n",
							 (unsigned)static_cast<InstVStateChunkStore *>(
							     ins)->offs);
						disp[m] += buf;
					}
				}
			}
			CHECK(disp[0] == disp[1]);
		}
	}
	printf("    ok  six shapes x VLEN: same declaration, same member list, same body multiset, "
	       "identical pass-1/pass-3 displacements\n");
}

// [D3]/[D4]/[D5]/[D6] The emitted code: identical multiset, identical guard/join/fallback,
// identical dataflow shape, and the exact expected permutation of the lane ops.
void P6C_CheckEmittedOrder()
{
	printf("[P6C-3] emitted code: identical multiset and shape, exactly the expected order\n");
	for (u32 vlen : {512u, 1024u}) {
		unsigned const k = vlen / 512u;
		u32 const stride = vlen / 8u / k;
		for (auto const &c : OrderCases()) {
			ArmBuild mem, chk;
			BuildOrderArm(mem, c.words, vlen, false);
			BuildOrderArm(chk, c.words, vlen, true);

			// -- D3: the host instruction multiset, the total count and the call count.
			CHECK(MnemonicMultiset(mem.insns) == MnemonicMultiset(chk.insns));
			CHECK_EQ(mem.insns.size(), chk.insns.size());
			CHECK_EQ(CountText(mem.insns, "call "), CountText(chk.insns, "call "));
			CHECK_EQ(mem.spans.size(), (size_t)1);
			CHECK_EQ(chk.spans.size(), (size_t)1);
			if (mem.spans.size() != 1 || chk.spans.size() != 1)
				continue;
			CHECK_EQ(NonFallbackCount(mem.insns, mem.spans),
				 NonFallbackCount(chk.insns, chk.spans));

			// -- D3: zero spill. Inside the guarded body every ZMM line must be one of the
			// three shapes a typed frame can contain (ParseVec), and no line may name the
			// stack at all. A spill would Panic in QEmit, so reaching here is already half
			// the proof; this is the other half, and it is checked on both arms because
			// chunk-major is the one that lengthens live ranges.
			for (int m = 0; m < 2; ++m) {
				auto const &ab = (m == 0 ? mem : chk);
				size_t const g = FirstGuardIndex(ab.insns);
				unsigned moves = 0, stack = 0, unparsed = 0;
				for (size_t i = g; i < ab.spans[0].first; ++i) {
					std::string const &t = ab.insns[i].text;
					if (Has(t, "rsp") || Has(t, "rbp"))
						++stack;
					if (StartsWith(t, "vmovdqu64 "))
						continue;
					if (StartsWith(t, "mov ") && Has(t, "0xb8"))
						continue; // guest PC store
					if (StartsWith(t, "mov ") || StartsWith(t, "movabs "))
						++moves;
					if (Has(t, "zmm") && !StartsWith(t, "vp"))
						++unparsed;
				}
				CHECK_EQ(moves, 0u);
				CHECK_EQ(stack, 0u);
				CHECK_EQ(unparsed, 0u);
			}

			// -- D4: the prologue, the guard's compares and the whole ordered fallback arm
			// are identical text; only the fast body between them moved.
			CHECK(SpanText(mem.insns, 0, FirstGuardIndex(mem.insns)) ==
			      SpanText(chk.insns, 0, FirstGuardIndex(chk.insns)));
			CHECK(SpanText(mem.insns, mem.spans[0].first, mem.spans[0].second) ==
			      SpanText(chk.insns, chk.spans[0].first, chk.spans[0].second));
			CHECK(MnemonicSeq(mem.insns, mem.spans[0].second, mem.insns.size()) ==
			      MnemonicSeq(chk.insns, chk.spans[0].second, chk.insns.size()));
			unsigned cm = 0, cc = 0;
			for (auto const &i : mem.insns)
				cm += StartsWith(i.text, "cmp ");
			for (auto const &i : chk.insns)
				cc += StartsWith(i.text, "cmp ");
			CHECK_EQ(cm, cc);

			// -- D5: the dataflow shape, reconstructed from the emitted registers.
			OrderShape const sm = ReadOrderShape(mem.b, stride, k);
			OrderShape const sc = ReadOrderShape(chk.b, stride, k);
			CHECK(sm.ok);
			CHECK(sc.ok);
			if (!sm.ok || !sc.ok)
				continue;
			CHECK_EQ(sm.n_alu, c.n_members * k);
			CHECK_EQ(sc.n_alu, c.n_members * k);
			CHECK_EQ(sm.n_load, sc.n_load);
			CHECK_EQ(sm.n_store, sc.n_store);
			// No lane op in either arm reads across chunks: the k chunks really are k
			// disjoint components, which is the reason the reordering is legal at all.
			CHECK_EQ(sm.cross_chunk, 0u);
			CHECK_EQ(sc.cross_chunk, 0u);
			// k chains, all of the same length, in both arms.
			CHECK(sm.chain_len == sc.chain_len);
			bool equal_len = true;
			for (unsigned x = 0; x < k; ++x)
				equal_len &= sm.chain_len[x] == c.n_members;
			CHECK(equal_len);

			// -- D5: the EXACT permutation, asserted on both arms rather than "they
			// differ". `serial*` is one chain per chunk, so its per-chunk def-use order is
			// also a linear chain; `twin8` and the two-member pairs are not, so the chain
			// property is only demanded where the guest actually wrote one.
			bool const one_chain = StartsWith(std::string(c.name), "serial");
			if (one_chain) {
				CHECK(sm.linear_chain);
				CHECK(sc.linear_chain);
			}
			bool member_major_ok = true, chunk_major_ok = true;
			for (unsigned j = 0; j < sm.alu_chunk.size(); ++j) {
				member_major_ok &= sm.alu_chunk[j] == (int)(j % k);
				member_major_ok &= sm.alu_index[j] == (int)(j / k);
			}
			for (unsigned j = 0; j < sc.alu_chunk.size(); ++j) {
				chunk_major_ok &= sc.alu_chunk[j] == (int)(j / c.n_members);
				chunk_major_ok &= sc.alu_index[j] == (int)(j % c.n_members);
			}
			CHECK(member_major_ok);
			CHECK(chunk_major_ok);

			// -- D6: at k = 1 the two nestings coincide, so the arms must be the SAME code.
			// At k > 1 they must not be, or the switch did nothing and every identity gate
			// above would be vacuously true.
			unsigned n0 = 0, n1 = 0;
			bool const same_text = NormalizedDisasm(mem.b.lines, &n0) ==
					       NormalizedDisasm(chk.b.lines, &n1);
			if (k == 1) {
				CHECK(same_text);
				CHECK_EQ(mem.b.code.size(), chk.b.code.size());
			} else if (c.n_members > 1) {
				CHECK(!same_text);
			}
			printf("    ok  %-11s vlen=%-5u k=%u m=%-2u alu=%u/chunk  multiset= chains= "
			       "guard= fallback=  order %s\n",
			       c.name, vlen, k, c.n_members, c.n_members,
			       k == 1 ? "identical (k=1)" : "member-major != chunk-major");
		}
	}
}

// [D-default] The new switch at its default reproduces the accepted configuration exactly.
// P6C-R (2026-09-10). [D2]+[D3]+[D4]+[D6] FOR THE SEVEN EXTENDED MEMBER KINDS.
//
// The three checks above are written against `OrderCases()`, whose runs are pure integer ALU: the
// frame-identity check asserts that the body holds exactly `n_members * k` lane ops and that every
// body op is a load, a store or an ALU chunk op. Those are true of that shape and false of a move
// (no lane op at all), a whole-register transfer (`vchunkload`/`vchunkstore`), or an OPMVX
// accumulate (TWO lane ops per chunk). So this is a SEPARATE carrier written over the opcode
// histogram rather than over one expected count -- it makes no assumption about which node kinds a
// member emits, only that the two orders emit the SAME ones.
//
// What it holds fixed, arm to arm: the frame declaration and the ordered member list; the QIR body
// opcode histogram and total node count; `n_typed`; the pass-1 load and pass-3 store displacement
// SEQUENCES (not merely their multiset -- this switch must not move a single state access); the
// emitted host instruction multiset, total count, call count and non-fallback count; zero spill in
// the guarded body; and the prologue, guard and whole ordered fallback arm as identical text.
//
// The k = 1 control is the harness's own falsification: at VLEN 512 the two nestings coincide, so
// the emitted text and the emitted BYTE COUNT must be identical. If the extension were reading
// noise, or if the order flag leaked into anything but the loop nesting, k = 1 would not come out
// identical. At k = 2 byte count is NOT asserted equal: register assignment is not claimed
// identical (the allocator sees a different value order), which is the one thing
// `--rvv-run-order`'s contract has always disclaimed.
void P6C_CheckExtendedFamilyOrderIdentity()
{
	printf("[P6C-5] extended member kinds: same frame, same body histogram, same state accesses, "
	       "same emitted multiset\n");
	g_run_extended_families = true;
	for (u32 vlen : {512u, 1024u}) {
		unsigned const k = vlen / 512u;
		for (auto const &c : ExtendedOrderCases()) {
			ArmBuild mem, chk;
			BuildOrderArm(mem, c.words, vlen, false);
			BuildOrderArm(chk, c.words, vlen, true);
			auto const f0 = FindFrames(mem.b.region), f1 = FindFrames(chk.b.region);
			CHECK_EQ(f0.size(), (size_t)1);
			CHECK_EQ(f1.size(), (size_t)1);
			if (f0.size() != 1 || f1.size() != 1)
				continue;

			// -- the declaration and the ordered member list
			auto const *g0 = f0[0].begin, *g1 = f1[0].begin;
			auto const *e0 = f0[0].end, *e1 = f1[0].end;
			CHECK_EQ((unsigned)g0->n_members, c.n_members);
			CHECK_EQ((unsigned)g1->n_members, c.n_members);
			CHECK_EQ((unsigned)g0->n_typed, (unsigned)g1->n_typed);
			CHECK_EQ((unsigned)g0->vtype, (unsigned)g1->vtype);
			CHECK_EQ((unsigned)g0->vlmax, (unsigned)g1->vlmax);
			CHECK_EQ((unsigned)g0->guard_kind, (unsigned)g1->guard_kind);
			CHECK_EQ((unsigned)e0->n_members, (unsigned)e1->n_members);
			bool same_members = true;
			for (unsigned i = 0; i < e0->n_members && i < e1->n_members; ++i)
				same_members &= e0->members[i].pc == e1->members[i].pc &&
						e0->members[i].raw == e1->members[i].raw &&
						e0->members[i].stub == e1->members[i].stub;
			CHECK(same_members);

			// -- the QIR body: same node count and same per-opcode histogram
			CHECK_EQ(f0[0].body.size(), f1[0].body.size());
			CHECK_EQ((unsigned)g0->n_typed, (unsigned)f0[0].body.size());
			std::map<unsigned, unsigned> hist[2];
			std::string disp[2];
			for (int m = 0; m < 2; ++m) {
				for (auto *ins : (m == 0 ? f0 : f1)[0].body) {
					auto const op = ins->GetOpcode();
					++hist[m][(unsigned)op];
					char buf[64];
					if (op == Op::_vstatechunkload) {
						snprintf(buf, sizeof(buf), "L%u\n",
							 (unsigned)static_cast<InstVStateChunkLoad *>(
							     ins)->offs);
						disp[m] += buf;
					} else if (op == Op::_vstatechunkstore) {
						snprintf(buf, sizeof(buf), "S%u\n",
							 (unsigned)static_cast<InstVStateChunkStore *>(
							     ins)->offs);
						disp[m] += buf;
					}
				}
			}
			CHECK(hist[0] == hist[1]);
			// The SEQUENCE, not the multiset: pass 1 and pass 3 must not have moved at all.
			CHECK(disp[0] == disp[1]);

			// -- the emitted host code
			CHECK(MnemonicMultiset(mem.insns) == MnemonicMultiset(chk.insns));
			CHECK_EQ(mem.insns.size(), chk.insns.size());
			CHECK_EQ(CountText(mem.insns, "call "), CountText(chk.insns, "call "));
			CHECK_EQ(mem.spans.size(), (size_t)1);
			CHECK_EQ(chk.spans.size(), (size_t)1);
			if (mem.spans.size() != 1 || chk.spans.size() != 1)
				continue;
			CHECK_EQ(NonFallbackCount(mem.insns, mem.spans),
				 NonFallbackCount(chk.insns, chk.spans));
			for (int m = 0; m < 2; ++m) {
				auto const &ab = (m == 0 ? mem : chk);
				size_t const g = FirstGuardIndex(ab.insns);
				unsigned stack = 0;
				for (size_t i = g; i < ab.spans[0].first; ++i)
					if (Has(ab.insns[i].text, "rsp") ||
					    Has(ab.insns[i].text, "rbp"))
						++stack;
				CHECK_EQ(stack, 0u);
			}
			CHECK(SpanText(mem.insns, 0, FirstGuardIndex(mem.insns)) ==
			      SpanText(chk.insns, 0, FirstGuardIndex(chk.insns)));
			CHECK(SpanText(mem.insns, mem.spans[0].first, mem.spans[0].second) ==
			      SpanText(chk.insns, chk.spans[0].first, chk.spans[0].second));

			unsigned n0 = 0, n1 = 0;
			bool const same_text = NormalizedDisasm(mem.b.lines, &n0) ==
					       NormalizedDisasm(chk.b.lines, &n1);
			CHECK_EQ(mem.b.code.size(), chk.b.code.size());
			if (k == 1) {
				CHECK(same_text);
			}
			printf("    ok  %-8s vlen=%-5u k=%u m=%-2u qir=%-3u typed=%-3u insns=%-4u "
			       "%s\n",
			       c.name, vlen, k, c.n_members, (unsigned)f0[0].body.size(),
			       (unsigned)g0->n_typed, (unsigned)mem.insns.size(),
			       k == 1 ? "byte-identical (k=1 control)" : "identical multiset");
		}
	}
	g_run_extended_families = false;
}

void P6C_CheckDefaultIsMemberMajor()
{
	printf("[P6C-4] the issue-order switch defaults to the accepted member-major body\n");
	// Captured in main() before any test touched the globals.
	CHECK(g_startup_run_order_chunk_major == false);
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &c : OrderCases()) {
			Built def;
			g_run_order_chunk_major = false;
			Build(def, c.words, vlen, true);
			ArmBuild mm;
			BuildOrderArm(mm, c.words, vlen, false);
			unsigned nd = 0, nm = 0;
			CHECK(NormalizedDisasm(def.lines, &nd) == NormalizedDisasm(mm.b.lines, &nm));
			CHECK_EQ(nd, nm);
		}
	}
	printf("    ok  default == explicit member-major at both widths, all six shapes\n");
}

} // namespace

int main(int argc, char **argv)
{
	printf("R1A.3b QCG vector-run codegen and correctness + R1A.3d three-arm ablation\n");
	g_startup_body_materialize = config::rvv_run_body_materialize;
	g_startup_hit_counter = config::rvv_qcg_hit_counter;
	g_startup_run_order_chunk_major = config::rvv_run_order_chunk_major;
	CheckFlagOffGoldens();
	CheckLaneCensusCodegenInvisible();
	CheckNamedPairsAndAllPairs();
	CheckAllocation();
	CheckEmitted();
	CheckOverlap();
	CheckConsumption();
	CheckBodyModeInvisibleToAdmission();
	CheckMaterializeFrameShape();
	CheckFallbackAndGuardIdentical();
	CheckHitCounterScope();
	CheckFrameCensusScope();
	CheckLiveSplitDepth1Probe();
	CheckArmLedger();
	CheckMaterializeAllocation();
	CheckMaterializeOverlap();
	CheckDefaultsUnchanged();
	CheckEveryRouteSharesTheBody();
	M2E_CheckAll();
	P6C_CheckOrderInvisibleToAdmission();
	P6C_CheckFrameIdentity();
	P6C_CheckEmittedOrder();
	P6C_CheckExtendedFamilyOrderIdentity();
	P6C_CheckDefaultIsMemberMajor();
	if (argc > 1 && std::string(argv[1]) == "--dump")
		DumpRepresentative();
	if (argc > 2 && std::string(argv[1]) == "--dump-arms")
		DumpArms((u32)atoi(argv[2]));

	if (g_failures) {
		fprintf(stderr, "\nFAILED: %d check(s)\n", g_failures);
		return 1;
	}
	M2F_CheckMaterializeDeclarationNotTruncated();

	printf("\nALL CHECKS PASSED\n");
	return 0;
}
