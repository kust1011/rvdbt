// P7N-D: the VLEN-derived host chunk geometry (--rvv-qcg-narrow-chunk-width), as a structural test.
//
// THE CHANGE UNDER TEST IS ONE RULE, NOT A NEW ROUTE. Until this checkpoint every typed chunk route
// except vadd.vv and the two logical shifts asked RvvGenericChunkShapeAdmit for its shape, and that
// predicate's `vlen % 512 == 0` REFUSES VLEN 128 and 256 outright. The switch replaces it, for the
// four routes named below, with the rule vadd.vv and the shifts already use:
//
//     chunk width = min(VLEN/8, 64) bytes        chunk count = (VLEN/8) / width
//
// WHAT THIS FILE HAS TO PROVE, and why each section exists.
//
//   [1] THE GEOMETRY IS DERIVED, NOT ENUMERATED, AND IT IS THE SAME ONE EVERYWHERE. VLEN
//       128/256/512/1024 must give 1/1/1/2 chunks of 16/32/64/64 bytes for vxor.vv, vor.vv and
//       vse32.v alike, and the ALREADY-ACCEPTED vadd.vv and vsll.vi routes -- whose shapes are
//       separate predicates carrying separate accepted evidence -- must agree with them at every
//       one of those widths. Three restatements of one derivation only stay one derivation if a
//       divergence is a red test.
//
//   [2] VLEN 512 AND 1024 DO NOT MOVE. For every one of the four routes, at VLEN 512 and 1024, the
//       QIR emitted with the switch ON must be IDENTICAL -- opcode sequence, value widths, CPUState
//       offsets, declared n_typed, the setvl node's constants -- to the QIR emitted with it OFF.
//       This is the non-regression claim stated as an equality over emitted structure rather than
//       as an appeal to the source.
//
//   [3] WITH THE SWITCH OFF, 128 AND 256 STILL TAKE THE HELPER. Without this the section above
//       would pass vacuously if the switch did nothing at all.
//
//   [4] THE STORE'S WIDTH IS CARRIED, NOT ASSUMED. vse32.v is the one route here whose mistakes are
//       WRITES to guest memory. Its data value's type must be exactly the chunk width and its guest
//       displacements must be `c * width`, so the windows tile [0, VLEN/8) with no gap, no overlap
//       and no tail.
//
//   [5] FAIL-CLOSED SEMANTICS SURVIVE. With the switch ON at a narrow VLEN, every unsupported form
//       -- masked, SEW != 32, LMUL != 1, strided/indexed/segment/whole-register stores, a store
//       based on x0, the reserved rd=x0&rs1=x0 vsetvli, --rvv-verify, --rvv-direct off, the LLVM
//       backend, and a VLEN that is not a whole number of host chunks -- must still keep its
//       existing helper.
//
//   [6] THE INTEGER FAMILY HAS ONE WIDTH RULE (A1, 2026-09-05). vsub.vv, vmul.vv and vand.vv used
//       to be the deliberate non-widening list of P7N-D; A1 gives them the same width-correct
//       shape as xor/or/add, so this section now asserts the OPPOSITE of what it asserted before:
//       all three are routed at VLEN 128/256 with the switch on, at exactly the geometry [1]
//       derives, and are refused with it off ([3]). (S1 had already moved vle32.v out of the
//       list for the same reason.)
//
//   [7] THE RUN CONSUMES THE WIDENED MEMBERS. At VLEN 128 an add -> xor -> sll -> srl -> or
//       sequence must form ONE five-member run over 16-byte chunks; with the switch off the same
//       five instructions cannot, because xor and or fall to the helper and cut it.
//
//   [8] MUTATION. Each check is shown to fail when the thing it checks is broken.
//
// SCOPE: structure only. Nothing here is executed and nothing here is timed; the hardware evidence
// is the checkpoint's xbd package. Like the other route tests it uses the audit force-emit
// switches, because it never runs what it emits.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
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
		auto _b = (b);                                                                               \
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
constexpr u32 F6_VADD = 0b000000, F6_VSUB = 0b000010, F6_VAND = 0b001001, F6_VOR = 0b001010,
	      F6_VXOR = 0b001011, F6_VMUL = 0b100101, F6_VSLL = 0b100101, F6_VSRL = 0b101000;
constexpr u32 F3_OPIVV = 0b000, F3_OPIVX = 0b100, F3_OPIVI = 0b011, F3_OPMVV = 0b010;

u32 Vxor(u32 vd, u32 vs2, u32 vs1) { return Enc(F6_VXOR, 1, vs2, vs1, F3_OPIVV, vd); }
u32 Vor(u32 vd, u32 vs2, u32 vs1) { return Enc(F6_VOR, 1, vs2, vs1, F3_OPIVV, vd); }
u32 Vand(u32 vd, u32 vs2, u32 vs1) { return Enc(F6_VAND, 1, vs2, vs1, F3_OPIVV, vd); }
u32 Vsub(u32 vd, u32 vs2, u32 vs1) { return Enc(F6_VSUB, 1, vs2, vs1, F3_OPIVV, vd); }
u32 Vadd(u32 vd, u32 vs2, u32 vs1) { return Enc(F6_VADD, 1, vs2, vs1, F3_OPIVV, vd); }
u32 Vmul(u32 vd, u32 vs2, u32 vs1) { return Enc(F6_VMUL, 1, vs2, vs1, F3_OPMVV, vd); }
u32 Vsll(u32 vd, u32 vs2, u32 uimm) { return Enc(F6_VSLL, 1, vs2, uimm, F3_OPIVI, vd); }
u32 Vsrl(u32 vd, u32 vs2, u32 uimm) { return Enc(F6_VSRL, 1, vs2, uimm, F3_OPIVI, vd); }
// A2: vmv.v.x vd, rs1 = OPIVX, funct6 010111, vm=1, vs2=0.
constexpr u32 F6_VMERGE = 0b010111;
u32 Vmvvx(u32 vd, u32 rs1) { return Enc(F6_VMERGE, 1, 0, rs1, F3_OPIVX, vd); }
// A7: vmv.v.i (signed imm5 field) and vmv.v.v (register copy), both vm=1, vs2=0.
u32 Vmvvi(u32 vd, u32 imm5) { return Enc(F6_VMERGE, 1, 0, imm5 & 31u, F3_OPIVI, vd); }
u32 Vmvvv(u32 vd, u32 vs1) { return Enc(F6_VMERGE, 1, 0, vs1, F3_OPIVV, vd); }
// A6: unmasked vadd.vx / vadd.vi (imm5 is the raw 5-bit field, sign-extended by the route).
u32 Vaddvx(u32 vd, u32 vs2, u32 rs1) { return Enc(F6_VADD, 1, vs2, rs1, F3_OPIVX, vd); }
u32 Vaddvi(u32 vd, u32 vs2, u32 imm5) { return Enc(F6_VADD, 1, vs2, imm5 & 31u, F3_OPIVI, vd); }

// The V-format load/store word, field by field in rv32_decode.h's own layout. `rd` carries vs3 on
// the store side; that naming trap is the reason this is written out rather than copied.
constexpr u32 EncMem(u32 nf, u32 mew, u32 mop, u32 vm, u32 lsumop, u32 rs1, u32 width, u32 vd_vs3,
		     u32 opcode)
{
	return (nf << 29) | (mew << 28) | (mop << 26) | (vm << 25) | (lsumop << 20) | (rs1 << 15) |
	       (width << 12) | (vd_vs3 << 7) | opcode;
}
constexpr u32 OP_STORE_FP = 0b0100111, OP_LOAD_FP = 0b0000111;
constexpr u32 W_EEW32 = 0b110, W_EEW8 = 0b000, W_EEW64 = 0b111;

// vse32.v v8, (a6) / vle32.v v8, (a6): unmasked, unit-stride, single register, EEW=32.
u32 Vse32(u32 vs3 = 8, u32 rs1 = 16) { return EncMem(0, 0, 0, 1, 0, rs1, W_EEW32, vs3, OP_STORE_FP); }
u32 Vle32(u32 vd = 8, u32 rs1 = 16) { return EncMem(0, 0, 0, 1, 0, rs1, W_EEW32, vd, OP_LOAD_FP); }

// vsetvli a0, a0, <vtype>, and the reserved rd=x0,rs1=x0 form.
constexpr u32 W_VSETVLI_E32M1 = 0x0d057557u; // vsetvli a0, a0, e32, m1, ta, ma
constexpr u32 W_VSETVLI_E64M1 = 0x0d857557u; // vsetvli a0, a0, e64, m1, ta, ma
constexpr u32 W_VSETVLI_E32M2 = 0x0d157557u; // vsetvli a0, a0, e32, m2, ta, ma
constexpr u32 W_VSETVLI_KEEPVL = 0x0d007057u; // vsetvli x0, x0, e32, m1, ta, ma  (reserved form)

struct Built {
	MemArena arena{1u << 20};
	std::vector<u32> words;
	Region *region = nullptr;
};

// `lead` is the in-block vsetvli that pins the observed vtype; passing 0 leaves the vtype
// unobserved, which is the candidate-plus-guard entry of every route.
void Build(Built &b, std::vector<u32> const &body, u32 lead = W_VSETVLI_E32M1)
{
	b.words.clear();
	if (lead)
		b.words.push_back(lead);
	for (u32 w : body)
		b.words.push_back(w);
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
}

void ApplyConfig(u32 vlen_bits, bool narrow, bool run = false, bool partial = false,
		 bool vadd_scalar = true)
{
	config::rvv_qcg_partial_vl = partial; // A3
	config::rvv_qcg_typed_chunk_vadd_scalar = vadd_scalar; // A6
	config::rvv_qcg_typed_chunk_falu = true; // A9
	config::rvv_qcg_typed_chunk_falu_force_emit = true;
	config::rvv_qcg_typed_chunk_fma = true;
	config::rvv_qcg_typed_chunk_fma_force_emit = true;
	config::rvv_qcg_typed_chunk_vadd_scalar_force_emit = true; // A6
	config::vlen_bits = vlen_bits;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::rvv_lowering = 1; // rvv_chunked; the memory routes refuse under the Ref arm
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_sub = true;
	config::rvv_qcg_typed_chunk_mul = true;
	config::rvv_qcg_typed_chunk_and = true;
	config::rvv_qcg_typed_chunk_xor = true;
	config::rvv_qcg_typed_chunk_or = true;
	config::rvv_qcg_typed_chunk_vle = true;
	config::rvv_qcg_typed_chunk_vse = true;
	config::rvv_qcg_typed_chunk_shift = true;
	config::rvv_qcg_typed_chunk_vmv = true; // A2
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_hit_counter = true;
	// The audit force-emit switches for EVERY route this file builds. This host has no AVX-512,
	// and without them every route would refuse on its own CPUID probe and every section would
	// pass vacuously by refusing for the wrong reason.
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_sub_force_emit = true;
	config::rvv_qcg_typed_chunk_mul_force_emit = true;
	config::rvv_qcg_typed_chunk_and_force_emit = true;
	config::rvv_qcg_typed_chunk_xor_force_emit = true;
	config::rvv_qcg_typed_chunk_or_force_emit = true;
	config::rvv_qcg_typed_chunk_vle_force_emit = true;
	config::rvv_qcg_typed_chunk_vse_force_emit = true;
	config::rvv_qcg_typed_chunk_shift_force_emit = true;
	config::rvv_qcg_typed_chunk_vmv_force_emit = true; // A2
	config::rvv_qcg_narrow_chunk_width = narrow;
	config::rvv_qcg_narrow_chunk_width_force_emit = true;
	config::rvv_vector_run = run;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_dep_probe_depth = 0;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_llvm_wide_vadd = false;
	config::rvv_llvm_wide_vadd_ssa = false;
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

unsigned CountRegionOp(Region *region, Op op)
{
	unsigned n = 0;
	for (auto &bb : region->GetBlocks())
		for (auto &ins : bb.ilist)
			n += ins.GetOpcode() == op;
	return n;
}

// A textual fingerprint of everything about the emitted region this checkpoint could change:
// every instruction's opcode, every operand's VType, and -- for the nodes that carry a width, an
// offset or a constant as a FIELD rather than an operand -- those fields. Two regions with the same
// fingerprint emit the same chunk geometry into the same CPUState and guest windows.
std::string Fingerprint(Region *region)
{
	std::string out;
	char buf[256];
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			snprintf(buf, sizeof(buf), "%u", (unsigned)ins.GetOpcode());
			out += buf;
			for (u8 k = 0; k < ins.OutputCount(); ++k) {
				snprintf(buf, sizeof(buf), ":o%u", (unsigned)ins.o(k).GetType());
				out += buf;
			}
			for (u8 k = 0; k < ins.InputCount(); ++k) {
				snprintf(buf, sizeof(buf), ":i%u", (unsigned)ins.i(k).GetType());
				out += buf;
			}
			switch (ins.GetOpcode()) {
			case Op::_vstatechunkload:
				snprintf(buf, sizeof(buf), ":off%u",
					 (unsigned)static_cast<InstVStateChunkLoad *>(&ins)->offs);
				out += buf;
				break;
			case Op::_vstatechunkstore:
				snprintf(buf, sizeof(buf), ":off%u",
					 (unsigned)static_cast<InstVStateChunkStore *>(&ins)->offs);
				out += buf;
				break;
			case Op::_vchunkstore: {
				auto *st = static_cast<InstVChunkStore *>(&ins);
				snprintf(buf, sizeof(buf), ":base%u:disp%u",
					 (unsigned)st->base_state_offs, (unsigned)st->disp);
				out += buf;
				break;
			}
			case Op::_vchunkload: {
				auto *ld = static_cast<InstVChunkLoad *>(&ins);
				snprintf(buf, sizeof(buf), ":base%u:disp%u",
					 (unsigned)ld->base_state_offs, (unsigned)ld->disp);
				out += buf;
				break;
			}
			case Op::_rvvsetvl: {
				auto *sv = static_cast<InstRVVSetVL *>(&ins);
				snprintf(buf, sizeof(buf), ":vtype%u:vlmax%u:vlenb%u:keep%u",
					 sv->vtype, sv->vlmax, sv->vlenb, (unsigned)sv->keep_vl);
				out += buf;
				break;
			}
			case Op::_rvvtypedchunkbegin: {
				auto *bg = static_cast<InstRVVTypedChunkBegin *>(&ins);
				snprintf(buf, sizeof(buf), ":ntyped%u:vtype%u:vlmax%u",
					 (unsigned)bg->n_typed, bg->vtype, bg->vlmax);
				out += buf;
				break;
			}
			default:
				break;
			}
			out += '\n';
		}
	}
	return out;
}

// ---------------------------------------------------------------------------------------------
// EMITTED HOST BYTES. The QIR sections above establish that the route carries a width; only the
// EMITTER decides what x86 register form and what memory operand size that width becomes, so the
// width claim has to be checked once at the encoding level too. objdump is the independent decoder,
// as in the sibling route tests, and it FAILS LOUDLY rather than skipping.
// ---------------------------------------------------------------------------------------------
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

std::vector<std::string> Disassemble(std::vector<u8> const &code, bool raw_bytes = false)
{
	char path[] = "/tmp/rvdbt_p7nd_emit_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "  mkstemp failed: %s\n", strerror(errno));
		++g_failures;
		return {};
	}
	size_t written = 0;
	while (written < code.size()) {
		ssize_t const n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0) {
			fprintf(stderr, "  write to temp file failed: %s\n", strerror(errno));
			close(fd);
			unlink(path);
			++g_failures;
			return {};
		}
		written += (size_t)n;
	}
	close(fd);
	// A1: `raw_bytes` keeps objdump's hex column, so a caller can test the ENCODING (EVEX
	// prefix byte 0x62 vs VEX 0xc4/0xc5) rather than a `{evex}` pseudo-prefix that only newer
	// binutils print (2.42 on xbd does, 2.38 on the development host does not).
	std::string const cmd = std::string("objdump -D -b binary -m i386:x86-64 -M intel ") +
				(raw_bytes ? "" : "--no-show-raw-insn ") + path + " 2>&1";
	FILE *pf = popen(cmd.c_str(), "r");
	if (!pf) {
		fprintf(stderr, "  popen(objdump) failed: %s\n", strerror(errno));
		unlink(path);
		++g_failures;
		return {};
	}
	std::vector<std::string> lines;
	char buf[1024];
	while (fgets(buf, sizeof(buf), pf)) {
		std::string cur(buf);
		if (!cur.empty() && cur.back() == '\n')
			cur.pop_back();
		lines.push_back(cur);
	}
	int const rc = pclose(pf);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
		fprintf(stderr, "  objdump did not exit cleanly (raw status %d)\n", rc);
		++g_failures;
		return {};
	}
	return lines;
}

std::vector<std::string> EmitAndDisassemble(std::vector<u32> const &body,
					    u32 lead = W_VSETVLI_E32M1, bool raw_bytes = false)
{
	Built b;
	Build(b, body, lead);
	TestCompilerRuntime cr;
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&cr, &segment, b.region, 0);
	CHECK(!span.empty());
	return Disassemble(std::vector<u8>(span.begin(), span.end()), raw_bytes);
}

// A1. From a raw-bytes disassembly, count the lines whose mnemonic is `mn` and whose first
// register operand is of class `cls`, split by ENCODING: {evex, vex}. objdump's raw line is
// `addr:\t<hex bytes>\t<text>`; the first hex byte is 0x62 for EVEX and 0xc4/0xc5 for VEX.
std::pair<unsigned, unsigned> CountEncodings(std::vector<std::string> const &raw_lines,
					     char const *mn, char const *cls)
{
	unsigned evex = 0, vex = 0;
	for (auto const &l : raw_lines) {
		auto const t1 = l.find('\t');
		if (t1 == std::string::npos)
			continue;
		auto const t2 = l.find('\t', t1 + 1);
		if (t2 == std::string::npos)
			continue;
		std::string const hex = l.substr(t1 + 1, t2 - t1 - 1);
		std::string text = l.substr(t2 + 1);
		if (text.rfind("{evex} ", 0) == 0)
			text = text.substr(7);
		if (text.rfind(mn, 0) != 0 || text.find(cls) == std::string::npos)
			continue;
		if (hex.rfind("62 ", 0) == 0)
			++evex;
		else if (hex.rfind("c4 ", 0) == 0 || hex.rfind("c5 ", 0) == 0)
			++vex;
	}
	return {evex, vex};
}

// Count disassembled lines whose mnemonic is `mn` and whose first register operand is of class
// `cls` ("xmm"/"ymm"/"zmm"). Deliberately a TEXT match on the decoded line: it is the one thing in
// this file that does not come from the code under test.
unsigned CountMnemonicWithClass(std::vector<std::string> const &lines, char const *mn,
				char const *cls)
{
	unsigned n = 0;
	for (auto const &l : lines) {
		auto const at = l.find('\t');
		if (at == std::string::npos)
			continue;
		std::string const text = l.substr(at + 1);
		if (text.rfind(mn, 0) != 0)
			continue;
		if (text.find(cls) == std::string::npos)
			continue;
		++n;
	}
	return n;
}

unsigned CountMnemonic(std::vector<std::string> const &lines, char const *mn)
{
	unsigned n = 0;
	for (auto const &l : lines) {
		auto const at = l.find('\t');
		if (at == std::string::npos)
			continue;
		if (l.substr(at + 1).rfind(mn, 0) == 0)
			++n;
	}
	return n;
}

// ---------------------------------------------------------------------------------------------
// [1] GEOMETRY
// ---------------------------------------------------------------------------------------------
struct WidthCase {
	u32 vlen;
	unsigned chunks;
	unsigned bytes;
};
constexpr WidthCase kWidths[] = {{128, 1, 16}, {256, 1, 32}, {512, 1, 64}, {1024, 2, 64}};

// Returns the (count, width) the route emitted, by reading the value type off the op that carries
// the chunk. {0,0} means the route refused and the instruction took its helper.
std::pair<unsigned, unsigned> EmittedShape(Region *region, Op lane_op)
{
	unsigned count = 0, bytes = 0;
	for (auto const &f : FindFrames(region)) {
		for (auto *i : f.body) {
			if (i->GetOpcode() != lane_op)
				continue;
			++count;
			auto const t = i->OutputCount() ? i->o(0).GetType() : i->i(1).GetType();
			unsigned const w = (unsigned)qir::VTypeToSize(t);
			if (bytes && bytes != w)
				CHECK_EQ(bytes, w); // one frame must not mix widths
			bytes = w;
		}
	}
	return {count, bytes};
}

void TestGeometry()
{
	printf("[1] the chunk geometry is derived from VLEN, and every route agrees on it\n");
	struct RouteCase {
		char const *name;
		std::vector<u32> body;
		Op lane_op;
	};
	std::vector<RouteCase> const routes = {
	    {"vxor.vv", {Vxor(9, 8, 7)}, Op::_vchunkxor},
	    {"vor.vv", {Vor(9, 8, 7)}, Op::_vchunkor},
	    {"vse32.v", {Vse32()}, Op::_vchunkstore},
	    {"vle32.v (S1)", {Vle32()}, Op::_vchunkload},
	    {"vsub.vv (A1)", {Vsub(9, 8, 7)}, Op::_vchunksub},
	    {"vmul.vv (A1)", {Vmul(9, 8, 7)}, Op::_vchunkmul},
	    {"vand.vv (A1)", {Vand(9, 8, 7)}, Op::_vchunkand},
	    // A2's vmv.v.x has ONE broadcast whatever the count and its per-chunk op (the store) has
	    // no output type to read a width from, so its geometry is pinned in [10] instead.
	    // The two ALREADY-ACCEPTED width-correct routes, included so the agreement below is an
	    // assertion about three separate predicates and not about one of them repeated.
	    {"vadd.vv (accepted, M2C)", {Vadd(9, 8, 7)}, Op::_vchunkadd},
	    {"vsll.vi (accepted, P7N-B)", {Vsll(9, 8, 7)}, Op::_vchunksll},
	};
	for (auto const &c : kWidths) {
		for (auto const &r : routes) {
			ApplyConfig(c.vlen, /*narrow=*/true);
			Built b;
			Build(b, r.body);
			auto const [n, w] = EmittedShape(b.region, r.lane_op);
			CHECK_EQ(n, c.chunks);
			CHECK_EQ(w, c.bytes);
		}
		// vsetvli has no chunks at all; what it carries is the VLEN as a constant, and the
		// route must be taken (one rvvsetvl node, zero rv32_vsetvli helper calls) at every
		// width rather than only at 512/1024.
		ApplyConfig(c.vlen, /*narrow=*/true);
		Built b;
		Build(b, {}, W_VSETVLI_E32M1);
		CHECK_EQ(CountRegionOp(b.region, Op::_rvvsetvl), 1u);
		for (auto &bb : b.region->GetBlocks())
			for (auto &ins : bb.ilist)
				if (ins.GetOpcode() == Op::_rvvsetvl) {
					auto *sv = static_cast<InstRVVSetVL *>(&ins);
					CHECK_EQ(sv->vlenb, c.vlen / 8u);
					CHECK_EQ(sv->vlmax, c.vlen / 32u);
				}
		printf("  VLEN %4u -> %u chunk(s) of %2u bytes on vxor/vor/vse32/vle32/vsub/vmul/vand/vadd/vsll; "
		       "vsetvli vlenb=%u vlmax=%u\n",
		       c.vlen, c.chunks, c.bytes, c.vlen / 8u, c.vlen / 32u);
	}
}

// ---------------------------------------------------------------------------------------------
// [1b] THE ONE PURE GEOMETRY (A1-review)
// ---------------------------------------------------------------------------------------------
// RvvHostChunkGeometry reads no config and probes no host: its answer is a function of
// (VLEN, SEW) alone, so it can be pinned as a truth table. Every route's shape predicate is that
// function plus the route's own gates, and [1] asserts they still agree; this section pins the
// function itself, including the refusals ([5] reaches only some of them through a route).
void TestPureGeometry()
{
	printf("[1b] RvvHostChunkGeometry(VLEN, SEW) truth table\n");
	struct Row {
		u32 vlen, sew_bytes;
		unsigned bytes, count; // count 0 = refused
	};
	Row const rows[] = {
	    {64, 4, 0, 0},     {96, 4, 0, 0},     {128, 4, 16, 1},   {192, 4, 0, 0},
	    {256, 4, 32, 1},   {384, 4, 0, 0},    {512, 4, 64, 1},   {768, 4, 0, 0},
	    {1024, 4, 64, 2},  {2048, 4, 64, 4},  {4096, 4, 64, 8},  {8192, 4, 0, 0},
	    {132, 4, 0, 0},    {0, 4, 0, 0},
	    {128, 1, 0, 0},    {128, 2, 0, 0},    {128, 8, 0, 0},    {512, 1, 0, 0},
	    {512, 2, 0, 0},    {512, 8, 0, 0},    {1024, 8, 0, 0},   {1024, 0, 0, 0},
	};
	// The switches, the backend and the host must be IRRELEVANT to this function: flip them all
	// to their most refusing values and the table must still hold.
	ApplyConfig(128, /*narrow=*/false);
	config::rvv_direct = false;
	config::rvv_verify = true;
	config::aot_use_llvm = true;
	for (auto const &r : rows) {
		auto const g = dbt::qir::rv32::RV32Translator::RvvHostChunkGeometry(r.vlen, r.sew_bytes);
		CHECK_EQ((unsigned)g.count, r.count);
		CHECK_EQ((unsigned)g.bytes, r.count ? r.bytes : 0u);
		if (g)
			CHECK_EQ((unsigned)g.bytes * g.count, r.vlen / 8u); // covers the register exactly
	}
	printf("  %zu rows: refused below 128, at non-multiples of 8 and at 96/192/384/768 (not a whole"
	       " number of 16/32/64-byte host vectors), at 8192 (k=16 > kMaxChunks) and at every"
	       " SEW != 32; 128/256/512/1024/2048/4096 -> {16,1}/{32,1}/{64,1}/{64,2}/{64,4}/{64,8}\n",
	       sizeof(rows) / sizeof(rows[0]));
}

// ---------------------------------------------------------------------------------------------
// [2] VLEN 512 AND 1024 DO NOT MOVE
// ---------------------------------------------------------------------------------------------
void TestWideNonRegression()
{
	printf("[2] at VLEN 512 and 1024 the switch changes NOTHING in the emitted QIR\n");
	struct Case {
		char const *name;
		std::vector<u32> body;
	};
	std::vector<Case> const cases = {
	    {"vxor.vv", {Vxor(9, 8, 7)}},
	    {"vor.vv", {Vor(9, 8, 7)}},
	    {"vse32.v", {Vse32()}},
	    {"vle32.v (S1)", {Vle32()}},
	    {"vsub.vv (A1)", {Vsub(9, 8, 7)}},
	    {"vmul.vv (A1)", {Vmul(9, 8, 7)}},
	    {"vand.vv (A1)", {Vand(9, 8, 7)}},
	    {"vmv.v.x (A2)", {Vmvvx(9, 7)}},
	    {"vsetvli", {}},
	    // A1: the whole six-opcode integer chain of the mixed microkernel in one region.
	    {"vadd/vsub/vmul/vand/vor/vxor chain",
	     {Vadd(3, 3, 2), Vsub(3, 3, 4), Vmul(3, 3, 2), Vand(3, 3, 4), Vor(3, 3, 5), Vxor(3, 3, 2)}},
	    // The whole five-instruction rotate shape in one region, so the equality covers the
	    // routes' interaction and not only each in isolation.
	    {"vadd/vxor/vsll/vsrl/vor + vse32",
	     {Vadd(3, 3, 2), Vxor(4, 3, 4), Vsll(5, 4, 7), Vsrl(6, 4, 25), Vor(4, 6, 5), Vse32(4)}},
	};
	for (u32 vlen : {512u, 1024u}) {
		for (auto const &c : cases) {
			ApplyConfig(vlen, /*narrow=*/false);
			Built off;
			Build(off, c.body);
			std::string const fp_off = Fingerprint(off.region);

			ApplyConfig(vlen, /*narrow=*/true);
			Built on;
			Build(on, c.body);
			std::string const fp_on = Fingerprint(on.region);

			if (fp_off != fp_on) {
				fprintf(stderr,
					"  FAIL VLEN %u %s: emitted QIR differs with the switch on\n",
					vlen, c.name);
				++g_failures;
			}
		}
		printf("  VLEN %4u: %zu cases, emitted QIR fingerprint identical off vs on\n", vlen,
		       cases.size());
	}
}

// ---------------------------------------------------------------------------------------------
// [3] WITH THE SWITCH OFF, 128 AND 256 STILL TAKE THE HELPER
// ---------------------------------------------------------------------------------------------
void TestSwitchOffNarrowRefuses()
{
	printf("[3] control: with the switch OFF, VLEN 128/256 keep the helper\n");
	for (u32 vlen : {128u, 256u}) {
		ApplyConfig(vlen, /*narrow=*/false);
		{
			Built b;
			Build(b, {Vxor(9, 8, 7)});
			CHECK_EQ(EmittedShape(b.region, Op::_vchunkxor).first, 0u);
		}
		{
			Built b;
			Build(b, {Vor(9, 8, 7)});
			CHECK_EQ(EmittedShape(b.region, Op::_vchunkor).first, 0u);
		}
		{
			Built b;
			Build(b, {Vse32()});
			CHECK_EQ(EmittedShape(b.region, Op::_vchunkstore).first, 0u);
		}
		{
			Built b;
			Build(b, {Vle32()});
			CHECK_EQ(EmittedShape(b.region, Op::_vchunkload).first, 0u);
		}
		{ // A1
			Built b;
			Build(b, {Vsub(9, 8, 7)});
			CHECK_EQ(EmittedShape(b.region, Op::_vchunksub).first, 0u);
		}
		{
			Built b;
			Build(b, {Vmul(9, 8, 7)});
			CHECK_EQ(EmittedShape(b.region, Op::_vchunkmul).first, 0u);
		}
		{
			Built b;
			Build(b, {Vand(9, 8, 7)});
			CHECK_EQ(EmittedShape(b.region, Op::_vchunkand).first, 0u);
		}
		{ // A2
			Built b;
			Build(b, {Vmvvx(9, 7)});
			CHECK_EQ(EmittedShape(b.region, Op::_vchunkbroadcast).first, 0u);
		}
		{ // A15 (GOLDEN CHANGE): the setup route does not depend on the narrow-chunk switch --
		  // it emits scalar moves only -- so with the switch OFF it is still admitted at 128/256.
			Built b;
			Build(b, {}, W_VSETVLI_E32M1);
			CHECK_EQ(CountRegionOp(b.region, Op::_rvvsetvl), 1u);
		}
		printf("  VLEN %u: vxor/vor/vse32/vle32/vsub/vmul/vand refused with the switch off; vsetvli admitted (A15)\n", vlen);
	}
}

// ---------------------------------------------------------------------------------------------
// [4] THE STORE CARRIES ITS WIDTH
// ---------------------------------------------------------------------------------------------
void TestStoreWindows()
{
	printf("[4] vse32.v: the data width is carried and the guest windows tile exactly\n");
	for (auto const &c : kWidths) {
		ApplyConfig(c.vlen, /*narrow=*/true);
		Built b;
		Build(b, {Vse32()});
		auto const frames = FindFrames(b.region);
		CHECK_EQ(frames.size(), 1u);
		if (frames.empty())
			continue;
		std::vector<unsigned> disps;
		for (auto *i : frames[0].body) {
			if (i->GetOpcode() != Op::_vchunkstore)
				continue;
			auto *st = static_cast<InstVChunkStore *>(i);
			// The DATA operand is i(1); i(0) is the (constant) address placeholder of the
			// indirect form.
			CHECK_EQ((unsigned)qir::VTypeToSize(st->i(1).GetType()), c.bytes);
			disps.push_back((unsigned)st->disp);
		}
		CHECK_EQ(disps.size(), (size_t)c.chunks);
		std::sort(disps.begin(), disps.end());
		unsigned covered = 0;
		for (unsigned k = 0; k < disps.size(); ++k) {
			CHECK_EQ(disps[k], k * c.bytes); // no gap, no overlap
			covered += c.bytes;
		}
		// Exactly the architectural register, not a byte more.
		CHECK_EQ(covered, c.vlen / 8u);
		// And the CPUState side reads the same windows out of the source register's slot.
		CHECK_EQ(CountOp(frames[0], Op::_vstatechunkload), c.chunks);
		CHECK_EQ((unsigned)frames[0].begin->n_typed, 2u * c.chunks);
		printf("  VLEN %4u: %u window(s) of %u bytes covering %u bytes total\n", c.vlen,
		       c.chunks, c.bytes, covered);
	}
}

// ---------------------------------------------------------------------------------------------
// [4b] THE LOAD CARRIES ITS WIDTH (S1, 2026-09-05) -- the mirror of [4]
// ---------------------------------------------------------------------------------------------
void TestLoadWindows()
{
	printf("[4b] vle32.v: the destination width is carried and the guest windows tile exactly\n");
	for (auto const &c : kWidths) {
		ApplyConfig(c.vlen, /*narrow=*/true);
		Built b;
		Build(b, {Vle32()});
		auto const frames = FindFrames(b.region);
		CHECK_EQ(frames.size(), 1u);
		if (frames.empty())
			continue;
		std::vector<unsigned> disps;
		for (auto *i : frames[0].body) {
			if (i->GetOpcode() != Op::_vchunkload)
				continue;
			auto *ld = static_cast<InstVChunkLoad *>(i);
			// The width the emitter will read is the DESTINATION operand's own type.
			CHECK_EQ((unsigned)qir::VTypeToSize(ld->o(0).GetType()), c.bytes);
			CHECK(ld->base_state_offs != InstVChunkLoad::NO_STATE_BASE); // indirect form
			disps.push_back((unsigned)ld->disp);
		}
		CHECK_EQ(disps.size(), (size_t)c.chunks);
		std::sort(disps.begin(), disps.end());
		unsigned covered = 0;
		for (unsigned k = 0; k < disps.size(); ++k) {
			CHECK_EQ(disps[k], k * c.bytes); // no gap, no overlap
			covered += c.bytes;
		}
		// Exactly the architectural register, not a byte more.
		CHECK_EQ(covered, c.vlen / 8u);
		// And the CPUState side writes the same windows into the destination register's slot,
		// each store carrying the same width and the same c * bytes displacement.
		std::vector<unsigned> st_offs;
		for (auto *i : frames[0].body) {
			if (i->GetOpcode() != Op::_vstatechunkstore)
				continue;
			auto *st = static_cast<InstVStateChunkStore *>(i);
			CHECK_EQ((unsigned)qir::VTypeToSize(st->i(0).GetType()), c.bytes);
			st_offs.push_back((unsigned)st->offs);
		}
		CHECK_EQ(st_offs.size(), (size_t)c.chunks);
		std::sort(st_offs.begin(), st_offs.end());
		for (unsigned k = 0; k < st_offs.size(); ++k)
			CHECK_EQ(st_offs[k] - st_offs[0], k * c.bytes);
		CHECK_EQ((unsigned)frames[0].begin->n_typed, 2u * c.chunks);
		printf("  VLEN %4u: %u window(s) of %u bytes covering %u bytes total\n", c.vlen,
		       c.chunks, c.bytes, covered);
	}
}

// ---------------------------------------------------------------------------------------------
// [5] Specialized-route refusals. Legal shapes may now use the separately tested
// general integer route, but must never enter the old restricted full-VL frame.
// ---------------------------------------------------------------------------------------------
void ExpectNoTypedChunk(char const *what, std::vector<u32> const &body, u32 lead = W_VSETVLI_E32M1)
{
	Built b;
	Build(b, body, lead);
	unsigned n = 0;
	for (auto const &f : FindFrames(b.region)) {
		if (f.begin->guard_kind == InstRVVTypedChunkBegin::GuardKind::VTypeInteger) {
			CHECK(!f.body.empty());
			for (auto *i : f.body) {
				// General vector-memory lowering has its own semantic and fault tests;
				// its node is not evidence that the restricted full-VL chunk route ran.
				if (i->GetOpcode() == Op::_vmemorynative)
					continue;
				CHECK(i->GetOpcode() == Op::_vchunkpartialalu);
				if (i->GetOpcode() == Op::_vchunkpartialalu)
					CHECK(static_cast<InstVChunkPartialAlu *>(i)->architectural_mask);
			}
			continue;
		}
		n += (unsigned)f.body.size();
	}
	if (n != 0) {
		fprintf(stderr, "  FAIL %s: emitted %u restricted chunk op(s)\n", what,
			n);
		++g_failures;
	} else {
		printf("  specialized route refused: %s\n", what);
	}
}

void TestFailClosed()
{
	printf("[5] unsupported specialized forms use the general route or fallback\n");

	ApplyConfig(128, /*narrow=*/true);
	ExpectNoTypedChunk("masked vxor.vv (vm=0)", {Enc(F6_VXOR, 0, 8, 7, F3_OPIVV, 9)});
	ExpectNoTypedChunk("masked vor.vv (vm=0)", {Enc(F6_VOR, 0, 8, 7, F3_OPIVV, 9)});
	ExpectNoTypedChunk("vxor.vx (scalar source)", {Enc(F6_VXOR, 1, 8, 7, F3_OPIVX, 9)});
	// A1: the three newly width-correct routes, masked and scalar-source forms.
	ExpectNoTypedChunk("masked vsub.vv (vm=0)", {Enc(F6_VSUB, 0, 8, 7, F3_OPIVV, 9)});
	ExpectNoTypedChunk("masked vmul.vv (vm=0)", {Enc(F6_VMUL, 0, 8, 7, F3_OPMVV, 9)});
	ExpectNoTypedChunk("masked vand.vv (vm=0)", {Enc(F6_VAND, 0, 8, 7, F3_OPIVV, 9)});
	ExpectNoTypedChunk("vsub.vx (scalar source)", {Enc(F6_VSUB, 1, 8, 7, F3_OPIVX, 9)});
	ExpectNoTypedChunk("vand.vx (scalar source)", {Enc(F6_VAND, 1, 8, 7, F3_OPIVX, 9)});
	// A2: everything that shares Op::_vmerge with vmv.v.x and is NOT vmv.v.x.
	ExpectNoTypedChunk("vmerge.vxm (vm=0)", {Enc(F6_VMERGE, 0, 8, 7, F3_OPIVX, 9)});
	ExpectNoTypedChunk("vmv.v.x with vs2 != 0 (reserved encoding)", {Enc(F6_VMERGE, 1, 3, 7, F3_OPIVX, 9)});
	// A7: vmv.v.v (OPIVV) and vmv.v.i (OPIVI) are now ADMITTED by the same switch; section [13]
	// pins their frames. The masked merges and reserved vs2 forms below still must refuse.
	ExpectNoTypedChunk("vmerge.vvm (OPIVV, vm=0)", {Enc(F6_VMERGE, 0, 8, 7, F3_OPIVV, 9)});
	ExpectNoTypedChunk("e64,m1 (SEW != 32), vmv.v.x", {Vmvvx(9, 7)}, W_VSETVLI_E64M1);
	ExpectNoTypedChunk("e32,m2 (LMUL != 1), vmv.v.x", {Vmvvx(9, 7)}, W_VSETVLI_E32M2);
	ExpectNoTypedChunk("e16,m1 (SEW != 32), vmv.v.x", {Vmvvx(9, 7)}, 0x0d457557u);
	ExpectNoTypedChunk("masked vse32.v", {EncMem(0, 0, 0, 0, 0, 16, W_EEW32, 8, OP_STORE_FP)});
	ExpectNoTypedChunk("vse8.v (EEW != 32)", {EncMem(0, 0, 0, 1, 0, 16, W_EEW8, 8, OP_STORE_FP)});
	ExpectNoTypedChunk("vse64.v (EEW != 32)",
			   {EncMem(0, 0, 0, 1, 0, 16, W_EEW64, 8, OP_STORE_FP)});
	ExpectNoTypedChunk("vsse32.v (strided, mop=10)",
			   {EncMem(0, 0, 0b10, 1, 0, 16, W_EEW32, 8, OP_STORE_FP)});
	ExpectNoTypedChunk("vsuxei32.v (indexed, mop=01)",
			   {EncMem(0, 0, 0b01, 1, 0, 16, W_EEW32, 8, OP_STORE_FP)});
	ExpectNoTypedChunk("vsseg2e32.v (nf != 0)",
			   {EncMem(1, 0, 0, 1, 0, 16, W_EEW32, 8, OP_STORE_FP)});
	ExpectNoTypedChunk("vs1r.v (sumop != 0)",
			   {EncMem(0, 0, 0, 1, 0b01000, 16, W_EEW32, 8, OP_STORE_FP)});
	ExpectNoTypedChunk("vse32.v with base x0", {EncMem(0, 0, 0, 1, 0, 0, W_EEW32, 8, OP_STORE_FP)});
	// S1: the load side's refusals, field for field.
	ExpectNoTypedChunk("masked vle32.v", {EncMem(0, 0, 0, 0, 0, 16, W_EEW32, 8, OP_LOAD_FP)});
	ExpectNoTypedChunk("vle8.v (EEW != 32)", {EncMem(0, 0, 0, 1, 0, 16, W_EEW8, 8, OP_LOAD_FP)});
	ExpectNoTypedChunk("vle64.v (EEW != 32)", {EncMem(0, 0, 0, 1, 0, 16, W_EEW64, 8, OP_LOAD_FP)});
	ExpectNoTypedChunk("vlse32.v (strided, mop=10)",
			   {EncMem(0, 0, 0b10, 1, 0, 16, W_EEW32, 8, OP_LOAD_FP)});
	ExpectNoTypedChunk("vluxei32.v (indexed, mop=01)",
			   {EncMem(0, 0, 0b01, 1, 0, 16, W_EEW32, 8, OP_LOAD_FP)});
	ExpectNoTypedChunk("vlseg2e32.v (nf != 0)",
			   {EncMem(1, 0, 0, 1, 0, 16, W_EEW32, 8, OP_LOAD_FP)});
	ExpectNoTypedChunk("vle32ff.v (lumop != 0)",
			   {EncMem(0, 0, 0, 1, 0b10000, 16, W_EEW32, 8, OP_LOAD_FP)});
	ExpectNoTypedChunk("vle32.v with base x0", {EncMem(0, 0, 0, 1, 0, 0, W_EEW32, 8, OP_LOAD_FP)});

	// SEW and LMUL come from the observed vtype: the lead vsetvli is the thing being varied.
	ApplyConfig(128, /*narrow=*/true);
	ExpectNoTypedChunk("e64,m1 (SEW != 32)", {Vxor(9, 8, 7), Vse32()}, W_VSETVLI_E64M1);
	ExpectNoTypedChunk("e32,m2 (LMUL != 1)", {Vxor(9, 8, 7), Vse32()}, W_VSETVLI_E32M2);
	ExpectNoTypedChunk("e64,m1 (SEW != 32), vsub/vmul/vand", {Vsub(9, 8, 7), Vmul(9, 8, 7), Vand(9, 8, 7)},
			   W_VSETVLI_E64M1);
	ExpectNoTypedChunk("e32,m2 (LMUL != 1), vsub/vmul/vand", {Vsub(9, 8, 7), Vmul(9, 8, 7), Vand(9, 8, 7)},
			   W_VSETVLI_E32M2);
	ExpectNoTypedChunk("e16,m1 (SEW != 32), vsub/vmul/vand", {Vsub(9, 8, 7), Vmul(9, 8, 7), Vand(9, 8, 7)},
			   0x0d457557u /* vsetvli a0,a0,e16,m1,ta,ma */);

	// The rd=x0,rs1=x0 vsetvli (retained vl). A15 (GOLDEN CHANGE): at 128 it is admitted exactly
	// as T7S admits it at 512/1024 -- the node carries keep_vl and the emitter's reserved arm
	// (new VLMAX < vl -> vill, vl = 0) implements the runtime-conditional write set.
	ApplyConfig(128, /*narrow=*/true);
	ExpectNoTypedChunk("vsetvli rd=x0,rs1=x0 (retained-vl form)", {}, W_VSETVLI_KEEPVL);
	{
		Built b;
		Build(b, {}, W_VSETVLI_KEEPVL);
		CHECK_EQ(CountRegionOp(b.region, Op::_rvvsetvl), 1u);
	}

	ApplyConfig(128, /*narrow=*/true);
	config::rvv_verify = true;
	ExpectNoTypedChunk("--rvv-verify", {Vxor(9, 8, 7), Vor(11, 10, 7), Vse32()});

	ApplyConfig(128, /*narrow=*/true);
	config::rvv_direct = false;
	ExpectNoTypedChunk("--rvv-direct off", {Vxor(9, 8, 7), Vor(11, 10, 7), Vse32()});

	// W5 (2026-09-17) WIDENED THE LLVM ARM, so this pair asserts the new behaviour and the thing
	// that did NOT change alongside it.
	//
	// It used to read "THE LLVM ARM IS NOT WIDENED", with two independent reasons: RvvSSAEnabled()
	// refused VLEN < 512, and RvvNarrowWidthChunkGeometry refuses the LLVM backend outright. The
	// first is gone -- the LLVM gates now ask RvvLLVMTypedSubstrate() and take their width from
	// RvvRouteChunkShape's own geometry branch. The SECOND IS UNCHANGED and is why this check still
	// has to exist: the LLVM arm gets its narrow shape from the shared geometry, NOT from the
	// pure-QCG narrow route, so `--rvv-qcg-narrow-chunk-width` (off below) has no bearing on it.
	// Section [1]'s three-predicates-agree row is what pins that refusal directly.
	for (u32 vlen : {128u, 256u}) {
		ApplyConfig(vlen, /*narrow=*/false); // the QCG narrow switch is OFF on purpose
		config::aot_use_llvm = true;
		config::rvv_vector_ssa = true;
		Built b;
		Build(b, {Vxor(9, 8, 7), Vor(11, 10, 7)}, W_VSETVLI_E32M1);
		auto const frames = FindFrames(b.region);
		CHECK_EQ(frames.size(), (size_t)2);
		u32 const want_bytes = vlen / 8u;
		for (auto const &f : frames) {
			CHECK(!f.body.empty());
			for (auto *i : f.body) {
				auto out = i->outputs();
				for (u8 k = 0; k < out.size(); ++k) {
					if (IsVectorVType(out[k].GetType()))
						CHECK_EQ((unsigned)qir::VTypeToSize(out[k].GetType()),
							 want_bytes);
				}
			}
		}
		printf("  LLVM backend at VLEN %u: typed frames at %u-byte chunks, QCG narrow switch off\n",
		       vlen, want_bytes);
	}

	// The memory routes' extra exclusion, unchanged: `--rvv-lowering 0` is the scalar reference
	// arm, whose address rule WRAPS modulo 2^32 while this frame walks host pointers.
	ApplyConfig(128, /*narrow=*/true);
	config::rvv_lowering = 0;
	ExpectNoTypedChunk("--rvv-lowering 0 (scalar reference arm), vse32.v", {Vse32()});
	ExpectNoTypedChunk("--rvv-lowering 0 (scalar reference arm), vle32.v", {Vle32()});

	// A VLEN whose register is not a whole number of host chunks REFUSES rather than rounds. This
	// is the row that keeps VectorVTypeForBytes from being handed a 48.
	ApplyConfig(384, /*narrow=*/true);
	ExpectNoTypedChunk("VLEN 384 (48-byte register is no host chunk width)",
			   {Vxor(9, 8, 7), Vor(11, 10, 7), Vse32(), Vle32()});
	ApplyConfig(64, /*narrow=*/true);
	ExpectNoTypedChunk("VLEN 64 (below the narrowest host vector)",
			   {Vxor(9, 8, 7), Vor(11, 10, 7), Vse32(), Vle32()});
}

// ---------------------------------------------------------------------------------------------
// [6] THE NON-WIDENING IS DELIBERATE
// ---------------------------------------------------------------------------------------------
void TestDeliberateNonWidening()
{
	printf("[6] A1: vsub/vmul/vand are routed at 128/256 with the switch on, at [1]'s geometry, and\n"
	       "    the run admits them at the same width\n");
	struct Case {
		char const *name;
		u32 word;
		Op lane_op;
	};
	Case const cases[] = {
	    {"vsub.vv", Vsub(9, 8, 7), Op::_vchunksub},
	    {"vmul.vv", Vmul(9, 8, 7), Op::_vchunkmul},
	    {"vand.vv", Vand(9, 8, 7), Op::_vchunkand},
	};
	for (auto const &c : kWidths) {
		for (auto const &r : cases) {
			ApplyConfig(c.vlen, /*narrow=*/true);
			Built b;
			Build(b, {r.word});
			auto const [n, w] = EmittedShape(b.region, r.lane_op);
			CHECK_EQ(n, c.chunks);
			CHECK_EQ(w, c.bytes);
			// The single-instruction frame: k loads per source, k lane ops, k stores.
			auto const frames = FindFrames(b.region);
			CHECK_EQ(frames.size(), 1u);
			if (!frames.empty()) {
				CHECK_EQ(CountOp(frames[0], Op::_vstatechunkload), 2u * c.chunks);
				CHECK_EQ(CountOp(frames[0], Op::_vstatechunkstore), c.chunks);
				CHECK_EQ((unsigned)frames[0].begin->n_typed, 4u * c.chunks);
			}
		}
		// The RUN uses the same shape fact: a sub -> mul -> and chain forms ONE three-member
		// run at this width, every value at the run's own chunk width.
		ApplyConfig(c.vlen, /*narrow=*/true, /*run=*/true);
		Built b;
		Build(b, {Vsub(3, 3, 2), Vmul(3, 3, 4), Vand(3, 3, 5)});
		Frame const *run = nullptr;
		auto const run_frames = FindFrames(b.region);
		for (auto const &f : run_frames)
			if (f.end->n_members >= 2)
				run = &f;
		CHECK(run != nullptr);
		if (run) {
			CHECK_EQ((unsigned)run->end->n_members, 3u);
			CHECK_EQ(CountOp(*run, Op::_vchunksub), c.chunks);
			CHECK_EQ(CountOp(*run, Op::_vchunkmul), c.chunks);
			CHECK_EQ(CountOp(*run, Op::_vchunkand), c.chunks);
			for (auto *i : run->body)
				if (i->OutputCount() && IsVectorVType(i->o(0).GetType()))
					CHECK_EQ((unsigned)qir::VTypeToSize(i->o(0).GetType()), c.bytes);
		}
		printf("  VLEN %4u: vsub/vmul/vand -> %u x %u-byte chunk(s); sub->mul->and run of 3 members\n",
		       c.vlen, c.chunks, c.bytes);
	}
}

// ---------------------------------------------------------------------------------------------
// [7] THE RUN
// ---------------------------------------------------------------------------------------------
void TestRun()
{
	printf("[7] at VLEN 128/256 the rotate shape forms ONE five-member narrow run\n");
	// The ISA shape of a rotate-and-mix step, written from the RVV encoding: no PC, no workload
	// constant, no workload register number.
	//   v3 = v3 + v2 ; v4 = v4 ^ v3 ; v5 = v4 << 7 ; v6 = v4 >> 25 ; v4 = v6 | v5
	std::vector<u32> const body = {Vadd(3, 3, 2), Vxor(4, 3, 4), Vsll(5, 4, 7), Vsrl(6, 4, 25),
				       Vor(4, 6, 5)};
	for (auto const &c : kWidths) {
		ApplyConfig(c.vlen, /*narrow=*/true, /*run=*/true);
		Built b;
		Build(b, body);
		Frame const *run = nullptr;
		auto const frames = FindFrames(b.region);
		for (auto const &f : frames)
			if (f.end->n_members >= 2)
				run = &f;
		CHECK(run != nullptr);
		if (!run)
			continue;
		unsigned const k = c.chunks;
		CHECK_EQ((unsigned)run->end->n_members, 5u);
		CHECK_EQ(CountOp(*run, Op::_vchunkadd), k);
		CHECK_EQ(CountOp(*run, Op::_vchunkxor), k);
		CHECK_EQ(CountOp(*run, Op::_vchunksll), k);
		CHECK_EQ(CountOp(*run, Op::_vchunksrl), k);
		CHECK_EQ(CountOp(*run, Op::_vchunkor), k);
		// Component residence: three live-ins loaded once, four live-outs stored once, and
		// NOTHING in between.
		CHECK_EQ(CountOp(*run, Op::_vstatechunkload), 3u * k);
		CHECK_EQ(CountOp(*run, Op::_vstatechunkstore), 4u * k);
		// Every value in the run is the run's own chunk width.
		for (auto *i : run->body)
			if (i->OutputCount() && IsVectorVType(i->o(0).GetType()))
				CHECK_EQ((unsigned)qir::VTypeToSize(i->o(0).GetType()),
					 c.bytes);
		printf("  VLEN %4u: 5 members over %u chunk(s) of %u bytes, %u loads, %u stores\n",
		       c.vlen, k, c.bytes, 3u * k, 4u * k);
	}

	// THE CONTROL, and it is what makes the section above about THIS switch: with it off, the
	// same five instructions at VLEN 128/256 cannot form one run, because vxor and vor fall to
	// the helper and cut the scan.
	for (u32 vlen : {128u, 256u}) {
		ApplyConfig(vlen, /*narrow=*/false, /*run=*/true);
		Built b;
		Build(b, body);
		unsigned longest = 0;
		for (auto const &f : FindFrames(b.region))
			longest = std::max<unsigned>(longest, f.end->n_members);
		CHECK(longest < 5u);
		printf("  control VLEN %u: with the switch off the longest run is %u members, not 5\n",
		       vlen, longest);
	}
}

// ---------------------------------------------------------------------------------------------
// [8] MUTATION -- each check is shown to fail when the thing it checks is broken.
// ---------------------------------------------------------------------------------------------
void TestMutationSensitivity()
{
	printf("[8] the checks are falsifiable\n");

	// (a) The [2] fingerprint is not vacuous: it DOES distinguish two shapes. The same region at
	//     VLEN 512 and at VLEN 1024 must produce different fingerprints -- if it did not, the
	//     equality in [2] would pass no matter what the switch did.
	ApplyConfig(512, /*narrow=*/true);
	Built a;
	Build(a, {Vxor(9, 8, 7), Vse32()});
	std::string const fp512 = Fingerprint(a.region);
	ApplyConfig(1024, /*narrow=*/true);
	Built c;
	Build(c, {Vxor(9, 8, 7), Vse32()});
	std::string const fp1024 = Fingerprint(c.region);
	CHECK(fp512 != fp1024);
	// And it distinguishes a narrow shape from a wide one, which is the difference the switch
	// actually makes at 128.
	ApplyConfig(128, /*narrow=*/true);
	Built d;
	Build(d, {Vxor(9, 8, 7), Vse32()});
	CHECK(Fingerprint(d.region) != fp512);
	printf("  the fingerprint separates VLEN 512 / 1024 / 128-narrow\n");

	// (b) EmittedShape's width really is read from the value and is not a constant: the accepted
	//     vadd route at VLEN 128 must report 16 and at VLEN 512 must report 64 through the SAME
	//     helper this file uses for the routes under test.
	ApplyConfig(128, /*narrow=*/true);
	Built e;
	Build(e, {Vadd(9, 8, 7)});
	CHECK_EQ(EmittedShape(e.region, Op::_vchunkadd).second, 16u);
	ApplyConfig(512, /*narrow=*/true);
	Built f;
	Build(f, {Vadd(9, 8, 7)});
	CHECK_EQ(EmittedShape(f.region, Op::_vchunkadd).second, 64u);

	// (c) ExpectNoTypedChunk is not vacuous: the admitted forms it is contrasted against DO emit
	//     typed ops at the same VLEN.
	ApplyConfig(128, /*narrow=*/true);
	Built g;
	Build(g, {Vxor(9, 8, 7), Vor(11, 10, 7), Vse32()});
	unsigned typed = 0;
	for (auto const &fr : FindFrames(g.region))
		typed += (unsigned)fr.body.size();
	CHECK(typed > 0u);
	printf("  the refusal helper is not vacuous: the admitted forms emit %u typed op(s)\n",
	       typed);

	// (d) The store's cover check is real: a shape that does not tile the register must be
	//     rejected rather than emitted. Build the node directly, since no admitted route can
	//     produce one.
	{
		auto data16 = VOperand::MakeVVPR(VType::V128, 1);
		// A 16-byte store at displacement 16 tiles; at displacement 8 it would overlap the
		// previous window, and the constructor is what forbids it. We can only assert the
		// legal one here without aborting the process, so assert that the LEGAL one is
		// accepted and that the width the node reports is the data's.
		InstVChunkStore ok(64u, 16u, data16);
		CHECK_EQ((unsigned)ok.disp, 16u);
		CHECK_EQ((unsigned)qir::VTypeToSize(ok.i(1).GetType()), 16u);
	}
}

// ---------------------------------------------------------------------------------------------
// [9] THE EMITTED HOST BYTES CARRY THE WIDTH
// ---------------------------------------------------------------------------------------------
// MUTATION RECORD FOR THIS SECTION, run by hand while it was written: replacing
// Emit_vchunkstore's `store_bytes` with the literal 64 -- which is what the emitter said before
// this checkpoint, and what a `/8` unit slip in the derivation also produces -- turns this section
// RED with 6 failures at VLEN 128 and 256 and leaves 512 and 1024 green, which is exactly the blast
// radius the switch has. That mutation is a 64-byte write over guest memory a VLEN=128 store was
// never asked to touch, and no other test in the tree notices it.
void TestEmittedWidth()
{
	printf("[9] the emitted host bytes are xmm / ymm / zmm as the VLEN says\n");
	struct EmitCase {
		u32 vlen;
		char const *cls;
		unsigned lane_ops; // one per chunk
	};
	EmitCase const cases[] = {
	    {128, "xmm", 1}, {256, "ymm", 1}, {512, "zmm", 1}, {1024, "zmm", 2}};
	// objdump's Intel-syntax name for the MEMORY operand's size, which is the half of the encoding
	// the register class does not pin. A 64-byte window emitted for a 16-byte register would show
	// up here as ZMMWORD next to an xmm register, and nowhere else.
	auto ptr_kw = [](char const *cls) -> char const * {
		if (std::string(cls) == "xmm")
			return "XMMWORD PTR";
		if (std::string(cls) == "ymm")
			return "YMMWORD PTR";
		return "ZMMWORD PTR";
	};
	for (auto const &c : cases) {
		ApplyConfig(c.vlen, /*narrow=*/true);
		// One xor and one or, then the store: three routes in one region.
		auto const lines = EmitAndDisassemble({Vxor(9, 8, 7), Vor(11, 10, 7), Vse32()});
		if (lines.empty())
			continue;
		unsigned const xors = CountMnemonicWithClass(lines, "vpxord", c.cls);
		unsigned const ors = CountMnemonicWithClass(lines, "vpord", c.cls);
		unsigned const movs = CountMnemonicWithClass(lines, "vmovdqu64", c.cls);
		CHECK_EQ(xors, c.lane_ops);
		CHECK_EQ(ors, c.lane_ops);
		// The store frame moves each chunk twice: CPUState -> register, register -> guest
		// memory. The two xor/or frames move theirs three times each (two loads, one store).
		CHECK_EQ(movs, 8u * c.lane_ops);
		// NOTHING of another width may appear. This is the check that would have caught a
		// 64-byte window emitted for a 16-byte register.
		for (char const *other : {"xmm", "ymm", "zmm"}) {
			if (std::string(other) == c.cls)
				continue;
			CHECK_EQ(CountMnemonicWithClass(lines, "vpxord", other), 0u);
			CHECK_EQ(CountMnemonicWithClass(lines, "vpord", other), 0u);
			CHECK_EQ(CountMnemonicWithClass(lines, "vmovdqu64", other), 0u);
		}
		// Every one of them is EVEX: at 128/256 the VEX encoding would be the shorter legal
		// form, and which one appeared would then depend on the register the allocator handed
		// out rather than on the guest instruction.
		CHECK_EQ(CountMnemonic(lines, "vpxor "), 0u); // the VEX mnemonic, if any escaped
		CHECK_EQ(CountMnemonic(lines, "vpor "), 0u);
		CHECK_EQ(CountMnemonic(lines, "vmovdqu "), 0u);
		// AND THE MEMORY OPERAND SIZE. Every vmovdqu64 this route emits touches a window of
		// exactly the chunk width; no other PTR size may appear anywhere in the region.
		unsigned mem_right = 0;
		for (auto const &l : lines) {
			auto const at = l.find('\t');
			if (at == std::string::npos)
				continue;
			std::string const text = l.substr(at + 1);
			if (text.rfind("vmovdqu64", 0) != 0)
				continue;
			if (text.find(ptr_kw(c.cls)) != std::string::npos)
				++mem_right;
			for (char const *other : {"XMMWORD PTR", "YMMWORD PTR", "ZMMWORD PTR"}) {
				if (std::string(other) == ptr_kw(c.cls))
					continue;
				CHECK(text.find(other) == std::string::npos);
			}
		}
		CHECK_EQ(mem_right, movs);
		printf("  VLEN %4u: %u vpxord, %u vpord, %u vmovdqu64 (%u %s), all %s, no other width\n",
		       c.vlen, xors, ors, movs, mem_right, ptr_kw(c.cls), c.cls);

		// A1: the three routes that joined the width rule. vpsubd and vpmulld HAVE a VEX form,
		// so the emitter's EvexOnly is what keeps the narrow widths EVEX; this is checked on the
		// ENCODING BYTES (0x62 vs 0xc4/0xc5), independent of the objdump version. vpandd is
		// EVEX-only by construction and is checked the same way.
		auto const l2 = EmitAndDisassemble({Vsub(9, 8, 7), Vmul(11, 10, 7), Vand(13, 12, 7)},
						   W_VSETVLI_E32M1, /*raw_bytes=*/true);
		if (l2.empty())
			continue;
		auto const [sub_evex, sub_vex] = CountEncodings(l2, "vpsubd", c.cls);
		auto const [mul_evex, mul_vex] = CountEncodings(l2, "vpmulld", c.cls);
		auto const [and_evex, and_vex] = CountEncodings(l2, "vpandd", c.cls);
		CHECK_EQ(sub_evex, c.lane_ops);
		CHECK_EQ(mul_evex, c.lane_ops);
		CHECK_EQ(and_evex, c.lane_ops);
		CHECK_EQ(sub_vex, 0u);
		CHECK_EQ(mul_vex, 0u);
		CHECK_EQ(and_vex, 0u);
		for (char const *other : {"xmm", "ymm", "zmm"}) {
			if (std::string(other) == c.cls)
				continue;
			for (char const *m : {"vpsubd", "vpmulld", "vpandd", "vmovdqu64"}) {
				auto const [e, v] = CountEncodings(l2, m, other);
				CHECK_EQ(e + v, 0u);
			}
		}
		{
			auto const [mv_evex, mv_vex] = CountEncodings(l2, "vmovdqu64", c.cls);
			CHECK_EQ(mv_evex, 9u * c.lane_ops);
			CHECK_EQ(mv_vex, 0u);
		}
		CHECK_EQ(CountMnemonic(l2, "vpand "), 0u); // the VEX and, if any escaped
		printf("  VLEN %4u: A1 %u vpsubd, %u vpmulld, %u vpandd, all %s and all EVEX (0 VEX)\n",
		       c.vlen, sub_evex, mul_evex, and_evex, c.cls);
	}
}

// ---------------------------------------------------------------------------------------------
// [10] A2: THE vmv.v.x FRAME AND ITS HOST BYTES
// ---------------------------------------------------------------------------------------------
void TestVmvFrame()
{
	printf("[10] A2 vmv.v.x: one broadcast of the GPR slot, k stores tiling vd, EVEX vpbroadcastd\n");
	for (auto const &c : kWidths) {
		for (u32 rs1 : {7u, 0u}) { // a normal GPR and x0
			ApplyConfig(c.vlen, /*narrow=*/true);
			Built b;
			Build(b, {Vmvvx(9, rs1)});
			auto const frames = FindFrames(b.region);
			CHECK_EQ(frames.size(), 1u);
			if (frames.empty())
				continue;
			auto const &f = frames[0];
			CHECK_EQ(CountOp(f, Op::_vchunkbroadcast), 1u);
			CHECK_EQ(CountOp(f, Op::_vstatechunkstore), c.chunks);
			CHECK_EQ(CountOp(f, Op::_vstatechunkload), 0u);
			CHECK_EQ((unsigned)f.begin->n_typed, 1u + c.chunks);
			CHECK((unsigned)f.begin->stub == (unsigned)RuntimeStubId::id_rv32_vmerge);
			std::vector<unsigned> offs;
			for (auto *i : f.body) {
				if (i->GetOpcode() == Op::_vchunkbroadcast) {
					auto *bc = static_cast<InstVChunkBroadcast *>(i);
					CHECK_EQ((unsigned)qir::VTypeToSize(bc->o(0).GetType()), c.bytes);
					CHECK_EQ((unsigned)bc->offs, (unsigned)(offsetof(CPUState, gpr) + 4u * rs1));
					CHECK_EQ((unsigned)bc->sew_bytes, 4u);
				}
				if (i->GetOpcode() == Op::_vstatechunkstore) {
					auto *st = static_cast<InstVStateChunkStore *>(i);
					CHECK_EQ((unsigned)qir::VTypeToSize(st->i(0).GetType()), c.bytes);
					offs.push_back((unsigned)st->offs);
				}
			}
			std::sort(offs.begin(), offs.end());
			unsigned const vd_base = (unsigned)(offsetof(CPUState, vec) +
							     offsetof(dbt::rv32::VectorState, vreg) +
							     9u * dbt::rv32::VLEN_MAX_BYTES);
			for (unsigned k = 0; k < offs.size(); ++k)
				CHECK_EQ(offs[k], vd_base + k * c.bytes); // tiles vd exactly, no gap
		}
		// Host bytes: exactly one vpbroadcastd of the class the VLEN says, EVEX, DWORD source.
		char const *const cls = c.bytes == 16 ? "xmm" : c.bytes == 32 ? "ymm" : "zmm";
		ApplyConfig(c.vlen, /*narrow=*/true);
		auto const l = EmitAndDisassemble({Vmvvx(9, 7)}, W_VSETVLI_E32M1, /*raw_bytes=*/true);
		if (l.empty())
			continue;
		auto const [bc_evex, bc_vex] = CountEncodings(l, "vpbroadcastd", cls);
		CHECK_EQ(bc_evex, 1u);
		CHECK_EQ(bc_vex, 0u);
		for (char const *other : {"xmm", "ymm", "zmm"}) {
			if (std::string(other) == cls)
				continue;
			auto const [e, v] = CountEncodings(l, "vpbroadcastd", other);
			CHECK_EQ(e + v, 0u);
		}
		unsigned dword_src = 0;
		for (auto const &line : l)
			if (line.find("vpbroadcastd") != std::string::npos &&
			    line.find("DWORD PTR [r13+") != std::string::npos)
				++dword_src;
		CHECK_EQ(dword_src, 1u);
		auto const [st_evex, st_vex] = CountEncodings(l, "vmovdqu64", cls);
		CHECK_EQ(st_evex, c.chunks);
		CHECK_EQ(st_vex, 0u);
		printf("  VLEN %4u: 1 vpbroadcastd %s (EVEX, DWORD source), %u store(s) of %u bytes; x0 -> gpr[0] slot\n",
		       c.vlen, cls, c.chunks, c.bytes);
	}
}

// ---------------------------------------------------------------------------------------------
// [11] A3: THE PARTIAL-vl ARM
// ---------------------------------------------------------------------------------------------
void TestPartialArm()
{
	printf("[11] partial/restart arm: one marker, bounded mask-and-ALU node per member per chunk\n");
	std::vector<u32> const chain = {Vsub(3, 3, 2), Vmul(3, 3, 4), Vand(5, 3, 3)};
	// A3-fix: a run near TB capacity: 60 members, all six ops, ONE accumulator (v4) with sources
	// v1..v3 -- the shape that keeps the full SSA body's register pressure low, so the long run
	// itself is admitted at every width. (A 60-member chain spread over v4..v9 already spills
	// in the FULL body at VLEN 1024 with live-range splitting off -- a pre-existing allocator
	// limit, recorded in the A3-fix report, not something the arm changes.)
	std::vector<u32> longchain_mut;
	for (unsigned r = 0; r < 10; ++r) {
		longchain_mut.push_back(Vadd(4, 4, 1)); longchain_mut.push_back(Vsub(4, 4, 2));
		longchain_mut.push_back(Vmul(4, 4, 3)); longchain_mut.push_back(Vand(4, 4, 1));
		longchain_mut.push_back(Vor(4, 4, 2)); longchain_mut.push_back(Vxor(4, 4, 3));
	}
	std::vector<u32> const longchain = longchain_mut;
	for (auto const &c : kWidths) {
		ApplyConfig(c.vlen, /*narrow=*/true, /*run=*/true, /*partial=*/false);
		Built off;
		Build(off, chain);
		CHECK_EQ(CountRegionOp(off.region, Op::_rvvtypedchunkpartial), 0u);
		CHECK_EQ(CountRegionOp(off.region, Op::_vchunkmaskset), 0u);
		CHECK_EQ(CountRegionOp(off.region, Op::_vchunkpartialalu), 0u);
		ApplyConfig(c.vlen, /*narrow=*/true, /*run=*/true, /*partial=*/true);
		unsigned const k = c.chunks;
		for (std::vector<u32> const *body : {&chain, &longchain}) {
			unsigned const n = (unsigned)body->size();
			Built on;
			Build(on, *body);
			auto const frames = FindFrames(on.region);
			Frame const *run = nullptr;
			for (auto const &f : frames)
				if (f.end->n_members >= 2)
					run = &f;
			CHECK(run != nullptr);
			if (!run)
				continue;
			CHECK_EQ((unsigned)run->end->n_members, n);
			CHECK((unsigned)run->begin->guard_kind ==
			      (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeIntegerTwoArm);
			CHECK_EQ(CountOp(*run, Op::_rvvtypedchunkpartial), 1u);
			CHECK_EQ(CountOp(*run, Op::_vchunkmaskset), 0u);
			CHECK_EQ(CountOp(*run, Op::_vchunkpartialalu), n * k);
			unsigned before = 0, after = 0; bool seen = false;
			for (auto *i : run->body) {
				if (i->GetOpcode() == Op::_rvvtypedchunkpartial) { seen = true; continue; }
				(seen ? after : before)++;
			}
			CHECK_EQ(after, n * k);
			CHECK_EQ((unsigned)run->begin->n_typed, before + after);
			// The arm creates NO virtual register: the region's vreg count with the arm equals
			// the count without it.
			ApplyConfig(c.vlen, /*narrow=*/true, /*run=*/true, /*partial=*/false);
			Built off2;
			Build(off2, *body);
			CHECK_EQ((unsigned)on.region->GetVRegsInfo()->NumAll(),
				 (unsigned)off2.region->GetVRegsInfo()->NumAll());
			ApplyConfig(c.vlen, /*narrow=*/true, /*run=*/true, /*partial=*/true);
			// Every node names windows of the run's chunk width, in the right register slots.
			unsigned const slot = dbt::rv32::VLEN_MAX_BYTES;
			unsigned const vbase = (unsigned)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
			unsigned idx = 0;
			for (auto *i : run->body) {
				if (i->GetOpcode() != Op::_vchunkpartialalu)
					continue;
				auto *p = static_cast<InstVChunkPartialAlu *>(i);
				u32 const w = (*body)[idx / k];
				unsigned const vd = (w >> 7) & 31, vs1 = (w >> 15) & 31, vs2 = (w >> 20) & 31;
				CHECK_EQ((unsigned)p->chunk_bytes, c.bytes);
				CHECK_EQ((unsigned)p->chunk, idx % k);
				CHECK_EQ((unsigned)p->rd_offs, vbase + vd * slot + (idx % k) * c.bytes);
				CHECK_EQ((unsigned)p->rs2_offs, vbase + vs2 * slot + (idx % k) * c.bytes);
				CHECK_EQ((unsigned)p->rs1_offs, vbase + vs1 * slot + (idx % k) * c.bytes);
				CHECK(p->architectural_mask && !p->masked);
				CHECK_EQ(p->element_base, (idx % k) * c.bytes / 4u);
				CHECK(p->finish_instruction == (idx % k + 1 == k));
				++idx;
			}
			CHECK_EQ(idx, n * k);
		}
		Built one;
		Build(one, {Vadd(9, 8, 7)});
		auto const f1 = FindFrames(one.region);
		CHECK_EQ(f1.size(), 1u);
		if (!f1.empty()) {
			CHECK_EQ(CountOp(f1[0], Op::_rvvtypedchunkpartial), 1u);
			CHECK_EQ((unsigned)f1[0].begin->n_typed, 4u * k + k);
		}
		Built mixed;
		Build(mixed, {Vadd(3, 3, 2), Vsll(4, 3, 7)});
		CHECK_EQ(CountRegionOp(mixed.region, Op::_rvvtypedchunkpartial), 1u);
		for (auto const &f : FindFrames(mixed.region))
			CHECK((unsigned)f.begin->guard_kind ==
			      (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeIntegerTwoArm);
		// Host bytes (the 60-member run): 60k kmovq, 60k masked stores of the width's class using
		// ONLY the reserved scratch registers 0/1, and no vpblendmd anywhere.
		auto const l = EmitAndDisassemble(longchain, W_VSETVLI_E32M1, /*raw_bytes=*/true);
		char const *const cls = c.bytes == 16 ? "xmm" : c.bytes == 32 ? "ymm" : "zmm";
		unsigned kmov = 0, mstore = 0, scratch_ops = 0, blend = 0;
		for (auto const &line : l) {
			if (line.find("kmovq") != std::string::npos) ++kmov;
			if (line.find("vmovdqu32") != std::string::npos && line.find("{k") != std::string::npos &&
			    line.find(std::string(cls) + "0") != std::string::npos) ++mstore;
			if (line.find("vpblendmd") != std::string::npos) ++blend;
			for (char const *mn : {"vpaddd ", "vpsubd ", "vpmulld ", "vpandd ", "vpord  ", "vpxord "})
				if (line.find(mn) != std::string::npos && line.find(std::string(cls) + "0," + cls + "0," + cls + "1") != std::string::npos)
					++scratch_ops;
		}
		CHECK_EQ(kmov, 60u * k);
		CHECK_EQ(mstore, 60u * k);
		CHECK_EQ(scratch_ops, 60u * k);
		CHECK_EQ(blend, 0u);
		printf("  VLEN %4u: runs of 3 and 60 -> 1 arm each, %u mask(s), %u bounded nodes for the long run, 0 new vregs, %u masked %s stores on scratch 0/1\n",
		       c.vlen, k, 60u * k, mstore, cls);
	}
}


// [12] A6: THE vadd.vx / vadd.vi FRAMES, THEIR PARTIAL ARM AND THEIR HOST BYTES
//
// What each assertion would catch if the route were wrong:
//   * k vs2 loads + ONE broadcast + k adds + k stores, n_typed = 3k+1 -> a body that still loaded
//     a "vs1" window for a GPR number or an immediate (reading vector register x[rs1] as data),
//     or one that broadcast per chunk;
//   * the broadcast's CPUState offset is gpr[rs1] (x0 -> gpr[0]) / the immediate is the
//     SIGN-EXTENDED field (0x1f -> -1, 0x10 -> -16) -> a wrong scalar source or a zero-extended
//     immediate (+31 instead of -1 would be a silent wrong value);
//   * the stub is rv32_vialu, where these encodings went before A6;
//   * with the partial arm on, each vchunkpartialalu carries the same source kind and the same
//     GPR offset / immediate, so a partial-vl frame cannot take a different source than a full one;
//   * masked forms, vsub.vx, vadd.vv-with-OPIVX-off, e64 and the switch-off case take the helper;
//   * the host bytes: exactly one EVEX vpbroadcastd of the frame's class with a DWORD [r13+..]
//     source (vx) or an eax source preceded by `mov eax, imm` (vi), and vpaddd of the class.
void TestVaddScalarFrame()
{
	printf("[12] A6 vadd.vx / vadd.vi: same shape and lane op as .vv, ONE broadcast source, partial arm, host bytes\n");
	struct Case { u32 word; bool imm; u32 field; i32 value; char const *name; };
	Case const cases[] = {
	    {Vaddvx(9, 8, 7), false, 7, 0, "vadd.vx v9,v8,x7"},
	    {Vaddvx(9, 9, 0), false, 0, 0, "vadd.vx v9,v9,x0 (vd==vs2, x0)"},
	    {Vaddvi(9, 8, 0x1f), true, 0x1f, -1, "vadd.vi v9,v8,-1"},
	    {Vaddvi(9, 8, 0x10), true, 0x10, -16, "vadd.vi v9,v8,-16"},
	    {Vaddvi(9, 9, 0x0f), true, 0x0f, 15, "vadd.vi v9,v9,15 (vd==vs2)"},
	    {Vaddvi(9, 8, 0), true, 0, 0, "vadd.vi v9,v8,0"},
	};
	unsigned const slot = dbt::rv32::VLEN_MAX_BYTES;
	unsigned const vbase = (unsigned)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
	for (auto const &c : kWidths) {
		unsigned const k = c.chunks;
		for (bool partial : {false, true}) {
			for (auto const &cs : cases) {
				ApplyConfig(c.vlen, /*narrow=*/true, /*run=*/false, partial);
				Built b;
				Build(b, {cs.word});
				auto const frames = FindFrames(b.region);
				CHECK_EQ(frames.size(), 1u);
				if (frames.empty())
					continue;
				auto const &f = frames[0];
				CHECK_EQ(CountOp(f, Op::_vchunkbroadcast), 1u);
				CHECK_EQ(CountOp(f, Op::_vstatechunkload), k);
				CHECK_EQ(CountOp(f, Op::_vchunkadd), k);
				CHECK_EQ(CountOp(f, Op::_vstatechunkstore), k);
				CHECK_EQ(CountOp(f, Op::_rvvtypedchunkpartial), partial ? 1u : 0u);
				CHECK_EQ(CountOp(f, Op::_vchunkpartialalu), partial ? k : 0u);
				CHECK_EQ((unsigned)f.begin->n_typed, 3u * k + 1u + (partial ? k : 0u));
				CHECK((unsigned)f.begin->stub == (unsigned)RuntimeStubId::id_rv32_vialu);
				u32 const vd = (cs.word >> 7) & 31, vs2 = (cs.word >> 20) & 31;
				unsigned loads = 0, stores = 0, palu = 0;
				for (auto *i : f.body) {
					if (i->GetOpcode() == Op::_vchunkbroadcast) {
						auto *bc = static_cast<InstVChunkBroadcast *>(i);
						CHECK_EQ((unsigned)qir::VTypeToSize(bc->o(0).GetType()), c.bytes);
						CHECK_EQ((unsigned)bc->sew_bytes, 4u);
						CHECK_EQ((unsigned)bc->is_imm, (unsigned)cs.imm);
						if (cs.imm)
							CHECK_EQ((int)(i32)bc->imm, cs.value);
						else
							CHECK_EQ((unsigned)bc->offs, (unsigned)(offsetof(CPUState, gpr) + 4u * cs.field));
					}
					if (i->GetOpcode() == Op::_vstatechunkload) {
						auto *ld = static_cast<InstVStateChunkLoad *>(i);
						CHECK_EQ((unsigned)ld->offs, vbase + vs2 * slot + loads * c.bytes);
						++loads;
					}
					if (i->GetOpcode() == Op::_vstatechunkstore) {
						auto *st = static_cast<InstVStateChunkStore *>(i);
						CHECK_EQ((unsigned)st->offs, vbase + vd * slot + stores * c.bytes);
						++stores;
					}
					if (i->GetOpcode() == Op::_vchunkpartialalu) {
						auto *p = static_cast<InstVChunkPartialAlu *>(i);
						CHECK_EQ((unsigned)p->op, (unsigned)InstVChunkPartialAlu::Kind::Add);
						CHECK_EQ((unsigned)p->chunk, palu);
						CHECK_EQ((unsigned)p->rd_offs, vbase + vd * slot + palu * c.bytes);
						CHECK_EQ((unsigned)p->rs2_offs, vbase + vs2 * slot + palu * c.bytes);
						if (cs.imm) {
							CHECK_EQ((unsigned)p->src1_kind, (unsigned)InstVChunkPartialAlu::Src1::Imm);
							CHECK_EQ((int)(i32)p->imm, cs.value);
							CHECK_EQ((unsigned)p->rs1_offs, 0u);
						} else {
							CHECK_EQ((unsigned)p->src1_kind, (unsigned)InstVChunkPartialAlu::Src1::GprWord);
							CHECK_EQ((unsigned)p->rs1_offs, (unsigned)(offsetof(CPUState, gpr) + 4u * cs.field));
						}
						++palu;
					}
				}
				CHECK_EQ(loads, k);
				CHECK_EQ(stores, k);
				if (partial)
					CHECK((unsigned)f.begin->guard_kind ==
					      (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeIntegerTwoArm);
			}
		}
		// Refusals: every one of these must stay a helper, with the switch on.
		ApplyConfig(c.vlen, /*narrow=*/true);
		ExpectNoTypedChunk("masked vadd.vx", {Enc(F6_VADD, 0, 8, 7, F3_OPIVX, 9)});
		ExpectNoTypedChunk("masked vadd.vi", {Enc(F6_VADD, 0, 8, 1, F3_OPIVI, 9)});
		ExpectNoTypedChunk("vsub.vx", {Enc(F6_VSUB, 1, 8, 7, F3_OPIVX, 9)});
		ExpectNoTypedChunk("vand.vi", {Enc(F6_VAND, 1, 8, 1, F3_OPIVI, 9)});
		ExpectNoTypedChunk("vadd.vx e64", {Vaddvx(9, 8, 7)}, 0x0d857557u /* vsetvli e64,m1 */);
		ExpectNoTypedChunk("vadd.vx m2", {Vaddvx(10, 8, 7)}, 0x0d157557u /* vsetvli e32,m2 */);
		ApplyConfig(c.vlen, /*narrow=*/true, false, false, /*vadd_scalar=*/false);
		ExpectNoTypedChunk("switch off vadd.vx", {Vaddvx(9, 8, 7)});
		ExpectNoTypedChunk("switch off vadd.vi", {Vaddvi(9, 8, 3)});
		// Host bytes.
		char const *const cls = c.bytes == 16 ? "xmm" : c.bytes == 32 ? "ymm" : "zmm";
		ApplyConfig(c.vlen, /*narrow=*/true);
		{
			auto const l = EmitAndDisassemble({Vaddvx(9, 8, 7)}, W_VSETVLI_E32M1, /*raw_bytes=*/true);
			if (!l.empty()) {
				auto const [bc_evex, bc_vex] = CountEncodings(l, "vpbroadcastd", cls);
				CHECK_EQ(bc_evex, 1u);
				CHECK_EQ(bc_vex, 0u);
				unsigned dword_src = 0, add_cls = 0;
				for (auto const &line : l) {
					if (line.find("vpbroadcastd") != std::string::npos && line.find("DWORD PTR [r13+") != std::string::npos)
						++dword_src;
					if (line.find("vpaddd") != std::string::npos && line.find(cls) != std::string::npos)
						++add_cls;
				}
				CHECK_EQ(dword_src, 1u);
				CHECK_EQ(add_cls, k);
			}
		}
		{
			auto const l = EmitAndDisassemble({Vaddvi(9, 8, 0x1f)}, W_VSETVLI_E32M1, /*raw_bytes=*/true);
			if (!l.empty()) {
				auto const [bc_evex, bc_vex] = CountEncodings(l, "vpbroadcastd", cls);
				CHECK_EQ(bc_evex, 1u);
				CHECK_EQ(bc_vex, 0u);
				unsigned eax_src = 0, mov_m1 = 0;
				for (auto const &line : l) {
					if (line.find("vpbroadcastd") != std::string::npos && line.find(",eax") != std::string::npos)
						++eax_src;
					if (line.find("mov    eax,0xffffffff") != std::string::npos)
						++mov_m1;
				}
				CHECK_EQ(eax_src, 1u);
				CHECK_EQ(mov_m1, 1u);
			}
		}
		printf("  VLEN %4u: 6 frames x {full, partial}: 1 broadcast + %u loads + %u adds + %u stores; refusals helper; host: 1 EVEX vpbroadcastd %s (DWORD [r13+] / eax after mov eax,-1)\n",
		       c.vlen, k, k, k, cls);
	}
}


// [13] A7: THE MOVE FAMILY vmv.v.x / vmv.v.i / vmv.v.v THROUGH ONE RECIPE, WITH THE PARTIAL ARM
//
// What each assertion would catch: a .v that broadcast instead of copying (or the reverse); a .i
// whose immediate was zero-extended; a self-copy whose stores preceded its loads; a partial arm
// whose Kind::Mov node read a vs2 window or carried a different source than the fast body; a
// masked merge (vm=0) or a reserved vs2 != 0 encoding swallowed by the route; and the old .x frame
// changing shape (section [10] still pins it with the partial arm off).
void TestVmvFamily()
{
	printf("[13] A7 vmv.v.{x,i,v}: one source recipe (broadcast GPR / broadcast simm5 / k copies), k stores, partial arm Kind::Mov\n");
	struct Case { u32 word; int kind; u32 field; i32 value; };
	Case const cases[] = {
	    {Vmvvx(9, 7), 1, 7, 0}, {Vmvvx(9, 0), 1, 0, 0},
	    {Vmvvi(9, 0x1f), 2, 0x1f, -1}, {Vmvvi(9, 0x10), 2, 0x10, -16}, {Vmvvi(9, 0), 2, 0, 0},
	    {Vmvvv(9, 8), 0, 8, 0}, {Vmvvv(9, 9), 0, 9, 0},
	};
	unsigned const slot = dbt::rv32::VLEN_MAX_BYTES;
	unsigned const vbase = (unsigned)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
	for (auto const &c : kWidths) {
		unsigned const k = c.chunks;
		for (bool partial : {false, true}) {
			for (auto const &cs : cases) {
				ApplyConfig(c.vlen, /*narrow=*/true, /*run=*/false, partial);
				Built b;
				Build(b, {cs.word});
				auto const frames = FindFrames(b.region);
				CHECK_EQ(frames.size(), 1u);
				if (frames.empty())
					continue;
				auto const &f = frames[0];
				bool const copy = cs.kind == 0;
				CHECK_EQ(CountOp(f, Op::_vchunkbroadcast), copy ? 0u : 1u);
				CHECK_EQ(CountOp(f, Op::_vstatechunkload), copy ? k : 0u);
				CHECK_EQ(CountOp(f, Op::_vchunkadd), 0u);
				CHECK_EQ(CountOp(f, Op::_vstatechunkstore), k);
				CHECK_EQ(CountOp(f, Op::_vchunkpartialalu), partial ? k : 0u);
				CHECK_EQ((unsigned)f.begin->n_typed, (copy ? 2u * k : k + 1u) + (partial ? k : 0u));
				CHECK((unsigned)f.begin->stub == (unsigned)RuntimeStubId::id_rv32_vmerge);
				unsigned loads = 0, stores = 0, palu = 0; bool store_seen = false, load_after_store = false;
				for (auto *i : f.body) {
					if (i->GetOpcode() == Op::_vchunkbroadcast) {
						auto *bc = static_cast<InstVChunkBroadcast *>(i);
						CHECK_EQ((unsigned)qir::VTypeToSize(bc->o(0).GetType()), c.bytes);
						CHECK_EQ((unsigned)bc->is_imm, (unsigned)(cs.kind == 2));
						if (cs.kind == 2) CHECK_EQ((int)(i32)bc->imm, cs.value);
						else CHECK_EQ((unsigned)bc->offs, (unsigned)(offsetof(CPUState, gpr) + 4u * cs.field));
					}
					if (i->GetOpcode() == Op::_vstatechunkload) {
						auto *ld = static_cast<InstVStateChunkLoad *>(i);
						CHECK_EQ((unsigned)ld->offs, vbase + cs.field * slot + loads * c.bytes);
						if (store_seen) load_after_store = true;
						++loads;
					}
					if (i->GetOpcode() == Op::_vstatechunkstore) {
						auto *st = static_cast<InstVStateChunkStore *>(i);
						CHECK_EQ((unsigned)st->offs, vbase + 9u * slot + stores * c.bytes);
						store_seen = true; ++stores;
					}
					if (i->GetOpcode() == Op::_vchunkpartialalu) {
						auto *p = static_cast<InstVChunkPartialAlu *>(i);
						CHECK_EQ((unsigned)p->op, (unsigned)InstVChunkPartialAlu::Kind::Mov);
						CHECK_EQ((unsigned)p->chunk, palu);
						CHECK_EQ((unsigned)p->rd_offs, vbase + 9u * slot + palu * c.bytes);
						if (cs.kind == 2) { CHECK_EQ((unsigned)p->src1_kind, (unsigned)InstVChunkPartialAlu::Src1::Imm); CHECK_EQ((int)(i32)p->imm, cs.value); }
						else if (cs.kind == 1) { CHECK_EQ((unsigned)p->src1_kind, (unsigned)InstVChunkPartialAlu::Src1::GprWord); CHECK_EQ((unsigned)p->rs1_offs, (unsigned)(offsetof(CPUState, gpr) + 4u * cs.field)); }
						else { CHECK_EQ((unsigned)p->src1_kind, (unsigned)InstVChunkPartialAlu::Src1::Vector); CHECK_EQ((unsigned)p->rs1_offs, vbase + cs.field * slot + palu * c.bytes); }
						++palu;
					}
				}
				CHECK(!load_after_store); // self-copy safety: every vs1 chunk is read before any vd chunk is written
				CHECK_EQ(stores, k);
				if (partial)
					CHECK((unsigned)f.begin->guard_kind == (unsigned)InstRVVTypedChunkBegin::GuardKind::VTypeIntegerTwoArm);
			}
		}
		ApplyConfig(c.vlen, /*narrow=*/true);
		ExpectNoTypedChunk("vmerge.vxm (vm=0)", {Enc(F6_VMERGE, 0, 8, 7, F3_OPIVX, 9)});
		ExpectNoTypedChunk("vmerge.vim (vm=0)", {Enc(F6_VMERGE, 0, 8, 1, F3_OPIVI, 9)});
		ExpectNoTypedChunk("vmerge.vvm (vm=0)", {Enc(F6_VMERGE, 0, 8, 7, F3_OPIVV, 9)});
		ExpectNoTypedChunk("vmv.v.i vs2!=0 (reserved)", {Enc(F6_VMERGE, 1, 3, 1, F3_OPIVI, 9)});
		ExpectNoTypedChunk("vmv.v.v vs2!=0 (reserved)", {Enc(F6_VMERGE, 1, 3, 7, F3_OPIVV, 9)});
		ExpectNoTypedChunk("vmv.v.v e64", {Vmvvv(9, 8)}, 0x0d857557u);
		ExpectNoTypedChunk("vmv.v.i m2", {Vmvvi(10, 1)}, 0x0d157557u);
		char const *const cls = c.bytes == 16 ? "xmm" : c.bytes == 32 ? "ymm" : "zmm";
		{
			auto const l = EmitAndDisassemble({Vmvvi(9, 0x1f)}, W_VSETVLI_E32M1, /*raw_bytes=*/true);
			if (!l.empty()) {
				auto const [bc_evex, bc_vex] = CountEncodings(l, "vpbroadcastd", cls);
				CHECK_EQ(bc_evex, 1u); CHECK_EQ(bc_vex, 0u);
				unsigned eax_src = 0, mov_m1 = 0;
				for (auto const &line : l) { if (line.find("vpbroadcastd") != std::string::npos && line.find(",eax") != std::string::npos) ++eax_src; if (line.find("mov    eax,0xffffffff") != std::string::npos) ++mov_m1; }
				CHECK_EQ(eax_src, 1u); CHECK_EQ(mov_m1, 1u);
			}
		}
		{
			auto const l = EmitAndDisassemble({Vmvvv(9, 8)}, W_VSETVLI_E32M1, /*raw_bytes=*/true);
			if (!l.empty()) {
				auto const [mv_evex, mv_vex] = CountEncodings(l, "vmovdqu64", cls);
				CHECK_EQ(mv_evex, 2u * k); CHECK_EQ(mv_vex, 0u);
				auto const [bc_e, bc_v] = CountEncodings(l, "vpbroadcastd", cls);
				CHECK_EQ(bc_e + bc_v, 0u);
			}
		}
		ApplyConfig(c.vlen, /*narrow=*/true, false, true);
		{
			auto const l = EmitAndDisassemble({Vmvvv(9, 9)}, W_VSETVLI_E32M1, /*raw_bytes=*/true);
			unsigned mstore = 0;
			for (auto const &line : l) if (line.find("vmovdqu32") != std::string::npos && line.find("{k") != std::string::npos && line.find(std::string(cls) + "1") != std::string::npos) ++mstore;
			if (!l.empty()) CHECK_EQ(mstore, k); // the arm's masked store is of scratch 1 (the source), no scratch-0 arithmetic
		}
		printf("  VLEN %4u: 7 frames x {full, partial}: x/i -> 1 broadcast + %u stores, v -> %u loads + %u stores; masked merges and reserved vs2 refused; host: vi eax broadcast, vv %u vmovdqu64, partial masked store of %s1\n", c.vlen, k, k, k, 2u * k, cls);
	}
}


// [14] A9: THE FP ROUTES AT EVERY WIDTH -- chunk width from the shared shape, lanes from the width
//
// What each assertion would catch: an FP frame that still addressed 64-byte windows or typed its
// values V512 at VLEN 128/256 (it would read 64 bytes out of a 16-byte guest register window);
// a broadcast typed wider than the lane op; a mask prologue whose lane count did not follow the
// chunk width (the disassembly counts `vaddps xmm{k1}` and the NaN fill on xmm0, never zmm);
// and any regression of the 512/1024 shapes, which the older FP tests pin independently.
void TestFpWidth()
{
	printf("[14] A9 vfadd.vv / vfmadd.vf / e64,m2: FP frames at 128/256/512/1024 use the shared chunk width\n");
	constexpr u32 F3_OPFVV = 0b001, F3_OPFVF = 0b101, F6_VFADD = 0b000000, F6_VFMADD = 0b101000;
	constexpr u32 W_VSETVLI_E64M2 = 0x0d957557u; // vsetvli a0,a0,e64,m2,ta,ma
	unsigned const slot = dbt::rv32::VLEN_MAX_BYTES;
	unsigned const vbase = (unsigned)(offsetof(CPUState, vec) + offsetof(dbt::rv32::VectorState, vreg));
	for (auto const &c : kWidths) {
		unsigned const k = c.chunks;
		ApplyConfig(c.vlen, /*narrow=*/true);
		char const *const cls = c.bytes == 16 ? "xmm" : c.bytes == 32 ? "ymm" : "zmm";
		{
			Built b; Build(b, {Enc(F6_VFADD, 1, 8, 10, F3_OPFVV, 9)});
			auto const frames = FindFrames(b.region);
			CHECK_EQ(frames.size(), 1u);
			if (!frames.empty()) {
				auto const &f = frames[0];
				CHECK_EQ(CountOp(f, Op::_vstatechunkload), 2u * k);
				CHECK_EQ(CountOp(f, Op::_vchunkfalu), k);
				CHECK_EQ(CountOp(f, Op::_vstatechunkstore), k);
				CHECK((unsigned)f.begin->stub == (unsigned)RuntimeStubId::id_rv32_vfalu);
				unsigned st = 0;
				for (auto *i : f.body) {
					if (i->GetOpcode() == Op::_vchunkfalu) {
						auto *op = static_cast<InstVChunkFALU *>(i);
						CHECK_EQ((unsigned)qir::VTypeToSize(op->o(0).GetType()), c.bytes);
						CHECK_EQ((unsigned)qir::VTypeToSize(op->i(0).GetType()), c.bytes);
					}
					if (i->GetOpcode() == Op::_vstatechunkstore) {
						auto *s = static_cast<InstVStateChunkStore *>(i);
						CHECK_EQ((unsigned)qir::VTypeToSize(s->i(0).GetType()), c.bytes);
						CHECK_EQ((unsigned)s->offs, vbase + 9u * slot + st * c.bytes); ++st;
					}
				}
			}
		}
		{
			Built b; Build(b, {Enc(F6_VFMADD, 1, 8, 10, F3_OPFVF, 9)});
			auto const frames = FindFrames(b.region);
			CHECK_EQ(frames.size(), 1u);
			if (!frames.empty()) {
				auto const &f = frames[0];
				CHECK_EQ(CountOp(f, Op::_vstatechunkload), 2u * k);
				CHECK_EQ(CountOp(f, Op::_vchunkfbroadcast), 1u);
				CHECK_EQ(CountOp(f, Op::_vchunkfma), k);
				CHECK_EQ(CountOp(f, Op::_vstatechunkstore), k);
				for (auto *i : f.body)
					if (i->GetOpcode() == Op::_vchunkfbroadcast)
						CHECK_EQ((unsigned)qir::VTypeToSize(static_cast<InstVChunkFBroadcast *>(i)->o(0).GetType()), c.bytes);
			}
		}
		{
			Built b; Build(b, {Enc(F6_VFADD, 1, 10, 12, F3_OPFVV, 8)}, W_VSETVLI_E64M2);
			auto const frames = FindFrames(b.region);
			CHECK_EQ(frames.size(), 1u);
			if (!frames.empty()) {
				auto const &f = frames[0];
				CHECK_EQ(CountOp(f, Op::_vchunkfalu), 2u * k);
				CHECK_EQ(CountOp(f, Op::_vstatechunkstore), 2u * k);
				unsigned st = 0;
				for (auto *i : f.body) {
					if (i->GetOpcode() != Op::_vstatechunkstore) continue;
					auto *s = static_cast<InstVStateChunkStore *>(i);
					CHECK_EQ((unsigned)qir::VTypeToSize(s->i(0).GetType()), c.bytes);
					CHECK_EQ((unsigned)s->offs, vbase + (8u + st / k) * slot + (st % k) * c.bytes); ++st;
				}
				CHECK_EQ(st, 2u * k);
			}
		}
		{
			auto const l = EmitAndDisassemble({Enc(F6_VFADD, 1, 8, 10, F3_OPFVV, 9)}, W_VSETVLI_E32M1, /*raw_bytes=*/true);
			if (!l.empty()) {
				unsigned add_k = 0, cmp = 0, fill = 0, other = 0, tern = 0;
				for (auto const &line : l) {
					if (line.find("vaddps") != std::string::npos && line.find(cls) != std::string::npos && line.find("{k1}") != std::string::npos) ++add_k;
					if (line.find("vcmp") != std::string::npos && line.find("ps") != std::string::npos && line.find(cls) != std::string::npos) ++cmp; // objdump prints the predicate form (vcmpunordps)
					if (line.find("vmovaps") != std::string::npos && line.find(std::string(cls) + "0") != std::string::npos && line.find("{k2}") != std::string::npos) ++fill;
					if (line.find("vpternlogd") != std::string::npos && line.find(cls) != std::string::npos) ++tern;
					for (char const *o : {"xmm", "ymm", "zmm"})
						if (std::string(o) != cls && (line.find("vaddps") != std::string::npos || line.find("vmovaps") != std::string::npos) && line.find(o) != std::string::npos) ++other;
				}
				CHECK_EQ(add_k, k); CHECK_EQ(cmp, k); CHECK_EQ(fill, k); CHECK_EQ(tern, k); CHECK_EQ(other, 0u);
			}
		}
		printf("  VLEN %4u: vfadd.vv %u %s chunk(s), vfmadd.vf 1 %s broadcast, e64m2 %u chunks over v10/v11; host vaddps %s{k1} x%u, NaN fill on %s0\n",
		       c.vlen, k, cls, cls, 2u * k, cls, k, cls);
	}
}

} // namespace

int main()
{
	printf("rvv_narrow_width_route_test\n");
	TestGeometry();
	TestPureGeometry();
	TestWideNonRegression();
	TestSwitchOffNarrowRefuses();
	TestStoreWindows();
	TestLoadWindows();
	TestFailClosed();
	TestDeliberateNonWidening();
	TestRun();
	TestEmittedWidth();
	TestVmvFrame();
	TestPartialArm();
	TestVaddScalarFrame();
	TestVmvFamily();
	TestFpWidth();
	TestMutationSensitivity();
	printf("%s (%d failure(s))\n", g_failures ? "FAILED" : "PASSED", g_failures);
	return g_failures ? 1 : 0;
}
