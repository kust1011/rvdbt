// Z3: the route and emitted-code audit for --rvv-qcg-typed-chunk-vlse-gather, the AVX-512 gather
// body for `vlse32.v`.
//
// WHAT THIS FILE OWNS. The admitted/refused matrix, the emitted shape of the fast path, the ORDER
// of the two runtime exits relative to the chunk's store, and the switch's inertness. It owns NO
// value: the architectural result is the value differential's obligation
// (rvv_vlse_gather_value_test.cpp), which EXECUTES the emitted bytes against rvv_ref::load_strided.
//
// HOST NOTE. The development host is an Ivy Bridge i7-3770 with no AVX-512, so every section here
// runs with the route's `-force-emit` audit switch on: it bypasses ONLY the host feature probe, so
// the bytes assembled below are the bytes a capable host would assemble, and nothing in this binary
// ever executes them (TestCompilerRuntime hands back a static writable buffer, never a PROT_EXEC page).
//
// THE DISASSEMBLY IS SPLIT AT THE EMBEDDED CONSTANT, and that is not cosmetic. The fast path embeds
// the 64-byte lane-index vector in the instruction stream behind a jump, exactly as Emit_vchunkindex
// does. objdump's linear sweep decodes those 64 data bytes as instructions and resynchronises in the
// middle of a real one -- in the first draft of this file it swallowed a REX prefix and printed
// `add edx,0x80000000` for `add r10d,0x80000000`. So the code is cut at the constant (whose exact
// bytes are searched for, and whose occurrence count is itself an assertion) and the two halves are
// disassembled separately. A test that skipped this would be reading invented mnemonics.
//
// EVERY ASSERTION'S FAILURE PATH, written before the assertion (memory:
// test-assertions-must-be-falsifiable). These are the mutation suite's targets:
//
//   M1 admission widened (a clause dropped from the emitter's predicate)  -> [2] a refused row gains
//                                                                            a vpgatherdd, and its
//                                                                            bytes stop matching the
//                                                                            switch-off bytes.
//   M2 admission narrowed                                                -> [1] an admitted row has
//                                                                            no vpgatherdd.
//   M3 wrong chunk count / wrong destination window                      -> [1] GATHERS != chunks,
//                                                                            or a missing store
//                                                                            displacement.
//   M4 P2 guard removed, or moved after the chunk's store                -> [3] the order check.
//   M5 P1 bias dropped or applied to the wrong side                      -> [4] the bias check.
//   M6 vstart precheck dropped                                           -> [5] the precheck check.
//   M7 the element-loop fallback dropped instead of kept                 -> [6] the loop marker.
//   M8 the switch made non-inert                                         -> [7] off-vs-on bytes, and
//                                                                            the cross-build hash.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <cstring>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{
int g_checks = 0, g_failures = 0;
#define CHECK(cond)                                                                                  \
	do {                                                                                         \
		++g_checks;                                                                          \
		if (!(cond)) {                                                                       \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)
#define CHECK_EQ(a, b)                                                                               \
	do {                                                                                         \
		++g_checks;                                                                          \
		auto _a = (a);                                                                       \
		auto _b = (b);                                                                       \
		if (!(_a == _b)) {                                                                   \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,         \
				__LINE__, #a, #b, (long long)_a, (long long)_b);                     \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

// ---------------------------------------------------------------------------------------------
// Encodings. One constexpr encoder, pinned with static_asserts against words the accepted vle32
// route test independently carries, so a typo cannot silently move a test case.
// ---------------------------------------------------------------------------------------------
constexpr u32 OP_LOAD_FP = 0b0000111u, OP_STORE_FP = 0b0100111u;
constexpr u32 W8 = 0b000u, W16 = 0b101u, W32 = 0b110u, W64 = 0b111u;
constexpr u32 MOP_UNIT = 0u, MOP_IDX_U = 1u, MOP_STRIDED = 2u;

constexpr u32 VMem(u32 opcode, u32 vd, u32 width, u32 rs1, u32 rs2, u32 vm, u32 mop, u32 nf)
{
	return opcode | (vd << 7) | (width << 12) | (rs1 << 15) | (rs2 << 20) | (vm << 25) |
	       (mop << 26) | ((nf - 1) << 29);
}
constexpr u32 VD = 8, RS1 = 16 /* a6 */, RS2 = 5 /* t0, the stride register */;

constexpr u32 INSN_VLSE32 = VMem(OP_LOAD_FP, VD, W32, RS1, RS2, 1, MOP_STRIDED, 1);
constexpr u32 INSN_VLSE32_MASKED = VMem(OP_LOAD_FP, VD, W32, RS1, RS2, 0, MOP_STRIDED, 1);
constexpr u32 INSN_VLSE32_X0BASE = VMem(OP_LOAD_FP, VD, W32, 0, RS2, 1, MOP_STRIDED, 1);
constexpr u32 INSN_VLSE32_X0STRIDE = VMem(OP_LOAD_FP, VD, W32, RS1, 0, 1, MOP_STRIDED, 1);
constexpr u32 INSN_VLSE8 = VMem(OP_LOAD_FP, VD, W8, RS1, RS2, 1, MOP_STRIDED, 1);
constexpr u32 INSN_VLSE16 = VMem(OP_LOAD_FP, VD, W16, RS1, RS2, 1, MOP_STRIDED, 1);
constexpr u32 INSN_VLSE64 = VMem(OP_LOAD_FP, VD, W64, RS1, RS2, 1, MOP_STRIDED, 1);
constexpr u32 INSN_VSSE32 = VMem(OP_STORE_FP, VD, W32, RS1, RS2, 1, MOP_STRIDED, 1);
constexpr u32 INSN_VLSSEG2E32 = VMem(OP_LOAD_FP, VD, W32, RS1, RS2, 1, MOP_STRIDED, 2);
constexpr u32 INSN_VLE32 = VMem(OP_LOAD_FP, VD, W32, RS1, 0, 1, MOP_UNIT, 1);
constexpr u32 INSN_VLUXEI32 = VMem(OP_LOAD_FP, VD, W32, RS1, RS2, 1, MOP_IDX_U, 1);
// Independently pinned: the accepted vle32 route test carries these two words verbatim.
static_assert(INSN_VLSE32 == 0x0a586407u, "vlse32.v v8,(a6),t0");
static_assert(INSN_VLE32 == 0x02086407u, "vle32.v v8,(a6)");

// vsetvli a0,a0,e<SEW>,m<LMUL>,ta,ma. zimm = vtype[7:0] = vma|vta|vsew[2:0]|vlmul[2:0].
constexpr u32 VSetVli(u32 vtype) { return 0x00007557u | (vtype << 20) | (10u << 15) | (10u << 7); }
constexpr u32 VT_E32M1 = 0xd0u, VT_E32M2 = 0xd1u, VT_E32M8 = 0xd3u, VT_E32MF2 = 0xd7u,
	      VT_E64M1 = 0xd8u, VT_E16M1 = 0xc8u;
static_assert(VSetVli(VT_E32M1) == 0x0d057557u, "vsetvli a0,a0,e32,m1,ta,ma");
static_assert(VSetVli(VT_E32M2) == 0x0d157557u, "vsetvli a0,a0,e32,m2,ta,ma");
static_assert(VSetVli(VT_E64M1) == 0x0d857557u, "vsetvli a0,a0,e64,m1,ta,ma");
static_assert(VSetVli(VT_E16M1) == 0x0c857557u, "vsetvli a0,a0,e16,m1,ta,ma");

// ---------------------------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------------------------
// ONE FIXED CODE BUFFER FOR EVERY BUILD IN THIS PROCESS, and it is load-bearing rather than tidy.
// A region's exit code contains host-absolute addresses and a call whose displacement is relative to
// the buffer, so two builds placed at two different heap addresses differ in bytes that have nothing
// to do with this route -- which is exactly what defeated the first draft's switch-on/switch-off
// memcmp. A single static buffer makes the two emissions comparable byte for byte.
alignas(4096) u8 g_code_buf[1u << 21];

struct TestCompilerRuntime final : CompilerRuntime {
	void *AllocateCode(size_t sz, uint) override
	{
		if (sz > sizeof(g_code_buf))
			Panic("z3 route test: emitted region larger than the fixed code buffer");
		memset(g_code_buf, 0, sz);
		return g_code_buf;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};

struct Cfg {
	u32 vlen = 512;
	u32 vtype = VT_E32M1;
	u32 word = INSN_VLSE32;
	bool gather = true;	// --rvv-qcg-typed-chunk-vlse-gather
	bool force_emit = true; // ...-force-emit (this host has no AVX-512)
};

void ApplyCfg(Cfg const &c)
{
	config::vlen_bits = c.vlen;
	config::aot_use_llvm = false;
	config::rvv_verify = false;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_qcg_typed_chunk = true; // the frame this route's node lives in
#ifndef Z3_BASELINE
	config::rvv_qcg_typed_chunk_vlse_gather = c.gather;
	config::rvv_qcg_typed_chunk_vlse_gather_force_emit = c.force_emit;
#else
	(void)c.gather;
	(void)c.force_emit;
#endif
	// Every sibling switch off, so a ZMM instruction in the disassembly can only be ours.
	config::rvv_qcg_typed_chunk_force_emit = false;
	config::rvv_qcg_typed_chunk_vle = false;
	config::rvv_qcg_typed_chunk_vse = false;
	config::rvv_qcg_typed_chunk_mem_e64 = false;
	config::rvv_qcg_typed_chunk_falu = false;
	config::rvv_qcg_typed_chunk_fma = false;
	config::rvv_qcg_typed_chunk_mul = false;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_typed_chunk_shift = false;
	config::rvv_qcg_typed_chunk_vmv = false;
	config::rvv_qcg_typed_chunk_vadd_scalar = false;
	config::rvv_qcg_narrow_chunk_width = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_qcg_active_vl_bound = false;
	config::rvv_qcg_whole_reg = false;
	config::rvv_qcg_vx_mulacc = false;
	config::rvv_qcg_diag_chunk = false;
	config::rvv_vector_ssa = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_hit_counter = false;
	config::rvv_qcg_fp_shared_mask = false;
}

struct Built {
	MemArena arena{1u << 22};
	u32 words[2]{};
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
};

void Build(Built &b, Cfg const &c)
{
	ApplyCfg(c);
	b.words[0] = VSetVli(c.vtype);
	b.words[1] = c.word;
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)b.words, CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	qir::CodeSegment seg(0u, 0x1000u);
	auto sp = qcg::GenerateCode(&b.cr, &seg, b.region, 0);
	b.code.assign(sp.begin(), sp.end());
}

InstVMemory *FindMemNode(Region *r)
{
	InstVMemory *found = nullptr;
	for (auto &bb : r->GetBlocks())
		for (auto &ins : bb.ilist)
			if (ins.GetOpcode() == Op::_vmemorynative)
				found = static_cast<InstVMemory *>(&ins);
	return found;
}

// The 64 bytes the fast path embeds: 16 little-endian dwords 0..15.
std::vector<u8> IotaBytes()
{
	std::vector<u8> v(64, 0);
	for (u32 e = 0; e < 16; ++e)
		memcpy(v.data() + e * 4, &e, 4);
	return v;
}

unsigned CountIota(std::vector<u8> const &code, size_t *first = nullptr)
{
	auto pat = IotaBytes();
	unsigned n = 0;
	if (code.size() < pat.size())
		return 0;
	for (size_t i = 0; i + pat.size() <= code.size(); ++i)
		if (!memcmp(code.data() + i, pat.data(), pat.size())) {
			if (!n && first)
				*first = i;
			++n;
		}
	return n;
}

std::vector<std::string> DisassembleRange(u8 const *p, size_t n)
{
	if (!n)
		return {};
	char path[] = "/tmp/rvdbt_z3_emit_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0)
		return {};
	size_t w = 0;
	while (w < n) {
		ssize_t k = write(fd, p + w, n - w);
		if (k <= 0) {
			close(fd);
			unlink(path);
			return {};
		}
		w += (size_t)k;
	}
	close(fd);
	std::string cmd = std::string("objdump -D -b binary -m i386:x86-64 -M intel "
				      "--no-show-raw-insn ") +
			  path + " 2>&1";
	FILE *f = popen(cmd.c_str(), "r");
	if (!f) {
		unlink(path);
		return {};
	}
	std::vector<std::string> ls;
	char buf[1024];
	while (fgets(buf, sizeof buf, f)) {
		std::string l(buf);
		if (!l.empty() && l.back() == '\n')
			l.pop_back();
		auto tab = l.find('\t'); // instruction lines are "   <hex>:\t<text>"
		if (tab != std::string::npos && l.find(':') < tab)
			ls.push_back(l.substr(tab + 1));
	}
	int rc = pclose(f);
	unlink(path);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
		return {};
	return ls;
}

// Disassembly with the embedded constant cut out; see the file header.
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	size_t at = 0;
	unsigned n = CountIota(code, &at);
	if (!n)
		return DisassembleRange(code.data(), code.size());
	auto head = DisassembleRange(code.data(), at);
	auto tail = DisassembleRange(code.data() + at + 64, code.size() - at - 64);
	head.insert(head.end(), tail.begin(), tail.end());
	return head;
}

unsigned Count(std::vector<std::string> const &ls, char const *needle)
{
	unsigned n = 0;
	for (auto const &l : ls)
		n += l.find(needle) != std::string::npos;
	return n;
}

// Index of the first/last line containing `needle`, or -1.
int FirstOf(std::vector<std::string> const &ls, char const *needle)
{
	for (size_t i = 0; i < ls.size(); ++i)
		if (ls[i].find(needle) != std::string::npos)
			return (int)i;
	return -1;
}

std::string Hex(u32 v)
{
	char b[32];
	snprintf(b, sizeof b, "0x%x", v);
	return b;
}

constexpr u32 ST_VREG = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg));
constexpr u32 ST_VSTART = (u32)(offsetof(CPUState, vec) + offsetof(rv32::VectorState, vstart));

u32 Vlmax(u32 vlen, u32 vtype) { return rv32::compute_vlmax(rv32::VType{vtype}, vlen); }

u64 Fnv1a(std::string const &v)
{
	u64 h = 1469598103934665603ull;
	for (unsigned char b : v) {
		h ^= b;
		h *= 1099511628211ull;
	}
	return h;
}

// ACROSS PROCESSES, two things in the emitted bytes are not properties of the emitter: the
// host-absolute pointers a region's exit embeds, and the displacement of the call to a runtime stub.
// Both print as hex literals of NINE OR MORE digits (12 and 16 here); every constant this route or
// its frame owns -- state offsets, guest instruction words, VLMAX, the 0x80000000 bias, the
// 0x7ffffffc limit -- is eight or fewer. So the cross-build comparison normalises exactly those and
// nothing else, and a switch that changed any real constant would still be caught.
std::string Normalize(std::vector<std::string> const &ls)
{
	std::string out;
	for (auto const &l : ls) {
		for (size_t i = 0; i < l.size();) {
			if (l.compare(i, 2, "0x") == 0) {
				size_t j = i + 2;
				while (j < l.size() && isxdigit((unsigned char)l[j]))
					++j;
				if (j - i - 2 >= 9) {
					out += "0xABS";
					i = j;
					continue;
				}
			}
			out += l[i++];
		}
		out += '\n';
	}
	return out;
}

// ---------------------------------------------------------------------------------------------
// The cells. `chunks` is derived here from VLMAX, never read back from the emitter.
// ---------------------------------------------------------------------------------------------
struct Cell {
	char const *name;
	u32 vlen, vtype, word;
};

Cell const ADMITTED[] = {
    {"vlse32 e32m1 @512", 512, VT_E32M1, INSN_VLSE32},
    {"vlse32 e32m1 @1024", 1024, VT_E32M1, INSN_VLSE32},
    {"vlse32 e32m2 @512", 512, VT_E32M2, INSN_VLSE32},
    {"vlse32 e32m2 @1024", 1024, VT_E32M2, INSN_VLSE32},
    {"vlse32 e32m8 @512", 512, VT_E32M8, INSN_VLSE32},
    {"vlse32 e32m8 @1024", 1024, VT_E32M8, INSN_VLSE32},
    {"vlse32 e32mf2 @512", 512, VT_E32MF2, INSN_VLSE32},   // VLMAX 8: a partial chunk
    {"vlse32 e32mf2 @1024", 1024, VT_E32MF2, INSN_VLSE32}, // VLMAX 16
    {"vlse32 e64m1 @512", 512, VT_E64M1, INSN_VLSE32},     // EEW 32 != SEW 64, EMUL 1/2
    {"vlse32 e64m1 @1024", 1024, VT_E64M1, INSN_VLSE32},
    {"vlse32 e16m1 @512", 512, VT_E16M1, INSN_VLSE32}, // EEW 32 != SEW 16, EMUL 2
    {"vlse32 e16m1 @1024", 1024, VT_E16M1, INSN_VLSE32},
    {"vlse32 x0 base @512", 512, VT_E32M1, INSN_VLSE32_X0BASE},
    {"vlse32 x0 stride @1024", 1024, VT_E32M1, INSN_VLSE32_X0STRIDE},
};

Cell const REFUSED[] = {
    {"masked vlse32 @512", 512, VT_E32M1, INSN_VLSE32_MASKED},
    {"masked vlse32 @1024", 1024, VT_E32M1, INSN_VLSE32_MASKED},
    {"vlse8 @512", 512, VT_E32M1, INSN_VLSE8},
    {"vlse16 @512", 512, VT_E32M1, INSN_VLSE16},
    {"vlse64 @512", 512, VT_E32M1, INSN_VLSE64},
    {"vlse64 @1024", 1024, VT_E32M1, INSN_VLSE64},
    {"vsse32 (store) @512", 512, VT_E32M1, INSN_VSSE32},
    {"vsse32 (store) @1024", 1024, VT_E32M1, INSN_VSSE32},
    {"vlsseg2e32 (nf=2) @512", 512, VT_E32M1, INSN_VLSSEG2E32},
    {"vle32 (unit) @512", 512, VT_E32M1, INSN_VLE32},
    {"vluxei32 (indexed) @512", 512, VT_E32M1, INSN_VLUXEI32},
    {"vlse32 @128", 128, VT_E32M1, INSN_VLSE32},
    {"vlse32 @256", 256, VT_E32M1, INSN_VLSE32},
};

// ---------------------------------------------------------------------------------------------
// [1] Admitted: the frame, the node's VLMAX, one gather per chunk, each chunk's own destination
//     window, and the element loop still present as the fallback body.
// ---------------------------------------------------------------------------------------------
void CheckAdmitted(Cell const &c)
{
	u32 const vlmax = Vlmax(c.vlen, c.vtype);
	u32 const chunks = (vlmax + 15) / 16;
	u32 const regbytes = c.vlen / 8;
	Built b;
	Build(b, Cfg{c.vlen, c.vtype, c.word, true, true});
	auto *node = FindMemNode(b.region);
	CHECK(node != nullptr);
	if (!node)
		return;
#ifndef Z3_BASELINE
	CHECK_EQ((u32)node->vlmax, vlmax);
#endif
	CHECK_EQ(CountIota(b.code), 1u); // exactly one embedded lane-index vector
	auto ls = Disassemble(b.code);
	CHECK(!ls.empty());
	// M2/M3: one gather, one masked store, one address-space-top guard per chunk.
	CHECK_EQ(Count(ls, "vpgatherdd"), chunks);
	CHECK_EQ(Count(ls, "kortestw"), chunks);
	CHECK_EQ(Count(ls, "vpcmpnled"), chunks); // objdump's name for vpcmpd imm=6 (signed >)
	CHECK_EQ(Count(ls, "vpmulld"), chunks);
	CHECK_EQ(Count(ls, "{k1},zmm0"), chunks); // the masked vmovdqu32 into CPUState
	// M3: each chunk's destination window, by the group_chunk formula, appears exactly once.
	for (u32 k = 0; k < chunks; ++k) {
		u32 const dl = k * 64u;
		u32 const off = ST_VREG + (VD + dl / regbytes) * 512u + dl % regbytes;
		std::string const want = "[r13+" + Hex(off) + "]{k1},zmm0";
		CHECK_EQ(Count(ls, want.c_str()), 1u);
	}
	// [6] M7: the element loop is still there, as the body of both runtime fallbacks. Its
	// signature is the per-element `imul edi,r11d` the gather has no counterpart for.
	CHECK_EQ(Count(ls, "imul   edi,r11d"), 1u);
	// [4] M5: the P1 bias, on the scalar base and on the host base, exactly once each.
	CHECK_EQ(Count(ls, "add    r10d,0x80000000"), 1u);
	CHECK_EQ(Count(ls, "mov    r8d,0x80000000"), 1u);
	CHECK_EQ(Count(ls, "add    r8,rbp"), 1u); // rbp == R_MEMBASE == mmu::base
	// [5] M6: the vstart precheck precedes every gather, and there is exactly one.
	std::string const vstart_cmp = "cmp    DWORD PTR [r13+" + Hex(ST_VSTART) + "],0x0";
	CHECK_EQ(Count(ls, vstart_cmp.c_str()), 1u);
	int const at_vstart = FirstOf(ls, vstart_cmp.c_str());
	int const at_gather = FirstOf(ls, "vpgatherdd");
	CHECK(at_vstart >= 0 && at_gather > at_vstart);
	CHECK(at_vstart >= 0 && ls[(size_t)at_vstart + 1].find("jne") != std::string::npos);
	// [3] M4: within every chunk the order is guard-branch THEN gather THEN store, and no store
	// precedes the first guard branch. Walked as a state machine over the whole fast path.
	unsigned seen_guard = 0, seen_gather = 0, seen_store = 0, order_faults = 0;
	for (auto const &l : ls) {
		bool const is_guard = l.find("kortestw") != std::string::npos;
		bool const is_gather = l.find("vpgatherdd") != std::string::npos;
		bool const is_store = l.find("{k1},zmm0") != std::string::npos;
		if (is_guard)
			++seen_guard;
		if (is_gather) {
			if (seen_gather + 1 > seen_guard)
				++order_faults; // a gather before its own chunk's guard
			++seen_gather;
		}
		if (is_store) {
			if (seen_store + 1 > seen_gather)
				++order_faults; // a store before its own chunk's gather
			++seen_store;
		}
	}
	CHECK_EQ(order_faults, 0u);
	CHECK_EQ(seen_store, chunks);
	// The switch off must remove the whole fast path and keep the element loop.
	Built off;
	Build(off, Cfg{c.vlen, c.vtype, c.word, false, true});
	CHECK_EQ(CountIota(off.code), 0u);
	auto lo = Disassemble(off.code);
	CHECK_EQ(Count(lo, "vpgatherdd"), 0u);
	CHECK_EQ(Count(lo, "imul   edi,r11d"), 1u);
	CHECK(off.code.size() < b.code.size());
}

// ---------------------------------------------------------------------------------------------
// [2] Refused: no gather, no embedded constant, and -- the strong form -- the emitted bytes are
//     IDENTICAL to the same cell built with the switch off. M1 fails this row.
// ---------------------------------------------------------------------------------------------
void CheckRefused(Cell const &c)
{
	Built on, off;
	Build(on, Cfg{c.vlen, c.vtype, c.word, true, true});
	Build(off, Cfg{c.vlen, c.vtype, c.word, false, true});
	CHECK_EQ(CountIota(on.code), 0u);
	auto ls = Disassemble(on.code);
	CHECK_EQ(Count(ls, "vpgatherdd"), 0u);
	CHECK_EQ(on.code.size(), off.code.size());
	CHECK(on.code.size() == off.code.size() &&
	      !memcmp(on.code.data(), off.code.data(), on.code.size()));
}

// ---------------------------------------------------------------------------------------------
// [7] Inertness. Two halves: within this build (switch off == switch off with the audit switch on,
//     and refused rows above), and ACROSS builds -- `--off-hashes` prints one line per cell that a
//     pre-Z3 build of this same file (compiled with -DZ3_BASELINE) must print identically.
// ---------------------------------------------------------------------------------------------
void PrintOffHashes()
{
	auto one = [](char const *name, Cell const &c) {
		Built b;
		Build(b, Cfg{c.vlen, c.vtype, c.word, false, false});
		printf("OFFHASH %-26s vlen=%-4u vtype=0x%02x word=0x%08x bytes=%-5zu fnv=%016llx\n",
		       name, c.vlen, c.vtype, c.word, b.code.size(),
		       (unsigned long long)Fnv1a(Normalize(Disassemble(b.code))));
	};
	for (auto const &c : ADMITTED)
		one(c.name, c);
	for (auto const &c : REFUSED)
		one(c.name, c);
}
} // namespace

int main(int argc, char **argv)
{
	std::string const arg = argc > 1 ? argv[1] : "";
	if (arg == "--off-hashes") {
		PrintOffHashes();
		return 0;
	}
#ifndef Z3_BASELINE
	if (arg == "--dump") {
		Cfg c;
		c.vlen = argc > 2 ? (u32)atoi(argv[2]) : 512;
		if (argc > 3)
			c.vtype = (u32)strtoul(argv[3], nullptr, 16);
		Built b;
		Build(b, c);
		for (auto const &l : Disassemble(b.code))
			printf("%s\n", l.c_str());
		return 0;
	}
	printf("[1] admitted shapes: frame, VLMAX, one gather per chunk, element loop retained\n");
	for (auto const &c : ADMITTED) {
		int const before = g_failures;
		CheckAdmitted(c);
		printf("    %-24s VLMAX=%-4u chunks=%-3u %s\n", c.name, Vlmax(c.vlen, c.vtype),
		       (Vlmax(c.vlen, c.vtype) + 15) / 16, g_failures == before ? "ok" : "FAIL");
	}
	printf("[2] refused shapes: byte-identical to the switch-off build\n");
	for (auto const &c : REFUSED) {
		int const before = g_failures;
		CheckRefused(c);
		printf("    %-24s %s\n", c.name, g_failures == before ? "ok" : "FAIL");
	}
	printf("[7] host feature gate: without --...-force-emit this host (no AVX-512) must refuse\n");
	{
		bool const capable =
		    __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("bmi2");
		Built b;
		Build(b, Cfg{512, VT_E32M1, INSN_VLSE32, true, false});
		CHECK_EQ(CountIota(b.code), capable ? 1u : 0u);
		printf("    host avx512f+bmi2=%s -> gather emitted without force-emit = %s\n",
		       capable ? "yes" : "no", CountIota(b.code) ? "yes" : "no");
	}
	printf("\nZ3_VLSE_GATHER_ROUTE_TEST checks=%d failures=%d\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
#else
	fprintf(stderr, "Z3_BASELINE build: only --off-hashes is available\n");
	return 2;
#endif
}
