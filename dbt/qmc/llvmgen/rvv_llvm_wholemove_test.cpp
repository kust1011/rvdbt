// W7 (2026-09-17). THE WHOLE-REGISTER MOVE `vmv<nr>r.v` ON THE LLVM/AOT ARM.
//
// This file exists to check the conditions that are DIFFICULT FOR THIS FAMILY SPECIFICALLY, not to
// re-check the typed-frame machinery the other LLVM tests already cover. The whole-register move is
// unusual in three ways, and each one gets a section whose failure path is stated:
//
//   [1] IT IS NOT GOVERNED BY VL OR THE MASK. RVV 1.0 16.6 -- NREG whole registers move; vl, LMUL,
//       the mask register and the tail/mask policy do not participate. The frame's guard must
//       therefore be the vtype-independent kind. Section 5 asserts the emitted guard reads NEITHER
//       `vec.vtype` NOR `vec.vl`. If someone "simplifies" this route by reusing RvvGuard (the
//       full-VL element-wise guard every other LLVM frame uses), those two loads appear and the
//       section fails. That is the assertion this file exists for.
//
//   [2] A REGISTER GROUP IS NOT CONTIGUOUS IN CPUState. Each architectural register occupies a
//       fixed `VLEN_MAX_BYTES` slot of which only `VLEN/8` bytes are live. Section 3 rebuilds the
//       exact set of CPUState byte ranges the emitted IR reads and writes and requires it to equal
//       the architectural set. A body that copied whole 512-byte slots, or that walked the group as
//       if it were contiguous, changes that set and fails -- an assertion a count of loads and
//       stores would not make.
//
//   [3] ITS RESTART UNIT IS THE CURRENT SEW, and the ratified RVV 1.0 text (v20240411) and the
//       current ISA main draft word the `vstart >= evl` case differently. The native arm therefore
//       admits `vstart == 0` ONLY and leaves every restart to QCG and the unchanged rv32_vmvNr
//       helper. Section 6 asserts the guard really does test vstart and that the ordered fallback
//       to that helper is intact, so "restricted envelope" is a property of the emitted code rather
//       than a sentence in a comment.
//
// Plus the ordinary obligations: an admission truth table including every refusal (section 2), the
// `vd == vs2` identity case (section 4), proof that the QCG arm is untouched and that exactly one
// of the two arms can fire (section 7), and the option-plumbing check that caught the sqrt route
// shipping dead (section 8).
//
// WHAT THIS FILE DOES NOT DO. It never runs the code it builds: no object is emitted and no
// PROT_EXEC page exists in this process, so it needs no AVX-512 host and executes no vector
// instruction. It asserts nothing about speed. It makes no claim about `vstart != 0` behaviour --
// that path is deliberately not this route's, and asserting it here would be asserting the helper.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/llvmgen/llvmgen.h"
#include "dbt/qmc/qir.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include "rvv_llvm_wholemove_srcid.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace dbt;
using namespace dbt::qir;

namespace
{

namespace rvv32 = dbt::rv32;

unsigned g_fail = 0;

#define CHECK(cond)                                                                                \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                   \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

#define CHECK_EQ(a, b)                                                                             \
	do {                                                                                       \
		auto va_ = (long long)(a);                                                         \
		auto vb_ = (long long)(b);                                                         \
		if (va_ != vb_) {                                                                  \
			printf("  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a,  \
			       #b, va_, vb_);                                                      \
			++g_fail;                                                                  \
		}                                                                                  \
	} while (0)

llvm::LLVMContext g_llvm_ctx;

// ---------------------------------------------------------------------------------------------
// Encodings. `vmv<nr>r.v vd, vs2` is OPIVI with funct6 = 0b100111, vm = 1, and the vs1 field
// carrying NREG-1 (rv32_decode.h decodes exactly this and nothing else onto id_rv32_vmvNr).
// ---------------------------------------------------------------------------------------------

constexpr u32 VmvNr(u32 nregs, u32 vs2, u32 vd)
{
	return (0b100111u << 26) | (1u << 25) | (vs2 << 20) | ((nregs - 1u) << 15) |
	       (0b011u << 12) | (vd << 7) | 0x57u;
}
// A vsetvli ahead of the move, so the block has an observed vtype. The point of several sections
// below is that the route does NOT consult it; it is here so that "the route ignores vtype" is
// tested against a block where a vtype is actually available to be wrongly consulted.
constexpr u32 Vsetvli(u32 zimm11)
{
	return (zimm11 << 20) | (10u << 15) | (0b111u << 12) | (10u << 7) | 0x57u;
}
constexpr u32 kVT_E32M1 = 0xd0u;
constexpr u32 kVT_E64M1 = 0xd8u;
constexpr u32 kJalr = 0x00008067u;

constexpr u32 WIDTHS[] = {128u, 256u, 512u, 1024u, 2048u, 4096u};
constexpr u32 NREGS[] = {1u, 2u, 4u, 8u};

// ---------------------------------------------------------------------------------------------
// Translation.
// ---------------------------------------------------------------------------------------------

struct Built {
	MemArena arena{1u << 21};
	CodeSegment segment{0u, 0x2000u};
	std::vector<u32> words;
	llvm::Module module;
	Region *region{};
	llvm::Function *fn{};
	explicit Built(std::vector<u32> w) : words(std::move(w)), module("w7", g_llvm_ctx) {}
};

// Every switch this file's route needs, at one place. The umbrella `rvv_qcg_typed_chunk` is held
// OFF so the LLVM route cannot borrow it -- it must read its own switch, which is the defect class
// the `=0`-is-a-no-op audit exists for.
void ConfigureLLVM(u32 vlen, bool llvm_backend = true, bool route = true)
{
	config::vlen_bits = vlen;
	config::aot_use_llvm = llvm_backend;
	config::rvv_vector_ssa = llvm_backend;
	config::rvv_direct = true;
	config::rvv_lowering = 1;
	config::rvv_verify = false;
	config::rvv_qcg_typed_chunk = !llvm_backend; // the QCG arm's own umbrella, section 7
	config::rvv_qcg_typed_chunk_wholemove = route;
	config::rvv_qcg_fp_shared_mask = false;
	config::rvv_qcg_partial_vl = false;
	config::rvv_vector_run = false;
	config::rvv_qcg_whole_reg = !llvm_backend;
}

void Translate(Built &b, bool run_backend)
{
	CompilerJob::IpRangesSet ranges = {{0u, (u32)(b.words.size() * sizeof(u32))}};
	CompilerJob job(nullptr, (uptr)b.words.data(), b.segment, std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	if (!run_backend)
		return;
	LLVMGenCtx ctx(&b.module);
	ctx.AddFunction(0u, b.segment);
	QIRToLLVM gen(ctx, &b.segment, b.region, 0u);
	b.fn = gen.Run();
}

// ---------------------------------------------------------------------------------------------
// QIR-level view.
// ---------------------------------------------------------------------------------------------

struct QirView {
	unsigned n_begin = 0, n_move = 0, n_hcall = 0, n_end_members = 0;
	unsigned guard_kind = ~0u;
	unsigned vlenb = 0;
	// the move node's own fields, so a wrong rd/src/nregs is a failure and not a silent pass
	unsigned rd = ~0u, src = ~0u, nregs = 0, regbytes = 0;
};

QirView ScanQir(Region *region)
{
	QirView v;
	for (auto &bb : region->GetBlocks()) {
		for (auto &ins : bb.ilist) {
			switch (ins.GetOpcode()) {
			case Op::_rvvtypedchunkbegin: {
				auto *b = static_cast<InstRVVTypedChunkBegin *>(&ins);
				++v.n_begin;
				v.guard_kind = (unsigned)b->guard_kind;
				v.vlenb = b->vlenb;
				break;
			}
			case Op::_rvvtypedchunkend:
				v.n_end_members += static_cast<InstRVVTypedChunkEnd *>(&ins)->n_members;
				break;
			case Op::_vwholemove: {
				auto *m = static_cast<InstVWholeMove *>(&ins);
				++v.n_move;
				v.rd = m->rd;
				v.src = m->src;
				v.nregs = m->nregs;
				v.regbytes = m->regbytes;
				break;
			}
			case Op::_hcall:
				++v.n_hcall;
				break;
			default:
				break;
			}
		}
	}
	return v;
}

// ---------------------------------------------------------------------------------------------
// LLVM-level view: the exact CPUState byte ranges the emitted function reads and writes.
//
// Every CPUState access this backend emits goes through LLVMGen::MakeStateEP, which is a
// constant-index inbounds GEP off the function's first argument. So resolving a load/store pointer
// to (is-state, offset) is exact rather than a heuristic, and an access that does NOT resolve is
// counted separately instead of being ignored.
// ---------------------------------------------------------------------------------------------

struct Access {
	u32 offs, size;
	bool operator<(Access const &o) const
	{
		return offs != o.offs ? offs < o.offs : size < o.size;
	}
	bool operator==(Access const &o) const { return offs == o.offs && size == o.size; }
};

struct IRView {
	std::vector<Access> loads, stores;
	unsigned unresolved = 0;
	unsigned calls = 0;
	bool Reads(u32 offs) const
	{
		for (auto const &a : loads)
			if (a.offs == offs)
				return true;
		return false;
	}
	bool Writes(u32 offs) const
	{
		for (auto const &a : stores)
			if (a.offs == offs)
				return true;
		return false;
	}
};

// Three outcomes, and the third is the one worth having. A pointer that is NOT derived from the
// state argument at all (an alloca for a region-local vloc, or a guest-memory pointer off
// `membase`) is simply not a CPUState access and is ignored. A pointer that IS derived from the
// state argument but whose offset is not a compile-time constant would be invisible to the
// byte-coverage comparison in section 3 and so would silently weaken it -- that one is counted.
enum class PtrKind { NotState, StateConst, StateVariable };

llvm::Value *StripToBase(llvm::Value *p)
{
	while (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(p))
		p = gep->getPointerOperand();
	return p;
}

PtrKind ResolveState(llvm::Value *p, llvm::Value *state, u32 *offs)
{
	if (StripToBase(p) != state)
		return PtrKind::NotState;
	if (p == state) {
		*offs = 0;
		return PtrKind::StateConst;
	}
	auto *gep = llvm::cast<llvm::GetElementPtrInst>(p);
	llvm::APInt ap(64, 0);
	if (!gep->accumulateConstantOffset(gep->getModule()->getDataLayout(), ap))
		return PtrKind::StateVariable;
	*offs = (u32)ap.getZExtValue();
	return PtrKind::StateConst;
}

IRView ScanIR(llvm::Function *fn)
{
	IRView v;
	llvm::Value *state = fn->getArg(0);
	for (auto &bb : *fn) {
		for (auto &ins : bb) {
			if (llvm::isa<llvm::CallInst>(&ins))
				++v.calls;
			llvm::Value *ptr = nullptr;
			llvm::Type *ty = nullptr;
			bool store = false;
			if (auto *l = llvm::dyn_cast<llvm::LoadInst>(&ins)) {
				ptr = l->getPointerOperand();
				ty = l->getType();
			} else if (auto *s = llvm::dyn_cast<llvm::StoreInst>(&ins)) {
				ptr = s->getPointerOperand();
				ty = s->getValueOperand()->getType();
				store = true;
			} else {
				continue;
			}
			u32 offs = 0;
			PtrKind const k = ResolveState(ptr, state, &offs);
			if (k == PtrKind::NotState)
				continue;
			if (k == PtrKind::StateVariable) {
				++v.unresolved;
				continue;
			}
			Access a{offs, (u32)(ty->getPrimitiveSizeInBits() / 8)};
			(store ? v.stores : v.loads).push_back(a);
		}
	}
	return v;
}

// The union of a set of accesses, as a byte-coverage map. Comparing COVERAGE rather than the raw
// access list is what lets the body choose its own chunk width freely while still failing if it
// touches one byte it must not.
std::vector<bool> Coverage(std::vector<Access> const &v, u32 lo, u32 hi)
{
	std::vector<bool> out(hi - lo, false);
	for (auto const &a : v)
		for (u32 b = a.offs; b < a.offs + a.size; ++b)
			if (b >= lo && b < hi)
				out[b - lo] = true;
	return out;
}

constexpr u32 kVecBase = offsetof(CPUState, vec);
constexpr u32 kVregBase = kVecBase + offsetof(rvv32::VectorState, vreg);
constexpr u32 kVtypeOffs = kVecBase + offsetof(rvv32::VectorState, vtype);
constexpr u32 kVlOffs = kVecBase + offsetof(rvv32::VectorState, vl);
constexpr u32 kVstartOffs = kVecBase + offsetof(rvv32::VectorState, vstart);
constexpr u32 kVlenbOffs = kVecBase + offsetof(rvv32::VectorState, vlenb);
constexpr u32 kSlot = rvv32::VLEN_MAX_BYTES;

// ---------------------------------------------------------------------------------------------
// [1]-[6] the emitted route.
// ---------------------------------------------------------------------------------------------

void SectionRoute()
{
	printf("[W1..W6] admission, geometry, guard and identity\n");
	for (u32 vlen : WIDTHS) {
		u32 const regbytes = vlen / 8;
		for (u32 nregs : NREGS) {
			// vd = 8*? -- pick two DIFFERENT aligned groups that both fit the file.
			u32 const vd = 0, vs2 = nregs == 8 ? 8u : nregs * 2u;
			ConfigureLLVM(vlen);
			Built b({Vsetvli(kVT_E32M1), VmvNr(nregs, vs2, vd), kJalr});
			Translate(b, true);
			QirView q = ScanQir(b.region);

			// [1] exactly one typed frame, with the VTYPE-INDEPENDENT guard kind.
			// Failure path: a route that refuses gives n_begin == 0; a route that reuses
			// the element-wise guard gives guard_kind == VTypeVlVstart (0).
			CHECK_EQ(q.n_begin, 1u);
			CHECK_EQ(q.n_move, 1u);
			CHECK_EQ(q.guard_kind,
				 (unsigned)InstRVVTypedChunkBegin::GuardKind::VlenbVstart);
			CHECK_EQ(q.vlenb, regbytes);
			CHECK_EQ(q.rd, vd);
			CHECK_EQ(q.src, vs2);
			CHECK_EQ(q.nregs, nregs);
			CHECK_EQ(q.regbytes, regbytes);
			// the frame keeps exactly one ordered fallback member
			CHECK_EQ(q.n_end_members, 1u);

			IRView ir = ScanIR(b.fn);
			CHECK_EQ(ir.unresolved, 0u);

			// [3] THE ARCHITECTURAL BYTE SET, exactly. Build the expected coverage of the
			// whole vector register file and compare. A body that copied whole 512-byte
			// slots, or that treated the group as contiguous, differs here.
			u32 const lo = kVregBase, hi = kVregBase + rvv32::VREG_NUM * kSlot;
			std::vector<bool> want_ld(hi - lo, false), want_st(hi - lo, false);
			for (u32 r = 0; r < nregs; ++r)
				for (u32 i = 0; i < regbytes; ++i) {
					want_ld[(vs2 + r) * kSlot + i] = true;
					want_st[(vd + r) * kSlot + i] = true;
				}
			CHECK(Coverage(ir.loads, lo, hi) == want_ld);
			CHECK(Coverage(ir.stores, lo, hi) == want_st);

			// [5] THE GUARD READS NEITHER vtype NOR vl. This is the section this file
			// exists for: reusing RvvGuard would add both loads and fail here, even
			// though every other assertion in [1] and [3] would still pass.
			CHECK(!ir.Reads(kVtypeOffs));
			CHECK(!ir.Reads(kVlOffs));
			// ...and it does read the two facts the body needs.
			CHECK(ir.Reads(kVlenbOffs));
			CHECK(ir.Reads(kVstartOffs));

			// [6] vstart is published exactly once, and the ordered fallback to the
			// unchanged helper is present (one call on the slow arm, plus the direct-hit
			// bookkeeping this backend emits).
			unsigned vstart_stores = 0;
			for (auto const &a : ir.stores)
				if (a.offs == kVstartOffs)
					++vstart_stores;
			CHECK_EQ(vstart_stores, 1u);
			CHECK(ir.calls >= 1u);
		}
	}

	// [4] IDENTITY. `vmv2r.v v4, v4` copies nothing, but still publishes vstart = 0.
	// Failure path: a body that emits the copy anyway writes into the vreg file and the first
	// check fails; a body that drops the vstart store fails the second.
	for (u32 vlen : {512u, 2048u}) {
		ConfigureLLVM(vlen);
		Built b({Vsetvli(kVT_E64M1), VmvNr(2u, 4u, 4u), kJalr});
		Translate(b, true);
		QirView q = ScanQir(b.region);
		CHECK_EQ(q.n_begin, 1u);
		CHECK_EQ(q.n_move, 1u);
		CHECK_EQ(q.rd, q.src);
		IRView ir = ScanIR(b.fn);
		u32 const lo = kVregBase, hi = kVregBase + rvv32::VREG_NUM * kSlot;
		std::vector<bool> none(hi - lo, false);
		CHECK(Coverage(ir.stores, lo, hi) == none);
		CHECK(Coverage(ir.loads, lo, hi) == none);
		CHECK(ir.Writes(kVstartOffs));
	}
}

// ---------------------------------------------------------------------------------------------
// [2] refusals. Each one must build NO typed frame and must still leave the instruction with a
// lowering -- the helper call. "Refused" must never mean "dropped".
// ---------------------------------------------------------------------------------------------

struct Refusal {
	char const *name;
	u32 word;
	bool route_on;
	bool verify;
};

void SectionRefusals()
{
	printf("[W2] refusals keep the unchanged rv32_vmvNr helper\n");
	Refusal const cases[] = {
	    // the family's own switch off -- `=0` must mean off, not "inherited from an umbrella"
	    {"switch off", VmvNr(2u, 4u, 0u), false, false},
	    // vd not aligned to NREG (the decoder does not check this; this route must)
	    {"vd misaligned", VmvNr(2u, 4u, 1u), true, false},
	    // vs2 not aligned to NREG
	    {"vs2 misaligned", VmvNr(4u, 6u, 0u), true, false},
	    // group runs off the end of the 32-register file
	    {"group out of file", VmvNr(8u, 0u, 28u), true, false},
	    // --rvv-verify compares helper-internal paths and cannot see emitted code
	    {"rvv-verify", VmvNr(2u, 4u, 0u), true, true},
	};
	for (auto const &c : cases) {
		ConfigureLLVM(1024u, true, c.route_on);
		config::rvv_verify = c.verify;
		Built b({Vsetvli(kVT_E32M1), c.word, kJalr});
		Translate(b, false);
		QirView q = ScanQir(b.region);
		if (q.n_begin != 0 || q.n_move != 0 || q.n_hcall == 0) {
			printf("  FAIL refusal '%s': begin=%u move=%u hcall=%u\n", c.name, q.n_begin,
			       q.n_move, q.n_hcall);
			++g_fail;
		}
	}
	config::rvv_verify = false;

	// An unsupported VLEN. `vlen_supported` is the guest's own rule; a width outside it must not
	// produce a frame whose `vlenb` the guard could never match.
	ConfigureLLVM(384u);
	{
		Built b({Vsetvli(kVT_E32M1), VmvNr(2u, 4u, 0u), kJalr});
		Translate(b, false);
		QirView q = ScanQir(b.region);
		CHECK_EQ(q.n_begin, 0u);
		CHECK(q.n_hcall > 0u);
	}

	// The predicate the route shares with the QCG arm and the interpreter, asserted directly so
	// that an NREG the DECODER already rejects (3, 5, 6, 7) is still refused here -- the route
	// must not depend on where it is called from for its legality rules.
	for (u32 n : {3u, 5u, 6u, 7u, 9u, 16u})
		CHECK(!rvv32::whole_reg_group_legal(0u, n));
	for (u32 n : NREGS) {
		CHECK(rvv32::whole_reg_group_legal(0u, n));
		CHECK(!rvv32::whole_reg_group_legal(32u - n + 1u, n));
	}
	// The alignment rule that makes overlap impossible: two DISTINCT groups of NREG registers,
	// both aligned to NREG, never intersect. This is the precondition the emitter's per-chunk
	// load-then-store relies on, so it is proved rather than asserted in prose.
	for (u32 n : NREGS)
		for (u32 a = 0; a + n <= 32; a += n)
			for (u32 b = 0; b + n <= 32; b += n)
				if (a != b)
					CHECK(a + n <= b || b + n <= a);
}

// ---------------------------------------------------------------------------------------------
// [7] the QCG arm is untouched, and exactly one of the two arms can fire.
// ---------------------------------------------------------------------------------------------

void SectionQcgUnchanged()
{
	printf("[W7] QCG arm unchanged; the two arms are mutually exclusive\n");
	for (u32 vlen : {512u, 1024u, 2048u}) {
		// Pure QCG: the whole-move still takes RvvTryIntegerFamily's route, whose guard kind
		// is the RESTARTABLE one -- the kind this backend deliberately does not lower.
		ConfigureLLVM(vlen, /*llvm_backend=*/false);
		Built qcg({Vsetvli(kVT_E32M1), VmvNr(2u, 4u, 0u), kJalr});
		Translate(qcg, false);
		QirView q = ScanQir(qcg.region);
		CHECK_EQ(q.n_begin, 1u);
		CHECK_EQ(q.n_move, 1u);
		CHECK_EQ(q.guard_kind,
			 (unsigned)InstRVVTypedChunkBegin::GuardKind::VlenbRestartable);

		// With the LLVM backend on, the QCG arm refuses and the LLVM arm takes it; the frame
		// count stays one, so no encoding gets two lowerings.
		ConfigureLLVM(vlen, /*llvm_backend=*/true);
		Built llv({Vsetvli(kVT_E32M1), VmvNr(2u, 4u, 0u), kJalr});
		Translate(llv, false);
		QirView l = ScanQir(llv.region);
		CHECK_EQ(l.n_begin, 1u);
		CHECK_EQ(l.guard_kind,
			 (unsigned)InstRVVTypedChunkBegin::GuardKind::VlenbVstart);

		// ...and with the LLVM backend on but THIS route off, neither arm fires.
		ConfigureLLVM(vlen, /*llvm_backend=*/true, /*route=*/false);
		Built off({Vsetvli(kVT_E32M1), VmvNr(2u, 4u, 0u), kJalr});
		Translate(off, false);
		QirView o = ScanQir(off.region);
		CHECK_EQ(o.n_begin, 0u);
		CHECK(o.n_hcall > 0u);
	}
}

// ---------------------------------------------------------------------------------------------
// [8] option plumbing. The sqrt route once shipped with its gate reading a flag no command line
// could set and no background builder was told about, so it was dead in every artifact while every
// IR test passed. Those tests set the config field by hand -- exactly as sections 1-7 above do --
// so this section reads the SOURCE instead.
// ---------------------------------------------------------------------------------------------

// THE SOURCE ROOT IS RESOLVED AT RUN TIME, NOT BAKED IN.
//
// The first version of this file used the compile-time `DBT_SOURCE_ROOT` directly. That is a path
// on the build machine, so on any other machine every read failed and section 8 reported failures
// that said nothing about the code under test -- which is how it failed independent review. The
// resolution order below ends in a walk up from the executable, so an in-tree build needs no
// configuration at all, and every candidate that was tried is PRINTED on failure. A root that
// cannot be found is a hard FAIL, never a skip: the section exists to catch a route that is dead in
// every artifact, and a silently skipped check would reintroduce exactly that.

std::string g_root;

bool LooksLikeRoot(std::string const &r)
{
	// Two markers, so a directory that merely happens to contain one file is rejected.
	return std::ifstream(r + "/dbt/aot/aot_boot.cpp").good() &&
	       std::ifstream(r + "/dbt/qmc/llvmgen/rvv_llvm_wholemove_test.cpp").good();
}

std::string ExeDir()
{
	char buf[4096];
	ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
	if (n <= 0)
		return {};
	buf[n] = '\0';
	std::string s(buf);
	auto slash = s.rfind('/');
	return slash == std::string::npos ? std::string() : s.substr(0, slash);
}

bool ResolveRoot(char const *explicit_root)
{
	std::vector<std::pair<std::string, std::string>> tried; // (how, path)
	if (explicit_root && *explicit_root)
		tried.emplace_back("argv", explicit_root);
	if (char const *e = getenv("DBT_WHOLEMOVE_SOURCE_ROOT"))
		tried.emplace_back("$DBT_WHOLEMOVE_SOURCE_ROOT", e);
	tried.emplace_back("compile-time DBT_SOURCE_ROOT", DBT_SOURCE_ROOT);
	// walk up from the executable, so an in-tree build needs no configuration
	std::string d = ExeDir();
	for (int i = 0; i < 8 && !d.empty(); ++i) {
		tried.emplace_back("walk-up from /proc/self/exe", d);
		auto slash = d.rfind('/');
		if (slash == std::string::npos || slash == 0)
			break;
		d = d.substr(0, slash);
	}
	for (auto const &t : tried) {
		if (LooksLikeRoot(t.second)) {
			g_root = t.second;
			printf("  source root: %s   (via %s)\n", g_root.c_str(), t.first.c_str());
			return true;
		}
	}
	printf("  FAIL cannot locate a source tree. Candidates tried, none containing both\n"
	       "       dbt/aot/aot_boot.cpp and dbt/qmc/llvmgen/rvv_llvm_wholemove_test.cpp:\n");
	for (auto const &t : tried)
		printf("         %-32s %s\n", t.first.c_str(), t.second.c_str());
	printf("       Pass the root as argv, or set $DBT_WHOLEMOVE_SOURCE_ROOT.\n");
	++g_fail;
	return false;
}

std::string Slurp(char const *rel)
{
	std::string path = g_root + "/" + rel;
	std::ifstream in(path);
	if (!in) {
		printf("  FAIL cannot read %s\n", path.c_str());
		++g_fail;
		return {};
	}
	std::ostringstream ss;
	ss << in.rdbuf();
	return ss.str();
}

bool Has(std::string const &hay, char const *needle) { return hay.find(needle) != std::string::npos; }

void SectionPlumbing()
{
	printf("[W8] the switch is reachable from a command line and forwarded to the builder\n");
	for (char const *f : {"dbt/elfrun.cpp", "dbt/elfaot.cpp"}) {
		std::string const s = Slurp(f);
		// registered as an option...
		CHECK(Has(s, "(\"rvv-qcg-typed-chunk-wholemove\""));
		// ...AND assigned into config. Registration without assignment is the exact shape of
		// the defect this section exists for.
		CHECK(Has(s, "dbt::config::rvv_qcg_typed_chunk_wholemove = "
			     "opts.rvv_qcg_typed_chunk_wholemove;"));
	}
	// forwarded from elfrun to the ONLINE background elfaot, or the route is dead online
	CHECK(Has(Slurp("dbt/aot/aot_boot.cpp"),
		  "{\"rvv-qcg-typed-chunk-wholemove\", &config::rvv_qcg_typed_chunk_wholemove"));
	// mirrored in the propagation audit, which requires the two lists in lockstep
	CHECK(Has(Slurp("scripts/vlen_propagation_audit.py"),
		  "(\"rvv-qcg-typed-chunk-wholemove\", \"rvv_qcg_typed_chunk_wholemove\", \"Route\")"));
	// the gate reads its OWN switch, never an umbrella disjunction
	std::string const qir = Slurp("dbt/guest/rv32_qir.cpp");
	CHECK(Has(qir, "if (!config::rvv_qcg_typed_chunk_wholemove || "
		       "stub != RuntimeStubId::id_rv32_vmvNr)"));
}

} // namespace

// TWO INDEPENDENTLY RUNNABLE HALVES.
//
//   (default)               IR sections + the source audit. Needs a source tree.
//   --ir-only               IR sections only. Runs anywhere; says so in the verdict line, so an
//                           `--ir-only` PASS can never be mistaken for the whole test.
//   --source-audit [ROOT]   the source audit only.
//
// The split exists because the two halves have different requirements: the IR sections need only
// this binary, while the source audit needs the tree the binary was built from. Keeping them in one
// binary that always ran both meant the production (AVX-512) build could not be checked on the
// machine that can execute it. Separating them is NOT a way to skip the audit -- a default run
// still fails if the tree cannot be found.
int main(int argc, char **argv)
{
	std::string mode = argc > 1 ? argv[1] : "";
	char const *root = argc > 2 ? argv[2] : nullptr;
	if (mode != "" && mode != "--ir-only" && mode != "--source-audit") {
		printf("usage: %s [--ir-only | --source-audit [SOURCE_ROOT]]\n", argv[0]);
		return 2;
	}
	printf("rvv_llvm_wholemove_test\n");
	// The source this binary was COMPILED from, so staleness is a printed fact rather than
	// something inferred from failure line numbers. Compare with:
	//   sha256sum dbt/qmc/llvmgen/rvv_llvm_wholemove_test.cpp
	printf("  built from %s sha256=%s\n", WM_SOURCE_NAME, WM_SOURCE_SHA256);
	printf("  mode: %s\n", mode.empty() ? "ir+source-audit" : mode.c_str());

	bool const want_ir = mode != "--source-audit";
	bool const want_audit = mode != "--ir-only";
	if (want_ir) {
		SectionRoute();
		SectionRefusals();
		SectionQcgUnchanged();
	}
	if (want_audit && ResolveRoot(root))
		SectionPlumbing();

	if (g_fail) {
		printf("FAILED (%u failures)\n", g_fail);
		return 1;
	}
	if (!want_audit)
		printf("PASS (0 failures; IR sections only -- source audit NOT run)\n");
	else if (!want_ir)
		printf("PASS (0 failures; source audit only -- IR sections NOT run)\n");
	else
		printf("PASS (0 failures)\n");
	return 0;
}
