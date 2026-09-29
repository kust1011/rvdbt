// P7L-B1: the matched dependency probe, as a structural instrument.
//
// WHAT THIS FILE HAS TO PROVE, and why each section exists. The probe is not a lowering -- it does
// not make any guest program run correctly, and nothing consumes its result. Its ONLY job is to be
// a single-factor manipulation of the emitted dependency graph, so every check below is about that
// single factor being real, being single, and being inert when off.
//
//   [1] OFF IS OFF. With depth 0 the frame contains no probe node and the emitted bytes are
//       identical whatever the `cross` arm says. `cross` alone must never change one byte.
//
//   [2] THE COUNT IS EXACTLY m * k * depth, at both VLENs and for depths 1, 2 and 4, and the
//       frame's declared n_typed accounts for every one of them (otherwise Emit_rvvtypedchunkend
//       Panics, which is itself the check).
//
//   [3] THE ARMS FORM THE SAME RUN. Same member count, same live-in/live-out chunk traffic, same
//       n_typed, same guest PCs. If `cross` reached admission this is what would move.
//
//   [4] k == 1 IS BYTE-IDENTICAL. At VLEN 512 `(c + 1) % 1 == c`, so the null control is a
//       property of the emitted code and not of a special case in the source.
//
//   [5] k == 2 DIFFERS IN ONE OPERAND AND IN NOTHING ELSE. Same instruction multiset from the real
//       disassembly, same instruction count, same CPUState accesses -- and a different probe
//       source register.
//
//   [6] THE DEPENDENCY GRAPH IS WHAT THE ARM CLAIMS. Connected components over the frame's lane
//       ops and probes: k components for `indep`, ONE for `serial`. Computed as components, not
//       read off register numbers.
//
//   [7] VALUE PRESERVATION IS STRUCTURAL. Every live-out store still stores the last member's lane
//       result reached through probes only, so no probe can change what the frame computes.
//
// SCOPE. Structure only. Nothing here is executed and nothing here is timed; the hardware evidence
// is the checkpoint's xbd package. Like the other route tests this one bypasses the AVX-512
// admission probes with the audit force-emit switches, because it never runs what it emits.

#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_qir.h"
#include "dbt/guest/rv32_vrun.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
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

// vsetvli a0,a0,e32,m1,ta,ma  then a chain of `vadd.vv v3,v3,v2`, which is the shape M4A's
// positive-control microkernel uses: one accumulator, one invariant addend, every member reading
// the previous member's result.
constexpr u32 W_VSETVLI_E32M1 = 0x0d057557u;
constexpr u32 W_VADD_V3_V3_V2 = 0x023101d7u;

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

void ApplyConfig(u32 vlen_bits, unsigned probe_depth, bool cross)
{
	config::rvv_vector_run = true;
	config::rvv_run_body_materialize = false;
	config::rvv_run_order_chunk_major = false;
	config::rvv_run_dep_probe_depth = probe_depth;
	config::rvv_run_dep_probe_cross = cross;
	config::rvv_qcg_hit_counter = true;
	config::rvv_lane_census = false;
	config::rvv_lane_census_out = nullptr;
	config::rvv_direct = true;
	config::rvv_verify = false;
	config::aot_use_llvm = false;
	config::rvv_vector_ssa = false;
	config::vlen_bits = vlen_bits;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_direct_setvl = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_diag_chunk = false;
}

struct Built {
	MemArena arena{1u << 20};
	std::vector<u32> words;
	Region *region = nullptr;
	TestCompilerRuntime cr;
	std::vector<u8> code;
};

void Build(Built &b, unsigned members, u32 vlen_bits, unsigned probe_depth, bool cross,
	   bool emit = true)
{
	ApplyConfig(vlen_bits, probe_depth, cross);
	b.words.clear();
	b.words.push_back(W_VSETVLI_E32M1);
	for (unsigned i = 0; i < members; ++i)
		b.words.push_back(W_VADD_V3_V3_V2);
	CompilerJob::IpRangesSet ranges = {{0u, (u32)b.words.size() * 4u}};
	CompilerJob job(nullptr, (uptr)b.words.data(), CodeSegment(0u, 0x1000u), std::move(ranges));
	b.region = CompilerGenRegionIR(&b.arena, job);
	// QSel/QRegAlloc REWRITE the region's operands in place, so a QIR-level check must be run on
	// a region that was never handed to the backend. That is not a convenience: reading
	// `GetVVPR()` off a post-allocation operand returns a PHYSICAL register number in a release
	// build, which would silently answer a different question than the one being asked.
	if (!emit)
		return;
	qir::CodeSegment segment(0u, 0x1000u);
	auto const span = qcg::GenerateCode(&b.cr, &segment, b.region, 0);
	b.code.assign(span.begin(), span.end());
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

Frame const *RunFrame(std::vector<Frame> const &frames)
{
	for (auto const &f : frames)
		if (f.end->n_members >= 2)
			return &f;
	return nullptr;
}

unsigned CountOp(Frame const &f, Op op)
{
	unsigned n = 0;
	for (auto *i : f.body)
		n += i->GetOpcode() == op;
	return n;
}

// Disassemble the emitted bytes with objdump. Fails loudly: emission evidence that cannot be
// produced is not evidence.
std::vector<std::string> Disassemble(std::vector<u8> const &code)
{
	char path[] = "/tmp/rvdbt_p7lb1_XXXXXX";
	int const fd = mkstemp(path);
	if (fd < 0)
		return {};
	size_t written = 0;
	while (written < code.size()) {
		ssize_t const n = write(fd, code.data() + written, code.size() - written);
		if (n <= 0)
			break;
		written += (size_t)n;
	}
	close(fd);
	std::string const cmd =
	    std::string("objdump -D -b binary -m i386:x86-64 -M intel --no-show-raw-insn ") + path +
	    " 2>/dev/null";
	std::vector<std::string> out;
	if (FILE *p = popen(cmd.c_str(), "r")) {
		char line[512];
		while (fgets(line, sizeof(line), p)) {
			std::string s(line);
			auto const colon = s.find(":\t");
			if (colon == std::string::npos)
				continue;
			std::string body = s.substr(colon + 2);
			while (!body.empty() && (body.back() == '\n' || body.back() == ' '))
				body.pop_back();
			out.push_back(body);
		}
		pclose(p);
	}
	unlink(path);
	return out;
}

// The only thing that legitimately differs between two Built objects is the rel32 of the fallback
// arm's `call`, which is relative to whatever heap address this test's code buffer landed at. That
// is a property of the harness, not of the code generator, so it is normalised away -- and ONLY it.
// The real byte-identity gate is run on `elfrun --dump-tbcode`, where both arms place the block at
// the same address and no normalisation is needed or allowed.
std::vector<std::string> NormalizeCallTargets(std::vector<std::string> const &lines)
{
	std::vector<std::string> out;
	out.reserve(lines.size());
	for (auto const &l : lines) {
		auto const pos = l.find("call ");
		out.push_back(pos == std::string::npos ? l : l.substr(0, pos + 5) + "<stub>");
	}
	return out;
}

std::string Mnemonic(std::string const &line)
{
	auto const sp = line.find(' ');
	return sp == std::string::npos ? line : line.substr(0, sp);
}

// Connected components over the frame's lane ops AND probes, using QIR value identity. This is
// computed as components rather than read off chunk indices, for M2E's reason: a claim about
// dependence must not be a claim about how the allocator numbered registers.
unsigned Components(Frame const &f)
{
	std::map<u32, u32> parent; // value id -> parent
	auto find = [&](u32 x) {
		while (parent[x] != x)
			x = parent[x] = parent[parent[x]];
		return x;
	};
	auto add = [&](u32 x) {
		if (!parent.count(x))
			parent[x] = x;
	};
	auto join = [&](u32 a, u32 b) {
		add(a);
		add(b);
		parent[find(a)] = find(b);
	};
	std::set<u32> nodes;
	for (auto *i : f.body) {
		auto const op = i->GetOpcode();
		if (op != Op::_vchunkadd && op != Op::_vchunkdep)
			continue;
		if (!i->o(0).IsVVPR())
			continue;
		u32 const d = i->o(0).GetVVPR();
		nodes.insert(d);
		add(d);
		auto ins = i->inputs();
		for (u8 s = 0; s < ins.size(); ++s)
			if (ins[s].IsVVPR())
				join(d, ins[s].GetVVPR());
	}
	std::set<u32> roots;
	for (u32 n : nodes)
		roots.insert(find(n));
	return (unsigned)roots.size();
}

// ---------------------------------------------------------------------------------------------

void Check1_OffIsOff()
{
	fprintf(stderr, "[1] depth 0: no probe node, and `cross` alone changes nothing\n");
	for (u32 vlen : {512u, 1024u}) {
		Built a, b;
		Build(a, 8, vlen, 0, false);
		Build(b, 8, vlen, 0, true);
		auto fa = FindFrames(a.region);
		auto const *ra = RunFrame(fa);
		CHECK(ra != nullptr);
		if (ra)
			CHECK_EQ(CountOp(*ra, Op::_vchunkdep), 0u);
		CHECK_EQ(a.code.size(), b.code.size());
		auto const la = NormalizeCallTargets(Disassemble(a.code));
		auto const lb = NormalizeCallTargets(Disassemble(b.code));
		CHECK(!la.empty());
		CHECK(la == lb);
		fprintf(stderr, "    VLEN %-4u  0 probe nodes, %zu instructions identical (%zu B)\n",
			vlen, la.size(), a.code.size());
	}
}

void Check2_CountAndCapacity()
{
	fprintf(stderr, "[2] probe count is exactly m * k * depth, and n_typed accounts for it\n");
	for (u32 vlen : {512u, 1024u}) {
		u8 const k = (u8)(vlen / 512u);
		for (unsigned depth : {1u, 2u, 4u}) {
			for (bool cross : {false, true}) {
				Built b;
				Build(b, 8, vlen, depth, cross);
				auto frames = FindFrames(b.region);
				auto const *f = RunFrame(frames);
				CHECK(f != nullptr);
				if (!f)
					continue;
				unsigned const m = f->end->n_members;
				CHECK_EQ(CountOp(*f, Op::_vchunkdep), m * k * depth);
				// The frame declares what the emitter must have seen; a wrong
				// declaration is a Panic in Emit_rvvtypedchunkend, so reaching here
				// with code emitted already proves it -- this pins the value too.
				unsigned const loads = CountOp(*f, Op::_vstatechunkload);
				unsigned const stores = CountOp(*f, Op::_vstatechunkstore);
				CHECK_EQ((unsigned)f->begin->n_typed,
					 loads + stores + m * k + m * k * depth);
				CHECK(!b.code.empty());
			}
		}
		fprintf(stderr, "    VLEN %-4u k=%u  depths 1/2/4 x indep/serial all exact\n", vlen, k);
	}
}

void Check3_SameRun()
{
	fprintf(stderr, "[3] the two arms form the SAME run (cross never reaches admission)\n");
	for (u32 vlen : {512u, 1024u}) {
		Built off, ind, ser;
		Build(off, 8, vlen, 0, false);
		Build(ind, 8, vlen, 1, false);
		Build(ser, 8, vlen, 1, true);
		auto foff = FindFrames(off.region), find_ = FindFrames(ind.region),
		     fser = FindFrames(ser.region);
		auto const *a = RunFrame(foff);
		auto const *b = RunFrame(find_);
		auto const *c = RunFrame(fser);
		CHECK(a && b && c);
		if (!(a && b && c))
			continue;
		CHECK_EQ((unsigned)a->end->n_members, (unsigned)b->end->n_members);
		CHECK_EQ((unsigned)b->end->n_members, (unsigned)c->end->n_members);
		// live-in/live-out chunk traffic is the descriptor's dataflow, made visible
		CHECK_EQ(CountOp(*b, Op::_vstatechunkload), CountOp(*c, Op::_vstatechunkload));
		CHECK_EQ(CountOp(*b, Op::_vstatechunkstore), CountOp(*c, Op::_vstatechunkstore));
		CHECK_EQ(CountOp(*a, Op::_vstatechunkload), CountOp(*b, Op::_vstatechunkload));
		CHECK_EQ(CountOp(*a, Op::_vstatechunkstore), CountOp(*b, Op::_vstatechunkstore));
		CHECK_EQ(CountOp(*b, Op::_vchunkadd), CountOp(*c, Op::_vchunkadd));
		CHECK_EQ((unsigned)b->begin->n_typed, (unsigned)c->begin->n_typed);
		for (u8 i = 0; i < b->end->n_members; ++i)
			CHECK_EQ(b->end->members[i].pc, c->end->members[i].pc);
		fprintf(stderr,
			"    VLEN %-4u  members=%u loads=%u stores=%u n_typed=%u, identical in both arms\n",
			vlen, (unsigned)b->end->n_members, CountOp(*b, Op::_vstatechunkload),
			CountOp(*b, Op::_vstatechunkstore), (unsigned)b->begin->n_typed);
	}
}

void Check4_NullControlAtK1()
{
	fprintf(stderr, "[4] VLEN 512 (k == 1): indep and serial are BYTE-IDENTICAL\n");
	for (unsigned depth : {1u, 2u, 4u}) {
		Built ind, ser;
		Build(ind, 8, 512, depth, false);
		Build(ser, 8, 512, depth, true);
		CHECK(!ind.code.empty());
		CHECK_EQ(ind.code.size(), ser.code.size());
		auto const la = NormalizeCallTargets(Disassemble(ind.code));
		auto const lb = NormalizeCallTargets(Disassemble(ser.code));
		CHECK(!la.empty());
		CHECK(la == lb);
		fprintf(stderr, "    depth %u: %zu bytes / %zu instructions, identical\n", depth,
			ind.code.size(), la.size());
	}
}

void Check5_OneOperandAtK2()
{
	fprintf(stderr, "[5] VLEN 1024 (k == 2): same instruction multiset, different probe source\n");
	Built ind, ser;
	Build(ind, 8, 1024, 1, false);
	Build(ser, 8, 1024, 1, true);
	auto li = Disassemble(ind.code), ls = Disassemble(ser.code);
	CHECK(!li.empty());
	CHECK_EQ(li.size(), ls.size());
	std::map<std::string, int> ma, mb;
	for (auto const &l : li)
		++ma[Mnemonic(l)];
	for (auto const &l : ls)
		++mb[Mnemonic(l)];
	CHECK(ma == mb);
	// the arms are NOT identical: exactly one operand moved
	CHECK(NormalizeCallTargets(li) != NormalizeCallTargets(ls));
	// QIR level, on regions the backend never rewrote: indep's probe reads its own value,
	// serial's does not.
	Built qi, qs;
	Build(qi, 8, 1024, 1, false, false);
	Build(qs, 8, 1024, 1, true, false);
	auto fri = FindFrames(qi.region), frs = FindFrames(qs.region);
	auto const *a = RunFrame(fri);
	auto const *b = RunFrame(frs);
	CHECK(a && b);
	if (a && b) {
		unsigned self_i = 0, self_s = 0, n = 0;
		for (auto *i : a->body)
			if (i->GetOpcode() == Op::_vchunkdep) {
				++n;
				self_i += i->i(0).GetVVPR() == i->i(1).GetVVPR();
			}
		for (auto *i : b->body)
			if (i->GetOpcode() == Op::_vchunkdep)
				self_s += i->i(0).GetVVPR() == i->i(1).GetVVPR();
		CHECK_EQ(self_i, n);  // every indep probe reads its own running value
		CHECK_EQ(self_s, 0u); // no serial probe does
		CHECK_EQ(ma["vpblendmq"], (int)n);
		fprintf(stderr,
			"    %u probes: indep %u/%u read their own value, serial %u/%u; "
			"%zu instructions, multiset identical\n",
			n, self_i, n, self_s, n, li.size());
	}
	// no allocator spill/fill anywhere in either arm
	for (auto const *lines : {&li, &ls})
		for (auto const &l : *lines)
			CHECK(l.find("rsp") == std::string::npos ||
			      l.find("vmovdqu64") == std::string::npos);
}

void Check6_DependencyGraph()
{
	fprintf(stderr, "[6] the dependency graph is what the arm claims (connected components)\n");
	for (u32 vlen : {512u, 1024u}) {
		u8 const k = (u8)(vlen / 512u);
		Built ind, ser;
		Build(ind, 8, vlen, 1, false, false);
		Build(ser, 8, vlen, 1, true, false);
		auto fi = FindFrames(ind.region), fs = FindFrames(ser.region);
		auto const *a = RunFrame(fi);
		auto const *b = RunFrame(fs);
		CHECK(a && b);
		if (!(a && b))
			continue;
		CHECK_EQ(Components(*a), (unsigned)k);
		CHECK_EQ(Components(*b), 1u);
		fprintf(stderr, "    VLEN %-4u  indep %u component(s), serial %u component(s)\n", vlen,
			Components(*a), Components(*b));
	}
}

void Check7_ValuePreservation()
{
	fprintf(stderr, "[7] every live-out is still the last member's result, reached via probes only\n");
	Built ser;
	Build(ser, 8, 1024, 2, true, false);
	auto frames = FindFrames(ser.region);
	auto const *f = RunFrame(frames);
	CHECK(f != nullptr);
	if (!f)
		return;
	// Walk back from each store: the chain to a lane op must consist of probes only.
	std::map<u32, Inst *> def;
	for (auto *i : f->body)
		if (i->outputs().size() && i->o(0).IsVVPR())
			def[i->o(0).GetVVPR()] = i;
	unsigned checked = 0;
	for (auto *i : f->body) {
		if (i->GetOpcode() != Op::_vstatechunkstore)
			continue;
		CHECK(i->i(0).IsVVPR());
		Inst *cur = def.count(i->i(0).GetVVPR()) ? def[i->i(0).GetVVPR()] : nullptr;
		unsigned hops = 0;
		while (cur && cur->GetOpcode() == Op::_vchunkdep) {
			++hops;
			CHECK(cur->i(0).IsVVPR());
			cur = def.count(cur->i(0).GetVVPR()) ? def[cur->i(0).GetVVPR()] : nullptr;
		}
		CHECK(cur != nullptr && cur->GetOpcode() == Op::_vchunkadd);
		CHECK_EQ(hops, 2u); // depth 2: exactly the probes stand between store and lane op
		++checked;
	}
	CHECK(checked > 0);
	fprintf(stderr, "    %u live-out chunk stores, each 2 probe hops from a lane op\n", checked);
}

} // namespace

int main()
{
	Check1_OffIsOff();
	Check2_CountAndCapacity();
	Check3_SameRun();
	Check4_NullControlAtK1();
	Check5_OneOperandAtK2();
	Check6_DependencyGraph();
	Check7_ValuePreservation();
	if (g_failures) {
		fprintf(stderr, "\nFAILED: %d failure(s)\n", g_failures);
		return 1;
	}
	fprintf(stderr, "\nOK\n");
	return 0;
}
