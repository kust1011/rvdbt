// P1c COVERAGE. Proves from the SOURCE that every typed-chunk frame in rv32_qir.cpp closes through
// the one common entry, and that every close states a classification.
//
// WHY THE SOURCE AND NOT A RUNTIME COUNTER. The task forbids adding runtime instrumentation to the
// common path, and a runtime count could only ever cover the shapes a test happens to build -- it
// could never show that the 37th producer body, which no test reaches, does not still call
// `Create_rvvtypedchunkend` directly. The complete statement is a source one: that call does not
// appear in rv32_qir.cpp at all.
//
// WHAT IS CHECKED
//   [C1] `Create_rvvtypedchunkend` appears ZERO times in rv32_qir.cpp. This is the whole
//        no-silent-bypass claim: the only remaining callers are inside the common close.
//   [C2] every `Create_rvvtypedchunkbegin` site assigns its node to a handle, regardless of the
//        handle's local name, so it can be handed to the common close.
//   [C3] every `CloseFrame` names a reason from the enum, and NO site declares `Unclassified`.
//   [C4] the per-reason histogram is printed for review. This source-count check cannot prove
//        dynamic balance on every control-flow path; guest and QIR tests remain necessary.
//
// The number of begin call sites is deliberately NOT compared with the number of close call sites.
// One producer can select among several alternative begin calls and converge on one common close,
// while another can use one begin and close it on alternative control-flow paths. Literal source
// counts therefore are not a frame-balance invariant.

#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace
{
int g_failures = 0;

#define CHECK_EQ(a, b)                                                                               \
	do {                                                                                         \
		long long _a = (long long)(a);                                                       \
		long long _b = (long long)(b);                                                       \
		if (_a != _b) {                                                                      \
			fprintf(stderr, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__,          \
				__LINE__, #a, #b, _a, _b);                                           \
			++g_failures;                                                                \
		}                                                                                    \
	} while (0)

unsigned Count(std::string const &hay, char const *needle)
{
	unsigned n = 0;
	for (size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
		++n;
	return n;
}
} // namespace

int main()
{
	printf("P1c common-frame-close coverage\n");
	auto slurp = [](char const *path) {
		std::string out;
		FILE *f = fopen(path, "rb");
		if (!f)
			return out;
		char buf[65536];
		size_t n;
		while ((n = fread(buf, 1, sizeof buf, f)) > 0)
			out.append(buf, n);
		fclose(f);
		return out;
	};
	std::string const src = slurp(RVV_QIR_SOURCE);
	std::string const hdr = slurp(RVV_FINALIZER_SOURCE);
	if (src.empty() || hdr.empty()) {
		fprintf(stderr, "  FAIL cannot read the sources\n");
		return 1;
	}
	if (src.size() < 100000) {
		fprintf(stderr, "  FAIL source looks truncated (%zu bytes)\n", src.size());
		return 1;
	}

	unsigned const begins = Count(src, "Create_rvvtypedchunkbegin(");
	unsigned const raw_ends = Count(src, "Create_rvvtypedchunkend(");
	unsigned const closes = Count(src, "rvvfinal::CloseFrame(") + Count(src, "rvvfinal::FinalizeFrame(");
	unsigned const captured = Count(src, "= qb.Create_rvvtypedchunkbegin(");
	unsigned const direct_closes = Count(src, "rvvfinal::CloseFrame(");
	unsigned const finalized = Count(src, "rvvfinal::FinalizeFrame(");

	// [C1] the whole no-silent-bypass claim.
	CHECK_EQ(raw_ends, 0u);
	// [C2] every begin site hands the common close a handle.
	CHECK_EQ(captured, begins);
	CHECK_EQ(begins > 0u, true);
	CHECK_EQ(closes > 0u, true);

	// [C3]/[C4] every close names a reason and none is Unclassified.
	static char const *const kReasons[] = {
	    "None",	     "MultiMember",	      "WholeRegisterEvl",	  "ScalarResult",
	    "IsaCrossLane",  "MemoryOrProtocol",      "LoweringNotDecomposed", "EligibleShapeNotEnrolled",
	    "Unclassified"};
	std::map<std::string, unsigned> hist;
	unsigned named = 0;
	for (char const *r : kReasons) {
		// Keeps the list below and the enum from drifting apart.
		if (hdr.find(std::string("\n\t") + r) == std::string::npos) {
			fprintf(stderr, "  FAIL reason %s is not in the Ineligibility enum\n", r);
			++g_failures;
		}
		std::string const tok = std::string("rvvfinal::Ineligibility::") + r;
		unsigned const n = Count(src, tok.c_str());
		hist[r] = n;
		named += n;
	}
	// Each direct close must name a reason; FinalizeFrame derives its reason internally.
	CHECK_EQ(named, direct_closes);
	CHECK_EQ(hist["Unclassified"], 0u);
	CHECK_EQ(direct_closes + finalized, closes);

	printf("  begin sites %u, close sites %u (%u planner + %u classified), raw end calls %u\n",
	       begins, closes, finalized, direct_closes, raw_ends);
	for (char const *r : kReasons)
		if (hist[r])
			printf("  %-26s %u\n", r, hist[r]);
	if (g_failures) {
		printf("FAILED: %d check(s)\n", g_failures);
		return 1;
	}
	printf("PASSED\n");
	return 0;
}
