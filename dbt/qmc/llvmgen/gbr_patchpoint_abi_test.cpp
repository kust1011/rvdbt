// The gbr patch point's register ABI, checked on EMITTED HOST CODE.
//
// WHAT BROKE. The patch point needs state in r13, membase in rbp and rsp back at the function's
// ENTRY stack pointer. Expressing the third as a `{rsp}` INLINE-ASM INPUT let the register
// allocator satisfy it by tearing the frame down first, and it ordered that BEFORE the copy that
// materializes `{rbp}`. When membase had been spilled, that copy is a RELOAD FROM THE FRAME, so it
// read from an address the frame no longer occupied:
//
//     add  $0x48,%rsp          <- frame gone
//     mov  0x40(%rsp),%rbp     <- membase from the wrong slot
//     call *0x4140(%r13)       <- QCG entered with a garbage membase
//
// The guest fault that followed was in the NEXT QCG block, forming an address off that membase --
// which is why it looked like a guest bug and not an ABI bug.
//
// WHAT THIS ASSERTS, and why it is not two-instruction pattern matching: for every function in a
// module compiled the way the loop tier compiles one, if membase is reloaded from the stack on the
// exit path, that reload must come BEFORE the instruction that switches rsp. The test fails on the
// ordering, whatever the offsets, frame size or register choice happen to be.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace dbt
{
namespace
{
unsigned g_fail = 0;

#define CHECK(cond, what)                                                                          \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, (what));                  \
			++g_fail;                                                                  \
		} else {                                                                           \
			printf("  ok   %s\n", (what));                                             \
		}                                                                                  \
	} while (0)

// One emitted function's exit path, as text.
struct Exit {
	long rsp_switch = -1;   // index of the instruction that puts the entry SP back in rsp
	long rbp_reload = -1;   // index of a reload of rbp FROM the stack
};

Exit ScanExit(std::vector<std::string> const &insns)
{
	Exit e;
	for (size_t i = 0; i < insns.size(); ++i) {
		auto const &s = insns[i];
		// A reload of the membase register out of the stack frame.
		if (s.find("(%rsp),%rbp") != std::string::npos)
			e.rbp_reload = (long)i;
		// Either shape of "rsp is now the entry SP": the old epilogue-satisfied pin, or the
		// explicit switch inside the asm.
		if (s.find(",%rsp") != std::string::npos &&
		    (s.find("add ") != std::string::npos || s.find("mov ") != std::string::npos) &&
		    s.find("(%rsp),%rbp") == std::string::npos)
			e.rsp_switch = (long)i;
	}
	return e;
}

} // namespace
} // namespace dbt

int main(int argc, char **argv)
{
	using namespace dbt;
	// The disassembly to check is supplied by the harness: `objdump -d` of an artifact built the
	// way the loop tier builds one. Keeping the compile out of this test is deliberate -- the
	// property is about EMITTED CODE, and reading it from the real compiler's output is stronger
	// than re-deriving it from a model of the compiler.
	if (argc < 2) {
		printf("usage: %s <objdump-output>\n  (checks the gbr patch-point exit ordering)\n",
		       argv[0]);
		return 2;
	}
	FILE *f = fopen(argv[1], "r");
	if (!f) {
		printf("  FAIL cannot open %s\n", argv[1]);
		return 1;
	}
	char line[4096];
	std::vector<std::string> insns;
	std::string fn;
	unsigned checked = 0, with_spill = 0;
	auto finish = [&]() {
		if (fn.empty() || insns.empty())
			return;
		auto e = ScanExit(insns);
		++checked;
		if (e.rbp_reload >= 0) {
			++with_spill;
			// THE CONTRACT: materialize membase, THEN switch the stack.
			char msg[512];
			snprintf(msg, sizeof msg,
				 "%s: membase reloaded from the frame BEFORE the rsp switch "
				 "(reload@%ld, switch@%ld)",
				 fn.c_str(), e.rbp_reload, e.rsp_switch);
			CHECK(e.rsp_switch < 0 || e.rbp_reload < e.rsp_switch, msg);
		}
		insns.clear();
	};
	while (fgets(line, sizeof line, f)) {
		std::string s(line);
		if (s.find(">:") != std::string::npos) { // new function header
			finish();
			auto lt = s.find('<');
			fn = lt == std::string::npos ? "?" : s.substr(lt);
			continue;
		}
		if (s.find('\t') != std::string::npos)
			insns.push_back(s);
	}
	finish();
	fclose(f);
	printf("  scanned %u function(s), %u with a stack-spilled membase on the exit path\n",
	       checked, with_spill);
	// NON-VACUITY: a disassembly in which nothing spills membase proves nothing about the
	// ordering, so it is not allowed to pass silently.
	CHECK(with_spill > 0, "at least one function actually spills membase (else this proves nothing)");
	printf(g_fail ? "FAIL (%u failures)\n" : "PASS (%u failures)\n", g_fail);
	return g_fail ? 1 : 0;
}
