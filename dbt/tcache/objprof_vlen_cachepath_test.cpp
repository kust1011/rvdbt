// X4g3 focused path test: VLEN-qualified ARTIFACT identity, unqualified PROFILE identity.
//
// The defect this guards (X4c/X4d/X4e): artifacts were keyed on the guest ELF checksum alone, so a
// build at VLEN 512 and a build at VLEN 1024 produced different code at the SAME path. The second
// destroyed the first, and a later run at the first VLEN silently loaded the wrong specialization.
//
// This test drives the REAL objprof::Init/Announce/GetCachePath -- no mock -- and asserts the
// property in both directions: artifact paths must separate by VLEN, and the profile path must not
// move at all (one profiling run has to keep serving builds at every VLEN).
//
// It touches no guest, emits no code and runs anywhere.

#include "dbt/aot/aot.h"
#include "dbt/config.h"
#include "dbt/tcache/objprof.h"
#include "dbt/util/fsmanager.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace
{

int g_failed = 0;

void check(bool ok, char const *what)
{
	printf("  %-4s %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		g_failed++;
}

std::string at_vlen(unsigned bits, char const *ext)
{
	dbt::config::vlen_bits = bits;
	return dbt::objprof::GetCachePath(ext);
}

// basename after the last '/'
std::string base(std::string const &p)
{
	auto s = p.rfind('/');
	return s == std::string::npos ? p : p.substr(s + 1);
}

bool ends_with(std::string const &s, char const *suf)
{
	size_t n = strlen(suf);
	return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
}

size_t count_occurrences(std::string const &hay, std::string const &needle)
{
	size_t n = 0, pos = 0;
	while ((pos = hay.find(needle, pos)) != std::string::npos) {
		n++;
		pos += needle.size();
	}
	return n;
}

} // namespace

int main()
{
	printf("X4g3 objprof VLEN-qualified cache-path test\n");

	// A private cache dir and any file to checksum: Announce hashes the fd, it does not parse ELF.
	char dir_tmpl[] = "/tmp/rvdbt_cachepath_test_XXXXXX";
	char const *dir = mkdtemp(dir_tmpl);
	if (!dir) {
		fprintf(stderr, "mkdtemp failed\n");
		return 2;
	}
	std::string seed = std::string(dir) + "/seed.bin";
	{
		FILE *f = fopen(seed.c_str(), "wb");
		if (!f) {
			fprintf(stderr, "cannot create seed file\n");
			return 2;
		}
		// Deterministic bytes -> deterministic checksum -> deterministic expectations below.
		for (int i = 0; i < 4096; i++)
			fputc(i & 0xff, f);
		fclose(f);
	}

	// Same init order as elfrun (:957-958) and elfaot (:1104-1105). fsmanager::Init starts the
	// worker thread that services OpenCacheFile; without it Announce blocks on the condition
	// variable forever.
	dbt::fsmanager::Init(dir);
	dbt::objprof::Init(dir, true);
	int fd = open(seed.c_str(), O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "cannot open seed file\n");
		return 2;
	}
	unsigned const saved_vlen = dbt::config::vlen_bits;
	dbt::objprof::Announce(fd, true);
	close(fd);
	if (!dbt::objprof::HasProfile()) {
		fprintf(stderr, "Announce did not produce a profile\n");
		return 2;
	}

	auto so512 = at_vlen(512, dbt::AOT_SO_EXTENSION);
	auto so1024 = at_vlen(1024, dbt::AOT_SO_EXTENSION);
	auto o512 = at_vlen(512, dbt::AOT_O_EXTENSION);

	printf("  cache dir : %s\n", dir);
	printf("  v512  .so : %s\n", base(so512).c_str());
	printf("  v1024 .so : %s\n", base(so1024).c_str());
	printf("  v512  .o  : %s\n", base(o512).c_str());

	// U1: the whole point -- two VLENs, two artifact paths.
	check(so512 != so1024, "U1  same ELF, VLEN 512 vs 1024 -> DIFFERENT .aot.so paths");

	// U2: deterministic. Same inputs must give the same string every time, or a build and the run
	// that follows it would look in different places.
	check(at_vlen(512, dbt::AOT_SO_EXTENSION) == so512, "U2  same ELF + same VLEN twice -> identical path");

	// U3: the qualifier is about VLEN, not about the extension.
	check(base(o512).substr(0, base(o512).find(".aot")) == base(so512).substr(0, base(so512).find(".aot")),
	      "U3  .aot.o and .aot.so at one VLEN share the same qualified stem");
	check(ends_with(o512, dbt::AOT_O_EXTENSION) && ends_with(so512, dbt::AOT_SO_EXTENSION),
	      "U4  the extension is still the FINAL suffix");

	// U5: every legal VLEN gets its own path, and no two collide.
	{
		unsigned const legal[] = {128, 256, 512, 1024};
		std::vector<std::string> paths;
		for (unsigned b : legal)
			paths.push_back(at_vlen(b, dbt::AOT_SO_EXTENSION));
		bool all_distinct = true;
		for (size_t i = 0; i < paths.size(); i++)
			for (size_t j = i + 1; j < paths.size(); j++)
				if (paths[i] == paths[j])
					all_distinct = false;
		check(all_distinct, "U5  VLEN 128/256/512/1024 -> four distinct paths");
		bool named = true;
		for (size_t i = 0; i < paths.size(); i++)
			if (base(paths[i]).find(".v" + std::to_string(legal[i]) + ".") == std::string::npos)
				named = false;
		check(named, "U6  each path names its own VLEN (.v<bits>.)");
	}

	// U7: the qualifier appears exactly once. A doubled qualifier would mean GetCachePath had been
	// applied twice somewhere, which would silently break every consumer that re-derives the name.
	check(count_occurrences(base(so512), ".v512.") == 1, "U7  qualifier appears exactly once");

	// U8: the qualified name still matches the shell glob the publish selectors and sr_builder use.
	// sr_builder.sh keeps its clear-then-glob invariant, so `*.aot.so` MUST still match.
	check(ends_with(so512, ".aot.so"), "U8  qualified name still matches the *.aot.so glob");

	// U9 -- the load-bearing separation. The profile is formed by MakeCachePath, not GetCachePath,
	// so it must be untouched by any of the above: one profiling run serves both VLENs. Assert it
	// from the filesystem, which is what actually has to be true, rather than from a code path.
	{
		std::string prof;
		char cmd[PATH_MAX + 64];
		snprintf(cmd, sizeof cmd, "ls %s", dir);
		FILE *p = popen(cmd, "r");
		char line[512];
		int n_prof = 0;
		while (p && fgets(line, sizeof line, p)) {
			std::string s(line);
			while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
				s.pop_back();
			if (ends_with(s, ".prof")) {
				prof = s;
				n_prof++;
			}
		}
		if (p)
			pclose(p);
		check(n_prof == 1, "U9  exactly one .prof exists after Announce");
		check(!prof.empty() && prof.find(".v") == std::string::npos,
		      "U10 the .prof filename carries NO VLEN qualifier (one profile serves every VLEN)");
		printf("  .prof     : %s\n", prof.c_str());
		// And it must equal the unqualified <csum>.prof shape: same stem as the artifacts minus
		// the qualifier.
		std::string stem = base(so512).substr(0, base(so512).find(".v512."));
		check(prof == stem + ".prof", "U11 .prof is exactly <csum>.prof -- byte-identical to pre-fix");
	}

	dbt::config::vlen_bits = saved_vlen;
	dbt::objprof::Destroy();
	dbt::fsmanager::Destroy();

	printf("%s (%d failed)\n", g_failed ? "FAILED" : "PASSED", g_failed);
	return g_failed ? 1 : 0;
}
