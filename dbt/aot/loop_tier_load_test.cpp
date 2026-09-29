// T5d2b1 focused test: LOAD AND VALIDATE, and nothing else.
//
// WHAT IS BEING CLAIMED. `looptier::LoadAndValidateArtifact` maps the exact artifact this run
// published, proves it is the one this process meant, and hands back an immutable view -- and does
// **not** install it. The claim therefore has two halves, and this file tests both:
//
//   (a) every validation step refuses, by name, with the handle closed and no view left behind;
//   (b) the translation cache is bit-for-bit unchanged across every case, success included.
//
// HOW (b) IS MEASURED RATHER THAN ASSERTED. `tcache::TierCensus` walks `tcache_map` and reports
// (AOT TBs, QCG TBs, their exec-count mass); the two L1 arrays are the dispatch caches every
// promotion path writes. A load that allocated, inserted, replaced, `CacheBr`'d, `CacheBrind`'d or
// relinked ANYTHING would move at least one of those numbers. The census is taken before and after
// each case and required to be identical -- so "no promotion" is a measurement here, not a promise
// about which function was called. Audit gate T11 covers the complementary half: the loader's
// translation unit may not so much as NAME a tcache mutation entry point.
//
// THE ARTIFACTS ARE REAL ELF IMAGES, built here byte by byte by the same `MakeSo` shape
// loop_tier_test uses, so each failure case is a genuinely malformed artifact rather than a stubbed
// return value. They are written to a temp directory and dlopen'd for real.
//
// WHAT IT DELIBERATELY DOES NOT DO. It enters no compiled code, times nothing, and makes no
// promotion, hotness or performance claim.

#include "dbt/aot/aot.h"
#include "dbt/aot/loop_tier.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/tcache/tcache.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
}

using namespace dbt;
using namespace dbt::looptier;

static int g_checks = 0, g_fail = 0;
static void CHECK(bool ok, char const *what)
{
	g_checks++;
	printf("  %-4s %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		g_fail++;
}
static void CHECKF(bool ok, char const *fmt, ...) __attribute__((format(printf, 2, 3)));
static void CHECKF(bool ok, char const *fmt, ...)
{
	char b[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	va_end(ap);
	CHECK(ok, b);
}
static void SECTION(char const *s)
{
	printf("\n== %s ==\n", s);
}

// ==============================================================================================
// A real ELF64 shared object carrying `_aot_tab`, `_aot_cpustate_abi`, `_aot_rvv_vlen_bits` and a
// defined `_x<gip>` for each table entry. Every knob below exists so one validation step can be
// broken while the artifact stays valid on every other axis -- which is what makes each refusal
// attributable to the gate it is meant to exercise.
struct SoSpec {
	std::vector<u32> gips;
	u64 n_sym_override = ~0ull;  // ~0 == gips.size()
	bool zero_first_vaddr = false;
	bool undefine_first_name = false; // table names a header the artifact does not define
	bool vaddr_outside_exec = false;  // an entry outside every executable PT_LOAD
	bool no_exec_segment = false;	  // ...or an object that declares no executable segment at all
};

struct Builder {
	std::vector<u8> img;
	size_t Add(void const *p, size_t n, size_t align = 1)
	{
		while (img.size() % align)
			img.push_back(0);
		size_t off = img.size();
		img.insert(img.end(), (u8 const *)p, (u8 const *)p + n);
		return off;
	}
};

static std::vector<u8> MakeSo(SoSpec const &sp)
{
	Builder f;
	Elf64_Ehdr eh{};
	memcpy(eh.e_ident, ELFMAG, SELFMAG);
	eh.e_ident[EI_CLASS] = ELFCLASS64;
	eh.e_ident[EI_DATA] = ELFDATA2LSB;
	eh.e_ident[EI_VERSION] = EV_CURRENT;
	eh.e_type = ET_DYN;
	eh.e_machine = EM_X86_64;
	eh.e_version = EV_CURRENT;
	eh.e_ehsize = sizeof eh;
	eh.e_shentsize = sizeof(Elf64_Shdr);
	f.Add(&eh, sizeof eh);

	AOTTabHeader hdr{};
	hdr.n_sym = sp.n_sym_override == ~0ull ? sp.gips.size() : sp.n_sym_override;
	size_t tab_off = f.Add(&hdr, sizeof hdr, 16);
	for (size_t i = 0; i < sp.gips.size(); ++i) {
		AOTSymbol as{};
		as.gip = sp.gips[i];
		as.aot_vaddr = 0x1000 + 0x40 * i;
		if (i == 0 && sp.zero_first_vaddr)
			as.aot_vaddr = 0;
		if (i == 0 && sp.vaddr_outside_exec)
			as.aot_vaddr = 0x900000; // well past the executable segment declared below
		as.gsize = 0;
		f.Add(&as, sizeof as);
	}
	size_t tab_size = f.img.size() - tab_off;

	std::string str;
	str.push_back('\0');
	std::vector<Elf64_Sym> syms(1);
	auto add_sym = [&](char const *nm, u64 val) {
		Elf64_Sym s{};
		s.st_name = (Elf64_Word)str.size();
		str += nm;
		str.push_back('\0');
		s.st_shndx = 1;
		s.st_value = val;
		s.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
		syms.push_back(s);
	};
	for (size_t i = 0; i < sp.gips.size(); ++i) {
		if (i == 0 && sp.undefine_first_name)
			continue;
		char nm[64];
		AotSymbolName(sp.gips[i], nm, sizeof nm);
		u64 v = 0x1000 + 0x40 * i;
		if (i == 0 && sp.zero_first_vaddr)
			v = 0;
		if (i == 0 && sp.vaddr_outside_exec)
			v = 0x900000;
		add_sym(nm, v);
	}
	size_t str_off = f.Add(str.data(), str.size(), 1);
	size_t sym_off = f.Add(syms.data(), syms.size() * sizeof(Elf64_Sym), 8);

	std::string shstr;
	shstr.push_back('\0');
	auto nm = [&](char const *s) {
		size_t o = shstr.size();
		shstr += s;
		shstr.push_back('\0');
		return (Elf64_Word)o;
	};
	Elf64_Word n_null = nm(""), n_tab = nm(".aottab"), n_str = nm(".strtab"), n_sym = nm(".symtab"),
		   n_shstr = nm(".shstrtab");
	size_t shstr_off = f.Add(shstr.data(), shstr.size(), 1);

	std::vector<Elf64_Shdr> sh(5);
	sh[0].sh_name = n_null;
	sh[0].sh_type = SHT_NULL;
	sh[1].sh_name = n_tab;
	sh[1].sh_type = SHT_PROGBITS;
	sh[1].sh_offset = tab_off;
	sh[1].sh_size = tab_size;
	sh[2].sh_name = n_str;
	sh[2].sh_type = SHT_STRTAB;
	sh[2].sh_offset = str_off;
	sh[2].sh_size = str.size();
	sh[3].sh_name = n_sym;
	sh[3].sh_type = SHT_SYMTAB;
	sh[3].sh_offset = sym_off;
	sh[3].sh_size = syms.size() * sizeof(Elf64_Sym);
	sh[3].sh_entsize = sizeof(Elf64_Sym);
	sh[3].sh_link = 2;
	sh[4].sh_name = n_shstr;
	sh[4].sh_type = SHT_STRTAB;
	sh[4].sh_offset = shstr_off;
	sh[4].sh_size = shstr.size();
	size_t sh_off = f.Add(sh.data(), sh.size() * sizeof(Elf64_Shdr), 8);

	// A REAL PROGRAM HEADER TABLE. The fixture must be well formed on every axis except the one a
	// case is exercising: an entry address is judged against the object's executable PT_LOAD ranges,
	// so an image with no program headers would be refused for the wrong reason in every case.
	size_t ph_off = 0;
	if (!sp.no_exec_segment) {
		Elf64_Phdr ph{};
		ph.p_type = PT_LOAD;
		ph.p_flags = PF_R | PF_X;
		ph.p_offset = 0;
		ph.p_vaddr = 0x1000;
		ph.p_paddr = 0x1000;
		ph.p_filesz = 0x7000;
		ph.p_memsz = 0x7000; // [0x1000, 0x8000): covers every entry the fixture places
		ph.p_align = 0x1000;
		ph_off = f.Add(&ph, sizeof ph, 8);
	}

	auto *e = (Elf64_Ehdr *)f.img.data();
	e->e_shoff = sh_off;
	e->e_shnum = (Elf64_Half)sh.size();
	e->e_shstrndx = 4;
	if (!sp.no_exec_segment) {
		e->e_phoff = ph_off;
		e->e_phnum = 1;
		e->e_phentsize = sizeof(Elf64_Phdr);
	}
	return f.img;
}

// The images above are ELF-correct but NOT linkable, so they exercise only the file-side reader.
// Everything that needs a real `dlopen` -- the shared ABI/VLEN gate, and the checks the loader makes
// against the MAPPED table -- is built here by the host toolchain from assembly.
//
// ASSEMBLY, NOT C, AND THAT IS FORCED BY WHAT IS BEING TESTED. The file-side reader requires every
// table entry's host address to equal the link-time value of the entry's own `_x<gip>` symbol, which
// is exactly the invariant a real artifact has. C cannot spell a symbol's address as a constant
// initialiser; `.quad _xNNNN` can, and produces the same on-disk addend + relocation the real
// producer emits. A C fixture that filled the addresses in a constructor would store RUNTIME
// addresses, disagree with the file, and make every case here refuse for the wrong reason.
struct RealSpec {
	std::vector<u32> gips;
	bool abi_sym = true;
	u64 abi = 0;
	bool vlen_sym = true;
	u64 vlen = 0;
	bool tab_sym = true;	    // define the `_aot_tab` symbol at all
	bool tab_sym_elsewhere = false; // define it AWAY from `.aottab`: a mapped/file disagreement
	bool wrong_count = false;	// ...claiming a different number of entries
	bool wrong_gip = false;		// ...or naming a different guest ip
	bool wrong_vaddr = false;	// ...or the SAME guest ip at a different host address
};

static void EmitRealAsm(FILE *f, RealSpec const &sp, std::vector<u64> const *resolved)
{
	fprintf(f, "\t.text\n");
	for (u32 g : sp.gips)
		fprintf(f, "\t.globl _x%x\n\t.type _x%x,@function\n_x%x:\n\tret\n\t.size _x%x,.-_x%x\n", g, g,
			g, g, g);
	if (sp.abi_sym)
		fprintf(f, "\t.data\n\t.globl _aot_cpustate_abi\n\t.align 8\n_aot_cpustate_abi:\n\t.quad %llu\n",
			(unsigned long long)sp.abi);
	if (sp.vlen_sym)
		fprintf(f,
			"\t.data\n\t.globl _aot_rvv_vlen_bits\n\t.align 8\n_aot_rvv_vlen_bits:\n\t.quad %llu\n",
			(unsigned long long)sp.vlen);
	auto entry = [&](size_t k, u32 gip) {
		fprintf(f, "\t.long 0x%x\n\t.zero 4\n", gip);
		if (resolved)
			fprintf(f, "\t.quad 0x%llx\n", (unsigned long long)(*resolved)[k]);
		else
			fprintf(f, "\t.quad _x%x\n", sp.gips[k]);
		fprintf(f, "\t.long 0\n\t.zero 4\n");
	};
	fprintf(f, "\t.section .aottab,\"a\",@progbits\n\t.align 16\n");
	if (sp.tab_sym && !sp.tab_sym_elsewhere)
		fprintf(f, "\t.globl _aot_tab\n_aot_tab:\n");
	fprintf(f, "\t.quad %zu\n", sp.gips.size());
	for (size_t k = 0; k < sp.gips.size(); ++k)
		entry(k, sp.gips[k]);
	if (sp.tab_sym && sp.tab_sym_elsewhere) {
		// A `_aot_tab` symbol that does NOT name the validated section's table: the mapped-vs-file
		// disagreement the loader must catch instead of trusting.
		fprintf(f, "\t.data\n\t.globl _aot_tab\n\t.align 16\n_aot_tab:\n\t.quad %zu\n",
			sp.wrong_count ? (size_t)99 : sp.gips.size());
		for (size_t k = 0; k < sp.gips.size(); ++k) {
			if (k == 0 && sp.wrong_vaddr) {
				// The SAME guest ip, at a DIFFERENT host address: the case a gip-only
				// comparison admits, which is a different artifact wearing the right label.
				fprintf(f, "\t.long 0x%x\n\t.zero 4\n\t.quad _x%x + 8\n\t.long 0\n\t.zero 4\n",
					sp.gips[k], sp.gips[k]);
				continue;
			}
			entry(k, (k == 0 && sp.wrong_gip) ? sp.gips[k] ^ 0x1000u : sp.gips[k]);
		}
	}
}

// TWO PASSES, and the second one is what makes the fixture a REAL artifact rather than a plausible
// one. `.quad _xNNNN` in a shared object leaves 0 in the section and a relocation beside it, while a
// real artifact carries the RESOLVED value on disk -- the producer links, reads its own symbol table
// back, and writes the addresses in. The file-side reader checks exactly that invariant, so a
// one-pass fixture would be refused for the wrong reason in every case. Pass 1 links to learn the
// addresses; pass 2 rewrites the table with them as literals. The two links have byte-identical
// section sizes, so the addresses pass 1 reports are the ones pass 2 produces -- and if they were
// not, the file reader would refuse and the test would fail rather than quietly pass.
static bool BuildRealSo(std::string const &path, RealSpec const &sp)
{
	std::string asmsrc = path + ".S";
	auto link = [&](std::vector<u64> const *resolved) {
		FILE *f = fopen(asmsrc.c_str(), "w");
		if (!f)
			return false;
		EmitRealAsm(f, sp, resolved);
		fclose(f);
		char cmd[2048];
		snprintf(cmd, sizeof cmd, "cc -shared -fPIC -nostdlib -o '%s' '%s' 2>/dev/null", path.c_str(),
			 asmsrc.c_str());
		return system(cmd) == 0 && access(path.c_str(), R_OK) == 0;
	};
	if (!link(nullptr))
		return false;
	std::vector<u64> vals(sp.gips.size(), 0);
	for (size_t k = 0; k < sp.gips.size(); ++k) {
		char cmd[512], nm[64];
		AotSymbolName(sp.gips[k], nm, sizeof nm);
		snprintf(cmd, sizeof cmd, "nm -f posix --defined-only '%s' 2>/dev/null | awk '$1==\"%s\"{print $3}'",
			 path.c_str(), nm);
		FILE *pp = popen(cmd, "r");
		if (!pp)
			return false;
		char out[64] = {0};
		bool got = fgets(out, sizeof out, pp) != nullptr;
		pclose(pp);
		if (!got)
			return false;
		vals[k] = strtoull(out, nullptr, 16);
		if (vals[k] == 0)
			return false;
	}
	unlink(path.c_str());
	bool ok = link(&vals);
	unlink(asmsrc.c_str());
	return ok;
}

// The translation cache's observable state, from APIs that already exist. Any promotion moves one.
struct TcacheCensus {
	unsigned long qcg_bytes, qcg_tbs, aot_tbs;
	unsigned long census[4];
	size_t l1_nonempty, brind_nonempty;
	bool operator==(TcacheCensus const &o) const
	{
		return qcg_bytes == o.qcg_bytes && qcg_tbs == o.qcg_tbs && aot_tbs == o.aot_tbs &&
		       census[0] == o.census[0] && census[1] == o.census[1] && census[2] == o.census[2] &&
		       census[3] == o.census[3] && l1_nonempty == o.l1_nonempty &&
		       brind_nonempty == o.brind_nonempty;
	}
};

static TcacheCensus Snapshot()
{
	TcacheCensus c{};
	unsigned long bytes[3] = {0, 0, 0};
	tcache::CodeBytes(bytes);
	c.qcg_bytes = bytes[0];
	c.qcg_tbs = bytes[1];
	c.aot_tbs = bytes[2];
	tcache::TierCensus(c.census);
	c.l1_nonempty = 0;
	c.brind_nonempty = 0;
	for (size_t i = 0; i < tcache::cache_tb_exec_count.size(); ++i)
		c.l1_nonempty += tcache::cache_tb_exec_count[i].tb != nullptr;
	for (size_t i = 0; i < tcache::l1_brind_cache.size(); ++i)
		c.brind_nonempty += tcache::l1_brind_cache[i].gip != 0;
	return c;
}

static std::string g_dir;
static std::string PubPath()
{
	return std::string(PublishPath());
}

static bool WriteFile(std::string const &p, std::vector<u8> const &b)
{
	int fd = open(p.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0)
		return false;
	bool ok = write(fd, b.data(), b.size()) == (ssize_t)b.size();
	close(fd);
	return ok;
}

// Run one case: install `img` at the published path, load, and require the outcome AND that the
// translation cache did not move.
static void Case(char const *name, std::vector<u8> const &img, u32 spawn, char const *want_reason)
{
	WriteFile(PubPath(), img);
	TcacheCensus before = Snapshot();
	char const *why = "";
	auto const *view = LoadAndValidateArtifact(PubPath().c_str(), spawn, &why);
	TcacheCensus after = Snapshot();
	CHECKF(view == nullptr, "%s: refused", name);
	CHECKF(strcmp(why, want_reason) == 0, "%s: reason is `%s` (got `%s`)", name, want_reason, why);
	CHECK(LoadedArtifactView() == nullptr, "   ...and no view is left behind");
	CHECK(before == after, "   ...and the translation cache did not move");
}

int main()
{
	printf("T5d2b1 loop-tier load/validate test\n");
	tcache::Init();
	char t[] = "/tmp/rvdbt_t5d2b1_XXXXXX";
	char *d = mkdtemp(t);
	if (!d) {
		printf("FATAL: no temp dir\n");
		return 1;
	}
	g_dir = d;
	config::loop_tier_stage = g_dir.c_str();
	config::vlen_bits = 512;
	SetPublishPath();
	u32 const SPAWN = 0x11890;
	std::vector<u32> const GIPS = {SPAWN, 0x118c4};

	// -------------------------------------------------------------------------------------
	SECTION("1. the path must be the one this run published");
	{
		std::string other = g_dir + "/somebody_elses.so";
		WriteFile(other, MakeSo({GIPS}));
		TcacheCensus before = Snapshot();
		char const *why = "";
		CHECK(LoadAndValidateArtifact(other.c_str(), SPAWN, &why) == nullptr &&
			  strcmp(why, "not_the_published_path") == 0,
		      "a well-formed artifact at ANOTHER path is refused by path identity alone");
		CHECK(LoadAndValidateArtifact(nullptr, SPAWN, &why) == nullptr, "a null path is refused");
		CHECK(before == Snapshot(), "...and the translation cache did not move");
		unlink(other.c_str());
	}

	// -------------------------------------------------------------------------------------
	SECTION("2. every structural refusal, by name, with the cache untouched");
	{
		unlink(PubPath().c_str());
		TcacheCensus before = Snapshot();
		char const *why = "";
		CHECK(LoadAndValidateArtifact(PubPath().c_str(), SPAWN, &why) == nullptr &&
			  strcmp(why, "artifact_unreadable") == 0,
		      "a MISSING artifact is refused");
		WriteFile(PubPath(), {});
		CHECK(LoadAndValidateArtifact(PubPath().c_str(), SPAWN, &why) == nullptr &&
			  strcmp(why, "artifact_unreadable") == 0,
		      "an EMPTY artifact is refused");
		CHECK(before == Snapshot(), "...and the translation cache did not move");

		Case("garbage bytes", std::vector<u8>(512, 0xcc), SPAWN, "table_malformed");

		SoSpec no_tab{GIPS};
		{
			// An ELF with no `.aottab` section at all.
			auto img = MakeSo(no_tab);
			// Blank the section name so the reader cannot find the table.
			for (size_t i = 0; i + 7 < img.size(); ++i)
				if (memcmp(&img[i], ".aottab", 7) == 0) {
					img[i + 1] = 'X';
					break;
				}
			Case("no .aottab section", img, SPAWN, "table_malformed");
		}
		{
			SoSpec sp{GIPS};
			sp.n_sym_override = 0;
			Case("an EMPTY table", MakeSo(sp), SPAWN, "table_empty");
		}
		{
			SoSpec sp{GIPS};
			sp.n_sym_override = 1000000; // more entries than the section can hold
			Case("a count its own section cannot hold", MakeSo(sp), SPAWN, "table_malformed");
		}
		{
			SoSpec sp{GIPS};
			sp.undefine_first_name = true;
			Case("an entry the artifact does not define", MakeSo(sp), SPAWN, "table_malformed");
		}
		{
			SoSpec sp{{SPAWN, SPAWN}};
			Case("a DUPLICATE guest ip", MakeSo(sp), SPAWN, "table_duplicate_gip");
		}
		{
			SoSpec sp{{0x11500, 0x118c4}}; // well-formed, but not this run's header
			Case("a table without this run's spawn header", MakeSo(sp), SPAWN,
			     "spawn_header_absent");
		}
		{
			// Structurally valid to the file reader, but not a loadable ELF: dlopen must fail
			// and the loader must report THAT rather than pretending it mapped something.
			Case("a file the dynamic loader cannot map", MakeSo({GIPS}), SPAWN, "dlopen_failed");
		}
	}

	// -------------------------------------------------------------------------------------
	SECTION("3. the gates that need a REAL mapping");
	// A refusal that happens before dlopen would not exercise the shared identity gate at all, so
	// every case here is a genuinely loadable object that differs in exactly one thing.
	{
		u64 const ABI = rv32::CPUStateAbiSignature();
		bool toolchain = true;
		auto real_case = [&](char const *name, RealSpec sp, char const *reason) {
			unlink(PubPath().c_str());
			if (!BuildRealSo(PubPath(), sp)) {
				toolchain = false;
				return;
			}
			TcacheCensus before = Snapshot();
			char const *why = "";
			auto const *v = LoadAndValidateArtifact(PubPath().c_str(), SPAWN, &why);
			CHECKF(v == nullptr && strcmp(why, reason) == 0, "%s -> `%s` (got `%s`)", name, reason,
			       why);
			CHECK(LoadedArtifactView() == nullptr, "   ...and no view is left behind");
			CHECK(before == Snapshot(), "   ...and the translation cache did not move");
		};
		real_case("no ABI symbol", {GIPS, false, 0, true, 512}, "abi_or_vlen_mismatch");
		real_case("WRONG ABI signature", {GIPS, true, ABI ^ 0xdeadbeefull, true, 512},
			  "abi_or_vlen_mismatch");
		real_case("no VLEN symbol", {GIPS, true, ABI, false, 0}, "abi_or_vlen_mismatch");
		real_case("WRONG VLEN (1024 for a 512 process)", {GIPS, true, ABI, true, 1024},
			  "abi_or_vlen_mismatch");
		{
			RealSpec sp{GIPS, true, ABI, true, 512};
			sp.tab_sym = false;
			real_case("a valid section but NO `_aot_tab` symbol to map", sp, "no_aot_tab");
		}
		{
			RealSpec sp{GIPS, true, ABI, true, 512};
			sp.tab_sym_elsewhere = true;
			sp.wrong_count = true;
			real_case("a mapped table claiming a different COUNT", sp, "table_count_disagrees");
		}
		{
			RealSpec sp{GIPS, true, ABI, true, 512};
			sp.tab_sym_elsewhere = true;
			sp.wrong_gip = true;
			real_case("a mapped table naming a different guest ip", sp, "table_entry_disagrees");
		}
		{
			// THE SAME GUEST IP AT A DIFFERENT HOST ADDRESS. A comparison that looked only at the
			// gip would accept this -- it is a different artifact wearing the right label.
			RealSpec sp{GIPS, true, ABI, true, 512};
			sp.tab_sym_elsewhere = true;
			sp.wrong_vaddr = true;
			real_case("a mapped entry with the SAME gip at a different host address", sp,
				  "table_entry_disagrees");
		}
		CHECK(toolchain, "the host toolchain built every real artifact these cases need");
	}

	// -------------------------------------------------------------------------------------
	SECTION("3b. the entry address is judged by the ELF, not by the file's byte length");
	{
		// A virtual address and a file length are unrelated quantities. The first version bounded
		// `aot_vaddr` by `image.size()`, which accepts an address outside every loadable segment as
		// long as the file happens to be long enough -- and rejects a perfectly good address in a
		// short file. Both fixtures below are well formed on every other axis.
		{
			SoSpec sp{GIPS};
			sp.vaddr_outside_exec = true; // 0x900000, past the declared PT_LOAD [0x1000,0x8000)
			Case("an entry OUTSIDE every executable PT_LOAD", MakeSo(sp), SPAWN,
			     "table_entry_bad_address");
		}
		{
			SoSpec sp{GIPS};
			sp.no_exec_segment = true; // no program headers at all: no address can be code
			Case("an object that declares no executable segment", MakeSo(sp), SPAWN,
			     "table_entry_bad_address");
		}
		{
			SoSpec sp{GIPS};
			sp.zero_first_vaddr = true;
			Case("an entry whose host address is ZERO", MakeSo(sp), SPAWN,
			     "table_entry_bad_address");
		}
	}

	// -------------------------------------------------------------------------------------
	SECTION("3c. the object that is VALIDATED is the object that is MAPPED");
	{
		// THE DEFECT, EXECUTED. The first version read the bytes, closed the fd, then called
		// dlopen(PATH). A publisher replacing the path in between -- which is exactly what
		// PublishAtomically's rename(2) does -- left the loader validating one inode and mapping
		// another, and `strcmp(path, PublishPath())` cannot see it: the string is identical either
		// way. This section runs both forms against a replaced path and shows they disagree.
		u64 const ABI = rv32::CPUStateAbiSignature();
		std::string a = g_dir + "/exact_a.so", b = g_dir + "/exact_b.so";
		bool built = BuildRealSo(a, {GIPS, true, ABI, true, 512}) &&
			     BuildRealSo(b, {{0x22000}, true, ABI, true, 512});
		CHECK(built, "two DIFFERENT real artifacts were built");
		if (built) {
			unlink(PubPath().c_str());
			CHECK(system(("cp '" + a + "' '" + PubPath() + "'").c_str()) == 0,
			      "the first is published");
			int fd = open(PubPath().c_str(), O_RDONLY | O_CLOEXEC);
			struct stat fst {};
			CHECK(fd >= 0 && fstat(fd, &fst) == 0, "and opened, exactly as the loader opens it");
			// Replace the published path, atomically, between the open and the map.
			std::string tmp = g_dir + "/replacement";
			CHECK(system(("cp '" + b + "' '" + tmp + "' && mv '" + tmp + "' '" + PubPath() + "'")
					 .c_str()) == 0,
			      "then the PATH is replaced by the other artifact");
			struct stat pst {};
			CHECK(stat(PubPath().c_str(), &pst) == 0 && pst.st_ino != fst.st_ino,
			      "...so the path now names a different inode -- the test is not vacuous");

			char fdpath[64];
			snprintf(fdpath, sizeof fdpath, "/proc/self/fd/%d", fd);
			void *h_fd = dlopen(fdpath, RTLD_NOW);
			CHECK(h_fd != nullptr, "dlopen(/proc/self/fd/N) succeeds");
			if (h_fd) {
				// The artifact this run validated defines _x11890; the replacement does not.
				CHECK(dlsym(h_fd, "_x11890") != nullptr,
				      "...and it mapped the FD'S OWN object: the validated one");
				link_map *lm = nullptr;
				struct stat lst {};
				CHECK(dlinfo(h_fd, RTLD_DI_LINKMAP, &lm) == 0 && lm && lm->l_name &&
					  stat(lm->l_name, &lst) == 0 && lst.st_ino == fst.st_ino,
				      "...and its link map resolves to that same inode, checkably");
				dlclose(h_fd);
			}
			void *h_path = dlopen(PubPath().c_str(), RTLD_NOW);
			CHECK(h_path != nullptr, "dlopen(PATH) also succeeds");
			if (h_path) {
				// THIS is what the old loader did, and what it would have mapped.
				CHECK(dlsym(h_path, "_x11890") == nullptr,
				      "...but it mapped the REPLACEMENT: validating one object and loading "
				      "another is what path-based dlopen permits");
				dlclose(h_path);
			}
			close(fd);
			unlink(a.c_str());
			unlink(b.c_str());
		}
	}

	// -------------------------------------------------------------------------------------
	SECTION("4. the success case: a validated view, and NOTHING installed");
	{
		u64 const ABI = rv32::CPUStateAbiSignature();
		unlink(PubPath().c_str());
		bool built = BuildRealSo(PubPath(), {GIPS, true, ABI, true, 512});
		CHECK(built, "a real, valid artifact carrying this run's spawn header was built");
		if (built) {
			TcacheCensus before = Snapshot();
			char const *why = "";
			auto const *v = LoadAndValidateArtifact(PubPath().c_str(), SPAWN, &why);
			TcacheCensus after = Snapshot();
			CHECKF(v != nullptr, "it LOADS and validates (`%s`)", why);
			CHECK(strcmp(why, "ok") == 0, "...reporting `ok`");
			if (v) {
				CHECK(v->handle != nullptr, "...the view owns a dlopen handle");
				CHECK(v->tab != nullptr && v->n_sym == GIPS.size(),
				      "...and a table with the entries the file bounded");
				CHECK(v->spawn_gip == SPAWN, "...naming this run's spawn header");
				CHECK(v->base != nullptr, "...and the base the object was mapped at");
				CHECK(v->path != nullptr && strcmp(v->path, PubPath().c_str()) == 0,
				      "...and the exact published path");
				CHECK(LoadedArtifactView() == v, "the view is reachable, and is the same one");
				// THE VIEW IS FD-BOUND, observed on the view rather than read out of the source:
				// a loader that had dlopen'd the PATH would name the path here.
				link_map *lm = nullptr;
				CHECK(dlinfo(v->handle, RTLD_DI_LINKMAP, &lm) == 0 && lm && lm->l_name &&
					  strncmp(lm->l_name, "/proc/self/fd/", 14) == 0,
				      "...and the mapping was taken from the open descriptor, not re-resolved "
				      "from the path");
			}
			// THE POINT OF THE CHECKPOINT.
			CHECK(before == after,
			      "and the translation cache is UNCHANGED: no TBlock, no CacheBr/CacheBrind, "
			      "no relink");
			CHECKF(after.aot_tbs == 0, "no AOT TBlock exists (%lu)", after.aot_tbs);
			CHECKF(after.l1_nonempty == 0 && after.brind_nonempty == 0,
			       "and both L1 dispatch caches are still empty (%zu/%zu)", after.l1_nonempty,
			       after.brind_nonempty);

			char const *why2 = "";
			CHECK(LoadAndValidateArtifact(PubPath().c_str(), SPAWN, &why2) == nullptr &&
				  strcmp(why2, "already_loaded") == 0,
			      "a second load is refused: the view is established once");

			ReleaseLoadedArtifact();
			CHECK(LoadedArtifactView() == nullptr, "after release the view is gone");
			CHECK(before == Snapshot(), "...and releasing moved no cache state either");
			ReleaseLoadedArtifact();
			CHECK(LoadedArtifactView() == nullptr, "and releasing twice is a no-op");

			char const *why3 = "";
			auto const *v3 = LoadAndValidateArtifact(PubPath().c_str(), SPAWN, &why3);
			CHECKF(v3 != nullptr, "the loader works again after a release (`%s`)", why3);
			ReleaseLoadedArtifact();
		}
	}

	// -------------------------------------------------------------------------------------
	SECTION("5. a refused load leaves the process able to carry on");
	{
		// Every refusal above returned to this point with the tier's own state untouched and the
		// cache unmoved; the run continues on QCG. Checked here as one statement rather than
		// inferred from the absence of a crash.
		CHECK(LoadedArtifactView() == nullptr, "no view is held after the refusal cases");
		TcacheCensus c = Snapshot();
		CHECKF(c.aot_tbs == 0 && c.qcg_tbs == 0,
		       "the translation cache holds no AOT and no QCG block (%lu/%lu)", c.aot_tbs,
		       c.qcg_tbs);
		CHECK(config::loop_tier_state != (int)State::LOADED,
		      "and the tier's own state was never moved to LOADED by a refusal");
	}

	unlink(PubPath().c_str());
	rmdir(g_dir.c_str());
	config::loop_tier_stage = nullptr;
	printf("\nRESULT checks=%d failures=%d\n", g_checks, g_fail);
	printf("%s\n", g_fail == 0 ? "LOOPTIER_LOAD_TEST PASS" : "LOOPTIER_LOAD_TEST FAIL");
	return g_fail == 0 ? 0 : 1;
}
