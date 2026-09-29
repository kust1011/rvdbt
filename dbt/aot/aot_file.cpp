#include "dbt/aot/aot.h"
#include "dbt/config.h"
#include "dbt/qmc/compile.h"
#include "dbt/tcache/objprof.h"
#include <sstream>

#include "elfio/elfio.hpp"
namespace elfio = ELFIO;

extern "C" {
#include <fcntl.h>
}

namespace dbt
{
LOG_STREAM(aot)

struct AOTCompilerRuntime final : CompilerRuntime {
	AOTCompilerRuntime(elfio::section *elf_text_, const elfio::string_section_accessor &elf_stra_,
			   const elfio::symbol_section_accessor &elf_syma_, std::vector<AOTSymbol> &aotsyms_)
	    : code_arena(256_MB), elf_text(elf_text_), elf_stra(elf_stra_), elf_syma(elf_syma_),
	      aotsyms(aotsyms_)
	{
	}

	void *AllocateCode(size_t sz, uint align) override
	{
		return code_arena.Allocate(sz, align);
	}

	bool AllowsRelocation() const override
	{
		return true;
	}

	void *AnnounceRegion(u32 ip, std::span<u8> const &code, u32 num_insns) override
	// void *AnnounceRegion(u32 ip, std::span<u8> const &code) override
	{
		auto str_idx = elf_stra.add_string(MakeAotSymbol(ip));
		uptr code_offs = (uptr)code.data() - (uptr)code_arena.BaseAddr();

		elf_syma.add_symbol(str_idx, code_offs, code.size(), elfio::STB_GLOBAL, elfio::STT_FUNC, 0,
				    elf_text->get_index());
		aotsyms.push_back({ip, 0});

		return nullptr;
	}

	MemArena code_arena;
	elfio::section *elf_text;
	elfio::string_section_accessor elf_stra;
	elfio::symbol_section_accessor elf_syma;
	std::vector<AOTSymbol> &aotsyms;
};

void AOTCompileELF()
{
	if (!objprof::HasProfile()) {
		log_aot("No profile data found");
		return;
	}
	log_aot("Start aot compilation");

	elfio::elfio writer;
	writer.create(elfio::ELFCLASS64, elfio::ELFDATA2LSB);
	writer.set_os_abi(elfio::ELFOSABI_LINUX);
	writer.set_type(elfio::ET_REL);
	writer.set_machine(elfio::EM_X86_64);

	elfio::section *aot_sec = writer.sections.add(".aot");
	aot_sec->set_type(elfio::SHT_PROGBITS);
	aot_sec->set_flags(elfio::SHF_ALLOC | elfio::SHF_EXECINSTR | elfio::SHF_WRITE);
	aot_sec->set_addr_align(0x10);

	std::vector<AOTSymbol> aot_symbols;
	aot_symbols.reserve(64_KB);

	elfio::section *aottab_sec = writer.sections.add(".aottab");
	aottab_sec->set_type(elfio::SHT_PROGBITS);
	aottab_sec->set_flags(elfio::SHF_ALLOC);
	aottab_sec->set_addr_align(0x1000);

	elfio::section *str_sec = writer.sections.add(".strtab");
	str_sec->set_type(elfio::SHT_STRTAB);
	elfio::section *sym_sec = writer.sections.add(".symtab");
	sym_sec->set_type(elfio::SHT_SYMTAB);
	sym_sec->set_info(1);
	sym_sec->set_addr_align(0x4);
	sym_sec->set_entry_size(writer.get_default_entry_size(elfio::SHT_SYMTAB));
	sym_sec->set_link(str_sec->get_index());

	elfio::string_section_accessor stra(str_sec);
	elfio::symbol_section_accessor syma(writer, sym_sec);
	AOTCompilerRuntime aotrt(aot_sec, stra, syma, aot_symbols);

	AOTCompileObject(&aotrt);

	aot_sec->set_data((char const *)aotrt.code_arena.BaseAddr(), aotrt.code_arena.GetUsedSize());

	aottab_sec->set_size(sizeof(AOTTabHeader) + sizeof(AOTSymbol) * aot_symbols.size());
	syma.add_symbol(stra.add_string(AOT_SYM_AOTTAB), 0, aottab_sec->get_size(), elfio::STB_GLOBAL,
			elfio::STT_OBJECT, 0, aottab_sec->get_index());

	assert(writer.validate().empty());

	auto obj_path = objprof::GetCachePath(AOT_O_EXTENSION);
	writer.save(obj_path);

	LinkAOTObject(aot_symbols);
}

void LinkAOTObject(std::vector<AOTSymbol> &aot_symbols)
{
	auto obj_path = objprof::GetCachePath(AOT_O_EXTENSION);
	auto aot_path = objprof::GetCachePath(AOT_SO_EXTENSION);

	// V-next R3: in shard-link aggregation mode, link the aottab object (obj_path) together with the N shard
	// function-objects (obj_path.IofN). Region functions resolve by symbol name (_aot_<gip>) across all objects.
	// -Bsymbolic: bind references to symbols DEFINED in this .so locally -> the linker relaxes cross-object PLT32
	// calls (R_X86_64_PLT32) to direct PC-relative calls, recovering the direct-call speed that the single-object
	// serial build gets for free (without it, cross-shard calls go through the PLT and regress runtime, e.g.
	// libyaml +26%). Applied only when sharding; serial single-object link is unchanged.
	std::string objects = obj_path;
	std::string extra_flags;
	if (dbt::config::aot_shard_link > 0) {
		extra_flags = " -Bsymbolic";
		for (int i = 0; i < dbt::config::aot_shard_link; ++i)
			objects += " " + obj_path + "." + std::to_string(i) + "of" +
				   std::to_string(dbt::config::aot_shard_link);
	}
	// OPAQUE_BOUNDARY diagnostic (default off): the linked-in helper bitcode (llvmaot.cpp,
	// --aot-diag-link-bitcode) brings in __builtin_cpu_supports() call sites (host-capability
	// gates already present in dbt/guest/rv32_vector_cascade.h and rv32_vector_fast.h) whose
	// clang/glibc lowering references __cpu_model with a PC32 relocation even under -fPIC --
	// harmless in the diagnostic's normal executable but rejected by `ld -shared` by default.
	// `-z notext` permits the resulting (rare) text relocation instead of failing the link; the
	// shipped default path (this flag unset) is byte-for-byte unaffected.
	if (dbt::config::aot_diag_link_bitcode)
		// -z notext: see the comment above (the __builtin_cpu_supports() text-relocation
		// case this predates and, for the paths that remain, still guards).
		// --defsym __dso_handle=0: the linked-in helper bitcode's translation unit brings a
		// static-storage global that clang gives a __cxa_atexit-guarded constructor,
		// referencing __dso_handle -- normally supplied by crtbeginS.o when a shared object
		// is linked through the compiler driver, absent here because LinkAOTObject invokes
		// the linker directly. This diagnostic .aot.so is never expected to run its static
		// destructors cleanly at process exit, so a dummy definition is sufficient to satisfy
		// the reference; the shipped (non-diagnostic) link is unaffected.
		extra_flags += " -z notext --defsym __dso_handle=0";
	// ld.lld rejects "-shared -pie" together (stricter than BFD ld, which silently accepts the
	// combination for a shared object); -pie is meaningless for -shared regardless, so drop it
	// on the lld path only -- the default /usr/bin/ld path is untouched (byte-of-behavior identical).
	std::string linker = dbt::config::aot_use_lld ? "/usr/lib/llvm-20/bin/ld.lld" : "/usr/bin/ld";
	std::string pie_flag = dbt::config::aot_use_lld ? "" : " -pie";
	int link_rc = system((linker + " -z relro --hash-style=gnu" + pie_flag + " -m elf_x86_64 -shared" +
			       extra_flags + " -o" + aot_path + " " + objects)
				  .c_str());
	if (link_rc != 0) {
		Panic("linker invocation failed, rc=" + std::to_string(link_rc));
	}

	elfio::elfio elf;
	if (!elf.load(aot_path)) {
		log_aot("no such file: %s", aot_path.c_str());
	}

	elfio::section *sym_sec = nullptr;

	for (const auto &section : elf.sections) {
		auto test_sec = [&section](elfio::section **res, elfio::Elf_Word type, char const *name) {
			if (section->get_type() == type &&
			    std::string(section->get_name()) == std::string(name)) {
				*res = section.get();
			}
		};
		test_sec(&sym_sec, elfio::SHT_SYMTAB, ".symtab");
	}

	elfio::symbol_section_accessor syma(elf, sym_sec);

	auto resolve_sym = [&](std::string const &name) {
		elfio::Elf64_Addr addr;
		elfio::Elf_Xword size;
		u8 bind, type, other;
		elfio::Elf_Half shidx;
		if (!syma.get_symbol(name, addr, size, bind, type, shidx, other)) {
			Panic("symbol " + name + " not found");
		}
		return std::make_pair(addr, shidx);
	};

#if 0
	AOTTabHeader const *aottab{};
	size_t aottab_offs;
	{
		auto [vaddr, shidx] = resolve_sym(AOT_SYM_AOTTAB);
		auto section = elf.sections[shidx];
		auto soffs = vaddr - section->get_address();
		aottab_offs = section->get_offset() + soffs;
		aottab = (AOTTabHeader const *)(section->get_data() + soffs);
	}
	auto const aottab_sz = aottab->n_sym;
	auto const aottab_mem_sz = sizeof(AOTTabHeader) + sizeof(AOTSymbol) * aottab_sz;

	auto aottab_res = (AOTTabHeader *)malloc(aottab_mem_sz);
	aottab_res->n_sym = aottab_sz;

	for (u64 idx = 0; idx < aottab_sz; ++idx) {
		auto gip = aottab->sym[idx].gip;
		aottab_res->sym[idx] = {gip, resolve_sym(MakeAotSymbol(gip)).first};
	}
#else
	for (auto &sym : aot_symbols) {
		auto gip = sym.gip;
		auto gsize = sym.gsize; // 2026-06-19 AARS: preserve region byte-extent set in LLVMAOTTranslatePage
		// log_aot("found aottab[%08x]", gip);
		sym = {gip, resolve_sym(MakeAotSymbol(gip)).first, gsize};
	}
	AOTTabHeader aottab_header;
	aottab_header.n_sym = aot_symbols.size();

	size_t aottab_offs;
	{
		auto [vaddr, shidx] = resolve_sym(AOT_SYM_AOTTAB);
		auto section = elf.sections[shidx];
		auto soffs = vaddr - section->get_address();
		aottab_offs = section->get_offset() + soffs;
	}
#endif

	int fd = open(aot_path.c_str(), O_RDWR);
	if (!fd) {
		Panic();
	}
	if (lseek(fd, aottab_offs, SEEK_SET) == (off_t)-1) {
		Panic();
	}
	if (write(fd, &aottab_header, sizeof(AOTTabHeader)) != sizeof(AOTTabHeader)) {
		Panic();
	}
	size_t aot_symbols_size = sizeof(aot_symbols[0]) * aot_symbols.size();
	if (write(fd, aot_symbols.data(), aot_symbols_size) != aot_symbols_size) {
		Panic();
	}

	{
		struct stat st;
		if (fstat(fd, &st) < 0) {
			Panic(strerror(errno));
		}
		void *fmap = host_mmap(nullptr, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (fmap == MAP_FAILED) {
			Panic(strerror(errno));
		}
		auto *ehdr = (elfio::Elf64_Ehdr *)fmap;
		auto *phtab = (elfio::Elf64_Phdr *)((uptr)fmap + ehdr->e_phoff);

		for (size_t i = 0; i < ehdr->e_phnum; ++i) {
			auto *phdr = &phtab[i];
			if (phdr->p_type != elfio::PT_LOAD) {
				continue;
			}
			if (phdr->p_flags & elfio::PF_X) {
				log_aot("patch phnum %zu", i);
				phdr->p_flags |= elfio::PF_W;
			}
		}
		munmap(fmap, st.st_size);
	}

	close(fd);
}

} // namespace dbt
