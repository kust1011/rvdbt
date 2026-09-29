#include "dbt/ccrf_materializer.h"

#include "dbt/config.h"
#include "dbt/arena.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/mmu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/jitabi.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir_builder.h"
#include "dbt/tcache/tcache.h"

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <set>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <thread>
#include <vector>

namespace dbt::ccrf
{
namespace
{
using boost::property_tree::ptree;

struct Range { u32 lo{}, hi{}; };
struct VectorPublication { u8 reg{}; u16 lo{}, hi{}; unsigned owner{}; };
struct ArchSnapshot {
	std::array<u32, 32> gpr{};
	u32 ip{};
	rv32::TrapCode trapno{};
	rv32::VectorState vec{};
	std::array<u32, 4096> csr{};
	rv32::FPUState fpu{};
};

bool enabled{}, sequential_mode{}, concurrent_mode{}, precompiled_sequential_mode{}, compute_mode{}, started{}, completed{};
ComponentLowering component_lowering{ComponentLowering::FunctionalXMM};
unsigned component{}, certified_components{};
u32 scope_entry{}, scope_end{}, exit_instruction{}, final_pc{};
u32 expected_vlen{}, expected_vlenb{};
u64 expected_epoch{}, entry_epoch{};
u8 compute_counter_gpr{};
u32 compute_read_mask{}, compute_write_mask{}, compute_workset_elements{}, compute_sew_bits{};
u32 compute_expected_invocations{}, compute_completed_invocations{};
std::vector<u32> compute_operations;
std::string output_path;
std::string exact_qir_path;
qir::CompilerJob::IpRangesSet exact_ranges;
std::set<u32> scalar_stores;
std::vector<Range> memory_ranges;
std::vector<Range> read_objects;
std::vector<VectorPublication> vector_publications;
static constexpr unsigned kMaxComponents = rv32::VLEN_MAX_BITS / 512;
ArchSnapshot entry_state, component_state[kMaxComponents];
[[noreturn]] void Fail(std::string const &why);
void ValidateReplicated(ArchSnapshot const &a, ArchSnapshot const &b);
void ValidatePrivateVectorEffects(unsigned owner);

struct ImageRuntime final : CompilerRuntime {
	~ImageRuntime() { if (mem) ::munmap(mem, size); }
	void *AllocateCode(size_t n, uint) override {
		size = (n + 4095) & ~size_t(4095);
		mem = ::mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mem == MAP_FAILED) Fail("COMPONENT_IMAGE_MMAP_FAILED");
		return mem;
	}
	bool AllowsRelocation() const override { return false; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
	void *mem{}; size_t size{};
};

struct WorkerPool {
	std::mutex mutex;
	std::condition_variable ready_cv, start_cv, done_cv;
	std::array<std::thread, 2> threads;
	std::array<CPUState *, 2> states{};
	std::array<void *, 2> code{};
	std::array<int, 2> cpus{{-1, -1}};
	unsigned ready{}, generation{}, done{};
	bool stop{};
};
WorkerPool workers;
std::array<std::unique_ptr<ImageRuntime>, 2> image_runtime;
std::array<std::span<u8>, 2> image_code;
std::array<std::unique_ptr<CPUState>, 2> worker_state;
struct ReadSnapshot {
	~ReadSnapshot() { if (base) ::munmap(base, size); }
	u8 *base{}; size_t size{};
};
std::array<std::unique_ptr<ReadSnapshot>, 2> read_snapshot;
u64 worker_startup_ns{}, materialization_ns{}, execution_ns{}, execution_begin_ns{};

u64 NowNs()
{
	return (u64)std::chrono::duration_cast<std::chrono::nanoseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
}

void WorkerMain(unsigned id)
{
	if (workers.cpus[id] < 0) Fail("WORKER_CPU_REQUIRED");
	cpu_set_t set; CPU_ZERO(&set); CPU_SET(workers.cpus[id], &set);
	if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set)) Fail("WORKER_AFFINITY_FAILED");
	std::unique_lock lock(workers.mutex);
	++workers.ready; workers.ready_cv.notify_one();
	unsigned seen = 0;
	for (;;) {
		workers.start_cv.wait(lock, [&] { return workers.stop || workers.generation != seen; });
		if (workers.stop) return;
		seen = workers.generation;
		auto *state = workers.states[id]; auto *code = workers.code[id];
		lock.unlock();
		CPUState::SetCurrent(state);
		jitabi::trampoline_to_jit(state, mmu::base, code);
		lock.lock();
		++workers.done; workers.done_cv.notify_one();
	}
}

void StartWorkers(int cpu0, int cpu1)
{
	if (cpu0 < 0 || cpu1 < 0 || cpu0 == cpu1 || cpu0 >= CPU_SETSIZE || cpu1 >= CPU_SETSIZE)
		Fail("DISTINCT_WORKER_CPUS_REQUIRED");
	auto topology = [](int cpu, char const *field) {
		std::ifstream in("/sys/devices/system/cpu/cpu" + std::to_string(cpu) +
				 "/topology/" + field);
		int value = -1; in >> value;
		if (!in) Fail("WORKER_TOPOLOGY_UNAVAILABLE");
		return value;
	};
	int const package0 = topology(cpu0, "physical_package_id");
	int const package1 = topology(cpu1, "physical_package_id");
	int const core0 = topology(cpu0, "core_id");
	int const core1 = topology(cpu1, "core_id");
	if (package0 == package1 && core0 == core1) Fail("SMT_SIBLING_WORKERS_REJECTED");
	workers.cpus = {cpu0, cpu1};
	u64 const begin = NowNs();
	for (unsigned i = 0; i < 2; ++i) workers.threads[i] = std::thread(WorkerMain, i);
	std::unique_lock lock(workers.mutex);
	workers.ready_cv.wait(lock, [] { return workers.ready == 2; });
	worker_startup_ns = NowNs() - begin;
	fprintf(stderr, "CCRF_WORKERS_READY cpu0=%d package0=%d core0=%d cpu1=%d package1=%d core1=%d\n",
		cpu0, package0, core0, cpu1, package1, core1);
}

void StopWorkers()
{
	if (!workers.threads[0].joinable()) return;
	{
		std::lock_guard lock(workers.mutex); workers.stop = true; ++workers.generation;
	}
	workers.start_cv.notify_all();
	for (auto &t : workers.threads) t.join();
}

struct WorkerShutdown { ~WorkerShutdown() { StopWorkers(); } } worker_shutdown;

[[noreturn]] void Fail(std::string const &why)
{
	fprintf(stderr, "CCRF_SEQUENTIAL_REJECT reason=%s\n", why.c_str());
	fflush(stderr);
	std::_Exit(2);
}

std::string Digest(void const *p, size_t n)
{
	unsigned char d[SHA256_DIGEST_LENGTH];
	SHA256(static_cast<unsigned char const *>(p), n, d);
	std::ostringstream s;
	for (unsigned char b : d)
		s << std::hex << std::setfill('0') << std::setw(2) << (unsigned)b;
	return s.str();
}

std::string FileDigest(char const *path)
{
	std::ifstream in(path, std::ios::binary);
	if (!in)
		Fail("ELF_OPEN_FAILED");
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	std::array<char, 65536> buf;
	while (in) {
		in.read(buf.data(), buf.size());
		if (in.gcount())
			SHA256_Update(&ctx, buf.data(), (size_t)in.gcount());
	}
	unsigned char d[SHA256_DIGEST_LENGTH];
	SHA256_Final(d, &ctx);
	std::ostringstream s;
	for (unsigned char b : d)
		s << std::hex << std::setfill('0') << std::setw(2) << (unsigned)b;
	return s.str();
}

ArchSnapshot Capture(CPUState const *s)
{
	ArchSnapshot a;
	a.gpr = s->gpr; a.ip = s->ip; a.trapno = s->trapno; a.vec = s->vec; a.csr = s->csr; a.fpu = s->fpu;
	return a;
}

void Restore(CPUState *s, ArchSnapshot const &a)
{
	s->gpr = a.gpr; s->ip = a.ip; s->trapno = a.trapno; s->vec = a.vec; s->csr = a.csr; s->fpu = a.fpu;
}

std::string ArchDigest(ArchSnapshot const &a)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, a.gpr.data(), sizeof(a.gpr));
	SHA256_Update(&ctx, &a.ip, sizeof(a.ip));
	SHA256_Update(&ctx, &a.trapno, sizeof(a.trapno));
	SHA256_Update(&ctx, a.vec.vreg.data(), sizeof(a.vec.vreg));
	SHA256_Update(&ctx, &a.vec.vl, sizeof(a.vec.vl));
	SHA256_Update(&ctx, &a.vec.vtype, sizeof(a.vec.vtype));
	SHA256_Update(&ctx, &a.vec.vstart, sizeof(a.vec.vstart));
	SHA256_Update(&ctx, &a.vec.vlenb, sizeof(a.vec.vlenb));
	SHA256_Update(&ctx, a.csr.data(), sizeof(a.csr));
	SHA256_Update(&ctx, a.fpu.f, sizeof(a.fpu.f));
	SHA256_Update(&ctx, &a.fpu.fcsr, sizeof(a.fpu.fcsr));
	unsigned char d[SHA256_DIGEST_LENGTH];
	SHA256_Final(d, &ctx);
	return Digest(d, sizeof(d));
}

void ValidatePages()
{
	for (auto const &r : memory_ranges) {
		for (u32 page = r.lo >> mmu::PAGE_BITS; page <= (r.hi >> mmu::PAGE_BITS); ++page) {
			mmu::PageInfo p;
			if (!mmu::QueryPage(page << mmu::PAGE_BITS, p) || !p.mapped || !(p.prot & PROT_WRITE) ||
			    !p.is_private || p.is_shared || p.backing == mmu::BackingType::None)
				Fail("LIVE_PAGE_FACT_MISMATCH");
		}
	}
}

void EmitResult(ArchSnapshot const &a)
{
	std::array<u32, 4> const vcfg{a.vec.vl, a.vec.vtype, a.vec.vstart, a.vec.vlenb};
	std::ofstream out(output_path, std::ios::trunc);
	if (!out)
		Fail("OUTPUT_OPEN_FAILED");
	char const *mode = concurrent_mode ? "concurrent" : precompiled_sequential_mode
		? "precompiled_sequential" : sequential_mode ? "sequential" : "ordinary";
	out << "{\n  \"kind\": \"RVDBT_CCRF_SEQUENTIAL_RESULT\",\n"
	    << "  \"mode\": \"" << mode << "\",\n"
	    << "  \"components_executed\": " << (sequential_mode ? certified_components : 0) << ",\n"
	    << "  \"worker_startup_ns\": " << worker_startup_ns << ",\n"
	    << "  \"materialization_ns\": " << materialization_ns << ",\n"
	    << "  \"steady_execution_ns\": " << execution_ns << ",\n"
	    << "  \"entry_epoch\": " << entry_epoch << ",\n  \"join_epoch\": " << mmu::MappingEpoch() << ",\n"
	    << "  \"final_pc\": " << a.ip << ",\n  \"architectural_sha256\": \"" << ArchDigest(a) << "\",\n"
	    << "  \"gpr_sha256\": \"" << Digest(a.gpr.data(), sizeof(a.gpr)) << "\",\n"
	    << "  \"vector_configuration_sha256\": \"" << Digest(vcfg.data(), sizeof(vcfg)) << "\",\n"
	    << "  \"vector_registers_sha256\": \"" << Digest(a.vec.vreg.data(), sizeof(a.vec.vreg)) << "\",\n"
	    << "  \"csr_sha256\": \"" << Digest(a.csr.data(), sizeof(a.csr)) << "\",\n"
	    << "  \"fpu_registers_sha256\": \"" << Digest(a.fpu.f, sizeof(a.fpu.f)) << "\",\n"
	    << "  \"fcsr\": " << a.fpu.fcsr << ",\n"
	    << "  \"memory\": [\n";
	for (size_t i = 0; i < memory_ranges.size(); ++i) {
		auto const &r = memory_ranges[i];
		out << "    {\"start\":" << r.lo << ",\"end\":" << r.hi << ",\"sha256\":\""
		    << Digest(mmu::g2h(r.lo), (size_t)r.hi - r.lo + 1) << "\"}"
		    << (i + 1 == memory_ranges.size() ? "\n" : ",\n");
	}
	out << "  ]\n}\n";
	out.close();
	if (!out)
		Fail("OUTPUT_WRITE_FAILED");
	completed = true;
	fprintf(stderr, "CCRF_SEQUENTIAL_EXECUTED components=%u final_pc=%08x epoch=%llu\n",
		sequential_mode ? certified_components : 0u, a.ip, (unsigned long long)mmu::MappingEpoch());
}

void MaterializeImages()
{
	if (certified_components != 2 || exact_ranges.empty()) Fail("TWO_COMPONENT_EXACT_QIR_REQUIRED");
	u64 const begin = NowNs();
	for (unsigned c = 0; c < 2; ++c) {
		component = c;
		image_runtime[c] = std::make_unique<ImageRuntime>();
		qir::CompilerJob::IpRangesSet ranges = exact_ranges;
		qir::CompilerJob job(image_runtime[c].get(), (uptr)mmu::base,
			qir::CodeSegment(scope_entry, scope_end - scope_entry), std::move(ranges));
		image_code[c] = qir::CompilerGetCode(job);
		if (image_code[c].empty()) Fail("EMPTY_COMPONENT_IMAGE");
		std::string const path = output_path + ".component" + std::to_string(c) + ".bin";
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		out.write(reinterpret_cast<char const *>(image_code[c].data()), (std::streamsize)image_code[c].size());
		if (!out) Fail("COMPONENT_IMAGE_WRITE_FAILED");
		fprintf(stderr, "CCRF_COMPONENT_IMAGE component=%u bytes=%zu path=%s\n",
			c, image_code[c].size(), path.c_str());
	}
	materialization_ns = NowNs() - begin;
}

void MaterializeComputeImages(ArchSnapshot const &entry)
{
	if (certified_components != 2 || compute_operations.empty())
		Fail("TWO_COMPONENT_COMPUTE_REGION_REQUIRED");
	u32 const iterations = entry.gpr[compute_counter_gpr];
	if (!iterations) Fail("ZERO_COMPUTE_ITERATIONS");
	static qir::StateReg state_regs[] = {{(u16)offsetof(CPUState, gpr), qir::VType::I32, "x0"}};
	static qir::StateInfo state_info{state_regs, 1};
	u64 const begin = NowNs();
	for (unsigned c = 0; c < 2; ++c) {
		MemArena arena(1u << 20);
		auto *region = arena.New<qir::Region>(&arena, &state_info);
		qir::Builder b(region->CreateBlock());
		b.Create_ccrfcompute(compute_operations.data(), (u32)compute_operations.size(), iterations,
				     (u8)c, expected_vlenb, compute_read_mask, compute_write_mask);
		image_runtime[c] = std::make_unique<ImageRuntime>();
		auto code = qcg::GenerateCode(image_runtime[c].get(), nullptr, region, 0);
		if (code.empty()) Fail("EMPTY_COMPUTE_COMPONENT_IMAGE");
		// The synthetic one-node region has no guest exit. Its HAS_CALLS frame saves rcx, so close
		// that ordinary QCG frame and return to the worker trampoline exactly as the focused T7m
		// executable differential does.
		code.data()[code.size()] = 0x59;
		code.data()[code.size() + 1] = 0xc3;
		image_code[c] = {code.data(), code.size() + 2};
		std::string const path = output_path + ".component" + std::to_string(c) + ".bin";
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		out.write(reinterpret_cast<char const *>(image_code[c].data()),
			  (std::streamsize)image_code[c].size());
		if (!out) Fail("COMPONENT_IMAGE_WRITE_FAILED");
		fprintf(stderr, "CCRF_COMPUTE_COMPONENT_IMAGE component=%u operations=%zu iterations=%u bytes=%zu path=%s\n",
			c, compute_operations.size(), iterations, image_code[c].size(), path.c_str());
	}
	materialization_ns += NowNs() - begin;
}

void MaterializeReadSnapshots()
{
	u64 const begin = NowNs();
	if (read_objects.empty()) Fail("CERTIFIED_READ_OBJECTS_REQUIRED");
	size_t const size = ((size_t)read_objects.back().hi + 4096) & ~size_t(4095);
	for (auto const &r : read_objects)
		for (u32 page = r.lo >> mmu::PAGE_BITS; page <= r.hi >> mmu::PAGE_BITS; ++page) {
			mmu::PageInfo p;
			if (!mmu::QueryPage(page << mmu::PAGE_BITS, p) || !p.mapped ||
			    !p.is_private || p.is_shared || p.backing == mmu::BackingType::None)
				Fail("READ_OBJECT_LIVE_PAGE_MISMATCH");
		}
	for (unsigned c = 0; c < 2; ++c) {
		read_snapshot[c] = std::make_unique<ReadSnapshot>();
		read_snapshot[c]->size = size;
		read_snapshot[c]->base = static_cast<u8 *>(::mmap(nullptr, size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
		if (read_snapshot[c]->base == MAP_FAILED) Fail("READ_SNAPSHOT_MMAP_FAILED");
		for (auto const &r : read_objects)
			memcpy(read_snapshot[c]->base + r.lo, mmu::g2h(r.lo), (size_t)r.hi - r.lo + 1);
	}
	materialization_ns += NowNs() - begin;
}

ArchSnapshot ExecutePrecompiled(ArchSnapshot const &entry)
{
	if (compute_mode)
		MaterializeComputeImages(entry);
	else {
		MaterializeImages();
		MaterializeReadSnapshots();
	}
	for (unsigned c = 0; c < 2; ++c) {
		worker_state[c] = std::make_unique<CPUState>(nullptr);
		Restore(worker_state[c].get(), entry);
		if (!compute_mode) worker_state[c]->ccrf_read_base = read_snapshot[c]->base;
	}
	u64 const begin = NowNs();
	if (concurrent_mode) {
		std::unique_lock lock(workers.mutex);
		workers.done = 0;
		for (unsigned c = 0; c < 2; ++c) {
			workers.states[c] = worker_state[c].get(); workers.code[c] = image_code[c].data();
		}
		++workers.generation; workers.start_cv.notify_all();
		workers.done_cv.wait(lock, [] { return workers.done == 2; });
	} else {
		for (unsigned c = 0; c < 2; ++c) {
			CPUState::SetCurrent(worker_state[c].get());
			jitabi::trampoline_to_jit(worker_state[c].get(), mmu::base, image_code[c].data());
		}
	}
	execution_ns = NowNs() - begin;
	for (unsigned c = 0; c < 2; ++c) component_state[c] = Capture(worker_state[c].get());
	if (mmu::MappingEpoch() != entry_epoch || (!compute_mode && mmu::MappingEpoch() != expected_epoch))
		Fail("JOIN_EPOCH_MISMATCH");
	if (!compute_mode) ValidatePages();
	for (unsigned c = 0; c < certified_components; ++c) {
		ValidatePrivateVectorEffects(c);
		if (c && !compute_mode) ValidateReplicated(component_state[0], component_state[c]);
	}
	ArchSnapshot joined = entry;
	if (!compute_mode) {
		joined.gpr = component_state[0].gpr; joined.csr = component_state[0].csr;
		joined.fpu = component_state[0].fpu; joined.trapno = component_state[0].trapno;
		joined.vec.vl = component_state[0].vec.vl; joined.vec.vtype = component_state[0].vec.vtype;
		joined.vec.vstart = component_state[0].vec.vstart; joined.vec.vlenb = component_state[0].vec.vlenb;
	} else {
		joined.gpr[compute_counter_gpr] = 0;
	}
	for (auto const &p : vector_publications) {
		auto const &src = component_state[p.owner].vec.vreg[p.reg];
		auto &dst = joined.vec.vreg[p.reg];
		memcpy(dst.data() + p.lo, src.data() + p.lo, (size_t)p.hi - p.lo + 1);
	}
	joined.ip = final_pc;
	return joined;
}

void ValidateReplicated(ArchSnapshot const &a, ArchSnapshot const &b)
{
	if (a.gpr != b.gpr || a.trapno != b.trapno || a.ip != b.ip || a.vec.vl != b.vec.vl ||
	    a.vec.vtype != b.vec.vtype || a.vec.vstart != b.vec.vstart || a.vec.vlenb != b.vec.vlenb ||
	    a.csr != b.csr || memcmp(a.fpu.f, b.fpu.f, sizeof(a.fpu.f)) || a.fpu.fcsr != b.fpu.fcsr)
		Fail("COMPONENT_STATE_MISMATCH");
}

void ValidatePrivateVectorEffects(unsigned owner)
{
	for (u32 reg = 0; reg < rv32::VREG_NUM; ++reg) {
		for (u32 byte = 0; byte < rv32::VLEN_MAX_BYTES; ++byte) {
			bool owned = false;
			for (auto const &p : vector_publications)
				owned |= p.owner == owner && p.reg == reg && byte >= p.lo && byte <= p.hi;
			if (!owned && component_state[owner].vec.vreg[reg][byte] != entry_state.vec.vreg[reg][byte])
				Fail("UNOWNED_VECTOR_EFFECT");
		}
	}
}
} // namespace

ComponentLowering SelectComponentLowering(bool host_avx512f, bool require_avx512)
{
	if (host_avx512f)
		return ComponentLowering::AVX512ZMM;
	return require_avx512 ? ComponentLowering::Unavailable : ComponentLowering::FunctionalXMM;
}

void Configure(char const *join_path, char const *affine_path, char const *elf_path,
	       char const *qir_path, char const *out_path, bool sequential, bool concurrent,
	       bool precompiled_sequential, bool require_avx512, int worker_cpu0, int worker_cpu1)
{
	if ((unsigned)sequential + (unsigned)concurrent + (unsigned)precompiled_sequential > 1)
		Fail("MULTIPLE_EXECUTION_MODES");
	bool const materialized = sequential || concurrent || precompiled_sequential;
	if (!join_path || !*join_path) {
		if ((affine_path && *affine_path) || (out_path && *out_path) || materialized)
			Fail("CERTIFICATE_REQUIRED");
		return;
	}
	if (!elf_path || !*elf_path || !out_path || !*out_path)
		Fail("INCOMPLETE_CONFIGURATION");
	if (materialized) {
#if defined(__x86_64__) || defined(__i386__)
		bool const host_avx512f = __builtin_cpu_supports("avx512f");
#else
		bool const host_avx512f = false;
#endif
		component_lowering = SelectComponentLowering(host_avx512f, require_avx512);
		if (component_lowering == ComponentLowering::Unavailable)
			Fail("AVX512_REQUIRED_HOST_FEATURE_MISSING");
		fprintf(stderr, "CCRF_COMPONENT_LOWERING_SELECTED mode=%s host_avx512f=%u required=%u\n",
			component_lowering == ComponentLowering::AVX512ZMM ? "AVX512_ZMM" :
			"FUNCTIONAL_XMM_FALLBACK_NONPERFORMANCE",
			(unsigned)host_avx512f, (unsigned)require_avx512);
	}
	ptree join, affine;
	try {
		boost::property_tree::read_json(join_path, join);
	} catch (std::exception const &) {
		Fail("MALFORMED_CERTIFICATE");
	}
	std::string const certificate_kind = join.get<std::string>("kind", "");
	if (FileDigest(elf_path) != join.get<std::string>("identity.elf_sha256", ""))
		Fail("ELF_IDENTITY_MISMATCH");
	if (certificate_kind == "T7P_COMPUTE_REGION_CERTIFICATE") {
		if (join.get<u32>("schema_version", 0) != 1 ||
		    join.get<std::string>("status", "") != "CERTIFIED_INDEPENDENT_SIBLING_STREAMS")
			Fail("UNACCEPTED_COMPUTE_CERTIFICATE");
		if (!qir_path || !*qir_path) Fail("EXACT_QIR_REQUIRED");
		if (FileDigest(qir_path) != join.get<std::string>("identity.exact_qir_sha256", ""))
			Fail("EXACT_QIR_IDENTITY_MISMATCH");
		if (config::vlen_bits != 512 && config::vlen_bits != 1024)
			Fail("UNSUPPORTED_COMPUTE_VLEN");
		expected_vlen = config::vlen_bits; expected_vlenb = expected_vlen / 8;
		certified_components = expected_vlen / 512;
		if (materialized && certified_components != 2)
			Fail("TWO_COMPONENT_COMPUTE_REGION_REQUIRED");
		scope_entry = join.get<u32>("scope.entry");
		exit_instruction = join.get<u32>("scope.latch");
		final_pc = join.get<u32>("scope.final_pc"); scope_end = join.get<u32>("scope.loop_exit");
		compute_counter_gpr = (u8)join.get<u32>("loop.counter_gpr");
		compute_workset_elements = join.get<u32>("work.fixed_elements");
		compute_sew_bits = join.get<u32>("work.sew_bits");
		if (scope_entry >= exit_instruction || scope_end != exit_instruction + 4 ||
		    (final_pc & 3) || final_pc == scope_entry ||
		    compute_counter_gpr == 0 || compute_counter_gpr >= 32 ||
		    !compute_workset_elements || compute_sew_bits != 32)
			Fail("MALFORMED_COMPUTE_SCOPE");
		u32 expected_pc = scope_entry;
		for (auto const &node : join.get_child("operations")) {
			auto const &op = node.second;
			u32 const pc = op.get<u32>("pc"), raw = op.get<u32>("raw");
			if (pc != expected_pc || (raw & 0x7fu) != 0x57u || ((raw >> 12) & 7u) != 0u ||
			    ((raw >> 26) & 0x3fu) != 0u || ((raw >> 25) & 1u) != 1u)
				Fail("UNSUPPORTED_COMPUTE_OPERATION");
			u32 const vd = (raw >> 7) & 31u, vs1 = (raw >> 15) & 31u, vs2 = (raw >> 20) & 31u;
			compute_read_mask |= (u32(1) << vs1) | (u32(1) << vs2);
			compute_write_mask |= u32(1) << vd;
			compute_operations.push_back(raw); expected_pc += 4;
		}
		if (compute_operations.empty() || expected_pc + 8 != scope_end ||
		    compute_read_mask != join.get<u32>("vector_state.read_mask") ||
		    compute_write_mask != join.get<u32>("vector_state.write_mask"))
			Fail("MALFORMED_COMPUTE_STREAM");
		u32 const elements_per_invocation = expected_vlen / compute_sew_bits;
		if (compute_workset_elements % elements_per_invocation)
			Fail("NONINTEGRAL_COMPUTE_INVOCATIONS");
		compute_expected_invocations = compute_workset_elements / elements_per_invocation;
		for (u32 reg = 0; reg < 32; ++reg)
			if (compute_write_mask & (u32(1) << reg))
				for (unsigned c = 0; c < certified_components; ++c)
					vector_publications.push_back({(u8)reg, (u16)(c * 64), (u16)(c * 64 + 63), c});
		output_path = out_path; exact_qir_path = qir_path; compute_mode = true;
		sequential_mode = materialized; concurrent_mode = concurrent;
		precompiled_sequential_mode = precompiled_sequential; enabled = true;
		if (concurrent) StartWorkers(worker_cpu0, worker_cpu1);
		fprintf(stderr, "CCRF_COMPUTE_CERTIFIED components=%u operations=%zu invocations=%u counter_gpr=%u\n",
			certified_components, compute_operations.size(), compute_expected_invocations,
			(unsigned)compute_counter_gpr);
		return;
	}
	if (certificate_kind != "T7L_FIX7_EXACT_JOIN_CERTIFICATE")
		Fail("UNACCEPTED_CERTIFICATE");
	if (!affine_path || !*affine_path) Fail("AFFINE_FACTS_REQUIRED");
	try {
		boost::property_tree::read_json(affine_path, affine);
	} catch (std::exception const &) {
		Fail("MALFORMED_AFFINE_FACTS");
	}
	if (FileDigest(affine_path) != join.get<std::string>("identity.affine_sha256", ""))
		Fail("AFFINE_IDENTITY_MISMATCH");
	if ((concurrent || precompiled_sequential)) {
		if (!qir_path || !*qir_path) Fail("EXACT_QIR_REQUIRED");
		if (FileDigest(qir_path) != join.get<std::string>("identity.exact_qir_sha256", ""))
			Fail("EXACT_QIR_IDENTITY_MISMATCH");
		exact_qir_path = qir_path;
		std::ifstream qin(qir_path); std::string line;
		if (!std::getline(qin, line) || line.rfind("; exact-qir-region ", 0)) Fail("MALFORMED_EXACT_QIR");
		auto pos = line.find("ranges:");
		if (pos == std::string::npos) Fail("MALFORMED_EXACT_QIR");
		std::istringstream ranges(line.substr(pos + 7)); std::string tok;
		while (ranges >> tok) {
			auto dash = tok.find('-');
			if (dash == std::string::npos) Fail("MALFORMED_EXACT_QIR_RANGE");
			u32 lo = (u32)std::stoul(tok.substr(0, dash), nullptr, 16);
			u32 hi = (u32)std::stoul(tok.substr(dash + 1), nullptr, 16);
			if (lo >= hi || (lo & 3) || (hi & 3)) Fail("MALFORMED_EXACT_QIR_RANGE");
			exact_ranges.push_back({lo, hi});
		}
	}
	std::string const status = join.get<std::string>("status", "");
	if (status == "NOT_APPLICABLE") {
		if (config::vlen_bits != 512 || join.get<u32>("runtime_shape.vlen", 0) != 512 ||
		    join.get<u32>("runtime_shape.vlenb", 0) != 64 ||
		    join.get<u32>("runtime_shape.chunks", 0) != 1 ||
		    join.get<u32>("not_applicable_analysis.components", 0) != 1 ||
		    !join.get<bool>("not_applicable_analysis.boundary_outputs_enumerated", false) ||
		    join.get<std::string>("not_applicable_analysis.reason", "") != "ONE_VECTOR_COMPONENT")
			Fail("INVALID_NOT_APPLICABLE_PROOF");
		std::ofstream out(out_path, std::ios::trunc);
		if (!out) Fail("OUTPUT_OPEN_FAILED");
		out << "{\n  \"kind\": \"RVDBT_CCRF_SEQUENTIAL_RESULT\",\n"
		    << "  \"status\": \"NOT_APPLICABLE\",\n  \"components\": 1,\n"
		    << "  \"reason\": \"ONE_VECTOR_COMPONENT\"\n}\n";
		out.close();
		if (!out) Fail("OUTPUT_WRITE_FAILED");
		fprintf(stderr, "CCRF_SEQUENTIAL_NOT_APPLICABLE components=1 vlen=512\n");
		return;
	}
	if (status != "EXACT_JOIN_SUBITEM_PASS") Fail("UNACCEPTED_CERTIFICATE");
	scope_entry = join.get<u32>("scope.entry"); scope_end = join.get<u32>("scope.end");
	exit_instruction = join.get<u32>("join_plan.final_pc.exit_instruction");
	final_pc = join.get<u32>("join_plan.final_pc.value");
	expected_vlen = join.get<u32>("runtime_shape.vlen"); expected_vlenb = join.get<u32>("runtime_shape.vlenb");
	expected_epoch = join.get<u64>("join_plan.join_epoch_guard.expected_epoch");
	if (scope_entry >= scope_end || exit_instruction < scope_entry || exit_instruction >= scope_end ||
	    expected_vlen <= 512 || expected_vlenb != expected_vlen / 8)
		Fail("MISMATCHED_SCOPE_OR_SHAPE");
	if (concurrent || precompiled_sequential) {
		if (exact_ranges.empty() || exact_ranges.front().first != scope_entry)
			Fail("EXACT_QIR_SCOPE_MISMATCH");
		for (auto const &r : exact_ranges)
			if (r.first < scope_entry || r.second > scope_end) Fail("EXACT_QIR_SCOPE_MISMATCH");
	}
	unsigned component_count = 0;
	for (auto const &node : join.get_child("join_plan.components")) {
		auto const &c = node.second;
		if (c.get<std::string>("id") != "chunk_" + std::to_string(component_count) ||
		    c.get<u32>("byte_start") != component_count * 64 || c.get<u32>("byte_end") != component_count * 64 + 63)
			Fail("MALFORMED_COMPONENT_PLAN");
		++component_count;
	}
	if (component_count != expected_vlen / 512 || component_count < 2 || component_count > kMaxComponents)
		Fail("COMPONENT_COUNT_MISMATCH");
	certified_components = component_count;
	std::map<u8, std::vector<bool>> vector_coverage;
	for (auto const &node : join.get_child("join_plan.vector_publications")) {
		auto const &v = node.second;
		std::string owner = v.get<std::string>("owner");
		unsigned own = kMaxComponents;
		if (owner.rfind("chunk_", 0) == 0) own = (unsigned)std::stoul(owner.substr(6));
		std::string reg = v.get<std::string>("register");
		if (own >= certified_components || reg.size() < 2 || reg[0] != 'v')
			Fail("MALFORMED_VECTOR_PUBLICATION");
		u8 const r = (u8)std::stoul(reg.substr(1));
		u32 const lo = v.get<u32>("byte_start"), hi = v.get<u32>("byte_end");
		if (r >= rv32::VREG_NUM || lo != own * 64 || hi != lo + 63)
			Fail("MALFORMED_VECTOR_PUBLICATION");
		auto &coverage = vector_coverage[r];
		if (coverage.empty()) coverage.resize(certified_components);
		if (coverage[own]) Fail("DUPLICATE_VECTOR_PUBLICATION");
		coverage[own] = true;
		vector_publications.push_back({r, (u16)lo, (u16)hi, own});
	}
	if (vector_coverage.empty()) Fail("MISSING_VECTOR_PUBLICATION");
	for (auto const &[reg, coverage] : vector_coverage)
		if (std::find(coverage.begin(), coverage.end(), false) != coverage.end())
			Fail("MISSING_VECTOR_PUBLICATION");
	std::set<std::string> tail_events;
	for (auto const &node : join.get_child("join_plan.memory_publications")) {
		auto const &m = node.second;
		if (m.get<std::string>("mode") != "direct_private_prevalidated_disjoint_fault_free")
			Fail("NON_DIRECT_MEMORY_PLAN_UNSUPPORTED");
		auto interval = m.get_child("absolute_interval");
		auto it = interval.begin(); u32 lo = it++->second.get_value<u32>(); u32 hi = it->second.get_value<u32>();
		memory_ranges.push_back({lo, hi});
		if (m.get<std::string>("owner") == "scalar_remainder")
			tail_events.insert(m.get<std::string>("event"));
	}
	for (auto const &node : affine.get_child("memory_events")) {
		auto const &m = node.second;
		if (tail_events.erase(m.get<std::string>("id", ""))) {
			scalar_stores.insert(m.get<u32>("pc"));
		}
	}
	if (!tail_events.empty() || scalar_stores.empty())
		Fail("AFFINE_TAIL_BINDING_MISSING");
	for (auto const &node : affine.get_child("objects")) {
		auto const &o = node.second;
		u32 const lo = o.get<u32>("base"), end = o.get<u32>("end");
		if (!o.get<bool>("ordinary_rw", false) || !o.get<bool>("private", false) ||
		    lo >= end || o.get<u32>("alignment", 0) < 64)
			Fail("UNSUPPORTED_READ_OBJECT");
		read_objects.push_back({lo, end - 1});
	}
	std::sort(read_objects.begin(), read_objects.end(), [](auto a, auto b) { return a.lo < b.lo; });
	for (size_t i = 1; i < read_objects.size(); ++i)
		if (read_objects[i].lo <= read_objects[i - 1].hi) Fail("OVERLAPPING_READ_OBJECTS");
	std::sort(memory_ranges.begin(), memory_ranges.end(), [](auto a, auto b) { return a.lo < b.lo || (a.lo == b.lo && a.hi < b.hi); });
	std::vector<Range> merged;
	for (auto r : memory_ranges) {
		if (!merged.empty() && r.lo <= merged.back().hi + 1)
			merged.back().hi = std::max(merged.back().hi, r.hi);
		else
			merged.push_back(r);
	}
	memory_ranges = std::move(merged);
	if (!mmu::EnableDetailedMetadata())
		Fail("MAPPING_METADATA_ENABLE_FAILED");
	output_path = out_path; sequential_mode = materialized; concurrent_mode = concurrent;
	precompiled_sequential_mode = precompiled_sequential; enabled = true;
	if (concurrent) StartWorkers(worker_cpu0, worker_cpu1);
}

bool Enabled() { return enabled; }
bool Sequential() { return sequential_mode; }
ComponentLowering Lowering() { return component_lowering; }
bool InScope(u32 pc) { return enabled && pc >= scope_entry && pc < scope_end; }
bool IsScopeEntry(u32 pc) { return enabled && pc == scope_entry; }
bool IsExitInstruction(u32 pc) { return enabled && pc == exit_instruction; }
bool IsScalarRemainderStore(u32 pc) { return enabled && scalar_stores.count(pc); }
unsigned Component() { return component; }

void RejectUnsupported(u32 pc, u32 raw)
{
	std::ostringstream s; s << "UNSUPPORTED_DECODED_OPERATION_pc_" << std::hex << pc << "_raw_" << raw;
	Fail(s.str());
}

bool ObserveBoundary(CPUState *state)
{
	if (!enabled || completed)
		return false;
	if ((!started || compute_mode) && state->ip == scope_entry) {
		if (compute_mode && started) Fail("COMPUTE_REGION_REENTRY_BEFORE_EXIT");
		if (config::vlen_bits != expected_vlen || state->vec.vlenb != expected_vlenb || state->vec.vstart != 0)
			Fail("RUNTIME_SHAPE_MISMATCH");
		if (sequential_mode) {
			bool const routes = compute_mode
				? config::rvv_direct && config::rvv_qcg_typed_chunk &&
				  config::rvv_qcg_typed_chunk_vle && config::rvv_qcg_typed_chunk_vse &&
				  config::rvv_qcg_direct_setvl && !config::aot_use_llvm
				: config::rvv_direct && config::rvv_qcg_whole_reg &&
				  config::rvv_qcg_vx_mulacc && config::rvv_qcg_direct_setvl && !config::aot_use_llvm;
			if (!routes) Fail("DIRECT_QCG_ROUTE_REQUIRED");
		}
		entry_epoch = mmu::MappingEpoch();
		if (!compute_mode && entry_epoch != expected_epoch)
			Fail("ENTRY_EPOCH_MISMATCH");
		if (!compute_mode) ValidatePages();
		if (sequential_mode) state->ccrf_read_base = mmu::base;
		entry_state = Capture(state); component = 0; started = true;
		if (!sequential_mode) execution_begin_ns = NowNs();
		if (concurrent_mode || precompiled_sequential_mode) {
			fprintf(stderr, "CCRF_REGION_DISPATCH mode=%s components=2 pc=%08x\n",
				concurrent_mode ? "concurrent" : "precompiled_sequential", state->ip);
			auto joined = ExecutePrecompiled(entry_state);
			CPUState::SetCurrent(state);
			Restore(state, joined);
			if (compute_mode) {
				++compute_completed_invocations; started = false;
				if (compute_completed_invocations == compute_expected_invocations) EmitResult(joined);
				else if (compute_completed_invocations > compute_expected_invocations)
					Fail("TOO_MANY_COMPUTE_INVOCATIONS");
			} else {
				EmitResult(joined);
			}
			fprintf(stderr, "CCRF_REGION_JOIN mode=%s synchronizations=1\n",
				concurrent_mode ? "concurrent" : "precompiled_sequential");
			return true;
		}
		if (sequential_mode)
			fprintf(stderr, "CCRF_COMPONENT_BEGIN component=0 pc=%08x\n", state->ip);
		return false;
	}
	if (!started || state->ip != final_pc)
		return false;
	if (!sequential_mode) {
		if ((!compute_mode && mmu::MappingEpoch() != expected_epoch) ||
		    (compute_mode && mmu::MappingEpoch() != entry_epoch)) Fail("JOIN_EPOCH_MISMATCH");
		execution_ns += NowNs() - execution_begin_ns;
		auto out = Capture(state);
		if (compute_mode) {
			if (out.gpr[compute_counter_gpr] != 0) Fail("COMPUTE_COUNTER_NOT_TERMINAL");
			++compute_completed_invocations; started = false;
			if (compute_completed_invocations == compute_expected_invocations) EmitResult(out);
			else if (compute_completed_invocations > compute_expected_invocations)
				Fail("TOO_MANY_COMPUTE_INVOCATIONS");
		} else {
			EmitResult(out);
		}
		return false;
	}
	component_state[component] = Capture(state);
	fprintf(stderr, "CCRF_COMPONENT_COMPLETE component=%u pc=%08x\n", component, state->ip);
	if (component + 1 < certified_components) {
		if (mmu::MappingEpoch() != entry_epoch) Fail("COMPONENT_EPOCH_MISMATCH");
		Restore(state, entry_state); state->ip = scope_entry; ++component;
		fprintf(stderr, "CCRF_COMPONENT_BEGIN component=%u pc=%08x\n", component, state->ip);
		// Every stale chunk-0 translation, region body, and inbound direct link is discarded before
		// chunk 1 is compiled. The ordinary cache reset changes compilation only; architectural and
		// mapped guest state remain the captured entry state plus certified direct publications.
		tcache::Invalidate();
		return true;
	}
	if (mmu::MappingEpoch() != entry_epoch || mmu::MappingEpoch() != expected_epoch)
		Fail("JOIN_EPOCH_MISMATCH");
	ValidatePages();
	for (unsigned c = 0; c < certified_components; ++c) {
		ValidatePrivateVectorEffects(c);
		if (!c) continue;
		ValidateReplicated(component_state[0], component_state[c]);
	}
	ArchSnapshot joined = entry_state;
	joined.gpr = component_state[0].gpr; joined.csr = component_state[0].csr;
	joined.fpu = component_state[0].fpu; joined.trapno = component_state[0].trapno;
	joined.vec.vl = component_state[0].vec.vl; joined.vec.vtype = component_state[0].vec.vtype;
	joined.vec.vstart = component_state[0].vec.vstart; joined.vec.vlenb = component_state[0].vec.vlenb;
	for (auto const &p : vector_publications) {
		auto const &src = component_state[p.owner].vec.vreg[p.reg];
		auto &dst = joined.vec.vreg[p.reg];
		memcpy(dst.data() + p.lo, src.data() + p.lo, (size_t)p.hi - p.lo + 1);
	}
	joined.ip = final_pc; Restore(state, joined); EmitResult(joined); return false;
}
} // namespace dbt::ccrf
