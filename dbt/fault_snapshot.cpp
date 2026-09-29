#include "dbt/fault_snapshot.h"

#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/mmu.h"

#include <openssl/sha.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace dbt::fault_snapshot
{
namespace
{
struct Query {
	bool sp_relative{};
	i64 lo{};
	i64 hi{};
	std::string access;
};

bool enabled{};
bool captured{};
u32 entry_pc{};
std::string output;
std::vector<Query> queries;

[[noreturn]] void BadPlan(std::string const &why)
{
	fprintf(stderr, "fault snapshot plan: %s\n", why.c_str());
	std::exit(2);
}

u64 ParseNumber(std::string const &s)
{
	char *end = nullptr;
	errno = 0;
	u64 v = strtoull(s.c_str(), &end, 0);
	if (errno || !end || *end)
		BadPlan("invalid integer '" + s + "'");
	return v;
}

i64 ParseSigned(std::string const &s)
{
	char *end = nullptr;
	errno = 0;
	i64 v = strtoll(s.c_str(), &end, 0);
	if (errno || !end || *end)
		BadPlan("invalid signed integer '" + s + "'");
	return v;
}

std::string Digest(u8 const *p, size_t n)
{
	unsigned char d[SHA256_DIGEST_LENGTH];
	SHA256(p, n, d);
	std::ostringstream s;
	for (unsigned char b : d)
		s << std::hex << std::setfill('0') << std::setw(2) << (unsigned)b;
	return s.str();
}

char const *BackingName(mmu::BackingType t)
{
	switch (t) {
	case mmu::BackingType::Anonymous: return "anonymous";
	case mmu::BackingType::File: return "file";
	default: return "none";
	}
}

std::string Permissions(int prot)
{
	std::string s;
	if (prot & PROT_READ) s += 'r';
	if (prot & PROT_WRITE) s += 'w';
	if (prot & PROT_EXEC) s += 'x';
	return s;
}
} // namespace

void Configure(char const *plan_path, char const *output_path)
{
	if (!plan_path || !*plan_path) {
		if (output_path && *output_path)
			BadPlan("output requires a plan");
		return;
	}
	if (!output_path || !*output_path)
		BadPlan("plan requires an output");
	std::ifstream in(plan_path);
	if (!in)
		BadPlan("cannot open plan");
	std::string line;
	if (!std::getline(in, line) || line != "RVDBT_FAULT_OBSERVATION_PLAN_V1")
		BadPlan("wrong header");
	bool have_entry = false;
	while (std::getline(in, line)) {
		if (line.empty() || line[0] == '#')
			continue;
		std::istringstream row(line);
		std::string kind, a, b, access, extra;
		row >> kind;
		if (kind == "entry") {
			if (!(row >> a) || (row >> extra) || have_entry)
				BadPlan("malformed entry row");
			u64 v = ParseNumber(a);
			if (v >= mmu::ASPACE_SIZE || (v & 3))
				BadPlan("entry outside aligned RV32 address space");
			entry_pc = (u32)v;
			have_entry = true;
		} else if (kind == "range" || kind == "sp-range") {
			if (!(row >> a >> b >> access) || (row >> extra) || access.find_first_not_of("rwx") != std::string::npos || access.empty())
				BadPlan("malformed range row");
			Query q;
			q.sp_relative = kind == "sp-range";
			q.lo = q.sp_relative ? ParseSigned(a) : (i64)ParseNumber(a);
			q.hi = q.sp_relative ? ParseSigned(b) : (i64)ParseNumber(b);
			q.access = access;
			if (q.hi < q.lo)
				BadPlan("empty range");
			queries.push_back(q);
		} else {
			BadPlan("unknown row '" + kind + "'");
		}
	}
	if (!have_entry || queries.empty())
		BadPlan("entry and at least one range are required");
	// SetupConfig calls Configure before elfrun calls mmu::Init and creates any guest mapping.
	// The MMU enforces that ordering as well: late enablement fails rather than fabricating facts.
	if (!mmu::EnableDetailedMetadata())
		BadPlan("detailed mapping metadata must be enabled before mmu initialization");
	output = output_path;
	enabled = true;
}

bool Enabled()
{
	return enabled;
}

void ObserveEntry(CPUState const *state)
{
	if (!enabled || captured || state->ip != entry_pc)
		return;
	captured = true;
	u64 const epoch = mmu::MappingEpoch();
	std::ofstream out(output, std::ios::trunc);
	if (!out)
		BadPlan("cannot create output");
	out << "{\n  \"kind\": \"RVDBT_RUNTIME_FAULT_SNAPSHOT\",\n  \"schema_version\": 2,\n";
	out << "  \"observed_entry_pc\": " << state->ip << ",\n";
	out << "  \"entry_gprs\": {\"x2\": " << state->gpr[2] << "},\n";
	out << "  \"vector_state\": {\"vstart\": " << state->vec.vstart << ", \"vlen_bits\": "
	    << config::vlen_bits << ", \"vlenb\": " << state->vec.vlenb << ", \"vl\": "
	    << state->vec.vl << ", \"vtype\": " << state->vec.vtype << "},\n";
	out << "  \"mapping_epoch\": " << epoch << ",\n  \"queries\": [\n";
	for (size_t i = 0; i < queries.size(); ++i) {
		auto const &q = queries[i];
		i64 const base = q.sp_relative ? state->gpr[2] : 0;
		i64 const lo64 = base + q.lo, hi64 = base + q.hi;
		if (lo64 < 0 || hi64 < lo64 || hi64 >= (i64)mmu::ASPACE_SIZE)
			BadPlan("resolved range outside RV32 address space");
		u32 const lo = (u32)lo64, hi = (u32)hi64;
		std::vector<mmu::PageInfo> page_info;
		bool readable = true;
		for (u32 p = lo >> mmu::PAGE_BITS; p <= (hi >> mmu::PAGE_BITS); ++p) {
			mmu::PageInfo info;
			if (!mmu::QueryPage(p << mmu::PAGE_BITS, info))
				BadPlan("detailed mapping metadata unavailable");
			page_info.push_back(info);
			readable = readable && page_info.back().mapped && (page_info.back().prot & PROT_READ);
		}
		out << "    {\"addressing\": \"" << (q.sp_relative ? "entry_sp_relative" : "absolute")
		    << "\", \"requested_start\": " << q.lo << ", \"requested_end\": " << q.hi
		    << ", \"resolved_start\": " << lo << ", \"resolved_end\": " << hi
		    << ", \"access\": \"" << q.access << "\", \"live_sha256\": ";
		if (readable)
			out << "\"" << Digest((u8 const *)mmu::g2h(lo), (size_t)hi - lo + 1) << "\"";
		else
			out << "null";
		out << ", \"pages\": [";
		size_t page_index = 0;
		for (u32 p = lo >> mmu::PAGE_BITS; p <= (hi >> mmu::PAGE_BITS); ++p) {
			auto const &info = page_info[page_index++];
			if (p != (lo >> mmu::PAGE_BITS)) out << ',';
			out << "{\"page\":" << p << ",\"mapped\":" << (info.mapped ? "true" : "false")
			    << ",\"permissions\":\"" << Permissions(info.prot) << "\",\"private\":"
			    << (info.is_private ? "true" : "false") << ",\"shared\":"
			    << (info.is_shared ? "true" : "false") << ",\"backing_type\":\""
			    << BackingName(info.backing) << "\"}";
		}
		out << "]}" << (i + 1 == queries.size() ? "\n" : ",\n");
	}
	out << "  ],\n  \"mapping_epoch_after_queries\": " << mmu::MappingEpoch() << "\n}\n";
	out.close();
	if (!out)
		BadPlan("failed writing output");
	fprintf(stderr, "RVDBT_FAULT_SNAPSHOT_CAPTURED pc=%08x epoch=%llu\n", state->ip,
		(unsigned long long)epoch);
}
} // namespace dbt::fault_snapshot
