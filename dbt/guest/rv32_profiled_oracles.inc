// Family-A oracle stable-load substitution map (PC -> profiled constant value). Default-empty.
static std::unordered_map<u32, u32> g_stable_loads;
void add_stable_load(u32 pc, u32 val) { g_stable_loads[pc] = val; }
bool lookup_stable_load(u32 pc, u32 &val)
{
	auto it = g_stable_loads.find(pc);
	if (it == g_stable_loads.end())
		return false;
	val = it->second;
	return true;
}

// C2 ceiling oracle (2026-07-25, OBSERVATION_BOTTOMUP_COST_DECOMPOSITION.md correction):
// --subst-stable-loads alone only changes the LOAD's own codegen (a vmload becomes a mov
// immediate) -- gprop() has no constant-propagation, so the jalr that consumes the loaded
// register still lowers via the unmodified Create_gbrind, paying the full generic dispatch
// resolution regardless of the load's value being known. This is a SEPARATE substitution map,
// keyed by the JALR's OWN pc, that lets the jalr TRANSLATOR itself skip Create_gbrind entirely
// and emit the SAME MakeGBr(...) a genuinely-direct jal already uses -- i.e. the true measurement
// ceiling for "this dispatch resolved with zero runtime resolution cost at all", not merely "the
// load that fed it was free". Measurement-only: no guard, unconditional substitution, correct
// ONLY on the exact profiled input by construction (same discipline as g_stable_loads above) --
// never enabled without dbt::config::subst_stable_jalr, default off.
static std::unordered_map<u32, u32> g_stable_jalr_targets;
void add_stable_jalr_target(u32 pc, u32 target) { g_stable_jalr_targets[pc] = target; }
bool lookup_stable_jalr_target(u32 pc, u32 &target)
{
	auto it = g_stable_jalr_targets.find(pc);
	if (it == g_stable_jalr_targets.end())
		return false;
	target = it->second;
	return true;
}

// A-line round 22 Gate 1 Row 4 (oracle-only, default-off): loads (source,target,count) edges
// keyed by source bb_ip, attached to InstGBrind::known_targets at the STOCK lowering call site
// only (rv32_qir.cpp's TRANSLATOR(jalr) final Create_gbrind) -- not the guard-mechanism paths,
// which are testing different rows. Static, process-lifetime storage (matches the pointer-
// stability contract InstGBrind::known_targets documents).
// A-line round 23 Gate 1 Row 5: extended to also retain the per-edge dynamic count (previously
// parsed and discarded) -- real --shadow-edges2-out evidence is "%x %x %u\n" (source,target,
// hit_count), the same file format Row 4 already consumes. targets/counts are parallel vectors
// (same index = same edge), stored in the same static, process-lifetime map as before.
static std::unordered_map<u32, std::pair<std::vector<u32>, std::vector<u32>>> const &LoadKnownTargetsOracle()
{
	static std::unordered_map<u32, std::pair<std::vector<u32>, std::vector<u32>>> m = [] {
		std::unordered_map<u32, std::pair<std::vector<u32>, std::vector<u32>>> out;
		if (dbt::config::aot_qir_known_targets_file) {
			std::ifstream f(dbt::config::aot_qir_known_targets_file);
			std::string line;
			while (std::getline(f, line)) {
				if (line.empty())
					continue;
				std::istringstream ls(line);
				unsigned long s, t, c = 1;
				ls >> std::hex >> s >> t;
				ls >> std::dec >> c;
				auto &e = out[(u32)s];
				e.first.push_back((u32)t);
				e.second.push_back((u32)c);
			}
		}
		return out;
	}();
	return m;
}

// A-line round 28 Gate 1 (oracle-only, default off): loads a .trans file (src prev target count,
// produced by --brind-edges-out --sr-record-returns=1, verified EXHAUSTIVE not sampled -- see
// dbt/qmc/qcg/jitabi.cpp's profile_brind_edges path) and reduces it to, per source, the parallel
// (prev, argmax_target) arrays InstGBrind::order1_prev/order1_target need. Also assigns each
// eligible source a unique, compile-time-stable tcache::gbrind_ctx1_slots index (bounded by that
// array's size -- sources beyond the bound get an empty entry here, i.e. no oracle, safe
// fallback). Static, process-lifetime storage, same pointer-stability contract as
// LoadKnownTargetsOracle.
struct Order1SiteData {
	std::vector<u32> prev, target;
	u32 slot;
};
static std::unordered_map<u32, Order1SiteData> const &LoadOrder1Oracle()
{
	static std::unordered_map<u32, Order1SiteData> m = [] {
		std::unordered_map<u32, Order1SiteData> out;
		if (dbt::config::aot_order1_context_file) {
			// src -> prev -> target -> count, so we can take the argmax target per (src,prev).
			std::unordered_map<u32, std::unordered_map<u32, std::unordered_map<u32, unsigned long long>>> raw;
			std::ifstream f(dbt::config::aot_order1_context_file);
			std::string line;
			while (std::getline(f, line)) {
				if (line.empty())
					continue;
				std::istringstream ls(line);
				unsigned long s, p, t;
				unsigned long long c = 1;
				ls >> std::hex >> s >> p >> t;
				ls >> std::dec >> c;
				raw[(u32)s][(u32)p][(u32)t] += c;
			}
			for (auto const &[src, prevmap] : raw) {
				Order1SiteData d;
				for (auto const &[prev, tgtmap] : prevmap) {
					u32 best_t = 0;
					unsigned long long best_c = 0;
					for (auto const &[t, c] : tgtmap) {
						if (c > best_c) {
							best_c = c;
							best_t = t;
						}
					}
					d.prev.push_back(prev);
					d.target.push_back(best_t);
				}
				if (!d.prev.empty() &&
				    dbt::config::g_gbrind_ctx1_slot_next < dbt::tcache::GBRIND_CTX1_SLOTS) {
					d.slot = dbt::config::g_gbrind_ctx1_slot_next++;
					out[src] = std::move(d);
				}
				// else: no data, or slot space exhausted -- source simply gets no oracle entry.
			}
		}
		return out;
	}();
	return m;
}

// A-line round 29 Gate 1 (oracle-only, default off): loads the SAME .trans file as
// LoadOrder1Oracle above but aggregates over prev (context-free), reducing it to a single
// argmax-target constant per source. Reuses --aot-order1-context-file (same file, no new
// collector); gated by its own --aot-marginal-context-oracle flag so it can be measured
// independently of the order-1 treatment. Deliberately assigns NO tcache::gbrind_ctx1_slots
// index -- this treatment carries no runtime state at all.
static std::unordered_map<u32, u32> const &LoadMarginalOracle()
{
	static std::unordered_map<u32, u32> m = [] {
		std::unordered_map<u32, u32> out;
		if (dbt::config::aot_order1_context_file) {
			std::unordered_map<u32, std::unordered_map<u32, unsigned long long>> raw; // src -> target -> count
			std::ifstream f(dbt::config::aot_order1_context_file);
			std::string line;
			while (std::getline(f, line)) {
				if (line.empty())
					continue;
				std::istringstream ls(line);
				unsigned long s, p, t;
				unsigned long long c = 1;
				ls >> std::hex >> s >> p >> t;
				ls >> std::dec >> c;
				raw[(u32)s][(u32)t] += c;
			}
			for (auto const &[src, tgtmap] : raw) {
				u32 best_t = 0;
				unsigned long long best_c = 0;
				for (auto const &[t, c] : tgtmap) {
					if (c > best_c) {
						best_c = c;
						best_t = t;
					}
				}
				out[src] = best_t;
			}
		}
		return out;
	}();
	return m;
}

// A-line round 32 Gate 2 (oracle-only, default off): loads a static jump-table target file (see
// r32_bootstrap_tool.py) of "src target1 target2 ..." lines -- each line is one gbrind source's
// FULL, immutability-verified target set, resolved OFFLINE by reading the guest ELF's own
// read-only memory directly (bootstrapped only via cheap --shadow-edges2-out evidence to locate
// which table a source's parameterized base resolves to -- the table itself is read in full from
// the ELF, going beyond whatever few samples were used to locate it). Static, process-lifetime
// storage, same pointer-stability contract as the other oracle loaders in this file.
static std::unordered_map<u32, std::vector<u32>> const &LoadStaticTableOracle()
{
	static std::unordered_map<u32, std::vector<u32>> m = [] {
		std::unordered_map<u32, std::vector<u32>> out;
		if (dbt::config::aot_static_table_file) {
			std::ifstream f(dbt::config::aot_static_table_file);
			std::string line;
			while (std::getline(f, line)) {
				if (line.empty())
					continue;
				std::istringstream ls(line);
				unsigned long s;
				ls >> std::hex >> s;
				std::vector<u32> targets;
				unsigned long t;
				while (ls >> std::hex >> t)
					targets.push_back((u32)t);
				if (!targets.empty())
					out[(u32)s] = std::move(targets);
			}
		}
		return out;
	}();
	return m;
}
