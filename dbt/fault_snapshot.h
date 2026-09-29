#pragma once

#include "dbt/util/common.h"

namespace dbt
{
struct CPUState;

// Default-off, one-shot observation of live guest state at a caller-selected block entry.
// The plan is deliberately workload-neutral text: an entry PC plus absolute or entry-SP-relative
// ranges.  It affects neither translation nor guest state.
namespace fault_snapshot
{
void Configure(char const *plan_path, char const *output_path);
void ObserveEntry(CPUState const *state);
bool Enabled();
} // namespace fault_snapshot
} // namespace dbt
