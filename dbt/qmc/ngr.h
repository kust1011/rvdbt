#pragma once

#include "dbt/qmc/compile.h"
#include "dbt/util/common.h"

// NGR — Normalized Gen-code Reuse. Reuse a QCG translation across structurally-identical guest blocks that
// differ only in immediate fields (parameterized generated code). On a JIT miss, compute a normalized
// fingerprint (immediate fields masked); on a hit, copy the cached host code + patch the immediate bytes
// instead of re-translating. Default-off (config::ngr). See dbt/qmc/ngr.cpp.
namespace dbt::ngr
{
// Called from the JIT miss handler (execute.cpp) when config::ngr. Returns the installed TBlock (as void*,
// matching CompilerDoJob), either by reusing a cached template (copy+patch) or by full-translating and
// recording a template. Non-normalizable blocks fall back to plain CompilerDoJob.
void *CompileOrReuse(qir::CompilerJob &job, u32 ip, u32 boundary);

// Record a guest mmap of writable+executable pages (a JIT code buffer). Enables NGR's address
// relocations inside gen-code only. Called from the ukernel mmap path when config::ngr.
void MarkGenCode(u32 addr, u32 len);

void PrintStats();
} // namespace dbt::ngr
