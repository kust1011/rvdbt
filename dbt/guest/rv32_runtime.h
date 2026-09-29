#pragma once

#include "dbt/guest/rv32_cpu.h"
#include "dbt/guest/rv32_ops.h"

namespace dbt::rv32
{

struct Interpreter {
	static void Execute(CPUState *state);
	// 2026-06-16 tier-0 lazy translation: interpret exactly ONE dynamic basic block (until a branch, a page
	// boundary, or TB_MAX_INSNS), advance state->ip to the next block entry, then RETURN to the Execute loop so
	// it can decide to keep interpreting (cold) or JIT-translate (hot). Traps unwind via siglongjmp as usual.
	// Same block boundary as the JIT TB so per-entry execution counts compare apples-to-apples.
	static void ExecuteBlock(CPUState *state);

private:
	Interpreter() = delete;
};

} // namespace dbt::rv32

namespace dbt
{
using Interpreter = rv32::Interpreter;
} // namespace dbt
