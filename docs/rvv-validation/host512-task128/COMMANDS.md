# Task128 isolated host512 commands and scope

Root: xbd:/home/vick/rvdbt-host512-task128. Source commit a6c50facfac092c10fdfee2e8a8b4f34e86a22f8 (Task127 code ed833f4). Copied retained Task127 dependencies and overlaid 289 current tracked dbt/CMake regular files. Source manifests verify zero differences before and after calls.

Exact configure/build/test commands and bounded target list: build.sh and focused.sh. Fresh Release CMake build: clang-22/clang++-22, LLVM22, RVV_HOST_CHUNK_BITS=512. No guest VLEN or other cache knob was changed. All 51 actual production C++ compile commands (49 archive TUs, executable and JIT library) carry host512, AVX512F/BW, O3 and NDEBUG. CMakeCache, compile_commands and flags.make copies are retained in build-evidence. CPU probe runs CPUID/XGETBV and real ZMM instructions on core28.

Build: nice10, cores28-31, -j4, configure180s/build900s. Focused targets sequential on core28, 120s each (linked production probe90s), cores disabled. Pilot: original ACT source/ELF/checker/expected/capture hashes, original flags and predicate, 32 calls (8 cases x B/M1/M2/BOTH); original300s per call. Code-dump diagnostics: same execution options/predicate with a missing exit-time dump option added; 32 passing calls plus one preserved pre-guest bad-options call. No helper/native switch forcing added. target-code-audit.py pins exact guest labels/PCs to the architectural PC stores and actual dumped host bytes/TB map.

Full replay: unchanged replay_memory_task125.py and collect_memory_task125.py from current repository. Four workers total, nice10, cores28-31; original CHIPS/Ara120s, ACT300s, guest VLEN1024 and complete original normalized flags. Queue equality compares exact selected call objects to compressed Task125 queues. Raw is new and isolated; no host128 receipt is overwritten.

Exit-only: unchanged replay_helper_signal_task126.py at exit-only/replay.py, original inputs/commands/specs/memory gates copied from Task126 helper; only build/source identity and work/cache paths bound to this host512 build. 300s overall, original30s per call, nice10/core28, 8 original calls. No reference or guest compiler execution.

No full unrelated suite, performance run, P4-04/equivalent blocked execution, guest sigreturn instruction, mapping repair or same-PC retry. No push, issue closure or launcher signaling from this task.
