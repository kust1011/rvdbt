# Preserved prelaunch failures (no DUT failures)

Formal manifest9393 and raw verdicts were never reduced or altered. None of the
formal3960 commands failed, timed out, or lacked output. The six-batch350-case-check
pilot also passed, separately outside formal credit.

Before that pilot:

1. Local build command selected the default `clang-22`, which is present on xbd
   but absent locally. The Python launch raised exactly
   `FileNotFoundError: [Errno 2] No such file or directory: 'clang-22'`.
   The incomplete `/tmp/task145-build/` was left in place. The successful fresh
   `/tmp/task145-build2/` explicitly used existing `clang-20` (20.1.8).
2. The first Sail probe raced the pilot-file transfer. It printed
   `Error: File '/home/vick/rvv-directed-task145/w128-e8-mf8-vv-start/sail.elf' is not found or it is not an ELF file`.
   Its original stderr pathname was reused during the next probe; this message
   is preserved here from the tool transcript, not represented as an untouched
   raw receipt. Its engine return code was not separately recorded.
3. The next Sail probe executed the program but spun at its terminal `jal x0,0`
   until the shell's30-second bound. Retained `pilot/{stdout,stderr}` and
   `pilot/trace.{stdout,stderr}` diagnose the exit adapter. Trace shows the loop
   at0x80000424. Retained `pilot/stop.{stdout,stderr}` and `signature2` show successful
   explicit `--stop-at-pc 0x80000424` termination and signature output. No guest
   handler/restart or instruction-body workaround was introduced.

These are compiler/environment, transport and exit-adapter failures, respectively.
No reference answer was changed. The formal runner uses the verified final-loop
stop PC, finite instruction limit, strict packet extent and successful exit.
A post-run hardening adds prelaunch guest-build hashes and nonzero aggregate exit
on failed check; the exact actually executed runner remains in raw. All formal
raw reapplication uses the unchanged semantic checker. Unit controls test failure
rejection, with copied actual packets separately stored under `rejections/`.
