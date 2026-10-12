# Task126 receipts

Code/tests commit `173fce8`. [Report](../../../SESSION0_RESULT_126.md),
[bounded commands](COMMANDS.md), [raw audit](LOCAL_RAW_AUDIT.json),
[build/source pins](SOURCE_IDENTITY.json), [eight original calls](SUMMARY.json).
Final test streams and compressed configure/build/object evidence are adjacent.
Full raw: xbd:/home/vick/rvdbt-helper-signal-task126; downloaded raw:
/home/user/research/materials/task126-raw-20261013. Immutable archive:
/home/user/research/materials/task126-receipts-20261013.tar.gz, SHA256
16d34fdf498bad0b29671ca98771409ec38f8d796c167866ba83acd058087452.
Original ELFs, checkers, reference packets and every new call's raw bytes remain
in that archive. LOCAL_RAW_AUDIT.json authenticates 175 files and compares the
new input hashes to ORIGINAL_PREFLIGHT.json; old reference bytes were retained.

The host API tests execute no guest handler. Synthetic HostCopy metadata covers
SEGV_MAPERR, SEGV_ACCERR, BUS_ADRERR and BUS_OBJERR for both directions/flags.
The real kernel helper probe covers ACCERR and ADRERR, both load/store and
aligned/split accesses, capture plus frame publication, no handler execution.
MAPERR and OBJERR are synthetic mapping tests, not claims of real kernel faults.
The eight guest calls are only the unchanged first-fault exit handler and later
FOF controls. Four handler exits and four controls pass with exact original
stdout; none executes sigreturn. No SIGBUS guest handler execution is claimed.

[Authoritative source hashes](AUTHORITATIVE_SOURCES.json) bind the fetched Linux
v6.12 asm-generic signal/siginfo and RISC-V signal.c plus pinned QEMU signal.c.
Linux target numbers/codes and RV32 fault union offsets determine the codec.
QEMU separately maps host signal numbers and materializes the guest fault PC,
address and access direction before synchronous delivery. Its SIGSEGV
write-protection repair and mask restoration before nonlocal exit are not
copied: this leaf path returns through kernel sigreturn before normal helper
unwind. The unchanged compiled HandleSignal body has no call instructions or
TLS resolver. The new frame path does not manipulate host signal masks.

Native/bulk/gather recovery, concurrency, mapping-race safety and guest restart
remain unimplemented. This evidence does not establish native recovery or a
full OS signal subsystem. No P4-04 or equivalent repair/return/same-PC execution,
external broad suite, performance run, push or issue closure. Launcher owns
completion signaling.
