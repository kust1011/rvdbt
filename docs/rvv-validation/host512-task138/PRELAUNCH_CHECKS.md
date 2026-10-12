# Prelaunch observations

Read Task135/136/137 reports and the Task128/129 retained replay, collector and reporter before dispatch. Task137's final successful elfrun and library were read directly on xbd and matched:

```
da5209ae488403f3eb2a15af8bf0376df4844eefb46b9525c8a0834f8e3f4d5e  /home/vick/rvdbt-goldens-task137/current/build/bin/elfrun
79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af  /home/vick/rvdbt-goldens-task137/current/build/lib/libdbtjitshared.so
```

Initial xbd uptime output: `04:20:36 up 5 days, 7:58, 6 users, load average: 0.14, 0.22, 0.33`. `mpstat -P 28,29,30,31 1 1` observed each core 100% idle. The launcher separately retains `load.before.txt` immediately before launch. No timestamp is inferred for these receipts from the workstation clock.

The actual current CMakeCache was read before launch: `CMAKE_BUILD_TYPE:STRING=Release`, `RVV_HOST_CHUNK_BITS:STRING=512`. Original ACT runner registration records XLEN32/ELEN64; the implementation's `dbt/guest/rv32_vector.h` defines `ELEN_BITS=64`. These are configured implementation/input claims, not per-target runtime tuples. The subsequent full DURING/AFTER snapshots verify actual compile commands, the authenticated compiled source, all 5,325 distinct retained ELF headers (RISC-V ELF32), cache and binary identities. Actual pilot stderr prints `chunk_bytes=64`. These snapshots retain their actual phases and are not relabeled as prelaunch snapshots.

The launcher authenticates all original ELF/checker/answer/source/observer dependencies before any guest dispatch, pins the exact executable/library, and saves `IDENTITY_BEFORE.json`. Each call uses the original acceptance implementation and original flags. It pilots one unchanged call per suite before scheduling the exact full-call disjoint remainder. All three pilots receive current-build credit once, with no credit from prior-build runs.
