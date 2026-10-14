Task191 retains a bounded production integration, not a full matrix replay.
See [SESSION0_RESULT_191.md](../../../SESSION0_RESULT_191.md) for scope and remaining obligations.

`raw-receipts.tar.gz` is the verified `task191/` tree from isolated186. It contains
all per-command captures, binary terminal snapshots, independent expected grouped
memory pages, original call selection, copied sequence ELFs/reference packets,
production configuration/link/build records, failures and the offline audit.
`SUMMARY.json` comes from the final offline join of the 50 accepted records;
intermediate `FINAL.json` covers the initial 32-command stage only. Intermediate
`RESULTS.json` was overwritten by the later helper stage; `ALL_ACCEPTED_RECEIPTS.json`
and the per-call execution.json files are the authoritative complete join.

Executed controller mapping:

- local `run191.attempt1.py` = archived administrative/run191.py: eight successful
  fixtures, followed by a pre-external-launch option assertion failure.
- local `run191.py` = archived administrative/run191-resume.py: the external-only
  continuation. This is a guarded continuation script, not a fresh-build runner.
- `extra191.py`: retained normal sequences and new anonymous guest; its final
  version supports the narrow anonymous-only/gather-on-only continuation. Earlier
  failure details are retained in administrative logs and failed anonymous roots.
- `audit191.py`: offline only, no builds or guests. It verifies all accepted
  receipts/identities/counters and the grouped expected memory pages.

No controller here should be launched into the existing retained namespace.
The exact production build command is administrative/BUILD_COMMAND.json; build
exit0 precedes execution. Test tools were copied separately to isolated186's
`task191-tools`, with their hashes retained. The helper reads receipt functions
from remote `run191-resume.py` (local `run191.py`); it does not execute that
controller's top-level loops. Local scripts preserve what was used, rather than
silently converting historical commands into a new whole-suite entrypoint.
