# Preserved Task178 harness attempts

No semantic DUT failure has been identified in these attempts. The immutable
Task174 executable and original input/reference packets remain unchanged.

- The first directed invocation preceded the completed plan and launched no
  guest. The next Task145 pilot admission failed because the oldest checker
  exposes `check`, not separate `check_isa`/`check_reference`. Its partial
  namespace is retained as `pilot-attempt1`; a wrapper calls the unchanged
  combined checker. The successful pilot executes each case once.
- Task145's repeated decoding of the same packet is memoized. Guest concurrency
  then expands from four to eight under shared admission; exact predicates and
  original flags remain unchanged. Later entries use forked queue workers with
  one shared two-slot predicate semaphore, and two audit workers. The exact
  `35de1be8...` earlier driver is preserved in harness-history; subsequent
  entries retain their runner/admission/storage source snapshots.
- A resource-census source edit briefly had an indentation error. The completed
  Task146 DUT replay is unaffected; the following audit failed at import,
  before opening an audit namespace or executing a guest. Its original log and
  stopped receipt remain as `audit-attempt1.log` and
  `DIRECTED_STOPPED-attempt1.json`. The corrected audit reopens existing DUT
  packets; it launches no guest/reference.
- Ara's original vset parser reads stdout and stderr by path. Stream capture
  initially provided a temporary stderr only, so the original parser rejected
  a missing plaintext stdout. Original compressed packets/commands/execution
  receipts remain in the same new Task178 namespace. Recovery materializes both
  original streams only for parsing, then removes the temporary copies. It
  performs no repeat of captured guests. The first recovery reaches a call that
  the original failed iterator cancelled before launch; the second recovery
  executes exactly 221 previously unattempted calls, then the complete external
  audit verifies all 21,316 exact receipts. Both original error logs are retained.
  Local `external.py` is the corrected reusable producer; the original invoked
  producer remains pinned remotely and in harness-history.
- Task159 historical result objects retain `/dev/shm` provenance. Their frozen
  retained corpus has moved to disk. The adapter preserves the recorded path,
  resolves the established disk corpus path, checks compressed/logical identity,
  and validates the original reference packet. It creates no replacement oracle.

Successful work/cache removal is logged by exact new paths in CLEANUP.jsonl;
failed scratch and every stream remain retained. No old raw/golden/failure
artifact is deleted. The live resource monitor is replaced once to include
forked audit workers separately from their controller; the original samples
remain in the appended resource ledger.

- Task181 found an inherited178 binding bug at b175-095. The pinned review175
  copy ignores existing declared vector shift_values, rejecting an original
  reference prestate before the failing unit launches a new DUT. Exact original
  tools-next passes900 references and3600 original174 outputs. Task181 preserves
  the old plan, stopped attempt and partial raw, amends only two narrowing tool
  bindings, and independently audits recovery on179. The historical178 plan and
 174 results are not rewritten or relabeled.
