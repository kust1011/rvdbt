# Historical Directed Tools

These generators, inspectors and campaign-specific launchers are retained for
source provenance and old receipts, not as the supported replay interface.
Do not run them as a substitute for the current 595-form selected corpus.

Use [`run_rvv_retained.py`](../../run_rvv_retained.py) for `list`, `show`,
`preflight`, bounded `run`, explicitly authorized `campaign` and receipt `audit`.
See the [retained-corpus commands](../../../docs/rvv-validation/portable-external.md#retained-directed-corpus).
The maintained runner does not import modules from this directory. It loads
each entry's original hash-pinned checker snapshot from the supplied corpus,
including transitive source/data dependencies. Historical files and those pins
must not be rewritten to resolve missing inputs or change an oracle.
