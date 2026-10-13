# Task147 prelaunch observations

Original streams, manifests, reports and controls remain under the new Task147
root. No145/146 raw was executed, audited again, repackaged, changed or deleted.

The 729-case/3,645-check pilot had no packet predicate failure. Its first
cross-case determinism report incorrectly grouped two different implementations,
Spike (VLMAX choice) and Sail with supported vl_use_ceil=true (ceil choice), as
one Reference implementation. Original pilot/determinism.json retains the12
reference-only reports and the original launcher transcript records exit1. Corrected
keys distinguish reference implementations; DUT keys still combine equal input
AVL/VLMAX across forms, policies, pre-states and equal-ratio geometries. The
original config-pilot-original.py is retained and its SHA256 exactly matches
pilot/runner-identity.json. No expected VL interval was changed. The complete
corrected pilot audit is retained separately as pilot-audit-final; pilot earns
no formal credit.

The first pilot audit rejected an inline assembly comment as if it were a
preprocessor adaptation. The audit now rejects actual preprocessor directives
at the first non-whitespace column within the shared body, while allowing
ordinary trailing assembly comments. Source-body/data/target verification
passed with this correction; pilot-audit.log retains the original rejection.
The original pilot corruption run rejected292 independent controls and accepted12
permitted endpoint controls. A subsequent formal control also checks determinism.

Before formal execution,72 e8/m8 max-CSR-vstart cases were reclassified from
reserved-vstart-profile to legal: VLMAX=VLEN, so VLEN-1 is less than VLMAX.
The original declaration and manifest are retained as DECLARATION-prelaunch.json
and manifest-prelaunch-classification.json. classification-amendment.json records
all72 IDs. Only labels changed; generated assembly and ELF hashes did not change.
The final declaration and manifest were transferred before formal execution.

A source lookup for Sail vext_config.sail returned404; the versioned directory
listing identified the actual vext_vset_insts.sail, which was then read before
predicates were defined. This was a source-location lookup, not a guest failure.
Compilation/development elapsed time was not separately instrumented. The
formal correctness runner records its own wall time and every command duration.

The first Task147 archive is retained as task147-directed-final-raw.tar.gz. A
second final-v2 snapshot corrects a report wording typo ("no ... repair was
needed") and archives the now-completed first packaging receipt, rather than
an in-progress empty packaging log. Original execution packets, oracle rules
and results are unchanged; neither archive is overwritten or deleted.
