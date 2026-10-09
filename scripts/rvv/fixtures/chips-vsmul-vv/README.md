# External CHIPS smoke fixture

`test.S.gz` stores the complete, unchanged CHIPS stage2 `vsmul_vv-0.S`
fixture from the registered VLEN1024 campaign. `fixture.json` identifies the
generator, environment, oracle revision, source bytes, expected ELF and four
execution configurations. The CHIPS Apache-2.0 license is retained in `LICENSE`.

The upstream generator creates stage1 operations and inputs; the upstream
patched Spike captures their results; the upstream merger inserts checks in
stage2. This repository contains that retained stage2, not newly authored
expected arithmetic. Rebuilding verifies fixture and ELF identity; it does not
regenerate the reference answers. Full historical generation logs remain in
the separately retained `chips_validation_20261007/fixed1024` artifact, which
is not included in this small fixture.

The local Linux-user reporting adapter changes terminal PASS/FAIL reporting.
It does not alter the instruction body or expected values. Four successful
configurations do not establish four different executed optimization paths.
This is a reproducibility smoke test, not the complete RVV validation corpus.
