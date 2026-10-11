# Published archived evidence — Task101

[GitHub Release](https://github.com/kust1011/rvdbt/releases/tag/rvv-validation-20261012)
targets exactly `49c44174fe95b68d85fcecf01b2a3bf8731e74d3`.
It contains 94 CHIPS94 archives (626,904,876 bytes), one ACT Task100 archive
(334,470,849 bytes), and two frozen manifests: 97 assets, 961,375,725 archive bytes.

[RECEIPT.json](RECEIPT.json) records all public URLs, frozen SHA256/size identities,
release/tag identity, selection preflight, clean extraction counts, exact commands
and exits, acceptance results, semantic rejection controls and checker limitations.
All 95 archives and both manifests were downloaded without authentication into
fresh xbd scratch; identities, offline acceptance and reader examples passed.
Eight ACT optimized-Python entry controls rejected with exit 1 as required.
Bulk evidence and complete command output remain at `xbd:/home/vick/rvv-task101/`.
No bulk payload was copied locally.

Reproduce using the [CHIPS reader](../chips-review-task93/README.md) and
[ACT reader](../act-primary-task99/README.md). Normal Python assertions are required.
The manifests published with the release are frozen before reader-doc publication
metadata was added to repository manifests; their archive identities are identical.

This is inspection of archived correctness evidence, with zero new ISA executions
or regenerated goldens. Original failures, exclusions, candidate separation and
unobserved optimized-path admission remain recorded. Host predicates do not
independently recompute architectural results or establish complete ISA conformance.
