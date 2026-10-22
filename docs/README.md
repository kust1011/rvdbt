# Documentation

## Architecture and development

- [RVV translation and optimization](rvv-qcg.md): frontend, QIR, register
  allocation, x86 emission, register promotion and runtime chunk bounds.
- [Support and validation](rvv-author-guide.md): supported configurations,
  implementation boundaries and how to interpret the tests.
- [Build profiles](build-profiles.md): performance and diagnostic builds.
- [Original rvdbt architecture](rvdbt.md): inherited system design.
- [Scalar examples and inherited AOT workflow](scalar-examples.md).

## Running and inspecting tests

- [Build, run and check](rvv-validation/portable-external.md): public samples
  and commands for separately supplied retained test data.
- [Instruction-form scope](rvv-current-scope.md).
- [Per-form test navigation](rvv-validation/all-form-records/README.md).
- [Measured-build results](rvv-validation/delivery-task182/README.md#measured-d252-replay).

## Historical records

The versioned records under `rvv-validation/` retain source provenance,
checker identities, original failures and results for particular builds.
They are evidence records, not additional setup instructions. Their original
paths remain stable because scripts and manifests refer to them.

Agent session reports have been removed from the working tree. Existing links
point to their [fixed historical revision](https://github.com/kust1011/rvdbt/tree/9dfc020b2aa7e98d068d954555b5902082538702).
No test inputs, reference answers or result records were rewritten by this
documentation cleanup.
