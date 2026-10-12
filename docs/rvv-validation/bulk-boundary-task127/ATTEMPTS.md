Initial aggregate build: exit2. Production elfrun and dbtjitshared succeeded;
rv32_host_copy_fault_test.cpp failed at the new fixture declaration:
`unknown type name 'VectorState'; did you mean 'dbt::rv32::VectorState'?`.
Corrected only the type qualifier. Original build stdout/stderr/rc preserved in
receipts.tar.gz; second focused build and all three tests exit0. Final changed
host-copy-only rebuild/test also exit0; both passing attempts retained.

First source audit failed locally with:
`IsADirectoryError: [Errno 21] Is a directory: 'dbt/third_party/asmjit'`.
The subsequent scp found no generated source-inputs.json and remote audit found
no file. Corrected the input selection to tracked regular files (289), matching
the prior task's source audit convention. Final audit stdout/stderr/rc retained.

Remote rg command returned `bash: line 1: rg: command not found`.
Used grep to retrieve the initial compiler error. No guest call occurred in
these audit/diagnostic failures. No failed guest result was altered or retried.
