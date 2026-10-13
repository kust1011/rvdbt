# Task160 — frozen FP full matrix execution and audit

Executed the unchanged Task157 `fp-full-final/launch.sh` on xbd from ea25734. **126,062 cases / 9,180 units / 630,310 packet checks / 45,900 commands** completed; build/run/full offline audit/frozen controls/additional controls/export all returned zero. Every arm has 126,062 runner/audit PASS receipts, with **zero failures, reference blockers, missing/duplicate checks or execution timeouts**. This is finite directed evidence; **main's audit acceptance and separate FP checker review remain pending**. No production change or push.

Per arm, **124,942 ordinary cases** have audited PASS outcomes; **1,120 reserved-start cases** have separately labeled `PROFILE_RESERVED_START` observations. Across five arms these are 624,710 ordinary checks and 5,600 profile observations. Sixty reserved-encoding declarations remain NOT_RUN. No full semantics proof or per-target M1/M2 method admission is claimed. The full denominator includes previously piloted cases; pilot counts are not added again, and no pilot launch or recheck was rerun.

| Forms | Ordinary per form/arm | Reserved-start per form/arm | Total per form/arm |
|---|---:|---:|---:|
| vfadd.vv, vfsub.vv, vfmul.vv, vfdiv.vv | 12,469 | 112 | 12,581 |
| vfadd.vf, vfsub.vf, vfmul.vf, vfdiv.vf, vfrsub.vf, vfrdiv.vf | 12,511 | 112 | 12,623 |

[Full result/audit evidence](docs/rvv-validation/directed-task160/evidence/VALIDATION.json), [per-form table](docs/rvv-validation/directed-task160/evidence/PER_FORM.csv), [per-geometry table](docs/rvv-validation/directed-task160/evidence/PER_GEOMETRY.csv), [rounding table](docs/rvv-validation/directed-task160/evidence/PER_ROUNDING.csv), and [all 630,310 audited rows](docs/rvv-validation/directed-task160/evidence/observed-checks.csv.gz) retain exact denominators, status separation, raw paths and offsets. [Stage status](docs/rvv-validation/directed-task160/evidence/STAGE_STATUS.json) is a separate Task160 receipt; the original launcher receipt, with offline stages125, remains unchanged and is exported separately.

Main's unchanged parallel wrapper ran four disjoint unit views through the frozen full-final auditor and predicates at the raw location. All four workers returned zero; merge accounted for the entire original declaration. Audit verified 12,420 compiled ELF identities, all target encodings/generated bodies and **3,240 Sail adapters**, plus full raw extraction, stream/storage hashes and packet predicates. [Audit](docs/rvv-validation/directed-task160/evidence/AUDIT.json), [parallel lineage/input hashes](docs/rvv-validation/directed-task160/evidence/PARALLEL.json), [worker receipts](docs/rvv-validation/directed-task160/evidence/AUDIT_WORKERS.json) and [scope/source review](docs/rvv-validation/directed-task160/AUDIT_SCOPE.md) retain the checks and their limits. The already corrected Task157 tininess predicate was not altered; original failed pilots, scripts and receipts remain intact. Main separately adjudicates that correction.

| Control suite | Selected packets | Ordinary rejected mutations | Reserved-start rejected mutations | Allowed ordinary variants |
|---|---:|---:|---:|---:|
| Frozen reject_fp157.py | 446 | 12,900 | 0 | 20 |
| Additional bounded geometry controls | 2,160 | 48,060 | 14,580 | 540 |

The additional suite covers all 54 geometries and ten forms, with rounding witnesses distributed across frm0–4, and requires every mutation/allowed variant to change bytes. Both suites consume actual retained packets and frozen ISA/reference predicates, with **zero guest reruns**. Suite selections may overlap; their packet counts are not a unique-coverage total. [Control counts](docs/rvv-validation/directed-task160/evidence/CONTROL_COUNTS.csv), compressed per-mutation/allowed/selection records and [preparation plan/correction](docs/rvv-validation/directed-task160/CONTROL_PLAN.json) retain the complete bounded controls. A local planning assertion rejected the assumption that baseline tags existed at every frm; this was corrected before any control replay, without changing the frozen declaration or predicates.

Persistent originals are **xbd:/home/vick/rvv-directed-task157/fp-full-final**. Derived audit, controls, cleanup inventory and compact exports are **xbd:/home/vick/rvv-directed-task160**. Raw stays on disk, not only /dev/shm; **45,900 packets, stdout and stderr artifacts each; 12,420 ELFs; 36,720 tbmaps; 3,240 signatures** remain. [Retention inventory](docs/rvv-validation/directed-task160/RETENTION.json) records about 3.29GiB allocated after cleanup. Only **36,720 closed successful per-run .prof caches and their metadata** were removed, freeing 2,419,749,233 bytes; hashes and exact paths are retained in the cleanup inventory. No stdout, packets, ELFs, tbmaps, failures or original artifacts were deleted. About 12MiB of compact evidence was exported once; no full raw transfer was performed.

Pins match e2559c5c host512 and the fixed library/Spike/pk/Sail0.14.1 identities. Launch used **guest8/build4/nice10/no affinity**, with Task159's eight-guest runner present initially: combined allocation16. The full launcher enforced its unchanged disk/memory gates. FP audit started only after guests closed and a fresh live-process check found no competing auditors; Task159's entire four-worker offline allowance stayed reserved alongside FP's four. Controls ran sequentially with one worker. [Preflight](docs/rvv-validation/directed-task160/PREFLIGHT.txt), [offline capacity](docs/rvv-validation/directed-task160/evidence/OFFLINE_CAPACITY.json), pins/freeze hashes and final resource state are retained. Guest time2098.973s and parallel audit133.611s are operational receipts, not performance evidence.

All 634 tracked Task156 files were checked byte-for-byte unchanged; existing untracked Python cache directories were preserved. No reset/restore, frozen script modification, forbidden retry, family ownership change, Linux/LLVM/performance expansion, shared thesis edit or production change occurred. The [reviewed wider-integer disposition](docs/rvv-validation/directed-task157/TASK156_DISPOSITION.json) remains explicit:

| Wider-integer work | Remaining disposition; no Task160 completion credit |
|---|---|
| Widening integer, 22 forms | Full69,328 unrun; prepared at task154/widen-full |
| Widening MAC, 7 forms | Full2 guests25,069 retained; main owns audit/acceptance disposition |
| Destination-chunk supplement | Full5,103 / pilot161 unrun; stopped queue |
| Sign/zero extension | Full10,354 / pilot660 unrun; retained historical capacity refusal |

Task159 continues to own fixed-point/mask evidence. Scoped local commit only. The remote finalizer completed data work but its notification trap found no remote tmux server; both required completion signals are issued from the local tmux server after this delivery's checks/commit. Original remote notification stderr is retained separately from successful guest/audit stages.
