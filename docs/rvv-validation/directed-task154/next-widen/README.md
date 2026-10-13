Twenty-two integer widening forms are developed independently of session3:
vwaddu/vwadd/vwsubu/vwsub vv/vx/wv/wx, vwmulu/vwmul/vwmulsu vv/vx.
Full finite declaration: 69,328 cases, 3,960 units; 65,236 ordinary and 4,092
reserved-start profile cases. The full manifest is not executed by Task154;
pilot credit is reported separately. All 136 reserved encoding declarations
remain NOT_RUN.

Destination EEW/EMUL and both source EEW/EMUL are explicit in every case.
Legal source EMUL>=1 high-part overlap, equal-wide-source overlap, source
identity, group end, fractional layouts, masks, policies, chunk/partial VL
and no-body/nonzero vstart are included. Different-EEW source-source overlap
is excluded as reserved, independently of what a reference might execute.
Checkers compute full double-width results and use the captured packed mask.
The current official overlap-agnostic rule is an allowed set, never a free
pass to ignore inactive elements.

Local preparation: `PYTHONDONTWRITEBYTECODE=1 python3
scripts/rvv/directed/prepare_widen154.py
 docs/rvv-validation/directed-task154/next-widen` (one shell command). Checks:
1,248; compiled distinct targets:377; layouts:69,328; geometry/form extents:360.
The 176-unit/2,948-case pilot uses the existing runner, fixed independent
Spike/Sail, build4/run8/nice10/no affinity; snapshot under remote
`/home/vick/rvv-directed-task154/widen-pilot`.

After successful pilot, the next executable entry is the separately frozen
`/home/vick/rvv-directed-task154/widen-full/launch.sh`. Before execution check
combined task154/session3 guests <=16, no existing target corpus, and capacity
for 10GiB reserve plus a 2GiB estimated new batch budget. The normal runner
continues enforcing reserve per build/capture/cache batch. A lack of capacity
leaves full widening NOT_RUN; it never authorizes deletion of retained raw.
See `CAPACITY_GATE.json` and the Task154 result for the latest disposition.

Pinned QEMU source-inspired qemu-* scenarios, exact source paths and RVV1.0
adaptations are documented in [semantic review](../SEMANTIC_REVIEW.md).
This is project-directed testing, not unchanged external-suite execution.
