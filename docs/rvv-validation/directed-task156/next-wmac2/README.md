Corrected widening MAC declaration: vwmaccu/vwmacc/vwmaccsu vv/vx,
vwmaccus vx. 25,069 cases/1,260 units, 23,767 ordinary and1,302 reserved-start
profile cases;50 reserved encoding declarations stay NOT_RUN. Pilot1,063
cases/56 units uses fixed DUT and independent Spike/Sail; all stages0,
322 mutations rejected and7 policy variants accepted. Original faulty
next-wmac and remote wmac-pilot/wmac-full stay retained with zero family
admission; see PREPARATION_FAILURES.json and SEMANTIC_REVIEW.md.

Remote corrected snapshots: /home/vick/rvv-directed-task156/wmac-pilot2 and
wmac-full2. launch.sh uses build4/run8/nice10/no affinity, per-write10GiB
reserve and finite1GiB full/256MiB pilot allowances. Finite destination-chunk
delta is separate in destchunk-delta2 and remote destchunk-{pilot,full}; it
never changes an active MAC snapshot. No accepted-family rerun is authorized.
