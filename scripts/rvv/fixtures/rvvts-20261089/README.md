BSD-3-Clause RVVTS API derivative, not an upstream canned test. Revision
ed9a96e74f9c8367ce42da5b6526b9727a18a293; upstream LICENSE included.
Retained inputs and complete 16-instruction body come unchanged from
artifacts/rvv_multichunk_batch_20261009 (read its README before porting).
seed20261089, VLEN2048/e32/m1/VL64, ta/mu, vstart0, frmRNE.

replay-ready-ported.S retains original MachineState restore and full-FLEN
snapshot fragments. Linux write/exit and page-aligned linker RAM replace the
privileged environment; original e8,ta,ma restore syntax adds explicit m1.
This is the previously accepted wrapper adaptation. No generated inputs or
new goldens: the same newly built ELF runs first in Spike+PK, then four DUT arms.
rvvts_packet.py imports original MachineState.compare(diff_full=True) and
FDQRegStateDump from the pinned checkout. Full32 vector registers (8192bytes),
32 full64 FPR, and10 CSR are compared exactly; packet size8768 is mandatory.
Before FPR8..264, vectors272..8464, CSR8464..8504, after FPR8512..8768;
padding is excluded. Input FPR injection/before-after and unwritten vectors are
also checked. GPR/PC/mstatus/memory final state and instruction-intermediate
flags are outside the observer.

M1/Both flags explicitly select SSA/member order, bounded batches, no splitting,
component-separable or grouped body. Current diagnostics and emitted host code
must establish multi-member admission; configuration labels alone are insufficient.
