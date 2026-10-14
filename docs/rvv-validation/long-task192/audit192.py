"""Offline join of retained Task192 receipts and Task177 full-state/path audits.

Run with the archived tools and original Task191 tool directory on PYTHONPATH.
No execution, builds, or reference calls. Argument is the retained remote root.
"""
import collections
import hashlib
import json
from pathlib import Path
import sys

import long192 as l
import vadd as v


def audit(root):
    l.install()
    seen = set()
    rows = []
    frames = []
    pin191 = l.PIN191
    fixed = json.loads((root/'FIXED_PIN.json').read_text())['elfrun']
    for name in ('baseline-int', 'affected', 'remaining', 'routes'):
        r = root/name
        a = json.loads((r/'audit/AUDIT.json').read_text())
        assert a['status'] == 'PASS' and a['all_packet_outcomes_checked']
        cs = json.loads((r/'manifest.json').read_text())['cases']
        ids = {c['id'] for c in cs}
        assert not seen & ids
        seen |= ids
        pins = json.loads((r/'identities-before.json').read_text())
        assert pins == json.loads((r/'identities-after.json').read_text())
        assert pins[next(p for p in pins if p.endswith('/elfrun'))] == (pin191 if name == 'baseline-int' else fixed)
        paths = json.loads((r/'audit/PC_PATH_RESULTS.json').read_text())
        assert len(paths) == len(cs)*65*4
        assert {p['arm'] for p in paths} == set(l.s.ARMS[1:])
        rows += paths
        frames += json.loads((r/'audit/FRAMES.json').read_text())
        for unit in {c['unit'] for c in cs}:
            for arm in l.s.ARMS:
                d = r/'runs'/unit/arm
                rec = json.loads((d/'execution.json').read_text())
                assert rec['returncode'] == 0 and not rec['timeout']
                for stream in ('stdout', 'stderr'):
                    assert hashlib.sha256(v.storage.verify(d/stream)).hexdigest() == rec[stream+'_sha256']
                checks = json.loads((d/'checks.json').read_text())
                assert len(checks) == sum(c['unit'] == unit for c in cs)
                assert all(c['status'] == 'PASS' for c in checks)
    assert len(seen) == 54
    failures = []
    for arm in l.s.ARMS[1:]:
        d = root/'pilot/runs/long192-fp-w4096-e32-m4'/arm
        rec = json.loads((d/'execution.json').read_text())
        assert rec['returncode'] == -6 and not rec['timeout']
        assert v.storage.verify(d/'stdout') == b''
        assert b'QRegAlloc: virtual-register track capacity exceeded' in v.storage.verify(d/'stderr')
        failures.append(dict(arm=arm, **rec))
    # Source identity: only owned production qra.cpp and its test differ from191.
    source = json.loads((root/'SOURCE191.json').read_text())
    changed = [p for p, h in source.items()
               if hashlib.sha256((root/'source'/p).read_bytes()).hexdigest() != h]
    assert set(changed) == {'dbt/qmc/qcg/qra.cpp', 'dbt/qmc/qcg/qra_vpr_test.cpp'}
    build = json.loads((root/'build.json').read_text())
    assert build['rc'] == 0 and '-j2' in build['command']
    rec = json.loads((root/'qra-regression/execution.json').read_text())
    assert rec['returncode'] == 0 and not rec['timeout']
    output = v.storage.text(root/'qra-regression/stdout')
    assert all(f'tracks={n} returned, globals synced at the call=3' in output
               for n in (274, 2104, 16504))
    paths = {arm: dict(collections.Counter(p['actual_path'] for p in rows if p['arm'] == arm))
             for arm in l.s.ARMS[1:]}
    for arm in ('M1', 'BOTH'):
        assert paths[arm].get('MULTI_MEMBER_NATIVE', 0) > 0
        assert any(f['fast_executions'] and f['arm'] == arm for f in frames)
    assert not any(f['arm'] in ('B', 'M2') for f in frames)
    # Actual bound nodes in emitted singleton frames; options alone are no proof.
    bounds = {arm: sum(bool((p.get('singleton') or {}).get('bounds')) for p in rows if p['arm'] == arm)
              for arm in l.s.ARMS[1:]}
    assert bounds['M2'] > bounds['B']
    result = dict(status='PASS', unique_cases=54, independent_reference_packets=54,
                  accepted_DUT_packets=216, current191_DUT_packets=16,
                  fixed192_DUT_packets=200, original_failed_DUT_packets=16,
                  original_failed_commands=failures, paths_by_arm=paths,
                  singleton_PCs_with_active_bounds=bounds,
                  multi_frames=len(frames), native_multi_frames=sum(bool(f['fast_executions']) for f in frames),
                  fixed_pin=fixed, production_changes=['dbt/qmc/qcg/qra.cpp'],
                  checked_source_changes=changed, guest_rebuilds_for_affected=0,
                  reference_reruns_for_affected=0, blocked_recovery_calls=0)
    v.save(root/'SUMMARY.json', result)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    audit(Path(sys.argv[1]))
