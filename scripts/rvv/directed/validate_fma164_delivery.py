#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate final declaration/audit/control lineage and preserved earlier work."""
import collections,csv,gzip,hashlib,json,subprocess,sys
from pathlib import Path

def read(p):return json.loads(p.read_text())
def run(root):
    prepared=json.load(gzip.open(root/'prepared/PREPARED_MANIFEST.json.gz','rt'))
    full=json.load(gzip.open(root/'full-evidence/EXECUTED_MANIFEST.json.gz','rt'))
    assert prepared==full
    v=read(root/'full-evidence/VALIDATION.json');assert v['cases']==237664 and v['checks']==1188320 and v['commands']==51840 and v['reserved_start_per_arm']==0
    ids={c['id']:c for c in full};seen=set();counts=collections.Counter();forms=collections.Counter();failed=collections.Counter()
    with gzip.open(root/'full-evidence/observed-checks.csv.gz','rt') as stream:
        for row in csv.DictReader(stream):
            c=ids[row['case']];key=c['id'],row['arm'];assert key not in seen;seen.add(key)
            counts[(row['arm'],row['status'])]+=1;forms[(c['mnemonic']+'.'+c['form'],row['arm'],row['status'])]+=1
            if row['status']!='PASS':failed[(c['mnemonic']+'.'+c['form'],c['tag'],row['arm'])]+=1
    arms=('Reference','B','M1','M2','BOTH');assert seen=={(c['id'],arm) for c in full for arm in arms}
    assert counts['Reference','PASS']==len(full)
    audit=read(root/'full-evidence/AUDIT.json')
    for arm in arms:
        assert all(counts[arm,s]==audit['counts'][arm][s] for s in ('PASS','FAIL','ISA_ONLY_REFERENCE_BLOCKED'))
    assert not read(root/'full-evidence/EXECUTION_ANOMALIES.json')
    findings=read(root/'full-findings/summary.json');assert findings['original_failures']==findings['reference_mismatches']==findings['missing_NV']==v['failures'];assert findings['result_mismatches']==findings['reference_failures']==0
    controls=read(root/'full-evidence/CONTROLS.json');assert controls['geometries']==54 and len(controls['forms'])==16 and controls['rounding_modes']==list(range(5)) and controls['guest_reruns']==0
    records=json.load(gzip.open(root/'full-evidence/controls-records.json.gz','rt'));assert len(records)==controls['rejected'] and all(r['rejected'] for r in records)
    assert all(controls['by_control'][tag]>0 for tag in ('nonfused-two-roundings','wrong-destructive-role','wrong-product-sign','wrong-addend-sign'))
    all_changed=subprocess.check_output(['git','diff','--name-only','725a7ab','--']).decode().splitlines()
    tracked=subprocess.check_output(['git','ls-tree','-r','725a7ab']).decode().splitlines()
    baseline_names={line.split('\t',1)[1] for line in tracked}
    changed=[name for name in all_changed if name in baseline_names]
    allowed={'scripts/rvv/directed/audit.py','scripts/rvv/directed/fp157.py','scripts/rvv/directed/vadd.py'}
    assert set(changed)<=allowed,changed
    preserved=[]
    for line in tracked:
        metadata,name=line.split('\t',1);mode,kind,oid=metadata.split()
        if kind!='blob' or name in allowed:continue
        p=Path(name);assert p.exists() or p.is_symlink(),name
        digest=(subprocess.check_output(['git','hash-object','--stdin'],input=str(p.readlink()).encode()) if mode=='120000' else subprocess.check_output(['git','hash-object','--',name])).decode().strip();assert digest==oid,name
        preserved.append(name)
    result=dict(cases=len(full),checks=len(seen),forms=16,geometries=54,rounding_modes=list(range(5)),counts=[dict(arm=k[0],status=k[1],checks=n) for k,n in sorted(counts.items())],original_failures=v['failures'],missing_NV=findings['missing_NV'],effective_rejected_controls=controls['rejected'],effective_allowed_controls=controls['allowed'],earlier_tracked_files_preserved=len(preserved),tracked_harness_changes=changed,Task161_guest_reruns=0,production_changes=0,semantic_pass=False,unresolved=['Pinned DUT missing NV for zero/infinity multiplicands with quiet-NaN addend across all 16 forms; no production fix or corrected-pin revalidation','Main review/acceptance of evidence and independent FMA checker review','96 reserved-encoding declarations NOT_RUN; no illegal-handler/retry credit','Finite testing is not full ISA proof; per-target M1/M2 admission not claimed'])
    (root/'FINAL_VALIDATION.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':run(Path(sys.argv[1]))
