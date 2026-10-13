#!/usr/bin/env python3
"""Add accepted Task173 final receipts to the existing compact map; no replay."""
import csv, hashlib, io, json, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
out=ROOT/'docs/rvv-validation/directed-task177';out.mkdir(parents=True,exist_ok=True)
commit='5b205bd'
def retained(name):
    return subprocess.check_output(['git','show',commit+':docs/rvv-validation/directed-task173/'+name],cwd=ROOT)
finalraw=retained('evidence/FINALIZATION_STATUS.json');final=json.loads(finalraw)
csvraw=retained('evidence/PER_FORM.csv');joinraw=retained('CANDIDATE_SOURCE_JOIN.json');join=json.loads(joinraw)
assert final['forms']==18 and final['cases_per_arm']==170910 and final['observations']==854550
per=list(csv.DictReader(io.StringIO(csvraw.decode())))
assert len(per)==18 and sum(int(r['Reference']) for r in per)==170910
for name,raw in [('TASK173_FINALIZATION_STATUS.json',finalraw),('TASK173_PER_FORM.csv',csvraw),('TASK173_CANDIDATE_SOURCE_JOIN.json',joinraw)]:
    (out/name).write_bytes(raw)
mappingfile=ROOT/'docs/rvv-validation/directed-task175/PER_FORM_BATCH_BUILD_RESULT.json'
mapping=json.loads(mappingfile.read_text());receipt='docs/rvv-validation/directed-task177/TASK173_PER_FORM.csv'
if receipt not in mapping['receipts']:mapping['receipts'].append(receipt)
index=mapping['receipts'].index(receipt);byform={r['form']:r for r in per};updated=[]
for row in mapping['rows']:
    if row[0] not in byform:continue
    assert row[3]=='PENDING173' or row[1]==173
    r=byform[row[0]];counts={a:int(r[a]) for a in ('Reference','B','M1','M2','BOTH')}
    assert len(set(counts.values()))==1 and counts['Reference']==final['per_form_per_arm'][row[0]]
    row[1:]=[173,join['engine_sha256'],'PASS_FINITE_SCOPE',index,counts];updated.append(row[0])
assert len(updated)==18
accepted=sum(row[3]=='PASS_FINITE_SCOPE' for row in mapping['rows'])
assert len(mapping['rows'])==595 and accepted==592
remaining=[row[0] for row in mapping['rows'] if row[3]!='PASS_FINITE_SCOPE']
assert set(remaining)=={'vfsqrt.v','vfrec7.v','vfrsqrt7.v'}
mapping['accepted_after173']=accepted
mapping['task173_final_evidence']=dict(commit=subprocess.check_output(['git','rev-parse',commit],cwd=ROOT,text=True).strip(),receipt=receipt,cases_per_arm=170910,forms=18,sha256={name:hashlib.sha256(raw).hexdigest() for name,raw in [('FINALIZATION_STATUS.json',finalraw),('PER_FORM.csv',csvraw),('CANDIDATE_SOURCE_JOIN.json',joinraw)]},resource_compliance=final['resources']['resource_compliance'],guest_reruns=0)
mappingfile.write_text(json.dumps(mapping,separators=(',',':'))+'\n')
(out/'EXACT_GAPS_AFTER177.json').write_text(json.dumps(dict(required=595,accepted=592,gaps=remaining,owner='session3 Task176',task173_credit='accepted final evidence only',sequence_validation_adds_per_form_credit=0,final_common_build_validation='NOT_RUN'),indent=2)+'\n')
print('592/595; retained Task173 18 forms /170910 per arm; no guest calls')
