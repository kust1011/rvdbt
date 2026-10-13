#!/usr/bin/env python3
"""Credit accepted176 final receipts once without replay or common-build credit."""
import csv,hashlib,io,json,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[3];S=R.parent/'rvdbt-directed-session3-20261013'
O=R/'docs/rvv-validation/directed-task179';O.mkdir(exist_ok=True)
commit='481bfb5'
def read(name):return subprocess.check_output(['git','show',f'{commit}:docs/rvv-validation/directed-task176/{name}'],cwd=S)
raws={n:read(n) for n in ['evidence/FINAL_RESULT.json','evidence/PER_FORM.csv','CANDIDATE_SOURCE_JOIN.json']}
f=json.loads(raws['evidence/FINAL_RESULT.json']);join=json.loads(raws['CANDIDATE_SOURCE_JOIN.json'])
print(json.dumps(f)[:1600]);print(json.dumps(join)[:1000])
for n,b in raws.items():(O/('TASK176_'+Path(n).name)).write_bytes(b)
assert f['status']=='PASS' and f['forms']==3 and f['cases_per_arm']==119950
per=list(csv.DictReader(io.StringIO(raws['evidence/PER_FORM.csv'].decode())))
assert len(per)==3 and sum(int(r['cases_per_arm']) for r in per)==119950
path=R/'docs/rvv-validation/directed-task175/PER_FORM_BATCH_BUILD_RESULT.json'
m=json.loads(path.read_text());receipt='docs/rvv-validation/directed-task179/TASK176_PER_FORM.csv'
if receipt not in m['receipts']:m['receipts'].append(receipt)
idx=m['receipts'].index(receipt);by={r['form']:r for r in per}
for row in m['rows']:
 if row[0] in by:
  r=by[row[0]];n=int(r['cases_per_arm']);assert r['status']=='PASS' and n==f['per_form_per_arm'][row[0]]
  row[1:]=[176,join['candidate_sha256'],'PASS_FINITE_SCOPE',idx,{a:n for a in ['Reference','B','M1','M2','BOTH']}]
assert len(m['rows'])==595 and all(r[3]=='PASS_FINITE_SCOPE' for r in m['rows'])
m['accepted_after176']=595
m['task176_final_evidence']=dict(commit=subprocess.check_output(['git','rev-parse',commit],cwd=S,text=True).strip(),receipt=receipt,forms=3,cases_per_arm=119950,guest_reruns=0,sha256={n:hashlib.sha256(b).hexdigest() for n,b in raws.items()})
path.write_text(json.dumps(m,separators=(',',':'))+'\n')
(O/'EXACT_GAPS_AFTER179.json').write_text(json.dumps(dict(required=595,accepted=595,gaps=[],scope='finite historical accepted matrices; mixed build pins preserved',final_common_build_validation='NOT_RUN',owner_final_common_build='Session3 Task178',task179_sequence_additional_form_credit=0),indent=2)+'\n')
print('595/595 finite; common-build validation remains separate')
