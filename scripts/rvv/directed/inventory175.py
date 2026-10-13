#!/usr/bin/env python3
"""Reconcile explicit accepted final per-form receipts without replaying guests."""
import csv,json,gzip
from pathlib import Path
R=Path(__file__).resolve().parents[3];S=R.parent/'rvdbt-directed-session3-20261013';T=R.parent/'thesis_rvv_20260921/artifacts/rvv_validation_delivery_20261009/throughput'
required={r['form'] for r in csv.DictReader(open(R.parent/'thesis_rvv_20260921/artifacts/external_suite_coverage_20261007/FORM_VERIFICATION_EVIDENCE.csv')) if r['rv32_elen64_applicability']=='REQUIRED'}
m={}; receipts={}; evidence_rows={}
def add(p,task):
 p=Path(p)
 x=list(csv.DictReader(open(p))) if p.suffix=='.csv' else json.load(open(p))
 if isinstance(x,dict) and 'per_form' in x:x=x['per_form']
 if isinstance(x,dict):x=[dict(form=k,**v) for k,v in x.items()]
 for r in x:
  form=r.get('form');
  if form in required:
   m[form]=dict(task=task,receipt=str(p),result='PASS_FINITE_SCOPE');evidence_rows.setdefault((task,form),[]).append(r)
for task,p in [(146,'PER_FORM_RESULTS.json'),(147,'PER_FORM_RESULTS.json'),(148,'shift/PER_FORM_RESULTS.json'),(148,'delta/PER_FORM_RESULTS.json'),(150,'FULL_PER_FORM_RESULTS.json'),(151,'full-evidence/PER_FORM_RESULTS.json'),(152,'full-evidence/PER_FORM_RESULTS.json'),(154,'full-evidence/PER_FORM_RESULTS.json'),(160,'evidence/PER_FORM.csv'),(161,'PER_FORM_ALL.csv'),(167,'full-evidence/PER_FORM.csv'),(170,'full-evidence/PER_FORM.csv'),(172,'full-evidence/PER_FORM.csv'),(174,'full-evidence/PER_FORM.csv')]:add(R/f'docs/rvv-validation/directed-task{task}'/p,task)
add(R/'docs/rvv-validation/directed-task150/task149-completion/full.json',149)
for task,p in [(153,'PER_FORM_RESULTS.json'),(159,'mask/PER_FORM_RESULTS.json'),(159,'narrowing/PER_FORM_RESULTS.json'),(159,'scaling/PER_FORM_RESULTS.json'),(162,'full/PER_FORM_RESULTS.json'),(163,'full/PER_FORM_RESULTS.json'),(165,'evidence/PER_FORM_RESULTS.json'),(166,'evidence/PER_FORM_RESULTS.json'),(168,'evidence/PER_FORM_RESULTS.json'),(169,'evidence/PER_FORM_RESULTS.json')]:add(S/f'docs/rvv-validation/directed-task{task}'/p,task)
add(T/'averaging155-final/PER_FORM_RESULTS.json',155)
x=json.load(open(S/'docs/rvv-validation/directed-task171/evidence/FINALIZATION_STATUS.json'))
for form in x['forms']:m[form]=dict(task=171,receipt=str(S/'docs/rvv-validation/directed-task171/evidence/FINALIZATION_STATUS.json'),result='PASS_FINITE_SCOPE')

def relative(p):
 import os
 return os.path.relpath(p,R)
pins={i:'e2559c5cd930e919503c79b44af219c243041e86f5b83a157bec860814e8336b' for i in range(145,170)}
pins.update({167:'da4dec6bfc5e28c0574dd659d0c84762e6b1b9e3b07cd7571cce0f73b835bb96',170:'da4dec6bfc5e28c0574dd659d0c84762e6b1b9e3b07cd7571cce0f73b835bb96',171:'7ae5086aef815fa7863a839e86ab0a617be783036fef9085f6518b2d1538ee60',174:'18521de85c7ba352b0dbc6155f26d96c25522b6a6bc81cb26fb38c4c0b1f79a4'})
# Vadd regression in146 is accepted but associate its original145 full receipt.
for form in ('vadd.vv','vadd.vx','vadd.vi'):m[form].update(task=145,receipt=str(R/'docs/rvv-validation/directed-task145/MANIFEST.json.gz'))
def counts(task,form):
 rows=evidence_rows.get((task,form),[]);arms={}
 for r in rows:
  if 'arm' in r:
   if r.get('status')!='PASS':raise ValueError(('not accepted',task,form,r))
   if r.get('class','ordinary')=='ordinary':arms[r['arm']]=arms.get(r['arm'],0)+int(r['checks'])
  elif 'arms' in r:
   for a,c in r['arms'].items():
    statuses=c.get('statuses',c)
    assert not any(v for k,v in statuses.items() if k not in ('PASS','PROFILE_RESERVED_START','ordinary_PASS','reserved_observations','OBSERVED_RESERVED','PROFILE_PASS','PROFILE_UNSUPPORTED_VTYPE') and isinstance(v,int)),(task,form,c)
    semantic=c.get('semantic_statuses',{})
    val=semantic.get('PASS',statuses.get('PASS'))
    if val is not None:arms[a]=arms.get(a,0)+val
 if task==145:
  cs=json.load(gzip.open(R/'docs/rvv-validation/directed-task145/MANIFEST.json.gz','rt'))['cases'];n=sum(c['form']==form.split('.')[1] and c['vstart']==0 for c in cs);arms={a:n for a in ('Reference','B','M1','M2','BOTH')}
 if task==171:arms={a:x['forms'][form] for a in ('Reference','B','M1','M2','BOTH')}
 return arms
out=R/'docs/rvv-validation/directed-task175';out.mkdir(parents=True,exist_ok=True)
paths=sorted({relative(v['receipt']) for v in m.values()});pathid={p:i for i,p in enumerate(paths)}
rows=[]
for form in sorted(required):
 if form in m:
  r=m[form];task=r['task'];build=pins.get(task)
  if task==172:build='80fc0a102921a43f0cb590c85c21671244304003c3e94620e900ebfcb42656ff' if form.startswith('vfncvt') else pins[167]
  rows.append([form,task,build,'PASS_FINITE_SCOPE',pathid[relative(r['receipt'])],counts(task,form)])
 else:rows.append([form,None,None,'PENDING173' if form.startswith(('vfwadd','vfwsub','vfwmul','vfwmacc','vfwmsac','vfwnmacc','vfwnmsac')) else 'SESSION3_UNARY' if form in ('vfsqrt.v','vfrec7.v','vfrsqrt7.v') else 'TASK175_GAP',None,{}])
gap=sorted(required-m.keys());owned=[r[0] for r in rows if r[3]=='TASK175_GAP']
assert len(required)==595 and len(m)==565 and len(gap)==30 and len(owned)==9
(out/'PER_FORM_BATCH_BUILD_RESULT.json').write_text(json.dumps(dict(schema=['form','batch','build_sha256_or_mixed_scope','result','receipt_index','ordinary_counts_when_available'],required=595,accepted_before175=565,receipts=paths,rows=rows,excluded_failed_original_rows={164:"all16 superseded by167",169:"failed scalar-insertion rows superseded by171; accepted other169 forms retained"},corrections={167:'replaces failed164 same16 forms',171:'replaces failed169 insertion; does not add duplicate transfer forms',172:'21 conversion forms once; original narrow failures retained'},reclassifications={162:'reserved rows excluded; eleven forms retained',165:'task168 reserved-v0 row correction;128 forms retained'},source_provenance_requires_rerun=False,final_common_build_validation='NOT_RUN'),separators=(',',':'))+'\n')
(out/'EXACT_GAPS_BEFORE175.json').write_text(json.dumps(dict(required=595,accepted=565,gaps=gap,task173_pending=[r[0] for r in rows if r[3]=='PENDING173'],session3_unary=[r[0] for r in rows if r[3]=='SESSION3_UNARY'],task175_owned=owned,expected_count_discrepancy=False),indent=2)+'\n')
print('required',len(required),'accepted',len(m),'gap',len(gap),'owned',owned)

final=out/'full-evidence/PER_FORM.json'
if final.exists():
 proof=json.load(open(final));mapfile=out/'PER_FORM_BATCH_BUILD_RESULT.json';mapping=json.load(open(mapfile));receipt=relative(final);index=len(mapping['receipts']);mapping['receipts'].append(receipt);byform={x['form']:x for x in proof}
 for row in mapping['rows']:
  if row[0] in byform:
   item=byform[row[0]];assert item['status']=='PASS_FINITE_SCOPE' and item['failures']==0
   row[1:]=[175,item['build_sha256'],item['status'],index,item['arms']]
 mapping['accepted_after175']=sum(row[3]=='PASS_FINITE_SCOPE' for row in mapping['rows']);assert mapping['accepted_after175']==574
 mapfile.write_text(json.dumps(mapping,separators=(',',':'))+'\n')
 (out/'EXACT_GAPS_AFTER175.json').write_text(json.dumps(dict(required=595,accepted=574,gaps=[row[0] for row in mapping['rows'] if row[3]!='PASS_FINITE_SCOPE'],task173_pending=18,session3_unary=3,task175_unresolved=0,final_common_build_validation='NOT_RUN'),indent=2)+'\n')
