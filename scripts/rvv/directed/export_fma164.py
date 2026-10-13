#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One compact export per frozen execution; original corpus remains on disk."""
import collections,csv,gzip,hashlib,json,os,shutil,sys
from pathlib import Path

def read(p):return json.loads(p.read_text())
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def run(base,review,out):
    out.mkdir(parents=True,exist_ok=False);root=base/'corpus';cases=read(root/'manifest.json')['cases'];ids={c['id']:c for c in cases}
    audit=review/'audit-parallel'/'audit';a=read(audit/'audit.json');arms=('Reference','B','M1','M2','BOTH');seen=set();forms=collections.Counter();geoms=collections.Counter();rms=collections.Counter();tags=collections.Counter();fails=[]
    with gzip.open(audit/'observed-checks.csv.gz','rt') as stream:
        for row in csv.DictReader(stream):
            c=ids[row['case']];key=row['case'],row['arm'];assert key not in seen;seen.add(key)
            assert c['vstart']<c['vlmax'],'ordinary legal vstart only'
            form=c['mnemonic']+'.'+c['form'];forms[(form,row['arm'],row['status'],row['semantic_status'])]+=1
            geoms[(form,c['vlen'],c['sew'],c['lmul'],row['arm'],row['status'])]+=1
            rms[(form,c['frm'],row['arm'],row['status'])]+=1;tags[(form,c['tag'],row['arm'],row['status'])]+=1
            if row['status']!='PASS':fails.append(row)
    assert seen=={(c['id'],arm) for c in cases for arm in arms}
    assert len(seen)==a['executed_case_checks']==len(cases)*5
    for name,fields,values in [('PER_FORM',['form','arm','status','semantic_status','checks'],forms),('PER_GEOMETRY',['form','vlen','sew','lmul','arm','status','checks'],geoms),('PER_ROUNDING',['form','frm','arm','status','checks'],rms),('PER_SCENARIO',['form','tag','arm','status','checks'],tags)]:
        with (out/(name+'.csv')).open('w') as stream:
            w=csv.writer(stream);w.writerow(fields)
            for key,count in sorted(values.items()):w.writerow([*key,count])
    anomalies=[];command_count=0
    for unit in dict.fromkeys(c['unit'] for c in cases):
        for arm in arms:
            r=read(root/'runs'/unit/arm/'execution.json');command_count+=1
            if r['returncode'] or r['timeout']:anomalies.append(dict(unit=unit,arm=arm,**r))
    assert command_count==a['executed_commands']==len({c['unit'] for c in cases})*5
    assert read(root/'identities-before.json')==read(root/'identities-after.json')
    for source,name in [(audit/'audit.json','AUDIT.json'),(root/'summary.json','RUNNER_SUMMARY.json'),(base/'STAGE_STATUS.json','ORIGINAL_STAGE_STATUS.json'),(base/'DECLARATION.json','DECLARATION.json'),(base/'FREEZE.sha256','FREEZE.sha256'),(review/'audit-parallel'/'parallel.json','PARALLEL.json'),(review/'audit-parallel'/'workers.json','AUDIT_WORKERS.json'),(review/'controls'/'summary.json','CONTROLS.json'),(review/'STAGE_STATUS.json','STAGE_STATUS.json')]:shutil.copy2(source,out/name)
    shutil.copy2(audit/'observed-checks.csv.gz',out/'observed-checks.csv.gz')
    for p in (review/'controls').glob('*.gz'):shutil.copy2(p,out/('controls-'+p.name))
    with gzip.open(out/'EXECUTED_MANIFEST.json.gz','wt') as stream:json.dump(cases,stream,separators=(',',':'))
    save(out/'IDENTITIES.json',dict(before=read(root/'identities-before.json'),after=read(root/'identities-after.json'),runner=read(root/'runner-identity.json')))
    save(out/'EXECUTION_ANOMALIES.json',anomalies);save(out/'ORIGINAL_FAILURES.json',fails)
    save(out/'VALIDATION.json',dict(cases=len(cases),checks=len(seen),units=len({c['unit'] for c in cases}),commands=command_count,ordinary_per_arm=len(cases),reserved_start_per_arm=0,forms=len({c['mnemonic']+'.'+c['form'] for c in cases}),geometries=len({(c['vlen'],c['sew'],c['lmul']) for c in cases}),rounding_modes=sorted({c['frm'] for c in cases}),failures=len(fails),execution_anomalies=len(anomalies),raw_location='xbd:'+str(base),audit_location='xbd:'+str(review),acceptance='PENDING_MAIN_REVIEW',per_target_method_admission='NOT_CLAIMED',semantics='finite ordinary-width FMA evidence; no full semantics proof'))
    save(out/'EVIDENCE_SHA256.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.is_file()})
    print(json.dumps(read(out/'VALIDATION.json')))
if __name__=='__main__':run(*map(Path,sys.argv[1:]))
