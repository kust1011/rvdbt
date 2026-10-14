import os
"""Export compact final coverage; no guest/reference execution or old forest hash."""
import collections,csv,gzip,hashlib,json,shutil
from pathlib import Path
B=Path(os.environ.get('RVV_TASK181_ROOT','/home/vick/rvv-task181'));P=json.load(open(B/'DIRECTED_PLAN.json'));E=B/'export';E.mkdir(exist_ok=False)
read=lambda p:json.loads(Path(p).read_text());sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
forms={f:dict(form=f,batch=b,planned=0,completed=0,passed=0,failed=0,blocked=0,reused_same179=0,new_dut=0,source_entries=[]) for f,b in P['owners'].items()}
entries=[];new_commands=0;recovered_commands=0
for e in P['entries']:
 d=B/'directed'/e['id'];s=read(d/'audit/summary.json');assert (d/'audit/COMPLETE').exists() and s['failed']==0
 expected={f:n*4 for f,n in e['forms'].items()};actual={f:c.get('PASS',0) for f,c in s['forms'].items()};assert expected==actual,(e['id'],expected,actual)
 stages=['reuse'] if e['reuse_same179'] else ['pilot','recover' if (d/'recover/COMPLETE').exists() else 'remaining']
 execution=[read(d/stage/'summary.json') for stage in stages]
 assert sum(r['checks'] for r in execution)==s['checks'] and not sum(r['failed'] for r in execution)
 recovered_commands+=sum(r.get('recovered_same181_dut_calls',0) for r in execution)
 new_commands+=sum(r['new_dut_calls']+r.get('recovered_same181_dut_calls',0) for r in execution)
 receipt=dict(entry=e['id'],batch=e['batch'],original=e['original'],manifest_sha256=e['manifest_sha256'],accepted_cases=e['accepted_cases'],audit_summary_sha256=sha(d/'audit/summary.json'),audit_namespace=str(d/'audit'),same179_reuse=e['reuse_same179'],execution_summaries={stage:sha(d/stage/'summary.json') for stage in stages})
 entries.append(receipt)
 for f,n in expected.items():
  row=forms[f];row['planned']+=n;row['completed']+=n;row['passed']+=n;row['reused_same179' if e['reuse_same179'] else 'new_dut']+=n;row['source_entries'].append(e['id'])
focus=[]
for name in ('guard165','guard166','faults','fof-startmask','vill'):
 d=B/'focused'/name;a=read(d/'audit/summary.json');r=read(d/'replay/summary.json');assert a==r and a['failed']==0
 focus.append(dict(suite=name,**a,audit_namespace=str(d/'audit'),audit_summary_sha256=sha(d/'audit/summary.json')))
 for f,counts in a['forms'].items():
  n=counts.get('PASS',0);row=forms[f];row['planned']+=n;row['completed']+=n;row['passed']+=n;row['new_dut']+=n;row['source_entries'].append('focused:'+name)
rows=[]
for f,row in sorted(forms.items()):
 assert row['planned']==row['passed'] and row['completed']==row['passed'] and row['planned']%4==0
 row['cases_per_arm']=row['planned']//4;row['result']='PASS_FINITE_SCOPE';row['build_sha256']=P['build'];rows.append(row)
assert len(rows)==595
families=[]
for batch in sorted(set(P['owners'].values())):
 rs=[r for r in rows if r['batch']==batch]
 families.append(dict(batch=batch,forms=len(rs),planned=sum(r['planned'] for r in rs),completed=sum(r['completed'] for r in rs),passed=sum(r['passed'] for r in rs),failed=sum(r['failed'] for r in rs),blocked=sum(r['blocked'] for r in rs),new_dut=sum(r['new_dut'] for r in rs),reused_same179=sum(r['reused_same179'] for r in rs)))
ext=read(B/'external/audit/SUMMARY.json');assert (B/'external/audit/COMPLETE').exists();assert ext['exact_joins']==21316
resources=[]
with (B/'RESOURCES.jsonl').open() as f:
 for l in f:resources.append(json.loads(l))
resource=dict(samples=len(resources),minimum_free_bytes=min(r['free'] for r in resources),max_own_guests=max(sum(p['kind']=='guest' and p['own'] for p in r['processes']) for r in resources),max_shared_guests=max(sum(p['kind']=='guest' for p in r['processes']) for r in resources),nice_values=sorted({p['nice'] for r in resources for p in r['processes'] if p['own']}),affinity='none',build_calls=0,offline_workers='two own audit workers, serialized between directed/external audits; online packet checks share a process semaphore of two',monitor='sampled process census; controller process counts differ from thread/worker allocation')
assert resource['minimum_free_bytes']>=10*1024**3 and resource['max_own_guests']<=8 and resource['max_shared_guests']<=16 and resource['nice_values']==[10],resource
result=dict(status='PASS_FINITE_SCOPE',build_sha256=P['build'],forms=595,directed_families=families,directed_dut_packets=sum(r['planned'] for r in rows),new_directed_dut_packets=sum(r['new_dut'] for r in rows),reused_exact_same179_dut_packets=sum(r['reused_same179'] for r in rows),external=ext,focused=focus,resource=resource,new_reference_calls=0,new_build_calls=0,failures=[],remaining_p4_gaps=['Task180 completes full P3 actual-path validation separately on the same179 build; the595-form table does not infer per-target native admission from requested flags','No handler return, mapping repair, same-PC retry or general trap/restart proof','Finite matrices do not exhaust arbitrary operand/mask/register/policy Cartesian products','Original two ACT reference blockers are outside accepted queue','Ara sixteen scoped MAC calls preserve TEST_CASE3/4 failures; whole-file PASS is not claimed','Task179 arbitrary inexact unordered sums remain outside the accepted finite oracle','Per-target optimized admission is not inferred from requested arm flags'])
result.update(recovered_same181_dut_commands=recovered_commands,recovery_credit_scope='exact same181 captures independently rechecked after harness recovery; counted once; no historical174/179 DUT credit',P4_complete=True,new_directed_dut_commands=new_commands,focused_dut_commands=sum(x['checks'] for x in focus),focused_denial_controls=sum(x['counts'].get('EXPECTED_DENIAL_CONTROL',0) for x in focus),external_dut_commands=ext['exact_joins'],original_vs_final_provenance_sha256=sha(B/'ORIGINAL_VERSUS_FINAL.json'),resource_transition_limitation=read(B/'TRANSITION_RESOURCE_LIMITATION.json'),P3_task180=read(B/'P3_TASK180_FINAL_TOTALS.json'))
assert new_commands==sum(len(e['units'])*4 for e in P['entries'])
assert result['reused_exact_same179_dut_packets']==0
for name,value in [('FINAL_RESULT.json',result),('PER_FORM_RESULTS.json',rows),('ENTRY_RECEIPTS.json',entries),('RESOURCE_FINAL.json',resource)]:
 (E/name).write_text(json.dumps(value,indent=2)+'\n')
with (E/'PER_FORM_RESULTS.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(dict(r,source_entries=';'.join(r['source_entries'])) for r in rows)
lines=['# Exact 595-form Task181 results','','All counts are legal DUT packets across B/M1/M2/BOTH; divide by four for cases per arm. Original references are reused and independently checked.','','| Form | Owner | Cases/arm | New DUT | Exact same179 joined | Failed | Blocked | Result |','|---|---:|---:|---:|---:|---:|---:|---|']
for r in rows:lines.append(f"|`{r['form']}`|{r['batch']}|{r['cases_per_arm']}|{r['new_dut']}|{r['reused_same179']}|{r['failed']}|{r['blocked']}|{r['result']}|")
(E/'PER_FORM_RESULTS.md').write_text('\n'.join(lines)+'\n')
for src,name in [(B/'external/audit/EXACT_JOINS.json.gz','EXTERNAL_EXACT_JOINS.json.gz'),(B/'external/audit/SUMMARY.json','EXTERNAL_SUMMARY.json'),(B/'external/INPUT_AUDIT.json','EXTERNAL_INPUT_AUDIT.json'),(B/'external/TOOLS.json','EXTERNAL_TOOLS.json'),(B/'external/PARTITION.json','EXTERNAL_PARTITION.json')]:shutil.copy2(src,E/name)
for name in ('CLEANUP.jsonl','RESOURCES.jsonl'):
 with (B/name).open('rb') as src,gzip.open(E/(name+'.gz'),'wb') as out:shutil.copyfileobj(src,out)
if (B/'TRANSFERS.jsonl').exists():
 with (B/'TRANSFERS.jsonl').open('rb') as src,gzip.open(E/'TRANSFERS.jsonl.gz','wb') as out:shutil.copyfileobj(src,out)
(E/'EXPORT_PINS.json').write_text(json.dumps({p.name:sha(p) for p in E.iterdir() if p.is_file()},indent=2)+'\n')
(B/'FINAL_COMPLETE').write_text('PASS\n');print(result['directed_dut_packets'],result['new_directed_dut_packets'],'directed;',ext['exact_joins'],'external; PASS',flush=True)
