import collections,gzip,json,hashlib,re,subprocess
from pathlib import Path
r=Path('/home/vick/rvdbt-host512-task128');read=lambda p:json.loads(Path(p).read_text());sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();save=lambda p,x:Path(p).write_text(json.dumps(x,indent=2)+'\n')
for suite,n in [('chips',1948),('act',3828),('ara',128)]:
 old=json.load(gzip.open(r/f'{suite}-queue.json.gz','rt'));new=read(r/suite/'QUEUE.json');key='cells' if suite=='chips' else 'calls';assert old[key]==new[key] and len(new[key])==n
save(r/'TASK125_QUEUE_EQUALITY.json',dict(exact_original_selected_calls=True,counts=dict(chips=1948,act=3828,ara=128),original_compressed_hashes={s:sha(r/f'{s}-queue.json.gz') for s in ('chips','act','ara')}))
records=json.load(gzip.open(r/'RECEIPTS.json.gz','rt'));lookup={x['receipt'].replace(str(r),''):x for x in records};bindings=json.load(gzip.open(r/'form-bindings.json.gz','rt'));newbindings=[]
for x in bindings:
 rel=x['task125_receipt'].replace('/home/vick/rvdbt-production-task125','');y=lookup[rel];assert y['result']['status']=='PASS'
 newbindings.append(dict(suite=y['suite'],case=y['case'] or x['case'],arm=y['arm'],forms=y['forms'],task128_receipt=y['receipt'],task128_result=y['result'],task128_command=y['command'],task128_identity=y['executable_pins'],source_assertion_binding_from_task125=x,attribution='Task125 source/assertion binding reused unchanged; task125_* fields remain older host128 evidence; task128_* identify this actual host512 run'))
with gzip.open(r/'form-bindings-host512.json.gz','wt') as f:json.dump(newbindings,f,separators=(',',':'))
checks=[]
for p in sorted(r.glob('*test.rc')):
 assert p.read_text().strip()=='0',p
 checks.append(dict(target=p.stem,returncode=0,stdout_sha256=sha(p.with_suffix('.stdout')),stderr_sha256=sha(p.with_suffix('.stderr')),stdout=p.with_suffix('.stdout').read_text()))
save(r/'FOCUSED_RESULTS.json',checks)
for group in ['pilot','inspection']:
 q=read(r/'pilot/QUEUE.json');entries={e['case']:e for e in q['entries']};ledger=[]
 for c in q['calls']:
  d=r/group/'raw'/c['case']/c['arm'];x=read(d/'result.json');assert x['status']=='PASS' and x['original_predicate_pass'];cmd=read(d/'command.json');assert sha(d/'stdout')==x['stdout_sha256'] and sha(d/'stderr')==x['stderr_sha256']
  normalized=[]
  for flag in cmd[1:]:
   if flag.startswith('--fsroot='):flag='--fsroot={WORK}/fs'
   elif flag.startswith('--cache='):flag='--cache={WORK}/cache'
   elif flag.startswith(('--dump-tbmap=','--dump-tbcode=')):continue
   normalized.append(flag)
  assert normalized==c['normalized_flags']
  ledger.append(dict(case=c['case'],form=entries[c['case']]['form'],arm=c['arm'],original_call=c,command=cmd,result=x,identity=read(d/'IDENTITY.json'),role='Original flags/predicate pilot' if group=='pilot' else 'Exit-time code dump diagnostic; same execution options and predicate'))
 save(r/group/'AUDITED_RESULTS.json',ledger)
assert read(r/'exit-only/SUMMARY.json')['pass_count']==8
obj=(r/'host-copy-object.disasm').read_text();body=re.search(r'<_ZN3dbt7rvvcopy12HandleSignal.*?>:(.*?)(?=\n[0-9a-f]+ <|\Z)',obj,re.S)
if not body:body=re.search(r'<[^>]*HandleSignal[^>]*>:(.*?)(?=\n[0-9a-f]+ <|\Z)',obj,re.S)
assert body and not re.search(r'\bcall\b',body[1])
save(r/'DISASSEMBLY_CHECK.json',dict(HandleSignal_calls=0,leaf_disassembly_sha256=sha(r/'bulk-leaves.disasm'),host_copy_object_sha256=sha(r/'host-copy-object.disasm'),target_code_records=len(read(r/'TARGET_CODE.json'))))
save(r/'COMPLETION.json',dict(queue_calls=len(records),queue_counts=read(r/'EXECUTION_COUNTS.json'),original_pilot_calls=32,code_dump_diagnostic_pass_calls=32,code_dump_bad_options_pre_guest_calls=1,exit_only_calls=8,focused_targets=len(checks),implementation_fixes=0,remaining='Unexpected native/SIMD/gather host-fault recovery and architectural guest restart remain unvalidated; no optimization claim for helper-only indexed/FOF targets'))
(r/'load.final.txt').write_text(subprocess.check_output(['uptime'],text=True))
print('FINALIZE_PASS',len(records),len(newbindings),len(checks))
