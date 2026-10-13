#!/usr/bin/env python3
"""Compact export from the one full raw audit, controls and supplemental traps."""
import collections,csv,gzip,hashlib,json,re,shutil,struct,sys
from pathlib import Path
import vadd as v
import audit

def read(p):return json.loads(p.read_text())
def export(base,out):
 assert (base/'COMPLETE').exists() and (base/'overlap-supplement/COMPLETE').exists();out.mkdir(parents=True,exist_ok=False)
 root=base/'review/corpus';rawaudit=base/'review/audit-parallel/audit';a=read(rawaudit/'audit.json');s=read(base/'review/EXECUTION_SUMMARY.json');assert not a['failures'] and a['executed_case_checks']==s['checks'] and all(c['FAIL']==c['ISA_ONLY_REFERENCE_BLOCKED']==0 for c in a['counts'].values())
 for source,name in [(rawaudit/'audit.json','AUDIT.json'),(base/'review/PER_FORM.csv','MAIN_PER_FORM.csv'),(base/'review/VIEW_LINEAGE.json','VIEW_LINEAGE.json'),(base/'review/EXECUTION_SUMMARY.json','EXECUTION_SUMMARY.json'),(base/'FREEZE.sha256','FREEZE.sha256'),(base/'PIPELINE_STATUS.json','PIPELINE_STATUS.json'),(base/'pilot/corpus/identities-before.json','IDENTITIES.json'),(base/'controls/CONTROLS.json','CONTROLS.json'),(base/'sail-crosscheck/SUMMARY.json','SAIL_CROSSCHECK.json')]:shutil.copy2(source,out/name)
 pins=read(rawaudit/'guest-pins.json');v.save(out/'AUDIT_COMPLETENESS.json',dict(elf_identities=len(pins),executed_commands=a['executed_commands'],executed_case_checks=a['executed_case_checks'],scope='all guest build hashes, target encodings, raw stream/storage identities, command records, extraction and independently checked full-state packets; original zero-start matrix has no built Sail adapters; separate six-unit Sail crosscheck compiles identical observer/target body',raw_evidence=str(base),extra_raw_file_inventory='NONE'))
 controls=read(base/'controls/CONTROLS.json');assert controls['status']=='PASS';cross=read(base/'sail-crosscheck/SUMMARY.json');assert cross['status']=='PASS'
 trap=read(base/'nonzero-vstart/SUMMARY.json');assert trap['status']=='PASS';proof=[]
 for r in trap['records']:
  d=base/'nonzero-vstart'/(r['form'].replace('.','-')+'-vl'+str(r['vl']));cs,syms=audit.elf_sections_symbols(d/'test.elf');pc=syms['target'];addr,code=cs['.text'];word=int.from_bytes(code[pc-addr:pc-addr+4],'little');sc,ss=audit.elf_sections_symbols(d/'sail.elf');saddr,scode=sc['.text'];spc=ss['target'];assert int.from_bytes(scode[spc-saddr:spc-saddr+4],'little')==word
  signature=r['Sail']['signature'];assert signature[0]==0x174bad and signature[1]==2 and signature[3]==spc
  # mtval may legally be zero; if supplied it must identify this target.
  assert signature[2] in (0,word)
  arms={}
  for arm,record in r['DUT'].items():
   stream=v.storage.verify(d/arm/'run/stderr').decode();match=re.search(r'ILLEGAL_INSN ip=([\da-f]+) raw=([\da-f]+)',stream);assert match and int(match[1],16)==pc and int(match[2],16)==word
   assert record['record']['returncode']!=0 and not record['record']['timeout'] and not v.storage.verify(d/arm/'run/stdout')
   arms[arm]=dict(returncode=record['record']['returncode'],specific_diagnostic=match[0],stdout_bytes=0,execution_sha256=v.sha(d/arm/'run/execution.json'))
  proof.append(dict(form=r['form'],vl=r['vl'],vstart=1,target=hex(word),user_pc=hex(pc),user_elf_sha256=v.sha(d/'test.elf'),sail_pc=hex(spc),sail_elf_sha256=v.sha(d/'sail.elf'),Sail_signature=signature,DUT=arms))
 v.save(out/'NONZERO_VSTART.json',dict(status='PASS',cases=len(proof),sail_commands=len(proof),dut_commands=len(proof)*4,ordinary_credit=0,records=proof,configuration='default Sail; zero_required was never disabled; target PC/raw checked against actual ELF'))
 extra=base/'overlap-supplement';ea=read(extra/'audit/audit.json');es=read(extra/'corpus/summary.json');assert not ea['failures'] and ea['executed_case_checks']==es['planned_executions'] and es['counts']=={'PASS':es['planned_executions']}
 shutil.copy2(extra/'audit/audit.json',out/'OVERLAP_AUDIT.json');shutil.copy2(extra/'DECLARATION.json',out/'OVERLAP_DECLARATION.json')
 manifest=read(root/'manifest.json');main_rows=manifest['cases'];extra_rows=read(extra/'corpus/manifest.json')['cases'];rows=main_rows+extra_rows;results=read(root/'results.json')+read(extra/'corpus/results.json');assert len({c['id'] for c in rows})==len(rows);case={c['id']:c for c in rows};profiles={};counts=collections.Counter((case[r['case']]['mnemonic'],r['arm'],r['status']) for r in results)
 for c in rows:
  profiles.setdefault(c['mnemonic'],set()).add((c['vlen'],c['sew'],c['lmul'],c['dst_eew'],c['vlmax'],c['group_registers']))
 per=[]
 for form,configs in sorted(profiles.items()):
  item=dict(form=form,configurations=len(configs),per_arm={arm:counts[form,arm,'PASS'] for arm in ('Reference','B','M1','M2','BOTH')},main_cases_per_arm=sum(c['mnemonic']==form for c in main_rows),supplemental_cases_per_arm=sum(c['mnemonic']==form for c in extra_rows),build='immutable174',status='PASS',predicate='ordered rational element fold' if 'osum' in form else 'proven exact tree-invariant subsets + bounded specials; arbitrary inexact unordered NOT_COVERED' if 'usum' in form else 'order-invariant minimumNumber/maximumNumber',failure_count=0)
  v.save(out/(form.replace('.','-')+'.json'),item);per.append(item)
 with (out/'PER_FORM.csv').open('w') as stream:
  writer=csv.writer(stream);writer.writerow(['form','arm','status','checks','main_cases','additional_overlap_cases'])
  for item in per:
   for arm,n in item['per_arm'].items():writer.writerow([item['form'],arm,'PASS',n,item['main_cases_per_arm'],item['supplemental_cases_per_arm']])
 v.save(out/'PER_FORM.json',per);v.save(out/'PROFILE_COMPACT.json',[dict(form=form,configs=[dict(zip(('vlen','sew','lmul','accumulator_bits','vlmax','source_regs'),x)) for x in sorted(configs)]) for form,configs in sorted(profiles.items())])
 v.save(out/'FINAL_TOTALS.json',dict(cases=len(rows),units=s['units']+read(extra/'corpus/manifest.json')['units'],forms=6,form_configurations=sum(len(x) for x in profiles.values()),commands=s['commands']+ea['executed_commands'],dut_commands=(s['units']+read(extra/'corpus/manifest.json')['units'])*4,reference_commands=s['units']+read(extra/'corpus/manifest.json')['units'],checks=s['checks']+ea['executed_case_checks'],main_cases=len(main_rows),supplemental_overlap_cases=len(extra_rows),dut_checks=len(rows)*4,per_arm_checks=len(rows),pilot_cases=read(base/'pilot/corpus/summary.json')['planned_cases'],remaining_cases=read(base/'remaining/corpus/summary.json')['planned_cases'],Sail_crosscheck_commands=cross['commands'],Sail_crosscheck_checks=cross['case_checks'],nonzero_vstart_commands=len(proof)*5,nonzero_vstart_cases=len(proof),supplemental_reference_and_trap_ordinary_credit=0,supplemental_overlap_ordinary_cases=len(extra_rows),accepted_build_scope='single immutable174 combines167+171+172; this reduction matrix and original focused fixtures only; broader common-build family rerun NOT_RUN',retained_failures=0,full_controls=controls['effective_rejections'],effective_changed_allowances=controls['effective_changed_allowances'],extra_raw_inventory='NONE'))
 samples=[json.loads(x) for folder in ('monitor','monitor-overlap') for x in (base/folder/'RESOURCE_SAMPLES.jsonl').read_text().splitlines()];own=[];nice=set();aff=set()
 for snap in samples:
  rs=[r for r in snap['rows'] if any('rvv-directed-task174' in x for x in r['args'])];own.append((sum(r['guest'] for r in rs),sum(r['offline'] for r in rs)))
  for r in rs:nice.add(r['nice']);aff.add(r['affinity'])
 v.save(out/'RESOURCES.json',dict(samples=len(samples),own_guest_peak=max(x[0] for x in own),shared_guest_peak=max(x['guests'] for x in samples),own_offline_peak=max(x[1] for x in own),shared_offline_peak=max(x['offline'] for x in samples),minimum_free_bytes=min(x['free_bytes'] for x in samples),nice_values=sorted(nice),affinity_values=sorted(aff),policy=dict(own_guest=8,shared_guest=16,own_build=4,shared_offline=4,own_offline=4,nice=10,affinity='none',reserve=10*1024**3),limits='sampled occupancy only; builds constrained by CLI; integration build/focused fixtures occurred before monitor start'))
 print(s['checks']+ea['executed_case_checks'],controls['effective_rejections'],len(proof),flush=True)
if __name__=='__main__':export(Path(sys.argv[1]),Path(sys.argv[2]))
