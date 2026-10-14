#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reviewer navigation and bounded replay of the existing directed packet protocol."""
import argparse, collections, fcntl, gzip, hashlib, importlib, json, os, shlex, shutil, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
INDEX=ROOT/'docs/rvv-validation/delivery-task182/forms.json.gz'
GENERATORS={'vadd145':'vadd','integer146':'vadd','configuration147':'config','configuration148':'config148','shiftminmax148':'shift148','muldiv149':'muldiv149','carry150':'carry149_next','mergemove151':'mergemove150_next','compare152':'compare151_next','saturation153':'saturation153','saturation153-boundary':'saturation153','rounding153-next':'rounding153_next','scaling155-next':'scaling155_next','narrowing155-next':'narrowing155_next','mac154':'mac152_next','widen154':'widen154_next','wmac156':'wmac156','extend156':'extend156_next','wmac156chunk':'wmac156','fp157':'fp157','fma164':'fma164','fpcompare170':'fpcompare170','fpconvert172':'fpconvert172','fpreduce174':'fpreduce174','fpmerge175':'gaps175','fpslide175':'gaps175','narrow175':'gaps175','fpwiden173':'fpwiden173','fpwiden173-extra':'fpwiden173','fpunary176':'fpunary176'}
FIELDS=('sew','lmul','vlen','mask','vl','vlmax','vstart','ta','ma','emul','frm','vd','vs1','vs2','overlap','nf','eew','index_eew')
def sha(b):return hashlib.sha256(b).hexdigest()
def load(p):
 p=Path(p);return json.loads(gzip.decompress(p.read_bytes()) if p.suffix=='.gz' else p.read_bytes())
def save(p,x):Path(p).write_text(json.dumps(x,indent=2)+'\n')
def form(c):
 op=c.get('mnemonic','vadd');return op if '.' in op or op.startswith('vset') else op+'.'+c['form']
def relocated(path,old,new):
 return Path(new)/Path(path).relative_to(old)
def ranges(indices):
 out=[]
 for i in indices:
  if out and i==out[-1][1]:out[-1][1]=i+1
  else:out.append([i,i+1])
 return out
def accepted_cases(e,cs):
 rr=e.get('accepted_ranges')
 if rr is None:raise ValueError('index lacks accepted selectors; regenerate index')
 indices=[];last=0
 for lo,hi in rr:
  if not (isinstance(lo,int) and isinstance(hi,int) and last<=lo<hi<=len(cs)):raise ValueError('invalid accepted range')
  indices.extend(range(lo,hi));last=hi
 if sha(json.dumps(indices,separators=(',',':')).encode())!=e['accepted_selector_sha256']:raise ValueError('accepted selector identity')
 return [(i,cs[i]) for i in indices]
def matches(c,a):
 length='UNKNOWN'
 if 'vl' in c and 'vlmax' in c:
  length='zero' if c['vl']==0 else 'full' if c['vl']==c['vlmax'] else 'partial' if 0<c['vl']<c['vlmax'] else 'UNKNOWN'
 return form(c)==a.form and all(getattr(a,k) is None or c.get(k)==getattr(a,k) for k in ('sew','lmul','vlen','mask','vstart','vl')) and (a.length is None or length==a.length) and (not a.unit or c['unit']==a.unit)
def select(index,row,a):
 ids=[r['entry'] for r in row['entries']]
 if a.entry and a.entry not in ids:raise ValueError('entry does not own form')
 unavailable=[]
 for entry_id in ([a.entry] if a.entry else ids):
  e=index['entries'][entry_id];original=relocated(e['original'],index['original_root'],a.raw_root)
  try:raw=(original/'manifest.json').read_bytes()
  except FileNotFoundError:
   unavailable.append(entry_id);continue
  if sha(raw)!=e['manifest_sha256']:raise ValueError('manifest identity mismatch '+entry_id)
  cs=json.loads(raw)['cases'];accepted=accepted_cases(e,cs);allowed={i for i,c in accepted}
  selected=[c for i,c in accepted if matches(c,a)]
  units=collections.defaultdict(list);excluded=set()
  for i,c in enumerate(cs):
   units[c['unit']].append(c)
   if i not in allowed:excluded.add(c['unit'])
  for c in selected:
   if c['unit'] in excluded:continue
   group=units[c['unit']]
   return entry_id,e,original,c,group
 raise ValueError('configuration has no complete accepted unit; unavailable entries: '+','.join(unavailable))
def compile_index(a):
 plan=load(a.plan);historical=load(a.historical);rows={r[0]:r for r in historical['rows']}
 assert len(rows)==595 and set(rows)==set(plan['owners'])
 agg={f:dict(form=f,origin='project-authored agent-generated directed tests',historical=dict(batch=r[1],build_sha256=r[2],result=r[3],receipt=historical['receipts'][r[4]],counts=r[5]),final179=None,entries=[],case_count=0,dimensions={k:set() for k in FIELDS},missing_fields=collections.Counter(),length_classes=collections.Counter()) for f,r in rows.items()}
 entries={}
 for e in plan['entries']:
  p=relocated(e['original'],a.original_root,a.raw_root)/'manifest.json';raw=p.read_bytes()
  if sha(raw)!=e['manifest_sha256']:raise ValueError('manifest identity '+str(p))
  m=json.loads(raw);counts=collections.Counter();sample={}
  for i in e['accepted_indices']:
   c=m['cases'][i];f=form(c)
   if f not in agg:raise ValueError('unknown manifest form '+f)
   r=agg[f];counts[f]+=1;r['case_count']+=1
   for k in FIELDS:
    if k in c:r['dimensions'][k].add(json.dumps(c[k],sort_keys=True))
    else:r['missing_fields'][k]+=1
   cl='UNKNOWN'
   if 'vl' in c and 'vlmax' in c:cl='zero' if c['vl']==0 else 'full' if c['vl']==c['vlmax'] else 'partial' if 0<c['vl']<c['vlmax'] else 'outside_vlmax'
   r['length_classes'][cl]+=1
   sample.setdefault(f,dict(manifest_index=i,**{k:c.get(k) for k in ('id','unit',*FIELDS)}))
  if dict(counts)!=e['forms']:raise ValueError('form selector count mismatch '+e['id'])
  entries[e['id']]={k:e[k] for k in ('batch','original','tools','install','family','manifest_sha256','build_commands_sha256','flags','tool_pins')}
  entries[e['id']]['generator_module']=e['install'] or GENERATORS.get(e['family'],'UNKNOWN')
  entries[e['id']]['source_test']='manifest unit/test.S; test.elf + build-commands.json; same-ELF Spike or Sail entry/exit adapter'
  entries[e['id']]['accepted_ranges']=ranges(e['accepted_indices'])
  entries[e['id']]['accepted_selector_sha256']=sha(json.dumps(e['accepted_indices'],separators=(',',':')).encode())
  for f in counts:
   agg[f]['entries'].append(dict(entry=e['id'],cases=counts[f],example=sample[f]))
 for f,r in agg.items():
  receipt=r['historical']['receipt']
  if receipt.startswith('../rvdbt-directed-session3-20261013/'):
   receipt=receipt.split('../rvdbt-directed-session3-20261013/',1)[1];r['historical']['receipt_read_command']='git show 481bfb56362952551be7367fc12d48abb198074b:'+receipt
  elif receipt.startswith('../'):
   r['historical']['receipt_read_command']='EXTERNAL_ACCEPTED_RAW_LOCATOR; retained original Task155 receipt; final179 entry receipt joined'
  else:r['historical']['receipt_read_command']='git show 9b768b6:'+receipt
  r['dimensions']={k:sorted([json.loads(x) for x in v],key=lambda x:(str(type(x)),x)) if v else None for k,v in r['dimensions'].items()}
  r['missing_fields']=dict(r['missing_fields']);r['length_classes']=dict(r['length_classes'])
  r['checked_state']={'batch_review':'docs/rvv-validation/directed-task'+str(r['historical']['batch'])+'/', 'checked_endpoints':['initialized and final 32 vector registers, including non-destination preservation and permitted agnostic sets','vl, vtype, vlenb, vstart, vxrm, vxsat, vcsr, fflags, frm, fcsr; applicable expected effects'], 'scalar_scope':'captured x8; x8/x9 for mask/permutation/reduction/memory/prefix/transfers; raw fs0 for FP packets; predicate specifies destination/preservation', 'memory_scope':'finite initialized/captured buffer including store winner sets and load preservation for memory batches165/166/168; otherwise not a memory-access proof', 'predicate':'vadd.check_isa + vadd.check_reference; install module when specified by entry','scope':'Consult the pinned predicate and batch review; captured fields alone are not checked state','unestablished':'arbitrary intermediate state, full access history and restart correctness'}
  r['independent_oracle']={'reference':'retained executed Spike/Sail packets; exact per-unit command and execution.json required','source':'batch review and source records; no DUT-derived golden','configuration':'entry-specific reference command; nonzero vstart is not a universal Spike claim'}
  r['external_original_cases']={'reader':'scripts/rvv_scope_report.py --navigation docs/rvv-validation/all-form-records/navigation.json.gz --form '+f+' --output OUT','index':'docs/rvv-validation/all-form-records/navigation.json.gz','result':'separate external acceptance; no PASS inferred from project receipt'}
  r['replay_command']='python3 scripts/rvv_verify.py command --form '+f+' --raw-root RAW --tools TOOLS --dut DUT --output NEW'
 out={'schema':1,'forms':595,'historical_scope':'finite mixed builds only','P3':'docs/rvv-validation/directed-task180/FINAL_TOTALS.json','final179':None,'selection_plan_sha256':sha(Path(a.plan).read_bytes()),'original_root':str(a.original_root),'dimension_interpretation':'exact marginal values of selected manifest rows; NOT a Cartesian product or runtime-observed configuration; missing fields remain unknown','entries':entries,'rows':[agg[f] for f in sorted(agg)]}
 join_final(out,plan,a.results,a.receipts,a.build_manifest,a.final_result)
 Path(a.output).write_bytes(gzip.compress(json.dumps(out,separators=(',',':')).encode(),mtime=0));print('generated 595 forms;',sum(r['case_count'] for r in agg.values()),'selected manifest cases')
def join_final(index,plan,results_path,receipts_path,build_path,final_path):
 results=load(results_path);receipts=load(receipts_path);build=load(build_path);final=load(final_path)
 focused=collections.Counter();denials=collections.Counter()
 for suite in final['focused']:
  for f,counts in suite['forms'].items():
   focused[f]+=counts.get('PASS',0);denials[f]+=counts.get('EXPECTED_DENIAL_CONTROL',0)
 by_form={r['form']:r for r in results};by_entry={r['entry']:r for r in receipts}
 if len(by_form)!=595 or len(results)!=595 or set(by_form)!={r['form'] for r in index['rows']}:raise ValueError('final form coverage')
 if len(by_entry)!=102 or len(receipts)!=102 or set(by_entry)!=set(index['entries']):raise ValueError('final entry coverage')
 executable=build['artifacts']['build/bin/elfrun']
 if executable!=plan['build'] or executable!=final['build_sha256'] or final['status']!='PASS_FINITE_SCOPE':raise ValueError('final build identity')
 if sum(r['passed'] for r in results)!=final['directed_dut_packets']:raise ValueError('final positive total')
 for e in plan['entries']:
  receipt=by_entry[e['id']]
  if receipt['manifest_sha256']!=e['manifest_sha256'] or receipt['accepted_cases']!=len(e['accepted_indices']) or receipt['original']!=e['original']:raise ValueError('final entry identity '+e['id'])
  index['entries'][e['id']]['final179_receipt']=receipt
 for row in index['rows']:
  r=by_form[row['form']]
  if r['build_sha256']!=executable or r['result']!='PASS_FINITE_SCOPE' or r['failed'] or r['blocked']:raise ValueError('final result '+row['form'])
  if 4*r['cases_per_arm']!=4*row['case_count']+focused[row['form']] or not r['completed']==r['passed']==r['planned']==4*row['case_count']+focused[row['form']]:raise ValueError('final count '+row['form'])
  if sorted(e for e in r['source_entries'] if not e.startswith('focused:'))!=sorted(e['entry'] for e in row['entries']):raise ValueError('final selector join '+row['form'])
  row['final179']=dict(r,ordinary_cases_per_arm=row['case_count'],ordinary_positive_dut_checks=4*row['case_count'],focused_positive_dut_checks=focused[row['form']],focused_denial_controls=denials[row['form']])
 index['final179']={'result':'PASS_FINITE_SCOPE','build_sha256':executable,'library_sha256':build['artifacts']['build/lib/libdbtjitshared.so'],'build_configuration':build['configuration'],'build_manifest':'docs/rvv-validation/directed-task181/BUILD_MANIFEST_179.json','cases_per_arm':sum(r['case_count'] for r in index['rows']),'ordinary_positive_dut_checks':4*sum(r['case_count'] for r in index['rows']),'focused_positive_dut_checks':sum(focused.values()),'focused_denial_controls':sum(denials.values()),'P3_separate':True,'rebuilt_executable_receipt_credit':False}
 index['final_evidence_pins']={str(p):sha(Path(p).read_bytes()) for p in (results_path,receipts_path,build_path,final_path)}

def export_unit(index,row,entry_id,e,original,group,a):
 # Verify the large source once; the resulting selected package is independently usable.
 sys.path.insert(0,str(a.checkout/'scripts/rvv/directed'));import storage149 as storage
 b=original/'build-commands.json'
 if sha(b.read_bytes())!=e['build_commands_sha256']:raise ValueError('build records identity')
 unit=group[0]['unit'];builds=[r for r in load(b) if Path(r['command'][-1]).parent.name==unit]
 files={}
 for name in ('test.S','test.elf'):
  files[unit+'/'+name]=storage.verify(original/unit/name)
 for arm in (a.arm,'Reference'):
  for name in (('command.json','execution.json','checks.json','packets.bin') if arm=='Reference' else ('command.json',)):
   path='runs/'+unit+'/'+arm+'/'+name
   files[path]=storage.verify(original/path)
 for r in builds:
  if r['returncode']!=0:raise ValueError('failed selected build')
  if Path(r['command'][-1]).name=='test.elf' and sha(files[unit+'/test.elf'])!=r['elf_sha256']:raise ValueError('guest identity')
 rr=load(original/'runs'/unit/'Reference'/'execution.json')
 if rr['returncode']!=0 or rr['timeout']:raise ValueError('failed reference execution')
 if sha(files['runs/'+unit+'/Reference/packets.bin'])!=rr['stdout_sha256']:raise ValueError('reference stream identity')
 refs=load(original/'runs'/unit/'Reference'/'checks.json');passed={r['case'] for r in refs if r['status']=='PASS'}
 if any(c['id'] not in passed for c in group):raise ValueError('unaccepted reference unit')
 files['manifest.json']=json.dumps(dict(project_tests=True,family=e['family'],cases=group,units=1)).encode()
 files['build-commands.json']=json.dumps(builds).encode()
 # Retain every pinned snapshot source/data dependency, including paths outside tools.
 for name,h in e['tool_pins'].items():
  path=relocated(name,index['original_root'],a.raw_root);raw=path.read_bytes()
  if sha(raw)!=h:raise ValueError('source snapshot identity '+name)
  files['__source__/'+str(Path(name).relative_to(index['original_root']))]=raw
 report=dict(entry=entry_id,unit=unit,cases=len(group),source_manifest_sha256=e['manifest_sha256'],source_selector_sha256=e['accepted_selector_sha256'],files={n:dict(bytes=len(v),sha256=sha(v)) for n,v in files.items()},bytes=sum(map(len,files.values())),scope='one complete accepted unit; retained ELF/reference, exact pinned source/data; no installed binary dependencies')
 if a.action=='preflight':print(json.dumps(report,indent=2));return
 a.output.mkdir();rawroot=a.output/'raw';target=relocated(e['original'],index['original_root'],rawroot)
 for n,raw in files.items():
  dest=rawroot/n.removeprefix('__source__/') if n.startswith('__source__/') else target/n
  dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
 subset=json.loads(json.dumps(index));ee=subset['entries'][entry_id];ee['manifest_sha256']=sha(files['manifest.json']);ee['build_commands_sha256']=sha(files['build-commands.json']);ee['accepted_ranges']=[[0,len(group)]];ee['accepted_selector_sha256']=sha(json.dumps(list(range(len(group))),separators=(',',':')).encode())
 subset['entries']={entry_id:ee};rr=json.loads(json.dumps(row));rr['entries']=[r for r in rr['entries'] if r['entry']==entry_id];subset['rows']=[rr];subset['forms']=1;subset['export_provenance']=report
 (a.output/'index.json.gz').write_bytes(gzip.compress(json.dumps(subset,separators=(',',':')).encode(),mtime=0));save(a.output/'EXPORT.json',report)
 print(json.dumps(dict(package=str(a.output),raw_root=str(rawroot),index=str(a.output/'index.json.gz'),tools=str(relocated(e['tools'],index['original_root'],rawroot)),bytes=report['bytes']),indent=2))
def census():
 guests=[];offline=[];external_offline=[];task181_live=False
 for p in Path('/proc').iterdir():
  if not p.name.isdecimal():continue
  try:
   args=[x.decode(errors='replace') for x in (p/'cmdline').read_bytes().split(b'\0') if x]
   if not args:continue
   exe=Path(args[0]).name
   owner=any('rvv-task181' in x for x in args[1:])
   if exe.startswith('python') and owner:task181_live=True
   if exe in ('elfrun','spike','sail_riscv_sim'):guests.append(int(p.name))
   if exe.startswith('python') and len(args)>1:
    name=Path(args[1]).name;is_audit=(name=='replay.py' and len(args)>2 and args[2]=='audit')
    if is_audit or any(x in name for x in ('audit','controls','reject_','crosscheck','finalize')):
     if is_audit and (p/'task'/p.name/'children').read_text().strip():continue
     offline.append(int(p.name))
     if not owner:external_offline.append(int(p.name))
  except (OSError,ProcessLookupError):pass
 return dict(guests=guests,offline=offline,task181_live=task181_live,offline_budget_used=(2+len(external_offline)) if task181_live else len(offline),policy='Reserve Task181 two predicate slots, including online checks invisible in process names')
def validate_packets(v,group,out,ref,rec):
 if rec['returncode']!=0 or rec['timeout'] or len(out)!=len(ref):raise ValueError('failed or missing DUT output: '+json.dumps(rec))
 size=v.packet_size(group[0])
 if len(ref)!=size*len(group):raise ValueError('reference packet extent')
 result=[]
 for i,c in enumerate(group):
  packet=out[i*size:(i+1)*size];rp=ref[i*size:(i+1)*size];v.check_isa(c,rp,0,False);v.check_isa(c,packet,rec['returncode'],rec['timeout']);v.check_reference(c,packet,rp);result.append(dict(case=c['id'],status='PASS'))
 return result
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['generate','list','show','command','smoke','export','preflight']);p.add_argument('--index',type=Path,default=INDEX);p.add_argument('--checkout',type=Path,default=ROOT);p.add_argument('--form');p.add_argument('--entry');p.add_argument('--unit');p.add_argument('--sew',type=int);p.add_argument('--lmul');p.add_argument('--vl',type=int);p.add_argument('--length',choices=['zero','partial','full']);p.add_argument('--vlen',type=int);p.add_argument('--mask');p.add_argument('--vstart',type=int)
 for k in ('plan','historical','results','receipts','build-manifest','final-result','raw-root','original-root','tools','dut','dut-lib','spike','pk','sail','compiler','link','output'):p.add_argument('--'+k,type=Path)
 p.add_argument('--library-path',default='');p.add_argument('--arm',choices=['B','M1','M2','BOTH'],default='B');p.add_argument('--timeout',type=int,default=60);a=p.parse_args()
 if a.action=='generate':
  if not all((a.plan,a.historical,a.raw_root,a.original_root,a.output,a.results,a.receipts,a.build_manifest,a.final_result)):p.error('generate requires plan/historical/raw-root/original-root/output/results/receipts/build-manifest/final-result')
  compile_index(a);return
 index=load(a.index)
 if a.action=='list':print('\n'.join(r['form'] for r in index['rows']));return
 row=next((r for r in index['rows'] if r['form']==a.form),None)
 if row is None:p.error('select a known --form')
 if a.action=='show':print(json.dumps(row,indent=2));return
 if not all((a.raw_root,a.output)) or (a.action in ('command','smoke') and not a.dut):p.error('requires --raw-root --output; command/smoke also requires --dut')
 if a.output.exists():raise ValueError('output already exists; never overwrite')
 entry_id,e,original,selected_case,group=select(index,row,a)
 unit=selected_case['unit']
 if len({c['vlen'] for c in group})!=1:raise ValueError('mixed VLEN unit')
 if a.action in ('export','preflight'):
  export_unit(index,row,entry_id,e,original,group,a);return
 recorded=load(original/'runs'/unit/a.arm/'command.json');d=a.output/'run';fs=a.output/'fs';cache=a.output/'cache';cmd=[str(a.dut),*recorded[1:]]
 for i,x in enumerate(cmd):
  for flag,target in [('fsroot',fs),('cache',cache),('dump-tbmap',d/'tbmap'),('dump-tbcode',d/'tbcode'),('rvv-pc-census-out',d/'pc-census.csv')]:
   if x.startswith('--'+flag+'='):cmd[i]='--'+flag+'='+str(target)
 builds=load(original/'build-commands.json');buildrow=next(r for r in builds if Path(r['command'][-1]).parent.name==unit and Path(r['command'][-1]).name=='test.elf');build_command=list(buildrow['command'])
 if a.compiler:build_command[0]=str(a.compiler)
 if a.link:
  for j,arg in enumerate(build_command):
   if arg=='-T':build_command[j+1]=str(a.link)
   elif arg.startswith('-Wl,-T,'):build_command[j]='-Wl,-T,'+str(a.link)
 refcmd=load(original/'runs'/unit/'Reference'/'command.json')
 if a.sail and any('--rv32'==x for x in refcmd):refcmd[0]=str(a.sail)
 elif a.spike:
  refcmd[0]=str(a.spike)
  if a.pk:refcmd[2]=str(a.pk)
 detail=dict(build_recipe=build_command,reference_recipe=refcmd,recipes_scope='historical inspection records; fresh vadd uses scripts/rvv_reproduce.py; other families require selected retained packages',form=a.form,entry=entry_id,unit=unit,unit_cases=len(group),selected_case=selected_case,command=cmd,shell='nice -n 10 '+shlex.join(cmd),reference_reused=str(original/'runs'/unit/'Reference'),new_reference_calls=0,new_build_calls=0,tools=str(a.tools or a.checkout/'scripts/rvv/directed'),toolchain=str(a.compiler) if a.compiler else 'NOT_NEEDED_REUSE',spike=str(a.spike) if a.spike else 'NOT_NEEDED_REUSE',sail=str(a.sail) if a.sail else 'NOT_NEEDED_REUSE')
 if a.action=='command':print(json.dumps(detail,indent=2));return
 if os.getpriority(os.PRIO_PROCESS,0)!=10:raise ValueError('smoke requires nice -n 10')
 if not 1<=a.timeout<=120:raise ValueError('smoke timeout must be 1..120')
 if a.tools:
  expected={Path(name).name:h for name,h in e['tool_pins'].items() if Path(name).parent==Path(e['tools']) and Path(name).suffix=='.py'}
  if 'vadd.py' not in expected:raise ValueError('no established vadd snapshot pin for supplied --tools')
  for name,h in expected.items():
   if sha((a.tools/name).read_bytes())!=h:raise ValueError('tool snapshot identity '+name)
 sys.path.insert(0,str(a.tools or a.checkout/'scripts/rvv/directed'));v=importlib.import_module('vadd')
 if e['install']:importlib.import_module(e['install']).install(v)
 elif not a.tools and e['family'] in ('rounding153-next','scaling155-next','narrowing155-next','saturation153','saturation153-boundary'):importlib.import_module('delivery155_adapter').install(v)
 if not hasattr(v,'check_isa'):
  if not hasattr(v,'check'):raise ValueError('checker snapshot lacks required check API')
  v.check_isa=lambda c,raw,rc=0,timeout=False:v.check(c,raw,rc,timeout)
  v.check_reference=lambda c,raw,ref:v.check(c,raw,0,False,ref)
 if len(group)>128:raise ValueError('bounded smoke permits at most 128 cases in one unit')
 lib=a.dut_lib or a.dut.parent.parent/'lib/libdbtjitshared.so'
 pin='8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281';libpin='79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af'
 if sha(a.dut.read_bytes())!=pin or sha(lib.read_bytes())!=libpin:raise ValueError('smoke requires immutable179 DUT/library')
 b=original/'build-commands.json'
 if sha(b.read_bytes())!=e['build_commands_sha256']:raise ValueError('build records identity')
 builds=load(b);guest=v.storage.verify(original/unit/'test.elf');gb=next(r for r in builds if Path(r['command'][-1]).parent.name==unit and Path(r['command'][-1]).name=='test.elf')
 if gb['returncode']!=0 or sha(guest)!=gb['elf_sha256']:raise ValueError('guest identity')
 refdir=original/'runs'/unit/'Reference';rr=load(refdir/'execution.json')
 if rr['returncode']!=0 or rr['timeout']:raise ValueError('failed reference execution')
 ref=v.storage.verify(refdir/'packets.bin');size=v.packet_size(group[0])
 if len(ref)!=size*len(group):raise ValueError('reference packet extent')
 # Match historical accepted reference checks, rather than treating all source rows as PASS.
 checks=load(refdir/'checks.json');accepted={r['case'] for r in checks if r['status']=='PASS'}
 if any(c['id'] not in accepted for c in group):raise ValueError('smoke unit contains unaccepted reference rows; select another unit')
 predicate_lock=None
 for n in range(2):
  lock=open('/tmp/rvv-task181-predicate-%d.lock'%n,'a')
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:lock.close();continue
  predicate_lock=lock;break
 if predicate_lock is None:raise RuntimeError('Task181 predicate slots occupied; retry later')
 admission_lock=open('/tmp/rvv-shared-admission.lock','a');fcntl.flock(admission_lock,fcntl.LOCK_EX)
 snap=census()
 if len(snap['guests'])>8 or snap['offline_budget_used']>2:raise RuntimeError('shared capacity unavailable; '+json.dumps(snap))
 if shutil.disk_usage(a.output.parent).free<10*1024**3+64*1024**2:raise RuntimeError('10GiB storage reserve')
 a.output.mkdir();fs.mkdir();cache.mkdir();(fs/'t.elf').write_bytes(guest);save(a.output/'selection.json',detail);save(a.output/'resources.json',snap)
 env=dict(os.environ,LD_LIBRARY_PATH=str(lib.parent)+(':'+a.library_path if a.library_path else ''));rec=v.execute(cmd,d,env,a.timeout)
 fcntl.flock(admission_lock,fcntl.LOCK_UN);admission_lock.close()
 out=v.storage.verify(d/'stdout')
 result=validate_packets(v,group,out,ref,rec)
 if sha(a.dut.read_bytes())!=pin or sha(lib.read_bytes())!=libpin:raise ValueError('DUT/library changed during smoke')
 save(a.output/'result.json',dict(status='PASS_BOUNDED_UNIT',form=a.form,arm=a.arm,checks=len(result),guest_calls=1,reference_calls=0,ELF_rebuilds=0,DUT_sha256=pin,library_sha256=libpin,guest_sha256=sha(guest),reference_sha256=sha(ref),output_sha256=sha(out),reference_command=load(refdir/'command.json'),checker_sha256=sha(Path(v.__file__).read_bytes()),checker_modules={str(Path(m.__file__)):sha(Path(m.__file__).read_bytes()) for m in list(sys.modules.values()) if getattr(m,'__file__',None) and Path(m.__file__).resolve().is_relative_to(Path(v.__file__).resolve().parent) and Path(m.__file__).suffix=='.py'},cases=result))
 predicate_lock.close()
 print('PASS_BOUNDED_UNIT',unit,len(result),'checks')
if __name__=='__main__':
 try:main()
 except (OSError,ValueError,RuntimeError,AssertionError,ImportError,StopIteration) as e:print('ERROR:',str(e),file=sys.stderr);sys.exit(1)
