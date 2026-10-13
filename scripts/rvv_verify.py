#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reviewer navigation and bounded replay of the existing directed packet protocol."""
import argparse, collections, fcntl, gzip, hashlib, importlib, json, os, shlex, shutil, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
INDEX=ROOT/'docs/rvv-validation/delivery-task182/forms.json.gz'
GENERATORS={'vadd145':'vadd','integer146':'vadd','configuration147':'config','configuration148':'config148','shiftminmax148':'shift148','muldiv149':'muldiv149','carry150':'carry149_next','mergemove151':'mergemove150_next','compare152':'compare151_next','saturation153':'saturation153','saturation153-boundary':'saturation153','rounding153-next':'rounding153_next','scaling155-next':'scaling155_next','narrowing155-next':'narrowing155_next','mac154':'mac152_next','widen154':'widen154_next','wmac156':'wmac156','extend156':'extend156_next','wmac156chunk':'wmac156','fp157':'fp157','fma164':'fma164','fpcompare170':'fpcompare170','fpconvert172':'fpconvert172','fpreduce174':'fpreduce174','fpmerge175':'gaps175','fpslide175':'gaps175','narrow175':'gaps175','fpwiden173':'fpwiden173','fpwiden173-extra':'fpwiden173','fpunary176':'fpunary176'}
FIELDS=('sew','lmul','vlen','mask','vl','vlmax','vstart','ta','ma','emul','frm')
def sha(b):return hashlib.sha256(b).hexdigest()
def load(p):
 p=Path(p);return json.loads(gzip.decompress(p.read_bytes()) if p.suffix=='.gz' else p.read_bytes())
def save(p,x):Path(p).write_text(json.dumps(x,indent=2)+'\n')
def form(c):
 op=c.get('mnemonic','vadd');return op if '.' in op or op.startswith('vset') else op+'.'+c['form']
def relocated(path,old,new):
 return Path(new)/Path(path).relative_to(old)
def compile_index(a):
 plan=load(a.plan);historical=load(a.historical);rows={r[0]:r for r in historical['rows']}
 assert len(rows)==595 and set(rows)==set(plan['owners'])
 agg={f:dict(form=f,origin='project-authored agent-generated directed tests',historical=dict(batch=r[1],build_sha256=r[2],result=r[3],receipt=historical['receipts'][r[4]],counts=r[5]),final179='PENDING_TASK181_NOT_IMPORTED',entries=[],case_count=0,dimensions={k:set() for k in FIELDS},missing_fields=collections.Counter(),length_classes=collections.Counter()) for f,r in rows.items()}
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
   sample.setdefault(f,{k:c.get(k) for k in ('id','unit',*FIELDS)})
  if dict(counts)!=e['forms']:raise ValueError('form selector count mismatch '+e['id'])
  entries[e['id']]={k:e[k] for k in ('batch','original','tools','install','family','manifest_sha256','build_commands_sha256','flags','tool_pins')}
  entries[e['id']]['generator_module']=e['install'] or GENERATORS.get(e['family'],'UNKNOWN')
  entries[e['id']]['source_test']='manifest unit/test.S; test.elf + build-commands.json; same-ELF Spike or Sail entry/exit adapter'
  entries[e['id']]['accepted_selector_sha256']=sha(json.dumps(e['accepted_indices'],separators=(',',':')).encode())
  for f in counts:
   agg[f]['entries'].append(dict(entry=e['id'],cases=counts[f],example=sample[f]))
 for f,r in agg.items():
  receipt=r['historical']['receipt']
  if receipt.startswith('../rvdbt-directed-session3-20261013/'):
   receipt=receipt.split('../rvdbt-directed-session3-20261013/',1)[1];r['historical']['receipt_read_command']='git show 481bfb56362952551be7367fc12d48abb198074b:'+receipt
  elif receipt.startswith('../'):
   r['historical']['receipt_read_command']='EXTERNAL_ACCEPTED_RAW_LOCATOR; Task155 committed delivery pending'
  else:r['historical']['receipt_read_command']='git show 9b768b6:'+receipt
  r['dimensions']={k:sorted([json.loads(x) for x in v],key=lambda x:(str(type(x)),x)) if v else None for k,v in r['dimensions'].items()}
  r['missing_fields']=dict(r['missing_fields']);r['length_classes']=dict(r['length_classes'])
  r['checked_state']={'batch_review':'docs/rvv-validation/directed-task'+str(r['historical']['batch'])+'/', 'checked_endpoints':['initialized and final 32 vector registers, including non-destination preservation and permitted agnostic sets','vl, vtype, vlenb, vstart, vxrm, vxsat, vcsr, fflags, frm, fcsr; applicable expected effects'], 'scalar_scope':'captured x8; x8/x9 for mask/permutation/reduction/memory/prefix/transfers; raw fs0 for FP packets; predicate specifies destination/preservation', 'memory_scope':'finite initialized/captured buffer including store winner sets and load preservation for memory batches165/166/168; otherwise not a memory-access proof', 'predicate':'vadd.check_isa + vadd.check_reference; install module when specified by entry','scope':'Consult the pinned predicate and batch review; captured fields alone are not checked state','unestablished':'arbitrary intermediate state, full access history and restart correctness'}
  r['independent_oracle']={'reference':'retained executed Spike/Sail packets; exact per-unit command and execution.json required','source':'batch review and source records; no DUT-derived golden','configuration':'entry-specific reference command; nonzero vstart is not a universal Spike claim'}
  r['external_original_cases']={'reader':'scripts/rvv_scope_report.py --navigation docs/rvv-validation/all-form-records/navigation.json.gz --form '+f+' --output OUT','index':'docs/rvv-validation/all-form-records/navigation.json.gz','result':'separate external acceptance; no PASS inferred from project receipt'}
  r['replay_command']='python3 scripts/rvv_verify.py command --form '+f+' --raw-root RAW --tools TOOLS --dut DUT --output NEW'
 out={'schema':1,'forms':595,'historical_scope':'finite mixed builds only','P3':'docs/rvv-validation/directed-task180/FINAL_TOTALS.json','final179':'PENDING_TASK181_NOT_IMPORTED','selection_plan_sha256':sha(Path(a.plan).read_bytes()),'original_root':str(a.original_root),'dimension_interpretation':'exact marginal values of selected manifest rows; NOT a Cartesian product or runtime-observed configuration; missing fields remain unknown','entries':entries,'rows':[agg[f] for f in sorted(agg)]}
 Path(a.output).write_bytes(gzip.compress(json.dumps(out,separators=(',',':')).encode(),mtime=0));print('generated 595 forms;',sum(r['case_count'] for r in agg.values()),'selected manifest cases')
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
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['generate','list','show','command','smoke']);p.add_argument('--index',type=Path,default=INDEX);p.add_argument('--checkout',type=Path,default=ROOT);p.add_argument('--form');p.add_argument('--entry');p.add_argument('--unit');p.add_argument('--sew',type=int);p.add_argument('--lmul');p.add_argument('--vl',type=int);p.add_argument('--length',choices=['zero','partial','full']);p.add_argument('--vlen',type=int);p.add_argument('--mask');p.add_argument('--vstart',type=int)
 for k in ('plan','historical','raw-root','original-root','tools','dut','dut-lib','spike','pk','sail','compiler','link','output'):p.add_argument('--'+k,type=Path)
 p.add_argument('--library-path',default='');p.add_argument('--arm',choices=['B','M1','M2','BOTH'],default='B');p.add_argument('--timeout',type=int,default=60);a=p.parse_args()
 if a.action=='generate':
  if not all((a.plan,a.historical,a.raw_root,a.original_root,a.output)):p.error('generate requires plan/historical/raw-root/original-root/output')
  compile_index(a);return
 index=load(a.index)
 if a.action=='list':print('\n'.join(r['form'] for r in index['rows']));return
 row=next((r for r in index['rows'] if r['form']==a.form),None)
 if row is None:p.error('select a known --form')
 if a.action=='show':print(json.dumps(row,indent=2));return
 if not all((a.raw_root,a.dut,a.output)):p.error('command/smoke requires --raw-root --dut --output')
 if a.output.exists():raise ValueError('output already exists; never overwrite')
 ids=[r['entry'] for r in row['entries']]
 entry_id=a.entry or ids[0]
 if entry_id not in ids:raise ValueError('entry does not own form')
 e=index['entries'][entry_id];original=relocated(e['original'],index['original_root'],a.raw_root);manifest=original/'manifest.json';raw=manifest.read_bytes()
 if sha(raw)!=e['manifest_sha256']:raise ValueError('manifest identity mismatch')
 cs=json.loads(raw)['cases'];selected=[c for c in cs if form(c)==a.form and all(getattr(a,k) is None or c.get(k)==getattr(a,k) for k in ('sew','lmul','vlen','mask','vstart','vl')) and (a.length is None or ('zero' if c.get('vl')==0 else 'full' if c.get('vl')==c.get('vlmax') else 'partial' if 0<c.get('vl',-1)<c.get('vlmax',-1) else 'UNKNOWN')==a.length) and (not a.unit or c['unit']==a.unit)]
 if not selected:raise ValueError('configuration has no manifest rows')
 unit=selected[0]['unit'];group=[c for c in cs if c['unit']==unit]
 if len({c['vlen'] for c in group})!=1:raise ValueError('mixed VLEN unit')
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
 detail=dict(build_recipe=build_command,reference_recipe=refcmd,recipes_scope='historical build/reference recipes for inspection; smoke reuses inputs; relocate remaining source/output arguments before rebuilding',form=a.form,entry=entry_id,unit=unit,unit_cases=len(group),selected_case=selected[0],command=cmd,shell='nice -n 10 '+shlex.join(cmd),reference_reused=str(original/'runs'/unit/'Reference'),new_reference_calls=0,new_build_calls=0,tools=str(a.tools or a.checkout/'scripts/rvv/directed'),toolchain=str(a.compiler) if a.compiler else 'NOT_NEEDED_REUSE',spike=str(a.spike) if a.spike else 'NOT_NEEDED_REUSE',sail=str(a.sail) if a.sail else 'NOT_NEEDED_REUSE')
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
 print('PASS_BOUNDED_UNIT',unit,len(result),'checks')
if __name__=='__main__':
 try:main()
 except (OSError,ValueError,RuntimeError,AssertionError,ImportError,StopIteration) as e:print('ERROR:',str(e),file=sys.stderr);sys.exit(1)
