"""Bounded xbd experiment. No guest generation, build, reference execution or retries."""
import hashlib, json, os, pathlib, re, resource, subprocess, sys, time
P=pathlib.Path
out=P(sys.argv[1]); out.mkdir(exist_ok=False)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
assert os.getpriority(os.PRIO_PROCESS,0)==10
old=P('/home/vick/rvdbt-exception-task186'); new=P('/home/vick/rvv-long-task192')
engines={'retained191':old/'build/bin/elfrun','fixed192':new/'build/bin/elfrun'}
def save(p,x): p.write_text(json.dumps(x,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def shell(args):return subprocess.check_output(args,text=True)
def observe():
 return dict(time=time.time(),load=os.getloadavg(),free_bytes=__import__('shutil').disk_usage(out).free,proc_stat=P('/proc/stat').read_text(),processes=shell(['ps','-eLo','pid,tid,ni,psr,pcpu,stat,comm']),cpuinfo=P('/proc/cpuinfo').read_text(),affinity=sorted(os.sched_getaffinity(0)))
def ticks():
 return {int(x.split()[0][3:]):list(map(int,x.split()[1:])) for x in P('/proc/stat').read_text().splitlines() if re.match(r'cpu\d+ ',x)}
a=ticks();time.sleep(1);b=ticks()
util={c:1-(b[c][3]-a[c][3])/(sum(b[c])-sum(a[c]) or 1) for c in a}
siblings={c:list(map(int,P(f'/sys/devices/system/cpu/cpu{c}/topology/thread_siblings_list').read_text().strip().split(','))) for c in a}
cpu=min(os.sched_getaffinity(0),key=lambda c:sum(util[s] for s in siblings[c]))
assert max(util[s] for s in siblings[cpu])<.1,'No idle sibling pair: stop, no retry'
save(out/'environment-before.json',dict(observe(),cpu=cpu,siblings=siblings[cpu],one_second_utilization=util))
# Compare compiler/build flags, link libraries, source boundaries and runtime resolution before any guest run.
identities={}; admin=out/'administrative';admin.mkdir()
for label,root in [('retained191',old),('fixed192',new)]:
 for path in ['CMakeCache.txt','compile_commands.json','dbt/CMakeFiles/dbtstatic.dir/flags.make','dbt/CMakeFiles/elfrun.dir/link.txt']:
  (admin/(label+'-'+path.replace('/','__'))).write_bytes((root/'build'/path).read_bytes())
 for path in ['bin/elfrun','lib/libdbtstatic.a','lib/libdbtjitshared.so','lib/libasmjit.a']:identities[str(root/'build'/path)]=sha(root/'build'/path)
 (admin/(label+'-ldd.txt')).write_text(shell(['env','LD_LIBRARY_PATH='+str(root/'build/lib'),'ldd',str(engines[label])]))
 for path in ['dbt/execute.cpp','dbt/qmc/qcg/qcg.cpp','dbt/elfrun.cpp']:
  (admin/(label+'-'+path.replace('/','__'))).write_bytes((root/'source'/path).read_bytes())
assert identities[str(engines['retained191'])]=='37a25624345214d97e3691cfd9f951166abfe92419ce2bbeca9c786b68227c14'
assert identities[str(engines['fixed192'])]=='908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4'
for lib in ('libdbtjitshared.so','libasmjit.a'):assert sha(old/'build/lib'/lib)==sha(new/'build/lib'/lib)
for path in ['dbt/CMakeFiles/dbtstatic.dir/flags.make','dbt/CMakeFiles/elfrun.dir/link.txt']:
 assert (old/'build'/path).read_text().replace(str(old),'{ROOT}')==(new/'build'/path).read_text().replace(str(new),'{ROOT}')
for path in ['dbt/execute.cpp','dbt/qmc/qcg/qcg.cpp','dbt/elfrun.cpp']:assert sha(old/'source'/path)==sha(new/'source'/path)
expected=json.loads((new/'SOURCE191.json').read_text());diff=[]
for path,h in expected.items():
 assert sha(old/'source'/path)==h
 if sha(new/'source'/path)!=h:diff.append(path)
save(out/'comparability.json',dict(identities=identities,source_files=len(expected),source_differences=diff))
sys.path[:0]=[str(old/'task191-tools'),str(new/'tools')]
import vadd as v, sequences177 as s
small='integer-w1024-e32-m1-alias-zero';large='long192-int-w4096-e8-m8'
selection=next(x for x in json.loads((old/'task191/SEQUENCE_SELECTION.json').read_text()) if x['unit']==small)
workloads=[('small',small,selection['cases'],old/'task191/sequence-inputs'/small/'test.elf',old/'task191/sequence-inputs'/small/'reference.bin'),('large',large,[x for x in json.loads((new/'baseline-int/manifest.json').read_text())['cases'] if x['unit']==large],new/'baseline-int'/large/'test.elf',new/'baseline-int/runs'/large/'Reference/packets.bin')]
rows=[]
for name,unit,cases,elf,ref in workloads:
 elfbytes=v.storage.verify(elf);answer=v.storage.verify(ref);size=v.packet_size(cases[0])
 assert len(answer)==size*len(cases)
 for arm in ('B','BOTH'):
  original=json.loads((old/'task191/sequences'/unit/arm/'capture/execution.json').read_text())['command'] if name=='small' else json.loads((new/'baseline-int/runs'/unit/arm/'command.json').read_text())
  save(out/(name+'-'+arm+'-original.json'),original)
  for pair in range(1,6):
   for label in (('retained191','fixed192') if pair%2 else ('fixed192','retained191')):
    d=out/f'{name}-{arm}-{pair}-{label}';d.mkdir();(d/'fs').mkdir();(d/'cache').mkdir();(d/'fs/t.elf').write_bytes(elfbytes)
    flags=[]
    drop=('dump-tbcode','dump-tbmap','rvv-pc-census','rvv-pc-census-out','rvv-route-census','rvv-qcg-active-chunk-census','rvv-run-frame-census')
    for x in original[1:]:
     if any(x.startswith('--'+f+'=') for f in drop):continue
     if x.startswith('--fsroot='):x='--fsroot='+str(d/'fs')
     if x.startswith('--cache='):x='--cache='+str(d/'cache')
     flags.append(x)
    flags.insert(flags.index('--'),'--measure-translation=1')
    cmd=['taskset','-c',str(cpu),str(engines[label]),*flags]
    save(d/'command.json',dict(argv=cmd,LD_LIBRARY_PATH=str(engines[label].parent.parent/'lib'),stdin='DEVNULL'))
    assert __import__('shutil').disk_usage(out).free>=10*1024**3
    with (d/'stdout').open('wb') as stdout,(d/'stderr').open('wb') as stderr:
     start=time.perf_counter_ns()
     child=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=dict(os.environ,LD_LIBRARY_PATH=str(engines[label].parent.parent/'lib')))
     pid,status,usage=os.wait4(child.pid,0);wall=time.perf_counter_ns()-start
     child.returncode=os.waitstatus_to_exitcode(status)
    raw=(d/'stdout').read_bytes();err=(d/'stderr').read_text();assert child.returncode==0 and len(raw)==len(answer)
    for i,c in enumerate(cases):
     packet=raw[i*size:(i+1)*size];s.check_isa(c,packet,child.returncode,False);s.check_reference(c,packet,answer[i*size:(i+1)*size])
    timing={k:int(value) for k,value in re.findall(r'(TRANSLATE_NS|TRANSLATE_COUNT|QSEL_NS|QRA_NS|EMIT_NS|INTERP_BLOCKS)=(\d+)',err)}
    assert len(timing)==6
    row=dict(workload=name,unit=unit,arm=arm,pair=pair,build=label,wall_ns=wall,max_rss_kib=usage.ru_maxrss,returncode=child.returncode,checks=len(cases),elf_sha256=hashlib.sha256(elfbytes).hexdigest(),reference_sha256=hashlib.sha256(answer).hexdigest(),timing=timing)
    save(d/'result.json',row);rows.append(row);save(out/'results.json',rows)
assert len(rows)==40
assert identities=={p:sha(P(p)) for p in identities}
save(out/'environment-after.json',observe())
save(out/'FINAL.json',dict(status='PASS',commands=len(rows),checks=sum(x['checks'] for x in rows),cpu=cpu,sibling=siblings[cpu],no_retries=True))
print(json.dumps(json.loads((out/'FINAL.json').read_text())))
