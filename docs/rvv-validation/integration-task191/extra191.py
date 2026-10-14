"""Bounded retained normal sequences and actual elfrun anonymous admission."""
import ast,hashlib,json,os,pathlib,re,resource,subprocess,sys,time
P=pathlib.Path;root=P('/home/vick/rvdbt-exception-task186');out=root/'task191';env=dict(os.environ,LD_LIBRARY_PATH=str(root/'build/lib')+':/lib/x86_64-linux-gnu')
assert os.getpriority(os.PRIO_PROCESS,0)==10
assert json.loads((out/'FINAL.json').read_text())['status']=='PASS_BOUNDED_INTEGRATION'
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
# Reuse the reviewed receipt writer, without executing its build/test loops.
tree=ast.parse((root/'run191-resume.py').read_text());body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('sha','save','resources','run')]
exec(compile(ast.Module(body=body,type_ignores=[]),'receipt-functions','exec'))
results=[];pins=json.loads((out/'MANIFEST.json').read_text())['build']
assert all(sha(root/'build'/p)==h for p,h in pins.items())
sys.path.insert(0,str(root/'task191-tools'))
import sequences177 as s
import vadd as v
selection=json.loads((out/'SEQUENCE_SELECTION.json').read_text()) if '--anonymous-only' in sys.argv else []
for part,scenario,start in ([] if '--anonymous-only' in sys.argv else [('integer','alias',False),('integer','boundary',True),('fp','chain',False),('cache','cache',False)]):
 b=P('/home/vick/rvv-directed-task177')/part/'pilot';m=json.loads((b/'manifest.json').read_text())
 cs=[c for c in m['cases'] if c['vlen']==1024 and c['sew']==32 and c['lmul']=='m1' and c['scenario']==scenario and bool(c['vstart'])==start]
 units={c['unit'] for c in cs};assert len(units)==1
 unit=next(iter(units));cs=[c for c in m['cases'] if c['unit']==unit]
 s.install(part)
 elf=v.storage.verify(b/unit/'test.elf');ref=v.storage.verify(b/'runs'/unit/'Reference/packets.bin');size=v.packet_size(cs[0]);assert len(ref)==len(cs)*size
 inp=out/'sequence-inputs'/unit;inp.mkdir(parents=True);(inp/'test.elf').write_bytes(elf);(inp/'reference.bin').write_bytes(ref)
 info=dict(part=part,unit=unit,cases=cs,elf_sha256=sha(inp/'test.elf'),reference_sha256=sha(inp/'reference.bin'),source_root=str(b))
 selection.append(info)
 for arm in ['B','M1','M2','BOTH']:
  d=out/'sequences'/unit/arm;w=d/'work';(w/'fs').mkdir(parents=True);(w/'cache').mkdir();os.symlink(inp/'test.elf',w/'fs/t.elf')
  old=json.loads((b/'runs'/unit/arm/'command.json').read_text());cmd=[str(root/'build/bin/elfrun')]
  for x in old[1:]:
   for prefix,target in [('--dump-tbcode=',d/'tbcode'),('--dump-tbmap=',d/'tbmap'),('--rvv-pc-census-out=',d/'pc-census.csv'),('--fsroot=',w/'fs'),('--cache=',w/'cache')]:
    if x.startswith(prefix):x=prefix+str(target);break
   cmd.append(x)
  def check(rc,raw,err):
   assert len(raw)==len(cs)*size
   for i,c in enumerate(cs):s.check_isa(c,raw[i*size:(i+1)*size],rc);s.check_reference(c,raw[i*size:(i+1)*size],ref[i*size:(i+1)*size])
   return True
  run(str(d.relative_to(out))+'/capture',cmd,check,dict(selection=info,original_command=old))
save(out/'SEQUENCE_SELECTION.json',selection)
# One new freestanding guest, no changes to the external suites or production.
d=out/'anonymous';d.mkdir(exist_ok='--gather-on-only' in sys.argv);cmd=['/usr/bin/clang-22','--target=riscv32-unknown-elf','-march=rv32gv','-mabi=ilp32d','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-relax','-Wl,-e,_start',str(root/'anonymous191.S'),'-o',str(d/'test.elf')]
if '--gather-on-only' not in sys.argv:
 before=resources();r=subprocess.run(cmd,capture_output=True);(d/'build.stdout').write_bytes(r.stdout);(d/'build.stderr').write_bytes(r.stderr);save(d/'build.json',dict(command=cmd,rc=r.returncode,before=before,after=resources()));assert r.returncode==0
flags=json.loads(P('/home/vick/act-current121/QUEUE.json').read_text())['calls'][3]['normalized_flags'];flags=flags[:flags.index('--')];flags=[x for x in flags if not x.startswith(('--fsroot=','--cache=','--rvv-gather=','--rvv-stats='))]
for gather in ([1] if '--gather-on-only' in sys.argv else [0,1]):
 runroot=d/str(gather);w=runroot/'work';(w/'fs').mkdir(parents=True);(w/'cache').mkdir();os.symlink(d/'test.elf',w/'fs/t.elf')
 cmd=[str(root/'build/bin/elfrun'),*flags,f'--rvv-gather={gather}','--rvv-stats=1','--fsroot='+str(w/'fs'),'--cache='+str(w/'cache'),'--','/t.elf']
 def check(rc,raw,err):
  assert rc==0 and raw==b''
  m=re.search(rb'RVV_GATHER attempts=(\d+) calls=(\d+) elems=(\d+) unmapped=(\d+)',err);assert m
  assert tuple(map(int,m.groups()))==((1,1,16,0) if gather else (0,0,0,0))
  return True
 run(str(runroot.relative_to(out))+'/capture',cmd,check,dict(elf_sha256=sha(d/'test.elf'),source_sha256=sha(root/'anonymous191.S'),gather=gather))
assert all(sha(root/'build'/p)==h for p,h in pins.items())
save(out/'EXTRA_FINAL.json',dict(status='PASS',sequence_invocations=16,sequence_checks=sum(len(x['cases']) for x in selection)*4,anonymous_invocations=2,after=resources()))
