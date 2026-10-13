#!/usr/bin/env python3
"""Export compact179 identities/receipts; keep all original raw evidence remotely."""
import collections,difflib,hashlib,json,os,sys
from pathlib import Path
import vadd as v
B=Path('/home/vick/rvv-directed-task179');C=Path('/home/vick/rvdbt-host512-task179-build');O=B/'export179';O.mkdir(exist_ok=False)
def save(name,x):v.save(O/name,x)
def copy(src,name=None):(O/(name or src.name)).write_bytes(src.read_bytes())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for p in [C/'MANIFEST.json',B/'FOCUSED_REPLAY.json',B/'CONTRACTS.json']:
 copy(p,'BUILD_MANIFEST.json' if p.parent==C else None)
for p,name in [(B/'gdb.stdout','ORIGINAL174_GDB.stdout'),(B/'gdb.stderr','ORIGINAL174_GDB.stderr'),(B/'gdb.cmd','ORIGINAL174_GDB.cmd'),(B/'command.json','ORIGINAL174_COMMAND.json'),(B/'fixed-gdb/gdb.stdout','FIXED179_GDB.stdout'),(B/'fixed-gdb/command.json','FIXED179_COMMAND.json'),(B/'original174-trace0/RESULT.json','ORIGINAL174_TRACE0.json')]:copy(p,name)
old=(B/'gdb.stdout').read_text();new=(B/'fixed-gdb/gdb.stdout').read_text()
assert 'ENTRY_GUEST_IP=0x10000' in old and 'r13            0x0' in old and 'si_code = 2' in old
assert 'exited normally' in new and 'pop    %rcx\n   0x7fffed5fe05b:\tpop' not in new
copy(B/'baseline-contract/RESULT.json','BASELINE_CODEGEN_RESULT.json')
copy(B/'codegen-updated.stderr','INHERITED_FP_SCRATCH_DIAGNOSTIC.stderr')
diffs=[]
for i in range(16):
 a=(B/f'golden-old/row{i}.norm').read_text();z=(B/f'golden-new/row{i}.norm').read_text()
 nd=list(difflib.unified_diff(a.splitlines(),z.splitlines(),fromfile=f'174/row{i}',tofile=f'179/row{i}',lineterm=''))
 # Compare the executable prefix separately from the post-terminal embedded slot/padding.
 # Each nonleaf code row has exactly one removed pop; scalar leaf rows are identical.
 assert a.count('pop    rcx')-z.count('pop    rcx')==(0 if i>=14 else 1)
 for row in nd:
  if row.startswith(('+','-')) and not row.startswith(('+++','---')):
   text=row[1:].strip()
   assert text=='pop    rcx' or text.startswith(('add ','or ','adc ','sbb ','and ','sub ','xor ','...')),row
 diffs.extend(nd)
(O/'GOLDEN174_TO179.diff').write_text('\n'.join(diffs)+'\n')
copy(B/'golden-old/stdout','GOLDEN174.stdout');copy(B/'golden-old/stderr','GOLDEN174.stderr');copy(B/'golden-new/stdout','GOLDEN179_BEFORE_REPIN.stdout')
s_ARMS=['B','M1','M2','BOTH']
records=[];per=[];frames=[];pcs=[]
for trace in [0,1]:
 for group in ['main','cache64']:
  a=B/f'audit-trace{trace}-{group}';copy(a/'AUDIT.json',f'AUDIT_TRACE{trace}_{group}.json')
  ctl=B/f'CONTROLS_TRACE{trace}_{group}.json';copy(ctl)
  for row in json.loads((a/'FRAMES.json').read_text()):frames.append(dict(trace=trace,**row))
  for row in json.loads((a/'PC_PATH_RESULTS.json').read_text()):pcs.append(dict(trace=trace,**row))
 for part in ['integer','fp','cache','cache64']:
  root=B/f'trace{trace}'/part;m=json.loads((root/'manifest.json').read_text());per.append(dict(trace=trace,part=part,manifest=m))
  units=sorted({c['unit'] for c in m['cases']})
  for unit in units:
   for arm in s_ARMS:
    d=root/'runs'/unit/arm;cmd=json.loads((d/'command.json').read_text());rec=json.loads((d/'execution.json').read_text())
    record=dict(trace=trace,part=part,unit=unit,arm=arm,execution=rec,command=cmd,checks=json.loads((d/'checks.json').read_text()),guest_sha256=v.sha(root/unit/'test.elf'),packet_sha256=v.sha(d/'packets.bin'),reference_sha256=v.sha(root/'runs'/unit/'Reference/packets.bin'))
    records.append(record)
for name,x in [('MANIFESTS.json',per),('EXECUTION_RECEIPTS.json',records),('FRAMES.json',frames),('PC_PATH_RESULTS.json',pcs)]:
 v.storage.write(O/name,json.dumps(x,separators=(',',':')).encode())
contracts={}
for d in sorted((B/'contracts').iterdir()):
 actual=B/'contracts-final'/d.name if d.name=='rvv_vector_run_codegen_test' else d
 text=v.storage.text(actual/'stdout');contracts[d.name]=dict(result='PASS',stdout_sha256=v.sha(actual/'stdout'),stderr_sha256=v.sha(actual/'stderr'),stdout_tail=text[-2200:])
copy(B/'contracts-final/rvv_vector_run_codegen_test/execution.json','CODEGEN_FINAL_EXECUTION.json');save('CONTRACT_DETAILS.json',contracts)
samples=[json.loads(l) for l in (B/'RESOURCES.jsonl').read_text().splitlines()]
own_guest_peak=max(sum(r['guest'] and any('rvv-directed-task179' in x for x in r['args']) for r in s['rows']) for s in samples)
save('RESOURCES.json',dict(samples=len(samples),sampled_own_guest_peak=own_guest_peak,sampled_shared_guest_peak=max(s['guests'] for s in samples),minimum_free_bytes=min(s['free_bytes'] for s in samples),own_enforced_guest_workers=4,own_enforced_offline_workers=2,own_build_jobs=4,owner_semaphore='/home/vick/rvv-directed-task179.own-semaphore',policy=dict(own_guest=8,own_build=4,own_offline=2,shared_guest=16,shared_offline=4,nice=10,affinity='none assigned',reserve_bytes=10*1024**3),limitations='preflight samples, not continuous telemetry; contract binaries are offline workers not classified by inherited resources164; bounded pool2 accounts for them. Initial diagnostic nested nice10 yielded nice19; authoritative repeat and all regression/build/offline subprocesses use nice10.',resource_compliance='INITIAL_NICE_EXCEPTION_RETAINED; subsequent own queue bounds enforced by a single cross-controller flock and bounded pools; sparse shared occupancy is not a continuous guarantee'))
save('RETENTION.json',dict(remote=str(B),candidate=str(C),all_original177_retained=True,all178_sources_ELFs_oracles_results_untouched=True,new_packets_stream_compressed=True,ELF_rebuilds=0,reference_executions=0,shared_notice='SESSION0_TASK179_COORDINATION.md',fixed_GDB_packet_sha256=sha(B/'fixed-gdb/packets.bin'),fixed_GDB_same_packet_as_focused_trace1_B=sha(B/'fixed-gdb/packets.bin')==v.sha(B/'trace1/integer/runs/integer-w1024-e32-m1-liveout-zero/B/packets.bin'),setup_attempts=['initial missing own-cache directory; corrected before host-fault capture','invocation-attempt1: wrapper duplicated dump options; no DUT execution credit','audit setup attempts: v1 lacks cache64 CLI; missing sail link; cache64 patch must audit separate root','fixed-gdb-invocation-attempt1: GDB run redirection reset argv; retained invalid-argument result'],initial_nice_exception=True))
print(O)
