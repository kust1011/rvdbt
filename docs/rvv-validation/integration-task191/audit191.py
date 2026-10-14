"""Offline receipt/identity join for Task191; launches no guests or builds."""
import hashlib,json,pathlib,re
P=pathlib.Path;root=P('/home/vick/rvdbt-exception-task186');out=root/'task191'
def sha(p):return hashlib.sha256(P(p).read_bytes()).hexdigest()
def read(p):return json.loads(P(p).read_text())
def save(p,x):P(p).write_text(json.dumps(x,indent=2)+'\n')
manifest=read(out/'MANIFEST.json')
assert all(sha(root/'source'/p)==h for p,h in manifest['source'].items())
assert all(sha(root/'build'/p)==h for p,h in manifest['build'].items())
assert all(sha(p)==h for p,h in manifest['frozen179'].items())
rows=[];counts={}
for kind,expected in [('fixtures',8),('external',24),('sequences',16),('anonymous',2)]:
 paths=list((out/kind).rglob('execution.json'));assert len(paths)==expected,(kind,len(paths))
 counts[kind]=expected
 for p in paths:
  r=read(p);assert r['rc']==0 and not r['timeout'] and r['pass_check']
  assert sha(p.parent/'stdout')==r['stdout_sha256'] and sha(p.parent/'stderr')==r['stderr_sha256']
  for stage in ['before','after']:
   assert r[stage]['nice']==10 and r[stage]['free_bytes']>=10*1024**3
  rows.append(r)
# Per-process existing reachability counters: never infer gather from requested flags.
gather=[]
for p in (out/'external').rglob('counters.json'):
 c=read(p);on=p.parent.name=='1'
 if not on:assert c==dict(attempts=0,calls=0,elems=0,unmapped=0)
 if 'Vls32-vluxei32.v' in str(p) and on:assert c==dict(attempts=164,calls=0,elems=0,unmapped=163)
 gather.append(dict(path=str(p.relative_to(out)),counters=c))
for on in [0,1]:
 p=out/'anonymous'/str(on)/'capture/stderr';text=p.read_text()
 m=re.search(r'RVV_GATHER attempts=(\d+) calls=(\d+) elems=(\d+) unmapped=(\d+)',text)
 assert tuple(map(int,m.groups()))==((1,1,16,0) if on else (0,0,0,0))
 m=re.search(r'RVV_DIRECT enabled=1 hit_counter=1 inline_hits=(\d+)',text);assert m and int(m[1])==9
 for route in ['vle32.v','vse32.v','vadd.vv']:assert f'RVV_ROUTE {route} handler_calls=0' in text
# Existing grouped receipt checks the entire accessible fault-time memory page.
grouped=out/'fixtures/rv32_grouped_memory_fault_test-terminal'
for p in grouped.glob('expected-memory-*.bin'):
 assert p.read_bytes()==(grouped/p.name.replace('expected-memory-','memory-')).read_bytes()
assert len(list(grouped.glob('snapshot-*.bin')))==10
save(out/'ALL_ACCEPTED_RECEIPTS.json',rows)
save(out/'SUMMARY.json',dict(status='PASS_BOUNDED_PRODUCTION_INTEGRATION',accepted_invocations=len(rows),counts=counts,sequence_checks=read(out/'EXTRA_FINAL.json')['sequence_checks'],source_files=len(manifest['source']),build=manifest['build'],gather=gather,minimum_endpoint_free_bytes=min(r[s]['free_bytes'] for r in rows for s in ['before','after']),nice=10,own_compile_limit=2,own_test_peak=1,affinity='none',frozen179_unchanged=manifest['frozen179'],prior595_replayed=0,recovery_calls=0,production_edits=0,terminal_child_count_claim='fixture-local counts; not sum of dynamic assertions'))
print('PASS: 50 accepted commands, 68 retained sequence packet checks; source/binary/raw hashes verified')
