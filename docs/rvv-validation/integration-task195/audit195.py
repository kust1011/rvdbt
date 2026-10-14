"""Offline receipt/hash/denominator join. Never executes a guest or reference."""
import collections, csv, hashlib, json, re, sys
from pathlib import Path as P
r=P(sys.argv[1]);old=P('/home/vick/rvv-long-task192')
def sha(p):return hashlib.sha256(P(p).read_bytes()).hexdigest()
def load(p):return json.loads(P(p).read_text())
def save(p,x):P(p).write_text(json.dumps(x,indent=2)+'\n')
selection=load(r/'SELECTION.json');final=load(r/'FINAL.json');initial=load(r/'BEFORE.json');results=load(r/'RESULTS.json')
assert final['status']=='PASS_BOUNDED_INTEGRATION'
assert initial['binaries']==final['binaries']=={p:sha(p) for p in initial['binaries']}
changed=[p for p,h in initial['source'].items() if final['source'][p]!=h]
assert set(changed)=={'dbt/qmc/qcg/vchunk_dataflow_test.cpp','dbt/qmc/qcg/rvv_fp_shared_mask_test.cpp'}
assert all(sha(old/'source'/p)==h for p,h in final['source'].items())
assert len(results)==57 # 4 builds + 13 fixture attempts + 40 external calls
for rec in results:
 d=r/rec['name'];assert rec==load(d/'execution.json')
 for stream in ['stdout','stderr']:assert sha(d/stream)==rec[stream+'_sha256']
 assert not rec['timeout']
 for endpoint in ['before','after']:assert rec[endpoint]['nice']==10 and rec[endpoint]['free_bytes']>=10*1024**3
builds=[x for x in results if x['name'].startswith('build')];assert len(builds)==4 and all(x['pass_check'] and '-j2' in x['command'] for x in builds)
assert builds[0]['detail']['missing_only']==selection['missing']==selection['fixtures']
fixtures=[x for x in results if x['name'].startswith('fixtures/')];assert len(fixtures)==13
assert sum(x['pass_check'] for x in fixtures)==10
failed=[x for x in fixtures if not x['pass_check']];assert len(failed)==3 and all(x['returncode']==1 for x in failed)
assert b'0 test(s) skipped' in (r/'fixtures/vchunk_dataflow_test/stdout').read_bytes()
assert b'OK: all tests passed, 0 skipped' in (r/'fixtures/vchunk_dataflow_test-corrected/stdout').read_bytes()
assert b'add inputs via frame=2/2' in (r/'fixtures/vchunk_dataflow_test-corrected/stdout').read_bytes()
assert b'native AVX-512' in (r/'fixtures/vstatechunkload_test/stdout').read_bytes()
ext=[x for x in results if x['name'].startswith('external/')];assert len(ext)==40 and all(x['pass_check'] and x['returncode']==0 for x in ext)
routes=[]
for rec in ext:
 d=r/rec['name'];parent=d.parent;route=load(parent/'ROUTE.json')
 for stream in ['pc-census.csv','tbmap','tbcode']:assert sha(d/stream)==route[{'pc-census.csv':'pc_census','tbmap':'tbmap','tbcode':'tbcode'}[stream]+'_sha256']
 text=(d/'stderr').read_text();match=re.search(r'RVV_DIRECT enabled=(\d+) hit_counter=(\d+) inline_hits=(\d+) guard_fallbacks=(\d+)',text);assert match and match[2]=='1'
 census=(d/'pc-census.csv').read_text();assert 'overflow=0' in census
 handlers=collections.Counter()
 for row in csv.DictReader(census.splitlines()[1:]):handlers[row['family']]+=int(row['handler_calls'])
 parts=rec['name'].split('/');routes.append(dict(suite=parts[1],case=parts[2],arm=parts[3],inline_hits=int(match[3]),guard_fallbacks=int(match[4]),handler_calls_by_family=dict(handlers),frames=[l for l in text.splitlines() if l.startswith('RVV_RUN_FRAME ')],scope='inline_hits are whole-guest execution counts; no target-form/per-PC native credit inferred'))
for suite in ['act','chips']:
 assert collections.Counter(x['arm'] for x in routes if x['suite']==suite)==dict.fromkeys(['B','M1','M2','BOTH'],5)
baseline=r/'baseline-int';a=load(baseline/'audit/AUDIT.json');assert a['status']=='PASS' and a['cases']==4 and a['target_pc_arm_rows']==1040
assert a['paths']=={'SINGLETON_NATIVE':1040}
reuse=load(baseline/'REUSE.json');assert reuse['guest_rebuilds']==reuse['reference_executions']==0
sys.path[:0]=[str(old/'tools'),'/home/vick/rvdbt-exception-task186/task191-tools'];import vadd as v
assert hashlib.sha256(v.storage.verify(baseline/reuse['unit']/'test.elf')).hexdigest()==reuse['elf_sha256']
assert hashlib.sha256(v.storage.verify(baseline/'runs'/reuse['unit']/'Reference/packets.bin')).hexdigest()==reuse['reference_sha256']
for arm in ['B','M1','M2','BOTH']:
 d=baseline/'runs'/reuse['unit']/arm;rec=load(d/'execution.json');assert rec['returncode']==0 and not rec['timeout']
 for stream in ['stdout','stderr']:assert hashlib.sha256(v.storage.verify(d/stream)).hexdigest()==rec[stream+'_sha256']
 assert len(load(d/'checks.json'))==4
ids={c['id'] for c in load(baseline/'manifest.json')['cases']};paths=load(baseline/'audit/PC_PATH_RESULTS.json');packets=16
for name in ['affected','remaining','routes']:
 previous=old/name;cs=load(previous/'manifest.json')['cases'];assert not ids & {c['id'] for c in cs};ids|={c['id'] for c in cs}
 assert load(previous/'audit/AUDIT.json')['status']=='PASS';pins=load(previous/'identities-before.json');assert pins==load(previous/'identities-after.json')
 assert pins[str(old/'build/bin/elfrun')]==final['binaries'][str(old/'build/bin/elfrun')]
 for unit in {c['unit'] for c in cs}:
  for arm in ['B','M1','M2','BOTH']:
   d=previous/'runs'/unit/arm;rec=load(d/'execution.json');assert rec['returncode']==0 and not rec['timeout']
   for stream in ['stdout','stderr']:assert hashlib.sha256(v.storage.verify(d/stream)).hexdigest()==rec[stream+'_sha256']
   checks=load(d/'checks.json');assert all(x['status']=='PASS' for x in checks);packets+=len(checks)
 paths+=load(previous/'audit/PC_PATH_RESULTS.json')
assert len(ids)==54 and packets==216
oldsummary=load(old/'SUMMARY.json');assert oldsummary['fixed192_DUT_packets']==200 and oldsummary['original_failed_DUT_packets']==16
for arm in ['B','M1','M2','BOTH']:
 d=old/'pilot/runs/long192-fp-w4096-e32-m4'/arm;assert load(d/'execution.json')['returncode']==-6
 assert b'virtual-register track capacity exceeded' in v.storage.verify(d/'stderr')
summary=dict(status='PASS_BOUNDED_INTEGRATION',accepted_fixture_commands=10,failed_fixture_attempts=failed,external_commands=40,external_unique_suite_cases=10,baseline_new_DUT_commands=4,baseline_new_packet_checks=16,accepted_execution_commands=54,all_execution_attempts=57,build_commands=4,new_guest_builds=0,new_reference_commands=0,long192_same_build_cases=54,long192_same_build_DUT_checks=216,reused_fixed192_DUT_checks=200,original191_failed_DUT_checks_preserved=16,previous191_accepted_baseline_checks=16,paths_by_arm={arm:dict(collections.Counter(x['actual_path'] for x in paths if x['arm']==arm)) for arm in ['B','M1','M2','BOTH']},external_routes=routes,changed_tests=changed,production_edits=0,binaries=final['binaries'],min_recorded_free_bytes=min(x[p]['free_bytes'] for x in results for p in ['before','after']),limitations=['bounded ordinary QCG only','codegen/static assertions give no native credit','external guest checkers retain original observability','blocked P4-04 untouched'],prior_summary_sha256=sha(old/'SUMMARY.json'))
save(r/'SUMMARY.json',summary);print('OFFLINE AUDIT195 PASS: 54 accepted commands; 3 retained failed fixture attempts; 54/216 same-production-build long192')
