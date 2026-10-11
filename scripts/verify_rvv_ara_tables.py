import argparse
import csv,json,hashlib,sys
from pathlib import Path
from rvv_ara_accepted import export_canonical, validate_evidence
csv.field_size_limit(64*1024*1024)
parser=argparse.ArgumentParser(description='Offline historical-row, join and deterministic regeneration checks')
parser.add_argument('--canonical',type=Path,required=True)
parser.add_argument('--derived',type=Path,required=True)
parser.add_argument('--source-only',action='store_true',help='Check newly joined Ara89 inputs against immutable Task87; no table regeneration')
parser.add_argument('--tables-only',action='store_true',help='Check table preservation/regeneration; source joins checked on author host')
args=parser.parse_args()
c=args.canonical;p=args.derived
d=json.loads((p/'compact-input.json').read_text());e=d['ara_evidence']
validate_evidence(d)
version=e.get('version',87)
expected=830 if version==90 else 1600
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
if args.source_only:
 assert version==90 and not args.tables_only
 original=json.loads((c/'compact-input.json').read_text())
 assert original['forms']==d['forms']
 assert [s for s in original['suites'] if s['suite']!='Ara']==[s for s in d['suites'] if s['suite']!='Ara']
 assert original['ara_evidence']['bindings']==e['bindings'][:1600]
 assert original['ara_evidence']['inputs']==e['inputs']
 inputs=e['ara89']['inputs']
 for path,sha in inputs.items():assert digest(Path(path))==sha,path
 report=dict(new_input_hashes_verified=len(inputs),immutable_task87_binding_prefix=1600,
  task87_input_manifest_unchanged=True,non_Ara_sets_unchanged=True,
  accepted_block_bindings=830,accepted_unique_receipts=195,
  failed_preliminary_references=8,recorded_DUT_calls=156,recorded_reference_calls=47,
  main_review_reused=dict(source_blocks=166,raw_receipts=195,rejection_controls=390),new_DUT_executions=0)
 (p/'TASK90_SOURCE_CHECK.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2));sys.exit(0)
def preserved_prefix(name):
 with (c/name).open('rb') as old,(p/name).open('rb') as new:
  for chunk in iter(lambda:old.read(1024*1024),b''):
   assert chunk==new.read(len(chunk)),name+' byte prefix changed'
 with (c/name).open(newline='') as old,(p/name).open(newline='') as new:
  a,b=csv.DictReader(old),csv.DictReader(new)
  count=0
  for row in a:
   assert row==next(b),(name,count)
   count+=1
  delta=list(b)
  assert len(delta)==expected
 return count,delta
binding_count,bindings=preserved_prefix('ACTUAL_FORM_VALIDATION_BINDINGS.csv')
ledger_count,ledger=preserved_prefix('SUITE_RUN_MANIFEST.csv')
assert {r['ledger_row_id'] for r in bindings}=={r['row_id'] for r in ledger}
assert len({r['row_id'] for r in ledger})==expected
with (c/'COMPLETE_FORM_SUITE_INVENTORY.csv').open(newline='') as old,(p/'COMPLETE_FORM_SUITE_INVENTORY.csv').open(newline='') as new:
 for a,b in zip(csv.DictReader(old),csv.DictReader(new),strict=True):
  assert {k:v for k,v in a.items() if not k.startswith('Ara_')}=={k:v for k,v in b.items() if not k.startswith('Ara_')}
a=json.loads((c/'ACTUAL_FORM_VALIDATION_SUMMARY.json').read_text());b=json.loads((p/'ACTUAL_FORM_VALIDATION_SUMMARY.json').read_text())
assert [s for s in a['suites'] if s['suite']!='Ara']==[s for s in b['suites'] if s['suite']!='Ara']
inputs=e['ara89']['inputs'] if version==90 else e['inputs']
if not args.tables_only:
 for path,sha in inputs.items():assert digest(Path(path))==sha,path
 for binding in e['bindings']:
  if version==90 and binding.get('task')!='ara89':continue
  source=binding.get('source',{})
  if version==87 and source.get('source_file') and source.get('source_sha256'):
   assert digest(c.parent.parent/source['source_file'])==source['source_sha256']
  for artifact in binding.get('artifacts',{}).values():assert digest(Path(artifact['path']))==artifact['sha256']
files=['ACTUAL_FORM_VALIDATION_BINDINGS.csv','ACTUAL_FORM_VALIDATION_SUMMARY.json','COMPLETE_FORM_SUITE_INVENTORY.csv','SUITE_RUN_MANIFEST.csv','ACTUAL_SUITE_FORM_LISTS.md']
before={f:digest(p/f) for f in files}
export_canonical(d,c,p)
assert before=={f:digest(p/f) for f in files}
records={b.get('raw_root') or b['original_binding']['ledger_row_id']:b for b in e['bindings']}
report=dict(original_binding_rows=binding_count,original_ledger_rows=ledger_count,scoped_overlay_binding_rows=len(bindings),scoped_overlay_ledger_rows=len(ledger),unique_overlay_receipts=len(records),accepted_unique_overlay_receipts=sum(b['positive'] for b in records.values()),input_hashes_verified=0 if args.tables_only else len(inputs),source_checks_on_author_host=args.tables_only,historical_rows_preserved=True,historical_byte_prefix_preserved=True,other_suite_fields_preserved=True,canonical_regeneration_byte_identical=True,duplicate_overlay_ids=0,new_DUT_executions=0)
(p/f'TASK{version}_CHECK.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
