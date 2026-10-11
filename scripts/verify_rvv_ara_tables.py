import argparse
import csv,json,hashlib,sys
from pathlib import Path
from rvv_ara_accepted import export_canonical
csv.field_size_limit(64*1024*1024)
parser=argparse.ArgumentParser(description='Offline Task87 historical-row, join, hash and regeneration checks')
parser.add_argument('--canonical',type=Path,required=True)
parser.add_argument('--derived',type=Path,required=True)
args=parser.parse_args()
c=args.canonical;p=args.derived
d=json.loads((p/'compact-input.json').read_text());e=d['ara_evidence']
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def preserved_prefix(name):
 with (c/name).open(newline='') as old,(p/name).open(newline='') as new:
  a,b=csv.DictReader(old),csv.DictReader(new)
  count=0
  for row in a:
   assert row==next(b),(name,count)
   count+=1
  delta=list(b)
  assert len(delta)==1600
 return count,delta
binding_count,bindings=preserved_prefix('ACTUAL_FORM_VALIDATION_BINDINGS.csv')
ledger_count,ledger=preserved_prefix('SUITE_RUN_MANIFEST.csv')
assert {r['ledger_row_id'] for r in bindings}=={r['row_id'] for r in ledger}
assert len({r['row_id'] for r in ledger})==1600
with (c/'COMPLETE_FORM_SUITE_INVENTORY.csv').open(newline='') as old,(p/'COMPLETE_FORM_SUITE_INVENTORY.csv').open(newline='') as new:
 for a,b in zip(csv.DictReader(old),csv.DictReader(new),strict=True):
  assert {k:v for k,v in a.items() if not k.startswith('Ara_')}=={k:v for k,v in b.items() if not k.startswith('Ara_')}
a=json.loads((c/'ACTUAL_FORM_VALIDATION_SUMMARY.json').read_text());b=json.loads((p/'ACTUAL_FORM_VALIDATION_SUMMARY.json').read_text())
assert [s for s in a['suites'] if s['suite']!='Ara']==[s for s in b['suites'] if s['suite']!='Ara']
for path,sha in e['inputs'].items():assert digest(Path(path))==sha,path
for binding in e['bindings']:
 source=binding.get('source',{})
 if source.get('source_file') and source.get('source_sha256'):
  assert digest(c.parent.parent/source['source_file'])==source['source_sha256']
 for artifact in binding.get('artifacts',{}).values():assert digest(Path(artifact['path']))==artifact['sha256']
files=['ACTUAL_FORM_VALIDATION_BINDINGS.csv','ACTUAL_FORM_VALIDATION_SUMMARY.json','COMPLETE_FORM_SUITE_INVENTORY.csv','SUITE_RUN_MANIFEST.csv','ACTUAL_SUITE_FORM_LISTS.md']
before={f:digest(p/f) for f in files}
export_canonical(d,c,p)
assert before=={f:digest(p/f) for f in files}
records={b.get('raw_root') or b['original_binding']['ledger_row_id']:b for b in e['bindings']}
report=dict(original_binding_rows=binding_count,original_ledger_rows=ledger_count,scoped_overlay_binding_rows=len(bindings),scoped_overlay_ledger_rows=len(ledger),unique_overlay_receipts=len(records),accepted_unique_overlay_receipts=sum(b['positive'] for b in records.values()),input_hashes_verified=len(e['inputs']),historical_rows_preserved=True,other_suite_fields_preserved=True,canonical_regeneration_byte_identical=True,duplicate_overlay_ids=0,new_DUT_executions=0)
(p/'TASK87_CHECK.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
