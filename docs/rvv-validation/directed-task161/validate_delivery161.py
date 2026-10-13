#!/usr/bin/env python3
"""Validate compact delivery against retained declarations and every observed row."""
import collections,csv,gzip,hashlib,json
from pathlib import Path
D=Path(__file__).resolve().parent;repo=D.parents[2]
def read(p):return json.loads(p.read_text())
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
paths={'widen-full':'directed-task154/next-widen','wmac-full2':'directed-task156/next-wmac2','extend-full':'directed-task156/next-extend','destchunk-full':'directed-task156/destchunk-delta2'}
receipts={};baseline=None;total=collections.Counter()
for name,source in paths.items():
 e=D/'remote'/name/'evidence';m=json.load(gzip.open(e/'manifest.json.gz','rt'));cases=m['cases'];prepared=json.load(gzip.open(D.parent/source/'PREPARED_MANIFEST.json.gz','rt'));prepared=prepared if isinstance(prepared,list) else prepared['cases'];assert cases==prepared,name
 a=read(e/'AUDIT.json');v=read(e/'VALIDATION.json');st=read(e/'STAGE_STATUS.json');assert set(st.values())=={0};assert not a['failures']
 before=read(e/'identities-before.json');assert before==read(e/'identities-after.json')
 if baseline is None:baseline=before
 assert before==baseline,name
 assert all(c['vlen'] in (128,256,512,1024,2048,4096) for c in cases);assert v['widths']==[128,256,512,1024,2048,4096]
 ids={c['id']:c for c in cases};seen=set();counts=collections.Counter();table=collections.Counter()
 with gzip.open(e/'observed-checks.csv.gz','rt') as f:
  for row in csv.DictReader(f):
   k=(row['case'],row['arm']);assert k not in seen;seen.add(k);c=ids[row['case']];reserved=c['vstart']>=c['vlmax'];assert row['status']=='PASS';assert row['semantic_status']==('PROFILE_RESERVED_START' if reserved else 'PASS')
   counts['reserved_start_checks' if reserved else 'ordinary_checks']+=1
   table[(c['mnemonic']+'.'+c['form'],row['arm'],'reserved-start-profile' if reserved else 'ordinary',row['status'],row['semantic_status'])]+=1
 expected={(c['id'],arm) for c in cases for arm in ('Reference','B','M1','M2','BOTH')};assert seen==expected;assert len(seen)==a['executed_case_checks']==v['checks']==len(cases)*5
 with (e/'PER_FORM.csv').open() as f:
  saved={(r['form'],r['arm'],r['class'],r['status'],r['semantic_status']):int(r['checks']) for r in csv.DictReader(f)}
 assert saved==dict(table)
 c=read(e/'CONTROLS.json');assert c['controls']==c['rejected']>0
 gpath=D/'remote'/name/'controls-geometry/summary.json';gpath=gpath if gpath.exists() else D/'remote'/name/'controls-geometry2/summary.json';g=read(gpath);assert g['effective']==g['controls']==g['rejected']>0;assert g['geometries_forms']==len({(c['mnemonic'],c['form'],c['vlen'],c['sew'],c['lmul']) for c in cases})
 effect=read(D/'remote'/name/'CONTROL_EFFECTIVENESS.json');assert all(x['effective'] and x['accepted'] for x in effect['allowed']);assert len(effect['allowed'])==c['allowed'];assert effect['negative_records_verified']+effect['negative_records_without_stored_mutations']==c['controls']
 declaration=read(D.parent/source/'DECLARATION.json');reserved_encodings=declaration.get('reserved_encodings',[]);assert all(r['execution']=='NOT_RUN' for r in reserved_encodings)
 receipts[name]=dict(cases=len(cases),units=m['units'],checks=len(seen),ordinary_per_arm=v['ordinary_per_arm'],reserved_start_per_arm=v['reserved_start_per_arm'],commands=a['executed_commands'],adapter_verified_units=a['adapter_verified_units'],forms=len({(c['mnemonic'],c['form']) for c in cases}),reserved_encoding_declarations=len(reserved_encodings),illegal_encoding_guests=0,negative_controls=c['controls'],effective_allowed_variants=len(effect['allowed']),geometry_controls=g['controls'],geometry_form_pairs=g['geometries_forms'],prepared_manifest_equal=True,raw=v['raw'],audit=v['audit'])
 total.update(dict(cases=len(cases),checks=len(seen),units=m['units'],commands=a['executed_commands'],adapter_verified_units=a['adapter_verified_units'],ordinary_checks=counts['ordinary_checks'],reserved_start_checks=counts['reserved_start_checks'],reserved_encoding_declarations=len(reserved_encodings)))
for name in ('extend-pilot','destchunk-pilot'):
 assert read(D/'remote'/name/'PILOT_REVIEW.json')['accepted'];assert set(read(D/'remote'/name/'evidence/STAGE_STATUS.json').values())=={0}
resources=read(D/'remote/RESOURCE_SUMMARY.json');assert resources['max_active_guests']<=16;assert resources['max_active_offline']<=4
save(D/'VALIDATION.json',dict(full_families=receipts,full_total=dict(total),pilots_counted_in_full_total=False,identities=baseline,resource_summary=resources,failures=0,reference_blockers=0,illegal_encoding_guest_tests=0,main_review='PENDING; no production fix or method admission',controls_finding=read(D/'CONTROL_FINDING.json')))
old=read(D/'PRESERVATION_BEFORE.json');changed=[p for p,h in old.items() if hashlib.sha256((repo/p).read_bytes()).hexdigest()!=h];assert not changed,changed
save(D/'PRESERVATION_CHECK.json',dict(regular_tracked_files=len(old),changed=changed,untracked_python_caches_preserved=True,raw_or_failed_inputs_deleted=0))
print(json.dumps(dict(total)))
