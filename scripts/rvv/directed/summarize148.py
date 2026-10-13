#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Minimal per-form declarations and audited results; no transport packaging."""
import argparse,collections,csv,gzip,json
from pathlib import Path
import vadd as v

def summarize(base,out):
    root=base/'corpus';audit=base/'audit'
    out.mkdir(parents=True,exist_ok=False)
    m=json.loads((root/'manifest.json').read_text());a=json.loads((audit/'audit.json').read_text())
    results=json.loads((root/'results.json').read_text());ids={c['id']:c for c in m['cases']}
    forms=collections.defaultdict(list)
    for c in m['cases']:
      name=c['form'] if c['family'].startswith('configuration') else c['mnemonic']+'.'+c['form']
      forms[name].append(c)
    counts=collections.defaultdict(collections.Counter);sem=collections.defaultdict(collections.Counter)
    for r in results:
      c=ids[r['case']];name=c['form'] if c['family'].startswith('configuration') else c['mnemonic']+'.'+c['form']
      counts[(name,r['arm'])][r['status']]+=1
    n=0
    with gzip.open(audit/'observed-checks.csv.gz','rt') as f:
      for row in csv.DictReader(f):
        c=ids[row['case']];name=c['form'] if c['family'].startswith('configuration') else c['mnemonic']+'.'+c['form']
        sem[(name,row['arm'])][row.get('semantic_status',row['status'])]+=1;n+=1
    assert n==a['executed_case_checks']==len(results)==len(ids)*5
    rows=[]
    for name,cases in forms.items():
      filename=name.replace('.','_')
      with gzip.open(out/(filename+'-manifest.json.gz'),'wt') as f:
        json.dump(dict(family=m['family'],manifest_sha256=v.sha(root/'manifest.json'),form=name,cases=cases),f,separators=(',',':'))
      row=dict(form=name,planned_per_arm=len(cases),arms={arm:dict(executed=sum(counts[(name,arm)].values()),statuses=dict(counts[(name,arm)]),semantic_statuses=dict(sem[(name,arm)])) for arm in ['Reference','B','M1','M2','BOTH']})
      v.save(out/(filename+'-results.json'),row);rows.append(row)
    v.save(out/'PER_FORM_RESULTS.json',rows)
    for name,source in [('SUMMARY.json',root/'summary.json'),('AUDIT.json',audit/'audit.json'),('CONTROLS.json',base/'controls/summary.json')]:
      v.save(out/name,json.loads(source.read_text()))
    v.save(out/'FREEZE.json',dict(snapshot=str(base/'scripts'),files=[dict(path=line.split('  ',1)[1],sha256=line.split('  ',1)[0]) for line in (base/'FREEZE.sha256').read_text().splitlines()]))
    v.save(out/'IDENTITIES.json',dict(before=json.loads((root/'identities-before.json').read_text()),after=json.loads((root/'identities-after.json').read_text()),runner=json.loads((root/'runner-identity.json').read_text())))
    print(len(rows),'forms,',n,'audited packets')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('base',type=Path);p.add_argument('output',type=Path);a=p.parse_args();summarize(a.base,a.output)
