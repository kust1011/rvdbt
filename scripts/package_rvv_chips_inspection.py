#!/usr/bin/env python3
"""Join existing CHIPS primary registrations/bindings into a portable inspection tree.

Run on xbd after export; no guest, build, oracle or golden is executed.
"""
import argparse
import collections
import csv
import hashlib
import json
import re
from pathlib import Path
import shutil


def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()


def save(p,x):
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2)+'\n')


def table(p,rows,fields=None):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields or list(rows[0]));w.writeheader();w.writerows(rows)


def copy(p,q):
    q.parent.mkdir(parents=True,exist_ok=True)
    if q.is_file() and q.stat().st_size==p.stat().st_size and digest(q)==digest(p):return
    shutil.copyfile(p,q)


def assertion_span(p):
    lines=[]
    with p.open() as f:
        for i,line in enumerate(f,1):
            if re.search(r'\bTEST_CASE\s*\(',line):lines.append(i)
    return {'count':len(lines),'first_line':lines[0] if lines else None,'last_line':lines[-1] if lines else None}


def literal_contexts(root, chains, nav):
    indexed={g['source'] for g in csv.DictReader((root/'sources/chips/SOURCE_GEOMETRY.csv').open())}
    records=[]
    for c in chains:
        if c['case'] in {'fail256','wrong-answer'} or str(Path(c['source']).relative_to('sources/chips')) in indexed:continue
        forms={n['source_form'] for n in nav if n['source']==c['source']}
        lines=(root/c['source']).read_text().splitlines()
        headers=[];instructions=[]
        for i,line in enumerate(lines,1):
            if line.startswith('# Generating tests'):headers.append({'line':i,'text':line})
            if re.match(r'^vset(?:ivli|vli|vl)\s',line) or any(re.match(r'^'+re.escape(f)+r'\s',line) for f in forms):
                start=max(1,i-6);end=min(len(lines),i+6)
                instructions.append({'line':i,'text':line,'window_first_line':start,'window':lines[start-1:end]})
        assert instructions,'missing source configuration/target instructions '+c['source']
        records.append({'batch':c['batch'],'case':c['case'],'source':c['source'],'source_sha256':c['source_sha256'],'headers':headers,'instructions':instructions,'scope':'Exact retained source lines, including register-valued AVL/vtype setup; not runtime branch/VL observations or a Cartesian product.'})
    save(root/'LITERAL_CONFIG_CONTEXTS.json',records)
    sources={r['source'] for r in records}
    for n in nav:
        if n['source'] in sources:n['configuration_selector']='LITERAL_CONFIG_CONTEXTS.json [source='+n['source']+']'
    return records


def build(root, canonical, campaign, historical):
    registration=json.loads((root/'records/historical/MANIFEST.json').read_text())
    primary=[x for x in csv.DictReader((canonical/'SUITE_RUN_MANIFEST.csv').open()) if x['suite']=='CHIPS' and x['cohort']=='sealed-47-batches']
    ids={x['row_id'] for x in primary}
    bindings=[x for x in csv.DictReader((canonical/'ACTUAL_FORM_VALIDATION_BINDINGS.csv').open()) if x['ledger_row_id'] in ids]
    table(root/'records/scope/PRIMARY_LEDGER.csv',primary)
    table(root/'records/scope/PRIMARY_BINDINGS.csv',bindings)
    blockers=[x for x in csv.DictReader((canonical/'SUITE_RUN_MANIFEST.csv').open()) if x['suite']=='CHIPS' and x['dut_status']=='BLOCKED']
    table(root/'records/scope/CHIPS_BLOCKED.csv',blockers)
    # Preserve the clean/historical distinction in physical receipt directories.
    for cand,base in [('clean961',campaign/'raw'),('historical2af5',historical/'runs')]:
        if cand=='clean961': dirs=[p for batch in base.iterdir() if batch.is_dir() for p in batch.iterdir() if p.is_dir() and (p/'result.json').is_file()]
        else: dirs=[p for p in base.iterdir() if p.is_dir() and (p/'result.json').is_file()]
        for p in dirs:
            for name in ('stdout','stderr','result.json','case.json','command.json','environment.json'):
                if (p/name).is_file():copy(p/name,root/'records'/cand/'receipts'/p.relative_to(base)/name)
        if cand=='clean961':
            for batch in base.iterdir():
                if not batch.is_dir():continue
                for name in ('invocation.json','summary.json'):
                    if (batch/name).is_file():copy(batch/name,root/'records'/cand/'batches'/batch.name/name)
            for p in (campaign/'manifests').glob('*.json'):copy(p,root/'records'/cand/'manifests'/p.name)
    cells={x['id']:x for x in registration['cells']}
    binding_index={b['ledger_row_id']:b for b in bindings}
    pilot=campaign.parent/'suite45-chips-first-b'
    for p in pilot.glob('*/result.json'):
        for name in ('stdout','stderr','result.json','case.json','command.json'):
            copy(p.parent/name,root/'records/clean961/receipts/pilot'/p.parent.name/name)
    for name in ('invocation.json','summary.json'):
        copy(pilot/name,root/'records/clean961/batches/pilot'/name)
    copy(pilot/'manifest.json',root/'records/clean961/manifests/pilot.json')
    source_records={};nav=[];missing=[];command_cache={}
    for row in primary:
        if row['row_kind'] not in {'EXECUTION','HARNESS_CONTROL'}:continue
        cellid=Path(row['raw_stdout']).parent.name
        cell=cells[cellid]
        if row['candidate']=='clean961' and '/raw/' not in row['raw_stdout']:
            base=campaign.parent/'rvv_validation_delivery_20261009-r1/clean-results'
            for name in ('stdout','stderr','result.json','case.json','command.json'):
                copy(base/cellid/name,root/'records/clean961/receipts/clean-replay'/cellid/name)
            copy(base/'invocation.json',root/'records/clean961/batches/clean-replay/invocation.json')
            copy(base.parent/'clean-manifest.json',root/'records/clean961/manifests/clean-replay.json')
        for alias in json.loads(row['aliases_json']):
            batch=alias['batch'];case=alias['test'];key=(batch,case)
            base=root/'sources/chips'/batch
            if batch not in command_cache:
                command_cache[batch]=collections.defaultdict(list)
                for name in ('build_commands.json','user_rebuild_commands.json'):
                    if (base/name).exists():
                        for ordinal,c in enumerate(json.loads((base/name).read_text()),1):
                            cmd=c.get('command',[])
                            if '-o' in cmd and '/user-bin/' in cmd[cmd.index('-o')+1]:
                                command_cache[batch][Path(cmd[cmd.index('-o')+1]).name].append((name,ordinal,c))
            commands=command_cache[batch][case+'.elf']
            source=None
            for _,_,c in reversed(commands):
                for token in c['command']:
                    if token.endswith('.S') and '/chips_validation_20261007/' in token:
                        source='sources/chips/'+token.split('/chips_validation_20261007/',1)[1]
            if source is None: source=str((base/'stage2'/ (case+'.S')).relative_to(root))
            if not (root/source).exists():
                missing.append({'batch':batch,'case':case,'dependency':source});continue
            if key not in source_records:
                hashes=json.loads((base/'file_hashes.json').read_text()) if (base/'file_hashes.json').exists() else {}
                source_records[key]={'batch':batch,'case':case,'source':source,'source_sha256':digest(root/source),'assertions':assertion_span(root/source),
                    'elf_sha256':row['elf_sha256'],'recorded_elf_sha256':hashes.get('user-bin/'+case+'.elf'),
                    'original_hash_manifest':str((base/'file_hashes.json').relative_to(root)),
                    'build_commands':[{'file':str((base/name).relative_to(root)),'ordinal':i,'record':c} for name,i,c in commands],
                    'stage1':str((base/'stage1'/(case+'.S')).relative_to(root)),
                    'capture_patch':str((base/'patches'/(case+'.patch')).relative_to(root))}
            source_form=alias.get('form') or 'HARNESS_CONTROL'
            checked_forms=binding_index[row['row_id']]['result_checked_forms'].split(';') if not cell['control'] else ['HARNESS_CONTROL']
            form=source_form if source_form in checked_forms else checked_forms[0]
            assert source_form in checked_forms or len(checked_forms)==1,'ambiguous accepted canonical form'
            nav.append({'candidate':row['candidate'],'form':form,'source_form':source_form,'batch':batch,'case':case,
                'arm':row['arm'],'VLEN':row['VLEN'],'cell_id':cellid,'ledger_row_id':row['row_id'],
                'source':source,'source_sha256':source_records[key]['source_sha256'],'elf_sha256':row['elf_sha256'],
                'receipt':('records/clean961/receipts/'+(str(Path(row['raw_stdout'].split('/raw/',1)[1]).parent) if '/raw/' in row['raw_stdout'] else 'clean-replay/'+cellid) if row['candidate']=='clean961' else 'records/historical2af5/receipts/'+cellid),'control':str(cell['control']),
                'configuration_selector':'sources/chips/SOURCE_GEOMETRY.csv [source='+str(Path(source).relative_to('sources/chips'))+']',
                'assertion_selector':source+' [TEST_CASE lines '+str(source_records[key]['assertions']['first_line'])+'..'+str(source_records[key]['assertions']['last_line'])+'; count='+str(source_records[key]['assertions']['count'])+']',
                'source_chain_selector':'SOURCE_CHAIN.json [batch='+batch+',case='+case+']'})
    literal_contexts(root,list(source_records.values()),nav)
    save(root/'SOURCE_CHAIN.json',list(source_records.values()))
    table(root/'NAVIGATION.csv',nav)
    save(root/'DEPENDENCIES.json',{'required_missing':missing,'excluded_reexecution':['clang20/lld, GCC toolchains','CHIPS TestFloat3 fetched at pinned upstream tree','Spike20feb9c2, pspike/merger executables','DUT executables/shared library','all guest ELFs and linked build outputs'],
        'not_in_primary_package':'Task47 supplemental and Task54 new-output/profile receipts; canonical binding subsets beyond sealed47 are not substituted for primary evidence'})
    save(root/'CANONICAL_INPUTS.json',{p.name:{'sha256':digest(p),'bytes':p.stat().st_size} for p in [canonical/'SUITE_RUN_MANIFEST.csv',canonical/'ACTUAL_FORM_VALIDATION_BINDINGS.csv']})
    return {'primary_ledger_rows':len(primary),'primary_binding_rows':len(bindings),'navigation_rows':len(nav),'source_chains':len(source_records),'missing':missing}


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--root',type=Path,required=True);ap.add_argument('--canonical',type=Path,required=True);ap.add_argument('--campaign',type=Path,required=True);ap.add_argument('--historical',type=Path,required=True)
    a=ap.parse_args();print(json.dumps(build(a.root,a.canonical,a.campaign,a.historical),indent=2))

if __name__=='__main__':main()
