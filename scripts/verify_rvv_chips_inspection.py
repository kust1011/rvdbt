#!/usr/bin/env python3
"""Offline retained CHIPS assertion/source/exit review, using package-relative paths."""
import argparse
from bisect import bisect_left
import collections
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys


def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()


def read(p):return json.loads(p.read_text())


def safe(root,name,files=None):
    if not isinstance(name,str) or Path(name).is_absolute() or '\\' in name or any(part in ('','.','..') for part in name.split('/')):
        raise ValueError('invalid package path: '+str(name))
    # Check every component before resolution, including links into this root.
    for component in (root.absolute(),*root.absolute().parents):
        if component.is_symlink():raise ValueError('symlink package root: '+str(root))
    p=root
    for part in Path(name).parts:
        p=p/part
        if p.is_symlink():raise ValueError('symlink package path: '+name)
    if not p.resolve().is_relative_to(root.resolve()) or not p.is_file():
        raise ValueError('missing/escaping payload '+name)
    if files is None:files=read(safe(root,'FILES.json',{'FILES.json':None}))
    if name not in files:raise ValueError('unmanifested package path: '+name)
    return p


def producer(root,files=None):
    spec=importlib.util.spec_from_file_location('retained_chips_runner',safe(root,'tools/runner.original.py',files))
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod


def verify(root):
    files=read(safe(root,'FILES.json',{'FILES.json':None}))
    # Reuse the loaded manifest for all references in this acceptance pass.
    def path(name):return safe(root,name,files)
    for name,value in files.items():assert digest(path(name))==value['sha256'],'payload hash '+name
    registration=read(path('records/historical/MANIFEST.json'))
    cells={c['id']:c for c in registration['cells']};original=producer(root,files)
    ledger={r['row_id']:r for r in csv.DictReader(path('records/scope/PRIMARY_LEDGER.csv').open())}
    bindings={r['ledger_row_id']:r for r in csv.DictReader(path('records/scope/PRIMARY_BINDINGS.csv').open())}
    nav=list(csv.DictReader(path('NAVIGATION.csv').open()))
    assert {r['row_id'] for r in ledger.values() if r['row_kind'] in {'EXECUTION','HARNESS_CONTROL'}}=={n['ledger_row_id'] for n in nav},'incomplete navigation'
    chains=read(path('SOURCE_CHAIN.json'));chain_index={(c['batch'],c['case']):c for c in chains}
    expected_candidates={'clean961':'6fda0f9ab06c2c824b5301d1f302b76799842981b00a88fffa85fe43f1dbd84f','historical2af5':'2af5d3e6b0d11564c1fe93cd86b4b7ec5467f8249a785b3ee4c350b440ad8de9'}
    source_assertions=0;no_assertion=[];missing_build=[];json_cache={}
    def cached(name):
        if name not in json_cache:json_cache[name]=read(path(name))
        return json_cache[name]
    for c in chains:
        p=path(c['source']);assert digest(p)==c['source_sha256'],'source identity'
        hashes=cached(c['original_hash_manifest'])
        base='sources/chips/'+(c['batch']+'/' if c['batch']!='.' else '')
        source_rel=c['source'].removeprefix(base)
        if source_rel in hashes:assert hashes[source_rel]==digest(p),'original recorded source hash '+c['source']
        assert c['recorded_elf_sha256']==c['elf_sha256'],'original compiled ELF identity '+str((c['batch'],c['case']))
        assert c['build_commands'],'missing source/ELF build join '+c['source']
        for b in c['build_commands']:
            records=cached(b['file']);assert records[b['ordinal']-1]==b['record'],'build record navigation'
            assert b['record']['returncode']==0,'unsuccessful build offered'
            cmd=b['record']['command'];assert any('/chips_validation_20261007/' in x and 'sources/chips/'+x.split('/chips_validation_20261007/',1)[1]==c['source'] for x in cmd),'build does not name asserted source '+c['source']
        count=0
        with p.open() as f:
            for line in f:
                if re.search(r'\bTEST_CASE\s*\(',line):count+=1
        if c['case'] not in {'fail256','wrong-answer'}:assert count>0,'no original assertions '+c['source']
        assert count==c['assertions']['count'],'assertion navigation count'
        if c['case']=='fail256':assert 'li TESTNUM, 256' in p.read_text() and 'RVTEST_FAIL' in p.read_text(),'original failure control source'
        source_assertions+=count
        for name in ('stage1','capture_patch'):
            candidate=root/c[name]
            if candidate.exists() or candidate.is_symlink():
                candidate=path(c[name])
                rel=candidate.relative_to(root/'sources/chips'/c['batch']).as_posix()
                if rel in hashes:assert digest(candidate)==hashes[rel],'generation identity '+c[name]
    verified_receipts=set();forms=collections.defaultdict(set);controls=collections.Counter(); configs=collections.Counter();cases=collections.defaultdict(set)
    for n in nav:
        r=ledger[n['ledger_row_id']];cell=cells[n['cell_id']];cand=n['candidate']
        assert r['candidate']==cand and r['executable_sha256']==expected_candidates[cand],'candidate identity substitution'
        assert r['elf_sha256']==n['elf_sha256']==cell['elf_sha256'],'ELF join'
        assert r['VLEN']==n['VLEN']==str(cell['vlen']),'configuration join'
        assert json.loads(r['flags_json'])==cell['flags'],'flags join'
        c=chain_index[n['batch'],n['case']];assert c['source']==n['source'] and c['source_sha256']==n['source_sha256'],'source navigation'
        receipt=n['receipt']
        if receipt not in verified_receipts:
            result=read(path(receipt+'/result.json'));case=read(path(receipt+'/case.json')) if cand=='clean961' else cell
            for field in ('id','elf_sha256','vlen','flags','control','expected_returncode','expected_stdout'):
                assert case[field]==cell[field],'registered expectation changed '+receipt+' '+field
            stdout=path(receipt+'/stdout').read_bytes();stderr=path(receipt+'/stderr').read_bytes()
            assert hashlib.sha256(stdout).hexdigest()==result['stdout_sha256'],'stdout identity'
            assert hashlib.sha256(stderr).hexdigest()==result['stderr_sha256'],'stderr identity'
            status=original.classify(result['returncode'],stdout,cell,error=result.get('error'),timed_out=result.get('status')=='TIMEOUT')
            recorded_status=result.get('status',result.get('classification'))
            if cand=='historical2af5':assert result['expected_returncode']==cell['expected_returncode'] and result['matched_expected'] is True,'historical original predicate'
            assert status=='PASS' and recorded_status=='PASS','original assertion/exit acceptance rejected '+receipt+' '+status
            assert str(result['returncode'])==r['returncode'],'recorded exit join'
            assert result['elf_sha256']==r['elf_sha256'],'result identity'
            if cand=='clean961':
                assert result['control']==cell['control'],'control identity'
                batch=Path(receipt).parent.name
                inv=cached('records/clean961/batches/'+batch+'/invocation.json')
                assert r['executable_sha256'] in inv['engine_files_before'].values() and r['library_sha256'] in inv['engine_files_before'].values(),'invocation engine identity'
                assert inv['runner_sha256']==digest(path('tools/runner.original.py')),'original runner identity'
            else:read(path(receipt+'/environment.json'))
            command=read(path(receipt+'/command.json'));assert len(command)==len(cell['flags'])+1,'command size'
            # {WORK} is an original runtime temporary directory, retained only as provenance.
            for actual,expected in zip(command[1:],cell['flags']):
                if '{WORK}' in expected:assert actual.startswith(expected.split('{WORK}')[0]) and actual.endswith(expected.split('{WORK}')[1]),'command path'
                else:assert actual==expected,'command flag'
            verified_receipts.add(receipt)
            if cell['control']:controls[cand]+=1
            else:configs[cand,n['VLEN'],n['arm']]+=1
        if not cell['control']:
            b=bindings[r['row_id']];assert b['candidate']==cand and b['acceptance']=='ACCEPTED_SCOPED' and b['result']=='PASS','accepted binding'
            assert n['form'] in b['result_checked_forms'].split(';'),'form/checker join'
            forms[cand].add(n['form']);cases[cand].add((n['batch'],n['case']))
    assert len(forms['clean961'])==len(forms['historical2af5'])==595,'primary 595 form set'
    assert forms['clean961']==forms['historical2af5'],'candidate form difference'
    # Source-level geometry is separate from dynamically observed branch coverage.
    geometry=0;geometry_sources=set();source_hash_cache={};header_cache={}
    spec=importlib.util.spec_from_file_location('retained_geometry',path('sources/chips/coverage_geometry.py'))
    original_geometry=importlib.util.module_from_spec(spec);spec.loader.exec_module(original_geometry)
    for g in csv.DictReader(path('sources/chips/SOURCE_GEOMETRY.csv').open()):
        p=path('sources/chips/'+g['source'])
        if p not in source_hash_cache:source_hash_cache[p]=digest(p)
        assert source_hash_cache[p]==g['source_sha256'],'geometry source identity '+g['source']
        if p not in header_cache:
            text=p.read_text();newlines=[m.start() for m in re.finditer('\n',text)];headers=list(original_geometry.HEADER.finditer(text));records={}
            for i,m in enumerate(headers):
                end=headers[i+1].start() if i+1<len(headers) else len(text)
                count=len(re.findall(r'^'+re.escape(g['form'])+r'\s+.*$',text[m.end():end],re.M))
                records[bisect_left(newlines,m.start())+1]=(m.groups(),count)
            header_cache[p]=(g['form'],records)
        form,records=header_cache[p];assert form==g['form'],'multi-form geometry source'
        groups,target_count=records[int(g['line'])]
        assert groups==(g['requested_vl'],g['lmul'],g['sew'],g['masked']),'geometry fields differ from original source header'
        assert target_count==int(g['target_occurrences']),'source target occurrences'
        geometry+=1;geometry_sources.add(g['source'])
    literals=read(path('LITERAL_CONFIG_CONTEXTS.json'))
    missing_geometry={c['source'] for c in chains if c['case'] not in {'fail256','wrong-answer'} and str(Path(c['source']).relative_to('sources/chips')) not in geometry_sources}
    assert {c['source'] for c in literals}==missing_geometry,'incomplete literal configuration navigation'
    for context in literals:
        p=path(context['source']);assert digest(p)==context['source_sha256'],'literal source identity'
        lines=p.read_text().splitlines()
        for entry in context['headers']+context['instructions']:
            assert lines[entry['line']-1]==entry['text'],'literal source line differs'
            if 'window' in entry:
                start=entry['window_first_line']-1
                assert lines[start:start+len(entry['window'])]==entry['window'],'configuration setup/assertion window differs'
    historical_failures=0
    for exclusion in registration['excluded']:
        prefix='artifacts/chips_validation_20261007/'
        original_record='sources/chips/'+exclusion['original_record'].split(prefix,1)[1]
        path(original_record+'/stdout');path(original_record+'/stderr');path(original_record+'/command.json')
        assert exclusion['original_returncode']!=0 and exclusion['original_matched_expected'] is False,'original failure relabeled'
        historical_failures+=1
    blocked=list(csv.DictReader(path('records/scope/CHIPS_BLOCKED.csv').open()))
    unsafe_sources={r['source_file'] for r in blocked if 'UNSAFE_ORIGINAL_STORE_GEOMETRY' in r['blocker']}
    assert len(unsafe_sources)==8,'unsafe original store exclusions'
    for name in unsafe_sources:path('sources/chips/'+name.split('artifacts/chips_validation_20261007/',1)[1])
    licenses={'Apache CHIPS':path('upstream/chips/LICENSE'),'BSD env':path('upstream/chips/env/riscv-test-env/LICENSE'),'MIT local':path('licenses/LOCAL-MIT.txt')}
    assert 'Apache License' in licenses['Apache CHIPS'].read_text()
    assert 'Regents' in licenses['BSD env'].read_text() and 'Redistribution' in licenses['BSD env'].read_text()
    assert 'Permission is hereby granted' in licenses['MIT local'].read_text()
    assert 'Regents' in path('licenses/GEM5_ASMTEST_BSD.txt').read_text()
    assert 'TestFloat Release 3e' in path('licenses/TESTFLOAT_NOTICE.md').read_text()
    return {'status':'PASS','payload_files':len(files),'primary_binding_rows':len(bindings),'source_chains':len(chains),'original_TEST_CASE_assertions':source_assertions,'unique_receipts':len(verified_receipts),'forms':{k:len(v) for k,v in forms.items()},'positive_source_cases':{k:len(v) for k,v in cases.items()},'controls':dict(controls),'receipt_configurations':[{'candidate':k[0],'VLEN':k[1],'arm':k[2],'positive_receipts':v} for k,v in sorted(configs.items())],'original_excluded_failure_records':historical_failures,'unsafe_original_store_sources':len(unsafe_sources),'literal_configuration_sources':len(literals),'source_geometry_rows':geometry,'source_geometry_files':len(geometry_sources),'geometry_scope':'source context only; no Cartesian product, runtime VL/branch or independent per-arm method admission','new_guest_executions':0}


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('root',type=Path);ap.add_argument('--form');ap.add_argument('--candidate',choices=['clean961','historical2af5']);ap.add_argument('--vlen');ap.add_argument('--arm');ap.add_argument('--batch');ap.add_argument('--case');ap.add_argument('--contexts',action='store_true');a=ap.parse_args()
    try:
        if a.form:
            files=read(safe(a.root,'FILES.json',{'FILES.json':None}))
            rows=[r for r in csv.DictReader(safe(a.root,'NAVIGATION.csv',files).open()) if r['form']==a.form and all(v is None or r[k]==v for k,v in [('candidate',a.candidate),('VLEN',a.vlen),('arm',a.arm),('batch',a.batch),('case',a.case)])]
            if a.contexts:
                source_names={str(Path(r['source']).relative_to('sources/chips')) for r in rows}
                contexts=[g for g in csv.DictReader(safe(a.root,'sources/chips/SOURCE_GEOMETRY.csv',files).open()) if g['source'] in source_names]
                print(json.dumps({'witnesses':rows,'source_contexts':contexts,'literal_contexts':[c for c in read(safe(a.root,'LITERAL_CONFIG_CONTEXTS.json',files)) if c['source'] in {r['source'] for r in rows}],'scope':'source configurations; exact source lines; not runtime branch coverage'},indent=2))
            else:print(json.dumps(rows,indent=2))
            return 0 if rows else 1
        print(json.dumps(verify(a.root),indent=2));return 0
    except (AssertionError,ValueError,KeyError,OSError) as e:print('CHIPS inspection rejected: '+str(e),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
