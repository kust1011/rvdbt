# SPDX-License-Identifier: Apache-2.0
"""Offline Task53 source/signature/predicate/navigation verification, no ISA runs."""
import argparse
import ast
import collections
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True

CHECKER = '943d320aaa7ca95dc405495a4cf993ad08275db4320e2f95df1e87d6b0a9e111'
PROCESSOR = '1427bce89a2272f41184fea8777dc2a5ba34a64e918ac26ec1d5d044afe2e39d'
DUT = '6fda0f9ab06c2c824b5301d1f302b76799842981b00a88fffa85fe43f1dbd84f'
LIBRARY = '1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def package_path(root, name):
    if not isinstance(name, str) or '\\' in name or any(p in ('', '.', '..') for p in name.split('/')):
        raise ValueError('invalid package path: '+str(name))
    p = root
    for part in name.split('/'):
        p = p/part
        if p.is_symlink():
            raise ValueError('symlink package path: '+name)
    return p


def original_predicates(audit_source):
    """Compile only the original pure predicates; do not import its audit runner."""
    tree = ast.parse(audit_source)
    accepted = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name=='accepted')
    scope = {}
    exec(compile(ast.Module(body=[accepted], type_ignores=[]), 'original-audit-accepted', 'exec'), scope)
    sail = [n.value for n in ast.walk(tree) if isinstance(n, ast.Assign) and
            any(isinstance(t, ast.Name) and t.id=='ok' for t in n.targets) and
            'TEST SIGRUN' in ast.get_source_segment(audit_source, n)]
    if len(sail)!=1:
        raise ValueError('original Sail predicate not uniquely resolved')
    expression = compile(ast.Expression(sail[0]), 'original-audit-sail', 'eval')
    def check_sail(raw, case):
        return eval(expression, {}, dict(raw=raw, text=raw['text'], N=case))
    return scope['accepted'], check_sail


def validate_receipt(predicate, result, text, case, expected=True):
    ok = predicate(dict(result, text=text), case)
    if ok != expected:
        raise ValueError('original predicate rejected receipt: '+case)
    return ok


def verify(root):
    root = root.resolve()
    manifest = json.loads(package_path(root, 'FILES.json').read_text())
    def path(name):
        p = package_path(root, name)
        if name not in manifest:
            raise ValueError('unmanifested dependency: '+name)
        return p
    def read(name):
        return json.loads(path(name).read_text())
    for name, record in manifest.items():
        p = path(name)
        if not p.is_file() or p.stat().st_size!=record['bytes'] or sha(p.read_bytes())!=record['sha256']:
            raise ValueError('missing/altered payload: '+name)
    files = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    if files != set(manifest)|{'FILES.json'}:
        raise ValueError('unmanifested payload files')
    audit = read('records/AUDIT.json'); reg = read('records/REGISTERED.json')
    for name, item in read('ORIGINAL_IDENTITIES.json').items():
        if sha(path(name).read_bytes())!=item['sha256']:
            raise ValueError('original retained identity changed: '+name)
    for name in ('records/common/user_env/signature.h', 'records/common/upstream/env/signature.h'):
        if sha(path(name).read_bytes()) != CHECKER:
            raise ValueError('original signature checker changed')
    processor_path = path('records/common/reference_config/sig_modify.py')
    if sha(processor_path.read_bytes())!=PROCESSOR or sha(path('sources/act/framework/sig_modify.py').read_bytes())!=PROCESSOR:
        raise ValueError('pinned signature processor changed')
    spec = importlib.util.spec_from_file_location('original_sig_modify', processor_path)
    processor = importlib.util.module_from_spec(spec); spec.loader.exec_module(processor)
    accepted, sail = original_predicates(path('records/audit.py').read_text())
    pins = read('records/LAUNCH_REGISTRATION.json')['pins']
    assert pins['/home/vick/ara-clean961-stage/elfrun']==DUT
    assert pins['/home/vick/ara-clean961-stage/libdbtjitshared.so']==LIBRARY
    inputs = read('records/INPUT_DISPOSITIONS.json')
    assert len(inputs)==2147 and reg['XLEN']==32 and reg['ELEN']==64 and reg['VLEN']==1024
    assert collections.Counter(x['applicability'] for x in inputs)=={'APPLICABLE':1919,'NOT_APPLICABLE':228}
    outputs = {Path(o['path']).stem:(o,x) for x in inputs for o in x.get('outputs', [])}
    cases = read('CASES.json'); case_index={c['case']:c for c in cases}
    assert len(cases)==len(case_index)==len(outputs)==1919
    paths = read('PATHS.json')
    for target in paths.values(): path(target)
    counts = collections.Counter(); references=collections.Counter(); receipt_keys=set(); roundtrips=0
    launch = read('records/LAUNCH_REGISTRATION.json')
    audit_cases = {c['case']:c for c in audit['records']}
    for c in cases:
        n=c['case']; r=read(c['result']); o,inp=outputs[n]
        assert r==audit_cases[n] and (c['input_id'],c['form'],c['sew'],c['status'])==(r['input_id'],r['form'],r['sew'],r['status'])
        assert sha(path(c['source']).read_bytes())==o['sha256']==r['source_sha256']
        assert paths['artifacts/rvv_validation_delivery_20261009/act-generation53/'+o['path']]==c['source']
        assert c['references']==r['reference'] and c['DUT']==r['DUT']
        counts[c['status']]+=1
        for name in ('checker','original_checker','processor','adapter','linker','capture_config'): path(c[name])
        if c['status']=='PRIOR_ACCEPTED':
            assert not r['DUT'] and not r['reference'] and len(r['prior_joins'])==4
            assert c['inspection_scope'].startswith('OUTSIDE_PRIMARY_PACKAGE')
            continue
        oracle=read(c['oracle']); preserve=read(c['preservation'])
        assert oracle['source_sha256']==r['source_sha256']
        assert sha(path(c['signature']).read_bytes())==oracle['raw_sig_sha256']
        assert sha(path(c['expected']).read_bytes())==oracle['processed_results_sha256']==r['oracle_sha256']
        assert oracle['processor_sha256']==PROCESSOR
        assert oracle['config_sha256']==sha(path(c['capture_config']).read_bytes())
        assert oracle['Sail_sha256']==pins['/home/vick/rvv-act4-tools/bin/sail_riscv_sim']
        assert preserve['source_unchanged'] and preserve['checker_unchanged']
        assert preserve['geometry']['VLEN']==1024 and preserve['geometry']['ELEN']==64
        path(c['checker_scope']); path(c['source_scope'])
        # Pure formatting of an existing retained capture, never Sail/ISA execution.
        with tempfile.TemporaryDirectory(prefix='act99-signature-') as tmp:
            sig=Path(tmp)/'capture.sig'; sig.write_bytes(path(c['signature']).read_bytes())
            processor.process_signature_file(sig,32)
            if sig.with_suffix('.results').read_bytes()!=path(c['expected']).read_bytes():
                raise ValueError('original signature processor roundtrip mismatch: '+n)
        roundtrips+=1
        for ref in r['reference']:
            d='records/cases/'+n+'/'+ref['raw']; raw=read(d+'/result.json')
            text=path(d+'/stdout').read_text(errors='replace')+path(d+'/stderr').read_text(errors='replace')
            assert read(d+'/IDENTITY.json')==read(d+'/IDENTITY_AFTER.json')==pins
            cmd=read(d+'/command.json');assert raw['returncode']==ref['returncode'] and not raw['timeout']
            predicate=sail if ref['engine']=='Sail' else accepted
            validate_receipt(predicate,raw,text,n,ref['status']=='PASS')
            if ref['engine']=='Sail':
                assert cmd[0]=='/home/vick/rvv-act4-tools/bin/sail_riscv_sim'
                assert cmd[1:3]==['--config','/home/vick/act-generation53/common/reference_config/sail.json']
                assert '--test-signature' in cmd and '--signature-granularity' in cmd
            else:
                assert cmd[:3]==['/home/vick/rvv_qemu_compare_20260930/bin/qemu-riscv32','-cpu','rv32,v=true,vlen=1024,elen=64']
                if ref['status']=='REFERENCE_ERROR':assert raw['returncode']==-4 and r['DUT']==[]
            references[ref['engine']+':'+ref['status']]+=1
        for dut in r['DUT']:
            d='records/cases/'+n+'/'+dut['raw'];raw=read(d+'/result.json')
            text=path(d+'/stdout').read_text(errors='replace')+path(d+'/stderr').read_text(errors='replace')
            validate_receipt(accepted,raw,text,n)
            assert not raw['timeout'] and raw['returncode']==dut['returncode']==0 and dut['status']=='PASS'
            assert read(d+'/IDENTITY.json')==read(d+'/IDENTITY_AFTER.json')==pins
            cmd=read(d+'/command.json');assert cmd[0]=='/home/vick/ara-clean961-stage/elfrun'
            normalized=['--fsroot={WORK}/fs' if x.startswith('--fsroot=') else '--cache={WORK}/cache' if x.startswith('--cache=') else x for x in cmd[1:]]
            assert normalized==dut['flags'] and normalized[:len(launch['flags'][dut['arm']])]==launch['flags'][dut['arm']]
            assert dut['elf_sha256']==r['elf_sha256'] and dut['oracle_sha256']==oracle['processed_results_sha256']
            key=(DUT,LIBRARY,dut['elf_sha256'],tuple(normalized))
            assert key not in receipt_keys; receipt_keys.add(key)
        if c['status']=='PASS':assert {x['arm'] for x in r['DUT']}=={'B','M1','M2','BOTH'}
    final=read('records/FINAL_COUNTS.json')
    assert dict(counts)==final['output_counts']=={'PASS':1876,'REFERENCE_ERROR':2,'PRIOR_ACCEPTED':41}
    assert dict(references)==final['reference_counts'] and len(receipt_keys)==final['new_DUT_calls']==7504
    assert roundtrips==1878
    with path('SUITE_RUN_MANIFEST.csv').open() as f: ledger=list(csv.DictReader(f))
    with path('ACTUAL_FORM_VALIDATION_BINDINGS.csv').open() as f: bindings=list(csv.DictReader(f))
    by_id={r['row_id']:r for r in ledger};bound={r['ledger_row_id']:r for r in bindings}
    assert len(ledger)==len(by_id)==15364 and len(bindings)==len(bound)==7512
    nav=read('NAVIGATION.json');assert len(nav)==7512 and len({x['ledger_row_id'] for x in nav})==7512
    blocked=0
    for n in nav:
        b=bound[n['ledger_row_id']];r=by_id[n['ledger_row_id']];c=case_index[n['case']]
        assert b['candidate']==r['candidate']=='clean961' and b['executable_sha256']==r['executable_sha256']==DUT
        assert b['library_sha256']==r['library_sha256']==LIBRARY
        assert (n['form'],n['case'],n['arm'],n['result'],n['acceptance'],n['flags_json'])==(b['target_forms'],b['source_case'],b['arm'],b['result'],b['acceptance'],b['flags_json'])
        assert n['source']==c['source'] and n['checker']==c['checker'] and n['oracle']==c['oracle']
        assert paths[b['source_file']]==c['source']
        assert b['checker_identity']==r['checker_identity']==CHECKER
        assert json.loads(b['reference_identity'])==json.loads(r['reference_identity'])==read(c['oracle'])
        if n['raw']:
            assert b['result']==r['dut_status']=='PASS' and b['acceptance']=='ACCEPTED_SCOPED'
            assert paths[b['raw_stdout']]==n['raw']+'/stdout' and paths[b['raw_stderr']]==n['raw']+'/stderr'
            dut=next(x for x in c['DUT'] if x['arm']==n['arm'])
            assert b['elf_sha256']==dut['elf_sha256'] and json.loads(b['flags_json'])==dut['flags']
            assert json.loads(r['original_command'])==read(n['raw']+'/command.json')
        else:
            assert r['dut_status']==b['result']=='BLOCKED' and c['status']=='REFERENCE_ERROR'
            assert not c['DUT'];blocked+=1
    assert blocked==8
    forms=read('FORMS.json');assert sorted(i for v in forms.values() for i in v)==list(range(1919))
    for form, indices in forms.items():assert all(cases[i]['form']==form for i in indices)
    prior=read('OUTSIDE_PRIMARY.json');assert len(prior)==41 and sum(len(x['prior_row_ids']) for x in prior)==164
    prelaunch=collections.Counter()
    for folder in ('adapter-blocked-attempts','adapter-corrections-v2'):
        for name in manifest:
            if name.startswith('records/'+folder+'/') and name.endswith('/RESULT.json'):
                r=read(name);assert r['status']=='BLOCKED' and r['DUT']==r['reference']==[]
                prelaunch[folder]+=1
    assert dict(prelaunch)=={'adapter-blocked-attempts':5,'adapter-corrections-v2':210}
    diagnostic=read('records/REFERENCE_DIAGNOSTICS.json')
    assert diagnostic['reference_calls']==2 and diagnostic['DUT_calls']==0
    for d in diagnostic['records']:
        assert read('records/reference-diagnostics/'+d['case']+'/result.json')['returncode']==d['returncode']==-4
    assert len(read('records/PROFILE_GAPS.json')['unresolved_applicable_source_profile_inputs'])==4
    assert read('DEPENDENCIES.json')['inspection_missing']==[]
    excluded=read(read('DEPENDENCIES.json')['exact_excluded_identities'])
    assert all(x['original'] not in paths and len(x['sha256'])==64 for x in excluded)
    for d in read('ADAPTER_DELTAS.json'):
        for k in ('original','adapter','diff'):path(d[k])
    for name in read('LICENSE_AUDIT.json')['files']:path(name)
    return dict(status='PASS', files_verified=len(manifest), original_identity_bindings=len(read('ORIGINAL_IDENTITIES.json')),
                source_outputs=1919, primary_signature_roundtrips=roundtrips, original_guest_checker_sha256=CHECKER,
                archived_DUT_receipts=len(receipt_keys), primary_reference_receipts=dict(references),
                unlaunched_DUT_arms=blocked, prelaunch_exclusions=dict(prelaunch), diagnostic_reference_repeats=2,
                outside_prior_outputs=41, outside_prior_receipts=164, selected_ledger_rows=15364, bindings=7512,
                inspection_missing=[], new_DUT_executions=0, new_reference_executions=0,
                limitation='Original guest assertions are inspectable; host check evaluates original retained summary predicates, not ISA results independently.')


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('root',type=Path)
    ap.add_argument('--form');ap.add_argument('--case');a=ap.parse_args()
    result=verify(a.root)
    print(json.dumps(result,indent=2))
    if a.form or a.case:
        nav=json.loads((a.root/'NAVIGATION.json').read_text())
        print(json.dumps([x for x in nav if (not a.form or x['form']==a.form) and (not a.case or x['case']==a.case)],indent=2))
