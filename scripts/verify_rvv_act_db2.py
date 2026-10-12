# SPDX-License-Identifier: Apache-2.0
"""Offline frozen db2 source/oracle/raw predicate checks; never execute guests."""
import argparse
import ast
import collections
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

from package_rvv_act_db2 import digest
from verify_rvv_act_inspection import package_path

sys.dont_write_bytecode = True
CHECKER = 'd4e7f032695ccd4bfb7dcf92687909aa20d4140e7f4ec7d999b829382f0ccacb'
PROCESSOR = '1051fc5c9044acbce52ecd1bb889f3658e0c2a3069fe2196fd868b64b01da6d5'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def original_predicates(source):
    """Extract only original runner's three pure acceptance expressions."""
    tree = ast.parse(source); expressions = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'ok' for t in n.targets):
            expressions.append(n.value)
    require(len(expressions) == 3, 'original acceptance expressions changed')
    return [compile(ast.Expression(n), 'original-execute109-predicate', 'eval') for n in expressions]


def validate_raw(directory, predicate, case, signature, expected=True, returncode=0):
    """Same raw concatenation and original predicate, with explicit file/exit checks."""
    for name in ('result.json', 'stdout', 'stderr', 'command.json', 'IDENTITY.json', 'IDENTITY_AFTER.json'):
        require((directory/name).is_file(), 'missing raw '+str(directory/name))
    raw_result = json.loads((directory/'result.json').read_text())
    require(raw_result['returncode'] == returncode and raw_result['timeout'] is False,
            'nonzero/timeout/inconsistent exit: '+str(directory))
    raw = (directory/'stdout').read_text(errors='replace')+(directory/'stderr').read_text(errors='replace')
    ok = eval(predicate, {'__builtins__': {}}, dict(rc=raw_result['returncode'],raw=raw,N=case,sig=signature))
    require(ok is expected, 'original predicate mismatch: '+str(directory))
    return raw_result


def verify(root, full_raw_root=None):
    if not __debug__:
        raise RuntimeError('db2 verification rejects -O/-OO/PYTHONOPTIMIZE')
    root = root.resolve()
    def path(name): return package_path(root, name)
    def read(name): return json.loads(path(name).read_text())
    manifest = read('FILES.json')
    for name, item in manifest.items():
        p = path(name)
        require(p.is_file() and p.stat().st_size == item['bytes'] and digest(p) == item['sha256'], 'missing/altered payload: '+name)
    require({str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()} == set(manifest)|{'FILES.json'}, 'unmanifested payload')
    for target in read('PATHS.json').values(): require(target in manifest, 'unmanifested path mapping')
    for name in ('user_env', 'upstream/env'):
        require(digest(path('records/common/'+name+'/signature.h')) == CHECKER, 'original checker changed')
    processor = path('records/producer/framework/src/act/sig_modify.py')
    require(digest(processor) == PROCESSOR, 'original processor changed')
    # reference_config contains an older retained copy; execute109 imports the
    # pinned producer processor above. Do not retroactively substitute that copy.
    spec = importlib.util.spec_from_file_location('db2_original_processor', processor)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    predicates = original_predicates(path('records/execute109.py').read_text())
    queue = read('records/EXACT_QUEUE.json'); cases=read('CASES.json'); joins=read('TASK104_JOIN.json')
    require(len(queue)==1919 and len(cases)==1918 and len(joins)==1, 'queue denominator')
    require(joins[0]['output']['case']=='Vls32-vluxei32.v' and joins[0]['output']['disposition']=='TASK104_ACCEPTED', 'Task104 exact join')
    outputs={q['output']['case']:q for q in queue}
    require(len(outputs)==1919 and len({c['case'] for c in cases})==1918, 'duplicate output/case')
    launch=read('records/LAUNCH_REGISTRATION.json'); pins=launch['pins']
    require(pins['/home/vick/ara-clean961-stage/elfrun']=='6fda0f9ab06c2c824b5301d1f302b76799842981b00a88fffa85fe43f1dbd84f', 'DUT pin')
    require(pins['/home/vick/ara-clean961-stage/libdbtjitshared.so']=='1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d', 'library pin')
    count=collections.Counter(); refs=collections.Counter(); dut=collections.Counter(); macros=collections.Counter(); targets=0; keys=set()
    for c in cases:
        n=c['case']; r=read(c['result']); q=outputs[n]; base='records/cases/'+n+'/'
        require(c['status']==r['status'] and c['form']==r['form']==q['input']['form'] and c['sew']==r['sew']==q['input']['sew'], 'case index mismatch '+n)
        require(digest(path(c['source']))==q['output']['sha256']==r['source_sha256'], 'source mismatch '+n)
        require(r['status'] in ('PASS','REFERENCE_ERROR'), 'unaccepted disposition '+n)
        count[r['status']]+=1
        oracle=read(c['oracle']); preserve=read(base+'PRESERVATION.json')
        require(oracle['source_sha256']==r['source_sha256'] and oracle['processor_sha256']==PROCESSOR, 'oracle identity '+n)
        require(digest(path(c['capture']))==oracle['raw_sig_sha256'], 'capture changed '+n)
        require(digest(path(c['expected']))==oracle['processed_results_sha256']==r['oracle_sha256'], 'expected changed '+n)
        require(oracle['config_sha256']==digest(path('records/common/reference_config/sail.json')), 'capture config changed')
        require(oracle['Sail_sha256']==pins['/home/vick/rvv-act4-tools/bin/sail_riscv_sim'], 'Sail pin')
        require(preserve['source_unchanged'] and preserve['checker_unchanged'] and preserve['geometry']['VLEN']==1024, 'original preservation '+n)
        require(r['checker_sha256']==CHECKER, 'case checker '+n)
        with tempfile.TemporaryDirectory(prefix='db2-offline-') as tmp:
            sig=Path(tmp)/'capture.sig'; sig.write_bytes(path(c['capture']).read_bytes())
            module.process_signature_file(sig,32)
            require(sig.with_suffix('.results').read_bytes()==path(c['expected']).read_bytes(), 'signature processing mismatch '+n)
        for label in ('compile-reference','compile-user'):
            raw=read(base+'raw/'+label+'/result.json')
            require(raw==dict(returncode=0,timeout=False), 'original compilation failure '+n)
        require([x['engine'] for x in r['reference']]==['Sail','QEMU'], 'reference sequence '+n)
        for rec in r['reference']+r['DUT']:
            d=base+rec['raw']; is_dut='arm' in rec; is_sail=rec.get('engine')=='Sail'
            rc=rec['returncode']; accepted=rec['status']=='PASS'
            require(rc==0 if accepted else rc==-4 and not is_dut and r['status']=='REFERENCE_ERROR', 'invalid receipt classification '+n)
            validate_raw(path(d), predicates[0 if is_sail else 2 if is_dut else 1], n,path(c['capture']),accepted,rc)
            require(read(d+'/IDENTITY.json')==read(d+'/IDENTITY_AFTER.json')==pins, 'identity changed '+d)
            cmd=read(d+'/command.json')
            if is_dut:
                normalized=['--fsroot={WORK}/fs' if x.startswith('--fsroot=') else '--cache={WORK}/cache' if x.startswith('--cache=') else x for x in cmd[1:] if not x.startswith('--dump-tbmap=')]
                require(cmd[0]=='/home/vick/ara-clean961-stage/elfrun' and normalized==rec['flags'] and normalized[:len(launch['flags'][rec['arm']])]==launch['flags'][rec['arm']], 'DUT flags '+n)
                require(rec['elf_sha256']==r['elf_sha256'] and rec['oracle_sha256']==r['oracle_sha256'], 'DUT binding '+n)
                key=(rec['elf_sha256'],tuple(normalized)); require(key not in keys, 'duplicate runtime'); keys.add(key);dut[rec['arm']]+=1
            else:
                require(cmd[0]==('/home/vick/rvv-act4-tools/bin/sail_riscv_sim' if is_sail else '/home/vick/rvv_qemu_compare_20260930/bin/qemu-riscv32'), 'reference executable '+n)
                refs[rec['engine']+':'+rec['status']]+=1
        if r['status']=='PASS':
            require(len(r['DUT'])==4 and {d['arm'] for d in r['DUT']}=={'B','M1','M2','BOTH'}, 'missing arm '+n)
            audit=read(c['target_audit']); targets+=len(audit['compiled_targets'])
            require(all(not a['unproven'] and a['proven_executed']==len(audit['compiled_targets']) and a['optimized_target_admission']=='NOT_ESTABLISHED' for a in audit['arms'].values()), 'target audit mismatch')
            macros.update(read(base+'CHECKER_SCOPE_CORRECTED.json')['compiled_macros'])
        else:
            require(n in ('Vf32-vfmv.f.s','Vf64-vfmv.f.s') and r['DUT']==[], 'unexpected blocker')
            source=path(c['source']).read_text()
            require('csrrc' in source and 'csrrs' in source and 'mstatus' in source and 'cp_custom_vfp_state' in source, 'original tested CSR setup removed')
    require(dict(count)=={'PASS':1916,'REFERENCE_ERROR':2}, 'final result count')
    require(dict(dut)=={'B':1916,'M1':1916,'M2':1916,'BOTH':1916}, 'final DUT count')
    require(dict(refs)=={'Sail:PASS':1918,'QEMU:PASS':1916,'QEMU:REFERENCE_ERROR':2}, 'final reference count')
    final=read('records/FINAL_COUNTS_109.json')
    require(targets==final['compiled_target_labels']==483103 and dict(macros)==final['compiled_original_checker_macros'], 'original checker/target totals')
    diag=read('records/REFERENCE_DIAGNOSTICS.json'); require(diag['reference_calls']==2 and diag['DUT_calls']==0, 'diagnostic counts')
    for rec in diag['records']:
        d='records/reference-diagnostics/'+rec['case']+'/'
        require(read(d+'result.json')==rec and rec['returncode']==-4, 'diagnostic failure lost')
        for name in ('command.json','stdout','stderr'): require(path(d+name).is_file(), 'diagnostic raw missing')
    full=read('FULL_RAW_INDEX.json'); checked=0
    if full_raw_root:
        for item in full:
            p=package_path(full_raw_root,item['relative'])
            require(p.is_file() and p.stat().st_size==item['bytes'] and digest(p)==item['sha256'], 'full raw changed '+str(p)); checked+=1
    return dict(status='PASS',files_verified=len(manifest),source_outputs=1919,Task104_prior_join=1,
        Task109_results=dict(count),signature_roundtrips=1918,DUT_receipts=len(keys),reference_receipts=dict(refs),
        diagnostic_failed_QEMU_receipts=2,compiled_target_labels=targets,archived_target_arm_reach_tuples=targets*4,
        original_compiled_checker_macros=dict(macros),full_raw_files_indexed=len(full),full_raw_files_verified=checked,
        new_guest_calls=0,optimized_target_admission='NOT_ESTABLISHED',
        limitation='Frozen original signature processing and raw-summary predicates verified; host does not execute architectural checker or recompute TB reach. Exact full raw is separately indexed.')

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('root',type=Path)
    ap.add_argument('--full-raw-root',type=Path);ap.add_argument('--case');ap.add_argument('--form');a=ap.parse_args()
    print(json.dumps(verify(a.root,a.full_raw_root),indent=2))
    if a.case or a.form:
        print(json.dumps([c for c in json.loads((a.root/'CASES.json').read_text()) if (not a.case or c['case']==a.case) and (not a.form or c['form']==a.form)],indent=2))
