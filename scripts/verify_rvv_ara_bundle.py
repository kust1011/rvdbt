"""Offline Task91 acceptance check, using the retained Ara parsers; no guests."""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def package_path(root, name):
    """Reject non-relative names and symlinks before following any component."""
    if not isinstance(name, str) or '\\' in name or any(
        part in ('', '.', '..') for part in name.split('/')
    ):
        raise ValueError('invalid package path: ' + str(name))
    p = root
    for part in name.split('/'):
        p = p / part
        if p.is_symlink():
            raise ValueError('symlink package path: ' + name)
    return p


def verify(root):
    root = root.resolve()
    manifest = json.loads(package_path(root, 'FILES.json').read_text())
    def path(name):
        p = package_path(root, name)
        if name not in manifest:
            raise ValueError('unmanifested package path: ' + name)
        return p
    for name, record in manifest.items():
        p = path(name)
        if not p.is_file() or digest(p.read_bytes()) != record['sha256']:
            raise ValueError('missing/altered evidence: ' + name)
    evidence = json.loads(path('ARA_EVIDENCE.json').read_text())
    # Import only content-verified producer parsers. They read their local run.original.
    modules = {}
    def module(task, name='checker'):
        key = task, name
        if key not in modules:
            spec = importlib.util.spec_from_file_location(task+'_'+name, path('records/'+task+'/'+name+'.py'))
            m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); modules[key] = m
        return modules[key]
    groups = {}
    def group(task, case):
        if task not in groups:
            groups[task] = {g['name']: g for g in json.loads(path('records/'+task+'/GROUPS.json').read_text())}
        return groups[task][case]
    joins = json.loads(path('BINDINGS.json').read_text())
    legal = {r['file']: r for r in json.loads(path('LEGAL_RESTORATIONS.json').read_text())}
    for name, r in legal.items():
        if digest(path(name).read_bytes()[r['notice_prefix_bytes']:]) != r['original_sha256']:
            raise ValueError('legal restoration changed compiled payload: '+name)
    originals = {tuple(b['identity']): b for b in evidence['bindings']}
    receipts = {}
    counts = collections.Counter()
    for b in joins:
        rawdir = b['raw']
        original = originals[tuple(b['identity'])]
        if (b['form'],b['scope'],b['positive']) != (original['form'],original['scope'],original['positive']):
            raise ValueError('binding disposition changed')
        for file, expected in original.get('raw_sha256',{}).items():
            if digest(path(rawdir+'/'+file).read_bytes()) != expected:
                raise ValueError('original raw identity changed: '+rawdir+'/'+file)
        if rawdir not in receipts:
            result = json.loads(path(rawdir+'/result.json').read_text())
            raw = path(rawdir+'/stdout').read_bytes()
            ok, obs, cases = module(b['parser_task']).check_cases(group(b['parser_task'], b['case']), result['returncode'], raw)
            receipts[rawdir] = result, raw, ok, obs, cases
        result, raw, ok, obs, cases = receipts[rawdir]
        if b['scope'] == 'TEST_CASE1_2_ONLY':
            if ok or result['status'] != 'RESULT_MISMATCH' or not all(c['status']=='PASS' for c in cases[:2]) or not all(c['status']=='RESULT_MISMATCH' for c in cases[2:]):
                raise ValueError('scoped MAC original failures changed: '+rawdir)
        elif b['positive']:
            if not ok or result['returncode'] != 0 or result['status'] != 'PASS':
                raise ValueError('failed evidence offered for acceptance: '+rawdir)
        if b['task']=='ara89':
            g=group('ara89',b['case'])
            if not module('ara89','exact_check').check_exact(g,obs)['accepted'] or not module('ara89','initializer_check').check_initialization(raw,0)['accepted']:
                raise ValueError('Ara89 configuration/initialization mismatch: '+rawdir)
            if b['M2_fast_admission'] is not None or b['M2_target_admission_status']!='UNOBSERVED':
                raise ValueError('unsupported M2 admission')
        if b.get('adapter') and original.get('artifacts',{}).get('adapter'):
            payload=path(b['adapter']).read_bytes()
            if b['adapter'] in legal: payload=payload[legal[b['adapter']]['notice_prefix_bytes']:]
            if digest(payload)!=original['artifacts']['adapter']['sha256']:
                raise ValueError('compiled adapter identity changed: '+b['adapter'])
        if b.get('source_range'):
            src=path(b['source']).read_text().splitlines(keepends=True)
            start,end=b['source_range']
            if digest(''.join(src[start-1:end]).encode()) != b['block_sha256']:
                raise ValueError('source range changed: '+b['source'])
        if b.get('source_sha256') and digest(path(b['source']).read_bytes())!=b['source_sha256']:
            raise ValueError('original source changed: '+b['source'])
        counts[b['scope']]+=1
    if len(joins)!=2430 or len({tuple(b['identity']) for b in joins})!=2430:
        raise ValueError('binding identity/cardinality mismatch')
    a=evidence['ara89']; cp=a['checkpoint_diff']
    if len(cp['added'])!=26 or cp['removed'] or set(cp['new']) != set(cp['old'])|set(cp['added']):
        raise ValueError('exact26 form join mismatch')
    admitted={b['form'] for b in joins if b['positive']}
    if set(evidence['diff']['new'])!=set(evidence['diff']['old'])|admitted:
        raise ValueError('cumulative form join mismatch')
    blocks=collections.defaultdict(list)
    for b in joins:
        if b['task']=='ara89': blocks[b['identity'][1]].append(b)
    if len(blocks)!=166 or any({b['arm'] for b in v}!={'reference','B','M1','M2','BOTH'} or len(v)!=5 for v in blocks.values()):
        raise ValueError('missing Ara89 block/arm binding')
    for h in json.loads(path('FAILED_HISTORY.json').read_text()):
        r=json.loads(path(h['raw']+'/result.json').read_text())
        if digest(path(h['source']).read_bytes()) != h['compiled_historical_source']['source_sha256']:
            raise ValueError('historical compiled source changed')
        if r['returncode']!=1 or r['status']=='PASS' or h['positive']:
            raise ValueError('preliminary failure admitted')
    return dict(status='PASS',files_verified=len(manifest),bindings=len(joins),unique_binding_receipts=len(receipts),scope_bindings=dict(counts),ara89_blocks=len(blocks),ara89_receipts=len({b['raw'] for b in joins if b['task']=='ara89'}),ara89_exact_added_forms=26,retained_preliminary_failures=8,M2_target_admission='UNOBSERVED',M2_fast_admission=None,new_DUT_executions=0)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',nargs='?',type=Path,default=Path(__file__).resolve().parent)
    a=p.parse_args()
    try: print(json.dumps(verify(a.root),indent=2))
    except (ValueError,KeyError,OSError,AssertionError) as e: p.exit(1,'REJECT: '+str(e)+'\n')

if __name__=='__main__': main()
