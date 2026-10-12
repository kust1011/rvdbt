"""Task122 joins retained Ara selection to new receipts; original observers only."""
import ast, functools, collections, gzip, hashlib, importlib.util, json, re
from pathlib import Path


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def read(p):
    return json.loads(Path(p).read_text())


@functools.lru_cache(maxsize=None)
def load(path):
    spec = importlib.util.spec_from_file_location('original_'+hashlib.sha256(str(path).encode()).hexdigest(), path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def observer(cell, rc, raw, base=None):
    """Read-only original parser execution; no runner main or guest launch."""
    root = Path(base or cell['producer'])
    c = cell['metadata']
    if cell['kind'] != 'campaign':
        if c.get('observer') == 'case-spans-v2' or 'case_metadata' in c:
            ok, obs, cases = load(root/'checker.py').check_cases(c, rc, raw)
        else:
            m = load(root/'runner.py')
            ok, obs = m.check(c, rc, raw)
            cases = []
        extra = {}
        if cell.get('original_fp_markers'):
            markers=re.findall(rb'ARA(?:84|85)_(?:INITIAL|FINAL)[^\n]*',raw)
            extra['original_fp_marker_match']=[m.decode() for m in markers]==cell['original_fp_markers']
            ok=ok and extra['original_fp_marker_match']
        if cell['task'] == 'ara89':
            extra['initialization'] = load(root/'initializer_check.py').check_initialization(raw,c['expected_initial_frm'])
            extra['exact'] = load(root/'exact_check.py').check_exact(c,obs)
            ok = ok and extra['initialization']['accepted'] and extra['exact']['accepted']
        if cell['scope'] == 'TEST_CASE1_2_ONLY':
            # Preserve the reviewed original failures, never credit whole-file PASS.
            scoped = len(cases)==4 and all(x['status']=='PASS' for x in cases[:2])
            preserved = all(x['status']=='RESULT_MISMATCH' for x in cases[2:])
            return scoped and preserved and rc==cell['original_result']['returncode'], dict(observations=obs,cases=cases,whole_file_pass=ok,preserved_original_failures=preserved,**extra)
        return ok,dict(observations=obs,cases=cases,**extra)
    source = (root/'run.py').read_text()
    tree = ast.parse(source)
    env = dict(re=re,json=json,Path=Path,R=root,j=read,raw=raw,rc=rc,c=c,case=c,n=c.get('vector_assertions'),test=cell.get('runner_case',cell['case']))
    if cell['batch']=='ara_scalar_mask_20261008':
        env.update(n=c['scalar_assertions'],maps=read(root/'COMPILED_SCALAR_MAP.json')[cell.get('runner_case',cell['case'])])
        loop=next(n for n in tree.body if isinstance(n,ast.For) and ast.unparse(n.target)=='m')
        env['expected']=[]
        exec(compile(ast.Module(body=[loop],type_ignores=[]),str(root/'run.py'),'exec'),env)
    env['vl']=int(next(x.split('=',1)[1] for x in cell['normalized_flags'] if x.startswith('--vlen=')))
    functions = [n for n in tree.body if isinstance(n,ast.FunctionDef)]
    exec(compile(ast.Module(body=functions,type_ignores=[]),str(root/'run.py'),'exec'),env)
    # Literal dependencies of the original parser; no top-level runner execution.
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('expected_vsets','expected','expected_obs') for t in node.targets):
            if cell['batch']=='ara_scalar_mask_20261008' and any(isinstance(t,ast.Name) and t.id=='expected' for t in node.targets): continue
            exec(compile(ast.Module(body=[node],type_ignores=[]),str(root/'run.py'),'exec'),env)
    if 'accepted' in env:
        arity = env['accepted'].__code__.co_argcount
        ok = env['accepted'](rc,raw,c) if arity==3 else env['accepted'](rc,raw)
        obs = env['observations'](raw)
        return ok,dict(observations=obs)
    if cell['batch']=='ara_vset_current_20261009':
        # Execute the exact retained post-run block, through its original ok expression.
        loop=next(n for n in tree.body if isinstance(n,ast.For) and ast.unparse(n.target)=='arm')
        start=next(i for i,n in enumerate(loop.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='text' for t in n.targets))
        end=next(i for i,n in enumerate(loop.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='row' for t in n.targets))
        env.update(dest=cell['_rawdir'],a=type('Args',(),dict(case=cell.get('runner_case',cell['case'])))())
        exec(compile(ast.Module(body=loop.body[start:end],type_ignores=[]),str(root/'run.py'),'exec'),env)
        return env['ok'],dict(configs=env['obs'],case_ids=env['starts'])
    text=raw.decode(errors='replace');env.update(text=text,obs=env['observations'](raw),sequences=[int(x) for x in re.findall(r'ARA_ASSERT[^\n]+ sequence=(\d+)',text)])
    if cell['batch']=='ara_masked_store_20261009':
        exp=read(root/'PREREGISTERED.json')['original_expected']
        env.update(samples=[list(map(int,m)) for m in re.findall(r'ARA_MEMORY id=(\d+) index=(\d+) actual_lo=(\d+) actual_hi=(\d+) expected_lo=(\d+) expected_hi=(\d+)',text)],sample_expected=[[11,i,v&0xffffffff,v>>32,v&0xffffffff,v>>32] for i,v in enumerate(exp)])
    expr=next(n.value for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ok' for t in n.targets))
    return eval(compile(ast.Expression(expr),str(root/'run.py'),'eval'),env),dict(observations=env['obs'],samples=env.get('samples'))


def prepare(repo, delivery, output):
    read = functools.lru_cache(maxsize=None)(globals()['read'])
    sha = functools.lru_cache(maxsize=None)(globals()['sha'])
    nav=json.loads(gzip.decompress((repo/'docs/rvv-validation/all-form-records/navigation.json.gz').read_bytes()))
    compact=read(repo/'docs/rvv-validation/current-scope/compact-input.json')['ara_evidence']
    bindings=[b for b in nav['canonical_bindings'] if b['suite']=='Ara' and b['candidate']=='clean961' and b['acceptance']=='ACCEPTED_SCOPED' and b['arm']!='reference']
    grouped=collections.defaultdict(list)
    for b in bindings: grouped[b['raw_stdout']].append(b)
    cells=[];inputs={};excluded=[b for b in nav['canonical_bindings'] if b['suite']=='Ara' and b['acceptance']!='ACCEPTED_SCOPED']
    def pin(p):
        if str(p) not in inputs: inputs[str(p)]=sha(p)
        return p
    for rawpath,rows in sorted(grouped.items()):
        b=rows[0];task=next(t for t in ('ara-campaign48','ara-remainder52','ara-source51','ara82','ara83','ara84','ara85','ara86','ara89') if '/'+t+'/' in rawpath)
        localraw=(Path(rawpath) if rawpath.startswith('/') else delivery.parents[1]/rawpath).parent
        name=localraw.parent.name if task=='ara-source51' else b['source_case'];arm=b['arm'];base=delivery/task
        forms=sorted({f for r in rows for f in r['result_checked_forms'].split(';') if f})
        if not forms:
            # Task82's accepted full-file reductions reused Task52 B; original canonical B rows have empty checked-form cells.
            forms=sorted({x['form'] for x in compact['bindings'] if x.get('task')=='ara82' and x['case']==name})
        scope='TEST_CASE1_2_ONLY' if any(r['checker_scope']=='TEST_CASE1_2_ONLY' for r in rows) else 'ORIGINAL_ACCEPTED_SCOPE'
        if task=='ara-campaign48':
            ident=localraw.parent.name
            conf=next(x for x in read(pin(base/'CONFIGS.json')) if x['case']==name)
            producer=base/'staged'/conf['batch']
            if (producer/'CASES.json').exists():
                metadata=read(pin(producer/'CASES.json'))
                c=next(x for x in metadata if x.get('name',x.get('file'))==conf['runner_case'])
            else:
                assert conf['batch']=='ara_external_pilot_20261007' and name=='vadd'
                c=dict(name=name,original_assertions='run.py accepted function and unchanged vadd.c')
            elf=pin(producer/'bin'/(conf['runner_case']+'.elf'))
            runner=pin(producer/'run.py');selected=read(pin(producer/'SELECTED.json'))
            orig=next(x for x in read(pin(localraw.parent/'results.json')) if x['test']==conf['runner_case'] and x['arm']==arm)
            batch=conf['batch'];kind='campaign'
        else:
            producer=base;filename='CASES_BUILT.json' if task=='ara-source51' else 'GROUPS.json'
            matches=[x for x in read(pin(base/filename)) if x['name']==name]
            assert len(matches)==1,(task,name,filename)
            c=matches[0]
            elf=pin(base/'bin'/(name+'.elf'));runner=pin(base/'runner.py');selected=read(pin(base/'CONFIGS.json'))
            orig=read(pin(localraw/'result.json'));batch=None;kind='group'
        cmd=read(pin(localraw/'command.json'));norm=['--fsroot={WORK}/fs' if x.startswith('--fsroot=') else '--cache={WORK}/cache' if x.startswith('--cache=') else x for x in cmd[1:]]
        matched=[x for x in selected if x['arm']==arm and x['elf_sha256']==sha(elf)]
        assert any(norm==(json.loads(x['flags_json']) if 'flags_json' in x else x['flags']) for x in matched),(task,name,arm)
        assert sha(elf)==orig['elf_sha256'];assert all(r['elf_sha256']==sha(elf) for r in rows), (task,name,'canonical ELF binding');assert 'timeout=120' in runner.read_text()
        for p in producer.glob('*.py'):pin(p)
        for p in producer.glob('*.json'):pin(p)
        if (producer/'run.original.py.txt').exists():pin(producer/'run.original.py.txt')
        adapter=pin(producer/'adapter'/((conf['runner_case'] if kind=='campaign' else name)+'.c'))
        src=Path(b['source_file']);src=src if src.is_absolute() else delivery.parents[1]/src
        if not src.is_file():
            filename=c.get('file',name)
            src=producer/'upstream'/(filename if filename.endswith('.c') else filename+'.c')
        pin(src)
        cell=dict(runner_case=conf['runner_case'] if kind=='campaign' else name,id=f'{task}__{localraw.parent.name}__{name}__{arm}',task=task,batch=batch,kind=kind,case=name,arm=arm,scope=scope,forms=forms,producer=str(producer),elf=str(elf),elf_sha256=sha(elf),adapter=str(adapter),adapter_sha256=sha(adapter),source=str(src),source_sha256=sha(src),runner=str(runner),runner_sha256=sha(runner),metadata=c,original_command=cmd,normalized_flags=norm,original_raw=str(localraw),original_result=orig,timeout=120,bindings=rows)
        if task in ('ara84','ara85','ara86'):
            cell['original_fp_markers']=[m.decode() for m in re.findall(rb'ARA(?:84|85)_(?:INITIAL|FINAL)[^\n]*', (localraw/'stdout').read_bytes())]
            assert len(cell['original_fp_markers'])==2
        cell['_rawdir']=localraw
        ok,detail=observer(cell,orig['returncode'],pin(localraw/'stdout').read_bytes())
        assert ok,(task,name,arm,orig,detail)
        cell.pop('_rawdir');cell['original_observer_check']=True
        cells.append(cell)
    union=sorted({f for c in cells for f in c['forms']});assert union==compact['diff']['new'] and len(union)==422
    assert len(cells)==1904 and collections.Counter(c['arm'] for c in cells)==dict.fromkeys(('B','M1','M2','BOTH'),476)
    q=dict(calls=cells,inputs=inputs,excluded_original_bindings=excluded,counts=dict(calls=len(cells),per_arm=dict(collections.Counter(c['arm'] for c in cells)),form_union=union,form_count=len(union),per_task=dict(collections.Counter(c['task'] for c in cells)),workers=4,timeout=120,new_reference_calls=0),navigation_sha256=sha(repo/'docs/rvv-validation/all-form-records/navigation.json.gz'),compact_sha256=sha(repo/'docs/rvv-validation/current-scope/compact-input.json'))
    output.mkdir(parents=True,exist_ok=True);(output/'QUEUE.json').write_text(json.dumps(q,indent=2)+'\n');print(json.dumps(q['counts'],indent=2))



def audit(index, raw, output):
    """Join current calls to the existing per-form reader, rechecking original predicates."""
    import csv
    q=read(raw/'QUEUE.json')
    if sha(Path(__file__)) != read(raw/'TOOLS.json')['rvv_ara_replay.py']:
        raise ValueError('observer tool identity changed')
    if sha(raw/'QUEUE.json') != read(raw/'TOOLS.json')['QUEUE.json']:
        raise ValueError('derived queue identity changed')
    for p,h in q['inputs'].items():
        if sha(p)!=h: raise ValueError('original input changed: '+p)
    if sha(raw/'ORIGINAL_DISPOSITIONS.json.gz')!=read(raw/'TOOLS.json')['ORIGINAL_DISPOSITIONS.json.gz']:
        raise ValueError('original exclusion snapshot changed')
    pins=read(raw/'IDENTITY_BEFORE.json')
    if pins != read(raw/'IDENTITY_AFTER.json'):raise ValueError('candidate changed')
    expected_pins={'elfrun':'533443050f4d1ad4dc49ca74f3e5ac4ca1ccc576f2b107d3771412a218ac3e31','libdbtjitshared.so':'1773ca2bf867b0d3bdd76f1b60b168cbeda6d620a71ebd0ae9653d6da6feea6d'}
    if {Path(p).name:h for p,h in pins.items()}!=expected_pins:raise ValueError('wrong candidate')
    if not read(raw/'PRODUCTION_EQUALITY.json')['production_matches']:raise ValueError('production equality absent')
    canonical={b['ledger_row_id']:b for b in index['canonical_bindings']}
    original_read=functools.lru_cache(maxsize=None)(read)
    for c in q['calls']:
        producer=Path(c['producer'])
        if c['kind']=='campaign':
            meta=producer/'CASES.json'
        else:
            meta=producer/('CASES_BUILT.json' if c['task']=='ara-source51' else 'GROUPS.json')
        if meta.exists():
            expected=next(x for x in original_read(meta) if x.get('name',x.get('file'))==c['runner_case'])
            if c['metadata']!=expected: raise ValueError('original assertion metadata changed')
        for path_key,hash_key in (('elf','elf_sha256'),('source','source_sha256'),('adapter','adapter_sha256'),('runner','runner_sha256')):
            if q['inputs'][c[path_key]]!=c[hash_key]: raise ValueError('original artifact binding changed')
        if not all(b==canonical.get(b['ledger_row_id']) and b['elf_sha256']==c['elf_sha256'] for b in c['bindings']):
            raise ValueError('original canonical case/ELF binding mismatch')
    records=[];counts=collections.Counter();forms=collections.defaultdict(list);comparisons={};observations={}
    for c in q['calls']:
        d=raw/'raw'/c['id']
        if not (d/'result.json').exists():
            counts['UNATTEMPTED']+=1
            continue
        result=read(d/'result.json');cmd=read(d/'command.json')
        for f in ('stdout','stderr','observer.json'):
            if sha(d/f)!=result[f.replace('.json','')+'_sha256']:raise ValueError('stream/detail changed: '+str(d/f))
        if read(d/'IDENTITY.json')!=pins or read(d/'IDENTITY_AFTER.json')!=pins:raise ValueError('call identity changed')
        normalized=['--fsroot={WORK}/fs' if x.startswith('--fsroot=') else '--cache={WORK}/cache' if x.startswith('--cache=') else x for x in cmd[1:]]
        if normalized!=c['normalized_flags'] or cmd[0] not in pins or result['elf_sha256']!=c['elf_sha256']:raise ValueError('call command/ELF changed')
        raw_stdout=(d/'stdout').read_bytes();check=dict(c,_rawdir=d)
        ok,detail=observer(check,result['returncode'],raw_stdout)
        # JSON canonicalization allows original parser tuple outputs to match retained lists.
        if json.loads(json.dumps(detail))!=read(d/'observer.json'):raise ValueError('observer detail mismatch')
        status='TIMEOUT' if result['timeout'] else 'CRASH' if result['returncode']<0 else 'SCOPED_PASS' if ok and c['scope']=='TEST_CASE1_2_ONLY' else 'PASS' if ok else 'RESULT_MISMATCH'
        if result['status']!=status or result['accepted_scope_pass']!=ok:raise ValueError('predicate mismatch')
        counts[status]+=1
        comparison=c['adapter_sha256']
        if comparison not in comparisons:
            comparisons[comparison]=dict(case=c['case'],task=c['task'],source=c['source'],source_sha256=c['source_sha256'],adapter=c['adapter'],adapter_sha256=c['adapter_sha256'],metadata=c['metadata'],original_source=Path(c['source']).read_text(),compiled_adapter=Path(c['adapter']).read_text(),scope=c['scope'],original_fp_markers=c.get('original_fp_markers'),original_observer=c['runner'],original_observer_sha256=c['runner_sha256'])
        auxiliary={}
        if c['kind']=='campaign':
            original_tree=ast.parse(Path(c['runner']).read_text())
            env=dict(re=re,json=json,Path=Path,R=Path(c['producer']))
            funcs=[n for n in original_tree.body if isinstance(n,ast.FunctionDef)]
            exec(compile(ast.Module(body=funcs,type_ignores=[]),c['runner'],'exec'),env)
            for name in ('flag_observations','scalar_observations'):
                if name in env: auxiliary[name]=env[name](raw_stdout)
        observations[c['id']]=dict(original_predicate_detail=detail,original_auxiliary_observations=auxiliary)
        row=dict(id=c['id'],case=c['case'],task=c['task'],arm=c['arm'],status=status,returncode=result['returncode'],scope=c['scope'],forms=';'.join(c['forms']),source=c['source'],source_sha256=c['source_sha256'],elf=c['elf'],elf_sha256=c['elf_sha256'],original_raw=c['original_raw'],current_raw=str(d),command=json.dumps(cmd),timeout=c['timeout'],comparison='comparison.json.gz#'+comparison,observation='observations.json.gz#'+c['id'],stdout_sha256=result['stdout_sha256'],stderr_sha256=result['stderr_sha256'])
        records.append(row)
        for f in c['forms']:forms[f].append(row)
    output.mkdir(parents=True,exist_ok=False)
    def gz(name,obj):(output/name).write_bytes(gzip.compress(json.dumps(obj,separators=(',',':')).encode(),mtime=0))
    gz('comparison.json.gz',comparisons);gz('observations.json.gz',observations)
    with (output/'replay-receipts.csv').open('w',newline='') as s:
        w=csv.DictWriter(s,fieldnames=list(records[0]));w.writeheader();w.writerows(records)
    checked={f for f,rs in forms.items() if any(r['status'] in ('PASS','SCOPED_PASS') for r in rs)}
    per_arm={a:sorted({f for c in q['calls'] if c['arm']==a and any(r['id']==c['id'] and r['status'] in ('PASS','SCOPED_PASS') for r in records) for f in c['forms']}) for a in ('B','M1','M2','BOTH')}
    result=dict(total=len(q['calls']),counts=dict(counts),checked_union_count=len(checked),checked_union=sorted(checked),per_arm_checked=per_arm,unattempted=counts['UNATTEMPTED'],original_excluded_bindings=q['excluded_original_bindings'],per_form=[dict(form=f['form'],applicability=f['applicability'],current_Ara= forms.get(f['form'],[]),original_selectors=f['selectors']) for f in index['forms']],candidate_pins=pins,inputs=dict(queue_sha256=sha(raw/'QUEUE.json'),tools=read(raw/'TOOLS.json')),scope='Original typed element equality, scalar/CSR predicates and observed VL where retained. Literal source and geometry are context, not a dynamic Cartesian coverage claim. SCOPED_PASS preserves original MAC whole-file failures; no full-state or target-specific optimized admission inferred.')
    gz('scope.json.gz',result)
    (output/'COUNTS.json').write_text(json.dumps({k:result[k] for k in ('total','counts','checked_union_count','checked_union','unattempted','candidate_pins')},indent=2)+'\n')
    return result


if __name__=='__main__':
    import sys
    prepare(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
