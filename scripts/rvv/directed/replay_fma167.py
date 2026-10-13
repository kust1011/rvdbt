#!/usr/bin/env python3
"""Replay frozen Task164 guests with its unchanged ISA/reference predicates.

The original corpus is read-only. Every DUT execution has a fresh fs/cache and
result directory. References and guest ELFs are reused only after hash checks.
"""
import argparse, collections, concurrent.futures, hashlib, json, os, shutil
from pathlib import Path
import vadd as v
import storage149 as storage

def replay(original, output, engine, build_manifest, flags_file, jobs, units=None):
    assert not output.exists(), 'new namespace required'
    assert 1 <= jobs <= 8
    pins=json.loads(build_manifest.read_text())['artifacts']
    library=engine.parent.parent/'lib/libdbtjitshared.so'
    assert v.sha(engine)==pins[str(engine)] and v.sha(library)==pins[str(library)]
    manifest_path=original/'manifest.json'
    manifest=json.loads(manifest_path.read_text())
    groups=collections.defaultdict(list)
    for c in manifest['cases']:
        if units is None or c['unit'] in units: groups[c['unit']].append(c)
    assert groups and (units is None or set(groups)==set(units))
    builds=json.loads((original/'build-commands.json').read_text())
    elf_pins={Path(row['command'][-1]).parent.name:row['elf_sha256'] for row in builds if Path(row['command'][-1]).name=='test.elf'}
    flags=json.loads(flags_file.read_text())
    output.mkdir(parents=True)
    v.save(output/'lineage.json',dict(original=str(original),manifest_sha256=v.sha(manifest_path),build_manifest_sha256=v.sha(build_manifest),checker_sha256=v.sha(Path(v.__file__)),flags_sha256=v.sha(flags_file),units=list(groups),jobs=jobs))
    v.save(output/'identities-before.json',pins)
    def worker(item):
        unit, cases=item
        storage.reserve(output)
        elf=storage.verify(original/unit/'test.elf')
        assert hashlib.sha256(elf).hexdigest()==elf_pins[unit]
        ref=storage.verify(original/'runs'/unit/'Reference'/'packets.bin')
        ref_checks=json.loads((original/'runs'/unit/'Reference'/'checks.json').read_text())
        assert len(ref_checks)==len(cases) and all(r['status']=='PASS' for r in ref_checks)
        ref_exec=json.loads((original/'runs'/unit/'Reference'/'execution.json').read_text())
        assert ref_exec['returncode']==0 and not ref_exec['timeout']
        size=v.packet_size(cases[0]);assert len(ref)==size*len(cases)
        for i,c in enumerate(cases):v.check_isa(c,ref[i*size:(i+1)*size],0,False)
        v.save(output/(unit+'-reuse.json'),dict(elf_sha256=hashlib.sha256(elf).hexdigest(),reference_sha256=hashlib.sha256(ref).hexdigest(),original_checks_sha256=v.sha(original/'runs'/unit/'Reference'/'checks.json')))
        rows=[]
        for arm, fsflags in flags.items():
            d=output/'runs'/unit/arm;fs=output/'work'/unit/arm/'fs';fs.mkdir(parents=True);cache=fs.parent/'cache';cache.mkdir()
            (fs/'t.elf').write_bytes(elf)
            env=dict(os.environ,LD_LIBRARY_PATH=str(library.parent)+':/home/vick/boost_vendor/lib')
            cmd=[engine,*[f'--vlen={cases[0]["vlen"]}' if f.startswith('--vlen=') else f for f in fsflags],f'--dump-tbmap={d}/tbmap',f'--fsroot={fs}',f'--cache={cache}','--','/t.elf']
            rec=v.execute(cmd,d,env);raw=storage.verify(d/'stdout');storage.write(d/'packets.bin',raw,alias=d/'stdout')
            checks=[]
            for i,c in enumerate(cases):
                error=None
                try:
                    assert len(raw)==size*len(cases), 'packet extent'
                    packet=raw[i*size:(i+1)*size]
                    v.check_isa(c,packet,rec['returncode'],rec['timeout'])
                    v.check_reference(c,packet,ref[i*size:(i+1)*size])
                except (ValueError,AssertionError) as ex:error=str(ex)
                checks.append(dict(case=c['id'],arm=arm,status='FAIL' if error else 'PASS',error=error,raw=str(d/'packets.bin'),offset=i*size,size=size))
            v.save(d/'checks.json',checks);rows.extend(checks)
            storage.compress(d/'tbmap')
            (fs/'t.elf').unlink();storage.retain_tree(cache)
        return rows
    rows=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for result in pool.map(worker,groups.items()):
            rows.extend(result);print(result[0]['case'],collections.Counter(r['status'] for r in result),flush=True)
    assert v.sha(engine)==pins[str(engine)] and v.sha(library)==pins[str(library)]
    v.save(output/'identities-after.json',pins);v.save(output/'results.json',rows)
    summary=dict(cases=sum(map(len,groups.values())),units=len(groups),checks=len(rows),arms={arm:dict(collections.Counter(r['status'] for r in rows if r['arm']==arm)) for arm in flags})
    v.save(output/'summary.json',summary)
    if any(r['status']!='PASS' for r in rows):raise SystemExit(1)
    (output/'COMPLETE').write_text('PASS\n')

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('original','output','engine','build-manifest','flags'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--jobs',type=int,default=8);p.add_argument('--units',type=Path)
    a=p.parse_args();replay(a.original,a.output,a.engine,a.build_manifest,a.flags,a.jobs,json.loads(a.units.read_text()) if a.units else None)
