# SPDX-License-Identifier: MIT
"""Package retained Task138 outputs and missing reader inputs; never run guests."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
from rvv_host512_corpus import read, sha, require


def package(raw, docs, ara, act_metadata, act, task104, output):
    output.mkdir(parents=True, exist_ok=False)
    paths = {}; legal = []; provenance = {}
    def add(p, name, prefix=b''):
        require(p.is_file() and not p.is_symlink(), 'missing/nonregular input: '+str(p))
        target = output/name; target.parent.mkdir(parents=True, exist_ok=True)
        original = p.read_bytes(); target.write_bytes(prefix+original)
        paths[str(p)] = name
        provenance[name] = dict(original_path=str(p), original_sha256=sha(p))
        if prefix:
            legal.append(dict(file=name, original_sha256=sha(p), notice_prefix_bytes=len(prefix),
                              distributed_sha256=sha(target), source_notice='licenses/Ara-SHL-0.51.txt'))
    receipts = read(docs/'host512-task138/RECEIPTS.json.gz')
    # Only authenticated direct receipt files; no work directories, ELFs or caches.
    for r in receipts:
        rel = Path(r['receipt']).relative_to('/home/vick/rvdbt-host512-task138')
        for name, digest in r['files'].items():
            require(Path(name).name == name, 'non-direct receipt file')
            p=raw/rel/name; require(sha(p)==digest, 'receipt input changed')
            add(p, 'raw/'+str(rel/name))
    for name in ('IDENTITY_BEFORE.json','IDENTITY_AFTER.json','PILOT_CALLS.json','PARTITION.json',
                 'CONFIGURATION_DURING.json','CONFIGURATION_AFTER.json','CMakeCache.txt','compile_commands.json',
                 'TOOLS.json','INPUT_AUDIT.json','INPUT_AFTER_AUDIT.json','AUDIT.json','SOURCE_EQUALITY.json'):
        add(raw/name, 'raw/'+name)
    for suite in ('chips','act','ara'): add(raw/suite/'QUEUE.json','raw/'+suite+'/QUEUE.json')
    for name in ('comparison-sites.json.gz','comparison.json.gz'):
        add(act_metadata/name,'metadata/act/'+name)
        paths['/home/vick/act-current121/'+name]='metadata/act/'+name
    for p in sorted(task104.rglob('*')):
        if p.is_file():
            name='metadata/task104/'+str(p.relative_to(task104)); add(p,name)
            paths['/home/vick/rvv-task104/'+str(p.relative_to(task104))]=name
            provenance[name]['historical_path']='/home/vick/rvv-task104/'+str(p.relative_to(task104))
    # Reuse the published Ara package wherever it already contains a hash,
    # including legally restored copies of historical adapter bytes.
    published_paths=read(ara/'PATHS.json')
    manifest=read(ara/'FILES.json'); present={v['sha256'] for v in manifest.values()}
    present.update(x['original_sha256'] for x in read(ara/'LEGAL_RESTORATIONS.json'))
    cells=[r['original_call'] for r in receipts if r['suite']=='ara']
    for c in cells:
        for key in ('source','adapter','runner'):
            p=Path(c[key]); digest=c[key+'_sha256']
            if digest in present or str(p) in paths: continue
            require(sha(p)==digest,'Ara original identity changed')
            prefix=b''
            if key in ('source','adapter') and b'Copyright' not in p.read_bytes()[:2000]:
                src=Path(c['source']); lines=src.read_bytes().splitlines(keepends=True); header=[]
                for line in lines:
                    if line.startswith(b'//') or not line.strip(): header.append(line)
                    else: break
                prefix=b''.join(header)
                if b'Copyright' not in prefix:
                    # Extracted Ara blocks retain original upstream notice here.
                    prefix=(b'// Copyright ETH Zurich and University of Bologna.\n'
                            b'// Solderpad Hardware License, Version 0.51; see licenses/Ara-SHL-0.51.txt.\n')
                prefix+=b'// Task139 distribution: notice restored; historical payload below unchanged.\n'
            add(p,'sources/ara/'+digest+'/'+p.name,prefix)
    # Original observer imports and literal data dependencies, no runner main.
    for c in cells:
        base=Path(c['producer'])
        for name in ('runner.py','checker.py','initializer_check.py','exact_check.py',
                     'run.py','run.original.py.txt','COMPILED_FLAG_MAP.json','COMPILED_SCALAR_MAP.json','PREREGISTERED.json',
                     *(['CASES.json'] if c['batch']=='ara_vset_current_20261009' else [])):
            p=base/name
            if p.is_file() and str(p) not in paths and str(p) not in published_paths:
                if name in ('COMPILED_FLAG_MAP.json','CASES.json'):
                    relative=str(base).split('rvv_validation_delivery_20261009/')[1]+'/'+name
                    key='/home/vick/rvdbt-host512-task138/ara/observers/'+relative
                    require(sha(p)==read(raw/'INPUT_AUDIT.json')[key], 'original observer metadata pin')
                add(p,'observers/'+hashlib.sha256(str(base).encode()).hexdigest()+'/'+name)
    for p in (act/'licenses').iterdir():
        if p.is_file(): add(p,'licenses/ACT-'+p.name)
    for p in (ara/'licenses').iterdir():
        if p.is_file(): add(p,'licenses/'+p.name)
    add(Path(__file__).resolve().parents[1]/'LICENSE','licenses/rvdbt-MIT.txt')
    (output/'NOTICE.md').write_text('Task138 retained outputs and Task139 reader metadata: repository MIT. Original Ara source/derivatives: ETH Zurich / University of Bologna, revision 34bd3bc152421b4601a7bf3d6e8e91ffb545c99e, SHL-0.51; original notices retained or restored in LEGAL_RESTORATIONS.json. Observer scripts retain their own SPDX/license markers. ACT metadata contains recorded source/checker sites, frozen words and the original Task104 source/capture/processed-signature/checker/command/log chain, whose upstream code/data terms are retained in the separately required licensed ACT packages (BSD-3-Clause / Apache-2.0 / CC-BY-4.0); those licenses must accompany redistribution. No whole-package relicensing. No unlicensed generator vectors, private inputs, guest ELF, executable, library or work/cache are included. Historical absolute paths in receipts are provenance, not retrieval instructions.\n')
    for name,value in [('PATHS.json',paths),('LEGAL_RESTORATIONS.json',legal),('PROVENANCE.json',provenance)]:
        (output/name).write_text(json.dumps(value,indent=2)+'\n')
    files={str(p.relative_to(output)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(output.rglob('*')) if p.is_file()}
    (output/'FILES.json').write_text(json.dumps(files,indent=2)+'\n')
    archive=output.with_suffix('.tar.gz')
    with tarfile.open(archive,'w:gz') as t:
        for p in sorted(output.rglob('*')):
            if p.is_file(): t.add(p,arcname=str(p.relative_to(output)),recursive=False)
    return dict(file=archive.name,bytes=archive.stat().st_size,sha256=sha(archive),payload_files=len(files)+1,
                manifest_sha256=sha(output/'FILES.json'),current_calls=len(receipts),new_guest_calls=0,
                publication='STAGED_LOCAL; main owns upload after review')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('raw','docs','ara','act-metadata','act','task104','output'): p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args(); print(json.dumps(package(a.raw,a.docs,a.ara,a.act_metadata,a.act,a.task104,a.output),indent=2))
if __name__=='__main__': main()
