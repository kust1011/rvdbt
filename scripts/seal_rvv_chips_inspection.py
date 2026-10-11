#!/usr/bin/env python3
"""Seal already prepared CHIPS inspection files into documented batch archives."""
import argparse
import collections
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import json
from pathlib import Path
import re
import tarfile
from package_rvv_chips_inspection import digest,save


def archive(root,paths,dest):
    # Deterministic package-relative regular files; no author-path symlinks.
    with gzip.GzipFile(filename=str(dest),mode='wb',compresslevel=6,mtime=0) as gz,tarfile.open(fileobj=gz,mode='w|',dereference=True) as tf:
        for p in sorted(paths):
            t=tf.gettarinfo(str(p),arcname=str(p.relative_to(root)))
            t.uid=t.gid=0;t.uname=t.gname='';t.mtime=0
            with p.open('rb') as f:tf.addfile(t,f)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('root',type=Path);ap.add_argument('output',type=Path);ap.add_argument('--prepare-only',action='store_true');a=ap.parse_args();root=a.root;out=a.output;out.mkdir(parents=True,exist_ok=True)
    banned={'.elf','.o','.a','.so','.bin','.pyc'};files=[p for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='FILES.json']
    assert not any(p.is_symlink() or p.suffix in banned for p in files),'binary/symlink distribution'
    pattern=re.compile(rb'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|\b(?:ghp_|github_pat_)[A-Za-z0-9_]{25,}|\bAKIA[0-9A-Z]{16}\b')
    matches=[]
    for p in files:
        with p.open('rb') as f:
            tail=b''
            for block in iter(lambda:f.read(1024*1024),b''):
                scan=tail+block
                if any(marker in scan for marker in (b'PRIVATE KEY-----',b'ghp_',b'github_pat_',b'AKIA')) and pattern.search(scan):
                    matches.append(str(p.relative_to(root)));break
                tail=scan[-256:]
    assert not matches,'credential patterns found (values suppressed): '+str(matches)
    licenses=[p for p in files if p.name in {'LICENSE','NOTICE','COPYING','LOCAL-MIT.txt','GEM5_ASMTEST_BSD.txt','TESTFLOAT_NOTICE.md'}]
    save(root/'LICENSE_AUDIT.json',{'license_files':{str(p.relative_to(root)):digest(p) for p in licenses},'source_headers':'Original source bytes and upstream notices retained; generated CHIPS source/adaptations under CHIPS Apache2, env helpers under their original BSD, local tools under repository MIT. No blanket relicensing.','excluded':'TestFloat3, toolchain/Spike dependencies fetched separately; no RVISmith/ATG/FORCE or unrelated third-party fixtures','credential_pattern_scan':'no matches; values not emitted','upstream_revision':'f76bff121dce91b6b23e1d37be77a5e44af914c3','env_revision':'81721c126d7dd7335829948b4a19070546e465d6'})
    files=[p for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='FILES.json']
    save(root/'FILES.json',{str(p.relative_to(root)):{'sha256':digest(p),'bytes':p.stat().st_size} for p in sorted(files)})
    if a.prepare_only:
        print(json.dumps({'sealed_files':len(files),'raw_bytes':sum(p.stat().st_size for p in files)}));return
    files.append(root/'FILES.json');groups=collections.defaultdict(list)
    batches=set(json.loads((root/'records/historical/MANIFEST.json').read_text())['source_batches'])- {'.'}
    for p in files:
        rel=p.relative_to(root).parts
        group=rel[2] if len(rel)>3 and rel[:2]==('sources','chips') and rel[2] in batches else 'core'
        groups[group].append(p)
    archives=[];preflight=[];cap=90*1024*1024
    def compress_group(item):
        group,paths=item
        local_archives=[];local_preflight=[]
        dest=out/('chips-'+group+'.tar.gz');archive(root,paths,dest)
        local_preflight.append({'group':group,'raw_bytes':sum(p.stat().st_size for p in paths),'compressed_bytes':dest.stat().st_size})
        if dest.stat().st_size<=cap:final=[(dest,paths)]
        else:
            pre=out/'size-preflight';pre.mkdir(exist_ok=True);dest.rename(pre/dest.name)
            pieces=collections.defaultdict(list)
            assert group!='core','core archive exceeds cap; separate records by candidate before sealing'
            for p in paths:
                rel=p.relative_to(root/'sources/chips'/group).parts
                family=rel[1].split('-',1)[0] if len(rel)>1 else 'metadata'
                pieces[family].append(p)
            final=[]
            for family,part in sorted(pieces.items()):
                d=out/('chips-'+group+'--'+family+'.tar.gz');archive(root,part,d)
                assert d.stat().st_size<=cap,'named form family exceeds cap '+str(d)
                final.append((d,part))
        for d,part in final:local_archives.append({'file':d.name,'bytes':d.stat().st_size,'sha256':digest(d),'members':len(part),'raw_bytes':sum(p.stat().st_size for p in part),'batch':group})
        print('sealed '+group,flush=True)
        return local_archives,local_preflight
    with ThreadPoolExecutor(max_workers=4) as pool:
        for result,measurements in pool.map(compress_group,sorted(groups.items())):
            archives.extend(result);preflight.extend(measurements)
    save(out/'ARCHIVES.json',{'archives':archives,'compressed_bytes':sum(x['bytes'] for x in archives),'raw_bytes':sum(p.stat().st_size for p in files),'payload_files':len(files),'preflight':preflight,'split_rule':'Named retained batch, then original form family when batch exceeds90MiB; all phases and raw histories for that family stay together. Core carries index, bindings, clean/historical receipts, licenses and tools.'})
    print(json.dumps({'archives':len(archives),'compressed_bytes':sum(x['bytes'] for x in archives),'largest':max(x['bytes'] for x in archives),'raw_bytes':sum(p.stat().st_size for p in files)},indent=2))

if __name__=='__main__':main()
