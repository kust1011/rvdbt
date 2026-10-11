#!/usr/bin/env python3
"""Fetch pinned licensed dependencies into a new directory; verify retained inputs."""
import argparse,json,subprocess,urllib.request
from pathlib import Path
from rvv_tests import digest,save
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
scripts=Path(__file__).resolve().parent;lock=json.loads((scripts/'rvv/sources.lock.json').read_text())['sources'];ar=lock['ara'];out=a.output/'ara';out.mkdir()
for name,relative in {**ar['paths'],'LICENSE':'LICENSE'}.items():
    data=urllib.request.urlopen('https://raw.githubusercontent.com/pulp-platform/ara/'+ar['revision']+'/'+relative,timeout=60).read();(out/name).write_bytes(data)
    bundled=scripts/'rvv/fixtures/ara-vredsum'/('vredsum.original.c' if name=='vredsum.c' else name)
    if name!='vector_macros.h' and digest(out/name)!=digest(bundled):raise ValueError('pinned Ara input differs: '+name)
rv=lock['rvvts'];subprocess.run(['git','clone',rv['url'],str(a.output/'rvvts')],check=True);subprocess.run(['git','-C',str(a.output/'rvvts'),'checkout','--detach',rv['revision']],check=True)
save(a.output/'fetch.json',dict(ara=ar,rvvts=rv,files={str(x.relative_to(a.output)):digest(x) for x in out.iterdir()}))
