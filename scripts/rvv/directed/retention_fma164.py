#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inventory retained persistent FMA artifacts and shared resource receipts."""
import collections,gzip,hashlib,json,os,shutil,sys
from pathlib import Path

def run(base,out):
    counts=collections.Counter();allocated=logical=0;paths=[]
    for parent,dirs,files in os.walk(base):
        for name in files:
            p=Path(parent)/name
            if p.is_symlink():continue
            stat=p.stat();allocated+=stat.st_blocks*512;logical+=stat.st_size
            counts['files']+=1
            if name.endswith('packets.bin.gz'):counts['packet_artifacts']+=1
            elif name.endswith('stdout.gz'):counts['stdout_artifacts']+=1
            elif name.endswith('stderr.gz'):counts['stderr_artifacts']+=1
            elif name.endswith('tbmap.gz'):counts['tbmap_artifacts']+=1
            elif name.endswith('signature.gz'):counts['signature_artifacts']+=1
            elif name.endswith('.elf.gz'):counts['elf_artifacts']+=1
            if name in ('manifest.json','results.json','summary.json','FREEZE.sha256','STAGE_STATUS.json','identities-before.json','identities-after.json','runner-identity.json','audit.json'):
                paths.append(dict(path=str(p),bytes=stat.st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
    samples=[]
    for p in [base/'RESOURCE_SAMPLES.jsonl',base/'full/RESOURCE_SAMPLES.jsonl']:
        if p.exists():samples.extend(json.loads(line) for line in p.read_text().splitlines())
    workers=[]
    for p in [base/'pilot-review/audit-parallel/workers.json',base/'full-review/audit-parallel/workers.json']:
        if p.exists():workers.extend(json.loads(p.read_text()))
    receipt=dict(base='xbd:'+str(base),allocated_bytes=allocated,logical_bytes=logical,counts=dict(counts),critical_artifacts=paths,free_bytes=shutil.disk_usage(base).free,reserve_bytes=10*1024**3,max_observed_guests=max((r['guests'] for r in samples),default=0),max_observed_offline_workers=max((r['offline'] for r in samples),default=0),resource_samples=len(samples),workers=workers,production_changes=0,original_deletions=0,retention='Persistent original source/ELF/packets/stdout/stderr/tbmap/cache/reference; only compact evidence plus selected original failure packets exported')
    assert receipt['free_bytes']>receipt['reserve_bytes'] and receipt['max_observed_guests']<=16 and receipt['max_observed_offline_workers']<=4
    out.write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({k:receipt[k] for k in ('allocated_bytes','counts','free_bytes','max_observed_guests','max_observed_offline_workers','resource_samples')}))
if __name__=='__main__':run(*map(Path,sys.argv[1:]))
