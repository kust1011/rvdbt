#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Repair only NEW completed Task149 retained ELF aliases, never guest execution."""
import argparse,hashlib,json,os
from pathlib import Path
import storage149 as storage

def repair(base):
    root=base/'corpus';rows=json.loads((root/'build-commands.json').read_text());records=[]
    assert json.loads((root/'summary.json').read_text())['counts'].keys()=={'PASS'}
    for row in rows:
      original=Path(row['command'][-1])
      if original.name!='test.elf':continue
      elf=root/original.parent.name/'test.elf';payload=storage.verify(elf)
      if storage.digest(payload)!=row['elf_sha256']:raise ValueError('compiled guest identity mismatch')
      gz=Path(str(elf)+'.gz')
      for arm in ['B','M1','M2','BOTH']:
        alias=root/'work'/original.parent.name/arm/'fs/t.elf.gz'
        if not alias.is_symlink():raise ValueError('expected retained ELF alias')
        before=os.readlink(alias);dangling=not alias.exists();target=os.path.relpath(gz,alias.parent)
        tmp=alias.with_name(alias.name+'.repair149.tmp');os.symlink(target,tmp);os.replace(tmp,alias)
        if alias.resolve()!=gz.resolve():raise ValueError('alias target mismatch')
        records.append(dict(alias=str(alias.relative_to(base)),before=before,was_dangling=dangling,after=target,logical_elf_sha256=row['elf_sha256']))
    # Verify one original arm command path can materialize/recover exact bytes.
    first=base/records[0]['alias'];logical=Path(str(first).removesuffix('.gz'))
    expected=records[0]['logical_elf_sha256'];created=storage.materialize(logical)
    if not created or storage.digest(logical.read_bytes())!=expected:raise ValueError('arm ELF recovery failed')
    logical.unlink() # NEW recovery-check temporary only; permanent gzip unchanged
    report=dict(command=['python3',str(Path(__file__).resolve()),str(base.resolve())],utility_sha256=storage.digest(Path(__file__).read_bytes()),aliases=len(records),repaired_dangling=sum(r['was_dangling'] for r in records),arm_command_path_recovery_verified=True,guest_executions=0,records=records)
    storage.write(base/'ELF_ALIAS_REPAIR.json',json.dumps(report,separators=(',',':')).encode())
    return {k:v for k,v in report.items() if k!='records'}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('bases',type=Path,nargs='+');a=p.parse_args()
    for base in a.bases:
      if base.parent!=Path('/home/vick/rvv-directed-task149'):raise ValueError('Task149-only retained artifacts')
      print(json.dumps(repair(base)),flush=True)
