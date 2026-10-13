#!/usr/bin/env python3
"""Inventory logical retained artifacts, including compressed media, without deletion."""
import collections,hashlib,json
from pathlib import Path
R=Path('/home/vick/rvv-directed-task161');rows={}
for name,base in [('widen-full','/home/vick/rvv-directed-task154/widen-full'),('wmac-full2','/home/vick/rvv-directed-task156/wmac-full2'),('extend-full','/home/vick/rvv-directed-task156/extend-full'),('destchunk-full','/home/vick/rvv-directed-task156/destchunk-full'),('extend-pilot','/home/vick/rvv-directed-task156/extend-pilot'),('destchunk-pilot','/home/vick/rvv-directed-task156/destchunk-pilot')]:
 base=Path(base);root=base/'corpus';out=R/name;assert (out/'COMPLETE').exists();m=json.loads((root/'manifest.json').read_text());a=json.loads((out/'audit/audit.json').read_text());types=collections.Counter();bytes_allocated=0
 for p in root.rglob('*'):
  if not p.is_file():continue
  logical=p.name.removesuffix('.gz');bytes_allocated+=p.stat().st_blocks*512
  if logical in ('stdout','stderr','packets.bin','tbmap'):types[logical]+=1
  elif logical.endswith('.elf'):
   types['ELF-paths-including-work-copies']+=1
   if 'work' not in p.relative_to(root).parts:types['compiled-ELF']+=1
  elif logical.endswith('.S'):types['assembly-source']+=1
  elif logical.endswith('.signature'):types['signature']+=1
  elif '.prof' in logical:types['profiling-cache-or-metadata']+=1
  elif logical.endswith('.storage.json'):types['storage-metadata']+=1
  else:types['other-retained']+=1
 commands=a['executed_commands'];assert types['stdout']==types['stderr']==types['packets.bin']==commands
 assert types['compiled-ELF']==m['units']+a['adapter_verified_units'],(name,types)
 hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [root/'manifest.json',root/'results.json',root/'build-commands.json',base/'FREEZE.sha256',base/'launch.sh']}
 rows[name]=dict(raw='xbd:'+str(base),audit='xbd:'+str(out),logical_artifacts=dict(types),allocated_bytes=bytes_allocated,critical_hashes=hashes,deleted_paths=[],cleanup_performed=False,all_ordinary_and_reserved_inputs_preserved=True)
(R/'RETENTION_DETAIL.json').write_text(json.dumps(rows,indent=2)+'\n')
