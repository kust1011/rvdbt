#!/usr/bin/env python3
"""Complete only the destination supplement after preserving selector failure."""
import gzip,json,subprocess,time
from pathlib import Path
R=Path('/home/vick/rvv-directed-task161')
for name in ('destchunk-full','destchunk-pilot'):
 base=Path('/home/vick/rvv-directed-task156')/name;out=R/name
 with (out/'effectiveness.log').open('wb') as f:subprocess.run(['python3',str(R/'verify_controls161.py'),str(base),str(out)],stdout=f,stderr=subprocess.STDOUT,check=True)
 for src in ('adapter-verification.json','guest-pins.json'):
  with gzip.open(out/'evidence'/(src+'.gz'),'wb') as f:f.write((out/'audit'/src).read_bytes())
(R/'SUPPLEMENT_RESULT.json').write_text(json.dumps(dict(original_error_preserved=str(R/'SUPPLEMENT_ERROR.txt'),cause='Deduplicated destination geometry can lack a zero-start case; initial supplemental selection assertion rejected that assumption.',correction='Select unmasked vstart<vl and mutate the actual vstart lane using unchanged frozen predicates.',corrected_controls=str(R/'destchunk-full/controls-geometry2'),guest_reruns=0,production_or_frozen_predicate_changes=0,final_status='PASS'),indent=2)+'\n')
(R/'SUPPLEMENT_COMPLETE').write_text(time.ctime()+'\n')
