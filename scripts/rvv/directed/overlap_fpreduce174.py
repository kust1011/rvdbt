#!/usr/bin/env python3
"""Disjoint supplemental legal overlap classes; preserve frozen main matrix."""
import json,os,sys,time
from pathlib import Path
import fpreduce174 as f
import fp157 as fp
import vadd as v
import resources164 as resources

def cases():
 configs={}
 for c in f.cases():configs.setdefault((c['mnemonic'],c['vlen'],c['sew'],c['lmul']),c)
 rows=[]
 for base in configs.values():
  n=base['vlmax'];regs=base['group_registers'];k=fp.constants(base['sew']);dk=fp.constants(base['dst_eew'])
  forms=[('data-v0-unmasked',dict(vs2=0,vs1=24,vd=8,values=[0],seed_word=0,mask='none')),('seed-v0-unmasked',dict(vs2=16,vs1=0,vd=8,values=[0],seed_word=0,mask='none')),('seed-destination-v0-unmasked',dict(vs2=16,vs1=0,vd=0,values=[0],seed_word=0,mask='none')),('high-source-destination-last',dict(vs2=32-regs,vs1=8,vd=31,values=[k['one'],k['negone'],k['two']],seed_word=dk['one'],mask='alternating'))]
  if not f.wide(base):forms.append(('all-three-same',dict(vs2=16,vs1=16,vd=16,values=[k['one'],k['negone']],seed_word=dk['one'],mask='alternating')))
  for tag,kw in forms:
   c=dict(base,vl=min(3,n),ta=True,ma=True,fflags_initial=8,tag='extra-'+tag,**kw);c['unit']=base['unit'].removesuffix('zero')+'extra';c['id']=c['unit']+'-'+tag;f.validate(c);f.allowed(c,f.initial(c));rows.append(c)
 return rows

def main(base):
 d=base/'overlap-supplement';d.mkdir();rows=cases();v.save(d/'DECLARATION.json',dict(cases=len(rows),units=len({c['unit'] for c in rows}),forms=list(f.FORMS),scope='disjoint additional v0 source/seed and combined aliases, high-end source groups; no original case changed',source_sha256=v.sha(Path(__file__))))
 v.manifest_cases=lambda family:cases()
 v.build(d/'corpus','clang-22',Path('/home/vick/rvv-directed-task145/link.ld'),'fpreduce174',4)
 while resources.snapshot()['guests']>8:time.sleep(2)
 v.run(d/'corpus',Path('/home/vick/rvdbt-host512-task174-build/build/bin/elfrun'),Path('/home/vick/rvv-directed-task145/deps/spike'),Path('/home/vick/rvv-directed-task145/deps/pk'),Path('/home/vick/rvv-act4-tools/bin/sail_riscv_sim'),base/'FLAGS.json',8)
 summary=json.loads((d/'corpus/summary.json').read_text());assert summary['counts']=={'PASS':len(rows)*5},summary
 import subprocess
 subprocess.run(['python3','/home/vick/rvv-task168/offline_admission168.py','1',str(d/'OFFLINE_ADMISSION.json')],check=True)
 import audit
 audit.v.manifest_cases=lambda family:cases()
 audit.audit(d/'corpus',d/'audit')
 (d/'COMPLETE').write_text('PASS\n')
if __name__=='__main__':main(Path(sys.argv[1]))
