#!/usr/bin/env python3
"""Disjoint extra masks/high-end sources. No original-matrix packet replay."""
import collections,json,sys
from pathlib import Path
import gaps175 as f
import vadd as v
original=f.cases

def cases(family):
 rows=[]
 for family in f.FORMS:
  for base in original(family):
   if base['tag']!='length0':continue
   def add(tag,**kw):
    c=dict(base,vl=base['vlmax'],mask='odd',ta=True,ma=True,fflags_initial=31);c.update(kw);c['tag']='supp-'+tag;c['unit']='supp-'+base['unit'].removesuffix('-zero')+('-start' if c['vstart'] else '-zero');c['id']=c['unit']+'-'+tag;f.validate(c);rows.append(c)
   add('odd')
   high=32-base['src_registers'];shiftreg=16 if base['family']=='narrow175' and base['form']=='wv' else base['vs1'];add('high-source',vs2=high,vs1=shiftreg)
   if base['mnemonic']!='vfslide1up':add('high-alias',vs2=high,vd=high,vs1=shiftreg)
   if base['family']!='narrow175':
    lane=base['vlmax']-1 if base['mnemonic']=='vfslide1down' else 0
    add('scalar-on',mask='custom',mask_bits=1<<lane,fp_b=0x7f800001 if base['sew']==32 else 0x7ff0000000000001)
    add('scalar-off',mask='custom',mask_bits=((1<<base['vlmax'])-1)^(1<<lane),bad_box=True)
    add('scalar-start-at',vstart=lane,mask='all')
    add('scalar-start-after',vstart=lane+1,mask='all')
 return json.loads(json.dumps(rows))

def install():f.cases=cases
if __name__=='__main__':
 install();args=sys.argv[1:]
 if args[0]=='declare':
  rows=cases('fpslide175');out=Path(args[1]);out.mkdir();v.save(out/'DECLARATION.json',dict(cases=len(rows),units=len({c['unit'] for c in rows}),per_form=dict(collections.Counter(c['mnemonic']+'.'+c['form'] for c in rows)),disjoint_ids=True,scope='odd complement, high sources/aliases, scalar lanes/masks/prestart'))
 elif args[0]=='audit':
  import audit
  audit.v.manifest_cases=lambda family:cases(family)
  audit.audit(Path(args[1]),Path(args[2]))
 else:sys.argv=[sys.argv[0]]+args;v.main()
