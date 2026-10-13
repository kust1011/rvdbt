#!/usr/bin/env python3
"""Review retained old QEMU source and extract INPUTS only, never expected arrays."""
import hashlib,json,re,sys
from pathlib import Path

def extract(root,output):
 import fpcompare170 as f
 wrappers=Path('docs/rvv-validation/directed-task157/qemu-source/rvv_ch14.inc').read_text()
 result={};review=[];excerpts=[]
 for op,forms in f.FORMS.items():
  for form in forms:
   name=op+'_'+form;p=root/(name+'.c');text=p.read_text();vectors={}
   for bits in (32,64):
    values={}
    for source,key in [('src0','fp_a'),('src1','fp_b')]:
     m=re.search(r'struct rvv_reg '+source+r'\[\] = \{(.*?)\n\};',text,re.S)
     if m:
      field=re.search(r'\.float'+str(bits)+r' = \{(.*?)(?=\n        \},)',m[1],re.S)
      if field:values[key]=[int(x,16) for x in re.findall(r'0x[0-9a-fA-F]+',field[1])]
    assert values.get('fp_a'),name
    if form!='v':assert values.get('fp_b'),name
    vectors[str(bits)]=values
   blocks=re.findall(r'TEST_FUNC\(test_'+re.escape(name)+r'_(?:16|32|64)(?:_vm)?\).*?(?=\nTEST_FUNC|\Z)',wrappers,re.S)
   assert len(blocks)==6,(name,len(blocks))
   for block in blocks:
    assert op+'.'+form in block,(name,block)
    excerpts.append(block)
   review.append(dict(form=op+'.'+form,case_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),wrappers=6,applicable_wrappers=4,unsupported_half_wrappers=2,inputs=vectors,adaptations=['current V1.0 encoding','packed EEW1 compare destination rather than legacy SEW-spaced masks','explicit tail/mask policies; discard old zero-tail golden','FLEN64 NaN boxing via fld','ratified F2.2 minimumNumber sNaN rule','no original expected arrays used']))
   result[name]=vectors
 output.write_text(json.dumps(result,indent=2)+'\n');(root/'CASE_WRAPPER_REVIEW.json').write_text(json.dumps(review,indent=2)+'\n');(root/'WRAPPER_EXCERPTS.txt').write_text('\n'.join(excerpts))
if __name__=='__main__':extract(Path(sys.argv[1]),Path(sys.argv[2]))
