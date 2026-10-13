#!/usr/bin/env python3
"""Extract original QEMU0.7.1 source operands only and review actual wrappers."""
import hashlib,json,re,sys
from pathlib import Path
import fpconvert172 as f

def extract(root,output):
 wrappers=Path('docs/rvv-validation/directed-task157/qemu-source/rvv_ch14.inc');text=wrappers.read_text();result={};review=[];excerpts=[]
 for path in sorted(root.glob('v*cvt*.c')):
  old=path.stem;form=old.replace('_','.')
  if form.startswith('vfn'):form=form.removesuffix('.v')+'.w'
  assert form in f.FORMS
  source=path.read_text();m=re.search(r'struct rvv_reg src0\[\] = \{(.*?)\n\};',source,re.S);assert m
  values={};applicable=[]
  for sew in (16,32,64):
   if not f.supported(form,sew):continue
   sw,dw=f.widths(form,sew);field=('wfloat' if form.startswith('vfn') else 'float')+str(sw)
   block=re.search(r'\.'+field+r' = \{(.*?)(?=\n        \},)',m[1],re.S);assert block,(form,sew,field)
   words=[int(x,16) for x in re.findall(r'0x[0-9a-fA-F]+',block[1])];assert words and max(words)<1<<sw
   values[str(sw)]=words;applicable.append(sew)
  blocks=re.findall(r'TEST_FUNC\(test_'+re.escape(old)+r'_(\d+)(?:_vm)?\).*?(?=\nTEST_FUNC|\Z)',text,re.S)
  full=re.findall(r'TEST_FUNC\(test_'+re.escape(old)+r'_\d+(?:_vm)?\).*?(?=\nTEST_FUNC|\Z)',text,re.S)
  assert blocks and len(blocks)==len(full),(form,len(blocks))
  for block in full:
   assert form.removesuffix('.w')+'.v' in block if form.startswith('vfn') else form in block
   excerpts.append(block)
  result[form]=values
  review.append(dict(form=form,original_name=old,case_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),original_wrapper_count=len(blocks),wrapper_sews=[int(x) for x in blocks],applicable_wrappers=sum(int(x) in applicable for x in blocks),unsupported_wrappers=sum(int(x) not in applicable for x in blocks),inputs=values,adaptations=['ratified1.0 target encoding; legacy narrowing .v renamed .w','source/destination EEW and EMUL checked independently','explicit tu/mu and ta/ma','discard expected/zero-tail arrays','FLEN64 unrelated scalar preservation','partial VL and complementary mask inspiration only']))
 # Old revision has no RTZ or ROD case. Borrow ONLY input/scenario provenance,
 # not a purported missing original form execution.
 derived=[]
 for form in f.FORMS:
  if form in result:continue
  origin=form.replace('.rtz.','.').replace('.rod.','.')
  assert origin in result;result[form]=result[origin]
  derived.append(dict(form=form,origin_form=origin,scope='same original input arrays and scenarios; new ratified RTZ/ROD opcode and exact predicates; original case absent'))
 output.write_text(json.dumps(result,indent=2)+'\n');(root/'CASE_WRAPPER_REVIEW.json').write_text(json.dumps(dict(original_cases=review,derived_input_reuse=derived,wrapper_path=str(wrappers),wrapper_sha256=hashlib.sha256(wrappers.read_bytes()).hexdigest()),indent=2)+'\n');(root/'WRAPPER_EXCERPTS.txt').write_text('\n'.join(excerpts))
 print(len(review),sum(x['original_wrapper_count'] for x in review),sum(x['applicable_wrappers'] for x in review),len(derived))
if __name__=='__main__':extract(Path(sys.argv[1]),Path(sys.argv[2]))
