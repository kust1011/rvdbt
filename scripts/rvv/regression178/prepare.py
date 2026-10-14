"""Declare exact frozen roots and ownership before replay; no guests or builds."""
import json,collections,hashlib,sys
from pathlib import Path
B=Path('/home/vick/rvv-task178');H=Path('/home/vick')
read=lambda p:json.loads(Path(p).read_text())
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
source=read(B/'SOURCE_MAP_175.json');owners={r[0]:r[1] or 176 for r in source['rows']}
assert len(owners)==595
entries=[]
def add(batch,root,tools=None,install=None,reuse=False):
 root=H/root; tools=H/tools if tools else root.parent/'scripts'
 assert (root/'manifest.json').is_file(),root
 if not (tools/'vadd.py').is_file():raise ValueError(('missing tools',tools))
 m=read(root/'manifest.json');cs=m['cases'];excluded=set()
 if batch in (162,165):
  name='TASK162_SOURCE_RULE_RECEIPT' if batch==162 else 'TASK165_RECLASSIFICATION'
  excluded=set(read(B/(name+'_EXCLUSIONS.json'))['excluded_case_ids'])
 if batch==166:
  # The canonical corrected family generator owns pilot reclassification.
  sys.path.insert(0,str(H/'rvv-task166/w128/scripts'))
  import indexed166
  legal={c['id'] for c in indexed166.cases()}
  sys.path.pop(0)
 else:legal=None
 def form(c):
  n=c.get('mnemonic','vadd')
  return n if n in owners else n+'.'+c['form']
 accepted=[]
 for i,c in enumerate(cs):
  f=form(c)
  if owners.get(f)!=batch or c['id'] in excluded:continue
  if legal is not None and c['id'] not in legal:continue
  if c.get('classification','').startswith('reserved'):continue
  if batch<=161 and c.get('vstart',0)>=c.get('vlmax',10**9):continue
  accepted.append(i)
 if not accepted:return
 units=sorted({cs[i]['unit'] for i in accepted})
 entries.append(dict(id=f'b{batch:03d}-{len(entries):03d}',batch=batch,original=str(root),tools=str(tools),install=install,reuse_same174=reuse,family=m.get('family','vadd145'),manifest_sha256=sha(root/'manifest.json'),build_commands_sha256=sha(root/'build-commands.json'),accepted_indices=accepted,accepted_cases=len(accepted),forms=dict(collections.Counter(form(cs[i]) for i in accepted)),units=units,tool_pins={str(p):sha(p) for p in sorted(tools.iterdir()) if p.is_file() and p.suffix in ('.py','.json')},flags=str(H/'rvv-directed-task153/FLAGS.json')))
add(145,'rvv-directed-task145/corpus','rvv-directed-task145')
add(146,'rvv-directed-task146/corpus','rvv-directed-task146/scripts-final')
add(147,'rvv-directed-task147/corpus','rvv-directed-task147')
add(148,'rvv-directed-task147/corpus','rvv-directed-task147')
add(148,'rvv-directed-task148/delta/corpus','rvv-directed-task148/delta/scripts')
add(148,'rvv-directed-task148/shift/corpus')
add(149,'rvv-directed-task149/full/corpus')
add(149,'rvv-directed-task149/zero-full/corpus')
add(150,'rvv-directed-task150/full/corpus')
add(151,'rvv-directed-task151/full/corpus')
add(152,'rvv-directed-task152/full/corpus')
add(153,'rvv-directed-task153/full/corpus')
add(153,'rvv-directed-task153/boundary/full/corpus')
add(154,'rvv-directed-task154/full/corpus')
add(155,'rvv-directed-task155/full/corpus')
for name,install in [('mask','mask158'),('scaling',None),('narrowing',None)]:add(159,'rvv-task159-full/'+name+'/corpus',install=install)
add(160,'rvv-directed-task157/fp-full-final/corpus')
for name in ['wmac-full2','destchunk-full','extend-full']:add(161,'rvv-directed-task156/'+name+'/corpus')
add(161,'rvv-directed-task154/widen-full/corpus')
add(162,'rvv-task162/full/corpus',install='permute162')
add(163,'rvv-task163/full/corpus',install='reduction163')
for batch,fam in [(165,'memory165'),(166,'indexed166'),(168,'memory168')]:
 for name in ['pilot','w128','w256','w512','w1024','w2048','w4096']:add(batch,f'rvv-task{batch}/{name}/corpus',install=fam)
add(168,'rvv-task168/policy/corpus','rvv-task168/tools',install='policy_memory168')
for name in ['pilot','w128','w256','w512','w1024','w2048','w4096']:
 add(169,'rvv-task169/prefix/'+name+'/corpus','rvv-task169/reviewed-tools',install='prefix169')
for name in ['pilot','w128','w256','w512','w1024','w2048','w4096']:
 root='rvv-task169/moves/pilot/accepted-corpus' if name=='pilot' else 'rvv-task169/moves-reviewed/'+name+'/corpus'
 add(169,root,'rvv-task169/reviewed-tools',install='moves169')
add(167,'rvv-directed-task167/full-review/corpus','rvv-directed-task167/scripts')
for name in ['minmax-pilot','minmax-remaining','sign-pilot','sign-remaining','compare-class-pilot-v2','compare-class-remaining-v2']:
 add(170,'rvv-directed-task170/'+name+'/corpus','rvv-directed-task170/tools-v2')
for name in ['original38','remaining','transfers-pilot','transfers-w128','transfers-w256','transfers-w512','transfers-w1024','transfers-w2048','transfers-w4096']:
 add(171,'rvv-task171/views/'+name+'/corpus','rvv-task171/scripts',install='moves169')
for name in ['same-pilot','same-remaining','widen-pilot','widen-remaining','narrow-pilot-fixed','narrow-remaining-fixed']:
 add(172,'rvv-directed-task172/'+name+'/corpus','rvv-directed-task172/tools-fixed')
for name in ['pilot','addsub','mul','fma','extra']:add(173,'rvv-task173/'+name,'rvv-task173/tools')
for name in ['pilot','remaining','overlap-supplement']:add(174,'rvv-directed-task174/'+name+'/corpus','rvv-directed-task174/tools',reuse=True)
for family in ['fpmerge175','fpslide175','narrow175']:
 for name in ['pilot','remaining']:add(175,'rvv-directed-task175/'+family+'/'+name+'/corpus','rvv-directed-task175/tools-review175',reuse=True)
add(175,'rvv-directed-task175/supplement/corpus','rvv-directed-task175/tools-supp-v2',reuse=True)
for name in ['pilot','vfsqrt','vfrec7','vfrsqrt7']:add(176,'rvv-task176/'+name,'rvv-task176/tools',reuse=True)
# No duplicate pilot credit; each owner's accepted declaration appears once.
seen=set()
for e in entries:
 cs=read(Path(e['original'])/'manifest.json')['cases'];e['accepted_indices']=[i for i in e['accepted_indices'] if (e['batch'],cs[i]['id']) not in seen]
 for i in e['accepted_indices']:seen.add((e['batch'],cs[i]['id']))
 e['accepted_cases']=len(e['accepted_indices'])
 e['forms']=dict(collections.Counter((cs[i].get('mnemonic','vadd') if cs[i].get('mnemonic','') in owners else cs[i].get('mnemonic','vadd')+'.'+cs[i]['form']) for i in e['accepted_indices']))
covered={f for e in entries for f in e['forms']}
assert covered==set(owners),(len(covered),set(owners)-covered)
(B/'DIRECTED_PLAN.json').write_text(json.dumps(dict(build='18521de85c7ba352b0dbc6155f26d96c25522b6a6bc81cb26fb38c4c0b1f79a4',forms=595,owners=owners,entries=entries),indent=2)+'\n')
print(len(entries),'batches',sum(e['accepted_cases'] for e in entries),'legal cases per arm')
