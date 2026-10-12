"""Offline authentication and independent scalar-loop state/shape audit; no execution."""
from pathlib import Path
import json,hashlib,re,struct,subprocess,sys
root=Path(sys.argv[1]);out=Path(sys.argv[2])
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((root/'MANIFEST.json').read_text());assert all(sha(root/p)==h for p,h in manifest.items())
f=root/'focused/terminal-reviewed';layout=json.loads((f/'layout.json').read_text());results=[]
for p in sorted(f.glob('geometry-*.json')):
 g=json.loads(p.read_text());suffix=p.name[len('geometry-'):-len('.json')]
 blob=(f/f'snapshot-{suffix}.bin').read_bytes();assert len(blob)==layout['size']
 before=(f/f'before-{suffix}.bin').read_bytes();memory=(f/f'input-{suffix}.bin').read_bytes();expected=bytearray(before);earlier=bytearray()
 assert len(before)==32*512 and len(memory)==8192
 for e in range(g['start'],g['evl']):
  if g['masked'] and not (before[e//8] & (1<<(e%8))):continue
  for field in range(g['fields']):
   if (e,field)>=(g['fault_element'],g['fault_field']):continue
   address=(g['base']+(-e if g['kind']==5 else e)*g['fields']*g['eew']+field*g['eew'])&0xffffffff
   logical=e*g['eew'];slot=(8+field+logical//64)*512+logical%64
   data=memory[address-0x24000000:address-0x24000000+g['eew']];assert len(data)==g['eew']
   earlier.extend(before[slot:slot+g['eew']] if g['store'] else data)
   if not g['store']:expected[slot:slot+g['eew']]=data
 if g['kind']==1 and g['store']:earlier.extend(before[8*512:8*512+g['eew']//2])
 assert (f/f'memory-{suffix}.bin').read_bytes()==earlier
 assert blob[layout['vreg']:layout['vreg']+len(expected)]==expected
 read=lambda off:struct.unpack_from('<I',blob,off)[0]
 event=struct.unpack_from('<12I',blob,layout['event'])
 signal=0 if g['kind']==6 else 7 if g['kind']==3 else 11
 origin=0 if g['kind']==6 else 2 if g['native'] else 1
 reason=1 if g['kind']==6 else 2
 nf=2 if g['mode']==4 else g['fields']
 assert event==(origin,g['store'],reason,0x80001238,g['raw'],g['address'],g['fault_element'],g['fault_field'],g['eew'],nf,signal,0 if not signal else 2),event
 assert read(layout['pc'])==0x80001238 and read(layout['gpr']+6*4)==0x123
 assert read(layout['csrs']+3*4)==g['fault_element'] and read(layout['csrs']+7*4)==g['vl'] and read(layout['csrs']+8*4)==g['vtype']
 results.append({'file':str(p.relative_to(root)),**g,'register_bytes':len(expected),'memory_prefix_bytes':len(earlier)})
assert len(results)==42
wraps=[]
for p in f.glob('wrapped-*.bin'):
 raw=int(p.stem.split('-')[1],16);blob=p.read_bytes();e=struct.unpack_from('<12I',blob,layout['event'])
 assert e==(0,int(raw&127==39),0,0x80001238,raw,0,0,0,4,1,0,0)
 assert blob[layout['vreg']+8*512:layout['vreg']+9*512]==bytes([0x67])*512
 wraps.append(str(p.relative_to(root)))
assert len(wraps)==2
shapes=[]
for p in sorted((root/'focused/normal-reviewed').glob('sites-*.txt')):
 code=p.with_name(p.name.replace('sites-','emit-').replace('.txt','.bin'));data=code.read_bytes()
 dis=subprocess.check_output(['objdump','-D','-b','binary','-m','i386:x86-64',str(code)],text=True)
 ins={}
 for line in dis.splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)',line)
  if m:ins[int(m[1],16)]=m[3]
 sites=[dict(item.split('=') for item in line.split()) for line in p.read_text().splitlines()]
 for s in sites:
  pc=int(s['pc']);cold=int(s['cold']);op=ins[pc]
  assert 'mov' in op and '(%rbp,%rdi,1)' in op and '%r13' not in op and '%zmm' not in op
  assert s['element']=='R8D' and s['addr']=='EDI'
  assert data[cold:cold+6]==bytes.fromhex('59 4c 89 ef 31 f6') and 'jmp' in ins[cold+6]
  # Load register publication precedes any next normal guest access.
  raw=int(p.name.split('-')[1],16)
  if raw&127!=39:
   nxt=min([int(t['pc']) for t in sites if int(t['pc'])>pc]+[cold])
   assert any('mov' in i and '%r13,%rax' in i and i.startswith('mov') and i.index('%')<i.index('(%r13') for pos,i in ins.items() if pc<pos<nxt)
 shapes.append({'file':str(p.relative_to(root)),'sites':len(sites)})
assert len(shapes)==38
summary={'manifest_files':len(manifest),'differences':[],'terminal_cells':44,'host_sigsegv':sum(x['caught'] and x['kind']!=3 for x in results),'host_sigbus':sum(x['caught'] and x['kind']==3 for x in results),'predicted_cells':sum(not x['caught'] for x in results)+len(wraps),'scalar_shapes':shapes,'cells':results,'wrapped_snapshots':wraps,'guest_executions':0,'restart_verified':False}
out.write_text(json.dumps(summary,indent=2)+'\n');print({k:v for k,v in summary.items() if k not in ['cells','scalar_shapes','wrapped_snapshots']})
