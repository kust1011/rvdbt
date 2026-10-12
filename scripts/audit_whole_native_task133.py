"""Authenticate Task133 receipts and independently check terminal register bytes.
Offline only: no guest execution or restart.
"""
from pathlib import Path
import hashlib,json,re,struct,subprocess,sys
root=Path(sys.argv[1]);out=Path(sys.argv[2])
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((root/'MANIFEST.json').read_text())
assert all(sha(root/p)==h for p,h in manifest.items())
layout=json.loads((root/'focused/ordinary/dispatcher-layout.json').read_text())
cells=[]
for folder in ['whole','extra','extra-final']:
 for p in sorted((root/'focused'/folder).glob('snapshot-*.bin')):
  raw,vlen,mode=re.fullmatch(r'snapshot-([0-9a-f]+)-vlen(\d+)-mode(\d+)\.bin',p.name).groups()
  raw=int(raw,16);vlen=int(vlen);mode=int(mode);n=(raw>>29)+1;store=(raw&127)==39
  width=(raw>>12)&7;eew=1 if width==0 else 1<<(width-4)
  total=n*vlen//8;chunk=min(vlen//8,64);prefix=chunk if total>chunk else 0
  if mode==1:prefix+=eew
  if prefix>=total:prefix=eew
  blob=p.read_bytes();assert len(blob)==layout['size']
  read=lambda o:struct.unpack_from('<I',blob,o)[0]
  event=struct.unpack_from('<12I',blob,layout['event'])
  assert event==(2 if mode==0 else 1,int(store),2,0x80001238,raw,0x24001000,prefix//eew,0,eew,n,11,2),event
  assert read(layout['pc'])==0x80001238 and read(layout['gpr']+24)==0x123
  assert read(layout['csrs']+12)==prefix//eew and read(layout['csrs']+28)==0
  # Entire fixed CPUState register file, including bytes outside small VLEN slots.
  expected=bytearray((r*19+b*7)&255 for r in range(32) for b in range(layout['vreg_stride']))
  if not store:
   for b in range(eew if mode==2 else 0,prefix):
    r=8+b//(vlen//8);slot=b%(vlen//8);expected[r*layout['vreg_stride']+slot]=(b*5+3)&255
  start=layout['vreg'];assert blob[start:start+len(expected)]==expected
  cells.append({'file':str(p.relative_to(root)),'vlen':vlen,'nregs':n,'eew':eew,'store':store,'mode':mode,'vstart':prefix//eew,'full_register_bytes':len(expected)})
assert len(cells)==54 # 30 distinct geometries plus retained accidental stale-binary batch
shapes=[]
for p in sorted((root/'focused/normal-complete').glob('sites-*.txt')):
 raw=int(p.name.split('-')[1],16);store=(raw&127)==39
 binary=p.with_name(p.name.replace('sites-','emit-').replace('.txt','.bin'))
 data=binary.read_bytes();dis=subprocess.check_output(['objdump','-D','-b','binary','-m','i386:x86-64',str(binary)],text=True)
 instructions={}
 for line in dis.splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)',line)
  if m:instructions[int(m.group(1),16)]=m.group(3)
 sites=[dict(item.split('=') for item in line.split()) for line in p.read_text().splitlines()]
 for k,s in enumerate(sites):
  off=int(s['pc']);cold=int(s['cold']);i=instructions[off]
  assert 'vmovdqu' in i and '(%rax)' in i and '%k' not in i
  assert (i.index('(%rax)')<min(x for x in [i.find('%xmm'),i.find('%ymm'),i.find('%zmm')] if x>=0))==(not store)
  assert data[cold:cold+6]==bytes.fromhex('59 4c 89 ef 31 f6') and 'jmp' in instructions[cold+6]
  assert int(s['disp'])==k*int(s['bytes']) and int(s['mask'])==255
  if not store:
   stop=int(sites[k+1]['pc']) if k+1<len(sites) else cold
   assert any('vmovdqu' in ins and '(%r13)' in ins and ins.index('%')<ins.index('(%r13)') for pos,ins in instructions.items() if off<pos<stop)
 shapes.append({'file':str(p.relative_to(root)),'exact_sites':len(sites)})
assert len(shapes)==48
out.write_text(json.dumps({'manifest_files':len(manifest),'differences':[],'terminal_cells':cells,'physical_whole_faults':54,'distinct_whole_geometries':30,'emitted_shapes':shapes,'guest_executions':0,'restart_verified':False},indent=2)+'\n')
print(json.dumps({'snapshots':len(cells),'shapes':len(shapes),'differences':0,'guest_executions':0}))
