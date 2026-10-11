#!/usr/bin/env python3
"""Check unchanged RVVTS body/input bytes and full register transport in new ELF."""
import argparse,json,re,struct,subprocess
from pathlib import Path
from rvv_tests import digest,save
p=argparse.ArgumentParser();p.add_argument('--elf',type=Path,required=True);p.add_argument('--nm',default='llvm-nm-22');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
f=Path(__file__).resolve().parent/'rvv/fixtures/rvvts-20261089';raw=a.elf.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',raw);assert h[0][:7]==b'\x7fELF\x01\x01\x01' and h[2]==243 and not h[7]&1
segments=[]
for i in range(h[10]):
 typ,off,addr,paddr,fs,ms,flags,align=struct.unpack_from('<8I',raw,h[5]+i*h[9])
 if typ==1:segments.append(dict(address=addr,offset=off,file_bytes=fs,bytes=ms,flags=flags))
def read(addr,size):
 s=next(s for s in reversed(segments) if s['address']<=addr and addr+size<=s['address']+s['file_bytes']);o=s['offset']+addr-s['address'];return raw[o:o+size]
nm=subprocess.check_output([a.nm,'-n',str(a.elf)],text=True);syms={n:int(addr,16) for addr,t,n in re.findall(r'^([0-9a-f]+)\s+(\w)\s+(\S+)$',nm,re.M)}
inputs=json.loads((f/'INPUT.json').read_text());spans=[]
for kind,size,key in [('f',8,'fprs'),('v',256,'vectors')]:
 for i in range(32):
  name=kind+str(i);addr=syms['_reg_'+name];assert read(addr,size).hex()==inputs[key][name];spans.append((addr,addr+size))
assert syms['sequence_end']-syms['sequence_begin']==64
joins=[]
for i,line in enumerate((f/'native16.txt').read_text().splitlines()):
 m=re.fullmatch(r'vfadd.vv v(\d+), v(\d+), v(\d+)(, v0.t)?',line);vd,vs2,vs1=map(int,m.group(1,2,3));pc=syms['sequence_begin']+i*4;w=int.from_bytes(read(pc,4),'little')
 assert w&127==0x57 and (w>>12)&7==1 and w>>26==0 and [(w>>7)&31,(w>>20)&31,(w>>15)&31]==[vd,vs2,vs1] and bool((w>>25)&1)==(not bool(m[4]));joins.append(dict(ordinal=i+1,pc=hex(pc),encoding=f'{w:08x}',instruction=line))
text=next(s for s in segments if s['flags']&1);pc=text['address'];end=pc+text['file_bytes'];words=[]
while pc<end:
 skip=next((b for lo,b in spans if lo<=pc<b),None)
 if skip:pc=skip;continue
 w=int.from_bytes(read(pc,4),'little');assert w&3==3;words.append(w);pc+=4
assert sum(w&127==7 and (w>>12)&7==3 for w in words)==32
assert sum(w&127==0x27 and (w>>12)&7==3 for w in words)==64
assert sum(w&127==7 and (w>>20)&31==8 and (w>>12)&7==0 for w in words)==32
assert sum(w&127==0x27 and (w>>20)&31==8 and (w>>12)&7==0 for w in words)==32
assert syms['resultdata']%4096==0
save(a.output,dict(status='PASS',elf_sha256=digest(a.elf),symbols=syms,segments=segments,body=joins,input_bytes_unchanged=True,full64_fld=32,full64_fsd=64,vector_restore_bytes=8192,vector_capture_bytes=8192,packet_bytes=8768))
print('PASS: original16 encodings, input bytes and full state transport')
