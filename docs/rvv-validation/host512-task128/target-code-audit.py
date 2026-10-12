import json,re,subprocess,hashlib
from pathlib import Path
r=Path('/home/vick/rvdbt-host512-task128');q=json.loads((r/'pilot/QUEUE.json').read_text());entries={e['case']:e for e in q['entries']};out=[]
for case in ('Vls32-vle32.v','Vls32-vse32.v','Vls8-vle32.v','Vls32-vl1re32.v','Vls32-vlm.v','Vls32-vlse32.v','Vls32-vluxei32.v','Vls32-vle32ff.v'):
 e=entries[case];guest=subprocess.check_output(['llvm-objdump-22','-d','--no-show-raw-insn',e['elf']],text=True);(r/'inspection'/f'{case}.guest.disasm').write_text(guest)
 labels=re.findall(r'^([0-9a-f]+) <('+re.escape(case.replace('-','_').replace('.','_'))+r'_cg_cp[^>]+)>:\n\s*([0-9a-f]+):\s*(.*)',guest,re.M)
 assert labels,case
 selected=[labels[0]]
 if case=='Vls32-vse32.v':selected.append(next(l for l in labels if 'v0.t' in l[3]))
 for label in selected:
  pc=int(label[0],16);instruction=label[3]
  for arm in ('B','M1','M2','BOTH'):
   d=r/'inspection/raw'/case/arm;tbmap={int(l.split()[0],16):dict(host_start=l.split()[1],size=int(l.split()[2]),exec_count=int(l.split()[3])) for l in ((d/'tbmap.txt').read_text().splitlines()[1:] if (d/'tbmap.txt').exists() else [])}
   matches=[]
   for line in (d/'tbcode.txt').read_text().splitlines():
    ip,size,h=line.split();data=bytes.fromhex(h)
    needle=bytes.fromhex('41c785b8000000')+pc.to_bytes(4,'little')
    if needle not in data:continue
    offset=data.index(needle)
    (d/'candidate.bin').write_bytes(data)
    dis=subprocess.check_output(['objdump','-D','-b','binary','-m','i386:x86-64','-Mintel','--start-address='+str(offset),str(d/'candidate.bin')],text=True)
    # architectural guest PC stores distinguish the target from setup/checker loads
    mark=re.search(r'^\s*([0-9a-f]+):.*mov\s+DWORD PTR \[r13\+0xb8\],0x'+f'{pc:x}'+r'\s*$',dis,re.M)
    if not mark:continue
    rest=dis[mark.start():];firstline=rest.index('\n')+1;nextmark=re.search(r'^\s*[0-9a-f]+:.*mov\s+DWORD PTR \[r13\+0xb8\],0x',rest[firstline:],re.M)
    segment=rest[:nextmark.start()+firstline] if nextmark else rest
    (d/f'tb-{ip}.disasm').write_text(dis);(d/f'target-{pc:08x}.disasm').write_text(segment)
    matches.append(dict(tb_guest_ip=ip,tbmap=tbmap.get(int(ip,16)),target_host_offset=mark.group(1),target_guest_pc=f'{pc:08x}',label=label[1],instruction=instruction,segment=segment,tb_bytes_sha256=hashlib.sha256(data).hexdigest()))
   assert matches,(case,arm,hex(pc))
   text=(r/'pilot/raw'/case/arm/'stderr').read_text()
   out.append(dict(case=case,form=e['form'],arm=arm,matches=matches,routes=re.findall(r'^RVV_ROUTE .*$',text,re.M),direct=re.findall(r'^RVV_DIRECT .*$',text,re.M)))
(r/'TARGET_CODE.json').write_text(json.dumps(out,indent=2)+'\n')
for x in out:
 s=x['matches'][0]['segment'];print(x['case'],x['arm'],x['matches'][0]['target_guest_pc'], 'zmm_mem=',len(re.findall(r'vmov\w+.*\[rax',s)), 'calls=',len(re.findall(r'\bcall\b',s)), 'exec=',(x['matches'][0]['tbmap'] or {}).get('exec_count','not_dumped'))
