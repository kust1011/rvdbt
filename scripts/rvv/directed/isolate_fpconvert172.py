#!/usr/bin/env python3
"""Keep original conversion failures; isolate one unchanged original target/case."""
import collections,json,struct,subprocess,sys
from pathlib import Path
import fpconvert172 as f
import vadd as v
import audit

def isolate(base):
 root=base/'narrow-pilot/corpus';rows=json.loads((root/'manifest.json').read_text())['cases'];ids={c['id']:c for c in rows};results=json.loads((root/'results.json').read_text());failed=[r for r in results if r['status']=='FAIL'];out=base/'adjudication';out.mkdir(exist_ok=False)
 proof=[];cache={}
 for receipt in failed:
  c=ids[receipt['case']];path=Path(receipt['raw']);cache.setdefault(str(path),v.storage.verify(path));raw=cache[str(path)][receipt['offset']:receipt['offset']+receipt['size']];pre,post,before,after=v.decode(c,raw);e=c['dst_eew']//8;b=c['vlen']//8;off=c['vd']*b
  refpath=root/'runs'/c['unit']/'Reference/packets.bin';cache.setdefault(str(refpath),v.storage.verify(refpath));ref=cache[str(refpath)][receipt['offset']:receipt['offset']+receipt['size']];f.check_isa(c,ref);_,rp,_,ra=v.decode(c,ref)
  assert after==ra and post[:7]==rp[:7] and post[7]==1 and rp[7]==3 and c['frm']==4
  try:f.check_isa(c,raw)
  except ValueError:pass
  else:raise AssertionError('old failure unexpectedly passes')
  proof.append(dict(original_receipt=receipt,input_word=hex(c['input_word']),result_word=hex(int.from_bytes(after[off:off+e],'little')),old_flags=post[7],reference_flags=rp[7],mathematical_flags=f.lane(c,before,0)[1],original_packet_sha256=v.storage.digest(raw),reference_packet_sha256=v.storage.digest(ref)))
 v.save(out/'ORIGINAL_FAILURES.json',dict(failed_checks=len(failed),proof=proof,summary=json.loads((root/'summary.json').read_text()),original_manifest_sha256=v.sha(root/'manifest.json'),original_results_sha256=v.sha(root/'results.json')))
 c=ids[failed[0]['case']];source=out/'original.S';source.write_text(v.assembly([c]));v.save(out/'ORIGINAL_CASE.json',c)
 # A separate Sail witness advances from lane 1 of the SAME repeated original
 # input bits, using vl2/vstart1 so both independently pinned engines cover RMM.
 sailcase=dict(c,vl=2,vstart=1);(out/'sail-witness.S').write_text(v.assembly([sailcase]));v.save(out/'SAIL_WITNESS_CASE.json',sailcase)
 for name in ('user.ld','sail.ld'):(out/name).write_bytes((root/name).read_bytes())
 builds=[]
 for name,case,machine in [('original',c,False),('sail-witness',sailcase,True)]:
  cmd=['clang-22','--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-relax','-Wl,-T,'+str(out/('sail.ld' if machine else 'user.ld'))]+(['-DSAIL'] if machine else [])+[str(out/(name+'.S')),'-o',str(out/(name+'.elf'))];p=subprocess.run(cmd,capture_output=True);(out/(name+'-build.stderr')).write_bytes(p.stderr);assert not p.returncode,p.stderr
  sec,sym=audit.elf_sections_symbols(out/(name+'.elf'));pc=sym['target_'+str(c['ordinal'])];word=int.from_bytes(sec['.text'][1][pc-sec['.text'][0]:pc-sec['.text'][0]+4],'little');assert word==f.instruction(c)
  builds.append(dict(command=cmd,elf_sha256=v.sha(out/(name+'.elf')),target_pc=hex(pc),instruction=hex(word)))
 v.save(out/'BUILDS.json',builds)
 v.save(out/'sail-config.json',{'base':{'xlen':32},'extensions':{'V':{'vlen_exp':7,'elen_exp':6,'vstart':{'zero_required':{'arith':False}},'reserved_behavior':{'vstart_out_of_bounds':'Vstart_Ignore'}},'D':{'supported':True}}})
 print(len(failed),c['id'],flush=True)
if __name__=='__main__':isolate(Path(sys.argv[1]))
