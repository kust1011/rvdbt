# Adapted path handling only; original RVVTS compare is imported at runtime.
import io,json,struct,sys,re
from pathlib import Path
from rvvts.MachineState import MachineState,FDQRegStateDump
from rvvts.RVISACfg import RVISACfg
CSRS=['vl','vtype','vlenb','vstart','vxrm','vxsat','vcsr','fflags','frm','fcsr']
cfg=dict(rvisacfg=RVISACfg(xlen=32,extensions_under_test=['v','d'],vlen=2048,velen=64),memstart=0,float_flen=64)
def decode(packet):
 assert len(packet)==8768,f'packet {len(packet)} !=8768'
 before=FDQRegStateDump(config=cfg,addr=0,offset=0,reglist=list(range(32))).extract(io.BytesIO(packet))
 after=FDQRegStateDump(config=cfg,addr=8504,offset=0,reglist=list(range(32))).extract(io.BytesIO(packet))
 state={f'v{i}':packet[272+i*256:272+(i+1)*256]for i in range(32)};state.update({f'f{i}':v for i,v in enumerate(after)});state.update(dict(zip(CSRS,struct.unpack('<10I',packet[8464:8504]))))
 assert (state['vl'],state['vtype'],state['vlenb'],state['vstart'],state['frm'])==(64,80,256,0,0)
 assert state['fcsr']==(state['frm']<<5)|state['fflags']and state['vcsr']==(state['vxrm']<<1)|state['vxsat']
 return before,MachineState(cfg,[{},state])
def audit_input_unchanged(packet,initial,body,out):
 before,state=decode(packet);fcfg=dict(cfg,rvisacfg=RVISACfg(xlen=32,extensions_under_test=['d']));reference=MachineState(fcfg,[{},{f'f{i}':bytes.fromhex(initial['fprs'][f'f{i}'])for i in range(32)}]);prefp=MachineState(fcfg,[{},{f'f{i}':v for i,v in enumerate(before)}]);postfp=MachineState(fcfg,[{},{f'f{i}':state.state[1][f'f{i}']for i in range(32)}])
 for n,a,b in [('FPR-injection',reference,prefp),('FPR-before-after',prefp,postfp)]:
  equal,diff=a.compare(b,diff_full=True);(out/(n+'-original-compare.txt')).write_text(diff);assert equal,n
 written={int(re.match(r'vfadd.vv v(\d+)',line)[1])for line in body.splitlines()};unwritten=sorted(set(range(32))-written)
 vcfg=dict(cfg,rvisacfg=RVISACfg(xlen=32,extensions_under_test=[],vlen=2048,velen=64));r=MachineState(vcfg,[{},{f'v{i}':bytes.fromhex(initial['vectors'][f'v{i}'])for i in unwritten}]);a=MachineState(vcfg,[{},{f'v{i}':state.state[1][f'v{i}']for i in unwritten}]);equal,diff=r.compare(a,diff_full=True);(out/'unwritten-vector-original-compare.txt').write_text(diff);assert equal,'unwritten vector mismatch'
 state.save(str(out/'mstate.json'));(out/'observations.json').write_text(json.dumps(dict(before_fprs={f'f{i}':v.hex()for i,v in enumerate(before)},state={k:v.hex()if isinstance(v,bytes)else v for k,v in state.state[1].items()},written_regs=sorted(written),unwritten_regs=unwritten),indent=2)+'\n')
 return state

def compare_packet(raw, reference, returncode, timed_out=False):
 if returncode != 0 or timed_out:
  return False, 'nonzero exit or timeout'
 try:
  _,state=decode(raw)
  _,expected=decode(reference)
  return expected.compare(state,diff_full=True)
 except (AssertionError,ValueError,KeyError) as error:
  return False,str(error)
