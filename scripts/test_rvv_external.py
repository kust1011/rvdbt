import json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_rvv_external import ara_check,verify_fixtures,F,check_reused_command
class ExternalChecks(unittest.TestCase):
 def test_reuse_retains_execution_options(self):
  old=['/engine','--vlen=1024','--rvv-run=0','--dump-tbcode=/old/code','--fsroot=/old/fs','--cache=/old/cache','--','/t.elf']
  relocated=[x.replace('/old/','/new/') for x in old]
  check_reused_command(old,relocated)
  for changed in ['--vlen=2048','--rvv-run=1']:
   current=relocated.copy();current[1 if changed.startswith('--vlen') else 2]=changed
   with self.assertRaisesRegex(ValueError,'execution options'):check_reused_command(old,current)
  with self.assertRaisesRegex(ValueError,'execution options'):check_reused_command(old,relocated+['--extra'])
 def test_reuse_reference_keeps_isa_and_pk(self):
  old=['/spike','--isa=rv32gcv_zvl2048b','/pk','/old/guest.elf']
  check_reused_command(old,old[:-1]+['/new/guest.elf'],True)
  for index,value in [(1,'--isa=rv32gcv_zvl1024b'),(2,'/different-pk')]:
   current=old.copy();current[index]=value
   with self.assertRaisesRegex(ValueError,'execution options'):check_reused_command(old,current,True)
 def packet(self):
  j=json.loads((F/'ara-vredsum/expected-observations.json').read_text());lines=[]
  for i in range(5):lines+=['ARA_CASE_BEGIN TEST_CASE'+str(i+1),'ARA_CASE_END TEST_CASE'+str(i+1)]
  lines+=['PASSED.']*20
  for row in j['vsets']:lines+=['ARA_VSET line=%d avl=%d vl=%d vtype=%d'%tuple(row)]
  for i,row in enumerate(j['assertions'],1):lines+=['ARA_ASSERT id=%d elements=%d bytes=%d vl=%d vtype=%d comparisons=%d completed=%d sequence=%d'%tuple(row+[i])]
  lines+=['ARA_SUMMARY status=%d vsets=%d assertions=%d comparisons=%d'%tuple(j['summary']),'ARA_FLAG_SUMMARY reads=0 flags=0 completed=0 comparisons=0','ARA_SCALAR_SUMMARY scalars=0 completed=0 comparisons=0']
  return ('\n'.join(lines)+'\n').encode()
 def test_original_initialization(self):verify_fixtures()
 def test_changed_observation(self):
  raw=self.packet();self.assertTrue(ara_check(raw,0));self.assertFalse(ara_check(raw.replace(b'comparisons=200',b'comparisons=199'),0))
 def test_exit_timeout_missing_truncated(self):
  raw=self.packet()
  for b,rc,to in [(raw,1,False),(raw,0,True),(b'',0,False),(raw[:len(raw)//2],0,False)]:self.assertFalse(ara_check(b,rc,to))
 def test_omitted_initialization(self):
  from unittest.mock import patch
  original=Path.read_text
  def read(p,*a,**k):
   t=original(p,*a,**k)
   return t.replace('  INIT_CHECK();\n','') if p.name=='context_original_vredsum.c' else t
  with patch.object(Path,'read_text',read):
   with self.assertRaisesRegex(ValueError,'initialization'):verify_fixtures()
if __name__=='__main__':unittest.main()
