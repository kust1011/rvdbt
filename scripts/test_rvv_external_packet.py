"""Full API checker controls. Supply pinned RVVTS_SOURCE and a recorded packet."""
import os,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'rvv'))
if os.environ.get('RVVTS_SOURCE'):
 sys.path.insert(0,os.environ['RVVTS_SOURCE'])
 from rvvts_packet import compare_packet
@unittest.skipUnless(os.environ.get('RVVTS_SOURCE') and os.environ.get('RVVTS_PACKET'),'supply pinned RVVTS_SOURCE and recorded RVVTS_PACKET')
class PacketChecks(unittest.TestCase):
 def test_full_observation_changes(self):
  raw=Path(os.environ['RVVTS_PACKET']).read_bytes();self.assertTrue(compare_packet(raw,raw,0)[0])
  for offset in [272,8512,8464+7*4]:
   changed=bytearray(raw);changed[offset]^=1
   self.assertFalse(compare_packet(bytes(changed),raw,0)[0])
 def test_transport(self):
  raw=Path(os.environ['RVVTS_PACKET']).read_bytes()
  for b,rc,to in [(raw,1,False),(raw,0,True),(b'',0,False),(raw[:-1],0,False)]:self.assertFalse(compare_packet(b,raw,rc,to)[0])
if __name__=='__main__':unittest.main()
