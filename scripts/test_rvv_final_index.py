#!/usr/bin/env python3
"""Offline final evidence joins and corruption controls; no guest execution."""
import collections,copy,gzip,json,tempfile,unittest
from pathlib import Path
import rvv_verify as v
E=v.ROOT/'docs/rvv-validation/directed-task181'
ARGS=[E/'evidence/PER_FORM_RESULTS.json',E/'evidence/ENTRY_RECEIPTS.json',E/'BUILD_MANIFEST_179.json',E/'evidence/FINAL_RESULT.json']
class FinalIndex(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.index=v.load(v.INDEX);cls.plan=v.load(E/'DIRECTED_PLAN.json.gz')
 def test_actual_index(self):
  x=copy.deepcopy(self.index);v.join_final(x,self.plan,*ARGS)
  self.assertEqual(x['rows'],self.index['rows'])
  self.assertEqual(x['final179']['ordinary_positive_dut_checks'],12069048)
  self.assertEqual(x['final179']['cases_per_arm'],3017262)
  self.assertEqual(x['final179']['focused_positive_dut_checks'],2256)
  self.assertEqual(x['final179']['focused_denial_controls'],592)
  self.assertNotIn('PENDING',json.dumps(x))
  self.assertEqual(v.sha((E/'DIRECTED_PLAN.json.gz').read_bytes()),x['selection_plan_sha256'])
  self.assertEqual(v.sha(gzip.decompress((E/'DIRECTED_PLAN.json.gz').read_bytes())),v.load(E/'CANDIDATE_PIN.json')['final_plan_sha256'])
  for row in x['rows']:
   self.assertTrue(row['dimensions']);self.assertTrue(row['independent_oracle']);self.assertTrue(row['checked_state'])
   for entry in row['entries']:
    self.assertIsInstance(entry['example']['manifest_index'],int)
    self.assertTrue(entry['example']['id']);self.assertTrue(entry['example']['unit'])
  for e in self.plan['entries']:
   saved=x['entries'][e['id']]
   ids=[i for lo,hi in saved['accepted_ranges'] for i in range(lo,hi)]
   self.assertEqual(ids,e['accepted_indices'])
   for k in ('tools','tool_pins','flags','manifest_sha256','build_commands_sha256'):
    self.assertEqual(saved[k],e[k])
 def test_corrupt_final_joins(self):
  for field,value in [('cases_per_arm',0),('build_sha256','wrong'),('source_entries',[]),('failed',1),('passed',0)]:
   with self.subTest(field=field),tempfile.TemporaryDirectory() as tmp:
    r=v.load(ARGS[0]);r[0][field]=value;p=Path(tmp)/'results.json';v.save(p,r)
    with self.assertRaises(ValueError):v.join_final(copy.deepcopy(self.index),self.plan,p,*ARGS[1:])
  with tempfile.TemporaryDirectory() as tmp:
   r=v.load(ARGS[1]);r[0]['manifest_sha256']='wrong';p=Path(tmp)/'receipts.json';v.save(p,r)
   with self.assertRaises(ValueError):v.join_final(copy.deepcopy(self.index),self.plan,ARGS[0],p,*ARGS[2:])
 def test_external_partition(self):
  rows=v.load(E/'evidence/EXTERNAL_EXACT_JOINS.json.gz')
  self.assertEqual(len(rows),21316);self.assertEqual(len({(r['suite'],r['id'],r['command_sha256']) for r in rows}),21316)
  self.assertEqual(collections.Counter(r['suite'] for r in rows),dict(chips=11744,act=7668,ara=1904))
  self.assertEqual(sum(bool(r['control']) for r in rows if r['suite']=='chips'),212)
  self.assertEqual(sum(r['status']=='SCOPED_PASS' for r in rows if r['suite']=='ara'),16)
  self.assertTrue(all(r['status'] in ('PASS','SCOPED_PASS') for r in rows))
  self.assertEqual(len(v.load(ARGS[3])['external']['original_blockers']),2)
if __name__=='__main__':unittest.main()
