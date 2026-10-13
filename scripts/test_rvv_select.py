#!/usr/bin/env python3
"""Small selector controls; no raw corpus or ISA execution required."""
import json,tempfile,unittest,subprocess,sys
from pathlib import Path
from types import SimpleNamespace
import rvv_verify as v
class Select(unittest.TestCase):
 def test_cli_parser(self):
  for args in (['--sew','x'],['--length','reserved'],['--arm','Reference']):
   run=subprocess.run([sys.executable,str(Path(v.__file__)),'list',*args],capture_output=True)
   self.assertEqual(run.returncode,2)
 def test_selection(self):
  with tempfile.TemporaryDirectory() as tmp:
   a=SimpleNamespace(raw_root=Path(tmp),form='vadd.vv',entry=None,unit=None,sew=32,lmul=None,vlen=None,mask=None,vstart=None,vl=None,length='partial')
   index=dict(original_root='/raw',entries={});row=dict(entries=[])
   for name,cases,ids in [('first',[dict(unit='bad',form='vv',sew=32,vl=1,vlmax=4),dict(unit='good',form='vv',sew=8,vl=1,vlmax=4)],[1]),('later',[dict(unit='ok',form='vv',sew=32,vl=1,vlmax=4)],[0])]:
    p=Path(tmp)/name;p.mkdir();raw=json.dumps(dict(cases=cases)).encode();(p/'manifest.json').write_bytes(raw)
    index['entries'][name]=dict(original='/raw/'+name,manifest_sha256=v.sha(raw),accepted_ranges=v.ranges(ids),accepted_selector_sha256=v.sha(json.dumps(ids,separators=(',',':')).encode()));row['entries'].append(dict(entry=name))
   self.assertEqual(v.select(index,row,a)[0],'later')
   a.entry='first'
   with self.assertRaises(ValueError):v.select(index,row,a)
   a.entry='unknown'
   with self.assertRaises(ValueError):v.select(index,row,a)
 def test_rejected_neighbor_in_unit(self):
  with tempfile.TemporaryDirectory() as tmp:
   cs=[dict(unit='mixed',form='vv',sew=32),dict(unit='mixed',form='vv',sew=32)]
   raw=json.dumps(dict(cases=cs)).encode();(Path(tmp)/'manifest.json').write_bytes(raw)
   e=dict(original='/raw',manifest_sha256=v.sha(raw),accepted_ranges=[[0,1]],accepted_selector_sha256=v.sha(b'[0]'))
   a=SimpleNamespace(raw_root=Path(tmp),form='vadd.vv',entry=None,unit=None,sew=32,lmul=None,vlen=None,mask=None,vstart=None,vl=None,length=None)
   with self.assertRaises(ValueError):v.select(dict(original_root='/raw',entries={'x':e}),dict(entries=[dict(entry='x')]),a)
 def test_parser_rejections(self):
  cs=[dict(unit='x',form='vv')]
  for rr in (None,[[0,2]],[[0,1],[0,1]],[[1,0]],[[0,1]]):
   with self.assertRaises(ValueError):v.accepted_cases(dict(accepted_ranges=rr,accepted_selector_sha256='bad'),cs)
 def test_incomplete_unit(self):
  self.assertFalse(v.matches(dict(form='vv',unit='x'),SimpleNamespace(form='vadd.vv',unit=None,sew=None,lmul=None,vlen=None,mask=None,vstart=None,vl=None,length='full')))
if __name__=='__main__':unittest.main()
