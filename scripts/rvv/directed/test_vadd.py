# SPDX-License-Identifier: MIT
"""Checker rejection and agnostic acceptance controls, separate from RVV credit."""
import importlib.util, struct, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('vadd',Path(__file__).with_name('vadd.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
class Checker(unittest.TestCase):
    def setUp(self):
        self.c=next(c for c in v.cases() if c['form']=='vv' and c['tag']=='length1' and c['lmul']=='m1')
        self.c['ordinal']=0;c=self.c;b=c['vlen']//8;e=c['sew']//8
        before=v.initial(c);after=bytearray(before)
        a=int.from_bytes(before[c['vs2']*b:c['vs2']*b+e],'little');z=int.from_bytes(before[c['vs1']*b:c['vs1']*b+e],'little')
        after[c['vd']*b:c['vd']*b+e]=((a+z)%(1<<c['sew'])).to_bytes(e,'little')
        self.raw=bytearray(struct.pack('<2I',0x145add,0)+struct.pack('<11I',*v.csr_expected(c),c['operand'])+struct.pack('<11I',*v.csr_expected(c,True),c['operand'])+before+after)
    def reject(self,offset):
        self.raw[offset]^=0x24
        with self.assertRaises(ValueError):v.check(self.c,self.raw)
    def test_good(self):self.assertTrue(v.check(self.c,self.raw))
    def test_active(self):self.reject(96+32*16+8*16)
    def test_preserved_tail(self):self.reject(96+32*16+8*16+1)
    def test_preserved_source(self):self.reject(96+32*16+16*16)
    def test_pre_state(self):self.reject(96+16*16)
    def test_post_csr(self):self.reject(52)
    def test_pre_csr(self):self.reject(8)
    def test_scalar(self):self.reject(92)
    def test_missing(self):
        with self.assertRaises(ValueError):v.check(self.c,self.raw[:-1])
    def test_failed_execution(self):
        with self.assertRaises(ValueError):v.check(self.c,self.raw,rc=1)
    def test_timeout(self):
        with self.assertRaises(ValueError):v.check(self.c,self.raw,timeout=True)
    def test_agnostic_sets(self):
        c=self.c;c['ta']=True
        struct.pack_into('<I',self.raw,12,v.csr_expected(c)[1]);struct.pack_into('<I',self.raw,56,v.csr_expected(c)[1])
        off=96+32*16+8*16+1
        self.raw[off]=255;self.assertTrue(v.check(c,self.raw))
        self.raw[off]=0x22
        with self.assertRaises(ValueError):v.check(c,self.raw)
if __name__=='__main__':unittest.main()
