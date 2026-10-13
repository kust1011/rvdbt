#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic new-family controls earn no guest/reference execution credit."""
import struct,unittest
import vadd as v
import mergemove150_next as m

class Prepared(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.rows=m.cases()
    def sample(self,op='vmerge',form='vvm',**kw):
        row=dict(next(c for c in self.rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,8,'m1') and c['tag']=='length0'),ordinal=0,vl=16)
        row.update(kw);return row,m.initial(row)
    def packet(self,row,before,after):
        x=row['operand']&0xffffffff
        return bytearray(struct.pack('<2I',0x145add,0)+struct.pack('<11I',*v.csr_expected(row),x)+struct.pack('<11I',*v.csr_expected(row,True),x)+before+after)
    def valid(self,row,before):
        after=bytearray(before);off=row['vd']*16
        for i in range(row['vstart'],row['vl']):after[off+i:off+i+1]=m.lane(row,before,i)
        return self.packet(row,before,after)
    def test_all_forms_false_selection_still_write(self):
        for op,forms in m.FORMS.items():
          for form in forms:
            row,before=self.sample(op,form,selection_pattern='off');raw=self.valid(row,before)
            self.assertTrue(m.check_isa(row,raw));raw[96+512+128]^=1
            with self.assertRaisesRegex(ValueError,'active'):m.check_isa(row,raw)
    def test_selection_bit_packing(self):
        row,before=self.sample(selection_bit=8);raw=self.valid(row,before);self.assertTrue(m.check_isa(row,raw))
        self.assertEqual(raw[96+512+128+7],before[256+7]);self.assertEqual(raw[96+512+128+8],before[384+8])
    def test_v0_move_destination(self):
        row,before=self.sample('vmv','v.i',vd=0,operand=-16);raw=self.valid(row,before)
        self.assertTrue(m.check_isa(row,raw));self.assertEqual(raw[96+512:96+512+16],b'\xf0'*16)
    def test_source_overlap_reads_prestate(self):
        row,before=self.sample(vd=16,selection_pattern='alternating');raw=self.valid(row,before);self.assertTrue(m.check_isa(row,raw))
    def test_move_reads_v0_as_vector_data(self):
        for vd in [0,8]:
            row,before=self.sample('vmv','v.v',vd=vd,vs1=0,selection_pattern='alternating');raw=self.valid(row,before)
            self.assertTrue(m.check_isa(row,raw));self.assertEqual(raw[96+512+vd*16:96+512+(vd+1)*16],before[:16])
    def test_scalar_sign_extension_and_immediate_extremes(self):
        for op,form in [('vmerge','vxm'),('vmv','v.x')]:
            row,before=self.sample(op,form,sew=64,vlmax=2,vl=2,operand=0x80000001,selection_pattern='all')
            self.assertEqual(m.lane(row,before,0),bytes.fromhex('01000080ffffffff'))
        for imm in [-16,-1,0,15]:
            row,before=self.sample('vmv','v.i',sew=64,vlmax=2,vl=2,operand=imm)
            self.assertEqual(m.lane(row,before,0),(imm&((1<<64)-1)).to_bytes(8,'little'))
    def test_prestart_and_tail(self):
        row,before=self.sample(vstart=8,vl=9);raw=self.valid(row,before);self.assertTrue(m.check_isa(row,raw))
        for i in [7,9]:
            bad=bytearray(raw);bad[96+512+128+i]^=1
            with self.assertRaisesRegex(ValueError,'preserved'):m.check_isa(row,bad)
    def test_no_body(self):
        row,before=self.sample(vstart=1,vl=0,ta=True);raw=self.packet(row,before,before);self.assertTrue(m.check_isa(row,raw))
        raw[96+512+128]^=1
        with self.assertRaisesRegex(ValueError,'no-body'):m.check_isa(row,raw)
    def test_reference_compares_both_selected_and_unselected_lanes(self):
        row,before=self.sample(selection_pattern='alternating');ref=self.valid(row,before)
        for i in [0,1]:
            bad=bytearray(ref);bad[96+512+128+i]^=1
            with self.assertRaisesRegex(ValueError,'reference'):m.check_reference(row,bad,ref)
    def test_all_layouts_and_immediates(self):
        for row in self.rows:
            regs=row['group_registers'];self.assertEqual(row['vd']%regs,0)
            if row['mnemonic']=='vmerge':self.assertNotEqual(row['vd'],0);self.assertEqual(row['vs2']%regs,0)
            else:self.assertEqual(row['vs2'],0)
            if m.kind(row)=='vv':self.assertEqual(row['vs1']%regs,0)
            if m.kind(row)=='vi':self.assertTrue(-16<=row['operand']<=15)
if __name__=='__main__':unittest.main()
