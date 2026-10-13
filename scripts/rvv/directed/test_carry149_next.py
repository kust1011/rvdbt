#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepared checker unit controls; synthetic packets earn no guest/reference credit."""
import struct,unittest
import vadd as v
import carry149_next as c
class Prepared(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.rows=c.cases()
    def sample(self,op='vadc',form='vvm',tag='witness-toggle-carry-cin0',**kw):
        row=dict(next(x for x in self.rows if x['mnemonic']==op and x['form']==form and x['vlen']==128 and x['sew']==8 and x['lmul']=='m1' and x['tag']==tag),ordinal=0,**kw)
        before=c.initial(row);return row,before
    def packet(self,row,before,after):
        value=row['operand']&0xffffffff
        return bytearray(struct.pack('<2I',0x145add,0)+struct.pack('<11I',*v.csr_expected(row),value)+struct.pack('<11I',*v.csr_expected(row,True),value)+before+after)
    def test_zero_carry_updates_all_lanes(self):
        # MAX + 0 + carry0 still writes all lanes, including false carry-input bits.
        row,before=self.sample(vd=8);after=bytearray(before);after[128:144]=b'\xff'*16
        raw=self.packet(row,before,after);self.assertTrue(c.check_isa(row,raw))
        raw[96+512+128]^=1
        with self.assertRaisesRegex(ValueError,'active'):c.check_isa(row,raw)
    def test_one_carry_wraps_all_lanes(self):
        row,before=self.sample(tag='witness-toggle-carry-cin1');after=bytearray(before);after[128:144]=b'\0'*16
        raw=self.packet(row,before,after);self.assertTrue(c.check_isa(row,raw))
        # Forgetting carry-in gives MAX instead of zero.
        raw[96+512+128]=255
        with self.assertRaisesRegex(ValueError,'active'):c.check_isa(row,raw)
    def test_borrow_bit_layout(self):
        row,before=self.sample('vmsbc','vvm','witness-toggle-borrow-cin1');after=bytearray(before);after[128:130]=b'\xff\xff'
        raw=self.packet(row,before,after);self.assertTrue(c.check_isa(row,raw))
        raw[96+512+129]^=128
        with self.assertRaisesRegex(ValueError,'active'):c.check_isa(row,raw)
    def test_no_carry_ignores_v0(self):
        row,before=self.sample('vmadc','vv','witness-toggle-carry-cin1');after=bytearray(before);after[128:130]=b'\0\0'
        raw=self.packet(row,before,after);self.assertTrue(c.check_isa(row,raw))
        raw[96+512+128]=255
        with self.assertRaisesRegex(ValueError,'active'):c.check_isa(row,raw)
    def test_mask_tail_even_tu(self):
        row,before=self.sample('vmadc','vvm','witness-toggle-carry-cin0',vl=1,ta=False)
        after=bytearray(before);after[128]&=254
        # Mask-tail calculated false may clear an old1 through VLMAX despite tu.
        after[128]&=253
        raw=self.packet(row,before,after);self.assertTrue(c.check_isa(row,raw))
        # Beyond VLMAX, old1 may only remain1, never become0.
        index=next(i for i in range(16,128) if before[128+i//8]>>(i%8)&1)
        raw[96+512+128+index//8]&=~(1<<(index%8))
        with self.assertRaisesRegex(ValueError,'mask-tail'):c.check_isa(row,raw)
    def test_no_body_preserves_all_mask_bits(self):
        row,before=self.sample('vmadc','vvm','witness-toggle-carry-cin0',vl=0,vstart=1,ta=True)
        raw=self.packet(row,before,before);self.assertTrue(c.check_isa(row,raw));raw[96+512+128]^=1
        with self.assertRaisesRegex(ValueError,'no-body'):c.check_isa(row,raw)
    def test_mask_destination_v0_uses_pre_input(self):
        row,before=self.sample('vmadc','vvm','witness-toggle-carry-cin1',vd=0);after=bytearray(before)
        # MAX+0+1 => carry1, v0 input/output overlap. Input bits are from pre-state.
        raw=self.packet(row,before,after);self.assertTrue(c.check_isa(row,raw));raw[96+512+1]^=128
        with self.assertRaisesRegex(ValueError,'active'):c.check_isa(row,raw)
    def test_mask_source_overlap_uses_pre_source(self):
        row,before=self.sample('vmadc','vvm','witness-toggle-carry-cin0',vd=16)
        after=bytearray(before);after[256:258]=b'\0\0'
        raw=self.packet(row,before,after);self.assertTrue(c.check_isa(row,raw))
        raw[96+512+256]^=1
        with self.assertRaisesRegex(ValueError,'active'):c.check_isa(row,raw)
    def test_prestart_mask_and_body_across_chunk(self):
        row=dict(next(x for x in self.rows if x['mnemonic']=='vmadc' and x['form']=='vvm' and x['vlen']==1024 and x['sew']==8 and x['lmul']=='m1' and x['tag']=='witness-toggle-carry-cin1'),ordinal=0,vstart=63,vl=66)
        before=c.initial(row);after=bytearray(before);vd=row['vd']*128
        for i in range(63,66):after[vd+i//8]|=1<<(i%8)
        raw=self.packet(row,before,after);self.assertTrue(c.check_isa(row,raw))
        raw[96+32*128+vd+62//8]^=1<<(62%8)
        with self.assertRaisesRegex(ValueError,'prestart'):c.check_isa(row,raw)
    def test_vector_tail_and_prestart(self):
        row,before=self.sample(tag='witness-toggle-carry-cin1',vl=3,vstart=1,ta=False)
        after=bytearray(before);after[129:131]=b'\0\0';raw=self.packet(row,before,after)
        self.assertTrue(c.check_isa(row,raw));raw[96+512+131]^=1
        with self.assertRaisesRegex(ValueError,'preserved'):c.check_isa(row,raw)
    def test_all_declared_layouts_are_legal(self):
        for row in self.rows:
            regs=row['group_registers']
            self.assertEqual(row['vs2']%regs,0)
            sources=[row['vs2']]
            if c.operand_form(row)=='vv':
                self.assertEqual(row['vs1']%regs,0);sources.append(row['vs1'])
            if c.mask_result(row):
                for source in sources:
                    if source<=row['vd']<source+regs:self.assertEqual(row['vd'],source)
            else:self.assertNotEqual(row['vd'],0);self.assertEqual(row['vd']%regs,0)
            if c.with_input(row):self.assertNotIn(0,sources)
            if c.operand_form(row)=='vi':self.assertTrue(-16<=row['operand']<=15)
    def test_carry_bit_crossing_byte_and_mask_chunk(self):
        for bit in [7,8,63,64,511,512]:
            row=dict(next(x for x in self.rows if x['mnemonic']=='vmadc' and x['form']=='vvm' and x['vlen']==1024 and x['sew']==8 and x['lmul']=='m8' and x['tag']=='carry-bit'+str(bit)),ordinal=0)
            before=c.initial(row);after=bytearray(before);vd=row['vd']*128
            # MAX+zero means output carry-mask equals the single input bit.
            after[vd:vd+128]=(1<<bit).to_bytes(128,'little')
            raw=self.packet(row,before,after);self.assertTrue(c.check_isa(row,raw))
            raw[96+4096+vd+bit//8]^=1<<(bit%8)
            with self.assertRaisesRegex(ValueError,'active'):c.check_isa(row,raw)
if __name__=='__main__':unittest.main()
