#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import struct,unittest
import vadd as v
import compare151_next as m

class Prepared(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.rows=m.cases()
    def sample(self,op='vmseq',form='vv',**kw):
        c=dict(next(c for c in self.rows if c['mnemonic']==op and c['form']==form and (c['vlen'],c['sew'],c['lmul'])==(128,8,'m1') and c['tag']=='length0'),ordinal=0,vl=16)
        c.update(kw);return c
    def packet(self,c):
        before=m.initial(c);after=bytearray(before);vd=c['vd']*16
        for i in range(c['vstart'],c['vl']):
            if c['mask']=='none' or before[i//8]>>(i%8)&1:
                pos=vd+i//8;bit=1<<(i%8);after[pos]=(after[pos]&~bit)|(m.lane(c,before,i)<<(i%8))
        x=c['operand']&0xffffffff
        return bytearray(struct.pack('<2I',0x145add,0)+struct.pack('<11I',*v.csr_expected(c),x)+struct.pack('<11I',*v.csr_expected(c,True),x)+before+after)
    def test_all_forms_reject_active_bit(self):
        for op,forms in m.FORMS.items():
          for form in forms:
            c=self.sample(op,form);raw=self.packet(c);self.assertTrue(m.check_isa(c,raw));bad=bytearray(raw);bad[96+512+c['vd']*16]^=1
            with self.assertRaises(ValueError):m.check_isa(c,bad)
            with self.assertRaises(ValueError):m.check_reference(c,bad,raw)
    def test_signed_unsigned_boundaries(self):
        for sew in [8,16,32,64]:
            sign=1<<(sew-1);c=self.sample(sew=sew)
            self.assertEqual(m.element(dict(c,mnemonic='vmslt'),sign,sign-1),1)
            self.assertEqual(m.element(dict(c,mnemonic='vmsltu'),sign,sign-1),0)
            for op in m.FORMS:
                expected=int(op in ('vmseq','vmsle','vmsleu'))
                self.assertEqual(m.element(dict(c,mnemonic=op),sign,sign),expected)
    def test_scalar_sign_extension(self):
        c=self.sample('vmsltu','vx',sew=64,operand=0x80000000)
        self.assertEqual(m.scalar(c),-2147483648)
        self.assertEqual(m.element(c,1<<32,m.scalar(c)),1)
    def test_signed_immediates_for_unsigned_compare(self):
        for imm in range(-16,16):
            c=self.sample('vmsleu','vi',operand=imm)
            self.assertEqual(m.element(c,255,imm),int(imm==-1))
    def test_dest_v0_masked_uses_prestate(self):
        c=self.sample(vd=0,mask='alternating');raw=self.packet(c);self.assertTrue(m.check_isa(c,raw))
        before=v.decode(c,raw)[2];after=v.decode(c,raw)[3]
        for i in range(16):
            expected=m.lane(c,before,i) if i%2==0 else before[i//8]>>(i%8)&1
            self.assertEqual(after[i//8]>>(i%8)&1,expected)
    def test_preserved_and_agnostic(self):
        c=self.sample(vstart=7,vl=9,mask='alternating');raw=self.packet(c);self.assertTrue(m.check_isa(c,raw))
        for bit in [6,7,9]:
            bad=bytearray(raw);bad[96+512+128+bit//8]^=1<<(bit%8)
            if bit==9 and bad[96+512+128+bit//8]>>(bit%8)&1:continue
            with self.assertRaises(ValueError):m.check_isa(c,bad)
        c=self.sample(vstart=1,vl=0);raw=self.packet(c);raw[96+512+128]^=1
        with self.assertRaises(ValueError):m.check_isa(c,raw)
    def test_mask_tail_ignores_vta(self):
        c=self.sample(vl=1,ta=False);raw=self.packet(c)
        raw[96+512+128+1:96+512+128+16]=b'\xff'*15
        self.assertTrue(m.check_isa(c,raw))
    def test_all_layouts_and_encodings(self):
        for c in self.rows:
            self.assertEqual(len(m.initial(c)),32*c['vlen']//8)
            self.assertTrue(0<=c['vd']<32)
            self.assertEqual(c['vs2']%c['group_registers'],0)
            if c['form']=='vv':self.assertEqual(c['vs1']%c['group_registers'],0)
            if m.overlap(c):self.assertIn(c['vd'],[c['vs2'],c['vs1']])
            if c['form']=='vi':self.assertTrue(-16<=c['operand']<=15)
            self.assertEqual((m.instruction(c)>>26)&63,m.FUNCT6[c['mnemonic']])
if __name__=='__main__':unittest.main()
