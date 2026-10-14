#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import struct, unittest
import inexact190 as q
import fp157 as fp
import fpreduce174 as f
import vadd as v

def packet(c,result=None):
    before=f.initial(c);after=bytearray(before);r=q.sequential(c,before)[0] if result is None else result
    if c['vl']:
        off=c['vd']*(c['vlen']//8);after[off:off+c['dst_eew']//8]=r[0].to_bytes(c['dst_eew']//8,'little')
    post=f.csr_expected(c);post[7:]=[r[1],c['frm'],c['frm']<<5|r[1]]
    return struct.pack('<2I',0x145add,c['ordinal'])+struct.pack('<11I',*f.csr_expected(c),c['operand'])+struct.pack('<11I',*post,c['operand'])+before+after+struct.pack('<2Q',f.scalar(c),f.scalar(c))

class Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.rows=q.cases();cls.c=cls.rows[0]
    def reject(self,c,raw,**kw):
        with self.assertRaises(ValueError):q.check(c,raw,**kw)
    def test_all_synthetic_states(self):
        for c in self.rows:q.check(c,packet(c))
    def test_analytical_steps(self):
        result,steps=q.sequential(self.c,f.initial(self.c))
        self.assertEqual(result,(0,1))
        self.assertEqual([(s['rounded'],s['add_flags']) for s in steps],[(0x4b800000,0),(0x4b800000,1),(0,0)])
        self.assertEqual(steps[1]['exact_sum'],'16777217')
        # Other association produces 1 exactly and is legal.
        self.assertIn((0x3f800000,0),q.witnesses(self.c,f.initial(self.c)))
    def test_legal_alternative_is_not_selected(self):
        raw=packet(self.c,(0x3f800000,0));self.reject(self.c,raw)
        q.check(self.c,raw,allowed=lambda c,b:q.witnesses(c,b))
    def test_bad_destination(self):
        raw=bytearray(packet(self.c));raw[96+32*16+8*16]^=1;self.reject(self.c,raw)
    def test_wrong_flags_coherent_fcsr(self):
        raw=bytearray(packet(self.c));struct.pack_into('<I',raw,52+7*4,0);struct.pack_into('<I',raw,52+9*4,0);self.reject(self.c,raw)
    def test_wrong_frm_coherent_fcsr(self):
        raw=bytearray(packet(self.c));struct.pack_into('<I',raw,52+8*4,1);struct.pack_into('<I',raw,52+9*4,33);self.reject(self.c,raw)
    def test_non_destination_register(self):
        raw=bytearray(packet(self.c));raw[96+32*16+15*16]^=1;self.reject(self.c,raw)
    def test_tail_corruption(self):
        raw=bytearray(packet(self.c));raw[96+32*16+8*16+4]^=1;self.reject(self.c,raw)
    def test_prestate_corruption(self):
        raw=bytearray(packet(self.c));raw[96+16*16]^=1;self.reject(self.c,raw)
    def test_marker_truncation_extra(self):
        raw=packet(self.c)
        for x in [raw[:-1],raw+b'x',b'\0'*8+raw[8:]]:self.reject(self.c,x)
    def test_scalar_fp(self):
        raw=bytearray(packet(self.c));raw[-1]^=1;self.reject(self.c,raw)
    def test_zero_length_preservation(self):
        c=next(c for c in self.rows if c['tag']=='zero-length');raw=bytearray(packet(c));raw[96+32*16+8*16]^=1;self.reject(c,raw)
    def test_masked_poison_suppression(self):
        c=next(c for c in self.rows if c['tag']=='mask-two-active');r,steps=q.sequential(c,f.initial(c))
        self.assertEqual(len(steps),2);self.assertEqual([s['promotion_flags']|s['add_flags'] for s in steps],[0,1])
        self.assertEqual(r[1],17)
    def test_sticky_loss(self):
        c=next(c for c in self.rows if c['tag']=='sticky-all');r=q.sequential(c,f.initial(c))[0];self.reject(c,packet(c,(r[0],1)))
    def test_exit_timeout(self):
        self.reject(self.c,packet(self.c),rc=1);self.reject(self.c,packet(self.c),timeout=True)
    def test_no_new_underflow(self):
        for c in self.rows:
            for s in q.sequential(c,f.initial(c))[1]:self.assertFalse(s['add_flags']&2)
    def test_expected_overflow(self):
        for bits in (32,64):
            k=fp.constants(bits)
            for rm in range(5):self.assertEqual(fp.arithmetic(bits,'vfadd',k['maxfinite'],k['maxfinite'],rm)[1],5)
        c=next(c for c in self.rows if c['mnemonic']=='vfwredusum.vs' and c['tag']=='overflow-positive' and c['frm']==3)
        self.assertEqual(q.sequential(c,f.initial(c))[0][1],5)

if __name__=='__main__':unittest.main()
