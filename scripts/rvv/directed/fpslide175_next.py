#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Next subfamily preparation only; not dispatched or credited by Task174."""
from fractions import Fraction
FORMS=('vfslide1up.vf','vfslide1down.vf')
def scalar_bits(sew,flen64_word):
 if sew==64:return flen64_word
 return flen64_word&0xffffffff if flen64_word>>32==0xffffffff else 0x7fc00000

def element(form,sew,i,vl,source,scalar):
 """Bit movement, no arithmetic, no NaN quieting and no FP exceptions."""
 assert 0<=i<vl and form in FORMS
 if form=='vfslide1up.vf':return scalar_bits(sew,scalar) if i==0 else source[i-1]
 return scalar_bits(sew,scalar) if i==vl-1 else source[i+1]

def profiles():
 return [dict(form=form,vlen=w,sew=sew,lmul_exp=exp,vlmax=int(Fraction(w,sew)*Fraction(2)**exp),source_destination_overlap='up forbidden; down allowed',nonzero_vstart='restartable; prestart preserved',scalar='FLEN64 with FP32 NaN unboxing',flags='unchanged, including signaling NaN movement') for form in FORMS for w in (128,256,512,1024,2048,4096) for sew in (32,64) for exp in range(-1 if sew==32 else 0,4)]
if __name__=='__main__':
 import json,sys
 assert element(FORMS[0],32,0,1,[0x7f800001],0xffffffff7f800001)==0x7f800001
 assert element(FORMS[1],32,0,1,[0],0x123456783f800000)==0x7fc00000
 assert element(FORMS[1],64,0,2,[1,0x7ff0000000000001],0)==0x7ff0000000000001
 print(json.dumps(dict(status='PREPARATION_ONLY',ordinary_credit=0,profiles=profiles(),planned_cases=['VL0/1/partial and 512-bit chunk edges','masks and vstart before/at/after scalar insertion lane','masked-off source bits copied without floating arithmetic','signed zeros/infinities/subnormals/qNaN/sNaN raw payloads','well/malformed FP32 boxes, sticky flags','up disjoint groups; down exact alias; aligned high-end groups']),indent=2))
