#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Complement the frozen e32-first cache visits with e64-first entries.

Arithmetic words, PCs and physical inputs match the first cache declaration.
The first observed vtype differs, so this tests the actual cached entry built
with that hint, followed by e32 and e64 reuse; it does not posit a vtype cache key.
"""
import json,sys
from pathlib import Path
import sequences177 as s
import vadd as v

original_cases=s.cases;original_target=s.target;original_expectation=s.expectation
def cases(part):
    rows=original_cases('cache')
    for c in rows:
        c['id']=c['id'].replace('cache-','cache64-',1)
        c['unit']=c['unit'].replace('cache-','cache64-',1)
        c['part']='cache64';c['scenario']='cache64'
    return rows

def target(c):
    text=original_target(dict(c,scenario='cache'));tag=c['ordinal'];n=c['vlmax'];p=max(1,n//4)
    text=text.replace(f'cfg_{tag}_0:\nli t0,{n}\nvsetvli zero,t0,e32,m1,tu,mu',f'cfg_{tag}_0:\nli t0,{n//2}\nvsetvli zero,t0,e64,m1,tu,mu')
    text=text.replace(f'cfg_{tag}_1:\nli t0,{p}\nvsetvli zero,t0,e64,m1,tu,mu',f'cfg_{tag}_1:\nli t0,{p}\nvsetvli zero,t0,e32,m1,tu,mu')
    text=text.replace(f'cfg_{tag}_2:\nli t0,{p}\nvsetvli zero,t0,e32,m1,tu,mu',f'cfg_{tag}_2:\nli t0,{p}\nvsetvli zero,t0,e64,m1,tu,mu')
    return text

def expectation(c):
    if c['scenario']!='cache64':return original_expectation(c)
    b=c['vlen']//8;n=c['vlmax'];p=max(1,n//4);image=bytearray(s.initial(c))
    for sew,vl in ((64,n//2),(32,p),(64,p)):
        e=sew//8
        for name,d,a,z,masked in c['ops']:
            old=bytes(image)
            for lane in range(vl):
                x=int.from_bytes(old[a*b+lane*e:a*b+(lane+1)*e],'little')
                y=int.from_bytes(old[z*b+lane*e:z*b+(lane+1)*e],'little')
                word=(x+y if name=='vadd' else x^y)%(1<<sew)
                image[d*b+lane*e:d*b+(lane+1)*e]=word.to_bytes(e,'little')
    return bytes(image),{},[p,24,b,0,2,1,5,5,0,5,c['operand']&0xffffffff]

def install():
    s.cases=cases;s.target=target;s.expectation=expectation

if __name__=='__main__':install();s.main()
