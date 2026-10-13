"""RVV 1.0 unary FP: rational sqrt intervals and specification estimate tables."""
from pathlib import Path
from fractions import Fraction
from functools import lru_cache
from math import isqrt
import re,json
import fp157 as fp

FORMS=('vfsqrt','vfrec7','vfrsqrt7')
SRC=Path(__file__).resolve().parent.parent/'source'
def table(name):
    rows=[(int(a),int(b)) for a,b in re.findall(r'^\|\s*(\d+)\s*\|\s*(\d+)\s*$',(SRC/(name+'.adoc')).read_text(),re.M)]
    assert len(rows)==128
    assert [a for a,b in rows]==list(range(128)) if name=='vfrec7' else [a for a,b in rows]==list(range(64))*2
    return tuple(b for a,b in rows)
REC=table('vfrec7');RSQ=table('vfrsqrt7')
QEMU=json.loads(Path(__file__).with_name('qemu_sqrt176.json').read_text())

@lru_cache(maxsize=65536)
def result(bits,op,a,rm):
    s,kind,x,snan=fp.unpack(bits,a);k=fp.constants(bits);f,e,bias=fp.layout(bits);sign=s<<(bits-1)
    if kind=='nan':return k['canonical'],16 if snan else 0
    if op!='vfrec7' and s and (kind=='inf' or x):return k['canonical'],16
    if kind=='inf':return (a if op=='vfsqrt' else sign),0
    if not x:return (a,0) if op=='vfsqrt' else (sign|k['inf'],8)
    if op=='vfsqrt':
        # Determine a precision interval [q*quantum,(q+1)*quantum].
        # Squaring endpoints and midpoint is exact over rational integers.
        ex=x.numerator.bit_length()-x.denominator.bit_length()
        if x<Fraction(2)**ex:ex-=1
        out_ex=ex//2;quantum=Fraction(2)**(out_ex-f);square=x/(quantum*quantum)
        q=isqrt(square.numerator//square.denominator)
        assert q*q<=square<(q+1)*(q+1)
        exact=q*q==square
        mid=(2*q+1)**2*square.denominator
        cmp=4*square.numerator-mid
        inc=not exact and (rm==3 or rm in (0,4) and (cmp>0 or cmp==0 and (rm==4 or q&1)))
        q+=int(inc)
        if q==1<<(f+1):q>>=1;out_ex+=1
        assert 1<=out_ex+bias<2*bias+1
        return ((out_ex+bias)<<f)|(q-(1<<f)),int(not exact)
    ex=(a>>f)&((1<<e)-1);sig=a&((1<<f)-1)
    if ex==0:
        ex=sig.bit_length()-f
        sig=(sig<<(1-ex))&((1<<f)-1)
    if op=='vfrsqrt7':
        idx=(ex&1)*64+(sig>>(f-6));out_ex=(3*bias-1-ex)//2
        return (out_ex<<f)|(RSQ[idx]<<(f-7)),0
    out_ex=2*bias-1-ex
    if out_ex>2*bias:
        inf=rm in (0,4) or rm==2 and s or rm==3 and not s
        return sign|(k['inf'] if inf else k['maxfinite']),5
    out_sig=REC[sig>>(f-7)]<<(f-7)
    if out_ex<=0:out_sig=((1<<f)|out_sig)>>(1-out_ex);out_ex=0
    return sign|(out_ex<<f)|out_sig,0

def target(c):return f'{c["mnemonic"]}.v v{c["vd"]},v{c["vs2"]}'+(',v0.t' if c['mask']!='none' else '')
def instruction(c):return 19<<26|int(c['mask']=='none')<<25|c['vs2']<<20|{'vfsqrt':0,'vfrsqrt7':4,'vfrec7':5}[c['mnemonic']]<<15|1<<12|c['vd']<<7|0x57
def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='unary-baseline')));b=c['vlen']//8;e=c['sew']//8;k=fp.constants(c['sew'])
    words=c.get('fp_words',[c.get('fp_a',k['two']),k['snan'],k['qnan'],0,k['inf'],k['minsub'],k['maxfinite'],k['negzero']])
    for i in range(c['group_registers']*b//e):
        word=words[i%len(words)]
        if 'exception_lane' in c:word=c['fp_a'] if i==c['exception_lane'] else k['one']
        off=c['vs2']*b+i*e;raw[off:off+e]=word.to_bytes(e,'little')
    raw[:b]=(sum(1<<i for i in range(c['vlmax']) if c['mask'] in ('none','all') or c['mask']=='alternating' and i%2==0 or c['mask']=='odd' and i%2==1 or c['mask']=='single-on' and i==min(8,c['vlmax']-1) or c['mask']=='single-off' and i!=min(8,c['vlmax']-1))).to_bytes(b,'little')
    return bytes(raw)
def lane(c,before,i):
    b=c['vlen']//8;e=c['sew']//8;off=c['vs2']*b+i*e
    return result(c['sew'],c['mnemonic'],int.from_bytes(before[off:off+e],'little'),c['frm'])
def legal(c):
    n=c['group_registers'];assert c['sew']<=64*2**c['lmul_exp'] and c['vd']%n==c['vs2']%n==0 and c['vd']+n<=32 and c['vs2']+n<=32
    assert c['mask']=='none' or c['vd']!=0
    return True

def vectors(bits,op):
    f,e,bias=fp.layout(bits);k=fp.constants(bits);sgn=1<<(bits-1);out=[]
    def add(label,word):out.append((label,word))
    for name in ('zero','negzero','inf','neginf','snan','qnan','canonical','minsub','maxsub','minnormal','maxfinite','one','two','three','nextone','negone'):
        add('special-'+name,k[name])
    for name in ('snan','qnan','minsub','maxsub','minnormal','maxfinite'):add('negative-'+name,k[name]|sgn)
    # All encoded exponent boundaries, and every subnormal normalization depth.
    for ex in (1,2,bias-1,bias,bias+1,2*bias-1,2*bias):
        for frac in (0,1,(1<<f)-1):
            for s in (0,sgn):add('exponent-'+str(ex),s|(ex<<f)|frac)
    for bit in range(f):
        for delta in (-1,0,1):
            for s in (0,sgn):
                w=(1<<bit)+delta
                if w: add('normalize-depth-'+str(f-1-bit),s|w)
    if op=='vfsqrt':
        # Exact squares and inputs bracketing squares of output midpoints.
        for ex in (-bias//2,-2,-1,0,1,2,bias//2):
            for n in (1<<f,(1<<f)+1,(1<<f)+(1<<(f-1)),(1<<(f+1))-1):
                y=Fraction(n)*Fraction(2)**(ex-f)
                for label,x in (('exact-square',y*y),('midpoint-square',(y+Fraction(2)**(ex-f-1))**2)):
                    for rm in (1,3):
                        w,fl=fp.rounded(bits,x,rm)
                        if 0<w<k['inf']:add(label,w)
        return out
    # Every bucket at both ends, normalized exponent parity, reciprocal sign.
    width=7 if op=='vfrec7' else 6
    for parity in (0,1):
        ex=bias+(parity^(bias&1))
        for idx in range(1<<width):
            for low in (0,(1<<(f-width))-1):
                for s in ((0,sgn) if op=='vfrec7' else (0,)):
                    add(f'lookup-normal-p{parity}-b{idx}',s|(ex<<f)|(idx<<(f-width))|low)
                # Two subnormal depths produce both normalized exponent parities.
                for depth in (0,1):
                    sig=(1<<(f-1-depth))|(((idx<<(f-width))|low)>>(1+depth))
                    add(f'lookup-subnormal-p{depth}-b{idx}',sig)
    return out

def cases():
    import vadd as v
    rows=[]
    for w in (128,256,512,1024,2048,4096):
      for bits in (32,64):
       for lm,exp in v.LMUL:
        if bits>64*2**exp:continue
        n=int(w/bits*2**exp);nr=max(1,2**exp)
        for op in FORMS:
         for rm in range(5):
          prefix=f'{op}-v-w{w}-e{bits}-{lm}-'
          base=dict(family='fpunary176',mnemonic=op,form='v',vlen=w,sew=bits,lmul=lm,lmul_exp=exp,emul=lm,vlmax=n,vl=n,vstart=0,mask='none',ta=False,ma=False,vd=8,vs2=16,vs1=24,operand=0x80000001,group_registers=nr,seed=176,frm=rm,fflags_initial=0)
          def add(tag,**kw):
            c=dict(base,tag=tag,**kw);c['id']=prefix+f'rm{rm}-'+tag;c['unit']=prefix+('start' if c['vstart'] else 'zero');legal(c);rows.append(c)
          vs=vectors(bits,op)
          for off in range(0,len(vs),n):
            chunk=vs[off:off+n];add('semantic-'+str(off),vl=len(chunk),fp_words=[b for a,b in chunk],semantic_labels=[a for a,b in chunk])
          for vl in sorted({0,1,n,n-1,max(1,n//2)}|{x for x in (7,8,9,15,16,17) if x<=n}):add('length'+str(vl),vl=vl)
          for mask in ('all','off','alternating','odd','single-on','single-off'):add('mask-'+mask,mask=mask)
          for ta,ma in ((False,True),(True,False),(True,True)):add('policy'+str(int(ta))+str(int(ma)),vl=n-1,mask='alternating',ta=ta,ma=ma)
          add('overlap',vs2=8);add('end-group',vd=32-nr,vs1=4)
          for start in sorted({1,n-1}|{x for x in (7,8,9,15,16,17) if 0<x<n}):
            if start<n:add('start'+str(start),vstart=start,mask='alternating',ta=True,ma=True)
          for tag,vl,start in (('start-equal',max(1,n//2),max(1,n//2)),('start-above',0 if n==2 else 1,n-1),('start-zero-vl',0,1)):
            if start<n:add(tag,vl=vl,vstart=start,fflags_initial=9)
          k=fp.constants(bits)
          for name in ('snan','negone','zero','minsub','two'):
            add('active-'+name,vl=1,fp_words=[k[name]])
            add('sticky-'+name,vl=1,fp_words=[k[name]],fflags_initial=9)
            add('suppress-'+name,vl=1,mask='off',fp_words=[k[name]])
            add('tail-'+name,vl=1,fp_a=k[name],exception_lane=1)
            add('prestart-'+name,vstart=1,fp_a=k[name],exception_lane=0)
            add('masked-'+name,vl=min(2,n),mask='alternating',fp_a=k[name],exception_lane=1)
          if op=='vfsqrt':
            for name,mask in (('partial','none'),('even','alternating'),('odd','odd')):add('qemu-'+name,vl=n-1 if mask=='none' else n,mask=mask,fp_words=QEMU[str(bits)])
    assert len(rows)==len({c['id'] for c in rows})
    return rows
