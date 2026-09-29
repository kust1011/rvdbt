// Check actual decoder/frontend routing, separately from the native emitter oracle.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qir.h"
#include <cstdio>
#include <cstdlib>
#include <utility>
using namespace dbt;
using namespace dbt::qir;
namespace {
unsigned cases = 0;
void Check(bool ok, char const *what) {
	if (!ok) { fprintf(stderr, "FAIL case=%u %s\n", cases, what); exit(1); }
}
void Test(u32 vlen, u32 sew_log, int lm, u32 f6, u32 f3, bool masked,
	  u32 rd, u32 rs1, bool enabled, bool legal) {
	++cases;
	config::aot_use_llvm = false;
	config::rvv_verify = false;
	config::rvv_direct = enabled;
	config::rvv_qcg_typed_chunk = true;
	config::rvv_qcg_typed_chunk_force_emit = true;
	config::rvv_qcg_typed_chunk_sub = false;
	config::rvv_qcg_typed_chunk_and = false;
	config::rvv_qcg_typed_chunk_or = false;
	config::rvv_qcg_typed_chunk_xor = false;
	config::rvv_vector_run = false;
	config::vlen_bits = vlen;
	u32 vt = (sew_log << 3) | (u32(lm) & 7u);
	u32 rs2 = f6 == 23 && !masked ? 0 : 16;
	u32 words[] = {(vt << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u,
		(f6 << 26) | (u32(!masked) << 25) | (rs2 << 20) | (rs1 << 15) |
		(f3 << 12) | (rd << 7) | 0x57u};
	MemArena arena(1u << 20);
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	Region *region = CompilerGenRegionIR(&arena, job);
	u32 n = 0, finishes = 0, begins = 0, ends = 0;
	bool masklogic = f3 == 2 && f6 >= 24 && f6 <= 31;
	bool averaging = (f3 == 2 || f3 == 6) && f6 >= 8 && f6 <= 11;
	bool multiply = !masklogic && !averaging && (f3 == 2 || f3 == 6);
	bool compare = !multiply && !averaging && ((f6 >= 24 && f6 <= 31) || f6 == 17 || f6 == 19);
	bool shift = !multiply && !averaging && (f6 == 37 || (f6 >= 40 && f6 <= 43));
	bool high = multiply && (f6 == 36 || f6 == 38 || f6 == 39);
	bool fractional = f6 == 39 && (f3 == 0 || f3 == 4);
	u32 rb = vlen / 8, sew = 1u << sew_log, cb = std::min(rb,
		((shift || multiply) && sew == 1) || ((high || fractional) && sew < 8) ? 32u : 64u);
	u32 gb = lm < 0 ? rb >> -lm : rb << lm;
	u32 base = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	auto offset = [&](u32 r, u32 b) { return base + (r + b / rb) * rv32::VLEN_MAX_BYTES + b % rb; };
	for (auto &bb : region->GetBlocks()) for (auto &i : bb.ilist) {
		if (i.GetOpcode() == Op::_rvvtypedchunkbegin) ++begins;
		if (i.GetOpcode() == Op::_rvvtypedchunkend) ++ends;
		if (i.GetOpcode() == Op::_vmasklogic) {
			auto &p = static_cast<InstVMaskLogic &>(i);
			Check(masklogic && p.op == f6 - 24 && p.base == n * 64, "mask word operation");
			Check(p.rd == base + rd * 512 + n * 8 && p.rs2 == base + rs2 * 512 + n * 8 &&
				p.rs1 == base + rs1 * 512 + n * 8, "single mask registers, no LMUL stride");
			finishes += p.finish; ++n; continue;
		}
		if (i.GetOpcode() != Op::_vchunkpartialalu) continue;
		auto &p = static_cast<InstVChunkPartialAlu &>(i);
		Check(p.architectural_mask && p.masked == masked, "architectural mask");
		Check(p.sew_bytes == sew && p.chunk_bytes == cb, "width");
		Check(p.element_base == n * cb / sew, "logical lane offset");
		Check(p.rd_offs == offset(rd, compare ? 0 : n * cb) && p.rs2_offs == offset(rs2, n * cb), "state windows");
		if (f3 == 0 || f3 == 2) Check(p.src1_kind == 0 && p.rs1_offs == offset(rs1, n * cb), "vector source");
		if ((f3 == 4 || f3 == 6) && rs1) Check(p.src1_kind == 1 && p.rs1_offs == offsetof(CPUState, gpr) + 4 * rs1, "RV32 scalar source");
		if (f3 == 3 || ((f3 == 4 || f3 == 6) && !rs1)) {
			Check(p.src1_kind == 2, "literal source");
			Check(p.imm == (f3 == 3 ? (shift ? rs1 : u32(i32(rs1 << 27) >> 27)) : 0), "immediate or x0");
		}
		finishes += p.finish_instruction;
		if (p.finish_instruction) Check(n + 1 == (gb + cb - 1) / cb, "finish only last chunk");
		++n;
	}
	if (enabled && legal) {
		Check(n == (masklogic ? (gb / sew + 63) / 64 : (gb + cb - 1) / cb), "full group directly lowered");
		Check(begins == 1 && ends == 1 && finishes == 1, "one instruction frame");
	} else Check(n == 0, "disabled or illegal shape not admitted");
}
}
void TestExtension(u32 vlen, u32 s, int lm, u32 sub, u32 rd, u32 rs2, bool masked, bool legal) {
	++cases;
	config::vlen_bits = vlen;
	u32 const vt = (s << 3) | (lm & 7);
	u32 words[] = {(vt << 20) | (10u << 15) | (7u << 12) | (10u << 7) | 0x57u,
		(18u << 26) | (u32(!masked) << 25) | (rs2 << 20) | (sub << 15) | (2u << 12) | (rd << 7) | 0x57u};
	MemArena arena(1u << 20);
	CompilerJob::IpRangesSet ranges = {{0u, 8u}};
	CompilerJob job(nullptr, (uptr)words, CodeSegment(0u, 0x1000u), std::move(ranges));
	Region *region = CompilerGenRegionIR(&arena, job);
	u32 n = 0, finish = 0, ds = 1u << s, div = sub < 4 ? 8 : sub < 6 ? 4 : 2;
	u32 const rb = vlen / 8, gb = lm < 0 ? rb >> -lm : rb << lm, bytes = std::min(rb, 64u);
	u32 const vo = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
	auto off = [rb, vo](u32 r, u32 byte) { return vo + (r + byte / rb) * 512 + byte % rb; };
	for (auto &bb : region->GetBlocks()) for (auto &i : bb.ilist) if (i.GetOpcode() == Op::_vchunkextend) {
		auto &e = static_cast<InstVChunkExtend &>(i);
		Check(e.dst_sew == ds && e.src_sew == ds / div && e.bytes == bytes && e.base == n * bytes / ds, "extension widths");
		Check(e.rd == off(rd, n * bytes) && e.rs2 == off(rs2, n * bytes / div), "extension separate group strides");
		Check(e.sign == bool(sub & 1) && e.masked == masked, "extension signedness/policy");
		finish += e.finish; ++n;
	}
	Check(n == (legal ? (gb + bytes - 1) / bytes : 0), "extension legality/admission");
	Check(finish == (legal ? 1 : 0), "extension finish");
}

void TestWiden(u32 vlen,u32 s,int lm,u32 f6,bool scalar,u32 rd,u32 rs2,u32 rs1,bool legal) {
	++cases; config::vlen_bits=vlen;
	u32 const vt=(s<<3)|(lm&7);
	u32 words[]={(vt<<20)|(10u<<15)|(7u<<12)|(10u<<7)|0x57u,
		(f6<<26)|(rs2<<20)|(rs1<<15)|((scalar?6u:2u)<<12)|(rd<<7)|0x57u};
	MemArena arena(1u<<20);
	CompilerJob::IpRangesSet ranges={{0u,8u}};
	CompilerJob job(nullptr,(uptr)words,CodeSegment(0u,0x1000u),std::move(ranges));
	Region *region=CompilerGenRegionIR(&arena,job);
	u32 n=0,finish=0,ss=1u<<s,rb=vlen/8,gb=lm<0?(rb>>-lm)*2:(rb<<lm)*2,bytes=std::min(rb,64u);
	bool wide=f6>=52&&f6<=55;
	u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
	auto off=[rb,vo](u32 r,u32 byte){return vo+(r+byte/rb)*512+byte%rb;};
	for(auto &bb:region->GetBlocks()) for(auto &i:bb.ilist) if(i.GetOpcode()==Op::_vchunkwiden) {
		auto &w=static_cast<InstVChunkWiden&>(i);
		Check(w.rd==off(rd,n*bytes)&&w.rs2==off(rs2,n*bytes/(wide?1:2)),"widen windows");
		Check(w.rs1==(scalar?(u32)offsetof(CPUState,gpr)+rs1*4:off(rs1,n*bytes/2)),"widen src1");
		Check(w.sew==ss&&w.bytes==bytes&&w.base==n*bytes/(2*ss)&&w.masked,"widen lane shape");
		Check(w.op==(f6>=60?3:f6>=56?2:(f6&2)?1:0)&&w.wide2==wide,"widen operation");
		Check(w.sign2==(f6<56?bool(f6&1):(f6==58||f6==59||f6==61||f6==62)),"widen vs2 sign");
		Check(w.sign1==(f6<56?bool(f6&1):(f6==59||f6==61||f6==63)),"widen vs1 sign");
		finish+=w.finish;++n;
	}
	Check(n==(legal?(gb+bytes-1)/bytes:0),"widen admission");
	Check(finish==(legal?1:0),"widen finish");
}

void TestNarrow(u32 vlen,u32 s,int lm,u32 f6,u32 f3,u32 rd,u32 rs2,u32 rs1,bool legal) {
	++cases;config::vlen_bits=vlen;
	u32 const vt=(s<<3)|(lm&7);
	u32 words[]={(vt<<20)|(10u<<15)|(7u<<12)|(10u<<7)|0x57u,
		(f6<<26)|(rs2<<20)|(rs1<<15)|(f3<<12)|(rd<<7)|0x57u};
	MemArena arena(1u<<20);CompilerJob::IpRangesSet ranges={{0u,8u}};
	CompilerJob job(nullptr,(uptr)words,CodeSegment(0u,0x1000u),std::move(ranges));
	Region *region=CompilerGenRegionIR(&arena,job);
	u32 n=0,finish=0,ds=1u<<s,rb=vlen/8,gb=lm<0?(rb>>-lm)*2:(rb<<lm)*2,bytes=std::min(rb,64u);
	u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
	auto off=[rb,vo](u32 r,u32 byte){return vo+(r+byte/rb)*512+byte%rb;};
	u8 source=f3==0?0:(f3==4&&rs1)?1:2;
	for(auto &bb:region->GetBlocks())for(auto &i:bb.ilist)if(i.GetOpcode()==Op::_vchunknarrowshift) {
		auto &w=static_cast<InstVChunkNarrowShift&>(i);
		Check(w.rd==off(rd,n*bytes/2)&&w.rs2==off(rs2,n*bytes),"narrow state windows");
		Check(w.rs1==(source==0?off(rs1,n*bytes/2):source==1?(u32)offsetof(CPUState,gpr)+rs1*4:0),"narrow source");
		Check(w.src==source&&w.imm==(f3==3?rs1:0)&&w.arith==(f6==45),"narrow opcode/immediate");
		Check(w.sew==ds&&w.bytes==bytes&&w.base==n*bytes/(2*ds)&&w.masked,"narrow lane shape");
		finish+=w.finish;++n;
	}
	for(auto &bb:region->GetBlocks())for(auto &i:bb.ilist)if(i.GetOpcode()==Op::_vchunkpartialalu) {
		auto &w=static_cast<InstVChunkPartialAlu&>(i);
		Check(f6>=46&&w.op==(f6==46?49:50),"clip operation");
		Check(w.rd_offs==off(rd,n*bytes/2)&&w.rs2_offs==off(rs2,n*bytes),"clip independent operand windows");
		Check(w.rs1_offs==(source==0?off(rs1,n*bytes/2):source==1?(u32)offsetof(CPUState,gpr)+rs1*4:0),"clip count source");
		Check(w.src1_kind==source&&w.imm==(f3==3?rs1:0),"clip immediate/scalar");
		Check(w.sew_bytes==2*ds&&w.chunk_bytes==bytes&&w.element_base==n*bytes/(2*ds)&&w.masked,"clip shape");
		finish+=w.finish_instruction;++n;
	}
	Check(n==(legal?(gb+bytes-1)/bytes:0),"narrow admission");
	Check(finish==(legal?1:0),"narrow finish");
}

void TestMaskScan(u32 vlen,u32 s,int lm,bool first,bool masked,u32 source,u32 rd) {
	++cases; config::vlen_bits=vlen;
	u32 const vt=(s<<3)|(lm&7),rb=vlen/8,gb=lm<0?rb>>-lm:rb<<lm;
	u32 words[]={(vt<<20)|(10u<<15)|(7u<<12)|(10u<<7)|0x57u,
		(16u<<26)|(u32(!masked)<<25)|(source<<20)|((first?17u:16u)<<15)|(2u<<12)|(rd<<7)|0x57u};
	MemArena arena(1u<<20);
	CompilerJob::IpRangesSet ranges={{0u,8u}};
	CompilerJob job(nullptr,(uptr)words,CodeSegment(0u,0x1000u),std::move(ranges));
	Region *region=CompilerGenRegionIR(&arena,job);
	u32 n=0,guards=0;
	for(auto &bb:region->GetBlocks())for(auto &i:bb.ilist) {
		if(i.GetOpcode()==Op::_vmaskscalar) {
			auto &p=static_cast<InstVMaskScalar&>(i);
			Check(p.source==offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg)+source*512,"mask source single register");
			Check(p.rd==rd&&p.first==first&&p.masked==masked&&p.vlmax==gb/(1u<<s),"mask scan semantics"); ++n;
		}
		if(i.GetOpcode()==Op::_rvvtypedchunkbegin) {
			auto &p=static_cast<InstRVVTypedChunkBegin&>(i);
			Check(p.guard_kind==InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart,"mask scan disallows restart");++guards;
		}
	}
	Check(n==1&&guards==1,"mask scan direct route");
}

void TestMaskPrefix(u32 vlen,u32 s,int lm,u32 sub,bool masked,u32 source,u32 rd) {
	++cases; config::vlen_bits=vlen;
	u32 const vt=(s<<3)|(lm&7),rb=vlen/8,gb=lm<0?rb>>-lm:rb<<lm;
	u32 words[]={(vt<<20)|(10u<<15)|(7u<<12)|(10u<<7)|0x57u,
		(20u<<26)|(u32(!masked)<<25)|(source<<20)|(sub<<15)|(2u<<12)|(rd<<7)|0x57u};
	MemArena arena(1u<<20);CompilerJob::IpRangesSet ranges={{0u,8u}};
	CompilerJob job(nullptr,(uptr)words,CodeSegment(0u,0x1000u),std::move(ranges));
	Region *region=CompilerGenRegionIR(&arena,job);u32 n=0,guards=0;
	for(auto &bb:region->GetBlocks())for(auto &i:bb.ilist) {
		if(i.GetOpcode()==Op::_vmaskprefix) {
			auto &p=static_cast<InstVMaskPrefix&>(i);u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
			Check(p.source==vo+source*512&&p.rd==vo+rd*512,"prefix mask single registers");
			Check(p.kind==(sub==1?0:sub==3?1:2)&&p.masked==masked&&p.vlmax==gb/(1u<<s),"prefix semantics");++n;
		}
		if(i.GetOpcode()==Op::_vmaskiota) {
			auto &p=static_cast<InstVMaskIota&>(i);u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
			Check(sub==16&&p.rd==vo+rd*512&&p.source==vo+source*512,"iota operands");
			Check(p.regbytes==rb&&p.sew==(1u<<s)&&p.vlmax==gb/(1u<<s)&&p.masked==masked,"iota shape");++n;
		}
		if(i.GetOpcode()==Op::_rvvtypedchunkbegin) {
			auto &p=static_cast<InstRVVTypedChunkBegin&>(i);
			Check(p.guard_kind==InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart,"prefix rejects restart");++guards;
		}
	}
	bool legal=rd!=source&&(!masked||rd!=0);
	if(sub==16){u32 group=lm<=0?1:1u<<lm;legal=legal&&rd%group==0&&!(source>=rd&&source<rd+group);}
	Check(n==u32(legal)&&guards==u32(legal),"prefix legality and routing");
}

void TestCrossElement(u32 vlen,u32 s,int lm,u32 f6,u32 f3,u32 rd,u32 data,u32 other,bool vm,bool legal) {
	++cases;config::vlen_bits=vlen;
	u32 vt=(s<<3)|(lm&7),raw=(f6<<26)|(u32(vm)<<25)|(data<<20)|(other<<15)|(f3<<12)|(rd<<7)|0x57u;
	u32 words[]={(vt<<20)|(10u<<15)|(7u<<12)|(10u<<7)|0x57u,raw};
	MemArena arena(1u<<20);CompilerJob::IpRangesSet ranges={{0u,8u}};
	CompilerJob job(nullptr,(uptr)words,CodeSegment(0u,0x1000u),std::move(ranges));
	Region *region=CompilerGenRegionIR(&arena,job);u32 n=0;
	for(auto &bb:region->GetBlocks())for(auto &i:bb.ilist){
		if(i.GetOpcode()==Op::_vcompressnative){auto &c=static_cast<InstVCompress&>(i);Check(f6==23&&c.rd==rd&&c.data==data&&c.mask==other,"compress operands");++n;}
		if(i.GetOpcode()==Op::_vreducenative){auto &r=static_cast<InstVReduce&>(i);Check(r.rd==rd&&r.data==data&&r.seed==other&&r.op==(f6>=48?8+(f6&1):f6)&&r.masked==!vm,"reduction operands");++n;}
	}
	Check(n==u32(legal),"cross-element legality");
}

void TestScalarMove(u32 vlen,u32 s,int lm,bool put,u32 vr,u32 xr) {
	++cases;config::vlen_bits=vlen;
	u32 vt=(s<<3)|(lm&7);
	u32 raw=(16u<<26)|(1u<<25)|(put?xr<<15:vr<<20)|((put?6u:2u)<<12)|((put?vr:xr)<<7)|0x57u;
	u32 words[]={(vt<<20)|(10u<<15)|(7u<<12)|(10u<<7)|0x57u,raw};
	MemArena arena(1u<<20);CompilerJob::IpRangesSet ranges={{0u,8u}};
	CompilerJob job(nullptr,(uptr)words,CodeSegment(0u,0x1000u),std::move(ranges));
	Region *region=CompilerGenRegionIR(&arena,job);u32 n=0;
	for(auto &bb:region->GetBlocks())for(auto &i:bb.ilist)if(i.GetOpcode()==Op::_vscalarmove){
		auto &m=static_cast<InstVScalarMove&>(i);
		Check(m.vreg==vr&&m.greg==xr&&m.sew==(1u<<s)&&m.to_vector==put,"scalar move shape");++n;
	}
	Check(n==1,"scalar move ignores group alignment");
}

void TestIndex(u32 vlen,u32 s,int lm,bool masked,u32 rd) {
	++cases;config::vlen_bits=vlen;
	u32 vt=(s<<3)|(lm&7),rb=vlen/8,gb=lm<0?rb>>-lm:rb<<lm,bytes=std::min(rb,64u);
	u32 words[]={(vt<<20)|(10u<<15)|(7u<<12)|(10u<<7)|0x57u,
		(20u<<26)|(u32(!masked)<<25)|(17u<<15)|(2u<<12)|(rd<<7)|0x57u};
	MemArena arena(1u<<20);CompilerJob::IpRangesSet ranges={{0u,8u}};
	CompilerJob job(nullptr,(uptr)words,CodeSegment(0u,0x1000u),std::move(ranges));
	Region *region=CompilerGenRegionIR(&arena,job);u32 n=0,finish=0;
	for(auto &bb:region->GetBlocks())for(auto &i:bb.ilist)if(i.GetOpcode()==Op::_vchunkindex) {
		auto &p=static_cast<InstVChunkIndex&>(i);u32 vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
		Check(p.rd==vo+(rd+n*bytes/rb)*512+n*bytes%rb&&p.sew==(1u<<s)&&p.bytes==bytes,"vid shape");
		Check(p.base==n*bytes/(1u<<s)&&p.masked==masked,"vid lane index");finish+=p.finish;++n;
	}
	bool legal=(!masked||rd!=0)&&(lm<=0||rd%(1u<<lm)==0);
	Check(n==(legal?(gb+bytes-1)/bytes:0)&&finish==u32(legal),"vid legality/routing");
}

void TestSourceLegality(u32 f6, u32 f3, bool vm, u32 rd, u32 data, u32 seed, bool legal) {
	++cases;
	config::aot_use_llvm=false; config::rvv_verify=false; config::rvv_direct=true;
	config::rvv_qcg_typed_chunk=true; config::rvv_qcg_typed_chunk_force_emit=true;
	config::rvv_vector_run=false; config::vlen_bits=512;
	u32 const vt=(2u<<3)|1u; // e32,m2: aligned data group, independent scalar seed.
	u32 words[]={(vt<<20)|(10u<<15)|(7u<<12)|(10u<<7)|0x57u,
		(f6<<26)|(u32(vm)<<25)|(data<<20)|(seed<<15)|(f3<<12)|(rd<<7)|0x57u};
	MemArena arena(1u<<20); CompilerJob::IpRangesSet ranges={{0u,8u}};
	CompilerJob job(nullptr,(uptr)words,CodeSegment(0u,0x1000u),std::move(ranges));
	Region *region=CompilerGenRegionIR(&arena,job); u32 guards=0;
	for(auto &bb:region->GetBlocks())for(auto &i:bb.ilist)
		guards+=i.GetOpcode()==Op::_rvvtypedchunkbegin;
	Check(guards==u32(legal),"reduction/merge source legality");
}

int main() {
	for(auto encoding:{std::pair{0u,2u},std::pair{48u,0u},std::pair{3u,1u},std::pair{51u,1u}}) {
		auto [f6,f3]=encoding; bool wide=f6>=48;
		TestSourceLegality(f6,f3,false,0,8,31,true);
		TestSourceLegality(f6,f3,false,2,0,31,false);
		TestSourceLegality(f6,f3,false,2,8,0,false);
		TestSourceLegality(f6,f3,true,2,8,9,!wide);
		TestSourceLegality(f6,f3,true,0,8,31,true);
	}
	TestSourceLegality(23,5,false,8,16,0,true); // f0 is not vector v0.
	TestSourceLegality(23,5,false,8,0,1,false);
	TestSourceLegality(23,5,false,0,16,1,false);
	TestSourceLegality(23,5,true,0,0,1,true); // vfmv does not read encoded vs2.
	for(auto encoding:{std::pair{0u,0u},std::pair{37u,2u},std::pair{24u,0u},std::pair{23u,0u}}) {
		auto [f6,f3]=encoding;
		TestSourceLegality(f6,f3,false,8,16,24,true);
		TestSourceLegality(f6,f3,false,8,0,24,false);
		TestSourceLegality(f6,f3,false,8,16,0,false);
		TestSourceLegality(f6,f3+4,false,8,16,0,true); // scalar x0 is legal.
	}
	TestSourceLegality(24,0,false,0,16,24,true); // masked compare may write v0.
	TestSourceLegality(23,0,true,0,0,16,true); // vmv.v.v ignores encoded vs2.
	if(std::getenv("RVV_ROUTE_CLOSURE_ONLY")) {
		printf("PASS source_legality_cases=%u\n",cases); return 0;
	}
	// Masked forms force the generic route even when an older specialized route exists.
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u, 4096u})
	for (u32 s : {0u, 1u, 2u, 3u}) for (int lm : {-3,-2,-1,0,1,2,3}) {
		if (lm < 0 && (1u << s) > (8u >> -lm)) continue;
		for (u32 f6 : {0u,2u,3u,4u,5u,6u,7u,9u,10u,11u,23u,37u,40u,41u}) for (u32 f3 : {0u,3u,4u}) {
			if ((f6 == 2 && f3 == 3) || (f6 == 3 && f3 == 0)) continue;
			if (f6 >= 4 && f6 <= 7 && f3 == 3) continue;
			Test(vlen,s,lm,f6,f3,true,8,24,true,true);
			Test(vlen,s,lm,f6,f3,true,16,24,true,true);
			if (f3 == 4) Test(vlen,s,lm,f6,f3,true,8,0,true,true);
			if (f6 == 23) Test(vlen,s,lm,f6,f3,false,8,24,true,true);
		}
		for (u32 f6 : {32u, 33u, 34u, 35u, 36u, 37u, 38u, 39u, 41u, 43u, 45u, 47u}) {
			Test(vlen,s,lm,f6,2,true,8,24,true,true);
			Test(vlen,s,lm,f6,6,true,8,24,true,true);
			Test(vlen,s,lm,f6,6,true,8,0,true,true);
		}
		for (u32 f6 = 24; f6 <= 31; ++f6) for (u32 f3 : {0u, 3u, 4u}) {
			if (((f6 == 26 || f6 == 27) && f3 == 3) || (f6 >= 30 && f3 == 0)) continue;
			for (u32 rd : {0u, 4u, 8u, 16u, 24u}) Test(vlen,s,lm,f6,f3,true,rd,24,true,true);
		}
		for (u32 f6 = 24; f6 <= 31; ++f6) for (u32 rd : {0u, 7u, 16u, 31u})
			Test(vlen,s,lm,f6,2,false,rd,31,true,true);
		for (u32 f6 = 16; f6 <= 19; ++f6) for (u32 f3 : {0u, 3u, 4u}) {
			if (f6 >= 18 && f3 == 3) continue;
			bool const mask_result = f6 == 17 || f6 == 19;
			for (u32 rd : {0u, 8u, 16u, 24u}) {
				if (!mask_result && rd == 0) continue;
				Test(vlen,s,lm,f6,f3,true,rd,24,true,true);
				if (mask_result) Test(vlen,s,lm,f6,f3,false,rd,24,true,true);
			}
		}
		for (u32 f6 : {32u,33u,34u,35u}) for (u32 f3 : {0u,3u,4u}) {
			if (f3==3&&f6>=34) continue;
			for (u32 rd : {8u,16u,24u}) Test(vlen,s,lm,f6,f3,true,rd,24,true,true);
			if (f3==4) Test(vlen,s,lm,f6,f3,true,8,0,true,true);
		}
		for (u32 f6 : {8u,9u,10u,11u}) for (u32 f3 : {2u,6u}) {
			for (u32 rd : {8u,16u,24u}) Test(vlen,s,lm,f6,f3,true,rd,24,true,true);
			if (f3==6) Test(vlen,s,lm,f6,f3,true,8,0,true,true);
		}
		for (u32 f6 : {42u,43u}) for (u32 f3 : {0u,3u,4u}) {
			for (u32 rd : {8u,16u,24u}) Test(vlen,s,lm,f6,f3,true,rd,24,true,true);
			if (f3==4) Test(vlen,s,lm,f6,f3,true,8,0,true,true);
		}
		for (u32 f3 : {0u,4u}) {
			for (u32 rd : {8u,16u,24u}) Test(vlen,s,lm,39,f3,true,rd,24,true,true);
			if (f3==4) Test(vlen,s,lm,39,f3,true,8,0,true,true);
		}
	}
	Test(512,0,0,0,0,true,8,24,false,true);
	Test(512,0,1,0,0,true,9,24,true,false);
	Test(512,0,1,0,0,true,8,25,true,false);
	Test(512,0,0,0,0,true,0,24,true,false);
	Test(512,0,1,24,0,true,17,24,true,false);
	Test(512,0,1,24,0,true,25,24,true,false);
	for (u32 vlen : {128u,256u,512u,1024u,2048u,4096u})
	for (u32 s : {1u,2u,3u}) for (int lm : {-3,-2,-1,0,1,2,3}) for (u32 sub = 2; sub < 8; ++sub) {
		u32 const div = sub < 4 ? 8 : sub < 6 ? 4 : 2;
		int const slm = lm - (div == 8 ? 3 : div == 4 ? 2 : 1);
		bool legal = (1u << s) >= div && slm >= -3 && !(lm < 0 && (1u << s) > (8u >> -lm));
		TestExtension(vlen,s,lm,sub,8,24,true,legal);
		if (legal && slm >= 0) TestExtension(vlen,s,lm,sub,8,8 + (1u << lm) - (1u << slm),false,true);
		if (legal) TestExtension(vlen,s,lm,sub,8,8,false,false);
	}
	for(u32 vlen:{128u,256u,512u,1024u,2048u,4096u})
	for(u32 s:{0u,1u,2u,3u}) for(int lm:{-3,-2,-1,0,1,2,3})
	for(u32 f6:{48u,49u,50u,51u,52u,53u,54u,55u,56u,58u,59u,60u,61u,62u,63u})
	for(bool scalar:{false,true}) {
		if(f6==62&&!scalar)continue;
		bool legal=s<3&&lm<3&&!(lm<0&&(1u<<s)>(8u>>-lm));
		TestWiden(vlen,s,lm,f6,scalar,8,16,24,legal);
		if(legal) {
			bool wide=f6>=52&&f6<=55;
			TestWiden(vlen,s,lm,f6,scalar,8,8,24,wide);
			if(lm>=0&&!wide)TestWiden(vlen,s,lm,f6,scalar,8,8+(1u<<lm),24,f6<60);
		}
	}
	for(u32 vlen:{128u,256u,512u,1024u,2048u,4096u})
	for(u32 s:{0u,1u,2u,3u})for(int lm:{-3,-2,-1,0,1,2,3})
	for(u32 f6:{44u,45u,46u,47u})for(u32 f3:{0u,3u,4u}) {
		bool legal=s<3&&lm<3&&!(lm<0&&(1u<<s)>(8u>>-lm));
		TestNarrow(vlen,s,lm,f6,f3,8,16,24,legal);
		if(legal) {
			TestNarrow(vlen,s,lm,f6,f3,16,16,24,true);
			if(f3==0)TestNarrow(vlen,s,lm,f6,f3,8,16,16,false);
			else TestNarrow(vlen,s,lm,f6,f3,8,16,0,true);
			if(lm>=0)TestNarrow(vlen,s,lm,f6,f3,16+(1u<<lm),16,24,false);
		}
	}
	for(u32 vlen:{128u,256u,512u,1024u,2048u,4096u})
	for(u32 s:{0u,1u,2u,3u})for(int lm:{-3,-2,-1,0,1,2,3}) {
		if(lm<0&&(1u<<s)>(8u>>-lm))continue;
		config::rvv_direct=true;
		for(bool first:{false,true})for(bool masked:{false,true})
		for(u32 source:{0u,1u,31u})for(u32 rd:{0u,15u,31u})TestMaskScan(vlen,s,lm,first,masked,source,rd);
		for(u32 sub:{1u,2u,3u})for(bool masked:{false,true})
		for(u32 source:{0u,1u,31u})for(u32 rd:{0u,1u,30u})TestMaskPrefix(vlen,s,lm,sub,masked,source,rd);
		for(bool masked:{false,true})for(u32 source:{0u,1u,31u})for(u32 rd:{0u,8u,24u,31u})TestMaskPrefix(vlen,s,lm,16,masked,source,rd);
		for(bool masked:{false,true})for(u32 rd:{0u,8u,24u,31u})TestIndex(vlen,s,lm,masked,rd);
		for(bool put:{false,true})for(u32 vr:{0u,1u,31u})for(u32 xr:{0u,15u,31u})TestScalarMove(vlen,s,lm,put,vr,xr);
	}
	for(u32 s=0;s<4;++s){
		TestCrossElement(512,s,3,23,2,8,16,1,true,true);
		TestCrossElement(512,s,3,23,2,8,16,9,true,false);
		TestCrossElement(512,s,3,23,2,8,8,1,true,false);
		TestCrossElement(512,s,3,23,2,9,16,1,true,false);
		for(u32 op=0;op<8;++op)for(u32 rd:{0u,16u,31u})TestCrossElement(512,s,3,op,2,rd,16,31,false,true);
		for(u32 op:{48u,49u})TestCrossElement(512,s,3,op,0,31,16,31,true,s<3);
	}
	printf("PASS frontend_cases=%u\n", cases);
}
