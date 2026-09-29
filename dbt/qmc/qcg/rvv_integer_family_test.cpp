// Execute the production chunk emitter against a byte-addressed independent oracle.
// The test checks every vector-state byte, including padding and non-destination registers.
#include "dbt/arena.h"
#include "dbt/config.h"
#include "dbt/guest/rv32_cpu.h"
#include "dbt/qmc/compile.h"
#include "dbt/qmc/qcg/arch_traits.h"
#include "dbt/qmc/qcg/qcg.h"
#include "dbt/qmc/qir_builder.h"
#include <cstdio>
#include <cstring>
#include <sys/mman.h>

using namespace dbt;
using namespace dbt::qir;
namespace {
StateReg regs[] = {{(u16)offsetof(CPUState, gpr), VType::I32, "x0"}};
StateInfo state_info{regs, 1};
struct Runtime : CompilerRuntime {
	void *mem = nullptr; size_t size = 0;
	bool relocatable = false;
	~Runtime() { if (mem) munmap(mem, size); }
	void *AllocateCode(size_t n, uint) override {
		size = (n + 64 + 4095) & ~size_t(4095);
		mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mem == MAP_FAILED) Panic("integer test mmap");
		return mem;
	}
	bool AllowsRelocation() const override { return relocatable; }
	void *AnnounceRegion(u32, std::span<u8> const &, u32) override { return nullptr; }
};
extern "C" __attribute__((noinline, naked)) void IntegerEnter(void *, void *);
extern "C" __attribute__((noinline, naked)) void IntegerEnter(void *, void *) {
	asm("pushq %rbp\n\tpushq %rbx\n\tpushq %r12\n\tpushq %r13\n\tpushq %r14\n\tpushq %r15\n\t"
	    "movq %rdi,%r13\n\tmovq %rsi,%rdx\n\t");
	asm("sub $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("callq *%rdx\n\t");
	asm("add $%c0,%%rsp\n\t" : : "i"(qcg::ArchTraits::spillframe_size + 8));
	asm("popq %r15\n\tpopq %r14\n\tpopq %r13\n\tpopq %r12\n\tpopq %rbx\n\tpopq %rbp\n\tretq\n\t");
}
u64 Load(u8 const *p, u32 n) { u64 v = 0; memcpy(&v, p, n); return v; }
u64 Calc(unsigned op, u64 a, u64 b, u64 d, u32 bytes, bool carry = false, bool *saturated = nullptr, u32 rm = 2) {
	u64 const mask = bytes == 8 ? ~u64(0) : (u64(1) << (bytes * 8)) - 1;
	a &= mask; b &= mask;
	u64 const sign = u64(1) << (bytes * 8 - 1);
	bool const signed_less = (a ^ sign) < (b ^ sign);
	switch (op) {
	case 0: return a + b; case 1: return a - b;
	case 2: return a * b;
	case 3: return a & b; case 4: return a | b;
	case 5: return a ^ b; case 7: return b - a;
	case 6: case 15: return b;
	case 8: return a < b ? a : b; case 9: return signed_less ? a : b;
	case 10: return a > b ? a : b; case 11: return signed_less ? b : a;
	case 12: return a << (b & (bytes * 8 - 1));
	case 13: return a >> (b & (bytes * 8 - 1));
	case 14: {
		u32 n = b & (bytes * 8 - 1);
		return (a >> n) | ((a & sign) && n ? mask ^ (mask >> n) : 0);
	}
	case 16: return d + a * b;
	case 17: return d - a * b;
	case 18: return a + d * b;
	case 19: return a - d * b;
	case 20: return (u64)(((unsigned __int128)a * b) >> (bytes * 8));
	case 21: case 22: {
		__int128 x = a, y = b;
		if (a & sign) x -= (__int128)1 << (bytes * 8);
		if (op == 21 && (b & sign)) y -= (__int128)1 << (bytes * 8);
		return (u64)((unsigned __int128)(x * y) >> (bytes * 8));
	}
	case 23: return b ? a / b : mask;
	case 25: return b ? a % b : a;
	case 24: case 26: {
		__int128 x = a, y = b;
		if (a & sign) x -= (__int128)1 << (bytes * 8);
		if (b & sign) y -= (__int128)1 << (bytes * 8);
		return !b ? (op == 24 ? mask : a) : (u64)(op == 24 ? x / y : x % y);
	}
	case 27: return a == b;
	case 28: return a != b;
	case 29: return a < b;
	case 30: return signed_less;
	case 31: return a <= b;
	case 32: return signed_less || a == b;
	case 33: return a > b;
	case 34: return !signed_less && a != b;
	case 35: return a + b + carry;
	case 36: return a - b - carry;
	case 37: return (((unsigned __int128)a + b + carry) >> (bytes * 8)) != 0;
	case 38: return (unsigned __int128)a < (unsigned __int128)b + carry;
	case 39: case 40: case 41: case 42: {
		bool const sign_op = op == 40 || op == 42;
		__int128 x=a,y=b;
		if(sign_op) {
			if(a&sign)x-=(__int128)1<<(bytes*8);
			if(b&sign)y-=(__int128)1<<(bytes*8);
		}
		__int128 z=op>=41?x-y:x+y;
		__int128 const lo=sign_op?-((__int128)1<<(bytes*8-1)):0;
		__int128 const hi=sign_op?((__int128)1<<(bytes*8-1))-1:(__int128)mask;
		if(z<lo||z>hi) { if(saturated)*saturated=true; z=z<lo?lo:hi; }
		return (u64)z;
	}
	case 43: case 44: case 45: case 46: {
		__int128 x = a, y = b;
		if (op == 44 || op == 46) {
			if (a & sign) x -= (__int128)1 << (bytes * 8);
			if (b & sign) y -= (__int128)1 << (bytes * 8);
		}
		__int128 z = op >= 45 ? x - y : x + y;
		// Floor division before rounding, expressed independently from SIMD bit logic.
		__int128 q = z / 2;
		if (z < 0 && z % 2) --q;
		bool odd = z % 2 != 0;
		bool inc = odd && (rm == 0 || (rm == 1 && (q & 1)) || (rm == 3 && !(q & 1)));
		return (u64)(q + inc);
	}
	case 47: case 48: {
		u32 n = b & (bytes * 8 - 1);
		if (!n) return a;
		__int128 x = a;
		if (op == 48 && (a & sign)) x -= (__int128)1 << (bytes * 8);
		__int128 den = (__int128)1 << n, q = x / den;
		if (x < 0 && x % den) --q;
		__int128 rem = x - q * den;
		bool inc = rm == 0 ? rem >= den / 2 : rm == 1 ?
			(rem > den / 2 || (rem == den / 2 && (q & 1))) : rm == 3 && rem && !(q & 1);
		return (u64)(q + inc);
	}
	case 51: {
		__int128 x=a,y=b;
		if(a&sign)x-=(__int128)1<<(bytes*8);
		if(b&sign)y-=(__int128)1<<(bytes*8);
		__int128 p=x*y,den=(__int128)1<<(bytes*8-1),q=p/den;
		if(p<0&&p%den)--q;
		__int128 rem=p-q*den;
		q+=rm==0?rem>=den/2:rm==1?(rem>den/2||(rem==den/2&&(q&1))):rm==3&&rem&&!(q&1);
		if(q>=den){q=den-1;if(saturated)*saturated=true;}
		return (u64)q;
	}
	default: Panic("bad test operation");
	}
}
u64 Clip(u64 a, u32 n, u32 ds, bool sign, u32 rm, bool &saturated) {
	u32 bits=ds*16;
	__int128 x=a;
	if(sign&&(a&(u64(1)<<(bits-1))))x-=(__int128)1<<bits;
	__int128 den=(__int128)1<<n,q=x/den;
	if(x<0&&x%den)--q;
	__int128 rem=x-q*den;
	if(n)q+=rm==0?rem>=den/2:rm==1?(rem>den/2||(rem==den/2&&(q&1))):rm==3&&rem&&!(q&1);
	__int128 lo=sign?-((__int128)1<<(ds*8-1)):0;
	__int128 hi=((__int128)1<<(sign?ds*8-1:ds*8))-1;
	if(q<lo||q>hi){saturated=true;q=q<lo?lo:hi;}
	return (u64)q;
}
}

int main(int argc, char **argv) {
	bool const compare_only = argc == 2 && strcmp(argv[1], "--execute-compare") == 0;
	bool const scan_only=argc==2 && strcmp(argv[1],"--execute-scan")==0;
	bool const mask_only = argc == 2 && (strcmp(argv[1], "--mask-only") == 0 || strcmp(argv[1], "--execute-mask") == 0);
	bool const execute = compare_only || scan_only || (argc == 2 && (strcmp(argv[1], "--execute") == 0 || strcmp(argv[1], "--execute-mask") == 0));
	if (execute && (!__builtin_cpu_supports("avx512bw") || !__builtin_cpu_supports("avx512vl") || !__builtin_cpu_supports("avx512dq") ||
			!__builtin_cpu_supports("bmi2"))) {
		fprintf(stderr, "AVX512F/BW/VL and BMI2 required\n"); return 2;
	}
	config::not_freq = true;
	config::rvv_qcg_hit_counter = false;
	qcg::ArchTraits::init();
	unsigned kernels = 0, cases = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u, 4096u})
	for (u32 sew : {1u, 2u, 4u, 8u})
	for (int lm : {-3, -2, -1, 0, 1, 2, 3}) {
		u32 const rb = vlen / 8, gb = lm < 0 ? rb >> -lm : rb << lm;
		if (lm < 0 && sew > (8u >> -lm)) continue;
		u32 const vlmax = gb / sew;
		u32 const sewfield = sew == 1 ? 0 : sew == 2 ? 1 : sew == 4 ? 2 : 3;
		u32 const vt = (sewfield << 3) | (lm & 7); // tu,mu; agnostic policies may retain bytes too
		config::vlen_bits = vlen;
		for (unsigned op = 0; !mask_only && !scan_only && op <= 51; ++op)
		for (u32 src : {0u, 1u, 2u})
		for (bool masked : {false, true})
		for (u32 rd : {0u, 4u, 8u, 16u, 24u}) {
			if (op == 49 || op == 50) continue; // Separate mixed-width clip fixture below.
			bool const compare = (op >= 27 && op <= 34) || op == 37 || op == 38;
			if (compare_only && !compare) continue;
			if (!compare && (rd == 0 || rd == 4)) continue;
			u32 const bytes = std::min(rb, (sew == 1 && (op == 2 || (op >= 16 && op <= 26) || (op >= 12 && op <= 14) || op >= 47)) ||
				(sew < 8 && ((op >= 20 && op <= 22) || op == 51)) ? 32u : 64u);
			u32 const chunks = (gb + bytes - 1) / bytes;
			MemArena arena(1u << 20);
			auto *region = arena.New<Region>(&arena, &state_info);
			Builder b(region->CreateBlock());
			u32 const vo = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
			auto off = [rb](u32 reg, u32 byte) { return (reg + byte / rb) * rv32::VLEN_MAX_BYTES + byte % rb; };
			// This fixture exercises only the emitted body, with no live allocated values.
			// Guest differential tests separately exercise translation and runtime guards.
			for (u32 c = 0; c < chunks; ++c) {
				u32 const byte = c * bytes;
				u32 const s1 = src == 0 ? vo + off(24, byte) : src == 1 ? offsetof(CPUState, gpr) + 44 : 0;
				b.Create_vchunkpartialalu((u8)op, (u8)sew, (u8)c, (u16)bytes,
					vo + off(rd, compare ? 0 : byte), vo + off(16, byte), s1, (u8)src, (u32)-7,
					true, masked, byte / sew, c + 1 == chunks);
			}
			Runtime rt;
			auto code = qcg::GenerateCode(&rt, nullptr, region, 0);
			code.data()[code.size()] = 0xc3; // leaf body, no external-call address table
			++kernels;
			if (!execute) continue;
			for (u32 vl : {0u, 1u, vlmax / 2u, vlmax - 1u, vlmax})
			for (u32 start : {0u, 1u, vlmax / 2u, vlmax})
			for (u32 rm = 0; rm < (op >= 43 ? 4u : 1u); ++rm) {
				CPUState got(nullptr);
				got.vec.vtype = vt; got.vec.vl = vl; got.vec.vstart = start; got.vec.vlenb = rb;
				got.vec.vxsat=start&1; got.vec.vxrm=rm;
				bool expected_sat=got.vec.vxsat;
				got.gpr[11] = 0x80000001u;
				auto *p = (u8 *)got.vec.vreg.data();
				constexpr size_t total = sizeof(got.vec.vreg);
				u8 before[total], expected[total];
				for (size_t z = 0; z < total; ++z) p[z] = (u8)((z * 73 + z / 11 + 0xa5) & 255);
				if (op >= 20) {
					u64 const sign = u64(1) << (sew * 8 - 1), mask = sew == 8 ? ~u64(0) : (sign * 2 - 1);
					u64 const a[] = {sign, sign, 0, mask, 1, sign - 1, mask, sign + 1};
					u64 b[] = {mask, 0, 0, 2, sign, mask, mask, 1};
					if (op == 51) b[0] = sign; // MIN*MIN must saturate, even at SEW=64.
					for (u32 e = 0; e < vlmax; ++e) {
						memcpy(p + off(16, e * sew), &a[e % 8], sew);
						memcpy(p + off(24, e * sew), &b[e % 8], sew);
					}
				}
				memcpy(before, p, total); memcpy(expected, p, total);
				for (u32 e = start; e < vl; ++e) {
					bool const selected = before[e / 8] & (1u << (e % 8));
					if (masked && op != 15 && !(op >= 35 && op <= 38) && !selected) continue;
					u64 const a = Load(before + off(16, e * sew), sew);
					u64 const rhs = src == 0 ? Load(before + off(24, e * sew), sew) :
						src == 1 ? (u64)(i64)(i32)0x80000001u : (u64)(i64)-7;
					u64 value = Calc(op, a, rhs, Load(before + off(rd, e * sew), sew), sew, masked && selected, &expected_sat, rm);
					if (op == 15 && !selected) value = a;
					if (compare) {
						u32 const pos = off(rd, 0) + e / 8, bit = 1u << (e % 8);
						expected[pos] = (expected[pos] & ~bit) | (value ? bit : 0);
					} else memcpy(expected + off(rd, e * sew), &value, sew);
				}
				IntegerEnter(&got, code.data());
				++cases;
				if (memcmp(expected, p, total) || got.vec.vstart != 0 || got.vec.vl != vl ||
					got.vec.vtype != vt || got.gpr[11] != 0x80000001u || got.vec.vxsat != expected_sat || got.vec.vxrm != rm) {
					size_t bad = 0; while (bad < total && expected[bad] == p[bad]) ++bad;
					fprintf(stderr, "FAIL vlen=%u sew=%u lm=%d op=%u src=%u mask=%d rd=%u vl=%u start=%u rm=%u byte=%zu\n",
						vlen, sew, lm, op, src, masked, rd, vl, start, rm, bad); return 1;
				}
			}
		}
	}
	if (compare_only) {
		printf("PASS mask-result publication: %u kernels, %u state comparisons\n", kernels, cases);
		return 0;
	}
	for (u32 vlmax : {2u, 4u, 8u, 16u, 32u, 64u, 128u, 256u, 512u, 1024u, 2048u, 4096u})
	for (u32 op = 0; !scan_only && op < 8; ++op)
	for (u32 rd : {0u, 1u, 7u, 31u}) {
		MemArena arena(1u << 20);
		auto *region = arena.New<Region>(&arena, &state_info);
		Builder b(region->CreateBlock());
		u32 const vo = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
		u32 const words = (vlmax + 63) / 64;
		for (u32 c = 0; c < words; ++c)
			b.Create_vmasklogic((u8)op, vo + rd * 512 + c * 8, vo + 512 + c * 8,
				vo + 7 * 512 + c * 8, c * 64, c + 1 == words);
		Runtime rt;
		auto code = qcg::GenerateCode(&rt, nullptr, region, 0);
		code.data()[code.size()] = 0xc3;
		++kernels;
		if (!execute) continue;
		for (u32 vl : {0u, 1u, vlmax / 2, vlmax - 1, vlmax})
		for (u32 start : {0u, 1u, vlmax / 2, vlmax}) {
			CPUState got(nullptr);
			got.vec.vl = vl; got.vec.vstart = start;
			auto *p = (u8 *)got.vec.vreg.data();
			constexpr size_t total = sizeof(got.vec.vreg);
			u8 before[total], expected[total];
			for (size_t z = 0; z < total; ++z) p[z] = (u8)((z * 73 + z / 11 + 0xa5) & 255);
			memcpy(before, p, total); memcpy(expected, p, total);
			for (u32 e = start; e < vl; ++e) {
				bool x = before[512 + e / 8] & (1u << (e % 8));
				bool y = before[7 * 512 + e / 8] & (1u << (e % 8));
				bool value = op == 0 ? x && !y : op == 1 ? x && y : op == 2 ? x || y :
					op == 3 ? x != y : op == 4 ? x || !y : op == 5 ? !(x && y) :
					op == 6 ? !(x || y) : x == y;
				u32 off = rd * 512 + e / 8, bit = 1u << (e % 8);
				expected[off] = (expected[off] & ~bit) | (value ? bit : 0);
			}
			IntegerEnter(&got, code.data()); ++cases;
			if (memcmp(expected, p, total) || got.vec.vstart || got.vec.vl != vl) {
				fprintf(stderr, "FAIL masklogic op=%u rd=%u vlmax=%u vl=%u start=%u\n", op, rd, vlmax, vl, start);
				return 1;
			}
		}
	}
	printf("PASS kernels=%u executed_cases=%u execute=%d\n", kernels, cases, execute);
	if (mask_only) return 0;
	unsigned move_kernels=0,move_cases=0;
	for(u32 sew:{1u,2u,4u,8u})for(bool put:{false,true})for(u32 vr:{0u,1u,31u})for(u32 xr:{0u,15u,31u}){
		MemArena arena(1u<<20);StateInfo info{nullptr,0};auto *region=arena.New<Region>(&arena,&info);Builder b(region->CreateBlock());
		auto stub=put?RuntimeStubId::id_rv32_vmvsx:RuntimeStubId::id_rv32_vmvxs;
		b.Create_rvvtypedchunkbegin(3u,128u,0,stub,1,InstRVVTypedChunkBegin::GuardKind::VTypeInteger);
		b.Create_vscalarmove(vr,xr,sew,put);b.Create_rvvtypedchunkend(0,stub);
		Runtime rt;rt.relocatable=true;auto code=qcg::GenerateCode(&rt,nullptr,region,0);
		code.data()[code.size()]=0x59;code.data()[code.size()+1]=0xc3;++move_kernels;
		if(!execute)continue;
		for(u32 vl:{0u,1u,3u})for(u32 start:{0u,1u,3u})for(u32 value:{0u,0x80u,0x8000u,0x80000000u,0xffffffffu}){
			CPUState got(nullptr);got.vec.vtype=3;got.vec.vl=vl;got.vec.vstart=start;
			for(u32 r=1;r<32;++r)got.gpr[r]=value;
			auto *p=(u8*)got.vec.vreg.data();constexpr size_t total=sizeof(got.vec.vreg);u8 want[total];
			for(u32 k=0;k<total;++k)p[k]=(u8)(k*53+0x80);memcpy(want,p,total);
			u32 expected=value;
			if(put){u64 v=xr?(u64)(i64)(i32)value:0;if(start<vl)memcpy(want+vr*512,&v,sew);}
			else {u64 v=0;memcpy(&v,p+vr*512,sew);expected=sew==1?(u32)(i32)(i8)v:sew==2?(u32)(i32)(i16)v:(u32)v;}
			IntegerEnter(&got,code.data());++move_cases;
			if(memcmp(want,p,total)||got.gpr[0]||got.vec.vstart||got.vec.vl!=vl){fprintf(stderr,"FAIL scalar move state\n");return 1;}
			for(u32 r=1;r<32;++r)if(got.gpr[r]!=(!put&&r==xr?expected:value)){fprintf(stderr,"FAIL scalar move gpr\n");return 1;}
		}
	}
	printf("PASS scalar_move_kernels=%u scalar_move_cases=%u execute=%d\n",move_kernels,move_cases,execute);
	unsigned scan_kernels = 0, scan_cases = 0;
	for (u32 vmax : {128u,256u,512u,1024u,2048u,4096u})
	for (bool first : {false,true}) for (bool masked : {false,true})
	for (u32 source : {0u,1u,31u}) for (u32 rd : {0u,15u}) {
		StateReg scan_regs[] = {
			{(u16)(offsetof(CPUState,gpr)+15*4), VType::I32, "x15"},
			{(u16)(offsetof(CPUState,gpr)+16*4), VType::I32, "x16"}};
		StateInfo scan_info{scan_regs,2};
		MemArena arena(1u<<20);
		auto *region=arena.New<Region>(&arena,&scan_info);
		Builder b(region->CreateBlock());
		auto x15=VOperand::MakeVGPR(VType::I32,0), x16=VOperand::MakeVGPR(VType::I32,1);
		b.Create_mov(x15,VOperand::MakeConst(VType::I32,99));
		u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
		u32 const raw=(16u<<26)|(u32(!masked)<<25)|(source<<20)|((first?17u:16u)<<15)|(2u<<12)|(rd<<7)|0x57u;
		auto frame=[&](u32 dest) {
			b.Create_rvvtypedchunkbegin(3u,vmax,raw,RuntimeStubId::id_rv32_vmaskpop,1,
				InstRVVTypedChunkBegin::GuardKind::VTypeIntegerNoRestart);
			b.Create_vmaskscalar(vo+source*512,(u16)vmax,(u8)dest,first,masked);
			b.Create_rvvtypedchunkend(raw,RuntimeStubId::id_rv32_vmaskpop);
		};
		frame(rd);
		// The scalar result must invalidate the cached old x15 before its next consumer.
		b.Create_add(x16,x15,VOperand::MakeConst(VType::I32,1));
		frame(0); // Force the normal caller-state flush of x16 as well.
		Runtime rt;
		// This fall-through harness appends RET after the code. Indirect stub calls avoid
		// an absolute-call address pool there; the guarded body/allocator are unchanged.
		rt.relocatable=true;
		auto code=qcg::GenerateCode(&rt,nullptr,region,0);
		// Non-leaf QCG prologue pushes RCX for call alignment; mirror FrameDestroy.
		code.data()[code.size()]=0x59; code.data()[code.size()+1]=0xc3; ++scan_kernels;
		if (!execute) continue;
		for (u32 vl : {0u,1u,63u,64u,65u,vmax-1,vmax}) for (u32 pat=0;pat<5;++pat) {
			CPUState got(nullptr);
			got.vec.vtype=3; got.vec.vl=vl; got.vec.vstart=0;
			auto *p=(u8*)got.vec.vreg.data();
			constexpr size_t total=sizeof(got.vec.vreg);
			u8 before[total];
			for(size_t z=0;z<total;++z)p[z]=(u8)(z*73+z/11+0xa5);
			memset(p+source*512,0,512);
			for(u32 e=0;e<vmax;++e) {
				bool bit=pat==1 || (pat==2&&e==vmax-1) || (pat==3&&e==vl) || (pat==4&&e%3==1);
				if(bit)p[source*512+e/8]|=1u<<(e%8);
			}
			memcpy(before,p,total);
			u32 expected=first?u32(-1):0;
			for(u32 e=0;e<vl;++e) {
				if(masked&&!(p[e/8]&(1u<<(e%8))))continue;
				if(!(p[source*512+e/8]&(1u<<(e%8))))continue;
				if(first) { expected=e;break; } else ++expected;
			}
			IntegerEnter(&got,code.data()); ++scan_cases;
			u32 x=rd?expected:99;
			if(memcmp(before,p,total)||got.gpr[0]||got.gpr[15]!=x||got.gpr[16]!=x+1||got.vec.vstart||got.vec.vl!=vl) {
				fprintf(stderr,"FAIL maskscan vmax=%u first=%u mask=%u source=%u rd=%u vl=%u pat=%u x15=%u expected=%u x16=%u\n",
					vmax,first,masked,source,rd,vl,pat,got.gpr[15],x,got.gpr[16]); return 1;
			}
		}
	}
	printf("PASS mask_scan_kernels=%u mask_scan_cases=%u execute=%d\n",scan_kernels,scan_cases,execute);
	unsigned prefix_kernels=0,prefix_cases=0;
	for(u32 vmax:{128u,256u,512u,1024u,2048u,4096u})
	for(u32 kind=0;kind<3;++kind)for(bool masked:{false,true})
	for(u32 source:{0u,1u,31u})for(u32 rd:{0u,2u,30u}) {
		if(rd==source||(masked&&rd==0))continue;
		MemArena arena(1u<<20);auto *region=arena.New<Region>(&arena,&state_info);
		Builder b(region->CreateBlock());
		u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
		b.Create_vmaskprefix(vo+rd*512,vo+source*512,(u16)vmax,(u8)kind,masked);
		Runtime rt;auto code=qcg::GenerateCode(&rt,nullptr,region,0);
		code.data()[code.size()]=0xc3;++prefix_kernels;
		if(!execute)continue;
		for(u32 vl:{0u,1u,63u,64u,65u,vmax-1,vmax})for(u32 first:{0u,1u,63u,64u,65u,vmax-1,vmax}) {
			CPUState got(nullptr);got.vec.vl=vl;got.vec.vstart=0;
			auto *p=(u8*)got.vec.vreg.data();constexpr size_t total=sizeof(got.vec.vreg);
			u8 before[total],expected[total];
			for(size_t z=0;z<total;++z)p[z]=(u8)(z*73+z/11+0xa5);
			memset(p+source*512,0,512);
			for(u32 e=first;e<vmax;++e)if(e==first||e%3==1)p[source*512+e/8]|=1u<<(e%8);
			memcpy(before,p,total);memcpy(expected,p,total);
			bool seen=false;
			for(u32 e=0;e<vl;++e) {
				u32 bit=1u<<(e%8);
				if(masked&&!(before[e/8]&bit))continue;
				bool hit=before[source*512+e/8]&bit;
				bool value=kind==0?!seen&&!hit:kind==1?!seen:!seen&&hit;
				expected[rd*512+e/8]=(expected[rd*512+e/8]&~bit)|(value?bit:0);
				seen|=hit;
			}
			IntegerEnter(&got,code.data());++prefix_cases;
			if(memcmp(expected,p,total)||got.vec.vstart||got.vec.vl!=vl) {
				fprintf(stderr,"FAIL maskprefix vmax=%u kind=%u mask=%u source=%u rd=%u vl=%u first=%u\n",vmax,kind,masked,source,rd,vl,first);return 1;
			}
		}
	}
	printf("PASS mask_prefix_kernels=%u mask_prefix_cases=%u execute=%d\n",prefix_kernels,prefix_cases,execute);
	if(scan_only)return 0;
	unsigned index_kernels=0,index_cases=0,iota_kernels=0,iota_cases=0;
	for(u32 vlen:{128u,256u,512u,1024u,2048u,4096u})
	for(u32 sew:{1u,2u,4u,8u})for(int lm:{-3,-2,-1,0,1,2,3}) {
		if(lm<0&&sew>(8u>>-lm))continue;
		u32 rb=vlen/8,gb=lm<0?rb>>-lm:rb<<lm,bytes=std::min(rb,64u),chunks=(gb+bytes-1)/bytes,vmax=gb/sew;
		for(bool iota:{false,true})for(bool masked:{false,true})for(u32 rd:{0u,8u,24u}) {
			if(masked&&rd==0)continue;
			if(iota&&rd==24&&lm==3)continue; // Source mask v31 cannot overlap the destination group.
			MemArena arena(1u<<20);auto *region=arena.New<Region>(&arena,&state_info);Builder b(region->CreateBlock());
			u32 vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
			auto off=[rb](u32 r,u32 byte){return (r+byte/rb)*512+byte%rb;};
			if(iota)b.Create_vmaskiota(vo+rd*512,vo+31*512,(u16)vmax,(u16)rb,(u8)sew,masked);
			else for(u32 c=0;c<chunks;++c)b.Create_vchunkindex(vo+off(rd,c*bytes),(u8)sew,(u16)bytes,c*bytes/sew,masked,c+1==chunks);
			Runtime rt;auto code=qcg::GenerateCode(&rt,nullptr,region,0);code.data()[code.size()]=0xc3;
			if(iota)++iota_kernels;else ++index_kernels;
			if(!execute)continue;
			for(u32 vl:{0u,1u,vmax/2,vmax-1,vmax})for(u32 start:{0u,1u,vmax/2,vmax}) {
				if(iota&&start)continue;
				CPUState got(nullptr);got.vec.vl=vl;got.vec.vstart=start;
				auto *p=(u8*)got.vec.vreg.data();constexpr size_t total=sizeof(got.vec.vreg);u8 expected[total];
				for(size_t z=0;z<total;++z)p[z]=(u8)(z*73+z/11+0xa5);memcpy(expected,p,total);
				u64 count=0;
				for(u32 e=start;e<vl;++e)if(!masked||(p[e/8]&(1u<<(e%8)))){
					u64 value=iota?count:e;memcpy(expected+off(rd,e*sew),&value,sew);
					count+=!!(p[31*512+e/8]&(1u<<(e%8)));
				}
				IntegerEnter(&got,code.data());if(iota)++iota_cases;else ++index_cases;
				if(memcmp(expected,p,total)||got.vec.vstart||got.vec.vl!=vl){fprintf(stderr,"FAIL index iota=%u vlen=%u sew=%u lm=%d rd=%u mask=%u vl=%u start=%u\n",iota,vlen,sew,lm,rd,masked,vl,start);return 1;}
			}
		}
	}
	printf("PASS index_kernels=%u index_cases=%u execute=%d\n",index_kernels,index_cases,execute);
	printf("PASS iota_kernels=%u iota_cases=%u execute=%d\n",iota_kernels,iota_cases,execute);
	unsigned ext_kernels = 0, ext_cases = 0;
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u, 4096u})
	for (u32 ds : {2u, 4u, 8u}) for (u32 ss : {1u, 2u, 4u})
	for (int lm : {-3,-2,-1,0,1,2,3}) {
		if (ss >= ds || (lm < 0 && ds > (8u >> -lm))) continue;
		u32 const div = ds / ss;
		int const slm = lm - (div == 8 ? 3 : div == 4 ? 2 : 1);
		if (slm < -3) continue;
		u32 const rb = vlen / 8, gb = lm < 0 ? rb >> -lm : rb << lm;
		u32 const dg = lm < 0 ? 1 : 1u << lm, sg = slm < 0 ? 1 : 1u << slm;
		u32 const vlmax = gb / ds, bytes = std::min(rb, 64u), chunks = (gb + bytes - 1) / bytes;
		for (bool sign : {false, true}) for (bool masked : {false, true}) for (bool alias : {false, true}) {
			if (alias && slm < 0) continue;
			u32 const rd = 8, rs2 = alias ? rd + dg - sg : 24;
			MemArena arena(1u << 20);
			auto *region = arena.New<Region>(&arena, &state_info);
			Builder b(region->CreateBlock());
			u32 const vo = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg);
			auto off = [rb](u32 reg, u32 byte) { return (reg + byte / rb) * 512 + byte % rb; };
			for (u32 c = 0; c < chunks; ++c)
				b.Create_vchunkextend(vo + off(rd, c * bytes), vo + off(rs2, c * bytes / div),
					(u8)ds, (u8)ss, (u16)bytes, c * bytes / ds, sign, masked, c + 1 == chunks);
			Runtime rt;
			auto code = qcg::GenerateCode(&rt, nullptr, region, 0);
			code.data()[code.size()] = 0xc3; ++ext_kernels;
			if (!execute) continue;
			for (u32 vl : {0u, 1u, vlmax / 2, vlmax - 1, vlmax})
			for (u32 start : {0u, 1u, vlmax / 2, vlmax}) {
				CPUState got(nullptr);
				got.vec.vl = vl; got.vec.vstart = start;
				auto *p = (u8 *)got.vec.vreg.data();
				constexpr size_t total = sizeof(got.vec.vreg);
				u8 before[total], expected[total];
				for (size_t z = 0; z < total; ++z) p[z] = (u8)((z * 73 + z / 11 + 0xa5) & 255);
				memcpy(before, p, total); memcpy(expected, p, total);
				for (u32 e = start; e < vl; ++e) {
					if (masked && !(before[e / 8] & (1u << (e % 8)))) continue;
					u64 value = Load(before + off(rs2, e * ss), ss);
					if (sign && (value & (u64(1) << (ss * 8 - 1)))) value |= ~((u64(1) << (ss * 8)) - 1);
					memcpy(expected + off(rd, e * ds), &value, ds);
				}
				IntegerEnter(&got, code.data()); ++ext_cases;
				if (memcmp(expected, p, total) || got.vec.vstart || got.vec.vl != vl) {
					fprintf(stderr, "FAIL extension VLEN=%u ds=%u ss=%u lm=%d sign=%u mask=%u alias=%u vl=%u start=%u\n",
						vlen, ds, ss, lm, sign, masked, alias, vl, start); return 1;
				}
			}
		}
	}
	printf("PASS extension_kernels=%u extension_cases=%u execute=%d\n", ext_kernels, ext_cases, execute);
	unsigned wide_kernels = 0, wide_cases = 0;
	for (u32 vlen : {128u,256u,512u,1024u,2048u,4096u})
	for (u32 ss : {1u,2u,4u}) for (int lm : {-3,-2,-1,0,1,2}) {
		if (lm < 0 && ss > (8u >> -lm)) continue;
		u32 const rb = vlen / 8, ngb = lm < 0 ? rb >> -lm : rb << lm;
		u32 const ds = 2 * ss, gb = 2 * ngb, vlmax = ngb / ss, bytes = std::min(rb,64u), chunks = (gb + bytes - 1) / bytes;
		u32 const dg = lm < 0 ? 1 : 2u << lm, sg = lm < 0 ? 1 : 1u << lm;
		for (u32 op = 0; op < 4; ++op) for (bool wide2 : {false,true})
		for (bool sign2 : {false,true}) for (bool sign1 : {false,true})
		for (bool scalar : {false,true}) for (bool masked : {false,true}) for (bool alias : {false,true}) {
			if ((wide2 && op >= 2) || (alias && (op == 3 || (!wide2 && lm < 0)))) continue;
			u32 const rd = 8, rs2 = alias ? (wide2 ? rd : rd + dg - sg) : 16, rs1 = 24;
			MemArena arena(1u << 20);
			auto *region = arena.New<Region>(&arena,&state_info);
			Builder b(region->CreateBlock());
			u32 const vo = offsetof(CPUState,vec) + offsetof(rv32::VectorState,vreg);
			auto off = [rb](u32 r,u32 byte) { return (r + byte / rb) * 512 + byte % rb; };
			for (u32 c = 0; c < chunks; ++c)
				b.Create_vchunkwiden((u8)op, vo + off(rd,c*bytes), vo + off(rs2,c*bytes/(wide2?1:2)),
					scalar ? (u32)offsetof(CPUState,gpr)+31*4 : vo + off(rs1,c*bytes/2),
					(u8)ss,(u16)bytes,c*bytes/ds,scalar,false,wide2,sign2,sign1,masked,c+1==chunks);
			Runtime rt;
			auto code = qcg::GenerateCode(&rt,nullptr,region,0);
			code.data()[code.size()] = 0xc3; ++wide_kernels;
			if (!execute) continue;
			for (u32 vl : {0u,1u,vlmax/2,vlmax-1,vlmax}) for (u32 start : {0u,1u,vlmax/2,vlmax}) {
				CPUState got(nullptr);
				got.vec.vl=vl; got.vec.vstart=start; got.gpr[31]=start?0x80000080u:0xffffffffu;
				auto *p=(u8*)got.vec.vreg.data(); constexpr size_t total=sizeof(got.vec.vreg);
				u8 before[total],expected[total];
				for(size_t z=0;z<total;++z) p[z]=(u8)((z*73+z/11+0xa5)&255);
				memcpy(before,p,total);memcpy(expected,p,total);
				auto value=[](u64 v,u32 n,bool sign) -> __int128 {
					__int128 x=v & (n==8?~u64(0):(u64(1)<<(n*8))-1);
					if(sign && (x & ((__int128)1<<(n*8-1)))) x-=(__int128)1<<(n*8);
					return x;
				};
				for(u32 e=start;e<vl;++e) {
					if(masked && !(before[e/8]&(1u<<(e%8)))) continue;
					__int128 a=value(Load(before+off(rs2,e*(wide2?ds:ss)),wide2?ds:ss),wide2?ds:ss,sign2);
					__int128 z=value(scalar?got.gpr[31]:Load(before+off(rs1,e*ss),ss),ss,sign1);
					__int128 d=Load(before+off(rd,e*ds),ds);
					u64 out=(u64)(op==0?a+z:op==1?a-z:op==2?a*z:d+a*z);
					memcpy(expected+off(rd,e*ds),&out,ds);
				}
				IntegerEnter(&got,code.data());++wide_cases;
				if(memcmp(expected,p,total)||got.vec.vstart||got.vec.vl!=vl) {
					fprintf(stderr,"FAIL widening vlen=%u ss=%u lm=%d op=%u wide2=%u sign2=%u sign1=%u scalar=%u mask=%u alias=%u vl=%u start=%u\n",
						vlen,ss,lm,op,wide2,sign2,sign1,scalar,masked,alias,vl,start); return 1;
				}
			}
		}
	}
	printf("PASS widening_kernels=%u widening_cases=%u execute=%d\n",wide_kernels,wide_cases,execute);
	unsigned narrow_kernels=0,narrow_cases=0;
	for(u32 vlen:{128u,256u,512u,1024u,2048u,4096u})
	for(u32 ds:{1u,2u,4u}) for(int lm:{-3,-2,-1,0,1,2}) {
		if(lm<0&&ds>(8u>>-lm))continue;
		u32 const rb=vlen/8,gb=lm<0?rb>>-lm:rb<<lm,ss=ds*2,vlmax=gb/ds;
		u32 const bytes=std::min(rb,64u),chunks=(2*gb+bytes-1)/bytes;
		for(bool clipping:{false,true}) for(bool arith:{false,true}) for(u32 src:{0u,1u,2u}) for(bool masked:{false,true})
		for(u32 rd:{8u,16u,24u}) {
			MemArena arena(1u<<20);
			auto *region=arena.New<Region>(&arena,&state_info);Builder b(region->CreateBlock());
			u32 const vo=offsetof(CPUState,vec)+offsetof(rv32::VectorState,vreg);
			auto off=[rb](u32 r,u32 byte){return (r+byte/rb)*512+byte%rb;};
			for(u32 c=0;c<chunks;++c) {
				u32 const s1=src==0?vo+off(24,c*bytes/2):src==1?(u32)offsetof(CPUState,gpr)+31*4:0;
				if(clipping)b.Create_vchunkpartialalu(arith?50:49,(u8)ss,(u8)c,(u16)bytes,
					vo+off(rd,c*bytes/2),vo+off(16,c*bytes),s1,(u8)src,31,true,masked,c*bytes/ss,c+1==chunks);
				else b.Create_vchunknarrowshift(vo+off(rd,c*bytes/2),vo+off(16,c*bytes),s1,
					31,(u8)src,(u8)ds,(u16)bytes,c*bytes/ss,arith,masked,c+1==chunks);
			}
			Runtime rt;auto code=qcg::GenerateCode(&rt,nullptr,region,0);
			code.data()[code.size()]=0xc3;++narrow_kernels;
			if(!execute)continue;
			for(u32 vl:{0u,1u,vlmax/2,vlmax-1,vlmax}) for(u32 start:{0u,1u,vlmax/2,vlmax})
			for(u32 rm=0;rm<(clipping?4u:1u);++rm) {
				CPUState got(nullptr);got.vec.vl=vl;got.vec.vstart=start;got.gpr[31]=start?0x80000080u:0xffffffffu;
				got.vec.vxrm=rm;got.vec.vxsat=(start+rm)&1;bool expected_sat=got.vec.vxsat;
				auto *p=(u8*)got.vec.vreg.data();constexpr size_t total=sizeof(got.vec.vreg);
				u8 before[total],expected[total];
				for(size_t z=0;z<total;++z)p[z]=(u8)((z*73+z/11+0xa5)&255);
				if(clipping) {
					u64 mask=ss==8?~u64(0):(u64(1)<<(ss*8))-1,dm=(u64(1)<<(ds*8))-1;
					u64 av[]={0,mask,u64(1)<<(ss*8-1),dm,dm+1,dm>>1,(dm>>1)+1,1};
					u64 sh[]={0,1,ds*8-1,ss*8-1,ss*8,ss*8+1,mask,2};
					for(u32 e=0;e<vlmax;++e) {
						memcpy(p+off(16,e*ss),&av[e%8],ss);
						memcpy(p+off(24,e*ds),&sh[e%8],ds);
					}
				}
				memcpy(before,p,total);memcpy(expected,p,total);
				for(u32 e=start;e<vl;++e) {
					if(masked&&!(before[e/8]&(1u<<(e%8))))continue;
					u64 a=Load(before+off(16,e*ss),ss);
					u32 n=(src==0?Load(before+off(24,e*ds),ds):src==1?got.gpr[31]:31)&(ss*8-1);
					u64 out=a>>n;
					if(arith&&n&&(a&(u64(1)<<(ss*8-1))))out|=(~u64(0))<<(ss*8-n);
					if(clipping)out=Clip(a,n,ds,arith,rm,expected_sat);
					memcpy(expected+off(rd,e*ds),&out,ds);
				}
				IntegerEnter(&got,code.data());++narrow_cases;
				if(memcmp(expected,p,total)||got.vec.vstart||got.vec.vl!=vl||got.vec.vxsat!=expected_sat||got.vec.vxrm!=rm) {
					fprintf(stderr,"FAIL narrow clip=%u vlen=%u ds=%u lm=%d arith=%u src=%u mask=%u rd=%u vl=%u start=%u rm=%u\n",
						clipping,vlen,ds,lm,arith,src,masked,rd,vl,start,rm);return 1;
				}
			}
		}
	}
	printf("PASS narrowing_shift_clip_kernels=%u narrowing_shift_clip_cases=%u execute=%d\n",narrow_kernels,narrow_cases,execute);
}
