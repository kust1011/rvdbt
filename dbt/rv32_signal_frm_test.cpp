// Host API verification only: no guest ELF, guest instructions, FP operations or external oracle.
#include "dbt/ukernel.cpp"
#include "dbt/guest/rv32_runtime.h"
using namespace dbt;
using namespace dbt::rv32_signal;
static void check(bool ok,char const *why)
{ if(!ok) { fprintf(stderr,"FRM_INTERFACE_FAILED %s\n",why); exit(2); } }
int main()
{
	static_assert(sizeof(CPUState)==42720); // Existing production ABI (Task131).
	u32 const stack=0x22000000,code=0x23000000;
	u32 const host=rv32::rvdbt_mxcsr_get();
	mmu::Init();
	check(mmu::mmap(stack,16384,PROT_READ|PROT_WRITE)!=MAP_FAILED,"stack");
	check(mmu::mmap(code,4096,PROT_READ|PROT_EXEC)!=MAP_FAILED,"PC/handler");
	ukernel::process.main_thread=std::make_unique<uthread>();
	auto *s=CPUState::Current();auto *ut=s->GetUThread();
	ut->signal_actions[10]={code+128,4,0};
	u32 restores=0,rejections=0;
	for(u32 frm=0;frm<8;++frm) {
		for(u32 flags=0;flags<32;++flags) {
			s->vec.Reset(1024);s->vec.vtype=16;s->vec.vl=9;s->vec.vstart=7;
			s->vec.vxrm=2;s->vec.vxsat=1;
			for(u32 r=0;r<32;++r) {
				s->gpr[r]=r?0x45670000+r:0;s->fpu.f[r]=0xffab000000000000ull+r;
				for(u32 b=0;b<rv32::VLEN_MAX_BYTES;++b)s->vec.vreg[r][b]=r*7+b;
			}
			s->gpr[2]=stack+16384;s->gpr[10]=flags?0x20001000:0;
			s->fpu.fcsr=flags;s->fpu.set_frm(frm);
			u32 saved=(frm<<5)|flags;
			check(s->fpu.fcsr==saved,"set_frm saves all 3 bits");
			s->fpu.fround_run_open=false;
			// Call existing admission predicate, not a floating-point operation.
			check((rv32::fp_mode(s->fpu,7).path==rv32::FP_ILLEGAL)==(frm>=5),"dynamic rounding legality unchanged");
			check(rv32::fp_mode(s->fpu,5).path==rv32::FP_ILLEGAL && rv32::fp_mode(s->fpu,6).path==rv32::FP_ILLEGAL,"static reserved rounding remains refused");
			for(u32 rm=0;rm<5;++rm)check(rv32::fp_mode(s->fpu,rm).path!=rv32::FP_ILLEGAL,"static legal rounding independent of frm");
			MemoryFaultEvent e;e.pc=code;e.raw=0x03056107;e.address=0x20001000;
			e.reason=MemoryFaultEvent::Reason::Protection;e.eew_bytes=4;e.nf=1;
			ukernel::QueueHelperMemoryFault(s,e);
			if(sigsetjmp(trap_unwind_env,0)==0) { rv32::FinishHelperMemoryFault(s);check(false,"unwind"); }
			auto snap=ukernel::CaptureHelperMemoryFault(s);ut->memory_fault_pending=false;
			check(snap.csrs[0]==flags && snap.csrs[1]==frm && snap.csrs[2]==saved,"CSR aliases captured");
			check(ukernel::DeliverHelperSignal(s,snap),"frame save with all frm values");
			u32 frame=ut->signal_frame;
			check(get32((u8*)mmu::g2h(frame+FP+256))==saved,"frame exact saved fcsr");
			for(u32 r=0;r<32;++r) { s->gpr[r]=0xdead0000+r;s->fpu.f[r]=0;s->vec.vreg[r].fill(0xee); }
			s->gpr[2]=frame;s->fpu.fcsr=saved^255u;
			// Test every unimplemented high bit for each frm, with all low flags set.
			if(flags==31) for(u32 bit=8;bit<32;++bit) {
				u8 bad[4];put32(bad,saved|(1u<<bit));check(CopyOut(frame+FP+256,bad,4),"bad fcsr injection");
				auto x=s->gpr;auto v=s->vec.vreg;u32 oldcsr=s->fpu.fcsr;
				check(!ukernel::RestoreSignalFrame(s),"unimplemented fcsr high bit badframe");
				check(s->gpr==x && s->vec.vreg==v && s->fpu.fcsr==oldcsr && ut->signal_frame==frame && s->GetUThread()==ut,"badframe atomic");
				++rejections;
			}
			u8 valid[4];put32(valid,saved);check(CopyOut(frame+FP+256,valid,4),"valid fcsr restored in frame");
			s->gpr[17]=139;check(ukernel::SignalSyscall(s),"139 StateRestored");
			check(s->fpu.fcsr==saved && s->fpu.frm()==frm && s->fpu.fflags()==flags,"all frm and flags exact roundtrip");
			check(s->gpr==snap.gpr && s->ip==code && !ut->signal_frame && !ut->terminating,"a0/PC/scalar state");
			for(u32 r=0;r<32;++r)check(s->fpu.f[r]==snap.fpr[r] && !memcmp(s->vec.vreg[r].data(),snap.vreg[r].data(),128),"f/vector state unchanged contract");
			check(s->vec.vlenb==128 && s->vec.vl==9 && s->vec.vstart==7 && s->vec.vtype==16 && s->vec.vxrm==2 && s->vec.vxsat==1,"V state");
			check(rv32::rvdbt_mxcsr_get()==host && !s->fpu.fround_run_open,"host FP environment");
			++restores;
		}
	}
	check(restores==256 && rejections==192,"exhaustive counts");
	ukernel::process.main_thread.reset();mmu::Destroy();
	puts("FRM_INTERFACE_PASS frm=0..7 fflags=0..31 roundtrips=256 high_bit_badframes=192 operation_admission_unchanged guest_calls=0 external_ISA_tests=0");
}
