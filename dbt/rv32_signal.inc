// Included after uthread in ukernel.cpp. Fixed RV32 LE Linux v6.12 ABI;
// no host sigaction/ucontext/unsigned-long sizes participate in the codec.
// See docs/rvv-validation/signal-issue-1/README.md for ABI sources and boundaries.
// SignalSyscall(true) means handled; rt_sigreturn restores state rather than a0=rc.
namespace rv32_signal {
constexpr u32 Info = 0, UC = 128, Mask = 148, MC = 288, FP = 416;
constexpr u32 Reserved = 932, Header = 936, VS = 944, Data = 976;
constexpr u32 Magic = 0x53465457;
constexpr u64 Unblockable = (1ull << (9-1)) | (1ull << (19-1));
constexpr u32 FrameSize(u32 vlenb) { return (Data + 32*vlenb + 8 + 15) & ~15u; }
u32 get32(u8 const *p) { return u32(p[0]) | (u32(p[1])<<8) | (u32(p[2])<<16) | (u32(p[3])<<24); }
u64 get64(u8 const *p) { return get32(p) | (u64(get32(p+4))<<32); }
void put32(u8 *p, u32 v) { for (u32 i=0;i<4;++i) p[i]=v>>(8*i); }
void put64(u8 *p, u64 v) { put32(p,v); put32(p+4,v>>32); }
bool CopyIn(void *out, u32 address, u32 size)
{
	if (!mmu::CheckedRange(address,size,PROT_READ)) return false;
	memcpy(out,mmu::g2h(address),size); return true;
}
bool CopyOut(u32 address, void const *in, u32 size)
{
	if (!mmu::CheckedRange(address,size,PROT_WRITE)) return false;
	memcpy(mmu::g2h(address),in,size); return true;
}
void CloseFP(CPUState *state)
{
	if (state->fpu.fround_run_open) {
		u32 saved=config::rvv_fround_mxcsr_mode==0
			? state->fpu.fround_run_saved_mxcsr : config::g_mxcsr_resting;
		rv32::rvv_fast::fround_run_force_close(state->fpu);
		// mode 2's ordinary close may keep host RC. Signal boundaries never do.
		rv32::rvdbt_mxcsr_set(saved);
	}
	if (config::rvv_fround_mxcsr_mode!=0) rv32::rvdbt_mxcsr_set(config::g_mxcsr_resting);
	state->fpu.fround_run_open=false;
	state->fpu.fround_run_rc=0;
	state->fpu.fround_run_saved_mxcsr=0;
}
}

bool ukernel::SignalSyscall(CPUState *state)
{
	using namespace rv32_signal;
	u32 no=state->gpr[17];
	if (no!=134 && no!=135 && no!=139) return false;
	auto *ut=state->GetUThread();
	if (no==139) {
		if (!RestoreSignalFrame(state)) {
			fprintf(stderr,"RVDBT_SIGNAL_BADFRAME sp=%08x\n",state->gpr[2]);
			EnqueueTermination(1);
		}
		return true; // StateRestored: never write a syscall result over restored a0.
	}
	u32 first=state->gpr[10], input=state->gpr[11], output=state->gpr[12];
	i32 rc=0;
	if (state->gpr[13]!=8) rc=-EINVAL;
	else if (no==134) {
		if (first<1 || first>64 || first==9 || first==19) rc=-EINVAL;
		else {
			u8 old[16]{}, incoming[16]{};
			auto &action=ut->signal_actions[first-1];
			put32(old,action.handler); put32(old+4,action.flags); put64(old+8,action.mask);
			// Both optional pointers are guest integers; zero means absent.
			if ((input && !CopyIn(incoming,input,16)) ||
			    (output && !mmu::CheckedRange(output,16,PROT_WRITE))) rc=-EFAULT;
			// Only synchronous helper SIGSEGV delivery is implemented. Queries are
			// available for all legal signal numbers; other installations fail explicitly.
			else if (input && first!=11) rc=-EOPNOTSUPP;
			else if (input && (get32(incoming+4)&~4u)) rc=-EOPNOTSUPP;
			else if (input && get32(incoming)==1) rc=-EOPNOTSUPP; // no ignored synchronous fault
			else {
				if (output) CopyOut(output,old,16);
				if (input) action={get32(incoming),get32(incoming+4),get64(incoming+8)&~Unblockable};
			}
		}
	} else {
		u8 incoming[8]{}, old[8]{}; put64(old,ut->guest_signal_mask);
		if ((input && !CopyIn(incoming,input,8)) ||
		    (output && !mmu::CheckedRange(output,8,PROT_WRITE))) rc=-EFAULT;
		else if (input && first>2) rc=-EINVAL;
		else {
			if (output) CopyOut(output,old,8);
			if (input) {
				u64 bits=get64(incoming)&~Unblockable;
				if (first==0) ut->guest_signal_mask|=bits;
				else if (first==1) ut->guest_signal_mask&=~bits;
				else ut->guest_signal_mask=bits;
			}
		}
	}
	state->gpr[10]=rc;
	return true;
}

bool ukernel::DeliverHelperSignal(CPUState *state, MemoryFaultSnapshot const &snapshot)
{
	using namespace rv32_signal;
	auto *ut=state->GetUThread();
	auto const action=ut->signal_actions[10];
	// This entry is only reached after helper scopes and the FP bracket have closed.
	if (snapshot.event.origin!=MemoryFaultEvent::Origin::PredictedHelper ||
	    snapshot.event.access!=MemoryFaultEvent::Access::Load || ut->signal_frame ||
	    (ut->guest_signal_mask&(1ull<<10)) || action.handler<=1 ||
	    (action.handler&1) || !mmu::CheckedRange(action.handler,2,PROT_EXEC) ||
	    state->fpu.fround_run_open || !snapshot.vlenb || snapshot.vlenb>rv32::VLEN_MAX_BYTES) {
		fprintf(stderr,"RVDBT_SIGNAL_UNDELIVERABLE helper_sync_SIGSEGV\n");
		return false;
	}
	u32 size=FrameSize(snapshot.vlenb), sp=state->gpr[2];
	if (sp<size) return false;
	u32 frame=(sp-size)&~15u;
	if (!mmu::CheckedRange(frame,size,PROT_WRITE)) return false;
	// Build on the ordinary dispatcher stack, never inside a host signal callback.
	std::vector<u8> bytes(size,0); auto *p=bytes.data();
	put32(p+Info,11);
	put32(p+Info+8,snapshot.event.reason==MemoryFaultEvent::Reason::Protection?2:1);
	put32(p+Info+12,snapshot.event.address);
	put32(p+UC+12,2); // SS_DISABLE; altstack is outside this implementation's scope.
	put64(p+Mask,ut->guest_signal_mask);
	put32(p+MC,snapshot.pc);
	for (u32 r=1;r<32;++r) put32(p+MC+4*r,snapshot.gpr[r]);
	for (u32 r=0;r<32;++r) put64(p+FP+8*r,snapshot.fpr[r]);
	put32(p+FP+256,snapshot.csrs[2]);
	put32(p+Header,Magic); put32(p+Header+4,40+32*snapshot.vlenb);
	put32(p+VS,snapshot.csrs[3]); put32(p+VS+4,snapshot.csrs[7]);
	put32(p+VS+8,snapshot.csrs[8]); put32(p+VS+12,snapshot.csrs[6]);
	put32(p+VS+16,snapshot.vlenb); put32(p+VS+20,frame+Data);
	for (u32 r=0;r<32;++r) memcpy(p+Data+r*snapshot.vlenb,snapshot.vreg[r].data(),snapshot.vlenb);
	// END header is already zero; size is zero in the pinned Linux ABI.
	if (!ut->signal_trampoline) {
		void *tramp=mmu::mmap(0,mmu::PAGE_SIZE,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE);
		if (tramp==MAP_FAILED) return false;
		u32 address=mmu::h2g(tramp);
		u8 code[8]; put32(code,0x08b00893); put32(code+4,0x00000073); // li a7,139; ecall
		if (!CopyOut(address,code,8) || mmu::mprotect(address,mmu::PAGE_SIZE,PROT_READ|PROT_EXEC)) {
			mmu::munmap(address,mmu::PAGE_SIZE); return false;
		}
		ut->signal_trampoline=address;
	}
	if (!mmu::CheckedRange(ut->signal_trampoline,8,PROT_READ|PROT_EXEC) ||
	    !CopyOut(frame,p,size)) return false;
	ut->signal_host_mxcsr=rv32::rvdbt_mxcsr_get();
	ut->signal_frame=frame; ut->signal_frame_size=size;
	ut->guest_signal_mask|=action.mask|(1ull<<10);
	state->gpr[0]=0; state->gpr[1]=ut->signal_trampoline; state->gpr[2]=frame;
	state->gpr[10]=11; state->gpr[11]=frame; state->gpr[12]=frame+UC;
	state->ip=action.handler; state->trapno=rv32::TrapCode::NONE;
	fprintf(stderr,"RVDBT_SIGNAL_DELIVERED signal=11 pc=%08x frame=%08x size=%u handler=%08x\n",
		snapshot.pc,frame,size,action.handler);
	return true;
}

bool ukernel::RestoreSignalFrame(CPUState *state)
{
	using namespace rv32_signal;
	auto *ut=state->GetUThread();
	u32 frame=state->gpr[2], vlenb=state->vec.vlenb;
	CloseFP(state); // A badframe must also leave host FP mode clean.
	if (!frame || frame!=ut->signal_frame || (frame&15) || !vlenb ||
	    vlenb>rv32::VLEN_MAX_BYTES || ut->signal_frame_size!=FrameSize(vlenb)) return false;
	std::vector<u8> bytes(FrameSize(vlenb)); auto *p=bytes.data();
	if (!CopyIn(p,frame,bytes.size())) return false;
	u32 pc=get32(p+MC), fcsr=get32(p+FP+256);
	u32 vstart=get32(p+VS), vl=get32(p+VS+4), vtype=get32(p+VS+8), vcsr=get32(p+VS+12);
	u32 end=Data+32*vlenb;
	if (get32(p+Reserved) || get32(p+Header)!=Magic || get32(p+Header+4)!=40+32*vlenb ||
	    // No alternate-stack restoration or relocated vector payload support.
	    get32(p+UC+8) || get32(p+UC+12)!=2 || get32(p+UC+16) ||
	    get32(p+VS+16)!=vlenb || get32(p+VS+20)!=frame+Data ||
	    get32(p+end) || get32(p+end+4) || (pc&1) || !mmu::CheckedRange(pc,2,PROT_EXEC) ||
	    // All three frm bits are saved CSR state, including reserved operation modes.
	    // FP operation legality remains in fp_mode(); only unimplemented fcsr bits are badframe.
	    (fcsr&~255u) || vcsr>7 || vstart>=vlenb*8)
		return false;
	if (vtype==rv32::VTYPE_VILL_BIT) { if (vl) return false; }
	else if (!rv32::vtype_supported(rv32::VType{vtype},vlenb*8) ||
	         vl>rv32::compute_vlmax(rv32::VType{vtype},vlenb*8)) return false;
	// Only architectural fields: retain owner/cache/profile/storage beyond configured VLEN.
	for (u32 r=1;r<32;++r) state->gpr[r]=get32(p+MC+4*r);
	state->gpr[0]=0;
	for (u32 r=0;r<32;++r) state->fpu.f[r]=get64(p+FP+8*r);
	state->fpu.fcsr=fcsr;
	for (u32 r=0;r<32;++r) memcpy(state->vec.vreg[r].data(),p+Data+r*vlenb,vlenb);
	state->vec.vstart=vstart; state->vec.vl=vl; state->vec.vtype=vtype;
	state->vec.vxrm=vcsr>>1; state->vec.vxsat=vcsr&1;
	ut->guest_signal_mask=get64(p+Mask)&~Unblockable;
	ut->signal_frame=0; ut->signal_frame_size=0; ut->memory_fault_pending=false;
	state->trapno=rv32::TrapCode::NONE; state->ip=pc;
	rv32::rvdbt_mxcsr_set(ut->signal_host_mxcsr);
	fprintf(stderr,"RVDBT_SIGNAL_RETURNED pc=%08x a0=%08x vlenb=%u\n",pc,state->gpr[10],vlenb);
	return true;
}
