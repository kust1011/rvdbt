// Local permission/state and actual QCG admission checks. No guest handler or retry.
#define main UnitMemoryMain
#include "dbt/rv32_unit_memory_fault_test.cpp"
#undef main
#include "dbt/aot/aot.h"
#include "dbt/ccrf_materializer.cpp"
#include <dlfcn.h>
static u64 native_hits, native_fallbacks;
extern "C" void qcgstub_rv32_vlm(CPUState *, u32);
extern "C" void qcgstub_rv32_vsm(CPUState *, u32);
extern "C" void qcgstub_rv32_vlNre(CPUState *, u32);
extern "C" void qcgstub_rv32_vsNr(CPUState *, u32);
extern "C" u32 qcgstub_rv32_special_memory_safe(CPUState *, u32);
static u32 special_word(bool mask, bool store, u32 eew, u32 nr, u32 reg = 8)
{
	return (word(eew, store) & ~(31u << 7)) | (reg << 7) | ((mask ? 11u : 8u) << 20) | ((nr - 1) << 29);
}
static RuntimeStubId special_stub(bool mask, bool store)
{
	return mask ? (store ? RuntimeStubId::id_rv32_vsm : RuntimeStubId::id_rv32_vlm)
		    : (store ? RuntimeStubId::id_rv32_vsNr : RuntimeStubId::id_rv32_vlNre);
}
static void special_invoke(CPUState *s, u32 raw, bool mask, bool store)
{
	if (sigsetjmp(trap_unwind_env, 0) == 0) {
		if (mask) {
			if (store)
				qcgstub_rv32_vsm(s, raw);
			else
				qcgstub_rv32_vlm(s, raw);
		} else {
			if (store)
				qcgstub_rv32_vsNr(s, raw);
			else
				qcgstub_rv32_vlNre(s, raw);
		}
	}
}
// Independent byte-array expectation, not a call back into the implementation.
static void cell(CPUState *s, bool mask, bool store, u32 vlen, u32 nr, u32 eew, u32 vt, u32 vl, u32 start,
		 int prot, u32 prefix, bool split, void *native_code = nullptr, u32 reg = 8)
{
	check(mmu::mmap(data, 8192, PROT_READ | PROT_WRITE) != MAP_FAILED, "special map");
	auto *mem = (u8 *)mmu::g2h(data);
	std::array<u8, 8192> expected_mem;
	for (u32 i = 0; i < 8192; ++i)
		mem[i] = expected_mem[i] = (u8)(i * 13 + 5);
	config::vlen_bits = vlen;
	clear(s);
	s->vec.Reset(vlen);
	s->vec.vtype = vt;
	s->vec.vl = vl;
	s->vec.vstart = start;
	for (u32 r = 0; r < 32; ++r)
		for (u32 b = 0; b < rv32::VLEN_MAX_BYTES; ++b)
			s->vec.vreg[r][b] = (u8)(r * 17 + b * 3);
	u32 const rb = vlen / 8, evl = mask ? (vl + 7) / 8 : nr * rb / eew;
	u32 const baseoff = 4096 - prefix * eew - (split ? eew - 1 : 0);
	s->gpr[5] = data + baseoff;
	auto expected = s->vec;
	u32 fault = evl, address = 0;
	bool const denied = prot == -1 || !(prot & (store ? PROT_WRITE : PROT_READ));
	for (u32 e = start; e < evl; ++e) {
		u32 off = baseoff + e * eew;
		if (denied && off + eew > 4096) {
			fault = e;
			address = data + std::max(off, 4096u);
			break;
		}
		u32 byte = e * eew, r = reg + byte / rb, b = byte % rb;
		if (store)
			memcpy(expected_mem.data() + off, expected.vreg[r].data() + b, eew);
		else
			memcpy(expected.vreg[r].data() + b, expected_mem.data() + off, eew);
	}
	if (prot == -1)
		check(mmu::munmap(data + 4096, 4096) == 0, "special unmap");
	else
		check(mmu::mprotect(data + 4096, 4096, prot) == 0, "special protect");
	u32 raw = special_word(mask, store, eew, nr, reg);
	bool admitted = mask && start == 0 && (evl * eew <= 4096 - baseoff || !denied);
	check(qcgstub_rv32_special_memory_safe(s, raw) == admitted, "live special admission");
	u64 hits = s->rvv_direct_hits, misses = s->rvv_direct_fallbacks;
	if (native_code) {
		if (sigsetjmp(trap_unwind_env, 0) == 0)
			Enter(s, mmu::base, native_code);
		native_hits += s->rvv_direct_hits - hits;
		native_fallbacks += s->rvv_direct_fallbacks - misses;
		check(s->rvv_direct_hits - hits == (admitted ? 1u : 0u), "actual special native hit");
		check(s->rvv_direct_fallbacks - misses == (admitted ? 0u : 1u), "actual special fallback");
	} else
		special_invoke(s, raw, mask, store);
	bool const failed = fault != evl;
	check(s->vec.vreg == expected.vreg, "special entire register file/prefix/tail");
	check(s->vec.vl == vl && s->vec.vtype == vt && s->vec.vstart == (failed ? fault : 0),
	      "special original VL/type and effective vstart");
	if (failed) {
		auto const &ev = s->GetUThread()->memory_fault;
		check(s->trapno == rv32::TrapCode::MEMORY_FAULT && s->GetUThread()->memory_fault_pending,
		      "special pending fault");
		check(s->ip == pc && ev.pc == pc && ev.raw == raw && ev.address == address &&
			  ev.element == fault,
		      "special fault PC/raw/address/unit");
		check(ev.access ==
			      (store ? MemoryFaultEvent::Access::Store : MemoryFaultEvent::Access::Load) &&
			  ev.nf == nr && ev.field == 0 && ev.eew_bytes == eew,
		      "special fault geometry/access");
		check(ev.reason == (prot == -1 ? MemoryFaultEvent::Reason::Unmapped
					       : MemoryFaultEvent::Reason::Protection),
		      "special reason");
		auto snap = ukernel::CaptureHelperMemoryFault(s);
		check(snap.vreg == expected.vreg && snap.pc == pc && snap.csrs[3] == fault &&
			  snap.csrs[7] == vl,
		      "special dispatcher snapshot");
	} else {
		check(s->trapno == rv32::TrapCode::NONE && !s->GetUThread()->memory_fault_pending,
		      "special normal completion");
		if (!native_code)
			check(s->ip == pc + 4, "special normal PC advance");
	}
	// Inspection cleanup after the cell. No further instruction is run on its state.
	if (prot != -1)
		check(mmu::mprotect(data + 4096, 4096, PROT_READ | PROT_WRITE) == 0, "inspection permission");
	check(!memcmp(mem, expected_mem.data(), prot == -1 ? 4096 : 8192),
	      "special completed memory prefix and denied bytes");
	++cells;
}
static void helper_cells(CPUState *s)
{
	for (u32 vlen : {128u, 256u, 512u, 1024u, 2048u, 4096u})
		for (bool store : {false, true})
			for (int prot : {PROT_NONE, PROT_READ, PROT_WRITE, -1}) {
				for (u32 nr : {1u, 2u, 4u, 8u})
					for (u32 eew : {1u, 2u, 4u, 8u}) {
						if (store && eew != 1)
							continue;
						u32 evl = nr * (vlen / 8) / eew;
						for (u32 vt : {0u, 24u, rv32::VTYPE_VILL_BIT})
							for (u32 start : {0u, 1u, 3u, evl, 0xffffffffu})
								cell(s, false, store, vlen, nr, eew, vt, 0,
								     start, prot, 1, eew > 1);
						// Cross a register boundary before denial; VL is still zero.
						cell(s, false, store, vlen, nr, eew, rv32::VTYPE_VILL_BIT, 0,
						     0, prot, evl - 1, false);
					}
				for (u32 vt : {0u, 17u, 24u, 7u})
					for (u32 vl : {0u, 1u, 7u, 8u, 9u,
						       rv32::compute_vlmax(rv32::VType{vt}, vlen)}) {
						if (vl > rv32::compute_vlmax(rv32::VType{vt}, vlen))
							continue;
						u32 evl = (vl + 7) / 8;
						for (u32 start : {0u, 1u, evl, evl + 1, 0xffffffffu})
							cell(s, true, store, vlen, 1, 1, vt, vl, start, prot,
							     1, false);
					}
			}
}
static void native_cells(CPUState *s)
{
	config::rvv_qcg_hit_counter = true;
	config::vlen_bits = 128;
	StateReg regs[] = {{(u16)offsetof(CPUState, gpr), VType::I32, "x0"}};
	StateInfo info{regs, 1};
	for (bool mask : {false, true})
		for (bool store : {false, true})
			for (bool chunks : {false, true}) {
				if (mask && chunks)
					continue;
				Runtime runtime;
				MemArena arena(4u << 20);
				auto *region = arena.New<Region>(&arena, &info);
				Builder b(region->CreateBlock());
				u32 raw = special_word(mask, store, 1, 1);
				auto stub = special_stub(mask, store);
				if (mask)
					b.Create_rvvtypedchunkbegin(
					    0, 16, raw, stub, 1,
					    InstRVVTypedChunkBegin::GuardKind::VTypeInteger);
				else
					b.Create_rvvtypedchunkbegin(
					    16, raw, stub, chunks ? 2 : 1,
					    InstRVVTypedChunkBegin::GuardKind::VlenbRestartable);
				if (!chunks)
					b.Create_vmemorynative(8, 5, mask ? 0 : 1, 1, 1, mask ? 3 : 4, 16,
							       store, false);
				else {
					auto v = VOperand::MakeVVPR(VType::V128, b.CreateVGPR(VType::V128));
					u32 off = offsetof(CPUState, vec) +
						  offsetof(rv32::VectorState, vreg) +
						  8 * rv32::VLEN_MAX_BYTES;
					if (store) {
						b.Create_vstatechunkload(v, off);
						b.Create_vchunkstore(offsetof(CPUState, gpr) + 20, 0, v);
					} else {
						b.Create_vchunkload(v, offsetof(CPUState, gpr) + 20, 0);
						b.Create_vstatechunkstore(off, v);
					}
				}
				b.Create_rvvtypedchunkend(raw, stub);
				qcg::ArchTraits::init();
				auto code = qcg::GenerateCode(&runtime, nullptr, region, 0);
				check(!code.empty(), "special native generation");
				auto *bytes = (u8 *)runtime.mem;
				size_t n = code.size();
				if (bytes[0] == 0x51)
					bytes[n++] = 0x59;
				bytes[n] = 0xc3;
				for (int prot : {PROT_NONE, PROT_READ, PROT_WRITE, PROT_READ | PROT_WRITE})
					for (u32 start : {0u, 1u, 2u, 16u, 0xffffffffu})
						cell(s, mask, store, 128, 1, 1,
						     mask ? 0 : rv32::VTYPE_VILL_BIT, mask ? 16 : 0, start,
						     prot, 1, false, bytes);
			}
}
static void legality_and_wrap(CPUState *s)
{
	// Test the actual certificate predicate, including objects outside store ranges.
	ccrf::read_objects = {{data, data + 8191}};
	for (int prot : {PROT_READ | PROT_WRITE, PROT_READ, PROT_WRITE, PROT_NONE}) {
		check(mmu::mmap(data, 8192, PROT_READ | PROT_WRITE) != MAP_FAILED, "certificate map");
		check(mmu::mprotect(data + 4096, 4096, prot) == 0, "certificate protect");
		check(ccrf::ReadObjectsReadable() == bool(prot & PROT_READ),
		      "actual CCRF read certificate admission");
	}
	ccrf::read_objects.clear();
	for (bool store : {false, true}) {
		cell(s, false, store, 128, 2, 1, 24, 7, 8, PROT_NONE, 10, false);
		cell(s, true, store, 128, 1, 1, 0, 9, 0, PROT_NONE, 1, false, nullptr, 0);
		cell(s, true, store, 128, 1, 1, 0, 9, 0, PROT_READ | PROT_WRITE, 1, false, nullptr, 31);
	}

	config::vlen_bits = 128;
	for (bool store : {false, true}) {
		for (u32 nr : {3u, 5u, 6u, 7u, 8u}) {
			clear(s);
			s->vec.Reset(128);
			s->vec.vtype = rv32::VTYPE_VILL_BIT;
			s->vec.vl = 0;
			s->gpr[5] = 0;
			u32 raw = special_word(false, store, 1, nr, nr == 8 ? 7 : 8);
			auto before = s->vec;
			special_invoke(s, raw, false, store);
			check(s->trapno == rv32::TrapCode::ILLEGAL_INSN && s->vec.vreg == before.vreg,
			      "whole reserved group before access");
		}
		clear(s);
		s->vec.Reset(128);
		s->vec.vtype = rv32::VTYPE_VILL_BIT;
		s->gpr[5] = 0;
		special_invoke(s, special_word(true, store, 1, 1), true, store);
		check(s->trapno == rv32::TrapCode::ILLEGAL_INSN, "mask vill remains illegal");
		check(mmu::mmap(0xfffff000, 4096, PROT_READ | PROT_WRITE) != MAP_FAILED, "special top page");
		for (bool mask : {false, true}) {
			clear(s);
			s->vec.Reset(128);
			s->vec.vtype = 0;
			s->vec.vl = 16;
			s->gpr[5] = 0xffffffff;
			s->vec.vreg[8].fill(0x73);
			auto *top = (u8 *)mmu::g2h(0xffffffff);
			*top = 0x35;
			special_invoke(s, special_word(mask, store, 1, 1), mask, store);
			check(s->vec.vstart == 1 && s->GetUThread()->memory_fault.address == 0 &&
				  s->vec.vl == 16,
			      "special RV32 wrap denied byte");
			check(store ? *top == 0x73 : s->vec.vreg[8][0] == 0x35,
			      "special wrapped completed prefix");
		}
		if (!store) {
			clear(s);
			s->vec.Reset(128);
			s->vec.vtype = rv32::VTYPE_VILL_BIT;
			s->gpr[5] = 0xfffffffe;
			s->vec.vreg[8].fill(0x76);
			auto before = s->vec;
			special_invoke(s, special_word(false, false, 4, 1), false, false);
			check(s->vec.vreg == before.vreg && s->vec.vstart == 0 &&
				  s->GetUThread()->memory_fault.address == 0,
			      "whole wrapped split element atomic denial");
		}
	}
}
static void combined_frames(CPUState *s)
{
	config::vlen_bits = 128;
	StateReg regs[] = {{(u16)offsetof(CPUState, gpr), VType::I32, "x0"}};
	StateInfo info{regs, 1};
	Runtime runtime;
	MemArena arena(4u << 20);
	auto *region = arena.New<Region>(&arena, &info);
	Builder b(region->CreateBlock());
	u32 add = (1u << 25) | (8u << 20) | (8u << 15) | (8u << 7) | 0x57;
	u32 load = special_word(false, false, 1, 1),
	    store = (special_word(false, true, 1, 1) & ~(31u << 15)) | (6u << 15);
	RVVRunMember members[] = {{pc, add, RuntimeStubId::id_rv32_vadd_vv},
				  {pc + 4, load, RuntimeStubId::id_rv32_vlNre},
				  {pc + 8, store, RuntimeStubId::id_rv32_vsNr}};
	b.Create_rvvtypedchunkbegin(0, 16, members, 3, 7,
				    InstRVVTypedChunkBegin::GuardKind::VTypeVlVstartBaseMask,
				    (1u << 5) | (1u << 6), 0u - 16, true);
	auto v = VOperand::MakeVVPR(VType::V128, b.CreateVGPR(VType::V128));
	u32 off = offsetof(CPUState, vec) + offsetof(rv32::VectorState, vreg) + 8 * rv32::VLEN_MAX_BYTES;
	b.Create_vstatechunkload(v, off);
	b.Create_vchunkadd(v, v, v, 1);
	b.Create_vstatechunkstore(off, v);
	b.Create_vchunkload(v, offsetof(CPUState, gpr) + 20, 0);
	b.Create_vstatechunkstore(off, v);
	b.Create_vstatechunkload(v, off);
	b.Create_vchunkstore(offsetof(CPUState, gpr) + 24, 0, v);
	b.Create_rvvtypedchunkend(members, 3);
	qcg::ArchTraits::init();
	auto code = qcg::GenerateCode(&runtime, nullptr, region, 0);
	auto *bytes = (u8 *)runtime.mem;
	size_t n = code.size();
	if (bytes[0] == 0x51)
		bytes[n++] = 0x59;
	bytes[n] = 0xc3;
	for (bool deny_load : {false, true})
		for (bool denied : {false, true}) {
			check(mmu::mmap(data, 8192, PROT_READ | PROT_WRITE) != MAP_FAILED, "run map");
			auto *mem = (u8 *)mmu::g2h(data);
			std::array<u8, 8192> expected_mem;
			for (u32 i = 0; i < 8192; ++i)
				mem[i] = expected_mem[i] = (u8)(i * 7 + 3);
			clear(s);
			s->vec.Reset(128);
			s->vec.vtype = 0;
			s->vec.vl = 16;
			s->vec.vreg[8].fill(0x65);
			auto expected = s->vec;
			for (u32 i = 0; i < 16; ++i)
				expected.vreg[8][i] = 0xca;
			u32 lo = deny_load ? 4088 : 512, so = deny_load ? 512 : 4088;
			s->gpr[5] = data + lo;
			s->gpr[6] = data + so;
			for (u32 i = 0; i < 16; ++i) {
				if (denied && deny_load && i == 8)
					break;
				expected.vreg[8][i] = expected_mem[lo + i];
			}
			if (!(denied && deny_load))
				for (u32 i = 0; i < 16; ++i) {
					if (denied && i == 8)
						break;
					expected_mem[so + i] = expected.vreg[8][i];
				}
			check(mmu::mprotect(data + 4096, 4096, denied ? PROT_NONE : PROT_READ | PROT_WRITE) ==
				  0,
			      "run protect");
			u64 hits = s->rvv_direct_hits, misses = s->rvv_direct_fallbacks;
			if (sigsetjmp(trap_unwind_env, 0) == 0)
				Enter(s, mmu::base, bytes);
			check(s->rvv_direct_hits - hits == 0 &&
				  s->rvv_direct_fallbacks - misses == 1,
			      "actual arithmetic-first/multiple-base run admission");
			check(s->vec.vreg == expected.vreg && s->vec.vl == 16 &&
				  s->vec.vstart == (denied ? 8u : 0u),
			      "run completed arithmetic/memory prefix");
			if (denied) {
				auto const &ev = s->GetUThread()->memory_fault;
				check(s->trapno == rv32::TrapCode::MEMORY_FAULT &&
					  s->ip == pc + (deny_load ? 4 : 8) && ev.pc == s->ip &&
					  ev.raw == (deny_load ? load : store) && ev.address == data + 4096 &&
					  ev.element == 8,
				      "run actual faulting member PC/address");
			} else
				check(s->trapno == rv32::TrapCode::NONE, "run normal completion");
			mmu::mprotect(data + 4096, 4096, PROT_READ | PROT_WRITE);
			check(!memcmp(mem, expected_mem.data(), 8192), "run prior and denied store prefix");
			++cells;
		}
	printf("ACTUAL_QCG_COMBINED native_hits=0 native_fallbacks=4 cells=4\n");
}

int main(int argc, char **argv)
{
	mmu::Init();
	ukernel::process.main_thread = std::make_unique<uthread>();
	auto *s = CPUState::Current();
	config::rvv_verify = false;
	config::rvv_lowering = 0;
	helper_cells(s);
	config::rvv_lowering = 1;
	config::rvv_fixed_copy = true;
	helper_cells(s);
	native_cells(s);
	legality_and_wrap(s);
	combined_frames(s);
	if (argc == 3) {
		for (int i = 1; i <= 2; ++i) {
			auto h = dlopen(argv[i], RTLD_NOW | RTLD_LOCAL);
			check(h != nullptr, "ABI fixture open");
			check(AotAbiCompatible(h, "task118") == (i == 2),
			      "production AOT stale/current gate");
			dlclose(h);
		}
	}
	printf("ACTUAL_QCG_SPECIAL native_hits=%llu native_fallbacks=%llu cells=120\n",
	       (unsigned long long)native_hits, (unsigned long long)native_fallbacks);
	printf("LOCAL_SPECIAL_MEMORY_PASS checks=%u cells=%u ABI=%016llx impl=%zu state=%zu fpu=%zu (no "
	       "guest retry)\n",
	       checks, cells, (unsigned long long)rv32::CPUStateAbiSignature(), sizeof(rv32::CPUStateImpl),
	       sizeof(CPUState), offsetof(CPUState, fpu));
}
