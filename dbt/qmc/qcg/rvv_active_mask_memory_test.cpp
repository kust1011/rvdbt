#define main ExistingMemoryMain
#include "dbt/qmc/qcg/rvv_vlse_gather_value_test.cpp"
#undef main
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>

void BuildMasked(Emitted &e, u32 width, u32 sew, u32 lmul, u32 mode, bool store, u32 nf)
{
    ApplyCfg(width, false);
    config::rvv_qcg_active_mask_memory = true;
    Region *region = e.arena.New<Region>(&e.arena, &state_info);
    Builder b(region->CreateBlock());
    b.Create_vmemorynative(8, 16, mode == 2 ? 24 : 5, sew, sew, mode,
                          width/8, store, true, nf, lmul, lmul*width/(8*sew));
    qcg::ArchTraits::init();
    auto code = qcg::GenerateCode(&e.rt, nullptr, region, 0);
    CHECK_MSG(!code.empty(), "empty masked memory code");
    e.code = code.data();
    e.bytes = code.size();
    size_t n = e.bytes;
    if (e.code[0] == 0x51)
        e.code[n++] = 0x59;
    e.code[n] = 0xc3;
}

u8 &RegisterByte(rv32::VectorState &v, u32 first, u32 offset, u32 bytes)
{
    return v.vreg[first + offset/bytes][offset%bytes];
}

void CheckShape(u32 width, u32 sew, u32 lmul, u32 mode, bool store, u32 nf)
{
    Emitted e;
    BuildMasked(e, width, sew, lmul, mode, store, nf);
    u32 const capacity = lmul*width/(8*sew), bytes = width/8;
    unsigned cells = 0;
    for (u32 vl : {0u, 1u, capacity/2, capacity-1, capacity})
    for (u32 start : {0u, 1u, vl/2, vl})
    for (u32 mask : {0u, 1u, 2u, 3u, 4u, 5u}) {
        CPUState st(nullptr);
        memset(&st, 0, sizeof(st));
        st.vec.vlenb = bytes;
        st.vec.vl = vl;
        st.vec.vstart = start;
        st.gpr[16] = REGION_LOW;
        st.gpr[5] = nf*sew*2;
        for (u32 r=0; r<32; ++r)
            for (u32 i=0; i<512; ++i)
                st.vec.vreg[r][i] = (u8)(r*19+i*7);
        memset(st.vec.vreg[0].data(), 0, 512);
        for (u32 i=0; i<capacity; ++i) {
            bool const on = mask==1 || (mask==2 && i<8) || (mask==3 && i%67==0) ||
                            (mask==4 && (i==63 || i==64 || i==127 || i==capacity-1)) ||
                            (mask==5 && ((i*17+31)%11 < 5));
            if (on) st.vec.vreg[0][i/8] |= 1u<<(i%8);
            u64 offset = (u64)i*nf*sew*2;
            for (u32 b=0; b<sew; ++b)
                RegisterByte(st.vec, 24, i*sew+b, bytes) = offset>>(8*b);
        }
        for (u32 i=0; i<REGION_BYTES; ++i)
            g_base[REGION_LOW+i] = PatternByte(REGION_LOW+i);
        std::vector<u8> memory(g_base+REGION_LOW, g_base+REGION_LOW+REGION_BYTES);
        auto expected = st.vec;
        for (u32 i=start; i<vl; ++i) {
            if (!(expected.vreg[0][i/8] & (1u<<(i%8)))) continue;
            u32 offset = i*nf*sew;
            if (mode==1) offset = i*st.gpr[5];
            if (mode==2) {
                u64 index=0;
                for (u32 b=0; b<sew; ++b)
                    index |= (u64)RegisterByte(expected,24,i*sew+b,bytes)<<(8*b);
                offset = (u32)index;
            }
            for (u32 field=0; field<nf; ++field)
                for (u32 b=0; b<sew; ++b) {
                    auto &reg = RegisterByte(expected,8+field*lmul,i*sew+b,bytes);
                    auto &mem = memory.at(offset+field*sew+b);
                    if (store) mem=reg; else reg=mem;
                }
        }
        expected.vstart=0;
        Enter(&st,g_base,e.code);
        CHECK_MSG(memcmp(st.vec.vreg.data(),expected.vreg.data(),sizeof(st.vec.vreg))==0 && st.vec.vstart==0,
                  "register state width=%u sew=%u lmul=%u mode=%u store=%d nf=%u vl=%u start=%u mask=%u",
                  width,sew,lmul,mode,store,nf,vl,start,mask);
        CHECK_MSG(memcmp(g_base+REGION_LOW,memory.data(),memory.size())==0,
                  "memory state width=%u mode=%u store=%d mask=%u",width,mode,store,mask);
        ++cells;
    }
    printf("MASK_SHAPE width=%u sew=%u lmul=%u mode=%u store=%d nf=%u cells=%u\n",
           width,sew,lmul,mode,store,nf,cells);
}

CPUState *fault_state;
void FaultHandler(int) { _exit(fault_state->vec.vstart==300 ? 0 : 3); }

void CheckFaultBoundary()
{
    Emitted e;
    BuildMasked(e,4096,1,1,0,false,1);
    CPUState st(nullptr);
    memset(&st,0,sizeof(st));
    st.vec.vlenb=512; st.vec.vl=512;
    st.gpr[16]=REGION_LOW+REGION_BYTES-8;
    st.vec.vreg[0][0]=0x80;
    Enter(&st,g_base,e.code); // Every address after lane 7 is inaccessible but masked off.
    CHECK_MSG(st.vec.vstart==0, "masked-off inaccessible suffix must complete normally");
    pid_t const child=fork();
    CHECK_MSG(child>=0,"fork failed");
    if (child==0) {
        st.vec.vreg[0][300/8] |= 1u<<(300%8);
        fault_state=&st;
        signal(SIGSEGV,FaultHandler);
        Enter(&st,g_base,e.code);
        _exit(4);
    }
    if (child>0) {
        int status=0;
        waitpid(child,&status,0);
        CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status)==0,
                  "fault must publish the first active faulting lane, status=%d",status);
    }
}

int main()
{
    config::rvv_qcg_active_mask_memory=true;
    ExistingMemoryMain(); // Includes RV32 wrap, signed strides, and nonzero vstart.
    for (u32 width : {128u,256u,512u,1024u,2048u,4096u})
    for (u32 sew : {1u,2u,4u,8u})
    for (u32 lmul : {1u,2u})
    for (u32 mode : {0u,1u,2u})
    for (bool store : {false,true})
    for (u32 nf : {1u,2u})
        CheckShape(width,sew,lmul,mode,store,nf);
    CheckShape(4096,1,8,0,false,1);
    CheckShape(4096,1,8,0,true,1);
    CheckFaultBoundary();
    printf("ACTIVE_MASK_MEMORY checks=%d failures=%d\n",g_checks,g_failures);
    return g_failures ? 1 : 0;
}
