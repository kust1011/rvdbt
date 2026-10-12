// Actual scanner admission, plus reused production translator/route assertions.
#define main ExistingMemoryRouteMain
#include "dbt/qmc/qcg/rvv_run_mem_member_test.cpp"
#undef main
#include "dbt/guest/rv32_vrun.h"
namespace run = dbt::rv32::rvvrun;
static run::MemberShape admit(void *,run::MemberQuery const &) {return {1,64};}
int main()
{
 ApplyEnv(512); config::rvv_run_scalar_passthrough=true;
 u32 add=(1u<<25)|(2u<<20)|(1u<<15)|(3u<<7)|0x57;
 u32 update=(64u<<20)|(14u<<15)|(14u<<7)|0x13;
 struct Row {const char *name;std::vector<u32> words;unsigned members;run::CutReason cut;};
 std::vector<Row> rows={
  {"scalar writes later load base",{add,update,VlNre32(1,14,8)},1,run::CutReason::ScalarInsn},
  {"scalar writes later store base",{VlNre32(1,14,8),update,VsNr(1,14,8)},1,run::CutReason::ScalarInsn},
  {"unrelated scalar bridge",{VlNre32(1,14,8),update^(14u<<7)^(15u<<7),VsNr(1,14,8)},3,run::CutReason::RegionBoundary},
  {"base changes after its final access",{VlNre32(1,14,8),update,VsNr(1,15,8)},3,run::CutReason::RegionBoundary},
  {"arithmetic then two bases",{add,VlNre32(1,14,8),VsNr(1,15,8)},3,run::CutReason::RegionBoundary},
  {"vset geometry barrier",{add,VSetVli(6),VlNre32(1,14,8)},1,run::CutReason::GuardStateWrite},
  {"vstart CSR barrier",{add,(8u<<20)|(14u<<15)|(1u<<12)|0x73,VlNre32(1,14,8)},1,run::CutReason::ScalarInsn},
  {"unit memory barrier",{add,0x02076407},1,run::CutReason::VectorMemory},
  {"strided memory barrier",{add,0x0ae76407},1,run::CutReason::VectorMemory},
  {"indexed memory barrier",{add,0x06a76407},1,run::CutReason::VectorMemory},
  {"mask memory barrier",{add,0x02b70407},1,run::CutReason::VectorMemory},
  {"segment memory barrier",{add,0x22076407},1,run::CutReason::VectorMemory},
  {"v0 changes before whole memory",{add^(3u<<7),VlNre32(1,14,8)},2,run::CutReason::RegionBoundary}
 };
 for(auto &row:rows) {
  auto d=run::FormRun((uptr)row.words.data(),0,row.words.size()*4,32,{16,true},{},512,{}, {admit,nullptr});
  CHECK_EQ(d.n_members,row.members);CHECK(d.cut==row.cut);
  if(row.members==3)CHECK(d.has_mem);
  printf("SCANNER %s members=%u cut=%s\n",row.name,d.n_members,run::CutReasonName(d.cut));
 }
 // Route-owned admission, not the permissive shape stub used to isolate the scanner above.
 CheckMulRun(512,1);CheckMaccRun(512,1);CheckCuts(512);
 printf("SCANNER_CHECK %s rows=%zu failures=%d\n",g_failures?"FAIL":"PASS",rows.size(),g_failures);
 return g_failures?1:0;
}
