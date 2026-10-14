// Independent review probe. Never executes guest instructions or edits production.
// Published V1.0 section Vector Operands reserves different source-EEW aliases.
// Reserved admissions are observations, NOT a mandatory illegal-trap verdict.
#include "dbt/guest/rv32_vector_lower.h"
#include <cstdio>

using namespace dbt::rv32;
struct Row {
    const char *name;
    u32 vt, width, mop, nf, data, index;
    bool store, vm, ordinary;
};

int main()
{
    const Row rows[] = {
        {"masked-unit-store-v0",0,0,0,1,0,16,true,false,false},
        {"masked-unit-store-neighbor",0,0,0,1,8,16,true,false,true},
        {"masked-segment-store-v0",0,0,0,2,0,16,true,false,false},
        {"masked-segment-store-neighbor",0,0,0,2,8,16,true,false,true},
        {"masked-index-load-index-v0",0,0,1,1,8,0,false,false,false},
        {"masked-index-load-neighbor",0,0,1,1,8,16,false,false,true},
        {"masked-index-segment-index-v0",0,0,3,2,8,0,false,false,false},
        {"masked-index-segment-neighbor",0,0,3,2,8,16,false,false,true},
        {"mixed-source-index-store",0,5,1,1,8,8,true,true,false},
        {"mixed-source-index-store-neighbor",0,5,1,1,8,16,true,true,true},
        {"mixed-source-second-segment-field",7,5,3,2,8,9,true,true,false},
        {"mixed-source-second-segment-field-neighbor",7,5,3,2,8,16,true,true,true},
        {"equal-width-index-store-alias",0,0,1,1,8,8,true,true,true},
        {"load-low-overlap",0,5,1,1,8,8,false,true,true},
        {"load-high-overlap",17,5,1,1,8,9,false,true,true},
        {"fractional-equal-width-last-register",5,0,1,1,31,31,false,true,true},
        {"fractional-masked-store-v0",5,0,0,1,0,16,true,false,false},
        {"fractional-masked-store-neighbor",5,0,0,1,31,16,true,false,true},
    };
    unsigned refused_ordinary = 0, reserved_admitted = 0;
    for (auto const &r : rows) {
        VType vt{r.vt};
        bool admitted;
        if (r.nf == 1)
            admitted = vmemory_registers_legal(vt,r.width,r.mop,r.data,r.index,r.store,r.vm);
        else
            admitted = vseg_registers_legal(vseg_shape(r.width,r.mop,r.nf-1,vt),
                                            r.data,r.index,!r.store,r.vm);
        refused_ordinary += r.ordinary && !admitted;
        reserved_admitted += !r.ordinary && admitted;
        std::printf("%s\t%s\t%s\n", r.name,
                    r.ordinary ? "ordinary" : "reserved-source-EEW",
                    admitted ? "admit" : "refuse");
    }
    std::printf("RESULT rows=18 legal_refusals=%u reserved_admissions=%u\n",
                refused_ordinary,reserved_admitted);
    return refused_ordinary != 0;
}
