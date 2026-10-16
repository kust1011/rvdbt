#pragma once
#include "dbt/util/common.h"

namespace dbt::rv32::memory_admission
{
// Internal owned affine scalar-frame contract, never architectural instruction
// bits. Guard callers prove exact VLEN/vtype, bounded VL and register legality;
// operands, mask, VL/vstart, mappings and directional permissions remain live.
// MEW/bit6 distinguish descriptors in the existing native-memory runtime slot.
constexpr u32 tag = (1u << 28) | (1u << 6);
constexpr u32 encode(u32 base_reg, u32 stride_reg, u32 eew, u32 nf,
                     bool store, bool masked, bool unit)
{
 return tag | (base_reg << 15) | (stride_reg << 20) | (eew << 8) |
        ((nf - 1u) << 25) | u32(store) | (u32(masked) << 1) | (u32(unit) << 2);
}
constexpr u32 eew(u32 descriptor) { return (descriptor >> 8) & 15u; }
constexpr u32 shape(u32 descriptor)
{
 return ((descriptor >> 25) & 7u) | ((descriptor & 2u) << 2);
}
constexpr u32 fields(u32 shape) { return (shape & 7u) + 1u; }
constexpr bool masked(u32 shape) { return shape & 8u; }
}
