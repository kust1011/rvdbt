#pragma once

#include "dbt/qmc/qir.h"
#include "dbt/qmc/qir_opt.h"

namespace dbt::qir
{

struct Builder {
	explicit Builder() : bb(nullptr), it(nullptr) {}
	explicit Builder(Block *bb_) : bb(bb_), it(bb->ilist.end()) {}
	explicit Builder(Block *bb_, IListIterator<Inst> it_) : bb(bb_), it(it_) {}
	NO_COPY(Builder)
	DEFAULT_MOVE(Builder)

	auto GetIterator() const
	{
		return it;
	}

	Block *GetBlock() const
	{
		return bb;
	}

	Block *CreateBlock() const
	{
		return bb->GetRegion()->CreateBlock();
	}

	RegN CreateVGPR(VType type) const
	{
		return bb->GetRegion()->GetVRegsInfo()->AddLocal(type);
	}

	// M2E: storage for a run frame's ordered member list, with the REGION's lifetime.
	// InstRVVTypedChunkEnd borrows the array rather than copying it (qir.h), so it must not be a
	// caller's local; this is the one place that allocation happens.
	RVVRunMember *CreateRunMembers(u8 n) const
	{
		if (n == 0 || n > RVV_RUN_MAX_MEMBERS) {
			Panic("qir: run member array size out of range");
		}
		auto *arena = bb->GetRegion()->GetArena();
		auto *p = (RVVRunMember *)arena->Allocate(sizeof(RVVRunMember) * n,
							  alignof(RVVRunMember));
		if (!p) {
			Panic("qir: out of arena for a run member array");
		}
		for (u8 i = 0; i < n; ++i) {
			new (&p[i]) RVVRunMember();
		}
		return p;
	}

private:
	using Flags = Inst::Flags;

public:
#define OP(name, cls, flags)                                                                                 \
	template <typename... Args>                                                                          \
	Inst *Create_##name(Args &&...args)                                                                  \
	{                                                                                                    \
		return Create<cls>(Flags(flags), Op::_##name, std::forward<Args>(args)...);                  \
	}
	QIR_LEAF_OPS_LIST(OP)
#undef OP

#define OP(name, cls, flags)                                                                                 \
	template <typename... Args>                                                                          \
	Inst *Create_##name(Args &&...args)                                                                  \
	{                                                                                                    \
		return Create<cls>(Flags(flags), std::forward<Args>(args)...);                               \
	}
	QIR_BASE_OPS_LIST(OP)
#undef OP

#define CLASS(cls, beg, end)                                                                                 \
	template <typename... Args>                                                                          \
	Inst *Create##cls(Op op, Args &&...args)                                                             \
	{                                                                                                    \
		return Create<cls>(GetOpFlags(op), std::forward<Args>(args)...);                             \
	}
	QIR_CLASS_LIST(CLASS)
#undef CLASS

private:
	template <typename T, typename... Args>
	requires std::is_base_of_v<Inst, T> Inst *Create(Args &&...args)
	{
		auto *ins = bb->GetRegion()->Create<T>(std::forward<Args>(args)...);
		bb->ilist.insert(it, *ins);
		return ApplyFolder(bb, ins);
	}

	Block *bb;
	IListIterator<Inst> it;
};

} // namespace dbt::qir
