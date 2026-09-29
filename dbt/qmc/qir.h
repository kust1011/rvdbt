#pragma once

#include "dbt/arena_objects.h"
#include "dbt/qmc/ilist.h"
#include "dbt/qmc/qir_ops.h"
#include "dbt/qmc/runtime_stubs.h"
#include "dbt/guest/rv32_vector.h"
#include "dbt/util/bitfield.h"
#include "dbt/util/logger.h"

#include <array>
#include <bit>
#include <vector>

namespace dbt::qcg
{
struct RAOpCt;
};

namespace dbt::qir
{
LOG_STREAM(qir);

// T6b. THE WIDEST GUEST VECTOR REGISTER A CHUNK ROUTE MAY SPAN, in 64-byte host chunks.
//
// The structural bounds on this file's chunk ops (a displacement, a `vlenb`) used to be written as
// the literal widths the admitted routes happened to reach -- `3 * CHUNK_BYTES`, `64 or 128`. Those
// literals were correct for a route set that stopped at VLEN=1024 and became a HARD FAILURE the
// moment one did not: a k=8 frame would have Panic'd here on its fifth chunk rather than been
// refused at admission. The bound is now the same quantity the admission side derives, so widening
// a route's admitted VLEN cannot leave a node constructor behind.
//
// It is `VLEN_MAX_BITS / 512`: the widest register the guest's storage reservation permits divided
// by the host chunk width. That is the SAME derivation `rvvrun::kMaxChunks` (dbt/guest/rv32_vrun.h)
// makes, and rv32_qir.cpp static_asserts the two agree -- neither file may include the other's
// header, so the cross-check is placed where both are visible rather than the constant duplicated
// silently. This is an UPPER BOUND on what a route may build, never a statement that any route
// admits it: which VLENs are admitted is the admission predicates' business alone.
static constexpr u32 MAX_REG_CHUNKS = rv32::VLEN_MAX_BITS / 512;

template <typename D, typename B>
requires std::is_base_of_v<B, D> ALWAYS_INLINE D *as(B *b)
{
	if (!D::classof(b)) {
		return nullptr;
	}
	return static_cast<D *>(b);
}

template <typename D, typename B>
ALWAYS_INLINE D *cast(B *b)
{
	auto res = as<D>(b);
	assert(res);
	return res;
}

enum class Op : u8 {
#define OP(name, base, flags) _##name,
#define CLASS(cls, beg, end) cls##_begin = _##beg, cls##_end = _##end,
	QIR_OPS_LIST(OP) QIR_CLASS_LIST(CLASS)
#undef OP
#undef CLASS
	    Count,
};

struct OpInfo {
	OpInfo() = delete;
	constexpr OpInfo(char const *name_, u8 n_out_, u8 n_in_) : name(name_), n_out(n_out_), n_in(n_in_) {}

	char const *name;
	const u8 n_out;
	const u8 n_in;

	qcg::RAOpCt const *ra_ct{};
	u8 const *ra_order{};
};

extern OpInfo op_info[to_underlying(qir::Op::Count)];

inline OpInfo const &GetOpInfo(qir::Op op)
{
	return op_info[to_underlying(op)];
}

enum class VType : u8 {
	UNDEF,
	I8,
	I16,
	I32,
	// Prior-art RVV substrate: one fixed AVX-512 legalization chunk and one
	// architectural mask word.  These are real QIR SSA value types; they are
	// intentionally not encoded as state-only metadata on an opaque opcode.
	V512,
	MASK64,
	// M2C.  The host vector width is a property of the VALUE, not of the emitter.
	//
	// A guest vector register is VLEN/8 architectural bytes wide.  Lowering it as a fixed
	// 64-byte chunk is only exact when VLEN >= 512; below that a 64-byte load reads, and a
	// 64-byte store WRITES, bytes outside the architectural register.  Encoding the width in the
	// type is what makes every dependent quantity derive from one fact instead of from a
	// per-site constant: VTypeToSize gives the CPUState window, the spill-slot size
	// (QRegAlloc::AllocFrameSlot), the `Mem` operand size (QEmit::make_slot) and the host
	// register form (QEmit::make_vpr) -- and the chunk ops' own constructors reject a mismatched
	// operand set before any of that runs.
	//
	// Appended rather than inserted next to V512 so that no existing VType's numeric value
	// moves. Count changes from 6 to 8, but enum_bits(VType::Count) remains 3, so VOperand's
	// bitfield layout is byte-for-byte what it was.
	V128,
	V256,
	Count,
};

// The three host vector widths, and the ONLY mapping between a byte count and a vector VType.
// Every width decision in the RVV lowering goes through these two functions, which is what keeps
// "16/32/64" from becoming a literal repeated at each site.
inline bool IsVectorVType(VType type)
{
	return type == VType::V128 || type == VType::V256 || type == VType::V512;
}

inline u8 VTypeToSize(VType type)
{
	switch (type) {
	case VType::I8:
		return 1;
	case VType::I16:
		return 2;
	case VType::I32:
		return 4;
	case VType::V128:
		return 16;
	case VType::V256:
		return 32;
	case VType::V512:
		return 64;
	case VType::MASK64:
		return 8;
	default:
		unreachable("");
	}
}

// The inverse of VTypeToSize over the vector widths. Fails closed: a byte count that is not one of
// the three host vector widths has no representation here, and inventing one silently is exactly
// how a "128-bit" value would end up moved by a 64-byte access.
inline VType VectorVTypeForBytes(u32 bytes)
{
	switch (bytes) {
	case 16:
		return VType::V128;
	case 32:
		return VType::V256;
	case 64:
		return VType::V512;
	default:
		Panic("qir: no vector value type for this host chunk width");
	}
}

// QCG host register classes.  A value's class is a pure function of its VType, so the register
// allocator never has to infer it from context: scalar values live in the 16 general-purpose
// registers, V512 chunks live in the AVX-512 ZMM file, and the two physical files are tracked
// completely independently (see QRegAlloc: separate p2v maps, separate fixed/avoid masks,
// separate AllocPReg).  A register number is only meaningful together with its class.
//
// NONE covers types QCG has no register file for.  MASK64 would map to the AVX-512 k-registers,
// which are not implemented here -- MASK64 only ever reaches the LLVM backend today (RvvSSAEnabled
// requires config::aot_use_llvm).  Asking the allocator for a NONE value fails closed with a
// Panic rather than silently landing in the GPR file.
enum class RegClass : u8 {
	GPR,
	VPR,
	NONE,
};

inline RegClass VTypeToRegClass(VType type)
{
	switch (type) {
	case VType::I8:
	case VType::I16:
	case VType::I32:
		return RegClass::GPR;
	// All three vector widths share ONE physical file: xmm<n>, ymm<n> and zmm<n> are the same
	// architectural register seen at three widths, so a narrower value needs no separate class,
	// no separate RegMask and no allocator change. What differs is only how much of that
	// register a value occupies -- which VTypeToSize already says.
	case VType::V128:
	case VType::V256:
	case VType::V512:
		return RegClass::VPR;
	default:
		return RegClass::NONE;
	}
}

enum class VSign : u8 {
	U = 0,
	S = 1,
};

using RegN = u16;
static constexpr auto RegNBad = static_cast<RegN>(-1);

struct VOperand {
private:
	enum class Kind : u8 {
		CONST = 0,
		GPR,
		// A vector register (RegClass::VPR).  A separate Kind, not a flavour of GPR, so that
		// every existing IsGPR()/IsVGPR()/IsPGPR() test in the scalar paths answers false for a
		// vector operand and those paths cannot accidentally treat a ZMM number as a GPR number.
		VPR,
		SLOT,
		BAD,
		Count,
	};

	VOperand(uptr value_) : value(value_) {}

public:
	explicit VOperand() : value(f_kind::encode(uptr(0), Kind::BAD)) {}

	DEFAULT_COPY(VOperand)
	DEFAULT_MOVE(VOperand)

	static VOperand MakeVGPR(VType type, RegN reg)
	{
		uptr value = 0;
		value = f_kind::encode(value, Kind::GPR);
		value = f_type::encode(value, type);
		value = f_is_virtual::encode(value, true);
		value = f_reg::encode(value, reg);
		return VOperand(value);
	}

	static VOperand MakePGPR(VType type, RegN reg)
	{
		uptr value = 0;
		value = f_kind::encode(value, Kind::GPR);
		value = f_type::encode(value, type);
		value = f_reg::encode(value, reg);
		return VOperand(value);
	}

	// Vector counterparts of MakeVGPR/MakePGPR.  `reg` is a VPR number: a virtual register index
	// into VRegsInfo for MakeVVPR (the virtual index space is shared with GPRs -- one region-wide
	// vreg array -- which is why the *class* travels with the operand), and a ZMM number in
	// [0, ArchTraits::VPR_NUM) for MakePVPR.
	static VOperand MakeVVPR(VType type, RegN reg)
	{
		uptr value = 0;
		value = f_kind::encode(value, Kind::VPR);
		value = f_type::encode(value, type);
		value = f_is_virtual::encode(value, true);
		value = f_reg::encode(value, reg);
		return VOperand(value);
	}

	static VOperand MakePVPR(VType type, RegN reg)
	{
		uptr value = 0;
		value = f_kind::encode(value, Kind::VPR);
		value = f_type::encode(value, type);
		value = f_reg::encode(value, reg);
		return VOperand(value);
	}

	static VOperand MakeConst(VType type, u32 cval)
	{
		uptr value = 0;
		value = f_kind::encode(value, Kind::CONST);
		value = f_type::encode(value, type);
		value = f_const::encode(value, cval);
		return VOperand(value);
	}

	static VOperand MakeSlot(bool is_glob, VType type, u16 offs)
	{
		uptr value = 0;
		value = f_kind::encode(value, Kind::SLOT);
		value = f_type::encode(value, type);
		value = f_slot_offs::encode(value, offs);
		value = f_slot_is_global::encode(value, is_glob);
		return VOperand(value);
	}

	VType GetType() const
	{
		return static_cast<VType>(f_type::decode(value));
	}

	bool IsConst() const
	{
		return GetKind() == Kind::CONST;
	}

	// preg or vreg
	bool IsGPR() const
	{
		return GetKind() == Kind::GPR;
	}

	// preg or vreg
	bool IsVPR() const
	{
		return GetKind() == Kind::VPR;
	}

	bool IsSlot() const
	{
		return GetKind() == Kind::SLOT;
	}

	bool IsBad() const
	{
		return GetKind() == Kind::BAD;
	}

	bool IsV() const
	{
		assert(IsGPR());
		return FlagV();
	}

	bool IsPGPR() const
	{
		return IsGPR() && !FlagV();
	}

	bool IsVGPR() const
	{
		return IsGPR() && FlagV();
	}

	bool IsPVPR() const
	{
		return IsVPR() && !FlagV();
	}

	bool IsVVPR() const
	{
		return IsVPR() && FlagV();
	}

	// Class-agnostic virtual-register test, for the register allocator's dispatch only.  Use
	// GetRegClass() to decide which physical file the result belongs to; never assume GPR.
	bool IsVirtualReg() const
	{
		return (IsGPR() || IsVPR()) && FlagV();
	}

	RegN GetVirtualReg() const
	{
		assert(IsVirtualReg());
		return f_reg::decode(value);
	}

	RegClass GetRegClass() const
	{
		assert(IsGPR() || IsVPR());
		return IsVPR() ? RegClass::VPR : RegClass::GPR;
	}

	bool IsGSlot() const
	{
		return IsSlot() && f_slot_is_global::decode(value);
	}

	bool IsLSlot() const
	{
		return IsSlot() && !f_slot_is_global::decode(value);
	}

	u32 GetConst() const
	{
		assert(IsConst());
		return f_const::decode(value);
	}

	RegN GetPGPR() const
	{
		assert(IsPGPR());
		return f_reg::decode(value);
	}

	RegN GetVGPR() const
	{
		assert(IsVGPR());
		return f_reg::decode(value);
	}

	RegN GetPVPR() const
	{
		assert(IsPVPR());
		return f_reg::decode(value);
	}

	RegN GetVVPR() const
	{
		assert(IsVVPR());
		return f_reg::decode(value);
	}

	u16 GetSlotOffs() const
	{
		assert(IsSlot());
		return f_slot_offs::decode(value);
	}

private:
	Kind GetKind() const
	{
		return static_cast<Kind>(f_kind::decode(value));
	}

	bool FlagV() const
	{
		return f_is_virtual::decode(value);
	}

	uptr value{0};

	using f_kind = bf_first<std::underlying_type_t<Kind>, enum_bits(Kind::Count)>;
	using f_type = f_kind::next<std::underlying_type_t<VType>, enum_bits(VType::Count)>;
	using f_is_virtual = f_type::next<bool, 1>;
	using last_ = f_is_virtual;

	static constexpr auto data_bits = bit_size<uptr> - last_::container_size;
	using f_reg = last_::next<RegN, bit_size<RegN>>;
	using f_const = last_::next<u32, 32>; // TODO: cpool
	using f_slot_offs = last_::next<u16, 16>;
	using f_slot_is_global = f_slot_offs::next<bool, 1>;
};

struct VOperandSpan {
	VOperandSpan(VOperand *head_, u8 size_) : head(head_), len(size_) {}

	VOperand &operator[](u8 idx) const
	{
		assert(idx < len);
		return head[-idx];
	}

	u8 size() const
	{
		return len;
	}

private:
	VOperand *head;
	u8 len;
};

template <typename Derived>
struct InstOperandAccessMixin {
	VOperand &o(u8 idx)
	{
		assert(idx < d()->OutputCount());
		return d()->GetOperand(idx);
	}

	VOperand &i(u8 idx)
	{
		assert(idx < d()->InputCount());
		return d()->GetOperand(idx + d()->OutputCount());
	}

	VOperandSpan outputs()
	{
		return VOperandSpan(&d()->GetOperand(0), d()->OutputCount());
	}

	VOperandSpan inputs()
	{
		return VOperandSpan(&d()->GetOperand(d()->OutputCount()), d()->InputCount());
	}

private:
	Derived *d()
	{
		return static_cast<Derived *>(this);
	}
};

struct alignas(alignof(VOperand)) Inst : IListNode<Inst>, InstOperandAccessMixin<Inst>, InArena {
	friend struct InstOperandAccessMixin<Inst>;

	enum Flags : u8 { // TODO: enum class
		SIDEEFF = 1 << 0,
		REXIT = 1 << 1,
		HAS_CALLS = 1 << 2,
		HAS_LOADS = 1 << 3,
		HAS_STORES = 1 << 4,
		HAS_BRCC = 1 << 5,
	};

	Op GetOpcode() const
	{
		return opcode;
	}

	u32 GetId() const
	{
		return id;
	}

	Flags GetFlags() const
	{
		return flags;
	}

	void SetFlags(Flags flags_)
	{
		flags = flags_;
	}

	auto OutputCount() const
	{
		return GetOpInfo(GetOpcode()).n_out;
	}

	auto InputCount() const
	{
		return GetOpInfo(GetOpcode()).n_in;
	}

protected:
	Inst(Op opcode_) : opcode(opcode_) {}

	VOperand &GetOperand(u8 idx)
	{
		return reinterpret_cast<VOperand *>(this)[-1 - idx];
	}

private:
	template <typename T, typename... Args>
	requires std::is_base_of_v<Inst, T>
	static T *New(MemArena *arena, u32 id, Flags flags, Args &&...args)
	{
		size_t n_ops = T::OutputCount() + T::InputCount();
		size_t ops_size = sizeof(VOperand) * n_ops;
		auto *mem = arena->Allocate(ops_size + sizeof(T), alignof(VOperand));
		auto res = new ((u8 *)mem + ops_size) T(std::forward<Args>(args)...);
		res->id = id;
		res->flags = flags;
		return res;
	}

	NO_COPY(Inst)
	NO_MOVE(Inst)

	friend struct Region;

	u32 id{(u32)-1};
	Op opcode;
	Flags flags{};
};

inline Inst::Flags GetOpFlags(Op op)
{
	using Flags = Inst::Flags;
	switch (op) {
#define OP(name, base, flags)                                                                                \
	case Op::_##name:                                                                                    \
		return Inst::Flags(flags);
		QIR_OPS_LIST(OP)
#undef OP
	default:
		unreachable("");
	};
}

struct InstNoOperands : Inst {
protected:
	InstNoOperands(Op opcode_) : Inst(opcode_) {}

public:
	constexpr static auto OutputCount()
	{
		return 0;
	}

	constexpr static auto InputCount()
	{
		return 0;
	}

	static constexpr u8 n_out = 0;
	static constexpr u8 n_in = 0;
};

template <size_t N_OUT, size_t N_IN>
struct InstWithOperands : Inst, InstOperandAccessMixin<InstWithOperands<N_OUT, N_IN>> {
	friend struct InstOperandAccessMixin<InstWithOperands<N_OUT, N_IN>>;

protected:
	InstWithOperands(Op opcode_, std::array<VOperand, N_OUT> &&o_, std::array<VOperand, N_IN> &&i_)
	    : Inst(opcode_)
	{
		// TODO: iterators
		for (u8 k = 0; k < N_OUT; ++k)
			GetOperand(k) = o_[k];
		for (u8 k = 0; k < N_IN; ++k)
			GetOperand(N_OUT + k) = i_[k];
	}

public:
	constexpr static auto OutputCount()
	{
		return N_OUT;
	}

	constexpr static auto InputCount()
	{
		return N_IN;
	}

	using InstOperandAccessMixin::i;
	using InstOperandAccessMixin::inputs;
	using InstOperandAccessMixin::o;
	using InstOperandAccessMixin::outputs;

	static constexpr u8 n_out = N_OUT;
	static constexpr u8 n_in = N_IN;
};

/* Common classes */

struct InstUnop : InstWithOperands<1, 1> {
	InstUnop(Op opcode_, VOperand d, VOperand s) : InstWithOperands(opcode_, {d}, {s})
	{
		assert(HasOpcode(opcode_));
	}

	static bool classof(Inst *op)
	{
		return HasOpcode(op->GetOpcode());
	}

	static bool HasOpcode(Op opcode)
	{
		return opcode >= Op::InstUnop_begin && opcode <= Op::InstUnop_end;
	}
};

struct InstBinop : InstWithOperands<1, 2> {
	InstBinop(Op opcode_, VOperand d, VOperand sl, VOperand sr) : InstWithOperands(opcode_, {d}, {sl, sr})
	{
		assert(HasOpcode(opcode_));
	}

	static bool classof(Inst *op)
	{
		return HasOpcode(op->GetOpcode());
	}

	static bool HasOpcode(Op opcode)
	{
		return opcode >= Op::InstBinop_begin && opcode <= Op::InstBinop_end;
	}
};

/* Custom classes */

struct Block;

struct InstBr : InstNoOperands {
	InstBr(u32 ip, bool backedge_ = false) : InstNoOperands(Op::_br), ip(ip), backedge(backedge_) {}

	u32 ip;
	// T5d2a1: true iff this INTRA-REGION edge came from a direct guest transfer whose
	// architectural target does not lie above the branch instruction -- the same predicate, on the
	// same two quantities, that InstGBr::backedge uses. Set only by the translator.
	//
	// WHY IT HAS TO EXIST HERE TOO. A tight guest loop whose latch targets its own region entry
	// never becomes a gbr at all (RV32Translator::MakeGBr's ip2bb hit path), so on the frozen GEMM
	// the hottest loop headers -- the ones the selector picks -- update their Wendell counter from
	// HERE and never from a gbr. A crossing test that only knew about gbr edges therefore saw
	// events only from blocks that were not loop headers, which is measured evidence, not a guess:
	// raw/T5D2A1_ARTIFACTS_*/local_gbr_only.stderr is the run that showed it.
	//
	// WHERE THE REQUEST IT RAISES IS CONSUMED depends on one default-off switch, and the two cases
	// are different claims. This edge still carries no T5d0 safepoint -- that mechanism belongs to
	// a gbr's branch slot and there is no slot here.
	//
	//   --loop-tier-side-exit OFF (the default, and T5d2a1/T5d2a2's behaviour): the request stays
	//     raised until the guest reaches the next gbr BACKEDGE and takes its T5d0 safepoint. On the
	//     frozen GEMM that happens a few instructions later; in general it is not bounded at all,
	//     because a loop whose hot path lies wholly inside one region reaches no gbr.
	//   --loop-tier-side-exit ON (T5d2a3): QEmit::Emit_Cache appends one `jmp`, behind T5d2a2's
	//     four guards and the one-shot claim, into an out-of-line block that commits the pinned
	//     guest globals, restores the frame, stores THIS edge's own target guest PC and leaves
	//     through the same escape_link stub with a real BranchSlot. Control then returns at the
	//     edge that raised the request rather than at a later, unrelated one.
	//
	// Neither case changes how this flag is COMPUTED, or which edges get one: that is the
	// translator's retreating predicate above, and it is the same in both.
	bool backedge;
};

// TODO: compact and fast encoding
enum class CondCode : u8 {
	EQ,
	NE,
	LE,
	LT,
	GE,
	GT,
	LEU,
	LTU,
	GEU,
	GTU,
	Count,
};

inline CondCode InverseCC(CondCode cc)
{
	switch (cc) {
	case CondCode::EQ:
		return CondCode::NE;
	case CondCode::NE:
		return CondCode::EQ;
	case CondCode::LE:
		return CondCode::GT;
	case CondCode::LT:
		return CondCode::GE;
	case CondCode::GE:
		return CondCode::LT;
	case CondCode::GT:
		return CondCode::LE;
	case CondCode::LEU:
		return CondCode::GTU;
	case CondCode::LTU:
		return CondCode::GEU;
	case CondCode::GEU:
		return CondCode::LTU;
	case CondCode::GTU:
		return CondCode::LEU;
	default:
		unreachable("");
	}
}

inline CondCode SwapCC(CondCode cc)
{
	switch (cc) {
	case CondCode::EQ:
		return CondCode::EQ;
	case CondCode::NE:
		return CondCode::NE;
	case CondCode::LE:
		return CondCode::GE;
	case CondCode::LT:
		return CondCode::GT;
	case CondCode::GE:
		return CondCode::LE;
	case CondCode::GT:
		return CondCode::LT;
	case CondCode::LEU:
		return CondCode::GEU;
	case CondCode::LTU:
		return CondCode::GTU;
	case CondCode::GEU:
		return CondCode::LEU;
	case CondCode::GTU:
		return CondCode::LTU;
	default:
		unreachable("");
	}
}

struct InstBrcc : InstWithOperands<0, 2> {
	InstBrcc(CondCode cc_, VOperand s1, VOperand s2, u32 f_ip, u32 t_ip, bool f_gbr_, bool t_gbr_,
		 bool t_backedge_ = false)
	    : InstWithOperands(Op::_brcc, {}, {s1, s2}), cc(cc_), f_ip(f_ip), t_ip(t_ip), f_gbr(f_gbr_),
	      t_gbr(t_gbr_), t_backedge(t_backedge_)
	{
	}

	CondCode cc;
	u32 f_ip;
	u32 t_ip;
	bool f_gbr;
	bool t_gbr;
	// T5d2a1, and only for the TAKEN arm: the false arm is `insn_ip + 4` and is never backward, so
	// giving it a field would be a place for a wrong value to live. Set from the same
	// IsDirectBackwardEdge predicate as InstGBr::backedge; meaningful only when `!t_gbr`, because
	// a taken arm that leaves the region is a gbr and carries the fact there instead.
	bool t_backedge;
};

struct InstGBr : InstNoOperands {
	InstGBr(VOperand tpc_, bool backedge_ = false)
	    : InstNoOperands(Op::_gbr), tpc(tpc_), backedge(backedge_)
	{
		assert(tpc_.IsConst());
	}

	VOperand tpc;
	// True iff this region exit came from a DIRECT guest control transfer (a B-type conditional
	// branch or a `jal`) whose architectural target does not lie above the branch instruction
	// itself -- a backward, i.e. retreating, guest edge. Set only by the translator, which is the
	// only place that still knows the branch instruction's own guest PC; every other producer of a
	// gbr (the region-boundary fallthrough, and the jalr paths that resolve an INDIRECT transfer
	// to a constant target) leaves it false by construction. Read by QEmit::Emit_gbr under
	// --qcg-backedge-safepoint and by nothing else; the LLVM backend ignores it entirely.
	bool backedge;
};

struct InstGBrind : InstWithOperands<0, 2> {
	InstGBrind(VOperand tpc_, bool shadow_track_ = true, u8 jalr_class_ = 0,
		   std::vector<u32> const *known_targets_ = nullptr,
		   std::vector<u32> const *known_target_counts_ = nullptr,
		   std::vector<u32> const *order1_prev_ = nullptr,
		   std::vector<u32> const *order1_target_ = nullptr, u32 order1_slot_ = 0,
		   bool has_marginal_target_ = false, u32 marginal_target_ = 0,
		   std::vector<u32> const *static_table_targets_ = nullptr,
		   std::vector<u32> const *vtable_narrow_targets_ = nullptr,
		   std::vector<u32> const *indexed_targets_ = nullptr,
		   VOperand index_operand_ = VOperand(), u32 src_ip_ = 0, bool ccrf_boundary_ = false)
	    : InstWithOperands(Op::_gbrind, {}, {tpc_, index_operand_}), indexed_targets(indexed_targets_),
	      src_ip(src_ip_), ccrf_boundary(ccrf_boundary_), static_table_targets(static_table_targets_),
	      vtable_narrow_targets(vtable_narrow_targets_), order1_prev(order1_prev_),
	      order1_target(order1_target_), order1_slot(order1_slot_),
	      has_marginal_target(has_marginal_target_), marginal_target(marginal_target_),
	      known_targets(known_targets_), known_target_counts(known_target_counts_),
	      shadow_track(shadow_track_), jalr_class(jalr_class_)
	{
	}
	// A-line Round 44 (oracle-only, default nullptr): index-preserving compact dispatch evidence.
	// Unlike static_table_targets (deduplicated, no index), this is the SAME provenly-immutable
	// table's RAW, index-ordered contents (size N == the proven bound+1) -- operand 1 (`i(1)`)
	// carries the guest register value that indexes it (dataflow-proven by the SAME bounds-check
	// TryResolve/TryResolveIndexed already require; see rv32_qir.h's IndexedTable comment). Lowered
	// (Expand_gbrind_EdgeSpecializeAndSlowpath) as a bounds check + ONE load from a compile-time
	// host-address table + one indirect call -- O(1) IR regardless of N, NOT an N-way SwitchInst --
	// falling back to the unchanged generic gbrind slowpath on out-of-bounds or a non-admitted
	// entry. nullptr (default) means this consumer is inert, byte-identical to before this round.
	std::vector<u32> const *indexed_targets;
	// A-line Round 48: this SOURCE's own compile-time-constant guest ip (the containing TB's entry,
	// exactly QCG's own `_entry_ip` -- a jalr always terminates its TB, so this is unambiguous).
	// Unlike every std::vector<u32> const* oracle field above (pointers into a process-lifetime
	// external map), this is a plain value copied at construction -- used only to key the Round 48
	// per-source L1-cache hit/miss lookup at LLVM-emission time (see llvmgen.cpp's
	// Emit_gbrind/Expand_gbrind). Always populated (not oracle-gated): zero cost to carry, since
	// it's a stack-resident u32 -- only READING it via --aot-gbrind-hitrate-file is oracle-gated.
	u32 src_ip;
	// Default-off T7m boundary: the translator marks only the certificate-selected return. QCG
	// commits its state and escapes to Execute instead of linking onward, allowing the host-stack
	// coordinator to perform the one-time join. No guest PC is embedded in this instruction class.
	bool ccrf_boundary;
	// A-line round 32 Gate 2 (oracle-only, default nullptr): this SOURCE's PROVEN-COMPLETE static
	// jump-table target set -- resolved offline by reading the guest ELF's own read-only memory
	// directly (--aot-static-table-file), bootstrapped via cheap --shadow-edges2-out evidence only
	// to LOCATE which table a given source's parameterized base resolves to (NOT to enumerate
	// targets from observed samples -- the table is read in FULL from the ELF once located, going
	// beyond whatever was sampled). Deliberately distinct from known_targets (Row 4/5, profile-
	// sample-derived, never proven complete) and from marginal_target (a single majority guess) --
	// this is the FULL, PROVEN target set for a genuine compiler-emitted switch table, verified
	// immutable (guest ELF segment mapped read-only, no write permission, confirmed against
	// rvdbt's own loader semantics) before being trusted. Lowered as a real llvm::SwitchInst
	// (Expand_gbrind_EdgeSpecializeAndSlowpath, llvmgen.cpp) so the backend chooses O(1) jump-table
	// codegen instead of a hand-rolled sequential compare chain -- the structural difference from
	// order-1/marginal's per-dispatch guard chains that were killed on economics in Rounds 28-30.
	std::vector<u32> const *static_table_targets;
	// A-line Round 33 (oracle-only, default nullptr): this SOURCE's RTTI-class-hierarchy-NARROWED
	// (not proven-complete -- see qir.h top-of-file/config.h aot_vtable_narrow_oracle comment)
	// candidate target set for a C++ virtual-call dispatch. Lowered as a GUARDED llvm::SwitchInst
	// (Expand_gbrind_EdgeSpecializeAndSlowpath) whose default case falls to the unchanged generic
	// gbrind slowpath -- deliberately NOT zero-guard like static_table_targets, since RTTI-
	// descendant membership alone does not guarantee the observed target is among the candidates.
	std::vector<u32> const *vtable_narrow_targets;
	// A-line round 28 Gate 1 (oracle-only, default nullptr): this SOURCE's own exhaustive order-1
	// transition data -- order1_prev[i] -> order1_target[i] is "if this site's PREVIOUS observed
	// target (from THIS SAME SITE, tracked in its own tcache::gbrind_ctx1_slots entry) was
	// order1_prev[i], the argmax next target was order1_target[i]" (parallel arrays, same index,
	// same length; from --brind-edges-out --sr-record-returns=1's .trans file, LoadOrder1Oracle in
	// rv32_qir.cpp). order1_slot is this site's assigned, compile-time-unique
	// tcache::gbrind_ctx1_slots index (0 if ineligible/no data). Never a global/shared context --
	// see tcache.h's gbrind_ctx1_slots comment.
	std::vector<u32> const *order1_prev;
	std::vector<u32> const *order1_target;
	u32 order1_slot;
	// A-line round 29 Gate 1 (oracle-only, default false): this SOURCE's exhaustive MARGINAL
	// (context-free) majority target -- argmax_t sum_prev count(src,prev,t), from the same .trans
	// file as order1 above but aggregated over prev. Deliberately carries ZERO runtime state: no
	// history slot, no prev-load, no per-dispatch update-store -- the guard is a single compile-
	// time-constant compare against gipv. Built because data analysis (Round 29) showed the
	// marginal predictor alone already reaches 78.60%/74.36% hit rate on expat/wasm3 vs order-1's
	// 88.82%/92.73%, while removing the two runtime-state operations order-1 pays for at every
	// covered dispatch regardless of whether that source ever needed context at all.
	bool has_marginal_target;
	u32 marginal_target;
	// A-line round 22 Gate 1 Row 4 (oracle-only, default nullptr): exact target alternatives for
	// THIS gbrind, from the same offline edge data as Row 1's ModuleGraphNode::indirect_succs --
	// but attached to the QIR INSTRUCTION itself (not the graph node), so a QIR-level pass can
	// read/dump it. Deliberately NOT read by Expand_gbrind's lowering (llvmgen.cpp) -- proves
	// (or disproves) "does the QIR merely CARRYING exact target-alternative data change codegen"
	// in isolation from any consumer that would act on it (that would be Row 5's job). Points
	// into a static, process-lifetime map (see rv32_qir.cpp's LoadKnownTargetsOracle) -- never
	// owned by the instruction, never null-derefed without a size check.
	std::vector<u32> const *known_targets;
	// A-line round 23 Gate 1 Row 5 (oracle-only, default nullptr): per-entry dynamic dispatch
	// count parallel to known_targets (same index, same length), sourced from real
	// --shadow-edges2-out evidence (source,target,count) triples. This IS a Row 5 consumer input
	// (unlike known_targets above): Emit_gbrind attaches it as LLVM !prof VP metadata on the
	// gbrind intrinsic call when --aot-gbrind-vp-metadata is set. Same pointer-stability contract
	// as known_targets.
	std::vector<u32> const *known_target_counts;

	// A-line (--shadow-edges): false only for the canonical RISC-V return idiom (rd=x0,
	// rs1=ra) -- a single static return site has as many distinct real targets as it has
	// callers, the worst case for the source-indexed shadow cache; matches the existing
	// --brind-edges-out/--sr-sampled-edges oracle convention of excluding returns by default.
	// Default true (never silently suppress a genuine call/tail-call site).
	bool shadow_track;
	// A-line round 15 (TRACK 1): static classification of this jalr, computed once from
	// (rd,rs1) in TRANSLATOR(jalr) -- 0=CALL (rd!=0, saves a link register), 1=TAILCALL
	// (rd==0, rs1!=ra), 2=RETURN (rd==0, rs1==ra, the canonical idiom). Used only by the
	// round-15 return-inclusive census counters (Emit_gbrind); does not affect any existing
	// mechanism's behavior. Default 0 (CALL) for any construction site that doesn't set it.
	u8 jalr_class;
};

struct InstHcall : InstWithOperands<0, 1> {
	// TODO: variable number of operands
	InstHcall(RuntimeStubId stub_, VOperand arg_) : InstWithOperands(Op::_hcall, {}, {arg_}), stub(stub_)
	{
	}

	RuntimeStubId stub;
};

// One certificate-labelled 64-byte sibling. The node keeps the architectural operation and
// component identity together until QCG emission; it has no helper fallback and is constructed
// only after the T7m pre-start certificate/mapping/shape guards have passed.
struct InstCCRFChunk : InstNoOperands {
	enum class Kind : u8 { WholeLoad, WholeStore, MulVX, MaccVX };
	enum class HostWidth : u8 { FunctionalXMM, AVX512ZMM };
	InstCCRFChunk(u32 raw_, Kind kind_, u8 component_, u32 vlenb_, HostWidth host_width_)
	    : InstNoOperands(Op::_ccrfchunk), raw(raw_), vlenb(vlenb_), kind(kind_), component(component_),
	      host_width(host_width_) {}
	u32 raw;
	u32 vlenb;
	Kind kind;
	u8 component;
	HostWidth host_width;
};

// One certificate-derived, component-local stream for a compute-only natural loop. The operation
// words live in the process-lifetime CCRF certificate object. QCG revalidates their exact unmasked
// e32/m1 vadd.vv shape before emission; this node therefore cannot broaden the guest ISA route.
// Guest vector register numbers select equally numbered ZMMs, making the saved executable image
// independently auditable without a workload-specific register table in production code.
struct InstCCRFComputeRegion : InstNoOperands {
	InstCCRFComputeRegion(u32 const *operations_, u32 operation_count_, u32 iterations_, u8 component_,
			      u32 vlenb_, u32 read_mask_, u32 write_mask_)
	    : InstNoOperands(Op::_ccrfcompute), operations(operations_), operation_count(operation_count_),
	      iterations(iterations_), read_mask(read_mask_), write_mask(write_mask_), vlenb(vlenb_),
	      component(component_) {}
	u32 const *operations;
	u32 operation_count;
	u32 iterations;
	u32 read_mask;
	u32 write_mask;
	u32 vlenb;
	u8 component;
};

// RVV direct lowering of vadd.vv (see experiments/.../docs/DESIGN.md, "direct QCG lowering").
//
// It carries ONLY translation-time constants. The vector data itself lives in CPUState::vec and
// is addressed straight off the state register, which is precisely why this needs no QIR vector
// value type and no register-allocator change -- the values never enter QIR's SSA world. The
// emitted code uses xmm0/xmm1 as fixed scratch, the same convention Emit_vmload4 already uses.
struct InstRVVAddV : InstNoOperands {
	InstRVVAddV(u8 vd_, u8 vs2_, u8 vs1_, u32 vtype_, u32 vlmax_, u8 sew_bytes_, u8 emul_regs_,
		    u8 chunks_per_reg_, u32 raw_, RuntimeStubId stub_, bool llvm_wide_ = false)
	    : InstNoOperands(Op::_rvvaddv), vtype(vtype_), vlmax(vlmax_), raw(raw_), stub(stub_),
	      vd(vd_), vs2(vs2_), vs1(vs1_), sew_bytes(sew_bytes_), emul_regs(emul_regs_),
	      chunks_per_reg(chunks_per_reg_), llvm_wide(llvm_wide_)
	{
	}

	u32 vtype;   // expected CPUState::vec.vtype; guarded at run time
	u32 vlmax;   // expected CPUState::vec.vl for the inline path
	u32 raw;     // guest encoding, for the fallback helper call
	RuntimeStubId stub; // the helper this falls back to
	u8 vd, vs2, vs1;
	u8 sew_bytes;      // selects paddb/paddw/paddd/paddq
	u8 emul_regs;      // registers in the group (== LMUL for vadd.vv)
	u8 chunks_per_reg; // (VLEN/8) / 16 -- the width-parametric chunk count
	// T7a: true only for the LLVM-AOT experiment. The node continues to denote ONE original guest
	// vadd.vv; LLVM uses vlmax lanes in one FixedVectorType and owns any later legalization split.
	bool llvm_wide;
};

// ---------------------------------------------------------------------------------------------
// DIAGNOSTIC CONTROL ARM -- NOT THE METHOD.  Read this before citing anything built on it.
//
// This group (rvvdiagchunkbegin, N x rvvdiagchunkadd, rvvdiagchunkend) is InstRVVAddV's emitter
// loop flattened into one node per 512-bit host chunk, and nothing more.  All three are
// InstNoOperands, so:
//
//   * There is NO QIR value here and no def-use edge.  The only dataflow link between chunks,
//     and between this guest instruction and the next, is CPUState::vec memory: each node emits
//     load-from-state / add / store-to-state, so every guest vector instruction still round-trips
//     its result through memory.  Removing that round trip is exactly what a real V512 SSA value
//     would buy, and it cannot be done without one.
//   * The register allocator is not involved.  Each node's ZMM is hardcoded by the emitter as
//     Zmm(index).  The two chunks of a VLEN=1024 operation do land in different ZMMs, so the
//     emitted code has no false dependency between them -- but that is the emitter asserting it,
//     not QIR expressing it.  No pass can derive chunk independence from this representation,
//     and a hardcoded index cannot coexist with any other ZMM user.
//
// What it is legitimately good for: it is the A/B control the typed V512-value lowering must be
// measured against, and it exercises the admission gate, the architectural guard, the counters
// and the helper fallback end to end.  Do NOT describe it as typed chunk QIR, as vector SSA, or
// as QIR-level chunk def-use.
//
// `begin` and `end` are opcode-agnostic: they own the guard, the counters and the fallback, so
// adding another element-wise same-EEW opcode to the control arm adds only a middle node.
struct InstRVVDiagChunkBegin : InstNoOperands {
	InstRVVDiagChunkBegin(u32 vtype_, u32 vlmax_, u32 raw_, RuntimeStubId stub_)
	    : InstNoOperands(Op::_rvvdiagchunkbegin), vtype(vtype_), vlmax(vlmax_), raw(raw_), stub(stub_)
	{
	}

	u32 vtype; // expected CPUState::vec.vtype; guarded at run time
	u32 vlmax; // the inline path runs only at vl == VLMAX
	u32 raw;   // guest encoding, for the fallback helper call
	RuntimeStubId stub;
};

// One 512-bit host chunk of an admitted vadd.vv, as a side-effect node with no operands. `index`
// is the chunk's position in the group; the emitter uses it both as the byte offset within each
// guest vector register and as the ZMM number, the latter being a hardcoded assignment rather
// than an allocation.
struct InstRVVDiagChunkAdd : InstNoOperands {
	InstRVVDiagChunkAdd(u8 index_, u8 vd_, u8 vs2_, u8 vs1_, u8 sew_bytes_)
	    : InstNoOperands(Op::_rvvdiagchunkadd), index(index_), vd(vd_), vs2(vs2_), vs1(vs1_),
	      sew_bytes(sew_bytes_)
	{
	}

	u8 index;
	u8 vd, vs2, vs1;
	u8 sew_bytes; // selects vpaddb/vpaddw/vpaddd/vpaddq
};

struct InstRVVDiagChunkEnd : InstNoOperands {
	InstRVVDiagChunkEnd(u32 raw_, RuntimeStubId stub_)
	    : InstNoOperands(Op::_rvvdiagchunkend), raw(raw_), stub(stub_)
	{
	}

	u32 raw;
	RuntimeStubId stub;
};

// ---------------------------------------------------------------------------------------------
// Typed 512-bit host chunk dataflow (pure QCG).
//
// This is what the diagnostic arm above is NOT.  A chunk here is a real QIR value of VType::V512:
// it is produced by a definition, consumed by name, and assigned a ZMM by QRegAlloc through
// qir::RegClass::VPR.  No chunk data travels through CPUState between these ops, and no emitter
// picks a register -- every register in the emitted code comes from an allocated operand.
//
// The three ops are deliberately the minimum closed set that can carry a value end to end:
// load a chunk from guest memory, combine two chunks, store a chunk back.  Element width matters
// only to the arithmetic; a load or store moves 64 raw bytes.
//
// ROUTING STATUS, and it differs per op -- do not read the group as one.
//
// vchunkload IS ROUTED, from exact unmasked unit-stride vle32.v only (S2.6), and ONLY in its
// INDIRECT addressing form -- see its own comment below for what that form is and why the direct
// form could not be used inside a guard frame.  It is the first routed chunk op that touches GUEST
// MEMORY rather than CPUState, and the first whose guest opcode's decode family does NOT split the
// admitted shape out for it: rv32_decode.h routes masked loads and every supported EEW to the same
// Op::_vle, so unlike all six ALU routes this one's admission predicate has to test `vm` and the
// width field itself.  Its destination half is `vstatechunkstore`, unchanged.
//
// vchunkstore IS ROUTED, from exact unmasked unit-stride vse32.v only (S2.7), and ONLY in its
// INDIRECT addressing form -- the mirror of the load's, and it exists for the identical reason (see
// InstVChunkLoad below).  It is the first routed chunk op that WRITES GUEST MEMORY, which is the
// whole of what separates it from the load: a wrong address or length here overwrites another
// buffer, the stack or a code page instead of corrupting an architectural vector register.  Its
// source half is `vstatechunkload`, unchanged.  Its decode family does not split the admitted shape
// out for it either: rv32_decode.h routes masked stores and every supported EEW to the same
// Op::_vse, so like the load's, this route's admission predicate tests `vm` and the width field
// itself.
//
// vchunkadd IS ROUTED.  RV32's vadd.vv typed-chunk path (TRANSLATOR(vadd_vv),
// dbt/guest/rv32_qir.cpp) has constructed it from a real guest instruction since commit 44ec1cbcd,
// inside a rvvtypedchunkbegin/rvvtypedchunkend guard frame whose vl/vtype admission and helper
// fallback already exist -- the same "ROUTED today" treatment the two InstVStateChunk* ops below
// carry.  Routing it for any other shape is still a separate obligation.
//
// vchunkmul IS ROUTED, from vmul.vv only (P3.5a), through the same guard frame and the same
// admission predicate shape.  It is a separate opcode from vchunkadd on purpose -- see its own
// comment below for why, and for why its SEW coverage is narrower than the add's.
//
// vchunksub IS ROUTED, from vsub.vv only (S2.1), through the same guard frame and the same
// admission predicate shape.  It is the first routed chunk op whose OPERAND ORDER carries meaning
// -- see its own comment below.
//
// vchunkxor IS ROUTED, from vxor.vv only (S2.2), through the same guard frame and the same
// admission predicate shape.  It is the first routed chunk op that is BITWISE rather than
// arithmetic, and the first whose guest opcode has two near-identical siblings in its own decode
// family -- see its own comment below.
//
// vchunkor IS ROUTED, from vor.vv only (S2.3), through the same guard frame and the same admission
// predicate shape.  It is the SECOND bitwise one, which is the only thing that makes it different
// from the xor: its guest opcode's nearest sibling above is no longer a helper-path family member
// but an accepted typed route, so confusing the two would be a regression rather than a novel bug
// -- see its own comment below.
//
// vchunkand IS ROUTED, from vand.vv only (S2.4), through the same guard frame and the same
// admission predicate shape.  It is the THIRD and LAST of the three adjacent bitwise funct6 values
// to leave the generic `vialu` family, which is what makes it different from both: after it there
// is no unrouted bitwise sibling left to serve as a negative control, and BOTH of its funct6
// neighbours in the routed direction are accepted routes -- see its own comment below.
// ---------------------------------------------------------------------------------------------

// vchunkload: chunk <- [membase + addr + disp], exactly 64 bytes, unaligned.
//
// TWO ADDRESSING FORMS, and the second exists for one reason that is not convenience.
//
// DIRECT (the original, unchanged).  `addr` is an ordinary I32 guest address operand, so it is
// allocated out of the GPR file while the result is allocated out of the VPR file -- the first op
// in the tree whose operands span both register classes.  `disp` is 0 and `base_state_offs` is
// NO_STATE_BASE.  This is the form the mechanism tests drive and it is byte-for-byte what it was.
//
// INDIRECT (S2.6).  `base_state_offs` names a translation-time constant CPUState offset holding a
// 32-bit guest address; the emitter reads it into its own fixed scratch GPR and dereferences it.
// The operand slot then carries the placeholder constant 0 and is read by nobody.
//
// WHY THE INDIRECT FORM HAD TO EXIST.  Inside a typed chunk group nothing may be emitted except the
// typed body ops (see InstRVVTypedChunkBegin below): the guard branches over the body, so an
// allocator `mov` landing there would be skipped on the fallback path while the allocator still
// believed the register was live -- and Emit_mov Panics to enforce it.  `rvvtypedchunkbegin` also
// carries HAS_CALLS, so QRegAlloc::CallOp has spilled EVERY global and every call-clobbered
// register by the time the body starts.  A direct-form vchunkload whose address is a guest GPR
// therefore reaches AllocOp with its track in MEM and QRegAlloc emits a fill -- inside the group,
// which is exactly the Panic.  Filling it before the guard instead would leave the allocator
// believing a call-clobbered register still holds the guest register after the fallback helper has
// clobbered it, which is a miscompile rather than a loud failure.
//
// The indirect form removes the question instead of answering it: the base comes from CPUState,
// where CallOp has just guaranteed the live value sits, through a scratch register the allocator
// never hands out (ArchTraits::AX is in GPR_FIXED, so QRegAlloc::AllocPReg cannot return it).  No
// operand of this form needs allocating, so no fill can be inserted and the group's invariant is
// untouched rather than relaxed.  It is the same argument vstatechunkload already relies on -- a
// fixed host register plus a translation-time constant -- with one extra dereference.
//
// `disp` IS A HOST-POINTER DISPLACEMENT AND THAT IS A SEMANTIC CHOICE, not an encoding detail.  It
// folds into the x86 memory operand, so chunk 1 of a VLEN=1024 register is addressed as
// [base + 64] in 64-bit host arithmetic and does NOT wrap modulo 2^32.  That is precisely what
// rvv_chunked::copy_chunked does (`src + c * HOST_CHUNK_BYTES` on a host pointer,
// rv32_vector_lower.h), so the direct route and the helper arm it replaces agree on all 2^32 base
// addresses including the top 64 (S2.5 section 4.3).  Computing the second address as a QIR I32
// add would have wrapped and silently disagreed there.  Do not "simplify" this into an add.
struct InstVChunkLoad : InstWithOperands<1, 1> {
	static constexpr u32 CHUNK_BYTES = 64;
	// Exclusive upper bound on a CPUState offset, matching InstVStateChunkLoad's u16 encoding.
	static constexpr u32 STATE_OFFS_LIMIT = 1u << 16;
	// Reserved value of `base_state_offs` meaning "direct form": one below the u16 limit, so it
	// can never collide with a real offset (a 4-byte guest register at 0xffff would not fit).
	static constexpr u16 NO_STATE_BASE = 0xffff;

	InstVChunkLoad(VOperand d, VOperand addr) : InstWithOperands(Op::_vchunkload, {d}, {addr}) {}

	InstVChunkLoad(VOperand d, u32 base_state_offs_, u32 disp_, u8 active_sew_ = 0,
			 u8 chunk_ = 0)
	    : InstWithOperands(Op::_vchunkload, {d}, {VOperand::MakeConst(VType::I32, 0)}),
	      base_state_offs(static_cast<u16>(base_state_offs_)), disp(static_cast<u16>(disp_)),
	      active_sew(active_sew_), chunk(chunk_)
	{
		if (active_sew && active_sew != 4 && active_sew != 8)
			Panic("qir: unsupported active guest load element width");
		// A 4-byte guest address must fit below the u16 offset encoding, and the reserved
		// NO_STATE_BASE value must stay unreachable.  Structural, like the vstatechunk* pair;
		// the bound against sizeof(CPUState) is QEmit's, which QIR cannot apply.
		if (base_state_offs_ > STATE_OFFS_LIMIT - sizeof(u32) ||
		    base_state_offs_ == NO_STATE_BASE) {
			Panic("qir: vchunkload indirect base is not a representable state offset");
		}
		// Only the chunk displacements an admitted shape can produce. Until Native-2 that was
		// chunk 0 of any VLEN and chunk 1 of VLEN=1024, because the unit-stride routes transfer
		// ONE register and a register is at most two 512-bit chunks. A whole-register transfer
		// moves a register GROUP, so chunk c of an nregs-register group sits at c*64. The bound
		// is the chunk-count limit, not a VLEN: a chunk past the widest register the storage
		// reservation permits still fails closed here, and this refusal is what caught the first
		// version of that route rather than letting it emit a displacement nothing had audited.
		//
		// T6b MADE THE BOUND GENERIC. It was the literal `3 * CHUNK_BYTES` -- the four chunks
		// Native-2's whole-register route reaches -- which was an accident of which routes existed,
		// not a property of this node. A VLEN=4096 unit-stride frame addresses chunk 7 at
		// displacement 448, so the literal would have turned a legitimately admitted k=8 vle32.v
		// into a translation Panic instead of code. MAX_REG_CHUNKS is the same bound the admission
		// side derives, so the two cannot disagree about which shapes exist.
		//
		// A17 MADE IT A FUNCTION OF THE WIDTH ACTUALLY BEING READ, the rule InstVChunkStore has
		// carried since P7N-D, stated there: with a 16- or 32-byte destination `disp % 64 == 0`
		// would refuse the second register of a whole-register group at VLEN 128/256 (its
		// window starts at 16/32), while a 64-byte destination keeps the previous test character
		// for character. Consecutive windows tile when the displacement is a whole number of
		// THIS load's own width and the window ends inside the storage reservation.
		if (!IsVectorVType(d.GetType())) {
			Panic("qir: vchunkload destination is not a vector value");
		}
		u32 const width = VTypeToSize(d.GetType()); // VTypeToSize is in BYTES
		// Unmasked whole-register transfers span up to eight registers. Masked
		// element transfers retain their per-register chunk-index bound.
		u32 const span_limit = (active_sew_ ? 1u : 8u) * MAX_REG_CHUNKS * CHUNK_BYTES;
		if (width == 0 || disp_ % width != 0 || disp_ > span_limit - width) {
			Panic("qir: vchunkload displacement is not an admitted chunk offset");
		}
	}

	// NO_STATE_BASE selects the direct form; anything else is the indirect form above.
	u16 base_state_offs{NO_STATE_BASE};
	u16 disp{0};
	// Nonzero: access only lanes below live vl. Unit-stride memory currently admits e32/e64.
	u8 active_sew{0}, chunk{0};
};

// M2C. Shared shape check for a typed chunk lane operation: three vector values, all of the same
// width, and a SEW that tiles that width exactly. Written once so the rule cannot be stated
// differently by two constructors.
inline void CheckChunkAluShape(char const *who, VOperand d, VOperand s1, VOperand s2, u8 sew_bytes)
{
	if (!IsVectorVType(d.GetType()) || !IsVectorVType(s1.GetType()) ||
	    !IsVectorVType(s2.GetType())) {
		Panic("qir: chunk lane op operand is not a vector value");
	}
	if (d.GetType() != s1.GetType() || d.GetType() != s2.GetType()) {
		Panic("qir: chunk lane op mixes host vector widths");
	}
	if (sew_bytes == 0 || VTypeToSize(d.GetType()) % sew_bytes != 0) {
		Panic("qir: chunk lane op SEW does not tile the host chunk width");
	}
	(void)who;
}

// vchunkadd: chunk <- chunk + chunk, lane width `sew_bytes` (1/2/4/8 -> vpaddb/w/d/q).
//
// The destination is a third, independent value: EVEX's three-operand form is non-destructive, so
// there is no tie between an input and the output and hence no operand-overlap hazard for the
// allocator to legalize.  That is why this op's constraint table carries no ALIAS, unlike every
// scalar binop in QCG.
// M2C. The three operands must be vector values OF THE SAME WIDTH, and the width must be a whole
// number of SEW-sized lanes.
//
// This constructor had no validation at all, which was survivable only while there was one vector
// width in the tree. With three, an operand set that mixes them is the exact shape of a
// wrong-width bug -- a 128-bit source added into a 512-bit destination would read 48 bytes of
// whatever the register happened to hold -- and it must not be representable, let alone reach an
// emitter that would pick the destination's width and encode it happily.
struct InstVChunkAdd : InstWithOperands<1, 2> {
	InstVChunkAdd(VOperand d, VOperand s1, VOperand s2, u8 sew_bytes_)
	    : InstWithOperands(Op::_vchunkadd, {d}, {s1, s2}), sew_bytes(sew_bytes_)
	{
		CheckChunkAluShape("vchunkadd", d, s1, s2, sew_bytes_);
	}

	u8 sew_bytes;
};

// T7b fair-wide vadd.vv. This ONE QIR node retains the original guest operation while its fixed
// V512 inputs/outputs keep it in the accepted typed-frame SSA dataflow. At active_chunks=2 LLVM
// concatenates vs2[0:1] and vs1[0:1], emits one <32 x i32> add, then splits that result back into
// d[0:1]. Inactive fixed-shape operands exist only for ordinary visitor machinery and are ignored.
// The surrounding rvvtypedchunk frame owns the unchanged architectural guard and helper fallback.
struct InstRVVWideAddSSA : InstWithOperands<4, 8> {
	InstRVVWideAddSSA(std::array<VOperand, 4> d, std::array<VOperand, 4> vs2,
			   std::array<VOperand, 4> vs1, u8 active_chunks_, u8 sew_bytes_, u32 raw_)
	    : InstWithOperands(Op::_vwideaddssa, std::move(d),
			       {vs2[0], vs2[1], vs2[2], vs2[3], vs1[0], vs1[1], vs1[2], vs1[3]}),
	      raw(raw_), active_chunks(active_chunks_), sew_bytes(sew_bytes_)
	{
		if (active_chunks != 1 && active_chunks != 2)
			Panic("qir: fair-wide vadd requires one or two chunks");
	}

	u32 raw;
	u8 active_chunks;
	u8 sew_bytes;
};

// vchunkmul: chunk <- chunk * chunk, LOW half of the product, lane width `sew_bytes`.
//
// Same non-destructive three-operand EVEX shape as vchunkadd, so the same CT(r_r_r) table and the
// same absence of an ALIAS constraint apply.
//
// The multiply is NOT as width-uniform as the add, and this op does not pretend otherwise. x86 has
// vpaddb/w/d/q for all four widths, but for a packed low-half integer multiply it has vpmullw
// (AVX512BW), vpmulld (AVX512F), vpmullq (AVX512DQ) and NO byte form at all. The emitter therefore
// implements exactly the width the P3.5a admission test admits -- SEW=4 -> vpmulld -- and panics on
// every other value rather than substituting a different operation. Widening this op means widening
// the admission test and the host-feature probe together, in one checkpoint, with its own evidence.
//
// ROUTED, for one exact shape. RV32's vmul.vv typed-chunk path (TRANSLATOR(vmul_vv),
// dbt/guest/rv32_qir.cpp) constructs it inside the same rvvtypedchunkbegin/rvvtypedchunkend guard
// frame vadd.vv uses, with the same low/high 64-byte CPUState windows and the same helper fallback
// -- the fallback stub being the pre-existing `id_rv32_vimul`, so no new architectural semantics
// enter the build with this op.
struct InstVChunkMul : InstWithOperands<1, 2> {
	InstVChunkMul(VOperand d, VOperand s1, VOperand s2, u8 sew_bytes_)
	    : InstWithOperands(Op::_vchunkmul, {d}, {s1, s2}), sew_bytes(sew_bytes_)
	{
	}

	u8 sew_bytes;
};

// vchunksub: chunk <- chunk - chunk, lane width `sew_bytes` (1/2/4/8 -> vpsubb/w/d/q).
//
// Same non-destructive three-operand EVEX shape as vchunkadd and vchunkmul, so the same CT(r_r_r)
// table and the same absence of an ALIAS constraint apply.
//
// OPERAND ORDER IS SEMANTIC HERE, and this is the ONE way this op differs from the two above.
// Subtraction does not commute, so `d = s1 - s2` is a statement, not a naming convention: input 0
// is the MINUEND and input 1 is the SUBTRAHEND, and the emitter must preserve that order in
// `vpsub<w> d, s1, s2`. RVV's `vsub.vv vd, vs2, vs1` computes `vd[i] = vs2[i] - vs1[i]`
// (rv32_vector_lower.h vialu_apply: `a` is the vs2 element, `b` the vs1 element), so the routed
// frame passes the vs2 chunk as input 0 and the vs1 chunk as input 1. Swapping them would negate
// every result while keeping every structural property -- chunk count, register disjointness,
// def-use, guard -- intact, which is precisely why the route's tests gate the ORDER of the decoded
// operands and not merely their set.
//
// SEW coverage matches the ADD's, not the multiply's: x86 has vpsubb/w/d/q for all four widths in
// AVX512F+BW, exactly as it has vpaddb/w/d/q. The admission test nevertheless admits only SEW=4
// today, so the emitter's wider table is unreachable; it is written out anyway so that widening the
// admission test is a one-place change with an already-correct emitter, and every other value is a
// hard failure rather than a substituted operation.
//
// ROUTED, for one exact shape (S2.1). RV32's vsub.vv typed-chunk path (TRANSLATOR(vsub_vv),
// dbt/guest/rv32_qir.cpp) constructs it inside the same rvvtypedchunkbegin/rvvtypedchunkend guard
// frame vadd.vv and vmul.vv use, with the same low/high 64-byte CPUState windows and the same
// helper fallback -- the fallback stub being the pre-existing `id_rv32_vialu`, so no new
// architectural semantics enter the build with this op.
struct InstVChunkSub : InstWithOperands<1, 2> {
	InstVChunkSub(VOperand d, VOperand s1, VOperand s2, u8 sew_bytes_)
	    : InstWithOperands(Op::_vchunksub, {d}, {s1, s2}), sew_bytes(sew_bytes_)
	{
	}

	u8 sew_bytes;
};

// vchunkxor: chunk <- chunk ^ chunk, a BITWISE operation over the whole 512-bit chunk.
//
// Same non-destructive three-operand EVEX shape as the three ops above, so the same CT(r_r_r) table
// and the same absence of an ALIAS constraint apply.  Operand order is not semantic here -- xor
// commutes, unlike vchunksub -- so the route's checks treat it as a structural traceability
// property, not as a correctness gate, and say so.
//
// `sew_bytes` IS CARRIED ANYWAY, and it is deliberately NOT used to select a host instruction.
// A bitwise xor is lane-width-independent: on unmasked ZMM operands `vpxord` and `vpxorq` compute
// the same 512 bits, and there is no byte/word EVEX form to choose between. So a width TABLE like
// vchunkadd's would be decorative -- four rows that cannot disagree -- and would falsely suggest
// this op tracks SEW the way the add does. The field is kept because it is what makes the QIR say
// which guest SEW the frame was admitted under (the printer emits it, and the route's tests gate
// it), and because a later widening must remain a change to the ADMISSION test rather than a
// silent reinterpretation of an existing node. The emitter therefore implements exactly the width
// the S2.2 admission test admits -- SEW=4 -> vpxord -- and panics on every other value.
//
// THE RISK THIS OP CARRIES THAT ITS ARITHMETIC SIBLINGS DO NOT is not inside the op at all; it is
// upstream. `vxor.vv` is one of three adjacent funct6 values (vand 0b001001, vor 0b001010, vxor
// 0b001011) that all have identical operand shapes and all originally decoded to the same generic
// `vialu` family. A decoder predicate that was one bit too loose would hand this op a guest AND or
// OR, and every structural property below -- chunk count, windows, def-use, disjointness, guard,
// counters -- would still hold while every lane was wrong. That is why the route's decoder evidence
// is an exhaustive sweep of the OP-V encoding space rather than a list of hand-picked negatives.
// Since S2.3, 0b001010 has its own op (vor_vv -> vchunkor) and since S2.4 so does 0b001001
// (vand_vv -> vchunkand), which does not relax the requirement: the sweep still demands that
// exactly one encoding reach THIS op, and it is now the only thing standing between three adjacent
// routed encodings.
//
// ROUTED, for one exact shape (S2.2). RV32's vxor.vv typed-chunk path (TRANSLATOR(vxor_vv),
// dbt/guest/rv32_qir.cpp) constructs it inside the same rvvtypedchunkbegin/rvvtypedchunkend guard
// frame vadd.vv, vmul.vv and vsub.vv use, with the same low/high 64-byte CPUState windows and the
// same helper fallback -- the fallback stub being the pre-existing `id_rv32_vialu`, so no new
// architectural semantics enter the build with this op.
struct InstVChunkXor : InstWithOperands<1, 2> {
	InstVChunkXor(VOperand d, VOperand s1, VOperand s2, u8 sew_bytes_)
	    : InstWithOperands(Op::_vchunkxor, {d}, {s1, s2}), sew_bytes(sew_bytes_)
	{
	}

	u8 sew_bytes;
};

// vchunkor: chunk <- chunk | chunk, a BITWISE operation over the whole 512-bit chunk.
//
// Same non-destructive three-operand EVEX shape as the four ops above, so the same CT(r_r_r) table
// and the same absence of an ALIAS constraint apply.  Operand order is not semantic here -- or
// commutes, exactly as xor does -- so the route's checks treat it as a structural traceability
// property, not as a correctness gate, and say so.
//
// `sew_bytes` IS CARRIED ANYWAY, and for the same reason it is on vchunkxor: a bitwise or is
// lane-width-independent (on unmasked ZMM operands `vpord` and `vporq` compute the same 512 bits,
// and there is no byte/word EVEX form), so a width table would be four rows that cannot disagree.
// The field is kept because it is what makes the QIR say which guest SEW the frame was admitted
// under -- the printer emits it and the route's tests gate it -- and because a later widening must
// remain a change to the ADMISSION test rather than a silent reinterpretation of an existing node.
// The emitter implements exactly the width the S2.3 admission test admits -- SEW=4 -> vpord -- and
// panics on every other value.
//
// A SEPARATE OPCODE FROM vchunkxor, NOT AN ALU SELECTOR ON IT. The two nodes have identical types,
// identical operand counts, identical constraints and identical semantics up to one host mnemonic.
// That similarity is exactly the argument for keeping them apart: with a selector field, choosing
// `vpord` where `vpxord` was meant would be a wrong VALUE in a field, and every structural
// property -- chunk count, windows, def-use, disjointness, guard, counters, even the QIR opcode
// name -- would still be right. As two opcodes, that same mistake is a wrong NODE TYPE, which the
// emitter's own visitor dispatch, the printer and every test that counts ops all see directly.
//
// THE HAZARD THIS OP CARRIES THAT vchunkxor DID NOT is on the other side of it in funct6 order.
// When the xor route landed, both of its neighbours (vand 0b001001, vor 0b001010) were plain
// helper-path members of the generic `vialu` family, so a decoder slip could only mean "a shape
// with no route got one". Now vxor.vv (0b001011) is an ACCEPTED route, so an upward slip here
// would take an already-accepted lowering away from it and compute an OR for a guest XOR: a
// regression of accepted evidence, not merely a new defect. That asymmetry is why the route's
// decoder evidence is an exhaustive sweep of the OP-V encoding space that gates ALL FIVE splits at
// once, rather than one that only looks for its own. Since S2.4 the downward neighbour vand.vv is
// an accepted route too (vchunkand below), so BOTH of this op's neighbours are now accepted and the
// sweep gates SIX splits.
//
// ROUTED, for one exact shape (S2.3). RV32's vor.vv typed-chunk path (TRANSLATOR(vor_vv),
// dbt/guest/rv32_qir.cpp) constructs it inside the same rvvtypedchunkbegin/rvvtypedchunkend guard
// frame vadd.vv, vmul.vv, vsub.vv and vxor.vv use, with the same low/high 64-byte CPUState windows
// and the same helper fallback -- the fallback stub being the pre-existing `id_rv32_vialu`, so no
// new architectural semantics enter the build with this op.
struct InstVChunkOr : InstWithOperands<1, 2> {
	InstVChunkOr(VOperand d, VOperand s1, VOperand s2, u8 sew_bytes_)
	    : InstWithOperands(Op::_vchunkor, {d}, {s1, s2}), sew_bytes(sew_bytes_)
	{
	}

	u8 sew_bytes;
};

// vchunkand: chunk <- chunk & chunk, a BITWISE operation over the whole 512-bit chunk.
//
// Same non-destructive three-operand EVEX shape as the five ops above, so the same CT(r_r_r) table
// and the same absence of an ALIAS constraint apply.  Operand order is not semantic here -- and
// commutes, exactly as xor and or do -- so the route's checks treat it as a structural traceability
// property, not as a correctness gate, and say so.
//
// `sew_bytes` IS CARRIED ANYWAY, and for the same reason it is on vchunkxor and vchunkor: a bitwise
// and is lane-width-independent (on unmasked ZMM operands `vpandd` and `vpandq` compute the same
// 512 bits, and there is no byte/word EVEX form), so a width table would be four rows that cannot
// disagree.  The field is kept because it is what makes the QIR say which guest SEW the frame was
// admitted under -- the printer emits it and the route's tests gate it -- and because a later
// widening must remain a change to the ADMISSION test rather than a silent reinterpretation of an
// existing node.  The emitter implements exactly the width the S2.4 admission test admits --
// SEW=4 -> vpandd -- and panics on every other value.
//
// A SEPARATE OPCODE FROM vchunkxor AND vchunkor, NOT AN ALU SELECTOR ON EITHER.  The argument that
// applied to the or applies here with one more term in it: there are now THREE nodes with identical
// types, operand counts, constraints and semantics up to one host mnemonic.  A shared node with an
// operation field would make the choice between `vpandd`, `vpord` and `vpxord` a wrong VALUE in a
// field, and every structural property -- chunk count, windows, def-use, disjointness, guard,
// counters, even the QIR opcode name -- would still be right for all three.  As three opcodes, that
// same mistake is a wrong NODE TYPE, which the emitter's own visitor dispatch, the printer and every
// test that counts ops all see directly.
//
// THE HAZARD THIS OP CARRIES THAT NEITHER OF THE OTHER TWO DID is that it is the LAST of the three
// to be routed, so both directions of a decoder slip now land in accepted territory or in nothing at
// all.  vand.vv is 0b001001; 0b001010 (vor.vv) and 0b001011 (vxor.vv) above it are BOTH accepted
// routes, so an upward slip removes an accepted lowering rather than adding a wrong one, while
// 0b001000 below it is not an OPIVV encoding this decoder implements at all and a downward slip
// therefore fails closed to `ill` rather than mislowering a live guest instruction.  The practical
// consequence for evidence is that the "the sibling still takes the helper" control this route's
// four predecessors all had NO LONGER EXISTS in the frozen workload -- every element-wise integer
// ALU opcode it contains is routed once this lands -- so non-capture has to be shown POSITIVELY,
// by the neighbours keeping their own nodes and their own mnemonics.
//
// ROUTED, for one exact shape (S2.4). RV32's vand.vv typed-chunk path (TRANSLATOR(vand_vv),
// dbt/guest/rv32_qir.cpp) constructs it inside the same rvvtypedchunkbegin/rvvtypedchunkend guard
// frame vadd.vv, vmul.vv, vsub.vv, vxor.vv and vor.vv use, with the same low/high 64-byte CPUState
// windows and the same helper fallback -- the fallback stub being the pre-existing `id_rv32_vialu`,
// so no new architectural semantics enter the build with this op.
struct InstVChunkAnd : InstWithOperands<1, 2> {
	InstVChunkAnd(VOperand d, VOperand s1, VOperand s2, u8 sew_bytes_)
	    : InstWithOperands(Op::_vchunkand, {d}, {s1, s2}), sew_bytes(sew_bytes_)
	{
	}

	u8 sew_bytes;
};

// P7N-B. vchunksll / vchunksrl: chunk <- chunk shifted LEFT / RIGHT LOGICALLY by a
// translation-time immediate, per SEW-wide lane.
//
// ONE SOURCE, NOT TWO, and that is the whole reason these are their own node shape rather than a
// third selector on the bitwise trio. Every chunk ALU op before them came from an OPIVV `.vv`
// encoding whose rs1 field names a VECTOR register; these come from OPIVI, where that same field
// is a 5-bit UNSIGNED IMMEDIATE. So the frame that lowers them loads ONE source per chunk, not
// two, and the shift amount travels in the node instead of in a register.
//
// `shamt` IS ALREADY REDUCED MODULO SEW at construction. RVV 1.0 defines the shift amount as the
// low log2(SEW) bits of the operand, and the reference helper implements exactly that
// (`a << (b & (bits - 1))` in vialu_apply, rv32_vector_lower.h). x86's vpslld/vpsrld instead
// produce ZERO for a count >= 32, so handing the raw 5-bit field to the host would agree with the
// reference at SEW=32 (where the mask is the identity on 5 bits) and DISAGREE at any narrower SEW
// the route might later admit. Reducing here, once, at the only place that knows the SEW, makes
// that divergence unrepresentable rather than merely absent today.
//
// SEPARATE OPCODES, one per host instruction, for the reason qir_ops.h gives.
struct InstVChunkSll : InstWithOperands<1, 1> {
	InstVChunkSll(VOperand d, VOperand s, u8 sew_bytes_, u8 shamt_)
	    : InstWithOperands(Op::_vchunksll, {d}, {s}), sew_bytes(sew_bytes_),
	      shamt((u8)(shamt_ & (8u * sew_bytes_ - 1u)))
	{
		if (!d.IsV() || !s.IsV())
			Panic("qir: vchunksll operands are not vector values");
		if (d.GetType() != s.GetType())
			Panic("qir: vchunksll operands disagree about chunk width");
		if (sew_bytes_ == 0 || sew_bytes_ > 8)
			Panic("qir: vchunksll has an impossible SEW");
	}

	u8 sew_bytes;
	u8 shamt;
};

struct InstVChunkSrl : InstWithOperands<1, 1> {
	InstVChunkSrl(VOperand d, VOperand s, u8 sew_bytes_, u8 shamt_)
	    : InstWithOperands(Op::_vchunksrl, {d}, {s}), sew_bytes(sew_bytes_),
	      shamt((u8)(shamt_ & (8u * sew_bytes_ - 1u)))
	{
		if (!d.IsV() || !s.IsV())
			Panic("qir: vchunksrl operands are not vector values");
		if (d.GetType() != s.GetType())
			Panic("qir: vchunksrl operands disagree about chunk width");
		if (sew_bytes_ == 0 || sew_bytes_ > 8)
			Panic("qir: vchunksrl has an impossible SEW");
	}

	u8 sew_bytes;
	u8 shamt;
};

// vchunkstore: [membase + addr + disp] <- chunk, exactly 64 bytes, unaligned.
//
// TWO ADDRESSING FORMS, exactly as InstVChunkLoad above has, and the second exists for the same
// reason rather than for symmetry's sake.
//
// DIRECT (the original, unchanged).  `addr` is an ordinary I32 guest address operand, allocated out
// of the GPR file while the data operand is allocated out of the VPR file.  `disp` is 0 and
// `base_state_offs` is NO_STATE_BASE.  Operand order matches InstVMStore's (base, data) so the
// existing `ri_r` constraint table applies unchanged.  This is the form the mechanism tests drive
// and it is byte-for-byte what it was.
//
// INDIRECT (S2.7).  `base_state_offs` names a translation-time constant CPUState offset holding a
// 32-bit guest address; the emitter reads it into its own fixed scratch GPR and dereferences it.
// The address operand slot then carries the placeholder constant 0 and is read by nobody; the DATA
// operand is untouched and is still a real allocated V512 value.
//
// WHY THE INDIRECT FORM HAD TO EXIST.  Verbatim the load's argument, and it is not weaker on the
// store side: inside a typed chunk group nothing may be emitted except the typed body ops, because
// the guard branches over the body and an allocator `mov` landing there would be skipped on the
// fallback path while the allocator still believed the register was live (Emit_mov Panics to
// enforce it).  `rvvtypedchunkbegin` carries HAS_CALLS, so QRegAlloc::CallOp has spilled EVERY
// global before the body starts, and a direct-form vchunkstore whose address is a guest GPR
// therefore reaches AllocOp with its track in MEM and gets a fill emitted inside the group.  The
// indirect form removes the question: the base comes from CPUState, where CallOp has just
// guaranteed the live value sits, through ArchTraits::AX -- a GPR_FIXED register QRegAlloc::AllocPReg
// can never hand out.  No ADDRESS operand needs allocating, so no fill can be inserted for it.
//
// THE DATA OPERAND STILL NEEDS ALLOCATING, and that is not a hole in the argument.  It is a V512
// value defined by this frame's own `vstatechunkload`, inside the same group, so it is live in a
// ZMM across the two ops and QRegAlloc has nothing to fill: the VPR file is untouched by CallOp
// (visitInstRVVTypedChunkBegin -> CallOp(true) syncs GLOBALS, and rv32's StateInfo declares only
// x1-x31 and ip, all GPRs).  The six accepted ALU routes already rely on exactly this -- their
// vstatechunkstore consumes a value defined earlier in the same group in the same way.
//
// `disp` IS A HOST-POINTER DISPLACEMENT AND THAT IS THE SAME SEMANTIC CHOICE the load made, made
// again here because the helper arm this route replaces makes it too: `rvv_chunked::store_unit_stride`
// hands `copy_chunked` a `vmem + (u32)base` destination and then walks `dst + c*HOST_CHUNK_BYTES` on
// a HOST pointer (rv32_vector_lower.h), which does not wrap modulo 2^32.  Folding the displacement
// into the x86 memory operand reproduces that for all 2^32 base addresses, including the 64 at the
// very top where a QIR I32 add would have wrapped and written 64 bytes to the BOTTOM of the guest
// address space instead (S2.5 section 4.3).  On the store side that divergence would be a wild
// write rather than a wrong register, which is why it is closed structurally and not by a guard.
// Do not "simplify" this into an add.
struct InstVChunkStore : InstWithOperands<0, 2> {
	static constexpr u32 CHUNK_BYTES = 64;
	// Exclusive upper bound on a CPUState offset, matching InstVChunkLoad's u16 encoding.
	static constexpr u32 STATE_OFFS_LIMIT = 1u << 16;
	// Reserved value of `base_state_offs` meaning "direct form", as in InstVChunkLoad.
	static constexpr u16 NO_STATE_BASE = 0xffff;

	InstVChunkStore(VOperand addr, VOperand data)
	    : InstWithOperands(Op::_vchunkstore, {}, {addr, data})
	{
	}

	InstVChunkStore(u32 base_state_offs_, u32 disp_, VOperand data, u8 active_sew_ = 0,
			  u8 chunk_ = 0)
	    : InstWithOperands(Op::_vchunkstore, {},
			       {VOperand::MakeConst(VType::I32, 0), data}),
	      base_state_offs(static_cast<u16>(base_state_offs_)), disp(static_cast<u16>(disp_)),
	      active_sew(active_sew_), chunk(chunk_)
	{
		if (active_sew && active_sew != 4 && active_sew != 8)
			Panic("qir: unsupported active guest store element width");
		// A 4-byte guest address must fit below the u16 offset encoding, and the reserved
		// NO_STATE_BASE value must stay unreachable.  Structural, like the load's; the bound
		// against sizeof(CPUState) is QEmit's, which QIR cannot apply.
		if (base_state_offs_ > STATE_OFFS_LIMIT - sizeof(u32) ||
		    base_state_offs_ == NO_STATE_BASE) {
			Panic("qir: vchunkstore indirect base is not a representable state offset");
		}
		// Only the chunk displacements an admitted shape can produce, and on THIS side an
		// unadmitted one is a wild WRITE rather than a wrong read. Same bound as the
		// load's, made generic by T6b for the same reason and stated there: the literal
		// `3 * CHUNK_BYTES` described the routes that existed rather than this node, and would
		// have Panic'd on the fourth chunk of a legitimately admitted VLEN=4096 vse32.v frame.
		//
		// P7N-D MADE IT A FUNCTION OF THE WIDTH ACTUALLY BEING WRITTEN. The rule was
		// `disp % 64 == 0`, which is the right rule only while every store is 64 bytes wide;
		// with a 16- or 32-byte data value it would accept a displacement that OVERLAPS the
		// previous window, or leaves a gap, and either is a wrong set of guest bytes. The
		// windows must tile, so the displacement must be a whole number of THIS store's own
		// width and the window must end inside the storage reservation. At a 64-byte data value
		// this is the previous test character for character (disp % 64 == 0 and
		// disp + 64 <= MAX_REG_CHUNKS*64 is disp <= (MAX_REG_CHUNKS-1)*64), so no existing
		// caller's admitted set moves.
		if (!IsVectorVType(data.GetType())) {
			Panic("qir: vchunkstore data operand is not a vector value");
		}
		u32 const width = VTypeToSize(data.GetType()); // VTypeToSize is in BYTES
		u32 const span_limit = (active_sew_ ? 1u : 8u) * MAX_REG_CHUNKS * CHUNK_BYTES;
		if (width == 0 || disp_ % width != 0 || disp_ > span_limit - width) {
			Panic("qir: vchunkstore displacement is not an admitted chunk offset");
		}
	}

	// NO_STATE_BASE selects the direct form; anything else is the indirect form above.
	u16 base_state_offs{NO_STATE_BASE};
	u16 disp{0};
	// Nonzero: access only lanes below live vl. The current route admits e32 only.
	u8 active_sew{0}, chunk{0};
};

// vstatechunkload: chunk <- [R_STATE + offs], exactly 64 bytes, unaligned.
//
// This is the CPUState counterpart of vchunkload, and the difference is the whole point.  The three
// ops above address GUEST memory: their address is a guest value, it arrives as an I32 operand, and
// the emitter forms it through make_vmem, which adds R_MEMBASE.  This one addresses the EMULATOR's
// own state: R_STATE is a fixed host register live for the entire region, and the offset is a
// translation-time constant.  So there is no address operand at all -- the instruction's only
// operand is the V512 result -- and the emitter must not go anywhere near make_vmem or R_MEMBASE.
// A guest program cannot influence where this reads.
//
// `offs` is VALIDATED, twice, and fails closed both times:
//
//   * here, structurally -- the destination really is a V512 vector value, and the 64-byte window
//     [offs, offs + 64) is describable as a CPUState offset.  u16 is the encoding StateReg and
//     VOperand::MakeSlot already use for "an offset from R_STATE", so the window has to fit in it;
//   * in QEmit, against sizeof(CPUState).  That is the bound that actually matters, and QIR cannot
//     apply it: CPUState is guest-specific and deliberately invisible from here.
//
// SIDEEFF, and not because a load has an effect.  It is an ALIAS statement: this reads raw bytes of
// CPUState at an offset QIR does not interpret, and that window may overlap the state slot of a
// guest global that the register allocator is currently keeping dirty in a host register.  SIDEEFF
// is what makes QRegAlloc sync globals back to CPUState first, so the bytes read are the live ones.
// Marking it pure would also license a later pass to hoist it across a helper call that writes the
// architectural vector state -- exactly the reordering this op must not permit.
//
// ROUTED today, for one exact shape.  RV32's vadd.vv typed-chunk path (TRANSLATOR(vadd_vv),
// dbt/guest/rv32_qir.cpp) already constructs this op, for the low/high 64-byte windows of
// CPUState::vec.vreg only.  The rule for the ALIAS concern above is unchanged: an arbitrary state
// offset still requires its own proof against RV32Translator::GetStateInfo before it may be
// trusted the same way.  RV32's routed vec.vreg windows already carry that proof -- they are
// disjoint from every global GetStateInfo tracks (x1-x31, ip), see
// experiments/2026-08-24-0935-rvv-typed-chunk-vaddvv-route/docs/C2_1A_TWO_CHUNK_SOURCE_AUDIT.md
// section 15.
struct InstVStateChunkLoad : InstWithOperands<1, 0> {
	static constexpr u32 CHUNK_BYTES = 64;
	// Exclusive upper bound on a CPUState offset, set by the u16 state-offset encoding.
	static constexpr u32 STATE_OFFS_LIMIT = 1u << 16;

	// M2C: the window is VTypeToSize(d) bytes, not CHUNK_BYTES. CHUNK_BYTES survives as the
	// MAXIMUM width (the AVX-512 chunk), which is what the offset bound below and the sibling
	// memory-addressed chunk ops still reason about.
	InstVStateChunkLoad(VOperand d, u32 offs_)
	    : InstWithOperands(Op::_vstatechunkload, {d}, {}), offs(static_cast<u16>(offs_))
	{
		if (!IsVectorVType(d.GetType())) {
			Panic("qir: vstatechunkload destination is not a vector value");
		}
		if (!d.IsVPR()) {
			Panic("qir: vstatechunkload destination is not a vector register");
		}
		// NO ALIGNMENT REQUIREMENT ON `offs_`, and that is not an omission. CPUState::vec.vreg
		// starts at an arbitrary struct offset (208 in the RV32 layout, so not even 64-byte
		// aligned), and the emitted move is the unaligned form precisely because of that. The
		// property that actually matters -- consecutive chunks are exactly `width` apart and
		// together cover the register once -- is a relation between SEVERAL of these nodes and
		// is therefore established where they are built (RvvEmitTypedAluChunkBody's single
		// `c * chunk_bytes` stride, checked against VLEN/8 in RvvEmitTypedChunkGroup), not here
		// where only one window is visible.
		// Written as a subtraction rather than `offs_ + CHUNK_BYTES > STATE_OFFS_LIMIT`: offs_ is
		// a u32, so that sum wraps for offsets within CHUNK_BYTES of 2^32 and would wave through
		// exactly the most out-of-range values. Both operands here are constants and the limit is
		// far larger than the chunk, so this side cannot underflow. Bounding by the widest chunk
		// rather than by this value's own width keeps the check independent of the type.
		if (offs_ > STATE_OFFS_LIMIT - CHUNK_BYTES) {
			Panic("qir: vstatechunkload state offset is not a representable window");
		}
	}

	u32 Bytes()
	{
		return VTypeToSize(o(0).GetType());
	}

	u16 offs;
};

// vstatechunkstore: [R_STATE + offs] <- chunk, exactly 64 bytes, unaligned.
//
// The exact counterpart of vstatechunkload above, and everything said there about addressing holds
// unchanged: the base is R_STATE, the offset is a translation-time constant, there is no address
// operand, and the emitter must not go near make_vmem or R_MEMBASE.  The instruction's only
// operand is the V512 value being written, so the shape is the mirror image -- one input, no
// result.  Operand order follows InstVChunkStore's (destination first, then data).
//
// `offs` is validated the same way and fails closed the same way: structurally here, and against
// sizeof(CPUState) in QEmit, which is the bound that actually matters and which QIR cannot apply.
//
// SIDEEFF, for a STRONGER reason than the load's.  This writes raw bytes of CPUState at an offset
// QIR does not interpret, so it is both a memory write and an alias statement.  SIDEEFF makes
// QRegAlloc sync dirty globals to CPUState before it, which is what stops a pending global store
// from landing on top of the bytes this just wrote.
//
// KNOWN LIMITATION, and the reason any NEW future routing must keep discharging the obligation
// below.  SIDEEFF syncs globals BEFORE the instruction; it does not INVALIDATE a host register
// that is caching a global whose state slot this store overwrites.  After such a store the
// register would hold the pre-store value while CPUState holds the new one, and the allocator
// would consider it clean.  The load has no equivalent hazard because it only reads.  The rule is
// unchanged: an arbitrary state offset still requires its own proof that the written window is
// disjoint from every global's slot (or that QRegAlloc drops the overlapping tracks) before it may
// be routed; do not route a new offset on the strength of this comment alone.
//
// ROUTED today, for one exact shape that already carries that proof.  RV32's vadd.vv typed-chunk
// path (TRANSLATOR(vadd_vv), dbt/guest/rv32_qir.cpp) constructs this op for the low/high 64-byte
// windows of CPUState::vec.vreg, and
// experiments/2026-08-24-0935-rvv-typed-chunk-vaddvv-route/docs/C2_1A_TWO_CHUNK_SOURCE_AUDIT.md
// section 15 proves exactly those windows are disjoint from every global RV32Translator::GetStateInfo
// tracks (x1-x31, ip), so this route cannot hit the hazard above.
struct InstVStateChunkStore : InstWithOperands<0, 1> {
	static constexpr u32 CHUNK_BYTES = 64;
	// Exclusive upper bound on a CPUState offset, set by the u16 state-offset encoding.
	static constexpr u32 STATE_OFFS_LIMIT = 1u << 16;

	// M2C: as on the load side, the written window is VTypeToSize(s) bytes. This is the direction
	// where the width matters most -- a 64-byte store of a 128-bit architectural register would
	// overwrite 48 bytes of guest vector state that the instruction does not define.
	InstVStateChunkStore(u32 offs_, VOperand s, u8 sew_ = 0, u8 chunk_ = 0, bool masked_ = false,
			     u8 kmask_ = 0)
	    : InstWithOperands(Op::_vstatechunkstore, {}, {s}), offs(static_cast<u16>(offs_)),
	      active_sew(sew_), chunk(chunk_), masked(masked_), kmask(kmask_)
	{
		if (active_sew && active_sew != 4 && active_sew != 8)
			Panic("qir: unsupported active state store element width");
		if (kmask && (!active_sew || chunk >= 64 ||
		    kmask != 1 + chunk % RVV_FP_SHARED_MASK_MAX_CHUNKS_STORE))
			Panic("qir: vstatechunkstore names a shared mask outside its own chunk");
		if (!IsVectorVType(s.GetType())) {
			Panic("qir: vstatechunkstore source is not a vector value");
		}
		if (!s.IsVPR()) {
			Panic("qir: vstatechunkstore source is not a vector register");
		}
		// Unaligned for the reason the load states: the vreg base is an arbitrary CPUState
		// offset, and chunk stride is a property of the group, not of one window.
		// Subtraction for the same reason as the load's: `offs_ + CHUNK_BYTES` wraps in u32 for
		// offsets near 2^32 and would accept them.
		if (offs_ > STATE_OFFS_LIMIT - CHUNK_BYTES) {
			Panic("qir: vstatechunkstore state offset is not a representable window");
		}
	}

	u32 Bytes()
	{
		return VTypeToSize(i(0).GetType());
	}

	u16 offs;
	// Nonzero: store only elements below live vl; inactive destination bytes survive.
	u8 active_sew, chunk;
	bool masked;
	// F1 GUARD (2026-09-23). 0: the store derives its own active-lane mask from the live vl and
	// vstart (EmitRvvFpLaneMask into k7), as before. 1 + chunk: the enclosing FP frame's
	// vchunkmaskset already left exactly that mask resident in k(1 + chunk) (A12), so the store
	// uses it instead of recomputing it; QEmit::FpMaskRegs Panics if the frame never set it.
	// Meaningful only with active_sew != 0.
	u8 kmask;
	// Same bound as RVV_FP_SHARED_MASK_MAX_CHUNKS (defined below); restated here because this
	// struct precedes it, and pinned equal by a static_assert after that definition.
	static constexpr u8 RVV_FP_SHARED_MASK_MAX_CHUNKS_STORE = 6;
};

// vchunkbroadcast: chunk <- splat(*(u32 *)[R_STATE + offs]) -- one 32-bit CPUState word replicated
// into all 512/8/sew_bytes lanes.  Native-3.
//
// WHAT IT IS FOR.  RVV's `.vx` forms take one operand from an INTEGER register: `vmul.vx vd, vs2,
// rs1` is `vd[i] = vs2[i] * x[rs1]`.  Every lane sees the same scalar, so the lowering of that
// operand is a splat -- and this op is that splat and nothing else.  It performs no arithmetic and
// it does not know which instruction routed it.
//
// THE SCALAR COMES FROM CPUState AND NOT FROM AN OPERAND, and that is the SAME indirect-form
// decision InstVChunkLoad above had to make, for exactly the same reason.  Inside a typed chunk
// group nothing may be emitted but the typed body ops, because the guard branches over the body; a
// guest GPR arriving as an I32 operand would reach QRegAlloc::AllocOp with its track in MEM (the
// enclosing `rvvtypedchunkbegin` carries HAS_CALLS, so CallOp has already spilled every global) and
// the allocator would insert a fill INSIDE the group, which Emit_mov Panics on.  Reading the word
// from CPUState -- where CallOp has just guaranteed the live value sits -- removes the question
// instead of answering it: this op has no input operand, so no fill can be inserted.
//
// `offs` NAMES A GUEST GPR SLOT, and this op is the FIRST routed chunk op whose CPUState window
// deliberately IS a global's slot rather than provably disjoint from every one of them.  That is
// safe here and would not be safe for a store: the hazard InstVStateChunkStore documents is a WRITE
// landing on a slot the allocator still believes a host register holds cleanly.  This op only
// READS, SIDEEFF makes QRegAlloc sync dirty globals to CPUState first, and the bytes it reads are
// therefore the live architectural value of x[rs1] -- the same word rvdbt's own `HANDLER(vimul)`
// reads as `s->gpr[i.rs1()]`, so the direct route and the helper it replaces cannot disagree about
// the scalar, including for rs1 == x0 whose slot is never written and is zero.
//
// `offs` IS VALIDATED TWICE and fails closed both times, exactly as the two ops above: here,
// structurally, that the destination is a V512 value and that the 4-byte window fits the u16
// state-offset encoding; and in the backends against sizeof(CPUState), the bound QIR cannot apply.
//
// SEW=4 ONLY today, and the field exists so a widening is a checked change rather than a silent
// reinterpretation of lanes: x86 spells the other widths vpbroadcastb/w/q, which live in different
// AVX-512 subsets from the AVX512F this route's admission predicate probes for.  Every other value
// is a hard failure in both backends rather than a substituted lane width.
struct InstVChunkBroadcast : InstWithOperands<1, 0> {
	// The scalar this op reads, not the chunk it produces: one guest GPR is 4 bytes.
	static constexpr u32 SCALAR_BYTES = 4;
	// Exclusive upper bound on a CPUState offset, set by the u16 state-offset encoding.
	static constexpr u32 STATE_OFFS_LIMIT = 1u << 16;

	InstVChunkBroadcast(VOperand d, u32 offs_, u8 sew_bytes_)
	    : InstWithOperands(Op::_vchunkbroadcast, {d}, {}), offs(static_cast<u16>(offs_)),
	      sew_bytes(sew_bytes_)
	{
		// A2: any host vector width (V128/V256/V512). The emitter reads the splat width out of
		// this operand's type (make_vpr), exactly as vchunkload/vchunkstore do since P7N-D, so a
		// narrow destination is a narrow vpbroadcastd and never a 64-byte write.
		if (!IsVectorVType(d.GetType())) {
			Panic("qir: vchunkbroadcast destination is not a vector value");
		}
		if (!d.IsVPR()) {
			Panic("qir: vchunkbroadcast destination is not a vector register");
		}
		// Written as a subtraction for InstVStateChunkLoad's reason: `offs_ + SCALAR_BYTES`
		// wraps in u32 near 2^32 and would wave through the most out-of-range values.
		if (offs_ > STATE_OFFS_LIMIT - SCALAR_BYTES) {
			Panic("qir: vchunkbroadcast state offset is not a representable 32-bit window");
		}
		// The scalar is a 32-bit guest register, so its slot is 4-byte aligned in CPUState and
		// a misaligned offset means the caller computed a GPR address wrongly.
		if (offs_ % SCALAR_BYTES != 0) {
			Panic("qir: vchunkbroadcast state offset is not 4-byte aligned");
		}
		if (sew_bytes_ != 4) {
			Panic("qir: vchunkbroadcast with an unsupported SEW");
		}
	}
	// A6: the IMMEDIATE form. `d <- splat(imm)` for a translation-time 32-bit constant (the
	// sign-extended imm5 of vadd.vi). It reads no CPUState word; QEmit materialises the constant
	// in the fixed scratch GPR (ArchTraits::AX, never allocated) and splats from it. A distinct
	// tag type rather than a second u32 so a caller cannot pass a CPUState offset where a value
	// is meant, or the reverse. QCG-only: llvmgen refuses it.
	struct Imm {
		i32 value;
	};
	InstVChunkBroadcast(VOperand d, Imm imm_, u8 sew_bytes_)
	    : InstWithOperands(Op::_vchunkbroadcast, {d}, {}), offs(0), sew_bytes(sew_bytes_),
	      is_imm(true), imm((u32)imm_.value)
	{
		if (!IsVectorVType(d.GetType())) {
			Panic("qir: vchunkbroadcast destination is not a vector value");
		}
		if (!d.IsVPR()) {
			Panic("qir: vchunkbroadcast destination is not a vector register");
		}
		if (sew_bytes_ != 4) {
			Panic("qir: vchunkbroadcast with an unsupported SEW");
		}
	}

	u16 offs;
	u8 sew_bytes;
	bool is_imm{}; // A6: when set, `imm` is the splat value and `offs` is meaningless
	u32 imm{};
};

// T7R: scalar-FP splat and packed FP lane operation used only by the guarded pure-QCG vfalu
// frame.  The scalar offset names one NaN-boxed RV32 F register.  `chunk` makes the runtime VL
// mask part of the typed operation rather than an emitter-side guess.
struct InstVChunkFBroadcast : InstWithOperands<1, 0> {
	InstVChunkFBroadcast(VOperand d, u32 offs_, u8 sew_bytes_)
	    : InstWithOperands(Op::_vchunkfbroadcast, {d}, {}), offs(static_cast<u16>(offs_)),
	      sew_bytes(sew_bytes_)
	{
		// A9: any host vector width; the emitter splats to the destination's own width.
		if (!IsVectorVType(d.GetType()) || !d.IsVPR() ||
		    (sew_bytes_ != 0 && sew_bytes_ != 4 && sew_bytes_ != 8) ||
		    offs_ > 0xffffu - sizeof(u64))
			Panic("qir: invalid vchunkfbroadcast");
	}
	u16 offs;
	u8 sew_bytes;
};

// A12. `kmask` is the FP lane op's ACTIVE-MASK SOURCE, stated on the node rather than inferred by
// the emitter: 0 means "derive k1 from the live vl yourself" (the pre-A12 per-op prologue, k2 as the
// epilogue scratch). Shared masks use k(1 + chunk % 6), with k7 as scratch. A bounded batch
// may reuse a slot only after its previous chunk's consumers finish; QEmit checks the current
// owner of each slot. A run-time element width has no translation-time shared mask.
static constexpr u8 RVV_FP_SHARED_MASK_MAX_CHUNKS = 6; // k1..k6 resident, k7 scratch
static_assert(InstVStateChunkStore::RVV_FP_SHARED_MASK_MAX_CHUNKS_STORE == RVV_FP_SHARED_MASK_MAX_CHUNKS,
	      "the shared-mask store bound must equal the shared-mask chunk bound");
static constexpr u8 RVV_FP_SCRATCH_KMASK = 7;
static inline void CheckFpKmask(u8 kmask, u8 chunk, u8 sew_bytes)
{
	if (kmask == 0)
		return;
	if (kmask != (u8)(1 + chunk % RVV_FP_SHARED_MASK_MAX_CHUNKS) ||
	    chunk >= 8u * MAX_REG_CHUNKS || sew_bytes == 0)
		Panic("qir: fp lane op names a shared mask register it may not use");
}

struct InstVChunkFALU : InstWithOperands<1, 2> {
	InstVChunkFALU(VOperand d, VOperand s2, VOperand s1, u8 sew_bytes_, u8 funct6_, u8 chunk_,
		       u8 kmask_ = 0, bool masked_ = false)
	    : InstWithOperands(Op::_vchunkfalu, {d}, {s2, s1}), sew_bytes(sew_bytes_),
	      funct6(funct6_), chunk(chunk_), kmask(kmask_), masked(masked_)
	{
		if ((sew_bytes_ != 0 && sew_bytes_ != 4 && sew_bytes_ != 8) || chunk_ >= 8u * MAX_REG_CHUNKS)
			Panic("qir: invalid vchunkfalu shape");
		CheckFpKmask(kmask_, chunk_, sew_bytes_);
	}
	u8 sew_bytes, funct6, chunk;
	u8 kmask; // 0 = own prologue; otherwise the frame's current shared-mask slot
	bool masked;
};

// A3. THE PARTIAL-vl ARM'S THREE NODES. See config.h rvv_qcg_partial_vl for the design.
//
// rvvtypedchunkpartial: the boundary between the frame's full-vl body and its partial-vl body. In
// the emitted code it ends the full body (jump to the frame's join) and binds the label the guard
// jumps to when vl < VLMAX. Not a typed body op (it does not count toward n_typed).
struct InstRVVTypedChunkPartial : InstNoOperands {
	InstRVVTypedChunkPartial() : InstNoOperands(Op::_rvvtypedchunkpartial) {}
};

// Scalar address/counter maintenance inside a vector run. The run former admits only RV32
// add/addi/sub, which cannot trap or transfer control. Keeping the raw word lets the QCG backend
// perform the exact architectural GPR update directly against CPUState without introducing a
// QIR-global value across the frame's hidden guard/fallback control-flow join.
struct InstRVVRunScalar : InstNoOperands {
	explicit InstRVVRunScalar(u32 raw_) : InstNoOperands(Op::_rvvrunscalar), raw(raw_) {}
	u32 raw;
};

// Build this chunk's mask from live vl/vstart into k(1 + chunk % 6). Batched frames
// place it immediately before its batch; later batches may recycle the slot. k7 remains
// scratch, and QEmit checks mask ownership. Reads CPUState, hence SIDEEFF.
struct InstVChunkMaskSet : InstNoOperands {
	InstVChunkMaskSet(u8 chunk_, u8 lanes_)
	    : InstNoOperands(Op::_vchunkmaskset), chunk(chunk_), lanes(lanes_)
	{
		if (chunk_ >= 8u * MAX_REG_CHUNKS || lanes_ == 0 || lanes_ > 16)
			Panic("qir: invalid vchunkmaskset shape");
	}
	u8 chunk, lanes;
};

// S1-3. The exclusive upper bound on any architectural element index a frame can name, DERIVED
// rather than chosen: the largest register group is LMUL=8, the widest supported register is
// VLEN_MAX_BITS = 4096 bits, and the smallest element is SEW=8 bits, so a group holds at most
// 8 * 4096 / 8 = 4096 elements. qir.h must not include a guest header, so the guest's own
// VLEN_MAX_BYTES is tied to this constant by a static_assert in rv32_qir.cpp -- the one translation
// unit that includes both -- rather than by this comment.
inline constexpr u32 kMaxVectorElements = 4096;

// S1-1. vchunkactive: THE ACTIVE-VL BOUND, and the ONLY node in a typed frame that is control flow
// rather than data.
//
// `base = chunk * lanes` is this chunk's first element index inside the register group, so
// `vl <= base` says every element the chunk covers lies in the TAIL (RVV 1.0 v-spec 3.4.3: the tail
// set is [vl, VLMAX)). A tail element is never an active body element, so for an unmasked or masked
// FP lane op the chunk's whole contribution is empty: its EVEX-masked arithmetic runs under an
// all-zero opmask, which writes no lane and -- this is the load-bearing half -- updates no MXCSR
// exception flag, and its masked destination store writes no byte. Skipping such a chunk is
// therefore bit-for-bit the architectural no-op the chunk already was.
//
// WHY THE TEST IS ON vl AND NOT ON THE MASK. `base` is strictly increasing in `chunk`, so
// `vl <= base_c` implies `vl <= base_{c+1} <= ...`: inactive chunks are always a SUFFIX and one
// forward branch can leave the whole rest of the body. The active MASK is NOT monotone -- with
// `vstart > 0` a leading chunk's mask is also zero while later chunks are active -- so a
// `kortest`-style test would skip live work. Prestart chunks are consequently NOT skipped here;
// they keep running under their zero mask, exactly as before.
//
// WHERE IT BRANCHES TO. The frame's body-done label. An FP frame binds it in Emit_rvvqcgfpend at the
// top of the FP epilogue: INSIDE the bracket, so an early-exited body still runs stmxcsr -> fflags
// accrual -> ldmxcsr and still clears vec.vstart. S1-3: an INTEGER frame has no such epilogue, so
// Emit_rvvtypedchunkend binds it instead, immediately before the frame's single `vstart = 0` write
// and before the join. In both cases it is NEVER the fallback label -- taking the fallback after a
// partial body would run the ordered helpers on top of results the body already stored.
//
// `chunk` is bounded by the largest index any admitted frame can name: LMUL=8 registers times
// VLEN_MAX/512 host chunks each, which is the `total > 8 * rvvrun::kMaxChunks` cap both FP
// admission predicates already apply, and which the integer route restates as its own `chunks <= 64`
// conjunct. It is a number here because qir.h must not include a guest header. `chunk` itself is
// carried for diagnostics and for the "chunk 0 is never bounded" invariant, not for the comparison.
//
// S1-3. THE COMPARISON OPERAND IS `element_base`, NOT `(chunk, lanes)`. It is this chunk's first
// ARCHITECTURAL ELEMENT INDEX, the same unit as vec.vl, and it replaces S1-1's product for two
// reasons:
//
//   (a) `lanes <= 16` was vchunkmaskset's range, borrowed because FP SEW is only 4 or 8 bytes
//       (a 64-byte chunk is at most 16 lanes). It is false for the integer routes: an e8/m1 frame
//       has 64 lanes per chunk and an e16/m2 frame has 32.
//   (b) every guarded chunk node ALREADY carries this exact quantity
//       (InstVChunkPartialAlu::element_base, InstVChunkWiden::base, InstVChunkNarrowShift::base,
//       InstVMaskLogic::base), so "does the bound agree with the body it guards" becomes an
//       equality between one field and another rather than an arithmetic re-derivation.
//
// The FP call site passes `first * lanes` -- the same number the old constructor multiplied -- so the
// emitted immediate, and therefore every emitted byte of an S1-1/S1-2A/S1-2D frame, is unchanged.
struct InstVChunkActive : InstNoOperands {
	InstVChunkActive(u8 chunk_, u32 element_base_)
	    : InstNoOperands(Op::_vchunkactive), chunk(chunk_), element_base(element_base_)
	{
		if (chunk_ >= 64 || element_base_ >= kMaxVectorElements)
			Panic("qir: invalid vchunkactive shape");
	}
	u8 chunk;
	u32 element_base;
};

// Different source/destination EEWs require separate CPUState windows and group validation.
struct InstVChunkExtend : InstNoOperands {
	InstVChunkExtend(u32 rd_, u32 rs2_, u8 dst_sew_, u8 src_sew_, u16 bytes_, u32 base_,
		bool sign_, bool masked_, bool finish_)
	    : InstNoOperands(Op::_vchunkextend), rd(rd_), rs2(rs2_), dst_sew(dst_sew_), src_sew(src_sew_),
	      bytes(bytes_), base(base_), sign(sign_), masked(masked_), finish(finish_)
	{
		if ((dst_sew != 2 && dst_sew != 4 && dst_sew != 8) ||
		    (src_sew != 1 && src_sew != 2 && src_sew != 4) || src_sew >= dst_sew ||
		    (bytes != 16 && bytes != 32 && bytes != 64) || rd > 0xffffu - bytes ||
		    rs2 > 0xffffu - bytes * src_sew / dst_sew)
			Panic("qir: invalid integer extension shape");
	}
	u32 rd, rs2;
	u8 dst_sew, src_sew;
	u16 bytes;
	u32 base;
	bool sign, masked, finish;
};

struct InstVChunkWiden : InstNoOperands {
	enum Kind : u8 { Add, Sub, Mul, Macc };
	InstVChunkWiden(u8 op_, u32 rd_, u32 rs2_, u32 rs1_, u8 sew_, u16 bytes_, u32 base_,
		bool scalar_, bool zero_, bool wide2_, bool sign2_, bool sign1_, bool masked_, bool finish_)
	    : InstNoOperands(Op::_vchunkwiden), op(op_), rd(rd_), rs2(rs2_), rs1(rs1_), sew(sew_),
	      bytes(bytes_), base(base_), scalar(scalar_), zero(zero_), wide2(wide2_),
	      sign2(sign2_), sign1(sign1_), masked(masked_), finish(finish_)
	{
		if (op > Macc || (sew != 1 && sew != 2 && sew != 4) ||
		    (bytes != 16 && bytes != 32 && bytes != 64) || (wide2 && op >= Mul))
			Panic("qir: invalid widening integer shape");
	}
	u8 op;
	u32 rd, rs2, rs1;
	u8 sew;
	u16 bytes;
	u32 base;
	bool scalar, zero, wide2, sign2, sign1, masked, finish;
};

struct InstVChunkNarrowShift : InstNoOperands {
	InstVChunkNarrowShift(u32 rd_, u32 rs2_, u32 rs1_, u32 imm_, u8 src_, u8 sew_,
		u16 bytes_, u32 base_, bool arith_, bool masked_, bool finish_)
	    : InstNoOperands(Op::_vchunknarrowshift), rd(rd_), rs2(rs2_), rs1(rs1_), imm(imm_),
	      src(src_), sew(sew_), bytes(bytes_), base(base_), arith(arith_), masked(masked_), finish(finish_)
	{
		if (src > 2 || (sew != 1 && sew != 2 && sew != 4) ||
		    (bytes != 16 && bytes != 32 && bytes != 64)) Panic("qir: invalid narrowing shift shape");
	}
	u32 rd, rs2, rs1, imm;
	u8 src, sew; // source 1: 0 vector, 1 RV32 GPR, 2 literal; sew is destination bytes.
	u16 bytes; // Wide source chunk bytes; the destination occupies half this amount.
	u32 base;
	bool arith, masked, finish;
};

// ORDER ITEM 4 (2026-09-19): the NARROWING CLIP `vnclipu.w*` / `vnclip.w*`. LAST of the five narrow
// fixed-point nodes.
//
// IT IS THE ONLY ONE OF THE FIVE THAT COMBINES ALL THREE FIXED-POINT MECHANISMS: a 2*SEW source
// narrowed to SEW (the geometry `vchunknarrowshift` already has), a `vxrm` rounding shift, and a
// saturating clip into `vxsat`. It is also the only one whose SHIFT IS A RUNTIME VECTOR rather than
// a constant, which is why `RvvRoundoffIncrement` takes a `Value *` -- generalised for this node
// rather than duplicated for it.
//
// SHAPE IS `vchunknarrowshift`'s, deliberately: an offset-carrying `InstNoOperands` that loads the
// wide source and stores the narrow destination itself, because the source group is twice the
// destination group and the SSA chunk operands the element-wise nodes use cannot express that.
//
// `is_signed` PICKS BOTH THE EXTENSION AND THE BOUNDS. `vnclipu` reads the source unsigned and
// clips to [0, 2^SEW - 1]; `vnclip` reads it signed and clips to [-2^(SEW-1), 2^(SEW-1) - 1]. They
// are not the same operation with a different bound, which is why this is not a bounds field.
struct InstVChunkNarrowClip : InstNoOperands {
	InstVChunkNarrowClip(u32 rd_, u32 rs2_, u32 rs1_, u32 imm_, u8 src_, u8 sew_, u16 bytes_,
			     u32 base_, bool is_signed_, bool masked_, bool finish_)
	    : InstNoOperands(Op::_vchunknarrowclip), rd(rd_), rs2(rs2_), rs1(rs1_), imm(imm_),
	      src(src_), sew(sew_), bytes(bytes_), base(base_), is_signed(is_signed_),
	      masked(masked_), finish(finish_)
	{
		if (src > 2 || (sew != 1 && sew != 2 && sew != 4) ||
		    (bytes != 16 && bytes != 32 && bytes != 64))
			Panic("qir: invalid narrowing clip shape");
	}
	u32 rd, rs2, rs1, imm;
	u8 src, sew; // source 1: 0 vector, 1 RV32 GPR, 2 literal; sew is DESTINATION bytes.
	u16 bytes;   // wide source chunk bytes; the destination occupies half
	u32 base;
	bool is_signed, masked, finish;
};

struct InstVChunkFToI : InstNoOperands {
	InstVChunkFToI(u32 rd_, u32 rs_, u8 sew_, u16 bytes_, u32 base_, bool signed_, bool masked_, bool rtz_, u8 src_sew_=0)
	    : InstNoOperands(Op::_vchunkftoi), rd(rd_), rs(rs_), sew(sew_), bytes(bytes_),
	      base(base_), is_signed(signed_), masked(masked_), rtz(rtz_), src_sew(src_sew_?src_sew_:sew_)
	{
		if ((sew != 4 && sew != 8 && !(sew==2&&src_sew==4)) || (src_sew != 4 && src_sew != 8) ||
		    (bytes != 8 && bytes != 16 && bytes != 32 && bytes != 64) || bytes/src_sew == 0 || bytes/sew*src_sew > 64)
			Panic("qir: invalid float-to-integer chunk");
	}
	u32 rd, rs;
	u8 sew;
	u16 bytes;
	u32 base;
	bool is_signed, masked, rtz;
	u8 src_sew;
};

struct InstVChunkIToF : InstNoOperands {
	InstVChunkIToF(u32 rd_, u32 rs_, u8 sew_, u16 bytes_, u32 base_, bool signed_, bool masked_, u8 src_sew_=0)
	    : InstNoOperands(Op::_vchunkitof), rd(rd_), rs(rs_), sew(sew_), bytes(bytes_),
	      base(base_), is_signed(signed_), masked(masked_), src_sew(src_sew_?src_sew_:sew_)
	{
		if ((sew != 4 && sew != 8) || (src_sew != 4 && src_sew != 8 && !(src_sew==2&&sew==4)) ||
		    (bytes != 8 && bytes != 16 && bytes != 32 && bytes != 64) || bytes/sew*src_sew > 64)
			Panic("qir: invalid integer-to-float chunk");
	}
	u32 rd, rs;
	u8 sew;
	u16 bytes;
	u32 base;
	bool is_signed, masked;
	u8 src_sew;
};

struct InstVChunkFToF : InstNoOperands {
	InstVChunkFToF(u32 rd_,u32 rs_,u8 sew_,u16 bytes_,u32 base_,bool masked_,bool rod_=false)
	    : InstNoOperands(Op::_vchunkftof),rd(rd_),rs(rs_),sew(sew_),bytes(bytes_),base(base_),masked(masked_),rod(rod_)
	{
		if ((sew!=4&&sew!=8)||(rod&&sew!=4)||(bytes!=8&&bytes!=16&&bytes!=32&&bytes!=64)||bytes/sew*(sew==4?8:4)>64)
			Panic("qir: invalid float-width conversion");
	}
	u32 rd,rs;
	u8 sew;
	u16 bytes;
	u32 base;
	bool masked,rod;
};

struct InstVChunkFClass : InstNoOperands {
	InstVChunkFClass(u32 rd_, u32 rs_, u8 sew_, u16 bytes_, u32 base_, bool masked_, bool finish_)
	    : InstNoOperands(Op::_vchunkfclass), rd(rd_), rs(rs_), sew(sew_), bytes(bytes_),
	      base(base_), masked(masked_), finish(finish_)
	{
		if ((sew != 4 && sew != 8) || (bytes != 16 && bytes != 32 && bytes != 64))
			Panic("qir: invalid floating classification chunk");
	}
	u32 rd, rs;
	u8 sew;
	u16 bytes;
	u32 base;
	bool masked, finish;
};

struct InstVChunkIndex : InstNoOperands {
	InstVChunkIndex(u32 rd_,u8 sew_,u16 bytes_,u32 base_,bool masked_,bool finish_)
	    : InstNoOperands(Op::_vchunkindex),rd(rd_),sew(sew_),bytes(bytes_),base(base_),masked(masked_),finish(finish_)
	{
		if((sew!=1&&sew!=2&&sew!=4&&sew!=8)||(bytes!=16&&bytes!=32&&bytes!=64))
			Panic("qir: invalid element-index chunk");
	}
	u32 rd;
	u8 sew;
	u16 bytes;
	u32 base;
	bool masked,finish;
};

struct InstVGather : InstNoOperands {
	InstVGather(u8 rd_, u8 data_, u8 index_, u8 sew_, u8 isew_, u8 mode_,
		    u16 regbytes_, u16 vlmax_, bool masked_, u8 slide_=0)
	    : InstNoOperands(Op::_vgathernative), rd(rd_), data(data_), index(index_), sew(sew_),
	      isew(isew_), mode(mode_), regbytes(regbytes_), vlmax(vlmax_), masked(masked_), slide(slide_)
	{
		if (rd > 31 || data > 31 || index > 31 || mode > 3 || slide > 4 || (mode==3&&slide<3) ||
		    (sew != 1 && sew != 2 && sew != 4 && sew != 8) ||
		    (isew != 1 && isew != 2 && isew != 4 && isew != 8) ||
		    regbytes < 16 || regbytes > 512 || (regbytes & (regbytes-1)) || !vlmax || vlmax > 4096)
			Panic("qir: invalid register gather shape");
	}
	u8 rd, data, index, sew, isew, mode; // mode: vector, GPR, immediate
	u16 regbytes, vlmax;
	bool masked;
	u8 slide; // 0: gather; 1/2: slide up/down; 3/4: slide1 up/down (mode 3: boxed FPR)
};

struct InstVMemory : InstNoOperands {
	// `vlmax` is the TRANSLATION-TIME element count of this access's vtype (LMUL*VLEN/SEW), and it
	// is OPTIONAL: zero means "the route did not record one". The element loop below does not need
	// it -- its trip count is the live `vec.vl` -- so every existing route may leave it zero and
	// nothing about the emitted loop changes. It exists for the Z3 strided-gather body, which is a
	// STATIC unroll over ceil(vlmax/lanes) chunks and therefore cannot derive its chunk count from
	// this node's other fields: `regbytes` is VLEN/8 and carries no LMUL, while the destination
	// register group spans EMUL = vlmax*EEW/regbytes registers. A zero here keeps the element loop.
	InstVMemory(u8 data_,u8 base_,u8 index_,u8 sew_,u8 isew_,u8 mode_,u16 regbytes_,bool store_,bool masked_,
	            u8 nf_=1,u8 fieldregs_=1,u16 vlmax_=0)
	    : InstNoOperands(Op::_vmemorynative),data(data_),base(base_),index(index_),sew(sew_),isew(isew_),
	      mode(mode_),regbytes(regbytes_),store(store_),masked(masked_),nf(nf_),fieldregs(fieldregs_),
	      vlmax(vlmax_)
	{
		if(data>31||base>31||index>31||mode>4||(mode==3&&(sew!=1||masked))||
		   (mode==4&&(masked||(index!=1&&index!=2&&index!=4&&index!=8)))||(sew!=1&&sew!=2&&sew!=4&&sew!=8)||
		   (isew!=1&&isew!=2&&isew!=4&&isew!=8)||regbytes<16||regbytes>512||(regbytes&(regbytes-1))||
		   nf<1||nf>8||!fieldregs||fieldregs>8||data+(nf-1)*fieldregs>=32||(mode>=3&&nf!=1)||
		   // EMUL <= 8: vlmax elements of `sew` bytes occupy vlmax*sew/regbytes registers, and an
		   // access whose destination group would exceed eight registers is not a legal encoding.
		   ((u32)vlmax*sew>8u*(u32)regbytes))
			Panic("qir: invalid vector memory shape");
	}
	u8 data,base,index,sew,isew,mode; // unit stride, scalar stride, vector offsets, mask bytes, whole-register
	u16 regbytes;
	bool store,masked;
	u8 nf,fieldregs;
	u16 vlmax;
};

struct InstVWholeMove : InstNoOperands {
	InstVWholeMove(u8 rd_,u8 src_,u8 nregs_,u16 regbytes_)
	    : InstNoOperands(Op::_vwholemove),rd(rd_),src(src_),nregs(nregs_),regbytes(regbytes_)
	{
		if((nregs!=1&&nregs!=2&&nregs!=4&&nregs!=8)||rd+nregs>32||src+nregs>32||
		   rd%nregs||src%nregs||regbytes<16||regbytes>512||(regbytes&(regbytes-1)))
			Panic("qir: invalid whole-register move shape");
	}
	u8 rd,src,nregs;
	u16 regbytes;
};

// ORDER ITEM 4 (2026-09-19): the CARRY/BORROW family -- `vadc.vvm`/`vadc.vxm` and
// `vsbc.vvm`/`vsbc.vxm`, the forms whose destination is a VECTOR register.
//
// `v0` IS A DATA OPERAND HERE, NOT A MASK, and it is the second family in this checkpoint where
// that distinction decides the lowering (the first was `vfmerge`). `vadc` computes
// `vd[i] = vs2[i] + vs1[i] + v0[i]` and writes EVERY body element; there is no masked-off element
// to preserve. An implementation that treated `v0` as a write enable would leave half the
// destination untouched and drop the carry from the other half.
//
// THE CARRY-OUT FORMS ARE NOT THIS NODE. `vmadc` and `vmsbc` write a MASK register -- one bit per
// element, one register regardless of LMUL -- which is a different destination shape with its own
// overlap rule, exactly as the FP compares are a different route from the FP arithmetic. They keep
// the helper.
//
// It is PURE. Unlike its saturating sibling this family raises nothing and sets no sticky flag, so
// the node's flags are `0` and the optimiser may treat it as an ordinary value computation.
struct InstVChunkAdc : InstWithOperands<1, 2> {
	InstVChunkAdc(VOperand d, VOperand s1, VOperand s2, u8 sew_bytes_, bool sub_,
		      u32 element_base_)
	    : InstWithOperands(Op::_vchunkadc, {d}, {s1, s2}), element_base(element_base_),
	      sew_bytes(sew_bytes_), sub(sub_)
	{
		CheckChunkAluShape("vchunkadc", d, s1, s2, sew_bytes_);
	}

	// The unit's first architectural element, so the emitter can fetch THIS unit's `v0` bits.
	u32 element_base;
	u8 sew_bytes;
	bool sub;
};

// ORDER ITEM 4 (2026-09-19): the FRACTIONAL MULTIPLY `vsmul.vv` / `vsmul.vx`. Fourth of the five
// narrow fixed-point nodes.
//
// IT IS THE FIRST NODE TO ROUND AT A SHIFT GREATER THAN ONE, which is why it comes after `vavg`:
// `vaadd` shifts by 1, where the spec's `v[d-2:0] != 0` term is empty and never observed. `vsmul`
// shifts by SEW-1, so the same shared `RvvRoundoffIncrement` is exercised with a real sticky-bit
// term for the first time. Reusing it rather than writing a second rounding rule is the point.
//
// THE OPERANDS ARE FRACTIONS, WHICH IS WHERE THE SHIFT COMES FROM. `vsmul` treats both inputs as
// Q(SEW-1) signed fractions, multiplies into 2*SEW and keeps the high half -- hence a rounding
// right shift of SEW-1 rather than SEW. Shifting by SEW would be the plausible-looking error and
// would halve every result.
//
// ONE SATURATING CASE, AND IT IS NOT A CORNER TO BE HANDWAVED. MIN*MIN is exactly +1.0 in that
// fixed-point format, one ulp above the representable maximum, so it is the only input pair that
// can set `vxsat` -- which means a test that never feeds it measures nothing about saturation here.
// The node is SIDEEFF for that flag, exactly as `InstVChunkSatAdd` is, and carries an element base
// so the flag is raised only for lanes the instruction actually operates on.
struct InstVChunkFracMul : InstWithOperands<1, 2> {
	InstVChunkFracMul(VOperand d, VOperand s1, VOperand s2, u8 sew_bytes_, u32 element_base_,
			  bool masked_ = false)
	    : InstWithOperands(Op::_vchunkfracmul, {d}, {s1, s2}), element_base(element_base_),
	      sew_bytes(sew_bytes_), masked(masked_)
	{
		CheckChunkAluShape("vchunkfracmul", d, s1, s2, sew_bytes_);
	}

	u32 element_base;
	u8 sew_bytes;
	// C5-MASK: same role as `InstVChunkSatAdd::masked` -- `vxsat` only.
	bool masked;
};

// ORDER ITEM 4 (2026-09-19): the FIXED-POINT AVERAGING family -- `vaaddu`, `vaadd`, `vasubu`,
// `vasub`, in their `.vv` and `.vx` forms. The third of the five narrow fixed-point nodes.
//
// THIS IS THE ONE THAT BRINGS IN `vxrm`, and that is why it comes before `vsmul` and `vnclip`:
// all three round by the same architectural CSR, so the rounding rule is emitted ONCE, by
// `RvvRoundoffIncrement`, and the two remaining nodes are meant to call it rather than restate it.
// `vxrm` is a REAL INPUT, not a mode flag that can be assumed: the same encoding on the same
// operands produces four different answers as it varies, so a route that hard-coded any one of
// them would be right 25% of the time on a guest that sets it.
//
// THERE IS NO IMMEDIATE FORM TO REFUSE. This family is OPMVV/OPMVX (funct3 2 and 6), and RVV 1.0
// defines no `.vi` encoding for it at all -- so unlike `vsatadd` and `vadc`, whose `.vi`/`.vim`
// forms this backend cannot build for want of an immediate `vchunkbroadcast` lowering, the
// averaging family's native support here is COMPLETE for every form the ISA defines.
//
// IT IS PURE. Averaging saturates nothing and raises nothing; it only READS `vxrm`. The node
// carries no element base for that reason -- there is no flag to gate on an active-lane predicate,
// so the rounding applies to whatever lanes the shared store predicate lets through.
struct InstVChunkAvg : InstWithOperands<1, 2> {
	// The four funct6 values, named individually for the same reason `InstVChunkSatAdd`'s are:
	// signedness changes how the operands are EXTENDED into the SEW+1 arithmetic, and add/sub
	// changes the operation, so a mis-selected pair must not be representable as one bit-flip.
	enum class Kind : u8 { AddU = 0, AddS = 1, SubU = 2, SubS = 3 };
	InstVChunkAvg(VOperand d, VOperand s1, VOperand s2, u8 sew_bytes_, Kind kind_)
	    : InstWithOperands(Op::_vchunkavg, {d}, {s1, s2}), sew_bytes(sew_bytes_), kind(kind_)
	{
		CheckChunkAluShape("vchunkavg", d, s1, s2, sew_bytes_);
		if ((u8)kind_ > (u8)Kind::SubS)
			Panic("qir: invalid averaging kind");
	}

	u8 sew_bytes;
	Kind kind;
};

// ORDER ITEM 4 (2026-09-19): the SATURATING integer add/sub family -- `vsaddu`, `vsadd`, `vssubu`,
// `vssub`, in their `.vv`, `.vx` and `.vi` forms.
//
// WHY ITS OWN NODE RATHER THAN A ROW ON `vchunkadd`, and why not the QCG mega-node either. QCG emits
// this family through `InstVChunkPartialAlu`, a 52-kind opcode that also carries the averaging,
// round-shift, clip and fractional-multiply families plus the partial-arm protocol. Lowering that
// wholesale would be one very large change whose per-kind correctness could not be reviewed family
// by family, and it would import a partial-VL protocol this backend deliberately does not use. The
// plan's recorded proposal is one narrow node per semantic family -- what `vchunkextend`,
// `vchunkwiden` and `vchunknarrowshift` already are -- and this is the first of them.
//
// IT IS NOT PURE, WHICH IS THE ONE STRUCTURAL DIFFERENCE FROM `vchunkadd`. Saturation sets
// `vec.vxsat`, a STICKY architectural flag that RVV 1.0 never clears implicitly, so the node carries
// `Flags::SIDEEFF` where the ordinary lane ops carry `0`. A pure node would let the optimiser drop
// a saturating operation whose RESULT was unused and silently lose the flag with it.
//
// THE FOUR KINDS ARE THE FOUR FUNCT6 VALUES, not a signedness bit plus an add/sub bit, because the
// unsigned and signed forms saturate to different bounds and LLVM has a distinct intrinsic for each
// (`uadd.sat`, `sadd.sat`, `usub.sat`, `ssub.sat`). Naming them individually is what keeps a
// mis-selected pair from being representable.
//
// IT CARRIES AN ELEMENT BASE AND `vchunkadd` DOES NOT, and the reason is the flag rather than the
// arithmetic. `vxsat` must be set only for elements the instruction actually operates on, so the
// emitter needs this unit's first element index to build the active-lane predicate the comparison is
// gated by. The node still delimits no anchor work unit -- it is a two-input SSA value op like its
// pure siblings -- which is why `ClassifyNode` keeps it on the Support row with no `has_base`.
struct InstVChunkSatAdd : InstWithOperands<1, 2> {
	enum class Kind : u8 { AddU = 0, AddS = 1, SubU = 2, SubS = 3 };
	InstVChunkSatAdd(VOperand d, VOperand s1, VOperand s2, u8 sew_bytes_, Kind kind_,
			 u32 element_base_, bool masked_ = false)
	    : InstWithOperands(Op::_vchunksatadd, {d}, {s1, s2}), element_base(element_base_),
	      sew_bytes(sew_bytes_), kind(kind_), masked(masked_)
	{
		CheckChunkAluShape("vchunksatadd", d, s1, s2, sew_bytes_);
		if ((u8)kind_ > (u8)Kind::SubS)
			Panic("qir: invalid saturating add kind");
	}

	u32 element_base;
	u8 sew_bytes;
	Kind kind;
	// C5-MASK: whether `v0` gates this lane operation. It changes NOTHING about the arithmetic
	// and everything about `vxsat`: a masked-off lane that would saturate must not set the
	// sticky flag, so the flag's reduction is ANDed with the architectural mask as well as with
	// the active-element predicate. The destination's own preservation is the store's business.
	bool masked;
};

// ORDER ITEM 4 (2026-09-19): one unit of `vfmerge.vfm` / `vfmv.v.f`.
//
// THE MASK IS AN OPERAND, NOT A WRITE ENABLE, and that is the one thing about this family that is
// easy to get backwards. `vfmerge` writes EVERY body element: `vd[i] = v0[i] ? f[rs1] : vs2[i]`.
// An implementation that treated `v0` as a store predicate -- the way every genuinely masked
// instruction does -- would leave `vs2`'s value out of the destination entirely and leave the old
// `vd` there instead, which is right only when `vd == vs2`.
//
// `merge` false is `vfmv.v.f`, whose encoding fixes `vs2 = 0` and which has no mask term at all.
// `fo` is the F-register's CPUState offset; the scalar is NaN-unboxed at SEW 32 by the emitter,
// using integer operations only, so this family raises nothing and needs no FP bracket.
struct InstVChunkFMerge : InstNoOperands {
	InstVChunkFMerge(u32 rd_, u32 rs2_, u32 fo_, u8 sew_, u16 bytes_, u32 base_, bool merge_,
			 bool finish_)
	    : InstNoOperands(Op::_vchunkfmerge), rd(rd_), rs2(rs2_), fo(fo_), sew(sew_),
	      bytes(bytes_), base(base_), merge(merge_), finish(finish_)
	{
		if ((sew != 4 && sew != 8) || (bytes != 16 && bytes != 32 && bytes != 64) ||
		    bytes % sew != 0)
			Panic("qir: invalid RVV float merge chunk");
	}
	u32 rd, rs2, fo;
	u8 sew;
	u16 bytes;
	u32 base;
	bool merge, finish;
};

// ORDER ITEM 4 (2026-09-19): the CHUNKED 7-bit estimates, `vfrsqrt7.v` and `vfrec7.v`.
//
// WHY A SECOND NODE ALONGSIDE `InstVFEstimate`. That one is a WHOLE-REGISTER node -- it carries
// `regbytes` and no chunk index, because QCG's emitter walks the elements in a run-time loop. Every
// LLVM route is chunked: one node per host-vector-sized unit, carrying its own element `base`, so
// the unit's active-lane predicate and its window are translation-time facts. The two shapes are not
// interchangeable and merging them would give one of the backends a field it cannot honour.
//
// ONE NODE FOR BOTH INSTRUCTIONS, selected by `sqrt`, for the reason the family question is decided
// everywhere else in this file: they share the frame, the geometry, the subnormal normalisation, the
// 7-bit table index and the flag path, and differ in the TABLE and in the special-value tree. That
// is one semantic family with two members, not two families.
//
// THE TABLE IS NOT A POINTER. `InstVFEstimate::table` carries a HOST address, which is correct for
// QCG (it emits code that runs in the same process) and would be a silent disaster for an artifact
// built by `elfaot` and executed by `elfrun` -- a different process. The LLVM emitter materialises
// the table as a private module constant instead, exactly as C2a's `vlmax` table is.
struct InstVChunkFEstimate : InstNoOperands {
	InstVChunkFEstimate(u32 rd_, u32 rs_, u8 sew_, u16 bytes_, u32 base_, bool masked_,
			    bool sqrt_, bool finish_)
	    : InstNoOperands(Op::_vchunkfestimate), rd(rd_), rs(rs_), sew(sew_), bytes(bytes_),
	      base(base_), masked(masked_), sqrt(sqrt_), finish(finish_)
	{
		if ((sew != 4 && sew != 8) || (bytes != 16 && bytes != 32 && bytes != 64) ||
		    bytes % sew != 0)
			Panic("qir: invalid RVV estimate chunk");
	}
	u32 rd, rs;
	u8 sew;
	u16 bytes;
	u32 base;
	bool masked, sqrt, finish;
};

struct InstVFEstimate : InstNoOperands {
	InstVFEstimate(u8 rd_,u8 src_,u8 sew_,u16 regbytes_,bool masked_,bool sqrt_,uptr table_)
	    : InstNoOperands(Op::_vfestimate),rd(rd_),src(src_),sew(sew_),regbytes(regbytes_),
	      masked(masked_),sqrt(sqrt_),table(table_)
	{
		if(rd>31||src>31||(sew!=4&&sew!=8)||regbytes<16||regbytes>512||
		   (regbytes&(regbytes-1))||!table) Panic("qir: invalid RVV estimate shape");
	}
	u8 rd,src,sew;
	u16 regbytes;
	bool masked,sqrt;
	uptr table;
};

struct InstVFReduce : InstNoOperands {
	InstVFReduce(u8 rd_, u8 data_, u8 seed_, u8 sew_, u16 regbytes_, bool masked_, bool wide_, u8 op_,
		     u16 vlmax_ = 0)
	    : InstNoOperands(Op::_vfreducenative), rd(rd_), data(data_), seed(seed_), sew(sew_),
	      regbytes(regbytes_), masked(masked_), wide(wide_), op(op_), vlmax(vlmax_)
	{
		if (rd > 31 || data > 31 || seed > 31 || (sew != 4 && sew != 8) ||
		    (wide && (sew != 4 || op != 0)) || op > 2 || regbytes < 16 || regbytes > 512 || (regbytes & (regbytes - 1)))
			Panic("qir: invalid floating sum reduction shape");
	}
	u8 rd, data, seed, sew;
	u16 regbytes;
	bool masked, wide;
	u8 op; // 0: ordered sum (also legal for unordered sum), 1: min, 2: max
	// THE ELEMENT COUNT THE ORDERED FOLD RUNS OVER, and it exists for the LLVM arm only.
	// The QCG body reads the ARCHITECTURAL `vl` out of CPUState at run time and therefore handles
	// a partial vl itself; it ignores this field. The LLVM arm has no run-time loop: its frame
	// guard proves `vl == VLMAX`, so the fold length is a translation-time constant and this is it.
	u16 vlmax;
};

struct InstVReduce : InstNoOperands {
	InstVReduce(u8 rd_,u8 data_,u8 seed_,u8 sew_,u8 op_,u16 regbytes_,u16 vlmax_,bool masked_)
	    : InstNoOperands(Op::_vreducenative),rd(rd_),data(data_),seed(seed_),sew(sew_),op(op_),regbytes(regbytes_),vlmax(vlmax_),masked(masked_)
	{
		if(rd>31||data>31||seed>31||op>9||(op>=8&&sew>4)||(sew!=1&&sew!=2&&sew!=4&&sew!=8)||
		   regbytes<16||regbytes>512||(regbytes&(regbytes-1))||!vlmax||vlmax>4096)
			Panic("qir: invalid integer reduction geometry");
	}
	u8 rd,data,seed,sew,op;
	u16 regbytes,vlmax;
	bool masked;
};

struct InstVCompress : InstNoOperands {
	InstVCompress(u8 rd_,u8 data_,u8 mask_,u8 sew_,u16 regbytes_,u16 vlmax_)
	    : InstNoOperands(Op::_vcompressnative),rd(rd_),data(data_),mask(mask_),sew(sew_),regbytes(regbytes_),vlmax(vlmax_)
	{
		if(rd>31||data>31||mask>31||(sew!=1&&sew!=2&&sew!=4&&sew!=8)||
		   regbytes<16||regbytes>512||(regbytes&(regbytes-1))||!vlmax||vlmax>4096)
			Panic("qir: invalid compress geometry");
	}
	u8 rd,data,mask,sew;
	u16 regbytes,vlmax;
};

struct InstVScalarMove : InstNoOperands {
	InstVScalarMove(u8 vreg_, u8 greg_, u8 sew_, bool to_vector_, bool floating_ = false)
	    : InstNoOperands(Op::_vscalarmove), vreg(vreg_), greg(greg_), sew(sew_), to_vector(to_vector_), floating(floating_)
	{
		if(vreg>31||greg>31||(sew!=1&&sew!=2&&sew!=4&&sew!=8))Panic("qir: invalid scalar vector move");
		if(floating&&sew<4)Panic("qir: unsupported floating scalar vector width");
	}
	u8 vreg,greg,sew;
	bool to_vector,floating;
};

struct InstVMaskIota : InstNoOperands {
	InstVMaskIota(u32 rd_,u32 source_,u16 vlmax_,u16 regbytes_,u8 sew_,bool masked_)
	    : InstNoOperands(Op::_vmaskiota),rd(rd_),source(source_),vlmax(vlmax_),regbytes(regbytes_),sew(sew_),masked(masked_)
	{
		if(!vlmax||vlmax>4096||regbytes<16||regbytes>512||(regbytes&(regbytes-1))||
		   (sew!=1&&sew!=2&&sew!=4&&sew!=8))Panic("qir: invalid mask iota shape");
	}
	u32 rd,source;
	u16 vlmax,regbytes;
	u8 sew;
	bool masked;
};

struct InstVMaskScalar : InstNoOperands {
	InstVMaskScalar(u32 source_, u16 vlmax_, u8 rd_, bool first_, bool masked_)
	    : InstNoOperands(Op::_vmaskscalar), source(source_), vlmax(vlmax_), rd(rd_), first(first_), masked(masked_)
	{
		if (!vlmax || vlmax > 4096 || rd > 31 || source % 8) Panic("qir: invalid mask scalar shape");
	}
	u32 source;
	u16 vlmax;
	u8 rd;
	bool first, masked;
};

struct InstVMaskPrefix : InstNoOperands {
	InstVMaskPrefix(u32 rd_, u32 source_, u16 vlmax_, u8 kind_, bool masked_)
	    : InstNoOperands(Op::_vmaskprefix), rd(rd_), source(source_), vlmax(vlmax_), kind(kind_), masked(masked_)
	{
		if (!vlmax || vlmax > 4096 || kind > 2 || rd % 8 || source % 8 || rd == source)
			Panic("qir: invalid mask prefix shape");
	}
	u32 rd, source;
	u16 vlmax;
	u8 kind; // 0 before, 1 including, 2 only the first active set bit.
	bool masked;
};

struct InstVMaskLogic : InstNoOperands {
	// One 64-bit mask word, independent of SEW/LMUL. Live vl/vstart select the bits
	// to update. Both sources are loaded before the aliased destination is written.
	InstVMaskLogic(u8 op_, u32 rd_, u32 rs2_, u32 rs1_, u32 base_, bool finish_)
	    : InstNoOperands(Op::_vmasklogic), op(op_), rd(rd_), rs2(rs2_), rs1(rs1_),
	      base(base_), finish(finish_)
	{
		if (op > 7 || base % 64 || base >= 4096)
			Panic("qir: invalid mask logical word");
		for (u32 o : {rd, rs2, rs1})
			if (o > 0xffffu - 8 || o % 8) Panic("qir: invalid mask word offset");
	}
	u8 op;
	u32 rd, rs2, rs1, base;
	bool finish;
};

// One bounded lane operation using two reserved vector scratch registers. Architectural mode
// derives the live body mask from vl/vstart/v0; legacy mode consumes a frame mask. Sources are
// read before an aliased destination is updated, and no allocated value survives this node.
struct InstVChunkPartialAlu : InstNoOperands {
	// The lane operation, named here so the emitter depends on nothing outside qir.h.
	// A7: Mov = `[rd]{k} := source 1` (masked copy/broadcast, no vs2 read, no arithmetic).
	enum class Kind : u8 { Add = 0, Sub = 1, Mul = 2, And = 3, Or = 4, Xor = 5, Mov = 6, RSub = 7,
		MinU = 8, MinS = 9, MaxU = 10, MaxS = 11, Sll = 12, Srl = 13, Sra = 14, Merge = 15,
		Macc = 16, Nmsac = 17, Madd = 18, Nmsub = 19,
		MulHU = 20, MulH = 21, MulHSU = 22, DivU = 23, DivS = 24, RemU = 25, RemS = 26,
		Eq = 27, Ne = 28, LtU = 29, LtS = 30, LeU = 31, LeS = 32, GtU = 33, GtS = 34,
		Adc = 35, Sbc = 36, Madc = 37, Msbc = 38,
		SatAddU = 39, SatAddS = 40, SatSubU = 41, SatSubS = 42,
		AvgAddU = 43, AvgAddS = 44, AvgSubU = 45, AvgSubS = 46,
		RoundSrl = 47, RoundSra = 48, ClipU = 49, ClipS = 50, FracMul = 51 };
	// A6. WHAT SOURCE 1 IS. `Vector` (the only kind before A6): a chunk window at rs1_offs.
	// `GprWord`: rs1_offs names a 4-byte GPR slot whose word is splat (vadd.vx). `Imm`: the
	// splat value is `imm`, rs1_offs is 0 and unused (vadd.vi). The emitter's scratch s1 is
	// filled by the kind; the op and the masked store are identical for all three.
	enum class Src1 : u8 { Vector = 0, GprWord = 1, Imm = 2, FprBoxed = 3 };
	InstVChunkPartialAlu(u8 op_, u8 sew_bytes_, u8 chunk_, u16 chunk_bytes_, u32 rd_offs_,
			     u32 rs2_offs_, u32 rs1_offs_, u8 src1_kind_ = 0, u32 imm_ = 0,
			     bool architectural_mask_ = false, bool masked_ = false, u32 element_base_ = 0,
			     bool finish_instruction_ = false)
	    : InstNoOperands(Op::_vchunkpartialalu), op(op_), sew_bytes(sew_bytes_), chunk(chunk_),
	      src1_kind(src1_kind_), chunk_bytes(chunk_bytes_), rd_offs(static_cast<u16>(rd_offs_)),
	      rs2_offs(static_cast<u16>(rs2_offs_)), rs1_offs(static_cast<u16>(rs1_offs_)), imm(imm_),
	      architectural_mask(architectural_mask_), masked(masked_), element_base(element_base_),
	      finish_instruction(finish_instruction_)
	{
		bool const valid_sew = sew_bytes_ == 1 || sew_bytes_ == 2 || sew_bytes_ == 4 || sew_bytes_ == 8;
		if (!valid_sew || (!architectural_mask_ && (sew_bytes_ != 4 || chunk_ >= 7)) ||
		    (chunk_bytes_ != 16 && chunk_bytes_ != 32 && chunk_bytes_ != 64))
			Panic("qir: invalid vchunkpartialalu shape");
		if (src1_kind_ > (u8)Src1::FprBoxed)
			Panic("qir: invalid vchunkpartialalu source-1 kind");
		if (src1_kind_ == (u8)Src1::FprBoxed &&
		    (!architectural_mask_ || (sew_bytes_ != 4 && sew_bytes_ != 8) ||
		     (op_ != (u8)Kind::Mov && op_ != (u8)Kind::Merge) ||
		     rs1_offs_ > 0xffffu - 8u || rs1_offs_ % 8u != 0))
			Panic("qir: invalid floating bit-move source");
		for (u32 o : {rd_offs_, rs2_offs_})
			if (o > 0xffffu - chunk_bytes_ || o % 4u != 0)
				Panic("qir: vchunkpartialalu window is not a representable CPUState window");
		if (src1_kind_ == (u8)Src1::Vector && (rs1_offs_ > 0xffffu - chunk_bytes_ || rs1_offs_ % 4u != 0))
			Panic("qir: vchunkpartialalu window is not a representable CPUState window");
		if (src1_kind_ == (u8)Src1::GprWord && (rs1_offs_ > 0xffffu - 4u || rs1_offs_ % 4u != 0))
			Panic("qir: vchunkpartialalu GPR word is not a representable CPUState word");
		if (src1_kind_ == (u8)Src1::Imm && rs1_offs_ != 0)
			Panic("qir: vchunkpartialalu immediate form names a source window");
	}
	// Clip uses sew_bytes/chunk_bytes for the wide input; vector counts and output
	// have half that element/window width. All other kinds use equal-width operands.
	u8 op, sew_bytes, chunk, src1_kind;
	u16 chunk_bytes, rd_offs, rs2_offs, rs1_offs;
	u32 imm;
	// General same-width integer lowering computes its mask from [vstart, vl) and v0.
	// Legacy partial frames instead supply a resident k-register indexed by chunk.
	bool architectural_mask, masked;
	u32 element_base;
	bool finish_instruction;
};

// P7L-B1. THE MATCHED DEPENDENCY PROBE, and what it is NOT.
//
// `d := value`, exactly. `probe` is read and its VALUE IS DISCARDED. The node exists so that an
// emitted frame can carry a data dependency that the computation does not need, which is the only
// way to ask a running machine whether two sibling chunk chains were actually overlapping: hold
// everything else fixed and add one edge.
//
// WHY IT IS AN INSTRUMENT AND NOT A LOWERING. Nothing in the translator ever needs this node to
// produce a correct guest result -- with `config::rvv_run_dep_probe_depth == 0` it is never
// created, and every emitted byte is what it was before. It has no guest opcode, no admission
// predicate and no fallback stub of its own: it lives strictly inside a vector-run frame that some
// other route already admitted, and the frame's existing ordered fallback replays that route's
// helpers, which never saw this node.
//
// WHY BOTH ARMS EMIT THE SAME INSTRUCTION. The two arms of the ablation differ only in which value
// is passed as `probe`: the chunk's own running value (independent) or the sibling chunk's
// (serialized). Operand 1 is therefore the only difference between the two emitted programs, and
// that is a property of THIS node's shape, not of a switch read somewhere else.
//
// WHY THE HOST FORM IS `vpblendmq` AND NOT `vpternlogq`. Both can be made value-preserving, but
// VPTERNLOGQ's destination is also an architectural SOURCE, so it would carry a false dependency
// on whatever last wrote the physical register the allocator happened to pick -- an edge that
// differs between arms for a reason that has nothing to do with the question. VPBLENDMQ with no
// writemask is `DEST := SRC2` for every lane, reading SRC1 and SRC2 and NOT reading DEST
// (Intel SDM VPBLENDMD/VPBLENDMQ operation, the `*no writemask*` arm). So the emitted edge set is
// exactly {value, probe} and nothing else.
struct InstVChunkDep : InstWithOperands<1, 2> {
	InstVChunkDep(VOperand d, VOperand value, VOperand probe)
	    : InstWithOperands(Op::_vchunkdep, {d}, {value, probe})
	{
		if (!d.IsV() || !value.IsV() || !probe.IsV())
			Panic("qir: vchunkdep operands are not vector values");
		if (d.GetType() != value.GetType() || d.GetType() != probe.GetType())
			Panic("qir: vchunkdep operands disagree about chunk width");
	}
};

// P7I: the FUSED three-input lane operation, and the reason it is a separate node rather than a
// third operand bolted onto InstVChunkFALU.
//
// RVV's OPFVF `vfmadd.vf`/`vfnmsub.vf` compute `fma(+-vd_old, scalar, vs2)` with ONE rounding
// (dbt/guest/rv32_vector_lower.h:1634,1637 -- `std::fma`). Three separate facts make the existing
// two-input node unable to carry that:
//
//   * ARITY. InstVChunkFALU is InstWithOperands<1,2>; a fused multiply-add needs THREE V512
//     inputs -- the old vd (the multiplicand), the multiplier and the addend. There is no slot.
//   * THE EMITTER. Emit_vchunkfalu's funct6 switch covers five funct6 values and Panics on the
//     rest, so 40/43 could not reach an encoding through it even with a slot.
//   * SEMANTICS. Decomposing into vfmul + vfadd rounds TWICE and is a different function from
//     std::fma. rv32_vector_lower.h:255-257 states the contract this node exists to keep: "RVV's
//     vfmacc/vfmadd family rounds ONCE, and so does x86 FMA3, so the two agree exactly".
//
// OPERAND NAMES ARE THE HELPER'S, deliberately, so there is exactly one vocabulary for the
// mapping: `dold` is the helper's `d` (rv32_vector_lower.h:1625), `b` its `b` (:1624, the .vf
// scalar splat) and `a` its `a` (:1623, the vs2 chunk).  funct6 selects
// VFMADD -> fma(dold, b, a) and VFNMSUB -> fma(-dold, b, a).
//
// Unlike InstVChunkFALU this node does NOT accept sew_bytes == 0.  That value is the falu route's
// "vtype was never observed, decide the element width at run time" encoding; the FMA route refuses
// unobserved vtypes outright (RvvQcgTypedFmaAdmit), so a zero here would mean the admission
// predicate and the node disagreed, and it is a translation Panic rather than a second emitter
// path that would never be reached by an admitted frame.
struct InstVChunkFMA : InstWithOperands<1, 3> {
	InstVChunkFMA(VOperand d, VOperand dold, VOperand b, VOperand a, u8 sew_bytes_, u8 funct6_,
		      u8 chunk_, u8 kmask_ = 0, bool masked_ = false)
	    : InstWithOperands(Op::_vchunkfma, {d}, {dold, b, a}), sew_bytes(sew_bytes_),
	      funct6(funct6_), chunk(chunk_), kmask(kmask_), masked(masked_)
	{
		if ((sew_bytes_ != 4 && sew_bytes_ != 8) || chunk_ >= 8u * MAX_REG_CHUNKS)
			Panic("qir: invalid vchunkfma shape");
		CheckFpKmask(kmask_, chunk_, sew_bytes_);
	}
	u8 sew_bytes, funct6, chunk;
	u8 kmask; // A12: see InstVChunkFALU::kmask
	bool masked;
};

// P8. vchunkfsqrt: chunk <- correctly-rounded square root of each SEW-wide lane.
//
// ONE SOURCE. RVV 1.0 13.8's vfsqrt.v is OPFVV with the vs1 field used as an opcode extension
// (00000), not as a register: the operation genuinely has one vector input. Giving this node a
// second operand to reuse InstVChunkFALU would put a value in the allocator's live set that the
// computation never reads, and would make every dump and every constraint table claim a dataflow
// edge that does not exist. InstVChunkSll made the same call for the same reason.
//
// NO RECIPROCAL-ESTIMATE LOWERING. The reference is std::sqrt / softfp::op_sqrt
// (rv32_vector_lower.h:2281-2295), i.e. the correctly-rounded IEEE square root, and x86's
// vsqrtps/vsqrtpd are that same function. vrsqrt14ps and friends are 14-bit APPROXIMATIONS whose
// Newton refinement is not correctly rounded and does not raise the same flags; they are never
// emitted for this node.
//
// `sew_bytes` is 4 or 8 only (there is no packed FP16 lane op in the admitted set) and, unlike
// InstVChunkFALU, never 0: the route refuses an unobserved vtype, so a run-time element width
// would mean the predicate and the node disagreed.
struct InstVChunkFSqrt : InstWithOperands<1, 1> {
	InstVChunkFSqrt(VOperand d, VOperand s, u8 sew_bytes_, u8 chunk_, u8 kmask_ = 0, bool masked_ = false)
	    : InstWithOperands(Op::_vchunkfsqrt, {d}, {s}), sew_bytes(sew_bytes_), chunk(chunk_),
	      kmask(kmask_), masked(masked_)
	{
		if (!d.IsV() || !s.IsV())
			Panic("qir: vchunkfsqrt operands are not vector values");
		if (d.GetType() != s.GetType())
			Panic("qir: vchunkfsqrt operands disagree about chunk width");
		if ((sew_bytes_ != 4 && sew_bytes_ != 8) || chunk_ >= 8u * MAX_REG_CHUNKS)
			Panic("qir: invalid vchunkfsqrt shape");
		CheckFpKmask(kmask_, chunk_, sew_bytes_);
	}
	u8 sew_bytes, chunk;
	u8 kmask; // A12: see InstVChunkFALU::kmask
	bool masked;
};

// P9. vchunkfcmpstate: compare one chunk of two FP source chunks and DEPOSIT the resulting mask
// bits into the destination mask register in CPUState.
//
// NO VALUE OUTPUT, and that is the operation's own shape rather than a lowering choice. RVV 1.0
// 13.13's compares write a mask register: one bit per element, the whole result of a 64-byte chunk
// being 8 (SEW 64) or 16 (SEW 32) BITS. Materialising that as a V512 value and storing it would
// write 64 bytes over a register that must only receive one or two, so the node writes the bytes it
// owns and nothing else.
//
// IT BLENDS RATHER THAN OVERWRITES. The reference (rv32_vector_lower.h vfcmp) sets bits only for
// ACTIVE elements below vl and leaves masked-off and tail bits untouched; RVV 1.0 would also permit
// a mask tail of all ones, but "untouched" is what the helper and QEMU produce, so a bit-exact
// differential requires it here too. The emitter therefore does a read-modify-write of the
// destination byte(s) under the active-lane mask.
//
// `offs` addresses the BYTE this chunk owns, so a chunk must cover a whole number of bytes of the
// mask: lanes % 8 == 0, which the admitting predicate checks (a 64-byte chunk gives 16 lanes at
// SEW 32 and 8 at SEW 64; a 16-byte chunk at SEW 64 would give 4 and is refused).
struct InstVChunkFCmpState : InstWithOperands<0, 2> {
	InstVChunkFCmpState(u32 offs_, VOperand a, VOperand b, u8 sew_bytes_, u8 funct6_, u8 chunk_,
			    bool masked_ = false)
	    : InstWithOperands(Op::_vchunkfcmpstate, {}, {a, b}), offs(static_cast<u16>(offs_)),
	      sew_bytes(sew_bytes_), funct6(funct6_), chunk(chunk_), masked(masked_)
	{
		if (!a.IsV() || !b.IsV())
			Panic("qir: vchunkfcmpstate operands are not vector values");
		if (a.GetType() != b.GetType())
			Panic("qir: vchunkfcmpstate operands disagree about chunk width");
		if ((sew_bytes_ != 4 && sew_bytes_ != 8) || chunk_ >= 8u * MAX_REG_CHUNKS)
			Panic("qir: invalid vchunkfcmpstate shape");
		// Two bytes is the widest deposit any admitted chunk makes (16 lanes at SEW 32).
		if (offs_ > STATE_OFFS_LIMIT_FCMP - 2u)
			Panic("qir: vchunkfcmpstate state offset is not a representable window");
	}
	static constexpr u32 STATE_OFFS_LIMIT_FCMP = 1u << 16;
	u16 offs;
	u8 sew_bytes, funct6, chunk;
	// v0.t: the emitter ANDs the guest mask's bits for this chunk into the active-lane mask, so
	// an inactive element neither contributes a result bit nor raises an exception.
	bool masked;
};

// P10. vchunkfwidencvt: chunk <- each f32 lane of a HALF-WIDTH WINDOW converted to f64.
//
// THE WINDOW IS HALF THE OUTPUT'S WIDTH. That is the whole reason this is its own node: every other
// lane op in this file has operands of one width, and the widening family's destination holds half
// as many elements per byte as its narrow source. A 64-byte destination chunk (8 f64) is produced
// from a 32-byte source window (8 f32).
//
// THE WINDOW IS NOT ALWAYS THE WHOLE SOURCE VALUE. Below 32 bytes the window would be 8 bytes, and
// qir has no 8-byte vector value type at all (VectorVTypeForBytes offers 16/32/64), so at a 16-byte
// destination chunk -- VLEN 128 -- the source is a 16-byte value whose LOW HALF is the window. The
// operand contract is therefore
//
//     VTypeToSize(source) == max(16, VTypeToSize(destination) / 2)
//
// and it is exactly what `vcvtps2pd` does: the instruction reads half the DESTINATION's width from
// the low part of its source, so `vcvtps2pd xmm, xmm` converts 2 f32 and ignores the upper 8 bytes.
// The frame widens only the LOAD, never a store: nothing in this family writes a state window wider
// than the destination chunk it is defining.
//
// WHY A CONVERT NODE AND NOT A FUSED WIDENING ALU. The reference widens both operands exactly and
// then performs ONE operation at the wide width (rv32_vector_lower.h:2769-2777: "A single-to-double
// conversion is exact, so this introduces no rounding of its own"). Emitting the convert separately
// and letting the existing vchunkfalu do the arithmetic at SEW 8 reproduces that definition exactly
// and reuses that emitter's NaN canonicalisation, active-lane mask and tail handling rather than
// growing a second copy of them.
//
// `chunk` is the DESTINATION chunk index, so the active-lane mask this node derives is the same one
// the vchunkfalu consuming it will derive: an inactive lane's operand is never converted, and a
// signalling NaN sitting in it cannot raise a spurious NV.
struct InstVChunkFWidenCvt : InstWithOperands<1, 1> {
	InstVChunkFWidenCvt(VOperand d, VOperand s, u8 chunk_, bool masked_ = false)
	    : InstWithOperands(Op::_vchunkfwidencvt, {d}, {s}), chunk(chunk_), masked(masked_)
	{
		if (!d.IsV() || !s.IsV())
			Panic("qir: vchunkfwidencvt operands are not vector values");
		// max(16, dst/2), spelled without <algorithm>: the exact window for a 64- or 32-byte
		// destination, and the 16-byte value whose low half is the window below that.
		u32 const dw = VTypeToSize(d.GetType()), half = dw / 2u;
		if (VTypeToSize(s.GetType()) != (half < 16u ? 16u : half))
			Panic("qir: vchunkfwidencvt source is not this destination's f32 window");
		if (chunk_ >= 8u * MAX_REG_CHUNKS)
			Panic("qir: invalid vchunkfwidencvt chunk index");
	}
	u8 chunk;
	// v0.t, carried for the same reason InstVChunkFALU carries it: the CONVERSION itself must see
	// the active mask, or an inactive lane holding a signalling NaN raises NV for an element the
	// instruction never touches.
	bool masked;
};

struct InstRVVQCGFPBegin : InstNoOperands {
	InstRVVQCGFPBegin() : InstNoOperands(Op::_rvvqcgfpbegin) {}
};
struct InstRVVQCGFPEnd : InstNoOperands {
	InstRVVQCGFPEnd() : InstNoOperands(Op::_rvvqcgfpend) {}
};

// ---------------------------------------------------------------------------------------------
// TYPED chunk group: the guard/fallback frame around the typed V512 body.
//
// `rvvtypedchunkbegin` emits the architectural guard, `rvvtypedchunkend` emits the hit counter,
// the join, and the fallback helper call.  Between them the frontend emits the ACCEPTED typed ops
// -- vstatechunkload, vchunkadd, vstatechunkstore -- as ordinary QIR values with def-use, so
// unlike the diagnostic arm above the chunk is a real value and QRegAlloc picks its ZMM.
//
// WHY THE GUARD IS NOT QIR CFG.  The guard compares CPUState::vec.vtype/vl/vstart, and none of
// those is a QIR global (rv32's StateInfo declares x1-x31 and ip, nothing else), so QIR has no
// value to feed a brcc.  The guard therefore lives in the emitter and branches over the typed
// body, exactly as the diagnostic arm's does.
//
// That has a hazard the diagnostic arm does not have, and it is the reason for the invariant
// below.  The diagnostic nodes are InstNoOperands and QRegAlloc skips them entirely, so nothing
// is ever inserted between its guard and its fallback label.  The typed ops DO go through
// AllocOp, which may insert `mov` spills, fills, copies and side-effect global syncs.  Any such
// instruction landing between the guard and the fallback label would be SKIPPED on the fallback
// path -- and a skipped global sync would lose a guest register write, because QRegAlloc has
// already marked that track clean.
//
// Two things make that safe, and both are enforced rather than assumed:
//
//   * HAS_CALLS on `begin`.  QRegAlloc::CallOp runs before the guard and spills/syncs everything
//     there, so the typed ops' own SIDEEFF syncs find nothing left dirty.
//   * QEmit refuses to emit anything else inside an open group.  Emit_mov Panics while a group is
//     open and `end` verifies it saw exactly the expected number of typed ops.  A future
//     allocator change that broke the first property would abort translation loudly instead of
//     silently miscompiling the fallback path.
//
// If this op is ever extended past the one admitted shape, revisit that invariant first: it holds
// because the admitted body is three V512 values in a 30-register pool with no call inside it.
//
// R1A.3b DID EXTEND IT, and this is how the invariant is maintained rather than assumed. A run
// frame's body is `(|live_in| + |live_out| + m) * k` V512 values instead of three, so "no spill"
// stopped being obvious. It is now decided at TRANSLATION time: dbt/guest/rv32_vrun.h computes a
// conservative bound on the peak simultaneously-live component count and REFUSES to extend a run
// past the host vector register pool, precisely because a spill here is the Emit_mov Panic above
// and not a slowdown. Nothing else about the invariant changes -- the body still contains no call,
// and Emit_mov still Panics.
//
// ---------------------------------------------------------------------------------------------
// R1A.3b: ONE MEMBER OF A VECTOR RUN, as the backend needs it.
//
// A vector run (VRUN) is `m` consecutive guest vector instructions admitted by the translation-time
// rule in dbt/guest/rv32_vrun.h and covered by ONE guard.  `m == 1` is the accepted
// single-instruction frame and is not a run in any new sense; `m > 1` is what this checkpoint adds.
//
// `pc` IS AN OBLIGATION, NOT BOOKKEEPING (R1A.2b section 2).  The architectural helpers take
// `(state, raw)` and read their trap PC out of `state->ip` -- `rv32_interp.cpp`'s stub wrapper does
// `u32 gip = state->ip;` and there is no PC parameter.  So an ordered fallback arm MUST write this
// member's own guest PC immediately before its call, or that helper's trap reports the wrong
// instruction.  For `m == 1` the backend writes nothing: the TRANSLATOR macro's PreSideeff already
// stored that instruction's PC immediately before the frame, so `pc` is left at `PC_UNUSED` and the
// emitters must not read it.  That is also what keeps every accepted single-instruction frame
// byte-identical.
struct RVVRunMember {
	static constexpr u32 PC_UNUSED = 0xffffffffu;

	u32 pc = PC_UNUSED;  // guest PC, written to CPUState::ip before this member's helper call
	u32 raw = 0;	     // guest encoding: the helper's second argument
	RuntimeStubId stub = RuntimeStubId::Count;
	bool scalar_passthrough = false;
};

// The run frame's member capacity (dbt/guest/rv32_vrun.h kMaxRunMembers). NOT a prototype length
// and NOT a correctness-scope bound -- M2E replaced that -- and not a tuned parameter either. It
// is also not raisable here alone: rv32_qir.cpp static_asserts it equal to kMaxRunMembers and to
// TB_MAX_INSNS, so changing this number without changing those fails to compile. Nor is raising
// it a node-size change any more, because M2E stores the member list by pointer.
//
// M2E: the run frame's member capacity. A run is a contiguous stretch of ONE translation block's
// ip range, so the most members one can ever have is the most guest instructions a block can hold
// (TB_MAX_INSNS). Kept numerically here -- qir.h is backend-side and must not include the RV32 CPU
// header -- and pinned to both that constant and rv32_vrun.h's kMaxRunMembers by static_asserts in
// guest/rv32_qir.cpp, so the three cannot drift.
//
// M2E stores the member list BY POINTER rather than as an inline array. Embedding 64 members
// would put ~800 bytes into every typed-chunk frame node, and the overwhelming majority of frames
// have exactly one member -- a 64-member-sized node per single-instruction frame is a region-arena
// cost paid for a capacity almost no frame uses. The same shape InstCCRFComputeRegion already uses
// for its variable-length operation list.
static constexpr u8 RVV_RUN_MAX_MEMBERS = 64;

struct InstRVVTypedChunkBegin : InstNoOperands {
	// Single-member frame: unchanged, and deliberately so -- every accepted route builds its
	// frame through this constructor and must keep producing exactly the node it produced before.
	InstRVVTypedChunkBegin(u32 vtype_, u32 vlmax_, u32 raw_, RuntimeStubId stub_, u16 n_typed_)
	    : InstNoOperands(Op::_rvvtypedchunkbegin), vtype(vtype_), vlmax(vlmax_), raw(raw_),
	      stub(stub_), n_typed(n_typed_), n_members(1)
	{
	}

	// Native-2. WHICH runtime facts the guard checks, because not every routed opcode depends on
	// the same ones. The eight accepted element-wise routes are vtype-DEPENDENT: their SEW and
	// LMUL come from vtype and their element count from vl, so the guard must pin both. A
	// whole-register transfer is defined by RVV 1.0 to move whole registers irrespective of
	// SEW, LMUL and vl, and to remain valid even when vill is set -- which is exactly why a
	// compiler uses it for spills and LMUL regrouping. Guarding it on vtype would not be
	// conservative, it would be WRONG in the way that matters for a research claim: the frame
	// would fall back whenever vtype happened to differ, so the route's coverage would be a
	// property of the surrounding code rather than of the instruction, and on one workload whose
	// vtype never changes it would look complete while being a special case.
	//
	// So the kind selects the predicate, and nothing else about the frame changes: the fallback
	// edge, the hit counter, the member bookkeeping and the `n_typed` check are shared. The
	// default is the accepted predicate, and both pre-existing constructors leave it there, so
	// every frame the eight routes build is byte-identical to what it was.
	enum class GuardKind : u8 {
		VTypeVlVstart = 0, // vtype == expected && vl == VLMAX && vstart == 0
		VlenbVstart = 1,   // vlenb == expected && vstart == 0   (vtype-independent transfers)
		VTypePartialVlVstartFrmRNE = 2, // exact vtype, vl <= VLMAX, vstart=0, frm=RNE
		VTypeE32OrE64M2PartialVlVstartFrmRNE = 3,
		// P7M-A. exact vtype, vl == VLMAX, vstart == 0, frm == RNE.
		//
		// THE CONJUNCTION OF THE TWO ABOVE, AND ONLY REACHABLE FROM A RUN. A run's single
		// guard must be at least as strong as every member's own single-instruction guard.
		// The integer routes need `vl == VLMAX` (their host chunk operations are unmasked and
		// full width); the FP routes need `frm == RNE` (their body is host FP arithmetic in a
		// fixed rounding mode). A run holding BOTH kinds therefore needs both facts, and
		// neither existing kind states both -- kind 2 WEAKENS vl to `<=`, which would let an
		// integer member's unmasked body run at a partial vl.
		//
		// It is strictly stronger than either member's own guard, so it can only ever send
		// MORE executions to the ordered fallback arm than the single-instruction frames
		// would have taken. It cannot admit anything they would have refused.
		VTypeVlVstartFrmRNE = 4,
		// A3: exact vtype, vstart == 0, and vl <= VLMAX; vl == VLMAX falls into the unchanged
		// full body, vl < VLMAX jumps to the frame's partial arm (rvvtypedchunkpartial), and
		// vl > VLMAX (impossible for a legal vtype, kept fail-closed) takes the helper.
		VTypeVlOrPartialVstart = 5,
		// A13: exact vtype, vl == VLMAX, vstart == 0, AND the guest base register read from
		// CPUState at `base_state_offs` is <= `base_limit` (2^32 - VLEN/8), so the frame's
		// host-pointer chunk window [base, base + VLEN/8) lies inside the 4 GiB guest space.
		// Used by the QCG unit-stride vle/vse frames when config::rvv_qcg_typed_chunk_mem_e64
		// is on; QCG-only (llvmgen refuses it).
		VTypeVlVstartBaseLimit = 6,
		// A14: vlenb == expected, vstart == 0, AND base <= base_limit, where base_limit is
		// 2^32 minus THIS opcode's transfer length (nregs * VLEN/8 for a whole-register
		// transfer; never vl). The whole-register frame's kind; QCG-only.
		VlenbVstartBaseLimit = 7,
		VTypeInteger = 8, // exact vtype, vl <= VLMAX; body handles vstart/mask/tail
		VTypeIntegerTwoArm = 9, // full VL/vstart=0 fast body, otherwise restart-aware partial body
		VTypeIntegerNoRestart = 10, // vl <= VLMAX; body requires vstart=0
		// P2e (2026-09-13): "body handles vstart/VL0" is true of the RESULT but not of the body's
		// arithmetic -- at vl == 0 the FP body's tail fill covers every lane of its accumulator and
		// it is Emit_vstatechunkstore's active-lane store mask that keeps guest state undisturbed.
		// This kind emits NO `vl == 0 -> fallback` compare (only the two ...FrmRNE kinds do), and it
		// admits vta = 0 as well as vta = 1. See Emit_vchunkfalu's A4/P2e comment.
		VTypePartialVlVstartFrmHost = 11, // vl <= VLMAX, body handles vstart/VL0; frm in RNE/RTZ/RDN/RUP
		VTypeFpNoRestart = 12, // reduction: vl <= VLMAX, vstart=0, four MXCSR rounding modes
		VlenbRestartable = 13, // whole-register memory; body handles encoded EEW and vstart
		VTypeFpAnyRM = 14, // exact/rounding-independent FP; body handles restart, all five guest modes
		VTypeFpAnyRMNoRestart = 15, // rounding-independent reduction, vstart must be zero
		// QCG unit-stride memory: exact vtype, vl <= VLMAX, vstart == 0 and a conservative
		// full-register guest-address bound. Full vl uses the original body; partial vl uses
		// masked guest-memory and state stores.
		VTypeVlOrPartialVstartBaseLimit = 16,
		// Multi-member QCG run containing both whole-register memory and FP arithmetic:
		// exact vtype, full vl, vstart=0, frm=RNE, and every base in base_state_mask is in range.
		// C6-FRM (2026-09-20): THE TWO ...FrmRNE KINDS, WITH THE ROUNDING TEST WIDENED FROM
		// `frm == RNE` TO `frm <= FRM_RUP`, and NOTHING ELSE changed. Kind 19 is the exact
		// analogue of kind 4 and kind 20 of kind 2: same vtype test, same vl test, same
		// `vstart == 0`, same body contract.
		//
		// WHY A NEW KIND RATHER THAN WIDENING KINDS 2 AND 4. The two backends emit the guard
		// independently -- QEmit emits `test dword[fcsr], 0xe0 ; jnz fallback` for kind 4 --
		// so widening the existing kind in one backend would make the two cover DIFFERENT
		// executions from identical QIR, which every arm-equivalence argument rests on not
		// happening. A new kind lets the LLVM arm opt in without moving kind 4 by one byte.
		//
		// WHY `<= FRM_RUP` IS THE RIGHT BOUND, AND NOT "any rounding mode". The frame's
		// bracket (RvvFpBracketOpenBody) installs the live guest `frm` into MXCSR.RC, and the
		// lane operations are `round.dynamic` constrained intrinsics, so RNE/RTZ/RDN/RUP are
		// all executed in the mode the guest asked for. **RMM (frm == 4, round to nearest with
		// ties away from zero) HAS NO x86 EQUIVALENT** -- the bracket's select maps it to 0,
		// which is RNE, and that is a WRONG result, not a slow one. So RMM must keep taking the
		// fallback, and the bound is `<= RUP` rather than `<= RMM` for exactly that reason.
		// Kinds 14/15 (`VTypeFpAnyRM`) admit all five modes and are for bodies whose result is
		// rounding-INDEPENDENT; a conversion that rounds by `frm` is not one of those.
		VTypeVlVstartFrmHostRound = 19,
		VTypePartialVlVstartFrmHostRound = 20,
		VTypeVlVstartFrmRNEBaseMask = 17,
		VTypeVlVstartBaseMask = 18,
	};

	// G11-A. DOES THIS FRAME'S OWN GUARD ALREADY PROVE `vl == VLMAX && vstart == 0`?
	//
	// The kinds below are exactly those whose emitted guard tests `vl` with `jne` against
	// `vlmax` AND `vstart` with `jne` against zero, so a body op that runs at all runs with
	// every element of the destination register group inside [vstart, vl):
	//
	//   RVV 1.0 v-spec 3.7   the prestart set is [0, vstart)      -> empty when vstart == 0
	//   RVV 1.0 v-spec 3.4.3 the tail set is [vl, VLMAX)          -> empty when vl == VLMAX
	//   RVV 1.0 v-spec 5.3   vm == 1 makes every body element active
	//
	// so with an unmasked member the per-element active predicate is the constant 1, `vta`/`vtu`
	// and `vma`/`vmu` are vacuous, and a lane mask derived at run time from vec.vl/vec.vstart is
	// a translation-time all-ones constant.
	//
	// IT IS A PURE FUNCTION OF A FIELD THE NODE ALREADY CARRIES, and that is the point: the
	// translator (which decides whether to build the frame's shared lane masks) and QEmit (which
	// decides whether to emit a mask at all) must not answer this question in two places that
	// can drift. Both call this. `default: return false` means a guard kind added later does not
	// silently inherit the fast body.
	//
	// The kinds NOT listed weaken exactly one of the two facts and are therefore excluded:
	// every `VType*Partial*` kind admits `vl <= VLMAX`; `VTypeInteger`/`VTypeFp*` admit the same
	// and some let the body handle a non-zero vstart; `VTypeIntegerTwoArm` reaches its full body
	// through a partial-arm branch rather than a fallback branch; the `Vlenb*` kinds are
	// vtype-independent whole-register transfers with no lane predicate at all.
	static constexpr bool GuardProvesFullVl(GuardKind kind)
	{
		switch (kind) {
		case GuardKind::VTypeVlVstart:		 // vtype exact, vl == VLMAX, vstart == 0
		case GuardKind::VTypeVlVstartFrmRNE:	 // + frm == RNE
		case GuardKind::VTypeVlVstartFrmHostRound: // + frm <= RUP (C6-FRM)
		case GuardKind::VTypeVlVstartBaseLimit:	 // + the guest base-range test
		case GuardKind::VTypeVlVstartFrmRNEBaseMask: // + FP mode and all memory bases
		case GuardKind::VTypeVlVstartBaseMask: // + all memory bases
			return true;
		default:
			return false;
		}
	}

	// S1-3. DOES THIS FRAME'S OWN GUARD LEAVE `vec.vl` BOUNDED BY `vlmax`?
	//
	// The active-VL bound compares a translation-time ELEMENT INDEX against the live `vec.vl`. That
	// comparison only means "this chunk is entirely tail" if `vec.vl` is this frame's live element
	// count -- i.e. if the frame's guard already compared it against the `vlmax` the translator
	// computed from the same vtype the guard pinned. Every `VType*` kind below does exactly that
	// before the body runs, with `ja` (vl <= VLMAX) or `jne` (vl == VLMAX); see
	// Emit_rvvtypedchunkbegin, where the vl compare is emitted on every path that is not `Vlenb*`.
	//
	// THE `Vlenb*` KINDS RETURN FALSE, AND NOT AS A CONSERVATIVE DEFAULT. A whole-register transfer
	// (vmv<nr>r.v, vl<nr>re<eew>.v, vs<nr>r.v) has EVL = nregs * VLEN / EEW by RVV 1.0 and is legal
	// even under `vill`; its guard deliberately reads `vlenb` and never `vec.vl`. Ending such a
	// body early on a `vec.vl` test would be WRONG, not merely unprofitable, so the exclusion is a
	// Panic in Emit_vchunkactive rather than a comment.
	//
	// Like GuardProvesFullVl this is a pure function of a field the node already carries, read by
	// both the translator (which decides whether to emit bounds) and QEmit (which refuses a bound
	// it should not see), so the two cannot drift. `default: return false` means a kind added later
	// does not silently inherit the right to be bounded.
	static constexpr bool GuardBoundsVlByVlmax(GuardKind kind)
	{
		switch (kind) {
		case GuardKind::VTypeVlVstart:
		case GuardKind::VTypePartialVlVstartFrmRNE:
		case GuardKind::VTypeE32OrE64M2PartialVlVstartFrmRNE:
		case GuardKind::VTypeVlVstartFrmRNE:
		case GuardKind::VTypeVlVstartFrmHostRound:	 // C6-FRM
		case GuardKind::VTypePartialVlVstartFrmHostRound: // C6-FRM
		case GuardKind::VTypeVlOrPartialVstart:
		case GuardKind::VTypeVlVstartBaseLimit:
		case GuardKind::VTypeInteger:
		case GuardKind::VTypeIntegerTwoArm:
		case GuardKind::VTypeIntegerNoRestart:
		case GuardKind::VTypePartialVlVstartFrmHost:
		case GuardKind::VTypeFpNoRestart:
		case GuardKind::VTypeFpAnyRM:
		case GuardKind::VTypeFpAnyRMNoRestart:
		case GuardKind::VTypeVlOrPartialVstartBaseLimit:
		case GuardKind::VTypeVlVstartFrmRNEBaseMask:
		case GuardKind::VTypeVlVstartBaseMask:
			return true;
		case GuardKind::VlenbVstart:
		case GuardKind::VlenbVstartBaseLimit:
		case GuardKind::VlenbRestartable:
			return false;
		default:
			return false;
		}
	}

	// A14 constructor: the vlenb guard with the base-range test.
	InstRVVTypedChunkBegin(u32 vlenb_, u32 raw_, RuntimeStubId stub_, u16 n_typed_, GuardKind kind,
			       u32 base_state_offs_, u32 base_limit_)
	    : InstNoOperands(Op::_rvvtypedchunkbegin), vtype(0), vlmax(0), raw(raw_), stub(stub_),
	      n_typed(n_typed_), n_members(1), guard_kind(kind), vlenb(vlenb_),
	      base_state_offs((u16)base_state_offs_), base_limit(base_limit_)
	{
		if (kind != GuardKind::VlenbVstartBaseLimit)
			Panic("qir: vlenb base-limit constructor used with another guard kind");
		// A17: the guard compares the architectural vlenb against the translation-time VLEN/8
		// for ANY register width the whole-register frame is emitted at -- 16/32 (one
		// xmm/ymm chunk per register) as well as 64/128. Same representability bound as
		// RvvHostChunkGeometry: a power of two in [16, VLEN_MAX_BYTES].
		// QIR checks representability; the guest frontend validates its supported VLEN.
		if (vlenb_ < 16 || vlenb_ > 0xffffu || (vlenb_ & (vlenb_ - 1)) != 0)
			Panic("qir: rvvtypedchunkbegin vlenb is not an admitted VLEN/8");
		if (base_state_offs_ > 0xffffu - sizeof(u32))
			Panic("qir: rvvtypedchunkbegin base register offset is not representable");
		if (base_limit_ == 0)
			Panic("qir: rvvtypedchunkbegin base limit is zero");
	}

	// A13 constructor: the base-range guard kind, which is the only kind carrying the two extra
	// fields. Anything else through this constructor is a translation Panic.
	InstRVVTypedChunkBegin(u32 vtype_, u32 vlmax_, u32 raw_, RuntimeStubId stub_, u16 n_typed_,
			       GuardKind kind, u32 base_state_offs_, u32 base_limit_)
	    : InstNoOperands(Op::_rvvtypedchunkbegin), vtype(vtype_), vlmax(vlmax_), raw(raw_),
	      stub(stub_), n_typed(n_typed_), n_members(1), guard_kind(kind),
	      base_state_offs((u16)base_state_offs_), base_limit(base_limit_)
	{
		if (kind != GuardKind::VTypeVlVstartBaseLimit &&
		    kind != GuardKind::VTypeVlOrPartialVstartBaseLimit)
			Panic("qir: base-limit constructor used with another guard kind");
		if (base_state_offs_ > 0xffffu - sizeof(u32))
			Panic("qir: rvvtypedchunkbegin base register offset is not representable");
		if (base_limit_ == 0)
			Panic("qir: rvvtypedchunkbegin base limit is zero");
	}

	// R1A.3b run frame.  `n_members_` may be 1: a run former that admitted a single member builds
	// exactly the frame above, which is why there is no separate "is a run" flag anywhere.
	//
	// P7M-A ADDED THE GUARD KIND, DEFAULTED TO THE ACCEPTED ONE, so every integer-only run is
	// byte-identical: a caller that passes nothing gets exactly the node this constructor built
	// before. It is declared after the enum because a member's parameter type must already be
	// visible at its declaration.
	InstRVVTypedChunkBegin(u32 vtype_, u32 vlmax_, RVVRunMember const *members_, u8 n_members_,
			       u16 n_typed_, GuardKind kind = GuardKind::VTypeVlVstart)
	    : InstNoOperands(Op::_rvvtypedchunkbegin), vtype(vtype_), vlmax(vlmax_),
	      raw(members_[0].raw), stub(members_[0].stub), n_typed(n_typed_),
	      n_members(n_members_), guard_kind(kind)
	{
		// A run frame is a vtype-dependent frame by construction: every member is an
		// element-wise route whose SEW and LMUL come from vtype. The vlenb-only kind is for
		// whole-register transfers, which have no typed route and cut a run.
		if (kind != GuardKind::VTypeVlVstart && kind != GuardKind::VTypePartialVlVstartFrmRNE &&
		    kind != GuardKind::VTypeVlVstartFrmRNE && kind != GuardKind::VTypeVlOrPartialVstart &&
		    kind != GuardKind::VTypeIntegerTwoArm && kind != GuardKind::VTypeIntegerNoRestart)
			Panic("qir: rvv run frame built with a non-vtype guard kind");
		CheckRunMembers(members_, n_members_);
	}

	// G1 run frame WITH the memory frames' base-range guard. A run that contains a whole-register
	// transfer must prove the same fact the single-instruction memory frames prove -- that the
	// frame's host-pointer chunk window lies inside the 4 GiB guest space -- and the run
	// constructor above has no field for it. The base register is the ONE the scanner admitted
	// for every memory member of the run (rvvrun::RunDescriptor::mem_base_reg), and the limit is
	// the full-register bound 2^32 - VLEN/8, never a vl-derived one.
	InstRVVTypedChunkBegin(u32 vtype_, u32 vlmax_, RVVRunMember const *members_, u8 n_members_,
			       u16 n_typed_, GuardKind kind, u32 base_state_offs_, u32 base_limit_)
	    : InstNoOperands(Op::_rvvtypedchunkbegin), vtype(vtype_), vlmax(vlmax_),
	      raw(members_[0].raw), stub(members_[0].stub), n_typed(n_typed_),
	      n_members(n_members_), guard_kind(kind), base_state_offs((u16)base_state_offs_),
	      base_limit(base_limit_)
	{
		if (kind != GuardKind::VTypeVlVstartBaseLimit)
			Panic("qir: rvv run base-limit frame built with the wrong guard kind");
		if (base_state_offs_ > 0xffffu - sizeof(u32))
			Panic("qir: rvvtypedchunkbegin base register offset is not representable");
		if (base_limit_ == 0)
			Panic("qir: rvvtypedchunkbegin base limit is zero");
		CheckRunMembers(members_, n_members_);
	}

	InstRVVTypedChunkBegin(u32 vtype_, u32 vlmax_, RVVRunMember const *members_, u8 n_members_,
			       u16 n_typed_, GuardKind kind, u32 base_state_mask_, u32 base_limit_, bool)
	    : InstNoOperands(Op::_rvvtypedchunkbegin), vtype(vtype_), vlmax(vlmax_),
	      raw(members_[0].raw), stub(members_[0].stub), n_typed(n_typed_),
	      n_members(n_members_), guard_kind(kind), base_limit(base_limit_),
	      base_state_mask(base_state_mask_)
	{
		if ((kind != GuardKind::VTypeVlVstartFrmRNEBaseMask &&
		     kind != GuardKind::VTypeVlVstartBaseMask) || base_state_mask_ == 0 ||
		    (base_state_mask_ & 1u) != 0 || base_limit_ == 0)
			Panic("qir: run base-mask frame has invalid guard arguments");
		CheckRunMembers(members_, n_members_);
	}

	// THE SINGLE-INSTRUCTION, VTYPE-DEPENDENT, NO-EXTRA-FIELD CONSTRUCTOR. What the allowlist
	// below really enforces is that the kind needs nothing this constructor does not set: the
	// `*BaseLimit` / `*BaseMask` kinds carry a guest base register and a limit, and the `Vlenb*`
	// kinds carry `vlenb` instead of vtype/vlmax, so each of those has its own constructor and
	// reaching this one with them would leave a field the emitter reads uninitialised.
	//
	// F4 (2026-09-16) ADDED `VTypeVlVstartFrmRNE`. It carries vtype and vlmax and nothing else, so
	// it satisfies that invariant exactly as the nine kinds already listed do. It was absent only
	// because until F4 the single builder of it was the RUN constructor below -- which, as its own
	// comment says, already permits `n_members_ == 1` and already accepts this kind. The frame F4
	// builds is that same one-member frame: the LLVM/AOT fused route needs a guard that proves
	// `vl == VLMAX && vstart == 0 && frm == RNE` because its body carries no lane mask, and
	// RvvEmitTypedFmaChunkGroup selects it for `config::aot_use_llvm` only, so no pure-QCG frame
	// changes kind. Both consumers already lower it: QEmit::Emit_rvvtypedchunkbegin has handled it
	// since P7M-A and QIRToLLVM::Emit_rvvtypedchunkbegin since F1.
	//
	// The Panic keeps its name -- the other nine rows ARE the partial-vl kinds -- and keeps its
	// job: a kind that needs an extra field still cannot be built here.
	InstRVVTypedChunkBegin(u32 vtype_, u32 vlmax_, u32 raw_, RuntimeStubId stub_, u16 n_typed_,
			       GuardKind kind)
	    : InstNoOperands(Op::_rvvtypedchunkbegin), vtype(vtype_), vlmax(vlmax_), raw(raw_),
	      stub(stub_), n_typed(n_typed_), n_members(1), guard_kind(kind)
	{
		if (kind != GuardKind::VTypeVlVstart && // Exact full-VL state needs no extra fields.
		    kind != GuardKind::VTypePartialVlVstartFrmRNE &&
		    kind != GuardKind::VTypeVlVstartFrmHostRound &&	  // C6-FRM
		    kind != GuardKind::VTypePartialVlVstartFrmHostRound && // C6-FRM
		    kind != GuardKind::VTypeFpAnyRM &&
		    kind != GuardKind::VTypeFpAnyRMNoRestart &&
		    kind != GuardKind::VTypePartialVlVstartFrmHost &&
		    kind != GuardKind::VTypeFpNoRestart &&
		    kind != GuardKind::VTypeE32OrE64M2PartialVlVstartFrmRNE &&
		    kind != GuardKind::VTypeVlVstartFrmRNE && // F4, see above
		    kind != GuardKind::VTypeInteger && kind != GuardKind::VTypeIntegerTwoArm &&
		    kind != GuardKind::VTypeIntegerNoRestart)
			Panic("qir: partial-vl constructor used with wrong guard kind");
	}

	// Native-2 constructor for a vtype-independent frame. `vlenb_` is the ONLY width fact such a
	// route depends on: the translator has already turned the runtime VLEN into a chunk count and
	// a set of displacements, and this is what proves at run time that the VLEN it compiled for is
	// the VLEN executing. vtype/vlmax are left zero and are never read for this kind.
	InstRVVTypedChunkBegin(u32 vlenb_, u32 raw_, RuntimeStubId stub_, u16 n_typed_, GuardKind kind)
	    : InstNoOperands(Op::_rvvtypedchunkbegin), vtype(0), vlmax(0), raw(raw_), stub(stub_),
	      n_typed(n_typed_), n_members(1), guard_kind(kind), vlenb(vlenb_)
	{
		if (kind != GuardKind::VlenbVstart && kind != GuardKind::VlenbRestartable) {
			Panic("qir: rvvtypedchunkbegin vlenb constructor used for a vtype guard");
		}
		if (vlenb_ < 16 || vlenb_ > 0xffffu || (vlenb_ & (vlenb_ - 1)) != 0) {
			Panic("qir: rvvtypedchunkbegin vlenb is not an admitted VLEN/8");
		}
	}

	u32 vtype; // expected CPUState::vec.vtype; guarded at run time (VTypeVlVstart only)
	u32 vlmax; // the typed path runs only at vl == VLMAX      (VTypeVlVstart only)
	u32 raw;   // guest encoding of member 0, for the fallback helper call
	RuntimeStubId stub; // fallback stub of member 0
	// M2E: u16, not u8. The bound on a run's members is now the translation block's own
	// instruction bound (64) and the widest admitted chunk count is 8, so a frame can legally
	// describe up to 4*64*8 = 2048 typed body ops. A u8 field could not represent every run the
	// other two limits admit, which would have made the NODE the binding constraint -- a
	// representation accident, not a translation one.
	u16 n_typed; // typed instructions the group must contain; checked by `end`
	u8 n_members; // members this ONE guard covers; 1 is the accepted single-instruction frame
	GuardKind guard_kind{GuardKind::VTypeVlVstart}; // default = the accepted predicate
	u32 vlenb{0}; // expected CPUState::vec.vlenb   (VlenbVstart only)
	u16 base_state_offs{0}; // A13: CPUState offset of the base GPR (VTypeVlVstartBaseLimit only)
	u32 base_limit{0};	// A13: largest admissible base, 2^32 - VLEN/8 (VTypeVlVstartBaseLimit only)
	u32 base_state_mask{0}; // run guard: one bit per guest GPR whose base must be <= base_limit
	// P7M-E diagnostic (`--rvv-run-frame-census`). `&rvvrun::FrameCensusEntry::count` for the
	// entry registered for THIS frame, or nullptr -- which is what every accepted arm carries,
	// because the allocator returns nullptr with the switch off and the translator only ever
	// calls it for a MULTI-member run frame. A default member initializer rather than a
	// constructor parameter, deliberately: all eleven existing constructors, and therefore every
	// single-instruction route's node, are untouched and keep producing exactly what they did.
	// QCG-only; the LLVM backend ignores it, which is why arming the switch refuses that backend
	// in elfrun rather than silently reporting zeros.
	u64 *frame_census_slot{nullptr};

	// C4e. IS THIS FRAME'S BODY EMITTED IN COMPONENT-MAJOR ORDER? A default member initializer for
	// the same reason `frame_census_slot` above is one: every existing constructor, and therefore
	// every single-instruction route's node and every member-major run's node, is untouched and
	// keeps producing exactly what it did.
	//
	// WHY THE NODE CARRIES IT AND NOT THE EMITTER. `QEmit::Emit_vchunkactive` has to refuse a bound
	// it must not see, and the fact it must check -- "does an early exit from here skip only
	// INACTIVE work?" -- is a property of the body's LINEAR ORDER, which QEmit cannot observe: it
	// sees one node at a time. The translator knows the order because it chose it, so the claim is
	// made here and checked twice: `rvvfinal::CloseFrame` re-derives the frame's work units from
	// the emitted nodes and refuses a frame whose units do not match the claim, and QEmit refuses a
	// bound in a multi-member frame that does not carry it.
	//
	// It is NEVER true for a single-member frame (whose chunk-ascending body is already the tail
	// property, stated by `n_members == 1` directly) and never true for the member-major, the
	// materialize, the chunk-major or the live-range-splitting run bodies.
	bool body_component_major{false};

	// Structural invariants a run must satisfy, checked at construction so a malformed run is a
	// loud translation failure rather than a silently wrong fallback arm.
	static void CheckRunMembers(RVVRunMember const *m, u8 n)
	{
		if (n == 0 || n > RVV_RUN_MAX_MEMBERS) {
			Panic("qir: rvv run member count out of range");
		}
		for (u8 i = 0; i < n; ++i) {
			if (m[i].stub == RuntimeStubId::Count && !m[i].scalar_passthrough) {
				Panic("qir: rvv run member has no fallback stub");
			}
			// Only a multi-member run needs per-member PCs; see RVVRunMember.
			if (n > 1 && m[i].pc == RVVRunMember::PC_UNUSED) {
				Panic("qir: rvv run member has no guest pc");
			}
			// Members are CONSECUTIVE guest instructions.  The run former only ever
			// extends across `pc + 4`, and the ordered fallback arm reproduces the guest
			// sequence exactly, so a gap here would mean the frame skips an instruction.
			if (i > 0 && m[i].pc != m[i - 1].pc + 4) {
				Panic("qir: rvv run members are not consecutive guest instructions");
			}
		}
	}
};

struct InstRVVTypedChunkEnd : InstNoOperands {
	// Single-member frame: unchanged.
	//
	// S1-3: `frame_clears_vstart_` is the TRANSLATOR'S half of "who writes vec.vstart = 0". False
	// (the default, and every pre-S1-3 caller) means the LAST chunk node does, through its own
	// `finish_instruction`. True means this node does, after binding the body-done label the frame's
	// active-VL bounds branch to -- the only placement at which an early-exited body still clears
	// vstart. QEmit holds the other half (`rvv_typed_chunk_bound_open`, set by the bounds it
	// actually emitted) and Panics if the two disagree, because the silent form of that
	// disagreement is a frame that never clears vstart and corrupts the NEXT vector instruction.
	// P2a: `census_units_` / `census_prefix_units_` are the finalizer's OWN derived geometry,
	// carried to the emitter so the default-off active-chunk census has a unit count and a first
	// bounded unit without a second classifier. Both are zero for every frame the common close
	// classified ineligible, and for every caller that predates P2a; see the fields below.
	InstRVVTypedChunkEnd(u32 raw_, RuntimeStubId stub_, u16 whole_regbytes_ = 0,
			     bool frame_clears_vstart_ = false, u16 census_units_ = 0,
			     u16 census_prefix_units_ = 0)
	    : InstNoOperands(Op::_rvvtypedchunkend), raw(raw_), stub(stub_), n_members(1),
	      whole_regbytes(whole_regbytes_), frame_clears_vstart(frame_clears_vstart_),
	      census_units(census_units_), census_prefix_units(census_prefix_units_)
	{
		if (census_prefix_units > census_units)
			Panic("qir: chunk-frame census prefix exceeds the frame's unit count");
		if (whole_regbytes &&
		    ((stub != RuntimeStubId::id_rv32_vlNre && stub != RuntimeStubId::id_rv32_vsNr) ||
		     whole_regbytes < 16 || whole_regbytes > 512 || (whole_regbytes & (whole_regbytes - 1))))
			Panic("qir: invalid native whole-register fallback");
		inline_member.raw = raw_;
		inline_member.stub = stub_;
		members = &inline_member;
	}

	// R1A.3b run frame.  This node carries the AUTHORITATIVE ordered member list: the QCG backend
	// emits the fallback arm here, one helper call per member in guest order.
	//
	// M2E: `members_` is BORROWED, not copied, and must outlive the node. The one production
	// caller (RvvEmitVectorRunGroup) allocates it from the region's own arena through
	// Builder::CreateRunMembers, so it has exactly the region's lifetime -- the same ownership
	// InstCCRFComputeRegion::operations has. A stack array here would dangle, which is why the
	// builder helper exists rather than leaving the allocation to each caller.
	InstRVVTypedChunkEnd(RVVRunMember const *members_, u8 n_members_)
	    : InstNoOperands(Op::_rvvtypedchunkend), raw(members_[0].raw), stub(members_[0].stub),
	      n_members(n_members_), members(members_)
	{
		InstRVVTypedChunkBegin::CheckRunMembers(members_, n_members_);
	}

	// C4e. THE RUN FRAME THAT WENT THROUGH THE PLANNER-ELIGIBLE CLOSE, and the only constructor
	// that carries BOTH the ordered member list and the derived geometry. It exists because a
	// component-major run frame is the first frame that is simultaneously a run (its fallback arm
	// needs the member list) and planner-eligible (its census fields are derived and its vstart
	// convention may have been relocated). The two pre-existing constructors each carry one half
	// and neither can be made to carry the other without changing what every existing caller
	// builds.
	InstRVVTypedChunkEnd(RVVRunMember const *members_, u8 n_members_, bool frame_clears_vstart_,
			     u16 census_units_, u16 census_prefix_units_)
	    : InstNoOperands(Op::_rvvtypedchunkend), raw(members_[0].raw), stub(members_[0].stub),
	      n_members(n_members_), frame_clears_vstart(frame_clears_vstart_),
	      census_units(census_units_), census_prefix_units(census_prefix_units_),
	      members(members_)
	{
		InstRVVTypedChunkBegin::CheckRunMembers(members_, n_members_);
		if (census_prefix_units > census_units)
			Panic("qir: chunk-frame census prefix exceeds the frame's unit count");
	}

	u32 raw;	    // member 0's encoding; == members[0].raw by construction
	RuntimeStubId stub; // member 0's stub;     == members[0].stub by construction
	u8 n_members;
	// Whole-register fast frames can fall back to restartable native memory code.
	u16 whole_regbytes = 0;
	// S1-3. Never set by the run constructor: a run's early exit would skip later MEMBERS, which
	// are different guest instructions, so a run frame is never bounded and never owns this write.
	bool frame_clears_vstart = false;
	// P2a. THE FRAME'S DERIVED WORK-UNIT GEOMETRY, for the default-off active-chunk census only.
	//
	// `census_units` is how many host work units this frame's body contains -- the count
	// `rvvfinal::CloseFrame` derived from the emitted QIR nodes and already checked against the
	// producer's geometry. `census_prefix_units` is how many of them carry NO active-VL bound and
	// are therefore reached on every execution of the native body; it equals `census_units` exactly
	// when the frame is unbounded, which is why a policy-off frame's executed count equals its
	// available count by construction rather than by a separate rule.
	//
	// ZERO MEANS "DO NOT COUNT THIS FRAME", and that is the only thing the emitter reads out of
	// them: a run frame, a whole-register transfer, a memory frame and every other ineligible shape
	// leave both at zero, so the census population is exactly the planner-eligible frames the
	// common close accepted. Nothing else in the backend reads these fields, and with the census
	// switch off nothing reads them at all.
	u16 census_units = 0;
	u16 census_prefix_units = 0;
	// Storage for the single-member frame, so that case needs no allocation at all. `members`
	// points here when n_members == 1 and at the caller's arena array otherwise. Inst nodes are
	// placement-new'd into the arena and never copied or moved, so the self-pointer is stable.
	RVVRunMember inline_member{};
	RVVRunMember const *members{};
};

// T7S general direct-QCG state update for admitted immediate-vtype vsetvli/vsetivli. The
// translator derives vtype, VLMAX and vlenb from legal instruction fields and the configured
// VLEN. Register AVL and immediate AVL share this node; an x0 destination is bound to a temporary.
//
//   vl <- min(AVL, VLMAX)   UNSIGNED, over the whole 2^32 AVL domain
//   gpr[rd]        <- vl
//   vec.vtype      <- vtype       vec.vl     <- vl
//   vec.vstart     <- 0           vec.vlenb  <- vlenb
//
// That is the WHOLE instruction, as HANDLER(vsetvli) (rv32_interp.cpp) defines it for this form:
// no guest memory is touched, no branch is taken, no trap is raised and nothing else in CPUState
// changes.  All four vec fields are guest-observable -- vstart/vl/vtype through their intercepted
// CSRs and vlenb through the read-only `vlenb` CSR -- so none of them may be skipped as bookkeeping.
//
// ONE OUTPUT (vl, which the translator binds to the guest rd global) AND ONE INPUT (AVL, the guest
// rs1 global).  Everything else is a translation-time constant carried as a node FIELD rather than
// read out of `config` in the emitter, modelled on InstRVVTypedChunkBegin: the emitter must produce
// code for the configuration the TRANSLATOR admitted, and a later `config` read would silently
// describe a different one.
//
// THE MIN IS UNSIGNED AND THAT IS A SEMANTIC REQUIREMENT, not an encoding preference.  rvdbt's own
// interpreter computes `avl < vlmax ? avl : vlmax` on u32 (rv32_interp.cpp), and every arm of this
// evidence chain -- the interpreter, the qcgstub helper, --rvv-verify and the QEMU oracle -- was
// taken against that choice.  A signed compare agrees on every AVL below 2^31 and disagrees on
// exactly the top half of the domain, where it would return AVL (up to 0xffffffff) as `vl`.
// Do not "simplify" the emitter's cmovb into a cmovl.
//
// Normal forms need no runtime guard: admission proves legality and unsigned min is exact over the
// whole AVL domain. The architectural rd=x0,rs1=x0 form instead carries keep_vl=true; its emitter
// retains current VL when it fits the new VLMAX and otherwise sets vill/vl=0 fail-closed.
struct InstRVVSetVL : InstWithOperands<1, 1> {
	InstRVVSetVL(VOperand d, VOperand avl, u32 vtype_, u32 vlmax_, u32 vlenb_, bool keep_vl_ = false)
	    : InstWithOperands(Op::_rvvsetvl, {d}, {avl}), vtype(vtype_), vlmax(vlmax_),
	      vlenb(vlenb_), keep_vl(keep_vl_)
	{
		// VLMAX fits e8,m8. Zero is reserved here for the explicit vill/zero-VL result;
		// legal configurations derive their positive VLMAX in the translator.
		//
		// T6b MADE THE WIDTH ROW GENERIC.  It was the literal pair `64 or 128`, i.e. VLEN 512 and
		// 1024, which is the set RvvSetVLShapeAdmit happened to admit rather than anything this
		// node depends on -- so widening that predicate alone would have turned an admitted
		// VLEN=2048 `vsetvli` into a Panic here.
		//
		// P7N-D REMOVES THE LAST THING IN IT THAT WAS NOT THIS NODE'S OWN PROPERTY. The rule was
		// "a whole number of 64-byte host chunks", which refused VLEN 128 and 256 -- but THIS
		// NODE HAS NO CHUNKS. Its emitter writes four scalar CPUState fields and one guest GPR;
		// `vlenb` is a constant it stores verbatim into the guest-observable `vlenb` CSR, and
		// nothing about a host vector width reaches it. Carrying the chunk rule here meant a
		// route that legitimately admitted VLEN=128 would Panic in the emitter's constructor
		// instead of producing code, which is a translation-time abort for a reason that has
		// nothing to do with what this node does.
		//
		// What the node actually requires is that `vlenb` is a representable architectural
		// VLEN/8: a power of two (rv32::vlen_supported() admits only those), at least the 16
		// bytes VLEN=128 gives, and no wider than the per-register storage reservation permits.
		// That is the bound below, and it still refuses every shape the old one refused for a
		// reason the old one actually had -- VLEN 384 is not a power of two, and anything past
		// MAX_REG_CHUNKS still fails closed.
		if (vlenb_ < 16 || (vlenb_ & (vlenb_ - 1)) != 0 ||
		    vlenb_ > MAX_REG_CHUNKS * InstVChunkLoad::CHUNK_BYTES) {
			Panic("qir: rvvsetvl vlenb is not an admitted VLEN/8");
		}
		// e8,m8 has VLEN elements. An invalid immediate has no keep-VL form: it clears VL.
		if ((vlmax_ == 0 && (vtype_ != 0x80000000u || keep_vl_)) || vlmax_ > vlenb_ * 8) {
			Panic("qir: rvvsetvl vlmax is outside the legal architectural bound");
		}
	}

	u32 vtype; // written verbatim to vec.vtype
	u32 vlmax; // the min() bound; zero encodes an unsupported immediate vtype (vill)
	u32 vlenb; // written verbatim to vec.vlenb
	bool keep_vl; // rd=x0,rs1=x0: retain current vl or set vill/zero if new VLMAX is too small
};

// Runtime vtype, unlike rvvsetvl's immediate configuration. Both inputs must be
// consumed before the output is written because guest rd can alias either source.
struct InstRVVSetVLReg : InstWithOperands<1, 2> {
	InstRVVSetVLReg(VOperand d, VOperand avl, VOperand vtype, u32 vlenb_, bool keep_vl_)
	    : InstWithOperands(Op::_rvvsetvlreg, {d}, {avl, vtype}), vlenb(vlenb_), keep_vl(keep_vl_)
	{
		if (vlenb < 16 || (vlenb & (vlenb - 1)) || vlenb > MAX_REG_CHUNKS * 64)
			Panic("qir: rvvsetvlreg invalid VLEN");
	}
	u32 vlenb;
	bool keep_vl;
};

// Fixed-host chunks for the LLVM-AOT prior-art comparator.  Four chunks cover
// the architectural maximum used here (VLEN=1024, LMUL=2); active_chunks and
// EVL state which prefix is live.  Unused operands remain typed SSA values so
// the instruction shape is fixed and the ordinary QIR visitor machinery can
// process it without a workload- or sequence-specific opcode.
struct InstRVVRead : InstWithOperands<1, 1> {
	InstRVVRead(VOperand d, VOperand state_off, u16 bytes_)
	    : InstWithOperands(Op::_rvvread, {d}, {state_off}), bytes(bytes_) {}
	u16 bytes;
};

struct InstRVVWrite : InstWithOperands<0, 2> {
	InstRVVWrite(VOperand state_off, VOperand value, u16 bytes_)
	    : InstWithOperands(Op::_rvvwrite, {}, {state_off, value}), bytes(bytes_) {}
	u16 bytes;
};

struct InstRVVSplatF : InstWithOperands<1, 1> {
	InstRVVSplatF(VOperand d, VOperand freg_off, u8 sew_)
	    : InstWithOperands(Op::_rvvsplatf, {d}, {freg_off}), sew(sew_) {}
	u8 sew;
};

struct InstRVVLoad : InstWithOperands<4, 1> {
	InstRVVLoad(VOperand d0, VOperand d1, VOperand d2, VOperand d3, VOperand addr,
		    u8 vd_, u8 nregs_, u8 active_chunks_, u16 evl_, u32 raw_, RuntimeStubId stub_)
	    : InstWithOperands(Op::_rvvload, {d0, d1, d2, d3}, {addr}), raw(raw_), stub(stub_),
	      evl(evl_), vd(vd_), nregs(nregs_), active_chunks(active_chunks_) {}
	u32 raw;
	RuntimeStubId stub;
	u16 evl;
	u8 vd, nregs, active_chunks;
};

struct InstRVVStore : InstWithOperands<0, 5> {
	InstRVVStore(VOperand addr, VOperand s0, VOperand s1, VOperand s2, VOperand s3,
		     u8 vs3_, u8 nregs_, u8 active_chunks_, u16 evl_, u32 raw_, RuntimeStubId stub_)
	    : InstWithOperands(Op::_rvvstore, {}, {addr, s0, s1, s2, s3}), raw(raw_), stub(stub_),
	      evl(evl_), vs3(vs3_), nregs(nregs_), active_chunks(active_chunks_) {}
	u32 raw;
	RuntimeStubId stub;
	u16 evl;
	u8 vs3, nregs, active_chunks;
};

struct InstRVVFCmp : InstWithOperands<1, 5> {
	InstRVVFCmp(VOperand mask, VOperand s0, VOperand s1, VOperand s2, VOperand s3,
		    VOperand scalar, u8 vd_, u8 vs2_, u8 active_chunks_, u8 sew_, u8 funct6_,
		    u32 vtype_, u16 evl_, u32 raw_, RuntimeStubId stub_)
	    : InstWithOperands(Op::_rvvfcmp, {mask}, {s0, s1, s2, s3, scalar}), raw(raw_),
	      vtype(vtype_), stub(stub_), evl(evl_), vd(vd_), vs2(vs2_),
	      active_chunks(active_chunks_), sew(sew_), funct6(funct6_) {}
	u32 raw, vtype;
	RuntimeStubId stub;
	u16 evl;
	u8 vd, vs2, active_chunks, sew, funct6;
};

struct InstRVVMerge : InstWithOperands<4, 9> {
	InstRVVMerge(std::array<VOperand, 4> d, std::array<VOperand, 4> vs2,
		     std::array<VOperand, 4> vs1, VOperand mask, u8 vd_, u8 vs2_reg_, u8 vs1_reg_,
		     u8 active_chunks_, u8 sew_, u32 vtype_, u16 evl_, u32 raw_, RuntimeStubId stub_)
	    : InstWithOperands(Op::_rvvmerge, std::move(d),
			       {vs2[0], vs2[1], vs2[2], vs2[3], vs1[0], vs1[1], vs1[2], vs1[3], mask}),
	      raw(raw_), vtype(vtype_), stub(stub_), evl(evl_), vd(vd_), vs2(vs2_reg_),
	      vs1(vs1_reg_), active_chunks(active_chunks_), sew(sew_) {}
	u32 raw, vtype;
	RuntimeStubId stub;
	u16 evl;
	u8 vd, vs2, vs1, active_chunks, sew;
};

// C5-FP Family A (2026-09-18). `oldd` IS NEW AND IT IS NOT AN OPTIMISATION.
//
// vfalu does not read vd architecturally, so until partial VL this node had no vd input and its
// operand layout was {vs2[0..3], vs1[0..3]}. A PARTIAL-VL execution writes only the elements below
// `vl`; the rest of the destination must keep the bytes it had, and on this route those bytes are
// the SSA chunk residency's current value for vd, not CPUState. So the old value has to be an
// OPERAND -- there is nowhere else to read it from once the residency owns the register.
//
// The layout is now {oldd[0..3], vs2[0..3], vs1[0..3]}, which is exactly InstRVVFMA's, so the two
// FP nodes of this family have one shape. `Emit_rvvfalu`'s fallback arm indexes vs2 at 4 and vs1 at
// 8 accordingly.
//
// `partial_vl` IS CARRIED ON THE NODE RATHER THAN RE-READ FROM config. The translator decides what
// it put in the `oldd` slots; when the switch is off it puts the vs2 operands there (aliases of
// values the node already holds, so no `rvvread`, no extra live value, no IR change at all) and the
// emitter must not read them. A field makes that agreement part of the node instead of two
// independent reads of a global that could drift.
struct InstRVVFALU : InstWithOperands<4, 12> {
	InstRVVFALU(std::array<VOperand, 4> d, std::array<VOperand, 4> oldd,
		    std::array<VOperand, 4> vs2, std::array<VOperand, 4> vs1, u8 vd_, u8 vs2_reg_,
		    u8 vs1_reg_, u8 active_chunks_, u8 sew_, u8 funct6_, u32 vtype_, u16 evl_,
		    u32 raw_, RuntimeStubId stub_, bool partial_vl_)
	    : InstWithOperands(Op::_rvvfalu, std::move(d),
			       {oldd[0], oldd[1], oldd[2], oldd[3], vs2[0], vs2[1], vs2[2], vs2[3],
				vs1[0], vs1[1], vs1[2], vs1[3]}),
	      raw(raw_), vtype(vtype_), stub(stub_), evl(evl_), vd(vd_), vs2(vs2_reg_),
	      vs1(vs1_reg_), active_chunks(active_chunks_), sew(sew_), funct6(funct6_),
	      partial_vl(partial_vl_) {}
	u32 raw, vtype;
	RuntimeStubId stub;
	u16 evl;
	u8 vd, vs2, vs1, active_chunks, sew, funct6;
	bool partial_vl;
};

struct InstRVVFMA : InstWithOperands<4, 13> {
	InstRVVFMA(std::array<VOperand, 4> d, std::array<VOperand, 4> oldd,
		   std::array<VOperand, 4> vs2, std::array<VOperand, 4> vs1, VOperand scalar,
		   u8 vd_, u8 vs2_reg_, u8 vs1_reg_, bool is_vf_, u8 active_chunks_, u8 sew_,
		   u8 funct6_, u32 vtype_, u16 evl_, u32 raw_, RuntimeStubId stub_, bool partial_vl_)
	    : InstWithOperands(Op::_rvvfma, std::move(d),
			       {oldd[0], oldd[1], oldd[2], oldd[3], vs2[0], vs2[1], vs2[2], vs2[3],
				vs1[0], vs1[1], vs1[2], vs1[3], scalar}),
	      raw(raw_), vtype(vtype_), stub(stub_), evl(evl_), vd(vd_), vs2(vs2_reg_),
	      vs1(vs1_reg_), is_vf(is_vf_), active_chunks(active_chunks_), sew(sew_), funct6(funct6_),
	      partial_vl(partial_vl_) {}
	u32 raw, vtype;
	RuntimeStubId stub;
	u16 evl;
	u8 vd, vs2, vs1;
	bool is_vf;
	u8 active_chunks, sew, funct6;
	// C5-FP Family A: unlike InstRVVFALU this node ALREADY carried `oldd` -- `vfmadd` reads vd as
	// a multiplicand, so the old value was never optional and there is no inertness question about
	// materialising it. The flag selects the partial guard, the operand neutralisation and the
	// destination merge only.
	bool partial_vl;
};

// C5-FP Family A (2026-09-18). WHY THE BRACKET NEEDED A `partial_vl` TOO, AND WHY THIS IS NOT
// SCOPE CREEP.
//
// `Emit_rvvfpbegin` guards `vl == VLMAX`. It is the ONLY thing that installs the guest `frm` into
// MXCSR.RC and sets `fround_run_open`, and `Emit_rvvfpend` accrues the host sticky bits into the
// guest `fcsr` only when that flag is set. So at `vl < VLMAX` the bracket does not open -- and a
// partial-VL `vfalu` fast arm would then have computed `round.dynamic` arithmetic under whatever
// rounding mode the HOST happened to be in, and every flag it raised would have been dropped
// instead of reaching `fcsr`. Widening the lane operation without widening the bracket is not a
// partial implementation of the fflags contract, it is a violation of it.
//
// WHAT WIDENING IT COSTS. The bracket is shared by the whole Family A FP block (vfalu, vfma,
// vfcmp). With the switch on, a `vl < VLMAX` block now opens it even though only `vfalu` has a
// partial-VL body; the others miss their own full-VL guards and take their ordered helper
// fallbacks. That is a combination the route already produces for every other guard-miss reason,
// and the helpers handle an INHERITED open bracket explicitly --
// `rvv_fast::fround_run_open_or_continue` compares the mirrored RC and re-opens if it differs, and
// `rvv_ref`'s `FRound` saves/clears/harvests around itself. Since `fcsr` accumulates by OR, an
// early harvest loses nothing.
struct InstRVVFPBegin : InstWithOperands<0, 1> {
	InstRVVFPBegin(VOperand expected_vtype, u16 evl_, bool partial_vl_)
	    : InstWithOperands(Op::_rvvfpbegin, {}, {expected_vtype}), evl(evl_),
	      partial_vl(partial_vl_) {}
	u16 evl;
	bool partial_vl;
};

struct InstRVVFPEnd : InstWithOperands<0, 1> {
	InstRVVFPEnd(VOperand expected_vtype, u16 evl_)
	    : InstWithOperands(Op::_rvvfpend, {}, {expected_vtype}), evl(evl_) {}
	u16 evl;
};

struct InstVMLoad : InstWithOperands<1, 1> {
	InstVMLoad(VType sz_, VSign sgn_, VOperand d, VOperand ptr)
	    : InstWithOperands(Op::_vmload, {d}, {ptr}), sz(sz_), sgn(sgn_)
	{
	}

	VType sz;
	VSign sgn;
};

struct InstVMStore : InstWithOperands<0, 2> {
	InstVMStore(VType sz_, VSign sgn_, VOperand ptr, VOperand val)
	    : InstWithOperands(Op::_vmstore, {}, {ptr, val}), sz(sz_), sgn(sgn_)
	{
	}

	VType sz;
	VSign sgn;
};

struct InstVMLoad2 : InstWithOperands<2, 1> {
	InstVMLoad2(VType sz_, VSign sgn_, VOperand d1, VOperand d2, VOperand ptr)
	    : InstWithOperands(Op::_vmload2, {d1, d2}, {ptr}), sz(sz_), sgn(sgn_)
	{
	}

	VType sz;
	VSign sgn;
};

struct InstVMLoad4 : InstWithOperands<4, 1> {
	InstVMLoad4(VType sz_, VSign sgn_, VOperand d1, VOperand d2, VOperand d3, VOperand d4, VOperand ptr)
	    : InstWithOperands(Op::_vmload4, {d1, d2, d3, d4}, {ptr}), sz(sz_), sgn(sgn_)
	{
	}

	VType sz;
	VSign sgn;
};

/*
Note:
	the order of vals is reversed from the IR when Qsel, 
	because the jit emit always use the same order instead of riscv load store.
	E.g., store two like below:
	store t1, 4(a0)
	store t2, 0(a0)
	will have corresponding load like below:
	load t2, 0(a0)
	load t1, 4(a0)

	but when jit emit in x86, it store two ints from low to high, so the order of vals is reversed.
*/
struct InstVMStore2 : InstWithOperands<0, 3> {
	InstVMStore2(VType sz_, VSign sgn_, VOperand ptr, VOperand val1, VOperand val2)
	    : InstWithOperands(Op::_vmstore2, {}, {ptr, val1, val2}), sz(sz_), sgn(sgn_)
	{
	}

	VType sz;
	VSign sgn;
};

struct InstVMStore4 : InstWithOperands<0, 5> {
	InstVMStore4(VType sz_, VSign sgn_, VOperand ptr, VOperand val1, VOperand val2, VOperand val3, VOperand val4)
	    : InstWithOperands(Op::_vmstore4, {}, {ptr, val1, val2, val3, val4}), sz(sz_), sgn(sgn_)
	{
	}

	VType sz;
	VSign sgn;
};


struct InstSetcc : InstWithOperands<1, 2> {
	InstSetcc(CondCode cc_, VOperand d, VOperand sl, VOperand sr)
	    : InstWithOperands(Op::_setcc, {d}, {sl, sr}), cc(cc_)
	{
	}

	CondCode cc;
};

struct Block;
struct Region;
inline MemArena *ArenaOf(Region *rn);

struct Block : IListNode<Block>, InArena {
	Block(Region *rn_, u32 id_) : rn(rn_), succs(ArenaOf(rn)), preds(ArenaOf(rn)), id(id_) {}

	IList<Inst> ilist;

	// V-next region-merge: guest entry IP if this block is an ip-range entry (set by the translator), else 0.
	// Used to build a switch(state->ip) dispatch when merging many dispatch handlers into one LLVM function.
	u32 entry_ip{};

	Region *GetRegion() const
	{
		return rn;
	}

	u32 GetId() const
	{
		return id;
	}

	void AddSucc(Block *succ)
	{
		succs.push_back(succ);
		succ->preds.push_back(this);
	}

	auto &GetSuccs()
	{
		return succs;
	}
	auto &GetPreds()
	{
		return preds;
	}

private:
	Region *rn;
	ArenaVector<Block *> succs, preds;
	u32 id{(u32)-1};
};

struct StateReg {
	u16 state_offs;
	VType type;
	char const *name;
};

struct StateInfo {
	StateReg const *GetStateReg(RegN idx) const
	{
		if (idx < n_regs) {
			return &regs[idx];
		}
		return nullptr;
	}

	StateReg *regs{};
	RegN n_regs{};
};

struct VRegsInfo {
	VRegsInfo(MemArena *arena_, StateInfo const *glob_info_) : glob_info(glob_info_), loc_info(arena_) {}

	auto NumGlobals() const
	{
		return glob_info->n_regs;
	}

	auto NumLocals() const
	{
		return loc_info.size();
	}

	auto NumAll() const
	{
		return glob_info->n_regs + loc_info.size();
	}

	bool IsGlobal(RegN idx) const
	{
		return idx < glob_info->n_regs;
	}

	bool IsLocal(RegN idx) const
	{
		return !IsGlobal(idx);
	}

	StateReg const *GetGlobalInfo(RegN idx) const
	{
		assert(IsGlobal(idx));
		return &glob_info->regs[idx];
	}

	VType GetLocalType(RegN idx) const
	{
		assert(IsLocal(idx));
		return loc_info[idx - glob_info->n_regs];
	}

	RegN AddLocal(VType type)
	{
		auto idx = loc_info.size() + glob_info->n_regs;
		loc_info.push_back(type);
		return idx;
	}

private:
	StateInfo const *glob_info;
	ArenaVector<VType> loc_info;
};

struct Region : InArena {
	explicit Region(MemArena *arena_, StateInfo const *state_info_)
	    : arena(arena_), vregs_info(arena, state_info_)
	{
	}

	auto &GetBlocks()
	{
		return blist;
	}

	Block *CreateBlock()
	{
		auto bb = arena->New<Block>(this, bb_id_counter++);
		blist.push_back(bb);
		return bb;
	}

	template <typename T, typename... Args>
	requires std::is_base_of_v<Inst, T> T *Create(Inst::Flags flags, Args &&...args)
	{
		return Inst::New<T>(arena, inst_id_counter++, flags, std::forward<Args>(args)...);
	}

	u32 GetNumBlocks() const
	{
		return bb_id_counter;
	}

	MemArena *GetArena()
	{
		return arena;
	}

	VRegsInfo *GetVRegsInfo()
	{
		return &vregs_info;
	}

	u32 num_insns{0};

	// 2026-06-21 --qcg-pin: guest registers the QCG register allocator pinned to reserved host regs for this region.
	// The codegen PROLOGUE (runs once per region entry; the loop backedge jumps past it) loads each from CPUState, so
	// loop-carried guest regs stay resident across the backedge without a separate preheader block.
	struct PinLoad {
		u8 preg;
		u16 offs;
		VType type;
	};
	u8 n_pins{0};
	PinLoad pins[8]{};

private:
	MemArena *arena;
	IList<Block> blist;

	VRegsInfo vregs_info;

	u32 inst_id_counter{0};
	u32 bb_id_counter{0};
};

MemArena *ArenaOf(Region *rn)
{
	return rn->GetArena();
}

template <typename Derived, typename RT>
struct InstVisitor {
#define VIS_CLASS(cls) return static_cast<Derived *>(this)->visit##cls(static_cast<cls *>(ins))

#define OP(name, cls, flags)                                                                                 \
	RT visit_##name(cls *ins)                                                                            \
	{                                                                                                    \
		VIS_CLASS(cls);                                                                              \
	}
	QIR_OPS_LIST(OP)
#undef OP

#define CLASS(cls, beg, end)                                                                                 \
	RT visit##cls(cls *ins)                                                                              \
	{                                                                                                    \
		VIS_CLASS(Inst);                                                                             \
	}
	QIR_CLASS_LIST(CLASS)
#undef CLASS

	void visitInst(Inst *ins) {}

	RT visit(Inst *ins)
	{
		switch (ins->GetOpcode()) {
#define OP(name, cls, flags)                                                                                 \
	case Op::_##name:                                                                                    \
		return static_cast<Derived *>(this)->visit_##name(static_cast<cls *>(ins));
			QIR_OPS_LIST(OP)
#undef OP
		default:
			unreachable("");
		};
	}
};

} // namespace dbt::qir
