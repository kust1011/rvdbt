#include "dbt/qmc/ngr.h"
#include "dbt/config.h"
#include <cstdio>
#include <cstring>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// NGR — Normalized Gen-code Reuse. See ngr.h. Relocations (host-byte offsets of the immediate fields) are
// discovered from the SECOND structurally-identical block of a fingerprint (a real variant with different
// immediates) by diffing its host code against the first (template) block — no guest-byte mutation needed.
// Third and later blocks are served by copy+patch. A re-translate byte-compare (--ngr-verify) guards
// correctness; any mismatch falls back to the real translation.
namespace dbt::ngr
{

// Gen-code pages: pages the guest mmap'd writable+executable (a JIT's code buffer). NGR's address
// relocations (R_ADDR, loop/branch targets) are only enabled inside gen-code — in read-only .text the
// `delta==ip_delta` heuristic has false positives (verified on lua/wasm3). Tracked from linux_mmap2.
static std::unordered_set<u32> g_gencode_pages;
void MarkGenCode(u32 addr, u32 len)
{
	for (u32 p = addr & ~0xfffu; p != 0 && p < addr + len; p += 0x1000)
		g_gencode_pages.insert(p >> 12);
}
static inline bool IsGenCode(u32 addr) { return g_gencode_pages.count(addr >> 12) != 0; }

enum RelocKind : u8 { R_IMM, R_ADDR }; // immediate field, or block-address-relative target (branch/dispatch)
struct Reloc {
	u32 host_off;
	u8 width;
	u8 kind;
	u8 word_idx; // for R_IMM: which guest word's immediate patches here
};
struct Template {
	std::vector<u8> bytes;       // first block's host code (the template)
	std::vector<u32> masked;     // collision guard
	std::vector<u8> imm_words;   // guest word indices carrying a relocatable immediate
	std::vector<i32> first_imms; // first block's immediate values (delta matching)
	std::vector<Reloc> relocs;
	u32 template_ip = 0;     // first block's guest ip (R_ADDR adjustment base)
	bool discovered = false; // relocations found (from 2nd block)
	bool poisoned = false;   // diff failed -> never reuse (always translate)
	bool has_addr = false;   // has an R_ADDR (heuristic) reloc -> self-verify the first K reuses
	u32 reuse_verified = 0;  // #reuses byte-verified so far (R_ADDR templates trust after K)
	u32 num_insns = 0;
};
static constexpr u32 kAddrVerifyK = 3; // self-verify K independent reuses of an R_ADDR template, then trust
static std::unordered_map<u64, Template> g_templates;
static u64 g_diag_gencode_blocks = 0; // diag: #JIT misses on gen-code pages (W+X)

static bool Classify(uptr vmem, u32 ip, u32 boundary, std::vector<u32> &masked, std::vector<u8> &imm_words)
{
	if (boundary <= ip)
		return false;
	u32 maxn = (boundary - ip) / 4; // upper bound is the page end; the real block ends at a terminator
	if (maxn == 0)
		return false;
	masked.clear();
	imm_words.clear();
	bool terminated = false;
	for (u32 i = 0; i < maxn && i < 64; i++) {
		u32 w = *(u32 const *)(vmem + ip + (uptr)i * 4);
		u32 op = w & 0x7f;
		u32 f3 = (w >> 12) & 7;
		u32 mw = w;
		bool term = false;
		switch (op) {
		case 0x13: // OP-IMM
			if (f3 == 1 || f3 == 5) { /* shift: shamt structural */
			} else {
				// Mask the immediate VALUE but KEEP its host-encoding-width class (imm8 vs imm32):
				// QCG emits a different x86 instruction form per width, so blocks must only group if
				// their immediates share the same width class (else copy+patch hits a size/form mismatch,
				// verified on antlr4 sz=104/120). bit20 = "fits signed imm8".
				{
					i32 iv = ((i32)w >> 20);
					mw = (w & 0x000fffffu) | ((iv >= -128 && iv <= 127) ? 0x00100000u : 0);
				}
				imm_words.push_back((u8)i);
			}
			break;
		case 0x03: // LOAD — displacement width class (disp8 vs disp32) likewise affects host encoding
			{
				i32 iv = ((i32)w >> 20);
				mw = (w & 0x000fffffu) | ((iv >= -128 && iv <= 127) ? 0x00100000u : 0);
			}
			imm_words.push_back((u8)i);
			break;
		case 0x33: // R-type — structural
			break;
		case 0x23: // STORE — structural (verbatim): the offset/regs are baked identically across
			   // structurally-identical blocks (e.g. a JIT prologue's stack saves sw reg,off(sp));
			   // a differing store offset/reg just changes the fingerprint -> no false grouping. The
			   // data stored is a runtime register, not in the instruction. (A store embeds the guest
			   // pc for fault recovery like a load -> handled by the R_ADDR path under --ngr-loops.)
			break;
		case 0x67: // JALR
			if (((w >> 7) & 0x1f) != 0) // rd != x0: a CALL — the host code embeds the RETURN ADDRESS
				return false;       // (block-end guest ip, block-specific) -> byte-diff unsound, bail
			term = true; // jalr x0 (ret / pure indirect jump): no return address -> RELOCATION-FREE -> sound
			break;
		case 0x63: // BRANCH
		case 0x6f: // JAL — DIRECT target embeds a host relocation (the successor address). The immediate
			   // byte-diff cannot distinguish it from an immediate (false positives, verified on
			   // antlr4). Sound NGR is JALR-terminated only; allow these only under research --ngr-loops.
			if (!config::ngr_loops)
				return false;
			term = true;
			break;
		default: // LUI/AUIPC/STORE/SYSTEM/FENCE/CSR/AMO/... -> bail
			return false;
		}
		masked.push_back(mw);
		if (term) {
			terminated = true;
			break;
		}
	}
	return terminated && !imm_words.empty();
}

static u64 Hash(std::vector<u32> const &w)
{
	u64 h = 1469598103934665603ull;
	for (u32 x : w) {
		h ^= x;
		h *= 1099511628211ull;
	}
	h ^= w.size();
	h *= 1099511628211ull;
	return h;
}

static inline i32 Iimm(u32 w) { return (i32)w >> 20; }

static inline i64 ReadLE(u8 const *p, u8 width)
{
	u64 v = 0;
	for (u8 b = 0; b < width; b++)
		v |= (u64)p[b] << (8 * b);
	if (width < 8 && (v & (1ull << (8 * width - 1))))
		v |= ~((1ull << (8 * width)) - 1);
	return (i64)v;
}

void *CompileOrReuse(qir::CompilerJob &job, u32 ip, u32 boundary)
{
	uptr vmem = job.vmem;
	// Scope to GEN-CODE (guest writable+executable pages = a JIT's code buffer). NGR's copy+patch
	// assumes structurally-identical blocks compile to identical host code modulo immediates; that holds
	// for isolated runtime-generated functions (the target use case) but NOT for general static .text,
	// where QCG register allocation varies between structurally-identical blocks (verified: antlr4 emits a
	// REX-prefixed extended-register form for one block, sz 104 vs 120). Static .text -> plain translate.
	if (!IsGenCode(ip)) {
		config::g_ngr_translate++;
		return qir::CompilerDoJob(job);
	}
	g_diag_gencode_blocks++; // diag: this block is in a gen-code page (W+X mmap)
	std::vector<u32> masked;
	std::vector<u8> imm_words;
	if (!Classify(vmem, ip, boundary, masked, imm_words)) {
		config::g_ngr_translate++;
		return qir::CompilerDoJob(job);
	}
	u64 fp = Hash(masked);
	auto it = g_templates.find(fp);

	// current block's immediate values (in imm_words order)
	std::vector<i32> cur_imms(imm_words.size());
	for (size_t k = 0; k < imm_words.size(); k++)
		cur_imms[k] = Iimm(*(u32 const *)(vmem + ip + (uptr)imm_words[k] * 4));

	if (it == g_templates.end()) {
		// FIRST block of this fingerprint: translate + cache as the template (no relocations yet).
		config::g_ngr_translate++;
		std::span<u8> h1 = qir::CompilerGetCode(job);
		void *tb = job.cruntime->AnnounceRegion(ip, h1, (u32)masked.size());
		Template t;
		t.bytes.assign(h1.begin(), h1.end());
		t.masked = masked;
		t.imm_words = imm_words;
		t.first_imms = cur_imms;
		t.template_ip = ip;
		t.num_insns = (u32)masked.size();
		g_templates.emplace(fp, std::move(t));
		return tb;
	}
	Template &t = it->second;
	if (t.masked != masked || t.poisoned) {
		config::g_ngr_translate++;
		return qir::CompilerDoJob(job);
	}

	if (!t.discovered) {
		// SECOND block: translate it + diff vs the template to discover immediate relocations.
		config::g_ngr_translate++;
		std::span<u8> h2 = qir::CompilerGetCode(job);
		void *tb = job.cruntime->AnnounceRegion(ip, h2, (u32)masked.size());
		if (h2.size() == t.bytes.size()) {
			std::vector<Reloc> relocs;
			std::vector<bool> used(imm_words.size(), false);
			bool ok = true;
			u32 n = (u32)h2.size();
			for (u32 s = 0; s < n && ok;) {
				if (t.bytes[s] == h2[s]) {
					s++;
					continue;
				}
				u32 e = s;
				while (e < n && t.bytes[e] != h2[e])
					e++;
				u8 width = (u8)(e - s);
				if (width > 4) {
					ok = false;
					break;
				}
				i64 hd = ReadLE(&h2[s], width) - ReadLE(&t.bytes[s], width);
				// (a) an immediate whose (cur - first) delta matches the host delta
				int found = -1;
				for (size_t k = 0; k < imm_words.size(); k++) {
					if (!used[k] && (i64)(cur_imms[k] - t.first_imms[k]) == hd) {
						found = (int)k;
						break;
					}
				}
				if (found >= 0) {
					used[found] = true;
					relocs.push_back({s, width, R_IMM, t.imm_words[found]});
					s = e;
				} else if (config::ngr_loops && IsGenCode(ip) && s + 4 <= n &&
					   ((u64)hd & ((1ull << (8 * width)) - 1)) ==
						   ((u64)(i64)(i32)(ip - t.template_ip) & ((1ull << (8 * width)) - 1)) &&
					   IsGenCode((u32)ReadLE(&t.bytes[s], 4))) {
					// A diff run may capture only the low byte(s) of a 4-byte gen-code address (the guest
					// pc embedded for a load's fault recovery, or a branch target); compare the address
					// delta MASKED to the run width (unsigned) so width-1/2 partials still match ip_delta.
					// GUEST-IP-relative target (loop back-edge / dispatch) INSIDE gen-code: the full
					// value is a 4-byte LE guest ip that is itself a gen-code address, differing by
					// exactly the block-ip delta. Both gen-code gates rule out the .text false
					// positives (delta==ip_delta coinciding with a non-target immediate). Record a
					// 4-byte R_ADDR + consume 4 bytes; patched per block by re-adjusting the guest ip.
					relocs.push_back({s, 4, R_ADDR, 0});
					s = s + 4;
				} else {
					// non-immediate, non-gen-code-address diff -> not reusable (straight-line scope).
					ok = false;
					break;
				}
			}
			if (ok && !relocs.empty()) {
				for (Reloc const &r : relocs)
					if (r.kind == R_ADDR)
						t.has_addr = true;
				t.relocs = std::move(relocs);
				t.discovered = true;
			} else {
				t.poisoned = true;
			}
		} else {
			t.poisoned = true;
		}
		return tb;
	}

	// THIRD+ block: copy the template + patch the immediate bytes (no re-translation).
	// Fits-check first: a guest immediate whose host encoding width differs from the template's reloc
	// width (e.g. an imm32-magnitude value where the template baked an imm8) cannot be patched in place
	// -> fall back to full translation (keeps NGR correct WITHOUT --ngr-verify).
	for (Reloc const &r : t.relocs) {
		if (r.kind != R_IMM)
			continue;
		i32 imm = Iimm(*(u32 const *)(vmem + ip + (uptr)r.word_idx * 4));
		if (r.width < 4) {
			i32 lo = -(i32)(1u << (8 * r.width - 1));
			i32 hi = (i32)(1u << (8 * r.width - 1)) - 1;
			if (imm < lo || imm > hi) {
				config::g_ngr_translate++;
				return qir::CompilerDoJob(job);
			}
		}
	}
	void *dst = job.cruntime->AllocateCode(t.bytes.size(), 8);
	std::memcpy(dst, t.bytes.data(), t.bytes.size());
	for (Reloc const &r : t.relocs) {
		u32 v;
		if (r.kind == R_IMM) {
			v = (u32)Iimm(*(u32 const *)(vmem + ip + (uptr)r.word_idx * 4));
		} else { // R_ADDR: template's baked target + (this block ip - template ip)
			v = (u32)ReadLE(&t.bytes[r.host_off], 4) + (ip - t.template_ip);
		}
		for (u8 b = 0; b < r.width; b++)
			((u8 *)dst)[r.host_off + b] = (u8)(v >> (8 * b));
	}
	// Always re-translate + byte-compare when --ngr-verify, OR (by default) for the first K reuses of an
	// R_ADDR template — its heuristic relocation positions get validated on K independent blocks, then
	// trusted. R_IMM-only templates (sound) skip this. A mismatch poisons the template (positions suspect).
	if (config::ngr_verify || (t.has_addr && t.reuse_verified < kAddrVerifyK)) {
		std::span<u8> real = qir::CompilerGetCode(job);
		if (real.size() != t.bytes.size() || std::memcmp(real.data(), dst, real.size()) != 0) {
			config::g_ngr_verify_fail++;
			if (t.has_addr)
				t.poisoned = true; // R_ADDR positions wrong -> stop reusing this fingerprint
			return job.cruntime->AnnounceRegion(ip, real, t.num_insns);
		}
		if (t.has_addr)
			t.reuse_verified++;
	}
	config::g_ngr_reuse++;
	return job.cruntime->AnnounceRegion(ip, {(u8 *)dst, t.bytes.size()}, t.num_insns);
}

void PrintStats()
{
	fprintf(stderr, "NGR reuse=%llu translate=%llu verify_fail=%llu templates=%zu gencode_blocks=%llu\n",
		(unsigned long long)config::g_ngr_reuse, (unsigned long long)config::g_ngr_translate,
		(unsigned long long)config::g_ngr_verify_fail, g_templates.size(),
		(unsigned long long)g_diag_gencode_blocks);
}

} // namespace dbt::ngr
