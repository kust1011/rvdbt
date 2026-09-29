#!/usr/bin/env python3
"""VLEN-propagation source audit -- focused test for the in-run builder contract.

Enumerates EVERY production subprocess spawn under dbt/, classifies each as an
elfaot EXECUTION (direct), a HANDOFF of the elfaot path to a script, or neither,
then requires every elfaot execution reachable from a running elfrun -- C++ site
or script site -- to carry the parent's active `--vlen`.

The contract covers 10 sites: 9 elfaot executions (3 direct in C++, 6 inside
sr_builder.sh) plus 1 script handoff.  The handoff is not itself an elfaot
execution; it is the reason six of them exist, and it must carry the VLEN onward.
The third direct site is T5d2a's loop-tier builder, added 2026-08-31; it names the
compiler through a caller-supplied `loop_tier_elfaot` (so the focused test can put
/bin/echo there and read the real argv) and is gated exactly like the other two.

It does not grep for "elfaot".  It resolves each spawn primitive's argument
identifiers back to their construction and follows one hop, so a builder added
later is found by construction rather than by being remembered -- which is the
failure this test exists to prevent (X4f and X4f-fix1 each missed one).

Source-only: reads files, builds nothing, runs nothing.  Exit 0 = PASS.
Usage: scripts/vlen_propagation_audit.py [<repo-root>] [--census]
"""
import os, re, sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
CENSUS = "--census" in sys.argv
DBT = os.path.join(ROOT, "dbt")

# ============================ frozen inventory ============================
# Updated only by a human who has re-run the census.  Any drift trips G3.
SPAWN_PRIMS = ("system(", "execv(", "execvp(", "execve(", "execl(", "posix_spawn(", "popen(")
ELFAOT_PTRS = ("p1_elfaot", "escalate_elfaot", "loop_tier_elfaot")  # the ONLY ways to name elfaot
FROZEN_SPAWNS = {                                 # file -> total production spawn primitives
    "dbt/aot/aot_boot.cpp": 5,                    # P1 build, sr_builder, .prof cp, escalation execv, publish mv
    "dbt/aot/aot_file.cpp": 1,                    # the linker -- not elfaot
    "dbt/aot/loop_tier.cpp": 1,                   # T5d2a: the loop tier's builder execv, and only that
}
FROZEN_DIRECT = 3      # C++ sites that exec elfaot themselves
FROZEN_INDIRECT = 1    # C++ sites that hand the elfaot path to a script
FROZEN_SCRIPTS = {     # script -> (elfaot shell var, expected execution count)
    "experiments/2026-06-28-0840-spare-core-gate-pass/scripts/sr_builder.sh": ("EA", 6),
}
# Production source names the builder script through this macro, defined by the build from
# ${PROJECT_SOURCE_DIR} so a checkout is self-contained.  G6 resolves and checks it.
SCRIPT_PATH_MACRO = "DBT_SR_BUILDER_SH"
SCRIPT_PATH_CMAKE = "dbt/CMakeLists.txt"
IDENTITY_SYMS = ("AOT_SYM_ABI", "AOT_SYM_VLEN")   # artifact-identity symbols; see G5
# S3.7: the RVV direct-route contract.  Every option here must reach EVERY reachable elfaot
# invocation, carrying the parent's live value -- including its OFF value, so a child's routes are
# a function of the parent's configuration and not of elfaot's defaults.  Each entry is
# (elfaot option spelling, dbt::config field).  Updated only together with kRvvRouteContract in
# the production source; G8 fails if the two drift.
ROUTE_FLAGS = (
    # T5f: the ONE Substrate row. Its kind is frozen here too, so a row silently re-labelled
    # Route (which would make the loop tier inherit the parent again -- the T5e artifact) is a
    # G8 failure and not merely a behaviour change no audit can see.
    ("rvv-vector-ssa", "rvv_vector_ssa", "Substrate"),
    ("rvv-qcg-direct-setvl", "rvv_qcg_direct_setvl", "Route"),
    ("rvv-qcg-typed-chunk-vle", "rvv_qcg_typed_chunk_vle", "Route"),
    ("rvv-qcg-typed-chunk-vse", "rvv_qcg_typed_chunk_vse", "Route"),
    ("rvv-qcg-typed-chunk-sub", "rvv_qcg_typed_chunk_sub", "Route"),   # T1c
    ("rvv-qcg-typed-chunk-mul", "rvv_qcg_typed_chunk_mul", "Route"),   # T1b
    ("rvv-qcg-typed-chunk-xor", "rvv_qcg_typed_chunk_xor", "Route"),   # T1d
    ("rvv-qcg-typed-chunk-or", "rvv_qcg_typed_chunk_or", "Route"),     # T1e
    ("rvv-qcg-typed-chunk-and", "rvv_qcg_typed_chunk_and", "Route"),   # T1f
    ("rvv-qcg-vx-mulacc", "rvv_qcg_vx_mulacc", "Route"),       # Native-3: vmul.vx / vmacc.vx
    ("rvv-vector-run", "rvv_vector_run", "Route"),
    ("rvv-qcg-partial-vl", "rvv_qcg_partial_vl", "Route"),
    ("rvv-qcg-typed-chunk-falu", "rvv_qcg_typed_chunk_falu", "Route"),
    ("rvv-qcg-typed-chunk-fma", "rvv_qcg_typed_chunk_fma", "Route"),
    # W5F: vfsqrt.v. Its gate reads this switch ALONE (no umbrella fallback), so an elfaot without
    # the option is an unreachable route, not a route with a different default -- the T1c failure.
    # The audit-only ...-fsqrt-force-emit bypasses the host AVX-512F/BMI2 check and is deliberately
    # NOT a contract row; G8x below asserts that absence so it cannot be added by habit.
    ("rvv-qcg-typed-chunk-fsqrt", "rvv_qcg_typed_chunk_fsqrt", "Route"),
    ("rvv-qcg-typed-chunk-fredosum", "rvv_qcg_typed_chunk_fredosum", "Route"),  # W6
    ("rvv-qcg-typed-chunk-wholemove", "rvv_qcg_typed_chunk_wholemove", "Route"),  # W7
    ("rvv-llvm-setvl-reg", "rvv_llvm_setvl_reg", "Route"),  # C2a
    ("rvv-llvm-scalar-move", "rvv_llvm_scalar_move", "Route"),  # C2b
    ("rvv-llvm-partial-vl", "rvv_llvm_partial_vl", "Route"),  # C5
    ("rvv-llvm-shift", "rvv_llvm_shift", "Route"),  # C3
    ("rvv-llvm-extend", "rvv_llvm_extend", "Route"),  # C3
    ("rvv-llvm-fclass", "rvv_llvm_fclass", "Route"),  # C4: vfclass.v, integer body, no FP bracket
    ("rvv-llvm-fcvt-itof", "rvv_llvm_fcvt_itof", "Route"),  # C4: same-width int->float
    ("rvv-llvm-fcvt-ftoi", "rvv_llvm_fcvt_ftoi", "Route"),  # C4: same-width rtz float->int
    ("rvv-llvm-fcvt-fwiden", "rvv_llvm_fcvt_fwiden", "Route"),  # C4: vfwcvt.f.f
    ("rvv-llvm-fcvt-fnarrow", "rvv_llvm_fcvt_fnarrow", "Route"),  # C4: vfncvt.f.f
    ("rvv-llvm-fcvt-itof-widen", "rvv_llvm_fcvt_itof_widen", "Route"),  # C4: vfwcvt.f.x{,u}
    ("rvv-llvm-fcvt-ftoi-widen", "rvv_llvm_fcvt_ftoi_widen", "Route"),  # C4: vfwcvt.{x,xu,rtz}.f
    ("rvv-llvm-fcvt-partial-vl", "rvv_llvm_fcvt_partial_vl", "Route"),  # order item 3: conversion partial VL
    ("rvv-llvm-masked", "rvv_llvm_masked", "Route"),  # order item 3: architectural mask, masked OPIVV ALU
    ("rvv-llvm-fp-masked", "rvv_llvm_fp_masked", "Route"),  # order item 3: FP predication, masked vfalu family
    ("rvv-llvm-restart", "rvv_llvm_restart", "Route"),  # order item 3: nonzero vstart, masked integer ALU
    ("rvv-llvm-fcvt-rod", "rvv_llvm_fcvt_rod", "Route"),  # order item 4: round-to-odd narrowing
    ("rvv-llvm-festimate", "rvv_llvm_festimate", "Route"),  # order item 4: vfrsqrt7 / vfrec7
    ("rvv-llvm-fmerge", "rvv_llvm_fmerge", "Route"),  # order item 4: vfmerge.vfm / vfmv.v.f
    ("rvv-llvm-fwiden", "rvv_llvm_fwiden", "Route"),  # order item 4: widening FP arithmetic
    ("rvv-llvm-satadd", "rvv_llvm_satadd", "Route"),  # order item 4: saturating integer add/sub
    ("rvv-llvm-adc", "rvv_llvm_adc", "Route"),  # order item 4: carry/borrow
    ("rvv-llvm-avg", "rvv_llvm_avg", "Route"),  # order item 4: fixed-point averaging
    ("rvv-llvm-smul", "rvv_llvm_smul", "Route"),  # order item 4: fractional multiply
    ("rvv-llvm-nclip", "rvv_llvm_nclip", "Route"),  # order item 4: narrowing clip
    ("rvv-llvm-ired", "rvv_llvm_ired", "Route"),  # C6: integer reductions
    ("rvv-llvm-mlogic", "rvv_llvm_mlogic", "Route"),  # C6: mask logical operations
    ("rvv-llvm-vid", "rvv_llvm_vid", "Route"),  # C6: vid.v
    ("rvv-llvm-mscalar", "rvv_llvm_mscalar", "Route"),  # C6: vcpop.m / vfirst.m
    ("rvv-llvm-mprefix", "rvv_llvm_mprefix", "Route"),  # C6: vmsbf/vmsif/vmsof
    ("rvv-llvm-viota", "rvv_llvm_viota", "Route"),  # C6: viota.m
    ("rvv-llvm-vcompress", "rvv_llvm_vcompress", "Route"),  # C6: vcompress.vm
    ("rvv-llvm-vrgather", "rvv_llvm_vrgather", "Route"),  # C6: vrgather
    ("rvv-llvm-vslide", "rvv_llvm_vslide", "Route"),  # C6: vslideup/down, vslide1up/down
    ("rvv-llvm-vstrided", "rvv_llvm_vstrided", "Route"),  # C7: vlse / vsse
    ("rvv-llvm-vindexed", "rvv_llvm_vindexed", "Route"),  # C7: vluxei/vloxei/vsuxei
    ("rvv-llvm-fixed-masked", "rvv_llvm_fixed_masked", "Route"),
    ("rvv-llvm-fp-cvt-masked", "rvv_llvm_fp_cvt_masked", "Route"),
    ("rvv-llvm-fp-dynamic-frm", "rvv_llvm_fp_dynamic_frm", "Route"),
    ("rvv-llvm-fwiden-partial-vl", "rvv_llvm_fwiden_partial_vl", "Route"),
    ("rvv-llvm-fwiden-masked", "rvv_llvm_fwiden_masked", "Route"),
    ("rvv-llvm-widen", "rvv_llvm_widen", "Route"),  # C3
    ("rvv-llvm-narrow", "rvv_llvm_narrow", "Route"),  # C3
    ("rvv-llvm-fp-partial-vl", "rvv_llvm_fp_partial_vl", "Route"),  # C5-FP
    ("rvv-qcg-typed-chunk-mem-e64", "rvv_qcg_typed_chunk_mem_e64", "Route"),
    # Diagnostic, not a route -- see the matching comment on kRvvRouteContract. It rides the same
    # mechanism so that a background-built artifact can report whether its typed frames were
    # entered, which is what lets S3.7 check the contract from the CHILD instead of inferring it
    # from the parent's flags.
    ("rvv-vector-ssa-counters", "rvv_vector_ssa_counters", "Diagnostic"),
    # T3b: second diagnostic, same reasoning -- it is what lets a mid-run-promoted artifact report
    # that it was ENTERED rather than merely loaded.  See kRvvRouteContract.
    ("aot-region-hit-count", "aot_region_hit_count", "Diagnostic"),
    # T5c-0: third diagnostic. Added to kRvvRouteContract then and NOT mirrored here, so G8 has been
    # failing on this row alone since; caught while adding the Native-3 row above and repaired in the
    # same edit, because a red audit cannot serve as evidence that the Native-3 row is right.
    ("aot-loop-entry", "aot_loop_entry", "Diagnostic"),
)
ROUTE_TABLE_FILE = "dbt/aot/aot_boot.cpp"   # the ONE place the contract is declared
ROUTE_TABLE_SYM = "kRvvRouteContract"
ROUTE_RENDERERS = ("RvvRouteArgsJoined", "RvvRouteArgv")  # joined-string and argv-slot forms
SCRIPT_ROUTE_VAR = "RVV"                    # the script parameter the rendered contract arrives in
# =========================================================================

fails, notes, census = [], [], []
def fail(g, m): fails.append("%s: %s" % (g, m))

def read(p):
    with open(os.path.join(ROOT, p), encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()

def cxx_files():
    out = []
    for d, _, fs in os.walk(DBT):
        if "third_party" in d: continue
        for f in sorted(fs):
            if f.endswith((".cpp", ".h")) and not f.endswith("_test.cpp"):
                out.append(os.path.relpath(os.path.join(d, f), ROOT))
    return sorted(out)

def is_code(ln):
    s = ln.strip()
    return s and not s.startswith(("//", "*", "/*"))

def block_before(lines, idx, back=40):
    return "\n".join(lines[max(0, idx - back):idx + 1])

# ---------------------------------------------------------------- G6
# The builder script must be named through a build-time macro that resolves to a
# file INSIDE this checkout.  A hardcoded absolute path (the pre-X4g1 state) let a
# branch edit its own script and change nothing about what actually ran.
script_macro_value = None
cm = os.path.join(ROOT, SCRIPT_PATH_CMAKE)
if not os.path.exists(cm):
    fail("G6", "%s not found; cannot resolve %s" % (SCRIPT_PATH_CMAKE, SCRIPT_PATH_MACRO))
else:
    m = re.search(r'%s="([^"]+)"' % re.escape(SCRIPT_PATH_MACRO), open(cm, encoding="utf-8").read())
    if not m:
        fail("G6", "%s is not defined in %s" % (SCRIPT_PATH_MACRO, SCRIPT_PATH_CMAKE))
    else:
        raw = m.group(1)
        rel = raw.replace("${PROJECT_SOURCE_DIR}/", "").replace("${CMAKE_SOURCE_DIR}/", "")
        if raw == rel and os.path.isabs(raw):
            fail("G6", "%s is a hardcoded absolute path (%s); it must be anchored to "
                       "${PROJECT_SOURCE_DIR} so the checkout is self-contained" % (SCRIPT_PATH_MACRO, raw))
        elif not os.path.exists(os.path.join(ROOT, rel)):
            fail("G6", "%s resolves to %s, which does not exist in this checkout" % (SCRIPT_PATH_MACRO, rel))
        else:
            script_macro_value = rel
            notes.append("G6 script path OK: %s -> %s (in-tree)" % (SCRIPT_PATH_MACRO, rel))

# ---------------------------------------------------------------- G8
# The route contract must exist as ONE table in ONE file, list exactly the frozen options, map each
# to the matching config field, and expose both renderers.  This is what makes "add a row" the only
# way to add a route flag; without it every spawn site would drift independently again.
rt_src = "\n".join(read(ROUTE_TABLE_FILE)) if os.path.exists(os.path.join(ROOT, ROUTE_TABLE_FILE)) else ""
if not rt_src:
    fail("G8", "%s not found; cannot resolve the route contract" % ROUTE_TABLE_FILE)
else:
    tm = re.search(r'%s\[\]\s*=\s*\{(.*?)\};' % re.escape(ROUTE_TABLE_SYM), rt_src, re.S)
    if not tm:
        fail("G8", "%s is not declared in %s" % (ROUTE_TABLE_SYM, ROUTE_TABLE_FILE))
    else:
        rows = re.findall(r'\{\s*"([^"]+)"\s*,\s*&config::(\w+)\s*,\s*RvvRouteKind::(\w+)\s*\}',
                          tm.group(1))
        if rows != list(ROUTE_FLAGS):
            fail("G8", "%s rows %s != frozen contract %s" % (ROUTE_TABLE_SYM, rows, list(ROUTE_FLAGS)))
        else:
            notes.append("G8 route contract OK: %d flags, one table in %s"
                         % (len(rows), ROUTE_TABLE_FILE))
        for r in ROUTE_RENDERERS:
            if not re.search(r'\b%s\s*\(' % re.escape(r), rt_src):
                fail("G8", "renderer %s is missing from %s" % (r, ROUTE_TABLE_FILE))
        # Each config field must be a real declared option, or the contract forwards a name the
        # child cannot parse and every builder silently fails its argument check.
        cfg = "\n".join(read("dbt/config.h"))
        for opt, field, _kind in ROUTE_FLAGS:
            if not re.search(r'\binline bool %s\b' % re.escape(field), cfg):
                fail("G8", "config::%s (for --%s) is not declared in dbt/config.h" % (field, opt))

        # ------------------------------------------------------------------ G8b
        # W5F: THE CONTRACT IS THREE PLACES, NOT ONE, AND G8 ONLY CHECKED TWO OF THEM.
        #
        # A row here renders `--flag=0/1` into every background builder's argv, and G8 above proves
        # the config field exists. Neither proves `elfaot` can PARSE the option or that parsing it
        # reaches the config field. W5F's vfsqrt.v had the lowering, the gate and passing IR tests,
        # and elfaot registered no option: the flag was false in every freshly exec'd elfaot, so the
        # route was unreachable from any artifact -- the identical failure the T1c comment in
        # kRvvRouteContract records for vsub.vv, one route family later. Worse than a wrong default:
        # RvvLLVMSqrtChunkAdmit reads that switch ALONE, so no other flag could turn it back on.
        #
        # So: every Route/Diagnostic row must be a REGISTERED elfaot option AND be assigned from
        # `opts` to `config` there. Substrate rows are excluded -- the child's value comes from the
        # spawning site's RvvChildSubstrate, not from the parent's (T5f/G9).
        aot_src = "\n".join(read("dbt/elfaot.cpp"))
        n_fails_before = len(fails)
        for opt, field, kind in ROUTE_FLAGS:
            if kind == "Substrate":
                continue
            if not re.search(r'\(\s*"%s"\s*,\s*bpo::' % re.escape(opt), aot_src):
                fail("G8b", "--%s is a contract row but elfaot.cpp registers no such option; "
                            "boost::program_options would reject the rendered argv" % opt)
            if not re.search(r'config::%s\s*=\s*opts\.%s\s*;' % (re.escape(field), re.escape(field)),
                             aot_src):
                fail("G8b", "elfaot.cpp never assigns config::%s from opts.%s, so --%s parses and "
                            "then does nothing" % (field, field, opt))
        # The note is a CLAIM, so it is withheld when the loop above failed: a green line printed
        # next to a red one is how a reader concludes the gate passed.
        if len(fails) == n_fails_before:
            notes.append("G8b elfaot wiring OK: every non-substrate row is registered and assigned")

        # ------------------------------------------------------------------ G8x
        # AUDIT-ONLY HOST-FEATURE BYPASSES ARE NEVER CONTRACT ROWS. `*-force-emit` switches skip the
        # host AVX-512F/BMI2 admission check, so the emitted code SIGILLs on a host without those
        # features. A parent may set one for itself; handing it to a background builder would make a
        # machine-invalid artifact on the parent's behalf, silently.
        n_fails_before = len(fails)
        for opt, field, _kind in ROUTE_FLAGS:
            if opt.endswith("-force-emit") or field.endswith("_force_emit"):
                fail("G8x", "--%s is an audit-only host-feature bypass and must not be forwarded "
                            "to background builders" % opt)
        if re.search(r'"[a-z0-9-]*-force-emit"', tm.group(1)):
            fail("G8x", "a *-force-emit option appears in %s" % ROUTE_TABLE_SYM)
        if re.search(r'\(\s*"[a-z0-9-]*-force-emit"\s*,\s*bpo::', aot_src):
            fail("G8x", "elfaot registers a *-force-emit option; the bypass belongs to elfrun's "
                        "audit surface only")
        if len(fails) == n_fails_before:
            notes.append("G8x no audit-only force-emit bypass is forwarded to builders")

# ---------------------------------------------------------------- G9
# T5f: THE BACKEND-AWARE SUBSTRATE, AND THE FACT THAT EXACTLY ONE SITE DECLARES IT.
#
# T5e measured what the shared boolean cost: the loop tier's parent must run at --rvv-vector-ssa=0
# (looptier::Arm() refuses `side_exit_needs_committed_vector_state`), inheritance carried that 0 to
# its elfaot child, and the child -- for which the same spelling means the LLVM typed-vector
# SUBSTRATE rather than a QCG residency policy -- compiled the hot loop into four helper calls per
# iteration.  This gate states the shape of the repair so it cannot silently regress:
#
#   G9a  exactly one row is Substrate, and it is --rvv-vector-ssa.
#   G9b  both renderers take an RvvChildSubstrate and resolve rows through ONE function, so the
#        joined and argv forms cannot disagree about a row's value.
#   G9c  every renderer call passes the parameter explicitly -- no default argument, because a
#        default is exactly how a new spawn site would inherit the T5e failure without saying so.
#   G9d  LlvmPrerequisite is declared at exactly ONE site, and that site is the loop tier's
#        SpawnBuilder.  The P1 and escalation builders keep InheritParent on purpose: their parents
#        are free to carry the substrate themselves, so nothing there is unsatisfiable, and T5f is
#        not licensed to change builders it did not measure.
#   G9e  no spawn site hand-writes a --rvv-vector-ssa literal into an argv or command string.  That
#        is the duplicate-option shape -- render the table, then append the option again and lean on
#        the child's parser taking the last value -- and it is forbidden: one option, one value.
#        Scoped to the files that BUILD a child's arguments (the ones containing a renderer call):
#        elfrun.cpp and elfaot.cpp mention the option by name in their own --help prose, which is
#        documentation of the option, not a second copy of it in somebody's argv.
SUBSTRATE_OPT = "rvv-vector-ssa"
SUBSTRATE_ENUM = "RvvChildSubstrate"
SUBSTRATE_SITE = "dbt/aot/loop_tier.cpp"   # the ONE site that may declare LlvmPrerequisite
if rt_src:
    subs = [o for o, _f, k in ROUTE_FLAGS if k == "Substrate"]
    if subs != [SUBSTRATE_OPT]:
        fail("G9a", "substrate rows %s != [%s]; the LLVM lowering prerequisite is exactly one row"
                    % (subs, SUBSTRATE_OPT))
    # G9b: one resolver, called by both renderers, and no renderer reading *row.value directly.
    if not re.search(r'\bstatic\s+bool\s+RvvRouteRenderedValue\s*\(', rt_src):
        fail("G9b", "RvvRouteRenderedValue is missing from %s; the two renderers would each decide "
                    "a row's value and could drift" % ROUTE_TABLE_FILE)
    for r in ROUTE_RENDERERS:
        m = re.search(r'\b%s\s*\([^)]*\)\s*\{(.*?)\n\}' % re.escape(r), rt_src, re.S)
        if not m:
            fail("G9b", "cannot read the body of renderer %s" % r)
            continue
        if "RvvRouteRenderedValue" not in m.group(1):
            fail("G9b", "renderer %s does not resolve rows through RvvRouteRenderedValue" % r)
        if re.search(r'\*\s*kRvvRouteContract\[\w+\]\.value', m.group(1)):
            fail("G9b", "renderer %s still reads a row's parent value directly, bypassing the "
                        "substrate resolution" % r)
    # G9c: no default argument on either renderer's substrate parameter.
    for r in ROUTE_RENDERERS:
        if re.search(r'\b%s\s*\([^)]*%s\s+\w+\s*=' % (re.escape(r), re.escape(SUBSTRATE_ENUM)),
                     rt_src, re.S):
            fail("G9c", "renderer %s gives its %s parameter a default; a new spawn site must state "
                        "which it is" % (r, SUBSTRATE_ENUM))
    hdr = "\n".join(read("dbt/aot/aot.h")) if os.path.exists(os.path.join(ROOT, "dbt/aot/aot.h")) else ""
    if not re.search(r'enum class\s+%s\b' % re.escape(SUBSTRATE_ENUM), hdr):
        fail("G9c", "%s is not declared in dbt/aot/aot.h; an out-of-file spawn site could not name "
                    "its choice" % SUBSTRATE_ENUM)

# G9c/G9d/G9e sweep every production translation unit.
_llvm_sites, _bare_ssa = [], []
for p in cxx_files():
    lines = read(p)
    src = "\n".join(lines)
    # A file BUILDS a child's arguments iff it renders the contract. Only those are subject to G9e.
    builds_argv = any(re.search(r'\b%s\s*\(' % re.escape(r), src) for r in ROUTE_RENDERERS)
    for i, ln in enumerate(lines, 1):
        if not is_code(ln):
            continue
        # Every renderer call states its substrate.
        for r in ROUTE_RENDERERS:
            if re.search(r'\b%s\s*\(' % re.escape(r), ln) and "size_t %s" % r not in ln \
               and not re.search(r'\b(static\s+)?(char const \*|size_t)\s+%s\s*\(' % re.escape(r), ln):
                call = "\n".join(lines[i - 1:i + 4])
                if SUBSTRATE_ENUM not in call:
                    fail("G9c", "%s:%d calls %s without declaring an %s"
                                % (p, i, r, SUBSTRATE_ENUM))
                elif "%s::LlvmPrerequisite" % SUBSTRATE_ENUM in call:
                    _llvm_sites.append("%s:%d" % (p, i))
        # No hand-written substrate literal anywhere a child's arguments are built.
        if builds_argv and re.search(r'"(?:[^"]* )?--%s[=" ]' % re.escape(SUBSTRATE_OPT), ln):
            _bare_ssa.append("%s:%d" % (p, i))
if len(_llvm_sites) != 1:
    fail("G9d", "%s::LlvmPrerequisite is declared at %d sites (%s); exactly one -- the loop tier's "
                "SpawnBuilder -- may declare it"
                % (SUBSTRATE_ENUM, len(_llvm_sites), ", ".join(_llvm_sites) or "none"))
elif not _llvm_sites[0].startswith(SUBSTRATE_SITE + ":"):
    fail("G9d", "%s::LlvmPrerequisite is declared at %s, not in %s"
                % (SUBSTRATE_ENUM, _llvm_sites[0], SUBSTRATE_SITE))
else:
    notes.append("G9 substrate contract OK: 1 Substrate row (--%s), one resolver, "
                 "LlvmPrerequisite at %s only" % (SUBSTRATE_OPT, _llvm_sites[0]))
if _bare_ssa:
    fail("G9e", "a --%s literal is written by hand at %s; the row is rendered from the contract, "
                "and appending it again would emit the option twice"
                % (SUBSTRATE_OPT, ", ".join(_bare_ssa)))

# ---------------------------------------------------------------- G0
# The elfaot binary must be nameable ONLY through the frozen config pointers.
# A hardcoded path would be an invocation route this scanner cannot resolve.
for p in cxx_files():
    for i, ln in enumerate(read(p), 1):
        if not is_code(ln): continue
        for lit in re.findall(r'"((?:[^"\\]|\\.)*)"', ln):
            path_lit = re.fullmatch(r'(.*/)?elfaot', lit) or \
                       re.search(r'(^|[;&|]\s*|[\w.-]/)([\w./-]*/)?elfaot\s+--', lit)
            if path_lit:
                fail("G0", "%s:%d hardcodes an elfaot binary path: %s" % (p, i, lit[:70]))

# ---------------------------------------------------------------- resolve
def spawn_command_text(lines, i):
    """Resolve what a spawn primitive at line i actually executes: take the
    call's argument identifiers, find each one's nearest preceding construction
    (snprintf(id, / id[] = {), and follow one further hop (argv[] -> cmd)."""
    call = "\n".join(lines[i:i + 3])
    args = call[call.index("("):] if "(" in call else call
    text = [args]
    NOT_VALUES = {"nullptr", "environ", "sizeof", "char", "const", "int", "unsigned", "size_t",
                  "static_cast", "const_cast", "reinterpret_cast", "void", "data", "push_back",
                  "true", "false", "if", "for", "return"}
    todo = [t for t in re.findall(r'\b[A-Za-z_]\w*\b', args) if t not in NOT_VALUES]
    seen = set()

    def statement_at(k):
        stmt = []
        while k < len(lines):
            stmt.append(lines[k])
            if lines[k].rstrip().endswith(";"):
                break
            k += 1
        return "\n".join(stmt)

    # Four construction shapes are recognised. The last two are S3.7's: a value can now be built by
    # a CALL that fills it (the route renderers) and an argv can be accumulated by REPEATED pushes
    # rather than declared as one initialiser list. A shape the resolver cannot see would make the
    # gates below pass vacuously, which is worse than failing, so `execv`/`push_back` sites that
    # resolve to nothing are reported by G2b rather than skipped.
    renderers_alt = "|".join(re.escape(r) for r in ROUTE_RENDERERS)
    for _ in range(3):                       # bounded: argv_sp -> cmd -> renderer output
        nxt = []
        for ident in todo:
            if ident in seen: continue
            seen.add(ident)
            pats = (r'\bsnprintf\s*\(\s*%s\s*,' % re.escape(ident),
                    r'\b%s\s*\[\]\s*=' % re.escape(ident),
                    r'\b(?:%s)\s*\([^;]*\b%s\b' % (renderers_alt, re.escape(ident)),
                    r'\b%s\s*\.\s*push_back\s*\(' % re.escape(ident))
            hits = []
            for j in range(i, max(0, i - 120), -1):
                l = lines[j]
                if any(re.search(pat, l) for pat in pats):
                    hits.append(statement_at(j))
            # push_back accumulates: keep every hit. The other shapes define once: nearest wins,
            # and `hits` is built backwards so that is hits[0].
            keep = list(reversed(hits)) if any(".push_back" in h for h in hits) else hits[:1]
            for blob in keep:
                text.append(blob)
                # The keyword filter applies to HARVESTED identifiers too, not just the initial
                # set. `sizeof` appears in every `Renderer(buf, sizeof buf)` call, so leaving it in
                # made the renderer reachable from any site whose resolution passed through a
                # `sizeof` -- i.e. from almost anywhere, which silently defeated G7.
                nxt += [t for t in re.findall(r'\b[A-Za-z_]\w*\b', blob) if t not in NOT_VALUES]
        todo = nxt
    return "\n".join(text)

# ---------------------------------------------------------------- G1/G2/G3
# Enumerate every spawn primitive; classify; gate the elfaot ones.
n_spawn, n_direct, n_indirect, scripts_seen = {}, 0, 0, set()
for p in cxx_files():
    lines = read(p)
    for i, ln in enumerate(lines):
        if not is_code(ln) or not any(k in ln for k in SPAWN_PRIMS): continue
        if re.search(r'^\s*(//|\*)', ln): continue
        n_spawn[p] = n_spawn.get(p, 0) + 1
        ctx = spawn_command_text(lines, i)            # what this spawn actually executes
        names_elfaot = any(x in ctx for x in ELFAOT_PTRS)
        sh = None
        m_lit = re.search(r'"([^"]*\.sh)"', ctx)
        if m_lit:
            sh = m_lit.group(1)
            fail("G6", "%s:%d names a builder script by string literal (%s); it must go through %s "
                       "so the path follows the checkout" % (p, i + 1, sh, SCRIPT_PATH_MACRO))
        elif SCRIPT_PATH_MACRO in ctx:
            sh = script_macro_value
        if sh:
            scripts_seen.add(os.path.relpath(sh, os.path.abspath(ROOT))
                             if os.path.isabs(sh) else sh)
        if not names_elfaot:
            census.append("%s:%d  spawn  NOT-elfaot  (%s)" % (p, i + 1, ln.strip()[:52]))
            continue
        if sh:
            n_indirect += 1
            census.append("%s:%d  spawn  HANDOFF -> %s" % (p, i + 1, os.path.basename(sh)))
            # the handoff itself must carry the VLEN onward to the script
            if "--vlen" not in ctx and not re.search(r'vlen', ctx):
                fail("G1", "%s:%d hands the elfaot path to %s with NO VLEN argument"
                     % (p, i + 1, os.path.basename(sh)))
            # G7 (S3.7): ... and the whole rendered route contract with it.  The check is that the
            # site uses a RENDERER, not that it mentions the five option strings: a site that
            # spelled the flags out by hand would pass a literal check today and silently miss the
            # next entry added, which is the entire failure mode this file exists to prevent.
            if not any(r in ctx for r in ROUTE_RENDERERS):
                fail("G7", "%s:%d hands VLEN to %s but not the rendered route contract "
                           "(expected one of %s)"
                     % (p, i + 1, os.path.basename(sh), ", ".join(ROUTE_RENDERERS)))
            for opt, _, _k in ROUTE_FLAGS:
                if "--%s=" % opt in ctx:
                    fail("G7", "%s:%d spells --%s out by hand; route flags must come from the "
                               "renderer so a new one cannot be forgotten here"
                         % (p, i + 1, opt))
            continue
        n_direct += 1
        census.append("%s:%d  spawn  DIRECT elfaot" % (p, i + 1))
        if "--vlen" not in ctx:
            fail("G1", "%s:%d direct elfaot execution built with NO --vlen" % (p, i + 1))
        elif "vlen_bits" not in ctx:
            fail("G2", "%s:%d --vlen present but not fed from config::vlen_bits" % (p, i + 1))
        # G7 (C5.2a, generalised by S3.7): --vlen says WHICH width to specialize for; it does not
        # permit any typed RVV lowering. Every route option defaults false in a fresh process, so a
        # builder that forwards --vlen but not the route contract produces a VLEN-qualified artifact
        # that is nonetheless helper-lowered. They must travel together, and they must travel
        # through the renderer for the reason given at the handoff above.
        if not any(r in ctx for r in ROUTE_RENDERERS):
            fail("G7", "%s:%d direct elfaot execution carries no rendered route contract "
                       "(expected one of %s)" % (p, i + 1, ", ".join(ROUTE_RENDERERS)))
        for opt, _, _k in ROUTE_FLAGS:
            if "--%s=" % opt in ctx:
                fail("G7", "%s:%d spells --%s out by hand instead of using the renderer"
                     % (p, i + 1, opt))
        # G2b: in a NULL-terminated argv[] the VLEN element must precede any
        # conditional nullptr slot, or it is silently dropped whenever that
        # condition is false.  The element may be an identifier built by an
        # earlier snprintf, so resolve carriers by name as well as by literal.
        # Two shapes are recognised, and an unrecognised one is a FAILURE rather than a skip: a
        # silently-skipped order gate is how an unconditional argument ends up after the optional
        # slot without anyone noticing.
        am = re.search(r'char const \*\w+\[\] = \{(.*?)\};', ctx, re.S)
        raw = "\n".join(lines[max(0, i - 60):i + 1])
        pushes = re.findall(r'(?:^[ \t]*if \(([^)]*)\)[ \t]*\n)?^[ \t]*(\w+)\.push_back\(([^;]*)\);',
                            raw, re.M)
        if am:
            carriers = set(re.findall(r'snprintf\s*\(\s*(\w+)\s*,[^;]*?"--vlen', ctx, re.S))
            elems = [e.strip() for e in re.split(r',(?![^(]*\))', am.group(1))]
            vi = next((k for k, e in enumerate(elems)
                       if "--vlen" in e or e in carriers), None)
            ni = next((k for k, e in enumerate(elems) if "nullptr" in e), None)
            if vi is None:
                fail("G1", "%s:%d argv[] carries no --vlen element" % (p, i + 1))
            elif ni is not None and ni < vi:
                fail("G2b", "%s:%d the --vlen element sits after a conditional nullptr "
                            "slot in argv[] (dropped when that condition is false)" % (p, i + 1))
        elif pushes:
            # S3.7 vector form. Emission order is textual push order. Every UNCONDITIONAL argument
            # -- the VLEN carrier and every route-contract slot -- must be pushed before the first
            # CONDITIONAL push and before the terminating nullptr.
            order = [(cond, arg) for cond, _, arg in pushes]
            carriers = set(re.findall(r'snprintf\s*\(\s*(\w+)\s*,[^;]*?"--vlen', ctx, re.S))
            vi = next((k for k, (_, a) in enumerate(order)
                       if "--vlen" in a or a.strip() in carriers), None)
            ci = next((k for k, (c, _) in enumerate(order) if c), None)
            ni = next((k for k, (_, a) in enumerate(order) if "nullptr" in a), None)
            ri = [k for k, (_, a) in enumerate(order) if "rvvargv" in a or "rvvslots" in a]
            if vi is None:
                fail("G1", "%s:%d argv vector carries no --vlen push" % (p, i + 1))
            if not ri:
                fail("G7", "%s:%d argv vector carries no route-contract push" % (p, i + 1))
            for k in ([vi] if vi is not None else []) + ri:
                if ci is not None and ci < k:
                    fail("G2b", "%s:%d an unconditional argv push (index %d) sits after the "
                                "conditional push at index %d" % (p, i + 1, k, ci))
                if ni is not None and ni < k:
                    fail("G2b", "%s:%d an unconditional argv push (index %d) sits after the "
                                "nullptr terminator" % (p, i + 1, k))
        elif "execv" in ctx:
            fail("G2b", "%s:%d builds an execv argv in a shape this scanner does not recognise; "
                        "the argument-order gate would be silently skipped" % (p, i + 1))

# ---------------------------------------------------------------- G9
# Command-building snprintf arity. A site can call a renderer and then drop the `%s` that consumes
# it -- every "does this site use the mechanism" check still passes while the rendered contract
# reaches nothing. Counting conversion specifiers against varargs catches that mechanically, and it
# is the same class of defect as G4's script arity one level down.
def _split_args(argtext):
    out, depth, cur = [], 0, ""
    for ch in argtext:
        if ch in "([{": depth += 1
        elif ch in ")]}": depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip(): out.append(cur.strip())
    return out

for p in cxx_files():
    lines = read(p)
    for i, ln in enumerate(lines):
        if "snprintf" not in ln or not is_code(ln): continue
        stmt = []
        k = i
        while k < len(lines) and k < i + 25:
            stmt.append(lines[k])
            if lines[k].rstrip().endswith(";"): break
            k += 1
        blob = "\n".join(stmt)
        if not any(x in blob for x in ELFAOT_PTRS) and "DBT_SR_BUILDER_SH" not in blob:
            continue
        m = re.search(r'snprintf\s*\((.*)\)\s*;\s*$', blob, re.S)
        if not m: continue
        parts = _split_args(m.group(1))
        if len(parts) < 3: continue
        fmt = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', "\n".join(parts[2:])))
        n_spec = len(re.findall(r'%[-#0-9.+ ]*(?:hh|h|ll|l|z|j|t|L)?[diouxXeEfgGaAcsp]', fmt))
        # varargs = everything after the format string's own argument
        fmt_arg_end = 2
        while fmt_arg_end < len(parts) and parts[fmt_arg_end].lstrip().startswith('"'):
            fmt_arg_end += 1
        n_va = len(parts) - fmt_arg_end
        if n_spec != n_va:
            fail("G9", "%s:%d builder command has %d conversion specifiers but %d varargs "
                       "(a rendered argument reaches nothing)" % (p, i + 1, n_spec, n_va))

for p, want in FROZEN_SPAWNS.items():
    if n_spawn.get(p, 0) != want:
        fail("G3", "%s has %d spawn primitives, inventory says %d" % (p, n_spawn.get(p, 0), want))
for p in n_spawn:
    if p not in FROZEN_SPAWNS:
        fail("G3", "%s spawns a subprocess and is not in the inventory (%d sites)" % (p, n_spawn[p]))
if n_direct != FROZEN_DIRECT:
    fail("G3", "%d direct elfaot spawn sites, inventory says %d" % (n_direct, FROZEN_DIRECT))
if n_indirect != FROZEN_INDIRECT:
    fail("G3", "%d indirect (script) elfaot sites, inventory says %d" % (n_indirect, FROZEN_INDIRECT))
if scripts_seen != set(FROZEN_SCRIPTS):
    fail("G3", "scripts spawned by production source %s != inventory %s"
         % (sorted(scripts_seen), sorted(FROZEN_SCRIPTS)))

# ---------------------------------------------------------------- G1s/G2s/G3s
# Every elfaot invocation inside a spawned script must carry --vlen, fed from
# the script's own positional VLEN parameter (never a literal, never a default).
for script, (var, want_n) in FROZEN_SCRIPTS.items():
    lines = read(script)
    hdr_i = next((j for j, l in enumerate(lines[:60]) if re.search(r'\b%s=\$\d' % var, l)), None)
    hdr = lines[hdr_i] if hdr_i is not None else ""
    vlen_var = next((m.group(1) for m in re.finditer(r'\b([A-Z_]+)=\$(\d+)', hdr)
                     if m.group(1) == "VLEN"), None)
    route_var = next((m.group(1) for m in re.finditer(r'\b([A-Z_]+)=\$(\d+)', hdr)
                      if m.group(1) == SCRIPT_ROUTE_VAR), None)
    if not route_var:
        fail("G7s", "%s header does not bind the rendered route contract to a positional "
                    "parameter named %s" % (script, SCRIPT_ROUTE_VAR))
    n = 0
    for i, ln in enumerate(lines, 1):
        if not re.search(r'"\$%s"' % var, ln): continue
        n += 1
        cmd, j = ln, i - 1
        while cmd.rstrip().endswith("\\") and j + 1 < len(lines):     # line continuation
            j += 1; cmd += lines[j]
        census.append("%s:%d  elfaot execution" % (script, i))
        if "--vlen" not in cmd:
            fail("G1s", "%s:%d elfaot execution with NO --vlen" % (script, i))
        elif not vlen_var or ("$%s" % vlen_var) not in cmd:
            fail("G2s", "%s:%d --vlen not fed from the script's positional VLEN parameter" % (script, i))
        # G7s (S3.7): same pairing rule inside the script, against the rendered contract. The
        # splice must be UNQUOTED so it word-splits into separate options; `"$RVV"` would arrive
        # as one unparseable argument and elfaot would reject it, so the quoted form is a failure.
        if not route_var or ("$%s" % route_var) not in cmd:
            fail("G7s", "%s:%d elfaot execution does not splice the rendered route contract ($%s)"
                 % (script, i, SCRIPT_ROUTE_VAR))
        elif '"$%s"' % route_var in cmd:
            fail("G7s", "%s:%d splices \"$%s\" quoted; it must word-split into separate options"
                 % (script, i, route_var))
        for opt, _, _k in ROUTE_FLAGS:
            if "--%s=" % opt in cmd:
                fail("G7s", "%s:%d spells --%s out by hand instead of splicing $%s"
                     % (script, i, opt, SCRIPT_ROUTE_VAR))
    if n != want_n:
        fail("G3", "%s has %d elfaot executions, inventory says %d" % (script, n, want_n))

# ---------------------------------------------------------------- G4
# Spawn arity: the C++ caller must pass exactly as many positional arguments as
# the script header consumes.  This is the gate that catches "script updated,
# caller not" -- the fix1-class miss one level down.
for script in FROZEN_SCRIPTS:
    hdr = next((l for l in read(script)[:60] if re.search(r'=\$\d', l)), "")
    want = max((int(x) for x in re.findall(r'=\$(\d+)', hdr)), default=0)
    got = None
    for p in cxx_files():
        lines = read(p)
        for i, ln in enumerate(lines):
            if os.path.basename(script) not in ln and SCRIPT_PATH_MACRO not in ln: continue
            ctx = block_before(lines, i, 8) + "\n" + "\n".join(lines[i:i + 8])
            fm = re.search(r'"(taskset[^"]*)"', ctx)
            if not fm: continue
            after = fm.group(1)[fm.group(1).index("bash"):]
            got = len(re.findall(r'%[-0-9.]*(?:hh|h|ll|l|z|j|t|L)?[diouxXeEfgGaAcspn]', after)) - 1
    if got is None:
        fail("G4", "no spawn of %s found under dbt/" % os.path.basename(script))
    elif got != want:
        fail("G4", "%s consumes $1..$%d but the spawn passes %d positional args"
             % (os.path.basename(script), want, got))
    else:
        notes.append("G4 arity OK: %s consumes $1..$%d, spawn passes %d"
                     % (os.path.basename(script), want, got))

# ---------------------------------------------------------------- G5
# Identity-symbol producer parity: a producer that embeds one artifact-identity
# symbol must embed all of them, or the load gate changes meaning for the lagging
# producer.  Emission = a symbol-table add, not a dlsym lookup or a declaration.
emit = {s: set() for s in IDENTITY_SYMS}
for p in cxx_files():
    lines = read(p)
    for i, ln in enumerate(lines):
        if not is_code(ln) or "static constexpr" in ln: continue
        for s_ in IDENTITY_SYMS:
            if s_ not in ln: continue
            win = "\n".join(l for l in lines[max(0, i - 6):i + 3]
                             if not l.strip().startswith(("//", "*")))
            if "dlsym" in ln: continue          # a lookup, not an emission
            if "add_symbol" in win or "GlobalVariable" in win:
                emit[s_].add(p)

# Parity is required only once a symbol is DECLARED anywhere in the tree.  The VLEN
# symbol is a later checkpoint (embedded identity / load gate); until it is declared
# this gate is armed but dormant, so it cannot pass vacuously later: the moment the
# symbol appears, every AOT_SYM_ABI producer must emit it too.
declared = {sym for sym in IDENTITY_SYMS
            if any(sym in ln for p in cxx_files() for ln in read(p))}
base = emit[IDENTITY_SYMS[0]]
for sym in IDENTITY_SYMS[1:]:
    if sym not in declared:
        notes.append("G5 dormant: %s is not declared yet (embedded-identity checkpoint not started)" % sym)
        continue
    if emit[sym] != base:
        fail("G5", "producers emitting %s %s != producers emitting %s %s"
             % (IDENTITY_SYMS[0], sorted(base), sym, sorted(emit[sym])))

# ---------------------------------------------------------------- report
print("VLEN-propagation source audit   root=%s" % os.path.abspath(ROOT))
n_script = sum(w for _, w in FROZEN_SCRIPTS.values())
print("  spawn primitives: %d | elfaot executions: %d (%d direct + %d in script) | handoffs: %d"
      % (sum(n_spawn.values()), n_direct + n_script, n_direct, n_script, n_indirect))
print("  propagation contract sites: %d executions + %d handoff = %d"
      % (n_direct + n_script, n_indirect, n_direct + n_script + n_indirect))
for n in notes: print("  note: " + n)
if CENSUS:
    print("  -- census --")
    for c in census: print("    " + c)
if fails:
    print("  FAIL (%d)" % len(fails))
    for f in fails: print("    " + f)
    sys.exit(1)
print("  PASS")
