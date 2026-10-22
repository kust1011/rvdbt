#!/bin/bash
# Cycle-2 builder: SET-DIFFERENCE deltas + MASS-DOUBLING batches + MASS-MAJORITY stop + KEEP-stop.
# Args: elfaot elf stagecache runcache T0 ONE VLEN RVV
# VLEN (X4g1) is the parent elfrun's ACTIVE config::vlen_bits, forwarded to every elfaot
# call below: dbt::config is per-process, so an unqualified child compiles/analyses at the
# elfaot default 128 whatever VLEN the guest is really running at. The caller's argument
# count (aot_boot.cpp) and the $7 here are one contract -- change either alone and $VLEN
# expands empty into `--vlen=` at sites whose output is redirected to /dev/null.
# RVV (C5.2a, widened by S3.7) is the parent's WHOLE rendered direct-route contract -- one
# pre-formatted string of `--flag=0/1` tokens, produced by kRvvRouteContract in dbt/aot/aot_boot.cpp
# and spliced verbatim into every elfaot call below. --vlen alone only says WHICH width to
# specialize for; it does not permit any typed RVV lowering. Every one of those options defaults
# false in a freshly exec'd elfaot, so without forwarding them the rung artifacts are helper-lowered
# regardless of the VLEN they are qualified for.
#   It is ONE argument on purpose. When it was a single SSA boolean ($8), adding a route flag meant
# editing this script and the caller together and getting all six call sites below right; now a new
# flag is a row in that C++ table and this script does not change at all. Caller arity stays 8, so
# the one-contract rule above is unchanged.
#   $RVV IS DELIBERATELY UNQUOTED at each elfaot call: it must word-split into separate arguments.
# The renderer emits only `--flag=0/1` tokens, so there is nothing in it that word-splitting can
# corrupt, and it can carry no quote of its own.
# Zero constants: batch fires when pending delta mass >= built mass (doubling in the value domain);
# terminal stop when built mass holds the MAJORITY of observed mass (never compiles the cold tail);
# parent writes $STG/want (1=insufficient evidence persists, 0=KEEP) -- builder idles on 0.
EA=$1; ELF=$2; STG=$3; RUN=$4; T=$5; ONE=$6; VLEN=$7; RVV=$8
PARENT0=$PPID
cd "$STG" || exit 1
start=$(date +%s%3N); spent=0; k=0; : > built.txt; built_mass=0
: > gric_admitted.txt  # GRIC (2026-07-22, B-line): per-source WATCH/COMMIT state, live within THIS run
while :; do
  [ "$(awk '{print $4}' /proc/$$/stat)" != "$PARENT0" ] && exit 0  # orphan self-check (numeric, /proc)
  if [ -f "$STG/want" ] && [ "$(cat "$STG/want")" = "0" ]; then sleep 0.4; continue; fi
  # GRIC live commit (opt-in SRB_GRIC=1): reads $STG/edges.txt, which --sr-live-edges-dump=1 now
  # refreshes DURING this same live run (not just at process exit) -- this loop iteration IS the
  # WATCH/COMMIT step of a genuine same-runtime-lifecycle closed loop, not a separate offline pass.
  # Per-source majority+doubling commit rule (same discipline as the rest of this file: doubling
  # evidence, majority-sign test, zero new constants). ADDITIVE ONLY this cycle (commits new correct
  # targets on new evidence; does not attempt live un-admission of an already-booted target -- see
  # GRIC_LIVE_2026-07-22.md for why removal is a separate, harder problem not solved this cycle).
  if [ "${SRB_GRIC:-}" = "1" ] && [ -s "$STG/edges.txt" ]; then
    python3 - "$STG/edges.txt" "$STG/gric_state.json" "$STG/gric_admitted.txt" "$STG/decomp.log" "$k" "$STG/revoke_request" <<'PYS'
import sys, json, os, time
edges_path, state_path, admitted_path, log_path, kk, revoke_path = sys.argv[1:7]
observe_only = os.environ.get("SRB_GRIC_OBSERVE_ONLY") == "1"  # B1: compute+log decisions, never touch the admit action
no_recommit = os.environ.get("SRB_GRIC_NO_RECOMMIT") == "1"    # B2: first commit is permanent, evidence-contradiction ignored
do_revoke = os.environ.get("SRB_GRIC_REVOKE") == "1"           # B3: RECOMMIT also requests a real in-run revoke of the old target
majority_thresh = float(os.environ.get("SRB_GRIC_MAJORITY", "0.5"))  # ablation (2026-07-22): default reuses this
double_k = float(os.environ.get("SRB_GRIC_DOUBLE_K", "2"))           # project's existing majority/doubling convention
src_t = {}
with open(edges_path) as f:
    for line in f:
        p = line.split()
        if len(p) != 3: continue
        src, dst, cnt = p[0], p[1], int(p[2])
        src_t.setdefault(src, {})[dst] = src_t.get(src, {}).get(dst, 0) + cnt
state = json.load(open(state_path)) if os.path.exists(state_path) else {}
newly = []
for src, tgts in src_t.items():
    total = sum(tgts.values())
    top_t, top_c = max(tgts.items(), key=lambda kv: kv[1])
    st = state.setdefault(src, {"state": "UNKNOWN", "committed_target": None, "last_evidence": 0})
    majority = top_c > total * majority_thresh
    doubled = total >= double_k * max(st["last_evidence"], 1)
    already = st.get("committed_target")
    if majority and doubled and already != top_t:
        is_recommit = already is not None
        if is_recommit and no_recommit:
            with open(log_path, "a") as lf:
                lf.write(f"{kk} GRIC RECOMMIT_SUPPRESSED src={src} old={already} new={top_t} "
                         f"share={top_c/total:.3f} total={total}\n")
            continue
        with open(log_path, "a") as lf:
            lf.write(f"{kk} GRIC {'RECOMMIT' if is_recommit else 'COMMIT'} src={src} "
                     f"old={already} new={top_t} share={top_c/total:.3f} total={total} t={time.time():.3f}\n")
        st["state"] = "COMMITTED"; st["committed_target"] = top_t; st["last_evidence"] = total
        if not observe_only:
            newly.append(top_t)
            if is_recommit and do_revoke:
                with open(revoke_path, "a") as rf:
                    rf.write(already + "\n")
                # RE-PROMOTION FIX (2026-07-22, found by real E2E on dist_cycle3 A->B->A: revoke-only
                # caused a 3.3x wall-time REGRESSION when the revoked target was revisited later --
                # RevokeTarget() correctly downgrades it to a fresh QCG recompile, but built.txt still
                # marked it "already built" forever, so the standard admission pipeline never rebuilds
                # it back to AOT even after it resumes accumulating hot exec-count evidence. Strip it
                # from built.txt so a future dry-run rung treats it as pending again if it goes hot.
                with open(admitted_path + ".revoked", "a") as vf:
                    vf.write(already + "\n")
                with open(log_path, "a") as lf:
                    lf.write(f"{kk} GRIC REVOKE_REQUEST target={already} t={time.time():.3f}\n")
json.dump(state, open(state_path, "w"))
if newly:
    with open(admitted_path, "a") as af:
        for t in newly:
            af.write(t + "\n")
PYS
    if [ -s "$STG/gric_admitted.txt.revoked" ]; then
      comm -23 <(sort -u built.txt) <(sort -u "$STG/gric_admitted.txt.revoked") > built.tmp3 && mv built.tmp3 built.txt
      cat "$STG/gric_admitted.txt.revoked" >> "$STG/gric_revoked_alltime.txt"
      : > "$STG/gric_admitted.txt.revoked"
    fi
  fi
  # DRY doubling gate: dry only when a channel's raw evidence (rip samples / prof pages) has DOUBLED
  # since the last dry (same discipline as BUILD/PROMOTE/DECIDE; zero constants)
  # REGIME-FLIP RESET (builder side): when the parent signals a census regime flip, our evidence
  # anchors (DRY doubling baselines) belong to the previous phase -- reset them so the new phase's
  # evidence is judged on its own scale (phase_keep raw: inherited anchors cost ~4.5s adaptation).
  rg_now=$(stat -c%s "$STG/regime" 2>/dev/null || echo 0)
  if [ "$rg_now" != "${rg_seen:-0}" ]; then
    rg_seen=$rg_now
    last_head=0; last_pages=0
    built_mass=0; built_smass=0
    echo "$(date +%s%3N) REGIME reset" >> "$STG/decomp.log"
  fi
  if [ -f "$STG/evid" ] && [ "${last_head:-0}" -gt 0 ]; then
    read cur_head cur_pages < "$STG/evid"
    if [ "${cur_head:-0}" -lt $((last_head * 2)) ] && [ "${cur_pages:-0}" -lt $((last_pages * 2)) ]; then
      # exponential backoff (reset on evidence change): idle iterations cost ~8 forks each; unchanged
      # evidence earns geometrically longer sleeps (cap = 8x keeper tick), same doubling discipline
      if [ "${cur_head:-0}" = "${bk_head:-x}" ]; then
        bk_ms=$(( ${bk_ms:-50} * 2 )); [ "$bk_ms" -gt 400 ] && bk_ms=400
      else
        bk_ms=50; bk_head="${cur_head:-0}"
      fi
      # PERMANENT-STALL ESCAPE (2026-07-18, C-line, root-caused via a >4900s-orphaned leela SPEC
      # candidate run: rip_head/pages evidence plateaus for workloads whose hot code, once compiled,
      # keeps re-executing WITHOUT touching new guest addresses -- game-tree search re-walks the same
      # already-linked functions -- so this doubling condition can go permanently unmet even though a
      # prior dry-run already saw substantial unbuilt pending mass (leela raw: k=3 pend_c=1,421,243,
      # built=0, then zero further decomp.log activity for the rest of a >1700s run). Bounded escape,
      # same liveness-timeout pattern as the wantprof handshake above (2000ms cap, already precedented
      # in this file): once this SAME stall (cur_head unchanged) has lasted 2000ms of consecutive
      # backoff, force one dry-run regardless of the doubling condition, then resume normal backoff.
      # Opt-in via SRB_STALL_ESCAPE=1 so it cannot alter any already-measured arm.
      if [ "${SRB_STALL_ESCAPE:-}" = "1" ]; then
        bk_accum=$(( ${bk_accum:-0} + bk_ms ))
        if [ "$bk_accum" -ge 2000 ]; then
          echo "$(date +%s%3N) $k STALL_ESCAPE forced dry after ${bk_accum}ms consecutive backoff at cur_head=${cur_head:-0}" >> "$STG/decomp.log"
          bk_accum=0
        else
          sleep "$(awk -v m="$bk_ms" "BEGIN{print m/1000}")"; continue
        fi
      else
        sleep "$(awk -v m="$bk_ms" "BEGIN{print m/1000}")"; continue
      fi
    fi
  fi
  [ -f "$STG/evid" ] && read last_head last_pages < "$STG/evid"
  last_head=${last_head:-1}; last_pages=${last_pages:-1}
  # demand-driven freshness handshake: request one profile update + dumps; parent honors on next tick
  # and unlinks the flag as ack. Timeout = liveness escape only (parent tick is 50ms; if the parent is
  # gone the orphan check exits us next iteration anyway).
  : > "$STG/wantprof"; wp0=$(date +%s%3N)
  while [ -f "$STG/wantprof" ] && [ $(( $(date +%s%3N) - wp0 )) -lt 2000 ]; do sleep 0.02; done
  cp "$RUN"/*.prof "$STG/" 2>/dev/null
  b0=$(date +%s%3N)
  "$EA" --elf="$ELF" --cache="$STG" --llvm=1 --vlen=$VLEN $RVV --threshold=$T --dump-applicability=1 --dump-regions=1 --dry-page-floor=1 2> "reg_$k" >/dev/null
  grep "DRYREGION" "reg_$k" | awk '/hot=1/{sub("ip=","",$2); sub("mx=","",$3); print $2, $3}' | sort > "admx_$k"
  # SAMPLE CHANNEL: resolve ring RIPs via tbmap -> guest ips covering the sample-mass MAJORITY (zero constants)
  if [ -s "$STG/ring.bin" ] && [ -s "$STG/tbmap.txt" ]; then
    python3 - "$STG/ring.bin" "$STG/tbmap.txt" > "sampx_$k" <<'PYS'
import sys, struct
ring = open(sys.argv[1], "rb").read()
rips = [x for x in struct.unpack(f"<{len(ring)//8}Q", ring) if x]
tb = []
for i, line in enumerate(open(sys.argv[2])):
    if i == 0: continue
    p = line.split()
    if len(p) >= 3:
        lo = int(p[1], 16); tb.append((lo, lo + int(p[2]), p[0]))
tb.sort()
import bisect
lows = [t[0] for t in tb]
from collections import Counter
c = Counter()
for r in rips:
    j = bisect.bisect_right(lows, r) - 1
    if j >= 0 and r < tb[j][1]:
        c[tb[j][2]] += 1
tot = sum(c.values())
acc = 0
for ip, n in c.most_common():
    print(ip, n)
    acc += n
    if acc * 2 >= tot: break
PYS
    sort "sampx_$k" -o "sampx_$k"
  else
    : > "sampx_$k"
  fi
  case "${SRB_CH:-dual}" in
    count)  awk '{print $1}' "admx_$k" | sort -u | comm -23 - built.txt > "new_$k" ;;
    sample) awk '{print $1}' "sampx_$k" | sort -u | comm -23 - built.txt > "new_$k" ;;
    *)      awk '{print $1}' "admx_$k" | sort -u - <(awk '{print $1}' "sampx_$k") | comm -23 - built.txt > "new_$k" ;;
  esac
  # per-channel pending mass (each channel doubles against ITS OWN built mass; monotone, resource-bounded)
  pend_c=$(awk 'NR==FNR{n[$1];next} ($1 in n){s+=$2} END{print s+0}' "new_$k" "admx_$k")
  pend_s=$(awk 'NR==FNR{n[$1];next} ($1 in n){s+=$2} END{print s+0}' "new_$k" "sampx_$k")
  tot_mass=$(awk '{s+=$2} END{print s+0}' "admx_$k")
  bytes=0; built_this=0
  # UNIFIED INVARIANT: build only when SOME channel's pending mass >= that channel's built mass (per-channel
  # doubling => builds per channel <= log(channel total); monotone; no cross-channel commensuration needed)
  gate=0
  [ "$built_mass" -eq 0 ] && [ -s "new_$k" ] && gate=1
  # FIRST-BUILD FIXED-COST AMORTIZATION v1 (2026-07-18, C-line, front 1) -- SUPERSEDED, kept default-off.
  # FALSIFIED this round (CLINE_FIRSTBUILD_AMORTIZATION_2026-07-18.md): deferring the tiny first build by
  # ONE rung moves WHICH rung pays the ~90-140ms LLVM fixed cost but does not reduce the total number of
  # elfaot invocations (nlp live test: swaps=2 either way, zero wall effect). Kept only as a reference
  # no-op (SRB_FIRSTBUILD_MIN2 is not set by the v2 mechanism below).
  if [ "${SRB_FIRSTBUILD_MIN2:-}" = "1" ] && [ "$built_mass" -eq 0 ] && [ "$gate" -eq 1 ]; then
    nnew_fb=$(wc -l < "new_$k" 2>/dev/null || echo 0)
    if [ "$nnew_fb" -eq 1 ] && [ "$T" -gt 512 ]; then
      gate=0
      echo "$(date +%s%3N) $k FIRSTBUILD_DEFER nnew=1 (waiting for batch>=2)" >> "$STG/decomp.log"
    fi
  fi
  # SAMPLE-MAJORITY BUILD GATE (reduce-C, ACTIVATION_BOUND lever): a batch whose regions -- together
  # with everything already built -- cover a MINORITY of resolved sample mass is premature; skip the
  # build and let the ladder descend (the tiny top-T rungs on diffuse workloads are pure activation
  # cost: seq1 syms=0 realized 0/N traces). Concentrated hot sets pass at T0 unchanged (switch/dispatch
  # seq1 covers the majority). Zero constants; skipped when samples resolve to nothing.
  if [ "$gate" -eq 1 ] && [ -s "sampx_$k" ]; then
    smtot=$(awk '{s+=$2} END{print s+0}' "sampx_$k")
    if [ "$smtot" -gt 0 ]; then
      smcov=$(cat built.txt "new_$k" 2>/dev/null | sort -u | awk 'NR==FNR{a[$1]=1;next} a[$1]{s+=$2} END{print s+0}' - "sampx_$k")
      if [ $((smcov * 2)) -lt "$smtot" ]; then
        gate=0
        cov_anchor=0
        echo "$(date +%s%3N) $k SMAJ skip cov=$smcov tot=$smtot" >> "$STG/decomp.log"
      else
        # STABILITY CONFIRMATION (NLP_CHURN raw: sub-second coarse sampling makes "majority of 15
        # samples" statistically empty -- the trio still built and paid C). Coverage-majority must HOLD
        # across a DOUBLING of sample evidence before the first build is allowed (verdict-stability
        # family). Sub-second runs never complete the doubling -> no build -> C_FLOOR (~0). Long runs
        # double promptly -> build proceeds one doubling later.
        if [ "${cov_anchor:-0}" -eq 0 ]; then
          cov_anchor=$smtot
          gate=0
          echo "$(date +%s%3N) $k SMAJ anchor tot=$smtot" >> "$STG/decomp.log"
        elif [ "$smtot" -lt $((cov_anchor * 2)) ]; then
          gate=0
          echo "$(date +%s%3N) $k SMAJ wait tot=$smtot anchor=$cov_anchor" >> "$STG/decomp.log"
        fi
      fi
    fi
  fi
  [ "$pend_c" -gt 0 ] && [ "$pend_c" -ge "$built_mass" ] && gate=1
  [ "$pend_s" -gt 0 ] && [ "$pend_s" -ge "${built_smass:-0}" ] && [ "${built_smass:-0}" -gt 0 ] && gate=1
  [ "$pend_s" -gt 0 ] && [ "${built_smass:-0}" -eq 0 ] && gate=1
  # BATCH VALUE GATE (all quantities online-measured THIS run, no constants): launching LLVM costs at least
  # fixed_ms (estimated by the dry-run's own invocation cost); a batch is worth launching only if its
  # estimated payload work (pending regions x measured per-region ms from the last real build) >= fixed_ms.
  # Micro-batches accumulate across wakes until they amount to one fixed-cost's worth of real work.
  if [ "$gate" -eq 1 ] && [ "${last_build_regions:-0}" -gt 0 ]; then
    nnew=$(wc -l < "new_$k")
    per_region_ms=$(( (last_build_ms - last_dry_ms) / last_build_regions ))
    [ "$per_region_ms" -lt 1 ] && per_region_ms=1
    price_bound="${last_dry_ms:-70}"
    # IDR (2026-07-22, A-line candidate, opt-in): discount the batch's compile-cost price bound by
    # the AGGREGATE share of this batch's mass sitting behind low-confidence indirect dispatch --
    # mass whose per-transfer L1-cache-check-or-slowpath tax compilation cannot remove (Node 6/7,
    # closed this campaign) is worth less per compiled byte than directly-reached mass, which DOES
    # amortize to zero once linked (TryLinkBranch). Zero new constants: the multiplier is a ratio in
    # [0,1] derived entirely from data BuildModuleGraph already computes (indirect_confidence,
    # default 1.0 -> multiplier 0 -> byte-identical to today whenever no edge evidence exists). Uses
    # a SEPARATE --aot-admit-mode=1 (A2, no floor) dry probe so this diagnostic-only computation
    # cannot reproduce the 2026-07-18 xerces 6x-inflation regression that came from feeding
    # unconditional-floor (mode=0/jserv-A) admission into the REAL build path (still correctly
    # avoided below, unchanged).
    if [ "${SRB_IDR:-}" = "1" ] && [ -s "$STG/edges.txt" ]; then
      "$EA" --elf="$ELF" --cache="$STG" --llvm=1 --vlen=$VLEN $RVV --threshold=$T --dump-applicability=1 --dump-regions=1 \
        --dry-page-floor=1 --aot-indirect-edges="$STG/edges.txt" --aot-admit-mode=1 2>"idr_reg_$k" >/dev/null
      read unpred_mass batch_mass <<EOF
$(awk 'NR==FNR{n[$1];next} $1=="DRYREGION" { ip=$2; sub("ip=","",ip); if(ip in n){ mx=$3; sub("mx=","",mx); ibt=$5; sub("ibt=","",ibt); ic=$6; sub("iconf=","",ic); bm+=mx; if(ibt==1){ um+=mx*(1-ic) } } } END{ printf "%d %d", um+0, bm+0 }' "new_$k" "idr_reg_$k")
EOF
      if [ "${batch_mass:-0}" -gt 0 ]; then
        # price_bound *= (1 + unpred_mass/batch_mass), integer arithmetic: bound*(batch+unpred)/batch
        price_bound=$(( price_bound * (batch_mass + unpred_mass) / batch_mass ))
        echo "$(date +%s%3N) $k IDR unpred_mass=$unpred_mass batch_mass=$batch_mass price_bound=$price_bound (base=${last_dry_ms:-70})" >> "$STG/decomp.log"
      fi
    fi
    if [ $((nnew * per_region_ms)) -lt "$price_bound" ]; then
      # compile-cheap batch: block ONLY if it is also executionally minor. A pending set holding the
      # MAJORITY of total observed mass is critical regardless of compile size (cheap != worthless;
      # the qsort starvation case). Same majority principle, no constants.
      if [ "$tot_mass" -gt 0 ] && [ $((pend_c * 2)) -lt "$tot_mass" ]; then gate=0; fi
    fi
  fi
  # CROSS-RUNG COALESCE v2 (2026-07-18, C-line prototype 2; MUST be the last gate modifier before the
  # build trigger -- every earlier gate stage, including the majority-mass overrides above, can force
  # gate=1 back on while built_mass=0, since "pend_c>=built_mass" is trivially true at 0). v1
  # (FIRSTBUILD_MIN2, above) was diagnostic: deferring the tiny first build by ONE rung moves WHICH rung
  # pays the ~90-140ms LLVM fixed cost but does not reduce the total INVOCATION COUNT (nlp live test:
  # swaps=2 either way, zero wall effect -- see CLINE_FIRSTBUILD_AMORTIZATION_2026-07-18.md). This
  # mechanism instead unconditionally SKIPS calling elfaot for the first SRB_COALESCE_N build
  # opportunities (built_mass/built.txt stay at their zero/empty state, so "new_$k" -- already a
  # set-difference against built.txt -- keeps growing for free across skipped rungs, no new bookkeeping
  # needed). The Nth opportunity (or the floor rung T<=512, whichever comes first) fires ONE real build
  # covering everything accumulated across all N skipped rungs, replacing N separate LLVM invocations
  # (each paying the fixed cost) with exactly one. Opt-in, assert-verified, independent of v1's flag.
  if [ -n "${SRB_COALESCE_N:-}" ] && [ "$built_mass" -eq 0 ] && [ "$gate" -eq 1 ]; then
    coal_skips=$(cat coalesce_skips 2>/dev/null || echo 0)
    # v3 MAJORITY ESCAPE HATCH (2026-07-18, same cycle): v2 was falsified LIVE on nlp -- unconditional
    # skip caused expat to NEVER escalate at all (its whole run fits inside the skip window), turning a
    # +37-46% regression into +50-59% (worse than doing nothing). Root cause: v2 disabled the EXISTING
    # majority-mass escape hatch (line ~148, "cheap != worthless") for the entire coalesce window. v3
    # restores it: only skip if this rung's pending mass is STILL a minority of total observed mass --
    # a batch that already IS the majority must build now regardless of the coalesce counter, exactly
    # the same principle the pre-existing BATCH VALUE GATE already uses elsewhere in this file.
    if [ "$coal_skips" -lt "$SRB_COALESCE_N" ] && [ "$T" -gt 512 ] && { [ "$tot_mass" -eq 0 ] || [ $((pend_c * 2)) -lt "$tot_mass" ]; }; then
      gate=0
      coal_skips=$((coal_skips + 1))
      echo "$coal_skips" > coalesce_skips
      echo "$(date +%s%3N) $k COALESCE_SKIP skips=$coal_skips/$SRB_COALESCE_N nnew_so_far=$(wc -l < "new_$k" 2>/dev/null||echo 0) pend_c=$pend_c tot_mass=$tot_mass" >> "$STG/decomp.log"
    else
      echo "$(date +%s%3N) $k COALESCE_FIRE skips=$coal_skips nnew_total=$(wc -l < "new_$k" 2>/dev/null||echo 0) pend_c=$pend_c tot_mass=$tot_mass" >> "$STG/decomp.log"
    fi
  fi
  # A-line lowering consumer v2 (arm SRB_SPEC): edge-triggered RESPECIALIZATION rung. Probe raw proved v1
  # structurally inert: ALL building lands in rung 0 within the first keeper tick, BEFORE the first edges
  # dump (probe: new_0 09:53:04 built=1 nnew=8; edges.txt 09:53:05; spec.log never created) -- later rungs
  # have no vehicle. v2: when sampled edge mass has DOUBLED since the last spec build (evidence-doubling,
  # first fire on any mass), rebuild {built regions} + majority-coverage top targets WITH specialization;
  # InsertOrReplace swaps the specialized bodies in. Cost lands in the same rusage accounting.
  RESPEC=0
  if [ -n "${SRB_SPEC:-}" ] && [ -s "$STG/edges.txt" ] && [ -s built.txt ]; then
    emass=$(awk '{s+=$3} END{print s+0}' "$STG/edges.txt")
    sanchor=$(cat spec_anchor 2>/dev/null || echo 0)
    if [ "$emass" -gt 0 ] && [ "$emass" -ge $((2*sanchor)) ]; then RESPEC=1; fi
  fi
  GRIC_FRESH=0
  if [ "${SRB_GRIC:-}" = "1" ] && [ -s "$STG/gric_admitted.txt" ]; then
    comm -23 <(sort -u "$STG/gric_admitted.txt") <(sort -u built.txt "new_$k" 2>/dev/null) > "gric_pending_$k"
    [ -s "gric_pending_$k" ] && GRIC_FRESH=1
  fi
  if { [ -s "new_$k" ] && [ "$gate" -eq 1 ]; } || [ "$RESPEC" -eq 1 ] || [ "$GRIC_FRESH" -eq 1 ]; then
    rm -f "$STG"/*.aot.so
    ADM="new_$k"; SPEC=""
    if [ "$GRIC_FRESH" -eq 1 ]; then
      sort -u "$STG/gric_admitted.txt" "new_$k" built.txt 2>/dev/null > "adm_gric_$k"; ADM="adm_gric_$k"
      echo "$(date +%s%3N) $k GRIC_FIRE pending=$(wc -l < "gric_pending_$k") admit_total=$(wc -l < "$ADM")" >> "$STG/decomp.log"
    fi
    if [ "$RESPEC" -eq 1 ]; then
      awk '{m[$2]+=$3} END{for(d in m) print m[d], d}' "$STG/edges.txt" | sort -rn > "dstm_$k"
      tmass=$(awk '{s+=$1} END{print s+0}' "dstm_$k")
      awk -v t="$tmass" 't>0{c+=$1; print $2; if (2*c>=t) exit}' "dstm_$k" > "topk_$k"
      K=$(wc -l < "topk_$k")
      sort -u built.txt "topk_$k" $( [ -s "new_$k" ] && echo "new_$k" ) > "adm_$k"; ADM="adm_$k"
      SPEC="--aot-edge-specialize=1 --aot-edge-topk=$K"
      echo "$k K=$K emass=$emass nadm=$(wc -l < "adm_$k")" >> "$STG/spec.log"
      echo "$emass" > spec_anchor
      if [ -n "${SRB_DVET:-}" ] && [ ! -f "$STG/trial_S.so" ] && [ "$K" -ge 2 ] && [ -f "$STG/dvet_ripe" ]; then
        # abstention gate (zero constants): majority coverage needing ONE target = monomorphic site;
        # direct-chaining already serves it -- a guard trial can only add noise (sha512 raw). Trial
        # requires a genuinely polymorphic majority set (K>=2).
        # DVET: build the instrumented PAIR (equal counters) and publish for the parent's epoch trial;
        # skip the normal respec swap this iteration (the trial decides WHETHER).
        "$EA" --elf="$ELF" --cache="$STG" --llvm=1 --vlen=$VLEN $RVV --threshold=999999999 --dispatch-admit-list="$STG/$ADM" --aot-work-counter=1 >/dev/null 2>&1
        so=$(ls "$STG"/*.aot.so 2>/dev/null | head -1)
        [ -n "$so" ] && mv "$so" "$STG/trial_P.so.tmp" && mv "$STG/trial_P.so.tmp" "$STG/trial_P.so"
        rm -f "$STG"/*.aot.so
        "$EA" --elf="$ELF" --cache="$STG" --llvm=1 --vlen=$VLEN $RVV --threshold=999999999 --dispatch-admit-list="$STG/$ADM" --aot-work-counter=1 $SPEC --aot-edge-profile="$STG/edges.txt" --aot-indirect-edges="$STG/edges.txt" >/dev/null 2>&1
        so=$(ls "$STG"/*.aot.so 2>/dev/null | head -1)
        [ -n "$so" ] && mv "$so" "$STG/trial_S.so.tmp" && mv "$STG/trial_S.so.tmp" "$STG/trial_S.so"
        echo "dvet pair published" >> "$STG/spec.log"
        continue
      fi
      if [ -f "$STG/dvet_wantS" ]; then
        # DVET winner realization: verdict S -> build the UNINSTRUMENTED specialized artifact and publish
        # it as this rung (normal landing path); the trial artifacts stay dormant.
        rm -f "$STG"/*.aot.so
        "$EA" --elf="$ELF" --cache="$STG" --llvm=1 --vlen=$VLEN $RVV --threshold=999999999 --dispatch-admit-list="$STG/$ADM" $SPEC --aot-edge-profile="$STG/edges.txt" --aot-indirect-edges="$STG/edges.txt" >/dev/null 2>&1
        rm -f "$STG/dvet_wantS"
        echo "dvet S realized" >> "$STG/spec.log"
      fi
    fi
    # CHEAP-FIRST-RUNG (2026-07-18, clean single-variable retest of the O0 lever; NO promotion queue this
    # time -- mechanisms #2/#3 from TIER_PROMOTION_BOUNDARY.md were compromised by a silent-surgery
    # failure and never cleanly retested; this variant is intentionally simpler: O0 for rung 0 ONLY, no
    # later O3 rebuild, so it isolates whether a cheaper first artifact alone moves the nlp trio residual
    # without reintroducing the promotion-queue bug surface).
    O0FIRST=""
    [ "${SRB_O0FIRST:-}" = "1" ] && [ "$built_mass" -eq 0 ] && O0FIRST="--aot-optlevel=0"
    "$EA" --elf="$ELF" --cache="$STG" --llvm=1 --vlen=$VLEN $RVV --threshold=999999999 --dispatch-admit-list="$STG/$ADM" $SPEC $O0FIRST >/dev/null 2>&1
    # (edges.txt consumers REMOVED from rung builds 2026-07-18: ind_in admission propagation was measured
    # NIL-value earlier and became actively HARMFUL once decimation gave edges content from the start --
    # FREEZE_NLP raw: xerces rung batches inflated 6x (17KB/295ms -> 112KB/1836ms), -34 -> +20. The
    # estimator's only online consumer is the DVET trial, which reads edges.txt directly.)
    so=$(ls "$STG"/*.aot.so 2>/dev/null | head -1)
    if [ -n "$so" ]; then
      bytes=$(stat -c%s "$so"); built_this=1
      kk=$k; [ "$kk" -gt 11 ] && kk=11  # R7''-8: cap the rung FILE index at the parent's last seq slot
      cp "$so" "$STG/rung_$kk.so.tmp" && mv "$STG/rung_$kk.so.tmp" "$STG/rung_$kk.so"
      if [ "$GRIC_FRESH" -eq 1 ]; then
        sort -u built.txt "new_$k" "$STG/gric_admitted.txt" > built.tmp && mv built.tmp built.txt
      else
        sort -u built.txt "new_$k" > built.tmp && mv built.tmp built.txt
      fi
      built_mass=$((built_mass + pend_c)); built_smass=$(( ${built_smass:-0} + pend_s ))
    fi
  fi
  b1=$(date +%s%3N); spent=$((spent + b1 - b0))
  if [ "$built_this" -eq 1 ]; then
    last_build_ms=$((b1 - b0)); last_build_regions=$(wc -l < "new_$k")
  else
    last_dry_ms=$((b1 - b0))
  fi
  # R6' pend publication (2026-07-18): parent's realized-no-gain idle consults this (leela race fix)
  echo "$pend_c $built_mass" > "$STG/pend"
  echo "$k $T $((b1-b0)) $bytes" >> "$STG/rungs.log"
  echo "$(date +%s%3N) $k $T built=$built_this nnew=$(wc -l < "new_$k") pend_c=$pend_c pend_s=$pend_s built_c=$built_mass built_s=${built_smass:-0} nsamp=$(wc -l < "sampx_$k" 2>/dev/null||echo 0)" >> "$STG/decomp.log"
  [ "$ONE" -eq 1 ] && break
  # mass-majority terminal stop: built covers majority of ALL observed mass at threshold floor
  # NOTE: a prefix-mass majority must NOT terminate the builder -- the profile evolves (the same trap as
  # count-bands and early-KEEP). Coverage-complete states IDLE on growth; kill-on-exit terminates.
  if [ "$T" -le 512 ] && { [ ! -s "new_$k" ] || { [ "$built_mass" -gt 0 ] && [ $((built_mass * 2)) -ge "$tot_mass" ]; }; }; then
    # coverage complete at the floor: idle until the profile actually grows (no hot dry-looping).
    # R-FAMILY-5 FIX (2026-07-19, seqfix xalan_1: builder entered this wait at k=9/t=41s and NEVER
    # left for ~1010s -- under the demand-driven handshake the $RUN profile mtime only changes when
    # the BUILDER issues wantprof, which it cannot do from inside this loop: the pause's release
    # signal was producible only by the paused actor. 5th instance of the starvation family. Fix:
    # (a) issue wantprof per poll so the parent refreshes the profile; (b) break on regime-file
    # growth (a census flip = new phase = re-dry NOW).)
    echo "$(date +%s%3N) $k TERMWAIT enter" >> "$STG/decomp.log"
    pm=$(stat -c %Y "$RUN" 2>/dev/null)
    rg_wait=$(stat -c%s "$STG/regime" 2>/dev/null || echo 0)
    while :; do
      sleep 0.2
      : > "$STG/wantprof"
      nm=$(stat -c %Y "$RUN" 2>/dev/null)
      if [ "$nm" != "$pm" ]; then cp "$RUN"/*.prof "$STG/" 2>/dev/null; echo "$(date +%s%3N) $k TERMWAIT exit=profgrew" >> "$STG/decomp.log"; break; fi
      rg_now2=$(stat -c%s "$STG/regime" 2>/dev/null || echo 0)
      if [ "$rg_now2" != "$rg_wait" ]; then echo "$(date +%s%3N) $k TERMWAIT exit=regime" >> "$STG/decomp.log"; break; fi
    done
  fi
  T=$((T / 2)); [ "$T" -lt 512 ] && T=512   # floor the DRY threshold; T=0 cold-tail never compiled
  k=$((k + 1))
  # rent-pace wait: ONE computed sleep (the old 50ms date-fork polling burned ~0.2-0.4 CPU-s/s of
  # sibling-core churn -- the NLP_C_FLOOR attribution: kernel substrate is ZERO, the entire "floor"
  # was this shell churn)
  rem=$(( spent - ($(date +%s%3N) - start) ))
  if [ "$rem" -gt 0 ]; then sleep "$(awk -v r="$rem" "BEGIN{print r/1000}")"; fi
done
