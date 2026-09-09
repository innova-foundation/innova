# Copyright (c) 2026 The Innova developers
# Per-feature checks sourced by iv5_onechain_evidence.sh, which owns the inventory, RPC
# transport and helpers. Each section ends in exactly one feature() row.

# The chain's own view of where the gates are, taken from a node rather than
# from the harness constants, so a driver that moved a switch is followed.
LADDER_JSON=""
TIP=0
load_ladder() {
    local n="${NODE_NAMES[0]}"
    LADDER_JSON="$(rpc "$n" getdaginfo 2>/dev/null)"
    TIP="$(height "$n")"
    DAG_FORK="$(jget "$LADDER_JSON" fork_height)"
    DAGKNIGHT_FORK="$(jget "$LADDER_JSON" dagknight_fork_height)"
    BOUNDARY_A="$(jget "$LADDER_JSON" boundary_a_activation_height)"
    EPOCH_LEN="$(jget "$LADDER_JSON" epoch_interval)"
    local fin; fin="$(rpc "$n" getfinalityinfo 2>/dev/null)"
    BOUNDARY_B="$(jget "$fin" boundary_b_activation_height)"
    CUR_EPOCH="$(jget "$fin" epoch)"
    info "tip $TIP; DAG $DAG_FORK; DAGKnight $DAGKNIGHT_FORK; Boundary A $BOUNDARY_A; Boundary B $BOUNDARY_B; epoch $CUR_EPOCH of $EPOCH_LEN blocks"
}

# ---------------------------------------------------------------------------
check_fleet_up() {
    header "0. The fleet is one chain"
    local n h ok=1 detail="" hashes="" bh
    local top=""
    for n in "${NODE_NAMES[@]}"; do
        h="$(height "$n")"
        is_int "${h:-x}" || { fail "node $n does not answer getblockcount"; ok=0; continue; }
        detail="$detail $n=$h"
        if [ -z "$top" ] || [ "$h" -lt "$top" ]; then top="$h"; fi
    done
    [ "$ok" -eq 1 ] || { feature "fleet" BLOCKED "-" "a node does not answer RPC"; return 1; }
    info "heights:$detail"
    # Same height is not the same chain. Compare the block hash at the lowest
    # common height: two nodes on forks can sit at the same number.
    BLOCK_Q="$top"
    if agree_on "the block at the lowest common height $top" r_block_hash; then
        COMMON_HEIGHT="$top"
        feature "fleet-is-one-chain" EXERCISED "h=$top" \
            "${#NODE_NAMES[@]} nodes agree on the block hash at $top ($AGREE_VALUE)"
    else
        COMMON_HEIGHT="$top"
        feature "fleet-is-one-chain" BLOCKED "h=$top" "the nodes are on different chains"
        return 1
    fi
}

# ---------------------------------------------------------------------------
check_idag() {
    header "1. IDAG ordering and DAGKnight"
    local n DI ok=1 why=""
    for n in "${NODE_NAMES[@]}"; do
        DI="$(rpc "$n" getdaginfo 2>/dev/null)"
        [ "$(jget "$DI" dag_active)" = "true" ] || { ok=0; why="$why $n:dag_active=$(jget "$DI" dag_active)"; }
        [ "$(jget "$DI" dagknight_active)" = "true" ] || { ok=0; why="$why $n:dagknight_active=$(jget "$DI" dagknight_active)"; }
        [ "$(jget "$DI" pos_block_production)" = "false" ] || { ok=0; why="$why $n:pos-production-open"; }
        local ord con; ord="$(jget "$DI" ordering_algorithm)"; con="$(jget "$DI" dagknight_contract)"
        [ -n "$ord" ] && [ "$ord" = "$con" ] || { ok=0; why="$why $n:orders-by-$ord-not-$con"; }
        local e; e="$(jget "$DI" dag_entries)"
        is_int "${e:-x}" && [ "$e" -gt 0 ] || { ok=0; why="$why $n:dag_entries=$e"; }
    done
    if [ "$ok" -eq 1 ]; then pass "every node runs DAGKnight ordering with a populated DAG"
    else fail "the DAG is not running everywhere:$why"; fi

    # Every block's coinbase from the DAG fork on must carry exactly one IDAG
    # parent commitment, decoded from the coinbase bytes.
    local lo=$(( DAG_FORK > 1 ? DAG_FORK : 1 ))
    local counts; counts="$(awk -F'\t' -v lo="$lo" -v hi="$COMMON_HEIGHT" \
        '$1 >= lo && $1 <= hi {print $4}' "$SWEEP_CACHE" | sort | uniq -c | tr '\n' ' ')"
    local total; total="$(awk -F'\t' -v lo="$lo" -v hi="$COMMON_HEIGHT" \
        '$1 >= lo && $1 <= hi' "$SWEEP_CACHE" | wc -l | tr -d ' ')"
    local carried; carried="$(awk -F'\t' -v lo="$lo" -v hi="$COMMON_HEIGHT" \
        '$1 >= lo && $1 <= hi && $4 >= 1' "$SWEEP_CACHE" | wc -l | tr -d ' ')"
    local bad; bad="$(awk -F'\t' -v lo="$lo" -v hi="$COMMON_HEIGHT" \
        '$1 >= lo && $1 <= hi && $4 < 1 {printf "h=%s ", $1}' "$SWEEP_CACHE")"
    if [ "${total:-0}" -gt 0 ] && [ "$carried" = "$total" ]; then
        pass "all $total blocks from the DAG fork at $lo to $COMMON_HEIGHT carry a decoded IDAG parent commitment (parent counts: $counts)"
    else
        fail "$(( total - carried )) of $total blocks in $lo..$COMMON_HEIGHT carry no IDAG commitment: $bad"
        ok=0
    fi

    # The DAGKnight ordering itself. getdagorder returns a bare array of block
    # entries, so the length is the array's own and the inferred k is per entry.
    local ORD; ORD="$(rpc "${NODE_NAMES[0]}" getdagorder 2>/dev/null)"
    local ordsum; ordsum="$(printf '%s' "$ORD" | python3 -c '
import json,sys
try: v=json.load(sys.stdin)
except Exception: print("0 - -"); sys.exit(0)
if not isinstance(v, list): print("0 - -"); sys.exit(0)
ks = sorted({e["inferred_k"] for e in v if "inferred_k" in e})
blues = sum(1 for e in v if e.get("blue"))
print("%d %s %d" % (len(v), ",".join(str(k) for k in ks) or "-", blues))')"
    local ordlen k blues; read -r ordlen k blues <<< "$ordsum"
    if is_int "${ordlen:-x}" && [ "$ordlen" -gt 0 ]; then
        pass "getdagorder returns a $ordlen-block DAGKnight ordering (inferred k=$k, $blues blue)"
    else
        fail "getdagorder returned no ordering"; ok=0
    fi

    if [ "$ok" -eq 1 ]; then
        feature "idag-ordering-dagknight" EXERCISED "h=$lo..$COMMON_HEIGHT" \
            "all $total blocks from the DAG fork carry a decoded IDAG parent commitment; ordering_algorithm=$(jget "$LADDER_JSON" ordering_algorithm), $ordlen-block order at inferred k=$k"
    else
        feature "idag-ordering-dagknight" CONFIGURED-ONLY "h=$COMMON_HEIGHT" "see failures above"
    fi
}

# ---------------------------------------------------------------------------
check_merge_block() {
    header "2. A real merge block committing more than one DAG parent"
    local lo=$(( DAG_FORK > 1 ? DAG_FORK : 1 )) rows first h cnt parents
    info "scanning heights $lo..$COMMON_HEIGHT for a coinbase committing >1 parent"
    rows="$(scan_merge_blocks "${NODE_NAMES[0]}" "$lo" "$COMMON_HEIGHT")"
    if [ -z "$rows" ]; then
        fail "no block in $lo..$COMMON_HEIGHT commits more than one DAG parent"
        feature "idag-merge-block" BLOCKED "-" \
            "no coinbase in $lo..$COMMON_HEIGHT decodes to more than one IDAG parent; one parent is not a merge"
        return 1
    fi
    info "merge blocks: $(printf '%s\n' "$rows" | awk '{printf "h=%s(%s) ", $1, $2}')"
    first="$(printf '%s\n' "$rows" | head -1)"
    read -r h cnt parents <<< "$first"
    pass "height $h commits $cnt DAG parents: $parents"

    # The same commitment, decoded from every node's own copy of the block.
    BLOCK_Q="$h"
    local agreed=1
    agree_on "the decoded IDAG commitment at height $h" r_coinbase_idag || agreed=0
    # And the node's own DAG view of the same block, as a cross-check on the
    # decoder's offsets.
    local dp; dp="$(jget "$(get_block "${NODE_NAMES[0]}" "$h")" dagparents)"
    local dplen; dplen="$(printf '%s' "$dp" | python3 -c 'import json,sys
try: print(len(json.load(sys.stdin)))
except Exception: print(0)')"
    if [ "${dplen:-0}" -ge 2 ]; then
        pass "the node's own DAG record for height $h lists $dplen parents, agreeing with the decoded commitment"
    else
        fail "the node reports $dplen DAG parents at height $h where the coinbase commits $cnt"
        agreed=0
    fi
    local total; total="$(printf '%s\n' "$rows" | wc -l | tr -d ' ')"
    if [ "$agreed" -eq 1 ]; then
        feature "idag-merge-block" EXERCISED "h=$h" \
            "coinbase commits $cnt DAG parents, decoded identically on all ${#NODE_NAMES[@]} nodes; $total merge block(s) in $lo..$COMMON_HEIGHT"
    else
        feature "idag-merge-block" CONFIGURED-ONLY "h=$h" "the merge block does not decode identically fleet-wide"
    fi
}

# ---------------------------------------------------------------------------
check_finality_transparent() {
    header "3. Epoch finality, transparent lane"
    local fh fhash ok=1
    agree_on "the finalized height" r_finalized_height || ok=0
    fh="$AGREE_VALUE"
    agree_on "the finalized block hash" r_finalized_hash || ok=0
    fhash="$AGREE_VALUE"
    if ! is_int "${fh:-x}" || [ "${fh:-0}" -le 0 ]; then
        fail "finalized_height is $fh: the transparent lane never bootstrapped"
        feature "epoch-finality-transparent" BLOCKED "-" "finalized_height=$fh"
        return 1
    fi
    pass "the chain has a finalized height of $fh ($fhash)"

    # Votes actually connected in blocks, not relayed. A vote counted is a vote
    # that a block carries.
    local lo=$(( fh - 3 * EPOCH_LEN )); [ "$lo" -lt 1 ] && lo=1
    local votes; votes="$(scan_votes "${NODE_NAMES[0]}" "$lo" "$fh")"
    local tvotes; tvotes="$(printf '%s\n' "$votes" | grep -c ' transparent ' || true)"
    local first_t; first_t="$(printf '%s\n' "$votes" | grep ' transparent ' | head -1)"
    if [ "${tvotes:-0}" -gt 0 ]; then
        pass "$tvotes transparent finality vote(s) are connected in blocks $lo..$fh (first at height ${first_t%% *})"
    else
        fail "no transparent finality vote is connected in blocks $lo..$fh"
        ok=0
    fi
    local hard; hard="$(jget "$(rpc "${NODE_NAMES[0]}" getfinalityinfo 2>/dev/null)" consecutive_hard_epochs)"
    local tier; tier="$(jget "$(rpc "${NODE_NAMES[0]}" getfinalityinfo 2>/dev/null)" finality_tier)"
    info "finality tier $tier over $hard consecutive HARD epoch(s)"
    if [ "$ok" -eq 1 ]; then
        feature "epoch-finality-transparent" EXERCISED "h=${first_t%% *}, finalized=$fh" \
            "$tvotes transparent votes connected in blocks; finalized_height $fh and hash $fhash identical on all ${#NODE_NAMES[@]} nodes; tier $tier, $hard consecutive HARD epochs"
    else
        feature "epoch-finality-transparent" CONFIGURED-ONLY "finalized=$fh" "no connected transparent vote found"
    fi
}

# ---------------------------------------------------------------------------
check_finality_private_cert() {
    header "4. Epoch finality, private lane: a v4 note-tally certificate"
    # private_certificate_present and tally_certificate_version stay false/0 for
    # the note lane (they follow HasPrivateWeight()). The lane is identified by
    # certificate version >= 4 plus a non-zero committee set hash.
    local fin; fin="$(rpc "${NODE_NAMES[0]}" getfinalityinfo 2>/dev/null)"
    local flagp flagv; flagp="$(jget "$fin" private_certificate_present)"; flagv="$(jget "$fin" tally_certificate_version)"
    info "status flags read private_certificate_present=$flagp tally_certificate_version=$flagv (expected false/0 for the note lane: not used as evidence)"

    local seated seathash m seats
    seated="$(jget "$fin" committee_seated)"; seathash="$(jget "$fin" committee_set_hash)"
    m="$(jget "$fin" committee_threshold_m)"; seats="$(jget "$fin" committee_seat_count)"
    if [ "$seated" = "true" ] && [ ${#seathash} -eq 64 ] && [ "$seathash" != "$(printf '0%.0s' $(seq 64))" ]; then
        pass "a committee is seated from the collateral registry draw: $m-of-$seats, set hash $seathash"
    else
        fail "no committee is seated (seated=$seated, set hash '$seathash')"
    fi

    local lo=$(( COMMON_HEIGHT - 4 * EPOCH_LEN )); [ "$lo" -lt 1 ] && lo=1
    info "scanning heights $lo..$COMMON_HEIGHT for connected tally certificates"
    local rows; rows="$(scan_certificates "${NODE_NAMES[0]}" "$lo" "$COMMON_HEIGHT")"
    if [ -z "$rows" ]; then
        fail "no block in $lo..$COMMON_HEIGHT connects a finality tally certificate"
        feature "epoch-finality-private-cert" BLOCKED "-" \
            "no certificate is connected in $lo..$COMMON_HEIGHT (committee seated=$seated)"
        return 1
    fi
    info "certificates: $(printf '%s\n' "$rows" | awk '{printf "h=%s(v%s) ", $1, $2}')"
    local v4; v4="$(printf '%s\n' "$rows" | awk '$2 >= 4 && $3 !~ /^0+$/ {print; exit}')"
    if [ -z "$v4" ]; then
        local best; best="$(printf '%s\n' "$rows" | head -1)"
        fail "the connected certificates are not v4 note certificates (best: $best)"
        feature "epoch-finality-private-cert" CONFIGURED-ONLY "h=${best%% *}" \
            "a certificate connects at height ${best%% *} but its version is $(echo "$best" | awk '{print $2}'), not >= 4"
        return 1
    fi
    # Tier and signer count are not in the sweep row; read them off the block.
    local ch cv cs; read -r ch cv cs <<< "$v4"
    local extra; extra="$(rpc "${NODE_NAMES[0]}" getblock "$(block_hash "${NODE_NAMES[0]}" "$ch")" 2>/dev/null | python3 -c '
import json,sys
try: b=json.load(sys.stdin)
except Exception: sys.exit(0)
for c in b.get("finality_tally_certificates",[]):
    if c.get("version",0) >= 4:
        print("%s %s %s" % (c.get("tier"), c.get("signer_count"), c.get("private_weight"))); break
')"
    local ct csig cpw; read -r ct csig cpw <<< "$extra"
    pass "height $ch connects a version-$cv tally certificate, tier $ct, $csig signer(s), committee set hash $cs"
    # Must be a note-lane certificate, not a private-weight one.
    if [ "$cpw" = "True" ] || [ "$cpw" = "true" ]; then
        fail "the certificate at height $ch carries private weight, so it is not the note lane this section is for"
        feature "epoch-finality-private-cert" CONFIGURED-ONLY "h=$ch" \
            "a version-$cv certificate connects but carries private weight rather than note weight"
        return 1
    fi
    pass "it carries note weight rather than private weight, which is why the status flags read false/0 for it"
    feature "epoch-finality-private-cert" EXERCISED "h=$ch" \
        "connected certificate version $cv (>=4 = note lane) with non-zero committee_set_hash $cs, tier $ct, $csig signer(s); private_weight false, so private_certificate_present and tally_certificate_version stay false/0 as designed"
}

# ---------------------------------------------------------------------------
check_note_votes() {
    header "5. Note votes"
    local e best=0 bestc=0 c
    # An epoch whose state counted note votes. The count is a consensus field of
    # the epoch state, so it is compared across the fleet.
    for ((e=1; e<=CUR_EPOCH; e++)); do
        c="$(jget "$(rpc "${NODE_NAMES[0]}" getepochinfo "$e" 2>/dev/null)" note_votes_counted)"
        is_int "${c:-x}" || continue
        [ "$c" -gt "$bestc" ] && { bestc="$c"; best="$e"; }
    done
    if [ "$bestc" -le 0 ]; then
        fail "no epoch counted a note vote"
        feature "note-votes" BLOCKED "-" "note_votes_counted is 0 in every epoch 1..$CUR_EPOCH"
        return 1
    fi
    pass "epoch $best counted $bestc note vote(s)"
    EPOCH_Q="$best"
    # Use agree_on's result: AGREE_VALUE holds the first node's answer even on a
    # disagreement.
    local agreed=1
    agree_on "epoch $best note_votes_counted" r_epoch_notevotes || agreed=0
    local epj; epj="$(rpc "${NODE_NAMES[0]}" getepochinfo "$best" 2>/dev/null)"
    local ntags; ntags="$(printf '%s' "$(jget "$epj" note_vote_tags)" | python3 -c 'import json,sys
try: print(len(json.load(sys.stdin)))
except Exception: print(0)')"
    local equiv; equiv="$(jget "$epj" note_votes_equivocated)"
    info "epoch $best carries $ntags note vote tag(s), $equiv equivocated"
    # A counted vote with no tag naming it is a number with nothing behind it.
    if [ "${ntags:-0}" -le 0 ]; then
        fail "epoch $best reports $bestc counted note vote(s) and no tag naming any of them"
    fi
    if [ "$agreed" -eq 1 ] && [ "${ntags:-0}" -gt 0 ]; then
        feature "note-votes" EXERCISED "epoch=$best" \
            "$bestc note votes counted into epoch $best's state with $ntags naming tag(s), identical on all ${#NODE_NAMES[@]} nodes; $equiv equivocated"
    else
        feature "note-votes" CONFIGURED-ONLY "epoch=$best" \
            "count $bestc with $ntags tag(s); fleet agreement:$AGREE_WHY"
    fi
}

# ---------------------------------------------------------------------------
check_nullstake_voting() {
    header "6. NullStake finality voting"
    local lo=$(( COMMON_HEIGHT - 4 * EPOCH_LEN )); [ "$lo" -lt 1 ] && lo=1
    local votes; votes="$(scan_votes "${NODE_NAMES[0]}" "$lo" "$COMMON_HEIGHT")"
    local ns; ns="$(printf '%s\n' "$votes" | grep -E ' nullstake_v[23]' | head -1)"
    local nsn; nsn="$(printf '%s\n' "$votes" | grep -cE ' nullstake_v[23]' || true)"
    if [ -z "$ns" ]; then
        fail "no NullStake finality vote is connected in blocks $lo..$COMMON_HEIGHT"
        local modes; modes="$(printf '%s\n' "$votes" | awk '{print $2}' | sort | uniq -c | tr '\n' ' ')"
        feature "nullstake-finality-voting" BLOCKED "-" \
            "no nullstake_v2/v3 vote in $lo..$COMMON_HEIGHT; connected vote modes were: ${modes:-none}"
        return 1
    fi
    local h mode auth; read -r h mode auth <<< "$ns"
    pass "height $h connects a $mode finality vote (auth $auth)"
    # A private vote must hide its weight in the block it is carried in.
    local bh; bh="$(block_hash "${NODE_NAMES[0]}" "$h")"
    local hidden; hidden="$(rpc "${NODE_NAMES[0]}" getblock "$bh" true 2>/dev/null | python3 -c '
import json,sys
try: b=json.load(sys.stdin)
except Exception: sys.exit(0)
for v in b.get("finality_votes",[]):
    if str(v.get("proof_mode","")).startswith("nullstake"):
        print("%s %s" % (v.get("weight_hidden"), v.get("weight","-"))); break
')"
    if [ "${hidden%% *}" = "True" ] || [ "${hidden%% *}" = "true" ]; then
        pass "the vote at height $h carries a hidden weight, not a transparent one"
    else
        fail "the NullStake vote at height $h reports weight_hidden=$hidden"
    fi
    feature "nullstake-finality-voting" EXERCISED "h=$h" \
        "$nsn NullStake vote(s) connected in blocks $lo..$COMMON_HEIGHT; first at $h, mode $mode, auth $auth, weight hidden"
}

# ---------------------------------------------------------------------------
check_masks() {
    header "7. The FCMP++ pool with all eight disclosure masks"
    # Masks are read from each confirmed transaction's bytes; the RPC's
    # disclosure_mask only cross-checks the reader's offsets.
    local lo=$(( BOUNDARY_B > 1 ? BOUNDARY_B : 1 ))
    local h raw txs t idx rows=""
    # Only blocks carrying more than the coinbase can carry a user transfer, and
    # the sweep already knows which those are.
    local candidates; candidates="$(scan_multitx - "$lo" "$COMMON_HEIGHT")"
    local ncand; ncand="$(printf '%s' "$candidates" | grep -c . || true)"
    info "$ncand block(s) in $lo..$COMMON_HEIGHT carry more than a coinbase; reading their transactions"
    for h in $candidates; do
        txs="$(jget "$(get_block "${NODE_NAMES[0]}" "$h")" tx)"
        [ -n "$txs" ] || continue
        while read -r idx t; do
            [ ${#t} -eq 64 ] || continue
            raw="$(raw_tx "${NODE_NAMES[0]}" "$t")"
            [ -n "$raw" ] || continue
            local d; d="$(python3 "$DECODE" iv5 "$raw" 2>/dev/null)"
            local isiv5; isiv5="$(printf '%s' "$d" | jq_path iv5)"
            [ "$isiv5" = "true" ] || continue
            local m; m="$(printf '%s' "$d" | jq_path disclosure_mask)"
            local op; op="$(printf '%s' "$d" | jq_path operation)"
            local role=tx; [ "$idx" = "0" ] && role=coinbase
            rows="$rows$h $t $m $op $role"$'\n'
        done <<< "$(printf '%s' "$txs" | python3 -c 'import json,sys
try:
    for i, t in enumerate(json.load(sys.stdin)): print("%d %s" % (i, t))
except Exception: pass')"
    done
    if [ -z "$rows" ]; then
        fail "no IV5 transaction is confirmed in $lo..$COMMON_HEIGHT"
        feature "fcmp-pool-eight-masks" BLOCKED "-" "no confirmed IV5 transaction on the chain"
        return 1
    fi
    local m found=0 missing=""
    MASK_EVIDENCE=""
    for m in 0 1 2 3 4 5 6 7; do
        # Only NOTE_TRANSFER (operation 2) counts. A coinbase fee note is pinned to
        # COINBASE_FEE_NOTE_DISCLOSURE_MASK = 3, and a shield (operation 0) is
        # transparently funded by construction.
        local row; row="$(printf '%s' "$rows" | awk -v m="$m" '$3 == m && $4 == 2 && $5 == "tx" {print; exit}')"
        if [ -z "$row" ]; then
            local other; other="$(printf '%s' "$rows" | awk -v m="$m" '$3 == m {print $4" "$5; exit}')"
            if [ -n "$other" ]; then
                info "mask $m appears only on operation ${other%% *} (${other##* }), not on a transfer; not counted"
            fi
            missing="$missing $m"; continue
        fi
        local rh rt rm ro rr; read -r rh rt rm ro rr <<< "$row"
        # The node's own parse must agree with the byte reader's offsets.
        local rpcmask rpcsize mysize
        rpcmask="$(jget "$(rpc "${NODE_NAMES[0]}" getrawtransaction "$rt" 1 2>/dev/null)" privacy_vnext disclosure_mask)"
        rpcsize="$(jget "$(rpc "${NODE_NAMES[0]}" getrawtransaction "$rt" 1 2>/dev/null)" privacy_vnext payload_size)"
        mysize="$(python3 "$DECODE" iv5 "$(raw_tx "${NODE_NAMES[0]}" "$rt")" 2>/dev/null | jq_path payload_size)"
        if [ "$rpcmask" != "$rm" ] || [ "$rpcsize" != "$mysize" ]; then
            fail "mask $m: the byte reader reads mask=$rm size=$mysize where the node reports mask=$rpcmask size=$rpcsize"
            missing="$missing $m"; continue
        fi
        # A transfer stays inside the pool, so neither side may be transparent.
        local nvin nvout json
        json="$(rpc "${NODE_NAMES[0]}" getrawtransaction "$rt" 1 2>/dev/null)"
        nvin="$(jlen "$json" vin)"; nvout="$(jlen "$json" vout)"
        if [ "${nvin:-1}" != "0" ] || [ "${nvout:-1}" != "0" ]; then
            fail "mask $m (transfer ${rt:0:16}) carries $nvin transparent input(s) and $nvout output(s); a transfer must carry neither"
            missing="$missing $m"; continue
        fi
        # Every node holds it.
        TX_Q="$rt"
        local allsee=1 nn
        for nn in "${NODE_NAMES[@]}"; do
            local mm; mm="$(r_tx_mask "$nn")"
            [ "$mm" = "$rm" ] || { allsee=0; break; }
        done
        if [ "$allsee" -ne 1 ]; then
            fail "mask $m: not every node reads mask $rm off tx ${rt:0:16}"
            missing="$missing $m"; continue
        fi
        pass "mask $m: tx ${rt:0:16} at height $rh declares mask $rm in its own $mysize-byte payload, no transparent value, read identically fleet-wide"
        MASK_EVIDENCE="$MASK_EVIDENCE m$m=${rt:0:12}@$rh"
        found=$((found+1))
    done
    if [ "$found" -eq 8 ]; then
        feature "fcmp-pool-eight-masks" EXERCISED "$MASK_EVIDENCE" \
            "all eight masks confirmed on this chain, each read off the transaction's own bytes and agreed fleet-wide"
    elif [ "$found" -gt 0 ]; then
        feature "fcmp-pool-eight-masks" CONFIGURED-ONLY "$MASK_EVIDENCE" \
            "$found of 8 masks confirmed; missing:$missing"
    else
        feature "fcmp-pool-eight-masks" BLOCKED "-" "no mask survived its assertions; missing:$missing"
    fi
}

# ---------------------------------------------------------------------------
check_fee_note() {
    header "8. The coinbase fee note"
    local lo=$(( BOUNDARY_B > 1 ? BOUNDARY_B : 1 ))
    local rows; rows="$(scan_fee_notes "${NODE_NAMES[0]}" "$lo" "$COMMON_HEIGHT")"
    if [ -z "$rows" ]; then
        fail "no coinbase in $lo..$COMMON_HEIGHT carries an IV5 fee note"
        feature "coinbase-fee-note" BLOCKED "-" "no version-2008 coinbase with a nonzero value balance"
        return 1
    fi
    local n; n="$(printf '%s\n' "$rows" | wc -l | tr -d ' ')"
    local first; first="$(printf '%s\n' "$rows" | head -1)"
    local h vb fee mask; read -r h vb fee mask <<< "$first"
    # The payload size is not in the sweep; read it off the one block being
    # reported rather than widening the cache for a single number.
    local size; size="$(python3 "$DECODE" iv5 "$(coinbase_raw "${NODE_NAMES[0]}" "$h")" 2>/dev/null | jq_path payload_size)"
    pass "height $h has a version-2008 coinbase carrying a ${size:-?}-byte IV5 note: value balance $vb sat, fee $fee sat, mask $mask"
    info "$n fee-note coinbase(s) in $lo..$COMMON_HEIGHT"

    # The coinbase version, decoded from every node's copy.
    BLOCK_Q="$h"
    local ok=1
    agree_on "the coinbase version at height $h" r_coinbase_version || ok=0
    [ "$AGREE_VALUE" = "2008" ] || { fail "the coinbase at $h decodes to version $AGREE_VALUE"; ok=0; }

    # COINBASE_FEE_NOTE_DISCLOSURE_MASK is consensus-pinned to
    # HIDE_SENDER|HIDE_RECEIVER = 3 so the shape does not identify the producer.
    if [ "$mask" = "3" ]; then
        pass "the note declares the consensus-pinned coinbase mask 3 (sender and receiver hidden, amount disclosed)"
    else
        fail "the coinbase note at height $h declares mask $mask, not the pinned 3"
        ok=0
    fi
    # The note's balance must equal its declared fee.
    if [ "$vb" -gt 0 ]; then
        pass "the note's value balance is positive ($vb sat), so the block's fee returns to the pool rather than crossing to the producer"
    else
        fail "the coinbase note at height $h declares a value balance of $vb"
        ok=0
    fi

    # The pool must actually rise by the note. Read the pool either side of the
    # block from a node's own accounting and compare with the decoded balance.
    local pb pa
    pb="$(jget "$(rpc "${NODE_NAMES[0]}" getepochinfo "$(( (h - 1 - BOUNDARY_A) / EPOCH_LEN + 1 ))" 2>/dev/null)" iv5_pool_balance)"
    info "epoch pool balance near the note block: $pb"
    if [ "$ok" -eq 1 ]; then
        feature "coinbase-fee-note" EXERCISED "h=$h" \
            "version-2008 coinbase with a $size-byte IV5 payload, value balance $vb sat / fee $fee sat decoded from the block's own bytes and agreed on all ${#NODE_NAMES[@]} nodes; $n such blocks"
    else
        feature "coinbase-fee-note" CONFIGURED-ONLY "h=$h" "the fee note does not decode identically fleet-wide"
    fi
    FEE_NOTE_HEIGHTS="$(printf '%s\n' "$rows" | awk '{print $1}' | tr '\n' ' ')"
}

# ---------------------------------------------------------------------------
check_ms_timestamps() {
    header "9. Millisecond timestamps, on the same chain as the fee note"
    # Only a NONZERO offset counts: zero is indistinguishable from unstamped, and
    # burst mining pins the offset at zero, so scan rather than sample the tip.
    local lo=1
    local rows; rows="$(scan_ms_offsets "${NODE_NAMES[0]}" "$lo" "$COMMON_HEIGHT")"
    if [ -z "$rows" ]; then
        fail "no block in $lo..$COMMON_HEIGHT stamps a nonzero millisecond offset"
        feature "millisecond-timestamps" BLOCKED "-" \
            "every IMTS commitment on the chain reads zero, which is indistinguishable from unstamped"
        return 1
    fi
    local n; n="$(printf '%s\n' "$rows" | wc -l | tr -d ' ')"
    local first; first="$(printf '%s\n' "$rows" | head -1)"
    local h ver off; read -r h ver off <<< "$first"
    pass "height $h stamps a nonzero millisecond offset of $off ms (coinbase version $ver)"
    info "$n block(s) with a nonzero offset: $(printf '%s\n' "$rows" | awk '{printf "%s@h%s ", $3, $1}' | head -c 200)"

    BLOCK_Q="$h"
    local ok=1
    agree_on "the millisecond offset decoded at height $h" r_coinbase_imts || ok=0

    # Find one block with both a nonzero offset and a fee note, or report that the
    # two only coexist on the chain.
    local both="" fh
    for fh in ${FEE_NOTE_HEIGHTS:-}; do
        if printf '%s\n' "$rows" | awk -v x="$fh" '$1 == x {found=1} END{exit !found}'; then
            both="$fh"; break
        fi
    done
    if [ -n "$both" ]; then
        local boff; boff="$(printf '%s\n' "$rows" | awk -v x="$both" '$1 == x {print $3}')"
        pass "height $both carries BOTH the IV5 fee note and a nonzero $boff ms offset: one block, both features"
        COMPOSED_HEIGHT="$both"; COMPOSED_MS="$boff"
    elif [ -n "${FEE_NOTE_HEIGHTS:-}" ]; then
        pass "the chain carries fee notes (h $(echo "$FEE_NOTE_HEIGHTS" | awk '{print $1}')) and nonzero ms offsets (h $h); no single block carries both"
    fi
    if [ "$ok" -eq 1 ]; then
        feature "millisecond-timestamps" EXERCISED "h=$h${both:+ (with fee note at h=$both)}" \
            "nonzero IMTS offset $off ms decoded from the coinbase and agreed on all ${#NODE_NAMES[@]} nodes; $n nonzero-offset block(s) on the same chain as the fee note"
    else
        feature "millisecond-timestamps" CONFIGURED-ONLY "h=$h" "the offset does not decode identically fleet-wide"
    fi
}

# ---------------------------------------------------------------------------
# One coinbase carries IDAG, millisecond and fee-note commitments; the fee-note binding
# covers the final vector. Asserted on one decoded coinbase, byte-identical across nodes.
check_one_coinbase_three_features() {
    header "9b. One coinbase carrying three features at once"
    local h="${COMPOSED_HEIGHT:-}"
    if [ -z "$h" ]; then
        fail "no single block carries an IV5 fee note and a nonzero millisecond offset together"
        feature "three-features-one-coinbase" BLOCKED "-" \
            "the fee note and a nonzero millisecond offset never landed in the same coinbase"
        return 1
    fi
    local n ok=1 first="" detail=""
    for n in "${NODE_NAMES[@]}"; do
        local raw; raw="$(coinbase_raw "$n" "$h")"
        local sum; sum="$(printf '%s' "$raw" | shasum -a 256 2>/dev/null | cut -c1-16)"
        local dec; dec="$(python3 "$DECODE" coinbase "$raw" 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
tags = {}
for r in d.get("op_returns",[]):
    if r.get("tag")=="IDAG": tags["idag"]=r["count"]
    elif r.get("tag")=="IMTS": tags["imts"]=r["offset_ms"]
print("v%s idag=%s imts=%s" % (d.get("version"), tags.get("idag","-"), tags.get("imts","-")))')"
        local iv5; iv5="$(python3 "$DECODE" iv5 "$raw" 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("payload=%s mask=%s vb=%s" % (d.get("payload_size","-"), d.get("disclosure_mask","-"),
                                    d.get("value_balance","-")) if d.get("iv5") else "payload=none")')"
        local line="$dec $iv5 raw=$sum"
        detail="$detail [$n $line]"
        [ -z "$first" ] && first="$line" || { [ "$line" = "$first" ] || ok=0; }
    done
    if [ "$ok" -ne 1 ]; then
        fail "the composed coinbase at height $h is not identical fleet-wide:$detail"
        feature "three-features-one-coinbase" BLOCKED "h=$h" "the four nodes decode different coinbases"
        return 1
    fi
    pass "height $h: every node decodes the same coinbase -- $first"
    # All three have to actually be present, not merely equal.
    case "$first" in
        v2008*) : ;;
        *) fail "the coinbase at height $h is not version 2008"; ok=0 ;;
    esac
    printf '%s' "$first" | grep -q 'idag=[1-9]' || { fail "no IDAG commitment in the composed coinbase"; ok=0; }
    printf '%s' "$first" | grep -qE 'imts=[1-9]' || { fail "the millisecond offset in the composed coinbase is zero"; ok=0; }
    printf '%s' "$first" | grep -q 'payload=[0-9]' || { fail "no IV5 payload in the composed coinbase"; ok=0; }
    if [ "$ok" -eq 1 ]; then
        feature "three-features-one-coinbase" EXERCISED "h=$h" \
            "one coinbase carries the IDAG parent commitment, a nonzero millisecond offset and the IV5 fee-note payload, decoded from its own bytes and byte-identical on all ${#NODE_NAMES[@]} nodes: $first"
    else
        feature "three-features-one-coinbase" CONFIGURED-ONLY "h=$h" "$first"
    fi
}

# ---------------------------------------------------------------------------
check_supply_cap() {
    header "10. The supply cap"
    local ok=1
    agree_on "the money supply" r_money_supply || ok=0
    local supply="$AGREE_VALUE"
    local cap; cap="$(rpc "${NODE_NAMES[0]}" getblockchaininfo 2>/dev/null | jq_path total_supply_cap)"
    # Find a block whose mint is below the previous block's while the subsidy
    # schedule is flat.
    local h mints="" m
    for ((h=COMMON_HEIGHT-30; h<=COMMON_HEIGHT; h++)); do
        [ "$h" -ge 1 ] || continue
        m="$(jget "$(get_block "${NODE_NAMES[0]}" "$h")" mint)"
        mints="$mints$h $m"$'\n'
    done
    local zero; zero="$(printf '%s' "$mints" | awk '$2 == 0 || $2 == "0.00000000" {print $1; exit}')"
    info "money supply $supply; recent mints: $(printf '%s' "$mints" | tail -5 | tr '\n' ' ')"
    if [ -n "$zero" ]; then
        pass "issuance is clamped to zero at height $zero with the chain still producing blocks"
        feature "supply-cap" EXERCISED "h=$zero" \
            "a block at height $zero mints nothing while the chain continues; money supply $supply agreed on all ${#NODE_NAMES[@]} nodes"
    elif [ "$ok" -eq 1 ]; then
        feature "supply-cap" CONFIGURED-ONLY "supply=$supply" \
            "the supply is tracked identically fleet-wide but no block on this chain was clamped, so the cap never bound"
    else
        feature "supply-cap" BLOCKED "-" "the fleet disagrees on the money supply:$AGREE_WHY"
    fi
}

# ---------------------------------------------------------------------------
check_collateralnodes() {
    header "11. Collateralnode payments and private registration"
    local count; count="$(rpc "${NODE_NAMES[0]}" collateralnode count 2>&1 | tr -d '"[:space:]')"
    local reg; reg="$(rpc "${NODE_NAMES[0]}" getfinalityinfo 2>/dev/null)"
    local rows; rows="$(jget "$reg" committee_next_term_draw registry_rows)"
    local need; need="$(jget "$reg" committee_next_term_draw rows_required)"
    local seats; seats="$(jget "$reg" committee_seat_count)"
    local seated; seated="$(jget "$reg" committee_seated)"
    info "collateralnode count $count; registry $rows of $need row(s) required; $seats seat(s) filled"

    # --- payments ---
    # On regtest the era gate is closed unless -regtestcnpayments is set; a closed
    # gate is reported separately from "possible but did not happen".
    local era_on=0 i
    for i in "${!NODE_NAMES[@]}"; do
        local lg
        lg="$(on_host "${NODE_HOSTS[$i]}" "grep -c 'Collateralnode payment rehearsal:' ${NODE_DIRS[$i]}/regtest/debug.log 2>/dev/null" 2>/dev/null | tr -d '[:space:]')"
        [ "${lg:-0}" != "0" ] && era_on=1
    done
    # A payment is a paying coinbase output beyond the producer's own, at a height
    # where the era is open. Post-DAG coinbases already carry two OP_RETURN
    # commitments (IDAG, IMTS), so those are excluded from the count.
    local wide_rows=""
    local h pays
    for h in $(awk -F'\t' -v hi="$COMMON_HEIGHT" '$1 > hi - 60 && $1 <= hi {print $1}' "$SWEEP_CACHE"); do
        pays="$(python3 "$DECODE" coinbase "$(coinbase_raw "${NODE_NAMES[0]}" "$h")" 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: print(0); sys.exit(0)
# vout_count less the OP_RETURN commitments is what actually pays anyone.
print(d.get("vout_count",0) - len(d.get("op_returns",[])))')"
        is_int "${pays:-x}" || continue
        [ "$pays" -ge 2 ] && { wide_rows="$h:$pays"; break; }
    done
    if [ "$era_on" -eq 0 ]; then
        fail "the collateralnode payment era is closed on this chain: no node logged the rehearsal knob, so CollateralnodePaymentsEnabledAtHeight() is false at every height"
        feature "collateralnode-payments" BLOCKED "-" \
            "-regtestcnpayments was never set, so producer and validator both hold payments off; no block on this chain could carry one"
    elif [ -n "$wide_rows" ]; then
        pass "a coinbase at height ${wide_rows%%:*} carries ${wide_rows##*:} PAYING outputs (OP_RETURN commitments excluded) with the payment era open"
        feature "collateralnode-payments" EXERCISED "h=${wide_rows%%:*}" \
            "coinbase splits its reward across ${wide_rows##*:} paying outputs at a height where the payment era is open; registry holds $rows row(s)"
    else
        feature "collateralnode-payments" CONFIGURED-ONLY "era open, registry_rows=$rows" \
            "the payment era is open but no coinbase in the last 60 blocks splits its reward beyond the producer output"
    fi

    # --- private registration ---
    # Private = carried by an IV5 payload, not a transparent collateral output. The
    # committee draw reads the registry, so an empty registry means none landed.
    if ! is_int "${rows:-x}" || [ "$rows" -le 0 ]; then
        fail "the collateral registry the committee draw reads is empty ($rows of $need required)"
        feature "collateralnode-private-registration" BLOCKED "registry_rows=$rows" \
            "no registration is in the registry, so nothing can be drawn from it"
        return 1
    fi
    pass "the collateral registry holds $rows row(s) against $need required"
    if [ "$seated" = "true" ]; then
        feature "collateralnode-private-registration" EXERCISED "registry_rows=$rows" \
            "the registry seated a $(jget "$reg" committee_threshold_m)-of-$seats committee with set hash $(jget "$reg" committee_set_hash)"
    else
        feature "collateralnode-private-registration" CONFIGURED-ONLY "registry_rows=$rows" \
            "$rows registration(s) are in the registry but no committee is seated from it yet"
    fi
}

# ---------------------------------------------------------------------------
check_idns() {
    header "12. The IDNS reset, and private IDNS with its positive control"
    local names; names="$(rpc "${NODE_NAMES[0]}" name_list 2>&1)"
    local n; n="$(printf '%s' "$names" | python3 -c 'import json,sys
try: print(len(json.load(sys.stdin)))
except Exception: print(0)')"
    info "wallet holds $n name(s)"
    if [ "${n:-0}" -eq 0 ]; then
        feature "idns-reset" BLOCKED "-" "no name is registered on this chain"
        feature "idns-private-tor" BLOCKED "-" "no name is registered on this chain"
        return 1
    fi

    # Positive control: a conventional record must be shown to leak its IP before
    # the descriptor's absence of one means anything.
    local rows; rows="$(printf '%s' "$names" | python3 -c 'import json,sys
try: v=json.load(sys.stdin)
except Exception: sys.exit(0)
for r in v:
    print("%s\t%s\t%s" % (r.get("name",""), r.get("value",""), r.get("txid","")))')"
    local rec_name="" rec_val="" rec_tx="" rv_name="" rv_val="" rv_tx=""
    local nm vl tx
    while IFS=$'\t' read -r nm vl tx; do
        [ -n "$nm" ] || continue
        case "$vl" in
            *onion*) [ -z "$rv_name" ] && { rv_name="$nm"; rv_val="$vl"; rv_tx="$tx"; } ;;
            *[0-9].[0-9]*) [ -z "$rec_name" ] && { rec_name="$nm"; rec_val="$vl"; rec_tx="$tx"; } ;;
        esac
    done <<< "$rows"

    local control=0
    if [ -n "$rec_name" ]; then
        local ip; ip="$(printf '%s' "$rec_val" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)"
        if [ -n "$ip" ] && [ -n "$rec_tx" ]; then
            local scan; scan="$(python3 "$DECODE" scanip "$(raw_tx "${NODE_NAMES[0]}" "$rec_tx")" "$ip" 2>/dev/null)"
            if [ "$(printf '%s' "$scan" | jq_path present)" = "true" ]; then
                pass "POSITIVE CONTROL: the conventional record '$rec_name' puts $ip in its own on-chain bytes (tx ${rec_tx:0:16})"
                control=1
            else
                fail "positive control failed: the record '$rec_name' claims $ip but the scanner cannot find it in the transaction; the absence test below would prove nothing"
            fi
        else
            fail "the conventional record '$rec_name' carries no IPv4 address to control with"
        fi
    else
        fail "no conventional record is registered; the no-IP claim has no positive control"
    fi

    if [ -z "$rv_name" ]; then
        feature "idns-private-tor" BLOCKED "-" "no rendezvous descriptor name is registered"
    else
        local rz; rz="$(rpc "${NODE_NAMES[0]}" name_rendezvous "$rv_name" 2>&1)"
        local kind host; kind="$(jget "$rz" kind)"; host="$(jget "$rz" host)"
        if [ "$kind" = "rendezvous" ]; then
            pass "'$rv_name' classifies as a rendezvous descriptor for $host"
        else
            fail "'$rv_name' classifies as '$kind', not a rendezvous descriptor"
        fi
        # The descriptor's transaction must contain no IPv4 address at all --
        # neither its own nor the control's.
        local raw; raw="$(raw_tx "${NODE_NAMES[0]}" "$rv_tx")"
        local anyip; anyip="$(printf '%s' "$raw" | python3 -c '
import re, sys
b = bytes.fromhex(sys.stdin.read().strip())
hits = re.findall(rb"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", b)
print(b"|".join(hits).decode("latin1") if hits else "")')"
        local ctrlhit="absent"
        if [ -n "$rec_name" ]; then
            local ip2; ip2="$(printf '%s' "$rec_val" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)"
            [ -n "$ip2" ] && ctrlhit="$(python3 "$DECODE" scanip "$raw" "$ip2" 2>/dev/null | jq_path present)"
        fi
        if [ -z "$anyip" ]; then
            pass "the descriptor's own on-chain bytes contain no IPv4 address in any form (control's IP: $ctrlhit)"
        else
            fail "the descriptor's transaction contains an address: $anyip"
        fi
        local conn; conn="$(rpc "${NODE_NAMES[0]}" name_rendezvous "$rv_name" true 2>&1)"
        local dialed; dialed="$(jget "$conn" connected)"
        if [ "$dialed" = "true" ]; then
            pass "the node dialled $host through its SOCKS endpoint and never learned an address for it"
        else
            info "the dial did not complete: $(jget "$conn" connect_error)"
        fi
        if [ "$control" -eq 1 ] && [ -z "$anyip" ] && [ "$kind" = "rendezvous" ]; then
            feature "idns-private-tor" EXERCISED "tx=${rv_tx:0:16} (control tx=${rec_tx:0:16})" \
                "'$rv_name' resolves to $host with no IPv4 anywhere in its bytes, against a control record that does carry its IP on chain; dial=${dialed:-not-attempted}"
        else
            feature "idns-private-tor" CONFIGURED-ONLY "tx=${rv_tx:0:16}" \
                "descriptor kind=$kind, IPs found='$anyip', positive control present=$control"
        fi
    fi

    # Names registered below the reset height are expired; registration resumes at
    # and above it. The applied height is read from the node's startup log line.
    local i reset=""
    for i in "${!NODE_NAMES[@]}"; do
        local ln
        ln="$(on_host "${NODE_HOSTS[$i]}" "grep -m1 'IDNS reset rehearsal: height=' ${NODE_DIRS[$i]}/regtest/debug.log 2>/dev/null" 2>/dev/null)"
        local v; v="$(printf '%s' "$ln" | sed -n 's/.*height=\([0-9]*\).*/\1/p')"
        [ -n "$v" ] && { [ -z "$reset" ] && reset="$v"; [ "$v" != "$reset" ] && reset="MIXED"; }
    done
    if [ -z "$reset" ] || [ "$reset" = "0" ]; then
        fail "no node applied an IDNS reset height, so the reset is not in force on this chain"
        feature "idns-reset" BLOCKED "-" "no node logged an IDNS reset rehearsal height"
        return 0
    fi
    if [ "$reset" = "MIXED" ]; then
        fail "the nodes applied different IDNS reset heights"
        feature "idns-reset" BLOCKED "-" "the fleet disagrees on the reset height"
        return 0
    fi
    pass "every node applied the IDNS reset at height $reset"

    # Which side of the reset each registered name sits on, from the chain.
    local above=0 below=0 above_name="" nm2
    while IFS=$'\t' read -r nm2 _ _; do
        [ -n "$nm2" ] || continue
        local sh; sh="$(jget "$(rpc "${NODE_NAMES[0]}" name_show "$nm2" 2>/dev/null)" height)"
        is_int "${sh:-x}" || continue
        if [ "$sh" -ge "$reset" ]; then
            above=$((above+1)); [ -z "$above_name" ] && above_name="$nm2@$sh"
        else
            below=$((below+1))
        fi
    done <<< "$rows"
    info "$above name(s) registered at or above the reset height, $below below it"
    if [ "$above" -gt 0 ]; then
        pass "registration works at and above the reset: '$above_name' is active"
        feature "idns-reset" EXERCISED "$above_name (reset h=$reset)" \
            "the reset is in force at height $reset on every node and $above name(s) registered and stayed active at or above it; $below name(s) predate it"
    else
        feature "idns-reset" CONFIGURED-ONLY "reset h=$reset" \
            "the reset is in force on every node but no name was registered at or above it, so only the gate was read"
    fi
}

# ---------------------------------------------------------------------------
check_cold_staking() {
    header "13. Cold staking"
    local gate; gate="$(rpc "${NODE_NAMES[0]}" getcoldstakinginfo 2>&1)"
    local enabled fork bal nstaker nowner
    enabled="$(jget "$gate" enabled)"; fork="$(jget "$gate" fork_height)"
    bal="$(jget "$gate" cold_staking_balance)"
    nstaker="$(jget "$gate" staker_utxo_count)"; nowner="$(jget "$gate" owner_utxo_count)"
    info "cold staking enabled=$enabled from height $fork; balance $bal, $nstaker staker / $nowner owner output(s)"

    # A delegated output is a consensus object, so every node is asked.
    local n confirmed=0 detail="" first=""
    for n in "${NODE_NAMES[@]}"; do
        local u; u="$(rpc "$n" listcoldutxos 2>/dev/null)"
        local c; c="$(printf '%s' "$u" | python3 -c 'import json,sys
try: print(len(json.load(sys.stdin)))
except Exception: print(0)')"
        detail="$detail $n=$c"
        if [ "${c:-0}" -gt 0 ] && [ -z "$first" ]; then
            first="$(printf '%s' "$u" | python3 -c 'import json,sys
v=json.load(sys.stdin)[0]
print("%s %s %s %s" % (v.get("txid",""), v.get("vout"), v.get("amount"), v.get("confirmations")))')"
            confirmed=$((confirmed + c))
        fi
    done
    info "cold outputs per node:$detail"

    # The M-of-N cold-stake side: a minted delegation the wallet can name.
    local mofn; mofn="$(rpc "${NODE_NAMES[0]}" n_coldstakeinfo 2>&1)"
    local nmofn; nmofn="$(printf '%s' "$mofn" | python3 -c 'import json,sys
try:
    v=json.load(sys.stdin)
    print(v.get("count", len(v.get("delegations", []))))
except Exception: print(0)')"
    is_int "${nmofn:-x}" || nmofn=0
    [ "$nmofn" -gt 0 ] && info "n_coldstakeinfo reports $nmofn M-of-N delegation(s)"

    if [ -z "$first" ] && [ "$nmofn" -eq 0 ]; then
        fail "no cold-staked output and no M-of-N delegation exist on this chain"
        feature "cold-staking" BLOCKED "-" \
            "cold staking is gated open from height $fork but nothing was delegated; a gate is not exercise"
        return 1
    fi

    local ctx cvout camt cconf
    if [ -n "$first" ]; then
        read -r ctx cvout camt cconf <<< "$first"
        pass "a delegated cold output is confirmed on chain: ${ctx:0:16}:$cvout for $camt, $cconf confirmation(s)"
        # The delegation exists only while the chain holds the output; read presence
        # from the chain, not the wallet list.
        local out; out="$(rpc "${NODE_NAMES[0]}" gettxout "$ctx" "$cvout" 2>/dev/null)"
        local unspent; unspent="$(jget "$out" value)"
        if [ -n "$unspent" ]; then
            pass "the output is unspent in the UTXO set at $unspent: the delegation stands"
            SPENT_NOTE="minted and standing; no spend or revoke on this chain"
        else
            pass "the output no longer appears in the UTXO set: it was spent or revoked"
            SPENT_NOTE="minted and then spent or revoked"
        fi
    fi
    feature "cold-staking" EXERCISED "${ctx:0:16}:${cvout:-} ${nmofn:+(+$nmofn M-of-N)}" \
        "cold staking open from height $fork; $SPENT_NOTE; balance $bal across $nstaker staker / $nowner owner output(s)"
}

# ---------------------------------------------------------------------------
# Run this last: it stops the fleet and reads each node's exit code on its own.
check_clean_shutdown() {
    header "17. Clean shutdown, every node checked individually"
    if [ "${IV5_EVIDENCE_SHUTDOWN:-0}" != "1" ]; then
        skip "the fleet is left running; set IV5_EVIDENCE_SHUTDOWN=1 for the final pass"
        feature "clean-shutdown" CONFIGURED-ONLY "-" "not attempted: the fleet is still needed"
        return 0
    fi
    local n i rc ok=1 rows=""
    for n in "${NODE_NAMES[@]}"; do
        i="$(node_index "$n")"
        # The daemon's own pid, so the exit status read below is that node's and
        # not another's.
        local pid
        pid="$(on_host "${NODE_HOSTS[$i]}" "cat ${NODE_DIRS[$i]}/regtest/innovad.pid 2>/dev/null" 2>/dev/null | tr -d '[:space:]')"
        rpc "$n" stop >/dev/null 2>&1
        local waited=0 alive=1
        while [ "$waited" -lt 120 ]; do
            if [ -n "$pid" ]; then
                if ! on_host "${NODE_HOSTS[$i]}" "kill -0 $pid 2>/dev/null"; then alive=0; break; fi
            else
                # No pid file: fall back to the RPC going away.
                local h; h="$(height "$n")"
                is_int "${h:-x}" || { alive=0; break; }
            fi
            sleep 3; waited=$((waited+3))
        done
        if [ "$alive" -eq 0 ]; then
            # A clean stop removes its pid file and leaves no "Aborted"/"Assertion"
            # line behind it.
            local dirty
            dirty="$(on_host "${NODE_HOSTS[$i]}" "tail -200 ${NODE_DIRS[$i]}/regtest/debug.log 2>/dev/null | grep -cE 'Assertion|Aborted|terminate called|Segmentation'" 2>/dev/null | tr -d '[:space:]')"
            local shutdown_line
            shutdown_line="$(on_host "${NODE_HOSTS[$i]}" "tail -50 ${NODE_DIRS[$i]}/regtest/debug.log 2>/dev/null | grep -c 'Shutdown : done'" 2>/dev/null | tr -d '[:space:]')"
            if [ "${dirty:-0}" = "0" ] && [ "${shutdown_line:-0}" != "0" ]; then
                pass "$n stopped on the stop RPC in ${waited}s, logged 'Shutdown : done', and left no abort in its log"
                rows="$rows $n=clean"
            else
                fail "$n stopped but its log shows $dirty abort line(s) and $shutdown_line completed-shutdown line(s)"
                rows="$rows $n=dirty"; ok=0
            fi
        else
            fail "$n did not stop within ${waited}s"
            rows="$rows $n=hung"; ok=0
        fi
    done
    if [ "$ok" -eq 1 ]; then
        feature "clean-shutdown" EXERCISED "$rows" \
            "every node stopped on the stop RPC, logged a completed shutdown, and left no abort behind; checked one node at a time"
    else
        feature "clean-shutdown" BLOCKED "$rows" "a node did not shut down cleanly"
    fi
}

# ---------------------------------------------------------------------------
check_poem() {
    header "14. POEM entropy"
    # The entropy the node reports must equal the entropy recomputed from the
    # block's own hash by an independent implementation of GetBlockEntropy.
    local h="$COMMON_HEIGHT" agreed=0 checked=0 mismatched=""
    local i
    for i in 0 1 2; do
        BLOCK_Q=$(( h - i ))
        [ "$BLOCK_Q" -ge 1 ] || continue
        local bh; bh="$(block_hash "${NODE_NAMES[0]}" "$BLOCK_Q")"
        local reported; reported="$(jget "$(get_block "${NODE_NAMES[0]}" "$BLOCK_Q")" entropy)"
        [ -n "$reported" ] || continue
        local recomputed; recomputed="$(python3 "$DECODE" entropy "$bh")"
        checked=$((checked+1))
        if [ "$reported" = "$recomputed" ]; then
            agreed=$((agreed+1))
        else
            mismatched="$mismatched h=$BLOCK_Q(node=$reported mine=$recomputed)"
        fi
    done
    if [ "$checked" -eq 0 ]; then
        fail "no block reports an entropy field"
        feature "poem-entropy" BLOCKED "-" "getblock reports no entropy field at the tip"
        return 1
    fi
    if [ "$agreed" -eq "$checked" ]; then
        pass "$agreed of $checked blocks: the node's entropy equals an independent recomputation from the block hash"
    else
        fail "entropy mismatch:$mismatched"
    fi
    BLOCK_Q="$h"
    local ok=1
    agree_on "the POEM entropy at height $h" r_block_entropy || ok=0
    if [ "$agreed" -eq "$checked" ] && [ "$ok" -eq 1 ]; then
        feature "poem-entropy" EXERCISED "h=$h" \
            "entropy $AGREE_VALUE reported identically by all ${#NODE_NAMES[@]} nodes and reproduced independently from the block hash ($checked blocks checked)"
    else
        feature "poem-entropy" CONFIGURED-ONLY "h=$h" "entropy is reported but does not verify: $mismatched$AGREE_WHY"
    fi
}

# ---------------------------------------------------------------------------
check_pod() {
    header "15. Proof-of-data"
    # The only check here that puts a transaction on the chain. A read-only
    # pass can be taken at any time without touching the driver's wallet.
    if [ "${IV5_EVIDENCE_READONLY:-0}" = "1" ]; then
        skip "proof-of-data needs to stamp a transaction; IV5_EVIDENCE_READONLY is set"
        feature "proof-of-data" CONFIGURED-ONLY "-" "not attempted: read-only pass"
        return 0
    fi
    local f="$OUT_DIR/pod-payload.bin"
    python3 -c "open('$f','wb').write(b'innova one-chain evidence proof-of-data\n' * 64)"
    local sha; sha="$(python3 -c "import hashlib;print(hashlib.sha256(open('$f','rb').read()).hexdigest())")"
    # The digest form: no node needs the file. Stamp from the driver's node and
    # verify from a DIFFERENT node with the digest alone.
    local stamp; stamp="$(rpc "${NODE_NAMES[0]}" proofofdata "$sha" false 2>&1)"
    local txid; txid="$(jget "$stamp" podtxid)"
    if [ ${#txid} -ne 64 ]; then
        fail "proofofdata did not stamp: $(printf '%s' "$stamp" | head -c 200)"
        feature "proof-of-data" BLOCKED "-" "proofofdata failed on ${NODE_NAMES[0]}"
        return 1
    fi
    pass "a proof-of-data stamp was anchored for digest ${sha:0:16} (tx ${txid:0:16})"
    # It has to confirm before a peer can verify it.
    local waited=0 bh=""
    while [ "$waited" -lt 90 ]; do
        bh="$(jget "$(rpc "${NODE_NAMES[0]}" gettransaction "$txid" 2>/dev/null)" blockhash)"
        [ ${#bh} -eq 64 ] && break
        sleep 5; waited=$((waited+5))
    done
    if [ ${#bh} -ne 64 ]; then
        fail "the stamp did not confirm within ${waited}s"
        feature "proof-of-data" CONFIGURED-ONLY "tx=${txid:0:16}" "the stamp was built but never confirmed"
        return 1
    fi
    local ph; ph="$(jget "$(rpc "${NODE_NAMES[0]}" getblock "$bh" 2>/dev/null)" height)"
    pass "the stamp confirmed at height $ph"
    local peer="${NODE_NAMES[1]:-${NODE_NAMES[0]}}"
    local v; v="$(rpc "$peer" podverify "$sha" "$txid" 2>&1)"
    local m; m="$(jget "$v" match)"
    if [ "$m" = "true" ]; then
        pass "node $peer, which holds neither the file nor file-RPC access, verifies the stamp from the digest alone"
    else
        fail "node $peer could not verify the stamp: $(printf '%s' "$v" | head -c 200)"
    fi
    # A detector that cannot refuse proves nothing.
    local wrong; wrong="$(rpc "$peer" podverify "0000000000000000000000000000000000000000000000000000000000000001" "$txid" 2>&1)"
    if [ "$(jget "$wrong" match)" = "true" ]; then
        fail "podverify accepted a digest the stamp does not carry; the positive result above is worthless"
        feature "proof-of-data" BLOCKED "tx=${txid:0:16}" "podverify cannot refuse a wrong digest"
        return 1
    fi
    pass "podverify refuses a digest the stamp does not carry"
    if [ "$m" = "true" ]; then
        feature "proof-of-data" EXERCISED "tx=${txid:0:16} h=$ph" \
            "digest ${sha:0:16} stamped on ${NODE_NAMES[0]}, confirmed at $ph, verified by $peer from the digest alone, and a wrong digest refused"
    else
        feature "proof-of-data" CONFIGURED-ONLY "tx=${txid:0:16} h=$ph" "the peer could not verify the confirmed stamp"
    fi
}

# ---------------------------------------------------------------------------
check_determinism() {
    header "16. Cross-node determinism"
    # A field no node reports is a coverage gap, reported separately from a
    # disagreement.
    local agreed=0 differed=0 absent="" summary="" empty=""
    det() {
        local label="$1" reader="$2"
        if agree_on "$label" "$reader"; then
            # An all-zero root means the object was never built; it does not count toward
            # determinism.
            case "$AGREE_VALUE" in
                0|0.0|0x0|0000000000000000000000000000000000000000000000000000000000000000)
                    info "$label is unset (all zero) on every node; not counted as an agreed value"
                    empty="$empty $label"
                    return ;;
            esac
            agreed=$((agreed+1))
            summary="$summary; $label=$AGREE_SHORT"
        elif [ "$AGREE_ABSENT" = "1" ]; then
            absent="$absent $label"
        else
            differed=$((differed+1))
            DIFF_WHY="$DIFF_WHY [$label:$AGREE_WHY]"
        fi
    }
    DIFF_WHY=""
    det "finalized hash" r_finalized_hash
    det "epoch nullifier root" r_epoch_null_root
    det "epoch curve root" r_epoch_curve_root
    EPOCH_Q=$(( CUR_EPOCH > 1 ? CUR_EPOCH - 1 : 1 ))
    det "epoch $EPOCH_Q state digest" r_epoch_digest
    det "epoch $EPOCH_Q IV5 tree root" r_epoch_treeroot
    det "epoch $EPOCH_Q nullifier root" r_epoch_nullroot
    det "epoch $EPOCH_Q block ordering" r_epoch_ordering
    [ -n "$absent" ] && info "not carried by this chain:$absent"
    [ -n "$empty" ] && info "unset (all zero) on every node:$empty"

    # Required by name: nullifier root, tree root, epoch state digest and epoch
    # ordering. The finalized hash is reported under epoch finality instead.
    local need_missing=""
    case "$summary" in *"nullifier root"*) : ;; *) need_missing="$need_missing nullifier-root" ;; esac
    case "$summary" in *"tree root"*) : ;; *) need_missing="$need_missing tree-root" ;; esac
    case "$summary" in *"state digest"*) : ;; *) need_missing="$need_missing epoch-state-digest" ;; esac
    case "$summary" in *"block ordering"*) : ;; *) need_missing="$need_missing epoch-ordering" ;; esac

    if [ "$differed" -gt 0 ]; then
        feature "cross-node-determinism" BLOCKED "epoch=$EPOCH_Q" \
            "$differed consensus value(s) differ across the fleet:$DIFF_WHY"
    elif [ -z "$need_missing" ]; then
        feature "cross-node-determinism" EXERCISED "epoch=$EPOCH_Q" \
            "$agreed non-zero consensus values byte-identical on all ${#NODE_NAMES[@]} nodes, including the nullifier root, the IV5 tree root, the epoch state digest and the whole epoch ordering${summary}${empty:+; still unset on every node (reported against their own features):$empty}"
    else
        feature "cross-node-determinism" CONFIGURED-ONLY "epoch=$EPOCH_Q" \
            "$agreed value(s) agreed but these were not among them:$need_missing; unset on every node:${empty:- none}; not carried:${absent:- none}"
    fi
}

# ---------------------------------------------------------------------------
run_all_checks() {
    load_ladder
    check_fleet_up || return
    # One pass over the chain into a cache, so every scan below reads the same
    # blocks once rather than re-fetching them per feature.
    header "Sweeping the chain"
    sweep_chain "${NODE_NAMES[0]}" 1 "$COMMON_HEIGHT"
    check_idag
    check_merge_block
    check_finality_transparent
    check_finality_private_cert
    check_note_votes
    check_nullstake_voting
    check_masks
    check_fee_note
    check_ms_timestamps
    check_one_coinbase_three_features
    check_supply_cap
    check_collateralnodes
    check_idns
    check_cold_staking
    check_poem
    check_pod
    check_determinism
    check_clean_shutdown
}
