# Copyright (c) 2026 The Innova developers
# One pass over the chain into a cache keyed by height and block hash; every feature
# scan reads the cache. A changed hash is refetched. Columns are raw.

SWEEP_CACHE=""
SWEEP_NODE=""

# h  hash  cbver  idag_count  idag_parents  imts  fee_vb  fee_fee  fee_mask
# dagparents  ntx  vote_modes  cert_versions  cert_sethashes
sweep_one() {
    local node="$1" h="$2"
    local bh; bh="$(block_hash "$node" "$h")"
    [ ${#bh} -eq 64 ] || return 1
    local bj; bj="$(rpc "$node" getblock "$bh" 2>/dev/null)"
    [ -n "$bj" ] || return 1
    local cb; cb="$(printf '%s' "$bj" | jq_path tx 0)"
    [ ${#cb} -eq 64 ] || return 1
    local raw; raw="$(raw_tx "$node" "$cb")"
    [ -n "$raw" ] || return 1
    local cbdec iv5dec
    cbdec="$(python3 "$DECODE" coinbase "$raw" 2>/dev/null)"
    iv5dec="$(python3 "$DECODE" iv5 "$raw" 2>/dev/null)"
    printf '%s\t%s\t' "$h" "$bh"
    printf '%s\t%s\t' "$cbdec" "$iv5dec" | python3 -c '
import json, sys
cb_raw, iv5_raw = sys.stdin.read().split("\t")[:2]
try: cb = json.loads(cb_raw)
except Exception: cb = {}
try: iv = json.loads(iv5_raw)
except Exception: iv = {}
idag_n, idag_p, imts = 0, "-", "-"
for r in cb.get("op_returns", []):
    if r.get("tag") == "IDAG":
        idag_n = r.get("count", 0); idag_p = ",".join(r.get("parents", [])) or "-"
    elif r.get("tag") == "IMTS":
        imts = r.get("offset_ms")
fee_vb = iv.get("value_balance", "-") if iv.get("iv5") else "-"
fee_fee = iv.get("fee", "-") if iv.get("iv5") else "-"
fee_mask = iv.get("disclosure_mask", "-") if iv.get("iv5") else "-"
sys.stdout.write("%s\t%d\t%s\t%s\t%s\t%s\t%s" %
                 (cb.get("version", "-"), idag_n, idag_p, imts, fee_vb, fee_fee, fee_mask))
'
    printf '\t'
    printf '%s' "$bj" | python3 -c '
import json, sys
try: b = json.load(sys.stdin)
except Exception: b = {}
dp = len(b.get("dagparents", []) or [])
ntx = len(b.get("tx", []) or [])
votes = ";".join("%s/%s" % (v.get("proof_mode"), v.get("auth_mode", "-"))
                 for v in b.get("finality_votes", []) or []) or "-"
certs = ";".join("%s" % c.get("version") for c in b.get("finality_tally_certificates", []) or []) or "-"
sets  = ";".join("%s" % c.get("committee_set_hash") for c in b.get("finality_tally_certificates", []) or []) or "-"
sys.stdout.write("%d\t%d\t%s\t%s\t%s" % (dp, ntx, votes, certs, sets))
'
    printf '\n'
}

# Fill the cache for lo..hi, refetching only what is missing or whose hash moved.
sweep_chain() {
    local node="$1" lo="$2" hi="$3"
    SWEEP_NODE="$node"
    SWEEP_CACHE="$OUT_DIR/sweep-$node.tsv"
    touch "$SWEEP_CACHE"
    local have; have="$(awk -F'\t' '{print $1}' "$SWEEP_CACHE" | sort -n | uniq | tr '\n' ' ')"
    local h fetched=0 tip_recheck=5
    for ((h=lo; h<=hi; h++)); do
        # The last few heights are always refetched: they are the ones a reorg
        # can still move under a cached row.
        if [ "$h" -lt $(( hi - tip_recheck )) ] && \
           grep -q "^$h	" "$SWEEP_CACHE" 2>/dev/null; then
            continue
        fi
        local row; row="$(sweep_one "$node" "$h")" || continue
        # Replace any stale row for this height, then append.
        if grep -q "^$h	" "$SWEEP_CACHE" 2>/dev/null; then
            grep -v "^$h	" "$SWEEP_CACHE" > "$SWEEP_CACHE.tmp" && mv "$SWEEP_CACHE.tmp" "$SWEEP_CACHE"
        fi
        printf '%s\n' "$row" >> "$SWEEP_CACHE"
        fetched=$((fetched+1))
        if [ $((fetched % 100)) -eq 0 ]; then info "swept $fetched new block(s), at height $h"; fi
    done
    sort -n -k1,1 "$SWEEP_CACHE" -o "$SWEEP_CACHE"
    local total; total="$(wc -l < "$SWEEP_CACHE" | tr -d ' ')"
    info "sweep cache $SWEEP_CACHE holds $total block(s); $fetched fetched this pass"
}

sweep_col() { awk -F'\t' -v c="$1" '{print $1"\t"$c}' "$SWEEP_CACHE"; }

# ---------------------------------------------------------------------------
# Chain scans over the sweep cache (sweep_chain() first); each returns the height
# that carries the feature.

# Cache columns:
#  1 height  2 hash  3 cbver  4 idag_count  5 idag_parents  6 imts
#  7 fee_vb  8 fee_fee  9 fee_mask  10 dagparents  11 ntx
#  12 vote_modes  13 cert_versions  14 cert_sethashes

# Heights whose coinbase commits to more than one DAG parent. One parent is not
# a merge block, so the decoded count byte is what decides.
scan_merge_blocks() {
    local lo="$2" hi="$3"
    awk -F'\t' -v lo="$lo" -v hi="$hi" \
        '$1 >= lo && $1 <= hi && $4 > 1 {print $1, $4, $5}' "$SWEEP_CACHE"
}

# Heights whose coinbase carries a NONZERO IMTS offset. A zero offset is
# indistinguishable from an unstamped field, so zero rows are not returned.
scan_ms_offsets() {
    local lo="$2" hi="$3"
    awk -F'\t' -v lo="$lo" -v hi="$hi" \
        '$1 >= lo && $1 <= hi && $6 != "-" && $6 + 0 != 0 {print $1, $3, $6}' "$SWEEP_CACHE"
}

# Heights connecting a tally certificate, with version and committee set hash. The v4
# note lane is identified by the certificate version, not the status flags.
scan_certificates() {
    local lo="$2" hi="$3"
    awk -F'\t' -v lo="$lo" -v hi="$hi" '
$1 >= lo && $1 <= hi && $13 != "-" {
    nv = split($13, vs, ";"); ns = split($14, ss, ";")
    for (i = 1; i <= nv; i++) print $1, vs[i], (i <= ns ? ss[i] : "-")
}' "$SWEEP_CACHE"
}

# Heights carrying finality votes, with the proof mode of each.
scan_votes() {
    local lo="$2" hi="$3"
    awk -F'\t' -v lo="$lo" -v hi="$hi" '
$1 >= lo && $1 <= hi && $12 != "-" {
    n = split($12, vs, ";")
    for (i = 1; i <= n; i++) {
        split(vs[i], p, "/")
        print $1, p[1], p[2]
    }
}' "$SWEEP_CACHE"
}

# Coinbases carrying an IV5 fee note: a version-2008 coinbase whose decoded
# payload declares a nonzero value balance.
scan_fee_notes() {
    local lo="$2" hi="$3"
    awk -F'\t' -v lo="$lo" -v hi="$hi" \
        '$1 >= lo && $1 <= hi && $7 != "-" && $7 + 0 != 0 {print $1, $7, $8, $9}' "$SWEEP_CACHE"
}

# Heights with more than one transaction, so the mask scan only fetches blocks
# that can carry a user transfer.
scan_multitx() {
    local lo="$2" hi="$3"
    awk -F'\t' -v lo="$lo" -v hi="$hi" '$1 >= lo && $1 <= hi && $11 > 1 {print $1}' "$SWEEP_CACHE"
}
