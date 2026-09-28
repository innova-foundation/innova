#!/usr/bin/env bash
# Every v5 feature on one regtest chain, with a PASS/FAIL line per feature. Wraps
# iv5_multi_machine_testchain.sh. Usage: [run|stop|status]; env INNOVAD, IV5RA_BASE,
# IV5RA_P2P/RPC/IDNS/MIX_BASE, IV5RA_END, IV5RA_KEEP=1.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${INNOVAD:-$ROOT/src/innovad}"
BASE="${IV5RA_BASE:-$HOME/iv5-allfeat-run}"
NODES_DIR="$BASE/nodes"
P2P_BASE="${IV5RA_P2P:-21400}"
RPC_BASE="${IV5RA_RPC:-21500}"
IDNS_BASE="${IV5RA_IDNS:-21600}"
MIX_BASE="${IV5RA_MIX_BASE:-21960}"
END_HEIGHT="${IV5RA_END:-2450}"
N_NODES=10
MINER=d9
RPCUSER=iv5tc
RPCPASS=iv5tcpass_local_only
WALLETPASS=iv5tcfleetpass
LOG="$BASE/run.log"
SUMMARY="$BASE/summary.tsv"
PACEFILE="$BASE/pace"
PACER_PIDFILE="$BASE/pacer.pid"
STUB_PIDFILE="$BASE/mixstub.pid"
HARNESS="$BASE/harness.sh"
T0=$(date +%s)

export DELL_SSH=- DELL_BIN="$BIN" DELL_BASE="$NODES_DIR" DELL_NODES=$N_NODES
export MAC_NODES=0 MAC_BASE="$BASE/unused" MAC_BIN="$BIN"
export DELL_P2P_BASE=$P2P_BASE DELL_RPC_BASE=$RPC_BASE DELL_IDNS_BASE=$IDNS_BASE
export ROLE_NOTE="d1 d2" MIX_COORD=d3 MIX_SEATS="d1 d2"
export MIX_STUB_PORT=$MIX_BASE MIX_COORD_PORT=$((MIX_BASE + 1)) MIX_DIR_PORT=$((MIX_BASE + 2))
export MIX_STUB_LOG="$BASE/mixstub.log" MIX_STUB_PIDFILE="$STUB_PIDFILE"
export WALLETPASS IV5TC_CONFDIR="$BASE"

# ---------------------------------------------------------------------------
say()  { echo "[$(date -u +%H:%M:%S) +$(( $(date +%s) - T0 ))s] $*" | tee -a "$LOG"; }
ev()   { { echo "--- $1"; printf '%s\n' "$2" | head -"${3:-40}"; } >> "$LOG"; }
result() {
  # feature verdict evidence
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$SUMMARY"
  say "$2 $1 -- $3"
}

idx() { echo "${1#d}"; }
STATE="$BASE/state.env"
st() { eval "$1=\"\$2\""; echo "$1='$2'" >> "$STATE"; }
rpc() {
  local n=$1; shift
  "$BIN" -datadir="$NODES_DIR/$n" -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS \
    -rpcport=$((RPC_BASE + $(idx "$n"))) "$@" 2>&1
}
jget() {
  printf '%s' "$1" | python3 -c '
import json, sys
try: v = json.loads(sys.stdin.read())
except Exception: sys.exit(0)
for k in sys.argv[1:]:
    try: v = v[int(k)] if isinstance(v, list) else v[k]
    except Exception: sys.exit(0)
print(("true" if v else "false") if isinstance(v, bool) else (json.dumps(v) if isinstance(v, (dict, list)) else v))
' "${@:2}"
}
height() { rpc "${1:-$MINER}" getblockcount | tr -d '"[:space:]'; }
is_int() { [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }
gt() { python3 -c 'import sys; from decimal import Decimal as D; sys.exit(0 if D(sys.argv[1] or "0") > D(sys.argv[2] or "0") else 1)' "${1:-0}" "${2:-0}" 2>/dev/null; }
ge() { python3 -c 'import sys; from decimal import Decimal as D; sys.exit(0 if D(sys.argv[1] or "0") >= D(sys.argv[2] or "0") else 1)' "${1:-0}" "${2:-0}" 2>/dev/null; }
dsum() { python3 -c 'import sys; from decimal import Decimal as D; print(sum(D(x or "0") for x in sys.argv[1:]))' "$@"; }
names() { local i; for i in $(seq 0 $((N_NODES - 1))); do echo "d$i"; done; }
unlock() { rpc "$1" walletpassphrase "$WALLETPASS" 99999999 false >/dev/null; }
finalized() { jget "$(rpc "${1:-d0}" getfinalityinfo)" finalized_height; }
tbal() { jget "$(rpc "$1" z_gettotalbalance)" "$2"; }
iv5addr() { jget "$(rpc "$1" z_getnewiv5address)" address; }
# The P2PKH address of a staking address's key: how the finality tally names the
# staker when it votes with delegated (P2CS) weight.
staker_voter_addr() {
  local pk; pk=$(jget "$(rpc d4 validateaddress "$1")" pubkey)
  local ref; ref=$(rpc d4 getaccountaddress "" | tr -d '"[:space:]')
  python3 - "$pk" "$ref" <<'PY'
import hashlib, sys
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def dec(s):
    n = 0
    for c in s: n = n * 58 + A.index(c)
    return n.to_bytes(25, "big")
def enc(b):
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = A[r] + s
    return s
try:
    h = hashlib.new("ripemd160", hashlib.sha256(bytes.fromhex(sys.argv[1])).digest()).digest()
    p = bytes([dec(sys.argv[2])[0]]) + h
    print(enc(p + hashlib.sha256(hashlib.sha256(p).digest()).digest()[:4]))
except Exception:
    print("")
PY
}

# ---------------------------------------------------------------------------
# Block production. A background pacer asks the miner for one block every
# $(cat pace) seconds, slower around epoch boundaries; 0 in the file pauses it.
pacer_start() {
  echo "${1:-1}" > "$PACEFILE"
  (
    while [ -f "$PACEFILE" ]; do
      p=$(cat "$PACEFILE" 2>/dev/null || echo 1)
      if [ "$p" != "0" ]; then
        rpc $MINER setgenerate true 1 1 >/dev/null 2>&1
        # Around each post-DAG epoch boundary (311 + k*300) the votes, a 9 KB note
        # vote proof among them, have a 24-block window to cross the whole line
        # through the dandelion stem; blocks slow to one per 6 s there (a vote measured ~10 s a hop).
        h=$(height 2>/dev/null); o=-1
        is_int "$h" && [ "$h" -ge 300 ] && o=$(( (h - 311) % 300 ))
        if [ "$o" -ge 295 ] || { [ "$o" -ge 0 ] && [ "$o" -le 30 ]; }; then sleep "${IV5RA_WINDOW_PACE:-6}"; else sleep "$p"; fi
      else sleep 1; fi
    done
  ) &
  echo $! > "$PACER_PIDFILE"
}
pace() { echo "$1" > "$PACEFILE"; }
pacer_stop() {
  rm -f "$PACEFILE"
  [ -f "$PACER_PIDFILE" ] && kill "$(cat "$PACER_PIDFILE")" 2>/dev/null
  rm -f "$PACER_PIDFILE"
  rpc $MINER setgenerate false >/dev/null 2>&1
}
wait_height() {
  local t=$1 lim=${2:-3600} s; s=$(date +%s)
  while :; do
    local h; h=$(height)
    is_int "$h" && [ "$h" -ge "$t" ] && return 0
    [ $(( $(date +%s) - s )) -gt "$lim" ] && { say "timed out waiting for height $t (at $h)"; return 1; }
    sleep 1
  done
}
# wait_for <timeout-secs> <label> <command...>: poll a predicate while blocks are produced.
wait_for() {
  local lim=$1 label=$2; shift 2
  local s; s=$(date +%s)
  while ! "$@"; do
    [ $(( $(date +%s) - s )) -gt "$lim" ] && { say "timed out ($lim s): $label"; return 1; }
    sleep 3
  done
  say "reached: $label (h=$(height), finalized=$(finalized))"
}
tx_confirmed() { local c; c=$(jget "$(rpc "$1" gettransaction "$2")" confirmations); is_int "$c" && [ "$c" -ge "${3:-1}" ]; }

# ---------------------------------------------------------------------------
preflight() {
  [ -x "$BIN" ] || { echo "no innovad at $BIN"; exit 1; }
  if pgrep -f -- "-datadir=$NODES_DIR/" >/dev/null; then
    echo "daemons are already running under $NODES_DIR; run '$0 stop' first"; exit 1
  fi
  local p used=""
  for p in $(seq $P2P_BASE $((P2P_BASE + N_NODES - 1))) $(seq $RPC_BASE $((RPC_BASE + N_NODES - 1))) \
           $(seq $IDNS_BASE $((IDNS_BASE + N_NODES - 1))) $MIX_BASE $((MIX_BASE + 1)) $((MIX_BASE + 2)); do
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$p\$" && used="$used $p"
  done
  [ -z "$used" ] || { echo "ports in use:$used"; exit 1; }
  case "$BASE" in /|"$HOME"|"$HOME/.innova"*) echo "refusing base $BASE"; exit 1 ;; esac
  rm -rf "$BASE"; mkdir -p "$BASE"
  : > "$SUMMARY"
  # The harness, with its fixed ports and host-local paths lifted into env
  # knobs. Applied to a copy so the tree's own file is untouched and an
  # already-patched harness passes through unchanged.
  cp "$SCRIPT_DIR/iv5_multi_machine_testchain.sh" "$HARNESS"
  cp "$SCRIPT_DIR/mix_socks_stub.py" "$BASE/mix_socks_stub.py"
  python3 - "$HARNESS" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
subs = [
 ('"d dell 18444 18500 18600 $DELL_NODES"',
  '"d dell ${DELL_P2P_BASE:-18444} ${DELL_RPC_BASE:-18500} ${DELL_IDNS_BASE:-18600} $DELL_NODES"'),
 ('emit_conf "$n" > "/tmp/iv5tc_$n.conf"', 'emit_conf "$n" > "${IV5TC_CONFDIR:-/tmp}/iv5tc_$n.conf"'),
 ('cp "/tmp/iv5tc_$n.conf" "$base/$n/innova.conf"', 'cp "${IV5TC_CONFDIR:-/tmp}/iv5tc_$n.conf" "$base/$n/innova.conf"'),
 ('local stub=contrib/test/mix_socks_stub.py', 'local stub; stub="$(dirname "${BASH_SOURCE[0]}")/mix_socks_stub.py"'),
 ('nohup python3 "$stub" --port "$MIX_STUB_PORT" >/tmp/iv5tc_mixstub.log 2>&1 &',
  'nohup python3 "$stub" --port "$MIX_STUB_PORT" >"${MIX_STUB_LOG:-/tmp/iv5tc_mixstub.log}" 2>&1 &\n    [ -n "${MIX_STUB_PIDFILE:-}" ] && echo $! > "$MIX_STUB_PIDFILE"'),
]
for a, b in subs:
    if b in s: continue
    if a not in s: sys.exit("harness patch point missing: " + a)
    s = s.replace(a, b)
open(p, "w").write(s)
PY
  [ $? -eq 0 ] || exit 1
  say "binary $BIN sha256 $(sha256sum "$BIN" | cut -c1-64)"
  say "version $(sed -n 's/.*BUILD_COMMIT "\(.*\)".*/\1/p' "$ROOT/src/obj/build.h" 2>/dev/null) tree $ROOT base $BASE"
}

H() { bash "$HARNESS" "$@" 2>/dev/null | tee -a "$LOG"; }

start_node() { "$BIN" -datadir="$NODES_DIR/$1" -regtest -daemon >/dev/null 2>&1; }
wait_rpc() { local i; for i in $(seq 1 "${2:-90}"); do is_int "$(height "$1")" && return 0; sleep 2; done; return 1; }
wait_down() { local i; for i in $(seq 1 150); do is_int "$(height "$1")" || { pgrep -f -- "-datadir=$NODES_DIR/$1 " >/dev/null || return 0; }; sleep 2; done; return 1; }
restart_node() {
  rpc "$1" stop >/dev/null; wait_down "$1" || { say "$1 did not stop"; return 1; }
  local a; for a in 1 2 3 4 5; do start_node "$1"; wait_rpc "$1" 15 && return 0; sleep 3; done; return 1
}
# Encrypt -> restart -> unlock -> seed, for a wallet the harness does not seed.
seed_wallet() {
  local n=$1
  rpc "$n" encryptwallet "$WALLETPASS" >/dev/null
  wait_down "$n" || { say "$n did not stop after encryptwallet"; return 1; }
  local a; for a in 1 2 3 4 5; do start_node "$n"; wait_rpc "$n" 15 && break; sleep 3; done
  unlock "$n"
  rpc "$n" z_createiv5seed >/dev/null
  local addr; addr=$(iv5addr "$n")
  [ -n "$addr" ] && say "$n encrypted and seeded (${addr:0:20}...)"
}

# ---------------------------------------------------------------------------
phase_bringup() {
  say "== bring-up: $N_NODES nodes, ports p2p $P2P_BASE rpc $RPC_BASE idns $IDNS_BASE mix $MIX_BASE"
  H setup >/dev/null
  local n; for n in $(names); do
    grep -q "^rpcport=$((RPC_BASE + $(idx "$n")))\$" "$NODES_DIR/$n/innova.conf" 2>/dev/null \
      || { result bringup FAIL "$n has no harness config"; return 1; }
  done
  H start >/dev/null
  for n in $(names); do wait_rpc "$n" || { result bringup FAIL "$n never answered RPC"; return 1; }; done
  # The collateral key has to be in d6's config before its encrypt restart.
  local key; key=$(rpc d6 collateralnode genkey | tr -d '"[:space:]')
  echo "collateralnodeprivkey=$key" >> "$NODES_DIR/d6/innova.conf"
  H prepare
  seed_wallet d5; seed_wallet d6
  H relink >/dev/null
  sleep 5
  local peers=""; for n in $(names); do peers="$peers $n:$(rpc "$n" getconnectioncount | tr -d '[:space:]')"; done
  say "peers:$peers"
  local s=0; for n in d1 d2 d3 d5 d6; do [ -n "$(iv5addr "$n")" ] && s=$((s + 1)); done
  [ "$s" -eq 5 ] && result "seeded-wallets" PASS "d1 d2 d3 d5 d6 encrypted, restarted, unlocked and seeded" \
                 || result "seeded-wallets" FAIL "$s of 5 seeded"
}

send() { rpc $MINER sendtoaddress "$(rpc "$1" getnewaddress | tr -d '"[:space:]')" "$2" | tr -d '"[:space:]'; }

# fund <node> <amount>: pay a fresh address of the node once the miner holds enough.
fund() {
  local n=$1 amt=$2 i tx
  for i in $(seq 1 600); do
    ge "$(rpc $MINER getbalance | tr -d '[:space:]')" "$((amt + 5))" && break
    sleep 1
  done
  tx=$(send "$n" "$amt"); ev "fund $n $amt at h=$(height)" "$tx"
  [ ${#tx} -eq 64 ] || { say "funding $n $amt failed: $tx"; return 1; }
}

phase_prefork() {
  say "== pre-Boundary-B: funding, cold-staking delegation, IDNS"
  pacer_start 0.3
  wait_height 20
  local ok=1
  # The transparent voter's stake and the owner's coin predate the 311 boundary.
  fund d0 600 && fund d0 600 && fund d7 700 && fund d8 50 || ok=0
  wait_height 90
  # Cold staking: the gate is 80. d4 holds no coin of its own, so any finality
  # weight it shows comes from the delegation.
  STAKER_ADDR=$(rpc d4 getnewstakingaddress | tr -d '"[:space:]'); st STAKER_ADDR "$STAKER_ADDR"
  local dg; dg=$(rpc d7 delegatestake "$STAKER_ADDR" 600)
  ev "delegatestake d7 -> d4 $STAKER_ADDR 600" "$dg"
  DELEG_TX=$(jget "$dg" txid); st DELEG_TX "$DELEG_TX"
  if [ ${#DELEG_TX} -eq 64 ]; then result "cold-stake-delegate" PASS "d7 delegatestake $STAKER_ADDR 600 -> $DELEG_TX at h=$(height)"
  else result "cold-stake-delegate" FAIL "delegatestake: $(echo "$DELEG_TX" | head -c 200)"; fi
  local n
  # A note vote spends a note of at least 500 INN and z_shieldall splits at a random
  # point, so only a 1000 INN shield guarantees one votable note. Three shields per
  # voter since a reissued note is not reusable within the run.
  for n in d1 d1 d1 d2 d2 d2; do fund "$n" 1000 || ok=0; done
  fund d3 300 || ok=0; fund d5 1500 || ok=0
  wait_height 215
  # IDNS registration above the reset gate (200). Not from d7: an ordinary
  # send from the owner's wallet may select the delegated output as an input.
  local nn; nn=$(rpc d8 name_new iv5ra 127.0.0.1 30)
  ev "name_new iv5ra" "$nn"
  NAME_TX=$(printf '%s' "$nn" | grep -o '[0-9a-f]\{64\}' | head -1); st NAME_TX "$NAME_TX"
  [ "$ok" -eq 1 ] && result "funding" PASS "d0 2x600, d7 700, d8 50, d1/d2 3x1000, d3 300, d5 1500 before h=311" \
                  || result "funding" FAIL "a funding payment failed (see run.log)"
  wait_height 318
}

phase_shield() {
  say "== Boundary B crossed: shields"
  local n out ok=0 tot=0 txs=""
  for n in d1 d1 d1 d2 d2 d2 d3 d5; do
    unlock "$n"
    out=$(rpc "$n" z_shieldall)
    ev "z_shieldall $n" "$out"
    local t; t=$(jget "$out" txid)
    [ ${#t} -eq 64 ] && { ok=$((ok + 1)); txs="$txs $n:${t:0:12}"; }
    tot=$((tot + 1))
  done
  SHIELD_H=$(height); st SHIELD_H "$SHIELD_H"
  [ "$ok" -eq "$tot" ] && result "shield-z_shieldall" PASS "$ok/$tot shields broadcast at h=$SHIELD_H:$txs" \
                       || result "shield-z_shieldall" FAIL "$ok/$tot shields broadcast:$txs"
}

phase_finality_early() {
  pace "${IV5RA_PACE:-0.8}"
  wait_height 400
  local si; si=$(rpc d4 getfinalitystakinginfo); ev "d4 getfinalitystakinginfo" "$si" 60
  local lc; lc=$(rpc d7 listcoldutxos); ev "d7 listcoldutxos" "$lc"
  local d4bal; d4bal=$(rpc d4 getbalance | tr -d '[:space:]')
  STAKER_VOTER=$(staker_voter_addr "$STAKER_ADDR"); st STAKER_VOTER "$STAKER_VOTER"
  local fi; fi=$(rpc d0 getfinalityinfo); ev "d0 getfinalityinfo voters" "$(jget "$fi" voters)"
  # getfinalitystakinginfo counts only outputs whose OWNER key the wallet holds,
  # so a pure staker reads eligible_utxos 0 there; the tally is the evidence.
  if [ -n "$STAKER_VOTER" ] && echo "$fi" | grep -q "$STAKER_VOTER" && echo "$lc" | grep -q "$DELEG_TX"; then
    result "cold-stake-delegated-weight" PASS "staker d4 (own coin $d4bal = vote rewards only) votes in epoch $(jget "$fi" epoch) as $STAKER_VOTER on the delegated output; owner d7 still lists $DELEG_TX (getfinalitystakinginfo on d4 reads eligible_utxos=$(jget "$si" eligible_utxos))"
  else
    result "cold-stake-delegated-weight" FAIL "staker voter '$STAKER_VOTER' in voters=$(echo "$fi" | grep -c "$STAKER_VOTER"); owner lists deleg=$(echo "$lc" | grep -c "$DELEG_TX")"
  fi
  # The staker's own coin is its vote reward; asking for more than that can only be
  # met from the delegated output, which the staker must not be able to spend.
  local want; want=$(python3 -c 'import sys; from decimal import Decimal as D; print(D(sys.argv[1] or "0") + 100)' "$d4bal")
  local st; st=$(rpc d4 sendtoaddress "$(rpc d9 getnewaddress | tr -d '"[:space:]')" "$want")
  ev "d4 spend attempt of $want (own $d4bal + delegated 600)" "$st"
  if [ ${#st} -ne 64 ] && rpc d7 listcoldutxos | grep -q "$DELEG_TX"; then result "cold-stake-staker-cannot-spend" PASS "d4 (own $d4bal) sendtoaddress $want refused: $(echo "$st" | tr -d '\n' | head -c 100); delegation still unspent"
  else result "cold-stake-staker-cannot-spend" FAIL "staker spend of $want: $st"; fi
  # IDNS resolves on another node.
  d0_has_name() { rpc d0 name_show iv5ra | grep -q '"value"'; }
  wait_for 300 "d0 sees iv5ra" d0_has_name
  local sh; sh=$(rpc d0 name_show iv5ra); ev "d0 name_show iv5ra" "$sh"
  if [ "$(jget "$sh" value)" = "127.0.0.1" ]; then
    result "idns-register-resolve" PASS "d8 name_new iv5ra at h>200 (reset gate); d0 name_show value=127.0.0.1 height=$(jget "$sh" height) txid=$(jget "$sh" txid | cut -c1-16)"
  else result "idns-register-resolve" FAIL "d0 name_show: $(echo "$sh" | tr -d '\n' | head -c 200)"; fi
}

# The transfer anchors on a finalized epoch whose tree holds d5's notes.
d5_spendable() { gt "$(tbal d5 shielded)" 1200; }
d5_change_spendable() { gt "$(tbal d5 shielded)" 100; }
phase_transfer() {
  say "== waiting for d5's shielded notes to become spendable (finality)"
  wait_for 3000 "d5 shielded notes spendable" d5_spendable || { result "iv5-transfer" FAIL "d5 never had spendable notes: $(rpc d5 z_gettotalbalance | tr -d '\n ')"; return 1; }
  RECV_ADDR=$(iv5addr d6); st RECV_ADDR "$RECV_ADDR"
  local before; before=$(rpc d5 z_gettotalbalance); ev "d5 before transfer" "$before"
  unlock d5
  local out; out=$(rpc d5 z_iv5transfer "$RECV_ADDR" 1000)
  ev "d5 z_iv5transfer d6 1000" "$out"
  XFER_TX=$(jget "$out" txid); XFER_NOTE=$(jget "$out" recipient_note)
  # The first transfer can spend every note d5 holds; the second waits for its change.
  wait_for 600 "transfer confirmed on d6" tx_confirmed d5 "$XFER_TX" 3
  wait_for 1800 "d5 change spendable" d5_change_spendable
  local out2; out2=$(rpc d5 z_iv5transfer "$RECV_ADDR" 100)
  ev "d5 z_iv5transfer d6 100" "$out2"
  HOLD_NOTE=$(jget "$out2" recipient_note); XFER2_TX=$(jget "$out2" txid); st HOLD_NOTE "$HOLD_NOTE"
  [ ${#XFER_TX} -eq 64 ] || { result "iv5-transfer" FAIL "z_iv5transfer: $(echo "$out" | tr -d '\n' | head -c 200)"; return 1; }
  wait_for 600 "transfer confirmed on d6" tx_confirmed d5 "$XFER_TX" 3
  wait_for 300 "second transfer confirmed" tx_confirmed d5 "$XFER2_TX" 3
  sleep 5
  local rv; rv=$(rpc d6 z_gettotalbalance); ev "d6 after transfer" "$rv"
  local after; after=$(rpc d5 z_gettotalbalance); ev "d5 after transfer" "$after"
  local rtot; rtot=$(dsum "$(jget "$rv" shielded)" "$(jget "$rv" shielded_pending)")
  local sp; sp=$(jget "$after" shielded_pending)
  if ge "$rtot" 1100 && gt "$sp" 0; then
    result "iv5-transfer" PASS "d5 -> d6 1000 + 100 ($XFER_TX, fee $(jget "$out" fee), mask $(jget "$out" disclosure_mask)); d6 owns $rtot; d5 change pending $sp"
  else result "iv5-transfer" FAIL "d6 owns $rtot (want >=1100); d5 pending $sp"; fi
}

phase_viewkey() {
  local vk; vk=$(rpc d6 z_exportiv5viewingkey all); ev "d6 z_exportiv5viewingkey" "$(echo "$vk" | sed 's/"viewingkey" : "\(.\{24\}\).*"/"viewingkey" : "\1..."/')"
  local key; key=$(jget "$vk" viewingkey)
  local im; im=$(rpc d7 z_importiv5viewingkey "$key" true 0); ev "d7 z_importiv5viewingkey" "$im"
  local wo; wo=$(tbal d7 shielded_watchonly)
  local sp; sp=$(rpc d7 z_iv5transfer "$RECV_ADDR" 1); ev "d7 spend attempt" "$sp"
  local own; own=$(dsum "$(tbal d7 shielded)" "$(tbal d7 shielded_pending)")
  if ge "$wo" 1100 && [ "$(jget "$sp" txid)" = "" ] && ! gt "$own" 0; then
    result "viewing-key-watch-only" PASS "d7 imported d6's key: watch_notes=$(jget "$im" watch_notes) received=$(jget "$im" received), z_gettotalbalance shielded_watchonly=$wo, owned=$own, spend refused: $(echo "$sp" | tr -d '\n' | head -c 90)"
  else result "viewing-key-watch-only" FAIL "watchonly=$wo owned=$own spend=$(echo "$sp" | tr -d '\n' | head -c 120)"; fi
}

phase_hold() {
  local h; h=$(rpc d6 z_holdiv5note "$HOLD_NOTE" true); ev "d6 z_holdiv5note $HOLD_NOTE true" "$h"
  sleep 2
  local tb; tb=$(rpc d6 z_gettotalbalance); ev "d6 z_gettotalbalance with hold" "$tb"
  local lh; lh=$(rpc d6 z_listiv5holds); ev "d6 z_listiv5holds" "$lh"
  local held; held=$(jget "$tb" shielded_held)
  if ge "$held" 100 && echo "$lh" | grep -q "${HOLD_NOTE%%:*}"; then
    result "hold-held-balance" PASS "z_holdiv5note $HOLD_NOTE -> shielded_held=$held, total=$(jget "$tb" total), listed by z_listiv5holds"
  else result "hold-held-balance" FAIL "shielded_held=$held holds=$(echo "$lh" | tr -d '\n ' | head -c 160)"; fi
}

phase_restore() {
  say "== recovery phrase: d6 -> fresh wallet on d8"
  unlock d6
  local ph; ph=$(jget "$(rpc d6 z_exportphrase)" phrase)
  local words; words=$(echo "$ph" | wc -w)
  local src; src=$(rpc d6 z_gettotalbalance)
  rpc d8 encryptwallet "$WALLETPASS" >/dev/null
  wait_down d8; local a; for a in 1 2 3 4 5; do start_node d8; wait_rpc d8 15 && break; sleep 3; done
  unlock d8
  local imp; imp=$(rpc d8 z_importphrase "$ph" 0 true); ev "d8 z_importphrase" "$imp" 8
  unlock d8
  local rs; rs=$(rpc d8 z_rescaniv5 0); ev "d8 z_rescaniv5 0" "$rs" 8
  H relink >/dev/null
  local want got i
  want=$(dsum "$(jget "$src" shielded)" "$(jget "$src" shielded_pending)" "$(jget "$src" shielded_collateral)" "$(jget "$src" shielded_held)")
  for i in $(seq 1 40); do
    local dst; dst=$(rpc d8 z_gettotalbalance)
    got=$(dsum "$(jget "$dst" shielded)" "$(jget "$dst" shielded_pending)" "$(jget "$dst" shielded_collateral)" "$(jget "$dst" shielded_held)")
    [ "$got" = "$want" ] && break
    sleep 5
  done
  ev "d8 z_gettotalbalance after restore" "$(rpc d8 z_gettotalbalance)"
  if [ "$words" -eq 24 ] && [ "$got" = "$want" ] && gt "$got" 0; then
    result "recovery-phrase-restore" PASS "24-word phrase from d6 restored on d8: shielded owned $got == $want (d6)"
  else result "recovery-phrase-restore" FAIL "words=$words d6 owned=$want d8 owned=$got"; fi
}

# ---------------------------------------------------------------------------
mix_prepared() {
  local n c; for n in d1 d2; do
    c=$(rpc "$n" mixnotes | python3 -c 'import json,sys
try: d=json.load(sys.stdin); print(sum(1 for x in d["notes"] if x.get("prepared") and x.get("usable") and x.get("eligible_height",0) > 0))
except Exception: print(0)')
    [ "${c:-0}" -ge 1 ] || return 1
  done
}
d12_spendable() { gt "$(tbal d1 shielded)" 5 && gt "$(tbal d2 shielded)" 5 && gt "$(tbal d3 shielded)" 5; }
phase_mix_prepare() {
  wait_for 3000 "d1 d2 d3 shielded notes spendable" d12_spendable || { result "nullsend-round" FAIL "seats never had spendable notes"; return 1; }
  local n p; for n in d1 d2; do unlock "$n"; p=$(rpc "$n" mixprepare 1); ev "$n mixprepare 1" "$p"; done
  H mixstub
}
# The harness's mixround prepares again before opening the round; a second
# preparation per seat takes another >=500 note from the note voters, so the round
# is opened here against the notes prepared above.
MIX_PUBKEY=""; MIX_SLOT=""
# A seat reads the record slot only once its prepared note is eligible, while the join
# window is wall-clock, so the round opens only after the notes are eligible.
mix_eligible() {
  local n e; for n in d1 d2; do
    e=$(rpc "$n" mixnotes | python3 -c 'import json,sys
try: d=json.load(sys.stdin); print(max(x.get("eligible_height",0) for x in d["notes"] if x.get("prepared")))
except Exception: print(999999999)')
    [ "$(height)" -ge "${e:-999999999}" ] || return 1
  done
}
phase_mix_open() {
  wait_for 3000 "prepared mix notes usable" mix_prepared || { result "nullsend-round" FAIL "prepared notes never became usable: $(rpc d1 mixnotes | tr -d '\n ' | head -c 200)"; return 1; }
  ev "d1 mixnotes" "$(rpc d1 mixnotes)"
  wait_for 3600 "prepared mix notes eligible" mix_eligible || { result "nullsend-round" FAIL "prepared notes never eligible: $(rpc d1 mixnotes | tr -d '\n ' | head -c 200)"; return 1; }
  local addr co; addr=$(rpc d3 getnewaddress | tr -d '"[:space:]')
  co=$(rpc d3 mixcoordinate "$addr" 1 2); ev "d3 mixcoordinate" "$co"
  MIX_PUBKEY=$(jget "$co" coordinator); st MIX_PUBKEY "$MIX_PUBKEY"
  [ ${#MIX_PUBKEY} -eq 66 ] || { result "nullsend-round" FAIL "mixcoordinate: $(echo "$co" | tr -d '\n' | head -c 200)"; return 1; }
  say "coordinator d3 opened a round ${MIX_PUBKEY:0:16}; seats join once its record slot is planned"
}
mix_slot_planned() { MIX_SLOT=$(jget "$(rpc d3 mixstatus)" jobs 0 recordslot); is_int "$MIX_SLOT" && [ "$MIX_SLOT" -gt 0 ]; }
phase_mix_join() {
  [ -n "$MIX_PUBKEY" ] || return 1
  wait_for 1800 "coordinator planned a record slot" mix_slot_planned || { result "nullsend-round" FAIL "no record slot: $(jget "$(rpc d3 mixstatus)" jobs 0 status)"; return 1; }
  st MIX_SLOT "$MIX_SLOT"
  local n j; for n in d1 d2; do j=$(rpc "$n" mixjoin "$MIX_PUBKEY" "$MIX_SLOT"); ev "$n mixjoin $MIX_SLOT" "$j"; done
}
mix_done() {
  local cs s1 s2
  cs=$(jget "$(rpc d3 mixstatus)" jobs 0 state); s1=$(jget "$(rpc d1 mixstatus)" jobs 0 state); s2=$(jget "$(rpc d2 mixstatus)" jobs 0 state)
  { [ "$cs" = 3 ] || [ "$cs" = 4 ]; } && { [ "$s1" = 12 ] || [ "$s1" = 13 ]; } && { [ "$s2" = 12 ] || [ "$s2" = 13 ]; } && return 0
  # A seat that failed ends the wait.
  case "$(jget "$(rpc d1 mixstatus)" jobs 0 status)$(jget "$(rpc d2 mixstatus)" jobs 0 status)" in
    *"window closed"*|*"has passed"*|*"cannot be read"*|*"published no round"*) return 0 ;;
  esac
  return 1
}
phase_mix_round() {
  [ -n "$MIX_PUBKEY" ] || return 1
  [ -n "$MIX_SLOT" ] || phase_mix_join || return 1
  wait_for "${IV5RA_MIX_WAIT:-1500}" "NullSend round finished" mix_done
  # The coordinator marks the round finished shortly after the seats complete.
  mix_coord_finished() { [ "$(jget "$(rpc d3 mixstatus)" jobs 0 state)" = 3 ]; }
  wait_for 600 "NullSend coordinator finished" mix_coord_finished
  local cs s1 s2 cst
  cs=$(jget "$(rpc d3 mixstatus)" jobs 0 state); s1=$(jget "$(rpc d1 mixstatus)" jobs 0 state); s2=$(jget "$(rpc d2 mixstatus)" jobs 0 state)
  cst=$(jget "$(rpc d3 mixstatus)" jobs 0 status)
  ev "d3 mixstatus" "$(rpc d3 mixstatus)"; ev "d1 mixstatus" "$(rpc d1 mixstatus)"; ev "d2 mixstatus" "$(rpc d2 mixstatus)"
  if [ "$cs" = 3 ] && [ "$s1" = 12 ] && [ "$s2" = 12 ]; then
    result "nullsend-round" PASS "coordinator d3 state 3 ($cst), seats d1/d2 state 12, record slot $MIX_SLOT"
  else result "nullsend-round" FAIL "coordinator state=$cs ($cst), seats $s1/$s2 ($(jget "$(rpc d1 mixstatus)" jobs 0 status)), slot $MIX_SLOT"; fi
}

# Registration needs one 25000 INN note, which no regtest wallet can reach within a
# run. The attestation is covered by iv5_collateral_rpc_regtest_test.sh; this shows
# the surface.
phase_collateral() {
  local tb; tb=$(rpc d6 z_gettotalbalance)
  local cn; cn=$(rpc d6 collateralnode collateral-notes); ev "d6 collateralnode collateral-notes" "$cn" 20
  local c; c=$(jget "$tb" shielded_collateral)
  if [ -n "$c" ] && echo "$cn" | grep -q '"candidates"'; then
    result "collateral-balance" SKIP "needs one 25000 INN note; money supply at Boundary B is ~14,000 INN and the post-B miner share is 1.575/block; shielded_collateral field reads $c, collateral-notes lists $(jget "$cn" candidates | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null) candidate(s)"
  else result "collateral-balance" FAIL "z_gettotalbalance shielded_collateral='$c'; collateral-notes: $(echo "$cn" | tr -d '\n' | head -c 160)"; fi
}

# ---------------------------------------------------------------------------
phase_final() {
  wait_height "$END_HEIGHT" 7200
  say "== final checks at h=$(height)"
  pacer_stop
  sleep 20
  local n hs=() h ref="" agree=0 mism="" top
  top=$(height)
  for i in $(seq 1 60); do
    local lo=999999999 hi=0 v
    for n in $(names); do v=$(height "$n"); is_int "$v" || v=0; [ "$v" -lt "$lo" ] && lo=$v; [ "$v" -gt "$hi" ] && hi=$v; done
    [ "$lo" = "$hi" ] && break; sleep 5
  done
  local tips=""
  for n in $(names); do
    h=$(rpc "$n" getbestblockhash | tr -d '"[:space:]')
    tips="$tips $n:$(height "$n"):${h:0:12}"
    [ -z "$ref" ] && ref=$h
    [ "$h" = "$ref" ] && agree=$((agree + 1)) || mism="$mism $n"
  done
  if [ "$agree" -eq "$N_NODES" ]; then result "tip-agreement" PASS "$agree/$N_NODES nodes on tip $ref at h=$(height d0)"
  else result "tip-agreement" FAIL "disagree:$mism;$tips"; fi
  ev "tips" "$tips"

  # DAG / DAGKnight
  local di; di=$(rpc d0 getdaginfo); ev "d0 getdaginfo" "$di" 70
  local ord; ord=$(rpc d0 getdagorder | python3 -c 'import json,sys
try: v=json.load(sys.stdin); print(len(v), sorted({e.get("inferred_k") for e in v if "inferred_k" in e}))
except Exception: print("0 -")')
  if [ "$(jget "$di" dag_active)" = true ] && [ "$(jget "$di" dagknight_active)" = true ] && [ "$(jget "$di" pos_block_production)" = false ]; then
    result "idag-dagknight" PASS "dag_active, dagknight_active, PoW producer; ordering=$(jget "$di" ordering_algorithm) contract=$(jget "$di" dagknight_contract) entries=$(jget "$di" dag_entries) inferred_k=$(jget "$di" inferred_k); getdagorder: $ord"
  else result "idag-dagknight" FAIL "dag_active=$(jget "$di" dag_active) dagknight_active=$(jget "$di" dagknight_active)"; fi

  # Gates
  local fi; fi=$(rpc d0 getfinalityinfo); ev "d0 getfinalityinfo" "$fi" 120
  local si; si=$(rpc d0 z_getshieldedinfo)
  local tip; tip=$(height d0)
  local g=""; for x in 50 80 120 200 311 911 1511; do [ "$tip" -gt "$x" ] || g="$g $x"; done
  if [ -z "$g" ] && [ "$(jget "$fi" boundary_a_active)" = true ] && [ "$(jget "$fi" boundary_b_active)" = true ] && [ "$(jget "$si" privacy_vnext_fee_note_active)" = true ]; then
    result "fork-gates" PASS "tip $tip past ms-ts 50, cold 80, CN 120, IDNS 200, A/B 311 (active), fee note 311 (active), note vote 911, supply cap 1511; DAG $(jget "$di" fork_height), DAGKnight $(jget "$di" dagknight_fork_height)"
  else result "fork-gates" FAIL "uncrossed:$g A=$(jget "$fi" boundary_a_active) B=$(jget "$fi" boundary_b_active) fee=$(jget "$si" privacy_vnext_fee_note_active)"; fi
  # IDNS reset in force
  local rl; rl=$(grep -m1 'IDNS reset rehearsal' "$NODES_DIR/d0/regtest/debug.log" 2>/dev/null)
  [ -n "$rl" ] && result "idns-reset-gate" PASS "$rl" || result "idns-reset-gate" FAIL "no IDNS reset rehearsal line in d0 debug.log"
  # Millisecond timestamps: a nonzero offset in a coinbase above the gate.
  local msh="" off="" hh raw cb
  for hh in $(seq $((tip - 40)) "$tip"); do
    cb=$(jget "$(rpc d0 getblock "$(rpc d0 getblockhash "$hh" | tr -d '"[:space:]')")" tx 0)
    raw=$(rpc d0 getrawtransaction "$cb" | tr -d '"[:space:]')
    off=$(python3 "$SCRIPT_DIR/iv5_onechain_evidence.py" coinbase "$raw" 2>/dev/null | python3 -c 'import json,sys
try:
  d=json.load(sys.stdin)
  print(next((r["offset_ms"] for r in d.get("op_returns",[]) if r.get("tag")=="IMTS"), ""))
except Exception: print("")')
    is_int "$off" && [ "$off" -gt 0 ] && { msh=$hh; break; }
  done
  [ -n "$msh" ] && result "ms-timestamps" PASS "coinbase at h=$msh carries IMTS offset ${off} ms" \
                || result "ms-timestamps" FAIL "no nonzero IMTS offset in the last 40 coinbases"

  # Finality
  local fh; fh=$(jget "$fi" finalized_height)
  local fstaking; fstaking=$(rpc d0 getfinalitystakinginfo)
  local tier; tier=$(jget "$fstaking" finality_tier); local chard; chard=$(jget "$fstaking" consecutive_hard_epochs)
  local e best=0 bestc=0 c nve="" nvn=0
  local cur; cur=$(jget "$fi" epoch)
  for e in $(seq 1 "$cur"); do
    local ej; ej=$(rpc d0 getepochinfo "$e")
    c=$(jget "$ej" note_votes_counted); is_int "$c" || continue
    nve="$nve e$e:$c/$(jget "$ej" finality_tier)"
    [ "$c" -gt 0 ] && nvn=$((nvn + 1))
    [ "$c" -gt "$bestc" ] && { bestc=$c; best=$e; }
  done
  local nvl=""; for n in d1 d2; do nvl="$nvl $n:produced=$(grep -c 'ProducePrivacyVNextNoteVote: epoch=' "$NODES_DIR/$n/regtest/debug.log" 2>/dev/null),none=$(grep -c 'no IV5 note vote for epoch' "$NODES_DIR/$n/regtest/debug.log" 2>/dev/null)"; done
  ev "note votes per epoch (counted/tier)" "$nve; log:$nvl"
  ev "d1 last refusal" "$(grep 'no IV5 note vote for epoch' "$NODES_DIR/d1/regtest/debug.log" | tail -1)"
  local fset=""; for n in $(names); do fset="$fset $(finalized "$n")"; done
  local funiq; funiq=$(echo $fset | tr ' ' '\n' | sort -u | wc -l)
  ev "getepochinfo $best" "$(rpc d0 getepochinfo "$best")" 40
  if is_int "$fh" && [ "$fh" -gt "$FIN_MID" ] && [ "$tier" = hard ] && [ "$nvn" -ge 2 ] && [ "$(jget "$fi" transparent_votes)" -gt 0 ] 2>/dev/null; then
    result "finality-hard-both-lanes" PASS "finalized_height $FIN_MID -> $fh (all nodes:$fset), tier=$tier consecutive_hard=$chard, transparent_votes=$(jget "$fi" transparent_votes) voters=$(jget "$fi" current_epoch_voters), epoch $best note_votes_counted=$bestc; epochs with note votes: $nvn ($nve)"
  else result "finality-hard-both-lanes" FAIL "finalized $FIN_MID -> $fh tier=$tier chard=$chard epochs with note votes=$nvn ($nve;$nvl) transparent_votes=$(jget "$fi" transparent_votes)"; fi
  [ "$funiq" -eq 1 ] || say "note: finalized heights differ across nodes:$fset"

  # Cold staking: the staker voted with delegated weight, the owner kept it and revokes it.
  local d4fi; d4fi=$(rpc d4 getfinalitystakinginfo); ev "d4 getfinalitystakinginfo" "$d4fi" 60
  local sk; sk=$(echo "$fi" | grep -c "$STAKER_ADDR")
  pace_off_revoke
  # Supply accounting: fleet agrees; supply delta equals the sum of block mints.
  local sup=""; for n in $(names); do sup="$sup $(jget "$(rpc "$n" getfinalityinfo)" money_supply)"; done
  local supu; supu=$(echo $sup | tr ' ' '\n' | sort -u | wc -l)
  local bc; bc=$(rpc d0 getblockchaininfo); ev "getblockchaininfo" "$bc" 60
  # Every block's mint from genesis to the tip, against the supply the nodes report.
  local sm mints="" hh
  for hh in $(seq 0 "$tip"); do mints="$mints $(jget "$(rpc d0 getblock "$(rpc d0 getblockhash "$hh" | tr -d '"[:space:]')")" mint)"; done
  sm=$(dsum $mints)
  local s2; s2=$(jget "$(rpc d0 getinfo)" moneysupply)
  say "supply: nodes$sup; getinfo moneysupply=$s2; sum(mint 0..$tip)=$sm; cap=$(jget "$bc" total_supply_cap)"
  # A block's mint counts the fees it collected and the supply does not (fees are
  # destroyed), so sum(mint) - supply is the run's total fees: small and never negative.
  local fees; fees=$(python3 -c 'import sys; from decimal import Decimal as D; print(D(sys.argv[2])-D(sys.argv[1]))' "$s2" "$sm")
  if [ "$supu" -eq 1 ] && python3 -c 'import sys; from decimal import Decimal as D; f=D(sys.argv[1]); sys.exit(0 if D(0) <= f <= D(5) else 1)' "$fees"; then
    result "supply-accounting" PASS "money_supply identical on all nodes ($s2); sum of block mints 0..$tip = $sm, exceeding supply by $fees = fees destroyed (bound 0..5); supply-cap gate 1511 crossed"
  else result "supply-accounting" FAIL "nodes:$sup; moneysupply=$s2 sum(mint)=$sm difference=$fees"; fi

  # Liveness and logs.
  local dead="" crash="" errs=0
  for n in $(names); do
    is_int "$(height "$n")" || dead="$dead $n"
    local lg="$NODES_DIR/$n/regtest/debug.log"
    local a; a=$(grep -cE 'Assertion|assert.*failed|EXCEPTION|terminate called|Segmentation|AddressSanitizer' "$lg" 2>/dev/null)
    [ "${a:-0}" -gt 0 ] && crash="$crash $n:$a"
    errs=$((errs + $(grep -c 'ERROR' "$lg" 2>/dev/null || echo 0)))
  done
  local top_err; top_err=$(cat "$NODES_DIR"/d*/regtest/debug.log 2>/dev/null | grep 'ERROR' | sed 's/[0-9a-f]\{16,\}/<h>/g; s/[0-9]\+/N/g' | sort | uniq -c | sort -rn | head -8)
  ev "ERROR lines by kind (normalized)" "$top_err" 20
  if [ -z "$dead" ] && [ -z "$crash" ]; then result "liveness-logs" PASS "all $N_NODES daemons answer; no assert/exception/terminate in any debug.log; $errs ERROR lines (by kind in run.log)"
  else result "liveness-logs" FAIL "dead:$dead crash-lines:$crash"; fi
}

pace_off_revoke() {
  local lc; lc=$(rpc d7 listcoldutxos)
  local vout; vout=$(printf '%s' "$lc" | TX="$DELEG_TX" python3 -c 'import json,os,sys
try:
  v=json.load(sys.stdin); print(next(u["vout"] for u in v if u.get("txid")==os.environ["TX"]))
except Exception: print("")')
  local fsi; fsi=$(rpc d4 getfinalitystakinginfo)
  local voted; voted=$(jget "$fsi" vote_epoch_voted)
  local inv; inv=$(rpc d0 getfinalityinfo | grep -c "${STAKER_VOTER:-none}")
  [ -n "$vout" ] || { say "delegation $DELEG_TX is no longer in the owner's listcoldutxos"; vout=1; }
  local rv; rv=$(rpc d7 revokecoldstaking "$DELEG_TX" "$vout"); ev "d7 revokecoldstaking" "$rv"
  local rt; rt=$(printf '%s' "$rv" | grep -o '[0-9a-f]\{64\}' | head -1)
  if [ -n "$rt" ] && [ "$inv" -gt 0 ]; then
    result "cold-stake-vote-and-revoke" PASS "staker d4 still in the current epoch's voters as $STAKER_VOTER (vote_epoch_voted $voted); owner d7 revokecoldstaking $DELEG_TX:$vout -> $rt"
  else result "cold-stake-vote-and-revoke" FAIL "d4 in voters=$inv vote_epoch_voted=$voted; revoke: $(echo "$rv" | tr -d '\n' | head -c 160)"; fi
}

# ---------------------------------------------------------------------------
cmd_stop() {
  pacer_stop 2>/dev/null
  [ -f "$STUB_PIDFILE" ] && kill "$(cat "$STUB_PIDFILE")" 2>/dev/null; rm -f "$STUB_PIDFILE"
  local n; for n in $(names); do rpc "$n" stop >/dev/null 2>&1; done
  for n in $(names); do wait_down "$n" || say "$n still running after stop"; done
  local left; left=$(pgrep -f -- "-datadir=$NODES_DIR/" | tr '\n' ' ')
  [ -n "$left" ] && say "still running: $left" || say "all daemons stopped"
}

cmd_run() {
  preflight
  say "== iv5 release all-features run, END=$END_HEIGHT"
  phase_bringup || { cmd_stop; exit 1; }
  phase_prefork
  phase_shield
  phase_finality_early
  FIN_MID=$(finalized); st FIN_MID "$FIN_MID"
  phase_mix_prepare
  phase_transfer
  phase_viewkey
  phase_hold
  phase_collateral
  phase_restore
  phase_mix_open
  phase_mix_join
  phase_mix_round
  phase_final
  say "== summary (run time $(( ($(date +%s) - T0) / 60 )) min)"
  column -t -s $'\t' "$SUMMARY" | tee -a "$LOG"
  local f; f=$(awk -F'\t' '$2=="FAIL"' "$SUMMARY" | wc -l)
  say "RESULT: $(awk -F'\t' '$2=="PASS"' "$SUMMARY" | wc -l) PASS, $f FAIL, $(awk -F'\t' '$2=="SKIP"' "$SUMMARY" | wc -l) SKIP"
  [ "${IV5RA_KEEP:-0}" = 1 ] || cmd_stop
  [ "$f" -eq 0 ]
}

case "${1:-run}" in
  run)    cmd_run ;;
  stop)   cmd_stop ;;
  status) bash "$HARNESS" status 2>/dev/null ;;
  # Resume on a live chain: run named phases (e.g. "phase restore final") with
  # the recorded state. The pacer is restarted for phases that wait on height.
  phase)  shift; . "$STATE"; FIN_MID=${FIN_MID:-0}; pacer_start 1
          for p in "$@"; do "phase_$p"; done
          pacer_stop; column -t -s $'\t' "$SUMMARY" ;;
  *) echo "usage: $0 [run|stop|status|phase <name>...]"; exit 1 ;;
esac
