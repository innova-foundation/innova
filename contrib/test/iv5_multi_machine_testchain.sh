#!/usr/bin/env bash
# Multi-machine IV5 regtest chain: d* on the primary host, m* on the secondary host, optional w*, in a line.
# Subcommands: setup | start | prepare | unlock | relink | mixstub | mixround | mine | status | verify | monitor | stop | wipe

set -uo pipefail

# Kept before anything else runs: the table builders below use `set --` to split
# rows, which at script scope overwrites the script's own arguments.
ARGV=("$@")

SECONDARY_BIN="${SECONDARY_BIN:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/src/innovad}"

RPCUSER=iv5tc
RPCPASS=iv5tcpass_local_only

# Regtest ladder: DAG 11, carrier 13, V3 and Boundary A at DAG+300, B aliases A.
# The fee note must not sit below B; the note vote must land on 311 + k*300.
BOUNDARY_B=311
FEE_NOTE=311
MS_TIMESTAMP="${MS_TIMESTAMP:-50}"
COLD_STAKING="${COLD_STAKING:-80}"
CN_PAYMENTS="${CN_PAYMENTS:-120}"
IDNS_RESET="${IDNS_RESET:-200}"
NOTE_VOTE="${NOTE_VOTE:-911}"
SUPPLY_CAP_HEIGHT="${SUPPLY_CAP_HEIGHT:-1511}"

# Passphrase for note-voting wallets: an IV5 seed requires an encrypted wallet and
# a note vote requires it unlocked. Local throwaway chain only.
WALLETPASS="${WALLETPASS:-iv5tcfleetpass}"

# How many nodes each machine carries. The primary host has the cores, so it takes
# the depth; the secondary side stays small because its value here is being a second
# platform, not a second crowd.
PRIMARY_NODES="${PRIMARY_NODES:-2}"
SECONDARY_NODES="${SECONDARY_NODES:-2}"
EXTRA_NODES="${EXTRA_NODES:-2}"

# A third machine is opt-in: without its address there is nothing to dial.
THIRD=0
[ -n "${EXTRA_SSH:-}" ] && THIRD=1

# Nothing dials the secondary host in a two-machine run, so loopback is a fine default
# there; with a third machine w0 dials it, and loopback would silently make the
# link local and the test meaningless.
if [ "$THIRD" -eq 1 ] && [ -z "${SECONDARY_TS:-}" ]; then
  echo "set SECONDARY_TS to the address the third machine reaches this one on" >&2
  exit 1
fi

# name  ssh-target ("-" is this machine)  address peers dial  binary  datadir base
HOSTS=(
  "primary ${PRIMARY_SSH:-user@linux-host} ${PRIMARY_TS:-linux-host} ${PRIMARY_BIN:-/home/user/innova-testchain/src/innovad} ${PRIMARY_BASE:-/home/user/iv5tc}"
  "secondary  -                            ${SECONDARY_TS:-127.0.0.1}     $SECONDARY_BIN                                           ${SECONDARY_BASE:-$HOME/iv5tc}"
)

if [ "$THIRD" -eq 1 ]; then
  EXTRA_USER="${EXTRA_SSH%@*}"
  [ "$EXTRA_USER" = "$EXTRA_SSH" ] && EXTRA_USER="$(id -un)"
  HOSTS+=("extra $EXTRA_SSH ${EXTRA_TS:-${EXTRA_SSH#*@}} ${EXTRA_BIN:-/home/$EXTRA_USER/innova/src/innovad} ${EXTRA_BASE:-/home/$EXTRA_USER/iv5tc}")
fi

# Per machine, contiguous p2p/rpc/idns port runs; only the base node's port faces the other machines.
# prefix  host  p2p-base  rpc-base  idns-base  count
LAYOUT=(
  "d primary 18444 18500 18600 $PRIMARY_NODES"
  "m secondary  18700 18800 18900 $SECONDARY_NODES"
)
[ "$THIRD" -eq 1 ] && LAYOUT+=("w extra 19000 19100 19200 $EXTRA_NODES")

NODES=()
for row in "${LAYOUT[@]}"; do
  set -- $row
  prefix=$1; lhost=$2; pbase=$3; rbase=$4; ibase=$5; count=$6
  for i in $(seq 0 $((count - 1))); do
    NODES+=("$prefix$i $lhost $((pbase + i)) $((rbase + i)) $((ibase + i)) -")
  done
done

# The three tally keys go one per machine, and on that machine to its first and
# last node, so no 2-of-3 can be reached without crossing a hop -- and on the
# miner's own machine, without traversing its whole line.
set_key() {
  local name=$1 index=$2 j=0
  for j in "${!NODES[@]}"; do
    set -- ${NODES[$j]}
    [ "$1" = "$name" ] && { NODES[$j]="$1 $2 $3 $4 $5 $index"; return; }
  done
}
LAST_D="d$((PRIMARY_NODES - 1))"
if [ "$THIRD" -eq 1 ]; then
  set_key d0 0; set_key m0 1; set_key w0 2
else
  # Two machines: the miner, the far end of its line, and the other platform.
  set_key d0 0
  if [ "$PRIMARY_NODES" -ge 2 ]; then set_key "$LAST_D" 1; else set_key m1 1; fi
  set_key m0 2
fi

TALLYKEYS=(
  "0000000000000000000000000000000000000000000000000000000000000001"
  "0000000000000000000000000000000000000000000000000000000000000002"
  "0000000000000000000000000000000000000000000000000000000000000003"
)

# Roles. Only transparent voters count in the tally; note voters are refused if no
# transparent voter exists, so both lanes need nodes. The rest relay.
ROLE_TRANSPARENT="$(echo "d0 $LAST_D m0")"
ROLE_NOTE="${ROLE_NOTE:-d1 d2 m1}"

# NullSend seats spend IV5 notes, so they are note nodes; the coordinator also serves
# the directory. All sit on one machine because the SOCKS stub forwards to local
# ports; real Tor is covered by contrib/test/iv5_nullsend_regtest_test.sh.
MIX_COORD="${MIX_COORD:-d3}"
MIX_SEATS="${MIX_SEATS:-d1 d2}"
MIX_STUB_PORT="${MIX_STUB_PORT:-18960}"
MIX_COORD_PORT="${MIX_COORD_PORT:-18961}"
MIX_DIR_PORT="${MIX_DIR_PORT:-18962}"
MIX_DIR_ONION=directoryaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion
MIX_COORD_ONION=coordaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion
MIX_DENOMINATION="${MIX_DENOMINATION:-1}"

has_role() { echo " $2 " | grep -q " $1 "; }
in_mix() { has_role "$1" "$MIX_COORD $MIX_SEATS"; }
role_of() {
  has_role "$1" "$ROLE_TRANSPARENT" && { echo transparent; return; }
  has_role "$1" "$ROLE_NOTE" && { echo note; return; }
  echo relay
}
note_nodes() { echo "$ROLE_NOTE"; }
# Wallets that need an IV5 seed. The mix coordinator publishes its rendezvous
# record from shielded funds, so it needs one even though it casts no note vote.
seed_nodes() { echo "$ROLE_NOTE $MIX_COORD" | tr ' ' '\n' | awk 'NF && !seen[$0]++' | tr '\n' ' '; }

field() { local n=$1 i=$2; for row in "${NODES[@]}"; do set -- $row; [ "$1" = "$n" ] && { eval echo "\${$i}"; return; }; done; }
nhost() { field "$1" 2; }
nport() { field "$1" 3; }
nrpc()  { field "$1" 4; }
nidns() { field "$1" 5; }
nkey()  { field "$1" 6; }

hfield() { local h=$1 i=$2; for row in "${HOSTS[@]}"; do set -- $row; [ "$1" = "$h" ] && { eval echo "\${$i}"; return; }; done; }
host_ssh()  { hfield "$1" 2; }
host_addr() { hfield "$1" 3; }
bin_for()   { hfield "$1" 4; }
base_for()  { hfield "$1" 5; }

node_names() { local row; for row in "${NODES[@]}"; do set -- $row; echo "$1"; done; }

# Links this node dials, as host:port: node i dials i-1 and i-2, so one lost peer
# does not cut the line. Machines join at the next machine's base port.
links_of() {
  local n=$1 prefix idx
  prefix="${n%%[0-9]*}"; idx="${n#"$prefix"}"
  [ "$idx" -ge 1 ] && echo "127.0.0.1:$(nport "$prefix$((idx - 1))")"
  [ "$idx" -ge 2 ] && echo "127.0.0.1:$(nport "$prefix$((idx - 2))")"
  if [ "$idx" -eq 0 ]; then
    case "$prefix" in
      d) [ "$PRIMARY_NODES" -ge 2 ] && echo "127.0.0.1:$(nport d1)" ;;
      m) echo "$(host_addr primary):$(nport d0)" ;;
      w) echo "$(host_addr secondary):$(nport m0)" ;;
    esac
  fi
  return 0
}

# Re-dial every configured link; peers do not reliably re-dial a restarted node.
cmd_relink() {
  local n l
  for n in $(node_names); do
    for l in $(links_of "$n"); do
      rpc "$n" addnode "$l" onetry >/dev/null 2>&1
    done
  done
  echo "re-dialled every configured link"
}

# Run a command on the machine that owns the node.
on_host() {
  local host=$1; shift
  local target; target=$(host_ssh "$host")
  if [ "$target" = "-" ]; then bash -c "$@"; else ssh -o ConnectTimeout=10 "$target" "$@"; fi
}

# RPC through the daemon's own client mode.
rpc() {
  local n=$1; shift
  local host; host=$(nhost "$n")
  on_host "$host" "$(bin_for "$host") -datadir=$(base_for "$host")/$n -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$(nrpc "$n") $* 2>&1"
}

height() { rpc "$1" getblockcount 2>/dev/null | tr -d '"[:space:]'; }
peers()  { rpc "$1" getconnectioncount 2>/dev/null | tr -d '"[:space:]'; }

emit_conf() {
  local n=$1
  local ki; ki=$(nkey "$n")
  echo "rpcuser=$RPCUSER"
  echo "rpcpassword=$RPCPASS"
  echo "rpcport=$(nrpc "$n")"
  echo "rpcallowip=127.0.0.1"
  echo "port=$(nport "$n")"
  echo "listen=1"
  echo "dnsseed=0"
  echo "nobootstrap=1"
  echo "nosmsg=1"
  echo "upnp=0"
  echo "listenonion=0"
  echo "idnsport=$(nidns "$n")"
  echo "maxconnections=32"
  # Pre-DAG PoS would fork the stretch where wallets are still being funded.
  echo "staking=0"
  echo "nofinalityvoting=0"
  # One lane per node. `note` is refused unless transparent voters exist elsewhere
  # on the chain, so the two roles are set together or neither works.
  case "$(role_of "$n")" in
    note) echo "finalityvotemode=note" ;;
    *)    echo "finalityvotemode=transparent" ;;
  esac
  # Every rehearsal gate, so one chain crosses all of them.
  echo "regtestboundaryb=$BOUNDARY_B"
  echo "regtestiv5rehearsal=1"
  echo "regtestiv5feenote=$FEE_NOTE"
  echo "regtestiv5notevote=$NOTE_VOTE"
  echo "regtestmstimestamp=$MS_TIMESTAMP"
  echo "regtestcoldstaking=$COLD_STAKING"
  echo "regtestcnpayments=$CN_PAYMENTS"
  echo "regtestidnsreset=$IDNS_RESET"
  echo "regtestsupplycapheight=$SUPPLY_CAP_HEIGHT"
  # IDNS runs rather than being switched off, so its reset gate above is reached.
  echo "idns=1"
  if in_mix "$n"; then
    echo "mixproxy=127.0.0.1:$MIX_STUB_PORT"
    echo "mixdir=$MIX_DIR_ONION:$MIX_DIR_PORT"
    if [ "$n" = "$MIX_COORD" ]; then
      echo "mixcoordinatorport=$MIX_COORD_PORT"
      echo "mixdirectoryport=$MIX_DIR_PORT"
      echo "mixonion=$MIX_COORD_ONION"
    fi
  fi
  echo "debug=1"
  echo "debugnet=1"
  [ "$ki" != "-" ] && echo "finalitytallyprivkey=${TALLYKEYS[$ki]}"
  # Each machine is a line, not a mesh: node i dials i-1, and i-2 where there is
  # one, so a block travels the length of the fleet and one lost peer does not
  # cut the line.
  local l
  for l in $(links_of "$n"); do echo "addnode=$l"; done
}

# The far end of the primary line. Mining there rather than at d0 is what makes
# the hop to the next machine the last link in the chain instead of the first.
MINER="$LAST_D"

cmd_setup() {
  local n host base target
  for row in "${NODES[@]}"; do
    set -- $row; n=$1; host=$2
    base=$(base_for "$host"); target=$(host_ssh "$host")
    emit_conf "$n" > "/tmp/iv5tc_$n.conf"
    if [ "$target" = "-" ]; then
      mkdir -p "$base/$n"
      cp "/tmp/iv5tc_$n.conf" "$base/$n/innova.conf"
    else
      ssh "$target" "mkdir -p $base/$n"
      scp -q "/tmp/iv5tc_$n.conf" "$target:$base/$n/innova.conf"
    fi
    echo "setup $n ($host) -> $base/$n"
  done
}

# z_getnewiv5address answers with an object, and an IV5 address is not in the
# transparent alphabet, so neither the shape nor a leading character from the
# transparent side identifies one.
iv5_addr() {
  rpc "$1" z_getnewiv5address 2>/dev/null \
    | tr -d '"[:space:]' | sed -n 's/.*address:\([A-Za-z0-9]\{20,\}\).*/\1/p' | head -1
}

wait_rpc() {
  local n=$1 tries=${2:-90} i
  for i in $(seq 1 "$tries"); do
    [[ "$(height "$n")" =~ ^[0-9]+$ ]] && return 0
    sleep 2
  done
  return 1
}

# Retried: RPC stops answering before the datadir lock is released, and a start in
# that window is refused.
start_one() {
  local n=$1 host attempt; host=$(nhost "$n")
  for attempt in 1 2 3 4 5 6; do
    on_host "$host" "$(bin_for "$host") -datadir=$(base_for "$host")/$n -regtest -daemon >/dev/null 2>&1"
    wait_rpc "$n" 10 && return 0
    sleep 3
  done
  return 1
}

wait_gone() {
  local n=$1 i
  for i in $(seq 1 90); do
    [[ "$(height "$n")" =~ ^[0-9]+$ ]] || return 0
    sleep 2
  done
  return 1
}

cmd_start() {
  local n host
  for row in "${NODES[@]}"; do
    set -- $row; n=$1; host=$2
    on_host "$host" "$(bin_for "$host") -datadir=$(base_for "$host")/$n -regtest -daemon >/dev/null 2>&1"
    echo "started $n"
  done
}

# A locked wallet cannot spend, and a note vote spends its note, so the unlock is
# not staking-only and has to be reapplied after every restart.
cmd_unlock() {
  local n
  for n in $(seed_nodes); do
    rpc "$n" walletpassphrase "$WALLETPASS" 99999999 false >/dev/null 2>&1
    echo "unlocked $n"
  done
}

# An IV5 seed is refused in an unencrypted wallet, and encryptwallet stops the
# node, so each note voter is encrypted, restarted, unlocked and seeded in turn.
cmd_prepare() {
  local n addr
  for n in $(seed_nodes); do
    if rpc "$n" z_getnewiv5address 2>&1 | grep -q 'address'; then
      echo "$n already seeded: $(iv5_addr "$n")"
      continue
    fi
    # Resumable: a run interrupted between the encrypt and the seed leaves a
    # wallet that is already encrypted, and encryptwallet then refuses and the
    # node does not stop. Encryption is a separate question from seeding.
    if ! rpc "$n" getinfo 2>/dev/null | grep -q unlocked_until; then
      rpc "$n" encryptwallet "$WALLETPASS" >/dev/null 2>&1
      wait_gone "$n" || { echo "$n did not stop after encryptwallet"; return 1; }
      start_one "$n" || { echo "$n did not come back after encryptwallet"; return 1; }
    fi
    rpc "$n" walletpassphrase "$WALLETPASS" 99999999 false >/dev/null 2>&1
    rpc "$n" z_createiv5seed >/dev/null 2>&1
    addr=$(iv5_addr "$n")
    case "$addr" in
      ?*) echo "$n encrypted, seeded, ${addr:0:24}..." ;;
      *)  echo "$n has no IV5 address"; return 1 ;;
    esac
  done
  # These nodes restarted, and their peers do not necessarily come back for them.
  cmd_relink
}

cmd_stop() {
  local n
  for n in $(node_names); do
    rpc "$n" setgenerate false 0 >/dev/null 2>&1
    rpc "$n" stop >/dev/null 2>&1
    echo "stopped $n"
  done
}

cmd_wipe() {
  local row target base
  for row in "${HOSTS[@]}"; do
    set -- $row; target=$2; base=$5
    if [ "$target" = "-" ]; then rm -rf "$base"; else ssh "$target" "rm -rf $base"; fi
    echo "wiped $1:$base"
  done
}

# Mine on d0 only. Post-DAG block production is PoW.
# setgenerate is <generate> [blocks] [threads]; blocks=0 mines until stopped.
cmd_mine() {
  local target=${1:-20} threads=${2:-1}
  rpc "$MINER" setgenerate true 0 "$threads" >/dev/null 2>&1
  while :; do
    local h; h=$(height "$MINER")
    [ -z "$h" ] && { sleep 2; continue; }
    [ "$h" -ge "$target" ] && break
    sleep 2
  done
  rpc "$MINER" setgenerate false >/dev/null 2>&1
  echo "$MINER at $(height "$MINER")"
}

cmd_status() {
  local n
  printf '%-4s %-6s %-8s %s\n' node height peers host
  for row in "${NODES[@]}"; do
    set -- $row; n=$1
    printf '%-4s %-6s %-8s %s\n' "$n" "$(height "$n")" "$(peers "$n")" "$2"
  done
}

# Compare block hashes at a height every node has passed; sequential height
# samples skew while blocks are being produced.
cmd_verify() {
  local height=${1:-} n h ref="" refnode="" agree=0 disagree=0 missing=0
  if [ -z "$height" ]; then
    # Highest height every node is known to hold, so the question is answerable.
    local min=999999999 v
    for n in $(node_names); do
      v=$(height "$n")
      [[ "$v" =~ ^[0-9]+$ ]] || { echo "$n did not answer; nothing to compare"; return 1; }
      [ "$v" -lt "$min" ] && min=$v
    done
    height=$min
  fi
  for n in $(node_names); do
    h=$(rpc "$n" getblockhash "$height" 2>/dev/null | tr -d '"[:space:]')
    if ! echo "$h" | grep -qE '^[0-9a-f]{64}$'; then
      echo "  $n: no hash at $height"; missing=$((missing + 1)); continue
    fi
    if [ -z "$ref" ]; then ref="$h"; refnode="$n"; agree=1; continue; fi
    if [ "$h" = "$ref" ]; then agree=$((agree + 1)); else
      echo "  $n: ${h:0:16} != ${ref:0:16} ($refnode)"; disagree=$((disagree + 1))
    fi
  done
  echo "height $height: $agree agree, $disagree disagree, $missing missing (${ref:0:16})"
  [ "$disagree" -eq 0 ] && [ "$missing" -eq 0 ]
}

# SOCKS stub standing in for Tor on the mix machine: forwards the two fixed onion
# names to the coordinator and directory ports.
cmd_mixstub() {
  local host; host=$(nhost "$MIX_COORD")
  local target; target=$(host_ssh "$host")
  local stub=contrib/test/mix_socks_stub.py
  if [ "$target" = "-" ]; then
    nohup python3 "$stub" --port "$MIX_STUB_PORT" >/tmp/iv5tc_mixstub.log 2>&1 &
  else
    scp -q "$stub" "$target:/tmp/mix_socks_stub.py"
    # The stub ignores the onion name and forwards to 127.0.0.1 at the port asked
    # for, so the names are arbitrary and only the ports have to be right.
    ssh "$target" "nohup python3 /tmp/mix_socks_stub.py --port $MIX_STUB_PORT \
      > /tmp/iv5tc_mixstub.log 2>&1 & echo started" >/dev/null 2>&1
  fi
  echo "mix stub on $host:$MIX_STUB_PORT"
}

# One NullSend round on the live chain: each seat prepares a note of the
# denomination, the coordinator opens a round, and the seats join it.
cmd_mixround() {
  local n prep co pubkey j
  for n in $MIX_SEATS; do
    prep=$(rpc "$n" mixprepare "$MIX_DENOMINATION" 2>&1 | tr -d '"[:space:]')
    if [ ${#prep} -eq 64 ]; then echo "$n prepared a $MIX_DENOMINATION INN note ${prep:0:16}"
    else echo "$n mixprepare: $(echo "$prep" | cut -c1-140)"; return 1; fi
  done
  local addr; addr=$(rpc "$MIX_COORD" getnewaddress 2>/dev/null | tr -d '"[:space:]')
  co=$(rpc "$MIX_COORD" mixcoordinate "$addr" "$MIX_DENOMINATION" "$(echo $MIX_SEATS | wc -w | tr -d ' ')" 2>&1)
  # The field is "coordinator"; it is the round's public key.
  pubkey=$(echo "$co" | tr -d '"[:space:]' | grep -o '[0-9a-f]\{66\}' | head -1)
  [ -n "$pubkey" ] || { echo "mixcoordinate: $(echo "$co" | tr -d '\n' | cut -c1-200)"; return 1; }
  echo "coordinator $MIX_COORD opened a round, pubkey $pubkey"
  # Every seat joins at the coordinator's record slot -- it is where the round was
  # published, not a per-seat index. The slot is fixed only once the coordinator's
  # plan lands in a publishing window, so it is read back rather than assumed.
  local slot= i
  for i in $(seq 1 90); do
    slot=$(rpc "$MIX_COORD" mixstatus 2>/dev/null | tr -d '"[:space:]' \
           | sed -n 's/.*recordslot:\([0-9]\{1,\}\).*/\1/p' | head -1)
    [ -n "$slot" ] && [ "$slot" -gt 0 ] 2>/dev/null && break
    sleep 10
  done
  { [ -n "$slot" ] && [ "$slot" -gt 0 ]; } 2>/dev/null || {
    echo "the coordinator never planned a slot: $(rpc "$MIX_COORD" mixstatus 2>/dev/null | tr -d '"[:space:]' | cut -c1-200)"
    return 1
  }
  echo "round planned for record slot $slot"
  for n in $MIX_SEATS; do
    j=$(rpc "$n" mixjoin "$pubkey" "$slot" 2>&1 | tr -d '"[:space:]')
    echo "$n join: $(echo "$j" | cut -c1-140)"
  done
}

# Sample every node's height on a fixed interval and record divergence.
# Does not re-dial or re-request: a peer that stalls behind is the
# observation this run is for.
cmd_monitor() {
  local secs=${1:-300} out=${2:-/tmp/iv5tc_monitor.tsv}
  local end=$(( $(date +%s) + secs ))
  local names; names=$(node_names | tr '\n' '\t')
  printf 'ts\t%sspread\n' "$names" > "$out"
  while [ "$(date +%s)" -lt "$end" ]; do
    local mx=0 mn=999999999 v line=""
    for n in $(node_names); do
      v=$(height "$n"); line="$line$v\t"
      [[ "$v" =~ ^[0-9]+$ ]] || continue
      [ "$v" -gt "$mx" ] && mx=$v
      [ "$v" -lt "$mn" ] && mn=$v
    done
    [ "$mn" -eq 999999999 ] && mn=$mx
    printf "%s\t$line%s\n" "$(date +%s)" "$((mx-mn))" >> "$out"
    sleep 5
  done
  echo "monitor written to $out"
}

[ "$THIRD" -eq 1 ] || echo "note: two machines. set EXTRA_SSH=user@host to add w0/w1 as a third." >&2

set -- "${ARGV[@]:-}"
case "${1:-}" in
  rpc)     shift; rpc "$@" ;;
  setup)   cmd_setup ;;
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  wipe)    cmd_wipe ;;
  mine)    shift; cmd_mine "$@" ;;
  status)  cmd_status ;;
  verify)  shift; cmd_verify "$@" ;;
  prepare) cmd_prepare ;;
  unlock)  cmd_unlock ;;
  relink)  cmd_relink ;;
  mixstub) cmd_mixstub ;;
  mixround) cmd_mixround ;;
  monitor) shift; cmd_monitor "$@" ;;
  *) echo "usage: $0 {setup|start|prepare|unlock|relink|mixstub|mixround|mine <height>|status|verify [height]|monitor <secs> [out]|stop|wipe}"; exit 1 ;;
esac
