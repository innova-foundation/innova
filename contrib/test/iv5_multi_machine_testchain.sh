#!/usr/bin/env bash
# Multi-machine IV5 regtest chain.
#
# Two machines by default: a line of d* nodes on the Linux build host and m* on
# the MacBook, joined by a single link at the far end of the Linux line. Set
# WORKSTATION_SSH to add a third machine, w*, joined the same way to the Mac.
# DELL_NODES/MAC_NODES/WORKSTATION_NODES set how many each carries.
#
# A line rather than a star, on purpose: a block from the miner (d0) reaches the
# far machine only by being relayed the whole way, which is what a single-host
# fleet cannot exercise.
#
# Regtest rather than a private testnet because IsShieldedVNextConsensusReady()
# is (fRegTest && -regtestiv5rehearsal), so the IV5 pool is unreachable off
# regtest, and the Boundary-B / fee-note / note-vote / supply-cap / IDNS-reset
# heights are regtest-only knobs.
#
# Subcommands: setup | start | mine | status | monitor | stop | wipe

set -uo pipefail

MAC_BIN="${MAC_BIN:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/src/innovad}"

RPCUSER=iv5tc
RPCPASS=iv5tcpass_local_only

# Regtest ladder: DAG 11, connected-finality-carrier 13, epoch-state V3 and
# Boundary A at DAG+300. Boundary B is scheduled as an alias of A, which is the
# shipping case, and the fee note must not sit below B.
BOUNDARY_B=311
FEE_NOTE=311

# How many nodes each machine carries. The Linux host has the cores, so it takes
# the depth; the Mac side stays small because its value here is being a second
# platform, not a second crowd.
DELL_NODES="${DELL_NODES:-2}"
MAC_NODES="${MAC_NODES:-2}"
WORKSTATION_NODES="${WORKSTATION_NODES:-2}"

# A third machine is opt-in: without its address there is nothing to dial.
THIRD=0
[ -n "${WORKSTATION_SSH:-}" ] && THIRD=1

# Nothing dials the Mac in a two-machine run, so loopback is a fine default
# there; with a third machine w0 dials it, and loopback would silently make the
# link local and the test meaningless.
if [ "$THIRD" -eq 1 ] && [ -z "${MAC_TS:-}" ]; then
  echo "set MAC_TS to the address the third machine reaches this one on" >&2
  exit 1
fi

# name  ssh-target ("-" is this machine)  address peers dial  binary  datadir base
HOSTS=(
  "dell ${DELL_SSH:-user@linux-host} ${DELL_TS:-linux-host} ${DELL_BIN:-/home/user/innova-testchain/src/innovad} ${DELL_BASE:-/home/user/iv5tc}"
  "mac  -                            ${MAC_TS:-127.0.0.1}     $MAC_BIN                                           ${MAC_BASE:-$HOME/iv5tc}"
)

if [ "$THIRD" -eq 1 ]; then
  WORKSTATION_USER="${WORKSTATION_SSH%@*}"
  [ "$WORKSTATION_USER" = "$WORKSTATION_SSH" ] && WORKSTATION_USER="$(id -un)"
  HOSTS+=("workstation $WORKSTATION_SSH ${WORKSTATION_TS:-${WORKSTATION_SSH#*@}} ${WORKSTATION_BIN:-/home/$WORKSTATION_USER/innova/src/innovad} ${WORKSTATION_BASE:-/home/$WORKSTATION_USER/iv5tc}")
fi

# Ports are assigned per machine from a base well clear of anything a build host
# is likely to be serving. Three contiguous runs per machine: p2p, rpc, idns.
# prefix  host  p2p-base  rpc-base  idns-base  count
LAYOUT=(
  "d dell 18400 18500 18600 $DELL_NODES"
  "m mac  18700 18800 18900 $MAC_NODES"
)
[ "$THIRD" -eq 1 ] && LAYOUT+=("w workstation 19000 19100 19200 $WORKSTATION_NODES")

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
LAST_D="d$((DELL_NODES - 1))"
if [ "$THIRD" -eq 1 ]; then
  set_key d0 0; set_key m0 1; set_key w0 2
else
  # Two machines: the miner, the far end of its line, and the other platform.
  set_key d0 0
  if [ "$DELL_NODES" -ge 2 ]; then set_key "$LAST_D" 1; else set_key m1 1; fi
  set_key m0 2
fi

TALLYKEYS=(
  "0000000000000000000000000000000000000000000000000000000000000001"
  "0000000000000000000000000000000000000000000000000000000000000002"
  "0000000000000000000000000000000000000000000000000000000000000003"
)

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
  echo "finalityvotemode=transparent"
  echo "regtestboundaryb=$BOUNDARY_B"
  echo "regtestiv5rehearsal=1"
  echo "regtestiv5feenote=$FEE_NOTE"
  echo "debug=1"
  echo "debugnet=1"
  [ "$ki" != "-" ] && echo "finalitytallyprivkey=${TALLYKEYS[$ki]}"
  # Each machine is a line, not a mesh: node i dials i-1, and i-2 where there is
  # one, so a block travels the length of the fleet and one lost peer does not
  # cut the line. The machines are joined by a single link each, at the FAR end
  # of the previous machine's line, so crossing a platform means having been
  # relayed the whole way first.
  local prefix="${n%%[0-9]*}" idx="${n#"${n%%[0-9]*}"}"
  [ "$idx" -ge 1 ] && echo "addnode=127.0.0.1:$(nport "$prefix$((idx - 1))")"
  [ "$idx" -ge 2 ] && echo "addnode=127.0.0.1:$(nport "$prefix$((idx - 2))")"
  if [ "$idx" -eq 0 ]; then
    case "$prefix" in
      d) [ "$DELL_NODES" -ge 2 ] && echo "addnode=127.0.0.1:$(nport d1)" ;;
      m) echo "addnode=$(host_addr dell):$(nport "$LAST_D")" ;;
      w) echo "addnode=$(host_addr mac):$(nport "m$((MAC_NODES - 1))")" ;;
    esac
  fi
}

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

cmd_start() {
  local n host
  for row in "${NODES[@]}"; do
    set -- $row; n=$1; host=$2
    on_host "$host" "$(bin_for "$host") -datadir=$(base_for "$host")/$n -regtest -daemon >/dev/null 2>&1"
    echo "started $n"
  done
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
  rpc d0 setgenerate true 0 "$threads" >/dev/null 2>&1
  while :; do
    local h; h=$(height d0)
    [ -z "$h" ] && { sleep 2; continue; }
    [ "$h" -ge "$target" ] && break
    sleep 2
  done
  rpc d0 setgenerate false >/dev/null 2>&1
  echo "d0 at $(height d0)"
}

cmd_status() {
  local n
  printf '%-4s %-6s %-8s %s\n' node height peers host
  for row in "${NODES[@]}"; do
    set -- $row; n=$1
    printf '%-4s %-6s %-8s %s\n' "$n" "$(height "$n")" "$(peers "$n")" "$2"
  done
}

# Sample every node's height on a fixed interval and record divergence.
# Deliberately does NOT re-dial or re-request: a peer that stalls behind is the
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

[ "$THIRD" -eq 1 ] || echo "note: two machines. set WORKSTATION_SSH=user@host to add w0/w1 as a third." >&2

case "${1:-}" in
  rpc)     shift; rpc "$@" ;;
  setup)   cmd_setup ;;
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  wipe)    cmd_wipe ;;
  mine)    shift; cmd_mine "$@" ;;
  status)  cmd_status ;;
  monitor) shift; cmd_monitor "$@" ;;
  *) echo "usage: $0 {setup|start|mine <height>|status|monitor <secs> [out]|stop|wipe}"; exit 1 ;;
esac
