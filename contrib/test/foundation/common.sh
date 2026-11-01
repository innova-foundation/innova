# Shared helpers for the foundation harness. Sourced, not run.

fnd_blk_files() {
    ls "$1"/blk[0-9][0-9][0-9][0-9].dat 2>/dev/null | sort | head -n "${2:-100000}"
}

# fnd_conf <datadir> <port> <rpcport>
fnd_conf() {
    mkdir -p "$1"
    cat > "$1/innova.conf" <<CONF
rpcuser=fnd
rpcpassword=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
rpcport=$3
port=$2
listen=0
dnsseed=0
upnp=0
nobootstrap=1
logtimestamps=1
staking=0
CONF
}

# Common node flags: no peers, full verification, no startup block walk.
fnd_flags() {
    echo "-datadir=$1 -connect=127.0.0.1:$2 -nobootstrap -listen=0 -dnsseed=0 -assumevalid=0 -parverify=0 -checkblocks=0 -printtoconsole=0"
}

fnd_rpc() {
    local bin=$1 dd=$2; shift 2
    "$bin" -datadir="$dd" "$@" 2>/dev/null
}

# Wait for RPC; prints seconds waited, returns 1 on timeout or process exit.
fnd_wait_rpc() {
    local bin=$1 dd=$2 pid=$3 timeout=${4:-3600} t0=$(date +%s.%N)
    while :; do
        if fnd_rpc "$bin" "$dd" getblockcount >/dev/null; then
            echo "$(echo "$(date +%s.%N) - $t0" | bc)"; return 0
        fi
        kill -0 "$pid" 2>/dev/null || return 1
        [ $(( $(date +%s) - ${t0%.*} )) -gt "$timeout" ] && return 1
        sleep 0.5
    done
}

fnd_stop() {
    local bin=$1 dd=$2 pid=$3 i
    fnd_rpc "$bin" "$dd" stop >/dev/null
    for i in $(seq 1 600); do kill -0 "$pid" 2>/dev/null || return 0; sleep 1; done
    kill -9 "$pid" 2>/dev/null; return 1
}

# Sample VmRSS/VmHWM (kB) of pid every $3 s into $2 until it exits.
fnd_sample_rss() {
    local pid=$1 out=$2 iv=${3:-5}
    while kill -0 "$pid" 2>/dev/null; do
        awk -v t="$(date +%s)" '/^VmRSS/{r=$2}/^VmHWM/{h=$2}END{if(r)print t, r, h}' /proc/"$pid"/status 2>/dev/null >> "$out"
        sleep "$iv"
    done
}
