#!/usr/bin/env bash
# Registered CN payees across activation, restart and chain replay.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/testports.sh
source "$SCRIPT_DIR/lib/testports.sh"
iv5_ports_init cn_payee_fork_test
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$ROOT/src/innovad}"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/innova-cn-payee.XXXXXX")"
P2P_BASE="$(iv5_port 0 28900)"
RPC_BASE="$(iv5_port 16 28920)"
IDNS_BASE="$(iv5_port 32 8890)"
FORK=2000

rpc() { local n="$1"; shift; "$INNOVAD" -regtest -datadir="$TEST_DIR/node$n" -rpcport="$((RPC_BASE+n))" "$@"; }
field() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
height() { rpc "$1" getblockcount; }
best() { rpc "$1" getbestblockhash | tr -d '"[:space:]'; }
hash_at() { rpc "$1" getblockhash "$2" | tr -d '"[:space:]'; }
start() {
    local n="$1"; shift
    "$INNOVAD" -regtest -datadir="$TEST_DIR/node$n" -daemon "$@" >/dev/null
    for ((j=0; j<120; j++)); do rpc "$n" getinfo >/dev/null 2>&1 && return; sleep 1; done
    echo "node$n did not start" >&2; return 1
}
stop() {
    local n="$1"
    rpc "$n" stop >/dev/null 2>&1 || true
    for ((j=0; j<120; j++)); do
        if ! rpc "$n" getinfo >/dev/null 2>&1; then
            # The RPC listener closes before the database does.
            if ! pgrep -f -- "-datadir=$TEST_DIR/node$n -daemon" >/dev/null; then return; fi
        fi
        sleep 1
    done
    return 1
}
cleanup() {
    for n in 0 1 2; do stop "$n" || true; done
    if [ "${KEEP_DIR:-0}" = 1 ]; then echo "Kept $TEST_DIR"; else rm -rf "$TEST_DIR"; fi
}
trap cleanup EXIT
mine_to() {
    local n="$1" target="$2" h
    for ((k=0; k<2400; k++)); do
        h="$(height "$n")"
        if [ "$h" -ge "$target" ]; then rpc "$n" setgenerate false 0 >/dev/null; return; fi
        if (( k % 20 == 0 )); then rpc "$n" setgenerate true "$((target-h))" >/dev/null; fi
        sleep 1
    done
    echo "node$n failed to reach $target" >&2; return 1
}
connect() { rpc "$1" addnode "127.0.0.1:$((P2P_BASE+$2))" onetry >/dev/null; }
sync_pair() {
    connect "$1" "$2"
    for ((k=0; k<600; k++)); do
        if [ "$(best "$1")" = "$(best "$2")" ]; then return; fi
        sleep 1
    done
    echo "nodes $1/$2 failed to converge" >&2; return 1
}
template() { rpc "$1" getblocktemplate; }
assert_amount() { test "$(template "$1" | field payee_amount)" = "$2"; }

test -x "$INNOVAD"
for n in 0 1 2; do
    mkdir -p "$TEST_DIR/node$n"
    cat > "$TEST_DIR/node$n/innova.conf" <<EOF
regtest=1
server=1
rpcuser=cnpayee
rpcpassword=cnpayeetest
rpcport=$((RPC_BASE+n))
port=$((P2P_BASE+n))
idnsport=$((IDNS_BASE+n))
bind=127.0.0.1
listen=1
connect=0
dnsseed=0
nobootstrap=1
nosmsg=1
upnp=0
listenonion=0
staking=0
stakingmode=0
nofinalityvoting=1
regtestboundaryb=311
regtestiv5rehearsal=1
regtestmergeset=311
regtestcnpayee=$FORK
EOF
done

start 0
mine_to 0 310
test "$(rpc 0 getforkinfo | field mergeset_active)" = False
mine_to 0 311
test "$(rpc 0 getforkinfo | field mergeset_active)" = True
mine_to 0 "$((FORK-1))"
test "$(rpc 0 getforkinfo | field cn_payee_active)" = False
start 1
sync_pair 1 0
# No collateral exists at activation; the template keeps its share for the producer.
assert_amount 0 0
mine_to 0 "$FORK"
sync_pair 1 0
test "$(rpc 0 getforkinfo | field cn_payee_active)" = True
test "$(rpc 0 getforkinfo | field cn_payee_fork_height)" = "$FORK"
echo "PASS: legacy fallback and fork activation"

ADDRESS="$(rpc 0 getnewaddress | tr -d '"[:space:]')"
TXID="$(rpc 0 sendtoaddress "$ADDRESS" 25000 | tr -d '"[:space:]')"
mine_to 0 "$((FORK+1))"
sync_pair 1 0
assert_amount 0 0
mine_to 0 "$((FORK+102))"
sync_pair 1 0
assert_amount 0 0
assert_amount 1 0
echo "PASS: mature unregistered 25000 INN output is not eligible"

VOUT="$(rpc 0 getrawtransaction "$TXID" 1 | python3 -c 'import json,sys; print(next(o["n"] for o in json.load(sys.stdin)["vout"] if o["value"] == 25000))')"
CNKEY="$(rpc 0 collateralnode genkey | tr -d '"[:space:]')"
stop 0
printf 'registered 127.0.0.1:14539 %s %s %s\n' "$CNKEY" "$TXID" "$VOUT" > "$TEST_DIR/node0/collateralnode.conf"
start 0
sync_pair 0 1
test "$(rpc 0 collateralnode start-alias registered | field result)" = successful
REGTX=""
for id in $(rpc 0 getrawmempool | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)))'); do
    decoded="$(rpc 0 getrawtransaction "$id" 1)"
    if printf '%s' "$decoded" | python3 -c 'import json,sys; sys.exit(not any(o["scriptPubKey"]["hex"].startswith("6a4c") and "49434e52" in o["scriptPubKey"]["hex"] for o in json.load(sys.stdin)["vout"]))'; then
        REGTX="$id"
        break
    fi
done
test -n "$REGTX"
rpc 0 getrawtransaction "$REGTX" 1 | python3 -c '
import json,sys
r=json.load(sys.stdin)
assert all(i["txid"] != sys.argv[1] or i["vout"] != int(sys.argv[2]) for i in r["vin"])
' "$TXID" "$VOUT"
# Re-sign the fee inputs after corrupting the collateral signature.
RAW="$(rpc 0 getrawtransaction "$REGTX" | tr -d '"[:space:]')"
REGSCRIPT="$(rpc 0 getrawtransaction "$REGTX" 1 | python3 -c 'import json,sys; print(next(o["scriptPubKey"]["hex"] for o in json.load(sys.stdin)["vout"] if "49434e52" in o["scriptPubKey"]["hex"]))')"
FORGED="$(python3 -c 'import sys; raw,script=sys.argv[1:]; bad=script[:-2]+format(int(script[-2:],16)^1,"02x"); assert raw.count(script)==1; print(raw.replace(script,bad))' "$RAW" "$REGSCRIPT")"
SIGNED_FORGED="$(rpc 0 signrawtransaction "$FORGED")"
test "$(printf '%s' "$SIGNED_FORGED" | field complete)" = True
FORGED="$(printf '%s' "$SIGNED_FORGED" | field hex)"
if rpc 0 sendrawtransaction "$FORGED" > "$TEST_DIR/forged-result" 2>&1; then
    echo "forged CN registration was accepted" >&2
    exit 1
fi
grep -q 'CTxMemPool::accept() : invalid CN registration' "$TEST_DIR/node0/regtest/debug.log"
# The valid registration still confirms and must age independently of its collateral.
mine_to 0 "$((FORK+103))"
sync_pair 1 0
assert_amount 0 0
mine_to 0 "$((FORK+202))"
sync_pair 1 0
assert_amount 0 0
mine_to 0 "$((FORK+203))"
sync_pair 1 0
PAYEE0="$(template 0 | field payee_script)"
PAYEE1="$(template 1 | field payee_script)"
test -n "$PAYEE0" && test "$PAYEE0" = "$PAYEE1"
test "$(template 0 | field payee)" = "$ADDRESS"
echo "PASS: registration required, forged signature refused, independent payees agree"
stop 1
start 1
sync_pair 1 0
test "$(template 1 | field payee)" = "$ADDRESS"
echo "PASS: registered payee survives restart"
start 2
sync_pair 2 0
test "$(template 2 | field payee)" = "$ADDRESS"
echo "PASS: fresh chain replay recovers the registered payee"

# An upgraded node lacks payee state and undo for blocks it connected before the
# upgrade; it must still reorganize through them.
H="$(height 0)"
stop 1
mine_to 0 "$((H+3))"
for ((k=0; k<120; k++)); do [ "$(best 2)" = "$(best 0)" ] && break; sleep 1; done
test "$(best 2)" = "$(best 0)"
stop 2
start 2 -regtestcnpayeedropundo=10
start 1
mine_to 1 "$((H+6))"
sync_pair 2 1
test "$(height 2)" = "$((H+6))"
test "$(template 2 | field payee)" = "$ADDRESS"
test "$(template 2 | field payee_script)" = "$(template 1 | field payee_script)"
stop 2
start 2
sync_pair 2 1
test "$(template 2 | field payee)" = "$ADDRESS"
sync_pair 0 1
test "$(best 0)" = "$(best 1)"
echo "PASS: upgraded node reorganizes through blocks without payee undo"

VOUT="$(rpc 0 getrawtransaction "$TXID" 1 | python3 -c 'import json,sys; print(next(o["n"] for o in json.load(sys.stdin)["vout"] if o["value"] == 25000))')"
DEST="$(rpc 0 getnewaddress | tr -d '"[:space:]')"
RAW="$(rpc 0 createrawtransaction "[{\"txid\":\"$TXID\",\"vout\":$VOUT}]" "{\"$DEST\":24999}" | tr -d '"[:space:]')"
SIGNED="$(rpc 0 signrawtransaction "$RAW" | field hex)"
rpc 0 sendrawtransaction "$SIGNED" >/dev/null
mine_to 0 "$(($(height 0)+1))"
sync_pair 1 0
assert_amount 0 0
echo "PASS: spent collateral is skipped and the no-CN fallback resumes"

sync_pair 2 0
assert_amount 2 0
echo "PASS: all nodes drop spent registered collateral"
