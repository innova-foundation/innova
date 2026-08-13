#!/bin/bash
# Copyright (c) 2026 The Innova developers
# Proof-of-data RPC surface on regtest: -enablefilerpc gating and cross-command stamp
# verification. POD_IPFS_ENDPOINT (e.g. ipfs_api_stub.py) enables the hyperfile section.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INNOVAD="${INNOVAD:-$INNOVA_ROOT/src/innovad}"

TEST_DIR="${POD_TEST_DIR:-/tmp/innova_pod_$$}"
NODE_DIR="$TEST_DIR/node0"
PORT="${POD_PORT:-29500}"
RPC="${POD_RPC:-29501}"
IDNS="${POD_IDNS:-29502}"
RPCUSER="podtest"
RPCPASS="podtestpass"

SEED_HEIGHT=140

PASSED=0
FAILED=0
SKIPPED=0

log()     { echo -e "${BLUE}[TEST]${NC} $*"; }
success() { echo -e "${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED + 1)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED + 1)); }
skip()    { echo -e "${YELLOW}[SKIP]${NC} $*"; SKIPPED=$((SKIPPED + 1)); }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
header()  { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================${NC}"; }

rpc() { "$INNOVAD" -datadir="$NODE_DIR" -regtest -rpcuser=$RPCUSER \
        -rpcpassword=$RPCPASS -rpcport=$RPC "$@" 2>&1; }

height() { rpc getblockcount 2>/dev/null | tr -d '"[:space:]'; }
is_int() { echo "$1" | grep -qE '^[0-9]+$'; }

jget() {
    FIELD="$2" python3 -c '
import json, os, sys
try:
    v = json.load(sys.stdin).get(os.environ["FIELD"])
    print("" if v is None else v)
except Exception:
    print("")
' <<< "$1" 2>/dev/null
}

stop_node() {
    rpc stop >/dev/null 2>&1 || true
    for _ in $(seq 1 180); do
        pgrep -f -- "-datadir=$NODE_DIR -regtest -daemon" >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}

# Extra daemon arguments differ per section, so the node is restarted rather
# than reconfigured: -enablefilerpc is read at call time but only from argv/conf.
start_node() {
    "$INNOVAD" -datadir="$NODE_DIR" -regtest -daemon "$@" >/dev/null 2>&1
    for _ in $(seq 1 90); do
        rpc getinfo >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

mine_to_exact() {
    local target="$1" h last=-1 idle=0
    h="$(height)"
    is_int "$h" || return 1
    [ "$h" -ge "$target" ] && return 0
    rpc setgenerate true $(( target - h )) >/dev/null 2>&1
    for _ in $(seq 1 300); do
        sleep 2
        h="$(height)"
        is_int "$h" || continue
        [ "$h" -ge "$target" ] && break
        if [ "$h" = "$last" ]; then
            idle=$(( idle + 1 ))
            [ "$idle" -ge 5 ] && { rpc setgenerate true $(( target - h )) >/dev/null 2>&1; idle=0; }
        else
            idle=0; last="$h"
        fi
    done
    [ "$(height)" -ge "$target" ]
}

# Mines until the stamp is in a block. Everything downstream reads a block time,
# and an unconfirmed stamp attests to nothing.
confirm_tx() {
    local txid="$1" raw
    for _ in $(seq 1 30); do
        raw="$(rpc getrawtransaction "$txid" 1 2>/dev/null)"
        echo "$raw" | grep -q '"blockhash"' && return 0
        rpc setgenerate true 1 >/dev/null 2>&1
        sleep 2
    done
    return 1
}

STUB_PID=""
cleanup() {
    [ -n "$STUB_PID" ] && kill "$STUB_PID" >/dev/null 2>&1
    stop_node || true
    [ "${POD_KEEP_DIR:-0}" = "1" ] || rm -rf "$TEST_DIR"
}
trap cleanup EXIT

header "Proof of data: stamps, verification and the file-RPC gate"

rm -rf "$TEST_DIR"; mkdir -p "$NODE_DIR"
cat > "$NODE_DIR/innova.conf" <<EOF
regtest=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$RPC
port=$PORT
listen=1
idnsport=$IDNS
dnsseed=0
stakingmode=0
nofinalityvoting=1
maxconnections=125
EOF

DATA_FILE="$TEST_DIR/subject.bin"
ABSENT_FILE="$TEST_DIR/no-such-file-here.bin"
head -c 65536 /dev/urandom > "$DATA_FILE"
FILE_SHA="$(shasum -a 256 "$DATA_FILE" 2>/dev/null | cut -d' ' -f1)"
[ -n "$FILE_SHA" ] || FILE_SHA="$(sha256sum "$DATA_FILE" | cut -d' ' -f1)"
[ ${#FILE_SHA} -eq 64 ] || { fail "could not hash the subject file"; exit 1; }

# ============================================================
header "1. Without -enablefilerpc, nothing reads the filesystem"
# ============================================================

start_node || { fail "node did not start"; exit 1; }
success "node started without -enablefilerpc"

OUT="$(rpc proofofdata "$DATA_FILE" false)"
if echo "$OUT" | grep -q "enablefilerpc"; then
    success "proofofdata is refused and names the flag"
else
    fail "proofofdata was not gated: $(echo "$OUT" | head -2)"
fi

# The point of the gate is that a caller learns nothing about the filesystem.
# A path that exists and a path that does not must produce the same refusal.
OUT_PRESENT="$(rpc podverify "$DATA_FILE" 0000000000000000000000000000000000000000000000000000000000000000)"
OUT_ABSENT="$(rpc podverify "$ABSENT_FILE" 0000000000000000000000000000000000000000000000000000000000000000)"
if [ "$OUT_PRESENT" = "$OUT_ABSENT" ] && echo "$OUT_PRESENT" | grep -q "enablefilerpc"; then
    success "podverify answers a present and an absent path identically"
else
    fail "podverify leaks path existence: present=[$(echo "$OUT_PRESENT" | head -1)] absent=[$(echo "$OUT_ABSENT" | head -1)]"
fi

# A digest target must still work unflagged, or a stamp cannot be checked by
# anyone who was not the node operator.
OUT="$(rpc podverify "$FILE_SHA" 0000000000000000000000000000000000000000000000000000000000000000)"
if echo "$OUT" | grep -q "No transaction with that txid"; then
    success "a digest target is accepted unflagged and fails only on the txid"
else
    fail "digest target was rejected unflagged: $(echo "$OUT" | head -2)"
fi

# ============================================================
header "2. With the flag, a plain stamp round-trips"
# ============================================================

stop_node || { fail "node would not stop"; exit 1; }
start_node -enablefilerpc=1 || { fail "node did not restart"; exit 1; }
mine_to_exact "$SEED_HEIGHT" || { fail "could not mine to $SEED_HEIGHT"; exit 1; }
success "chain at $(height) with a funded wallet"

OUT="$(rpc proofofdata "$DATA_FILE" false)"
PLAIN_TXID="$(jget "$OUT" podtxid)"
PLAIN_DIGEST="$(jget "$OUT" stampdigest)"
if [ ${#PLAIN_TXID} -eq 64 ] && [ "$PLAIN_DIGEST" = "$FILE_SHA" ]; then
    success "plain stamp published, on-chain digest equals sha256sum"
else
    fail "plain stamp failed: $(echo "$OUT" | head -4)"
fi

confirm_tx "$PLAIN_TXID" || { fail "the plain stamp never confirmed"; exit 1; }

OUT="$(rpc podverify "$DATA_FILE" "$PLAIN_TXID")"
if [ "$(jget "$OUT" match)" = "True" ] && [ "$(jget "$OUT" legacy)" = "False" ] \
   && [ "$(jget "$OUT" type)" = "plain" ]; then
    success "podverify matches the file target"
else
    fail "file verification failed: $(echo "$OUT" | head -6)"
fi

OUT="$(rpc podverify "$FILE_SHA" "$PLAIN_TXID")"
if [ "$(jget "$OUT" match)" = "True" ]; then
    success "podverify matches the same stamp from the bare digest"
else
    fail "digest verification failed: $(echo "$OUT" | head -6)"
fi

BLOCKTIME="$(jget "$OUT" blocktime)"
if is_int "$BLOCKTIME" && [ "$BLOCKTIME" -gt 0 ]; then
    success "the stamp is anchored to a block time ($BLOCKTIME)"
else
    fail "no block time reported: $(echo "$OUT" | head -8)"
fi

# A different file must not verify against this stamp.
OTHER="$TEST_DIR/other.bin"
head -c 4096 /dev/urandom > "$OTHER"
OUT="$(rpc podverify "$OTHER" "$PLAIN_TXID")"
if [ "$(jget "$OUT" match)" = "False" ]; then
    success "an unrelated file does not verify"
else
    fail "an unrelated file verified: $(echo "$OUT" | head -4)"
fi

# ============================================================
header "3. A blinded stamp needs its salt"
# ============================================================

OUT="$(rpc proofofdata "$DATA_FILE" true)"
BLIND_TXID="$(jget "$OUT" podtxid)"
BLIND_SALT="$(jget "$OUT" salt)"
BLIND_DIGEST="$(jget "$OUT" stampdigest)"
if [ ${#BLIND_TXID} -eq 64 ] && [ ${#BLIND_SALT} -eq 64 ] && [ "$BLIND_DIGEST" != "$FILE_SHA" ]; then
    success "blinded stamp published, on-chain digest differs from the file's"
else
    fail "blinded stamp failed: $(echo "$OUT" | head -5)"
fi

confirm_tx "$BLIND_TXID" || { fail "the blinded stamp never confirmed"; exit 1; }

OUT="$(rpc podverify "$DATA_FILE" "$BLIND_TXID")"
if echo "$OUT" | grep -q "salt-hex is required"; then
    success "verification without the salt is refused, not reported as a mismatch"
else
    fail "blinded stamp verified without a salt: $(echo "$OUT" | head -4)"
fi

OUT="$(rpc podverify "$DATA_FILE" "$BLIND_TXID" "$BLIND_SALT")"
if [ "$(jget "$OUT" match)" = "True" ] && [ "$(jget "$OUT" type)" = "blinded" ]; then
    success "verification with the salt matches"
else
    fail "blinded verification failed: $(echo "$OUT" | head -6)"
fi

WRONG_SALT="$(python3 -c 'print("ab"*32)')"
OUT="$(rpc podverify "$DATA_FILE" "$BLIND_TXID" "$WRONG_SALT")"
if [ "$(jget "$OUT" match)" = "False" ]; then
    success "the wrong salt does not match"
else
    fail "the wrong salt matched: $(echo "$OUT" | head -4)"
fi

# ============================================================
header "4. Hyperfile against a reachable IPFS API"
# ============================================================

ENDPOINT="${POD_IPFS_ENDPOINT:-}"
if [ -z "$ENDPOINT" ] && [ -f "$SCRIPT_DIR/ipfs_api_stub.py" ]; then
    STUB_PORT="${POD_IPFS_PORT:-25801}"
    python3 "$SCRIPT_DIR/ipfs_api_stub.py" "$STUB_PORT" > "$TEST_DIR/ipfs_stub.log" 2>&1 &
    STUB_PID=$!
    for _ in $(seq 1 20); do
        curl -s -m 2 -X POST "http://127.0.0.1:$STUB_PORT/api/v0/version" >/dev/null 2>&1 && break
        sleep 0.5
    done
    if kill -0 "$STUB_PID" >/dev/null 2>&1; then
        ENDPOINT="127.0.0.1:$STUB_PORT"
        log "using the bundled IPFS API stub on $ENDPOINT"
    else
        STUB_PID=""
    fi
fi

if [ -z "$ENDPOINT" ]; then
    skip "no IPFS endpoint; hyperfileupload and hyperfilepod were not exercised"
else
    stop_node || { fail "node would not stop"; exit 1; }
    start_node -enablefilerpc=1 -hyperfilelocal=1 -hyperfileip="$ENDPOINT" \
        || { fail "node did not restart with hyperfile enabled"; exit 1; }

    OUT="$(rpc hyperfileversion)"
    if [ "$(jget "$OUT" connected)" = "True" ]; then
        success "hyperfileversion reaches the endpoint"
    else
        fail "hyperfileversion failed: $(echo "$OUT" | head -4)"
    fi

    OUT="$(rpc hyperfileupload "$DATA_FILE")"
    UPLOAD_CID="$(jget "$OUT" ipfshash)"
    if [ "${UPLOAD_CID:0:2}" = "Qm" ] && [ ${#UPLOAD_CID} -ge 46 ]; then
        success "hyperfileupload returned CIDv0 $UPLOAD_CID"
    else
        fail "hyperfileupload failed: $(echo "$OUT" | head -4)"
    fi

    OUT="$(rpc hyperfilepod "$DATA_FILE")"
    POD_CID="$(jget "$OUT" ipfshash)"
    POD_TXID="$(jget "$OUT" podtxid)"
    POD_SHA="$(jget "$OUT" filesha256)"
    if [ "$(jget "$OUT" stamped)" = "True" ] && [ ${#POD_TXID} -eq 64 ]; then
        success "hyperfilepod uploaded and stamped in one call"
    else
        fail "hyperfilepod failed: $(echo "$OUT" | head -8)"
    fi

    if [ "$POD_SHA" = "$FILE_SHA" ]; then
        success "the stamped digest is the file's own sha256sum, not the CID's"
    else
        fail "stamped digest $POD_SHA != $FILE_SHA"
    fi

    if [ "$POD_CID" = "$UPLOAD_CID" ]; then
        success "the same bytes produced the same CID on both paths"
    else
        fail "CID differs between upload and pod: $UPLOAD_CID vs $POD_CID"
    fi

    confirm_tx "$POD_TXID" || { fail "the hyperfile stamp never confirmed"; exit 1; }

    OUT="$(rpc podverify "$DATA_FILE" "$POD_TXID")"
    if [ "$(jget "$OUT" match)" = "True" ] && [ "$(jget "$OUT" type)" = "hyperfile" ]; then
        success "the hyperfile stamp verifies from the file"
    else
        fail "hyperfile verification failed: $(echo "$OUT" | head -8)"
    fi

    if [ "$(jget "$OUT" locatorcid)" = "$POD_CID" ]; then
        success "the stamp carries the CID as its locator"
    else
        fail "locator missing or wrong: $(echo "$OUT" | head -8)"
    fi

    OUT="$(rpc podverify "$POD_CID" "$POD_TXID")"
    if [ "$(jget "$OUT" locatormatch)" = "True" ]; then
        success "a CID target matches the locator"
    else
        fail "CID target did not match: $(echo "$OUT" | head -8)"
    fi
    if echo "$OUT" | grep -q "retrieval hint"; then
        success "a CID-only match says the locator is not the proof"
    else
        fail "a CID-only match did not qualify itself: $(echo "$OUT" | head -8)"
    fi

    # A rotated CID must not undo a digest that matches.
    STALE_CID="QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT"
    OUT="$(rpc podverify "$FILE_SHA" "$POD_TXID" "" "$STALE_CID")"
    if [ "$(jget "$OUT" match)" = "True" ] && [ "$(jget "$OUT" locatormatch)" = "False" ] \
       && echo "$OUT" | grep -q "locator stale"; then
        success "a stale locator is reported as verified with a stale locator"
    else
        fail "stale-locator path wrong: $(echo "$OUT" | head -10)"
    fi
fi

# ============================================================
header "Summary"
# ============================================================
echo -e "${GREEN}Passed:${NC}  $PASSED"
echo -e "${RED}Failed:${NC}  $FAILED"
echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
