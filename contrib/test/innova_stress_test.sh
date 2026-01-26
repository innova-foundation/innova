#!/bin/bash
# Copyright (c) 2019-2026 The Innova developers
# Innova Chain Stress Test Script
# Tests consensus, performance, and stability
# Author: 0xcircuitbreaker - CircuitBreaker
# Usage: ./innova_stress_test.sh [options]
#   --nodes N       Number of nodes to run (default: 3)
#   --duration S    Test duration in seconds (default: 300)
#   --tx-rate N     Transactions per second target (default: 10)
#   --clean         Clean up data directories before starting
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNOVA_DIR="${SCRIPT_DIR}/../.."
INNOVAD="${INNOVA_DIR}/src/innovad"
INNOVA_CLI="${INNOVAD}"

NUM_NODES=${NUM_NODES:-3}
TEST_DURATION=${TEST_DURATION:-300}
TX_RATE=${TX_RATE:-10}
CLEAN_START=${CLEAN_START:-false}

TEST_DIR="/tmp/innova_stress_test"
LOG_DIR="${TEST_DIR}/logs"
RESULTS_FILE="${TEST_DIR}/results.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --nodes)
            NUM_NODES="$2"
            shift 2
            ;;
        --duration)
            TEST_DURATION="$2"
            shift 2
            ;;
        --tx-rate)
            TX_RATE="$2"
            shift 2
            ;;
        --clean)
            CLEAN_START=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "  --nodes N       Number of nodes (default: 3)"
            echo "  --duration S    Test duration in seconds (default: 300)"
            echo "  --tx-rate N     Target transactions per second (default: 10)"
            echo "  --clean         Clean data directories before starting"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%H:%M:%S') $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $(date '+%H:%M:%S') $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%H:%M:%S') $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    if [[ ! -x "${INNOVAD}" ]]; then
        log_error "innovad not found at ${INNOVAD}"
        log_info "Please build the project first: cd src && make -f makefile.osx"
        exit 1
    fi

    for cmd in jq bc curl; do
        if ! command -v $cmd &> /dev/null; then
            log_error "$cmd is required but not installed"
            exit 1
        fi
    done

    log_success "Prerequisites OK"
}

create_node_config() {
    local node_id=$1
    local data_dir="${TEST_DIR}/node${node_id}"
    local rpc_port=$((15530 + node_id))
    local p2p_port=$((15539 + node_id))

    mkdir -p "${data_dir}"

    cat > "${data_dir}/innova.conf" << EOF
# Testnet stress test configuration for node ${node_id}
testnet=1
server=1
daemon=0
rpcuser=stresstest
rpcpassword=stresstestpass${node_id}
rpcport=${rpc_port}
port=${p2p_port}
rpcallowip=127.0.0.1
listen=1
listenonion=0
upnp=0
dnsseed=0
staking=1
stakemindepth=1
stakemintime=1
debug=1
printtoconsole=0
logtimestamps=1
logips=1
maxconnections=50
idns=0
EOF

    for ((i=0; i<NUM_NODES; i++)); do
        if [[ $i -ne $node_id ]]; then
            local other_port=$((15539 + i))
            echo "addnode=127.0.0.1:${other_port}" >> "${data_dir}/innova.conf"
        fi
    done

    echo "${data_dir}"
}

start_node() {
    local node_id=$1
    local data_dir="${TEST_DIR}/node${node_id}"
    local log_file="${LOG_DIR}/node${node_id}.log"

    log_info "Starting node ${node_id}..."

    "${INNOVAD}" -datadir="${data_dir}" -testnet > "${log_file}" 2>&1 &
    local pid=$!
    echo $pid > "${data_dir}/innovad.pid"

    local rpc_port=$((15530 + node_id))
    local max_wait=60
    local waited=0

    while ! curl -s --user stresstest:stresstestpass${node_id} \
        --data-binary '{"jsonrpc":"1.0","id":"test","method":"getinfo","params":[]}' \
        -H 'content-type:text/plain;' \
        http://127.0.0.1:${rpc_port}/ > /dev/null 2>&1; do
        sleep 1
        waited=$((waited + 1))
        if [[ $waited -ge $max_wait ]]; then
            log_error "Node ${node_id} failed to start within ${max_wait}s"
            return 1
        fi
    done

    log_success "Node ${node_id} started (PID: ${pid}, RPC: ${rpc_port})"
    return 0
}

stop_node() {
    local node_id=$1
    local data_dir="${TEST_DIR}/node${node_id}"
    local pid_file="${data_dir}/innovad.pid"

    if [[ -f "${pid_file}" ]]; then
        local pid=$(cat "${pid_file}")
        if kill -0 $pid 2>/dev/null; then
            log_info "Stopping node ${node_id} (PID: ${pid})..."
            kill $pid 2>/dev/null || true
            sleep 2
            kill -9 $pid 2>/dev/null || true
        fi
        rm -f "${pid_file}"
    fi
}

rpc_call() {
    local node_id=$1
    local method=$2
    shift 2
    local params="$@"

    local rpc_port=$((15530 + node_id))

    if [[ -z "$params" ]]; then
        params="[]"
    fi

    curl -s --user stresstest:stresstestpass${node_id} \
        --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"stress\",\"method\":\"${method}\",\"params\":${params}}" \
        -H 'content-type:text/plain;' \
        http://127.0.0.1:${rpc_port}/ 2>/dev/null
}

get_block_height() {
    local node_id=$1
    local result=$(rpc_call $node_id "getblockcount")
    echo "$result" | jq -r '.result // 0'
}

get_block_hash() {
    local node_id=$1
    local height=$2
    local result=$(rpc_call $node_id "getblockhash" "[${height}]")
    echo "$result" | jq -r '.result // ""'
}

get_connection_count() {
    local node_id=$1
    local result=$(rpc_call $node_id "getconnectioncount")
    echo "$result" | jq -r '.result // 0'
}

get_new_address() {
    local node_id=$1
    local result=$(rpc_call $node_id "getnewaddress")
    echo "$result" | jq -r '.result // ""'
}

get_balance() {
    local node_id=$1
    local result=$(rpc_call $node_id "getbalance")
    echo "$result" | jq -r '.result // 0'
}

send_transaction() {
    local from_node=$1
    local to_address=$2
    local amount=$3

    local result=$(rpc_call $from_node "sendtoaddress" "[\"${to_address}\", ${amount}]")
    echo "$result" | jq -r '.result // ""'
}

check_consensus() {
    local height=$1
    local first_hash=""
    local consensus=true

    for ((i=0; i<NUM_NODES; i++)); do
        local node_height=$(get_block_height $i)

        if [[ $node_height -ge $height ]]; then
            local hash=$(get_block_hash $i $height)

            if [[ -z "$first_hash" ]]; then
                first_hash="$hash"
            elif [[ "$hash" != "$first_hash" ]]; then
                consensus=false
                log_error "Consensus failure at height ${height}!"
                log_error "  Node 0: ${first_hash}"
                log_error "  Node ${i}: ${hash}"
            fi
        fi
    done

    echo $consensus
}

monitor_nodes() {
    local start_time=$(date +%s)
    local last_heights=()
    local total_txs=0
    local consensus_failures=0

    for ((i=0; i<NUM_NODES; i++)); do
        last_heights[$i]=0
    done

    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))

        if [[ $elapsed -ge $TEST_DURATION ]]; then
            break
        fi

        echo ""
        log_info "=== Status at ${elapsed}s / ${TEST_DURATION}s ==="

        local min_height=999999999
        local max_height=0

        for ((i=0; i<NUM_NODES; i++)); do
            local height=$(get_block_height $i)
            local connections=$(get_connection_count $i)
            local balance=$(get_balance $i)

            if [[ $height -lt $min_height ]]; then min_height=$height; fi
            if [[ $height -gt $max_height ]]; then max_height=$height; fi

            local blocks_produced=$((height - last_heights[$i]))
            last_heights[$i]=$height

            echo "  Node ${i}: height=${height} conns=${connections} balance=${balance} (+${blocks_produced} blocks)"
        done

        local height_diff=$((max_height - min_height))
        if [[ $height_diff -gt 5 ]]; then
            log_warn "Nodes out of sync by ${height_diff} blocks"
        else
            log_success "Nodes in sync (diff: ${height_diff})"
        fi

        if [[ $min_height -gt 0 ]]; then
            local consensus=$(check_consensus $min_height)
            if [[ "$consensus" == "false" ]]; then
                consensus_failures=$((consensus_failures + 1))
            fi
        fi

        local mempool_result=$(rpc_call 0 "getrawmempool")
        local mempool_size=$(echo "$mempool_result" | jq -r '.result | length // 0')
        echo "  Mempool: ${mempool_size} transactions"

        sleep 10
    done

    echo ""
    log_info "=== Final Statistics ==="
    echo "  Test duration: ${TEST_DURATION}s"
    echo "  Consensus failures: ${consensus_failures}"

    local final_min_height=999999999
    for ((i=0; i<NUM_NODES; i++)); do
        local height=$(get_block_height $i)
        if [[ $height -lt $final_min_height ]]; then final_min_height=$height; fi
    done

    if [[ $final_min_height -gt 0 ]]; then
        local final_consensus=$(check_consensus $final_min_height)
        if [[ "$final_consensus" == "true" ]]; then
            log_success "Final consensus check PASSED at height ${final_min_height}"
        else
            log_error "Final consensus check FAILED at height ${final_min_height}"
        fi
    fi
}

tx_stress_test() {
    log_info "Starting transaction stress test..."
    log_info "Target rate: ${TX_RATE} tx/s for ${TEST_DURATION}s"

    local start_time=$(date +%s)
    local tx_count=0
    local tx_failed=0
    local sleep_time=$(echo "scale=3; 1/${TX_RATE}" | bc)

    local addresses=()
    for ((i=0; i<NUM_NODES; i++)); do
        addresses[$i]=$(get_new_address $i)
        log_info "Node ${i} address: ${addresses[$i]}"
    done

    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))

        if [[ $elapsed -ge $TEST_DURATION ]]; then
            break
        fi

        local from=$((RANDOM % NUM_NODES))
        local to=$((RANDOM % NUM_NODES))
        while [[ $to -eq $from ]]; do
            to=$((RANDOM % NUM_NODES))
        done

        local balance=$(get_balance $from)
        if (( $(echo "$balance > 1" | bc -l) )); then
            local amount=$(echo "scale=8; 0.001 + ($RANDOM / 32768) * 0.01" | bc)
            local txid=$(send_transaction $from "${addresses[$to]}" $amount)

            if [[ -n "$txid" && "$txid" != "null" ]]; then
                tx_count=$((tx_count + 1))
                if [[ $((tx_count % 100)) -eq 0 ]]; then
                    log_info "Sent ${tx_count} transactions..."
                fi
            else
                tx_failed=$((tx_failed + 1))
            fi
        fi

        sleep $sleep_time 2>/dev/null || sleep 1
    done

    log_info "Transaction stress test complete"
    log_info "  Total sent: ${tx_count}"
    log_info "  Failed: ${tx_failed}"

    echo "{\"tx_sent\": ${tx_count}, \"tx_failed\": ${tx_failed}}" > "${TEST_DIR}/tx_stats.json"
}

monitor_performance() {
    local start_time=$(date +%s)

    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))

        if [[ $elapsed -ge $TEST_DURATION ]]; then
            break
        fi

        for ((i=0; i<NUM_NODES; i++)); do
            local pid_file="${TEST_DIR}/node${i}/innovad.pid"
            if [[ -f "$pid_file" ]]; then
                local pid=$(cat "$pid_file")
                if kill -0 $pid 2>/dev/null; then
                    local mem=$(ps -o rss= -p $pid 2>/dev/null | tr -d ' ')
                    local mem_mb=$((mem / 1024))
                    echo "$(date +%s),node${i},${mem_mb}" >> "${TEST_DIR}/memory_stats.csv"
                fi
            fi
        done

        sleep 5
    done
}

cleanup() {
    log_info "Cleaning up..."

    for ((i=0; i<NUM_NODES; i++)); do
        stop_node $i
    done

    log_success "Cleanup complete"
}

main() {
    echo ""
    echo "========================================"
    echo "  Innova Chain Stress Test"
    echo "========================================"
    echo "  Nodes: ${NUM_NODES}"
    echo "  Duration: ${TEST_DURATION}s"
    echo "  TX Rate: ${TX_RATE}/s"
    echo "========================================"
    echo ""

    trap cleanup EXIT

    check_prerequisites

    if [[ "$CLEAN_START" == "true" ]]; then
        log_info "Cleaning test directory..."
        rm -rf "${TEST_DIR}"
    fi

    mkdir -p "${TEST_DIR}" "${LOG_DIR}"
    echo "timestamp,node,memory_mb" > "${TEST_DIR}/memory_stats.csv"

    for ((i=0; i<NUM_NODES; i++)); do
        create_node_config $i
        if ! start_node $i; then
            log_error "Failed to start node ${i}"
            exit 1
        fi
    done

    log_info "Waiting for nodes to connect..."
    sleep 10

    for ((i=0; i<NUM_NODES; i++)); do
        local conns=$(get_connection_count $i)
        log_info "Node ${i} has ${conns} connections"
    done

    monitor_performance &
    PERF_PID=$!

    tx_stress_test &
    TX_PID=$!

    monitor_nodes

    wait $TX_PID 2>/dev/null || true
    kill $PERF_PID 2>/dev/null || true

    log_info "Generating final report..."

    cat > "${RESULTS_FILE}" << EOF
{
    "test_config": {
        "num_nodes": ${NUM_NODES},
        "duration_seconds": ${TEST_DURATION},
        "tx_rate_target": ${TX_RATE}
    },
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "results": {
        "status": "complete"
    }
}
EOF

    log_success "Results saved to ${RESULTS_FILE}"
    log_success "Logs available in ${LOG_DIR}"

    echo ""
    echo "========================================"
    echo "  Stress Test Complete"
    echo "========================================"
}

main "$@"
