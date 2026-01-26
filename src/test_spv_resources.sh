#!/bin/bash
#
# Innova SPV Mode Resource Monitoring Script
# Tracks memory, CPU, disk usage during SPV operation
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

DATADIR="${DATADIR:-$HOME/.innova-spv-test}"
DAEMON="./innovad"
CLI="./innova-cli"
RPC_PORT=15532
LOG_FILE="$DATADIR/resource_monitor.log"
RESULTS_FILE="$DATADIR/spv_test_results.txt"
MONITOR_INTERVAL=5
TEST_DURATION=300

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_metric() { echo -e "${CYAN}[METRIC]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    $CLI -datadir="$DATADIR" -testnet stop 2>/dev/null || true
    sleep 2
    pkill -f "innovad.*$DATADIR" 2>/dev/null || true
}

trap cleanup EXIT

get_pid() {
    pgrep -f "innovad.*$DATADIR" | head -1
}

get_memory_mb() {
    local pid=$1
    if [ -z "$pid" ]; then
        echo "0"
        return
    fi

    if [[ "$OSTYPE" == "darwin"* ]]; then
        ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f", $1/1024}' || echo "0"
    else
        ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f", $1/1024}' || echo "0"
    fi
}

get_vmem_mb() {
    local pid=$1
    if [ -z "$pid" ]; then
        echo "0"
        return
    fi

    if [[ "$OSTYPE" == "darwin"* ]]; then
        ps -o vsz= -p "$pid" 2>/dev/null | awk '{printf "%.1f", $1/1024}' || echo "0"
    else
        ps -o vsz= -p "$pid" 2>/dev/null | awk '{printf "%.1f", $1/1024}' || echo "0"
    fi
}

get_cpu_percent() {
    local pid=$1
    if [ -z "$pid" ]; then
        echo "0"
        return
    fi

    ps -o %cpu= -p "$pid" 2>/dev/null | awk '{printf "%.1f", $1}' || echo "0"
}

get_disk_mb() {
    if [ -d "$DATADIR" ]; then
        du -sm "$DATADIR" 2>/dev/null | awk '{print $1}' || echo "0"
    else
        echo "0"
    fi
}

get_block_height() {
    $CLI -datadir="$DATADIR" -testnet getblockcount 2>/dev/null || echo "0"
}

get_connections() {
    $CLI -datadir="$DATADIR" -testnet getconnectioncount 2>/dev/null || echo "0"
}

setup_datadir() {
    log_info "Setting up SPV test data directory: $DATADIR"

    mkdir -p "$DATADIR"

    cat > "$DATADIR/innova.conf" << EOF
testnet=1
server=1
rpcuser=innovatest
rpcpassword=testpass456
rpcport=$RPC_PORT
rpcallowip=127.0.0.1
listen=1
debug=1
logtimestamps=1
# SPV specific settings
maxconnections=16
EOF

    log_ok "Data directory configured"
}

start_daemon_spv() {
    log_info "Starting innovad in Hybrid SPV mode..."

    $DAEMON -datadir="$DATADIR" -testnet -hybridspv &

    local attempts=0
    while [ $attempts -lt 60 ]; do
        if $CLI -datadir="$DATADIR" -testnet getinfo &>/dev/null; then
            log_ok "SPV Daemon started successfully"
            return 0
        fi
        sleep 1
        ((attempts++))
    done

    log_error "SPV Daemon failed to start"
    return 1
}

start_daemon_normal() {
    log_info "Starting innovad in Normal mode (for comparison)..."

    $DAEMON -datadir="$DATADIR" -testnet &

    local attempts=0
    while [ $attempts -lt 60 ]; do
        if $CLI -datadir="$DATADIR" -testnet getinfo &>/dev/null; then
            log_ok "Normal Daemon started successfully"
            return 0
        fi
        sleep 1
        ((attempts++))
    done

    log_error "Normal Daemon failed to start"
    return 1
}

stop_daemon() {
    log_info "Stopping daemon..."
    $CLI -datadir="$DATADIR" -testnet stop 2>/dev/null || true

    local attempts=0
    while [ $attempts -lt 30 ]; do
        if ! pgrep -f "innovad.*$DATADIR" &>/dev/null; then
            log_ok "Daemon stopped"
            return 0
        fi
        sleep 1
        ((attempts++))
    done

    pkill -9 -f "innovad.*$DATADIR" 2>/dev/null || true
}

monitor_resources() {
    local mode=$1
    local duration=$2
    local output_file=$3

    log_info "Monitoring $mode mode for ${duration}s..."

    local pid=$(get_pid)
    if [ -z "$pid" ]; then
        log_error "Cannot find daemon PID"
        return 1
    fi

    log_info "Daemon PID: $pid"

    local max_mem=0
    local min_mem=999999
    local total_mem=0
    local max_cpu=0
    local samples=0
    local start_time=$(date +%s)
    local start_blocks=$(get_block_height)
    local start_disk=$(get_disk_mb)

    echo "# $mode Mode Resource Monitor - $(date)" > "$output_file"
    echo "# Time, Memory(MB), VMem(MB), CPU(%), Disk(MB), Blocks, Connections" >> "$output_file"

    while true; do
        local elapsed=$(($(date +%s) - start_time))

        if [ $elapsed -ge $duration ]; then
            break
        fi

        local mem=$(get_memory_mb "$pid")
        local vmem=$(get_vmem_mb "$pid")
        local cpu=$(get_cpu_percent "$pid")
        local disk=$(get_disk_mb)
        local blocks=$(get_block_height)
        local conns=$(get_connections)

        local mem_int=${mem%.*}
        if [ "$mem_int" -gt "$max_mem" ]; then max_mem=$mem_int; fi
        if [ "$mem_int" -lt "$min_mem" ] && [ "$mem_int" -gt 0 ]; then min_mem=$mem_int; fi
        total_mem=$((total_mem + mem_int))

        local cpu_int=${cpu%.*}
        if [ "$cpu_int" -gt "$max_cpu" ]; then max_cpu=$cpu_int; fi

        ((samples++))

        echo "$elapsed, $mem, $vmem, $cpu, $disk, $blocks, $conns" >> "$output_file"

        if [ $((samples % 2)) -eq 0 ]; then
            log_metric "Time: ${elapsed}s | Mem: ${mem}MB | CPU: ${cpu}% | Blocks: $blocks | Conns: $conns"
        fi

        sleep $MONITOR_INTERVAL
    done

    local end_blocks=$(get_block_height)
    local end_disk=$(get_disk_mb)
    local avg_mem=$((total_mem / samples))

    echo "$mode,$max_mem,$min_mem,$avg_mem,$max_cpu,$start_blocks,$end_blocks,$start_disk,$end_disk,$samples"
}

run_spv_test() {
    log_info "=== SPV Mode Resource Test ==="

    setup_datadir

    rm -rf "$DATADIR/testnet/blocks" "$DATADIR/testnet/chainstate" 2>/dev/null || true

    start_daemon_spv
    sleep 10

    local spv_stats=$(monitor_resources "SPV" "$TEST_DURATION" "$DATADIR/spv_monitor.csv")

    stop_daemon
    sleep 5

    echo "$spv_stats"
}

run_normal_test() {
    log_info "=== Normal Mode Resource Test (Comparison) ==="

    rm -rf "$DATADIR/testnet/blocks" "$DATADIR/testnet/chainstate" 2>/dev/null || true

    start_daemon_normal
    sleep 10

    local normal_stats=$(monitor_resources "Normal" "$TEST_DURATION" "$DATADIR/normal_monitor.csv")

    stop_daemon
    sleep 5

    echo "$normal_stats"
}

generate_report() {
    local spv_stats=$1
    local normal_stats=$2

    echo ""
    echo "=================================================================="
    echo "          INNOVA SPV RESOURCE TEST REPORT"
    echo "=================================================================="
    echo ""
    echo "Test Date: $(date)"
    echo "Test Duration: ${TEST_DURATION}s per mode"
    echo "Monitor Interval: ${MONITOR_INTERVAL}s"
    echo ""

    IFS=',' read -r mode max_mem min_mem avg_mem max_cpu start_b end_b start_d end_d samples <<< "$spv_stats"

    echo "=== SPV MODE RESULTS ==="
    echo "  Memory Usage:"
    echo "    - Maximum: ${max_mem} MB"
    echo "    - Minimum: ${min_mem} MB"
    echo "    - Average: ${avg_mem} MB"
    echo "  CPU Usage:"
    echo "    - Maximum: ${max_cpu}%"
    echo "  Sync Progress:"
    echo "    - Start Block: $start_b"
    echo "    - End Block: $end_b"
    echo "    - Blocks Synced: $((end_b - start_b))"
    echo "  Disk Usage:"
    echo "    - Start: ${start_d} MB"
    echo "    - End: ${end_d} MB"
    echo "    - Growth: $((end_d - start_d)) MB"
    echo "  Samples Collected: $samples"
    echo ""

    if [ -n "$normal_stats" ]; then
        IFS=',' read -r mode n_max_mem n_min_mem n_avg_mem n_max_cpu n_start_b n_end_b n_start_d n_end_d n_samples <<< "$normal_stats"

        echo "=== NORMAL MODE RESULTS (Comparison) ==="
        echo "  Memory Usage:"
        echo "    - Maximum: ${n_max_mem} MB"
        echo "    - Minimum: ${n_min_mem} MB"
        echo "    - Average: ${n_avg_mem} MB"
        echo "  CPU Usage:"
        echo "    - Maximum: ${n_max_cpu}%"
        echo "  Sync Progress:"
        echo "    - Start Block: $n_start_b"
        echo "    - End Block: $n_end_b"
        echo "    - Blocks Synced: $((n_end_b - n_start_b))"
        echo "  Disk Usage:"
        echo "    - Start: ${n_start_d} MB"
        echo "    - End: ${n_end_d} MB"
        echo "    - Growth: $((n_end_d - n_start_d)) MB"
        echo ""

        echo "=== COMPARISON ==="
        local mem_diff=$((n_avg_mem - avg_mem))
        local mem_pct=0
        if [ "$n_avg_mem" -gt 0 ]; then
            mem_pct=$((mem_diff * 100 / n_avg_mem))
        fi
        local disk_diff=$((n_end_d - end_d))

        echo "  Memory Savings: ${mem_diff} MB (${mem_pct}% reduction)"
        echo "  Disk Savings: ${disk_diff} MB"
        echo ""
    fi

    echo "=== 50MB TARGET ANALYSIS ==="
    if [ "$avg_mem" -le 50 ]; then
        echo "  ✅ SPV mode achieves 50MB target (avg: ${avg_mem} MB)"
    elif [ "$avg_mem" -le 100 ]; then
        echo "  ⚠️  SPV mode close to target (avg: ${avg_mem} MB)"
        echo "     Consider header pruning to reduce further"
    else
        echo "  ❌ SPV mode exceeds 50MB target (avg: ${avg_mem} MB)"
        echo "     Header storage is the main memory consumer"
        echo "     At full chain sync, expect ~600MB+ for headers alone"
    fi
    echo ""

    echo "=== RECOMMENDATIONS ==="
    echo "  1. For true 50MB operation, implement:"
    echo "     - Checkpoint-based startup (skip old headers)"
    echo "     - Header pruning (keep only recent N headers)"
    echo "     - Or compact block filters (Neutrino-style)"
    echo ""
    echo "  2. Current SPV mode provides:"
    echo "     - Significant disk savings (no full blocks)"
    echo "     - Faster initial sync (headers only)"
    echo "     - Staking capability without full validation"
    echo ""

    echo "=================================================================="
    echo "  Raw data saved to:"
    echo "    - $DATADIR/spv_monitor.csv"
    if [ -f "$DATADIR/normal_monitor.csv" ]; then
        echo "    - $DATADIR/normal_monitor.csv"
    fi
    echo "=================================================================="
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -d, --duration SECONDS   Test duration per mode (default: 300)"
    echo "  -i, --interval SECONDS   Monitor interval (default: 5)"
    echo "  -s, --spv-only           Only test SPV mode (skip normal comparison)"
    echo "  -n, --normal-only        Only test Normal mode"
    echo "  -h, --help               Show this help"
    echo ""
    echo "Environment Variables:"
    echo "  DATADIR                  Data directory (default: ~/.innova-spv-test)"
    echo ""
    echo "Examples:"
    echo "  $0                       # Run full test (SPV + Normal comparison)"
    echo "  $0 -d 600 -s             # 10 minute SPV-only test"
    echo "  $0 --duration 60         # Quick 1 minute test"
}

SPV_ONLY=0
NORMAL_ONLY=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--duration)
            TEST_DURATION="$2"
            shift 2
            ;;
        -i|--interval)
            MONITOR_INTERVAL="$2"
            shift 2
            ;;
        -s|--spv-only)
            SPV_ONLY=1
            shift
            ;;
        -n|--normal-only)
            NORMAL_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

main() {
    echo ""
    echo "============================================"
    echo "   INNOVA SPV RESOURCE MONITORING TEST"
    echo "============================================"
    echo ""
    echo "Configuration:"
    echo "  Test Duration: ${TEST_DURATION}s per mode"
    echo "  Monitor Interval: ${MONITOR_INTERVAL}s"
    echo "  Data Directory: $DATADIR"
    echo ""

    if [ ! -x "$DAEMON" ]; then
        log_error "innovad not found at $DAEMON"
        log_info "Please run from the src directory or set correct path"
        exit 1
    fi

    local spv_stats=""
    local normal_stats=""

    if [ $NORMAL_ONLY -eq 0 ]; then
        spv_stats=$(run_spv_test)
    fi

    if [ $SPV_ONLY -eq 0 ] && [ $NORMAL_ONLY -eq 0 ]; then
        normal_stats=$(run_normal_test)
    elif [ $NORMAL_ONLY -eq 1 ]; then
        setup_datadir
        normal_stats=$(run_normal_test)
    fi

    generate_report "$spv_stats" "$normal_stats" | tee "$RESULTS_FILE"

    log_ok "Test complete! Results saved to $RESULTS_FILE"
}

main "$@"
