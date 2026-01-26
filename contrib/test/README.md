# Innova Testing Tools

## Quick Test

```bash
./quick_test.sh
```

This tests:
- Binary existence and version
- Node startup
- Basic RPC commands
- Address validation

## Stress Test

Run a comprehensive stress test with multiple nodes:

```bash
./innova_stress_test.sh [options]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--nodes N` | Number of nodes to run | 3 |
| `--duration S` | Test duration in seconds | 300 |
| `--tx-rate N` | Target transactions per second | 10 |
| `--clean` | Clean data directories first | false |

### Examples

```bash
# Quick 1-minute test w/ 2 nodes
./innova_stress_test.sh --nodes 2 --duration 60

# Full stress test w/ 5 nodes for 10 minutes
./innova_stress_test.sh --nodes 5 --duration 600 --tx-rate 20

# Clean start
./innova_stress_test.sh --clean --nodes 3 --duration 300
```

### What It Tests

1. **Consensus** - Verifies all nodes agree on block hashes
2. **Performance** - Measures block production rate
3. **Transaction Throughput** - Sends transactions between nodes
4. **Memory Usage** - Monitors RAM consumption over time
5. **Network Sync** - Checks nodes stay in sync

### Output

Results are saved to `/tmp/innova_stress_test/`:
- `results.json` - Final test results
- `memory_stats.csv` - Memory usage over time
- `tx_stats.json` - Transaction statistics
- `logs/` - Node debug logs

## Requirements

- Built `innovad` binary
- `jq` - JSON processor
- `bc` - Calculator
- `curl` - HTTP client

Install on macOS:
```bash
brew install jq bc curl
```

## Testnet Mode

All tests run in testnet mode (`-testnet`) to avoid hitting mainnet.

Testnet ports:
- RPC: 15531
- P2P: 15539