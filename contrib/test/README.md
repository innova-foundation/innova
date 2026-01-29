# Innova Test Suite

Comprehensive stress testing and validation suite for Innova Core.

## Test Scripts Overview

| Script | Focus Area | Nodes | Mode |
|--------|-----------|-------|------|
| `quick_test.sh` | Basic sanity checks | 1 | Testnet |
| `regtest_test.sh` | Regtest block generation | 1 | Regtest |
| `innova_stress_test.sh` | Multi-node stress (legacy) | 3-5 | Testnet |
| `staking_stress_test.sh` | PoS staking validation | 2 | Regtest |
| `cold_staking_test.sh` | P2CS cold staking | 2 | Regtest |
| `spv_staking_test.sh` | SPV/HybridSPV staking | 2 | Regtest |
| `wallet_stress_test.sh` | Wallet operations | 2 | Regtest |
| `transaction_stress_test.sh` | Transaction types & edge cases | 2 | Regtest |
| `blockchain_stress_test.sh` | Chain structure & reorgs | 3 | Regtest |
| `rpc_stress_test.sh` | Full RPC interface | 1 | Regtest |
| `security_stress_test.sh` | Security & attack vectors | 2 | Regtest |

Additional scripts in `src/`:
| Script | Focus Area |
|--------|-----------|
| `src/test_staking.sh` | Staking info on testnet |
| `src/test_spv_resources.sh` | SPV resource monitoring |

---

## Quick Start

```bash
# Individual tests
bash contrib/test/wallet_stress_test.sh
bash contrib/test/transaction_stress_test.sh
bash contrib/test/blockchain_stress_test.sh
bash contrib/test/rpc_stress_test.sh
bash contrib/test/security_stress_test.sh
bash contrib/test/staking_stress_test.sh
bash contrib/test/cold_staking_test.sh
bash contrib/test/spv_staking_test.sh

# Run all stress tests sequentially
for test in contrib/test/*_stress_test.sh contrib/test/*_staking_test.sh; do
    echo "=== Running: $test ==="
    bash "$test"
    echo ""
done
```

---

## Test Details

### Quick Test (`quick_test.sh`)
Basic sanity checks:
- Binary existence and version
- Node startup
- Basic RPC commands
- Address validation

### Regtest Test (`regtest_test.sh`)
Regtest block generation and basic operations.

### Stress Test (`innova_stress_test.sh`)
Multi-node stress test (legacy, requires `jq`, `bc`, `curl`):

```bash
./innova_stress_test.sh --nodes 3 --duration 300 --tx-rate 10
```

Options: `--nodes N`, `--duration S`, `--tx-rate N`, `--clean`

### Staking Stress Test (`staking_stress_test.sh`)
- UTXO splitting for staking inputs
- PoS block generation monitoring
- Staking info validation
- Multi-node sync verification

### Cold Staking Test (`cold_staking_test.sh`)
- P2CS delegation creation (`delegatestake`)
- Cold staking address generation
- Delegation listing and info
- Owner revocation spending

### SPV Staking Test (`spv_staking_test.sh`)
- HybridSPV mode startup
- Header-only sync verification
- SPV UTXO cache validation
- SPV staking capability check

### Wallet Stress Test (`wallet_stress_test.sh`)
- Rapid address generation (50 addresses)
- Key import/export (`dumpprivkey`, `importprivkey`)
- Wallet backup and restore
- Wallet encryption/decryption/lock/unlock
- Multi-send stress (10 concurrent sends)
- Keypool management and refill
- Transaction history queries
- Balance consistency checks

### Transaction Stress Test (`transaction_stress_test.sh`)
- P2PKH standard transactions
- Self-send transactions
- Dust transaction rejection
- Rapid transaction stress (30 sends)
- Raw transaction create/decode/sign/send
- Fee estimation and custom fees
- Mempool operations
- Large amount transactions
- Invalid amount rejection (zero, negative, excessive)

### Blockchain Stress Test (`blockchain_stress_test.sh`)
- Genesis block validation across nodes
- Block generation and propagation
- Block structure field validation
- Hash chain integrity verification
- Chain fork and reorganization
- Difficulty tracking
- Invalid block hash rejection
- Three-node consensus verification

### RPC Stress Test (`rpc_stress_test.sh`)
- Information RPCs (`getinfo`, `getblockchaininfo`, `getmininginfo`, etc.)
- Network RPCs (`getpeerinfo`, `getnettotals`, `getnetworkinfo`)
- Wallet RPCs (`getbalance`, `getnewaddress`, `validateaddress`, `dumpprivkey`, etc.)
- Block RPCs (`getblockhash`, `getblock`, `gettxout`)
- Mining RPCs (`setgenerate`, `getstakinginfo`)
- Raw transaction RPCs (`createrawtransaction`, `decoderawtransaction`, `signrawtransaction`)
- Mempool RPCs (`getrawmempool`)
- Rapid-fire stress (50 sequential + 60 mixed calls)
- Error handling (invalid methods, params, addresses)
- Cold staking RPCs (`getcoldstakinginfo`, `getnewstakingaddress`, `listcoldutxos`)

### Security Stress Test (`security_stress_test.sh`)
- Double-spend prevention (same UTXO, pre/post confirmation)
- Malformed transaction rejection
- Invalid address handling
- Overflow and edge value testing (negative, zero, excessive amounts)
- Signature validation (tampered tx, unsigned tx)
- Block validation rules (required fields, non-existent blocks)
- RPC authentication enforcement (wrong/missing credentials)
- Concurrent operation safety (parallel sends and reads)

---

## Requirements

- Built `innovad` binary (in `src/`)
- Regtest tests: no external dependencies
- Legacy stress test: `jq`, `bc`, `curl`

macOS:
```bash
brew install jq bc curl
```

## Port Allocation

Each test uses isolated ports to avoid conflicts:

| Test | P2P Ports | RPC Ports |
|------|-----------|-----------|
| staking_stress | 21445-21447 | 21500-21502 |
| wallet_stress | 22445-22446 | 22500-22501 |
| tx_stress | 23445-23446 | 23500-23501 |
| rpc_stress | 24445 | 24500 |
| security_stress | 25445-25446 | 25500-25501 |
| blockchain_stress | 26445-26447 | 26500-26502 |
| cold_staking | 20445-20446 | 20500-20501 |
| spv_staking | 20545-20546 | 20600-20601 |

## Cleanup

All tests clean up automatically on exit via `trap`. If a test is interrupted, processes can be killed manually:

```bash
pkill -f "innovad.*stress\|innovad.*staking\|innovad.*test"
rm -rf /tmp/innova_*
```
