# Innova Test Suite

Comprehensive stress testing and validation suite for Innova Core.

## Test Scripts Overview

`suites.json` is the canonical inventory and the only list a sweep reads:

```bash
python3 contrib/test/run_suite_sweep.py --list      # every runnable suite
python3 contrib/test/run_suite_sweep.py --jobs 4 --output sweep.json
```

The table below covers the pre-v5 stress harnesses only. The IDAG, IV5, finality
and privacy suites are in `suites.json`; adding one here as well would only give
it a second place to go stale.

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
| `crash_injection_test.sh` | SIGKILL recovery at the batched persistence points | 3 | Regtest |

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

Ports come from `lib/testports.sh`, not from literals in each harness. A harness
asks for a slot and gets its historical port when no base is set, or a port in
the caller's window when one is:

```bash
IV5_TEST_PORT_BASE=auto bash contrib/test/wallet_stress_test.sh   # private window
bash contrib/test/wallet_stress_test.sh                           # historical ports
```

`check_port_isolation.py` evaluates every harness under two bases and fails any
that ignores the variable. The harnesses it currently names bind fixed sockets
and cannot run beside each other; `suites.json` marks them `fixed_ports` and the
sweep runs those serially.

## Cleanup

All tests clean up automatically on exit via `trap`. If a test is interrupted,
kill the leftover daemons by PID — a pattern kill on `innovad` also matches
unrelated nodes on the host, including a mainnet wallet:

```bash
pgrep -fl innovad          # identify the datadir in each command line first
kill <pid>
rm -rf "$TEST_DIR"         # the datadir the harness printed, not /tmp/innova_*
```

---

## Qt5/Qt6 connections

A signal Qt6 removed still compiles and links: `SIGNAL()`, Designer's
`connectSlotsByName` and `.ui` `<connections>` all resolve by name at runtime.
The connection then never fires, and no build of either lane says so. Two checks
cover that, and they cover different halves:

```bash
python3 contrib/test/check_qt6_removed_signals.py .        # static, whole tree
contrib/test/qt_connect_probe.sh ./Innova /tmp/probe-dd    # runtime, what is built
```

The static check names the file and line and sees code no run reaches. The probe
builds the widget tree under the offscreen platform and reports what Qt could not
resolve; it fails if the wallet never reaches the marker that proves the widgets
were constructed, so it cannot pass by not executing. Run both: the static check
alone cannot tell a live widget from a dead one, and the probe alone never
constructs a widget nothing instantiates.

## Native Tor and -datadir

```bash
contrib/test/nativetor_datadir_regtest_test.sh
```

`-nativetor=1` derives the tor DataDirectory and the hidden service directory
from the configured datadir. The harness asserts tor ran with that path
(positive control), that the onion hostname is under it, that nothing appeared
under the default datadir (the assertion the old behaviour fails), and that
`getinfo` reports the same address the file holds. The bundled tor's SOCKS port
is the compile-time `NATIVETOR_SOCKS_PORT`, so only one nativetor node runs per
host and the suite is marked `fixed_ports`.

## Release verification evidence

`check_v5_release_policy.py` requires a SHA-256 for every field of
`REQUIRED_VERIFICATION_FIELDS` in the release manifest's `verification` block.
Nine of those fields are produced here, one producer each:

| Field | Producer | Host |
|-------|----------|------|
| `asan_lsan_sha256` | `produce_asan_lsan_evidence.sh` | Linux |
| `ubsan_sha256` | `produce_ubsan_evidence.sh` | Linux |
| `linux_clean_sha256` | `produce_linux_clean_evidence.sh` | Linux |
| `macos_clean_sha256` | `produce_macos_clean_evidence.sh` | macOS |
| `qt6_release_sha256` | `produce_qt6_release_evidence.sh` | Linux, Qt6 qmake |
| `fuzz_corpora_sha256` | `produce_fuzz_corpora_evidence.sh` | Linux, clang |
| `integration_sha256` | `produce_integration_evidence.sh` | any, built `innovad` |
| `performance_sha256` | `produce_performance_evidence.sh` | any, built `innovad` |

Each producer either reuses the document already written for this commit or
performs the run, and writes `<obligation>.json` plus `<obligation>.log` into
`V5_EVIDENCE_DIR` (default `$TMPDIR/innova-v5-evidence`). The document's own
SHA-256 is the manifest value; `v5_verification_evidence.py index` writes them all
to `verification.json` in the same directory, which is the block a manifest
carries. A producer never exits 0 without a document: a host that cannot perform
the run and has no document for this commit fails and names the file to copy in.

```bash
contrib/test/v5_release_gate.sh --verification   # run every producer
contrib/test/v5_release_gate.sh --evidence       # verify the documents, write verification.json
```

Cross-platform runs collect: produce the macOS document on a Mac, copy
`macos_clean.json` and `macos_clean.log` into the Linux host's `V5_EVIDENCE_DIR`,
and the gate verifies it there. Documents are keyed to the commit and to the log
they name, so one from another commit, or one whose log was edited afterwards, is
refused rather than reused.

`performance_sha256` additionally needs a reviewed floor in
`contrib/test/performance_baseline.json`. None is committed yet, so that producer
measures, writes `performance_baseline.candidate.json` for review and fails: a
throughput figure with nothing to fail against is a number, not evidence.
