# Innova test scripts

Regtest and testnet harnesses for `innovad`. Unit tests live in `src/test/` and run
with `src/test_innova`; the scripts here start real nodes.

## Requirements

- `innovad` built in `src/` (`make -C src -f makefile.unix innovad`)
- `python3`, `bash`, `curl`
- `jq` and `bc` for `innova_stress_test.sh` only

## Running

`suites.json` lists every regtest suite. `run_suite_sweep.py` runs them in
parallel, each in its own port range:

```bash
python3 contrib/test/run_suite_sweep.py --list
python3 contrib/test/run_suite_sweep.py --jobs 4 --output sweep.json
```

A single suite runs on its own:

```bash
IV5_TEST_PORT_BASE=auto bash contrib/test/wallet_stress_test.sh
```

`IV5_TEST_PORT_BASE=auto` gives the script a private port range
(`lib/testports.sh`), so it can run next to other suites. Without it the script
uses its fixed default ports. Suites marked `fixed_ports` in `suites.json` bind
fixed sockets and run one at a time. `check_port_isolation.py` checks that every
harness honours the variable.

## General harnesses

| Script | Covers | Nodes | Network |
|--------|--------|-------|---------|
| `quick_test.sh` | binary, startup, basic RPC | 1 | testnet |
| `regtest_test.sh` | block generation | 2 | regtest |
| `innova_stress_test.sh` | multi-node load (`--nodes`, `--duration`, `--tx-rate`) | 3-5 | testnet |
| `staking_stress_test.sh` | PoS staking | 2 | regtest |
| `cold_staking_test.sh` | P2CS delegation and revocation | 3 | regtest |
| `spv_staking_test.sh` | HybridSPV staking | 3 | regtest |
| `wallet_stress_test.sh` | keys, backup, encryption, keypool | 2 | regtest |
| `transaction_stress_test.sh` | transaction types, fees, mempool | 2 | regtest |
| `blockchain_stress_test.sh` | propagation, reorgs | 3 | regtest |
| `rpc_stress_test.sh` | RPC surface and error handling | 1 | regtest |
| `security_stress_test.sh` | double spends, malformed input, RPC auth | 2 | regtest |
| `crash_injection_test.sh` | recovery after SIGKILL | 3 | regtest |

The IDAG, IV5, finality and privacy suites are listed in `suites.json`.

## Qt checks

```bash
python3 contrib/test/check_qt6_removed_signals.py .        # signals Qt6 removed, by file and line
contrib/test/qt_connect_probe.sh ./Innova /tmp/probe-dd    # connections that fail at runtime
contrib/test/qt_shutdown_probe.sh ./Innova /tmp/qt-sd      # SIGTERM and stop RPC exit cleanly
```

## Native Tor

`nativetor_datadir_regtest_test.sh` checks that `-nativetor=1` keeps the Tor data
and hidden-service directories under `-datadir`. The bundled Tor uses a fixed
SOCKS port, so only one such node runs per host.

## Release checks

`v5_release_gate.sh` runs the release checks:

```bash
contrib/test/v5_release_gate.sh --static-checks   # source and configuration checks
contrib/test/v5_release_gate.sh --verification    # every verification producer
contrib/test/v5_release_gate.sh --evidence        # check the results, write verification.json
```

Each `produce_*_evidence.sh` script performs one verification run and writes
`<name>.json` and `<name>.log` to `V5_EVIDENCE_DIR` (default
`$TMPDIR/innova-v5-evidence`). Results are tied to the commit, so a result from
another commit is not reused.

| Result | Script | Host |
|--------|--------|------|
| `asan_lsan_sha256` | `produce_asan_lsan_evidence.sh` | Linux |
| `ubsan_sha256` | `produce_ubsan_evidence.sh` | Linux |
| `linux_clean_sha256` | `produce_linux_clean_evidence.sh` | Linux |
| `macos_clean_sha256` | `produce_macos_clean_evidence.sh` | macOS |
| `qt6_release_sha256` | `produce_qt6_release_evidence.sh` | Linux, Qt6 |
| `fuzz_corpora_sha256` | `produce_fuzz_corpora_evidence.sh` | Linux, clang |
| `integration_sha256` | `produce_integration_evidence.sh` | any |
| `performance_sha256` | `produce_performance_evidence.sh` | any |
| `crash_injection_sha256` | `produce_crash_injection_evidence.sh` | any |
| `rust_audit_sha256` | `produce_rust_audit_evidence.sh` | any, `cargo-deny` |
| `history_replay_sha256` | `produce_history_replay_evidence.sh` | any |

`produce_performance_evidence.sh` compares against
`performance_baseline.json`. To produce the macOS result for a Linux run, copy
`macos_clean.json` and `macos_clean.log` into the Linux host's
`V5_EVIDENCE_DIR`.

## Cleanup

Every script stops its nodes on exit. After an interrupted run, stop leftover
nodes by PID rather than by name, since a name match also hits other nodes on the
host:

```bash
pgrep -fl innovad     # check the -datadir in each command line
kill <pid>
```
