# Innova Testnet Metrics And Traffic Tooling

`innova_testnet_tool.py` collects live testnet RPC metrics, writes CSV files, renders a static HTML/SVG dashboard, and can run guarded traffic from a dedicated traffic wallet.

The tool has no Python dependencies outside the standard library. It uses the existing `innovad` CLI either locally or through SSH, so remote RPC ports do not need to be exposed.

## Clean IDAG Testnet

The public testnet identity is reset for the IDAG hidden-finality launch. Operators must wipe old testnet chain data before joining this network.

- genesis hash: `00004f9f245acf85d86878eff8f80cf47f7e563727531c21fa175a0fe503bf6b`
- message magic: `9b 1d fc 26`
- P2P/RPC ports: `15539` / `15531`
- activation heights: POEM `9`, finality `10`, DAG and epoch-root FCMP `11`, DAGKNIGHT `13`
- seed peers: `45.32.161.27:15539`, `45.77.164.87:15539`, `144.202.37.36:15539`, `45.32.168.101:15539`, `45.77.118.217:15539`

## Read-Only Metrics

Collect the latest 50 blocks plus one node snapshot:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py collect \
  --backend ssh \
  --ssh root@45.32.161.27 \
  --innovad /usr/local/bin/innovad \
  --datadir /root/.innova \
  --testnet \
  --node node1 \
  --blocks 50 \
  --output-dir testnet_metrics
```

Render the dashboard:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py report \
  --input-dir testnet_metrics \
  --output testnet_metrics/report.html
```

CSV outputs:

- `blocks.csv`: block height/hash/time, interval, size, tx count, PoW/PoS flag, difficulty, adaptive block limit, utilization percent.
- `snapshots.csv`: node height/hash, mempool, mining, staking, DAG, finality, shielded/DSP, and NullSend state.
- `traffic_runs.csv`: generated-traffic logs when `traffic run` is used.

## Dedicated Traffic Wallet

Use a dedicated live traffic node/wallet instead of node1/node4 wallets.

Defaults:

- datadir: `/root/.innova-traffic`
- RPC port: `15631`
- P2P port: `15639`
- `testnet=1`, `server=1`, `staking=0`, `txindex=1`
- peers: the current five live testnet node IPs on port `15539`

Preview the setup without writing config, starting a daemon, funding, or splitting:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py traffic prepare \
  --backend ssh \
  --ssh root@45.32.168.101 \
  --innovad /usr/local/bin/innovad \
  --dry-run
```

Live prepare requires `--yes-live-traffic`. Funding must be explicitly pointed at the funding wallet:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py traffic prepare \
  --backend ssh \
  --ssh root@45.32.168.101 \
  --innovad /usr/local/bin/innovad \
  --funding-backend ssh \
  --funding-ssh root@45.32.161.27 \
  --funding-innovad /usr/local/bin/innovad \
  --funding-datadir /root/.innova \
  --funding-rpcport 15531 \
  --funding-amount 2500 \
  --split-count 1000 \
  --split-amount 1 \
  --yes-live-traffic
```

Check readiness before sending traffic:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py traffic status \
  --backend ssh \
  --ssh root@45.32.168.101 \
  --innovad /usr/local/bin/innovad \
  --json
```

Run a short guarded transparent load test:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py traffic run \
  --backend ssh \
  --ssh root@45.32.168.101 \
  --innovad /usr/local/bin/innovad \
  --duration 60 \
  --target-min 0.50 \
  --target-max 0.60 \
  --max-tx 100 \
  --yes-live-traffic
```

Transparent `sendmany` traffic is the only stage used to control block fill. Privacy/DSP, silent-payment, and NullSend probes are opt-in:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py traffic run \
  --backend ssh \
  --ssh root@45.32.168.101 \
  --innovad /usr/local/bin/innovad \
  --duration 60 \
  --target-min 0.50 \
  --target-max 0.60 \
  --max-tx 100 \
  --privacy-probes \
  --silent-probe \
  --nullsend-probe \
  --yes-live-traffic
```

## Safety Notes

- Mutating traffic commands refuse to run unless `--yes-live-traffic` or `--dry-run` is provided.
- Keep the traffic wallet separate from mining and staking wallets.
- The controller backs off for high utilization, large or growing mempool, node warnings, initial block download, low peer count, peer height divergence, RPC errors, or high reject rate.
- The first implementation reports global shielded/DSP/NullSend RPC state and the tool's own generated privacy logs. It does not infer exact privacy-mode counts from arbitrary historical blocks.

## Local Fixture Test

Run parser/report checks without touching testnet:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py selftest
```
