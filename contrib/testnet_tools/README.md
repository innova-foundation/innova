# Testnet tools

Python tools (standard library only) for operating an Innova testnet: metrics,
fleet checks, activation-height calculation and controlled traffic. They call
`innovad` RPC through the local CLI, or through `ssh` to a remote CLI, so RPC
ports stay on loopback.

| Tool | Purpose |
|------|---------|
| `innova_testnet_tool.py` | metrics collection, HTML reports, seed audit, mempool inspection, guarded test traffic |
| `v5_testnet_rollout.py` | read-only fleet preflight and Boundary-B height calculation |
| `v5_mainnet_activation.py` | mainnet activation-ladder shift calculation |
| `../test/idag_four_node_differential.py` | compares consensus state across four nodes at each epoch boundary |

## Fleet inventory

Commands that reach remote nodes take an explicit inventory file
(`--inventory` or `--fleet-file`): a JSON file listing each node's label, SSH
target and P2P host. There is no default host, so nothing contacts a node unless
an inventory is given. Inventories hold no secrets; the tools refuse password,
token and private-key fields. Pass SSH keys with `--ssh-option`.

## Examples

Read-only seed audit and report:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py seed-audit \
  --fleet-file fleet.json --output-dir testnet_metrics
python3 contrib/testnet_tools/innova_testnet_tool.py report \
  --input-dir testnet_metrics --output testnet_metrics/report.html
```

Fleet preflight (read-only):

```bash
python3 contrib/testnet_tools/v5_testnet_rollout.py \
  --inventory fleet.json \
  --expected-binary-sha256 <sha256 of the deployed innovad> \
  --output preflight.json
```

Activation height from a common height (first `60 + 300*k` boundary at least
900 blocks ahead):

```bash
python3 contrib/testnet_tools/v5_testnet_rollout.py --common-height 430
```

Test traffic changes chain state, so it needs `--yes-live-traffic`; start with
`--dry-run`:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py traffic prepare \
  --backend ssh --ssh <controller> --fleet-file fleet.json \
  --innovad /usr/local/bin/innovad --dry-run
```

## Self-tests

These run offline:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py selftest
python3 contrib/testnet_tools/v5_testnet_rollout.py --selftest
python3 contrib/test/idag_four_node_differential.py --selftest
```
