#!/usr/bin/env bash
# Emit the four-node inventory the release differential consumes: four local nodes, or
# four remote nodes each with its own ssh endpoint and p2p_host; no credentials.
# Usage: make_differential_inventory.sh [-n network] [-b innovad] [-o out] label:datadir:rpcport[:ssh:p2phost] x4

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NETWORK=regtest
INNOVAD="${INNOVAD:-$ROOT/src/innovad}"
OUT=-

while getopts ":n:b:o:h" opt; do
    case "$opt" in
        n) NETWORK="$OPTARG" ;;
        b) INNOVAD="$OPTARG" ;;
        o) OUT="$OPTARG" ;;
        h) sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "unknown option -$OPTARG" >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

[ "$#" -eq 4 ] || { echo "need exactly four node specs, got $#" >&2; exit 2; }

python3 - "$NETWORK" "$INNOVAD" "$OUT" "$@" <<'PY'
import json
import sys

network, innovad, out = sys.argv[1:4]
specs = sys.argv[4:]

nodes = []
for spec in specs:
    parts = spec.split(":")
    if len(parts) not in (3, 5):
        sys.exit("node spec must be label:datadir:rpcport[:ssh:p2phost], got %r" % spec)
    label, datadir, rpcport = parts[0], parts[1], parts[2]
    node = {
        "label": label,
        "innovad": innovad,
        "datadir": datadir,
        "rpcport": int(rpcport),
        "network": network,
    }
    if len(parts) == 5:
        node["ssh_target"] = parts[3]
        node["p2p_host"] = parts[4]
    nodes.append(node)

remote = [bool(n.get("ssh_target")) for n in nodes]
if any(remote) and not all(remote):
    sys.exit("the schema refuses a mix of local and remote nodes; give all four an "
             "ssh endpoint or none")
if any(remote):
    if len({n["ssh_target"] for n in nodes}) != 4:
        sys.exit("four distinct SSH endpoints are required")
    if len({n["p2p_host"] for n in nodes}) != 4:
        sys.exit("four distinct p2p_host identities are required")
if len({n["label"] for n in nodes}) != 4:
    sys.exit("node labels must be unique")

text = json.dumps({"schema_version": 1, "nodes": nodes}, indent=2, sort_keys=True) + "\n"
if out == "-":
    sys.stdout.write(text)
else:
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(text)
    sys.stderr.write("wrote %s\n" % out)
PY
