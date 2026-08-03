#!/usr/bin/env python3
"""Fail-closed four-node IDAG/epoch/finality equality gate.

The tool is read-only.  It invokes each node's existing ``innovad`` RPC client
locally or through SSH, captures a height-stable snapshot, and compares every
selected consensus-visible field across the four nodes. This is one release
lane, not a complete readiness preflight: binary identity, mining state, peer
mesh, wallet/pool state, and activation calculation belong to the companion
testnet preflight. Inventory files must contain exactly four nodes and must not
contain credentials or fields outside the documented schema.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import json
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


EVIDENCE_SCHEMA_VERSION = 3


EPOCH_FIELDS: Tuple[str, ...] = (
    "epoch",
    "height_start",
    "height_end",
    "boundary_block",
    "block_count",
    "tx_count",
    "total_trust",
    "finalized",
    "curve_root",
    "nullifier_root",
    "vote_set_root",
    "finality_certificate",
    "finality_tier",
    "consecutive_hard_epochs",
    "finalized_height_as_of",
    "schema_version",
    "anchor_rule",
    "epoch_state_digest",
    "blocks",
)

FINALITY_FIELDS: Tuple[str, ...] = (
    "epoch",
    "candidate_build_identifier",
    "boundary_a_activation_height",
    "boundary_a_configured",
    "boundary_a_active",
    "boundary_b_activation_height",
    "boundary_b_configured",
    "boundary_b_active",
    "serializer_schema_version",
    "serializer_schema",
    "boundary_a_carrier_schema",
    "boundary_a_carrier_schema_version",
    "boundary_a_carrier_tag",
    "boundary_a_carrier_exactly_one",
    "boundary_a_carrier_max_parents",
    "boundary_a_dagknight_contract",
    "migration_state",
    "legacy_anon_status",
    "privacy_protocol_status",
    "finalized_height",
    "finalized_hash",
    "finality_tier",
    "consecutive_hard_epochs",
    "tally_committee_set_hash",
    "tally_threshold",
    "connected_committee_rotations",
    "epoch_state_health",
    "epoch_state_schema_version",
    "epoch_state_required_schema_version",
    "epoch_state_schema_marker_present",
    "epoch_state_anchor_rule",
    "epoch_state_records",
    "epoch_state_latest_completed_epoch",
    "epoch_state_digest",
    "epoch_curve_root",
    "epoch_nullifier_root",
    "epoch_vote_set_root",
    "deterministic_finalized_height_available",
    "deterministic_finalized_height",
    "deterministic_finalized_epoch",
)

DAG_INFO_FIELDS: Tuple[str, ...] = (
    "dag_active",
    "current_height",
    "dag_tips",
    "dag_entries",
    "ordering_algorithm",
    "boundary_a_active",
    "parent_commitment_schema",
    "parent_commitment_schema_version",
    "parent_commitment_tag",
    "parent_commitment_exactly_one",
    "parent_commitment_max_parents",
    "parent_commitment_strict_active",
    "dagknight_contract",
    "dagknight_anchor_pure",
    "dagknight_k_floor",
    "dagknight_k_ceiling",
    "best_dag_tip",
    "best_dag_score",
    "inferred_k",
    "anchor_metrics_available",
    "anchor_selected_parent",
    "anchor_score",
    "anchor_inferred_k",
    "anchor_order_count",
    "anchor_blue_count",
    "anchor_order_digest",
    "best_parent_count",
    "best_parent_commitment_hex",
    "pruned_below",
    "finality_tier",
    "consecutive_hard_epochs",
    "finalized_height",
    "finalized_hash",
    "epoch_curve_root",
    "epoch_nullifier_root",
    "epoch_finality_certificate",
)

FORBIDDEN_INVENTORY_KEYS = {
    "api_key",
    "apikey",
    "credential",
    "credentials",
    "identity_file",
    "passphrase",
    "password",
    "privatekey",
    "rpcpassword",
    "rpc_password",
    "secret",
    "ssh_key",
    "ssh_private_key",
    "token",
    "private_key",
    "privkey",
}

INVENTORY_FIELDS = {"schema_version", "nodes"}
NODE_FIELDS = {
    "label",
    "innovad",
    "datadir",
    "rpcport",
    "network",
    "ssh_target",
    "conf",
    "p2p_host",
}

SAFE_SSH_OPTIONS = [
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "PasswordAuthentication=no",
    "-o", "KbdInteractiveAuthentication=no",
    "-o", "StrictHostKeyChecking=yes",
]

REQUIRED_SSH_OPTIONS = {
    "batchmode": "yes",
    "identitiesonly": "yes",
    "passwordauthentication": "no",
    "kbdinteractiveauthentication": "no",
    "stricthostkeychecking": "yes",
}

ALLOWED_NUMERIC_SSH_OPTIONS = {
    "connecttimeout",
    "connectionattempts",
    "serveraliveinterval",
    "serveralivecountmax",
}


class GateError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def reject_credentials(value: Any, path: str = "inventory") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
            if normalized_key in FORBIDDEN_INVENTORY_KEYS:
                raise GateError("%s contains forbidden credential field %r" % (path, key))
            reject_credentials(child, "%s.%s" % (path, key))
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            reject_credentials(child, "%s[%d]" % (path, idx))


def validate_ssh_options(values: Sequence[str]) -> List[str]:
    """Accept only inert connection material; reject command/config injection."""
    flattened: List[str] = []
    for value in values:
        try:
            parts = shlex.split(str(value))
        except ValueError as exc:
            raise GateError("invalid --ssh-option value: %s" % exc) from exc
        if not parts:
            raise GateError("empty --ssh-option value")
        flattened.extend(parts)

    idx = 0
    while idx < len(flattened):
        token = flattened[idx]
        if token in ("-i", "-p"):
            idx += 1
            if idx >= len(flattened):
                raise GateError("--ssh-option %s requires a value" % token)
            option_value = flattened[idx]
            if not option_value or option_value.startswith("-") or "\n" in option_value:
                raise GateError("--ssh-option %s has an unsafe value" % token)
            if token == "-p":
                try:
                    port = int(option_value)
                except ValueError as exc:
                    raise GateError("--ssh-option -p requires a numeric port") from exc
                if port < 1 or port > 65535:
                    raise GateError("--ssh-option -p port is out of range")
            idx += 1
            continue

        if token.startswith("-i") and len(token) > 2:
            if token[2:].startswith("-") or "\n" in token[2:]:
                raise GateError("--ssh-option -i has an unsafe value")
            idx += 1
            continue
        if token.startswith("-p") and len(token) > 2:
            try:
                port = int(token[2:])
            except ValueError as exc:
                raise GateError("--ssh-option -p requires a numeric port") from exc
            if port < 1 or port > 65535:
                raise GateError("--ssh-option -p port is out of range")
            idx += 1
            continue

        setting = ""
        if token == "-o":
            idx += 1
            if idx >= len(flattened):
                raise GateError("--ssh-option -o requires a setting")
            setting = flattened[idx]
        elif token.startswith("-o") and len(token) > 2:
            setting = token[2:]
        else:
            raise GateError("SSH option %r is not allowed" % token)

        key, sep, option_value = setting.partition("=")
        normalized_key = key.strip().lower()
        option_value = option_value.strip()
        if not sep or not option_value or "\n" in option_value:
            raise GateError("SSH -o option must use Key=Value form")
        if normalized_key in REQUIRED_SSH_OPTIONS:
            if option_value.lower() != REQUIRED_SSH_OPTIONS[normalized_key]:
                raise GateError("SSH option %s may not weaken mandatory value %s" %
                                (key, REQUIRED_SSH_OPTIONS[normalized_key]))
        elif normalized_key == "userknownhostsfile":
            if option_value.startswith("-"):
                raise GateError("UserKnownHostsFile has an unsafe path")
        elif normalized_key in ALLOWED_NUMERIC_SSH_OPTIONS:
            if not option_value.isdigit():
                raise GateError("SSH option %s requires a non-negative integer" % key)
        else:
            raise GateError("SSH -o option %s is not allowed" % key)
        idx += 1
    return flattened


@dataclasses.dataclass(frozen=True)
class Node:
    label: str
    innovad: str
    datadir: str
    rpcport: int
    network: str
    ssh_target: str = ""
    conf: str = ""
    p2p_host: str = ""

    def endpoint_identity(self) -> str:
        return digest(
            {
                "network": self.network,
                "ssh_target": self.ssh_target or "local",
                "datadir": self.datadir,
                "rpcport": self.rpcport,
            }
        )

    @staticmethod
    def from_json(value: Mapping[str, Any]) -> "Node":
        unknown = set(value) - NODE_FIELDS
        if unknown:
            raise GateError("fleet node contains unsupported fields: %s" %
                            ", ".join(sorted(str(key) for key in unknown)))
        for field in NODE_FIELDS - {"rpcport"}:
            if field in value and not isinstance(value[field], str):
                raise GateError("fleet node field %s must be a string" % field)
        label = str(value.get("label", "")).strip()
        if not label:
            raise GateError("every fleet node needs a non-empty label")
        network = str(value.get("network", "testnet")).strip().lower()
        if network not in ("mainnet", "testnet", "regtest"):
            raise GateError("node %s has unsupported network %r" % (label, network))
        ssh_target = str(value.get("ssh_target", "")).strip()
        ssh_user = ssh_target.rsplit("@", 1)[0] if "@" in ssh_target else ""
        if (ssh_target.startswith("-") or any(ch.isspace() for ch in ssh_target) or
                "://" in ssh_target or ssh_target.count("@") > 1 or ":" in ssh_user):
            raise GateError("node %s has an unsafe SSH target" % label)
        if ssh_target.lower().endswith(".invalid"):
            raise GateError("node %s still uses the example placeholder SSH target" % label)
        rpcport_raw = value.get("rpcport", 15531)
        if isinstance(rpcport_raw, bool) or not isinstance(rpcport_raw, int):
            raise GateError("node %s rpcport must be an integer" % label)
        if rpcport_raw < 1 or rpcport_raw > 65535:
            raise GateError("node %s rpcport is out of range" % label)
        return Node(
            label=label,
            innovad=str(value.get("innovad", "/usr/local/bin/innovad")),
            datadir=str(value.get("datadir", "/root/.innova")),
            rpcport=rpcport_raw,
            network=network,
            ssh_target=ssh_target,
            conf=str(value.get("conf", "")),
            p2p_host=str(value.get("p2p_host", "")).strip().lower().strip("[]"),
        )


def load_inventory(path: Path) -> List[Node]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError("cannot read fleet inventory %s: %s" % (path, exc)) from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise GateError("fleet inventory must be an object with schema_version=1")
    if set(raw) != INVENTORY_FIELDS:
        raise GateError("fleet inventory fields do not match schema")
    reject_credentials(raw)
    values = raw.get("nodes")
    if not isinstance(values, list) or len(values) != 4:
        raise GateError("release differential inventory must contain exactly four nodes")
    nodes = [Node.from_json(value) for value in values if isinstance(value, dict)]
    if len(nodes) != 4:
        raise GateError("all four inventory node entries must be objects")
    labels = [node.label for node in nodes]
    if len(set(labels)) != len(labels):
        raise GateError("fleet node labels must be unique")
    identities = [node.endpoint_identity() for node in nodes]
    if len(set(identities)) != len(identities):
        raise GateError("fleet node endpoints/datadirs must identify four distinct nodes")
    if len({node.network for node in nodes}) != 1:
        raise GateError("all four differential nodes must use the same network")
    remote_targets = [node.ssh_target for node in nodes]
    if any(remote_targets):
        if any(not target for target in remote_targets) or len(set(remote_targets)) != 4:
            raise GateError("remote fleet inventory requires four distinct SSH endpoints")
        p2p_hosts = [node.p2p_host for node in nodes]
        if any(not host for host in p2p_hosts) or len(set(p2p_hosts)) != 4:
            raise GateError("remote fleet inventory requires four distinct p2p_host identities")
    return nodes


class RpcClient:
    def __init__(self, node: Node, timeout: int, ssh_options: Sequence[str]):
        self.node = node
        self.timeout = max(1, int(timeout))
        self.ssh_options = validate_ssh_options(ssh_options)

    def argv(self, method: str, args: Sequence[Any]) -> List[str]:
        argv = [self.node.innovad, "-datadir=%s" % self.node.datadir, "-rpcport=%d" % self.node.rpcport]
        if self.node.conf:
            argv.append("-conf=%s" % self.node.conf)
        if self.node.network == "testnet":
            argv.append("-testnet")
        elif self.node.network == "regtest":
            argv.append("-regtest")
        argv.append(method)
        argv.extend(str(arg) for arg in args)
        return argv

    def call(self, method: str, *args: Any) -> Any:
        argv = self.argv(method, args)
        if self.node.ssh_target:
            remote = "timeout %d %s" % (
                self.timeout,
                " ".join(shlex.quote(part) for part in argv),
            )
            command = ["ssh"] + SAFE_SSH_OPTIONS + self.ssh_options + [self.node.ssh_target, remote]
        else:
            command = argv
        try:
            proc = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout + (8 if self.node.ssh_target else 2),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GateError("%s %s failed: %s" % (self.node.label, method, exc)) from exc
        if proc.returncode != 0:
            message = proc.stderr.strip() or proc.stdout.strip() or "exit status %d" % proc.returncode
            raise GateError("%s %s failed: %s" % (self.node.label, method, message))
        text = proc.stdout.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            try:
                return int(text)
            except ValueError:
                return text.strip('"')


def require_object(label: str, method: str, value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise GateError("%s %s did not return a JSON object" % (label, method))
    return value


def select_fields(label: str, group: str, value: Mapping[str, Any], fields: Iterable[str]) -> Dict[str, Any]:
    missing = [field for field in fields if field not in value]
    if missing:
        raise GateError("%s %s is missing release fields: %s" % (label, group, ", ".join(missing)))
    return {field: value[field] for field in fields}


def normalized_tips(label: str, value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        raise GateError("%s getdagtips did not return an array" % label)
    tips: List[Dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict) or not entry.get("hash"):
            raise GateError("%s getdagtips returned a malformed entry" % label)
        tips.append(dict(entry))
    return sorted(tips, key=lambda entry: str(entry.get("hash")))


def normalized_order(label: str, value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        raise GateError("%s getdagorder did not return an array" % label)
    result: List[Dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict) or "order" not in entry or not entry.get("hash"):
            raise GateError("%s getdagorder returned a malformed entry" % label)
        result.append(dict(entry))
    return result


def collect_base(client: RpcClient) -> Dict[str, Any]:
    for _ in range(3):
        height_before = int(client.call("getblockcount"))
        best_hash = str(client.call("getblockhash", height_before))
        dag_info = require_object(client.node.label, "getdaginfo", client.call("getdaginfo"))
        dag_tips = normalized_tips(client.node.label, client.call("getdagtips"))
        dag_order = normalized_order(client.node.label, client.call("getdagorder", 1000))
        finality = require_object(client.node.label, "getfinalityinfo", client.call("getfinalityinfo"))
        if str(finality.get("migration_state", "")) != "recovery_idle":
            raise GateError(
                "%s reports non-ready migration state %r" %
                (client.node.label, finality.get("migration_state"))
            )
        if not str(finality.get("candidate_build_identifier", "")).strip():
            raise GateError("%s has no candidate build identifier" % client.node.label)
        mempool_raw = client.call("getrawmempool")
        if not isinstance(mempool_raw, list):
            raise GateError("%s getrawmempool did not return an array" % client.node.label)
        height_after = int(client.call("getblockcount"))
        hash_after = str(client.call("getblockhash", height_after))
        if height_after == height_before and hash_after == best_hash:
            return {
                "label": client.node.label,
                "node_identity": client.node.endpoint_identity(),
                "best_height": height_before,
                "best_hash": best_hash,
                "dag_info": select_fields(client.node.label, "getdaginfo", dag_info, DAG_INFO_FIELDS),
                "dag_tips": dag_tips,
                "dag_order": dag_order,
                "finality": select_fields(client.node.label, "getfinalityinfo", finality, FINALITY_FIELDS),
                "current_epoch": int(finality.get("epoch", 0)),
                "mempool": sorted(str(txid) for txid in mempool_raw),
            }
    raise GateError("%s changed height/hash during three snapshot attempts" % client.node.label)


def verify_anchor(client: RpcClient, expected_height: int, expected_hash: str) -> None:
    height = int(client.call("getblockcount"))
    block_hash = str(client.call("getblockhash", height))
    if height != expected_height or block_hash != expected_hash:
        raise GateError(
            "%s changed from %d/%s to %d/%s while collecting epoch state" %
            (client.node.label, expected_height, expected_hash, height, block_hash)
        )


def verify_anchors(clients: Sequence[RpcClient], bases: Sequence[Mapping[str, Any]]) -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [
            pool.submit(verify_anchor, client, int(base["best_height"]), str(base["best_hash"]))
            for client, base in zip(clients, bases)
        ]
        for future in futures:
            future.result()


def collect_epoch(client: RpcClient, epoch: int) -> Dict[str, Any]:
    value = require_object(client.node.label, "getepochinfo", client.call("getepochinfo", epoch))
    if value.get("status") == "not_computed" or "blocks" not in value:
        raise GateError("%s epoch %d is not computed" % (client.node.label, epoch))
    selected = select_fields(client.node.label, "getepochinfo", value, EPOCH_FIELDS)
    if int(selected["schema_version"]) not in (2, 3):
        raise GateError("%s epoch %d uses unsupported schema %r" % (client.node.label, epoch, selected["schema_version"]))
    if int(selected["block_count"]) != len(selected["blocks"]):
        raise GateError("%s epoch %d block_count does not match blocks array" % (client.node.label, epoch))
    return selected


def run_parallel(clients: Sequence[RpcClient], fn: Any) -> List[Any]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(fn, client) for client in clients]
        return [future.result() for future in futures]


def choose_computed_epoch(clients: Sequence[RpcClient], bases: Sequence[Mapping[str, Any]], requested: Optional[int]) -> Tuple[int, List[Dict[str, Any]]]:
    if requested is not None:
        epoch = requested
        return epoch, run_parallel(clients, lambda client: collect_epoch(client, epoch))
    candidate = min(int(base["current_epoch"]) for base in bases)
    last_error = ""
    for epoch in range(candidate, max(-1, candidate - 5), -1):
        try:
            return epoch, run_parallel(clients, lambda client, selected=epoch: collect_epoch(client, selected))
        except GateError as exc:
            last_error = str(exc)
    raise GateError("no common computed epoch near %d: %s" % (candidate, last_error))


def compare_snapshots(snapshots: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    if len(snapshots) != 4:
        raise GateError("differential comparison requires exactly four snapshots")
    reference = snapshots[0]
    groups = (
        "best_height",
        "best_hash",
        "dag_info",
        "dag_tips",
        "dag_order",
        "epoch_state",
        "finality",
        "mempool",
    )
    mismatches: List[Dict[str, Any]] = []
    for snapshot in snapshots[1:]:
        for group in groups:
            if canonical(snapshot[group]) != canonical(reference[group]):
                mismatches.append(
                    {
                        "node": snapshot["label"],
                        "reference_node": reference["label"],
                        "field_group": group,
                        "reference_digest": digest(reference[group]),
                        "observed_digest": digest(snapshot[group]),
                    }
                )
    return {
        "passed": not mismatches,
        "reference_node": reference["label"],
        "mismatches": mismatches,
        "component_digests": {
            str(snapshot["label"]): {group: digest(snapshot[group]) for group in groups}
            for snapshot in snapshots
        },
    }


def capture(clients: Sequence[RpcClient], requested_epoch: Optional[int], require_schema_v3: bool = False) -> Dict[str, Any]:
    bases: List[Dict[str, Any]] = run_parallel(clients, collect_base)
    epoch, epochs = choose_computed_epoch(clients, bases, requested_epoch)
    verify_anchors(clients, bases)
    snapshots: List[Dict[str, Any]] = []
    for base, epoch_state in zip(bases, epochs):
        snapshot = dict(base)
        snapshot["epoch_state"] = epoch_state
        snapshots.append(snapshot)
    if require_schema_v3 and any(int(snapshot["epoch_state"]["schema_version"]) != 3 for snapshot in snapshots):
        raise GateError("newest common computed epoch is not schema V3 on every node")
    if require_schema_v3 and any(
            snapshot["finality"].get("boundary_a_active") is not True
            for snapshot in snapshots):
        raise GateError("schema V3 was requested before Boundary A is active on every node")
    comparison = compare_snapshots(snapshots)
    return {
        "timestamp": utc_now(),
        "epoch": epoch,
        "passed": comparison["passed"],
        "comparison": comparison,
        "nodes": snapshots,
    }


def write_json(path: Optional[Path], value: Any) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(rendered)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print("wrote %s" % path)


def validate_private_output_path(path: Optional[Path]) -> None:
    """Release evidence supplied with --output must stay outside the checkout."""
    if path is None:
        return
    source_root = Path(__file__).resolve().parents[2]
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(source_root)
    except ValueError:
        return
    raise GateError("--output must be outside the source repository")


def should_record_capture(evidence: Mapping[str, Any], last_epoch: Optional[int]) -> bool:
    return (last_epoch is None or int(evidence["epoch"]) != last_epoch or
            evidence.get("passed") is not True)


def boundary_transition_increment(last_epoch: Optional[int], current_epoch: int) -> int:
    """Count one completely observed next boundary, rejecting missed/reversed epochs."""
    if last_epoch is None or current_epoch == last_epoch:
        return 0
    if current_epoch != last_epoch + 1:
        raise GateError(
            "watch did not observe consecutive epoch boundaries (%d -> %d)" %
            (last_epoch, current_epoch)
        )
    return 1


def selftest() -> int:
    epoch = {
        "epoch": 3,
        "height_start": 900,
        "height_end": 1199,
        "boundary_block": "01",
        "block_count": 2,
        "tx_count": 3,
        "total_trust": "0c",
        "finalized": True,
        "curve_root": "02",
        "nullifier_root": "03",
        "vote_set_root": "04",
        "finality_certificate": "05",
        "finality_tier": "hard",
        "consecutive_hard_epochs": 3,
        "finalized_height_as_of": 600,
        "schema_version": 3,
        "anchor_rule": "canonical-boundary",
        "epoch_state_digest": "06",
        "blocks": ["07", "08"],
    }
    template = {
        "best_height": 1200,
        "best_hash": "09",
        "dag_info": {field: field for field in DAG_INFO_FIELDS},
        "dag_tips": [{"hash": "0a"}],
        "dag_order": [{"order": 1, "hash": "0a"}],
        "epoch_state": epoch,
        "finality": {field: field for field in FINALITY_FIELDS},
        "mempool": ["0b"],
    }
    snapshots = [dict(template, label="node%d" % idx) for idx in range(1, 5)]
    assert compare_snapshots(snapshots)["passed"] is True
    divergent = [dict(snapshot) for snapshot in snapshots]
    divergent[3] = dict(divergent[3], mempool=["ff"])
    result = compare_snapshots(divergent)
    assert result["passed"] is False
    assert result["mismatches"][0]["field_group"] == "mempool"

    with tempfile.TemporaryDirectory(prefix="innova-fleet-selftest-") as tmp:
        path = Path(tmp) / "fleet.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "nodes": [
                        {"label": "n%d" % idx, "innovad": "/bin/false", "datadir": "/tmp/n%d" % idx, "rpcport": 19000 + idx, "network": "regtest"}
                        for idx in range(4)
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert len(load_inventory(path)) == 4
        duplicate = json.loads(path.read_text(encoding="utf-8"))
        duplicate["nodes"][3]["datadir"] = duplicate["nodes"][0]["datadir"]
        duplicate["nodes"][3]["rpcport"] = duplicate["nodes"][0]["rpcport"]
        path.write_text(json.dumps(duplicate), encoding="utf-8")
        try:
            load_inventory(path)
        except GateError:
            pass
        else:
            raise AssertionError("duplicate fleet endpoint was accepted")

        path.write_text(json.dumps({"schema_version": 1, "nodes": [
            {"label": "n%d" % idx, "innovad": "/bin/false", "datadir": "/tmp/n%d" % idx,
             "rpcport": 19000 + idx, "network": "regtest"}
            for idx in range(4)
        ]}), encoding="utf-8")
        bad = json.loads(path.read_text(encoding="utf-8"))
        # Unknown fields are rejected by exact schema, including credential
        # names not anticipated by a blacklist.
        bad["rpcuser"] = "must-not-be-stored"
        path.write_text(json.dumps(bad), encoding="utf-8")
        try:
            load_inventory(path)
        except GateError:
            pass
        else:
            raise AssertionError("credential-bearing inventory was accepted")

    assert validate_ssh_options(["-i", "/tmp/maintenance-key"]) == [
        "-i", "/tmp/maintenance-key"
    ]
    assert validate_ssh_options([
        "-o", "UserKnownHostsFile=/tmp/known_hosts"
    ]) == ["-o", "UserKnownHostsFile=/tmp/known_hosts"]
    try:
        validate_ssh_options(["-o", "StrictHostKeyChecking=no"])
    except GateError:
        pass
    else:
        raise AssertionError("unsafe SSH host-key override was accepted")
    try:
        validate_ssh_options(["-o", "PasswordAuthentication=yes"])
    except GateError:
        pass
    else:
        raise AssertionError("password SSH authentication override was accepted")
    for unsafe_option in (
        ["-o", "ProxyCommand=/bin/false"],
        ["-o", "LocalCommand=/bin/false"],
        ["-F", "/tmp/ssh-config"],
    ):
        try:
            validate_ssh_options(unsafe_option)
        except GateError:
            pass
        else:
            raise AssertionError("unsafe SSH execution option was accepted")
    try:
        validate_private_output_path(
            Path(__file__).resolve().parents[2] / "evidence.json"
        )
    except GateError:
        pass
    else:
        raise AssertionError("in-repository release evidence path was accepted")
    assert should_record_capture({"epoch": 3, "passed": True}, 3) is False
    assert should_record_capture({"epoch": 3, "passed": False}, 3) is True
    assert should_record_capture({"epoch": 2, "passed": True}, 3) is True
    assert boundary_transition_increment(None, 3) == 0
    assert boundary_transition_increment(3, 3) == 0
    assert boundary_transition_increment(3, 4) == 1
    for nonconsecutive in (2, 5):
        try:
            boundary_transition_increment(3, nonconsecutive)
        except GateError:
            pass
        else:
            raise AssertionError("non-consecutive watch epoch was accepted")

    class AnchorClient:
        def __init__(self, block_hash: str):
            self.node = Node("anchor", "/bin/false", "/tmp/anchor", 19000, "regtest")
            self.block_hash = block_hash

        def call(self, method: str, *args: Any) -> Any:
            return 1200 if method == "getblockcount" else self.block_hash

    verify_anchor(AnchorClient("aa"), 1200, "aa")  # type: ignore[arg-type]
    try:
        verify_anchor(AnchorClient("bb"), 1200, "aa")  # type: ignore[arg-type]
    except GateError:
        pass
    else:
        raise AssertionError("same-height reorg passed snapshot anchor verification")
    print("four-node differential selftest passed")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="Run offline parser/comparator tests")
    parser.add_argument("--inventory", type=Path, help="Credential-free four-node fleet JSON")
    parser.add_argument("--epoch", type=int, help="Compare this computed epoch; default is newest common epoch")
    parser.add_argument("--require-schema-v3", action="store_true", help="Fail unless the compared epoch uses schema V3")
    parser.add_argument("--output", type=Path, help="Write JSON evidence to this path")
    parser.add_argument("--watch", action="store_true", help="Capture again whenever the common epoch changes")
    parser.add_argument("--poll-interval", type=float, default=10.0)
    parser.add_argument(
        "--max-boundaries", type=int, default=1,
        help="Watch-mode epoch transitions after the initial capture; 0 means unbounded",
    )
    parser.add_argument("--rpc-timeout", type=int, default=30)
    parser.add_argument(
        "--ssh-option", action="append", default=[],
        help="Restricted SSH option (-i, -p, UserKnownHostsFile, or timeout/keepalive); repeatable",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()
    if args.inventory is None:
        raise GateError("--inventory is required (no retired seed defaults are used)")
    if args.max_boundaries < 0:
        raise GateError("--max-boundaries must be non-negative")
    if args.watch and args.epoch is not None:
        raise GateError("--watch cannot be combined with a fixed --epoch")
    validate_private_output_path(args.output)
    nodes = load_inventory(args.inventory)
    clients = [RpcClient(node, args.rpc_timeout, args.ssh_option) for node in nodes]

    captures: List[Dict[str, Any]] = []
    last_epoch: Optional[int] = None
    observed_boundary_transitions = 0
    while True:
        evidence = capture(clients, args.epoch, args.require_schema_v3)
        if not args.watch or should_record_capture(evidence, last_epoch):
            current_epoch = int(evidence["epoch"])
            observed_boundary_transitions += boundary_transition_increment(
                last_epoch, current_epoch
            )
            captures.append(evidence)
            last_epoch = current_epoch
            output: Any = {
                "schema_version": EVIDENCE_SCHEMA_VERSION,
                "captures": captures,
                "observed_boundary_transitions": observed_boundary_transitions,
                "passed": all(item["passed"] for item in captures),
            }
            write_json(args.output, output)
            if not evidence["passed"]:
                return 1
            if not args.watch:
                return 0
            if (args.max_boundaries > 0 and
                    observed_boundary_transitions >= args.max_boundaries):
                return 0
        time.sleep(max(0.25, args.poll_interval))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as exc:
        print("four-node differential gate: ERROR: %s" % exc, file=sys.stderr)
        raise SystemExit(2)
