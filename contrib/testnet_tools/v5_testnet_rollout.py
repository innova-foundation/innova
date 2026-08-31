#!/usr/bin/env python3
"""Read-only schema-V3 testnet preflight and activation calculator.

This tool never stops daemons, mines, copies binaries, snapshots wallets, or
changes remote configuration.  It verifies the four-node fleet is converged and
quiescent, reports the compiled Boundary-A height the fleet must carry, and
calculates the first Boundary-B epoch boundary with the required lead time.
Deployment remains a separately authorized operation.
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
import stat
import subprocess
import sys
import tempfile
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
TEST_DIR = SCRIPT_DIR.parent / "test"
sys.path.insert(0, str(TEST_DIR))

from idag_four_node_differential import (  # noqa: E402
    GateError,
    Node,
    RpcClient,
    SAFE_SSH_OPTIONS,
    digest,
    load_inventory,
    reject_credentials,
    validate_ssh_options,
)
from check_v5_release_policy import (  # noqa: E402
    PolicyError,
    validate_testnet_activation_ladder,
)
from v5_release_evidence_schema import (  # noqa: E402
    PREFLIGHT_SCHEMA_VERSION,
    REQUIRED_BOUNDARY_ORIGIN,
    REQUIRED_CHECKS,
    REQUIRED_EVIDENCE_FIELDS,
    REQUIRED_EPOCH_INTERVAL,
    REQUIRED_LEAD_BLOCKS,
    REQUIRED_NODE_FIELDS,
    REQUIRED_PRIVACY_VNEXT_DISCLOSURE_MODES,
    REQUIRED_PRIVACY_VNEXT_MEMBERSHIP_SCOPE,
    REQUIRED_PRIVACY_VNEXT_NULLSTAKE_GENERATION_IDS,
    REQUIRED_PRIVACY_VNEXT_OPERATIONS,
    REQUIRED_PRIVACY_VNEXT_POST_DAG_STAKING_ROLE,
    REQUIRED_PRIVACY_VNEXT_TREE_LAYERS,
    REQUIRED_SNAPSHOT_MANIFEST_FIELDS,
    REQUIRED_SNAPSHOT_NODE_FIELDS,
    SNAPSHOT_MANIFEST_SCHEMA_VERSION,
)


DEFAULT_BOUNDARY_ORIGIN = REQUIRED_BOUNDARY_ORIGIN
DEFAULT_EPOCH_INTERVAL = REQUIRED_EPOCH_INTERVAL
DEFAULT_LEAD_BLOCKS = REQUIRED_LEAD_BLOCKS
UNSET_HEIGHT = 0x7FFFFFFF


def validate_checked_in_seed_inventory() -> List[str]:
    """Require rollout targets and the compiled testnet seed list to match."""
    inventory_path = SCRIPT_DIR / "fleet.v3.json"
    source_path = SCRIPT_DIR.parent.parent / "src" / "net.cpp"
    nodes = load_inventory(inventory_path)
    inventory_hosts = validate_testnet_inventory(nodes)
    for node in nodes:
        ssh_host = node.ssh_target.rsplit("@", 1)[-1]
        if ssh_host != node.p2p_host:
            raise GateError("checked-in fleet SSH/P2P host mismatch for %s" % node.label)

    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GateError("cannot read compiled seed inventory: %s" % exc) from exc
    match = re.search(
        r"static const char \*strDNSSeedTestnet\[\]\[2\] = \{(.*?)\n\};",
        source,
        flags=re.DOTALL,
    )
    if not match:
        raise GateError("cannot locate strDNSSeedTestnet in src/net.cpp")
    pairs = re.findall(r'\{"([0-9.]+)",\s*"([0-9.]+)"\}', match.group(1))
    if len(pairs) != 4 or any(left != right for left, right in pairs):
        raise GateError("compiled testnet seed list must contain four direct IPv4 entries")
    source_hosts = [left for left, _ in pairs]
    if set(source_hosts) != set(inventory_hosts):
        raise GateError("compiled testnet seeds and checked-in rollout inventory differ")
    return source_hosts


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def activation_height(common_height: int, origin: int, interval: int, lead: int) -> int:
    if common_height < 0 or origin < 0 or interval <= 0 or lead < 0:
        raise GateError("height/origin/interval/lead values must be non-negative (interval > 0)")
    target = common_height + lead
    if target <= origin:
        return origin
    steps = (target - origin + interval - 1) // interval
    return origin + steps * interval


def boundary_b_activation_height(boundary_a_height: int, candidate_freeze_height: int,
                                 origin: int, interval: int, lead: int) -> int:
    """First epoch boundary at least ``lead`` blocks after both B prerequisites."""
    if boundary_a_height < 0 or candidate_freeze_height < 0:
        raise GateError("Boundary A and Boundary-B freeze heights must be non-negative")
    return activation_height(
        max(boundary_a_height, candidate_freeze_height), origin, interval, lead
    )


def boundary_b_inputs_available(boundary_a_height: Optional[int],
                                candidate_freeze_height: Optional[int]) -> bool:
    if (boundary_a_height is None) != (candidate_freeze_height is None):
        raise GateError("Boundary-B calculation requires both Boundary A and candidate-freeze heights")
    return boundary_a_height is not None


def parse_utc_timestamp(value: Any, field: str) -> dt.datetime:
    text = str(value or "")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise GateError("%s is missing or malformed" % field) from exc
    if parsed.tzinfo is None:
        raise GateError("%s must include a UTC offset" % field)
    return parsed.astimezone(dt.timezone.utc)


def empty_snapshot_manifest() -> Dict[str, Any]:
    return {
        "schema_version": SNAPSHOT_MANIFEST_SCHEMA_VERSION,
        "completed_at": "",
        "common_height": -1,
        "common_hash": "",
        "nodes": [],
    }


def load_snapshot_manifest(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return empty_snapshot_manifest()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError("cannot read snapshot manifest %s: %s" % (path, exc)) from exc
    reject_credentials(raw, "snapshot_manifest")
    if not isinstance(raw, dict) or set(raw) != REQUIRED_SNAPSHOT_MANIFEST_FIELDS:
        raise GateError("snapshot manifest fields do not match schema")
    if raw.get("schema_version") != SNAPSHOT_MANIFEST_SCHEMA_VERSION:
        raise GateError("snapshot manifest has an unsupported schema version")
    parse_utc_timestamp(raw.get("completed_at"), "snapshot_manifest.completed_at")
    nodes = raw.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 4 or not all(isinstance(node, dict) for node in nodes):
        raise GateError("snapshot manifest must contain exactly four node objects")
    if any(set(node) != REQUIRED_SNAPSHOT_NODE_FIELDS for node in nodes):
        raise GateError("snapshot manifest node fields do not match schema")
    labels = [str(node.get("label", "")) for node in nodes]
    if any(not label for label in labels) or len(set(labels)) != 4:
        raise GateError("snapshot manifest node labels are missing or duplicated")
    normalized = dict(raw)
    normalized["nodes"] = sorted((dict(node) for node in nodes), key=lambda node: str(node["label"]))
    return normalized


def is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in text)


def is_zero_amount(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    try:
        return Decimal(str(value)) == Decimal(0)
    except (InvalidOperation, ValueError):
        return False


def local_git_head(source_root: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(source_root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def local_source_clean(source_root: Path) -> bool:
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=str(source_root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0 and not proc.stdout.strip()


def command_output(command: Sequence[str], timeout: int) -> str:
    try:
        proc = subprocess.run(
            list(command),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(1, timeout),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError("command failed: %s" % exc) from exc
    if proc.returncode != 0:
        raise GateError(proc.stderr.strip() or proc.stdout.strip() or "exit status %d" % proc.returncode)
    return proc.stdout.strip()


def require_rollout_ssh_material(ssh_options: Sequence[str], nodes: Sequence[Node],
                                 source_root: Path, timeout: int) -> None:
    """Require one explicit private key and one dedicated, preloaded host-key file."""
    identity_paths: List[str] = []
    known_hosts_paths: List[str] = []
    idx = 0
    while idx < len(ssh_options):
        token = ssh_options[idx]
        if token == "-i":
            idx += 1
            if idx >= len(ssh_options):
                raise GateError("--ssh-option -i requires a private-key path")
            identity_paths.append(ssh_options[idx])
        elif token.startswith("-i") and len(token) > 2:
            identity_paths.append(token[2:])
        else:
            setting = ""
            if token == "-o":
                idx += 1
                if idx >= len(ssh_options):
                    raise GateError("--ssh-option -o requires a setting")
                setting = ssh_options[idx]
            elif token.startswith("-o") and len(token) > 2:
                setting = token[2:]
            key, sep, value = setting.partition("=")
            if sep and key.strip().lower() == "userknownhostsfile":
                known_hosts_paths.append(value.strip())
        idx += 1

    if len(identity_paths) != 1:
        raise GateError("live rollout requires exactly one explicit -i private-key path")
    if len(known_hosts_paths) != 1:
        raise GateError(
            "live rollout requires exactly one explicit UserKnownHostsFile path"
        )

    identity = Path(identity_paths[0]).expanduser().resolve()
    known_hosts = Path(known_hosts_paths[0]).expanduser().resolve()
    if not identity.is_file():
        raise GateError("rollout private-key file is missing")
    if identity.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise GateError("rollout private-key permissions must deny group/other access")
    try:
        identity.relative_to(source_root.expanduser().resolve())
    except ValueError:
        pass
    else:
        raise GateError("rollout private key must not be stored inside the source tree")
    public_identity = Path(str(identity) + ".pub")
    if not public_identity.is_file():
        raise GateError("rollout key requires its companion .pub file")
    try:
        key_info = subprocess.run(
            ["ssh-keygen", "-lf", str(public_identity), "-E", "sha256"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=max(1, timeout),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError("cannot inspect rollout public key: %s" % exc) from exc
    if key_info.returncode != 0 or "ED25519" not in key_info.stdout.upper():
        raise GateError("rollout maintenance key must be Ed25519")
    if not known_hosts.is_file() or known_hosts.stat().st_size == 0:
        raise GateError("dedicated rollout known_hosts file is missing or empty")

    for node in nodes:
        host = node.ssh_target.rsplit("@", 1)[-1]
        try:
            proc = subprocess.run(
                ["ssh-keygen", "-F", host, "-f", str(known_hosts)],
                text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                timeout=max(1, timeout),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GateError("cannot verify rollout host-key inventory: %s" % exc) from exc
        if proc.returncode != 0:
            raise GateError("dedicated known_hosts has no verified entry for %s" % host)


def binary_sha256(node: Node, ssh_options: Sequence[str], timeout: int) -> str:
    ssh_options = validate_ssh_options(ssh_options)
    if node.ssh_target:
        remote = "sha256sum %s" % shlex.quote(node.innovad)
        text = command_output(["ssh"] + SAFE_SSH_OPTIONS + list(ssh_options) + [node.ssh_target, remote], timeout + 8)
        value = text.split(None, 1)[0] if text else ""
    else:
        path = Path(node.innovad)
        try:
            hasher = hashlib.sha256()
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    hasher.update(chunk)
            value = hasher.hexdigest()
        except OSError as exc:
            raise GateError("%s cannot hash %s: %s" % (node.label, path, exc)) from exc
    if len(value) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise GateError("%s returned an invalid binary SHA-256" % node.label)
    return value.lower()


def bool_field(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if str(value).lower() in ("true", "1"):
        return True
    if str(value).lower() in ("false", "0"):
        return False
    return None


def exact_int_list(value: Any, required: Sequence[int]) -> bool:
    return (
        isinstance(value, list) and
        all(isinstance(item, int) and not isinstance(item, bool) for item in value) and
        tuple(value) == tuple(required)
    )


def boundary_b_status_is_consistent(nodes: Sequence[Mapping[str, Any]],
                                    calculation_available: bool,
                                    recommended_height: int,
                                    common_height: int) -> bool:
    configured = [bool_field(node.get("boundary_b_configured")) for node in nodes]
    try:
        activation_heights = [int(node.get("boundary_b_activation_height", -1)) for node in nodes]
    except (TypeError, ValueError):
        return False
    if not calculation_available:
        return all(value is False for value in configured) and all(
            bool_field(node.get("boundary_b_active")) is False and
            activation_height == UNSET_HEIGHT
            for node, activation_height in zip(nodes, activation_heights)
        )
    if recommended_height < 0 or not all(value is True for value in configured):
        return False
    return all(
        activation_height == recommended_height and
        bool_field(node.get("boundary_b_active")) is (common_height >= recommended_height)
        for node, activation_height in zip(nodes, activation_heights)
    )


def peer_host(value: Any) -> str:
    text = str(value or "").strip().lower().split("/", 1)[0]
    if not text:
        return ""
    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")]
    if text.count(":") == 1:
        return text.rsplit(":", 1)[0]
    return text.strip("[]")


def collect_node(client: RpcClient, ssh_options: Sequence[str], timeout: int,
                 fleet_p2p_hosts: Sequence[str]) -> Dict[str, Any]:
    label = client.node.label
    before = int(client.call("getblockcount"))
    best_hash = str(client.call("getblockhash", before))
    chain = client.call("getblockchaininfo")
    info = client.call("getinfo")
    network_info = client.call("getnetworkinfo")
    mining = client.call("getmininginfo")
    staking = client.call("getstakinginfo")
    dag = client.call("getdaginfo")
    finality = client.call("getfinalityinfo")
    shielded = client.call("z_getshieldedinfo")
    mempool = client.call("getrawmempool")
    peers = client.call("getpeerinfo")
    banned = client.call("listbanned")
    after = int(client.call("getblockcount"))
    hash_after = str(client.call("getblockhash", after))
    for method, value in (("getblockchaininfo", chain), ("getinfo", info),
                          ("getnetworkinfo", network_info), ("getmininginfo", mining),
                          ("getstakinginfo", staking), ("getdaginfo", dag),
                          ("getfinalityinfo", finality),
                          ("z_getshieldedinfo", shielded)):
        if not isinstance(value, dict):
            raise GateError("%s %s did not return an object" % (label, method))
    if not isinstance(mempool, list):
        raise GateError("%s getrawmempool did not return an array" % label)
    if not isinstance(peers, list) or not isinstance(banned, list):
        raise GateError("%s peer/ban RPC did not return arrays" % label)
    observed_peer_hosts = {
        peer_host(entry.get("addr")) for entry in peers if isinstance(entry, dict)
    }
    expected_peer_hosts = set(fleet_p2p_hosts) - {client.node.p2p_host}
    connected_fleet_hosts = sorted(expected_peer_hosts & observed_peer_hosts)
    missing_fleet_hosts = sorted(expected_peer_hosts - observed_peer_hosts)
    banned_hosts = {
        peer_host(entry.get("address")) for entry in banned if isinstance(entry, dict)
    }
    banned_fleet_hosts = sorted(set(fleet_p2p_hosts) & banned_hosts)
    local_addresses = network_info.get("localaddresses", [])
    if not isinstance(local_addresses, list):
        raise GateError("%s getnetworkinfo.localaddresses is not an array" % label)
    advertised_hosts = {
        peer_host(entry.get("address")) for entry in local_addresses if isinstance(entry, dict)
    }
    result = {
        "label": label,
        "network": client.node.network,
        "node_identity": client.node.endpoint_identity(),
        "p2p_identity": digest(client.node.p2p_host),
        "p2p_identity_advertised": client.node.p2p_host in advertised_hosts,
        "height": before,
        "height_hash_stable": before == after and best_hash == hash_after,
        "best_hash": best_hash,
        "initialblockdownload": bool_field(chain.get("initialblockdownload")),
        "warnings": info.get("errors", "") or chain.get("warnings", ""),
        "cpumining": bool_field(mining.get("cpumining")),
        "staking": bool_field(staking.get("staking")),
        "dag_active": bool_field(dag.get("dag_active")),
        "dag_best_tip": dag.get("best_dag_tip", ""),
        "finality_tier": finality.get("finality_tier", ""),
        "finalized_height": finality.get("deterministic_finalized_height", finality.get("finalized_height", -1)),
        "epoch_state_health": finality.get("epoch_state_health", "missing"),
        "schema_version": finality.get("epoch_state_schema_version", 0),
        "required_schema_version": finality.get("epoch_state_required_schema_version", 0),
        "schema_marker_present": bool_field(finality.get("epoch_state_schema_marker_present")),
        "deterministic_finalized_height_available": bool_field(
            finality.get("deterministic_finalized_height_available")
        ),
        "committee_set_hash": finality.get("tally_committee_set_hash", ""),
        "candidate_build_identifier": finality.get("candidate_build_identifier", ""),
        "boundary_a_activation_height": finality.get("boundary_a_activation_height", -1),
        "boundary_a_configured": bool_field(finality.get("boundary_a_configured")),
        "boundary_a_active": bool_field(finality.get("boundary_a_active")),
        "boundary_b_activation_height": finality.get("boundary_b_activation_height", -1),
        "boundary_b_configured": bool_field(finality.get("boundary_b_configured")),
        "boundary_b_active": bool_field(finality.get("boundary_b_active")),
        "serializer_schema_version": finality.get("serializer_schema_version", 0),
        "serializer_schema": finality.get("serializer_schema", ""),
        "migration_state": finality.get("migration_state", "missing"),
        "legacy_anon_status": finality.get("legacy_anon_status", "missing"),
        "privacy_protocol_status": finality.get("privacy_protocol_status", "missing"),
        "epoch_state_digest": finality.get("epoch_state_digest", ""),
        "epoch_state_curve_root": finality.get("epoch_state_curve_root", ""),
        "epoch_state_nullifier_root": finality.get("epoch_state_nullifier_root", ""),
        "epoch_state_vote_set_root": finality.get("epoch_state_vote_set_root", ""),
        "shielded_pool_value": shielded.get("shielded_pool_value"),
        "unspent_notes": shielded.get("unspent_notes"),
        "shielded_state_healthy": bool_field(shielded.get("shielded_state_healthy")),
        "legacy_shielded_consensus_active": bool_field(shielded.get("legacy_shielded_consensus_active")),
        "legacy_shielded_creation_enabled": bool_field(shielded.get("legacy_shielded_creation_enabled")),
        "legacy_privacy_retired": bool_field(shielded.get("legacy_privacy_retired")),
        "privacy_vnext_consensus_ready": bool_field(shielded.get("privacy_vnext_consensus_ready")),
        "privacy_vnext_abi_version": shielded.get("privacy_vnext_abi_version", 0),
        "privacy_vnext_abi_sha256": shielded.get("privacy_vnext_abi_sha256", ""),
        "privacy_vnext_disclosure_modes": shielded.get("privacy_vnext_disclosure_modes", []),
        "privacy_vnext_parameter_digest": shielded.get("privacy_vnext_parameter_digest", ""),
        "privacy_vnext_tree_root": shielded.get("privacy_vnext_tree_root", ""),
        "privacy_vnext_tree_size": shielded.get("privacy_vnext_tree_size", -1),
        "privacy_vnext_tree_layers": shielded.get("privacy_vnext_tree_layers", 0),
        "privacy_vnext_max_inputs": shielded.get("privacy_vnext_max_inputs", 0),
        "privacy_vnext_max_outputs": shielded.get("privacy_vnext_max_outputs", 0),
        "privacy_vnext_max_payload_bytes": shielded.get("privacy_vnext_max_payload_bytes", 0),
        "privacy_vnext_membership_scope": shielded.get("privacy_vnext_membership_scope", ""),
        "privacy_vnext_nullstake_generation_ids": shielded.get(
            "privacy_vnext_nullstake_generation_ids", []
        ),
        "privacy_vnext_post_dag_staking_role": shielded.get(
            "privacy_vnext_post_dag_staking_role", ""
        ),
        "privacy_vnext_supported_operations": shielded.get("privacy_vnext_supported_operations", []),
        "privacy_vnext_wallet_migration_state": shielded.get("privacy_vnext_wallet_migration_state", "missing"),
        "shielded_privacy_protocol_status": shielded.get("privacy_protocol_status", "missing"),
        "commitment_tree_size": shielded.get("commitment_tree_size", -1),
        "mempool_count": len(mempool),
        "peer_count": len(peers),
        "connected_fleet_peer_count": len(connected_fleet_hosts),
        "missing_fleet_peer_count": len(missing_fleet_hosts),
        "banned_fleet_peer_count": len(banned_fleet_hosts),
        "binary_sha256": binary_sha256(client.node, ssh_options, timeout),
    }
    if set(result) != REQUIRED_NODE_FIELDS:
        raise GateError("internal preflight node schema drift")
    return result


def validate_testnet_inventory(nodes: Sequence[Node]) -> List[str]:
    if any(node.network != "testnet" for node in nodes):
        raise GateError("testnet preflight rejects mainnet/regtest inventory entries")
    targets = [node.ssh_target for node in nodes]
    if any(not target for target in targets) or len(set(targets)) != 4:
        raise GateError("testnet preflight requires four distinct SSH endpoints")
    p2p_hosts = [node.p2p_host for node in nodes]
    if (any(not host or host.endswith(".invalid") or peer_host(host) != host or
            any(ch.isspace() for ch in host)
            for host in p2p_hosts) or len(set(p2p_hosts)) != 4):
        raise GateError("testnet preflight requires four distinct non-placeholder p2p_host values")
    return p2p_hosts


def run_preflight(args: argparse.Namespace) -> Dict[str, Any]:
    nodes = load_inventory(args.inventory)
    p2p_hosts = validate_testnet_inventory(nodes)
    ssh_options = validate_ssh_options(args.ssh_option)
    require_rollout_ssh_material(
        ssh_options, nodes, args.source_root, args.rpc_timeout
    )
    clients = [RpcClient(node, args.rpc_timeout, ssh_options) for node in nodes]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [
            pool.submit(collect_node, client, ssh_options, args.rpc_timeout, p2p_hosts)
            for client in clients
        ]
        results = [future.result() for future in futures]

    heights = [int(node["height"]) for node in results]
    hashes = [str(node["best_hash"]) for node in results]
    binaries = [str(node["binary_sha256"]) for node in results]
    common_height = heights[0] if len(set(heights)) == 1 else -1
    common_hash = hashes[0] if len(set(hashes)) == 1 else ""
    # Boundary A comes from the compiled ladder (testnet remines from genesis); the
    # check below proves all four nodes carry it. Boundary B keeps the lead calculation.
    try:
        recommended = validate_testnet_activation_ladder(
            Path(args.source_root) / "src" / "main.h")["boundary_a"]
    except PolicyError as exc:
        raise GateError("compiled testnet activation ladder is invalid: %s" % exc) from exc
    source_commit = local_git_head(args.source_root)
    source_clean = local_source_clean(args.source_root)
    expected_binary = args.expected_binary_sha256.lower()
    expected_build = args.expected_candidate_build_identifier.strip()
    expected_serializer = args.expected_serializer_schema.strip()
    expected_serializer_version = args.expected_serializer_schema_version
    node_identities = [str(node["node_identity"]) for node in results]
    p2p_identities = [str(node["p2p_identity"]) for node in results]
    snapshot_manifest = load_snapshot_manifest(args.snapshot_manifest)
    snapshot_supplied = args.snapshot_manifest is not None
    snapshot_nodes = {
        str(node.get("label")): node for node in snapshot_manifest.get("nodes", [])
        if isinstance(node, dict)
    }
    snapshots_complete = snapshot_supplied and len(snapshot_nodes) == 4 and all(
        node.get("chain_snapshot_complete") is True and
        node.get("wallet_snapshot_complete") is True and
        is_sha256(node.get("chain_snapshot_sha256")) and
        is_sha256(node.get("wallet_snapshot_sha256"))
        for node in snapshot_nodes.values()
    )
    snapshots_match_chain = snapshots_complete and set(snapshot_nodes) == {
        str(node["label"]) for node in results
    } and int(snapshot_manifest.get("common_height", -1)) == common_height and \
        str(snapshot_manifest.get("common_hash", "")) == common_hash and all(
            int(snapshot_nodes[str(node["label"])].get("height", -1)) == common_height and
            str(snapshot_nodes[str(node["label"])].get("best_hash", "")) == common_hash
            for node in results
        )
    boundary_b_available = boundary_b_inputs_available(
        args.boundary_a_height, args.boundary_b_candidate_freeze_height
    )
    boundary_b_recommended = boundary_b_activation_height(
        args.boundary_a_height, args.boundary_b_candidate_freeze_height,
        args.boundary_origin, args.epoch_interval, args.lead_blocks,
    ) if boundary_b_available else -1
    boundary_b_status_consistent = boundary_b_status_is_consistent(
        results, boundary_b_available, boundary_b_recommended, common_height
    )
    consensus_health = {
        (str(node["dag_best_tip"]), str(node["finality_tier"]),
         int(node["finalized_height"]), str(node["committee_set_hash"]))
        for node in results
    }
    digest_health = {
        (str(node["epoch_state_digest"]), str(node["epoch_state_curve_root"]),
         str(node["epoch_state_nullifier_root"]), str(node["epoch_state_vote_set_root"]))
        for node in results
    }
    checks = {
        "exactly_four_nodes": len(results) == 4,
        "testnet_only": all(str(node["network"]) == "testnet" for node in results),
        "unique_node_identities": len(set(node_identities)) == 4 and len(set(p2p_identities)) == 4,
        "p2p_identities_advertised": all(bool(node["p2p_identity_advertised"]) for node in results),
        "height_and_hash_stable": all(bool(node["height_hash_stable"]) for node in results),
        "common_height": common_height >= 0,
        "common_best_hash": bool(common_hash),
        "out_of_ibd": all(bool_field(node["initialblockdownload"]) is False for node in results),
        "controlled_mining_paused": all(bool_field(node["cpumining"]) is False for node in results),
        "controlled_staking_paused": all(bool_field(node["staking"]) is False for node in results),
        "mempools_empty": all(int(node["mempool_count"]) == 0 for node in results),
        "no_warnings": all(not str(node["warnings"] or "") for node in results),
        "dag_active": all(bool_field(node["dag_active"]) is True for node in results),
        "four_node_peer_mesh": all(int(node["missing_fleet_peer_count"]) == 0 and
                                   int(node["connected_fleet_peer_count"]) == 3
                                   for node in results),
        "no_fleet_bans": all(int(node["banned_fleet_peer_count"]) == 0 for node in results),
        "epoch_state_healthy": all(str(node["epoch_state_health"]) == "ok" for node in results),
        "schema_consistent": all(
            int(node["schema_version"]) in (2, 3)
            and int(node["schema_version"]) == int(node["required_schema_version"])
            for node in results
        ),
        "schema_marker_present": all(bool_field(node["schema_marker_present"]) is True for node in results),
        "deterministic_finalized_height_available": all(
            bool_field(node["deterministic_finalized_height_available"]) is True for node in results
        ),
        "consensus_health_matches": len(consensus_health) == 1,
        "health_digests_match": len(digest_health) == 1 and all(
            is_sha256(value) for values in digest_health for value in values
        ),
        "boundary_a_matches_recommendation": common_height >= 0 and all(
            bool_field(node["boundary_a_configured"]) is True and
            int(node["boundary_a_activation_height"]) == recommended and
            bool_field(node["boundary_a_active"]) is (common_height >= recommended)
            for node in results
        ),
        "boundary_b_status_consistent": boundary_b_status_consistent,
        "boundary_b_calculation_consistent": (
            (boundary_b_available and args.boundary_a_height == recommended and
             boundary_b_recommended == activation_height(
                max(args.boundary_a_height, args.boundary_b_candidate_freeze_height),
                args.boundary_origin, args.epoch_interval, args.lead_blocks)) or
            (not boundary_b_available and boundary_b_recommended == -1)
        ),
        "expected_candidate_build_identifier_supplied": bool(expected_build),
        "candidate_build_identifiers_match": bool(expected_build) and all(
            str(node["candidate_build_identifier"]) == expected_build for node in results
        ),
        "candidate_build_bound_to_source": bool(source_commit) and
        source_commit.lower() in expected_build.lower() and
        "dirty" not in expected_build.lower(),
        "expected_serializer_schema_supplied": bool(expected_serializer) and
        expected_serializer_version > 0 and expected_serializer != "legacy_v5_decode",
        "serializer_schema_matches": bool(expected_serializer) and all(
            str(node["serializer_schema"]) == expected_serializer and
            int(node["serializer_schema_version"]) == expected_serializer_version
            for node in results
        ),
        "migration_ready": all(
            str(node["migration_state"]) == "recovery_idle" for node in results
        ),
        "legacy_anon_historical": all(str(node["legacy_anon_status"]) == "historical_only" for node in results),
        "legacy_privacy_consensus_retired": all(
            bool_field(node["legacy_shielded_consensus_active"]) is False and
            bool_field(node["legacy_privacy_retired"]) is True
            for node in results
        ),
        "privacy_health_consistent": len({
            (str(node["privacy_protocol_status"]), str(node["shielded_privacy_protocol_status"]))
            for node in results
        }) == 1 and all(
            str(node["privacy_protocol_status"]) == str(node["shielded_privacy_protocol_status"]) and
            bool_field(node["legacy_shielded_creation_enabled"]) is False
            for node in results
        ),
        "privacy_vnext_ready": all(
            bool_field(node["privacy_vnext_consensus_ready"]) is True and
            str(node["privacy_vnext_wallet_migration_state"]) == "ready"
            for node in results
        ),
        "privacy_vnext_product_contract": all(
            exact_int_list(
                node["privacy_vnext_disclosure_modes"],
                REQUIRED_PRIVACY_VNEXT_DISCLOSURE_MODES,
            ) and
            exact_int_list(
                node["privacy_vnext_nullstake_generation_ids"],
                REQUIRED_PRIVACY_VNEXT_NULLSTAKE_GENERATION_IDS,
            ) and
            int(node["privacy_vnext_tree_layers"]) == REQUIRED_PRIVACY_VNEXT_TREE_LAYERS and
            str(node["privacy_vnext_membership_scope"]) ==
                REQUIRED_PRIVACY_VNEXT_MEMBERSHIP_SCOPE and
            str(node["privacy_vnext_post_dag_staking_role"]) ==
                REQUIRED_PRIVACY_VNEXT_POST_DAG_STAKING_ROLE and
            node["privacy_vnext_supported_operations"] ==
                list(REQUIRED_PRIVACY_VNEXT_OPERATIONS)
            for node in results
        ),
        "privacy_vnext_state_consistent": len({
            (
                int(node["privacy_vnext_abi_version"]),
                str(node["privacy_vnext_abi_sha256"]),
                str(node["privacy_vnext_parameter_digest"]),
                str(node["privacy_vnext_tree_root"]),
                int(node["privacy_vnext_tree_size"]),
                int(node["privacy_vnext_max_inputs"]),
                int(node["privacy_vnext_max_outputs"]),
                int(node["privacy_vnext_max_payload_bytes"]),
                tuple(node["privacy_vnext_disclosure_modes"]),
                tuple(node["privacy_vnext_nullstake_generation_ids"]),
                int(node["privacy_vnext_tree_layers"]),
                str(node["privacy_vnext_membership_scope"]),
                str(node["privacy_vnext_post_dag_staking_role"]),
                tuple(node["privacy_vnext_supported_operations"]),
            )
            for node in results
        }) == 1,
        "legacy_pool_empty": all(is_zero_amount(node["shielded_pool_value"]) for node in results),
        "zero_unspent_legacy_notes": all(
            not isinstance(node["unspent_notes"], bool) and
            isinstance(node["unspent_notes"], int) and node["unspent_notes"] == 0
            for node in results
        ),
        "shielded_state_healthy": all(bool_field(node["shielded_state_healthy"]) is True for node in results),
        "snapshot_manifest_supplied": snapshot_supplied,
        "snapshots_complete": snapshots_complete,
        "snapshot_manifest_matches_chain": snapshots_match_chain,
        "binary_hashes_match": len(set(binaries)) == 1,
        "expected_binary_supplied": len(expected_binary) == 64
        and all(ch in "0123456789abcdef" for ch in expected_binary),
        "expected_binary_matches": len(expected_binary) == 64
        and all(value == expected_binary for value in binaries),
        "release_parameters_fixed": (
            args.lead_blocks == DEFAULT_LEAD_BLOCKS
            and args.epoch_interval == DEFAULT_EPOCH_INTERVAL
            and args.boundary_origin == DEFAULT_BOUNDARY_ORIGIN
        ),
        "source_tree_clean": source_clean,
        "source_commit_present": len(source_commit) in (40, 64)
        and all(ch in "0123456789abcdef" for ch in source_commit.lower()),
        "artifact_source_commit_matches": bool(args.artifact_source_commit)
        and args.artifact_source_commit.lower() == source_commit.lower(),
    }
    if set(checks) != REQUIRED_CHECKS:
        raise GateError("internal preflight check schema drift")
    evidence = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "source_commit": source_commit,
        "artifact_source_commit": args.artifact_source_commit.lower(),
        "expected_binary_sha256": expected_binary,
        "expected_candidate_build_identifier": expected_build,
        "expected_serializer_schema": expected_serializer,
        "expected_serializer_schema_version": expected_serializer_version,
        "passed": all(checks.values()),
        "failed_checks": [name for name, passed in checks.items() if not passed],
        "checks": checks,
        "common_height": common_height,
        "common_hash": common_hash,
        "activation_height": recommended,
        "lead_blocks": args.lead_blocks,
        "epoch_interval": args.epoch_interval,
        "boundary_origin": args.boundary_origin,
        "boundary_b_calculation_available": boundary_b_available,
        "boundary_b_boundary_a_height": args.boundary_a_height if boundary_b_available else -1,
        "boundary_b_candidate_freeze_height": (
            args.boundary_b_candidate_freeze_height if boundary_b_available else -1
        ),
        "boundary_b_recommended_activation_height": boundary_b_recommended,
        "snapshot_manifest": snapshot_manifest,
        "snapshot_manifest_sha256": digest(snapshot_manifest) if snapshot_supplied else "",
        "nodes": results,
    }
    if set(evidence) != REQUIRED_EVIDENCE_FIELDS:
        raise GateError("internal preflight evidence schema drift")
    return evidence


def write_result(value: Dict[str, Any], output: Optional[Path]) -> None:
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print("wrote %s" % output)
    else:
        sys.stdout.write(text)


def selftest() -> int:
    # The preflight recommends the compiled Boundary A; its placement is part of the contract.
    ladder = validate_testnet_activation_ladder(SCRIPT_DIR.parent.parent / "src" / "main.h")
    assert ladder["boundary_a"] == ladder["dag"] + ladder["epoch_interval"]
    assert activation_height(0, 60, 300, 900) == 960
    assert activation_height(60, 60, 300, 900) == 960
    assert activation_height(61, 60, 300, 900) == 1260
    assert activation_height(360, 60, 300, 900) == 1260
    assert activation_height(361, 60, 300, 900) == 1560
    assert boundary_b_activation_height(1860, 1860, 60, 300, 900) == 2760
    assert boundary_b_activation_height(1860, 2000, 60, 300, 900) == 3060
    assert boundary_b_activation_height(1860, 3000, 60, 300, 900) == 3960
    assert boundary_b_inputs_available(None, None) is False
    assert boundary_b_inputs_available(1860, 1860) is True
    try:
        boundary_b_inputs_available(1860, None)
    except GateError:
        pass
    else:
        raise AssertionError("partial Boundary-B arithmetic inputs were accepted")
    unconfigured_boundary_b = [{
        "boundary_b_activation_height": UNSET_HEIGHT,
        "boundary_b_configured": False,
        "boundary_b_active": False,
    } for _ in range(4)]
    assert boundary_b_status_is_consistent(unconfigured_boundary_b, False, -1, 853)
    assert not boundary_b_status_is_consistent(unconfigured_boundary_b, True, 2760, 853)
    configured_boundary_b = [{
        "boundary_b_activation_height": 2760,
        "boundary_b_configured": True,
        "boundary_b_active": False,
    } for _ in range(4)]
    assert boundary_b_status_is_consistent(configured_boundary_b, True, 2760, 853)
    assert not boundary_b_status_is_consistent(configured_boundary_b, False, -1, 853)
    configured_boundary_b[0]["boundary_b_activation_height"] = 3060
    assert not boundary_b_status_is_consistent(configured_boundary_b, True, 2760, 853)
    assert peer_host("192.0.2.1:15539") == "192.0.2.1"
    assert peer_host("[2001:db8::1]:15539") == "2001:db8::1"
    assert peer_host("192.0.2.1/32") == "192.0.2.1"
    product_contract = {
        "privacy_vnext_disclosure_modes": list(REQUIRED_PRIVACY_VNEXT_DISCLOSURE_MODES),
        "privacy_vnext_nullstake_generation_ids": list(
            REQUIRED_PRIVACY_VNEXT_NULLSTAKE_GENERATION_IDS
        ),
        "privacy_vnext_tree_layers": REQUIRED_PRIVACY_VNEXT_TREE_LAYERS,
        "privacy_vnext_membership_scope": REQUIRED_PRIVACY_VNEXT_MEMBERSHIP_SCOPE,
        "privacy_vnext_post_dag_staking_role": REQUIRED_PRIVACY_VNEXT_POST_DAG_STAKING_ROLE,
        "privacy_vnext_supported_operations": list(REQUIRED_PRIVACY_VNEXT_OPERATIONS),
    }
    assert product_contract["privacy_vnext_disclosure_modes"] == list(range(8))
    assert product_contract["privacy_vnext_nullstake_generation_ids"] == [1, 2, 3]
    assert product_contract["privacy_vnext_tree_layers"] == 8
    assert product_contract["privacy_vnext_membership_scope"] == "full_chain_finalized_root"
    assert product_contract["privacy_vnext_post_dag_staking_role"] == "finality"
    assert exact_int_list(list(range(8)), REQUIRED_PRIVACY_VNEXT_DISCLOSURE_MODES)
    assert not exact_int_list(
        [0, True, 2, 3, 4, 5, 6, 7], REQUIRED_PRIVACY_VNEXT_DISCLOSURE_MODES
    )
    nodes = [
        Node("n%d" % idx, "/bin/false", "/tmp/n%d" % idx, 19000 + idx,
             "testnet", "root@192.0.2.%d" % (idx + 1), "", "192.0.2.%d" % (idx + 1))
        for idx in range(4)
    ]
    assert len(validate_testnet_inventory(nodes)) == 4
    try:
        require_rollout_ssh_material([], nodes, SCRIPT_DIR.parent.parent, 1)
    except GateError:
        pass
    else:
        raise AssertionError("live rollout accepted missing key/known_hosts material")
    try:
        validate_testnet_inventory([dataclasses.replace(nodes[0], network="mainnet")] + nodes[1:])
    except GateError:
        pass
    else:
        raise AssertionError("non-testnet rollout inventory was accepted")
    assert len(validate_checked_in_seed_inventory()) == 4
    with tempfile.TemporaryDirectory(prefix="innova-snapshot-manifest-") as tmp:
        manifest_path = Path(tmp) / "snapshots.json"
        manifest_path.write_text(json.dumps({
            "schema_version": SNAPSHOT_MANIFEST_SCHEMA_VERSION,
            "completed_at": "2026-07-11T12:00:00Z",
            "common_height": 853,
            "common_hash": "ab" * 32,
            "nodes": [{
                "label": "n%d" % idx,
                "height": 853,
                "best_hash": "ab" * 32,
                "chain_snapshot_complete": True,
                "chain_snapshot_sha256": "%064x" % (idx + 1),
                "wallet_snapshot_complete": True,
                "wallet_snapshot_sha256": "%064x" % (idx + 101),
            } for idx in range(4)],
        }), encoding="utf-8")
        loaded = load_snapshot_manifest(manifest_path)
        assert len(loaded["nodes"]) == 4
        assert is_sha256(loaded["nodes"][0]["chain_snapshot_sha256"])
        assert is_zero_amount("0.00000000")
    print("v5 testnet rollout selftest passed")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--common-height", type=int, help="Offline calculation only; no inventory or RPC access")
    parser.add_argument("--inventory", type=Path, help="Credential-free four-node inventory for read-only preflight")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--boundary-origin", type=int, default=DEFAULT_BOUNDARY_ORIGIN)
    parser.add_argument("--epoch-interval", type=int, default=DEFAULT_EPOCH_INTERVAL)
    parser.add_argument("--lead-blocks", type=int, default=DEFAULT_LEAD_BLOCKS)
    parser.add_argument("--expected-binary-sha256", default="")
    parser.add_argument("--expected-candidate-build-identifier", default="")
    parser.add_argument("--expected-serializer-schema", default="")
    parser.add_argument("--expected-serializer-schema-version", type=int, default=0)
    parser.add_argument("--artifact-source-commit", default="",
                        help="Commit from which the deployed expected binary was built")
    parser.add_argument("--snapshot-manifest", type=Path,
                        help="Credential-free hashes/completion metadata for all chain and wallet snapshots")
    parser.add_argument("--boundary-a-height", type=int,
                        help="Boundary A height used only for Boundary-B arithmetic")
    parser.add_argument("--boundary-b-candidate-freeze-height", type=int,
                        help="Immutable Boundary-B candidate freeze height used only for arithmetic")
    parser.add_argument("--source-root", type=Path, default=SCRIPT_DIR.parent.parent)
    parser.add_argument("--rpc-timeout", type=int, default=30)
    parser.add_argument("--ssh-option", action="append", default=[])
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()
    if args.common_height is not None:
        b_available = boundary_b_inputs_available(
            args.boundary_a_height, args.boundary_b_candidate_freeze_height
        )
        result = {
            "common_height": args.common_height,
            "minimum_height": args.common_height + args.lead_blocks,
            "activation_height": activation_height(args.common_height, args.boundary_origin, args.epoch_interval, args.lead_blocks),
            "lead_blocks": args.lead_blocks,
            "epoch_interval": args.epoch_interval,
            "boundary_origin": args.boundary_origin,
            "boundary_b_calculation_available": b_available,
            "boundary_b_boundary_a_height": args.boundary_a_height if b_available else -1,
            "boundary_b_candidate_freeze_height": (
                args.boundary_b_candidate_freeze_height if b_available else -1
            ),
            "boundary_b_activation_height": boundary_b_activation_height(
                args.boundary_a_height, args.boundary_b_candidate_freeze_height,
                args.boundary_origin, args.epoch_interval, args.lead_blocks,
            ) if b_available else -1,
        }
        write_result(result, args.output)
        return 0
    if args.inventory is None:
        raise GateError("--inventory is required for preflight; retired seed defaults are forbidden")
    result = run_preflight(args)
    write_result(result, args.output)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as exc:
        print("v5 testnet rollout: ERROR: %s" % exc, file=sys.stderr)
        raise SystemExit(2)
