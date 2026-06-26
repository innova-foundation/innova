#!/usr/bin/env python3
"""Live testnet metrics, reports, and guarded traffic tooling for Innova.

This script intentionally uses only the Python standard library.  It talks to
existing Innova RPC methods through the local innovad CLI or through ssh to a
remote innovad CLI, so RPC ports do not need to be exposed.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import html
import json
import math
import os
import platform
import random
import shlex
import statistics
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_OUTPUT_DIR = "testnet_metrics"
DEFAULT_SEED_DATADIR = "/root/.innova"
DEFAULT_SEED_RPC_PORT = 15531
DEFAULT_TRAFFIC_DATADIR = "/root/.innova-traffic"
DEFAULT_TRAFFIC_RPC_PORT = 15631
DEFAULT_TRAFFIC_P2P_PORT = 15639
DEFAULT_TRAFFIC_RPC_USER = "innova_traffic"
DEFAULT_TRAFFIC_RPC_PASSWORD = "change_this_traffic_rpc_password"
DEFAULT_TESTNET_PEERS = [
    "45.32.161.27:15539",
    "45.77.164.87:15539",
    "144.202.37.36:15539",
    "45.32.168.101:15539",
    "45.77.118.217:15539",
]
DEFAULT_TESTNET_SEED_IPS = tuple(peer.split(":", 1)[0] for peer in DEFAULT_TESTNET_PEERS)
DEFAULT_TESTNET_SEED_NODES = tuple(
    ("seed%s" % (idx + 1), "root@%s" % peer.split(":", 1)[0])
    for idx, peer in enumerate(DEFAULT_TESTNET_PEERS)
)

BLOCK_COLUMNS = [
    "collected_at",
    "node",
    "height",
    "hash",
    "time",
    "interval_seconds",
    "size_bytes",
    "tx_count",
    "flags",
    "block_type",
    "difficulty",
    "adaptive_block_limit",
    "utilization_pct",
]

SNAPSHOT_COLUMNS = [
    "timestamp",
    "node",
    "height",
    "hash",
    "mempool_count",
    "connections",
    "peer_count_rpc",
    "banned_count",
    "seed_ip_bans",
    "initialblockdownload",
    "mining_cpumining",
    "mining_threads",
    "mining_pooledtx",
    "mining_errors",
    "staking_enabled",
    "staking",
    "staking_weight",
    "staking_netstakeweight",
    "dag_active",
    "dag_tips",
    "dag_entries",
    "dag_inferred_k",
    "dag_ordering_algorithm",
    "dag_adaptive_block_limit",
    "finality_epoch",
    "finalized_height",
    "finalized_hash",
    "finality_tier",
    "finality_votes",
    "finality_voters",
    "shielded_active",
    "dsp_active",
    "shielded_pool_value",
    "commitment_tree_size",
    "shielded_balance",
    "nullsend_active",
    "nullsend_sessions",
    "nullsend_queue_size",
    "warnings",
]

TRAFFIC_COLUMNS = [
    "timestamp",
    "run_id",
    "stage",
    "submitted_tx_count",
    "failed_tx_count",
    "submitted_bytes_estimate",
    "target_utilization",
    "observed_utilization",
    "throttle_reason",
    "details",
]


class RpcError(RuntimeError):
    pass


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso_utc(value: str) -> float:
    if not value:
        return 0.0
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return _dt.datetime.fromisoformat(value).timestamp()
    except ValueError:
        return 0.0


def to_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def to_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return float(int(value))
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def boolish(value: Any) -> Optional[bool]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return None


def seed_ip_bans(banned: Any) -> List[str]:
    if not isinstance(banned, list):
        return []
    result: List[str] = []
    for entry in banned:
        if not isinstance(entry, dict):
            continue
        address = str(entry.get("address", ""))
        ip = address.split("/", 1)[0].split(":", 1)[0]
        if ip in DEFAULT_TESTNET_SEED_IPS and ip not in result:
            result.append(ip)
    return result


def csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


def field(obj: Any, key: str, default: Any = "") -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return default


def nested(obj: Any, *keys: str, default: Any = "") -> Any:
    cur = obj
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def parse_rpc_output(text: str) -> Any:
    text = text.strip()
    if text == "":
        return ""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    low = text.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    try:
        if any(ch in text for ch in ".eE"):
            return float(text)
        return int(text)
    except ValueError:
        return text


def format_rpc_arg(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def split_ssh_options(values: Optional[Sequence[str]]) -> List[str]:
    opts: List[str] = []
    for item in values or []:
        opts.extend(shlex.split(item))
    return opts


def default_innovad_for_backend(backend: str) -> str:
    repo_binary = Path.cwd() / "src" / "innovad"
    if backend == "local" and repo_binary.exists():
        return str(repo_binary)
    return "/usr/local/bin/innovad"


class RpcClient:
    def __init__(
        self,
        backend: str = "local",
        innovad: Optional[str] = None,
        datadir: Optional[str] = None,
        conf: Optional[str] = None,
        rpcuser: Optional[str] = None,
        rpcpassword: Optional[str] = None,
        rpcport: Optional[int] = None,
        testnet: Optional[bool] = None,
        ssh_target: Optional[str] = None,
        ssh_options: Optional[Sequence[str]] = None,
        timeout: int = 30,
    ) -> None:
        if backend not in ("local", "ssh"):
            raise ValueError("backend must be local or ssh")
        if backend == "ssh" and not ssh_target:
            raise ValueError("--ssh is required when --backend ssh is used")
        self.backend = backend
        self.innovad = innovad or default_innovad_for_backend(backend)
        self.datadir = datadir
        self.conf = conf
        self.rpcuser = rpcuser
        self.rpcpassword = rpcpassword
        self.rpcport = rpcport
        self.testnet = testnet
        self.ssh_target = ssh_target
        self.ssh_options = split_ssh_options(ssh_options)
        self.timeout = timeout

    def describe(self) -> str:
        if self.backend == "ssh":
            return "ssh:%s:%s" % (self.ssh_target, self.datadir or self.conf or self.innovad)
        return "local:%s" % (self.datadir or self.conf or self.innovad)

    def with_timeout(self, timeout: int) -> "RpcClient":
        return RpcClient(
            backend=self.backend,
            innovad=self.innovad,
            datadir=self.datadir,
            conf=self.conf,
            rpcuser=self.rpcuser,
            rpcpassword=self.rpcpassword,
            rpcport=self.rpcport,
            testnet=self.testnet,
            ssh_target=self.ssh_target,
            ssh_options=self.ssh_options,
            timeout=max(1, int(timeout)),
        )

    def _argv(self, method: str, args: Sequence[Any]) -> List[str]:
        argv = [self.innovad]
        if self.conf:
            argv.append("-conf=%s" % self.conf)
        if self.datadir:
            argv.append("-datadir=%s" % self.datadir)
        if self.rpcuser:
            argv.append("-rpcuser=%s" % self.rpcuser)
        if self.rpcpassword:
            argv.append("-rpcpassword=%s" % self.rpcpassword)
        if self.rpcport:
            argv.append("-rpcport=%s" % self.rpcport)
        if self.testnet is True:
            argv.append("-testnet")
        argv.append(method)
        argv.extend(format_rpc_arg(arg) for arg in args)
        return argv

    def call(self, method: str, *args: Any, optional: bool = False) -> Any:
        argv = self._argv(method, args)
        try:
            if self.backend == "local":
                proc = subprocess.run(
                    argv,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout,
                )
            else:
                remote_argv = " ".join(shlex.quote(part) for part in argv)
                remote_command = "timeout %s %s" % (shlex.quote(str(max(1, int(self.timeout)))), remote_argv)
                proc = subprocess.run(
                    ["ssh"] + self.ssh_options + [self.ssh_target or "", remote_command],
                    text=True,
                    capture_output=True,
                    timeout=max(1, int(self.timeout)) + 5,
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            if optional:
                return None
            raise RpcError("%s failed before RPC returned: %s" % (method, exc)) from exc

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        if proc.returncode != 0:
            message = stderr or stdout or "exit status %s" % proc.returncode
            if optional:
                return None
            raise RpcError("%s RPC failed: %s" % (method, message))
        if stdout.lower().startswith("error:"):
            if optional:
                return None
            raise RpcError("%s RPC failed: %s" % (method, stdout))
        return parse_rpc_output(stdout)


def client_from_args(args: argparse.Namespace, traffic_defaults: bool = False) -> RpcClient:
    datadir = args.datadir
    rpcport = args.rpcport
    rpcuser = args.rpcuser
    rpcpassword = args.rpcpassword
    testnet = args.testnet
    if traffic_defaults:
        datadir = datadir or DEFAULT_TRAFFIC_DATADIR
        rpcport = rpcport or DEFAULT_TRAFFIC_RPC_PORT
        rpcuser = rpcuser or None
        rpcpassword = rpcpassword or None
        if testnet is None:
            testnet = True
    return RpcClient(
        backend=args.backend,
        innovad=args.innovad,
        datadir=datadir,
        conf=args.conf,
        rpcuser=rpcuser,
        rpcpassword=rpcpassword,
        rpcport=rpcport,
        testnet=testnet,
        ssh_target=args.ssh,
        ssh_options=args.ssh_option,
        timeout=args.rpc_timeout,
    )


def funding_client_from_args(args: argparse.Namespace) -> RpcClient:
    testnet = args.funding_testnet
    if testnet is None:
        testnet = True
    return RpcClient(
        backend=args.funding_backend,
        innovad=args.funding_innovad,
        datadir=args.funding_datadir,
        conf=args.funding_conf,
        rpcuser=args.funding_rpcuser,
        rpcpassword=args.funding_rpcpassword,
        rpcport=args.funding_rpcport,
        testnet=testnet,
        ssh_target=args.funding_ssh,
        ssh_options=args.funding_ssh_option,
        timeout=args.rpc_timeout,
    )


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def ensure_csv(path: Path, columns: Sequence[str]) -> None:
    if path.exists() and path.stat().st_size > 0:
        return
    ensure_dir(path.parent)
    with path.open("w", newline="") as fh:
        csv.DictWriter(fh, fieldnames=list(columns)).writeheader()


def write_json_file(path: Path, obj: Any) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")


def append_csv_rows(path: Path, columns: Sequence[str], rows: Iterable[Dict[str, Any]]) -> int:
    rows = list(rows)
    if not rows:
        return 0
    ensure_csv(path, columns)
    with path.open("a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(columns), extrasaction="ignore")
        for row in rows:
            writer.writerow({col: csv_value(row.get(col, "")) for col in columns})
    return len(rows)


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def existing_block_hashes(path: Path) -> set:
    return {row.get("hash", "") for row in read_csv_rows(path) if row.get("hash")}


def append_block_rows(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    seen = existing_block_hashes(path)
    filtered: List[Dict[str, Any]] = []
    for row in rows:
        block_hash = str(row.get("hash", ""))
        if block_hash and block_hash in seen:
            continue
        filtered.append(row)
        seen.add(block_hash)
    return append_csv_rows(path, BLOCK_COLUMNS, filtered)


def block_type_from_flags(flags: Any) -> str:
    text = str(flags or "").lower()
    if "proof-of-stake" in text:
        return "PoS"
    if "proof-of-work" in text:
        return "PoW"
    return ""


def optional_rpc(client: RpcClient, method: str, *args: Any) -> Any:
    try:
        return client.call(method, *args)
    except RpcError as exc:
        return {"_error": str(exc)}


def error_text(*objects: Any) -> str:
    errors = []
    for obj in objects:
        if isinstance(obj, dict) and obj.get("_error"):
            errors.append(str(obj["_error"]))
    return "; ".join(errors)


def get_height_from_info(info: Any) -> int:
    height = to_int(field(info, "blocks"))
    if height is None:
        raise RpcError("getinfo did not include a numeric blocks field")
    return height


def get_block_time(client: RpcClient, height: int) -> Optional[int]:
    if height < 0:
        return None
    block_hash = client.call("getblockhash", height)
    block = client.call("getblock", block_hash)
    return to_int(field(block, "time"))


def collect_sample(
    client: RpcClient,
    node_name: str,
    blocks: int,
    collected_at: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    collected_at = collected_at or utc_now()
    info = client.call("getinfo")
    if not isinstance(info, dict):
        raise RpcError("getinfo returned %r, expected object" % (info,))

    height = get_height_from_info(info)
    best_hash = client.call("getblockhash", height)
    mempool = optional_rpc(client, "getrawmempool")
    peerinfo = optional_rpc(client, "getpeerinfo")
    banned = optional_rpc(client, "listbanned")
    mining = optional_rpc(client, "getmininginfo")
    staking = optional_rpc(client, "getstakinginfo")
    dag = optional_rpc(client, "getdaginfo")
    finality = optional_rpc(client, "getfinalityinfo")
    shielded = optional_rpc(client, "z_getshieldedinfo")
    nullsend = optional_rpc(client, "z_nullsendinfo")

    adaptive_limit = to_int(field(dag, "adaptive_block_limit"))
    start_height = max(0, height - max(1, blocks) + 1)
    previous_time = get_block_time(client, start_height - 1) if start_height > 0 else None

    block_rows: List[Dict[str, Any]] = []
    for block_height in range(start_height, height + 1):
        block_hash = client.call("getblockhash", block_height)
        block = client.call("getblock", block_hash)
        if not isinstance(block, dict):
            continue

        block_time = to_int(field(block, "time"))
        size_bytes = to_int(field(block, "size"))
        tx_list = field(block, "tx", [])
        tx_count = len(tx_list) if isinstance(tx_list, list) else to_int(field(block, "tx_count"), 0)
        interval = ""
        if block_time is not None and previous_time is not None:
            interval = block_time - previous_time
        previous_time = block_time
        utilization = ""
        if size_bytes is not None and adaptive_limit:
            utilization = round(100.0 * size_bytes / adaptive_limit, 3)
        flags = field(block, "flags")

        block_rows.append(
            {
                "collected_at": collected_at,
                "node": node_name,
                "height": field(block, "height", block_height),
                "hash": field(block, "hash", block_hash),
                "time": block_time,
                "interval_seconds": interval,
                "size_bytes": size_bytes,
                "tx_count": tx_count,
                "flags": flags,
                "block_type": block_type_from_flags(flags),
                "difficulty": field(block, "difficulty"),
                "adaptive_block_limit": adaptive_limit,
                "utilization_pct": utilization,
            }
        )

    mempool_count = len(mempool) if isinstance(mempool, list) else field(mining, "pooledtx", "")
    staking_weight = field(staking, "weight", "")
    if staking_weight == "":
        staking_weight = nested(mining, "stakeweight", "combined", default="")

    warnings = "; ".join(
        part
        for part in [
            field(info, "errors", ""),
            field(mining, "errors", ""),
            field(staking, "errors", ""),
            error_text(mempool, peerinfo, banned, mining, staking, dag, finality, shielded, nullsend),
        ]
        if part
    )

    snapshot = {
        "timestamp": collected_at,
        "node": node_name,
        "height": height,
        "hash": best_hash,
        "mempool_count": mempool_count,
        "connections": field(info, "connections"),
        "peer_count_rpc": len(peerinfo) if isinstance(peerinfo, list) else "",
        "banned_count": len(banned) if isinstance(banned, list) else "",
        "seed_ip_bans": seed_ip_bans(banned),
        "initialblockdownload": field(info, "initialblockdownload"),
        "mining_cpumining": field(mining, "cpumining"),
        "mining_threads": field(mining, "cputhreads"),
        "mining_pooledtx": field(mining, "pooledtx"),
        "mining_errors": field(mining, "errors"),
        "staking_enabled": field(staking, "enabled"),
        "staking": field(staking, "staking"),
        "staking_weight": staking_weight,
        "staking_netstakeweight": field(staking, "netstakeweight", field(mining, "netstakeweight", "")),
        "dag_active": field(dag, "dag_active"),
        "dag_tips": field(dag, "dag_tips"),
        "dag_entries": field(dag, "dag_entries"),
        "dag_inferred_k": field(dag, "inferred_k"),
        "dag_ordering_algorithm": field(dag, "ordering_algorithm"),
        "dag_adaptive_block_limit": adaptive_limit,
        "finality_epoch": field(finality, "epoch"),
        "finalized_height": field(finality, "finalized_height"),
        "finalized_hash": field(finality, "finalized_hash"),
        "finality_tier": field(finality, "finality_tier"),
        "finality_votes": field(finality, "current_epoch_votes"),
        "finality_voters": field(finality, "current_epoch_voters"),
        "shielded_active": field(shielded, "shielded_active"),
        "dsp_active": field(shielded, "dsp_active"),
        "shielded_pool_value": field(shielded, "shielded_pool_value"),
        "commitment_tree_size": field(shielded, "commitment_tree_size"),
        "shielded_balance": field(shielded, "shielded_balance"),
        "nullsend_active": field(nullsend, "nullsend_active"),
        "nullsend_sessions": field(nullsend, "active_sessions"),
        "nullsend_queue_size": field(nullsend, "queue_size"),
        "warnings": warnings,
    }
    return block_rows, snapshot


def cmd_collect(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir)
    ensure_dir(out_dir)
    blocks_path = out_dir / "blocks.csv"
    snapshots_path = out_dir / "snapshots.csv"

    if args.reset:
        for path in (blocks_path, snapshots_path):
            if path.exists():
                path.unlink()

    client = client_from_args(args)
    total_blocks = 0
    total_snapshots = 0
    for sample_idx in range(args.samples):
        block_rows, snapshot = collect_sample(client, args.node, args.blocks)
        total_blocks += append_block_rows(blocks_path, block_rows)
        total_snapshots += append_csv_rows(snapshots_path, SNAPSHOT_COLUMNS, [snapshot])
        print(
            "sample %s/%s: height=%s mempool=%s new_blocks=%s"
            % (
                sample_idx + 1,
                args.samples,
                snapshot.get("height", ""),
                snapshot.get("mempool_count", ""),
                len(block_rows),
            )
        )
        if sample_idx + 1 < args.samples:
            time.sleep(args.interval)

    print("wrote %s block rows and %s snapshot rows to %s" % (total_blocks, total_snapshots, out_dir))
    return 0


def numeric_series(rows: Sequence[Dict[str, str]], key: str) -> List[Optional[float]]:
    return [to_float(row.get(key), None) for row in rows]


def labels_for_rows(rows: Sequence[Dict[str, str]], preferred: str) -> List[str]:
    labels: List[str] = []
    for idx, row in enumerate(rows):
        label = row.get(preferred) or row.get("height") or row.get("timestamp") or str(idx)
        labels.append(str(label))
    return labels


def compact_number(value: Any) -> str:
    num = to_float(value)
    if num is None:
        return ""
    if abs(num) >= 1_000_000:
        return "%.2fm" % (num / 1_000_000.0)
    if abs(num) >= 1_000:
        return "%.1fk" % (num / 1_000.0)
    if abs(num - int(num)) < 0.00001:
        return str(int(num))
    return "%.3f" % num


def svg_line_chart(
    title: str,
    labels: Sequence[str],
    series: Sequence[Tuple[str, Sequence[Optional[float]], str]],
    width: int = 920,
    height: int = 260,
) -> str:
    values = [v for _, vals, _ in series for v in vals if v is not None and math.isfinite(v)]
    if not values:
        return '<section class="chart"><h2>%s</h2><p class="empty">No data.</p></section>' % html.escape(title)

    pad_left = 56
    pad_right = 18
    pad_top = 22
    pad_bottom = 34
    chart_w = width - pad_left - pad_right
    chart_h = height - pad_top - pad_bottom
    min_y = min(values)
    max_y = max(values)
    if max_y == min_y:
        max_y += 1.0
        min_y -= 1.0
    y_pad = (max_y - min_y) * 0.08
    min_y -= y_pad
    max_y += y_pad

    count = max(1, max(len(vals) for _, vals, _ in series))

    def x_for(index: int) -> float:
        if count == 1:
            return pad_left + chart_w / 2
        return pad_left + chart_w * index / (count - 1)

    def y_for(value: float) -> float:
        return pad_top + chart_h * (1.0 - (value - min_y) / (max_y - min_y))

    grid = []
    for step in range(5):
        y = pad_top + chart_h * step / 4
        value = max_y - (max_y - min_y) * step / 4
        grid.append(
            '<line x1="%s" y1="%.2f" x2="%s" y2="%.2f" class="grid"/>'
            '<text x="8" y="%.2f" class="axis">%s</text>'
            % (pad_left, y, width - pad_right, y, y + 4, html.escape(compact_number(value)))
        )

    polylines = []
    legend = []
    for name, vals, color in series:
        points = []
        for idx, value in enumerate(vals):
            if value is None or not math.isfinite(value):
                continue
            points.append("%.2f,%.2f" % (x_for(idx), y_for(value)))
        if points:
            polylines.append(
                '<polyline points="%s" fill="none" stroke="%s" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/>'
                % (" ".join(points), color)
            )
        legend.append(
            '<span><i style="background:%s"></i>%s</span>' % (html.escape(color), html.escape(name))
        )

    x_labels = []
    if labels:
        for idx in sorted(set([0, len(labels) // 2, len(labels) - 1])):
            if idx < 0 or idx >= len(labels):
                continue
            anchor = "middle"
            if idx == 0:
                anchor = "start"
            elif idx == len(labels) - 1:
                anchor = "end"
            x_labels.append(
                '<text x="%.2f" y="%s" text-anchor="%s" class="axis">%s</text>'
                % (x_for(idx), height - 8, anchor, html.escape(labels[idx])[:32])
            )

    svg = (
        '<svg viewBox="0 0 %s %s" role="img" aria-label="%s">'
        '<rect x="0" y="0" width="%s" height="%s" class="plot-bg"/>'
        '%s%s%s'
        '<line x1="%s" y1="%s" x2="%s" y2="%s" class="axis-line"/>'
        "</svg>"
    ) % (
        width,
        height,
        html.escape(title),
        width,
        height,
        "".join(grid),
        "".join(polylines),
        "".join(x_labels),
        pad_left,
        height - pad_bottom,
        width - pad_right,
        height - pad_bottom,
    )
    return '<section class="chart"><h2>%s</h2>%s<div class="legend">%s</div></section>' % (
        html.escape(title),
        svg,
        "".join(legend),
    )


def svg_bar_chart(
    title: str,
    labels: Sequence[str],
    values: Sequence[Optional[float]],
    color: str = "#355f8a",
    width: int = 920,
    height: int = 230,
) -> str:
    nums = [v for v in values if v is not None and math.isfinite(v)]
    if not nums:
        return '<section class="chart"><h2>%s</h2><p class="empty">No data.</p></section>' % html.escape(title)
    pad_left = 48
    pad_right = 16
    pad_top = 18
    pad_bottom = 30
    chart_w = width - pad_left - pad_right
    chart_h = height - pad_top - pad_bottom
    max_y = max(nums) or 1.0
    bar_count = len(values)
    bar_w = max(2.0, chart_w / max(1, bar_count) * 0.72)
    bars = []
    for idx, value in enumerate(values):
        if value is None or not math.isfinite(value):
            continue
        x = pad_left + chart_w * idx / max(1, bar_count) + (chart_w / max(1, bar_count) - bar_w) / 2
        h = chart_h * value / max_y
        y = pad_top + chart_h - h
        bars.append('<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="%s"/>' % (x, y, bar_w, h, color))
    x_labels = []
    if labels:
        for idx in sorted(set([0, len(labels) // 2, len(labels) - 1])):
            x = pad_left + chart_w * idx / max(1, len(labels) - 1)
            anchor = "middle"
            if idx == 0:
                anchor = "start"
            elif idx == len(labels) - 1:
                anchor = "end"
            x_labels.append(
                '<text x="%.2f" y="%s" text-anchor="%s" class="axis">%s</text>'
                % (x, height - 8, anchor, html.escape(labels[idx])[:32])
            )
    svg = (
        '<svg viewBox="0 0 %s %s" role="img" aria-label="%s">'
        '<rect x="0" y="0" width="%s" height="%s" class="plot-bg"/>'
        '<line x1="%s" y1="%s" x2="%s" y2="%s" class="axis-line"/>'
        '<text x="8" y="26" class="axis">%s</text>'
        '%s%s</svg>'
    ) % (
        width,
        height,
        html.escape(title),
        width,
        height,
        pad_left,
        height - pad_bottom,
        width - pad_right,
        height - pad_bottom,
        html.escape(compact_number(max_y)),
        "".join(bars),
        "".join(x_labels),
    )
    return '<section class="chart"><h2>%s</h2>%s</section>' % (html.escape(title), svg)


def table_html(title: str, row: Dict[str, Any], keys: Sequence[str]) -> str:
    if not row:
        return '<section class="panel"><h2>%s</h2><p class="empty">No data.</p></section>' % html.escape(title)
    trs = []
    for key in keys:
        trs.append(
            "<tr><th>%s</th><td>%s</td></tr>"
            % (html.escape(key.replace("_", " ")), html.escape(str(row.get(key, ""))))
        )
    return '<section class="panel"><h2>%s</h2><table>%s</table></section>' % (
        html.escape(title),
        "".join(trs),
    )


def latest_row(rows: Sequence[Dict[str, str]], time_key: str = "timestamp") -> Dict[str, str]:
    if not rows:
        return {}
    return max(rows, key=lambda row: parse_iso_utc(row.get(time_key, "")))


def traffic_submission_rates(rows: Sequence[Dict[str, str]]) -> List[Optional[float]]:
    rates: List[Optional[float]] = []
    previous_ts: Optional[float] = None
    for row in rows:
        submitted = to_float(row.get("submitted_tx_count"), 0.0) or 0.0
        ts = parse_iso_utc(row.get("timestamp", ""))
        if previous_ts is None or ts <= previous_ts:
            rates.append(submitted)
        else:
            rates.append(submitted / max(1.0, ts - previous_ts))
        previous_ts = ts if ts > 0 else previous_ts
    return rates


def render_report(input_dir: Path, output: Path) -> None:
    blocks = read_csv_rows(input_dir / "blocks.csv")
    snapshots = read_csv_rows(input_dir / "snapshots.csv")
    traffic = read_csv_rows(input_dir / "traffic_runs.csv")

    blocks.sort(key=lambda row: to_int(row.get("height"), -1) or -1)
    snapshots.sort(key=lambda row: parse_iso_utc(row.get("timestamp", "")))
    traffic.sort(key=lambda row: parse_iso_utc(row.get("timestamp", "")))

    block_labels = labels_for_rows(blocks, "height")
    snap_labels = [row.get("timestamp", "").replace("T", " ").replace("Z", "")[-8:] for row in snapshots]
    traffic_labels = [row.get("timestamp", "").replace("T", " ").replace("Z", "")[-8:] for row in traffic]

    pow_count = sum(1 for row in blocks if row.get("block_type") == "PoW")
    pos_count = sum(1 for row in blocks if row.get("block_type") == "PoS")

    latest_snapshot = latest_row(snapshots)
    latest_traffic = latest_row(traffic)
    traffic_rates = traffic_submission_rates(traffic)

    cards = [
        ("Blocks", len(blocks)),
        ("Snapshots", len(snapshots)),
        ("Latest height", latest_snapshot.get("height", "")),
        ("Mempool", latest_snapshot.get("mempool_count", "")),
        ("Peers", latest_snapshot.get("peer_count_rpc") or latest_snapshot.get("connections", "")),
        ("Bans", latest_snapshot.get("banned_count", "")),
        ("DAG tips", latest_snapshot.get("dag_tips", "")),
        ("Shielded pool", latest_snapshot.get("shielded_pool_value", "")),
    ]

    card_html = "".join(
        '<div class="metric"><span>%s</span><strong>%s</strong></div>'
        % (html.escape(name), html.escape(str(value)))
        for name, value in cards
    )

    charts = [
        svg_line_chart(
            "Block Interval Over Time",
            block_labels,
            [("interval seconds", numeric_series(blocks, "interval_seconds"), "#355f8a")],
        ),
        svg_line_chart(
            "Block Size And Utilization",
            block_labels,
            [
                ("size bytes", numeric_series(blocks, "size_bytes"), "#315f72"),
                ("utilization percent", numeric_series(blocks, "utilization_pct"), "#b05d2b"),
            ],
        ),
        svg_bar_chart("Transaction Count Per Block", block_labels, numeric_series(blocks, "tx_count"), "#5f6f52"),
        svg_bar_chart("PoW Vs PoS Block Mix", ["PoW", "PoS"], [float(pow_count), float(pos_count)], "#355f8a"),
        svg_line_chart(
            "DAG Tips, Entries, Inferred K",
            snap_labels,
            [
                ("tips", numeric_series(snapshots, "dag_tips"), "#355f8a"),
                ("entries", numeric_series(snapshots, "dag_entries"), "#5f6f52"),
                ("inferred k", numeric_series(snapshots, "dag_inferred_k"), "#b05d2b"),
            ],
        ),
        svg_line_chart(
            "Staking Weight And Mining Status",
            snap_labels,
            [
                ("staking weight", numeric_series(snapshots, "staking_weight"), "#315f72"),
                ("staking on", [float(boolish(row.get("staking")) or False) for row in snapshots], "#5f6f52"),
                ("cpu mining on", [float(boolish(row.get("mining_cpumining")) or False) for row in snapshots], "#b05d2b"),
            ],
        ),
        svg_line_chart(
            "Mempool Count",
            snap_labels,
            [
                ("mempool tx", numeric_series(snapshots, "mempool_count"), "#355f8a"),
            ],
        ),
        svg_line_chart(
            "Peer And Ban Counts",
            snap_labels,
            [
                ("peers", numeric_series(snapshots, "peer_count_rpc"), "#315f72"),
                ("bans", numeric_series(snapshots, "banned_count"), "#b05d2b"),
            ],
        ),
        svg_line_chart(
            "Traffic Submission Rate",
            traffic_labels,
            [
                ("submitted tx/s", traffic_rates, "#b05d2b"),
            ],
        ),
        svg_line_chart(
            "Shielded, DSP, NullSend State",
            snap_labels,
            [
                ("shielded active", [float(boolish(row.get("shielded_active")) or False) for row in snapshots], "#315f72"),
                ("dsp active", [float(boolish(row.get("dsp_active")) or False) for row in snapshots], "#5f6f52"),
                ("nullsend active", [float(boolish(row.get("nullsend_active")) or False) for row in snapshots], "#b05d2b"),
                ("nullsend sessions", numeric_series(snapshots, "nullsend_sessions"), "#6b4e71"),
            ],
        ),
    ]

    css = """
    :root { color-scheme: light; --ink:#1f2528; --muted:#667078; --line:#d8dee2; --bg:#f5f7f8; --panel:#ffffff; }
    body { margin:0; font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; color:var(--ink); background:var(--bg); }
    header { padding:28px 32px 16px; border-bottom:1px solid var(--line); background:#fff; }
    h1 { margin:0 0 6px; font-size:28px; letter-spacing:0; }
    h2 { margin:0 0 12px; font-size:16px; letter-spacing:0; }
    main { max-width:1180px; margin:0 auto; padding:24px 24px 48px; }
    .metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:18px; }
    .metric, .chart, .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; box-shadow:0 1px 2px rgba(0,0,0,.03); }
    .metric { padding:14px 16px; }
    .metric span { display:block; color:var(--muted); font-size:12px; text-transform:uppercase; }
    .metric strong { display:block; margin-top:4px; font-size:24px; font-weight:650; }
    .grid { stroke:#e6ebee; stroke-width:1; }
    .axis, .empty { fill:var(--muted); color:var(--muted); font-size:12px; }
    .axis-line { stroke:#9aa4aa; stroke-width:1; }
    .plot-bg { fill:#fff; }
    .chart { padding:16px; margin:14px 0; overflow:hidden; }
    .chart svg { width:100%; height:auto; display:block; }
    .legend { display:flex; flex-wrap:wrap; gap:14px; color:var(--muted); font-size:12px; margin-top:8px; }
    .legend i { display:inline-block; width:10px; height:10px; margin-right:6px; border-radius:2px; vertical-align:-1px; }
    .panel { padding:16px; margin:14px 0; }
    table { width:100%; border-collapse:collapse; }
    th, td { text-align:left; border-top:1px solid var(--line); padding:7px 6px; vertical-align:top; }
    th { width:240px; color:var(--muted); font-weight:550; }
    .two { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
    @media (max-width: 760px) { .two { grid-template-columns:1fr; } header { padding:22px 20px 12px; } main { padding:18px 14px 36px; } }
    """

    generated = utc_now()
    body = """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Innova Testnet Metrics</title>
      <style>%s</style>
    </head>
    <body>
      <header>
        <h1>Innova Testnet Metrics</h1>
        <div class="empty">Generated %s from %s</div>
      </header>
      <main>
        <section class="metrics">%s</section>
        %s
        <section class="two">
          %s
          %s
        </section>
      </main>
    </body>
    </html>
    """ % (
        css,
        html.escape(generated),
        html.escape(str(input_dir)),
        card_html,
        "\n".join(charts),
        table_html(
            "Latest Snapshot",
            latest_snapshot,
            [
                "timestamp",
                "node",
                "height",
                "hash",
                "mempool_count",
                "connections",
                "peer_count_rpc",
                "banned_count",
                "seed_ip_bans",
                "dag_adaptive_block_limit",
                "finality_tier",
                "shielded_active",
                "dsp_active",
                "nullsend_sessions",
                "warnings",
            ],
        ),
        table_html(
            "Latest Traffic Run",
            latest_traffic,
            [
                "timestamp",
                "run_id",
                "stage",
                "submitted_tx_count",
                "failed_tx_count",
                "target_utilization",
                "observed_utilization",
                "throttle_reason",
                "details",
            ],
        ),
    )

    ensure_dir(output.parent)
    output.write_text(body, encoding="utf-8")


def cmd_report(args: argparse.Namespace) -> int:
    input_dir = Path(args.input_dir)
    output = Path(args.output or (input_dir / "report.html"))
    render_report(input_dir, output)
    print("wrote %s" % output)
    return 0


def parse_seed_node(value: str, index: int) -> Tuple[str, str]:
    if "=" in value:
        label, target = value.split("=", 1)
        label = label.strip()
        target = target.strip()
    else:
        label = "seed%s" % (index + 1)
        target = value.strip()
    if not label or not target:
        raise ValueError("seed entries must be label=ssh-target or ssh-target")
    return label, target


def seed_nodes_from_args(args: argparse.Namespace) -> List[Tuple[str, str]]:
    values = getattr(args, "seed", None)
    if not values:
        return list(DEFAULT_TESTNET_SEED_NODES)
    return [parse_seed_node(value, idx) for idx, value in enumerate(values)]


def ssh_capture_text(
    target: str,
    argv: Sequence[str],
    ssh_options: Optional[Sequence[str]],
    timeout: int,
    optional: bool = False,
) -> str:
    remote_argv = " ".join(shlex.quote(part) for part in argv)
    remote_command = "timeout %s %s" % (shlex.quote(str(max(1, int(timeout)))), remote_argv)
    try:
        proc = subprocess.run(
            ["ssh"] + split_ssh_options(ssh_options) + [target, remote_command],
            text=True,
            capture_output=True,
            timeout=max(1, int(timeout)) + 5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        if optional:
            return "ERROR: %s" % exc
        raise
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "exit status %s" % proc.returncode
        if optional:
            return "ERROR: %s" % message
        raise RuntimeError("%s failed on %s: %s" % (" ".join(argv), target, message))
    return proc.stdout


def process_uses_datadir(command: str, datadir: str) -> bool:
    try:
        parts = shlex.split(command)
    except ValueError:
        return ("-datadir=%s" % datadir) in command or ("-datadir %s" % datadir) in command
    for idx, part in enumerate(parts):
        if part == "-datadir" and idx + 1 < len(parts) and parts[idx + 1] == datadir:
            return True
        if part == "-datadir=%s" % datadir:
            return True
    return False


def parse_process_inventory(text: str, datadir: str) -> Dict[str, Any]:
    processes: List[Dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or "innovad" not in stripped:
            continue
        parts = stripped.split(None, 2)
        if len(parts) < 3:
            continue
        if not process_uses_datadir(parts[2], datadir):
            continue
        age = to_int(parts[0], -1)
        pid = to_int(parts[1], -1)
        processes.append({"etimes": age, "pid": pid, "command": parts[2]})
    ages = [proc["etimes"] for proc in processes if isinstance(proc.get("etimes"), int) and proc["etimes"] >= 0]
    return {
        "process_count": len(processes),
        "min_age_seconds": min(ages) if ages else "",
        "processes": processes,
    }


def seed_client(
    target: str,
    args: argparse.Namespace,
    datadir: Optional[str] = None,
    rpcport: Optional[int] = None,
) -> RpcClient:
    return RpcClient(
        backend="ssh",
        innovad=getattr(args, "seed_innovad", None) or "/usr/local/bin/innovad",
        datadir=datadir or getattr(args, "seed_datadir", None) or DEFAULT_SEED_DATADIR,
        rpcport=rpcport or getattr(args, "seed_rpcport", None) or DEFAULT_SEED_RPC_PORT,
        testnet=True,
        ssh_target=target,
        ssh_options=getattr(args, "ssh_option", None),
        timeout=getattr(args, "rpc_timeout", 30),
    )


def audit_one_node(
    label: str,
    target: str,
    args: argparse.Namespace,
    datadir: Optional[str] = None,
    rpcport: Optional[int] = None,
    traffic: bool = False,
) -> Dict[str, Any]:
    datadir = datadir or (DEFAULT_TRAFFIC_DATADIR if traffic else getattr(args, "seed_datadir", None) or DEFAULT_SEED_DATADIR)
    rpcport = rpcport or (DEFAULT_TRAFFIC_RPC_PORT if traffic else getattr(args, "seed_rpcport", None) or DEFAULT_SEED_RPC_PORT)
    client = seed_client(target, args, datadir=datadir, rpcport=rpcport)
    entry: Dict[str, Any] = {
        "label": label,
        "target": target,
        "datadir": datadir,
        "rpcport": rpcport,
        "traffic": traffic,
        "timestamp": utc_now(),
    }
    try:
        info = client.call("getinfo")
        if not isinstance(info, dict):
            raise RpcError("getinfo returned %r, expected object" % (info,))
        height = get_height_from_info(info)
        best_hash = client.call("getblockhash", height)
        optional_timeout = getattr(args, "optional_rpc_timeout", getattr(args, "rpc_timeout", 30))
        optional_client = client.with_timeout(optional_timeout)
        peerinfo = optional_rpc(optional_client, "getpeerinfo")
        banned = optional_rpc(optional_client, "listbanned")
        mining = optional_rpc(optional_client, "getmininginfo")
        staking = optional_rpc(optional_client, "getstakinginfo")
        dag = optional_rpc(optional_client, "getdaginfo")
        finality = optional_rpc(optional_client, "getfinalityinfo")
        mempool = optional_rpc(optional_client, "getrawmempool")
        process_text = ssh_capture_text(
            target,
            ["ps", "-eo", "etimes=,pid=,args="],
            getattr(args, "ssh_option", None),
            optional_timeout,
            optional=True,
        )
        process_inventory = parse_process_inventory(process_text, datadir)
        peer_count = len(peerinfo) if isinstance(peerinfo, list) else to_int(info.get("connections"), -1)
        banned_count = len(banned) if isinstance(banned, list) else -1
        warnings = "; ".join(
            part
            for part in [
                field(info, "errors", ""),
                field(mining, "errors", ""),
                field(staking, "errors", ""),
                error_text(peerinfo, banned, mining, staking, dag, finality, mempool),
            ]
            if part
        )
        entry.update(
            {
                "ok": True,
                "info": info,
                "height": height,
                "hash": best_hash,
                "connections": field(info, "connections"),
                "peer_count": peer_count,
                "initialblockdownload": field(info, "initialblockdownload"),
                "banned_count": banned_count,
                "seed_ip_bans": seed_ip_bans(banned),
                "mempool_count": len(mempool) if isinstance(mempool, list) else "",
                "mining": mining,
                "cpumining": field(mining, "cpumining"),
                "staking": staking,
                "dag": dag,
                "finality": finality,
                "warnings": warnings,
                "process_inventory": process_inventory,
            }
        )
    except Exception as exc:
        entry.update({"ok": False, "error": str(exc)})
    return entry


def common_hashes_for_audit(nodes: Sequence[Dict[str, Any]], args: argparse.Namespace) -> Dict[str, str]:
    good = [node for node in nodes if node.get("ok") and to_int(node.get("height"), -1) is not None and to_int(node.get("height"), -1) >= 0]
    if not good:
        return {}
    common_height = min(to_int(node.get("height"), -1) or -1 for node in good)
    hashes: Dict[str, str] = {}
    for node in good:
        try:
            client = seed_client(
                str(node.get("target")),
                args,
                datadir=str(node.get("datadir") or DEFAULT_SEED_DATADIR),
                rpcport=to_int(node.get("rpcport"), DEFAULT_SEED_RPC_PORT),
            ).with_timeout(getattr(args, "optional_rpc_timeout", getattr(args, "rpc_timeout", 30)))
            hashes[str(node.get("label"))] = str(client.call("getblockhash", common_height))
        except Exception as exc:
            hashes[str(node.get("label"))] = "ERROR: %s" % exc
    return hashes


def summarize_seed_audit(seed_nodes: Sequence[Dict[str, Any]], args: argparse.Namespace) -> Dict[str, Any]:
    expected_labels = [label for label, _ in seed_nodes_from_args(args)]
    good = [node for node in seed_nodes if node.get("ok")]
    heights = {str(node.get("label")): to_int(node.get("height"), -1) for node in seed_nodes}
    max_height = max((to_int(node.get("height"), -1) or -1 for node in good), default=-1)
    common_height = min((to_int(node.get("height"), -1) or -1 for node in good), default=-1)
    common_hashes = common_hashes_for_audit(seed_nodes, args)
    hash_values = [value for value in common_hashes.values() if not value.startswith("ERROR:")]
    hashes_match = bool(hash_values) and len(hash_values) == len(good) and len(set(hash_values)) == 1
    peer_counts = {
        str(node.get("label")): to_int(node.get("peer_count"), -1)
        for node in seed_nodes
    }
    warnings = {
        str(node.get("label")): str(node.get("warnings"))
        for node in seed_nodes
        if str(node.get("warnings") or "")
    }
    seed_bans = {
        str(node.get("label")): node.get("seed_ip_bans")
        for node in seed_nodes
        if isinstance(node.get("seed_ip_bans"), list) and node.get("seed_ip_bans")
    }
    process_issues = {}
    for node in seed_nodes:
        inventory = node.get("process_inventory") if isinstance(node.get("process_inventory"), dict) else {}
        count = to_int(inventory.get("process_count"), 0) or 0
        min_age = to_int(inventory.get("min_age_seconds"), -1)
        if count < 1:
            process_issues[str(node.get("label"))] = "no matching innovad process"
        elif count > 1:
            process_issues[str(node.get("label"))] = "%s matching innovad processes" % count
        elif min_age is not None and min_age >= 0 and min_age < args.min_process_age:
            process_issues[str(node.get("label"))] = "matching process age %ss < %ss" % (min_age, args.min_process_age)
    seed4 = next((node for node in seed_nodes if node.get("label") == "seed4"), {})
    checks = {
        "all_seed_rpc_ok": len(good) == len(expected_labels),
        "no_stale_restart_loop_signal": not process_issues,
        "no_seed_ip_bans": not seed_bans,
        "no_ibd": not any(boolish(node.get("initialblockdownload")) for node in seed_nodes),
        "common_seed_hash": hashes_match,
        "height_spread_zero": max_height >= 0 and common_height >= 0 and max_height - common_height == 0,
        "min_seed_peers_ok": min((to_int(node.get("peer_count"), -1) or -1 for node in seed_nodes), default=-1) >= args.min_seed_peers,
        "seed4_cpumining_false": boolish(seed4.get("cpumining")) is False,
        "no_warnings": not warnings,
    }
    return {
        "timestamp": utc_now(),
        "height_spread": max_height - common_height if max_height >= 0 and common_height >= 0 else "",
        "max_height": max_height,
        "common_height": common_height,
        "common_hashes": common_hashes,
        "hashes_match_common_height": hashes_match,
        "peer_counts": peer_counts,
        "min_peers": min((to_int(node.get("peer_count"), -1) or -1 for node in seed_nodes), default=-1),
        "warnings": warnings,
        "seed_ip_bans": seed_bans,
        "process_issues": process_issues,
        "checks": checks,
        "passed": all(bool(value) for value in checks.values()),
        "failed_checks": [key for key, value in checks.items() if not bool(value)],
        "nodes": seed_nodes,
    }


def summarize_traffic_audit(traffic_node: Dict[str, Any], args: argparse.Namespace) -> Dict[str, Any]:
    checks = {
        "traffic_rpc_ok": bool(traffic_node.get("ok")),
        "traffic_no_ibd": boolish(traffic_node.get("initialblockdownload")) is False,
        "traffic_min_peers_ok": (to_int(traffic_node.get("peer_count"), -1) or -1) >= args.min_traffic_peers,
        "traffic_no_warnings": not str(traffic_node.get("warnings") or ""),
    }
    return {
        "timestamp": utc_now(),
        "checks": checks,
        "passed": all(bool(value) for value in checks.values()),
        "failed_checks": [key for key, value in checks.items() if not bool(value)],
        "node": traffic_node,
    }


def cmd_seed_audit(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir)
    ensure_dir(out_dir)
    seed_nodes = [audit_one_node(label, target, args) for label, target in seed_nodes_from_args(args)]
    seed_summary = summarize_seed_audit(seed_nodes, args)
    audit: Dict[str, Any] = {
        "timestamp": utc_now(),
        "seed_summary": seed_summary,
    }
    if args.include_traffic:
        traffic_node = audit_one_node(
            args.traffic_label,
            args.traffic_ssh,
            args,
            datadir=args.traffic_datadir,
            rpcport=args.traffic_rpcport,
            traffic=True,
        )
        audit["traffic_summary"] = summarize_traffic_audit(traffic_node, args)
    else:
        audit["traffic_summary"] = None

    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = Path(args.output or (out_dir / ("seed_audit_%s.json" % stamp)))
    write_json_file(output, audit)

    print(
        "seed audit: passed=%s height=%s spread=%s min_peers=%s failed=%s"
        % (
            seed_summary.get("passed"),
            seed_summary.get("common_height"),
            seed_summary.get("height_spread"),
            seed_summary.get("min_peers"),
            ",".join(seed_summary.get("failed_checks", [])) or "-",
        )
    )
    if audit.get("traffic_summary"):
        traffic = audit["traffic_summary"]
        node = traffic.get("node", {})
        print(
            "traffic audit: passed=%s height=%s peers=%s mempool=%s failed=%s"
            % (
                traffic.get("passed"),
                node.get("height"),
                node.get("peer_count"),
                node.get("mempool_count"),
                ",".join(traffic.get("failed_checks", [])) or "-",
            )
        )
    print("wrote %s" % output)
    return 0 if seed_summary.get("passed") and (not audit.get("traffic_summary") or audit["traffic_summary"].get("passed")) else 2


def verbose_raw_transaction(client: RpcClient, txid: str) -> Any:
    tx = optional_rpc(client, "getrawtransaction", txid, 1)
    if isinstance(tx, dict) and not tx.get("_error"):
        return tx
    raw = optional_rpc(client, "getrawtransaction", txid)
    if isinstance(raw, str) and raw and not raw.startswith("ERROR"):
        decoded = optional_rpc(client, "decoderawtransaction", raw)
        if isinstance(decoded, dict) and not decoded.get("_error"):
            decoded["_raw_length"] = len(raw)
            return decoded
    wallet_tx = optional_rpc(client, "gettransaction", txid)
    if isinstance(wallet_tx, dict) and not wallet_tx.get("_error"):
        wallet_tx["_source"] = "gettransaction"
        return wallet_tx
    return tx if tx is not None else raw


def classify_mempool_tx(tx: Any) -> Dict[str, Any]:
    if not isinstance(tx, dict):
        return {"classification": "unknown", "error": tx}
    vout = tx.get("vout", [])
    vin = tx.get("vin", [])
    output_value = 0.0
    output_types: Dict[str, int] = {}
    if isinstance(vout, list):
        for out in vout:
            if not isinstance(out, dict):
                continue
            output_value += to_float(out.get("value"), 0.0) or 0.0
            script = out.get("scriptPubKey") if isinstance(out.get("scriptPubKey"), dict) else {}
            out_type = str(script.get("type", "unknown"))
            output_types[out_type] = output_types.get(out_type, 0) + 1
    has_coinbase = any(isinstance(item, dict) and item.get("coinbase") for item in vin) if isinstance(vin, list) else False
    classification = "transparent"
    if output_types.get("nulldata"):
        classification = "data-carrying"
    if has_coinbase:
        classification = "coinbase-like"
    return {
        "classification": classification,
        "vin_count": len(vin) if isinstance(vin, list) else "",
        "vout_count": len(vout) if isinstance(vout, list) else "",
        "output_value": round(output_value, 8),
        "output_types": output_types,
        "size": tx.get("size") or tx.get("_raw_length") or "",
        "confirmations": tx.get("confirmations", ""),
    }


def cmd_mempool_inspect(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir)
    ensure_dir(out_dir)
    node_specs = list(seed_nodes_from_args(args))
    clients: Dict[str, RpcClient] = {
        label: seed_client(target, args)
        for label, target in node_specs
    }
    targets: Dict[str, str] = {label: target for label, target in node_specs}
    if args.include_traffic:
        clients[args.traffic_label] = seed_client(
            args.traffic_ssh,
            args,
            datadir=args.traffic_datadir,
            rpcport=args.traffic_rpcport,
        )
        targets[args.traffic_label] = args.traffic_ssh

    node_mempools: Dict[str, Any] = {}
    tx_locations: Dict[str, List[str]] = {}
    for label, client in clients.items():
        mempool_client = client.with_timeout(getattr(args, "optional_rpc_timeout", getattr(args, "rpc_timeout", 30)))
        mempool = optional_rpc(mempool_client, "getrawmempool")
        node_mempools[label] = mempool
        if isinstance(mempool, list):
            for txid in mempool:
                tx_locations.setdefault(str(txid), []).append(label)

    detail_clients = {
        label: client.with_timeout(getattr(args, "tx_detail_timeout", 5))
        for label, client in clients.items()
    }
    txs: Dict[str, Any] = {}
    for txid, labels in tx_locations.items():
        tx_obj: Any = None
        for label in labels:
            tx_obj = verbose_raw_transaction(detail_clients[label], txid)
            if isinstance(tx_obj, dict) and not tx_obj.get("_error"):
                break
        txs[txid] = {
            "seen_on": labels,
            "seen_count": len(labels),
            "details": classify_mempool_tx(tx_obj),
            "raw": tx_obj if args.include_raw else "",
        }

    aggregate_count = sum(len(mempool) for mempool in node_mempools.values() if isinstance(mempool, list))
    result = {
        "timestamp": utc_now(),
        "nodes": targets,
        "node_mempool_counts": {
            label: len(mempool) if isinstance(mempool, list) else -1
            for label, mempool in node_mempools.items()
        },
        "aggregate_count": aggregate_count,
        "unique_count": len(tx_locations),
        "txs": txs,
    }
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = Path(args.output or (out_dir / ("mempool_inspect_%s.json" % stamp)))
    write_json_file(output, result)
    print(
        "mempool inspect: aggregate=%s unique=%s counts=%s"
        % (aggregate_count, len(tx_locations), json.dumps(result["node_mempool_counts"], sort_keys=True))
    )
    for txid, tx in txs.items():
        details = tx.get("details", {})
        print(
            "  %s seen_on=%s class=%s vin=%s vout=%s"
            % (
                txid,
                ",".join(tx.get("seen_on", [])),
                details.get("classification", ""),
                details.get("vin_count", ""),
                details.get("vout_count", ""),
            )
        )
    print("wrote %s" % output)
    return 0


def recent_block_utilization(client: RpcClient, count: int = 8) -> Dict[str, Any]:
    info = client.call("getinfo")
    height = get_height_from_info(info)
    dag = optional_rpc(client, "getdaginfo")
    adaptive_limit = to_int(field(dag, "adaptive_block_limit"))
    rows = []
    for block_height in range(max(0, height - count + 1), height + 1):
        block_hash = client.call("getblockhash", block_height)
        block = client.call("getblock", block_hash)
        size_bytes = to_int(field(block, "size"))
        util = None
        if size_bytes is not None and adaptive_limit:
            util = size_bytes / float(adaptive_limit)
        rows.append({"height": block_height, "size": size_bytes, "utilization": util})
    utils = [row["utilization"] for row in rows if row["utilization"] is not None]
    return {
        "height": height,
        "adaptive_block_limit": adaptive_limit,
        "latest_utilization": utils[-1] if utils else None,
        "average_utilization": statistics.mean(utils) if utils else None,
        "blocks": rows,
    }


def traffic_run_path(output_dir: str) -> Path:
    return Path(output_dir) / "traffic_runs.csv"


def append_traffic_row(output_dir: str, row: Dict[str, Any]) -> None:
    append_csv_rows(traffic_run_path(output_dir), TRAFFIC_COLUMNS, [row])


def require_live_ack(args: argparse.Namespace, action: str) -> None:
    if getattr(args, "dry_run", False):
        return
    if not getattr(args, "yes_live_traffic", False):
        raise SystemExit(
            "Refusing to %s without --yes-live-traffic. Use --dry-run to preview commands." % action
        )


def local_or_remote_write_text(client: RpcClient, path: str, text: str) -> None:
    if client.backend == "local":
        target = Path(path)
        ensure_dir(target.parent)
        target.write_text(text, encoding="utf-8")
        return
    remote = "cat > %s" % shlex.quote(path)
    proc = subprocess.run(
        ["ssh"] + client.ssh_options + [client.ssh_target or "", remote],
        input=text,
        text=True,
        capture_output=True,
        timeout=client.timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "remote write failed")


def local_or_remote_mkdir(client: RpcClient, path: str) -> None:
    if client.backend == "local":
        ensure_dir(Path(path))
        return
    remote = "mkdir -p %s" % shlex.quote(path)
    proc = subprocess.run(
        ["ssh"] + client.ssh_options + [client.ssh_target or "", remote],
        text=True,
        capture_output=True,
        timeout=client.timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "remote mkdir failed")


def traffic_config_text(args: argparse.Namespace) -> str:
    peers = args.peer or DEFAULT_TESTNET_PEERS
    rpcuser = args.rpcuser or DEFAULT_TRAFFIC_RPC_USER
    rpcpassword = args.rpcpassword or DEFAULT_TRAFFIC_RPC_PASSWORD
    rpcport = args.rpcport or DEFAULT_TRAFFIC_RPC_PORT
    p2p_port = args.p2p_port or DEFAULT_TRAFFIC_P2P_PORT
    lines = [
        "testnet=1",
        "server=1",
        "daemon=1",
        "listen=1",
        "txindex=1",
        "staking=0",
        "dnsseed=0",
        "listenonion=0",
        "dandelion=%s" % (1 if getattr(args, "enable_dandelion", False) else 0),
        "rpcuser=%s" % rpcuser,
        "rpcpassword=%s" % rpcpassword,
        "rpcport=%s" % rpcport,
        "port=%s" % p2p_port,
        "debug=1",
        "printtoconsole=0",
    ]
    lines.extend("addnode=%s" % peer for peer in peers)
    return "\n".join(lines) + "\n"


def start_traffic_daemon(client: RpcClient, args: argparse.Namespace) -> None:
    datadir = args.datadir or DEFAULT_TRAFFIC_DATADIR
    argv = [client.innovad, "-datadir=%s" % datadir, "-testnet", "-daemon"]
    if client.backend == "local":
        subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    remote_command = "nohup %s >/tmp/innova-traffic-daemon.log 2>&1 &" % " ".join(
        shlex.quote(part) for part in argv
    )
    proc = subprocess.run(
        ["ssh"] + client.ssh_options + [client.ssh_target or "", remote_command],
        text=True,
        capture_output=True,
        timeout=client.timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "remote daemon start failed")


def wait_for_rpc(client: RpcClient, timeout_seconds: int = 120) -> Dict[str, Any]:
    deadline = time.time() + timeout_seconds
    last_error = ""
    while time.time() < deadline:
        try:
            info = client.call("getinfo")
            if isinstance(info, dict):
                return info
        except RpcError as exc:
            last_error = str(exc)
        time.sleep(3)
    raise RpcError("RPC did not become ready within %ss: %s" % (timeout_seconds, last_error))


def wait_for_node_ready(client: RpcClient, timeout_seconds: int, min_peers: int) -> Dict[str, Any]:
    deadline = time.time() + timeout_seconds
    last_info: Dict[str, Any] = {}
    while time.time() < deadline:
        info = client.call("getinfo")
        if isinstance(info, dict):
            last_info = info
            ibd = boolish(info.get("initialblockdownload"))
            peers = to_int(info.get("connections"), 0) or 0
            if ibd is not True and peers >= min_peers:
                return info
        time.sleep(5)
    raise RpcError(
        "node did not become ready within %ss; last height=%s peers=%s ibd=%s"
        % (
            timeout_seconds,
            last_info.get("blocks", ""),
            last_info.get("connections", ""),
            last_info.get("initialblockdownload", ""),
        )
    )


def confirmed_balance(client: RpcClient, min_conf: int) -> Tuple[int, float]:
    unspent = client.call("listunspent", min_conf, 9999999)
    if not isinstance(unspent, list):
        return 0, 0.0
    total = 0.0
    for utxo in unspent:
        if isinstance(utxo, dict):
            total += to_float(utxo.get("amount"), 0.0) or 0.0
    return len(unspent), total


def wait_for_confirmed_balance(
    client: RpcClient,
    min_conf: int,
    min_amount: float,
    timeout_seconds: int,
) -> Tuple[int, float]:
    deadline = time.time() + timeout_seconds
    last = (0, 0.0)
    while time.time() < deadline:
        last = confirmed_balance(client, min_conf)
        if last[1] >= min_amount:
            return last
        time.sleep(10)
    raise RpcError(
        "timed out waiting for %.6f confirmed INN at minconf=%s; last balance %.6f in %s UTXOs"
        % (min_amount, min_conf, last[1], last[0])
    )


def funding_args_configured(args: argparse.Namespace) -> bool:
    return bool(args.funding_datadir or args.funding_conf or args.funding_rpcport or args.funding_ssh)


def cmd_traffic_prepare(args: argparse.Namespace) -> int:
    require_live_ack(args, "prepare live traffic wallet")
    traffic_client = client_from_args(args, traffic_defaults=True)
    datadir = args.datadir or DEFAULT_TRAFFIC_DATADIR
    config = traffic_config_text(args)

    if args.dry_run:
        print("traffic backend: %s" % traffic_client.describe())
        print("traffic datadir: %s" % datadir)
        print("traffic config preview:\n%s" % config.rstrip())
        if not args.no_fund:
            print("would request a traffic funding address and fund %.6f INN" % args.funding_amount)
        if not args.no_split:
            print(
                "would split into %s UTXOs of %.6f INN using batches of %s"
                % (args.split_count, args.split_amount, args.split_batch_size)
            )
        return 0

    if not args.no_config:
        local_or_remote_mkdir(traffic_client, datadir)
        local_or_remote_write_text(traffic_client, os.path.join(datadir, "innova.conf"), config)
        print("wrote traffic node config to %s" % os.path.join(datadir, "innova.conf"))

    if not args.no_start:
        start_traffic_daemon(traffic_client, args)
        print("started traffic daemon")

    info = wait_for_rpc(traffic_client, args.rpc_ready_timeout)
    print("traffic node RPC ready at height %s with %s connection(s)" % (info.get("blocks"), info.get("connections")))
    if args.sync_timeout > 0:
        info = wait_for_node_ready(traffic_client, args.sync_timeout, args.min_peers)
        print(
            "traffic node ready at height %s with %s peer(s)"
            % (info.get("blocks"), info.get("connections"))
        )

    funding_txid = ""
    if not args.no_fund:
        if not funding_args_configured(args):
            raise SystemExit(
                "Funding is enabled, but no funding node was configured. "
                "Provide --funding-datadir/--funding-conf/--funding-rpcport or use --no-fund."
            )
        funding_client = funding_client_from_args(args)
        fund_addr = traffic_client.call("getnewaddress")
        funding_txid = funding_client.call("sendtoaddress", fund_addr, args.funding_amount)
        print("funding tx submitted: %s -> %s INN" % (funding_txid, args.funding_amount))
        wait_for_confirmed_balance(
            traffic_client,
            args.wait_confirmations,
            min(args.funding_amount * 0.5, args.split_count * args.split_amount * 0.5),
            args.confirmation_timeout,
        )

    split_txids: List[str] = []
    if not args.no_split and args.split_count > 0:
        needed = args.split_count * args.split_amount
        utxo_count, balance = confirmed_balance(traffic_client, args.wait_confirmations)
        if balance < needed:
            raise SystemExit(
                "Traffic wallet has %.6f confirmed INN, but split needs %.6f INN" % (balance, needed)
            )
        remaining = args.split_count
        while remaining > 0:
            batch_size = min(args.split_batch_size, remaining)
            outputs: Dict[str, float] = {}
            for _ in range(batch_size):
                addr = traffic_client.call("getnewaddress")
                outputs[str(addr)] = args.split_amount
            txid = traffic_client.call("sendmany", "", outputs, args.wait_confirmations, "traffic split")
            split_txids.append(str(txid))
            remaining -= batch_size
            print("split batch submitted: %s outputs txid=%s" % (batch_size, txid))
            time.sleep(args.split_pause)
        if args.wait_after_split:
            wait_for_confirmed_balance(
                traffic_client,
                args.wait_confirmations,
                needed * 0.5,
                args.confirmation_timeout,
            )

    final_utxos, final_balance = confirmed_balance(traffic_client, 0)
    print(
        "traffic prepare complete: balance=%.6f INN utxos=%s funding_txid=%s split_batches=%s"
        % (final_balance, final_utxos, funding_txid, len(split_txids))
    )
    return 0


def summarize_last_traffic(output_dir: str) -> Dict[str, str]:
    rows = read_csv_rows(traffic_run_path(output_dir))
    return latest_row(rows)


def cmd_traffic_status(args: argparse.Namespace) -> int:
    client = client_from_args(args, traffic_defaults=True)
    status: Dict[str, Any] = {
        "node": client.describe(),
        "timestamp": utc_now(),
    }
    info = client.call("getinfo")
    status["height"] = field(info, "blocks")
    status["connections"] = field(info, "connections")
    status["initialblockdownload"] = field(info, "initialblockdownload")
    status["balance"] = optional_rpc(client, "getbalance")
    zero_conf_utxos, zero_conf_balance = confirmed_balance(client, 0)
    one_conf_utxos, one_conf_balance = confirmed_balance(client, 1)
    status["utxos_0conf"] = zero_conf_utxos
    status["balance_0conf"] = zero_conf_balance
    status["utxos_1conf"] = one_conf_utxos
    status["balance_1conf"] = one_conf_balance
    mempool = optional_rpc(client, "getrawmempool")
    status["mempool_count"] = len(mempool) if isinstance(mempool, list) else ""
    status["recent_utilization"] = recent_block_utilization(client, args.recent_blocks)
    status["shielded"] = optional_rpc(client, "z_getshieldedinfo")
    status["nullsend"] = optional_rpc(client, "z_nullsendinfo")
    status["peers"] = optional_rpc(client, "getpeerinfo")
    status["last_traffic_run"] = summarize_last_traffic(args.output_dir)

    if args.json:
        print(json.dumps(status, indent=2, sort_keys=True))
        return 0

    recent = status["recent_utilization"]
    print("traffic node: %s" % status["node"])
    print("height: %s  peers: %s  ibd: %s" % (status["height"], status["connections"], status["initialblockdownload"]))
    print("wallet balance: %s  confirmed: %.6f INN in %s UTXOs" % (status["balance"], one_conf_balance, one_conf_utxos))
    print("mempool: %s tx" % status["mempool_count"])
    print(
        "recent utilization: latest=%s avg=%s adaptive_limit=%s"
        % (
            compact_number((recent.get("latest_utilization") or 0.0) * 100.0) + "%",
            compact_number((recent.get("average_utilization") or 0.0) * 100.0) + "%",
            recent.get("adaptive_block_limit"),
        )
    )
    if status["last_traffic_run"]:
        print("last traffic run: %s" % json.dumps(status["last_traffic_run"], sort_keys=True))
    return 0


def peer_divergence_reason(client: RpcClient, local_height: int, max_delta: int, min_peers: int) -> str:
    peers = optional_rpc(client, "getpeerinfo")
    if not isinstance(peers, list):
        return ""
    if len(peers) < min_peers:
        return "peer_count_below_%s" % min_peers
    heights: List[int] = []
    for peer in peers:
        if not isinstance(peer, dict):
            continue
        height = to_int(peer.get("bestknownheight"))
        age = to_int(peer.get("heightage"))
        if height is not None and height > 0 and (age is None or age < 0 or age <= 120):
            heights.append(height)

    # Legacy chainheight is a version-handshake hint and can be stale for the
    # whole connection. Do not use it for strict spread checks; otherwise a
    # controlled one-block PoW pulse can look like a peer divergence while the
    # local node is still processing the newly announced block.
    heights = [height for height in heights if height is not None and height > 0]
    if heights:
        if max(abs(local_height - height) for height in heights) > max_delta:
            return "peer_height_divergence"
    return ""


def safety_throttle_reason(
    client: RpcClient,
    max_mempool: int,
    min_peers: int,
    max_peer_height_delta: int,
) -> Tuple[str, Dict[str, Any]]:
    info = client.call("getinfo")
    height = get_height_from_info(info)
    if boolish(field(info, "initialblockdownload")):
        return "initial_block_download", {"info": info}
    warning = str(field(info, "errors", "") or "")
    if warning:
        return "node_warning", {"info": info}
    mempool = optional_rpc(client, "getrawmempool")
    mempool_count = len(mempool) if isinstance(mempool, list) else 0
    if mempool_count > max_mempool:
        return "mempool_limit", {"info": info, "mempool_count": mempool_count}
    peer_reason = peer_divergence_reason(client, height, max_peer_height_delta, min_peers)
    if peer_reason:
        return peer_reason, {"info": info, "mempool_count": mempool_count}
    return "", {"info": info, "mempool_count": mempool_count}


def estimate_sendmany_bytes(outputs: int) -> int:
    return 180 + outputs * 34 + 12


def make_sendmany_outputs(client: RpcClient, outputs: int, amount: float, jitter: float) -> Dict[str, float]:
    result: Dict[str, float] = {}
    for _ in range(outputs):
        addr = str(client.call("getnewaddress"))
        multiplier = 1.0
        if jitter > 0:
            multiplier = random.uniform(max(0.1, 1.0 - jitter), 1.0 + jitter)
        result[addr] = round(amount * multiplier, 6)
    return result


def submit_transparent_batch(client: RpcClient, outputs: int, amount: float, jitter: float) -> Tuple[bool, str, int]:
    send_to = make_sendmany_outputs(client, outputs, amount, jitter)
    estimate = estimate_sendmany_bytes(outputs)
    txid = client.call("sendmany", "", send_to, 1, "traffic run")
    return True, str(txid), estimate


def seed_mempool_visibility(args: argparse.Namespace, txids: Sequence[str]) -> Dict[str, Any]:
    wanted = [str(txid) for txid in txids if str(txid)]
    wanted_set = set(wanted)
    locations: Dict[str, List[str]] = {txid: [] for txid in wanted}
    node_counts: Dict[str, int] = {}
    errors: Dict[str, str] = {}
    optional_timeout = getattr(args, "optional_rpc_timeout", getattr(args, "rpc_timeout", 30))
    for label, target in seed_nodes_from_args(args):
        client = seed_client(target, args).with_timeout(optional_timeout)
        mempool = optional_rpc(client, "getrawmempool")
        if not isinstance(mempool, list):
            node_counts[label] = -1
            errors[label] = field(mempool, "_error", str(mempool))
            continue
        node_counts[label] = len(mempool)
        seen_here = wanted_set.intersection(str(txid) for txid in mempool)
        for txid in seen_here:
            locations.setdefault(txid, []).append(label)
    return {
        "timestamp": utc_now(),
        "locations": {txid: sorted(labels) for txid, labels in locations.items()},
        "seen_counts": {txid: len(locations.get(txid, [])) for txid in wanted},
        "node_mempool_counts": node_counts,
        "errors": errors,
    }


def poll_seed_visibility(
    args: argparse.Namespace,
    txids: Sequence[str],
    min_seen: int,
    timeout_seconds: int,
    interval_seconds: float,
) -> Tuple[bool, Dict[str, Any]]:
    if min_seen <= 0 or not txids:
        return True, seed_mempool_visibility(args, txids)
    deadline = time.time() + max(1, int(timeout_seconds))
    last = seed_mempool_visibility(args, txids)
    while True:
        below = [
            txid for txid in txids
            if int(last.get("seen_counts", {}).get(str(txid), 0)) < min_seen
        ]
        if not below:
            return True, last
        if time.time() >= deadline:
            return False, last
        time.sleep(max(0.25, float(interval_seconds)))
        last = seed_mempool_visibility(args, txids)


def cmd_traffic_recover(args: argparse.Namespace) -> int:
    require_live_ack(args, "recover live traffic relay")
    ensure_dir(Path(args.output_dir))
    client = client_from_args(args, traffic_defaults=True)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if args.dry_run:
        print(
            "would call resendtx and poll seed mempools for %ss, min seed visibility %s"
            % (args.retry_window, args.min_seed_visibility)
        )
        print("traffic backend: %s" % client.describe())
        return 0

    before = client.call("getrawmempool")
    if not isinstance(before, list):
        raise SystemExit("Traffic getrawmempool returned %r, expected list" % (before,))
    before_txids = [str(txid) for txid in before]
    resend_result = client.call("resendtx")

    deadline = time.time() + max(1, int(args.retry_window))
    visibility: Dict[str, Any] = {"seen_counts": {}, "locations": {}}
    local_txids = before_txids
    while True:
        local_mempool = optional_rpc(client.with_timeout(getattr(args, "optional_rpc_timeout", args.rpc_timeout)), "getrawmempool")
        if isinstance(local_mempool, list):
            local_txids = [str(txid) for txid in local_mempool]
        visibility = seed_mempool_visibility(args, local_txids)
        below_min = [
            txid for txid in local_txids
            if int(visibility.get("seen_counts", {}).get(txid, 0)) < args.min_seed_visibility
        ]
        if not below_min or time.time() >= deadline:
            break
        time.sleep(max(0.25, float(args.poll_interval)))

    seen_counts = visibility.get("seen_counts", {})
    local_only = [txid for txid in local_txids if int(seen_counts.get(txid, 0)) == 0]
    below_min = [txid for txid in local_txids if int(seen_counts.get(txid, 0)) < args.min_seed_visibility]
    result = {
        "timestamp": utc_now(),
        "traffic_backend": client.describe(),
        "initial_local_mempool_count": len(before_txids),
        "final_local_mempool_count": len(local_txids),
        "resendtx_result": resend_result,
        "min_seed_visibility": args.min_seed_visibility,
        "retry_window": args.retry_window,
        "visibility": visibility,
        "local_only_txids": local_only,
        "below_min_visibility_txids": below_min,
        "passed": not below_min,
    }
    output = Path(args.output or (Path(args.output_dir) / ("traffic_recovery_%s.json" % stamp)))
    write_json_file(output, result)
    print(
        "traffic recovery: passed=%s local=%s local_only=%s below_min=%s wrote=%s"
        % (result["passed"], len(local_txids), len(local_only), len(below_min), output)
    )
    return 0 if result["passed"] else 2


def run_privacy_probes(client: RpcClient, args: argparse.Namespace, run_id: str) -> None:
    zinfo = optional_rpc(client, "z_getshieldedinfo")
    if not isinstance(zinfo, dict) or not boolish(field(zinfo, "shielded_active")):
        append_traffic_row(
            args.output_dir,
            {
                "timestamp": utc_now(),
                "run_id": run_id,
                "stage": "privacy",
                "submitted_tx_count": 0,
                "failed_tx_count": 0,
                "submitted_bytes_estimate": 0,
                "target_utilization": "",
                "observed_utilization": "",
                "throttle_reason": "shielded_not_ready",
                "details": "privacy probes skipped",
            },
        )
        return

    submitted = 0
    failed = 0
    details: List[str] = []
    try:
        zaddr1 = str(client.call("z_getnewaddress"))
        zaddr2 = str(client.call("z_getnewaddress"))
        txid = client.call("z_shield", "*", args.privacy_amount, zaddr1)
        submitted += 1
        details.append("z_shield=%s" % txid)
    except RpcError as exc:
        failed += 1
        details.append("z_shield_failed=%s" % exc)
        zaddr1 = ""
        zaddr2 = ""

    zinfo_after = optional_rpc(client, "z_getshieldedinfo")
    shielded_balance = to_float(field(zinfo_after, "shielded_balance"), 0.0) or 0.0
    dsp_ready = boolish(field(zinfo_after, "dsp_active"))
    if zaddr1 and zaddr2 and dsp_ready and shielded_balance >= args.privacy_amount:
        for mode in range(8):
            try:
                txid = client.call("z_send", zaddr1, zaddr2, args.privacy_amount, mode)
                submitted += 1
                details.append("z_send_mode_%s=%s" % (mode, txid))
                time.sleep(args.privacy_pause)
            except RpcError as exc:
                failed += 1
                details.append("z_send_mode_%s_failed=%s" % (mode, exc))
    else:
        details.append("z_send_skipped=dsp_or_confirmed_balance_not_ready")

    append_traffic_row(
        args.output_dir,
        {
            "timestamp": utc_now(),
            "run_id": run_id,
            "stage": "privacy",
            "submitted_tx_count": submitted,
            "failed_tx_count": failed,
            "submitted_bytes_estimate": "",
            "target_utilization": "",
            "observed_utilization": "",
            "throttle_reason": "",
            "details": "; ".join(details)[:4000],
        },
    )


def run_silent_probe(client: RpcClient, args: argparse.Namespace, run_id: str) -> None:
    submitted = 0
    failed = 0
    details: List[str] = []
    try:
        address = str(client.call("sp_getnewaddress"))
        result = client.call("sp_send", address, args.silent_amount)
        submitted = 1
        details.append("sp_send=%s" % result)
    except RpcError as exc:
        failed = 1
        details.append("sp_probe_failed=%s" % exc)
    append_traffic_row(
        args.output_dir,
        {
            "timestamp": utc_now(),
            "run_id": run_id,
            "stage": "silent-payment",
            "submitted_tx_count": submitted,
            "failed_tx_count": failed,
            "submitted_bytes_estimate": "",
            "target_utilization": "",
            "observed_utilization": "",
            "throttle_reason": "",
            "details": "; ".join(details)[:4000],
        },
    )


def run_nullsend_probe(client: RpcClient, args: argparse.Namespace, run_id: str) -> None:
    submitted = 0
    failed = 0
    details: List[str] = []
    try:
        zaddr = str(client.call("z_getnewaddress"))
        shield = client.call("z_shield", "*", args.nullsend_amount, zaddr)
        submitted += 1
        details.append("z_shield=%s" % shield)
        result = client.call("z_nullsend", zaddr, args.nullsend_amount, args.nullsend_mode, args.nullsend_pool, args.nullsend_timeout)
        submitted += 1
        details.append("z_nullsend=%s" % result)
    except RpcError as exc:
        failed += 1
        details.append("nullsend_probe_failed=%s" % exc)
    append_traffic_row(
        args.output_dir,
        {
            "timestamp": utc_now(),
            "run_id": run_id,
            "stage": "nullsend",
            "submitted_tx_count": submitted,
            "failed_tx_count": failed,
            "submitted_bytes_estimate": "",
            "target_utilization": "",
            "observed_utilization": "",
            "throttle_reason": "",
            "details": "; ".join(details)[:4000],
        },
    )


def cmd_traffic_run(args: argparse.Namespace) -> int:
    require_live_ack(args, "run live traffic")
    ensure_dir(Path(args.output_dir))
    client = client_from_args(args, traffic_defaults=True)
    run_id = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if args.dry_run:
        print(
            "would run traffic for %ss, target %.0f-%.0f%% utilization, max %s sendmany tx, seed visibility %s/%ss"
            % (
                args.duration,
                args.target_min * 100.0,
                args.target_max * 100.0,
                args.max_tx,
                args.seed_visibility_min,
                args.seed_visibility_timeout,
            )
        )
        print("traffic backend: %s" % client.describe())
        return 0

    utxos, balance = confirmed_balance(client, 1)
    if utxos < args.min_utxos:
        raise SystemExit(
            "Traffic wallet has %s confirmed UTXOs, below --min-utxos=%s. Run traffic prepare first."
            % (utxos, args.min_utxos)
        )
    if balance < args.amount * args.batch_size:
        raise SystemExit("Traffic wallet balance %.6f is too low for one batch" % balance)

    start = time.time()
    sent = 0
    failed = 0
    guard_failed = False
    attempts = 0
    last_mempool: Optional[int] = None
    growing_mempool_ticks = 0
    last_submit = 0.0

    while time.time() - start < args.duration and sent < args.max_tx:
        observed = recent_block_utilization(client, args.recent_blocks)
        observed_avg = observed.get("average_utilization")
        reason, safety = safety_throttle_reason(
            client,
            max_mempool=args.max_mempool,
            min_peers=args.min_peers,
            max_peer_height_delta=args.max_peer_height_delta,
        )

        mempool_count = to_int(safety.get("mempool_count"), 0) or 0
        if last_mempool is not None and mempool_count > last_mempool:
            growing_mempool_ticks += 1
        else:
            growing_mempool_ticks = 0
        last_mempool = mempool_count

        if not reason and growing_mempool_ticks >= args.mempool_growth_ticks:
            reason = "mempool_growing"
        if not reason and observed_avg is not None and observed_avg > args.target_max:
            reason = "utilization_above_target"

        if reason:
            append_traffic_row(
                args.output_dir,
                {
                    "timestamp": utc_now(),
                    "run_id": run_id,
                    "stage": "transparent",
                    "submitted_tx_count": 0,
                    "failed_tx_count": 0,
                    "submitted_bytes_estimate": 0,
                    "target_utilization": "%.3f-%.3f" % (args.target_min, args.target_max),
                    "observed_utilization": "" if observed_avg is None else "%.5f" % observed_avg,
                    "throttle_reason": reason,
                    "details": "mempool=%s height=%s" % (mempool_count, observed.get("height")),
                },
            )
            time.sleep(args.backoff)
            continue

        should_submit = observed_avg is None or observed_avg < args.target_min
        if not should_submit:
            append_traffic_row(
                args.output_dir,
                {
                    "timestamp": utc_now(),
                    "run_id": run_id,
                    "stage": "transparent",
                    "submitted_tx_count": 0,
                    "failed_tx_count": 0,
                    "submitted_bytes_estimate": 0,
                    "target_utilization": "%.3f-%.3f" % (args.target_min, args.target_max),
                    "observed_utilization": "%.5f" % observed_avg,
                    "throttle_reason": "within_target_pause",
                    "details": "mempool=%s height=%s" % (mempool_count, observed.get("height")),
                },
            )
            time.sleep(args.pause)
            continue

        elapsed_since_submit = time.time() - last_submit
        if elapsed_since_submit < args.min_submit_interval:
            time.sleep(args.min_submit_interval - elapsed_since_submit)

        attempts += 1
        try:
            ok, txid, estimate = submit_transparent_batch(client, args.batch_size, args.amount, args.amount_jitter)
            if ok:
                sent += 1
                last_submit = time.time()
                visible, visibility = poll_seed_visibility(
                    args,
                    [txid],
                    args.seed_visibility_min,
                    args.seed_visibility_timeout,
                    args.seed_visibility_interval,
                )
                seed_seen = int(visibility.get("seen_counts", {}).get(txid, 0))
                seen_on = ",".join(visibility.get("locations", {}).get(txid, []))
                if not visible:
                    failed += 1
                    guard_failed = True
                    append_traffic_row(
                        args.output_dir,
                        {
                            "timestamp": utc_now(),
                            "run_id": run_id,
                            "stage": "transparent",
                            "submitted_tx_count": 1,
                            "failed_tx_count": 1,
                            "submitted_bytes_estimate": estimate,
                            "target_utilization": "%.3f-%.3f" % (args.target_min, args.target_max),
                            "observed_utilization": "" if observed_avg is None else "%.5f" % observed_avg,
                            "throttle_reason": "seed_visibility_failed",
                            "details": "txid=%s seed_seen=%s seen_on=%s errors=%s"
                            % (txid, seed_seen, seen_on or "-", json.dumps(visibility.get("errors", {}), sort_keys=True)),
                        },
                    )
                    print(
                        "stopping: tx %s visible on %s seed mempools within %ss, required %s"
                        % (txid, seed_seen, args.seed_visibility_timeout, args.seed_visibility_min)
                    )
                    break
                append_traffic_row(
                    args.output_dir,
                    {
                        "timestamp": utc_now(),
                        "run_id": run_id,
                        "stage": "transparent",
                        "submitted_tx_count": 1,
                        "failed_tx_count": 0,
                        "submitted_bytes_estimate": estimate,
                        "target_utilization": "%.3f-%.3f" % (args.target_min, args.target_max),
                        "observed_utilization": "" if observed_avg is None else "%.5f" % observed_avg,
                        "throttle_reason": "",
                        "details": "txid=%s outputs=%s mempool=%s seed_seen=%s seen_on=%s"
                        % (txid, args.batch_size, mempool_count, seed_seen, seen_on or "-"),
                    },
                )
                print("submitted transparent tx %s/%s: %s seed_seen=%s" % (sent, args.max_tx, txid, seed_seen))
        except RpcError as exc:
            failed += 1
            append_traffic_row(
                args.output_dir,
                {
                    "timestamp": utc_now(),
                    "run_id": run_id,
                    "stage": "transparent",
                    "submitted_tx_count": 0,
                    "failed_tx_count": 1,
                    "submitted_bytes_estimate": 0,
                    "target_utilization": "%.3f-%.3f" % (args.target_min, args.target_max),
                    "observed_utilization": "" if observed_avg is None else "%.5f" % observed_avg,
                    "throttle_reason": "rpc_error",
                    "details": str(exc)[:4000],
                },
            )
            print("traffic submit failed: %s" % exc)
            if attempts >= 10 and failed / float(attempts) >= args.max_reject_rate:
                print("stopping after reject rate %.2f" % (failed / float(attempts)))
                break
            time.sleep(args.backoff)

    append_traffic_row(
        args.output_dir,
        {
            "timestamp": utc_now(),
            "run_id": run_id,
            "stage": "summary",
            "submitted_tx_count": sent,
            "failed_tx_count": failed,
            "submitted_bytes_estimate": "",
            "target_utilization": "%.3f-%.3f" % (args.target_min, args.target_max),
            "observed_utilization": "",
            "throttle_reason": "",
            "details": "duration=%.1fs attempts=%s" % (time.time() - start, attempts),
        },
    )

    if args.privacy_probes:
        run_privacy_probes(client, args, run_id)
    if args.silent_probe:
        run_silent_probe(client, args, run_id)
    if args.nullsend_probe:
        run_nullsend_probe(client, args, run_id)

    print("traffic run complete: submitted=%s failed=%s run_id=%s" % (sent, failed, run_id))
    return 2 if guard_failed else 0


class FakeClient:
    def call(self, method: str, *args: Any, optional: bool = False) -> Any:
        if method == "getinfo":
            return {
                "blocks": 104,
                "connections": 5,
                "initialblockdownload": False,
                "errors": "",
            }
        if method == "getblockhash":
            height = int(args[0])
            return ("%064x" % height)[-64:]
        if method == "getblock":
            height = int(str(args[0]), 16)
            flags = "proof-of-stake" if height % 3 == 0 else "proof-of-work"
            return {
                "hash": args[0],
                "height": height,
                "time": 1_700_000_000 + height * 60 + (height % 2) * 7,
                "size": 900 + height * 10,
                "tx": ["coinbase"] + ["tx%s" % idx for idx in range(height % 5)],
                "flags": flags,
                "difficulty": 1.0 + height / 1000.0,
            }
        if method == "getrawmempool":
            return ["a", "b", "c"]
        if method == "getpeerinfo":
            return [{"addr": "45.32.161.27:15539"}, {"addr": "45.77.164.87:15539"}]
        if method == "listbanned":
            return []
        if method == "getmininginfo":
            return {"cpumining": True, "cputhreads": 2, "pooledtx": 3, "errors": "", "netstakeweight": 99}
        if method == "getstakinginfo":
            return {"enabled": True, "staking": False, "weight": 12, "netstakeweight": 99}
        if method == "getdaginfo":
            return {
                "dag_active": True,
                "dag_tips": 2,
                "dag_entries": 100,
                "inferred_k": 3,
                "ordering_algorithm": "DAGKNIGHT",
                "adaptive_block_limit": 2_000_000,
            }
        if method == "getfinalityinfo":
            return {
                "epoch": 2,
                "finalized_height": 96,
                "finalized_hash": "f" * 64,
                "finality_tier": "soft",
                "current_epoch_votes": 4,
                "current_epoch_voters": 3,
            }
        if method == "z_getshieldedinfo":
            return {
                "shielded_active": True,
                "dsp_active": True,
                "shielded_pool_value": 123.45,
                "commitment_tree_size": 7,
                "shielded_balance": 1.25,
            }
        if method == "z_nullsendinfo":
            return {"nullsend_active": True, "active_sessions": 1, "queue_size": 2}
        raise RpcError("unexpected fake RPC %s" % method)


def cmd_selftest(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir or tempfile.mkdtemp(prefix="innova-testnet-tool-"))
    ensure_dir(workdir)
    parsed = parse_rpc_output('{"ok":true,"n":2}')
    assert parsed["ok"] is True and parsed["n"] == 2
    assert parse_rpc_output("0000abcd") == "0000abcd"
    inventory = parse_process_inventory(
        "100 1 /usr/local/bin/innovad -datadir=/root/.innova-traffic -testnet -daemon\n"
        "200 2 /usr/local/bin/innovad -conf=/root/.innova/innova.conf -datadir=/root/.innova -daemon\n",
        "/root/.innova",
    )
    assert inventory["process_count"] == 1
    assert inventory["processes"][0]["pid"] == 2

    fake = FakeClient()
    block_rows, snapshot = collect_sample(fake, "fixture", blocks=5, collected_at="2026-01-01T00:00:00Z")
    assert len(block_rows) == 5
    assert snapshot["mempool_count"] == 3
    assert snapshot["peer_count_rpc"] == 2
    append_block_rows(workdir / "blocks.csv", block_rows)
    append_csv_rows(workdir / "snapshots.csv", SNAPSHOT_COLUMNS, [snapshot])
    append_csv_rows(
        workdir / "traffic_runs.csv",
        TRAFFIC_COLUMNS,
        [
            {
                "timestamp": "2026-01-01T00:01:00Z",
                "run_id": "fixture",
                "stage": "transparent",
                "submitted_tx_count": 2,
                "failed_tx_count": 0,
                "submitted_bytes_estimate": 1024,
                "target_utilization": "0.500-0.800",
                "observed_utilization": "0.125",
                "throttle_reason": "",
                "details": "fixture",
            }
        ],
    )
    render_report(workdir, workdir / "report.html")
    assert (workdir / "report.html").exists()
    assert "Innova Testnet Metrics" in (workdir / "report.html").read_text(encoding="utf-8")
    print("selftest passed: %s" % workdir)
    return 0


def add_rpc_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--backend", choices=["local", "ssh"], default="local", help="RPC transport backend")
    parser.add_argument("--innovad", help="innovad binary path on the local or remote host")
    parser.add_argument("--datadir", help="Innova data directory")
    parser.add_argument("--conf", help="Innova config path")
    parser.add_argument("--rpcuser", help="RPC username override")
    parser.add_argument("--rpcpassword", help="RPC password override")
    parser.add_argument("--rpcport", type=int, help="RPC port override")
    net = parser.add_mutually_exclusive_group()
    net.add_argument("--testnet", dest="testnet", action="store_true", default=None, help="Pass -testnet to innovad CLI")
    net.add_argument("--mainnet", dest="testnet", action="store_false", help="Do not pass -testnet")
    parser.add_argument("--ssh", help="SSH target, for example root@host")
    parser.add_argument("--ssh-option", action="append", help="Extra ssh option; repeatable")
    parser.add_argument("--rpc-timeout", type=int, default=30, help="Per-RPC timeout in seconds")


def add_funding_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--funding-backend", choices=["local", "ssh"], default="local")
    parser.add_argument("--funding-innovad", help="Funding node innovad binary path")
    parser.add_argument("--funding-datadir", help="Funding node data directory")
    parser.add_argument("--funding-conf", help="Funding node config path")
    parser.add_argument("--funding-rpcuser", help="Funding node RPC username")
    parser.add_argument("--funding-rpcpassword", help="Funding node RPC password")
    parser.add_argument("--funding-rpcport", type=int, help="Funding node RPC port")
    net = parser.add_mutually_exclusive_group()
    net.add_argument("--funding-testnet", dest="funding_testnet", action="store_true", default=None)
    net.add_argument("--funding-mainnet", dest="funding_testnet", action="store_false")
    parser.add_argument("--funding-ssh", help="Funding SSH target")
    parser.add_argument("--funding-ssh-option", action="append", help="Extra funding ssh option; repeatable")


def add_live_seed_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--seed",
        action="append",
        help="Seed SSH target as label=root@host; repeatable. Defaults to the five public testnet seeds.",
    )
    parser.add_argument("--seed-innovad", default="/usr/local/bin/innovad", help="Remote seed innovad path")
    parser.add_argument("--seed-datadir", default=DEFAULT_SEED_DATADIR, help="Remote seed data directory")
    parser.add_argument("--seed-rpcport", type=int, default=DEFAULT_SEED_RPC_PORT, help="Remote seed RPC port")
    parser.add_argument("--ssh-option", action="append", help="Extra ssh option; repeatable")
    parser.add_argument("--rpc-timeout", type=int, default=30, help="Per-RPC/SSH timeout in seconds")
    parser.add_argument("--optional-rpc-timeout", type=int, default=10, help="Timeout for optional live diagnostics")


def add_seed_selection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--seed",
        action="append",
        help="Seed SSH target as label=root@host; repeatable. Defaults to the five public testnet seeds.",
    )
    parser.add_argument("--seed-innovad", default="/usr/local/bin/innovad", help="Remote seed innovad path")
    parser.add_argument("--seed-datadir", default=DEFAULT_SEED_DATADIR, help="Remote seed data directory")
    parser.add_argument("--seed-rpcport", type=int, default=DEFAULT_SEED_RPC_PORT, help="Remote seed RPC port")
    parser.add_argument("--optional-rpc-timeout", type=int, default=10, help="Timeout for optional live diagnostics")


def add_traffic_audit_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--include-traffic", action="store_true", help="Also audit the dedicated traffic wallet")
    parser.add_argument("--traffic-label", default="traffic-seed4")
    parser.add_argument("--traffic-ssh", default="root@45.32.168.101")
    parser.add_argument("--traffic-datadir", default=DEFAULT_TRAFFIC_DATADIR)
    parser.add_argument("--traffic-rpcport", type=int, default=DEFAULT_TRAFFIC_RPC_PORT)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="Collect live testnet metrics into CSV files")
    add_rpc_args(collect)
    collect.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    collect.add_argument("--node", default=platform.node() or "innova-node")
    collect.add_argument("--blocks", type=int, default=50, help="Recent blocks to collect per sample")
    collect.add_argument("--samples", type=int, default=1, help="Number of snapshot samples")
    collect.add_argument("--interval", type=float, default=30.0, help="Seconds between samples")
    collect.add_argument("--reset", action="store_true", help="Remove existing block/snapshot CSV before collecting")
    collect.set_defaults(func=cmd_collect)

    report = sub.add_parser("report", help="Render CSV files into a static HTML/SVG dashboard")
    report.add_argument("--input-dir", default=DEFAULT_OUTPUT_DIR)
    report.add_argument("--output", help="Output HTML path; defaults to <input-dir>/report.html")
    report.set_defaults(func=cmd_report)

    audit = sub.add_parser("seed-audit", help="Run read-only five-seed live safety gates")
    add_live_seed_args(audit)
    add_traffic_audit_args(audit)
    audit.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    audit.add_argument("--output", help="Output JSON path; defaults to <output-dir>/seed_audit_<timestamp>.json")
    audit.add_argument("--min-seed-peers", type=int, default=4)
    audit.add_argument("--min-traffic-peers", type=int, default=4)
    audit.add_argument("--min-process-age", type=int, default=60)
    audit.set_defaults(func=cmd_seed_audit)

    mempool = sub.add_parser("mempool-inspect", help="Read and de-duplicate mempools across seeds")
    add_live_seed_args(mempool)
    add_traffic_audit_args(mempool)
    mempool.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    mempool.add_argument("--output", help="Output JSON path; defaults to <output-dir>/mempool_inspect_<timestamp>.json")
    mempool.add_argument("--include-raw", action="store_true", help="Include decoded raw transaction objects in JSON")
    mempool.add_argument("--tx-detail-timeout", type=int, default=5, help="Per-transaction decode timeout in seconds")
    mempool.set_defaults(func=cmd_mempool_inspect)

    traffic = sub.add_parser("traffic", help="Guarded live traffic wallet operations")
    traffic_sub = traffic.add_subparsers(dest="traffic_command", required=True)

    prepare = traffic_sub.add_parser("prepare", help="Initialize, fund, and split the dedicated traffic wallet")
    add_rpc_args(prepare)
    add_funding_args(prepare)
    prepare.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    prepare.add_argument("--p2p-port", type=int, default=DEFAULT_TRAFFIC_P2P_PORT)
    prepare.add_argument("--peer", action="append", help="Testnet peer host:port; repeatable")
    prepare.add_argument("--funding-amount", type=float, default=2500.0)
    prepare.add_argument("--split-count", type=int, default=1000)
    prepare.add_argument("--split-amount", type=float, default=1.0)
    prepare.add_argument("--split-batch-size", type=int, default=50)
    prepare.add_argument("--split-pause", type=float, default=1.0)
    prepare.add_argument("--wait-confirmations", type=int, default=1)
    prepare.add_argument("--confirmation-timeout", type=int, default=7200)
    prepare.add_argument("--rpc-ready-timeout", type=int, default=180)
    prepare.add_argument("--sync-timeout", type=int, default=300)
    prepare.add_argument("--min-peers", type=int, default=1)
    prepare.add_argument("--wait-after-split", action="store_true")
    prepare.add_argument("--enable-dandelion", action="store_true", help="Enable Dandelion on the traffic wallet config")
    prepare.add_argument("--no-config", action="store_true")
    prepare.add_argument("--no-start", action="store_true")
    prepare.add_argument("--no-fund", action="store_true")
    prepare.add_argument("--no-split", action="store_true")
    prepare.add_argument("--dry-run", action="store_true")
    prepare.add_argument("--yes-live-traffic", action="store_true")
    prepare.set_defaults(func=cmd_traffic_prepare)

    run = traffic_sub.add_parser("run", help="Submit controlled staged traffic")
    add_rpc_args(run)
    add_seed_selection_args(run)
    run.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    run.add_argument("--duration", type=int, default=60)
    run.add_argument("--target-min", type=float, default=0.50)
    run.add_argument("--target-max", type=float, default=0.80)
    run.add_argument("--max-tx", type=int, default=100)
    run.add_argument("--batch-size", type=int, default=10)
    run.add_argument("--amount", type=float, default=0.001)
    run.add_argument("--amount-jitter", type=float, default=0.20)
    run.add_argument("--min-utxos", type=int, default=20)
    run.add_argument("--recent-blocks", type=int, default=8)
    run.add_argument("--max-mempool", type=int, default=5000)
    run.add_argument("--mempool-growth-ticks", type=int, default=3)
    run.add_argument("--min-peers", type=int, default=1)
    run.add_argument("--max-peer-height-delta", type=int, default=3)
    run.add_argument("--max-reject-rate", type=float, default=0.25)
    run.add_argument("--seed-visibility-min", type=int, default=4)
    run.add_argument("--seed-visibility-timeout", type=int, default=30)
    run.add_argument("--seed-visibility-interval", type=float, default=2.0)
    run.add_argument("--pause", type=float, default=5.0)
    run.add_argument("--backoff", type=float, default=15.0)
    run.add_argument("--min-submit-interval", type=float, default=2.0)
    run.add_argument("--privacy-probes", action="store_true")
    run.add_argument("--privacy-amount", type=float, default=0.01)
    run.add_argument("--privacy-pause", type=float, default=2.0)
    run.add_argument("--silent-probe", action="store_true")
    run.add_argument("--silent-amount", type=float, default=0.001)
    run.add_argument("--nullsend-probe", action="store_true")
    run.add_argument("--nullsend-amount", type=float, default=0.01)
    run.add_argument("--nullsend-mode", type=int, default=7)
    run.add_argument("--nullsend-pool", type=int, default=5)
    run.add_argument("--nullsend-timeout", type=int, default=300)
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--yes-live-traffic", action="store_true")
    run.set_defaults(func=cmd_traffic_run)

    recover = traffic_sub.add_parser("recover", help="Rebroadcast traffic wallet txs and verify seed mempools")
    add_rpc_args(recover)
    add_seed_selection_args(recover)
    recover.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    recover.add_argument("--output", help="Output JSON path; defaults to <output-dir>/traffic_recovery_<timestamp>.json")
    recover.add_argument("--retry-window", type=int, default=60)
    recover.add_argument("--poll-interval", type=float, default=2.0)
    recover.add_argument("--min-seed-visibility", type=int, default=4)
    recover.add_argument("--dry-run", action="store_true")
    recover.add_argument("--yes-live-traffic", action="store_true")
    recover.set_defaults(func=cmd_traffic_recover)

    status = traffic_sub.add_parser("status", help="Summarize dedicated traffic wallet readiness")
    add_rpc_args(status)
    status.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    status.add_argument("--recent-blocks", type=int, default=8)
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_traffic_status)

    selftest = sub.add_parser("selftest", help="Run parser/report tests with fixture RPC data")
    selftest.add_argument("--workdir", help="Directory for fixture CSV/report output")
    selftest.set_defaults(func=cmd_selftest)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
