#!/usr/bin/env python3
"""Controlled PoW-to-PoS liveness recovery run for the live Innova testnet.

The script intentionally talks to remote nodes through ssh and the existing
innovad CLI so RPC ports stay private.  It writes all run artifacts under a
single output directory and keeps setgenerate false as the cleanup invariant.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


NODES: Sequence[Tuple[str, str]] = (
    ("seed1", "root@45.32.161.27"),
    ("seed2", "root@45.77.164.87"),
    ("seed3", "root@144.202.37.36"),
    ("seed4", "root@45.32.168.101"),
    ("seed5", "root@45.77.118.217"),
)
SEED_IPS = tuple(target.split("@", 1)[-1] for _, target in NODES)

ACTIVE_LABEL = "seed4"
ACTIVE_TARGET = "root@45.32.168.101"
INNOVAD = "/usr/local/bin/innovad"
DATADIR = "/root/.innova"
RPCPORT = "15531"
DEBUG_LOG = "/root/.innova/testnet/debug.log"
MODE_AUTO = "auto"
MODE_LEGACY_POS = "legacy-pos"
MODE_POST_DAG_POW = "post-dag-pow"

SAMPLE_COLUMNS = [
    "timestamp",
    "phase",
    "cycle",
    "event",
    "max_height",
    "common_height",
    "height_spread",
    "hashes_match_common_height",
    "ibd_any",
    "min_peers",
    "seed_peer_counts",
    "seed_ban_counts",
    "seed_ip_bans",
    "mempool_total",
    "seed4_cpumining",
    "seed4_staking",
    "seed_heights",
    "seed_hashes",
    "notes",
]

BLOCK_COLUMNS = [
    "timestamp",
    "phase",
    "cycle",
    "height",
    "hash",
    "block_type",
    "flags",
    "tx_count",
    "size_bytes",
    "block_time",
    "source_node",
]

DIAG_PATTERNS = (
    "AcceptBlock FAILED",
    "AcceptBlock()",
    "ConnectBlock()",
    "coinbase reward exceeded",
    "finality stake proof",
    "Misbehaving",
    "DoS",
    "invalid",
    "reject",
    "CheckStake",
    "CreateCoinStake",
    "StakeMiner",
    "SetBestChain",
    "ProcessBlock",
    "generated block is stale",
    "proof-of-stake checking failed",
)
CONSENSUS_REJECT_PATTERN = (
    "AcceptBlock FAILED|AcceptBlock\\(\\)|ConnectBlock\\(\\)|coinbase reward exceeded|"
    "finality stake proof|Misbehaving|DoS|invalid|reject"
)


class RpcError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_rpc(text: str) -> Any:
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
    try:
        if any(ch in text for ch in ".eE"):
            return float(text)
        return int(text)
    except ValueError:
        return text


def rpc(target: str, method: str, *args: Any, timeout: int = 25, optional: bool = False) -> Any:
    argv = [
        INNOVAD,
        "-datadir=%s" % DATADIR,
        "-rpcport=%s" % RPCPORT,
        "-testnet",
        method,
    ]
    argv.extend(format_rpc_arg(arg) for arg in args)
    remote_command = " ".join(shlex.quote(part) for part in argv)
    try:
        proc = subprocess.run(
            ["ssh", target, remote_command],
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        if optional:
            return {"_error": str(exc)}
        raise RpcError("%s %s failed before RPC returned: %s" % (target, method, exc)) from exc
    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()
    if proc.returncode != 0:
        message = stderr or stdout or "exit status %s" % proc.returncode
        if optional:
            return {"_error": message}
        raise RpcError("%s %s RPC failed: %s" % (target, method, message))
    if stdout.lower().startswith("error:"):
        if optional:
            return {"_error": stdout}
        raise RpcError("%s %s RPC failed: %s" % (target, method, stdout))
    return parse_rpc(stdout)


def ssh_text(target: str, remote_argv: Sequence[str], timeout: int = 25, optional: bool = False) -> str:
    remote_command = " ".join(shlex.quote(part) for part in remote_argv)
    try:
        proc = subprocess.run(
            ["ssh", target, remote_command],
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        if optional:
            return "ERROR: %s" % exc
        raise
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "exit status %s" % proc.returncode
        if optional:
            return "ERROR: %s" % message
        raise RuntimeError("%s failed: %s" % (target, message))
    return proc.stdout


def format_rpc_arg(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def block_type(flags: Any) -> str:
    text = str(flags or "").lower()
    if "proof-of-stake" in text:
        return "PoS"
    if "proof-of-work" in text:
        return "PoW"
    return "unknown"


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def intish(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def seed_ip_bans(banned: Any) -> List[str]:
    if not isinstance(banned, list):
        return []
    found: List[str] = []
    for entry in banned:
        if not isinstance(entry, dict):
            continue
        address = str(entry.get("address", ""))
        ip = address.split("/", 1)[0].split(":", 1)[0]
        if ip in SEED_IPS and ip not in found:
            found.append(ip)
    return found


def explicit_false(value: Any) -> bool:
    if isinstance(value, bool):
        return not value
    if value is None:
        return False
    return str(value).strip().lower() in ("0", "false", "no", "off")


def pos_block_production_disabled(staking: Any) -> bool:
    return isinstance(staking, dict) and explicit_false(staking.get("pos_block_production"))


def json_default(value: Any) -> str:
    return str(value)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True, default=json_default)
        fh.write("\n")


def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps(obj, sort_keys=True, default=json_default))
        fh.write("\n")


def append_csv(path: Path, columns: Sequence[str], row: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(columns), extrasaction="ignore")
        if not exists:
            writer.writeheader()
        clean = {}
        for col in columns:
            value = row.get(col, "")
            if isinstance(value, (dict, list)):
                value = json.dumps(value, sort_keys=True, separators=(",", ":"), default=json_default)
            clean[col] = value
        writer.writerow(clean)


def node_status(label: str, target: str) -> Dict[str, Any]:
    info = rpc(target, "getinfo")
    if not isinstance(info, dict):
        raise RpcError("%s getinfo returned %r" % (label, info))
    height = intish(info.get("blocks"), -1)
    best_hash = rpc(target, "getblockhash", height) if height >= 0 else ""
    mining = rpc(target, "getmininginfo", optional=True)
    staking = rpc(target, "getstakinginfo", optional=True)
    mempool = rpc(target, "getrawmempool", optional=True)
    peerinfo = rpc(target, "getpeerinfo", optional=True)
    banned = rpc(target, "listbanned", optional=True)
    mempool_count = len(mempool) if isinstance(mempool, list) else -1
    return {
        "label": label,
        "target": target,
        "info": info,
        "height": height,
        "hash": best_hash,
        "connections": intish(info.get("connections"), -1),
        "ibd": boolish(info.get("initialblockdownload")),
        "mining": mining,
        "cpumining": boolish(mining.get("cpumining")) if isinstance(mining, dict) else False,
        "staking_info": staking,
        "staking": boolish(staking.get("staking")) if isinstance(staking, dict) else False,
        "mempool": mempool,
        "mempool_count": mempool_count,
        "peerinfo": peerinfo,
        "peer_count": len(peerinfo) if isinstance(peerinfo, list) else intish(info.get("connections"), -1),
        "listbanned": banned,
        "ban_count": len(banned) if isinstance(banned, list) else -1,
        "seed_ip_bans": seed_ip_bans(banned),
        "errors": info.get("errors", ""),
    }


def sample_all(out_dir: Path, phase: str, cycle: int, event: str, notes: str = "") -> Dict[str, Any]:
    timestamp = utc_now()
    statuses: Dict[str, Dict[str, Any]] = {}
    sample_notes: List[str] = [notes] if notes else []
    for label, target in NODES:
        try:
            statuses[label] = node_status(label, target)
        except Exception as exc:
            sample_notes.append("%s=%s" % (label, exc))
            statuses[label] = {
                "label": label,
                "target": target,
                "height": -1,
                "hash": "",
                "connections": -1,
                "ibd": True,
                "cpumining": False,
                "staking": False,
                "mempool_count": -1,
                "peer_count": -1,
                "ban_count": -1,
                "seed_ip_bans": [],
                "error": str(exc),
            }

    good = [st for st in statuses.values() if st.get("height", -1) >= 0]
    heights = {label: intish(st.get("height"), -1) for label, st in statuses.items()}
    hashes = {label: str(st.get("hash", "")) for label, st in statuses.items()}
    peer_counts = {label: intish(st.get("peer_count"), -1) for label, st in statuses.items()}
    ban_counts = {label: intish(st.get("ban_count"), -1) for label, st in statuses.items()}
    seed_bans = {
        label: st.get("seed_ip_bans", [])
        for label, st in statuses.items()
        if isinstance(st.get("seed_ip_bans"), list) and st.get("seed_ip_bans")
    }
    max_height = max((st["height"] for st in good), default=-1)
    common_height = min((st["height"] for st in good), default=-1)
    common_hashes: Dict[str, str] = {}
    hashes_match = False
    if common_height >= 0:
        for label, target in NODES:
            if heights.get(label, -1) >= common_height:
                try:
                    common_hashes[label] = str(rpc(target, "getblockhash", common_height, optional=True))
                except Exception as exc:
                    sample_notes.append("%s_common_hash=%s" % (label, exc))
        hashes_match = bool(common_hashes) and len(set(common_hashes.values())) == 1

    row = {
        "timestamp": timestamp,
        "phase": phase,
        "cycle": cycle,
        "event": event,
        "max_height": max_height,
        "common_height": common_height,
        "height_spread": max_height - common_height if good else "",
        "hashes_match_common_height": hashes_match,
        "ibd_any": any(boolish(st.get("ibd")) for st in statuses.values()),
        "min_peers": min((intish(st.get("peer_count", st.get("connections")), -1) for st in statuses.values()), default=-1),
        "seed_peer_counts": peer_counts,
        "seed_ban_counts": ban_counts,
        "seed_ip_bans": seed_bans,
        "mempool_total": sum(max(0, intish(st.get("mempool_count"), -1)) for st in statuses.values()),
        "seed4_cpumining": statuses.get("seed4", {}).get("cpumining", ""),
        "seed4_staking": statuses.get("seed4", {}).get("staking", ""),
        "seed_heights": heights,
        "seed_hashes": hashes,
        "notes": "; ".join(part for part in sample_notes if part),
    }
    append_csv(out_dir / "samples.csv", SAMPLE_COLUMNS, row)
    append_jsonl(
        out_dir / "samples.jsonl",
        {
            **row,
            "statuses": statuses,
            "common_hashes": common_hashes,
        },
    )
    return {"row": row, "statuses": statuses, "common_hashes": common_hashes}


def collect_blocks(
    out_dir: Path,
    phase: str,
    cycle: int,
    from_height: int,
    to_height: int,
    preferred_label: str = ACTIVE_LABEL,
) -> Dict[str, int]:
    counts = {"PoS": 0, "PoW": 0, "unknown": 0}
    if to_height <= from_height:
        return counts
    node_map = dict(NODES)
    preferred_target = node_map[preferred_label]
    for height in range(from_height + 1, to_height + 1):
        source_label = preferred_label
        source_target = preferred_target
        block_hash = rpc(source_target, "getblockhash", height, optional=True)
        if isinstance(block_hash, dict) and block_hash.get("_error"):
            for label, target in NODES:
                block_hash = rpc(target, "getblockhash", height, optional=True)
                if not (isinstance(block_hash, dict) and block_hash.get("_error")):
                    source_label = label
                    source_target = target
                    break
        if isinstance(block_hash, dict):
            append_jsonl(
                out_dir / "events.jsonl",
                {"timestamp": utc_now(), "event": "block_lookup_failed", "height": height, "error": block_hash},
            )
            continue
        block = rpc(source_target, "getblock", block_hash, optional=True)
        if not isinstance(block, dict) or block.get("_error"):
            append_jsonl(
                out_dir / "events.jsonl",
                {"timestamp": utc_now(), "event": "block_fetch_failed", "height": height, "hash": block_hash, "error": block},
            )
            continue
        btype = block_type(block.get("flags"))
        counts[btype] = counts.get(btype, 0) + 1
        txs = block.get("tx", [])
        append_csv(
            out_dir / "blocks.csv",
            BLOCK_COLUMNS,
            {
                "timestamp": utc_now(),
                "phase": phase,
                "cycle": cycle,
                "height": height,
                "hash": block.get("hash", block_hash),
                "block_type": btype,
                "flags": block.get("flags", ""),
                "tx_count": len(txs) if isinstance(txs, list) else "",
                "size_bytes": block.get("size", ""),
                "block_time": block.get("time", ""),
                "source_node": source_label,
            },
        )
        print(
            "%s %s cycle=%s block height=%s type=%s hash=%s"
            % (utc_now(), phase, cycle, height, btype, str(block_hash)[:16]),
            flush=True,
        )
    return counts


def setgenerate(generate: bool, blocks: Optional[int] = None) -> Any:
    args: List[Any] = [generate]
    if blocks is not None:
        args.append(blocks)
    return rpc(ACTIVE_TARGET, "setgenerate", *args, timeout=30)


def resolve_mode(requested_mode: str, out_dir: Path) -> Tuple[str, Dict[str, Any]]:
    staking = rpc(ACTIVE_TARGET, "getstakinginfo")
    if not isinstance(staking, dict):
        raise RuntimeError("getstakinginfo returned %r, expected object" % (staking,))
    if requested_mode == MODE_AUTO:
        resolved = MODE_POST_DAG_POW if pos_block_production_disabled(staking) else MODE_LEGACY_POS
    else:
        resolved = requested_mode
    append_jsonl(
        out_dir / "events.jsonl",
        {
            "timestamp": utc_now(),
            "event": "mode_resolved",
            "requested_mode": requested_mode,
            "mode": resolved,
            "seed4_pos_block_production": staking.get("pos_block_production"),
            "seed4_staking": staking.get("staking"),
        },
    )
    print(
        "%s mode=%s requested=%s seed4_pos_block_production=%s seed4_staking=%s"
        % (utc_now(), resolved, requested_mode, staking.get("pos_block_production"), staking.get("staking")),
        flush=True,
    )
    return resolved, staking


def wait_convergence(out_dir: Path, phase: str, cycle: int, timeout_seconds: int, interval: int) -> Optional[Dict[str, Any]]:
    deadline = time.time() + timeout_seconds
    last_sample: Optional[Dict[str, Any]] = None
    while time.time() < deadline:
        last_sample = sample_all(out_dir, phase, cycle, "convergence")
        row = last_sample["row"]
        if (
            row.get("height_spread") == 0
            and boolish(row.get("hashes_match_common_height"))
            and not boolish(row.get("ibd_any"))
            and intish(row.get("min_peers"), -1) >= 4
        ):
            return last_sample
        print(
            "%s waiting convergence cycle=%s max=%s common=%s spread=%s hash_match=%s ibd_any=%s min_peers=%s"
            % (
                utc_now(),
                cycle,
                row.get("max_height"),
                row.get("common_height"),
                row.get("height_spread"),
                row.get("hashes_match_common_height"),
                row.get("ibd_any"),
                row.get("min_peers"),
            ),
            flush=True,
        )
        time.sleep(interval)
    return last_sample


def preflight(out_dir: Path, mode: str) -> Dict[str, Any]:
    print("%s preflight starting mode=%s" % (utc_now(), mode), flush=True)
    snapshots = {}
    sample = sample_all(out_dir, "preflight", 0, "preflight")
    for label, target in NODES:
        entry = dict(sample["statuses"].get(label, {}))
        entry["dag"] = rpc(target, "getdaginfo", optional=True)
        entry["finality"] = rpc(target, "getfinalityinfo", optional=True)
        height = intish(entry.get("height"), -1)
        recent = []
        for block_height in range(max(0, height - 19), height + 1):
            block_hash = rpc(target, "getblockhash", block_height, optional=True)
            if isinstance(block_hash, dict):
                continue
            block = rpc(target, "getblock", block_hash, optional=True)
            if isinstance(block, dict) and not block.get("_error"):
                recent.append(
                    {
                        "height": block_height,
                        "hash": block.get("hash", block_hash),
                        "flags": block.get("flags", ""),
                        "block_type": block_type(block.get("flags")),
                        "time": block.get("time", ""),
                    }
                )
        entry["recent_blocks"] = recent
        snapshots[label] = entry
    write_json(out_dir / "preflight.json", snapshots)

    seed4 = snapshots.get("seed4", {})
    seed4_mining = seed4.get("mining", {}) if isinstance(seed4.get("mining"), dict) else {}
    seed4_staking = seed4.get("staking_info", {}) if isinstance(seed4.get("staking_info"), dict) else {}
    if mode == MODE_LEGACY_POS and not boolish(seed4_staking.get("staking")):
        raise RuntimeError("preflight failed: seed4 staking is not true")
    if mode == MODE_POST_DAG_POW and not pos_block_production_disabled(seed4_staking):
        append_jsonl(
            out_dir / "events.jsonl",
            {
                "timestamp": utc_now(),
                "event": "post_dag_mode_without_disabled_pos_flag",
                "seed4_pos_block_production": seed4_staking.get("pos_block_production"),
            },
        )
    if boolish(seed4_mining.get("cpumining")):
        raise RuntimeError("preflight failed: seed4 cpumining is true")
    row = sample["row"]
    if intish(row.get("height_spread"), 99) != 0 or not boolish(row.get("hashes_match_common_height")):
        raise RuntimeError("preflight failed: seeds are not converged")
    if boolish(row.get("ibd_any")):
        raise RuntimeError("preflight failed: at least one seed is in IBD")
    if intish(row.get("min_peers"), -1) < 4:
        raise RuntimeError("preflight failed: peer count below 4")
    print(
        "%s preflight ok height=%s hash=%s seed4_weight=%s expectedtime=%s"
        % (
            utc_now(),
            row.get("common_height"),
            seed4.get("hash", ""),
            seed4_staking.get("weight", ""),
            seed4_staking.get("expectedtime", ""),
        ),
        flush=True,
    )
    return snapshots


def pow_pulse(out_dir: Path, cycle: int, blocks: int, poll_interval: int, baseline_mempool: int) -> Dict[str, Any]:
    start = sample_all(out_dir, "pow", cycle, "pulse_start")
    start_height = intish(start["row"].get("max_height"), -1)
    print("%s cycle=%s starting finite PoW target_blocks=%s start_height=%s" % (utc_now(), cycle, blocks, start_height), flush=True)
    append_jsonl(out_dir / "events.jsonl", {"timestamp": utc_now(), "event": "setgenerate_true", "cycle": cycle, "blocks": blocks})
    result = setgenerate(True, blocks)
    append_jsonl(out_dir / "events.jsonl", {"timestamp": utc_now(), "event": "setgenerate_true_result", "cycle": cycle, "result": result})

    last_classified = start_height
    ibd_consecutive = 0
    early_reason = ""
    final_sample: Optional[Dict[str, Any]] = None
    stop_result: Any = None
    try:
        while True:
            time.sleep(poll_interval)
            sample = sample_all(out_dir, "pow", cycle, "pulse_poll")
            final_sample = sample
            row = sample["row"]
            max_height = intish(row.get("max_height"), -1)
            counts = collect_blocks(out_dir, "pow", cycle, last_classified, max_height)
            last_classified = max(last_classified, max_height)
            if counts:
                append_jsonl(out_dir / "events.jsonl", {"timestamp": utc_now(), "event": "pulse_block_counts", "cycle": cycle, "counts": counts})

            if boolish(row.get("ibd_any")):
                ibd_consecutive += 1
            else:
                ibd_consecutive = 0
            height_spread = intish(row.get("height_spread"), 99)
            min_peers = intish(row.get("min_peers"), -1)
            mempool_total = intish(row.get("mempool_total"), 0)
            advanced = max_height - start_height
            print(
                "%s cycle=%s pow max=%s advanced=%s spread=%s min_peers=%s mempool=%s cpumining=%s"
                % (
                    utc_now(),
                    cycle,
                    max_height,
                    advanced,
                    height_spread,
                    min_peers,
                    mempool_total,
                    row.get("seed4_cpumining"),
                ),
                flush=True,
            )

            if advanced >= blocks:
                early_reason = "target_height_advanced"
                break
            if height_spread > 3:
                early_reason = "height_spread_gt_3"
                break
            if ibd_consecutive >= 2:
                early_reason = "persistent_ibd"
                break
            if min_peers < 4:
                early_reason = "peer_count_below_4"
                break
            if mempool_total > max(5, baseline_mempool + 5):
                early_reason = "unexpected_mempool_growth"
                break
            if not boolish(row.get("seed4_cpumining")) and advanced > 0:
                early_reason = "miner_stopped"
                break
    finally:
        print("%s cycle=%s forcing setgenerate false" % (utc_now(), cycle), flush=True)
        append_jsonl(out_dir / "events.jsonl", {"timestamp": utc_now(), "event": "setgenerate_false", "cycle": cycle, "reason": early_reason})
        stop_result = setgenerate(False)
        append_jsonl(out_dir / "events.jsonl", {"timestamp": utc_now(), "event": "setgenerate_false_result", "cycle": cycle, "result": stop_result})

    post = wait_convergence(out_dir, "pow", cycle, timeout_seconds=180, interval=15)
    post_height = intish(post["row"].get("max_height"), last_classified) if post else last_classified
    if post_height > last_classified:
        collect_blocks(out_dir, "pow", cycle, last_classified, post_height)
        last_classified = post_height
    verify = sample_all(out_dir, "pow", cycle, "post_stop_verify")
    cleanup_confirmed = not boolish(verify["row"].get("seed4_cpumining"))
    if not cleanup_confirmed:
        raise RuntimeError("seed4 cpumining remained true after setgenerate false")
    return {
        "cycle": cycle,
        "start_height": start_height,
        "end_height": last_classified,
        "reason": early_reason,
        "cleanup_confirmed": cleanup_confirmed,
        "stop_result": stop_result,
        "final_sample": final_sample["row"] if final_sample else None,
        "post_stop_sample": verify["row"],
        "post_stop_statuses": verify["statuses"],
    }


def pos_watch(
    out_dir: Path,
    cycle: int,
    duration: int,
    interval: int,
    pass_pos_blocks: int,
) -> Dict[str, Any]:
    start = wait_convergence(out_dir, "pos_watch", cycle, timeout_seconds=180, interval=15)
    if not start:
        raise RuntimeError("could not establish convergence before PoS watch")
    if boolish(start["row"].get("seed4_cpumining")):
        raise RuntimeError("seed4 cpumining true before PoS watch")
    start_height = intish(start["row"].get("max_height"), -1)
    last_classified = start_height
    pos_count = 0
    pow_count = 0
    unknown_count = 0
    started_at = time.time()
    deadline = started_at + duration
    pass_reached = False
    print("%s cycle=%s PoS-only watch start height=%s duration=%ss" % (utc_now(), cycle, start_height, duration), flush=True)
    append_jsonl(
        out_dir / "events.jsonl",
        {"timestamp": utc_now(), "event": "pos_watch_start", "cycle": cycle, "height": start_height, "duration": duration},
    )

    while time.time() < deadline:
        tick_started = time.time()
        sample = sample_all(out_dir, "pos_watch", cycle, "watch_poll")
        row = sample["row"]
        max_height = intish(row.get("max_height"), -1)
        counts = collect_blocks(out_dir, "pos_watch", cycle, last_classified, max_height)
        last_classified = max(last_classified, max_height)
        pos_count += counts.get("PoS", 0)
        pow_count += counts.get("PoW", 0)
        unknown_count += counts.get("unknown", 0)
        elapsed = int(time.time() - started_at)
        print(
            "%s cycle=%s pos_watch elapsed=%ss max=%s common=%s pos=%s pow=%s unknown=%s cpumining=%s ibd_any=%s hash_match=%s"
            % (
                utc_now(),
                cycle,
                elapsed,
                row.get("max_height"),
                row.get("common_height"),
                pos_count,
                pow_count,
                unknown_count,
                row.get("seed4_cpumining"),
                row.get("ibd_any"),
                row.get("hashes_match_common_height"),
            ),
            flush=True,
        )
        if boolish(row.get("seed4_cpumining")):
            print("%s cycle=%s cpumining unexpectedly true; forcing stop" % (utc_now(), cycle), flush=True)
            setgenerate(False)
        if pos_count >= pass_pos_blocks and not pass_reached:
            pass_reached = True
            confirm = wait_convergence(out_dir, "pos_watch", cycle, timeout_seconds=120, interval=interval)
            return {
                "cycle": cycle,
                "passed": bool(confirm and intish(confirm["row"].get("height_spread"), 99) == 0),
                "start_height": start_height,
                "end_height": last_classified,
                "pos_count": pos_count,
                "pow_count": pow_count,
                "unknown_count": unknown_count,
                "duration_seconds": int(time.time() - started_at),
                "confirm_sample": confirm["row"] if confirm else None,
            }
        sleep_for = interval - (time.time() - tick_started)
        if sleep_for > 0:
            time.sleep(sleep_for)

    confirm = sample_all(out_dir, "pos_watch", cycle, "watch_end")
    return {
        "cycle": cycle,
        "passed": False,
        "start_height": start_height,
        "end_height": last_classified,
        "pos_count": pos_count,
        "pow_count": pow_count,
        "unknown_count": unknown_count,
        "duration_seconds": int(time.time() - started_at),
        "confirm_sample": confirm["row"],
    }


def capture_diagnostics(out_dir: Path, cycle: int) -> Dict[str, Any]:
    print("%s cycle=%s capturing read-only diagnostics" % (utc_now(), cycle), flush=True)
    diag_dir = out_dir / ("diagnostics_cycle_%s" % cycle)
    diag_dir.mkdir(parents=True, exist_ok=True)
    diagnostics: Dict[str, Any] = {"timestamp": utc_now(), "cycle": cycle, "nodes": {}}
    methods = (
        "getinfo",
        "getstakinginfo",
        "getmininginfo",
        "getpeerinfo",
        "getrawmempool",
        "getdaginfo",
        "getfinalityinfo",
        "listbanned",
    )
    for label, target in NODES:
        node: Dict[str, Any] = {}
        for method in methods:
            node[method] = rpc(target, method, optional=True, timeout=35)
        height = intish(node.get("getinfo", {}).get("blocks") if isinstance(node.get("getinfo"), dict) else -1, -1)
        recent = []
        for block_height in range(max(0, height - 39), height + 1):
            block_hash = rpc(target, "getblockhash", block_height, optional=True)
            if isinstance(block_hash, dict):
                continue
            block = rpc(target, "getblock", block_hash, optional=True)
            if isinstance(block, dict) and not block.get("_error"):
                recent.append(
                    {
                        "height": block_height,
                        "hash": block.get("hash", block_hash),
                        "flags": block.get("flags", ""),
                        "block_type": block_type(block.get("flags")),
                        "time": block.get("time", ""),
                        "tx_count": len(block.get("tx", [])) if isinstance(block.get("tx", []), list) else "",
                    }
                )
        node["recent_blocks"] = recent
        log_tail = ssh_text(target, ["tail", "-n", "2500", DEBUG_LOG], timeout=35, optional=True)
        (diag_dir / ("%s_debug_tail.log" % label)).write_text(log_tail)
        filtered = []
        for line in log_tail.splitlines():
            if any(pattern in line for pattern in DIAG_PATTERNS):
                filtered.append(line)
        (diag_dir / ("%s_debug_filtered.log" % label)).write_text("\n".join(filtered) + ("\n" if filtered else ""))

        reject_scan = ssh_text(
            target,
            [
                "sh",
                "-c",
                "grep -Ein %s %s | tail -n 5000 || true"
                % (shlex.quote(CONSENSUS_REJECT_PATTERN), shlex.quote(DEBUG_LOG)),
            ],
            timeout=45,
            optional=True,
        )
        reject_count_text = ssh_text(
            target,
            [
                "sh",
                "-c",
                "grep -Ei %s %s | wc -l || true"
                % (shlex.quote(CONSENSUS_REJECT_PATTERN), shlex.quote(DEBUG_LOG)),
            ],
            timeout=45,
            optional=True,
        )
        (diag_dir / ("%s_consensus_reject_scan.log" % label)).write_text(reject_scan)
        try:
            reject_count = int(reject_count_text.strip().splitlines()[-1])
        except (IndexError, ValueError):
            reject_count = -1
        node["debug_filtered_line_count"] = len(filtered)
        node["debug_filtered_tail"] = filtered[-80:]
        node["consensus_reject_scan_line_count"] = reject_count
        node["consensus_reject_scan_tail"] = reject_scan.splitlines()[-80:]
        node["seed_ip_bans"] = seed_ip_bans(node.get("listbanned"))
        diagnostics["nodes"][label] = node
    write_json(diag_dir / "diagnostics.json", diagnostics)
    append_jsonl(out_dir / "events.jsonl", {"timestamp": utc_now(), "event": "diagnostics_captured", "cycle": cycle, "dir": str(diag_dir)})
    return diagnostics


def default_output_dir() -> Path:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("testnet_metrics") / ("pos_recovery_%s" % stamp)


def post_dag_liveness_checks(pulse: Dict[str, Any]) -> Dict[str, Any]:
    row = pulse.get("post_stop_sample") if isinstance(pulse.get("post_stop_sample"), dict) else {}
    statuses = pulse.get("post_stop_statuses") if isinstance(pulse.get("post_stop_statuses"), dict) else {}
    warnings = {
        label: str(status.get("errors", ""))
        for label, status in statuses.items()
        if isinstance(status, dict) and str(status.get("errors", "") or "")
    }
    seed_bans = {
        label: status.get("seed_ip_bans", [])
        for label, status in statuses.items()
        if isinstance(status, dict) and status.get("seed_ip_bans")
    }
    start_height = intish(pulse.get("start_height"), -1)
    pulse_end_height = max(intish(pulse.get("end_height"), -1), intish(row.get("max_height"), -1))
    checks = {
        "pow_advanced": pulse_end_height > start_height,
        "all_five_reported": len(statuses) == len(NODES)
        and all(intish(status.get("height"), -1) >= 0 for status in statuses.values() if isinstance(status, dict)),
        "height_spread_zero": intish(row.get("height_spread"), 99) == 0,
        "final_hashes_match": boolish(row.get("hashes_match_common_height")),
        "no_ibd": not boolish(row.get("ibd_any")),
        "min_peers_ok": intish(row.get("min_peers"), -1) >= 4,
        "no_seed_ip_bans": not seed_bans,
        "cleanup_confirmed": boolish(pulse.get("cleanup_confirmed")),
        "no_warnings": not warnings,
        "pulse_start_height": start_height,
        "pulse_end_height": pulse_end_height,
        "final_common_height": intish(row.get("common_height"), -1),
        "final_min_peers": intish(row.get("min_peers"), -1),
        "final_height_spread": intish(row.get("height_spread"), 99),
        "warnings": warnings,
        "seed_ip_bans": seed_bans,
    }
    bool_keys = (
        "pow_advanced",
        "all_five_reported",
        "height_spread_zero",
        "final_hashes_match",
        "no_ibd",
        "min_peers_ok",
        "no_seed_ip_bans",
        "cleanup_confirmed",
        "no_warnings",
    )
    checks["passed"] = all(bool(checks[key]) for key in bool_keys)
    checks["failed_checks"] = [key for key in bool_keys if not bool(checks[key])]
    return checks


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=str(default_output_dir()))
    parser.add_argument("--mode", choices=[MODE_AUTO, MODE_LEGACY_POS, MODE_POST_DAG_POW], default=MODE_AUTO)
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--pulse-blocks", type=int, default=25)
    parser.add_argument("--pulse-interval", type=int, default=15)
    parser.add_argument("--watch-duration", type=int, default=1800)
    parser.add_argument("--watch-interval", type=int, default=30)
    parser.add_argument("--pass-pos-blocks", type=int, default=10)
    args = parser.parse_args(argv)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        out_dir / "run_config.json",
        {
            "timestamp": utc_now(),
            "nodes": [{"label": label, "target": target} for label, target in NODES],
            "active_label": ACTIVE_LABEL,
            "requested_mode": args.mode,
            "cycles": args.cycles,
            "pulse_blocks": args.pulse_blocks,
            "pulse_interval": args.pulse_interval,
            "watch_duration": args.watch_duration,
            "watch_interval": args.watch_interval,
            "pass_pos_blocks": args.pass_pos_blocks,
        },
    )
    print("%s output_dir=%s" % (utc_now(), out_dir), flush=True)

    overall: Dict[str, Any] = {"passed": False, "requested_mode": args.mode, "cycles": []}
    try:
        mode, mode_staking = resolve_mode(args.mode, out_dir)
        skip_reason = "pos_block_production=false" if mode == MODE_POST_DAG_POW else ""
        overall.update(
            {
                "mode": mode,
                "pos_watch_skipped": mode == MODE_POST_DAG_POW,
                "skip_reason": skip_reason,
                "seed4_pos_block_production": mode_staking.get("pos_block_production"),
            }
        )
        write_json(
            out_dir / "run_config.json",
            {
                "timestamp": utc_now(),
                "nodes": [{"label": label, "target": target} for label, target in NODES],
                "active_label": ACTIVE_LABEL,
                "requested_mode": args.mode,
                "mode": mode,
                "cycles": args.cycles,
                "pulse_blocks": args.pulse_blocks,
                "pulse_interval": args.pulse_interval,
                "watch_duration": args.watch_duration,
                "watch_interval": args.watch_interval,
                "pass_pos_blocks": args.pass_pos_blocks,
                "seed4_pos_block_production": mode_staking.get("pos_block_production"),
            },
        )

        pre = preflight(out_dir, mode)
        baseline_mempool = 0
        for node in pre.values():
            baseline_mempool += max(0, intish(node.get("mempool_count"), -1))

        for cycle in range(1, args.cycles + 1):
            cycle_result: Dict[str, Any] = {"cycle": cycle}
            pulse = pow_pulse(out_dir, cycle, args.pulse_blocks, args.pulse_interval, baseline_mempool)
            cycle_result["pulse"] = pulse
            if mode == MODE_POST_DAG_POW:
                checks = post_dag_liveness_checks(pulse)
                watch = {
                    "cycle": cycle,
                    "passed": True,
                    "skipped": True,
                    "skip_reason": skip_reason,
                    "pos_count": 0,
                    "pow_count": "",
                    "unknown_count": "",
                    "confirm_sample": pulse.get("post_stop_sample"),
                }
                cycle_result["watch"] = watch
                cycle_result["post_dag_checks"] = checks
                overall.update(
                    {
                        "pulse_start_height": checks.get("pulse_start_height"),
                        "pulse_end_height": checks.get("pulse_end_height"),
                        "final_common_height": checks.get("final_common_height"),
                        "final_hashes_match": checks.get("final_hashes_match"),
                        "final_height_spread": checks.get("final_height_spread"),
                        "final_min_peers": checks.get("final_min_peers"),
                        "setgenerate_false_confirmed": checks.get("cleanup_confirmed"),
                    }
                )
                overall["cycles"].append(cycle_result)
                write_json(out_dir / "run_summary.json", overall)
                if checks.get("passed"):
                    overall["passed"] = True
                    overall["passed_cycle"] = cycle
                    write_json(out_dir / "run_summary.json", overall)
                    print(
                        "%s PASS cycle=%s post_dag_pow start=%s end=%s final_common=%s"
                        % (
                            utc_now(),
                            cycle,
                            checks.get("pulse_start_height"),
                            checks.get("pulse_end_height"),
                            checks.get("final_common_height"),
                        ),
                        flush=True,
                    )
                    return 0
                print("%s cycle=%s post-DAG checks failed: %s" % (utc_now(), cycle, checks.get("failed_checks")), flush=True)
                capture_diagnostics(out_dir, cycle)
                continue

            watch = pos_watch(out_dir, cycle, args.watch_duration, args.watch_interval, args.pass_pos_blocks)
            cycle_result["watch"] = watch
            overall["cycles"].append(cycle_result)
            write_json(out_dir / "run_summary.json", overall)
            if watch.get("passed") and watch.get("pos_count", 0) >= args.pass_pos_blocks and watch.get("pow_count", 0) == 0:
                overall["passed"] = True
                overall["passed_cycle"] = cycle
                write_json(out_dir / "run_summary.json", overall)
                print("%s PASS cycle=%s pos_blocks=%s" % (utc_now(), cycle, watch.get("pos_count")), flush=True)
                return 0
            capture_diagnostics(out_dir, cycle)

        if overall.get("mode") == MODE_POST_DAG_POW:
            print("%s FAIL no post-DAG PoW liveness pass after %s cycles" % (utc_now(), args.cycles), flush=True)
        else:
            print("%s FAIL no PoS liveness pass after %s cycles" % (utc_now(), args.cycles), flush=True)
        write_json(out_dir / "run_summary.json", overall)
        return 2
    except KeyboardInterrupt:
        print("%s interrupted; forcing setgenerate false" % utc_now(), flush=True)
        setgenerate(False)
        return 130
    except Exception as exc:
        append_jsonl(out_dir / "events.jsonl", {"timestamp": utc_now(), "event": "fatal", "error": str(exc)})
        print("%s fatal: %s" % (utc_now(), exc), file=sys.stderr, flush=True)
        try:
            setgenerate(False)
        except Exception as stop_exc:
            print("%s failed to stop mining after fatal: %s" % (utc_now(), stop_exc), file=sys.stderr, flush=True)
        return 1
    finally:
        try:
            setgenerate(False)
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
