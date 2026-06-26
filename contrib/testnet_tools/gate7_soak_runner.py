#!/usr/bin/env python3
"""Autonomous Gate 7 testnet soak runner.

This script is intended to run on seed4.  It performs the 72-hour Gate 7 soak
without relying on the operator's local network connection:

* health checks all five seeds plus the traffic wallet at least once per cycle
* submits light guarded transparent traffic from the traffic wallet
* verifies every traffic tx is visible on all five seed mempools before mining
* mines finite one-block PoW pulses from seed4
* verifies mining stops, all nodes converge, and mempools drain

It writes JSONL events, CSV health/traffic rows, and a status JSON file under
the selected output directory.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fcntl
import json
import os
import random
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_INNOVAD = "/usr/local/bin/innovad"
DEFAULT_SEED_DATADIR = "/root/.innova"
DEFAULT_SEED_RPC_PORT = 15531
DEFAULT_TRAFFIC_DATADIR = "/root/.innova-traffic"
DEFAULT_TRAFFIC_RPC_PORT = 15631
DEFAULT_SSH_KEY = "/root/.ssh/id_gate7_soak"

SEED_NODES = [
    {"label": "seed1", "target": "root@45.32.161.27"},
    {"label": "seed2", "target": "root@45.77.164.87"},
    {"label": "seed3", "target": "root@144.202.37.36"},
    {"label": "seed4", "target": None},
    {"label": "seed5", "target": "root@45.77.118.217"},
]

HEALTH_COLUMNS = [
    "timestamp",
    "stage",
    "passed",
    "height_spread",
    "hashes_match",
    "heights",
    "hashes",
    "mempools",
    "connections",
    "failed_checks",
]

TRAFFIC_COLUMNS = [
    "timestamp",
    "cycle",
    "txid",
    "seed_seen",
    "seen_on",
    "mempools",
    "mined_height",
    "included",
]


class SoakError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return None


def to_int(value: Any, default: int = -1) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def parse_rpc_output(text: str) -> Any:
    text = text.strip()
    if text == "":
        return ""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        return int(text)
    except ValueError:
        return text


def ensure_csv(path: Path, columns: Sequence[str]) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        csv.DictWriter(fh, fieldnames=list(columns)).writeheader()


def append_csv(path: Path, columns: Sequence[str], row: Dict[str, Any]) -> None:
    ensure_csv(path, columns)
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(columns))
        writer.writerow({key: csv_value(row.get(key, "")) for key in columns})


def csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


def node_with_defaults(node: Dict[str, Any], args: argparse.Namespace) -> Dict[str, Any]:
    result = dict(node)
    result.setdefault("innovad", args.innovad)
    result.setdefault("datadir", DEFAULT_SEED_DATADIR)
    result.setdefault("rpcport", DEFAULT_SEED_RPC_PORT)
    return result


def traffic_node(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "label": "traffic-seed4",
        "target": None,
        "innovad": args.innovad,
        "datadir": DEFAULT_TRAFFIC_DATADIR,
        "rpcport": DEFAULT_TRAFFIC_RPC_PORT,
        "traffic": True,
    }


def run_command(argv: Sequence[str], timeout: int) -> str:
    proc = subprocess.run(
        list(argv),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=max(1, int(timeout)),
    )
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "exit status %s" % proc.returncode
        raise SoakError("%s failed: %s" % (" ".join(shlex.quote(part) for part in argv), message))
    return proc.stdout


def rpc_call(node: Dict[str, Any], method: str, *rpc_args: Any, timeout: int = 30, args: argparse.Namespace) -> Any:
    node = node_with_defaults(node, args)
    argv = [
        str(node["innovad"]),
        "-datadir=%s" % node["datadir"],
        "-rpcport=%s" % node["rpcport"],
        "-testnet",
        method,
    ] + [str(value) for value in rpc_args]

    target = node.get("target")
    if target:
        remote_argv = " ".join(shlex.quote(part) for part in argv)
        remote_command = "timeout %s %s" % (shlex.quote(str(max(1, int(timeout)))), remote_argv)
        ssh_argv = [
            "ssh",
            "-i",
            args.ssh_key,
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=%s" % max(1, min(10, int(timeout))),
            str(target),
            remote_command,
        ]
        return parse_rpc_output(run_command(ssh_argv, timeout + 8))

    return parse_rpc_output(run_command(argv, timeout))


def optional_rpc(node: Dict[str, Any], method: str, *rpc_args: Any, timeout: int, args: argparse.Namespace) -> Any:
    try:
        return rpc_call(node, method, *rpc_args, timeout=timeout, args=args)
    except Exception as exc:
        return {"_error": str(exc)}


class SoakRunner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.output_dir = Path(args.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.output_dir / "events.jsonl"
        self.status_path = self.output_dir / "status.json"
        self.health_path = self.output_dir / "health.csv"
        self.traffic_path = self.output_dir / "traffic.csv"
        self.summary_path = self.output_dir / "summary.json"
        self.lock_path = self.output_dir / "runner.lock"
        self.lock_fh = self.lock_path.open("w")
        self.stop_requested = False
        self.start_time = time.time()
        self.deadline = self.start_time + args.duration
        self.run_id = args.run_id or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.submitted = 0
        self.failed = 0
        self.cycles = 0
        self.last_height = 0

    def lock(self) -> None:
        try:
            fcntl.flock(self.lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise SoakError("another Gate 7 soak runner already holds %s: %s" % (self.lock_path, exc))
        self.lock_fh.write(str(os.getpid()))
        self.lock_fh.flush()

    def log_event(self, event: str, data: Dict[str, Any]) -> None:
        row = {"timestamp": utc_now(), "event": event}
        row.update(data)
        line = json.dumps(row, sort_keys=True, default=str)
        with self.events_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        print(line, flush=True)

    def write_status(self, state: str, **extra: Any) -> None:
        status = {
            "run_id": self.run_id,
            "state": state,
            "timestamp": utc_now(),
            "pid": os.getpid(),
            "output_dir": str(self.output_dir),
            "started_at": dt.datetime.fromtimestamp(self.start_time, dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "deadline": dt.datetime.fromtimestamp(self.deadline, dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "duration_seconds": self.args.duration,
            "elapsed_seconds": round(time.time() - self.start_time, 1),
            "remaining_seconds": max(0, round(self.deadline - time.time(), 1)),
            "cycles": self.cycles,
            "submitted": self.submitted,
            "failed": self.failed,
            "last_height": self.last_height,
        }
        status.update(extra)
        tmp = self.status_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(status, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        tmp.replace(self.status_path)

    def fail(self, reason: str, **extra: Any) -> int:
        self.failed += 1
        self.log_event("failed", {"reason": reason, **extra})
        self.write_status("failed", failure_reason=reason, **extra)
        self.write_summary("failed", reason=reason, **extra)
        return 2

    def write_summary(self, state: str, **extra: Any) -> None:
        summary = {
            "run_id": self.run_id,
            "state": state,
            "timestamp": utc_now(),
            "duration_seconds": self.args.duration,
            "elapsed_seconds": round(time.time() - self.start_time, 1),
            "cycles": self.cycles,
            "submitted": self.submitted,
            "failed": self.failed,
            "output_dir": str(self.output_dir),
        }
        summary.update(extra)
        self.summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")

    def collect_node(self, node: Dict[str, Any]) -> Dict[str, Any]:
        label = node["label"]
        result: Dict[str, Any] = {"label": label, "target": node.get("target"), "ok": False}
        try:
            info = rpc_call(node, "getinfo", timeout=self.args.rpc_timeout, args=self.args)
            if not isinstance(info, dict):
                raise SoakError("%s getinfo returned %r" % (label, info))
            height = to_int(info.get("blocks"))
            best_hash = str(rpc_call(node, "getblockhash", height, timeout=self.args.rpc_timeout, args=self.args))
            mempool = rpc_call(node, "getrawmempool", timeout=self.args.rpc_timeout, args=self.args)
            mining = optional_rpc(node, "getmininginfo", timeout=self.args.optional_rpc_timeout, args=self.args)
            peerinfo = optional_rpc(node, "getpeerinfo", timeout=self.args.optional_rpc_timeout, args=self.args)
            peer_count = len(peerinfo) if isinstance(peerinfo, list) else to_int(info.get("connections"))
            errors = []
            if str(info.get("errors") or ""):
                errors.append(str(info.get("errors")))
            if isinstance(mining, dict) and str(mining.get("errors") or ""):
                errors.append(str(mining.get("errors")))
            if isinstance(mempool, dict) and mempool.get("_error"):
                errors.append(str(mempool.get("_error")))
            result.update(
                {
                    "ok": True,
                    "height": height,
                    "hash": best_hash,
                    "mempool_count": len(mempool) if isinstance(mempool, list) else -1,
                    "connections": to_int(info.get("connections")),
                    "peer_count": peer_count,
                    "initialblockdownload": parse_bool(info.get("initialblockdownload")),
                    "errors": errors,
                    "cpumining": parse_bool(mining.get("cpumining")) if isinstance(mining, dict) else None,
                    "pooledtx": to_int(mining.get("pooledtx"), -1) if isinstance(mining, dict) else -1,
                    "netstakeweight": str(info.get("netstakeweight", "")),
                }
            )
        except Exception as exc:
            result.update({"error": str(exc)})
        return result

    def collect_state(self) -> Dict[str, Any]:
        seed_results = [self.collect_node(node_with_defaults(node, self.args)) for node in SEED_NODES]
        traffic_result = self.collect_node(traffic_node(self.args))
        seed4_extra = {
            "dag": optional_rpc(node_with_defaults(SEED_NODES[3], self.args), "getdaginfo", timeout=self.args.optional_rpc_timeout, args=self.args),
            "finality": optional_rpc(node_with_defaults(SEED_NODES[3], self.args), "getfinalityinfo", timeout=self.args.optional_rpc_timeout, args=self.args),
        }
        return {"seeds": seed_results, "traffic": traffic_result, "seed4_extra": seed4_extra}

    def evaluate_state(self, state: Dict[str, Any], require_empty_mempool: bool) -> Dict[str, Any]:
        nodes = list(state["seeds"]) + [state["traffic"]]
        ok_nodes = [node for node in nodes if node.get("ok")]
        heights = {node["label"]: node.get("height", -1) for node in nodes}
        hashes = {node["label"]: node.get("hash", "") for node in nodes}
        mempools = {node["label"]: node.get("mempool_count", -1) for node in nodes}
        connections = {node["label"]: node.get("connections", -1) for node in nodes}
        failed: List[str] = []
        if len(ok_nodes) != len(nodes):
            failed.append("rpc_unresponsive")
        if any(node.get("initialblockdownload") for node in ok_nodes):
            failed.append("initial_block_download")
        if any(node.get("errors") for node in ok_nodes):
            failed.append("node_warnings")
        seed_peer_floor = min((to_int(node.get("peer_count")) for node in state["seeds"] if node.get("ok")), default=-1)
        traffic_peers = to_int(state["traffic"].get("peer_count")) if state["traffic"].get("ok") else -1
        if seed_peer_floor < self.args.min_seed_peers:
            failed.append("seed_peer_floor")
        if traffic_peers < self.args.min_traffic_peers:
            failed.append("traffic_peer_floor")
        good_heights = [to_int(node.get("height")) for node in ok_nodes]
        height_spread = max(good_heights) - min(good_heights) if good_heights else -1
        if height_spread != 0:
            failed.append("height_spread")
        good_hashes = [str(node.get("hash")) for node in ok_nodes]
        hashes_match = bool(good_hashes) and len(set(good_hashes)) == 1
        if not hashes_match:
            failed.append("hash_spread")
        if require_empty_mempool and any(to_int(node.get("mempool_count")) != 0 for node in ok_nodes):
            failed.append("mempool_not_empty")
        seed4 = next((node for node in state["seeds"] if node.get("label") == "seed4"), {})
        if seed4.get("cpumining") is not False:
            failed.append("seed4_mining_not_off")

        dag = state.get("seed4_extra", {}).get("dag")
        if not isinstance(dag, dict) or dag.get("_error") or parse_bool(dag.get("dag_active")) is not True:
            failed.append("dag_inactive")
        if isinstance(dag, dict) and parse_bool(dag.get("dagknight_active")) is not True:
            failed.append("dagknight_inactive")
        finality = state.get("seed4_extra", {}).get("finality")
        if not isinstance(finality, dict) or finality.get("_error") or parse_bool(finality.get("fork_active")) is not True:
            failed.append("finality_inactive")

        if good_heights:
            self.last_height = max(good_heights)
        return {
            "passed": not failed,
            "failed_checks": failed,
            "height_spread": height_spread,
            "hashes_match": hashes_match,
            "heights": heights,
            "hashes": hashes,
            "mempools": mempools,
            "connections": connections,
            "seed_peer_floor": seed_peer_floor,
            "traffic_peers": traffic_peers,
        }

    def health_check(self, stage: str, require_empty_mempool: bool = True) -> Tuple[bool, Dict[str, Any]]:
        state = self.collect_state()
        evaluation = self.evaluate_state(state, require_empty_mempool=require_empty_mempool)
        append_csv(
            self.health_path,
            HEALTH_COLUMNS,
            {
                "timestamp": utc_now(),
                "stage": stage,
                "passed": evaluation["passed"],
                "height_spread": evaluation["height_spread"],
                "hashes_match": evaluation["hashes_match"],
                "heights": evaluation["heights"],
                "hashes": evaluation["hashes"],
                "mempools": evaluation["mempools"],
                "connections": evaluation["connections"],
                "failed_checks": evaluation["failed_checks"],
            },
        )
        self.log_event("health", {"stage": stage, "evaluation": evaluation})
        self.write_status("running", last_health=evaluation)
        return bool(evaluation["passed"]), {"state": state, "evaluation": evaluation}

    def wait_for_clean_convergence(self, stage: str) -> Tuple[bool, Dict[str, Any]]:
        deadline = time.time() + self.args.sync_timeout
        last: Dict[str, Any] = {}
        while time.time() < deadline:
            state = self.collect_state()
            evaluation = self.evaluate_state(state, require_empty_mempool=True)
            last = {"state": state, "evaluation": evaluation}
            if evaluation["passed"]:
                append_csv(
                    self.health_path,
                    HEALTH_COLUMNS,
                    {
                        "timestamp": utc_now(),
                        "stage": stage,
                        "passed": True,
                        "height_spread": evaluation["height_spread"],
                        "hashes_match": evaluation["hashes_match"],
                        "heights": evaluation["heights"],
                        "hashes": evaluation["hashes"],
                        "mempools": evaluation["mempools"],
                        "connections": evaluation["connections"],
                        "failed_checks": evaluation["failed_checks"],
                    },
                )
                self.log_event("health", {"stage": stage, "evaluation": evaluation})
                self.write_status("running", last_health=evaluation)
                return True, last
            time.sleep(self.args.poll_interval)
        self.log_event("health_failed", {"stage": stage, "last": last.get("evaluation", {})})
        return False, last

    def confirmed_utxos(self) -> Tuple[int, float]:
        unspent = rpc_call(traffic_node(self.args), "listunspent", 1, 9999999, timeout=self.args.rpc_timeout, args=self.args)
        if not isinstance(unspent, list):
            raise SoakError("traffic listunspent returned %r" % (unspent,))
        total = 0.0
        for item in unspent:
            if isinstance(item, dict):
                try:
                    total += float(item.get("amount", 0))
                except (TypeError, ValueError):
                    pass
        return len(unspent), total

    def ensure_wallet_ready(self, batches: int) -> None:
        utxos, balance = self.confirmed_utxos()
        if utxos < self.args.min_utxos:
            raise SoakError("traffic wallet has %s confirmed UTXOs, below %s" % (utxos, self.args.min_utxos))
        max_multiplier = max(0.1, 1.0 + self.args.amount_jitter)
        required = self.args.amount * max_multiplier * self.args.batch_size * max(1, batches)
        if balance < required:
            raise SoakError("traffic wallet balance %.8f too low for %s batch(es)" % (balance, batches))

    def submit_batch(self) -> str:
        outputs: Dict[str, float] = {}
        for _ in range(self.args.batch_size):
            address = str(rpc_call(traffic_node(self.args), "getnewaddress", timeout=self.args.rpc_timeout, args=self.args))
            multiplier = random.uniform(max(0.1, 1.0 - self.args.amount_jitter), 1.0 + self.args.amount_jitter)
            outputs[address] = round(self.args.amount * multiplier, 6)
        txid = rpc_call(
            traffic_node(self.args),
            "sendmany",
            "",
            json.dumps(outputs, sort_keys=True, separators=(",", ":")),
            1,
            "gate7 soak",
            timeout=self.args.rpc_timeout,
            args=self.args,
        )
        self.submitted += 1
        return str(txid)

    def seed_mempools(self) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
        mempools: Dict[str, List[str]] = {}
        errors: Dict[str, str] = {}
        for seed in SEED_NODES:
            node = node_with_defaults(seed, self.args)
            try:
                mempool = rpc_call(node, "getrawmempool", timeout=self.args.rpc_timeout, args=self.args)
                if isinstance(mempool, list):
                    mempools[str(node["label"])] = [str(txid) for txid in mempool]
                else:
                    errors[str(node["label"])] = "unexpected mempool result %r" % (mempool,)
            except Exception as exc:
                errors[str(node["label"])] = str(exc)
        return mempools, errors

    def poll_seed_visibility(self, txid: str) -> Dict[str, Any]:
        deadline = time.time() + self.args.seed_visibility_timeout
        last: Dict[str, Any] = {}
        while time.time() < deadline:
            mempools, errors = self.seed_mempools()
            seen_on = sorted(label for label, txids in mempools.items() if txid in txids)
            last = {
                "txid": txid,
                "seed_seen": len(seen_on),
                "seen_on": seen_on,
                "mempool_counts": {label: len(txids) for label, txids in mempools.items()},
                "errors": errors,
            }
            if len(seen_on) >= self.args.seed_visibility_min:
                return last
            time.sleep(self.args.poll_interval)
        return last

    def mine_one_block(self, txids: Sequence[str]) -> Dict[str, Any]:
        seed4 = node_with_defaults(SEED_NODES[3], self.args)
        info = rpc_call(seed4, "getinfo", timeout=self.args.rpc_timeout, args=self.args)
        before_height = to_int(info.get("blocks") if isinstance(info, dict) else info)
        start_result = rpc_call(seed4, "setgenerate", "true", 1, self.args.mining_threads, timeout=self.args.rpc_timeout, args=self.args)
        self.log_event("mining_started", {"before_height": before_height, "start_result": start_result, "txids": list(txids)})

        deadline = time.time() + self.args.mining_timeout
        mining_info: Any = {}
        after_height = before_height
        while time.time() < deadline:
            mining_info = rpc_call(seed4, "getmininginfo", timeout=self.args.rpc_timeout, args=self.args)
            if isinstance(mining_info, dict):
                after_height = to_int(mining_info.get("blocks"))
                if after_height > before_height and parse_bool(mining_info.get("cpumining")) is False:
                    break
            time.sleep(self.args.poll_interval)
        else:
            raise SoakError("finite PoW pulse did not complete within %ss" % self.args.mining_timeout)

        block_hash = str(rpc_call(seed4, "getblockhash", after_height, timeout=self.args.rpc_timeout, args=self.args))
        block = rpc_call(seed4, "getblock", block_hash, timeout=self.args.rpc_timeout, args=self.args)
        block_txids = [str(txid) for txid in block.get("tx", [])] if isinstance(block, dict) else []
        missing = [txid for txid in txids if txid not in block_txids]
        if missing:
            raise SoakError("mined block %s missing expected txids %s" % (block_hash, missing))

        clean, last = self.wait_for_clean_convergence("post_mine_height_%s" % after_height)
        if not clean:
            raise SoakError("post-mine convergence/mempool cleanup failed: %s" % last.get("evaluation", {}))
        return {
            "height": after_height,
            "hash": block_hash,
            "tx_count": len(block_txids),
            "flags": block.get("flags", "") if isinstance(block, dict) else "",
            "mining_info": mining_info,
        }

    def traffic_cycle(self, cycle: int) -> int:
        txids: List[str] = []
        # Avoid listunspent between unconfirmed sends. This legacy wallet can
        # run FixSpentCoins during listunspent and re-expose just-spent inputs.
        self.ensure_wallet_ready(self.args.txs_per_pulse)
        for _ in range(self.args.txs_per_pulse):
            if self.stop_requested:
                break
            txid = self.submit_batch()
            visibility = self.poll_seed_visibility(txid)
            seed_seen = int(visibility.get("seed_seen", 0))
            if seed_seen < self.args.seed_visibility_min:
                raise SoakError("tx %s seed visibility %s below %s: %s" % (
                    txid,
                    seed_seen,
                    self.args.seed_visibility_min,
                    visibility,
                ))
            txids.append(txid)
            append_csv(
                self.traffic_path,
                TRAFFIC_COLUMNS,
                {
                    "timestamp": utc_now(),
                    "cycle": cycle,
                    "txid": txid,
                    "seed_seen": seed_seen,
                    "seen_on": visibility.get("seen_on", []),
                    "mempools": visibility.get("mempool_counts", {}),
                    "mined_height": "",
                    "included": "",
                },
            )
            self.log_event("traffic_tx", {"cycle": cycle, "txid": txid, "visibility": visibility})
            time.sleep(self.args.submit_pause)

        if not txids:
            return 0
        mined = self.mine_one_block(txids)
        for txid in txids:
            append_csv(
                self.traffic_path,
                TRAFFIC_COLUMNS,
                {
                    "timestamp": utc_now(),
                    "cycle": cycle,
                    "txid": txid,
                    "seed_seen": self.args.seed_visibility_min,
                    "seen_on": "mined",
                    "mempools": {},
                    "mined_height": mined["height"],
                    "included": True,
                },
            )
        self.log_event("traffic_mined", {"cycle": cycle, "txids": txids, "mined": mined})
        return len(txids)

    def install_signal_handlers(self) -> None:
        def _handler(signum: int, _frame: Any) -> None:
            self.stop_requested = True
            self.log_event("signal", {"signum": signum})
            self.write_status("stopping", signal=signum)

        signal.signal(signal.SIGTERM, _handler)
        signal.signal(signal.SIGINT, _handler)

    def run(self) -> int:
        if not self.args.yes_live_traffic:
            raise SoakError("refusing to run live Gate 7 soak without --yes-live-traffic")
        self.lock()
        self.install_signal_handlers()
        self.log_event(
            "started",
            {
                "duration_seconds": self.args.duration,
                "traffic_interval": self.args.traffic_interval,
                "txs_per_pulse": self.args.txs_per_pulse,
            },
        )
        self.write_status("running")

        passed, detail = self.health_check("initial", require_empty_mempool=True)
        if not passed:
            return self.fail("initial_health_failed", detail=detail.get("evaluation", {}))

        next_cycle = time.time()
        try:
            while time.time() < self.deadline and not self.stop_requested:
                now = time.time()
                if now < next_cycle:
                    time.sleep(min(30, next_cycle - now, max(0, self.deadline - now)))
                    continue
                self.cycles += 1
                cycle = self.cycles
                passed, detail = self.health_check("cycle_%s_pre" % cycle, require_empty_mempool=True)
                if not passed:
                    return self.fail("cycle_health_failed", cycle=cycle, detail=detail.get("evaluation", {}))
                submitted = self.traffic_cycle(cycle)
                passed, detail = self.health_check("cycle_%s_post" % cycle, require_empty_mempool=True)
                if not passed:
                    return self.fail("cycle_post_health_failed", cycle=cycle, detail=detail.get("evaluation", {}))
                self.write_status("running", last_cycle={"cycle": cycle, "submitted": submitted})
                next_cycle = time.time() + self.args.traffic_interval
        except Exception as exc:
            return self.fail("exception", error=str(exc))

        if self.stop_requested:
            self.write_summary("stopped")
            self.write_status("stopped")
            return 130

        passed, detail = self.health_check("final", require_empty_mempool=True)
        if not passed:
            return self.fail("final_health_failed", detail=detail.get("evaluation", {}))
        self.write_summary("passed")
        self.write_status("passed")
        self.log_event("passed", {"submitted": self.submitted, "cycles": self.cycles})
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--duration", type=int, default=72 * 60 * 60)
    parser.add_argument("--traffic-interval", type=int, default=30 * 60)
    parser.add_argument("--txs-per-pulse", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--amount", type=float, default=0.001)
    parser.add_argument("--amount-jitter", type=float, default=0.20)
    parser.add_argument("--min-utxos", type=int, default=20)
    parser.add_argument("--min-seed-peers", type=int, default=4)
    parser.add_argument("--min-traffic-peers", type=int, default=4)
    parser.add_argument("--seed-visibility-min", type=int, default=5)
    parser.add_argument("--seed-visibility-timeout", type=int, default=90)
    parser.add_argument("--submit-pause", type=float, default=5.0)
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument("--sync-timeout", type=int, default=180)
    parser.add_argument("--mining-timeout", type=int, default=900)
    parser.add_argument("--mining-threads", type=int, default=16)
    parser.add_argument("--rpc-timeout", type=int, default=30)
    parser.add_argument("--optional-rpc-timeout", type=int, default=10)
    parser.add_argument("--innovad", default=DEFAULT_INNOVAD)
    parser.add_argument("--ssh-key", default=DEFAULT_SSH_KEY)
    parser.add_argument("--yes-live-traffic", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    runner = SoakRunner(args)
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
